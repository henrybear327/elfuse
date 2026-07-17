"""Boot and tear down the QEMU reference VM for the LTP lane.

The QEMU invocation mirrors tests/qemu-runner.sh:125-137 (machine,
accelerator and CPU auto-selection, user networking with an SSH forward,
and the read-only virtio-9p share of the repo root at /mnt/host). The
runner script cannot be driven as a subprocess because it registers an
EXIT trap that stops the VM as soon as the driving process exits, so the
argv lives here too; keep the two files in sync when either changes.

Kirk's own qemu channel is not used: it boots a private VM and speaks
over the serial console, whereas this lane needs the repo 9p share and
the root-side supervisor of tests/ltp/helpers/qemu-supervisor.c.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, List


def _fixtures_dir(repo_root: str) -> str:
    return os.path.join(repo_root, "externals", "test-fixtures")


def _boot_files(repo_root: str) -> Dict[str, str]:
    fixtures = _fixtures_dir(repo_root)
    return {
        "kernel": os.environ.get(
            "QEMU_KERNEL", os.path.join(fixtures, "kernel", "vmlinuz-virt")
        ),
        "initrd": os.environ.get(
            "QEMU_INITRD", os.path.join(fixtures, "initramfs.cpio.gz")
        ),
        "ssh_key": os.environ.get(
            "QEMU_SSH_KEY", os.path.join(fixtures, "keys", "ssh_key")
        ),
    }


def _pick_port() -> int:
    # Bind-then-close has an inherent reuse race; QEMU rebinding failure
    # surfaces as a boot timeout, and reruns pick a fresh port.
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Vm:
    """One booted QEMU reference VM."""

    def __init__(self, repo_root: str) -> None:
        self.repo_root = repo_root
        self.port = 0
        self.ssh_key = ""
        self._proc: Any = None
        self._rundir = ""

    def _ssh(self, command: str, cap: float) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "LogLevel=ERROR",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                "-i",
                self.ssh_key,
                "-p",
                str(self.port),
                "root@127.0.0.1",
                command,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=cap,
        )

    def start(self, boot_timeout: int = 90) -> None:
        from ltp_harness.cli import HarnessFatal, HarnessSkip

        qemu_bin = os.environ.get("QEMU_BIN", "qemu-system-aarch64")
        if not shutil.which(qemu_bin):
            raise HarnessSkip(f"{qemu_bin} not found in PATH; install qemu")

        files = _boot_files(self.repo_root)
        missing = [path for path in files.values() if not os.path.isfile(path)]
        if missing:
            raise HarnessSkip(
                "QEMU boot fixtures are absent "
                f"({', '.join(missing)}); run: bash tests/fetch-fixtures.sh"
            )

        accel = os.environ.get("QEMU_ACCEL", "")
        if not accel:
            probe = subprocess.run(
                [qemu_bin, "-accel", "help"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            accel = "hvf" if "hvf" in probe.stdout.split() else "tcg"
        cpu = os.environ.get("QEMU_CPU", "host" if accel == "hvf" else "cortex-a72")

        self.port = _pick_port()
        self.ssh_key = files["ssh_key"]
        self._rundir = tempfile.mkdtemp(prefix="elfuse-ltp-qemu.")

        # Mirrored from tests/qemu-runner.sh qemu_start(); keep in sync.
        argv = [
            qemu_bin,
            "-machine",
            "virt",
            "-accel",
            accel,
            "-cpu",
            cpu,
            "-m",
            os.environ.get("QEMU_MEM", "2048"),
            "-smp",
            os.environ.get("QEMU_SMP", "4"),
            "-kernel",
            files["kernel"],
            "-initrd",
            files["initrd"],
            "-append",
            "console=ttyAMA0 panic=5 quiet",
            "-netdev",
            f"user,id=net0,hostfwd=tcp:127.0.0.1:{self.port}-:22",
            "-device",
            "virtio-net-pci,netdev=net0",
            "-fsdev",
            f"local,id=share,path={self.repo_root},security_model=none,readonly=on",
            "-device",
            "virtio-9p-pci,fsdev=share,mount_tag=host",
            "-nographic",
            "-display",
            "none",
            "-no-reboot",
            "-monitor",
            "none",
            "-serial",
            f"file:{os.path.join(self._rundir, 'qemu-serial.log')}",
        ]
        self._proc = subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        deadline = time.monotonic() + boot_timeout
        ready = False
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                    ready = True
                    break
            except OSError:
                time.sleep(1)
        if not ready:
            self.stop()
            raise HarnessFatal(f"QEMU VM did not boot within {boot_timeout}s")

        # The first connections can race dropbear's startup.
        for _ in range(30):
            try:
                if self._ssh("echo ready", cap=15).returncode == 0:
                    break
            except subprocess.TimeoutExpired:
                pass
            time.sleep(1)
        else:
            self.stop()
            raise HarnessFatal("VM SSH endpoint never became ready")

        # The initramfs keeps /tmp on rootfs; give it a real tmpfs so the
        # copied LTP root gets a resolvable, writable mount.
        mount = self._ssh(
            'grep -q " /tmp tmpfs " /proc/mounts || mount -t tmpfs tmpfs /tmp',
            cap=30,
        )
        if mount.returncode != 0:
            self.stop()
            raise HarnessFatal(f"cannot mount tmpfs on VM /tmp: {mount.stdout}")

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
            self._proc = None
        if self._rundir:
            shutil.rmtree(self._rundir, ignore_errors=True)
            self._rundir = ""


def run_qemu_backend(
    args: argparse.Namespace,
    paths: Dict[str, str],
    run_dir: str,
    repo_root: str,
    sup_timeout: int,
    channel_cap: int,
    kirk_argv_builder: Callable[[Dict[str, str]], List[str]],
    kirk_env: Dict[str, str],
    run_kirk: Callable[[List[str], Dict[str, str], str], int],
    check_report: Callable[[str, str, int, str], None],
) -> None:
    """Boot the VM, drive kirk with the qemuchroot channel, tear down."""
    from ltp_harness.cli import HarnessFatal

    fixture_dir = os.path.realpath(args.fixture_dir)
    repo_real = os.path.realpath(repo_root)
    if not (fixture_dir + "/").startswith(repo_real + "/"):
        raise HarnessFatal(
            "the QEMU backend reaches the fixture through the repo 9p share; "
            f"LTP_FIXTURE_DIR must stay under {repo_real} (got {fixture_dir})"
        )

    def guest_path(host_path: str) -> str:
        return "/mnt/host/" + os.path.relpath(os.path.realpath(host_path), repo_real)

    machine = Vm(repo_real)
    try:
        machine.start()
        options = {
            "port": str(machine.port),
            "key_file": machine.ssh_key,
            "supervisor": guest_path(
                os.path.join(fixture_dir, "bin", "qemu-supervisor")
            ),
            "rootfs_src": guest_path(paths["rootfs"]),
            "rootfs_host": paths["rootfs"],
            "sup_timeout": str(sup_timeout),
            "timeout": str(channel_cap),
        }
        argv = kirk_argv_builder(options)
        log_path = os.path.join(run_dir, "kirk-qemu.log")
        kirk_rc = run_kirk(argv, kirk_env, log_path)
        check_report(run_dir, "qemu", kirk_rc, log_path)
    finally:
        machine.stop()
