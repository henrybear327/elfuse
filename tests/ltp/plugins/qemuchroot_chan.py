"""Kirk communication channel for the QEMU reference backend.

Loaded by kirk's plugin discovery (see ltp_harness/kirk_shim.py). Each
run_command opens one SSH connection (system ssh, no asyncssh) to the
already-booted Alpine VM and runs:

    env -i VARS... SUPERVISOR --root /tmp/ltp-root --cwd CWD
        --uid 1000 --gid 1000 --timeout T --status STATUS
        -- /opt/elfuse-ltp/bin/case-launcher -- /bin/sh -c 'COMMAND'

qemu-supervisor (tests/ltp/helpers/) chroots into the copied glibc
rootfs, drops to uid/gid 1000, enforces the test deadline, and reaps the
whole descendant session; case-launcher keeps the test itself a
non-session-leader child, matching the elfuse lane's process shape.
Suite setup copies the read-only 9p rootfs into the VM once and binds
/proc, /dev, /sys plus a private /dev/shm tmpfs; teardown unwinds in
reverse.

Timeout layering (enforced by a harness selftest): the supervisor
deadline plus its fixed cleanup budget stays below kirk's exec-timeout
(QEMU_EXEC_SLACK_SEC in ltp_harness/kirkdrive.py), which stays below
this channel's per-command SSH cap, so every layer can always report
before the one above it fires. SSH exit 255 means transport loss and
aborts the session immediately.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
import time
from typing import Any, Dict, List, Optional

from libkirk.com import ComChannel, IOBuffer
from libkirk.errors import CommunicationError
from libkirk.io import AsyncFile

from _common import LAUNCHER, guest_environment, rewrite_command

CHROOT = "/tmp/ltp-root"

SSH_BASE = [
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
    "ConnectTimeout=10",
    "-o",
    "ServerAliveInterval=10",
    "-o",
    "ServerAliveCountMax=6",
]

# Chroot mounts, in setup order; teardown unwinds them reversed.
MOUNTS = [
    ("mount -t proc proc", "/proc"),
    ("mount -o bind /dev", "/dev"),
    ("mount -t sysfs sys", "/sys"),
    ("mount -t tmpfs -o mode=1777 shm", "/dev/shm"),
]

AUX_CAP_SEC = 30
SUITE_SETUP_CAP_SEC = 300

# The per-command remote script always exits 0 and reports the test's real
# exit status on this sentinel line, so a test that legitimately exits 255
# is never mistaken for SSH transport loss (a bare rc 255 from ssh itself).
RC_SENTINEL = "__ltp_supervisor_rc__"


def _extract_rc(stdout: str, fallback: int) -> tuple[str, int]:
    """Split the supervisor rc sentinel off the tail of the remote output.

    Returns (stdout_without_sentinel, returncode). The sentinel is the last
    line the remote echoes, so a legitimate test exit of 255 travels here
    rather than colliding with ssh's own transport-loss rc 255.
    """
    lines = stdout.splitlines()
    for i in range(len(lines) - 1, -1, -1):
        marker = lines[i].strip()
        if marker.startswith(RC_SENTINEL + ":"):
            try:
                rc = int(marker[len(RC_SENTINEL) + 1:])
            except ValueError:
                break
            del lines[i]
            trimmed = "\n".join(lines)
            if trimmed:
                trimmed += "\n"
            return trimmed, rc
    return stdout, fallback


class QemuChrootComChannel(ComChannel):
    """Run commands inside the supervised chroot of the reference VM."""

    BUFFSIZE = 1024

    _name = "qemuchroot"

    def __init__(self) -> None:
        self._logger = logging.getLogger("kirk.qemuchroot")
        self._port = 0
        self._key_file = ""
        self._supervisor = ""
        self._rootfs_src = ""
        self._rootfs_host = ""
        self._sup_timeout = 0
        self._cap = 0.0
        self._procs = []
        self._active = False
        self._serial = 0

    def setup(self, **kwargs: Dict[str, Any]) -> None:
        self._port = int(kwargs.get("port", 0))
        self._key_file = str(kwargs.get("key_file", ""))
        self._supervisor = str(kwargs.get("supervisor", ""))
        self._rootfs_src = str(kwargs.get("rootfs_src", ""))
        self._rootfs_host = str(kwargs.get("rootfs_host", ""))
        self._sup_timeout = int(kwargs.get("sup_timeout", 0))
        self._cap = float(kwargs.get("timeout", 0.0))

    @property
    def config_help(self) -> Dict[str, str]:
        return {
            "port": "forwarded SSH port of the booted VM",
            "key_file": "SSH private key",
            "supervisor": "in-VM path of qemu-supervisor (9p share)",
            "rootfs_src": "in-VM path of the staged rootfs (9p share)",
            "rootfs_host": "host path of the same rootfs, for fetch_file",
            "sup_timeout": "per-test deadline enforced by the supervisor",
            "timeout": "per-command SSH cap in seconds",
        }

    @property
    def parallel_execution(self) -> bool:
        return False

    async def active(self) -> bool:
        return self._active

    async def ping(self) -> float:
        if not await self.active():
            raise CommunicationError("qemuchroot channel is not running")
        t_start = time.monotonic()
        await self._ssh("true", AUX_CAP_SEC)
        return time.monotonic() - t_start

    async def _ssh(self, command: str, cap: float) -> Dict[str, Any]:
        """One SSH invocation with a hard cap and 255 fast abort."""
        argv = SSH_BASE + [
            "-i",
            self._key_file,
            "-p",
            str(self._port),
            "root@127.0.0.1",
            command,
        ]

        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        self._procs.append(proc)
        stdout = ""
        try:
            assert proc.stdout is not None
            data = await asyncio.wait_for(proc.stdout.read(), cap)
            stdout = data.decode(encoding="utf-8", errors="ignore")
            await asyncio.wait_for(proc.wait(), 5)
        except asyncio.TimeoutError as err:
            raise CommunicationError(
                f"SSH command exceeded its {cap}s cap: {command[:120]}"
            ) from err
        finally:
            self._procs.remove(proc)
            if proc.returncode is None:
                proc.kill()
                await proc.wait()

        if proc.returncode == 255:
            raise CommunicationError(
                f"SSH transport to the VM was lost (rc 255): {stdout[-400:]}"
            )
        return {"returncode": proc.returncode, "stdout": stdout}

    async def _ssh_check(self, command: str, cap: float, what: str) -> None:
        ret = await self._ssh(command, cap)
        if ret["returncode"] != 0:
            raise CommunicationError(f"{what} failed: {ret['stdout'][-400:]}")

    async def communicate(self, iobuffer: Optional[IOBuffer] = None) -> None:
        if await self.active():
            raise CommunicationError("qemuchroot channel is running")
        for option in ("port", "key_file", "supervisor", "rootfs_src", "rootfs_host"):
            if not getattr(self, f"_{option}"):
                raise CommunicationError(f"missing channel option '{option}'")
        if self._sup_timeout <= 0 or self._cap <= 0:
            raise CommunicationError("sup_timeout and timeout must be positive")

        await self._ssh_check(
            f"rm -rf {CHROOT} && cp -a {shlex.quote(self._rootfs_src)} {CHROOT}",
            SUITE_SETUP_CAP_SEC,
            "copying the rootfs into the VM",
        )
        for prefix, target in MOUNTS:
            await self._ssh_check(
                f"{prefix} {CHROOT}{target}", AUX_CAP_SEC, f"mounting {target}"
            )
        self._active = True

    async def stop(self, iobuffer: Optional[IOBuffer] = None) -> None:
        if not self._active:
            for proc in list(self._procs):
                proc.kill()
                await proc.wait()
            return

        try:
            for proc in list(self._procs):
                proc.kill()
                await proc.wait()
            for _prefix, target in reversed(MOUNTS):
                await self._ssh(f"umount {CHROOT}{target}", AUX_CAP_SEC)
            await self._ssh(f"rm -rf {CHROOT}", SUITE_SETUP_CAP_SEC)
        except CommunicationError as err:
            self._logger.warning("teardown incomplete: %s", err)
        finally:
            self._active = False

    def _guest_environment(
        self, env: Optional[Dict[str, str]], scratch: str
    ) -> List[str]:
        guest_env = guest_environment(env, scratch)
        return [f"{key}={value}" for key, value in sorted(guest_env.items())]

    async def run_command(
        self,
        command: str,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        iobuffer: Optional[IOBuffer] = None,
    ) -> Optional[Dict[str, Any]]:
        if not command:
            raise ValueError("command is empty")
        if not await self.active():
            raise CommunicationError("qemuchroot channel is not running")

        self._logger.info("executing: %s", command)
        self._serial += 1
        scratch = f"/tmp/ltp-scratch-{self._serial}"
        status = f"/tmp/ltp-sup-{self._serial}.status"

        env_args = " ".join(
            shlex.quote(item) for item in self._guest_environment(env, scratch)
        )
        script = rewrite_command(command)
        remote = (
            f"mkdir -p {CHROOT}{scratch} && chmod 1777 {CHROOT}{scratch} && "
            f"rm -f {status} && "
            f"env -i {env_args} {shlex.quote(self._supervisor)} "
            f"--root {CHROOT} --cwd {shlex.quote(cwd or '/')} "
            f"--uid 1000 --gid 1000 "
            f"--timeout {self._sup_timeout} --status {status} "
            f"-- {LAUNCHER} -- /bin/sh -c {shlex.quote(script)}; "
            f'rc=$?; rm -rf {CHROOT}{scratch}; echo "{RC_SENTINEL}:$rc"'
        )

        t_start = time.monotonic()
        ret = await self._ssh(remote, self._cap)
        exec_time = time.monotonic() - t_start
        stdout, returncode = _extract_rc(ret["stdout"], ret["returncode"])

        note = await self._status_note(status)
        if note:
            stdout += note

        return {
            "command": command,
            "stdout": stdout,
            "returncode": returncode,
            "exec_time": exec_time,
        }

    async def _status_note(self, status_path: str) -> str:
        """Summarize supervisor anomalies for the preserved test log."""
        ret = await self._ssh(f"cat {status_path}; rm -f {status_path}", AUX_CAP_SEC)
        if ret["returncode"] != 0:
            return "ltp-harness: supervisor status file missing\n"

        try:
            data = json.loads(ret["stdout"].strip().splitlines()[-1])
        except (ValueError, IndexError):
            return "ltp-harness: supervisor status file malformed\n"

        notes = []
        if data.get("timed_out"):
            notes.append("supervisor deadline expired")
        if not data.get("cleanup_ok", True):
            notes.append("descendant cleanup incomplete")
        if data.get("setup_errno"):
            notes.append(f"chroot setup failed (errno {data['setup_errno']})")
        if data.get("exec_errno"):
            notes.append(f"exec failed (errno {data['exec_errno']})")
        if not notes:
            return ""
        return "ltp-harness: " + "; ".join(notes) + "\n"

    async def fetch_file(self, target_path: str) -> bytes:
        """Read chroot paths from the host-side copy of the same rootfs."""
        if not target_path.startswith("/"):
            raise CommunicationError(f"guest path must be absolute: {target_path}")
        normalized = os.path.normpath(target_path)
        host_path = os.path.normpath(self._rootfs_host + normalized)
        rootfs_real = os.path.realpath(self._rootfs_host)
        if not (os.path.realpath(host_path) + "/").startswith(rootfs_real + "/"):
            raise CommunicationError(f"guest path escapes the rootfs: {target_path}")

        if not os.path.isfile(host_path):
            raise CommunicationError(f"'{target_path}' does not exist in the rootfs")
        async with AsyncFile(host_path, "rb") as handle:
            return await handle.read()
