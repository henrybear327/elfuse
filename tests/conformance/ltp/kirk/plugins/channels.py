# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import codecs
import json
import logging
import os
import shlex
import signal
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from libkirk.com import ComChannel, IOBuffer
from libkirk.errors import CommunicationError

from conformance.backends import base
from conformance.backends.elfuse import WRAPPER, ElfuseBackend
from conformance.backends.ssh import SshSession
from conformance.ltp.build import LAUNCHER
from conformance.ltp.results import STATUS_PREFIX

GUEST_PATH = "/opt/ltp/testcases/bin:/usr/bin:/bin"
RUNTEST_DIR = "/opt/ltp/runtest"
FORWARD_PREFIXES = ("LTP_", "TST_")
CHROOT = "/tmp/ltp-root"
MOUNTS = (("mount -t proc proc", "/proc"), ("mount -o bind /dev", "/dev"),
          ("mount -t sysfs sys", "/sys"), ("mount -t tmpfs -o mode=1777 shm", "/dev/shm"))


def status_line(**fields: Any) -> str:
    fields["schema_version"] = 1
    return STATUS_PREFIX + json.dumps(fields, sort_keys=True, separators=(",", ":")) + "\n"


def append_status(text: str, status: str) -> str:
    """The status parses only on its own line; a killed guest ends mid-line."""
    return text + ("" if not text or text.endswith("\n") else "\n") + status


async def _wait_bounded(proc: Any) -> None:
    """Bound the wait for a guest stuck in an uninterruptible state."""
    try:
        await asyncio.wait_for(proc.wait(), base.KILL_WAIT_S)
    except asyncio.TimeoutError:
        pass


def rewrite_command(command: str) -> str:
    """Replace the GNU ls option with its BusyBox spelling."""
    return command.replace("ls --format=single-column", "ls -1")


def channel_environment(scratch: str, env: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Build a fixed guest environment and forward LTP_ and TST_ names."""
    out = {**base.FIXED_ENV, **{name: scratch for name in base.SCRATCH_NAMES},
           "LTPROOT": "/opt/ltp", "PATH": GUEST_PATH, "LTP_COLORIZE_OUTPUT": "0"}
    for key, value in (env or {}).items():
        if key.startswith(FORWARD_PREFIXES) and key != "LTP_COLORIZE_OUTPUT":
            out[key] = value
    return out


class Served:
    """Serve runtest files without modifying the payload."""

    def __init__(self, directory: str):
        self.directory = Path(directory) if directory else None

    def path_of(self, guest_path: str) -> Optional[Path]:
        if self.directory is None or not guest_path.startswith(RUNTEST_DIR + "/"):
            return None
        candidate = self.directory / guest_path[len(RUNTEST_DIR) + 1:]
        return candidate if candidate.is_file() else None

    def answer(self, command: str) -> Optional[Dict[str, Any]]:
        words = command.split()
        if len(words) == 3 and words[0] == "test" and words[1] == "-f" and self.path_of(words[2]):
            return {"command": command, "stdout": "", "returncode": 0, "exec_time": 0.0}
        if self.directory is not None and words[:3] == ["ls", "--format=single-column", RUNTEST_DIR]:
            names = sorted(p.name for p in self.directory.iterdir() if p.is_file())
            return {"command": command, "stdout": "".join(n + "\n" for n in names),
                    "returncode": 0, "exec_time": 0.0}
        return None


class _Channel(ComChannel):
    BUFFSIZE = 4096

    def __init__(self) -> None:
        self._logger = logging.getLogger("kirk." + self._name)
        self._active = False
        self._timeout = 0.0
        self._served = Served("")
        self._procs: List[Any] = []

    @property
    def parallel_execution(self) -> bool:
        return False

    async def active(self) -> bool:
        return self._active

    async def ping(self) -> float:
        if not self._active:
            raise CommunicationError("%s channel is not running" % self._name)
        ret = await self.run_command("true")
        if not ret or ret["returncode"] != 0:
            raise CommunicationError("'true' failed on %s" % self._name)
        return ret["exec_time"]

    async def stop(self, iobuffer: Optional[IOBuffer] = None) -> None:
        for proc in list(self._procs):
            _kill_group(proc)
        self._active = False

    def _intercept(self, command: str) -> Optional[Dict[str, Any]]:
        # Kernel taint is not a result, and elfuse has no kernel to poll.
        if command.strip() == "cat /proc/sys/kernel/tainted":
            return {"command": command, "stdout": "0\n", "returncode": 0, "exec_time": 0.0}
        return self._served.answer(command)

    async def fetch_file(self, target_path: str) -> bytes:
        if not target_path.startswith("/"):
            raise CommunicationError("guest path must be absolute: %s" % target_path)
        served = self._served.path_of(target_path)
        if served is not None:
            return served.read_bytes()
        return self._fetch_from_rootfs(target_path)

    def _fetch_from_rootfs(self, target_path: str) -> bytes:
        root = Path(self._rootfs_host)
        host = Path(os.path.normpath(str(root) + os.path.normpath(target_path)))
        if not (str(host.resolve()) + "/").startswith(str(root.resolve()) + "/"):
            raise CommunicationError("guest path escapes the rootfs: %s" % target_path)
        if not host.is_file():
            raise CommunicationError("'%s' does not exist in the guest" % target_path)
        return host.read_bytes()


class ElfuseChannel(_Channel):
    """Run each command in a new elfuse process."""

    _name = "elfuse"

    def setup(self, **kwargs: Any) -> None:
        self._binary = str(kwargs.get("binary", ""))
        self._rootfs_host = str(kwargs.get("sysroot", ""))
        self._backend = ElfuseBackend(Path("."), sysroot=Path(self._rootfs_host), binary=Path(self._binary))
        self._timeout = float(kwargs.get("timeout", 0.0))
        self._served = Served(str(kwargs.get("serve", "")))

    @property
    def config_help(self) -> Dict[str, str]:
        return {"binary": "elfuse executable on the host", "sysroot": "staged guest rootfs",
                "timeout": "cap per command in seconds", "serve": "host directory of runtest files"}

    async def communicate(self, iobuffer: Optional[IOBuffer] = None) -> None:
        if not os.access(self._binary, os.X_OK):
            raise CommunicationError("elfuse binary not executable: %s" % self._binary)
        if not os.path.isdir(self._rootfs_host):
            raise CommunicationError("sysroot missing: %s" % self._rootfs_host)
        self._active = True

    async def run_command(self, command: str, cwd: Optional[str] = None,
                          env: Optional[Dict[str, str]] = None,
                          iobuffer: Optional[IOBuffer] = None) -> Optional[Dict[str, Any]]:
        if not command:
            raise ValueError("command is empty")
        if not self._active:
            raise CommunicationError("elfuse channel is not running")
        answer = self._intercept(command)
        if answer is not None:
            return answer
        host_tmp = os.path.join(self._rootfs_host, "tmp")
        scratch_host = tempfile.mkdtemp(prefix="ltp-", dir=host_tmp)
        os.chmod(scratch_host, 0o777)
        scratch_guest = "/tmp/" + os.path.basename(scratch_host)
        script = rewrite_command(command)
        if cwd:
            script = "cd %s && %s" % (shlex.quote(cwd), script)
        argv = WRAPPER + self._backend.argv([LAUNCHER, "--", "/bin/sh", "-c", script])
        chunks: List[str] = []
        timed_out = False
        started = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            cwd=scratch_host, env=channel_environment(scratch_guest, env), start_new_session=True)
        self._procs.append(proc)
        try:
            reader = _read_all(proc, chunks, iobuffer, self.BUFFSIZE)
            if self._timeout > 0:
                try:
                    await asyncio.wait_for(reader, self._timeout)
                except asyncio.TimeoutError:
                    timed_out = True
                    _kill_group(proc)
            else:
                await reader
            await _wait_bounded(proc)
        finally:
            self._procs.remove(proc)
            _kill_group(proc)
            await _wait_bounded(proc)
            self._backend.reap_orphans(proc.pid)
            _rmtree(scratch_host)
        elapsed = time.monotonic() - started
        rc = proc.returncode if proc.returncode is not None else -1
        stdout = append_status("".join(chunks), status_line(
            source="elfuse", timed_out=timed_out, host_signal=-rc if rc < 0 else 0))
        return {"command": command, "stdout": stdout, "returncode": rc, "exec_time": elapsed}


class QemuChannel(_Channel):
    """Run commands under the VM supervisor in a per-session rootfs."""

    _name = "qemu"

    def setup(self, **kwargs: Any) -> None:
        self._port = int(kwargs.get("port", 0))
        self._key = str(kwargs.get("key", ""))
        self._supervisor = str(kwargs.get("supervisor", ""))
        self._rootfs_guest = str(kwargs.get("rootfs_guest", ""))
        self._rootfs_host = str(kwargs.get("rootfs_host", ""))
        self._deadline = int(kwargs.get("deadline", 0))
        self._timeout = float(kwargs.get("timeout", 0.0))
        self._served = Served(str(kwargs.get("serve", "")))
        self._scratch = str(kwargs.get("scratch", tempfile.gettempdir()))
        self._mounted: List[str] = []
        self._copied = False
        self._serial = 0

    @property
    def config_help(self) -> Dict[str, str]:
        return {"port": "forwarded ssh port of the booted VM", "key": "ssh private key",
                "supervisor": "guest path of guest-supervisor on the 9p share",
                "rootfs_guest": "guest path of the staged rootfs on the 9p share",
                "rootfs_host": "host path of the same rootfs, for fetch_file",
                "deadline": "per-test deadline the supervisor enforces",
                "timeout": "cap per command in seconds", "serve": "host directory of runtest files",
                "scratch": "host directory for ssh transcripts"}

    def _session(self) -> SshSession:
        return SshSession(self._port, Path(self._key))

    async def _ssh(self, script: str, timeout_s: int, name: str) -> Dict[str, Any]:
        self._serial += 1
        scratch = Path(self._scratch) / ("ssh-%06d-%s" % (self._serial, name))
        inv = await asyncio.to_thread(self._session().run, ["sh", "-c", script], timeout_s, scratch, cwd="/")
        if inv.execution == "transport":
            raise CommunicationError("ssh transport to the VM was lost\n" + status_line(
                source="qemu", execution="transport"))
        return {"returncode": inv.exit_code if inv.exit_code is not None else 128 + (inv.signal or 0),
                "stdout": Path(inv.stdout).read_text(errors="replace"), "execution": inv.execution,
                "wall_us": inv.wall_us}

    async def _check(self, script: str, timeout_s: int, what: str) -> None:
        ret = await self._ssh(script, timeout_s, what)
        if ret["returncode"] != 0:
            raise CommunicationError("%s failed: %s" % (what, ret["stdout"][-400:]))

    async def communicate(self, iobuffer: Optional[IOBuffer] = None) -> None:
        for option in ("_port", "_key", "_supervisor", "_rootfs_guest", "_rootfs_host"):
            if not getattr(self, option):
                raise CommunicationError("missing channel option %s" % option[1:])
        try:
            # Expand tmpfs to fit the copied rootfs.
            await self._check("mount -o remount,size=80% /tmp", 30, "sizing /tmp")
            # Remove stale binds before rm can enter the VM's real /dev.
            await self._check(
                "for m in $(cut -d' ' -f2 /proc/mounts | grep '^%s/' | sort -r); do umount \"$m\" || "
                "umount -l \"$m\"; done; ! cut -d' ' -f2 /proc/mounts | grep -q '^%s/' && rm -rf %s && "
                "cp -a %s %s" % (CHROOT, CHROOT, CHROOT, shlex.quote(self._rootfs_guest), CHROOT),
                900, "copying the rootfs into the VM")
            self._copied = True
            for prefix, target in MOUNTS:
                await self._check("%s %s%s" % (prefix, CHROOT, target), 30, "mounting " + target)
                self._mounted.append(target)
        except Exception:
            await self._teardown()
            raise
        self._active = True

    async def stop(self, iobuffer: Optional[IOBuffer] = None) -> None:
        try:
            await self._teardown()
        except CommunicationError as e:
            self._logger.warning("teardown incomplete: %s", e)
        finally:
            self._active = False

    async def _teardown(self) -> None:
        for target in reversed(list(self._mounted)):
            await self._check("umount %s%s" % (CHROOT, target), 30, "unmounting " + target)
            self._mounted.remove(target)
        if self._copied:
            await self._check("rm -rf " + CHROOT, 900, "removing the copied rootfs")
            self._copied = False

    async def run_command(self, command: str, cwd: Optional[str] = None,
                          env: Optional[Dict[str, str]] = None,
                          iobuffer: Optional[IOBuffer] = None) -> Optional[Dict[str, Any]]:
        if not command:
            raise ValueError("command is empty")
        if not self._active:
            raise CommunicationError("qemu channel is not running")
        answer = self._intercept(command)
        if answer is not None:
            return answer
        self._serial += 1
        scratch = "/tmp/ltp-scratch-%d" % self._serial
        status = "/tmp/ltp-sup-%d.status" % self._serial
        env_words = " ".join(shlex.quote("%s=%s" % kv) for kv in sorted(channel_environment(scratch, env).items()))
        remote = ("mkdir -p %s%s && chmod 1777 %s%s && rm -f %s %s.tmp && env -i %s %s --root %s --cwd %s "
                  "--uid 1000 --gid 1000 --timeout %d --status %s -- %s -- /bin/sh -c %s; rc=$?; "
                  "rm -rf %s%s; printf '\\n'; cat %s 2>/dev/null; rm -f %s; exit $rc") % (
            CHROOT, scratch, CHROOT, scratch, status, status, env_words, shlex.quote(self._supervisor),
            CHROOT, shlex.quote(cwd or "/"), self._deadline, status, LAUNCHER,
            shlex.quote(rewrite_command(command)), CHROOT, scratch, status, status)
        started = time.monotonic()
        ret = await self._ssh(remote, int(self._timeout), "cmd")
        elapsed = time.monotonic() - started
        stdout, note = _split_supervisor_status(ret["stdout"])
        if iobuffer:
            await iobuffer.write(stdout)
        return {"command": command, "stdout": append_status(stdout, note), "returncode": ret["returncode"],
                "exec_time": elapsed}


def _split_supervisor_status(text: str) -> tuple:
    """Convert the final supervisor JSON line to a channel status."""
    lines = text.splitlines(keepends=True)
    if lines and lines[-1].startswith("{"):
        try:
            data = json.loads(lines[-1])
        except ValueError:
            data = None
        if isinstance(data, dict):
            data.pop("schema_version", None)
            return "".join(lines[:-1]), status_line(source="qemu-supervisor", **data)
    return text, status_line(source="qemu-supervisor", error="supervisor status missing")


async def _read_all(proc: Any, chunks: List[str], iobuffer: Optional[IOBuffer], size: int) -> None:
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    while True:
        data = await proc.stdout.read(size)
        text = decoder.decode(data, final=not data)
        if text:
            chunks.append(text)
            if iobuffer:
                await iobuffer.write(text)
        if not data:
            return


def _kill_group(proc: Any) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _rmtree(path: str) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)
