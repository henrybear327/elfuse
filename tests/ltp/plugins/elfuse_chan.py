"""Kirk communication channel that executes every command under elfuse.

Loaded by kirk's plugin discovery (see ltp_harness/kirk_shim.py), so
libkirk is importable when this module is executed. Each run_command
spawns one elfuse process on the macOS host:

    elfuse --timeout 0 --sysroot ROOTFS /opt/elfuse-ltp/bin/case-launcher
        -- /bin/sh -c 'cd CWD && COMMAND'

The case-launcher fork keeps the test a non-session-leader child
(elfuse models the initial process as PID/SID/PGID 1, and busybox ash
tail-execs a lone command), and busybox provides the shell semantics
kirk's LTP framework expects from a target. With --sysroot, guest /tmp
resolves inside the rootfs, so scratch directories live under
ROOTFS/tmp and cannot escape into the host or the repository.

Elfuse backs guest /dev/shm with the per-host-UID directory
/tmp/elfuse-shm-<uid> (src/runtime/procemu.c), shared by every elfuse
process of this user: the channel takes a suite lock around the whole
session and sweeps leaked ltp_* objects so one case cannot contaminate
the next, and a crashed previous run cannot be blamed on this one.
"""

from __future__ import annotations

import asyncio
import glob
import logging
import os
import shlex
import shutil
import signal
import tempfile
import time
from typing import Any, Dict, Optional

from libkirk.com import ComChannel, IOBuffer
from libkirk.errors import CommunicationError
from libkirk.io import AsyncFile

from _common import GUEST_PATH, LAUNCHER, guest_environment, rewrite_command


def guest_script(command: str, cwd: Optional[str]) -> str:
    """The /bin/sh -c payload: enter the working directory, then run."""
    command = rewrite_command(command)
    if cwd:
        return f"cd {shlex.quote(cwd)} && {command}"
    return command


class ElfuseComChannel(ComChannel):
    """Run commands as elfuse guests on the macOS host."""

    BUFFSIZE = 1024

    _name = "elfuse"

    def __init__(self) -> None:
        self._logger = logging.getLogger("kirk.elfuse")
        self._binary = ""
        self._sysroot = ""
        self._timeout = 0.0
        self._procs = []
        self._active = False
        self._lock_dir = ""
        self._shm_dir = f"/tmp/elfuse-shm-{os.getuid()}"

    def setup(self, **kwargs: Dict[str, Any]) -> None:
        self._binary = str(kwargs.get("binary", ""))
        self._sysroot = str(kwargs.get("sysroot", ""))
        self._timeout = float(kwargs.get("timeout", 0.0))

    @property
    def config_help(self) -> Dict[str, str]:
        return {
            "binary": "elfuse executable on the host",
            "sysroot": "staged guest root filesystem",
            "timeout": "safety cap per command in seconds (0 disables)",
        }

    @property
    def parallel_execution(self) -> bool:
        return False

    async def active(self) -> bool:
        return self._active

    async def ping(self) -> float:
        if not await self.active():
            raise CommunicationError("elfuse channel is not running")

        ret = await self.run_command("true")
        if not ret or ret["returncode"] != 0:
            raise CommunicationError("'true' failed under elfuse")
        return ret["exec_time"]

    def _sweep_shm(self, note: str) -> int:
        """Remove leaked ltp_* objects from the shared shm backing dir."""
        removed = 0
        for path in glob.glob(os.path.join(self._shm_dir, "ltp_*")):
            self._logger.warning("%s: removing %s", note, path)
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.unlink(path)
                removed += 1
            except OSError as err:
                raise CommunicationError(
                    f"cannot remove leaked shm object {path}: {err}"
                ) from err
        return removed

    async def communicate(self, iobuffer: Optional[IOBuffer] = None) -> None:
        if await self.active():
            raise CommunicationError("elfuse channel is running")
        if not os.path.isfile(self._binary) or not os.access(self._binary, os.X_OK):
            raise CommunicationError(f"elfuse binary not executable: {self._binary}")
        if not os.path.isdir(self._sysroot):
            raise CommunicationError(f"sysroot missing: {self._sysroot}")

        # One elfuse LTP session per host user: the /dev/shm backing
        # directory is shared across every elfuse process of this UID.
        lock_dir = f"/tmp/elfuse-ltp-{os.getuid()}.lock"
        try:
            os.mkdir(lock_dir)
        except FileExistsError:
            owner_file = os.path.join(lock_dir, "pid")
            owner = None
            try:
                with open(owner_file, "r", encoding="utf-8") as handle:
                    owner = int(handle.read().strip())
            except (OSError, ValueError):
                pass
            if owner is not None and _pid_alive(owner):
                raise CommunicationError(
                    f"another LTP session (pid {owner}) holds {lock_dir}"
                )
            self._logger.warning("removing stale suite lock %s", lock_dir)
            shutil.rmtree(lock_dir, ignore_errors=True)
            os.mkdir(lock_dir)
        self._lock_dir = lock_dir
        with open(
            os.path.join(self._lock_dir, "pid"), "w", encoding="utf-8"
        ) as handle:
            handle.write(f"{os.getpid()}\n")

        # Leftovers here predate this session (a crashed earlier run);
        # clean them now so they are never attributed to a test.
        if os.path.isdir(self._shm_dir):
            self._sweep_shm("stale shm object from a previous session")

        self._active = True

    async def stop(self, iobuffer: Optional[IOBuffer] = None) -> None:
        if not await self.active():
            return

        try:
            for proc in list(self._procs):
                _kill_process_group(proc)
            if self._procs:
                await asyncio.gather(*[proc.wait() for proc in self._procs])
        finally:
            if self._lock_dir:
                shutil.rmtree(self._lock_dir, ignore_errors=True)
                self._lock_dir = ""
            self._active = False

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
            raise CommunicationError("elfuse channel is not running")

        # Kirk's SUT layer polls kernel taint around every test and treats
        # a failed read as fatal. Elfuse is a userspace loader with no
        # kernel to taint and no such procfs node; answer "untainted"
        # here instead of spawning a guest that cannot serve the read.
        if command.strip() == "cat /proc/sys/kernel/tainted":
            return {
                "command": command,
                "stdout": "0\n",
                "returncode": 0,
                "exec_time": 0.0,
            }

        self._logger.info("executing: %s", command)

        host_tmp = os.path.join(self._sysroot, "tmp")
        os.makedirs(host_tmp, exist_ok=True)
        scratch_host = tempfile.mkdtemp(prefix="ltp-", dir=host_tmp)
        os.chmod(scratch_host, 0o777)
        scratch_guest = "/tmp/" + os.path.basename(scratch_host)

        # No --status here: on a case-insensitive sysroot elfuse may store
        # new guest files under sidecar names the host cannot resolve, and
        # the exit code already travels launcher -> elfuse -> kirk. The
        # launcher is used purely for its non-session-leader fork.
        argv = [
            self._binary,
            "--timeout",
            "0",
            "--sysroot",
            self._sysroot,
            LAUNCHER,
            "--",
            "/bin/sh",
            "-c",
            guest_script(command, cwd),
        ]

        proc = None
        chunks = []
        stdout = ""
        t_start = time.monotonic()
        t_end = 0.0

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=scratch_host,
                env=guest_environment(env, scratch_guest),
                start_new_session=True,
            )
            self._procs.append(proc)

            assert proc.stdout is not None
            # Chunks accumulate in an external list so partial output
            # survives when the read loop is cancelled by a timeout,
            # which is exactly when the log matters most.
            read_loop = self._read_stdout(proc, chunks, iobuffer)
            if self._timeout > 0:
                try:
                    await asyncio.wait_for(read_loop, self._timeout)
                except asyncio.TimeoutError:
                    chunks.append(
                        "\nltp-harness: channel safety cap of "
                        f"{self._timeout}s expired\n"
                    )
                    _kill_process_group(proc)
            else:
                await read_loop

            await proc.wait()
            t_end = time.monotonic() - t_start
        finally:
            if proc:
                self._procs.remove(proc)
                _kill_process_group(proc)
                await proc.wait()

            stdout = "".join(chunks)
            if proc and proc.returncode is not None and proc.returncode < 0:
                stdout += (
                    "ltp-harness: elfuse itself died on host signal "
                    f"{-proc.returncode}\n"
                )

            try:
                leaked = self._sweep_shm("shm object leaked by this command")
            except CommunicationError as err:
                # Raising inside finally would mask the primary error.
                leaked = 0
                stdout += f"ltp-harness: shm sweep failed: {err}\n"
            if leaked:
                stdout += (
                    f"ltp-harness: removed {leaked} leaked /dev/shm object(s)\n"
                )

            shutil.rmtree(scratch_host, ignore_errors=True)

        return {
            "command": command,
            "stdout": stdout,
            "returncode": proc.returncode if proc.returncode is not None else -1,
            "exec_time": t_end,
        }

    async def _read_stdout(
        self, proc, chunks: list, iobuffer: Optional[IOBuffer]
    ) -> None:
        while True:
            data = await proc.stdout.read(self.BUFFSIZE)
            if not data:
                break
            text = data.decode(encoding="utf-8", errors="ignore")
            chunks.append(text)
            if iobuffer:
                await iobuffer.write(text)

    async def fetch_file(self, target_path: str) -> bytes:
        if not target_path:
            raise ValueError("target path is empty")
        if not await self.active():
            raise CommunicationError("elfuse channel is not running")

        host_path = self.guest_to_host(target_path)
        if not os.path.isfile(host_path):
            raise CommunicationError(f"'{target_path}' does not exist in the guest")

        async with AsyncFile(host_path, "rb") as handle:
            return await handle.read()

    def guest_to_host(self, guest_path: str) -> str:
        """Map an absolute guest path to its host location in the rootfs."""
        if not guest_path.startswith("/"):
            raise CommunicationError(f"guest path must be absolute: {guest_path}")
        normalized = os.path.normpath(guest_path)
        host_path = os.path.normpath(self._sysroot + normalized)
        # normpath containment is lexical only; a symlink staged inside
        # the rootfs could still point outside it, so re-check the
        # resolved path.
        sysroot_real = os.path.realpath(self._sysroot)
        if not (os.path.realpath(host_path) + "/").startswith(sysroot_real + "/"):
            raise CommunicationError(f"guest path escapes the sysroot: {guest_path}")
        return host_path


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _kill_process_group(proc) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
