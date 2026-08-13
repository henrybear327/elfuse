"""Backend execution seam shared by both providers and both kirk channels.

One Invocation contract covers elfuse on the host and the QEMU reference
VM, and guest environment normalization lives here once. Classification
is by exit code plus wall clock: timeout(1) exits 124 (or 137 after
--kill-after) only as its own verdict, so those codes count as TIMEOUT
only at or past the deadline; any other exit above 128 is a signal
death. The QEMU transport uses one OpenSSH ControlMaster per backend
instance (the per-command handshake costs ~100 ms and a lane issues
thousands of commands); a dying master cascades rc 255 into every later
command, so an rc-255 result triggers a master health check, one
restart, and one retry before it is reported as transport loss, and an
RC: sentinel printed by the remote script distinguishes a legitimate
in-guest 255 from ssh's own. The ControlPath socket lives under a short
mkdtemp dir because unix socket paths cap near 104 bytes on macOS.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
import resource
import shlex
import subprocess
import shutil
import tempfile
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
QEMU_RUNNER = REPO_ROOT / "tests" / "qemu-runner.sh"

SCRUB_ENV = (
    "TEST_ON_GVISOR",
    "GTEST_ALSO_RUN_DISABLED_TESTS", "GTEST_BREAK_ON_FAILURE",
    "GTEST_CATCH_EXCEPTIONS", "GTEST_COLOR", "GTEST_DEATH_TEST_STYLE",
    "GTEST_DEATH_TEST_USE_FORK", "GTEST_FAIL_FAST", "GTEST_FILTER",
    "GTEST_INSTALL_FAILURE_SIGNAL_HANDLER", "GTEST_OUTPUT",
    "GTEST_PRINT_TIME", "GTEST_PRINT_UTF8", "GTEST_RANDOM_SEED",
    "GTEST_RECREATE_ENVIRONMENTS_WHEN_REPEATING", "GTEST_REPEAT",
    "GTEST_SHARD_INDEX", "GTEST_SHARD_STATUS_FILE", "GTEST_SHUFFLE",
    "GTEST_STACK_TRACE_DEPTH", "GTEST_THROW_ON_FAILURE",
    "GTEST_TOTAL_SHARDS",
)


class BackendError(Exception):
    """Transport or backend setup failed; never attributable to a test."""


@dataclasses.dataclass
class Invocation:
    exit_code: int
    execution: str
    wall_us: int
    stdout: pathlib.Path
    stderr: pathlib.Path


def guest_environment(scratch) -> dict:
    scratch = str(scratch)
    return {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": scratch,
        "TMPDIR": scratch,
        "TEST_TMPDIR": scratch,
    }


def classify(exit_code: int, wall_us: int, timeout_s: int) -> str:
    deadline_us = timeout_s * 1_000_000
    if exit_code in (124, 137) and wall_us >= deadline_us:
        return "timeout"
    if exit_code > 128:
        return "signal"
    return "normal"


def parse_state_file(path) -> dict:
    state = {}
    for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            state[key] = value
    for required in ("port", "key", "pidfile"):
        if not state.get(required):
            raise BackendError("state file %s lacks %s=" % (path, required))
    return state


def _timeout_tool() -> str:
    return shutil.which("gtimeout") or "timeout"


def _limits_and_umask():
    os.umask(0o022)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    stack = 8192 * 1024
    resource.setrlimit(resource.RLIMIT_STACK, (stack, stack))


class ElfuseBackend:
    name = "elfuse"

    def __init__(self, binary, sysroot=None):
        self.binary = pathlib.Path(binary)
        self.sysroot = pathlib.Path(sysroot) if sysroot else None

    def start(self) -> None:
        if not self.binary.is_file():
            raise BackendError("elfuse binary is absent: %s" % self.binary)

    def stop(self) -> None:
        pass

    def host_to_guest(self, host_path) -> str:
        return str(host_path)

    def run(self, argv, *, timeout_s, scratch, env_extra=None,
            fetch_files=()) -> Invocation:
        # fetch_files is part of the shared contract: files the guest
        # command writes into its working directory that the caller needs
        # back in scratch. Here the guest cwd IS scratch, so nothing to do.
        del fetch_files
        scratch = pathlib.Path(scratch)
        stdout = scratch / "stdout.log"
        stderr = scratch / "stderr.log"
        command = [_timeout_tool(), "--kill-after=5", str(timeout_s),
                   str(self.binary), "--timeout", "0"]
        if self.sysroot:
            command += ["--sysroot", str(self.sysroot)]
        command += [str(a) for a in argv]
        env = guest_environment(scratch)
        env.update(env_extra or {})
        start = time.monotonic_ns()
        with open(stdout, "wb") as out, open(stderr, "wb") as err:
            result = subprocess.run(command, stdout=out, stderr=err,
                                    stdin=subprocess.DEVNULL, env=env,
                                    cwd=str(scratch),
                                    preexec_fn=_limits_and_umask)
        wall_us = (time.monotonic_ns() - start) // 1000
        # GNU timeout re-raises the child's fatal signal at itself, so
        # subprocess reports a negative returncode; normalize to the shell
        # convention (128 + signal) that classify() speaks.
        exit_code = result.returncode
        if exit_code < 0:
            exit_code = 128 - exit_code
        return Invocation(
            exit_code=exit_code,
            execution=classify(exit_code, wall_us, timeout_s),
            wall_us=wall_us, stdout=stdout, stderr=stderr)


class QemuBackend:
    name = "qemu"

    def __init__(self, qemu_mem=None):
        self.qemu_mem = qemu_mem
        self.runtime = None
        self.state = None

    def start(self) -> None:
        if self.state:
            return
        self.runtime = pathlib.Path(tempfile.mkdtemp(prefix="conf-qemu-"))
        state_file = self.runtime / "state"
        try:
            env = dict(os.environ)
            if self.qemu_mem:
                env["QEMU_MEM"] = str(self.qemu_mem)
            result = subprocess.run(
                ["bash", str(QEMU_RUNNER), "start", "--state-file",
                 str(state_file)], env=env)
            if result.returncode != 0:
                raise BackendError("qemu-runner start failed (%d)"
                                   % result.returncode)
            self.state = parse_state_file(state_file)
            self._master(restart=False)
        except Exception as exc:
            self.stop()
            if isinstance(exc, BackendError):
                raise
            raise BackendError("reference VM setup failed: %s" % exc) from exc

    def stop(self) -> None:
        runtime = self.runtime
        if self.state:
            subprocess.run(
                self._ssh_base() + ["-O", "exit", "root@127.0.0.1"],
                capture_output=True)
        if runtime and (runtime / "state").is_file():
            subprocess.run(
                ["bash", str(QEMU_RUNNER), "stop", "--state-file",
                 str(runtime / "state")], capture_output=True)
        if runtime:
            shutil.rmtree(runtime, ignore_errors=True)
        self.state = None
        self.runtime = None

    def host_to_guest(self, host_path) -> str:
        host_path = pathlib.Path(host_path).resolve()
        try:
            return "/mnt/host/%s" % host_path.relative_to(REPO_ROOT)
        except ValueError:
            raise BackendError(
                "%s is outside the repo root, unreachable over the 9p share"
                % host_path)

    def _ssh_base(self) -> list:
        return [
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=6",
            "-o", "ControlMaster=auto",
            "-o", "ControlPath=%s" % (self.runtime / "ctl"),
            "-o", "ControlPersist=600",
            "-i", self.state["key"], "-p", self.state["port"],
        ]

    def _master(self, restart: bool) -> None:
        if restart:
            subprocess.run(
                self._ssh_base() + ["-O", "exit", "root@127.0.0.1"],
                capture_output=True)
        probe = subprocess.run(
            self._ssh_base() + ["root@127.0.0.1", "true"],
            capture_output=True)
        if probe.returncode != 0:
            raise BackendError("cannot reach the reference VM over ssh")

    def _remote(self, script: str, stdout_path, cap_s: int):
        with open(stdout_path, "wb") as out:
            return subprocess.run(
                self._ssh_base() + ["root@127.0.0.1", script],
                stdout=out, stderr=subprocess.PIPE,
                timeout=cap_s)

    def run(self, argv, *, timeout_s, scratch, env_extra=None,
            fetch_files=()) -> Invocation:
        scratch = pathlib.Path(scratch)
        stdout = scratch / "stdout.log"
        stderr = scratch / "stderr.log"
        env = guest_environment("$d")
        env.update(env_extra or {})
        exports = "; ".join(
            "export %s=%s" % (k, v if v == "$d" else shlex.quote(str(v)))
            for k, v in env.items())
        unsets = "unset %s" % " ".join(SCRUB_ENV)
        quoted = " ".join(shlex.quote(str(a)) for a in argv)
        # The RC: sentinel separates a legitimate in-guest exit (any code,
        # 255 included) from ssh's own 255 on transport loss.
        script = (
            'd=$(mktemp -d /tmp/conf.XXXXXX) && cd "$d" && umask 022 && '
            "ulimit -c 0 -s 8192 -n 1024 && %s && %s && "
            '/usr/bin/timeout --kill-after=5 %d %s > "$d/stdout" '
            '2> "$d/stderr"; printf "RC:%%s D:%%s\\n" "$?" "$d"'
            % (unsets, exports, timeout_s, quoted))
        cap = timeout_s + 30
        start = time.monotonic_ns()
        for attempt in (1, 2):
            rc_file = scratch / "rc.txt"
            try:
                result = self._remote(script, rc_file, cap)
            except subprocess.TimeoutExpired:
                raise BackendError("ssh command exceeded its cap (%ds)" % cap)
            text = rc_file.read_text(encoding="utf-8", errors="replace")
            if result.returncode == 255 and "RC:" not in text:
                if attempt == 1:
                    self._master(restart=True)
                    continue
                wall_us = (time.monotonic_ns() - start) // 1000
                stdout.write_bytes(b"")
                stderr.write_bytes(result.stderr or b"")
                return Invocation(exit_code=255, execution="transport",
                                  wall_us=wall_us, stdout=stdout,
                                  stderr=stderr)
            break
        wall_us = (time.monotonic_ns() - start) // 1000
        rc_line = [l for l in text.splitlines() if l.startswith("RC:")]
        if not rc_line:
            raise BackendError("remote script printed no RC: line")
        head = rc_line[-1].split()
        exit_code = int(head[0][3:])
        guest_dir = head[1][2:]
        self._remote("cat %s/stdout" % shlex.quote(guest_dir), stdout,
                     cap_s=60)
        self._remote("cat %s/stderr" % shlex.quote(guest_dir), stderr,
                     cap_s=60)
        for name in fetch_files:
            self._remote("cat %s/%s" % (shlex.quote(guest_dir),
                                        shlex.quote(name)),
                         scratch / name, cap_s=120)
        self._remote("rm -rf %s" % shlex.quote(guest_dir),
                     scratch / "cleanup.txt", cap_s=60)
        return Invocation(
            exit_code=exit_code,
            execution=classify(exit_code, wall_us, timeout_s),
            wall_us=wall_us, stdout=stdout, stderr=stderr)

    def fetch(self, guest_path, host_path) -> None:
        result = self._remote("cat %s" % shlex.quote(str(guest_path)),
                              host_path, cap_s=120)
        if result.returncode != 0:
            raise BackendError("cannot fetch %s from the VM" % guest_path)
