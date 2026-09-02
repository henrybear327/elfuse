# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable, Iterable, List, NamedTuple, Optional, Tuple

from conformance.backends.base import BackendError
from conformance.backends.elfuse import ElfuseBackend
from conformance.backends.qemu import QemuBackend, parse_state

# elfuse names its host scratch with fixed templates (src/runtime/procemu.c,
# procemu-pty.c, forkipc.c, usb-sysfs.c, src/syscall/fuse.c, net-absock.c,
# proc.c). Review scratch shares the elfuse- prefix, so only these exact
# shapes are swept. The tmpfile_anon files in src/utils.h are unlinked at
# creation, so no name of theirs survives a kill.
RUNTIME_NAME = re.compile(
    r"elfuse-(?:fork|proc|syscpu|tid|task|fd|fdinfo|pts|usbsys|usbdev)-[A-Za-z0-9]{6}$"
    r"|elfuse-fuse-exec\.[A-Za-z0-9]{6}$"
    r"|elfuse-absock-[0-9]+$"
)
TRANSPORT_NAME = re.compile(r"elfuse-(?:sig|procs|life|pidseq)-[0-9]+$")
# macOS mktemp keeps the literal XXXXXX and appends its own suffix.
QEMU_PIDFILE = re.compile(r" -pidfile (\S+/elfuse-qemu\.[^/\s]+/qemu\.pid)(?= |$)")
TERM_WAIT_S = 5


class Process(NamedTuple):
    pid: int
    ppid: int
    pgid: int
    uid: int
    tty: str
    command: str


class IpcRow(NamedTuple):
    kind: str
    ident: int
    pids: Tuple[int, ...]


def ps_listing() -> str:
    return subprocess.run(["ps", "-eo", "pid=,ppid=,pgid=,uid=,tty=,command="],
                          capture_output=True, text=True).stdout


def ipcs_listing(kind: str, uid: int) -> str:
    argv = ["ipcs", "-" + kind, "-u", str(uid)]
    if kind != "s":
        argv.insert(2, "-p")
    return subprocess.run(argv, capture_output=True, text=True).stdout


def user_temp_dir() -> Optional[Path]:
    """The per-user temp dir elfuse's proc.c transports live in (macOS only)."""
    done = subprocess.run(["getconf", "DARWIN_USER_TEMP_DIR"],
                          capture_output=True, text=True)
    text = done.stdout.strip()
    return Path(text) if done.returncode == 0 and text else None


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    return True


def processes(ps_text: str) -> List[Process]:
    out = []
    for line in ps_text.splitlines():
        fields = line.split(None, 5)
        if len(fields) == 6:
            out.append(Process(int(fields[0]), int(fields[1]), int(fields[2]),
                               int(fields[3]), fields[4], fields[5]))
    return out


def guest_groups(procs: Iterable[Process], binary: str, uid: int) -> List[Process]:
    """Session leaders the harness started: backends/proc.py spawns each case
    with start_new_session, so its pid is the pgid, while a make lane inherits
    make's group. An interactive run is spared by its tty."""
    return [p for p in procs
            if p.uid == uid and p.pgid == p.pid and p.tty in ("??", "?")
            and p.command.startswith(binary + " --timeout 0 ")]


def fork_orphans(procs: Iterable[Process], binary: str, uid: int) -> List[Process]:
    return [p for p in procs
            if p.uid == uid and p.ppid == 1 and p.command.startswith(binary + " ")
            and "--fork-child" in p.command.split()]


def qemu_pidfile(p: Process) -> Optional[Path]:
    m = QEMU_PIDFILE.search(p.command)
    return Path(m.group(1)) if m else None


def stray_qemu(procs: Iterable[Process], repo_root: Path, uid: int) -> List[Tuple[Process, Path]]:
    """VMs qemu-runner.sh disowned for this checkout; the 9p share names the
    checkout, so another worktree's VM does not match."""
    shares = {"path=%s," % root for root in (repo_root, repo_root.resolve())}
    out = []
    for p in procs:
        pidfile = qemu_pidfile(p)
        if (pidfile is not None and p.uid == uid and p.ppid == 1
                and any(share in p.command for share in shares)):
            out.append((p, pidfile))
    return out


def live_elfuse(procs: Iterable[Process], uid: int) -> List[Process]:
    """Any elfuse of this uid, whatever its checkout: the /tmp scratch names are
    shared by all of them."""
    return [p for p in procs
            if p.uid == uid and os.path.basename(p.command.split(None, 1)[0]) == "elfuse"]


def runtime_paths(tmp: Path, user_tmp: Optional[Path], uid: int) -> List[Path]:
    out = [p for p in tmp.iterdir() if RUNTIME_NAME.match(p.name)] if tmp.is_dir() else []
    shm = tmp / ("elfuse-shm-%d" % uid)
    if shm.is_dir():
        out += list(shm.iterdir())  # the dir itself is shared by every elfuse of the uid
    if user_tmp is not None and user_tmp.is_dir():
        out += [p for p in user_tmp.iterdir() if TRANSPORT_NAME.match(p.name)]
    return sorted(out)


def qemu_rundirs(roots: Iterable[Path]) -> List[Path]:
    out = []
    for root in roots:
        if root.is_dir():
            out += [p for p in root.iterdir()
                    if p.name.startswith("elfuse-qemu.") and p.is_dir() and not p.is_symlink()]
    return sorted(out)


def temp_roots() -> List[Path]:
    """mktemp -t and Python disagree on the default when TMPDIR is unset."""
    out: List[Path] = []
    for root in (Path(tempfile.gettempdir()), user_temp_dir(), Path("/tmp")):
        if root is not None and root.resolve() not in [r.resolve() for r in out]:
            out.append(root)
    return out


def ipc_rows(text: str) -> List[IpcRow]:
    """Rows of ipcs -m -p / -q -p / -s on macOS: T ID KEY MODE OWNER GROUP, then
    CPID LPID for shm and LSPID LRPID for queues; semaphores carry no pid."""
    out = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 6 and fields[0] in ("m", "q", "s") and fields[1].isdigit():
            pids = tuple(int(f) for f in fields[6:8] if f.isdigit())
            out.append(IpcRow(fields[0], int(fields[1]), pids))
    return out


def dead_ipc(rows: Iterable[IpcRow], is_alive: Callable[[int], bool]
             ) -> Tuple[List[Tuple[IpcRow, str]], List[Tuple[IpcRow, str]]]:
    """Split SysV objects into leaked and kept, each with its reason."""
    leaked_rows, keep_rows = [], []
    for row in rows:
        if row.kind == "s":
            keep_rows.append((row, "no creator pid in ipcs"))
        elif row.kind == "m":
            cpid = row.pids[0] if row.pids else 0
            if not cpid:
                keep_rows.append((row, "no creator pid in ipcs"))
            elif not is_alive(cpid):
                leaked_rows.append((row, "cpid %d dead" % cpid))
            else:
                keep_rows.append((row, "cpid %d alive" % cpid))
        else:
            users = [pid for pid in row.pids if pid]
            if not users:
                keep_rows.append((row, "never used; ipcrm -q %d by hand" % row.ident))
            elif all(not is_alive(pid) for pid in users):
                leaked_rows.append((row, "pids %s dead" % " ".join(map(str, users))))
            else:
                keep_rows.append((row, "in use"))
    return leaked_rows, keep_rows


def fix_modes(root: Path, apply: bool) -> List[Path]:
    """Directories rm -rf cannot descend into. Without apply the walk stops at
    each one, since a mode 0 directory cannot be opened to look below it."""
    out = []
    stack = [root]
    while stack:
        d = stack.pop()
        mode = stat.S_IMODE(os.lstat(d).st_mode)
        if mode & 0o700 != 0o700:
            out.append(d)
            if not apply:
                continue
            os.chmod(d, mode | 0o700)
        with os.scandir(d) as entries:
            stack += [Path(e.path) for e in entries if e.is_dir(follow_symlinks=False)]
    return out


def lock_openers(paths: Iterable[Path]) -> List[int]:
    """lsof names openers, not flock holders; serialize() keeps the fd open only
    while it holds the lock, so here the two coincide."""
    pids = set()
    for path in paths:
        if path.exists():
            done = subprocess.run(["lsof", "-t", str(path)], capture_output=True, text=True)
            pids.update(int(pid) for pid in done.stdout.split() if pid.isdigit())
    return sorted(pids)


def remove(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def terminate(pid: int) -> None:
    """A pid already gone is the goal, not a failure."""
    try:
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + TERM_WAIT_S
        while time.monotonic() < deadline:
            if not alive(pid):
                return
            time.sleep(0.1)
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


class Sweep:
    """Order matters: the VM goes before its state record, kills before the
    scratch sweep, and the scratch sweep only when no elfuse is left alive."""

    def __init__(self, repo_root: Path, results: Path, out: Callable[[str], None],
                 fail: Callable[[str], None], dry_run: bool = False,
                 uid: Optional[int] = None, tmp: Path = Path("/tmp"),
                 user_tmp: Optional[Path] = None, roots: Optional[List[Path]] = None,
                 qemu: Optional[QemuBackend] = None):
        self.repo_root = repo_root
        self.results = results
        self.out = out
        self.fail = fail
        self.dry_run = dry_run
        self.uid = os.getuid() if uid is None else uid
        self.tmp = tmp
        self.user_tmp = user_temp_dir() if user_tmp is None else user_tmp
        self.roots = temp_roots() if roots is None else roots
        self.qemu = qemu or QemuBackend(repo_root)
        self.elfuse = ElfuseBackend(repo_root)
        self.failed = False

    def act(self, line: str, action: Callable[[], None]) -> bool:
        self.out(("would " if self.dry_run else "") + line)
        if self.dry_run:
            return True
        try:
            action()
        except (OSError, BackendError) as e:
            self.fail("%s: %s" % (line, e))
            self.failed = True
            return False
        return True

    def run(self) -> bool:
        procs = processes(ps_listing())
        self.stop_qemu(procs)
        gone = self.kill_guests(procs)
        left = [p for p in live_elfuse(procs, self.uid)
                if p.pid not in gone and p.pgid not in gone]
        if left:
            self.out("keep runtime scratch: elfuse pids %s are alive"
                     % " ".join(str(p.pid) for p in left))
        else:
            self.sweep_runtime()
            self.report_ipc()
        if self.results.is_dir():
            self.fix_results_modes()
        return not self.failed

    def fix_results_modes(self) -> None:
        try:
            found = fix_modes(self.results, not self.dry_run)
        except OSError as e:
            self.fail("chmod u+rwx under %s: %s" % (self.results, e))
            self.failed = True
            return
        for d in found:
            self.out(("would " if self.dry_run else "") + "chmod u+rwx %s" % d)

    def stop_qemu(self, procs: List[Process]) -> None:
        state = self.qemu.state_file
        stopped = None
        if state.exists():
            named = parse_state(state.read_text()).get("pidfile")
            if self.act("stop qemu %s" % state, self.qemu.stop) and named is not None:
                stopped = Path(named)
        killed = set()
        for p, pidfile in stray_qemu(procs, self.repo_root, self.uid):
            # ps is a pre-stop snapshot, and a VM the runner disowned outlives
            # its shell, so the one just stopped still matches here.
            if pidfile == stopped:
                killed.add(pidfile)
                continue
            if self.act("kill -TERM %d qemu-system-aarch64 (-pidfile %s)" % (p.pid, pidfile),
                        lambda pid=p.pid: terminate(pid)):
                killed.add(pidfile)
        # A fresh listing: a VM that exited on its own during the sweep would
        # otherwise still read as referenced, and keep its rundir.
        live = processes(ps_listing())
        referenced = {f for f in map(qemu_pidfile, live) if f is not None} - killed
        for rundir in qemu_rundirs(self.roots):
            if rundir / "qemu.pid" not in referenced:
                self.act("rm -rf %s" % rundir, lambda d=rundir: shutil.rmtree(d))
        for leftover in (state, state.with_name(state.name + ".tmp")):
            if not leftover.exists():
                continue
            named = parse_state(leftover.read_text()).get("pidfile")
            if named is None or Path(named) not in referenced:
                self.act("rm -f %s" % leftover, leftover.unlink)

    def kill_guests(self, procs: List[Process]) -> set:
        binary = str(self.elfuse.binary)
        gone = set()
        for p in guest_groups(procs, binary, self.uid):
            if self.act("killpg -KILL %d %s" % (p.pgid, p.command),
                        lambda pgid=p.pgid: os.killpg(pgid, signal.SIGKILL)):
                gone.add(p.pgid)
        for p in fork_orphans(procs, binary, self.uid):
            if p.pgid in gone:
                continue
            if self.act("kill -KILL %d %s" % (p.pid, p.command),
                        lambda pid=p.pid: os.kill(pid, signal.SIGKILL)):
                gone.add(p.pid)
        return gone

    def sweep_runtime(self) -> None:
        for path in runtime_paths(self.tmp, self.user_tmp, self.uid):
            self.act("rm -rf %s" % path, lambda p=path: remove(p))

    def report_ipc(self) -> None:
        """Report only. sys_shmget and sys_msgget forward the guest key to the
        host unchanged, so an elfuse object is indistinguishable from any other
        of the user's, and outliving its creator is ordinary SysV lifecycle."""
        rows = [row for kind in ("m", "q", "s") for row in ipc_rows(ipcs_listing(kind, self.uid))]
        leaked_rows, keep_rows = dead_ipc(rows, alive)
        for row, why in leaked_rows:
            self.out("leaked ipc -%s %d: %s; ipcrm -%s %d by hand"
                     % (row.kind, row.ident, why, row.kind, row.ident))
        sems = [row for row, _ in keep_rows if row.kind == "s"]
        for row, why in keep_rows:
            if row.kind != "s":
                self.out("keep ipc -%s %d: %s" % (row.kind, row.ident, why))
        if sems:  # one line, not one per set: a leaked run leaves thousands
            self.out("keep ipc -s: %d sets, no creator pid in ipcs; ipcrm -s ID by hand" % len(sems))
