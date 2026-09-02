# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import os
import stat
import unittest
import unittest.mock
from pathlib import Path

from conformance import sweep
from conformance.backends import qemu
from conformance.selftest.fixture import TempDirTest
from conformance.selftest.test_backends import script

BIN = "/repo/build/elfuse"
SHARE = "-fsdev local,id=share,path=%s,security_model=none,readonly=on"
PS = "\n".join([
    "  40     1   40  501 ??       %s --timeout 0 /bin/true" % BIN,
    "  41    40   40  501 ??       %s --fork-child 8" % BIN,
    "  42     1   42  501 ttys003  %s --timeout 0 /bin/true" % BIN,
    "  43     1   43  501 ??       %s /bin/true" % BIN,
    "  44     1   44  502 ??       %s --timeout 0 /bin/true" % BIN,
    "  46     1   40  501 ??       %s --fork-child 9" % BIN,
    "  47     1   47  501 ??       %s --fork-child 9" % BIN,
    "  48     1   48  501 ??       /other/build/elfuse --fork-child 9",
    "  50     1   50  501 ??       qemu-system-aarch64 -machine virt %s"
    " -pidfile /var/T/elfuse-qemu.XXXXXX.abc/qemu.pid" % (SHARE % "/repo"),
    "  51     1   51  501 ??       qemu-system-aarch64 %s"
    " -pidfile /var/T/elfuse-qemu.XXXXXX.def/qemu.pid" % (SHARE % "/elsewhere"),
    "  52   900   52  501 ??       qemu-system-aarch64 %s"
    " -pidfile /var/T/elfuse-qemu.XXXXXX.ghi/qemu.pid" % (SHARE % "/repo"),
    "  60     1   60  501 ttys001  /bin/zsh -c ls /Users/x/code/elfuse/src",
    "  61     1   61  501 ??       (elfuse)",
]) + "\n"
IPCS_M = ("IPC status from <running system> as of Wed Sep  2 10:04:00 CEST 2026\n"
          "T     ID     KEY        MODE       OWNER    GROUP  CPID  LPID\n"
          "Shared Memory:\n"
          "m  65536 0x00000000 --rw------- henry    staff  4321  4321\n"
          "m  65537 0x0000abcd --rw------- henry    staff  4322  4322\n\n")
IPCS_Q = ("T     ID     KEY        MODE       OWNER    GROUP LSPID LRPID\n"
          "Message Queues:\n"
          "q      0 0x00000000 --rw------- henry    staff     0     0\n"
          "q      1 0x00000000 --rw------- henry    staff  4321     0\n\n")
IPCS_S = ("T     ID     KEY        MODE       OWNER    GROUP\n"
          "Semaphores:\n"
          "s 393216 0x6111bfce --ra-ra-ra- root     wheel\n\n")


def pids(procs):
    return [p.pid for p in procs]


class MatcherTest(unittest.TestCase):
    def setUp(self):
        self.procs = sweep.processes(PS)

    def test_only_a_detached_harness_leader_is_a_guest_group(self):
        self.assertEqual(pids(sweep.guest_groups(self.procs, BIN, 501)), [40])

    def test_fork_orphans_need_ppid_one_and_this_binary(self):
        self.assertEqual(pids(sweep.fork_orphans(self.procs, BIN, 501)), [46, 47])

    def test_a_stray_vm_names_this_checkout_and_is_reparented(self):
        found = sweep.stray_qemu(self.procs, Path("/repo"), 501)
        self.assertEqual([(p.pid, str(f)) for p, f in found],
                         [(50, "/var/T/elfuse-qemu.XXXXXX.abc/qemu.pid")])

    def test_a_pathname_mentioning_elfuse_is_not_a_live_elfuse(self):
        self.assertEqual(pids(sweep.live_elfuse(self.procs, 501)),
                         [40, 41, 42, 43, 46, 47, 48])

    def test_ipc_rows_skip_the_preamble(self):
        rows = sweep.ipc_rows(IPCS_M + IPCS_Q + IPCS_S)
        self.assertEqual([(r.kind, r.ident, r.pids) for r in rows], [
            ("m", 65536, (4321, 4321)), ("m", 65537, (4322, 4322)),
            ("q", 0, (0, 0)), ("q", 1, (4321, 0)), ("s", 393216, ()),
        ])

    def test_dead_ipc_reports_only_what_a_dead_pid_owned(self):
        rows = sweep.ipc_rows(IPCS_M + IPCS_Q + IPCS_S)
        leaked, keep = sweep.dead_ipc(rows, lambda pid: pid == 4322)
        self.assertEqual([(r.kind, r.ident) for r, _ in leaked], [("m", 65536), ("q", 1)])
        self.assertEqual([(r.kind, r.ident) for r, _ in keep],
                         [("m", 65537), ("q", 0), ("s", 393216)])
        self.assertEqual(keep[2][1], "no creator pid in ipcs")


class PlantedTest(TempDirTest):
    def plant(self):
        self.tmp, self.user_tmp, self.t = self.dir / "tmp", self.dir / "ut", self.dir / "T"
        for rel in ("tmp/elfuse-fork-Ab12Cd", "tmp/elfuse-task-Ab12Cd/123",
                    "tmp/elfuse-absock-42", "tmp/elfuse-shm-501",
                    "tmp/elfuse-review-clone.abc", "tmp/elfuse-conf-split.abc",
                    "tmp/elfuse-fork-toolong1", "tmp/elfuse-fork-Ab12C",
                    "T/elfuse-qemu.XXXXXX.abc", "T/elfuse-qemu.XXXXXX.def", "ut"):
            (self.dir / rel).mkdir(parents=True)
        for rel in ("tmp/elfuse-fork-Ab12Cd/snap", "tmp/elfuse-fuse-exec.Ab12Cd",
                    "tmp/elfuse-absock-42/x", "tmp/elfuse-shm-501/f",
                    "tmp/elfuse-shm-502", "tmp/elfuse-pr341-comments.json",
                    "T/elfuse-qemu.XXXXXX.abc/qemu.pid", "T/elfuse-qemu.XXXXXX.def/qemu.pid",
                    "T/elfuse-qemu.plainfile", "ut/elfuse-sig-4321", "ut/elfuse-procs-77",
                    "ut/elfuse-sig-x"):
            (self.dir / rel).write_text("")

    def names(self, root):
        return sorted(p.name for p in root.iterdir())


class LayoutTest(PlantedTest):
    def test_runtime_paths_match_the_fixed_templates_only(self):
        self.plant()
        found = sweep.runtime_paths(self.tmp, self.user_tmp, 501)
        self.assertEqual([str(p.relative_to(self.dir)) for p in found], [
            "tmp/elfuse-absock-42", "tmp/elfuse-fork-Ab12Cd", "tmp/elfuse-fuse-exec.Ab12Cd",
            "tmp/elfuse-shm-501/f", "tmp/elfuse-task-Ab12Cd",
            "ut/elfuse-procs-77", "ut/elfuse-sig-4321",
        ])
        self.assertEqual(sweep.runtime_paths(self.dir / "absent", None, 501), [])

    def test_qemu_rundirs_are_directories_under_every_root(self):
        self.plant()
        found = sweep.qemu_rundirs([self.t, self.dir / "absent"])
        self.assertEqual([p.name for p in found],
                         ["elfuse-qemu.XXXXXX.abc", "elfuse-qemu.XXXXXX.def"])

    @unittest.skipIf(os.geteuid() == 0, "root ignores directory permissions")
    def test_fix_modes_opens_nested_directories(self):
        root = self.dir / "results"
        inner = root / "a" / "gvisor_test_temp_1" / "b" / "gvisor_test_temp_2"
        inner.mkdir(parents=True)
        (root / "a" / "link").symlink_to("/")
        (inner.parent / "b2").mkdir()
        inner.chmod(0)
        (root / "a" / "gvisor_test_temp_1").chmod(0o500)
        try:
            listed = sweep.fix_modes(root, apply=False)
            self.assertEqual(listed, [root / "a" / "gvisor_test_temp_1"])
            fixed = sweep.fix_modes(root, apply=True)
            self.assertEqual(sorted(fixed), sorted([root / "a" / "gvisor_test_temp_1", inner]))
            self.assertEqual(stat.S_IMODE(inner.stat().st_mode) & 0o700, 0o700)
            self.assertEqual(sweep.fix_modes(root, apply=True), [])
        finally:
            for d in (inner, inner.parents[1]):
                d.chmod(0o700)


class SweepTest(PlantedTest):
    def setUp(self):
        super().setUp()
        self.plant()
        self.out, self.err = [], []
        self.state_dir = self.dir / "state"
        self.state_dir.mkdir()
        self.verbs = self.dir / "verbs"
        self.runner = script(self.dir / "runner.sh",
                             'echo "$1" >> "%s"\n[ "$1" = stop ] && rm -f "$3"\nexit 0\n'
                             % self.verbs)

    def sweep(self, ps="", dry_run=False, runner=None):
        backend = qemu.QemuBackend(self.dir, runner=runner or self.runner, state_dir=self.state_dir)
        job = sweep.Sweep(self.dir, self.dir / "results", self.out.append, self.err.append,
                          dry_run=dry_run, uid=501, tmp=self.tmp, user_tmp=self.user_tmp,
                          roots=[self.t], qemu=backend)
        ipcs = {"m": IPCS_M, "q": IPCS_Q, "s": IPCS_S}
        listings = ps if isinstance(ps, list) else [ps, ps]
        with unittest.mock.patch.object(sweep, "ps_listing", side_effect=listings), \
                unittest.mock.patch.object(sweep, "ipcs_listing", lambda kind, uid: ipcs[kind]), \
                unittest.mock.patch.object(sweep, "alive", lambda pid: pid == 4322), \
                unittest.mock.patch.object(sweep.subprocess, "run") as run:
            ok = job.run()
        return ok, run

    def test_a_dead_host_is_swept_and_decoys_survive(self):
        (self.state_dir / "qemu.state").write_text(
            "port=1\nkey=/k\npidfile=%s/elfuse-qemu.XXXXXX.abc/qemu.pid\n" % self.t)
        ok, run = self.sweep()
        self.assertTrue(ok, self.err)
        self.assertEqual(self.err, [])
        self.assertEqual(self.verbs.read_text().split(), ["stop"])
        self.assertEqual(self.names(self.tmp), [
            "elfuse-conf-split.abc", "elfuse-fork-Ab12C", "elfuse-fork-toolong1",
            "elfuse-pr341-comments.json", "elfuse-review-clone.abc",
            "elfuse-shm-501", "elfuse-shm-502",
        ])
        self.assertEqual(self.names(self.tmp / "elfuse-shm-501"), [])
        self.assertEqual(self.names(self.user_tmp), ["elfuse-sig-x"])
        self.assertEqual(self.names(self.t), ["elfuse-qemu.plainfile"])
        self.assertEqual(run.call_args_list, [])  # SysV objects are reported only
        self.assertIn("leaked ipc -m 65536: cpid 4321 dead; ipcrm -m 65536 by hand", self.out)
        self.assertIn("leaked ipc -q 1: pids 4321 dead; ipcrm -q 1 by hand", self.out)
        self.assertIn("keep ipc -s: 1 sets, no creator pid in ipcs; ipcrm -s ID by hand", self.out)
        self.assertIn("keep ipc -m 65537: cpid 4322 alive", self.out)
        self.assertIn("keep ipc -q 0: never used; ipcrm -q 0 by hand", self.out)
        self.assertNotIn("keep runtime scratch", " ".join(self.out))

    def test_dry_run_reports_the_same_actions_and_touches_nothing(self):
        before = sorted(str(p) for p in self.dir.rglob("*"))
        ok, run = self.sweep(dry_run=True)
        self.assertTrue(ok)
        self.assertEqual(sorted(str(p) for p in self.dir.rglob("*")), before)
        self.assertEqual(run.call_args_list, [])
        self.assertTrue(all(line.startswith(("would ", "keep ", "leaked ")) for line in self.out),
                        self.out)
        self.assertIn("would rm -rf %s" % (self.tmp / "elfuse-fork-Ab12Cd"), self.out)
        self.assertIn("leaked ipc -m 65536: cpid 4321 dead; ipcrm -m 65536 by hand", self.out)

    def test_a_live_elfuse_keeps_the_runtime_scratch(self):
        ok, run = self.sweep(ps="  70     1   70  501 ??       /other/build/elfuse /bin/true\n")
        self.assertTrue(ok)
        self.assertIn("keep runtime scratch: elfuse pids 70 are alive", self.out)
        self.assertTrue((self.tmp / "elfuse-fork-Ab12Cd").is_dir())
        self.assertEqual(run.call_args_list, [])

    def test_kills_target_only_this_checkout(self):
        binary = str(self.dir / "build" / "elfuse")
        ps = ("  40     1   40  501 ??       %s --timeout 0 /bin/true\n"
              "  46     1   40  501 ??       %s --fork-child 9\n"
              "  47     1   47  501 ??       %s --fork-child 9\n"
              "  50     1   50  501 ??       qemu-system-aarch64 %s -pidfile %s/elfuse-qemu.XXXXXX.abc/qemu.pid\n"
              "  51     1   51  501 ??       qemu-system-aarch64 %s -pidfile %s/elfuse-qemu.XXXXXX.def/qemu.pid\n"
              % (binary, binary, binary, SHARE % self.dir, self.t, SHARE % "/elsewhere", self.t))
        with unittest.mock.patch.object(sweep.os, "killpg") as killpg, \
                unittest.mock.patch.object(sweep.os, "kill") as kill, \
                unittest.mock.patch.object(sweep, "terminate") as terminate:
            ok, run = self.sweep(ps=ps)
        self.assertTrue(ok, self.err)
        self.assertEqual(terminate.call_args_list, [unittest.mock.call(50)])
        self.assertEqual(killpg.call_args_list, [unittest.mock.call(40, sweep.signal.SIGKILL)])
        self.assertEqual(kill.call_args_list, [unittest.mock.call(47, sweep.signal.SIGKILL)])
        # The other checkout's VM keeps its rundir; ours goes with its process,
        # and with every guest gone the scratch sweep runs.
        self.assertEqual(self.names(self.t), ["elfuse-qemu.XXXXXX.def", "elfuse-qemu.plainfile"])
        self.assertFalse((self.tmp / "elfuse-fork-Ab12Cd").exists())

    def test_the_stopped_vm_is_not_signalled_again(self):
        rundir = self.t / "elfuse-qemu.XXXXXX.abc"
        pidfile = rundir / "qemu.pid"
        (self.state_dir / "qemu.state").write_text(
            "port=1\nkey=/k\npidfile=%s\n" % pidfile)
        # qemu-runner.sh disowns the VM, so it outlives the shell that started
        # it and is still in the pre-stop snapshot the sweep works from.
        ps = ("  50     1   50  501 ??       qemu-system-aarch64 %s -pidfile %s\n"
              % (SHARE % self.dir, pidfile))
        with unittest.mock.patch.object(sweep, "terminate") as terminate:
            ok, _ = self.sweep(ps=ps)
        self.assertTrue(ok, self.err)
        self.assertEqual(self.err, [])
        self.assertEqual(terminate.call_args_list, [])
        self.assertEqual(self.verbs.read_text().split(), ["stop"])
        self.assertEqual(self.names(self.t), ["elfuse-qemu.plainfile"])

    def test_a_results_tree_it_cannot_walk_is_reported(self):
        (self.dir / "results").mkdir()
        with unittest.mock.patch.object(sweep, "fix_modes",
                                        side_effect=OSError(13, "Permission denied")):
            ok, _ = self.sweep()
        self.assertFalse(ok)
        self.assertIn("chmod u+rwx under", self.err[0])

    def test_a_vm_that_exits_during_the_sweep_loses_its_rundir(self):
        ps = ("  51     1   51  501 ??       qemu-system-aarch64 %s -pidfile %s\n"
              % (SHARE % "/elsewhere", self.t / "elfuse-qemu.XXXXXX.def" / "qemu.pid"))
        ok, _ = self.sweep(ps=[ps, ""])
        self.assertTrue(ok, self.err)
        self.assertEqual(self.names(self.t), ["elfuse-qemu.plainfile"])

    def test_a_state_file_naming_a_live_vm_survives_a_failed_stop(self):
        runner = script(self.dir / "failing.sh", 'echo "no such vm"; exit 1\n')
        state = self.state_dir / "qemu.state"
        pidfile = "%s/elfuse-qemu.XXXXXX.def/qemu.pid" % self.t
        state.write_text("port=1\nkey=/k\npidfile=%s\n" % pidfile)
        ps = ("  51     1   51  501 ??       qemu-system-aarch64 %s -pidfile %s\n"
              % (SHARE % "/elsewhere", pidfile))
        ok, run = self.sweep(ps=ps, runner=runner)
        self.assertFalse(ok)
        self.assertIn("no such vm", self.err[0])
        self.assertTrue(state.exists())
        self.assertTrue((self.t / "elfuse-qemu.XXXXXX.def").is_dir())
        self.assertFalse((self.t / "elfuse-qemu.XXXXXX.abc").exists())


if __name__ == "__main__":
    unittest.main()
