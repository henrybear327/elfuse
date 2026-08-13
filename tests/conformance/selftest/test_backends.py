"""Selftests for the backend execution seam.

The classification rule is the contract every provider builds on: exit
124/137 from timeout(1) at or past the deadline is TIMEOUT, another exit
above 128 is a signal death, everything else ran to completion. Guest
environment normalization is written once here for both providers and
both kirk channels, so its content is pinned. The ElfuseBackend tests
drive a stand-in script through the real timeout tool, so they verify
the argv shape, the scratch isolation, and the deadline kill without a
VM. Code under test: tests/conformance/backends.py.
"""

from __future__ import annotations

import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

from conformance import backends


class ClassifyTest(unittest.TestCase):
    def test_normal_exit(self):
        self.assertEqual(backends.classify(0, 1_000_000, 10), "normal")
        self.assertEqual(backends.classify(1, 1_000_000, 10), "normal")

    def test_timeout_codes_at_deadline(self):
        for code in (124, 137):
            self.assertEqual(backends.classify(code, 10_000_000, 10),
                             "timeout")

    def test_early_137_is_signal(self):
        # A test killed by SIGKILL long before the deadline is a crash,
        # not a timeout, even though timeout(1) also exits 137.
        self.assertEqual(backends.classify(137, 1_000_000, 10), "signal")

    def test_signal_exit(self):
        self.assertEqual(backends.classify(139, 1_000_000, 10), "signal")

    def test_early_124_is_normal(self):
        # 124 is only timeout(1)'s verdict; a test exiting 124 itself
        # before the deadline ran to completion.
        self.assertEqual(backends.classify(124, 1_000_000, 10), "normal")


class EnvTest(unittest.TestCase):
    def test_normalized_content(self):
        env = backends.guest_environment(pathlib.Path("/scratch"))
        self.assertEqual(env["PATH"], "/usr/bin:/bin")
        self.assertEqual(env["LC_ALL"], "C")
        self.assertEqual(env["TZ"], "UTC")
        for name in ("HOME", "TMPDIR", "TEST_TMPDIR"):
            self.assertEqual(env[name], "/scratch")

    def test_scrub_names(self):
        self.assertIn("TEST_ON_GVISOR", backends.SCRUB_ENV)
        self.assertIn("GTEST_SHARD_INDEX", backends.SCRUB_ENV)
        self.assertIn("GTEST_TOTAL_SHARDS", backends.SCRUB_ENV)


class StateFileTest(unittest.TestCase):
    def test_parse(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("port=2222\nkey=/tmp/k\npidfile=/tmp/d/pid\n")
        path = pathlib.Path(fh.name)
        self.addCleanup(path.unlink)
        state = backends.parse_state_file(path)
        self.assertEqual(state, {"port": "2222", "key": "/tmp/k",
                                 "pidfile": "/tmp/d/pid"})

    def test_missing_field_rejected(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("port=2222\n")
        path = pathlib.Path(fh.name)
        self.addCleanup(path.unlink)
        with self.assertRaises(backends.BackendError):
            backends.parse_state_file(path)


class ElfuseBackendTest(unittest.TestCase):
    """A shell stand-in for build/elfuse records its argv and behaves per
    the requested guest command, exercising the wrapper end to end."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.fake = self.root / "elfuse"
        self.fake.write_text(
            "#!/bin/sh\n"
            'printf "%s\\n" "$@" > "$ELFUSE_ARGV_OUT"\n'
            "shift 2\n"
            'if [ "$1" = "--sysroot" ]; then shift 2; fi\n'
            'exec "$@"\n',
            encoding="utf-8")
        self.fake.chmod(self.fake.stat().st_mode | stat.S_IEXEC)

    def backend(self, sysroot=None):
        return backends.ElfuseBackend(self.fake, sysroot=sysroot)

    def run_guest(self, argv, timeout_s=10):
        scratch = self.root / "scratch"
        scratch.mkdir(exist_ok=True)
        return backends.Invocation, self.backend().run(
            argv, timeout_s=timeout_s, scratch=scratch,
            env_extra={"ELFUSE_ARGV_OUT": str(self.root / "argv.txt")})

    def test_argv_shape_and_exit(self):
        _, inv = self.run_guest(["/bin/sh", "-c", "exit 7"])
        self.assertEqual(inv.exit_code, 7)
        self.assertEqual(inv.execution, "normal")
        argv = (self.root / "argv.txt").read_text().splitlines()
        self.assertEqual(argv[0], "--timeout")
        self.assertEqual(argv[1], "0")

    def test_sysroot_flag(self):
        scratch = self.root / "s2"
        scratch.mkdir()
        self.backend(sysroot=self.root).run(
            ["/bin/sh", "-c", "true"], timeout_s=10, scratch=scratch,
            env_extra={"ELFUSE_ARGV_OUT": str(self.root / "argv2.txt")})
        argv = (self.root / "argv2.txt").read_text().splitlines()
        self.assertEqual(argv[2], "--sysroot")
        self.assertEqual(argv[3], str(self.root))

    def test_stdout_captured(self):
        _, inv = self.run_guest(["/bin/sh", "-c", "echo out; echo err >&2"])
        self.assertEqual(pathlib.Path(inv.stdout).read_text(), "out\n")
        self.assertEqual(pathlib.Path(inv.stderr).read_text(), "err\n")

    def test_deadline_kill(self):
        _, inv = self.run_guest(["/bin/sh", "-c", "sleep 30"], timeout_s=1)
        self.assertEqual(inv.execution, "timeout")

    def test_host_environment_does_not_leak(self):
        os.environ["ELFUSE_HOST_SECRET"] = "must-not-leak"
        self.addCleanup(os.environ.pop, "ELFUSE_HOST_SECRET", None)
        _, inv = self.run_guest(
            ["/bin/sh", "-c", 'test -z "${ELFUSE_HOST_SECRET+x}"'])
        self.assertEqual(inv.exit_code, 0)


class QemuLifecycleTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_invalid_state_rolls_back_runtime(self):
        (self.root / "state").write_text("port=2222\n", encoding="utf-8")
        completed = mock.Mock(returncode=0)
        backend = backends.QemuBackend()
        with mock.patch.object(backends.tempfile, "mkdtemp",
                               return_value=str(self.root)), \
                mock.patch.object(backends.subprocess, "run",
                                  return_value=completed) as run:
            with self.assertRaises(backends.BackendError):
                backend.start()
        self.assertIsNone(backend.runtime)
        self.assertIsNone(backend.state)
        self.assertEqual(run.call_count, 2)

    def test_master_failure_stops_started_vm(self):
        (self.root / "state").write_text(
            "port=2222\nkey=/tmp/key\npidfile=/tmp/qemu.pid\n",
            encoding="utf-8")
        backend = backends.QemuBackend()
        with mock.patch.object(backends.tempfile, "mkdtemp",
                               return_value=str(self.root)), \
                mock.patch.object(backends.subprocess, "run",
                                  return_value=mock.Mock(returncode=0)) as run, \
                mock.patch.object(backend, "_master",
                                  side_effect=backends.BackendError("ssh")):
            with self.assertRaises(backends.BackendError):
                backend.start()
        self.assertIsNone(backend.runtime)
        self.assertIsNone(backend.state)
        self.assertEqual(run.call_count, 3)


if __name__ == "__main__":
    unittest.main()
