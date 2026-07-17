"""Unit tests for the kirk channel plugins.

The plugins import libkirk, which lives in the pinned fixture checkout,
so these tests skip (with a visible notice) until the fixture is built.
"""

from __future__ import annotations

import os
import sys
import unittest

LTP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(os.path.dirname(LTP_DIR))
FIXTURE_DIR = os.environ.get(
    "LTP_FIXTURE_DIR",
    os.path.join(REPO_ROOT, "externals", "test-fixtures", "ltp-aarch64"),
)
KIRK_DIR = os.path.join(FIXTURE_DIR, "kirk")
HAVE_KIRK = os.path.isfile(os.path.join(KIRK_DIR, "libkirk", "com.py"))

if HAVE_KIRK:
    sys.path.insert(0, KIRK_DIR)
    sys.path.insert(0, os.path.join(LTP_DIR, "plugins"))
    import elfuse_chan


@unittest.skipUnless(HAVE_KIRK, "pinned kirk fixture is not built")
class CommandTranslationTest(unittest.TestCase):
    def test_ls_rewrite(self):
        self.assertEqual(
            elfuse_chan.rewrite_command("ls --format=single-column /opt/ltp/runtest"),
            "ls -1 /opt/ltp/runtest",
        )

    def test_other_commands_untouched(self):
        self.assertEqual(elfuse_chan.rewrite_command("readv01"), "readv01")

    def test_guest_script_enters_cwd(self):
        self.assertEqual(
            elfuse_chan.guest_script("readv01", "/opt/ltp/testcases/bin"),
            "cd /opt/ltp/testcases/bin && readv01",
        )

    def test_guest_script_quotes_cwd(self):
        self.assertEqual(
            elfuse_chan.guest_script("x", "/a dir"), "cd '/a dir' && x"
        )

    def test_guest_script_without_cwd(self):
        self.assertEqual(elfuse_chan.guest_script("test -d /opt/ltp", None),
                         "test -d /opt/ltp")


@unittest.skipUnless(HAVE_KIRK, "pinned kirk fixture is not built")
class GuestEnvironmentTest(unittest.TestCase):
    def test_canonical_environment(self):
        env = elfuse_chan.guest_environment(None, "/tmp/scratch")
        self.assertEqual(env["PATH"], elfuse_chan.GUEST_PATH)
        self.assertEqual(env["TMPDIR"], "/tmp/scratch")
        self.assertEqual(env["HOME"], "/tmp/scratch")
        self.assertEqual(env["LTPROOT"], "/opt/ltp")
        self.assertEqual(env["LTP_COLORIZE_OUTPUT"], "0")

    def test_host_path_pollution_dropped(self):
        env = elfuse_chan.guest_environment(
            {"PATH": "/usr/local/bin:/opt/ltp/testcases/bin", "SHELL": "/bin/zsh"},
            "/tmp/s",
        )
        self.assertEqual(env["PATH"], elfuse_chan.GUEST_PATH)
        self.assertNotIn("SHELL", env)

    def test_ltp_and_tst_vars_forwarded(self):
        env = elfuse_chan.guest_environment(
            {"LTP_TIMEOUT_MUL": "2", "TST_X": "y", "LTP_COLORIZE_OUTPUT": "1"},
            "/tmp/s",
        )
        self.assertEqual(env["LTP_TIMEOUT_MUL"], "2")
        self.assertEqual(env["TST_X"], "y")
        self.assertEqual(env["LTP_COLORIZE_OUTPUT"], "0")


@unittest.skipUnless(HAVE_KIRK, "pinned kirk fixture is not built")
class GuestPathMappingTest(unittest.TestCase):
    def channel(self):
        chan = elfuse_chan.ElfuseComChannel()
        chan.setup(binary="/x/elfuse", sysroot="/x/rootfs")
        return chan

    def test_absolute_path_maps_into_sysroot(self):
        self.assertEqual(
            self.channel().guest_to_host("/opt/ltp/runtest/elfuse-fast"),
            "/x/rootfs/opt/ltp/runtest/elfuse-fast",
        )

    def test_leading_traversal_stays_contained(self):
        # normpath collapses "/.." at the root, so an absolute guest path
        # can never resolve outside the sysroot.
        self.assertEqual(
            self.channel().guest_to_host("/../etc/passwd"),
            "/x/rootfs/etc/passwd",
        )

    def test_relative_rejected(self):
        from libkirk.errors import CommunicationError

        with self.assertRaises(CommunicationError):
            self.channel().guest_to_host("etc/passwd")


if __name__ == "__main__":
    unittest.main()
