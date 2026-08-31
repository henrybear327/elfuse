# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import asyncio
import os
import stat
import sys
import tempfile
import types
import unittest
from pathlib import Path


def _stub_libkirk():
    if "libkirk" in sys.modules:
        return
    libkirk = types.ModuleType("libkirk")
    com = types.ModuleType("libkirk.com")
    errors = types.ModuleType("libkirk.errors")

    class Plugin:
        _name = ""

    class ComChannel(Plugin):
        pass

    class IOBuffer:
        pass

    class CommunicationError(Exception):
        pass

    com.ComChannel, com.IOBuffer = ComChannel, IOBuffer
    errors.CommunicationError = CommunicationError
    libkirk.com, libkirk.errors = com, errors
    sys.modules.update({"libkirk": libkirk, "libkirk.com": com, "libkirk.errors": errors})


_stub_libkirk()
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ltp" / "kirk" / "plugins"))
import channels  # noqa: E402

REPO = Path(__file__).resolve().parents[3]


def script(path, body):
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class PureTest(unittest.TestCase):
    def test_rewrite_and_env(self):
        self.assertEqual(channels.rewrite_command("ls --format=single-column /opt/ltp/runtest"),
                         "ls -1 /opt/ltp/runtest")
        env = channels.channel_environment("/tmp/s", {"PATH": "/host", "LTP_X": "1", "TST_Y": "2", "HOME": "/h"})
        self.assertEqual(env["PATH"], channels.GUEST_PATH)
        self.assertEqual((env["LTP_X"], env["TST_Y"], env["HOME"], env["TMPDIR"], env["TEST_TMPDIR"]),
                         ("1", "2", "/tmp/s", "/tmp/s", "/tmp/s"))
        self.assertEqual(env["LC_ALL"], "C")

    def test_status_line(self):
        line = channels.status_line(source="x", timed_out=True)
        self.assertTrue(line.startswith(channels.STATUS_PREFIX))
        self.assertIn('"schema_version":1', line)

    def test_split_supervisor_status(self):
        out, note = channels._split_supervisor_status('TPASS: ok\n\n{"schema_version":1,"timed_out":false,"exit_code":0}\n')
        self.assertEqual(out, "TPASS: ok\n\n")
        self.assertIn('"source":"qemu-supervisor"', note)
        self.assertIn('"timed_out":false', note)
        out, note = channels._split_supervisor_status("no status\n")
        self.assertIn("supervisor status missing", note)

    def test_served(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "batch-1").write_text("chmod01 chmod01\n")
            served = channels.Served(tmp)
            self.assertEqual(served.answer("test -f /opt/ltp/runtest/batch-1")["returncode"], 0)
            self.assertIsNone(served.answer("test -f /opt/ltp/runtest/other"))
            self.assertEqual(served.answer("ls --format=single-column /opt/ltp/runtest")["stdout"], "batch-1\n")
            self.assertIsNone(served.answer("test -d /opt/ltp"))
            self.assertEqual(served.path_of("/opt/ltp/runtest/batch-1").read_text(), "chmod01 chmod01\n")
            self.assertIsNone(channels.Served("").answer("ls --format=single-column /opt/ltp/runtest"))


class ElfuseChannelTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "rootfs" / "tmp").mkdir(parents=True)
        (self.dir / "rootfs" / "etc").mkdir()
        (self.dir / "rootfs" / "etc" / "passwd").write_text("root:x:0:0::/:/bin/sh\n")
        (self.dir / "serve").mkdir()
        (self.dir / "serve" / "b1").write_text("chmod01 chmod01\n")
        # Strip the elfuse wrapper and run the guest shell command on the host.
        self.binary = script(self.dir / "elfuse", 'shift 6; exec "$@"\n')
        self.chan = channels.ElfuseChannel()
        self.chan.setup(binary=str(self.binary), sysroot=str(self.dir / "rootfs"), timeout=2,
                        serve=str(self.dir / "serve"))
        asyncio.run(self.chan.communicate())

    def tearDown(self):
        asyncio.run(self.chan.stop())
        self.tmp.cleanup()

    def run_cmd(self, command, **kw):
        return asyncio.run(self.chan.run_command(command, **kw))

    def test_command_and_status(self):
        ret = self.run_cmd('echo "$LTP_X:$HOME"; exit 3', env={"LTP_X": "v", "HOME": "/host"})
        self.assertEqual(ret["returncode"], 3)
        self.assertEqual(self.run_cmd("ulimit -s")["stdout"].split("\n")[0], "8192")
        lines = ret["stdout"].splitlines()
        self.assertTrue(lines[0].startswith("v:/tmp/ltp-"), lines)
        self.assertTrue(lines[-1].startswith(channels.STATUS_PREFIX))
        self.assertIn('"timed_out":false', lines[-1])
        self.assertGreater(ret["exec_time"], 0)
        self.assertEqual([p for p in (self.dir / "rootfs" / "tmp").iterdir()], [])

    def test_timeout_and_intercepts(self):
        ret = self.run_cmd("sleep 30")
        self.assertIn('"timed_out":true', ret["stdout"])
        self.assertEqual(self.run_cmd("cat /proc/sys/kernel/tainted")["stdout"], "0\n")
        self.assertEqual(self.run_cmd("test -f /opt/ltp/runtest/b1")["returncode"], 0)
        self.assertEqual(asyncio.run(self.chan.fetch_file("/opt/ltp/runtest/b1")), b"chmod01 chmod01\n")
        self.assertEqual(asyncio.run(self.chan.fetch_file("/etc/passwd")), b"root:x:0:0::/:/bin/sh\n")
        with self.assertRaises(Exception):
            asyncio.run(self.chan.fetch_file("/../../etc/hosts"))


class QemuChannelTest(unittest.TestCase):
    def test_remote_script_shape(self):
        chan = channels.QemuChannel()
        chan.setup(port=2200, key="/k", supervisor="/mnt/host/sup", rootfs_guest="/mnt/host/rootfs",
                   rootfs_host="/x", deadline=120, timeout=150, serve="", scratch="/tmp")
        chan._active = True
        seen = {}

        async def fake_ssh(script, timeout_s, name):
            seen.update(script=script, timeout=timeout_s)
            return {"returncode": 0, "stdout": 'TPASS\n\n{"schema_version":1,"exit_code":0,"timed_out":false}\n',
                    "execution": "normal", "wall_us": 5}

        chan._ssh = fake_ssh
        ret = asyncio.run(chan.run_command("chmod01", cwd="/opt/ltp/testcases/bin", env={"LTP_X": "1"}))
        self.assertEqual(ret["returncode"], 0)
        self.assertIn('"source":"qemu-supervisor"', ret["stdout"])
        self.assertEqual(seen["timeout"], 150)
        s = seen["script"]
        for fragment in ("env -i", "LTP_X=1", "/mnt/host/sup --root /tmp/ltp-root --cwd /opt/ltp/testcases/bin",
                         "--uid 1000 --gid 1000 --timeout 120", "-- %s -- /bin/sh -c chmod01" % channels.LAUNCHER):
            self.assertIn(fragment, s)


if __name__ == "__main__":
    unittest.main()
