# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import tempfile
import unittest
from pathlib import Path

from conformance import jsonc, ltp, payload, providers, selection
from conformance.ltp import build

REPO = Path(__file__).resolve().parents[3]

RUNTEST = """# comment
chmod01 chmod01
chmod01_16 chmod01_16
epoll01 epoll-ltp
pipeio_1 pipeio -T pipeio_1 -c 5 -s 4090 -i 100 -b -f x80
"""


class ParseTest(unittest.TestCase):
    def test_runtest(self):
        entries = build.parse_runtest(RUNTEST)
        self.assertEqual([t for t, _ in entries], ["chmod01", "chmod01_16", "epoll01", "pipeio_1"])
        self.assertEqual(entries[3][1][:3], ["pipeio", "-T", "pipeio_1"])
        with self.assertRaises(payload.PayloadError):
            build.parse_runtest("a a\na b\n")

    def test_dir_candidates(self):
        self.assertEqual(build.dir_candidates("clone301")[0], "kernel/syscalls/clone3")
        self.assertEqual(build.dir_candidates("fcntl24_64")[0], "kernel/syscalls/fcntl")
        self.assertEqual(build.dir_candidates("accept4_01")[0], "kernel/syscalls/accept4")
        self.assertIn("kernel/syscalls/timerfd", build.dir_candidates("timerfd_settime01"))
        self.assertIn("kernel/syscalls/ipc/msgctl", build.dir_candidates("msgctl01"))

    def test_resolve_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp)
            (src / "testcases/kernel/syscalls/clone3").mkdir(parents=True)
            (src / "testcases/kernel/security/dirtypipe").mkdir(parents=True)
            self.assertEqual(build.resolve_dir(src, "clone301", None), "kernel/syscalls/clone3")
            self.assertIsNone(build.resolve_dir(src, "nothing01", None))
            self.assertEqual(build.resolve_dir(src, "dirtypipe", "kernel/security/dirtypipe"),
                             "kernel/security/dirtypipe")
            self.assertIsNone(build.resolve_dir(src, "dirtypipe", "kernel/security/gone"))


class GenerateTest(unittest.TestCase):
    def test_full_selection(self):
        text = ltp.generate_full(RUNTEST, "20260529", {"epoll01": {"source_dir": "x", "timeout_s": 300}})
        doc = jsonc.loads(text)
        self.assertEqual(doc["provenance"], {"release": "20260529", "entries": 4})
        sel = selection.parse(doc, "t")
        self.assertEqual([e.group for e in sel.groups("full")], ["chmod01", "chmod01_16", "epoll01", "pipeio_1"])
        self.assertEqual(sel.groups("pr"), [])
        self.assertEqual(sel.entry("epoll01").timeout_s, 300)
        with self.assertRaises(selection.SelectionError):
            ltp.generate_full(RUNTEST, "x", {"gone": {}})

    def test_shipped_full_is_generated_from_its_header(self):
        doc = jsonc.load(REPO / "tests/conformance/ltp/data/full.jsonc")
        self.assertEqual(doc["provenance"]["entries"], len(doc["enabled"]))
        self.assertTrue(all(e["scope"] == "full" for e in doc["enabled"]))


class ProviderTest(unittest.TestCase):
    def setUp(self):
        self.provider = providers.make("ltp", REPO)

    def test_selection_merges_the_curated_subset(self):
        sel = self.provider.selection
        pr = [e.group for e in sel.groups("pr")]
        self.assertIn("setpgid01", pr)
        self.assertGreater(len(pr), 20)
        self.assertLess(len(pr), 80)
        self.assertGreater(len(sel.groups("full")), 1400)
        self.assertEqual(self.provider.backend_options("qemu"), {"mem_mib": 4096})
        self.assertEqual(self.provider.backend_options("elfuse")["sysroot"].name, "rootfs")

    def test_fingerprint_and_prerequisites(self):
        fp = self.provider.fingerprint()
        self.assertRegex(fp, r"^[0-9a-f]{64}$")
        with tempfile.TemporaryDirectory() as tmp:
            self.provider.payload_root = lambda: Path(tmp) / "none"
            self.assertIn("run: make ltp-payload", self.provider.prerequisites("elfuse"))
            self.assertIn("is absent", self.provider.regen_selection(check=True)[0])

    def test_pins(self):
        doc = payload.load_pins(self.provider.pins_path, self.provider.pins_schema)
        self.assertTrue(doc["ltp"]["archive_url"].endswith(".tar.xz"))


if __name__ == "__main__":
    unittest.main()
