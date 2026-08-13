"""Selftests for the LTP payload's manifest and sweep generation.

Regression guards for behavior written in the same commit: the sweep
is generated from the pinned runtest/syscalls text, keyed on the tag
(parameterized lines
reuse a binary under distinct tags), curated ids are excluded, a
timeout override above the default promotes to sweep-slow, and an
override naming no runtest entry is an error so the override table
cannot rot. The committed data/ltp-manifest.jsonc must itself load.
Code under test: tests/conformance/payload/ltp.py.
"""

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from conformance.payload import common, ltp

RUNTEST = """\
#DESCRIPTION:Kernel system calls
abort01 abort01

accept01 accept01
execve05 execve05 -i 5 -n 32
readv01 readv01
"""


def manifest(overrides=None, curated=("readv01",)):
    return {
        "schema_version": 1,
        "sweep": {"runtest_file": "runtest/syscalls",
                  "default_timeout_seconds": 60,
                  "overrides": overrides or {}},
        "tests": [{"id": tag, "tier": "fast", "group": tag.rstrip("0123456789"),
                   "timeout_seconds": 120, "result_format": "new-api",
                   "notes": "n"} for tag in curated],
    }


class GenerateSweepTest(unittest.TestCase):
    def test_tags_argv_and_curated_exclusion(self):
        entries = ltp.generate_sweep(RUNTEST, manifest())
        by_id = {entry["id"]: entry for entry in entries}
        self.assertEqual(sorted(by_id), ["abort01", "accept01", "execve05"])
        self.assertEqual(by_id["execve05"]["arguments"],
                         ["execve05", "-i", "5", "-n", "32"])
        self.assertEqual(by_id["abort01"]["tier"], "sweep")
        self.assertIsNone(by_id["abort01"]["source_dir"])

    def test_dir_candidates_convention(self):
        # Pinned against real layouts that broke earlier rules on the
        # real runtest file: accept4_01 builds in accept4/ (separator
        # residue), fcntl24_64 and chown01_16 in the base directory
        # (large-file and compat-16 builds), timerfd_settime01 shortens
        # at the underscore, and msgctl01 lives under ipc/.
        self.assertEqual(ltp.dir_candidates("accept4_01")[0],
                         "kernel/syscalls/accept4")
        self.assertEqual(ltp.dir_candidates("fcntl24_64")[0],
                         "kernel/syscalls/fcntl")
        self.assertEqual(ltp.dir_candidates("chown01_16")[0],
                         "kernel/syscalls/chown")
        # Two-digit index strip comes first: stripping every trailing
        # digit would resolve these into the existing but wrong clone/
        # and wait/ directories. Observed failing at the staging guard
        # on the real tree.
        self.assertEqual(ltp.dir_candidates("clone301")[0],
                         "kernel/syscalls/clone3")
        self.assertEqual(ltp.dir_candidates("wait401")[0],
                         "kernel/syscalls/wait4")
        self.assertEqual(ltp.dir_candidates("preadv201_64")[0],
                         "kernel/syscalls/preadv2")
        self.assertIn("kernel/syscalls/clone", ltp.dir_candidates("clone301"))
        self.assertIn("kernel/syscalls/timerfd",
                      ltp.dir_candidates("timerfd_settime01"))
        self.assertIn("kernel/syscalls/ipc/msgctl",
                      ltp.dir_candidates("msgctl01"))

    def test_timeout_override_promotes_to_sweep_slow(self):
        entries = ltp.generate_sweep(
            RUNTEST, manifest({"abort01": {"timeout_seconds": 300}}))
        by_id = {entry["id"]: entry for entry in entries}
        self.assertEqual(by_id["abort01"]["tier"], "sweep-slow")
        self.assertEqual(by_id["abort01"]["timeout_seconds"], 300)

    def test_source_dir_override(self):
        entries = ltp.generate_sweep(
            RUNTEST,
            manifest({"abort01": {"source_dir": "kernel/syscalls/other"}}))
        by_id = {entry["id"]: entry for entry in entries}
        self.assertEqual(by_id["abort01"]["source_dir"],
                         "kernel/syscalls/other")

    def test_stale_override_rejected(self):
        with self.assertRaises(ltp.PayloadError) as ctx:
            ltp.generate_sweep(
                RUNTEST, manifest({"gone01": {"timeout_seconds": 300}}))
        self.assertIn("gone01", str(ctx.exception))

    def test_duplicate_tag_rejected(self):
        with self.assertRaises(ltp.PayloadError):
            ltp.generate_sweep("a01 a01\na01 a01 -i 2\n", manifest())

    def test_unknown_override_key_rejected(self):
        with self.assertRaises(ltp.PayloadError):
            ltp.generate_sweep(
                RUNTEST, manifest({"abort01": {"timeout": 300}}))


class GenerateRuntestTest(unittest.TestCase):
    def test_tier_filter_and_argv(self):
        entries = ltp.generate_sweep(RUNTEST, manifest())
        text = ltp.generate_runtest(entries, "sweep")
        self.assertIn("execve05 execve05 -i 5 -n 32", text)
        self.assertIn("abort01 abort01", text)
        self.assertNotIn("readv01", text)


class CommittedManifestTest(unittest.TestCase):
    def test_committed_manifest_loads(self):
        doc = ltp.load_manifest()
        self.assertEqual(len(doc["tests"]), 24)
        self.assertEqual(len(doc["sweep"]["overrides"]), 37)


class PayloadIntegrityTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_busybox_bytes_change_the_fingerprint(self):
        first = self.root / "busybox-a"
        second = self.root / "busybox-b"
        first.write_bytes(b"first")
        second.write_bytes(b"second")
        self.assertNotEqual(ltp.payload_fingerprint(busybox=first),
                            ltp.payload_fingerprint(busybox=second))

    def test_runtime_verifier_detects_tampering(self):
        rootfs = self.root / "rootfs"
        rootfs.mkdir()
        binary = rootfs / "tool"
        binary.write_bytes(b"payload")
        binary.chmod(0o755)
        manifest = common.inventory(self.root, ["rootfs"])
        (self.root / "runtime-manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8")
        common.write_complete(
            self.root, fingerprint="f" * 64,
            contents={"files": 1, "tests": 1,
                      "busybox_sha256": "0" * 64})
        self.assertEqual(ltp.verify(directory=self.root), 0)
        binary.write_bytes(b"tampered")
        with self.assertRaises(ltp.PayloadError):
            ltp.verify(directory=self.root)


if __name__ == "__main__":
    unittest.main()
