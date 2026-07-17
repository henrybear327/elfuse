"""Unit tests for manifest and pin handling."""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ltp_harness import manifest  # noqa: E402

LTP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH = os.path.join(LTP_DIR, "manifest.json")
PIN_PATH = os.path.join(LTP_DIR, "pin.json")


def write_manifest(tmp, tests):
    path = os.path.join(tmp, "manifest.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"schema_version": 1, "tests": tests}, handle)
    return path


def sample_test(**overrides):
    test = {
        "id": "readv01",
        "command": "/opt/ltp/testcases/bin/readv01",
        "arguments": [],
        "tier": "fast",
        "timeout_seconds": 120,
        "result_format": "new-api",
        "helpers": [],
        "data": [],
        "notes": "sample",
    }
    test.update(overrides)
    return test


class RealFilesTest(unittest.TestCase):
    def test_committed_manifest_is_valid(self):
        tests = manifest.load_manifest(MANIFEST_PATH)
        self.assertEqual(len(tests), 24)
        by_tier = {}
        for test in tests:
            by_tier[test["tier"]] = by_tier.get(test["tier"], 0) + 1
        self.assertEqual(by_tier, {"fast": 13, "extended": 7, "nightly": 4})

        legacy = [t["id"] for t in tests if t["result_format"] == "legacy-exit"]
        self.assertEqual(legacy, ["recv01"])

    def test_committed_pins_are_valid(self):
        pins = manifest.load_pins(PIN_PATH)
        self.assertEqual(pins["ltp"]["release"], "20260529")
        self.assertEqual(pins["kirk"]["tag"], "v4.1.0")
        pin = manifest.baseline_pin(pins)
        self.assertEqual(
            sorted(pin), ["kirk_tag", "ltp_commit", "ltp_release"]
        )


class SelectTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tests = manifest.load_manifest(MANIFEST_PATH)

    def test_tier_filtering(self):
        self.assertEqual(len(manifest.select_tests(self.tests, "fast")), 13)
        self.assertEqual(len(manifest.select_tests(self.tests, "extended")), 7)
        self.assertEqual(len(manifest.select_tests(self.tests, "nightly")), 4)
        self.assertEqual(len(manifest.select_tests(self.tests, "all")), 24)

    def test_single_test(self):
        selected = manifest.select_tests(self.tests, "fast", "readv01")
        self.assertEqual([t["id"] for t in selected], ["readv01"])

    def test_unknown_test_is_error(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.select_tests(self.tests, "fast", "no_such_test")

    def test_tier_mismatch_is_error(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.select_tests(self.tests, "fast", "fcntl34")

    def test_tier_all_accepts_any_test(self):
        selected = manifest.select_tests(self.tests, "all", "fcntl34")
        self.assertEqual([t["id"] for t in selected], ["fcntl34"])

    def test_unknown_tier_is_error(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.select_tests(self.tests, "weekly")

    def test_tier_timeout(self):
        self.assertEqual(manifest.tier_timeout(self.tests, "fast"), 120)
        self.assertEqual(manifest.tier_timeout(self.tests, "nightly"), 300)
        self.assertEqual(manifest.tier_timeout(self.tests, "all"), 300)


class RuntestTest(unittest.TestCase):
    def test_generated_runtest(self):
        tests = manifest.load_manifest(MANIFEST_PATH)
        content = manifest.generate_runtest(tests, "fast")
        lines = [
            line
            for line in content.splitlines()
            if line and not line.startswith("#")
        ]
        self.assertEqual(len(lines), 13)
        self.assertEqual(lines[0], "readv01 readv01")
        self.assertIn("recv01 recv01", lines)
        self.assertTrue(content.endswith("\n"))

    def test_suite_name(self):
        self.assertEqual(manifest.suite_name("fast"), "elfuse-fast")


class ValidationTest(unittest.TestCase):
    def check_rejected(self, tests):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_manifest(tmp, tests)
            with self.assertRaises(manifest.ManifestError):
                manifest.load_manifest(path)

    def test_duplicate_id(self):
        self.check_rejected([sample_test(), sample_test()])

    def test_bad_tier(self):
        self.check_rejected([sample_test(tier="weekly")])

    def test_bad_result_format(self):
        self.check_rejected([sample_test(result_format="tap")])

    def test_relative_command(self):
        self.check_rejected([sample_test(command="readv01")])

    def test_absolute_data_path(self):
        self.check_rejected([sample_test(data=["/etc/passwd"])])

    def test_traversal_data_path(self):
        self.check_rejected([sample_test(data=["../escape"])])

    def test_missing_key(self):
        broken = sample_test()
        del broken["notes"]
        self.check_rejected([broken])

    def test_unknown_key(self):
        self.check_rejected([sample_test(requirements=["futex"])])

    def test_bad_timeout(self):
        self.check_rejected([sample_test(timeout_seconds=0)])

    def test_valid_manifest_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_manifest(tmp, [sample_test()])
            tests = manifest.load_manifest(path)
            self.assertEqual(len(tests), 1)

    def test_bad_pin_digest(self):
        pins = manifest.load_pins(PIN_PATH)
        broken = copy.deepcopy(pins)
        broken["kirk"]["archive_sha256"] = "not-a-digest"
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "pin.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(broken, handle)
            with self.assertRaises(manifest.ManifestError):
                manifest.load_pins(path)


if __name__ == "__main__":
    unittest.main()
