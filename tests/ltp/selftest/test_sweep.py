"""Unit tests for the sweep-manifest generator.

The generator (ltp_harness/sweep.py) turns the pinned upstream
runtest/syscalls file into manifest-sweep.json. These tests fabricate a
miniature LTP source tree and pin the resolution conventions: exact
source match, _64/_16 variant stripping, override application, curated
dedup, unbuilt marking, and byte-identical regeneration. Every
unresolvable or ambiguous shape must be a ManifestError, never a
silently defaulted entry.
"""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ltp_harness import manifest, sweep  # noqa: E402

NEW_API_SOURCE = "#include <tst_test.h>\nstatic struct tst_test test = {};\n"
LEGACY_SOURCE = "int main(void) { return 0; }\n"

RUNTEST = """\
# comment line

readv01 readv01
foo01 foo01
foo64 foo01_64
bar01 bar01 -T bar01 -c 5
pip01 pip
scr01 scr_script
host01 host01
"""


def curated_readv01():
    return {
        "id": "readv01",
        "command": "/opt/ltp/testcases/bin/readv01",
        "arguments": [],
        "tier": "fast",
        "group": "readv",
        "timeout_seconds": 120,
        "result_format": "new-api",
        "helpers": [],
        "data": [],
        "notes": "curated",
    }


class TreeTest(unittest.TestCase):
    """Base: fabricate the source tree once per test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.src = self._tmp.name
        self.write("runtest/syscalls", RUNTEST)
        self.write("lib/libltp.a", "not a real archive\n")
        sc = "testcases/kernel/syscalls"
        self.write(f"{sc}/readv/readv01.c", NEW_API_SOURCE)
        self.write(f"{sc}/foo/foo01.c", NEW_API_SOURCE)
        self.write(f"{sc}/bar/bar01.c", LEGACY_SOURCE)
        self.write("testcases/kernel/ipc/pip/pip.c", NEW_API_SOURCE)
        self.write(f"{sc}/scr/scr_script", "#!/bin/sh\nexit 0\n")
        self.write(f"{sc}/aliassrc/alias01.c", NEW_API_SOURCE)
        self.overrides = {
            "scr01": {"source": f"{sc}/scr/scr_script"},
            "host01": {
                "source": f"{sc}/aliassrc/alias01.c",
                "source_dir": f"{sc.replace('testcases/', '')}/host",
            },
        }

    def write(self, rel, content):
        path = os.path.join(self.src, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)

    def generate(self, curated=None, overrides=None, **kwargs):
        return sweep.generate(
            self.src,
            [curated_readv01()] if curated is None else curated,
            self.overrides if overrides is None else overrides,
            "20260529",
            **kwargs,
        )


class ParseTest(TreeTest):
    def test_comments_and_arguments(self):
        entries = sweep.parse_runtest(sweep.runtest_path(self.src))
        self.assertEqual(len(entries), 7)
        by_id = {test_id: (binary, args) for test_id, binary, args in entries}
        self.assertEqual(by_id["bar01"], ("bar01", ["-T", "bar01", "-c", "5"]))
        self.assertEqual(by_id["foo64"], ("foo01_64", []))

    def test_metacharacter_rejected(self):
        self.write("runtest/syscalls", "evil01 sh -c 'boom'\n")
        with self.assertRaises(manifest.ManifestError):
            sweep.parse_runtest(sweep.runtest_path(self.src))

    def test_short_line_rejected(self):
        self.write("runtest/syscalls", "lonely01\n")
        with self.assertRaises(manifest.ManifestError):
            sweep.parse_runtest(sweep.runtest_path(self.src))

    def test_duplicate_id_rejected(self):
        self.write("runtest/syscalls", "a01 a01\na01 a01\n")
        with self.assertRaises(manifest.ManifestError):
            sweep.parse_runtest(sweep.runtest_path(self.src))


class GenerateTest(TreeTest):
    def test_curated_id_skipped(self):
        document = self.generate()
        ids = [test["id"] for test in document["tests"]]
        self.assertNotIn("readv01", ids)
        self.assertEqual(
            ids, ["foo01", "foo64", "bar01", "pip01", "scr01", "host01"]
        )

    def test_curated_divergence_rejected(self):
        self.write("runtest/syscalls", "readv01 readv01 -x\n")
        with self.assertRaises(manifest.ManifestError):
            self.generate(overrides={})

    def test_variant_suffix_resolution(self):
        document = self.generate()
        foo64 = next(t for t in document["tests"] if t["id"] == "foo64")
        self.assertEqual(foo64["command"], "/opt/ltp/testcases/bin/foo01_64")
        self.assertEqual(foo64["group"], "foo")
        self.assertEqual(foo64["result_format"], "new-api")

    def test_result_format_classification(self):
        document = self.generate()
        formats = {t["id"]: t["result_format"] for t in document["tests"]}
        self.assertEqual(formats["foo01"], "new-api")
        self.assertEqual(formats["bar01"], "legacy-exit")
        self.assertEqual(formats["scr01"], "legacy-exit")

    def test_group_outside_syscalls_tree(self):
        document = self.generate()
        pip01 = next(t for t in document["tests"] if t["id"] == "pip01")
        self.assertEqual(pip01["group"], "ipc/pip")
        self.assertEqual(pip01["source_dir"], "kernel/ipc/pip")

    def test_source_dir_override(self):
        document = self.generate()
        host01 = next(t for t in document["tests"] if t["id"] == "host01")
        self.assertEqual(host01["group"], "host")
        self.assertEqual(host01["source_dir"], "kernel/syscalls/host")

    def test_unresolved_binary_rejected(self):
        with self.assertRaises(manifest.ManifestError):
            self.generate(overrides={"host01": self.overrides["host01"]})

    def test_ambiguous_source_rejected(self):
        self.write("testcases/kernel/syscalls/foo2/foo01.c", NEW_API_SOURCE)
        with self.assertRaises(manifest.ManifestError):
            self.generate()

    def test_unknown_override_rejected(self):
        overrides = dict(self.overrides, nosuch01={"notes": "ghost"})
        with self.assertRaises(manifest.ManifestError):
            self.generate(overrides=overrides)

    def test_override_for_curated_id_rejected(self):
        overrides = dict(self.overrides, readv01={"notes": "no"})
        with self.assertRaises(manifest.ManifestError):
            self.generate(overrides=overrides)

    def test_timeout_override_promotes_to_sweep_slow(self):
        overrides = dict(self.overrides)
        overrides["bar01"] = {"timeout_seconds": 300}
        document = self.generate(overrides=overrides)
        bar01 = next(t for t in document["tests"] if t["id"] == "bar01")
        self.assertEqual(bar01["tier"], "sweep-slow")
        self.assertEqual(bar01["timeout_seconds"], 300)
        others = [t["tier"] for t in document["tests"] if t["id"] != "bar01"]
        self.assertEqual(set(others), {"sweep"})

    def test_unbuilt_marking(self):
        self.write("testcases/kernel/syscalls/foo/foo01", "ELF\n")
        self.write("testcases/kernel/syscalls/foo/foo01_64", "ELF\n")
        self.write("testcases/kernel/syscalls/bar/bar01", "ELF\n")
        self.write("testcases/kernel/ipc/pip/pip", "ELF\n")
        self.write("testcases/kernel/syscalls/host/host01", "ELF\n")
        document = self.generate(mark_unbuilt=True)
        unbuilt = {t["id"] for t in document["tests"] if "unbuilt" in t}
        # scr01 is an INSTALL_TARGETS script already present in its
        # source dir; everything staged as a file counts as built.
        self.assertEqual(unbuilt, set())

        os.unlink(os.path.join(self.src, "testcases/kernel/ipc/pip/pip"))
        document = self.generate(mark_unbuilt=True)
        unbuilt = {t["id"] for t in document["tests"] if "unbuilt" in t}
        self.assertEqual(unbuilt, {"pip01"})

    def test_unbuilt_marking_requires_build_evidence(self):
        os.unlink(os.path.join(self.src, "lib", "libltp.a"))
        with self.assertRaises(manifest.ManifestError):
            self.generate(mark_unbuilt=True)

    def test_byte_identical_regeneration(self):
        first = sweep.render(self.generate())
        second = sweep.render(self.generate())
        self.assertEqual(first, second)

    def test_provenance_pins_the_runtest(self):
        document = self.generate()
        provenance = document["generated_from"]
        self.assertEqual(provenance["ltp_release"], "20260529")
        self.assertEqual(len(provenance["runtest_sha256"]), 64)
        before = provenance["runtest_sha256"]
        self.write("runtest/syscalls", RUNTEST + "extra01 foo01\n")
        after = self.generate()["generated_from"]["runtest_sha256"]
        self.assertNotEqual(before, after)


class DriftTest(TreeTest):
    def test_check_drift(self):
        document = self.generate()
        path = os.path.join(self.src, "manifest-sweep.json")
        self.assertIsNotNone(sweep.check_drift(path, document))
        sweep.write(path, document)
        self.assertIsNone(sweep.check_drift(path, document))
        changed = copy.deepcopy(document)
        changed["tests"][0]["timeout_seconds"] = 61
        self.assertIsNotNone(sweep.check_drift(path, changed))


class LoadSweepTest(TreeTest):
    def _write_sweep(self, document):
        path = os.path.join(self.src, "manifest-sweep.json")
        sweep.write(path, document)
        return path

    def test_roundtrip_and_normalization(self):
        path = self._write_sweep(self.generate())
        tests = manifest.load_sweep(path)
        self.assertEqual(len(tests), 6)
        for test in tests:
            self.assertEqual(test["helpers"], [])
            self.assertEqual(test["data"], [])

    def test_curated_tier_rejected_in_sweep(self):
        document = self.generate()
        document["tests"][0]["tier"] = "fast"
        with self.assertRaises(manifest.ManifestError):
            manifest.load_sweep(self._write_sweep(document))

    def test_missing_provenance_rejected(self):
        document = self.generate()
        del document["generated_from"]
        with self.assertRaises(manifest.ManifestError):
            manifest.load_sweep(self._write_sweep(document))

    def test_empty_unbuilt_rejected(self):
        document = self.generate()
        document["tests"][0]["unbuilt"] = ""
        with self.assertRaises(manifest.ManifestError):
            manifest.load_sweep(self._write_sweep(document))

    def test_helpers_key_rejected_in_sweep(self):
        document = self.generate()
        document["tests"][0]["helpers"] = []
        with self.assertRaises(manifest.ManifestError):
            manifest.load_sweep(self._write_sweep(document))


class MergeAndSelectTest(TreeTest):
    def _merged(self, mark_unbuilt=False):
        document = self.generate(mark_unbuilt=mark_unbuilt)
        path = os.path.join(self.src, "manifest-sweep.json")
        sweep.write(path, document)
        return manifest.merge_tests(
            [curated_readv01()], manifest.load_sweep(path)
        )

    def test_merge_rejects_duplicates(self):
        tests = self._merged()
        duplicate = copy.deepcopy(tests[1])
        with self.assertRaises(manifest.ManifestError):
            manifest.merge_tests([curated_readv01()], tests[1:] + [duplicate])

    def test_all_spans_curated_and_sweep(self):
        tests = self._merged()
        self.assertEqual(len(manifest.select_tests(tests, "all")), 7)
        self.assertEqual(len(manifest.select_tests(tests, "sweep")), 6)
        self.assertEqual(len(manifest.select_tests(tests, "fast")), 1)

    def test_unbuilt_excluded_from_selection(self):
        # No binaries fabricated: every non-script sweep entry is unbuilt.
        tests = self._merged(mark_unbuilt=True)
        selected = manifest.select_tests(tests, "sweep")
        self.assertEqual([t["id"] for t in selected], ["scr01"])
        unbuilt = manifest.unbuilt_tests(tests, "sweep")
        self.assertEqual(len(unbuilt), 5)

    def test_targeting_unbuilt_test_is_explicit_error(self):
        tests = self._merged(mark_unbuilt=True)
        with self.assertRaises(manifest.ManifestError) as caught:
            manifest.select_tests(tests, "sweep", "foo01")
        self.assertIn("was not built", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
