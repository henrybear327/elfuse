"""Unit tests for the recorded-baseline extraction and gate."""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ltp_harness import baseline  # noqa: E402
from selftest import corpus  # noqa: E402

PIN = {"ltp_release": "r", "ltp_commit": "c", "kirk_tag": "v"}


def entry(status, subtests=None):
    return {"status": status, "subtests": subtests}


class ExtractSubtestsTest(unittest.TestCase):
    def test_counts_per_key(self):
        log = corpus.new_api_log(
            [
                "preadv02.c:77: TPASS: preadv() failed as expected",
                "preadv02.c:77: TPASS: preadv() failed as expected",
                "preadv02.c:72: TFAIL: preadv() succeeded unexpectedly",
            ]
        )
        self.assertEqual(
            baseline.extract_subtests(log),
            {"preadv02.c:77": {"TPASS": 2}, "preadv02.c:72": {"TFAIL": 1}},
        )

    def test_ignores_info_and_prose(self):
        log = corpus.new_api_log(
            [
                "readv01.c:33: TINFO: starting",
                "not a result line mentioning TFAIL: nope",
                "  readv01.c:40: TPASS: indented lines do not count",
            ]
        )
        self.assertEqual(baseline.extract_subtests(log), {})

    def test_all_result_types(self):
        log = "\n".join(
            [
                "t.c:1: TPASS: a",
                "t.c:2: TFAIL: b",
                "t.c:3: TBROK: c",
                "t.c:4: TCONF: d",
                "t.c:5: TWARN: e",
            ]
        )
        self.assertEqual(
            baseline.extract_subtests(log),
            {
                "t.c:1": {"TPASS": 1},
                "t.c:2": {"TFAIL": 1},
                "t.c:3": {"TBROK": 1},
                "t.c:4": {"TCONF": 1},
                "t.c:5": {"TWARN": 1},
            },
        )


class ClassifyResultTest(unittest.TestCase):
    def test_pass(self):
        result = corpus.kirk_result("t", passed=3)
        self.assertEqual(baseline.classify_result(result), "PASS")

    def test_fail_beats_warn(self):
        result = corpus.kirk_result("t", passed=2, failed=1, warnings=1, status="fail")
        self.assertEqual(baseline.classify_result(result), "FAIL")

    def test_broken_beats_fail(self):
        result = corpus.kirk_result("t", failed=1, broken=1, status="brok")
        self.assertEqual(baseline.classify_result(result), "BROKEN")

    def test_brok_status_alone(self):
        result = corpus.kirk_result("t", passed=1, status="brok", retval="-1")
        self.assertEqual(baseline.classify_result(result), "BROKEN")

    def test_conf_only_is_skip(self):
        result = corpus.kirk_result("t", skipped=2, status="conf", retval="32")
        self.assertEqual(baseline.classify_result(result), "SKIP")

    def test_warnings(self):
        result = corpus.kirk_result("t", passed=1, warnings=1, status="warn")
        self.assertEqual(baseline.classify_result(result), "WARN")

    def test_no_results_is_broken(self):
        result = corpus.kirk_result("t", status="pass")
        self.assertEqual(baseline.classify_result(result), "BROKEN")


class ObservedFromReportTest(unittest.TestCase):
    FORMATS = {"readv01": "new-api", "recv01": "legacy-exit"}

    def test_new_api_and_legacy(self):
        report = corpus.kirk_report(
            [
                corpus.kirk_result(
                    "readv01",
                    log=corpus.new_api_log(["readv01.c:40: TPASS: ok"]),
                    passed=1,
                ),
                corpus.kirk_result("recv01", log="recv01  1 TPASS : ok\n", passed=1),
            ]
        )
        observed = baseline.observed_from_report(report, self.FORMATS)
        self.assertEqual(
            observed["readv01"]["subtests"], {"readv01.c:40": {"TPASS": 1}}
        )
        self.assertIsNone(observed["recv01"]["subtests"])

    def test_unknown_test_rejected(self):
        report = corpus.kirk_report([corpus.kirk_result("mystery", passed=1)])
        with self.assertRaises(baseline.BaselineError):
            baseline.observed_from_report(report, self.FORMATS)

    def test_duplicate_rejected(self):
        report = corpus.kirk_report(
            [
                corpus.kirk_result("readv01", passed=1),
                corpus.kirk_result("readv01", passed=1),
            ]
        )
        with self.assertRaises(baseline.BaselineError):
            baseline.observed_from_report(report, self.FORMATS)


class CompareStatusTest(unittest.TestCase):
    def gate(self, base_status, seen_status):
        return baseline.compare(
            {"t": entry(base_status)}, {"t": entry(seen_status)}
        )

    def test_equal_is_green(self):
        for status in baseline.STATUSES:
            gate = self.gate(status, status)
            self.assertTrue(gate.passed, status)

    def test_regressions(self):
        for base_status, seen_status in (
            ("PASS", "FAIL"),
            ("PASS", "BROKEN"),
            ("PASS", "SKIP"),
            ("PASS", "WARN"),
            ("SKIP", "FAIL"),
            ("SKIP", "BROKEN"),
            ("FAIL", "BROKEN"),
            ("WARN", "FAIL"),
        ):
            gate = self.gate(base_status, seen_status)
            self.assertEqual(len(gate.regressions), 1, (base_status, seen_status))
            self.assertFalse(gate.passed)

    def test_improvements_fail_until_rerecorded(self):
        for base_status, seen_status in (
            ("FAIL", "PASS"),
            ("BROKEN", "FAIL"),
            ("BROKEN", "PASS"),
            ("SKIP", "PASS"),
            ("WARN", "PASS"),
        ):
            gate = self.gate(base_status, seen_status)
            self.assertEqual(len(gate.improvements), 1, (base_status, seen_status))
            self.assertFalse(gate.passed)

    def test_missing_from_baseline_is_config_error(self):
        with self.assertRaises(baseline.BaselineError):
            baseline.compare({}, {"t": entry("PASS")})

    def test_stale_baseline_entry_is_config_error(self):
        with self.assertRaises(baseline.BaselineError):
            baseline.compare(
                {"t": entry("PASS"), "gone": entry("PASS")}, {"t": entry("PASS")}
            )


class CompareSubtestsTest(unittest.TestCase):
    def gate(self, base_subs, seen_subs):
        return baseline.compare(
            {"t": entry("FAIL", base_subs)}, {"t": entry("FAIL", seen_subs)}
        )

    def test_equal_counts_green(self):
        subs = {"t.c:10": {"TPASS": 5, "TFAIL": 1}}
        self.assertTrue(self.gate(subs, copy.deepcopy(subs)).passed)

    def test_lost_pass_count_regresses(self):
        gate = self.gate(
            {"t.c:10": {"TPASS": 5}}, {"t.c:10": {"TPASS": 4, "TFAIL": 1}}
        )
        self.assertEqual(len(gate.regressions), 1)

    def test_fail_to_pass_improves(self):
        gate = self.gate(
            {"t.c:10": {"TPASS": 4, "TFAIL": 1}}, {"t.c:10": {"TPASS": 5}}
        )
        self.assertEqual(len(gate.improvements), 1)
        self.assertFalse(gate.passed)

    def test_conf_to_pass_improves(self):
        gate = self.gate({"t.c:10": {"TCONF": 1}}, {"t.c:10": {"TPASS": 1}})
        self.assertEqual(len(gate.improvements), 1)
        self.assertEqual(gate.regressions, [])

    def test_pass_to_conf_regresses(self):
        gate = self.gate({"t.c:10": {"TPASS": 1}}, {"t.c:10": {"TCONF": 1}})
        self.assertEqual(len(gate.regressions), 1)

    def test_extra_conf_firing_is_info(self):
        gate = self.gate(
            {"t.c:10": {"TPASS": 2, "TCONF": 1}},
            {"t.c:10": {"TPASS": 2, "TCONF": 2}},
        )
        self.assertTrue(gate.passed)
        self.assertEqual(len(gate.infos), 1)

    def test_missing_key_regresses(self):
        gate = self.gate({"t.c:10": {"TPASS": 1}}, {})
        self.assertEqual(len(gate.regressions), 1)

    def test_new_bad_key_regresses(self):
        gate = self.gate({}, {"t.c:99": {"TFAIL": 1}})
        self.assertEqual(len(gate.regressions), 1)

    def test_new_pass_key_is_info(self):
        gate = self.gate({}, {"t.c:99": {"TPASS": 1}})
        self.assertTrue(gate.passed)
        self.assertEqual(len(gate.infos), 1)

    def test_legacy_null_subtests_not_compared(self):
        gate = baseline.compare(
            {"t": entry("FAIL", None)}, {"t": entry("FAIL", None)}
        )
        self.assertTrue(gate.passed)


class LoadRecordTest(unittest.TestCase):
    def test_record_then_load_round_trip(self):
        observed = {
            "a": entry("PASS", {"a.c:1": {"TPASS": 2}}),
            "b": entry("BROKEN", {}),
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "baseline.json")
            added, changed, pruned = baseline.record(path, "elfuse", PIN, observed)
            self.assertEqual(added, ["a", "b"])
            self.assertEqual(changed, [])
            self.assertEqual(pruned, [])

            tests = baseline.load(path, PIN)
            gate = baseline.compare(tests, observed)
            self.assertTrue(gate.passed)

    def test_pin_mismatch_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "baseline.json")
            baseline.record(path, "elfuse", PIN, {"a": entry("PASS", {})})
            other_pin = dict(PIN, ltp_release="different")
            with self.assertRaises(baseline.BaselineError):
                baseline.load(path, other_pin)

    def test_merge_keeps_other_tiers_and_prunes_dropped(self):
        previous = {
            "kept": {"status": "PASS", "subtests": {}, "reason": "why"},
            "updated": {"status": "FAIL", "subtests": {}, "issue": "GH-1"},
            "dropped": {"status": "PASS", "subtests": {}},
        }
        observed = {"updated": entry("PASS", {})}
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "baseline.json")
            added, changed, pruned = baseline.record(
                path, "elfuse", PIN, observed, previous, {"kept", "updated"}
            )
            self.assertEqual(added, [])
            self.assertEqual(changed, ["updated"])
            self.assertEqual(pruned, ["dropped"])

            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertEqual(data["tests"]["kept"]["reason"], "why")
            self.assertEqual(data["tests"]["updated"]["status"], "PASS")
            self.assertEqual(data["tests"]["updated"]["issue"], "GH-1")
            self.assertNotIn("dropped", data["tests"])

    def test_record_is_deterministic(self):
        observed = {
            "b": entry("PASS", {"b.c:2": {"TPASS": 1}, "b.c:1": {"TPASS": 1}}),
            "a": entry("PASS", {}),
        }
        with tempfile.TemporaryDirectory() as tmp:
            first = os.path.join(tmp, "one.json")
            second = os.path.join(tmp, "two.json")
            baseline.record(first, "elfuse", PIN, observed)
            reordered = dict(reversed(list(observed.items())))
            baseline.record(second, "elfuse", PIN, reordered)
            with open(first, encoding="utf-8") as handle:
                one = handle.read()
            with open(second, encoding="utf-8") as handle:
                two = handle.read()
            self.assertEqual(one, two)


if __name__ == "__main__":
    unittest.main()
