"""Selftests for the result model.

results.json is the only carrier of a run's outcome (the gate is
re-derivable from it alone), so the serialization must round-trip every
field and reject statuses and verdicts outside the closed sets. Code
under test: tests/conformance/model.py.
"""

from __future__ import annotations

import unittest

from conformance import model


class StatusTest(unittest.TestCase):
    def test_closed_set(self):
        self.assertEqual(
            {s.value for s in model.Status},
            {"PASS", "FAIL", "SKIP", "CONF", "WARN", "BROK", "TIMEOUT",
             "CRASH", "INCONSISTENT", "ERROR"})

    def test_unknown_status_rejected(self):
        with self.assertRaises(ValueError):
            model.Status("XPASS")


class VerdictTest(unittest.TestCase):
    def test_closed_set(self):
        self.assertEqual(
            {v.value for v in model.Verdict},
            {"as_expected", "unexpected_failure", "unexpected_pass",
             "flaked", "filtered", "error"})

    def test_red_membership(self):
        self.assertTrue(model.Verdict.UNEXPECTED_FAILURE.is_red)
        self.assertTrue(model.Verdict.UNEXPECTED_PASS.is_red)
        self.assertTrue(model.Verdict.ERROR.is_red)
        self.assertFalse(model.Verdict.AS_EXPECTED.is_red)
        self.assertFalse(model.Verdict.FLAKED.is_red)
        self.assertFalse(model.Verdict.FILTERED.is_red)


class CaseResultTest(unittest.TestCase):
    def roundtrip(self, case):
        return model.CaseResult.from_dict(case.to_dict())

    def test_roundtrip_all_fields(self):
        case = model.CaseResult(
            id="ltp:chmod09",
            suite="ltp",
            backend="elfuse",
            status=model.Status.FAIL,
            verdict=model.Verdict.AS_EXPECTED,
            expectation={"type": "expect_failure", "file": "ltp_elfuse.jsonc",
                         "matcher": "ltp:chmod09", "reason": "r", "bug": "#1"},
            attempts=[model.Attempt(status=model.Status.FAIL, exit_code=1,
                                    wall_us=1234, execution="normal",
                                    detail="")],
            detail="chmod09.c:63 TFAIL",
            artifacts="cases/ltp_chmod09")
        back = self.roundtrip(case)
        self.assertEqual(back, case)
        self.assertIs(back.status, model.Status.FAIL)
        self.assertIs(back.attempts[0].status, model.Status.FAIL)

    def test_multiple_attempts_preserve_order(self):
        case = model.CaseResult(
            id="ltp:nanosleep01", suite="ltp", backend="qemu",
            status=model.Status.PASS, verdict=model.Verdict.FLAKED,
            expectation={"type": "expect_pass", "file": "ltp.jsonc",
                         "matcher": "*", "reason": None, "bug": None},
            attempts=[
                model.Attempt(model.Status.FAIL, 1, 10, "normal", ""),
                model.Attempt(model.Status.PASS, 0, 11, "normal", ""),
            ],
            detail="", artifacts="cases/ltp_nanosleep01")
        back = self.roundtrip(case)
        self.assertEqual([a.status for a in back.attempts],
                         [model.Status.FAIL, model.Status.PASS])

    def test_unknown_execution_rejected(self):
        with self.assertRaises(ValueError):
            model.Attempt(model.Status.PASS, 0, 1, "retried", "")


if __name__ == "__main__":
    unittest.main()
