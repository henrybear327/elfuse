"""Selftests for the ratchet.

The verdict table is the whole gating policy, so it is pinned
exhaustively: which statuses satisfy which expectation types, that a PASS
under any non-pass expectation is an unexpected pass (bidirectional
ratchet), and that TIMEOUT, CRASH, INCONSISTENT, and ERROR are never
satisfiable by any expectation. The message texts are contract: PR
authors act on them, so the tests assert their load-bearing fragments.
Code under test: tests/conformance/ratchet.py.
"""

from __future__ import annotations

import unittest

from conformance import expectations, model, ratchet

S = model.Status
V = model.Verdict


def resolution(action_type, matcher="ltp:x01", file="ltp_elfuse.jsonc",
               reason="r", bug=None):
    return expectations.Resolution(
        type=action_type, file=file, matcher=matcher, reason=reason, bug=bug,
        quarantined=False)


def judge(status, action_type, **kwargs):
    return ratchet.judge("ltp:x01", "elfuse", status,
                         resolution(action_type, **kwargs), detail="d")


class VerdictTableTest(unittest.TestCase):
    # (status, expectation type) -> verdict, exhaustively. TIMEOUT, CRASH,
    # INCONSISTENT, and ERROR rows are constant across all types: a hang,
    # a crash, a self-contradictory result, or a harness fault is never a
    # recordable divergence.
    TABLE = {
        "expect_pass": {
            S.PASS: V.AS_EXPECTED, S.WARN: V.AS_EXPECTED,
            S.FAIL: V.UNEXPECTED_FAILURE, S.BROK: V.UNEXPECTED_FAILURE,
            S.SKIP: V.UNEXPECTED_FAILURE, S.CONF: V.UNEXPECTED_FAILURE,
        },
        "expect_failure": {
            S.FAIL: V.AS_EXPECTED, S.BROK: V.AS_EXPECTED,
            S.PASS: V.UNEXPECTED_PASS, S.WARN: V.UNEXPECTED_FAILURE,
            S.SKIP: V.UNEXPECTED_FAILURE, S.CONF: V.UNEXPECTED_FAILURE,
        },
        "expect_skip": {
            S.SKIP: V.AS_EXPECTED,
            S.PASS: V.UNEXPECTED_PASS, S.WARN: V.UNEXPECTED_FAILURE,
            S.FAIL: V.UNEXPECTED_FAILURE, S.BROK: V.UNEXPECTED_FAILURE,
            S.CONF: V.UNEXPECTED_FAILURE,
        },
        "expect_conf": {
            S.CONF: V.AS_EXPECTED,
            S.PASS: V.UNEXPECTED_PASS, S.WARN: V.UNEXPECTED_FAILURE,
            S.FAIL: V.UNEXPECTED_FAILURE, S.BROK: V.UNEXPECTED_FAILURE,
            S.SKIP: V.UNEXPECTED_FAILURE,
        },
    }

    def test_table(self):
        for action_type, rows in self.TABLE.items():
            for status, want in rows.items():
                verdict, _ = judge(status, action_type)
                self.assertIs(
                    verdict, want,
                    "judge(%s, %s)" % (status.value, action_type))

    def test_never_satisfiable_rows(self):
        for action_type in self.TABLE:
            for status in (S.TIMEOUT, S.CRASH, S.INCONSISTENT):
                verdict, message = judge(status, action_type)
                self.assertIs(verdict, V.UNEXPECTED_FAILURE,
                              "judge(%s, %s)" % (status.value, action_type))
                self.assertIsNotNone(message)
            verdict, message = judge(S.ERROR, action_type)
            self.assertIs(verdict, V.ERROR)
            self.assertIsNotNone(message)

    def test_as_expected_has_no_message(self):
        _, message = judge(S.PASS, "expect_pass")
        self.assertIsNone(message)


class MessageTest(unittest.TestCase):
    def test_unexpected_pass_names_the_edit(self):
        _, message = judge(S.PASS, "expect_failure",
                           matcher="ltp:x*", file="ltp_elfuse.jsonc",
                           bug="#12")
        self.assertIn("UNEXPECTED PASS: ltp:x01 on elfuse", message)
        self.assertIn('matcher "ltp:x*" in ltp_elfuse.jsonc', message)
        self.assertIn("(bug #12)", message)
        self.assertIn("Narrow or delete that matcher in this same PR", message)

    def test_unexpected_pass_without_bug_omits_clause(self):
        _, message = judge(S.PASS, "expect_failure")
        self.assertNotIn("(bug", message)

    def test_unexpected_failure_names_observed_and_fix(self):
        _, message = judge(S.FAIL, "expect_pass", matcher="*",
                           file="ltp.jsonc")
        self.assertIn("UNEXPECTED FAILURE: ltp:x01 on elfuse", message)
        self.assertIn('expected: pass (matcher "*" in ltp.jsonc)', message)
        self.assertIn("observed: FAIL: d", message)
        self.assertIn("expect_failure action with a reason", message)

    def test_hang_and_crash_point_at_skip_or_quarantine(self):
        for status in (S.TIMEOUT, S.CRASH):
            _, message = judge(status, "expect_failure")
            self.assertIn("never a recordable divergence", message)

    def test_error_message_names_the_invariant(self):
        _, message = judge(S.ERROR, "expect_pass")
        self.assertIn("HARNESS ERROR", message)
        self.assertIn("failed to happen", message)


if __name__ == "__main__":
    unittest.main()
