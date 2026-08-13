"""Selftests for the expectations engine.

The engine is Fuchsia's ordered-actions model: flatten includes, then the
last matching action wins. These tests pin the load-time validation (a
malformed file must fail before any lane boots), the resolution order
(leaf overrides base, the loader-appended quarantine layer flags but never
replaces the underlying expectation), and the stale-matcher check that
keeps an allowlist from outliving its test. Code under test:
tests/conformance/expectations.py.
"""

from __future__ import annotations

import pathlib
import tempfile
import unittest

from conformance import expectations

BASELINE = '{"actions": [{"type": "expect_pass", "matchers": ["*"]}]}'


class LoaderCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.write("flaky.jsonc", '{"actions": []}')

    def write(self, name, text):
        (self.root / name).write_text(text, encoding="utf-8")

    def load(self, suite="ltp", backend="elfuse"):
        return expectations.load(suite, backend, self.root)


class ResolveTest(LoaderCase):
    def test_baseline_matches_everything(self):
        self.write("ltp.jsonc", BASELINE)
        self.write("ltp_elfuse.jsonc",
                   '{"actions": [{"include": "ltp.jsonc"}]}')
        res = self.load().resolve("ltp:chmod09")
        self.assertEqual(res.type, "expect_pass")
        self.assertEqual(res.matcher, "*")
        self.assertEqual(res.file, "ltp.jsonc")

    def test_last_match_wins_leaf_over_base(self):
        self.write("ltp.jsonc", """
        {"actions": [
          {"type": "expect_pass", "matchers": ["*"]},
          {"type": "expect_failure", "reason": "base", "matchers": ["ltp:chmod09"]},
        ]}""")
        self.write("ltp_elfuse.jsonc", """
        {"actions": [
          {"include": "ltp.jsonc"},
          {"type": "expect_skip", "reason": "leaf", "matchers": ["ltp:chmod09"]},
        ]}""")
        res = self.load().resolve("ltp:chmod09")
        self.assertEqual(res.type, "expect_skip")
        self.assertEqual(res.reason, "leaf")
        self.assertEqual(res.file, "ltp_elfuse.jsonc")

    def test_glob_matcher(self):
        self.write("ltp.jsonc", """
        {"actions": [
          {"type": "expect_pass", "matchers": ["*"]},
          {"type": "expect_failure", "reason": "r", "matchers": ["ltp:nanosleep*"]},
        ]}""")
        self.write("ltp_elfuse.jsonc",
                   '{"actions": [{"include": "ltp.jsonc"}]}')
        exp = self.load()
        self.assertEqual(exp.resolve("ltp:nanosleep01").type, "expect_failure")
        self.assertEqual(exp.resolve("ltp:chmod09").type, "expect_pass")

    def test_quarantine_flags_without_replacing(self):
        self.write("ltp.jsonc", BASELINE)
        self.write("ltp_elfuse.jsonc",
                   '{"actions": [{"include": "ltp.jsonc"}]}')
        self.write("flaky.jsonc", """
        {"actions": [
          {"type": "quarantine", "reason": "timer wakeup bound",
           "matchers": ["ltp:nanosleep01"]},
        ]}""")
        exp = self.load()
        res = exp.resolve("ltp:nanosleep01")
        self.assertTrue(res.quarantined)
        self.assertEqual(res.type, "expect_pass")
        self.assertFalse(exp.resolve("ltp:chmod09").quarantined)


class LoadValidationTest(LoaderCase):
    def assert_load_error(self, fragment, suite="ltp", backend="elfuse"):
        with self.assertRaises(expectations.ExpectationError) as ctx:
            self.load(suite, backend)
        self.assertIn(fragment, str(ctx.exception))

    def test_missing_leaf(self):
        self.assert_load_error("ltp_elfuse.jsonc")

    def test_missing_include(self):
        self.write("ltp_elfuse.jsonc",
                   '{"actions": [{"include": "absent.jsonc"}]}')
        self.assert_load_error("absent.jsonc")

    def test_include_cycle(self):
        self.write("a.jsonc", '{"actions": [{"include": "b.jsonc"}]}')
        self.write("b.jsonc", '{"actions": [{"include": "a.jsonc"}]}')
        self.write("ltp_elfuse.jsonc",
                   '{"actions": [{"include": "a.jsonc"}]}')
        self.assert_load_error("cycle")

    def test_unknown_action_key(self):
        self.write("ltp_elfuse.jsonc", """
        {"actions": [
          {"type": "expect_pass", "matchers": ["*"], "why": "x"},
        ]}""")
        self.assert_load_error("why")

    def test_unknown_action_type(self):
        self.write("ltp_elfuse.jsonc", """
        {"actions": [
          {"type": "expect_pass", "matchers": ["*"]},
          {"type": "exclude", "reason": "r", "matchers": ["ltp:a01"]},
        ]}""")
        self.assert_load_error("exclude")

    def test_first_effective_action_must_be_baseline(self):
        self.write("ltp_elfuse.jsonc", """
        {"actions": [
          {"type": "expect_failure", "reason": "r", "matchers": ["ltp:a01"]},
        ]}""")
        self.assert_load_error("expect_pass")

    def test_reason_required_on_non_pass(self):
        self.write("ltp_elfuse.jsonc", """
        {"actions": [
          {"type": "expect_pass", "matchers": ["*"]},
          {"type": "expect_failure", "matchers": ["ltp:a01"]},
        ]}""")
        self.assert_load_error("reason")

    def test_bug_shape_validated_when_present(self):
        self.write("ltp_elfuse.jsonc", """
        {"actions": [
          {"type": "expect_pass", "matchers": ["*"]},
          {"type": "expect_failure", "reason": "r", "bug": "someday",
           "matchers": ["ltp:a01"]},
        ]}""")
        self.assert_load_error("bug")

    def test_matchers_sorted_within_action(self):
        self.write("ltp_elfuse.jsonc", """
        {"actions": [
          {"type": "expect_pass", "matchers": ["*"]},
          {"type": "expect_failure", "reason": "r",
           "matchers": ["ltp:b01", "ltp:a01"]},
        ]}""")
        self.assert_load_error("sorted")

    def test_matchers_namespaced(self):
        self.write("ltp_elfuse.jsonc", """
        {"actions": [
          {"type": "expect_pass", "matchers": ["*"]},
          {"type": "expect_failure", "reason": "r", "matchers": ["chmod09"]},
        ]}""")
        self.assert_load_error("namespaced")

    def test_quarantine_only_in_flaky(self):
        self.write("ltp_elfuse.jsonc", """
        {"actions": [
          {"type": "expect_pass", "matchers": ["*"]},
          {"type": "quarantine", "reason": "r", "matchers": ["ltp:a01"]},
        ]}""")
        self.assert_load_error("flaky.jsonc")

    def test_em_dash_rejected(self):
        # The glyph is constructed from its escape so the repo-wide
        # grep -rnP '\x{2014}' check never matches this test's source.
        self.write("ltp_elfuse.jsonc",
                   '{"actions": [{"type": "expect_pass", "matchers": ["*"]}]}'
                   '// timer \u2014 flaky\n')
        self.assert_load_error("U+2014")


class StaleMatcherTest(LoaderCase):
    def test_stale_matcher_reported_and_baseline_exempt(self):
        self.write("ltp.jsonc", BASELINE)
        self.write("ltp_elfuse.jsonc", """
        {"actions": [
          {"include": "ltp.jsonc"},
          {"type": "expect_failure", "reason": "r", "matchers": ["ltp:gone01"]},
          {"type": "expect_skip", "reason": "r", "matchers": ["ltp:real0*"]},
        ]}""")
        exp = self.load()
        errors = exp.check_stale(["ltp:real01", "ltp:real02"])
        self.assertEqual(len(errors), 1)
        self.assertIn("ltp:gone01", errors[0])
        self.assertEqual(exp.check_stale(["ltp:gone01", "ltp:real01"]), [])

    def test_foreign_suite_quarantine_not_stale(self):
        # flaky.jsonc spans both suites, so a gvisor quarantine entry is
        # invisible to every ltp lane's listing and must not read as stale.
        self.write("ltp.jsonc", BASELINE)
        self.write("ltp_elfuse.jsonc",
                   '{"actions": [{"include": "ltp.jsonc"}]}')
        self.write("flaky.jsonc", """
        {"actions": [
          {"type": "quarantine", "reason": "r",
           "matchers": ["gvisor:aio_test/AIOTest.CloneVm"]},
          {"type": "quarantine", "reason": "r", "matchers": ["ltp:gone01"]},
        ]}""")
        errors = self.load().check_stale(["ltp:real01"])
        self.assertEqual(len(errors), 1)
        self.assertIn("ltp:gone01", errors[0])


if __name__ == "__main__":
    unittest.main()
