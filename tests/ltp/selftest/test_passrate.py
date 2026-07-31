"""Unit tests for the pass-rate aggregation.

Pins the three rate definitions (pass, pass excluding skips,
conformance over attesting tests), the zero-denominator guards, the
per-group breakdown incl. the (unknown) fallback, the worst-group
ordering, and the markdown failing-list cap with its explicit
overflow marker.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ltp_harness import passrate  # noqa: E402


def observed(**statuses):
    return {
        test_id: {"status": status, "subtests": None}
        for test_id, status in statuses.items()
    }


def tests_by_id(**groups):
    return {
        test_id: {"id": test_id, "group": group}
        for test_id, group in groups.items()
    }


class ComputeTest(unittest.TestCase):
    def test_rates_and_totals(self):
        data = passrate.compute(
            observed(a="PASS", b="PASS", c="FAIL", d="SKIP"),
            None,
            tests_by_id(a="g1", b="g1", c="g2", d="g2"),
        )
        self.assertEqual(data["totals"]["total"], 4)
        self.assertEqual(data["totals"]["PASS"], 2)
        self.assertAlmostEqual(data["rates"]["pass"], 0.5)
        self.assertAlmostEqual(data["rates"]["pass_excl_skip"], 2 / 3)
        self.assertIsNone(data["rates"]["conformance"])
        self.assertIsNone(data["reference"])

    def test_all_skip_selection(self):
        data = passrate.compute(
            observed(a="SKIP", b="SKIP"), None, tests_by_id(a="g", b="g")
        )
        self.assertAlmostEqual(data["rates"]["pass"], 0.0)
        self.assertIsNone(data["rates"]["pass_excl_skip"])

    def test_empty_observed(self):
        data = passrate.compute({}, None, {})
        self.assertIsNone(data["rates"]["pass"])
        self.assertEqual(data["groups"], {})

    def test_conformance_counts_only_attesting(self):
        reference = {
            "a": {"status": "PASS", "attesting": True},
            "b": {"status": "PASS", "attesting": True},
            "c": {"status": "FAIL", "attesting": False},
            "d": {"status": "UNRECORDED", "attesting": False},
        }
        data = passrate.compute(
            observed(a="PASS", b="FAIL", c="PASS", d="PASS"),
            reference,
            tests_by_id(a="g", b="g", c="g", d="g"),
        )
        # c and d pass on elfuse but do not attest; only a of the two
        # attesting tests conforms.
        self.assertAlmostEqual(data["rates"]["conformance"], 0.5)
        self.assertEqual(
            data["reference"],
            {"attesting": 2, "non_pass": 1, "unrecorded": 1},
        )
        self.assertEqual(data["groups"]["g"]["non_attesting"], 2)

    def test_no_attesting_tests_guards_division(self):
        reference = {"a": {"status": "FAIL", "attesting": False}}
        data = passrate.compute(
            observed(a="PASS"), reference, tests_by_id(a="g")
        )
        self.assertIsNone(data["rates"]["conformance"])

    def test_unknown_id_falls_back_to_unknown_group(self):
        data = passrate.compute(observed(ghost="FAIL"), None, {})
        self.assertEqual(data["groups"]["(unknown)"]["FAIL"], 1)
        self.assertEqual(data["groups"]["(unknown)"]["failing"], ["ghost"])

    def test_group_failing_lists_fail_and_broken_only(self):
        data = passrate.compute(
            observed(a="FAIL", b="BROKEN", c="WARN", d="SKIP"),
            None,
            tests_by_id(a="g", b="g", c="g", d="g"),
        )
        self.assertEqual(data["groups"]["g"]["failing"], ["a", "b"])


class RenderTest(unittest.TestCase):
    def test_worst_groups_order_and_green_exclusion(self):
        data = passrate.compute(
            observed(a="PASS", b="FAIL", c="FAIL", d="FAIL", e="PASS"),
            None,
            tests_by_id(a="green", b="worst", c="worst", d="mid", e="mid"),
        )
        self.assertEqual(
            passrate.worst_groups(data), ["worst 0/2", "mid 1/2"]
        )

    def test_summary_line_mentions_conformance_only_with_reference(self):
        plain = passrate.compute(
            observed(a="PASS"), None, tests_by_id(a="g")
        )
        self.assertNotIn("conformance", passrate.summary_line(plain, "qemu", "sweep"))
        with_ref = passrate.compute(
            observed(a="PASS"),
            {"a": {"status": "PASS", "attesting": True}},
            tests_by_id(a="g"),
        )
        line = passrate.summary_line(with_ref, "elfuse", "sweep")
        self.assertIn("conformance 100.0% of 1 attesting", line)

    def test_markdown_caps_failing_ids_with_explicit_overflow(self):
        many = {f"t{index:02d}": "FAIL" for index in range(15)}
        data = passrate.compute(
            observed(**many), None, tests_by_id(**{k: "g" for k in many})
        )
        text = passrate.render_markdown(data, "elfuse", "sweep")
        self.assertIn("+5 more", text)
        self.assertIn("| g | 0/15 | 0.0% |", text)

    def test_markdown_sorts_worst_first(self):
        data = passrate.compute(
            observed(a="PASS", b="FAIL", c="PASS"),
            None,
            tests_by_id(a="alpha", b="beta", c="beta"),
        )
        text = passrate.render_markdown(data, "elfuse", "sweep")
        beta = text.index("| beta |")
        alpha = text.index("| alpha |")
        self.assertLess(beta, alpha)


if __name__ == "__main__":
    unittest.main()
