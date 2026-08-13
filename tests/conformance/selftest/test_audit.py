"""Selftests for the gVisor roster audit.

The roster must cover the pinned test/syscalls/linux/BUILD exactly: an
enabled or declined target that vanished upstream and an upstream binary
that is neither enabled nor declined are both errors, so a pin bump
forces triage instead of silently shrinking coverage. BUILD parsing is
block-aware because the file also declares a cc_library whose name ends
in _test (base_poll_test at the current pin). All set comparison happens
in Python: locale-collated shell sorting misordered preadv_test against
preadv2_test during development and produced a false mismatch. Code
under test: tests/conformance/audit.py.
"""

from __future__ import annotations

import pathlib
import tempfile
import unittest

from conformance import audit

BUILD = """
cc_library(
    name = "base_poll_test",
    testonly = 1,
)

cc_binary(
    name = "read_test",
    testonly = 1,
)

cc_binary(
    name = "write_test",
    testonly = 1,
)

cc_binary(
    name = "preadv_test",
    testonly = 1,
)
"""

PREFIX = "//test/syscalls/linux:"


def roster(enabled, declined_targets):
    return {
        "schema_version": 1,
        "enabled": [PREFIX + t for t in enabled],
        "declined": [
            {"reason": "r", "targets": [PREFIX + t for t in declined_targets]},
        ],
    }


class ParseBuildTest(unittest.TestCase):
    def test_binaries_only(self):
        self.assertEqual(
            audit.parse_build(BUILD),
            [PREFIX + "preadv_test", PREFIX + "read_test",
             PREFIX + "write_test"])


class CompareTest(unittest.TestCase):
    def upstream(self):
        return audit.parse_build(BUILD)

    def test_exact_cover_is_clean(self):
        errors = audit.compare(roster(["read_test", "write_test"],
                                      ["preadv_test"]), self.upstream())
        self.assertEqual(errors, [])

    def test_vanished_target_reported(self):
        errors = audit.compare(
            roster(["read_test", "write_test", "gone_test"],
                   ["preadv_test"]), self.upstream())
        self.assertEqual(len(errors), 1)
        self.assertIn("gone_test", errors[0])
        self.assertIn("vanished", errors[0])

    def test_untriaged_upstream_reported(self):
        errors = audit.compare(roster(["read_test"], ["preadv_test"]),
                               self.upstream())
        self.assertEqual(len(errors), 1)
        self.assertIn("write_test", errors[0])
        self.assertIn("triage", errors[0])

    def test_overlap_reported(self):
        errors = audit.compare(
            roster(["read_test", "write_test"],
                   ["preadv_test", "read_test"]), self.upstream())
        self.assertEqual(len(errors), 1)
        self.assertIn("read_test", errors[0])
        self.assertIn("both", errors[0])

    def test_duplicate_reported(self):
        errors = audit.compare(
            roster(["read_test", "read_test", "write_test"],
                   ["preadv_test"]), self.upstream())
        self.assertEqual(len(errors), 1)
        self.assertIn("read_test", errors[0])


class CommittedRosterTest(unittest.TestCase):
    def test_committed_roster_loads(self):
        enabled, declined = audit.load_roster(audit.ROSTER_PATH)
        self.assertEqual(len(enabled), 128)
        self.assertEqual(sum(len(row["targets"]) for row in declined), 117)


if __name__ == "__main__":
    unittest.main()
