"""Selftests for the LTP runner's mapping and timeout layers.

LTP exit codes are OR'd bitmasks (TPASS=0 TFAIL=1 TBROK=2 TWARN=4
TCONF=32), so decoding masks rather than equality-compares, and no
single source of truth is trusted: a kirk status contradicting the exit
code, or a passing status over a Summary block counting failures
(imperfect MAP_SHARED corrupts LTP's shared-memory result accounting),
is INCONSISTENT. The timeout inequality (supervisor cleanup budget
below the kirk exec-timeout slack below the ssh cap slack) is asserted
against the constants in helpers/guest-supervisor.c itself, so the two
files cannot drift apart silently. Code under test:
tests/conformance/ltp.py.
"""

from __future__ import annotations

import re
import unittest

from conformance import ltp
from conformance.kirk_plugins import _common
from conformance.model import Status

LOG_PASS = """\
tst_test.c:1741: TINFO: === Testing on ext4 ===
readv01.c:35: TPASS: readv() returned 64

Summary:
passed   1
failed   0
broken   0
skipped  0
warnings 0
"""

LOG_HIDDEN_FAIL = """\
readv01.c:35: TFAIL: readv() returned 3

Summary:
passed   0
failed   1
broken   0
skipped  0
warnings 0
"""


class PartitionTest(unittest.TestCase):
    def entry(self, tag, timeout):
        return {"id": tag, "timeout_seconds": timeout}

    def test_rounding_up_to_buckets(self):
        tiers = ltp.partition_timeouts([
            self.entry("a01", 60), self.entry("b01", 120),
            self.entry("c01", 121), self.entry("d01", 900)])
        self.assertEqual(sorted(tiers), [120, 300, 900])
        self.assertEqual([e["id"] for e in tiers[120]], ["a01", "b01"])
        self.assertEqual([e["id"] for e in tiers[300]], ["c01"])
        self.assertEqual([e["id"] for e in tiers[900]], ["d01"])

    def test_over_maximum_rejected(self):
        with self.assertRaises(ltp.LtpRunnerError):
            ltp.partition_timeouts([self.entry("a01", 901)])


class DecodeExitTest(unittest.TestCase):
    def test_kirk_mapping(self):
        self.assertIs(ltp.decode_exit(0), Status.PASS)
        self.assertIs(ltp.decode_exit(2), Status.BROK)
        self.assertIs(ltp.decode_exit(-1), Status.BROK)
        self.assertIs(ltp.decode_exit(4), Status.WARN)
        self.assertIs(ltp.decode_exit(32), Status.CONF)

    def test_bitmask_falls_to_fail(self):
        # TFAIL|TCONF = 33: masks are OR'd, equality would misread it.
        self.assertIs(ltp.decode_exit(33), Status.FAIL)
        self.assertIs(ltp.decode_exit(1), Status.FAIL)
        self.assertIs(ltp.decode_exit(6), Status.FAIL)


class SummaryTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(ltp.parse_summary(LOG_PASS),
                         {"passed": 1, "failed": 0, "broken": 0,
                          "skipped": 0, "warnings": 0})

    def test_absent(self):
        self.assertIsNone(ltp.parse_summary("no block here"))


class MapCaseTest(unittest.TestCase):
    def test_consistent_pass(self):
        status, _ = ltp.map_case("pass", ["0"], LOG_PASS)
        self.assertIs(status, Status.PASS)

    def test_hidden_failure_is_inconsistent(self):
        # Exit 0 and kirk status pass, but the log counted a failure:
        # the Gramine MAP_SHARED lesson.
        status, detail = ltp.map_case("pass", ["0"], LOG_HIDDEN_FAIL)
        self.assertIs(status, Status.INCONSISTENT)
        self.assertIn("Summary", detail)

    def test_status_contradicting_exit_is_inconsistent(self):
        status, _ = ltp.map_case("fail", ["0"], LOG_HIDDEN_FAIL)
        self.assertIs(status, Status.INCONSISTENT)

    def test_conf(self):
        status, _ = ltp.map_case("conf", ["32"], "tst_test.c: TCONF: no fs\n")
        self.assertIs(status, Status.CONF)

    def test_fail_detail_names_first_tfail_line(self):
        status, detail = ltp.map_case("fail", ["1"], LOG_HIDDEN_FAIL)
        self.assertIs(status, Status.FAIL)
        self.assertIn("readv01.c:35: TFAIL", detail)

    def test_supervisor_timeout_precedes_ltp_exit_mapping(self):
        log = LOG_HIDDEN_FAIL + _common.harness_status(
            source="qemu-supervisor", timed_out=True, signaled=False,
            cleanup_ok=True, setup_errno=0, exec_errno=0)
        status, detail = ltp.map_case("fail", ["124"], log)
        self.assertIs(status, Status.TIMEOUT)
        self.assertIn("deadline", detail)

    def test_supervisor_signal_is_a_crash(self):
        log = LOG_HIDDEN_FAIL + _common.harness_status(
            source="qemu-supervisor", timed_out=False, signaled=True,
            signal=11, cleanup_ok=True, setup_errno=0, exec_errno=0)
        status, detail = ltp.map_case("fail", ["139"], log)
        self.assertIs(status, Status.CRASH)
        self.assertIn("11", detail)

    def test_supervisor_setup_failure_is_an_error(self):
        log = LOG_HIDDEN_FAIL + _common.harness_status(
            source="qemu-supervisor", timed_out=False, signaled=False,
            cleanup_ok=True, setup_errno=2, exec_errno=0)
        status, detail = ltp.map_case("fail", ["126"], log)
        self.assertIs(status, Status.ERROR)
        self.assertIn("setup", detail)

    def test_transport_failure_is_an_error(self):
        log = LOG_HIDDEN_FAIL + _common.harness_status(
            source="qemu-channel", execution="transport",
            error="SSH transport was lost")
        status, detail = ltp.map_case("brok", ["-1"], log)
        self.assertIs(status, Status.ERROR)
        self.assertIn("transport", detail)

    def test_last_machine_record_is_authoritative(self):
        forged = _common.harness_status(
            source="test-output", timed_out=True)
        channel = _common.harness_status(
            source="elfuse-channel", channel_timed_out=False,
            host_signal=0, shm_error="")
        status, _ = ltp.map_case("pass", ["0"],
                                 forged + LOG_PASS + channel)
        self.assertIs(status, Status.PASS)

    def test_malformed_machine_record_is_an_error(self):
        log = LOG_PASS + _common.HARNESS_STATUS_PREFIX + "{bad json}\n"
        status, _ = ltp.map_case("pass", ["0"], log)
        self.assertIs(status, Status.ERROR)


class TimeoutLayeringTest(unittest.TestCase):
    def test_supervisor_constants_and_inequality(self):
        text = (ltp.HELPERS_DIR / "guest-supervisor.c").read_text(
            encoding="utf-8")
        constants = dict(re.findall(
            r"#define (TERM_GRACE_SEC|KILL_WAIT_SEC|REAP_POLL_SEC) (\d+)",
            text))
        self.assertEqual(len(constants), 3, "supervisor constants renamed")
        budget = sum(int(v) for v in constants.values()) + 1
        self.assertEqual(budget, ltp.SUPERVISOR_CLEANUP_BUDGET_SEC)
        self.assertLess(ltp.SUPERVISOR_CLEANUP_BUDGET_SEC,
                        ltp.QEMU_EXEC_SLACK_SEC)
        self.assertLess(ltp.QEMU_EXEC_SLACK_SEC, ltp.CHANNEL_CAP_SLACK_SEC)


if __name__ == "__main__":
    unittest.main()
