"""Selftests for the CLI's exit-code contract and report gate.

The exit codes are the interface mk/tests.mk and CI build on, so they
are exercised through real subprocess invocations: 77 when a payload is
absent, 2 for the same condition under CONF_REQUIRE=1 (a silent SKIP in
a gating job would be a fake green), 2 for unusable flags, 0 for
lint-expectations over the committed files. The report tests pin the
one invariant the gate rests on: an empty result set is red. Code under
test: tests/conformance/cli.py and tests/conformance/report.py.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from conformance import cli, expectations, report
from conformance.model import Attempt, CaseResult, Status, Verdict

CLI = pathlib.Path(__file__).resolve().parents[1] / "cli.py"


def run_cli(*argv, env_extra=None):
    env = dict(os.environ)
    env.pop("CONF_REQUIRE", None)
    # Hermetic regardless of payloads built on this host: an empty
    # payload root makes every lane provably absent.
    env["CONF_PAYLOAD_DIR"] = tempfile.mkdtemp(prefix="conf-empty-")
    env.update(env_extra or {})
    return subprocess.run([sys.executable, str(CLI), *argv],
                         capture_output=True, text=True, env=env)


class ExitCodeTest(unittest.TestCase):
    def test_absent_payload_skips_77(self):
        result = run_cli("run", "--suite", "gvisor", "--backend", "elfuse")
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertIn("build-gvisor-payload", result.stdout)

    def test_conf_require_turns_skip_into_config_error(self):
        result = run_cli("run", "--suite", "gvisor", "--backend", "elfuse",
                         env_extra={"CONF_REQUIRE": "1"})
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_bad_flags_are_usage_errors(self):
        result = run_cli("run", "--suite", "nonesuch", "--backend", "elfuse")
        self.assertEqual(result.returncode, 2)

    def test_lint_over_committed_files(self):
        result = run_cli("lint-expectations")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_pin_lookup(self):
        result = run_cli("pin", "kirk.tag")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "v4.1.0")

    def test_unknown_pin_is_config_error(self):
        result = run_cli("pin", "kirk.branch")
        self.assertEqual(result.returncode, 2)


class ReportGateTest(unittest.TestCase):
    def case(self, verdict):
        return CaseResult(
            id="ltp:x01", suite="ltp", backend="elfuse",
            status=Status.PASS, verdict=verdict,
            expectation={}, attempts=[Attempt(Status.PASS, 0, 1, "normal",
                                              "")],
            detail="", artifacts="")

    def test_empty_result_set_is_red(self):
        self.assertEqual(report.gate([]), "red")

    def test_flaked_and_filtered_stay_green(self):
        cases = [self.case(Verdict.AS_EXPECTED), self.case(Verdict.FLAKED),
                 self.case(Verdict.FILTERED)]
        self.assertEqual(report.gate(cases), "green")

    def test_any_red_verdict_is_red(self):
        cases = [self.case(Verdict.AS_EXPECTED),
                 self.case(Verdict.UNEXPECTED_PASS)]
        self.assertEqual(report.gate(cases), "red")

    def test_results_json_rederives_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            report.write_results(tmp, {"lane": "t"},
                                 [self.case(Verdict.AS_EXPECTED)])
            self.assertEqual(report.load_gate(tmp), "green")
            self.assertTrue((pathlib.Path(tmp) / "junit.xml").is_file())

    def test_stored_gate_cannot_override_red_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            report.write_results(tmp, {"lane": "t"},
                                 [self.case(Verdict.UNEXPECTED_FAILURE)])
            path = pathlib.Path(tmp) / "results.json"
            doc = json.loads(path.read_text(encoding="utf-8"))
            doc["gate"] = "green"
            path.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(report.ReportError):
                report.load_gate(tmp)
            result = run_cli("report", "--results", tmp)
            self.assertEqual(result.returncode, 2)
            self.assertIn("contradicts", result.stderr)

    def test_stored_counts_must_match_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            report.write_results(tmp, {"lane": "t"},
                                 [self.case(Verdict.AS_EXPECTED)])
            path = pathlib.Path(tmp) / "results.json"
            doc = json.loads(path.read_text(encoding="utf-8"))
            doc["counts"] = {"status": {}, "verdict": {}}
            path.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(report.ReportError):
                report.load_gate(tmp)


class LtpRetryTest(unittest.TestCase):
    def run_lane(self, statuses):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            runtest = root / "payloads" / "ltp" / "rootfs" / "opt" / \
                "ltp" / "runtest"
            runtest.mkdir(parents=True)
            results = root / "results"
            results.mkdir()
            entry = {"id": "retry01", "arguments": ["retry01"],
                     "timeout_seconds": 120}
            resolution = expectations.Resolution(
                type="expect_pass", file="flaky.jsonc",
                matcher="ltp:retry01", reason=None, bug=None,
                quarantined=True)
            exp = mock.Mock()
            exp.resolve.return_value = resolution
            args = SimpleNamespace(bootstrap=False, filter="ltp:retry01",
                                   tier="fast")
            mapped = [{"retry01": (status, status.value)}
                      for status in statuses]

            def fake_kirk(argv, ltproot):
                del ltproot
                report_path = pathlib.Path(
                    argv[argv.index("--json-report") + 1])
                report_path.write_text("{}", encoding="utf-8")
                return 0

            with mock.patch.object(cli, "PAYLOAD_ROOT", root / "payloads"), \
                    mock.patch.object(cli, "_ltp_entries",
                                      return_value=[entry]), \
                    mock.patch.object(cli.ltp, "run_kirk",
                                      side_effect=fake_kirk), \
                    mock.patch.object(cli.ltp, "map_report",
                                      side_effect=mapped):
                cases, messages, error = cli._ltp_lane(
                    args, exp, SimpleNamespace(name="elfuse"), results)
        self.assertIsNone(error)
        return cases[0], messages

    def test_red_attempt_retries_until_expected(self):
        case, messages = self.run_lane([Status.FAIL, Status.PASS])
        self.assertEqual([attempt.status for attempt in case.attempts],
                         [Status.FAIL, Status.PASS])
        self.assertIs(case.verdict, Verdict.FLAKED)
        self.assertEqual(messages, [])

    def test_persistent_red_attempt_uses_full_budget(self):
        case, messages = self.run_lane(
            [Status.FAIL, Status.FAIL, Status.FAIL])
        self.assertEqual(len(case.attempts), 3)
        self.assertIs(case.verdict, Verdict.UNEXPECTED_FAILURE)
        self.assertEqual(len(messages), 1)


if __name__ == "__main__":
    unittest.main()
