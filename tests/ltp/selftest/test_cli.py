"""End-to-end CLI contract tests (no fixture, no kirk, no network)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from selftest import corpus  # noqa: E402

LTP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(LTP_DIR, "harness.py")

with open(os.path.join(LTP_DIR, "manifest.json"), encoding="utf-8") as _handle:
    FAST_IDS = [
        test["id"] for test in json.load(_handle)["tests"] if test["tier"] == "fast"
    ]


def run_harness(argv, env_overrides=None):
    env = dict(os.environ)
    env.pop("LTP_TEST", None)
    env.pop("LTP_TIER", None)
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        [sys.executable, HARNESS] + argv,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


class ExitContractTest(unittest.TestCase):
    def test_missing_fixture_is_skip_77(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_harness(
                ["run", "--backend", "elfuse"],
                {"LTP_FIXTURE_DIR": os.path.join(tmp, "absent")},
            )
        self.assertEqual(proc.returncode, 77, proc.stdout)
        self.assertIn("build-ltp-fixture", proc.stdout)

    def test_unknown_test_flag_is_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_harness(
                ["run", "--backend", "elfuse", "--test", "no_such_test"],
                {"LTP_FIXTURE_DIR": os.path.join(tmp, "absent")},
            )
        self.assertEqual(proc.returncode, 2, proc.stdout)

    def test_ltp_test_env_is_consumed(self):
        # The old harness accepted LTP_TEST from make and silently ignored
        # it; a bogus id must now fail even though the tier alone is valid.
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_harness(
                ["run", "--backend", "elfuse"],
                {
                    "LTP_FIXTURE_DIR": os.path.join(tmp, "absent"),
                    "LTP_TEST": "no_such_test",
                },
            )
        self.assertEqual(proc.returncode, 2, proc.stdout)

    def test_flag_overrides_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_harness(
                ["run", "--backend", "elfuse", "--test", "readv01"],
                {
                    "LTP_FIXTURE_DIR": os.path.join(tmp, "absent"),
                    "LTP_TEST": "no_such_test",
                },
            )
        # The valid flag wins over the bogus env var; the run then skips
        # on the missing fixture.
        self.assertEqual(proc.returncode, 77, proc.stdout)

    def test_tier_mismatch_is_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_harness(
                ["run", "--backend", "elfuse", "--tier", "fast", "--test", "fcntl34"],
                {"LTP_FIXTURE_DIR": os.path.join(tmp, "absent")},
            )
        self.assertEqual(proc.returncode, 2, proc.stdout)


class RecordAndGateTest(unittest.TestCase):
    def _write_report(self, run_dir, report):
        with open(
            os.path.join(run_dir, "kirk-elfuse.json"), "w", encoding="utf-8"
        ) as handle:
            json.dump(report, handle)

    def test_record_then_gate_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = os.path.join(tmp, "run")
            os.makedirs(run_dir)
            self._write_report(run_dir, corpus.passing_report_fast(FAST_IDS))

            env = {"LTP_BASELINE_DIR": tmp}
            proc = run_harness(
                [
                    "record-baseline",
                    "--backend",
                    "elfuse",
                    "--tier",
                    "fast",
                    "--from-results",
                    run_dir,
                ],
                env,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            baseline_path = os.path.join(tmp, "baseline-elfuse.json")
            self.assertTrue(os.path.isfile(baseline_path))

            with open(baseline_path, encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertEqual(len(data["tests"]), 13)
            self.assertEqual(data["tests"]["readv01"]["status"], "PASS")
            self.assertIsNone(data["tests"]["recv01"]["subtests"])

    def test_record_refuses_missing_results_dir(self):
        # The gate math itself is covered by the baseline unit tests;
        # this exercises the record subcommand's directory validation.
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = os.path.join(tmp, "run")
            os.makedirs(run_dir)
            self._write_report(run_dir, corpus.passing_report_fast(FAST_IDS))
            env = {"LTP_BASELINE_DIR": tmp}
            proc = run_harness(
                [
                    "record-baseline",
                    "--backend",
                    "elfuse",
                    "--tier",
                    "fast",
                    "--from-results",
                    run_dir,
                ],
                env,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)

            proc = run_harness(
                [
                    "record-baseline",
                    "--backend",
                    "elfuse",
                    "--tier",
                    "fast",
                    "--from-results",
                    os.path.join(tmp, "missing"),
                ],
                env,
            )
            self.assertEqual(proc.returncode, 2, proc.stdout)


if __name__ == "__main__":
    unittest.main()
