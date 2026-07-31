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


class AllModeReferenceTest(unittest.TestCase):
    """In 'all' mode the QEMU reference annotates the elfuse report; it
    must not block the elfuse leg. A reference failure marks the test
    as not attesting conformance in gate-elfuse.json while elfuse still
    runs, gates, and reports. This was observed red against the old
    _require_qemu_green hard stop, which aborted the run instead."""

    FAILING_ID = "readv01"

    def _fake_qemu_report(self):
        results = []
        for test_id in FAST_IDS:
            if test_id == self.FAILING_ID:
                results.append(
                    corpus.kirk_result(
                        test_id,
                        log=corpus.new_api_log(
                            [f"{test_id}.c:40: TFAIL: reference limitation"],
                            summary={"failed": 1},
                        ),
                        failed=1,
                        status="fail",
                    )
                )
                continue
            results.append(
                corpus.kirk_result(
                    test_id,
                    log=corpus.new_api_log(
                        [f"{test_id}.c:40: TPASS: ok"], summary={"passed": 1}
                    ),
                    passed=1,
                )
            )
        return corpus.kirk_report(results)

    def test_elfuse_runs_and_reports_despite_qemu_failure(self):
        from ltp_harness import cli, kirkdrive, vm

        with tempfile.TemporaryDirectory() as tmp:
            fixture = os.path.join(tmp, "fixture")
            os.makedirs(os.path.join(fixture, "kirk", "libkirk"))
            os.makedirs(os.path.join(fixture, "rootfs"))
            for name in ("kirk/libkirk/main.py", ".complete"):
                with open(os.path.join(fixture, name), "w") as handle:
                    handle.write("x\n")
            elfuse_bin = os.path.join(tmp, "elfuse")
            with open(elfuse_bin, "w") as handle:
                handle.write("#!/bin/sh\nexit 0\n")
            os.chmod(elfuse_bin, 0o755)

            qemu_report = self._fake_qemu_report()

            def fake_run_qemu_backend(**kwargs):
                path = os.path.join(kwargs["run_dir"], "kirk-qemu.json")
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(qemu_report, handle)

            def fake_run_kirk(argv, env, log_path):
                report_path = argv[argv.index("--json-report") + 1]
                with open(report_path, "w", encoding="utf-8") as handle:
                    json.dump(corpus.passing_report_fast(FAST_IDS), handle)
                return 0

            saved = (vm.run_qemu_backend, kirkdrive._run_kirk)
            saved_env = os.environ.get("ELFUSE")
            vm.run_qemu_backend = fake_run_qemu_backend
            kirkdrive._run_kirk = fake_run_kirk
            os.environ["ELFUSE"] = elfuse_bin
            try:
                rc = cli.main(
                    [
                        "run",
                        "--backend",
                        "all",
                        "--tier",
                        "fast",
                        "--no-gate",
                        "--fixture-dir",
                        fixture,
                        "--results-dir",
                        os.path.join(tmp, "results"),
                    ]
                )
            finally:
                vm.run_qemu_backend, kirkdrive._run_kirk = saved
                if saved_env is None:
                    os.environ.pop("ELFUSE", None)
                else:
                    os.environ["ELFUSE"] = saved_env

            self.assertEqual(rc, 0)
            run_dirs = os.listdir(os.path.join(tmp, "results"))
            self.assertEqual(len(run_dirs), 1)
            gate_path = os.path.join(
                tmp, "results", run_dirs[0], "gate-elfuse.json"
            )
            self.assertTrue(
                os.path.isfile(gate_path),
                "elfuse leg did not run or report after the qemu failure",
            )
            with open(gate_path, encoding="utf-8") as handle:
                gate = json.load(handle)
            reference = gate["reference"]
            self.assertFalse(reference[self.FAILING_ID]["attesting"])
            self.assertEqual(reference[self.FAILING_ID]["status"], "FAIL")
            other = [t for t in FAST_IDS if t != self.FAILING_ID][0]
            self.assertTrue(reference[other]["attesting"])


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


class SplitBaselineTest(unittest.TestCase):
    """Sweep-tier results record into baseline-<backend>-sweep.json so
    the curated baselines stay hand-reviewable; the gate loads exactly
    the files the selection's tier classes need."""

    SWEEP_ID = "accept01"

    def test_record_partitions_by_tier_class(self):
        report = corpus.passing_report_fast(FAST_IDS + [self.SWEEP_ID])
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = os.path.join(tmp, "run")
            os.makedirs(run_dir)
            with open(
                os.path.join(run_dir, "kirk-elfuse.json"), "w", encoding="utf-8"
            ) as handle:
                json.dump(report, handle)

            proc = run_harness(
                [
                    "record-baseline",
                    "--backend",
                    "elfuse",
                    "--tier",
                    "all",
                    "--from-results",
                    run_dir,
                ],
                {"LTP_BASELINE_DIR": tmp},
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)

            with open(
                os.path.join(tmp, "baseline-elfuse.json"), encoding="utf-8"
            ) as handle:
                curated = json.load(handle)["tests"]
            with open(
                os.path.join(tmp, "baseline-elfuse-sweep.json"), encoding="utf-8"
            ) as handle:
                swept = json.load(handle)["tests"]

            self.assertIn("readv01", curated)
            self.assertNotIn(self.SWEEP_ID, curated)
            self.assertEqual(list(swept), [self.SWEEP_ID])

    def test_record_rejects_ids_outside_the_manifests(self):
        """An observed test no manifest knows is a configuration
        anomaly (stale results directory, edited manifest); recording
        must refuse it rather than silently dropping it from the
        snapshot."""
        report = corpus.passing_report_fast(FAST_IDS + ["ghost01"])
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = os.path.join(tmp, "run")
            os.makedirs(run_dir)
            with open(
                os.path.join(run_dir, "kirk-elfuse.json"), "w", encoding="utf-8"
            ) as handle:
                json.dump(report, handle)

            proc = run_harness(
                [
                    "record-baseline",
                    "--backend",
                    "elfuse",
                    "--tier",
                    "all",
                    "--from-results",
                    run_dir,
                ],
                {"LTP_BASELINE_DIR": tmp},
            )
            self.assertEqual(proc.returncode, 2, proc.stdout)
            self.assertIn("ghost01", proc.stdout)

    def test_gate_needs_only_the_selected_tier_classes(self):
        from ltp_harness import baseline, cli

        pin = {"ltp_release": "r", "ltp_commit": "c", "kirk_tag": "t"}
        curated_test = {"id": "fast01", "tier": "fast"}
        sweep_test = {"id": "sweep01", "tier": "sweep"}

        def write_baseline(path, tests):
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "schema_version": 1,
                        "backend": "elfuse",
                        "pin": pin,
                        "tests": tests,
                    },
                    handle,
                )

        saved = os.environ.get("LTP_BASELINE_DIR")
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["LTP_BASELINE_DIR"] = tmp
            try:
                entry = {"status": "PASS", "subtests": None}
                write_baseline(
                    os.path.join(tmp, "baseline-elfuse.json"), {"fast01": entry}
                )

                # A curated-only selection must not require the sweep file.
                recorded = cli._load_recorded("elfuse", pin, [curated_test])
                self.assertEqual(list(recorded), ["fast01"])

                # A sweep selection without its baseline file is exit-2
                # material, not a silent pass.
                with self.assertRaises(baseline.BaselineError):
                    cli._load_recorded("elfuse", pin, [curated_test, sweep_test])

                write_baseline(
                    os.path.join(tmp, "baseline-elfuse-sweep.json"),
                    {"sweep01": entry},
                )
                recorded = cli._load_recorded(
                    "elfuse", pin, [curated_test, sweep_test]
                )
                self.assertEqual(sorted(recorded), ["fast01", "sweep01"])
            finally:
                if saved is None:
                    os.environ.pop("LTP_BASELINE_DIR", None)
                else:
                    os.environ["LTP_BASELINE_DIR"] = saved


if __name__ == "__main__":
    unittest.main()
