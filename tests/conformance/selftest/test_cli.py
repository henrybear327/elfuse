# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import os
import unittest
import unittest.mock
from pathlib import Path

from conformance import cli, providers, report, sweep
from conformance.backends.base import BackendError
from conformance.selftest.fixture import FixtureProvider, LocalBackend, TempDirTest, setup


class CliTest(TempDirTest):
    def setUp(self):
        super().setUp()
        setup(self.root)
        self.out = []
        self.err = []
        self.registry = unittest.mock.patch.dict(
            providers.REGISTRY, {"fixture": FixtureProvider}, clear=True
        )
        self.backend = unittest.mock.patch.object(
            cli.backends, "make", return_value=LocalBackend()
        )
        self.registry.start()
        self.backend.start()

    def tearDown(self):
        self.backend.stop()
        self.registry.stop()

    def invoke(self, *args):
        self.out.clear()
        self.err.clear()
        return cli.main(list(args), self.root, self.out.append, self.err.append)

    def test_suite_json_uses_a_versioned_envelope(self):
        self.assertEqual(self.invoke("suites", "--format", "json"), 0)
        doc = json.loads(self.out[0])
        self.assertEqual(doc, {
            "kind": "suite-list", "schema_version": 1,
            "suites": ["fixture"],
        })
        self.assertEqual(self.err, [])

    def test_list_all_uses_one_backend(self):
        self.assertEqual(
            self.invoke("list", "fixture", "--scope", "pr", "--backend", "all"),
            0,
        )
        self.assertEqual(self.out, [
            "fixture:basic/pass", "fixture:basic/fail", "fixture:basic/flaky",
            "fixture:basic/quarantined",
        ])
        self.assertEqual(cli.backends.make.call_count, 1)

    def test_run_writes_results_and_report_reads_them(self):
        self.assertEqual(self.invoke("payload", "build", "fixture"), 0)
        results = self.root / "results"
        self.assertEqual(self.invoke(
            "run", "fixture", "--scope", "pr", "--results", str(results)
        ), 0, self.err)
        paths = list(results.rglob(report.RESULTS))
        self.assertEqual(len(paths), 1)
        doc = json.loads(paths[0].read_text())
        self.assertEqual((doc["kind"], doc["gate"]), ("run", "green"))
        flaky = next(c for c in doc["cases"] if c["id"].endswith("/flaky"))
        self.assertEqual(len(flaky["attempts"]), 2)
        self.assertEqual(self.invoke(
            "report", str(paths[0].parent), "--format", "json"
        ), 0)
        self.assertEqual(json.loads(self.out[0])["gate"], "green")

    def test_results_survive_a_failing_stop(self):
        self.assertEqual(self.invoke("payload", "build", "fixture"), 0)
        results = self.root / "results"
        with unittest.mock.patch.object(LocalBackend, "stop",
                                        side_effect=BackendError("vm stuck")):
            self.assertEqual(self.invoke(
                "run", "fixture", "--scope", "pr", "--results", str(results)
            ), 1)
        self.assertEqual(len(list(results.rglob(report.RESULTS))), 1)
        self.assertEqual(self.err[-1], "conformance: backend error: vm stuck")

    def test_a_backend_that_cannot_start_is_red(self):
        self.assertEqual(self.invoke("payload", "build", "fixture"), 0)
        with unittest.mock.patch.object(LocalBackend, "start",
                                        side_effect=BackendError("did not boot")):
            self.assertEqual(self.invoke(
                "run", "fixture", "--scope", "pr",
                "--results", str(self.root / "results")
            ), 1)
        self.assertEqual(self.err[-1], "conformance: backend error: did not boot")

    def test_results_record_the_argv_that_ran(self):
        self.assertEqual(self.invoke("payload", "build", "fixture"), 0)
        results = self.root / "results"
        argv = ["run", "fixture", "--scope", "pr", "--results", str(results)]
        self.assertEqual(self.invoke(*argv), 0, self.err)
        doc = json.loads(next(results.rglob(report.RESULTS)).read_text())
        self.assertEqual(doc["run"]["argv"], argv)

    def test_results_record_the_segments_a_lane_created(self):
        self.assertEqual(self.invoke("payload", "build", "fixture"), 0)
        results = self.root / "results"
        before, after = {(1, "0x1", 7)}, {(1, "0x1", 7), (2, "0x2", 8)}
        with unittest.mock.patch.object(sweep, "shm_ids", side_effect=[before, after]):
            self.assertEqual(self.invoke(
                "run", "fixture", "--scope", "pr", "--results", str(results)
            ), 0, self.err)
        doc = json.loads(next(results.rglob(report.RESULTS)).read_text())
        self.assertEqual(doc["run"]["shm"], [{"id": 2, "key": "0x2", "cpid": 8}])

    def test_case_selector_and_dry_run(self):
        self.assertEqual(self.invoke("payload", "build", "fixture"), 0)
        self.assertEqual(self.invoke(
            "run", "fixture", "--case", "fixture:basic/pa*", "--dry-run"
        ), 0)
        self.assertEqual(self.out, ["fixture:basic/pass"])
        self.assertEqual(self.invoke(
            "run", "fixture", "--case", "fixture:basic/pas", "--dry-run"
        ), 2)
        self.assertIn("near: fixture:basic/pass", self.err[0])

    def test_skip_and_require_are_stable(self):
        args = argparse.Namespace(require=False)
        instance = cli.Cli(self.root, self.out.append, self.err.append)
        with unittest.mock.patch.dict(os.environ, {"CONF_REQUIRE": "0"}):
            self.assertEqual(instance.skip(args, "missing"), 77)
            args.require = True
            self.assertEqual(instance.skip(args, "missing"), 2)
            args.require = False
            os.environ["CONF_REQUIRE"] = "1"
            self.assertEqual(instance.skip(args, "missing"), 2)
        self.assertEqual(self.out, [])
        self.assertEqual(self.err, ["conformance: missing"] * 3)

    def test_expectation_errors_use_stderr(self):
        leaf = self.root / "fixture" / "expectations" / "fixture_elfuse.jsonc"
        leaf.write_text("{")
        self.assertEqual(self.invoke("expectations", "check", "fixture"), 2)
        self.assertEqual(self.out, [])
        self.assertIn("line 1", self.err[0])

    def test_a_provider_must_declare_its_registry_name(self):
        with unittest.mock.patch.dict(providers.REGISTRY, {"other": FixtureProvider}):
            with self.assertRaisesRegex(providers.ProviderError, "declares name"):
                providers.make("other", self.root)

    def clean(self, *args):
        real = sweep.Sweep

        def local(*a, **kw):
            job = real(*a, tmp=self.root / "tmp", user_tmp=self.root / "ut",
                       roots=[self.root / "T"], **kw)
            job.elfuse.lock_file = self.root / "lock"
            return job

        (self.root / "tmp" / "elfuse-fork-Ab12Cd").mkdir(parents=True, exist_ok=True)
        with unittest.mock.patch.object(sweep, "Sweep", local), \
                unittest.mock.patch.object(sweep, "ps_listing", return_value=""), \
                unittest.mock.patch.object(sweep, "ipcs_listing", return_value=""), \
                unittest.mock.patch.object(sweep, "lock_openers", return_value=[4242]):
            return self.invoke("clean", "--results", str(self.root / "r"), *args)

    def test_clean_dry_run_lists_the_scratch_it_would_remove(self):
        self.assertEqual(self.clean("--dry-run"), 0)
        self.assertEqual(self.out, ["would rm -rf %s" % (self.root / "tmp" / "elfuse-fork-Ab12Cd")])
        self.assertEqual(self.err, [])
        self.assertTrue((self.root / "tmp" / "elfuse-fork-Ab12Cd").is_dir())
        self.assertEqual(self.clean(), 0)
        self.assertFalse((self.root / "tmp" / "elfuse-fork-Ab12Cd").exists())

    def test_clean_refuses_while_a_session_holds_a_lock(self):
        holder = LocalBackend()
        holder.lock_file = self.root / "lock"
        with holder.serialize():
            self.assertEqual(self.clean("--dry-run"), 2)
        self.assertEqual(self.out, [])
        self.assertIn("another elfuse conformance session holds", self.err[0])
        self.assertEqual(self.err[1], "conformance: held open by pid 4242")

    def test_parser_has_no_suite_owned_commands(self):
        help_text = cli.build_parser(["fixture"]).format_help()
        self.assertIn("{suites,list,run,payload,selection,expectations,pins,report,clean,selftest}",
                      help_text)
        self.assertNotIn("fixture}", help_text)


if __name__ == "__main__":
    unittest.main()
