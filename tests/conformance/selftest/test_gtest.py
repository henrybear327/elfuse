# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import stat
import tempfile
import unittest
from pathlib import Path

from conformance import expectations, providers, report, runner
from conformance.gvisor import gtest
from conformance.model import Invocation, Status, Verdict
from conformance.selftest.fixture import LocalBackend
from conformance.selection import Entry

REPO = Path(__file__).resolve().parents[3]

LISTING = """PipeTest.
  Seek
  Flags  # GetParam() = 3
Params/OpenTest.
  Blocking/0
"""

FAKE_GTEST = r'''#!/bin/sh
# Fake gtest lists cases, writes XML, and can fail, crash, or hang.
filter="*"
for a; do
  case "$a" in
    --gtest_list_tests) printf 'PipeTest.\n  Seek\n  Flags\n  Fails\n  Crash\n  Hang\n'; exit 0 ;;
    --gtest_filter=*) filter="${a#--gtest_filter=}" ;;
  esac
done
selected() {
  case "$filter" in
    -*) case ":${filter#-}:" in *":$1:"*) return 1 ;; esac; return 0 ;;
    "*") return 0 ;;
    *) case ":$filter:" in *":$1:"*) return 0 ;; esac; return 1 ;;
  esac
}
rc=0
body=""
for c in Seek Flags Fails Crash Hang; do
  selected "PipeTest.$c" || continue
  case "$c" in
    Crash) kill -SEGV $$ ;;
    Hang) sleep 30 ;;
    Fails) body="$body<testcase name=\"$c\" status=\"run\"><failure message=\"x\"/></testcase>"; rc=1 ;;
    Flags) body="$body<testcase name=\"$c\" status=\"run\" result=\"skipped\"/>" ;;
    *) body="$body<testcase name=\"$c\" status=\"run\"/>" ;;
  esac
done
printf '<?xml version="1.0"?><testsuites><testsuite name="PipeTest">%s</testsuite></testsuites>' "$body" > result.xml
exit $rc
'''


class ParseTest(unittest.TestCase):
    def test_listing(self):
        self.assertEqual(gtest.parse_list(LISTING),
                         ["PipeTest.Seek", "PipeTest.Flags", "Params/OpenTest.Blocking/0"])
        for bad in ("  Orphan\n", "PipeTest.\n  A\n  A\n", "", "garbage\n"):
            with self.assertRaises(gtest.GtestError):
                gtest.parse_list(bad)

    def test_run_argv_picks_the_shorter_filter(self):
        include, exclude = ["A.a", "A.b", "A.c"], ["A.d"]
        self.assertIn("--gtest_filter=-A.d", gtest.run_argv("bin", include, exclude))
        self.assertIn("--gtest_filter=A.a", gtest.run_argv("bin", ["A.a"], exclude + ["A.e"]))
        self.assertNotIn("--gtest_filter", " ".join(gtest.run_argv("bin", include, [])))

    def test_resolve_consistency(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml = Path(tmp) / "result.xml"
            xml.write_text('<testsuites><testsuite name="S"><testcase name="a" status="run"/>'
                           '<testcase name="b" status="run"><failure/></testcase>'
                           '<testcase name="c" status="notrun"/></testsuite></testsuites>')
            ok = gtest.resolve(Invocation("normal", 1, exit_code=1), xml, ["S.a", "S.b", "S.c"])
            self.assertEqual({k: v.status for k, v in ok.items()}, {"S.a": Status.PASS, "S.b": Status.FAIL})
            bad = gtest.resolve(Invocation("normal", 1, exit_code=0), xml, ["S.a", "S.b"])
            self.assertEqual({v.status for v in bad.values()}, {Status.INCONSISTENT})
            self.assertEqual(gtest.resolve(Invocation("signal", 1, signal=11), xml, ["S.a", "S.b"]), {})
            one = gtest.resolve(Invocation("timeout", 1), xml, ["S.a"])
            self.assertEqual(one["S.a"].status, Status.TIMEOUT)
            remote = gtest.resolve(Invocation("normal", 1, exit_code=139), xml, ["S.a"])
            self.assertEqual(remote["S.a"].status, Status.CRASH)
            self.assertIn("signal 11", remote["S.a"].detail)
            omitted = gtest.resolve(Invocation("normal", 1, exit_code=0), xml, ["S.c"])
            self.assertEqual(omitted["S.c"].status, Status.INCONSISTENT)


class ProviderRunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.provider = providers.make("gvisor", REPO)
        self.provider.payload_root = lambda: self.dir / "payload"
        self.provider.__class__.scratch = property(lambda p: self.dir / "scratch")
        (self.dir / "payload" / "bin").mkdir(parents=True)
        binary = self.dir / "payload" / "bin" / "pipe_test"
        binary.write_text(FAKE_GTEST)
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
        self.backend = LocalBackend()
        self.provider.selection.extra["case_timeout_s"] = 1
        self.provider.selection.extra["suite_timeout_s"] = 3

    def tearDown(self):
        self.tmp.cleanup()

    def enumerate(self, **kw):
        return self.provider.enumerate(self.backend, [Entry("pipe_test", "pr", **kw)])

    def test_enumerate(self):
        cases = self.enumerate()
        self.assertEqual([c.id for c in cases][:2], ["gvisor:pipe_test/PipeTest.Seek", "gvisor:pipe_test/PipeTest.Flags"])
        self.assertEqual(cases[0].timeout_s, 3)
        only = self.enumerate(only=["PipeTest.Se*"])
        self.assertEqual([c.id for c in only], ["gvisor:pipe_test/PipeTest.Seek"])
        missing = self.provider.enumerate(self.backend, [Entry("nope_test", "pr")])
        self.assertEqual(missing[0].id, "gvisor:nope_test/Harness.ListingFailed")

    def test_lane_through_the_runner(self):
        cases = self.enumerate()
        root = self.dir / "exp"
        root.mkdir()
        (root / "gvisor.jsonc").write_text('{"actions":[{"type":"expect_pass","matchers":["*"]}]}')
        (root / "gvisor_elfuse.jsonc").write_text(
            '{"actions":[{"include":"gvisor.jsonc"},'
            '{"type":"expect_failure","reason":"r","matchers":["gvisor:pipe_test/PipeTest.Fails"]}]}')
        exps = expectations.load("gvisor", "elfuse", root)
        results = {r.id: r for r in runner.run_lane(self.provider, self.backend, cases, exps, self.dir / "res")}
        by = lambda n: results["gvisor:pipe_test/PipeTest." + n]
        self.assertEqual((by("Seek").status, by("Seek").verdict), (Status.PASS, Verdict.AS_EXPECTED))
        self.assertEqual((by("Flags").status, by("Flags").verdict), (Status.SKIP, Verdict.FILTERED))
        self.assertEqual(by("Fails").verdict, Verdict.AS_EXPECTED)
        self.assertEqual(by("Crash").status, Status.CRASH)
        self.assertEqual(by("Crash").attempts[0].invocation.signal, 11)
        self.assertEqual(by("Hang").status, Status.TIMEOUT)
        self.assertEqual(report.gate(results.values()), "red")
        self.assertTrue((self.dir / "res" / by("Seek").attempts[0].invocation.stdout).is_file())

    def test_listing_failure_is_a_harness_error(self):
        cases = self.provider.enumerate(self.backend, [Entry("nope_test", "pr")])
        root = self.dir / "exp"
        root.mkdir()
        (root / "gvisor_elfuse.jsonc").write_text('{"actions":[{"type":"expect_pass","matchers":["*"]}]}')
        exps = expectations.load("gvisor", "elfuse", root)
        results = runner.run_lane(self.provider, self.backend, cases, exps, self.dir / "res")
        self.assertEqual(results[0].verdict, Verdict.ERROR)
        self.assertIn("listing exited", results[0].detail)


if __name__ == "__main__":
    unittest.main()
