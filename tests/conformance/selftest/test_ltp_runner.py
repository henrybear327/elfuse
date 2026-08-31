# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from conformance import expectations, providers, report, runner
from conformance.ltp import results
from conformance.model import Status, Verdict
from conformance.selftest.fixture import LocalBackend
from conformance.selection import Entry

REPO = Path(__file__).resolve().parents[3]
STATUS = results.STATUS_PREFIX


def status(**fields):
    fields["schema_version"] = 1
    return STATUS + json.dumps(fields) + "\n"


class ResultsTest(unittest.TestCase):
    def test_buckets_and_runtest(self):
        self.assertEqual([results.bucket_of(t) for t in (1, 120, 121, 900)], [120, 120, 300, 900])
        with self.assertRaises(results.KirkError):
            results.bucket_of(901)
        self.assertEqual(results.runtest_text([("a", ["a", "-x"]), ("b", [])]), "a a -x\nb b\n")

    def test_kirk_argv_binds_the_sut_to_the_channel(self):
        argv = results.kirk_argv(Path("shim"), Path("kirk"), "elfuse", {"binary": "/b", "timeout": 175},
                                 "batch", 145, 1000, Path("r.json"), Path("tmp"))
        self.assertEqual(argv[0], sys.executable)
        self.assertIn("default:com=elfuse", argv)
        self.assertIn("elfuse:binary=/b:timeout=175", argv)
        self.assertEqual(argv[argv.index("--exec-timeout") + 1], "145")

    def test_map_case(self):
        ok = "tst_test.c:1: TPASS: fine\n\nSummary:\npassed   1\nfailed   0\nbroken   0\nskipped  0\nwarnings 0\n"
        table = [
            (("pass", ["0"], ok + status(source="elfuse", timed_out=False, host_signal=0)), Status.PASS),
            (("fail", ["1"], "x: TFAIL: bad\n" + status(source="elfuse", timed_out=False)), Status.FAIL),
            (("conf", ["32"], "x: TCONF: no\n" + status(source="elfuse")), Status.CONF),
            (("pass", ["0"], ok + status(source="elfuse", timed_out=True)), Status.TIMEOUT),
            (("fail", ["139"], status(source="elfuse", host_signal=11)), Status.CRASH),
            (("fail", ["1"], status(source="qemu", execution="transport")), Status.ERROR),
            (("fail", ["126"], status(source="qemu-supervisor", setup_errno=2)), Status.ERROR),
            (("pass", ["1"], ok), Status.INCONSISTENT),
            (("pass", ["0"], ok.replace("failed   0", "failed   1")), Status.INCONSISTENT),
            (("fail", ["1"], ok), Status.INCONSISTENT),
            (("weird", ["0"], ""), Status.ERROR),
        ]
        for (kirk_status, retval, log), want in table:
            got, _, _ = results.map_case(kirk_status, retval, log)
            self.assertEqual(got, want, (kirk_status, retval, log[:40]))
        _, _, detail = results.map_case("fail", ["1"], "a\nx.c:9: TFAIL: bad thing\n")
        self.assertEqual(detail, "x.c:9: TFAIL: bad thing")

    def test_map_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            rep = Path(tmp) / "r.json"
            rep.write_text(json.dumps({"results": [
                {"test_fqn": "chmod01", "status": "pass",
                 "test": {"log": "ok\n" + status(source="elfuse"), "retval": ["0"], "duration": 0.25}},
                {"test_fqn": "chmod02", "status": "fail",
                 "test": {"log": "TFAIL: x\n" + status(source="elfuse", timed_out=True), "retval": ["124"], "duration": 61}},
                {"test_fqn": "chmod03", "status": "brok",
                 "test": {"log": status(source="elfuse", signaled=True, signal=11), "retval": ["139"], "duration": 1}},
                {"test_fqn": "chmod04", "status": "pass",
                 "test": {"log": "ok\n" + status(source="elfuse"), "duration": 1}},
            ]}))
            out = results.map_report(rep, Path(tmp) / "logs")
            self.assertEqual(out["chmod01"].status, Status.PASS)
            self.assertEqual((out["chmod01"].invocation.exit_code, out["chmod01"].invocation.wall_us), (0, 250000))
            self.assertEqual(out["chmod02"].status, Status.TIMEOUT)
            self.assertIsNone(out["chmod02"].invocation.exit_code)
            self.assertEqual((out["chmod03"].status, out["chmod03"].invocation.execution,
                              out["chmod03"].invocation.signal), (Status.CRASH, "signal", 11))
            self.assertEqual((out["chmod04"].invocation.execution, out["chmod04"].invocation.exit_code),
                             ("transport", None))
            self.assertIs(out["chmod04"].status, Status.INCONSISTENT)
            self.assertTrue((Path(tmp) / "logs" / "chmod02.log").is_file())
            with self.assertRaises(results.KirkError):
                results.map_report(Path(tmp) / "none.json", Path(tmp))


class ProviderRunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        root = self.dir / "payload"
        (root / "metadata").mkdir(parents=True)
        (root / "metadata" / "syscalls.runtest").write_text("chmod01 chmod01\nslow01 slow01 -x\nbroken01 broken01\n")
        (root / "kirk").mkdir()
        (root / "rootfs").mkdir()
        self.provider = providers.make("ltp", REPO)
        self.provider.payload_root = lambda: root
        fake = self.dir / "fake-kirk.py"
        fake.write_text(
            "import json, sys\n"
            "args = sys.argv[1:]\n"
            "report = args[args.index('--json-report') + 1]\n"
            "com = args[args.index('--com') + 1]\n"
            "serve = [o for o in com.split(':') if o.startswith('serve=')][0][6:]\n"
            "tags = [l.split()[0] for l in open(serve + '/batch') if l.strip()]\n"
            "rows = []\n"
            "for t in tags:\n"
            "    st = 'fail' if t.startswith('broken') else 'pass'\n"
            "    rows.append({'test_fqn': t, 'status': st, 'test': {'log': ('TFAIL: x\\n' if st == 'fail' else 'ok\\n') + %r + json.dumps({'schema_version': 1, 'source': 'elfuse', 'timed_out': False}) + '\\n', 'retval': ['1' if st == 'fail' else '0'], 'duration': 0.5}})\n"
            "json.dump({'results': rows}, open(report, 'w'))\n" % STATUS)
        self.provider.suite_dir = self.dir
        (self.dir / "kirk").mkdir()
        (self.dir / "kirk" / "shim.py").write_text(fake.read_text())
        (self.dir / "expectations").mkdir()
        self.backend = LocalBackend()
        self.backend.binary = Path("/bin/true")

    def tearDown(self):
        self.tmp.cleanup()

    def test_enumerate_and_buckets(self):
        cases = self.provider.enumerate(self.backend, [Entry("chmod01", "pr"), Entry("slow01", "full", 200)])
        self.assertEqual([c.id for c in cases], ["ltp:chmod01", "ltp:slow01"])
        self.assertEqual(cases[1].meta["argv"], ["slow01", "-x"])
        self.assertEqual([self.provider.batch_key(c) for c in cases], ["bucket-120", "bucket-300"])

    def test_lane_through_the_runner(self):
        self.backend.name = "elfuse"
        cases = self.provider.enumerate(self.backend, [Entry("chmod01", "pr"), Entry("broken01", "pr")])
        (self.dir / "expectations" / "ltp_elfuse.jsonc").write_text(
            '{"actions":[{"type":"expect_pass","matchers":["*"]},'
            '{"type":"expect_failure","reason":"r","matchers":["ltp:broken01"]}]}')
        exps = expectations.load("ltp", "elfuse", self.dir / "expectations")
        out = {r.id: r for r in runner.run_lane(self.provider, self.backend, cases, exps, self.dir / "res")}
        self.assertEqual(out["ltp:chmod01"].verdict, Verdict.AS_EXPECTED)
        self.assertEqual(out["ltp:broken01"].status, Status.FAIL)
        self.assertEqual(out["ltp:broken01"].verdict, Verdict.AS_EXPECTED)
        self.assertEqual(report.gate(out.values()), "green")
        self.assertTrue((self.dir / "res" / out["ltp:chmod01"].attempts[0].invocation.stdout).is_file())
        self.assertEqual(out["ltp:chmod01"].attempts[0].invocation.wall_us, 500000)


if __name__ == "__main__":
    unittest.main()
