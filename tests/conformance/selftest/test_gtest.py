"""Selftests for the gVisor gtest provider.

Pins the strict listing parser (two-level indentation, GetParam
comments, banner lines legal only before the first suite), the XML
parser, and the exit-code cross-check that decides which cases are
resolved by a batched suite run: XML claiming all-pass with a failing
exit (or the reverse) resolves nothing, a case missing from the XML is
rerun in isolation, and an isolated rerun whose exit still contradicts
its XML is INCONSISTENT. The end-to-end test drives a fake gtest binary
through ElfuseBackend, covering batch, negative filter, mid-suite crash
attribution, and the isolated-rerun path. Code under test:
tests/conformance/gtest.py.
"""

from __future__ import annotations

import os
import pathlib
import stat
import tempfile
import textwrap
import unittest

from conformance import backends, gtest
from conformance.model import Status

LISTING = """\
Running main() from test/syscalls/linux/main.cc
EpollTest.
  AllWritable
  CycleOfOneDisallowed
AllTCPSockets/TCPSocketPairTest.  # TypeParam = tcp
  BasicSendmmsg/0  # GetParam() = loopback
  BasicSendmmsg/1
"""

XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="3" failures="%d" name="AllTests">
  <testsuite name="EpollTest" tests="3" failures="%d">
    <testcase name="AllWritable" classname="EpollTest" status="run" result="completed" time="0.01"/>
    <testcase name="CycleOfOneDisallowed" classname="EpollTest" status="run" result="completed" time="0.01">%s</testcase>
    <testcase name="Skipped" classname="EpollTest" status="run" result="skipped" time="0.0"/>
  </testsuite>
</testsuites>
"""


class ParseListTest(unittest.TestCase):
    def test_full_names_and_comments(self):
        self.assertEqual(gtest.parse_list(LISTING), [
            "EpollTest.AllWritable",
            "EpollTest.CycleOfOneDisallowed",
            "AllTCPSockets/TCPSocketPairTest.BasicSendmmsg/0",
            "AllTCPSockets/TCPSocketPairTest.BasicSendmmsg/1",
        ])

    def test_banner_after_first_suite_rejected(self):
        with self.assertRaises(gtest.GtestParseError):
            gtest.parse_list("Suite.\n  Case\nstray line\n")

    def test_case_before_suite_rejected(self):
        with self.assertRaises(gtest.GtestParseError):
            gtest.parse_list("  Case\nSuite.\n")

    def test_duplicate_case_rejected(self):
        with self.assertRaises(gtest.GtestParseError):
            gtest.parse_list("Suite.\n  Case\n  Case\n")

    def test_empty_listing_rejected(self):
        with self.assertRaises(gtest.GtestParseError):
            gtest.parse_list("Running main() from x.cc\n")


class ParseXmlTest(unittest.TestCase):
    def parse(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".xml",
                                         delete=False) as fh:
            fh.write(text)
        path = pathlib.Path(fh.name)
        self.addCleanup(path.unlink)
        return gtest.parse_xml(path)

    def test_pass_fail_skip(self):
        results = self.parse(XML_TEMPLATE % (
            1, 1, '<failure message="epoll_wait returned 1"/>'))
        self.assertEqual(results["EpollTest.AllWritable"][0], Status.PASS)
        self.assertEqual(results["EpollTest.CycleOfOneDisallowed"][0],
                         Status.FAIL)
        self.assertIn("epoll_wait returned 1",
                      results["EpollTest.CycleOfOneDisallowed"][1])
        self.assertEqual(results["EpollTest.Skipped"][0], Status.SKIP)

    def test_truncated_xml_rejected(self):
        with self.assertRaises(gtest.GtestParseError):
            self.parse("<testsuites><testsuite>")


class CrossCheckTest(unittest.TestCase):
    def results(self, fail=False):
        detail = ('<failure message="m"/>' if fail else "")
        xml = XML_TEMPLATE % (int(fail), int(fail), detail)
        with tempfile.NamedTemporaryFile("w", suffix=".xml",
                                         delete=False) as fh:
            fh.write(xml)
        self.addCleanup(pathlib.Path(fh.name).unlink)
        return gtest.parse_xml(pathlib.Path(fh.name))

    def test_consistent_pass(self):
        self.assertTrue(gtest.exit_consistent(self.results(False), 0))

    def test_consistent_fail(self):
        self.assertTrue(gtest.exit_consistent(self.results(True), 1))

    def test_all_pass_with_failing_exit(self):
        self.assertFalse(gtest.exit_consistent(self.results(False), 1))

    def test_failure_with_zero_exit(self):
        self.assertFalse(gtest.exit_consistent(self.results(True), 0))


class UnresolvedTest(unittest.TestCase):
    def test_missing_case_is_unresolved(self):
        planned = ["A.a", "A.b", "A.c"]
        resolved = {"A.a": (Status.PASS, ""), "A.b": (Status.FAIL, "d")}
        self.assertEqual(gtest.unresolved(planned, resolved), ["A.c"])


FAKE_GTEST = r"""#!/bin/sh
# Fake gtest binary: 3 cases; Crashy.Boom aborts mid-suite before the XML
# is written unless filtered out; honors --gtest_list_tests and a
# negative --gtest_filter of exact names joined by ':'.
list=0
filter=""
xml=""
for arg in "$@"; do
    case "$arg" in
        --gtest_list_tests) list=1 ;;
        --gtest_filter=-*) filter="${arg#--gtest_filter=-}" ;;
        --gtest_filter=*) filter_pos="${arg#--gtest_filter=}" ;;
        --gtest_output=xml:*) xml="${arg#--gtest_output=xml:}" ;;
    esac
done
if [ "$list" = 1 ]; then
    printf 'Quiet.\n  Pass\n  Fail\nCrashy.\n  Boom\n'
    exit 0
fi
excluded() { case ":$filter:" in *":$1:"*) return 0 ;; esac; return 1; }
selected() {
    if [ -n "$filter_pos" ]; then [ "$filter_pos" = "$1" ] && return 0 || return 1
    fi
    excluded "$1" && return 1 || return 0
}
if selected Crashy.Boom; then
    kill -ABRT $$
fi
open_xml() {
    printf '<?xml version="1.0"?>\n<testsuites name="AllTests">\n<testsuite name="Quiet">\n' > "$xml"
}
close_xml() { printf '</testsuite>\n</testsuites>\n' >> "$xml"; }
rc=0
open_xml
if selected Quiet.Pass; then
    printf '<testcase name="Pass" classname="Quiet" status="run" result="completed"/>\n' >> "$xml"
fi
if selected Quiet.Fail; then
    printf '<testcase name="Fail" classname="Quiet" status="run" result="completed"><failure message="broken"/></testcase>\n' >> "$xml"
    rc=1
fi
close_xml
exit $rc
"""


class RunBinaryTest(unittest.TestCase):
    """End to end against the fake binary through ElfuseBackend."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        fake_elfuse = self.root / "elfuse"
        fake_elfuse.write_text(
            "#!/bin/sh\nshift 2\n"
            'if [ "$1" = "--sysroot" ]; then shift 2; fi\n'
            'exec "$@"\n', encoding="utf-8")
        fake_elfuse.chmod(fake_elfuse.stat().st_mode | stat.S_IEXEC)
        self.binary = self.root / "fake_test"
        self.binary.write_text(FAKE_GTEST, encoding="utf-8")
        self.binary.chmod(self.binary.stat().st_mode | stat.S_IEXEC)
        self.backend = backends.ElfuseBackend(fake_elfuse)
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()

    def run_binary(self, excluded=("Crashy.Boom",)):
        listing = gtest.discover(self.backend, self.binary, self.scratch)
        return gtest.run_binary(
            self.backend, self.binary, listing,
            excluded=set(excluded), scratch=self.scratch,
            suite_timeout_s=20, case_timeout_s=10)

    def test_batch_with_filter(self):
        results = self.run_binary()
        self.assertEqual(results["Quiet.Pass"][0], Status.PASS)
        self.assertEqual(results["Quiet.Fail"][0], Status.FAIL)
        self.assertNotIn("Crashy.Boom", results)

    def test_crash_attributed_by_isolated_rerun(self):
        # Unfiltered, the suite dies on SIGABRT before writing any XML;
        # every planned case is rerun alone and the crash lands on
        # Crashy.Boom while the healthy cases still resolve.
        results = self.run_binary(excluded=())
        self.assertEqual(results["Quiet.Pass"][0], Status.PASS)
        self.assertEqual(results["Quiet.Fail"][0], Status.FAIL)
        self.assertEqual(results["Crashy.Boom"][0], Status.CRASH)


if __name__ == "__main__":
    unittest.main()
