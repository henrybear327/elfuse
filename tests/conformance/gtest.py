"""gVisor provider: enumerate, batch-run, and attribute gtest binaries.

Execution is whole-binary batched with isolated rerun of unresolved
cases: batching amortizes per-invocation cost (the QEMU lane pays a
round trip per command), gtest XML still yields per-case results, and a
mid-suite crash is repaired by rerunning only the unresolved remainder
one case at a time under the tighter case timeout, which attributes the
crash to the exact case. A batch resolves nothing unless its XML and
exit code agree (all-pass requires exit 0, any failure requires exit
1); an isolated rerun whose exit still contradicts its XML is
INCONSISTENT, because a self-contradictory result measured nothing.
"""

from __future__ import annotations

import pathlib
import xml.etree.ElementTree as ET

from conformance import backends
from conformance.model import Status

GTEST_FLAGS = ("--gtest_color=no", "--gtest_repeat=1")


class GtestParseError(ValueError):
    """A listing or XML report is not in the strict expected shape."""


def _strip_comment(line: str) -> str:
    return line.split("#", 1)[0].rstrip()


def parse_list(text: str) -> list:
    names = []
    seen = set()
    suite = None
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        if line.startswith("  "):
            if suite is None:
                raise GtestParseError("listing has a case before any suite: %r"
                                      % raw)
            name = suite + line.strip()
            if name in seen:
                raise GtestParseError("listing repeats %s" % name)
            seen.add(name)
            names.append(name)
        elif line.endswith("."):
            suite = line
        elif suite is None:
            continue
        else:
            raise GtestParseError(
                "unexpected listing line after the first suite: %r" % raw)
    if not names:
        raise GtestParseError("listing names no test cases")
    return names


def parse_xml(path) -> dict:
    try:
        root = ET.parse(str(path)).getroot()
    except (ET.ParseError, OSError) as exc:
        raise GtestParseError("cannot parse %s: %s" % (path, exc)) from exc
    results = {}
    for suite in root.iter("testsuite"):
        for case in suite.iter("testcase"):
            name = "%s.%s" % (case.get("classname"), case.get("name"))
            if case.get("status") == "notrun":
                continue
            failures = case.findall("failure")
            if failures:
                results[name] = (Status.FAIL,
                                 failures[0].get("message") or "failed")
            elif case.get("result") == "skipped" or \
                    case.findall("skipped"):
                results[name] = (Status.SKIP, "")
            else:
                results[name] = (Status.PASS, "")
    return results


def exit_consistent(results, exit_code: int) -> bool:
    any_fail = any(status is Status.FAIL for status, _ in results.values())
    return exit_code == (1 if any_fail else 0)


def unresolved(planned, resolved) -> list:
    return [name for name in planned if name not in resolved]


def _tail(path, limit=400) -> str:
    try:
        return pathlib.Path(path).read_text(
            encoding="utf-8", errors="replace")[-limit:].strip()
    except OSError:
        return ""


def discover(backend, binary, scratch) -> list:
    scratch = pathlib.Path(scratch) / "list"
    scratch.mkdir(parents=True, exist_ok=True)
    inv = backend.run([backend.host_to_guest(binary), "--gtest_list_tests"],
                      timeout_s=60, scratch=scratch)
    if inv.execution != "normal" or inv.exit_code != 0:
        raise GtestParseError(
            "listing failed (%s, exit %d): %s"
            % (inv.execution, inv.exit_code, _tail(inv.stderr)))
    return parse_list(pathlib.Path(inv.stdout).read_text(
        encoding="utf-8", errors="replace"))


def _classify_abnormal(inv) -> tuple:
    if inv.execution == "timeout":
        return Status.TIMEOUT, "killed at the deadline: %s" % _tail(inv.stderr)
    if inv.execution == "signal":
        return Status.CRASH, "died on signal %d: %s" % (inv.exit_code - 128,
                                                        _tail(inv.stderr))
    return Status.ERROR, "transport loss: %s" % _tail(inv.stderr)


def run_one(backend, binary, name, scratch, case_timeout_s) -> tuple:
    inv = backend.run(
        [backend.host_to_guest(binary), *GTEST_FLAGS,
         "--gtest_filter=%s" % name, "--gtest_output=xml:result.xml"],
        timeout_s=case_timeout_s, scratch=scratch,
        fetch_files=("result.xml",))
    if inv.execution != "normal":
        return _classify_abnormal(inv)
    try:
        results = parse_xml(pathlib.Path(scratch) / "result.xml")
    except GtestParseError as exc:
        return Status.INCONSISTENT, "exit %d but no XML: %s" % (
            inv.exit_code, exc)
    if name not in results:
        return Status.INCONSISTENT, \
            "isolated rerun's XML does not report the case"
    if not exit_consistent({name: results[name]}, inv.exit_code):
        return Status.INCONSISTENT, (
            "exit %d contradicts XML %s"
            % (inv.exit_code, results[name][0].value))
    return results[name]


def run_binary(backend, binary, listing, *, excluded, scratch,
               suite_timeout_s, case_timeout_s) -> dict:
    scratch = pathlib.Path(scratch)
    planned = [name for name in listing if name not in excluded]
    results = {}
    batch = scratch / "batch"
    batch.mkdir(parents=True, exist_ok=True)
    argv = [backend.host_to_guest(binary), *GTEST_FLAGS,
            "--gtest_output=xml:result.xml"]
    if excluded:
        argv.append("--gtest_filter=-%s" % ":".join(sorted(excluded)))
    inv = backend.run(argv, timeout_s=suite_timeout_s, scratch=batch,
                      fetch_files=("result.xml",))
    if inv.execution == "normal":
        try:
            batch_results = parse_xml(batch / "result.xml")
        except GtestParseError:
            batch_results = {}
        if exit_consistent(batch_results, inv.exit_code):
            for name in planned:
                if name in batch_results:
                    results[name] = batch_results[name]
    for index, name in enumerate(unresolved(planned, results)):
        rerun = scratch / ("rerun-%d" % index)
        rerun.mkdir(parents=True, exist_ok=True)
        results[name] = run_one(backend, binary, name, rerun,
                                case_timeout_s)
    return results
