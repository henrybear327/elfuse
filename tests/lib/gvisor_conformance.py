#!/usr/bin/env python3
"""Strict result handling for the gVisor syscall conformance lane."""

# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

BACKENDS = ("elfuse-aarch64", "qemu-aarch64")
EXPECTED_STATES = ("PASS", "SKIP", "XFAIL")
# EXCLUDE rows document tests that are never executed on a backend, for
# example tests that crash on the reference kernel itself.
MANIFEST_STATES = EXPECTED_STATES + ("EXCLUDE",)
FINAL_STATES = ("PASS", "FAIL", "SKIP", "BROKEN", "TIMEOUT", "SIGNAL", "XFAIL", "XPASS")
TEST_RE = re.compile(r"[A-Za-z0-9_/]+\.[A-Za-z0-9_/]+")


class ValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Expectation:
    test: str
    backend: str
    expected: str
    reason: str
    issue: str


@dataclass(frozen=True)
class Classification:
    actual: str
    final: str
    fatal: bool
    detail: str


@dataclass(frozen=True)
class SuiteCase:
    test: str
    state: str
    detail: str
    duration_ms: int


def read_utf8(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"output is not valid UTF-8: {exc}") from exc


def test_slug(test: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", test)


def is_disabled(test: str) -> bool:
    return any(
        segment.startswith("DISABLED_")
        for part in test.split(".")
        for segment in part.split("/")
    )


def parse_gtest_list(text: str) -> List[str]:
    tests: List[str] = []
    suite: Optional[str] = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if not line or line.lstrip().startswith("#"):
            continue
        if line[:1].isspace():
            if suite is None:
                raise ValidationError("test entry appeared before a suite")
            test = line.strip().split("#", 1)[0].rstrip()
            if not test:
                raise ValidationError("empty GoogleTest name")
            tests.append(suite + test)
        else:
            heading = line.split("#", 1)[0].rstrip()
            if not heading.endswith("."):
                raise ValidationError(f"malformed suite heading: {line!r}")
            suite = heading
    if not tests:
        raise ValidationError("GoogleTest listing contained no tests")
    if len(tests) != len(set(tests)):
        raise ValidationError("GoogleTest listing contained duplicate tests")
    for test in tests:
        if not TEST_RE.fullmatch(test):
            raise ValidationError(f"invalid GoogleTest name: {test!r}")
    return tests


def read_test_names(path: Path) -> List[str]:
    tests: List[str] = []
    seen = set()
    for lineno, line in enumerate(read_utf8(path).splitlines(), 1):
        if not line:
            raise ValidationError(f"empty test name on line {lineno}")
        if not TEST_RE.fullmatch(line):
            raise ValidationError(f"invalid test name on line {lineno}: {line!r}")
        if line in seen:
            raise ValidationError(f"duplicate test name: {line}")
        seen.add(line)
        tests.append(line)
    if not tests:
        raise ValidationError(f"test list is empty: {path}")
    return tests


def parse_gtest_suite_xml(path: Path) -> List[SuiteCase]:
    root = ET.parse(path).getroot()
    cases: List[SuiteCase] = []
    seen = set()
    for case in root.findall(".//testcase"):
        name = case.get("name")
        classname = case.get("classname")
        if not name or not classname:
            raise ValidationError("testcase is missing name or classname")
        test = f"{classname}.{name}"
        if not TEST_RE.fullmatch(test):
            raise ValidationError(f"invalid testcase name: {test!r}")
        if test in seen:
            raise ValidationError(f"duplicate testcase in XML: {test}")
        seen.add(test)
        if case.get("status") != "run":
            if is_disabled(test):
                continue
            raise ValidationError(
                f"testcase {test} was not run (status={case.get('status')!r})"
            )

        try:
            duration_ms = int(float(case.get("time", "0")) * 1000)
        except ValueError as exc:
            raise ValidationError(f"testcase {test} has an invalid time") from exc
        skipped = case.findall("skipped")
        failures = case.findall("failure") + case.findall("error")
        if skipped and failures:
            raise ValidationError(f"testcase {test} is both skipped and failed")
        if len(skipped) > 1:
            raise ValidationError(f"testcase {test} has ambiguous result elements")
        if skipped:
            if case.get("result") not in (None, "skipped"):
                raise ValidationError(
                    f"skipped testcase {test} has result={case.get('result')!r}"
                )
            cases.append(SuiteCase(test, "SKIP", skipped[0].get("message", ""), duration_ms))
            continue
        if case.get("result") not in (None, "completed"):
            raise ValidationError(
                f"testcase {test} did not complete (result={case.get('result')!r})"
            )
        if failures:
            messages = [failure.get("message", "") for failure in failures]
            detail = "; ".join(message for message in messages if message)
            cases.append(SuiteCase(test, "FAIL", detail, duration_ms))
        else:
            cases.append(SuiteCase(test, "PASS", "", duration_ms))
    if not cases:
        raise ValidationError("suite XML contained no executed testcases")
    return cases


def classify_abnormal(execution: str, exit_code: int) -> Optional[Classification]:
    if execution == "transport":
        return Classification("BROKEN", "BROKEN", True, "backend transport or setup failed")
    if execution == "timeout":
        return Classification("TIMEOUT", "TIMEOUT", True, "external timeout expired")
    if execution == "signal":
        signal_number = exit_code - 128 if exit_code > 128 else 0
        return Classification("SIGNAL", "SIGNAL", True, f"terminated by signal {signal_number}")
    if execution != "normal":
        return Classification("BROKEN", "BROKEN", True, f"unknown execution state {execution}")
    if 128 < exit_code <= 255:
        return Classification(
            "SIGNAL", "SIGNAL", True, f"terminated by signal {exit_code - 128}"
        )
    return None


def apply_expectation(result: Classification, expected: str) -> Classification:
    if result.final in ("BROKEN", "TIMEOUT", "SIGNAL"):
        return result
    reported = result.actual
    if expected == "XFAIL":
        if reported == "FAIL":
            return Classification("FAIL", "XFAIL", False, "expected assertion failure")
        if reported == "PASS":
            return Classification("PASS", "XPASS", True, "declared XFAIL passed")
        return Classification("SKIP", "SKIP", True, "expected XFAIL, got SKIP")
    if reported != expected:
        detail = f"expected {expected}, got {reported}"
        if result.detail:
            detail += f": {result.detail}"
        return Classification(reported, reported, True, detail)
    return Classification(reported, reported, False, result.detail)


def classify_gtest_case(
    xml_path: Path,
    selected_test: str,
    exit_code: int,
    execution: str = "normal",
) -> Classification:
    abnormal = classify_abnormal(execution, exit_code)
    if abnormal is not None:
        return abnormal
    if not xml_path.is_file():
        return Classification("BROKEN", "BROKEN", True, "missing GoogleTest XML")
    try:
        cases = parse_gtest_suite_xml(xml_path)
    except (OSError, ET.ParseError, ValidationError) as exc:
        return Classification("BROKEN", "BROKEN", True, str(exc))
    if len(cases) != 1:
        return Classification(
            "BROKEN", "BROKEN", True, f"expected exactly one testcase, found {len(cases)}"
        )
    case = cases[0]
    if case.test != selected_test:
        return Classification(
            "BROKEN", "BROKEN", True, f"XML names {case.test!r}, expected {selected_test!r}"
        )
    required_exit = {"PASS": 0, "SKIP": 0, "FAIL": 1}[case.state]
    if exit_code != required_exit:
        return Classification(
            "BROKEN",
            "BROKEN",
            True,
            f"{case.state} XML requires exit {required_exit}, got {exit_code}",
        )
    return Classification(case.state, case.state, case.state == "FAIL", case.detail)


def load_expectations(
    path: Path, tests: Sequence[str]
) -> Dict[Tuple[str, str], Expectation]:
    lines = read_utf8(path).splitlines()
    data_lines = [
        (n, line) for n, line in enumerate(lines, 1) if line and not line.startswith("#")
    ]
    if not data_lines:
        raise ValidationError("expectations manifest is empty")
    header_lineno, header = data_lines[0]
    if header != "test\tbackend\texpected\treason\tissue":
        raise ValidationError(f"invalid expectations header on line {header_lineno}")

    known_tests = set(tests)
    entries: Dict[Tuple[str, str], Expectation] = {}
    for lineno, line in data_lines[1:]:
        fields = line.split("\t")
        if len(fields) != 5:
            raise ValidationError(f"line {lineno}: expected five tab-separated fields")
        test, backend, expected, reason, issue = fields
        if any(char in test for char in "*?["):
            raise ValidationError(f"line {lineno}: wildcard test names are forbidden")
        if not TEST_RE.fullmatch(test):
            raise ValidationError(f"line {lineno}: invalid test name {test!r}")
        if test not in known_tests:
            raise ValidationError(f"line {lineno}: unknown test {test}")
        if backend not in BACKENDS:
            raise ValidationError(f"line {lineno}: invalid backend {backend!r}")
        if expected not in MANIFEST_STATES:
            raise ValidationError(f"line {lineno}: invalid expected state {expected!r}")
        if not reason:
            raise ValidationError(f"line {lineno}: reason must not be empty")
        if expected in ("SKIP", "XFAIL", "EXCLUDE") and reason == "-":
            raise ValidationError(f"line {lineno}: {expected} requires a concrete reason")
        if expected == "XFAIL" and issue == "-":
            raise ValidationError(f"line {lineno}: XFAIL requires an issue or reference")
        key = (test, backend)
        if key in entries:
            raise ValidationError(f"line {lineno}: duplicate expectation for {test} on {backend}")
        entries[key] = Expectation(test, backend, expected, reason, issue)

    required = {(test, backend) for test in tests for backend in BACKENDS}
    missing = sorted(required.difference(entries))
    if missing:
        test, backend = missing[0]
        raise ValidationError(f"missing expectation for {test} on {backend}")
    extra = sorted(set(entries).difference(required))
    if extra:
        test, backend = extra[0]
        raise ValidationError(f"unexpected expectation for {test} on {backend}")
    return entries


def load_plan(path: Path) -> Dict[str, Expectation]:
    entries: Dict[str, Expectation] = {}
    for lineno, line in enumerate(read_utf8(path).splitlines(), 1):
        fields = line.split("\t")
        if len(fields) != 4:
            raise ValidationError(f"plan line {lineno}: expected four tab-separated fields")
        test, expected, reason, issue = fields
        if test in entries:
            raise ValidationError(f"plan line {lineno}: duplicate test {test}")
        if expected not in EXPECTED_STATES:
            raise ValidationError(f"plan line {lineno}: invalid expected state {expected!r}")
        entries[test] = Expectation(test, "", expected, reason, issue)
    if not entries:
        raise ValidationError(f"plan is empty: {path}")
    return entries


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def load_results(root: Path) -> List[Mapping[str, object]]:
    results: List[Mapping[str, object]] = []
    for path in sorted(root.glob("**/result.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or "test" not in value or "final" not in value:
            raise ValidationError(f"invalid per-test result: {path}")
        results.append(value)
    return results


def aggregate_results(results: Sequence[Mapping[str, object]]) -> Mapping[str, object]:
    counts = {state: 0 for state in FINAL_STATES}
    fatal = 0
    for result in results:
        final = str(result["final"])
        if final not in counts:
            raise ValidationError(f"unknown final result state: {final}")
        counts[final] += 1
        if bool(result.get("fatal", False)):
            fatal += 1
    # An empty result set means the runner recorded nothing; treat that as
    # fatal so a lane that produced no results can never report success.
    if not results:
        fatal = 1
    return {
        "schema_version": 1,
        "total": len(results),
        "fatal": fatal,
        "counts": counts,
        "results": list(results),
    }


def read_junit_log(path: Path) -> str:
    text = path.read_bytes().decode("utf-8", errors="replace")
    return "".join(
        char
        if char in "\t\n\r"
        or 0x20 <= ord(char) <= 0xD7FF
        or 0xE000 <= ord(char) <= 0xFFFD
        or 0x10000 <= ord(char) <= 0x10FFFF
        else "�"
        for char in text
    )


def write_junit(path: Path, results: Sequence[Mapping[str, object]]) -> None:
    failures = sum(bool(result.get("fatal", False)) for result in results)
    # A fatal SKIP or XFAIL (an expectation mismatch) is a failure; counting
    # it as skipped too would make the testsuite totals inconsistent.
    skipped = sum(
        str(result["final"]) in ("SKIP", "XFAIL") and not bool(result.get("fatal", False))
        for result in results
    )
    suite = ET.Element(
        "testsuite",
        name="gvisor-conformance",
        tests=str(len(results)),
        failures=str(failures),
        skipped=str(skipped),
    )
    for result in results:
        testcase = ET.SubElement(
            suite,
            "testcase",
            classname=str(result["backend"]),
            name=str(result["test"]),
            time=f"{float(result.get('duration_ms', 0)) / 1000.0:.6f}",
        )
        final = str(result["final"])
        detail = str(result.get("detail", ""))
        if bool(result.get("fatal", False)):
            failure = ET.SubElement(testcase, "failure", type=final, message=detail or final)
            failure.text = f"complete log: {result.get('log', '')}"
            # Whole-binary runs point every per-test record at the shared
            # suite-level logs; embed them only for failures so the JUnit
            # file does not repeat the full suite output per passing test.
            stdout_path = Path(str(result.get("stdout", "")))
            stderr_path = Path(str(result.get("stderr", "")))
            if stdout_path.is_file():
                ET.SubElement(testcase, "system-out").text = read_junit_log(stdout_path)
            if stderr_path.is_file():
                ET.SubElement(testcase, "system-err").text = read_junit_log(stderr_path)
        elif final in ("SKIP", "XFAIL"):
            ET.SubElement(testcase, "skipped", message=detail or final)
    tree = ET.ElementTree(suite)
    if hasattr(ET, "indent"):
        ET.indent(tree, space="  ")
    path.parent.mkdir(parents=True, exist_ok=True)
    tree.write(path, encoding="utf-8", xml_declaration=True)


def sanitize_tsv(value: str) -> str:
    return value.replace("\t", " ").replace("\r", " ").replace("\n", " ")


def write_classification(path: Path, result: Classification) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\t".join(
            (result.actual, result.final, "1" if result.fatal else "0", sanitize_tsv(result.detail))
        )
        + "\n",
        encoding="utf-8",
    )


def result_record(
    test: str,
    backend: str,
    expectation: Expectation,
    result: Classification,
    exit_code: int,
    duration_ms: int,
    stdout: Path,
    stderr: Path,
    log: Path,
) -> Mapping[str, object]:
    return {
        "test": test,
        "backend": backend,
        "expected": expectation.expected,
        "expectation_reason": expectation.reason,
        "issue": expectation.issue,
        "actual": result.actual,
        "final": result.final,
        "fatal": result.fatal,
        "detail": result.detail,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "stdout": str(stdout.resolve()),
        "stderr": str(stderr.resolve()),
        "log": str(log.resolve()),
    }


def command_gtest_list(args: argparse.Namespace) -> int:
    tests = parse_gtest_list(read_utf8(args.input))
    args.output.write_text("".join(f"{test}\n" for test in tests), encoding="utf-8")
    return 0


def command_plan(args: argparse.Namespace) -> int:
    tests = read_test_names(args.input)
    active = [test for test in tests if not is_disabled(test)]
    if not active:
        raise ValidationError("listing contains only disabled tests")
    # Case artifacts are stored under test_slug(test), which is lossy; two
    # distinct tests sharing a slug would silently overwrite each other's
    # records, so reject the listing outright.
    slugs: Dict[str, str] = {}
    for test in active:
        slug = test_slug(test)
        if slug in slugs:
            raise ValidationError(f"slug collision between {slugs[slug]} and {test}")
        slugs[slug] = test
    if args.bootstrap:
        rows = [Expectation(test, args.backend, "PASS", "-", "-") for test in active]
    else:
        if args.manifest is None:
            raise ValidationError("--manifest is required unless --bootstrap is given")
        entries = load_expectations(args.manifest, active)
        rows = [
            entries[(test, args.backend)]
            for test in active
            if entries[(test, args.backend)].expected != "EXCLUDE"
        ]
        if not rows:
            raise ValidationError("every discovered test is excluded")
    args.output.write_text(
        "".join(
            "\t".join((row.test, row.expected, row.reason, row.issue)) + "\n" for row in rows
        ),
        encoding="utf-8",
    )
    return 0


def command_record(args: argparse.Namespace) -> int:
    result = classify_gtest_case(args.xml, args.test, args.exit_code, args.execution)
    result = apply_expectation(result, args.expected)
    if args.execution_detail and result.final in ("BROKEN", "TIMEOUT", "SIGNAL"):
        result = Classification(result.actual, result.final, result.fatal, args.execution_detail)
    expectation = Expectation(args.test, args.backend, args.expected, args.reason, args.issue)
    record = result_record(
        args.test,
        args.backend,
        expectation,
        result,
        args.exit_code,
        args.duration_ms,
        args.stdout,
        args.stderr,
        args.log,
    )
    write_json(args.output, record)
    write_classification(args.classification, result)
    return 0


def command_record_suite(args: argparse.Namespace) -> int:
    tests = read_test_names(args.tests)
    plan = load_plan(args.plan)
    # Listed tests absent from the validated plan are manifest EXCLUDE rows;
    # the runner keeps them out of the suite invocation with a negative
    # gtest filter, so they must not be recorded here either.
    planned = [test for test in tests if not is_disabled(test) and test in plan]
    if not planned:
        raise ValidationError("no planned tests for this binary")

    abnormal = classify_abnormal(args.execution, args.exit_code)
    suite_cases: Dict[str, SuiteCase] = {}
    suite_error: Optional[Classification] = None
    if abnormal is not None:
        suite_error = abnormal
    elif not args.xml.is_file():
        suite_error = Classification("BROKEN", "BROKEN", True, "missing suite XML")
    else:
        try:
            parsed = parse_gtest_suite_xml(args.xml)
        except (OSError, ET.ParseError, ValidationError) as exc:
            suite_error = Classification("BROKEN", "BROKEN", True, str(exc))
        else:
            for case in parsed:
                if case.test not in plan:
                    raise ValidationError(f"suite XML names unplanned test {case.test}")
            suite_cases = {case.test: case for case in parsed}
            has_fail = any(case.state == "FAIL" for case in parsed)
            required_exit = 1 if has_fail else 0
            if args.exit_code != required_exit:
                suite_error = Classification(
                    "BROKEN",
                    "BROKEN",
                    True,
                    f"suite exit {args.exit_code} is inconsistent with its XML",
                )
                suite_cases = {}
    if suite_error is not None and args.execution_detail:
        suite_error = Classification(
            suite_error.actual, suite_error.final, suite_error.fatal, args.execution_detail
        )

    rerun: List[str] = []
    summary_lines: List[str] = []
    for test in planned:
        expectation = plan[test]
        duration_ms = 0
        if suite_error is not None:
            result = suite_error
            rerun.append(test)
        elif test in suite_cases:
            case = suite_cases[test]
            duration_ms = case.duration_ms
            result = apply_expectation(
                Classification(case.state, case.state, case.state == "FAIL", case.detail),
                expectation.expected,
            )
        else:
            result = Classification("BROKEN", "BROKEN", True, "missing from suite XML")
            rerun.append(test)
        case_dir = args.output_dir / test_slug(test)
        record = result_record(
            test,
            args.backend,
            Expectation(test, args.backend, expectation.expected, expectation.reason,
                        expectation.issue),
            result,
            args.exit_code,
            duration_ms,
            args.stdout,
            args.stderr,
            args.log,
        )
        write_json(case_dir / "result.json", record)
        write_classification(case_dir / "classification.tsv", result)
        summary_lines.append(
            "\t".join((result.final, test, test_slug(test), sanitize_tsv(result.detail)))
        )

    # Carry the expectation columns so the runner's isolated reruns do not
    # have to rediscover them from the plan.
    args.rerun_list.write_text(
        "".join(
            "\t".join(
                (test, test_slug(test), plan[test].expected, plan[test].reason,
                 plan[test].issue)
            ) + "\n"
            for test in rerun
        ),
        encoding="utf-8",
    )
    args.summary.write_text("".join(f"{line}\n" for line in summary_lines), encoding="utf-8")
    return 0


def command_expectations_init(args: argparse.Namespace) -> int:
    results = load_results(args.root)
    if not results:
        raise ValidationError(f"no per-test results under {args.root}")
    reference: Dict[str, Mapping[str, object]] = {}
    for result in results:
        if str(result["backend"]) == args.reference_backend:
            reference[str(result["test"])] = result
    if not reference:
        raise ValidationError(f"no results for reference backend {args.reference_backend}")

    lines = [
        "# Draft manifest generated by expectations-init from "
        f"{args.reference_backend} results.",
        "# Review every REVIEW marker before committing.",
        "test\tbackend\texpected\treason\tissue",
    ]
    for test in sorted(reference):
        actual = str(reference[test].get("actual", ""))
        detail = sanitize_tsv(str(reference[test].get("detail", "")))
        if actual == "PASS":
            expected, reason, issue = "PASS", "-", "-"
        elif actual == "SKIP":
            expected = "SKIP"
            reason = detail or "REVIEW: add the environmental skip reason"
            issue = "-"
        elif actual == "FAIL":
            expected = "XFAIL"
            reason = f"REVIEW: {detail or 'assertion failure on the reference kernel'}"
            issue = "REVIEW"
        else:
            expected = "EXCLUDE"
            reason = f"REVIEW: reference result was {actual}: {detail}" if detail \
                else f"REVIEW: reference result was {actual}"
            issue = "-"
        for backend in BACKENDS:
            lines.append("\t".join((test, backend, expected, reason, issue)))
    args.output.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    return 0


def command_aggregate(args: argparse.Namespace) -> int:
    results = load_results(args.root)
    aggregate = aggregate_results(results)
    write_json(args.json, aggregate)
    write_junit(args.junit, results)
    counts = aggregate["counts"]
    print(
        "SUMMARY\t{total}\t{fatal}\t{PASS}\t{FAIL}\t{SKIP}\t{BROKEN}\t{TIMEOUT}\t{SIGNAL}\t{XFAIL}\t{XPASS}".format(
            total=aggregate["total"], fatal=aggregate["fatal"], **counts
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    executions = ("normal", "timeout", "signal", "transport")

    gtest_list = commands.add_parser("gtest-list")
    gtest_list.add_argument("--input", type=Path, required=True)
    gtest_list.add_argument("--output", type=Path, required=True)
    gtest_list.set_defaults(func=command_gtest_list)

    plan = commands.add_parser("plan")
    plan.add_argument("--input", type=Path, required=True)
    plan.add_argument("--manifest", type=Path)
    plan.add_argument("--backend", choices=BACKENDS, required=True)
    plan.add_argument("--bootstrap", action="store_true")
    plan.add_argument("--output", type=Path, required=True)
    plan.set_defaults(func=command_plan)

    record = commands.add_parser("record")
    record.add_argument("--xml", type=Path, required=True)
    record.add_argument("--test", required=True)
    record.add_argument("--backend", choices=BACKENDS, required=True)
    record.add_argument("--expected", choices=EXPECTED_STATES, required=True)
    record.add_argument("--reason", required=True)
    record.add_argument("--issue", required=True)
    record.add_argument("--exit-code", type=int, required=True)
    record.add_argument("--execution", choices=executions, default="normal")
    record.add_argument("--execution-detail", default="")
    record.add_argument("--duration-ms", type=int, required=True)
    record.add_argument("--stdout", type=Path, required=True)
    record.add_argument("--stderr", type=Path, required=True)
    record.add_argument("--log", type=Path, required=True)
    record.add_argument("--output", type=Path, required=True)
    record.add_argument("--classification", type=Path, required=True)
    record.set_defaults(func=command_record)

    record_suite = commands.add_parser("record-suite")
    record_suite.add_argument("--xml", type=Path, required=True)
    record_suite.add_argument("--tests", type=Path, required=True)
    record_suite.add_argument("--plan", type=Path, required=True)
    record_suite.add_argument("--backend", choices=BACKENDS, required=True)
    record_suite.add_argument("--exit-code", type=int, required=True)
    record_suite.add_argument("--execution", choices=executions, default="normal")
    record_suite.add_argument("--execution-detail", default="")
    record_suite.add_argument("--stdout", type=Path, required=True)
    record_suite.add_argument("--stderr", type=Path, required=True)
    record_suite.add_argument("--log", type=Path, required=True)
    record_suite.add_argument("--output-dir", type=Path, required=True)
    record_suite.add_argument("--rerun-list", type=Path, required=True)
    record_suite.add_argument("--summary", type=Path, required=True)
    record_suite.set_defaults(func=command_record_suite)

    expectations_init = commands.add_parser("expectations-init")
    expectations_init.add_argument("--root", type=Path, required=True)
    expectations_init.add_argument(
        "--reference-backend", choices=BACKENDS, default="qemu-aarch64"
    )
    expectations_init.add_argument("--output", type=Path, required=True)
    expectations_init.set_defaults(func=command_expectations_init)

    aggregate = commands.add_parser("aggregate")
    aggregate.add_argument("--root", type=Path, required=True)
    aggregate.add_argument("--json", type=Path, required=True)
    aggregate.add_argument("--junit", type=Path, required=True)
    aggregate.set_defaults(func=command_aggregate)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (KeyError, OSError, ET.ParseError, ValidationError, json.JSONDecodeError) as exc:
        print(f"gvisor-conformance: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
