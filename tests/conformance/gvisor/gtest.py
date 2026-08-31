# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional

from conformance.model import Attempt, Invocation, Status


class GtestError(ValueError):
    pass


def parse_list(text: str) -> List[str]:
    """Parse listings while preserving typed and parameterized names."""
    names: List[str] = []
    suite: Optional[str] = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.startswith("  "):
            if suite is None:
                raise GtestError("case %r before any suite" % line.strip())
            names.append(suite + line.strip())
        elif line.endswith("."):
            suite = line.strip()
        else:
            raise GtestError("unexpected listing line %r" % raw)
    if not names:
        raise GtestError("empty listing")
    if len(set(names)) != len(names):
        raise GtestError("duplicate case names in the listing")
    return names


def list_argv(binary: str) -> List[str]:
    return [binary, "--gtest_list_tests"]


def run_argv(binary: str, include: List[str], exclude: List[str]) -> List[str]:
    """Use the shorter include or exclude filter."""
    argv = [binary, "--gtest_color=no", "--gtest_output=xml:result.xml"]
    if exclude and len(exclude) < len(include):
        argv.append("--gtest_filter=-" + ":".join(exclude))
    elif exclude:
        argv.append("--gtest_filter=" + ":".join(include))
    return argv


def parse_xml(path: Path) -> Dict[str, Status]:
    """Return statuses for cases the report ran."""
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as e:
        raise GtestError("unreadable gtest report: %s" % e) from None
    out: Dict[str, Status] = {}
    for suite in root.iter("testsuite"):
        for case in suite.findall("testcase"):
            if case.get("status") == "notrun":
                continue
            name = "%s.%s" % (suite.get("name"), case.get("name"))
            if case.find("failure") is not None:
                out[name] = Status.FAIL
            elif case.get("result") == "skipped" or case.find("skipped") is not None:
                out[name] = Status.SKIP
            else:
                out[name] = Status.PASS
    return out


def status_of(inv: Invocation) -> Optional[Status]:
    """Return an abnormal execution status, or None to read the report."""
    if inv.execution == "timeout":
        return Status.TIMEOUT
    if (inv.execution == "signal"
            or inv.execution == "normal" and 128 < inv.exit_code <= 192):
        return Status.CRASH
    if inv.execution == "transport":
        return Status.ERROR
    return None


def resolve(inv: Invocation, report: Path, planned: List[str]) -> Dict[str, Attempt]:
    """Return resolved attempts and omit cases that require isolation."""
    abnormal = status_of(inv)
    if abnormal is not None:
        signum = inv.signal or (inv.exit_code - 128 if inv.exit_code else 0)
        detail = "%s (%s)" % (inv.execution, "signal %s" % signum if signum else "")
        if len(planned) == 1:
            return {planned[0]: Attempt(abnormal, inv, detail)}
        return {}
    try:
        statuses = parse_xml(report)
    except GtestError as e:
        if len(planned) == 1:
            return {planned[0]: Attempt(Status.INCONSISTENT, inv, str(e))}
        return {}
    failed = any(s is Status.FAIL for n, s in statuses.items() if n in planned)
    consistent = (inv.exit_code == 1) == failed
    out: Dict[str, Attempt] = {}
    for name in planned:
        if name in statuses:
            status = statuses[name] if consistent else Status.INCONSISTENT
            detail = "" if consistent else "report says %s but the binary exited %s" % (
                statuses[name].value, inv.exit_code)
            out[name] = Attempt(status, inv, detail)
        elif len(planned) == 1:
            out[name] = Attempt(Status.INCONSISTENT, inv, "report omits the case")
    return out
