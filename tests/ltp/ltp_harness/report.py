"""Gate and JUnit reporting derived from kirk JSON reports."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Any, Dict, Optional

from ltp_harness.baseline import GateResult, classify_result


def write_gate_json(
    path: str,
    backend: str,
    tier: str,
    gate: Optional[GateResult],
    observed: Dict[str, Any],
) -> None:
    """Machine-readable gate outcome next to the kirk report."""
    data = {
        "backend": backend,
        "tier": tier,
        "gate": gate.to_dict() if gate else None,
        "observed": observed,
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_junit(
    path: str,
    backend: str,
    report: Dict[str, Any],
    gate: Optional[GateResult],
) -> None:
    """JUnit XML for CI consumption.

    A test case fails when its kirk result classifies as FAIL or BROKEN;
    gate-level regressions and pending improvements are appended as
    synthetic cases so a red gate is visible even when every LTP result
    matches a red baseline entry.
    """
    results = report.get("results", [])
    suite = ET.Element(
        "testsuite",
        name=f"ltp-{backend}",
        tests=str(len(results)),
    )

    failures = 0
    for result in results:
        test = result["test"]
        case = ET.SubElement(
            suite,
            "testcase",
            classname=f"ltp.{backend}",
            name=result["test_fqn"],
            time=f"{test.get('duration') or 0.0:.3f}",
        )
        status = classify_result(result)
        if status in ("FAIL", "BROKEN"):
            failures += 1
            failure = ET.SubElement(case, "failure", message=status)
            failure.text = test.get("log", "")
        elif status == "SKIP":
            ET.SubElement(case, "skipped")

    if gate:
        for kind, messages in (
            ("gate-regression", gate.regressions),
            ("gate-improvement-pending-record", gate.improvements),
        ):
            for message in messages:
                failures += 1
                case = ET.SubElement(
                    suite, "testcase", classname=f"ltp.{backend}", name=kind
                )
                ET.SubElement(case, "failure", message=message)

    suite.set("failures", str(failures))

    ET.indent(suite)
    tree = ET.ElementTree(suite)
    tree.write(path, encoding="unicode", xml_declaration=True)
