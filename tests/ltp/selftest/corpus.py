"""Fake kirk JSON reports for the harness selftests."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def kirk_result(
    test_id: str,
    log: str = "",
    passed: int = 0,
    failed: int = 0,
    broken: int = 0,
    skipped: int = 0,
    warnings: int = 0,
    status: str = "pass",
    retval: str = "0",
    duration: float = 0.5,
) -> Dict[str, Any]:
    return {
        "test_fqn": test_id,
        "status": status,
        "test": {
            "command": test_id,
            "arguments": [],
            "log": log,
            "retval": [retval],
            "duration": duration,
            "failed": failed,
            "passed": passed,
            "broken": broken,
            "skipped": skipped,
            "warnings": warnings,
            "result": status,
        },
    }


def kirk_report(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "results": results,
        "stats": {
            "runtime": sum(result["test"]["duration"] for result in results),
            "passed": sum(result["test"]["passed"] for result in results),
            "failed": sum(result["test"]["failed"] for result in results),
            "broken": sum(result["test"]["broken"] for result in results),
            "skipped": sum(result["test"]["skipped"] for result in results),
            "warnings": sum(result["test"]["warnings"] for result in results),
        },
        "environment": {"arch": "aarch64"},
    }


def new_api_log(
    entries: List[str], summary: Optional[Dict[str, int]] = None
) -> str:
    """Build a plausible new-API stdout with an optional Summary block."""
    lines = ["tst_test.c:1741: TINFO: LTP version: 20260529"]
    lines.extend(entries)
    if summary is not None:
        lines.append("")
        lines.append("Summary:")
        for field in ("passed", "failed", "broken", "skipped", "warnings"):
            lines.append(f"{field}   {summary.get(field, 0)}")
    return "\n".join(lines) + "\n"


def passing_report_fast(test_ids: List[str]) -> Dict[str, Any]:
    """An all-pass report: two TPASS firings from one call site each."""
    results = []
    for test_id in test_ids:
        if test_id == "recv01":
            results.append(
                kirk_result(test_id, log="recv01     1  TPASS  :  ok\n", passed=1)
            )
            continue
        log = new_api_log(
            [
                f"{test_id}.c:40: TPASS: call succeeded",
                f"{test_id}.c:40: TPASS: call succeeded",
                f"{test_id}.c:55: TPASS: errno matched",
            ],
            summary={"passed": 3},
        )
        results.append(kirk_result(test_id, log=log, passed=3))
    return kirk_report(results)
