"""Recorded-baseline extraction, comparison, and persistence.

A baseline is a committed snapshot of what one backend does today, at
test granularity and, for new-API tests, at subtest granularity. The
gate never asks "did everything pass"; it asks "did anything move away
from the recorded snapshot". Improvements also fail the gate until the
baseline is re-recorded, so the snapshot stays honest.

Subtest identity: LTP prints "file.c:line: TPASS: message" and never
prints the case index, so file.c:line is the only stable key while the
LTP pin is fixed. Table-driven tests report every table entry from one
call site, so each key stores counts per result type rather than a
single value ("preadv02.c:77": {"TPASS": 5}).
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

BASELINE_SCHEMA_VERSION = 1

# Test-level classification, ordered best to worst.
STATUSES = ("PASS", "SKIP", "WARN", "FAIL", "BROKEN")
_SEVERITY = {status: index for index, status in enumerate(STATUSES)}

# Subtest result types, ordered best to worst.
RESULT_TYPES = ("TPASS", "TCONF", "TWARN", "TFAIL", "TBROK")
_TYPE_SEVERITY = {rtype: index for index, rtype in enumerate(RESULT_TYPES)}

_SUBTEST_RE = re.compile(
    r"^([A-Za-z0-9_.+-]+\.c):(\d+): (TPASS|TFAIL|TBROK|TCONF|TWARN): ",
    re.MULTILINE,
)


class BaselineError(Exception):
    """Raised for malformed or mismatched baseline input; maps to exit 2."""


class GateResult:
    """Outcome of comparing one run against one baseline."""

    def __init__(self) -> None:
        self.regressions: List[str] = []
        self.improvements: List[str] = []
        self.infos: List[str] = []

    @property
    def passed(self) -> bool:
        return not self.regressions and not self.improvements

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "regressions": self.regressions,
            "improvements": self.improvements,
            "infos": self.infos,
        }


def extract_subtests(log: str) -> Dict[str, Dict[str, int]]:
    """Count per-result-type occurrences of each file.c:line key."""
    counts: Dict[str, Dict[str, int]] = {}
    for match in _SUBTEST_RE.finditer(log):
        key = f"{match.group(1)}:{match.group(2)}"
        rtype = match.group(3)
        per_key = counts.setdefault(key, {})
        per_key[rtype] = per_key.get(rtype, 0) + 1

    return counts


def classify_result(result: Dict[str, Any]) -> str:
    """Map one kirk JSON result entry to a test-level status.

    Kirk's per-test counters come from the Summary block when present,
    from TPASS/TFAIL line counts otherwise, and from the exit code alone
    for legacy tests; its "status" field reflects the exit-code map. A
    run that produced no results at all is BROKEN, never PASS.
    """
    try:
        test = result["test"]
        broken = test["broken"]
        failed = test["failed"]
        warnings = test["warnings"]
        skipped = test["skipped"]
        passed = test["passed"]
    except (KeyError, TypeError) as err:
        raise BaselineError(
            f"kirk result entry missing its counter block: {err}"
        ) from err

    if result.get("status") == "brok" or broken:
        return "BROKEN"
    if failed:
        return "FAIL"
    if warnings:
        return "WARN"
    if passed:
        return "PASS"
    if skipped:
        return "SKIP"

    return "BROKEN"


def observed_from_report(
    report: Dict[str, Any], result_formats: Dict[str, str]
) -> Dict[str, Any]:
    """Digest a kirk JSON report into per-test observations.

    result_formats maps test id to the manifest result_format; legacy
    tests carry subtests=None because their output has no stable
    per-subtest key.
    """
    results = report.get("results")
    if not isinstance(results, list):
        raise BaselineError("kirk report has no 'results' list")

    observed: Dict[str, Any] = {}
    for result in results:
        test_id = result.get("test_fqn")
        if not isinstance(test_id, str) or not test_id:
            raise BaselineError("kirk report entry without test_fqn")
        if test_id in observed:
            raise BaselineError(f"kirk report repeats test '{test_id}'")

        fmt = result_formats.get(test_id)
        if fmt is None:
            raise BaselineError(f"kirk report contains unknown test '{test_id}'")

        entry: Dict[str, Any] = {"status": classify_result(result)}
        if fmt == "new-api":
            entry["subtests"] = extract_subtests(result["test"].get("log", ""))
        else:
            entry["subtests"] = None

        observed[test_id] = entry

    return observed


def _compare_subtests(
    test_id: str,
    base: Dict[str, Dict[str, int]],
    seen: Dict[str, Dict[str, int]],
    gate: GateResult,
) -> None:
    """Per-key count comparison for one new-API test."""
    for key in sorted(set(base) | set(seen)):
        base_counts = base.get(key)
        seen_counts = seen.get(key)

        if base_counts is None:
            assert seen_counts is not None
            bad = {
                rtype: count
                for rtype, count in seen_counts.items()
                if rtype in ("TFAIL", "TBROK", "TWARN")
            }
            if bad:
                gate.regressions.append(
                    f"{test_id}: new failing subtest key {key}: {_fmt(bad)}"
                )
            else:
                gate.infos.append(
                    f"{test_id}: new passing subtest key {key}: {_fmt(seen_counts)}"
                )
            continue

        if seen_counts is None:
            gate.regressions.append(
                f"{test_id}: subtest key {key} not observed "
                f"(baseline {_fmt(base_counts)})"
            )
            continue

        if base_counts == seen_counts:
            continue

        # Regression: more results of a bad type, fewer TPASS results, or
        # fewer results overall (lost coverage). Improvement: fewer bad
        # results or more TPASS results without any of the above. Anything
        # else (say, an extra TCONF firing) is informational.
        delta = {
            rtype: seen_counts.get(rtype, 0) - base_counts.get(rtype, 0)
            for rtype in RESULT_TYPES
        }
        total_delta = sum(delta.values())
        worse = (
            any(delta[rtype] > 0 for rtype in ("TWARN", "TFAIL", "TBROK"))
            or delta["TPASS"] < 0
            or total_delta < 0
        )
        better = not worse and (
            any(delta[rtype] < 0 for rtype in ("TWARN", "TFAIL", "TBROK"))
            or delta["TPASS"] > 0
        )

        message = (
            f"{test_id}: subtest key {key} moved from "
            f"{_fmt(base_counts)} to {_fmt(seen_counts)}"
        )
        if worse:
            gate.regressions.append(message)
        elif better:
            gate.improvements.append(message)
        else:
            gate.infos.append(message)


def _fmt(counts: Dict[str, int]) -> str:
    if not counts:
        return "none"
    return ",".join(f"{rtype}={counts[rtype]}" for rtype in sorted(counts))


def compare(baseline: Dict[str, Any], observed: Dict[str, Any]) -> GateResult:
    """Apply the gate decision table.

    Both inputs map test id to {"status": ..., "subtests": ...}. Tests
    present on only one side are configuration errors (record or prune
    the baseline), not gate outcomes.
    """
    missing = sorted(set(observed) - set(baseline))
    if missing:
        raise BaselineError(
            f"tests not in baseline (run record-baseline): {', '.join(missing)}"
        )
    stale = sorted(set(baseline) - set(observed))
    if stale:
        raise BaselineError(
            f"baseline entries not in this run (stale baseline or narrowed "
            f"selection): {', '.join(stale)}"
        )

    gate = GateResult()
    for test_id in sorted(observed):
        base_entry = baseline[test_id]
        seen_entry = observed[test_id]
        base_status = base_entry["status"]
        seen_status = seen_entry["status"]

        if base_status not in _SEVERITY:
            raise BaselineError(f"baseline {test_id}: bad status '{base_status}'")

        if _SEVERITY[seen_status] > _SEVERITY[base_status]:
            gate.regressions.append(
                f"{test_id}: {base_status} regressed to {seen_status}"
            )
        elif _SEVERITY[seen_status] < _SEVERITY[base_status]:
            gate.improvements.append(
                f"{test_id}: {base_status} improved to {seen_status}"
            )

        base_subs = base_entry.get("subtests")
        seen_subs = seen_entry.get("subtests")
        if base_subs is not None and seen_subs is not None:
            _compare_subtests(test_id, base_subs, seen_subs, gate)

    return gate


def load(path: str, pin: Dict[str, str]) -> Dict[str, Any]:
    """Load a baseline file and refuse a pin mismatch."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as err:
        raise BaselineError(f"cannot read {path}: {err}") from err
    except ValueError as err:
        raise BaselineError(f"{path} is not valid JSON: {err}") from err

    if data.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise BaselineError(f"{path}: unsupported schema_version")
    if data.get("pin") != pin:
        raise BaselineError(
            f"{path}: baseline was recorded against a different pin; "
            f"rebuild the fixture and run record-baseline"
        )

    tests = data.get("tests")
    if not isinstance(tests, dict):
        raise BaselineError(f"{path}: 'tests' must be an object")

    return tests


def record(
    path: str,
    backend: str,
    pin: Dict[str, str],
    observed: Dict[str, Any],
    previous: Optional[Dict[str, Any]] = None,
    keep_ids: Optional[set] = None,
) -> Tuple[List[str], List[str], List[str]]:
    """Write a baseline snapshot, carrying reason/issue notes forward.

    Previous entries for tests outside this run's selection survive when
    they are still in the manifest (keep_ids); entries for tests no
    longer in the manifest are pruned. Returns (added, changed, pruned)
    test-id lists for reporting.
    """
    tests: Dict[str, Any] = {}
    added = []
    changed = []
    pruned = []

    for test_id, old in sorted((previous or {}).items()):
        if test_id in observed:
            continue
        if keep_ids is not None and test_id not in keep_ids:
            pruned.append(test_id)
            continue
        tests[test_id] = old

    for test_id in sorted(observed):
        entry: Dict[str, Any] = {
            "status": observed[test_id]["status"],
            "subtests": observed[test_id]["subtests"],
        }
        old = (previous or {}).get(test_id)
        if old is None:
            added.append(test_id)
        else:
            for note in ("reason", "issue"):
                if note in old:
                    entry[note] = old[note]
            if old.get("status") != entry["status"] or old.get("subtests") != entry[
                "subtests"
            ]:
                changed.append(test_id)

        tests[test_id] = entry

    data = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "backend": backend,
        "pin": pin,
        "tests": tests,
    }

    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp_path, path)

    return added, changed, pruned
