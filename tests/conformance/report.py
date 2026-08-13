"""Run reports: results.json, JUnit, and the gate.

results.json alone re-derives the gate (report --results DIR recomputes
it), so it is written atomically and no machine contract ever parses
human stdout. An empty result set is red: a lane that recorded nothing
must never read as a lane that passed. Red verdicts additionally emit
GitHub ::error annotations when running under Actions, so the ratchet
message reaches the PR author inline.
"""

from __future__ import annotations

import json
import os
import pathlib
from xml.sax.saxutils import escape

from conformance.model import CaseResult, Verdict

SCHEMA_VERSION = 1


class ReportError(Exception):
    """results.json is unreadable or contradicts its case records."""


def gate(cases) -> str:
    if not cases:
        return "red"
    return "red" if any(c.verdict.is_red for c in cases) else "green"


def counts(cases) -> dict:
    by_status = {}
    by_verdict = {}
    for case in cases:
        by_status[case.status.value] = by_status.get(case.status.value, 0) + 1
        by_verdict[case.verdict.value] = \
            by_verdict.get(case.verdict.value, 0) + 1
    return {"status": by_status, "verdict": by_verdict}


def write_results(results_dir, run_meta: dict, cases) -> pathlib.Path:
    results_dir = pathlib.Path(results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    doc = {
        "schema_version": SCHEMA_VERSION,
        "run": run_meta,
        "counts": counts(cases),
        "gate": gate(cases),
        "cases": [case.to_dict() for case in cases],
    }
    path = results_dir / "results.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n",
                   encoding="utf-8")
    tmp.replace(path)
    _write_junit(results_dir / "junit.xml", run_meta, cases)
    return path


def _write_junit(path, run_meta, cases) -> None:
    reds = sum(1 for c in cases if c.verdict.is_red)
    skips = sum(1 for c in cases if not c.verdict.is_red
                and c.verdict is not Verdict.AS_EXPECTED)
    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append(
        '<testsuite name="%s" tests="%d" failures="%d" skipped="%d">'
        % (escape(str(run_meta.get("lane", "conformance"))), len(cases),
           reds, skips))
    for case in cases:
        lines.append('  <testcase name="%s" classname="%s">'
                     % (escape(case.id), escape(case.backend)))
        if case.verdict.is_red:
            lines.append('    <failure message="%s">%s</failure>'
                         % (escape(case.verdict.value),
                            escape(case.detail or case.status.value)))
        elif case.verdict is not Verdict.AS_EXPECTED:
            lines.append('    <skipped message="%s"/>'
                         % escape(case.verdict.value))
        lines.append("  </testcase>")
    lines.append("</testsuite>")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_gate(results_dir) -> str:
    path = pathlib.Path(results_dir) / "results.json"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        if doc.get("schema_version") != SCHEMA_VERSION:
            raise ReportError("unsupported schema_version in %s" % path)
        if not isinstance(doc.get("run"), dict) or \
                not isinstance(doc.get("cases"), list):
            raise ReportError("invalid report shape in %s" % path)
        cases = [CaseResult.from_dict(case) for case in doc["cases"]]
    except ReportError:
        raise
    except (OSError, json.JSONDecodeError, KeyError, TypeError,
            ValueError) as exc:
        raise ReportError("cannot load %s: %s" % (path, exc)) from exc
    derived_counts = counts(cases)
    derived_gate = gate(cases)
    if doc.get("counts") != derived_counts:
        raise ReportError("stored counts contradict cases in %s" % path)
    if doc.get("gate") != derived_gate:
        raise ReportError("stored gate contradicts cases in %s" % path)
    return derived_gate


def print_summary(run_meta, cases, messages) -> None:
    print("lane %s: %s (%d cases)"
          % (run_meta.get("lane"), gate(cases), len(cases)))
    for key, value in sorted(counts(cases)["verdict"].items()):
        print("  %-20s %d" % (key, value))
    annotate = os.environ.get("GITHUB_ACTIONS") == "true"
    for message in messages:
        print(message)
        if annotate:
            first = message.splitlines()[0]
            print("::error title=conformance::%s" % first)
