# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from conformance.model import Attempt, Invocation, Status
from conformance.providers.base import ProviderError

STATUS_PREFIX = "__conformance_status__:"
BUCKETS = (120, 300, 900)
# Preserve ordering: supervisor cleanup < kirk timeout < channel cap.
EXEC_SLACK_S = 25
CAP_SLACK_S = 30

_EXIT_STATUS = {0: Status.PASS, 2: Status.BROK, -1: Status.BROK, 4: Status.WARN, 32: Status.CONF}
_KIRK_STATUS = {"pass": Status.PASS, "fail": Status.FAIL, "brok": Status.BROK,
                "conf": Status.CONF, "warn": Status.WARN}
_SUMMARY_RE = re.compile(r"^Summary:\s*\npassed\s+(\d+)\s*\nfailed\s+(\d+)\s*\nbroken\s+(\d+)\s*\n"
                         r"skipped\s+(\d+)\s*\nwarnings\s+(\d+)", re.MULTILINE)


class KirkError(ProviderError):
    pass


def bucket_of(timeout_s: int) -> int:
    for b in BUCKETS:
        if timeout_s <= b:
            return b
    raise KirkError("timeout %ds exceeds the largest bucket (%ds)" % (timeout_s, BUCKETS[-1]))


def runtest_text(entries: List[Tuple[str, List[str]]]) -> str:
    return "".join("%s %s\n" % (tag, " ".join(argv or [tag])) for tag, argv in entries)


def kirk_argv(shim: Path, kirk_dir: Path, channel: str, options: Dict[str, Any], suite: str,
              exec_timeout_s: int, suite_timeout_s: int, report: Path, tmp_dir: Path) -> List[str]:
    joined = ":".join("%s=%s" % (k, v) for k, v in options.items())
    # --com configures the channel; --sut binds the test system to it.
    return [sys.executable, str(shim), str(kirk_dir), "--no-colors",
            "--sut", "default:com=%s" % channel, "--com", "%s:%s" % (channel, joined),
            "--tmp-dir", str(tmp_dir), "--run-suite", suite,
            "--exec-timeout", str(exec_timeout_s), "--suite-timeout", str(suite_timeout_s),
            "--workers", "1", "--json-report", str(report)]


def parse_status_line(log: str) -> Optional[Dict[str, Any]]:
    for line in reversed(log.splitlines()):
        if line.startswith(STATUS_PREFIX):
            try:
                data = json.loads(line[len(STATUS_PREFIX):])
            except ValueError:
                return {"error": "status line is malformed"}
            return data if isinstance(data, dict) else {"error": "status line is not an object"}
    return None


def parse_summary(log: str) -> Optional[Dict[str, int]]:
    m = _SUMMARY_RE.search(log)
    if not m:
        return None
    return dict(zip(("passed", "failed", "broken", "skipped", "warnings"), map(int, m.groups())))


def map_case(kirk_status: str, retval: Any, log: str) -> Tuple[Status, str, str]:
    """Map one kirk row to status, execution class, and detail."""
    data = parse_status_line(log or "")
    if data is not None:
        if data.get("timed_out"):
            return Status.TIMEOUT, "timeout", "deadline expired"
        sig = data.get("host_signal") or (data.get("signal") if data.get("signaled") else 0)
        if sig:
            return Status.CRASH, "signal", "died on signal %s" % sig
        if data.get("execution") == "transport":
            return Status.ERROR, "transport", "guest transport failed"
        problems = [str(data["error"])] if data.get("error") else []
        if data.get("setup_errno"):
            problems.append("guest setup failed (errno %s)" % data["setup_errno"])
        if data.get("exec_errno"):
            problems.append("guest exec failed (errno %s)" % data["exec_errno"])
        if data.get("cleanup_ok") is False:
            problems.append("guest cleanup was incomplete")
        if problems:
            return Status.ERROR, "normal", "; ".join(problems)
    status = _KIRK_STATUS.get(kirk_status)
    if status is None:
        return Status.ERROR, "normal", "kirk reported status %r" % (kirk_status,)
    try:
        exit_code = int(retval[0]) if retval else -1
    except (ValueError, TypeError):
        exit_code = -1
    derived = _EXIT_STATUS.get(exit_code, Status.FAIL)
    if derived is not status:
        return Status.INCONSISTENT, "normal", "kirk status %s contradicts exit %d (%s)" % (
            kirk_status, exit_code, derived.value)
    summary = parse_summary(log or "")
    if summary is not None:
        red = summary["failed"] + summary["broken"]
        if status is Status.PASS and red:
            return Status.INCONSISTENT, "normal", "exit 0 but the Summary block counts %d failed/broken" % red
        if status is Status.FAIL and not red:
            return Status.INCONSISTENT, "normal", "failing status but the Summary block counts no failure"
    detail = ""
    if status in (Status.FAIL, Status.BROK, Status.WARN):
        detail = next((l.strip() for l in (log or "").splitlines() if re.search(r"T(FAIL|BROK|WARN)", l)), "")
    return status, "normal", detail


def map_report(path: Path, log_dir: Path) -> Dict[str, Attempt]:
    """Map a kirk report and retain each tag's log."""
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise KirkError("kirk report %s is unreadable: %s" % (path, e)) from None
    out: Dict[str, Attempt] = {}
    log_dir.mkdir(parents=True, exist_ok=True)
    for row in doc.get("results", []):
        tag = row["test_fqn"]
        test = row.get("test", {})
        log = test.get("log", "") or ""
        log_path = log_dir / (tag + ".log")
        log_path.write_text(log)
        status, execution, detail = map_case(row.get("status", ""), test.get("retval"), log)
        fields: Dict[str, Any] = {}
        if execution == "signal":
            data = parse_status_line(log) or {}
            fields["signal"] = int(data.get("host_signal") or data.get("signal"))
        elif execution == "normal":
            try:
                fields["exit_code"] = int(test["retval"][0])
            except (KeyError, IndexError, ValueError, TypeError):
                # Missing exit codes represent lost results, not placeholders.
                execution = "transport"
        inv = Invocation(execution=execution, wall_us=int(float(test.get("duration", 0)) * 1_000_000),
                         stdout=str(log_path), **fields)
        out[tag] = Attempt(status, inv, detail)
    return out
