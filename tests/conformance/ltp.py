"""LTP provider: kirk invocations, timeout tiers, and report mapping.

Kirk takes one --exec-timeout per invocation, so the selection is
partitioned into timeout tiers (each entry rounds up to the smallest
bucket that holds it) and kirk runs once per non-empty tier; the merged
reports feed one gate. Mapping trusts no single source: kirk's status
must agree with the LTP exit bitmask (TPASS=0 TFAIL=1 TBROK=2 TWARN=4
TCONF=32, OR'd; kirk maps 0 PASS, 2 BROK, -1 BROK, 4 WARN, 32 CONF,
everything else FAIL) and with the parsed Summary block, because a
compat layer with imperfect MAP_SHARED corrupts LTP's shared-memory
result accounting and exits 0 over a failing log; disagreement is
INCONSISTENT. The timeout layers nest strictly: the guest supervisor's
cleanup budget stays below the kirk exec-timeout slack, which stays
below the ssh cap slack, so each layer always reports before the one
above it cancels; a selftest asserts the inequality against the
constants in helpers/guest-supervisor.c.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

from conformance.model import Status
from conformance.kirk_plugins._common import HARNESS_STATUS_PREFIX

_PACKAGE_DIR = pathlib.Path(__file__).resolve().parent
HELPERS_DIR = _PACKAGE_DIR / "helpers"
KIRK_SHIM = _PACKAGE_DIR / "kirk_shim.py"

# TERM_GRACE_SEC + KILL_WAIT_SEC + REAP_POLL_SEC + 1s slack in
# guest-supervisor.c; the selftest recomputes this from the C source.
SUPERVISOR_CLEANUP_BUDGET_SEC = 12
QEMU_EXEC_SLACK_SEC = 25
CHANNEL_CAP_SLACK_SEC = 30

TIER_BUCKETS = (120, 300, 900)

_KIRK_EXIT = {0: Status.PASS, 2: Status.BROK, -1: Status.BROK,
              4: Status.WARN, 32: Status.CONF}
_SUMMARY_RE = re.compile(
    r"^Summary:\s*\n"
    r"passed\s+(\d+)\s*\n"
    r"failed\s+(\d+)\s*\n"
    r"broken\s+(\d+)\s*\n"
    r"skipped\s+(\d+)\s*\n"
    r"warnings\s+(\d+)", re.MULTILINE)


class LtpRunnerError(Exception):
    """Selection or kirk-invocation configuration is unusable."""


def partition_timeouts(entries) -> dict:
    tiers = {}
    for entry in entries:
        timeout = entry["timeout_seconds"]
        for bucket in TIER_BUCKETS:
            if timeout <= bucket:
                tiers.setdefault(bucket, []).append(entry)
                break
        else:
            raise LtpRunnerError(
                "%s: timeout %ds exceeds the largest tier bucket (%ds)"
                % (entry["id"], timeout, TIER_BUCKETS[-1]))
    return tiers


def decode_exit(code: int) -> Status:
    return _KIRK_EXIT.get(code, Status.FAIL)


def parse_summary(log: str):
    match = _SUMMARY_RE.search(log)
    if not match:
        return None
    keys = ("passed", "failed", "broken", "skipped", "warnings")
    return dict(zip(keys, map(int, match.groups())))


def parse_harness_status(log: str):
    """Return the last channel-authored machine status record, if any."""
    for line in reversed((log or "").splitlines()):
        if not line.startswith(HARNESS_STATUS_PREFIX):
            continue
        try:
            data = json.loads(line[len(HARNESS_STATUS_PREFIX):])
        except (ValueError, TypeError):
            return {"error": "harness status record is malformed"}
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            return {"error": "harness status record has an invalid schema"}
        return data
    return None


def classify_harness_status(log: str):
    data = parse_harness_status(log)
    if data is None:
        return None
    if data.get("timed_out") or data.get("channel_timed_out"):
        return Status.TIMEOUT, "conformance harness deadline expired"
    signal_number = data.get("host_signal") or (
        data.get("signal") if data.get("signaled") else 0)
    if signal_number:
        return Status.CRASH, "test process died on signal %s" % signal_number
    errors = []
    if data.get("error"):
        errors.append(str(data["error"]))
    if data.get("setup_errno"):
        errors.append("guest setup failed (errno %s)" % data["setup_errno"])
    if data.get("exec_errno"):
        errors.append("guest exec failed (errno %s)" % data["exec_errno"])
    if data.get("cleanup_ok") is False:
        errors.append("guest cleanup was incomplete")
    if data.get("shm_error"):
        errors.append("shared-memory cleanup failed: %s" % data["shm_error"])
    if data.get("execution") == "transport":
        errors.append("guest transport failed")
    if errors:
        return Status.ERROR, "; ".join(errors)
    return None


def map_case(status_str: str, retval, log: str) -> tuple:
    harness = classify_harness_status(log)
    if harness is not None:
        return harness
    status = {"pass": Status.PASS, "fail": Status.FAIL, "brok": Status.BROK,
              "conf": Status.CONF, "warn": Status.WARN}[status_str]
    try:
        exit_code = int(retval[0]) if retval else -1
    except (ValueError, TypeError):
        exit_code = -1
    derived = decode_exit(exit_code)
    if derived is not status:
        return Status.INCONSISTENT, (
            "kirk status %s contradicts exit %d (%s)"
            % (status_str, exit_code, derived.value))
    summary = parse_summary(log or "")
    if summary is not None:
        broken_count = summary["failed"] + summary["broken"]
        if status is Status.PASS and broken_count:
            return Status.INCONSISTENT, (
                "exit 0 but the Summary block counts %d failed/broken"
                % broken_count)
        if status is Status.FAIL and not broken_count:
            return Status.INCONSISTENT, \
                "failing status but the Summary block counts no failure"
    detail = ""
    if status in (Status.FAIL, Status.BROK, Status.WARN):
        for line in (log or "").splitlines():
            if re.search(r"T(FAIL|BROK|WARN)", line):
                detail = line.strip()
                break
    return status, detail


def map_report(doc: dict) -> dict:
    results = {}
    for row in doc.get("results", []):
        tag = row["test_fqn"]
        test = row.get("test", {})
        results[tag] = map_case(row["status"], test.get("retval"),
                                test.get("log", ""))
    return results


def kirk_argv(kirk_dir, *, channel, channel_options, suite,
              exec_timeout_s, suite_timeout_s, report_path, tmp_dir,
              workers=1) -> list:
    options = ":".join("%s=%s" % (k, v) for k, v in channel_options.items())
    com = "%s:%s" % (channel, options) if options else channel
    return [
        sys.executable, str(KIRK_SHIM), str(kirk_dir),
        "--no-colors",
        # Both flags are needed: --com configures the channel, and the
        # SUT must be bound to it or kirk stays on the host channel.
        "--sut", "default:com=%s" % channel,
        "--com", com,
        "--tmp-dir", str(tmp_dir),
        "--run-suite", suite,
        "--exec-timeout", str(exec_timeout_s),
        "--suite-timeout", str(suite_timeout_s),
        "--workers", str(workers),
        "--json-report", str(report_path),
    ]


def run_kirk(argv, *, ltproot) -> int:
    """Kirk's exit code, with its output streaming to the caller's tty.

    Kirk resolves $LTPROOT/runtest/<suite> through the channel's
    fetch_file, so LTPROOT is the guest path (/opt/ltp) and the channel
    maps it into the staged rootfs on the host.
    """
    import os
    env = dict(os.environ)
    env["LTPROOT"] = str(ltproot)
    # The extracted kirk tree is part of the verified runtime payload.
    # Keep interpreter caches in memory so one lane cannot mutate the
    # payload seen by the next lane.
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run([str(a) for a in argv], env=env).returncode


def load_report(path) -> dict:
    try:
        return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LtpRunnerError("kirk report %s is unreadable: %s"
                             % (path, exc)) from exc
