"""Verdicts: one observed status judged against one expectation.

The gate is bidirectional: got != want is red in both directions, so the
checked-in expectations always describe current behavior exactly. Four
statuses are never satisfiable by any expectation: TIMEOUT and CRASH (a
hang or crash is a defect to skip or quarantine, not a divergence to
record), INCONSISTENT (the result contradicts itself, so nothing was
measured), and ERROR (the run failed to happen). Messages are contract:
the unexpected-pass text names the exact matcher to narrow or delete, and
CI shows it to the PR author verbatim.
"""

from __future__ import annotations

from conformance.model import Status, Verdict

# Retry policy: only quarantined ids retry (blanket retries would
# launder real regressions), every attempt is recorded, and a
# quarantined pass after a red attempt reports the flaked verdict so
# quarantine rot stays measurable.
MAX_ATTEMPTS = 3

_SATISFIES = {
    "expect_pass": (Status.PASS, Status.WARN),
    "expect_failure": (Status.FAIL, Status.BROK),
    "expect_skip": (Status.SKIP,),
    "expect_conf": (Status.CONF,),
}
_EXPECTED_WORD = {
    "expect_pass": "pass",
    "expect_failure": "failure",
    "expect_skip": "skip",
    "expect_conf": "conf",
}


def judge(test_id, backend, status, resolution, detail=""):
    """Return (Verdict, message or None) for one executed case."""
    if status is Status.ERROR:
        return Verdict.ERROR, (
            "HARNESS ERROR: %s on %s: %s\n"
            "  A run that failed to happen must not read as a run that "
            "passed; no expectation can cover this." % (test_id, backend,
                                                        detail))
    where = 'matcher "%s" in %s' % (resolution.matcher, resolution.file)
    expected = _EXPECTED_WORD[resolution.type]
    if status in (Status.TIMEOUT, Status.CRASH, Status.INCONSISTENT):
        return Verdict.UNEXPECTED_FAILURE, (
            "UNEXPECTED FAILURE: %s on %s\n"
            "  expected: %s (%s)\n"
            "  observed: %s: %s\n"
            "  A hang, crash, or self-contradictory result is never a "
            "recordable divergence; fix it, or skip or quarantine the test "
            "with a reason." % (test_id, backend, expected, where,
                                status.value, detail))
    if status in _SATISFIES[resolution.type]:
        return Verdict.AS_EXPECTED, None
    if status is Status.PASS:
        bug_clause = " (bug %s)" % resolution.bug if resolution.bug else ""
        return Verdict.UNEXPECTED_PASS, (
            "UNEXPECTED PASS: %s on %s\n"
            "  expected: %s\n"
            "  declared by: %s%s\n"
            "  This test now passes. Narrow or delete that matcher in this "
            "same PR so the pass is recorded as expected; the ratchet "
            "exists so progress cannot regress silently."
            % (test_id, backend, expected, where, bug_clause))
    return Verdict.UNEXPECTED_FAILURE, (
        "UNEXPECTED FAILURE: %s on %s\n"
        "  expected: %s (%s)\n"
        "  observed: %s: %s\n"
        "  Fix the regression, or record a known divergence as an "
        "expect_failure action with a reason in the backend leaf file."
        % (test_id, backend, expected, where, status.value, detail))
