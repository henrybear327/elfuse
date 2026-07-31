#!/usr/bin/env bash
# Measure the raw gVisor syscall pass rate per backend.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# The conformance lane gates against tests/conformance/gvisor/expectations.tsv,
# so EXCLUDE rows keep tests from running at all and the expected states keep
# known divergences out of the failure column. This wrapper answers the other
# question: of every test the payload discovers, how much passes on each
# backend today. It runs run-gvisor-conformance.sh with GVISOR_BOOTSTRAP=1,
# which plans every discovered test as expected PASS so nothing is masked, and
# reduces each backend's summary.tsv to one pass-rate row. A red conformance
# exit is the measurement here, not an error: this script fails only when a
# requested backend produced no aggregate at all.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage()
{
    echo "Usage: $0 [elfuse-aarch64|qemu-aarch64|all] [binary-directory]" >&2
    exit 2
}

# The backend-to-list mapping mirrors run-gvisor-conformance.sh on purpose:
# the table below must iterate the backends the caller requested, not the
# backend directories the run produced, so a backend that died before
# leaving an aggregate is reported as an error instead of silently missing.
BACKEND="${1:-all}"
case "$BACKEND" in
    elfuse-aarch64) BACKENDS=(elfuse-aarch64) ;;
    qemu-aarch64) BACKENDS=(qemu-aarch64) ;;
    all) BACKENDS=(qemu-aarch64 elfuse-aarch64) ;;
    *) usage ;;
esac
[ "$#" -le 2 ] || usage

RUNNER_LOG="$(mktemp "${TMPDIR:-/tmp}/gvisor-passrate.XXXXXX")" || exit 1
trap 'rm -f "$RUNNER_LOG"' EXIT

runner_args=("$BACKEND")
if [ "$#" -eq 2 ]; then
    runner_args+=("$2")
fi
rc=0
GVISOR_BOOTSTRAP=1 bash "${ROOT_DIR}/tests/run-gvisor-conformance.sh" \
    "${runner_args[@]}" 2>&1 | tee "$RUNNER_LOG" || rc=$?
# Exit 77 (payload missing) and exits 2 and 127 (usage errors and missing
# prerequisites) happen before any backend runs; propagate them so make's
# skip handling and caller diagnostics keep working. Exit 1 is the expected
# red lane and is judged below by whether each backend left an aggregate.
case "$rc" in
    77 | 2 | 127) exit "$rc" ;;
esac

RUN_ROOT="$(sed -n 's/^Artifacts: //p' "$RUNNER_LOG" | tail -n 1)"
if [ -z "$RUN_ROOT" ] || [ ! -d "$RUN_ROOT" ]; then
    echo "gvisor-passrate: runner reported no artifacts directory" >&2
    exit 1
fi

echo
echo "Raw pass rate (GVISOR_BOOTSTRAP=1: every discovered test planned, none excluded)"
printf '%-15s %6s %6s %6s %6s %7s %8s %7s %10s\n' \
    backend total PASS FAIL SKIP BROKEN TIMEOUT SIGNAL pass-rate
status=0
for backend in "${BACKENDS[@]}"; do
    summary="${RUN_ROOT}/${backend}/summary.tsv"
    if [ ! -f "$summary" ]; then
        echo "gvisor-passrate: no summary for ${backend} (${summary})" >&2
        status=1
        continue
    fi
    if ! IFS=$'\t' read -r tag total _ passed failed skipped broken timed_out \
        signaled _ < "$summary"; then
        echo "gvisor-passrate: unreadable summary for ${backend}" >&2
        status=1
        continue
    fi
    if [ "$tag" != SUMMARY ] || [ "$total" -eq 0 ]; then
        echo "gvisor-passrate: malformed summary for ${backend}" >&2
        status=1
        continue
    fi
    rate="$(awk -v p="$passed" -v t="$total" \
        'BEGIN { printf "%.1f%%", 100 * p / t }')"
    printf '%-15s %6d %6d %6d %6d %7d %8d %7d %10s\n' \
        "$backend" "$total" "$passed" "$failed" "$skipped" "$broken" \
        "$timed_out" "$signaled" "$rate"
done
echo "Artifacts: ${RUN_ROOT}"
exit "$status"
