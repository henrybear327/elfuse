#!/usr/bin/env bash
# Run the pinned gVisor syscall tests through Elfuse and/or Linux/QEMU.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PARSER="${ROOT_DIR}/tests/lib/gvisor_conformance.py"
EXPECTATIONS="${GVISOR_EXPECTATIONS:-${ROOT_DIR}/tests/conformance/gvisor/expectations.tsv}"
BIN_DIR="${GVISOR_TESTS_DIR:-${ROOT_DIR}/build/gvisor-tests}"
ELFUSE="${ELFUSE_BINARY:-${ROOT_DIR}/build/elfuse}"
SUITE_TIMEOUT="${GVISOR_SUITE_TIMEOUT:-600}"
CASE_TIMEOUT="${GVISOR_CASE_TIMEOUT:-30}"
BOOTSTRAP="${GVISOR_BOOTSTRAP:-0}"
# ReadvTestNoFixture.TruncatedAtMax value-initializes a ~2 GiB buffer
# (MAX_RW_COUNT), which the default 2048 MiB no-swap guest cannot back, so the
# allocation faults. Raise the conformance guest only: qemu-runner.sh honors an
# already-set QEMU_MEM, and the general test-matrix sources it in a separate
# process, so its 2048 MiB default is unaffected.
QEMU_MEM="${QEMU_MEM:-6144}"
RUN_ID="$(date -u '+%Y%m%dT%H%M%SZ')-$$"
RESULT_BASE="${GVISOR_RESULTS_DIR:-${ROOT_DIR}/build/gvisor-conformance-results}"
RUN_ROOT="${RESULT_BASE}/${RUN_ID}"
# The stage must live under the repo root regardless of GVISOR_RESULTS_DIR:
# the QEMU guest reaches host binaries only through the repo's 9p share, so
# an out-of-tree results override must not relocate the staged payload. The
# cleanup trap removes it.
STAGE="${ROOT_DIR}/build/gvisor-conformance-stage/${RUN_ID}"

# shellcheck source=tests/lib/test-runner.sh
. "${ROOT_DIR}/tests/lib/test-runner.sh"
# shellcheck source=tests/lib/gvisor-common.sh
. "${ROOT_DIR}/tests/lib/gvisor-common.sh"

usage()
{
    echo "Usage: $0 <elfuse-aarch64|qemu-aarch64|all> [binary-directory]" >&2
    exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
case "$1" in
    elfuse-aarch64) BACKENDS=(elfuse-aarch64) ;;
    qemu-aarch64) BACKENDS=(qemu-aarch64) ;;
    all) BACKENDS=(qemu-aarch64 elfuse-aarch64) ;;
    *) usage ;;
esac
if [ "$#" -eq 2 ]; then
    BIN_DIR="$2"
fi
case "$BIN_DIR" in
    /*) ;;
    *) BIN_DIR="${ROOT_DIR}/${BIN_DIR}" ;;
esac

for value in "$SUITE_TIMEOUT" "$CASE_TIMEOUT"; do
    # The arithmetic zero test also catches "00", which GNU timeout would
    # interpret as "never time out".
    case "$value" in
        '' | *[!0-9]*)
            echo "gVisor conformance: timeouts must be positive integers" >&2
            exit 2
            ;;
    esac
    if [ "$value" -eq 0 ]; then
        echo "gVisor conformance: timeouts must be positive integers" >&2
        exit 2
    fi
done

if ! command -v python3 > /dev/null 2>&1 || \
    ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 9))'; then
    echo "gVisor conformance: Python 3.9+ is required for strict result parsing" >&2
    exit 127
fi
[ -f "$PARSER" ] || {
    echo "gVisor conformance: parser not found: $PARSER" >&2
    exit 127
}
if [ "$BOOTSTRAP" -eq 0 ] && [ ! -f "$EXPECTATIONS" ]; then
    echo "gVisor conformance: expectations not found: $EXPECTATIONS" >&2
    echo "  Bootstrap a draft with GVISOR_BOOTSTRAP=1 and expectations-init." >&2
    exit 2
fi
missing=0
for name in "${GVISOR_TEST_BINARIES[@]}"; do
    if [ ! -f "${BIN_DIR}/${name}" ]; then
        echo "SKIP gVisor conformance: missing ${BIN_DIR}/${name}" >&2
        missing=1
    fi
done
if [ "$missing" -ne 0 ]; then
    echo "Build the payload with: make build-gvisor-tests" >&2
    exit 77
fi

mkdir -p "$STAGE"
QEMU_LOADED=0

# Environment scrubbed on both backends before any payload invocation so a
# caller's GoogleTest or gVisor settings cannot skew the run.
GTEST_ENV_VARS='TEST_ON_GVISOR GVISOR_SAVE_TEST
    GTEST_ALSO_RUN_DISABLED_TESTS GTEST_BREAK_ON_FAILURE
    GTEST_CATCH_EXCEPTIONS GTEST_COLOR GTEST_FAIL_FAST GTEST_FILTER
    GTEST_FLAGFILE GTEST_LIST_TESTS GTEST_OUTPUT GTEST_PRINT_TIME
    GTEST_PREMATURE_EXIT_FILE GTEST_RANDOM_SEED GTEST_REPEAT
    GTEST_SHARD_INDEX GTEST_SHARD_STATUS_FILE GTEST_SHUFFLE
    GTEST_STREAM_RESULT_TO GTEST_THROW_ON_FAILURE GTEST_TOTAL_SHARDS'

# shellcheck disable=SC2329  # Invoked by the signal/exit trap.
cleanup()
{
    if [ "$QEMU_LOADED" -eq 1 ]; then
        qemu_stop
    fi
    rm -rf "$STAGE"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for name in "${GVISOR_TEST_BINARIES[@]}"; do
    if ! gvisor_validate_static_aarch64 "${BIN_DIR}/${name}"; then
        exit 2
    fi
    cp "${BIN_DIR}/${name}" "${STAGE}/${name}"
    chmod +x "${STAGE}/${name}"
done

complete_log()
{
    local invocation_dir="$1"
    {
        echo "===== stdout ====="
        cat "${invocation_dir}/stdout.log"
        echo "===== stderr ====="
        cat "${invocation_dir}/stderr.log"
        if [ -s "${invocation_dir}/transport.log" ]; then
            echo "===== backend transport ====="
            cat "${invocation_dir}/transport.log"
        fi
    } > "${invocation_dir}/complete.log"
}

decimal_file_value()
{
    local path="$1" value lines

    [ -f "$path" ] || return 1
    lines=$(wc -l < "$path") || return 1
    [ "$lines" -eq 1 ] || return 1
    IFS= read -r value < "$path" || return 1
    case "$value" in '' | *[!0-9]*) return 1 ;; esac
    printf '%s\n' "$value"
}

# Sets INVOKE_RC and INVOKE_EXECUTION from the status and elapsed artifacts.
classify_invocation()
{
    local invocation_dir="$1" timeout_seconds="$2"
    local elapsed limit_us

    INVOKE_EXECUTION=transport
    INVOKE_RC=$(decimal_file_value "${invocation_dir}/status") || {
        INVOKE_RC=125
        return
    }
    elapsed=$(decimal_file_value "${invocation_dir}/elapsed-us") || return
    limit_us=$((timeout_seconds * 1000000))
    INVOKE_EXECUTION=normal
    if [ "$INVOKE_RC" -eq 124 ] && [ "$elapsed" -ge "$limit_us" ]; then
        INVOKE_EXECUTION=timeout
    elif [ "$INVOKE_RC" -eq 137 ] && [ "$elapsed" -ge "$limit_us" ]; then
        # GNU timeout returns the SIGKILL status after --kill-after fires.
        # Wall time distinguishes that from an immediate guest SIGKILL.
        INVOKE_EXECUTION=timeout
    elif [ "$INVOKE_RC" -gt 128 ]; then
        INVOKE_EXECUTION=signal
    fi
}

# Runs one payload invocation through Elfuse on the host. gtest arguments
# arrive as "$@"; artifacts land in the invocation directory.
invoke_elfuse()
{
    local invocation_dir="$1" binary="$2" timeout_seconds="$3"
    shift 3
    local scratch start_us end_us rc

    : > "${invocation_dir}/transport.log"
    scratch=$(mktemp -d "${invocation_dir}/scratch.XXXXXX") || {
        echo "unable to create scratch directory" > "${invocation_dir}/transport.log"
        return
    }
    start_us=$(epoch_us)
    (
        cd "$scratch" || exit 125
        umask 022
        ulimit -c 0 || exit 125
        # Elfuse virtualizes the guest RLIMIT_NOFILE at 1024 and needs an
        # additional 256 host descriptors, so lowering the host limit here
        # would prevent the translator from starting.
        ulimit -s 8192 || exit 125
        # shellcheck disable=SC2086  # Deliberate word splitting.
        unset $GTEST_ENV_VARS
        export TEST_TMPDIR="$scratch" TMPDIR="$scratch" HOME="$scratch"
        export LC_ALL=C TZ=UTC
        timeout --kill-after=5 "$timeout_seconds" \
            "$ELFUSE" --timeout 0 "$binary" \
            --gtest_color=no --gtest_repeat=1 "$@" < /dev/null
    ) > "${invocation_dir}/stdout.log" 2> "${invocation_dir}/stderr.log"
    rc=$?
    end_us=$(epoch_us)
    printf '%s\n' "$rc" > "${invocation_dir}/status"
    printf '%s\n' "$((end_us - start_us))" > "${invocation_dir}/elapsed-us"
    if [ -f "${scratch}/result.xml" ]; then
        cp "${scratch}/result.xml" "${invocation_dir}/result.xml"
    fi
}

# Runs one payload invocation inside the QEMU reference guest. The guest
# writes stdout, stderr, status, and XML into its scratch directory; they
# are retrieved afterwards so transport noise never mixes with test output.
invoke_qemu()
{
    local invocation_dir="$1" binary="$2" timeout_seconds="$3"
    shift 3
    local guest_binary guest_scratch launch_rc retrieval_rc
    local start_us end_us

    : > "${invocation_dir}/stdout.log"
    : > "${invocation_dir}/stderr.log"
    : > "${invocation_dir}/transport.log"
    guest_binary=$(qemu_guestpath "$binary")
    guest_scratch=$(qemu_exec mktemp -d "/tmp/gvisor-conformance.XXXXXX" \
        2>> "${invocation_dir}/transport.log" < /dev/null)
    launch_rc=$?
    case "$guest_scratch" in
        /tmp/gvisor-conformance.*) ;;
        *)
            echo "invalid guest scratch path: ${guest_scratch}" >> "${invocation_dir}/transport.log"
            launch_rc=125
            ;;
    esac
    if [ "$launch_rc" -ne 0 ]; then
        return
    fi

    start_us=$(epoch_us)
    # shellcheck disable=SC2016  # Expanded by the remote shell.
    qemu_exec sh -c '
guest_scratch=$1
guest_binary=$2
timeout_seconds=$3
shift 3
cd "$guest_scratch" || exit 125
umask 022
ulimit -c 0 || exit 125
ulimit -n 1024 || exit 125
ulimit -s 8192 || exit 125
unset '"$GTEST_ENV_VARS"'
export TEST_TMPDIR="$guest_scratch" TMPDIR="$guest_scratch" HOME="$guest_scratch"
export LC_ALL=C TZ=UTC
/usr/bin/timeout --kill-after=5 "$timeout_seconds" \
    "$guest_binary" --gtest_color=no --gtest_repeat=1 "$@" \
    > stdout.log 2> stderr.log < /dev/null
rc=$?
printf "%s\n" "$rc" > status
exit 0
' sh "$guest_scratch" "$guest_binary" "$timeout_seconds" "$@" \
        >> "${invocation_dir}/transport.log" 2>&1 < /dev/null
    launch_rc=$?
    end_us=$(epoch_us)
    if [ "$launch_rc" -ne 0 ]; then
        qemu_exec rm -rf "$guest_scratch" \
            >> "${invocation_dir}/transport.log" 2>&1 < /dev/null || true
        return
    fi
    retrieval_rc=0
    qemu_exec cat "${guest_scratch}/stdout.log" \
        > "${invocation_dir}/stdout.log" 2>> "${invocation_dir}/transport.log" \
        < /dev/null || retrieval_rc=$?
    qemu_exec cat "${guest_scratch}/stderr.log" \
        > "${invocation_dir}/stderr.log" 2>> "${invocation_dir}/transport.log" \
        < /dev/null || retrieval_rc=$?
    qemu_exec cat "${guest_scratch}/status" \
        > "${invocation_dir}/status" 2>> "${invocation_dir}/transport.log" \
        < /dev/null || retrieval_rc=$?
    if qemu_exec test -f "${guest_scratch}/result.xml" \
        > /dev/null 2>> "${invocation_dir}/transport.log" < /dev/null; then
        qemu_exec cat "${guest_scratch}/result.xml" \
            > "${invocation_dir}/result.xml" 2>> "${invocation_dir}/transport.log" \
            < /dev/null || retrieval_rc=$?
    fi
    qemu_exec rm -rf "$guest_scratch" \
        >> "${invocation_dir}/transport.log" 2>&1 < /dev/null || true
    if [ "$retrieval_rc" -ne 0 ]; then
        rm -f "${invocation_dir}/status"
        return
    fi
    printf '%s\n' "$((end_us - start_us))" > "${invocation_dir}/elapsed-us"
}

invoke_backend()
{
    local backend="$1"
    shift
    case "$backend" in
        elfuse-aarch64) invoke_elfuse "$@" ;;
        qemu-aarch64) invoke_qemu "$@" ;;
    esac
}

record_infrastructure_failure()
{
    local backend="$1" backend_dir="$2" phase="$3" detail="$4"
    local failure_dir="${backend_dir}/infrastructure-${phase}"

    mkdir -p "$failure_dir"
    : > "${failure_dir}/stdout.log"
    printf '%s\n' "$detail" > "${failure_dir}/stderr.log"
    cp "${failure_dir}/stderr.log" "${failure_dir}/complete.log"
    python3 "$PARSER" record --xml "${failure_dir}/result.xml" \
        --test "infrastructure.${phase}" --backend "$backend" \
        --expected PASS --reason "runner infrastructure" --issue - \
        --exit-code 125 --execution transport --execution-detail "$detail" \
        --duration-ms 0 --stdout "${failure_dir}/stdout.log" \
        --stderr "${failure_dir}/stderr.log" --log "${failure_dir}/complete.log" \
        --output "${failure_dir}/result.json" \
        --classification "${failure_dir}/classification.tsv"
}

# Records a backend-level infrastructure failure and still emits the
# aggregate so a partial run leaves parseable artifacts behind.
fail_backend()
{
    local backend="$1" backend_dir="$2" phase="$3" detail="$4"

    record_infrastructure_failure "$backend" "$backend_dir" "$phase" \
        "$detail" || true
    aggregate_and_report "$backend" "$backend_dir" || true
}

aggregate_and_report()
{
    local label="$1" root="$2"
    local tag='' total=0 fatal=1 passed=0 failed=0 skipped=0 broken=0
    local timed_out=0 signaled=0 xfailed=0 xpassed=0

    python3 "$PARSER" aggregate --root "$root" \
        --json "${root}/results.json" --junit "${root}/results.xml" \
        > "${root}/summary.tsv" || return 1
    IFS=$'\t' read -r tag total fatal passed failed skipped broken timed_out \
        signaled xfailed xpassed < "${root}/summary.tsv" || return 1
    [ "$tag" = SUMMARY ] || return 1
    printf '%s summary: %d total, %d PASS, %d FAIL, %d SKIP, %d BROKEN, %d TIMEOUT, %d SIGNAL, %d XFAIL, %d XPASS\n' \
        "$label" "$total" "$passed" "$failed" "$skipped" "$broken" \
        "$timed_out" "$signaled" "$xfailed" "$xpassed"
    [ "$fatal" -eq 0 ]
}

list_binary()
{
    local backend="$1" backend_dir="$2" name="$3"
    local list_dir="${backend_dir}/list-${name}"

    mkdir -p "$list_dir"
    invoke_backend "$backend" "$list_dir" "${STAGE}/${name}" "$CASE_TIMEOUT" \
        --gtest_list_tests
    classify_invocation "$list_dir" "$CASE_TIMEOUT"
    complete_log "$list_dir"
    if [ "$INVOKE_EXECUTION" != normal ] || [ "$INVOKE_RC" -ne 0 ]; then
        echo "${backend} list ${name} BROKEN (${INVOKE_EXECUTION}, exit ${INVOKE_RC}; ${list_dir}/complete.log)" >&2
        return 1
    fi
    if ! python3 "$PARSER" gtest-list --input "${list_dir}/stdout.log" \
        --output "${list_dir}/tests.list" 2>> "${list_dir}/transport.log"; then
        complete_log "$list_dir"
        echo "${backend} list ${name} BROKEN (malformed GoogleTest listing; ${list_dir}/complete.log)" >&2
        return 1
    fi
    return 0
}

run_suite()
{
    local backend="$1" backend_dir="$2" name="$3"
    local suite_dir="${backend_dir}/suites/${name}"
    local final test slug detail excluded included
    local suite_args=("--gtest_output=xml:result.xml")

    mkdir -p "$suite_dir"
    # run_backend reads rerun.tsv unconditionally; make sure it exists even
    # when the all-excluded skip below returns before record-suite writes it.
    : > "${suite_dir}/rerun.tsv"
    # A binary whose every listed test is a manifest EXCLUDE row (or DISABLED_)
    # has nothing to run; skip it rather than launch gtest with an all-negative
    # filter, which would produce an empty XML the recorder rejects as BROKEN.
    included=$(awk -F'\t' 'NR == FNR { plan[$1]; next } ($0 in plan) { c++ }
        END { print c + 0 }' \
        "${backend_dir}/plan.tsv" "${backend_dir}/list-${name}/tests.list")
    if [ "$included" -eq 0 ]; then
        echo "${backend} suite ${name}: all tests excluded, skipping" >&2
        return 0
    fi
    # Listed tests without a plan row are manifest EXCLUDE entries (or
    # DISABLED_ tests gtest skips anyway); keep them out of the suite run.
    excluded=$(awk -F'\t' 'NR == FNR { plan[$1]; next } !($0 in plan) {
            out = out (out == "" ? "" : ":") $0
        } END { print out }' \
        "${backend_dir}/plan.tsv" "${backend_dir}/list-${name}/tests.list")
    if [ -n "$excluded" ]; then
        suite_args+=("--gtest_filter=-${excluded}")
    fi
    invoke_backend "$backend" "$suite_dir" "${STAGE}/${name}" "$SUITE_TIMEOUT" \
        "${suite_args[@]}"
    classify_invocation "$suite_dir" "$SUITE_TIMEOUT"
    complete_log "$suite_dir"
    if ! python3 "$PARSER" record-suite --xml "${suite_dir}/result.xml" \
        --tests "${backend_dir}/list-${name}/tests.list" \
        --plan "${backend_dir}/plan.tsv" --backend "$backend" \
        --exit-code "$INVOKE_RC" --execution "$INVOKE_EXECUTION" \
        --stdout "${suite_dir}/stdout.log" --stderr "${suite_dir}/stderr.log" \
        --log "${suite_dir}/complete.log" \
        --output-dir "${backend_dir}/cases" \
        --rerun-list "${suite_dir}/rerun.tsv" \
        --summary "${suite_dir}/summary.tsv" 2>> "${suite_dir}/transport.log"; then
        complete_log "$suite_dir"
        echo "${backend} suite ${name} BROKEN (result recording failed; ${suite_dir}/complete.log)" >&2
        return 1
    fi
    while IFS=$'\t' read -r final test slug detail; do
        if [ "$final" != PASS ]; then
            printf '%-15s %-7s %s %s\n' "$backend" "$final" "$test" "$detail"
        fi
    done < "${suite_dir}/summary.tsv"
    return 0
}

rerun_case()
{
    local backend="$1" backend_dir="$2" name="$3" test="$4" slug="$5"
    local expected="$6" reason="$7" issue="$8"
    local case_dir="${backend_dir}/cases/${slug}"
    local final detail rest duration_us duration_ms=0

    mkdir -p "$case_dir"
    invoke_backend "$backend" "$case_dir" "${STAGE}/${name}" "$CASE_TIMEOUT" \
        "--gtest_filter=${test}" "--gtest_output=xml:result.xml"
    classify_invocation "$case_dir" "$CASE_TIMEOUT"
    complete_log "$case_dir"
    if duration_us=$(decimal_file_value "${case_dir}/elapsed-us"); then
        duration_ms=$((duration_us / 1000))
    fi
    if ! python3 "$PARSER" record --xml "${case_dir}/result.xml" \
        --test "$test" --backend "$backend" --expected "$expected" \
        --reason "$reason" --issue "$issue" --exit-code "$INVOKE_RC" \
        --execution "$INVOKE_EXECUTION" --duration-ms "$duration_ms" \
        --stdout "${case_dir}/stdout.log" --stderr "${case_dir}/stderr.log" \
        --log "${case_dir}/complete.log" --output "${case_dir}/result.json" \
        --classification "${case_dir}/classification.tsv" \
        2>> "${case_dir}/transport.log"; then
        complete_log "$case_dir"
        echo "${backend} rerun ${test} BROKEN (result recording failed; ${case_dir}/complete.log)" >&2
        return 1
    fi
    IFS=$'\t' read -r _ final _ detail rest < "${case_dir}/classification.tsv" || true
    printf '%-15s %-7s %s (isolated rerun) %s\n' "$backend" "$final" "$test" "$detail"
    return 0
}

run_backend()
{
    local backend="$1"
    local backend_dir="${RUN_ROOT}/${backend}"
    local name test slug expected reason issue runner_error=0 plan_args
    mkdir -p "${backend_dir}/cases"

    if [ "$backend" = elfuse-aarch64 ] && [ ! -x "$ELFUSE" ]; then
        echo "gVisor conformance: Elfuse binary not found: $ELFUSE" >&2
        echo "  Build it with: make elfuse" >&2
        fail_backend "$backend" "$backend_dir" setup \
            "Elfuse binary not found: $ELFUSE"
        return 1
    fi
    if [ "$backend" = qemu-aarch64 ] && [ "$QEMU_LOADED" -eq 0 ]; then
        # qemu-runner installs its own EXIT trap when sourced; replace it with
        # this script's cleanup immediately after loading the public API.
        # shellcheck source=tests/qemu-runner.sh
        . "${ROOT_DIR}/tests/qemu-runner.sh"
        QEMU_LOADED=1
        trap cleanup EXIT
        if ! qemu_start; then
            echo "qemu-aarch64 setup BROKEN" >&2
            fail_backend "$backend" "$backend_dir" setup \
                "QEMU VM failed to start"
            return 1
        fi
    fi

    for name in "${GVISOR_TEST_BINARIES[@]}"; do
        if ! list_binary "$backend" "$backend_dir" "$name"; then
            fail_backend "$backend" "$backend_dir" "list_${name}" \
                "listing ${name} failed"
            return 1
        fi
    done

    for name in "${GVISOR_TEST_BINARIES[@]}"; do
        cat "${backend_dir}/list-${name}/tests.list"
    done > "${backend_dir}/all-tests.list"
    plan_args=(plan --input "${backend_dir}/all-tests.list" --backend "$backend"
        --output "${backend_dir}/plan.tsv")
    if [ "$BOOTSTRAP" -ne 0 ]; then
        plan_args+=(--bootstrap)
    else
        plan_args+=(--manifest "$EXPECTATIONS")
    fi
    if ! python3 "$PARSER" "${plan_args[@]}" 2> "${backend_dir}/plan-error.log"; then
        cat "${backend_dir}/plan-error.log" >&2
        echo "${backend} plan BROKEN (listing or expectations mismatch)" >&2
        fail_backend "$backend" "$backend_dir" plan \
            "expectation validation failed"
        return 1
    fi

    for name in "${GVISOR_TEST_BINARIES[@]}"; do
        if ! run_suite "$backend" "$backend_dir" "$name"; then
            runner_error=1
            record_infrastructure_failure "$backend" "$backend_dir" "suite_${name}" \
                "runner failed while processing ${name}" || true
            continue
        fi
        while IFS=$'\t' read -r test slug expected reason issue <&3; do
            if ! rerun_case "$backend" "$backend_dir" "$name" "$test" "$slug" \
                "$expected" "$reason" "$issue"; then
                runner_error=1
            fi
        done 3< "${backend_dir}/suites/${name}/rerun.tsv"
    done

    aggregate_and_report "$backend" "$backend_dir" || runner_error=1
    [ "$runner_error" -eq 0 ]
}

overall_fatal=0
for backend in "${BACKENDS[@]}"; do
    run_backend "$backend" || overall_fatal=1
    if [ "$backend" = qemu-aarch64 ] && [ "$QEMU_LOADED" -eq 1 ]; then
        qemu_stop
        QEMU_LOADED=0
    fi
done

aggregate_and_report all "$RUN_ROOT" || overall_fatal=1
echo "Artifacts: ${RUN_ROOT}"
exit "$overall_fatal"
