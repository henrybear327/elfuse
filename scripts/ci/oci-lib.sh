#!/usr/bin/env bash
# Shared helpers for the OCI CI test scripts. Sourcing enables strict mode and
# an ERR trap: under plain set -e a bare test/grep -q failure kills the script
# with no output at all. Bash 3.2 (macOS /bin/bash): no mapfile, wait -n, or
# ${var,,}.

# -E so the ERR trap fires inside functions too.
set -Eeuo pipefail

# fd 3 is the real stderr. wait_for runs its predicate under >/dev/null 2>&1, so
# a diagnostic a predicate emits before exiting (and the EXIT trap's own output)
# is discarded unless written here instead.
exec 3>&2

# report_error MSG: on the real stderr, and as a ::error:: annotation on the PR
# checks page under GitHub Actions.
report_error()
{
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "::error::$*" >&3
    fi
    echo "FAIL: $*" >&3
}

on_err()
{
    local s=$? cmd=$BASH_COMMAND
    report_error "${BASH_SOURCE[1]:-$0}:${BASH_LINENO[0]:-?}: $cmd (exit $s)"
}
trap on_err ERR

OCI_CI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$OCI_CI_DIR/../.." && pwd)"

fail()
{
    report_error "$*"
    exit 1
}

# One BIN resolution rule for every entry point that sources this.
require_bin()
{
    BIN="${ELFUSE_OCI_BIN:-$ROOT/build/elfuse-oci}"
    if [ ! -x "$BIN" ]; then
        echo "elfuse-oci not found at $BIN (set ELFUSE_OCI_BIN or run 'make elfuse-oci')" >&2
        exit 2
    fi
}

# Exported so every elfuse-oci child resolves the same store, even when the
# caller only set the variable.
require_store()
{
    : "${ELFUSE_OCI_STORE:?set ELFUSE_OCI_STORE to the store directory to use}"
    export ELFUSE_OCI_STORE
}

# run_capture DESC PATTERN CMD...: echoes the command's output, so a failure is
# diagnosable from the CI log alone, and asserts PATTERN appears in it.
run_capture()
{
    local desc="$1" pattern="$2" out
    shift 2
    out="$("$@")"
    printf '%s: %s\n' "$desc" "$out"
    printf '%s\n' "$out" | expect_grep "$pattern"
}

# Bounds a persistent store's disk use by dropping unpacked trees while keeping
# blobs. clean has no liveness guard: call this only after the lane's own guests
# have exited, and never against a store another live execution shares.
prune_store_cache()
{
    "$BIN" clean --cache > /dev/null
}

# wait_for TIMEOUT_SEC DESC CMD...: polls twice a second. Poll loops must live
# here; an inline loop under set -e dies silently on the first transient
# command-substitution failure. Predicates report fatal conditions on fd 3 (fail
# already does).
wait_for()
{
    local timeout="$1" desc="$2" tries i=0
    shift 2
    tries=$((timeout * 2))
    while [ "$i" -lt "$tries" ]; do
        if "$@" > /dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
        i=$((i + 1))
    done
    fail "timed out after ${timeout}s waiting for: $desc"
}

# reap_guest: called from EXIT traps. A leaked guest keeps holding its loopback
# port bound and its per-run clone live on the attached volume, poisoning the
# next run on a persistent self-hosted runner.
reap_guest()
{
    if [ -n "${guest:-}" ] && kill -0 "$guest" 2> /dev/null; then
        kill "$guest" 2> /dev/null || true
        wait "$guest" 2> /dev/null || true
    fi
}

guest_gone()
{
    ! kill -0 "$guest" 2> /dev/null
}

# start_server_guest PATTERN DESC CMD...: sets $guest and $srv_outfile; the
# caller's EXIT trap owns both. A dead guest dumps its captured output rather
# than reading as an opaque readiness timeout.
start_server_guest()
{
    local pattern="$1" desc="$2"
    shift 2
    srv_outfile="$(mktemp)"
    "$@" > "$srv_outfile" 2>&1 &
    guest=$!
    # Invoked indirectly: wait_for calls the predicate by name.
    server_ready()
    {
        if ! kill -0 "$guest" 2> /dev/null; then
            cat "$srv_outfile" >&3
            guest=""
            fail "$desc exited before readiness"
        fi
        grep -Eq "$pattern" "$srv_outfile"
    }
    wait_for 60 "$desc readiness" server_ready
}

# await_server_exit DESC: bounded wait, then assert exit 0. On timeout the
# caller's EXIT trap reaps rather than blocking to the job's timeout.
await_server_exit()
{
    local desc="$1"
    wait_for 10 "$desc exit" guest_gone
    if ! wait "$guest"; then
        guest=""
        fail "$desc exited non-zero"
    fi
    guest=""
}

# dump_evidence RC FILE LABEL: after a failed run (RC != 0), surface FILE on fd
# 3; a server that dies before answering often leaves the only evidence there.
dump_evidence()
{
    [ "$1" -eq 0 ] && return 0
    [ -s "$2" ] || return 0
    {
        echo "--- $3 ---"
        cat "$2"
    } >&3
}

# expect_grep PATTERN asserts stdin contains the fixed string PATTERN. No -q:
# grep must drain the pipe, or the producer dies of SIGPIPE (exit 141) under
# pipefail when grep exits at the first match.
expect_grep()
{
    grep -F -- "$1" > /dev/null
}
