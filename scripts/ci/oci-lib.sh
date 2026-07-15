#!/usr/bin/env bash
# Shared helpers for the OCI CI test scripts (oci-run-smoke.sh,
# oci-lifecycle.sh, oci-cli-smoke.sh). Source this first; it enables strict
# mode and an ERR trap so any unguarded failure reports its file, line, and
# command. Without the trap, a bare `test`/`grep -q` failing under plain
# `set -e` kills the script with no output at all, which once cost a full
# CI log forensics session to diagnose.
#
# Bash 3.2 compatible: macOS ships /bin/bash 3.2, so no mapfile, wait -n,
# or ${var,,} here or in the scripts that source this.

# -E so the ERR trap fires inside functions too.
set -Eeuo pipefail
on_err() {
    local s=$? where cmd=$BASH_COMMAND
    where="${BASH_SOURCE[1]:-$0}:${BASH_LINENO[0]:-?}"
    # ::error:: mirrors what the pre-extraction inline steps emitted, so
    # failures still surface as annotations on the PR checks page.
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "::error::$where: $cmd (exit $s)"
    fi
    echo "FAIL $where: $cmd (exit $s)" >&2
}
trap on_err ERR

OCI_CI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$OCI_CI_DIR/../.." && pwd)"

fail() {
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "::error::$*"
    fi
    echo "FAIL: $*" >&2
    exit 1
}

# require_bin resolves the elfuse-oci binary into BIN, the same
# resolution scripts/oci-interop.sh uses.
require_bin() {
    BIN="${ELFUSE_OCI_BIN:-$ROOT/build/elfuse-oci}"
    if [ ! -x "$BIN" ]; then
        echo "elfuse-oci not found at $BIN (set ELFUSE_OCI_BIN or run 'make build/elfuse-oci')" >&2
        exit 2
    fi
}

# wait_for TIMEOUT_SEC DESC CMD... polls CMD twice a second until it
# succeeds, and fails loudly with DESC on timeout. Poll loops must live
# here: an inline loop under set -e dies silently on the first transient
# failure of a command substitution.
wait_for() {
    local timeout="$1" desc="$2" tries i=0
    shift 2
    tries=$((timeout * 2))
    while [ "$i" -lt "$tries" ]; do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
        i=$((i + 1))
    done
    fail "timed out after ${timeout}s waiting for: $desc"
}

# reap_guest kills and waits the backgrounded guest recorded in $guest,
# if one is still alive. The scripts that background a guest call this
# from their EXIT trap: a failed phase must not leak the guest, which
# would keep holding its per-digest flock or a bound host loopback port
# and poison the next run on a persistent self-hosted runner.
reap_guest() {
    if [ -n "${guest:-}" ] && kill -0 "$guest" 2>/dev/null; then
        kill "$guest" 2>/dev/null || true
        wait "$guest" 2>/dev/null || true
    fi
}

# expect_grep PATTERN asserts stdin contains the fixed string PATTERN.
# No -q: grep must drain the pipe, or the producer dies of SIGPIPE
# (exit 141) under pipefail when grep exits at the first match.
expect_grep() {
    grep -F -- "$1" >/dev/null
}

# must_report PATTERN DESC CMD... runs a command that must SUCCEED and
# report the fixed string PATTERN on stderr. The stderr is echoed through
# either way so the actual report is visible in the log.
must_report() {
    local pattern="$1" desc="$2" errfile
    shift 2
    errfile="$(mktemp)"
    if ! "$@" 2>"$errfile"; then
        cat "$errfile" >&2
        rm -f "$errfile"
        fail "$desc: command failed"
    fi
    cat "$errfile" >&2
    if ! grep -F -- "$pattern" "$errfile" >/dev/null; then
        rm -f "$errfile"
        fail "$desc: stderr does not mention '$pattern'"
    fi
    rm -f "$errfile"
}

# must_refuse PATTERN DESC CMD... runs a command that must FAIL with a
# stderr containing the fixed string PATTERN. The stderr is echoed either
# way so a wrong refusal message is visible in the log.
must_refuse() {
    local pattern="$1" desc="$2" errfile
    shift 2
    errfile="$(mktemp)"
    if "$@" 2>"$errfile"; then
        cat "$errfile" >&2
        rm -f "$errfile"
        fail "$desc: command succeeded, expected a refusal"
    fi
    cat "$errfile" >&2
    if ! grep -F -- "$pattern" "$errfile" >/dev/null; then
        rm -f "$errfile"
        fail "$desc: refusal does not mention '$pattern'"
    fi
    rm -f "$errfile"
}

# assert_store_empty STORE asserts a store retains no image state: no
# pinned refs, no blobs, no cs/ sparsebundle bundles, no plain rootfs
# caches, and no volume still mounted beneath it. On Linux the cs/ and
# mount checks pass vacuously.
assert_store_empty() {
    local store="$1" refs
    # Capture first: a failing `list` inside `[ -z "$(...)" ]` would be
    # swallowed (the [ builtin's status is all set -e sees), letting a
    # broken list pass the gate; a plain assignment propagates the status.
    refs="$("$BIN" list --store "$store")"
    [ -z "$refs" ] || fail "store not empty: list still shows pinned refs"
    [ -z "$(ls "$store/blobs/sha256" 2>/dev/null || true)" ] \
        || fail "store not empty: blobs remain"
    [ -z "$(find "$store/cs" -mindepth 2 -maxdepth 2 -type d 2>/dev/null || true)" ] \
        || fail "store not empty: cs/ bundle dirs remain"
    [ -z "$(find "$store/rootfs/sha256" -mindepth 1 -maxdepth 1 2>/dev/null || true)" ] \
        || fail "store not empty: plain rootfs caches remain"
    if mount | grep -F "$store" >/dev/null; then
        fail "store not empty: a volume is still mounted under $store"
    fi
}

# sha256_hex prints the hex digest of stdin. Hosted macOS runners ship
# shasum but not coreutils sha256sum.
sha256_hex() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{print $1}'
    else
        shasum -a 256 | awk '{print $1}'
    fi
}
