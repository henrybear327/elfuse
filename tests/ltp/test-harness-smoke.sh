#!/bin/bash
# Fixture-free smoke test for the harness exit-code contract consumed by
# mk/tests.mk: a missing fixture is exactly rc 77 with a setup hint, and
# an unknown test id is a usage error (rc 2), never a green skip.
set -u

LTP_DIR="$(cd "$(dirname "$0")" && pwd)"
HARNESS="$LTP_DIR/harness.py"

fail=0

check_rc() {
    expected="$1"
    label="$2"
    shift 2
    output=$("$@" 2>&1)
    rc=$?
    if [ "$rc" != "$expected" ]; then
        printf 'FAIL %s: expected rc %s, got %s\n%s\n' \
            "$label" "$expected" "$rc" "$output"
        fail=1
    else
        printf 'ok   %s\n' "$label"
    fi
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

export LTP_FIXTURE_DIR="$tmpdir/absent-fixture"
unset LTP_TEST LTP_TIER 2>/dev/null || true

check_rc 77 "missing fixture skips" \
    python3 "$HARNESS" run --backend elfuse

output=$(python3 "$HARNESS" run --backend elfuse 2>&1)
case "$output" in
    *build-ltp-fixture*) printf 'ok   skip message names the setup target\n' ;;
    *)
        printf 'FAIL skip message lacks setup hint:\n%s\n' "$output"
        fail=1
        ;;
esac

check_rc 2 "unknown --test errors" \
    python3 "$HARNESS" run --backend elfuse --test no_such_test

check_rc 2 "unknown LTP_TEST env errors" \
    env LTP_TEST=no_such_test python3 "$HARNESS" run --backend elfuse

check_rc 2 "tier mismatch errors" \
    python3 "$HARNESS" run --backend elfuse --tier fast --test fcntl34

exit "$fail"
