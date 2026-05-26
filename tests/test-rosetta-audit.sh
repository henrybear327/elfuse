#!/usr/bin/env bash
# test-rosetta-audit.sh - Rosetta thread/signal audit smoke
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ELFUSE_INPUT="${1:-build/elfuse}"
case "$ELFUSE_INPUT" in
    /*) ELFUSE="$ELFUSE_INPUT" ;;
    *) ELFUSE="$(pwd)/$ELFUSE_INPUT" ;;
esac

FIXTURES="${FIXTURES_DIR:-externals/test-fixtures}"
ROSETTA_PATH="${MATRIX_ROSETTA_TRANSLATOR:-/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta}"
AUDIT_BIN="$(pwd)/tests/fixtures/rosetta/x86_64-rosetta-audit"
TLS0_BIN="$(pwd)/tests/fixtures/rosetta/x86_64-rosetta-tls0"

# shellcheck source=tests/lib/rosetta-test.sh
. "$(dirname "$0")/lib/rosetta-test.sh"

pass=0
fail=0
skip=0
total=0

if [ ! -x "$ROSETTA_PATH" ]; then
    printf 'rosetta translator not found at %s\n' "$ROSETTA_PATH" >&2
    exit 77
fi
if [ ! -x "$ELFUSE" ]; then
    printf 'elfuse binary not found: %s\n' "$ELFUSE" >&2
    exit 1
fi

require_timeout

if [ ! -x "$AUDIT_BIN" ] || [ ! -x "$TLS0_BIN" ]; then
    printf 'vendored Rosetta audit fixtures missing under tests/fixtures/rosetta/\n' >&2
    exit 77
fi

total=$((total + 1))
set +e
audit_out="$("$ELFUSE" "$AUDIT_BIN" 2>&1)"
audit_rc=$?
set -e
if [ "$audit_rc" -eq 41 ] && printf '%s\n' "$audit_out" | grep -q 'XFAIL sa-resethand-shadowed'; then
    report_pass "audit-known-limitations"
elif [ "$audit_rc" -eq 0 ] && printf '%s\n' "$audit_out" | grep -q 'PASS sa-resethand-reset'; then
    report_pass "audit-known-limitations"
else
    report_fail "audit-known-limitations: rc=$audit_rc"
    printf '%s\n' "$audit_out" >&2
fi

total=$((total + 1))
set +e
"$TIMEOUT" 5 "$ELFUSE" "$TLS0_BIN" > /tmp/elfuse-rosetta-tls0.out 2>&1
tls0_rc=$?
set -e
if [ "$tls0_rc" -eq 124 ]; then
    report_pass "tls0-known-hang"
else
    report_fail "tls0-known-hang: rc=$tls0_rc"
    cat /tmp/elfuse-rosetta-tls0.out >&2
fi
rm -f /tmp/elfuse-rosetta-tls0.out

report_summary "$total"
