#!/usr/bin/env bash
# test-rosetta-jit.sh - LuaJIT guest-JIT smoke through Rosetta
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
ROOTFS="${FIXTURES}/x86_64-musl/rootfs"
ROSETTA_PATH="${MATRIX_ROSETTA_TRANSLATOR:-/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta}"
LUAJIT="${ROOTFS}/usr/bin/luajit"

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
if [ ! -x "$LUAJIT" ]; then
    printf 'luajit fixture missing at %s\n' "$LUAJIT" >&2
    printf 'stage via: INCLUDE_X86_64=1 bash tests/fetch-fixtures.sh\n' >&2
    exit 77
fi
if [ ! -x "$ELFUSE" ]; then
    printf 'elfuse binary not found: %s\n' "$ELFUSE" >&2
    exit 1
fi

require_timeout

total=$((total + 1))
set +e
jit_out="$("$TIMEOUT" 12 "$ELFUSE" --sysroot "$ROOTFS" "$LUAJIT" -jv -e 'jit.opt.start(3); local f=function(n) local s=0 for i=1,n do s=s+i end return s end; local out=0; for i=1,4000 do out=f(200) end; io.stdout:write(out, "\n")' 2>&1)"
jit_rc=$?
set -e
if [ "$jit_rc" -eq 0 ] && printf '%s\n' "$jit_out" | grep -q '^20100$' \
    && printf '%s\n' "$jit_out" | grep -q 'TRACE'; then
    report_pass "luajit-trace"
else
    report_fail "luajit-trace: rc=$jit_rc"
    printf '%s\n' "$jit_out" >&2
fi

total=$((total + 1))
set +e
cross_out="$("$TIMEOUT" 12 "$ELFUSE" --sysroot "$ROOTFS" "$LUAJIT" -e 'local jit=require("jit"); assert(jit.status()); local ok=false; local worker=coroutine.create(function() for i=1,4000 do local t={} for j=1,32 do t[j]=j*i end end ok=true end); assert(coroutine.resume(worker)); print(ok and "jit-coroutine-ok" or "jit-coroutine-bad")' 2>&1)"
cross_rc=$?
set -e
if [ "$cross_rc" -eq 0 ] && printf '%s\n' "$cross_out" | grep -q '^jit-coroutine-ok$'; then
    report_pass "luajit-coroutine"
else
    report_fail "luajit-coroutine: rc=$cross_rc"
    printf '%s\n' "$cross_out" >&2
fi

report_summary "$total"
