#!/usr/bin/env bash
# test-rosetta-execfd.sh - guest fd is preserved across a rosetta execve
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Regression for the hardcoded guest fd 3 in rosetta_finalize. The runner
# used to install the x86_64 binary at guest fd 3, clobbering whatever the
# guest had already opened there. apt hands gpgv a status pipe on fd 3
# (gpgv --status-fd 3); the eviction broke signature verification with
# "Good signature, but could not determine key fingerprint". rosetta_finalize
# now takes the lowest free non-stdio slot and publishes it via AT_EXECFD, so a
# guest fd opened before an x86_64 execve survives into the new image and
# intentionally closed stdio fds stay closed.
#
# The probe: a shell opens fd 3 onto a marker file, then execs busybox to
# cat /proc/self/fd/3. If the runner evicts fd 3, cat reads the busybox ELF
# instead of the marker. Both processes are x86_64 statics, so the inner
# exec goes through the rosetta exec re-bootstrap path.
#
# Skips cleanly when Rosetta Linux is absent or the x86_64 fixture tree is
# missing (run tests/fetch-fixtures.sh INCLUDE_X86_64=1 first).
#
# Usage: tests/test-rosetta-execfd.sh [path/to/elfuse]

set -euo pipefail

ELFUSE_INPUT="${1:-build/elfuse}"
case "$ELFUSE_INPUT" in
    /*) ELFUSE="$ELFUSE_INPUT" ;;
    *) ELFUSE="$(pwd)/$ELFUSE_INPUT" ;;
esac

FIXTURES="${FIXTURES_DIR:-externals/test-fixtures}"
BUSYBOX="$(pwd)/${FIXTURES}/x86_64-musl/staticbin/bin/busybox"
ROSETTA_PATH="${MATRIX_ROSETTA_TRANSLATOR:-/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta}"

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
if [ ! -x "$BUSYBOX" ]; then
    printf 'x86_64 busybox fixture missing; run fetch-fixtures.sh INCLUDE_X86_64=1\n' >&2
    exit 77
fi

require_timeout

MARKER="fd3-preserved-across-rosetta-execve"
MARKER_FILE="$(mktemp -t elfuse-fd3.XXXXXX)"
trap 'rm -f "$MARKER_FILE"' EXIT
printf '%s\n' "$MARKER" > "$MARKER_FILE"

total=$((total + 1))
set +e
out="$("$TIMEOUT" 30 "$ELFUSE" "$BUSYBOX" sh -c \
    "exec 3<$MARKER_FILE; exec \"$BUSYBOX\" cat /proc/self/fd/3" 2> /dev/null)"
rc=$?
set -e
if [ "$rc" -eq 0 ] && [ "$out" = "$MARKER" ]; then
    report_pass "fd3-survives-rosetta-execve"
else
    report_fail "fd3-survives-rosetta-execve: rc=$rc"
    printf 'expected %q, got %q\n' "$MARKER" "$out" >&2
fi

# Closing stdin frees fd 0, so the lowest free slot is below 3. Allocating the
# pre-opened binary from 0 (a plain fd_alloc) would drop it onto fd 0; the
# Rosetta cat then reads the ELF image instead of an empty/closed stdin.
# fd_alloc_from(3) keeps the binary at >= 3, leaving fd 0 closed. The read must
# be by the exec target itself: a child dd would exec-close the CLOEXEC binary
# fd before reading it, hiding the leak. Assert empty stdout and no crash.
total=$((total + 1))
LEAK_OUT="$(mktemp -t elfuse-closed-stdin.XXXXXX)"
trap 'rm -f "$MARKER_FILE" "$LEAK_OUT"' EXIT
set +e
"$TIMEOUT" 30 "$ELFUSE" "$BUSYBOX" sh -c "exec 0<&-; exec \"$BUSYBOX\" cat" \
    > "$LEAK_OUT" 2> /dev/null
rc=$?
set -e
leak_bytes="$(wc -c < "$LEAK_OUT" | tr -d ' ')"
if [ "$leak_bytes" = 0 ] && [ "$rc" -ne 139 ] && [ "$rc" -ne 134 ]; then
    report_pass "closed-stdin-not-backfilled-by-rosetta-binary"
else
    report_fail "closed-stdin-not-backfilled: rc=$rc leaked_bytes=$leak_bytes"
fi

# An x86_64 execve whose guest fd table is full must fail gracefully, not abort
# elfuse after the point of no return. rosetta_finalize allocates the binary fd
# post-reset; sys_execve preflights slot availability before guest_reset and
# returns EMFILE. The guest fd ceiling (1024) is well below the host RLIMIT so a
# guest can fill its table without the pre-PNR host open failing first, which is
# why this is reachable. The helper fills every slot with dup(0) (no setrlimit,
# so the host stays unconstrained) then execs the x86_64 binary; a graceful
# reject lets it run its own "return 3", whereas a post-PNR abort kills elfuse
# (exit 128/134/139). Needs an aarch64 cross-compiler; skips cleanly without.
total=$((total + 1))
CC_AARCH64="${CROSS_COMPILE:-/opt/toolchain/aarch64-linux-gnu/bin/aarch64-linux-gnu-}gcc"
if command -v "$CC_AARCH64" > /dev/null 2>&1; then
    EXH_SRC="$(mktemp -t elfuse-exh.XXXXXX)"
    EXH_BIN="$(mktemp -t elfuse-exh.XXXXXX)"
    trap 'rm -f "$MARKER_FILE" "$LEAK_OUT" "$EXH_SRC" "$EXH_BIN"' EXIT
    printf '#include <unistd.h>\nint main(int c,char**v){(void)c;while(dup(0)>=0);execv(v[1],&v[1]);return 3;}\n' \
        > "$EXH_SRC"
    # -x c: macOS mktemp does not honor a .c suffix, so name the language.
    if "$CC_AARCH64" -x c -O2 -static -o "$EXH_BIN" "$EXH_SRC" 2> /dev/null; then
        set +e
        "$TIMEOUT" 30 "$ELFUSE" "$EXH_BIN" "$BUSYBOX" true > /dev/null 2>&1
        rc=$?
        set -e
        if [ "$rc" = 3 ]; then
            report_pass "fd-exhausted-exec-fails-gracefully"
        else
            report_fail "fd-exhausted-exec-fails-gracefully: rc=$rc (128/134/139=abort)"
        fi
    else
        report_skip "fd-exhausted-exec-fails-gracefully (helper compile failed)"
    fi
else
    report_skip "fd-exhausted-exec-fails-gracefully (no aarch64 cross-compiler)"
fi

report_summary "$total"
