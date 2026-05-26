#!/usr/bin/env bash
# test-rosetta-glibc.sh - glibc loader smoke through Rosetta
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
ROOTFS="${FIXTURES}/x86_64-glibc/rootfs"
ROSETTA_PATH="${MATRIX_ROSETTA_TRANSLATOR:-/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta}"
GLIBC_FIXTURE_TAR="$(pwd)/tests/fixtures/rosetta/x86_64-glibc-rootfs.tar.gz"
LD_SO="${ROOTFS}/lib64/ld-linux-x86-64.so.2"
HELLO="${ROOTFS}/usr/bin/hello-dynamic"
DLOPEN_BIN="${ROOTFS}/usr/bin/dlopen-probe"
TLS_BIN="${ROOTFS}/usr/bin/tls-probe"
GDTLS_BIN="${ROOTFS}/usr/bin/gdtls-probe"
PTHREAD_TLS_BIN="${ROOTFS}/usr/bin/pthread-tls-probe"

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

stage_glibc_fixture()
{
    if [ ! -f "$GLIBC_FIXTURE_TAR" ]; then
        printf 'vendored glibc Rosetta fixture missing: %s\n' "$GLIBC_FIXTURE_TAR" >&2
        exit 77
    fi
    rm -rf "$ROOTFS"
    mkdir -p "${FIXTURES}/x86_64-glibc"
    tar -xzf "$GLIBC_FIXTURE_TAR" -C "${FIXTURES}/x86_64-glibc"
}

if [ ! -x "$LD_SO" ] || [ ! -x "$HELLO" ] \
    || [ ! -x "$DLOPEN_BIN" ] || [ ! -x "$TLS_BIN" ] \
    || [ ! -x "$GDTLS_BIN" ] || [ ! -x "$PTHREAD_TLS_BIN" ]; then
    stage_glibc_fixture
fi

# Run a probe binary under elfuse + sysroot, expect rc=0 and the
# probe's "<label>-ok" success marker on stdout. Variant probes
# (--list output check, ld.so chained loader, etc.) stay inline below.
probe_marker_ok()
{
    local label="$1"
    local marker="$2"
    shift 2
    total=$((total + 1))

    local out rc
    set +e
    out="$("$TIMEOUT" 10 "$ELFUSE" --sysroot "$ROOTFS" "$@" 2>&1)"
    rc=$?
    set -e
    if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q "^${marker}\$"; then
        report_pass "$label"
    else
        report_fail "$label: rc=$rc"
        printf '%s\n' "$out" >&2
    fi
}

probe_marker_ok "glibc-hello" "glibc-hello-ok" "$HELLO"
probe_marker_ok "glibc-hello-via-ldso" "glibc-hello-ok" "$LD_SO" "$HELLO"

total=$((total + 1))
set +e
list_out="$("$TIMEOUT" 10 "$ELFUSE" --sysroot "$ROOTFS" "$LD_SO" --list "$HELLO" 2>&1)"
list_rc=$?
set -e
if [ "$list_rc" -eq 0 ] && printf '%s\n' "$list_out" | grep -q 'libc.so.6' \
    && printf '%s\n' "$list_out" | grep -q 'ld-linux-x86-64.so.2'; then
    report_pass "glibc-hello-list"
else
    report_fail "glibc-hello-list: rc=$list_rc"
    printf '%s\n' "$list_out" >&2
fi

# Runtime dlopen of libm.so.6 -> dlsym sqrt -> sqrt(16.0) -> dlclose.
# Exercises the runtime mmap-fresh-.so codepath, which is distinct from
# the load-time PT_INTERP path the three probes above touch.
probe_marker_ok "glibc-dlopen" "glibc-dlopen-ok" "$DLOPEN_BIN"

# Initial-exec TLS read/write through FS-register translation. The
# binary touches a __thread int and a __thread pointer; a broken
# FS-to-TPIDR_EL0 plumbing under Rosetta surfaces as a value mismatch
# rather than a crash.
probe_marker_ok "glibc-tls" "glibc-tls-ok" "$TLS_BIN"

# General-dynamic TLS via dlopen + __tls_get_addr. The companion
# libgdtls.so is loaded at runtime, which forces the compiler-emitted
# access sequence to call __tls_get_addr instead of using initial-exec
# offsets. A broken Rosetta lowering of that path surfaces as a value
# mismatch from the get/set accessors.
probe_marker_ok "glibc-gdtls" "glibc-gdtls-ok" "$GDTLS_BIN"

# pthread per-thread TLS isolation. A worker thread reads + writes its
# own __thread slot; the probe asserts the worker saw its initial
# default (not the main thread's value) and that the main thread's
# slot survives the worker's write. Exercises per-thread FS-register /
# TPIDR_EL0 setup that the single-thread glibc-tls probe does not
# touch.
probe_marker_ok "glibc-pthread-tls" "glibc-pthread-tls-ok" "$PTHREAD_TLS_BIN"

report_summary "$total"
