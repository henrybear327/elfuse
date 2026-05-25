#!/usr/bin/env bash
#
# CLI gating for x86_64-via-Rosetta
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Verifies that the three command-line gates around x86_64 guests
# reject as designed. Treats the failure itself as the test: every
# probe is expected to exit non-zero AND emit a recognisable error
# fragment.
#
# Categories covered:
#   1. --gdb on x86_64 ELF: rejected by main.c
#   2. --no-rosetta with x86_64: rejected at exec.c
#   3. ELFUSE_NO_ROSETTA=1 with x86_64: same rejection via env
#
# The end-to-end dynamic-linker bring-up under Rosetta is covered by
# tests/test-rosetta-glibc.sh (glibc-hello / glibc-hello-via-ldso),
# and mid-process execve re-bootstrap is covered by
# tests/test-rosetta-statics.sh (env-execve). Those tests carry the
# same code-path scrutiny as the dynamic / execve probes that used to
# live here, against the vendored fixture trees that are always
# present, so this script no longer needs the x86_64-musl Alpine
# corpus and no longer self-stages it.
#
# Usage: tests/test-rosetta-failure-modes.sh [path/to/elfuse]

set -euo pipefail

ELFUSE_INPUT="${1:-build/elfuse}"
case "$ELFUSE_INPUT" in
    /*) ELFUSE="$ELFUSE_INPUT" ;;
    *) ELFUSE="$(pwd)/$ELFUSE_INPUT" ;;
esac

SHORTDIR=/tmp/elfuse-rfm

# Shared report_pass / report_fail / report_skip + Results: summary
# emitter. Matches the matrix runner's aarch64 per-binary format so
# tests/test-matrix.sh elfuse-x86_64 output reads uniformly.
# shellcheck source=tests/lib/rosetta-test.sh
. "$(dirname "$0")/lib/rosetta-test.sh"

pass=0
fail=0
skip=0
total=0

# Expect a non-zero exit AND a stderr fragment match.
# Args: <label> <stderr-grep-pattern> <command...>
probe_fail()
{
    local label="$1" pattern="$2"
    shift 2
    total=$((total + 1))

    local stderr rc
    stderr="$(mktemp "${SHORTDIR}/${label}.XXXXXX")"
    set +e
    "$TIMEOUT" 5 "$@" > /dev/null 2> "$stderr"
    rc=$?
    set -e

    if [ "$rc" = "0" ]; then
        report_fail "$label: unexpected success (rc=0)"
        head -3 "$stderr" >&2 || true
        return
    fi
    if ! grep -Eq -- "$pattern" "$stderr"; then
        report_fail "$label: stderr missing /$pattern/ (rc=$rc)"
        head -3 "$stderr" >&2 || true
        return
    fi
    report_pass "$label (rc=$rc)"
}

# Pre-flight.
if [ ! -x "$ELFUSE" ]; then
    printf 'elfuse binary not found: %s\n' "$ELFUSE" >&2
    exit 1
fi

require_timeout

mkdir -p "$SHORTDIR"
trap 'rm -rf "$SHORTDIR"' EXIT

# Synthesize a minimal x86_64 ELF (header-only, no segments worth loading).
# This is enough to drive the CLI gates that key on e_machine = EM_X86_64.
# Self-contained: no external fixture tree needed.
min_elf="${SHORTDIR}/min-x86_64.elf"
python3 - "$min_elf" << 'PY'
import struct, sys
ehdr = struct.pack("<16sHHIQQQIHHHHHH",
    b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8),
    2, 62, 1, 0x400000, 64, 0, 0, 64, 56, 1, 0, 0, 0)
phdr = struct.pack("<IIQQQQQQ",
    1, 5, 0, 0x400000, 0, 0, 0x1000, 0x1000)
open(sys.argv[1], "wb").write(ehdr + phdr)
PY

probe_fail "no-rosetta-flag" \
    "x86_64 ELF rejected by --no-rosetta" \
    "$ELFUSE" --no-rosetta "$min_elf"

probe_fail "no-rosetta-env" \
    "x86_64 ELF rejected by --no-rosetta" \
    env ELFUSE_NO_ROSETTA=1 "$ELFUSE" "$min_elf"

probe_fail "gdb-x86_64" \
    "--gdb is not supported for x86_64 guests" \
    "$ELFUSE" --gdb 4242 "$min_elf"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

report_summary "$total"

if [ "$fail" -gt 0 ]; then
    exit 1
fi
exit 0
