#!/usr/bin/env bash
# Shared pin and artifact validation for the gVisor conformance payload.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

# shellcheck shell=bash
# shellcheck disable=SC2034  # Consumed by scripts that source this file.

# gVisor master commit of 2026-07-15,
# "use official docker:dind image for basic/docker image".
GVISOR_PIN=c30a6d1b6f26b353ca5d6ff5a288d96ed820e89c

# Enabled test targets are the opt-in allowlist in targets.txt (one Bazel
# label per line; blank lines and # comments ignored), so a single reviewed
# file drives what the lane builds and runs. Resolve it relative to this
# script so cwd does not matter; GVISOR_TARGETS_FILE overrides the location.
_gvisor_common_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
GVISOR_TARGETS_FILE="${GVISOR_TARGETS_FILE:-${_gvisor_common_dir}/../conformance/gvisor/targets.txt}"
if [ ! -f "$GVISOR_TARGETS_FILE" ]; then
    echo "gVisor targets file not found: $GVISOR_TARGETS_FILE" >&2
    return 1 2> /dev/null || exit 1
fi
GVISOR_TEST_TARGETS="$(awk '{ sub(/#.*/, ""); for (i = 1; i <= NF; i++) printf "%s ", $i }' "$GVISOR_TARGETS_FILE")"
unset _gvisor_common_dir
# Binary names are the target label basenames; derive them so adding a
# target cannot leave the two lists out of sync.
GVISOR_TEST_BINARIES=()
for _gvisor_target in $GVISOR_TEST_TARGETS; do
    GVISOR_TEST_BINARIES+=("${_gvisor_target##*:}")
done
unset _gvisor_target

gvisor_find_readelf()
{
    if [ -n "${GVISOR_READELF:-}" ]; then
        printf '%s\n' "$GVISOR_READELF"
        return
    fi
    if [ -n "${CROSS_COMPILE:-}" ] && command -v "${CROSS_COMPILE}readelf" > /dev/null 2>&1; then
        printf '%s\n' "${CROSS_COMPILE}readelf"
        return
    fi
    # CROSS_COMPILE is a make variable and is not exported to scripts run
    # directly (CI invokes the runner without make), so probe the repo's
    # LINUX_TOOLCHAIN convention and Homebrew's keg-only binutils, neither
    # of which is on PATH.
    if [ -n "${LINUX_TOOLCHAIN:-}" ] \
        && command -v "${LINUX_TOOLCHAIN}/bin/aarch64-linux-gnu-readelf" > /dev/null 2>&1; then
        printf '%s\n' "${LINUX_TOOLCHAIN}/bin/aarch64-linux-gnu-readelf"
        return
    fi
    if command -v aarch64-linux-gnu-readelf > /dev/null 2>&1; then
        printf '%s\n' aarch64-linux-gnu-readelf
        return
    fi
    if command -v readelf > /dev/null 2>&1; then
        printf '%s\n' readelf
        return
    fi
    if command -v /opt/homebrew/opt/binutils/bin/readelf > /dev/null 2>&1; then
        printf '%s\n' /opt/homebrew/opt/binutils/bin/readelf
        return
    fi
    return 1
}

gvisor_validate_static_aarch64()
{
    local binary="$1" readelf_tool header program dynamic

    [ -f "$binary" ] || {
        echo "gVisor artifact is missing: $binary" >&2
        return 1
    }
    [ -x "$binary" ] || {
        echo "gVisor artifact is not executable: $binary" >&2
        return 1
    }
    readelf_tool=$(gvisor_find_readelf) || {
        echo "No readelf found; install an AArch64 binutils toolchain or set GVISOR_READELF." >&2
        return 1
    }
    header=$("$readelf_tool" -h "$binary" 2>&1) || {
        echo "readelf could not inspect $binary:" >&2
        printf '%s\n' "$header" >&2
        return 1
    }
    program=$("$readelf_tool" -l "$binary" 2>&1) || {
        echo "readelf could not inspect program headers for $binary:" >&2
        printf '%s\n' "$program" >&2
        return 1
    }
    dynamic=$("$readelf_tool" -d "$binary" 2>&1) || {
        echo "readelf could not inspect the dynamic section for $binary:" >&2
        printf '%s\n' "$dynamic" >&2
        return 1
    }

    printf '%s\n' "$header" | grep -Eq 'Class:[[:space:]]+ELF64' || {
        echo "$binary is not an ELF64 artifact." >&2
        return 1
    }
    printf '%s\n' "$header" | grep -Eq 'Machine:[[:space:]]+AArch64' || {
        echo "$binary is not an AArch64 artifact." >&2
        return 1
    }
    printf '%s\n' "$header" | grep -Eq 'Type:[[:space:]]+(EXEC|DYN)' || {
        echo "$binary is not a runnable ELF executable or static PIE." >&2
        return 1
    }
    printf '%s\n' "$program" | grep -Eq '(^|[[:space:]])LOAD([[:space:]]|$)' || {
        echo "$binary has no loadable program segment." >&2
        return 1
    }
    if printf '%s\n' "$program" | grep -Eq '(^|[[:space:]])INTERP([[:space:]]|$)|Requesting program interpreter'; then
        echo "$binary requests PT_INTERP; rebuild with BAZEL_OPTIONS='--config=aarch64 -c opt --linkopt=-static'." >&2
        return 1
    fi
    if printf '%s\n' "$dynamic" | grep -q '(NEEDED)'; then
        echo "$binary has DT_NEEDED dependencies; rebuild the static payload." >&2
        return 1
    fi
}
