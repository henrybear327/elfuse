#!/usr/bin/env bash
# Build the pinned gVisor syscall GoogleTest binaries from scratch.
#
# What this script does, in order:
#   1. Resolve the output directory, the gVisor checkout, and whether Bazel
#      runs inside Docker (the default) or natively (Linux CI passes
#      GVISOR_DOCKER_BUILD=false).
#   2. Clone google/gvisor when needed and check out the pinned commit,
#      refusing to disturb a dirty checkout and re-verifying that HEAD
#      resolved to the pin.
#   3. On macOS, put GNU findutils ahead on PATH because gVisor's build
#      pipeline ends in host-side xargs stages that assume GNU semantics.
#   4. Build each target one at a time through gVisor's supported Bazel make
#      wrapper as a fully static AArch64 ELF: "make copy" on Linux, "make
#      build" plus docker cp extraction on macOS (where the Bazel cache must
#      live in a Docker volume, so the host never sees the outputs).
#   5. Validate every artifact with readelf (ELF64, AArch64, a loadable
#      segment, no PT_INTERP, no DT_NEEDED) and install the verified set into
#      the destination directory.
#
# The pin, the target list, and the readelf/validation helpers come from
# tests/lib/gvisor-common.sh. Behavior is tuned through these environment
# overrides: GVISOR_TESTS_DIR (output dir), GVISOR_CHECKOUT (source tree),
# GVISOR_REPOSITORY (clone URL), GVISOR_DOCKER_BUILD (true/false), and
# GVISOR_READELF (validation tool).
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=tests/lib/gvisor-common.sh
. "$ROOT/tests/lib/gvisor-common.sh"

destination=${1:-${GVISOR_TESTS_DIR:-$ROOT/build/gvisor-tests}}
checkout=${GVISOR_CHECKOUT:-$ROOT/externals/gvisor/$GVISOR_PIN}
repository=${GVISOR_REPOSITORY:-https://github.com/google/gvisor.git}
# gVisor's Bazel wrapper runs inside Docker by default; Linux hosts with a
# native Bazel (CI) set GVISOR_DOCKER_BUILD=false instead.
docker_build=${GVISOR_DOCKER_BUILD:-true}
build_destination=

cleanup()
{
    if [ -n "$build_destination" ]; then
        rm -rf "$build_destination"
    fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

case "$destination" in
    /*) ;;
    *) destination="$ROOT/$destination" ;;
esac
case "$checkout" in
    /*) ;;
    *) checkout="$ROOT/$checkout" ;;
esac
case "$docker_build" in
    true | false) ;;
    *)
        echo "GVISOR_DOCKER_BUILD must be true or false: $docker_build" >&2
        exit 2
        ;;
esac

command -v git > /dev/null 2>&1 || {
    echo "git is required to obtain the pinned gVisor checkout." >&2
    exit 2
}

if [ ! -e "$checkout/.git" ]; then
    if [ -e "$checkout" ]; then
        echo "GVISOR_CHECKOUT exists but is not a Git checkout: $checkout" >&2
        exit 2
    fi
    mkdir -p "$(dirname "$checkout")"
    echo "Cloning gVisor into $checkout (explicit opt-in network operation)"
    git clone --filter=blob:none "$repository" "$checkout"
fi

if [ -n "$(git -C "$checkout" status --porcelain)" ]; then
    echo "Refusing to alter dirty gVisor checkout: $checkout" >&2
    echo "Use a clean dedicated GVISOR_CHECKOUT for pin $GVISOR_PIN." >&2
    exit 2
fi

if ! git -C "$checkout" cat-file -e "$GVISOR_PIN^{commit}" 2> /dev/null; then
    echo "Fetching pinned gVisor commit $GVISOR_PIN"
    git -C "$checkout" fetch origin "$GVISOR_PIN"
fi
git -C "$checkout" checkout --detach "$GVISOR_PIN"
actual=$(git -C "$checkout" rev-parse HEAD)
[ "$actual" = "$GVISOR_PIN" ] || {
    echo "gVisor checkout resolved to $actual, expected $GVISOR_PIN" >&2
    exit 2
}

# gVisor's build_paths pipeline finishes with host-side xargs stages that
# assume GNU semantics; BSD xargs caps -I replacements at 255 bytes, far
# below the resolved Bazel cache paths. macOS additionally must keep the
# Bazel cache in a Docker volume (a bind-mounted cache breaks Bazel's
# linux-sandbox on virtiofs), so the host never sees the built artifacts
# and they are extracted from the build container with docker cp instead.
if [ "$(uname -s)" = Darwin ]; then
    gnubin=/opt/homebrew/opt/findutils/libexec/gnubin
    if [ -d "$gnubin" ]; then
        PATH="$gnubin:$PATH"
        export PATH
    fi
    if ! xargs --version 2> /dev/null | grep -q GNU; then
        echo "GNU xargs is required for gVisor's build pipeline on macOS." >&2
        echo "Install it with: brew install findutils" >&2
        exit 2
    fi
fi

# Mirrors the HASH computation in gVisor's tools/bazel.mk so the container
# started by make can be addressed for artifact extraction.
gvisor_container_name()
{
    local hash8

    hash8=$(python3 "$checkout/tools/compat/realpath.py" "$checkout" | {
        if command -v md5sum > /dev/null 2>&1; then
            md5sum
        else
            md5
        fi
    } | cut -c1-8) || return 1
    printf 'gvisor-bazel-%s-%s\n' "$hash8" "$(uname -m)"
}

mkdir -p "$(dirname "$destination")"
build_destination=$(mktemp -d "${TMPDIR:-/tmp}/gvisor-tests.XXXXXX")
echo "Building pinned gVisor syscall tests into $destination"
# The build and copy targets resolve TARGETS through one Bazel cquery
# expression, so they accept exactly one label per invocation.
for target in $GVISOR_TEST_TARGETS; do
    if [ "$(uname -s)" = Darwin ]; then
        make -C "$checkout" build \
            DOCKER_BUILD="$docker_build" \
            BAZEL_OPTIONS='--config=aarch64 -c opt --linkopt=-static --linkopt=-Wl,--eh-frame-hdr' \
            TARGETS="$target"
    else
        make -C "$checkout" copy \
            DOCKER_BUILD="$docker_build" \
            BAZEL_OPTIONS='--config=aarch64 -c opt --linkopt=-static --linkopt=-Wl,--eh-frame-hdr' \
            TARGETS="$target" \
            DESTINATION="$build_destination"
    fi
done

if [ "$(uname -s)" = Darwin ]; then
    container=$(gvisor_container_name) || {
        echo "Could not derive the gVisor build container name." >&2
        exit 2
    }
    if ! docker inspect "$container" > /dev/null 2>&1; then
        echo "gVisor build container is not available: $container" >&2
        exit 2
    fi
    # The output-config directory (aarch64-opt) is derived by Bazel from the
    # build flags; glob it so a mnemonic change on a pin bump does not silently
    # break extraction. The single-match check below catches any ambiguity.
    cache_glob="\$HOME/.cache/bazel/_bazel_\$(whoami)/*/execroot/*/bazel-out/*/bin/test/syscalls/linux"
    for name in "${GVISOR_TEST_BINARIES[@]}"; do
        artifact=$(docker exec "$container" sh -c "ls -1 ${cache_glob}/${name}") || {
            echo "Could not locate ${name} inside ${container}." >&2
            exit 2
        }
        if [ "$(printf '%s\n' "$artifact" | wc -l)" -ne 1 ]; then
            echo "Ambiguous Bazel outputs for ${name}:" >&2
            printf '%s\n' "$artifact" >&2
            exit 2
        fi
        docker cp "${container}:${artifact}" "${build_destination}/${name}"
    done
fi

for name in "${GVISOR_TEST_BINARIES[@]}"; do
    binary="$build_destination/$name"
    if [ ! -f "$binary" ]; then
        echo "Expected gVisor make copy artifact was not produced: $binary" >&2
        echo "Inspect the Bazel output above; do not substitute a *_native launcher." >&2
        exit 2
    fi
    chmod +x "$binary"
    gvisor_validate_static_aarch64 "$binary"
    echo "Validated $name (ELF64 AArch64, no PT_INTERP or DT_NEEDED)"
done

mkdir -p "$destination"
for name in "${GVISOR_TEST_BINARIES[@]}"; do
    cp -f "$build_destination/$name" "$destination/$name"
    chmod +x "$destination/$name"
done
echo "Installed verified artifacts in $destination"
