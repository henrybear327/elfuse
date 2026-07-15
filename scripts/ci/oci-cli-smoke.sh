#!/usr/bin/env bash
# Store-level CLI lifecycle smoke: everything short of `run` (which needs
# HVF), driving the built binary through the same user-facing flow the Go
# unit tests model in-process: pull, inspect, list, rmi by ref and by
# unique digest prefix, stale-temp-blob GC, and orphan-blob prune.
#
# With --unpack it also unpacks a rootfs and checks that a plain rmi
# reclaims the cold cache (the Linux CI job). Without it, every rmi runs
# the deliberate cache-free path where nothing was ever unpacked and no
# --force is involved (the hosted-macOS CI job, whose runners lack HVF but
# exercise the darwin binary). Needs jq and network.
#
# Usage: scripts/ci/oci-cli-smoke.sh [--unpack]
# shellcheck source=scripts/ci/oci-lib.sh
. "$(dirname "$0")/oci-lib.sh"
require_bin
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 2; }

UNPACK=0
case "${1:-}" in
--unpack) UNPACK=1 ;;
'') ;;
*)
    echo "usage: $0 [--unpack]" >&2
    exit 2
    ;;
esac

STORE="$(mktemp -d)"
# Clean up on every exit path; a failing phase must not leak a populated
# blob store into the runner's temp dir.
trap 'rm -rf "$STORE"' EXIT
REF=alpine:3

phase_pull_inspect_list() {
    "$BIN" version
    "$BIN" pull --store "$STORE" "$REF"
    "$BIN" inspect --store "$STORE" --json "$REF" \
        | jq -e '(.os == "linux") and (.architecture == "arm64")' >/dev/null
    "$BIN" list --store "$STORE" | expect_grep "$REF"
}

# A cold unpacked cache is derived state: a plain `rmi` reclaims it as part
# of removing the image, no --force needed. --force is only for a
# `run --keep` cache (retained output) or a live run's volume, neither of
# which a bare `unpack` produces. See TestRmiDropsColdCacheWithoutForce in
# cmd/elfuse-oci/lifecycle_test.go.
phase_unpack_rmi() {
    local digest cache refs
    "$BIN" unpack --store "$STORE" "$REF"
    digest="$("$BIN" images --store "$STORE" --json | jq -er '.[0].digest')"
    cache="$STORE/rootfs/sha256/${digest#sha256:}"
    test -e "$cache/bin/sh" || fail "unpacked rootfs has no /bin/sh"

    must_report 'dropped unpacked cache' 'plain rmi of an unpacked cache' \
        "$BIN" rmi --store "$STORE" "$REF"
    test ! -e "$cache" || fail "unpacked cache survived a plain rmi"
    refs="$("$BIN" list --store "$STORE")"
    [ -z "$refs" ] || fail "list not empty after rmi"

    # Restore the pulled image for the digest-rmi phase below.
    "$BIN" pull --store "$STORE" "$REF"
}

# rmi resolves a unique digest prefix from the list table, and its GC also
# sweeps an aborted download's temp blob (digest name plus random suffix),
# which is unreachable by digest.
phase_digest_rmi_stale_blob() {
    local digest layer_hex stale table short refs
    digest="$("$BIN" images --store "$STORE" --json | jq -er '.[0].digest')"
    layer_hex="$(jq -er '.layers[0].digest' \
        "$STORE/blobs/sha256/${digest#sha256:}" | sed 's/^sha256://')"
    stale="$STORE/blobs/sha256/${layer_hex}1072211852"
    printf 'stale temp blob' >"$stale"

    table="$("$BIN" list --store "$STORE")"
    printf '%s\n' "$table"
    short="$(printf '%s\n' "$table" | awk 'NR == 2 {print $2}')"
    test -n "$short" || fail "list table has no digest column to resolve"
    "$BIN" rmi --store "$STORE" "$short"
    test ! -e "$stale" || fail "stale temp blob survived the rmi GC"
    refs="$("$BIN" list --store "$STORE")"
    [ -z "$refs" ] || fail "list not empty after digest rmi"
}

# prune's reachability GC reclaims orphan blobs whether or not their name
# parses as a digest.
phase_orphan_prune() {
    local valid malformed
    valid="$(printf 'ci-prune-orphan' | sha256_hex)"
    malformed="$STORE/blobs/sha256/${valid}9999"
    printf 'orphan blob' >"$STORE/blobs/sha256/$valid"
    printf 'malformed orphan blob' >"$malformed"
    "$BIN" prune --store "$STORE"
    test ! -e "$STORE/blobs/sha256/$valid" || fail "orphan blob survived prune"
    test ! -e "$malformed" || fail "malformed orphan blob survived prune"
    "$BIN" prune --store "$STORE" --cache
}

phase_pull_inspect_list
if [ "$UNPACK" = 1 ]; then
    phase_unpack_rmi
fi
phase_digest_rmi_stale_blob
phase_orphan_prune
assert_store_empty "$STORE"

echo "cli smoke OK (unpack=$UNPACK)"
