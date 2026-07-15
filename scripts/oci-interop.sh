#!/usr/bin/env bash
# OCI image-layout conformance + cross-tool interop for the elfuse-oci store.
#
# Treats the on-disk store as the contract: after `elfuse-oci pull`, the store
# must be a valid OCI image-layout that other tools can read and that agrees
# with registry truth on the manifest digest.
#
# Hard assertions (always available, gate the script):
#   - oci-layout has imageLayoutVersion 1.0.0; index.json is schemaVersion 2
#     with a manifest descriptor matching the pinned digest.
#   - the manifest blob parses and references a config blob + >=1 layer blob,
#     all present under blobs/sha256/.
#   - if `crane` is installed, the store's pinned manifest digest matches
#     registry truth for the selected platform.
#
# Best-effort third-party reads (run when present; fatal on failure so CI can
# promote them once the invocation is confirmed):
#   - skopeo inspect --raw oci:<store>:@<source-index> reads our layout
#   - umoci list --layout <store>             parses our layout
#
# Usage: scripts/oci-interop.sh [STORE_DIR]
# Env:   ELFUSE_OCI_BIN (path to elfuse-oci; default build/elfuse-oci)
#        FIXTURES (space-separated refs; default "alpine:3 busybox")
#        PLAT_OS / PLAT_ARCH (platform to pull and compare; default linux/arm64)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN="${ELFUSE_OCI_BIN:-$ROOT/build/elfuse-oci}"

# A store passed as $1 belongs to the caller; an auto-created one is ours to
# reclaim, including on a mid-run failure.
if [ -n "${1:-}" ]; then
    STORE="$1"
    STORE_OWNED=0
else
    STORE="$(mktemp -d -t elfuse-interop.XXXXXX)"
    STORE_OWNED=1
fi
# Absolutize the store path: the skopeo view symlinks blobs -> "$STORE/blobs",
# a target resolved relative to the (separate) view dir, so a relative store arg
# would dangle. skopeo/umoci oci: transports also want an absolute layout path.
case "$STORE" in
    /*) ;;
    *) STORE="$(pwd)/$STORE" ;;
esac

# Temp files/dirs created per fixture. An EXIT trap reclaims them plus the
# auto-created store, so a failure (set -e) or fail() no longer orphans the
# store's pulled blobs or the per-iteration scratch. Bash 3.2 (macOS) errors on
# "${arr[@]}" for an empty array under set -u, so guard on length.
TMPFILES=()
cleanup() {
    if [ "${#TMPFILES[@]}" -gt 0 ]; then
        rm -rf "${TMPFILES[@]}"
    fi
    if [ "$STORE_OWNED" = 1 ]; then
        rm -rf "$STORE"
    fi
    return 0
}
trap cleanup EXIT

FIXTURES="${FIXTURES:-alpine:3 busybox}"
# One platform drives BOTH the pull and the registry-truth comparison; setting
# it only on the crane side would fail the comparison against a correctly
# pulled default-platform image.
PLAT_OS="${PLAT_OS:-linux}"
PLAT_ARCH="${PLAT_ARCH:-arm64}"

have() { command -v "$1" >/dev/null 2>&1; }

if [ ! -x "$BIN" ]; then
    echo "elfuse-oci not found at $BIN (set ELFUSE_OCI_BIN or run 'make build/elfuse-oci')" >&2
    exit 2
fi
have jq || { echo "jq is required" >&2; exit 2; }

echo "store: $STORE"
echo "bin:   $BIN"
mkdir -p "$STORE"

# Hard failures exit directly via `fail`.
fail() { echo "FAIL: $*" >&2; exit 1; }

for ref in $FIXTURES; do
    echo
    echo "=== $ref ==="

    # Pull into the store.
    "$BIN" pull --store "$STORE" --platform "$PLAT_OS/$PLAT_ARCH" "$ref" >/dev/null
    digest="$(jq -er --arg ref "$ref" '.[$ref]' "$STORE/refs.json" \
        || fail "refs.json has no pin for $ref")"
    echo "pinned manifest digest: $digest"

    # --- Conformance: oci-layout ---
    [ "$(jq -r .imageLayoutVersion "$STORE/oci-layout")" = "1.0.0" ] \
        || fail "oci-layout imageLayoutVersion != 1.0.0"

    # --- Conformance: index.json has our manifest descriptor ---
    [ "$(jq -r .schemaVersion "$STORE/index.json")" = "2" ] \
        || fail "index.json schemaVersion != 2"
    jq -e --arg d "$digest" 'any(.manifests[]; .digest == $d)' \
        "$STORE/index.json" >/dev/null \
        || fail "index.json has no manifest descriptor with digest $digest"

    # --- Conformance: manifest blob parses and references config + layers ---
    hex="${digest#sha256:}"
    manifest_path="$STORE/blobs/sha256/$hex"
    [ -f "$manifest_path" ] || fail "manifest blob missing at $manifest_path"
    config_digest="$(jq -er .config.digest "$manifest_path" \
        || fail "manifest blob is not a valid image manifest (no .config.digest)")"
    config_hex="${config_digest#sha256:}"
    [ -f "$STORE/blobs/sha256/$config_hex" ] \
        || fail "config blob missing for $config_digest"
    layer_count="$(jq '.layers | length' "$manifest_path")"
    [ "$layer_count" -ge 1 ] || fail "manifest has no layers"
    # Every layer blob must exist on disk.
    while IFS= read -r ld; do
        lx="${ld#sha256:}"
        [ -f "$STORE/blobs/sha256/$lx" ] || fail "layer blob missing for $ld"
    done < <(jq -r '.layers[].digest' "$manifest_path")
    echo "ok: layout valid, $layer_count layer(s), config + manifest + layers present"

    # --- Interop: registry truth via crane (if installed) ---
    # `elfuse-oci pull` uses crane.Pull(WithPlatform), which resolves a manifest
    # list to the per-arch child manifest and pins THAT digest. So for a
    # multi-arch ref, `crane digest` (the list digest) legitimately differs; we
    # resolve the platform child from `crane manifest` and compare that.
    if have crane; then
        plat_os="$PLAT_OS"; plat_arch="$PLAT_ARCH"
        top="$(crane manifest "$ref")"
        if [ "$(printf '%s' "$top" | jq '.manifests // [] | any(.platform != null)')" = "true" ]; then
            # first(...) keeps the comparison single-valued if several entries
            # match the platform (e.g. multiple variants), and the annotation
            # filter drops BuildKit attestation manifests, which are not
            # runnable images. crane.Pull resolves the same first match.
            reg_digest="$(printf '%s' "$top" | jq -er --arg os "$plat_os" --arg ar "$plat_arch" \
                'first(.manifests[]
                   | select(.platform.os==$os and .platform.architecture==$ar
                            and (.annotations["vnd.docker.reference.type"] != "attestation-manifest"))
                   | .digest)' \
                || fail "crane manifest list for $ref has no $plat_os/$plat_arch entry")"
        else
            reg_digest="$(crane digest "$ref")"
        fi
        [ "$reg_digest" = "$digest" ] \
            || fail "crane ($reg_digest) != store pin ($digest) for $ref [$plat_os/$plat_arch]"
        echo "ok: crane agrees on manifest digest ($plat_os/$plat_arch)"
    else
        echo "info: crane not installed; skipping registry-truth comparison"
    fi

    # --- Interop: skopeo reads our layout (if installed) ---
    if have skopeo; then
        # skopeo's oci: transport addresses an image by ref-name annotation or
        # (since skopeo 1.14) by @source-index. Our layout intentionally
        # carries no ref-name annotations, and distro skopeo is often older
        # than 1.14, so neither form is portable. Present a single-manifest
        # view instead (the same oci-layout and blobs, index.json filtered
        # to the pinned descriptor), which every skopeo version resolves
        # with a bare oci:<dir> reference.
        skopeo_view="$(mktemp -d -t elfuse-skopeo-view.XXXXXX)"
        TMPFILES+=("$skopeo_view")
        cp "$STORE/oci-layout" "$skopeo_view/oci-layout"
        jq --arg d "$digest" \
            '.manifests = [.manifests[] | select(.digest == $d)]' \
            "$STORE/index.json" >"$skopeo_view/index.json"
        ln -s "$STORE/blobs" "$skopeo_view/blobs"
        skopeo_ref="oci:$skopeo_view"
        skopeo_raw="$(mktemp -t elfuse-skopeo-raw.XXXXXX)"
        skopeo_err="$(mktemp -t elfuse-skopeo-err.XXXXXX)"
        TMPFILES+=("$skopeo_raw" "$skopeo_err")
        if skopeo inspect --raw "$skopeo_ref" >"$skopeo_raw" 2>"$skopeo_err"; then
            jq -e '(.schemaVersion == 2) and (.config.digest | type == "string") and
                (.layers | type == "array") and (.layers | length >= 1)' \
                "$skopeo_raw" >/dev/null \
                || fail "skopeo read $skopeo_ref but did not return an image manifest"
            echo "ok: skopeo inspect --raw $skopeo_ref read the pinned manifest"
        else
            echo "skopeo stderr: $(cat "$skopeo_err")" >&2
            fail "skopeo could not read $skopeo_ref"
        fi
    else
        echo "info: skopeo not installed; skipping skopeo interop"
    fi

    # --- Interop: umoci parses our layout (if installed) ---
    # The layout is valid even when no descriptors carry ref-name annotations.
    # elfuse keeps refs.json as its own lookup table for full pull references;
    # umoci list may therefore show zero tags, but it must still parse.
    if have umoci; then
        umoci_out="$(mktemp -t elfuse-umoci-list.XXXXXX)"
        umoci_err="$(mktemp -t elfuse-umoci-err.XXXXXX)"
        TMPFILES+=("$umoci_out" "$umoci_err")
        if umoci list --layout "$STORE" >"$umoci_out" 2>"$umoci_err"; then
            echo "ok: umoci list --layout parsed our layout (tags: $(wc -l <"$umoci_out" | tr -d ' '))"
        else
            echo "umoci stderr: $(cat "$umoci_err")" >&2
            fail "umoci could not parse layout $STORE"
        fi
    else
        echo "info: umoci not installed; skipping umoci interop"
    fi
done

echo
echo "ALL OK: store is a valid OCI image-layout and interops with available tools"
# The EXIT trap reclaims the auto-created store and any per-iteration scratch.
