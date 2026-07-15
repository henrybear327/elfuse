#!/usr/bin/env bash
# End-to-end smoke for the default `run` path: pull an image, provision the
# case-sensitive sparsebundle, COW-clone it, boot the guest under HVF, and
# check output, exit status, and per-run isolation. Needs macOS with
# Hypervisor.framework; network only when the store is cold (pull is
# idempotent per digest, so a warm store skips the blob downloads).
#
# Usage: ELFUSE_OCI_STORE=<store dir> scripts/ci/oci-run-smoke.sh
# shellcheck source=scripts/ci/oci-lib.sh
. "$(dirname "$0")/oci-lib.sh"
require_bin
: "${ELFUSE_OCI_STORE:?set ELFUSE_OCI_STORE to the store directory to use}"

out="$("$BIN" run alpine:3 /bin/echo elfuse-oci-ci-ok)"
printf 'guest said: %s\n' "$out"
printf '%s\n' "$out" | expect_grep elfuse-oci-ci-ok

# The guest's exit status must propagate through the runner untouched;
# cleanup errors must never win over it.
code=0
"$BIN" run alpine:3 /bin/sh -c 'exit 7' || code=$?
[ "$code" -eq 7 ] || fail "guest exit status: got $code, want 7"

# Non-trivial multi-stage shell pipeline: generate a 200k-line file,
# gzip it, decompress and byte-compare the round-trip, then checksum
# the original against a constant precomputed from the exact same
# deterministic input. Exercises fork/exec pipelines, pipes, and
# coreutils gzip/sha256sum in the guest. debian:stable-slim rather
# than alpine because the bare-name PATH search must resolve every
# candidate inside the rootfs: the sysroot resolver falls back to
# the host for absent absolute paths, and alpine ships gzip only at
# /bin/gzip while its PATH tries /usr/bin first, which on a macOS
# host holds an incompatible Mach-O gzip. Debian is usr-merged, so
# each searched binary exists at /usr/bin inside the image.
want=5af7b95208fdcff454bab3f5eddf567a688a3796c703d4fef91072e38645c062
got="$("$BIN" run debian:stable-slim /bin/sh -c 'set -e
  seq 1 200000 > /tmp/data.txt
  gzip -c /tmp/data.txt > /tmp/data.gz
  gunzip -c /tmp/data.gz | cmp - /tmp/data.txt
  sha256sum /tmp/data.txt | cut -d" " -f1')"
printf 'debian pipeline sha256: %s\n' "$got"
[ "$got" = "$want" ] || fail "debian pipeline sha256: got $got, want $want"

# Per-run COW clone isolation: the previous run's /tmp writes must not be
# visible to a fresh run of the same digest. Exact match, not a substring:
# a diagnostic quoting the failed command would also contain the token.
out="$("$BIN" run debian:stable-slim /bin/sh -c 'test ! -e /tmp/data.txt && echo isolated-ok')"
[ "$out" = isolated-ok ] || fail "isolation check said '$out'"

# When a pinned tag moves, the re-pin strands the old digest's blobs; GC
# them so a persistent store stays bounded.
"$BIN" prune >/dev/null

echo "run smoke OK"
