#!/usr/bin/env bash
# End-to-end smoke for the default run path: pull, sparsebundle, COW clone, HVF
# guest boot. Needs macOS with Hypervisor.framework and network for the pull.
#
# Usage: ELFUSE_OCI_STORE=<store dir> scripts/ci/oci-run-smoke.sh
# shellcheck source=scripts/ci/oci-lib.sh
. "$(dirname "$0")/oci-lib.sh"
require_bin
require_store

run_capture 'guest said' elfuse-oci-ci-ok \
    "$BIN" run alpine:3 /bin/echo elfuse-oci-ci-ok

# The guest's exit status must propagate through the runner untouched; cleanup
# errors must never win over it.
code=0
"$BIN" run alpine:3 /bin/sh -c 'exit 7' || code=$?
[ "$code" -eq 7 ] || fail "guest exit status: got $code, want 7"

# debian:stable-slim, not alpine: the sysroot resolver falls back to the host
# for absent absolute paths, and alpine ships gzip only at /bin/gzip while its
# PATH tries /usr/bin first, where the macOS host holds a Mach-O gzip. Debian is
# usr-merged.
want=5af7b95208fdcff454bab3f5eddf567a688a3796c703d4fef91072e38645c062
got="$("$BIN" run debian:stable-slim /bin/sh -c 'set -e
  seq 1 200000 > /tmp/data.txt
  gzip -c /tmp/data.txt > /tmp/data.gz
  gunzip -c /tmp/data.gz | cmp - /tmp/data.txt
  sha256sum /tmp/data.txt | cut -d" " -f1')"
printf 'debian pipeline sha256: %s\n' "$got"
[ "$got" = "$want" ] || fail "debian pipeline sha256: got $got, want $want"

# Per-run COW clone isolation: the previous run's /tmp writes must not be
# visible to a fresh run of the same digest. Exact match: a diagnostic quoting
# the failed command would also contain the token.
out="$("$BIN" run debian:stable-slim /bin/sh -c 'test ! -e /tmp/data.txt && echo isolated-ok')"
[ "$out" = isolated-ok ] || fail "isolation check said '$out'"

# No cache prune here: oci-exec-checks.sh runs next in the same CI job on the
# same warm store and re-uses the unpacked trees; it prunes when it is done.
echo "run smoke OK"
