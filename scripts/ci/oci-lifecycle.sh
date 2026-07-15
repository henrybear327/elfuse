#!/usr/bin/env bash
# Whole user-facing image lifecycle against a real HVF-booted guest, then
# the teardown guardrails, one function per phase:
#   run_workloads            pull/inspect/list, an --entrypoint override,
#                            and a glibc dynamically-linked python workload
#   teardown_plain_rmi       a plain rmi reclaims the cold unpacked cache
#                            with the image
#   teardown_keep_guardrails rmi refuses to discard run --keep output
#                            without --force; --force detaches the still-
#                            attached volume and drops the bundle
#   teardown_live_run_lock   a live --plain-rootfs guest pins its cache
#                            against prune --cache --all and rmi until the
#                            guest exits; only this exercises the lock
#                            descriptor's ride through the exec into elfuse
# Needs macOS with Hypervisor.framework and network for the seed pull.
#
# Usage: ELFUSE_OCI_STORE=<ephemeral store> \
#        ELFUSE_OCI_SEED_STORE=<persistent warm store> \
#        [IMG=<ref>] scripts/ci/oci-lifecycle.sh
# shellcheck source=scripts/ci/oci-lib.sh
. "$(dirname "$0")/oci-lib.sh"
require_bin
STORE="${ELFUSE_OCI_STORE:?set ELFUSE_OCI_STORE to an ephemeral store directory}"
SEED="${ELFUSE_OCI_SEED_STORE:?set ELFUSE_OCI_SEED_STORE to the warm seed store directory}"
IMG="${IMG:-python:3.12-slim}"
export ELFUSE_OCI_STORE

guest=""
on_exit() {
    rc=$?
    # A failed phase must not leak the backgrounded guest: it would keep
    # holding the per-digest flock (and its sleep) and poison the next
    # prune/rmi on a persistent self-hosted runner.
    if [ -n "$guest" ] && kill -0 "$guest" 2>/dev/null; then
        kill "$guest" 2>/dev/null || true
        wait "$guest" 2>/dev/null || true
    fi
    exit "$rc"
}
trap on_exit EXIT

# The teardowns leave the ephemeral store EMPTY (asserted), so the
# lifecycle store itself cannot persist between CI runs. Keep a warm seed
# store on the persistent disk instead and clone it in per phase (cp -Rc,
# APFS clonefile, the same trick as the fixture-cache restore): the pull
# in run_workloads then dedups every blob by digest and only the manifest
# HEAD/GET goes out, while the empty-store assertions stay meaningful.
seed_warm_store() {
    ELFUSE_OCI_STORE="$SEED" "$BIN" pull "$IMG"
    # GC blobs stranded in the seed when the tag moves to a new digest.
    ELFUSE_OCI_STORE="$SEED" "$BIN" prune >/dev/null
}

reseed() {
    rm -rf "$STORE"
    cp -Rc "$SEED" "$STORE"
}

run_workloads() {
    "$BIN" version
    "$BIN" pull "$IMG"
    "$BIN" inspect "$IMG" | expect_grep 'linux/arm64'
    "$BIN" list | expect_grep "$IMG"

    local out
    out="$("$BIN" run --entrypoint /usr/local/bin/python3 "$IMG" \
        -c 'import json,math; print(json.dumps({"pi":round(math.pi,5),"ok":True}))')"
    printf 'guest said: %s\n' "$out"
    [ "$out" = '{"pi": 3.14159, "ok": true}' ] || fail "python one-liner said '$out'"

    # A non-trivial application: concurrent SQLite writers (fcntl locking,
    # fsync, WAL where the guest FS supports it) plus a 64-file
    # write/read/checksum fan-out. Exercises far more of the dynamically-
    # linked glibc guest than the one-liner above; prints a single sentinel
    # token only on full success.
    out="$("$BIN" run --entrypoint /usr/local/bin/python3 "$IMG" \
        -c "$(cat "$OCI_CI_DIR/oci-python-workload.py")")"
    printf 'python workload said: %s\n' "$out"
    [ "$out" = elfuse-oci-python-workload-ok ] || fail "python workload said '$out'"
}

# The runs above left the cache warm and then detached on exit, so a plain
# rmi (no --force, no separate prune) must reclaim it with the image.
teardown_plain_rmi() {
    must_report 'dropped unpacked cache' 'plain rmi of a cold cache' \
        "$BIN" rmi "$IMG"
    assert_store_empty "$STORE"
}

# run --keep retains the per-run clone with the volume still attached: rmi
# must refuse without --force, and rmi --force must detach the volume,
# drop the bundle, and GC the blobs.
teardown_keep_guardrails() {
    reseed
    "$BIN" run --keep --entrypoint /usr/local/bin/python3 "$IMG" -c 'pass'
    must_refuse 'retained run --keep output; pass --force' \
        'rmi of run --keep output without --force' \
        "$BIN" rmi "$IMG"
    "$BIN" rmi --force "$IMG"
    assert_store_empty "$STORE"
}

# The published cache is rootfs/sha256/<hex>, renamed into place when the
# unpack completes. Never match the unpacker's .tmp-<random> staging
# sibling: it is mid-write, and prune skips it via the digest lock.
published_plain_cache() {
    # sed, not `head -n1`: head exits at the first line, and under pipefail
    # a find killed by the resulting SIGPIPE would fail the whole pipeline
    # even though a cache was found. sed -n 1p drains its input.
    find "$STORE/rootfs/sha256" -mindepth 1 -maxdepth 1 -type d \
        ! -name '*.tmp-*' 2>/dev/null | sed -n 1p | grep .
}

# A live --plain-rootfs guest must pin its cache against prune --cache
# --all and rmi, and its exit alone (no cleanup code, SIGKILL included)
# must free it: the kernel drops the flock with the process.
teardown_live_run_lock() {
    reseed
    "$BIN" run --plain-rootfs --entrypoint /bin/sleep "$IMG" 60 &
    guest=$!
    # The run takes its per-digest lock before unpacking, so once the
    # cache dir has been published the guest provably holds the lock.
    wait_for 120 'published plain rootfs cache' published_plain_cache
    local plain_cache
    plain_cache="$(published_plain_cache)"

    "$BIN" prune --cache --all
    test -d "$plain_cache" || fail 'prune --cache --all reclaimed a live plain rootfs'
    must_refuse 'in use by a live run' \
        'rmi of an image whose plain rootfs hosts a live run' \
        "$BIN" rmi "$IMG"

    kill "$guest" 2>/dev/null || true
    wait "$guest" || true
    guest=""
    # Guest gone means the kernel released the flock; prune reclaims the
    # cache (lock file included) and the image can finally be removed.
    "$BIN" prune --cache --all
    test ! -e "$plain_cache" || fail 'plain rootfs cache survived prune after guest exit'
    "$BIN" rmi "$IMG"
    assert_store_empty "$STORE"

    # Nothing left to reclaim.
    "$BIN" prune --cache
}

seed_warm_store
reseed
run_workloads
teardown_plain_rmi
teardown_keep_guardrails
teardown_live_run_lock

echo "lifecycle OK"
