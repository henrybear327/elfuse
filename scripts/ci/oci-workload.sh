#!/usr/bin/env bash
# Per-image real-workload smoke: drive each image's characteristic operations
# (issue #224) through `elfuse-oci run` under HVF and assert a sentinel token.
# One key per image. `run` pulls on demand, so a warm persistent
# ELFUSE_OCI_STORE keeps reruns network-free.
#
# Usage: ELFUSE_OCI_STORE=<store> scripts/ci/oci-workload.sh <python|node|go|jvm|c>
# shellcheck source=scripts/ci/oci-lib.sh
. "$(dirname "$0")/oci-lib.sh"
require_bin
: "${ELFUSE_OCI_STORE:?set ELFUSE_OCI_STORE to the store directory to use}"
export ELFUSE_OCI_STORE

key="${1:?usage: oci-workload.sh <python|node|go|jvm|c>}"
WL="$OCI_CI_DIR/workloads"

# assert_sentinel SENTINEL DESC OUTPUT: OUTPUT must contain the fixed SENTINEL.
assert_sentinel() {
    printf '%s\n' "$3" | expect_grep "$1" \
        || fail "$2: output missing sentinel '$1'"
}

# run_capture SENTINEL DESC RUN-ARGS...: run a single-shot guest workload,
# echo its output for the log, and assert the sentinel. Covers every image
# whose workload is one `run` invocation (all but node's two-phase server).
run_capture() {
    local sentinel="$1" desc="$2"
    shift 2
    local out
    out="$("$BIN" run "$@")"
    printf '%s\n' "$out"
    assert_sentinel "$sentinel" "$desc" "$out"
}

# Background guest bookkeeping for the node server phase; reap_guest (in
# oci-lib.sh) keeps a failed assertion from leaking the guest.
guest=""
node_outfile=""
on_exit() {
    rc=$?
    reap_guest
    [ -n "$node_outfile" ] && rm -f "$node_outfile"
    exit "$rc"
}
trap on_exit EXIT

# guest_gone succeeds once the backgrounded guest has exited.
guest_gone() {
    ! kill -0 "$guest" 2>/dev/null
}

run_node() {
    # Phase A: in-guest compute.
    run_capture elfuse-oci-node-compute-ok node-compute \
        --entrypoint /usr/local/bin/node node:22-alpine \
        -e "$(cat "$WL/node-compute.js")"

    # Phase B: HTTP server reached over the host loopback. elfuse forwards
    # socket syscalls to host sockets and does no netns isolation, so a guest
    # bound to 127.0.0.1 is reachable from the host. The server binds an
    # ephemeral port and prints "PORT=<n>"; read it back rather than fixing a
    # port that could collide with a leaked or concurrent guest.
    local reqs="${WL_NODE_REQUESTS:-100}"
    node_outfile="$(mktemp)"
    "$BIN" run --entrypoint /usr/local/bin/node node:22-alpine \
        -e "$(cat "$WL/node-server.js")" >"$node_outfile" 2>&1 &
    guest=$!

    # Wait for the server to announce its ephemeral port. Poll rather than
    # wait_for so a guest that dies (a bind failure or a runtime crash) surfaces
    # its own captured output instead of an opaque timeout.
    local waited=0 port=""
    while [ "$waited" -lt 120 ]; do
        port="$(awk -F= '/^PORT=/{print $2; exit}' "$node_outfile")"
        [ -n "$port" ] && break
        if ! kill -0 "$guest" 2>/dev/null; then
            cat "$node_outfile" >&2
            guest=""
            fail "node server exited before announcing a port"
        fi
        sleep 0.5
        waited=$((waited + 1))
    done
    if [ -z "$port" ]; then
        cat "$node_outfile" >&2
        fail "node server did not announce a port within 60s"
    fi
    # The PORT= line is the guest flushing stdout, not proof the socket accepts
    # connections yet; probe the port directly before hammering it.
    wait_for 30 "node server on 127.0.0.1:$port" \
        curl -fsS -o /dev/null "http://127.0.0.1:$port/"
    printf 'node server on 127.0.0.1:%s\n' "$port"

    local i=0 body
    while [ "$i" -lt "$reqs" ]; do
        # Guard the substitution: a bare body=$(curl ...) would trip the ERR
        # trap on any transient failure instead of the specific diagnostic.
        if ! body="$(curl -fsS "http://127.0.0.1:$port/")"; then
            fail "node server request $i failed (curl)"
        fi
        [ "$body" = elfuse-node-server-ok ] \
            || fail "node server request $i returned '$body'"
        i=$((i + 1))
    done
    printf 'node server answered %d requests\n' "$reqs"

    # Clean shutdown: /quit makes the guest exit 0. The connection may reset as
    # the guest exits, so tolerate the curl status. If /quit never reaches the
    # server the guest would run forever, so bound the wait; on timeout
    # wait_for fails and the EXIT trap kills the guest rather than blocking
    # to the job's timeout-minutes.
    curl -fsS -o /dev/null "http://127.0.0.1:$port/quit" || true
    wait_for 10 "node server exit after /quit" guest_gone
    if ! wait "$guest"; then
        guest=""
        fail "node server exited non-zero after /quit"
    fi
    guest=""
}

case "$key" in
    python)
        run_capture elfuse-oci-python-workload-ok python \
            --entrypoint /usr/local/bin/python3 python:3.12-slim \
            -c "$(cat "$WL/python-workload.py")"
        ;;
    node) run_node ;;
    go)
        run_capture elfuse-oci-go-workload-ok go \
            golang:1.23-alpine /bin/sh -c "$(cat "$WL/go-workload.sh")"
        ;;
    jvm)
        run_capture elfuse-oci-jvm-workload-ok jvm \
            eclipse-temurin:21 /bin/sh -c "$(cat "$WL/jvm-workload.sh")"
        ;;
    c)
        run_capture elfuse-oci-c-workload-ok c \
            gcc:14 /bin/sh -c "$(cat "$WL/c-workload.sh")"
        ;;
    *) fail "unknown workload key: $key (want python|node|go|jvm|c)" ;;
esac

# Keep a persistent store bounded: GC blobs stranded when a pinned tag moves.
"$BIN" prune >/dev/null

echo "workload $key OK"
