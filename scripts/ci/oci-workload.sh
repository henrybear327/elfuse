#!/usr/bin/env bash
# Per-image real-workload smoke: drive each image's characteristic operations
# through `elfuse-oci run` under HVF and assert a sentinel token.
# One key per image. `run` pulls on demand, so a warm persistent
# ELFUSE_OCI_STORE keeps reruns network-free.
#
# Usage: ELFUSE_OCI_STORE=<store> scripts/ci/oci-workload.sh <python|node|go|jvm|c|redis>
# shellcheck source=scripts/ci/oci-lib.sh
. "$(dirname "$0")/oci-lib.sh"
require_bin
: "${ELFUSE_OCI_STORE:?set ELFUSE_OCI_STORE to the store directory to use}"
export ELFUSE_OCI_STORE

key="${1:?usage: oci-workload.sh <python|node|go|jvm|c|redis>}"
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

# Background guest bookkeeping for the node and redis server phases;
# reap_guest (in oci-lib.sh) keeps a failed assertion from leaking the guest.
guest=""
srv_outfile=""
on_exit() {
    rc=$?
    reap_guest
    # On failure the server's own log often holds the only evidence (a fork
    # error during BGSAVE never reaches the driver guest); a duplicate dump
    # on the paths that already cat it beats a missing one.
    if [ "$rc" -ne 0 ] && [ -s "$srv_outfile" ]; then
        echo "--- server guest output ---" >&2
        cat "$srv_outfile" >&2
    fi
    [ -n "$srv_outfile" ] && rm -f "$srv_outfile"
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
    # Zero would let the request loop pass vacuously; non-numeric already
    # trips the ERR trap at the loop's [ ] comparison.
    case "$reqs" in
    '' | *[!0-9]* | 0) fail "WL_NODE_REQUESTS must be a positive integer, got '$reqs'" ;;
    esac
    srv_outfile="$(mktemp)"
    "$BIN" run --entrypoint /usr/local/bin/node node:22-alpine \
        -e "$(cat "$WL/node-server.js")" >"$srv_outfile" 2>&1 &
    guest=$!

    # Wait for the server to announce its ephemeral port. Poll rather than
    # wait_for so a guest that dies (a bind failure or a runtime crash) surfaces
    # its own captured output instead of an opaque timeout.
    local waited=0 port=""
    while [ "$waited" -lt 120 ]; do
        port="$(awk -F= '/^PORT=/{print $2; exit}' "$srv_outfile")"
        [ -n "$port" ] && break
        if ! kill -0 "$guest" 2>/dev/null; then
            cat "$srv_outfile" >&2
            guest=""
            fail "node server exited before announcing a port"
        fi
        sleep 0.5
        waited=$((waited + 1))
    done
    if [ -z "$port" ]; then
        cat "$srv_outfile" >&2
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

run_redis() {
    # redis-server runs foreground as the guest process and is driven from
    # outside by a second redis-cli guest over the shared host loopback:
    # an in-guest backgrounded daemon risks the backgrounded-fork wait
    # livelock, and per-probe redis-cli guests would pay a boot each.
    # --entrypoint bypasses the image's docker-entrypoint.sh, whose user
    # switching this smoke does not need.
    #
    # redis cannot announce an ephemeral port (--port 0 disables TCP), so the
    # host picks one: probe the shared loopback until a port refuses, in a
    # range below the OS ephemeral allocator so another lane's port-0 bind
    # cannot land on it. The probe-to-bind window stays unguarded; losing
    # that race surfaces as the exited-early dump below.
    local port="" try=0
    while [ "$try" -lt 10 ]; do
        port=$((20000 + RANDOM % 20000))
        if ! nc -z 127.0.0.1 "$port" 2>/dev/null; then
            break
        fi
        port=""
        try=$((try + 1))
    done
    [ -n "$port" ] || fail "no free loopback port for redis after 10 probes"

    # --save '' disables periodic snapshots so the only fork is the BGSAVE
    # the driver issues; --dir /data names a path present in the rootfs.
    srv_outfile="$(mktemp)"
    "$BIN" run --entrypoint /usr/local/bin/redis-server redis:7-alpine \
        --bind 127.0.0.1 --port "$port" --save '' --dir /data \
        >"$srv_outfile" 2>&1 &
    guest=$!

    # Wait for the server's readiness log line. Poll rather than wait_for so
    # a guest that dies (the ARM64 COW safety check aborting because
    # /proc/self/smaps is not synthesized) surfaces its own captured output
    # instead of an opaque timeout.
    local waited=0 ready=""
    while [ "$waited" -lt 120 ]; do
        if grep -F "Ready to accept connections" "$srv_outfile" >/dev/null; then
            ready=1
            break
        fi
        if ! kill -0 "$guest" 2>/dev/null; then
            cat "$srv_outfile" >&2
            guest=""
            fail "redis server exited before reporting readiness"
        fi
        sleep 0.5
        waited=$((waited + 1))
    done
    if [ -z "$ready" ]; then
        cat "$srv_outfile" >&2
        fail "redis server not ready within 60s"
    fi
    # The log line is the guest flushing stdout, not proof the socket accepts
    # connections yet; probe it before booting the driver guest.
    wait_for 30 "redis server on 127.0.0.1:$port" nc -z 127.0.0.1 "$port"
    printf 'redis server on 127.0.0.1:%s\n' "$port"

    # One driver guest runs the whole PING/SET/GET/BGSAVE sequence. The port
    # rides in as $1 so the script text stays fixed.
    run_capture elfuse-oci-redis-workload-ok redis-driver \
        --entrypoint /bin/sh redis:7-alpine \
        -c "$(cat "$WL/redis-driver.sh")" sh "$port"

    # The driver ends with SHUTDOWN NOSAVE; redis exits 0 on it. Bound the
    # wait so a lost shutdown fails here and the EXIT trap reaps the guest
    # instead of idling to the job's timeout-minutes.
    wait_for 10 "redis server exit after SHUTDOWN" guest_gone
    if ! wait "$guest"; then
        guest=""
        fail "redis server exited non-zero after SHUTDOWN"
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
    redis) run_redis ;;
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
    *) fail "unknown workload key: $key (want python|node|go|jvm|c|redis)" ;;
esac

# Keep a persistent store bounded: a moved pin strands the old digest's
# blobs and its unpacked caches; --cache reclaims both (the sparsebundles
# dwarf the blobs). Concurrent legs are safe: the sweep runs under the store
# lock, skips still-pinned digests, and skips busy caches via their flocks.
"$BIN" prune --cache >/dev/null

echo "workload $key OK"
