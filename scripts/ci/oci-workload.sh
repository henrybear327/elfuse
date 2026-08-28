#!/usr/bin/env bash
# Per-image real-workload smoke through elfuse-oci run under HVF, asserting a
# sentinel token. CI cleans ELFUSE_OCI_STORE before every leg, so each run
# pulls.
#
# Usage: ELFUSE_OCI_STORE=<store> scripts/ci/oci-workload.sh <key>
# shellcheck source=scripts/ci/oci-lib.sh
. "$(dirname "$0")/oci-lib.sh"

# Adding an image is a case arm below plus its workload file and the CI matrix
# entry in build.yml. The key list is named once so the usage and unknown-key
# messages cannot drift from the case arms.
KEYS='python|node|go|jvm|c|redis'
key="${1:?usage: oci-workload.sh <$KEYS>}"

require_bin
require_store

WL="$OCI_CI_DIR/workloads"

# Guest workloads run from self-created /tmp scratch dirs: every workload image
# ships /tmp, so it resolves inside the rootfs and the scratch churn stays
# inside the ephemeral clone.

guest=""
srv_outfile=""
on_exit()
{
    rc=$?
    reap_guest
    dump_evidence "$rc" "$srv_outfile" "server guest output"
    [ -n "$srv_outfile" ] && rm -f "$srv_outfile"
    exit "$rc"
}
trap on_exit EXIT

run_node()
{
    run_capture node-compute elfuse-oci-node-compute-ok \
        "$BIN" run --entrypoint /usr/local/bin/node node:22-alpine \
        -e "$(cat "$WL/node-compute.js")"

    local reqs=100

    start_server_guest '^PORT=' "node server" \
        "$BIN" run --entrypoint /usr/local/bin/node node:22-alpine \
        -e "$(cat "$WL/node-server.js")"
    local port
    port="$(awk -F= '/^PORT=/{print $2; exit}' "$srv_outfile")"

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

    # /quit makes the guest exit 0; the connection may reset as it exits, so
    # tolerate the curl status.
    curl -fsS -o /dev/null "http://127.0.0.1:$port/quit" || true
    await_server_exit "node server after /quit"
}

run_redis()
{
    # redis-server runs foreground, driven by a second redis-cli guest: an
    # in-guest daemon risks the backgrounded-fork wait livelock. A missing nc
    # would read as a free port first and a server timeout later; exit 2 marks
    # the missing prerequisite.
    command -v nc > /dev/null 2>&1 \
        || {
            echo "nc is required for the redis lane" >&2
            exit 2
        }

    # redis cannot announce an ephemeral port (--port 0 disables TCP), so the
    # host picks one below the OS ephemeral range, where another lane's port-0
    # bind cannot land. The probe-to-bind window stays unguarded; losing that
    # race surfaces as the exited-early dump below.
    local port="" try=0
    while [ "$try" -lt 10 ]; do
        port=$((20000 + RANDOM % 20000))
        if ! nc -z 127.0.0.1 "$port" 2> /dev/null; then
            break
        fi
        port=""
        try=$((try + 1))
    done
    [ -n "$port" ] || fail "no free loopback port for redis after 10 probes"

    # --entrypoint skips the image's docker-entrypoint.sh; --save '' disables
    # periodic snapshots so the only fork is the BGSAVE the driver issues; --dir
    # /data names a path present in the rootfs.
    start_server_guest 'Ready to accept connections' "redis server" \
        "$BIN" run --entrypoint /usr/local/bin/redis-server redis:7-alpine \
        --bind 127.0.0.1 --port "$port" --save '' --dir /data

    # Same stdout-flush caveat as the node lane: probe before booting the driver
    # guest.
    wait_for 30 "redis server on 127.0.0.1:$port" nc -z 127.0.0.1 "$port"
    printf 'redis server on 127.0.0.1:%s\n' "$port"

    # One driver guest runs the whole PING/SET/GET/BGSAVE sequence. The port
    # rides in as $1 so the script text stays fixed.
    run_capture redis-driver elfuse-oci-redis-workload-ok \
        "$BIN" run --entrypoint /bin/sh redis:7-alpine \
        -c "$(cat "$WL/redis-driver.sh")" sh "$port"

    # The driver ends with SHUTDOWN NOSAVE; redis exits 0 on it.
    await_server_exit "redis server after SHUTDOWN"
}

case "$key" in
    python)
        run_capture python elfuse-oci-python-workload-ok \
            "$BIN" run --entrypoint /usr/local/bin/python3 python:3.12-slim \
            -c "$(cat "$WL/python-workload.py")"
        ;;
    node) run_node ;;
    redis) run_redis ;;
    go)
        run_capture go elfuse-oci-go-workload-ok \
            "$BIN" run golang:1.23-alpine /bin/sh -c "$(cat "$WL/go-workload.sh")"
        ;;
    jvm)
        run_capture jvm elfuse-oci-jvm-workload-ok \
            "$BIN" run eclipse-temurin:21 /bin/sh -c "$(cat "$WL/jvm-workload.sh")"
        ;;
    c)
        run_capture c elfuse-oci-c-workload-ok \
            "$BIN" run gcc:14 /bin/sh -c "$(cat "$WL/c-workload.sh")"
        ;;
    *) fail "unknown workload key: $key (want $KEYS)" ;;
esac

prune_store_cache

echo "workload $key OK"
