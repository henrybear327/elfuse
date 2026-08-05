# shellcheck shell=sh
# Redis image workload driver, run in a second guest via `/bin/sh -c` while
# the first guest runs redis-server in the foreground. elfuse forwards socket
# syscalls to host sockets and does no netns isolation, so 127.0.0.1 here is
# the same loopback the server bound; the target port arrives as $1. BGSAVE
# is the point of this lane: it forks the server and snapshots the dataset
# copy-on-write, the path redis's ARM64 safety check reads /proc/self/smaps
# to vet, so a regression there turns the BGSAVE stanza red.
# Prints one sentinel token on success. POSIX sh (busybox ash).
set -e
port="$1"

r() {
    redis-cli -h 127.0.0.1 -p "$port" "$@"
}

# Every reply is string-compared: redis-cli exits 0 even when the server
# answers with an (error) reply, so exit status alone asserts nothing.
out=$(r PING)
if [ "$out" != PONG ]; then
    echo "PING returned '$out'" >&2
    exit 1
fi

out=$(r SET elfuse:workload elfuse-redis-value)
if [ "$out" != OK ]; then
    echo "SET returned '$out'" >&2
    exit 1
fi

out=$(r GET elfuse:workload)
if [ "$out" != elfuse-redis-value ]; then
    echo "GET returned '$out'" >&2
    exit 1
fi

# The reply pins that the fork itself happened; completion and the child's
# fate are only visible through INFO persistence. rdb_last_bgsave_status
# reads "ok" from boot, so checking it without this reply would pass with
# no save ever run.
out=$(r BGSAVE)
if [ "$out" != "Background saving started" ]; then
    echo "BGSAVE returned '$out'" >&2
    exit 1
fi

# INFO lines end in \r\n, so substring greps only, never full-line matches.
i=0
while [ "$i" -lt 30 ]; do
    if r INFO persistence | grep -q 'rdb_bgsave_in_progress:0'; then
        break
    fi
    sleep 1
    i=$((i + 1))
done

# Re-assert completion outside the loop: falling out on timeout with the
# save still in flight must not reach the status check, whose boot-time
# default would read as a pass.
if ! r INFO persistence | grep -q 'rdb_bgsave_in_progress:0'; then
    r INFO persistence >&2
    echo "BGSAVE still in progress after 30s" >&2
    exit 1
fi
if ! r INFO persistence | grep -q 'rdb_last_bgsave_status:ok'; then
    r INFO persistence >&2
    echo "BGSAVE did not finish with status ok" >&2
    exit 1
fi

echo "elfuse-oci-redis-workload-ok"

# Sentinel first, shutdown last: the server closes the connection while
# acknowledging SHUTDOWN, so redis-cli's status is noise here; the host
# asserts the server's own exit code instead.
r SHUTDOWN NOSAVE || true
