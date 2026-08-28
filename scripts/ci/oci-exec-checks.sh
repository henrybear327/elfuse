#!/usr/bin/env bash
# Execution checks beyond oci-run-smoke.sh: pathname AF_UNIX sockets in the
# guest, cold-provision versus warm re-attach, and dynamic-interpreter
# resolution from the image. Needs macOS with HVF and network for the pull.
#
# Usage: ELFUSE_OCI_STORE=<store dir> scripts/ci/oci-exec-checks.sh
# shellcheck source=scripts/ci/oci-lib.sh
. "$(dirname "$0")/oci-lib.sh"
require_bin
require_store

# The bound name must read back byte-identical through getsockname: the runtime
# translates sun_path on the way in and must reverse-map it out, and the clone's
# deep host path forces the over-length shortening indirection.
sock_py='
import socket, threading, os
os.makedirs("/srv-sock", exist_ok=True)
path = "/srv-sock/echo.sock"
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.settimeout(30)
srv.bind(path)
assert srv.getsockname() == path, srv.getsockname()
srv.listen(1)
msg = b"elfuse-unix-sock-ok"
# A stream socket has no message boundary, so read to the length.
def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        assert chunk, "peer closed early"
        buf += chunk
    return buf
def serve():
    conn, _ = srv.accept()
    conn.settimeout(30)
    conn.sendall(recv_exact(conn, len(msg)))
    conn.close()
t = threading.Thread(target=serve)
t.start()
cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
cli.settimeout(30)
cli.connect(path)
cli.sendall(msg)
print(recv_exact(cli, len(msg)).decode())
t.join(30)
assert not t.is_alive(), "echo thread hung"
'
run_capture 'unix socket check' elfuse-unix-sock-ok \
    "$BIN" run --entrypoint /usr/local/bin/python3 python:3.12-slim \
    -c "$sock_py"

# Seed a cold store from the warm store's pin table and blobs only (a raw tree
# copy would recurse into a live bundle mount), so the first run must provision
# and unpack offline and the second must re-attach warm.
coldstore="$(mktemp -d)/store"
errf="$(mktemp)"

# dump_evidence before the temp files go, or a red run carries no evidence. The
# runs below leave a bundle volume attached in the cold store, so clean detaches
# it before the tree goes; both steps are guarded so the trap never replaces the
# script's own exit status.
on_exit()
{
    rc=$?
    dump_evidence "$rc" "$errf" "guest stderr"
    "$BIN" clean --store "$coldstore" > /dev/null || true
    rm -rf "$(dirname "$coldstore")" "$errf" || true
    exit "$rc"
}
trap on_exit EXIT
mkdir -p "$coldstore"
cp -Rc "$ELFUSE_OCI_STORE/blobs" "$coldstore/blobs"
cp "$ELFUSE_OCI_STORE/refs.json" "$coldstore/"

out="$(ELFUSE_OCI_STORE=$coldstore "$BIN" run alpine:3 /bin/echo cold-ok \
    2> "$errf")"
printf '%s\n' "$out" | expect_grep cold-ok
grep -q 'Unpacking' "$errf" || fail "cold boot did not report an unpack"

out="$(ELFUSE_OCI_STORE=$coldstore "$BIN" run alpine:3 /bin/echo warm-ok \
    2> "$errf")"
printf '%s\n' "$out" | expect_grep warm-ok
if grep -q 'Unpacking' "$errf"; then
    fail "warm re-attach unpacked again"
fi
echo "cold/warm boot check OK"

# Run a glibc dynamically linked binary from the image explicitly, so PT_INTERP
# and its .so closure must resolve inside the rootfs.
run_capture 'interp check' elfuse-interp-ok \
    "$BIN" run --entrypoint /bin/bash debian:stable-slim -c \
    'echo elfuse-interp-ok'

prune_store_cache

echo "exec checks OK"
