#!/usr/bin/env bash
# Execution checks for the default `run` path beyond oci-run-smoke.sh:
# pathname AF_UNIX sockets inside the guest (bind, getsockname round-trip,
# connect, payload echo), the cold-provision versus warm re-attach boot
# seam, and explicit dynamic-interpreter resolution from the image. Needs
# macOS with Hypervisor.framework; network only when the store is cold.
#
# Usage: ELFUSE_OCI_STORE=<store dir> scripts/ci/oci-exec-checks.sh
# shellcheck source=scripts/ci/oci-lib.sh
. "$(dirname "$0")/oci-lib.sh"
require_bin
: "${ELFUSE_OCI_STORE:?set ELFUSE_OCI_STORE to the store directory to use}"

# Pathname AF_UNIX socket bound inside a guest-created directory. The
# bound name must read back byte-identical through getsockname: under a
# sysroot the runtime translates sun_path on the way in and must
# reverse-map it on the way out, and the sparsebundle clone's deep host
# path forces the over-length shortening indirection as well.
sock_py='
import socket, threading, os
os.makedirs("/srv-sock", exist_ok=True)
path = "/srv-sock/echo.sock"
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(path)
assert srv.getsockname() == path, srv.getsockname()
srv.listen(1)
def serve():
    conn, _ = srv.accept()
    conn.sendall(conn.recv(64))
    conn.close()
t = threading.Thread(target=serve)
t.start()
cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
cli.connect(path)
cli.sendall(b"elfuse-unix-sock-ok")
print(cli.recv(64).decode())
t.join()
'
out="$("$BIN" run --entrypoint /usr/local/bin/python3 python:3.12-slim \
    -c "$sock_py")"
printf 'unix socket check: %s\n' "$out"
printf '%s\n' "$out" | expect_grep elfuse-unix-sock-ok

# Cold-provision versus warm re-attach. Clone the warm store's blobs into
# an ephemeral store but drop the cs/ bundles, so the first run must
# provision the sparsebundle and unpack (network-free cold boot) and the
# second must re-attach the warm base without unpacking again.
coldstore="$(mktemp -d)/store"
errf="$(mktemp)"
trap 'rm -rf "$(dirname "$coldstore")" "$errf"' EXIT
cp -Rc "$ELFUSE_OCI_STORE" "$coldstore"
rm -rf "$coldstore/cs"

out="$(ELFUSE_OCI_STORE=$coldstore "$BIN" run alpine:3 /bin/echo cold-ok \
    2>"$errf")"
printf '%s\n' "$out" | expect_grep cold-ok
grep -q 'Unpacking' "$errf" || fail "cold boot did not report an unpack"

out="$(ELFUSE_OCI_STORE=$coldstore "$BIN" run alpine:3 /bin/echo warm-ok \
    2>"$errf")"
printf '%s\n' "$out" | expect_grep warm-ok
if grep -q 'Unpacking' "$errf"; then
    fail "warm re-attach unpacked again"
fi
echo "cold/warm boot check OK"

# Dynamic-interpreter resolution: run a glibc dynamically linked binary
# from the image explicitly, so PT_INTERP and its .so closure must resolve
# inside the rootfs through path translation.
out="$("$BIN" run --entrypoint /bin/bash debian:stable-slim -c \
    'echo elfuse-interp-ok')"
printf 'interp check: %s\n' "$out"
printf '%s\n' "$out" | expect_grep elfuse-interp-ok

"$BIN" prune >/dev/null

echo "exec checks OK"
