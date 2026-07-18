# shellcheck shell=sh
# Go image workload (issue #224 go profile), run in the guest via
# `/bin/sh -c`. `go version`, gofmt over stdlib trees (the fcntl/read/epoll
# signature), and a build+run of a tiny module to exercise the compiler and
# linker. Prints one sentinel token on success. POSIX sh (busybox ash).
set -e

go version

# The stdlib is gofmt-clean, so `gofmt -l` over these trees must report nothing;
# any output means gofmt itself misbehaved in the guest.
flagged=$(gofmt -l /usr/local/go/src/net /usr/local/go/src/runtime /usr/local/go/src/crypto)
if [ -n "$flagged" ]; then
    echo "gofmt -l flagged stdlib files: $flagged" >&2
    exit 1
fi
gofmt -d /usr/local/go/src/fmt >/dev/null

d=/tmp/gowork
rm -rf "$d"
mkdir -p "$d"
cd "$d"
cat > main.go <<'EOF'
package main

import "fmt"

func sum(n int) int {
	s := 0
	for i := 1; i <= n; i++ {
		s += i
	}
	return s
}

func main() { fmt.Println("sum", sum(100)) }
EOF

# local toolchain only (no network toolchain download); stdlib-only build.
export GOTOOLCHAIN=local
go mod init elfuse-goworkload >/dev/null 2>&1
out=$(go run .)
if [ "$out" != "sum 5050" ]; then
    echo "go run said: $out" >&2
    exit 1
fi

echo elfuse-oci-go-workload-ok
