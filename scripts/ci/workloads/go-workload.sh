# shellcheck shell=sh
# Go image workload, run in the guest via `/bin/sh -c`. A deliberately light
# check that the go toolchain runs under elfuse: `go version` plus a `gofmt` of
# a tiny file. GOMAXPROCS is pinned low because a full `go build`/`go run`
# spawns one OS thread per blocked syscall and overruns elfuse's fixed thread
# table; the compile-and-run stress variant lives on the oci/workload-stress
# branch. Prints one sentinel token on success. POSIX sh (busybox ash).
set -e

# Keep the go runtime's OS-thread count well under elfuse's thread table, and
# give it a writable cache/toolchain path (the guest gets no HOME).
export GOMAXPROCS=1 GOCACHE=/tmp/go-build GOTOOLCHAIN=local

v=$(go version)
case "$v" in
    *"go version go1."*) ;;
    *) echo "unexpected go version: $v" >&2; exit 1 ;;
esac

# gofmt (a single-threaded, compile-free tool) over a canonical file must report
# nothing to reformat; any output means gofmt itself misbehaved in the guest.
d=/tmp/gowork
rm -rf "$d"
mkdir -p "$d"
printf 'package main\n\nfunc main() {}\n' > "$d/main.go"
flagged=$(gofmt -l "$d")
if [ -n "$flagged" ]; then
    echo "gofmt -l flagged a canonical file: $flagged" >&2
    exit 1
fi

echo elfuse-oci-go-workload-ok
