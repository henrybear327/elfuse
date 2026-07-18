# shellcheck shell=sh
# Go image workload, run in the guest via `/bin/sh -c`. The Go toolchain
# binaries are themselves Go programs, so driving them reaches an elfuse entry
# path no other workload in this suite uses: the Go runtime issues raw Linux
# syscalls instead of routing through libc, and schedules its own goroutines
# over a worker pool that walks and rewrites a directory tree concurrently.
# Prints one sentinel token on success. POSIX sh (busybox ash).
#
# Deliberately does not compile anything in the guest. `go build` spawns
# /usr/local/go/pkg/tool/linux_arm64/compile, which dies on SIGHUP before it
# finishes the first package, so a build step here would test that gap rather
# than the toolchain; the compile-and-run variant lives on the
# oci/workload-stress branch. gofmt needs no compiler, so it exercises the same
# runtime without depending on that gap being closed.
set -e

# The guest has no HOME, so give the toolchain a writable cache; the go command
# refuses to start without one. GOTOOLCHAIN=local stops it from reaching for a
# toolchain over a network this job does not have.
#
# Both paths carry the elfuse- prefix on purpose. A guest path that is absent
# from the rootfs falls back to the literal host path, so a generic name like
# /tmp/gowork would find, and then write through to, whatever the runner left
# in its own /tmp; an unclaimed name is created inside the rootfs instead.
export GOCACHE=/tmp/elfuse-go-cache GOTOOLCHAIN=local
export GOMAXPROCS=2

go version

d=/tmp/elfuse-go-work
rm -rf "$d"
mkdir -p "$d/src"
cd "$d/src"

# Every fixture is written here rather than read out of the image, so what the
# assertions below pin belongs to this test and cannot move when the tag is
# republished. Each file is misformatted the same way, so gofmt must rewrite
# all of them and the expected result is one fixed byte sequence.
n=64
i=1
while [ "$i" -le "$n" ]; do
    printf 'package p\n\nfunc F%s()  {\n\tx :=1\n\t_ = x\n}\n' "$i" > "f$i.go"
    i=$((i + 1))
done

# gofmt walks the tree across goroutines, so this is the concurrent-read half.
# It must name every fixture and nothing else.
listed=$(gofmt -l . | wc -l | tr -d ' ')
if [ "$listed" != "$n" ]; then
    echo "gofmt -l named $listed files, expected $n" >&2
    gofmt -l . >&2
    exit 1
fi

# The rewrite half: gofmt writes each file through a temporary and renames it
# into place, so this covers create, write and rename as well.
gofmt -w .

# Byte-exact, because "gofmt changed something" is not the same claim as
# "gofmt produced the right bytes".
expected_file=$(printf 'package p\n\nfunc F7() {\n\tx := 1\n\t_ = x\n}\n')
actual_file=$(cat f7.go)
if [ "$actual_file" != "$expected_file" ]; then
    echo "f7.go after gofmt -w:" >&2
    cat f7.go >&2
    exit 1
fi

# Nothing may remain unformatted, which is a claim about files this test wrote.
remaining=$(gofmt -l . | wc -l | tr -d ' ')
if [ "$remaining" != "0" ]; then
    echo "gofmt -l still names $remaining files after -w" >&2
    gofmt -l . >&2
    exit 1
fi

# go env reads the toolchain's own configuration through the same runtime.
root=$(go env GOROOT)
if [ ! -x "$root/bin/go" ]; then
    echo "go env GOROOT gave $root, which holds no go binary" >&2
    exit 1
fi

echo "elfuse-oci-go-workload-ok files=$n formatted=$n"
