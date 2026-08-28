# shellcheck shell=sh
# Go image workload via /bin/sh -c, POSIX sh (busybox ash): raw Linux syscalls
# and goroutine scheduling, an elfuse entry path no other workload reaches.
# gofmt rather than go build, whose compile child dies on SIGHUP mid-package;
# that gap is the runtime's, not this lane's, and the GODEBUG below narrows it.
set -e

# The guest has no HOME, so give the toolchain a writable cache;
# GOTOOLCHAIN=local stops it reaching for a toolchain over the network.
# asyncpreemptoff=1 drops the preemption SIGURG whose kick, landing while the
# EL1 shim services the vDSO clock_gettime MRS trap, reaches Go's handler
# numbered as SIGHUP; that killed gofmt in CI. Drop it once the runtime defers a
# kick that finds the vCPU at EL1.
export GOCACHE=/tmp/elfuse-go-cache GOTOOLCHAIN=local GODEBUG=asyncpreemptoff=1

# The guest reports a single CPU, so the default GOMAXPROCS would serialize the
# runtime; two keeps the workload actually concurrent.
export GOMAXPROCS=2

go version

d=/tmp/elfuse-go-work
rm -rf "$d"
mkdir -p "$d/src"
cd "$d/src"

# Fixtures are written here, not read from the image, so the assertions cannot
# move when the tag is republished; each file is misformatted the same way, so
# the expected result is one fixed byte sequence.
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

gofmt -w .

# Byte-exact: "gofmt changed something" does not claim it produced the right
# bytes.
printf 'package p\n\nfunc F7() {\n\tx := 1\n\t_ = x\n}\n' > "$d/f7.expected"
if ! cmp -s f7.go "$d/f7.expected"; then
    echo "f7.go after gofmt -w:" >&2
    cat f7.go >&2
    exit 1
fi

remaining=$(gofmt -l . | wc -l | tr -d ' ')
if [ "$remaining" != "0" ]; then
    echo "gofmt -l still names $remaining files after -w" >&2
    gofmt -l . >&2
    exit 1
fi

root=$(go env GOROOT)
if [ ! -x "$root/bin/go" ]; then
    echo "go env GOROOT gave $root, which holds no go binary" >&2
    exit 1
fi

echo "elfuse-oci-go-workload-ok files=$n formatted=$n"
