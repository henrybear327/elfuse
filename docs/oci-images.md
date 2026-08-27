# OCI Images

`elfuse-oci` turns an OCI container image into a sysroot and launches it
under `elfuse`. Commands, flags, and environment are in
[usage.md](usage.md#oci-images); this document records the decisions
behind them and what the CI lanes prove. The runtime the tool launches
is in [internals.md](internals.md).

## The Problem

An OCI image is a filesystem plus a launch recipe, packaged for a
registry. The [image specification](https://github.com/opencontainers/image-spec)
(v1.1.1) defines the pieces. A layer is a tar archive of filesystem
changes; layers stack, each one adding, replacing, or deleting files
relative to the ones below it. A config is a JSON blob holding the launch
recipe (`Entrypoint`, `Cmd`, `Env`, `User`, `WorkingDir`) and the platform
the image was built for. A manifest is a JSON blob naming the config and
the layers, each by digest: a `sha256:` hash of the blob's bytes, which is
also its name in storage, so a layer shared by two images is stored once.
A manifest list (the spec calls it an image index) names one manifest per
platform, an `os/arch[/variant]` triple such as `linux/arm64/v8`; pulling
`alpine:3` on an Apple Silicon Mac means selecting the `linux/arm64` child
of the list. A registry serves those blobs over HTTP under the
[distribution specification](https://github.com/opencontainers/distribution-spec),
and a reference such as `docker.io/library/alpine:3` names a repository
and a tag (or a digest) inside one. A descriptor is a blob's media type,
digest, and size, the unit containerd's pull walk fetches.

elfuse needs two things from an image: a directory tree to use as
`--sysroot`, and the launch recipe turned into elfuse's own launch flags.
Everything else a container runtime does with an image is outside what
elfuse is, a process-scoped Linux syscall translator with no isolation.

## Model

Two binaries with a one-way dependency. `build/elfuse` is the C runtime
and knows nothing about OCI. `build/elfuse-oci` (Go, `cmd/elfuse-oci`)
pulls images into a local store, unpacks them, resolves the launch
recipe, and launches `elfuse --sysroot <rootfs> ...`:

```text
registry --pull--> store --unpack--> rootfs --run--> elfuse --sysroot rootfs
```

There is no daemon: each `run` is one foreground guest whose exit status
the shell sees.

## Scope: Not A Full OCI Toolchain

`elfuse-oci` implements what turning an image into a running elfuse
guest requires, and none of the command surface a Docker-shaped image
manager carries.

| Absent | Why |
|--------|-----|
| The OCI runtime specification: bundles, `config.json`, namespaces, cgroups, seccomp, capabilities, hooks, mounts and volumes | elfuse runs one Linux process tree as a syscall translator. It has no isolation to configure, so a runtime bundle would describe nothing the runtime can honor. |
| The distribution write side: `push`, `build`, `login`, `tag` | The tool consumes images. Credentials come from the ambient docker config (see [Pull](#pull)), so a `login` would only duplicate `docker login`. |
| Image management: `list`, `rmi`, `prune`, reachability garbage collection, image signing and policy | The store is a re-pullable cache. `clean` is its whole lifecycle, and every per-image command would be machinery to keep that cache consistent under concurrent use, which the cache contract does not promise (see [Locking And The Cache Contract](#locking-and-the-cache-contract)). |
| Network and port isolation, `ExposedPorts` | elfuse forwards socket calls to host sockets; a guest listener is host-reachable on the port it binds. |
| Non-Linux images, other architectures | elfuse runs Linux guests on arm64 and amd64, so `--platform` refuses any other OS or architecture at parse time. |
| The config fields `Volumes`, `ExposedPorts`, `StopSignal`, and `Labels` | Each describes a service the runtime does not provide. They are decoded and ignored; Docker's `Healthcheck`, which the image spec does not define, is not decoded at all and survives only in `inspect --json`. |

## Library Boundary

One project carries the generic OCI mechanics:
[containerd](https://github.com/containerd/containerd) v2, used as a
library with no daemon. Of the two Go libraries that apply an OCI layer
to a directory with whiteouts, containment, and darwin as a build
target (containerd's `pkg/archive` and moby/go-archive), containerd's is
used because containerd also supplies the registry client, the
descriptor walk, and the content store, so the tool depends on one
project. The price is the module: `go.mod` carries
containerd's dependency graph, and the Go floor is what containerd
v2.3.4 requires, 1.26.3. Two of its defaults are turned off at the
boundary: the local store warns on every open that its fsverity check
failed (the check errors off Linux), so the package sets the logrus
level to `error` at init (`cmd/elfuse-oci/store.go`), and
`archive.Apply` applies file ownership by default, which an unprivileged
process cannot, so the one `Apply` call passes `WithNoSameOwner`.

Two jobs the daemonless library does not do stay here. containerd core
does not read `~/.docker/config.json`, so `creds.go` does. And the pull
walk trusts an index child's stated platform while a bare manifest
states none, so `selectManifest` reads its config (see [Pull](#pull)).
The rest of what stays is policy no library carries: the per-platform
pin table, the tar-stream filter, Docker-style resolution of the launch
recipe, the runtime `/etc` injection, the case-sensitive sparsebundle
rootfs, and the two launch paths. Go's `os.Root` (1.24) is load-bearing
throughout the run path, and `os.Root.MkdirAll` needs 1.25.

The store is a cache, and that premise settles what the tool does not
carry. Nothing in it is authoritative, so nothing needs to survive a
crash: recovery from any corruption is `clean` and a re-pull. Without
durability, garbage collection and a per-image lifecycle have nothing to
protect, and because no command removes a single image, no run needs a
liveness lock.

## The Store

containerd's `local.NewStore` owns `blobs/` and `ingest/`: a blob that
exists is complete and read-only. The store is not the spec's image
layout (no `index.json`, no `oci-layout` marker), because containerd
keeps image names in its metadata plugin, which this tool does not use,
so `refs.json` is the only name index. It maps each reference, spelled
as the user gave it, to the manifest digest pinned at pull time, keyed
by the platform the pull requested, so `alpine:3` pulled for
`linux/amd64` does not replace the `linux/arm64` pin. The unpacked trees
live beside it under `rootfs/sha256/<hex>` and, on macOS, one
sparsebundle per digest under `cs/sha256/<hex>`; `clean`, the
inside-store refusal, and the cache fills read one definition of that
layout, so they agree on what a slot is.

## Locking And The Cache Contract

There is one lock: an exclusive `flock(2)` on `<store>/.lock`, taken by
`withLock` (`cmd/elfuse-oci/store.go`). It serializes whole pulls,
sparsebundle provisioning on macOS, and `clean` against each other.
Nothing else is synchronized: readers resolve pins and open blobs
without it, and a running guest holds no lock on the rootfs it executes
from.

The lock covers the blob fetch and the pin together; the reference
resolve, read-only against the registry, stays outside it. Two things
make the span necessary: the pin table is a read-modify-write of one
file, so two unlocked pulls would lose one entry; and the content store
names an in-progress write under `ingest/` by a key derived from the
descriptor's digest and resumes an entry it finds there, which is right
for one process retrying and wrong for two processes fetching the same
blob at once. A blocking `flock` ignores every deadline, so the
acquisition polls `LOCK_NB` under the caller's context, which puts the
wait for another pull under `--timeout`. `clean` leaves `.lock` in
place: removing it under a waiting acquirer would leave that acquirer
holding a lock on an orphaned inode no later process can see.

A cold `run` may race another `run` of the same digest and both may
unpack; the publish rule in [Unpack](#unpack) makes that safe. `clean`
while a guest runs pulls the rootfs out from under it, and nothing
prevents it; stop guests first.

## Pull

References expand under Docker's grammar (`reference.ParseDockerRef`,
the package containerd itself normalizes with), and the pin is stored
under the spelling the user gave. Resolution and fetch are containerd's
own pull, minus the daemon: `images.Dispatch` with
`remotes.FetchHandler`, an index filtered to the platform's children and
cut to the best one, so a multi-platform image costs one manifest's
blobs.

The walk trusts an index entry's stated platform, and a bare manifest
states none, so `selectManifest` closes that gap before pinning: for an
index it pins the child the walk fetched, reading that child's own
config when the index entry states no platform; for a bare manifest it
reads the config and refuses when its platform disagrees with the
request. The matcher is `platforms.OnlyStrict`: `linux/arm64` accepts
`linux/arm64` and the `linux/arm64/v8` spelling that normalizes to it
and nothing else, where containerd's default `Only` would also accept an
`arm/v7` image for an `arm64` request. Pulling a digest the store already
holds fetches nothing and only refreshes the pin.

### Credentials And Timeouts

Credentials come from the ambient docker configuration,
`$DOCKER_CONFIG/config.json` or `~/.docker/config.json`. containerd's
authorizer asks for them only when a registry answers a challenge, and
with an empty answer to a Bearer challenge it requests an anonymous
token, which is how Docker Hub's public images pull. The lookup follows
docker's own order: the helper named for the registry in `credHelpers`,
else the store-wide `credsStore` helper, else the inline `auths` entry.
Keys are compared by host, since docker accepts them with or without a
scheme, and Docker Hub is the one special case: its registry answers as
`registry-1.docker.io` but the config keys it as
`https://index.docker.io/v1/`.

A credential helper is an external program, and a wedged one
(`docker-credential-desktop` with Docker Desktop not running is the
common case) would hang the pull silently, so each run is bounded at ten
seconds. `--timeout` bounds the whole pull, the lock wait included,
because a hung registry has no other limit; its default is unbounded,
since any fixed bound would fail large images on slow links.

### Platforms

The default platform is `linux/arm64`, which aarch64 guests run natively
under Hypervisor.framework; `linux/amd64` selects an image that runs
under Rosetta. Spellings go through containerd's `platforms.Parse` and
`Normalize`, so one image identity pins under one key. `--platform` is
registered only on the commands that resolve a platform; a command that
accepted the flag and discarded it would report a target selection that
never happened.

## Unpack

Layers are applied in manifest order, base first, through containerd's
`compression.DecompressStream` (gzip and zstd by magic, plain tar passed
through) and `archive.Apply`. `Apply` honors whiteouts (a `.wh.name`
entry deletes `name` from lower layers) and opaque markers
(`.wh..wh..opq` hides a directory's lower contents), creates hardlinks,
and contains every path through `fs.RootPath`, which resolves a symlink
in the tar name inside the extraction root rather than on the host. An
extended attribute the filesystem does not support is skipped; any
other xattr failure fails the layer. An xz or bzip2 layer is passed
through as plain tar and fails in `Apply`.

### The Tar Filter

`layerFilter` (`cmd/elfuse-oci/tarfilter.go`) is the `archive.Filter`
handed to `Apply` for each layer. `Apply` calls it on every header
before reading that header's mode, type, or link target, so the filter
mutates headers in place or rejects entries, with no second pass over
the stream.

Character and block devices and FIFOs are dropped on every host, because
elfuse synthesizes the `/dev` entries it supports and a node shipped in
an image is never read. On macOS a device entry could not be created
anyway: `Apply` creates all three kinds through `mknod(2)`, and an
unprivileged mknod of a character or block device fails and aborts the
layer.

A dropped entry leaves as a whiteout of its own path, so a device that
replaces a lower layer's file still removes that file. A hardlink whose
target was dropped is dropped with it, because `Apply` would call
`link(2)` against the missing target and abort the whole layer; one
filter spans every layer of the image, so the drop is remembered until
a later layer recreates the path.

setuid, setgid, and sticky bits are cleared on darwin. macOS gives an
unprivileged `chmod(2)` `EPERM` when it would set setgid on a file whose
group, inherited from the parent directory under BSD rules, is not the
caller's; `Apply` treats any chmod failure as fatal; and Debian-family
images ship setgid binaries in their shadow suite. elfuse has no setuid
privilege transition, so nothing observable is lost. The gate is named
for the capability (`clearSpecialBits`), and Linux unpacks keep the bits.

Absolute symlink targets are rewritten to the equivalent relative form,
because the run path reads the rootfs through `os.Root`, which refuses
to follow any absolute symlink target; the two spellings resolve to the
same guest path under `--sysroot`.

### Publishing A Cache

The store's cache directory `rootfs/sha256/<hex>` has one invariant: if
it exists, it is fully unpacked. `run` reads existence as completeness
and boots from it without further checks, so a partially written tree
must never be visible under that name: the unpack extracts into a
sibling temporary directory and `rename(2)`s it into place, and the
loser of a concurrent unpack of the same digest removes its own staging
tree and reports success. A symlink or a non-directory at a cache path
is refused rather than resolved through, since both the extraction and
the guest resolve through the directory name; `unpack --rootfs` refuses
a symlink the same way. `unpack` reports a warm cache; `run` reuses one
silently.

A `--rootfs` inside the store is refused before any network work, on
both `unpack` and `run`: it would fill a digest-keyed cache slot under a
spelling that need not match the digest, and a later `run` would boot
that tree as the digest's.

Plain directories inherit the host volume's case folding. On the default
APFS volume `Foo` and `foo` are one name, so an image that ships both
loses one of each pair under `unpack`, whether into the cache or into
`--rootfs`; the sparsebundle run path does not fold.
[filenames.md](filenames.md) covers how elfuse handles the matching side
of the same problem.

## Run

### Refusals Before Any Network Work

A cold `run` may download hundreds of megabytes before launching, so
every refusal that can be decided from the flags alone is decided first
(`cmdRun`, `cmd/elfuse-oci/run.go`). A sparsebundle-only flag on a path
that can never honor it is refused, since parse-and-ignore would
mislead; the check is on values, so `--keep=false` passes. Which path
is reachable comes from a build-tag constant (`csAvailable`), and the
refusal lives on the same seam, so its message names the right remedy.
The elfuse binary is probed, so a missing build fails in milliseconds
rather than after a pull. Then the store is opened and a `--rootfs`
aliasing the cache is rejected.

Auto-pull fires only on `errNotPulled`. A corrupt pin table or an
unreadable blob surfaces as its own error; hiding it behind a network
pull would mask the corruption until it bit again. On the plain path
the unpack precedes the launch spec, because resolving a symbolic
`--user` reads the rootfs's `/etc/passwd`. An already-published cache is
never re-extracted, since refreshing a stale rootfs is `unpack`'s job;
the per-launch writes below go into it on the plain path and into the
per-run clone on the sparsebundle path.

### Runtime Files

Before launch, `injectRuntimeFiles` (`cmd/elfuse-oci/etc.go`) writes
`/etc/hostname`, `/etc/hosts`, and `/etc/resolv.conf` into the rootfs
from the host. elfuse does no network namespacing, so the guest resolves
names through the host's resolver, and an image's stub `resolv.conf`
would otherwise win. The three are runtime state rather than image
content, which is why overwriting them inside a shared unpacked cache
is correct. An unreadable or empty hostname becomes `localhost`, and an
unreadable or empty host `resolv.conf` becomes `nameserver 8.8.8.8`, so
an odd host degrades the guest's networking rather than failing its
launch.

All writes go through `os.Root`, so an image-controlled symlink cannot
redirect them outside the rootfs. A rootfs-internal `/etc` symlink is
followed, confined, because runc and Docker resolve injected files
through in-rootfs links and images rely on that; `os.Root` diverges from
their `securejoin` only on an absolute target, which this tool's own
unpack rewrites relative, so that spelling occurs only in a foreign
`--rootfs` and is refused there. Each file is written to a unique
temporary name and `rename(2)`d over the target: rename replaces the
entry without following it, so an image-shipped symlink at that name is
unlinked rather than chased, and two runs sharing a cache never see a
half-written file.

The working directory is created when no layer shipped it, as Docker's
runtime does at container start. `prepareRootfsForRun` is the single
caller of both steps so that a new preparation step cannot land in one
launch path and miss the other.

### Launching elfuse

`elfuseArgv` passes `--clear-env` plus explicit `--env` entries, so the
guest gets exactly the computed environment, and ends elfuse's own flags
with `--`, which keeps an untrusted image `Entrypoint` beginning with
`-` out of its flag parsing.

The plain path owns nothing that needs tearing down, so `execElfuse`
replaces the process with `execve(2)`: the shell reaps the same pid and
Ctrl-C reaches elfuse directly. The sparsebundle path must remove its
per-run clone after the guest exits, so `spawnElfuseWait` runs elfuse as
a child and waits. It installs its signal handling before `Start`, so no
window exists in which a signal kills the wrapper between launching the
child and entering the wait loop; `SIGINT`, `SIGTERM`, `SIGQUIT`, and
`SIGHUP` are forwarded, `SIGHUP` included so a terminal hangup still
runs the teardown. A guest killed by a signal reports `128 + signal`, as
a shell would. `runCaseSensitive` returns that status as an
`exitStatus` error value rather than calling `os.Exit` itself, so its
one deferred teardown runs on every exit and `main` is the only place
the process ends. A clone-removal failure after a nonzero guest exit is
only printed: teardown never masks the guest's own failure code.

### Why The Rootfs Is A Root, Not A Boundary

`--sysroot` is a root for absolute paths, not a jail. An absolute guest
path absent under the rootfs falls back to the literal host path.
`run`'s own argv[0] lookup refuses a bare name that misses in the image
(`lookPathInRootfs`), but a PATH search performed inside the guest, by
its shell, ends in absolute spellings and so inherits the fallback.
Alpine ships `gzip` only at `/bin/gzip` while its PATH tries `/usr/bin`
first, and on a macOS host `/usr/bin/gzip` exists and is a Mach-O binary
the guest cannot run; a usr-merged image such as `debian:stable-slim`
finds its own `gzip` first. Absolute in-image paths or an explicit
`--env PATH=...` sidestep the hazard; [internals.md](internals.md)
describes the resolver.

## Runtime Configuration

`computeRunSpec` (`cmd/elfuse-oci/runspec.go`) turns the image config
and the `run` flags into a launch spec under Docker's precedence rules,
applied host-side because elfuse resolves the initial ELF before it
changes directory and performs no PATH lookup of its own. Everything
after `<ref>` is passed verbatim, because flags parse only up to the
first positional.

Environment: the merge rules follow `guest_env_build`
(`src/core/guest-env.c`), which elfuse applies to its own `--env`, with
one divergence: a key an image `Env` lists twice keeps its last value
here and its first there (`TestResolveEnvDuplicateOrdering`). An image
entry with an empty key (`=VAL`) is dropped, since elfuse rejects such a
name and the image still starts under Docker; an empty key from the
command line is an error, caught before any rootfs work. When the merge
yields no `PATH`, Docker's default is appended, because the guest is
launched with `--clear-env` and would otherwise have no search path.

Working directory: `--workdir`, else the image `WorkingDir`, else `/`.
It must be guest-absolute, and it is cleaned the way the guest resolver
cleans paths (`lexical_normalize_absolute_path`,
`src/syscall/proc-state.c`), folding `//` and clamping `/..` at `/`, so
the two agree on what a spelling names.

Program: a bare argv[0] is searched along the merged `PATH` inside the
rootfs, probing candidates through `os.Root` so image symlinks stay
confined. An empty PATH element names the working directory and a
relative one resolves against it, the POSIX rule `exec.LookPath` and
runc share. Docker leaves argv[0] as written; here the resolved absolute
path is what the guest sees.

User: `--user`, else the image `User`, else `0:0`, with the user and
group halves resolved independently. A bare numeric uid defaults its
gid to the same number, elfuse's `--user` convention. `/etc/passwd` and
`/etc/group` are read through `os.Root`, so a symlinked `etc/passwd`
cannot read the host's account database. `root` resolves through
`/etc/passwd` first, because its gid can differ from zero, and falls
back to `0:0` only when there is no passwd file or no entry; a root line
whose uid or gid field does not parse surfaces as an error rather than
launching as `0:0`. Database lines are read up to 1 MiB rather than the
scanner's default 64 KB, because a real `/etc/group` line lists every
member of a group.

## The Sparsebundle Rootfs

On macOS the default rootfs is a volume. The usual host volume is
case-insensitive APFS, on which an image's case-colliding names cannot
coexist, so `run` provisions a per-digest sparsebundle (a disk image
stored as a bundle of band files, growing on demand) formatted as
case-sensitive APFS and unpacks the image inside it (`runCaseSensitive`,
`cmd/elfuse-oci/csrootfs_darwin.go`). The mechanism mirrors
`--create-sysroot` on the C side (`src/core/sysroot.c`).

The `16g` size is a ceiling: a sparsebundle occupies what it holds.
`--sparse-size` changes it for a new bundle only; against an existing
one it is inert, and the tool says so whenever the requested size
differs from the default. A symlink at the mount path is refused,
because the mount probe, the pre-attach clear, and any later detach all
follow the name, so a planted link would aim them at an unrelated
directory. The mount probe compares the directory's `st_dev` against
its parent's, so a mount on the same device would read as absent. The
attached path is decoded from `hdiutil attach -plist`, so a store path
containing `&` or `'` comes back unescaped, with stdout and stderr kept
separate so hdiutil's diagnostic reaches the error without corrupting
the parse. A `.metadata_never_index` marker keeps Spotlight off the
volume. The base tree is `<mnt>/rootfs`, published under the same
staging-and-rename rule and the same symlink refusal as the plain cache.

### Per-Run Clones

Each run executes from an APFS copy-on-write clone of the base tree,
made with `clonefile(2)` (`CLONE_NOFOLLOW`, so a symlinked base is not
chased). Whatever the guest writes into its `/` stays in the clone, and
the base tree serves the next run unchanged. `--no-clone` runs the base
tree itself, so mutations persist into the warm tree. The clone is
removed when the guest exits, unless `--keep`, which prints where the
clone and the still-attached volume are; `--keep` preserves the clone on
the failure exits too, since inspecting a broken preparation is what
the flag is for.

### Lifecycle

The bundle stays attached after a run. Reattaching costs seconds of disk
arbitration, and the next run of the same digest is then warm: provision
finds the mount, skips the unpack, clones, and launches. Detaching is
`clean`'s job. No lock records which runs are live, so `clean` during a
run breaks the run. Off darwin, `runCaseSensitive` is a stub so the
package compiles; `cmdRun` never dispatches to it there.

## Clean

`clean --cache` removes every unpacked rootfs and every sparsebundle,
keeping the blobs and the pins, so the next run re-unpacks without
re-downloading; bare `clean` removes the whole store except `.lock`, for
the reason given in [Locking](#locking-and-the-cache-contract). A
mounted bundle volume is force-detached first, because removing a
directory that is a live mount point fails.

Either form then sweeps orphaned bundle volumes: a store removed under a
live mount, by a killed test's TempDir cleanup or an `rm -rf`, loses its
`rootfs.sparsebundle` directory while the volume stays attached, and no
store can reach it any more. The sweep reads `hdiutil info -plist` and
detaches every store-shaped bundle whose image is gone; bundles whose
store still exists are left to that store's `clean`. Nothing guards a
live guest: stop guests, then clean.

## CLI Conventions

Standard output carries only what a caller captures: `inspect`'s summary
or raw JSON, and `version`. Progress, warnings, and diagnostics go to
standard error, and an error exits 1 as `elfuse-oci: <message>`; a guest
run exits with the guest's own status on both launch paths. `inspect`
treats a failed write to stdout as an error, because a closed pipe or a
full disk must not exit 0 while a caller consumes truncated JSON. Usage
is generated from the commands' own `FlagSet`s, so the help text cannot
drift from what parsing accepts.

## Known Limitations

| Limitation | Reason | Where |
|------------|--------|-------|
| `go build` inside a guest dies on `SIGHUP` mid-compile | A runtime gap the go CI lane routes around | `scripts/ci/workloads/go-workload.sh` |
| The guest reports a single CPU and no `HOME` | Runtime facts the lanes set `GOMAXPROCS` and `GOCACHE` for | `scripts/ci/workloads/go-workload.sh` |
| A daemonizing server inside a guest risks a wait livelock on its backgrounded fork | The redis lane runs its server in the foreground with a second driver guest | `scripts/ci/oci-workload.sh` |

## Testing

### Running The Tests Locally

The targets are listed in [testing.md](testing.md#oci-image-cli). The
offline suite needs only a Go toolchain; the live lanes need a built
`build/elfuse`, macOS with Hypervisor.framework, and a network for a
cold store. No test in the package uses `t.Parallel`: several swap
package-level seams, many call `t.Setenv`, and both are process-global.
Three tests are gated behind environment variables because they leave
the machine or need real disk arbitration: `TestPullRegistryRoundTrip`
pulls `alpine:3` from Docker Hub into a temporary store;
`TestDarwinCSRealHdiutil` creates a real sparsebundle, attaches it,
proves `Foo` and `foo` coexist on it, clones a tree with `clonefile(2)`,
and detaches; `TestDarwinCSOrphanSweep` removes a bundle from under its
live mount and proves the sweep detaches the orphan.

The Go targets are opted into `all`, `check`, and `lint` only when a
`go` on `PATH` is new enough for `go.mod` (probed with
`GOTOOLCHAIN=local go list -m`, so the probe never downloads a newer
toolchain); a host without a usable Go toolchain still builds `elfuse`.
`oci-test` always passes `-race`: the launch path runs a goroutine
around `Wait`, and the concurrent-pin-writer test hammers `withLock`
from eight goroutines. CI reads the Go floor through `go-version-file`,
so the two cannot drift.

`TestMain` (`cmd/elfuse-oci/main_test.go`) points `ELFUSE_OCI_STORE` at
a throwaway directory for the whole test process unless the variable is
already set. A command dispatched without `--store` resolves the real
default store, and `clean` reached through a dispatch test would empty
it; the sandbox is what stands between any test and a developer's
images. No test in the offline suite contacts a registry, needs an image
on disk, runs `hdiutil`, or runs a real elfuse: images are built in
memory and written through `content.WriteBlob`, a fake `hdiutil` on
`PATH` answers `attach` with a plist naming the requested mount point,
and a shell script stands in as `$ELFUSE_BIN`.

### The Live Lanes

The live lanes are the CI scripts themselves, run against a scratch
store so the default store is never touched; the commands are in
[usage.md](usage.md#running-the-lanes-locally).

A cold lane spends most of its wall clock on the pull and unpack.
Sparsebundle volumes stay attached between runs; `elfuse-oci clean` on
the scratch store detaches them, and it must not run while a guest is
still executing from that store.

### CI Lanes

`oci-linux` runs on `ubuntu-24.04`, because the CLI is pure Go: no
Hypervisor.framework entitlement, no code signing. It runs `make
oci-lint`, `scripts/ci/oci-lib-selftest.sh`, and `make oci-test`; off
darwin the sparsebundle path compiles to a stub, so this job proves the
store, pull, unpack, and the plain run path. `oci-image-macos` runs on
`macos-15`, which has `hdiutil` and case-sensitive APFS but no
Hypervisor.framework: it runs the lint and the race-detected suite on
darwin, the only place the race detector sees the sparsebundle and clone
code, and `make oci-test-hdiutil`, which proves attach, case-colliding
coexistence, `clonefile(2)`, and detach against real disk arbitration.

#### Self-Hosted Release Leg

The release leg of `runtime-macos` (the sanitizer legs skip it) builds
`elfuse-oci` and runs two scripts against one store,
`$HOME/.cache/elfuse-ci/oci-store`. A "Reset OCI store" step runs
`elfuse-oci clean` on it first, so every run starts cold and pulls its
images; `clean` also detaches a bundle volume a cancelled run left
attached. The second script reuses what the first pulled.

`scripts/ci/oci-run-smoke.sh` asserts: an `alpine:3` guest boots through
pull, sparsebundle, clone, and Hypervisor.framework and prints its
sentinel; `exit 7` inside the guest arrives as exit status 7; a
`debian:stable-slim` guest runs a `seq | gzip | gunzip | cmp | sha256sum`
pipeline whose digest matches a fixed known answer, which exercises the
in-rootfs `PATH` search on a usr-merged image (Alpine would find the
host's Mach-O `gzip` first, the hazard in
[Why The Rootfs Is A Root, Not A Boundary](#why-the-rootfs-is-a-root-not-a-boundary));
and a fresh run of the same digest does not see the previous run's
`/tmp` file, which is the per-run clone isolating it.

`scripts/ci/oci-exec-checks.sh` asserts: a pathname `AF_UNIX` socket
created in a guest-made directory reads back byte-identical through
`getsockname`; a cold store provisions and unpacks on the first run and
re-attaches without unpacking on the second; and a dynamically linked
binary from the image resolves its `PT_INTERP` and shared libraries
inside the rootfs. Its cold store is seeded from the shared store's
`blobs/` and `refs.json` only, never a raw tree copy, which would recurse
into a live mounted volume. It prunes the shared store's caches at the
end, as the last consumer.

#### Workloads

The `workload` job runs one real image per leg on the self-hosted
runner, with `fail-fast: false` so one image regressing does not hide
the state of the others. Its per-key store
(`$HOME/.cache/elfuse-ci/oci-workload-<key>`) is emptied by the same
reset step before the lane, so every leg pulls its image. Legs get 30
minutes, jvm and c 45, for slower startup and the largest pulls.
`scripts/ci/oci-workload.sh <key>` is the driver:

| Key | Image | What it proves |
|-----|-------|----------------|
| python | `python:3.12-slim` | a Debian image through the setgid degrade; SQLite from eight writer threads (WAL where the guest filesystem can back it, rollback journal otherwise); `subprocess` fork and exec of a glibc interpreter; a deep `os.walk` |
| node | `node:22-alpine` | a host-reachable HTTP listener answering 100 requests, bound to port 0 because a fixed port could collide with a leaked or concurrent guest; fs fan-out, zlib, JSON, and crypto self-checks |
| go | `golang:1.23-alpine` | the Go runtime's raw syscalls and goroutine scheduling, via `gofmt` over 64 fixtures; it compiles nothing, because `go build` spawns `compile`, which dies on `SIGHUP` mid-package in a guest; it runs with `GODEBUG=asyncpreemptoff=1`, since the same misnumbered signal killed `gofmt` once |
| jvm | `eclipse-temurin:21` | an Ubuntu shadow-suite image through the setgid degrade; `javac` and `java` with a thread pool and a `ProcessBuilder` child |
| c | `gcc:14` | a Debian shadow-suite image; a multi-file `make` project and a 1000-function compile |
| redis | `redis:7-alpine` | fork and copy-on-write: `BGSAVE` forks the server and the snapshot must complete with status `ok`; the server runs in the foreground in one guest and a second guest drives it, because a daemonizing server risks a wait livelock on its backgrounded fork |

The redis server takes a port from 20000 to 39999, below the ephemeral
range, so another lane's port-0 bind cannot land on it; the host probes
the port with `nc` before driving it, since a "ready" line on stdout is
not proof the socket accepts. Guest workloads keep their churn under
`/tmp`, which every workload image ships and which therefore resolves
inside the rootfs, so it stays in the ephemeral clone; the redis server
snapshots to the image's `/data`.

`.github/actions/hvf-elfuse-setup` is the composite step every workload
leg runs after checkout. `.ci/hvf-check-superseded.sh` fails the leg
when the run has been superseded by a newer commit on the same pull
request: a manual re-run replays a frozen commit against the one
self-hosted runner, the job's token cannot cancel a run, and the lookup
fails open. The action then sets up Go, downloads the `elfuse` artifact
the build job produced, restores its execute bit and re-checks the
Hypervisor.framework entitlement (`.ci/hvf-verify-elfuse-binary.sh`;
Mach-O signatures travel inside the file and survive the artifact
round-trip), and builds `elfuse-oci`.

### The Shell Library

`scripts/ci/oci-lib.sh` is sourced by every lane script. Each of its
rules keeps a failure from passing silently:

- Sourcing sets `set -Eeuo pipefail` and an `ERR` trap. Under plain
  `set -e` a bare `test` or `grep -q` failure kills the script with no
  output; `-E` makes the trap fire inside functions.
- Diagnostics go to file descriptor 3, a copy of the real stderr, because
  `wait_for` runs its predicates under `>/dev/null 2>&1` and a message a
  predicate prints on stderr would vanish.
- Poll loops live in `wait_for`, since an inline loop under `set -e` dies
  on the first transient failure of a command substitution.
- `expect_grep` never uses `grep -q`. With `-q`, grep exits at the first
  match, the producer takes `SIGPIPE`, and under `pipefail` a passing
  check reports 141.
- The scripts run under macOS's Bash 3.2: no `mapfile`, no `wait -n`, no
  `${var,,}`.
- `reap_guest` kills a leaked guest at exit, because one that survives
  keeps its loopback port bound and its per-run clone live on the
  attached volume.
- `prune_store_cache` (`clean --cache`) runs only after the lane's own
  guests have exited and never against a store another live leg shares,
  since `clean` has no liveness guard.

`scripts/ci/oci-lib-selftest.sh` proves the fd 3 plumbing and the
`fail`-inside-a-predicate path, and cross-checks three lists against
each other: `KEYS` in `oci-workload.sh`, that script's `case` arms, and
the `workload` matrix in `build.yml`, so a case arm without a matrix
entry cannot silently never run. It needs no binary, store, or
Hypervisor.framework and runs on the Linux job.

### Adding A Workload Image

1. Add the key to `KEYS` in `scripts/ci/oci-workload.sh` and a `case` arm
   that runs the image (`run` auto-pulls) and asserts a unique sentinel
   through `run_capture`. Use `--entrypoint` with an absolute in-image
   path for interpreters, and `/bin/sh -c` with a workload script from
   `scripts/ci/workloads/` for shell-driven work. A server workload gets
   a `run_node`-style function built on `start_server_guest`, `wait_for`,
   and `await_server_exit`; it binds port 0 and prints the port, or takes
   a port the host chose below the ephemeral range.
2. Add the workload file. It prints a sentinel of the form
   `elfuse-oci-<key>-workload-ok` only after every assertion passed, and
   keeps its writes under `/tmp`. A split workload varies that: node's
   compute half prints `elfuse-oci-node-compute-ok`, and its server half
   prints `PORT=<n>` for the readiness match and answers each request
   with `elfuse-node-server-ok`.
3. Add a matrix entry to the `workload` job in
   `.github/workflows/build.yml` with a timeout; 30 minutes unless the
   image is large or compiles.
4. Run `scripts/ci/oci-lib-selftest.sh`, which fails if the three lists
   disagree, then the lane locally with a scratch store.
