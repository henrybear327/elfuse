# OCI Image Support Design

This is the reference for how elfuse consumes OCI images without becoming a
container runtime. It is the single source of truth for what is and is not
implemented. For day-to-day commands and flags, see
[usage.md](usage.md#oci-images); for validation targets, see
[testing.md](testing.md).

## Model

elfuse uses the OCI image format for distribution and filesystem packaging
only. It does not implement the OCI runtime spec. The goal is narrow: pull an
image, unpack its layers into a Linux rootfs, resolve the image runtime
configuration, and launch the configured program through the existing
`elfuse --sysroot` path. The guest is a single elfuse process translating
Linux syscalls to Darwin, not an isolated container.

## Scope And Limitations

The OCI ecosystem is three specifications plus a set of conventions. elfuse
implements the consumer side of the image format and nothing else.

Implemented:

- the on-disk OCI image-layout store (`oci-layout`, `index.json`,
  content-addressed blobs) plus an elfuse-specific `refs.json` pin file;
- pulling with `go-containerregistry` through the ambient default keychain,
  with `--platform` selection resolved against manifest lists;
- layer application: whiteouts and opaque directories, hardlinks and symlinks
  (absolute targets rewritten rootfs-relative), setuid/setgid/sticky bits, and
  gzip or zstd compression, all applied under `os.OpenRoot`;
- image-config resolution of `Entrypoint`, `Cmd`, `Env`, `User`, and
  `WorkingDir` with Docker-style precedence;
- local lifecycle management (`list`, `rmi`, `prune`) with reachability-based
  garbage collection and macOS sparsebundle cache handling;
- runtime injection of `/etc/resolv.conf`, `/etc/hosts`, and `/etc/hostname`
  into the run rootfs.

Out of scope:

- **OCI runtime spec.** No runtime bundle or `config.json`, and no namespaces,
  cgroups, seccomp, capabilities, hooks, or mounts/volumes. The image rootfs is
  the guest's root but not a boundary: an absolute guest path absent from the
  rootfs falls back to the host filesystem (see [Run Paths](#run-paths)), and
  the guest shares the host network identity, PID space, and clock.
- **Distribution write side.** Pull only: no `push`, no image building, and no
  `login`. Credentials come from the ambient default keychain (for example an
  existing Docker credential store); elfuse adds none of its own.
- **Network and port isolation.** The guest shares the host network. There is
  no port mapping, and `ExposedPorts` has no effect.
- **Ignored image-config fields.** `Volumes`, `ExposedPorts`, `Healthcheck`,
  `StopSignal`, and `Labels` are accepted but have no runtime effect.
- **Daemon conveniences.** No daemon, no `exec` or `attach`, no detached
  containers; each `run` is one foreground guest process.
- **Non-Linux images.** Only `linux` images, on the platforms the runtime
  executes: `arm64` natively, `amd64` via Rosetta.
- **Device nodes in layers.** Character, block, and FIFO entries are rejected
  rather than materialized; the C runtime synthesizes the supported `/dev` and
  `/proc` entries at run time.
- **Supply-chain verification.** Content is verified against manifest digests,
  but there is no signature or attestation checking (cosign, notation) and no
  policy engine.

A workload that needs any of the above needs a container runtime, not an ELF
runner that consumes OCI images.

## Library Boundary

`elfuse-oci` imports `go-containerregistry` for registry transport and
image-layout blob access, and owns everything above that layer: durable store
writes, layer application, runtime-configuration resolution, and lifecycle
management. The obvious alternative (shelling out to `skopeo` for pull and
delete plus `umoci` for unpack; both install cleanly on macOS) was evaluated
empirically: a prototype wrapper over the two tools was driven through this
repository's entire OCI CI suite unmodified.

The wrapper passed the suite, but only by reimplementing on top of the tools
every macOS and lifecycle behavior the CI asserts:

- `umoci gc` aborts on a stale temporary blob whose name is not a valid
  digest (the exact debris prune must sweep), so the reachability sweep had
  to be rebuilt;
- umoci stores absolute symlink targets verbatim, so the rootfs-relative
  rewrite of [Layer Application](#layer-application) had to be rebuilt;
- no copy tool tolerates the setgid `chmod` `EPERM` that group inheritance
  produces on macOS volumes, so the special-bit degrade had to be rebuilt;
- no tool models unpacked caches, sparsebundles, or per-run clones, so the
  whole [Lifecycle](#lifecycle) layer had to be rebuilt.

What the tools cover well (registry transport and whiteout-correct layer
application) is the part this design already delegates to
`go-containerregistry` or that changes rarely. Shelling out would also give
up crash-durable store writes (both tools write `index.json` with plain
writes), the flock-based store and live-run locking, the device-node
rejection policy (umoci materializes empty placeholder files instead), and
the single-binary install. The boundary therefore stays put: import
`go-containerregistry` as a library, own every behavior the CI asserts, and
keep skopeo and umoci as independent readers that cross-check the store (see
[Validation](#validation)).

## Boundary Between C And Go

There are two binaries with a one-way dependency: `elfuse-oci` calls
`elfuse`, never the reverse, so the runtime stays useful on its own as a plain
ELF runner.

`build/elfuse` (C) is purely the Linux syscall-to-Darwin runtime, with no OCI
awareness. It provides the positional ELF launcher, the `--user`/`--workdir`/
`--env`/`--clear-env` launch flags, and the synthetic `/proc` and `/dev`
entries served to every guest.

`build/elfuse-oci` (Go) is the only OCI entry point. It pulls images,
maintains the image-layout store, inspects and unpacks stored images, resolves
the runtime configuration, prepares the runtime `/etc` files, and invokes
`elfuse` with the resolved launch flags. It locates `elfuse` as a sibling of
its own executable; `$ELFUSE_BIN` overrides the location for tests and wrapper
scripts.

## Store

The store is an OCI image-layout directory plus one pin file:

```text
<store>/
  oci-layout
  index.json
  blobs/sha256/<hex>
  refs.json
```

`oci-layout`, `index.json`, and `blobs/` are the standard layout. `refs.json`
maps each original image reference to the manifest digest elfuse pinned at pull
time. It is elfuse-specific lookup metadata; OCI readers parse the layout
through `index.json` and the content-addressed blobs without it. Keeping it
separate preserves the exact pull reference (`docker.io/library/alpine:3`,
`name@sha256:...`).

The default store is `$ELFUSE_OCI_STORE` when set, otherwise
`~/.local/share/elfuse/oci`.

## Pull And Platform Selection

`pull` defaults to `linux/arm64`, matching the native Apple Silicon guest path.
`--platform os/arch[/variant]` selects another image, such as `linux/amd64` for
a Rosetta-backed guest. When a reference is a manifest list, `pull` fetches and
pins the selected platform's child manifest, so the pinned digest can differ
from the top-level manifest-list digest that registry tools report.

## Layer Application

Extraction runs under `os.OpenRoot`, so every layer path resolves relative to
the target rootfs and cannot escape via `..` or a symlink. The unpacker
implements the layer behavior common images need:

- regular files, directories, symlinks, and hardlinks;
- Docker/OCI whiteouts and opaque directory markers;
- permission bits plus setuid, setgid, and sticky, finalized with an explicit
  chmod so layer modes survive a restrictive host umask. Where an unprivileged
  host rejects the setuid/setgid chmod, the unpacker drops the special bits
  (with a warning) and continues rather than aborting: the rootfs is owned by
  the invoking user, so those bits could not be honored there anyway. This
  fires on macOS when the unpacked file's inherited group is one the invoking
  user is not in (a new file takes its parent directory's group, e.g. wheel
  under `/tmp`), which is what lets Debian-family images and their shadow suite
  (`chage`, `passwd`, ...) unpack at all. Linux keeps the bits (an owned-file
  chmod succeeds), so the C runtime's setuid-exec support still applies where
  they survive;
- absolute symlink targets rewritten to rootfs-relative links;
- rejection of special files elfuse does not materialize from layers.

Runtime `/dev` and `/proc` entries are not unpacked from layers; the C runtime
synthesizes the supported ones when the guest opens them.

## Run Paths

On macOS the default `run` path uses a case-sensitive APFS sparsebundle per
manifest digest, with the unpacked base rootfs inside it. Each run makes an
APFS copy-on-write clone of the base tree, launches elfuse against the clone,
removes the clone, and detaches the sparsebundle once the last concurrent run
of that digest exits. This protects case-sensitive Linux filenames on normal
(case-insensitive) macOS volumes and keeps repeated runs isolated from
image-layer mutations.

The plain-rootfs path stays available with `--plain-rootfs` or an explicit
`--rootfs`. It uses a regular directory and execs `elfuse` directly, which is
useful for debugging and for non-Darwin operation. The default sparsebundle
sits on a volume the invoking user created, so unpacked files inherit that
user's own group and the setuid/setgid chmod above succeeds; the special-bit
degrade is therefore mostly a plain-rootfs concern, where `--rootfs` can point
at a directory whose group the user is not in.

Before launch, `run` writes runtime `/etc/resolv.conf`, `/etc/hosts`, and
`/etc/hostname` into the run rootfs so DNS, localhost, and hostname lookups
work without network namespacing. The writes go through `os.OpenRoot` and
replace any existing entry, so an image that ships one of these names as a
symlink (including a symlinked `/etc`) cannot redirect the write outside the
rootfs.

`run` launches `elfuse --sysroot <rootfs>` with the host-literal fallback in
place: an absolute guest path absent under the rootfs resolves to the literal
host path. The rootfs is a root, not a boundary; elfuse favors transparency
over isolation, so an image-launched guest keeps the same filesystem view a
plain positional `elfuse <binary>` run has (a development workflow that
deliberately reaches host resources such as `/etc/resolv.conf` or files under
the user's home). The guest-private prefixes are the exception: `/tmp`,
`/var/tmp`, and `.ccache` paths always resolve inside the rootfs and never
fall back to the host (see `sysroot.md`). The practical caveat is
the guest `PATH` search: with an image `Env` `PATH` putting `/usr/bin` before
`/bin`, a bare `gzip` in an image that ships it only at `/bin/gzip` resolves to
the host's incompatible `/usr/bin/gzip` (a macOS Mach-O) first. Prefer
usr-merged images, invoke by absolute path, or reorder the search with
`--env PATH=...`. When the merged environment carries no `PATH`, `run` appends
Docker's conventional default so the guest always has a search path.

## Runtime Configuration

`elfuse-oci` resolves the image configuration before calling `elfuse`.

Command resolution follows Docker-style rules:

- `--entrypoint` replaces the image Entrypoint and drops the image Cmd;
- without `--entrypoint`, CLI arguments after the reference replace the image
  Cmd while preserving the image Entrypoint;
- with neither override, image Entrypoint and Cmd are concatenated;
- an empty final command is an error;
- a relative path command (one containing a slash, like `./server`) resolves
  against the working directory; a bare name resolves against the merged
  `PATH` inside the image rootfs, and not finding it there is an error.
  Unlike Docker, the resolved absolute path is also what the guest sees as
  `argv[0]` (elfuse's positional argument names both the binary to load and
  the guest argv head).

Environment resolution starts from image `Env`, or from an empty environment
under `--clear-env`. Each `--env KEY=VALUE` sets or replaces a value; a bare
`--env KEY` imports `KEY` from the host when present.

User resolution accepts numeric `UID[:GID]` and symbolic `name[:group]`.
Symbolic names resolve against the unpacked rootfs `/etc/passwd` and
`/etc/group`, opened through `os.OpenRoot` so a symlinked account file cannot
redirect resolution to host data. Working directories must be guest-absolute.

## Lifecycle

The lifecycle commands operate on the local store:

- `list` reads `refs.json` and the pinned image metadata;
- `rmi` removes a ref (or a unique SHA-256 digest prefix from `list`),
  garbage-collects blobs no remaining manifest reaches, and reclaims the
  image's unpacked cache when its last ref goes away;
- `prune` garbage-collects unreachable blobs without removing a named ref;
  `prune --cache` also removes unpacked rootfs caches.

Garbage collection is reachability-based: shared manifests, configs, and layers
stay on disk while any remaining ref reaches them.

On macOS, cache cleanup also handles sparsebundle state, detaching stale mounts
and reaping per-run clone directories left by killed runs, with two safety
rules. A still-pinned digest's bundle is untouched by a plain `prune --cache`
(recovery of a crashed pinned bundle happens on the next `run`, or via `--all`),
and a volume a live run still uses is never force-detached. Liveness is decided
by a per-digest advisory lock (`run.lock`, held shared by every live run for
its whole lifetime), not by inspecting process ids, which avoids the pid-reuse
hazard. A sweep acquires that lock exclusively; while it cannot, the bundle is
left in place, and once it can, every clone is abandoned by construction and is
reaped except those a `run --keep` retained (a `.elfuse-keep` file) and any
leftover unpack staging directory. `rmi` reclaims a cache the same way: a plain
`rmi` drops the removed image's cache (derived state that goes with the image),
but refuses while a live run uses the volume (not even `--force` overrides) and
refuses without `--force` when the cache holds `run --keep` output.

### Concurrency

elfuse-oci is a single-user CLI, not a daemon. Store metadata stays
consistent under concurrency: pin and index updates, `rmi`, `prune`'s GC, and
`list`'s snapshot all serialize on an exclusive store file lock, so parallel
pulls and lifecycle commands cannot corrupt `refs.json`, `index.json`, or
reachability accounting.

Per-digest sparsebundle state uses two advisory locks kept beside the bundle
(outside the mounted volume, so a detach cannot revoke them): an `attach.lock`
serializing lifecycle transitions, and the shared `run.lock` above. Concurrent
runs of the same image share one attach: the first provisions and attaches,
later runs join under a shared `run.lock`, and the volume detaches only when the
last exits. A `prune`/`rmi` sweep takes both locks non-blocking, so it either
wins (no run is live) or skips the busy bundle. A cold run unpacks into a
temporary directory and atomically renames it into place, so a concurrent probe
never sees a half-written rootfs and an interleaved sweep cannot delete one
mid-unpack.

The plain digest-keyed rootfs cache (`rootfs/<algo>/<hex>`, the default on
non-Darwin and on the `--plain-rootfs` path) follows the same liveness rule
with a single sibling `<hex>.lock`, held shared by a run from before the
cache-existence probe until the guest exits. The lock sits beside the directory
because the directory is the guest's `/` and its existence is the
unpack-complete signal. The plain run path execs `elfuse` in place, so the lock
descriptor is made exec-survivable and rides into the elfuse process: the kernel
releases the flock exactly when the guest exits, `SIGKILL` included. An explicit
`--rootfs` directory is user-managed and outside this scheme.

## Validation

The on-disk store is the contract: its layout is checked for spec-conformance
and cross-tool readability (crane/skopeo/umoci), and the pipeline is exercised
offline on Linux and end-to-end on macOS/HVF. `elfuse-oci` builds and
unit-tests without Hypervisor.framework; only an actual `run` guest boot needs
it. The concrete targets, env-var gates, and the Linux/macOS CI split live in
[testing.md](testing.md#oci-image-cli).
