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
  with `--platform` selection resolved against manifest lists and then
  checked against the pulled config: a ref naming a single manifest bypasses
  list resolution, so the registry's answer is verified rather than trusted.

Out of scope:

- OCI runtime spec: no runtime bundle or `config.json`, and no namespaces,
  cgroups, seccomp, capabilities, hooks, or mounts/volumes.
- Distribution write side: pull only, with no `push`, image building, or
  `login`. Credentials come from the ambient default keychain (for example an
  existing Docker credential store), time-bounded so a wedged helper fails the
  pull with an explanation rather than hanging it; `DOCKER_CONFIG` pointing at
  a config without that helper forces an anonymous pull.
- Non-Linux images: only `linux` images, on the platforms the runtime
  executes (`arm64` natively, `amd64` via Rosetta).
- Supply-chain verification: content is verified against manifest digests,
  but there is no signature or attestation checking and no policy engine.

## Library Boundary

`elfuse-oci` imports `go-containerregistry` for registry transport and
image-layout blob access, and owns everything above that layer, starting with
durable store writes: both `skopeo` and `umoci`, the alternative boundary of
shelling out to installed tools, write `index.json` with plain writes, and
neither provides the flock-based store locking concurrent pulls need. The
boundary is therefore a library import: own every behavior the CI asserts,
and keep skopeo and umoci as independent readers that cross-check the store.

## Boundary Between C And Go

There are two binaries with a one-way dependency: `elfuse-oci` calls
`elfuse`, never the reverse, so the runtime stays useful on its own as a plain
ELF runner.

`build/elfuse` (C) is purely the Linux syscall-to-Darwin runtime, with no OCI
awareness. It provides the positional ELF launcher, the `--user`/`--workdir`/
`--env`/`--clear-env` launch flags, and the synthetic `/proc` and `/dev`
entries served to every guest.

`build/elfuse-oci` (Go) is the only OCI entry point. It pulls images,
maintains the image-layout store, and inspects stored images.

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
maps each original image reference to the manifest digests elfuse pinned at
pull time, keyed by the platform the pull requested, so one ref can hold its
`linux/arm64` and `linux/amd64` variants side by side. It is elfuse-specific
lookup metadata; OCI readers parse the layout through `index.json` and the
content-addressed blobs without it. Keeping it separate preserves the exact
pull reference (`docker.io/library/alpine:3`, `name@sha256:...`).

The default store is `$ELFUSE_OCI_STORE` when set, otherwise
`~/.local/share/elfuse/oci`.

## Pull And Platform Selection

`pull` defaults to `linux/arm64`, matching the native Apple Silicon guest path.
`--platform os/arch[/variant]` selects another image, such as `linux/amd64` for
a Rosetta-backed guest. When a reference is a manifest list, `pull` fetches and
pins the selected platform's child manifest, so the pinned digest can differ
from the top-level manifest-list digest that registry tools report. A reference
naming a single manifest skips that resolution, so `pull` also checks the
fetched config's OS and architecture against the request and rejects a
mismatch. Pins are per platform: pulling a second platform for a ref adds a
pin beside the first instead of replacing it, and `inspect --platform` picks
which one to read.
