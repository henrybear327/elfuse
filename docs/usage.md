# Using elfuse

This document covers the command-line interface, common launch patterns,
dynamic linking through `--sysroot`, and debugger attachment.

## Command-Line Synopsis

```sh
build/elfuse [options] <elf-path> [args...]
```

Supported user-facing options:

| Option | Meaning |
|--------|---------|
| `-h`, `--help` | Print built-in usage help |
| `-V`, `--version` | Print the build version and exit |
| `-v`, `--verbose` | Enable syscall-level and loader diagnostics |
| `-t`, `--timeout N` | Per-iteration vCPU watchdog, in seconds (default `10`, `0` disables) |
| `--sysroot PATH` | Resolve guest absolute paths under `PATH` first |
| `--create-sysroot PATH` | Provision a case-sensitive APFS sparsebundle mounted at `PATH`, then use it as the sysroot |
| `--no-rosetta` | Disable the x86_64-via-Rosetta translator (also `ELFUSE_NO_ROSETTA=1`) |
| `--gdb PORT` | Listen for a GDB RSP client on `PORT` (aarch64 guests only) |
| `--gdb-stop-on-entry` | Stop before the first guest instruction |
| `--` | End `elfuse` option parsing; remaining tokens are guest argv |

`--timeout` is a run-loop watchdog. It does not cap total process runtime. It
only bounds a single `hv_vcpu_run()` iteration before the host regains control,
which is what allows host-side timers and signals to be observed promptly.
Setting `--timeout 0` disables this watchdog for long-running CPU-bound guests.

## Common Launch Patterns

Run a statically linked guest binary:

```sh
build/elfuse ./build/test-hello
```

Run with verbose tracing:

```sh
build/elfuse --verbose ./guest-program arg1 arg2
```

Pass guest arguments that begin with `-`:

```sh
build/elfuse -- ./guest-program --guest-flag
```

The guest's exit status is propagated as the `elfuse` exit status, so
`elfuse` composes with shell pipelines, `make`, CI scripts, and
anything else that inspects `$?`.

### Worked Examples

The guest reads and writes the host filesystem directly (no overlay,
no volume mount), so file arguments are just file arguments.

Run a Linux static `jq` against a host JSON file:

```sh
build/elfuse ./jq-aarch64-static '.name' /tmp/data.json
```

Drop into an interactive `bash` session against a musl sysroot:

```sh
build/elfuse --sysroot ./aarch64-musl-sysroot \
    /path/to/aarch64-linux/bin/bash
```

Run a Linux `sqlite3` against a host database file:

```sh
build/elfuse ./sqlite3-aarch64-static /tmp/mydata.db \
    'SELECT name FROM sqlite_master WHERE type = "table";'
```

Run an x86_64 Linux binary (architecture is auto-detected; Rosetta
hosts the translator):

```sh
build/elfuse ./hello-x86_64-static
```

## x86_64-via-Rosetta

Statically linked `x86_64-linux` ELFs run through Apple's embedded
Rosetta translator hosted inside the guest VM. The architecture is
auto-detected from the ELF header, so the same `elfuse` invocation
works for both aarch64 and x86_64 inputs:

```sh
build/elfuse ./x86_64-static-binary
```

Rosetta is on by default. To force the aarch64-only path (or to
verify that a binary really is aarch64), pass `--no-rosetta` or
export `ELFUSE_NO_ROSETTA=1`:

```sh
build/elfuse --no-rosetta ./aarch64-program
```

Both statically and dynamically linked x86_64 binaries are supported.
Dynamic guests need an x86_64-linux sysroot:

```sh
build/elfuse --sysroot /path/to/x86_64-sysroot ./x86_64-dynamic-binary
```

The sysroot must contain the requested dynamic linker
(typically `/lib64/ld-linux-x86-64.so.2` for glibc, or
`/lib/ld-musl-x86_64.so.1` for musl) and any shared libraries the
guest opens. elfuse loads Rosetta into the VM and lets the translator
read the guest ELF; the translated x86_64 dynamic linker then maps
the interpreter and shared libraries through the sysroot like any
other guest process. Runtime `dlopen` and per-thread TLS are
exercised by `tests/test-rosetta-glibc.sh`.

Notes:

- `--gdb` is rejected for x86_64 guests: the stub serves the aarch64
  view Rosetta produces, not the original x86_64 architectural state.
- The CoW fork fast path is disabled for Rosetta because HVF caches
  the host VA-to-PA mapping at `hv_vm_map` time.
- Two Rosetta-internal divergences are documented and not papered
  over: `SA_RESETHAND` is shadowed by Rosetta's own signal-handler
  state, and `clone(..., CLONE_SETTLS, tls=0, ...)` can hang.

The first x86_64 launch may pause briefly while the AOT cache under
`$HOME/.cache/elfuse-rosettad/` warms up; subsequent launches reuse
the SHA-256-keyed translations.

## Dynamic Linking And Sysroots

Dynamic Linux guests need a sysroot that contains the expected interpreter and
shared libraries. `elfuse` reads `PT_INTERP`, loads the requested interpreter
from the supplied sysroot, and redirects guest absolute-path opens to that tree
before falling back to the host filesystem.

Example:

```sh
build/elfuse --sysroot /path/to/sysroot ./hello-dynamic
```

This model supports both musl and glibc guest environments as long as the
expected interpreter path (for example `/lib/ld-musl-aarch64.so.1` or
`/lib/ld-linux-aarch64.so.1`) exists inside the sysroot.

Practical notes:

- The sysroot is consulted only for guest absolute paths; relative paths still
  resolve from the guest working directory.
- The sysroot setting is preserved across guest `fork` and `execve`, so spawned
  children see the same view of the filesystem.
- On case-insensitive macOS volumes, `elfuse` maintains per-directory
  sidecar token files so case-colliding Linux names remain distinct, and
  lookups verify the on-disk spelling byte-for-byte: a name that differs
  from an existing entry only by case (or Unicode normalization form)
  reports `ENOENT`, matching Linux semantics instead of APFS's folding.
- Use `--create-sysroot PATH` if the host filesystem is case-insensitive
  (default APFS) and the sysroot is being provisioned for the first
  time; `elfuse` creates a case-sensitive APFS sparsebundle, mounts it
  at `PATH`, and uses it as the sysroot for this run.
- The sysroot is a root, not a boundary: absolute paths absent from the
  sysroot deliberately fall through to the literal host file, and no
  isolation is provided. `docs/sysroot.md` defines the dispatch model,
  the translation invariants, and the case-handling details.

## Debugging With GDB Or LLDB

`elfuse` includes a built-in GDB Remote Serial Protocol stub.

Start the guest and wait at entry:

```sh
build/elfuse --gdb 1234 --gdb-stop-on-entry ./guest-program
```

Attach with GNU GDB:

```sh
aarch64-linux-gnu-gdb -ex "target remote :1234" ./guest-program
```

Or attach with LLDB:

```sh
lldb --batch -o "gdb-remote 1234" ./guest-program
```

The stub supports all-stop debugging, up to 16 hardware breakpoints, up to 16
watchpoints, single-step (implemented as a temporary breakpoint), full register
and memory access, and per-thread inspection. Implementation details, including
the snapshot protocol used to keep Hypervisor.framework register access on the
owning thread, are documented in [internals.md](internals.md).

## Guest Compatibility Model

`elfuse` is designed for Linux user-space workloads, not for booting a Linux
kernel or presenting a complete Linux host environment. Compatibility comes
from targeted ABI translation and emulation at the syscall boundary.

That has a few direct implications:

- `/proc` and `/dev` are compatibility surfaces, not passthrough mounts.
- macOS and Linux file, socket, and signal semantics are normalized in the host
  syscall layer.
- Behavior is strongest for normal command-line tools, language runtimes, test
  binaries, and debugger-driven workflows.
- Guest-internal FUSE means `/dev/fuse` and `mount(..., "fuse", ...)`
  work entirely inside the VM. Programs that link against `libfuse`
  (sshfs, ntfs-3g, AppImage runtimes) run without macFUSE, FUSE-T, or
  FSKit on the host.

## OCI Images

elfuse can run programs from OCI images. All image work is handled by
`build/elfuse-oci` (Go); execution still goes through the normal
`build/elfuse --sysroot` runtime, so `elfuse` itself has no OCI commands.

```sh
build/elfuse-oci <command> [flags]
```

This consumes the OCI image format for distribution; it is not a container
runtime. There are no namespaces, cgroups, port mapping, daemon, `docker exec`,
or image build/push, and the rootfs is the guest's root, not an isolation
boundary. See
[oci-design.md](oci-design.md#scope-and-limitations) for the exact list of what
is and is not implemented, and for the design model.

### Store And Platform

`elfuse-oci` stores images in an OCI image-layout directory. The default
store is `$ELFUSE_OCI_STORE` when set, otherwise `~/.local/share/elfuse/oci`.
Use `--store DIR` on any subcommand to override it.

Pulls default to `linux/arm64`. Use `--platform os/arch[/variant]` to select
another platform, such as `linux/amd64` for a Rosetta-backed guest:

```sh
build/elfuse-oci pull --platform linux/amd64 alpine:3
```

### Commands

```sh
build/elfuse-oci pull [--store DIR] [--platform os/arch[/variant]] <ref>
```

Pull `<ref>` into the local store and pin it by its original reference.

```sh
build/elfuse-oci inspect [--store DIR] [--json] <ref>
```

Print the stored image's manifest and config summary. `--json` prints the raw
config JSON.

```sh
build/elfuse-oci unpack [--store DIR] [--rootfs DIR] <ref>
```

Unpack the stored image's layers into a rootfs directory. Without `--rootfs`,
the store's digest-keyed rootfs cache is used.

```sh
build/elfuse-oci run [flags] <ref> [args...]
```

Run an image. If `<ref>` is not present, `run` pulls it first; if the rootfs
cache is missing, it unpacks it first.

```sh
build/elfuse-oci list [--store DIR] [--json]      # alias: images
```

List pinned refs, their manifest digests, platform, compressed layer size, and
layer count.

```sh
build/elfuse-oci rmi [--store DIR] [--force] <ref|digest>
```

Remove a ref, or a unique SHA-256 digest prefix from `list`, and
garbage-collect blobs no remaining ref reaches. Removing the last ref for an
image also reclaims its unpacked cache. `rmi` refuses while a live run still
uses the cache (never overridable), and refuses without `--force` when the
cache holds `run --keep` output.

```sh
build/elfuse-oci prune [--store DIR] [--cache] [--all] [--dry-run]
```

Garbage-collect unreachable blobs. `--cache` also removes unpacked rootfs
caches; with `--cache`, `--all` removes them even for still-pulled refs.
`--dry-run` reports what would be removed.

### Running Images

```sh
make elfuse elfuse-oci

build/elfuse-oci run alpine:3 /bin/sh -c 'echo hello'
```

`run` accepts the common flags plus these run-specific flags:

| Flag | Meaning |
|------|---------|
| `--entrypoint PATH` | Replace the image Entrypoint. The image Cmd is dropped. |
| `--env KEY=VALUE` | Set or replace a guest environment variable. Repeatable. |
| `--env KEY` | Import `KEY` from the host environment when present. |
| `--clear-env` | Start from an empty environment instead of image `Env`. |
| `--user UID[:GID]` | Run as a numeric user and optional group. |
| `--user name[:group]` | Resolve names through rootfs `/etc/passwd` and `/etc/group`. |
| `--workdir DIR` | Set the initial guest working directory. Must be absolute. |
| `--rootfs DIR` | Use an explicit rootfs directory. |
| `--plain-rootfs` | Use a plain directory cache instead of the macOS sparsebundle. |
| `--sparse-size SIZE` | Set the sparsebundle virtual size. Default is `16g`. |
| `--no-clone` | Run against the cached base rootfs directly. Mutations persist. |
| `--keep` | Keep the per-run clone and sparsebundle mount for inspection. |

The command vector follows Docker-style rules: with no CLI args, the image
Entrypoint plus Cmd is used; CLI args after `<ref>` replace image Cmd but keep
image Entrypoint; `--entrypoint` replaces image Entrypoint and discards Cmd; an
empty final command is an error. A relative path command (`./server`) resolves
against the working directory, and a bare name resolves via the merged `PATH`
inside the image rootfs (see `oci-design.md` for the `argv[0]` caveat).

Environment resolution starts from image `Env` (or an empty environment under
`--clear-env`); each `--env KEY=VALUE` sets or appends, and a bare `--env KEY`
imports the host value when set. `--user` defaults to image `User`, then root;
symbolic users and groups are resolved after the rootfs exists, and a name that
fails to resolve is an error.

### macOS Rootfs Behavior

By default, `run` uses a case-sensitive APFS sparsebundle per image digest so
the guest's case-sensitive filenames do not collide on a case-insensitive host
volume. The unpacked image lives as a cached base tree inside the sparsebundle,
and each run gets an APFS copy-on-write clone of it, so guest writes do not
mutate the cached rootfs. The clone is removed and the sparsebundle detached
when the guest exits; `--keep` leaves both for inspection, and `prune --cache`
reaps stale caches (including clones left by killed runs) later.

Use `--plain-rootfs` or `--rootfs DIR` when you explicitly want the regular
directory path.

### Runtime Files

Before launching the guest, `run` writes these files into the run rootfs:

| File | Source |
|------|--------|
| `/etc/resolv.conf` | Host resolver config, with a fallback nameserver if needed. |
| `/etc/hosts` | localhost plus the host name. |
| `/etc/hostname` | Host name. |

The `resolv.conf` fallback (used only when the host's own config is unreadable
or empty) is Google's public `8.8.8.8`; on hosts using private or split-horizon
DNS, fix the host `/etc/resolv.conf` if guest lookups must stay on the local
resolver. The C runtime also serves synthetic `/proc` and selected `/dev`
entries to every guest, image-launched or not.

### Host Fallback And PATH

The image rootfs is a root, not a boundary: an absolute guest path absent from
the rootfs falls back to the literal host path, the same mechanism that lets a
plain positional `elfuse <binary>` run reach host resources such as
`/etc/resolv.conf`. The guest-private prefixes (`/tmp`, `/var/tmp`, `.ccache`)
are the exception and always resolve inside the rootfs; see
[sysroot.md](sysroot.md) for the dispatch model.

The visible consequence is the guest `PATH` search. With an image `PATH`
searching `/usr/bin` before `/bin`, a bare `gzip` in an image that ships it only
at `/bin/gzip` resolves to the host's incompatible `/usr/bin/gzip` (a macOS
Mach-O) first. Prefer usr-merged images, invoke by absolute path, or reorder the
search with `--env PATH=...`. When neither the image config nor `--env` provides
a `PATH`, `run` appends Docker's conventional default
(`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`). See
[oci-design.md](oci-design.md#run-paths) for the rationale.

### Lifecycle

The store keeps image blobs separately from unpacked rootfs caches, and garbage
collection is reachability-based: removing a ref never deletes blobs another ref
still reaches, and removing one of several refs to the same digest keeps the
shared cache. A normal cleanup sequence:

```sh
build/elfuse-oci list
build/elfuse-oci rmi alpine:3
build/elfuse-oci prune --cache --dry-run
build/elfuse-oci prune --cache
```

See [oci-design.md](oci-design.md#lifecycle) for the GC and cache-safety model.
