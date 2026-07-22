# Sysroot Path Translation

`--sysroot DIR` resolves absolute guest paths under a Linux root filesystem
staged in DIR while keeping the host filesystem reachable. The sysroot is a
root, not a boundary: elfuse is not a sandbox, and guest access to files in
the real macOS filesystem is a feature. This document describes the dispatch
model that chooses between sysroot and host, the translation pipeline every
path-taking syscall uses and its invariants, case handling, and the special
treatment of AF_UNIX socket addresses.

## Path Dispatch

Every absolute guest path is dispatched on existence by
`proc_resolve_sysroot_path_flags` (`src/syscall/proc-state.c`):

- If the path exists under `<sysroot><path>`, the guest operates on the
  sysroot copy, subject to the containment check below.
- If the path is absent under the sysroot, the resolver returns the guest
  path unchanged and the host kernel operates on the literal host file, for
  reads and writes alike. This fall-through is what lets guests reach host
  resources such as `/etc/resolv.conf` or files under the user's home
  directory.

### Guest-Private Prefixes

Creates and lookups under `/tmp`, `/var/tmp`, and any `.ccache` directory
(the directories themselves included, not only their contents) always
resolve inside the sysroot. Pinning these prefixes keeps a name from
splitting between host and guest depending on the verb, and keeps a `/tmp`
listing from showing host entries its own child lookups cannot reach. The
rule applies to the lexically normalized path, so non-canonical spellings
such as `//tmp/x` or `/tmp/../tmp/x` resolve inside the sysroot as well.

### Symlink Containment

A realpath check stops a symlink inside the sysroot from redirecting an
in-sysroot lookup to an arbitrary host file, and
`path_check_relative_sysroot_containment` applies the same check to
dirfd-relative names. Both checks are check-then-use symlink hardening, not
sandboxing: the guest runs in the host user's trust domain, and no isolation
is provided or intended.

### Consequences Of Existence Dispatch

Because dispatch depends on what the image ships, a host binary can shadow a
path the image does not provide (PATH ordering decides which spelling of a
tool wins), and host configuration files are visible to guests that omit
their own. This host visibility follows directly from dispatching on
existence.

## The Translation Pipeline

`path_translate_at` (`src/syscall/path.c`) is the single forward resolver.
It applies, in order: `/proc` resolution, FUSE resolution, the sidecar
reserved-name guard, sysroot prefixing (in follow, nofollow, or create
flavor), the relative containment recheck, and the sidecar lookup. It fills
a `path_translation_t` with three views of the same path:

| View | Meaning | Correct consumer |
|---|---|---|
| `guest_path` | the path in guest namespace | guest-visible bookkeeping |
| `intercept_path` | the intercept-matching path | `/proc`, `/dev`, `/sys`, FUSE handlers |
| `host_path` | the actual macOS path | every host syscall, no exceptions |

Two rules govern every consumer:

- After translation, the raw guest string is dead: a host syscall receives
  `host_path` (or a host fd) and nothing else. Under a casefold sysroot a
  guest-created file exists on disk only under its sidecar token, so any
  other spelling misses the file.
- Any host-derived path that becomes guest-visible (host `getcwd`,
  `F_GETPATH`, readdir names) goes through `path_host_to_guest`, which
  strips the sysroot prefix and reverse-maps token components. Prefix
  arithmetic alone would leak token spellings into the guest.
- `path_host_to_guest` inverts the sysroot leg only. The `/dev/shm` redirect
  and FUSE materialization are not reversible through it, and a host path
  from either leg comes back unchanged, so a caller publishing one of those
  to the guest carries the guest spelling forward instead of reversing it.

Companion helpers keep the shared policies in one place:
`path_translation_relative_fast_path` handles the `AT_FDCWD` relative fast
path, and `path_resolve_empty_at` handles `AT_EMPTY_PATH` resolution with
FUSE and `/proc` interception. AF_UNIX socket addresses carry paths outside
the normal argument convention and have their own entry point in the socket
layer, described in [AF_UNIX Socket Addresses](#af_unix-socket-addresses).

## Case Handling And The Sidecar

A Linux guest expects case-sensitive, byte-exact names; the default APFS
volume folds case. At startup `sysroot_probe_case_sensitivity`
(`src/core/sysroot.c`) probes the sysroot volume once, and the resulting
casefold flag decides whether the sidecar (`src/syscall/sidecar.c`), the
subsystem that emulates case-sensitive naming on a case-insensitive volume,
is active: it runs iff a sysroot is set and the volume folds case. Both the
flag and the sidecar state travel to forked children over the fork IPC.

- Case-insensitive volume (default APFS): guest-created names are stored as
  `.ef_<16 hex>` token files, with the real name recorded in the
  per-directory `.elfuse_case_index`. Host-staged names keep their real
  spelling and are matched byte-exactly, so a wrong-case lookup returns
  ENOENT exactly as on Linux.
- Case-sensitive volume (a `--create-sysroot` sparsebundle, or any volume
  that probes sensitive): the sidecar is inert and paths are plain
  byte-exact host names.

Guest-visible behavior must not depend on the mode; the mode only changes
the on-disk representation. Paths that fall through to the host live on the
host volume with the host's case semantics; that mix is inherent to the
transparent-overlay model.

Two rules follow from the index being a mapping rather than a gate.

A name the index does not describe keeps its on-disk spelling. Lookup falls
back to the literal name whenever no row matches, which is exactly what lets
a host-staged file be opened, and a directory listing passes the same name
through for the same reason. This holds even for a name shaped like a sidecar
token: with no row to map it, `.ef_<16 hex>` is an ordinary file that the
guest can stat and open under that spelling, so hiding it from a listing
would make a reachable file impossible to enumerate. Directory listings and
inotify event names follow this rule identically, so a listing, an event, and
a lookup never disagree about what a directory contains.

If a directory's index exists but cannot be read, the operation fails instead
of falling back. Treating an unreadable index as an empty one would report
every mapped child under a spelling the guest has never seen, and for a watch
it would diff as though those children had been deleted. A listing therefore
reports the error, and a watch discards the snapshot and keeps its previous
baseline so the next successful snapshot reconciles.

## AF_UNIX Socket Addresses

A Unix-domain socket is named by a filesystem path, but that path never
reaches the generic path-taking handlers: it is embedded in
`struct sockaddr_un` at byte offset 2 and measured by the caller's
`addrlen` rather than by a NUL terminator. The socket layer therefore
extracts and translates the path itself, in `net_sockaddr_to_mac`
(`src/syscall/net-absock.c`) on the way to the host and
`net_sockaddr_from_mac` on the way back. Both pipeline rules above still
hold: the host call receives `host_path`, and host-derived paths return to
the guest through `path_host_to_guest`.

### Pathname Sockets

A pathname socket (its `sun_path` does not begin with a NUL byte) carries a
real filesystem path and goes through `path_translate_at` like every other
path; passing the raw bytes would name an unrelated host file outside the
sysroot. `bind` takes one extra step: the sidecar lookup is skipped under
create semantics, so translating the whole path would miss a tokenized
parent directory. The handler translates the parent directory (picking up
any sidecar token) and reattaches the final component verbatim, because a
socket keeps its real name and socket names are never tokenized.

A reattached leaf never passes through the pipeline, so it would also miss
the reserved-name guard listed above. The handler applies that guard to the
leaf itself: binding a sidecar bookkeeping name reports ENOENT, the answer
`stat` and `open(O_CREAT)` already give for it, rather than colliding with
the real index file.

### Path Length Limits

`sun_path` holds 108 bytes on Linux but only 104 on macOS, and sysroot
prefixing makes the translated path longer still, so a legal guest path
routinely does not fit the host struct. `absock_shorten_path` absorbs the
difference: it creates a short symlink in a private per-instance directory
pointing at the over-long host path and hands the kernel the symlink
instead. On macOS a `bind` through the symlink creates the socket at the
link target and a `connect` follows it (verified on macOS 15), so the
socket physically lives at the long path while the kernel only ever handles
the short name.

### Abstract Sockets

An abstract socket (its `sun_path` begins with a NUL byte) lives in a
Linux-only kernel namespace with no filesystem presence and no macOS
equivalent, so elfuse emulates it with real files. The abstract name is
hex-encoded into a filename inside a per-instance `/tmp/elfuse-absock-<id>`
directory, a fixed table maps each abstract name to its on-disk file, and
the file is unlinked when the owning descriptor closes, matching the way an
abstract socket disappears with its last reference. The directory is
created through `create_private_dir` (`src/utils.h`), which rejects a
pre-planted symlink or a foreign-owned directory in world-writable `/tmp`.

### Reverse Translation

Reading an address back (`getsockname`, `getpeername`, `recvmsg`) reverses
each step: `net_sockaddr_from_mac` undoes the shortening symlink with a
`readlink`, maps the host path into the guest namespace through
`path_host_to_guest`, and writes the Linux `sockaddr` directly. Writing the
Linux form directly matters because the guest may have bound a Linux-legal
name longer than the 103 usable bytes of a macOS `sun_path`; rebuilding a
host `sockaddr` first would reject it.

### Socket Directory Lifecycle

The `/tmp/elfuse-absock-<id>` directory holds both the abstract-socket
files and the pathname shortening links. Its `<id>` is the root guest's
namespace id, which forked children inherit over the fork IPC, so one
directory is shared across a forked guest tree.

Exit cleanup is registered once, when the directory is first created, so it
covers every producer of on-disk state, and it is split three ways.

Every process unlinks its own table-tracked abstract-socket files. A forked
child starts from an empty table, because fork hands over only the namespace
id, so a process never unlinks a sibling's socket this way.

Only the process whose pid equals the namespace id sweeps the untracked
shortening links, and the sweep covers symlinks alone. Restricting it to the
creator keeps a departing sibling from deleting links a live sibling still
needs; restricting it to symlinks keeps the owner from deleting an
abstract-socket file that a child which outlives it still has bound. A
sibling that loses a shortening link degrades to the raw host link path in
its `getsockname` until the next `bind` or `connect` recreates it, which is
recoverable; losing the socket file itself would not be.

Any process may remove the directory, not only the owner. `rmdir` succeeds
only once the directory is empty, so the last participant out retires it and
a namespace whose directory was created by a forked child does not leak.

## Testing

The `test-path-matrix` suite (`tests/test-path-matrix.c`) enforces the two
translation-pipeline rules. The `test-path-matrix-fold` and
`test-path-matrix-sensitive` lanes run the same expectations on a
case-insensitive and a case-sensitive sysroot volume respectively, holding
the contract that guest-visible behavior is mode-independent, and
`tests/check-sidecar-state.sh` asserts the on-disk index and token contract
from the host after each run.

Two narrower lanes cover the index rules above, both of which need the host to
stage state the guest cannot produce for itself. `test-sidecar-orphan` stages a
token-shaped file with no index row beside an ordinary host-staged file and
asserts both are listed and both resolve, which is what separates passing an
unmapped name through from hiding whatever the index does not name.
`test-inotify-index-fail` makes a watched directory's index unreadable between
the baseline and the next snapshot, and asserts no child is announced as
deleted; the guest signals readiness on stdout and waits on a host-staged
sentinel, because the failure has to begin after the baseline is taken.

Known limitations are tracked as expected failures, with the XFAIL ids
listed in the header comment of `tests/test-path-matrix.c`. The qemu lane
runs the same binary in native mode, where each of those cases must pass,
so the expected-failure table stays checked against a real Linux kernel.
