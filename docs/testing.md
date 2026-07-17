# Building And Testing

This document describes the development toolchain, the main `make` targets, and
how the repository validation flow is structured.

## Build Requirements

Host build requirements:

- Apple Silicon macOS host
- macOS 13 or newer
- Xcode Command Line Tools
- `clang`
- `codesign`
- GNU `make`
- GNU `objcopy` or `llvm-objcopy`
- GNU coreutils
- `bash` 3.2+ (the version Apple ships as `/bin/bash`) is sufficient for
  the test harness; no Homebrew `bash` is required. See
  `tests/lib/bash-compat.sh` for the cross-version shims (a portable
  microsecond clock and the parallel-array lookup pattern that replaces
  associative arrays). When editing a shell script under `tests/` or
  `scripts/`, the conventions in that file's header are the source of
  truth: no `EPOCHREALTIME`, no `declare -A`, no `mapfile`, no
  `${var^^}` / `${var,,}` case-conversion, and guard any potentially
  empty array expansion with `${arr[@]+"${arr[@]}"}` so `set -u` does
  not trip on it.
- Hypervisor entitlement: `com.apple.security.hypervisor`

Guest test builds additionally require:

- An AArch64 Linux cross-compiler for C test programs
- An AArch64 bare-metal toolchain for the assembly smoke test

The toolchain defaults are defined in `mk/toolchain.mk`. 
These variables are intended to be overridden when needed:

- `CROSS_COMPILE`
- `BAREMETAL_CROSS`
- `SIGN_IDENTITY`

### Installing the toolchains with Homebrew

The following block installs everything needed to run both `make check` and
the full `make test-matrix` (including the `qemu-aarch64` reference run). Run it
once on an Apple Silicon macOS host:

```sh
# GNU coreutils (gtimeout) — required by the test harness timeout wrapper
brew install coreutils

# GNU objcopy
brew install binutils

# Bare-metal aarch64-none-elf toolchain used by `make check`
brew install --cask gcc-aarch64-embedded

# AArch64 Linux cross-compiler for guest test binaries (make test-matrix)
brew tap messense/macos-cross-toolchains
brew trust --formula messense/macos-cross-toolchains/aarch64-unknown-linux-gnu
brew install aarch64-unknown-linux-gnu

# QEMU — boots the Alpine minirootfs for the qemu-aarch64 reference run
brew install qemu
```

Depending on your setup, you might need to add the following to your PATH
```
export PATH="/opt/homebrew/opt/aarch64-elf-gcc/bin:$PATH"
```

## Main Targets

The most useful development targets are:

```sh
make elfuse
make check
make test-rosetta-all
make test-gdbstub
make test-matrix
make lint
make clean
```

What they do:

- `make elfuse`: build and sign `build/elfuse`
- `make check`: fast elfuse-internal gate. Runs, in order:
  - `scripts/check-syscall-coverage.py` so any new `dispatch.tbl`
    entry without a direct or aliased test reference fails the build
  - the unit suite from `tests/manifest.txt` -- deliberately narrow: only
    tests that assert elfuse-internal implementation details with no real
    Linux counterpart (the EL1 shim fast-path suite, `test-mremap-infra`,
    `test-oom-proc`), plus whatever `mk/tests.mk`'s `SANITIZER_SECTIONS`
    needs for the `check-{asan,ubsan,tsan}` lanes. Everything that is
    meaningful to cross-check against a real Linux kernel lives exclusively
    in `tests/test-matrix.sh`'s `run_unit_tests` instead (see Test Matrix
    below) -- `make check` alone is *not* a substitute for it
  - the TLBI RVAE1IS encoder unit test
  - the proctitle argv-tail and low-stack regressions
  - the BusyBox applet smoke suite (auto-resolved from
    `externals/test-fixtures/aarch64-musl/staticbin/bin/busybox` or
    downloaded into `build/busybox` on first run)
  - the sysroot procfs exec, FUSE-on-Alpine, and `timeout=0` regressions
  - the Rosetta CLI gating regressions
  - the hot-syscall guardrail (`tests/test-bench-guardrail.sh`)
    asserting `getpid`, libc `clock_gettime`, and 1-byte
    `/dev/urandom` reads stay under their ns/op ceilings
  - the LTP harness selftests (`make test-ltp-harness`), hermetic Python
    unit tests plus an exit-code contract smoke; they need no LTP
    fixture, cross toolchain, or network
- `make test-rosetta-all`: Rosetta-specific x86_64 acceptance scripts
  (`test-rosetta-cli`, `test-rosetta-failure-modes`,
  `test-rosetta-statics`, `test-rosetta-alpine`,
  `test-rosetta-audit`, `test-rosetta-jit`, `test-rosetta-glibc`)
- `make test-busybox`: just the BusyBox suite, useful when iterating on a
  single applet failure without rerunning the unit suite
- `make test-fuse-alpine`: validate guest `/dev/fuse` + `mount("fuse")`
  against the Alpine musl sysroot fixture
- `make test-gdbstub`: debugger integration checks against the built-in GDB stub
- `make test-matrix`: cross-check `elfuse` (aarch64), QEMU (aarch64),
  and `elfuse` (x86_64-via-Rosetta) on overlapping corpora
- `make build-ltp-fixture`: explicitly download, verify, and cross-build
  the pinned LTP + kirk conformance fixture
- `make test-ltp`: run the selected LTP tier in the QEMU Linux reference,
  then through elfuse, gated against the recorded baselines
- `make lint`: static analysis through `clang-tidy`

## Quick Iteration

For normal code changes touching syscall or runtime logic:

```sh
make elfuse
make check
make test-matrix-elfuse-aarch64
```

`make check` alone only covers elfuse-internal plumbing and the sanitizer
subset now; `test-matrix-elfuse-aarch64` is what actually exercises the full
unit-test surface against `build/elfuse` (no qemu boot needed, so it is about
as fast to iterate with as `make check` was before the split). For changes
that touch procfs, path handling, `/dev`, FUSE, networking, dynamic linking,
or guest process semantics, also cross-check against the qemu reference
kernel:

```sh
make test-matrix-qemu-aarch64
```

or run all matrix modes back-to-back with `make test-matrix`.

`make check` already runs the BusyBox applet suite as a second stage, so a
green `make check` covers BusyBox validation. Use `make test-busybox` to
iterate on a single applet failure without rerunning the unit suite.

## Test Matrix

The matrix driver lives in `tests/test-matrix.sh`. It currently covers three
execution modes:

- `elfuse-aarch64`: every binary is executed via `build/elfuse` on macOS
- `qemu-aarch64`: the same binaries run natively inside an Alpine
  `aarch64-linux-musl` minirootfs booted by `qemu-system-aarch64`
- `elfuse-x86_64`: Rosetta-for-Linux acceptance scripts against the staged
  Alpine x86_64 fixture tree

The goal is not to compare performance. The goal is to compare guest-observable
behavior against a ground-truth Linux AArch64 environment so that any divergence
in syscall translation, procfs emulation, or process semantics is caught early.

`run_unit_tests` in `tests/test-matrix.sh` is the full aarch64 unit-test
surface -- every binary that is meaningful to run against a real kernel, which
is almost everything. It deliberately excludes only the handful of tests that
assert elfuse-internal implementation details with no meaningful counterpart
on a real kernel (the EL1 shim fast-path suite, `test-mremap-infra`,
`test-oom-proc` -- these live solely in `tests/manifest.txt` / `make check`,
see that file's header for the full split rationale). There is no separate
"core" vs "extended" test set inside the matrix; a test that has a real,
understood divergence from the qemu reference kernel is listed in
`QEMU_SKIP` with a comment explaining why instead -- see that variable in
`tests/test-matrix.sh` for the current list and rationale. `run_unit_tests`
runs in both `elfuse-aarch64` and `qemu-aarch64` modes, so most tests are
exercised twice per matrix run: once against `build/elfuse`, once against the
real kernel.

The x86_64 mode is narrower: it aggregates the Rosetta-specific acceptance
scripts and their per-binary summaries into the same matrix runner, including
the Rosetta thread/signal audit smoke, the LuaJIT guest-JIT probe, and the
glibc dynamic-binary acceptance helper.

Run a single mode with `bash tests/test-matrix.sh elfuse-aarch64`,
`bash tests/test-matrix.sh qemu-aarch64`, or
`bash tests/test-matrix.sh elfuse-x86_64`; `all` runs all three back-to-back.

Fixture handling is self-contained:

- On first use, `tests/fetch-fixtures.sh` downloads the required Alpine
  packages and the `linux-virt` kernel into `externals/test-fixtures/` and
  assembles an initramfs. Subsequent runs are zero-config.
- The same fixture tree is reused across the matrix modes.
- When Rosetta mode is requested and the translator is installed,
  `tests/test-matrix.sh` auto-fetches the x86_64 fixture tree
  (`INCLUDE_X86_64=1`) on demand.
- QEMU mode requires `qemu-system-aarch64` on `PATH` (Homebrew `qemu` provides it).
- musl is the only Alpine libc; the glibc-dynamic suite is skipped unless
  `GUEST_GLIBC_*` environment variables point at an external sysroot.

## Linux Test Project syscall conformance

The opt-in LTP lane runs unmodified, pinned Linux Test Project binaries
through kirk (LTP's official runner; upstream removed `runltp`) against
two backends: the QEMU Alpine reference VM as ground truth, and elfuse
loading the same AArch64 glibc binaries. It deliberately exercises the
dynamic-binary stack (glibc loader, symbol versions, library search)
before any syscall assertion can run. The full internals, including the
kirk integration, both execution paths, and the result model, are in
`docs/ltp-conformance.md`; this section is the operating manual.

The fixture is locked in `tests/ltp/pin.json`: LTP release `20260529`
(commit `3a64d78f`) verified against both the pinned sha256 and the
release's official checksum asset, and kirk `v4.1.0` by tarball sha256.
Everything generated stays under `externals/test-fixtures/ltp-aarch64/`,
which is ignored by Git and reaped by `distclean`: the LTP payload and
kirk are GPL-covered external fixtures and must never be committed to
the Apache-2.0 tree.

Prerequisites: the `CROSS_COMPILE` AArch64 GNU/Linux toolchain, Python 3,
and QEMU plus the boot fixtures (`bash tests/fetch-fixtures.sh`) for the
reference backend. Build and check the fixture explicitly:

```sh
make build-ltp-fixture
python3 tests/ltp/harness.py verify-fixture
```

Run the lane:

```sh
make test-ltp-qemu            # reference VM only
make test-ltp-elfuse          # elfuse only
make test-ltp                 # QEMU must fully pass before elfuse runs
make test-ltp LTP_TIER=extended
make test-ltp-elfuse LTP_TIER=fast LTP_TEST=readv01
```

`fast` is the bounded gate; `extended` adds socket-message, process
state, exec, interval-timer, and exit-group coverage; `nightly` holds
the slower OFD-lock, CPU-time, and process-group cases; `all` selects
everything. `LTP_TEST` selects one manifest test and must match the
requested tier (or `LTP_TIER=all`); an unknown id is an error, never a
silent skip. `LTP_TIMEOUT_MUL=2` scales every enforcement layer at once
(LTP's own watchdog, the QEMU supervisor, kirk's exec timeout, the SSH
caps). Results land under `build/ltp-results/<run>/` as kirk JSON (full
per-test output), a machine-readable gate diff, and JUnit XML.

Results are gated against committed per-subtest baselines
(`tests/ltp/baseline-{elfuse,qemu}.json`), snapshots of current behavior
keyed by each LTP result line's `file.c:line` with counts per result
type. The gate fails only on movement: a known-BROKEN test staying
BROKEN is green, a regression is red, and an improvement is also red
until `make record-ltp-baseline` refreshes the snapshot in the same
change, so the baselines never rot. Baselines embed the pin; bumping
`tests/ltp/pin.json` forces a rebuild and a reviewed re-record. To add a
test, extend `tests/ltp/manifest.json`, rebuild the fixture, run both
backends, and commit the manifest with the recorded baseline diff.

### Current conformance baseline and next steps

The QEMU reference passes every selected case (24 PASS, 50 recorded
subtest keys). The elfuse baseline, recorded on 2026-07-18 after the
`/dev/shm` path-translation fix and the namespace-wide PID/TID
allocation and WIFSIGNALED fixes, records 9 PASS, 5 FAIL, and 10
BROKEN. The two former universal blockers are gone:

- The `/dev/shm` open-vs-chmod split (`tst_test.c:144` ENOENT) was fixed
  by centralizing the redirect in `path_translate_at` (regression-tested
  by `tests/test-dev-shm-paths.c`), which moved every entry to the next
  barrier.
- That next barrier, the nested-fork guest-PID collision, is also fixed:
  a fork child re-ran `proc_init` and restarted PID allocation from 2, so
  a grandchild reused its parent's PID and the LTP heartbeat
  `kill(getppid(), SIGUSR1)` killed the test child itself
  (`tst_test.c:1936: Child returned with 138`). PIDs and TIDs now come
  from a namespace-wide cursor, directed `kill` resolves ancestors
  through the process registry, and a guest signal death is reported as
  WIFSIGNALED (so LTP's own timeout/signal detection works). Nine tests
  now pass.

What the pass-through exposed, as the honest next barriers (each
annotated in `baseline-elfuse.json`):

- errno parity: `readv02`, `preadv02`, `pwritev02`, and `writev01`
  accept invalid iovecs/offsets/lengths that Linux rejects with
  EINVAL/EFAULT.
- `recv01` FAIL: `MSG_ERRQUEUE` is dropped (recv returns 0 instead of
  -1). `epoll_wait03` FAIL: an epoll readiness/permission divergence.
- procfs gaps: `/proc/<pid>/stat` of another process (`futex_wait02`),
  `/proc/self/stat` sleeping state (`futex_wait03`), and
  `/proc/sys/kernel/pid_max` (`setpgid02`) are not emulated.
- `execve01` loses the LTP shm IPC region across `execve` (bad magic);
  `fcntl36` hits `pthread_create` EAGAIN under its thread fan-out;
  `setpgid03` times out on a `tst_checkpoint` futex; `recvmsg01`,
  `setitimer01`, and `times03` pass their assertions but do not
  terminate cleanly within the deadline.

The tmpdir-removal warning (`tst_tmpdir.c` TWARN) is cosmetic (tests
still pass). Its primary cause is the directory `st_nlink` gap described
in the list below: elfuse reports the host directory link count, which
APFS computes differently from Linux. On a case-insensitive sysroot the
case-fold sidecar shadow entries inflate the count further, so the
warning is loudest there and is avoided by a case-sensitive sysroot
(`--create-sysroot`); but the durable fix is a directory-link-count
translation in `translate_stat`, which corrects both sysroot kinds.

The remainder of this subsection records each gap and the reason elfuse
diverges from Linux. Every item is an elfuse divergence, not a test
defect: the QEMU reference lane passes all 24. Locations are given as
`file` or `file:function` in the elfuse tree.

Vector I/O accepts an over-long iovec (`readv02`, `preadv02`,
`pwritev02`, `writev01`). Linux rejects any iovec whose `iov_len` exceeds
`SSIZE_MAX` (it is negative read as `ssize_t`) with EINVAL, before any
transfer. elfuse instead clamps the length to the bytes available in the
guest buffer and performs a short, successful transfer. The correct
check already exists as `validate_iov_total` in `src/syscall/io.c`, but
it is wired only into the `FD_URANDOM` readv path; the scalar
`iovcnt == 1` fast paths of `sys_readv`/`sys_preadv`/`sys_pwritev` and the
multi-iovec `sys_writev` path (through `build_host_iov`, which clamps
rather than rejects) skip it. Reason: elfuse treats a too-large length as
"transfer as much as fits" where Linux treats it as a malformed argument.

A read-only anonymous mapping is installed writable (`epoll_wait03`). The
test registers an always-ready `EPOLLOUT` fd and passes a `PROT_READ`
page as the `events` buffer, so `epoll_wait` must copy an event into a
non-writable page and Linux returns EFAULT. The divergence is not in
epoll (`sys_epoll_pwait` copies out through `guest_write_small` and would
fault correctly); the anonymous branch of `sys_mmap` in
`src/syscall/mem.c` hardcodes the page permission to read-write instead
of deriving it from `prot` via `prot_to_perms` (which the high-VA path
uses), so the `PROT_READ` buffer is actually writable and the copy-out
succeeds, returning 1. Reason: a missing `prot`-to-permission mapping on
one mmap path silently grants write access.

A broken-pipe write raises a host SIGPIPE (`writev01`, secondary). The
test blocks SIGPIPE and expects `writev` to a closed pipe to return
EPIPE. elfuse does emulate a maskable guest SIGPIPE from a host EPIPE in
`io_write_result`, but host pipe fds are created without `F_SETNOSIGPIPE`
and the vCPU thread does not ignore host SIGPIPE, so the host delivers
SIGPIPE and terminates the child before the emulation runs; sockets avoid
this with `SO_NOSIGPIPE`, but pipes have no equivalent. Reason: the
guest-visible signal path is correct, but a host signal fires first. The
death is now faithfully reported as WIFSIGNALED (see the wait-status
fix), which is why this surfaces as a signal kill rather than EPIPE.

`MSG_ERRQUEUE` is dropped (`recv01`, `recvmsg01`). `translate_msg_flags`
in `src/syscall/net-abi.c` does not map Linux `MSG_ERRQUEUE`, and there
is no socket error-queue emulation, so a receive that should drain the
error queue (or return EAGAIN when it is empty) performs an ordinary
receive and returns 0. Reason: an unmapped flag becomes a no-op rather
than an error, and the feature it selects is unimplemented.

Directory `st_nlink` is passed through from the host (`recvmsg01`
teardown, and the tmpdir warning above). `translate_stat` in
`src/syscall/fs-stat.c` copies the macOS `st_nlink` verbatim. APFS does
not follow the traditional Unix convention where a directory's link
count is 2 plus its subdirectory count; a directory holding one regular
file reports `st_nlink == 3` where Linux reports 2. LTP's `rmobjat` uses
`st_nlink >= 3` to decide a directory still has subdirectories and calls
plain `unlink` on it, which returns EPERM. Reason: elfuse reports a host
link count that the guest interprets under Linux rules.

procfs process state is partial (`futex_wait02`, `futex_wait03`,
`setpgid02`). elfuse emulates `/proc/self` for the calling process only:
`proc_alias_self` in `src/runtime/procemu.c` rewrites `/proc/<pid>` to
`/proc/self` only when `<pid>` is the caller, so `/proc/<other-pid>/stat`
falls through to the absent sysroot and returns ENOENT (`futex_wait02`
reads its parent's stat). Where `/proc/self/stat` is emulated, its
process-state field is a constant `R`, never `S`, so a test waiting for a
peer to enter a sleeping/futex-wait state spins forever (`futex_wait03`).
And `/proc/sys/kernel/pid_max` is not provided at all (`setpgid02`).
Reason: elfuse models a single observable process with a static running
state, while these tests observe other processes and dynamic scheduling
state.

`/dev/shm` shared writes do not reach the host backing file across
`execve` (`execve01`). LTP hands its shm IPC region to an exec'd child
through `$LTP_IPC_PATH`: the child re-opens the `/dev/shm` file and mmaps
it. elfuse backs `/dev/shm` with host files, but a parent's `MAP_SHARED`
writes stay in guest-private memory and never reach the host inode
(verified: the backing file is all zeros after a run). `execve` then
resets guest memory, and the child's fresh mmap of the file reads zeros,
so the IPC magic check fails. Reason: the shared mapping is not
write-through to its host file, so it does not survive the exec the way a
real tmpfs mapping does. (Deterministic guest pids also reuse the shm
filename between runs, so a later `O_CREAT | O_EXCL` can EEXIST.)

The guest thread table is fixed at 64 slots (`fcntl36`). The test sizes
its worker pool from the host CPU count and needs on the order of 90
threads alive at once on a barrier (about `cpus * 3 * 3` on a 10-CPU
host). elfuse's thread table (`MAX_THREADS` in `src/runtime/thread.h`)
holds 63 workers, and `sys_clone_thread` returns EAGAIN once full.
Reason: a fixed guest thread ceiling below a CPU-scaled test's peak;
deterministic on hosts with eight or more CPUs, and not a leak.

Interval timers are not delivered to a syscall-free loop (`setitimer01`,
`times03`). elfuse evaluates the guest `ITIMER_REAL`/`alarm` only at
syscall boundaries, through `signal_check_timer` in `src/syscall/signal.c`.
Both tests arm a timer and then spin in a compute loop that issues no
syscalls, so the poll is never reached; the only asynchronous host timer
is the coarse per-run watchdog, which on firing exits rather than
delivering the guest SIGALRM. Reason: there is no periodic preemption
tick to drive timer evaluation while the guest runs EL0 code, so `alarm`
and `setitimer` do not interrupt a busy loop.

Futexes are not shared across processes (`setpgid03`). LTP's
`tst_checkpoint` is a `FUTEX_WAIT`/`FUTEX_WAKE` on a word in a
`MAP_SHARED` `/dev/shm` region shared across a fork. elfuse forks are
separate host processes, but the futex wait queues are process-local
(`src/runtime/futex.c` keys its buckets by guest virtual address, and the
fast path uses a host-process-local address wait), so a child's wake
never finds the parent's waiter and the checkpoint times out. Reason:
elfuse models process-private futexes only; a cross-process futex over
shared memory has no rendezvous. This is the shared cause for any
`tst_checkpoint`-across-fork test.

Work the remaining barriers in this order, never editing the manifest or
baselines merely to hide a step:

1. Done: centralize the `/dev/shm` backing-path translation.
2. Done: namespace-wide PID/TID allocation, directed-kill registry
   fallback, and WIFSIGNALED wait-status reporting.
3. Close the errno-parity gaps in the readv/writev/preadv/pwritev
   validators and implement `MSG_ERRQUEUE`. Exit criterion: the
   `readv02`, `preadv02`, `pwritev02`, and `recv01` FAIL entries record
   PASS; `writev01` is BROKEN rather than FAIL because it also dies on
   the secondary host SIGPIPE, so it needs that fix (below) before it
   can pass.
4. Provide truthful dynamic process state for the two futex procfs
   probes and a real read-only `pid_max`. Exit criterion: the three
   affected tests record real assertion passes.
5. Translate directory `st_nlink` in `translate_stat` (clears the tmpdir
   cleanup warning), then work the remaining process/thread/exec BROKEN
   entries: the interval-timer preemption tick, process-shared futex,
   `/dev/shm` write-through across exec, and the thread ceiling.
6. After each step, rerun QEMU before elfuse and record; keep any newly
   exposed divergence red by default and fix or document it under an
   issue reference in the baseline entry before recording.
7. Once fast and extended are stable across repeated serial runs,
   qualify nightly, then grow the manifest (a zero-length blocking
   `recv` case is a good next addition; legacy `recv01` does not cover
   it).

## Rosetta Limitations

`elfuse-x86_64` is expected to inherit two Rosetta-internal limitations that are
not treated as elfuse regressions:

- `SA_RESETHAND` is not reset reliably because Rosetta shadows guest signal
  handler state internally.
- `clone(..., CLONE_SETTLS, tls=0, ...)` can hang.

The x86_64 matrix branch is therefore a Rosetta acceptance gate, not a claim
that translated guests fully match native Linux thread and signal semantics.

## x86_64 Acceptance Inventory and Per-Host Baselines

The `elfuse-x86_64` matrix mode aggregates seven sub-suites. Each one
emits a deterministic per-binary pass list; the matrix runner sums
those into a single `Results:` line and compares against a per-host
baseline. The exact labels each sub-suite emits, and the contract
they verify, are:

- `tests/test-rosetta-cli.sh` (4): `rosetta-disabled-flag`,
  `rosetta-disabled-env`, `rosetta-gdb`, `rosetta-default` --
  command-line gating of the translator path (opt-out flag, env
  override, `--gdb` rejection, install-hint surface).

- `tests/test-rosetta-failure-modes.sh` (3): `no-rosetta-flag`,
  `no-rosetta-env`, `gdb-x86_64` -- command-line rejection paths.
  Self-contained against a synthesized minimal x86_64 ELF; no
  external fixture tree required. The dynamic-linker bring-up and
  mid-process execve scenarios that used to live here are now
  exclusively in the glibc and statics suites against the vendored
  rootfs (see `glibc-hello` / `glibc-hello-via-ldso` and
  `env-execve`).

- `tests/test-rosetta-statics.sh` (20): `echo`, `true`, `false`,
  `printenv`, `expr-zero`, `expr-mul`, `basename`, `dirname`,
  `stat-self`, `factor`, `seq`, `sha256sum`, `md5sum`, `uname-m`, `arch`,
  `busybox-arch-subcommand`, `date-utc`, `id-u`, `nproc`,
  `env-execve` -- statically-linked Alpine busybox applets,
  exercising VZ ioctl gate, `/proc/self/exe` redirect, high-VA mmap,
  and the kbuf alias.

- `tests/test-rosetta-alpine.sh` (33): `cat-fruits-first-line`,
  `wc-l-fruits`, `wc-l-lines`, `wc-c-lines`, `ls-data`, `stat-data`,
  `find-by-name`, `du-sk-data`, `sha256-fruits`,
  `sha256-lines-matches-host`, `sha512-lines`, `md5-fruits`,
  `cksum-fruits`, `sort-first`, `sort-reverse-first`, `pipe-sort-wc`,
  `pipe-tr-uppercase`, `pipe-cat-grep`, `pipe-sed-subst`,
  `pipe-awk-field`, `head-n3`, `tail-n3`, `pipe-sort-uniq`,
  `pipe-cut-field`, `pipe-rev`, `tac-reverse-first-line`, `seq-1-5`,
  `seq-step`, `factor-prime`, `factor-composite`, `diff-identical`,
  `diff-differs`, `pipe-base64-decode` -- broader file I/O, text
  processing, and host-shell pipelines stitched through Rosetta on
  every stage.

- `tests/test-rosetta-audit.sh` (2): `audit-known-limitations`,
  `tls0-known-hang` -- bookkeeping probe that asserts the documented
  Rosetta shadowing failures (above) remain the only divergences;
  fails loudly if a new threading/signal-state edge case starts
  diverging.

- `tests/test-rosetta-jit.sh` (2): `luajit-trace`,
  `luajit-coroutine` -- guest-side JIT under translation
  (LuaJIT trace emission + coroutine allocation), covering the
  small-mprotect RW->RX and per-thread icache observation path that
  rosetta's own JIT does not exercise.

- `tests/test-rosetta-glibc.sh` (7): `glibc-hello`,
  `glibc-hello-via-ldso`, `glibc-hello-list`, `glibc-dlopen`,
  `glibc-tls`, `glibc-gdtls`, `glibc-pthread-tls` --
  dynamically-linked glibc x86_64 binary acceptance through
  `--sysroot` against the staged minimal glibc rootfs under
  `externals/test-fixtures/x86_64-glibc/rootfs/`. The first three
  cover load-time `PT_INTERP` resolution and `ld.so --list`
  introspection. `glibc-dlopen` runs `dlopen("libm.so.6")` plus a
  `dlsym(sqrt)` round-trip to exercise the runtime fresh-`.so`-mmap
  codepath, which is distinct from the load-time path the first
  three probes touch. `glibc-tls` reads and writes two
  initial-exec `__thread` variables (one integer, one pointer) so a
  broken FS-register to `TPIDR_EL0` translation surfaces as a
  value mismatch rather than as a silent skip. `glibc-gdtls`
  `dlopen`s a companion `libgdtls.so` whose `__thread` variable
  must use the general-dynamic model (calls `__tls_get_addr`);
  this is the only probe that exercises that lowering path, which
  the initial-exec probe cannot reach. `glibc-pthread-tls`
  `pthread_create`s a worker thread that reads and writes its own
  `__thread` slot; the probe asserts the worker saw its own
  default value (not the main thread's overwritten marker) and that
  the main thread's slot survives the worker's write, so a broken
  per-thread `TPIDR_EL0` setup on additional threads surfaces as
  isolation failure rather than as a silent crash.

Total: 71 expected passes, 0 expected failures.

### Per-Host Baseline Capture

The matrix runner keys its `elfuse-x86_64` baseline by detected host
SoC class. Two classes matter because `sys_mmap_fixed_high_va` takes
different paths under different IPA widths:

- `apple-m1-m2`: 36-bit native IPA, exercises the overflow-segment
  path. Captured on this codebase against Apple M1 hardware
  (MacBookAir10,1). The seven sub-suites land at 71/0/0.

- `apple-m3-plus`: 40-bit native IPA, exercises the bisected-slab
  path (and the M5 slab-bisection variant). Currently held equal to
  `apple-m1-m2` pending operator capture on real M3+ hardware. When
  that capture lands, only the
  `"elfuse-x86_64:apple-m3-plus|<min_pass>|<max_fail>"` row in the
  `EXPECTED_BASELINES` array in `tests/test-matrix.sh` moves; the
  M1/M2 row stays intact.

- `apple-unknown`: fallback for SoC brand strings the detector does
  not recognise. Inherits the M1/M2 numbers and triggers a one-line
  warning so a new SoC does not silently graft onto an existing row.

Class detection reads `sysctl -n machdep.cpu.brand_string` and matches
against `Apple M1`/`Apple M2` (M1/M2) and `Apple M3`/`Apple M4`/`Apple
M5` (M3+). To exercise the M3+ row from an M1/M2 host (and vice
versa) without changing the detector, set
`MATRIX_HOST_CLASS_OVERRIDE=apple-m3-plus` (or `apple-m1-m2`,
`apple-unknown`) before invoking `tests/test-matrix.sh`.

When the seven sub-suites grow or trim a test, the per-sub-suite
counts in the comment block above `EXPECTED_BASELINES` and the
inventory list above must move in the same commit so the per-host
baseline stays in sync with reality. Each `EXPECTED_BASELINES` entry
is a pipe-separated `mode-key|min_pass|max_fail` triple parsed by
`expected_baseline_get()` in `tests/test-matrix.sh`.

## Test Inventory

The repository contains several layers of validation:

- unit-style guest tests compiled from `tests/*.c`
- shell integration suites such as BusyBox, coreutils, and dynamic-loader tests
- debugger integration tests for the GDB stub
- native macOS HVF checks such as multi-vCPU and RWX validation

The quick suite is driven by `tests/driver.sh`, which supports:

- `-f PATTERN` to filter tests
- `-l` to list them
- `-T` for TAP output

Example:

```sh
bash tests/driver.sh -f test-proc
```

## Validation Strategy By Change Type

Suggested minimum validation:

| Change area | Recommended validation |
|-------------|------------------------|
| CLI, logging, docs-only build rules | `make elfuse` |
| General syscall or runtime logic | `make elfuse && make check && make test-matrix-elfuse-aarch64` |
| `/proc`, `/dev`, path, or BusyBox-sensitive behavior | `make elfuse && make check && make test-matrix-elfuse-aarch64` |
| Rosetta hosting, x86_64 dispatch, VZ ioctls, AOT cache | `make elfuse && make test-rosetta-all` |
| Broad behavioral changes | `make elfuse && make check && make test-matrix` |
| Debugger or ptrace flow | `make elfuse && make test-gdbstub` |
