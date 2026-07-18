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
make test-gvisor-conformance-qemu
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
- `make test-gvisor-conformance-qemu`: run the pinned gVisor syscall test
  binaries on the QEMU AArch64 Linux reference. The combined
  `make test-gvisor-conformance` adds the `elfuse` lane, which
  intentionally exits nonzero at the current baseline (see gVisor
  Syscall Conformance below)
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

## gVisor Syscall Conformance

The conformance lane runs unmodified gVisor syscall test binaries through
two backends and compares the outcomes: the QEMU AArch64 Linux reference
kernel provides the ground truth, and elfuse must match it. The payload is
built from gVisor at pinned commit
`c30a6d1b6f26b353ca5d6ff5a288d96ed820e89c` (master, 2026-07-15). The enabled
suites are the opt-in allowlist in `tests/conformance/gvisor/targets.txt`
(the reference-feasible single-process syscall tests; suites that need a
network stack, elevated privilege, namespaces, host `/proc`, or a pty are
declined there). gVisor and elfuse are both Apache-2.0 projects. The lane is
opt-in and separate from `make check` and the test matrix.

### Building the payload

```sh
make build-gvisor-tests
```

The build script clones `google/gvisor` at the pin into
`externals/gvisor/<pin>` (refusing to touch a dirty checkout), builds the
selected targets as fully static AArch64 binaries through gVisor's
supported Bazel make wrapper (`make copy` on Linux; `make build` plus
container artifact extraction on macOS), verifies every artifact with
`readelf`
(ELF64, AArch64, a loadable segment, no `PT_INTERP`, no `DT_NEEDED`), and
installs the result into `build/gvisor-tests`. The static link keeps
`--eh-frame-hdr` (`PT_GNU_EH_FRAME`) so that `pthread_cancel` and thread-exit
stack unwinding resolve their frames; without it the fully-static binaries
abort at teardown in any test that cancels or joins a thread.

On macOS the wrapper runs Bazel inside Docker, so a running Docker daemon
and GNU xargs (`brew install findutils`) are required. The macOS Bazel
cache must stay in a Docker volume (a bind-mounted cache breaks Bazel's
sandbox on virtiofs), so the script extracts the artifacts from the build
container with `docker cp`. On Linux hosts with a native Bazel, set
`GVISOR_DOCKER_BUILD=false` to build without Docker; this is what CI does.
Override the checkout with `GVISOR_CHECKOUT`, the output directory with
`GVISOR_TESTS_DIR`, and the `readelf` used for validation with
`GVISOR_READELF`.

### Running the lane

```sh
make test-gvisor-conformance-qemu
make test-gvisor-conformance-elfuse
make test-gvisor-conformance       # QEMU reference first, then elfuse
```

The runner can also be invoked directly:

```sh
tests/run-gvisor-conformance.sh qemu-aarch64
tests/run-gvisor-conformance.sh elfuse-aarch64
tests/run-gvisor-conformance.sh all
```

A missing payload directory is reported as a skip with the build command;
nothing is downloaded implicitly. All modes require Python 3.9+ and GNU
`timeout` (Homebrew coreutils provides `gtimeout`); QEMU mode additionally
requires `qemu-system-aarch64` and the normal repository test fixtures. The
runner aligns locale, timezone, working directory, scratch and `GTEST_*`
variables, umask, and resource limits on both backends, and runs the QEMU
reference guest with `QEMU_MEM=6144` (some tests, e.g.
`ReadvTestNoFixture.TruncatedAtMax`, allocate ~2 GiB and fault on the
default 2 GiB guest). This is scoped to the lane; the general test matrix is
unaffected.

Execution is whole-binary batched: each binary is first listed with
`--gtest_list_tests` and strictly parsed, then executed once with XML
output under `GVISOR_SUITE_TIMEOUT` (default 600 s), and every planned test
is classified from the XML with an exit-code cross-check. When a binary
crashes, times out, or produces inconsistent output, the unresolved tests
are re-run one at a time with `--gtest_filter` under `GVISOR_CASE_TIMEOUT`
(default 30 s), so a mid-suite crash is attributed to the exact test that
caused it instead of hiding the results of the others.

### Expectations

`tests/conformance/gvisor/expectations.tsv` holds one row per test per
backend and must exactly cover the discovered listing; wildcard rows,
duplicate rows, and stale rows are all rejected. The states are:

- `PASS`: a well-formed passing test with the matching exit status
- `SKIP`: a legitimate environment skip reported by GoogleTest, with a
  concrete reason
- `XFAIL`: an expected assertion failure with a concrete reason and an
  issue or reference; only a clean, well-formed failure satisfies it
- `EXCLUDE`: the test is not executed on that backend at all, with a
  concrete reason. Reserved for tests that are unusable against the
  reference itself, for example tests that crash the reference kernel in
  this environment.

A passing XFAIL is `XPASS` and fails the lane because the baseline is
stale. Crashes, signals, timeouts, transport errors, and malformed output
are always fatal and cannot satisfy `XFAIL`. Do not add `XFAIL` or
`EXCLUDE` rows just to make a newly exposed elfuse semantic difference
green.

The manifest is bootstrapped from the reference backend rather than written
by hand:

```sh
GVISOR_BOOTSTRAP=1 tests/run-gvisor-conformance.sh qemu-aarch64
python3 tests/lib/gvisor_conformance.py expectations-init \
    --root build/gvisor-conformance-results/<run-id> \
    --output tests/conformance/gvisor/expectations.tsv
```

`expectations-init` turns the observed reference results into draft rows
and marks everything that needs human judgement with `REVIEW`; review and
resolve every marker before committing the manifest. The same procedure
applies on a pin bump: rebuild the payload, re-bootstrap on QEMU, and
review the manifest diff.

### Results

Complete per-test stdout, stderr, XML, process metadata, and human logs are
kept under `build/gvisor-conformance-results/<run-id>/`, along with
aggregate JSON and JUnit output per backend and overall. Set
`GVISOR_RESULTS_DIR` to choose another results base; the runner still
creates a unique run-id directory beneath it.

### CI topology

CI splits the lane across two runners. A Linux ARM64 job builds the payload
with a host Bazel (`GVISOR_DOCKER_BUILD=false`), caches it keyed by the
gVisor pin (with a recipe salt, so a build-flag change such as
`--eh-frame-hdr` invalidates stale caches), runs the target drift audit
(`check-gvisor-targets`), and uploads the payload as an artifact; the macOS
runtime job downloads the artifact and runs the QEMU reference lane. The
128-suite reference lane runs thousands of tests and can take tens of
minutes (suites that crash or exit inconsistently with their XML trigger
isolated per-test reruns), so the runtime job's timeout is sized
accordingly. The elfuse lane remains explicit local validation until the
gaps recorded in the manifest are fixed.

### Baseline (2026-07-19)

The opt-in set in `targets.txt` enables 128 suites; the payload discovers
2319 tests. The QEMU AArch64 Linux reference passes them cleanly except for
43 that do not run cleanly against the reference itself in this environment
and are `EXCLUDE`d on both backends, leaving 2276 planned tests per backend:

| Backend | PASS | SKIP | EXCLUDE |
| --- | ---: | ---: | ---: |
| QEMU AArch64 Linux reference | 2237 | 39 | 43 |

elfuse runs the same 2276 planned tests and is intentionally red at this
baseline (measured with `make test-gvisor-conformance-elfuse`); every
reference-PASS test is expected `PASS`, so each divergence is a real elfuse
gap. CI runs only the QEMU reference lane.

The 39 SKIPs are gVisor-specific tests that skip on a real kernel
(`!IsRunningOnGvisor()`) or are version-gated. The 43 reference exclusions
group as:

- architecture x86-isms: e.g. `FPSigTest.NestedSignals` checks `xmm`
  registers, which do not exist on AArch64;
- tests that `execve` a companion binary the single-file payload does not
  ship (all `RseqTest.*`, `SigaltstackTest.ResetByExecve`,
  `PrctlTest.OrphansReparentedToSubreaper`);
- missing guest devices or mounts: `/dev/fuse` (`DevTest.*Fuse`,
  `IoctlTest.FIOASYNCHandlesFuseFD`), `/dev/mqueue` (`MqTest.Open*`);
- environment specifics: `AffinityTest.*` (CPU-mask size),
  `GetrusageTest.Grandchild`, `Pipes/PipeTest.PipeFdCount/*`, `KeysTest`;
- a timestamp test that is flaky at clock-tick granularity
  (`OpenTest.TruncateNoSizeChangeUpdatesTimestamps`);
- hard crashers on the reference (`ConcurrencyTest.MultiProcessConcurrency`,
  `PollTest.InvalidFds`, `FaultTest.InRange`).

Two upstream suites do not build against the pinned tree without extra
helpers (`exec_test`, `sticky_test`) and two link no GoogleTest cases
(`fpsig_mut_test`, `time_test`); all four are left out of `targets.txt`.
Fix the runtime, not the manifest.

### Known elfuse gaps (remediation order)

Across the full 128-suite corpus elfuse is broadly red; run `make
test-gvisor-conformance-elfuse` for the current breakdown. Some gaps are
whole missing syscalls (for example `io_setup` returns `ENOSYS`, so the
`aio` suite fails at setup); others are semantic divergences in calls that
are already implemented. The original five hand-picked suites (`readv`,
`fcntl`, `epoll`, `futex`, `ppoll`) remain the highest-leverage starting
points: their divergences collapse into a small number of root causes, and
fixing a cluster's core often clears its advanced cases too. A rough fix
order by leverage and independence follows.

1. `readv` zero-length iovec. A `{bad_address, 0}` entry must be address
   validated and fault with `EFAULT` before the zero-length shortcut. One
   isolated test, the smallest fix.
2. `fcntl` `F_SETSIG`/`F_GETSIG`. These commands return `EINVAL`, which alone
   gates the whole `FcntlSignalTest` suite plus the `FcntlTest` `SetSig`
   cases, about 21 tests from one feature in `src/syscall/fs.c`.
3. Localized `fcntl` and `ppoll` fixes: validate `F_SETOWN`/`F_SETOWN_EX`
   owners so a bad pid, tid, or process group returns `ESRCH` (about 5);
   treat `O_PATH` descriptors specially so disallowed commands return `EBADF`
   (about 6); honor `ppoll`'s temporary signal mask and validate its size
   (4).
4. `futex` `FUTEX_WAIT` returning `EAGAIN` instead of parking. Waiters never
   block, so `FUTEX_WAKE` finds nobody and the wake counts come out zero. One
   likely root cause in the wait value-check path in `src/runtime/futex.c`,
   with high fan-out across the futex suite.
5. POSIX byte-range record locks. `FcntlLockTest` exercises classic
   `F_SETLK`, `F_SETLKW`, and `F_GETLK` conflict, blocking, and multi-process
   semantics, which are distinct from the OFD locks already implemented.
   About 15 tests and a subsystem rather than a one-liner.
6. `epoll` readiness and lifecycle. Readiness is never reported, so
   `epoll_wait` blocks to the timeout on several cases; the rest need
   `EPOLLHUP`/`EPOLLERR` delivered independently of the requested mask,
   regular files rejected with `EPERM`, and cycle detection. About 13 tests,
   including six hangs, in `src/syscall/poll.c`.
7. `futex` advanced paths: `FUTEX_WAKE_OP`, wrong-kind detection,
   priority-inheritance (`FUTEX_LOCK_PI`, two of which crash), and the
   interprocess shared and copy-on-write cases. Best attempted after the core
   wait fix, which may resolve several.

Any `TIMEOUT` and `SIGNAL` results should each be reproduced in isolation
first. They are valid tests, since the QEMU reference passes them, but the
elfuse hang or crash should be confirmed as a genuine semantic gap rather than
an artifact of the heavier GoogleTest runtime before a root cause is assigned.

### Adding coverage

Opting a new suite in is a three-step change:

1. add its Bazel label to `tests/conformance/gvisor/targets.txt` (the binary
   name is derived from the label);
2. `make build-gvisor-tests` to build the new binary;
3. regenerate `tests/conformance/gvisor/expectations.tsv`
   (`GVISOR_BOOTSTRAP=1` run on `qemu-aarch64`, then `expectations-init`).

Until step 3 the exact-cover manifest deliberately fails the `plan` step,
because the new suite's tests have no rows yet. Qualify every new suite on
QEMU before interpreting its elfuse results: a suite that does not run
cleanly against the reference (crashes, x86-only, needs a companion binary
or a device the guest lacks) belongs in the `# DECLINED` block of
`targets.txt`, not in the enabled set.

`make check-gvisor-targets` lists the upstream `*_test` targets that are
available at the pin but not yet enabled (opt-in candidates), and fails if
an enabled label no longer exists after a pin bump. It needs the gVisor
checkout that `make build-gvisor-tests` creates, and skips cleanly when the
checkout is absent.

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
