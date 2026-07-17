# LTP Conformance Lane Internals

This document explains how the Linux Test Project (LTP) conformance lane
works internally: the architecture, the kirk integration, the result and
baseline model, both execution backends, and the fixture pinning story.
For the day-to-day commands see the "Linux Test Project syscall
conformance" section of `docs/testing.md`.

## What the lane tests

The lane runs unmodified, pinned LTP test binaries against two backends
and compares elfuse's behavior with a real Linux kernel's:

- the QEMU reference: an Alpine `qemu-system-aarch64` VM whose kernel is
  the ground truth for what the selected tests should do;
- elfuse itself, loading the same AArch64 glibc binaries on macOS.

Unlike the unit suite, this exercises the full dynamic-binary stack
first: the glibc loader, symbol resolution, and library search must all
work before any syscall assertion runs.

## Architecture

```
tests/ltp/manifest.json ─┐
tests/ltp/pin.json ──────┤
                         v
        harness.py build-fixture          (ltp_harness/fixture.py)
                         │  downloads + verifies LTP and kirk archives,
                         │  cross-builds the selected tests, stages the
                         │  rootfs, generates runtest files
                         v
externals/test-fixtures/ltp-aarch64/{rootfs,kirk,bin,...}
                         │
        harness.py run --backend ...      (ltp_harness/kirkdrive.py)
                         │  spawns pinned kirk via kirk_shim.py
                         v
   kirk scheduler ── ComChannel plugin ── guest processes
   (libkirk)         elfuse_chan.py         elfuse + case-launcher
                     qemuchroot_chan.py     ssh + qemu-supervisor
                         │
                         v
   kirk-<backend>.json (full stdout per test)
                         │
        gate             v                (ltp_harness/baseline.py)
   baseline-<backend>.json  ──>  REGRESSION / IMPROVED / green
                         │
                         v
   gate-<backend>.json + results-<backend>.xml (ltp_harness/report.py)
```

Division of labor: kirk owns runtest parsing, scheduling, per-execution
timeout enforcement, per-binary result classification, and the JSON
report. The harness owns the pinned fixture, the two channel plugins,
VM boot, the recorded-baseline gate, and reporting.

## Why kirk

Upstream removed `runltp`: at our pinned LTP commit the script is a stub
that prints "runltp was removed from LTP use kirk instead" and exits 1.
Kirk (github.com/linux-test-project/kirk) is the only supported runner,
so building on it keeps the lane aligned with how LTP is meant to be
consumed, and it deletes an entire bespoke scheduler/parser layer from
this repository.

Kirk is pinned exactly like LTP: `pin.json` records the release tag and
the tarball sha256, the fixture builder fetches and verifies it, and the
checkout lives out-of-tree under the fixture directory (kirk is GPL and
is never vendored into the Apache-2.0 tree).

Two kirk details shape the integration:

- Custom channels cannot be selected through kirk's plain CLI: `--com`
  names are validated while arguments are parsed, but `--plugins`
  directories are only discovered afterwards. `ltp_harness/kirk_shim.py`
  therefore registers `tests/ltp/plugins/` with kirk's discovery API
  first and then calls kirk's own `run(cmd_args=...)` untouched.
- Kirk's built-in qemu channel boots a private VM and drives it over the
  serial console; it cannot attach to an existing VM and has no 9p share
  or privilege-drop story. The lane keeps its own VM boot
  (`ltp_harness/vm.py`, argv mirrored from `tests/qemu-runner.sh`, which
  cannot be reused as a subprocess because its EXIT trap stops the VM
  when the driver exits) and its own channel. Kirk's ssh channel is not
  used either: it depends on the third-party asyncssh package, and the
  harness stays standard-library-only by shelling out to system `ssh`.

## The kirk communication channels

A kirk `ComChannel` implements one coroutine that matters:
`run_command(command, cwd, env) -> {returncode, stdout, exec_time}`.
Kirk's LTP framework issues shell-syntax command strings (for example
`cd DIR && ./test`, `test -d /opt/ltp`, `ls --format=single-column`),
passes guest working directories, and builds a guest environment from
`LTPROOT`, `TMPDIR`, and every `LTP_*`/`TST_*` variable of the kirk
process. Both channels therefore:

- ship busybox `sh` (plus a small applet set) in the rootfs and run
  every command through `/bin/sh -c`;
- rewrite the one GNU-only command kirk emits (`ls
  --format=single-column` becomes `ls -1`) because the guest `ls` is
  busybox;
- rebuild `PATH` to the canonical guest value
  `/opt/ltp/testcases/bin:/usr/bin:/bin` (kirk appends the testcases
  directory to the host `PATH`, which is meaningless in the guest) and
  forward only `LTP_*`/`TST_*` variables;
- wrap the command in `/opt/elfuse-ltp/bin/case-launcher`
  (`tests/ltp/helpers/case-launcher.c`), whose only job in this position
  is a fork: elfuse models the initial guest process as PID/SID/PGID 1
  and busybox ash execs a lone command in place, so without the launcher
  the test would run as a session leader and break process-group
  assertions (setpgid01 and friends); with it the test is an ordinary
  child on both backends;
- kill the spawned process group when kirk cancels the coroutine on
  `--exec-timeout` (the subprocess is started in its own session).

### elfuse channel (tests/ltp/plugins/elfuse_chan.py)

Each command spawns one host process:

```
build/elfuse --timeout 0 --sysroot ROOTFS \
    /opt/elfuse-ltp/bin/case-launcher -- /bin/sh -c 'cd CWD && COMMAND'
```

`--timeout 0` disables elfuse's internal vCPU watchdog; kirk enforces
the deadline. With `--sysroot`, guest `/tmp` resolves inside the rootfs,
so the channel creates one `mkdtemp` scratch directory per command under
`ROOTFS/tmp`, points guest `TMPDIR`/`HOME` at it, uses it as the host
working directory (elfuse's sysroot is a path preference, not a chroot,
so a host-fallback relative write must land somewhere harmless), and
removes it afterwards. No launcher status file is used on this backend:
on a case-insensitive sysroot elfuse may store newly created guest files
under sidecar names the host cannot resolve by pathname, and the exit
code already travels launcher to elfuse to kirk. When elfuse itself dies
on a host signal the channel appends an `ltp-harness:` marker line to
the preserved stdout.

Kernel taint: kirk's SUT layer polls `cat /proc/sys/kernel/tainted`
around every test and treats a failed read as fatal. Elfuse is a
userspace loader with no kernel to taint and no such procfs node, so the
channel answers `0` to exactly that command without spawning a guest.

`/dev/shm` hygiene: elfuse backs guest `/dev/shm` with the per-host-UID
directory `/tmp/elfuse-shm-<uid>` (`src/runtime/procemu.c`), shared by
every elfuse process of that user. The channel takes a suite lock
(`/tmp/elfuse-ltp-<uid>.lock`, a mkdir lock holding the owner pid, with
stale-owner recovery), sweeps `ltp_*` leftovers from previous crashed
sessions before the first test so they are never blamed on it, and after
every command removes objects the command leaked, appending a marker
line to that test's stdout.

### QEMU channel (tests/ltp/plugins/qemuchroot_chan.py)

Suite setup copies the read-only 9p rootfs into the VM once
(`cp -a /mnt/host/.../rootfs /tmp/ltp-root`), then binds `/proc`,
`/dev`, `/sys` and mounts a private tmpfs on `/dev/shm` inside it;
teardown unwinds in reverse. Each command is one SSH invocation:

```
env -i VARS... /mnt/host/.../bin/qemu-supervisor \
    --root /tmp/ltp-root --cwd CWD --uid 1000 --gid 1000 \
    --timeout T --status /tmp/ltp-sup-N.status \
    -- /opt/elfuse-ltp/bin/case-launcher -- /bin/sh -c 'COMMAND'
```

`qemu-supervisor` (`tests/ltp/helpers/qemu-supervisor.c`) runs as root
outside the chroot: it forks a child that starts a fresh session,
chroots, drops supplementary groups and GID/UID (and verifies the drop
stuck), and execs the launcher; the parent enforces the monotonic
deadline, and afterwards kills and reaps every process left in the
child's session (it is a child subreaper and sweeps `/proc` by session
id). Its single-line JSON status file is read back after each command
and any anomaly (deadline expiry, incomplete cleanup, chroot or exec
failure) is appended to the test's stdout as an `ltp-harness:` line.

SSH discipline: every call, including auxiliary mkdir/cat/umount, runs
with a hard cap and BatchMode; exit 255 (transport loss) raises
immediately, which aborts the kirk session rather than letting a dead VM
degrade into per-command timeouts.

### Timeout layering

One tier value T (times `LTP_TIMEOUT_MUL`) drives every layer, ordered
so each can always report before the layer above it fires:

```
supervisor deadline            T
supervisor cleanup budget      T + 12   (constants in qemu-supervisor.c)
kirk --exec-timeout (qemu)     T + QEMU_EXEC_SLACK_SEC   (25)
channel SSH / subprocess cap   T + CHANNEL_CAP_SLACK_SEC (30)
```

On the elfuse backend there is no remote enforcement, so kirk's
exec-timeout is T itself. The same multiplier reaches LTP's own watchdog
via `LTP_TIMEOUT_MUL`, so raising it genuinely buys the test time at
every level at once. `tests/ltp/selftest/test_timeouts.py` parses the C
constants and asserts the inequalities, so the budget cannot silently
rot when either file changes.

## Result contract and subtest identity

Kirk classifies each runtest entry from the `Summary:` block when
present, from TPASS/TFAIL line counts otherwise, and from LTP's
documented exit bits for old-API tests; its JSON report preserves each
test's complete stdout. The harness digests that report
(`baseline.observed_from_report`) into:

- a per-test status, ordered `PASS < SKIP < WARN < FAIL < BROKEN`
  (`BROKEN` covers broken counts, a broken retcode classification, and
  the produced-no-results case);
- for new-API tests, a per-subtest map keyed by the `file.c:line`
  prefix of every `TPASS/TFAIL/TBROK/TCONF/TWARN` line, with a count
  per result type at each key.

The key choice is forced by LTP itself (verified against the pinned
source): binaries cannot select or skip individual subtest indices at
runtime (the new-API run loop iterates all `.tcnt` cases; the only
options are `-h/-i/-I/-D/-V`), and result lines print neither the case
index nor the variant, only `file.c:line`. Within one pinned LTP commit
that prefix is stable. Counts, not single values, are stored because
table-driven tests report every table entry from one `tst_res` call
site: on the reference, pinned `preadv02.c` emits eight results from the
single line `preadv02.c:77` (`{"TPASS": 8}`), so `{"TPASS": 7, "TFAIL":
1}` versus `{"TPASS": 8}` at that key is the difference a single folded
value cannot see.

The one old-API test in the manifest, `recv01`, has no stable subtest
key (its counter is a running index over emitted lines), so it is
recorded at whole-binary granularity (`"subtests": null`).

## The recorded-baseline gate

`baseline-elfuse.json` and `baseline-qemu.json` are committed snapshots
of what each backend does today at the pinned LTP/kirk versions. The
gate compares a run against the snapshot and fails only on movement;
"many tests are BROKEN because elfuse lacks syscalls" is a green state
once recorded, which is what makes per-subtest on/off control work
without patching LTP.

Test-level rules:

| Baseline    | Observed        | Outcome |
| ----------- | --------------- | ------- |
| X           | X               | green |
| better      | worse           | REGRESSION (exit 1) |
| worse       | better          | IMPROVED (exit 1 until re-recorded) |
| absent      | anything        | exit 2 (record it) |
| present     | not in this run | exit 2 (stale baseline) |

Subtest-level rules (checked even when the test statuses match): at each
key, a count increase for `TWARN/TFAIL/TBROK`, a `TPASS` count
decrease, or a total-count decrease (lost coverage) is a REGRESSION; the
reverse without any regression is IMPROVED; a baselined key never
observed is a REGRESSION; a brand-new key is green info when it passes
and a REGRESSION when it fails. Movement between `TCONF` and `TPASS`
follows the same arithmetic (`TCONF` gained at `TPASS`'s expense
regresses; the reverse improves; an extra `TCONF` firing alone is
info).

Improvements fail the gate deliberately (a ratchet). A warn-but-green
gate would let a baselined failure silently pass for months and then
regress back with no gate firing at any point in that arc; instead the
same pull request that fixes a syscall runs `make record-ltp-baseline`
and carries the reviewable baseline diff. Baselines are written with
sorted keys and stable indentation so those diffs stay small. `reason`
and `issue` fields on baseline entries survive re-recording.

Each baseline embeds the pin (LTP release/commit, kirk tag); `run`
refuses a mismatched pin with exit 2, so a pin bump forces the
documented re-record workflow instead of comparing across versions.

Two failure classes stay out of baselines entirely: infrastructure
failures (SSH 255, kirk producing no parseable report, fixture
verification failure, unknown backends) raise harness-fatal errors and
exit 1 without touching the gate, and configuration mistakes (unknown
test id, tier mismatch, malformed manifest or baseline, zero selection)
exit 2. An unknown `--test`/`LTP_TEST` is exit 2, never a green skip;
exit 77 is reserved for provably absent optional setup (fixture not
built, elfuse not built, QEMU fixtures or binary missing), which is what
`RUN_LTP_TARGET` in `mk/tests.mk` renders as SKIP.

In `--backend all` mode the QEMU reference runs first and every selected
test must be PASS or SKIP there before elfuse runs at all, so elfuse
results are only ever interpreted against ground-truthed expectations.

## Results layout

Each run writes
`build/ltp-results/<backend>-<tier>-<utcstamp>/` containing:

- `kirk-<backend>.json`: kirk's report, full stdout per test;
- `kirk-<backend>.log`: kirk's console output;
- `gate-<backend>.json`: machine-readable gate outcome (regressions,
  improvements, infos) plus the digested per-test observations;
- `results-<backend>.xml`: JUnit, where FAIL/BROKEN tests and gate
  findings (including pending improvements) are failures;
- kirk's own session directory (`--tmp-dir` points here).

## Fixture pinning and verification

`tests/ltp/pin.json` pins LTP (release, commit, archive URL, sha256,
official checksum-asset URL, `SOURCE_DATE_EPOCH` derived from the
commit time) and kirk (tag, archive URL, sha256). The builder
(`ltp_harness/fixture.py`):

1. downloads both archives into `cache/` (urllib, `.partial` then
   atomic rename) and verifies the LTP tarball against both the pinned
   digest and the release's own `.sha256` asset, and the kirk tarball
   against its pinned digest;
2. extracts LTP and configures it once
   (`--host=aarch64-linux-gnu --prefix=/opt/ltp`, cross `CC`, pinned
   `SOURCE_DATE_EPOCH`, `MAKEFLAGS` scrubbed for LTP's compat_16.mk);
3. builds `lib/` plus only the source directories of the selected tests
   (each test id is located by its `<id>.c` under
   `testcases/kernel/syscalls/`), not the full LTP tree;
4. stages the rootfs: test binaries and helpers into
   `/opt/ltp/testcases/bin` (each verified AArch64 via cross
   `readelf -h`), LTP's `COPYING` and a `Version` provenance file, the
   dynamic loader at its `PT_INTERP` pathname plus the transitive
   `DT_NEEDED` closure into `/lib` (with a `/lib64` symlink alias and
   `libnss_files` when the sysroot provides it), minimal `/etc`
   passwd/group/nsswitch entries for uid 1000, busybox at `/bin` with
   applet links, the cross-compiled `case-launcher` at
   `/opt/elfuse-ltp/bin`, and one generated runtest file per tier
   (`/opt/ltp/runtest/elfuse-{fast,extended,nightly}`) rendered from
   `manifest.json`;
5. places `qemu-supervisor` under the fixture's `bin/` (outside the
   rootfs: it runs in the VM before the chroot);
6. writes `inventory.txt` (sorted sha256/mode/symlink line per rootfs
   entry), `fixture-metadata.json` (toolchain identity, sysroot,
   busybox provenance and digest, helper digests), and `.complete`
   containing the input fingerprint, a sha256 over `pin.json`,
   `manifest.json`, both helper sources, and `fixture.py` itself, so
   any input change invalidates the fixture.

`verify-fixture` recomputes the fingerprint, re-checks both cached
archive digests, re-hashes the entire rootfs against the inventory,
re-validates every staged test's ELF machine and full dependency
closure, and confirms the launcher, supervisor, busybox, and kirk
checkout are present; `--quick` checks only metadata and fingerprint.

Everything generated stays under `externals/test-fixtures/ltp-aarch64/`:
ignored by Git, reaped by `make distclean`, never fetched implicitly by
`make check`. The LTP source, the installed payload, and kirk are
GPL-covered external fixtures; do not copy them into the Apache-2.0
tree, and review source-offer obligations before distributing a built
fixture.

Busybox is resolved at build time (`LTP_BUSYBOX`, then the checked-in
`externals/test-fixtures/aarch64-musl/staticbin` copy, then the
`build/busybox` Debian download) rather than URL-pinned, because the
Debian page-scrape URLs are not stable; the chosen binary's provenance
and sha256 are recorded in `fixture-metadata.json` and the inventory.

## Workflows

Add a test: inspect the pinned LTP source, add the entry to
`manifest.json` (id, installed command, tier, timeout, result format,
helpers, data files), run `make build-ltp-fixture` (the fingerprint
change forces a rebuild), run both backends, then
`make record-ltp-baseline` and review the baseline diff in the same
commit as the manifest change.

Reproduce one failure: `make test-ltp-elfuse LTP_TEST=<id>
LTP_TIER=<its tier>`, then read the preserved stdout in
`kirk-elfuse.json` (or `kirk-elfuse.log`) under the printed results
directory.

Refresh after an elfuse improvement: the gate exits 1 listing IMPROVED
entries; run `make record-ltp-baseline`, review the diff (statuses or
per-key counts moving toward PASS), commit it with the fix.

Bump a pin: edit `pin.json`, `make build-ltp-fixture FORCE=1`, run both
backends, `make record-ltp-baseline`, review the (possibly large,
file:line shifted) baseline diff, and commit pin plus baselines
together. The gate's pin check makes skipping this workflow impossible.

Debug the harness itself: `make test-ltp-harness` runs the hermetic
selftests (gate decision table against a fake kirk-report corpus,
manifest validation, channel command translation, timeout-layering
invariants, and the shell smoke test of the 77/2 exit contract) without
any fixture, toolchain, or network.
