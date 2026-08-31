# Conformance Harness

The harness runs registered Linux test suites on elfuse and a QEMU reference.
The public commands are listed in [testing.md](testing.md#conformance-tests).
LTP is a registered suite.

## Results

`run` writes below `build/conformance/<suite>/<backend>/` unless `--results`
selects another root. Each run directory contains `results.json` and a text
summary. `results.json` has `schema_version: 1`, `kind: run`, run metadata,
counts, a gate, and case records. Loading rejects counts or a gate that do not
match the records. An empty run is red.

An attempt records its execution type, elapsed microseconds, output paths, and
an exit code or signal when applicable. Execution types are `normal`,
`timeout`, `signal`, and `transport`. Case statuses are `PASS`, `FAIL`, `SKIP`,
`CONF`, `WARN`, `BROK`, `TIMEOUT`, `CRASH`, `INCONSISTENT`, and `ERROR`.
Verdicts are `as_expected`, `unexpected_failure`, `unexpected_pass`, `flaked`,
`filtered`, and `error`.

Machine-readable lists also have `schema_version: 1` and a `kind`. Requested
data uses stdout. Diagnostics use stderr.

Exit codes are:

- `0`: success or a green run.
- `1`: a completed run or artifact check is red.
- `2`: invalid command, configuration, or operation.
- `3`: a read-only pin or selection check found drift.
- `77`: an optional prerequisite is absent. `--require` or `CONF_REQUIRE=1`
  promotes this to `2`.

## IDs and Selection

IDs use `<suite>:<group>` or `<suite>:<group>/<case>`. Selectors and
expectation matchers use shell globs over the complete ID. A bare group also
selects its cases. An unmatched selector is an error.

A selection file assigns each upstream group to `pr`, `full`, or a declined
entry with a reason. PR groups run in both scopes. Enabled entries may set a
timeout and suite-specific filters. `selection check` compares the file with
the pinned inventory. `selection update` rewrites generated selection data.

## Expectations

Expectation files are JSONC. A suite has a base file, one leaf per backend,
and optional `flaky.jsonc`. The last matching non-quarantine action wins. The
first effective action is `expect_pass` for `*`.

Actions are `expect_pass`, `expect_failure`, `expect_conf`, `skip`, and
`quarantine`. Every non-pass action needs a reason. A skipped case is not
launched. A quarantined case runs alone for at most three attempts and a test
mismatch is reported as `flaked`; a harness error remains red. Full runs reject
matchers that select no case.

`--bootstrap` launches skipped cases and records status without applying
expectations. `expectations seed` proposes actions from bootstrap statuses or
red verdicts. It refuses harness errors.

## Payloads and Pins

Payloads live under `externals/payloads/` and are not committed. Their
fingerprint hashes the pin and builder inputs. `manifest.json` records the
fingerprint and every staged file or symlink. Verification detects missing,
extra, changed, and stale content before a run.

Pins are schema-checked JSON. `pins check` fetches without writing and returns
`3` for drift. `pins update` validates the replacement before writing it.

## Suite Interface

The static registry is `tests/conformance/providers/__init__.py`. A provider
supplies selection, prerequisites, payload and pin hooks, case discovery,
batch keys, and result decoding. The shared runner owns expectation loading,
skip handling, isolated retries, ordering, and judgment. Backends return
process invocations. A provider translates host paths through
`backend.guest_path()` before putting them in argv; `Backend.run` forwards
argv unchanged, because only the provider knows which elements are paths.

QEMU records non-timeout shell statuses as exit codes. Providers interpret
`128+n` through the suite contract because the shell cannot distinguish it
from a plain exit with the same value.

The elfuse backend starts `build/elfuse --timeout 0` for each command. The QEMU
backend starts one VM through `tests/qemu-runner.sh`, mounts the repository
read-only at `/mnt/host`, and executes commands over SSH.

## LTP

`make ltp-payload` verifies the pinned LTP and kirk archives, builds the
selected AArch64 tests, and stages a glibc rootfs. elfuse uses that rootfs as a
sysroot. QEMU copies it from the shared repository and enters it with `chroot`.

LTP IDs are `ltp:<runtest-tag>`. `full.jsonc` is generated from the pinned
`runtest/syscalls` file; `pr.jsonc` chooses the PR subset and overrides source
directories or timeouts where needed. `selection check` detects drift and
`selection update` rewrites the generated file.

kirk runs each LTP batch. The elfuse channel uses a launcher so the test does
not become the guest's initial process. The QEMU channel uses a supervisor for
the chroot, credentials, deadline, and process cleanup. Channel timeouts,
signals, and transport loss take precedence over kirk output. kirk status must
agree with the LTP exit mask and Summary block; disagreement is
`INCONSISTENT`. TCONF maps to `CONF`.

## Make and CI

`mk/conformance.mk` maps Make targets to the public CLI; the suite list comes
from the registry through `scripts/conformance suites`. The workflow builds
one payload artifact, runs QEMU before elfuse, and ends at the required
`Conformance (make test-conformance)` job. Pull requests use `pr`; schedules
and `scope=full` dispatches use `full`.
