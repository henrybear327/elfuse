# Conformance Harness

The harness runs registered Linux test suites on elfuse and a QEMU reference.
It records suite status separately from the expectation verdict. The command
reference is in [testing.md](testing.md#conformance-tests).

## Results

`run` writes `results.json` below `<results>/<suite>/<backend>/<stamp>-<pid>/`,
where `<results>` defaults to `build/conformance`. That file is the canonical
artifact: `schema_version: 1`, `kind: run`, run metadata, derived counts and
gate, and case records. Loading rejects a gate or count that disagrees with
the cases. An empty run is red. A `summary.txt` beside it carries the lines
`report` prints.

Each attempt records `normal`, `timeout`, `signal`, or `transport`, elapsed
microseconds, output paths, and an exit code or signal when applicable. Case
statuses are `PASS`, `FAIL`, `SKIP`, `CONF`, `WARN`, `BROK`, `TIMEOUT`,
`CRASH`, `INCONSISTENT`, and `ERROR`. Verdicts are `as_expected`,
`unexpected_failure`, `unexpected_pass`, `flaked`, `filtered`, and `error`.

JSON list output also has `schema_version: 1` and a `kind` field. Requested
machine data uses stdout. Diagnostics use stderr.

Exit codes are:

- `0`: the operation succeeded or the run is green.
- `1`: a run is red, a backend failed, or an artifact check is red.
- `2`: the command, configuration, or operation is invalid.
- `3`: a non-writing pin or selection check found drift.
- `77`: an optional prerequisite is absent. `--require` and `CONF_REQUIRE=1`
  promote it to `2`.

## IDs and Selection

Case IDs have one of these forms:

```text
<suite>:<group>
<suite>:<group>/<case>[/<parameter>...]
```

Selectors and expectation matchers use shell globs across the complete ID.
A bare group selector also selects its cases. An unmatched selector is an
error.

A selection file assigns each upstream launch group to `pr`, `full`, or a
declined group with a reason. PR groups run in both scopes. Enabled entries
may set `timeout_s` and suite-specific case filters. `selection check`
compares the file against the pinned inventory and reports drift; `selection
update` rewrites the generated selection data.

## Expectations

Expectation files are JSONC and accept comments and trailing commas. Each
backend has a leaf, `<suite>_<backend>.jsonc`, which may `include` shared
files; the optional `flaky.jsonc` holds the quarantine actions. Files contain
ordered actions; the last matching non-quarantine action wins, and the first
effective action must be `expect_pass` on `*`.

Actions are `expect_pass`, `expect_failure`, `expect_conf`, `skip`, and
`quarantine`. Every non-pass action needs a reason. A quarantined case runs
alone for at most three attempts and reports test mismatches as `flaked`.
Harness errors remain red. A full run rejects matchers that select no case.

A skipped expectation prevents launch. `--bootstrap` launches skipped cases
and records status without applying expectations. `expectations seed` derives
actions from bootstrap statuses or red verdicts. It refuses harness errors.

## Payloads and Pins

Payloads live below `externals/payloads/` and are not committed. A fingerprint
hashes the pin and builder inputs. `manifest.json` records the fingerprint and
each staged file or symlink. Verification detects missing, extra, changed, and
stale content before a run starts.

Pins are schema-checked JSON. `pins check` fetches the upstream ref without
writing and reports drift. `pins update` validates the new pin before
replacing the file.

## Suite Interface

`tests/conformance/providers/__init__.py` is the static suite registry;
`Provider` in `providers/base.py` declares what a suite supplies: selection,
prerequisites, payload and pin hooks, case discovery, batch keys, and result
decoding.

The shared runner owns expectation resolution, skip handling, unresolved batch
reruns, quarantine retries, result ordering, and judgment. Providers map
suite output to statuses. Backends return process invocations. A provider
translates host paths through `backend.guest_path()` before putting them in
argv; `Backend.run` forwards argv unchanged, because only the provider knows
which elements are paths. QEMU records non-timeout shell statuses as exit
codes. Providers interpret `128+n` through the suite contract because the
shell cannot distinguish it from a plain exit with the same value.

The elfuse backend starts one `build/elfuse --timeout 0` process for each
command. The QEMU backend starts one VM through `tests/qemu-runner.sh`, shares
the repository read-only at `/mnt/host`, and executes commands over SSH.

## Make and CI

The Make targets take their suite list from the registry through
`scripts/conformance suites`. An empty registry makes suite targets print
`SKIP`; harness selftests still run.

`make clean-conformance` sweeps what an interrupted run left: the QEMU VM and
its state record, detached guest process groups, orphaned fork children, and
elfuse scratch under `/tmp`. Shared memory a run recorded creating is removed;
any other dead-creator SysV object is reported, since the guest key reaches the
host unchanged and nothing tells one apart from a third party's. It refuses
while a session holds a lock, skips the scratch and the SysV pass while any
elfuse of the user is alive, and keeps results.

`.github/workflows/conformance.yml` runs QEMU before elfuse and gates on the
required `Conformance (make test-conformance)` job. Pull requests use the PR
scope. Schedules and `scope=full` dispatches use the full scope.
