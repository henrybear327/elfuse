---
name: elfuse-verify
description: How elfuse validates a change - choosing the lanes for the area you touched, the test matrix, make check, and the Frama-C proof targets declared in mk/verify.mk, including how to drive the frama-c MCP server on a stuck proof and how to read its proof_coverage report. Use when adding bounds math to src/proved/, writing or repairing ACSL contracts, running or debugging make verify / verify-mutants, asking how much of a target is actually proved, touching frama-c-stubs/, adding a test lane, or deciding what to run before calling work done.
---

# Validating an elfuse change

Two independent gates: the runtime tests and the proofs. A change to
attacker-facing bounds math needs both.

Independent in what they prove, not in what they consume. Run them one after
the other, never concurrently. `make verify` re-invokes itself parallel and
`verify-mutants` fans out too, while the runtime lanes are wall-clock
sensitive, so overlapping them makes the machine fail tests that a serial run
passes. The harness does not absorb that load: `test_host_is_busy` skips only
the throughput guardrail, and a timeout on a busy host is retried once. A
timing FAIL from an overlapped run is not evidence either way; only a serial
re-run tells whether it was real.

The pure source scanners are the exception, and they are the cheap early
signal while something long is in flight: `check-lock-order`,
`check-eintr-contract`, `check-atomics`, `check-proof-targets`,
`check-stub-shadow` and `check-syscall-coverage` read the tree, cost seconds,
and fail long before a full lane would. Five of the six are on `make check`;
`check-stub-shadow` is a prerequisite of every `verify-*` target instead, so it
is not reached by `make check` alone. Running one directly with
`python3 scripts/<name>.py` costs nothing and needs no arguments.

Five of the six write nothing. `check-proof-targets` is the one that does:
it shells out to `make print-verify-targets` rather than reading
`mk/verify.mk`, and a sub-make evaluates the build-flavor guard while it reads
the makefiles. `print-%` goals are skipped by that guard for exactly this
reason (`mk/common.mk`), so the scanner is safe to run beside a build; if you
add a scanner that invokes make on some other goal, it is not.

## Choosing what to run

`docs/testing.md`, section "Validation Strategy By Change Type", is a table
from the area you touched to the minimum command set, and it is more specific
than any habit. Consult it first. It is where you learn that Rosetta work
wants `make test-rosetta-all`, that ptrace and debugger work want
`make test-gdbstub`, and that filename-codec work wants the soak lane on top
of `make check`.

The defaults below are what that table falls back to, not a substitute for it.

```
make check                       # unit tests, busybox, coverage gate, guardrail
bash tests/test-matrix.sh all    # the three modes
```

## Runtime

Modes and what a failure in each means:

- `elfuse-aarch64` - primary. Must stay green. A failure here is a regression.
- `qemu-aarch64` - ground truth via Alpine `aarch64-linux-musl` under
  `qemu-system-aarch64`. It answers "what does real Linux do", which is why
  `elfuse-debug` reaches for it on any behavioral divergence. TIMEOUTs are
  emulation speed, not regressions.
- `elfuse-x86_64` - the Rosetta path, with per-host-class baselines from
  `detect_x86_64_host_class`. Skips cleanly without the translator.

`tests/fetch-fixtures.sh` pulls Alpine packages, the `linux-virt` kernel, and
Rosetta fixtures on first run. musl is Alpine's only libc, so glibc-dynamic
lanes skip unless `GUEST_GLIBC_*` points at an external sysroot.

A fixture step that fails on a malformed archive may have received a
network's own HTML page as a valid 200, so check what arrived before blaming
the archive. A busybox `.deb` made of HTML fails when `ar` unpacks it, and
`build/busybox` fetches an `http://` mirror link as the Debian page lists it.

### Writing a test lane

The runner is already hardened, and every one of these exists because a test
once passed without running anything. Do not work around them, and do not
loosen one to get a build green.

- `tests/lib/test-runner.sh::run` and `run_check` wrap every invocation in
  `timeout $TEST_TIMEOUT` (gtimeout fallback on macOS).
- `run_check` and `run_pipe` fail on non-zero exit before pattern evaluation.
  A test that greps for a string in the output of a crashed binary is not a
  test.
- `driver.sh::evaluate_result` requires `rc == expected_rc`.
- `ALLOW_MISSING_BINARIES` defaults to 0. A missing fixture is a failure, not
  a skip.

## Proofs

`src/proved/` is header-only arithmetic carrying ACSL contracts: the bounds
math of an attacker-facing parser or packer, split out of a `.c` and proved
with `-wp-rte`.

Every `src/proved/` header must have a matching `make verify-<name>` target,
but the reverse does not hold. A few targets prove a `.c` file directly, each
for a reason stated in the comment above it in `mk/verify.mk`; the general
one is that the loops in question could only have been described as
test-covered had they been split into a header.

`make print-verify-targets` is the current list. CI reads it to build its
matrix, so do not hardcode the set anywhere else, including here.

```
make verify           # every proof target, parallel by default
make verify-<name>    # one target
make verify-mutants   # assert each proof rejects a known-broken source
make print-verify-targets
make check-contracts  # rebuild with -DELFUSE_CONTRACT_ASSERT, then make check
```

`make verify` re-invokes itself with `-j$(VERIFY_JOBS)` unless you brought your
own `-j`. `VERIFY_JOBS=1` is how you ask for serial on both GNU make 4.x and
Apple's 3.81.

`verify-mutants` accepts `MUTANT_TARGET=<name>`, `MUTANT_JOBS=<n>`,
`MUTANT_SINCE=<rev>` for a changed-only run, and `MUTANT_ESCALATE=<seconds>`
(see the exhaustion section below).

Read past the "N mutations, N caught" line. It also prints the proved functions
that have no mutation yet, and that list, not the caught count, is the
measure of what the gate covers: all-caught alongside a handful of functions
nobody has tried to break says the gate is green and that those proofs have
never been asked whether they would reject a broken source. They are not
failures, and they are not covered either.

Recompute that list before quoting it. The comment above the coverage report
in `scripts/check-mutants.py` says what its two lists count.

A function can also sit in a `_FCTS` list with no ACSL contract at all, proved
only for absence of runtime errors. Nothing there can reject a mutation, so
adding one is wasted effort until the function has a contract: that is the fix,
and it is usually two lines. Write the contract in the domain the code is in,
too. `futex_uaddr_is_aligned` would not discharge as `uaddr % 4 == 0` and does
as `(uaddr & 0x3) == 0`, because bridging modulo and bitmask on a 64-bit value
is what the prover times out on, not the property itself.

Adding a contract raises the obligation count, so raise
`VERIFY_<T>_MIN_GOALS` with it. That floor is a tripwire against an emptied
body or a dropped contract, which prove 0 of 0 and would otherwise pass; it is
meant to sit at the target's baseline. A floor left below the baseline fails
nothing, because the count is only ever compared against it from below.

Mutating a function that lives in an included header rather than in
`VERIFY_<T>_SRC` works: the runner stages the mutant in its own directory and
prepends it via `MUTANT_INCDIR`, where it shadows the real header. What a
target may mutate is its source plus the headers in its `VERIFY_<T>_SCAN`.

The runner probes each header shadow with an `#error` copy before scoring
(`check_shadow_reaches` in `scripts/check-mutants.py`). A SETUP FAILED there
means those mutations would prove the real header, so fix the staging before
reading any verdict.

### A mutation is caught by exhaustion here, not by refutation

Every catch the gate scores is an exhausted prover (`[Timeout]` or
`[Stepout]`), not a refutation (`[Unknown]` or `[Failed]`); the comment in
`run_mutation` in `scripts/check-mutants.py` explains why that still counts.
The remaining gap is a mutation that turns an easy true goal into a hard true
one. `MUTANT_ESCALATE=<seconds>` re-runs every resource verdict at that budget
and reports MISSED for any mutation that then proves. It costs that budget
once per mutation, so run it when a contract changes or when slow versus
unprovable is the question:

```
make verify-mutants MUTANT_TARGET=futexdeadline MUTANT_ESCALATE=240
```

Report the resource verdicts separately, with the budget that produced them,
so the count never reads as "these proofs refute their mutants". Do not blame
load without measuring: a mutation run is its own load source, so only a
serial run (`MUTANT_JOBS=1`) on a quiet host measures it.

WP's cache replays a stored timeout at the same budget as readily as a proof,
so re-running `make verify-<name>` can report a cached timeout without
re-proving it; pass `WP_CACHE=none` for a fresh verdict. The mutation runner
always does, since a replayed timeout would score as a catch with no prover
run.

`scripts/proof-scope.py` decides which targets a diff can reach, and
`.github/workflows/verify.yml` builds its jobs from it, so a target the branch
cannot affect gets no runner. It answers two questions: which targets to prove,
and, with `--mutation`, which mutation sets to re-run, the second being narrower
because a file that only schedules the run cannot change whether a target
rejects a broken source. Every "cannot tell" answer widens back to the whole
set, and a push to `main` always proves and mutates everything.

Three things follow when adding a target or a proof input. An input reached
through `-include` or an `-I` the scan does not use is invisible to the closure
and belongs in `HARNESS_FILES` (or under `STUB_PREFIX`). A file that only picks
what runs goes in `SCHEDULING_FILES`, and the self-test refuses it if it also
carries a prover budget or a make invocation. And `proof-scope.py --self-test`,
run by `.github/workflows/lint.yml`, is what tells you the lists are still
honest.

### Adding to src/proved/

Nothing lands there without a proof target -
`scripts/check-proof-targets.py` (a CI job in `.github/workflows/lint.yml`)
fails otherwise. Callers include the header as `proved/<name>.h`.

The routine:

1. Extract the arithmetic into `src/proved/<name>.h` with ACSL contracts.
2. Add the `VERIFY_<NAME>_SRC` / `VERIFY_<NAME>_MODEL` / `VERIFY_<NAME>_FCTS`
   variables in `mk/verify.mk` so the rule template instantiates
   `verify-<name>`. `typed` is the default choice for a model; see below.
3. `make verify-<name>` until it discharges with `-wp-rte`.
4. `make verify-mutants MUTANT_TARGET=<name>` - a proof that cannot reject a
   broken source proves nothing.

Supporting gates, all of which run per target:

- `scripts/check-acsl-coverage.py` - catches a contract assumed because its
  function was left out of `-wp-fct`.
- `scripts/check-char-signedness.py` (`make check-char-signedness`) - compiles
  each proved function under `-fsigned-char` and `-funsigned-char` at -O0 and
  requires identical code. The data model used for proving differs from arm64
  macOS on plain-char signedness; this is what keeps that sound.
- `scripts/check-stub-constants.py` (`make check-stub-constants`) - asserts
  every `frama-c-stubs/` constant matches the macOS SDK. The analyzer never
  links, so a wrong constant cannot fail a build, it silently changes what the
  proof reasons about.

### Choosing the next target

Parsability decides it before anything else does: a file Frama-C cannot parse
cannot be proved, however good a candidate it looks. Test that first, because
it costs one invocation and rules candidates out for free.

```
FC=$(command -v frama-c)
ARGS="-nostdinc -isystem $($FC -print-share-path)/libc -Iframa-c-stubs \
      -include prelude.h -include macos-libc.h -Isrc -Ibuild"
FILE=src/syscall/fs-stat.c
$FC -machdep gcc_x86_64 -cpp-extra-args="$ARGS" "$FILE"
```

`CPP_DEFS` is empty for every target but `verify-gva`, so leaving it out
matches what most targets are proved under. A failure names its own cause:
`'sys/attr.h' file not found` is the real modeling gap and ends the matter,
while `Cannot resolve variable X` is a missing declaration and is fixable
under `frama-c-stubs/`.

Read which header stopped a file and whose include it was. An unused
`#include` of an unmodeled header blocks every file that includes the header
carrying it, and deleting it changes no compiled code.

Then rank what survives by whether it actually holds attacker-facing bounds
math. The shape that has worked every time is a self-contained codec or walk
over a guest-chosen blob: pure arithmetic, libc-only includes, an explicit
output-buffer bound, and no syscalls. A file whose header comment already says
it treats its input as untrusted and is free of project dependencies is
telling you it was written to be proved.

Two things that look like candidates and are not. A file whose length
arithmetic is all delegated to an already-proved header adds nothing but a
second harness. And a translation table with no arithmetic, however
attacker-reachable, has no obligations worth generating: `-wp-rte` on it
proves that a switch is a switch.

### Memory models, and what no model checks

Each target picks its own model via `VERIFY_<NAME>_MODEL` in `mk/verify.mk`,
and the comment above it says why. Pick the model the code needs, not the
model a neighbour target uses.

The general limit is worth understanding before trusting any of them: a
non-`typed` model buys reasoning power by assuming something the proof does
not check. `caveat`, used where `typed` cannot follow a byte-addressed buffer
whose entry stride is attacker-chosen, assumes formal pointer parameters do
not alias. The contracts state that with `\separated`, but the callers are not
in `-wp-fct`, so nothing verifies they honor it, and a future caller passing
the same address twice would invalidate the proof with no diagnostic.

That call-site gap is general, and it bites hardest for `proved/gva.h`:
`guest.c` cannot be given to Frama-C at all, so nothing verifies its call
sites honor the `requires` clauses. `make check-contracts` narrows it from the
runtime side by turning the expressible ones into runtime asserts, and is
deliberately separate from `make check` because those functions sit on the
`guest_read` / `guest_write` hot path.

### The frama-c MCP server

When the `frama-c` MCP server is connected, read `references/frama-c-mcp.md`
before loading a target into it, surveying files with `parse_surface`, reading
`proof_coverage`, or trusting a count it reports.

### frama-c-stubs/

Declarations the analyzer needs that the compiler or macOS supplies:
`Hypervisor/Hypervisor.h` and `macos-libc.h` for Darwin constants the modeled
libc omits, plus `prelude.h`, which declares nothing of its own and instead
force-includes the two headers Frama-C ships but never reaches on its own: its
gcc-builtins model, and its stdatomic.h for the `_Atomic` qualifier its front
end cannot parse and for the C11 atomics vocabulary the tree calls.

It sits outside `src/` on purpose so a real compile, which resolves through
`-Isrc`, cannot reach it. Only `FRAMAC_STUB_DIR` in `mk/verify.mk` does.
It is tracked in git because every proof target needs it to parse.

A missing declaration fails with "Cannot resolve variable", which is how the
next one gets found. A file that stops on a macOS header Frama-C's libc does
not model (`sys/event.h` and `sys/mount.h` among them) has a real modeling gap;
do not add a fake stub for it.

## Other checks

These are not part of `make check` and each answers a different question:

```
make lint                  # clang-tidy
make check-format          # formatting, and regenerates the dispatch header
make check-asan            # use-after-free, overflow, on the host side
make check-ubsan           # undefined behavior
make check-tsan            # data races, worth it for anything multi-vCPU
make infer-uninit          # uninitialized reads
```

## What done means

Green is a claim about named commands, so report it as one: which lanes ran,
what each said, and which ones did not run. The failure modes to avoid:

- A lane that could not run is named along with the risk that leaves. It is
  never rounded up into the passing set.
- The exit status a gate reports is the one to quote, and it is not always the
  one you are shown. A backgrounded `make check > log 2>&1; echo $?` reports
  the status of the whole command line, so a trailing `echo` makes a failing
  make look like a success. Read the status from inside the command, or read
  the log for `make: *** [target] Error N` and the suite's own `Results:` line.
  A single green summary line proves nothing on its own either, since `make`
  stops at the first failing step and the suites after it never print.
- A count, a latency, or a coverage figure is recomputed before it is quoted,
  including from this file and from any other document, since nothing gates a
  count written in prose. The gates print the live number, so take it from
  `make print-verify-targets` and from what `check-lock-order` and
  `check-proof-targets` report. A number carried forward from a document reads
  as measured and is not.
- The `PROVED n of n` line is not in `build/verify-<name>.log`, which carries
  Frama-C's own `[wp] Proved goals: N / N` instead. It is check-wp-result.py's
  console output, colorized unconditionally, with the escape sitting between
  `PROVED` and the count. So a total summed from a `make verify` transcript
  with a naive `grep -oE 'PROVED +[0-9]+ of [0-9]+'` silently matches nothing
  and reports an empty sum rather than failing. Strip the escapes first
  (`sed 's/\x1b\[[0-9;]*m//g'`), or total the logs on `Proved goals` instead.
- A proof is done when `make verify` and `make verify-mutants` say so from the
  Makefile. MCP goals discharging is progress, not a verdict.
- A failure blamed on the environment earns one reproduction attempt under the
  condition blamed for it before it is written off. "Transient" and "the host
  was busy" are the two that hide real defects here, because a test harness
  racing its own pipeline and a probe that measures the wrong thing both fail
  only under load or only on some networks. Reproduce it, or say it went
  unexplained; do not report it as understood. Raising the reproduction rate on
  a failure that will not repeat on demand is `elfuse-debug`, under "When it
  only fails sometimes".

The throughput guardrail is the exception to that bullet: it is the one lane
where load genuinely decides the result. It runs near the end of `make check`,
so it measures on a machine `make check` has just loaded, and an UNMEASURED
verdict there says nothing about the change. Re-run `make test-bench-guardrail`
alone on an idle host and report what it says. UNMEASURED exits non-zero
exactly as a threshold violation does.

Establish the baseline before a multi-command session rather than after: this
tree is not green everywhere, and without the before-picture there is no way
to separate breakage you caused from breakage you inherited.

## Authoritative sources

This skill is a working summary. These are tracked and survive a fresh clone,
so prefer them when the two disagree:

- `docs/testing.md`, section "Validation Strategy By Change Type" - the change
  area to command mapping.
- `mk/verify.mk` - the per-target `_SRC` / `_MODEL` / `_FCTS` variables and
  the comment above each explaining its model choice.
- `tests/test-bench-guardrail.sh` - the comment above the unmeasured check,
  for why UNMEASURED and FAIL both exit non-zero.
