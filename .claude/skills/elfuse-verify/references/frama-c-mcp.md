# The frama-c MCP server

The tools and fields below are upstream `sysprog21/frama-c-mcp`. An installed
binary can predate one of them; `self_check` reports the server version.

Start with `self_check`, because the optional pieces degrade independently.
Load the target from its profile (below), run WP one function at a time, and
use `get_wp_goals` and `context` to find which obligation is unproved before
rewriting a contract. `create_sandbox` proves a strengthened contract on a
copy and leaves the real source unchanged.

Read the `self_check` fields, not the absence of an error: a degraded server
answers like a healthy one. `frama_c.status: ok` says only that the binary
runs; `socket_spawn` and `wp.available` / `eva.available` under
`capabilities` decide whether the interactive path works.

A failed `socket_spawn` does not show that the `ast_utils` plugin is missing.
The probes are time-bounded, so on a loaded host they report `error` or
`unknown` for a working plugin, and `opam_switch_hint` timing out in the same
report points at host load. Confirm with
`frama-c -load-module ast_utils_plugin -print-libc` and re-run `self_check` on
a quiet machine. Only if the plugin is absent, install it with
`cd ast-utils && dune install` in the frama-c-mcp checkout.

`reload_project` takes structured fields, not a preprocessor string, and drops
an unknown key without an error, so a call carrying `cpp_extra_args` loads
with no flags. `parse_surface` takes the same fields and groups parse failures
by cause across a file list. For a file no target proves, copy
`include_paths`, `force_includes`, `machdep`, `nostdinc` and `isystem_paths`
from any `make print-verify-profiles` entry: without the last two the macOS
headers shadow the modeled libc, and a file whose parse depends on that loads
as a different program.

A load can also differ from the recipe in its RTE generator. The kernel's
`-rte` emits `pointer_alignment` assertions that WP's `-wp-rte` does not, so a
`pointer_alignment` goal the build never generates means the kernel's
generator ran, not that the proof is hard. `run_wp` adds WP's RTE checks; a
sandbox still starts with the kernel's `-rte`.

What a result proves:

- The server's default WP model is not what every target uses, so a goal that
  discharges under defaults says nothing about `make verify-<name>`. Mirror
  the target's `VERIFY_<NAME>_MODEL`.
- A prover budget is wall-clock, so on a saturated host any goal can reach it.
  Read `wp_timeout_triage` before believing a timeout: its `host_load` evidence
  is `quiet`, `saturated`, `unavailable` or `unreadable`, and anything but
  `quiet` leaves `confidence: low`. The reading itself is `host_load.per_cpu`
  in the response.
- A re-run does not re-prove what WP's cache holds. The cache defaults to
  `update` and replays a stored timeout at the same budget, so a second run
  can mark every timed-out goal `from_cache: true` and prove nothing. When
  `measurement.every_timed_out_goal_was_replayed` is true, `wp_timeout_triage`
  reports `confidence: low`. Pass `cache: "None"` to prove afresh, at the cost
  of a full re-prove, before acting on a timeout. `proof_coverage` draws the
  same line between `fresh_valid` and `cached_valid`.
- `retry_unproved` re-proves the targeted functions at double the budget and
  reports in `flipped` which timed-out goals then prove; an empty `flipped`
  means more time is not the fix. It does not check that the loaded program is
  the one you meant, so rule out the load, the cache, and the flags first.
- The server is not the gate: a proof is done only when `make verify` and
  `make verify-mutants` say so. Never add a workflow step, script, or CI job
  that depends on the server.

`proof_coverage` shows a target that passes while proving less than expected:

```
# denominator: every defined function of the loaded project
proof_coverage {}

# denominator: the function set that target declares
proof_coverage {verify_profile: "<target>", detail: "full"}
```

It reads stored conclusions, not the last run, so it reports nothing until
`store_function_conclusion` has filed a receipt from a `run_wp` on the real
project. With nothing loaded and nothing stored it answers `0 of 0`,
`incomplete`, and an empty function list rather than an error; check the
denominator before the percent. Sandbox receipts are refused, because a sandbox
proves an extracted copy whose uncontracted callees are stubs: merge the
annotations back, re-run WP on the main project, and store that receipt.

A row counts only when its `reason` is empty. The common ones:

- `stale_source`: a receipt hashes the whole loaded file set, so editing any
  source marks every row stale.
- `unverified_callee`, propagated up the call chain: fix what
  `blocking_callees` names first.
- `proved_under_a_goal_filter`: the run passed `prop` and left the other
  obligations unattempted.

Coverage reads WP only, so `complete` covers the obligations that the ACSL, RTE
and WP configuration generated. A requirement no contract states is absent from
the denominator, so coverage cannot show the property table is complete.

## Calibrate the server before trusting a number from it

Run an already-green target through it and compare the obligation count with
what `make verify-<name>` reports; `iov` has three functions and one header.

```
make verify-<name>                  # the answer, for name=iov
reload_project {verify_profiles: <make print-verify-profiles>,
                verify_profile: "iov"}
run_wp         {verify_profile: "iov", cache: "None"}
```

The counts must match exactly. A server that reads a model name differently,
starts the wrong RTE generator, or rejects a valid model still returns a
normal-looking result for a program the build system does not prove.

## Loading a target from its profile

`make print-verify-profiles` emits the `verify_profiles` JSON for every target
in `mk/verify.mk` from the variables the `verify-<name>` recipe uses, so a
profile and a Makefile run prove the same program. Emit it; never hand-write
one. `scripts/emit-verify-profiles.py` defines the fields and the conditions
under which it refuses to emit.

```
make print-verify-profiles                      # from the build system
reload_project {verify_profiles: <that JSON>, verify_profile: "<target>"}
run_wp         {verify_profile: "<target>"}
store_function_conclusion {function, status: "verified",
                           proof_receipt_sha256, verify_profile: "<target>"}
proof_coverage {verify_profile: "<target>", detail: "full"}
```

`verify_profiles` accepts the JSON object or its text. Name the profile on
every call: `run_wp` and `store_function_conclusion` refuse a load whose `rte`,
`nostdinc` or `isystem_paths` differ from the profile as that target's
evidence, and a conclusion stored without a profile does not settle a target.
