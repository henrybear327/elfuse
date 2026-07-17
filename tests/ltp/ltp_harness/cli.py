"""Command-line interface and top-level orchestration.

Exit-code contract (shared with mk/tests.mk's RUN_LTP_TARGET macro):
0 gate green, 1 gate regression or harness failure, 2 usage or
configuration error, 77 provably absent optional setup (skip).
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import Any, Dict, List, Optional

from ltp_harness import EXIT_FAIL, EXIT_OK, EXIT_SKIP, EXIT_USAGE
from ltp_harness import baseline as baseline_mod
from ltp_harness import manifest as manifest_mod
from ltp_harness import report as report_mod

LTP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.realpath(os.path.join(LTP_DIR, os.pardir, os.pardir))

MANIFEST_PATH = os.path.join(LTP_DIR, "manifest.json")
PIN_PATH = os.path.join(LTP_DIR, "pin.json")

BACKENDS = ("elfuse", "qemu")


class HarnessFatal(Exception):
    """Infrastructure failure that must abort the run; maps to exit 1."""


class HarnessSkip(Exception):
    """A provably absent optional prerequisite; maps to exit 77."""


def _default_fixture_dir() -> str:
    return os.environ.get(
        "LTP_FIXTURE_DIR",
        os.path.join(REPO_ROOT, "externals", "test-fixtures", "ltp-aarch64"),
    )


def _default_results_dir() -> str:
    return os.environ.get(
        "LTP_RESULTS_DIR", os.path.join(REPO_ROOT, "build", "ltp-results")
    )


def _positive_float(text: str) -> float:
    value = float(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="harness.py", description="LTP syscall-conformance harness"
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    build = sub.add_parser("build-fixture", help="build the pinned LTP payload")
    build.add_argument("--force", action="store_true")
    build.add_argument("--jobs", type=int, default=0)
    _add_fixture_arg(build)

    verify = sub.add_parser("verify-fixture", help="re-validate the built payload")
    verify.add_argument("--quick", action="store_true")
    _add_fixture_arg(verify)

    run = sub.add_parser("run", help="run a tier and gate against the baseline")
    _add_run_args(run)
    run.add_argument("--no-gate", action="store_true")

    rec = sub.add_parser("record-baseline", help="snapshot current results")
    _add_run_args(rec)
    rec.add_argument(
        "--from-results",
        default="",
        help="record from an existing results directory instead of running",
    )

    rep = sub.add_parser("report", help="regenerate reports from a results dir")
    rep.add_argument("--results", required=True)
    rep.add_argument("--junit", default="")

    return parser


def _add_fixture_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--fixture-dir", default=_default_fixture_dir())


def _add_run_args(parser: argparse.ArgumentParser) -> None:
    _add_fixture_arg(parser)
    parser.add_argument("--backend", required=True, choices=BACKENDS + ("all",))
    parser.add_argument("--tier", default=os.environ.get("LTP_TIER", "fast"))
    parser.add_argument("--test", default=os.environ.get("LTP_TEST", ""))
    parser.add_argument("--results-dir", default=_default_results_dir())
    parser.add_argument(
        "--timeout-mul",
        type=_positive_float,
        default=float(os.environ.get("LTP_TIMEOUT_MUL", "1") or "1"),
    )
    parser.add_argument("--workers", type=int, default=1)


def _fixture_ready(fixture_dir: str) -> bool:
    marker = os.path.join(fixture_dir, ".complete")
    return os.path.isfile(marker) and os.path.getsize(marker) > 0


def _skip(message: str) -> int:
    print(f"SKIP: {message}")
    return EXIT_SKIP


def _load_inputs(args: argparse.Namespace):
    pins = manifest_mod.load_pins(PIN_PATH)
    tests = manifest_mod.load_manifest(MANIFEST_PATH)
    selection = manifest_mod.select_tests(tests, args.tier, args.test)
    return pins, tests, selection


def _baseline_path(backend: str) -> str:
    # LTP_BASELINE_DIR exists for the harness selftests; production
    # baselines are the committed files next to the manifest.
    base = os.environ.get("LTP_BASELINE_DIR", LTP_DIR)
    return os.path.join(base, f"baseline-{backend}.json")


def _result_formats(tests: List[Dict[str, Any]]) -> Dict[str, str]:
    return {test["id"]: test["result_format"] for test in tests}


def _gate_backend(
    backend: str,
    tier: str,
    pins: Dict[str, Any],
    selection: List[Dict[str, Any]],
    observed: Dict[str, Any],
    run_dir: str,
    no_gate: bool,
) -> int:
    """Compare one backend's observations against its baseline."""
    gate: Optional[baseline_mod.GateResult] = None
    status = EXIT_OK

    if not no_gate:
        pin = manifest_mod.baseline_pin(pins)
        recorded = baseline_mod.load(_baseline_path(backend), pin)
        selected_ids = {test["id"] for test in selection}
        sliced = {
            test_id: entry
            for test_id, entry in recorded.items()
            if test_id in selected_ids
        }
        gate = baseline_mod.compare(sliced, observed)

        for message in gate.regressions:
            print(f"REGRESSION [{backend}] {message}")
        for message in gate.improvements:
            print(f"IMPROVED [{backend}] {message} (run: make record-ltp-baseline)")
        for message in gate.infos:
            print(f"INFO [{backend}] {message}")

        if not gate.passed:
            status = EXIT_FAIL

    report_mod.write_gate_json(
        os.path.join(run_dir, f"gate-{backend}.json"), backend, tier, gate, observed
    )

    kirk_report = _read_kirk_report(run_dir, backend)
    if kirk_report is not None:
        report_mod.write_junit(
            os.path.join(run_dir, f"results-{backend}.xml"), backend, kirk_report, gate
        )

    counts: Dict[str, int] = {}
    for entry in observed.values():
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    summary = " ".join(
        f"{status_name}={counts[status_name]}"
        for status_name in baseline_mod.STATUSES
        if status_name in counts
    )
    verdict = "green" if status == EXIT_OK else "RED"
    print(f"LTP {backend} tier={tier}: {summary} gate={verdict}")

    return status


def _kirk_report_path(run_dir: str, backend: str) -> str:
    return os.path.join(run_dir, f"kirk-{backend}.json")


def _read_kirk_report(run_dir: str, backend: str) -> Optional[Dict[str, Any]]:
    path = _kirk_report_path(run_dir, backend)
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _observed_for_backend(
    run_dir: str, backend: str, tests: List[Dict[str, Any]]
) -> Dict[str, Any]:
    kirk_report = _read_kirk_report(run_dir, backend)
    if kirk_report is None:
        raise HarnessFatal(f"missing kirk report for backend '{backend}' in {run_dir}")
    return baseline_mod.observed_from_report(kirk_report, _result_formats(tests))


def _execute_backends(args: argparse.Namespace, pins, tests, selection) -> str:
    """Run kirk for the requested backends; returns the run directory.

    QEMU always runs before elfuse in 'all' mode and must qualify first,
    so elfuse is only ever compared against ground-truthed expectations.
    """
    try:
        from ltp_harness import kirkdrive
    except ImportError as err:
        raise HarnessFatal(f"execution engine unavailable: {err}") from err

    backends = list(BACKENDS) if args.backend == "all" else [args.backend]
    if "qemu" in backends:
        backends.sort(key=lambda name: 0 if name == "qemu" else 1)

    return kirkdrive.run_backends(
        backends=backends, args=args, tests=tests, repo_root=REPO_ROOT
    )


def cmd_run(args: argparse.Namespace) -> int:
    pins, tests, selection = _load_inputs(args)

    if not _fixture_ready(args.fixture_dir):
        return _skip(
            f"LTP fixture is absent at {args.fixture_dir}; run: make build-ltp-fixture"
        )

    run_dir = _execute_backends(args, pins, tests, selection)

    status = EXIT_OK
    backends = list(BACKENDS) if args.backend == "all" else [args.backend]
    for backend in backends:
        observed = _observed_for_backend(run_dir, backend, tests)
        backend_status = _gate_backend(
            backend, args.tier, pins, selection, observed, run_dir, args.no_gate
        )
        status = max(status, backend_status)

    print(f"Results: {run_dir}")
    return status


def cmd_record_baseline(args: argparse.Namespace) -> int:
    pins, tests, selection = _load_inputs(args)

    if args.from_results:
        run_dir = args.from_results
        if not os.path.isdir(run_dir):
            raise manifest_mod.ManifestError(f"no results directory {run_dir}")
    else:
        if not _fixture_ready(args.fixture_dir):
            return _skip(
                f"LTP fixture is absent at {args.fixture_dir}; "
                f"run: make build-ltp-fixture"
            )
        args.no_gate = True
        run_dir = _execute_backends(args, pins, tests, selection)

    pin = manifest_mod.baseline_pin(pins)
    manifest_ids = {test["id"] for test in tests}
    backends = list(BACKENDS) if args.backend == "all" else [args.backend]

    for backend in backends:
        observed = _observed_for_backend(run_dir, backend, tests)
        path = _baseline_path(backend)
        previous: Optional[Dict[str, Any]] = None
        if os.path.isfile(path):
            try:
                previous = baseline_mod.load(path, pin)
            except baseline_mod.BaselineError:
                print(f"note: replacing {path} recorded against a different pin")

        added, changed, pruned = baseline_mod.record(
            path, backend, pin, observed, previous, manifest_ids
        )
        print(
            f"recorded {path}: {len(observed)} tests "
            f"({len(added)} added, {len(changed)} changed, {len(pruned)} pruned)"
        )

    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    tests = manifest_mod.load_manifest(MANIFEST_PATH)

    reports = sorted(glob.glob(os.path.join(args.results, "kirk-*.json")))
    if not reports:
        raise manifest_mod.ManifestError(f"no kirk reports under {args.results}")

    for path in reports:
        backend = os.path.basename(path)[len("kirk-") : -len(".json")]
        kirk_report = _read_kirk_report(args.results, backend)
        assert kirk_report is not None
        observed = baseline_mod.observed_from_report(
            kirk_report, _result_formats(tests)
        )
        junit = args.junit or os.path.join(args.results, f"results-{backend}.xml")
        report_mod.write_junit(junit, backend, kirk_report, None)
        report_mod.write_gate_json(
            os.path.join(args.results, f"gate-{backend}.json"),
            backend,
            "unknown",
            None,
            observed,
        )
        print(f"wrote {junit}")

    return EXIT_OK


def cmd_build_fixture(args: argparse.Namespace) -> int:
    pins = manifest_mod.load_pins(PIN_PATH)
    tests = manifest_mod.load_manifest(MANIFEST_PATH)

    from ltp_harness import fixture

    return fixture.build(args, pins, tests, ltp_dir=LTP_DIR, repo_root=REPO_ROOT)


def cmd_verify_fixture(args: argparse.Namespace) -> int:
    pins = manifest_mod.load_pins(PIN_PATH)
    tests = manifest_mod.load_manifest(MANIFEST_PATH)

    from ltp_harness import fixture

    return fixture.verify(args, pins, tests, ltp_dir=LTP_DIR)


def main(argv: Optional[List[str]] = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)

    handlers = {
        "run": cmd_run,
        "record-baseline": cmd_record_baseline,
        "report": cmd_report,
        "build-fixture": cmd_build_fixture,
        "verify-fixture": cmd_verify_fixture,
    }

    try:
        return handlers[args.subcommand](args)
    except (manifest_mod.ManifestError, baseline_mod.BaselineError) as err:
        print(f"error: {err}", file=sys.stderr)
        return EXIT_USAGE
    except HarnessSkip as err:
        return _skip(str(err))
    except HarnessFatal as err:
        print(f"fatal: {err}", file=sys.stderr)
        return EXIT_FAIL
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_FAIL
