"""Spawn the pinned kirk against one backend and collect its report.

Kirk owns scheduling, per-execution timeouts, result parsing, and the
JSON report; this module only assembles the invocation. The channel
plugins in tests/ltp/plugins are registered ahead of argument parsing by
kirk_shim.py (kirk validates --com names during parsing, before it would
discover --plugins directories).

Timeout layering, all derived from one tier value times the multiplier:
kirk --exec-timeout enforces the per-test deadline; the same multiplier
reaches LTP's own watchdog via LTP_TIMEOUT_MUL; the channel receives a
strictly larger safety cap so a wedged auxiliary command cannot hang the
session; and the suite timeout covers the whole selection.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, List

from ltp_harness import manifest as manifest_mod

# Timeout layering, from the inside out (T is the tier timeout times the
# multiplier): the QEMU supervisor enforces T on the test and needs its
# fixed cleanup budget (about 12s, see tests/ltp/helpers/qemu-supervisor.c)
# afterwards; kirk's exec-timeout must therefore sit QEMU_EXEC_SLACK_SEC
# above T on that backend so the supervisor always reports before kirk
# cancels; and the channel's own per-command cap sits CHANNEL_CAP_SLACK_SEC
# above T as the outermost belt. A harness selftest asserts
# budget < QEMU_EXEC_SLACK_SEC < CHANNEL_CAP_SLACK_SEC.
QEMU_EXEC_SLACK_SEC = 25
CHANNEL_CAP_SLACK_SEC = 30

# Fixed schedule overhead allowed beyond the sum of all test timeouts.
SUITE_SLACK_SEC = 120


def _module_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def _check_option_value(value: str, what: str) -> str:
    """Kirk splits --com options on ':' and '='; refuse ambiguous paths."""
    from ltp_harness.cli import HarnessFatal

    if ":" in value or "=" in value:
        raise HarnessFatal(f"{what} must not contain ':' or '=': {value}")
    return value


def resolve_elfuse(repo_root: str) -> str:
    from ltp_harness.cli import HarnessSkip

    binary = os.environ.get("ELFUSE", os.path.join(repo_root, "build", "elfuse"))
    if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        raise HarnessSkip(f"elfuse binary is absent at {binary}; run: make elfuse")
    return os.path.realpath(binary)


def _kirk_paths(fixture_dir: str) -> Dict[str, str]:
    from ltp_harness.cli import HarnessFatal

    kirk_dir = os.path.join(fixture_dir, "kirk")
    if not os.path.isfile(os.path.join(kirk_dir, "libkirk", "main.py")):
        raise HarnessFatal(
            f"pinned kirk checkout missing under {kirk_dir}; "
            f"run: make build-ltp-fixture"
        )
    rootfs = os.path.join(fixture_dir, "rootfs")
    if not os.path.isdir(rootfs):
        raise HarnessFatal(f"rootfs missing under {fixture_dir}")
    return {"kirk_dir": kirk_dir, "rootfs": rootfs}


def make_run_dir(results_dir: str, backend: str, tier: str) -> str:
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    for attempt in range(100):
        suffix = f"-{attempt}" if attempt else ""
        run_dir = os.path.join(results_dir, f"{backend}-{tier}-{stamp}{suffix}")
        try:
            os.makedirs(run_dir, exist_ok=False)
            return run_dir
        except FileExistsError:
            continue

    from ltp_harness.cli import HarnessFatal

    raise HarnessFatal(f"cannot allocate a run directory under {results_dir}")


def _kirk_argv(
    backend: str,
    channel_options: Dict[str, str],
    args: argparse.Namespace,
    tests: List[Dict[str, Any]],
    paths: Dict[str, str],
    run_dir: str,
) -> List[str]:
    channel = {"elfuse": "elfuse", "qemu": "qemuchroot"}[backend]
    com_config = channel + "".join(
        f":{key}={_check_option_value(value, f'channel option {key!r}')}"
        for key, value in sorted(channel_options.items())
    )

    exec_timeout = manifest_mod.tier_timeout(tests, args.tier, args.test)
    exec_timeout = int(exec_timeout * args.timeout_mul)
    if backend == "qemu":
        exec_timeout += QEMU_EXEC_SLACK_SEC
    selection = manifest_mod.select_tests(tests, args.tier, args.test)
    suite_timeout = (
        int(sum(t["timeout_seconds"] for t in selection) * args.timeout_mul)
        + SUITE_SLACK_SEC
    )
    # Each qemu test's exec-timeout gains QEMU_EXEC_SLACK_SEC above, so the
    # suite budget must cover that per-test slack too, or kirk's suite deadline
    # can fire before the per-test deadlines have summed out.
    if backend == "qemu":
        suite_timeout += len(selection) * QEMU_EXEC_SLACK_SEC

    suites = sorted(
        {manifest_mod.suite_name(test["tier"]) for test in selection}
    )

    argv = [
        sys.executable,
        os.path.join(_module_dir(), "kirk_shim.py"),
        paths["kirk_dir"],
        os.path.join(os.path.dirname(_module_dir()), "plugins"),
        "--sut",
        f"default:com={channel}",
        "--com",
        com_config,
        "--run-suite",
    ]
    argv.extend(suites)
    if args.test:
        argv.extend(["--run-pattern", f"^{re.escape(args.test)}$"])
    argv.extend(
        [
            "--exec-timeout",
            str(exec_timeout),
            "--suite-timeout",
            str(suite_timeout),
            "--workers",
            str(args.workers),
            "--tmp-dir",
            run_dir,
            "--json-report",
            os.path.join(run_dir, f"kirk-{backend}.json"),
            "--no-colors",
        ]
    )
    return argv


def _kirk_env(mul: float) -> Dict[str, str]:
    """Environment for the kirk process itself.

    Kirk's LTP framework snapshots LTPROOT/TMPDIR and every LTP_*/TST_*
    variable from its own environment into the per-test env, using guest
    pathnames because the channels resolve them on the target.
    """
    env = dict(os.environ)
    env["LTPROOT"] = "/opt/ltp"
    env["TMPDIR"] = "/tmp"
    env["LTP_COLORIZE_OUTPUT"] = "0"
    env["LTP_TIMEOUT_MUL"] = str(mul)
    return env


def _run_kirk(argv: List[str], env: Dict[str, str], log_path: str) -> int:
    print(f"  KIRK    {' '.join(argv[4:])}")
    with open(log_path, "w", encoding="utf-8") as log:
        proc = subprocess.run(argv, env=env, stdout=log, stderr=subprocess.STDOUT)
    return proc.returncode


def _check_report(run_dir: str, backend: str, kirk_rc: int, log_path: str) -> None:
    from ltp_harness.cli import HarnessFatal

    report_path = os.path.join(run_dir, f"kirk-{backend}.json")
    try:
        with open(report_path, "r", encoding="utf-8") as handle:
            json.load(handle)
    except (OSError, ValueError) as err:
        tail = ""
        try:
            with open(log_path, "r", encoding="utf-8") as handle:
                tail = "".join(handle.readlines()[-25:])
        except OSError:
            pass
        raise HarnessFatal(
            f"kirk produced no usable report for backend '{backend}' "
            f"(rc {kirk_rc}): {err}\n{tail}"
        ) from err


def run_backends(
    backends: List[str],
    args: argparse.Namespace,
    tests: List[Dict[str, Any]],
    repo_root: str,
) -> str:
    from ltp_harness.cli import HarnessFatal

    fixture_dir = os.path.realpath(args.fixture_dir)
    paths = _kirk_paths(fixture_dir)
    results_dir = os.path.realpath(args.results_dir)
    os.makedirs(results_dir, exist_ok=True)
    run_dir = make_run_dir(
        results_dir, "-".join(backends) if len(backends) > 1 else backends[0], args.tier
    )

    tier_deadline = int(
        manifest_mod.tier_timeout(tests, args.tier, args.test) * args.timeout_mul
    )
    channel_cap = tier_deadline + CHANNEL_CAP_SLACK_SEC

    for backend in backends:
        if backend == "elfuse":
            options = {
                "binary": resolve_elfuse(repo_root),
                "sysroot": paths["rootfs"],
                "timeout": str(channel_cap),
            }
            argv = _kirk_argv(backend, options, args, tests, paths, run_dir)
            log_path = os.path.join(run_dir, f"kirk-{backend}.log")
            kirk_rc = _run_kirk(argv, _kirk_env(args.timeout_mul), log_path)
            _check_report(run_dir, backend, kirk_rc, log_path)
        elif backend == "qemu":
            from ltp_harness import vm

            vm.run_qemu_backend(
                args=args,
                paths=paths,
                run_dir=run_dir,
                repo_root=repo_root,
                sup_timeout=tier_deadline,
                channel_cap=channel_cap,
                kirk_argv_builder=lambda options: _kirk_argv(
                    "qemu", options, args, tests, paths, run_dir
                ),
                kirk_env=_kirk_env(args.timeout_mul),
                run_kirk=_run_kirk,
                check_report=_check_report,
            )
        else:
            raise HarnessFatal(f"unknown backend '{backend}'")

        if backend == "qemu" and len(backends) > 1:
            _require_qemu_green(run_dir, tests)

    return run_dir


def _require_qemu_green(run_dir: str, tests: List[Dict[str, Any]]) -> None:
    """In 'all' mode the reference lane must qualify before elfuse runs."""
    from ltp_harness import baseline as baseline_mod
    from ltp_harness.cli import HarnessFatal

    report_path = os.path.join(run_dir, "kirk-qemu.json")
    with open(report_path, "r", encoding="utf-8") as handle:
        report = json.load(handle)

    formats = {test["id"]: test["result_format"] for test in tests}
    observed = baseline_mod.observed_from_report(report, formats)
    bad = sorted(
        test_id
        for test_id, entry in observed.items()
        if entry["status"] not in ("PASS", "SKIP")
    )
    if bad:
        raise HarnessFatal(
            "QEMU reference lane did not qualify; elfuse will not run. "
            f"Non-passing: {', '.join(bad)}"
        )
