"""Conformance harness CLI: run, list, lint, deflake, report.

Exit-code contract (shared with mk/tests.mk's RUN_OPTIONAL_SKIP77):
0 every case as-expected (or flaked/filtered), 1 gate red, 2 usage or
configuration error, 77 an optional prerequisite (payload, elfuse
binary, qemu, fixtures) is provably absent. CONF_REQUIRE=1 turns 77
into 2, because a silent SKIP in a gating CI job would be a fake green.
Bootstrap mode (--bootstrap) runs without gating and reports observed
statuses, for seeding the expectation files.

The lane driver synthesizes one gvisor:<binary>/Harness.ListingFailed
ERROR case when a binary cannot even be enumerated, so an unloadable
binary reads as a red harness fault, never as an empty green.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import fnmatch
import os
import pathlib
import shutil
import sys

_PACKAGE_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_PACKAGE_DIR.parent))

from conformance import (audit, backends, expectations, gtest, ids,
                         jsonc, ltp, pins, ratchet, report)
from conformance.model import Attempt, CaseResult, Status, Verdict

REPO_ROOT = _PACKAGE_DIR.parents[1]
# Overridable so hermetic selftests can point at an empty root and CI at
# an unpacked artifact; defaults to the fixture location.
PAYLOAD_ROOT = pathlib.Path(os.environ.get(
    "CONF_PAYLOAD_DIR", REPO_ROOT / "externals" / "payloads"))
EXPECTATIONS_DIR = _PACKAGE_DIR / "expectations"
TIMEOUTS_PATH = _PACKAGE_DIR / "data" / "gvisor-timeouts.jsonc"
EXIT_OK, EXIT_RED, EXIT_USAGE, EXIT_SKIP = 0, 1, 2, 77


def _skip(code=EXIT_SKIP):
    return EXIT_USAGE if os.environ.get("CONF_REQUIRE") == "1" else code


def _results_dir(args, lane):
    base = pathlib.Path(args.results or (REPO_ROOT / "build" / "conformance"))
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ")
    return base / lane / ("%s-%d" % (stamp, os.getpid()))


def _load_expectations(suite, backend):
    return expectations.load(suite, backend, EXPECTATIONS_DIR)


def _gvisor_payload():
    doc = pins.load()
    payload = PAYLOAD_ROOT / "gvisor" / doc["gvisor"]["commit"]
    return payload if (payload / "manifest.json").is_file() else None


def _make_backend(suite, backend_name):
    if backend_name == "elfuse":
        binary = REPO_ROOT / "build" / "elfuse"
        if not binary.is_file():
            return None, "elfuse binary is absent; run: make"
        sysroot = None
        if suite == "ltp":
            sysroot = PAYLOAD_ROOT / "ltp" / "rootfs"
        return backends.ElfuseBackend(binary, sysroot=sysroot), None
    if not shutil.which("qemu-system-aarch64"):
        return None, "qemu-system-aarch64 is not installed"
    if suite == "gvisor":
        qemu_mem = jsonc.load_path(TIMEOUTS_PATH).get("qemu_mem_mib")
    else:
        from conformance.payload import ltp as ltp_payload
        qemu_mem = ltp_payload.load_manifest().get("qemu_mem_mib")
    return backends.QemuBackend(qemu_mem=qemu_mem), None


def _timeouts():
    doc = jsonc.load_path(TIMEOUTS_PATH)
    return (doc.get("suite_timeout_s", 600), doc.get("case_timeout_s", 30),
            doc.get("per_binary", {}))


def _gvisor_lane(args, exp, backend, payload, results_dir):
    import json
    manifest = json.loads((payload / "manifest.json").read_text())
    binaries = sorted(manifest)
    if args.filter:
        binaries = [b for b in binaries
                    if fnmatch.fnmatchcase("gvisor:%s/" % b + "*",
                                           args.filter)
                    or fnmatch.fnmatchcase(b, args.filter)]
    suite_timeout, case_timeout, per_binary = _timeouts()
    cases, messages, listings = [], [], []

    def run_one_binary(name):
        scratch = results_dir / "cases" / name
        scratch.mkdir(parents=True, exist_ok=True)
        binary = payload / name
        local_cases, local_msgs = [], []
        try:
            listing = gtest.discover(backend, binary, scratch)
        except (gtest.GtestParseError, backends.BackendError) as exc:
            case = CaseResult(
                id="gvisor:%s/Harness.ListingFailed" % name, suite="gvisor",
                backend=backend.name, status=Status.ERROR,
                verdict=Verdict.ERROR, expectation={},
                attempts=[], detail=str(exc), artifacts=str(scratch))
            _, message = ratchet.judge(case.id, backend.name, Status.ERROR,
                                       None, detail=str(exc))
            return [case], [message], []
        case_ids = ["gvisor:%s/%s" % (name, c) for c in listing]
        resolutions = {cid: exp.resolve(cid) for cid in case_ids}
        excluded = {cid.split("/", 1)[1] for cid, res in resolutions.items()
                    if res.type == "skip"}
        results = gtest.run_binary(
            backend, binary, listing, excluded=excluded, scratch=scratch,
            suite_timeout_s=per_binary.get(name, suite_timeout),
            case_timeout_s=case_timeout)
        for cid in case_ids:
            res = resolutions[cid]
            short = cid.split("/", 1)[1]
            if res.type == "skip":
                local_cases.append(CaseResult(
                    id=cid, suite="gvisor", backend=backend.name,
                    status=Status.SKIP, verdict=Verdict.FILTERED,
                    expectation=vars(res), attempts=[], detail=res.reason,
                    artifacts=""))
                continue
            status, detail = results[short]
            attempts = [Attempt(status=status, exit_code=0, wall_us=0,
                                execution="normal", detail=detail)]
            if args.bootstrap:
                verdict, message = Verdict.AS_EXPECTED, None
            else:
                verdict, message = ratchet.judge(cid, backend.name, status,
                                                 res, detail=detail)
                # Retries are legal only for quarantined ids; the first
                # attempt already ran in the batch, so up to two isolated
                # reruns follow.
                while verdict.is_red and res.quarantined and \
                        len(attempts) < ratchet.MAX_ATTEMPTS:
                    sub = scratch / ("retry-%d-%s"
                                     % (len(attempts), ids.slug(cid)))
                    sub.mkdir(parents=True, exist_ok=True)
                    status, detail = gtest.run_one(backend, binary, short,
                                                   sub, case_timeout)
                    attempts.append(Attempt(status=status, exit_code=0,
                                            wall_us=0, execution="normal",
                                            detail=detail))
                    verdict, message = ratchet.judge(
                        cid, backend.name, status, res, detail=detail)
                if verdict is Verdict.AS_EXPECTED and len(attempts) > 1:
                    verdict, message = Verdict.FLAKED, None
            local_cases.append(CaseResult(
                id=cid, suite="gvisor", backend=backend.name,
                status=attempts[-1].status, verdict=verdict,
                expectation=vars(res), attempts=attempts,
                detail=attempts[-1].detail, artifacts=str(scratch)))
            if message:
                local_msgs.append(message)
        return local_cases, local_msgs, case_ids

    jobs = args.jobs if backend.name == "elfuse" else 1
    if jobs > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            outcomes = list(pool.map(run_one_binary, binaries))
    else:
        outcomes = [run_one_binary(b) for b in binaries]
    for local_cases, local_msgs, case_ids in outcomes:
        cases.extend(local_cases)
        messages.extend(local_msgs)
        listings.extend(case_ids)
    if not args.bootstrap and not args.filter:
        stale = exp.check_stale(listings)
        if stale:
            for error in stale:
                print("stale expectation: %s" % error, file=sys.stderr)
            return cases, messages, EXIT_USAGE
    return cases, messages, None


def _ltp_entries(args):
    from conformance.payload import ltp as ltp_payload
    manifest = ltp_payload.load_manifest()
    tier = args.tier or "fast"
    entries = [e for e in manifest["tests"] if e["tier"] == tier]
    if tier in ("sweep", "sweep-slow"):
        runtest = (PAYLOAD_ROOT / "ltp" / "metadata" /
                   "syscalls.runtest").read_text(encoding="utf-8")
        entries = [e for e in
                   ltp_payload.generate_sweep(runtest, manifest)
                   if e["tier"] == tier]
    if args.filter:
        entries = [e for e in entries
                   if fnmatch.fnmatchcase("ltp:" + e["id"], args.filter)]
    return entries


def _ltp_lane(args, exp, backend, results_dir):
    payload = PAYLOAD_ROOT / "ltp"
    rootfs = payload / "rootfs"
    entries = _ltp_entries(args)
    resolutions = {"ltp:" + e["id"]: exp.resolve("ltp:" + e["id"])
                   for e in entries}
    if not args.bootstrap and not args.filter:
        # Staleness is judged against the whole discoverable id space
        # (curated tiers plus the generated sweep), never against one
        # tier's subset: a suite-wide matcher legitimately names tests
        # outside the tier being run.
        from conformance.payload import ltp as ltp_payload
        manifest = ltp_payload.load_manifest()
        full = ["ltp:" + e["id"] for e in manifest["tests"]]
        runtest = payload / "metadata" / "syscalls.runtest"
        if runtest.is_file():
            full += ["ltp:" + e["id"] for e in ltp_payload.generate_sweep(
                runtest.read_text(encoding="utf-8"), manifest)]
        stale = exp.check_stale(full)
        if stale:
            for error in stale:
                print("stale expectation: %s" % error, file=sys.stderr)
            return [], [], EXIT_USAGE
    cases, messages = [], []
    planned = []
    for entry in entries:
        cid = "ltp:" + entry["id"]
        res = resolutions[cid]
        if res.type == "skip":
            cases.append(CaseResult(
                id=cid, suite="ltp", backend=backend.name,
                status=Status.SKIP, verdict=Verdict.FILTERED,
                expectation=vars(res), attempts=[], detail=res.reason,
                artifacts=""))
        else:
            planned.append(entry)
    attempts = {"ltp:" + entry["id"]: [] for entry in planned}
    pending = list(planned)
    for round_number in range(ratchet.MAX_ATTEMPTS):
        for bucket, bucket_entries in sorted(
                ltp.partition_timeouts(pending).items()):
            suite_name = "conf-%d-%d-%d" % (
                os.getpid(), bucket, round_number + 1)
            runtest_path = rootfs / "opt" / "ltp" / "runtest" / suite_name
            runtest_path.write_text(
                "\n".join(
                    " ".join([e["id"]] +
                             list(e.get("arguments") or [e["id"]]))
                    for e in bucket_entries) + "\n",
                encoding="utf-8")
            try:
                report_path = results_dir / ("kirk-%s.json" % suite_name)
                kirk_tmp = results_dir / ("kirk-tmp-%s" % suite_name)
                kirk_tmp.mkdir(parents=True, exist_ok=True)
                if backend.name == "elfuse":
                    options = {
                        "binary": REPO_ROOT / "build" / "elfuse",
                        "sysroot": rootfs,
                        "timeout": bucket + ltp.CHANNEL_CAP_SLACK_SEC,
                    }
                    channel = "elfuse"
                else:
                    options = {
                        "port": backend.state["port"],
                        "key_file": backend.state["key"],
                        "supervisor": backend.host_to_guest(
                            payload / "bin" / "guest-supervisor"),
                        "rootfs_src": backend.host_to_guest(rootfs),
                        "rootfs_host": rootfs,
                        "sup_timeout": bucket,
                        "timeout": bucket + ltp.CHANNEL_CAP_SLACK_SEC,
                    }
                    channel = "qemuchroot"
                argv = ltp.kirk_argv(
                    payload / "kirk", channel=channel,
                    channel_options=options, suite=suite_name,
                    exec_timeout_s=bucket + ltp.QEMU_EXEC_SLACK_SEC,
                    suite_timeout_s=(bucket + ltp.QEMU_EXEC_SLACK_SEC)
                    * max(len(bucket_entries), 1),
                    report_path=report_path, tmp_dir=kirk_tmp)
                kirk_rc = ltp.run_kirk(argv, ltproot="/opt/ltp")
                if not report_path.is_file():
                    raise ltp.LtpRunnerError(
                        "kirk exited %d without writing %s"
                        % (kirk_rc, report_path))
                mapped = ltp.map_report(ltp.load_report(report_path))
            finally:
                runtest_path.unlink(missing_ok=True)
            for entry in bucket_entries:
                cid = "ltp:" + entry["id"]
                status, detail = mapped.get(
                    entry["id"],
                    (Status.ERROR, "missing from the kirk report"))
                execution = "normal"
                if status is Status.TIMEOUT:
                    execution = "timeout"
                elif status is Status.CRASH:
                    execution = "signal"
                attempts[cid].append(Attempt(
                    status=status, exit_code=0, wall_us=0,
                    execution=execution, detail=detail))
        if args.bootstrap:
            break
        retry = []
        for entry in pending:
            cid = "ltp:" + entry["id"]
            final = attempts[cid][-1]
            verdict, _ = ratchet.judge(
                cid, backend.name, final.status, resolutions[cid],
                detail=final.detail)
            if verdict.is_red and resolutions[cid].quarantined and \
                    len(attempts[cid]) < ratchet.MAX_ATTEMPTS:
                retry.append(entry)
        pending = retry
        if not pending:
            break

    for entry in planned:
        cid = "ltp:" + entry["id"]
        res = resolutions[cid]
        final = attempts[cid][-1]
        if args.bootstrap:
            verdict, message = Verdict.AS_EXPECTED, None
        else:
            verdict, message = ratchet.judge(
                cid, backend.name, final.status, res, detail=final.detail)
            if verdict is Verdict.AS_EXPECTED and len(attempts[cid]) > 1:
                verdict, message = Verdict.FLAKED, None
        cases.append(CaseResult(
            id=cid, suite="ltp", backend=backend.name, status=final.status,
            verdict=verdict, expectation=vars(res), attempts=attempts[cid],
            detail=final.detail, artifacts=""))
        if message:
            messages.append(message)
    return cases, messages, None


def cmd_run(args) -> int:
    try:
        exp = _load_expectations(args.suite, args.backend)
    except expectations.ExpectationError as exc:
        print(exc, file=sys.stderr)
        return EXIT_USAGE
    if args.suite == "gvisor":
        payload = _gvisor_payload()
        if payload is None:
            print("gVisor payload is absent; run: make build-gvisor-payload")
            return _skip()
        from conformance.payload import gvisor as gvisor_payload
        try:
            gvisor_payload.verify(directory=payload)
        except gvisor_payload.PayloadError as exc:
            print("gVisor payload verification failed: %s" % exc,
                  file=sys.stderr)
            return EXIT_USAGE
    else:
        if not (PAYLOAD_ROOT / "ltp" / ".complete").is_file():
            print("LTP payload is absent; run: make build-ltp-payload")
            return _skip()
        from conformance.payload import ltp as ltp_payload
        try:
            ltp_payload.verify(directory=PAYLOAD_ROOT / "ltp")
        except ltp_payload.PayloadError as exc:
            print("LTP payload verification failed: %s" % exc,
                  file=sys.stderr)
            return EXIT_USAGE
    backend, why = _make_backend(args.suite, args.backend)
    if backend is None:
        print(why)
        return _skip()
    lane = "%s-%s" % (args.suite, args.backend)
    results_dir = _results_dir(args, lane)
    results_dir.mkdir(parents=True, exist_ok=True)
    try:
        backend.start()
    except backends.BackendError as exc:
        print(exc, file=sys.stderr)
        return _skip()
    try:
        if args.suite == "gvisor":
            cases, messages, err = _gvisor_lane(args, exp, backend,
                                                payload, results_dir)
        else:
            cases, messages, err = _ltp_lane(args, exp, backend, results_dir)
    finally:
        backend.stop()
    run_meta = {"lane": lane, "argv": sys.argv[1:],
                "bootstrap": bool(args.bootstrap)}
    report.write_results(results_dir, run_meta, cases)
    report.print_summary(run_meta, cases, messages)
    print("Results: %s" % results_dir)
    if err is not None:
        return err
    if args.bootstrap:
        return EXIT_OK if not any(
            c.status is Status.ERROR for c in cases) else EXIT_RED
    return EXIT_OK if report.gate(cases) == "green" else EXIT_RED


def cmd_lint(args) -> int:
    failed = False
    for suite in ("gvisor", "ltp"):
        for backend_name in ("elfuse", "qemu"):
            try:
                expectations.load(suite, backend_name, EXPECTATIONS_DIR)
            except expectations.ExpectationError as exc:
                print("lint: %s" % exc, file=sys.stderr)
                failed = True
    return EXIT_RED if failed else EXIT_OK


def cmd_list_expectations(args) -> int:
    exp = _load_expectations(args.suite, args.backend)
    listing = [line.strip() for line in sys.stdin if line.strip()] \
        if not sys.stdin.isatty() else []
    print("id,type,file,matcher,reason,bug")
    for test_id in listing:
        res = exp.resolve(test_id)
        print(",".join([test_id, res.type, res.file, res.matcher,
                        (res.reason or "").replace(",", ";"),
                        res.bug or ""]))
    return EXIT_OK


def cmd_pin(args) -> int:
    print(pins.lookup(pins.load(), args.path))
    return EXIT_OK


def cmd_report(args) -> int:
    try:
        result = report.load_gate(args.results)
    except report.ReportError as exc:
        print(exc, file=sys.stderr)
        return EXIT_USAGE
    return EXIT_OK if result == "green" else EXIT_RED


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="conformance")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run")
    run_p.add_argument("--suite", required=True, choices=("gvisor", "ltp"))
    run_p.add_argument("--backend", required=True,
                       choices=("elfuse", "qemu"))
    run_p.add_argument("--filter")
    run_p.add_argument("--jobs", type=int,
                       default=min(4, (os.cpu_count() or 2) // 2) or 1)
    run_p.add_argument("--tier")
    run_p.add_argument("--bootstrap", action="store_true")
    run_p.add_argument("--results")
    run_p.set_defaults(func=cmd_run)

    lint_p = sub.add_parser("lint-expectations")
    lint_p.set_defaults(func=cmd_lint)

    lexp_p = sub.add_parser("list-expectations")
    lexp_p.add_argument("--suite", required=True)
    lexp_p.add_argument("--backend", required=True)
    lexp_p.set_defaults(func=cmd_list_expectations)

    pin_p = sub.add_parser("pin")
    pin_p.add_argument("path")
    pin_p.set_defaults(func=cmd_pin)

    audit_p = sub.add_parser("audit")
    audit_p.set_defaults(func=lambda args: audit.main([]))

    report_p = sub.add_parser("report")
    report_p.add_argument("--results", required=True)
    report_p.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except pins.PinError as exc:
        print(exc, file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
