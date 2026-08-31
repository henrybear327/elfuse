# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

import os

from conformance import ids, jsonc, payload, selection
from conformance.backends import proc
from conformance.backends.base import Backend
from conformance.ltp import results
from conformance.model import Attempt, Invocation, Status
from conformance.providers.base import Case, Provider

API_ROOT = "https://api.github.com"
DEFAULT_TIMEOUT_S = 60


def _get_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "elfuse-conformance"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except (urllib.error.URLError, ValueError) as e:
        raise payload.UpdateError("%s: %s" % (url, e)) from None


def _epoch(iso: str) -> int:
    import datetime

    return int(datetime.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())


def _fetch_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "elfuse-conformance"})
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return resp.read()
    except urllib.error.URLError as e:
        raise payload.UpdateError("%s: %s" % (url, e)) from None


def generate_full(runtest_text: str, release: str, overrides: Dict[str, Dict[str, Any]]) -> str:
    """Generate the full selection from pinned runtest tags."""
    from conformance.ltp import build

    entries = build.parse_runtest(runtest_text)
    tags = {t for t, _ in entries}
    stale = sorted(set(overrides) - tags)
    if stale:
        raise selection.SelectionError("overrides name no runtest entry: %s" % ", ".join(stale))
    lines = ["// Generated from pinned runtest tags; edit pr.jsonc, not this file.",
             "{", '  "schema_version": 1,',
             '  "provenance": { "release": %s, "entries": %d },' % (json.dumps(release), len(entries)),
             '  "enabled": [']
    for tag, argv in entries:
        entry: Dict[str, Any] = {"group": tag, "scope": "full"}
        override = overrides.get(tag, {})
        if override.get("timeout_s"):
            entry["timeout_s"] = override["timeout_s"]
        fields = ", ".join('"%s": %s' % (k, json.dumps(v)) for k, v in entry.items())
        lines.append("    { %s }," % fields)
    lines += ["  ],", "}", ""]
    return "\n".join(lines)


class LtpProvider(Provider):
    name = "ltp"
    default_timeout_s = DEFAULT_TIMEOUT_S
    pins_schema = {
        "ltp": {"project": "str", "release": "str", "commit": "hex40", "archive_url": "url",
                "archive_sha256": "hex64", "sha256_url": "url", "source_date_epoch": "int"},
        "kirk": {"project": "str", "tag": "str", "archive_url": "url", "archive_sha256": "hex64"},
    }

    def __init__(self, repo_root: Path):
        super().__init__(repo_root)
        self._selection: Optional[selection.Selection] = None
        self._pr: Optional[Dict[str, Any]] = None

    def pr_doc(self) -> Dict[str, Any]:
        if self._pr is None:
            self._pr = jsonc.load(self.suite_dir / "data" / "pr.jsonc")
        return self._pr

    @property
    def selection(self) -> selection.Selection:
        if self._selection is None:
            doc = jsonc.load(self.suite_dir / "data" / "full.jsonc")
            pr = self.pr_doc()
            curated = {e["group"]: e for e in pr["pr"]}
            unknown = sorted(set(curated) - {e["group"] for e in doc["enabled"]})
            if unknown:
                raise selection.SelectionError("pr.jsonc names tags absent from full.jsonc: %s" % ", ".join(unknown))
            for e in doc["enabled"]:
                if e["group"] in curated:
                    e["scope"] = "pr"
                    if curated[e["group"]].get("timeout_s"):
                        e["timeout_s"] = curated[e["group"]]["timeout_s"]
            doc["declined"] = pr.get("declined", [])
            self._selection = selection.parse(doc, "full.jsonc")
        return self._selection

    def argv_of(self) -> Dict[str, List[str]]:
        """Return argv by tag from the payload's pinned runtest file."""
        from conformance.ltp import build

        text = (self.payload_root() / "metadata" / "syscalls.runtest").read_text()
        return {tag: argv for tag, argv in build.parse_runtest(text)}

    def overrides(self) -> Dict[str, Dict[str, Any]]:
        return self.pr_doc().get("overrides", {})

    def pins(self) -> Dict[str, Any]:
        return payload.load_pins(self.pins_path, self.pins_schema)

    def backend_options(self, backend: str) -> Dict[str, Any]:
        if backend == "qemu":
            return {"mem_mib": self.pr_doc().get("qemu_mem_mib", 4096)}
        if backend == "elfuse":
            return {"sysroot": self.payload_root() / "rootfs"}
        return {}

    def fingerprint(self) -> str:
        from conformance.ltp import build

        harness = self.repo_root / "tests" / "conformance"
        doc = self.pins()
        try:
            cc = build.compiler_id(build.resolve_cross())
        except payload.PayloadError:
            cc = "no-compiler"
        try:
            busybox = payload.sha256_file(build.resolve_busybox(self.repo_root))
        except payload.PayloadError:
            busybox = "no-busybox"
        return payload.fingerprint({"ltp": doc["ltp"], "kirk": doc["kirk"]}, [
            self.suite_dir / "data" / "full.jsonc", self.suite_dir / "data" / "pr.jsonc",
            self.suite_dir / "build.py", self.suite_dir / "helpers" / "case-launcher.c",
            self.suite_dir / "helpers" / "guest-supervisor.c",
            harness / "elfcheck.py", harness / "payload.py"], "%s:busybox=%s" % (cc, busybox))

    def prerequisites(self, backend: str) -> Optional[str]:
        state = payload.status(self.payload_root(), self.fingerprint())
        if state in ("missing", "stale"):
            return payload.absent_message(self.name, self.payload_root(), state, self.build_hint())
        return None  # a corrupt tree is the CLI's verify error, not a skip

    def build_payload(self, force: bool = False) -> None:
        from conformance.ltp import build

        doc = self.pins()
        overrides = self.overrides()
        tags = {e.group: overrides.get(e.group, {}).get("source_dir") for e in self.selection.enabled}
        built = build.build({"ltp": doc["ltp"], "kirk": doc["kirk"]}, self.payload_root(), self.repo_root,
                            self.suite_dir / "helpers", tags, self.fingerprint(), force)
        print("%s: %s" % (self.payload_root(), "built %d tests" % len(tags) if built else "complete"))

    def enumerate(self, backend: Backend, entries: List[selection.Entry]) -> List[Case]:
        argv = self.argv_of()
        return [Case("ltp:" + e.group, e.group, e.scope, e.timeout_s or self.default_timeout_s,
                     {"argv": argv.get(e.group, [])}) for e in entries]

    def batch_key(self, case: Case) -> str:
        return "bucket-%d" % results.bucket_of(case.timeout_s)

    def _channel_options(self, backend: Backend, deadline_s: int, serve: Path, scratch: Path) -> Dict[str, Any]:
        root = self.payload_root()
        if backend.name == "elfuse":
            return {"binary": backend.binary, "sysroot": root / "rootfs",
                    "timeout": deadline_s + results.EXEC_SLACK_S + results.CAP_SLACK_S, "serve": serve}
        if backend.name == "qemu":
            session = backend.session
            return {"port": session.port, "key": session.key,
                    "supervisor": backend.guest_path(root / "bin" / "guest-supervisor"),
                    "rootfs_guest": backend.guest_path(root / "rootfs"), "rootfs_host": root / "rootfs",
                    "deadline": deadline_s, "timeout": deadline_s + results.EXEC_SLACK_S + results.CAP_SLACK_S,
                    "serve": serve, "scratch": scratch / "ssh"}
        raise NotImplementedError("the ltp suite runs on elfuse or qemu")

    def _run_kirk(self, backend: Backend, cases: List[Case], scratch: Path) -> Dict[str, Attempt]:
        deadline = max(c.timeout_s for c in cases)
        scratch.mkdir(parents=True, exist_ok=True)
        serve = scratch / "runtest"
        serve.mkdir(exist_ok=True)
        (serve / "batch").write_text(results.runtest_text([(c.group, c.meta["argv"]) for c in cases]))
        report = scratch / "kirk-report.json"
        tmp = scratch / "kirk-tmp"
        tmp.mkdir(exist_ok=True)
        argv = results.kirk_argv(self.suite_dir / "kirk" / "shim.py", self.payload_root() / "kirk",
                                 backend.name, self._channel_options(backend, deadline, serve, scratch),
                                 "batch", deadline + results.EXEC_SLACK_S,
                                 (deadline + results.EXEC_SLACK_S) * len(cases) + 300, report, tmp)
        env = dict(os.environ, LTPROOT="/opt/ltp", PYTHONDONTWRITEBYTECODE="1")
        inv = proc.run_local([str(a) for a in argv], 24 * 3600, scratch, env=env, stdout_name="kirk.log")
        if not report.is_file():
            return {c.id: Attempt(Status.ERROR, inv, "kirk exited %s without a report; see %s" % (
                inv.exit_code, scratch / "kirk.log")) for c in cases}
        mapped = results.map_report(report, scratch / "logs")
        return {"ltp:" + tag: attempt for tag, attempt in mapped.items()}

    def run_batch(self, backend: Backend, cases: List[Case], scratch: Path) -> Dict[str, Attempt]:
        return self._run_kirk(backend, cases, scratch)

    def run_single(self, backend: Backend, case: Case, scratch: Path) -> Attempt:
        out = self._run_kirk(backend, [case], scratch)
        if case.id not in out:
            inv = next(iter(out.values())).invocation if out else Invocation("transport", 0, stdout=str(scratch / "kirk.log"))
            return Attempt(Status.ERROR, inv, "kirk's report omits %s" % case.id)
        return out[case.id]

    def latest_pin(self, doc: Dict[str, Any], ref: Optional[str]) -> Dict[str, Any]:
        tag = ref
        for section, kind in (("ltp", "release"), ("kirk", "tag")):
            repo = doc[section]["project"]
            latest = _get_json("%s/repos/%s/releases/%s" % (API_ROOT, repo, ("tags/" + tag) if tag and section == "ltp" else "latest"))
            name = latest["tag_name"]
            assets = {a["name"]: a["browser_download_url"] for a in latest.get("assets", [])}
            if section == "ltp":
                commit = _get_json("%s/repos/%s/commits/%s" % (API_ROOT, repo, name))
                archive = "ltp-full-%s.tar.xz" % name
                if archive not in assets or archive + ".sha256" not in assets:
                    raise payload.UpdateError("release %s has no %s asset" % (name, archive))
                digest = _fetch_bytes(assets[archive + ".sha256"]).decode().split()[0]
                if digest != hashlib.sha256(_fetch_bytes(assets[archive])).hexdigest():
                    raise payload.UpdateError("release %s: archive digest does not match its .sha256 asset" % name)
                doc["ltp"].update({"release": name, "archive_url": assets[archive],
                                   "archive_sha256": digest, "sha256_url": assets[archive + ".sha256"],
                                   "commit": commit["sha"], "source_date_epoch": _epoch(commit["commit"]["committer"]["date"])})
            else:
                url = "https://github.com/%s/archive/refs/tags/%s.tar.gz" % (repo, name)
                doc["kirk"].update({"tag": name, "archive_url": url,
                                    "archive_sha256": hashlib.sha256(_fetch_bytes(url)).hexdigest()})
        return doc

    def update_next_steps(self) -> List[str]:
        return [
            self.build_hint(),
            "scripts/conformance selection update ltp",
            "scripts/conformance selection check ltp",
        ]

    def regen_selection(self, check: bool = False) -> List[str]:
        runtest = self.payload_root() / "metadata" / "syscalls.runtest"
        if not runtest.is_file():
            return ["%s is absent; run: %s" % (runtest, self.build_hint())]
        text = generate_full(runtest.read_text(), self.pins()["ltp"]["release"], self.overrides())
        target = self.suite_dir / "data" / "full.jsonc"
        current = target.read_text() if target.exists() else ""
        if text == current:
            return []
        if check:
            return [
                "%s is stale against the pinned runtest; run: "
                "scripts/conformance selection update ltp" % target
            ]
        payload.atomic_write(target, text)
        return ["%s rewritten" % target]
