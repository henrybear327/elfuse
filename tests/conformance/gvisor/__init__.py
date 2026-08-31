# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from conformance import ids, payload, selection
from conformance.backends.base import Backend
from conformance.gvisor import gtest
from conformance.model import Attempt, Status
from conformance.providers.base import Case, Provider

API_ROOT = "https://api.github.com"
BUILD_RELPATH = Path("test/syscalls/linux/BUILD")
_CC_BINARY_RE = re.compile(r'cc_binary\(\s*\n\s*name = "([a-z0-9_]+_test)"')


def parse_build(text: str) -> List[str]:
    """Return *_test cc_binary names, excluding cc_library entries."""
    return sorted(_CC_BINARY_RE.findall(text))


def compare(sel: selection.Selection, upstream: List[str]) -> List[str]:
    listed = {e.group for e in sel.enabled} | {g for _, gs in sel.declined for g in gs}
    errors = ["%s vanished from the pinned BUILD; drop it from selection" % g
              for g in sorted(listed - set(upstream))]
    errors += ["%s is new upstream; triage it into enabled or declined" % g
               for g in sorted(set(upstream) - listed)]
    return errors


def _get_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "elfuse-conformance"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except (urllib.error.URLError, ValueError) as e:
        raise payload.UpdateError("%s: %s" % (url, e)) from None


class GvisorProvider(Provider):
    name = "gvisor"
    pins_schema = {"gvisor": {"repository": "url", "commit": "hex40", "tree": "hex40",
                              "date": "str", "subject": "str"}}

    def __init__(self, repo_root: Path):
        super().__init__(repo_root)
        self._selection: Optional[selection.Selection] = None
        self.listing: Dict[str, List[str]] = {}

    @property
    def selection(self) -> selection.Selection:
        if self._selection is None:
            self._selection = selection.load(self.suite_dir / "data" / "targets.jsonc")
        return self._selection

    def checkout_dir(self, commit: str) -> Path:
        return self.repo_root / "externals" / "gvisor" / commit

    def pins(self) -> Dict[str, Any]:
        return payload.load_pins(self.pins_path, self.pins_schema)

    def backend_options(self, backend: str) -> Dict[str, Any]:
        return {"mem_mib": self.selection.extra["qemu_mem_mib"]} if backend == "qemu" else {}

    def fingerprint(self) -> str:
        from conformance.gvisor import build as builder

        harness = self.repo_root / "tests" / "conformance"
        return payload.fingerprint(self.pins()["gvisor"], [
            self.suite_dir / "data" / "targets.jsonc", self.suite_dir / "build.py",
            harness / "elfcheck.py", harness / "payload.py"], builder.FLAVOR)

    def prerequisites(self, backend: str) -> Optional[str]:
        state = payload.status(self.payload_root(), self.fingerprint())
        if state in ("missing", "stale"):
            return payload.absent_message(self.name, self.payload_root(), state, self.build_hint())
        # Corruption is a verify error, not an absent prerequisite.
        return None

    def build_payload(self, force: bool = False) -> None:
        from conformance.gvisor import build as builder

        section = self.pins()["gvisor"]
        names = [e.group for e in self.selection.enabled]
        built = builder.build(section, self.checkout_dir(section["commit"]), self.payload_root(),
                              names, self.fingerprint(), force)
        print("%s: %s" % (self.payload_root(), "built %d binaries" % len(names) if built else "complete"))

    def binary(self, group: str) -> Path:
        return self.payload_root() / "bin" / group

    def enumerate(self, backend: Backend, entries: List[selection.Entry]) -> List[Case]:
        out: List[Case] = []
        suite_timeout = self.selection.extra.get("suite_timeout_s", 600)
        for entry in entries:
            guest = backend.guest_path(self.binary(entry.group))
            inv = backend.run(gtest.list_argv(guest), 60, self.scratch / "list" / entry.group)
            try:
                if gtest.status_of(inv) is not None or inv.exit_code != 0:
                    raise gtest.GtestError("listing exited %s (%s)" % (inv.exit_code, inv.execution))
                names = gtest.parse_list(Path(inv.stdout).read_text())
            except gtest.GtestError as e:
                out.append(Case("gvisor:%s/Harness.ListingFailed" % entry.group, entry.group, entry.scope,
                                suite_timeout, {"error": str(e), "invocation": inv}))
                continue
            self.listing[entry.group] = names
            for name in names:
                if entry.only and not ids.expand(list(entry.only), [name]):
                    continue
                out.append(Case("gvisor:%s/%s" % (entry.group, name), entry.group, entry.scope,
                                entry.timeout_s or suite_timeout, {"name": name}))
        return out

    @property
    def scratch(self) -> Path:
        return self.repo_root / "build" / "conformance" / "gvisor-scratch"

    def _invoke(self, backend: Backend, group: str, include: List[str], timeout_s: int,
                scratch: Path) -> Dict[str, Attempt]:
        exclude = [n for n in self.listing.get(group, []) if n not in set(include)]
        argv = gtest.run_argv(backend.guest_path(self.binary(group)), include, exclude)
        inv = backend.run(argv, timeout_s, scratch, fetch=["result.xml"])
        resolved = gtest.resolve(inv, scratch / "result.xml", include)
        return {"gvisor:%s/%s" % (group, n): a for n, a in resolved.items()}

    def run_batch(self, backend: Backend, cases: List[Case], scratch: Path) -> Dict[str, Attempt]:
        group = cases[0].group
        failed = [c for c in cases if "error" in c.meta]
        if failed:
            return {c.id: Attempt(Status.ERROR, c.meta["invocation"], c.meta["error"]) for c in failed}
        return self._invoke(backend, group, [c.meta["name"] for c in cases], cases[0].timeout_s, scratch)

    def run_single(self, backend: Backend, case: Case, scratch: Path) -> Attempt:
        if "error" in case.meta:
            return Attempt(Status.ERROR, case.meta["invocation"], case.meta["error"])
        timeout = self.selection.extra.get("case_timeout_s", 30)
        result = self._invoke(backend, case.group, [case.meta["name"]], timeout, scratch)
        return result[case.id]

    def regen_selection(self, check: bool = False) -> List[str]:
        # The selection file is hand-curated; update reports the same
        # drift for a human to apply.
        doc = self.pins()
        build = self.checkout_dir(doc["gvisor"]["commit"]) / BUILD_RELPATH
        if not build.is_file():
            return ["gVisor checkout is absent (%s); run: %s" % (build.parent, self.build_hint())]
        return compare(self.selection, parse_build(build.read_text()))

    def latest_pin(self, doc: Dict[str, Any], ref: Optional[str]) -> Dict[str, Any]:
        repo = doc["gvisor"]["repository"].removeprefix("https://github.com/").removesuffix(".git")
        if not ref:
            ref = _get_json("%s/repos/%s" % (API_ROOT, repo))["default_branch"]
        data = _get_json("%s/repos/%s/commits/%s" % (API_ROOT, repo, ref))
        doc["gvisor"].update({
            "commit": data["sha"],
            "tree": data["commit"]["tree"]["sha"],
            "date": data["commit"]["committer"]["date"][:10],
            "subject": data["commit"]["message"].splitlines()[0][:100],
        })
        return doc

    def update_next_steps(self) -> List[str]:
        return [
            self.build_hint(),
            "scripts/conformance selection check gvisor",
        ]
