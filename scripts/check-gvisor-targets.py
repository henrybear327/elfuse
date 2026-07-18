#!/usr/bin/env python3
"""Best-effort drift audit for the gVisor conformance target allowlist.

Enumerates every *_test target declared in the pinned gVisor checkout's
test/syscalls/linux/BUILD and compares it against the enabled allowlist in
tests/conformance/gvisor/targets.txt. Available-but-not-enabled targets are
printed as opt-in candidates (informational). The audit fails only when an
enabled target no longer exists at the pin (a stale label after a pin bump),
which would otherwise surface later as a confusing build failure.

The checkout only exists after `make build-gvisor-tests` clones it; when it is
absent the audit exits 77 (SKIP), matching the runner's optional-skip idiom.
"""

# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
COMMON = ROOT / "tests" / "lib" / "gvisor-common.sh"
TARGETS = ROOT / "tests" / "conformance" / "gvisor" / "targets.txt"

PIN_RE = re.compile(r"^GVISOR_PIN=([0-9a-fA-F]+)", re.MULTILINE)
LABEL_RE = re.compile(r"//test/syscalls/linux:([A-Za-z0-9_]+_test)")
BUILD_NAME_RE = re.compile(r'name\s*=\s*"([A-Za-z0-9_]+_test)"')

SKIP_EXIT = 77


def read_pin() -> str:
    match = PIN_RE.search(COMMON.read_text(encoding="utf-8"))
    if not match:
        raise SystemExit("check-gvisor-targets: could not read GVISOR_PIN from gvisor-common.sh")
    return match.group(1)


def enabled_targets() -> set[str]:
    names: set[str] = set()
    for line in TARGETS.read_text(encoding="utf-8").splitlines():
        code = line.split("#", 1)[0].strip()
        if not code:
            continue
        match = LABEL_RE.search(code)
        if match:
            names.add(match.group(1))
    return names


def available_targets(build: pathlib.Path) -> set[str]:
    # Best-effort: matches cc_binary/syscall_test/cc_library names ending in
    # _test. A stray library name is harmless (it only ever shows up as a
    # candidate, never as enabled), matching check-syscall-coverage's spirit.
    return set(BUILD_NAME_RE.findall(build.read_text(encoding="utf-8")))


def main() -> int:
    if len(sys.argv) > 1:
        checkout = pathlib.Path(sys.argv[1])
    else:
        checkout = ROOT / "externals" / "gvisor" / read_pin()
    build = checkout / "test" / "syscalls" / "linux" / "BUILD"
    if not build.is_file():
        print(f"SKIP check-gvisor-targets: gVisor checkout not present ({build})")
        print("  Build the payload first with: make build-gvisor-tests")
        return SKIP_EXIT

    enabled = enabled_targets()
    available = available_targets(build)
    if not available:
        raise SystemExit(f"check-gvisor-targets: no *_test targets found in {build}")

    stale = sorted(enabled - available)
    candidates = sorted(available - enabled)

    print(f"gVisor targets: {len(enabled)} enabled, {len(available)} available at the pin")
    if candidates:
        print(f"\nAvailable but not enabled ({len(candidates)} opt-in candidates):")
        for name in candidates:
            print(f"  {name}")
    if stale:
        print(
            f"\nERROR: {len(stale)} enabled target(s) no longer exist at the pin:",
            file=sys.stderr,
        )
        for name in stale:
            print(f"  //test/syscalls/linux:{name}", file=sys.stderr)
        print(
            "Reconcile tests/conformance/gvisor/targets.txt with the current pin.",
            file=sys.stderr,
        )
        return 1
    print("\ncheck-gvisor-targets: no stale enabled targets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
