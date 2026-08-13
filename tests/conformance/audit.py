"""Audit: the roster must cover the pinned BUILD file exactly.

Every *_test cc_binary in the pinned test/syscalls/linux/BUILD appears in
data/gvisor-targets.jsonc exactly once, enabled or declined with a
reason. A target that vanished upstream and an upstream binary that is
neither enabled nor declined are both errors, so a pin bump forces triage
instead of silently shrinking coverage. BUILD parsing is block-aware:
the file also declares a cc_library named base_poll_test. Set comparison
stays in Python because locale-collated shell sorting misorders names
like preadv_test against preadv2_test.

Runs standalone (python3 tests/conformance/audit.py): exit 0 clean,
1 on violations, 77 when the pinned checkout is absent.
"""

from __future__ import annotations

import pathlib
import re
import sys

_PACKAGE_DIR = pathlib.Path(__file__).resolve().parent
ROSTER_PATH = _PACKAGE_DIR / "data" / "gvisor-targets.jsonc"
REPO_ROOT = _PACKAGE_DIR.parents[1]
BUILD_RELPATH = pathlib.Path("test/syscalls/linux/BUILD")
_PREFIX = "//test/syscalls/linux:"

_CC_BINARY_RE = re.compile(r'cc_binary\(\s*\n\s*name = "([a-z0-9_]+_test)"')


def parse_build(text: str) -> list:
    return sorted(_PREFIX + name for name in _CC_BINARY_RE.findall(text))


def load_roster(path=ROSTER_PATH):
    from conformance import jsonc
    doc = jsonc.load_path(path)
    return doc["enabled"], doc["declined"]


def compare(roster_doc_or_pair, upstream) -> list:
    if isinstance(roster_doc_or_pair, dict):
        enabled = roster_doc_or_pair["enabled"]
        declined = roster_doc_or_pair["declined"]
    else:
        enabled, declined = roster_doc_or_pair
    errors = []
    declined_targets = [t for row in declined for t in row["targets"]]
    listed = enabled + declined_targets
    seen = set()
    for target in listed:
        if target in seen:
            if target in set(enabled) and target in set(declined_targets):
                errors.append(
                    "%s is both enabled and declined" % target)
            else:
                errors.append("%s is listed twice" % target)
        seen.add(target)
    upstream_set = set(upstream)
    for target in sorted(seen - upstream_set):
        errors.append(
            "%s vanished from the pinned BUILD; drop it from the roster"
            % target)
    for target in sorted(upstream_set - seen):
        errors.append(
            "%s is new upstream; triage it into enabled or declined"
            % target)
    return errors


def checkout_dir(pin_commit: str) -> pathlib.Path:
    return REPO_ROOT / "externals" / "gvisor" / pin_commit


def main(argv=None) -> int:
    sys.path.insert(0, str(_PACKAGE_DIR.parent))
    from conformance import pins
    doc = pins.load()
    build_path = checkout_dir(doc["gvisor"]["commit"]) / BUILD_RELPATH
    if not build_path.is_file():
        print("gVisor checkout is absent (%s); run: make build-gvisor-payload"
              % checkout_dir(doc["gvisor"]["commit"]))
        return 77
    errors = compare(load_roster(), parse_build(
        build_path.read_text(encoding="utf-8")))
    for error in errors:
        print("audit: %s" % error)
    if errors:
        return 1
    print("audit: roster covers the pinned BUILD exactly")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
