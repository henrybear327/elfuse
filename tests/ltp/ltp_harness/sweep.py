"""Derive the sweep manifest from the pinned upstream runtest file.

The sweep tiers run every entry of LTP's runtest/syscalls file, so the
manifest for them is generated, not hand-written: this module parses
the pinned runtest file, resolves each entry's source for result-format
classification and grouping, and renders tests/ltp/manifest-sweep.json.
The rendered file is committed so the recorded baselines always gate a
reviewable selection; the fixture builder regenerates it in memory and
fails on drift.

Resolution is convention-plus-overrides: an entry's source is the exact
<binary>.c under testcases/, else the base source of a _64/_16 build
variant in the same directory, else an explicit entry in the
hand-maintained tests/ltp/sweep-overrides.json. Anything unresolvable
or ambiguous is a generation error, never a silent default.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from ltp_harness.manifest import ManifestError, _check_relative_dir

SWEEP_DEFAULT_TIMEOUT = 60

# runtest entries are plain argv lines; kirk hands them to a shell, so
# any metacharacter would change meaning silently after a pin bump.
# The verified pinned file needs none.
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.,:/=+%-]+$")

_VARIANT_SUFFIXES = ("_64", "_16")

_OVERRIDE_KEYS = frozenset({"source", "source_dir", "timeout_seconds", "notes"})

_UNBUILT_REASON = "not produced by the cross build"


def runtest_path(src_root: str) -> str:
    return os.path.join(src_root, "runtest", "syscalls")


def parse_runtest(path: str) -> List[Tuple[str, str, List[str]]]:
    """Parse runtest lines into (id, binary, arguments) triples."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError as err:
        raise ManifestError(f"cannot read {path}: {err}") from err

    entries: List[Tuple[str, str, List[str]]] = []
    seen = set()
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        tokens = stripped.split()
        if len(tokens) < 2:
            raise ManifestError(f"{path}:{number}: entry needs an id and a command")
        for token in tokens:
            if not _TOKEN_RE.fullmatch(token):
                raise ManifestError(
                    f"{path}:{number}: token {token!r} contains characters the "
                    f"generator does not pass through; add explicit handling"
                )
        test_id, binary = tokens[0], tokens[1]
        if test_id in seen:
            raise ManifestError(f"{path}:{number}: duplicate id '{test_id}'")
        seen.add(test_id)
        entries.append((test_id, binary, tokens[2:]))

    if not entries:
        raise ManifestError(f"{path}: no runtest entries")
    return entries


def load_overrides(path: str) -> Dict[str, Dict[str, Any]]:
    """Load and validate sweep-overrides.json."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as err:
        raise ManifestError(f"cannot read {path}: {err}") from err
    except ValueError as err:
        raise ManifestError(f"{path} is not valid JSON: {err}") from err

    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ManifestError(f"{path}: unsupported schema_version")
    tests = data.get("tests")
    if not isinstance(tests, dict):
        raise ManifestError(f"{path}: 'tests' must be an object")

    for test_id, override in tests.items():
        where = f"{path}: {test_id}"
        if not isinstance(override, dict):
            raise ManifestError(f"{where}: must be an object")
        extra = override.keys() - _OVERRIDE_KEYS
        if extra:
            raise ManifestError(f"{where}: unknown keys {sorted(extra)}")
        if not override:
            raise ManifestError(f"{where}: empty override")
        for key in ("source", "notes"):
            if key in override and (
                not isinstance(override[key], str) or not override[key]
            ):
                raise ManifestError(f"{where}: {key} must be a non-empty string")
        if "source_dir" in override:
            _check_relative_dir(override["source_dir"], where, "source_dir")
        if "timeout_seconds" in override:
            timeout = override["timeout_seconds"]
            if not isinstance(timeout, int) or timeout <= 0:
                raise ManifestError(
                    f"{where}: timeout_seconds must be a positive integer"
                )

    return tests


def _index_sources(testcases_root: str) -> Dict[str, List[str]]:
    """Map each .c basename (without extension) to its directories."""
    index: Dict[str, List[str]] = {}
    for dirpath, dirnames, filenames in os.walk(testcases_root):
        dirnames.sort()
        for filename in sorted(filenames):
            if filename.endswith(".c"):
                index.setdefault(filename[: -len(".c")], []).append(dirpath)
    return index


def _resolve_source(
    binary: str,
    index: Dict[str, List[str]],
    override: Dict[str, Any],
    src_root: str,
    test_id: str,
) -> str:
    """The file whose content classifies the test; absolute path."""
    if "source" in override:
        source = os.path.join(src_root, override["source"])
        if not os.path.isfile(source):
            raise ManifestError(
                f"override for '{test_id}': source {override['source']} "
                f"does not exist in the pinned tree"
            )
        return source

    names = [binary]
    for suffix in _VARIANT_SUFFIXES:
        if binary.endswith(suffix):
            names.append(binary[: -len(suffix)])
    for name in names:
        dirs = index.get(name)
        if not dirs:
            continue
        if len(dirs) > 1:
            raise ManifestError(
                f"'{test_id}': {name}.c exists in multiple directories "
                f"{dirs}; disambiguate in sweep-overrides.json"
            )
        return os.path.join(dirs[0], f"{name}.c")

    raise ManifestError(
        f"'{test_id}': no source found for binary '{binary}'; "
        f"add it to sweep-overrides.json"
    )


def _group_for(source_dir: str) -> str:
    """The pass-rate group: the source dir relative to the syscalls
    tree when under it, else to kernel/, else to testcases/."""
    for prefix in ("kernel/syscalls/", "kernel/"):
        if source_dir.startswith(prefix):
            return source_dir[len(prefix):]
    return source_dir


def generate(
    src_root: str,
    curated: List[Dict[str, Any]],
    overrides: Dict[str, Dict[str, Any]],
    ltp_release: str,
    mark_unbuilt: bool = False,
) -> Dict[str, Any]:
    """Build the manifest-sweep.json document (as a Python object).

    With mark_unbuilt, entries whose binary is absent from its build
    directory get an explicit "unbuilt" reason; this requires the LTP
    build to have run so absence means "the cross build skipped it",
    not "nothing was built yet".
    """
    testcases_root = os.path.join(src_root, "testcases")
    if not os.path.isdir(testcases_root):
        raise ManifestError(f"{testcases_root} missing from the LTP source tree")

    if mark_unbuilt and not os.path.isfile(
        os.path.join(src_root, "lib", "libltp.a")
    ):
        raise ManifestError(
            f"{src_root} has no built lib/libltp.a; build the fixture before "
            f"marking unbuilt entries"
        )

    entries = parse_runtest(runtest_path(src_root))
    entry_ids = {test_id for test_id, _binary, _args in entries}
    curated_by_id = {test["id"]: test for test in curated}

    for test_id in overrides:
        if test_id not in entry_ids:
            raise ManifestError(
                f"sweep-overrides.json names unknown test '{test_id}'"
            )
        if test_id in curated_by_id:
            raise ManifestError(
                f"sweep-overrides.json names curated test '{test_id}'; "
                f"curated entries are edited in manifest.json"
            )

    index = _index_sources(testcases_root)
    tests: List[Dict[str, Any]] = []
    for test_id, binary, arguments in entries:
        curated_test = curated_by_id.get(test_id)
        if curated_test is not None:
            # The curated manifest owns this id. Its upstream line must
            # be the plain "id id" form, or curated and sweep would
            # disagree about what the id runs.
            if binary != test_id or arguments:
                raise ManifestError(
                    f"curated test '{test_id}' diverges from its upstream "
                    f"runtest entry ({binary} {' '.join(arguments)}); "
                    f"reconcile manifest.json first"
                )
            continue

        override = overrides.get(test_id, {})
        source = _resolve_source(binary, index, override, src_root, test_id)
        source_dir = override.get(
            "source_dir",
            os.path.relpath(os.path.dirname(source), testcases_root),
        )

        with open(source, "r", encoding="utf-8", errors="replace") as handle:
            new_api = "struct tst_test" in handle.read()

        timeout = override.get("timeout_seconds", SWEEP_DEFAULT_TIMEOUT)
        test: Dict[str, Any] = {
            "id": test_id,
            "command": f"/opt/ltp/testcases/bin/{binary}",
            "arguments": arguments,
            "tier": "sweep" if timeout <= SWEEP_DEFAULT_TIMEOUT else "sweep-slow",
            "group": _group_for(source_dir),
            "source_dir": source_dir,
            "timeout_seconds": timeout,
            "result_format": "new-api" if new_api else "legacy-exit",
            "notes": override.get("notes", "generated from runtest/syscalls"),
        }
        if mark_unbuilt:
            built = os.path.join(testcases_root, source_dir, binary)
            if not os.path.isfile(built):
                test["unbuilt"] = _UNBUILT_REASON
        tests.append(test)

    with open(runtest_path(src_root), "rb") as handle:
        runtest_sha = hashlib.sha256(handle.read()).hexdigest()

    return {
        "schema_version": 1,
        "comment": [
            "Generated by harness.py gen-sweep from the pinned upstream",
            "runtest/syscalls file; do not edit by hand. Regenerate with",
            "make gen-ltp-sweep after a pin bump or a fixture rebuild and",
            "review the diff. Entries marked unbuilt were skipped by the",
            "cross build (missing optional libraries on the build host)",
            "and are excluded from runs; every run announces their count.",
        ],
        "generated_from": {
            "ltp_release": ltp_release,
            "runtest_sha256": runtest_sha,
        },
        "tests": tests,
    }


def render(document: Dict[str, Any]) -> str:
    """Deterministic byte-exact serialization of the sweep manifest."""
    return json.dumps(document, indent=2) + "\n"


def write(path: str, document: Dict[str, Any]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(render(document))
    os.replace(tmp, path)


def check_drift(path: str, document: Dict[str, Any]) -> Optional[str]:
    """None when the committed sweep manifest matches the regenerated
    one, else a one-line description of the mismatch."""
    if not os.path.isfile(path):
        return f"{path} is missing"
    with open(path, "r", encoding="utf-8") as handle:
        committed = handle.read()
    if committed != render(document):
        return f"{path} does not match the regenerated sweep"
    return None
