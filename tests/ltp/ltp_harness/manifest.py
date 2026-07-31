"""Manifest and pin loading, validation, and runtest generation.

The manifests are the source of truth for which LTP tests the lane
runs: tests/ltp/manifest.json holds the hand-curated tiers, and
tests/ltp/manifest-sweep.json holds the sweep tiers derived from the
pinned upstream runtest/syscalls file (see sweep.py). The fixture
builder turns the merged list into one runtest file per tier so kirk
can consume the selection natively.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List


class ManifestError(Exception):
    """Raised for malformed manifest or pin input; maps to exit 2."""


CURATED_TIERS = ("fast", "extended", "nightly")
# The sweep tiers cover the full upstream runtest/syscalls selection.
# sweep-slow exists because kirk's --exec-timeout is one value per
# invocation (the max over the selection), so a single long-runner in
# the bulk sweep would make every hang cost its timeout.
SWEEP_TIERS = ("sweep", "sweep-slow")
TIERS = CURATED_TIERS + SWEEP_TIERS
RESULT_FORMATS = ("new-api", "legacy-exit")
SUITE_PREFIX = "elfuse-"

_ID_RE = re.compile(r"^[A-Za-z0-9_.+-]+$")
# A group is the test's source directory relative to LTP's
# testcases/kernel/syscalls (or testcases/ for suites outside it), the
# unit pass rates aggregate over. It is an explicit field because the
# id does not encode it reliably (epoll01 builds from epoll/, pipeio_1
# from ../ipc/pipeio/).
_GROUP_RE = re.compile(r"^[A-Za-z0-9_.+-]+(/[A-Za-z0-9_.+-]+)*$")
_COMMON_TEST_KEYS = frozenset(
    {
        "id",
        "command",
        "arguments",
        "tier",
        "group",
        "timeout_seconds",
        "result_format",
        "notes",
    }
)
_REQUIRED_TEST_KEYS = _COMMON_TEST_KEYS | {"helpers", "data"}
# Sweep entries add source_dir (where the binary is built, relative to
# testcases/) and may carry unbuilt (why the cross build produced no
# binary); they have no helpers/data because the sweep stages the whole
# installed testcases/bin.
_SWEEP_REQUIRED_KEYS = _COMMON_TEST_KEYS | {"source_dir"}
_SWEEP_OPTIONAL_KEYS = frozenset({"unbuilt"})


def _load_json(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as err:
        raise ManifestError(f"cannot read {path}: {err}") from err
    except ValueError as err:
        raise ManifestError(f"{path} is not valid JSON: {err}") from err

    if not isinstance(data, dict):
        raise ManifestError(f"{path}: top level must be a JSON object")

    return data


def load_pins(path: str) -> Dict[str, Any]:
    """Load and validate pin.json."""
    data = _load_json(path)

    if data.get("schema_version") != 2:
        raise ManifestError(f"{path}: unsupported schema_version")

    for project, keys in (
        ("ltp", ("release", "commit", "archive_url", "archive_sha256", "sha256_url")),
        ("kirk", ("tag", "archive_url", "archive_sha256")),
    ):
        section = data.get(project)
        if not isinstance(section, dict):
            raise ManifestError(f"{path}: missing '{project}' pin")
        for key in keys:
            value = section.get(key)
            if not isinstance(value, str) or not value:
                raise ManifestError(f"{path}: {project}.{key} must be a string")

    sha = data["ltp"]["archive_sha256"]
    if not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise ManifestError(f"{path}: ltp.archive_sha256 is not a sha256 digest")
    sha = data["kirk"]["archive_sha256"]
    if not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise ManifestError(f"{path}: kirk.archive_sha256 is not a sha256 digest")

    if not isinstance(data["ltp"].get("source_date_epoch"), int):
        raise ManifestError(f"{path}: ltp.source_date_epoch must be an integer")

    return data


def baseline_pin(pins: Dict[str, Any]) -> Dict[str, str]:
    """The pin subset embedded into recorded baselines."""
    return {
        "ltp_release": pins["ltp"]["release"],
        "ltp_commit": pins["ltp"]["commit"],
        "kirk_tag": pins["kirk"]["tag"],
    }


def _check_relative_dir(value: Any, where: str, what: str) -> None:
    if not isinstance(value, str) or not _GROUP_RE.fullmatch(value):
        raise ManifestError(
            f"{where}: {what} must be a relative source directory path"
        )
    normalized = os.path.normpath(value)
    # The regex admits dot-only segments, so ".." passes it; the
    # normpath comparison is what actually rejects traversal.
    if normalized != value or normalized.startswith(".."):
        raise ManifestError(f"{where}: {what} must be a normalized relative path")


def _validate_common_fields(test: Dict[str, Any], where: str, tiers) -> None:
    test_id = test["id"]
    if not isinstance(test_id, str) or not _ID_RE.fullmatch(test_id):
        raise ManifestError(f"{where}: invalid id")

    command = test["command"]
    if not isinstance(command, str) or not command.startswith("/opt/ltp/"):
        raise ManifestError(f"{where}: command must be an absolute /opt/ltp path")

    if test["tier"] not in tiers:
        raise ManifestError(f"{where}: tier must be one of {tiers}")

    _check_relative_dir(test["group"], where, "group")

    if test["result_format"] not in RESULT_FORMATS:
        raise ManifestError(
            f"{where}: result_format must be one of {RESULT_FORMATS}"
        )

    timeout = test["timeout_seconds"]
    if not isinstance(timeout, int) or timeout <= 0:
        raise ManifestError(f"{where}: timeout_seconds must be a positive integer")

    arguments = test["arguments"]
    if not isinstance(arguments, list) or any(
        not isinstance(item, str) for item in arguments
    ):
        raise ManifestError(f"{where}: arguments must be a list of strings")

    if not isinstance(test["notes"], str) or not test["notes"]:
        raise ManifestError(f"{where}: notes must be a non-empty string")


def _check_test_shape(test: Any, where: str, required, optional=frozenset()):
    if not isinstance(test, dict):
        raise ManifestError(f"{where}: must be an object")
    missing = required - test.keys()
    if missing:
        raise ManifestError(f"{where}: missing keys {sorted(missing)}")
    extra = test.keys() - required - optional
    if extra:
        raise ManifestError(f"{where}: unknown keys {sorted(extra)}")


def load_manifest(path: str) -> List[Dict[str, Any]]:
    """Load and validate manifest.json; returns the test list."""
    data = _load_json(path)

    if data.get("schema_version") != 1:
        raise ManifestError(f"{path}: unsupported schema_version")

    tests = data.get("tests")
    if not isinstance(tests, list) or not tests:
        raise ManifestError(f"{path}: 'tests' must be a non-empty list")

    seen = set()
    for index, test in enumerate(tests):
        where = f"{path}: tests[{index}]"
        _check_test_shape(test, where, _REQUIRED_TEST_KEYS)
        _validate_common_fields(test, where, CURATED_TIERS)

        if test["id"] in seen:
            raise ManifestError(f"{where}: duplicate id '{test['id']}'")
        seen.add(test["id"])

        for key in ("helpers", "data"):
            values = test[key]
            if not isinstance(values, list) or any(
                not isinstance(item, str) for item in values
            ):
                raise ManifestError(f"{where}: {key} must be a list of strings")

        for entry in test["data"]:
            normalized = os.path.normpath(entry)
            traversal = normalized.startswith("..") or normalized != entry
            if entry.startswith("/") or traversal:
                raise ManifestError(
                    f"{where}: data entries must be normalized paths relative to /opt/ltp"
                )

    return tests


def load_sweep(path: str) -> List[Dict[str, Any]]:
    """Load and validate manifest-sweep.json; returns the test list.

    Entries are normalized to the curated shape (empty helpers/data) so
    every consumer handles one test schema.
    """
    data = _load_json(path)

    if data.get("schema_version") != 1:
        raise ManifestError(f"{path}: unsupported schema_version")

    generated_from = data.get("generated_from")
    if not isinstance(generated_from, dict):
        raise ManifestError(f"{path}: missing 'generated_from' provenance")
    release = generated_from.get("ltp_release")
    if not isinstance(release, str) or not release:
        raise ManifestError(f"{path}: generated_from.ltp_release must be a string")
    sha = generated_from.get("runtest_sha256")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise ManifestError(
            f"{path}: generated_from.runtest_sha256 is not a sha256 digest"
        )

    tests = data.get("tests")
    if not isinstance(tests, list) or not tests:
        raise ManifestError(f"{path}: 'tests' must be a non-empty list")

    seen = set()
    for index, test in enumerate(tests):
        where = f"{path}: tests[{index}]"
        _check_test_shape(test, where, _SWEEP_REQUIRED_KEYS, _SWEEP_OPTIONAL_KEYS)
        _validate_common_fields(test, where, SWEEP_TIERS)

        if test["id"] in seen:
            raise ManifestError(f"{where}: duplicate id '{test['id']}'")
        seen.add(test["id"])

        _check_relative_dir(test["source_dir"], where, "source_dir")

        if "unbuilt" in test and (
            not isinstance(test["unbuilt"], str) or not test["unbuilt"]
        ):
            raise ManifestError(f"{where}: unbuilt must be a non-empty string")

        test["helpers"] = []
        test["data"] = []

    return tests


def merge_tests(
    curated: List[Dict[str, Any]], sweep: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Concatenate the curated and sweep lists, rejecting duplicate ids.

    Each loader already rejects duplicates within its own file; the
    global check here is what catches an id in both files.
    """
    seen = set()
    for test in curated + sweep:
        if test["id"] in seen:
            raise ManifestError(
                f"test '{test['id']}' appears more than once across the "
                f"curated and sweep manifests; regenerate the sweep "
                f"(make gen-ltp-sweep)"
            )
        seen.add(test["id"])
    return curated + sweep


def select_tests(
    tests: List[Dict[str, Any]], tier: str, test_id: str = ""
) -> List[Dict[str, Any]]:
    """Filter the manifest by tier and optional single test id.

    An unknown id, or an id outside the requested tier, is a usage error
    (never a silent skip): the old harness turned both into green runs.
    """
    if tier != "all" and tier not in TIERS:
        raise ManifestError(f"unknown tier '{tier}'")

    if test_id:
        matches = [test for test in tests if test["id"] == test_id]
        if not matches:
            raise ManifestError(f"unknown test id '{test_id}'")
        test = matches[0]
        if test.get("unbuilt"):
            raise ManifestError(
                f"test '{test_id}' was not built: {test['unbuilt']}"
            )
        if tier not in ("all", test["tier"]):
            raise ManifestError(
                f"test '{test_id}' belongs to tier '{test['tier']}', "
                f"not requested tier '{tier}'"
            )
        return matches

    selected = [
        test
        for test in tests
        if tier in ("all", test["tier"]) and not test.get("unbuilt")
    ]
    if not selected:
        raise ManifestError(f"tier '{tier}' selects no tests")

    return selected


def unbuilt_tests(
    tests: List[Dict[str, Any]], tier: str
) -> List[Dict[str, Any]]:
    """The tier's entries excluded from selection because the cross
    build produced no binary; callers announce this count so the
    exclusion is never silent."""
    return [
        test
        for test in tests
        if tier in ("all", test["tier"]) and test.get("unbuilt")
    ]


def suite_name(tier: str) -> str:
    return SUITE_PREFIX + tier


def generate_runtest(tests: List[Dict[str, Any]], tier: str) -> str:
    """Render the runtest file for one tier.

    Lines are "<name> <command> [args...]" per LTP's runtest format. The
    command is the installed basename: kirk sets the working directory to
    /opt/ltp/testcases/bin and appends it to PATH.
    """
    lines = [
        "# Generated from the committed tests/ltp manifests; do not edit.",
        f"# Tier: {tier}",
    ]
    for test in select_tests(tests, tier):
        parts = [test["id"], os.path.basename(test["command"])] + test["arguments"]
        lines.append(" ".join(parts))

    return "\n".join(lines) + "\n"


def tier_timeout(tests: List[Dict[str, Any]], tier: str, test_id: str = "") -> int:
    """The per-execution timeout for a selection: the max over its tests."""
    return max(t["timeout_seconds"] for t in select_tests(tests, tier, test_id))
