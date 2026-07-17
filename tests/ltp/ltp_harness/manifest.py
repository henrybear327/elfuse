"""Manifest and pin loading, validation, and runtest generation.

The manifest (tests/ltp/manifest.json) is the source of truth for which
LTP tests the lane runs. The fixture builder turns it into one runtest
file per tier so kirk can consume the selection natively.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List


class ManifestError(Exception):
    """Raised for malformed manifest or pin input; maps to exit 2."""


TIERS = ("fast", "extended", "nightly")
RESULT_FORMATS = ("new-api", "legacy-exit")
SUITE_PREFIX = "elfuse-"

_ID_RE = re.compile(r"^[A-Za-z0-9_.+-]+$")
_REQUIRED_TEST_KEYS = frozenset(
    {
        "id",
        "command",
        "arguments",
        "tier",
        "timeout_seconds",
        "result_format",
        "helpers",
        "data",
        "notes",
    }
)


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
        if not isinstance(test, dict):
            raise ManifestError(f"{where}: must be an object")

        missing = _REQUIRED_TEST_KEYS - test.keys()
        if missing:
            raise ManifestError(f"{where}: missing keys {sorted(missing)}")
        extra = test.keys() - _REQUIRED_TEST_KEYS
        if extra:
            raise ManifestError(f"{where}: unknown keys {sorted(extra)}")

        test_id = test["id"]
        if not isinstance(test_id, str) or not _ID_RE.fullmatch(test_id):
            raise ManifestError(f"{where}: invalid id")
        if test_id in seen:
            raise ManifestError(f"{where}: duplicate id '{test_id}'")
        seen.add(test_id)

        command = test["command"]
        if not isinstance(command, str) or not command.startswith("/opt/ltp/"):
            raise ManifestError(f"{where}: command must be an absolute /opt/ltp path")

        if test["tier"] not in TIERS:
            raise ManifestError(f"{where}: tier must be one of {TIERS}")
        if test["result_format"] not in RESULT_FORMATS:
            raise ManifestError(
                f"{where}: result_format must be one of {RESULT_FORMATS}"
            )

        timeout = test["timeout_seconds"]
        if not isinstance(timeout, int) or timeout <= 0:
            raise ManifestError(f"{where}: timeout_seconds must be a positive integer")

        for key in ("arguments", "helpers", "data"):
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

        if not isinstance(test["notes"], str) or not test["notes"]:
            raise ManifestError(f"{where}: notes must be a non-empty string")

    return tests


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
        if tier not in ("all", test["tier"]):
            raise ManifestError(
                f"test '{test_id}' belongs to tier '{test['tier']}', "
                f"not requested tier '{tier}'"
            )
        return matches

    selected = [test for test in tests if tier in ("all", test["tier"])]
    if not selected:
        raise ManifestError(f"tier '{tier}' selects no tests")

    return selected


def suite_name(tier: str) -> str:
    return SUITE_PREFIX + tier


def generate_runtest(tests: List[Dict[str, Any]], tier: str) -> str:
    """Render the runtest file for one tier.

    Lines are "<name> <command> [args...]" per LTP's runtest format. The
    command is the installed basename: kirk sets the working directory to
    /opt/ltp/testcases/bin and appends it to PATH.
    """
    lines = [
        "# Generated from tests/ltp/manifest.json; do not edit.",
        f"# Tier: {tier}",
    ]
    for test in select_tests(tests, tier):
        parts = [test["id"], os.path.basename(test["command"])] + test["arguments"]
        lines.append(" ".join(parts))

    return "\n".join(lines) + "\n"


def tier_timeout(tests: List[Dict[str, Any]], tier: str, test_id: str = "") -> int:
    """The per-execution timeout for a selection: the max over its tests."""
    return max(t["timeout_seconds"] for t in select_tests(tests, tier, test_id))
