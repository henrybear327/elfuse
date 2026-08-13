"""Canonical test ids shared by discovery, expectations, and reports.

An id is suite-prefixed so one matcher engine and one quarantine file can
span both suites: gvisor:<binary>/<gtest full name> (the binary is part of
the id because two binaries can define the same gtest suite name) and
ltp:<runtest tag>. Globs are matcher syntax only; an id is always one
concrete case. Slugs name per-case artifact directories and carry a digest
suffix because bare character replacement can map distinct ids to the same
directory name.
"""

from __future__ import annotations

import hashlib
import re

_PATTERNS = {
    "gvisor": re.compile(r"^gvisor:[A-Za-z0-9_]+/[A-Za-z0-9_.]+(/[A-Za-z0-9_.]+)*$"),
    "ltp": re.compile(r"^ltp:[A-Za-z0-9][A-Za-z0-9_.-]*$"),
}


class IdError(ValueError):
    """A string is not a canonical test id, or slugs would collide."""


def validate(test_id: str) -> None:
    suite, sep, _ = test_id.partition(":")
    pattern = _PATTERNS.get(suite) if sep else None
    if pattern is None:
        raise IdError("not a canonical test id (unknown suite): %r" % test_id)
    if not pattern.match(test_id):
        raise IdError("not a canonical %s test id: %r" % (suite, test_id))


def parse(test_id: str) -> tuple[str, str]:
    validate(test_id)
    suite, _, name = test_id.partition(":")
    return suite, name


def slug(test_id: str) -> str:
    validate(test_id)
    digest = hashlib.sha256(test_id.encode("utf-8")).hexdigest()[:8]
    return "%s-%s" % (re.sub(r"[:/]", "_", test_id), digest)


def assert_unique_slugs(test_ids) -> None:
    seen: dict[str, str] = {}
    for test_id in test_ids:
        s = slug(test_id)
        if s in seen:
            raise IdError(
                "slug collision between %r and %r" % (seen[s], test_id))
        seen[s] = test_id
