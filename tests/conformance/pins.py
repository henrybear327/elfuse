"""Loader for pins.json, the single source of upstream versions.

Plain JSON so CI can read it with the stdlib; all metadata is structured
fields, so the file needs no comments. gVisor is pinned by commit plus
tree hash (a commit is already a content address and GitHub's generated
archives are not byte-stable, so there is no tarball digest to record);
LTP and kirk publish real release assets and keep the tarball sha256
pattern. Consumers read values through lookup(), never by pattern
matching shell source.
"""

from __future__ import annotations

import json
import pathlib
import re

DEFAULT_PATH = pathlib.Path(__file__).resolve().parent / "pins.json"
SCHEMA_VERSION = 1

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_FIELDS = {
    "gvisor": {"repository": str, "commit": _HEX40, "tree": _HEX40,
               "date": str, "subject": str},
    "ltp": {"project": str, "release": str, "commit": _HEX40,
            "archive_url": str, "archive_sha256": _HEX64,
            "sha256_url": str, "source_date_epoch": int},
    "kirk": {"project": str, "tag": str, "archive_url": str,
             "archive_sha256": _HEX64},
}


class PinError(ValueError):
    """pins.json is malformed or a lookup path does not exist."""


def load(path=DEFAULT_PATH) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise PinError("cannot read %s: %s" % (path, exc)) from exc
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise PinError("%s: schema_version must be %d"
                       % (path, SCHEMA_VERSION))
    if not isinstance(doc.get("license_boundary"), str):
        raise PinError("%s: missing license_boundary" % path)
    for section, fields in _FIELDS.items():
        values = doc.get(section)
        if not isinstance(values, dict):
            raise PinError("%s: missing section %s" % (path, section))
        for name, shape in fields.items():
            value = values.get(name)
            dotted = "%s.%s" % (section, name)
            if value is None:
                raise PinError("%s: missing %s" % (path, dotted))
            if isinstance(shape, type):
                if not isinstance(value, shape):
                    raise PinError("%s: %s must be %s"
                                   % (path, dotted, shape.__name__))
            elif not (isinstance(value, str) and shape.match(value)):
                raise PinError("%s: %s does not look like a pinned digest"
                               % (path, dotted))
    return doc


def lookup(doc: dict, dotted: str):
    node = doc
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            raise PinError("no pin at %r" % dotted)
        node = node[part]
    return node
