"""Fingerprints and completion records shared by the payload builders.

The fingerprint hashes the pin section, the data files, and the builder
sources themselves, so editing a build recipe invalidates caches with no
manual salt bump. It is compared as content, never as an mtime: the host
make is 3.81 and compares whole seconds, so mtime freshness lies here.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat

COMPLETE_NAME = ".complete"


class ManifestError(Exception):
    """A payload completion or runtime manifest is unusable."""


def sha256_file(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fingerprint(*, pin_section: dict, files, flavor: str) -> str:
    digest = hashlib.sha256()
    digest.update(json.dumps(pin_section, sort_keys=True).encode("utf-8"))
    for path in files:
        path = pathlib.Path(path)
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    digest.update(flavor.encode("utf-8"))
    return digest.hexdigest()


def write_complete(directory, *, fingerprint: str, contents: dict) -> None:
    doc = {"fingerprint": fingerprint, "contents": contents}
    path = pathlib.Path(directory) / COMPLETE_NAME
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    tmp.replace(path)


def is_complete(directory, fingerprint: str) -> bool:
    path = pathlib.Path(directory) / COMPLETE_NAME
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return doc.get("fingerprint") == fingerprint


def verify_complete(directory, expected_fingerprint=None) -> dict:
    path = pathlib.Path(directory) / COMPLETE_NAME
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError("%s is unreadable: %s" % (path, exc)) from exc
    fingerprint = doc.get("fingerprint")
    if not isinstance(fingerprint, str) or len(fingerprint) != 64:
        raise ManifestError("%s has an invalid fingerprint" % path)
    if expected_fingerprint is not None and fingerprint != expected_fingerprint:
        raise ManifestError(
            "%s records fingerprint %s, expected %s"
            % (path, fingerprint, expected_fingerprint))
    if not isinstance(doc.get("contents"), dict):
        raise ManifestError("%s has invalid contents" % path)
    return doc


def _inventory_entry(path: pathlib.Path) -> dict:
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISLNK(info.st_mode):
        return {"type": "symlink", "mode": mode,
                "target": os.readlink(path)}
    if stat.S_ISDIR(info.st_mode):
        return {"type": "directory", "mode": mode}
    if stat.S_ISREG(info.st_mode):
        return {"type": "file", "mode": mode, "size": info.st_size,
                "sha256": sha256_file(path)}
    raise ManifestError("unsupported payload entry: %s" % path)


def inventory(directory, roots) -> dict:
    """Describe every entry under the named runtime roots."""
    base = pathlib.Path(directory)
    root_names = []
    for root in roots:
        pure = pathlib.PurePosixPath(root)
        if pure.is_absolute() or not pure.parts or ".." in pure.parts:
            raise ManifestError("invalid runtime root: %s" % root)
        root_names.append(str(pure))
    entries = {}
    for root_name in root_names:
        root = base / root_name
        if not root.exists() and not root.is_symlink():
            raise ManifestError("runtime root is absent: %s" % root)
        if root.is_symlink() or root.is_file():
            entries[root_name] = _inventory_entry(root)
            continue
        for current, dirnames, filenames in os.walk(root, followlinks=False):
            current = pathlib.Path(current)
            relative = current.relative_to(base).as_posix()
            entries[relative] = _inventory_entry(current)
            for name in list(dirnames):
                child = current / name
                if child.is_symlink():
                    entries[child.relative_to(base).as_posix()] = \
                        _inventory_entry(child)
                    dirnames.remove(name)
            for name in filenames:
                child = current / name
                entries[child.relative_to(base).as_posix()] = \
                    _inventory_entry(child)
            dirnames.sort()
    return {"roots": root_names,
            "entries": {name: entries[name] for name in sorted(entries)}}


def verify_inventory(directory, manifest: dict) -> None:
    if not isinstance(manifest, dict) or \
            not isinstance(manifest.get("roots"), list) or \
            not isinstance(manifest.get("entries"), dict):
        raise ManifestError("runtime manifest has an invalid shape")
    actual = inventory(directory, manifest["roots"])
    if actual != manifest:
        wanted = manifest["entries"]
        got = actual["entries"]
        missing = sorted(set(wanted) - set(got))
        extra = sorted(set(got) - set(wanted))
        changed = sorted(name for name in set(wanted) & set(got)
                         if wanted[name] != got[name])
        raise ManifestError(
            "runtime inventory mismatch (missing=%r, extra=%r, changed=%r)"
            % (missing[:5], extra[:5], changed[:5]))
