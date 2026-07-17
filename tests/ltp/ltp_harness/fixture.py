"""Build and verify the pinned LTP + kirk fixture.

Everything generated lands under the fixture directory (default
externals/test-fixtures/ltp-aarch64), which is ignored by Git and reaped
by distclean: the LTP source and payload are GPL-covered and must never
enter the Apache-2.0 tree.

Layout:
    cache/       pinned downloads (LTP tarball + checksum asset, kirk)
    src/         extracted LTP source and build tree
    kirk/        extracted pinned kirk (kirk script + libkirk/)
    rootfs/      staged guest root: /opt/ltp subset, loader closure,
                 busybox, case-launcher, generated runtest files
    bin/         qemu-supervisor (runs in the VM outside the chroot)
    fixture-metadata.json, inventory.txt, .complete

Only the manifest-selected test directories are cross-compiled, not the
full LTP tree; the pinned source of a selected test is located by its
<id>.c file under testcases/. The .complete marker holds a fingerprint
over pin.json, manifest.json, the helper sources, and this module, so
any input change invalidates the fixture.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

from ltp_harness import EXIT_FAIL, EXIT_OK
from ltp_harness import manifest as manifest_mod

BUSYBOX_APPLETS = (
    "sh", "ls", "cat", "echo", "test", "id", "uname", "mkdir", "rm", "true",
)

SYSROOT_LIB_DIRS = (
    "lib",
    "lib64",
    "usr/lib",
    "usr/lib64",
    "lib/aarch64-linux-gnu",
    "usr/lib/aarch64-linux-gnu",
)

# Optional glibc plugins resolved at runtime via dlopen rather than
# DT_NEEDED; staged when the sysroot provides them.
OPTIONAL_LIBS = ("libnss_files.so.2",)

HELPER_SOURCES = ("status-io.h", "case-launcher.c", "qemu-supervisor.c")

ETC_PASSWD = "root:x:0:0:root:/root:/bin/sh\nltp:x:1000:1000:ltp:/tmp:/bin/sh\n"
ETC_GROUP = "root:x:0:\nltp:x:1000:\n"
ETC_NSSWITCH = "passwd: files\ngroup: files\n"


class FixtureError(Exception):
    """Fixture build or verification failure; maps to exit 1."""


def _run(
    argv: List[str],
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    capture: bool = False,
) -> str:
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
            text=True,
        )
    except OSError as err:
        raise FixtureError(f"cannot run {argv[0]}: {err}") from err

    if proc.returncode != 0:
        detail = f"\n{proc.stdout}" if capture and proc.stdout else ""
        raise FixtureError(f"{' '.join(argv)} failed (rc {proc.returncode}){detail}")

    return proc.stdout or ""


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tool(cross_compile: str, name: str) -> str:
    return f"{cross_compile}{name}"


def _resolve_cross_compile() -> str:
    """CROSS_COMPILE from the environment, with the toolchain.mk default."""
    cross = os.environ.get("CROSS_COMPILE", "")
    candidates = (
        [cross] if cross else ["aarch64-linux-gnu-", "aarch64-unknown-linux-gnu-"]
    )
    for candidate in candidates:
        if shutil.which(_tool(candidate, "gcc")):
            return candidate
    raise FixtureError(
        "no AArch64 Linux cross compiler found; install one (see docs/testing.md) "
        "or set CROSS_COMPILE"
    )


def _download(url: str, dest: str) -> None:
    partial = dest + ".partial"
    print(f"  FETCH   {url}")
    try:
        request = urllib.request.urlopen(url, timeout=60)
        with request as response, open(partial, "wb") as out:
            shutil.copyfileobj(response, out)
    except OSError as err:
        if os.path.exists(partial):
            os.unlink(partial)
        raise FixtureError(f"download failed: {url}: {err}") from err
    os.replace(partial, dest)


def _fetch_pinned(cache: str, name: str, url: str, sha256: str) -> str:
    """Download once into the cache and verify the pinned digest."""
    dest = os.path.join(cache, name)
    if not os.path.isfile(dest):
        _download(url, dest)

    actual = _sha256_file(dest)
    if actual != sha256:
        raise FixtureError(
            f"{name}: sha256 mismatch: pinned {sha256}, downloaded {actual}; "
            f"refusing to use the archive"
        )
    return dest


def _verify_official_checksum(archive: str, asset_path: str, name: str) -> None:
    """Cross-check the pinned digest against the release's own asset."""
    with open(asset_path, "r", encoding="utf-8") as handle:
        content = handle.read()

    expected = None
    for line in content.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == name:
            expected = parts[0]
            break
        if len(parts) == 1 and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            expected = parts[0]
            break

    if expected is None:
        raise FixtureError(f"official checksum asset does not mention {name}")
    if expected != _sha256_file(archive):
        raise FixtureError(
            f"{name}: official checksum asset disagrees with the archive"
        )


def input_fingerprint(ltp_dir: str) -> str:
    """Digest over every input that shapes the fixture."""
    digest = hashlib.sha256()
    paths = [
        os.path.join(ltp_dir, "pin.json"),
        os.path.join(ltp_dir, "manifest.json"),
        os.path.abspath(__file__),
    ]
    paths.extend(
        os.path.join(ltp_dir, "helpers", source) for source in HELPER_SOURCES
    )
    for path in paths:
        digest.update(os.path.basename(path).encode())
        digest.update(b"\0")
        with open(path, "rb") as handle:
            digest.update(handle.read())
        digest.update(b"\0")
    return digest.hexdigest()


def _extract_tar(archive: str, dest_parent: str, expect_prefix: str) -> str:
    """Extract and return the (single) top-level directory."""
    os.makedirs(dest_parent, exist_ok=True)
    _run(["tar", "-xf", archive, "-C", dest_parent])
    extracted = os.path.join(dest_parent, expect_prefix)
    if not os.path.isdir(extracted):
        raise FixtureError(f"{archive} did not extract to {expect_prefix}")
    return extracted


def _find_test_source_dirs(
    src_root: str, tests: List[Dict[str, Any]]
) -> Dict[str, str]:
    """Locate the source directory of every selected test id."""
    wanted = {test["id"] for test in tests}
    found: Dict[str, str] = {}
    syscalls_root = os.path.join(src_root, "testcases", "kernel", "syscalls")
    if not os.path.isdir(syscalls_root):
        raise FixtureError(f"{syscalls_root} missing from the LTP source tree")

    for dirpath, _dirnames, filenames in os.walk(syscalls_root):
        for test_id in wanted - found.keys():
            if f"{test_id}.c" in filenames:
                found[test_id] = dirpath

    missing = sorted(wanted - found.keys())
    if missing:
        raise FixtureError(
            f"tests not found in the pinned LTP source: {', '.join(missing)}"
        )
    return found


def _build_env(cross_compile: str, source_date_epoch: int) -> Dict[str, str]:
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = str(source_date_epoch)
    env["CC"] = _tool(cross_compile, "gcc")
    env["AR"] = _tool(cross_compile, "ar")
    env["RANLIB"] = _tool(cross_compile, "ranlib")
    env["STRIP"] = _tool(cross_compile, "strip")
    # LTP's compat_16.mk chokes on inherited make flags.
    env.pop("MAKEFLAGS", None)
    env.pop("MFLAGS", None)
    return env


def _configure_and_build(
    src_root: str,
    source_dirs: Dict[str, str],
    cross_compile: str,
    env: Dict[str, str],
    jobs: int,
) -> None:
    if not os.path.isfile(os.path.join(src_root, "include", "config.h")):
        print("  CONF    ltp")
        _run(
            [
                "./configure",
                "--host=aarch64-linux-gnu",
                "--prefix=/opt/ltp",
                f"CC={env['CC']}",
            ],
            cwd=src_root,
            env=env,
            capture=True,
        )

    job_flag = f"-j{jobs}" if jobs > 0 else f"-j{os.cpu_count() or 2}"
    print("  MAKE    ltp lib")
    _run(["make", job_flag, "-C", os.path.join(src_root, "lib")], env=env, capture=True)

    for build_dir in sorted(set(source_dirs.values())):
        rel = os.path.relpath(build_dir, src_root)
        print(f"  MAKE    {rel}")
        _run(["make", job_flag, "-C", build_dir], env=env, capture=True)


def _readelf(cross_compile: str, args: List[str]) -> str:
    return _run([_tool(cross_compile, "readelf")] + args, capture=True)


def _elf_machine(cross_compile: str, path: str) -> Optional[str]:
    try:
        header = _readelf(cross_compile, ["-h", path])
    except FixtureError:
        return None
    match = re.search(r"Machine:\s+(.+)", header)
    return match.group(1).strip() if match else None


def _elf_needed(cross_compile: str, path: str) -> List[str]:
    dynamic = _readelf(cross_compile, ["-d", path])
    return re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", dynamic)


def _elf_interp(cross_compile: str, path: str) -> Optional[str]:
    headers = _readelf(cross_compile, ["-l", path])
    match = re.search(r"Requesting program interpreter: ([^\]]+)\]", headers)
    return match.group(1) if match else None


def _compiler_sysroot(cross_compile: str) -> str:
    sysroot = _run(
        [_tool(cross_compile, "gcc"), "-print-sysroot"], capture=True
    ).strip()
    if not sysroot or not os.path.isdir(sysroot):
        raise FixtureError(
            f"{_tool(cross_compile, 'gcc')} -print-sysroot returned no usable path"
        )
    return os.path.realpath(sysroot)


def _find_sysroot_file(sysroot: str, name: str) -> Optional[str]:
    for libdir in SYSROOT_LIB_DIRS:
        candidate = os.path.join(sysroot, libdir, name)
        if os.path.isfile(candidate):
            return os.path.realpath(candidate)
    return None


def _stage_file(source: str, dest: str, mode: int) -> None:
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copyfile(source, dest)
    os.chmod(dest, mode)


def _stage_library_closure(
    cross_compile: str, sysroot: str, rootfs: str, seeds: List[str]
) -> None:
    """Stage the dynamic loader and the full DT_NEEDED closure.

    Libraries land in /lib inside the rootfs, with /lib64 as a symlink
    alias, and the loader is staged at its PT_INTERP pathname.
    """
    interp: Optional[str] = None
    queue: List[str] = []
    staged: Set[str] = set()

    for seed in seeds:
        if _elf_machine(cross_compile, seed) is None:
            continue
        seed_interp = _elf_interp(cross_compile, seed)
        if seed_interp:
            if interp is None:
                interp = seed_interp
            elif interp != seed_interp:
                raise FixtureError(
                    f"inconsistent interpreters: {interp} vs {seed_interp}"
                )
        queue.extend(_elf_needed(cross_compile, seed))

    if interp is None:
        raise FixtureError("no staged binary requests a program interpreter")

    loader_source = _find_sysroot_file(sysroot, os.path.basename(interp))
    if not loader_source:
        raise FixtureError(f"loader {interp} not found in sysroot {sysroot}")
    _stage_file(loader_source, rootfs + interp, 0o755)

    for optional in OPTIONAL_LIBS:
        source = _find_sysroot_file(sysroot, optional)
        if source:
            queue.append(optional)

    while queue:
        name = queue.pop()
        if name in staged:
            continue
        staged.add(name)

        source = _find_sysroot_file(sysroot, name)
        if not source:
            raise FixtureError(f"library {name} not found in sysroot {sysroot}")
        dest = os.path.join(rootfs, "lib", name)
        _stage_file(source, dest, 0o755)
        queue.extend(_elf_needed(cross_compile, dest))

    lib64 = os.path.join(rootfs, "lib64")
    if not os.path.islink(lib64) and not os.path.exists(lib64):
        os.symlink("lib", lib64)


def _resolve_busybox(repo_root: str) -> str:
    candidates = [
        os.environ.get("LTP_BUSYBOX", ""),
        os.path.join(
            repo_root,
            "externals",
            "test-fixtures",
            "aarch64-musl",
            "staticbin",
            "bin",
            "busybox",
        ),
        os.path.join(repo_root, "build", "busybox"),
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    raise FixtureError(
        "no aarch64 busybox found; set LTP_BUSYBOX, stage the aarch64-musl "
        "fixture tree, or run a target that downloads build/busybox first "
        "(for example: make test-busybox)"
    )


def _stage_busybox(cross_compile: str, repo_root: str, rootfs: str) -> Tuple[str, str]:
    source = _resolve_busybox(repo_root)
    machine = _elf_machine(cross_compile, source)
    if machine != "AArch64":
        raise FixtureError(f"busybox at {source} is {machine}, not AArch64")

    dest = os.path.join(rootfs, "bin", "busybox")
    _stage_file(source, dest, 0o755)
    for applet in BUSYBOX_APPLETS:
        link = os.path.join(rootfs, "bin", applet)
        if os.path.islink(link) or os.path.exists(link):
            os.unlink(link)
        os.symlink("busybox", link)

    return source, _sha256_file(source)


def _stage_runtest_files(
    tests: List[Dict[str, Any]], rootfs: str
) -> List[str]:
    runtest_dir = os.path.join(rootfs, "opt", "ltp", "runtest")
    os.makedirs(runtest_dir, exist_ok=True)
    names = []
    for tier in manifest_mod.TIERS:
        name = manifest_mod.suite_name(tier)
        content = manifest_mod.generate_runtest(tests, tier)
        with open(os.path.join(runtest_dir, name), "w", encoding="utf-8") as handle:
            handle.write(content)
        names.append(name)
    return names


def _build_helpers(
    ltp_dir: str, cross_compile: str, env: Dict[str, str], fixture_dir: str, rootfs: str
) -> Dict[str, str]:
    digests = {}
    targets = {
        "case-launcher.c": os.path.join(
            rootfs, "opt", "elfuse-ltp", "bin", "case-launcher"
        ),
        "qemu-supervisor.c": os.path.join(fixture_dir, "bin", "qemu-supervisor"),
    }
    for source_name, dest in targets.items():
        source = os.path.join(ltp_dir, "helpers", source_name)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        print(f"  CROSSCC {source_name}")
        _run(
            [
                _tool(cross_compile, "gcc"),
                "-static",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-o",
                dest,
                source,
            ],
            env=env,
            capture=True,
        )
        os.chmod(dest, 0o755)
        digests[os.path.basename(dest)] = _sha256_file(dest)
    return digests


def write_inventory(rootfs: str, inventory_path: str) -> str:
    """Sorted "sha256-or-link mode path" lines; returns the list digest."""
    entries = []
    for dirpath, dirnames, filenames in os.walk(rootfs):
        dirnames.sort()
        for filename in sorted(filenames):
            full = os.path.join(dirpath, filename)
            rel = os.path.relpath(full, rootfs)
            mode = stat.S_IMODE(os.lstat(full).st_mode)
            if os.path.islink(full):
                entries.append(f"link:{os.readlink(full)} {mode:04o} {rel}")
            else:
                entries.append(f"{_sha256_file(full)} {mode:04o} {rel}")
        for dirname in list(dirnames):
            full = os.path.join(dirpath, dirname)
            if os.path.islink(full):
                rel = os.path.relpath(full, rootfs)
                entries.append(f"link:{os.readlink(full)} 0755 {rel}")
                dirnames.remove(dirname)

    entries.sort(key=lambda line: line.split(" ", 2)[2])
    content = "\n".join(entries) + "\n"
    with open(inventory_path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return hashlib.sha256(content.encode()).hexdigest()


def build(
    args: argparse.Namespace,
    pins: Dict[str, Any],
    tests: List[Dict[str, Any]],
    ltp_dir: str,
    repo_root: str,
) -> int:
    try:
        return _build(args, pins, tests, ltp_dir, repo_root)
    except FixtureError as err:
        print(f"error: {err}", file=sys.stderr)
        return EXIT_FAIL


def _build(
    args: argparse.Namespace,
    pins: Dict[str, Any],
    tests: List[Dict[str, Any]],
    ltp_dir: str,
    repo_root: str,
) -> int:
    fixture_dir = os.path.realpath(args.fixture_dir)
    marker = os.path.join(fixture_dir, ".complete")
    fingerprint = input_fingerprint(ltp_dir)

    if os.path.isfile(marker) and not args.force:
        with open(marker, "r", encoding="utf-8") as handle:
            recorded = handle.read().strip()
        if recorded == fingerprint:
            print(f"fixture is up to date at {fixture_dir}")
            return EXIT_OK
        print("fixture inputs changed; rebuilding")

    cross_compile = _resolve_cross_compile()
    sysroot = _compiler_sysroot(cross_compile)
    cache = os.path.join(fixture_dir, "cache")
    os.makedirs(cache, exist_ok=True)
    if os.path.isfile(marker):
        os.unlink(marker)

    ltp_pin = pins["ltp"]
    kirk_pin = pins["kirk"]

    ltp_name = os.path.basename(ltp_pin["archive_url"])
    ltp_archive = _fetch_pinned(
        cache, ltp_name, ltp_pin["archive_url"], ltp_pin["archive_sha256"]
    )
    checksum_asset = os.path.join(cache, ltp_name + ".sha256")
    if not os.path.isfile(checksum_asset):
        _download(ltp_pin["sha256_url"], checksum_asset)
    _verify_official_checksum(ltp_archive, checksum_asset, ltp_name)

    kirk_name = f"kirk-{kirk_pin['tag']}.tar.gz"
    kirk_archive = _fetch_pinned(
        cache, kirk_name, kirk_pin["archive_url"], kirk_pin["archive_sha256"]
    )

    kirk_dest = os.path.join(fixture_dir, "kirk")
    if not os.path.isfile(os.path.join(kirk_dest, "kirk")):
        with tempfile.TemporaryDirectory(dir=fixture_dir) as scratch:
            extracted = _extract_tar(
                kirk_archive, scratch, f"kirk-{kirk_pin['tag'].lstrip('v')}"
            )
            if os.path.isdir(kirk_dest):
                shutil.rmtree(kirk_dest)
            shutil.move(extracted, kirk_dest)
    if not os.path.isfile(os.path.join(kirk_dest, "libkirk", "com.py")):
        raise FixtureError("extracted kirk tree lacks libkirk/com.py")

    src_parent = os.path.join(fixture_dir, "src")
    src_root = os.path.join(src_parent, f"ltp-full-{ltp_pin['release']}")
    if not os.path.isdir(src_root):
        print("  UNTAR   " + ltp_name)
        _extract_tar(ltp_archive, src_parent, f"ltp-full-{ltp_pin['release']}")

    source_dirs = _find_test_source_dirs(src_root, tests)
    env = _build_env(cross_compile, ltp_pin["source_date_epoch"])
    _configure_and_build(src_root, source_dirs, cross_compile, env, args.jobs)

    rootfs = os.path.join(fixture_dir, "rootfs")
    if os.path.isdir(rootfs):
        shutil.rmtree(rootfs)

    tc_bin = os.path.join(rootfs, "opt", "ltp", "testcases", "bin")
    staged_elves = []
    for test in tests:
        names = [test["id"]] + test["helpers"]
        for name in names:
            source = os.path.join(source_dirs[test["id"]], name)
            if not os.path.isfile(source):
                raise FixtureError(
                    f"{name} was not produced by the build in "
                    f"{source_dirs[test['id']]}"
                )
            dest = os.path.join(tc_bin, name)
            _stage_file(source, dest, 0o755)
            staged_elves.append(dest)
        for entry in test["data"]:
            source = os.path.join(src_root, entry)
            dest = os.path.join(rootfs, "opt", "ltp", entry)
            if not os.path.isfile(source):
                raise FixtureError(f"data file {entry} missing from the source tree")
            _stage_file(source, dest, 0o644)

    for staged in staged_elves:
        machine = _elf_machine(cross_compile, staged)
        if machine != "AArch64":
            raise FixtureError(f"{staged} is {machine}, not AArch64")

    _stage_file(
        os.path.join(src_root, "COPYING"),
        os.path.join(rootfs, "opt", "ltp", "COPYING"),
        0o644,
    )
    with open(
        os.path.join(rootfs, "opt", "ltp", "Version"), "w", encoding="utf-8"
    ) as handle:
        handle.write(f"{ltp_pin['release']} (commit {ltp_pin['commit']})\n")

    _stage_library_closure(cross_compile, sysroot, rootfs, staged_elves)
    busybox_source, busybox_sha = _stage_busybox(cross_compile, repo_root, rootfs)
    helper_digests = _build_helpers(ltp_dir, cross_compile, env, fixture_dir, rootfs)
    runtest_names = _stage_runtest_files(tests, rootfs)

    for name, content in (
        ("passwd", ETC_PASSWD),
        ("group", ETC_GROUP),
        ("nsswitch.conf", ETC_NSSWITCH),
    ):
        path = os.path.join(rootfs, "etc", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(path, 0o644)

    for directory, mode in (
        ("tmp", 0o1777),
        ("dev", 0o755),
        ("dev/shm", 0o1777),
        ("proc", 0o555),
        ("sys", 0o555),
        ("root", 0o700),
    ):
        path = os.path.join(rootfs, directory)
        os.makedirs(path, exist_ok=True)
        os.chmod(path, mode)

    inventory_digest = write_inventory(
        rootfs, os.path.join(fixture_dir, "inventory.txt")
    )

    gcc_version = _run(
        [_tool(cross_compile, "gcc"), "--version"], capture=True
    ).splitlines()[0]
    metadata = {
        "schema_version": 1,
        "pins": {
            "ltp_release": ltp_pin["release"],
            "ltp_commit": ltp_pin["commit"],
            "kirk_tag": kirk_pin["tag"],
        },
        "cross_compile": cross_compile,
        "compiler": gcc_version,
        "compiler_sysroot": sysroot,
        "source_date_epoch": ltp_pin["source_date_epoch"],
        "busybox": {"source": busybox_source, "sha256": busybox_sha},
        "helpers": helper_digests,
        "runtest_files": runtest_names,
        "inventory_sha256": inventory_digest,
        "input_fingerprint": fingerprint,
    }
    with open(
        os.path.join(fixture_dir, "fixture-metadata.json"), "w", encoding="utf-8"
    ) as handle:
        json.dump(metadata, handle, indent=2, sort_keys=True)
        handle.write("\n")

    with open(marker + ".tmp", "w", encoding="utf-8") as handle:
        handle.write(fingerprint + "\n")
    os.replace(marker + ".tmp", marker)

    print(f"fixture ready at {fixture_dir}")
    return EXIT_OK


def verify(
    args: argparse.Namespace,
    pins: Dict[str, Any],
    tests: List[Dict[str, Any]],
    ltp_dir: str,
) -> int:
    try:
        return _verify(args, pins, tests, ltp_dir)
    except FixtureError as err:
        print(f"error: {err}", file=sys.stderr)
        return EXIT_FAIL


def _verify(
    args: argparse.Namespace,
    pins: Dict[str, Any],
    tests: List[Dict[str, Any]],
    ltp_dir: str,
) -> int:
    fixture_dir = os.path.realpath(args.fixture_dir)
    marker = os.path.join(fixture_dir, ".complete")
    metadata_path = os.path.join(fixture_dir, "fixture-metadata.json")
    inventory_path = os.path.join(fixture_dir, "inventory.txt")
    rootfs = os.path.join(fixture_dir, "rootfs")

    for path in (marker, metadata_path, inventory_path):
        if not os.path.isfile(path):
            raise FixtureError(f"{path} is missing; run: make build-ltp-fixture")
    if not os.path.isdir(rootfs):
        raise FixtureError(f"{rootfs} is missing; run: make build-ltp-fixture")

    with open(marker, "r", encoding="utf-8") as handle:
        recorded = handle.read().strip()
    fingerprint = input_fingerprint(ltp_dir)
    if recorded != fingerprint:
        raise FixtureError(
            "fixture inputs changed since the last build; run: make build-ltp-fixture"
        )

    with open(metadata_path, "r", encoding="utf-8") as handle:
        metadata = json.load(handle)
    expected_pins = {
        "ltp_release": pins["ltp"]["release"],
        "ltp_commit": pins["ltp"]["commit"],
        "kirk_tag": pins["kirk"]["tag"],
    }
    if metadata.get("pins") != expected_pins:
        raise FixtureError("fixture-metadata.json pins disagree with pin.json")

    if args.quick:
        print("fixture metadata and fingerprint verified (quick)")
        return EXIT_OK

    cache = os.path.join(fixture_dir, "cache")
    ltp_name = os.path.basename(pins["ltp"]["archive_url"])
    for name, sha in (
        (ltp_name, pins["ltp"]["archive_sha256"]),
        (f"kirk-{pins['kirk']['tag']}.tar.gz", pins["kirk"]["archive_sha256"]),
    ):
        path = os.path.join(cache, name)
        if not os.path.isfile(path):
            raise FixtureError(
                f"cached archive {name} is missing; verification needs the cache "
                f"(run: make build-ltp-fixture FORCE=1)"
            )
        if _sha256_file(path) != sha:
            raise FixtureError(f"cached archive {name} no longer matches its pin")

    with open(inventory_path, "r", encoding="utf-8") as handle:
        recorded_inventory = handle.read()
    with tempfile.NamedTemporaryFile("r", delete=True) as scratch:
        current_digest = write_inventory(rootfs, scratch.name)
    if hashlib.sha256(recorded_inventory.encode()).hexdigest() != current_digest:
        raise FixtureError("rootfs contents drifted from inventory.txt")

    cross_compile = _resolve_cross_compile()
    tc_bin = os.path.join(rootfs, "opt", "ltp", "testcases", "bin")
    seeds = []
    for test in tests:
        for name in [test["id"]] + test["helpers"]:
            path = os.path.join(tc_bin, name)
            if not os.path.isfile(path):
                raise FixtureError(f"{name} is missing from the staged rootfs")
            machine = _elf_machine(cross_compile, path)
            if machine != "AArch64":
                raise FixtureError(f"{path} is {machine}, not AArch64")
            seeds.append(path)

    resolved: Set[str] = set()
    queue: List[str] = []
    for seed in seeds:
        interp = _elf_interp(cross_compile, seed)
        if interp and not os.path.isfile(rootfs + interp):
            raise FixtureError(f"interpreter {interp} is not staged")
        queue.extend(_elf_needed(cross_compile, seed))
    while queue:
        name = queue.pop()
        if name in resolved:
            continue
        resolved.add(name)
        staged = os.path.join(rootfs, "lib", name)
        if not os.path.isfile(staged):
            raise FixtureError(f"DT_NEEDED {name} is not staged in /lib")
        queue.extend(_elf_needed(cross_compile, staged))

    for name in ("bin/busybox", "bin/sh", "opt/elfuse-ltp/bin/case-launcher"):
        path = os.path.join(rootfs, name)
        if not (os.path.isfile(path) or os.path.islink(path)):
            raise FixtureError(f"{name} is missing from the staged rootfs")
    if not os.path.isfile(os.path.join(fixture_dir, "bin", "qemu-supervisor")):
        raise FixtureError("bin/qemu-supervisor is missing from the fixture")
    if not os.path.isfile(os.path.join(fixture_dir, "kirk", "libkirk", "com.py")):
        raise FixtureError("kirk checkout is missing from the fixture")

    print("fixture verified: pins, inventory, ELF machine, dependency closure")
    return EXIT_OK
