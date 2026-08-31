# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from conformance import elfcheck, payload

PREFIX = "/opt/ltp"
BUSYBOX_APPLETS = ("sh", "ash", "cat", "cp", "ln", "ls", "mkdir", "mknod", "mv", "rm",
                   "rmdir", "sed", "sleep", "touch", "true")
ETC_PASSWD = "root:x:0:0:root:/root:/bin/sh\nltp:x:1000:1000:ltp:/tmp:/bin/sh\n"
ETC_GROUP = "root:x:0:\nltp:x:1000:\n"
ETC_NSSWITCH = "passwd: files\ngroup: files\n"
OPTIONAL_LIBS = ("libnss_files.so.2",)
LAUNCHER = "/opt/elfuse-ltp/bin/case-launcher"


def _run(argv: List[str], **kw) -> subprocess.CompletedProcess:
    kw.setdefault("stdout", subprocess.PIPE)
    kw.setdefault("stderr", subprocess.STDOUT)
    done = subprocess.run(argv, text=True, **kw)
    if done.returncode != 0:
        raise payload.PayloadError("build", "command failed (%d): %s\n%s" % (
            done.returncode, " ".join(map(str, argv)), (done.stdout or "")[-4000:]))
    return done


def parse_runtest(text: str) -> List[Tuple[str, List[str]]]:
    """Return unique tag and argv pairs from a runtest file."""
    out: List[Tuple[str, List[str]]] = []
    seen = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = shlex.split(line)
        if parts[0] in seen:
            raise payload.PayloadError("config", "runtest file repeats tag %s" % parts[0])
        seen.add(parts[0])
        out.append((parts[0], parts[1:]))
    return out


def dir_candidates(binary: str) -> List[str]:
    """Return source directories in upstream naming order.

    Strip two-digit indices before trailing digits (clone301 -> clone3), then
    shorten compound names and try the SysV IPC directory.
    """
    stem = binary[:-3] if binary.endswith(("_64", "_16")) else binary
    stems: List[str] = []
    m = re.match(r"^(.*?)_?\d{2}$", stem)
    if m:
        stems.append(m.group(1).rstrip("_"))
    bare = stem.rstrip("0123456789").rstrip("_")
    if bare not in stems:
        stems.append(bare)
    short = stems[0]
    while "_" in short:
        short = short.rsplit("_", 1)[0]
        if short not in stems:
            stems.append(short)
    return ["kernel/syscalls/%s" % s for s in stems] + ["kernel/syscalls/ipc/%s" % s for s in stems]


def resolve_dir(src: Path, binary: str, override: Optional[str]) -> Optional[str]:
    if override:
        return override if (src / "testcases" / override).is_dir() else None
    for candidate in dir_candidates(binary):
        if (src / "testcases" / candidate).is_dir():
            return candidate
    return None


def resolve_cross() -> str:
    cross = os.environ.get("CROSS_COMPILE", "")
    for candidate in ([cross] if cross else ["aarch64-linux-gnu-", "aarch64-unknown-linux-gnu-", ""]):
        if shutil.which(candidate + "gcc"):
            probe = subprocess.run([candidate + "gcc", "-dumpmachine"], capture_output=True, text=True)
            if "aarch64" in probe.stdout and "linux" in probe.stdout:
                return candidate
    raise payload.PayloadError("config", "no AArch64 Linux gcc found; set CROSS_COMPILE")


def compiler_id(cross: str) -> str:
    return subprocess.run([cross + "gcc", "--version"], capture_output=True, text=True).stdout.splitlines()[0]


def build_env(cross: str, epoch: int) -> Dict[str, str]:
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(epoch), CC=cross + "gcc", AR=cross + "ar",
               RANLIB=cross + "ranlib", STRIP=cross + "strip")
    # LTP compatibility makefiles reject inherited jobserver flags.
    env.pop("MAKEFLAGS", None)
    env.pop("MFLAGS", None)
    return env


def resolve_busybox(repo_root: Path) -> Path:
    for candidate in (os.environ.get("LTP_BUSYBOX", ""),
                      repo_root / "externals/test-fixtures/aarch64-musl/staticbin/bin/busybox"):
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    raise payload.PayloadError("config", "no AArch64 busybox; run: bash tests/fetch-fixtures.sh")


def _download(url: str, dest: Path) -> None:
    print("Downloading %s" % url)
    try:
        with urllib.request.urlopen(url) as resp, open(dest, "wb") as out:
            shutil.copyfileobj(resp, out)
    except (OSError, urllib.error.URLError) as e:
        raise payload.PayloadError("build", "%s: %s" % (url, e)) from None


def fetch_pinned(cache: Path, name: str, url: str, sha256: str) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    dest = cache / name
    if not dest.is_file() or payload.sha256_file(dest) != sha256:
        _download(url, dest)
    actual = payload.sha256_file(dest)
    if actual != sha256:
        raise payload.PayloadError("config", "%s: sha256 %s is not the pinned %s" % (name, actual, sha256))
    return dest


def verify_official_checksum(cache: Path, archive: Path, section: Dict[str, str]) -> None:
    asset = cache / (archive.name + ".sha256")
    if not asset.is_file():
        _download(section["sha256_url"], asset)
    words = asset.read_text().split()
    if not words or words[0] != section["archive_sha256"]:
        raise payload.PayloadError("config", "upstream's checksum asset disagrees with pins.json for %s" % archive.name)


def extract(archive: Path, parent: Path, name: str) -> Path:
    dest = parent / name
    if dest.exists():
        shutil.rmtree(dest)
    parent.mkdir(parents=True, exist_ok=True)
    _run(["tar", "-xf", str(archive), "-C", str(parent)])
    if not dest.is_dir():
        raise payload.PayloadError("build", "%s did not produce %s" % (archive.name, name))
    return dest


def _stage(source: Path, dest: Path, mode: int) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)
    dest.chmod(mode)


def _sysroot_file(sysroot: Path, name: str) -> Optional[Path]:
    for base in ("lib", "lib64", "usr/lib", "usr/lib64", "aarch64-unknown-linux-gnu/lib",
                 "aarch64-linux-gnu/lib", "usr/lib/aarch64-linux-gnu"):
        if (sysroot / base / name).is_file():
            return sysroot / base / name
    hits = list(sysroot.glob("**/" + name))
    return hits[0] if hits else None


def stage_library_closure(sysroot: Path, rootfs: Path, seeds: List[Path]) -> None:
    """Stage PT_INTERP and DT_NEEDED, with lib64 aliased to lib."""
    interp = None
    queue: List[str] = list(OPTIONAL_LIBS)
    for seed in seeds:
        info = elfcheck.read_dynamic(seed)
        if info.interp:
            if interp not in (None, info.interp):
                raise payload.PayloadError("build", "interpreters differ: %s vs %s" % (interp, info.interp))
            interp = info.interp
        queue.extend(info.needed)
    if interp is None:
        raise payload.PayloadError("build", "no staged binary requests an interpreter")
    loader = _sysroot_file(sysroot, Path(interp).name)
    if loader is None:
        raise payload.PayloadError("build", "loader %s not found under %s" % (interp, sysroot))
    _stage(loader, Path(str(rootfs) + interp), 0o755)
    staged = set()
    while queue:
        name = queue.pop()
        if name in staged:
            continue
        staged.add(name)
        source = _sysroot_file(sysroot, name)
        if source is None:
            if name in OPTIONAL_LIBS:
                continue
            raise payload.PayloadError("build", "library %s not found under %s" % (name, sysroot))
        _stage(source, rootfs / "lib" / name, 0o755)
        queue.extend(elfcheck.read_dynamic(rootfs / "lib" / name).needed)
    if not (rootfs / "lib64").exists():
        (rootfs / "lib64").symlink_to("lib")


def stage_rootfs(rootfs: Path, busybox: Path) -> None:
    if elfcheck.read_dynamic(busybox).machine != elfcheck.EM_AARCH64:
        raise payload.PayloadError("config", "%s is not AArch64" % busybox)
    _stage(busybox, rootfs / "bin" / "busybox", 0o755)
    for applet in BUSYBOX_APPLETS:
        (rootfs / "bin" / applet).symlink_to("busybox")
    (rootfs / "etc").mkdir(exist_ok=True)
    (rootfs / "etc" / "passwd").write_text(ETC_PASSWD)
    (rootfs / "etc" / "group").write_text(ETC_GROUP)
    (rootfs / "etc" / "nsswitch.conf").write_text(ETC_NSSWITCH)
    for name in ("tmp", "root", "proc", "sys", "dev", "opt/ltp/runtest"):
        (rootfs / name).mkdir(parents=True, exist_ok=True)
    (rootfs / "tmp").chmod(0o1777)


def build(section: Dict[str, Dict[str, str]], root: Path, repo_root: Path, helpers: Path,
          tags: Dict[str, Optional[str]], fp: str, force: bool = False) -> bool:
    """Build tags with optional source overrides; return False if current."""
    if not force and payload.status(root, fp) == "ok":
        return False
    cross = resolve_cross()
    busybox = resolve_busybox(repo_root)
    env = build_env(cross, int(section["ltp"]["source_date_epoch"]))
    cache = root / "cache"
    ltp_archive = fetch_pinned(cache, Path(section["ltp"]["archive_url"]).name,
                               section["ltp"]["archive_url"], section["ltp"]["archive_sha256"])
    verify_official_checksum(cache, ltp_archive, section["ltp"])
    kirk_archive = fetch_pinned(cache, "kirk-%s.tar.gz" % section["kirk"]["tag"],
                                section["kirk"]["archive_url"], section["kirk"]["archive_sha256"])
    for stale in ("rootfs", "bin", "kirk", "metadata", payload.MANIFEST):
        target = root / stale
        if target.is_symlink() or target.is_file():
            target.unlink()
        elif target.is_dir():
            shutil.rmtree(target)
    src = extract(ltp_archive, root / "src", "ltp-full-%s" % section["ltp"]["release"])
    kirk = extract(kirk_archive, root / "src", "kirk-%s" % section["kirk"]["tag"].lstrip("v"))
    shutil.copytree(kirk, root / "kirk")
    (root / "metadata").mkdir()
    shutil.copy2(src / "runtest" / "syscalls", root / "metadata" / "syscalls.runtest")
    argv_of = dict(parse_runtest((src / "runtest" / "syscalls").read_text()))
    unknown = sorted(set(tags) - set(argv_of))
    if unknown:
        raise payload.PayloadError("config", "not in the pinned runtest/syscalls: %s" % ", ".join(unknown))
    entries = [(tag, argv_of[tag], override) for tag, override in tags.items()]

    print("  CONF    ltp")
    _run(["./configure", "--host=aarch64-linux-gnu", "--prefix=" + PREFIX, "CC=" + env["CC"]],
         cwd=str(src), env=env)
    jobs = "-j%d" % (os.cpu_count() or 2)
    _run(["make", jobs, "-C", str(src / "lib")], env=env)
    dirs: Dict[str, str] = {}
    unresolved = []
    for tag, argv, override in entries:
        binary = Path((argv or [tag])[0]).name
        rel = resolve_dir(src, binary, override)
        if rel is None:
            unresolved.append("%s (%s)" % (tag, override or "no candidate directory"))
        else:
            dirs[tag] = rel
    if unresolved:
        raise payload.PayloadError("config", "no testcase directory for: %s" % ", ".join(unresolved))
    for rel in sorted(set(dirs.values())):
        print("  MAKE    %s" % rel)
        _run(["make", jobs, "-C", str(src / "testcases" / rel)], env=env)

    rootfs = root / "rootfs"
    bindir = rootfs / "opt/ltp/testcases/bin"
    bindir.mkdir(parents=True)
    seeds: List[Path] = []
    missing = []
    for tag, argv, _ in entries:
        rel = dirs[tag]
        for built in sorted((src / "testcases" / rel).iterdir()):
            if built.is_file() and os.access(built, os.X_OK) and not built.suffix in (".c", ".h", ".o"):
                dest = bindir / built.name
                if not dest.exists():
                    _stage(built, dest, 0o755)
                    try:
                        if elfcheck.read_dynamic(dest).interp:
                            seeds.append(dest)
                    except elfcheck.ElfError:
                        pass
        name = Path((argv or [tag])[0]).name
        if not (bindir / name).exists():
            missing.append("%s (%s)" % (name, rel))
    if missing:
        raise payload.PayloadError("build", "built tests are missing: %s" % ", ".join(sorted(set(missing))))
    stage_rootfs(rootfs, busybox)
    print("  CROSSCC helpers")
    launcher = Path(str(rootfs) + LAUNCHER)
    supervisor = root / "bin" / "guest-supervisor"
    for source, dest in ((helpers / "case-launcher.c", launcher), (helpers / "guest-supervisor.c", supervisor)):
        dest.parent.mkdir(parents=True, exist_ok=True)
        _run([cross + "gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror", "-o", str(dest), str(source)], env=env)
        elfcheck.validate_static_aarch64(dest)
        dest.chmod(0o755)
    stage_library_closure(Path(_run([cross + "gcc", "-print-sysroot"]).stdout.strip()), rootfs, seeds)
    shutil.rmtree(root / "src")
    payload.write_manifest(root, fp, {"release": section["ltp"]["release"], "kirk": section["kirk"]["tag"],
                                      "tests": len(entries), "busybox_sha256": payload.sha256_file(busybox)},
                           volatile=["rootfs/%s/" % d for d in ("tmp", "proc", "sys", "dev")])
    return True
