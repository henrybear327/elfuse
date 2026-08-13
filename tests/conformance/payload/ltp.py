"""Build the pinned LTP payload and stage one rootfs for both backends.

Acquisition verifies the release tarball against the recorded sha256 and
against upstream's published .sha256 asset, and unpacks kirk beside it;
neither tree ever enters the repo (see license_boundary in pins.json).
The cross-build compiles LTP's lib/ plus only the testcase directories
the selection references. Staging produces one glibc rootfs consumed by
both backends: elfuse runs it via --sysroot, the QEMU guest copies it
from the read-only 9p share into tmpfs. The sweep selection is generated
here from the pinned runtest/syscalls file instead of being committed,
so it cannot drift from the pin; data/ltp-manifest.jsonc carries the
curated tiers and the overrides the generator's conventions cannot
resolve.

Runs standalone (python3 tests/conformance/payload/ltp.py [--force]
[--no-sweep] or verify [EXPECTED_FINGERPRINT]): exit 0 built, complete,
or verified; 1 build or staging failure; 2 configuration error (no
cross compiler, no busybox).
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import urllib.request

_PACKAGE_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_PACKAGE_DIR.parents[1]))

from conformance import jsonc, pins
from conformance.payload import common, elfcheck

REPO_ROOT = _PACKAGE_DIR.parents[2]
MANIFEST_PATH = _PACKAGE_DIR.parent / "data" / "ltp-manifest.jsonc"
HELPERS_DIR = _PACKAGE_DIR.parent / "helpers"
PAYLOAD_DIR = REPO_ROOT / "externals" / "payloads" / "ltp"
TIERS = ("fast", "extended", "nightly", "sweep", "sweep-slow")

BUSYBOX_APPLETS = ("sh", "ash", "cat", "cp", "ln", "ls", "mkdir", "mknod",
                   "mv", "rm", "rmdir", "sed", "sleep", "touch", "true")
ETC_PASSWD = "root:x:0:0:root:/root:/bin/sh\nltp:x:1000:1000:ltp:/tmp:/bin/sh\n"
ETC_GROUP = "root:x:0:\nltp:x:1000:\n"
ETC_NSSWITCH = "passwd: files\ngroup: files\n"
OPTIONAL_LIBS = ("libnss_files.so.2",)


class PayloadError(Exception):
    def __init__(self, message, exit_code=1):
        super().__init__(message)
        self.exit_code = exit_code


def _run(argv, **kwargs):
    kwargs.setdefault("stdout", subprocess.PIPE)
    kwargs.setdefault("stderr", subprocess.STDOUT)
    result = subprocess.run(argv, text=True, **kwargs)
    if result.returncode != 0:
        raise PayloadError(
            "command failed (%d): %s\n%s"
            % (result.returncode, " ".join(map(str, argv)),
               (result.stdout or "")[-4000:]))
    return result


def load_manifest(path=MANIFEST_PATH) -> dict:
    doc = jsonc.load_path(path)
    if doc.get("schema_version") != 1:
        raise PayloadError("%s: schema_version must be 1" % path, exit_code=2)
    seen = set()
    for entry in doc["tests"]:
        if entry["tier"] not in TIERS[:3]:
            raise PayloadError(
                "%s: curated entry %s has tier %r"
                % (path, entry["id"], entry["tier"]), exit_code=2)
        if entry["id"] in seen:
            raise PayloadError("%s: duplicate id %s" % (path, entry["id"]),
                               exit_code=2)
        seen.add(entry["id"])
    return doc


def dir_candidates(binary: str) -> list:
    """Candidate source directories for a runtest binary, best first.

    _64 and _16 suffixes are the large-file and compat-16 builds of the
    base test and live in the base directory (fcntl24_64 in fcntl/,
    chown01_16 in chown/); after stripping the numeric index a trailing
    underscore is separator residue (accept4_01 builds in accept4/).
    Compound names then shorten at underscores (timerfd_settime01 builds
    in timerfd/, futex_wait05 in futex/), and the SysV IPC families live
    one level down (msgctl01 in ipc/msgctl/). A wrong candidate can only
    fail loudly: the staged binary is looked up in the resolved
    directory, so a mis-probe surfaces as a missing artifact, never as a
    silently wrong payload. Entries no convention fits carry explicit
    source_dir overrides in the manifest.
    """
    stem = binary
    if stem.endswith(("_64", "_16")):
        stem = stem[:-3]
    stems = []
    # The naming convention indexes tests with two digits, so strip
    # exactly that first: clone301 builds in clone3/, wait401 in wait4/,
    # and stripping every trailing digit would land in the existing but
    # wrong clone/ and wait/ directories.
    match = re.match(r"^(.*?)_?\d{2}$", stem)
    if match:
        stems.append(match.group(1).rstrip("_"))
    bare = stem.rstrip("0123456789").rstrip("_")
    if bare not in stems:
        stems.append(bare)
    shortened = stems[0]
    while "_" in shortened:
        shortened = shortened.rsplit("_", 1)[0]
        if shortened not in stems:
            stems.append(shortened)
    return (["kernel/syscalls/%s" % s for s in stems]
            + ["kernel/syscalls/ipc/%s" % s for s in stems])


def generate_sweep(runtest_text: str, manifest: dict) -> list:
    """One entry per runtest/syscalls line, tagged sweep or sweep-slow.

    The tag, not the binary, is the identity: parameterized lines reuse a
    binary under distinct tags. The build directory defaults to the
    binary's name with trailing digits stripped
    (testcases/kernel/syscalls/<dir>); overrides name the entries whose
    source or directory that convention cannot resolve.
    """
    sweep = manifest["sweep"]
    overrides = sweep.get("overrides", {})
    default_timeout = sweep["default_timeout_seconds"]
    curated_ids = {entry["id"] for entry in manifest["tests"]}
    entries = []
    seen = set()
    for raw in runtest_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = shlex.split(line)
        tag, argv = parts[0], parts[1:]
        if tag in seen:
            raise PayloadError("runtest file repeats tag %s" % tag)
        seen.add(tag)
        if tag in curated_ids:
            continue
        override = overrides.get(tag, {})
        unknown = set(override) - {"source", "source_dir", "timeout_seconds",
                                   "notes"}
        if unknown:
            raise PayloadError("override %s has unknown keys: %s"
                               % (tag, sorted(unknown)), exit_code=2)
        timeout = override.get("timeout_seconds", default_timeout)
        entries.append({
            "id": tag,
            "arguments": argv,
            "tier": "sweep" if timeout <= default_timeout else "sweep-slow",
            "timeout_seconds": timeout,
            "source_dir": override.get("source_dir"),
            "source": override.get("source"),
        })
    stale = set(overrides) - seen
    if stale:
        raise PayloadError("overrides name no runtest entry: %s"
                           % sorted(stale), exit_code=2)
    return entries


def generate_runtest(entries, tier) -> str:
    lines = ["# Generated by tests/conformance/payload/ltp.py for tier %s"
             % tier]
    for entry in entries:
        if entry["tier"] != tier:
            continue
        argv = entry.get("arguments") or [entry["id"]]
        lines.append(" ".join([entry["id"]] + list(argv)))
    return "\n".join(lines) + "\n"


def _resolve_cross_compile() -> str:
    cross = os.environ.get("CROSS_COMPILE", "")
    candidates = [cross] if cross else ["aarch64-linux-gnu-",
                                        "aarch64-unknown-linux-gnu-", ""]
    for candidate in candidates:
        gcc = candidate + "gcc"
        if shutil.which(gcc):
            probe = subprocess.run([gcc, "-dumpmachine"],
                                   capture_output=True, text=True)
            if "aarch64" in probe.stdout and "linux" in probe.stdout:
                return candidate
    raise PayloadError(
        "no AArch64 Linux compiler found; set CROSS_COMPILE", exit_code=2)


def _build_env(cross: str, source_date_epoch: int) -> dict:
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = str(source_date_epoch)
    env["CC"] = cross + "gcc"
    env["AR"] = cross + "ar"
    env["RANLIB"] = cross + "ranlib"
    env["STRIP"] = cross + "strip"
    # LTP's compat_16.mk chokes on inherited make flags.
    env.pop("MAKEFLAGS", None)
    env.pop("MFLAGS", None)
    return env


def payload_fingerprint(doc=None, sweep=True, busybox=None) -> str:
    doc = doc or pins.load()
    busybox = pathlib.Path(busybox) if busybox else _resolve_busybox()
    try:
        cross = _resolve_cross_compile()
        cc_id = subprocess.run([cross + "gcc", "--version"],
                               capture_output=True,
                               text=True).stdout.splitlines()[0]
    except PayloadError:
        cc_id = "no-compiler"
    return common.fingerprint(
        pin_section={"ltp": doc["ltp"], "kirk": doc["kirk"]},
        files=[MANIFEST_PATH, _PACKAGE_DIR / "ltp.py",
               _PACKAGE_DIR / "elfcheck.py", _PACKAGE_DIR / "common.py",
               HELPERS_DIR / "status-io.h", HELPERS_DIR / "case-launcher.c",
               HELPERS_DIR / "guest-supervisor.c"],
        flavor="%s:%s:busybox-sha256=%s"
        % ("sweep" if sweep else "curated", cc_id,
           common.sha256_file(busybox)))


def _download(url: str, dest: pathlib.Path) -> None:
    print("Downloading %s (explicit opt-in network operation)" % url)
    with urllib.request.urlopen(url) as response, open(dest, "wb") as fh:
        shutil.copyfileobj(response, fh)


def _fetch_pinned(cache: pathlib.Path, name: str, url: str,
                  sha256: str) -> pathlib.Path:
    cache.mkdir(parents=True, exist_ok=True)
    dest = cache / name
    if not dest.is_file() or common.sha256_file(dest) != sha256:
        _download(url, dest)
    actual = common.sha256_file(dest)
    if actual != sha256:
        raise PayloadError("%s: sha256 %s does not match pinned %s"
                           % (name, actual, sha256))
    return dest


def _verify_official_checksum(cache, archive, section) -> None:
    asset = cache / (archive.name + ".sha256")
    if not asset.is_file():
        _download(section["sha256_url"], asset)
    text = asset.read_text(encoding="utf-8").split()
    if not text or text[0] != section["archive_sha256"]:
        raise PayloadError(
            "upstream checksum asset disagrees with pins.json for %s"
            % archive.name)


def _extract(archive: pathlib.Path, parent: pathlib.Path,
             expect_prefix: str) -> pathlib.Path:
    dest = parent / expect_prefix
    if not dest.is_dir():
        parent.mkdir(parents=True, exist_ok=True)
        _run(["tar", "-xf", str(archive), "-C", str(parent)])
    if not dest.is_dir():
        raise PayloadError("archive %s did not produce %s"
                           % (archive.name, expect_prefix))
    return dest


def _stage_file(source, dest, mode) -> None:
    dest = pathlib.Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)
    dest.chmod(mode)


def _compiler_sysroot(cross: str) -> pathlib.Path:
    out = _run([cross + "gcc", "-print-sysroot"]).stdout.strip()
    if not out:
        raise PayloadError("%sgcc reports no sysroot" % cross, exit_code=2)
    return pathlib.Path(out)


def _find_sysroot_file(sysroot: pathlib.Path, name: str):
    for base in ("lib", "lib64", "usr/lib", "usr/lib64",
                 "aarch64-unknown-linux-gnu/lib",
                 "aarch64-linux-gnu/lib", "usr/lib/aarch64-linux-gnu"):
        candidate = sysroot / base / name
        if candidate.is_file():
            return candidate
    matches = list(sysroot.glob("**/" + name))
    return matches[0] if matches else None


def stage_library_closure(sysroot, rootfs, seeds) -> None:
    """Stage the dynamic loader and the full DT_NEEDED closure.

    Libraries land in /lib with /lib64 as a symlink alias, and the
    loader is staged at its PT_INTERP pathname.
    """
    interp = None
    queue = []
    for seed in seeds:
        try:
            info = elfcheck.read_dynamic(seed)
        except elfcheck.ElfCheckError:
            continue
        if info.interp:
            if interp is None:
                interp = info.interp
            elif interp != info.interp:
                raise PayloadError("inconsistent interpreters: %s vs %s"
                                   % (interp, info.interp))
        queue.extend(info.needed)
    if interp is None:
        raise PayloadError("no staged binary requests an interpreter")
    loader = _find_sysroot_file(sysroot, pathlib.Path(interp).name)
    if not loader:
        raise PayloadError("loader %s not found in sysroot %s"
                           % (interp, sysroot))
    _stage_file(loader, str(rootfs) + interp, 0o755)
    for optional in OPTIONAL_LIBS:
        if _find_sysroot_file(sysroot, optional):
            queue.append(optional)
    staged = set()
    while queue:
        name = queue.pop()
        if name in staged:
            continue
        staged.add(name)
        source = _find_sysroot_file(sysroot, name)
        if not source:
            raise PayloadError("library %s not found in sysroot %s"
                               % (name, sysroot))
        dest = rootfs / "lib" / name
        _stage_file(source, dest, 0o755)
        queue.extend(elfcheck.read_dynamic(dest).needed)
    lib64 = rootfs / "lib64"
    if not lib64.exists() and not lib64.is_symlink():
        lib64.symlink_to("lib")


def _resolve_busybox():
    candidates = [
        os.environ.get("LTP_BUSYBOX", ""),
        REPO_ROOT / "externals" / "test-fixtures" / "aarch64-musl" /
        "staticbin" / "bin" / "busybox",
        REPO_ROOT / "build" / "busybox",
    ]
    for candidate in candidates:
        if candidate and pathlib.Path(candidate).is_file():
            return pathlib.Path(candidate)
    raise PayloadError(
        "no aarch64 busybox found; set LTP_BUSYBOX or stage the "
        "aarch64-musl fixture tree (bash tests/fetch-fixtures.sh)",
        exit_code=2)


def build(force=False, sweep=True) -> int:
    doc = pins.load()
    manifest = load_manifest()
    fingerprint = payload_fingerprint(doc, sweep=sweep)
    if not force and common.is_complete(PAYLOAD_DIR, fingerprint):
        print("LTP payload is complete at %s" % PAYLOAD_DIR)
        return 0
    cross = _resolve_cross_compile()
    env = _build_env(cross, doc["ltp"]["source_date_epoch"])
    cache = PAYLOAD_DIR / "cache"
    ltp_archive = _fetch_pinned(
        cache, pathlib.Path(doc["ltp"]["archive_url"]).name,
        doc["ltp"]["archive_url"], doc["ltp"]["archive_sha256"])
    _verify_official_checksum(cache, ltp_archive, doc["ltp"])
    kirk_archive = _fetch_pinned(
        cache, "kirk-%s.tar.gz" % doc["kirk"]["tag"],
        doc["kirk"]["archive_url"], doc["kirk"]["archive_sha256"])
    # A changed fingerprint means some build input changed. Re-extract
    # instead of letting make reuse objects produced for the old input.
    source_parent = PAYLOAD_DIR / "src"
    if source_parent.exists():
        shutil.rmtree(source_parent)
    src = _extract(ltp_archive, PAYLOAD_DIR / "src",
                   "ltp-full-%s" % doc["ltp"]["release"])
    kirk_dir = _extract(kirk_archive, PAYLOAD_DIR,
                        "kirk-%s" % doc["kirk"]["tag"].lstrip("v"))
    kirk_link = PAYLOAD_DIR / "kirk"
    if kirk_link.is_symlink() or kirk_link.exists():
        if kirk_link.is_symlink():
            kirk_link.unlink()
        else:
            shutil.rmtree(kirk_link)
    kirk_link.symlink_to(kirk_dir.name)

    entries = list(manifest["tests"])
    pinned_runtest = src / manifest["sweep"]["runtest_file"]
    metadata = PAYLOAD_DIR / "metadata"
    if metadata.exists():
        shutil.rmtree(metadata)
    metadata.mkdir(parents=True)
    shutil.copy2(pinned_runtest, metadata / "syscalls.runtest")
    if sweep:
        runtest = pinned_runtest.read_text(encoding="utf-8")
        entries += generate_sweep(runtest, manifest)

    if not (src / "include" / "config.h").is_file():
        print("  CONF    ltp")
        _run(["./configure", "--host=aarch64-linux-gnu", "--prefix=/opt/ltp",
              "CC=" + env["CC"]], cwd=str(src), env=env)
    jobs = "-j%d" % (os.cpu_count() or 2)
    print("  MAKE    lib")
    _run(["make", jobs, "-C", str(src / "lib")], env=env)
    unresolved = []
    for entry in entries:
        rel = entry.get("source_dir")
        if rel is None and entry.get("source"):
            rel = str(pathlib.Path(entry["source"]).parent.relative_to(
                "testcases"))
        if rel is None and entry.get("group"):
            rel = "kernel/syscalls/" + entry["group"]
        if rel is None:
            binary = (entry.get("arguments") or [entry["id"]])[0]
            for candidate in dir_candidates(binary):
                if (src / "testcases" / candidate).is_dir():
                    rel = candidate
                    break
        if rel is None or not (src / "testcases" / rel).is_dir():
            unresolved.append("%s (%s)" % (entry["id"], rel or "no candidate"))
        entry["source_dir"] = rel
    if unresolved:
        raise PayloadError(
            "no testcase directory for: %s (fix the naming convention or "
            "add sweep overrides)" % ", ".join(unresolved))
    for rel in sorted({entry["source_dir"] for entry in entries}):
        print("  MAKE    %s" % rel)
        _run(["make", jobs, "-C", str(src / "testcases" / rel)], env=env)

    rootfs = PAYLOAD_DIR / "rootfs"
    if rootfs.exists():
        shutil.rmtree(rootfs)
    bindir = rootfs / "opt" / "ltp" / "testcases" / "bin"
    bindir.mkdir(parents=True)
    seeds = []
    missing = []
    for entry in entries:
        rel = entry["source_dir"]
        # The staged artifact always carries the runtest argv name: a
        # source override pins the build directory, not the name (the
        # sethostname binaries compile from setdomainname sources).
        names = [pathlib.Path((entry.get("arguments") or [entry["id"]])[0]).name]
        names += entry.get("helpers", [])
        for name in names:
            built = src / "testcases" / rel / name
            if not built.is_file():
                missing.append("%s (%s)" % (name, rel))
                continue
            dest = bindir / name
            if not dest.exists():
                _stage_file(built, dest, 0o755)
                seeds.append(dest)
        for data_name in entry.get("data", []):
            _stage_file(src / "testcases" / rel / data_name,
                        bindir / data_name, 0o644)
    if missing:
        raise PayloadError("built tests are missing: %s"
                           % ", ".join(sorted(set(missing))))

    runtest_dir = rootfs / "opt" / "ltp" / "runtest"
    runtest_dir.mkdir(parents=True)
    for tier in TIERS:
        content = generate_runtest(entries, tier)
        if content.count("\n") > 1:
            (runtest_dir / ("elfuse-%s" % tier)).write_text(
                content, encoding="utf-8")

    busybox = _resolve_busybox()
    info = elfcheck.read_dynamic(busybox)
    if info.machine != elfcheck.EM_AARCH64:
        raise PayloadError("busybox at %s is not AArch64" % busybox,
                           exit_code=2)
    _stage_file(busybox, rootfs / "bin" / "busybox", 0o755)
    for applet in BUSYBOX_APPLETS:
        link = rootfs / "bin" / applet
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to("busybox")

    (rootfs / "etc").mkdir(exist_ok=True)
    (rootfs / "etc" / "passwd").write_text(ETC_PASSWD, encoding="utf-8")
    (rootfs / "etc" / "group").write_text(ETC_GROUP, encoding="utf-8")
    (rootfs / "etc" / "nsswitch.conf").write_text(ETC_NSSWITCH,
                                                  encoding="utf-8")
    for name in ("tmp", "root", "proc", "sys", "dev"):
        (rootfs / name).mkdir(exist_ok=True)

    print("  CROSSCC helpers")
    launcher = rootfs / "opt" / "elfuse-ltp" / "bin" / "case-launcher"
    supervisor = PAYLOAD_DIR / "bin" / "guest-supervisor"
    for source, dest in ((HELPERS_DIR / "case-launcher.c", launcher),
                         (HELPERS_DIR / "guest-supervisor.c", supervisor)):
        dest.parent.mkdir(parents=True, exist_ok=True)
        _run([cross + "gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
              "-I", str(HELPERS_DIR), "-o", str(dest), str(source)], env=env)
        dest.chmod(0o755)
    seeds.append(launcher)

    stage_library_closure(_compiler_sysroot(cross), rootfs, seeds)

    inventory = sorted(
        str(p.relative_to(rootfs)) for p in rootfs.rglob("*") if p.is_file())
    (PAYLOAD_DIR / "inventory.txt").write_text(
        "\n".join(inventory) + "\n", encoding="utf-8")
    runtime_roots = ["rootfs", "bin", "metadata", "kirk", kirk_dir.name]
    runtime_manifest = common.inventory(PAYLOAD_DIR, runtime_roots)
    (PAYLOAD_DIR / "runtime-manifest.json").write_text(
        json.dumps(runtime_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    runtime_files = sum(1 for record in runtime_manifest["entries"].values()
                        if record["type"] == "file")
    common.write_complete(
        PAYLOAD_DIR, fingerprint=fingerprint,
        contents={"tests": len(entries), "files": runtime_files,
                  "busybox_sha256": common.sha256_file(busybox)})
    print("Staged %d tests (%d runtime files) in %s"
          % (len(entries), runtime_files, PAYLOAD_DIR))
    return 0


def verify(expected_fingerprint=None, directory=None) -> int:
    payload_dir = pathlib.Path(directory) if directory else PAYLOAD_DIR
    try:
        complete = common.verify_complete(payload_dir, expected_fingerprint)
        manifest_path = payload_dir / "runtime-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        common.verify_inventory(payload_dir, manifest)
    except (common.ManifestError, OSError, json.JSONDecodeError) as exc:
        raise PayloadError("runtime payload is invalid: %s" % exc)
    files = sum(1 for record in manifest["entries"].values()
                if record["type"] == "file")
    if complete["contents"].get("files") != files:
        raise PayloadError("completion record has the wrong runtime file count")
    print("Verified %d LTP runtime files in %s" % (files, payload_dir))
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if argv[:1] == ["fingerprint"] and set(argv[1:]) <= {"--no-sweep"}:
            print(payload_fingerprint(sweep="--no-sweep" not in argv))
            return 0
        if argv[:1] == ["verify"] and len(argv) <= 2:
            return verify(argv[1] if len(argv) == 2 else None)
        if set(argv) <= {"--force", "--no-sweep"} and len(argv) == len(set(argv)):
            return build(force="--force" in argv,
                         sweep="--no-sweep" not in argv)
        raise PayloadError("usage: ltp.py [--force] [--no-sweep] | "
                           "fingerprint [--no-sweep] | "
                           "verify [EXPECTED_FINGERPRINT]", exit_code=2)
    except PayloadError as exc:
        print("ltp payload: %s" % exc, file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    sys.exit(main())
