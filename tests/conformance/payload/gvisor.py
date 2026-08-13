"""Build the pinned gVisor syscall test payload.

Acquisition is git: clone with --filter=blob:none, fetch the pinned
commit, and verify both the commit and its tree hash from pins.json (a
commit is already a content address; GitHub's generated archives are not
byte-stable, so there is no tarball digest to verify instead). The build
runs Bazel directly in one batched invocation on Linux; macOS goes
through gVisor's supported Docker wrapper, where the Bazel cache must
live in a Docker volume (a bind-mounted cache breaks Bazel's
linux-sandbox on virtiofs), so artifacts are extracted from the build
container with docker cp. make build and make copy resolve TARGETS
through one Bazel cquery expression, hence the per-target loop there.
Every artifact is validated by elfcheck and recorded in manifest.json
(per-binary sha256), so a lane can verify the payload survived artifact
transport.

Runs standalone (python3 tests/conformance/payload/gvisor.py [--force] or
verify [EXPECTED_FINGERPRINT]): exit 0 built, complete, or verified;
1 build or validation failure; 2 configuration error.
"""

from __future__ import annotations

import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile

_PACKAGE_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_PACKAGE_DIR.parents[1]))

from conformance import audit, pins
from conformance.payload import common, elfcheck

REPO_ROOT = _PACKAGE_DIR.parents[2]
BAZEL_OPTIONS = "--config=aarch64 -c opt --linkopt=-static " \
                "--linkopt=-Wl,--eh-frame-hdr"
_GNUBIN = pathlib.Path("/opt/homebrew/opt/findutils/libexec/gnubin")


class PayloadError(Exception):
    def __init__(self, message, exit_code=1):
        super().__init__(message)
        self.exit_code = exit_code


def _run(argv, **kwargs):
    result = subprocess.run(argv, **kwargs)
    if result.returncode != 0:
        raise PayloadError("command failed (%d): %s"
                           % (result.returncode, " ".join(map(str, argv))))
    return result


def enabled_binaries() -> list:
    enabled, _ = audit.load_roster()
    return sorted(label.split(":")[-1] for label in enabled)


def payload_fingerprint(doc=None) -> str:
    doc = doc or pins.load()
    return common.fingerprint(
        pin_section=doc["gvisor"],
        files=[audit.ROSTER_PATH, _PACKAGE_DIR / "gvisor.py",
               _PACKAGE_DIR / "elfcheck.py", _PACKAGE_DIR / "common.py"],
        flavor="static-aarch64")


def install_dir(doc) -> pathlib.Path:
    return REPO_ROOT / "externals" / "payloads" / "gvisor" / \
        doc["gvisor"]["commit"]


def acquire(doc) -> pathlib.Path:
    section = doc["gvisor"]
    checkout = pathlib.Path(
        os.environ.get("GVISOR_CHECKOUT")
        or audit.checkout_dir(section["commit"]))
    if not (checkout / ".git").exists():
        if checkout.exists():
            raise PayloadError(
                "checkout path exists but is not a git checkout: %s"
                % checkout, exit_code=2)
        checkout.parent.mkdir(parents=True, exist_ok=True)
        print("Cloning gVisor into %s (explicit opt-in network operation)"
              % checkout)
        _run(["git", "clone", "--filter=blob:none", section["repository"],
              str(checkout)])
    status = _run(["git", "-C", str(checkout), "status", "--porcelain"],
                  capture_output=True, text=True).stdout
    if status.strip():
        raise PayloadError("refusing to alter dirty checkout: %s" % checkout,
                           exit_code=2)
    have = subprocess.run(
        ["git", "-C", str(checkout), "cat-file", "-e",
         section["commit"] + "^{commit}"], capture_output=True)
    if have.returncode != 0:
        _run(["git", "-C", str(checkout), "fetch", "origin",
              section["commit"]])
    _run(["git", "-C", str(checkout), "checkout", "--detach",
          section["commit"]])
    for spec, want in (("HEAD", section["commit"]),
                       ("HEAD^{tree}", section["tree"])):
        got = _run(["git", "-C", str(checkout), "rev-parse", spec],
                   capture_output=True, text=True).stdout.strip()
        if got != want:
            raise PayloadError(
                "checkout %s resolved to %s, pins.json records %s"
                % (spec, got, want), exit_code=2)
    return checkout


def _container_name(checkout) -> str:
    import hashlib
    real = _run(["python3", str(checkout / "tools/compat/realpath.py"),
                 str(checkout)], capture_output=True, text=True).stdout
    hash8 = hashlib.md5(real.encode("utf-8")).hexdigest()[:8]
    return "gvisor-bazel-%s-%s" % (hash8, platform.machine())


def _build_linux(checkout, labels, staging) -> None:
    bazel = shutil.which("bazelisk") or shutil.which("bazel")
    if not bazel:
        raise PayloadError("bazel or bazelisk is required on Linux",
                           exit_code=2)
    _run([bazel, "build", *BAZEL_OPTIONS.split(), *labels],
         cwd=str(checkout))
    files = _run(
        [bazel, "cquery", *BAZEL_OPTIONS.split(),
         "set(%s)" % " ".join(labels), "--output=files"],
        cwd=str(checkout), capture_output=True, text=True).stdout.split()
    by_name = {pathlib.Path(f).name: pathlib.Path(f) for f in files}
    for label in labels:
        name = label.split(":")[-1]
        if name not in by_name:
            raise PayloadError("bazel cquery lists no output for %s" % label)
        shutil.copy2(checkout / by_name[name], staging / name)


def _build_darwin(checkout, labels, staging) -> None:
    # gVisor's build_paths pipeline ends in host-side xargs stages that
    # assume GNU semantics; BSD xargs caps -I replacements at 255 bytes.
    env = dict(os.environ)
    if _GNUBIN.is_dir():
        env["PATH"] = "%s:%s" % (_GNUBIN, env.get("PATH", ""))
    probe = subprocess.run(["xargs", "--version"], capture_output=True,
                           text=True, env=env)
    if "GNU" not in probe.stdout:
        raise PayloadError(
            "GNU xargs is required on macOS: brew install findutils",
            exit_code=2)
    if not shutil.which("docker"):
        raise PayloadError("docker is required for the macOS build",
                           exit_code=2)
    for label in labels:
        _run(["make", "-C", str(checkout), "build", "DOCKER_BUILD=true",
              "BAZEL_OPTIONS=" + BAZEL_OPTIONS, "TARGETS=" + label], env=env)
    container = _container_name(checkout)
    _run(["docker", "inspect", container], capture_output=True)
    cache_glob = ("$HOME/.cache/bazel/_bazel_$(whoami)/*/execroot/*/"
                  "bazel-out/*/bin/test/syscalls/linux")
    for label in labels:
        name = label.split(":")[-1]
        listing = _run(
            ["docker", "exec", container, "sh", "-c",
             "ls -1 %s/%s" % (cache_glob, name)],
            capture_output=True, text=True).stdout.strip().splitlines()
        if len(listing) != 1:
            raise PayloadError(
                "ambiguous Bazel outputs for %s: %r" % (name, listing))
        _run(["docker", "cp", "%s:%s" % (container, listing[0]),
              str(staging / name)])


def build(force=False) -> int:
    doc = pins.load()
    dest = install_dir(doc)
    fingerprint = payload_fingerprint(doc)
    if not force and common.is_complete(dest, fingerprint):
        print("gVisor payload is complete at %s" % dest)
        return 0
    checkout = acquire(doc)
    names = enabled_binaries()
    labels = ["//test/syscalls/linux:%s" % n for n in names]
    with tempfile.TemporaryDirectory() as tmp:
        staging = pathlib.Path(tmp)
        if platform.system() == "Darwin":
            _build_darwin(checkout, labels, staging)
        else:
            _build_linux(checkout, labels, staging)
        manifest = {}
        for name in names:
            binary = staging / name
            if not binary.is_file():
                raise PayloadError("expected artifact was not produced: %s"
                                   % name)
            binary.chmod(0o755)
            try:
                elfcheck.validate_static_aarch64(binary)
            except elfcheck.ElfCheckError as exc:
                raise PayloadError(str(exc))
            manifest[name] = {"sha256": common.sha256_file(binary),
                              "size": binary.stat().st_size}
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True, exist_ok=True)
        for name in names:
            shutil.copy2(staging / name, dest / name)
            (dest / name).chmod(0o755)
    (dest / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    common.write_complete(dest, fingerprint=fingerprint,
                          contents={"binaries": len(names)})
    print("Installed %d validated binaries in %s" % (len(names), dest))
    return 0


def verify(expected_fingerprint=None, directory=None) -> int:
    doc = pins.load()
    dest = pathlib.Path(directory) if directory else install_dir(doc)
    try:
        complete = common.verify_complete(dest, expected_fingerprint)
        manifest_path = dest / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (common.ManifestError, OSError, json.JSONDecodeError) as exc:
        raise PayloadError("payload metadata is invalid: %s" % exc)
    names = enabled_binaries()
    if sorted(manifest) != names:
        raise PayloadError(
            "manifest binary set differs from the enabled roster")
    allowed = set(names) | {"manifest.json", common.COMPLETE_NAME}
    actual = {path.name for path in dest.iterdir()}
    if actual != allowed:
        raise PayloadError(
            "payload file set differs from its manifest (missing=%r, extra=%r)"
            % (sorted(allowed - actual), sorted(actual - allowed)))
    for name in names:
        binary = dest / name
        record = manifest[name]
        if binary.is_symlink() or not binary.is_file():
            raise PayloadError("manifest binary is not a regular file: %s"
                               % name)
        if binary.stat().st_mode & 0o111 != 0o111:
            raise PayloadError("manifest binary is not executable: %s" % name)
        if record != {"sha256": common.sha256_file(binary),
                      "size": binary.stat().st_size}:
            raise PayloadError("manifest mismatch for binary: %s" % name)
        try:
            elfcheck.validate_static_aarch64(binary)
        except elfcheck.ElfCheckError as exc:
            raise PayloadError(str(exc))
    if complete["contents"].get("binaries") != len(names):
        raise PayloadError("completion record has the wrong binary count")
    print("Verified %d gVisor binaries in %s" % (len(names), dest))
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv == ["fingerprint"]:
        print(payload_fingerprint())
        return 0
    try:
        if argv[:1] == ["verify"] and len(argv) <= 2:
            return verify(argv[1] if len(argv) == 2 else None)
        if not argv or argv == ["--force"]:
            return build(force=argv == ["--force"])
        raise PayloadError("usage: gvisor.py [--force] | fingerprint | "
                           "verify [EXPECTED_FINGERPRINT]", exit_code=2)
    except PayloadError as exc:
        print("gvisor payload: %s" % exc, file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    sys.exit(main())
