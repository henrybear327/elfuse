# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from conformance import elfcheck, payload

BAZEL_OPTIONS = ["--config=aarch64", "-c", "opt", "--linkopt=-static", "--linkopt=-Wl,--eh-frame-hdr"]
_GNUBIN = Path("/opt/homebrew/opt/findutils/libexec/gnubin")
FLAVOR = "static-aarch64"


def _run(argv: List[str], **kw: Any) -> subprocess.CompletedProcess:
    done = subprocess.run(argv, **kw)
    if done.returncode != 0:
        raise payload.PayloadError("build", "command failed (%d): %s" % (done.returncode, " ".join(map(str, argv))))
    return done


def _git(checkout: Path, *args: str, capture: bool = False) -> str:
    done = _run(["git", "-C", str(checkout), *args],
                stdout=subprocess.PIPE if capture else None, text=True)
    return done.stdout.strip() if capture else ""


def acquire(section: Dict[str, str], checkout: Path) -> Path:
    fresh = not (checkout / ".git").exists()
    if fresh:
        checkout.parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "clone", "--filter=blob:none", "--no-checkout", section["repository"], str(checkout)])
    if not fresh and _git(checkout, "status", "--porcelain", "--untracked-files=no", capture=True):
        raise payload.PayloadError("config", "refusing to alter a dirty checkout: %s" % checkout)
    if subprocess.run(["git", "-C", str(checkout), "cat-file", "-e", section["commit"] + "^{commit}"],
                      capture_output=True).returncode != 0:
        _git(checkout, "fetch", "origin", section["commit"])
    _git(checkout, "checkout", "--detach", "--quiet", section["commit"])
    for spec, want in (("HEAD", section["commit"]), ("HEAD^{tree}", section["tree"])):
        got = _git(checkout, "rev-parse", spec, capture=True)
        if got != want:
            raise payload.PayloadError("config", "checkout %s is %s, pins.json records %s" % (spec, got, want))
    return checkout


def build_linux(checkout: Path, names: List[str], staging: Path) -> None:
    bazel = shutil.which("bazelisk") or shutil.which("bazel")
    if not bazel:
        raise payload.PayloadError("config", "bazel or bazelisk is required on Linux")
    labels = ["//test/syscalls/linux:%s" % n for n in names]
    _run([bazel, "build", *BAZEL_OPTIONS, *labels], cwd=str(checkout))
    files = _run([bazel, "cquery", *BAZEL_OPTIONS, "set(%s)" % " ".join(labels), "--output=files"],
                 cwd=str(checkout), stdout=subprocess.PIPE, text=True).stdout.split()
    by_name = {Path(f).name: Path(f) for f in files}
    for name in names:
        if name not in by_name:
            raise payload.PayloadError("build", "bazel cquery lists no output for %s" % name)
        shutil.copy2(checkout / by_name[name], staging / name)


def _container_name(checkout: Path) -> str:
    real = _run(["python3", str(checkout / "tools/compat/realpath.py"), str(checkout)],
                stdout=subprocess.PIPE, text=True).stdout
    return "gvisor-bazel-%s-%s" % (hashlib.md5(real.encode()).hexdigest()[:8], platform.machine())


def build_darwin(checkout: Path, names: List[str], staging: Path) -> None:
    """Build one label set inside gVisor's Bazel container.

    The upstream target passes multiple labels to a single-label cquery.
    docker exec cat follows bazel-out where docker cp does not.
    """
    env = dict(os.environ)
    if _GNUBIN.is_dir():
        env["PATH"] = "%s:%s" % (_GNUBIN, env.get("PATH", ""))
    if not shutil.which("docker"):
        raise payload.PayloadError("config", "docker is required for the macOS build")
    _run(["make", "-C", str(checkout), "bazel-server", "DOCKER_BUILD=true"], env=env,
         stdout=subprocess.DEVNULL)
    execute = ["docker", "exec", "--user", "%d:%d" % (os.getuid(), os.getgid()),
               "-w", str(checkout), _container_name(checkout)]
    labels = ["//test/syscalls/linux:%s" % n for n in names]
    _run(execute + ["bazel", "build", *BAZEL_OPTIONS, *labels])
    files = _run(execute + ["bazel", "cquery", *BAZEL_OPTIONS, "set(%s)" % " ".join(labels),
                            "--output=files"], stdout=subprocess.PIPE, text=True).stdout.split()
    by_name = {Path(f).name: f for f in files}
    for name in names:
        if name not in by_name:
            raise payload.PayloadError("build", "bazel cquery lists no output for %s" % name)
        with open(staging / name, "wb") as out:
            _run(execute + ["cat", by_name[name]], stdout=out)


def stage(staging: Path, root: Path, names: List[str], fp: str, extra: Dict[str, Any]) -> None:
    for name in names:
        binary = staging / name
        if not binary.is_file():
            raise payload.PayloadError("build", "expected artifact was not produced: %s" % name)
        elfcheck.validate_static_aarch64(binary)
    if root.exists():
        shutil.rmtree(root)
    (root / "bin").mkdir(parents=True)
    for name in names:
        shutil.copy2(staging / name, root / "bin" / name)
        (root / "bin" / name).chmod(0o755)
    payload.write_manifest(root, fp, dict(extra, binaries=len(names)))


def build(section: Dict[str, str], checkout: Path, root: Path, names: List[str], fp: str,
          force: bool = False, system: Optional[str] = None) -> bool:
    """Return False when the payload already matches the fingerprint."""
    if not force and payload.status(root, fp) == "ok":
        return False
    acquire(section, checkout)
    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp)
        if (system or platform.system()) == "Darwin":
            build_darwin(checkout, names, staging)
        else:
            build_linux(checkout, names, staging)
        stage(staging, root, names, fp, {"commit": section["commit"]})
    return True
