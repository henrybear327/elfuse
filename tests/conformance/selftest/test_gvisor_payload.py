# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from conformance import payload, providers
from conformance.gvisor import build as builder
from conformance.selftest.test_elfcheck import elf

REPO = Path(__file__).resolve().parents[3]


class GvisorPayloadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        upstream = self.dir / "upstream"
        (upstream / "test/syscalls/linux").mkdir(parents=True)
        (upstream / "test/syscalls/linux/BUILD").write_text('cc_binary(\n    name = "a_test",\n)\n')
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_NAME="t",
                   GIT_COMMITTER_EMAIL="t@x")
        for argv in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "pin"]):
            subprocess.run(["git", "-C", str(upstream)] + argv, check=True, env=env)
        commit = subprocess.run(["git", "-C", str(upstream), "rev-parse", "HEAD"], check=True,
                                capture_output=True, text=True).stdout.strip()
        tree = subprocess.run(["git", "-C", str(upstream), "rev-parse", "HEAD^{tree}"], check=True,
                              capture_output=True, text=True).stdout.strip()
        self.section = {"repository": str(upstream), "commit": commit, "tree": tree,
                        "date": "2026-01-01", "subject": "pin"}
        bazel = self.dir / "bin" / "bazel"
        bazel.parent.mkdir()
        bazel.write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            '  build) mkdir -p bazel-bin/test/syscalls/linux; for l; do case "$l" in *:b_test) ;; //*) '
            'python3 -c "import sys; sys.path.insert(0, %r); '
            'from conformance.selftest.test_elfcheck import elf; '
            "open('bazel-bin/test/syscalls/linux/' + sys.argv[1], 'wb').write(elf())\" ${l##*:};; esac; done ;;\n"
            "  cquery) ls bazel-bin/test/syscalls/linux/* ;;\n"
            "esac\n" % str(REPO / "tests"))
        bazel.chmod(bazel.stat().st_mode | stat.S_IXUSR)
        os.environ["PATH"] = "%s:%s" % (bazel.parent, os.environ["PATH"])
        self.checkout = self.dir / "checkout"
        self.root = self.dir / "payload"

    def tearDown(self):
        os.environ["PATH"] = os.environ["PATH"].split(":", 1)[1]
        self.tmp.cleanup()

    def test_build_stages_and_verifies(self):
        built = builder.build(self.section, self.checkout, self.root, ["a_test"], "f" * 64, system="Linux")
        self.assertTrue(built)
        binary = self.root / "bin" / "a_test"
        self.assertTrue(os.access(binary, os.X_OK))
        doc = payload.verify(self.root, "f" * 64)
        self.assertEqual(doc["extra"], {"commit": self.section["commit"], "binaries": 1})
        self.assertFalse(builder.build(self.section, self.checkout, self.root, ["a_test"], "f" * 64, system="Linux"))
        self.assertTrue(builder.build(self.section, self.checkout, self.root, ["a_test"], "0" * 64, system="Linux"))

    def test_wrong_tree_is_refused(self):
        bad = dict(self.section, tree="0" * 40)
        with self.assertRaises(payload.PayloadError) as cm:
            builder.build(bad, self.checkout, self.root, ["a_test"], "f" * 64, system="Linux")
        self.assertEqual(cm.exception.kind, "config")

    def test_missing_artifact_is_an_error(self):
        with self.assertRaises(payload.PayloadError) as cm:
            builder.build(self.section, self.checkout, self.root, ["a_test", "b_test"], "f" * 64, system="Linux")
        self.assertIn("no output for b_test", str(cm.exception))


class ProviderPayloadTest(unittest.TestCase):
    def test_fingerprint_follows_selection(self):
        provider = providers.make("gvisor", REPO)
        fp = provider.fingerprint()
        self.assertRegex(fp, r"^[0-9a-f]{64}$")
        self.assertEqual(fp, providers.make("gvisor", REPO).fingerprint())

    def test_prerequisites_name_the_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            provider = providers.make("gvisor", REPO)
            provider.payload_root = lambda: Path(tmp) / "none"
            msg = provider.prerequisites("elfuse")
            self.assertIn("gvisor payload missing", msg)
            self.assertIn("run: make gvisor-payload", msg)
            corrupt = Path(tmp) / "corrupt"
            corrupt.mkdir()
            (corrupt / payload.MANIFEST).write_text("{}")
            provider.payload_root = lambda: corrupt
            self.assertIsNone(provider.prerequisites("elfuse"))
        self.assertEqual(provider.backend_options("qemu"), {"mem_mib": 6144})


if __name__ == "__main__":
    unittest.main()
