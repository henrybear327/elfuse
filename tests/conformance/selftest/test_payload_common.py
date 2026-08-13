"""Selftests for payload fingerprints and completion records.

The fingerprint is the freshness mechanism and the CI cache key: it
hashes the pin section, the data files, and the builder sources
themselves, so a recipe edit invalidates caches without a manual salt
bump, and it never consults mtimes (make 3.81 compares whole seconds).
Code under test: tests/conformance/payload/common.py.
"""

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest
from unittest import mock

from conformance.payload import common, gvisor


class FingerprintTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        (self.root / "data.jsonc").write_text("data-v1", encoding="utf-8")
        (self.root / "builder.py").write_text("code-v1", encoding="utf-8")

    def fingerprint(self):
        return common.fingerprint(
            pin_section={"commit": "c" * 40},
            files=[self.root / "data.jsonc", self.root / "builder.py"],
            flavor="static-aarch64")

    def test_stable_across_calls(self):
        self.assertEqual(self.fingerprint(), self.fingerprint())

    def test_changes_with_pin(self):
        base = self.fingerprint()
        other = common.fingerprint(
            pin_section={"commit": "d" * 40},
            files=[self.root / "data.jsonc", self.root / "builder.py"],
            flavor="static-aarch64")
        self.assertNotEqual(base, other)

    def test_changes_with_builder_source(self):
        base = self.fingerprint()
        (self.root / "builder.py").write_text("code-v2", encoding="utf-8")
        self.assertNotEqual(base, self.fingerprint())

    def test_changes_with_flavor(self):
        base = self.fingerprint()
        other = common.fingerprint(
            pin_section={"commit": "c" * 40},
            files=[self.root / "data.jsonc", self.root / "builder.py"],
            flavor="sweep")
        self.assertNotEqual(base, other)


class CompleteTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_roundtrip(self):
        common.write_complete(self.root, fingerprint="f" * 64,
                              contents={"binaries": 128})
        self.assertTrue(common.is_complete(self.root, "f" * 64))
        self.assertFalse(common.is_complete(self.root, "0" * 64))

    def test_absent_or_corrupt_is_incomplete(self):
        self.assertFalse(common.is_complete(self.root, "f" * 64))
        (self.root / common.COMPLETE_NAME).write_text("not json",
                                                      encoding="utf-8")
        self.assertFalse(common.is_complete(self.root, "f" * 64))

    def test_verify_rejects_wrong_expected_fingerprint(self):
        common.write_complete(self.root, fingerprint="f" * 64,
                              contents={"binaries": 1})
        with self.assertRaises(common.ManifestError):
            common.verify_complete(self.root, "0" * 64)


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        tree = self.root / "rootfs"
        (tree / "bin").mkdir(parents=True)
        binary = tree / "bin" / "tool"
        binary.write_bytes(b"payload")
        binary.chmod(0o755)
        (tree / "bin" / "alias").symlink_to("tool")

    def test_roundtrip_checks_files_modes_and_symlinks(self):
        manifest = common.inventory(self.root, ["rootfs"])
        common.verify_inventory(self.root, manifest)
        (self.root / "rootfs" / "bin" / "tool").write_bytes(b"tampered")
        with self.assertRaises(common.ManifestError) as ctx:
            common.verify_inventory(self.root, manifest)
        self.assertIn("changed", str(ctx.exception))

    def test_extra_runtime_file_is_rejected(self):
        manifest = common.inventory(self.root, ["rootfs"])
        (self.root / "rootfs" / "extra").write_text("x", encoding="utf-8")
        with self.assertRaises(common.ManifestError) as ctx:
            common.verify_inventory(self.root, manifest)
        self.assertIn("extra", str(ctx.exception))

    def test_runtime_roots_cannot_escape_payload(self):
        with self.assertRaises(common.ManifestError):
            common.inventory(self.root, ["../outside"])


class GvisorVerifyTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.binary = self.root / "syscall-test"
        self.binary.write_bytes(b"binary")
        self.binary.chmod(0o755)
        manifest = {
            "syscall-test": {"sha256": common.sha256_file(self.binary),
                             "size": self.binary.stat().st_size},
        }
        (self.root / "manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8")
        common.write_complete(self.root, fingerprint="f" * 64,
                              contents={"binaries": 1})

    def verify(self):
        with mock.patch.object(gvisor, "enabled_binaries",
                               return_value=["syscall-test"]), \
                mock.patch.object(gvisor.elfcheck,
                                  "validate_static_aarch64"):
            return gvisor.verify(directory=self.root)

    def test_complete_payload_verifies(self):
        self.assertEqual(self.verify(), 0)

    def test_binary_tampering_is_rejected(self):
        self.binary.write_bytes(b"changed")
        with self.assertRaises(gvisor.PayloadError):
            self.verify()


if __name__ == "__main__":
    unittest.main()
