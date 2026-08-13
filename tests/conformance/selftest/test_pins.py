"""Selftests for the pin file loader.

pins.json is the single source of upstream versions; CI reads values
through pins.lookup(), so nothing ever re-derives a pin by pattern
matching shell source. The tests pin the validation: every required field
present, digests and commits shaped like digests and commits, and dotted
lookup failing loudly on an unknown path. The committed pins.json itself
must load. Code under test: tests/conformance/pins.py.
"""

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from conformance import pins

VALID = {
    "schema_version": 1,
    "gvisor": {
        "repository": "https://github.com/google/gvisor.git",
        "commit": "c" * 40,
        "tree": "7" * 40,
        "date": "2026-07-15",
        "subject": "s",
    },
    "ltp": {
        "project": "linux-test-project/ltp",
        "release": "20260529",
        "commit": "3" * 40,
        "archive_url": "https://example.com/ltp.tar.xz",
        "archive_sha256": "6" * 64,
        "sha256_url": "https://example.com/ltp.tar.xz.sha256",
        "source_date_epoch": 1780048197,
    },
    "kirk": {
        "project": "linux-test-project/kirk",
        "tag": "v4.1.0",
        "archive_url": "https://example.com/kirk.tar.gz",
        "archive_sha256": "d" * 64,
    },
    "license_boundary": "external GPL-covered fixtures",
}


class LoadTest(unittest.TestCase):
    def load_doc(self, doc):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as fh:
            json.dump(doc, fh)
        self.addCleanup(pathlib.Path(fh.name).unlink)
        return pins.load(fh.name)

    def test_valid_document(self):
        doc = self.load_doc(VALID)
        self.assertEqual(doc["kirk"]["tag"], "v4.1.0")

    def assert_pin_error(self, doc, fragment):
        with self.assertRaises(pins.PinError) as ctx:
            self.load_doc(doc)
        self.assertIn(fragment, str(ctx.exception))

    def test_missing_field_named(self):
        doc = json.loads(json.dumps(VALID))
        del doc["ltp"]["archive_sha256"]
        self.assert_pin_error(doc, "ltp.archive_sha256")

    def test_unknown_schema_version(self):
        doc = json.loads(json.dumps(VALID))
        doc["schema_version"] = 2
        self.assert_pin_error(doc, "schema_version")

    def test_digest_shape(self):
        doc = json.loads(json.dumps(VALID))
        doc["kirk"]["archive_sha256"] = "not-a-digest"
        self.assert_pin_error(doc, "kirk.archive_sha256")

    def test_commit_shape(self):
        doc = json.loads(json.dumps(VALID))
        doc["gvisor"]["commit"] = "c30a"
        self.assert_pin_error(doc, "gvisor.commit")

    def test_committed_pins_load(self):
        doc = pins.load()
        self.assertEqual(len(doc["gvisor"]["commit"]), 40)
        self.assertEqual(len(doc["gvisor"]["tree"]), 40)


class LookupTest(unittest.TestCase):
    def test_dotted_lookup(self):
        self.assertEqual(pins.lookup(VALID, "gvisor.commit"), "c" * 40)
        self.assertEqual(pins.lookup(VALID, "ltp.source_date_epoch"),
                         1780048197)

    def test_unknown_path_rejected(self):
        with self.assertRaises(pins.PinError):
            pins.lookup(VALID, "gvisor.branch")


if __name__ == "__main__":
    unittest.main()
