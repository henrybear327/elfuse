# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import unittest
from pathlib import Path

from conformance import gvisor, payload, providers, selection

REPO = Path(__file__).resolve().parents[3]

BUILD = '''
cc_library(
    name = "base_poll_test",
)

cc_binary(
    name = "access_test",
    testonly = 1,
)

cc_binary(
    name = "brand_new_test",
)
'''


class SelectionTest(unittest.TestCase):
    def setUp(self):
        self.provider = providers.make("gvisor", REPO)

    def test_selection_loads_and_scopes(self):
        selected = self.provider.selection
        self.assertEqual(selected.lint(), [])
        pr = [entry.group for entry in selected.groups("pr")]
        self.assertIn("open_test", pr)
        self.assertNotIn("aio_test", pr)
        self.assertTrue(set(pr) <= {
            entry.group for entry in selected.groups("full")
        })
        self.assertLess(len(pr), 40)
        self.assertEqual(selected.extra["qemu_mem_mib"], 6144)

    def test_pins_load(self):
        doc = payload.load_pins(
            self.provider.pins_path, self.provider.pins_schema
        )
        self.assertEqual(len(doc["gvisor"]["commit"]), 40)

    def test_parse_build_skips_libraries(self):
        self.assertEqual(
            gvisor.parse_build(BUILD), ["access_test", "brand_new_test"]
        )

    def test_compare(self):
        selected = selection.parse({
            "schema_version": 1,
            "enabled": [{"group": "access_test", "scope": "pr"}],
            "declined": [{"reason": "r", "groups": ["gone_test"]}],
        }, "t")
        errors = gvisor.compare(selected, gvisor.parse_build(BUILD))
        self.assertEqual(errors, [
            "gone_test vanished from the pinned BUILD; drop it from selection",
            "brand_new_test is new upstream; triage it into enabled or declined",
        ])

    def test_check_without_checkout(self):
        self.provider.checkout_dir = lambda commit: Path("/nonexistent") / commit
        problems = self.provider.regen_selection(check=True)
        self.assertEqual(len(problems), 1)
        self.assertIn("checkout is absent", problems[0])

    def test_latest_pin_shapes_the_section(self):
        calls = []

        def fake_get(url):
            calls.append(url)
            if url.endswith("/gvisor"):
                return {"default_branch": "master"}
            return {
                "sha": "b" * 40,
                "commit": {
                    "tree": {"sha": "c" * 40},
                    "committer": {"date": "2026-09-01T00:00:00Z"},
                    "message": "subject line\n\nbody",
                },
            }

        original = gvisor._get_json
        gvisor._get_json = fake_get
        try:
            doc = payload.load_pins(
                self.provider.pins_path, self.provider.pins_schema
            )
            new = self.provider.latest_pin(doc, None)
        finally:
            gvisor._get_json = original
        self.assertEqual(calls[0], "https://api.github.com/repos/google/gvisor")
        self.assertEqual(
            calls[1],
            "https://api.github.com/repos/google/gvisor/commits/master",
        )
        self.assertEqual(
            (
                new["gvisor"]["commit"],
                new["gvisor"]["tree"],
                new["gvisor"]["date"],
                new["gvisor"]["subject"],
            ),
            ("b" * 40, "c" * 40, "2026-09-01", "subject line"),
        )
        payload.check_pins(new, self.provider.pins_schema)


if __name__ == "__main__":
    unittest.main()
