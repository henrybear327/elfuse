"""Cross-file timeout-layering invariants.

The QEMU supervisor's post-deadline cleanup budget lives in C, kirk's
extra slack lives in kirkdrive.py, and the channel cap above that; these
tests parse the C constants so the inequality cannot silently rot when
either file changes.
"""

from __future__ import annotations

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ltp_harness import kirkdrive  # noqa: E402

LTP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(os.path.dirname(LTP_DIR))
SUPERVISOR_C = os.path.join(LTP_DIR, "helpers", "qemu-supervisor.c")
PROCEMU_C = os.path.join(REPO_ROOT, "src", "runtime", "procemu.c")
ELFUSE_CHAN = os.path.join(LTP_DIR, "plugins", "elfuse_chan.py")


def c_constant(source: str, name: str) -> int:
    match = re.search(rf"#define {name} (\d+)", source)
    if not match:
        raise AssertionError(f"{name} not found in qemu-supervisor.c")
    return int(match.group(1))


class TimeoutLayeringTest(unittest.TestCase):
    def test_supervisor_budget_fits_under_kirk_exec_slack(self):
        with open(SUPERVISOR_C, "r", encoding="utf-8") as handle:
            source = handle.read()

        budget = (
            c_constant(source, "TERM_GRACE_SEC")
            + c_constant(source, "KILL_WAIT_SEC")
            + c_constant(source, "REAP_POLL_SEC")
            + 1
        )
        self.assertLess(
            budget,
            kirkdrive.QEMU_EXEC_SLACK_SEC,
            "supervisor cleanup budget must finish before kirk cancels",
        )

    def test_kirk_cancels_before_channel_cap(self):
        self.assertLess(
            kirkdrive.QEMU_EXEC_SLACK_SEC,
            kirkdrive.CHANNEL_CAP_SLACK_SEC,
            "kirk's exec-timeout must fire before the channel SSH cap",
        )


class ShmBackingPathTest(unittest.TestCase):
    def test_channel_matches_procemu_backing_dir(self):
        # The elfuse channel sweeps elfuse's /dev/shm backing directory;
        # both files spell the per-UID path independently, so pin them
        # to each other here.
        with open(PROCEMU_C, "r", encoding="utf-8") as handle:
            self.assertIn('"/tmp/elfuse-shm-%u"', handle.read())
        with open(ELFUSE_CHAN, "r", encoding="utf-8") as handle:
            self.assertIn('f"/tmp/elfuse-shm-{os.getuid()}"', handle.read())


if __name__ == "__main__":
    unittest.main()
