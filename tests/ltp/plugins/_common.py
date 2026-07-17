"""Shared guest contract for the two kirk communication channels.

The elfuse and qemuchroot channels present kirk's LTP framework with the
same target: the canonical guest PATH, the case-launcher fork wrapper,
LTP_/TST_ environment forwarding, and the one busybox ls rewrite. Those
live here so the two channels cannot drift apart.
"""

from __future__ import annotations

from typing import Dict, Optional

GUEST_PATH = "/opt/ltp/testcases/bin:/usr/bin:/bin"
LAUNCHER = "/opt/elfuse-ltp/bin/case-launcher"

# Environment names forwarded from the framework env into the guest.
FORWARD_PREFIXES = ("LTP_", "TST_")


def rewrite_command(command: str) -> str:
    """Adapt the one GNU-only command kirk's LTP framework issues.

    Kirk lists runtest files with "ls --format=single-column", which
    busybox ls does not know; -1 is the portable spelling.
    """
    return command.replace("ls --format=single-column", "ls -1")


def guest_environment(
    env: Optional[Dict[str, str]], scratch: str
) -> Dict[str, str]:
    """The complete guest environment for one command.

    The framework's env carries host-side PATH pollution (kirk appends
    the testcases directory to the host PATH), so PATH is rebuilt from
    the canonical guest value and only LTP_*/TST_* names are forwarded.
    """
    guest_env = {
        "LTPROOT": "/opt/ltp",
        "PATH": GUEST_PATH,
        "TMPDIR": scratch,
        "HOME": scratch,
        "LC_ALL": "C",
        "TZ": "UTC",
        "LTP_COLORIZE_OUTPUT": "0",
    }
    for key, value in (env or {}).items():
        if key.startswith(FORWARD_PREFIXES) and key != "LTP_COLORIZE_OUTPUT":
            guest_env[key] = value
    return guest_env
