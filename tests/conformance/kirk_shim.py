"""Launch kirk with the harness channel plugins pre-discovered.

Kirk validates --com channel names while parsing the command line, but
only discovers --plugins directories afterwards, so a custom channel can
never be selected through the plain CLI (kirk v4.1.0). This shim runs
inside the pinned kirk checkout's import space, registers the harness
plugin directory first, then hands the untouched argument list to kirk's
own entry point. The tests/ directory joins sys.path so the channels
can import the conformance package (shared ssh options, backends).

Usage: python3 kirk_shim.py KIRK_DIR [kirk args...]
"""

from __future__ import annotations

import pathlib
import sys

PLUGINS_DIR = pathlib.Path(__file__).resolve().parent / "kirk_plugins"
TESTS_DIR = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: kirk_shim.py KIRK_DIR [kirk args...]", file=sys.stderr)
        return 2
    sys.path.insert(0, sys.argv[1])
    sys.path.insert(0, str(TESTS_DIR))
    sys.path.insert(0, str(PLUGINS_DIR))

    import libkirk.com
    import libkirk.sut

    libkirk.com.discover(str(PLUGINS_DIR))
    libkirk.sut.discover(str(PLUGINS_DIR))

    from libkirk.main import run

    # Kirk's entry point ends with parser.exit(), so this call raises
    # SystemExit carrying kirk's own exit code.
    run(cmd_args=sys.argv[2:])
    return 0


if __name__ == "__main__":
    sys.exit(main())
