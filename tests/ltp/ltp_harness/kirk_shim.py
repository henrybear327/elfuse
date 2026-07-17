"""Launch kirk with the harness channel plugins pre-discovered.

Kirk validates --com channel names while parsing the command line, but
only discovers --plugins directories afterwards, so a custom channel can
never be selected through the plain CLI (kirk v4.1.0). This shim runs
inside the pinned kirk checkout's import space, registers the harness
plugin directory first, then hands the untouched argument list to kirk's
own entry point.

Usage: python3 kirk_shim.py KIRK_DIR PLUGINS_DIR [kirk args...]
"""

from __future__ import annotations

import sys


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: kirk_shim.py KIRK_DIR PLUGINS_DIR [kirk args...]",
            file=sys.stderr,
        )
        return 2

    kirk_dir, plugins_dir = sys.argv[1], sys.argv[2]
    sys.path.insert(0, kirk_dir)
    # Put the plugin directory on the path too so the channels can share a
    # sibling _common module regardless of how kirk's discover loads them.
    sys.path.insert(0, plugins_dir)

    import libkirk.com
    import libkirk.sut

    libkirk.com.discover(plugins_dir)
    libkirk.sut.discover(plugins_dir)

    from libkirk.main import run

    # Kirk's entry point ends with parser.exit(), so this call raises
    # SystemExit carrying kirk's own exit code.
    run(cmd_args=sys.argv[3:])
    return 0


if __name__ == "__main__":
    sys.exit(main())
