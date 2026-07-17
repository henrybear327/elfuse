"""LTP syscall-conformance harness for elfuse.

The harness drives pinned LTP test binaries through kirk (LTP's official
runner) on two backends, a QEMU Linux reference and elfuse itself, and
gates elfuse results against recorded per-subtest baselines. See
docs/ltp-conformance.md for the full design.
"""

from __future__ import annotations

# Exit-code contract shared by every subcommand. EXIT_SKIP follows the
# rc-77 convention consumed by RUN_LTP_TARGET in mk/tests.mk.
EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_SKIP = 77
