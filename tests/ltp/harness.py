#!/usr/bin/env python3
"""Entry point for the LTP conformance harness.

Everything lives in the ltp_harness package next to this file; this
wrapper only makes "python3 tests/ltp/harness.py" work from any cwd.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ltp_harness.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
