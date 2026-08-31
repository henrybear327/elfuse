# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

# kirk validates --com before loading --plugins, so discover channels first.
# Keep plugins separate because discovery imports every Python file.

import os
import sys

kirk_dir = sys.argv[1]
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(here, "..", "..", ".."))
sys.path.insert(0, kirk_dir)

import libkirk.com  # noqa: E402
import libkirk.main  # noqa: E402

libkirk.com.discover(os.path.join(here, "plugins"))
libkirk.main.run(cmd_args=sys.argv[2:])
