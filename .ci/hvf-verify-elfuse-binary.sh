#!/usr/bin/env bash

# Restore the execute bit on an elfuse binary and check the HVF entitlement.
# Mach-O signatures travel inside the file, so a downloaded artifact keeps its
# entitlement and loses only the mode bits.
#
# Usage: hvf-verify-elfuse-binary.sh [path] (default build/elfuse)

set -euo pipefail

bin=${1:-build/elfuse}
chmod +x "$bin"

# No grep -q: it exits at the first match, codesign takes SIGPIPE, and pipefail
# turns that 141 into a failure of a check that passed.
if ! codesign -d --entitlements - "$bin" 2>&1 \
    | grep 'com\.apple\.security\.hypervisor' > /dev/null; then
    echo "$bin does not embed com.apple.security.hypervisor;" \
        "HVF guest boot would fail at runtime" >&2
    exit 1
fi
