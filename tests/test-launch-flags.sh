#!/usr/bin/env bash
# test-launch-flags.sh -- Pin the rejection rules of the guest launch flags
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Usage: tests/test-launch-flags.sh <elfuse-binary> <guest-elf>
#
# --user, --workdir, and --env select the guest identity, cwd, and
# environment. Each rejects a contradictory request during option parsing,
# before any VM is created, so a launcher (`elfuse-oci run` above all) gets a
# diagnostic instead of a guest that silently runs as something other than
# what was asked for.
#
# The --fakeroot lane covers a privilege-model rule rather than a typo:
# fakeroot means the guest starts as uid/gid 0, and the setuid permission
# check grants every id switch on that basis. Pairing it with a non-root
# --user left that grant in place while the guest reported an unprivileged
# uid, so the guest could call setuid(0) at will. The other lanes are
# regression guards for parse rules that already held.

set -euo pipefail

ELFUSE="${1:?Usage: $0 <elfuse-binary> <guest-elf>}"
GUEST="${2:?Usage: $0 <elfuse-binary> <guest-elf>}"

fail=0

# Asserts elfuse exits nonzero and says why, without starting a guest.
reject()
{
    local desc="$1" want="$2"
    shift 2
    local out status=0
    out="$("$ELFUSE" "$@" "$GUEST" 2>&1)" || status=$?
    if [ "$status" -eq 0 ]; then
        printf '[ FAIL ] %s: accepted (exit 0), want rejection\n' "$desc"
        fail=1
        return
    fi
    if ! printf '%s' "$out" | grep -qF "$want"; then
        printf '[ FAIL ] %s: exit %d but message lacks %q:\n%s\n' \
            "$desc" "$status" "$want" "$out"
        fail=1
        return
    fi
    printf '[ OK ] %s\n' "$desc"
}

accept()
{
    local desc="$1"
    shift
    local out status=0
    out="$("$ELFUSE" "$@" "$GUEST" 2>&1)" || status=$?
    if [ "$status" -ne 0 ]; then
        printf '[ FAIL ] %s: exit %d, want success:\n%s\n' "$desc" "$status" "$out"
        fail=1
        return
    fi
    printf '[ OK ] %s\n' "$desc"
}

reject "--fakeroot with a non-root --user" "cannot be combined" \
    --fakeroot --user 1000:1000
reject "--fakeroot with a root uid but non-root gid" "cannot be combined" \
    --fakeroot --user 0:1000
reject "--workdir relative path" "absolute" --workdir rel/path
reject "--user non-numeric" "invalid --user" --user alice

# --fakeroot and --user agree here, so the pair must still launch: the check
# refuses a contradiction, not the combination itself.
accept "--fakeroot with an explicit root --user" --fakeroot --user 0:0

if [ "$fail" -ne 0 ]; then
    printf 'test-launch-flags: FAILED\n'
    exit 1
fi
printf 'test-launch-flags: all checks passed\n'
