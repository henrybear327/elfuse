#!/usr/bin/env bash
# Host-side check of a sysroot's casefold sidecar on-disk state, run by test
# recipes after the guest exits.
#
#   check-sidecar-state.sh <sysroot> ci [outside-dir...]
#   check-sidecar-state.sh <sysroot> cs [outside-dir...]
#
# ci mode asserts the index/token contract: at least one token was minted
# (the guest created mixed-case names, so a token-free sysroot means the
# sidecar never engaged), every index row names an existing token file, and
# every token file has an index row. cs mode asserts purity: no sidecar
# artifacts at all. Any extra directories are checked for artifact leakage
# outside the sysroot.
set -u -o pipefail

sysroot=$1
mode=$2
shift 2

tab=$(printf '\t')

fail() {
    echo "check-sidecar-state: $1"
    exit 1
}

if [ "$mode" = ci ]; then
    find "$sysroot" -name '.ef_*' -print -quit | grep -q . ||
        fail "no tokens found in casefold sysroot"

    while IFS= read -r -d '' idx; do
        dir=$(dirname "$idx")
        while IFS="$tab" read -r hexname token; do
            [ -n "$hexname" ] || continue
            if [ ! -e "$dir/$token" ] && [ ! -L "$dir/$token" ]; then
                fail "row for $token in $idx has no token file"
            fi
        done < "$idx"
        while IFS= read -r -d '' tokenpath; do
            token=$(basename "$tokenpath")
            # Exact field compare rather than a regex: a token name contains
            # "." (".ef_<hex>"), which as a BRE metacharacter matches any byte,
            # so a corrupted index row could otherwise satisfy the check.
            awk -F "$tab" -v tok="$token" '$2 == tok {f = 1} END {exit !f}' \
                "$idx" ||
                fail "token $tokenpath has no index row"
        done < <(find "$dir" -mindepth 1 -maxdepth 1 -name '.ef_*' -print0)
    done < <(find "$sysroot" -name '.elfuse_case_index' -print0)
else
    hit=$(find "$sysroot" \( -name '.ef_*' -o -name '.elfuse_case_index*' \) \
        -print -quit)
    [ -z "$hit" ] || fail "sidecar artifact on case-sensitive volume: $hit"
fi

for outside in "$@"; do
    hit=$(find "$outside" \( -name '.ef_*' -o -name '.elfuse_case_index*' \) \
        -print -quit 2>/dev/null)
    [ -z "$hit" ] || fail "sidecar artifact escaped the sysroot: $hit"
done

exit 0
