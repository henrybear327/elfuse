#!/usr/bin/env bash

# Fail a self-hosted workload run whose commit is no longer the PR head.
# cancel-in-progress does not cover a manual "Re-run jobs": the re-run replays a
# frozen head.sha against the one self-hosted runner. Fail rather than cancel
# (the job token has no actions scope, so the cancel API is unavailable); the
# lookup fails open.
#
# Inputs: GH_TOKEN, REPO, PR_NUMBER, RUN_SHA.

set -uo pipefail

: "${GH_TOKEN:?}" "${REPO:?}" "${PR_NUMBER:?}" "${RUN_SHA:?}"

# curl and system python3 are always present on macOS; jq and gh are not
# guaranteed on a self-hosted runner, so don't depend on them. Without the
# deadlines a stalled API call never reaches the fail-open branch.
latest=$(curl -fsSL --connect-timeout 10 --max-time 60 \
    -H "Authorization: Bearer $GH_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$REPO/pulls/$PR_NUMBER" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["head"]["sha"])') \
    || latest=""
echo "Run targets : $RUN_SHA"
echo "PR HEAD now : ${latest:-<unknown>}"
if [ -n "$latest" ] && [ "$latest" != "$RUN_SHA" ]; then
    echo "::error::This run targets $RUN_SHA, but PR #$PR_NUMBER HEAD is now $latest, so the commit is no longer the latest. Failing instead of re-testing stale code on the self-hosted runner; re-run CI on the current commit."
    exit 1
fi
