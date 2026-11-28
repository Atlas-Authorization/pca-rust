#!/usr/bin/env bash
# Self-check for flagship-source.sh: bash flagship-source.selftest.sh
set -euo pipefail
. "$(dirname "$0")/flagship-source.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
A=$(printf 'a%.0s' $(seq 40)); B=$(printf 'b%.0s' $(seq 40)); C=$(printf 'c%.0s' $(seq 40))
git init -q "$T"; export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
git -C "$T" commit -q --allow-empty -m "sync"$'\n\n'"source $A"; first=$(git -C "$T" rev-parse HEAD)
git -C "$T" commit -q --allow-empty -m "sync"$'\n\n'"source $B"
[ "$(find_source_commit "$T" "$A")" = "$first" ] || { echo "FAIL: older source not found in history"; exit 1; }
[ "$(find_source_commit "$T" "$B")" = "$(git -C "$T" rev-parse HEAD)" ] || { echo "FAIL: head source not found"; exit 1; }
[ -z "$(find_source_commit "$T" "$C")" ] || { echo "FAIL: matched a different source"; exit 1; }
echo "flagship-source selftest ok"
