#!/usr/bin/env bash
# mutation-layout.sh <crate> [<subdir of this repo that is the crate>]
# The mutation tools and the equivalent-mutant ledger live in the flagship repo (tools/pca-audit) and expect its layout:
#   <root>/tools/pca-audit, <root>/packages/pca/conformance, <root>/sdks/<crate>
# Fetches the flagship at the same ref as this run (falls back to its main, with a warning, when the flagship has no such
# ref), copies this repo (or <subdir>) to <root>/sdks/<crate> and exports MONO=<root> to later steps.
# IN_REPO=1 also lays packages/pca/conformance, packages/pca-conformance and tools/pca-audit into this repo (tests that
# reach them by repo-relative paths when run in place). LESS=1 also builds libatlas_less (fetch-flagship-corpus.sh --less).
set -euo pipefail
CRATE="${1:?crate}"; SUB="${2:-.}"
ref="${GITHUB_REF_NAME:-main}"
if ! git ls-remote --exit-code "https://github.com/${GITHUB_REPOSITORY_OWNER:-Atlas-Authorization}/pca.git" "refs/heads/$ref" "refs/tags/$ref" >/dev/null 2>&1; then
  echo "::warning::the flagship repo has no ref '$ref': using the mutation tooling and ledger from its main"
  ref=main
fi
args=()
[ "${IN_REPO:-0}" = 1 ] && args+=(--layout)
[ "${LESS:-0}" = 1 ] && args+=(--less)
PCA_FLAGSHIP_REF="$ref" bash "$(dirname "$0")/fetch-flagship-corpus.sh" ${args[@]+"${args[@]}"}
M="${RUNNER_TEMP:-/tmp}/pca-flagship"
mkdir -p "$M/sdks"
rm -rf "${M:?}/sdks/$CRATE"
cp -R "$SUB" "$M/sdks/$CRATE"
rm -rf "$M/sdks/$CRATE/.git"
echo "MONO=$M" >> "${GITHUB_ENV:-/dev/null}"
echo "layout: $M (tools/pca-audit + sdks/$CRATE)"
