#!/usr/bin/env bash
# fetch-flagship-corpus.sh [--layout | --mono <sdk-dir>]
# This repo vendors only the curated core corpus (conformance/vectors.json). The full adversarial set and the
# mutation-oracle inputs live in the flagship repo (Atlas-Authorization/pca). Fetch them from the flagship at the SAME
# ref as this run (a ci/** branch or tag pushed together with this repo, or main), waiting up to 20 min for the ref:
#   conformance/vectors-adversarial.json.gz   always
#   packages/pca/conformance/, packages/pca-conformance/, tools/pca-audit/   with --layout (suites that locate the corpus by the flagship's layout)
#   --mono <sdk-dir>   rebuild the source layout around a copy of this repo, for suites whose fixed relative paths
#                      reach ABOVE the repo root (../../../tools/...): $RUNNER_TEMP/mono/{packages/pca/conformance,
#                      tools/pca-audit,sdks/<sdk-dir>}; exports PCA_MONO_SDK (the copy, run the tests there) to $GITHUB_ENV
set -euo pipefail
REF="${PCA_FLAGSHIP_REF:-${GITHUB_REF_NAME:-main}}"
URL="https://github.com/${GITHUB_REPOSITORY_OWNER:-Atlas-Authorization}/pca.git"
DEST="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pca-flagship"
for i in $(seq 1 40); do
  git ls-remote --exit-code "$URL" "refs/heads/$REF" "refs/tags/$REF" >/dev/null 2>&1 && break
  [ "$i" = 40 ] && { echo "::error::the flagship repo has no ref '$REF' (push it at the same ref)"; exit 1; }
  echo "waiting for the flagship ref '$REF' ($i/40)"; sleep 30
done
rm -rf "$DEST"
git clone -q --depth 1 --filter=blob:none --sparse --branch "$REF" "$URL" "$DEST"
git -C "$DEST" sparse-checkout set conformance packages/pca/conformance packages/pca-conformance tools/pca-audit
echo "flagship $REF @ $(git -C "$DEST" rev-parse HEAD)"
cp "$DEST/conformance/vectors-adversarial.json.gz" conformance/
if [ "${1:-}" = --mono ]; then
  M="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/mono"; SDK="$M/sdks/${2:?--mono needs the sdk dir name}"
  rm -rf "$M"; mkdir -p "$M/packages/pca" "$M/tools" "$SDK"
  cp -R "$DEST/packages/pca/conformance" "$M/packages/pca/"
  cp -R "$DEST/packages/pca-conformance" "$M/packages/"
  cp -R "$DEST/tools/pca-audit" "$M/tools/"
  cp -R . "$SDK/"; rm -rf "$SDK/.git"
  echo "PCA_MONO_SDK=$SDK" >> "${GITHUB_ENV:-/dev/null}"
  echo "source layout rebuilt at $M (tests run in $SDK)"
elif [ "${1:-}" = --layout ]; then
  mkdir -p packages/pca tools
  rm -rf packages/pca/conformance packages/pca-conformance tools/pca-audit
  cp -R "$DEST/packages/pca/conformance" packages/pca/
  cp -R "$DEST/packages/pca-conformance" packages/
  cp -R "$DEST/tools/pca-audit" tools/
fi
