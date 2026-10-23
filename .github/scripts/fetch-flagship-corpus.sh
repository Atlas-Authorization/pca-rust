#!/usr/bin/env bash
# fetch-flagship-corpus.sh [--layout | --mono <sdk-dir>] [--less]
# This repo vendors only the curated core corpus (conformance/vectors.json). The full adversarial set, the mutation-oracle
# inputs and the LESS reference C live in the flagship repo (Atlas-Authorization/pca). Fetch them from the flagship at the
# SAME ref as this run (a ci/** branch or tag pushed together with this repo, or main), waiting up to 20 min for the ref:
#   conformance/vectors-adversarial.json.gz   always
#   --layout           + packages/pca/conformance/, packages/pca-conformance/, tools/pca-audit/ in this checkout (suites that
#                      locate the corpus by the flagship's layout)
#   --mono <sdk-dir>   rebuild the source layout around a copy of this repo, for suites whose fixed relative paths reach ABOVE
#                      the repo root (../../../tools/...): $RUNNER_TEMP/mono/{packages/pca/conformance,tools/pca-audit,
#                      sdks/<sdk-dir>}; exports PCA_MONO_SDK (the copy: run the tests there) to $GITHUB_ENV
#   --less             build libatlas_less from the flagship's sdks/pca-less-c (needs a C compiler; not on Windows) and
#                      export ATLAS_PCA_LIBLESS to $GITHUB_ENV, so the FFI backend runs the LESS vectors
set -euo pipefail
MODE="" SDK_DIR="" LESS=0
while [ $# -gt 0 ]; do
  case "$1" in
    --layout) MODE=layout ;;
    --mono)   MODE=mono; SDK_DIR="${2:?--mono needs the sdk dir name}"; shift ;;
    --less)   LESS=1 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
REF="${PCA_FLAGSHIP_REF:-${GITHUB_REF_NAME:-main}}"
URL="https://github.com/${GITHUB_REPOSITORY_OWNER:-Atlas-Authorization}/pca.git"
TMP="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
DEST="$TMP/pca-flagship"
for i in $(seq 1 40); do
  git ls-remote --exit-code "$URL" "refs/heads/$REF" "refs/tags/$REF" >/dev/null 2>&1 && break
  [ "$i" = 40 ] && { echo "::error::the flagship repo has no ref '$REF' (push it at the same ref)"; exit 1; }
  echo "waiting for the flagship ref '$REF' ($i/40)"; sleep 30
done
rm -rf "$DEST"
git clone -q --depth 1 --filter=blob:none --sparse --branch "$REF" "$URL" "$DEST"
# tools/pca-diff-fuzz/counterexamples: the conformance runners of the mutation layouts ($MONO/sdks/<crate>) reach them at
# ../../tools/pca-diff-fuzz/counterexamples and silently SKIP them when absent (fewer oracle inputs for the mutants)
git -C "$DEST" sparse-checkout set conformance packages/pca/conformance packages/pca-conformance tools/pca-audit sdks/pca-less-c tools/pca-diff-fuzz/counterexamples
echo "flagship $REF @ $(git -C "$DEST" rev-parse HEAD)"
cp "$DEST/conformance/vectors-adversarial.json.gz" conformance/

if [ "$LESS" = 1 ]; then
  [ -f "$DEST/sdks/pca-less-c/build.sh" ] || { echo "::error::the flagship at $REF has no sdks/pca-less-c"; exit 1; }
  lib="$(bash "$DEST/sdks/pca-less-c/build.sh" "$TMP/libatlas_less" | tail -1)"
  [ -f "$lib" ] || { echo "::error::libatlas_less did not build"; exit 1; }
  echo "ATLAS_PCA_LIBLESS=$lib" >> "${GITHUB_ENV:-/dev/null}"
  echo "libatlas_less: $lib"
fi

if [ "$MODE" = mono ]; then
  M="$TMP/mono"; SDK="$M/sdks/$SDK_DIR"
  rm -rf "$M"; mkdir -p "$M/packages/pca" "$M/tools" "$SDK"
  cp -R "$DEST/packages/pca/conformance" "$M/packages/pca/"
  cp -R "$DEST/packages/pca-conformance" "$M/packages/"
  cp -R "$DEST/tools/pca-audit" "$M/tools/"
  cp -R "$DEST/sdks/pca-less-c" "$M/sdks/" 2>/dev/null || true
  cp -R . "$SDK/"; rm -rf "$SDK/.git"
  echo "PCA_MONO_SDK=$SDK" >> "${GITHUB_ENV:-/dev/null}"
  echo "source layout rebuilt at $M (tests run in $SDK)"
elif [ "$MODE" = layout ]; then
  mkdir -p packages/pca tools
  rm -rf packages/pca/conformance packages/pca-conformance tools/pca-audit
  cp -R "$DEST/packages/pca/conformance" packages/pca/
  cp -R "$DEST/packages/pca-conformance" packages/
  cp -R "$DEST/tools/pca-audit" tools/
fi
