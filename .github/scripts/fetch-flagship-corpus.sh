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
# The clone is partial (blobs are fetched on demand), so a dropped connection can fail the clone's own checkout or the sparse-checkout
# below ("could not fetch ... from promisor remote"): retry the whole fetch a few times rather than failing the job on one network blip.
fetch_flagship() {
  rm -rf "$DEST"
  git clone -q --depth 1 --filter=blob:none --sparse --branch "$REF" "$URL" "$DEST" || return 1
# tools/pca-diff-fuzz/counterexamples: the conformance runners of the mutation layouts ($MONO/sdks/<crate>) reach them at
# ../../tools/pca-diff-fuzz/counterexamples and silently SKIP them when absent (fewer oracle inputs for the mutants)
# packages/pca/src: the SDK catalog tests compare their built-in action catalog with the reference (catalog-builtin.generated.ts)
  git -C "$DEST" sparse-checkout set conformance packages/pca/conformance packages/pca-conformance tools/pca-audit sdks/pca-less-c packages/pca-fhe packages/pca-dpop tools/pca-diff-fuzz/counterexamples packages/pca/src packages/pca-verified-core packages/pca-mpc-lwe-ot-wasm/crate packages/pca-fndsa-wasm/crate packages/pca-zk/crate packages/pca-sandbox/wasmtime-host
}
for i in 1 2 3 4 5; do
  fetch_flagship && break
  [ "$i" = 5 ] && { echo "::error::could not fetch the flagship corpus from $URL after 5 attempts"; exit 1; }
  echo "flagship fetch failed (attempt $i/5); retrying"; sleep $((i * 20))
done
# a push names its monorepo commit in every repo's head commit ("source <sha>"): the natives are pushed before the flagship,
# so wait until the flagship at this ref was built from the same commit, or this run tests against the previous push's corpus
# safe.directory: container jobs check out as another user, and git then refuses to read the repo (exit 128)
source_of() { { git -c safe.directory='*' -C "$1" log -1 --format=%B 2>/dev/null || true; } | sed -n 's/^source \([0-9a-f]\{40\}\)$/\1/p' | tail -1; }
WANT="$(source_of .)"
if [ -n "$WANT" ]; then
  for i in $(seq 1 40); do
    [ "$(source_of "$DEST")" = "$WANT" ] && break
    [ "$i" = 40 ] && { echo "::error::the flagship at '$REF' was not built from source $WANT after 20 min (push it with this repo)"; exit 1; }
    echo "waiting for the flagship at '$REF' to be built from source $WANT ($i/40)"; sleep 30
    for j in 1 2 3 4 5; do fetch_flagship && break; [ "$j" = 5 ] && { echo "::error::could not fetch the flagship corpus from $URL"; exit 1; }; sleep $((j * 20)); done
  done
fi
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
  cp -R "$DEST/packages/pca-fhe" "$M/packages/"  # fhe-seal-corpus.sh generates from this source
  mkdir -p "$M/packages/pca-mpc-lwe-ot-wasm" && cp -R "$DEST/packages/pca-mpc-lwe-ot-wasm/crate" "$M/packages/pca-mpc-lwe-ot-wasm/"  # build-liblweot.sh builds the C library from this crate
  mkdir -p "$M/packages/pca-sandbox" && cp -R "$DEST/packages/pca-sandbox/wasmtime-host" "$M/packages/pca-sandbox/"  # build-wasmtime-host.sh builds the sandbox subprocess host from this crate
  mkdir -p "$M/packages/pca-fndsa-wasm" && cp -R "$DEST/packages/pca-fndsa-wasm/crate" "$M/packages/pca-fndsa-wasm/"  # build-libfndsa.sh builds the C library from this crate
  mkdir -p "$M/packages/pca-zk" && cp -R "$DEST/packages/pca-zk/crate" "$M/packages/pca-zk/"  # build-libpcazk.sh builds the Groth16 C library from this crate
  cp -R "$DEST/packages/pca/src" "$M/packages/pca/"; cp -R "$DEST/packages/pca-verified-core" "$M/packages/"  # fhe-seal-corpus.sh loads the reference @atlasauth/pca from this source
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
  mkdir -p packages/pca/src && cp "$DEST/packages/pca/src/catalog-builtin.generated.ts" packages/pca/src/
fi
