#!/usr/bin/env bash
# gen-secret-corpus.sh <absolute-out-dir> <generator>:<lane-corpus-name> [...]  [--root <flagship-or-mono-root>]
# Generates the oracle cases that carry private keys (never committed): for each spec the TS generator tools/pca-audit/oracles/<generator>.mts
# writes out/ref-<generator>-gen.json.gz, which is copied to <out-dir>/ref-<lane-corpus-name>-gen.json.gz where the lane's replay test looks for it
# (tests fail instead of skipping when CI is set and the file is missing). Examples: oprf:oprf  oprf-swift:oprf  core-frost-java:core-frost-java
# core-frost-swift:frost  mpc-ot:mpc-ot  attest-eat:attest-eat  abe:abe  abe-go:abe-go. The TypeScript reference is THIS tree's packages/*/src
# (tsconfig paths in tools/pca-audit/oracles/tsconfig.json); only third-party packages come from npm. Needs Node 20+ and git.
set -euo pipefail
OUT="${1:?absolute output dir}"; shift; case "$OUT" in /*|[A-Za-z]:*) ;; *) echo "output dir must be absolute" >&2; exit 2 ;; esac
M="${RUNNER_TEMP:-/tmp}/pca-flagship"; SPECS=()
while [ $# -gt 0 ]; do case "$1" in --root) M="${2:?}"; shift 2 ;; *) SPECS+=("$1"); shift ;; esac; done
[ ${#SPECS[@]} -gt 0 ] || { echo "no generator specs" >&2; exit 2; }
[ -f "$M/tools/pca-audit/oracles/lib.mjs" ] || { echo "::error::$M has no tools/pca-audit/oracles (run fetch-flagship-corpus.sh first)"; exit 1; }
# the sparse flagship checkout carries only some packages: the generators import many (pca-oprf, pca-mpc, pca-abe, pca-attest-eat, ...)
if [ -d "$M/.git" ]; then git -C "$M" sparse-checkout add packages >/dev/null 2>&1 || true; fi
cd "$M"
# the flagship root package.json declares pnpm workspaces (workspace: deps) that npm cannot install: use a bare one for this throwaway checkout
if [ ! -f package.json ] || grep -q '"workspaces"' package.json; then echo '{"name":"oracle-gen","private":true}' > package.json; fi
npm install --loglevel=error --no-audit --no-fund tsx@4.19.2 jose@^5 @noble/curves@^1.9.1 @noble/hashes@^1.8.0 @noble/post-quantum@^0.4.1 @scure/base@^1.2.6 bignumber.js
mkdir -p "$OUT"
for spec in "${SPECS[@]}"; do
  g="${spec%%:*}"; n="${spec##*:}"
  npx tsx --tsconfig tools/pca-audit/oracles/tsconfig.json "tools/pca-audit/oracles/$g.mts"
  f="tools/pca-audit/oracles/out/ref-$g-gen.json.gz"
  [ -s "$f" ] || { echo "::error::the generator $g did not write $f"; exit 1; }
  cp "$f" "$OUT/ref-$n-gen.json.gz"; echo "wrote $OUT/ref-$n-gen.json.gz"
done
