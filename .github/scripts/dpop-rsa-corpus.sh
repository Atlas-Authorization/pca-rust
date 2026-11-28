#!/usr/bin/env bash
# dpop-rsa-corpus.sh <absolute-out.json.gz> [mono-root]
# Generates the DPoP oracle cases whose arguments carry the RSA test private key (ref-dpop-rsa.json.gz). That key is never committed: the TS
# generator (tools/pca-audit/oracles/dpop.mts) builds it from seeded primes and splits those cases off, and the native suites replay the file
# this script writes before they run (a missing file fails the suite when CI=true). The TypeScript reference is THIS tree's source (the
# packages/pca* paths map in tools/pca-audit/oracles/tsconfig.json); only third-party packages come from npm. Needs Node 20+.
set -euo pipefail
OUT="${1:?absolute output path}"; case "$OUT" in /*|[A-Za-z]:*) ;; *) echo "output path must be absolute" >&2; exit 2 ;; esac
# the flagship checkout fetch-flagship-corpus.sh leaves behind (every mode fetches it); a mono layout also works when passed explicitly
M="${2:-${RUNNER_TEMP:-/tmp}/pca-flagship}"
GEN="$M/tools/pca-audit/oracles/dpop.mts"
[ -f "$GEN" ] || { echo "::error::generator not found: $GEN (run fetch-flagship-corpus.sh first)"; exit 1; }
[ -f "$M/packages/pca-dpop/src/index.ts" ] && [ -f "$M/packages/pca/src/index.ts" ] || { echo "::error::packages/pca-dpop/src or packages/pca/src missing from the source layout (fetch-flagship-corpus.sh)"; exit 1; }
cd "$M"
# the flagship root package.json declares pnpm workspaces (workspace: deps) that npm cannot install: use a bare one for this throwaway checkout
if [ ! -f package.json ] || grep -q '"workspaces"' package.json; then echo '{"name":"oracle-gen","private":true}' > package.json; fi
npm install --loglevel=error --no-audit --no-fund tsx@4.19.2 jose@^5 @noble/curves@^1.9.1 @noble/hashes@^1.8.0 @noble/post-quantum@^0.4.1 @scure/base@^1.2.6 bignumber.js@9.3.1
npx tsx --tsconfig tools/pca-audit/oracles/tsconfig.json tools/pca-audit/oracles/dpop.mts
GENERATED="$M/tools/pca-audit/oracles/out/ref-dpop-rsa.json.gz"
[ -s "$GENERATED" ] || { echo "::error::the generator did not write $GENERATED"; exit 1; }
mkdir -p "$(dirname "$OUT")"; cp "$GENERATED" "$OUT"
echo "wrote $OUT"
