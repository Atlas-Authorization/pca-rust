#!/usr/bin/env bash
# fhe-seal-corpus.sh <absolute-out.json.gz> [generator.mts]
# Generates the node-seal BFV corpus (public keys, ciphertexts, evaluated results, verdicts; no secret key) for the native SEAL replays.
# node-seal is pinned to the version whose bundled Microsoft SEAL (4.1.2) the native ports are built against; the TypeScript reference is
# THIS tree's packages/pca-fhe source, and its @atlasauth/pca (+ pca-verified-core) dependency is THIS tree's packages/pca/src too (run with tsx through a tsconfig paths map; only the third-party deps come from npm). Needs Node 20+. The corpus is tens of MB and keys are random per run, so it is generated, never committed.
set -euo pipefail
OUT="${1:?absolute output path}"; case "$OUT" in /*) ;; *) echo "output path must be absolute" >&2; exit 2 ;; esac
GEN="${2:-${RUNNER_TEMP:-/tmp}/mono/tools/pca-audit/oracles/fhe-seal.mts}"
[ -f "$GEN" ] || { echo "::error::generator not found: $GEN (run fetch-flagship-corpus.sh --mono first)"; exit 1; }
FHE="$(cd "$(dirname "$GEN")/../../../packages/pca-fhe/src" 2>/dev/null && pwd)" || { echo "::error::packages/pca-fhe/src not in the source layout (fetch-flagship-corpus.sh --mono)"; exit 1; }
PK="$(cd "$FHE/../.." && pwd)"
[ -f "$PK/pca/src/index.ts" ] && [ -f "$PK/pca-verified-core/src/index.ts" ] || { echo "::error::packages/pca/src or packages/pca-verified-core/src missing from the source layout (fetch-flagship-corpus.sh --mono)"; exit 1; }
D="$(mktemp -d)"; mkdir "$D/pca-fhe" "$D/pca"
cp "$FHE/index.ts" "$FHE/origin.ts" "$D/pca-fhe/"
cp -R "$PK/pca/src" "$D/pca/src"; cp -R "$PK/pca-verified-core" "$D/pca-verified-core"
cat > "$D/tsconfig.json" <<'J'
{"compilerOptions":{"module":"esnext","moduleResolution":"bundler","target":"es2022","baseUrl":".","paths":{"@atlasauth/pca":["./pca/src/index.ts"]}}}
J
sed "s#'@atlasauth/pca-fhe'#'./pca-fhe/index.ts'#" "$GEN" > "$D/fhe-seal.mts"; cd "$D"
npm init -y >/dev/null; npm pkg set type=module >/dev/null # ESM so tsx resolves the reference's named exports (CJS interop hid them)
npm install --silent --no-audit --no-fund node-seal@5.1.7 tsx@4.19.2 bignumber.js @noble/curves@^1.9.1 @noble/hashes@^1.8.0 @noble/post-quantum@^0.4.1 @scure/base@^1.2.6
# verified-core is CommonJS (its adapters require() the generated Dafny JS), so loaded from source an ESM importer cannot see its re-exported names
# (export * from './ext-wire' -> "does not provide an export named wireCanonicalizeStrict"): bundle it once into an ESM node_modules package instead
V=node_modules/@atlasauth/pca-verified-core; mkdir -p "$V"; echo '{"name":"@atlasauth/pca-verified-core","type":"module","main":"index.js"}' > "$V/package.json"
npx esbuild pca-verified-core/src/index.ts --bundle --format=esm --platform=node --target=es2022 --outfile="$V/index.js" --log-level=error
# the reference must load from this tree's source: fail the step loudly if it cannot
echo "import * as P from '@atlasauth/pca'; if (!(P as any).DEFAULT_RISK_POLICY) throw new Error('DEFAULT_RISK_POLICY missing');" > check-ref.mts
npx tsx check-ref.mts 2>&1 || { echo "::error::the @atlasauth/pca reference (packages/pca/src) failed to load (error above)"; exit 1; }
npx tsx fhe-seal.mts "$OUT"
