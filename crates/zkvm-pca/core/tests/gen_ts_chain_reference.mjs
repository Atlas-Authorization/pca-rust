// Regenerates fixtures/ts_chain_reference.json: the verdicts of the TypeScript reference
// implementation (@atlasauth/pca verifyChain, Node/OpenSSL Ed25519) on the committed sample chain
// (which was minted by the Rust side) and on three tampered variants. Run from the repo root after
// `pnpm --filter @atlasauth/pca build`:  node sdks/zkvm-pca/core/tests/gen_ts_chain_reference.mjs
// Output of the TS reference implementation; not an official standard vector.
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const { verifyChain } = require(join(here, '../../../../packages/pca/dist/index.js'));
const inp = JSON.parse(readFileSync(join(here, '../../fixtures/decide_input.sample.json'), 'utf8'));
const flip = (s) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
const variants = {
  untouched: [inp.chain, inp.expected_root_principal],
  leaf_hop_signature_tampered: [inp.chain.map((h, i) => (i === 1 ? { ...h, sig: flip(h.sig) } : h)), inp.expected_root_principal],
  root_hop_signature_tampered: [inp.chain.map((h, i) => (i === 0 ? { ...h, sig: flip(h.sig) } : h)), inp.expected_root_principal],
  wrong_pinned_root: [inp.chain, 'not-the-pinned-root-principal-key'],
};
const out = {
  description: 'Verdicts of the TypeScript reference verifyChain on the committed sample chain and tampered variants.',
  cases: Object.entries(variants).map(([name, [chain, root]]) => {
    const r = verifyChain(chain, root);
    return { name, ts_ok: r.ok, ts_reason: r.ok ? null : r.reason };
  }),
};
writeFileSync(join(here, '../../fixtures/ts_chain_reference.json'), JSON.stringify(out, null, 2) + '\n');
console.log(JSON.stringify(out.cases));
