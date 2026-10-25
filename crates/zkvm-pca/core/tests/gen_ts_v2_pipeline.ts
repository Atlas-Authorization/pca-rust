// Intent Layer v2 pipeline (decideIntentV2: schema -> intent_session -> layers -> accumulators -> W-B) verdicts of the
// TypeScript reference over the realistic session scenarios of the rule-13 port (fixtures/ts_v2_session.json `steps`: signed
// session roots, grant chains, revocation evidence, schemas, accumulators), so the guest's composition (intent_v2.rs) is checked
// end to end: the ordered (name, ok) check list and the verifier-computed env.
//   packages/pca/node_modules/.bin/tsx sdks/zkvm-pca/core/tests/gen_ts_v2_pipeline.ts sdks/zkvm-pca/fixtures/ts_v2_pipeline.json
import { readFileSync, writeFileSync } from 'node:fs';
import { decideIntentV2 } from '../../../../packages/pca/src/intent-v2';

const out = process.argv[2];
if (!out) throw new Error('usage: gen_ts_v2_pipeline.ts <out.json>');
const src = JSON.parse(readFileSync(new URL('../../fixtures/ts_v2_session.json', import.meta.url), 'utf8'));
const cases = [];
for (const s of src.steps) {
  const ctx = s.ctx_absent ? undefined : s.ctx;
  let d;
  try {
    d = decideIntentV2(s.pcactn, s.grant, ctx, s.now);
  } catch (e) {
    continue; // decideIntentV2 never throws; keep the generator total anyway
  }
  cases.push({
    name: s.name,
    pq: !!s.pq,
    pcactn: s.pcactn,
    grant: s.grant,
    ...(s.ctx_absent ? { ctx_absent: true } : { ctx }),
    now: s.now,
    checks: d.checks.map((c) => ({ name: c.name, ok: c.ok })),
    env: d.env ?? null,
  });
}
writeFileSync(out, JSON.stringify({ about: 'decideIntentV2 verdicts over the rule-13 scenarios (gen_ts_v2_pipeline.ts)', cases }, null, 1) + '\n');
console.log(`pipeline cases ${cases.length}, all-ok ${cases.filter((c) => c.checks.every((x) => x.ok)).length}`);
