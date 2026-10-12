// R4-04: verdicts of the TypeScript reference (pcactn.ts `verifyPCActnCore`: checks `wire`, `version`, `audience`, `validity`,
// `counter`) on mutated freshness fields of the committed sample PCActn, for core/tests/r4_pcactn_freshness.rs.
// `fresh` = all five of those checks pass. Output of the TS reference implementation; NOT an official standard vector.
//   nice -n 15 redteam/run.sh --tsconfig redteam/round4/tsconfig.json \
//       sdks/zkvm-pca/core/tests/gen_ts_pcactn_freshness.ts sdks/zkvm-pca/fixtures/ts_pcactn_freshness.json
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyPCActnCore } from '../../../../packages/pca/src/pcactn';
import { validateWireV2 } from '../../../../packages/pca/src/wire';

const here = dirname(fileURLToPath(import.meta.url));
const out = process.argv[2];
if (!out) throw new Error('usage: gen_ts_pcactn_freshness.ts <out.json>');
const inp = JSON.parse(readFileSync(join(here, '../../fixtures/decide_input.sample.json'), 'utf8'));
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
// The committed sample PCActn is minted by the Rust side and is not in the TS wire-v2 shape (`action.params` instead of
// `action.params_digest`, `plan.inclusion_proof` as an array). Its freshness fields are what is under test, so the TS side
// receives the same PCActn with those two wire-shape fields normalised (everything this file mutates is untouched).
const wireShaped = clone(inp.pcactn);
delete wireShaped.action.params;
wireShaped.action.params_digest = 'A'.repeat(43);
wireShaped.plan.inclusion_proof = { index: 0, size: 1, path: [] };
const wireErr = validateWireV2(wireShaped);
if (wireErr !== null) throw new Error('normalised sample PCActn is not wire-valid: ' + wireErr);
const IAT = inp.pcactn.iat as number;
const EXP = inp.pcactn.exp as number;
const AUD = inp.pcactn.aud as string;

const muts: Array<[string, (p: any) => void]> = [['none', () => {}]];
for (const v of [1, 3, 0, '2', 2.5, null]) muts.push([`ver=${JSON.stringify(v)}`, (p) => (p.ver = v)]);
muts.push(['ver missing', (p) => delete p.ver]);
for (const k of ['iat', 'exp', 'counter', 'aud']) muts.push([`${k} missing`, (p) => delete p[k]]);
for (const v of [null, '1760000000000', true, 1.5, 9007199254740992]) for (const k of ['iat', 'exp', 'counter']) muts.push([`${k}=${JSON.stringify(v)}`, (p) => (p[k] = v)]);
for (const d of [3_600_000, 3_600_001, 1, 0, -1]) muts.push([`exp=iat+${d}`, (p) => (p.exp = IAT + d)]);
for (const v of [-1, 0, 7, 9007199254740991]) muts.push([`counter=${v}`, (p) => (p.counter = v)]);
for (const v of ['', 'other', 'a'.repeat(256), 'a'.repeat(257), 123, null]) muts.push([`aud=${JSON.stringify(v).slice(0, 12)}(${typeof v === 'string' ? v.length : 'x'})`, (p) => (p.aud = v)]);
muts.push(['iat=exp-1', (p) => (p.iat = EXP - 1)], ['iat after exp', (p) => (p.iat = EXP + 5)]);
const nows = [IAT - 60_001, IAT - 60_000, IAT, EXP - 1, EXP, EXP + 1, EXP + 86_400_000];

async function main() {
const rows: any[] = [];
for (const [name, f] of muts) {
  for (const now of nows) {
    const p = clone(wireShaped);
    f(p);
    const r = await verifyPCActnCore(p, { grant: inp.grant, nowEpoch: now, audience: AUD } as any);
    const c = r.checks as Record<string, string>;
    const fresh = ['wire', 'version', 'audience', 'validity', 'counter'].every((k) => c[k] === 'pass');
    const fields: Record<string, unknown> = {};
    for (const k of ['ver', 'iat', 'exp', 'counter', 'aud']) if (k in p) fields[k] = p[k];
    rows.push({ name, now, fields, expected_aud: AUD, fresh, checks: { wire: c.wire ?? null, version: c.version ?? null, audience: c.audience ?? null, validity: c.validity ?? null, counter: c.counter ?? null } });
  }
}
writeFileSync(out, JSON.stringify(rows) + '\n');
console.log(`rows=${rows.length} fresh=${rows.filter((r) => r.fresh).length} -> ${out}`);
}
main().catch((e) => { console.error(e); process.exit(1); });
