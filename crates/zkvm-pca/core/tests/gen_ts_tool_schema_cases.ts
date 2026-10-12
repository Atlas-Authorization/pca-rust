// R4-03: verdicts of the TypeScript reference (agent-native.ts `agentNativeCaveatEvaluator` -> `evaluateToolSchema`) on
// well-formed, malformed and unbound `tool_schema` caveats, for core/tests/r4_tool_schema_fail_closed.rs.
// Output of the TS reference implementation; NOT an official standard vector.
//   nice -n 15 redteam/run.sh --tsconfig redteam/round4/tsconfig.json \
//       sdks/zkvm-pca/core/tests/gen_ts_tool_schema_cases.ts sdks/zkvm-pca/fixtures/ts_tool_schema_cases.json
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { agentNativeCaveatEvaluator, toolSchemaCaveat } from '../../../../packages/pca/src/agent-native';
import { hashCanonical } from '../../../../packages/pca/src/hash';

const here = dirname(fileURLToPath(import.meta.url));
const out = process.argv[2];
if (!out) throw new Error('usage: gen_ts_tool_schema_cases.ts <out.json>');
type Case = { id: string; caveat: any; tool: string; args: any; tool_signature_digest?: string };
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

const schema = { props: { amount: { type: 'integer', max: 10 }, to: { type: 'string', maxLength: 8 } }, required: ['amount'] };
const good = toolSchemaCaveat({ name: 'pay', v: 1 }, schema as any);
const sig = good.signature_digest;
const del = (o: any, k: string) => { const c = clone(o); delete c[k]; return c; };
const set = (o: any, k: string, v: unknown) => { const c = clone(o); c[k] = v; return c; };

// 1. the six round-4 PoC cases (the "@SD@" marker is replaced by hashCanonical(schema), as the PoC does)
const poc = JSON.parse(readFileSync(join(here, '../../../../redteam/round4/zk/caveat-cases.json'), 'utf8')) as Case[];
const cases: Case[] = poc.map((c) => ({ ...c, id: 'poc:' + c.id }));

// 2. extras
const ok = { amount: 5 };
cases.push(
  { id: 'good-allows', caveat: good, tool: 'pay', args: ok },
  { id: 'good-optional-arg', caveat: good, tool: 'pay', args: { amount: 5, to: 'bob' } },
  { id: 'good-with-matching-binding', caveat: good, tool: 'pay', args: ok, tool_signature_digest: sig },
  { id: 'binding-differs', caveat: good, tool: 'pay', args: ok, tool_signature_digest: 'zzz' },
  { id: 'over-max', caveat: good, tool: 'pay', args: { amount: 11 } },
  { id: 'extra-arg', caveat: good, tool: 'pay', args: { amount: 5, evil: 1 } },
  { id: 'missing-required', caveat: good, tool: 'pay', args: {} },
  { id: 'wrong-type', caveat: good, tool: 'pay', args: { amount: '5' } },
  { id: 'wrong-tool', caveat: good, tool: 'delete_all', args: ok },
  { id: 'args-not-object', caveat: good, tool: 'pay', args: [1] },
  { id: 'args-null', caveat: good, tool: 'pay', args: null },
  { id: 'no-tool', caveat: del(good, 'tool'), tool: 'pay', args: ok },
  { id: 'empty-tool', caveat: set(good, 'tool', ''), tool: 'pay', args: ok },
  { id: 'tool-not-string', caveat: set(good, 'tool', 7), tool: 'pay', args: ok },
  { id: 'no-schema', caveat: del(good, 'schema'), tool: 'pay', args: ok },
  { id: 'schema-null', caveat: set(good, 'schema', null), tool: 'pay', args: ok },
  { id: 'schema-string', caveat: set(good, 'schema', 'x'), tool: 'pay', args: ok },
  { id: 'schema-array', caveat: set(good, 'schema', []), tool: 'pay', args: ok },
  { id: 'schema-no-props', caveat: set(good, 'schema', {}), tool: 'pay', args: ok },
  { id: 'schema-props-null', caveat: set(good, 'schema', { props: null }), tool: 'pay', args: ok },
  { id: 'schema-unknown-key', caveat: set(good, 'schema', { props: {}, extra: 1 }), tool: 'pay', args: {} },
  { id: 'schema-required-undeclared', caveat: set(good, 'schema', { props: {}, required: ['x'] }), tool: 'pay', args: {} },
  { id: 'no-schema-digest', caveat: del(good, 'schema_digest'), tool: 'pay', args: ok },
  { id: 'schema-digest-wrong', caveat: set(good, 'schema_digest', 'AAAA'), tool: 'pay', args: ok },
  { id: 'schema-digest-not-string', caveat: set(good, 'schema_digest', 5), tool: 'pay', args: ok },
  { id: 'no-binding-digest', caveat: del(good, 'binding_digest'), tool: 'pay', args: ok },
  { id: 'binding-digest-wrong', caveat: set(good, 'binding_digest', 'AAAA'), tool: 'pay', args: ok },
  { id: 'binding-digest-not-string', caveat: set(good, 'binding_digest', null), tool: 'pay', args: ok },
  { id: 'signature-digest-changed', caveat: set(good, 'signature_digest', hashCanonical('other')), tool: 'pay', args: ok },
  { id: 'schema-edited-after-signing', caveat: set(good, 'schema', { props: { amount: { type: 'integer', max: 1000000 } } }), tool: 'pay', args: { amount: 999999 } },
  { id: 'unknown-type', caveat: { type: 'nonsense' }, tool: 'pay', args: ok },
  { id: 'caveat-not-object', caveat: 'tool_schema', tool: 'pay', args: ok },
);

// 3. R5-ZK-01/02: malformed scalar bounds (the guest used to DROP them and apply defaults) and UTF-16 lengths. Built by hand
// (toolSchemaCaveat refuses an invalid schema), with correct digests so only the bound can decide.
const mk = (schema: any) => {
  try {
    return { type: 'tool_schema', tool: 'pay', signature_digest: sig, schema, schema_digest: hashCanonical(schema), binding_digest: hashCanonical({ tool: 'pay', signature_digest: sig, schema }) };
  } catch {
    return { type: 'tool_schema', tool: 'pay', signature_digest: sig, schema, schema_digest: 'AAAA', binding_digest: 'AAAA' }; // outside the strict profile: no digest exists
  }
};
const str = (extra: any) => mk({ props: { to: { type: 'string', ...extra } } });
const numc = (extra: any) => mk({ props: { n: { type: 'number', ...extra } } });
const arrc = (extra: any) => mk({ props: { a: { type: 'array', items: { type: 'number' }, ...extra } } });
for (const [id, c, args] of [
  ['r5-maxlength-string', str({ maxLength: '1' }), { to: 'abc' }], ['r5-maxlength-negative', str({ maxLength: -1 }), { to: 'abc' }], ['r5-maxlength-fraction', str({ maxLength: 1.5 }), { to: 'abc' }],
  ['r5-maxlength-null', str({ maxLength: null }), { to: 'abc' }], ['r5-maxlength-over-absolute', str({ maxLength: 1048577 }), { to: 'abc' }], ['r5-maxlength-ok', str({ maxLength: 3 }), { to: 'abc' }],
  ['r5-minlength-string', str({ minLength: '9' }), { to: 'abc' }], ['r5-minlength-null', str({ minLength: null }), { to: 'abc' }], ['r5-minlength-above-maxlength', str({ minLength: 5, maxLength: 2 }), { to: 'abc' }],
  ['r5-prefix-number', str({ prefix: 5 }), { to: 'abc' }], ['r5-prefix-too-long', str({ prefix: 'x'.repeat(513) }), { to: 'abc' }], ['r5-prefix-ok', str({ prefix: 'ab' }), { to: 'abc' }],
  ['r5-max-string', numc({ max: '1' }), { n: 5 }], ['r5-min-string', numc({ min: '9' }), { n: 5 }], ['r5-max-null', numc({ max: null }), { n: 5 }], ['r5-min-above-max', numc({ min: 9, max: 1 }), { n: 5 }], ['r5-minmax-ok', numc({ min: 1, max: 9 }), { n: 5 }],
  ['r5-maxitems-string', arrc({ maxItems: '1' }), { a: [1, 2] }], ['r5-maxitems-fraction', arrc({ maxItems: 1.5 }), { a: [1, 2] }], ['r5-minitems-string', arrc({ minItems: '9' }), { a: [1, 2] }], ['r5-minitems-above-maxitems', arrc({ minItems: 3, maxItems: 2 }), { a: [1, 2] }], ['r5-items-ok', arrc({ minItems: 1, maxItems: 2 }), { a: [1, 2] }],
  ['r5-utf16-maxlength-1-emoji', str({ maxLength: 1 }), { to: '😀' }], ['r5-utf16-maxlength-2-emoji', str({ maxLength: 2 }), { to: '😀' }], ['r5-utf16-minlength-3-emoji', str({ minLength: 3 }), { to: '😀' }], ['r5-utf16-minlength-2-emoji', str({ minLength: 2 }), { to: '😀' }],
  ['r5-utf16-const-over-1024-units', str({ const: '😀'.repeat(513) }), { to: '😀'.repeat(513) }], ['r5-utf16-const-512-emoji', str({ const: '😀'.repeat(512) }), { to: '😀'.repeat(512) }],
  ['r5-unsafe-integer-bound', numc({ max: 2 ** 60 }), { n: 5 }],
] as Array<[string, any, any]>) cases.push({ id, caveat: c, tool: 'pay', args });

const res = cases.map((c) => {
  const cv = clone(c.caveat);
  if (cv && cv.schema_digest === '@SD@') cv.schema_digest = hashCanonical(cv.schema);
  const toolCall: any = { tool: c.tool, args: c.args };
  if (c.tool_signature_digest !== undefined) toolCall.toolSignatureDigest = c.tool_signature_digest;
  const satisfied = agentNativeCaveatEvaluator(cv, { now: 1e12, action: { verb: c.tool, resource: 'x', params: c.args }, toolCall } as any);
  return { id: c.id, caveat: cv, tool: c.tool, args: c.args, tool_signature_digest: c.tool_signature_digest ?? null, satisfied };
});
writeFileSync(out, JSON.stringify(res, null, 1) + '\n');
console.log(`cases=${res.length} satisfied=${res.filter((r) => r.satisfied).length} -> ${out}`);
for (const r of res) console.log(r.id.padEnd(32), r.satisfied);
