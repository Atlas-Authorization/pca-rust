// R5-ZK-01/02: seeded RANDOM differential for `tool_schema` (agent-native.ts `evaluateToolSchema` via the agent-native caveat
// evaluator) over schemas with well-formed AND malformed scalar bounds (maxLength/minLength/prefix/min/max/minItems/maxItems/
// enum/const), astral strings (UTF-16 vs code-point lengths) and mixed-type arguments. Output of the TS reference; NOT a
// standard vector.
//   nice -n 15 redteam/run.sh --tsconfig redteam/round4/tsconfig.json \
//       sdks/zkvm-pca/core/tests/gen_ts_tool_schema_random.ts <out.json> [schemas=1200] [seed=1]
// Committed golden: fixtures/ts_tool_schema_random.json (defaults). 100k run: `<out> 25000 7` then
//   PCA_SCHEMA_CASES=<out> cargo test -p pca-zkvm-core --release --test r5_tool_schema_random
import { writeFileSync } from 'node:fs';
import { agentNativeCaveatEvaluator } from '../../../../packages/pca/src/agent-native';
import { hashCanonical } from '../../../../packages/pca/src/hash';

const out = process.argv[2];
if (!out) throw new Error('usage: gen_ts_tool_schema_random.ts <out.json> [schemas] [seed]');
const N = Number(process.argv[3] ?? 1200);
let s = (Number(process.argv[4] ?? 1) >>> 0) || 1;
const rnd = () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 4294967296; };
const pick = <T,>(a: readonly T[]): T => a[Math.floor(rnd() * a.length)]!;
const ri = (a: number, b: number) => a + Math.floor(rnd() * (b - a + 1));
// values that are WRONG as a bound (type, sign, fraction, range) or boundary values
const BADS: unknown[] = ['abc', '5', '', -1, 1.5, 0.5, -0.5, null, true, false, [], [1], {}, 4097, 1048577, 1e6, 1e21, 1e300, 2 ** 53 - 1, 'x'.repeat(600)];
const GOODS = [0, 1, 2, 3, 4, 5, 6, 10, 255, 256, 1024, 4096, 65536, 1048576];
const STRS = ['', 'a', 'ab', 'abc', 'abcd', '😀', '😀😀', '😀😀😀', 'a😀', '😀a', 'é', ' ', 'x'.repeat(300), '😀'.repeat(300), 'pre-fix', 'pre', '\u{10FFFF}', '中文', 'a'.repeat(1025)];
const NUMS = [0, 1, 2, 3, 5, 10, 11, 100, -1, -100, 1.5, 2.5, 0.1, 1e6, 2 ** 31, 2 ** 53 - 1];

function spec(depth: number): any {
  const t = pick(['string', 'string', 'string', 'number', 'integer', 'integer', 'boolean', 'array', ...(depth < 3 ? ['object', 'object'] : [])]);
  const sp: any = { type: t };
  const bound = (goodPool: readonly number[]) => (rnd() < 0.3 ? pick(BADS) : pick(goodPool));
  if (t === 'string') {
    if (rnd() < 0.55) sp.maxLength = bound([0, 1, 2, 3, 4, 5, 6]);
    if (rnd() < 0.45) sp.minLength = bound([0, 1, 2, 3, 4]);
    if (rnd() < 0.3) sp.prefix = rnd() < 0.2 ? pick(BADS) : pick(['pre', 'a', '😀', '', 'x'.repeat(513)]);
    if (rnd() < 0.2) sp.enum = [pick(STRS), pick(STRS), ...(rnd() < 0.1 ? [pick(BADS)] : [])];
    if (rnd() < 0.1) sp.const = rnd() < 0.15 ? pick(BADS) : pick(STRS);
  } else if (t === 'number' || t === 'integer') {
    if (rnd() < 0.5) sp.max = rnd() < 0.3 ? pick(BADS) : pick(NUMS);
    if (rnd() < 0.5) sp.min = rnd() < 0.3 ? pick(BADS) : pick(NUMS);
    if (rnd() < 0.12) sp.enum = [pick(NUMS), pick(NUMS), ...(rnd() < 0.1 ? [pick(BADS)] : [])];
    if (rnd() < 0.1) sp.const = rnd() < 0.2 ? pick(BADS) : pick(NUMS);
  } else if (t === 'boolean') {
    if (rnd() < 0.25) sp.const = rnd() < 0.2 ? pick(BADS) : pick([true, false]);
    if (rnd() < 0.1) sp.enum = [true, rnd() < 0.2 ? 'x' : false];
  } else if (t === 'array') {
    sp.items = spec(depth + 1);
    if (rnd() < 0.45) sp.maxItems = bound([0, 1, 2, 3, 4]);
    if (rnd() < 0.35) sp.minItems = bound([0, 1, 2, 3]);
  } else {
    sp.props = { a: spec(depth + 1), b: spec(depth + 1) };
    if (rnd() < 0.4) sp.required = pick([['a'], ['a', 'b'], ['c'], [1], 'a', [], null]);
  }
  if (rnd() < 0.015) sp.extra = 1; // unknown spec key
  return sp;
}
function value(sp: any): any {
  if (rnd() < 0.07) return pick([null, 'x', 1, true, [], {}, 2.5, '😀', -1]);
  switch (sp.type) {
    case 'string': return pick(STRS);
    case 'number': case 'integer': return pick(NUMS);
    case 'boolean': return pick([true, false]);
    case 'array': return Array.from({ length: ri(0, 5) }, () => value(sp.items));
    default: {
      const o: any = {};
      for (const k of ['a', 'b']) if (rnd() < 0.75) o[k] = value(sp.props?.[k] ?? { type: 'boolean' });
      if (rnd() < 0.04) o.zz = 1;
      return o;
    }
  }
}
const caveats: any[] = [];
const cases: Array<[number, any, boolean]> = [];
const sig = hashCanonical({ name: 'tool' });
for (let i = 0; i < N; i++) {
  const props: any = { q: spec(0), r: spec(0) };
  const schema: any = { props };
  if (rnd() < 0.3) schema.required = pick([['q'], ['q', 'r'], ['z']]);
  let cv: any;
  try {
    cv = { type: 'tool_schema', tool: 'tool', signature_digest: sig, schema, schema_digest: hashCanonical(schema), binding_digest: hashCanonical({ tool: 'tool', signature_digest: sig, schema }) };
  } catch {
    // the schema is outside the strict canonical profile (hashCanonical throws): any digest is unusable => both must deny
    cv = { type: 'tool_schema', tool: 'tool', signature_digest: sig, schema, schema_digest: 'AAAA', binding_digest: 'AAAA' };
  }
  const idx = caveats.push(cv) - 1;
  for (let j = 0; j < 4; j++) {
    const args: any = {};
    for (const k of ['q', 'r']) if (rnd() < 0.85) args[k] = value(props[k]);
    let t = false;
    try { t = agentNativeCaveatEvaluator(cv, { now: 1e12, action: { verb: 'tool', resource: 'x', params: args }, toolCall: { tool: 'tool', args } } as any); } catch { t = false; }
    cases.push([idx, args, t]);
  }
}
writeFileSync(out, JSON.stringify({ caveats, cases }) + '\n');
console.log(`schemas=${caveats.length} cases=${cases.length} TS-satisfied=${cases.filter((c) => c[2]).length} -> ${out}`);
