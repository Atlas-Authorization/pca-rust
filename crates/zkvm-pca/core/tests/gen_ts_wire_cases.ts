// R5-ZK-03/04: verdicts of the TypeScript reference for (a) the STRICT canonical profile (hash.ts `canonicalizeStrict`:
// unsafe integers, exponent / over-precise floats, -0, nesting > 32) and the exact canonical bytes when it accepts, (b) the wire
// constants (capability.ts caveat caps, pcactn.ts MAX_ARTIFACT_BYTES, hash.ts depth/digits), and (c) `matches` conditions and
// whole-document regex budgets (predicates.ts, regex-budget.ts). Output of the TS reference; NOT a standard vector.
//   nice -n 15 redteam/run.sh --tsconfig redteam/round4/tsconfig.json \
//       sdks/zkvm-pca/core/tests/gen_ts_wire_cases.ts <out.json> [random-values=3000] [seed=1]
import { writeFileSync } from 'node:fs';
import { canonicalizeStrict, MAX_JSON_DEPTH, MAX_DECIMAL_DIGITS } from '../../../../packages/pca/src/hash';
import { MAX_CAVEATS_PER_HOP, MAX_CAVEATS_PER_CHAIN } from '../../../../packages/pca/src/capability';
import { MAX_ARTIFACT_BYTES } from '../../../../packages/pca/src/pcactn';
import { evaluatePredicates } from '../../../../packages/pca/src/predicates';
import {
  MAX_REGEX_EVALUATIONS_PER_DOCUMENT, MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT, MAX_REGEX_STEPS_PER_DOCUMENT,
} from '../../../../packages/pca/src/regex-budget';

const out = process.argv[2];
if (!out) throw new Error('usage: gen_ts_wire_cases.ts <out.json> [count] [seed]');
const count = Number(process.argv[3] ?? 3000);
let seed = Number(process.argv[4] ?? 1) >>> 0;
const rnd = (): number => {
  seed = (seed + 0x6d2b79f5) >>> 0;
  let t = seed;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = <T,>(a: readonly T[]): T => a[Math.floor(rnd() * a.length)]!;
const int = (lo: number, hi: number) => lo + Math.floor(rnd() * (hi - lo + 1));

// ---- (a) strict canonical profile -------------------------------------------------------------------------------------
type Canon = { text: string; ok: boolean; canon: string | null };
const canon: Canon[] = [];
const addText = (text: string) => {
  let ok = false;
  let c: string | null = null;
  try { c = canonicalizeStrict(JSON.parse(text)); ok = true; } catch { ok = false; c = null; }
  canon.push({ text, ok, canon: c });
};
const nest = (n: number, leaf = '1') => '['.repeat(n) + leaf + ']'.repeat(n);
const nestObj = (n: number) => '{"a":'.repeat(n) + '1' + '}'.repeat(n);
const NUMTXT = [
  '0', '-0', '0.0', '-0.0', '1', '-1', '1.0', '2.5', '-2.5', '0.1', '0.5', '123456789012345', '1234567890123456', '9007199254740991', '-9007199254740991',
  '9007199254740992', '-9007199254740992', '9007199254740993', '18446744073709551615', '18446744073709551616', '-9223372036854775808', '1e2', '1E2', '1e21', '1e-7', '1e-6',
  '0.000001', '0.0000001', '0.00001', '1.5e3', '1.5e-3', '1e400', '-1e400', '0.1234567890123456', '0.123456789012345', '0.12345678901234567', '123456789.123456',
  '123456789.1234567', '12345678901234.5', '123456789012345.5', '99999999999999.9', '1e15', '1e16', '100000000000000000000', '4.35', '0.30000000000000004', '1.7976931348623157e308',
  '5e-324', '2.2250738585072014e-308', '123.456', '-123.456e0', '3.0e0', '1000000', '0.000001000000000000001',
];
for (const n of NUMTXT) { addText(n); addText(`[${n}]`); addText(`{"k":${n}}`); }
for (const n of [1, 2, 31, 32, 33, 34, 40, 100]) { addText(nest(n)); addText(nestObj(n)); }
for (const t of ['"a"', '"\\ud800"', '"\\udc00"', '"\\ud83d\\ude00"', '"é"', '"\\u0000"', '"a\\nb"', 'null', 'true', 'false', '[]', '{}', '{"b":1,"a":2}', '{"é":1,"z":2,"a":3}', '{"😀":1,"\\uffff":2}', '[1,[2,[3]]]']) addText(t);
const rnum = (): string => {
  switch (int(0, 9)) {
    case 0: return String(int(-1000, 1000));
    case 1: return String(Math.floor(rnd() * 2 ** 53) * (rnd() < 0.5 ? -1 : 1));
    case 2: return String(2 ** 53 + int(-3, 3));
    case 3: return (rnd() * 1000 - 500).toFixed(int(0, 8));
    case 4: return String(rnd() * 10 ** int(-9, 25));
    case 5: return String((rnd() - 0.5) * 10 ** int(-9, 25)) + (rnd() < 0.3 ? 'e' + int(-10, 10) : '');
    case 6: return pick(['0.1', '0.2', '0.7', '1.1', '4.35', '1e-6', '999999999999999', '0.999999999999999']);
    case 7: return (rnd() * 10).toPrecision(int(1, 20));
    case 8: return pick(['-0', '0', '-0.0', '0e0', '-0e5']);
    default: return String(Math.round(rnd() * 1e15) / 10 ** int(0, 15));
  }
};
const rval = (d: number): string => {
  const r = rnd();
  if (d > 4 || r < 0.5) return r < 0.1 ? JSON.stringify(pick(['a', 'é', '😀', 'x'.repeat(int(0, 5))])) : rnum();
  if (r < 0.75) return '[' + Array.from({ length: int(0, 3) }, () => rval(d + 1)).join(',') + ']';
  return '{' + Array.from({ length: int(0, 3) }, (_, i) => `${JSON.stringify(pick(['a', 'b', 'é', '😀', 'k' + i, 'Z']))}:${rval(d + 1)}`).join(',') + '}';
};
for (let i = 0; i < count; i++) addText(rval(0));

// ---- (b) constants ---------------------------------------------------------------------------------------------------
const constants = {
  MAX_CAVEATS_PER_HOP, MAX_CAVEATS_PER_CHAIN, MAX_ARTIFACT_BYTES, MAX_JSON_DEPTH, MAX_DECIMAL_DIGITS,
  MAX_REGEX_EVALUATIONS_PER_DOCUMENT, MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT, MAX_REGEX_STEPS_PER_DOCUMENT,
};

// ---- (c) `matches` conditions and regex-budget documents ---------------------------------------------------------------
type Doc = { id: string; predicates: unknown[]; action: unknown; allow: boolean };
const docs: Doc[] = [];
const ACT = { verb: 'read', resource: '/acct/7', params: { s: 'abc', n: 'acct_7', e: '😀', long: 'a'.repeat(512), toolong: 'a'.repeat(513) } };
const addDoc = (id: string, predicates: unknown[]) =>
  docs.push({ id, predicates, action: JSON.parse(JSON.stringify(ACT)), allow: evaluatePredicates(predicates as never, { action: ACT } as never).allowed });
const m = (field: string, value: unknown, op = 'matches') => ({ verb: '*', where: [{ field: `action.params.${field}`, op, value }] });
const rp = (re: string) => ({ verb: '*', resource: 're:' + re });
const mm = (i: number) => m('s', `zz${i}[0-9]+`); // a matches condition that misses (charged)
// single matches conditions
for (const [id, field, pat] of [
  ['lit', 's', 'abc'], ['lit-miss', 's', 'abd'], ['class', 's', '[a-c]+'], ['dotstar', 's', '.*'], ['empty', 's', ''], ['anchor', 's', '^abc$'], ['digits', 'n', 'acct_\\d+'],
  ['digits-miss', 's', '\\d+'], ['emoji-dot', 'e', '..'], ['emoji-dot1', 'e', '.'], ['emoji-lit', 'e', '😀'], ['unsafe-nested', 's', '(a+)+b'], ['backref', 's', '\\1'],
  ['lookahead', 's', '(?=a)abc'], ['4-unbounded', 's', 'a*b*c*d*'], ['long-subject', 'long', 'a*'], ['subject-513', 'toolong', 'a*'], ['pattern-200', 's', 'a'.repeat(200)],
  ['pattern-201', 's', 'a'.repeat(201)], ['astral-pattern-100', 'e', '😀'.repeat(100)], ['astral-pattern-101', 'e', '😀'.repeat(101)],
  ['missing-field', 'nope', 'a'], ['bad-class', 's', '[c-a]'], ['alt', 's', 'abc|x'], ['bounded', 's', '[a-c]{3}'], ['bounded-miss', 's', '[a-c]{4}'],
] as Array<[string, string, string]>) addDoc(`matches:${id}`, [m(field, pat)]);
addDoc('matches:value-not-string', [m('s', 5)]);
addDoc('matches:field-not-string', [m('n', 'x')].map((p) => ({ ...p, where: [{ field: 'action.verb', op: 'matches', value: 'read' }] })));
addDoc('matches:ref', [{ verb: '*', where: [{ field: 'action.params.s', op: 'matches', ref: 'action.params.s' }] }]);
// budget: 64 evaluations per document, shared by `matches` and `re:`
for (const n of [0, 10, 62, 63, 64, 65, 100]) addDoc(`budget:matches-${n}-misses-then-matches-hit`, [...Array.from({ length: n }, (_, i) => mm(i)), m('s', '[a-c]+')]);
for (const n of [0, 10, 62, 63, 64, 65, 100]) addDoc(`budget:matches-${n}-misses-then-re-hit`, [...Array.from({ length: n }, (_, i) => mm(i)), rp('/acct/[0-9]+')]);
for (const n of [0, 10, 62, 63, 64, 65, 100]) addDoc(`budget:re-${n}-misses-then-matches-hit`, [...Array.from({ length: n }, (_, i) => rp(`/nomatch/${i}/[a-z]+`)), m('s', '[a-c]+')]);
for (const n of [30, 31, 32, 33, 34]) addDoc(`budget:mixed-${n}+${n}-then-hit`, [...Array.from({ length: n }, (_, i) => mm(i)), ...Array.from({ length: n }, (_, i) => rp(`/nomatch/${i}/[a-z]+`)), rp('/acct/[0-9]+')]);
const big = '[^]{64}'.repeat(28);
for (const n of [1, 4, 5, 6, 7]) addDoc(`budget:steps-${n}-big-matches-then-dotstar`, [...Array.from({ length: n }, () => m('long', big)), m('long', '.*')]);
for (const n of [38, 39, 40, 41, 42]) addDoc(`budget:chars-${n}x200-matches-then-hit`, [...Array.from({ length: n }, (_, i) => m('s', String.fromCharCode(97 + (i % 26)) + 'q'.repeat(198) + String(i % 10))), m('s', '[a-c]+')]);
addDoc('budget:poison-order-matches', [m('long', big), m('long', big), m('long', big), m('long', big), m('long', big), m('long', big), rp('/acct/[0-9]+')]);
addDoc('budget:refused-matches-not-charged', [...Array.from({ length: 80 }, () => m('s', '(a+)+b')), rp('/acct/[0-9]+')]);
addDoc('budget:overlong-subject-not-charged', [...Array.from({ length: 80 }, () => m('toolong', 'a*')), rp('/acct/[0-9]+')]);
addDoc('budget:one-predicate-many-conditions', [{ verb: '*', where: Array.from({ length: 70 }, () => ({ field: 'action.params.s', op: 'matches', value: 'abc' })) }]);
addDoc('budget:one-predicate-63-conditions-then-re', [{ verb: '*', resource: 're:/acct/[0-9]+', where: Array.from({ length: 63 }, () => ({ field: 'action.params.s', op: 'matches', value: 'abc' })) }]);
addDoc('budget:one-predicate-64-conditions-then-re', [{ verb: '*', resource: 're:/acct/[0-9]+', where: Array.from({ length: 64 }, () => ({ field: 'action.params.s', op: 'matches', value: 'abc' })) }]);
// random single conditions over a small grammar
const ATOMS = ['a', 'b', 'c', 'ab', '[a-c]', '[^a]', '.', '\\d', '\\w', 'x', '😀', '_'];
const QS = ['', '', '', '*', '+', '?', '{2}', '{1,3}'];
for (let i = 0; i < 400; i++) {
  const pat = Array.from({ length: int(0, 4) }, () => pick(ATOMS) + pick(QS)).join(pick(['', '', '|']));
  const subj = Array.from({ length: int(0, 6) }, () => pick(['a', 'b', 'c', 'ab', 'x', '1', '😀', '_', '-'])).join('');
  ACT.params.s = subj;
  addDoc(`matches:rand${i}`, [m('s', pat)]);
}
ACT.params.s = 'abc';
writeFileSync(out, JSON.stringify({ constants, canon, docs }) + '\n');
console.log(`canon=${canon.length} (ok ${canon.filter((c) => c.ok).length}) docs=${docs.length} (allow ${docs.filter((d) => d.allow).length}) -> ${out}`);
