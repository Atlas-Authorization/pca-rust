// R4-02: verdicts of the TypeScript reference (predicates.ts `resourceMatches` via `evaluatePredicates`: isSafeRegexSource +
// the R3-02 linear-time NFA) on a `re:` pattern x resource corpus, for the Rust guest's differential test
// (core/tests/r4_regex_differential.rs).  Output of the TS reference implementation; NOT an official standard vector.
//
//   nice -n 15 redteam/run.sh --tsconfig redteam/round4/tsconfig.json \
//       sdks/zkvm-pca/core/tests/gen_ts_regex_cases.ts <out.json> [generated-count=3000] [seed=1]
//
// The committed fixtures/ts_regex_cases.json uses the defaults; the 100k run is `... /tmp/regex100k.json 100000 7`
// followed by `PCA_REGEX_CASES=/tmp/regex100k.json cargo test -p pca-zkvm-core --release --test r4_regex_differential`.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateCaveats, evaluatePredicates } from '../../../../packages/pca/src/predicates';
import { agentNativeCaveatEvaluator } from '../../../../packages/pca/src/agent-native';

const here = dirname(fileURLToPath(import.meta.url));
const out = process.argv[2];
if (!out) throw new Error('usage: gen_ts_regex_cases.ts <out.json> [count] [seed]');
const count = Number(process.argv[3] ?? 3000);
let seed = Number(process.argv[4] ?? 1) >>> 0;

const ts = (pattern: string, resource: string): boolean =>
  evaluatePredicates([{ verb: '*', resource: 're:' + pattern }] as never, { action: { verb: 'read', resource } } as never).allowed;

// mulberry32
const rnd = (): number => {
  seed = (seed + 0x6d2b79f5) >>> 0;
  let t = seed;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = <T>(a: readonly T[]): T => a[Math.floor(rnd() * a.length)]!;
const int = (lo: number, hi: number) => lo + Math.floor(rnd() * (hi - lo + 1));

const cases: Array<{ id: string; pattern?: string; predicates?: unknown[]; caveats?: unknown[]; resource: string; allow: boolean }> = [];
const add = (id: string, pattern: string, resource: string) => cases.push({ id, pattern, resource, allow: ts(pattern, resource) });

// 1. the 17 round-4 PoC cases
for (const c of JSON.parse(readFileSync(join(here, '../../../../redteam/round4/zk/regex-cases.json'), 'utf8')) as Array<{ id: string; pattern: string; resource: string }>) {
  add('poc:' + c.id, c.pattern, c.resource);
}

// 2. hand-written corpus: semantics the Rust `regex` crate got wrong, subset edges, refusals, budgets
const hand: Array<[string, string, string]> = [
  ['digit-ascii', '\\d+', '123'], ['digit-ascii-neg', '\\d+', '12a'], ['digit-fullwidth', '\\d', '５'], ['digit-arabic', '\\d+', '١٢٣'],
  ['word-underscore', '\\w+', 'a_1'], ['word-accent', '\\w+', 'é'], ['word-k-sign', '\\w', 'K'], ['word-long-s', '\\w', 'ſ'],
  ['space-nbsp', 'a\\sb', 'a b'], ['space-nel', 'a\\sb', 'a\u0085b'], ['space-bom', 'a\\sb', 'a﻿b'], ['space-vt', 'a\\sb', 'a\u000bb'],
  ['dot-lf', '.', '\n'], ['dot-cr', '.', '\r'], ['dot-ls', '.', ' '], ['dot-ps', '.', ' '], ['dot-nel', '.', '\u0085'], ['dot-tab', '.', '\t'],
  ['astral-dot-1', '.', '😀'], ['astral-dot-2', '..', '😀'], ['astral-class', '[^a]{2}', '😀'], ['astral-literal', '😀', '😀'], ['astral-literal-star', '😀*', '😀😀'],
  ['astral-range', '[😀]', '😀'], ['astral-lit-neg', 'x😀y', 'x😀y'],
  ['caret-in-mid', 'a^b', 'ab'], ['dollar-mid', 'a$b', 'ab'], ['caret-only', '^', ''], ['dollar-only', '$', ''], ['bol-alt', '^a|b$', 'b'], ['quantified-bol', '^*', ''],
  ['empty-pattern', '', ''], ['empty-pattern-nonempty', '', 'a'], ['empty-alt', 'a|', ''], ['empty-alt2', '|a', 'a'], ['empty-group-star', '()*', ''],
  ['empty-class', '[]', ''], ['empty-class-a', 'a[]', 'a'], ['any-class', '[^]', '\n'], ['any-class-2', '[^]+', 'a\r\n '],
  ['class-range', '[a-c]+', 'abcabc'], ['class-range-bad', '[c-a]', 'b'], ['class-escape-range', '[\\d-x]+', '1-x'], ['class-escape-range2', '[a-\\d]+', 'a-1'],
  ['class-neg-d', '[\\D]+', 'abc'], ['class-neg-d-digit', '[\\D]', '1'], ['class-neg-w', '[\\W]', '_'], ['class-neg-s', '[\\S]+', 'ab'],
  ['class-backspace', '[\\b]', '\b'], ['class-dash-first', '[-a]+', '-a-'], ['class-dash-last', '[a-]+', 'a-'], ['class-caret-late', '[a^]+', '^a'],
  ['class-bracket-escape', '[\\]]', ']'], ['class-unterminated', '[a', 'a'], ['class-lone-close', 'a]', 'a]'], ['brace-lone-close', 'a}', 'a}'],
  ['esc-hex', '\\x41', 'A'], ['esc-hex-bad', '\\x4', 'A'], ['esc-uni', '\\u0041', 'A'], ['esc-uni-bad', '\\u004', 'A'], ['esc-uni-brace', '\\u{41}', 'A'],
  ['esc-ctrl', '\\cJ', '\n'], ['esc-ctrl-bad', '\\c1', 'x'], ['esc-nul', '\\0', '\u0000'], ['esc-octal', '\\00', '\u0000'], ['esc-octal2', '\\01', '\u0001'],
  ['esc-t', '\\t', '\t'], ['esc-v', '\\v', '\u000b'], ['esc-f', '\\f', '\f'], ['esc-n', '\\n', '\n'], ['esc-r', '\\r', '\r'],
  ['esc-punct', '\\.', '.'], ['esc-punct-nomatch', '\\.', 'a'], ['esc-slash', '\\/', '/'], ['esc-dash', '\\-', '-'], ['esc-underscore', '\\_', '_'],
  ['esc-letter', '\\a', 'a'], ['esc-digit', '\\1', '\u0001'], ['esc-trailing', 'a\\', 'a\\'], ['esc-k', '\\k<n>', 'k'], ['esc-B', '\\B', ''],
  ['wordb', '\\bfoo\\b', 'foo'], ['wordb-class', '[\\b]', '\b'], ['flag-i', '(?i)ABC', 'abc'], ['flag-s', '(?s)a.b', 'a\nb'], ['flag-m', '(?m)^a$', 'a'],
  ['lookahead', 'a(?=b)', 'a'], ['neg-lookahead', 'a(?!b)', 'a'], ['lookbehind', '(?<=a)b', 'b'], ['named', '(?<n>a)', 'a'], ['named-p', '(?P<n>a)', 'a'],
  ['noncapture', '(?:ab)+', 'abab'], ['group', '(ab)+', 'abab'], ['group-quant-inner', '(a+)+b', 'aaab'], ['group-alt-quant', '(a|b)+', 'abab'],
  ['group-alt-noquant', '(a|b)', 'a'], ['group-then-star-nonquant', '(ab)*', 'abab'], ['nested-group', '((a))', 'a'], ['unbalanced-open', '(a', 'a'], ['unbalanced-close', 'a)', 'a'],
  ['unicode-prop', '\\p{L}+', 'abc'], ['posix', '[[:alpha:]]+', 'abc'], ['posix-lit', '[[:alpha:]]', ':'],
  ['quant-star', 'a*', ''], ['quant-plus', 'a+', ''], ['quant-opt', 'a?', 'a'], ['quant-lazy', 'a+?', 'aaa'], ['quant-lazy-opt', 'a??', 'a'],
  ['quant-brace', 'a{3}', 'aaa'], ['quant-brace-short', 'a{3}', 'aa'], ['quant-brace-open', 'a{2,}', 'aaaa'], ['quant-brace-range', 'a{2,3}', 'aaa'],
  ['quant-brace-range-over', 'a{2,3}', 'aaaa'], ['quant-brace-zero', 'a{0}', ''], ['quant-brace-zero-a', 'a{0}', 'a'], ['quant-brace-64', 'a{64}', 'a'.repeat(64)],
  ['quant-brace-65', 'a{65}', 'a'.repeat(65)], ['quant-brace-0-64', 'a{0,64}', 'a'.repeat(64)], ['quant-brace-0-65', 'a{0,65}', 'a'], ['quant-brace-4digit', 'a{1000}', 'a'],
  ['quant-brace-5digit', 'a{10000}', 'a'], ['quant-brace-rev', 'a{3,2}', 'aaa'], ['quant-brace-comma-first', 'a{,2}', 'a'], ['quant-brace-lone', 'a{', 'a{'], ['quant-brace-lit', '{', '{'],
  ['quant-brace-text', 'a{x}', 'a{x}'], ['quant-brace-space', 'a{1, 2}', 'a'], ['quant-brace-lazy', 'a{1,2}?', 'aa'], ['quant-double', 'a**', 'a'], ['quant-star-plus', 'a*+', 'a'],
  ['quant-lead', '*a', 'a'], ['quant-lead-plus', '+a', 'a'], ['quant-lead-q', '?a', 'a'], ['quant-after-alt', 'a|*', 'a'], ['quant-after-group-open', '(*a)', 'a'],
  ['quant-lazy-star-lazy', 'a*??', 'a'], ['unbounded-3', 'a*b*c*', 'abc'], ['unbounded-4', 'a*b*c*d*', 'abcd'], ['bits-22', 'a?b?c?d?e?f?g?h?i?j?k?l?m?n?o?p?q?r?s?t?u?v?', 'abc'],
  ['bits-23', 'a?b?c?d?e?f?g?h?i?j?k?l?m?n?o?p?q?r?s?t?u?v?w?', 'abc'], ['alt-many', 'a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w', 'w'], ['alt-22', 'a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w'.slice(0, 43), 'v'],
  ['path-1', '/acct/[^/]+/items/\\d+', '/acct/xyz/items/42'], ['path-2', '/acct/[^/]+/items/\\d+', '/acct/xyz/items/4x'], ['path-3', '(?:GET|POST) /x', 'POST /x'],
  ['path-4', '/files/.*', '/files/a/b/c'], ['path-5', '/files/.*', '/files/a\nb'], ['path-6', '/u/[a-z0-9_]{3,16}', '/u/ab_1'], ['path-7', '/u/[a-z0-9_]{3,16}', '/u/ab'],
  ['dot-star-dot-star', '.*a.*b.*', 'xaxbx'], ['long-subject', 'a*', 'a'.repeat(512)], ['over-subject', 'a*', 'a'.repeat(513)],
  ['budget-ok', '[^]{64}[^]{64}[^]{64}[^]{64}[^]{64}[^]{64}[^]{64}[^]{64}', 'a'.repeat(512)], ['budget-over', ('[^]{64}'.repeat(24) + '.*'), 'a'.repeat(512)],
  ['src-200', 'a'.repeat(200), 'a'.repeat(200)], ['src-201', 'a'.repeat(201), 'a'.repeat(201)], ['src-200-astral', '😀'.repeat(100), '😀'.repeat(100)], ['src-202-astral', '😀'.repeat(101), '😀'.repeat(101)],
  ['plain', '/acct/[0-9]+', '/acct/123'], ['plain-deny', '/acct/[0-9]+', '/acct/12x'], ['dollar-end', 'abc$', 'abc'], ['caret-start', '^abc', 'abc'],
  ['anchors-both-in-alt', '^(?:a|b)$', 'a'],
];
for (const [id, p, s] of hand) add('hand:' + id, p, s);


// 2b. R4-05 mirror: whole-document regex budget (64 evaluations, 8192 source chars, 5M NFA steps; poisoned scope). Documents are
// predicate lists (evaluatePredicates) and caveat lists of `predicates` caveats (evaluateCaveats with the agent-native evaluator).
const addDoc = (id: string, predicates: unknown[], resource: string) =>
  cases.push({ id: 'doc:' + id, predicates, resource, allow: evaluatePredicates(predicates as never, { action: { verb: 'read', resource } } as never).allowed });
const addCaveatDoc = (id: string, caveats: unknown[], resource: string) =>
  cases.push({ id: 'cdoc:' + id, caveats, resource, allow: evaluateCaveats(caveats as never, { now: 1e12, action: { action: { verb: 'read', resource } } } as never, agentNativeCaveatEvaluator as never).ok });
const rp = (re: string) => ({ verb: '*', resource: 're:' + re });
const miss = (i: number) => rp(`/nomatch/${i}/[a-z]+`);
for (const n of [0, 10, 62, 63, 64, 65, 100]) addDoc(`evals-${n}-misses-then-hit`, [...Array.from({ length: n }, (_, i) => miss(i)), rp('/acct/[0-9]+')], '/acct/7');
addDoc('evals-64-misses-no-hit', Array.from({ length: 64 }, (_, i) => miss(i)), '/acct/7');
const big = '[^]{64}'.repeat(28); // 1793 instructions
for (const n of [1, 4, 5, 6, 7]) addDoc(`steps-${n}-big-then-dotstar`, [...Array.from({ length: n }, () => rp(big)), rp('.*')], 'a'.repeat(512));
for (const n of [38, 39, 40, 41, 42]) addDoc(`chars-${n}x200-then-hit`, [...Array.from({ length: n }, (_, i) => rp(String.fromCharCode(97 + (i % 26)) + 'q'.repeat(198) + String(i % 10))), rp('/acct/[0-9]+')], '/acct/7');
addDoc('poison-order', [rp(big), rp(big), rp(big), rp(big), rp(big), rp(big), rp('/acct/[0-9]+')], '/acct/7');
addDoc('refused-patterns-are-not-charged', [...Array.from({ length: 80 }, () => rp('(a+)+b')), rp('/acct/[0-9]+')], '/acct/7');
addDoc('cap-not-hit-by-plain-prefix', [...Array.from({ length: 200 }, (_, i) => ({ verb: '*', resource: `/p${i}/*` })), rp('/acct/[0-9]+')], '/acct/7');
for (const n of [63, 64, 65, 70]) addCaveatDoc(`pred-caveats-${n}`, Array.from({ length: n }, () => ({ type: 'predicates', allow: [rp('/x/[0-9]+')] })), '/x/1');
addCaveatDoc('two-caveats-40-patterns-each', [0, 1].map(() => ({ type: 'predicates', allow: [...Array.from({ length: 40 }, (_, i) => miss(i)), rp('/x/[0-9]+')] })), '/x/1');
addCaveatDoc('two-caveats-31-patterns-each', [0, 1].map(() => ({ type: 'predicates', allow: [...Array.from({ length: 31 }, (_, i) => miss(i)), rp('/x/[0-9]+')] })), '/x/1');

// 3. generated: grammar over the supported subset + refused constructs; subjects from a hostile alphabet
// [pattern, a string that tends to match it]
const ATOMS: Array<[string, string]> = [['a', 'a'], ['b', 'b'], ['c', 'c'], ['0', '0'], ['1', '1'], ['-', '-'], ['/', '/'], ['_', '_'], [' ', ' '], ['é', 'é'], ['😀', '😀'],
  ['\\d', '7'], ['\\D', 'x'], ['\\w', 'w'], ['\\W', '-'], ['\\s', ' '], ['\\S', 'z'], ['.', 'q'], ['[abc]', 'b'], ['[^a]', 'b'], ['[a-c]', 'c'], ['[0-9_]', '_'], ['[\\d_]', '3'],
  ['[^\\s]', 'k'], ['[\\w-]', '-'], ['[^]', '\n'], ['[]', ''], ['\\.', '.'], ['\\t', '\t'], ['\\n', '\n'], ['\\x41', 'A'], ['\\u00e9', 'é'], ['^', ''], ['$', '']];
const REFUSED = ['\\b', '\\B', '(?i)', '\\p{L}', '(?=a)', '(?!a)', '(?<n>a)', '\\1', '\\k<n>', '[[:alpha:]]', '{,2}', 'a{', '\\q', '\\c1', '\\x4', '(a', 'a)', '[a', '*', '+a', '\\00', '(?s)'];
const SUBJ = ['a', 'b', 'c', 'A', '0', '1', '9', '-', '/', '_', ' ', '\t', '\n', '\r', ' ', ' ', '\u0085', ' ', 'é', '中', '١', '😀', '.', 'x', 'B', '﻿', 'K', 'ſ'];
const QUANT: Array<[string, number, number]> = [['*', 0, 3], ['+', 1, 3], ['?', 0, 1], ['{2}', 2, 2], ['{1,3}', 1, 3], ['{0,2}', 0, 2], ['{2,}', 2, 4], ['*?', 0, 3], ['+?', 1, 3], ['??', 0, 1], ['{3}?', 3, 3]];
function genPattern(depth: number): [string, string] {
  const nAlt = rnd() < 0.2 ? int(2, 3) : 1;
  const alts: Array<[string, string]> = [];
  for (let a = 0; a < nAlt; a++) {
    let p = '';
    let m = '';
    const n = int(0, 5);
    for (let i = 0; i < n; i++) {
      let atom: [string, string];
      const r = rnd();
      if (r < 0.12 && depth < 3) {
        const [ip, im] = genPattern(depth + 1);
        atom = [(rnd() < 0.5 ? '(?:' : '(') + ip + ')', im];
      } else if (r < 0.14) atom = [pick(REFUSED), 'a'];
      else atom = pick(ATOMS);
      p += atom[0];
      if (rnd() < 0.3) {
        const [q, lo, hi] = pick(QUANT);
        p += q;
        m += atom[1].repeat(int(lo, hi));
      } else m += atom[1];
    }
    alts.push([p, m]);
  }
  const chosen = pick(alts);
  return [alts.map((x) => x[0]).join('|'), chosen[1]];
}
function mutate(s: string): string {
  const u = [...s];
  const k = int(0, 3);
  if (k === 0 || u.length === 0) u.splice(int(0, u.length), 0, pick(SUBJ));
  else if (k === 1) u.splice(int(0, u.length - 1), 1);
  else if (k === 2) u[int(0, u.length - 1)] = pick(SUBJ);
  else u.push(pick(SUBJ));
  return u.join('');
}
function genSubject(): string {
  let s = '';
  const n = int(0, 8);
  for (let i = 0; i < n; i++) s += pick(SUBJ);
  return s;
}
for (let i = 0; i < count; i++) {
  const [p, m] = genPattern(0);
  add('gen:' + i + 'm', p, m);
  add('gen:' + i + 'x', p, mutate(m));
  if (i % 3 === 0) add('gen:' + i + 'r', p, genSubject());
}

writeFileSync(out, JSON.stringify(cases) + '\n');
const allow = cases.filter((c) => c.allow).length;
console.log(`cases=${cases.length} allow=${allow} deny=${cases.length - allow} -> ${out}`);
