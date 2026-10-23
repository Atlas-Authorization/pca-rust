// Intent Layer v2 W-B (rules 16, 17, 18 and their composition): verdicts of the TypeScript reference that the guest's
// `oracle_facts` / `offer_set` / `param_provenance` / `label_receipts` / `intent_classifier` modules must reproduce.
// Output of the TS reference; NOT a standard vector (the conformance `primitives.intent_world` / `intent_provenance` /
// `intent_classifier` vectors come from packages/pca/scripts/gen-conformance-intent-wb.mjs and are read by the Rust test
// directly). These are EXTRA cases: one mutation per step of rules 16-18, boundaries, malformed shapes, and the
// decideIntentWB composition (first failing check ends W-B; a provenance question continues to rule 18).
//     packages/pca/node_modules/.bin/tsx sdks/zkvm-pca/core/tests/gen_ts_v2_wb.ts sdks/zkvm-pca/fixtures/ts_v2_wb.json
import { writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { b64u, hashCanonical } from '../../../../packages/pca/src/hash';
import { publicKeyOf } from '../../../../packages/pca/src/keys';
import { mlDsa65Keygen, mlDsa87Keygen, slhDsa128fKeygen, suitePqPublicKey } from '../../../../packages/pca/src/pq';
import { decideIntentWorld, factRef, signFact } from '../../../../packages/pca/src/oracle-facts';
import { offerSetRef, signOfferSet } from '../../../../packages/pca/src/offer-set';
import { decideParamProvenance } from '../../../../packages/pca/src/param-provenance';
import { labelsRef, signLabels } from '../../../../packages/pca/src/label-receipts';
import { classifierContentDigest, classifierVerdictRef, decideClassifierDimensions, signClassifierVerdict } from '../../../../packages/pca/src/intent-classifier';
import { decideIntentWB } from '../../../../packages/pca/src/intent-env';

const out = process.argv[2];
if (!out) throw new Error('usage: gen_ts_v2_wb.ts <out.json>');
type J = any; // eslint-disable-line @typescript-eslint/no-explicit-any

const seed = (l: string) => new Uint8Array(createHash('sha256').update(`atlas-pca-zkvm-v2wb/${l}`).digest());
const mk = (l: string) => { const sk = seed(l); return { sk, pk: b64u(publicKeyOf(sk)) }; };
const clone = (x: J): J => (x === undefined ? undefined : JSON.parse(JSON.stringify(x)));
const NOW = 1_800_000_000_000;
const AUD = 'skyair.example';
const SESSION = b64u(seed('session'));
const OTHER_SESSION = b64u(seed('other-session'));
const O = [mk('oracle-1'), mk('oracle-2'), mk('oracle-3'), mk('oracle-4')];
const ROGUE = mk('rogue');
const SITE = mk('site');
const GOV = mk('gov');
const JD = [mk('judge-1'), mk('judge-2'), mk('judge-3')];
const D32 = (l: string) => b64u(seed(`d/${l}`));
// ---- signature suites. The guest implements ed25519, ML-DSA-65/87, SLH-DSA-SHA2-128f/256s and their hybrids (incl. the
// nested hybrid); FN-DSA / LESS / unknown are `unsupported_suite` there. Cases whose artifact names a suite the GUEST does
// not implement are marked `guest_unsupported: true`: the guest must fail them with a reason containing unsupported_suite.
const seedN = (l: string, n: number) => { const out = new Uint8Array(n); for (let i = 0; i < n; i += 32) out.set(seed(`${l}/${i}`).slice(0, Math.min(32, n - i)), i); return out; };
const KEYS: J = { mlDsa: mlDsa65Keygen(seed('mldsa65')), mlDsa87: mlDsa87Keygen(seed('mldsa87')), slhDsa: slhDsa128fKeygen(seedN('slh128f', 48)) };
const OTHER_KEYS: J = { mlDsa: mlDsa65Keygen(seed('mldsa65-other')), mlDsa87: mlDsa87Keygen(seed('mldsa87-other')), slhDsa: slhDsa128fKeygen(seedN('slh128f-other', 48)) };
const PQ_ALGS = ['ml-dsa-65', 'ml-dsa-87', 'hybrid-ed25519-ml-dsa-65', 'hybrid-nested-ed25519-ml-dsa-65', 'slh-dsa-sha2-128f', 'hybrid-ed25519-slh-dsa-sha2-128f'];
const suite = (alg: string, keys: J = KEYS) => ({ alg, ...keys }) as J;
const pqPk = (alg: string, keys: J = KEYS) => suitePqPublicKey(alg, keys)!;
const GUEST_UNSUPPORTED = ['less-cat1', 'hybrid-ed25519-less-cat1']; // FN-DSA: implemented (fn-dsa-vrfy)
// a structurally plausible artifact naming a suite the guest lacks (the TS then fails it on the signature or the suite)
const fakeSuite = (a: J, alg: string) => ({ ...a, alg, pq_pk: D32('fake-pq-pk') });
let guestUnsupported = false;
const gu = <T,>(f: () => T): T => { guestUnsupported = true; try { return f(); } finally { guestUnsupported = false; } };
const mark = (o: J) => (guestUnsupported ? { ...o, guest_unsupported: true } : o);
// a reference that TS cannot compute (non-strict artifact) is replaced by an unrelated digest: such an artifact can never match
const safe = (f: (x: J) => string) => (x: J) => { try { return f(x); } catch { return D32('unreferenceable'); } };

// ------------------------------------------------------------------ rule 16
const world: J[] = [];
const addW = (name: string, input: J) => {
  const r = decideIntentWorld(clone(input));
  world.push(mark({ name: 'w-' + name, input: clone(input), expect: r.ok ? { ok: true, world: r.world, single_source: r.single_source } : { ok: false, reason: r.reason } }));
};
const fact = (i: number, name: string, value: J, t_obs = NOW - 1_000, subject = 'OF-2', kid = `o${i + 1}`, key = O[i]!) => signFact({ name, subject, value, t_obs, oracle: kid } as J, key.sk) as J;
const oracles = (n = 3) => O.slice(0, n).map((o, i) => ({ kid: `o${i + 1}`, pk: o.pk }));
const fareWorld = (over: J = {}) => ({ name: 'fare', subject_path: 'action.params.offer_id', oracles: oracles(), freshness_ms: 60_000, min_oracles: 3, max_faulty: 1, ...over });
const ACTION = { verb: 'air.book', resource: 'skyair.example/bookings', params: { offer_id: 'OF-2', total: 77_800, quote: 38_900, pax: 2, nested: { id: 'OF-2' }, big: 9_007_199_254_740_991, zero: 0 } };
const W = (facts: J[], policy: J, over: J = {}) => ({ now: NOW, aud: AUD, session: SESSION, action: ACTION, committed: { facts: facts.map(safe(factRef)) }, facts, policy, ...over });
const three = () => [fact(0, 'fare', 39_800), fact(1, 'fare', 39_900), fact(2, 'fare', 1)];
const base = () => W(three(), { worlds: [fareWorld()] });
const rel = (r: J[], over: J = {}) => W([], { relational: r }, over);

addW('baseline', base());
addW('policy-null', { ...base(), policy: null, committed: {}, facts: [] });
addW('policy-number', { ...base(), policy: 5 });
addW('policy-array', { ...base(), policy: [] });
for (const s of [-1, 1.5, '5', null, 0, 9_007_199_254_740_991]) addW(`skew-${JSON.stringify(s)}`, W(three(), { skew_ms: s, worlds: [fareWorld()] }));
addW('worlds-null', W([], { worlds: null }));
addW('worlds-object', W([], { worlds: {} }));
addW('worlds-17', W([], { worlds: Array.from({ length: 17 }, (_, i) => fareWorld({ name: `w${i}` })) }));
addW('world-not-object', W([], { worlds: [5] }));
addW('world-name-upper', W(three(), { worlds: [fareWorld({ name: 'Fare' })] }));
addW('world-name-64', W([], { worlds: [fareWorld({ name: 'a'.repeat(64), min_oracles: 1, max_faulty: 0 })] }));
addW('world-name-65', W([], { worlds: [fareWorld({ name: 'a'.repeat(65) })] }));
addW('world-name-digit-first', W([], { worlds: [fareWorld({ name: '1a' })] }));
addW('world-dup-name', W(three(), { worlds: [fareWorld(), fareWorld()] }));
addW('world-subject-path-bad', W(three(), { worlds: [fareWorld({ subject_path: 'params.offer_id' })] }));
addW('world-subject-resource', W([fact(0, 'fare', 5, NOW - 1_000, 'skyair.example/bookings')], { worlds: [fareWorld({ subject_path: 'action.resource', min_oracles: 1, max_faulty: 0 })] }));
addW('world-subject-verb', W([fact(0, 'fare', 5, NOW - 1_000, 'air.book')], { worlds: [fareWorld({ subject_path: 'action.verb', min_oracles: 1, max_faulty: 0 })] }));
addW('world-subject-nested', W([fact(0, 'fare', 5)], { worlds: [fareWorld({ subject_path: 'action.params.nested.id', min_oracles: 1, max_faulty: 0 })] }));
addW('world-subject-other-root', W([fact(0, 'fare', 5)], { worlds: [fareWorld({ subject_path: 'action.offer_id', min_oracles: 1, max_faulty: 0 })] }));
addW('world-subject-number', W([fact(0, 'fare', 5, NOW - 1_000, '77800')], { worlds: [fareWorld({ subject_path: 'action.params.total', min_oracles: 1, max_faulty: 0 })] }));
for (const f of [-1, 1.5, '60000']) addW(`world-freshness-${JSON.stringify(f)}`, W(three(), { worlds: [fareWorld({ freshness_ms: f })] }));
addW('world-freshness-0-exact', W([fact(0, 'fare', 5, NOW)], { worlds: [fareWorld({ freshness_ms: 0, min_oracles: 1, max_faulty: 0 })] }));
addW('world-freshness-0-stale', W([fact(0, 'fare', 5, NOW - 1)], { worlds: [fareWorld({ freshness_ms: 0, min_oracles: 1, max_faulty: 0 })] }));
for (const f of [-1, 0.5, null]) addW(`world-max-faulty-${JSON.stringify(f)}`, W(three(), { worlds: [fareWorld({ max_faulty: f })] }));
for (const m of [0, 1.5, '3', 4]) addW(`world-min-oracles-${JSON.stringify(m)}`, W(three(), { worlds: [fareWorld({ min_oracles: m, max_faulty: 0 })] }));
addW('world-min-oracles-huge', W(three(), { worlds: [fareWorld({ min_oracles: 9_007_199_254_740_991, max_faulty: 4_503_599_627_370_495 })] }));
addW('world-oracles-not-array', W(three(), { worlds: [fareWorld({ oracles: {} })] }));
addW('world-oracle-dup-kid', W(three(), { worlds: [fareWorld({ oracles: [...oracles(), { kid: 'o1', pk: O[3]!.pk }] })] }));
addW('world-oracle-bad-pk', W(three(), { worlds: [fareWorld({ oracles: [...oracles(2), { kid: 'o3', pk: 'abc' }] })] }));
addW('world-oracle-kid-65', W(three(), { worlds: [fareWorld({ oracles: [...oracles(2), { kid: 'k'.repeat(65), pk: O[2]!.pk }] })] }));
addW('world-oracle-kid-empty', W(three(), { worlds: [fareWorld({ oracles: [...oracles(2), { kid: '', pk: O[2]!.pk }] })] }));
addW('world-oracle-not-object', W(three(), { worlds: [fareWorld({ oracles: [...oracles(), 'x'] })] }));
addW('world-extra-pins-ok', W(three(), { worlds: [fareWorld({ oracles: oracles(4) })] }));
// relational policy
addW('rel-null', W([], { relational: null }));
addW('rel-object', W([], { relational: {} }));
addW('rel-17', rel(Array.from({ length: 17 }, (_, i) => ({ name: `r${i}`, fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }))));
addW('rel-16', rel(Array.from({ length: 16 }, (_, i) => ({ name: `r${i}`, fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }))));
addW('rel-not-object', rel([null]));
addW('rel-bad-fn', rel([{ name: 'r', fn: 'add', a: 'action.params.total', b: 'action.params.quote' }]));
addW('rel-self-ref', rel([{ name: 'r', fn: 'sub', a: 'env.world.r', b: 'action.params.quote' }]));
addW('rel-earlier-rel', rel([{ name: 'r', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }, { name: 's', fn: 'sub', a: 'env.world.r', b: 'action.params.quote' }]));
addW('rel-unknown-world', rel([{ name: 'r', fn: 'sub', a: 'env.world.nope', b: 'action.params.quote' }]));
addW('rel-9-segments', rel([{ name: 'r', fn: 'sub', a: 'action.params.a.b.c.d.e.f.g.h.i', b: 'action.params.quote' }]));
addW('rel-8-segments-missing', rel([{ name: 'r', fn: 'sub', a: 'action.params.a.b.c.d.e.f.g.h', b: 'action.params.quote' }]));
addW('rel-proto-segment', rel([{ name: 'r', fn: 'sub', a: 'action.params.__proto__', b: 'action.params.quote' }]));
addW('rel-operand-number', rel([{ name: 'r', fn: 'sub', a: 5, b: 'action.params.quote' }]));
addW('rel-operand-env-other', rel([{ name: 'r', fn: 'sub', a: 'env.canon.x', b: 'action.params.quote' }]));
addW('rel-sub-max', rel([{ name: 'r', fn: 'sub', a: 'action.params.big', b: 'action.params.zero' }]));
addW('rel-sub-neg-overflow', rel([{ name: 'r', fn: 'sub', a: 'action.params.neg', b: 'action.params.one' }], { action: { ...ACTION, params: { ...ACTION.params, neg: -9_007_199_254_740_991, one: 1 } } }));
addW('rel-sub-neg-max', rel([{ name: 'r', fn: 'sub', a: 'action.params.neg', b: 'action.params.zero' }], { action: { ...ACTION, params: { ...ACTION.params, neg: -9_007_199_254_740_991 } } }));
addW('rel-sub-zero', rel([{ name: 'r', fn: 'sub', a: 'action.params.zero', b: 'action.params.zero' }]));
addW('rel-ratio-max', rel([{ name: 'r', fn: 'ratio_ppm', a: 'action.params.big', b: 'action.params.m' }], { action: { ...ACTION, params: { ...ACTION.params, m: 1_000_000 } } }));
addW('rel-ratio-exact-safe', rel([{ name: 'r', fn: 'ratio_ppm', a: 'action.params.x', b: 'action.params.one' }], { action: { ...ACTION, params: { ...ACTION.params, x: 9_007_199_254, one: 1 } } }));
addW('rel-ratio-floor', rel([{ name: 'r', fn: 'ratio_ppm', a: 'action.params.x', b: 'action.params.y' }], { action: { ...ACTION, params: { ...ACTION.params, x: 1, y: 3 } } }));
addW('rel-ratio-a-zero', rel([{ name: 'r', fn: 'ratio_ppm', a: 'action.params.zero', b: 'action.params.quote' }]));
addW('rel-ratio-neg-b', rel([{ name: 'r', fn: 'ratio_ppm', a: 'action.params.total', b: 'action.params.n' }], { action: { ...ACTION, params: { ...ACTION.params, n: -2 } } }));
addW('rel-operand-float', rel([{ name: 'r', fn: 'sub', a: 'action.params.f', b: 'action.params.quote' }], { action: { ...ACTION, params: { ...ACTION.params, f: 1.5 } } }));
addW('rel-operand-unsafe', rel([{ name: 'r', fn: 'sub', a: 'action.params.f', b: 'action.params.quote' }], { action: { ...ACTION, params: { ...ACTION.params, f: 9_007_199_254_740_992 } } }));
addW('rel-operand-bool', rel([{ name: 'r', fn: 'sub', a: 'action.params.f', b: 'action.params.quote' }], { action: { ...ACTION, params: { ...ACTION.params, f: true } } }));
addW('rel-operand-world-string', W([fact(0, 'fare', 'gold')], { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0 })], relational: [{ name: 'r', fn: 'sub', a: 'env.world.fare', b: 'action.params.quote' }] }));
addW('rel-params-null', rel([{ name: 'r', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }], { action: { ...ACTION, params: null } }));
addW('rel-action-null', rel([{ name: 'r', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }], { action: null }));
addW('rel-params-array', rel([{ name: 'r', fn: 'sub', a: 'action.params.0', b: 'action.params.1' }], { action: { ...ACTION, params: [1, 2] } }));
// committed / supplied
addW('committed-null', { ...base(), committed: null, policy: {} });
addW('committed-facts-null', { ...base(), committed: { facts: null }, policy: {} });
addW('committed-17', { ...base(), committed: { facts: Array.from({ length: 17 }, (_, i) => D32(`c${i}`)) } });
addW('committed-16-unsupplied', { ...base(), committed: { facts: Array.from({ length: 16 }, (_, i) => D32(`c${i}`)) } });
addW('committed-padded-digest', { ...base(), committed: { facts: [factRef(three()[0]) + 'A'] } });
addW('committed-number', { ...base(), committed: { facts: [5] } });
addW('committed-offer-null', { ...W([], {}), committed: { offer_set: null } });
addW('committed-offer-bad', { ...W([], {}), committed: { offer_set: 'abc' } });
addW('committed-offer-no-policy', { ...W([], {}), committed: { offer_set: D32('o') } });
addW('facts-number', { ...W([], {}), facts: 5 });
addW('facts-object', { ...W([], {}), facts: {} });
addW('facts-string', { ...W([], {}), facts: 'abc' });
addW('facts-null', { ...W([], {}), facts: null });
addW('facts-junk-uncommitted', { ...base(), facts: [...three(), 5, null, 'x', { v: 1 }] });
const malformed = (name: string, mutate: (f: J) => J) => {
  const f = three();
  f[0] = mutate(f[0]);
  addW('fact-' + name, W(f, { worlds: [fareWorld()] }));
};
malformed('value-float', (f) => signFact({ name: 'fare', subject: 'OF-2', value: 1.5, t_obs: NOW - 1_000, oracle: 'o1' } as J, O[0]!.sk));
malformed('value-bool', (f) => ({ ...f, value: true }));
malformed('value-empty-string', (f) => signFact({ name: 'fare', subject: 'OF-2', value: '', t_obs: NOW - 1_000, oracle: 'o1' } as J, O[0]!.sk));
malformed('value-257', (f) => signFact({ name: 'fare', subject: 'OF-2', value: 'x'.repeat(257), t_obs: NOW - 1_000, oracle: 'o1' } as J, O[0]!.sk));
malformed('value-unsafe', (f) => ({ ...f, value: 9_007_199_254_740_992 }));
malformed('v2', (f) => ({ ...f, v: 2 }));
malformed('kind', (f) => ({ ...f, kind: 'pca-facts' }));
malformed('missing-sig', (f) => { const { sig: _s, ...r } = f; return r; });
malformed('sig-number', (f) => ({ ...f, sig: 5 }));
malformed('sig-garbage', (f) => ({ ...f, sig: 'not-base64!' }));
malformed('sig-short', (f) => ({ ...f, sig: f.sig.slice(0, 40) }));
malformed('name-bad', (f) => ({ ...f, name: 'Fare' }));
malformed('subject-257', (f) => ({ ...f, subject: 's'.repeat(257) }));
malformed('oracle-65', (f) => ({ ...f, oracle: 'o'.repeat(65) }));
malformed('t-obs-float', (f) => ({ ...f, t_obs: 1.5 }));
malformed('array', () => [1]);
// freshness / median
addW('median-2', W([fact(0, 'fare', 50), fact(1, 'fare', 10)], { worlds: [fareWorld({ min_oracles: 2, max_faulty: 0 })] }));
addW('median-negative', W([fact(0, 'fare', -5), fact(1, 'fare', -50), fact(2, 'fare', 7)], { worlds: [fareWorld()] }));
addW('median-equal', W([fact(0, 'fare', 7), fact(1, 'fare', 7), fact(2, 'fare', 7)], { worlds: [fareWorld()] }));
addW('median-4-of-3-needed', W([fact(0, 'fare', 40), fact(1, 'fare', 10), fact(2, 'fare', 30), fact(3, 'fare', 20, NOW - 1_000, 'OF-2', 'o4', O[3]!)], { worlds: [fareWorld({ oracles: oracles(4) })] }));
addW('future-beyond-skew', W([fact(0, 'fare', 5, NOW + 60_001), fact(1, 'fare', 6), fact(2, 'fare', 7)], { worlds: [fareWorld()] }));
addW('stale-by-one', W([fact(0, 'fare', 5, NOW - 60_001), fact(1, 'fare', 6), fact(2, 'fare', 7)], { worlds: [fareWorld()] }));
addW('t-obs-zero', W([fact(0, 'fare', 5, 0)], { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0, freshness_ms: 9_007_199_254_740_991 })] }));
addW('now-missing', { ...W([fact(0, 'fare', 5)], { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0 })] }), now: undefined });
for (const n of ['1800000000000', 1800000000000.5, null, true, 9_007_199_254_740_992, -0]) {
  addW(`now-${JSON.stringify(n)}-world`, { ...W([fact(0, 'fare', 5)], { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0 })] }), now: n });
  addW(`now-${JSON.stringify(n)}-relational-only`, { ...rel([{ name: 'r', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }]), now: n });
}
addW('now-zero-fresh', { ...W([fact(0, 'fare', 5, 0)], { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0 })] }), now: 0 });
addW('proto-world-names', W([fact(0, 'constructor', 5), fact(1, 'tostring', 6)], { worlds: [fareWorld({ name: 'constructor', min_oracles: 1, max_faulty: 0 }), fareWorld({ name: 'tostring', min_oracles: 1, max_faulty: 0 })], relational: [{ name: 'valueof', fn: 'sub', a: 'env.world.constructor', b: 'env.world.tostring' }, { name: 'hasownproperty', fn: 'sub', a: 'env.world.valueof', b: 'action.params.zero' }] }));
addW('strings-single', W([fact(0, 'fare', 'gold')], { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0 })] }));
addW('two-worlds', W([fact(0, 'fare', 5), fact(0, 'tier', 'gold', NOW - 1_000, 'OF-2')], { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0 }), fareWorld({ name: 'tier', min_oracles: 1, max_faulty: 0 })] }));
addW('same-oracle-two-worlds', W([fact(0, 'fare', 5), fact(0, 'tier', 6)], { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0 }), fareWorld({ name: 'tier', min_oracles: 1, max_faulty: 0 })] }));
addW('second-world-short', W([fact(0, 'fare', 5)], { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0 }), fareWorld({ name: 'tier', min_oracles: 1, max_faulty: 0 })] }));
addW('action-null-facts', { ...W([fact(0, 'fare', 5)], { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0 })] }), action: null });
addW('action-null-empty', { ...W([], {}), action: null });
addW('dup-supplied-same-fact', { ...W([fact(0, 'fare', 5)], { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0 })] }), facts: [fact(0, 'fare', 5), fact(0, 'fare', 5)] });
addW('fact-key-order-irrelevant', (() => { const f = fact(0, 'fare', 5); const g = Object.fromEntries(Object.entries(f).reverse()); return { ...W([f], { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0 })] }), facts: [g] }; })());
// suites (facts)
const W1 = (f: J, pin: J = {}) => W([f], { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0, oracles: [{ kid: 'o1', pk: O[0]!.pk, ...pin }] })] });
const FB = { name: 'fare', subject: 'OF-2', value: 39_800, t_obs: NOW - 1_000, oracle: 'o1' };
for (const alg of PQ_ALGS) {
  const f = signFact(FB as J, O[0]!.sk, suite(alg)) as J;
  addW(`fact-${alg}-pinned`, W1(f, { pq_pk: pqPk(alg) }));
  addW(`fact-${alg}-unpinned`, W1(f));
  addW(`fact-${alg}-other-pin`, W1(f, { pq_pk: pqPk(alg, OTHER_KEYS) }));
  addW(`fact-${alg}-pin-other-kid`, W([f], { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0, oracles: [{ kid: 'o1', pk: O[0]!.pk }, { kid: 'o2', pk: O[1]!.pk, pq_pk: pqPk(alg) }] })] }));
  addW(`fact-${alg}-other-signer`, W1(signFact(FB as J, O[0]!.sk, suite(alg, OTHER_KEYS)) as J, { pq_pk: pqPk(alg) }));
  addW(`fact-${alg}-value-tampered`, W1({ ...f, value: 1 }, { pq_pk: pqPk(alg) }));
  addW(`fact-${alg}-pq-pk-swapped`, W1({ ...f, pq_pk: pqPk(alg, OTHER_KEYS) }, { pq_pk: pqPk(alg, OTHER_KEYS) }));
  addW(`fact-${alg}-pq-sig-dropped`, W1((({ pq_sig: _p, ...r }) => r)(f), { pq_pk: pqPk(alg) }));
  if (f.pq_sig !== undefined) {
    const g = signFact({ ...FB, value: 1 } as J, O[0]!.sk, suite(alg)) as J;
    addW(`fact-${alg}-pq-sig-from-other`, W1({ ...f, pq_sig: g.pq_sig }, { pq_pk: pqPk(alg) }));
    addW(`fact-${alg}-ed-sig-from-other`, W1({ ...f, sig: g.sig }, { pq_pk: pqPk(alg) }));
    addW(`fact-${alg}-ed-wrong-oracle`, W1(signFact(FB as J, O[1]!.sk, suite(alg)) as J, { pq_pk: pqPk(alg) }));
  }
}
addW('fact-ml-dsa-65-relabelled-87', W1({ ...(signFact(FB as J, O[0]!.sk, suite('ml-dsa-65')) as J), alg: 'ml-dsa-87' }, { pq_pk: pqPk('ml-dsa-65') }));
addW('fact-alg-ed25519-explicit', W1(signFact({ ...FB, alg: 'ed25519' } as J, O[0]!.sk) as J));
addW('fact-ed25519-with-pq-sig', W1({ ...fact(0, 'fare', 5), pq_sig: D32('x') }));
addW('fact-ed25519-with-pq-pk', W1({ ...fact(0, 'fare', 5), pq_pk: D32('x') }, { pq_pk: D32('x') }));
addW('fact-alg-ed25519-with-pq-pk', W1({ ...fact(0, 'fare', 5), alg: 'ed25519', pq_pk: D32('x') }));
addW('fact-alg-null', W1({ ...fact(0, 'fare', 5), alg: null }));
addW('fact-alg-number', W1({ ...fact(0, 'fare', 5), alg: 7 }));
addW('fact-alg-unknown', W1({ ...fact(0, 'fare', 5), alg: 'no-such-suite' }));
addW('fact-pq-pk-null', W1({ ...(signFact(FB as J, O[0]!.sk, suite('ml-dsa-65')) as J), pq_pk: null }, { pq_pk: pqPk('ml-dsa-65') }));
addW('fact-pq-sig-number', W1({ ...(signFact(FB as J, O[0]!.sk, suite('hybrid-ed25519-ml-dsa-65')) as J), pq_sig: 5 }, { pq_pk: pqPk('hybrid-ed25519-ml-dsa-65') }));
for (const alg of GUEST_UNSUPPORTED) gu(() => addW(`fact-guest-unsupported-${alg}`, W1(fakeSuite(fact(0, 'fare', 5), alg), { pq_pk: D32('fake-pq-pk') })));
addW('pin-pq-pk-null', W1(fact(0, 'fare', 5), { pq_pk: null }));
addW('pin-pq-pk-empty', W1(fact(0, 'fare', 5), { pq_pk: '' }));
addW('pin-pq-pk-number', W1(fact(0, 'fare', 5), { pq_pk: 5 }));
addW('pin-pq-pk-ed25519-fact-ok', W1(fact(0, 'fare', 5), { pq_pk: pqPk('ml-dsa-65') }));
// closed and typed policies
addW('closed-policy-extra', W(three(), { worlds: [fareWorld()], extra: 1 }));
addW('closed-world-extra', W(three(), { worlds: [fareWorld({ note: 'x' })] }));
addW('closed-oracle-extra', W(three(), { worlds: [fareWorld({ oracles: [...oracles(2), { kid: 'o3', pk: O[2]!.pk, x: 1 }] })] }));
addW('closed-relational-extra', rel([{ name: 'r', fn: 'sub', a: 'action.params.total', b: 'action.params.quote', c: 1 }]));
addW('typed-fn-number', rel([{ name: 'r', fn: 1, a: 'action.params.total', b: 'action.params.quote' }]));
addW('input-array', [] as J);
addW('input-null', null as J);
// absent vs null
addW('absent-committed', { ...W([], {}), committed: undefined });
addW('absent-action', { ...W([], {}), action: undefined });
addW('action-array', { ...W([], {}), action: [] });
addW('action-string', { ...W([], {}), action: 'x' });
addW('params-absent', { ...W([], {}), action: { verb: 'v', resource: 'r' } });
addW('params-string', { ...W([], {}), action: { verb: 'v', resource: 'r', params: 'x' } });
addW('offer-set-null-no-policy', { ...W([], {}), offer_set: null });
addW('offer-set-array-no-policy', { ...W([], {}), offer_set: [] });
addW('offer-set-object-no-policy', { ...W([], {}), offer_set: {} });
addW('committed-array', { ...W([], {}), committed: [] });
addW('relational-null', W([], { relational: null }));
addW('skew-null', W([], { skew_ms: null }));
// offers
const OFFERS = [
  { offer_id: 'OF-1', price: 38_900, stops: 1, refundable: false },
  { offer_id: 'OF-2', price: 39_800, stops: 0, refundable: false },
  { offer_id: 'OF-3', price: 41_200, stops: 0, refundable: true },
];
const QUERY = { from: 'SFO', to: 'JFK', date: '2026-11-20', pax: 2 };
const offerSet = (over: J = {}, key = SITE) => signOfferSet({ v: 1, kind: 'pca-offer-set', site: AUD, session: SESSION, query: QUERY, rank: 'price_asc', complete: true, offers: OFFERS, issued_at: NOW - 10_000, kid: 'skyair-2026', ...over } as J, key.sk) as J;
const offerPolicy = (over: J = {}) => ({ name: 'excess_cents', site_keys: [{ kid: 'skyair-2026', pk: SITE.pk }], max_age_ms: 600_000, offer_param: 'action.params.offer_id', filter: { query: QUERY, offer: { refundable: false } }, ...over });
const OS = (os: J, policy: J = offerPolicy(), over: J = {}) => ({ now: NOW, aud: AUD, session: SESSION, action: ACTION, committed: { offer_set: offerSetRef(os) }, offer_set: os, policy: { offers: policy }, ...over });
const withOffer = (id: J) => ({ action: { ...ACTION, params: { ...ACTION.params, offer_id: id } } });
addW('offers-baseline', OS(offerSet()));
addW('offers-chosen-max', OS(offerSet({ offers: [...OFFERS, { offer_id: 'OF-4', price: 50_000, refundable: false }] }), offerPolicy(), withOffer('OF-4')));
addW('offers-filter-empty', OS(offerSet(), offerPolicy({ filter: { query: QUERY, offer: {} } }), withOffer('OF-3')));
addW('offers-filter-missing-attr', OS(offerSet(), offerPolicy({ filter: { query: QUERY, offer: { meal: true } } })));
addW('offers-filter-typed', OS(offerSet(), offerPolicy({ filter: { query: QUERY, offer: { refundable: 0 } } })));
addW('offers-filter-number', OS(offerSet(), offerPolicy({ filter: { query: QUERY, offer: { stops: 0 } } })));
addW('offers-nested-param', OS(offerSet(), offerPolicy({ offer_param: 'action.params.nested.id' })));
addW('offers-param-absent', OS(offerSet(), offerPolicy({ offer_param: 'action.params.nope' })));
addW('offers-issued-skew-edge', OS(offerSet({ issued_at: NOW + 60_000 })));
addW('offers-issued-skew-policy', { ...OS(offerSet({ issued_at: NOW + 1 })), policy: { skew_ms: 0, offers: offerPolicy() } });
addW('offers-max-age-0', OS(offerSet({ issued_at: NOW }), offerPolicy({ max_age_ms: 0 })));
addW('offers-name-dup-world', { ...OS(offerSet()), policy: { worlds: [fareWorld({ name: 'excess_cents' })], offers: offerPolicy() } });
addW('offers-name-number', OS(offerSet(), offerPolicy({ name: 5 })));
addW('offers-name-bad-regex', OS(offerSet(), offerPolicy({ name: 'Excess' })));
addW('offers-policy-null', { ...OS(offerSet()), policy: { offers: null } });
addW('offers-policy-dup-kid', OS(offerSet(), offerPolicy({ site_keys: [{ kid: 'skyair-2026', pk: SITE.pk }, { kid: 'skyair-2026', pk: GOV.pk }] })));
addW('offers-policy-second-key', OS(offerSet({ kid: 'k2' }, GOV), offerPolicy({ site_keys: [{ kid: 'skyair-2026', pk: SITE.pk }, { kid: 'k2', pk: GOV.pk }] })));
addW('offers-policy-max-age-neg', OS(offerSet(), offerPolicy({ max_age_ms: -1 })));
addW('offers-policy-param-bad', OS(offerSet(), offerPolicy({ offer_param: 'action.offer_id' })));
addW('offers-policy-filter-missing', OS(offerSet(), offerPolicy({ filter: { query: QUERY } })));
addW('offers-policy-filter-object-value', OS(offerSet(), offerPolicy({ filter: { query: QUERY, offer: { x: { y: 1 } } } })));
addW('offers-policy-filter-float', OS(offerSet(), offerPolicy({ filter: { query: QUERY, offer: { x: 1.5 } } })));
addW('offers-supplied-null', { ...OS(offerSet()), offer_set: null });
addW('offers-query-33', OS(offerSet({ query: Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`k${i}`, i])) })));
addW('offers-query-key-65', OS(offerSet({ query: { ['k'.repeat(65)]: 1 } })));
addW('offers-query-float', OS(offerSet({ query: { pax: 2.5 } })));
addW('offers-query-null', OS(offerSet({ query: { pax: null } })));
addW('offers-attrs-32', OS(offerSet({ offers: [{ offer_id: 'OF-2', price: 1, ...Object.fromEntries(Array.from({ length: 32 }, (_, i) => [`a${i}`, i])) }] }), offerPolicy({ filter: { query: QUERY, offer: {} } })));
addW('offers-attrs-33', OS(offerSet({ offers: [{ offer_id: 'OF-2', price: 1, ...Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`a${i}`, i])) }] }), offerPolicy({ filter: { query: QUERY, offer: {} } })));
addW('offers-attr-key-empty', OS(offerSet({ offers: [{ offer_id: 'OF-2', price: 1, '': 1 }] })));
addW('offers-id-128', OS(offerSet({ offers: [{ offer_id: 'i'.repeat(128), price: 1, refundable: false }] }), offerPolicy(), withOffer('i'.repeat(128))));
addW('offers-id-129', OS(offerSet({ offers: [{ offer_id: 'i'.repeat(129), price: 1, refundable: false }] }), offerPolicy(), withOffer('i'.repeat(129))));
addW('offers-256', OS(offerSet({ offers: Array.from({ length: 256 }, (_, i) => ({ offer_id: `O${i}`, price: 1000 - i, refundable: false })) }), offerPolicy(), withOffer('O3')));
addW('offers-257', OS(offerSet({ offers: Array.from({ length: 257 }, (_, i) => ({ offer_id: `O${i}`, price: i, refundable: false })) }), offerPolicy(), withOffer('O3')));
addW('offers-price-float', OS(offerSet({ offers: [{ offer_id: 'OF-2', price: 1.5 }] })));
addW('offers-price-missing', OS(offerSet({ offers: [{ offer_id: 'OF-2' }] })));
addW('offers-issued-neg', OS(offerSet({ issued_at: -1 })));
addW('offers-kid-empty', OS(offerSet({ kid: '' })));
addW('offers-site-257', OS(offerSet({ site: 's'.repeat(257) })));
addW('offers-session-bad', OS(offerSet({ session: 'abc' })));
addW('offers-complete-string', OS(offerSet({ complete: 'true' })));
addW('offers-v2', OS(offerSet({ v: 2 })));
addW('offers-extra-member', (() => { const os = { ...offerSet(), extra: 1 }; return OS(os); })());
addW('offers-sig-bad', (() => { const os = { ...offerSet(), sig: 'x' }; return OS(os); })());
addW('offers-tampered-price', (() => { const os = offerSet(); os.offers = [{ ...OFFERS[0], price: 1 }, OFFERS[1], OFFERS[2]]; return OS(os); })());
for (const n of ['1800000000000', 1800000000000.5, null]) addW(`offers-now-${JSON.stringify(n)}`, { ...OS(offerSet()), now: n });
addW('offers-aud-number', { ...OS(offerSet()), aud: 5 });
for (const alg of ['ml-dsa-65', 'hybrid-nested-ed25519-ml-dsa-65', 'slh-dsa-sha2-128f']) {
  const os = signOfferSet({ v: 1, kind: 'pca-offer-set', site: AUD, session: SESSION, query: QUERY, rank: 'price_asc', complete: true, offers: OFFERS, issued_at: NOW - 10_000, kid: 'skyair-2026' } as J, SITE.sk, suite(alg)) as J;
  addW(`offers-${alg}-pinned`, OS(os, offerPolicy({ site_keys: [{ kid: 'skyair-2026', pk: SITE.pk, pq_pk: pqPk(alg) }] })));
  addW(`offers-${alg}-unpinned`, OS(os));
  addW(`offers-${alg}-other-pin`, OS(os, offerPolicy({ site_keys: [{ kid: 'skyair-2026', pk: SITE.pk, pq_pk: pqPk(alg, OTHER_KEYS) }] })));
}
addW('closed-offers-extra', OS(offerSet(), offerPolicy({ extra: 1 })));
addW('closed-site-key-extra', OS(offerSet(), offerPolicy({ site_keys: [{ kid: 'skyair-2026', pk: SITE.pk, x: 1 }] })));
addW('closed-filter-extra', OS(offerSet(), offerPolicy({ filter: { query: QUERY, offer: { refundable: false }, x: {} } })));
addW('typed-max-age-string', OS(offerSet(), offerPolicy({ max_age_ms: '600000' })));
addW('offers-site-key-pq-null', OS(offerSet(), offerPolicy({ site_keys: [{ kid: 'skyair-2026', pk: SITE.pk, pq_pk: null }] })));
addW('offers-alg-unknown', OS({ ...offerSet(), alg: 'no-such-suite' }));
addW('offers-ed25519-pq-sig', OS({ ...offerSet(), pq_sig: D32('x') }));
for (const alg of GUEST_UNSUPPORTED) gu(() => addW(`offers-guest-unsupported-${alg}`, OS(fakeSuite(offerSet(), alg), offerPolicy({ site_keys: [{ kid: 'skyair-2026', pk: SITE.pk, pq_pk: D32('fake-pq-pk') }] }))));

// ------------------------------------------------------------------ rule 17
const prov: J[] = [];
const addP = (name: string, input: J) => {
  const r = decideParamProvenance(clone(input));
  prov.push(mark({ name: 'p-' + name, input: clone(input), expect: r.outcome === 'deny' ? { outcome: 'deny', reason: r.reason } : { outcome: r.outcome, friction: r.friction ?? null, labels: r.labels, classes: r.classes, env: r.env } }));
};
const PARAMS = { offer_id: 'OF-1', payment_ref: 'pm_ana_visa', add_ons: 'tripshield', passport: 'X1234567', note: 'hi', pax: { lead: 'px_ana' }, big: 1e21, flt: 1.5 };
const POLICY = {
  params: { 'action.params.offer_id': 'material', 'action.params.add_ons': 'material', 'action.params.payment_ref': 'critical', 'action.params.passport': 'critical' },
  registry: { 'skyair:offer_set:1': 'first_party', 'wallet:profile:ana': 'trusted', 'web:ad': 'web', 'tool:fx': 'tool', 'agent:planner': 'agent' },
  label_keys: [{ site: AUD, kid: 'k1', pk: SITE.pk }, { site: 'gov.example', kid: 'g1', pk: GOV.pk }],
};
const CLEAN = { 'action.params.offer_id': ['skyair:offer_set:1'], 'action.params.payment_ref': ['wallet:profile:ana'], 'action.params.add_ons': ['wallet:profile:ana'], 'action.params.passport': ['wallet:profile:ana'] };
const P = (provOver: J = {}, policyOver: J = {}, over: J = {}) => ({ aud: AUD, session: SESSION, action: { params: PARAMS }, prov: { ...CLEAN, ...provOver }, policy: { ...POLICY, ...policyOver }, ...over });
const receipt = (site: string, key: J, kid: string, fields: J, session = SESSION, over: J = {}) => signLabels({ site, session, response_digest: D32('response'), fields, issued_at: NOW - 5_000, kid, ...over } as J, key.sk) as J;
const PASS = { class: 'pii.identity', value_digest: hashCanonical('X1234567') };
const PASSPORT = receipt(AUD, SITE, 'k1', { 'travellers[0].passport': PASS, 'a#b': PASS });
const GOVR = receipt('gov.example', GOV, 'g1', { passport: PASS, name: { class: 'pii.contact', value_digest: hashCanonical('Ana') }, card: { class: 'payment.card', value_digest: hashCanonical('pm_ana_visa') } });
const lref = (r: J, f: string) => `pca-labels:${labelsRef(r)}#${f}`;
const withLabel = (r: J, f: string, extra: J = {}) => ({ committed_labels: [labelsRef(r)], labels: [r], ...extra, prov: { ...CLEAN, 'action.params.passport': [lref(r, f)] } });

addP('baseline', P());
addP('policy-null', { ...P(), policy: null });
addP('policy-params-missing', P({}, { params: undefined }));
addP('policy-params-array', P({}, { params: [] }));
addP('policy-param-not-path', P({}, { params: { 'params.x': 'material' } }));
addP('policy-param-bad-sens', P({}, { params: { 'action.params.x': 'free' } }));
addP('policy-param-nested-ok', P({}, { params: { ...POLICY.params, 'action.params.pax.lead': 'material' } }));
addP('policy-registry-array', P({}, { registry: [] }));
addP('policy-registry-null', P({}, { registry: null }));
addP('policy-registry-empty-key', P({}, { registry: { '': 'trusted' } }));
addP('policy-registry-257-key', P({}, { registry: { ['r'.repeat(257)]: 'trusted' } }));
addP('policy-registry-proto-level', P({}, { registry: { x: 'toString' } }));
addP('policy-label-keys-object', P({}, { label_keys: {} }));
addP('policy-label-key-bad-pk', P({}, { label_keys: [{ site: AUD, kid: 'k1', pk: 'abc' }] }));
addP('policy-label-key-no-site', P({}, { label_keys: [{ kid: 'k1', pk: SITE.pk }] }));
addP('policy-critical-max-null', P({}, { critical_max: null }));
addP('policy-material-null', P({}, { material_tainted: null }));
addP('policy-material-bad', P({}, { material_tainted: 'warn' }));
addP('policy-critical-tainted-question', P({ 'action.params.payment_ref': ['web:ad'] }, { critical_tainted: 'question' }));
addP('policy-flows-array', P({}, { flows: [] }));
addP('policy-flows-sinks-string', P({}, { flows: { 'pii.*': AUD } }));
addP('policy-flows-sink-empty', P({}, { flows: { 'pii.*': [''] } }));
addP('policy-flows-dot-star', P({}, { flows: { '.*': [AUD] } }));
addP('policy-flows-star-star', P({}, { flows: { '*.*': [AUD] } }));
addP('policy-flows-ok-many', P({}, { flows: { '*': [], 'pii.*': [AUD], 'pii.identity': [AUD], 'pii.identity.*': [] } }, withLabel(GOVR, 'passport')));
// prov wire
addP('prov-null', { ...P(), prov: null });
addP('prov-string', { ...P(), prov: 'x' });
addP('prov-ref-number', P({ 'action.params.offer_id': [5] }));
addP('prov-refs-string', P({ 'action.params.offer_id': 'skyair:offer_set:1' }));
addP('prov-name-64', P({ ['action.params.' + 'n'.repeat(64)]: ['tool:fx'] }, {}, { action: { params: { ...PARAMS, ['n'.repeat(64)]: 1 } } }));
addP('prov-name-65', P({ ['action.params.' + 'n'.repeat(65)]: ['tool:fx'] }, {}, { action: { params: { ...PARAMS, ['n'.repeat(65)]: 1 } } }));
addP('prov-prototype-name', P({ 'action.params.prototype': ['tool:fx'] }, {}, { action: { params: { ...PARAMS, prototype: 1 } } }));
addP('prov-8-refs', P({ 'action.params.offer_id': Array.from({ length: 8 }, () => 'skyair:offer_set:1') }));
addP('prov-ref-256', P({ 'action.params.note': ['x'.repeat(256)] }));
addP('prov-32-paths', { ...P(), action: { params: Object.fromEntries(Array.from({ length: 32 }, (_, i) => [`p${i}`, i])) }, prov: Object.fromEntries(Array.from({ length: 32 }, (_, i) => [`action.params.p${i}`, ['tool:fx']])), policy: { params: { 'action.params.p3': 'material' } } });
addP('committed-labels-object', { ...P(), committed_labels: {} });
addP('committed-labels-null', { ...P(), committed_labels: null });
addP('committed-labels-17', { ...P(), committed_labels: Array.from({ length: 17 }, (_, i) => D32(`l${i}`)) });
addP('committed-labels-16', { ...P(), committed_labels: Array.from({ length: 16 }, (_, i) => D32(`l${i}`)) });
addP('committed-labels-bad', { ...P(), committed_labels: ['abc'] });
addP('labels-number', { ...P(), labels: 5 });
addP('labels-object', { ...P(), labels: {} });
addP('labels-string', { ...P(), labels: 'abc' });
addP('labels-junk', { ...P(), labels: [null, 5, 'x', {}] });
// classification
addP('registry-proto-own', P({ 'action.params.offer_id': ['__proto__', 'constructor'] }, { registry: { ...POLICY.registry, ['__proto__']: 'trusted', constructor: 'first_party' } }));
addP('registry-tool', P({ 'action.params.add_ons': ['tool:fx'] }));
addP('registry-agent', P({ 'action.params.add_ons': ['agent:planner', 'wallet:profile:ana'] }));
addP('free-param-undeclared', P({}, {}, { action: { params: { ...PARAMS, extra: 'x' } } }));
addP('params-null', { ...P(), prov: {}, action: { params: null } });
addP('action-null', { ...P(), prov: {}, action: null });
addP('action-missing-with-prov', { ...P(), action: undefined });
addP('typed-and-tap', P({ 'action.params.add_ons': ['web:ad'], 'action.params.payment_ref': ['tool:fx'] }));
addP('critical-max-tool-web', P({ 'action.params.payment_ref': ['web:ad'] }, { critical_max: 'tool' }));
addP('critical-max-trusted-ok', P({}, { critical_max: 'trusted' }));
addP('material-question-explicit', P({ 'action.params.add_ons': ['web:ad'] }, { material_tainted: 'question' }));
addP('critical-allow-material-deny-untainted', P({}, { material_tainted: 'deny', critical_tainted: 'deny' }));
addP('nested-policy-overlap', P({ 'action.params.pax': ['wallet:profile:ana'] }, { params: { ...POLICY.params, 'action.params.pax.lead': 'material' } }));
addP('nested-policy-both', P({}, { params: { ...POLICY.params, 'action.params.pax': 'material', 'action.params.pax.lead': 'material' } }));
addP('nested-policy-only-child', P({}, { params: { ...POLICY.params, 'action.params.pax.lead': 'critical' } }));
// label refs
addP('label-first-party', P({}, {}, withLabel(PASSPORT, 'travellers[0].passport')));
addP('label-hash-in-field', P({}, {}, withLabel(PASSPORT, 'a#b')));
addP('label-foreign-no-flow', P({}, {}, withLabel(GOVR, 'passport')));
addP('label-foreign-flow-prefix', P({}, { flows: { 'pii.*': [AUD] } }, withLabel(GOVR, 'passport')));
addP('label-foreign-flow-longest', P({}, { flows: { 'pii.*': ['x.example'], 'pii.identity.*': [AUD] } }, withLabel(GOVR, 'passport')));
addP('label-foreign-flow-exact-beats-star', P({}, { flows: { '*': [AUD], 'pii.identity': [] } }, withLabel(GOVR, 'passport')));
addP('label-foreign-prefix-not-self', P({}, { flows: { 'pii.identity.*': [AUD] } }, withLabel(GOVR, 'passport')));
addP('label-two-classes', { ...P({}, { flows: { '*': [AUD] } }, withLabel(GOVR, 'passport')), prov: { ...CLEAN, 'action.params.passport': [lref(GOVR, 'passport'), lref(GOVR, 'name'), lref(GOVR, 'passport')] } });
addP('label-two-params', { ...P({}, { flows: { '*': [AUD] } }, withLabel(GOVR, 'passport')), prov: { ...CLEAN, 'action.params.passport': [lref(GOVR, 'passport')], 'action.params.payment_ref': [lref(GOVR, 'card')] } });
addP('label-mismatch-agent', { ...P({}, {}, withLabel(PASSPORT, 'travellers[0].passport')), action: { params: { ...PARAMS, passport: 'Y' } } });
addP('label-value-nonstrict', { ...P({}, {}, withLabel(PASSPORT, 'travellers[0].passport')), prov: { ...CLEAN, 'action.params.big': [lref(PASSPORT, 'travellers[0].passport')] } });
addP('label-value-float', (() => { const r = receipt(AUD, SITE, 'k1', { f: { class: 'public', value_digest: hashCanonical(1.5) } }); return { ...P({}, {}, { committed_labels: [labelsRef(r)], labels: [r] }), prov: { ...CLEAN, 'action.params.flt': [lref(r, 'f')] } }; })());
addP('label-object-value', (() => { const r = receipt(AUD, SITE, 'k1', { pax: { class: 'pii.contact', value_digest: hashCanonical({ lead: 'px_ana' }) } }); return { ...P({}, {}, { committed_labels: [labelsRef(r)], labels: [r] }), prov: { ...CLEAN, 'action.params.pax': [lref(r, 'pax')] } }; })());
addP('label-dup-key-first-wins', P({}, { label_keys: [{ site: AUD, kid: 'k1', pk: GOV.pk }, { site: AUD, kid: 'k1', pk: SITE.pk }] }, withLabel(PASSPORT, 'travellers[0].passport')));
addP('label-second-key-ok', P({}, { label_keys: [{ site: AUD, kid: 'k0', pk: GOV.pk }, { site: AUD, kid: 'k1', pk: SITE.pk }] }, withLabel(PASSPORT, 'travellers[0].passport')));
addP('label-no-label-keys', P({}, { label_keys: undefined }, withLabel(PASSPORT, 'travellers[0].passport')));
addP('label-field-empty', P({ 'action.params.passport': [`pca-labels:${labelsRef(PASSPORT)}#`] }, {}, { committed_labels: [labelsRef(PASSPORT)], labels: [PASSPORT] }));
addP('label-prefix-only', P({ 'action.params.passport': ['pca-labels:'] }));
addP('label-proto-field', P({}, {}, withLabel(PASSPORT, '__proto__')));
addP('label-uncommitted-supplied-ignored', { ...P(), committed_labels: [], labels: [PASSPORT] });
const badReceipt = (name: string, r: J) => addP('receipt-' + name, { ...P({}, { flows: { '*': [AUD] } }), committed_labels: [labelsRef(r)], labels: [r], prov: { ...CLEAN, 'action.params.passport': [lref(r, Object.keys(r.fields ?? { x: 1 })[0] ?? 'x')] } });
badReceipt('fields-empty', receipt(AUD, SITE, 'k1', {}));
badReceipt('fields-65', receipt(AUD, SITE, 'k1', Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`f${i}`, PASS]))));
badReceipt('fields-64', receipt(AUD, SITE, 'k1', Object.fromEntries(Array.from({ length: 64 }, (_, i) => [`f${i}`, PASS]))));
badReceipt('class-upper', receipt(AUD, SITE, 'k1', { p: { class: 'PII', value_digest: PASS.value_digest } }));
badReceipt('class-129', receipt(AUD, SITE, 'k1', { p: { class: 'a'.repeat(129), value_digest: PASS.value_digest } }));
badReceipt('class-128', receipt(AUD, SITE, 'k1', { p: { class: 'a'.repeat(128), value_digest: PASS.value_digest } }));
badReceipt('class-trailing-dot', receipt(AUD, SITE, 'k1', { p: { class: 'pii.', value_digest: PASS.value_digest } }));
badReceipt('field-extra', receipt(AUD, SITE, 'k1', { p: { ...PASS, x: 1 } }));
badReceipt('field-digest-bad', receipt(AUD, SITE, 'k1', { p: { class: 'pii', value_digest: 'abc' } }));
badReceipt('field-key-257', receipt(AUD, SITE, 'k1', { ['f'.repeat(257)]: PASS }));
badReceipt('issued-neg', receipt(AUD, SITE, 'k1', { p: PASS }, SESSION, { issued_at: -1 }));
badReceipt('kid-65', receipt(AUD, SITE, 'k'.repeat(65), { p: PASS }));
badReceipt('response-digest-bad', receipt(AUD, SITE, 'k1', { p: PASS }, SESSION, { response_digest: 'x' }));
badReceipt('v2', { ...receipt(AUD, SITE, 'k1', { p: PASS }), v: 2 });
badReceipt('sig-garbage', { ...receipt(AUD, SITE, 'k1', { p: PASS }), sig: '!!' });
badReceipt('ok-control', receipt(AUD, SITE, 'k1', { p: PASS }));
const pqReceipt = (alg: string, keys: J = KEYS) => signLabels({ site: AUD, session: SESSION, response_digest: D32('response'), fields: { 'travellers[0].passport': PASS }, issued_at: NOW - 5_000, kid: 'k1' } as J, SITE.sk, suite(alg, keys)) as J;
for (const alg of ['ml-dsa-65', 'hybrid-ed25519-ml-dsa-65', 'slh-dsa-sha2-128f']) {
  const r = pqReceipt(alg);
  addP(`label-${alg}-pinned`, P({}, { label_keys: [{ site: AUD, kid: 'k1', pk: SITE.pk, pq_pk: pqPk(alg) }] }, withLabel(r, 'travellers[0].passport')));
  addP(`label-${alg}-unpinned`, P({}, {}, withLabel(r, 'travellers[0].passport')));
  addP(`label-${alg}-other-signer`, P({}, { label_keys: [{ site: AUD, kid: 'k1', pk: SITE.pk, pq_pk: pqPk(alg) }] }, withLabel(pqReceipt(alg, OTHER_KEYS), 'travellers[0].passport')));
}
addP('label-key-pq-null', P({}, { label_keys: [{ site: AUD, kid: 'k1', pk: SITE.pk, pq_pk: null }] }));
addP('label-alg-null', P({}, {}, withLabel({ ...PASSPORT, alg: null }, 'travellers[0].passport')));
addP('label-alg-unknown', P({}, {}, withLabel({ ...PASSPORT, alg: 'no-such-suite' }, 'travellers[0].passport')));
addP('label-ed25519-pq-pk', P({}, {}, withLabel({ ...PASSPORT, pq_pk: D32('x') }, 'travellers[0].passport')));
for (const alg of GUEST_UNSUPPORTED) gu(() => addP(`label-guest-unsupported-${alg}`, P({}, { label_keys: [{ site: AUD, kid: 'k1', pk: SITE.pk, pq_pk: D32('fake-pq-pk') }] }, withLabel(fakeSuite(PASSPORT, alg), 'travellers[0].passport'))));
// absent vs null (rule 17)
addP('null-prov', { ...P(), prov: null });
addP('null-committed-labels', { ...P(), committed_labels: null });
addP('null-labels', { ...P(), labels: null });
addP('absent-action', { ...P(), action: undefined });
addP('action-null', { ...P(), action: null });
addP('params-absent-empty-prov', { ...P(), prov: {}, action: {} });
addP('params-array', { ...P(), prov: {}, action: { params: [] } });
addP('closed-policy-extra', P({}, { extra: 1 }));
addP('closed-label-key-extra', P({}, { label_keys: [{ site: AUD, kid: 'k1', pk: SITE.pk, x: 1 }] }));
addP('typed-critical-max-number', P({}, { critical_max: 4 }));
addP('input-array', [] as J);
addP('null-flows', P({}, { flows: null }));

// ------------------------------------------------------------------ rule 18
const cls: J[] = [];
const addC = (name: string, input: J) => {
  const r = decideClassifierDimensions(clone(input));
  cls.push(mark({ name: 'c-' + name, input: clone(input), expect: r.ok ? { ok: true, classes: r.classes } : { ok: false, reason: r.reason } }));
};
const MESSAGE = 'We are sorry for the delay.';
const TONE = { id: 'tone', param: 'action.params.body', labels: ['neutral', 'apologetic', 'hostile', 'other'], keys: JD.map((j) => j.pk), k: 2, measurements: ['m-tone-1'] };
const verdict = (j: J, label: string, over: J = {}) => signClassifierVerdict({ classifier: 'tone', session: SESSION, content_digest: classifierContentDigest(MESSAGE), label, measurement: 'm-tone-1', ...over } as J, j.sk) as J;
const C = (verdicts: J[], policyOver: J = {}, over: J = {}) => ({ session: SESSION, action: { params: { body: MESSAGE, flt: 1.5, big: 1e21, nested: { body: MESSAGE } } }, committed: verdicts.map(classifierVerdictRef), verdicts, policy: { classifiers: [{ ...TONE, ...policyOver }] }, ...over });
const two = () => [verdict(JD[0], 'apologetic'), verdict(JD[1], 'apologetic')];
addC('baseline', C(two()));
addC('k3-all', C([...two(), verdict(JD[2], 'apologetic')], { k: 3 }));
addC('k3-two', C(two(), { k: 3 }));
addC('policy-null', { ...C(two()), policy: null });
addC('policy-classifiers-object', { ...C(two()), policy: { classifiers: {} } });
addC('policy-entry-null', { ...C(two()), policy: { classifiers: [null] } });
addC('policy-dup-ids', { ...C(two()), policy: { classifiers: [TONE, TONE] } });
addC('policy-id-bad', C(two(), { id: 'Tone' }));
addC('policy-param-bad', C(two(), { param: 'action.body' }));
addC('policy-labels-empty', C(two(), { labels: [] }));
addC('policy-labels-33', C(two(), { labels: Array.from({ length: 33 }, (_, i) => `l${i}`) }));
addC('policy-labels-32', C(two(), { labels: [...Array.from({ length: 31 }, (_, i) => `l${i}`), 'apologetic'] }));
addC('policy-label-65', C(two(), { labels: ['apologetic', 'x'.repeat(65)] }));
addC('policy-label-number', C(two(), { labels: ['apologetic', 5] }));
addC('policy-keys-empty', C(two(), { keys: [], k: 1 }));
addC('policy-keys-dup', C(two(), { keys: [JD[0]!.pk, JD[0]!.pk, JD[1]!.pk] }));
addC('policy-keys-bad', C(two(), { keys: [JD[0]!.pk, 'abc'] }));
for (const k of [0, 1.5, '2', null]) addC(`policy-k-${JSON.stringify(k)}`, C(two(), { k }));
addC('policy-measurements-null', C(two(), { measurements: null }));
addC('policy-measurements-number', C(two(), { measurements: ['m-tone-1', 5] }));
addC('policy-measurements-empty', C(two(), { measurements: [] }));
addC('committed-object', { ...C(two()), committed: {} });
addC('committed-null', { ...C(two()), committed: null });
addC('committed-8-unsupplied', { ...C(two()), committed: Array.from({ length: 8 }, (_, i) => D32(`v${i}`)) });
addC('committed-bad', { ...C(two()), committed: ['abc'] });
addC('verdicts-number', { ...C(two()), verdicts: 5 });
addC('verdicts-string', { ...C([]), verdicts: 'abc', policy: { classifiers: [] } });
addC('verdicts-null', { ...C([]), verdicts: null, policy: { classifiers: [] } });
addC('verdicts-junk-uncommitted', { ...C(two()), verdicts: [...two(), 5, null, {}] });
const badV = (name: string, mutate: (v: J) => J) => { const v = mutate(verdict(JD[1], 'apologetic')); addC('verdict-' + name, C([verdict(JD[0], 'apologetic'), v])); };
badV('classifier-bad', (v) => ({ ...v, classifier: 'Tone' }));
badV('session-bad', (v) => ({ ...v, session: 'x' }));
badV('content-digest-bad', (v) => ({ ...v, content_digest: 'x' }));
badV('label-65', () => verdict(JD[1], 'x'.repeat(65)));
badV('label-empty', () => verdict(JD[1], ''));
badV('measurement-257', () => verdict(JD[1], 'apologetic', { measurement: 'm'.repeat(257) }));
badV('judge-bad', (v) => ({ ...v, judge: 'x' }));
badV('sig-number', (v) => ({ ...v, sig: 5 }));
badV('sig-garbage', (v) => ({ ...v, sig: '!!' }));
badV('v2', (v) => ({ ...v, v: 2 }));
badV('missing-member', (v) => { const { measurement: _m, ...r } = v; return r; });
badV('judge-swapped', (v) => ({ ...v, judge: JD[2]!.pk }));
addC('content-float', (() => { const vs = [0, 1].map((i) => verdict(JD[i], 'neutral', { content_digest: classifierContentDigest(1.5) })); return C(vs, { param: 'action.params.flt' }); })());
addC('content-nonstrict', (() => { const vs = [0, 1].map((i) => verdict(JD[i], 'neutral', { content_digest: D32('x') })); return C(vs, { param: 'action.params.big' }); })());
addC('content-nested', C(two(), { param: 'action.params.nested.body' }));
addC('params-null', { ...C(two()), action: { params: null } });
addC('action-null', { ...C(two()), action: null });
addC('session-mismatch-input', { ...C(two()), session: OTHER_SESSION });
addC('two-classifiers', (() => {
  const dc = { id: 'dclass', param: 'action.params.body', labels: ['public', 'pii'], keys: [JD[2]!.pk], k: 1 };
  const vs = [...two(), signClassifierVerdict({ classifier: 'dclass', session: SESSION, content_digest: classifierContentDigest(MESSAGE), label: 'public', measurement: 'm' } as J, JD[2]!.sk) as J];
  return { ...C(vs), policy: { classifiers: [TONE, dc] } };
})());
addC('two-classifiers-second-short', (() => {
  const dc = { id: 'dclass', param: 'action.params.body', labels: ['public', 'pii'], keys: [JD[2]!.pk], k: 1 };
  return { ...C(two()), policy: { classifiers: [TONE, dc] } };
})());
addC('same-judge-two-classifiers', (() => {
  const dc = { id: 'dclass', param: 'action.params.body', labels: ['public', 'pii'], keys: [JD[0]!.pk], k: 1 };
  const vs = [...two(), signClassifierVerdict({ classifier: 'dclass', session: SESSION, content_digest: classifierContentDigest(MESSAGE), label: 'pii', measurement: 'm' } as J, JD[0]!.sk) as J];
  return { ...C(vs), policy: { classifiers: [TONE, dc] } };
})());
addC('proto-labels', (() => {
  const L = ['constructor', 'toString', '__proto__', 'valueOf', 'hasOwnProperty'];
  const vs = [verdict(JD[0], '__proto__'), verdict(JD[1], '__proto__'), verdict(JD[2], 'toString')];
  return C(vs, { labels: L });
})());
addC('proto-label-constructor-k1', C([verdict(JD[0], 'constructor')], { labels: ['constructor', 'neutral'], k: 1 }));
addC('proto-id-constructor', (() => {
  const vs = [0, 1].map((i) => signClassifierVerdict({ classifier: 'constructor', session: SESSION, content_digest: classifierContentDigest(MESSAGE), label: 'valueOf', measurement: 'm' } as J, JD[i]!.sk) as J);
  return { ...C(vs), policy: { classifiers: [{ id: 'constructor', param: 'action.params.body', labels: ['valueOf', 'name'], keys: JD.map((j) => j.pk), k: 2 }] } };
})());
for (const alg of ['ml-dsa-65', 'hybrid-nested-ed25519-ml-dsa-65', 'hybrid-ed25519-slh-dsa-sha2-128f']) {
  const pv = signClassifierVerdict({ classifier: 'tone', session: SESSION, content_digest: classifierContentDigest(MESSAGE), label: 'apologetic', measurement: 'm-tone-1' } as J, JD[1]!.sk, suite(alg)) as J;
  addC(`verdict-${alg}-pinned`, C([verdict(JD[0], 'apologetic'), pv], { pq_keys: { [JD[1]!.pk]: pqPk(alg) } }));
  addC(`verdict-${alg}-unpinned`, C([verdict(JD[0], 'apologetic'), pv]));
  addC(`verdict-${alg}-pinned-for-other-judge`, C([verdict(JD[0], 'apologetic'), pv], { pq_keys: { [JD[0]!.pk]: pqPk(alg) } }));
  addC(`verdict-${alg}-other-pin`, C([verdict(JD[0], 'apologetic'), pv], { pq_keys: { [JD[1]!.pk]: pqPk(alg, OTHER_KEYS) } }));
}
addC('pq-keys-null', C(two(), { pq_keys: null }));
addC('pq-keys-array', C(two(), { pq_keys: [] }));
addC('pq-keys-not-allowlisted', C(two(), { pq_keys: { [ROGUE.pk]: pqPk('ml-dsa-65') } }));
addC('pq-keys-empty-value', C(two(), { pq_keys: { [JD[0]!.pk]: '' } }));
addC('pq-keys-ed25519-verdicts-ok', C(two(), { pq_keys: { [JD[0]!.pk]: pqPk('ml-dsa-65') } }));
addC('verdict-alg-unknown', C([verdict(JD[0], 'apologetic'), { ...verdict(JD[1], 'apologetic'), alg: 'no-such-suite' }]));
addC('verdict-alg-null', C([verdict(JD[0], 'apologetic'), { ...verdict(JD[1], 'apologetic'), alg: null }]));
addC('verdict-ed25519-pq-sig', C([verdict(JD[0], 'apologetic'), { ...verdict(JD[1], 'apologetic'), pq_sig: D32('x') }]));
for (const alg of GUEST_UNSUPPORTED) gu(() => addC(`verdict-guest-unsupported-${alg}`, C([verdict(JD[0], 'apologetic'), fakeSuite(verdict(JD[1], 'apologetic'), alg)], { pq_keys: { [JD[1]!.pk]: D32('fake-pq-pk') } })));
addC('closed-policy-extra', { ...C(two()), policy: { classifiers: [TONE], x: 1 } });
addC('closed-classifier-extra', C(two(), { x: 1 }));
addC('typed-k-string', C(two(), { k: '2' }));
addC('input-string', 'x' as J);
addC('null-committed', { ...C(two()), committed: null });
addC('null-verdicts', { ...C(two()), verdicts: null });
addC('absent-action', { ...C(two()), action: undefined });
addC('params-absent', { ...C([]), action: {}, policy: { classifiers: [] } });
addC('votes-over-k-one-label', C([...two(), verdict(JD[2], 'apologetic')], { k: 1 }));

// ------------------------------------------------------------------ W-B composition
const wb: J[] = [];
const addB = (name: string, input: J) => {
  const r = decideIntentWB(clone(input));
  wb.push(mark({ name: 'b-' + name, input: clone(input), expect: { outcome: r.outcome, checks: Object.entries(r.checks), env: r.env, friction: r.friction ?? null, reason: r.reason ?? null } }));
};
const F1 = fact(0, 'fare', 38_900);
const WPOL = { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0 })] };
const B = (over: J = {}) => ({
  now: NOW, aud: AUD, session: SESSION,
  action: { verb: 'air.book', resource: 'skyair.example/bookings', params: { ...PARAMS, offer_id: 'OF-2', body: MESSAGE } },
  intent_session: { facts: [factRef(F1)], prov: { 'action.params.offer_id': ['skyair:offer_set:1'] }, classes: two().map(classifierVerdictRef) },
  artifacts: { facts: [F1], verdicts: two() },
  policy: { world: WPOL, provenance: { params: { 'action.params.offer_id': 'material' }, registry: POLICY.registry }, classifiers: [TONE] },
  ...over,
});
const Bs = (s: J) => B({ intent_session: { ...B().intent_session, ...s } });
const Bp = (p: J) => B({ policy: { ...B().policy, ...p } });
addB('all-pass', B());
addB('nothing-active', { now: NOW, aud: AUD, session: SESSION, action: ACTION, intent_session: {}, policy: {} });
addB('nothing-at-all', { now: NOW, aud: AUD, session: SESSION, action: ACTION });
addB('facts-fail-stops', Bs({ facts: [D32('nope')], prov: { 'action.params.offer_id': ['web:ad'] } }));
addB('prov-question-classes-pass', Bs({ prov: { 'action.params.offer_id': ['web:ad'] } }));
addB('prov-question-typed', B({ intent_session: { ...B().intent_session, prov: { 'action.params.offer_id': ['web:ad'] } }, policy: { ...B().policy, provenance: { params: { 'action.params.offer_id': 'material' }, registry: POLICY.registry, material_tainted: 'question_typed' } } }));
addB('prov-question-classes-fail', B({ intent_session: { ...B().intent_session, prov: { 'action.params.offer_id': ['web:ad'] } }, artifacts: { facts: [F1], verdicts: [] } }));
addB('prov-deny-stops', B({ intent_session: { ...B().intent_session, prov: { 'action.params.offer_id': ['web:ad'] } }, policy: { ...B().policy, provenance: { params: { 'action.params.offer_id': 'material' }, registry: POLICY.registry, material_tainted: 'deny' } } }));
addB('classes-fail', B({ artifacts: { facts: [F1], verdicts: [verdict(JD[0], 'apologetic')] } }));
addB('only-world', B({ intent_session: { facts: [factRef(F1)] }, policy: { world: WPOL } }));
addB('world-policy-only-fails', B({ intent_session: {}, policy: { world: WPOL } }));
addB('world-offer-null-active', B({ intent_session: { offer_set: null }, policy: {} }));
addB('world-facts-empty-inactive', B({ intent_session: { facts: [] }, policy: {} }));
addB('world-policy-null', Bp({ world: null }));
addB('prov-only-policy-null', B({ intent_session: {}, policy: { provenance: null } }));
addB('prov-only-session-null', B({ intent_session: { prov: null }, policy: {} }));
addB('prov-labels-empty-inactive', B({ intent_session: { labels: [] }, policy: {} }));
addB('prov-labels-active', B({ intent_session: { labels: [D32('lab')] }, policy: {} }));
addB('prov-default-policy-agent-params', B({ intent_session: { prov: { 'action.params.offer_id': ['x'] } }, policy: {} }));
addB('classes-only-committed', B({ intent_session: { classes: two().map(classifierVerdictRef) }, policy: {} }));
addB('classes-only-policy', B({ intent_session: {}, policy: { classifiers: [TONE] } }));
addB('classes-null-policy', B({ intent_session: { classes: [] }, policy: { classifiers: null } }));
addB('single-source-world', B({ intent_session: { facts: [factRef(F1)] }, policy: { world: WPOL } }));
addB('intent-session-null', B({ intent_session: null, policy: {} }));
addB('artifacts-null', B({ artifacts: null }));
addB('policy-null', B({ policy: null }));
for (const n of ['1800000000000', 1.5, null]) addB(`now-${JSON.stringify(n)}`, { ...B(), now: n });
addB('now-missing', { ...B(), now: undefined });
addB('length-objects-inactive', B({ intent_session: { facts: { length: 1 }, classes: { length: 2 }, labels: { length: 3 } }, policy: { world: { worlds: { length: 1 }, relational: { length: 1 }, offers: [] }, classifiers: { length: 1 } } }));
addB('offer-set-number-inactive', B({ intent_session: { offer_set: 5 }, policy: {} }));
addB('offer-set-string-active', B({ intent_session: { offer_set: 'abc' }, policy: {} }));
addB('prov-policy-array-inactive', B({ intent_session: {}, policy: { provenance: [] } }));
addB('prov-policy-string-inactive', B({ intent_session: {}, policy: { provenance: 'x' } }));
addB('prov-active-policy-array', B({ intent_session: { prov: {} }, policy: { provenance: [] } }));
addB('pq-fact-through-wb', B({ intent_session: { facts: [factRef(signFact({ ...FB, value: 38_900 } as J, O[0]!.sk, suite('hybrid-nested-ed25519-ml-dsa-65')) as J)] }, artifacts: { facts: [signFact({ ...FB, value: 38_900 } as J, O[0]!.sk, suite('hybrid-nested-ed25519-ml-dsa-65'))] }, policy: { world: { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0, oracles: [{ kid: 'o1', pk: O[0]!.pk, pq_pk: pqPk('hybrid-nested-ed25519-ml-dsa-65') }] })] } } }));
gu(() => addB('guest-unsupported-fact-through-wb', (() => { const f = fakeSuite(F1, 'hybrid-ed25519-less-cat1'); return B({ intent_session: { facts: [factRef(f)] }, artifacts: { facts: [f] }, policy: { world: { worlds: [fareWorld({ min_oracles: 1, max_faulty: 0, oracles: [{ kid: 'o1', pk: O[0]!.pk, pq_pk: D32('fake-pq-pk') }] })] } } }); })()));
gu(() => addB('guest-unsupported-verdict-through-wb', (() => { const v = fakeSuite(verdict(JD[1], 'apologetic'), 'less-cat1'); return B({ intent_session: { ...B().intent_session, classes: [classifierVerdictRef(verdict(JD[0], 'apologetic')), classifierVerdictRef(v)] }, artifacts: { facts: [F1], verdicts: [verdict(JD[0], 'apologetic'), v] } }); })()));
addB('ctx-intent-session-absent', { ...B(), intent_session: undefined });
addB('ctx-intent-session-array', B({ intent_session: [] }));
addB('ctx-artifacts-array', B({ artifacts: [] }));
addB('ctx-artifacts-facts-null', B({ artifacts: { facts: null, verdicts: two() } }));
addB('ctx-artifacts-labels-object', B({ artifacts: { facts: [F1], verdicts: two(), labels: {} } }));
addB('ctx-artifacts-verdicts-string', B({ artifacts: { facts: [F1], verdicts: 'x' } }));
addB('ctx-artifacts-offer-set-array', B({ artifacts: { facts: [F1], verdicts: two(), offer_set: [] } }));
addB('ctx-artifacts-offer-set-null', B({ artifacts: { facts: [F1], verdicts: two(), offer_set: null } }));
addB('ctx-policy-array', B({ policy: [] }));
addB('ctx-policy-world-null', Bp({ world: null }));
addB('ctx-policy-world-array', Bp({ world: [] }));
addB('ctx-policy-provenance-array', Bp({ provenance: [] }));
addB('ctx-policy-classifiers-object', Bp({ classifiers: {} }));
addB('ctx-policy-absent', { ...B(), policy: undefined });
addB('ctx-artifacts-absent', { ...B(), artifacts: undefined });
addB('ctx-artifacts-unknown-member', B({ artifacts: { facts: [F1], verdicts: two(), extra: 1 } }));
addB('ctx-policy-unknown-member', Bp({ extra: {} }));
addB('ctx-input-array', [] as J);
addB('ctx-input-null', null as J);
addB('world-and-offers', B({
  intent_session: { facts: [factRef(F1)], offer_set: offerSetRef(offerSet()) },
  artifacts: { facts: [F1], offer_set: offerSet() },
  policy: { world: { ...WPOL, relational: [{ name: 'd', fn: 'sub', a: 'action.params.big2', b: 'env.world.fare' }], offers: offerPolicy() } },
  action: { verb: 'air.book', resource: 'skyair.example/bookings', params: { offer_id: 'OF-2', big2: 40_000 } },
}));

const file = { world, prov, cls, wb };
writeFileSync(out, JSON.stringify(file, null, 1) + '\n');
console.log(`ts_v2_wb: ${world.length} world, ${prov.length} prov, ${cls.length} cls, ${wb.length} wb`);
