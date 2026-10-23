// PCA 0.4.2 Intent Layer v2, rule 13 (`intent_session`): verdicts of the TypeScript reference that the guest's
// `intent_session` module must reproduce. Output of the TS reference (packages/pca/src/intent-session.ts,
// intent-session-caveat.ts, intent-revocation.ts, revocation.ts, intent-v2.ts `sessionStep` via `decideIntentV2`).
//   wire        validateIntentSessionWire(v)
//   caveat      intentSessionCaveatError(c); grant_caveat: grantSessionCaveat(grant)
//   roots       sessionRootShapeError(S), verifySessionRoot(S, {pqPins}), sessionRootDigest(S) (`pq_pins` = the verifier's pins)
//   ids         the namespaced revocation ids
//   nonmem      verifyNonMembership(root, proof, id)
//   revocation  checkSessionRevocation (the primitives.intent_revocation input format; rev13-* replicate the conformance set)
//   steps       the `intent_session` check of decideIntentV2 (session-* replicate gen-conformance-intent-v2.mjs)
//     packages/pca/node_modules/.bin/tsx sdks/zkvm-pca/core/tests/gen_ts_v2_session.ts <out.json>
import { writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import * as pca from '../../../../packages/pca/src/index';

const out = process.argv[2];
if (!out) throw new Error('usage: gen_ts_v2_session.ts <out.json>');

const seed = (l: string) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l: string) => {
  const sk = seed(l);
  return { sk, pub: pca.b64u(pca.publicKeyOf(sk)) };
};
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const d32 = (l: string) => pca.b64u(seed(l));
const tail = (s: string) => {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  return s.slice(0, -1) + A[A.indexOf(s.at(-1)!) ^ 1];
};
const principal = mk('v2/principal'), principal2 = mk('v2/principal-2'), agent = mk('v2/agent'), site = mk('v2/site'), stranger = mk('v2/stranger'), revKey = mk('v2/revocation-key');
const NOW = 1_800_000_000_000;
const AUD = 'skyair.example';
const REF = d32('v2/ref'), MAP0 = d32('v2/map0'), MAP1 = d32('v2/map1'), MAP2 = d32('v2/map2'), SESSION = d32('v2/session'), SESSION2 = d32('v2/session-2');

// ---- the site schema (as the conformance stage) ----
const UNSIGNED = {
  v: 1, kind: 'pca-action-schema', site: 'https://skyair.example', aud: AUD, version: '2026-10-01',
  units: { usd_cents: { kind: 'money', currency: 'USD', exponent: 2 } },
  verbs: [
    {
      verb: 'air.book', kind: 'write',
      params: {
        'action.params.offer_id': { type: 'string', semantic: 'product.ref', sensitivity: 'material' },
        'action.params.total': { type: 'integer', unit: 'usd_cents', min: 0, max: 5_000_000, semantic: 'money.amount', sensitivity: 'critical', accumulates_into: ['spend.usd_cents'] },
        'action.params.add_ons': { type: 'set', values: ['none', 'tripshield', 'seat_plus'], default: ['none'], principal_neutral_default: true, semantic: 'product.addon', sensitivity: 'material' },
        'action.params.refundable': { type: 'boolean', semantic: 'flag', sensitivity: 'material' },
      },
      reversibility_by: { param: 'action.params.refundable', map: { true: 'reversible', false: 'irreversible' } },
    },
  ],
};
const SCHEMA = pca.signActionSchema(UNSIGNED as any, 'skyair-2026', site.sk);
const KEYS = [pca.actionSchemaKeyOf('skyair-2026', site.sk)];
const SD = pca.actionSchemaDigest(SCHEMA);

// ---- session roots ----
const TRIP = { id: 'trip_spend', agg: 'sum', unit: 'usd_cents', sel: { accumulates_into: 'spend.usd_cents' }, win: { kind: 'task' }, key: null, domain_max: 500_000, holder: { kind: 'site_local' } };
const QUESTIONS = { id: 'questions', agg: 'count', sel: { event: 'intent_required' }, win: { kind: 'task' }, key: null, cap: 6, holder: { kind: 'wallet' } };
const MON1 = { id: 'quote_first', kind: 'requires_prior', p: { verb: 'air.search' }, q: { verb: ['air.book'] } };
const MON2 = { id: 'confirm', kind: 'responds_within', p: { verb: 'air.book' }, q: { verb: 'air.confirm' }, within: 3, status: 'committed' };
const rootBody = (over: Record<string, unknown> = {}): any => ({
  v: 1, kind: 'pca-intent-session', session: SESSION, principals: [{ key: principal.pub }, { key: principal2.pub }], intent_ref: REF, schema: { aud: AUD, digest: SD },
  layers: { task: { map_digest: MAP0 } }, accumulators: [TRIP, QUESTIONS], monitors: [MON1, MON2], question_uri: 'https://atlas.example/q', expires_at: NOW + 86_400_000, ...over,
});
const sign = (body: any, who = principal, suite?: any) => pca.signSessionRoot(body, who.sk, suite);
const rootOf = (over: Record<string, unknown> = {}, who = principal) => {
  const S = sign(rootBody(over), who);
  return { S, R: pca.sessionRootDigest(S) };
};
const BASE = rootOf();

// ======================================================================================================================
// wire
const wire: any[] = [];
const W = (name: string, v: unknown) => {
  const r = pca.validateIntentSessionWire(v);
  wire.push({ name, v: v === undefined ? null : clone(v), ok: r === null, reason: r });
};
const is0 = (over: Record<string, unknown> = {}) => ({ session: SESSION, root: BASE.R, seq: 0, schema: SD, ...over });
W('ok-minimal', is0());
W('ok-full', is0({ acc: [{ id: 'trip_spend', post: 38_900, receipt: d32('rc') }, { id: 'b', post: 0 }], facts: [d32('f1'), d32('f2')], offer_set: d32('o'), prov: { 'action.params.total': ['pca-labels:x', 'r2'], 'action.params.offer_id': ['é'.repeat(128)] }, classes: [d32('c')], labels: [d32('l')] }));
W('ok-seq-max', is0({ seq: 2_147_483_647 }));
W('ok-empty-lists', is0({ acc: [], facts: [], classes: [], labels: [], prov: {} }));
W('ok-acc-16', is0({ acc: Array.from({ length: 16 }, (_, i) => ({ id: `a${i}`, post: i })) }));
W('ok-acc-id-64', is0({ acc: [{ id: 'a'.repeat(64), post: 9007199254740991 }] }));
W('ok-facts-16', is0({ facts: Array.from({ length: 16 }, (_, i) => d32('f' + i)) }));
W('ok-prov-32', is0({ prov: Object.fromEntries(Array.from({ length: 32 }, (_, i) => [`action.params.p${i}`, ['r']])) }));
W('ok-prov-8-refs', is0({ prov: { 'action.params.x': Array.from({ length: 8 }, (_, i) => 'r' + i) } }));
W('ok-prov-256-bytes', is0({ prov: { 'action.params.x': ['x'.repeat(256)] } }));
W('not-object-array', [is0()]);
W('not-object-null', null);
W('not-object-string', 'x');
W('unknown-member', { ...is0(), note: 'x' });
W('unknown-proto-member', JSON.parse(JSON.stringify(is0()).replace('{', '{"__proto__":1,')));
for (const k of ['session', 'root', 'seq', 'schema']) {
  const v: any = is0();
  delete v[k];
  W('missing-' + k, v);
}
W('session-31', is0({ session: pca.b64u(seed('x').slice(0, 31)) }));
W('session-noncanonical', is0({ session: tail(SESSION) }));
W('root-number', is0({ root: 7 }));
W('schema-padded', is0({ schema: SD + '=' }));
W('seq-negative', is0({ seq: -1 }));
W('seq-over', is0({ seq: 2_147_483_648 }));
W('seq-fraction', is0({ seq: 0.5 }));
W('seq-string', is0({ seq: '0' }));
W('seq-null', is0({ seq: null }));
W('acc-not-array', is0({ acc: {} }));
W('acc-null', is0({ acc: null }));
W('acc-17', is0({ acc: Array.from({ length: 17 }, (_, i) => ({ id: `a${i}`, post: 0 })) }));
W('acc-entry-array', is0({ acc: [[]] }));
W('acc-unknown-member', is0({ acc: [{ id: 'a', post: 1, x: 1 }] }));
W('acc-bad-id', is0({ acc: [{ id: 'a-b', post: 1 }] }));
W('acc-id-65', is0({ acc: [{ id: 'a'.repeat(65), post: 1 }] }));
W('acc-id-empty', is0({ acc: [{ id: '', post: 1 }] }));
W('acc-id-number', is0({ acc: [{ id: 5, post: 1 }] }));
W('acc-id-newline', is0({ acc: [{ id: 'a\n', post: 1 }] }));
W('acc-dup-id', is0({ acc: [{ id: 'a', post: 1 }, { id: 'a', post: 2 }] }));
W('acc-post-fraction', is0({ acc: [{ id: 'a', post: 1.5 }] }));
W('acc-post-negative', is0({ acc: [{ id: 'a', post: -1 }] }));
W('acc-post-unsafe', is0({ acc: [{ id: 'a', post: 9007199254740992 }] }));
W('acc-post-missing', is0({ acc: [{ id: 'a' }] }));
W('acc-receipt-bad', is0({ acc: [{ id: 'a', post: 1, receipt: 'abc' }] }));
W('acc-receipt-null', is0({ acc: [{ id: 'a', post: 1, receipt: null }] }));
W('facts-17', is0({ facts: Array.from({ length: 17 }, (_, i) => d32('f' + i)) }));
W('facts-dup', is0({ facts: [REF, REF] }));
W('facts-bad', is0({ facts: ['x'] }));
W('facts-object', is0({ facts: {} }));
W('offer-set-bad', is0({ offer_set: tail(SD) }));
W('offer-set-null', is0({ offer_set: null }));
W('prov-array', is0({ prov: [] }));
W('prov-33', is0({ prov: Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`action.params.p${i}`, ['r']])) }));
W('prov-bad-path', is0({ prov: { 'env.x': ['r'] } }));
W('prov-nested-path', is0({ prov: { 'action.params.a.b': ['r'] } }));
W('prov-long-name', is0({ prov: { ['action.params.' + 'n'.repeat(65)]: ['r'] } }));
W('prov-empty-refs', is0({ prov: { 'action.params.total': [] } }));
W('prov-9-refs', is0({ prov: { 'action.params.total': Array.from({ length: 9 }, (_, i) => `r${i}`) } }));
W('prov-empty-string', is0({ prov: { 'action.params.total': [''] } }));
W('prov-257-bytes', is0({ prov: { 'action.params.total': ['x'.repeat(257)] } }));
W('prov-257-bytes-multibyte', is0({ prov: { 'action.params.total': ['x' + 'é'.repeat(128)] } }));
W('prov-non-string', is0({ prov: { 'action.params.total': [5] } }));
W('prov-refs-string', is0({ prov: { 'action.params.total': 'r' } }));
W('classes-9', is0({ classes: Array.from({ length: 9 }, (_, i) => d32('c' + i)) }));
W('classes-dup', is0({ classes: [SD, SD] }));
W('labels-17', is0({ labels: Array.from({ length: 17 }, (_, i) => d32('l' + i)) }));
W('labels-bad', is0({ labels: [7] }));

// ======================================================================================================================
// caveat + grantSessionCaveat
const caveat: any[] = [];
const C = (name: string, c: unknown, absent = false) => caveat.push({ name, c: absent ? null : clone(c), absent, reason: pca.intentSessionCaveatError(absent ? undefined : c) });
const cv = (over: Record<string, unknown> = {}) => ({ type: 'intent_session', session: SESSION, seq: 0, root: BASE.R, ...over });
C('ok-seq0', cv());
C('ok-seq1', cv({ seq: 1, prev: d32('p') }));
C('ok-seq-max', cv({ seq: 2_147_483_647, prev: d32('p') }));
C('absent', undefined, true);
C('null', null);
C('array', [cv()]);
C('other-type', cv({ type: 'envelope' }));
C('unknown-member', cv({ x: 1 }));
C('session-bad', cv({ session: 'x' }));
C('root-bad', cv({ root: tail(BASE.R) }));
C('seq-negative', cv({ seq: -1 }));
C('seq-over', cv({ seq: 2_147_483_648, prev: d32('p') }));
C('seq-fraction', cv({ seq: 1.5, prev: d32('p') }));
C('seq-string', cv({ seq: '1', prev: d32('p') }));
C('seq0-with-prev', cv({ prev: d32('p') }));
C('seq1-without-prev', cv({ seq: 1 }));
C('prev-bad', cv({ seq: 1, prev: 'p' }));
C('prev-null', cv({ seq: 1, prev: null }));
const grantCaveat: any[] = [];
const GC = (name: string, grant: unknown) => grantCaveat.push({ name, grant: clone(grant), found: pca.grantSessionCaveat(grant) ?? null });
GC('none', { caveats: [{ type: 'envelope' }] });
GC('first', { caveats: [{ type: 'envelope' }, cv({ x: 1 }), cv()] });
GC('skip-non-objects', { caveats: ['intent_session', null, [cv()], cv({ seq: 3 })] });
GC('caveats-not-array', { caveats: { 0: cv() } });
GC('grant-null', null);
GC('grant-array', [cv()]);

// ======================================================================================================================
// session roots
const roots: any[] = [];
const R = (name: string, s: unknown, requiresSuite?: string, pqPins?: unknown) => {
  const shape = pca.sessionRootShapeError(s);
  const v = pca.verifySessionRoot(s, pqPins === undefined ? {} : { pqPins: pqPins as any });
  let digest: string | null = null;
  try {
    if (v.ok) digest = pca.sessionRootDigest(s as any);
  } catch {
    digest = null;
  }
  roots.push({ name, s: clone(s), ...(requiresSuite ? { requires_suite: requiresSuite } : {}), ...(pqPins !== undefined ? { pq_pins: clone(pqPins) } : {}), shape, verify_ok: v.ok, verify_reason: v.ok ? null : v.reason, digest });
};
const mut = (f: (s: any) => void, base: any = BASE.S) => {
  const s = clone(base);
  f(s);
  return s;
};
R('ok-base', BASE.S);
R('ok-second-principal', sign(rootBody(), principal2));
R('ok-explicit-ed25519', sign({ ...rootBody(), principals: [{ key: principal.pub, alg: 'ed25519' }] }));
R('ok-revocation', rootOf({ revocation: { epoch_uri: 'https://atlas.example/rev', max_age_s: 60, key: revKey.pub } }).S);
R('ok-flows', rootOf({ flows: { read: { allow: ['a'], n: 1.25 } } }).S);
R('ok-layers-all', rootOf({ layers: { org: { digest: d32('org'), name: 'acme' }, std: { profile: 'acme-travel', version: 3, digest: d32('std') }, task: { map_digest: MAP0 } } }).S);
R('layers-org-null', mut((s) => (s.layers.org = null)));
R('layers-std-null', mut((s) => (s.layers.std = null)));
R('ok-revocation-pq-pk', rootOf({ revocation: { epoch_uri: 'u', max_age_s: 60, key: revKey.pub, pq_pk: d32('rk-pq') } }).S);
R('revocation-pq-pk-without-key', mut((s) => (s.revocation = { epoch_uri: 'u', max_age_s: 60, pq_pk: d32('rk-pq') })));
R('revocation-key-missing', mut((s) => (s.revocation = { epoch_uri: 'u', max_age_s: 60 })));
R('revocation-key-is-principal', mut((s) => (s.revocation = { epoch_uri: 'u', max_age_s: 60, key: principal2.pub })));
R('revocation-pq-pk-bad', mut((s) => (s.revocation = { epoch_uri: 'u', max_age_s: 60, key: revKey.pub, pq_pk: 'A' })));
R('revocation-null', mut((s) => (s.revocation = null)));
R('flows-null', mut((s) => (s.flows = null)));
R('alg-x-unknown', mut((s) => (s.alg = 'x-unknown-suite')));
R('alg-fn-dsa-512', mut((s) => ((s.alg = 'fn-dsa-512'), (s.pq_pk = d32('fn')))), 'fn-dsa-512');
R('alg-less-cat1', mut((s) => ((s.alg = 'less-cat1'), (s.pq_pk = d32('less')))), 'less-cat1');
R('alg-hybrid-less-cat1', mut((s) => ((s.alg = 'hybrid-ed25519-less-cat1'), (s.pq_pk = d32('less')), (s.pq_sig = d32('less-sig')))), 'hybrid-ed25519-less-cat1');
R('alg-number', mut((s) => (s.alg = 5)));
R('principal-alg-x-unknown', mut((s) => (s.principals[1].alg = 'x-unknown-suite')));
R('principal-alg-fn-dsa-512', sign({ ...rootBody(), principals: [{ key: principal.pub }, { key: principal2.pub, alg: 'fn-dsa-512' }] }), 'fn-dsa-512');
R('principal-alg-less-cat1', sign({ ...rootBody(), principals: [{ key: principal.pub }, { key: principal2.pub, alg: 'less-cat1' }] }), 'less-cat1');
R('principal-alg-number', mut((s) => (s.principals[1].alg = 5)));
R('ok-no-accs', rootOf({ accumulators: [], monitors: [] }).S);
R('ok-16-principals', sign({ ...rootBody(), principals: [{ key: principal.pub }, ...Array.from({ length: 15 }, (_, i) => ({ key: mk('p' + i).pub }))] }));
R('ok-principal-pq-declared', sign({ ...rootBody(), principals: [{ key: principal.pub, alg: 'ml-dsa-65', pq_pk: d32('pq') }] }));
R('ok-expires-zero', rootOf({ expires_at: 0 }).S);
R('ok-question-uri-2048', rootOf({ question_uri: 'q'.repeat(2048) }).S);
R('ok-seq-accs', rootOf({ accumulators: [TRIP, QUESTIONS, { id: 'seqd', agg: 'max', val: 'action.params.total', sel: { verbs: ['air.book'] }, win: { kind: 'period', ms: 86_400_000, t0: 0 }, key: 'action.params.offer_id', holder: { kind: 'sequenced', uri: 'https://seq.example', root: d32('seqroot'), root_alg: 'ed25519', root_pq_pk: 'AAAA', keys_uri: 'https://seq.example/keys' } }, { id: 'd', agg: 'distinct', val: 'action.params.offer_id', sel: { verbs: ['air.book'] }, win: { kind: 'sliding', ms: 1 }, key: null, holder: { kind: 'site_local' } }] }).S);
// a body nested exactly 32 deep: verifies, but digest(S) throws (the {d, s} wrapper adds a level)
{
  // body = depth 1, flows = depth 2: 31 nested objects reach depth 32 (allowed); the digest wrapper makes it 33
  let edge: any = { leaf: 1 };
  for (let i = 0; i < 29; i++) edge = { n: edge };
  R('deep-flows-31-digest-ok', rootOf({ flows: edge }).S);
  let deep: any = { leaf: 1 };
  for (let i = 0; i < 30; i++) deep = { n: deep };
  R('deep-flows-digest-throws', sign(rootBody({ flows: deep })));
  let deeper: any = { leaf: 1 };
  for (let i = 0; i < 31; i++) deeper = { n: deeper };
  R('deeper-flows-shape-throws', mut((s) => (s.flows = deeper)));
}
// PQ suites (R3-01, guest version 9): a PQ / hybrid root verifies only under the VERIFIER's pin for its signer (pqPins,
// the context's session.pq_pins), never under the root's own principals[].pq_pk
{
  const kp = pca.mlDsa65Keygen(seed('v2/pq-principal'));
  const pqPk = pca.b64u(kp.publicKey);
  const otherPk = pca.b64u(pca.mlDsa65Keygen(seed('other')).publicKey);
  const pin = { [principal.pub]: pqPk };
  const body = { ...rootBody(), principals: [{ key: principal.pub, alg: 'ml-dsa-65', pq_pk: pqPk }] };
  const S65 = sign(body, principal, { alg: 'ml-dsa-65', mlDsa: kp });
  R('pq-ml-dsa-65', S65, 'ml-dsa-65', pin);
  const hb = { ...rootBody(), principals: [{ key: principal.pub, alg: 'hybrid-ed25519-ml-dsa-65', pq_pk: pqPk }] };
  const SH = sign(hb, principal, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: kp });
  R('pq-hybrid', SH, 'hybrid-ed25519-ml-dsa-65', pin);
  const nb = { ...rootBody(), principals: [{ key: principal.pub, alg: 'hybrid-nested-ed25519-ml-dsa-65', pq_pk: pqPk }] };
  R('pq-hybrid-nested', sign(nb, principal, { alg: 'hybrid-nested-ed25519-ml-dsa-65', mlDsa: kp }), 'hybrid-nested-ed25519-ml-dsa-65', pin);
  R('pq-ml-dsa-65-pin-mismatch', mut((x) => (x.principals[0].pq_pk = otherPk), S65), 'ml-dsa-65', pin);
  R('pq-ml-dsa-65-sig-tampered', mut((x) => (x.question_uri = 'https://evil.example'), S65), 'ml-dsa-65', pin);
  R('pq-ml-dsa-65-pq-pk-missing', mut((x) => delete x.pq_pk, S65), 'ml-dsa-65', pin);
  R('pq-ml-dsa-65-pq-pk-missing-unpinned', mut((x) => delete x.pq_pk, S65), 'ml-dsa-65');
  const k87 = pca.mlDsa87Keygen(seed('v2/pq-87'));
  const pk87 = pca.b64u(k87.publicKey);
  R('pq-ml-dsa-87', sign({ ...rootBody(), principals: [{ key: principal.pub, alg: 'ml-dsa-87', pq_pk: pk87 }] }, principal, { alg: 'ml-dsa-87', mlDsa87: k87 }), 'ml-dsa-87', { [principal.pub]: pk87 });
  // the signer's principals entry need not declare a PQ key: the verifier's pin is the authority
  const SU = sign(rootBody(), principal, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: kp });
  R('pq-hybrid-no-entry-unpinned', SU, 'hybrid-ed25519-ml-dsa-65');
  R('pq-hybrid-no-entry-pinned', SU, 'hybrid-ed25519-ml-dsa-65', pin);
  for (const [n, S, alg] of [['ml-dsa-65', S65, 'ml-dsa-65'], ['hybrid', SH, 'hybrid-ed25519-ml-dsa-65']] as const) {
    // the root's own principals entry names the right key, but the verifier pins nothing for the signer
    R(`pq-${n}-unpinned`, S, alg);
    R(`pq-${n}-pins-empty`, S, alg, {});
    R(`pq-${n}-pin-other-signer`, S, alg, { [revKey.pub]: pqPk });
    R(`pq-${n}-pin-other-key`, S, alg, { [principal.pub]: otherPk });
    R(`pq-${n}-pin-non-string`, S, alg, { [principal.pub]: 1 });
    R(`pq-${n}-pin-null`, S, alg, { [principal.pub]: null });
    R(`pq-${n}-pins-array`, S, alg, [pqPk]);
    R(`pq-${n}-pins-null`, S, alg, null);
    R(`pq-${n}-pins-string`, S, alg, pqPk);
    R(`pq-${n}-pin-extra-ok`, S, alg, { [revKey.pub]: otherPk, [principal.pub]: pqPk });
  }
  // the root is signed (and pinned) under one key while the signer's own principals entry declares another
  const SX = sign({ ...rootBody(), principals: [{ key: principal.pub, alg: 'ml-dsa-65', pq_pk: otherPk }] }, principal, { alg: 'ml-dsa-65', mlDsa: kp });
  R('pq-ml-dsa-65-principal-entry-mismatch', SX, 'ml-dsa-65', pin);
  // R3-01: a pure-PQ root signed under an attacker's ML-DSA key, naming the real principal as signer and that key in its
  // principals entry (a pure ML-DSA signature uses no Ed25519 secret): the old rule accepted it; only a verifier pin decides
  const evil = pca.mlDsa65Keygen(seed('v2/pq-attacker'));
  const evilPk = pca.b64u(evil.publicKey);
  const SE = sign({ ...rootBody(), principals: [{ key: principal.pub, alg: 'ml-dsa-65', pq_pk: evilPk }] }, principal, { alg: 'ml-dsa-65', mlDsa: evil });
  R('pq-attacker-root-unpinned', SE, 'ml-dsa-65');
  R('pq-attacker-root-real-pin', SE, 'ml-dsa-65', pin);
  R('pq-attacker-root-attacker-pin', SE, 'ml-dsa-65', { [principal.pub]: evilPk });
  // an Ed25519 root never consults the pins
  R('ed25519-pq-pins-ignored', BASE.S, undefined, { [principal.pub]: otherPk });
  R('ed25519-pq-pins-malformed-ignored', BASE.S, undefined, [1]);
}
// shape / signature mutations
R('not-object', [BASE.S]);
R('null', null);
R('unknown-member', mut((s) => (s.extra = 1)));
R('v-2', mut((s) => (s.v = 2)));
R('v-string', mut((s) => (s.v = '1')));
R('kind-other', mut((s) => (s.kind = 'pca-intent-map')));
R('session-bad', mut((s) => (s.session = tail(s.session))));
R('intent-ref-bad', mut((s) => (s.intent_ref = 5)));
R('principals-empty', mut((s) => (s.principals = [])));
R('principals-17', mut((s) => (s.principals = Array.from({ length: 17 }, (_, i) => ({ key: mk('q' + i).pub })))));
R('principals-not-array', mut((s) => (s.principals = { key: principal.pub })));
R('principal-extra-member', mut((s) => (s.principals[1].x = 1)));
R('principal-key-bad', mut((s) => (s.principals[1].key = 'x')));
R('principal-not-object', mut((s) => (s.principals[1] = principal2.pub)));
R('principal-alg-unknown', mut((s) => (s.principals[1].alg = 'rsa')));
R('principal-alg-null', mut((s) => (s.principals[1].alg = null)));
R('principal-pq-pk-bad', mut((s) => (s.principals[1].pq_pk = 'A')));
R('principal-pq-pk-empty-ok', mut((s) => (s.principals[1].pq_pk = '')));
R('principal-dup', mut((s) => (s.principals[1].key = principal.pub)));
R('schema-extra', mut((s) => (s.schema.x = 1)));
R('schema-aud-empty', mut((s) => (s.schema.aud = '')));
R('schema-digest-bad', mut((s) => (s.schema.digest = 'x')));
R('schema-missing-aud', mut((s) => delete s.schema.aud));
R('layers-array', mut((s) => (s.layers = [])));
R('layers-unknown', mut((s) => (s.layers.site = null)));
R('layers-task-extra', mut((s) => (s.layers.task.x = 1)));
R('layers-task-missing', mut((s) => delete s.layers.task));
R('layers-task-bad', mut((s) => (s.layers.task.map_digest = 'x')));
R('layers-org-no-digest', mut((s) => (s.layers.org = { name: 'acme' })));
R('layers-org-string', mut((s) => (s.layers.org = 'acme')));
R('layers-std-extra', mut((s) => (s.layers.std = { profile: 'p', version: 1, digest: d32('std'), x: 1 })));
R('layers-std-version-0', mut((s) => (s.layers.std = { profile: 'p', version: 0, digest: d32('std') })));
R('layers-std-profile-empty', mut((s) => (s.layers.std = { profile: '', version: 1, digest: d32('std') })));
R('layers-std-profile-129', mut((s) => (s.layers.std = { profile: 'p'.repeat(129), version: 1, digest: d32('std') })));
R('layers-std-profile-128-multibyte-ok', sign({ ...rootBody(), layers: { task: { map_digest: MAP0 }, std: { profile: 'é'.repeat(64), version: 1, digest: d32('std') } } }));
R('layers-std-profile-130-multibyte', mut((s) => (s.layers.std = { profile: 'é'.repeat(65), version: 1, digest: d32('std') })));
R('layers-std-version-fraction', mut((s) => (s.layers.std = { profile: 'p', version: 1.5, digest: d32('std') })));
R('accs-not-array', mut((s) => (s.accumulators = {})));
R('accs-17', mut((s) => (s.accumulators = Array.from({ length: 17 }, (_, i) => ({ ...TRIP, id: 't' + i })))));
R('accs-dup', mut((s) => (s.accumulators = [TRIP, TRIP])));
R('monitors-dup', mut((s) => (s.monitors = [MON1, MON1])));
R('monitors-17', mut((s) => (s.monitors = Array.from({ length: 17 }, (_, i) => ({ ...MON1, id: 'm' + i })))));
R('monitors-missing', mut((s) => delete s.monitors));
// accumulator declaration rules (one mutation per rule)
const A = (name: string, f: (a: any) => void, base: any = TRIP) => {
  const a = clone(base);
  f(a);
  R('acc-' + name, mut((s) => (s.accumulators = [a])));
};
A('not-object', (a) => Object.keys(a).forEach((k) => delete a[k]));
R('acc-string', mut((s) => (s.accumulators = ['trip'])));
A('unknown-member', (a) => (a.x = 1));
A('id-bad', (a) => (a.id = 'a.b'));
A('agg-unknown', (a) => (a.agg = 'avg'));
A('val-bad', (a) => (a.val = 'env.x'));
A('unit-bad', (a) => (a.unit = 'USD'));
A('unit-65', (a) => (a.unit = 'u'.repeat(65)));
A('unit-dotted-ok', (a) => (a.unit = 'usd.cents_2'));
A('unit-trailing-dot', (a) => (a.unit = 'usd.'));
A('sel-not-object', (a) => (a.sel = []));
A('sel-unknown', (a) => (a.sel.x = 1));
A('sel-verbs-empty', (a) => (a.sel = { verbs: [] }));
A('sel-verbs-65', (a) => (a.sel = { verbs: Array.from({ length: 65 }, (_, i) => 'v' + i) }));
A('sel-verbs-empty-string', (a) => (a.sel = { verbs: [''] }));
A('sel-accumulates-into-bad', (a) => (a.sel.accumulates_into = 'Spend'));
A('sel-event-unknown', (a) => (a.sel = { event: 'nope' }), QUESTIONS);
A('sel-both', (a) => (a.sel = { verbs: ['air.book'], event: 'question' }));
A('sel-neither', (a) => (a.sel = {}));
A('win-not-object', (a) => (a.win = 'task'));
A('win-task-extra', (a) => (a.win = { kind: 'task', ms: 1 }));
A('win-sliding-ok', (a) => (a.win = { kind: 'sliding', ms: 60_000 }));
A('win-sliding-zero', (a) => (a.win = { kind: 'sliding', ms: 0 }));
A('win-sliding-extra', (a) => (a.win = { kind: 'sliding', ms: 5, t0: 0 }));
A('win-period-negative-t0', (a) => (a.win = { kind: 'period', ms: 5, t0: -1 }));
A('win-period-missing-t0', (a) => (a.win = { kind: 'period', ms: 5 }));
A('win-unknown', (a) => (a.win = { kind: 'forever' }));
A('key-missing', (a) => delete a.key);
A('key-bad', (a) => (a.key = 'offer_id'));
A('key-ok', (a) => (a.key = 'action.params.offer_id'));
A('domain-max-negative', (a) => (a.domain_max = -1));
A('cap-fraction', (a) => (a.cap = 0.5));
A('holder-not-object', (a) => (a.holder = 'site_local'));
A('holder-site-local-extra', (a) => (a.holder = { kind: 'site_local', uri: 'x' }));
A('holder-unknown', (a) => (a.holder = { kind: 'cloud' }));
A('holder-seq-unknown', (a) => (a.holder = { kind: 'sequenced', uri: 'u', root: d32('r'), x: 1 }));
A('holder-seq-no-uri', (a) => (a.holder = { kind: 'sequenced', uri: '', root: d32('r') }));
A('holder-seq-root-bad', (a) => (a.holder = { kind: 'sequenced', uri: 'u', root: 'r' }));
A('holder-seq-root-alg-bad', (a) => (a.holder = { kind: 'sequenced', uri: 'u', root: d32('r'), root_alg: 'x' }));
A('holder-seq-root-pq-bad', (a) => (a.holder = { kind: 'sequenced', uri: 'u', root: d32('r'), root_pq_pk: 'A=' }));
A('holder-seq-keys-uri-empty', (a) => (a.holder = { kind: 'sequenced', uri: 'u', root: d32('r'), keys_uri: '' }));
A('holder-seq-ok', (a) => (a.holder = { kind: 'sequenced', uri: 'u', root: d32('r') }));
A('holder-seq-root-alg-number', (a) => (a.holder = { kind: 'sequenced', uri: 'u', root: d32('r'), root_alg: 1 }));
R('acc-holder-seq-root-alg-fn-dsa', mut((s) => (s.accumulators = [{ ...clone(TRIP), holder: { kind: 'sequenced', uri: 'u', root: d32('r'), root_alg: 'fn-dsa-1024' } }])), 'fn-dsa-1024');
R('acc-holder-seq-root-alg-less', sign(rootBody({ accumulators: [{ ...clone(TRIP), holder: { kind: 'sequenced', uri: 'u', root: d32('r'), root_alg: 'less-cat1' } }] })), 'less-cat1');
A('id-constructor', (a) => (a.id = 'constructor'));
A('id-prototype', (a) => (a.id = 'prototype'));
A('wallet-action-sel', (a) => (a.holder = { kind: 'wallet' }));
A('event-site-held', (a) => (a.holder = { kind: 'site_local' }), QUESTIONS);
A('max-no-val', (a) => (a.agg = 'max'));
A('distinct-sel-into', (a) => (a.agg = 'distinct'));
A('sum-verbs-no-val', (a) => (a.sel = { verbs: ['air.book'] }));
A('count-with-val', (a) => ((a.agg = 'count'), (a.val = 'action.params.total')));
A('count-ok', (a) => ((a.agg = 'count'), (a.sel = { verbs: ['air.book'] })));
// monitor declaration rules
const M = (name: string, f: (m: any) => void, base: any = MON1) => {
  const m = clone(base);
  f(m);
  R('mon-' + name, mut((s) => (s.monitors = [m])));
};
R('mon-string', mut((s) => (s.monitors = ['m'])));
M('unknown-member', (m) => (m.x = 1));
M('id-bad', (m) => (m.id = ''));
M('id-proto', (m) => (m.id = '__proto__'));
M('kind-unknown', (m) => (m.kind = 'eventually'));
M('p-bad', (m) => (m.p = { verb: [] }));
M('p-verb-number', (m) => (m.p = { verb: 5 }));
M('p-array-mixed', (m) => (m.p = { verb: ['a', 1] }));
M('q-missing', (m) => delete m.q);
M('q-on-never', (m) => (m.kind = 'never'));
M('never-ok', (m) => ((m.kind = 'never'), delete m.q));
M('q-bad', (m) => (m.q = 'air.book'));
M('status-bad', (m) => (m.status = 'pending'));
M('within-on-precedes', (m) => (m.within = 2));
M('within-missing', (m) => delete m.within, MON2);
M('within-0', (m) => (m.within = 0), MON2);
M('within-65', (m) => (m.within = 65), MON2);
M('within-64-ok', (m) => (m.within = 64), MON2);
R('question-uri-empty', mut((s) => (s.question_uri = '')));
R('question-uri-2049', mut((s) => (s.question_uri = 'q'.repeat(2049))));
R('question-uri-2049-multibyte', mut((s) => (s.question_uri = 'q'.repeat(2047) + 'é')));
R('revocation-not-object', mut((s) => (s.revocation = 'x')));
R('revocation-unknown', mut((s) => (s.revocation = { epoch_uri: 'u', max_age_s: 1, key: revKey.pub, x: 1 })));
R('revocation-epoch-uri-empty', mut((s) => (s.revocation = { epoch_uri: '', max_age_s: 1, key: revKey.pub })));
R('revocation-max-age-negative', mut((s) => (s.revocation = { epoch_uri: 'u', max_age_s: -1, key: revKey.pub })));
R('revocation-key-bad', mut((s) => (s.revocation = { epoch_uri: 'u', max_age_s: 1, key: 'k' })));
R('flows-array', mut((s) => (s.flows = [])));
R('flows-unsafe-int', mut((s) => (s.flows = { n: 1e300 })));
R('flows-16-digits', mut((s) => (s.flows = { n: 0.1234567890123456 })));
R('flows-tiny', mut((s) => (s.flows = { n: 1e-7 })));
R('expires-negative', mut((s) => (s.expires_at = -1)));
R('expires-missing', mut((s) => delete s.expires_at));
R('signer-bad', mut((s) => (s.signer = 'x')));
R('signer-not-principal', mut((s) => (s.signer = stranger.pub)));
R('alg-unknown', mut((s) => (s.alg = 'rsa')));
R('alg-null', mut((s) => (s.alg = null)));
R('alg-ed25519-explicit', mut((s) => (s.alg = 'ed25519')));
R('ed25519-with-pq-pk', mut((s) => (s.pq_pk = d32('x'))));
R('ed25519-with-pq-sig', mut((s) => (s.pq_sig = d32('x'))));
R('sig-number', mut((s) => (s.sig = 5)));
R('sig-missing', mut((s) => delete s.sig));
R('sig-flipped', mut((s) => (s.sig = tail(s.sig))));
R('sig-other-principal', mut((s) => (s.signer = principal2.pub)));
R('tampered-question-uri', mut((s) => (s.question_uri = 'https://evil.example/q')));
R('tampered-expires', mut((s) => (s.expires_at = s.expires_at + 1)));
R('tampered-principal-order', mut((s) => s.principals.reverse()));
R('signed-by-stranger-listed', (() => {
  const b = { ...rootBody(), principals: [{ key: principal.pub }, { key: stranger.pub }] };
  return mut((s) => (s.signer = stranger.pub), sign(b));
})());

// ======================================================================================================================
// ids
const ids = {
  session: [SESSION, pca.sessionRevocationId(SESSION)],
  map: [MAP0, pca.mapRevocationId(MAP0)],
  delta: [d32('g'), pca.deltaRevocationId(d32('g'))],
  profile: ['acme-travel', 3, pca.profileRevocationId('acme-travel', 3)],
  scope: [SESSION, pca.sessionRevocationScope(SESSION)],
};

// ======================================================================================================================
// non-membership
const nonmem: any[] = [];
const N = (name: string, root: unknown, proof: unknown, id: string) => nonmem.push({ name, root, proof: clone(proof), id, ok: pca.verifyNonMembership(root as string, proof as any, id) });
{
  const letters = ['b', 'd', 'f', 'h', 'j', 'l', 'n', 'p', 'r', 't', 'v'];
  for (let n = 0; n <= letters.length; n++) {
    const set = new pca.RevocationSet(letters.slice(0, n).map((x) => 'pca-intent:map:' + x));
    for (const q of ['a', 'c', 'e', 'i', 'o', 'u', 'w', 'é']) {
      const id = 'pca-intent:map:' + q;
      if (set.has(id)) continue;
      N(`set${n}-${q}`, set.root, set.nonMembershipProof(id), id);
    }
    if (n > 0) {
      const member = 'pca-intent:map:' + letters[0];
      N(`set${n}-member-with-foreign-proof`, set.root, set.nonMembershipProof('pca-intent:map:a'), member);
    }
  }
  const set = new pca.RevocationSet(['pca-intent:map:b', 'pca-intent:map:d', 'pca-intent:map:f', 'pca-intent:map:h', 'pca-intent:map:j']);
  const id = 'pca-intent:map:e';
  const good: any = set.nonMembershipProof(id);
  const P = (name: string, f: (p: any) => void, root: unknown = set.root, qid = id) => {
    const p = clone(good);
    f(p);
    N('mut-' + name, root, p, qid);
  };
  P('ok', () => {});
  P('root-other', () => {}, new pca.RevocationSet(['x']).root);
  P('root-number', () => {}, 5);
  P('size-off', (p) => (p.size = 6));
  P('size-fraction', (p) => (p.size = 5.5));
  P('size-negative', (p) => (p.size = -1));
  P('size-string', (p) => (p.size = '5'));
  P('no-lo-no-hi', (p) => (delete p.lo, delete p.hi));
  P('lo-null', (p) => (p.lo = null));
  P('lo-false-hi-only', (p) => (p.lo = false));
  P('lo-only', (p) => delete p.hi);
  P('hi-only', (p) => delete p.lo);
  P('lo-true', (p) => (p.lo = true));
  P('lo-id-number', (p) => (p.lo.id = 5));
  P('lo-index-off', (p) => (p.lo.proof.index += 1));
  P('lo-index-fraction', (p) => (p.lo.proof.index = 1.5));
  P('lo-index-string', (p) => (p.lo.proof.index = '1'));
  P('lo-proof-size-off', (p) => (p.lo.proof.size = 4));
  P('lo-side-flip', (p) => (p.lo.proof.path[0].side = p.lo.proof.path[0].side === 'L' ? 'R' : 'L'));
  P('lo-hash-flip', (p) => (p.lo.proof.path[0].hash = tail(p.lo.proof.path[0].hash)));
  P('lo-hash-short-ok-decode', (p) => (p.lo.proof.path[0].hash = 'AAAA'));
  P('lo-hash-padded', (p) => (p.lo.proof.path[0].hash = p.lo.proof.path[0].hash + '='));
  P('lo-hash-number', (p) => (p.lo.proof.path[0].hash = 5));
  P('lo-step-null', (p) => (p.lo.proof.path[0] = null));
  P('lo-path-short', (p) => p.lo.proof.path.pop());
  P('lo-path-long', (p) => p.lo.proof.path.push(p.lo.proof.path[0]));
  P('lo-path-object', (p) => (p.lo.proof.path = {}));
  P('lo-proof-null', (p) => (p.lo.proof = null));
  P('hi-id-equal', (p) => (p.hi.id = id));
  P('swap', (p) => ([p.lo, p.hi] = [p.hi, p.lo]));
  P('not-adjacent', (p) => (p.hi = clone(set.nonMembershipProof('pca-intent:map:i').hi)));
  P('query-out-of-bracket', () => {}, set.root, 'pca-intent:map:g');
  P('query-equal-lo', () => {}, set.root, 'pca-intent:map:d');
  // id below the minimum with a hi that is not leaf 0; above the maximum with a lo that is not the last leaf
  N('below-min-hi-not-first', set.root, { size: 5, hi: clone(set.nonMembershipProof('pca-intent:map:c').hi) }, 'pca-intent:map:a');
  N('above-max-lo-not-last', set.root, { size: 5, lo: clone(set.nonMembershipProof('pca-intent:map:i').lo) }, 'pca-intent:map:z');
  const empty = new pca.RevocationSet([]);
  N('empty-ok', empty.root, { size: 0 }, id);
  N('empty-with-lo', empty.root, { size: 0, lo: good.lo }, id);
  N('empty-lo-null-ok', empty.root, { size: 0, lo: null, hi: 0 }, id);
  N('empty-wrong-root', set.root, { size: 0 }, id);
  N('proof-null', set.root, null, id);
}

// ======================================================================================================================
// revocation (checkSessionRevocation, staged redesign: one dedicated authority, the FULL sorted revoked list, append-only
// against the tracked last epoch). Input format: {epoch, revoked, session, authority, ids, now, max_age_ms, last?}.
const revocation: any[] = [];
const AUTH = revKey;
const REVOKED_DEFAULT = ['pca-intent:map:a', 'pca-intent:session:zzzz'];
const epochOf = (revoked: string[], issued: number, signer = AUTH, scope = pca.sessionRevocationScope(SESSION), suite?: any, over: Record<string, unknown> = {}) => {
  const set = new pca.RevocationSet(revoked);
  const body = { instance_id: 'ana', grant_ref: scope, epoch: set.size, set_size: set.size, root: set.root, issued_at: issued, not_after: issued + 300_000, ...over } as any;
  return { set, epoch: pca.signRevocationEpoch(signer.sk, body, suite) as any };
};
const evOf = (revoked: string[], issued = NOW - 10_000, signer = AUTH, over: Record<string, unknown> = {}) => {
  const { set, epoch } = epochOf(revoked, issued, signer, undefined, undefined, over);
  return { epoch, revoked: set.list() };
};
const REV_ID = pca.sessionRevocationId(SESSION);
type RevArgs = {
  revoked?: string[]; issued?: number; signer?: any; scope?: string; ids?: string[]; maxAge?: number; suite?: any; over?: Record<string, unknown>;
  mutEpoch?: (e: any) => void; ev?: any; evAbsent?: boolean; requiresSuite?: string; idsRaw?: unknown; now?: number; list?: unknown; authority?: unknown; last?: unknown;
};
const V = (name: string, a: RevArgs = {}) => {
  const { revoked = REVOKED_DEFAULT, issued = NOW - 10_000, signer = AUTH, scope, ids = [REV_ID], maxAge = 60_000 } = a;
  const { set, epoch } = epochOf(revoked, issued, signer, scope, a.suite, a.over);
  if (a.mutEpoch) a.mutEpoch(epoch);
  const list = 'list' in a ? a.list : set.list();
  const ev = a.evAbsent ? undefined : a.ev !== undefined ? a.ev : { epoch, revoked: list };
  const idsIn: any = 'idsRaw' in a ? a.idsRaw : ids;
  const authority: any = 'authority' in a ? a.authority : AUTH.pub;
  const now = a.now ?? NOW;
  const r = pca.checkSessionRevocation(ev, { session: SESSION, authority, ids: idsIn, now, maxAgeMs: maxAge, ...('last' in a ? { last: a.last as any } : {}) } as any);
  const input: any = { session: SESSION, authority, ids: idsIn, now, max_age_ms: maxAge, ...('last' in a ? { last: a.last } : {}) };
  const plain = ev !== undefined && ev !== null && typeof ev === 'object' && !Array.isArray(ev);
  if (plain) {
    if ('epoch' in ev) input.epoch = clone(ev.epoch);
    if ('revoked' in ev) input.revoked = clone(ev.revoked);
  }
  revocation.push({ name, input: clone(input), ev_raw: plain || ev === undefined ? undefined : clone(ev), ev_absent: ev === undefined, ...(a.requiresSuite ? { requires_suite: a.requiresSuite } : {}), ok: r.ok, reason: r.ok ? null : r.reason });
};
// the conformance primitives' scenarios (rev13-*), under the new signer model
V('rev13-ok');
V('rev13-ok-empty-set', { revoked: [] });
V('rev13-ok-at-max-age', { issued: NOW - 60_000 });
V('rev13-stale', { issued: NOW - 60_001 });
V('rev13-revoked', { revoked: [REV_ID] });
V('rev13-foreign-signer', { signer: stranger });
V('rev13-other-scope', { scope: pca.sessionRevocationScope(d32('v2/s2')) });
V('rev13-max-age-negative', { maxAge: -1 });
V('rev13-principal-signer', { signer: principal });
V('rev13-future', { issued: NOW + 61_000 });
V('future-at-skew-ok', { issued: NOW + 60_000 });
V('max-age-fraction', { maxAge: 1.5 });
V('max-age-unsafe', { maxAge: 9007199254740992 });
V('max-age-zero-now', { maxAge: 0, issued: NOW });
V('max-age-zero-stale', { maxAge: 0, issued: NOW - 1 });
V('now-fraction', { now: NOW + 0.5 });
V('now-unsafe', { now: 2 ** 53 });
V('ids-string', { idsRaw: REV_ID });
V('ids-object', { idsRaw: { 0: REV_ID } });
V('ids-number-entry', { idsRaw: [5] });
V('authority-number', { authority: 5 });
V('authority-null', { authority: null });
V('authority-principal', { authority: principal.pub });
V('ev-absent', { evAbsent: true });
V('ev-null', { ev: null });
V('ev-array', { ev: [] });
V('ev-string', { ev: 'epoch' });
V('ev-no-epoch', { ev: { revoked: [] } });
V('ev-epoch-zero', { ev: { epoch: 0, revoked: [] } });
V('ev-epoch-string', { ev: { epoch: 'x', revoked: [] } });
V('ev-epoch-array', { ev: { epoch: [], revoked: [] } });
// the epoch's strict shape
V('guardian-number', { mutEpoch: (e) => (e.guardian = 5) });
V('alg-ed25519-explicit-unsigned', { mutEpoch: (e) => (e.alg = 'ed25519') });
V('alg-x-unknown', { mutEpoch: (e) => (e.alg = 'x-unknown-suite') });
V('alg-null', { mutEpoch: (e) => (e.alg = null) });
V('alg-number', { mutEpoch: (e) => (e.alg = 1) });
V('epoch-fraction', { mutEpoch: (e) => (e.epoch = 1.5) });
V('epoch-negative', { mutEpoch: (e) => (e.epoch = -1) });
V('epoch-missing', { mutEpoch: (e) => delete e.epoch });
V('set-size-string', { mutEpoch: (e) => (e.set_size = '2') });
V('instance-missing', { mutEpoch: (e) => delete e.instance_id });
V('instance-number', { mutEpoch: (e) => (e.instance_id = 7) });
V('root-missing', { mutEpoch: (e) => delete e.root });
V('sig-number', { mutEpoch: (e) => (e.sig = 5) });
V('pq-pk-number', { mutEpoch: (e) => (e.pq_pk = 1) });
V('pq-sig-null', { mutEpoch: (e) => (e.pq_sig = null) });
V('guardian-epoch-string', { mutEpoch: (e) => (e.guardian_epoch = '1') });
V('guardian-epoch-ok-unsigned', { mutEpoch: (e) => (e.guardian_epoch = 3) });
V('not-after-string', { over: { not_after: String(NOW + 1000) } });
V('not-after-null', { over: { not_after: null } });
V('issued-string', { over: { issued_at: String(NOW - 10) } });
// signature / binding / freshness
V('sig-flipped', { mutEpoch: (e) => (e.sig = tail(e.sig)) });
V('root-tampered', { mutEpoch: (e) => (e.root = d32('other-root')) });
V('issued-tampered', { mutEpoch: (e) => (e.issued_at += 1) });
V('not-after-past', { over: { not_after: NOW - 1 } });
V('not-after-now', { over: { not_after: NOW } });
// the revoked list is the signed set
V('list-missing', { list: undefined, ev: (() => { const { epoch } = epochOf(REVOKED_DEFAULT, NOW - 10_000); return { epoch }; })() });
V('list-null', { list: null });
V('list-string', { list: 'pca-intent:map:a' });
V('list-number-entry', { list: ['pca-intent:map:a', 5] });
V('list-unsorted', { list: [...REVOKED_DEFAULT].reverse() });
V('list-duplicate', { revoked: ['pca-intent:map:a'], list: ['pca-intent:map:a', 'pca-intent:map:a'] });
V('list-short', { list: REVOKED_DEFAULT.slice(0, 1) });
V('list-substituted', { list: ['pca-intent:map:a', 'pca-intent:session:zzzy'] });
V('list-utf8-order-ok', { revoked: ['pca-intent:map:z', 'pca-intent:map:é', 'pca-intent:map:€'] });
V('list-utf16-order-wrong', { revoked: ['pca-intent:map:z', 'pca-intent:map:\u{1F600}', 'pca-intent:map:｡'], list: ['pca-intent:map:z', 'pca-intent:map:\u{1F600}', 'pca-intent:map:｡'] });
V('epoch-not-size', { over: { epoch: 5 } });
V('empty-list-ok', { revoked: [], ids: [REV_ID, 'pca-intent:map:a'] });
// append-only against the tracked last epoch
{
  const L1 = evOf(['pca-intent:map:a'], NOW - 100_000);
  V('last-ok-extends', { last: L1 });
  V('last-ok-identical', { revoked: ['pca-intent:map:a'], last: evOf(['pca-intent:map:a'], NOW - 50_000) });
  V('last-rollback', { revoked: ['pca-intent:map:a'], last: evOf(['pca-intent:map:a', 'pca-intent:map:b', 'pca-intent:map:c'], NOW - 50_000) });
  V('last-drops', { last: evOf(['pca-intent:map:a', 'pca-intent:map:q'], NOW - 50_000) });
  V('last-equivocation', { revoked: ['pca-intent:map:a', 'pca-intent:map:b'], last: evOf(['pca-intent:map:a', 'pca-intent:map:c'], NOW - 50_000) });
  V('last-null', { last: null });
  V('last-array', { last: [] });
  V('last-list-tampered', { last: { ...clone(L1), revoked: ['pca-intent:map:b'] } });
  V('last-epoch-bad', { last: { ...clone(L1), epoch: { ...clone(L1.epoch), set_size: '1' } } });
  V('last-foreign-signed-ok', { last: evOf(['pca-intent:map:a'], NOW - 100_000, stranger) });
}
{
  const ids3 = [REV_ID, pca.mapRevocationId(MAP0), pca.deltaRevocationId(d32('g'))];
  V('three-ids-ok', { ids: ids3 });
  V('three-ids-second-revoked', { ids: ids3, revoked: [ids3[1]!] });
  V('three-ids-third-revoked', { ids: ids3, revoked: [ids3[2]!, 'pca-intent:x'] });
  V('no-ids', { ids: [] });
  V('ids-inherited-name', { ids: ['toString'] });
}
{
  const kp = pca.mlDsa65Keygen(seed('v2/pq-guardian'));
  V('pq-ml-dsa-65-no-pin', { suite: { alg: 'ml-dsa-65', mlDsa: kp }, requiresSuite: 'ml-dsa-65' });
  V('pq-hybrid-no-pin', { suite: { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: kp }, requiresSuite: 'hybrid-ed25519-ml-dsa-65' });
  V('pq-alg-missing-pq-pk', { mutEpoch: (e) => (e.alg = 'ml-dsa-65'), requiresSuite: 'ml-dsa-65' });
  V('alg-fn-dsa-512', { mutEpoch: (e) => (e.alg = 'fn-dsa-512'), requiresSuite: 'fn-dsa-512' });
  V('alg-less-cat1', { mutEpoch: (e) => ((e.alg = 'less-cat1'), (e.pq_pk = d32('less'))), requiresSuite: 'less-cat1' });
}
// ======================================================================================================================
// steps: the `intent_session` check of decideIntentV2
const steps: any[] = [];
type Mint = { seq: number; prev?: string; map: string; salt: string; signer?: any; root?: string; session?: string; extraCaveats?: any[] };
const cap = (lo: number | null, hi: number) => [{ verb: 'air.book', resource: '*', where: [...(lo !== null ? [{ field: 'env.acc.trip_spend.post', op: 'gt', value: lo }] : []), { field: 'env.acc.trip_spend.post', op: 'lte', value: hi }] }];
const mint = ({ seq, prev, map, salt, signer = principal, root = BASE.R, session = SESSION }: Mint) =>
  pca.mintSessionGrant({ principalSecret: signer.sk, principalPublic: signer.pub, holder: agent.pub, session, seq, ...(prev !== undefined ? { prev } : {}), root, mapDigest: map, predicates: (seq === 0 ? cap(null, 40_000) : cap(40_000, 80_000)) as any, salt }).grant as any;
const PARAMS = { offer_id: 'OF-1', total: 38_900, add_ons: ['none'], refundable: false };
const plan = [{ id: 'book', verb: 'air.book', resource: 'skyair.example/bookings', reversibility_class: 'irreversible' }];
const build = (grant: any, { salt, map, is, ref = REF }: { salt: string; map: string; is?: any; ref?: string }) =>
  pca.buildPCActn({ grant, chain: [grant], plan, nodeId: 'book', params: PARAMS, counter: 1, signerSecret: agent.sk, aud: AUD, now: NOW, ttlMs: 600_000, intent: { ref, map_digest: map, goal_salt: salt, fidelity_ppm: 1_000_000, residual_risk_ppm: 0 }, ...(is ? { intentSession: is } : {}) } as any) as any;
const isOf = (root: string, over: Record<string, unknown> = {}) => ({ session: SESSION, root, seq: 0, schema: SD, acc: [{ id: 'trip_spend', post: 38_900 }], ...over });
const ctxOf = (over: Record<string, unknown> = {}, S: any = BASE.S, grants: any[] = []) => ({ params: PARAMS, schema: { docs: [SCHEMA], keys: KEYS }, session: { root: S, grants }, acc: { state: { trip_spend: { sum: 0 } }, monitors: {} }, ...over });
const T = (name: string, grant: any, pcactn: any, ctx: any, opts: { suite?: string; now?: number } = {}) => {
  const now = opts.now ?? NOW;
  const d = pca.decideIntentV2(pcactn, grant, ctx, now);
  const c = d.checks.find((x: any) => x.name === 'intent_session');
  steps.push({ name, grant: clone(grant), pcactn: clone(pcactn), ctx: ctx === undefined ? null : clone(ctx), ctx_absent: ctx === undefined, now, ...(opts.suite ? { requires_suite: opts.suite } : {}), ctx_error: pca.intentV2ContextError(ctx), reported: c !== undefined, ok: c?.ok ?? null, reason: c?.reason ?? null });
};
const G0 = mint({ seq: 0, map: MAP0, salt: 'salt0' });
const D1 = mint({ seq: 1, prev: G0.id, map: MAP1, salt: 'salt1' });
const D2 = mint({ seq: 2, prev: D1.id, map: MAP2, salt: 'salt2', signer: principal2 });
const P0 = build(G0, { salt: 'salt0', map: MAP0, is: isOf(BASE.R) });
const P1 = build(D1, { salt: 'salt1', map: MAP1, is: isOf(BASE.R, { seq: 1, acc: [{ id: 'trip_spend', post: 77_800 }] }) });
const P2 = build(D2, { salt: 'salt2', map: MAP2, is: isOf(BASE.R, { seq: 2 }) });
const withIs = (p: any, over: Record<string, unknown>) => ({ ...clone(p), intent_session: { ...clone(p.intent_session), ...over } });
// conformance session-* (the intent_session check of each)
T('session-g0', G0, P0, ctxOf());
T('session-d1', D1, P1, ctxOf({}, BASE.S, [G0]));
T('session-d1-unheld', D1, P1, ctxOf());
T('session-backcompat', G0, build(G0, { salt: 'salt0', map: MAP0 }), ctxOf());
T('session-require-absent', G0, build(G0, { salt: 'salt0', map: MAP0 }), ctxOf({ policy: { session: { require: true } } }));
{
  const forged = mint({ seq: 1, prev: G0.id, map: MAP1, salt: 'salt1', signer: agent });
  T('session-agent-signed-delta', forged, build(forged, { salt: 'salt1', map: MAP1, is: isOf(BASE.R, { seq: 1 }) }), ctxOf({}, BASE.S, [G0]));
  const loose = mint({ seq: 1, prev: d32('v2/nope'), map: MAP1, salt: 'salt1' });
  T('session-broken-prev', loose, build(loose, { salt: 'salt1', map: MAP1, is: isOf(BASE.R, { seq: 1 }) }), ctxOf({}, BASE.S, [G0]));
  T('session-seq-mismatch', G0, build(G0, { salt: 'salt0', map: MAP0, is: isOf(BASE.R, { seq: 1 }) }), ctxOf({}, BASE.S, [G0]));
  T('session-ref-not-statement', G0, build(G0, { salt: 'salt0', map: MAP0, is: isOf(BASE.R), ref: d32('v2/x') }), ctxOf());
  T('session-root-missing', G0, P0, ctxOf({ session: { grants: [] } }));
  const expired = rootOf({ expires_at: NOW });
  const ge = mint({ seq: 0, map: MAP0, salt: 'salt0', root: expired.R });
  T('session-root-expired', ge, build(ge, { salt: 'salt0', map: MAP0, is: isOf(expired.R) }), ctxOf({}, expired.S));
  const fresh = rootOf({ expires_at: NOW + 1 });
  const gf = mint({ seq: 0, map: MAP0, salt: 'salt0', root: fresh.R });
  T('root-expires-now-plus-1', gf, build(gf, { salt: 'salt0', map: MAP0, is: isOf(fresh.R) }), ctxOf({}, fresh.S));
}
// step 0: the policy max age
for (const [n, v] of [['negative', -1], ['fraction', 1.5], ['string', '5'], ['null', null], ['unsafe', 9007199254740992], ['zero-ok', 0], ['big-ok', 3600]] as const) {
  T('policy-max-age-' + n, G0, P0, ctxOf({ policy: { session: { max_revocation_age_s: v } } }));
}
T('policy-max-age-bad-before-absent-is', G0, build(G0, { salt: 'salt0', map: MAP0 }), ctxOf({ policy: { session: { require: true, max_revocation_age_s: -1 } } }));
T('policy-session-not-object', G0, P0, ctxOf({ policy: { session: 5 } }));
// steps 1-2
T('require-absent-no-ctx-policy', G0, build(G0, { salt: 'salt0', map: MAP0 }), { policy: { session: { require: true } } });
T('no-intent', G0, (() => { const p = clone(P0); delete p.intent; return p; })(), ctxOf());
T('ctx-absent', G0, P0, undefined);
T('ctx-session-null', G0, P0, ctxOf({ session: null }));
// step 3
T('root-null', G0, P0, ctxOf({}, null));
T('root-tampered', G0, P0, ctxOf({}, mut((s) => (s.question_uri = 'https://evil.example'))));
T('root-shape-bad', G0, P0, ctxOf({}, mut((s) => (s.extra = 1))));
T('root-digest-mismatch', G0, withIs(P0, { root: d32('other-root') }), ctxOf());
{
  const other = rootOf({ session: SESSION2 });
  T('root-other-session', G0, withIs(P0, { root: other.R }), ctxOf({}, other.S));
  const deep = (() => { let x: any = { leaf: 1 }; for (let i = 0; i < 30; i++) x = { n: x }; return { S: sign(rootBody({ flows: x })) }; })();
  T('root-deep-digest-throws', G0, withIs(P0, { root: d32('any') }), ctxOf({}, deep.S));
  const kp = pca.mlDsa65Keygen(seed('v2/pq-principal'));
  const pqS = sign({ ...rootBody(), principals: [{ key: principal.pub, alg: 'ml-dsa-65', pq_pk: pca.b64u(kp.publicKey) }] }, principal, { alg: 'ml-dsa-65', mlDsa: kp });
  const pqR = pca.sessionRootDigest(pqS);
  const gq = mint({ seq: 0, map: MAP0, salt: 'salt0', root: pqR });
  const pq0 = build(gq, { salt: 'salt0', map: MAP0, is: isOf(pqR) });
  const pqCtx = (pins?: unknown) => ctxOf({ session: { root: pqS, grants: [], ...(pins !== undefined ? { pq_pins: pins } : {}) } });
  T('root-pq-principal-pinned', gq, pq0, pqCtx({ [principal.pub]: pca.b64u(kp.publicKey) }), { suite: 'ml-dsa-65' });
  // R3-01 (guest version 9): the root's own principals entry is not a pin
  T('root-pq-principal-entry-only', gq, pq0, pqCtx(), { suite: 'ml-dsa-65' });
}
T('schema-digest-mismatch', G0, withIs(P0, { schema: d32('other-schema') }), ctxOf());
T('aud-mismatch', G0, { ...clone(P0), aud: 'other.example' }, ctxOf());
T('aud-absent', G0, (() => { const p = clone(P0); delete p.aud; return p; })(), ctxOf());
T('seq0-map-mismatch', G0, { ...clone(P0), intent: { ...P0.intent, map_digest: MAP1 } }, ctxOf());
T('seq1-map-free', D1, { ...clone(P1), intent: { ...P1.intent, map_digest: d32('anything') } }, ctxOf({}, BASE.S, [G0]));
// step 4
{
  const strip = (g: any, f: (cs: any[]) => any[]) => ({ ...clone(g), caveats: f(clone(g.caveats)) });
  T('grant-no-session-caveat', strip(G0, (cs) => cs.filter((c) => c.type !== 'intent_session')), P0, ctxOf());
  T('grant-caveat-malformed', strip(G0, (cs) => cs.map((c) => (c.type === 'intent_session' ? { ...c, x: 1 } : c))), P0, ctxOf());
  T('grant-first-caveat-wins', strip(G0, (cs) => [{ ...cs[1], seq: 0, root: d32('zz') }, ...cs]), P0, ctxOf());
  T('grant-caveat-other-session', strip(G0, (cs) => cs.map((c) => (c.type === 'intent_session' ? { ...c, session: SESSION2 } : c))), P0, ctxOf());
  T('grant-caveat-other-root', strip(G0, (cs) => cs.map((c) => (c.type === 'intent_session' ? { ...c, root: d32('zz') } : c))), P0, ctxOf());
  T('grant-caveats-not-array', { ...clone(G0), caveats: {} }, P0, ctxOf());
  // step 5
  T('grant-issuer-stranger', { ...clone(G0), issuer: stranger.pub }, P0, ctxOf());
  T('grant-issuer-missing', (() => { const g = clone(G0); delete g.issuer; return g; })(), P0, ctxOf());
  T('grant-issuer-principal2', { ...clone(G0), issuer: principal2.pub }, P0, ctxOf());
}
// step 6: the delta chain
T('chain-d2-ok', D2, P2, ctxOf({}, BASE.S, [G0, D1]));
T('chain-d2-extra-held-ok', D2, P2, ctxOf({}, BASE.S, [G0, D1, D2]));
T('chain-d2-one-held', D2, P2, ctxOf({}, BASE.S, [G0]));
T('chain-grants-object', D2, P2, ctxOf({}, BASE.S, { 0: G0, 1: D1 } as any));
T('chain-grants-null', D1, P1, ctxOf({}, BASE.S, null as any));
T('chain-grants-null-seq0-ok', G0, P0, ctxOf({}, BASE.S, null as any));
T('chain-swapped', D2, P2, ctxOf({}, BASE.S, [D1, G0]));
T('chain-held-0-null', D2, P2, ctxOf({}, BASE.S, [null, D1]));
T('chain-held-0-stranger', D2, P2, ctxOf({}, BASE.S, [{ ...clone(G0), issuer: stranger.pub }, D1]));
T('chain-held-1-bad-prev', D2, P2, ctxOf({}, BASE.S, [G0, mint({ seq: 1, prev: d32('nope'), map: MAP1, salt: 'salt1' })]));
T('chain-held-1-other-session', D2, P2, ctxOf({}, BASE.S, [G0, mint({ seq: 1, prev: G0.id, map: MAP1, salt: 'salt1', session: SESSION2 })]));
T('chain-admitting-bad-prev', mint({ seq: 2, prev: G0.id, map: MAP2, salt: 'salt2' }), P2, ctxOf({}, BASE.S, [G0, D1]));
T('chain-held-0-id-tampered', D1, P1, ctxOf({}, BASE.S, [{ ...clone(G0), id: d32('other-id') }]));
// step 7: revocation (the dedicated authority S.revocation.key, the full revoked list, append-only)
{
  const R4 = rootOf({ revocation: { epoch_uri: 'https://atlas.example/rev', max_age_s: 60, key: revKey.pub }, layers: { task: { map_digest: MAP0 }, std: { profile: 'acme-travel', version: 3, digest: d32('std') } } });
  const g0 = mint({ seq: 0, map: MAP0, salt: 'salt0', root: R4.R });
  const d1 = mint({ seq: 1, prev: g0.id, map: MAP1, salt: 'salt1', root: R4.R });
  const p0 = build(g0, { salt: 'salt0', map: MAP0, is: isOf(R4.R) });
  const p1 = build(d1, { salt: 'salt1', map: MAP1, is: isOf(R4.R, { seq: 1 }) });
  const ids0 = [pca.sessionRevocationId(SESSION), pca.mapRevocationId(MAP0), pca.deltaRevocationId(g0.id), pca.profileRevocationId('acme-travel', 3)];
  const ids1 = [pca.sessionRevocationId(SESSION), pca.mapRevocationId(MAP1), pca.deltaRevocationId(g0.id), pca.deltaRevocationId(d1.id), pca.profileRevocationId('acme-travel', 3)];
  const c = (S: any, grants: any[], rev?: any, policy?: any, last?: any) =>
    ctxOf({ ...(policy ? { policy } : {}), session: { root: S, grants, ...(rev !== undefined ? { revocation: rev } : {}), ...(last !== undefined ? { revocation_last: last } : {}) } });
  T('rev-fresh', g0, p0, c(R4.S, [], evOf(['pca-intent:session:zz'], NOW - 30_000)));
  T('rev-d1-fresh', d1, p1, c(R4.S, [g0], evOf([], NOW - 1_000)));
  T('rev-d1-held-delta-revoked', d1, p1, c(R4.S, [g0], evOf([ids1[2]!], NOW - 1_000)));
  T('rev-d1-admitting-revoked', d1, p1, c(R4.S, [g0], evOf([ids1[3]!], NOW - 1_000)));
  T('rev-profile-revoked', g0, p0, c(R4.S, [], evOf([ids0[3]!], NOW - 1_000)));
  T('rev-absent', g0, p0, c(R4.S, []));
  T('rev-stale', g0, p0, c(R4.S, [], evOf([], NOW - 61_000)));
  T('rev-at-max', g0, p0, c(R4.S, [], evOf([], NOW - 60_000)));
  T('rev-session-revoked', g0, p0, c(R4.S, [], evOf([ids0[0]!], NOW - 1_000)));
  T('rev-map-revoked', g0, p0, c(R4.S, [], evOf([ids0[1]!], NOW - 1_000)));
  T('rev-delta-revoked', g0, p0, c(R4.S, [], evOf([ids0[2]!], NOW - 1_000)));
  T('rev-principal-signer', g0, p0, c(R4.S, [], evOf([], NOW - 1_000, principal)));
  T('rev-foreign-signer', g0, p0, c(R4.S, [], evOf([], NOW - 1_000, stranger)));
  T('rev-policy-stricter', g0, p0, c(R4.S, [], evOf([], NOW - 20_000), { session: { max_revocation_age_s: 10 } }));
  T('rev-policy-looser-root-wins', g0, p0, c(R4.S, [], evOf([], NOW - 61_000), { session: { max_revocation_age_s: 600 } }));
  T('rev-policy-misconfigured', g0, p0, c(R4.S, [], evOf([], NOW - 1_000), { session: { max_revocation_age_s: -1 } }));
  T('rev-other-scope', g0, p0, c(R4.S, [], (() => { const { set, epoch } = epochOf([], NOW - 1_000, revKey, pca.sessionRevocationScope(SESSION2)); return { epoch, revoked: set.list() }; })()));
  T('rev-list-tampered', g0, p0, c(R4.S, [], { ...evOf([ids0[1]!], NOW - 1_000), revoked: [] }));
  T('rev-last-ok', g0, p0, c(R4.S, [], evOf(['pca-intent:map:x'], NOW - 1_000), undefined, evOf([], NOW - 90_000)));
  T('rev-last-drops', g0, p0, c(R4.S, [], evOf(['pca-intent:map:x'], NOW - 1_000), undefined, evOf(['pca-intent:map:y'], NOW - 90_000)));
  T('rev-last-rollback', g0, p0, c(R4.S, [], evOf([], NOW - 1_000), undefined, evOf(['pca-intent:map:y'], NOW - 90_000)));
  T('rev-last-null', g0, p0, c(R4.S, [], evOf([], NOW - 1_000), undefined, null));
  T('rev-last-malformed', g0, p0, c(R4.S, [], evOf([], NOW - 1_000), undefined, { epoch: 1 }));
  // policy-only Δ_rev: S names no authority
  T('rev-policy-only-no-authority', G0, P0, ctxOf({ policy: { session: { max_revocation_age_s: 30 } } }));
  T('rev-policy-zero-with-authority', g0, p0, c(R4.S, [], evOf([], NOW), { session: { max_revocation_age_s: 0 } }));
  // huge max ages: 2^53-1 s * 1000 is not a safe integer -> misconfigured inside the revocation step
  const RH = rootOf({ revocation: { epoch_uri: 'u', max_age_s: 9007199254740991, key: revKey.pub } });
  const gh = mint({ seq: 0, map: MAP0, salt: 'salt0', root: RH.R });
  T('rev-huge-max-age', gh, build(gh, { salt: 'salt0', map: MAP0, is: isOf(RH.R) }), c(RH.S, [], evOf([], NOW - 1_000)));
  // the admitting grant's id is not a string: the TS template literal stringifies it
  const gNum = { ...clone(g0), id: 12345 };
  T('rev-grant-id-number', gNum, p0, c(R4.S, [], evOf([], NOW - 1_000)));
  T('rev-grant-id-number-revoked', gNum, p0, c(R4.S, [], evOf(['pca-intent:delta:12345'], NOW - 1_000)));
  const gUndef = (() => { const g = clone(g0); delete g.id; return g; })();
  T('rev-grant-id-missing-revoked', gUndef, p0, c(R4.S, [], evOf(['pca-intent:delta:undefined'], NOW - 1_000)));
}

// ---- strict pass (5e0a33a9): the conformance session-* strictness / null-vs-absent / suite vectors, plus guest extras ----
{
  T('session-policy-age-string', G0, P0, ctxOf({ policy: { session: { max_revocation_age_s: '60' } } }));
  T('session-grants-string', G0, P0, ctxOf({ session: { root: BASE.S, grants: 'G0' } }));
  T('ctx-session-grants-null', G0, P0, ctxOf({ session: { root: BASE.S, grants: null } }));
  T('ctx-session-grants-absent', G0, P0, ctxOf({ session: { root: BASE.S } }));
  T('ctx-session-revocation-null', G0, P0, ctxOf({ session: { root: BASE.S, grants: [], revocation: null } }));
  T('ctx-session-revocation-array', G0, P0, ctxOf({ session: { root: BASE.S, grants: [], revocation: [] } }));
  T('ctx-session-array', G0, P0, ctxOf({ session: [] }));
  // session.pq_pins (the verifier's session-root PQ pins): absent = none; present it is an object of strings
  T('ctx-session-pq-pins-null', G0, P0, ctxOf({ session: { root: BASE.S, grants: [], pq_pins: null } }));
  T('ctx-session-pq-pins-array', G0, P0, ctxOf({ session: { root: BASE.S, grants: [], pq_pins: [] } }));
  T('ctx-session-pq-pins-string', G0, P0, ctxOf({ session: { root: BASE.S, grants: [], pq_pins: 'x' } }));
  T('ctx-session-pq-pins-non-string', G0, P0, ctxOf({ session: { root: BASE.S, grants: [], pq_pins: { [principal.pub]: 1 } } }));
  T('ctx-session-pq-pins-null-value', G0, P0, ctxOf({ session: { root: BASE.S, grants: [], pq_pins: { [principal.pub]: null } } }));
  T('ctx-session-pq-pins-nested', G0, P0, ctxOf({ session: { root: BASE.S, grants: [], pq_pins: { [principal.pub]: { k: 'x' } } } }));
  T('ctx-session-pq-pins-empty', G0, P0, ctxOf({ session: { root: BASE.S, grants: [], pq_pins: {} } }));
  T('ctx-session-pq-pins-other-ok', G0, P0, ctxOf({ session: { root: BASE.S, grants: [], pq_pins: { [revKey.pub]: d32('x') } } }));
  T('ctx-policy-null', G0, P0, ctxOf({ policy: null })); // pipeline-level (malformed top-level context)
  T('session-root-layers-org-null', G0, P0, ctxOf({ session: { root: { ...BASE.S, layers: { ...BASE.S.layers, org: null } }, grants: [] } }));
  T('session-root-revocation-null', G0, P0, ctxOf({ session: { root: { ...BASE.S, revocation: null }, grants: [] } }));
  T('session-root-unknown-suite', G0, P0, ctxOf({ session: { root: { ...BASE.S, alg: 'x-unknown-suite' }, grants: [] } }));
  T('clock-fraction', G0, P0, ctxOf(), { now: NOW + 0.5 });
  T('clock-unsafe', G0, P0, ctxOf(), { now: 2 ** 53 });
  const ml65 = pca.mlDsa65Keygen(seed('v2/ml65'));
  const ml87 = pca.mlDsa87Keygen(seed('v2/ml87'));
  const pq65 = pca.encodeMlDsaPublicKey(ml65.publicKey);
  const pq87 = pca.b64u(ml87.publicKey);
  for (const [alg, mat, pq] of [['hybrid-ed25519-ml-dsa-65', { mlDsa: ml65 }, pq65], ['ml-dsa-65', { mlDsa: ml65 }, pq65], ['ml-dsa-87', { mlDsa87: ml87 }, pq87]] as const) {
    const S = pca.signSessionRoot(rootBody({ principals: [{ key: principal.pub, alg, pq_pk: pq }] }), principal.sk, { alg, ...(mat as any) } as any);
    const R = pca.sessionRootDigest(S);
    const g = mint({ seq: 0, map: MAP0, salt: 'salt0', root: R });
    const p = build(g, { salt: 'salt0', map: MAP0, is: isOf(R) });
    const c = (pins?: unknown) => ctxOf({ session: { root: S, grants: [], ...(pins !== undefined ? { pq_pins: pins } : {}) } });
    T(`session-root-${alg}`, g, p, c({ [principal.pub]: pq }), { suite: alg });
    // R3-01 (conformance session-root-<alg>-{unpinned,pin-other-signer,pin-mismatch})
    T(`session-root-${alg}-unpinned`, g, p, c(), { suite: alg });
    T(`session-root-${alg}-pin-other-signer`, g, p, c({ [revKey.pub]: pq }), { suite: alg });
    T(`session-root-${alg}-pin-mismatch`, g, p, c({ [principal.pub]: alg === 'ml-dsa-87' ? pq65 : pq87 }), { suite: alg });
  }
  {
    // the signer's own principals entry declares another PQ key than the (pinned) one the root is signed under
    const Sx = pca.signSessionRoot(rootBody({ principals: [{ key: principal.pub, alg: 'ml-dsa-65', pq_pk: pq87 }] }), principal.sk, { alg: 'ml-dsa-65', mlDsa: ml65 } as any);
    const Rx = pca.sessionRootDigest(Sx);
    const gx = mint({ seq: 0, map: MAP0, salt: 'salt0', root: Rx });
    T('session-root-ml-dsa-65-principal-entry-mismatch', gx, build(gx, { salt: 'salt0', map: MAP0, is: isOf(Rx) }), ctxOf({ session: { root: Sx, grants: [], pq_pins: { [principal.pub]: pq65 } } }), { suite: 'ml-dsa-65' });
    // an Ed25519 root ignores pq_pins (even one naming its signer with an unrelated key)
    T('session-root-ed25519-pq-pins-ignored', G0, P0, ctxOf({ session: { root: BASE.S, grants: [], pq_pins: { [principal.pub]: pq65 } } }));
  }
  // PQ revocation epochs: only by the authority, only under S.revocation.pq_pk
  const set0 = new pca.RevocationSet([]);
  const epochPq = (signer: any, mat: any) => pca.signRevocationEpoch(signer.sk, { instance_id: 'ana', grant_ref: pca.sessionRevocationScope(SESSION), epoch: 0, set_size: 0, root: set0.root, issued_at: NOW - 1_000, not_after: NOW + 300_000 }, mat);
  const caseRev = (name: string, over: Record<string, unknown>, ep: any, suite: string) => {
    const RR = rootOf(over);
    const g = mint({ seq: 0, map: MAP0, salt: 'salt0', root: RR.R });
    T(name, g, build(g, { salt: 'salt0', map: MAP0, is: isOf(RR.R) }), ctxOf({ session: { root: RR.S, grants: [], revocation: { epoch: ep, revoked: [] } } }), { suite });
  };
  const rev = { epoch_uri: 'https://atlas.example/rev', max_age_s: 60, key: revKey.pub };
  const epK = epochPq(revKey, { alg: 'ml-dsa-65', mlDsa: ml65 });
  caseRev('revocation-key-pq-pinned', { revocation: { ...rev, pq_pk: pq65 } }, epK, 'ml-dsa-65');
  caseRev('revocation-key-pq-unpinned', { revocation: rev }, epK, 'ml-dsa-65');
  caseRev('revocation-key-pq-pin-other', { revocation: { ...rev, pq_pk: pca.b64u(ml87.publicKey) } }, epK, 'ml-dsa-65');
  caseRev('revocation-principal-pq-epoch', { principals: [{ key: principal.pub, alg: 'ml-dsa-65', pq_pk: pq65 }], revocation: { ...rev, pq_pk: pq65 } }, epochPq(principal, { alg: 'ml-dsa-65', mlDsa: ml65 }), 'ml-dsa-65');
  caseRev('revocation-hybrid-pinned', { revocation: { ...rev, pq_pk: pq65 } }, epochPq(revKey, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml65 }), 'hybrid-ed25519-ml-dsa-65');
  caseRev('revocation-ml-dsa-87-pinned', { revocation: { ...rev, pq_pk: pq87 } }, epochPq(revKey, { alg: 'ml-dsa-87', mlDsa87: ml87 }), 'ml-dsa-87');
  // held grants: capability objects whose suite this verifier implements
  T('held-grant-id-number', D1, P1, ctxOf({}, BASE.S, [{ ...clone(G0), id: 5 }]));
  T('held-grant-issuer-missing', D1, P1, ctxOf({}, BASE.S, [(() => { const g = clone(G0); delete g.issuer; return g; })()]));
  T('held-grant-array', D1, P1, ctxOf({}, BASE.S, [[G0]]));
  T('held-grant-alg-unknown', D1, P1, ctxOf({}, BASE.S, [{ ...clone(G0), alg: 'x-unknown-suite' }]));
  T('held-grant-alg-number', D1, P1, ctxOf({}, BASE.S, [{ ...clone(G0), alg: 7 }]));
  T('held-grant-alg-fn-dsa', D1, P1, ctxOf({}, BASE.S, [{ ...clone(G0), alg: 'fn-dsa-512' }]), { suite: 'fn-dsa-512' });
  T('held-grant-alg-less-cat1', D1, P1, ctxOf({}, BASE.S, [{ ...clone(G0), alg: 'less-cat1' }]), { suite: 'less-cat1' });
  T('held-grant-alg-ml-dsa-65', D1, P1, ctxOf({}, BASE.S, [{ ...clone(G0), alg: 'ml-dsa-65' }]), { suite: 'ml-dsa-65' });
}

const fixture = { generated_by: 'sdks/zkvm-pca/core/tests/gen_ts_v2_session.ts', now: NOW, wire, caveat, grant_caveat: grantCaveat, roots, ids, nonmem, revocation, steps };
writeFileSync(out, JSON.stringify(fixture));
console.log(`ts_v2_session: wire ${wire.length}, caveat ${caveat.length}, grant_caveat ${grantCaveat.length}, roots ${roots.length}, nonmem ${nonmem.length}, revocation ${revocation.length}, steps ${steps.length}`);
