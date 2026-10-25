// PCA 0.4.2 Intent Layer v2, conformance rule 15 (`accumulators`): verdicts of the TypeScript reference that the guest's
// `intent_acc` module must reproduce. Output of the TS reference; NOT a standard vector.
//   cases[]:      decideIntentV2(p, grant, ctx, now) -> the `accumulators` check + env.acc / env.mon (the reference includes
//                 the bound-root step; every case here has a BOUND root, asserted below, so the guest's acc_step - which
//                 takes the bound root - must agree). `requires_suite: alg` marks a case needing a suite the guest does
//                 not implement (the guest must fail it with `unsupported_suite`); `guest_reason_contains` a reason the guest
//                 must give; `top_ctx_error` a context the coordinator refuses before rule 15 (intentV2ContextError).
//   decls[] / monitors[] / pre_states[] / combine[] / arith[] / digests[] / receipt_shapes[] / key_set_shapes[]: the
//                 helpers on their own.
//     packages/pca/node_modules/.bin/tsx sdks/zkvm-pca/core/tests/gen_ts_v2_acc.ts <out.json>
import { writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import {
  b64u,
  publicKeyOf,
  hashCanonical,
  mlDsa65Keygen,
  mlDsa87Keygen,
  fnDsa512Keygen,
  fnDsa1024Keygen,
  slhDsa128fKeygen,
  intentV2ContextError,
  encodeMlDsaPublicKey,
  encodeMlDsa87PublicKey,
  actionSchemaDigest,
  signSessionRoot,
  sessionRootDigest,
  verifySessionRoot,
  signAccReceipt,
  accReceiptDigest,
  pcactnReservationDigest,
  signSequencerKeySet,
  sequencerKeySetShapeError,
  accReceiptShapeError,
  accumulatorDeclError,
  monitorDeclError,
  monitorStates,
  preStateError,
  combineAcc,
  preValue,
  receiptArithmeticOk,
  accSelects,
  accValueOf,
  decideIntentV2,
  sequencerKeySetDigest,
} from '../../../../packages/pca/src/index';

const out = process.argv[2];
if (!out) throw new Error('usage: gen_ts_v2_acc.ts <out.json>');
const seed = (l: string) => new Uint8Array(createHash('sha256').update(`zk-v2-acc/${l}`).digest());
const mk = (l: string) => { const sk = seed(l); return { sk, pub: b64u(publicKeyOf(sk)) }; };
const d32 = (l: string) => b64u(seed(l));
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const principal = mk('principal'), seqRoot = mk('seq-root'), s1 = mk('seq-1'), s2 = mk('seq-2'), stranger = mk('stranger'), seqRoot2 = mk('seq-root-2');
const NOW = 1_800_000_000_000;
const AUD = 'pay.example';
const SESSION = d32('session');
const MAX = Number.MAX_SAFE_INTEGER;

// ---- schemas (unsigned: accStep never verifies the schema, it looks it up by digest) -------------------------------
const SCHEMA: any = {
  v: 1, kind: 'pca-action-schema', site: 'https://pay.example', aud: AUD, version: '1',
  verbs: [
    {
      verb: 'pay.send', kind: 'write',
      params: {
        'action.params.payee': { type: 'string', semantic: 'party.ref', sensitivity: 'material' },
        'action.params.amount': { type: 'integer', semantic: 'money.amount', sensitivity: 'critical', accumulates_into: ['spend.usd_cents'] },
        'action.params.fee': { type: 'integer', semantic: 'money.amount', sensitivity: 'critical', required: false, accumulates_into: ['spend.usd_cents', 'fees'] },
        'action.params.memo': { type: 'string', semantic: 'text.memo', sensitivity: 'free', required: false },
        'action.params.ref': { type: 'integer', semantic: 'id.num', sensitivity: 'material', required: false },
        'action.params.tip': { type: 'string', semantic: 'money.amount', sensitivity: 'free', required: false, accumulates_into: ['spend.usd_cents'] },
      },
    },
    { verb: 'air.book', kind: 'write', params: { 'action.params.total': { type: 'integer', semantic: 'money.amount', sensitivity: 'critical', accumulates_into: ['spend.usd_cents'] } } },
    { verb: 'air.search', kind: 'read', params: { 'action.params.pax': { type: 'integer', semantic: 'quantity', sensitivity: 'material' } } },
  ],
};
const SD = actionSchemaDigest(SCHEMA);
const withVerbs = (verbs: unknown) => ({ ...clone(SCHEMA), verbs });
const payVerb = () => clone(SCHEMA.verbs[0]);

// ---- declarations ---------------------------------------------------------------------------------------------------
const SITE = { kind: 'site_local' };
const SEQ_HOLDER = { kind: 'sequenced', uri: 'https://seq.example', root: seqRoot.pub };
const D: Record<string, any> = {
  spent: { id: 'spent', agg: 'sum', val: 'action.params.amount', sel: { verbs: ['pay.send'] }, win: { kind: 'task' }, key: null, holder: SITE },
  spend_unit: { id: 'spend_unit', agg: 'sum', unit: 'usd_cents', sel: { accumulates_into: 'spend.usd_cents' }, win: { kind: 'sliding', ms: 3_600_000 }, key: null, domain_max: 1_000_000, holder: SITE },
  per_payee: { id: 'per_payee', agg: 'count', sel: { verbs: ['pay.send'] }, win: { kind: 'period', ms: 86_400_000, t0: 0 }, key: 'action.params.payee', domain_max: 5, holder: SITE },
  payees: { id: 'payees', agg: 'distinct', val: 'action.params.payee', sel: { verbs: ['pay.send', 'air.book'] }, win: { kind: 'task' }, key: null, holder: SITE },
  largest: { id: 'largest', agg: 'max', val: 'action.params.amount', sel: { verbs: ['pay.send'] }, win: { kind: 'task' }, key: null, domain_max: 50_000, holder: SITE },
  flights: { id: 'flights', agg: 'sum', val: 'action.params.total', sel: { verbs: ['air.book'] }, win: { kind: 'task' }, key: null, holder: SITE },
  questions: { id: 'questions', agg: 'count', sel: { event: 'intent_required' }, win: { kind: 'task' }, key: null, cap: 6, holder: { kind: 'wallet' } },
};
const SEQ_SUM = { id: 'seq_spent', agg: 'sum', val: 'action.params.amount', sel: { verbs: ['pay.send'] }, win: { kind: 'task' }, key: null, domain_max: 100_000, holder: SEQ_HOLDER };
const SEQ_CNT = { id: 'seq_count', agg: 'count', sel: { verbs: ['pay.send'] }, win: { kind: 'task' }, key: null, holder: SEQ_HOLDER };
const SEQ_MAX = { id: 'seq_max', agg: 'max', val: 'action.params.amount', sel: { verbs: ['pay.send'] }, win: { kind: 'task' }, key: null, holder: SEQ_HOLDER };
const SEQ_DIST = { id: 'seq_dist', agg: 'distinct', val: 'action.params.payee', sel: { verbs: ['pay.send'] }, win: { kind: 'task' }, key: null, holder: SEQ_HOLDER };
const SEQ_UNIT = { id: 'seq_unit', agg: 'sum', sel: { accumulates_into: 'spend.usd_cents' }, win: { kind: 'task' }, key: null, holder: SEQ_HOLDER };

const M: Record<string, any> = {
  rp: { id: 'rp', kind: 'requires_prior', p: { verb: 'kyc.check' }, q: { verb: 'pay.send' } },
  pr: { id: 'pr', kind: 'precedes', p: { verb: ['a', 'b'] }, q: { verb: 'c' }, status: 'committed' },
  nv: { id: 'nv', kind: 'never', p: { verb: 'pay.refund' } },
  al: { id: 'al', kind: 'always', p: { verb: 'pay.send' }, status: 'admitted' },
  rw: { id: 'rw', kind: 'responds_within', p: { verb: 'x' }, q: { verb: 'y' }, within: 3 },
};

// ---- scenario builder ---------------------------------------------------------------------------------------------
type Sc = {
  accs: any[];
  mons?: any[];
  verb?: string;
  params?: any;
  noParams?: boolean;
  docs?: any[];
  isSchema?: string;
  state?: any;
  monitors?: any;
  receipts?: any[] | any;
  keys?: any[] | any;
  last_seq?: any;
  claims?: any[] | null; // null: auto
  claimPatch?: (c: any[]) => any[];
  now?: number;
  extraP?: Record<string, unknown>;
  ctxPatch?: (c: any) => any;
};
const PARAMS = { payee: 'P-1', amount: 1_000, fee: 25, memo: 'hi', ref: 7 };
const BASE_STATE = { spent: { sum: 5_000 }, spend_unit: { sum: 10_000 }, per_payee: { count: 2 }, payees: { values: ['"P-1"', '"P-2"'] }, largest: { max: 3_000 }, flights: { sum: 1 } };
const BASE_MONS = { rp: 'met', pr: 'unmet', nv: 'clean', al: 'ok', rw: 'pending:2' };

const rootCache = new Map<string, { S: any; R: string }>();
function rootOf(accs: any[], mons: any[]) {
  const k = JSON.stringify([accs, mons]);
  const hit = rootCache.get(k);
  if (hit) return hit;
  const S = signSessionRoot({ v: 1, kind: 'pca-intent-session', session: SESSION, principals: [{ key: principal.pub }], intent_ref: d32('ref'), schema: { aud: AUD, digest: SD }, layers: { task: { map_digest: d32('map') } }, accumulators: accs, monitors: mons, question_uri: 'https://q.example', expires_at: NOW + 86_400_000 } as any, principal.sk);
  const v = verifySessionRoot(S);
  if (!v.ok) throw new Error(`root: ${v.reason}`);
  const r = { S, R: sessionRootDigest(S) };
  rootCache.set(k, r);
  return r;
}
const pcactnOf = (verb: string, R: string, extra: Record<string, unknown> = {}) => ({
  v: 1, aud: AUD, action: { verb, resource: 'pay.example/x', params_digest: d32('pd') }, nonce: 'n-1', counter: 1, iat: NOW - 1, exp: NOW + 600_000, grant_ref: d32('g'),
  intent: { ref: d32('ref'), map_digest: d32('map'), goal_salt: 's', fidelity_ppm: 1_000_000, residual_risk_ppm: 0 },
  intent_session: { session: SESSION, root: R, seq: 0, schema: SD } as any, sig: 'x', ...extra,
});
const draftOf = (sc: Sc) => {
  const { R } = rootOf(sc.accs, sc.mons ?? []);
  return pcactnOf(sc.verb ?? 'pay.send', R, sc.extraP);
};

/** auto claims: the verifier's own post for every selected non-wallet accumulator */
function autoClaims(sc: Sc, schemaDoc: any): any[] {
  const verb = sc.verb ?? 'pay.send';
  const params = sc.params ?? PARAMS;
  const claims: any[] = [];
  for (const a of sc.accs) {
    if (a.holder.kind === 'wallet') continue;
    let sel = false;
    try { sel = accSelects(a, verb, schemaDoc); } catch { sel = false; }
    if (!sel) continue;
    if (a.holder.kind === 'site_local') {
      let post = 0;
      try {
        const v = accValueOf(a, verb, params, schemaDoc);
        const pre = (sc.state ?? BASE_STATE)[a.id];
        if (v.ok && pre && preStateError(a, pre) === null) post = combineAcc(a, pre, v) ?? 0;
      } catch { /* fail later */ }
      claims.push({ id: a.id, post });
    } else {
      const rc = (Array.isArray(sc.receipts) ? sc.receipts : []).find((r: any) => r && r.acc === a.id);
      claims.push(rc ? { id: a.id, post: rc.post, receipt: accReceiptDigest(rc) } : { id: a.id, post: 0 });
    }
  }
  return claims;
}

const cases: any[] = [];
type Extra = { requires_suite?: string; guest_reason_contains?: string };
function add(name: string, sc: Sc, extra: Extra = {}) {
  const mons = sc.mons ?? [];
  const { S, R } = rootOf(sc.accs, mons);
  const docs = sc.docs ?? [SCHEMA];
  const p: any = pcactnOf(sc.verb ?? 'pay.send', R, sc.extraP);
  if (sc.isSchema) p.intent_session.schema = sc.isSchema;
  const schemaDoc = docs.find((d) => { try { return actionSchemaDigest(d) === p.intent_session.schema; } catch { return false; } });
  let claims = sc.claims === undefined || sc.claims === null ? autoClaims(sc, schemaDoc) : sc.claims;
  if (sc.claimPatch) claims = sc.claimPatch(clone(claims));
  p.intent_session.acc = claims;
  const acc: any = { state: sc.state ?? BASE_STATE, monitors: sc.monitors ?? BASE_MONS };
  if (sc.receipts !== undefined) acc.receipts = sc.receipts;
  if (sc.keys !== undefined) acc.sequencer_keys = sc.keys;
  if (sc.last_seq !== undefined) acc.last_seq = sc.last_seq;
  let ctx: any = { ...(sc.noParams ? {} : { params: sc.params ?? PARAMS }), schema: { docs, keys: [] }, session: { root: S, grants: [] }, acc };
  if (sc.ctxPatch) ctx = sc.ctxPatch(ctx);
  const ctxDocs = Array.isArray(ctx?.schema?.docs) ? ctx.schema.docs : [];
  const ctxSchemaDoc = ctxDocs.find((d: any) => { try { return actionSchemaDigest(d) === p.intent_session.schema; } catch { return false; } });
  const now = sc.now ?? NOW;
  const topErr = intentV2ContextError(ctx);
  // the bound-root step (rule 15 step 1) must pass: the guest's acc_step takes the bound root
  if (!(verifySessionRoot(ctx.session.root).ok && sessionRootDigest(ctx.session.root) === p.intent_session.root && now < ctx.session.root.expires_at)) throw new Error(`case ${name}: root not bound`);
  const d = decideIntentV2(p, {} as any, ctx, now);
  const c = d.checks.find((x) => x.name === 'accumulators');
  if (!c) throw new Error(`case ${name}: accumulators not reported`);
  const expect: any = { ok: c.ok, ...(c.ok ? {} : { reason: c.reason }) };
  if (c.ok) expect.env = JSON.parse(JSON.stringify({ acc: d.env?.acc ?? {}, mon: d.env?.mon ?? {} }));
  cases.push({ name, pcactn: p, ctx, now, schema_doc: ctxSchemaDoc === undefined ? null : ctxSchemaDoc, ...extra, ...(topErr ? { top_ctx_error: topErr } : {}), expect });
}

// ---- site-local scenarios ---------------------------------------------------------------------------------------------
const ALL = [D.spent, D.spend_unit, D.per_payee, D.payees, D.largest, D.flights, D.questions];
const MONS = [M.rp, M.pr, M.nv, M.al, M.rw];
const base: Sc = { accs: ALL, mons: MONS };
add('base', base);
add('base-no-monitors', { accs: ALL });
add('base-air-book', { ...base, verb: 'air.book', params: { total: 900 } });
add('base-air-search-nothing-selected', { ...base, verb: 'air.search', params: { pax: 2 } });
add('base-unknown-verb', { ...base, verb: 'nope.verb', params: {} });
add('only-wallet', { accs: [D.questions] });
add('empty-root', { accs: [] });
// claims
for (const id of ['spent', 'spend_unit', 'per_payee', 'payees', 'largest']) {
  add(`claim-plus1-${id}`, { ...base, claimPatch: (c) => c.map((x) => (x.id === id ? { ...x, post: x.post + 1 } : x)) });
  add(`claim-minus1-${id}`, { ...base, claimPatch: (c) => c.map((x) => (x.id === id ? { ...x, post: Math.max(0, x.post - 1) } : x)) });
  add(`claim-missing-${id}`, { ...base, claimPatch: (c) => c.filter((x) => x.id !== id) });
  add(`claim-receipt-on-site-local-${id}`, { ...base, claimPatch: (c) => c.map((x) => (x.id === id ? { ...x, receipt: d32('r') } : x)) });
}
add('claim-not-fed', { ...base, claimPatch: (c) => [...c, { id: 'flights', post: 1 }] });
add('claim-unknown', { ...base, claimPatch: (c) => [...c, { id: 'nope', post: 0 }] });
add('claim-wallet', { ...base, claimPatch: (c) => [...c, { id: 'questions', post: 1 }] });
add('claim-wallet-first', { ...base, claimPatch: (c) => [{ id: 'questions', post: 1 }, ...c] });
add('claims-absent', { ...base, claimPatch: () => undefined as any });
add('claims-absent-nothing-selected', { ...base, verb: 'air.search', params: { pax: 2 }, claimPatch: () => undefined as any });
// state
const st = (patch: Record<string, unknown>) => ({ ...BASE_STATE, ...patch });
add('state-missing-spent', { ...base, state: (() => { const s: any = { ...BASE_STATE }; delete s.spent; return s; })() });
add('state-missing-flights-unselected', { ...base, state: (() => { const s: any = { ...BASE_STATE }; delete s.flights; return s; })() });
add('state-empty', { ...base, state: {} });
add('state-absent', { ...base, ctxPatch: (c) => { delete c.acc.state; return c; } });
add('state-null', { ...base, ctxPatch: (c) => { c.acc.state = null; return c; } });
add('acc-ctx-absent', { ...base, ctxPatch: (c) => { delete c.acc; return c; } });
add('acc-ctx-absent-nothing-selected', { ...base, verb: 'air.search', params: { pax: 2 }, ctxPatch: (c) => { delete c.acc; return c; } });
add('state-wrong-member', { ...base, state: st({ spent: { count: 5 } }) });
add('state-extra-member', { ...base, state: st({ spent: { sum: 5, count: 1 } }) });
add('state-negative', { ...base, state: st({ spent: { sum: -1 } }) });
add('state-fraction', { ...base, state: st({ spent: { sum: 1.5 } }) });
add('state-string', { ...base, state: st({ spent: { sum: '5' } }) });
add('state-unsafe', { ...base, state: st({ spent: { sum: MAX + 1 } }) });
add('state-not-object', { ...base, state: st({ spent: 5 }) });
add('state-null-entry', { ...base, state: st({ spent: null }) });
add('state-array-entry', { ...base, state: st({ spent: [5] }) });
add('state-values-not-strings', { ...base, state: st({ payees: { values: ['"P-2"', 3] } }) });
add('state-values-dup', { ...base, state: st({ payees: { values: ['"P-2"', '"P-2"'] } }) });
add('state-values-not-array', { ...base, state: st({ payees: { values: '"P-2"' } }) });
add('state-values-empty', { ...base, state: st({ payees: { values: [] } }) });
add('state-unselected-bad', { ...base, state: st({ flights: { count: 1 } }) });
add('state-unselected-null', { ...base, state: st({ flights: null }) });
add('state-unselected-values-for-sum', { ...base, state: st({ flights: { values: [] } }) });
add('state-for-wallet-ignored', { ...base, state: st({ questions: 'garbage' }) });
add('state-extra-unknown-id-ignored', { ...base, state: st({ zzz: 'garbage' }) });
add('state-max-at-safe', { ...base, state: st({ largest: { max: MAX } }), claimPatch: (c) => c.map((x) => (x.id === 'largest' ? { ...x, post: MAX } : x)) });
add('state-max-domain', { ...base, state: st({ largest: { max: 50_000 } }) });
add('state-max-domain-plus1', { ...base, state: st({ largest: { max: 50_001 } }) });
add('state-max-below', { ...base, state: st({ largest: { max: 0 } }) });
add('state-sum-overflow', { ...base, state: st({ spent: { sum: MAX - 999 } }), claimPatch: (c) => c.map((x) => (x.id === 'spent' ? { ...x, post: MAX } : x)) });
add('state-sum-at-safe', { ...base, state: st({ spent: { sum: MAX - 1000 } }), claimPatch: (c) => c.map((x) => (x.id === 'spent' ? { ...x, post: MAX } : x)) });
add('state-count-overflow', { ...base, state: st({ per_payee: { count: MAX } }) });
add('state-count-domain', { ...base, state: st({ per_payee: { count: 4 } }) });
add('state-count-over-domain', { ...base, state: st({ per_payee: { count: 5 } }), claimPatch: (c) => c.map((x) => (x.id === 'per_payee' ? { ...x, post: 6 } : x)) });
add('state-unit-domain', { ...base, state: st({ spend_unit: { sum: 1_000_000 - 1_025 } }) });
add('state-unit-over-domain', { ...base, state: st({ spend_unit: { sum: 1_000_000 - 1_024 } }), claimPatch: (c) => c.map((x) => (x.id === 'spend_unit' ? { ...x, post: 1_000_001 } : x)) });
add('state-distinct-new', { ...base, state: st({ payees: { values: ['"P-7"'] } }) });
add('state-distinct-new-claim-old', { ...base, state: st({ payees: { values: ['"P-7"'] } }), claimPatch: (c) => c.map((x) => (x.id === 'payees' ? { ...x, post: 1 } : x)) });
add('state-distinct-raw-not-canonical', { ...base, state: st({ payees: { values: ['P-1'] } }) });
// params
add('params-absent', { ...base, noParams: true });
add('params-array', { ...base, ctxPatch: (c) => { c.params = []; return c; } });
add('params-absent-nothing-selected', { ...base, verb: 'air.search', noParams: true });
add('param-amount-missing', { ...base, params: { payee: 'P-1', fee: 25 } });
add('param-amount-string', { ...base, params: { ...PARAMS, amount: '1000' } });
add('param-amount-negative', { ...base, params: { ...PARAMS, amount: -1 } });
add('param-amount-fraction', { ...base, params: { ...PARAMS, amount: 1.5 } });
add('param-amount-zero', { ...base, params: { ...PARAMS, amount: 0 } });
add('param-amount-unsafe', { ...base, params: { ...PARAMS, amount: MAX + 1 } });
add('param-fee-absent', { ...base, params: { payee: 'P-1', amount: 1_000 } });
add('param-fee-negative', { ...base, params: { ...PARAMS, fee: -5 } });
add('param-fee-string', { ...base, params: { ...PARAMS, fee: '5' } });
add('param-tip-string-ignored', { ...base, params: { ...PARAMS, tip: 'x' } });
add('param-unit-overflow', { accs: [D.spend_unit], state: { spend_unit: { sum: 0 } }, params: { payee: 'P', amount: MAX, fee: 1 } });
add('param-unit-at-safe', { accs: [{ ...D.spend_unit, domain_max: undefined }].map((a) => { const b = { ...a }; delete b.domain_max; return b; }), state: { spend_unit: { sum: 0 } }, params: { payee: 'P', amount: MAX - 1, fee: 1 } });
add('param-payee-int', { ...base, params: { ...PARAMS, payee: 42 }, state: st({ payees: { values: ['42'] } }) });
add('param-payee-int-new', { ...base, params: { ...PARAMS, payee: 42 } });
add('param-payee-object', { ...base, params: { ...PARAMS, payee: { a: 1 } } });
add('param-payee-null', { ...base, params: { ...PARAMS, payee: null } });
add('param-payee-bool', { ...base, params: { ...PARAMS, payee: true } });
add('param-payee-fraction', { ...base, params: { ...PARAMS, payee: 4.5 } });
add('param-payee-escaped', { ...base, params: { ...PARAMS, payee: 'a"b\\c\n\u0001é😀/' }, state: st({ payees: { values: [JSON.stringify('a"b\\c\n\u0001é😀/')] } }) });
add('param-payee-missing', { ...base, params: { amount: 1_000, fee: 25 } });
// keyed accumulators
const keyed = (key: string, extra: any = {}) => ({ id: 'k', agg: 'count', sel: { verbs: ['pay.send'] }, win: { kind: 'task' }, key, holder: SITE, ...extra });
add('key-identity', { accs: [keyed('action.params.payee')], state: { k: { count: 0 } } });
add('key-int-identity', { accs: [keyed('action.params.ref')], state: { k: { count: 0 } } });
add('key-missing-param', { accs: [keyed('action.params.payee')], state: { k: { count: 0 } }, params: { amount: 1 } });
add('key-text', { accs: [keyed('action.params.memo')], state: { k: { count: 0 } } });
add('key-undeclared', { accs: [keyed('action.params.zzz')], state: { k: { count: 0 } }, params: { ...PARAMS, zzz: 'q' } });
add('key-no-schema', { accs: [keyed('action.params.payee')], state: { k: { count: 0 } }, docs: [] });
add('key-verb-not-in-schema', { accs: [{ ...keyed('action.params.payee'), sel: { verbs: ['pay.other'] } }], verb: 'pay.other', state: { k: { count: 0 } } });
add('key-semantic-absent', { accs: [keyed('action.params.payee')], state: { k: { count: 0 } }, docs: [withVerbs([{ ...payVerb(), params: { ...payVerb().params, 'action.params.payee': { type: 'string' } } }])], isSchema: actionSchemaDigest(withVerbs([{ ...payVerb(), params: { ...payVerb().params, 'action.params.payee': { type: 'string' } } }])) });
add('key-semantic-text-dot-only', { accs: [keyed('action.params.payee')], state: { k: { count: 0 } }, docs: [withVerbs([{ ...payVerb(), params: { ...payVerb().params, 'action.params.payee': { type: 'string', semantic: 'text.' } } }])], isSchema: actionSchemaDigest(withVerbs([{ ...payVerb(), params: { ...payVerb().params, 'action.params.payee': { type: 'string', semantic: 'text.' } } }])) });
add('key-semantic-textual', { accs: [keyed('action.params.payee')], state: { k: { count: 0 } }, docs: [withVerbs([{ ...payVerb(), params: { ...payVerb().params, 'action.params.payee': { type: 'string', semantic: 'textual' } } }])], isSchema: actionSchemaDigest(withVerbs([{ ...payVerb(), params: { ...payVerb().params, 'action.params.payee': { type: 'string', semantic: 'textual' } } }])) });
add('key-decl-string', { accs: [keyed('action.params.payee')], state: { k: { count: 0 } }, docs: [withVerbs([{ ...payVerb(), params: { ...payVerb().params, 'action.params.payee': 'party.ref' } }])], isSchema: actionSchemaDigest(withVerbs([{ ...payVerb(), params: { ...payVerb().params, 'action.params.payee': 'party.ref' } }])) });
add('key-unselected-ok', { accs: [{ ...keyed('action.params.memo'), sel: { verbs: ['air.book'] } }], state: {} });
// schema availability / odd schema docs
const oddDoc = (verbs: unknown) => { const d = withVerbs(verbs); return { docs: [d], isSchema: actionSchemaDigest(d) }; };
add('schema-unavailable-unit', { ...base, docs: [] });
add('schema-unavailable-no-unit', { accs: [D.spent, D.per_payee.key ? { ...D.per_payee, key: null } : D.per_payee], state: BASE_STATE, docs: [] });
add('schema-other-digest', { ...base, isSchema: d32('other-schema') });
add('schema-second-doc', { ...base, docs: [withVerbs([]), SCHEMA] });
add('schema-verbs-null-entry-first', { accs: [D.spend_unit], state: BASE_STATE, ...oddDoc([null, payVerb()]) });
add('schema-verbs-null-entry-after', { accs: [D.spend_unit], state: BASE_STATE, ...oddDoc([payVerb(), null]) });
add('schema-verbs-string-entry', { accs: [D.spend_unit], state: BASE_STATE, ...oddDoc(['x', payVerb()]) });
add('schema-verbs-not-array', { accs: [D.spend_unit], state: BASE_STATE, ...oddDoc({ 'pay.send': payVerb() }) });
add('schema-verb-params-missing', { accs: [D.spend_unit], state: BASE_STATE, ...oddDoc([{ verb: 'pay.send' }]) });
add('schema-verb-params-null-decl', { accs: [D.spend_unit], state: BASE_STATE, ...oddDoc([{ verb: 'pay.send', params: { 'action.params.amount': null } }]) });
add('schema-acc-into-string-substring', { accs: [D.spend_unit], state: BASE_STATE, ...oddDoc([{ verb: 'pay.send', params: { 'action.params.amount': { type: 'integer', semantic: 'm', accumulates_into: 'xspend.usd_centsx' } } }]) });
add('schema-acc-into-number', { accs: [D.spend_unit], state: BASE_STATE, ...oddDoc([{ verb: 'pay.send', params: { 'action.params.amount': { type: 'integer', semantic: 'm', accumulates_into: 5 } } }]) });
add('schema-acc-into-null', { accs: [D.spend_unit], state: BASE_STATE, ...oddDoc([{ verb: 'pay.send', params: { 'action.params.amount': { type: 'integer', semantic: 'm', accumulates_into: null } } }]) });
add('schema-acc-into-other-unit', { accs: [D.spend_unit], state: BASE_STATE, ...oddDoc([{ verb: 'pay.send', params: { 'action.params.amount': { type: 'integer', semantic: 'm', accumulates_into: ['fees'] } } }]) });
add('schema-acc-into-on-string-type', { accs: [D.spend_unit], state: BASE_STATE, ...oddDoc([{ verb: 'pay.send', params: { 'action.params.amount': { type: 'string', semantic: 'm', accumulates_into: ['spend.usd_cents'] } } }]) });
add('schema-params-array', { accs: [D.spend_unit], state: BASE_STATE, ...oddDoc([{ verb: 'pay.send', params: [{ type: 'integer', accumulates_into: ['spend.usd_cents'] }] }]) });
add('schema-params-string', { accs: [D.spend_unit], state: BASE_STATE, ...oddDoc([{ verb: 'pay.send', params: 'abc' }]) });
add('schema-fees-unit', { accs: [{ ...D.spend_unit, id: 'fees', sel: { accumulates_into: 'fees' } }], state: { fees: { sum: 0 } } });
add('schema-both-verbs-and-unit', { accs: [{ ...D.spend_unit, sel: { verbs: ['air.search'], accumulates_into: 'spend.usd_cents' } }], verb: 'air.search', params: { pax: 2 }, state: BASE_STATE });
// monitors
add('mon-absent-ctx', { ...base, monitors: undefined, ctxPatch: (c) => { delete c.acc.monitors; return c; } });
add('mon-null-ctx', { ...base, ctxPatch: (c) => { c.acc.monitors = null; return c; } });
for (const [id, good, badS] of [['rp', 'unmet', 'clean'], ['pr', 'met', 'ok'], ['nv', 'seen', 'unmet'], ['al', 'broken', 'seen'], ['rw', 'idle', 'pending:0']] as const) {
  add(`mon-${id}-good`, { ...base, monitors: { ...BASE_MONS, [id]: good } });
  add(`mon-${id}-bad`, { ...base, monitors: { ...BASE_MONS, [id]: badS } });
  add(`mon-${id}-missing`, { ...base, monitors: (() => { const m: any = { ...BASE_MONS }; delete m[id]; return m; })() });
  add(`mon-${id}-number`, { ...base, monitors: { ...BASE_MONS, [id]: 1 } });
}
for (const s of ['missed', 'pending:1', 'pending:3', 'pending:4', 'pending:01', 'pending:', 'pending:+1', 'Idle', 'pending:3 ']) add(`mon-rw-${s}`, { ...base, monitors: { ...BASE_MONS, rw: s } });
add('mon-rw-within-64', { accs: [], mons: [{ ...M.rw, within: 64 }], monitors: { rw: 'pending:64' } });
add('mon-rw-within-64-over', { accs: [], mons: [{ ...M.rw, within: 64 }], monitors: { rw: 'pending:65' } });
add('mon-id-toString-absent', { accs: [], mons: [{ ...M.nv, id: 'toString' }], monitors: {} });
add('mon-id-toString-present', { accs: [], mons: [{ ...M.nv, id: 'toString' }], monitors: { toString: 'clean' } });
add('mon-ctx-array', { accs: [], mons: [{ ...M.nv, id: '0' }], ctxPatch: (c) => { c.acc.monitors = ['clean']; return c; } });
add('mon-ctx-string-length', { accs: [], mons: [{ ...M.nv, id: 'length' }], ctxPatch: (c) => { c.acc.monitors = 'clean'; return c; } });
add('mon-fails-after-acc-ok', { ...base, monitors: { ...BASE_MONS, nv: 'x' } });
add('state-ctx-array', { accs: [{ ...D.spent, id: '0' }], ctxPatch: (c) => { c.acc.state = [{ sum: 1 }]; return c; } });
add('state-ctx-string-unselected-length', { accs: [{ ...D.flights, id: 'length' }], ctxPatch: (c) => { c.acc.state = 'abc'; return c; } });
add('state-ctx-number', { accs: [{ ...D.flights, id: 'x' }], ctxPatch: (c) => { c.acc.state = 5; return c; } });

// ---- sequenced scenarios ----------------------------------------------------------------------------------------------
const pqKp = mlDsa65Keygen(seed('pq-1'));
const pqRootKp = mlDsa65Keygen(seed('pq-root'));
const HYB = 'hybrid-ed25519-ml-dsa-65' as const;
const KS = signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: NOW - 100, keys: [{ kid: 's1', pk: s1.pub, not_before: NOW - 100_000, not_after: NOW - 1_000 }, { kid: 's2', pk: s2.pub, not_before: NOW - 1_000 }] } as any, seqRoot.sk);
const SEQS = [SEQ_SUM, SEQ_CNT, SEQ_MAX, SEQ_DIST, SEQ_UNIT];
const seqBase: Sc = { accs: [...SEQS, D.spent], mons: [M.nv], monitors: { nv: 'clean' } };
const draftDigest = pcactnReservationDigest(draftOf(seqBase) as any);
const rcBody = (acc: string, pre: number, delta: number, post: number, over: any = {}) => ({ v: 1, kind: 'pca-acc-receipt', session: SESSION, acc, seq: 3, pre, delta, post, pcactn_digest: draftDigest, aud: AUD, issued_at: NOW, expires_at: NOW + 60_000, kid: 's2', ledger: { index: 7, head: d32('head') }, ...over });
const rcSum = (over: any = {}, sk = s2.sk, suite?: any): any => {
  try {
    return signAccReceipt(rcBody('seq_spent', 10_000, 1_000, 11_000, over) as any, sk, suite);
  } catch {
    // a body the signer refuses (lifetime rule): sign a valid one, then patch the fields (the shape check refuses it first)
    const ok = signAccReceipt(rcBody('seq_spent', 10_000, 1_000, 11_000, { ...over, expires_at: over.issued_at ?? NOW }) as any, sk, suite);
    return { ...ok, ...over };
  }
};
const goodRcs = () => [rcSum(), signAccReceipt(rcBody('seq_count', 4, 1, 5) as any, s2.sk), signAccReceipt(rcBody('seq_max', 700, 1_000, 1_000) as any, s2.sk), signAccReceipt(rcBody('seq_dist', 3, 0, 3) as any, s2.sk), signAccReceipt(rcBody('seq_unit', 0, 1_025, 1_025) as any, s2.sk)];
const seqSc = (over: Partial<Sc>): Sc => ({ ...seqBase, receipts: goodRcs(), keys: [KS], ...over });
const withRc = (rc: any) => { const r = goodRcs(); r[0] = rc; return r; };
add('seq-base', seqSc({}));
add('seq-sum-only', { accs: [SEQ_SUM], receipts: [rcSum()], keys: [KS], extraP: {} });
add('seq-rotated-key-in-window', seqSc({ receipts: withRc(rcSum({ kid: 's1', issued_at: NOW - 5_000 }, s1.sk)) }));
add('seq-rotated-key-at-not-after', seqSc({ receipts: withRc(rcSum({ kid: 's1', issued_at: NOW - 1_000 }, s1.sk)) }));
add('seq-retired-key', seqSc({ receipts: withRc(rcSum({ kid: 's1', issued_at: NOW - 999 }, s1.sk)) }));
add('seq-key-before-not-before', seqSc({ receipts: withRc(rcSum({ issued_at: NOW - 1_001 })) }));
add('seq-key-at-not-before', seqSc({ receipts: withRc(rcSum({ issued_at: NOW - 1_000 })) }));
add('seq-wrong-kid', seqSc({ receipts: withRc(rcSum({ kid: 's9' })) }));
add('seq-kid-of-other-key', seqSc({ receipts: withRc(rcSum({ kid: 's1' })) }));
add('seq-no-keyset', seqSc({ keys: [] }));
add('seq-keys-absent', seqSc({ keys: undefined }));
add('seq-keys-null', seqSc({ ctxPatch: (c) => { c.acc.sequencer_keys = null; return c; } }));
add('seq-keys-object', seqSc({ keys: KS }));
add('seq-keys-string', seqSc({ keys: 'abc' }));
add('seq-keyset-foreign-root', seqSc({ keys: [signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: NOW, keys: [{ kid: 's2', pk: s2.pub, not_before: 0 }] } as any, stranger.sk)] }));
add('seq-keyset-other-root-claims-pinned', seqSc({ keys: [{ ...signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: NOW, keys: [{ kid: 's2', pk: s2.pub, not_before: 0 }] } as any, stranger.sk), sequencer: seqRoot.pub }] }));
add('seq-keyset-bad-sig', seqSc({ keys: [{ ...clone(KS), issued_at: NOW - 99 }] }));
add('seq-keyset-tampered-entry', seqSc({ keys: [{ ...clone(KS), keys: [KS.keys[0], { ...KS.keys[1], not_before: 0 }] }] }));
add('seq-keyset-foreign-then-good', seqSc({ keys: [signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: NOW, keys: [{ kid: 's2', pk: s2.pub, not_before: 0 }] } as any, stranger.sk), KS] }));
add('seq-keyset-garbage-then-good', seqSc({ keys: [null, 5, 'x', { v: 1 }, KS] }));
add('seq-keyset-explicit-ed25519', seqSc({ keys: [{ ...clone(KS), alg: 'ed25519' }] }));
add('seq-keyset-unknown-alg', seqSc({ keys: [{ ...clone(KS), alg: 'rsa' }] }));
add('seq-keyset-ed-with-pq-pk', seqSc({ keys: [{ ...clone(KS), pq_pk: 'AAAA' }] }));
add('seq-keyset-extra-member', seqSc({ keys: [{ ...clone(KS), note: 1 }] }));
add('seq-keyset-v2', seqSc({ keys: [{ ...clone(KS), v: 2 }] }));
const ks2 = (keys: any[]) => signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: NOW, keys } as any, seqRoot.sk);
add('seq-keyset-entry-pq-alg', seqSc({ keys: [ks2([{ kid: 's2', pk: s2.pub, alg: HYB, pq_pk: 'AAAA', not_before: 0 }])] }));
add('seq-keyset-entry-ed-alg-explicit', seqSc({ keys: [ks2([{ kid: 's2', pk: s2.pub, alg: 'ed25519', not_before: 0 }])] }));
add('seq-keyset-entry-pq-then-ed-other-set', seqSc({ keys: [ks2([{ kid: 's2', pk: s2.pub, alg: HYB, pq_pk: 'AAAA', not_before: 0 }]), KS] }));
add('seq-keyset-dup-kid', seqSc({ keys: [{ ...clone(KS), keys: [KS.keys[1], KS.keys[1]] }] }));
add('seq-keyset-entry-not-after-lt-before', seqSc({ keys: [{ ...clone(KS), keys: [{ kid: 's2', pk: s2.pub, not_before: 10, not_after: 9 }] }] }));
add('seq-keyset-entry-extra', seqSc({ keys: [{ ...clone(KS), keys: [{ ...KS.keys[1], x: 1 }] }] }));
add('seq-keyset-empty-keys', seqSc({ keys: [{ ...clone(KS), keys: [] }] }));
add('seq-keyset-entry-pk-31', seqSc({ keys: [{ ...clone(KS), keys: [{ ...KS.keys[1], pk: b64u(seed('x').slice(0, 31)) }] }] }));
add('seq-future', seqSc({ receipts: withRc(rcSum({ issued_at: NOW + 60_001, expires_at: NOW + 120_001 })) }));
add('seq-future-at-skew', seqSc({ receipts: withRc(rcSum({ issued_at: NOW + 60_000, expires_at: NOW + 120_000 })) }));
add('seq-receipt-missing', seqSc({ receipts: goodRcs().slice(1), claimPatch: (c) => c.map((x) => (x.id === 'seq_spent' ? { ...x, post: 11_000, receipt: accReceiptDigest(rcSum()) } : x)) }));
add('seq-receipts-absent', seqSc({ receipts: undefined, claimPatch: () => goodRcs().map((r) => ({ id: r.acc, post: r.post, receipt: accReceiptDigest(r) })).concat([{ id: 'spent', post: 6_000 } as any]) }));
add('seq-receipts-object', seqSc({ ctxPatch: (c) => { c.acc.receipts = { a: c.acc.receipts[0] }; return c; }, claimPatch: () => goodRcs().map((r) => ({ id: r.acc, post: r.post, receipt: accReceiptDigest(r) })).concat([{ id: 'spent', post: 6_000 } as any]) }));
add('seq-receipts-garbage-first', seqSc({ receipts: [{ v: 1.5 }, null, 'x', ...goodRcs()] }));
add('seq-claim-no-receipt', seqSc({ claimPatch: (c) => c.map((x) => (x.id === 'seq_spent' ? { id: x.id, post: x.post } : x)) }));
for (const last of [2, 3, 4, '2', '3', ' 2 ', '0x2', '', null, true, [2], [3], { a: 1 }, 'abc', 2.5]) {
  add(`seq-last-seq-${JSON.stringify(last)}`, seqSc({ last_seq: { seq_spent: last } }));
}
add('seq-last-seq-other-id', seqSc({ last_seq: { other: 99 } }));
add('seq-last-seq-null-container', seqSc({ last_seq: null }));
const ctorAcc = { ...SEQ_SUM, id: 'toString' };
const ctorRc = signAccReceipt(rcBody('toString', 10_000, 1_000, 11_000, { pcactn_digest: pcactnReservationDigest(draftOf({ accs: [ctorAcc] }) as any) }) as any, s2.sk);
add('seq-id-constructor-no-last-seq', { accs: [ctorAcc], receipts: [ctorRc], keys: [KS] });
add('seq-id-constructor-last-seq-empty', { accs: [ctorAcc], receipts: [ctorRc], keys: [KS], last_seq: {} });
add('seq-id-constructor-last-seq-own', { accs: [ctorAcc], receipts: [ctorRc], keys: [KS], last_seq: { toString: 1 } });
add('seq-id-tostring-last-seq-own-3', { accs: [ctorAcc], receipts: [ctorRc], keys: [KS], last_seq: { toString: 3 } });
add('seq-foreign-signer', seqSc({ receipts: withRc(rcSum({}, stranger.sk)) }));
add('seq-arith-sum-post', seqSc({ receipts: withRc(rcSum({ post: 11_001 })) }));
add('seq-arith-sum-delta', seqSc({ receipts: withRc(rcSum({ delta: 999, post: 10_999 })) }));
const r = (acc: string, pre: number, delta: number, post: number) => signAccReceipt(rcBody(acc, pre, delta, post) as any, s2.sk);
const at = (i: number, rc: any) => { const x = goodRcs(); x[i] = rc; return x; };
add('seq-arith-count-delta2', seqSc({ receipts: at(1, r('seq_count', 4, 2, 6)) }));
add('seq-arith-count-post', seqSc({ receipts: at(1, r('seq_count', 4, 1, 6)) }));
add('seq-arith-count-zero-pre', seqSc({ receipts: at(1, r('seq_count', 0, 1, 1)) }));
add('seq-arith-max-pre-higher', seqSc({ receipts: at(2, r('seq_max', 5_000, 1_000, 5_000)) }));
add('seq-arith-max-wrong', seqSc({ receipts: at(2, r('seq_max', 5_000, 1_000, 1_000)) }));
add('seq-arith-max-delta', seqSc({ receipts: at(2, r('seq_max', 0, 999, 999)) }));
add('seq-arith-dist-new', seqSc({ receipts: at(3, r('seq_dist', 3, 1, 4)) }));
add('seq-arith-dist-delta2', seqSc({ receipts: at(3, r('seq_dist', 3, 2, 5)) }));
add('seq-arith-dist-post', seqSc({ receipts: at(3, r('seq_dist', 3, 1, 3)) }));
add('seq-arith-unit-delta', seqSc({ receipts: at(4, r('seq_unit', 0, 1_000, 1_000)) }));
add('seq-domain-max', seqSc({ receipts: withRc(rcSum({ pre: 99_000, post: 100_000 })) }));
add('seq-domain-max-plus1', seqSc({ receipts: withRc(rcSum({ pre: 99_001, post: 100_001 })) }));
add('seq-claim-post-differs', seqSc({ claimPatch: (c) => c.map((x) => (x.id === 'seq_spent' ? { ...x, post: x.post + 1 } : x)) }));
add('seq-other-aud', seqSc({ receipts: withRc(rcSum({ aud: 'other.example' })) }));
add('seq-other-session', seqSc({ receipts: withRc(rcSum({ session: d32('other-session') })) }));
{
  const oa = rcSum({ acc: 'seq_count' });
  add('seq-other-acc', seqSc({ receipts: withRc(oa), claimPatch: (c) => c.map((x) => (x.id === 'seq_spent' ? { ...x, receipt: accReceiptDigest(oa) } : x)) }));
}
add('seq-expired', seqSc({ receipts: withRc(rcSum({ issued_at: NOW - 1_001, expires_at: NOW - 1 })) }));
add('seq-expires-now', seqSc({ receipts: withRc(rcSum({ issued_at: NOW - 1_000, expires_at: NOW })) }));
// receipt lifetime and freshness, key-set version and age, retired keys (TS 5e718f47)
add('fresh-lifetime-max', seqSc({ receipts: withRc(rcSum({ issued_at: NOW - 1_000, expires_at: NOW - 1_000 + 900_000 })) }));
add('fresh-lifetime-over', seqSc({ receipts: withRc(rcSum({ issued_at: NOW - 1_000, expires_at: NOW - 1_000 + 900_001 })) }));
add('fresh-expires-before-issue', seqSc({ receipts: withRc(rcSum({ issued_at: NOW, expires_at: NOW - 1 })) }));
add('fresh-receipt-age-default-edge', { accs: [SEQ_SUM], receipts: [rcSum({ kid: 's1', issued_at: NOW - 59_000, expires_at: NOW + 1 }, s1.sk)], keys: [KS] });
add('fresh-policy-receipt-age-ok', seqSc({ receipts: withRc(rcSum({ kid: 's1', issued_at: NOW - 5_000 }, s1.sk)), ctxPatch: (c) => { c.policy = { acc: { max_receipt_age_s: 5 } }; return c; } }));
add('fresh-policy-receipt-age-over', seqSc({ receipts: withRc(rcSum({ kid: 's1', issued_at: NOW - 5_001 }, s1.sk)), ctxPatch: (c) => { c.policy = { acc: { max_receipt_age_s: 5 } }; return c; } }));
add('fresh-policy-receipt-age-zero', seqSc({ ctxPatch: (c) => { c.policy = { acc: { max_receipt_age_s: 0 } }; return c; } }));
add('fresh-policy-receipt-age-unsafe-product', seqSc({ receipts: withRc(rcSum({ kid: 's1', issued_at: NOW - 5_000 }, s1.sk)), ctxPatch: (c) => { c.policy = { acc: { max_receipt_age_s: 9_007_199_254_740 } }; return c; } }));
add('fresh-policy-receipt-age-string', seqSc({ ctxPatch: (c) => { c.policy = { acc: { max_receipt_age_s: '5' } }; return c; } }));
add('fresh-policy-acc-unknown-member', seqSc({ ctxPatch: (c) => { c.policy = { acc: { other: 1 } }; return c; } }));
add('fresh-policy-keyset-age-zero', seqSc({ ctxPatch: (c) => { c.policy = { acc: { max_keyset_age_s: 0 } }; return c; } }));
add('fresh-policy-keyset-age-ok', seqSc({ ctxPatch: (c) => { c.policy = { acc: { max_keyset_age_s: 1 } }; return c; } }));
add('fresh-policy-empty-acc', seqSc({ ctxPatch: (c) => { c.policy = { acc: {} }; return c; } }));
const ksAt = (issued: number, version = 1, sk = seqRoot.sk) => signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version, issued_at: issued, keys: [{ kid: 's2', pk: s2.pub, not_before: NOW - 1_000 }] } as any, sk);
add('fresh-keyset-age-at-default', seqSc({ keys: [ksAt(NOW - 3_600_000)] }));
add('fresh-keyset-age-over-default', seqSc({ keys: [ksAt(NOW - 3_600_001)] }));
add('fresh-keyset-future-at-skew', seqSc({ keys: [ksAt(NOW + 60_000)] }));
add('fresh-keyset-future', seqSc({ keys: [ksAt(NOW + 60_001)] }));
add('fresh-keyset-stale-then-fresh', seqSc({ keys: [ksAt(NOW - 3_600_001), ksAt(NOW - 10)] }));
// tracked acc.keyset_versions[root] = {version, digest} (5501b545): no rollback, no equivocation at the tracked version
const tk = (ks: any) => ({ version: ks.version, digest: sequencerKeySetDigest(ks) });
{
  const k3 = ksAt(NOW, 3);
  const k3b = ksAt(NOW - 1, 3); // the same version, another set: an equivocation against k3
  add('fresh-version-tracked-equal', seqSc({ keys: [k3], ctxPatch: (c) => { c.acc.keyset_versions = { [seqRoot.pub]: tk(k3) }; return c; } }));
  add('fresh-version-tracked-older', seqSc({ keys: [ksAt(NOW, 2)], ctxPatch: (c) => { c.acc.keyset_versions = { [seqRoot.pub]: tk(k3) }; return c; } }));
  add('fresh-version-tracked-older-then-newer', seqSc({ keys: [ksAt(NOW, 2), ksAt(NOW, 4)], ctxPatch: (c) => { c.acc.keyset_versions = { [seqRoot.pub]: tk(k3) }; return c; } }));
  add('fresh-version-tracked-newer', seqSc({ keys: [ksAt(NOW, 4)], ctxPatch: (c) => { c.acc.keyset_versions = { [seqRoot.pub]: tk(k3) }; return c; } }));
  add('fresh-version-equivocation', seqSc({ keys: [k3b], ctxPatch: (c) => { c.acc.keyset_versions = { [seqRoot.pub]: tk(k3) }; return c; } }));
  add('fresh-version-equivocation-then-tracked', seqSc({ keys: [k3b, k3], ctxPatch: (c) => { c.acc.keyset_versions = { [seqRoot.pub]: tk(k3) }; return c; } }));
  add('fresh-version-other-root', seqSc({ keys: [ksAt(NOW, 1)], ctxPatch: (c) => { c.acc.keyset_versions = { [seqRoot2.pub]: { version: 9, digest: tk(k3).digest } }; return c; } }));
  const bad = (name: string, v: unknown) => add(`fresh-tracked-${name}`, seqSc({ ctxPatch: (c) => { c.acc.keyset_versions = { [seqRoot.pub]: v }; return c; } }));
  bad('bare-number', 3);
  bad('null', null);
  bad('version-zero', { version: 0, digest: tk(k3).digest });
  bad('version-string', { version: '3', digest: tk(k3).digest });
  bad('digest-short', { version: 3, digest: 'AAAA' });
  bad('digest-missing', { version: 3 });
  bad('unknown-member', { ...tk(k3), note: 1 });
  add('fresh-versions-null', seqSc({ ctxPatch: (c) => { c.acc.keyset_versions = null; return c; } }));
  add('fresh-versions-array', seqSc({ ctxPatch: (c) => { c.acc.keyset_versions = []; return c; } }));
}
add('fresh-keyset-version-0', seqSc({ keys: [{ ...clone(KS), version: 0 }] }));
add('fresh-keyset-version-missing', seqSc({ keys: [(() => { const k: any = clone(KS); delete k.version; return k; })()] }));
add('fresh-keyset-version-tampered', seqSc({ keys: [{ ...clone(KS), version: 2 }] }));
const ksRet = (na: number) => signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: NOW - 100, keys: [{ kid: 's1', pk: s1.pub, not_before: NOW - 3_000_000, not_after: na }] } as any, seqRoot.sk);
const oldRc = (issued: number) => withRc(rcSum({ kid: 's1', issued_at: issued, expires_at: issued + 900_000 }, s1.sk));
add('retired-within-skew', seqSc({ receipts: oldRc(NOW - 200_000), keys: [ksRet(NOW - 60_000), KS] }));
add('retired-past-skew', seqSc({ receipts: oldRc(NOW - 200_000), keys: [ksRet(NOW - 60_001), KS] }));
add('retired-not-after-in-future', seqSc({ receipts: oldRc(NOW - 200_000), keys: [ksRet(NOW + 10), KS] }));
add('seq-other-action', seqSc({ receipts: withRc(rcSum({ pcactn_digest: d32('other-action') })) }));
add('seq-pcactn-extra-member', seqSc({ extraP: { extra: 1 } }));
add('seq-pcactn-sig-fields-ignored', seqSc({ extraP: { sig: 'other', pq_sig: 'y', threshold: { t: 1 } } }));
add('seq-pcactn-alg-not-ignored', seqSc({ extraP: { alg: 'ed25519' } }));
add('seq-receipt-explicit-ed25519', seqSc({ receipts: withRc({ ...rcSum(), alg: 'ed25519' }) }));
add('seq-receipt-unknown-alg', seqSc({ receipts: withRc({ ...rcSum(), alg: 'rsa' }) }));
add('seq-receipt-ed-with-pq-pk', seqSc({ receipts: withRc({ ...rcSum(), pq_pk: 'AAAA' }) }));
add('seq-receipt-extra-member', seqSc({ receipts: withRc({ ...rcSum(), extra: 1 }) }));
add('seq-receipt-seq-0', seqSc({ receipts: withRc({ ...rcSum(), seq: 0 }) }));
add('seq-receipt-sig-number', seqSc({ receipts: withRc({ ...rcSum(), sig: 5 }) }));
add('seq-receipt-ledger-extra', seqSc({ receipts: withRc({ ...rcSum(), ledger: { index: 7, head: d32('head'), x: 1 } }) }));
add('seq-receipt-tampered-ledger', seqSc({ receipts: withRc({ ...rcSum(), ledger: { index: 8, head: d32('head') } }) }));
add('seq-receipt-kid-bad-chars', seqSc({ receipts: withRc({ ...rcSum(), kid: 's 2' }) }));
add('seq-unselected-no-claim', { accs: [SEQ_SUM, D.flights], verb: 'air.book', params: { total: 5 }, state: { flights: { sum: 0 } }, receipts: [], keys: [KS] });
add('seq-unselected-claim', { accs: [SEQ_SUM, D.flights], verb: 'air.book', params: { total: 5 }, state: { flights: { sum: 0 } }, receipts: [rcSum()], keys: [KS], claimPatch: (c) => [...c, { id: 'seq_spent', post: 11_000, receipt: accReceiptDigest(rcSum()) }] });
add('seq-state-ignored', seqSc({ state: { ...BASE_STATE, seq_spent: 'garbage' } }));
// PQ: the TS reference accepts (pinned PQ keys); the guest fails closed
{
  const pqRc = rcSum({}, s2.sk, { alg: HYB, mlDsa: pqKp });
  const ksPqEntry = ks2([{ kid: 's2', pk: s2.pub, alg: HYB, pq_pk: pqRc.pq_pk, not_before: 0 }]);
  add('pq-receipt-hybrid', { accs: [SEQ_SUM], receipts: [pqRc], keys: [ksPqEntry] });
  add('pq-receipt-hybrid-entry-pin-other', { accs: [SEQ_SUM], receipts: [pqRc], keys: [ks2([{ kid: 's2', pk: s2.pub, alg: HYB, pq_pk: encodeMlDsaPublicKey(mlDsa65Keygen(seed('pq-other')).publicKey), not_before: 0 }])] });
  add('pq-receipt-hybrid-entry-ed', { accs: [SEQ_SUM], receipts: [pqRc], keys: [KS] });
  add('pq-receipt-hybrid-plus-ed-set', { accs: [SEQ_SUM], receipts: [pqRc], keys: [KS, ksPqEntry] });
  const pqHolder = { ...SEQ_HOLDER, root_alg: HYB };
  const ksPq = signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: NOW, keys: [{ kid: 's2', pk: s2.pub, not_before: 0 }] } as any, seqRoot.sk, { alg: HYB, mlDsa: pqRootKp });
  const pinned = { ...SEQ_SUM, holder: { ...pqHolder, root_pq_pk: ksPq.pq_pk } };
  const dig = pcactnReservationDigest(draftOf({ accs: [pinned] }) as any);
  const rcP = signAccReceipt(rcBody('seq_spent', 10_000, 1_000, 11_000, { pcactn_digest: dig }) as any, s2.sk);
  add('pq-keyset-hybrid-pinned', { accs: [pinned], receipts: [rcP], keys: [ksPq] });
  const unpinned = { ...SEQ_SUM, holder: pqHolder };
  const dig2 = pcactnReservationDigest(draftOf({ accs: [unpinned] }) as any);
  const rcU = signAccReceipt(rcBody('seq_spent', 10_000, 1_000, 11_000, { pcactn_digest: dig2 }) as any, s2.sk);
  add('pq-keyset-hybrid-unpinned', { accs: [unpinned], receipts: [rcU], keys: [ksPq] });
  add('pq-keyset-hybrid-unpinned-plus-ed', { accs: [unpinned], receipts: [rcU], keys: [ksPq, KS] });
}
// more suites: pure ML-DSA-65 / ML-DSA-87 receipts and key sets (compared exactly), suites the guest lacks
{
  const k65 = mlDsa65Keygen(seed('ml65')), k87 = mlDsa87Keygen(seed('ml87'));
  const r65 = rcSum({}, s2.sk, { alg: 'ml-dsa-65', mlDsa: k65 });
  add('pq-receipt-ml-dsa-65', { accs: [SEQ_SUM], receipts: [r65], keys: [ks2([{ kid: 's2', pk: s2.pub, alg: 'ml-dsa-65', pq_pk: r65.pq_pk, not_before: 0 }])] });
  add('pq-receipt-ml-dsa-65-entry-hybrid', { accs: [SEQ_SUM], receipts: [r65], keys: [ks2([{ kid: 's2', pk: s2.pub, alg: HYB, pq_pk: r65.pq_pk, not_before: 0 }])] });
  add('pq-receipt-ml-dsa-65-entry-unpinned', { accs: [SEQ_SUM], receipts: [r65], keys: [ks2([{ kid: 's2', pk: s2.pub, alg: 'ml-dsa-65', not_before: 0 }])] });
  add('pq-receipt-ml-dsa-65-tampered', { accs: [SEQ_SUM], receipts: [{ ...r65, ledger: { index: 9, head: d32('head') } }], keys: [ks2([{ kid: 's2', pk: s2.pub, alg: 'ml-dsa-65', pq_pk: r65.pq_pk, not_before: 0 }])] });
  const r87 = rcSum({}, s2.sk, { alg: 'ml-dsa-87', mlDsa87: k87 });
  add('pq-receipt-ml-dsa-87', { accs: [SEQ_SUM], receipts: [r87], keys: [ks2([{ kid: 's2', pk: s2.pub, alg: 'ml-dsa-87', pq_pk: r87.pq_pk, not_before: 0 }])] });
  const ks65 = signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: NOW, keys: [{ kid: 's2', pk: s2.pub, not_before: 0 }] } as any, seqRoot.sk, { alg: 'ml-dsa-65', mlDsa: k65 });
  const pin65 = { ...SEQ_SUM, holder: { ...SEQ_HOLDER, root_alg: 'ml-dsa-65', root_pq_pk: ks65.pq_pk } };
  const rp = signAccReceipt(rcBody('seq_spent', 10_000, 1_000, 11_000, { pcactn_digest: pcactnReservationDigest(draftOf({ accs: [pin65] }) as any) }) as any, s2.sk);
  add('pq-keyset-ml-dsa-65-pinned', { accs: [pin65], receipts: [rp], keys: [ks65] });
  add('pq-keyset-ml-dsa-65-pin-mismatch', { accs: [{ ...pin65, holder: { ...pin65.holder, root_pq_pk: encodeMlDsa87PublicKey(k87.publicKey) } }], receipts: [rp], keys: [ks65] });
  // suites the guest does not implement: the reference may accept (declaration only) or refuse; the guest says unsupported_suite
  for (const alg of ['less-cat1', 'hybrid-ed25519-less-cat1']) {
    add(`suite-root-alg-${alg}`, { accs: [{ ...SEQ_SUM, holder: { ...SEQ_HOLDER, root_alg: alg } }], receipts: [rcSum()], keys: [KS] }, { requires_suite: alg });
    add(`suite-receipt-${alg}`, { accs: [SEQ_SUM], receipts: [{ ...rcSum(), alg, pq_pk: 'AAAA' }], keys: [KS] }, { requires_suite: alg });
    add(`suite-keyset-${alg}`, { accs: [SEQ_SUM], receipts: [rcSum()], keys: [{ ...clone(KS), alg, pq_pk: 'AAAA' }] }, { requires_suite: alg });
    add(`suite-key-entry-${alg}`, { accs: [SEQ_SUM], receipts: [{ ...rcSum(), alg, pq_pk: 'AAAA' }], keys: [ks2([{ kid: 's2', pk: s2.pub, alg, pq_pk: 'AAAA', not_before: 0 }])] }, { requires_suite: alg });
  }
  // FN-DSA is implemented in the guest: compared exactly (fake signatures and declarations always; real ones when the wasm
  // backend is available to the generator)
  for (const alg of ['fn-dsa-512', 'fn-dsa-1024']) {
    add(`fn-root-alg-${alg}`, { accs: [{ ...SEQ_SUM, holder: { ...SEQ_HOLDER, root_alg: alg } }], receipts: [rcSum()], keys: [KS] });
    add(`fn-receipt-fake-${alg}`, { accs: [SEQ_SUM], receipts: [{ ...rcSum(), alg, pq_pk: 'AAAA' }], keys: [ks2([{ kid: 's2', pk: s2.pub, alg, pq_pk: 'AAAA', not_before: 0 }])] });
    try {
      const kp = alg === 'fn-dsa-512' ? fnDsa512Keygen(seed(alg)) : fnDsa1024Keygen(seed(alg));
      const km = { ...kp, signSeed: seed(`${alg}-sign`) };
      const mat = alg === 'fn-dsa-512' ? { fnDsa512: km } : { fnDsa1024: km };
      const rf = rcSum({}, s2.sk, { alg, ...mat } as any);
      add(`fn-receipt-${alg}`, { accs: [SEQ_SUM], receipts: [rf], keys: [ks2([{ kid: 's2', pk: s2.pub, alg, pq_pk: rf.pq_pk, not_before: 0 }])] });
      add(`fn-receipt-${alg}-unpinned`, { accs: [SEQ_SUM], receipts: [rf], keys: [ks2([{ kid: 's2', pk: s2.pub, alg, not_before: 0 }])] });
      const ksf = signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: NOW, keys: [{ kid: 's2', pk: s2.pub, not_before: 0 }] } as any, seqRoot.sk, { alg, ...mat } as any);
      const hf = { ...SEQ_SUM, holder: { ...SEQ_HOLDER, root_alg: alg, root_pq_pk: ksf.pq_pk } };
      const rr = signAccReceipt(rcBody('seq_spent', 10_000, 1_000, 11_000, { pcactn_digest: pcactnReservationDigest(draftOf({ accs: [hf] }) as any) }) as any, s2.sk);
      add(`fn-keyset-${alg}-pinned`, { accs: [hf], receipts: [rr], keys: [ksf] });
    } catch (e) {
      console.log(`(${alg} signing unavailable: ${(e as Error).message})`);
    }
  }
  try {
    const kp = slhDsa128fKeygen(seed('slh').length === 32 ? new Uint8Array(48).map((_, i) => i) : seed('slh'));
    const rs = rcSum({}, s2.sk, { alg: 'hybrid-ed25519-slh-dsa-sha2-128f', slhDsa: kp } as any);
    add('pq-receipt-hybrid-slh-128f', { accs: [SEQ_SUM], receipts: [rs], keys: [ks2([{ kid: 's2', pk: s2.pub, alg: 'hybrid-ed25519-slh-dsa-sha2-128f', pq_pk: rs.pq_pk, not_before: 0 }])] });
  } catch (e) {
    console.log(`(slh signing unavailable: ${(e as Error).message})`);
  }
  add('suite-receipt-unknown', { accs: [SEQ_SUM], receipts: [{ ...rcSum(), alg: 'no-such-suite' }], keys: [KS] }, { guest_reason_contains: 'unsupported_suite' });
  add('suite-keyset-unknown', { accs: [SEQ_SUM], receipts: [rcSum()], keys: [{ ...clone(KS), alg: 'no-such-suite' }] });
  add('suite-receipt-alg-number', { accs: [SEQ_SUM], receipts: [{ ...rcSum(), alg: 5 }], keys: [KS] });
}
// strict context typing (TS 5e0a33a9)
add('strict-acc-null', { ...base, ctxPatch: (c) => { c.acc = null; return c; } });
add('strict-acc-array', { ...base, ctxPatch: (c) => { c.acc = []; return c; } });
add('strict-state-array', { ...base, ctxPatch: (c) => { c.acc.state = []; return c; } });
add('strict-state-string', { ...base, ctxPatch: (c) => { c.acc.state = 'x'; return c; } });
add('strict-monitors-array', { ...base, ctxPatch: (c) => { c.acc.monitors = []; return c; } });
add('strict-last-seq-null', { ...base, ctxPatch: (c) => { c.acc.last_seq = null; return c; } });
add('strict-last-seq-array', { ...base, ctxPatch: (c) => { c.acc.last_seq = []; return c; } });
add('strict-last-seq-unused-string', { ...base, last_seq: { other: '1' } });
add('strict-last-seq-unused-negative', { ...base, last_seq: { other: -1 } });
add('strict-last-seq-unused-fraction', { ...base, last_seq: { other: 0.5 } });
add('strict-last-seq-unused-ok', { ...base, last_seq: { other: 0 } });
add('strict-receipts-null', { ...base, ctxPatch: (c) => { c.acc.receipts = null; return c; } });
add('strict-receipts-object', { ...base, ctxPatch: (c) => { c.acc.receipts = {}; return c; } });
add('strict-receipts-empty', { ...base, receipts: [] });
add('strict-keys-null', { ...base, ctxPatch: (c) => { c.acc.sequencer_keys = null; return c; } });
add('strict-keys-string', { ...base, ctxPatch: (c) => { c.acc.sequencer_keys = 'k'; return c; } });
add('strict-schema-ctx-null', { ...base, ctxPatch: (c) => { c.schema = null; return c; } });
add('strict-schema-ctx-absent', { accs: [D.spent], ctxPatch: (c) => { delete c.schema; return c; } });
add('strict-schema-docs-string', { accs: [D.spent], ctxPatch: (c) => { c.schema = { docs: 'x', keys: [] }; return c; } });
add('strict-schema-keys-object', { accs: [D.spent], ctxPatch: (c) => { c.schema = { docs: [SCHEMA], keys: {} }; return c; } });
add('strict-schema-keys-absent', { accs: [D.spent], ctxPatch: (c) => { c.schema = { docs: [SCHEMA] }; return c; } });
add('strict-clock-fraction', { ...base, now: NOW + 0.5 });
add('strict-state-own-proto', { accs: [D.spent], ctxPatch: (c) => { c.acc.state = JSON.parse('{"__proto__": {"sum": 0}}'); return c; } });
add('strict-inherited-state-name', { accs: [{ ...D.spent, id: 'toString' }], state: {}, claims: [{ id: 'toString', post: 1000 }] });
add('strict-own-state-name', { accs: [{ ...D.spent, id: 'toString' }], state: { toString: { sum: 0 } }, claims: [{ id: 'toString', post: 1000 }] });
add('strict-inherited-monitor-name', { accs: [], mons: [{ ...M.nv, id: 'hasOwnProperty' }], monitors: {} });
add('strict-params-null-top', { ...base, ctxPatch: (c) => { c.params = null; return c; } });
add('strict-params-own-proto', { accs: [{ ...D.spent, val: 'action.params.amount' }], params: JSON.parse('{"__proto__": 5, "amount": 7}'), state: { spent: { sum: 0 } } });

// a second sequencer root: the holder's root decides
{
  const other = { ...SEQ_SUM, holder: { ...SEQ_HOLDER, root: seqRoot2.pub } };
  const dig = pcactnReservationDigest(draftOf({ accs: [other] }) as any);
  const rc = signAccReceipt(rcBody('seq_spent', 0, 1_000, 1_000, { pcactn_digest: dig }) as any, s2.sk);
  const KS2 = signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: NOW, keys: [{ kid: 's2', pk: s2.pub, not_before: 0 }] } as any, seqRoot2.sk);
  add('root2-ok', { accs: [other], receipts: [rc], keys: [KS2] });
  add('root2-keyset-of-root1', { accs: [other], receipts: [rc], keys: [KS] });
}

// ---- the acc-* conformance scenarios (gen-conformance-intent-v2.mjs), rule 15 only -----------------------------------
{
  const SCH = { v: 1, kind: 'pca-action-schema', site: 'https://skyair.example', aud: AUD, version: '2026-10-01', verbs: [{ verb: 'air.book', kind: 'write', params: { 'action.params.offer_id': { type: 'string', semantic: 'product.ref' }, 'action.params.total': { type: 'integer', semantic: 'money.amount', accumulates_into: ['spend.usd_cents'] } } }] };
  const TRIP = { id: 'trip_spend', agg: 'sum', unit: 'usd_cents', sel: { accumulates_into: 'spend.usd_cents' }, win: { kind: 'task' }, key: null, domain_max: 500_000, holder: { kind: 'site_local' } };
  const QUESTIONS = D.questions;
  const P = { offer_id: 'OF-1', total: 38_900 };
  const c = (name: string, o: Partial<Sc>) => add('conf-' + name, { accs: [TRIP, QUESTIONS], verb: 'air.book', params: P, docs: [SCH], isSchema: actionSchemaDigest(SCH), state: { trip_spend: { sum: 0 } }, monitors: {}, claims: [{ id: 'trip_spend', post: 38_900 }], ...o });
  c('g0', {});
  c('acc-claim-mismatch', { claims: [{ id: 'trip_spend', post: 38_899 }] });
  c('acc-claim-missing', { claims: [] });
  c('acc-claim-unknown', { claims: [{ id: 'trip_spend', post: 38_900 }, { id: 'nope', post: 0 }] });
  c('acc-claim-wallet', { claims: [{ id: 'trip_spend', post: 38_900 }, { id: 'questions', post: 1 }] });
  c('acc-no-state', { state: {} });
  c('acc-bad-state', { state: { trip_spend: { count: 0 } } });
  c('acc-over-domain', { claims: [{ id: 'trip_spend', post: 500_100 }], state: { trip_spend: { sum: 461_200 } } });
  c('acc-at-domain-max', { claims: [{ id: 'trip_spend', post: 500_000 }], state: { trip_spend: { sum: 461_100 } } });
  c('schema-unknown-digest', { docs: [{ ...SCH, version: 'v2' }] });
  c('schema-params-not-opening-digest', { params: { ...P, total: 1 } });
  const mon = { id: 'hotel_after_flight', kind: 'requires_prior', p: { verb: 'air.book' }, q: { verb: 'hotel.book' }, status: 'committed' };
  c('acc-monitor-state', { mons: [mon], monitors: { hotel_after_flight: 'unmet' } });
  c('acc-monitor-missing', { mons: [mon], monitors: {} });
  c('acc-monitor-bad-state', { mons: [mon], monitors: { hotel_after_flight: 'maybe' } });
  const DIST = { id: 'payees', agg: 'distinct', val: 'action.params.offer_id', sel: { verbs: ['air.book'] }, win: { kind: 'task' }, key: null, domain_max: 3, holder: SITE };
  const MX = { id: 'largest', agg: 'max', val: 'action.params.total', sel: { verbs: ['air.book'] }, win: { kind: 'task' }, key: null, holder: SITE };
  const CNT = { id: 'per_offer', agg: 'count', sel: { verbs: ['air.book'] }, win: { kind: 'sliding', ms: 60_000 }, key: 'action.params.offer_id', domain_max: 1, holder: SITE };
  const goodAcc = [{ id: 'payees', post: 2 }, { id: 'largest', post: 40_000 }, { id: 'per_offer', post: 1 }];
  const stx = { payees: { values: ['"OF-1"', '"OF-9"'] }, largest: { max: 40_000 }, per_offer: { count: 0 } };
  c('acc-distinct-max-count', { accs: [DIST, MX, CNT], claims: goodAcc, state: stx });
  c('acc-distinct-new-value', { accs: [DIST, MX, CNT], claims: goodAcc, state: { ...stx, payees: { values: ['"OF-7"', '"OF-9"'] } } });
  c('acc-keyed-count-over-domain', { accs: [DIST, MX, CNT], claims: [...goodAcc.slice(0, 2), { id: 'per_offer', post: 2 }], state: { ...stx, per_offer: { count: 1 } } });
  const SEQ = { ...TRIP, holder: { kind: 'sequenced', uri: 'https://atlas.example/seq', root: seqRoot.pub } };
  const dg = pcactnReservationDigest(draftOf({ accs: [SEQ], verb: 'air.book' }) as any);
  const body = { v: 1, kind: 'pca-acc-receipt', session: SESSION, acc: 'trip_spend', seq: 3, pre: 10_000, delta: 38_900, post: 48_900, pcactn_digest: dg, aud: AUD, issued_at: NOW, expires_at: NOW + 60_000, kid: 's2', ledger: { index: 7, head: d32('head') } };
  const rc = signAccReceipt(body as any, s2.sk);
  const cs = (name: string, rcv: any, o: Partial<Sc> = {}, post = 48_900) => c(name, { accs: [SEQ], state: {}, receipts: [rcv], keys: [KS], claims: [{ id: 'trip_spend', post, receipt: accReceiptDigest(rcv) }], ...o });
  cs('acc-receipt', rc);
  cs('acc-receipt-rotated-key-in-window', signAccReceipt({ ...body, kid: 's1', issued_at: NOW - 5_000 } as any, s1.sk));
  cs('acc-receipt-retired-key', signAccReceipt({ ...body, kid: 's1' } as any, s1.sk));
  cs('acc-receipt-no-keyset', rc, { keys: [] });
  cs('acc-receipt-foreign-keyset', rc, { keys: [signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: NOW, keys: [{ kid: 's2', pk: s2.pub, not_before: 0 }] } as any, stranger.sk)] });
  cs('acc-receipt-future', signAccReceipt({ ...body, issued_at: NOW + 61_000, expires_at: NOW + 121_000 } as any, s2.sk));
  cs('acc-receipt-missing', rc, { receipts: [] });
  cs('acc-receipt-replay', rc, { last_seq: { trip_spend: 3 } });
  cs('acc-receipt-foreign-signer', signAccReceipt(body as any, stranger.sk));
  cs('acc-receipt-arithmetic', signAccReceipt({ ...body, post: 48_901 } as any, s2.sk), {}, 48_901);
  cs('acc-receipt-other-aud', signAccReceipt({ ...body, aud: 'hotel.example' } as any, s2.sk));
  cs('acc-receipt-expired', signAccReceipt({ ...body, issued_at: NOW - 1_000, expires_at: NOW - 1 } as any, s2.sk));
  c('acc-state-sum-null', { state: { trip_spend: { sum: null } } });
  c('acc-state-sum-string', { state: { trip_spend: { sum: '0' } } });
  c('acc-state-sum-fraction', { state: { trip_spend: { sum: 0.5 } } });
  c('acc-state-sum-negative', { state: { trip_spend: { sum: -1 } } });
  c('acc-last-seq-string', { last_seq: { trip_spend: '3' } });
  c('acc-receipts-string', { ctxPatch: (x) => { x.acc.receipts = 'r'; return x; } });
  c('acc-sequencer-keys-object', { ctxPatch: (x) => { x.acc.sequencer_keys = {}; return x; } });
  c('acc-state-array', { ctxPatch: (x) => { x.acc.state = []; return x; } });
  c('acc-state-own-proto-key', { ctxPatch: (x) => { x.acc.state = JSON.parse('{"__proto__": {"sum": 0}}'); return x; } });
  c('ctx-acc-receipts-null', { ctxPatch: (x) => { x.acc.receipts = null; return x; } });
  c('ctx-acc-monitors-null', { ctxPatch: (x) => { x.acc.monitors = null; return x; } });
  c('ctx-acc-monitors-absent', { ctxPatch: (x) => { delete x.acc.monitors; return x; } });
  c('schema-docs-string', { ctxPatch: (x) => { x.schema = { docs: 'x', keys: [] }; return x; } });
  c('schema-keys-object', { ctxPatch: (x) => { x.schema = { docs: x.schema.docs, keys: { 0: 1 } }; return x; } });
  {
    const TSA = { ...TRIP, id: 'toString' };
    c('acc-inherited-name', { accs: [TSA], claims: [{ id: 'toString', post: 38_900 }], state: {}, last_seq: {} });
    c('acc-own-name', { accs: [TSA], claims: [{ id: 'toString', post: 38_900 }], state: { toString: { sum: 0 } } });
  }
  {
    const ml65 = mlDsa65Keygen(seed('conf-ml65'));
    const pq65 = encodeMlDsaPublicKey(ml65.publicKey);
    const KSQ = signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: NOW - 100, keys: [{ kid: 'pq1', pk: s1.pub, alg: 'ml-dsa-65', pq_pk: pq65, not_before: NOW - 10_000 }] } as any, seqRoot.sk);
    const rq = signAccReceipt({ ...body, seq: 1, pre: 0, delta: 38_900, post: 38_900, kid: 'pq1', ledger: { index: 0, head: d32('head') } } as any, s1.sk, { alg: 'ml-dsa-65', mlDsa: ml65 });
    cs('acc-receipt-ml-dsa-65', rq, { keys: [KSQ] }, 38_900);
  }
  cs('acc-receipt-other-action', signAccReceipt({ ...body, pcactn_digest: d32('other-action') } as any, s2.sk));
}

// ---- helpers on their own ------------------------------------------------------------------------------------------------
const declVariants: unknown[] = [
  ...Object.values(D), SEQ_SUM, SEQ_UNIT, { ...SEQ_SUM, holder: { ...SEQ_HOLDER, root_alg: HYB, root_pq_pk: 'AAAA', keys_uri: 'https://k' } },
  null, [], 'x', { ...D.spent, extra: 1 }, { ...D.spent, id: 'a-b' }, { ...D.spent, id: 'x'.repeat(65) }, { ...D.spent, id: 'x'.repeat(64) }, { ...D.spent, agg: 'avg' },
  { ...D.spent, val: 'params.amount' }, { ...D.spent, val: 5 }, { ...D.spent, unit: 'USD' }, { ...D.spent, unit: 'a..b' }, { ...D.spent, unit: 'a'.repeat(65) }, { ...D.spent, unit: 'a.b_c.9' },
  { ...D.spent, sel: [] }, { ...D.spent, sel: { verbs: [] } }, { ...D.spent, sel: { verbs: [''] } }, { ...D.spent, sel: { verbs: Array.from({ length: 65 }, (_, i) => `v${i}`) } }, { ...D.spent, sel: { verbs: ['a'], x: 1 } },
  { ...D.spent, sel: { verbs: ['a'], event: 'question' } }, { ...D.spent, sel: {} }, { ...D.spent, sel: { accumulates_into: 'Bad' } }, { ...D.questions, sel: { event: 'other' } },
  { ...D.spent, win: { kind: 'task', ms: 1 } }, { ...D.spent, win: { kind: 'sliding', ms: 0 } }, { ...D.spent, win: { kind: 'sliding', ms: 1.5 } }, { ...D.spent, win: { kind: 'sliding' } },
  { ...D.spent, win: { kind: 'period', ms: 1, t0: -1 } }, { ...D.spent, win: { kind: 'period', ms: 1, t0: 0 } }, { ...D.spent, win: { kind: 'period', ms: 1 } }, { ...D.spent, win: { kind: 'hour' } }, { ...D.spent, win: null },
  { ...D.spent, key: 'action.params.x' }, { ...D.spent, key: 'x' }, (() => { const a: any = { ...D.spent }; delete a.key; return a; })(), { ...D.spent, domain_max: -1 }, { ...D.spent, domain_max: 0 }, { ...D.spent, cap: 1.5 },
  { ...D.spent, holder: { kind: 'site_local', x: 1 } }, { ...D.spent, holder: { kind: 'other' } }, { ...D.spent, holder: { kind: 'wallet' } }, { ...D.questions, holder: SITE },
  { ...SEQ_SUM, holder: { ...SEQ_HOLDER, uri: '' } }, { ...SEQ_SUM, holder: { ...SEQ_HOLDER, root: 'abc' } }, { ...SEQ_SUM, holder: { ...SEQ_HOLDER, root_alg: 'rsa' } }, { ...SEQ_SUM, holder: { ...SEQ_HOLDER, root_pq_pk: 'A' } },
  { ...SEQ_SUM, holder: { ...SEQ_HOLDER, root_pq_pk: '' } }, { ...SEQ_SUM, holder: { ...SEQ_HOLDER, keys_uri: '' } }, { ...SEQ_SUM, holder: { ...SEQ_HOLDER, other: 1 } }, { ...SEQ_SUM, holder: { ...SEQ_HOLDER, root_alg: null } },
  (() => { const a: any = { ...D.largest }; delete a.val; return a; })(), (() => { const a: any = { ...D.payees }; delete a.val; return a; })(), (() => { const a: any = { ...D.spent }; delete a.val; return a; })(),
  { ...D.spent, id: '__proto__' }, { ...D.spent, id: 'constructor' }, { ...D.spent, id: 'prototype' }, { ...D.spent, id: 'toString' },
  { ...SEQ_SUM, holder: { ...SEQ_HOLDER, root_alg: 5 } }, { ...SEQ_SUM, holder: { ...SEQ_HOLDER, root_alg: 'fn-dsa-512' } }, { ...SEQ_SUM, holder: { ...SEQ_HOLDER, root_alg: 'no-such-suite' } },
  { ...D.per_payee, val: 'action.params.x' }, (() => { const a: any = { ...D.spend_unit, agg: 'max' }; return a; })(), { ...D.questions, agg: 'sum' },
];
const decls = declVariants.map((decl) => ({ decl, ok: accumulatorDeclError(decl) === null }));
const monVariants: unknown[] = [
  ...Object.values(M), null, { ...M.nv, extra: 1 }, { ...M.nv, id: '' }, { ...M.nv, kind: 'eventually' }, { ...M.nv, p: { verb: [] } }, { ...M.nv, p: { verb: [1] } }, { ...M.nv, p: null }, { ...M.nv, q: { verb: 'x' } },
  (() => { const m: any = { ...M.rp }; delete m.q; return m; })(), { ...M.rp, q: { verb: 5 } }, { ...M.nv, status: 'done' }, { ...M.rw, within: 0 }, { ...M.rw, within: 65 }, { ...M.rw, within: 64 }, { ...M.rw, within: 1.5 },
  (() => { const m: any = { ...M.rw }; delete m.within; return m; })(), { ...M.nv, id: '__proto__' }, { ...M.nv, id: 'constructor' }, { ...M.nv, id: 'prototype' }, { ...M.nv, id: 'valueOf' }, { ...M.nv, within: 3 }, { ...M.nv, p: { verb: 'x', where: [] } },
];
const monitors = monVariants.map((decl) => ({ decl, ok: monitorDeclError(decl) === null, ...(monitorDeclError(decl) === null ? { states: monitorStates(decl as any) } : {}) }));
const preVariants: [string, unknown][] = [
  ['sum', { sum: 0 }], ['sum', { sum: MAX }], ['sum', { sum: MAX + 1 }], ['sum', { sum: -1 }], ['sum', { count: 1 }], ['sum', {}], ['sum', null], ['sum', [1]], ['sum', { sum: 1, x: 1 }],
  ['count', { count: 3 }], ['count', { sum: 3 }], ['max', { max: 9 }], ['max', { max: '9' }], ['distinct', { values: [] }], ['distinct', { values: ['a', 'b'] }], ['distinct', { values: ['a', 'a'] }], ['distinct', { values: [1] }], ['distinct', { values: 'a' }],
];
const pre_states = preVariants.map(([agg, s]) => {
  const err = preStateError({ agg } as any, s) === null;
  return { agg, s, ok: err, ...(err ? { value: preValue({ agg } as any, s as any) } : {}) };
});
const combVariants: [string, any, any][] = [
  ['sum', { sum: 1 }, { val: 2 }], ['sum', { sum: MAX - 1 }, { val: 1 }], ['sum', { sum: MAX }, { val: 1 }], ['sum', { sum: MAX }, { val: MAX }], ['count', { count: MAX - 1 }, { val: 1 }], ['count', { count: MAX }, { val: 1 }],
  ['max', { max: 5 }, { val: 3 }], ['max', { max: 3 }, { val: 5 }], ['max', { max: MAX }, { val: 0 }], ['distinct', { values: ['"a"'] }, { val: 1, key: '"a"' }], ['distinct', { values: ['"a"'] }, { val: 1, key: '"b"' }], ['distinct', { values: [] }, { val: 1, key: '1' }],
];
const combine = combVariants.map(([agg, pre, v]) => ({ agg, pre, v, post: combineAcc({ agg } as any, pre, v) }));
const arithVariants: [string, any, number][] = [
  ['sum', { pre: 1, delta: 2, post: 3 }, 2], ['sum', { pre: 1, delta: 2, post: 3 }, 3], ['sum', { pre: 1, delta: 2, post: 4 }, 2], ['count', { pre: 1, delta: 1, post: 2 }, 1], ['count', { pre: 1, delta: 0, post: 1 }, 1],
  ['max', { pre: 5, delta: 3, post: 5 }, 3], ['max', { pre: 5, delta: 3, post: 3 }, 3], ['max', { pre: 1, delta: 3, post: 3 }, 3], ['distinct', { pre: 2, delta: 0, post: 2 }, 1], ['distinct', { pre: 2, delta: 1, post: 3 }, 1], ['distinct', { pre: 2, delta: 2, post: 4 }, 1],
  ['sum', { pre: MAX - 1, delta: 2, post: MAX }, 2],
];
const arith = arithVariants.map(([agg, rc, val]) => ({ agg, r: rc, val, ok: receiptArithmeticOk({ agg } as any, rc, val) }));
const digestInputs: any[] = [draftOf(seqBase), { ...draftOf(seqBase), threshold: { a: 1 }, pq_sig: 'z' }, { a: 1 }, {}, { sig: 1, intent_session: 2 }, { x: [1, 'é', { b: null }] }, { x: 1.5 }, { x: MAX + 1 }];
const digests = digestInputs.map((p) => {
  let reservation: string | null = null;
  try { reservation = pcactnReservationDigest(p); } catch { reservation = null; }
  return { pcactn: p, reservation };
});
const rcBase = rcSum();
const rcVariants: unknown[] = [rcBase, goodRcs()[1], { ...rcBase, alg: 'ed25519' }, { ...rcBase, alg: HYB, pq_pk: 'AAAA', pq_sig: 'AAAA' }, { ...rcBase, alg: 'rsa' }, { ...rcBase, alg: 'fn-dsa-512', pq_pk: 'AAAA' }, { ...rcBase, alg: 5 }, { ...rcBase, alg: null }, { ...rcBase, pq_sig: 'x' }, { ...rcBase, v: 2 }, { ...rcBase, kind: 'x' },
  { ...rcBase, session: 'x' }, { ...rcBase, acc: 'a-b' }, { ...rcBase, seq: 0 }, { ...rcBase, seq: 1.5 }, { ...rcBase, pre: -1 }, { ...rcBase, post: MAX + 1 }, { ...rcBase, aud: '' }, { ...rcBase, issued_at: -1 }, { ...rcBase, kid: '' }, { ...rcBase, kid: 'k'.repeat(65) },
  { ...rcBase, kid: 'a.b:c-d_e' }, { ...rcBase, ledger: { index: -1, head: d32('h') } }, { ...rcBase, ledger: { index: 1 } }, { ...rcBase, signer: 'abc' }, { ...rcBase, sig: null }, { ...rcBase, extra: 1 }, null, [], { ...rcBase, v: 1.0 }, { ...rcBase, expires_at: rcBase.issued_at + 900_000 }, { ...rcBase, expires_at: rcBase.issued_at + 900_001 }, { ...rcBase, expires_at: rcBase.issued_at - 1 }];
const receipt_shapes = rcVariants.map((rv) => ({ r: rv, ok: accReceiptShapeError(rv) === null, digest: (() => { try { return accReceiptDigest(rv as any); } catch { return null; } })() }));
const ksVariants: unknown[] = [KS, { ...clone(KS), alg: 'ed25519' }, { ...clone(KS), alg: 'zz' }, { ...clone(KS), keys: [] }, { ...clone(KS), keys: Array.from({ length: 257 }, (_, i) => ({ kid: `k${i}`, pk: s2.pub, not_before: 0 })) },
  { ...clone(KS), keys: Array.from({ length: 256 }, (_, i) => ({ kid: `k${i}`, pk: s2.pub, not_before: 0 })) }, { ...clone(KS), issued_at: -1 }, { ...clone(KS), sequencer: 'x' }, { ...clone(KS), sig: 1 }, { ...clone(KS), keys: [{ kid: 'a', pk: s2.pub, not_before: 5, not_after: 5 }] },
  { ...clone(KS), keys: [{ kid: 'a', pk: s2.pub, not_before: 5, not_after: 4 }] }, { ...clone(KS), keys: [{ kid: 'a', pk: s2.pub }] }, { ...clone(KS), keys: [{ kid: 'a', pk: s2.pub, not_before: 0, pq_pk: '' }] }, { ...clone(KS), keys: [{ kid: 'a', pk: s2.pub, not_before: 0, alg: 'x' }] }, null, { ...clone(KS), version: 0 }, { ...clone(KS), version: 1.5 }, (() => { const k: any = clone(KS); delete k.version; return k; })(), { ...clone(KS), version: MAX }];
const key_set_shapes = ksVariants.map((k) => ({ k, ok: sequencerKeySetShapeError(k) === null }));

writeFileSync(out, JSON.stringify({ cases, decls, monitors, pre_states, combine, arith, digests, receipt_shapes, key_set_shapes, hash_check: hashCanonical({ a: 1 }) }, null, 1));
console.log(`acc: ${cases.length} cases (${cases.filter((c) => c.expect.ok).length} ok, ${cases.filter((c) => c.pq).length} pq), ${decls.length} decls, ${monitors.length} monitors, ${pre_states.length} pre, ${combine.length} combine, ${arith.length} arith, ${digests.length} digests, ${receipt_shapes.length} receipts, ${key_set_shapes.length} key sets`);
