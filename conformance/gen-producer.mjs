// Regenerates producer-vectors.json: the agent/issuer-side (signing) vectors every native producer must reproduce byte for byte.
// Independent of the TypeScript code (node:crypto only): it restates the wire rules, and producer-vectors.test.ts checks the
// real TypeScript producers (mintGrant, delegate, buildPCActn, signEscalationAnswer, ...) against the committed file.
// FIXED keys, nonces, counters and timestamps: Ed25519 is deterministic, so every output is exact.
// Usage: node conformance/gen-producer.mjs > conformance/producer-vectors.json
import { createHash, createPrivateKey, createPublicKey, sign as edSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const b64u = (b) => Buffer.from(b).toString('base64url');
const unb64u = (s) => Buffer.from(s, 'base64url');
const sha = (b) => createHash('sha256').update(b).digest();

// ---- canonical JSON (strict profile; in-profile data only) ----
const cmp = (a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
function ser(v) {
  if (v === null) return 'null';
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') {
    if (!Number.isFinite(v) || Object.is(v, -0)) throw new Error('bad number');
    if (Number.isInteger(v) && !Number.isSafeInteger(v)) throw new Error('unsafe int');
    return String(v);
  }
  if (Array.isArray(v)) return '[' + v.map(ser).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.keys(v).sort(cmp).map((k) => JSON.stringify(k) + ':' + ser(v[k])).join(',') + '}';
  throw new Error('unsupported');
}
const canon = (v) => Buffer.from(ser(v), 'utf8');
const hashC = (v) => b64u(sha(canon(v)));
const plain = (v) => JSON.parse(JSON.stringify(v));

// ---- keys ----
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const priv = (seed) => createPrivateKey({ key: Buffer.concat([PKCS8, unb64u(seed)]), format: 'der', type: 'pkcs8' });
const pubOf = (seed) => b64u(createPublicKey(priv(seed)).export({ format: 'der', type: 'spki' }).subarray(-32));
const signRaw = (seed, msg) => b64u(edSign(null, msg, priv(seed)));
const dmsg = (domain, body) => Buffer.concat([Buffer.from(domain, 'utf8'), canon(body)]);
const signBody = (seed, domain, body) => signRaw(seed, dmsg(domain, body));

const here = fileURLToPath(new URL('.', import.meta.url));
const K = JSON.parse(readFileSync(here + 'keys.json', 'utf8'));
const SEED = { principal: K.principal.seed, agent: K.agent.seed, subagent: K.subagent.seed, rogue: K.rogue.seed };
const PUB = Object.fromEntries(Object.entries(SEED).map(([n, s]) => [n, pubOf(s)]));
for (const n of Object.keys(PUB)) if (PUB[n] !== K[n].public) throw new Error('keys.json public mismatch for ' + n);
// extra fixed identities (not in keys.json)
SEED.rs = b64u(sha(Buffer.from('producer-vector:rs', 'utf8')));
SEED.approver = b64u(sha(Buffer.from('producer-vector:approver', 'utf8')));
SEED.issuer3p = b64u(sha(Buffer.from('producer-vector:third-party', 'utf8')));
for (const n of ['rs', 'approver', 'issuer3p']) PUB[n] = pubOf(SEED[n]);

// ---- capability chain ----
const CAP_DOMAIN = 'atlas-pca/cap/v1\0';
function seal(body, signerSeed) {
  const bodyObj = { issuer: body.issuer, holder: body.holder, caveats: body.caveats, parent: body.parent ?? null, ...(body.holder_pq !== undefined ? { holder_pq: body.holder_pq } : {}) };
  const body_digest = hashC(bodyObj);
  const sig = signRaw(signerSeed, Buffer.concat([Buffer.from(CAP_DOMAIN, 'utf8'), unb64u(body_digest)]));
  const cap = { id: body_digest, issuer: body.issuer, holder: body.holder, caveats: body.caveats, body_digest, sig };
  if (body.parent !== undefined) cap.parent = body.parent;
  if (body.holder_pq !== undefined) cap.holder_pq = body.holder_pq;
  return cap;
}
const clone = (c) => JSON.parse(canon(c).toString('utf8'));
const capHash = (c) => hashC(c);
const GOAL_DOMAIN = 'atlas-pca/goal/v1\0';
const goalCommit = (goal, salt) => hashC({ d: GOAL_DOMAIN, goal, salt });

function mintGrant(a) {
  const goalSalt = a.salt;
  const env = plain({
    goal_commit: goalCommit(a.goal, goalSalt),
    predicates: a.envelope.predicates,
    caveats: a.envelope.caveats,
    agent_binding: a.envelope.agent_binding ?? {},
    risk_policy: a.envelope.risk_policy,
    ...(a.envelope.units !== undefined ? { units: a.envelope.units } : {}),
    ...(a.envelope.actions !== undefined ? { actions: a.envelope.actions } : {}),
  });
  ser(env);
  const grant = seal({ issuer: PUB[a.principal], holder: PUB[a.holder], caveats: clone([{ type: 'envelope', ...env }]) }, SEED[a.principal]);
  return { grant, goal_commit: env.goal_commit, goal_salt: goalSalt };
}
function delegate(parent, signer, toHolder, added) {
  return seal({ issuer: parent.holder, holder: toHolder ?? parent.holder, caveats: [...clone(parent.caveats), ...clone(added)], parent: capHash(parent), ...(toHolder === undefined || toHolder === parent.holder ? (parent.holder_pq !== undefined ? { holder_pq: parent.holder_pq } : {}) : {}) }, SEED[signer]);
}

// ---- plan ----
const EMPTY = hashC({});
const paramsDigest = (p) => hashC(p ?? {});
const condDigest = (pre, post) => b64u(sha(canon({ pre: pre ?? null, post: post ?? null })));
const leafOf = (n) => ({ node_id: n.id, verb: n.verb, resource: n.resource, params_digest: n.params_digest ?? EMPTY, reversibility_class: n.reversibility_class ?? 'reversible', conditions: condDigest(n.pre, n.post) });
const lh = (leaf) => sha(Buffer.concat([Buffer.from([0]), canon(leaf)]));
const nh = (l, r) => sha(Buffer.concat([Buffer.from([1]), l, r]));
const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
const build = (hs) => (hs.length === 1 ? hs[0] : nh(build(hs.slice(0, split(hs.length))), build(hs.slice(split(hs.length)))));
function prove(hs, idx, out) {
  if (hs.length === 1) return;
  const k = split(hs.length);
  if (idx < k) { prove(hs.slice(0, k), idx, out); out.push({ side: 'R', hash: b64u(build(hs.slice(k))) }); } else { prove(hs.slice(k), idx - k, out); out.push({ side: 'L', hash: b64u(build(hs.slice(0, k))) }); }
}
function commitPlan(nodes) {
  const hs = nodes.map((n) => lh(leafOf(n)));
  return { root: b64u(build(hs)), proofFor: (id) => { const i = nodes.findIndex((n) => n.id === id); const path = []; prove(hs, i, path); return { index: i, size: nodes.length, path }; } };
}

// ---- act ----
const ACT_DOMAIN = 'atlas-pca/actn/v2\0';
function act(a) {
  const node = a.plan.find((n) => n.id === a.node_id);
  const committed = commitPlan(a.plan);
  const body = {
    ver: 2,
    action: { verb: node.verb, resource: node.resource, params_digest: paramsDigest(a.params), reversibility_class: node.reversibility_class ?? 'reversible' },
    grant_ref: a.grant.id,
    cap_chain: a.chain,
    plan: { root: committed.root, inclusion_proof: committed.proofFor(a.node_id), node_id: a.node_id, conditions_digest: condDigest(node.pre, node.post) },
    attestation: { quote_digest: '', epoch: 0, model_id: 'unattested', measurement: '', operator: 'unattested' },
    provenance: { causal_hash: '', taint_level: 0, trusted_refs: [] },
    freshness: { beacon_ref: '', epoch: 0, accumulator_witness: '' },
    counter: a.counter,
    risk_claim: { r: 0, inputs: {} },
    aud: a.aud,
    iat: a.iat,
    exp: a.exp,
    ...(a.nonce !== undefined ? { nonce: a.nonce } : {}),
    ...(a.caution !== undefined ? { caution: a.caution } : {}),
    ...(a.rationale_commitment !== undefined ? { rationale_commitment: a.rationale_commitment } : {}),
    ...(a.tool_binding !== undefined ? { tool_binding: a.tool_binding } : {}),
    ...(a.fresh_at !== undefined ? { fresh_at: a.fresh_at } : {}),
  };
  const msg = Buffer.concat([Buffer.from(ACT_DOMAIN, 'utf8'), sha(canon(body))]);
  const pcactn = { ...body, sig: signRaw(SEED[a.signer], msg) };
  return { pcactn, threshold_message: b64u(msg), header: b64u(Buffer.from(JSON.stringify(sortLenient(pcactn)), 'utf8')) };
}
// encodePCActn: lenient canonical JSON (sorted keys, no whitespace); identical bytes to the strict form for in-profile data
function sortLenient(v) {
  if (Array.isArray(v)) return v.map(sortLenient);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort(cmp).map((k) => [k, sortLenient(v[k])]));
  return v;
}

// ---- artifacts ----
const art = (domain, body, seed) => ({ ...body, sig: signBody(seed, domain, body) });
const ESC = { ans: 'atlas-pca/escalation-answer/v1\0', pol: 'atlas-pca/escalation-policy/v1', act: 'atlas-pca/escalation-action/v1', hist: 'atlas-pca/escalation-history/v1' };
const D = 'atlas-pca/discharge/v1\0';
const N = 'atlas-pca/narrow/v1\0';
const FRESH = 'atlas-pca/fresh-at/v1\0';

function passportId(p) {
  return hashC({ d: 'atlas-pca/passport/v1', model_id: p.model_id, weights_digest: p.weights_digest ?? null, system_prompt_digest: p.system_prompt_digest ?? null, tool_manifest_digest: p.tool_manifest_digest ?? null, runtime_measurement: p.runtime_measurement ?? null, operator: p.operator, hardware_rooted: p.hardware_rooted });
}

// ---- the case set ----
const RISK = { weights: { alpha: 0.25, beta: 0.2, gamma: 0.2, delta: 0.2, epsilon: 0.1, zeta: 0.05 }, theta1: 0.25, theta2: 0.6, kappa: 1, lambda: 0.0005, rho: 0.5, bMax: 1 };
const AUD = 'rs-producer-vectors';
const T0 = 1_800_000_000_000;
const SALT = b64u(sha(Buffer.from('producer-vector:salt', 'utf8')).subarray(0, 16));
const NONCE = (n) => b64u(sha(Buffer.from('producer-vector:nonce:' + n, 'utf8')).subarray(0, 16));
const PLAN = [
  { id: 'n1', verb: 'refund', resource: 'orders/1', params_digest: paramsDigest({ amount_cents: 500, currency: 'USD' }), reversibility_class: 'compensable' },
  { id: 'n2', verb: 'read', resource: 'orders/1' },
  { id: 'n3', verb: 'notify', resource: 'users/9', pre: { exists: true }, post: { sent: true } },
];
const ENVELOPE = {
  predicates: [{ verb: 'refund', resource: 'orders/*' }, { verb: 'read', resource: 'orders/*' }, { verb: 'notify', resource: 'users/*' }],
  caveats: [{ type: 'budget_alloc', limit: 10 }],
  agent_binding: { operator: 'acme' },
  risk_policy: RISK,
};

const rootArgs = { principal: 'principal', holder: 'agent', envelope: ENVELOPE, goal: 'refund order 1 up to 5 dollars', salt: SALT };
const root = mintGrant(rootArgs);
const rootEnv2 = mintGrant({ ...rootArgs, envelope: { ...ENVELOPE, units: { 'action.params.amount_cents': 'cents' }, caveats: [] }, goal: 'second', salt: NONCE('salt2') });
const att = delegate(root.grant, 'agent', undefined, [{ type: 'budget_alloc', limit: 5 }]);
const sub = delegate(att, 'agent', PUB.subagent, [{ type: 'sealed' }]);
const sub2 = delegate(att, 'agent', PUB.subagent, [{ type: 'max_uses', id: 'm1', n: 3, until: T0 + 86_400_000 }]);

const cases = [];
const add = (name, op, args, expect) => cases.push({ name, op, args, expect });

for (const [n, msg] of [['empty', ''], ['ascii', 'atlas-pca producer vector'], ['unicode', 'sälz ✓ \u0000 end']]) add('ed25519-' + n, 'ed25519_sign', { seed: SEED.agent, message_utf8: msg }, { public: PUB.agent, sig: signRaw(SEED.agent, Buffer.from(msg, 'utf8')) });
add('goal-commit-basic', 'goal_commit', { goal: 'refund order 1', salt: 'salt-1' }, { commit: goalCommit('refund order 1', 'salt-1') });
add('goal-commit-unicode', 'goal_commit', { goal: 'zurück ✓', salt: 'sälz' }, { commit: goalCommit('zurück ✓', 'sälz') });
add('params-digest-empty', 'params_digest', { params: null }, { digest: EMPTY });
add('params-digest-nested', 'params_digest', { params: { b: [1, 2.5, 'x'], a: { z: true, y: null } } }, { digest: paramsDigest({ b: [1, 2.5, 'x'], a: { z: true, y: null } }) });
for (const [n, size] of [['plan-1', 1], ['plan-3', 3]]) {
  const nodes = PLAN.slice(0, size);
  const c = commitPlan(nodes);
  add(n, 'plan_commit', { nodes }, { root: c.root, proofs: Object.fromEntries(nodes.map((x) => [x.id, c.proofFor(x.id)])) });
}
add('mint-grant-basic', 'mint_grant', rootArgs, root);
add('mint-grant-units-no-caveats', 'mint_grant', { ...rootArgs, envelope: { ...ENVELOPE, units: { 'action.params.amount_cents': 'cents' }, caveats: [] }, goal: 'second', salt: NONCE('salt2') }, rootEnv2);
add('delegate-attenuate', 'delegate', { parent: root.grant, signer: 'agent', to_holder: null, added_caveats: [{ type: 'budget_alloc', limit: 5 }] }, att);
add('delegate-subagent-sealed', 'delegate', { parent: att, signer: 'agent', to_holder: 'subagent', added_caveats: [{ type: 'sealed' }] }, sub);
add('delegate-subagent-max-uses', 'delegate', { parent: att, signer: 'agent', to_holder: 'subagent', added_caveats: [{ type: 'max_uses', id: 'm1', n: 3, until: T0 + 86_400_000 }] }, sub2);

const actBase = { aud: AUD, iat: T0, exp: T0 + 1_200_000, params: { amount_cents: 500, currency: 'USD' }, plan: PLAN };
const A1 = { ...actBase, grant: root.grant, chain: [root.grant], node_id: 'n1', counter: 1, signer: 'agent', nonce: NONCE('a1') };
add('act-root-refund', 'act', A1, act(A1));
const A2 = { ...actBase, grant: root.grant, chain: [root.grant, att], node_id: 'n1', counter: 2, signer: 'agent', nonce: NONCE('a2'), caution: 0.25 };
add('act-attenuated-caution', 'act', A2, act(A2));
const A3 = { ...actBase, params: undefined, grant: root.grant, chain: [root.grant, att, sub], node_id: 'n2', counter: 1, signer: 'subagent' };
delete A3.params;
add('act-subagent-no-params', 'act', A3, act(A3));
const A4 = { ...actBase, params: undefined, grant: root.grant, chain: [root.grant], node_id: 'n3', counter: 7, signer: 'agent', rationale_commitment: b64u(sha(Buffer.from('why', 'utf8'))), tool_binding: b64u(sha(Buffer.from('tool', 'utf8'))) };
delete A4.params;
add('act-pre-post-conditions', 'act', A4, act(A4));
const fa = { v: 1, scope: 'inst_1', revocation_epoch: 3, ledger_tree_size: 40, budget_version: 7, policy_revision: 2, policy_digest: 'pol-2', issued_at: T0, signer: PUB.rs };
const faBody = { ...fa };
const faTok = { ...fa, sig: signBody(SEED.rs, FRESH, faBody) };
add('fresh-at-token', 'fresh_at', { signer: 'rs', scope: 'inst_1', state: { revocation_epoch: 3, ledger_tree_size: 40, budget_version: 7, policy_revision: 2, policy_digest: 'pol-2' }, issued_at: T0 }, faTok);
const A5 = { ...actBase, grant: root.grant, chain: [root.grant], node_id: 'n1', counter: 3, signer: 'agent', fresh_at: faTok };
add('act-fresh-at-member', 'act', A5, act(A5));

// escalation
const a1 = act(A1).pcactn;
const dig = { policy_digest: hashC({ d: ESC.pol, grant: root.grant }), action_digest: hashC({ d: ESC.act, pcactn: a1 }), history_head: hashC({ d: ESC.hist, last_counter: 0 }) };
add('escalation-digests', 'escalation_digests', { grant: root.grant, pcactn: a1, last_counter: 0 }, dig);
add('escalation-digests-no-history', 'escalation_digests', { grant: root.grant, pcactn: a1, last_counter: null }, { ...dig, history_head: hashC({ d: ESC.hist, last_counter: null }) });
const ansBody = { v: 1, kind: 'pca-escalation-answer', principal: PUB.approver, ...dig, decision: 'allow', iat: T0, expires_at: T0 + 600_000, nonce: NONCE('ans1') };
add('escalation-answer-allow', 'sign_escalation_answer', { signer: 'approver', body: ansBody }, art(ESC.ans, ansBody, SEED.approver));
const ansBody2 = { ...ansBody, decision: 'deny', nonce: NONCE('ans2'), render_digest: b64u(sha(Buffer.from('render', 'utf8'))) };
add('escalation-answer-deny-render', 'sign_escalation_answer', { signer: 'approver', body: ansBody2 }, art(ESC.ans, ansBody2, SEED.approver));

// discharge (third-party caveat)
const chainHop = capHash(root.grant);
const dBody = { v: 1, kind: 'pca-discharge', caveat_id: 'kyc', issuer: 'kyc-service', cap_hash: chainHop, bind: 'chain_hop', claims: { kyc_level: 2, verified: true, region: 'eu' }, iat: T0, not_after: T0 + 300_000, nonce: NONCE('d1') };
add('discharge-chain-hop', 'sign_discharge', { signer: 'issuer3p', body: dBody }, art(D, dBody, SEED.issuer3p));
const dBody2 = { ...dBody, bind: 'action', action_digest: hashC({ d: 'atlas-pca/discharge-action/v1', pcactn: a1 }), nonce: NONCE('d2'), claims: { score: 90 } };
add('discharge-action-bound', 'sign_discharge', { signer: 'issuer3p', body: dBody2 }, art(D, dBody2, SEED.issuer3p));
add('discharge-ref', 'discharge_digest', { discharge: art(D, dBody, SEED.issuer3p) }, { digest: hashC({ d: 'atlas-pca/discharge-ref/v1', discharge: art(D, dBody, SEED.issuer3p) }) });
const nBody = { v: 1, kind: 'pca-narrow', cap_hash: capHash(att), holder: att.holder, caveats: [{ type: 'budget_alloc', limit: 1 }], iat: T0, not_after: T0 + 60_000, nonce: NONCE('n1') };
add('narrow-self-attenuation', 'sign_narrow', { signer: 'agent', body: nBody }, art(N, nBody, SEED.agent));

// passport
const identity = { model_id: 'm1', weights_digest: 'w1', operator: 'acme', hardware_rooted: false, weights_measured: false, issued_at: T0 - 1000 };
const ppt = { ...identity, id: passportId(identity) };
const ppBody = { typ: 'atlas-pca/passport', ver: 1, passport: ppt, iss: PUB.principal, sub: PUB.agent, iat: T0 - 1000, nbf: T0 - 1000, exp: T0 + 3_600_000 };
add('passport-sign', 'sign_passport', { issuer: 'principal', subject: 'agent', identity, exp: T0 + 3_600_000 }, { passport: ppt, signed: { ...ppBody, sig: signBody(SEED.principal, 'atlas-pca/passport-sig/v1\0', ppBody) } });

// workflow commitment + receipts
const step = (id, deps, extra = {}) => ({ id, verb: 'pay', resource: 'invoices/' + id, params_digest: null, deps, sink: null, deny_labels: [], escalate_labels: [], fresh_ms: null, cost: {}, ...extra });
const wfBody = { v: 1, id: 'wf-1', principal: PUB.principal, goal_digest: null, plan_root: null, issued_at: T0, expires_at: T0 + 3_600_000, steps: [step('s1', []), step('s2', ['s1'], { cost: { pay: 1 } })], edges: [{ from: { step: 's1', field: 'amount' }, to: { step: 's2', param: 'amount' }, op: 'le', unit: 'cents', deny_labels: [], promise: null }], budget: { max_steps: 4, caps: { pay: 2 } } };
const wfSigned = { body: wfBody, sig: signBody(SEED.principal, 'atlas-pca/workflow/v1\0', wfBody) };
add('workflow-sign', 'sign_workflow', { signer: 'principal', body: wfBody }, wfSigned);
const wfDigest = hashC({ d: 'atlas-pca/workflow-ref/v1', w: wfBody });
const valueDigest = (v) => hashC({ d: 'atlas-pca/wf-value/v1', v });
const out1 = { amount: { digest: valueDigest(400), num: 400, unit: 'cents', labels: [] } };
const rcBase1 = { v: 1, wf: wfDigest, step: 's1', seq: 0, prev: null, outcome: 'ok', params_digest: EMPTY, outputs: out1, issued_at: T0 + 1000, signer: PUB.rs };
const rc1 = { ...rcBase1, sig: signBody(SEED.rs, 'atlas-pca/wf-receipt/v1\0', rcBase1) };
add('workflow-receipt-first', 'sign_step_receipt', { signer: 'rs', workflow: wfBody, step: 's1', outcome: 'ok', params_digest: EMPTY, outputs: out1, issued_at: T0 + 1000, prev: null }, rc1);
const rcBase2 = { v: 1, wf: wfDigest, step: 's2', seq: 1, prev: hashC({ d: 'atlas-pca/wf-receipt-ref/v1', r: rc1 }), outcome: 'failed', params_digest: paramsDigest({ amount: 300 }), outputs: {}, issued_at: T0 + 2000, signer: PUB.rs };
add('workflow-receipt-chained', 'sign_step_receipt', { signer: 'rs', workflow: wfBody, step: 's2', outcome: 'failed', params_digest: paramsDigest({ amount: 300 }), outputs: {}, issued_at: T0 + 2000, prev: rc1 }, { ...rcBase2, sig: signBody(SEED.rs, 'atlas-pca/wf-receipt/v1\0', rcBase2) });

// signed read grant + aggregate grant
const rgBody = { v: 1, id: 'rg-1', principal: PUB.principal, issued_at: T0, expires_at: T0 + 3_600_000, reads: [{ verb: 'read', resource_prefix: 'customers/', purposes: ['support'], modes: { email: 'hash', ssn: 'drop' }, default_mode: 'show' }], caps: { rows: 100 }, sinks: { llm: { allow: ['public'], escalate: ['pii'] } } };
add('read-grant-sign', 'sign_read_grant', { signer: 'principal', body: rgBody }, { body: rgBody, sig: signBody(SEED.principal, 'atlas-pca/read-grant/v1\0', rgBody) });
const agBody = { v: 1, id: 'ag-1', principal: PUB.principal, issued_at: T0, expires_at: T0 + 3_600_000, rules: [{ verb: 'aggregate', resource_prefix: 'orders/', purposes: ['analytics'], fns: ['count', 'sum'], min_group: 5, clamp: 1000, epsilon_micro: 100000, dp: true }], epsilon_budget_micro: 1_000_000, max_queries: 10 };
add('aggregate-grant-sign', 'sign_aggregate_grant', { signer: 'principal', body: agBody }, { body: agBody, sig: signBody(SEED.principal, 'atlas-pca/aggregate-grant/v1\0', agBody) });

const out = {
  format: 1,
  suite: 'producer',
  layer: 'agent-side signing',
  description: 'Exact outputs of the agent/issuer-side producers. Every key is a fixed Ed25519 seed (`keys`), every nonce/counter/timestamp is fixed, and Ed25519 is deterministic, so a native producer must reproduce `expect` BYTE FOR BYTE (compare parsed JSON). `op` names the producer; `args` its inputs (a name in `signer`/`principal`/`holder`/`to_holder` is a key name from `keys`; `message_utf8` is the UTF-8 text to sign). Domain strings are JSON strings: \\u0000 is a NUL byte. `header` is the PCA-Action header value (base64url of the sorted-key JSON of the PCActn). Randomised post-quantum signatures are not here: those are checked by cross-verification (TS verifies native-produced proofs, natives verify TS-produced ones) in CI.',
  keys: Object.fromEntries(Object.keys(SEED).map((n) => [n, { seed: SEED[n], public: PUB[n] }])),
  cases,
};
process.stdout.write(JSON.stringify(out, null, 2) + '\n');
