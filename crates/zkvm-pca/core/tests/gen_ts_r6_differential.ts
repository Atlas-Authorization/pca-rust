// R6 (red-team round 6): verdicts of the TypeScript reference for the guest-vs-TS differential.
//
// A case is a list of PATCHES applied to a base "logical document" L derived from fixtures/decide_input.sample.json:
//   L = { root_caveats, extra, action, subject, env, plan, node_id, cond_digest, tool_binding }
// (root_caveats = grant.caveats; extra = caveats appended by the delegation hop; cond_digest = pcactn.plan.conditions_digest).
// Patch = { p: [path...], v?: value }  (no `v` => delete). The Rust side (tests/r6_differential.rs) applies the same patches,
// RE-MINTS the chain and the PCActn (validly signed) and runs the guest `decide`; this side runs the TS reference:
//   allow = plan_inclusion (verifyPCActnCore: planLeaf(node_id, action, cond ?? default) is a leaf of the plan)
//           AND decide(...).admit  (policy-vm.ts; chainVerified, nodeId = pcactn.plan.node_id, the server's ActionContext)
// Output of the TS reference; NOT a standard vector.
//
//   redteam/run.sh --tsconfig redteam/round4/tsconfig.json \
//       sdks/zkvm-pca/core/tests/gen_ts_r6_differential.ts <out> <mode: matrix|random> [count] [seed]
//   matrix => a JSON array (the committed golden fixtures/ts_r6_cases.json); random => JSON lines (the 100k box run).
import { createWriteStream, readFileSync, writeFileSync } from 'node:fs';
import { decide } from '../../../../packages/pca/src/policy-vm';
import { hashCanonical } from '../../../../packages/pca/src/hash';
import { conditionsDigest, planLeaf, planNodeLeaf } from '../../../../packages/pca/src/merkle';

const [, , out, mode = 'matrix', countArg = '100000', seedArg = '1'] = process.argv;
if (!out) throw new Error('usage: gen_ts_r6_differential.ts <out> <matrix|random> [count] [seed]');
const base = JSON.parse(readFileSync(new URL('../../fixtures/decide_input.sample.json', import.meta.url), 'utf8'));
const S = 1_000_000;
const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x));

type Patch = { p: (string | number)[]; v?: unknown };
type Case = { name: string; patches: Patch[] };

const L0 = {
  root_caveats: base.grant.caveats,
  extra: [] as unknown[],
  action: base.action,
  subject: base.subject,
  env: base.env,
  plan: base.plan,
  node_id: base.pcactn.plan.node_id,
  cond_digest: base.pcactn.plan.conditions_digest,
  tool_binding: base.tool_binding,
};

function apply(patches: Patch[]): any {
  const L: any = clone(L0);
  for (const patch of patches) {
    const { p } = patch;
    let cur = L;
    for (let i = 0; i < p.length - 1; i++) cur = cur[p[i]!];
    const k = p[p.length - 1]!;
    if (!('v' in patch)) delete cur[k];
    else cur[k] = clone(patch.v);
  }
  return L;
}

function tsVerdict(L: any) {
  let incl = false;
  try {
    const cond = L.cond_digest === undefined || L.cond_digest === null ? conditionsDigest() : L.cond_digest;
    const h = hashCanonical(planLeaf(L.node_id, L.action, cond));
    incl = Array.isArray(L.plan) && L.plan.some((n: any) => {
      try {
        return hashCanonical(planNodeLeaf(n)) === h;
      } catch {
        return false;
      }
    });
  } catch {
    incl = false;
  }
  const a = L.action;
  const actionCtx: any = { action: { verb: a?.verb, resource: a?.resource, params: a?.params, reversibility_class: a?.reversibility_class } };
  if ('subject' in L) actionCtx.subject = L.subject;
  if ('env' in L) actionCtx.env = L.env;
  if (typeof L.tool_binding === 'string') actionCtx.toolBinding = L.tool_binding;
  const r = base.risk_inputs_scaled.map((x: number) => x / S);
  const d = decide({
    grant: { caveats: L.root_caveats } as any,
    chain: [{ caveats: L.root_caveats }, { caveats: [...L.root_caveats, ...L.extra] }] as any,
    chainVerified: true,
    now: base.now,
    action: actionCtx,
    plan: L.plan,
    nodeId: L.node_id,
    risk: { semanticDistance: r[0], reversibility: r[1], blastRadius: r[2], taint: r[3], confidence: r[4], age: r[5] },
    budget: { B: base.budget_scaled / S, tau: base.now },
    caveatContext: { recentActionTimes: base.recent_action_times },
  } as any);
  return { incl, release: d.releaseGuardianShare, admit: d.admit, allow: incl && d.admit };
}

// ---- paths into L ------------------------------------------------------------------------------------------------------
const ENV_IDX = (base.grant.caveats as any[]).findIndex((c) => c.type === 'envelope');
const E = ['root_caveats', ENV_IDX];
const envCaveats: any[] = base.grant.caveats[ENV_IDX].caveats;
const cavIdx = (t: string) => envCaveats.findIndex((c) => c.type === t);
const WHERE = [...E, 'predicates', 0, 'where'];
const nWhere = base.grant.caveats[ENV_IDX].predicates[0].where.length;
const NEW_COND = [...WHERE, nWhere];

// ---- value pools --------------------------------------------------------------------------------------------------------
const ABSENT = Symbol('absent');
const C_T = { field: 'action.params.acct', op: 'eq', value: 'acct_123' };
const C_F = { field: 'action.params.acct', op: 'eq', value: 'acct_999' };
const C_U = { field: 'action.params.nope', op: 'eq', value: 1 };
const TYPES: unknown[] = [
  ABSENT, null, 0, 1, 5, -1.5, 0.25, true, false, '', 'acct_123', 'acct_', 'action.params.acct', 'env.current_device',
  'action.params', 'reversible', 'irreversible', 'rate_limited', 'read', '*', [], ['acct_123'], ['read'], [1, 2], [null],
  [[1], 'a'], {}, { a: 1 }, C_T, C_F, [C_T], [C_F], [C_U], [C_T, C_F], [C_T, C_U],
];
const tname = (v: unknown) => (v === ABSENT ? 'absent' : JSON.stringify(v).slice(0, 40));
const set = (p: (string | number)[], v: unknown): Patch => (v === ABSENT ? { p } : { p, v });

const cases: Case[] = [];
const add = (name: string, patches: Patch[]) => cases.push({ name, patches });

const OPS = ['eq', 'ne', 'in', 'nin', 'lt', 'lte', 'gt', 'gte', 'prefix', 'exists', 'like', 'matches', 'is_a', 'member_of', 'bogus'];
const ENV_EXTRA = { groups: { 'dev-1': ['team'], team: 'fleet', __proto__x: 'y' }, tags: { type: 'acct::gold', tags: ['vip'] }, n: 3, s: 'acct_123' };

function matrix() {
  add('control', []);
  // every key of an appended where-condition x every type, on four base conditions
  const baseConds: [string, any][] = [
    ['eq', C_T],
    ['member_of', { field: 'env.current_device', op: 'member_of', value: 'fleet', collection: 'env.groups' }],
    ['like', { field: 'action.params.acct', op: 'like', value: 'acct_*' }],
    ['is_a', { field: 'env.tags', op: 'is_a', value: 'acct' }],
  ];
  for (const [bn, bc] of baseConds) {
    for (const key of ['field', 'op', 'value', 'ref', 'collection', 'all_of', 'any_of', 'not']) {
      for (const v of TYPES) {
        const c: any = clone(bc);
        if (v === ABSENT) delete c[key];
        else c[key] = v;
        add(`cond[${bn}].${key}=${tname(v)}`, [set(['env', 'groups'], ENV_EXTRA.groups), set(['env', 'tags'], ENV_EXTRA.tags), set(NEW_COND, c)]);
      }
    }
    for (const op of OPS) {
      for (const v of TYPES) {
        const c: any = { ...clone(bc), op };
        if (v === ABSENT) delete c.value;
        else c.value = v;
        add(`cond[${bn}].op=${op}.value=${tname(v)}`, [set(['env', 'groups'], ENV_EXTRA.groups), set(['env', 'tags'], ENV_EXTRA.tags), set(NEW_COND, c)]);
      }
    }
  }
  // refs: every op x a set of refs (string paths, unresolvable, params-rooted, non-string)
  for (const op of OPS) {
    for (const r of [ABSENT, null, 5, true, {}, [], 'env.s', 'action.params.acct', 'action.params.limit', 'env.n', 'env.nope', 'env.groups', 'subject.role', '']) {
      const c: any = { field: 'action.params.acct', op, value: 'acct_123', collection: 'env.groups' };
      if (r !== ABSENT) c.ref = r;
      add(`ref.op=${op}.ref=${tname(r)}`, [set(['env', 's'], ENV_EXTRA.s), set(['env', 'n'], ENV_EXTRA.n), set(['env', 'groups'], ENV_EXTRA.groups), set(NEW_COND, c)]);
    }
  }
  // the predicate itself
  for (const key of ['verb', 'resource', 'where']) {
    for (const v of [...TYPES, 're:/acct/[0-9]+/items', '/acct/*', '/acct/123/items', 're:(a+)+', ['list', 'read'], ['*']]) {
      add(`pred.${key}=${tname(v)}`, [set([...E, 'predicates', 0, key], v)]);
    }
  }
  // the envelope (readEnvelope / validateRiskPolicy)
  for (const key of ['goal_commit', 'predicates', 'caveats', 'agent_binding', 'risk_policy']) {
    for (const v of TYPES) add(`env.${key}=${tname(v)}`, [set([...E, key], v)]);
  }
  for (const key of ['weights', 'theta1', 'theta2', 'kappa', 'lambda', 'rho', 'bMax']) {
    for (const v of [ABSENT, null, -1, 0, 0.1, 0.25, 0.6, 1, 5, '1', true, [], {}]) add(`rp.${key}=${tname(v)}`, [set([...E, 'risk_policy', key], v)]);
  }
  for (const key of ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta']) {
    for (const v of [ABSENT, null, -0.1, 0, 0.05, 0.2, 1, '0.2', true, []]) add(`w.${key}=${tname(v)}`, [set([...E, 'risk_policy', 'weights', key], v)]);
  }
  // envelope caveats: every field of every built-in caveat type
  const fields: Record<string, string[]> = {
    expires: ['at', 'type'], not_before: ['at'], max_blast_radius: ['max'], reversibility_max: ['class'], delegation_depth: ['max'],
    predicates: ['allow'], tool_schema: ['tool', 'schema', 'schema_digest', 'signature_digest', 'binding_digest'],
  };
  for (const [t, fs] of Object.entries(fields)) {
    const i = cavIdx(t);
    for (const f of fs) {
      for (const v of [...TYPES, 1759999999999, 1760000000000, 1760000000001, 1e15]) {
        const ps: Patch[] = [set([...E, 'caveats', i, f], v)];
        if (t === 'tool_schema' && f === 'signature_digest') {
          // the TS binds String(signature_digest): recompute the binding digest so only the typing is under test
          const tc = envCaveats[i];
          ps.push(set([...E, 'caveats', i, 'binding_digest'], hashCanonical({ tool: tc.tool, signature_digest: String(v === ABSENT ? undefined : v), schema: tc.schema })));
          add(`cav.${t}.${f}=${tname(v)}+nobinding`, [...ps, { p: ['tool_binding'] }]);
        }
        add(`cav.${t}.${f}=${tname(v)}`, ps);
      }
    }
  }
  // delegated (extra) caveats of every type, with typed fields
  const extras: unknown[] = [
    { type: 'rate', max: 2, per_secs: 10 }, { type: 'rate', max: 1, per_secs: 10 }, { type: 'rate', max: '2', per_secs: 10 }, { type: 'rate', max: 2, per_secs: 0 },
    { type: 'rate', max: 2, per_secs: null }, { type: 'reversibility_max', class: 'reversible' }, { type: 'reversibility_max', class: ['reversible'] },
    { type: 'reversibility_max', class: null }, { type: 'delegation_depth', max: 1 }, { type: 'delegation_depth', max: 0 }, { type: 'delegation_depth', max: '1' },
    { type: 'max_blast_radius', max: 0.04 }, { type: 'max_blast_radius', max: 0.05 }, { type: 'expires', at: null }, { type: 'not_before', at: 0 },
    { type: 'predicates', allow: [{ verb: 'read' }] }, { type: 'predicates', allow: [] }, { type: 'predicates', allow: null }, { type: 'predicates', allow: {} },
    { type: 'predicates', allow: [{ verb: 'read', where: [{ not: C_F }] }] }, { type: 'predicates', allow: [{ verb: 'read', where: [{ ...C_T, not: C_T }] }] },
    { type: 'budget_alloc', limit: 1 }, { type: 'nope' }, { type: null }, {}, null, 5, 'expires', [],
  ];
  for (const x of extras) add(`extra=${tname(x)}`, [set(['extra', 0], x)]);
  // the action: params and reversibility_class typing, with and without the signed node synced
  for (const v of TYPES) {
    add(`action.params=${tname(v)}`, [set(['action', 'params'], v)]);
    add(`action.rc=${tname(v)}`, [set(['action', 'reversibility_class'], v)]);
    add(`action.rc=${tname(v)}+node`, [set(['action', 'reversibility_class'], v), set(['plan', 1, 'reversibility_class'], v)]);
    add(`node.rc=${tname(v)}+noactionrc`, [{ p: ['action', 'reversibility_class'] }, set(['plan', 1, 'reversibility_class'], v)]);
    add(`node.params_digest=${tname(v)}`, [set(['plan', 1, 'params_digest'], v)]);
    add(`action.params_digest=${tname(v)}`, [set(['action', 'params_digest'], v)]);
    add(`cond_digest=${tname(v)}`, [set(['cond_digest'], v)]);
    add(`subject=${tname(v)}`, [set(['subject'], v)]);
    add(`env=${tname(v)}`, [set(['env'], v)]);
  }
  // R6-ZK-03: decoy nodes before / after the signed node
  for (const [dc, rc] of [['reversible', 'irreversible'], ['irreversible', 'reversible'], ['reversible', null], ['reversible', ABSENT], ['rate_limited', 'reversible']] as const) {
    for (const first of [true, false]) {
      const decoy = { id: 'n1d', verb: 'read', resource: '/acct/123/items', reversibility_class: dc };
      const real: any = { id: 'n1', verb: 'read', resource: '/acct/123/items' };
      if (rc !== ABSENT) real.reversibility_class = rc;
      const plan = base.plan.filter((n: any) => n.id !== 'n1');
      if (first) plan.push(decoy, real);
      else plan.push(real, decoy);
      add(`decoy=${dc}.signed=${tname(rc)}.first=${first}`, [{ p: ['action', 'reversibility_class'] }, set(['plan'], plan)]);
    }
  }
  // R6-ZK-04: env / subject outside the strict profile (subject.role keeps the fixture's predicate true)
  const weird: unknown[] = [9007199254740993, 2 ** 53, -(2 ** 60), 1e-7, 0.1234567890123456, 1e21, 1.5e300, 5e-324, -0];
  for (const w of weird) {
    add(`env.weird=${w}`, [set(['env', 'w'], w)]);
    add(`subject.weird=${w}`, [set(['subject', 'w'], w)]);
    add(`env.weird.eq=${w}`, [set(['env', 'w'], w), set(NEW_COND, { field: 'env.w', op: 'eq', value: 9007199254740991 })]);
    add(`env.weird.lt=${w}`, [set(['env', 'w'], w), set(NEW_COND, { field: 'env.w', op: 'lt', value: 1 })]);
  }
  let deep: unknown = 1;
  for (let d = 1; d <= 64; d++) {
    deep = [deep];
    if (d % 8 === 0 || d === 33) add(`env.deep=${d}`, [set(['env', 'deep'], deep)]);
  }
  // the poisoned TS action object (undefined members): equality against the whole action root
  add('action-root-eq-without-rc', [{ p: ['action', 'reversibility_class'] }, set(NEW_COND, { field: 'action', op: 'ne', value: {} })]);
  add('action-root-eq-with-rc', [set(NEW_COND, { field: 'action', op: 'ne', value: {} })]);
  const wholeAction = { type: 'predicates', allow: [{ verb: 'read', where: [{ field: 'action', op: 'ne', value: {} }] }] };
  add('delegated-action-root-ne-without-rc', [{ p: ['action', 'reversibility_class'] }, set(['extra', 0], wholeAction)]);
  add('delegated-action-root-ne-with-rc', [set(['extra', 0], wholeAction)]);
  add('delegated-action-root-eq-self', [set(['extra', 0], { type: 'predicates', allow: [{ verb: 'read', where: [{ field: 'action', op: 'eq', value: base.action }] }] })]);
  // a grant is a wire document: in the TS it is strict-parsed by verifyPCActn before decide ever runs, so the matrix keeps
  // every number in the grant / action / plan inside the strict profile (2^53 itself is NOT a safe integer).
  add('action-root-exists', [{ p: ['action', 'reversibility_class'] }, set(NEW_COND, { field: 'action', op: 'exists' })]);
}

// ---- random mode --------------------------------------------------------------------------------------------------------
let seed = Number(seedArg) >>> 0;
const rnd = (): number => {
  seed = (seed + 0x6d2b79f5) >>> 0;
  let t = seed;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = <T,>(a: readonly T[]): T => a[Math.floor(rnd() * a.length)]!;
const chance = (p: number) => rnd() < p;

const FIELDS = ['action.params.acct', 'action.params.limit', 'action.params.tags', 'action.params.tags.0', 'action.params', 'action.verb', 'action.resource',
  'action.reversibility_class', 'action', 'subject.role', 'subject', 'env.current_device', 'env.groups', 'env.tags', 'env.n', 'env.s', 'env.x', 'env.w', 'env',
  'nope.x', '', 'action.params.__proto__', 'action.params.nope'];
const SCALARS: unknown[] = ['acct_123', 'acct_', 'acct_*', 'acct_?23', 'acct_\\*', 'acct', 'reader', 'admin', 'dev-1', 'team', 'fleet', 'vip', 'acct::gold', 'read',
  '/acct/123/items', 'acct_[0-9]+', '(a+)+', '😀', '', 0, 1, 3, 50, 100, -1, 0.5, true, false, null];
const val = (): unknown => {
  const r = rnd();
  if (r < 0.6) return pick(SCALARS);
  if (r < 0.8) return Array.from({ length: Math.floor(rnd() * 3) }, () => pick(SCALARS));
  if (r < 0.9) return { type: pick(['acct', 'acct::gold', 5]), tags: [pick(SCALARS)] };
  return {};
};
function cond(depth: number): unknown {
  const r = rnd();
  if (depth < 3 && r < 0.25) {
    const g = pick(['all_of', 'any_of', 'not']);
    const c: any = g === 'not' ? { not: cond(depth + 1) } : { [g]: Array.from({ length: Math.floor(rnd() * 3) }, () => cond(depth + 1)) };
    if (chance(0.2)) Object.assign(c, { field: pick(FIELDS), op: pick(OPS), value: val() }); // mixed leaf + group
    if (chance(0.05)) c[pick(['all_of', 'any_of'])] = pick([null, 5, [], {}]);
    return c;
  }
  if (r < 0.28) return pick([null, 5, 'x', [], [C_T]]);
  const c: any = {};
  if (!chance(0.03)) c.field = chance(0.03) ? pick([5, null, true]) : pick(FIELDS);
  if (!chance(0.03)) c.op = chance(0.03) ? pick([5, null]) : pick(OPS);
  if (chance(0.75)) c.value = val();
  if (chance(0.25)) c.ref = chance(0.3) ? pick([null, 5, true, {}, []]) : pick(FIELDS);
  if (chance(0.3)) c.collection = chance(0.2) ? pick([null, 5, '']) : pick(['env.groups', 'env.tags', 'env', 'subject']);
  return c;
}
const RC = [ABSENT, null, 'reversible', 'rate_limited', 'irreversible', 'costly', 5, ['reversible']];
function randomCase(i: number): Case {
  const ps: Patch[] = [];
  ps.push(set(['env'], {
    current_device: pick(['dev-1', 'team', 'x']), groups: { 'dev-1': ['team'], team: pick(['fleet', ['fleet', 'x'], 5]), x: 'dev-1' },
    tags: { type: pick(['acct', 'acct::gold', 'x']), tags: [pick(['vip', 'acct'])] }, n: pick([3, 9007199254740993, 1e-7, 0.1234567890123456, -0, 1e21]),
    s: pick(SCALARS), ...(chance(0.3) ? { w: pick([2 ** 53, 1.5e300, 5e-324]) } : {}),
  }));
  if (chance(0.1)) ps.push(chance(0.5) ? { p: ['env'] } : set(['env'], pick([null, [], 5])));
  if (chance(0.15)) ps.push(chance(0.5) ? { p: ['subject'] } : set(['subject'], pick([null, { role: 'admin' }, [], { role: 'reader', w: 1e-7 }])));
  const nw = Math.floor(rnd() * 4);
  for (let k = 0; k < nw; k++) ps.push(set([...WHERE, nWhere + k], cond(0)));
  if (chance(0.15)) ps.push(set([...E, 'predicates', 0, 'resource'], pick(['/acct/*', 're:/acct/[0-9]+/items', '*', ABSENT, null, 5, 're:/acct/(a+)+'])));
  if (chance(0.1)) ps.push(set([...E, 'predicates', 0, 'verb'], pick(['read', '*', ['list', 'read'], ['write'], null, 5])));
  if (chance(0.3)) {
    const n = 1 + Math.floor(rnd() * 3);
    for (let k = 0; k < n; k++) {
      ps.push(set(['extra', k], pick<unknown>([
        { type: 'predicates', allow: [{ verb: pick(['read', '*', 'x']), ...(chance(0.7) ? { where: [cond(0), cond(1)] } : {}) }] },
        { type: 'rate', max: pick([1, 2, '2']), per_secs: pick([1, 10, 0]) },
        { type: 'reversibility_max', class: pick(RC.filter((x) => x !== ABSENT)) },
        { type: 'delegation_depth', max: pick([0, 1, 2]) },
        { type: 'max_blast_radius', max: pick([0.01, 0.05, 1]) },
        { type: 'expires', at: pick([1760000000001, 1, null]) },
      ])));
    }
  }
  if (chance(0.2)) ps.push(set([...E, 'caveats', cavIdx('reversibility_max'), 'class'], pick(RC)));
  // action params / rc and the signed node
  if (chance(0.25)) ps.push(set(['action', 'params'], pick([ABSENT, null, [], ['acct_123'], 'acct_123', { acct: 'acct_123', limit: 50, tags: ['a'] }, { acct: 'acct_123' }, { acct: 'nope', limit: 50 }])));
  if (chance(0.3)) {
    const arc = pick(RC);
    ps.push(set(['action', 'reversibility_class'], arc));
    const nrc = chance(0.6) ? (arc === null ? ABSENT : arc) : pick(RC);
    if (chance(0.3)) {
      const decoy = { id: 'n1d', verb: 'read', resource: '/acct/123/items', reversibility_class: pick(['reversible', 'irreversible']) };
      const real: any = { id: 'n1', verb: 'read', resource: '/acct/123/items' };
      if (nrc !== ABSENT) real.reversibility_class = nrc;
      const plan = base.plan.filter((n: any) => n.id !== 'n1');
      if (chance(0.5)) plan.push(decoy, real);
      else plan.push(real, decoy);
      ps.push(set(['plan'], plan));
    } else ps.push(set(['plan', 1, 'reversibility_class'], nrc));
  }
  if (chance(0.05)) ps.push(set(['cond_digest'], pick([ABSENT, null, 5, conditionsDigest({ a: 1 })])));
  if (chance(0.05)) ps.push({ p: ['tool_binding'] });
  if (chance(0.05)) ps.push(set([...E, 'risk_policy', pick(['lambda', 'kappa', 'rho', 'theta2'])], pick([ABSENT, null, 0, -1, '1'])));
  return { name: `r${i}`, patches: ps };
}

if (mode === 'matrix') {
  matrix();
  const res = cases.map((c) => ({ ...c, ts: tsVerdict(apply(c.patches)) }));
  const allow = res.filter((r) => r.ts.allow).length;
  writeFileSync(out, JSON.stringify({ generator: 'gen_ts_r6_differential.ts matrix', count: res.length, ts_allow: allow, cases: res }));
  console.log(`matrix: ${res.length} cases, TS allow ${allow}`);
} else {
  const n = Number(countArg);
  const w = createWriteStream(out);
  let allow = 0;
  for (let i = 0; i < n; i++) {
    const c = randomCase(i);
    const ts = tsVerdict(apply(c.patches));
    if (ts.allow) allow++;
    w.write(JSON.stringify({ ...c, ts }) + '\n');
  }
  w.end();
  console.log(`random: ${n} cases (seed ${seedArg}), TS allow ${allow}`);
}
