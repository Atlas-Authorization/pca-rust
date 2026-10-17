// V5 layers (decideLayerCeilings / decideLayers) verdicts of the TypeScript reference (packages/pca/src/intent-layers.ts):
// ceiling order, absent vs null, closed and typed layers (0cc44911), denied / task, plus a seeded random sweep. The guest
// (intent_layers.rs) must agree on every case.
//   packages/pca/node_modules/.bin/tsx sdks/zkvm-pca/core/tests/gen_ts_v2_layers.ts sdks/zkvm-pca/fixtures/ts_v2_layers.json
import { writeFileSync } from 'node:fs';
import { decideLayerCeilings, decideLayers } from '../../../../packages/pca/src/intent-layers';

const out = process.argv[2];
if (!out) throw new Error('usage: gen_ts_v2_layers.ts <out.json>');
const cap = (max: number) => ({ predicates: [{ verb: 'air.book', where: [{ field: 'action.params.total', op: 'lte', value: max }] }] });
const eq = (v: number) => ({ predicates: [{ verb: 'air.book', where: [{ field: 'action.params.total', op: 'eq', value: v }] }] });
const world = { predicates: [{ verb: 'air.book', where: [{ field: 'env.world.fraud_flag', op: 'eq', value: 0 }] }] };
const root = (total: number, env?: Record<string, unknown>) => ({ action: { verb: 'air.book', resource: 'r', params: { total } }, env: env ?? {} });

const ceil: [string, unknown, unknown][] = [
  ['empty', {}, root(10_000)],
  ['org-deny', { org: cap(500), site: cap(400), std: cap(300) }, root(600)],
  ['site-deny', { org: cap(500), site: cap(400), std: cap(300) }, root(450)],
  ['std-deny', { std: cap(300) }, root(350)],
  ['all-pass', { org: cap(500), site: cap(400), std: cap(300) }, root(100)],
  ['world-ok', { org: world }, root(1, { world: { fraud_flag: 0 } })],
  ['world-bad', { org: world }, root(1, { world: { fraud_flag: 1 } })],
  ['world-missing', { org: world }, root(1)],
  ['org-empty-obj', { org: {} }, root(1)],
  ['org-empty-preds', { org: { predicates: [] } }, root(1)],
  ['org-null', { org: null }, root(1)],
  ['site-preds-null', { site: { predicates: null } }, root(1)],
  ['std-array', { std: [] }, root(1)],
  ['std-string', { std: 'x' }, root(1)],
  ['layers-null', null, root(1)],
  ['layers-array', [], root(1)],
  ['layers-string', 'org', root(1)],
  ['unknown-member', { org: cap(500), extra: cap(1) }, root(1)],
  ['unknown-member-only', { task: [] }, root(1)],
  ['layer-extra-member', { site: { ...cap(500), note: 'x' } }, root(1)],
  ['site-null-after-org-pass', { org: cap(500), site: null }, root(1)],
  ['org-deny-before-site-null', { org: cap(5), site: null }, root(10)],
];
const grants: [string, unknown, unknown][] = [
  ['g-ceiling', { org: cap(500), task: [cap(100), cap(200)], denied: [eq(150)] }, root(600)],
  ['g-denied', { org: cap(500), task: [cap(100), cap(200)], denied: [eq(150)] }, root(150)],
  ['g-admit0', { org: cap(500), task: [cap(100), cap(200)], denied: [eq(150)] }, root(90)],
  ['g-admit1', { org: cap(500), task: [cap(100), cap(200)], denied: [eq(150)] }, root(190)],
  ['g-required', { org: cap(500), task: [cap(100), cap(200)], denied: [eq(150)] }, root(300)],
  ['g-denied-null', { task: [cap(100)], denied: null }, root(50)],
  ['g-task-null', { task: null }, root(50)],
  ['g-task-absent', {}, root(50)],
  ['g-task-entry-null', { task: [null, cap(100)] }, root(50)],
  ['g-ok', { task: [cap(100)] }, root(50)],
  ['g-task-empty', { task: [] }, root(50)],
  ['g-unknown', { task: [cap(100)], extra: [] }, root(50)],
  ['g-task-entry-extra', { task: [{ ...cap(100), caveats: [] }] }, root(50)],
  ['g-denied-entry-extra', { task: [cap(100)], denied: [{ ...eq(1), x: 1 }] }, root(50)],
  ['g-not-object', [], root(50)],
  ['g-null', null, root(50)],
  ['g-site-null', { site: null, task: [cap(100)] }, root(50)],
];
// seeded random sweep (xorshift32)
let s = 0x9e3779b9;
const rnd = (n: number) => {
  s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0;
  return s % n;
};
for (let i = 0; i < 300; i++) {
  const g: Record<string, unknown> = {};
  for (const k of ['org', 'site', 'std']) {
    const r = rnd(6);
    if (r === 0) g[k] = null;
    else if (r < 3) g[k] = cap(rnd(1000));
  }
  const t = rnd(5);
  g.task = Array.from({ length: t }, () => (rnd(15) === 0 ? null : cap(rnd(1000))));
  if (rnd(3) === 0) g.denied = Array.from({ length: rnd(3) }, () => eq(rnd(1000)));
  const total = rnd(1000);
  grants.push([`rand-${i}`, g, root(total)]);
  const { task: _t, denied: _d, ...c } = g;
  ceil.push([`rand-${i}`, c, root(total)]);
}
const cases = [
  ...ceil.map(([name, layers, ctx]) => {
    const d = decideLayerCeilings(layers as never, ctx as never);
    return { kind: 'ceilings', name, layers, root: ctx, ok: d.status === 'pass', ...(d.status === 'fail' ? { layer: d.layer } : {}) };
  }),
  ...grants.map(([name, grant, ctx]) => {
    const d = decideLayers(grant as never, ctx as never);
    return { kind: 'layers', name, grant, root: ctx, decision: d.decision, ...('layer' in d ? { layer: d.layer } : {}), ...('by' in d ? { by: d.by } : {}) };
  }),
];
writeFileSync(out, JSON.stringify({ about: 'decideLayerCeilings / decideLayers verdicts (gen_ts_v2_layers.ts)', cases }, null, 1) + '\n');
console.log(`layers cases ${cases.length}`);
