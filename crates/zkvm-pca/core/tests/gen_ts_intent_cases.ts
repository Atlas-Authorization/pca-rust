// PCA 0.4.2 Intent Layer M2: verdicts of the TypeScript reference (packages/pca/src/intent-binding.ts) that the guest's
// `intent` module must reproduce. Output of the TS reference; NOT a standard vector (the conformance `intent-*` vectors are
// generated at code freeze by packages/pca/scripts/gen-conformance-intent.mjs).
//   (a) wire:    validateIntentWire(slot) === null
//   (b) commit:  intentGoalCommit({ref, map_digest, goal_salt})
//   (c) binding: decideIntentBinding(slot, grant, policy).status for slots, root grants and policies
//     packages/pca/node_modules/.bin/tsx sdks/zkvm-pca/core/tests/gen_ts_intent_cases.ts <out.json>
import { writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { validateIntentWire, intentGoalCommit, decideIntentBinding } from '../../../../packages/pca/src/intent-binding';

const out = process.argv[2];
if (!out) throw new Error('usage: gen_ts_intent_cases.ts <out.json>');
const b64u = (b: Buffer) => b.toString('base64url');
const d32 = (label: string) => b64u(createHash('sha256').update(label).digest());
const REF = d32('intent-ref'), MAP = d32('intent-map'), REF2 = d32('other-ref');
const valid = { ref: REF, map_digest: MAP, goal_salt: 'salt-01', fidelity_ppm: 900_000, residual_risk_ppm: 2_500 };
const without = (k: string) => Object.fromEntries(Object.entries(valid).filter(([kk]) => kk !== k));
const tail = (s: string) => {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  return s.slice(0, -1) + A[A.indexOf(s.at(-1)!) ^ 1];
};

// (a) wire
const wireSlots: unknown[] = [
  valid,
  { ...valid, fidelity_ppm: 0, residual_risk_ppm: 0 },
  { ...valid, fidelity_ppm: 1_000_000 },
  { ...valid, residual_risk_ppm: 5_000_000 },
  { ...valid, residual_risk_ppm: 9007199254740991 },
  { ...valid, goal_salt: 's'.repeat(128) },
  { ...valid, goal_salt: 'é'.repeat(64) }, // 128 UTF-8 bytes
  { ...valid, goal_salt: 'é'.repeat(65) }, // 130 UTF-8 bytes
  { ...valid, goal_salt: 's'.repeat(129) },
  { ...valid, goal_salt: '' },
  { ...valid, goal_salt: 5 },
  { ...valid, fidelity_ppm: 1_000_001 },
  { ...valid, fidelity_ppm: -1 },
  { ...valid, fidelity_ppm: 1.5 },
  { ...valid, fidelity_ppm: '1' },
  { ...valid, fidelity_ppm: null },
  { ...valid, residual_risk_ppm: -1 },
  { ...valid, residual_risk_ppm: 9007199254740992 },
  { ...valid, residual_risk_ppm: 0.5 },
  { ...valid, ref: d32('x').slice(0, 42) },
  { ...valid, ref: tail(REF) },
  { ...valid, ref: b64u(Buffer.alloc(31)) },
  { ...valid, ref: 7 },
  { ...valid, map_digest: tail(MAP) },
  { ...valid, map_digest: REF + '=' },
  { ...valid, extra: 1 },
  ...['ref', 'map_digest', 'goal_salt', 'fidelity_ppm', 'residual_risk_ppm'].map(without),
  [],
  'x',
  null,
  7,
];
const wire = wireSlots.map((slot) => ({ slot, ok: validateIntentWire(slot) === null }));

// (b) commit
const commitInputs = [
  { ref: REF, map_digest: MAP, goal_salt: 'salt-01' },
  { ref: REF2, map_digest: MAP, goal_salt: 'ünïcødé ✓ salt' },
  { ref: REF, map_digest: REF2, goal_salt: 's'.repeat(128) },
];
const commit = commitInputs.map((i) => ({ ...i, commit: intentGoalCommit(i) }));

// (c) binding: slot x grant x policy
const C = intentGoalCommit(valid);
const env = (gc: unknown) => ({ type: 'envelope', goal_commit: gc, predicates: [], caveats: [] });
const grants: Record<string, unknown> = {
  bound: { caveats: [env(C)] },
  bound_after_other_caveats: { caveats: [{ type: 'expires', at: 1 }, 'not-an-object', env(C)] },
  first_envelope_wins_unbound: { caveats: [env(d32('other-commit')), env(C)] },
  first_envelope_wins_bound: { caveats: [env(C), env(d32('other-commit'))] },
  unbound: { caveats: [env(d32('other-commit'))] },
  goal_commit_not_string: { caveats: [env(7)] },
  no_envelope: { caveats: [{ type: 'expires', at: 1 }] },
  caveats_not_array: { caveats: {} },
};
const slots: Record<string, unknown> = {
  absent: undefined,
  valid,
  wrong_salt: { ...valid, goal_salt: 'salt-02' },
  wrong_ref: { ...valid, ref: REF2 },
  low_fidelity: { ...valid, fidelity_ppm: 100 },
};
const policies: Record<string, { require?: boolean; min_fidelity_ppm?: number; max_residual_risk_ppm?: number } | undefined> = {
  none: undefined,
  inactive: {},
  require: { require: true },
  min_fid_900000: { min_fidelity_ppm: 900_000 },
  min_fid_900001: { min_fidelity_ppm: 900_001 },
  max_risk_2500: { max_residual_risk_ppm: 2_500 },
  max_risk_2499: { max_residual_risk_ppm: 2_499 },
  both_ok: { min_fidelity_ppm: 0, max_residual_risk_ppm: 9007199254740991 },
  misconfigured: { min_fidelity_ppm: 9007199254740992 },
};
const binding: unknown[] = [];
for (const [gn, g] of Object.entries(grants))
  for (const [sn, s] of Object.entries(slots))
    for (const [pn, p] of Object.entries(policies))
      binding.push({ grant: gn, slot: sn, policy: pn, status: decideIntentBinding(s as never, g, p).status });

writeFileSync(out, JSON.stringify({ about: 'TS intent-binding.ts verdicts (gen_ts_intent_cases.ts)', grants, slots: Object.fromEntries(Object.entries(slots).filter(([, v]) => v !== undefined)), policies, wire, commit, binding }, null, 1) + '\n');
console.log(`wire ${wire.length} (${wire.filter((w) => w.ok).length} ok), commit ${commit.length}, binding ${binding.length}`);
