// Regenerates goal-commit-vectors.json (goal binding v3: goal_commit = H(goal_digest || policy_digest)).
// Independent of the TypeScript code: it re-implements the 3-member canonical object and sha256 directly, so the committed
// file is an independent reference that goal-commit-vectors.test.ts checks the real implementation against.
// Usage: node conformance/gen-goal-commit.mjs > conformance/goal-commit-vectors.json
import { createHash } from 'node:crypto';

const b64u = (b) => Buffer.from(b).toString('base64url');
const dig = (label) => b64u(createHash('sha256').update(`g2d-t3-vector:${label}`).digest());
const DOMAIN = 'atlas-pca/goal/v1\0';
const commitOf = (goal, salt) => {
  const o = { d: DOMAIN, goal, salt };
  const s = '{' + ['d', 'goal', 'salt'].map((k) => `${JSON.stringify(k)}:${JSON.stringify(o[k])}`).join(',') + '}';
  return createHash('sha256').update(Buffer.from(s, 'utf8')).digest('base64url');
};
const v3goal = (g, p) => `pca-intent:v3:${g}:${p}`;
const GD1 = dig('goal-1');
const GD2 = dig('goal-2');
const PD1 = dig('policy-1');
const PD2 = dig('policy-2');
const REF = dig('intent-ref');
const MAP = dig('intent-map');
const SESSION = dig('session');

const commit = [];
const add = (name, g, p, salt) => commit.push({ name, goal_digest: g, policy_digest: p, salt, goal: v3goal(g, p), commit: commitOf(v3goal(g, p), salt) });
add('basic', GD1, PD1, 'salt-1');
add('digests-swapped', PD1, GD1, 'salt-1');
add('other-goal', GD2, PD1, 'salt-1');
add('other-policy', GD1, PD2, 'salt-1');
add('other-salt', GD1, PD1, 'salt-2');
add('unicode-salt', GD1, PD1, 'sälz-✓');
add('max-salt-128-bytes', GD1, PD1, 'x'.repeat(128));
const invalid = [
  { name: 'goal-digest-not-canonical', goal_digest: 'AAAA', policy_digest: PD1 },
  { name: 'policy-digest-31-bytes', goal_digest: GD1, policy_digest: b64u(Buffer.alloc(31, 1)) },
  { name: 'goal-digest-padded', goal_digest: GD1 + '=', policy_digest: PD1 },
  { name: 'policy-digest-empty', goal_digest: GD1, policy_digest: '' },
];

const intent = (salt) => ({ ref: REF, map_digest: MAP, goal_salt: salt, fidelity_ppm: 900000, residual_risk_ppm: 10 });
const v1 = (salt) => commitOf(`pca-intent:v1:${REF}:${MAP}`, salt);
const v2 = (salt) => commitOf(`pca-intent:v2:${SESSION}:${MAP}`, salt);
const A1 = { goal_digest: GD1, policy_digest: PD1 };
const binding = [];
const b = (name, grant_commit, i, policy, expect, session) => binding.push({ name, grant_commit, intent: i, policy, ...(session ? { session } : {}), expect });
b('v3-opens', commitOf(v3goal(GD1, PD1), 's'), intent('s'), { approved_goal: A1 }, 'pass');
b('v3-wrong-policy-digest', commitOf(v3goal(GD1, PD1), 's'), intent('s'), { approved_goal: { goal_digest: GD1, policy_digest: PD2 } }, 'fail');
b('v3-wrong-goal-digest', commitOf(v3goal(GD1, PD1), 's'), intent('s'), { approved_goal: { goal_digest: GD2, policy_digest: PD1 } }, 'fail');
b('v3-digests-swapped', commitOf(v3goal(PD1, GD1), 's'), intent('s'), { approved_goal: A1 }, 'fail');
b('v3-wrong-salt', commitOf(v3goal(GD1, PD1), 's'), intent('t'), { approved_goal: A1 }, 'fail');
b('v1-grant-under-v3-policy', v1('s'), intent('s'), { approved_goal: A1 }, 'fail');
b('v2-grant-under-v3-policy', v2('s'), intent('s'), { approved_goal: A1 }, 'fail', SESSION);
b('v3-grant-under-v1-verifier', commitOf(v3goal(GD1, PD1), 's'), intent('s'), { require: true }, 'fail');
b('v1-still-opens', v1('s'), intent('s'), { require: true }, 'pass');
b('v2-still-opens', v2('s'), intent('s'), { require: true }, 'pass', SESSION);
b('v3-absent-intent', commitOf(v3goal(GD1, PD1), 's'), null, { approved_goal: A1 }, 'fail');
b('v3-no-envelope-commit', null, intent('s'), { approved_goal: A1 }, 'fail');
b('v3-misconfigured-short-digest', commitOf(v3goal(GD1, PD1), 's'), intent('s'), { approved_goal: { goal_digest: 'AAAA', policy_digest: PD1 } }, 'fail');
b('v3-misconfigured-extra-member', commitOf(v3goal(GD1, PD1), 's'), intent('s'), { approved_goal: { ...A1, extra: 1 } }, 'fail');
b('v3-with-floor-met', commitOf(v3goal(GD1, PD1), 's'), intent('s'), { approved_goal: A1, min_fidelity_ppm: 900000 }, 'pass');
b('v3-with-floor-missed', commitOf(v3goal(GD1, PD1), 's'), intent('s'), { approved_goal: A1, min_fidelity_ppm: 900001 }, 'fail');

const doc = {
  format: 1,
  suite: 'goal-commit',
  layer: 'proof',
  description:
    'Goal binding v3: the root grant goal commitment is H({d: "atlas-pca/goal/v1\\u0000", goal: "pca-intent:v3:" || goal_digest || ":" || policy_digest, salt}) with both digests canonical base64url (32 bytes). `commit` vectors pin the function; `invalid` digests must be refused; `binding` vectors pin the intent check when the verifier is configured with approved_goal (v3) or not (v1/v2 retained). Verifiers must reproduce `expect` (pass or fail); reason text is not part of the contract.',
  domain: DOMAIN,
  goal_prefix: 'pca-intent:v3:',
  commit,
  invalid,
  binding,
};
process.stdout.write(`${JSON.stringify(doc, null, 2)}\n`);
