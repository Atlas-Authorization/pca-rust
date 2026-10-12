// Generates fixtures/differential_corpus.json: a seeded corpus of random + boundary witnesses with
// (a) an EXACT integer (BigInt) reference decision and (b) the decision of the TypeScript float risk
// model (@atlasauth/pca riskScore / admit). Copied to the sibling crates' fixtures by this script.
//   node sdks/stark-pca/tests/gen_differential_corpus.mjs     (after `pnpm --filter @atlasauth/pca build`)
// The JSON is output of the reference implementations; it is not an official standard vector.
import { createRequire } from 'node:module';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const { riskScore, admit, requiredThreshold, DEFAULT_RISK_POLICY } = require(join(here, '../../../packages/pca/dist/index.js'));

const S = 1_000_000n;
const policy = DEFAULT_RISK_POLICY;
const W = policy.weights;
const q = (x) => BigInt(Math.round(x * 1e6));
const w = [W.alpha, W.beta, W.gamma, W.delta, W.epsilon, W.zeta].map(q);
const THETA1 = q(policy.theta1);
const KAPPA = BigInt(policy.kappa);
const BMAX = q(policy.bMax);
const INV = [false, true, false, false, true, false];

// mulberry32, seeded: the corpus is reproducible
let seed = 0x5eed_c0de;
const rnd = () => {
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const ri = (lo, hi) => lo + BigInt(Math.floor(rnd() * Number(hi - lo + 1n)));

const rraw = (x) => x.reduce((a, xi, i) => a + w[i] * (INV[i] ? S - xi : xi), 0n);
const exactAllow = (x, B, pm, co) => {
  if (x.some((v) => v < 0n || v > S)) return false;
  if (B < 0n || B > BMAX) return false;
  const r = rraw(x);
  return r <= THETA1 * S && B * S >= KAPPA * r && pm && co;
};

const cases = [];
const add = (cls, x, B, pm, co, inDomain = true) => {
  const xs = x.map((v) => v);
  const tsIn = {
    semanticDistance: Number(xs[0]) / 1e6, reversibility: Number(xs[1]) / 1e6, blastRadius: Number(xs[2]) / 1e6,
    taint: Number(xs[3]) / 1e6, confidence: Number(xs[4]) / 1e6, age: Number(xs[5]) / 1e6,
  };
  const r = riskScore(tsIn, W);
  const a = admit(r, { B: Number(B) / 1e6, tau: 0 }, policy);
  const exact = exactAllow(xs, B, pm, co);
  const raw = rraw(xs);
  cases.push({
    class: cls,
    in_domain: inDomain,
    inputs_scaled: xs.map(String),
    budget_scaled: String(B),
    predicate_match: pm,
    caveats_ok: co,
    exact_allow: exact,
    exact_rraw: String(raw),
    ts_risk: r,
    ts_required_tier: requiredThreshold(r, policy).t,
    ts_allow: Boolean(a.admit && pm && co),
  });
};

const randX = (scale) => {
  // risk-increasing inputs shrunk by `scale` (so a good share of witnesses land under theta1)
  return [0, 1, 2, 3, 4, 5].map((i) => {
    const u = BigInt(Math.floor(rnd() * 1_000_001));
    if (INV[i]) return S - (u * BigInt(Math.floor(scale * 1000))) / 1000n; // inverted: high value = low risk
    return (u * BigInt(Math.floor(scale * 1000))) / 1000n;
  });
};
const flags = () => [rnd() < 0.93, rnd() < 0.93];

// 1. random in-domain (1200)
for (let i = 0; i < 1200; i++) {
  const x = randX(rnd() * 0.9 + 0.05);
  const [pm, co] = flags();
  const r = rraw(x);
  const need = (r + S - 1n) / S; // minimal budget covering the cost
  const B = rnd() < 0.5 ? ri(need, BMAX) : ri(0n, BMAX);
  add('random', x, B > BMAX ? BMAX : B, pm, co);
}
// 2. theta1 boundary (600): construct r_raw = theta1*S^2 exactly (+/- one weight step) by solving one input
for (let i = 0; i < 600; i++) {
  const x = randX(0.3);
  const k = Number(ri(0n, 5n));
  const T = THETA1 * S;
  const rest = rraw(x.map((v, j) => (j === k ? (INV[k] ? S : 0n) : v))) - (INV[k] ? 0n : 0n);
  // solve w[k]*term = T - rest + delta*w[k]
  const delta = BigInt([0, 0, 0, 1, -1, 2, -2][Number(ri(0n, 6n))]);
  const need = T - (rraw(x) - w[k] * (INV[k] ? S - x[k] : x[k])) + delta * w[k];
  if (w[k] === 0n || need % w[k] !== 0n) { i--; continue; }
  const term = need / w[k];
  const xk = INV[k] ? S - term : term;
  if (xk < 0n || xk > S) { i--; continue; }
  x[k] = xk;
  void rest;
  add(`theta1_boundary(delta=${delta})`, x, BMAX, true, true);
}
// 3. budget boundary (400): B = ceil(kappa*r/S) and one below
for (let i = 0; i < 400; i++) {
  const x = randX(0.25);
  const r = rraw(x);
  if (r > THETA1 * S) { i--; continue; }
  const need = (KAPPA * r + S - 1n) / S;
  const B = need - BigInt(rnd() < 0.5 ? 0 : 1);
  add(`budget_boundary(${need - B === 0n ? 'exact' : 'minus1'})`, x, B < 0n ? 0n : B, true, true);
}
// 4. extremes (corners of the box) (all 2^6 corners x a few budgets)
for (let m = 0; m < 64; m++) {
  const x = [0, 1, 2, 3, 4, 5].map((i) => (m >> i) & 1 ? S : 0n);
  for (const B of [0n, BMAX]) add('corner', x, B, true, true);
}
// 5. out-of-domain (200): NOT part of the equality claim; STARK must deny, TS/zkVM clamp
const ood = [];
for (let i = 0; i < 200; i++) {
  const x = randX(0.2);
  const k = Number(ri(0n, 5n));
  x[k] = rnd() < 0.5 ? S + ri(1n, 5000n) : 0n;
  let B = ri(0n, BMAX);
  let outB = false;
  if (x[k] === 0n) { B = BMAX + ri(1n, 1000n); outB = true; }
  ood.push({ x, B, outB });
}
for (const o of ood) add(o.outB ? 'budget_above_bmax' : 'input_above_S', o.x, o.B, true, true, false);

const inDomain = cases.filter((c) => c.in_domain).length;
const out = {
  description:
    'Seeded differential corpus. exact_allow is an exact BigInt evaluation of the release relation; ts_* is the TypeScript float reference (@atlasauth/pca riskScore/admit). Generated by tests/gen_differential_corpus.mjs; not an official standard vector.',
  scale: Number(S),
  policy: { weights_scaled: w.map(Number), theta1_scaled: Number(THETA1), kappa: Number(KAPPA), bmax_scaled: Number(BMAX) },
  in_domain_cases: inDomain,
  cases,
};
const json = JSON.stringify(out) + '\n';
for (const d of ['../fixtures', '../../stark-pca-plonky3/fixtures', '../../zkvm-pca/fixtures']) {
  mkdirSync(join(here, d), { recursive: true });
  writeFileSync(join(here, d, 'differential_corpus.json'), json);
}
const nAllow = cases.filter((c) => c.in_domain && c.exact_allow).length;
const tsDis = cases.filter((c) => c.in_domain && c.exact_allow !== c.ts_allow);
console.log(`wrote ${cases.length} cases (${inDomain} in-domain, ${nAllow} exact-allow); TS-float disagreements with exact: ${tsDis.length}`);
