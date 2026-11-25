//! Property-based machine-checking of the core safety invariants (attenuation monotonicity, budget soundness, fail-closed behaviour,
//! determinism) against the real core, plus the generators they draw from. The generators run over a small deterministic SplitMix64
//! stream (the reference draws from a property-testing library with its own generator and shrinking; neither is reproduced, so a given
//! seed explores different cases than the reference does, but every case family, range and mutation is the reference's). A property is a
//! `fn(&mut InvRng) -> bool`; [`check_invariants`] runs each one `num_runs` times from a fixed seed and reports a failing case's seed so
//! it can be replayed with [`replay_invariant`].
use crate::agent::{delegate, KeyPair, Suite};
use crate::forbid::{decide_clauses, when_matches, ClauseOptions};
use crate::invariants::{build_chain, key_pair_from_seed, DEFAULT_NUM_RUNS, INVARIANT_NAMES};
use crate::predicates::{evaluate_condition_tri, evaluate_predicates, Ctx, Tri};
use crate::risk::{admit, cost, required_threshold, risk_score, safety_bound, validate_risk_policy, RiskInputs, RiskPolicy, RiskWeights, TrustBudget};
use crate::{allocations_monotone, evaluate_caveats, hash_canonical, verify_chain};
use serde_json::{json, Map, Value};

/// A deterministic SplitMix64 generator: the same seed always yields the same stream.
#[derive(Clone, Debug)]
pub struct InvRng {
    s: u64,
}

impl InvRng {
    pub fn new(seed: u64) -> InvRng {
        InvRng { s: seed }
    }

    /// The next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.s = self.s.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.s;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in [0, 1).
    pub fn float(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform in [lo, hi] inclusive.
    pub fn int(&mut self, lo: i64, hi: i64) -> i64 {
        if hi <= lo {
            return lo;
        }
        lo + (self.next_u64() % ((hi - lo + 1) as u64)) as i64
    }

    /// A fair coin.
    pub fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    /// A double in [lo, hi], the endpoints included on purpose.
    pub fn dbl(&mut self, lo: f64, hi: f64) -> f64 {
        let x = self.float();
        if x < 0.08 {
            return lo;
        }
        if x < 0.16 {
            return hi;
        }
        lo + (hi - lo) * self.float()
    }
}

fn pick<T: Clone>(r: &mut InvRng, xs: &[T]) -> T {
    xs[r.int(0, xs.len() as i64 - 1) as usize].clone()
}

fn string(r: &mut InvRng, lo: i64, hi: i64) -> String {
    let n = r.int(lo, hi);
    (0..n).map(|_| r.int(0x20, 0x7e) as u8 as char).collect()
}

fn array<T>(r: &mut InvRng, mut gen: impl FnMut(&mut InvRng) -> T, lo: i64, hi: i64) -> Vec<T> {
    let n = r.int(lo, hi);
    (0..n).map(|_| gen(r)).collect()
}

/// A JSON integer.
fn jint(i: i64) -> Value {
    json!(i)
}

/// 32 random bytes as a base64url Ed25519 secret seed.
pub fn arb_seed32(r: &mut InvRng) -> String {
    let b: Vec<u8> = (0..32).map(|_| r.next_u64() as u8).collect();
    crate::b64_encode(&b)
}

const VERBS: [&str; 6] = ["read", "write", "delete", "transfer", "list", "admin"];
const RESOURCES: [&str; 6] = ["/acct/a", "/acct/b", "/docs/1", "/docs/2", "/x/y", "/"];
const LEAF_OPS: [&str; 10] = ["eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists"];
const FIELDS: [&str; 6] = ["subject.role", "subject.tier", "env.ip", "action.verb", "action.resource", "action.params.amount"];

fn arb_verb(r: &mut InvRng) -> String {
    pick(r, &VERBS).to_string()
}

fn arb_resource(r: &mut InvRng) -> String {
    if r.float() < 0.5 {
        pick(r, &RESOURCES).to_string()
    } else {
        string(r, 0, 10)
    }
}

/// A random leaf condition `{field, op, value}`.
pub fn arb_leaf_condition(r: &mut InvRng) -> Value {
    let v = match r.int(0, 3) {
        0 => json!(string(r, 0, 10)),
        1 => jint(r.int(-10, 10)),
        2 => json!(r.bool()),
        _ => json!(array(r, |r| string(r, 0, 10), 0, 3)),
    };
    json!({ "field": pick(r, &FIELDS), "op": pick(r, &LEAF_OPS), "value": v })
}

/// A random predicate `{verb, resource?, where?}`.
pub fn arb_predicate(r: &mut InvRng) -> Value {
    let verb = match r.int(0, 2) {
        0 => json!(arb_verb(r)),
        1 => json!(array(r, arb_verb, 1, 3)),
        _ => json!("*"),
    };
    let mut p = Map::new();
    p.insert("verb".into(), verb);
    match r.int(0, 3) {
        1 => {
            p.insert("resource".into(), json!("*"));
        }
        2 => {
            p.insert("resource".into(), json!(pick(r, &["/acct/*", "/docs/*"])));
        }
        3 => {
            p.insert("resource".into(), json!(arb_resource(r)));
        }
        _ => {}
    }
    if r.float() < 0.5 {
        p.insert("where".into(), Value::Array(array(r, arb_leaf_condition, 0, 2)));
    }
    Value::Object(p)
}

/// 1-4 random predicates.
pub fn arb_predicate_list(r: &mut InvRng) -> Vec<Value> {
    array(r, arb_predicate, 1, 4)
}

/// A random `{action, subject?, env?}` context.
pub fn arb_action_context(r: &mut InvRng) -> Value {
    let mut action = Map::new();
    action.insert("verb".into(), json!(arb_verb(r)));
    action.insert("resource".into(), json!(arb_resource(r)));
    if r.float() < 0.5 {
        let mut params = Map::new();
        let mut keys = vec!["amount", "target", "reason"];
        let mut i = r.int(0, 3);
        while i > 0 && !keys.is_empty() {
            let j = r.int(0, keys.len() as i64 - 1) as usize;
            let k = keys.remove(j);
            let v = match r.int(0, 2) {
                0 => json!(string(r, 0, 10)),
                1 => jint(r.int(-5, 100)),
                _ => json!(r.bool()),
            };
            params.insert(k.into(), v);
            i -= 1;
        }
        action.insert("params".into(), Value::Object(params));
    }
    let mut ctx = Map::new();
    ctx.insert("action".into(), Value::Object(action));
    let role = pick(r, &["admin", "user", "guest"]);
    let tier = r.int(0, 5);
    let ip = string(r, 0, 10);
    if r.float() < 0.5 {
        ctx.insert("subject".into(), json!({ "role": role, "tier": tier }));
    }
    if r.float() < 0.5 {
        ctx.insert("env".into(), json!({ "ip": ip }));
    }
    Value::Object(ctx)
}

/// A random caveat evaluation context (snake_case keys).
pub fn arb_caveat_context(r: &mut InvRng) -> Value {
    let mut ctx = Map::new();
    ctx.insert("now".into(), jint(r.int(0, 10_000_000)));
    if r.float() < 0.5 {
        ctx.insert("blast_radius".into(), json!(r.dbl(0.0, 1.0)));
    }
    if r.float() < 0.5 {
        ctx.insert("reversibility_class".into(), json!(pick(r, &["reversible", "rate_limited", "irreversible", "teleport"])));
    }
    if r.float() < 0.5 {
        ctx.insert("delegation_depth".into(), jint(r.int(0, 20)));
    }
    if r.float() < 0.5 {
        ctx.insert("recent_action_times".into(), Value::Array(array(r, |r| jint(r.int(0, 10_000_000)), 0, 6)));
    }
    Value::Object(ctx)
}

/// An action context and a caveat context together: one point at which to probe a chain's authority.
#[derive(Clone, Debug)]
pub struct EvalPoint {
    pub action: Value,
    pub cav_ctx: Value,
}

pub fn arb_eval_point(r: &mut InvRng) -> EvalPoint {
    EvalPoint { action: arb_action_context(r), cav_ctx: arb_caveat_context(r) }
}

/// A random caveat spec as [`build_chain`] takes it.
pub fn arb_caveat_spec(r: &mut InvRng) -> Value {
    match r.int(0, 6) {
        0 => json!({ "k": "expires", "at": jint(r.int(0, 10_000_000)) }),
        1 => json!({ "k": "not_before", "at": jint(r.int(0, 10_000_000)) }),
        2 => json!({ "k": "rate", "max": jint(r.int(1, 10)), "per_secs": jint(r.int(1, 3600)) }),
        // quantized to 3 decimals so the limit is canonical-wire-safe
        3 => json!({ "k": "max_blast_radius", "max": r.int(0, 1000) as f64 / 1000.0 }),
        4 => json!({ "k": "reversibility_max", "cls": pick(r, &["reversible", "rate_limited", "irreversible"]) }),
        5 => json!({ "k": "delegation_depth", "max": jint(r.int(0, 20)) }),
        _ => json!({ "k": "budget_frac", "frac": r.dbl(0.0, 1.0) }),
    }
}

/// A random signed, legally attenuating chain of up to 6 capabilities: `{caps, predicates, rootIssuer, holders}`.
pub fn arb_chain(r: &mut InvRng) -> Result<Value, String> {
    let principal = arb_seed32(r);
    let holder0 = arb_seed32(r);
    let root_specs = array(r, arb_caveat_spec, 1, 4);
    let hops = array(r, |r| json!({ "holderSeed": arb_seed32(r), "addedSpecs": array(r, arb_caveat_spec, 0, 3) }), 0, 5);
    let predicates = arb_predicate_list(r);
    build_chain(&json!({ "principalSeed": principal, "holder0Seed": holder0, "rootSpecs": root_specs, "hops": hops, "predicates": predicates }))
}

/// A well-formed risk policy: kappa > 0, 0 <= theta1 <= theta2, the rest finite >= 0.
pub fn arb_risk_policy(r: &mut InvRng) -> RiskPolicy {
    let weights = RiskWeights {
        alpha: r.dbl(0.0, 2.0),
        beta: r.dbl(0.0, 2.0),
        gamma: r.dbl(0.0, 2.0),
        delta: r.dbl(0.0, 2.0),
        epsilon: r.dbl(0.0, 2.0),
        zeta: r.dbl(0.0, 2.0),
    };
    let t1 = r.dbl(0.0, 1.0);
    let theta2 = t1 + r.dbl(0.0, 1.0);
    RiskPolicy { weights, theta1: t1, theta2, kappa: r.dbl(0.001, 5.0), lambda: r.dbl(0.0, 0.01), rho: r.dbl(0.0, 2.0), b_max: r.dbl(0.0, 10.0) }
}

/// A random risk input, every axis in [0, 1].
pub fn arb_risk_inputs(r: &mut InvRng) -> RiskInputs {
    RiskInputs {
        semantic_distance: r.dbl(0.0, 1.0),
        reversibility: r.dbl(0.0, 1.0),
        blast_radius: r.dbl(0.0, 1.0),
        taint: r.dbl(0.0, 1.0),
        confidence: r.dbl(0.0, 1.0),
        age: r.dbl(0.0, 1.0),
    }
}

/// A random trust budget.
pub fn arb_trust_budget(r: &mut InvRng) -> TrustBudget {
    let b = r.dbl(0.0, 10.0);
    let tau = r.int(0, 10_000_000) as f64;
    let as_of = if r.float() < 0.5 { Some(r.int(0, 10_000_000) as f64) } else { None };
    TrustBudget { b, tau, as_of }
}

fn clamp01(x: f64) -> f64 {
    x.max(0.0).min(1.0)
}

fn worsen(b: &RiskInputs, r: &mut InvRng) -> RiskInputs {
    let (sd, bl, ta, ag) = (r.dbl(0.0, 1.0), r.dbl(0.0, 1.0), r.dbl(0.0, 1.0), r.dbl(0.0, 1.0));
    let (rv, cf) = (r.dbl(0.0, 1.0), r.dbl(0.0, 1.0));
    RiskInputs {
        semantic_distance: clamp01(b.semantic_distance + sd),
        blast_radius: clamp01(b.blast_radius + bl),
        taint: clamp01(b.taint + ta),
        age: clamp01(b.age + ag),
        reversibility: clamp01(b.reversibility - rv),
        confidence: clamp01(b.confidence - cf),
    }
}

fn policy_value(p: &RiskPolicy) -> Value {
    let w = &p.weights;
    json!({
        "weights": { "alpha": w.alpha, "beta": w.beta, "gamma": w.gamma, "delta": w.delta, "epsilon": w.epsilon, "zeta": w.zeta },
        "theta1": p.theta1, "theta2": p.theta2, "kappa": p.kappa, "lambda": p.lambda, "rho": p.rho, "bMax": p.b_max,
    })
}

/// A property: true when the generated case upholds the invariant.
pub type InvProp = fn(&mut InvRng) -> bool;

const EPS: f64 = 1e-9;

fn caps_of(chain: &Value) -> Vec<Value> {
    chain["caps"].as_array().cloned().unwrap_or_default()
}

fn cap_caveats(cap: &Value) -> Vec<Value> {
    cap.get("caveats").and_then(Value::as_array).cloned().unwrap_or_default()
}

fn auth_allowed(caveats: &[Value], predicates: &[Value], p: &EvalPoint) -> bool {
    if !evaluate_predicates(predicates, &Ctx::new(&p.action)) {
        return false;
    }
    evaluate_caveats(&Value::Array(caveats.to_vec()), &p.cav_ctx).0
}

fn verifies(caps: &[Value], root: &str) -> bool {
    verify_chain(caps, Some(root)).is_ok()
}

fn hash_of(v: &Value) -> String {
    hash_canonical(v)
}

/// A legal chain verifies; each hop's caveats extend its parent's append-only; budget_alloc limits never grow; and at every probe point
/// the per-hop verdict is monotone non-increasing root to leaf.
pub fn inv_attenuation_monotonicity(r: &mut InvRng) -> bool {
    let Ok(chain) = arb_chain(r) else { return false };
    let points = array(r, arb_eval_point, 1, 5);
    let caps = caps_of(&chain);
    let root = chain["rootIssuer"].as_str().unwrap_or("").to_string();
    if caps.is_empty() || !verifies(&caps, &root) {
        return false;
    }
    for i in 1..caps.len() {
        let (parent, child) = (cap_caveats(&caps[i - 1]), cap_caveats(&caps[i]));
        if child.len() < parent.len() {
            return false;
        }
        for (j, p) in parent.iter().enumerate() {
            if hash_of(&child[j]) != hash_of(p) {
                return false;
            }
        }
    }
    let leaf = cap_caveats(&caps[caps.len() - 1]);
    if allocations_monotone(&leaf).is_err() {
        return false;
    }
    let mut prev: Option<f64> = None;
    for cv in &leaf {
        if cv.get("type").and_then(Value::as_str) != Some("budget_alloc") {
            continue;
        }
        let Some(lim) = cv.get("limit").and_then(Value::as_f64) else { continue };
        if prev.is_some_and(|p| lim > p) {
            return false;
        }
        prev = Some(lim);
    }
    let preds = chain["predicates"].as_array().cloned().unwrap_or_default();
    for pt in &points {
        let mut ancestor = true;
        for c in &caps {
            let allowed = auth_allowed(&cap_caveats(c), &preds, pt);
            if allowed && !ancestor {
                return false; // a true after a false would be a widening
            }
            ancestor = allowed;
        }
    }
    true
}

/// r is clamped to [0, 1] and a pointwise-worse input never yields a lower r.
pub fn inv_risk_monotone(r: &mut InvRng) -> bool {
    let (policy, inputs) = (arb_risk_policy(r), arb_risk_inputs(r));
    let s = risk_score(&inputs, &policy.weights);
    if !(0.0..=1.0).contains(&s) {
        return false;
    }
    let w = risk_score(&worsen(&inputs, r), &policy.weights);
    (0.0..=1.0).contains(&w) && w + EPS >= s
}

/// Whenever Admit lets an action proceed without a human the admitted cost is covered by the budget, and the safety bound is exactly
/// bMax / kappa.
pub fn inv_admission_soundness(r: &mut InvRng) -> bool {
    let (policy, inputs, budget) = (arb_risk_policy(r), arb_risk_inputs(r), arb_trust_budget(r));
    if validate_risk_policy(&policy_value(&policy)).is_some() {
        return false;
    }
    let s = risk_score(&inputs, &policy.weights);
    let c = cost(s, policy.kappa);
    let adm = admit(s, &budget, &policy);
    if adm.metered && (adm.t >= 3 || !(budget.b + EPS >= c)) {
        return false;
    }
    if adm.admit && (adm.t != 1 || !adm.metered || !(budget.b + EPS >= c)) {
        return false;
    }
    let expected = if policy.kappa > 0.0 { policy.b_max.max(0.0) / policy.kappa } else { 0.0 };
    (safety_bound(policy.b_max, policy.kappa) - expected).abs() <= EPS
}

/// Any sequence of machine-only actions debiting kappa * r never drives B negative and the total admitted risk obeys Sum(r) <= bMax / kappa.
pub fn inv_cumulative_budget_bound(r: &mut InvRng) -> bool {
    let policy = arb_risk_policy(r);
    let seq = array(r, arb_risk_inputs, 1, 40);
    let bound = safety_bound(policy.b_max, policy.kappa);
    let (mut b, mut sum) = (policy.b_max.max(0.0), 0.0f64);
    for input in &seq {
        let s = risk_score(input, &policy.weights);
        let adm = admit(s, &TrustBudget { b, tau: 0.0, as_of: Some(0.0) }, &policy);
        if adm.metered && adm.t < 3 {
            let c = cost(s, policy.kappa);
            if !(b + EPS >= c) {
                return false;
            }
            b = (b - c).max(0.0);
            sum += s;
            if b < -EPS || !(policy.kappa * sum <= policy.b_max + 1e-6) || !(sum <= bound + 1e-6) {
                return false;
            }
        }
    }
    true
}

fn undecidable(i: usize, f: &str) -> Value {
    match i {
        0 => json!({ "field": format!("{f}.definitely_absent"), "op": "eq", "value": "x" }),
        1 => json!({ "field": f, "op": "lt", "value": 5 }),
        2 => json!({ "field": f, "op": "in", "value": "not-an-array" }),
        3 => json!({ "field": f, "op": "eq" }),
        _ => json!({ "field": f, "op": "member_of", "value": "g", "collection": "env.no_such_collection" }),
    }
}

fn tri(c: &Value, ctx: &Value) -> Tri {
    evaluate_condition_tri(c, &Ctx::new(ctx))
}

/// Every structurally undecidable leaf is never "true", so a predicate carrying it never grants.
pub fn inv_undecidable_leaf_fails_closed(r: &mut InvRng) -> bool {
    let leaf = undecidable(r.int(0, 4) as usize, "subject.role");
    let verb = pick(r, &["read", "write", "delete"]);
    let ctx = json!({ "action": { "verb": verb, "resource": "/x" }, "subject": { "role": "admin" } });
    if tri(&leaf, &ctx) == Tri::True {
        return false;
    }
    !evaluate_predicates(&[json!({ "verb": verb, "resource": "/x", "where": [leaf] })], &Ctx::new(&ctx))
}

/// not / all_of / any_of over undecidable or empty children are never "true".
pub fn inv_undecidable_groups_fail_closed(_r: &mut InvRng) -> bool {
    let ctx = json!({ "action": { "verb": "read", "resource": "/x" }, "subject": { "role": "admin" } });
    let child = json!({ "field": "subject.role", "op": "lt", "value": 5 });
    let groups = [json!({ "not": child }), json!({ "all_of": [] }), json!({ "any_of": [] }), json!({ "all_of": [child] }), json!({ "any_of": [child] })];
    groups.iter().all(|c| tri(c, &ctx) != Tri::True)
}

/// member_of over a cyclic adjacency terminates with a correct verdict and fails closed on an unreachable target.
pub fn inv_member_of_cycle_safe(r: &mut InvRng) -> bool {
    let target = pick(r, &["a", "b", "c", "z"]);
    let rel = json!({ "a": ["b"], "b": ["a", "c"] });
    let ctx = json!({ "action": { "verb": "read", "resource": "/x" }, "subject": { "g": "a" }, "env": { "rel": rel } });
    let got = tri(&json!({ "field": "subject.g", "op": "member_of", "value": target, "collection": "env.rel" }), &ctx);
    if target == "z" {
        got == Tri::False
    } else {
        got == Tri::True
    }
}

const KNOWN_CAVEAT_TYPES: [&str; 9] =
    ["expires", "not_before", "rate", "max_blast_radius", "reversibility_max", "delegation_depth", "budget_alloc", "max_spend", "intent_session"];

/// An unknown caveat type is never satisfied, so a caveat set containing it is never ok.
pub fn inv_unknown_caveat_type_denies(r: &mut InvRng) -> bool {
    let mut t = string(r, 1, 12);
    while KNOWN_CAVEAT_TYPES.contains(&t.as_str()) {
        t = string(r, 1, 12);
    }
    let cav = json!({ "type": t });
    let ctx = json!({ "now": jint(r.int(0, 10_000_000)) });
    if crate::caveat_satisfied(&cav, &ctx) {
        return false;
    }
    !evaluate_caveats(&json!([cav]), &ctx).0
}

const MUTATIONS: [&str; 9] =
    ["tamper-caveat", "drop-leaf-caveat", "swap-holder", "break-parent", "bad-sig", "wrong-root-issuer", "suite-mismatch", "break-id", "append-forged-hop"];

/// A legal chain mutated by one of nine attacks never verifies.
pub fn inv_forged_chain_rejected(r: &mut InvRng) -> bool {
    let Ok(chain) = arb_chain(r) else { return false };
    let mutation = pick(r, &MUTATIONS);
    let pick_n = r.int(0, 1_000_000) as usize;
    let seed = (0..32).map(|_| r.next_u64() as u8).collect::<Vec<u8>>();
    let Ok(aux) = key_pair_from_seed(&seed) else { return false };
    let caps = caps_of(&chain);
    let root = chain["rootIssuer"].as_str().unwrap_or("").to_string();
    if caps.is_empty() || !verifies(&caps, &root) {
        return false;
    }
    let n = caps.len();
    let idx = pick_n % n;
    let rejects = |m: &[Value]| !verifies(m, &root);
    let mut m = caps.clone();
    match mutation {
        "tamper-caveat" => {
            if let Some(a) = m[idx].get_mut("caveats").and_then(Value::as_array_mut) {
                a.push(json!({ "type": "expires", "at": 999 }));
            }
            rejects(&m)
        }
        "drop-leaf-caveat" => {
            let Some(a) = m[n - 1].get_mut("caveats").and_then(Value::as_array_mut) else { return false };
            if a.is_empty() {
                return true; // inapplicable
            }
            a.pop();
            rejects(&m)
        }
        "swap-holder" => {
            m[idx]["holder"] = json!(aux.public);
            rejects(&m)
        }
        "break-parent" => {
            if n < 2 {
                return true;
            }
            m[idx.max(1)]["parent"] = json!(hash_of(&json!({ "bogus": "x", "tag": "not-a-real-parent" })));
            rejects(&m)
        }
        "bad-sig" => {
            m[idx]["sig"] = json!(crate::b64_encode(&aux.signer.sign(&[1, 2, 3, 4])));
            rejects(&m)
        }
        "wrong-root-issuer" => aux.public == root || !verifies(&caps, &aux.public),
        "suite-mismatch" => {
            m[idx]["alg"] = json!("ml-dsa-65"); // suite fields are bound into the body digest
            rejects(&m)
        }
        "break-id" => {
            m[idx]["id"] = json!(hash_of(&json!({ "not": "the-body-digest", "n": idx as i64 })));
            rejects(&m)
        }
        _ => {
            // append-forged-hop: issued as if from the leaf, but signed by a key that is not the leaf's holder
            match delegate(&caps[n - 1], &aux.signer, Some(aux.public.as_str()), &json!([]), None, &Suite::default()) {
                Err(_) => true, // refused outright
                Ok(forged) => {
                    m.push(forged);
                    rejects(&m)
                }
            }
        }
    }
}

/// Arbitrary never-signed chains (including the empty chain) never verify.
pub fn inv_garbage_chain_rejected(r: &mut InvRng) -> bool {
    let chain = array(
        r,
        |r| {
            json!({ "id": string(r, 0, 10), "issuer": string(r, 0, 10), "holder": string(r, 0, 10),
                    "caveats": [{ "type": string(r, 0, 10) }], "body_digest": string(r, 0, 10), "sig": string(r, 0, 10) })
        },
        0,
        4,
    );
    !verifies(&chain, "")
}

/// VerifyChain, predicates, caveats, the risk score, the threshold and Admit are deterministic.
pub fn inv_determinism(r: &mut InvRng) -> bool {
    let Ok(chain) = arb_chain(r) else { return false };
    let (pt, preds) = (arb_eval_point(r), arb_predicate_list(r));
    let (policy, inputs, budget) = (arb_risk_policy(r), arb_risk_inputs(r), arb_trust_budget(r));
    let caps = caps_of(&chain);
    let root = chain["rootIssuer"].as_str().unwrap_or("").to_string();
    if caps.is_empty() || verifies(&caps, &root) != verifies(&caps, &root) {
        return false;
    }
    let ctx = Ctx::new(&pt.action);
    if evaluate_predicates(&preds, &ctx) != evaluate_predicates(&preds, &ctx) {
        return false;
    }
    let leaf = Value::Array(cap_caveats(&caps[caps.len() - 1]));
    if evaluate_caveats(&leaf, &pt.cav_ctx) != evaluate_caveats(&leaf, &pt.cav_ctx) {
        return false;
    }
    let s = risk_score(&inputs, &policy.weights);
    s == risk_score(&inputs, &policy.weights)
        && required_threshold(s, policy.theta1, policy.theta2, false) == required_threshold(s, policy.theta1, policy.theta2, false)
        && admit(s, &budget, &policy) == admit(s, &budget, &policy)
}

/// Forbid-wins is monotone and order-independent: adding a forbid clause only moves a decision down, a matching forbid always denies,
/// and the decision does not depend on clause order.
pub fn inv_forbid_monotone(r: &mut InvRng) -> bool {
    let rank = |d: &str| match d {
        "deny" => Some(0),
        "escalate" => Some(1),
        "allow" => Some(2),
        _ => None,
    };
    let mk = |kind: &str, ps: &[Value], tag: &str| -> Vec<Value> {
        ps.iter().enumerate().map(|(i, w)| json!({ "id": format!("{tag}{i}"), "kind": kind, "when": w })).collect()
    };
    let (permits, forbids, extra) = (arb_predicate_list(r), arb_predicate_list(r), arb_predicate_list(r));
    let (pt, rot) = (arb_eval_point(r), r.int(0, 5) as usize);
    let mut base = mk("permit", &permits, "p");
    base.extend(mk("escalate", &extra, "e"));
    let mut with = base.clone();
    with.extend(mk("forbid", &forbids, "f"));
    let dec = |c: &[Value]| decide_clauses(&Value::Array(c.to_vec()), &pt.action, &ClauseOptions::default()).decision;
    let (before, after) = (dec(&base), dec(&with));
    let (Some(rb), Some(ra)) = (rank(before), rank(after)) else { return false };
    if ra > rb {
        return false;
    }
    for w in &forbids {
        if when_matches(w, &pt.action) && after != "deny" {
            return false;
        }
    }
    let k = rot % with.len();
    let mut rotated = with[k..].to_vec();
    rotated.extend_from_slice(&with[..k]);
    dec(&rotated) == after
}

/// One named invariant of the registry.
pub struct InvariantCheck {
    pub name: &'static str,
    pub prop: InvProp,
}

/// The invariants in run order (the order of [`INVARIANT_NAMES`]).
pub const INVARIANT_REGISTRY: [InvariantCheck; 12] = [
    InvariantCheck { name: "attenuation-monotonicity", prop: inv_attenuation_monotonicity },
    InvariantCheck { name: "risk-wellformed-and-monotone", prop: inv_risk_monotone },
    InvariantCheck { name: "admission-soundness", prop: inv_admission_soundness },
    InvariantCheck { name: "cumulative-budget-bound", prop: inv_cumulative_budget_bound },
    InvariantCheck { name: "fail-closed:undecidable-leaf", prop: inv_undecidable_leaf_fails_closed },
    InvariantCheck { name: "fail-closed:undecidable-groups", prop: inv_undecidable_groups_fail_closed },
    InvariantCheck { name: "fail-closed:member-of-cycle-safe", prop: inv_member_of_cycle_safe },
    InvariantCheck { name: "fail-closed:unknown-caveat-type", prop: inv_unknown_caveat_type_denies },
    InvariantCheck { name: "fail-closed:forged-chain-rejected", prop: inv_forged_chain_rejected },
    InvariantCheck { name: "fail-closed:garbage-chain-rejected", prop: inv_garbage_chain_rejected },
    InvariantCheck { name: "forbid-monotone", prop: inv_forbid_monotone },
    InvariantCheck { name: "determinism", prop: inv_determinism },
];

/// One invariant's outcome; `ok` false with `error` is a surfaced counterexample (a candidate core bug).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvariantResult {
    pub name: &'static str,
    pub ok: bool,
    pub num_runs: u64,
    pub seed: u64,
    pub error: Option<String>,
}

fn run_prop(p: InvProp, num_runs: u64, seed: u64) -> Result<(), String> {
    let mut master = InvRng::new(seed);
    for i in 0..num_runs {
        let cs = master.next_u64();
        let held = std::panic::catch_unwind(|| p(&mut InvRng::new(cs))).map_err(|_| format!("property panicked (seed {seed}, case seed {cs})"))?;
        if !held {
            return Err(format!("property failed after {} run(s) (seed {seed}, case seed {cs})", i + 1));
        }
    }
    Ok(())
}

/// Machine-check every invariant (`bail` stops at the first failure). `num_runs` 0 means [`DEFAULT_NUM_RUNS`]; a count above 1e7 is
/// refused. The seed is always explicit (pass [`crate::invariants::DEFAULT_SEED`] for the default).
pub fn check_invariants(num_runs: u64, seed: u64, bail: bool) -> Result<Vec<InvariantResult>, String> {
    let num_runs = if num_runs == 0 { DEFAULT_NUM_RUNS } else { num_runs };
    if num_runs > 10_000_000 {
        return Err("checkInvariants: numRuns must be a positive integer".into());
    }
    debug_assert_eq!(INVARIANT_REGISTRY.len(), INVARIANT_NAMES.len());
    let mut out = Vec::with_capacity(INVARIANT_REGISTRY.len());
    for inv in &INVARIANT_REGISTRY {
        let error = run_prop(inv.prop, num_runs, seed).err();
        let res = InvariantResult { name: inv.name, ok: error.is_none(), num_runs, seed, error };
        let stop = bail && !res.ok;
        out.push(res);
        if stop {
            break;
        }
    }
    Ok(out)
}

/// Re-run one invariant on the case seed a failure reported: `Ok(true)` when the case now upholds it.
pub fn replay_invariant(name: &str, case_seed: u64) -> Result<bool, String> {
    let inv = INVARIANT_REGISTRY.iter().find(|i| i.name == name).ok_or_else(|| format!("unknown invariant {name:?}"))?;
    std::panic::catch_unwind(|| (inv.prop)(&mut InvRng::new(case_seed))).map_err(|_| "property panicked".to_string())
}

/// A key pair from a generated seed (for callers building their own forged chains).
pub fn arb_key_pair(r: &mut InvRng) -> Result<KeyPair, String> {
    let b: Vec<u8> = (0..32).map(|_| r.next_u64() as u8).collect();
    key_pair_from_seed(&b).map(|k| k.signer)
}
