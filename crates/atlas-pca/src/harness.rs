//! The attested orchestration harness ("attest the mediator, not the weights") and the resource-server hook that admits an
//! allowlisted harness measurement. The model is an UNTRUSTED ORACLE: [`Harness::step`] is the only path from its proposal to a
//! signed PCActn and enforces plan inclusion, then the taint fold, then the trust budget, then signs.
//!
//! JSON-valued like the other 0.6 ports: candidates, results and the attestation config are `serde_json::Value`s with the
//! reference's member names. The policy used for gating must carry numeric weights / thresholds; a policy missing `weights`,
//! `theta1`, `theta2` or `kappa` is refused at construction (the reference fails later, on the first step).
use crate::agent::{build_pcactn, KeyPair, PcactnInput, Suite};
use crate::risk::{cost, debit, leak, required_threshold, risk_score, RiskInputs, RiskWeights, TrustBudget};
use crate::{canonicalize, hash_canonical_strict};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

/// The ordered manifest of checks the harness enforces before signing; folded into the measurement.
pub const ENFORCED_CHECKS: [&str; 4] = ["plan_inclusion_before_signing", "taint_provenance_fold", "trust_budget_debit", "pcactn_sign"];
/// Semantic version of the harness's policy-relevant surface. A bump changes the measurement.
pub const HARNESS_VERSION: &str = "0.1.0";
/// The model id stamped into an emitted PCActn's `attestation.model_id` when attestation is enabled (the mediator, not an LLM).
pub const HARNESS_MODEL_ID: &str = "@atlasauth/pca-harness";

/// Pure self-measurement: base64url SHA-256 over the harness version, the enforced-checks manifest and the risk-policy identity
/// (`weights`, `theta1`, `theta2`, `kappa`). A policy that is not an object, or lacks one of those members, is refused, as is a
/// value outside the strict canonical profile (the reference's canonical form refuses an undefined member).
pub fn compute_harness_measurement(version: &Value, enforced_checks: &Value, policy: &Value) -> Result<String, String> {
    let p = policy.as_object().ok_or("computeHarnessMeasurement: policy is not an object")?;
    let mut rp = Map::new();
    for k in ["weights", "theta1", "theta2", "kappa"] {
        rp.insert(k.into(), p.get(k).ok_or("canonicalize: unsupported type undefined")?.clone());
    }
    let body = json!({"harness": HARNESS_MODEL_ID, "version": version, "enforces": enforced_checks, "risk_policy": Value::Object(rp)});
    hash_canonical_strict(&body).ok_or_else(|| "canonicalize: value is outside the strict JSON profile".to_string())
}

// ---- allowlisting verifier -------------------------------------------------------------------------------------------------

/// `v?.key` for a decoded JSON value: only an object has members.
fn member<'a>(v: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    v.and_then(Value::as_object).and_then(|o| o.get(key))
}

/// The hook of [`create_harness_attestation_verifier`]: a PCActn-verify context in, `{enforced, ok?, reason?}` out.
pub type AttestationHook = Box<dyn Fn(&Value) -> Value + Send + Sync>;

/// The resource-server hook. FAIL CLOSED: an empty allowlist accepts nothing; an absent measurement fails unless `required` is
/// `false` (then `{enforced: false}`); a pinned `expectedModelId` must match; a present measurement outside the allowlist ALWAYS
/// fails. `config`: `measurements` (allowlisted strings), `required` (default true), `expectedModelId` (`true` = the harness id,
/// or a non-empty string). The measurement's integrity rests on the surrounding verdict requiring the leaf signature to verify.
/// A config that is not an object is refused.
pub fn create_harness_attestation_verifier(config: &Value) -> Result<AttestationHook, String> {
    let cfg = config.as_object().ok_or("createHarnessAttestationVerifier: config must be an object")?;
    let allow: HashSet<String> = match cfg.get("measurements") {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).filter(|m| !m.is_empty()).map(String::from).collect(),
        _ => HashSet::new(),
    };
    let required = cfg.get("required") != Some(&Value::Bool(false));
    let expected: Option<String> = match cfg.get("expectedModelId") {
        Some(Value::Bool(true)) => Some(HARNESS_MODEL_ID.to_string()),
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    Ok(Box::new(move |ctx: &Value| {
        if allow.is_empty() {
            return json!({"enforced": true, "ok": false, "reason": "harness attestation configured with an empty measurement allowlist (fail closed)"});
        }
        let att = member(member(Some(ctx), "pcactn"), "attestation");
        let measurement = member(att, "measurement").and_then(Value::as_str).unwrap_or("");
        if measurement.is_empty() {
            return if required {
                json!({"enforced": true, "ok": false, "reason": "harness attestation required but the PCActn carries no harness measurement (fail closed)"})
            } else {
                json!({"enforced": false})
            };
        }
        if let Some(want) = &expected {
            let got = member(att, "model_id");
            if got.and_then(Value::as_str) != Some(want.as_str()) {
                let shown = got.map(crate::oauth::js_str).unwrap_or_else(|| "undefined".into());
                return json!({"enforced": true, "ok": false, "reason": format!("attestation.model_id '{shown}' is not the required harness identity '{want}'")});
            }
        }
        if !allow.contains(measurement) {
            return json!({"enforced": true, "ok": false, "reason": "harness measurement is not in the allowlisted set (unattested or unknown mediator)"});
        }
        json!({"enforced": true, "ok": true})
    }))
}

// ---- the harness -----------------------------------------------------------------------------------------------------------

/// Everything [`Harness::new`] needs. `budget` is `{B, tau, asOf}`; `base_risk` is an object of overrides of the base risk inputs;
/// `attestation` is `{operator, epoch?}` to stamp this harness's self-measurement into every emitted PCActn.
pub struct HarnessOptions {
    pub grant: Value,
    /// The chain ending at the leaf the harness signs for; default `[grant]`.
    pub chain: Option<Vec<Value>>,
    /// Seed of the leaf holder's Ed25519 key. The oracle never sees it.
    pub agent_seed: [u8; 32],
    pub plan: Vec<Value>,
    pub audience: String,
    pub budget: Value,
    /// A risk policy in wire form (`weights`, `theta1`, `theta2`, `kappa`, `lambda`); default the DEFAULT risk policy.
    pub policy: Option<Value>,
    pub base_risk: Option<Value>,
    /// Clock, epoch ms. Default: the system clock.
    pub now: Option<Box<dyn Fn() -> f64 + Send>>,
    pub ttl_ms: Option<i64>,
    pub measurement_manifest: Option<Vec<String>>,
    /// Nonce source. Default: 16 random bytes as hex.
    pub nonce: Option<Box<dyn FnMut() -> String + Send>>,
    pub attestation: Option<Value>,
}

impl HarnessOptions {
    pub fn new(grant: Value, agent_seed: [u8; 32], plan: Vec<Value>, audience: &str, budget: Value) -> HarnessOptions {
        HarnessOptions {
            grant,
            chain: None,
            agent_seed,
            plan,
            audience: audience.to_string(),
            budget,
            policy: None,
            base_risk: None,
            now: None,
            ttl_ms: None,
            measurement_manifest: None,
            nonce: None,
            attestation: None,
        }
    }
}

struct Pol {
    weights: RiskWeights,
    theta1: f64,
    theta2: f64,
    kappa: f64,
    lambda: f64,
}

fn num(v: Option<&Value>) -> f64 {
    v.filter(|x| x.is_number()).and_then(Value::as_f64).unwrap_or(f64::NAN)
}

fn pol_of(p: &Value) -> Result<Pol, String> {
    let o = p.as_object().ok_or("Harness: `policy` must be an object")?;
    for k in ["weights", "theta1", "theta2", "kappa"] {
        if !o.contains_key(k) {
            return Err(format!("Harness: `policy.{k}` is required"));
        }
    }
    let w = o["weights"].as_object().ok_or("Harness: `policy.weights` must be an object")?;
    let g = |k: &str| num(w.get(k));
    Ok(Pol {
        weights: RiskWeights { alpha: g("alpha"), beta: g("beta"), gamma: g("gamma"), delta: g("delta"), epsilon: g("epsilon"), zeta: g("zeta") },
        theta1: num(o.get("theta1")),
        theta2: num(o.get("theta2")),
        kappa: num(o.get("kappa")),
        lambda: num(o.get("lambda")),
    })
}

/// Base risk inputs for an in-plan action; `taint` is overwritten per step from the input provenance.
fn default_base_risk() -> Map<String, Value> {
    let mut m = Map::new();
    for (k, v) in [("semanticDistance", 0.1), ("reversibility", 1.0), ("blastRadius", 0.1), ("taint", 0.0), ("confidence", 1.0), ("age", 0.0)] {
        m.insert(k.into(), json!(v));
    }
    m
}

/// `Math.round`: nearest integer, ties toward +Infinity.
fn js_round(x: f64) -> f64 {
    let f = x.floor();
    if x - f >= 0.5 {
        f + 1.0
    } else {
        f
    }
}

/// `Number.prototype.toFixed(4)` of a non-negative double: ties pick the larger integer (Rust's `{:.4}` rounds half to even).
fn js_to_fixed4(x: f64) -> String {
    if !x.is_finite() || x < 0.0 {
        return format!("{x:.4}");
    }
    let bits = x.to_bits();
    let (exp, frac) = (((bits >> 52) & 0x7ff) as i32, bits & ((1u64 << 52) - 1));
    let (m, e) = if exp == 0 { (frac, -1074) } else { (frac | (1u64 << 52), exp - 1075) };
    let n: u128 = if e >= 0 {
        (m as u128).checked_shl(e as u32).and_then(|v| v.checked_mul(10_000)).unwrap_or(u128::MAX)
    } else if -e > 120 {
        0
    } else {
        let denom = 1u128 << (-e) as u32;
        ((m as u128) * 10_000 + denom / 2) / denom
    };
    format!("{}.{:04}", n / 10_000, n % 10_000)
}

fn random_nonce() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("os randomness");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn refuse(reason: &str, detail: String) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("ok".into(), json!(false));
    m.insert("reason".into(), json!(reason));
    m.insert("detail".into(), json!(detail));
    m
}

fn budget_json(b: &TrustBudget) -> Value {
    json!({"B": b.b, "tau": b.tau, "asOf": b.as_of.unwrap_or(b.tau)})
}

/// The attested mediator: holds the principal's grant, the committed plan, the signing key and the trust budget.
pub struct Harness {
    grant: Value,
    chain: Vec<Value>,
    signer: KeyPair,
    plan: Vec<Value>,
    plan_root: String,
    audience: String,
    policy_value: Value,
    policy: Pol,
    base_risk: Map<String, Value>,
    now: Box<dyn Fn() -> f64 + Send>,
    ttl_ms: Option<i64>,
    manifest: Value,
    nonce: Box<dyn FnMut() -> String + Send>,
    attest: Option<(Value, Value)>,
    budget: TrustBudget,
    counter: i64,
}

impl Harness {
    pub fn new(o: HarnessOptions) -> Result<Harness, String> {
        if o.audience.is_empty() {
            return Err("Harness: `audience` is required (the resource-server / instance id PCActns are for)".into());
        }
        if o.plan.is_empty() {
            return Err("Harness: `plan` must be a non-empty array (an empty plan authorises nothing)".into());
        }
        let ids: HashSet<String> = o.plan.iter().map(|n| n.get("id").map(canonicalize).unwrap_or_default()).collect();
        if ids.len() != o.plan.len() {
            return Err("Harness: plan node ids must be unique".into());
        }
        let bad_budget = "Harness: `budget` must have finite B >= 0, tau and asOf";
        let b = o.budget.as_object().ok_or(bad_budget)?;
        let fin = |k: &str| b.get(k).filter(|v| v.is_number()).and_then(Value::as_f64).filter(|f| f.is_finite());
        let (bb, tau, as_of) = match (fin("B"), fin("tau"), fin("asOf")) {
            (Some(bb), Some(t), Some(a)) if bb >= 0.0 => (bb, t, a),
            _ => return Err(bad_budget.into()),
        };
        let policy_value = o.policy.unwrap_or_else(crate::agent::default_risk_policy);
        let policy = pol_of(&policy_value)?;
        let mut base_risk = default_base_risk();
        match &o.base_risk {
            None | Some(Value::Null) => {}
            Some(Value::Object(m)) => base_risk.extend(m.iter().map(|(k, v)| (k.clone(), v.clone()))),
            Some(_) => return Err("Harness: `baseRisk` must be an object".into()),
        }
        let attest = match &o.attestation {
            None => None,
            Some(a) => {
                let operator = a.get("operator").filter(|v| v.is_string()).cloned().ok_or("Harness: `attestation.operator` must be a string")?;
                Some((operator, a.get("epoch").filter(|v| !v.is_null()).cloned().unwrap_or(json!(0))))
            }
        };
        // Commit the principal-authorised plan ONCE; every emitted action carries an inclusion proof under this root.
        let plan_root = crate::agent::plan_commit(&o.plan)?["root"].as_str().ok_or("Harness: plan commitment has no root")?.to_string();
        let chain = o.chain.unwrap_or_else(|| vec![o.grant.clone()]);
        Ok(Harness {
            grant: o.grant,
            chain,
            signer: KeyPair::from_seed(&o.agent_seed),
            plan: o.plan,
            plan_root,
            audience: o.audience,
            policy_value,
            policy,
            base_risk,
            now: o.now.unwrap_or_else(|| {
                Box::new(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as f64).unwrap_or(0.0))
            }),
            ttl_ms: o.ttl_ms,
            manifest: Value::Array(match o.measurement_manifest {
                Some(m) => m.into_iter().map(Value::String).collect(),
                None => ENFORCED_CHECKS.iter().map(|s| json!(s)).collect(),
            }),
            nonce: o.nonce.unwrap_or_else(|| Box::new(random_nonce)),
            attest,
            budget: TrustBudget { b: bb, tau, as_of: Some(as_of) },
            counter: 0,
        })
    }

    /// The committed plan root the principal authorised.
    pub fn plan_root(&self) -> &str {
        &self.plan_root
    }

    /// The current (leaked-to-last-touch) trust budget, `{B, tau, asOf}`.
    pub fn budget(&self) -> Value {
        budget_json(&self.budget)
    }

    /// Monotonic action counter: the number of PCActns this harness has emitted.
    pub fn counter(&self) -> i64 {
        self.counter
    }

    /// What a remote attestation of the MEDIATOR would cover, in place of the unmeasurable model weights.
    pub fn harness_measurement(&self) -> Result<String, String> {
        compute_harness_measurement(&json!(HARNESS_VERSION), &self.manifest, &self.policy_value)
    }

    /// Ask the untrusted oracle for a candidate `{verb, resource, params?, nodeId, inputs?}` and, only if it survives the gate,
    /// emit a signed PCActn: `{ok: true, pcactn, inclusionProof, risk, budget}`, or a refusal `{ok: false, reason: out_of_plan |
    /// over_budget | bad_candidate, detail, requiredT?, budget?}`. An oracle that fails (`Err`) or returns a malformed candidate is a
    /// refusal, never a panic.
    pub fn step<F: FnOnce() -> Result<Value, String>>(&mut self, propose_action: F) -> Value {
        let candidate = match propose_action() {
            Ok(c) => c,
            Err(e) => return Value::Object(refuse("bad_candidate", format!("oracle failed: {e}"))),
        };
        // (0) the oracle is untrusted: validate the shape before use
        let str_of = |k: &str| candidate.get(k).and_then(Value::as_str);
        let (Some(node_id), Some(verb), Some(resource)) = (str_of("nodeId"), str_of("verb"), str_of("resource")) else {
            return Value::Object(refuse("bad_candidate", "oracle returned a malformed candidate".into()));
        };
        // (1) PLAN INCLUSION: reject out-of-plan BEFORE signing
        let Some(node) = self.plan.iter().find(|n| n.get("id").and_then(Value::as_str) == Some(node_id)) else {
            return Value::Object(refuse("out_of_plan", format!("node '{node_id}' is not in the committed plan")));
        };
        let nv = node.get("verb").and_then(Value::as_str).unwrap_or("undefined");
        let nr = node.get("resource").and_then(Value::as_str).unwrap_or("undefined");
        if nv != verb || nr != resource {
            return Value::Object(refuse("out_of_plan", format!("action {verb} {resource} does not match committed node '{node_id}' ({nv} {nr})")));
        }
        // (2) TAINT FOLD: only a well-formed 'trusted' input is trusted; anything else counts as untrusted lineage
        let raw_inputs: &[Value] = match candidate.get("inputs") {
            None => &[],
            Some(Value::Array(a)) => a,
            Some(_) => return Value::Object(refuse("bad_candidate", "candidate.inputs is not an array".into())),
        };
        let inputs: Vec<(String, bool)> = raw_inputs
            .iter()
            .map(|i| {
                let r = i.get("ref").and_then(Value::as_str);
                match (i.get("provenance").and_then(Value::as_str), r) {
                    (Some("trusted"), Some(r)) => (r.to_string(), true),
                    _ => (r.unwrap_or("").to_string(), false),
                }
            })
            .collect();
        let taint = if inputs.iter().any(|(_, t)| !*t) { 1.0 } else { 0.0 };
        let trusted_refs: Vec<Value> = inputs.iter().filter(|(_, t)| *t).map(|(r, _)| json!(r)).collect();
        let mut risk_inputs = self.base_risk.clone();
        risk_inputs.insert("taint".into(), json!(taint));
        let g = |k: &str| num(risk_inputs.get(k));
        let ri = RiskInputs {
            semantic_distance: g("semanticDistance"),
            reversibility: g("reversibility"),
            blast_radius: g("blastRadius"),
            taint: g("taint"),
            confidence: g("confidence"),
            age: g("age"),
        };
        // rounded to 6 d.p. so the reported r, the signed risk_claim.r and the budget cost agree and stay canonical
        let r = js_round(risk_score(&ri, &self.policy.weights) * 1e6) / 1e6;
        let irreversible = node.get("reversibility_class").and_then(Value::as_str) == Some("irreversible");
        let rt = required_threshold(r, self.policy.theta1, self.policy.theta2, irreversible);

        // (3) TRUST BUDGET: meter machine-only actions, leaking to now first
        let now_ms = (self.now)();
        let leaked = leak(&self.budget, now_ms, self.policy.lambda);
        let c = cost(r, self.policy.kappa);
        if rt.t < 3 && !(leaked.b.is_finite() && leaked.b >= c) {
            // the budget cannot cover even a low-risk in-plan action: escalate to a human, debit nothing, produce no PCActn
            self.budget = leaked;
            let mut out = refuse("over_budget", format!("budget {} < cost {}; step up to a human co-sign", js_to_fixed4(leaked.b), js_to_fixed4(c)));
            out.insert("requiredT".into(), json!(3));
            out.insert("budget".into(), budget_json(&leaked));
            return Value::Object(out);
        }

        // (4) SIGN
        let ins: Vec<Value> = inputs.iter().map(|(r, t)| json!({"ref": r, "provenance": if *t { "trusted" } else { "untrusted" }})).collect();
        let Some(causal_hash) = hash_canonical_strict(&Value::Array(ins)) else {
            return Value::Object(refuse("bad_candidate", "could not build PCActn: provenance is outside the strict JSON profile".into()));
        };
        let mut extra = Map::new();
        extra.insert("provenance".into(), json!({"causal_hash": causal_hash, "taint_level": taint, "trusted_refs": trusted_refs}));
        extra.insert("risk_claim".into(), json!({"r": r, "inputs": Value::Object(risk_inputs.clone())}));
        extra.insert("nonce".into(), json!((self.nonce)()));
        if let Some((operator, epoch)) = &self.attest {
            let m = match self.harness_measurement() {
                Ok(m) => m,
                Err(e) => return Value::Object(refuse("bad_candidate", format!("could not build PCActn: {e}"))),
            };
            extra.insert(
                "attestation".into(),
                json!({"quote_digest": "", "epoch": epoch, "model_id": HARNESS_MODEL_ID, "measurement": m, "operator": operator}),
            );
        }
        let params = candidate.get("params");
        let iat = now_ms as i64;
        let built = build_pcactn(&PcactnInput {
            grant: &self.grant,
            chain: &self.chain,
            plan: &self.plan,
            node_id,
            params,
            counter: self.counter + 1,
            signer: &self.signer,
            aud: &self.audience,
            iat,
            exp: self.ttl_ms.map(|t| iat + t),
            extra,
            suite: Suite::default(),
        });
        let pcactn = match built {
            Ok(p) => p,
            Err(e) => {
                // e.g. params do not match the node's committed params_digest: still never emits an out-of-plan action
                let e = e.strip_prefix("build_pcactn:").map(|r| format!("buildPCActn:{r}")).unwrap_or(e);
                return Value::Object(refuse("bad_candidate", format!("could not build PCActn: {e}")));
            }
        };
        let inclusion_proof = pcactn["plan"]["inclusion_proof"].clone();

        // debit only a metered (machine-only, t < 3) action; commit the counter
        self.budget = if rt.t < 3 { debit(&leaked, c) } else { leaked };
        self.counter += 1;
        json!({
            "ok": true,
            "pcactn": pcactn,
            "inclusionProof": inclusion_proof,
            "risk": {"r": r, "inputs": Value::Object(risk_inputs), "taint": taint, "t": rt.t},
            "budget": budget_json(&self.budget),
        })
    }
}
