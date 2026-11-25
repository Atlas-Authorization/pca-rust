//! Shadow policy rollout (port of @atlasauth/pca-grants): run candidate policy bundles beside the enforced one, record every divergence
//! as a verifier-signed diff, and gate promotion on zero unexplained widenings. The enforced decision is computed first and returned
//! untouched, so a candidate that errs, returns junk or mutates its input cannot change the answer. Nothing here decides an action; it
//! is analysis and rollout tooling.
//!
//! `decide` hooks return `Ok("allow" | "deny" | "escalate")` (a `Value`); `Err` is a thrown error. Gate options are a JSON object with the
//! reference's member names (`shadow_digest`, `enforced_digest`, `minSamples`, `principals`, `explanations`, `surface`, `approval`).
use crate::fresh_at::verify_body as verify_body_opt;
use crate::grants::{gt, pick_all, rank_of, sign_body, signer_of, spread, u16key, without};
use crate::k3::bundle_digest;
use crate::lease::{nat, pick, s};
use crate::safe_int;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};

pub const SHADOW_DIFF_DOMAIN: &str = "atlas-pca/shadow-diff/v1\0";
pub const WIDENING_EXPLANATION_DOMAIN: &str = "atlas-pca/shadow-widening-explanation/v1\0";
pub const PROMOTION_APPROVAL_DOMAIN: &str = "atlas-pca/shadow-promotion-approval/v1\0";

const DIFF_KEYS: [&str; 9] = ["v", "shadow_digest", "enforced_digest", "action_digest", "enforced", "shadow", "widening", "at", "signer"];
const EXP_KEYS: [&str; 5] = ["v", "shadow_digest", "action_digest", "reason_digest", "principal"];
const AP_KEYS: [&str; 5] = ["v", "shadow_digest", "enforced_digest", "at", "principal"];

fn is_kind(v: &Value) -> bool {
    rank_of(Some(v)).is_some()
}

fn is_one(v: Option<&Value>) -> bool {
    v.and_then(safe_int) == Some(1)
}

/// A candidate policy: its bundle digest and its pure decision function.
pub struct ShadowCandidate<'a> {
    pub digest: String,
    pub decide: &'a dyn Fn(&Value) -> Result<Value, String>,
}

/// The enforced decision, plus what each candidate would have said: `{decision, shadow: [outcome]}` with outcome
/// `{digest, decision | "error", diverged, widening}`. The returned `decision` is the enforced one, always. Errs only when `enforced` errs.
pub fn run_shadow(input: &Value, enforced: &dyn Fn(&Value) -> Result<Value, String>, candidates: &[ShadowCandidate]) -> Result<Value, String> {
    let decision = enforced(input)?;
    let mut shadow = Vec::new();
    for c in candidates {
        let out = match (c.decide)(&input.clone()) {
            Ok(d) if is_kind(&d) => {
                json!({"digest": c.digest, "decision": d, "diverged": d != decision, "widening": gt(rank_of(Some(&d)), rank_of(Some(&decision)))})
            }
            _ => json!({"digest": c.digest, "decision": "error", "diverged": false, "widening": false}),
        };
        shadow.push(out);
    }
    Ok(json!({"decision": decision, "shadow": shadow}))
}

/// The `shadow` member of a decision record, from the outcomes.
pub fn shadow_record_field(outcomes: &[Value]) -> Vec<Value> {
    outcomes.iter().map(|o| json!({"digest": o["digest"], "decision": o["decision"], "diverged": o["diverged"]})).collect()
}

/// A well formed diff signed by its own `signer` (and by `signer` when given). Never panics.
pub fn verify_shadow_diff(d: &Value, signer: Option<&str>) -> bool {
    if !d.is_object() || !is_one(d.get("v")) || !(s(d.get("shadow_digest"), 128) && s(d.get("enforced_digest"), 128) && s(d.get("action_digest"), 128)) {
        return false;
    }
    let (Some(enforced), Some(shadow)) = (d.get("enforced"), d.get("shadow")) else { return false };
    let Some(widening) = d.get("widening").and_then(Value::as_bool) else { return false };
    if !is_kind(enforced) || !is_kind(shadow) || nat(d.get("at")).is_none() || !s(d.get("signer"), 128) {
        return false;
    }
    if enforced == shadow || widening != gt(rank_of(Some(shadow)), rank_of(Some(enforced))) {
        return false;
    }
    let who = d.get("signer").and_then(Value::as_str).unwrap_or("");
    if signer.is_some_and(|x| x != who) {
        return false;
    }
    verify_body_opt(SHADOW_DIFF_DOMAIN, &pick(d, &DIFF_KEYS), who, d.get("sig").and_then(Value::as_str))
}

/// Per-candidate counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShadowStats {
    pub total: i64,
    pub diverged: i64,
    pub widened: i64,
    pub tightened: i64,
    pub errors: i64,
}

impl ShadowStats {
    pub fn to_json(&self) -> Value {
        json!({"total": self.total, "diverged": self.diverged, "widened": self.widened, "tightened": self.tightened, "errors": self.errors})
    }
}

/// Collects the signed diffs and counters per candidate. In memory: persist [`ShadowLog::diffs`] to the decision log for the audit trail.
pub struct ShadowLog {
    secret: [u8; 32],
    stat: BTreeMap<String, ShadowStats>,
    list: BTreeMap<String, Vec<Value>>,
}

impl ShadowLog {
    pub fn new(secret: [u8; 32]) -> Self {
        Self { secret, stat: BTreeMap::new(), list: BTreeMap::new() }
    }

    pub fn signer(&self) -> String {
        signer_of(&self.secret)
    }

    /// Count one observation; sign and keep a diff when the candidate diverged. `outcome` is a [`run_shadow`] outcome.
    pub fn observe(&mut self, enforced_digest: &str, action_digest: &str, enforced: &str, outcome: &Value, at: &Value) -> Result<Option<Value>, String> {
        let digest = outcome.get("digest").and_then(Value::as_str).ok_or("observe: outcome without a digest")?.to_string();
        let decision = outcome.get("decision").and_then(Value::as_str).unwrap_or("").to_string();
        let diverged = outcome.get("diverged") == Some(&Value::Bool(true));
        let widening = outcome.get("widening") == Some(&Value::Bool(true));
        {
            let st = self.stat.entry(digest.clone()).or_default();
            st.total += 1;
            if decision == "error" {
                st.errors += 1;
                return Ok(None);
            }
            if !diverged {
                return Ok(None);
            }
            st.diverged += 1;
            if widening {
                st.widened += 1;
            } else {
                st.tightened += 1;
            }
        }
        let base = json!({"v": 1, "shadow_digest": digest, "enforced_digest": enforced_digest, "action_digest": action_digest, "enforced": enforced, "shadow": decision, "widening": widening, "at": at, "signer": self.signer()});
        let sig = sign_body(SHADOW_DIFF_DOMAIN, &pick_all(&base, &DIFF_KEYS)?, &self.secret)?;
        let mut diff = base;
        diff["sig"] = Value::String(sig);
        self.list.entry(digest).or_default().push(diff.clone());
        Ok(Some(diff))
    }

    pub fn stats(&self, digest: &str) -> ShadowStats {
        self.stat.get(digest).cloned().unwrap_or_default()
    }

    pub fn diffs(&self, digest: &str) -> Vec<Value> {
        self.list.get(digest).cloned().unwrap_or_default()
    }
}

fn sign_member(secret: &[u8; 32], e: &Value, who: &str, domain: &str, keys: &[&str]) -> Result<Value, String> {
    let mut m = Map::new();
    m.insert("v".to_string(), json!(1));
    for (k, v) in spread(e) {
        m.insert(k, v);
    }
    m.insert("principal".to_string(), Value::String(who.to_string()));
    let base = Value::Object(m);
    let sig = sign_body(domain, &pick_all(&base, keys)?, secret)?;
    let mut out = base;
    out["sig"] = Value::String(sig);
    Ok(out)
}

/// A principal states that this widening is intended (`reason_digest` binds the display-only reason text).
pub fn sign_widening_explanation(secret: &[u8; 32], e: &Value) -> Result<Value, String> {
    sign_member(secret, e, &signer_of(secret), WIDENING_EXPLANATION_DOMAIN, &EXP_KEYS)
}

/// A principal approves promoting `shadow_digest` over `enforced_digest`.
pub fn sign_promotion_approval(secret: &[u8; 32], a: &Value) -> Result<Value, String> {
    sign_member(secret, a, &signer_of(secret), PROMOTION_APPROVAL_DOMAIN, &AP_KEYS)
}

fn verify_explanation(e: &Value) -> bool {
    if !e.is_object()
        || !is_one(e.get("v"))
        || !(s(e.get("shadow_digest"), 128) && s(e.get("action_digest"), 128) && s(e.get("reason_digest"), 128) && s(e.get("principal"), 128))
    {
        return false;
    }
    verify_body_opt(WIDENING_EXPLANATION_DOMAIN, &pick(e, &EXP_KEYS), e["principal"].as_str().unwrap_or(""), e.get("sig").and_then(Value::as_str))
}

fn verify_approval(a: &Value) -> bool {
    if !a.is_object()
        || !is_one(a.get("v"))
        || !(s(a.get("shadow_digest"), 128) && s(a.get("enforced_digest"), 128))
        || nat(a.get("at")).is_none()
        || !s(a.get("principal"), 128)
    {
        return false;
    }
    verify_body_opt(PROMOTION_APPROVAL_DOMAIN, &pick(a, &AP_KEYS), a["principal"].as_str().unwrap_or(""), a.get("sig").and_then(Value::as_str))
}

fn no(code: &str, reason: &str, unexplained: &[String]) -> Value {
    let mut o = json!({"ok": false, "code": code, "reason": reason});
    if !unexplained.is_empty() {
        o["unexplained"] = json!(unexplained);
    }
    o
}

/// May this candidate be promoted? Enough samples, no candidate failures, every diff verifies, zero unexplained widenings, and a
/// principal-signed approval when the static verdict on the declared surfaces is `wider` or `unknown`. Fails closed: a gate that cannot
/// be evaluated is `{ok: false, code: "bad_input"}`.
pub fn promotion_gate(log: &ShadowLog, o: &Value) -> Value {
    let principals = o.get("principals").and_then(Value::as_array);
    let surface = o.get("surface").and_then(Value::as_str);
    let min_samples = nat(o.get("minSamples"));
    let (Some(principals), Some(min_samples), Some(surface)) =
        (principals, min_samples.filter(|n| *n >= 1), surface.filter(|x| matches!(*x, "narrower" | "equal" | "wider" | "unknown")))
    else {
        return no("bad_input", "bad gate options", &[]);
    };
    if !s(o.get("shadow_digest"), 128) || !s(o.get("enforced_digest"), 128) {
        return no("bad_input", "bad gate options", &[]);
    }
    let sd = o["shadow_digest"].as_str().unwrap_or("");
    let ed = o["enforced_digest"].as_str().unwrap_or("");
    let st = log.stats(sd);
    if st.total < min_samples {
        return no("too_few_samples", &format!("{} observation(s), need {}", st.total, min_samples), &[]);
    }
    if st.errors > 0 {
        return no("shadow_errors", &format!("{} observation(s) where the candidate failed", st.errors), &[]);
    }
    let diffs = log.diffs(sd);
    let signer = log.signer();
    let all_ok = diffs.iter().all(|d| verify_shadow_diff(d, Some(&signer)) && d["shadow_digest"] == sd && d["enforced_digest"] == ed);
    if !all_ok || diffs.len() as i64 != st.diverged {
        return no("bad_diff", "a recorded diff does not verify, belongs to another pair, or is missing", &[]);
    }
    let mut explained: HashSet<String> = HashSet::new();
    match o.get("explanations") {
        None | Some(Value::Null) | Some(Value::String(_)) => {}
        Some(Value::Array(list)) => {
            for e in list {
                let principal = e.get("principal").and_then(Value::as_str).unwrap_or("");
                if verify_explanation(e) && principals.iter().any(|p| p.as_str() == Some(principal)) && e["shadow_digest"] == sd {
                    explained.insert(e["action_digest"].as_str().unwrap_or("").to_string());
                }
            }
        }
        // a value the reference cannot iterate: its TypeError is caught and fails closed
        Some(_) => return no("bad_input", "evaluation error (fail closed)", &[]),
    }
    let mut unexplained: Vec<String> = diffs
        .iter()
        .filter(|d| d["widening"] == true)
        .filter_map(|d| d["action_digest"].as_str())
        .filter(|a| !explained.contains(*a))
        .map(String::from)
        .collect::<HashSet<String>>()
        .into_iter()
        .collect();
    unexplained.sort_by_key(|x| u16key(x));
    if !unexplained.is_empty() {
        return no("unexplained_widening", &format!("{} widening(s) without a principal's explanation", unexplained.len()), &unexplained);
    }
    if surface == "wider" || surface == "unknown" {
        let ok = o.get("approval").is_some_and(|a| {
            let principal = a.get("principal").and_then(Value::as_str).unwrap_or("");
            verify_approval(a) && principals.iter().any(|p| p.as_str() == Some(principal)) && a["shadow_digest"] == sd && a["enforced_digest"] == ed
        });
        if !ok {
            let what = if surface == "wider" { "wider" } else { "not provably narrower" };
            return no(
                "advisory_wider",
                &format!("the analyzer reports the candidate {what} on the declared surfaces: a principal-signed approval is required"),
                &[],
            );
        }
    }
    let widenings = diffs.iter().filter(|d| d["widening"] == true).count();
    json!({"ok": true, "samples": st.total, "widenings": widenings, "surface": surface})
}

/// The body of the bundle revision that makes the candidate the enforced policy: its content at revision + 1, chained to the enforced
/// revision, with the shadow list cleared. Needs a passing gate for this candidate, and the candidate must be listed in the enforced
/// revision's `shadow`. Sign it with [`crate::grants::sign_bundle`] / [`crate::grants::assemble_bundle`] like any revision.
pub fn promote_shadow(enforced: &Value, candidate: &Value, gate: &Value, now: &Value) -> Result<Value, String> {
    let digest = bundle_digest(candidate);
    if gate.get("ok") != Some(&Value::Bool(true)) {
        let code = gate.get("code").and_then(Value::as_str).unwrap_or("undefined");
        return Err(format!("promoteShadow: the gate did not pass ({code})"));
    }
    let listed = enforced.get("shadow").and_then(Value::as_array).is_some_and(|l| digest.as_deref().is_some_and(|d| l.iter().any(|x| x.as_str() == Some(d))));
    if !listed {
        return Err("promoteShadow: the candidate is not listed in the enforced revision's shadow".to_string());
    }
    if nat(Some(now)).is_none() {
        return Err("promoteShadow: bad time".to_string());
    }
    let revision = nat(enforced.get("revision")).ok_or("promoteShadow: the enforced revision has no revision number")? + 1;
    let prev = bundle_digest(enforced).ok_or("promoteShadow: the enforced revision is not a bundle")?;
    let mut out = spread(&without(candidate, &["sigs", "shadow", "prev"]));
    out.insert("revision".to_string(), json!(revision));
    out.insert("prev".to_string(), Value::String(prev));
    out.insert("issued_at".to_string(), now.clone());
    Ok(Value::Object(out))
}
