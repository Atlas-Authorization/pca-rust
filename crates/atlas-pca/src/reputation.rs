//! Reputation and coverage pricing (port of `reputation.ts` and `reputation-evidence.ts`): an explainable score from observed
//! outcomes (deny rate, step-up rate, slashed disputes), a transparent underwriting curve on top of it, signed coverage quotes
//! whose premium a verifier recomputes, and disputes derived only from guardian-signed settlement records.
//!
//! Advisory by construction: nothing in the verifier or `authorize` reads a reputation, and none should be wired into an allow
//! decision. What is guaranteed: the score is a pure deterministic function of validated input (malformed input scores 0 and
//! says why; a dispute counts once per unique `id`; a dispute for another subject is invalid), and a quote is signed and
//! re-derivable.
//!
//! JSON-valued (`&Value` in, the reference's member names out). A reference throw is an `Err`; the verifiers are total.
use serde_json::{json, Value};

use crate::agent::KeyPair;
use crate::doctor::js_to_fixed;
use crate::intent_v2::js_number_string;
use crate::prohibitions::num_value;

/// The most events, and the most disputes, one input may carry.
pub const MAX_REPUTATION_RECORDS: usize = 100_000;
/// Domain separator of a signed coverage quote (it ends in a NUL byte).
pub const COVERAGE_QUOTE_DOMAIN: &str = "atlas-pca/coverage-quote/v1\0";

const OUTCOMES: [&str; 4] = ["auto", "step_up", "deny", "executed"];

/// A finite JSON number.
fn finite(v: Option<&Value>) -> Option<f64> {
    v.filter(|n| n.is_number()).and_then(Value::as_f64).filter(|f| f.is_finite())
}

/// The member as an array: absent is empty, anything else that is not an array is `None`.
fn list<'a>(input: &'a Value, key: &str) -> Option<&'a [Value]> {
    match input.get(key) {
        None => Some(&[]),
        Some(v) => v.as_array().map(Vec::as_slice),
    }
}

/// Why `input` (`{subject, events?, disputes?}`) is unusable, or `None`.
pub fn validate_reputation_input(input: &Value) -> Option<String> {
    let subject = input.get("subject").and_then(Value::as_str).filter(|s| !s.is_empty());
    let Some(subject) = subject else {
        return Some("subject must be a non-empty string".into());
    };
    let (Some(events), Some(disputes)) = (list(input, "events"), list(input, "disputes")) else {
        return Some("events and disputes must be arrays".into());
    };
    if events.len() > MAX_REPUTATION_RECORDS || disputes.len() > MAX_REPUTATION_RECORDS {
        return Some("too many records".into());
    }
    if events.iter().any(|e| !e.get("outcome").and_then(Value::as_str).is_some_and(|o| OUTCOMES.contains(&o))) {
        return Some("event with an unknown outcome".into());
    }
    for d in disputes {
        if !d.get("id").and_then(Value::as_str).is_some_and(|id| !id.is_empty()) {
            return Some("dispute without an id".into());
        }
        if d.get("subject").and_then(Value::as_str) != Some(subject) {
            return Some("dispute for another subject".into());
        }
        if !d.get("slashed").is_some_and(Value::is_boolean) {
            return Some("dispute.slashed must be a boolean".into());
        }
        if !finite(d.get("at")).is_some_and(|at| at >= 0.0) {
            return Some("dispute.at must be finite and >= 0".into());
        }
        if d.get("amount").is_some() && !finite(d.get("amount")).is_some_and(|a| a >= 0.0) {
            return Some("dispute.amount must be finite and >= 0".into());
        }
    }
    None
}

fn report(subject: &str, counts: [usize; 6], score: f64, factors: Vec<String>) -> Value {
    let [actions, autos, step_ups, denies, slashes, disputes] = counts;
    json!({"subject": subject, "actions": actions, "autos": autos, "stepUps": step_ups, "denies": denies, "slashes": slashes,
        "disputes": disputes, "score": num_value(score), "factors": factors})
}

/// The reputation of `input.subject`: `{subject, actions, autos, stepUps, denies, slashes, disputes, score, factors}`. The score
/// starts at 1 and loses 0.6 times the deny rate, 0.15 times the step-up rate and 0.3 per slashed dispute (at most 0.8), clamped
/// to [0, 1]. No history scores a neutral 0.5; unusable input scores 0 and the factor says why (it never throws).
pub fn reputation(input: &Value) -> Value {
    if let Some(bad) = validate_reputation_input(input) {
        // fail closed: unusable input is the lowest score, never the neutral "unproven" 0.5
        let subject = input.get("subject").filter(|s| !s.is_null()).map(crate::adapters::js_string).unwrap_or_default();
        return report(&subject, [0; 6], 0.0, vec![format!("invalid input: {bad}")]);
    }
    let subject = input["subject"].as_str().unwrap_or("");
    let events = list(input, "events").unwrap_or(&[]);
    let mut seen: Vec<&str> = Vec::new();
    let mut slashes = 0usize;
    for d in list(input, "disputes").unwrap_or(&[]) {
        let id = d["id"].as_str().unwrap_or("");
        if !seen.contains(&id) {
            seen.push(id);
            slashes += usize::from(d["slashed"] == true);
        }
    }
    let count = |o: &str| events.iter().filter(|e| e["outcome"] == o).count();
    let (actions, autos, step_ups, denies) = (events.len(), count("auto"), count("step_up"), count("deny"));
    let counts = [actions, autos, step_ups, denies, slashes, seen.len()];
    if actions == 0 && seen.is_empty() {
        return report(subject, counts, 0.5, vec!["unproven (no history)".into()]);
    }
    let mut score = 1.0f64;
    let mut factors = Vec::new();
    if actions > 0 {
        let deny_rate = denies as f64 / actions as f64;
        let step_up_rate = step_ups as f64 / actions as f64;
        if deny_rate > 0.0 {
            score -= 0.6 * deny_rate;
            factors.push(format!("deny rate {}%", js_to_fixed(deny_rate * 100.0, 0)));
        }
        if step_up_rate > 0.0 {
            score -= 0.15 * step_up_rate;
            factors.push(format!("step-up rate {}%", js_to_fixed(step_up_rate * 100.0, 0)));
        }
    }
    // slashes dominate: each one is a heavy, saturating penalty
    if slashes > 0 {
        let penalty = 0.3 * slashes as f64;
        score -= if penalty < 0.8 { penalty } else { 0.8 };
        factors.push(format!("{slashes} slashed dispute{}", if slashes > 1 { "s" } else { "" }));
    }
    if factors.is_empty() {
        factors.push("clean history".into());
    }
    report(subject, counts, score.clamp(0.0, 1.0), factors)
}

// ---- underwriting -------------------------------------------------------------------------------------------------------------

/// Underwriting parameters: the premium per unit exposure at a perfect reputation (default 0.01), how steeply a poor reputation
/// raises it (default 4) and the score below which coverage is declined (default 0.25).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PricingOptions {
    pub base_rate: Option<f64>,
    pub risk_load: Option<f64>,
    pub min_score: Option<f64>,
}

struct Pricing {
    declined: bool,
    premium: f64,
    coverage: f64,
    rationale: String,
}

impl Pricing {
    fn to_json(&self) -> Value {
        json!({"declined": self.declined, "premium": num_value(self.premium), "coverage": num_value(self.coverage), "rationale": self.rationale})
    }
}

fn price(score: f64, exposure: f64, base_rate: f64, risk_load: f64, min_score: f64) -> Pricing {
    let declined = |rationale: String| Pricing { declined: true, premium: 0.0, coverage: 0.0, rationale };
    if !score.is_finite() || !(0.0..=1.0).contains(&score) {
        return declined("invalid reputation score".into());
    }
    // a non-finite exposure would quote a nonsensical price: it covers nothing
    let exp = if exposure.is_finite() && exposure > 0.0 { exposure } else { 0.0 };
    if score < min_score {
        return declined(format!("reputation {} below underwriting floor {}", js_to_fixed(score, 2), js_number_string(min_score)));
    }
    let load = 1.0 + risk_load * (1.0 - score);
    Pricing {
        declined: false,
        premium: base_rate * exp * load,
        coverage: exp,
        rationale: format!(
            "base {} \u{d7} exposure {} \u{d7} load {} (score {})",
            js_number_string(base_rate),
            js_number_string(exp),
            js_to_fixed(load, 2),
            js_to_fixed(score, 2)
        ),
    }
}

/// `priceCoverage({score}, exposure, opts)`: `{declined, premium, coverage, rationale}`. The premium is
/// `baseRate * exposure * (1 + riskLoad * (1 - score))`; coverage is declined for a score outside [0, 1] (NaN included) or below
/// the floor. A negative or non-finite exposure covers 0.
pub fn price_coverage(score: f64, exposure: f64, opts: &PricingOptions) -> Value {
    price(score, exposure, opts.base_rate.unwrap_or(0.01), opts.risk_load.unwrap_or(4.0), opts.min_score.unwrap_or(0.25)).to_json()
}

// ---- signed coverage quotes ---------------------------------------------------------------------------------------------------

fn quote_message(claim: &Value) -> Vec<u8> {
    [COVERAGE_QUOTE_DOMAIN.as_bytes(), crate::canonicalize(claim).as_bytes()].concat()
}

/// Prices and signs a quote for the reputation `rep` (`{subject, score, ..}`): the claim `{v: 1, subject, score, exposure,
/// baseRate, riskLoad, minScore, declined, premium, coverage, issued_at, expires_at, underwriter}` plus `sig`. `Err` for a bad
/// score, subject, expiry or exposure, and for a premium that is not finite: a nonsense quote is never signed.
pub fn issue_coverage_quote(rep: &Value, exposure: f64, underwriter: &KeyPair, now: f64, ttl_ms: f64, opts: &PricingOptions) -> Result<Value, String> {
    if !exposure.is_finite() || exposure < 0.0 {
        return Err("issueCoverageQuote: exposure must be finite and >= 0".into());
    }
    if !now.is_finite() || !(ttl_ms > 0.0) || !ttl_ms.is_finite() {
        return Err("issueCoverageQuote: now and ttlMs must be finite, ttlMs > 0".into());
    }
    let score = finite(rep.get("score")).filter(|s| (0.0..=1.0).contains(s)).ok_or("issueCoverageQuote: invalid reputation score")?;
    let subject = rep.get("subject").and_then(Value::as_str).ok_or("issueCoverageQuote: the reputation names no subject")?;
    let (base_rate, risk_load, min_score) = (opts.base_rate.unwrap_or(0.01), opts.risk_load.unwrap_or(4.0), opts.min_score.unwrap_or(0.25));
    let p = price(score, exposure, base_rate, risk_load, min_score);
    let numbers = [score, exposure, base_rate, risk_load, min_score, p.premium, p.coverage, now, now + ttl_ms];
    if numbers.iter().any(|n| !n.is_finite()) {
        return Err("issueCoverageQuote: the quote carries a number that is not finite".into());
    }
    let mut quote = json!({"v": 1, "subject": subject, "score": num_value(score), "exposure": num_value(exposure), "baseRate": num_value(base_rate),
        "riskLoad": num_value(risk_load), "minScore": num_value(min_score), "declined": p.declined, "premium": num_value(p.premium),
        "coverage": num_value(p.coverage), "issued_at": num_value(now), "expires_at": num_value(now + ttl_ms), "underwriter": underwriter.public});
    quote["sig"] = json!(crate::b64_encode(&underwriter.sign(&quote_message(&quote))));
    Ok(quote)
}

/// Verifies a quote: `{ok: true}` or `{ok: false, reason}` with `malformed`, `underwriter` (not the pinned key), `signature`,
/// `not-yet-valid`, `expired` or `price-mismatch` (the premium is recomputed from the stated inputs). Total.
pub fn verify_coverage_quote(quote: &Value, underwriter: &str, now: f64) -> Value {
    let no = |reason: &str| json!({"ok": false, "reason": reason});
    let Some(q) = quote.as_object() else { return no("malformed") };
    let (Some(sig), true) = (q.get("sig").and_then(Value::as_str), finite(q.get("v")) == Some(1.0)) else {
        return no("malformed");
    };
    let n = |k: &str| finite(q.get(k));
    let (Some(score), Some(exposure), Some(base_rate), Some(risk_load), Some(min_score), Some(premium), Some(coverage), Some(issued), Some(expires)) =
        (n("score"), n("exposure"), n("baseRate"), n("riskLoad"), n("minScore"), n("premium"), n("coverage"), n("issued_at"), n("expires_at"))
    else {
        return no("malformed");
    };
    let (Some(declined), true) = (q.get("declined").and_then(Value::as_bool), q.get("subject").is_some_and(Value::is_string)) else {
        return no("malformed");
    };
    if q.get("underwriter").and_then(Value::as_str) != Some(underwriter) {
        return no("underwriter");
    }
    let mut claim = q.clone();
    claim.remove("sig");
    if !crate::verify_b64u(underwriter, &quote_message(&Value::Object(claim)), sig) {
        return no("signature");
    }
    if !now.is_finite() || now < issued {
        return no("not-yet-valid");
    }
    if !(now < expires) {
        return no("expired");
    }
    let p = price(score, exposure, base_rate, risk_load, min_score);
    if p.declined != declined || p.premium != premium || p.coverage != coverage {
        return no("price-mismatch");
    }
    json!({"ok": true})
}

// ---- disputes from signed settlement records ----------------------------------------------------------------------------------

/// Derives disputes only from guardian-signed settlement records: `{disputes: [{id, subject, slashed, at, amount}], rejected}`.
/// `subject_of` maps a bond / claim handle to the subject it was posted for (`None` = unknown). A record of an unknown handle,
/// or whose signature does not verify under `guardian_public` (and the post-quantum `pins`), is counted in `rejected`, never as
/// a dispute; an `open` record is not an outcome. The dispute id is the settlement record digest.
pub fn disputes_from_settlements(records: &[Value], guardian_public: &str, subject_of: impl Fn(&str) -> Option<String>, pins: Option<&Value>) -> Value {
    let mut disputes = Vec::new();
    let mut rejected = 0usize;
    for r in records {
        let subject = r.get("claimId").and_then(Value::as_str).and_then(&subject_of);
        let Some(subject) = subject.filter(|_| crate::bond_settlement::verify_settlement(r, guardian_public, pins)) else {
            rejected += 1;
            continue;
        };
        if r["action"] == "open" {
            continue;
        }
        let mut d = json!({"id": crate::bond_settlement::settlement_record_digest(r), "subject": subject, "slashed": r["action"] == "slash"});
        for k in ["at", "amount"] {
            if let Some(v) = r.get(k) {
                d[k] = v.clone();
            }
        }
        disputes.push(d);
    }
    json!({"disputes": disputes, "rejected": rejected})
}
