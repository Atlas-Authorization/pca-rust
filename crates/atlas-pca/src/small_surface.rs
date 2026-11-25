//! Small pure helpers of the reference that sit between larger modules: the cheap PCActn claim check over an untyped clock, the agent caveat
//! context and the JSON-valued revocation-staleness policy validator.
use serde_json::{json, Map, Value};

use crate::pcactn_cheap::{pcactn_cheap_claims, CheapClaimFailure};
use crate::policy_vm::tool_call_of;
use crate::safe_int;

/// [`pcactn_cheap_claims`] with the verifier clock as an untyped value: a clock that is not a safe integer epoch-ms fails the `validity` check
/// (after the audience and the `iat` / `exp` shape checks, as the reference's validity decision does).
pub fn pcactn_cheap_claims_at(p: &Value, audience: &str, now: &Value) -> Option<CheapClaimFailure> {
    match safe_int(now) {
        Some(n) => pcactn_cheap_claims(p, audience, n),
        None => {
            // with a usable clock this reaches the same audience / shape verdicts; only a window that would otherwise pass hits the clock
            let probe = pcactn_cheap_claims(p, audience, p.get("iat").and_then(safe_int).unwrap_or(0));
            match probe {
                Some(f) if f.check == "audience" || f.reason.starts_with("iat and exp must be") => Some(f),
                _ => Some(CheapClaimFailure { check: "validity", reason: "the verifier clock is not a safe integer epoch-ms".into() }),
            }
        }
    }
}

/// The context agent caveats are evaluated in: the base context with the action and its derived tool call applied LAST (a caller-supplied
/// context can never forge them).
pub fn agent_caveat_context(base: &Value, action: &Value) -> Value {
    let mut m: Map<String, Value> = base.as_object().cloned().unwrap_or_default();
    m.insert("action".into(), action.clone());
    m.insert("toolCall".into(), tool_call_of(action));
    Value::Object(m)
}

/// `validateRevocationStaleness` over a JSON policy `{maxRevocationAgeMs?, staleness?: {irreversible?, rate_limited?, costly?}}`: every given
/// age must be a finite number above zero (a present `null` is not). `Err` names the first bad one.
pub fn validate_revocation_staleness_json(p: &Value) -> Result<(), String> {
    let check = |name: &str, v: Option<&Value>| -> Result<(), String> {
        match v {
            None => Ok(()),
            Some(x) if x.is_number() && x.as_f64().is_some_and(|f| f.is_finite() && f > 0.0) => Ok(()),
            Some(_) => Err(format!("{name} must be a positive number of milliseconds")),
        }
    };
    check("maxRevocationAgeMs", p.get("maxRevocationAgeMs"))?;
    let st = p.get("staleness").and_then(Value::as_object);
    for k in ["irreversible", "rate_limited", "costly"] {
        check(&format!("staleness.{k}"), st.and_then(|s| s.get(k)))?;
    }
    Ok(())
}

/// Used by the tests of this module and kept public for hosts that build a verdict by hand.
pub fn failure_json(f: Option<CheapClaimFailure>) -> Value {
    f.map_or(Value::Null, |f| json!({"check": f.check, "reason": f.reason}))
}
