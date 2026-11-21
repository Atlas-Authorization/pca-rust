//! `pcactnCheapClaims`: the PCActn's `aud`, `iat` and `exp`, checked BEFORE any signature verification or metering.
//!
//! These fields are unauthenticated at that point, so a pass proves nothing; but a FAIL is final: the full verifier makes exactly the same
//! `audience` and `validity` decisions on the same fields, so a document refused here could never be admitted. A server refuses it without
//! touching a shared rate-limit bucket or doing any crypto. O(1).
use crate::consts::{PCACTN_MAX_LIFETIME_MS, PCACTN_MAX_SKEW_MS};
use crate::safe_int;
use serde_json::Value;

/// Which full-verifier check a [`pcactn_cheap_claims`] refusal corresponds to (`audience` or `validity`) and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheapClaimFailure {
    pub check: &'static str,
    pub reason: String,
}

fn fail(check: &'static str, reason: impl Into<String>) -> Option<CheapClaimFailure> {
    Some(CheapClaimFailure { check, reason: reason.into() })
}

/// `None` when `aud`, `iat` and `exp` pass. `audience` is this verifier's audience id (the hosted API passes the instance id); `now` is
/// epoch ms.
pub fn pcactn_cheap_claims(p: &Value, audience: &str, now: i64) -> Option<CheapClaimFailure> {
    if p.get("aud").and_then(Value::as_str).is_none_or(|a| a.is_empty() || a != audience) {
        return fail("audience", "aud does not match this resource server / instance");
    }
    let (Some(iat), Some(exp)) = (p.get("iat").and_then(safe_int), p.get("exp").and_then(safe_int)) else {
        return fail("validity", "iat and exp must be safe-integer epoch ms");
    };
    if exp <= iat {
        return fail("validity", "exp must be greater than iat");
    }
    if exp - iat > PCACTN_MAX_LIFETIME_MS {
        return fail("validity", format!("lifetime exceeds {PCACTN_MAX_LIFETIME_MS} ms"));
    }
    if iat > now.saturating_add(PCACTN_MAX_SKEW_MS) {
        return fail("validity", "iat is in the future (clock skew)");
    }
    if now > exp {
        return fail("validity", "the PCActn has expired");
    }
    None
}
