//! Consistency tokens (`fresh_at`): a signed high-water mark of the verifier-side state (revocation epoch, ledger size,
//! budget version, policy revision + digest). A request that carries the newest token it holds is only decided against
//! state at least that new: a verifier that is behind answers `escalate: stale_state` (refresh and retry), never allow.
//!
//! The token is also a PCActn member (`fresh_at`, covered by the leaf signature); [`decide_fresh_at`] is the verifier's
//! `fresh_at` check. A side-carried token (a header next to the PCActn) is still read for one release through
//! [`FreshAtPolicy::side_carried`]. Verify-only and total: malformed input is a refusal, never a panic.
use crate::{
    canonicalize_strict, decode_b64u_strict, hash_canonical_strict, safe_int, verify_b64u,
};
use serde_json::{json, Map, Value};

/// Signing domain of a token (the NUL is part of it).
pub const FRESH_AT_DOMAIN: &str = "atlas-pca/fresh-at/v1\0";
/// Domain of the content address ([`fresh_at_digest`]).
pub const FRESH_AT_REF_DOMAIN: &str = "atlas-pca/fresh-at-ref/v1";

const NUMERIC: [&str; 4] = [
    "revocation_epoch",
    "ledger_tree_size",
    "budget_version",
    "policy_revision",
];
const MEMBER_KEYS: [&str; 10] = [
    "v",
    "scope",
    "revocation_epoch",
    "ledger_tree_size",
    "budget_version",
    "policy_revision",
    "policy_digest",
    "issued_at",
    "signer",
    "sig",
];
/// Tokens may be issued this far ahead of the verifier's clock.
const FUTURE_SKEW_MS: i128 = 60_000;

fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// A non-empty string of at most `max` UTF-16 code units.
fn is_str(v: Option<&Value>, max: usize) -> bool {
    v.and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty() && utf16_len(s) <= max)
}

/// A non-negative JSON safe integer.
fn nat(v: Option<&Value>) -> Option<i64> {
    v.and_then(safe_int).filter(|n| *n >= 0)
}

/// utf8(domain) || strictCanonical(body); `None` where the reference throws.
pub(crate) fn domain_bytes(domain: &str, body: &Value) -> Option<Vec<u8>> {
    let mut m = domain.as_bytes().to_vec();
    m.extend_from_slice(canonicalize_strict(body).ok()?.as_bytes());
    Some(m)
}

/// `sig` is a canonical 64-byte base64url signature by `signer` over domain || strictCanonical(body).
pub(crate) fn verify_body(domain: &str, body: &Value, signer: &str, sig: Option<&str>) -> bool {
    match (sig, domain_bytes(domain, body)) {
        (Some(sig), Some(msg)) => {
            decode_b64u_strict(sig, Some(64)).is_some() && verify_b64u(signer, &msg, sig)
        }
        _ => false,
    }
}

/// The verifier-side state counters a token orders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshAtState {
    pub revocation_epoch: i64,
    pub ledger_tree_size: i64,
    pub budget_version: i64,
    /// Revision of the policy bundle in force (orders policy states; digests alone are not ordered).
    pub policy_revision: i64,
    pub policy_digest: String,
}

impl FreshAtState {
    /// From `{revocation_epoch, ledger_tree_size, budget_version, policy_revision, policy_digest}`; `None` when malformed.
    pub fn from_json(v: &Value) -> Option<Self> {
        Some(Self {
            revocation_epoch: nat(v.get("revocation_epoch"))?,
            ledger_tree_size: nat(v.get("ledger_tree_size"))?,
            budget_version: nat(v.get("budget_version"))?,
            policy_revision: nat(v.get("policy_revision"))?,
            policy_digest: v.get("policy_digest")?.as_str()?.to_string(),
        })
    }

    fn counter(&self, k: &str) -> i64 {
        match k {
            "revocation_epoch" => self.revocation_epoch,
            "ledger_tree_size" => self.ledger_tree_size,
            "budget_version" => self.budget_version,
            _ => self.policy_revision,
        }
    }
}

/// Well formed and signed by `signer` over exactly its content. Never panics.
pub fn verify_fresh_at(t: &Value, signer: &str) -> bool {
    let o = match t.as_object() {
        Some(o) => o,
        None => return false,
    };
    if o.get("v").and_then(safe_int) != Some(1)
        || o.get("signer").and_then(Value::as_str) != Some(signer)
        || !is_str(o.get("scope"), 256)
        || !is_str(o.get("policy_digest"), 128)
        || nat(o.get("issued_at")).is_none()
        || NUMERIC.iter().any(|k| nat(o.get(*k)).is_none())
    {
        return false;
    }
    // the signed body is exactly these nine fields; anything else in the object is not covered
    let mut body = Map::new();
    for k in [
        "v",
        "scope",
        "revocation_epoch",
        "ledger_tree_size",
        "budget_version",
        "policy_revision",
        "policy_digest",
        "issued_at",
        "signer",
    ] {
        body.insert(k.to_string(), o[k].clone());
    }
    verify_body(
        FRESH_AT_DOMAIN,
        &Value::Object(body),
        signer,
        o.get("sig").and_then(Value::as_str),
    )
}

/// The content address a PCActn or request signs to bind the token it carried; `None` outside the strict JSON profile.
pub fn fresh_at_digest(t: &Value) -> Option<String> {
    hash_canonical_strict(&json!({"d": FRESH_AT_REF_DOMAIN, "t": t}))
}

/// Outcome of [`check_fresh_at`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreshAtVerdict {
    Ok,
    /// The verifier is behind the token on these counters: refresh and retry. Never an allow.
    Escalate {
        behind: Vec<&'static str>,
    },
    /// `bad_token`, `wrong_scope`, `token_from_the_future`, `token_too_old` or `policy_fork`.
    Deny(&'static str),
}

impl FreshAtVerdict {
    /// The conformance shape: `{decision:"ok"}`, `{decision:"escalate",code:"stale_state",behind:[..]}`, `{decision:"deny",code}`.
    pub fn to_json(&self) -> Value {
        match self {
            Self::Ok => json!({"decision": "ok"}),
            Self::Escalate { behind } => {
                json!({"decision": "escalate", "code": "stale_state", "behind": behind})
            }
            Self::Deny(code) => json!({"decision": "deny", "code": code}),
        }
    }
}

/// May the verifier decide against `local` for a request carrying `token`? Each step fails closed: signature and shape,
/// scope, issued in the future (more than 60 s of skew), token age, policy fork (same revision, different digest), then
/// any counter behind the token (`stale_state`, escalate).
pub fn check_fresh_at(
    token: &Value,
    local: &FreshAtState,
    signer: &str,
    scope: &str,
    now: i64,
    max_token_age_ms: Option<i64>,
) -> FreshAtVerdict {
    if !verify_fresh_at(token, signer) {
        return FreshAtVerdict::Deny("bad_token");
    }
    let n = |k: &str| nat(token.get(k)).unwrap_or(0);
    if token.get("scope").and_then(Value::as_str) != Some(scope) {
        return FreshAtVerdict::Deny("wrong_scope");
    }
    let issued = n("issued_at") as i128;
    let now = now as i128;
    if issued > now + FUTURE_SKEW_MS {
        return FreshAtVerdict::Deny("token_from_the_future");
    }
    if let Some(max) = max_token_age_ms {
        if now - issued > max as i128 {
            return FreshAtVerdict::Deny("token_too_old");
        }
    }
    if n("policy_revision") == local.policy_revision
        && token.get("policy_digest").and_then(Value::as_str) != Some(local.policy_digest.as_str())
    {
        return FreshAtVerdict::Deny("policy_fork");
    }
    let behind: Vec<&'static str> = NUMERIC
        .iter()
        .copied()
        .filter(|k| local.counter(k) < n(k))
        .collect();
    if behind.is_empty() {
        FreshAtVerdict::Ok
    } else {
        FreshAtVerdict::Escalate { behind }
    }
}

/// Wire shape of the `fresh_at` PCActn member: the problem, or `None`. Does NOT check the signature (that is the `fresh_at` check).
pub fn validate_fresh_at_wire(v: &Value) -> Option<String> {
    let o = match v.as_object() {
        Some(o) => o,
        None => return Some("'fresh_at' must be an object".into()),
    };
    for k in o.keys() {
        if !MEMBER_KEYS.contains(&k.as_str()) {
            return Some(format!("'fresh_at' has an unknown field '{k}'"));
        }
    }
    if o.get("v").and_then(safe_int) != Some(1) {
        return Some("'fresh_at.v' must be 1".into());
    }
    if !is_str(o.get("scope"), 256) || !is_str(o.get("policy_digest"), 128) {
        return Some("'fresh_at' scope and policy_digest must be non-empty strings".into());
    }
    for k in [
        "revocation_epoch",
        "ledger_tree_size",
        "budget_version",
        "policy_revision",
        "issued_at",
    ] {
        if nat(o.get(k)).is_none() {
            return Some(format!(
                "'fresh_at.{k}' must be a non-negative safe integer"
            ));
        }
    }
    if !o
        .get("signer")
        .and_then(Value::as_str)
        .is_some_and(|s| decode_b64u_strict(s, Some(32)).is_some())
    {
        return Some("'fresh_at.signer' is not canonical base64url (32 bytes)".into());
    }
    if !o
        .get("sig")
        .and_then(Value::as_str)
        .is_some_and(|s| decode_b64u_strict(s, Some(64)).is_some())
    {
        return Some("'fresh_at.sig' is not canonical base64url (64 bytes)".into());
    }
    None
}

/// Verifier-side configuration of the `fresh_at` check.
#[derive(Debug, Clone)]
pub struct FreshAtPolicy {
    /// The pinned token signer (base64url Ed25519 public key).
    pub signer: String,
    /// The scope this verifier decides for; a token for another scope is refused.
    pub scope: String,
    /// The verifier's OWN current state counters.
    pub local: FreshAtState,
    pub max_token_age_ms: Option<i64>,
    /// Every PCActn must carry (or have side-carried) a token; none is `escalate: ...` (refresh and retry).
    pub require: bool,
    /// The pre-member form: a token that travelled beside the PCActn. `Some` (even `Some(Null)`) means one was presented;
    /// it is read only when the PCActn has no member.
    pub side_carried: Option<Value>,
}

impl FreshAtPolicy {
    /// From the conformance shape `{signer, scope, local, max_token_age_ms?, require?, side_carried?}`; `None` when malformed.
    pub fn from_json(v: &Value) -> Option<Self> {
        Some(Self {
            signer: v.get("signer")?.as_str()?.to_string(),
            scope: v.get("scope")?.as_str()?.to_string(),
            local: FreshAtState::from_json(v.get("local")?)?,
            max_token_age_ms: v.get("max_token_age_ms").and_then(safe_int),
            require: v.get("require") == Some(&Value::Bool(true)),
            side_carried: v.get("side_carried").cloned(),
        })
    }
}

/// Outcome of [`decide_fresh_at`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreshAtCheck {
    /// Not reported: no member, no side-carried token, no `require` (the verdict is byte-identical to before).
    None,
    Pass,
    /// The reason after `fresh_at: `; a stale verifier starts it with `escalate:` (the decision fold turns it into escalate).
    Fail(String),
}

/// The verifier's `fresh_at` check. Reported only when the PCActn carries the member, a side-carried token is read, or the
/// policy requires one. A member with no policy fails closed.
pub fn decide_fresh_at(
    member: Option<&Value>,
    policy: Option<&FreshAtPolicy>,
    now: i64,
) -> FreshAtCheck {
    let policy = match policy {
        Some(p) => p,
        None => {
            return if member.is_some() {
                FreshAtCheck::Fail("the PCActn carries fresh_at but this verifier has no fresh_at policy (fail closed)".into())
            } else {
                FreshAtCheck::None
            }
        }
    };
    let token = match member.or(policy.side_carried.as_ref()) {
        Some(t) => t,
        None if policy.require => {
            return FreshAtCheck::Fail("escalate: a consistency token is required (refresh and retry with the token of your latest write)".into())
        }
        None => return FreshAtCheck::None,
    };
    match check_fresh_at(
        token,
        &policy.local,
        &policy.signer,
        &policy.scope,
        now,
        policy.max_token_age_ms,
    ) {
        FreshAtVerdict::Ok => FreshAtCheck::Pass,
        FreshAtVerdict::Escalate { behind } => FreshAtCheck::Fail(format!(
            "escalate: stale_state (verifier state is behind the token on {})",
            behind.join(", ")
        )),
        FreshAtVerdict::Deny(code) => FreshAtCheck::Fail(code.to_string()),
    }
}
