//! OAuth Transaction Tokens for a PCA custody chain: the chain as a nested RFC 8693 `sub` / `act` claim, issuing an EdDSA
//! transaction token (draft-11 `txntoken+jwt`, the default, or the legacy `txn_token+jwt` profile) and verifying one fail-closed
//! (canonical compact JWS, `typ`, `alg`, required claims, audience, clock, `tctx`, `rctx`, `act`, replay of `txn` / `jti`).
use crate::jose::{assert_canonical_compact_jws, check_jws_header, sign_ed25519_jws, validate_jwt_claims, JwtClaimsCheck};
use crate::oauth::truthy;
use serde_json::{json, Map, Value};

pub const TXN_TOKEN_TYP: &str = "txn_token+jwt";
pub const TXN_TOKEN_TYP_DRAFT_11: &str = "txntoken+jwt";
pub const MAX_TOKEN_CHARS: usize = 16384;
const DEFAULT_TTL_SEC: f64 = 120.0;

/// A refusal. `code` is `Some("replay_store_required")` for a verifier configured without replay protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxnTokenError {
    pub code: Option<&'static str>,
    pub message: String,
}

impl From<String> for TxnTokenError {
    fn from(message: String) -> Self {
        TxnTokenError { code: None, message }
    }
}

fn e(m: impl Into<String>) -> TxnTokenError {
    TxnTokenError { code: None, message: m.into() }
}

/// A JSON number as `JSON.stringify` writes it: integral values as integers.
fn num(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 {
        json!(f as i64)
    } else {
        serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)
    }
}

fn nonempty(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// The custody chain as a nested claim (`subActChain`): `sub` = the root issuer (principal), `act` = the holders, outermost the
/// root's holder, innermost the leaf's.
pub fn sub_act_chain(chain: &Value) -> Result<Value, String> {
    let Some(c) = chain.as_array().filter(|c| !c.is_empty()) else { return Err("subActChain: chain must be a non-empty CapabilityChain".into()) };
    let mut act: Option<Value> = None;
    for i in (0..c.len()).rev() {
        let Some(holder) = nonempty(c[i].get("holder")) else { return Err(format!("subActChain: hop {i} has no holder")) };
        act = Some(match act {
            Some(a) => json!({ "sub": holder, "act": a }),
            None => json!({ "sub": holder }),
        });
    }
    let Some(root) = nonempty(c[0].get("issuer")) else { return Err("subActChain: root hop has no issuer (principal)".into()) };
    Ok(match act {
        Some(a) => json!({ "sub": root, "act": a }),
        None => json!({ "sub": root }),
    })
}

/// The number of nested `act` levels (`actDepth`).
pub fn act_depth(claim: &Value) -> Result<usize, String> {
    if !(claim.is_object() || claim.is_array()) {
        return Err("actDepth: expected a sub/act claim object".into());
    }
    let (mut depth, mut cur) = (0, claim.get("act"));
    while truthy(cur) {
        depth += 1;
        cur = cur.and_then(|c| c.get("act"));
    }
    Ok(depth)
}

fn with_sub(sub: Option<&Value>, act: Option<Value>) -> Value {
    let mut m = Map::new();
    if let Some(s) = sub {
        m.insert("sub".into(), s.clone());
    }
    if let Some(a) = act {
        m.insert("act".into(), a);
    }
    Value::Object(m)
}

/// The reference's RFC 8693 re-nesting (`toRfc8693Act`): the actors in reverse nesting (the most recent actor outermost).
pub fn to_rfc8693_act(claim: &Value) -> Result<Value, String> {
    if claim.is_null() {
        return Err("toRfc8693Act: claim must not be null".into());
    }
    let mut actors = Vec::new();
    let mut c = claim.get("act");
    while truthy(c) {
        actors.push(c.and_then(|x| x.get("sub")).filter(|s| !s.is_null()).cloned());
        c = c.and_then(|x| x.get("act"));
    }
    let mut act: Option<Value> = None;
    for sub in actors {
        act = Some(with_sub(sub.as_ref(), act));
    }
    Ok(with_sub(claim.get("sub"), act))
}

/// What to issue (`toTransactionToken`). `now_sec` and `id` (the legacy `jti`, or the draft-11 `txn` when `txn` is not given)
/// are the caller's: pass the clock and a fresh random identifier.
#[derive(Debug, Clone)]
pub struct TxnIssue<'a> {
    pub profile: Option<&'a str>,
    pub scope: Option<&'a Value>,
    pub req_wl: Option<&'a Value>,
    pub txn: Option<&'a str>,
    pub trust_domain: Option<&'a Value>,
    pub chain: &'a Value,
    pub action: &'a Value,
    /// The 32-byte Ed25519 secret (seed).
    pub issuer_secret: &'a [u8],
    pub issuer: &'a Value,
    pub ttl_sec: Option<f64>,
    pub now_sec: i64,
    pub id: &'a str,
}

/// Issue an EdDSA transaction token for the chain and action.
pub fn to_transaction_token(a: &TxnIssue) -> Result<String, String> {
    let Some(issuer) = nonempty(Some(a.issuer)) else { return Err("toTransactionToken: `issuer` is required".into()) };
    let act = a.action;
    let (Some(verb), Some(resource), Some(aud)) = (act.get("verb").and_then(Value::as_str), act.get("resource").and_then(Value::as_str), act.get("aud").and_then(Value::as_str)) else {
        return Err("toTransactionToken: `action` must have string verb, resource and aud".into());
    };
    let custody = sub_act_chain(a.chain)?;
    let ttl = a.ttl_sec.unwrap_or(DEFAULT_TTL_SEC);
    if !ttl.is_finite() || ttl <= 0.0 {
        return Err("toTransactionToken: ttlSec must be > 0".into());
    }
    let seed: [u8; 32] = a.issuer_secret.try_into().map_err(|_| "toTransactionToken: a raw Ed25519 secret key must be 32 bytes".to_string())?;
    let draft = a.profile.unwrap_or("draft-11") == "draft-11";
    if a.profile.is_some_and(|p| p != "legacy") && !draft {
        return Err("toTransactionToken: profile must be legacy or draft-11".into());
    }
    let tctx = json!({ "verb": verb, "resource": resource, "aud": aud });
    let exp = a.now_sec as f64 + ttl;
    let mut c = Map::new();
    c.insert("tctx".into(), tctx);
    if let Some(x) = custody.get("act") {
        c.insert("act".into(), x.clone());
    }
    let typ = if draft {
        let scope = nonempty(a.scope).ok_or("toTransactionToken: draft-11 requires `scope`")?;
        let req_wl = nonempty(a.req_wl).ok_or("toTransactionToken: draft-11 requires `reqWl`")?;
        let td = match a.trust_domain.filter(|t| !t.is_null()) {
            Some(t) => t,
            None => &act["aud"],
        };
        let td = nonempty(Some(td)).ok_or("toTransactionToken: draft-11 requires a non-empty trust domain (aud)")?;
        c.insert("txn".into(), json!(a.txn.unwrap_or(a.id)));
        c.insert("scope".into(), json!(scope));
        c.insert("req_wl".into(), json!(req_wl));
        for (k, v) in [("iat", json!(a.now_sec)), ("iss", json!(issuer)), ("sub", custody["sub"].clone()), ("aud", json!(td)), ("exp", num(exp))] {
            c.insert(k.into(), v);
        }
        TXN_TOKEN_TYP_DRAFT_11
    } else {
        for (k, v) in [("iat", json!(a.now_sec)), ("iss", json!(issuer)), ("sub", custody["sub"].clone()), ("aud", json!(aud)), ("exp", num(exp)), ("jti", json!(a.id))] {
            c.insert(k.into(), v);
        }
        TXN_TOKEN_TYP
    };
    Ok(sign_ed25519_jws(&json!({ "alg": "EdDSA", "typ": typ }), &Value::Object(c), &seed))
}

/// How a transaction token is verified (`FromTransactionTokenOptions`).
#[derive(Default)]
pub struct FromTxnOptions<'a> {
    pub profile: Option<&'a str>,
    /// REQUIRED for draft-11: the trust domain this verifier serves.
    pub audience: Option<&'a str>,
    pub clock_tolerance_sec: Option<f64>,
    /// Unix seconds; default the clock.
    pub now_sec: Option<f64>,
    /// The replay store: `true` when the identifier was already seen (called with the id and `exp`).
    pub seen_txn: Option<&'a dyn Fn(&str, f64) -> bool>,
    /// Run without replay detection (must be explicit).
    pub replay_unchecked: bool,
}

/// A verified token: the custody chain, the PCA action (absent for an opaque draft-11 `tctx`), `tctx` and every claim.
#[derive(Debug, Clone)]
pub struct TxnVerified {
    pub chain: Value,
    pub action: Option<Value>,
    pub tctx: Value,
    pub claims: Value,
}

fn normalize_act(node: Option<&Value>) -> Result<Option<Value>, String> {
    let Some(n) = node else { return Ok(None) };
    let Some(o) = n.as_object() else { return Err("transaction token: malformed `act` claim".into()) };
    let Some(sub) = nonempty(o.get("sub")) else { return Err("transaction token: `act.sub` must be a non-empty string".into()) };
    Ok(Some(match normalize_act(o.get("act"))? {
        Some(inner) => json!({ "sub": sub, "act": inner }),
        None => json!({ "sub": sub }),
    }))
}

/// Verify a transaction token under the issuer's raw 32-byte Ed25519 public key (`fromTransactionToken`).
pub fn from_transaction_token(jwt: &Value, verify_key: &[u8], o: &FromTxnOptions) -> Result<TxnVerified, TxnTokenError> {
    let draft = o.profile.unwrap_or("draft-11") == "draft-11";
    if o.profile.is_some_and(|p| p != "legacy") && !draft {
        return Err(e("fromTransactionToken: profile must be legacy or draft-11"));
    }
    if draft && !o.audience.is_some_and(|a| !a.is_empty()) {
        return Err(e("fromTransactionToken: draft-11 requires opts.audience (the trust domain this verifier serves)"));
    }
    if o.seen_txn.is_none() && !o.replay_unchecked {
        return Err(TxnTokenError {
            code: Some("replay_store_required"),
            message: "fromTransactionToken: supply opts.seenTxn (a replay store) or set opts.replayCheck to 'unchecked'".into(),
        });
    }
    if jwt.as_str().is_some_and(|t| t.encode_utf16().count() > MAX_TOKEN_CHARS) {
        return Err(e("transaction token: token exceeds the size limit"));
    }
    let jws = assert_canonical_compact_jws(jwt, 3, crate::jose::DEFAULT_MAX_JWS_BYTES, true).map_err(e)?;
    let pk: [u8; 32] = verify_key.try_into().map_err(|_| e("fromTransactionToken: a raw Ed25519 public key must be 32 bytes"))?;
    check_jws_header(&jws.header, &["EdDSA"]).map_err(e)?;
    let input = format!("{}.{}", jws.segments[0], jws.segments[1]);
    let sig: Result<[u8; 64], _> = jws.bytes[2].as_slice().try_into();
    if !sig.is_ok_and(|s| crate::verify_ed25519_strict(&pk, input.as_bytes(), &s)) {
        return Err(e("signature verification failed"));
    }
    let p = jws.payload.clone().unwrap_or_default();
    let required: &[&str] = if draft { &["iat", "exp", "aud", "sub", "txn", "scope", "req_wl"] } else { &["exp"] };
    let check = JwtClaimsCheck {
        typ: Some(if draft { TXN_TOKEN_TYP_DRAFT_11 } else { TXN_TOKEN_TYP }),
        required,
        audience: o.audience,
        clock_tolerance: o.clock_tolerance_sec.unwrap_or(0.0),
        now_sec: o.now_sec.map(f64::floor).unwrap_or_else(crate::jose::now_unix_sec),
    };
    validate_jwt_claims(&jws.header, &p, &check).map_err(e)?;
    if draft {
        for k in ["txn", "scope", "req_wl"] {
            if nonempty(p.get(k)).is_none() {
                return Err(e(format!("transaction token: `{k}` must be a non-empty string")));
            }
        }
    }
    let Some(sub) = nonempty(p.get("sub")) else { return Err(e("transaction token: missing `sub` (root principal)")) };
    let Some(raw) = p.get("tctx").filter(|t| t.is_object()) else { return Err(e("transaction token: missing or malformed `tctx`")) };
    let uses_pca = ["verb", "resource", "aud"].iter().any(|k| raw.get(*k).is_some());
    let action = if !draft || uses_pca {
        match (raw.get("verb").and_then(Value::as_str), raw.get("resource").and_then(Value::as_str), raw.get("aud").and_then(Value::as_str)) {
            (Some(v), Some(r), Some(a)) => Some(json!({ "verb": v, "resource": r, "aud": a })),
            _ => return Err(e("transaction token: missing or malformed `tctx`")),
        }
    } else {
        None
    };
    if draft && p.get("rctx").is_some_and(|r| !r.is_object()) {
        return Err(e("transaction token: malformed `rctx`"));
    }
    let act = normalize_act(p.get("act"))?;
    if let Some(seen) = o.seen_txn {
        let id = nonempty(p.get(if draft { "txn" } else { "jti" })).ok_or_else(|| e("transaction token: no transaction identifier to check for replay"))?;
        if seen(id, p.get("exp").and_then(Value::as_f64).unwrap_or(f64::NAN)) {
            return Err(e("transaction token: replayed (transaction identifier already seen)"));
        }
    }
    let chain = match act {
        Some(a) => json!({ "sub": sub, "act": a }),
        None => json!({ "sub": sub }),
    };
    Ok(TxnVerified { chain, action, tctx: raw.clone(), claims: Value::Object(p) })
}
