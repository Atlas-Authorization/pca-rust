//! Risk-adaptive threshold signatures (`threshold.ts`): a t-of-n co-signature over a PCActn, where each role (`agent`, `guardian`,
//! `principal`) signs a share bound to its role, the signer set, the threshold and the suite. The share signers are in
//! [`crate::signers_more`] ([`crate::signers_more::sign_threshold_share`]); the per-share check is [`crate::verify_threshold_share`];
//! this module is the t-of-n verifier ([`verify_threshold`]) and the `threshold` hook for [`crate::authorize`]
//! ([`create_threshold_verifier`]).
//!
//! A signer set is `[{role, publicKey, pq_pk?}]` and a threshold signature `{shares: [...]}`.

use crate::authorize::HookResult;
use crate::{b64_encode, decode_b64u_strict, verify_b64u, verify_threshold_share};
use serde_json::{json, Value};
use std::collections::HashMap;

const ROLES: [&str; 3] = ["agent", "guardian", "principal"];
const PQ_PK_LENGTHS: [usize; 7] = [1952, 2592, 32, 64, 897, 1793, 97484];

fn show(v: &Value) -> String {
    match v {
        Value::Array(_) => "<array>".into(),
        Value::Object(_) => "<object>".into(),
        other => crate::intent_v2::js_value_string(other),
    }
}

fn is_pq_pk(v: &Value) -> bool {
    v.as_str().and_then(|s| decode_b64u_strict(s, None)).is_some_and(|b| PQ_PK_LENGTHS.contains(&b.len()))
}

/// Collect shares into a threshold signature `{shares: [...]}`.
pub fn assemble_threshold(shares: &[Value]) -> Value {
    json!({"shares": shares})
}

fn verdict(ok: bool, count: usize, roles: &[String], reason: Option<String>) -> Value {
    let mut v = json!({"ok": ok, "count": count, "roles": roles});
    if let Some(r) = reason {
        v["reason"] = json!(r);
    }
    v
}

/// The agent-leaf baseline's own signature over the bare threshold message. Counts only an Ed25519 leaf, or a leaf under the suite whose
/// post-quantum key the signer set REGISTERS for the agent (never a key the leaf names itself): any other baseline is not counted
/// (fail closed).
fn baseline_ok(b: &Value, message: &[u8], registered_pq: Option<&str>) -> bool {
    let holder = match b.get("holder").and_then(Value::as_str) {
        Some(h) => h,
        None => return false,
    };
    let alg = b.get("alg");
    let ed = alg.is_none_or(|a| a.as_str() == Some("ed25519"));
    match (ed, registered_pq) {
        (true, None) => b.get("pq_pk").is_none() && b.get("pq_sig").is_none() && b.get("sig").and_then(Value::as_str).is_some_and(|s| verify_b64u(holder, message, s)),
        (false, Some(rq)) => match crate::pinned::PinnedPq::caller_vouched(rq) {
            Some(k) => crate::verify_suite(alg, holder, Some(&k), message, b.get("sig"), b.get("pq_sig")),
            None => false,
        },
        _ => false, // an agent that registers a PQ key needs a PQ leaf; an unregistered PQ leaf is unbound here
    }
}

/// Verify a t-of-n multi-signature over `message` (the PCActn's [`crate::threshold_message`]): `{ok, count, roles, reason?}`.
///
/// The signer set is validated FIRST and the verification fails closed if it is malformed (every role known, one key per role, one role
/// per key, well-formed keys); `t` must be 1, 2 or 3. A share counts iff its role and key are registered and its signature verifies over
/// that role's signer-set and t-bound share message (a bare agent share is rejected); the count is of DISTINCT keys. `baseline`
/// (`{holder, sig, alg?, pq_pk?, pq_sig?}`) admits the PCActn leaf signature as the agent's effective-t=1 share. Total: never panics.
pub fn verify_threshold(sig: &Value, message: &[u8], signer_set: &Value, t: &Value, baseline: Option<&Value>) -> Value {
    let none: Vec<String> = Vec::new();
    let tt = match t.as_f64().filter(|f| t.is_number() && [1.0, 2.0, 3.0].contains(f)) {
        Some(f) => f as i64,
        None => return verdict(false, 0, &none, Some(format!("invalid threshold t={} (must be 1, 2 or 3)", show(t)))),
    };
    let st: &[Value] = signer_set.as_array().map(Vec::as_slice).unwrap_or(&[]);
    let mut reg: HashMap<&str, &str> = HashMap::new();
    let mut pq_of: HashMap<&str, Option<&str>> = HashMap::new();
    let mut seen: HashMap<(&str, &str), Option<&str>> = HashMap::new();
    for s in st {
        let o = s.as_object();
        let role = o.and_then(|o| o.get("role")).and_then(Value::as_str).filter(|r| ROLES.contains(r));
        let key = o.and_then(|o| o.get("publicKey")).and_then(Value::as_str).filter(|k| decode_b64u_strict(k, Some(32)).is_some());
        let (role, key) = match (role, key) {
            (Some(r), Some(k)) => (r, k),
            _ => return verdict(false, 0, &none, Some("malformed signer set".into())),
        };
        let o = o.expect("object checked");
        let mut pq_ok = o.get("pq_pk").is_none_or(is_pq_pk);
        let pq = o.get("pq_pk").and_then(Value::as_str);
        if pq_ok {
            match seen.get(&(role, key)) {
                Some(prev) if *prev != pq => pq_ok = false,
                _ => {
                    seen.insert((role, key), pq);
                }
            }
        }
        if !pq_ok {
            return verdict(false, 0, &none, Some("malformed signer set (pq_pk)".into()));
        }
        if reg.get(role).is_some_and(|k| *k != key) {
            return verdict(false, 0, &none, Some(format!("signer set registers more than one key for role {role}")));
        }
        if reg.iter().any(|(r, k)| *k == key && *r != role) {
            return verdict(false, 0, &none, Some("signer set registers one key under two roles".into()));
        }
        if !reg.contains_key(role) {
            reg.insert(role, key);
            pq_of.insert(role, pq);
        }
    }
    let empty = Vec::new();
    let shares = sig.get("shares").and_then(Value::as_array).unwrap_or(&empty);
    let (mut keys, mut roles): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    let mut reason: Option<String> = None;
    let mut first = |r: String| {
        if reason.is_none() {
            reason = Some(r);
        }
    };
    let tm = b64_encode(message);
    for share in shares {
        let (srole, spk) = match (share.get("role"), share.get("publicKey")) {
            (Some(Value::String(r)), Some(Value::String(k))) => (r.as_str(), k.as_str()),
            _ => {
                first("malformed share".into());
                continue;
            }
        };
        if keys.iter().any(|k| k == spk) {
            continue;
        }
        let role = ROLES.iter().find(|r| **r == srole).copied();
        let reg_key = role.and_then(|r| reg.get(r).copied());
        let Some(reg_key) = reg_key else {
            first(format!("role {srole} is not in the signer set"));
            continue;
        };
        if reg_key != spk {
            first(format!("share for role {srole} uses a key not registered for that role"));
            continue;
        }
        let role = role.unwrap_or_default();
        if let Some(a) = share.get("alg") {
            if crate::resolve_sig_alg(Some(a)).is_none() {
                first(format!("share for role {srole} declares an unknown signature alg"));
                continue;
            }
        }
        if let Some(p) = share.get("pq_pk") {
            if !(p.as_str().is_some() && p.as_str() == pq_of.get(role).copied().flatten()) {
                first(format!("share for role {srole} names a pq_pk that is not the key its role registers"));
                continue;
            }
        }
        let entry = json!({"role": srole, "t": tt, "signer_set": signer_set, "threshold_message": tm, "share": share});
        if !verify_threshold_share(&entry) {
            first(format!("invalid signature for role {srole}"));
            continue;
        }
        keys.push(spk.to_string());
        roles.push(role.to_string());
    }
    if let (Some(b), Some(agent)) = (baseline, reg.get("agent")) {
        if !roles.iter().any(|r| r == "agent") && b.get("holder").and_then(Value::as_str) == Some(agent) && baseline_ok(b, message, pq_of.get("agent").copied().flatten())
        {
            keys.push((*agent).to_string());
            roles.push("agent".into());
        }
    }
    let count = keys.len();
    if count as i64 >= tt {
        return verdict(true, count, &roles, None);
    }
    verdict(false, count, &roles, Some(reason.unwrap_or_else(|| format!("only {count} distinct valid key(s), need {tt}"))))
}

/// The `threshold` hook for [`crate::authorize`]: it recomputes the PCActn's threshold message, verifies the explicit shares in
/// `pcactn.threshold`, admits the PCActn leaf signature as the agent's effective-t=1 baseline, and reports the `t` it enforced.
///
/// Exactly one of `t` (fixed by the server) / `required_t` (`ctx -> t` from SERVER-held data only, never from the PCActn's `risk_claim`;
/// `ctx` is `{pcactn, grant, now}`) is mandatory: a default derived from the agent's own claim would let a compromised agent claim r=0.
/// The assurance label of the scheme (multisig, frost, frost_dkg, mpc) is declared through `AuthorizeOptions::with_assurance_hooks`.
pub fn create_threshold_verifier(
    signer_set: Vec<Value>,
    t: Option<i64>,
    required_t: Option<Box<dyn Fn(&Value) -> i64 + Send + Sync>>,
) -> Result<impl Fn(&Value, &Value, i64) -> HookResult + Send + Sync + 'static, String> {
    if t.is_none() && required_t.is_none() {
        return Err(
            "create_threshold_verifier: supply `t` or `required_t` derived from SERVER-held data (the agent's risk_claim is never a source for the threshold)".into()
        );
    }
    let ss = Value::Array(signer_set);
    Ok(move |p: &Value, grant: &Value, now: i64| {
        let want = match (&required_t, t) {
            (Some(f), _) => f(&json!({"pcactn": p, "grant": grant, "now": now})),
            (None, Some(t)) => t,
            (None, None) => return HookResult::Enforced { ok: false, reason: Some("no threshold configured".into()), t: None },
        };
        let message = match p.as_object().map(crate::threshold_message) {
            Some(Ok(m)) => m,
            Some(Err(e)) => return HookResult::Enforced { ok: false, reason: Some(e), t: Some(want) },
            None => return HookResult::Enforced { ok: false, reason: Some("the PCActn is not an object".into()), t: Some(want) },
        };
        let explicit = p.get("threshold").and_then(|t| t.get("shares")).filter(|s| s.is_array()).cloned().unwrap_or_else(|| json!([]));
        let leaf = p.get("cap_chain").and_then(Value::as_array).and_then(|c| c.last());
        let baseline = match (leaf.and_then(|l| l.get("holder")).and_then(Value::as_str), p.get("sig").and_then(Value::as_str)) {
            (Some(holder), Some(sig)) => {
                let mut b = json!({"holder": holder, "sig": sig});
                for k in ["alg", "pq_pk", "pq_sig"] {
                    if let Some(v) = p.get(k) {
                        b[k] = v.clone();
                    }
                }
                Some(b)
            }
            _ => None,
        };
        let v = verify_threshold(&json!({"shares": explicit}), &message, &ss, &json!(want), baseline.as_ref());
        if v["ok"] == json!(true) {
            HookResult::Enforced { ok: true, reason: None, t: Some(want) }
        } else {
            HookResult::Enforced { ok: false, reason: Some(v["reason"].as_str().unwrap_or("threshold not met").to_string()), t: Some(want) }
        }
    })
}
