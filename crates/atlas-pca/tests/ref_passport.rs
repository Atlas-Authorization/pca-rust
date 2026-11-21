//! Differential replay of test-data/ref-passport.json.gz (written by the TypeScript reference): the identity fingerprint and issuing,
//! the binding match, the registry, the trust score, the evidence binding, signing (ed25519 / ML-DSA / hybrid), verification with
//! revocation and hardware evidence, and the assurance label. Every function of the corpus has a handler and the per-function totals are
//! asserted. A reference refusal must be a refusal here. The 1 passport the reference accepts only through its legacy unbound
//! post-quantum opt-out is asserted REFUSED.
mod common;
use std::collections::BTreeMap;
use std::sync::Arc;

use atlas_pca::agent::{issue_passport, passport_fingerprint, KeyPair, PqKeyPair, Suite};
use atlas_pca::attestation::HardwareVerifierFn;
use atlas_pca::passport::*;
use atlas_pca::serde_json::{json, Value};
use common::replay::thrown;

fn hw(spec: &Value) -> Option<Arc<HardwareVerifierFn>> {
    if spec.is_null() {
        return None;
    }
    let (throws, result) =
        (spec.get("throws").and_then(Value::as_str).map(str::to_string), spec.get("result").cloned().unwrap_or(Value::Null));
    Some(Arc::new(move |_: &Value| match &throws {
        Some(m) => Err(m.clone()),
        None => Ok(result.clone()),
    }))
}

fn revocation(spec: &Value) -> Option<Arc<RevocationFn>> {
    match spec {
        Value::Null => None,
        Value::String(s) if s == "none" => None,
        Value::String(_) => Some(Arc::new(|_: &Value| Err("rev".to_string()))),
        r => match r.get("revokedIds").and_then(Value::as_array).cloned() {
            Some(ids) => Some(Arc::new(move |p: &Value| Ok(ids.contains(&p["id"])))),
            None => {
                let revoked = r.get("revoked").and_then(Value::as_bool).unwrap_or(false);
                Some(Arc::new(move |_: &Value| Ok(revoked)))
            }
        },
    }
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => json!({
            "PASSPORT_SIG_DOMAIN": PASSPORT_SIG_DOMAIN,
            "PASSPORT_VERSION": PASSPORT_VERSION,
            "DEFAULT_PASSPORT_EVIDENCE_AGE_MS": DEFAULT_PASSPORT_EVIDENCE_AGE_MS,
        }),
        "passportFingerprint" => passport_fingerprint(&a[0]).map(Value::String).unwrap_or_else(thrown),
        "issuePassport" => issue_passport(&a[0]).unwrap_or_else(thrown),
        "matchesBinding" => matches_binding(&a[0], &a[1]).unwrap_or_else(thrown),
        "registry" => {
            let r = build_passport_registry(a[0].as_array().unwrap());
            Value::Array(
                a[1].as_array()
                    .unwrap()
                    .iter()
                    .map(|op| match op[0].as_str().unwrap() {
                        "get" => op[1].as_str().and_then(|id| r.get(id)).cloned().unwrap_or(Value::Null),
                        "has" => json!(op[1].as_str().is_some_and(|id| r.has(id))),
                        _ => Value::Array(r.all()),
                    })
                    .collect(),
            )
        }
        "trustScore" => json!(passport_trust_score(&a[0], if a[1].is_null() { &Value::Null } else { &a[1] })),
        // the reference copies its arguments through (the id by template string): non-strings are not refused
        "passportEvidenceBinding" => match (a[0].as_str(), a[1].as_str(), a[2].as_str()) {
            (Some(x), Some(y), Some(z)) => passport_evidence_binding(x, y, z),
            _ => {
                let id = a[0].as_str().map_or_else(|| if a[0].is_number() { a[0].to_string() } else { "undefined".to_string() }, String::from);
                json!({"holderPub": a[1], "grantRef": format!("passport:{id}"), "epoch": 0, "nonce": a[2]})
            }
        },
        "signPassport" => {
            let o = &a[1];
            let issuer = KeyPair::from_seed_b64u(o["issuerSecret"]["$bytes"].as_str().unwrap()).unwrap();
            let spec = o.get("suite").filter(|s| !s.is_null());
            let alg = spec.and_then(|s| s["alg"].as_str());
            let pq = match spec.filter(|_| alg != Some("ed25519")) {
                Some(s) => match s.get("pqSeed") {
                    Some(seed) => Some(PqKeyPair::from_seed("ML-DSA-65", &common::b64d(seed["$bytes"].as_str().unwrap())).unwrap()),
                    None => return thrown("mlDsa65Keygen: the seed is required"),
                },
                None => None,
            };
            sign_passport_value(&a[0], o, &issuer, &Suite { alg, pq: pq.as_ref() }).unwrap_or_else(thrown)
        }
        "verifyPassport" => {
            let o = &a[1];
            let rev = revocation(o.get("revocation").unwrap_or(&Value::Null));
            let verifier = o.get("hardware").filter(|h| !h.is_null()).and_then(hw);
            verify_passport_value(&a[0], o, rev.as_deref(), verifier.as_deref())
        }
        "passportAssurance" => passport_assurance_value(&a[0], Some(&a[1]).filter(|l| !l.is_null() && l.is_object())),
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn passport_replay() {
    let cases = common::ref_cases_seeded("passport");
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(c["fn"].as_str().unwrap().to_string()).or_default() += 1;
    }
    let want: BTreeMap<String, usize> = [
        ("matchesBinding", 267),
        ("verifyPassport", 109),
        ("trustScore", 67),
        ("signPassport", 30),
        ("passportFingerprint", 13),
        ("issuePassport", 12),
        ("passportAssurance", 8),
        ("passportEvidenceBinding", 5),
        ("registry", 4),
        ("constants", 1),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), *n))
    .collect();
    assert_eq!(per_fn, want, "per-function case totals");
    assert_eq!(cases.len(), 516);

    // the reference accepts a post-quantum passport without a pin only through its legacy unbound opt-out, which is not offered here
    let (unbound, rest): (Vec<Value>, Vec<Value>) =
        cases.into_iter().partition(|c| c["args"].to_string().contains("allowUnboundPq") && c["out"]["ok"] == json!(true));
    assert_eq!(unbound.len(), 1, "reference acceptances through the unbound opt-out");
    for c in &unbound {
        assert_eq!(run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap())["ok"], json!(false), "{} must be refused", c["name"]);
    }
    let mut bad = Vec::new();
    for c in &rest {
        let got = run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap());
        let differs = if c["out"].get("$throws").is_some() {
            got.get("$throws").is_none()
        } else {
            atlas_pca::canonicalize(&c["out"]) != atlas_pca::canonicalize(&got)
        };
        if differs {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), rest.len(), bad.join("\n"));
}
