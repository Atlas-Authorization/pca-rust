//! Differential replay of test-data/ref-action-pin.json.gz (written by the TypeScript reference): the signing half of the action pin module
//! (registry documents, evolution records, the registry key entry, the principal's re-approval) plus the constants and the verify side
//! over documents the oracle signs. Every function of the corpus has a handler and the per-function totals are asserted. A reference
//! refusal must be a refusal here; after the prefix `verification error:` the reference's own text is not compared.
mod common;
use std::collections::BTreeMap;

use atlas_pca::actions_registry::*;
use atlas_pca::agent::{KeyPair, PqKeyPair, Suite};
use atlas_pca::serde_json::{json, Value};
use atlas_pca::sign_parity::{registry_key_of, sign_evolution_record, sign_reapproval, sign_registry_doc_value};
use common::replay::thrown;

fn key(v: &Value) -> KeyPair {
    KeyPair::from_seed_b64u(v["$bytes"].as_str().unwrap()).unwrap()
}

/// `suite` spec `{alg, pqSeed?}` -> the arguments of a [`Suite`] (the ML-DSA-65 key of the seed).
fn with_suite<R>(spec: &Value, f: impl FnOnce(&Suite) -> R) -> Result<R, String> {
    let spec = Some(spec).filter(|s| !s.is_null());
    let alg = spec.and_then(|s| s["alg"].as_str());
    let pq = match spec.filter(|_| alg != Some("ed25519")) {
        Some(s) => match s.get("pqSeed") {
            Some(seed) => Some(PqKeyPair::from_seed("ML-DSA-65", &common::b64d(seed["$bytes"].as_str().unwrap())).unwrap()),
            None => return Err("mlDsa65Keygen: the seed is required".into()),
        },
        None => None,
    };
    Ok(f(&Suite { alg, pq: pq.as_ref() }))
}

fn verdict(r: Result<(), String>) -> Value {
    match r {
        Ok(()) => json!({"ok": true}),
        Err(reason) => json!({"ok": false, "reason": reason}),
    }
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => json!({
            "ACTION_PIN_ON_NEW": ACTION_PIN_ON_NEW,
            "EVOLUTION_CLASSES": EVOLUTION_CLASSES,
            "EVOLUTION_DIFF_DOMAIN": EVOLUTION_DIFF_DOMAIN,
            "EVOLUTION_DOMAIN": EVOLUTION_DOMAIN,
            "EVOLUTION_RECORD_KIND": EVOLUTION_RECORD_KIND,
            "MAX_ESC_TIER": MAX_ESC_TIER,
            "MAX_EVOLUTION_STEPS": MAX_EVOLUTION_STEPS,
            "REAPPROVAL_DOMAIN": REAPPROVAL_DOMAIN,
            "REAPPROVAL_KIND": REAPPROVAL_KIND,
        }),
        "signRegistryDoc" => {
            with_suite(&a[4], |s| sign_registry_doc_value(a[0].as_str().unwrap(), &a[1], a[2].as_str().unwrap(), &key(&a[3]), s))
                .and_then(|r| r)
                .unwrap_or_else(thrown)
        }
        "signEvolutionRecord" => with_suite(&a[3], |s| sign_evolution_record(&a[0], a[1].as_str().unwrap(), &key(&a[2]), s))
            .and_then(|r| r)
            .unwrap_or_else(thrown),
        "registryKeyOf" => {
            with_suite(&a[2], |s| registry_key_of(a[0].as_str().unwrap(), &key(&a[1]), s)).and_then(|r| r).unwrap_or_else(thrown)
        }
        "signReapproval" => {
            let r = &a[0];
            sign_reapproval(r["grantId"].as_str().unwrap(), &r["record"], &key(&r["principalSecret"])).unwrap_or_else(thrown)
        }
        "verifyRegistrySig" => match a[2].as_object() {
            Some(sig) => verdict(verify_registry_sig(a[0].as_str().unwrap(), &a[1], sig, &a[3])),
            None => json!({"ok": false, "reason": "verification error: Cannot read properties of null (reading 'kid')"}),
        },
        "verifyEvolutionRecord" => verdict(verify_evolution_record(&a[0], &a[1])),
        "reapprovalValid" => {
            let s = |i: usize| a[i].as_str().unwrap_or("\u{0}none");
            json!(reapproval_valid(&a[0], s(1), s(2), s(3), s(4)))
        }
        other => panic!("unhandled corpus function {other}"),
    }
}

fn norm(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| match (k.as_str(), x.as_str()) {
                    ("reason", Some(r)) if r.starts_with("verification error:") => (k.clone(), json!("verification error:")),
                    _ => (k.clone(), x.clone()),
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

#[test]
fn action_pin_replay() {
    let cases = common::ref_cases_seeded("action-pin");
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(c["fn"].as_str().unwrap().to_string()).or_default() += 1;
    }
    let want: BTreeMap<String, usize> = [
        ("signEvolutionRecord", 33),
        ("verifyEvolutionRecord", 21),
        ("signRegistryDoc", 20),
        ("reapprovalValid", 17),
        ("signReapproval", 8),
        ("verifyRegistrySig", 6),
        ("registryKeyOf", 5),
        ("constants", 1),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), *n))
    .collect();
    assert_eq!(per_fn, want, "per-function case totals");
    assert_eq!(cases.len(), 111);
    let mut bad = Vec::new();
    for c in &cases {
        if common::lone_refusal(c) {
            continue;
        }
        let got = run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap());
        let differs = if c["out"].get("$throws").is_some() {
            got.get("$throws").is_none()
        } else {
            atlas_pca::canonicalize(&norm(&c["out"])) != atlas_pca::canonicalize(&norm(&got))
        };
        if differs {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
