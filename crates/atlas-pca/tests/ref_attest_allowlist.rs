//! Differential replay of test-data/ref-attest-allowlist.json.gz (written by the TypeScript reference): the signed measurement-allowlist
//! manifests (verify under every suite, durable verify, create / sign / revoke, projection and the per-vendor policy fields) and their
//! transparency anchor (commit, operator log, signed heads, evidence, and the verifier over the committed conformance vectors). Every
//! function of the corpus has a handler and the per-function totals are asserted. A reference refusal must be a refusal here, and a
//! failed verification is compared by its code (the reason text is not part of the contract). The cases whose arguments carry a lone
//! surrogate cannot be built as Rust strings and are counted as not run.
mod common;
use std::collections::BTreeMap;
use std::sync::Mutex;

use atlas_pca::agent::{KeyPair, PqKeyPair, Suite};
use atlas_pca::attest::allowlist::*;
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::{
    allowlist_anchor_commit, anchor_allowlist_head, anchor_entry_of, create_allowlist_anchor_log, evidence_for, refresh_anchor_head,
    verify_allowlist_anchored, AnchorEntry, AnchorOptions,
};
use common::replay::{replay_cases, thrown};

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

/// A non-finite double marker `{"$num": "NaN" | "Infinity" | "-Infinity"}`.
fn marker(v: &Value) -> Option<f64> {
    match v.as_object().filter(|m| m.len() == 1)?.get("$num")?.as_str()? {
        "NaN" => Some(f64::NAN),
        "Infinity" => Some(f64::INFINITY),
        "-Infinity" => Some(f64::NEG_INFINITY),
        _ => None,
    }
}

fn js_num(v: Option<&Value>) -> JsNum {
    match v {
        None => JsNum::Undefined,
        Some(x) => match marker(x).or(x.as_f64().filter(|_| x.is_number())) {
            Some(n) => JsNum::Num(n),
            None => JsNum::Other,
        },
    }
}

fn options(o: &Value) -> VerifyOptions {
    VerifyOptions {
        now_ms: js_num(o.get("nowMs")),
        min_version: js_num(o.get("minVersion")),
        last_seen_version: js_num(o.get("lastSeenVersion")),
        last_seen_digest: o.get("lastSeenDigest").and_then(Value::as_str).map(String::from),
        clock_skew_ms: js_num(o.get("clockSkewMs")),
        max_lifetime_ms: js_num(o.get("maxLifetimeMs")),
    }
}

/// The in-memory durable key-value store of the corpus.
#[derive(Default)]
struct MemKv(Mutex<BTreeMap<String, Value>>);

impl AllowlistKv for MemKv {
    fn get(&self, key: &str) -> Option<Value> {
        self.0.lock().unwrap().get(key).cloned()
    }
    fn update(&self, key: &str, f: &mut dyn FnMut(Option<&Value>) -> Option<Value>) -> Option<Value> {
        let mut m = self.0.lock().unwrap();
        if let Some(next) = f(m.get(key)) {
            m.insert(key.to_string(), next);
        }
        m.get(key).cloned()
    }
}

fn durable(c: &Value) -> Value {
    let kv = MemKv::default();
    for (k, v) in c.get("initial").and_then(Value::as_object).into_iter().flatten() {
        kv.0.lock().unwrap().insert(k.clone(), v.clone());
    }
    let opts = options(&c["opts"]);
    let results: Vec<Value> =
        c["steps"].as_array().unwrap().iter().map(|s| verify_allowlist_durable(s, &c["opts"]["issuerKeys"], &opts, &kv)).collect();
    let snapshot: Map<String, Value> = kv.0.lock().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    json!({"results": results, "kv": Value::Object(snapshot)})
}

fn sign_case(a: &[Value]) -> Value {
    let (body, o) = (&a[0], &a[1]);
    let (issuer, alg) = (text(&o["issuer"]), text(&o["alg"]));
    let spec = &o["keySpec"];
    let ed = spec.get("edSecret").and_then(Value::as_str).map(|s| KeyPair::from_seed_b64u(s).unwrap());
    let pq = spec.get("seed").and_then(Value::as_str).and_then(|s| {
        let family = if alg.contains("ml-dsa-87") {
            "ML-DSA-87"
        } else if alg.contains("ml-dsa-65") {
            "ML-DSA-65"
        } else {
            return None;
        };
        Some(PqKeyPair::from_seed(family, &common::b64d(s)).unwrap())
    });
    sign_allowlist_manifest(body, issuer, alg, ed.as_ref(), pq.as_ref()).unwrap_or_else(thrown)
}

fn policy_fields(a: &[Value]) -> Value {
    match text(&a[0]) {
        "azureMaaPolicyFields" => azure_maa_policy_fields(&a[1]),
        "intelDcapPolicyFields" => intel_dcap_policy_fields(&a[1]),
        "sevSnpPolicyFields" => sev_snp_policy_fields(&a[1]),
        "gcpCsPolicyFields" => gcp_cs_policy_fields(&a[1]),
        "nvidiaCcPolicyFields" => nvidia_cc_policy_fields(&a[1]),
        other => panic!("unhandled policy field function {other}"),
    }
}

fn anchor_ops(c: &Value) -> Value {
    let mut log = create_allowlist_anchor_log(text(&c["instanceId"]), text(&c["principal"]));
    let guardian = KeyPair::from_seed_b64u(text(&c["secret"])).unwrap();
    let suite = Suite { alg: None, pq: None };
    let out: Vec<Value> = c["ops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|op| {
            if let Some(what) = op.get("anchor") {
                anchor_allowlist_head(&mut log, what, &guardian, op["nowMs"].as_f64().unwrap(), &suite).unwrap_or_else(thrown)
            } else if let Some(now) = op.get("refresh") {
                refresh_anchor_head(&mut log, &guardian, now.as_f64().unwrap(), &suite).unwrap_or_else(thrown)
            } else if let Some(i) = op.get("evidenceFor") {
                evidence_for(&log, i, op.get("cached").and_then(|c| c["size"].as_f64())).unwrap_or_else(thrown)
            } else if op.get("latest").is_some() {
                log.latest().cloned().unwrap_or(Value::Null)
            } else {
                Value::Array(log.entries())
            }
        })
        .collect();
    Value::Array(out)
}

fn verify_anchored(c: &Value) -> Value {
    let (v, o) = (&c["verified"], &c["opts"]);
    let mine =
        AnchorEntry { issuer: text(&v["issuer"]).into(), version: v["version"].as_i64().unwrap(), digest: text(&v["digest"]).into() };
    let evidence = Some(&c["evidence"]).filter(|e| !e.is_null());
    let trust = &o["trust"];
    let got = verify_allowlist_anchored(
        &mine,
        evidence,
        &AnchorOptions {
            log_key: text(&trust["logKey"]),
            instance_id: text(&trust["instanceId"]),
            principal: text(&trust["principal"]),
            now_ms: o["nowMs"].as_i64().unwrap(),
            max_head_age_ms: o.get("maxHeadAgeMs").and_then(Value::as_i64),
            clock_skew_ms: o.get("clockSkewMs").and_then(Value::as_i64),
            cached_head: Some(&o["cachedHead"]).filter(|h| !h.is_null()),
        },
    );
    match got {
        Ok(highest) => json!({
            "ok": true, "issuer": mine.issuer, "version": mine.version, "digest": mine.digest, "highestAnchoredVersion": highest,
            "head": evidence.map_or(Value::Null, |e| e["head"].clone()),
        }),
        Err(code) => json!({"ok": false, "code": code}),
    }
}

/// A refusal is compared as a refusal and a failed verification by its code: the reference's reason texts are not part of the contract.
fn norm(v: &Value) -> Value {
    match v {
        Value::Object(m) if m.contains_key("$throws") => json!({"$throws": true}),
        Value::Object(m) => {
            let failed = m.get("ok") == Some(&json!(false));
            Value::Object(m.iter().filter(|(k, _)| !(failed && k.as_str() == "reason")).map(|(k, x)| (k.clone(), norm(x))).collect())
        }
        Value::Array(a) => Value::Array(a.iter().map(norm).collect()),
        other => other.clone(),
    }
}

fn run(f: &str, a: &[Value]) -> Value {
    let out = match f {
        "constants" => json!({"ALLOWLIST_KINDS": ALLOWLIST_KINDS, "DOMAIN": ALLOWLIST_DOMAIN}),
        "verifyAllowlistManifest" => verify_allowlist_manifest(&a[0], &a[1]["issuerKeys"], &options(&a[1])),
        "verifyAllowlistDurable" => durable(&a[0]),
        "createAllowlistManifest" => create_allowlist_manifest(&a[0]).unwrap_or_else(thrown),
        "signAllowlistManifest" => sign_case(a),
        "revokeAllowlistEntry" => revoke_allowlist_entry(&a[0], &a[1], &a[2]).unwrap_or_else(thrown),
        "driverVersionSlotHex" => driver_version_slot_hex(text(&a[0])).map(Value::String).unwrap_or_else(thrown),
        "projectAllowlist" => project_allowlist(&a[0], a[1]["nowMs"].as_f64().unwrap()),
        "policyFields" => policy_fields(a),
        "anchorCommit" => allowlist_anchor_commit(&a[0]).map(Value::String).unwrap_or_else(thrown),
        "anchorEntryOf" => anchor_entry_of(&a[0]),
        "anchorOps" => anchor_ops(&a[0]),
        "verifyAnchored" => verify_anchored(&a[0]),
        other => panic!("unhandled corpus function {other}"),
    };
    norm(&out)
}

#[test]
fn allowlist_replay() {
    let mut cases = common::ref_cases_seeded("attest-allowlist");
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(text(&c["fn"]).to_string()).or_default() += 1;
    }
    let want: BTreeMap<String, usize> = [
        ("verifyAllowlistManifest", 744),
        ("verifyAnchored", 72),
        ("policyFields", 45),
        ("verifyAllowlistDurable", 23),
        ("anchorOps", 20),
        ("driverVersionSlotHex", 13),
        ("revokeAllowlistEntry", 11),
        ("signAllowlistManifest", 10),
        ("projectAllowlist", 9),
        ("createAllowlistManifest", 6),
        ("anchorCommit", 4),
        ("constants", 1),
        ("anchorEntryOf", 1),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), *n))
    .collect();
    assert_eq!(per_fn, want, "per-function case totals");
    for c in cases.iter_mut() {
        let w = norm(&c["out"]);
        c["out"] = w;
    }
    // 27 cases carry a lone surrogate in a hostile manifest member
    replay_cases("attest-allowlist", cases, 959, 27, run);
}
