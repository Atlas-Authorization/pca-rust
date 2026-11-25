//! Differential replay of the BLS aggregation package (BLS12-381 PoP signatures, rogue-key-safe registry, capability chain,
//! witness cosignatures) against the TypeScript reference (test-data/ref-aggsig.json.gz). A reference throw only requires a
//! refusal. Secret keys arrive as seed labels ({"$seed": label}: sha256(sha256("atlas-pca-conformance/"+label)) reduced into
//! 1..r-1) or raw bytes for the malformed-key cases. Skipped: none.
mod common;
use atlas_pca::aggsig::*;
use atlas_pca::serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn bytes(v: &Value) -> Vec<u8> {
    common::b64d(v["$bytes"].as_str().expect("$bytes"))
}

fn byte_list(v: &Value) -> Vec<Vec<u8>> {
    v.as_array().expect("list").iter().map(bytes).collect()
}

fn list(v: &Value) -> Vec<Value> {
    v.as_array().cloned().unwrap_or_default()
}

fn limbs(b: &[u8]) -> [u64; 4] {
    let mut o = [0u64; 4];
    for (i, c) in b.chunks(8).enumerate() {
        o[i] = u64::from_be_bytes(c.try_into().unwrap());
    }
    o
}

/// A seed label's scalar: sha256(sha256("atlas-pca-conformance/"+label)) mod (r-1), plus one.
fn seed_scalar(label: &str) -> Vec<u8> {
    let seed = Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes());
    let mut d = limbs(&Sha256::digest(seed));
    let m: [u64; 4] = [0x73eda753299d7d48, 0x3339d80809a1d805, 0x53bda402fffe5bfe, 0xffffffff00000000];
    while d >= m {
        let mut borrow = 0u64;
        for i in (0..4).rev() {
            let (x, b1) = d[i].overflowing_sub(m[i]);
            let (x, b2) = x.overflowing_sub(borrow);
            d[i] = x;
            borrow = (b1 || b2) as u64;
        }
    }
    let mut carry = 1u64;
    for i in (0..4).rev() {
        let (x, c) = d[i].overflowing_add(carry);
        d[i] = x;
        carry = c as u64;
    }
    d.iter().flat_map(|l| l.to_be_bytes()).collect()
}

fn secret(v: &Value) -> Vec<u8> {
    match v.get("$seed").and_then(Value::as_str) {
        Some(l) => seed_scalar(l),
        None => bytes(v),
    }
}

fn b(x: Vec<u8>) -> Value {
    use base64::Engine;
    json!({ "$bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&x) })
}

fn register_all(v: &Value) -> Option<Vec<RegisteredKey>> {
    list(v).iter().map(|k| register_key(&bytes(&k["pk"]), &bytes(&k["pop"])).ok()).collect()
}

/// Registers pairs until the first failure and keeps what it has (the reference harness does the same).
fn registry_of(v: &Value) -> KeyRegistry {
    let mut r = KeyRegistry::new();
    for k in list(v) {
        if r.register(&bytes(&k["pk"]), &bytes(&k["pop"])).is_err() {
            break;
        }
    }
    r
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "publicKeyOf" => public_key_of(&secret(&a[0])).map(b),
        "sign" => sign(&secret(&a[0]), &bytes(&a[1])).map(b),
        "popProve" => pop_prove(&secret(&a[0])).map(b),
        "verify" => Ok(json!(verify(&bytes(&a[0]), &bytes(&a[1]), &bytes(&a[2])))),
        "keyValidate" => Ok(json!(key_validate(&bytes(&a[0])))),
        "registerKey" => Ok(match register_key(&bytes(&a[0]), &bytes(&a[1])) {
            Ok(_) => json!({"ok": true}),
            Err(e) => json!({"ok": false, "reason": e}),
        }),
        "aggregate" => aggregate(&byte_list(&a[0])).map(b),
        "aggregateVerify" => Ok(match register_all(&a[0]) {
            None => json!({"registerFailed": true}),
            Some(ks) => json!(aggregate_verify(&ks, &byte_list(&a[1]), &bytes(&a[2]))),
        }),
        "fastAggregateVerify" => Ok(match register_all(&a[0]) {
            None => json!({"registerFailed": true}),
            Some(ks) => json!(fast_aggregate_verify(&ks, &bytes(&a[1]), &bytes(&a[2]))),
        }),
        "mintBlsRoot" => mint_bls_root(&secret(&a[0]), a[1].as_str().unwrap(), a[2].as_str().unwrap(), &a[3]),
        "chainDelegate" => bls_delegate(&a[0], a[1].as_str().unwrap(), &a[2], &secret(&a[3])),
        "chainAttenuate" => bls_attenuate(&a[0], &a[1], &secret(&a[2])),
        "capHash" => cap_hash(&a[0]).map(Value::String),
        "aggregateChainSignatures" => aggregate_chain_signatures(&list(&a[0])).map(b),
        "verifyAggregatedChain" => Ok(match verify_aggregated_chain(&list(&a[0]), &bytes(&a[1]), &registry_of(&a[2]), a.get(3).and_then(Value::as_str)) {
            Ok(()) => json!({"ok": true}),
            Err(e) => json!({"ok": false, "reason": e}),
        }),
        "cosignTreeHead" => cosign_tree_head(&a[0], &secret(&a[1])),
        "verifyWitnessCosignature" => Ok(json!(verify_witness_cosignature(&a[0], &a[1]))),
        "aggregateWitnessCosignatures" => aggregate_witness_cosignatures(&list(&a[0])).map(b),
        "verifyAggregatedWitnessCosignatures" => Ok(match register_all(&a[1]) {
            None => json!({"registerFailed": true}),
            Some(ks) => json!(verify_aggregated_witness_cosignatures(&a[0], &ks, &bytes(&a[2]))),
        }),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn matches_reference() {
    let cases = common::ref_cases("aggsig");
    let mut bad = Vec::new();
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        let got = std::panic::catch_unwind(|| run(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn unregistered_and_degenerate_inputs_are_refused() {
    let (sk, pk) = key_gen().unwrap();
    let sig = sign(&sk, b"m").unwrap();
    assert!(verify(&pk, b"m", &sig));
    let pop = pop_prove(&sk).unwrap();
    let mut reg = KeyRegistry::new();
    assert!(reg.register(&pk, &pop).is_ok() && reg.has(&pk) && reg.len() == 1);
    assert!(!aggregate_verify(&[], &[], &sig) && !fast_aggregate_verify(&[], b"m", &sig));
    // a key without its PoP never becomes a RegisteredKey
    assert!(register_key(&pk, &sig).is_err());
}
