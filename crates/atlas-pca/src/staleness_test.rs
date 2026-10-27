//! Replays staleness-vectors.json (`max_age`, `effective_reversibility`, `age`, `epoch`, `gate`) against the real functions.
//! A missing vector file fails the test.
use super::staleness::*;
use serde_json::{json, Value};

fn doc() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/staleness-vectors.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("staleness-vectors.json must exist")).expect("json")
}

/// "NaN" stands for a NaN number; null / a non-number is absent.
fn num(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) if s == "NaN" => Some(f64::NAN),
        _ => None,
    }
}

/// Compare an outcome with the recorded `{ok, reason?}` (reason only where the vector does not say `ok_only`).
fn same(got: Result<(), String>, want: &Value, ok_only: bool, name: &str) {
    assert_eq!(got.is_ok(), want["ok"].as_bool().unwrap(), "{name}: {got:?}");
    if !ok_only {
        assert_eq!(got.err(), want["reason"].as_str().map(str::to_string), "{name}");
    }
}

#[test]
fn constants() {
    let d = doc();
    assert_eq!(d["constants"]["refresh_ms"].as_f64(), Some(REVOCATION_EPOCH_REFRESH_MS));
    assert_eq!(d["constants"]["validity_ms"].as_f64(), Some(REVOCATION_EPOCH_VALIDITY_MS));
    assert_eq!(d["constants"]["irreversible_max_age_ms"].as_f64(), Some(REVOCATION_IRREVERSIBLE_MAX_AGE_MS));
}

#[test]
fn max_age_vectors() {
    let d = doc();
    let rows = d["max_age"].as_array().unwrap();
    assert_eq!(rows.len(), 15);
    for v in rows {
        let policy = RevocationStalenessPolicy::from_json(&v["policy"]);
        policy.validate().unwrap();
        let cls = match v["class"].as_str().unwrap() {
            "reversible" => Reversibility::Reversible,
            "costly" | "rate_limited" => Reversibility::Costly,
            _ => Reversibility::Irreversible,
        };
        assert_eq!(policy.max_age_ms(cls), v["max_age_ms"].as_f64().unwrap(), "{v}");
    }
}

#[test]
fn effective_reversibility_vectors() {
    let d = doc();
    let rows = d["effective_reversibility"].as_array().unwrap();
    assert_eq!(rows.len(), 14);
    for v in rows {
        let signed = (!v["signed_class"].is_null()).then(|| &v["signed_class"]);
        let got = effective_reversibility(v["server_class"].as_str(), signed);
        assert_eq!(got.as_str(), v["effective"].as_str().unwrap(), "{v}");
    }
}

#[test]
fn age_vectors() {
    let d = doc();
    let rows = d["age"].as_array().unwrap();
    assert_eq!(rows.len(), 13);
    for v in rows {
        let got = check_revocation_age(num(&v["issued_at"]), num(&v["now"]).unwrap(), num(&v["max_age_ms"]).unwrap(), v["what"].as_str().unwrap_or("revocation state"));
        same(got, &v["result"], v["ok_only"].as_bool() == Some(true), &v.to_string());
    }
}

#[test]
fn epoch_vectors() {
    let d = doc();
    let rows = d["epoch"].as_array().unwrap();
    assert_eq!(rows.len(), 25);
    for v in rows {
        let name = v["name"].as_str().unwrap();
        let got = check_revocation_epoch(
            &v["epoch"],
            &EpochCheckOptions {
                guardian_public: v["guardian_public"].as_str().unwrap(),
                now: num(&v["now"]).unwrap(),
                grant_ref: v["grant_ref"].as_str(),
                last_accepted_epoch: num(&v["last_accepted_epoch"]),
                pcactn_epoch: num(&v["pcactn_epoch"]),
                max_age_ms: num(&v["max_age_ms"]),
                pq_pin: None,
            },
        );
        same(got, &v["result"], v["ok_only"].as_bool() == Some(true), name);
    }
}

#[test]
fn gate_vectors() {
    let d = doc();
    let guardian = d["guardian_public"].as_str().unwrap();
    let rows = d["gate"].as_array().unwrap();
    assert_eq!(rows.len(), 28);
    for v in rows {
        let name = v["name"].as_str().unwrap();
        let mut policy = RevocationStalenessPolicy::from_json(&v["policy"]);
        policy.allow_unsigned_root_for_irreversible = v["allow_unsigned_root_for_irreversible"] == json!(true);
        policy.validate().unwrap();
        let mut pcactn = json!({"grant_ref": "g1", "cap_chain": [{"id": "cap-a"}], "action": {}, "freshness": {"epoch": 0}});
        if let Some(c) = v["signed_class"].as_str() {
            pcactn["action"]["reversibility_class"] = json!(c);
        }
        let state = match v["mode"].as_str().unwrap() {
            "epoch" => Some(RevocationState { epoch: Some(v["epoch"].clone()), root: v["bare_root"].as_str().map(str::to_string), root_issued_at: None }),
            "root" => Some(RevocationState { epoch: None, root: Some(d["revocation_root"].as_str().unwrap().to_string()), root_issued_at: num(&v["root_issued_at"]) }),
            _ => None,
        };
        let got = decide_gate(&policy, Some(guardian), None, None, &pcactn, v["server_class"].as_str(), num(&v["now"]).unwrap(), state.as_ref());
        same(got, &v["result"], false, name);
    }
}

#[test]
fn a_malformed_policy_is_a_configuration_error() {
    for bad in [json!({"maxRevocationAgeMs": -5}), json!({"maxRevocationAgeMs": 0}), json!({"staleness": {"irreversible": "x"}}), json!({"staleness": {"costly": -1}})] {
        assert!(RevocationStalenessPolicy::from_json(&bad).validate().is_err(), "{bad}");
    }
    assert!(RevocationStaleness::new(RevocationStalenessPolicy { max_revocation_age_ms: Some(f64::NAN), ..Default::default() }, |_, _| Ok(None)).is_err());
    assert!(RevocationStalenessPolicy::default().validate().is_ok());
}

#[test]
fn membership_vectors() {
    let d = doc();
    let set = &d["revocation_set"];
    let rows = d["membership"].as_array().unwrap();
    assert_eq!(rows.len(), 27);
    for v in rows {
        let name = v["name"].as_str().unwrap();
        let got = verify_non_membership(v["root"].as_str().unwrap_or(""), &v["proof"], v["id"].as_str().unwrap());
        assert_eq!(got, v["ok"].as_bool().unwrap(), "{name}");
    }
    // the named sets are the roots the cases use
    assert!(rows.iter().any(|v| v["set"] == "main" && v["root"] == set["root"]));
    assert!(rows.iter().any(|v| v["set"] == "empty" && v["root"] == set["empty_root"]));
    assert!(rows.iter().any(|v| v["set"] == "one" && v["root"] == set["single"]["root"]));
}

/// The vectors' guardian key: 32 bytes of 0x0b.
fn signed_main_epoch(root: &str, size: u64, issued: i64) -> Value {
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let key = SigningKey::from_bytes(&[11u8; 32]);
    let mut e = json!({"instance_id": "i", "grant_ref": "g1", "epoch": 0, "set_size": size, "root": root, "issued_at": issued, "not_after": issued + 600_000});
    let mut msg = b"atlas-pca/revepoch/v1\0".to_vec();
    msg.extend_from_slice(crate::canonicalize_strict(&e).unwrap().as_bytes());
    e["guardian"] = json!(b64(key.verifying_key().as_bytes()));
    e["sig"] = json!(b64(&key.sign(&msg).to_bytes()));
    e
}

#[test]
fn gate_ids_vectors() {
    let d = doc();
    let guardian = d["guardian_public"].as_str().unwrap();
    let set = &d["revocation_set"];
    let rows = d["gate_ids"].as_array().unwrap();
    assert_eq!(rows.len(), 10);
    let policy = RevocationStalenessPolicy { max_revocation_age_ms: Some(REVOCATION_EPOCH_VALIDITY_MS), ..Default::default() };
    for v in rows {
        let name = v["name"].as_str().unwrap();
        let ids: Vec<String> = v["ids"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
        let chain: Vec<Value> = ids.iter().map(|i| json!({"id": i})).collect();
        let pcactn = json!({"grant_ref": "g1", "cap_chain": chain, "action": {"reversibility_class": "costly"}, "freshness": {"epoch": 0}});
        let ep = signed_main_epoch(set["root"].as_str().unwrap(), set["size"].as_u64().unwrap(), v["epoch_issued_at"].as_i64().unwrap());
        assert_eq!(ep["guardian"], json!(guardian), "{name}: the test key must be the vectors' guardian");
        let state = RevocationState { epoch: Some(ep), ..Default::default() };
        let proofs = &v["proofs"];
        let got = decide_gate_ids(&policy, Some(guardian), None, None, &pcactn, None, num(&v["now"]).unwrap(), Some(&state), &ids, &|id| proofs.get(id).cloned());
        same(got, &v["result"], false, name);
    }
}
