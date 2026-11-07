//! Leases: packages/pca/conformance/lease-vectors.json. A missing file fails, it never skips.
use atlas_pca::lease::{check_lease, LeasePolicy, LeaseRegistry};
use atlas_pca::serde_json::Value;

#[test]
fn lease_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/lease-vectors.json");
    let doc: Value = atlas_pca::serde_json::from_str(&std::fs::read_to_string(path).expect("read lease-vectors.json")).expect("parse");
    let (recs, revs) = (doc["records"].as_array().unwrap(), doc["revocations"].as_array().unwrap());
    let strs = |v: &Value| v.as_array().map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect::<Vec<_>>());
    let mut bad = Vec::new();
    let scenarios = doc["scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 20);
    for s in scenarios {
        let name = s["name"].as_str().unwrap();
        let mut pol = LeasePolicy::new(vec![doc["authority"].as_str().unwrap().to_string()]);
        pol.min_approvals = s["policy"]["minApprovals"].as_i64();
        pol.eligible = strs(&s["policy"]["eligibleApprovers"]);
        pol.fresh_justification = s["policy"]["freshJustification"].as_bool().unwrap_or(true);
        let mut reg = LeaseRegistry::new(pol);
        for st in s["steps"].as_array().unwrap() {
            let exp = &st["expect"];
            match st["op"].as_str().unwrap() {
                "accept" => {
                    let got = reg.accept(&recs[st["record"].as_u64().unwrap() as usize], &strs(&st["chain"]).unwrap_or_default());
                    let ok = match (&got, exp["ok"].as_bool().unwrap()) {
                        (Ok((replaced, seq)), true) => Some(*replaced) == exp["replaced"].as_bool() && Some(*seq) == exp["seq"].as_i64(),
                        (Err(c), false) => Some(*c) == exp["code"].as_str(),
                        _ => false,
                    };
                    if !ok {
                        bad.push(format!("{name}: accept {got:?} want {exp}"));
                    }
                }
                "revoke" => {
                    let got = reg.revoke(&revs[st["revocation"].as_u64().unwrap() as usize]);
                    let ok = match (&got, exp["ok"].as_bool().unwrap()) {
                        (Ok(n), true) => Some(*n as i64) == exp["revoked"].as_i64(),
                        (Err(c), false) => Some(*c) == exp["code"].as_str(),
                        _ => false,
                    };
                    if !ok {
                        bad.push(format!("{name}: revoke {got:?} want {exp}"));
                    }
                }
                _ => {
                    let got = check_lease(&recs[st["record"].as_u64().unwrap() as usize], &reg, &st["now"]);
                    let ok = Some(got.decision) == exp["decision"].as_str()
                        && got.code == exp["code"].as_str()
                        && got.lease_id.as_deref() == exp["lease_id"].as_str()
                        && got.expires_at == exp["expires_at"].as_i64();
                    if !ok {
                        bad.push(format!("{name}: check {got:?} want {exp}"));
                    }
                }
            }
        }
    }
    assert!(bad.is_empty(), "{} failures:\n{}", bad.len(), bad.join("\n"));
}

#[test]
fn max_ttl_ceiling_refuses_right_after_over_max_ttl() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/lease-vectors.json");
    let doc: Value = atlas_pca::serde_json::from_str(&std::fs::read_to_string(path).expect("read lease-vectors.json")).expect("parse");
    let auth = doc["authority"].as_str().unwrap().to_string();
    let accept = |ceiling: Option<i64>, i: usize| {
        let mut pol = LeasePolicy::new(vec![auth.clone()]);
        pol.max_ttl_ceiling = ceiling;
        LeaseRegistry::new(pol).accept(&doc["records"][i], &[]).map(|_| ())
    };
    // Record 0: max_ttl 3600000, accepted when no ceiling is set.
    let max_ttl = doc["records"][0]["max_ttl"].as_i64().unwrap();
    assert_eq!(max_ttl, 3_600_000);
    assert_eq!(accept(None, 0), Ok(()), "absent");
    assert_eq!(accept(Some(max_ttl + 1), 0), Ok(()), "ceiling above max_ttl");
    assert_eq!(accept(Some(max_ttl), 0), Ok(()), "ceiling equal to max_ttl");
    assert_eq!(accept(Some(max_ttl - 1), 0), Err("ttl_ceiling"), "ceiling below max_ttl");
    assert_eq!(accept(Some(1), 0), Err("ttl_ceiling"), "smallest ceiling");
    // Record 16 is over its own cap and over this ceiling: over_max_ttl is checked first.
    assert_eq!(accept(Some(1), 16), Err("over_max_ttl"));
}

#[test]
fn max_ttl_ceiling_malformed_panics_and_the_edges_construct() {
    let new = |c: i64| {
        let mut pol = LeasePolicy::new(vec!["a".into()]);
        pol.max_ttl_ceiling = Some(c);
        std::panic::catch_unwind(|| drop(LeaseRegistry::new(pol))).is_ok()
    };
    for bad in [0, -1, i64::MIN, 9_007_199_254_740_992, i64::MAX] {
        assert!(!new(bad), "{bad} must panic");
    }
    for good in [1, 9_007_199_254_740_991] {
        assert!(new(good), "{good} must construct");
    }
}
