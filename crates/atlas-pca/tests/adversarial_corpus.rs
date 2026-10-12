mod common;
use atlas_pca::*;
use common::*;
use serde_json::Value;

#[test]
fn adversarial_vectors() {
    let doc = load("vectors-adversarial.json.gz");
    let vs = doc["vectors"].as_array().expect("vectors");
    let mut bad = Vec::new();
    let mut ran = 0usize;
    for v in vs {
        let name = v["name"].as_str().unwrap();
        let want = v["expect"]["checks"].as_object().unwrap();
        let terminal_wire_false = want.len() == 1 && want.get("wire") == Some(&Value::Bool(false));
        if unsupported_suite(v).is_some() && !terminal_wire_false {
            continue;
        }
        ran += 1;
        let now = v["context"]["now"].as_i64().unwrap();
        let aud = v["context"]["aud"].as_str().unwrap();
        let allowed: Option<Vec<String>> = v["context"]["allowed_suites"]
            .as_array()
            .map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect());
        let got = if let Some(raw) = v.get("pcactn_json").and_then(Value::as_str) {
            verify_pcactn_json_policy(raw, &v["grant"], now, aud, allowed.as_deref())
        } else if has_lone(&v["pcactn"]) {
            let mut checks = std::collections::BTreeMap::new();
            checks.insert("wire".to_string(), false);
            Verdict { allow: false, checks, reason: "wire: lone surrogate".into() }
        } else {
            verify_pcactn_core_policy(&v["pcactn"], &v["grant"], now, aud, allowed.as_deref())
        };
        if got.allow != v["expect"]["allow"].as_bool().unwrap() || got.checks.len() != want.len()
            || want.iter().any(|(k, w)| got.checks.get(k) != w.as_bool().as_ref())
        {
            bad.push(format!("{name}: got {:?} {:?} ({}), want {}", got.allow, got.checks, got.reason, v["expect"]));
        }
    }
    assert!(bad.is_empty(), "{} of {ran} adversarial vectors failed:\n{}", bad.len(), bad[..bad.len().min(20)].join("\n"));
    assert!(ran > 3000, "ran {ran}");
}

#[test]
fn adversarial_primitives() {
    let doc = load("vectors-adversarial.json.gz");
    let prim = &doc["primitives"];
    for c in prim["canonical"].as_array().into_iter().flatten() {
        let v = &c["value"];
        assert_eq!(canonicalize_strict(v).unwrap(), c["expect"].as_str().unwrap());
        assert_eq!(hash_canonical(v), c["hash"].as_str().unwrap());
    }
    for c in prim["json_parse"].as_array().into_iter().flatten() {
        let input = c["input"].as_str().unwrap();
        let r = strict_parse(input);
        if c["accept"].as_bool().unwrap() {
            assert_eq!(canonicalize_strict(&r.expect(input)).unwrap(), c["canonical"].as_str().unwrap(), "{input}");
        } else {
            assert!(r.is_err(), "{input}");
        }
    }
    for c in prim["b64u"].as_array().into_iter().flatten() {
        let len = c["len"].as_u64().map(|n| n as usize);
        assert_eq!(decode_b64u_strict(c["input"].as_str().unwrap(), len).is_some(), c["valid"].as_bool().unwrap(), "{}", c["input"]);
    }
    for s in prim["threshold_share"].as_array().into_iter().flatten() {
        assert_eq!(verify_threshold_share(s), s.get("valid").and_then(Value::as_bool).unwrap_or(true));
    }
}
