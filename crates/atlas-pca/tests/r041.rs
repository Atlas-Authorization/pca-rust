//! PCA 0.4.1 shared vectors (packages/pca/conformance/vectors.json, gen-conformance-041.mjs):
//!   * `primitives.caveat_eval`: the policy-layer helpers `policy_caveats` / `evaluate_caveats` (root caveats outside the
//!     envelope are evaluated like delegated ones, incl. `max_spend`);
//!   * `primitives.pca_header`: strict unpadded base64url + strict UTF-8 `PCA-Action` decoding (`decode_pca_header`);
//!   * `r041-share-*`: threshold share signatures are validated PER SUITE in `wire`.
mod common;
use atlas_pca::*;
use common::{load, unsupported_suite, SUPPORTED_SUITES};
use serde_json::{json, Value};

fn section(doc: &Value, k: &str) -> Vec<Value> {
    doc["primitives"][k].as_array().unwrap_or_else(|| panic!("missing primitives.{k}")).clone()
}

#[test]
fn caveat_eval_vectors() {
    let doc = load("vectors.json");
    let cases = section(&doc, "caveat_eval");
    assert!(cases.len() >= 40, "expected >= 40 caveat_eval vectors, got {}", cases.len());
    let by = |n: &str| cases.iter().find(|c| c["name"] == n).unwrap_or_else(|| panic!("{n} missing")).clone();
    assert_eq!(by("r041-root-max-spend-exceeded")["expect"]["allow"], false);
    assert_eq!(by("r041-root-max-spend-within")["expect"]["allow"], true);
    let mut bad = Vec::new();
    for c in &cases {
        let name = c["name"].as_str().unwrap();
        let (ok, failed) = evaluate_caveats(&policy_caveats(&c["grant"], &c["chain"]), &c["context"]);
        let got = json!({"allow": ok, "failed": failed});
        if got != c["expect"] {
            bad.push(format!("{name}: got {got}, want {}", c["expect"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} caveat_eval vectors failed:\n{}", bad.len(), cases.len(), bad.join("\n"));
    eprintln!("[caveat_eval] {} vectors passed", cases.len());
}

#[test]
fn pca_header_vectors() {
    let doc = load("vectors.json");
    let cases = section(&doc, "pca_header");
    assert!(cases.len() >= 27, "expected >= 27 pca_header vectors, got {}", cases.len());
    let mut bad = Vec::new();
    for c in &cases {
        let name = c["name"].as_str().unwrap();
        let input = c["input"].as_str().unwrap();
        let valid = c["valid"].as_bool().unwrap();
        match (decode_pca_header(input), valid) {
            (Ok(text), true) => {
                if Some(text.as_str()) != c["text"].as_str() {
                    bad.push(format!("{name}: text {text:?}, want {:?}", c["text"]));
                }
            }
            (Err(_), false) => {}
            (Ok(t), false) => bad.push(format!("{name}: accepted ({t:?}), want refused")),
            (Err(e), true) => bad.push(format!("{name}: refused ({e:?}), want accepted")),
        }
    }
    assert!(bad.is_empty(), "{} of {} pca_header vectors failed:\n{}", bad.len(), cases.len(), bad.join("\n"));
    eprintln!("[pca_header] {} vectors passed", cases.len());
}

#[test]
fn share_wire_vectors() {
    let doc = load("vectors.json");
    let vs: Vec<&Value> = doc["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["name"].as_str().is_some_and(|n| n.starts_with("r041-share-")))
        .collect();
    assert!(vs.len() >= 20, "expected >= 20 r041-share-* vectors, got {}", vs.len());
    let (mut ran, mut skipped) = (0usize, 0usize);
    let mut bad = Vec::new();
    for v in vs {
        let name = v["name"].as_str().unwrap();
        if unsupported_suite(v).is_some() {
            skipped += 1;
            continue;
        }
        ran += 1;
        let want = v["expect"]["checks"].as_object().unwrap();
        let now = v["context"]["now"].as_i64().unwrap();
        let aud = v["context"]["aud"].as_str().unwrap();
        let got = verify_pcactn_core_policy(&v["pcactn"], &v["grant"], now, aud, None);
        if got.allow != v["expect"]["allow"].as_bool().unwrap() {
            bad.push(format!("{name}: allow = {}, want {} ({})", got.allow, v["expect"]["allow"], got.reason));
        }
        for (k, w) in want {
            if got.checks.get(k) != w.as_bool().as_ref() {
                bad.push(format!("{name}: check {k} = {:?}, want {w} ({})", got.checks.get(k), got.reason));
            }
        }
        // wire alone agrees too
        let wire_ok = want.get("wire") == Some(&Value::Bool(true));
        if validate_wire(&v["pcactn"]).is_ok() != wire_ok {
            bad.push(format!("{name}: validate_wire = {:?}, want ok={wire_ok}", validate_wire(&v["pcactn"])));
        }
    }
    assert!(bad.is_empty(), "{} of {ran} share vectors failed:\n{}", bad.len(), bad.join("\n"));
    assert_eq!(skipped, 0, "every r041 share suite (incl. ml-dsa-87 and slh-dsa-sha2-128f) is implemented in Rust");
    eprintln!("[r041-share] {ran} checked, {skipped} skipped (suites not in Rust; supported: {SUPPORTED_SUITES:?})");
}

/// Reason text for a malformed share names the share index and the suite.
#[test]
fn share_wire_reason_names_suite() {
    let doc = load("vectors.json");
    let v = doc["vectors"].as_array().unwrap().iter().find(|v| v["name"] == "r041-share-ml-dsa-65-3308").unwrap();
    let e = validate_wire(&v["pcactn"]).unwrap_err();
    assert!(e.starts_with("threshold.shares[0]: 'sig' is not canonical base64url (3309 bytes) for alg 'ml-dsa-65'"), "{e}");
}

fn ctx() -> Value {
    json!({"now": 1_800_000_000_000i64, "delegation_depth": 1,
           "action": {"verb": "pay", "resource": "invoice:42", "params": {"amount": 10}}})
}

#[test]
fn evaluate_caveats_is_total_and_fails_closed() {
    // non-array list
    for bad_list in [json!(null), json!({}), json!("x"), json!(3)] {
        assert_eq!(evaluate_caveats(&bad_list, &ctx()), (false, vec!["<malformed caveats>".to_string()]));
    }
    assert_eq!(evaluate_caveats(&json!([]), &ctx()), (true, vec![]));
    // non-object caveats and non-string types
    let (ok, failed) = evaluate_caveats(&json!([1, null, "max_spend", [], {"type": 7}, {"usd": 100}]), &ctx());
    assert!(!ok);
    assert_eq!(failed, vec!["<malformed>"; 6]);
    // unknown / unimplemented types fail closed
    for t in ["note", "envelope", "resource_prefix", "predicates", "tool_schema", "whatever"] {
        assert_eq!(evaluate_caveats(&json!([{"type": t}]), &ctx()), (false, vec![t.to_string()]), "{t}");
    }
    // a non-object context satisfies nothing
    for c in [json!(null), json!([]), json!(1)] {
        assert_eq!(evaluate_caveats(&json!([{"type": "max_spend", "usd": 100}]), &c).0, false);
        assert_eq!(evaluate_caveats(&json!([{"type": "budget_alloc", "limit": 1}]), &c).0, false);
    }
}

#[test]
fn max_spend_semantics() {
    let with = |params: Value| {
        let mut c = ctx();
        c["action"]["params"] = params;
        c
    };
    let ok = |usd: Value, c: &Value| evaluate_caveats(&json!([{"type": "max_spend", "usd": usd}]), c).0;
    assert!(ok(json!(10), &with(json!({"amount": 10}))));
    assert!(!ok(json!(9.99), &with(json!({"amount": 10}))));
    assert!(ok(json!(0), &with(json!({"amount": 0}))));
    assert!(!ok(json!(true), &with(json!({"amount": 0}))), "bool limit");
    assert!(!ok(json!(100), &with(json!({"amount": true}))), "bool amount");
    assert!(!ok(json!(100), &with(json!({"amount": null}))));
    assert!(!ok(json!(100), &with(json!({"amount": -0.5}))));
    assert!(!ok(json!(-0.5), &with(json!({"amount": 0}))));
    assert!(ok(json!(100), &with(json!({"amount": 1, "currency": "usd"}))));
    assert!(ok(json!(100), &with(json!({"amount": 1, "currency": "USD"}))));
    assert!(!ok(json!(100), &with(json!({"amount": 1, "currency": "uSD"}))));
    assert!(!ok(json!(100), &with(json!({"amount": 1, "currency": 1}))));
    assert!(!ok(json!(100), &with(json!({"amount": 1, "currency": null}))));
    assert!(!ok(json!(100), &with(json!(null))));
    assert!(!ok(json!(100), &with(json!("amount"))));
    // max_spend does not need `now`
    let mut c = with(json!({"amount": 1}));
    c.as_object_mut().unwrap().remove("now");
    assert!(ok(json!(100), &c));
    // ... but expires does
    assert!(!evaluate_caveats(&json!([{"type": "expires", "at": 1}]), &c).0);
    // no action / action not an object
    let mut c = ctx();
    c["action"] = json!("pay");
    assert!(!ok(json!(100), &c));
    c.as_object_mut().unwrap().remove("action");
    assert!(!ok(json!(100), &c));
}

#[test]
fn rate_and_reversibility_semantics() {
    let mut c = ctx();
    let now = 1_800_000_000_000i64;
    c["recent_action_times"] = json!([now, now - 59_999, now - 60_000, now + 1, "x", null]);
    // counted: now, now-59999 (2); edge, future, non-numbers excluded
    assert!(!evaluate_caveats(&json!([{"type": "rate", "max": 2, "per_secs": 60}]), &c).0);
    assert!(evaluate_caveats(&json!([{"type": "rate", "max": 3, "per_secs": 60}]), &c).0);
    assert!(!evaluate_caveats(&json!([{"type": "rate", "max": 3, "per_secs": 0}]), &c).0);
    c["recent_action_times"] = json!({});
    assert!(!evaluate_caveats(&json!([{"type": "rate", "max": 3, "per_secs": 60}]), &c).0);
    // reversibility_max reads ctx.reversibility_class, not ctx.action.reversibility_class
    let mut c = ctx();
    c["action"]["reversibility_class"] = json!("reversible");
    assert!(!evaluate_caveats(&json!([{"type": "reversibility_max", "class": "irreversible"}]), &c).0);
    c["reversibility_class"] = json!("rate_limited");
    assert!(evaluate_caveats(&json!([{"type": "reversibility_max", "class": "irreversible"}]), &c).0);
    assert!(evaluate_caveats(&json!([{"type": "reversibility_max", "class": "rate_limited"}]), &c).0);
    assert!(!evaluate_caveats(&json!([{"type": "reversibility_max", "class": "reversible"}]), &c).0);
    assert!(!evaluate_caveats(&json!([{"type": "reversibility_max", "class": ["irreversible"]}]), &c).0);
    c["reversibility_class"] = json!("bogus");
    assert!(!evaluate_caveats(&json!([{"type": "reversibility_max", "class": "irreversible"}]), &c).0);
}

#[test]
fn policy_caveats_shapes() {
    let env = json!({"type": "envelope", "predicates": []});
    let ms = json!({"type": "max_spend", "usd": 1});
    let grant = json!({"caveats": [ms, env, env]});
    // first envelope removed, the second kept; no chain => nothing appended
    assert_eq!(policy_caveats(&grant, &json!(null)), json!([ms, env]));
    assert_eq!(policy_caveats(&grant, &json!([])), json!([ms, env]));
    // hop-appended caveats follow
    let leaf = json!({"caveats": [ms, env, env, {"type": "note"}]});
    assert_eq!(policy_caveats(&grant, &json!([grant, leaf])), json!([ms, env, {"type": "note"}]));
    // a leaf shorter than the grant appends nothing; a non-array leaf list appends nothing
    assert_eq!(policy_caveats(&grant, &json!([{"caveats": []}])), json!([ms, env]));
    assert_eq!(policy_caveats(&grant, &json!([{"caveats": {}}])), json!([ms, env]));
    assert_eq!(policy_caveats(&grant, &json!([5])), json!([ms, env]));
    // a non-array grant list is returned as is (and evaluate_caveats refuses it)
    assert_eq!(policy_caveats(&json!({"caveats": {"type": "x"}}), &json!([])), json!({"type": "x"}));
    let pc = policy_caveats(&json!({}), &json!([]));
    assert_eq!(evaluate_caveats(&pc, &ctx()), (false, vec!["<malformed caveats>".to_string()]));
    assert_eq!(evaluate_caveats(&policy_caveats(&json!(null), &json!(null)), &ctx()).0, false);
}

#[test]
fn decode_pca_header_unit() {
    assert_eq!(decode_pca_header("e30").unwrap(), "{}");
    assert_eq!(decode_pca_header(""), Err(PcaHeaderError::Empty));
    assert_eq!(decode_pca_header("e30="), Err(PcaHeaderError::NotBase64url));
    assert_eq!(decode_pca_header(" e30"), Err(PcaHeaderError::NotBase64url));
    assert_eq!(decode_pca_header("__57"), Err(PcaHeaderError::NotUtf8));
    assert_eq!(decode_pca_header("77u_e30").unwrap(), "\u{feff}{}");
}

/// The middleware's header path uses the strict decoder: every refused `pca_header` vector is a 401 at the decode stage,
/// never a verdict, and every accepted one gets past decoding.
#[cfg(feature = "axum")]
#[test]
fn middleware_header_is_strict() {
    use atlas_pca::middleware::{verify_request, GuardConfig};
    let doc = load("vectors.json");
    let cfg = GuardConfig::new("rs-conformance".to_string(), |_: &str| None).with_signature_only();
    let mut bad = Vec::new();
    for c in section(&doc, "pca_header") {
        let name = c["name"].as_str().unwrap();
        let input = c["input"].as_str().unwrap();
        if input.is_empty() {
            continue; // an empty header falls through to the body (as the reference's defaultExtract)
        }
        let r = verify_request(Some(input), None, &cfg);
        let decode_err = r.status == 401
            && (r.description == "PCA-Action is not valid base64url" || r.description == "PCA-Action does not decode to UTF-8 JSON");
        if c["valid"].as_bool().unwrap() == decode_err {
            bad.push(format!("{name}: status {} {:?}", r.status, r.description));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
