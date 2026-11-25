//! Differential replay of OAuth Transaction Tokens against the TypeScript reference (test-data/ref-txn-tokens-rs.json.gz).
//! Messages are compared exactly except a JavaScript runtime TypeError and the strict-JSON parser's detail text.
mod common;
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::txn_tokens::*;
use std::collections::HashSet;

fn same(want: &Value, got: Result<Value, String>) -> bool {
    match (want.get("$throws").and_then(Value::as_str), got) {
        (Some(m), Err(e)) => m.contains("Cannot read properties") || m.starts_with("non-canonical compact JWS: bad-json") || m == e,
        (None, Ok(v)) => atlas_pca::canonicalize(want) == atlas_pca::canonicalize(&v),
        _ => false,
    }
}

fn seg(t: &str, i: usize) -> Value {
    atlas_pca::serde_json::from_slice(&common::b64d(t.split('.').nth(i).unwrap())).unwrap()
}

/// The generator's view of an issued token: iat dropped, exp as `ttl`, a generated jti / txn as `true`.
fn issued_view(tok: &str, txn_given: bool) -> Value {
    let mut c: Map<String, Value> = seg(tok, 1).as_object().unwrap().clone();
    let (iat, exp) = (c.remove("iat").unwrap().as_f64().unwrap(), c.remove("exp").unwrap().as_f64().unwrap());
    let jti = c.remove("jti");
    let txn = c.remove("txn");
    let ttl = exp - iat;
    c.insert("ttl".into(), if ttl.fract() == 0.0 { json!(ttl as i64) } else { json!(ttl) });
    if jti.is_some() {
        c.insert("jti".into(), json!(true));
    }
    if let Some(t) = txn {
        c.insert("txn".into(), if txn_given { t } else { json!(true) });
    }
    json!({ "header": seg(tok, 0), "claims": c })
}

#[test]
fn txn_tokens_vectors() {
    let cases = common::ref_cases_seeded("txn-tokens-rs");
    let mut bad = Vec::new();
    for c in &cases {
        let a = c["args"].as_array().unwrap();
        let got: Result<Value, String> = match c["fn"].as_str().unwrap() {
            "subActChain" => sub_act_chain(&a[0]),
            "actDepth" => act_depth(&a[0]).map(|d| json!(d)),
            "toRfc8693Act" => to_rfc8693_act(&a[0]),
            "toTransactionToken" => {
                let x = &a[0];
                let secret = common::b64d(x["seed"].as_str().unwrap());
                let issue = TxnIssue {
                    profile: x.get("profile").and_then(Value::as_str),
                    scope: x.get("scope"),
                    req_wl: x.get("reqWl"),
                    txn: x.get("txn").and_then(Value::as_str),
                    trust_domain: x.get("trustDomain"),
                    chain: &x["chain"],
                    action: &x["action"],
                    issuer_secret: &secret,
                    issuer: &x["issuer"],
                    ttl_sec: x.get("ttlSec").and_then(Value::as_f64),
                    now_sec: 1_800_000_000,
                    id: "generated-id",
                };
                to_transaction_token(&issue).map(|t| issued_view(&t, x.get("txn").is_some()))
            }
            "fromTransactionToken" => {
                let w = &a[2];
                let seen: Option<HashSet<String>> = w.get("seen").and_then(Value::as_array).map(|l| l.iter().filter_map(|x| x.as_str().map(String::from)).collect());
                let seen_fn = seen.as_ref().map(|s| move |id: &str, _exp: f64| s.contains(id));
                let o = FromTxnOptions {
                    profile: w.get("profile").and_then(Value::as_str),
                    audience: w.get("audience").and_then(Value::as_str),
                    clock_tolerance_sec: w.get("clockToleranceSec").and_then(Value::as_f64),
                    now_sec: w.get("nowMs").and_then(Value::as_f64).map(|ms| (ms / 1000.0).floor()),
                    seen_txn: seen_fn.as_ref().map(|f| f as &dyn Fn(&str, f64) -> bool),
                    replay_unchecked: w.get("unchecked") == Some(&json!(true)),
                };
                from_transaction_token(&a[0], &common::b64d(a[1].as_str().unwrap()), &o)
                    .map(|r| {
                        let mut m = Map::new();
                        m.insert("chain".into(), r.chain);
                        if let Some(x) = r.action {
                            m.insert("action".into(), x);
                        }
                        m.insert("tctx".into(), r.tctx);
                        m.insert("claims".into(), r.claims);
                        Value::Object(m)
                    })
                    .map_err(|e| e.message)
            }
            f => panic!("unknown fn {f}"),
        };
        let shown = format!("{got:?}");
        if !same(&c["out"], got) {
            bad.push(format!("{}\n  want {}\n  got  {shown}", c["name"], c["out"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn issued_tokens_verify_natively() {
    let seed = [7u8; 32];
    let pk = atlas_pca::serde_json::from_value::<String>(atlas_pca::jose::ed25519_public_jwk(&seed)["x"].clone()).unwrap();
    let chain = json!([{ "id": "c", "issuer": "P", "holder": "A", "caveats": [] }]);
    let action = json!({ "verb": "v", "resource": "r", "aud": "https://rs" });
    let (scope, wl, iss) = (json!("s"), json!("w"), json!("i"));
    let now = atlas_pca::jose::now_unix_sec() as i64;
    let t = to_transaction_token(&TxnIssue { profile: None, scope: Some(&scope), req_wl: Some(&wl), txn: None, trust_domain: None, chain: &chain, action: &action, issuer_secret: &seed, issuer: &iss, ttl_sec: None, now_sec: now, id: "T" }).unwrap();
    let seen = |_: &str, _: f64| false;
    let o = FromTxnOptions { audience: Some("https://rs"), seen_txn: Some(&seen), ..Default::default() };
    let r = from_transaction_token(&json!(t), &common::b64d(&pk), &o).unwrap();
    assert_eq!(r.chain, json!({ "sub": "P", "act": { "sub": "A" } }));
    let replayed = |_: &str, _: f64| true;
    let o = FromTxnOptions { audience: Some("https://rs"), seen_txn: Some(&replayed), ..Default::default() };
    assert!(from_transaction_token(&json!(t), &common::b64d(&pk), &o).is_err());
}
