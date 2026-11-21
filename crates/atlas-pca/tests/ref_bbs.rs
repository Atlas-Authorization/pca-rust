//! Differential replay of the BBS signature package (BLS12-381-SHA-256: hashing, generators, keys, sign / verify, proofs with
//! fixed randomness, and the capability-credential layer) against the TypeScript reference (test-data/ref-bbs.json.gz). A
//! reference throw only requires a refusal. Secret keys arrive as labels ({"$bbssk": n} = key_gen(32 bytes of n, no info)), as
//! arguments and as keyGen results. A lone surrogate (a sentinel in the loaded corpus) is
//! what a UTF-8 encoder turns into U+FFFD, so it is replaced by that before use. Skipped: none.
mod common;
use atlas_pca::bbs::*;
use atlas_pca::serde_json::{json, Value};

fn bytes(v: &Value) -> Vec<u8> {
    common::b64d(v["$bytes"].as_str().expect("$bytes"))
}

fn byte_list(v: &Value) -> Vec<Vec<u8>> {
    v.as_array().expect("list").iter().map(bytes).collect()
}

fn ints(v: &Value) -> Vec<i64> {
    v.as_array().expect("list").iter().map(|x| x.as_i64().unwrap_or(i64::MIN) /* a non-integer index never selects a message */).collect()
}

fn b(x: Vec<u8>) -> Value {
    use base64::Engine;
    json!({ "$bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&x) })
}

fn secret(v: &Value) -> Fr {
    match v.get("$bbssk").and_then(Value::as_u64) {
        Some(n) => key_gen(&[n as u8; 32], &[]).expect("labelled key"),
        None => Fr::from_hex(v.as_str().expect("hex scalar")).expect("scalar"),
    }
}

fn res(r: Result<(), String>) -> Value {
    match r {
        Ok(()) => json!({"ok": true}),
        Err(e) => json!({"ok": false, "reason": e}),
    }
}

fn fix_lone(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(s.replace(common::LONE, "\u{FFFD}")),
        Value::Array(a) => Value::Array(a.iter().map(fix_lone).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.replace(common::LONE, "\u{FFFD}"), fix_lone(x))).collect()),
        x => x.clone(),
    }
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "hashToScalar" => Ok(json!(hash_to_scalar(&bytes(&a[0]), a[1].as_str().unwrap()).to_hex())),
        "mapMessageToScalarAsHash" => Ok(json!(map_message_to_scalar_as_hash(&bytes(&a[0])).to_hex())),
        "createGenerators" => create_generators(a[0].as_i64().unwrap()).map(|g| Value::Array(g.into_iter().map(b).collect())),
        "keyGen" => key_gen(&bytes(&a[0]), &bytes(&a[1])).map(|sk| json!(sk.to_hex())),
        "skToPk" => sk_to_pk(&secret(&a[0])).map(b),
        "sign" => sign(&secret(&a[0]), &bytes(&a[1]), &bytes(&a[2]), &byte_list(&a[3])).map(b),
        "verifyDetailed" => Ok(res(verify_detailed(&bytes(&a[0]), &bytes(&a[1]), &bytes(&a[2]), &byte_list(&a[3])))),
        "proofGen" => {
            let rs: Vec<Fr> = a[6].as_array().unwrap().iter().map(|s| Fr::from_hex(s.as_str().unwrap()).unwrap()).collect();
            proof_gen(&bytes(&a[0]), &bytes(&a[1]), &bytes(&a[2]), &bytes(&a[3]), &byte_list(&a[4]), &ints(&a[5]), Some(&rs)).map(b)
        }
        "proofVerifyDetailed" => Ok(res(proof_verify_detailed(&bytes(&a[0]), &bytes(&a[1]), &bytes(&a[2]), &bytes(&a[3]), &byte_list(&a[4]), &ints(&a[5])))),
        "capabilityAttributes" => capability_attributes(&a[0]),
        "issueCapabilityCredential" => issue_capability_credential(&a[0], &secret(&a[1]), &bytes(&a[2]), &bytes(&a[3])),
        "verifyCredential" => Ok(json!(verify_credential(&a[0]))),
        "verifyPresentation" => {
            let o = &a[1];
            let opts = PresentOptions {
                public_key: o.get("pk").map(bytes),
                disclosed: o.get("disclosed").cloned(),
                presentation_header: o.get("presentationHeader").map(bytes),
            };
            Ok(json!(verify_presentation(&a[0], &opts)))
        }
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn matches_reference() {
    let cases = common::ref_cases("bbs");
    let mut bad = Vec::new();
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        let args: Vec<Value> = c["args"].as_array().unwrap().iter().map(fix_lone).collect();
        let want = match c["out"].get("$bbssk") {
            // a keyGen result that is a signing key: recorded as its label
            Some(_) if f == "keyGen" => json!(secret(&c["out"]).to_hex()),
            _ => c["out"].clone(),
        };
        let got = std::panic::catch_unwind(|| run(f, &args)).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (want.get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&want) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], want, got));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn round_trip_present_and_verify() {
    let (sk, pk) = generate_key_pair().unwrap();
    let cap = json!({"issuer": "i", "holder": "h", "caveats": [{"type": "amount", "max": 10}, {"type": "audience", "aud": "x"}]});
    let cred = issue_capability_credential(&cap, &sk, &pk, b"hdr").unwrap();
    assert!(verify_credential(&cred));
    let pres = present_credential(&cred, &["iss", "cav:1:audience"], b"ph").unwrap();
    assert!(verify_presentation(&pres, &PresentOptions::default()));
    assert!(!verify_presentation(&pres, &PresentOptions { presentation_header: Some(b"other".to_vec()), ..Default::default() }));
    assert!(present_credential(&cred, &["nope"], b"ph").is_err());
}
