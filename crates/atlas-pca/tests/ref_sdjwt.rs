//! Differential replay of the SD-JWT bridge against the TypeScript reference (test-data/ref-sdjwt.json.gz): issuance (compared
//! in the generator's normalized form, since salts are random), presentation (byte-exact, Ed25519 is deterministic),
//! verification and core re-verification of the recovered PCActn.
//! A reference refusal must be a refusal; its text is compared exactly unless it is a JavaScript runtime / key-object message
//! (no Rust counterpart). Cases with a lone surrogate are skipped.
mod common;
use atlas_pca::sdjwt::*;
use atlas_pca::serde_json::{json, Map, Value};

/// Refusal texts from the JS crypto runtime (key-object / JWK import), which a native verifier words differently.
const RUNTIME: [&str; 6] = ["Invalid key for", "KeyObject instances", "Invalid JWK", "Key for the", "alg none is not supported", "is not iterable"];
/// Cases where the native side is deliberately stricter than the reference (refuses where the reference accepts).
const STRICTER: [&str; 3] = [
    "verifyPcaSdJwt/real now invalid date",    // a clock outside the Date range: the reference then skips every time check
    "verifyPcaSdJwt/cnf jwk with d",           // a cnf key carrying its private half
    "verifyPcaSdJwt/es256 jwk with d refused", // a private JWK as the issuer verification key
];
/// The native API takes a raw key as a base64url string, so a string that is not a key reads as a short key.
const OTHER_TEXT: [&str; 1] = ["issuePcaSdJwt/key_binding holder string"];

fn b64e(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// `{"$bytes": s}` -> s (the native options carry raw keys as base64url strings), recursively.
fn unbytes(v: &Value) -> Value {
    match v {
        Value::Object(m) if m.len() == 1 && m.contains_key("$bytes") => m["$bytes"].clone(),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), unbytes(x))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(unbytes).collect()),
        x => x.clone(),
    }
}

fn bytes(v: &Value) -> Vec<u8> {
    common::b64d(v["$bytes"].as_str().expect("$bytes"))
}

fn seg(s: &str) -> Value {
    atlas_pca::serde_json::from_slice(&common::b64d(s)).unwrap()
}

fn camel(a: &Value, map: &[(&str, &str)]) -> Value {
    let mut m = Map::new();
    for (k, v) in a.as_object().into_iter().flatten() {
        let c = map.iter().find(|(s, _)| s == k).map_or(k.as_str(), |(_, c)| c);
        m.insert(c.into(), unbytes(v));
    }
    Value::Object(m)
}

const VERIFY_OPTS: [(&str, &str); 11] = [
    ("required_disclosures", "requiredDisclosures"),
    ("expected_audience", "expectedAudience"),
    ("expected_kb_audience", "expectedKbAudience"),
    ("expected_nonce", "expectedNonce"),
    ("require_key_binding", "requireKeyBinding"),
    ("kb_algorithms", "kbAlgorithms"),
    ("kb_max_age_sec", "kbMaxAgeSec"),
    ("clock_tolerance_sec", "clockToleranceSec"),
    ("key_binding_key", "keyBindingKey"),
    ("algorithms", "algorithms"),
    ("now", "now"),
];

/// The generator's normalized view of an issued SD-JWT (`verified` only when the issue time is a valid JS Date).
fn norm_issued(sd: &str, issuer_seed: &[u8; 32]) -> Value {
    let parts: Vec<&str> = sd.split('~').collect();
    let ds = &parts[1..parts.len() - 1];
    let jwt: Vec<&str> = parts[0].split('.').collect();
    let (h, mut p) = (seg(jwt[0]), seg(jwt[1]));
    let mut sdl: Vec<String> = p.get("_sd").and_then(Value::as_array).map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect()).unwrap_or_default();
    sdl.sort();
    p.as_object_mut().unwrap().remove("_sd");
    let mut digs: Vec<String> = ds.iter().map(|d| b64e(&<sha2::Sha256 as sha2::Digest>::digest(d.as_bytes()))).collect();
    digs.sort();
    let mut disc: Vec<Value> = ds.iter().map(|d| seg(d)).map(|d| json!([d[1], d[2]])).collect();
    disc.sort_by(|a, b| a[0].as_str().cmp(&b[0].as_str()));
    let pk = ed25519_dalek::SigningKey::from_bytes(issuer_seed).verifying_key().to_bytes();
    let now = p["iat"].as_f64().unwrap() * 1000.0;
    let verified = if now.abs() <= 8.64e15 { json!(verify_pca_sd_jwt(&json!(sd), &SdJwtKey::Ed25519(pk), &json!({ "now": now }))["ok"]) } else { Value::Null };
    json!({ "end": parts[parts.len() - 1], "header": h, "payload": p, "n": ds.len(), "digestsOk": digs == sdl, "disclosures": disc, "verified": verified })
}

fn refusal_matches(name: &str, want: &str, got: &str) -> bool {
    if RUNTIME.iter().any(|r| want.contains(r)) || OTHER_TEXT.contains(&name) {
        return true;
    }
    if let Some(inner) = want.strip_prefix("KB-JWT signature/claims invalid: ") {
        return got.starts_with("KB-JWT signature/claims invalid: ") && (RUNTIME.iter().any(|r| inner.contains(r)) || got == want);
    }
    if want.starts_with("non-canonical compact JWS: bad-json") {
        return got.starts_with("non-canonical compact JWS: bad-json");
    }
    want == got
}

fn same_result(name: &str, want: &Value, got: Result<Value, String>) -> Result<(), String> {
    match (want.get("$throws").and_then(Value::as_str), got) {
        (Some(w), Err(g)) if refusal_matches(name, w, &g) => Ok(()),
        (None, Ok(g)) if atlas_pca::canonicalize(want) == atlas_pca::canonicalize(&g) => Ok(()),
        (_, g) => Err(format!("want {want}, got {g:?}")),
    }
}

fn issue_case(args: &[Value]) -> Result<Value, String> {
    let opt = &args[1];
    let seed = bytes(&opt["issuer_seed"]);
    let mut o = camel(opt, &[("signing_alg", "signingAlg"), ("key_binding", "keyBinding")]);
    o.as_object_mut().unwrap().remove("issuer_seed");
    if let Some(kb) = o.get_mut("keyBinding").and_then(Value::as_object_mut) {
        if let Some(h) = kb.remove("holder_public_key") {
            kb.insert("holderPublicKey".into(), h);
        }
    }
    let sd = issue_pca_sd_jwt(&args[0], &seed, &o)?;
    Ok(norm_issued(&sd, &seed.try_into().unwrap()))
}

fn present_case(args: &[Value]) -> Result<Value, String> {
    let kb = args.get(2).and_then(|o| o.get("key_binding"));
    let seed = kb.map(|k| bytes(&k["holder_seed"]));
    present(&args[0], &args[1], seed.as_deref(), kb.unwrap_or(&Value::Null)).map(Value::String)
}

fn verify_case(args: &[Value]) -> Result<Value, String> {
    let ik = &args[1]["issuer_key"];
    let key = if ik.get("$bytes").is_some() { SdJwtKey::ed25519(&bytes(ik))? } else { SdJwtKey::Jwk(ik.clone()) };
    let mut o = camel(&args[1], &VERIFY_OPTS);
    o.as_object_mut().unwrap().retain(|k, _| VERIFY_OPTS.iter().any(|(_, c)| c == k));
    Ok(verify_pca_sd_jwt(&args[0], &key, &o))
}

#[test]
fn sdjwt_replays_the_reference() {
    let (mut fails, mut ran, mut skipped) = (Vec::new(), 0, 0);
    for c in common::ref_cases("sdjwt") {
        let (name, args, want) = (c["name"].as_str().unwrap().to_string(), c["args"].as_array().unwrap().clone(), &c["out"]);
        if common::has_lone(&c) {
            skipped += 1;
            continue;
        }
        let r: Result<(), String> = match c["fn"].as_str().unwrap() {
            "constants" => {
                let got = json!({ "SD_ALG": SD_ALG, "PCA_SD_JWT_TYP": PCA_SD_JWT_TYP, "KB_JWT_TYP": KB_JWT_TYP, "DEFAULT_SIGNING_ALG": DEFAULT_SIGNING_ALG, "PCA_CAPABILITY_CLAIMS": PCA_CAPABILITY_CLAIMS });
                same_result(&name, want, Ok(got))
            }
            "ed25519PublicJwk" => same_result(&name, want, ed25519_public_jwk(&bytes(&args[0]))),
            "importEd25519PrivateKey" => same_result(&name, want, ed25519_seed(&bytes(&args[0])).map(|_| json!("ok"))),
            "importEd25519PublicKey" => same_result(&name, want, SdJwtKey::ed25519(&bytes(&args[0])).map(|_| json!("ok"))),
            "issuePcaSdJwt" => match issue_case(&args) {
                Ok(mut g) if want.get("$throws").is_none() => {
                    if g["verified"].is_null() {
                        g["verified"] = want["verified"].clone(); // issue time outside the Date range: the native verifier refuses that clock
                    }
                    same_result(&name, want, Ok(g))
                }
                g => same_result(&name, want, g),
            },
            "present" => same_result(&name, want, present_case(&args)),
            "verifyPcaSdJwt" => {
                let got = verify_case(&args);
                if STRICTER.contains(&name.as_str()) {
                    match &got {
                        Ok(v) if v["ok"] == json!(false) => Ok(()),
                        Err(_) => Ok(()),
                        g => Err(format!("stricter case must refuse, got {g:?}")),
                    }
                } else {
                    match (want.get("ok"), got) {
                        (Some(Value::Bool(false)), Ok(g)) if g["ok"] == json!(false) => {
                            let (w, gr) = (want["reason"].as_str().unwrap(), g["reason"].as_str().unwrap_or(""));
                            if refusal_matches(&name, w, gr) {
                                Ok(())
                            } else {
                                Err(format!("reason: want {w:?}, got {gr:?}"))
                            }
                        }
                        (_, g) => same_result(&name, want, g),
                    }
                }
            }
            "verifyRecovered" => {
                let opt = &args[1];
                match opt.get("audience").and_then(Value::as_str) {
                    // the core verifier always checks the audience: "accept any audience" (null) / omitted has no native form
                    None => {
                        skipped += 1;
                        continue;
                    }
                    Some(aud) => {
                        let v = verify_recovered(
                            &args[0],
                            &opt["grant"],
                            aud,
                            opt["now"].as_i64().unwrap(),
                            opt.get("insecure_skip_plan_root_check") == Some(&json!(true)),
                        );
                        let w_reason = want.get("reason").and_then(Value::as_str).unwrap_or("");
                        if v.allow != want["allow"].as_bool().unwrap() {
                            Err(format!("allow: want {want}, got {} ({})", v.allow, v.reason))
                        } else if w_reason.starts_with("pca-sdjwt:") && v.reason != w_reason {
                            Err(format!("reason: want {w_reason:?}, got {:?}", v.reason))
                        } else {
                            Ok(())
                        }
                    }
                }
            }
            f => Err(format!("unknown fn {f}")),
        };
        ran += 1;
        if let Err(e) = r {
            fails.push(format!("{name}: {e}"));
        }
    }
    assert!(skipped * 10 < ran, "too many skipped: {skipped} of {ran}");
    assert!(fails.is_empty(), "{} of {ran} cases differ:\n{}", fails.len(), fails.join("\n"));
}
