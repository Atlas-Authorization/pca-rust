//! Differential replay of the agent-passport VC bridge against the TypeScript reference (test-data/ref-vc.json.gz): did:key and
//! base58btc, the SD-JWT VC (issued output compared in the generator's normalized form, since salts are random) and RFC 9421
//! request signatures. A reference throw only requires a refusal. Cases with a lone surrogate are skipped.
mod common;
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::vc::*;

const NOW_SEC: i64 = 1_700_000_100;

fn b64e(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn bytes(v: &Value) -> Vec<u8> {
    common::b64d(v["$bytes"].as_str().expect("$bytes"))
}

fn seed32(v: &Value) -> Result<[u8; 32], String> {
    bytes(v).try_into().map_err(|_| "a seed is 32 bytes".to_string())
}

fn out_bytes(b: Vec<u8>) -> Value {
    json!({ "$bytes": b64e(&b) })
}

fn seg(s: &str) -> Value {
    atlas_pca::serde_json::from_slice(&common::b64d(s)).unwrap()
}

/// The generator's normalized view of an issued VC.
fn norm_vc(sd: &str, verify_key: &[u8; 32]) -> Value {
    let parts: Vec<&str> = sd.split('~').collect();
    let ds = &parts[1..parts.len() - 1];
    let jwt: Vec<&str> = parts[0].split('.').collect();
    let (h, mut p) = (seg(jwt[0]), seg(jwt[1]));
    let cs = &mut p["vc"]["credentialSubject"];
    let mut sdl: Vec<String> = cs.get("_sd").and_then(Value::as_array).map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect()).unwrap_or_default();
    sdl.sort();
    if let Some(m) = cs.as_object_mut() {
        m.remove("_sd");
    }
    let mut digs: Vec<String> = ds.iter().map(|d| b64e(&<sha2::Sha256 as sha2::Digest>::digest(d.as_bytes()))).collect();
    digs.sort();
    let mut disc: Vec<Value> = ds.iter().map(|d| seg(d)).map(|d| json!([d[1], d[2]])).collect();
    disc.sort_by(|a, b| a[0].as_str().cmp(&b[0].as_str()));
    let verified = verify_passport_vc(&json!(sd), verify_key, None, NOW_SEC as f64).is_ok();
    json!({ "end": parts[parts.len() - 1], "header": h, "payload": p, "n": ds.len(), "digestsOk": digs == sdl, "disclosures": disc, "verified": verified })
}

fn camel(a: &Value, map: &[(&str, &str)]) -> Value {
    let mut m = Map::new();
    for (k, v) in a.as_object().into_iter().flatten() {
        let c = map.iter().find(|(s, _)| s == k).map_or(k.as_str(), |(_, c)| c);
        m.insert(c.into(), v.clone());
    }
    Value::Object(m)
}

#[test]
fn vc_vectors() {
    let cases = common::ref_cases("vc");
    let p1 = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]).verifying_key().to_bytes();
    let (mut bad, mut skipped) = (Vec::new(), 0);
    let none = Value::Null;
    for c in &cases {
        if common::has_lone(c) {
            skipped += 1;
            continue;
        }
        let a = c["args"].as_array().unwrap();
        let arg = |i: usize| a.get(i).unwrap_or(&none);
        let got: Result<Value, String> = match c["fn"].as_str().unwrap() {
            "base58btcEncode" => Ok(json!(base58btc_encode(&bytes(arg(0))))),
            "base58btcDecode" => base58btc_decode(arg(0)).map(out_bytes),
            "didKeyFromEd25519" => did_key_from_ed25519(&bytes(arg(0))).map(Value::String),
            "ed25519FromDidKey" => ed25519_from_did_key(arg(0)).map(out_bytes),
            "resolveAgentPassportContext" => Ok(resolve_agent_passport_context(arg(0))),
            "constants" => Ok(json!({
                "VC_CONTEXT": VC_CONTEXT,
                "AGENT_PASSPORT_CONTEXT": AGENT_PASSPORT_CONTEXT,
                "AGENT_PASSPORT_VC_TYPE": AGENT_PASSPORT_VC_TYPE,
                "AGENT_PASSPORT_CONTEXT_DIGEST": agent_passport_context_digest(),
                "AGENT_PASSPORT_CONTEXT_DOC": agent_passport_context_doc(),
            })),
            "passportToVC" => {
                let o = arg(1);
                seed32(&o["issuer_seed"])
                    .and_then(|s| passport_to_vc(arg(0), &s, o.get("issuer_did"), o.get("subject_did"), o.get("ttl_sec"), NOW_SEC))
                    .map(|sd| norm_vc(&sd, &p1))
            }
            "verifyPassportVC" => seed32(arg(1)).and_then(|k| verify_passport_vc(arg(0), &k, a.get(2), NOW_SEC as f64)),
            "signRequestMessage" => {
                let o = arg(0);
                seed32(&o["key"]).and_then(|s| sign_request_message(&camel(o, &[("signature_agent", "signatureAgent")]), &s, NOW_SEC))
            }
            "verifyRequestSignature" => {
                let map = [
                    ("signature_input", "signatureInput"),
                    ("signature_agent", "signatureAgent"),
                    ("required_components", "requiredComponents"),
                    ("max_age_sec", "maxAgeSec"),
                    ("now_sec", "nowSec"),
                ];
                seed32(arg(1)).map(|k| json!(verify_request_signature(&camel(arg(0), &map), &k)))
            }
            f => panic!("unknown fn {f}"),
        };
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), r) => r.is_err(),
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            (None, Err(_)) => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {got:?}", c["name"], c["out"]));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} lone-surrogate cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
