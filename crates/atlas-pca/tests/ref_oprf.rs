//! Differential replay of the OPRF / VOPRF / POPRF core (RFC 9497 ristretto255-SHA512) and the private revocation / rate-limit layer
//! against the TypeScript reference (test-data/ref-oprf.json.gz). Bytes cross as {"$bytes": b64u}; a reference throw only requires a
//! refusal. Keys come from the corpus; the one extra key the lying-evaluator cases need is re-derived from the generator's seed label
//! (sha256("atlas-pca-conformance/ref-oprf/key-poprf"), info "k").
//! Skipped (counted, must stay under 10%): cases whose strings carry a lone surrogate (a Rust `&str` cannot hold one).
//! Not ported: randomScalar / randomKeyPair (random; the generator does not cover them).
mod common;
use atlas_pca::oprf::*;
use atlas_pca::serde_json::{json, Map, Value};
use base64::Engine;
use sha2::{Digest, Sha256};

fn b64e(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn js(b: &[u8]) -> Value {
    json!({ "$bytes": b64e(b) })
}

/// A `{"$bytes": ...}` value (anything else is the reference TypeError).
fn as_bytes(v: &Value) -> Option<Vec<u8>> {
    let m = v.as_object()?;
    if m.len() != 1 {
        return None;
    }
    Some(common::b64d(m.get("$bytes")?.as_str()?))
}

fn req(v: Option<&Value>) -> Result<Vec<u8>, String> {
    v.and_then(as_bytes).ok_or_else(|| "expected a Uint8Array".to_string())
}

/// An optional bytes argument: null / absent = None, bytes = Some, anything else is a refusal.
fn opt(v: Option<&Value>) -> Result<Option<Vec<u8>>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(x) => as_bytes(x).map(Some).ok_or_else(|| "expected a Uint8Array".to_string()),
    }
}

fn st(v: Option<&Value>) -> Result<&str, String> {
    v.and_then(Value::as_str).ok_or_else(|| "expected a string".to_string())
}

fn seed(label: &str) -> Vec<u8> {
    Sha256::digest(format!("atlas-pca-conformance/{label}")).to_vec()
}

fn ev_json(e: &Evaluated) -> Value {
    let mut m = Map::new();
    m.insert("evaluatedElement".into(), js(&e.evaluated_element));
    if let Some(p) = &e.proof {
        m.insert("proof".into(), js(p));
    }
    Value::Object(m)
}

fn sorted_outputs(s: &RevocationSet) -> Value {
    let mut o: Vec<&String> = s.outputs.iter().collect();
    o.sort();
    let mut m = Map::new();
    m.insert("outputs".into(), json!(o));
    m.insert("mode".into(), json!(s.mode));
    if let Some(pk) = &s.public_key {
        m.insert("publicKey".into(), js(pk));
    }
    Value::Object(m)
}

fn strings(v: Option<&Value>) -> Result<Vec<String>, String> {
    v.and_then(Value::as_array)
        .ok_or("expected an array")?
        .iter()
        .map(|x| x.as_str().map(String::from).ok_or_else(|| "expected a string".to_string()))
        .collect()
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let g = |i: usize| a.get(i);
    match f {
        "deriveKeyPair" => {
            let k = derive_key_pair(&req(g(0))?, &req(g(1))?, st(g(2))?)?;
            Ok(json!({ "secretKey": js(&k.secret_key), "publicKey": js(&k.public_key) }))
        }
        "publicKeyFor" => Ok(js(&public_key_for(&req(g(0))?)?)),
        "deserializeScalar" => Ok(Value::String(deserialize_scalar(&req(g(0))?)?.to_str_radix(10))),
        "serializeScalar" => Ok(js(&serialize_scalar_decimal(st(g(0))?)?)),
        "hashToGroup" => Ok(js(&hash_to_group(&req(g(0))?, st(g(1))?)?)),
        "deserializeElement" => Ok(js(&deserialize_element(&req(g(0))?)?)),
        "blind" => {
            let fixed = opt(g(2))?;
            let b = blind(&req(g(0))?, st(g(1))?, fixed.as_deref())?;
            Ok(json!({ "blind": js(&b.blind), "blindedElement": js(&b.blinded_element) }))
        }
        "blindEvaluate" => {
            let (pk, pr) = (opt(g(3))?, opt(g(4))?);
            Ok(ev_json(&blind_evaluate(&req(g(0))?, &req(g(1))?, st(g(2))?, pk.as_deref(), pr.as_deref())?))
        }
        "finalize" => {
            let o = g(4).and_then(Value::as_object);
            let field = |k: &str| opt(o.and_then(|o| o.get(k)));
            let (proof, pk, bl) = (field("proof")?, field("publicKey")?, field("blindedElement")?);
            Ok(js(&finalize(&req(g(0))?, &req(g(1))?, &req(g(2))?, st(g(3))?, proof.as_deref(), pk.as_deref(), bl.as_deref())?))
        }
        "evaluate" => Ok(js(&evaluate(&req(g(0))?, &req(g(1))?, st(g(2))?)?)),
        "blindPoprf" => {
            let fixed = opt(g(3))?;
            let b = blind_poprf(&req(g(0))?, &req(g(1))?, &req(g(2))?, fixed.as_deref())?;
            Ok(json!({ "blind": js(&b.blind), "blindedElement": js(&b.blinded_element), "tweakedKey": js(&b.tweaked_key) }))
        }
        "blindEvaluatePoprf" => {
            let pr = opt(g(3))?;
            Ok(ev_json(&blind_evaluate_poprf(&req(g(0))?, &req(g(1))?, &req(g(2))?, pr.as_deref())?))
        }
        "finalizePoprf" => {
            let o = g(4).and_then(Value::as_object).ok_or("expected an options object")?;
            let (proof, bl, tk) = (req(o.get("proof"))?, req(o.get("blindedElement"))?, req(o.get("tweakedKey"))?);
            Ok(js(&finalize_poprf(&req(g(0))?, &req(g(1))?, &req(g(2))?, &req(g(3))?, &proof, &bl, &tk)?))
        }
        "evaluatePoprf" => Ok(js(&evaluate_poprf(&req(g(0))?, &req(g(1))?, &req(g(2))?)?)),
        "toHex" => Ok(Value::String(to_hex(&req(g(0))?))),
        "bytesEqual" => Ok(Value::Bool(bytes_equal(&req(g(0))?, &req(g(1))?))),
        "buildRevocationSet" => {
            let s = build_revocation_set(&req(g(0))?, &strings(g(1))?, st(g(2))?)?;
            Ok(sorted_outputs(&s))
        }
        "isRevokedPrivate" => {
            let id = st(g(0))?;
            let o = g(1).and_then(Value::as_object).ok_or("expected an options object")?;
            let (sk, mode) = (req(o.get("sk"))?, st(o.get("mode"))?);
            let set = build_revocation_set(&sk, &strings(o.get("revoked"))?, mode)?;
            let lie = o.get("lie").and_then(Value::as_str).map(String::from);
            let key = if lie.as_deref() == Some("wrong-key") { derive_key_pair(&seed("ref-oprf/key-poprf"), b"k", "poprf")?.secret_key } else { sk };
            let real = make_revocation_evaluator(&key, mode)?;
            let eval = move |b: &[u8]| -> Result<Evaluated, String> {
                let mut r = real(b)?;
                if lie.as_deref() == Some("no-proof") {
                    r.proof = None;
                }
                Ok(r)
            };
            is_revoked_private(id, &eval, &set).map(Value::Bool)
        }
        "rateToken" => Ok(js(&rate_token(&req(g(0))?, st(g(1))?, st(g(2))?)?)),
        "rateTokenHex" => Ok(Value::String(rate_token_hex(&req(g(0))?, st(g(1))?, st(g(2))?)?)),
        "privateRateToken" => {
            let o = g(2).and_then(Value::as_object).ok_or("expected an options object")?;
            let sk = req(o.get("sk"))?;
            let pk = match opt(o.get("pk"))? {
                Some(p) => p,
                None => public_key_for(&sk)?,
            };
            let ev = make_rate_evaluator(&sk);
            Ok(js(&private_rate_token(st(g(0))?, st(g(1))?, &*ev, &pk)?))
        }
        "rateCounter" => {
            let c = RateWindowCounter::new(g(0).and_then(Value::as_i64).ok_or("RateWindowCounter: limit must be a positive integer")?)?;
            let mut out = Vec::new();
            for s in g(1).and_then(Value::as_array).ok_or("expected steps")? {
                let s = s.as_array().ok_or("expected a step")?;
                out.push(match st(s.first())? {
                    "hit" => {
                        let (n, ok) = c.hit(&req(s.get(1))?);
                        json!({ "count": n, "allowed": ok })
                    }
                    "count" => json!(c.count(&req(s.get(1))?)),
                    "reset" => {
                        c.reset();
                        Value::Null
                    }
                    _ => return Err("unknown step".into()),
                });
            }
            Ok(Value::Array(out))
        }
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn oprf_vectors() {
    let mut cases = common::ref_cases_seeded("oprf");
    cases.extend(common::ref_gen_cases("oprf", true));
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let args = c["args"].as_array().unwrap();
        let mut got = std::panic::catch_unwind(|| run(f, args)).unwrap_or_else(|_| Err("panic".into()));
        // the generator's "-dups" wrapper reports only {outputs, mode}
        if f == "buildRevocationSet" && c["name"].as_str().is_some_and(|n| n.ends_with("-dups")) {
            if let Ok(Value::Object(m)) = &mut got {
                m.remove("publicKey");
            }
        }
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
