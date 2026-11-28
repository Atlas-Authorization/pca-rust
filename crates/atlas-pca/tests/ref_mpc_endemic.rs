#![cfg(feature = "mpc-endemic")]
//! Differential replay of the endemic LWE base OT (Kyber-768 K-PKE through the pca-mpc-lwe-ot-wasm safe API) against the TypeScript
//! reference (test-data/ref-mpc-endemic.json.gz). Receiver keys come from seed labels (seed = sha256("atlas-pca-conformance/" + label));
//! every random draw is the seeded SplitMix64 stream, so every nonce, point, ciphertext and pad matches the reference byte for byte.
//! A reference throw only requires a refusal. Skipped: nothing.
mod common;
use atlas_pca::mpc_endemic::*;
use atlas_pca::mpc_ot::OtRng;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;
use sha2::{Digest, Sha256};

type R = Result<Value, String>;

fn b64(b: &[u8]) -> Value {
    json!({ "$bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b) })
}

fn bytes(v: &Value) -> Result<Vec<u8>, String> {
    let s = v.get("$bytes").and_then(Value::as_str).ok_or("expected bytes")?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).map_err(|e| e.to_string())
}

fn text(v: &Value) -> Result<&str, String> {
    v.as_str().ok_or_else(|| "not a string".to_string())
}

fn seed(label: &str) -> Vec<u8> {
    Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes()).to_vec()
}

fn rng(v: &Value) -> Result<OtRng, String> {
    OtRng::from_decimal(text(v)?).map_err(|e| e.to_string())
}

fn choices(v: &Value) -> Result<Vec<u8>, String> {
    v.as_array().ok_or("not a list")?.iter().map(|x| x.as_u64().map(|n| n as u8).ok_or_else(|| "bad choice".to_string())).collect()
}

fn pairs_out(p: &[(Vec<u8>, Vec<u8>)]) -> Value {
    Value::Array(p.iter().map(|(a, b)| json!([b64(a), b64(b)])).collect())
}

fn list_out(p: &[Vec<u8>]) -> Value {
    Value::Array(p.iter().map(|a| b64(a)).collect())
}

fn flip(b: &[u8]) -> Vec<u8> {
    b.iter().map(|x| x ^ 1).collect()
}

fn e<T: ToString>(x: T) -> String {
    x.to_string()
}

fn key_out(k: (Vec<u8>, Vec<u8>)) -> R {
    Ok(json!({ "pk": b64(&k.0), "skSha256": Sha256::digest(&k.1).iter().map(|x| format!("{x:02x}")).collect::<String>() }))
}

fn run(f: &str, a: &[Value]) -> R {
    let n = Value::Null;
    let g = |i: usize| a.get(i).unwrap_or(&n);
    match f {
        "lweKeygenFips" => key_out(kpke_keygen_fips203(&seed(text(g(0))?)).map_err(e)?),
        "lweKeygen" => key_out(kpke_keygen(&seed(text(g(0))?)).map_err(e)?),
        "lweEnc" => {
            let (pk, _) = kpke_keygen(&seed(text(g(0))?)).map_err(e)?;
            Ok(b64(&kpke_enc(&pk, &bytes(g(1))?, &bytes(g(2))?).map_err(e)?))
        }
        "lweDec" => {
            let (_, sk) = kpke_keygen(&seed(text(g(0))?)).map_err(e)?;
            Ok(b64(&kpke_dec(&sk, &bytes(g(1))?).map_err(e)?))
        }
        "lweRing" => {
            let (x, y) = (bytes(g(1))?, bytes(g(2))?);
            let r = if text(g(0))? == "add" { ring_add(&x, &y) } else { ring_sub(&x, &y) };
            Ok(b64(&r.map_err(e)?))
        }
        "lweHash" => Ok(b64(&hash_to_ring(&bytes(g(0))?).map_err(e)?)),
        "randomOt" | "randomOtTamper" => {
            let (mut r, mut s) = (rng(g(1))?, rng(g(2))?);
            let (msg, st) = receive(&choices(g(0))?, &mut r).map_err(e)?;
            let trunc = |c: &mut Vec<(Vec<u8>, Vec<u8>)>| c[0].0.truncate(1087);
            let tamper: Option<&dyn Fn(&mut Vec<(Vec<u8>, Vec<u8>)>)> = if f == "randomOtTamper" { Some(&trunc) } else { None };
            let sm = send_random(&msg, &mut s, tamper).map_err(e)?;
            let recv = recover_random(&st, &sm).map_err(e)?;
            Ok(json!({ "rn": b64(&msg.rn), "points": pairs_out(&msg.points), "rhos": list_out(&msg.rhos), "ciphertexts": pairs_out(&sm.ciphertexts),
                       "senderPads": pairs_out(&sm.sender_pads), "recvPads": list_out(&recv) }))
        }
        "baseOt" => {
            let msgs: Vec<(Vec<u8>, Vec<u8>)> =
                g(0).as_array().ok_or("not a list")?.iter().map(|p| Ok((bytes(&p[0])?, bytes(&p[1])?))).collect::<Result<_, String>>()?;
            let ch = choices(g(1))?;
            let c0 = ch.first().map_or(0, |c| (c & 1) as usize);
            let mut one = rng(g(2))?;
            let enc_tamper = |slot: usize| move |t: &mut Vec<(Vec<u8>, Vec<u8>)>| if slot == 0 { t[0].0 = flip(&t[0].0) } else { t[0].1 = flip(&t[0].1) };
            let (t_enc, t_chosen) = (enc_tamper(0), enc_tamper(c0));
            let tamper: Option<&dyn Fn(&mut Vec<(Vec<u8>, Vec<u8>)>)> = match text(g(3))? {
                "enc" => Some(&t_enc),
                "encChosen" => Some(&t_chosen),
                _ => None,
            };
            let (recv, t) = base_ot(&msgs, &ch, &mut one, None, tamper).map_err(e)?;
            Ok(json!({ "received": list_out(&recv), "ciphertexts": pairs_out(&t.ciphertexts), "encrypted": pairs_out(&t.encrypted),
                       "commitments": pairs_out(&t.commitments) }))
        }
        "sendMalformed" => {
            let (m, _) = receive(&[0, 1], &mut OtRng::from_decimal("77").map_err(e)?).map_err(e)?;
            let mut m = m;
            let fill = |n: usize, k: usize| -> Vec<u8> { (0..n).map(|i| ((i * 31 + k * 7 + (i >> 3)) & 255) as u8).collect() };
            match text(g(0))? {
                "nonce" => m.rn = fill(31, 1),
                "count" => {
                    m.rhos.remove(0);
                }
                "point" => m.points[1].0 = fill(1151, 1),
                "rho" => m.rhos[0] = fill(33, 1),
                _ => {}
            }
            Ok(json!(send_random(&m, &mut OtRng::from_decimal("78").map_err(e)?, None).map_err(e)?.ciphertexts.len()))
        }
        _ => Err(format!("unknown fn {f}")),
    }
}

#[test]
fn replays_the_endemic_lwe_base_ot() {
    let cases = common::ref_cases("mpc-endemic");
    assert!(cases.len() >= 80, "corpus shrank: {}", cases.len());
    let mut failures = vec![];
    for c in &cases {
        let (f, name) = (c["fn"].as_str().expect("fn"), c["name"].as_str().expect("name"));
        let (args, want) = (c["args"].as_array().expect("args"), &c["out"]);
        let got = run(f, args);
        if want.get("$throws").is_some() {
            if let Ok(v) = got {
                failures.push(format!("{name}: the reference refuses but the native returned {v}"));
            }
        } else {
            match got {
                Ok(v) if &v == want => {}
                Ok(_) => failures.push(format!("{name}: output differs")),
                Err(er) => failures.push(format!("{name}: refused ({er})")),
            }
        }
    }
    assert!(failures.is_empty(), "{} of {} cases differ; first: {:#?}", failures.len(), cases.len(), &failures[..failures.len().min(10)]);
}
