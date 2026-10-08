use atlas_pca::*;
use ed25519_dalek::SigningKey;
use serde_json::Value;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/");

/// A Rust `String` cannot hold a lone surrogate, but `vectors.json` carries one in an OBJECT-form vector
/// (`"aud": "rs-\ud800"`), which `serde_json` refuses to load. Replace every lone surrogate escape inside a
/// JSON string with this sentinel; the harness then reports `wire` failure for any vector containing it
/// (exactly what a UTF-16 language reaches via the strict canonical encoder).
const LONE: char = '\u{10FFFF}';

fn sanitize_lone_surrogates(text: &str) -> String {
    let cs: Vec<char> = text.chars().collect();
    let hex = |at: usize| -> Option<u32> {
        let s: String = cs.get(at..at + 4)?.iter().collect();
        if s.chars().all(|c| c.is_ascii_hexdigit()) {
            u32::from_str_radix(&s, 16).ok()
        } else {
            None
        }
    };
    let mut out = String::with_capacity(text.len());
    let (mut i, mut in_str) = (0, false);
    while i < cs.len() {
        let c = cs[i];
        if !in_str {
            in_str = c == '"';
            out.push(c);
            i += 1;
        } else if c == '"' {
            in_str = false;
            out.push(c);
            i += 1;
        } else if c == '\\' {
            if cs.get(i + 1) == Some(&'u') {
                match hex(i + 2) {
                    Some(hi) if (0xD800..=0xDBFF).contains(&hi) => {
                        let paired = cs.get(i + 6) == Some(&'\\')
                            && cs.get(i + 7) == Some(&'u')
                            && hex(i + 8).map_or(false, |lo| (0xDC00..=0xDFFF).contains(&lo));
                        if paired {
                            out.extend(&cs[i..i + 12]);
                            i += 12;
                        } else {
                            out.push(LONE);
                            i += 6;
                        }
                    }
                    Some(lo) if (0xDC00..=0xDFFF).contains(&lo) => {
                        out.push(LONE);
                        i += 6;
                    }
                    _ => {
                        out.extend(&cs[i..(i + 2).min(cs.len())]);
                        i += 2;
                    }
                }
            } else {
                out.extend(&cs[i..(i + 2).min(cs.len())]);
                i += 2;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

fn load(name: &str) -> Value {
    let b = std::fs::read_to_string(format!("{DIR}{name}")).expect("read file");
    serde_json::from_str(&sanitize_lone_surrogates(&b)).expect("parse json")
}

fn has_lone(v: &Value) -> bool {
    match v {
        Value::String(s) => s.contains(LONE),
        Value::Array(a) => a.iter().any(has_lone),
        Value::Object(m) => m.iter().any(|(k, x)| k.contains(LONE) || has_lone(x)),
        _ => false,
    }
}

fn b64d(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()
}

#[test]
fn vectors() {
    let doc = load("vectors.json");
    assert_eq!(doc["format"].as_i64(), Some(2));
    let vs = doc["vectors"].as_array().expect("vectors");
    assert!(!vs.is_empty());
    // This verifier implements the ed25519 signature suite AND the B4 post-quantum suites (ml-dsa-65,
    // hybrid-ed25519-ml-dsa-65) via the fips204 crate — for the LEAF signature (requires:"pq") AND for
    // non-leaf capability-chain hops (requires:"pq-nonleaf"). Vectors tagged with a `requires` suite we do
    // not support are skipped explicitly, not silently.
    const SUPPORTED_SUITES: &[&str] = &["ed25519", "pq", "pq-nonleaf"];
    let mut bad = Vec::new();
    let mut skipped = 0usize;
    for v in vs {
        let name = v["name"].as_str().unwrap();
        if let Some(req) = v.get("requires").and_then(Value::as_str) {
            if !req.is_empty() && !SUPPORTED_SUITES.contains(&req) {
                skipped += 1;
                continue;
            }
        }
        let now = v["context"]["now"].as_i64().unwrap();
        let aud = v["context"]["aud"].as_str().unwrap();
        let got = if let Some(raw) = v.get("pcactn_json").and_then(Value::as_str) {
            verify_pcactn_json(raw, &v["grant"], now, aud)
        } else if has_lone(&v["pcactn"]) {
            // not representable as a Rust String: a lone surrogate is a wire failure
            let mut checks = std::collections::BTreeMap::new();
            checks.insert("wire".to_string(), false);
            Verdict { allow: false, checks, reason: "wire: lone surrogate".into() }
        } else {
            verify_pcactn_core(&v["pcactn"], &v["grant"], now, aud)
        };
        let exp = &v["expect"];
        if got.allow != exp["allow"].as_bool().unwrap() {
            bad.push(format!("{name}: allow = {}, want {} ({})", got.allow, exp["allow"], got.reason));
        }
        let want = exp["checks"].as_object().unwrap();
        if got.checks.len() != want.len() {
            bad.push(format!("{name}: checks {:?}, want {:?}", got.checks, want));
        }
        for (k, w) in want {
            if got.checks.get(k) != w.as_bool().as_ref() {
                bad.push(format!("{name}: check {k} = {:?}, want {w} ({})", got.checks.get(k), got.reason));
            }
        }
    }
    assert!(bad.is_empty(), "{} of {} vectors failed:\n{}", bad.len(), vs.len() - skipped, bad.join("\n"));
    if skipped > 0 {
        eprintln!("skipped {skipped} vectors requiring unsupported suite: pq");
    }
    eprintln!("{} vectors passed ({} skipped)", vs.len() - skipped, skipped);
}

#[test]
fn primitives() {
    let doc = load("vectors.json");
    let prim = &doc["primitives"];
    for c in prim["canonical"].as_array().unwrap() {
        assert_eq!(canonicalize_strict(&c["value"]).unwrap(), c["expect"].as_str().unwrap());
        assert_eq!(hash_canonical(&c["value"]), c["hash"].as_str().unwrap());
    }
    for m in prim["merkle"].as_array().unwrap() {
        let leaves = m["leaves"].as_array().unwrap();
        let root = merkle_root(leaves).unwrap();
        assert_eq!(root, m["root"].as_str().unwrap());
        for (i, p) in m["proofs"].as_array().unwrap().iter().enumerate() {
            assert!(verify_inclusion(&root, p.as_object(), &leaves[i]), "proof {i}");
        }
    }
    assert_eq!(params_digest(None), prim["params_digest_empty"].as_str().unwrap());
}

#[test]
fn json_parse_table() {
    let doc = load("vectors.json");
    let mut bad = Vec::new();
    for t in doc["primitives"]["json_parse"].as_array().unwrap() {
        let input = t["input"].as_str().unwrap();
        let accept = t["accept"].as_bool().unwrap();
        match (strict_parse(input), accept) {
            (Ok(v), true) => {
                if let Some(c) = t["canonical"].as_str() {
                    if canonicalize_strict(&v).ok().as_deref() != Some(c) {
                        bad.push(format!("{input:?}: canonical {:?}, want {c:?}", canonicalize_strict(&v)));
                    }
                }
            }
            (Err(_), false) => {}
            (Ok(_), false) => bad.push(format!("{input:?}: accepted, want reject")),
            (Err(e), true) => bad.push(format!("{input:?}: rejected ({e}), want accept")),
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn b64u_table() {
    let doc = load("vectors.json");
    let mut bad = Vec::new();
    for t in doc["primitives"]["b64u"].as_array().unwrap() {
        let input = t["input"].as_str().unwrap();
        let valid = t["valid"].as_bool().unwrap();
        let len = t.get("len").and_then(Value::as_u64).map(|n| n as usize);
        if decode_b64u_strict(input, len).is_some() != valid {
            bad.push(format!("{input:?} (len {len:?}): want valid={valid}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn keys_consistent() {
    let keys = load("keys.json");
    for (label, k) in keys.as_object().unwrap() {
        let seed: [u8; 32] = b64d(k["seed"].as_str().unwrap()).try_into().unwrap();
        let sk = SigningKey::from_bytes(&seed);
        assert_eq!(sk.verifying_key().to_bytes().to_vec(), b64d(k["public"].as_str().unwrap()), "{label}");
    }
}
