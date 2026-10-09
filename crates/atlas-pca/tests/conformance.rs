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

/// The signature suites this Rust verifier implements — for the LEAF signature (`requires:"pq"`), for
/// non-leaf capability-chain hops (`requires:"pq-nonleaf"`), and for the threshold-share binding. The three
/// CROSS-IMPL suites every conformant impl is required to agree on (GAP 1): classical Ed25519, the pure
/// lattice ML-DSA-65 (FIPS-204, via the `fips204` crate), and the hybrid Ed25519 + ML-DSA-65. The remaining
/// registered suites (ml-dsa-87, slh-dsa-sha2-128f/256s, their hybrids, and the SUF-CMA nested hybrid) are
/// NOT yet wired in Rust, so vectors that need a real signature verdict under them are skipped explicitly.
const SUPPORTED_SUITES: &[&str] = &["ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65"];

/// Which concrete signature suite a vector exercises that this verifier does NOT implement, if any:
/// the leaf `alg` for `requires:"pq"`, or any capability-hop `alg` for `requires:"pq-nonleaf"`.
/// `None` for core vectors and for vectors that stay entirely within [`SUPPORTED_SUITES`].
fn unsupported_suite(v: &Value) -> Option<String> {
    let p = v.get("pcactn")?;
    let alg = |o: &Value| o.get("alg").and_then(Value::as_str).unwrap_or("ed25519").to_string();
    match v.get("requires").and_then(Value::as_str) {
        Some("pq") => {
            let a = alg(p);
            (!SUPPORTED_SUITES.contains(&a.as_str())).then_some(a)
        }
        Some("pq-nonleaf") => p
            .get("cap_chain")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(alg)
            .find(|a| !SUPPORTED_SUITES.contains(&a.as_str())),
        _ => None,
    }
}

#[test]
fn vectors() {
    let doc = load("vectors.json");
    assert_eq!(doc["format"].as_i64(), Some(2));
    let vs = doc["vectors"].as_array().expect("vectors");
    assert!(!vs.is_empty());
    let mut bad = Vec::new();
    let mut skipped = 0usize;
    let mut skipped_suites: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for v in vs {
        let name = v["name"].as_str().unwrap();
        let want = v["expect"]["checks"].as_object().unwrap();
        // A terminal `wire` failure ({wire:false}) is suite-agnostic: this verifier rejects an unknown /
        // unimplemented suite at the wire stage (unknown `alg`, or a `pq_sig` the suite requires but we
        // cannot size), which IS the correct contract verdict for those negatives, so we still run them.
        // A vector whose expected verdict needs a genuine signature outcome under an unsupported suite
        // (every positive, and every `*-corrupt-sig`/`*-corrupt-pqsig` that expects `wire:true`) is skipped
        // with an explicit count — never silently passed.
        let terminal_wire_false = want.len() == 1 && want.get("wire") == Some(&Value::Bool(false));
        if let Some(suite) = unsupported_suite(v) {
            if !terminal_wire_false {
                skipped += 1;
                skipped_suites.insert(suite);
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
    eprintln!(
        "{} of {} vectors passed; {skipped} skipped (suites not yet in Rust: {})",
        vs.len() - skipped,
        vs.len(),
        skipped_suites.iter().cloned().collect::<Vec<_>>().join(", ")
    );
}

/// v2.1 agent-leaf share binding (GAP 2). Every `primitives.threshold_share[]` entry must verify over the
/// `signerSetHash‖t`-bound share message iff `valid`; in particular the PRE-v2.1 bare agent share and a
/// cross-signer-set replay MUST be rejected. All corpus share vectors are Ed25519, so no PQ suite is needed.
#[test]
fn threshold_shares() {
    let doc = load("vectors.json");
    let shares = doc["primitives"]["threshold_share"].as_array().expect("threshold_share");
    assert!(!shares.is_empty());
    let mut bad = Vec::new();
    let (mut accepted, mut rejected) = (0usize, 0usize);
    let (mut bare_rejected, mut wrong_set_rejected) = (false, false);
    for s in shares {
        let name = s.get("name").and_then(Value::as_str).unwrap_or_else(|| s["role"].as_str().unwrap());
        let want = s.get("valid").and_then(Value::as_bool).unwrap_or(true);
        let got = verify_threshold_share(s);
        if got != want {
            bad.push(format!("{name}: share verified = {got}, want valid = {want}"));
        }
        if want {
            accepted += 1;
        } else {
            rejected += 1;
        }
        bare_rejected |= name == "agent-bare-rejected" && !got;
        wrong_set_rejected |= name == "agent-bound-wrong-set" && !got;
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    assert!(bare_rejected, "v2.1 binding: the pre-v2.1 bare agent share MUST be rejected");
    assert!(wrong_set_rejected, "v2.1 binding: a cross-signer-set agent share replay MUST be rejected");
    eprintln!(
        "threshold shares: {accepted} valid accepted, {rejected} invalid rejected \
         (incl. v2.1 bare-agent-share + cross-signer-set replay)"
    );
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
