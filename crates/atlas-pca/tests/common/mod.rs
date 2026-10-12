#![allow(dead_code)]
use serde_json::Value;

pub const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/");

/// A Rust `String` cannot hold a lone surrogate, but `vectors.json` carries one in an OBJECT-form vector
/// (`"aud": "rs-\ud800"`), which `serde_json` refuses to load. Replace every lone surrogate escape inside a
/// JSON string with this sentinel; the harness then reports `wire` failure for any vector containing it
/// (exactly what a UTF-16 language reaches via the strict canonical encoder).
pub const LONE: char = '\u{10FFFF}';

pub fn sanitize_lone_surrogates(text: &str) -> String {
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
                            && hex(i + 8).is_some_and(|lo| (0xDC00..=0xDFFF).contains(&lo));
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

pub fn load(name: &str) -> Value {
    let b = if name.ends_with(".gz") {
        let o = std::process::Command::new("gzip").arg("-dc").arg(format!("{DIR}{name}")).output().expect("gzip");
        assert!(o.status.success());
        String::from_utf8(o.stdout).expect("utf8")
    } else {
        std::fs::read_to_string(format!("{DIR}{name}")).expect("read file")
    };
    serde_json::from_str(&sanitize_lone_surrogates(&b)).expect("parse json")
}

pub fn has_lone(v: &Value) -> bool {
    match v {
        Value::String(s) => s.contains(LONE),
        Value::Array(a) => a.iter().any(has_lone),
        Value::Object(m) => m.iter().any(|(k, x)| k.contains(LONE) || has_lone(x)),
        _ => false,
    }
}

pub fn b64d(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()
}

/// The signature suites this Rust verifier implements — for the LEAF signature (`requires:"pq"`), for
/// non-leaf capability-chain hops (`requires:"pq-nonleaf"`), and for the threshold-share binding. The three
/// CROSS-IMPL suites every conformant impl is required to agree on (GAP 1): classical Ed25519, the pure
/// lattice ML-DSA-65 (FIPS-204, via the `fips204` crate), and the hybrid Ed25519 + ML-DSA-65. The remaining
/// registered suites (ml-dsa-87, slh-dsa-sha2-128f/256s, their hybrids, and the SUF-CMA nested hybrid) are
/// NOT yet wired in Rust, so vectors that need a real signature verdict under them are skipped explicitly.
pub const SUPPORTED_SUITES: &[&str] = &["ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65"];

/// Which concrete signature suite a vector exercises that this verifier does NOT implement, if any:
/// the leaf `alg` for `requires:"pq"`, or any capability-hop `alg` for `requires:"pq-nonleaf"`.
/// `None` for core vectors and for vectors that stay entirely within [`SUPPORTED_SUITES`].
pub fn unsupported_suite(v: &Value) -> Option<String> {
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
        // 0.4.1: a vector may name the one suite it needs directly (e.g. a threshold share under `ml-dsa-87`).
        Some(r) => (!SUPPORTED_SUITES.contains(&r)).then(|| r.to_string()),
        None => None,
    }
}

