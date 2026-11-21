#![allow(dead_code)]
use serde_json::Value;

pub mod replay;

/// The raw V8 TypeErrors a hostile input provokes in the reference. A case that expects one of these passes when the native call
/// refuses (the message is not compared); never use it for any other message or for a Node error code.
pub fn engine_crash(msg: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"Cannot read propert(y|ies) of (null|undefined)|is not a function|is not iterable|Cannot convert undefined or null to object|Cannot destructure|Cannot use 'in' operator|Cannot create property|Reduce of empty array|is not an object|Cannot mix BigInt|Do not know how to serialize a BigInt|Converting circular structure|Invalid array length|Maximum call stack",
        )
        .unwrap()
    })
    .is_match(msg)
}

/// Structural equality with the lead's floating-point ruling: a non-integral double that differs from the reference only in its last
/// digits (the platform's libm: log, exp, pow) is equal within a relative 1e-12; integers, strings and booleans stay exact.
pub fn json_close(want: &Value, got: &Value) -> bool {
    match (want, got) {
        (Value::Number(a), Value::Number(b)) => {
            if a == b {
                return true;
            }
            let integral = |n: &serde_json::Number| n.is_i64() || n.is_u64();
            if integral(a) && integral(b) {
                return false;
            }
            match (a.as_f64(), b.as_f64()) {
                (Some(x), Some(y)) => (x - y).abs() <= 1e-12 * x.abs().max(y.abs()).max(1e-300),
                _ => false,
            }
        }
        (Value::Array(a), Value::Array(b)) => a.len() == b.len() && a.iter().zip(b).all(|(x, y)| json_close(x, y)),
        (Value::Object(a), Value::Object(b)) => a.len() == b.len() && a.iter().all(|(k, x)| b.get(k).is_some_and(|y| json_close(x, y))),
        (x, y) => x == y,
    }
}

/// Does a case argument carry a `{"$num": "NaN" | "Infinity" | "-Infinity"}` marker? A Rust `Value` cannot hold a non-finite number, so a
/// case that expects the reference's "non-finite number" refusal is refused by construction (the typed API has no way to receive it).
pub fn has_nonfinite(v: &Value) -> bool {
    match v {
        Value::Object(m) => {
            m.len() == 1 && matches!(m.get("$num").and_then(Value::as_str), Some("NaN" | "Infinity" | "-Infinity")) || m.values().any(has_nonfinite)
        }
        Value::Array(a) => a.iter().any(has_nonfinite),
        _ => false,
    }
}

/// A case whose arguments carry the lone-surrogate stand-in and whose reference answer is the canonicalizer's "lone surrogate" refusal:
/// a Rust string cannot hold the surrogate, so the refusal holds by construction (the typed API can never be handed one).
pub fn lone_refusal(c: &Value) -> bool {
    has_lone(&c["args"]) && c["out"].get("$throws").and_then(Value::as_str).is_some_and(|m| m.contains("lone surrogate"))
}

/// The expected message of a `{"$throws": ..}` value.
pub fn expected_throw(want: &Value) -> Option<&str> {
    want.get("$throws").and_then(Value::as_str)
}

/// Is this answer a refusal: a throw, an `$err`, or a decision that says no.
pub fn refused(got: &Value) -> bool {
    got.get("$throws").is_some()
        || got.get("$err").is_some_and(|e| e != &Value::Bool(false))
        || [("ok", false), ("allow", false), ("allowed", false), ("valid", false), ("verified", false)].iter().any(|(k, b)| got.get(*k) == Some(&Value::Bool(*b)))
}

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

/// The signature suites this Rust verifier implements: its capability manifest ([`atlas_pca::supported_suites`]; every
/// registered suite but the LESS pair, packages/pca/conformance/SUITES.md). A vector needing a suite outside it must be
/// refused with the distinct reason `unsupported_suite`.
pub static SUPPORTED_SUITES: std::sync::LazyLock<Vec<&'static str>> = std::sync::LazyLock::new(atlas_pca::supported_suites);

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


/// The conformance harness mediator every allow-expecting authorize test presents provenance from (as the TypeScript harness
/// does): Ed25519 seed = 32 bytes of 0x01, mediator `conformance-harness`, kid `k1`.
pub fn harness_recorder() -> atlas_pca::arg_provenance::ProvenanceRecorder {
    atlas_pca::arg_provenance::ProvenanceRecorder::new("conformance-harness", "k1", Some([1u8; 32])).expect("harness recorder")
}

/// The harness mediator pin, configured as the verifier's provenance mediators.
pub fn harness_pins() -> Vec<Value> {
    vec![harness_recorder().pin()]
}

/// The principal-direct bundle of `op` under the harness mediator (the bundle hook of allow-expecting tests).
pub fn principal_direct(op: &atlas_pca::Operation) -> Result<Option<Value>, String> {
    atlas_pca::arg_provenance::principal_direct_provenance(&mut harness_recorder(), op).map(Some)
}

/// base deadline (BRIEF "Timeouts are not kills"): `f` must answer within 2 s on its own thread, so a mutant that stops a
/// loop advancing FAILS here instead of timing out the mutation run. Same contract as the crate's k042_support::within.
pub fn within<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(std::time::Duration::from_secs(2)) {
        Ok(v) => v,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("{what}: no answer within 2 s (a loop that stopped advancing)"),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => panic!("{what}: panicked"),
    }
}

/// Replaces, in place, every seed object (keys within {$seed, es256, ec, ed448}) by its derived base64url key:
/// plain: SHA-256("atlas-pca-conformance/" + label), byte0 &= 0x7F when es256; ec P-384/P-521: first 48/66 bytes of
/// SHA256(P+L)||SHA256(P+L+"/2")||SHA256(P+L+"/3") with byte0 &= 0x7F / 0x01; ed448: SHA256(P+L) || SHA256(P+L+"/2")[..25].
/// Other `$seed` shapes are left alone.
pub fn resolve_seeds(v: &mut Value) {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    match v {
        Value::Object(m) => {
            // {"$utf16": [code units]}: a string holding a lone surrogate; Rust strings cannot hold one, so it becomes the lane's sentinel scalar
            if m.len() == 1 {
                if let Some(Value::Array(u)) = m.get("$utf16") {
                    let units: Vec<u16> = u.iter().filter_map(|x| x.as_u64().map(|n| n as u16)).collect();
                    let s: String = char::decode_utf16(units).map(|r| r.unwrap_or('\u{10FFFF}')).collect();
                    *v = Value::String(s);
                    return;
                }
            }
            if let Some(label) = m.get("$seed").and_then(Value::as_str) {
                if m.keys().all(|k| ["$seed", "es256", "ec", "ed448"].contains(&k.as_str())) {
                    let h = |sfx: &str| Sha256::digest(format!("atlas-pca-conformance/{label}{sfx}").as_bytes()).to_vec();
                    let mut raw = h("");
                    if m.get("es256") == Some(&Value::Bool(true)) {
                        raw[0] &= 0x7F;
                    }
                    match m.get("ec").and_then(Value::as_str) {
                        Some(c @ ("P-384" | "P-521")) => {
                            raw = [h(""), h("/2"), h("/3")].concat();
                            if c == "P-384" {
                                raw.truncate(48);
                                raw[0] &= 0x7F;
                            } else {
                                raw.truncate(66);
                                raw[0] &= 0x01;
                            }
                        }
                        _ => {}
                    }
                    if m.get("ed448") == Some(&Value::Bool(true)) {
                        raw = [h(""), h("/2")[..25].to_vec()].concat();
                    }
                    *v = Value::String(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw));
                    return;
                }
            }
            m.values_mut().for_each(resolve_seeds);
        }
        Value::Array(a) => a.iter_mut().for_each(resolve_seeds),
        _ => {}
    }
}

/// [`ref_cases`] with the corpus seed objects resolved (for corpora that carry no key material).
pub fn ref_cases_seeded(pkg: &str) -> Vec<Value> {
    let mut cases = ref_cases(pkg);
    cases.iter_mut().for_each(resolve_seeds);
    cases
}

/// The cases of ref-<pkg>-gen.json.gz: the oracle cases that carry private keys, which CI generates with gen-secret-corpus.sh and
/// never commits (next to test-data/ unless PCA_SECRET_CORPUS_DIR is set). Missing: panics when CI is "true"/"1", else empty (skipped).
pub fn ref_gen_cases(pkg: &str, seeded: bool) -> Vec<Value> {
    let dir = std::env::var("PCA_SECRET_CORPUS_DIR").unwrap_or_else(|_| format!("{}/test-data", env!("CARGO_MANIFEST_DIR")));
    let path = format!("{dir}/ref-{pkg}-gen.json.gz");
    if !std::path::Path::new(&path).exists() {
        if matches!(std::env::var("CI").as_deref(), Ok("true") | Ok("1")) {
            panic!("secret corpus missing ({path}): CI must generate it with gen-secret-corpus.sh");
        }
        eprintln!("skipping: secret corpus missing ({path}); run gen-secret-corpus.sh");
        return Vec::new();
    }
    let mut cases = ref_cases_at(&path);
    if seeded {
        cases.iter_mut().for_each(resolve_seeds);
    }
    cases
}

/// The cases of test-data/ref-<pkg>.json.gz.
/// (0.6 differential corpora, written by the TypeScript reference; a missing file fails, never skips.)
pub fn ref_cases(pkg: &str) -> Vec<Value> {
    ref_cases_at(&format!("{}/test-data/ref-{pkg}.json.gz", env!("CARGO_MANIFEST_DIR")))
}

/// The whole document of the corpus file at `path`.
fn ref_doc_at(path: &str) -> Value {
    let path = path.to_string();
    let o = std::process::Command::new("gzip").arg("-dc").arg(&path).output().expect("gzip");
    assert!(o.status.success(), "{path}: gzip failed (missing corpus?)");
    serde_json::from_str(&sanitize_lone_surrogates(&String::from_utf8(o.stdout).expect("utf8"))).expect("parse")
}

/// The cases of the corpus file at `path` (same format as [`ref_cases`]).
pub fn ref_cases_at(path: &str) -> Vec<Value> {
    let doc = ref_doc_at(path);
    let cases = doc["cases"].as_array().expect("cases").clone();
    assert_eq!(cases.len() as u64, doc["count"].as_u64().expect("count"), "{path}: case count");
    cases
}

/// The generator clock (epoch ms) of corpora committed before the header carried `clockMs`.
pub const FALLBACK_CLOCK_MS: f64 = 1_800_000_000_000.0;

/// The frozen clock a corpus header records as `clockMs`, else [`FALLBACK_CLOCK_MS`].
pub fn clock_of_header(doc: &Value) -> f64 {
    doc.get("clockMs").and_then(Value::as_f64).filter(|f| f.is_finite()).unwrap_or(FALLBACK_CLOCK_MS)
}

/// The one clock accessor of the replays: the frozen clock of test-data/ref-<pkg>.json.gz.
pub fn ref_clock_ms(pkg: &str) -> f64 {
    clock_of_header(&ref_doc_at(&format!("{}/test-data/ref-{pkg}.json.gz", env!("CARGO_MANIFEST_DIR"))))
}

