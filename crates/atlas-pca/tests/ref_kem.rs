//! Differential replay of the hybrid KEM against the TypeScript reference (test-data/ref-kem.json.gz, 464 cases): X25519 + ML-KEM-768
//! and -1024, X-Wing (the corpus carries the three draft-09 test vectors), the FIPS 203 key checks and the text forms. Every key and
//! every random stream of the corpus is a seed label, so the randomised entry points replay through their derandomised forms. A
//! case the reference refuses must be refused here. The 24 cases that pass `null` where this API takes bytes, text or a level are
//! replayed through the harness, which gives `null` the reference's answer for it (a refusal; `false` for a key check of a key
//! that is not bytes). An unknown function fails the test.
mod common;
use atlas_pca::kem::*;
use atlas_pca::serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn b64(b: &[u8]) -> Value {
    json!({"$bytes": encode_hybrid_public_key(b)})
}

fn level(v: &Value) -> u32 {
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())).unwrap_or(0) as u32
}

fn patch(mut b: Vec<u8>, spec: &Value) -> Vec<u8> {
    if let Some(t) = spec["trim"].as_u64() {
        b.truncate(b.len().saturating_sub(t as usize));
    }
    if let Some(p) = spec["pad"].as_u64() {
        b.extend(std::iter::repeat(0u8).take(p as usize));
    }
    for s in spec["set"].as_array().into_iter().flatten() {
        b[s[0].as_u64().expect("offset") as usize] = s[1].as_u64().expect("byte") as u8;
    }
    b
}

/// The bytes a corpus argument names: literal bytes, a stream of parts, a hybrid secret key or an expanded ML-KEM key built here.
fn bytes(v: &Value) -> Vec<u8> {
    if let Some(parts) = v.as_array() {
        return parts.iter().flat_map(bytes).collect();
    }
    if let Some(s) = v.get("$bytes") {
        return decode_hybrid_public_key(s.as_str().expect("$bytes text")).expect("corpus bytes");
    }
    if let Some(h) = v.get("$hybridSk") {
        let dk = ml_kem_expanded_dk(level(&h["level"]), &bytes(&h["d"]), &bytes(&h["z"])).expect("expanded dk");
        return patch([bytes(&h["x"]), dk.to_vec()].concat(), h);
    }
    if let Some(m) = v.get("$mlkemDk") {
        let k = if level(&m["level"]) == 768 { 3 } else { 4 };
        let mut dk = patch(ml_kem_expanded_dk(level(&m["level"]), &bytes(&m["d"]), &bytes(&m["z"])).expect("expanded dk").to_vec(), m);
        if m["rehash"] == json!(true) {
            let h = <sha3::Sha3_256 as sha3::Digest>::digest(&dk[384 * k..768 * k + 32]);
            dk[768 * k + 32..768 * k + 64].copy_from_slice(&h);
        }
        return dk;
    }
    panic!("unknown argument form {v}");
}

fn key_bytes(v: &Value) -> Vec<u8> {
    if v.is_object() {
        bytes(v)
    } else {
        Vec::new()
    }
}

fn pair(r: Result<KemKeyPair, String>) -> Result<Value, String> {
    r.map(|k| json!({"publicKey": b64(&k.public_key), "secretKeySha256": hex(&Sha256::digest(&k.secret_key[..])), "secretKeyLen": k.secret_key.len()}))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn enc(r: Result<Encapsulation, String>) -> Result<Value, String> {
    r.map(|e| json!({"ciphertext": b64(&e.ciphertext), "sharedSecret": b64(&e.shared_secret)}))
}

fn secret(r: Result<[u8; 32], String>) -> Result<Value, String> {
    r.map(|s| b64(&s))
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    // `null` where this API takes bytes, text or a level: the reference refuses it, except that a key check at a valid level
    // answers false for a key that is not bytes (the empty slice stands in for it, see `key_bytes`)
    let key_check = f.ends_with("KeyCheck");
    if a.iter().enumerate().any(|(i, v)| v.is_null() && !(key_check && i == 1)) {
        return Err("null argument".into());
    }
    let text = |i: usize| a[i].as_str().ok_or_else(|| "not a string".to_string());
    match f {
        "constants" => Ok(json!({
            "HYBRID_PUBLIC_KEY_LEN": HYBRID_PUBLIC_KEY_LEN, "HYBRID_CIPHERTEXT_LEN": HYBRID_CIPHERTEXT_LEN, "HYBRID_SHARED_SECRET_LEN": HYBRID_SHARED_SECRET_LEN,
            "HYBRID_KEM_SUITE": HYBRID_KEM_SUITE, "XWING_SUITE": XWING_SUITE, "XWING_SEED_LEN": XWING_SEED_LEN, "XWING_SECRET_KEY_LEN": XWING_SECRET_KEY_LEN,
            "XWING_PUBLIC_KEY_LEN": XWING_PUBLIC_KEY_LEN, "XWING_CIPHERTEXT_LEN": XWING_CIPHERTEXT_LEN, "XWING_SHARED_SECRET_LEN": XWING_SHARED_SECRET_LEN,
            "XWING_ESEED_LEN": XWING_ESEED_LEN, "XWING_LABEL": b64(&XWING_LABEL), "HYBRID1024_PUBLIC_KEY_LEN": HYBRID1024_PUBLIC_KEY_LEN,
            "HYBRID1024_CIPHERTEXT_LEN": HYBRID1024_CIPHERTEXT_LEN, "HYBRID1024_SHARED_SECRET_LEN": HYBRID1024_SHARED_SECRET_LEN, "HYBRID1024_KEM_SUITE": HYBRID1024_KEM_SUITE,
        })),
        "hybridKemKeygen" => pair(hybrid_kem_keygen_derand(&bytes(&a[0]))),
        "hybridKem1024Keygen" => pair(hybrid_kem_1024_keygen_derand(&bytes(&a[0]))),
        "hybridEncapsulate" => enc(hybrid_encapsulate_derand(&bytes(&a[0]), &bytes(&a[1]))),
        "hybridEncapsulate1024" => enc(hybrid_encapsulate_1024_derand(&bytes(&a[0]), &bytes(&a[1]))),
        "hybridDecapsulate" => secret(hybrid_decapsulate(&bytes(&a[0]), &bytes(&a[1]))),
        "hybridDecapsulate1024" => secret(hybrid_decapsulate_1024(&bytes(&a[0]), &bytes(&a[1]))),
        "xwingKeygen" => pair(xwing_keygen(Some(&bytes(&a[0])))),
        "xwingEncapsulateDerand" | "xwingEncapsulate" => enc(xwing_encapsulate_derand(&bytes(&a[0]), &bytes(&a[1]))),
        "xwingDecapsulate" => secret(xwing_decapsulate(&bytes(&a[0]), &bytes(&a[1]))),
        "encodeHybridPublicKey" => Ok(json!(encode_hybrid_public_key(&bytes(&a[0])))),
        "encodeHybridCiphertext" => Ok(json!(encode_hybrid_ciphertext(&bytes(&a[0])))),
        "encodeXWingPublicKey" => Ok(json!(encode_xwing_public_key(&bytes(&a[0])))),
        "encodeXWingCiphertext" => Ok(json!(encode_xwing_ciphertext(&bytes(&a[0])))),
        "decodeHybridPublicKey" => decode_hybrid_public_key(text(0)?).map(|b| b64(&b)),
        "decodeHybridCiphertext" => decode_hybrid_ciphertext(text(0)?).map(|b| b64(&b)),
        "decodeXWingPublicKey" => decode_xwing_public_key(text(0)?).map(|b| b64(&b)),
        "decodeXWingCiphertext" => decode_xwing_ciphertext(text(0)?).map(|b| b64(&b)),
        // a key that is not bytes at all (a string in the corpus) is no key: the empty slice stands in for it
        "mlKemEncapsulationKeyCheck" => ml_kem_encapsulation_key_check(level(&a[0]), &key_bytes(&a[1])).map(Value::Bool),
        "mlKemDecapsulationKeyCheck" => ml_kem_decapsulation_key_check(level(&a[0]), &key_bytes(&a[1])).map(Value::Bool),
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn the_hybrid_kem_matches_the_reference() {
    let cases = common::ref_cases_seeded("kem");
    assert_eq!(cases.len(), 464, "case total");
    let (mut ran, mut with_null, mut bad) = (0usize, 0usize, Vec::new());
    for c in &cases {
        let args = c["args"].as_array().cloned().unwrap_or_default();
        if args.iter().any(Value::is_null) {
            with_null += 1;
        }
        ran += 1;
        let got = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(c["fn"].as_str().unwrap_or(""), &args))).unwrap_or_else(|_| Err("panic".into()));
        let same = match (&got, c["out"].get("$throws")) {
            (Err(_), Some(_)) => true,
            (Ok(v), None) => atlas_pca::canonicalize(v) == atlas_pca::canonicalize(&c["out"]),
            _ => false,
        };
        if !same {
            bad.push(format!("{}: got {:?}", c["name"], got.map(|v| v.to_string().chars().take(160).collect::<String>())));
        }
    }
    assert_eq!((ran, with_null), (464, 24), "cases replayed / of them with a null argument");
    assert!(bad.is_empty(), "{} cases differ:\n{}", bad.len(), bad.join("\n"));
}

#[test]
fn the_randomised_calls_round_trip_and_differ() {
    let (a, b) = (hybrid_kem_keygen().unwrap(), hybrid_kem_keygen().unwrap());
    assert_ne!(a.public_key, b.public_key);
    assert_eq!((a.public_key.len(), a.secret_key.len()), (HYBRID_PUBLIC_KEY_LEN, 2432));
    let (e1, e2) = (hybrid_encapsulate(&a.public_key).unwrap(), hybrid_encapsulate(&a.public_key).unwrap());
    assert_ne!(e1.ciphertext, e2.ciphertext);
    assert_eq!(hybrid_decapsulate(&e1.ciphertext, &a.secret_key).unwrap(), e1.shared_secret);
    assert_ne!(hybrid_decapsulate(&e1.ciphertext, &b.secret_key).unwrap(), e1.shared_secret, "another key does not agree");

    let k = hybrid_kem_1024_keygen().unwrap();
    assert_eq!((k.public_key.len(), k.secret_key.len()), (HYBRID1024_PUBLIC_KEY_LEN, 3200));
    let e = hybrid_encapsulate_1024(&k.public_key).unwrap();
    assert_eq!(hybrid_decapsulate_1024(&e.ciphertext, &k.secret_key).unwrap(), e.shared_secret);
    assert!(hybrid_encapsulate(&k.public_key).is_err(), "a 1024 key is refused by the 768 suite");

    let (x, y) = (xwing_keygen(None).unwrap(), xwing_keygen(None).unwrap());
    assert_ne!(x.public_key, y.public_key);
    assert_eq!((x.public_key.len(), x.secret_key.len()), (XWING_PUBLIC_KEY_LEN, XWING_SECRET_KEY_LEN));
    let e = xwing_encapsulate(&x.public_key).unwrap();
    assert_eq!(xwing_decapsulate(&e.ciphertext, &x.secret_key).unwrap(), e.shared_secret);
    assert_ne!(xwing_encapsulate(&x.public_key).unwrap().ciphertext, e.ciphertext);
}
