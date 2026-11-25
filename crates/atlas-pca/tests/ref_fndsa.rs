//! Differential replay of the FN-DSA suite registry, framing and hybrid composition (`@atlasauth/pca-fndsa`) against the
//! TypeScript reference (test-data/ref-fndsa.json.gz). The corpus runs through the reference's deterministic hash-derived MOCK
//! backend or an explicit stub ("kind"): the Falcon primitive is not in it, so there are no real FN-DSA known-answer vectors to
//! replay (neither verify nor, under `fndsa-sign`, sign / keygen); the native primitive is covered by the core's `fn-dsa-*` suite
//! tests and by the `native_backend_*` checks below. A reference throw only requires an Err. Arguments the Rust types cannot
//! hold (a null where bytes belong) become the reference's own outcome: false for verify, a refusal for sign.
//! Skipped (counted, must stay under 10%): cases with a lone surrogate.
mod common;
use atlas_pca::fndsa_pkg::*;
use atlas_pca::serde_json::{json, Value};

fn b64u(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn bytes(v: &Value) -> Option<Vec<u8>> {
    v.get("$bytes").and_then(Value::as_str).and_then(|s| atlas_pca::decode_b64u_strict(s, None))
}

fn byte_val(b: &[u8]) -> Value {
    json!({ "$bytes": b64u(b) })
}

// ---- the reference harness's stub backends ----
struct VerifyOnly(MockBackend);
impl FalconBackend for VerifyOnly {
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, String> {
        self.0.verify(pk, msg, sig)
    }
}
struct ShortSig(MockBackend);
impl FalconBackend for ShortSig {
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, String> {
        self.0.verify(pk, msg, sig)
    }
    fn sign(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, String> {
        Ok(vec![0; 10])
    }
}
struct AllTrue(MockBackend);
impl FalconBackend for AllTrue {
    fn verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> Result<bool, String> {
        Ok(true)
    }
    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
        self.0.sign(sk, msg)
    }
}
struct Throws(MockBackend);
impl FalconBackend for Throws {
    fn verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> Result<bool, String> {
        Err("backend exploded".into())
    }
    fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
        self.0.sign(sk, msg)
    }
}

fn backend(kind: &str) -> Box<dyn FalconBackend> {
    match kind {
        "mock" => Box::new(MockBackend::default()),
        "none" => Box::new(NoBackend),
        "verify-only" => Box::new(VerifyOnly(MockBackend::default())),
        "short-sig" => Box::new(ShortSig(MockBackend::default())),
        "all-true" => Box::new(AllTrue(MockBackend::default())),
        "throws" => Box::new(Throws(MockBackend::default())),
        k => panic!("unknown backend kind {k}"),
    }
}

fn kat_backend(vectors: &Value) -> Result<MockBackend, String> {
    let mut v = Vec::new();
    for e in vectors.as_array().ok_or("vectors")? {
        v.push((bytes(&e["pk"]).ok_or("pk")?, bytes(&e["msg"]).ok_or("msg")?, bytes(&e["sig"]).ok_or("sig")?));
    }
    Ok(MockBackend::new(&v))
}

fn verify_with(b: &dyn FalconBackend, a: &[Value]) -> Result<Value, String> {
    let variant = a[1].as_str().unwrap_or("");
    // a non-byte key, message or signature is `false` in the reference (it checks the types before the backend)
    let (Some(pk), Some(msg), Some(sig)) = (bytes(&a[2]), bytes(&a[3]), bytes(&a[4])) else { return Ok(Value::Bool(false)) };
    fndsa_verify(b, variant, &pk, &msg, &sig).map(Value::Bool)
}

fn run(name: &str, f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "resolveFnDsaAlg" => Ok(resolve_fndsa_alg(&a[0]).map_or(Value::Null, |s| s.to_json())),
        "isKnownFnDsaAlg" => Ok(Value::Bool(is_known_fndsa_alg(&a[0]))),
        "isFnDsaVariant" => Ok(Value::Bool(is_fndsa_variant(&a[0]))),
        "hashKat" => {
            let n = usize::try_from(a[1].as_i64().ok_or("length")?).map_err(|_| "negative length")?;
            Ok(byte_val(&hash_kat(&bytes(&a[0]).ok_or("seed")?, n)))
        }
        "mockKeypair" => {
            let variant = a[0].as_str().unwrap_or("");
            let seed = match a.get(1) {
                None => b"default".to_vec(),
                Some(Value::String(s)) => s.as_bytes().to_vec(),
                Some(v) => bytes(v).ok_or("seed")?,
            };
            let (pk, sk) = mock_keypair(variant, &seed)?;
            Ok(json!({ "pk": byte_val(&pk), "sk": byte_val(&sk) }))
        }
        "fndsaLeafMessage" => {
            let (alg, pk) = (a[1].as_str().ok_or("alg")?, a[2].as_str().ok_or("pk")?);
            fndsa_leaf_message(&a[0], alg, pk).map(|m| byte_val(&m))
        }
        "fndsaSignWith" => {
            let (sk, msg) = (bytes(&a[2]).ok_or("sk")?, bytes(&a[3]).ok_or("msg")?);
            fndsa_sign(&*backend(a[0].as_str().unwrap()), a[1].as_str().unwrap_or(""), &sk, &msg).map(|s| byte_val(&s))
        }
        "fndsaVerifyWith" => verify_with(&*backend(a[0].as_str().unwrap()), a),
        "fndsaVerifyKat" => {
            let b = kat_backend(&a[4])?;
            let shifted = [Value::Null, a[0].clone(), a[1].clone(), a[2].clone(), a[3].clone()];
            verify_with(&b, &shifted)
        }
        "fndsaSignKat" => {
            let variant = name.rsplit('/').next().unwrap();
            let (_, sk) = mock_keypair(variant, b"ref")?;
            fndsa_sign(&kat_backend(&a[0])?, variant, &sk, b"m").map(|s| byte_val(&s))
        }
        "signPcaWithFndsa" => {
            let i = &a[0];
            let (pk, sk, ed) = (bytes(&i["fnDsa"]["pk"]), bytes(&i["fnDsa"]["sk"]), bytes(&i["edSecret"]));
            let input = SignPcaInput { alg: &i["alg"], leaf: &i["leaf"], pk: pk.as_deref(), sk: sk.as_deref(), ed_secret: ed.as_deref() };
            sign_pca_with_fndsa(&MockBackend::default(), &input)
        }
        "verifyPcaFndsa" => verify_pca_fndsa(&MockBackend::default(), &a[0]).map(Value::Bool),
        "verifyPcaFndsaNone" => verify_pca_fndsa(&NoBackend, &a[0]).map(Value::Bool),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn fndsa_vectors() {
    let cases = common::ref_cases_seeded("fndsa");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let (name, f) = (c["name"].as_str().unwrap(), c["fn"].as_str().unwrap());
        let got = std::panic::catch_unwind(|| run(name, f, c["args"].as_array().unwrap())).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{name}\n  want {}\n  got  {:?}", c["out"], got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

/// The vetted native verifier through the same seam: right lengths reach it and it refuses what is not a real FN-DSA signature
/// (a mock-derived one included); wrong lengths and unknown key sizes never reach it.
#[test]
fn native_backend_refuses_non_falcon_signatures() {
    for variant in ["fn-dsa-512", "fn-dsa-1024"] {
        let (pk, sk) = mock_keypair(variant, b"native").unwrap();
        let msg = b"m";
        let mock_sig = fndsa_sign(&MockBackend::default(), variant, &sk, msg).unwrap();
        assert_eq!(fndsa_verify(&NativeBackend, variant, &pk, msg, &mock_sig), Ok(false), "{variant}: a mock signature verified natively");
        assert_eq!(fndsa_verify(&NativeBackend, variant, &pk, msg, &mock_sig[1..]), Ok(false));
        assert_eq!(fndsa_verify(&NativeBackend, variant, &pk[1..], msg, &mock_sig), Ok(false));
        assert!(fndsa_sign(&NativeBackend, variant, &sk, msg).is_err(), "the native backend is verify-only");
    }
    assert_eq!(NativeBackend.verify(&[0u8; 5], b"m", &[0u8; 5]), Ok(false));
}
