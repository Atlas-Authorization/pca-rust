//! Differential replay of DPoP / mTLS sender-constraint binding against the TypeScript reference (test-data/ref-dpop.json.gz).
//! A refusal with a code must carry that code (and, outside the `signature` / `malformed` / `cert` codes whose texts embed a JOSE
//! or X.509 library message, the same message); a refusal without one only requires a refusal.
mod common;
use atlas_pca::dpop::*;
use atlas_pca::serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Mutex;

const NOW: f64 = 1_800_000_000.0;

fn same(want: &Value, got: Result<Value, DpopError>) -> bool {
    match (want.get("$throws"), got) {
        (Some(msg), Err(e)) => match want.get("code").and_then(Value::as_str) {
            None => true,
            Some(code) => code == e.code && (["signature", "malformed", "cert"].contains(&code) || msg.as_str() == Some(e.message.as_str())),
        },
        (None, Ok(v)) => atlas_pca::canonicalize(want) == atlas_pca::canonicalize(&v),
        _ => false,
    }
}

fn b64(s: &Value) -> Vec<u8> {
    common::b64d(s.as_str().unwrap())
}

fn issuer(n: &Value) -> Result<DpopNonceIssuer, DpopError> {
    DpopNonceIssuer::new(&b64(&n["secret"]), n.get("ttlSec").and_then(Value::as_f64))
}

fn s(v: &Value) -> Option<&str> {
    v.as_str()
}

/// An insertion-ordered seen set (a JavaScript `Set` lists its members in insertion order).
struct OrderedSeen(Mutex<Vec<String>>);

impl JtiSeenSet for OrderedSeen {
    fn has(&self, jti: &str) -> bool {
        self.0.lock().map(|v| v.iter().any(|x| x == jti)).unwrap_or(true)
    }
    fn add(&self, jti: &str) {
        if let Ok(mut v) = self.0.lock() {
            if !v.iter().any(|x| x == jti) {
                v.push(jti.to_string());
            }
        }
    }
}

/// The replay-store stand-ins of the corpus: always true, always false, always throwing.
struct Fixed(Option<bool>);

impl DpopReplayStore for Fixed {
    fn add_if_absent(&self, _: &str, _: f64, _: f64) -> Result<bool, String> {
        self.0.ok_or_else(|| "boom".to_string())
    }
}

/// The 32-byte-or-more secret and ttl of a nonce issuer given as `{secret, ttl | ttlSec}`.
fn issuer_of(n: &Value) -> Result<DpopNonceIssuer, DpopError> {
    DpopNonceIssuer::new(&b64(&n["secret"]), n.get("ttl").or_else(|| n.get("ttlSec")).and_then(Value::as_f64))
}

fn verify(proof: &Value, w: &Value) -> Result<Value, DpopError> {
    let memory = InMemoryDpopReplayStore::new(None).unwrap();
    let seen = OrderedSeen(Mutex::new(Vec::new()));
    let mut preloaded_seen = false;
    let ni = match w.get("nonceIssuer").or_else(|| w.get("nonce")) {
        Some(n) => Some(issuer_of(n)?),
        None => None,
    };
    let mut o = VerifyDpopOptions {
        method: w["method"].as_str().unwrap().into(),
        url: w["url"].as_str().unwrap().into(),
        max_age_sec: w["maxAgeSec"].as_f64().unwrap(),
        now_sec: w.get("nowSec").and_then(Value::as_f64),
        expected_jkt: w.get("expectedJkt").and_then(s).map(String::from),
        expected_nonce: w.get("expectedNonce").and_then(s).map(String::from),
        access_token: w.get("accessToken").and_then(s).map(String::from),
        require_replay_store: w.get("requireReplayStore").and_then(Value::as_bool),
        nonce_issuer: ni.as_ref(),
        ..Default::default()
    };
    let fixed_true = Fixed(Some(true));
    let fixed_false = Fixed(Some(false));
    let fixed_throws = Fixed(None);
    let sized;
    if let Some(ids) = w.get("seenJti").and_then(Value::as_array) {
        for k in ids.iter().filter_map(Value::as_str) {
            seen.add(k);
        }
        preloaded_seen = true;
        o.seen_jti = Some(&seen);
    }
    if let Some(rs) = w.get("replayStore") {
        let store: &dyn DpopReplayStore = match rs["kind"].as_str() {
            Some("true") => &fixed_true,
            Some("false") => &fixed_false,
            Some("throws") => &fixed_throws,
            _ => match rs.get("maxEntries").and_then(Value::as_u64) {
                Some(m) => {
                    sized = InMemoryDpopReplayStore::new(Some(m as usize))?;
                    &sized
                }
                None => &memory,
            },
        };
        if rs["kind"].as_str() == Some("memory") {
            for k in rs.get("preload").and_then(Value::as_array).into_iter().flatten() {
                store.add_if_absent(k[0].as_str().unwrap(), k[1].as_f64().unwrap(), k[2].as_f64().unwrap()).unwrap();
            }
        }
        o.replay_store = Some(store);
    }
    // the previous corpus shape: `replay` names the kind and `preSeen` the keys
    match w.get("replay").and_then(Value::as_str) {
        Some("store") => {
            for k in w.get("preSeen").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                memory.add_if_absent(k, NOW + 10_000.0, NOW).unwrap();
            }
            o.replay_store = Some(&memory);
        }
        Some("seen") => {
            for k in w.get("preSeen").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                seen.add(k);
            }
            preloaded_seen = true;
            o.seen_jti = Some(&seen);
        }
        _ => {}
    }
    let r = verify_dpop_proof(proof, &o)?;
    let mut out = json!({ "claims": r.claims, "jwk": r.jwk, "jkt": r.jkt });
    if preloaded_seen {
        out["seen"] = json!(seen.0.lock().unwrap().clone());
    }
    Ok(out)
}

fn ctx_err(m: impl Into<String>) -> DpopError {
    DpopError { code: "", message: m.into() }
}

/// A DPoP proof for any supported key: the header carries `publicJwk`, the signature is made with `privateKey` (a mismatch of the
/// two is the reference's "Invalid key for this operation").
fn create_proof(x: &Value) -> Result<String, DpopError> {
    use base64::Engine;
    let b64_encode = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let public = &x["publicJwk"];
    let alg = dpop_alg_for_jwk(public)?;
    let mut claims = atlas_pca::serde_json::Map::new();
    claims.insert("htm".into(), json!(x["method"].as_str().unwrap().to_uppercase()));
    claims.insert("htu".into(), json!(normalize_htu(x["url"].as_str().unwrap()).map_err(ctx_err)?));
    claims.insert("iat".into(), x["iat"].clone());
    claims.insert("jti".into(), x["jti"].clone());
    for k in ["nonce", "ath"] {
        if let Some(v) = x.get(k) {
            claims.insert(k.into(), v.clone());
        }
    }
    let header = json!({ "typ": DPOP_JWT_TYP, "alg": alg, "jwk": public });
    let input = format!(
        "{}.{}",
        b64_encode(atlas_pca::js_stringify(&header).as_bytes()),
        b64_encode(atlas_pca::js_stringify(&Value::Object(claims)).as_bytes())
    );
    let key = &x["privateKey"];
    let d = key.get("d").and_then(Value::as_str).map(common::b64d);
    let mismatch = || ctx_err("Invalid key for this operation, its asymmetricKeyType must match the key");
    let sig: Vec<u8> = match (alg, key.get("kty").and_then(Value::as_str), key.get("crv").and_then(Value::as_str), d) {
        ("EdDSA", Some("OKP"), Some("Ed25519"), Some(d)) if public["crv"] == "Ed25519" => {
            use ed25519_dalek::Signer;
            let seed: [u8; 32] = d.try_into().map_err(|_| mismatch())?;
            ed25519_dalek::SigningKey::from_bytes(&seed).sign(input.as_bytes()).to_bytes().to_vec()
        }
        ("ES256", Some("EC"), Some("P-256"), Some(d)) => {
            use p256::ecdsa::signature::Signer;
            let k = p256::ecdsa::SigningKey::from_slice(&d).map_err(|_| mismatch())?;
            let sg: p256::ecdsa::Signature = k.sign(input.as_bytes());
            sg.to_bytes().to_vec()
        }
        ("ES384", Some("EC"), Some("P-384"), Some(d)) => {
            use p384::ecdsa::signature::Signer;
            let k = p384::ecdsa::SigningKey::from_slice(&d).map_err(|_| mismatch())?;
            let sg: p384::ecdsa::Signature = k.sign(input.as_bytes());
            sg.to_bytes().to_vec()
        }
        ("ES512", Some("EC"), Some("P-521"), Some(d)) => {
            use p521::ecdsa::signature::Signer;
            let k = p521::ecdsa::SigningKey::from_slice(&d).map_err(|_| mismatch())?;
            let sg: p521::ecdsa::Signature = k.sign(input.as_bytes());
            sg.to_bytes().to_vec()
        }
        ("PS256", Some("RSA"), _, _) => {
            use rsa::signature::{RandomizedSigner, SignatureEncoding};
            let m = |k: &str| key.get(k).and_then(Value::as_str).map(|t| rsa::BigUint::from_bytes_be(&common::b64d(t)));
            let (Some(n), Some(e), Some(d), Some(p), Some(q)) = (m("n"), m("e"), m("d"), m("p"), m("q")) else { return Err(mismatch()) };
            let sk = rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q]).map_err(|_| mismatch())?;
            let signing = rsa::pss::SigningKey::<sha2::Sha256>::new(sk);
            signing.sign_with_rng(&mut CounterRng(0), input.as_bytes()).to_bytes().to_vec()
        }
        _ => return Err(mismatch()),
    };
    Ok(format!("{input}.{}", b64_encode(&sig)))
}

/// A deterministic byte source for the PSS salt (a salt only has to be unpredictable to an attacker; the replay checks the
/// verification outcome, never the signature bytes).
struct CounterRng(u64);

impl rsa::rand_core::RngCore for CounterRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        use sha2::Digest;
        self.0 += 1;
        u64::from_be_bytes(sha2::Sha256::digest(self.0.to_be_bytes())[..8].try_into().unwrap())
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.chunks_mut(8).for_each(|c| c.copy_from_slice(&self.next_u64().to_be_bytes()[..c.len()]));
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rsa::rand_core::CryptoRng for CounterRng {}

fn create_then_verify(x: &Value, vo: &Value) -> Result<Value, DpopError> {
    let proof = create_proof(x)?;
    let mut w = json!({ "method": x["method"], "url": x["url"], "maxAgeSec": 300, "nowSec": x["iat"].as_f64().unwrap_or(0.0) + 1.0, "seenJti": [] });
    for (k, v) in vo.as_object().into_iter().flatten() {
        w[k] = v.clone();
    }
    verify(&Value::String(proof), &w)
}

fn replay_store_script(max: &Value, ops: &Value) -> Result<Value, DpopError> {
    let store = match max {
        Value::Null => InMemoryDpopReplayStore::new(None),
        // the reference passes any value through: a non-positive-integer size is refused
        v => match v.as_f64() {
            Some(m) if m >= 1.0 && m.fract() == 0.0 => InMemoryDpopReplayStore::new(Some(m as usize)),
            _ => return Err(ctx_err("maxEntries must be a positive integer")),
        },
    }?;
    Ok(Value::Array(
        ops.as_array()
            .unwrap()
            .iter()
            .map(|o| match store.add_if_absent(o["key"].as_str().unwrap(), o["exp"].as_f64().unwrap(), o["now"].as_f64().unwrap()) {
                Ok(b) => json!(b),
                Err(_) => json!("throws"),
            })
            .collect(),
    ))
}

fn nonce_script(secret: &Value, ttl: &Value, ops: &Value) -> Result<Value, DpopError> {
    let issuer = DpopNonceIssuer::new(&b64(secret), ttl.as_f64())?;
    let (mut issued, mut out) = (Vec::<String>::new(), Vec::<Value>::new());
    for op in ops.as_array().unwrap() {
        let now = op.get("now").and_then(Value::as_f64).unwrap_or(0.0);
        match op["op"].as_str() {
            Some("issue") => {
                let n = issuer.issue(now as u64);
                issued.push(n.clone());
                out.push(json!(n));
            }
            _ => {
                let nonce = match op["nonce"].get("$issued").and_then(Value::as_u64) {
                    Some(i) => json!(issued[i as usize]),
                    None => op["nonce"].clone(),
                };
                out.push(json!(issuer.check(&nonce, now)));
            }
        }
    }
    Ok(Value::Array(out))
}

fn conformance(kind: &str) -> Value {
    let failed = match kind {
        "memory" => run_dpop_replay_store_conformance(|| InMemoryDpopReplayStore::new(None).unwrap()),
        "alwaysTrue" => run_dpop_replay_store_conformance(|| Fixed(Some(true))),
        "alwaysFalse" => run_dpop_replay_store_conformance(|| Fixed(Some(false))),
        // a store that remembers keys but never lets an entry expire
        _ => {
            struct NoExpiry(Mutex<HashSet<String>>);
            impl DpopReplayStore for NoExpiry {
                fn add_if_absent(&self, k: &str, _: f64, _: f64) -> Result<bool, String> {
                    Ok(self.0.lock().unwrap().insert(k.to_string()))
                }
            }
            run_dpop_replay_store_conformance(|| NoExpiry(Mutex::new(HashSet::new())))
        }
    };
    json!(failed)
}

fn pem(v: &Value) -> CertInput<'_> {
    CertInput::Pem(v.as_str().unwrap())
}

#[test]
fn dpop_vectors() {
    dpop_replay(common::ref_cases_seeded("dpop"));
}

/// ref-dpop-rsa.json.gz is generated by CI (never committed): a missing file fails under CI, else skips.
#[test]
fn dpop_rsa_vectors() {
    let path = std::env::var("PCA_DPOP_RSA_CORPUS").unwrap_or_else(|_| format!("{}/test-data/ref-dpop-rsa.json.gz", env!("CARGO_MANIFEST_DIR")));
    if !std::path::Path::new(&path).exists() {
        if matches!(std::env::var("CI").as_deref(), Ok("true") | Ok("1")) {
            panic!("RSA DPoP corpus missing ({path}): CI must generate it with .github/scripts/dpop-rsa-corpus.sh");
        }
        eprintln!("skipping: RSA DPoP corpus missing ({path}); run .github/scripts/dpop-rsa-corpus.sh");
        return;
    }
    let mut cases = common::ref_cases_at(&path);
    cases.iter_mut().for_each(common::resolve_seeds);
    dpop_replay(cases);
}

fn dpop_replay(cases: Vec<Value>) {
    let mut bad = Vec::new();
    for c in &cases {
        let a = c["args"].as_array().unwrap();
        let str_err = |r: Result<String, String>| r.map(Value::String).map_err(|m| DpopError { code: "", message: m });
        let got: Result<Value, DpopError> = match c["fn"].as_str().unwrap() {
            "constants" => Ok(json!({
                "allowedAlgs": DPOP_ALLOWED_ALGS, "typ": DPOP_JWT_TYP, "defaultMaxAgeSec": DPOP_DEFAULT_MAX_AGE_SEC, "clockSkewSec": DPOP_CLOCK_SKEW_SEC,
                "maxProofBytes": DPOP_MAX_PROOF_BYTES, "inMemoryMaxEntries": DPOP_INMEMORY_MAX_ENTRIES
            })),
            "nonceIssuer" => nonce_script(&a[0], &a[1], &a[2]),
            "replayStore" => replay_store_script(&a[0], &a[1]),
            "replayConformance" => Ok(conformance(a[0].as_str().unwrap())),
            "createThenVerify" => {
                #[cfg(not(feature = "ed448"))]
                if a[0]["publicJwk"]["crv"] == "Ed448" {
                    continue; // the Ed448 signer is the optional OpenSSL feature, replayed by its own job
                }
                create_then_verify(&a[0], &a[1])
            }
            "jwkThumbprint" => str_err(jwk_thumbprint_of(&a[0], a.get(1).and_then(Value::as_str))),
            "dpopAlgForJwk" => dpop_alg_for_jwk(&a[0]).map(|x| json!(x)),
            "dpopAlgMatchesJwk" => Ok(json!(a[0].as_str().is_some_and(|alg| dpop_alg_matches_jwk(alg, &a[1])))),
            // `new URL(x)` throws a Node ERR_INVALID_URL for anything it cannot parse, a non-string included
            "normalizeHtu" => a[0]
                .as_str()
                .map_or_else(|| Err("Invalid URL".to_string()), normalize_htu)
                .map(Value::String)
                .map_err(|m| DpopError { code: if m == "Invalid URL" { "ERR_INVALID_URL" } else { "" }, message: m }),
            "athFor" => Ok(json!(ath_for(a[0].as_str().unwrap_or("")))),
            "createDpopProof" => {
                let x = &a[0];
                let seed: [u8; 32] = b64(&x["seed"]).try_into().unwrap();
                str_err(create_dpop_proof_ed25519(
                    x["method"].as_str().unwrap(),
                    x["url"].as_str().unwrap(),
                    &seed,
                    x["iat"].as_i64().unwrap(),
                    x["jti"].as_str().unwrap(),
                    x.get("nonce").and_then(s),
                    x.get("ath").and_then(s),
                ))
            }
            "verifyDpopProof" => verify(&a[0], &a[1]),
            "nonceIssue" => issuer(&a[0]).map(|i| json!(i.issue(a[1].as_u64().unwrap()))),
            "nonceCheck" => issuer(&a[0]).map(|i| json!(i.check(&a[1], a[2].as_f64().unwrap()))),
            "mtlsCnf" => Ok(mtls_cnf(pem(&a[0]))),
            "mtlsCnfDer" => Ok(mtls_cnf(CertInput::Der(&b64(&a[0]["$bytes"])))),
            "mtlsThumbprint" => mtls_thumbprint(pem(&a[0])).map(Value::String),
            "assertMtlsBound" => assert_mtls_bound(pem(&a[0]), &a[1]),
            "leafHolderJwk" => leaf_holder_jwk(&a[0]),
            "bindPcaToDpop" => bind_pca_to_dpop(&a[0]).map(|j| json!({ "jkt": j })),
            f => panic!("unknown fn {f}"),
        };
        let shown = format!("{got:?}");
        if !same(&c["out"], got) {
            bad.push(format!("{}\n  want {}\n  got  {shown}", c["name"], c["out"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn in_memory_replay_store_is_conformant() {
    assert!(run_dpop_replay_store_conformance(|| InMemoryDpopReplayStore::new(None).unwrap()).is_empty());
    let full = InMemoryDpopReplayStore::new(Some(1)).unwrap();
    assert_eq!(full.add_if_absent("a", 200.0, 100.0), Ok(true));
    assert!(full.add_if_absent("b", 200.0, 100.0).is_err(), "full with a live entry fails closed");
    assert_eq!(full.add_if_absent("b", 400.0, 300.0), Ok(true), "an expired entry is swept");
}

/// A non-finite max age would disable the stale check and a non-finite clock would void the window: both are refused.
#[test]
fn non_finite_max_age_and_now_are_refused() {
    let seed = [7u8; 32];
    let url = "https://rs.example/r";
    let proof = Value::String(create_dpop_proof_ed25519("GET", url, &seed, 1_800_000_000, "jti-nf", None, None).expect("proof"));
    let code = |max_age_sec: f64, now: f64| {
        let o = VerifyDpopOptions { method: "GET".into(), url: url.into(), max_age_sec, now_sec: Some(now), require_replay_store: Some(false), ..Default::default() };
        verify_dpop_proof(&proof, &o).map(|_| "ok").unwrap_or_else(|e| e.code)
    };
    assert_eq!(code(300.0, 1_800_000_001.0), "ok");
    for v in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(code(v, 1_800_000_001.0), "max_age", "max_age_sec {v}");
        assert_eq!(code(300.0, v), "now", "now_sec {v}");
    }
}
