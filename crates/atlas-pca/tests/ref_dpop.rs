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

/// The bytes of a base64url string argument; anything else is the reference's refusal (a non-byte input), never a panic.
fn b64(s: &Value) -> Result<Vec<u8>, DpopError> {
    let t = s.as_str().ok_or_else(|| DpopError { code: "", message: "Uint8Array expected".to_string() })?;
    Ok(common::b64d(t))
}

fn issuer(n: &Value) -> Result<DpopNonceIssuer, DpopError> {
    DpopNonceIssuer::new(&b64(&n["secret"])?, n.get("ttlSec").and_then(Value::as_f64))
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
    DpopNonceIssuer::new(&b64(&n["secret"])?, n.get("ttl").or_else(|| n.get("ttlSec")).and_then(Value::as_f64))
}

/// `pca`: the PCActn whose leaf holder key the proof must be bound to (`assertPcaDpop`); `None` is a plain `verifyDpopProof`.
fn verify(pca: Option<&Value>, proof: &Value, w: &Value) -> Result<Value, DpopError> {
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
        max_age_sec: w.get("maxAgeSec").and_then(Value::as_f64).unwrap_or(DPOP_DEFAULT_MAX_AGE_SEC),
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
    let r = match pca {
        Some(p) => assert_pca_dpop(p, proof, o)?,
        None => verify_dpop_proof(proof, &o)?,
    };
    let mut out = json!({ "claims": r.claims, "jwk": r.jwk, "jkt": r.jkt });
    if preloaded_seen {
        out["seen"] = json!(seen.0.lock().unwrap().clone());
    }
    Ok(out)
}

fn ctx_err(m: impl Into<String>) -> DpopError {
    DpopError { code: "", message: m.into() }
}

/// `createDpopProof` through the native creator: the private JWK signs, the header carries only the public members of `publicJwk`.
fn create_proof(x: &Value) -> Result<String, DpopError> {
    create_dpop_proof(
        &x["privateKey"],
        &x["publicJwk"],
        x["method"].as_str().unwrap(),
        x["url"].as_str().unwrap(),
        x["iat"].as_f64().unwrap(),
        x["jti"].as_str().unwrap(),
        x.get("nonce").and_then(s),
        x.get("ath").and_then(s),
    )
}

fn create_then_verify(x: &Value, vo: &Value) -> Result<Value, DpopError> {
    let proof = create_proof(x)?;
    let mut w = json!({ "method": x["method"], "url": x["url"], "maxAgeSec": 300, "nowSec": x["iat"].as_f64().unwrap_or(0.0) + 1.0, "seenJti": [] });
    for (k, v) in vo.as_object().into_iter().flatten() {
        w[k] = v.clone();
    }
    verify(None, &Value::String(proof), &w)
}

fn replay_store_script(max: &Value, ops: &Value) -> Result<Value, DpopError> {
    let store = match max {
        Value::Null => InMemoryDpopReplayStore::new(None),
        // the reference passes any value through: a non-positive-integer size is refused
        v => match v.as_f64() {
            Some(m) if m >= 1.0 && m.fract() == 0.0 => InMemoryDpopReplayStore::new(Some(m as usize)),
            _ => InMemoryDpopReplayStore::new(Some(0)), // not a positive integer: the store itself refuses it as misconfigured
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
    // an absent secret is an empty one: the issuer refuses it as misconfigured
    let secret = if secret.is_null() { Vec::new() } else { b64(secret)? };
    let issuer = DpopNonceIssuer::new(&secret, ttl.as_f64())?;
    let (mut issued, mut out) = (Vec::<String>::new(), Vec::<Value>::new());
    for op in ops.as_array().unwrap() {
        let now = op.get("now").and_then(Value::as_f64).unwrap_or(0.0);
        match op["op"].as_str() {
            Some("issue") => {
                let n = issuer.issue_at(now)?;
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

/// A certificate argument: a PEM string, or `{"$bytes": ..}` for the DER the corpus carries for the binary forms.
enum CertArg<'a> {
    Pem(&'a str),
    Der(Vec<u8>),
}

impl CertArg<'_> {
    fn input(&self) -> CertInput<'_> {
        match self {
            CertArg::Pem(s) => CertInput::Pem(s),
            CertArg::Der(b) => CertInput::Der(b),
        }
    }
}

fn pem(v: &Value) -> CertArg<'_> {
    match v.get("$bytes").and_then(Value::as_str) {
        Some(b) => CertArg::Der(common::b64d(b)),
        // anything else that is not a string reads as no certificate at all (the refusal), never a panic
        None => CertArg::Pem(v.as_str().unwrap_or("")),
    }
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
                    continue; // the Ed448 signer is the optional OpenSSL feature (the "Ed448 (OpenSSL)" CI step replays it with the feature on)
                }
                create_then_verify(&a[0], &a[1])
            }
            "jwkThumbprint" => jwk_thumbprint_coded(&a[0], a.get(1).and_then(Value::as_str)).map(Value::String),
            "dpopAlgForJwk" => dpop_alg_for_jwk(&a[0]).map(|x| json!(x)),
            "dpopAlgMatchesJwk" => match a[0].as_str() {
                Some(alg) => dpop_alg_matches_jwk_checked(alg, &a[1]).map(|b| json!(b)),
                None => Ok(json!(false)),
            },
            // `new URL(x)` throws a Node ERR_INVALID_URL for anything it cannot parse, a non-string included
            "normalizeHtu" => a[0]
                .as_str()
                .map_or_else(|| Err("Invalid URL".to_string()), normalize_htu)
                .map(Value::String)
                .map_err(|m| DpopError { code: if m == "Invalid URL" { "ERR_INVALID_URL" } else { "" }, message: m }),
            // JavaScript encodes a lone surrogate as U+FFFD; the corpus carries it as the crate's stand-in
            "athFor" => Ok(json!(ath_for(&a[0].as_str().unwrap_or("").replace('\u{10FFFF}', "\u{FFFD}")))),
            "createDpopProof" => {
                // the Ed448 signer is the optional OpenSSL feature (the "Ed448 (OpenSSL)" CI step replays it with the feature on)
                #[cfg(not(feature = "ed448"))]
                if a[0]["publicJwk"]["crv"] == "Ed448" {
                    continue;
                }
                create_proof(&a[0]).map(Value::String)
            }
            "verifyDpopProof" => {
                #[cfg(not(feature = "ed448"))]
                if c["name"].as_str().is_some_and(|n| n.contains("ed448")) {
                    continue; // the Ed448 verifier is the optional OpenSSL feature (the "Ed448 (OpenSSL)" CI step replays it with the feature on)
                }
                verify(None, &a[0], &a[1])
            }
            "assertPcaDpop" => verify(Some(&a[0]), &a[1], &a[2]),
            "nonceIssue" => issuer(&a[0]).map(|i| json!(i.issue(a[1].as_u64().unwrap()))),
            "nonceCheck" => issuer(&a[0]).map(|i| json!(i.check(&a[1], a[2].as_f64().unwrap()))),
            "mtlsCnf" => Ok(mtls_cnf(pem(&a[0]).input())),
            "mtlsCnfDer" => b64(&a[0]["$bytes"]).map(|der| mtls_cnf(CertInput::Der(&der))),
            "mtlsThumbprint" => mtls_thumbprint(pem(&a[0]).input()).map(Value::String),
            "assertMtlsBound" => assert_mtls_bound(pem(&a[0]).input(), &a[1]),
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
