//! DPoP (RFC 9449) and mTLS (RFC 8705) sender-constraint binding for a PCActn: the leaf capability's holder key is the DPoP
//! key (`jkt` = its RFC 7638 thumbprint), so a stolen PCActn cannot be replayed without that key. Proof creation (Ed25519),
//! verification (EdDSA / ES256 / ES384 / ES512 / PS256 / RS256; Ed448 only with the `ed448` feature), replay stores, stateless HMAC nonces,
//! `ath`, `htu` normalization and the `x5t#S256` certificate binding.
use crate::attest::x509::Cert;
use crate::jose::{assert_canonical_compact_jws, import_public_jwk, jwk_thumbprint, sign_ed25519_jws, verify_jws_signature};
use crate::{b64_encode, decode_b64u_strict};
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

pub const DPOP_ALLOWED_ALGS: [&str; 6] = ["EdDSA", "ES256", "ES384", "ES512", "PS256", "RS256"];
pub const DPOP_JWT_TYP: &str = "dpop+jwt";
pub const DPOP_DEFAULT_MAX_AGE_SEC: f64 = 300.0;
pub const DPOP_CLOCK_SKEW_SEC: f64 = 5.0;
pub const DPOP_INMEMORY_MAX_ENTRIES: usize = 100_000;
pub const DPOP_MAX_PROOF_BYTES: usize = 8192;

/// A refusal: `code` is the stable reason (`typ`, `signature`, `jti_replay`, ...), `message` the reference's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpopError {
    pub code: &'static str,
    pub message: String,
}

fn err(code: &'static str, message: impl Into<String>) -> DpopError {
    DpopError { code, message: message.into() }
}

/// A set of `jti`s already seen (single process).
pub trait JtiSeenSet {
    fn has(&self, jti: &str) -> bool;
    fn add(&self, jti: &str);
}

impl JtiSeenSet for Mutex<HashSet<String>> {
    fn has(&self, jti: &str) -> bool {
        self.lock().map(|s| s.contains(jti)).unwrap_or(true)
    }
    fn add(&self, jti: &str) {
        if let Ok(mut s) = self.lock() {
            s.insert(jti.to_string());
        }
    }
}

/// An atomic replay store: `add_if_absent` returns true exactly once per key until `expires_at_sec`.
pub trait DpopReplayStore {
    fn add_if_absent(&self, key: &str, expires_at_sec: f64, now_sec: f64) -> Result<bool, String>;
}

/// The bounded in-memory replay store (`createInMemoryDpopReplayStore`): when full, expired entries are swept; still full is
/// an error (fail closed), never an eviction of a live entry.
pub struct InMemoryDpopReplayStore {
    max: usize,
    seen: Mutex<HashMap<String, f64>>,
}

impl InMemoryDpopReplayStore {
    pub fn new(max_entries: Option<usize>) -> Result<Self, DpopError> {
        let max = max_entries.unwrap_or(DPOP_INMEMORY_MAX_ENTRIES);
        if max < 1 {
            return Err(err("misconfigured", "maxEntries must be a positive integer"));
        }
        Ok(Self { max, seen: Mutex::new(HashMap::new()) })
    }
}

impl DpopReplayStore for InMemoryDpopReplayStore {
    fn add_if_absent(&self, key: &str, expires_at_sec: f64, now_sec: f64) -> Result<bool, String> {
        if !now_sec.is_finite() || !expires_at_sec.is_finite() {
            return Ok(false);
        }
        let mut seen = self.seen.lock().map_err(|_| "replay store lock poisoned".to_string())?;
        let held = seen.get(key).copied();
        if held.is_some_and(|h| !(now_sec >= h)) {
            return Ok(false);
        }
        if held.is_none() && seen.len() >= self.max {
            seen.retain(|_, exp| !(now_sec >= *exp));
            if seen.len() >= self.max {
                return Err("replay store is full".into());
            }
        }
        seen.insert(key.to_string(), expires_at_sec);
        Ok(true)
    }
}

/// The replay-store contract (`runDpopReplayStoreConformance`): the names of the failed checks (empty = conformant).
pub fn run_dpop_replay_store_conformance<S: DpopReplayStore + Sync>(make: impl Fn() -> S) -> Vec<String> {
    let mut failures = Vec::new();
    let mut check = |ok: bool, name: &str| {
        if !ok {
            failures.push(name.to_string());
        }
    };
    let s = make();
    check(s.add_if_absent("a", 200.0, 100.0) == Ok(true), "first sight of a key returns true");
    check(s.add_if_absent("a", 200.0, 101.0) == Ok(false), "second sight of the same key returns false");
    check(s.add_if_absent("b", 200.0, 101.0) == Ok(true), "a different key is independent");
    check(s.add_if_absent("a", 200.0, 199.0) == Ok(false), "still seen one second before expiry");
    let t = make();
    let _ = t.add_if_absent("c", 200.0, 100.0);
    check(t.add_if_absent("c", 400.0, 200.0) == Ok(true), "an expired entry may be added again (nowSec >= expiresAtSec)");
    let u = make();
    let wins = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..16).map(|_| sc.spawn(|| u.add_if_absent("race", 200.0, 100.0) == Ok(true))).collect();
        hs.into_iter().map(|h| h.join().unwrap_or(false)).filter(|w| *w).count()
    });
    check(wins == 1, &format!("16 concurrent adds of one key: exactly one wins (got {wins})"));
    failures
}

/// Stateless server nonces (`createDpopNonceIssuer`): base64url(8-byte big-endian issue time || HMAC-SHA256(secret,
/// "dpop-nonce\0" || time)[..16]), valid from `DPOP_CLOCK_SKEW_SEC` before issue to `ttl_sec` after.
pub struct DpopNonceIssuer {
    secret: Vec<u8>,
    ttl: f64,
}

impl DpopNonceIssuer {
    pub fn new(secret: &[u8], ttl_sec: Option<f64>) -> Result<Self, DpopError> {
        if secret.len() < 32 {
            return Err(err("misconfigured", "nonce secret must be at least 32 bytes"));
        }
        let ttl = ttl_sec.unwrap_or(300.0);
        if !ttl.is_finite() || ttl <= 0.0 {
            return Err(err("misconfigured", "nonce ttlSec must be positive"));
        }
        Ok(Self { secret: secret.to_vec(), ttl })
    }
    fn mac(&self, ts: &[u8]) -> Vec<u8> {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&self.secret).expect("hmac accepts any key length");
        m.update(b"dpop-nonce\0");
        m.update(ts);
        m.finalize().into_bytes()[..16].to_vec()
    }
    /// `issue(nowSec)` for a JavaScript number: the reference converts it with `BigInt`, which refuses a fraction or a non-finite value
    /// (a negative integer wraps to its 64-bit two's complement, as `setBigUint64` writes it).
    pub fn issue_at(&self, now_sec: f64) -> Result<String, DpopError> {
        if !now_sec.is_finite() || now_sec.fract() != 0.0 {
            return Err(err("", format!("The number {} cannot be converted to a BigInt because it is not an integer", crate::intent_v2::js_number_string(now_sec))));
        }
        Ok(self.issue((now_sec as i128) as u64))
    }
    pub fn issue(&self, now_sec: u64) -> String {
        let ts = now_sec.to_be_bytes();
        let mut raw = ts.to_vec();
        raw.extend(self.mac(&ts));
        b64_encode(&raw)
    }
    pub fn check(&self, nonce: &Value, now_sec: f64) -> bool {
        let Some(raw) = nonce.as_str().and_then(|n| decode_b64u_strict(n, Some(24))) else { return false };
        let (ts, tag) = raw.split_at(8);
        if !crate::attest::util::timing_safe_eq(tag, &self.mac(ts)) {
            return false;
        }
        let issued = u64::from_be_bytes(ts.try_into().unwrap()) as f64;
        issued <= now_sec + DPOP_CLOCK_SKEW_SEC && now_sec - issued <= self.ttl
    }
}

/// RFC 7638 thumbprint (`jwkThumbprint`), SHA-256 by default.
pub fn jwk_thumbprint_of(jwk: &Value, digest: Option<&str>) -> Result<String, String> {
    jwk_thumbprint(jwk, digest.unwrap_or("sha256"))
}

/// [`jwk_thumbprint_of`] with the JOSE error code of a refusal: `ERR_JWK_INVALID` for a missing or invalid member,
/// `ERR_JOSE_NOT_SUPPORTED` for an unsupported key type.
pub fn jwk_thumbprint_coded(jwk: &Value, digest: Option<&str>) -> Result<String, DpopError> {
    jwk_thumbprint_of(jwk, digest).map_err(thumbprint_error)
}

fn thumbprint_error(m: String) -> DpopError {
    let code = if m.ends_with(" missing or invalid") {
        "ERR_JWK_INVALID"
    } else if m.ends_with(" missing or unsupported") {
        "ERR_JOSE_NOT_SUPPORTED"
    } else {
        ""
    };
    err(code, m)
}

fn crv_text(jwk: &Value) -> String {
    match jwk.get("crv") {
        None => "undefined".into(),
        Some(v) => crate::oauth::js_str(v),
    }
}

/// The DPoP `alg` for a public JWK (`dpopAlgForJwk`): OKP Ed25519/Ed448 EdDSA, EC P-256/384/521 ES256/384/512, RSA PS256.
pub fn dpop_alg_for_jwk(jwk: &Value) -> Result<&'static str, DpopError> {
    let crv = jwk.get("crv").and_then(Value::as_str);
    match jwk.get("kty").and_then(Value::as_str) {
        Some("OKP") => match crv {
            Some("Ed25519" | "Ed448") => Ok("EdDSA"),
            _ => Err(err("unsupported_key", format!("unsupported OKP curve '{}' for DPoP", crv_text(jwk)))),
        },
        Some("EC") => match crv {
            Some("P-256") => Ok("ES256"),
            Some("P-384") => Ok("ES384"),
            Some("P-521") => Ok("ES512"),
            _ => Err(err("unsupported_key", format!("unsupported EC curve '{}' for DPoP", crv_text(jwk)))),
        },
        Some("RSA") => Ok("PS256"),
        _ => {
            let kty = match jwk.get("kty") {
                None => "undefined".into(),
                Some(v) => crate::oauth::js_str(v),
            };
            Err(err("unsupported_key", format!("unsupported key type '{kty}' for DPoP")))
        }
    }
}

/// Does `alg` fit the JWK's key type (`dpopAlgMatchesJwk`)?
pub fn dpop_alg_matches_jwk(alg: &str, jwk: &Value) -> bool {
    dpop_alg_matches_jwk_checked(alg, jwk).unwrap_or(false)
}

/// [`dpop_alg_matches_jwk`] where the reference throws: reading `kty` of a null key is a TypeError.
pub fn dpop_alg_matches_jwk_checked(alg: &str, jwk: &Value) -> Result<bool, DpopError> {
    // the reference switches on the alg first: an alg it does not know is false without the key being read
    let known = matches!(alg, "EdDSA" | "ES256" | "ES384" | "ES512" | "PS256" | "RS256");
    if known && jwk.is_null() {
        return Err(err("", "Cannot read properties of null (reading 'kty')"));
    }
    Ok(alg_matches(alg, jwk))
}

fn alg_matches(alg: &str, jwk: &Value) -> bool {
    let kty = jwk.get("kty").and_then(Value::as_str);
    let crv = jwk.get("crv").and_then(Value::as_str);
    match alg {
        "EdDSA" => kty == Some("OKP") && matches!(crv, Some("Ed25519" | "Ed448")),
        "ES256" => kty == Some("EC") && crv == Some("P-256"),
        "ES384" => kty == Some("EC") && crv == Some("P-384"),
        "ES512" => kty == Some("EC") && crv == Some("P-521"),
        "PS256" | "RS256" => kty == Some("RSA"),
        _ => false,
    }
}

/// RFC 9449 section 4.3 `htu`: scheme, host and path of the request URL (query and fragment dropped).
pub fn normalize_htu(url: &str) -> Result<String, String> {
    let u = url::Url::parse(url).map_err(|_| "Invalid URL".to_string())?;
    let host = match (u.host_str(), u.port()) {
        (Some(h), Some(p)) => format!("{h}:{p}"),
        (Some(h), None) => h.to_string(),
        _ => String::new(),
    };
    Ok(format!("{}://{host}{}", u.scheme(), u.path()))
}

/// RFC 9449 section 4.2 `ath`: base64url(SHA-256(access token)).
pub fn ath_for(access_token: &str) -> String {
    b64_encode(&Sha256::digest(access_token.as_bytes()))
}

/// An Ed25519 DPoP proof (`createDpopProof` with an Ed25519 key): header `{typ, alg, jwk}`, claims `{htm, htu, iat, jti,
/// nonce?, ath?}`. `iat` and `jti` are the caller's (pass the current time and a fresh random id).
pub fn create_dpop_proof_ed25519(method: &str, url: &str, seed: &[u8; 32], iat: i64, jti: &str, nonce: Option<&str>, ath: Option<&str>) -> Result<String, String> {
    let jwk = crate::jose::ed25519_public_jwk(seed);
    let mut claims = Map::new();
    claims.insert("htm".into(), json!(method.to_uppercase()));
    claims.insert("htu".into(), json!(normalize_htu(url)?));
    claims.insert("iat".into(), json!(iat));
    claims.insert("jti".into(), json!(jti));
    if let Some(n) = nonce {
        claims.insert("nonce".into(), json!(n));
    }
    if let Some(a) = ath {
        claims.insert("ath".into(), json!(a));
    }
    Ok(sign_ed25519_jws(&json!({ "typ": DPOP_JWT_TYP, "alg": "EdDSA", "jwk": jwk }), &Value::Object(claims), seed))
}

/// The public members of a JWK, in the reference's order (`toPublicJwk`): `kty`, `crv`, `x`, `y`, `n`, `e`. No private member is ever
/// embedded in a proof.
fn to_public_jwk(jwk: &Value) -> Value {
    let mut out = Map::new();
    for k in ["kty", "crv", "x", "y", "n", "e"] {
        if let Some(v) = jwk.get(k) {
            out.insert(k.into(), v.clone());
        }
    }
    Value::Object(out)
}

/// A getrandom-backed byte source for the PSS salt.
struct SaltRng;

impl rsa::rand_core::RngCore for SaltRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("the operating system's random source");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rsa::rand_core::CryptoRng for SaltRng {}

/// A DPoP proof for any supported key (`createDpopProof`): header `{typ, alg, jwk}` with ONLY the public members of `public_jwk`
/// (never a private member), claims `{htm, htu, iat, jti, nonce?, ath?}`, signed with `private_jwk` (EdDSA Ed25519 and, with the
/// `ed448` feature, Ed448; ES256 / ES384 / ES512; PS256). The `alg` follows the public key; a private key of another type or curve is
/// refused ("Invalid key for this operation").
pub fn create_dpop_proof(private_jwk: &Value, public_jwk: &Value, method: &str, url: &str, iat: f64, jti: &str, nonce: Option<&str>, ath: Option<&str>) -> Result<String, DpopError> {
    let public = to_public_jwk(public_jwk);
    let alg = dpop_alg_for_jwk(&public)?;
    let mut claims = Map::new();
    claims.insert("htm".into(), json!(method.to_uppercase()));
    claims.insert("htu".into(), json!(normalize_htu(url).map_err(|m| err(if m == "Invalid URL" { "ERR_INVALID_URL" } else { "" }, m))?));
    claims.insert("iat".into(), if iat.fract() == 0.0 && iat.abs() <= 9_007_199_254_740_991.0 { json!(iat as i64) } else { json!(iat) });
    claims.insert("jti".into(), json!(jti));
    if let Some(n) = nonce {
        claims.insert("nonce".into(), json!(n));
    }
    if let Some(a) = ath {
        claims.insert("ath".into(), json!(a));
    }
    let claims = Value::Object(claims);
    let header = json!({ "typ": DPOP_JWT_TYP, "alg": alg, "jwk": public });
    let mismatch = || err("", "Invalid key for this operation, its asymmetricKeyType must match the key");
    let kty = private_jwk.get("kty").and_then(Value::as_str);
    let crv = private_jwk.get("crv").and_then(Value::as_str);
    let member = |k: &str| private_jwk.get(k).and_then(Value::as_str).and_then(|t| decode_b64u_strict(t, None));
    if kty != Some("RSA") && member("d").is_none() {
        return Err(err("", "JSON Web Key for this operation be a private JWK"));
    }
    let input = format!("{}.{}", b64_encode(crate::js_stringify(&header).as_bytes()), b64_encode(crate::js_stringify(&claims).as_bytes()));
    let sig: Vec<u8> = match (alg, kty, crv) {
        ("EdDSA", Some("OKP"), Some("Ed25519")) if public.get("crv") == Some(&json!("Ed25519")) => {
            use ed25519_dalek::Signer;
            let seed: [u8; 32] = member("d").and_then(|d| d.try_into().ok()).ok_or_else(mismatch)?;
            ed25519_dalek::SigningKey::from_bytes(&seed).sign(input.as_bytes()).to_bytes().to_vec()
        }
        #[cfg(feature = "ed448")]
        ("EdDSA", Some("OKP"), Some("Ed448")) if public.get("crv") == Some(&json!("Ed448")) => {
            let seed: [u8; 57] = member("d").and_then(|d| d.try_into().ok()).ok_or_else(mismatch)?;
            return crate::jose::sign_ed448_jws(&header, &claims, &seed).map_err(|m| err("", m));
        }
        ("ES256", Some("EC"), Some("P-256")) => {
            use p256::ecdsa::signature::Signer;
            let k = p256::ecdsa::SigningKey::from_slice(&member("d").ok_or_else(mismatch)?).map_err(|_| mismatch())?;
            let sg: p256::ecdsa::Signature = k.sign(input.as_bytes());
            sg.to_bytes().to_vec()
        }
        ("ES384", Some("EC"), Some("P-384")) => {
            use p384::ecdsa::signature::Signer;
            let k = p384::ecdsa::SigningKey::from_slice(&member("d").ok_or_else(mismatch)?).map_err(|_| mismatch())?;
            let sg: p384::ecdsa::Signature = k.sign(input.as_bytes());
            sg.to_bytes().to_vec()
        }
        ("ES512", Some("EC"), Some("P-521")) => {
            use p521::ecdsa::signature::Signer;
            let k = p521::ecdsa::SigningKey::from_slice(&member("d").ok_or_else(mismatch)?).map_err(|_| mismatch())?;
            let sg: p521::ecdsa::Signature = k.sign(input.as_bytes());
            sg.to_bytes().to_vec()
        }
        ("PS256", Some("RSA"), _) => {
            use rsa::signature::{RandomizedSigner, SignatureEncoding};
            let big = |k: &str| member(k).map(|b| rsa::BigUint::from_bytes_be(&b));
            let (Some(n), Some(e), Some(d), Some(p), Some(q)) = (big("n"), big("e"), big("d"), big("p"), big("q")) else { return Err(mismatch()) };
            let sk = rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q]).map_err(|_| mismatch())?;
            rsa::pss::SigningKey::<Sha256>::new(sk).sign_with_rng(&mut SaltRng, input.as_bytes()).to_bytes().to_vec()
        }
        _ => return Err(mismatch()),
    };
    Ok(format!("{input}.{}", b64_encode(&sig)))
}

/// What a DPoP proof is checked against (`VerifyDpopProofOptions`).
#[derive(Default)]
pub struct VerifyDpopOptions<'a> {
    pub method: String,
    pub url: String,
    pub max_age_sec: f64,
    pub expected_jkt: Option<String>,
    pub seen_jti: Option<&'a dyn JtiSeenSet>,
    pub replay_store: Option<&'a dyn DpopReplayStore>,
    /// `Some(false)` only to run without replay detection (default: a replay store or seen-set is required).
    pub require_replay_store: Option<bool>,
    pub nonce_issuer: Option<&'a DpopNonceIssuer>,
    pub now_sec: Option<f64>,
    pub expected_nonce: Option<String>,
    pub access_token: Option<String>,
}

/// A verified proof: its claims, the embedded public JWK and that key's thumbprint.
#[derive(Debug, Clone)]
pub struct DpopVerified {
    pub claims: Value,
    pub jwk: Value,
    pub jkt: String,
}

fn now_sec() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs() as f64)
}

/// Verify a DPoP proof (`verifyDpopProof`), fail closed, in the reference's order of checks.
pub fn verify_dpop_proof(proof: &Value, o: &VerifyDpopOptions) -> Result<DpopVerified, DpopError> {
    // A NaN or infinite max age would disable the stale check (now - iat > NaN is never true): refuse it.
    if !o.max_age_sec.is_finite() || o.max_age_sec < 0.0 {
        return Err(err("max_age", "maxAgeSec must be a finite, non-negative number of seconds"));
    }
    if o.require_replay_store != Some(false) && o.replay_store.is_none() && o.seen_jti.is_none() {
        return Err(err("replay_store_required", "no replay store configured; replay cannot be detected"));
    }
    if !proof.as_str().is_some_and(|p| p.encode_utf16().count() <= DPOP_MAX_PROOF_BYTES) {
        return Err(err("oversize", format!("proof is not a string or exceeds {DPOP_MAX_PROOF_BYTES} bytes")));
    }
    let jws = assert_canonical_compact_jws(proof, 3, crate::jose::DEFAULT_MAX_JWS_BYTES, true).map_err(|e| err("malformed", format!("not a JWS: {e}")))?;
    let h = &jws.header;
    if h.get("typ").and_then(Value::as_str) != Some(DPOP_JWT_TYP) {
        let got = h.get("typ").map_or("undefined".to_string(), crate::oauth::js_str);
        return Err(err("typ", format!("header typ must be '{DPOP_JWT_TYP}', got '{got}'")));
    }
    let Some(hj) = h.get("jwk").filter(|j| !j.is_null()) else { return Err(err("no_jwk", "proof header has no embedded jwk")) };
    if hj.as_object().is_some_and(|m| ["d", "p", "q", "dp", "dq", "qi", "k"].iter().any(|k| m.contains_key(*k))) {
        return Err(err("private_jwk", "proof header jwk contains private key material"));
    }
    let alg = h.get("alg").and_then(Value::as_str);
    if let Some(a) = alg.filter(|a| DPOP_ALLOWED_ALGS.contains(a)) {
        if !dpop_alg_matches_jwk(a, hj) {
            return Err(err("alg_jwk_mismatch", format!("alg '{a}' does not match the embedded jwk key type")));
        }
    }
    // the JWT verification step: allowed alg, no crit, an embedded public key that imports, the signature, exp / nbf / iat types
    let sig_fail = |why: &str| err("signature", format!("DPoP signature did not verify: {why}"));
    let alg = alg.filter(|a| DPOP_ALLOWED_ALGS.contains(a)).ok_or_else(|| sig_fail("\"alg\" (Algorithm) Header Parameter value not allowed"))?;
    // shortcut: any `crit` is refused (the reference's JOSE library admits `crit: ["b64"]` with `b64: true`); stricter, never looser
    // `crit` is understood only for `b64` (RFC 7797), as the JOSE library does; `b64: false` (an unencoded payload) is refused for a JWT
    if !crate::jose::check_crit_b64(h).map_err(|e| sig_fail(&e))? {
        return Err(sig_fail("JWTs MUST NOT use unencoded payload"));
    }
    if !hj.is_object() {
        return Err(sig_fail("\"jwk\" (JSON Web Key) Header Parameter must be a JSON object"));
    }
    let key = import_public_jwk(hj, alg).map_err(|e| sig_fail(&e))?;
    let input = format!("{}.{}", jws.segments[0], jws.segments[1]);
    if !verify_jws_signature(alg, &key, input.as_bytes(), &jws.bytes[2]) {
        return Err(sig_fail("signature verification failed"));
    }
    let payload = jws.payload.clone().unwrap_or_default();
    let wall = now_sec();
    for (k, past) in [("iat", None), ("exp", Some(true)), ("nbf", Some(false))] {
        if let Some(v) = payload.get(k) {
            let Some(n) = v.as_f64() else { return Err(sig_fail(&format!("\"{k}\" claim must be a number"))) };
            match past {
                Some(true) if n <= wall => return Err(sig_fail("\"exp\" claim timestamp check failed")),
                Some(false) if n > wall => return Err(sig_fail("\"nbf\" claim timestamp check failed")),
                _ => {}
            }
        }
    }
    let jwk = hj.clone();
    let htm = payload.get("htm").and_then(Value::as_str).ok_or_else(|| err("htm", "htm is missing or not a string"))?;
    let htu = payload.get("htu").and_then(Value::as_str).ok_or_else(|| err("htu", "htu is missing or not a string"))?;
    let iat = payload.get("iat").and_then(Value::as_f64).ok_or_else(|| err("iat", "iat is missing or not a number"))?;
    let jti = payload.get("jti").and_then(Value::as_str).filter(|j| !j.is_empty()).ok_or_else(|| err("jti", "jti is missing or empty"))?;
    if htm != o.method.to_uppercase() {
        return Err(err("htm", format!("htm '{htm}' does not match request method")));
    }
    let want_htu = normalize_htu(&o.url).map_err(|e| err(if e == "Invalid URL" { "ERR_INVALID_URL" } else { "htu" }, e))?;
    if htu != want_htu {
        return Err(err("htu", format!("htu '{htu}' does not match request URL")));
    }
    let now = o.now_sec.unwrap_or_else(now_sec);
    if !now.is_finite() {
        return Err(err("now", "nowSec must be a finite number"));
    }
    if !(iat <= now + DPOP_CLOCK_SKEW_SEC) {
        return Err(err("iat_future", "iat is in the future"));
    }
    if !(now - iat <= o.max_age_sec) {
        return Err(err("iat_stale", format!("proof is older than {}s", crate::intent_v2::js_number_string(o.max_age_sec))));
    }
    let jkt = jwk_thumbprint(&jwk, "sha256").map_err(|e| sig_fail(&e))?;
    if o.expected_jkt.as_ref().is_some_and(|e| *e != jkt) {
        return Err(err("jkt", "embedded key thumbprint does not match expected jkt"));
    }
    let pn = payload.get("nonce");
    if let Some(e) = &o.expected_nonce {
        if pn.and_then(Value::as_str) != Some(e.as_str()) {
            return Err(err("nonce", "proof nonce is missing or does not match the expected nonce"));
        }
    }
    if let Some(ni) = o.nonce_issuer {
        if !ni.check(pn.unwrap_or(&Value::Null), now) {
            return Err(err("nonce", "proof nonce is missing, forged or expired"));
        }
    }
    if let Some(at) = &o.access_token {
        if payload.get("ath").and_then(Value::as_str) != Some(ath_for(at).as_str()) {
            return Err(err("ath", "proof ath is missing or does not match the access token"));
        }
    }
    if let Some(s) = o.seen_jti {
        if s.has(jti) {
            return Err(err("jti_replay", format!("jti '{jti}' has already been seen")));
        }
        s.add(jti);
    }
    if let Some(rs) = o.replay_store {
        let fresh = rs
            .add_if_absent(&format!("{jkt}.{jti}"), iat + o.max_age_sec + DPOP_CLOCK_SKEW_SEC, now)
            .map_err(|e| err("replay_store_error", format!("replay store failed: {e}")))?;
        if !fresh {
            return Err(err("jti_replay", format!("jti '{jti}' has already been seen")));
        }
    }
    Ok(DpopVerified { claims: Value::Object(payload), jwk, jkt })
}

/// The DER of a certificate given as PEM text (the first CERTIFICATE block, else the whole text as base64).
fn pem_to_der(pem: &str) -> Vec<u8> {
    let body = match (pem.find("-----BEGIN CERTIFICATE-----"), pem.find("-----END CERTIFICATE-----")) {
        (Some(b), Some(e)) if e > b + 27 => &pem[b + 27..e],
        _ => pem,
    };
    let clean: String = body.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=').collect();
    let mut data = clean.split('=').next().unwrap_or("").to_string();
    if data.len() % 4 == 1 {
        data.pop();
    }
    use base64::Engine;
    let lenient = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true).with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone),
    );
    lenient.decode(data).unwrap_or_default()
}

/// A certificate given as DER bytes or PEM text.
pub enum CertInput<'a> {
    Der(&'a [u8]),
    Pem(&'a str),
}

/// RFC 8705 `cnf` for a client certificate (`mtlsCnf`): `{"x5t#S256": base64url(SHA-256(DER))}` (the bytes as given).
pub fn mtls_cnf(cert: CertInput) -> Value {
    let der = match cert {
        CertInput::Der(d) => d.to_vec(),
        CertInput::Pem(p) => pem_to_der(p),
    };
    json!({ "x5t#S256": b64_encode(&Sha256::digest(&der)) })
}

/// The `x5t#S256` of a parsed X.509 certificate (`mtlsThumbprint`); not a certificate is refused (`cert`).
pub fn mtls_thumbprint(cert: CertInput) -> Result<String, DpopError> {
    let parsed = match cert {
        CertInput::Der(d) => Cert::from_der(d),
        CertInput::Pem(p) => crate::attest::x509::pem_blocks(p).first().ok_or_else(|| "no PEM block".to_string()).and_then(|b| Cert::from_pem(b)),
    };
    let c = parsed.map_err(|e| err("cert", format!("not an X.509 certificate: {e}")))?;
    Ok(b64_encode(&Sha256::digest(&c.raw)))
}

/// RFC 8705 binding check (`assertMtlsBound`): the presented certificate's thumbprint equals `cnf["x5t#S256"]`.
pub fn assert_mtls_bound(cert: CertInput, cnf: &Value) -> Result<Value, DpopError> {
    let want = cnf.as_object().and_then(|m| m.get("x5t#S256")).and_then(Value::as_str).filter(|s| !s.is_empty());
    let Some(want) = want else { return Err(err("x5t_missing", "cnf has no 'x5t#S256' thumbprint")) };
    let got = mtls_thumbprint(cert)?;
    if !crate::attest::util::timing_safe_eq(got.as_bytes(), want.as_bytes()) {
        return Err(err("x5t", "client certificate thumbprint does not match cnf x5t#S256"));
    }
    Ok(json!({ "x5t#S256": got }))
}

/// The leaf capability's holder key as an OKP JWK (`leafHolderJwk`).
pub fn leaf_holder_jwk(p: &Value) -> Result<Value, DpopError> {
    // a string chain has a length and indexes to its characters: a non-empty one has a leaf that holds no key
    let chain = p.get("cap_chain");
    let char_leaf = chain.and_then(Value::as_str).filter(|s| !s.is_empty()).map(|_| Value::Null);
    let leaf = chain.and_then(Value::as_array).and_then(|c| c.last()).or(char_leaf.as_ref());
    let Some(leaf) = leaf else { return Err(err("no_leaf", "PCActn capability chain is empty; no bound holder key")) };
    if char_leaf.is_none() && leaf.is_null() {
        return Err(err("", "Cannot read properties of null (reading 'holder')")); // a null hop has no `holder` to read
    }
    let mut j = Map::new();
    j.insert("kty".into(), json!("OKP"));
    j.insert("crv".into(), json!("Ed25519"));
    if let Some(h) = leaf.get("holder") {
        j.insert("x".into(), h.clone());
    }
    Ok(Value::Object(j))
}

/// The `jkt` a PCActn binds to (`bindPcaToDpop`).
pub fn bind_pca_to_dpop(p: &Value) -> Result<String, DpopError> {
    jwk_thumbprint_coded(&leaf_holder_jwk(p)?, None)
}

/// Verify a DPoP proof bound to the PCActn's leaf holder key (`assertPcaDpop`). `max_age_sec` 0 or less is taken as given;
/// leave it at [`DPOP_DEFAULT_MAX_AGE_SEC`] for the default.
pub fn assert_pca_dpop(p: &Value, proof: &Value, mut o: VerifyDpopOptions) -> Result<DpopVerified, DpopError> {
    o.expected_jkt = Some(bind_pca_to_dpop(p)?);
    verify_dpop_proof(proof, &o)
}

#[cfg(test)]
mod thumbprint_error_tests {
    use super::*;

    fn coded(jwk: Value) -> (String, String) {
        let e = jwk_thumbprint_coded(&jwk, None).unwrap_err();
        (e.code.to_string(), e.message)
    }

    #[test]
    fn a_missing_member_names_jose_label_and_code() {
        let bad = |m: &str| ("ERR_JWK_INVALID".to_string(), format!("{m} missing or invalid"));
        assert_eq!(coded(json!({"kty": "OKP", "crv": "Ed25519"})), bad("\"x\" (Public Key) Parameter"));
        assert_eq!(coded(json!({"kty": "OKP", "x": "a"})), bad("\"crv\" (Subtype of Key Pair) Parameter"));
        assert_eq!(coded(json!({"kty": "EC", "crv": "", "x": "a", "y": "b"})), bad("\"crv\" (Curve) Parameter"));
        assert_eq!(coded(json!({"kty": "EC", "crv": "P-256", "y": "b"})), bad("\"x\" (X Coordinate) Parameter"));
        assert_eq!(coded(json!({"kty": "EC", "crv": "P-256", "x": "a"})), bad("\"y\" (Y Coordinate) Parameter"));
        assert_eq!(coded(json!({"kty": "RSA", "n": "a"})), bad("\"e\" (Exponent) Parameter"));
        assert_eq!(coded(json!({"kty": "RSA", "e": "a"})), bad("\"n\" (Modulus) Parameter"));
        assert_eq!(coded(json!({"kty": "oct"})), bad("\"k\" (Key Value) Parameter"));
        assert_eq!(coded(json!({"kty": "XYZ"})), ("ERR_JOSE_NOT_SUPPORTED".to_string(), "\"kty\" (Key Type) Parameter missing or unsupported".to_string()));
    }

    #[test]
    fn a_leaf_that_holds_no_key_is_a_jwk_error_and_a_null_hop_is_a_type_error() {
        let bind = |p: Value| bind_pca_to_dpop(&p).unwrap_err();
        assert_eq!(bind(json!({"cap_chain": [{}]})).code, "ERR_JWK_INVALID");
        assert_eq!(bind(json!({"cap_chain": "x"})).code, "ERR_JWK_INVALID");
        assert_eq!(bind(json!({"cap_chain": [5]})).code, "ERR_JWK_INVALID");
        assert_eq!(bind(json!({"cap_chain": []})).code, "no_leaf");
        assert_eq!(bind(json!({"cap_chain": ""})).code, "no_leaf");
        assert_eq!(bind(json!({"cap_chain": [null]})).message, "Cannot read properties of null (reading 'holder')");
        assert_eq!(leaf_holder_jwk(&json!({"cap_chain": "x"})).unwrap(), json!({"kty": "OKP", "crv": "Ed25519"}));
    }
}

#[cfg(test)]
mod verify_gate_tests {
    use super::*;

    fn proof(extra: Value) -> String {
        let seed = [7u8; 32];
        let mut header = json!({"typ": DPOP_JWT_TYP, "alg": "EdDSA", "jwk": crate::jose::ed25519_public_jwk(&seed)});
        for (k, v) in extra.as_object().into_iter().flatten() {
            header[k] = v.clone();
        }
        let claims = json!({"htm": "POST", "htu": "https://a.example/x", "iat": 1000, "jti": "j"});
        crate::jose::sign_ed25519_jws(&header, &claims, &seed)
    }

    fn verify(proof: &str, max_age: f64, url: &str) -> Result<DpopVerified, DpopError> {
        let o = VerifyDpopOptions { method: "POST".into(), url: url.into(), max_age_sec: max_age, now_sec: Some(1001.0), require_replay_store: Some(false), ..Default::default() };
        verify_dpop_proof(&Value::String(proof.to_string()), &o)
    }

    #[test]
    fn crit_is_understood_only_for_b64_true() {
        let url = "https://a.example/x";
        assert!(verify(&proof(json!({})), 300.0, url).is_ok());
        assert!(verify(&proof(json!({"crit": ["b64"], "b64": true})), 300.0, url).is_ok());
        let e = verify(&proof(json!({"crit": ["b64"], "b64": false})), 300.0, url).err().unwrap();
        assert_eq!((e.code, e.message.as_str()), ("signature", "DPoP signature did not verify: JWTs MUST NOT use unencoded payload"));
        let e = verify(&proof(json!({"crit": ["exp"], "exp": 1})), 300.0, url).err().unwrap();
        assert_eq!(e.message, "DPoP signature did not verify: Extension Header Parameter \"exp\" is not recognized");
        let e = verify(&proof(json!({"crit": ["b64"]})), 300.0, url).err().unwrap();
        assert_eq!(e.message, "DPoP signature did not verify: Extension Header Parameter \"b64\" is missing");
    }

    #[test]
    fn a_negative_max_age_and_an_unparsable_url_are_refused_with_the_reference_codes() {
        let p = proof(json!({}));
        assert_eq!(verify(&p, -1.0, "https://a.example/x").err().unwrap().code, "max_age");
        assert!(verify(&p, 0.0, "https://a.example/x").is_ok() || verify(&p, 0.0, "https://a.example/x").err().unwrap().code == "iat_stale");
        let e = verify(&p, 300.0, "not a url").err().unwrap();
        assert_eq!((e.code, e.message.as_str()), ("ERR_INVALID_URL", "Invalid URL"));
    }

    #[test]
    fn an_rsa_key_with_other_primes_is_refused_and_a_null_key_is_a_type_error_and_a_fractional_nonce_time_is_refused() {
        let e = crate::jose::import_public_jwk(&json!({"kty": "RSA", "n": "AQAB", "e": "AQAB", "oth": []}), "PS256").err().unwrap();
        assert_eq!(e, "RSA JWK \"oth\" (Other Primes Info) Parameter value is not supported");
        assert_eq!(dpop_alg_matches_jwk_checked("EdDSA", &Value::Null).err().unwrap().message, "Cannot read properties of null (reading 'kty')");
        assert_eq!(dpop_alg_matches_jwk_checked("EdDSA", &json!({"kty": "OKP", "crv": "Ed25519"})).ok(), Some(true));
        for unknown in ["HS256", "none", "ps256", ""] {
            assert_eq!(dpop_alg_matches_jwk_checked(unknown, &Value::Null).ok(), Some(false), "{unknown}");
        }
        let issuer = DpopNonceIssuer::new(&[1u8; 32], None).unwrap();
        assert_eq!(issuer.issue_at(1.5).err().unwrap().message, "The number 1.5 cannot be converted to a BigInt because it is not an integer");
        assert_eq!(issuer.issue_at(7.0).unwrap(), issuer.issue(7));
        assert!(issuer.issue_at(f64::NAN).is_err());
    }
}

#[cfg(test)]
mod create_proof_tests {
    use super::*;
    use base64::Engine;

    fn jwk_of(seed: &[u8; 32]) -> (Value, Value) {
        let public = crate::jose::ed25519_public_jwk(seed);
        let mut private = public.clone();
        private["d"] = json!(b64_encode(seed));
        (private, public)
    }

    fn header_of(proof: &str) -> Value {
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(proof.split('.').next().unwrap()).unwrap();
        serde_json::from_slice(&h).unwrap()
    }

    #[test]
    fn a_private_member_never_reaches_the_embedded_jwk() {
        let (private, mut public) = jwk_of(&[7u8; 32]);
        // the caller hands over a public key that carries private and extra members
        public["d"] = json!("SECRET");
        public["kid"] = json!("k");
        public["use"] = json!("sig");
        let proof = create_dpop_proof(&private, &public, "post", "https://api.example.com/v1/items?q=1#f", 1_800_000_000.0, "jti-1", Some("n"), None).unwrap();
        let h = header_of(&proof);
        assert_eq!(h["jwk"], crate::jose::ed25519_public_jwk(&[7u8; 32]));
        assert!(!proof.contains("SECRET") && !h["jwk"].as_object().unwrap().contains_key("d"));
        // it verifies, as an ordinary proof
        let o = VerifyDpopOptions { method: "POST".into(), url: "https://api.example.com/v1/items".into(), max_age_sec: 300.0, now_sec: Some(1_800_000_001.0), require_replay_store: Some(false), expected_nonce: Some("n".into()), ..Default::default() };
        assert!(verify_dpop_proof(&Value::String(proof), &o).is_ok());
    }

    #[test]
    fn the_ed25519_creator_and_the_generic_one_agree_and_bad_keys_are_refused() {
        let (private, public) = jwk_of(&[7u8; 32]);
        let a = create_dpop_proof(&private, &public, "GET", "https://a.example/x", 1000.0, "j", None, None).unwrap();
        assert_eq!(a, create_dpop_proof_ed25519("GET", "https://a.example/x", &[7u8; 32], 1000, "j", None, None).unwrap());
        // fractional iat is written as given; a bad URL, an unsupported key and a public key as private are refused
        assert!(create_dpop_proof(&private, &public, "GET", "https://a.example/x", 1.5, "j", None, None).is_ok());
        assert_eq!(create_dpop_proof(&private, &public, "GET", "not a url", 1.0, "j", None, None).err().unwrap().code, "ERR_INVALID_URL");
        assert_eq!(create_dpop_proof(&private, &json!({"kty": "oct", "k": "AAAA"}), "GET", "https://a.example/x", 1.0, "j", None, None).err().unwrap().code, "unsupported_key");
        assert!(create_dpop_proof(&public, &public, "GET", "https://a.example/x", 1.0, "j", None, None).is_err());
        let (other_private, _) = jwk_of(&[8u8; 32]);
        let p256_public = json!({"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"});
        assert!(create_dpop_proof(&other_private, &p256_public, "GET", "https://a.example/x", 1.0, "j", None, None).is_err());
    }

    #[test]
    fn an_ecdsa_proof_verifies_under_its_public_key() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let pt = sk.verifying_key().to_encoded_point(false);
        let public = json!({"kty": "EC", "crv": "P-256", "x": b64_encode(pt.x().unwrap()), "y": b64_encode(pt.y().unwrap())});
        let mut private = public.clone();
        private["d"] = json!(b64_encode(&[9u8; 32]));
        let proof = create_dpop_proof(&private, &public, "GET", "https://a.example/x", 1000.0, "j", None, None).unwrap();
        let o = VerifyDpopOptions { method: "GET".into(), url: "https://a.example/x".into(), max_age_sec: 300.0, now_sec: Some(1001.0), require_replay_store: Some(false), ..Default::default() };
        assert_eq!(verify_dpop_proof(&Value::String(proof), &o).unwrap().jwk, public);
    }
}
