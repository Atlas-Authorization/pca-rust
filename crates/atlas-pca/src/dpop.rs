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
    if !o.max_age_sec.is_finite() {
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
    if h.contains_key("crit") {
        return Err(sig_fail("unsupported JWS header extension"));
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
    let want_htu = normalize_htu(&o.url).map_err(|e| err("htu", e))?;
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
    let leaf = p.get("cap_chain").and_then(Value::as_array).and_then(|c| c.last());
    let Some(leaf) = leaf else { return Err(err("no_leaf", "PCActn capability chain is empty; no bound holder key")) };
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
    jwk_thumbprint(&leaf_holder_jwk(p)?, "sha256").map_err(|e| err("no_leaf", e))
}

/// Verify a DPoP proof bound to the PCActn's leaf holder key (`assertPcaDpop`). `max_age_sec` 0 or less is taken as given;
/// leave it at [`DPOP_DEFAULT_MAX_AGE_SEC`] for the default.
pub fn assert_pca_dpop(p: &Value, proof: &Value, mut o: VerifyDpopOptions) -> Result<DpopVerified, DpopError> {
    o.expected_jkt = Some(bind_pca_to_dpop(p)?);
    verify_dpop_proof(proof, &o)
}
