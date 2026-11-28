//! Per-session attestation freshness and channel binding: Entity Attestation Tokens (RFC 9711, a compact JWS with the `eat+jwt`
//! typ), their channel / nonce binding (IETF SEAT / RA-TLS), the RATS appraisal (RFC 9334: evidence, reference values and
//! endorsements into a trust tier), the tolerant SEV-SNP report parse, the AMD hardware root (delegated to the chain, report
//! signature and VCEK binding checks of [`crate::attest::snp`]), EAT admission evidence and the artifact discharge. The
//! post-quantum co-signature of a verdict is in [`crate::attest_eat_pqcosign`] (re-exported here).
//!
//! JSON-valued, as the reference: options, claims and verdicts are `serde_json::Value`s with the reference's member names.
//! A JavaScript `undefined` is `None` (an explicit JSON `null` is `Some(Value::Null)`); a reference throw is `Err(message)`.
//! Binary inputs of the JSON surface (an SEV-SNP report, a DER certificate) are `{"$bytes": base64url}` objects; a PEM
//! certificate is a string.
//!
//! shortcuts: ES256 tokens are verified but never signed here (an ES256 `build_eat` is refused); `issue_nonce` and
//! `generate_eat_key_pair` are not ported (a nonce is the caller's CSPRNG); a present `clockSkewMs` that is not a finite number
//! is refused by `verify_freshness` (the reference would read `NaN` / `Infinity` as an unbounded window), and an admission
//! `minTier` outside `affirming` / `affirming-hw-rooted` is refused before verification.
use crate::agent::{sign_artifact, KeyPair, Suite};
use crate::attest::der::tbs_of_certificate;
use crate::attest::snp::{self, SnpReport};
use crate::attest::util::{b64_std, b64url_enc, hex_lower, sha384};
use crate::attest::x509::{ecdsa_verify_raw, pem_blocks, pem_to_der, Cert, EcCurve, PubKey};
use crate::caveat_lang::{discharge_shape_error, DISCHARGE_DOMAIN};
use crate::intent_v2::js_value_string;
use crate::jose::{assert_canonical_compact_jws, verify_jws_signature, JwkKey};
use crate::sigstore::{verify_sigstore_bundle, PinnedRoots};
use crate::{js_stringify, provenance_gate};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub use crate::attest_eat_pqcosign::*;

pub const EAT_TYP: &str = "eat+jwt";
pub const DEFAULT_EAT_ALG: &str = "EdDSA";
pub const SUPPORTED_ALGS: [&str; 2] = ["EdDSA", "ES256"];
pub const DEFAULT_MAX_AGE_MS: f64 = 300_000.0;
pub const CHANNEL_BINDING_DOMAIN: &str = "atlas-pca/eat-channel/v1";
pub const AMD_SEV_SNP_SIGNED_REGION_END: u64 = 0x2a0;
pub const AMD_SEV_SNP_HARDWARE_ROOT_LABEL: &str = "amd-sev-snp/ecdsa-p384 (VCEK\u{2192}ASK\u{2192}ARK; classical hardware root, not post-quantum)";
pub const KNOWN_REPORT_VERSIONS: [u32; 3] = [2, 3, 5];
const MAX_EAT_BYTES: usize = 1 << 20;
const DBGSTAT_VALUES: [&str; 5] = ["enabled", "disabled", "disabled-since-boot", "disabled-permanently", "disabled-fully-and-permanently"];
const FULL_REPORT_MIN_LEN: usize = 0x2e8 + 72;
const REPORT_LEN: usize = 0x4a0;

/// The AMD ARK pins by family, as the reference exports them (`KNOWN_AMD_ARK_SPKI_SHA384`).
pub fn known_amd_ark_spki_sha384() -> Value {
    json!({"milan": snp::ark_pin("milan"), "genoa": snp::ark_pin("genoa"), "turin": snp::ark_pin("turin")})
}

/// The reference's exported constants, as one object (the differential corpus compares it).
pub fn constants() -> Value {
    json!({
        "EAT_TYP": EAT_TYP, "DEFAULT_EAT_ALG": DEFAULT_EAT_ALG, "DEFAULT_MAX_AGE_MS": 300000, "CHANNEL_BINDING_DOMAIN": CHANNEL_BINDING_DOMAIN,
        "AMD_SEV_SNP_SIGNED_REGION_END": 672, "AMD_SEV_SNP_HARDWARE_ROOT_LABEL": AMD_SEV_SNP_HARDWARE_ROOT_LABEL,
        "KNOWN_REPORT_VERSIONS": KNOWN_REPORT_VERSIONS, "KNOWN_AMD_ARK_SPKI_SHA384": known_amd_ark_spki_sha384(),
        "AMD_MILAN_ARK_SPKI_SHA384": snp::ark_pin("milan"), "PQCOSIGN_DOMAIN": PQCOSIGN_DOMAIN, "DEFAULT_PQ_COSIGN_SUITE": DEFAULT_PQ_COSIGN_SUITE,
        "PQ_COSIGN_SUITES": PQ_COSIGN_SUITES,
    })
}

// ---- JavaScript value helpers --------------------------------------------------------------------------------------------

/// A JavaScript value: `None` is `undefined`.
pub(crate) type U<'a> = Option<&'a Value>;

/// `o.k`: the member (`None` when absent, or when `o` is a value without members); a TypeError on `null` / `undefined`.
pub(crate) fn g<'a>(o: U<'a>, k: &str) -> Result<U<'a>, String> {
    match o {
        None => Err(format!("Cannot read properties of undefined (reading '{k}')")),
        Some(Value::Null) => Err(format!("Cannot read properties of null (reading '{k}')")),
        Some(Value::Object(m)) => Ok(m.get(k)),
        Some(_) => Ok(None),
    }
}

/// `typeof v === 'string'`.
pub(crate) fn as_str<'a>(v: U<'a>) -> Option<&'a str> {
    match v {
        Some(Value::String(s)) => Some(s),
        _ => None,
    }
}

/// `typeof v === 'number' && Number.isFinite(v)`.
pub(crate) fn fin(v: U) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64().filter(|f| f.is_finite()),
        _ => None,
    }
}

pub(crate) fn is_num(v: U) -> bool {
    matches!(v, Some(Value::Number(_)))
}

pub(crate) fn is_record(v: U) -> bool {
    matches!(v, Some(Value::Object(_)))
}

/// JavaScript truthiness.
pub(crate) fn truthy(v: U) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// `String(v)`.
pub(crate) fn js_string(v: U) -> String {
    match v {
        None => "undefined".into(),
        Some(x) => js_value_string(x),
    }
}

/// `a === b` for JSON values (containers compare by identity: never equal here).
pub(crate) fn strict_eq(a: U, b: U) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::Null), Some(Value::Null)) => true,
        (Some(Value::Bool(p)), Some(Value::Bool(q))) => p == q,
        (Some(Value::Number(p)), Some(Value::Number(q))) => p.as_f64() == q.as_f64(),
        (Some(Value::String(p)), Some(Value::String(q))) => p == q,
        _ => false,
    }
}

fn str_is(v: U, s: &str) -> bool {
    as_str(v) == Some(s)
}

/// `Array.prototype.includes` over the elements of an array value (SameValueZero ~ strict equality over JSON scalars).
fn includes(list: U, v: U) -> bool {
    match list {
        Some(Value::Array(a)) => a.iter().any(|x| strict_eq(Some(x), v)),
        _ => false,
    }
}

/// `typeof v === 'string' && v.length > 0` and constant-time equality, as `strEq` (a non-string throws, as `Buffer.from` does).
pub(crate) fn ct_eq(a: U, b: &str) -> Result<bool, String> {
    match a {
        Some(Value::String(s)) => Ok(s.len() == b.len() && crate::attest::util::timing_safe_eq(s.as_bytes(), b.as_bytes())),
        _ => Err("The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object.".into()),
    }
}

/// A JSON number from a double (an integral value as an integer).
pub(crate) fn jnum(f: f64) -> Value {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.0e15 {
        json!(f as i64)
    } else {
        serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null)
    }
}

pub(crate) fn clock_ms() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as f64).unwrap_or(0.0)
}

/// `{"$bytes": b64url}` -> bytes (the JSON surface's binary form).
pub fn bytes_of(v: U) -> Option<Vec<u8>> {
    let m = match v {
        Some(Value::Object(m)) if m.len() == 1 => m,
        _ => return None,
    };
    crate::decode_b64u_strict(m.get("$bytes")?.as_str()?, None)
}

/// The JSON form of bytes (`{"$bytes": b64url}`).
pub fn bytes_value(b: &[u8]) -> Value {
    json!({ "$bytes": b64url_enc(b) })
}

fn sha256_b64u(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    b64url_enc(&h.finalize())
}

fn js_trim(s: &str) -> &str {
    let ws = |c: char| {
        matches!(
            c,
            '\u{9}' | '\u{a}' | '\u{b}' | '\u{c}' | '\u{d}' | '\u{20}' | '\u{a0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
        )
    };
    s.trim_matches(ws)
}

// ---- evidence projection ----------------------------------------------------------------------------------------------------

/// The JSON-safe SEV-SNP evidence of a parsed report (`version` is the report's format version).
pub fn evidence_from_report(version: u32, r: &SnpReport) -> Value {
    json!({"version": version, "measurement": hex_lower(&r.measurement), "reported_tcb": r.reported_tcb.to_string(), "guest_svn": r.guest_svn,
           "chip_id": hex_lower(&r.chip_id), "debug": r.policy & (1u64 << 19) != 0})
}

/// The measured identity of a report: runtime_measurement = hex(MEASUREMENT), operator = hex(CHIP_ID); no weights field.
pub fn measured_from_report(r: &SnpReport) -> Value {
    json!({"model_id": "", "weights_digest": "", "weights_measured": false, "runtime_measurement": hex_lower(&r.measurement), "operator": hex_lower(&r.chip_id)})
}

fn u32le(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64le(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8).map(|s| {
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        u64::from_le_bytes(a)
    })
}

/// `parseReportTolerant`: the report across format versions, degrading to the version-stable header instead of failing.
/// Returns the result object (`ok`, `version`, `known`, `degraded`, `notes`, `evidence?`) and the full parse when there is one.
/// `None` is an input that is not a byte string.
pub fn parse_report_tolerant(raw: Option<&[u8]>) -> (Value, Option<SnpReport>) {
    let Some(b) = raw else {
        return (json!({"ok": false, "version": 0, "known": false, "degraded": true, "notes": ["input is not a Uint8Array"]}), None);
    };
    let Some(version) = u32le(b, 0) else {
        return (json!({"ok": false, "version": 0, "known": false, "degraded": true, "notes": ["buffer too short to read the report version"]}), None);
    };
    let known = KNOWN_REPORT_VERSIONS.contains(&version);
    let mut notes: Vec<String> = vec![];
    if known && b.len() >= FULL_REPORT_MIN_LEN {
        match snp::parse_report(b) {
            Ok(r) => {
                let ev = evidence_from_report(version, &r);
                return (json!({"ok": true, "version": version, "known": true, "degraded": false, "notes": notes, "evidence": ev}), Some(r));
            }
            Err(e) => notes.push(format!("full parse failed, falling back to the stable header: {e}")),
        }
    } else if !known {
        notes.push(format!(
            "unknown report version {version} \u{2014} parsing version-stable header fields only (newer firmware, e.g. GCP 2025-10-27, may relocate version-specific fields)"
        ));
    } else {
        notes.push(format!("buffer length {} < full report {} \u{2014} degraded header-only parse", b.len(), FULL_REPORT_MIN_LEN));
    }
    let Some(m) = b.get(0x090..0x090 + 48) else {
        notes.push("buffer too short to read the launch measurement".into());
        return (json!({"ok": false, "version": version, "known": known, "degraded": true, "notes": notes}), None);
    };
    let mut ev = Map::new();
    ev.insert("version".into(), json!(version));
    ev.insert("measurement".into(), json!(hex_lower(m)));
    ev.insert("degraded".into(), json!(true));
    if let Some(s) = u32le(b, 0x004) {
        ev.insert("guest_svn".into(), json!(s));
    }
    if let Some(p) = u64le(b, 0x008) {
        ev.insert("debug".into(), json!(p & (1u64 << 19) != 0));
    }
    if let Some(t) = u64le(b, 0x180) {
        ev.insert("reported_tcb".into(), json!(t.to_string()));
    }
    if let Some(c) = b.get(0x1a0..0x1a0 + 64) {
        ev.insert("chip_id".into(), json!(hex_lower(c)));
    }
    (json!({"ok": true, "version": version, "known": known, "degraded": true, "notes": notes, "evidence": Value::Object(ev)}), None)
}

// ---- channel binding -----------------------------------------------------------------------------------------------------------

/// `cnf.tls_exporter` = `b64u(sha256(DOMAIN || channelId))` (RA-TLS), plus `jkt` when a thumbprint is given.
pub fn derive_channel_cnf(channel_id: U, holder_key_thumbprint: U) -> Result<Value, String> {
    let id = match as_str(channel_id) {
        Some(s) if !s.is_empty() => s,
        _ => return Err("deriveChannelCnf: channelId is required".into()),
    };
    let mut cnf = Map::new();
    cnf.insert("tls_exporter".into(), json!(sha256_b64u(&[CHANNEL_BINDING_DOMAIN.as_bytes(), id.as_bytes()])));
    if let Some(t) = as_str(holder_key_thumbprint).filter(|t| !t.is_empty()) {
        cnf.insert("jkt".into(), json!(t));
    }
    Ok(Value::Object(cnf))
}

/// Bind evidence to a TLS channel id and a per-session freshness nonce (the inputs of [`build_eat`]).
pub fn bind_channel(evidence: U, channel_id: U, nonce: U) -> Result<Value, String> {
    if !as_str(nonce).is_some_and(|n| !n.is_empty()) {
        return Err("bindChannel: a per-session nonce is required for freshness".into());
    }
    let mut m = Map::new();
    if let Some(e) = evidence {
        m.insert("evidence".into(), e.clone());
    }
    m.insert("nonce".into(), nonce.cloned().unwrap_or(Value::Null));
    m.insert("cnf".into(), derive_channel_cnf(channel_id, None)?);
    Ok(Value::Object(m))
}

// ---- build / verify ------------------------------------------------------------------------------------------------------------

fn resolve_cnf(args: &Value) -> Result<Map<String, Value>, String> {
    let mut out = Map::new();
    if let Some(id) = g(Some(args), "channelId")? {
        if let Some(t) = derive_channel_cnf(Some(id), None)?.get("tls_exporter") {
            out.insert("tls_exporter".into(), t.clone());
        }
    }
    if let Some(cb) = g(Some(args), "channelBinding")? {
        if let Some(te) = as_str(g(Some(cb), "tls_exporter")?) {
            out.insert("tls_exporter".into(), json!(te));
        }
        if let Some(j) = as_str(g(Some(cb), "jkt")?) {
            out.insert("jkt".into(), json!(j));
        }
    }
    Ok(out)
}

/// A signed EAT (compact JWS, typ `eat+jwt`) over the evidence: `iss`, `iat`, `eat_nonce`, `cnf` and the optional measured identity /
/// sevsnp evidence / measurements / ueid / sueid / dbgstat / oemid claims. It needs a nonce AND a channel binding (an unbound EAT
/// would re-open the replay gap). `seed` is the 32-byte Ed25519 seed of an EdDSA token (ES256 signing is not provided).
pub fn build_eat(args: &Value, seed: Option<&[u8; 32]>) -> Result<String, String> {
    let a = Some(args);
    let issuer = g(a, "issuer")?;
    let nonce = g(a, "nonce")?;
    if !as_str(issuer).is_some_and(|s| !s.is_empty()) {
        return Err("buildEAT: issuer is required".into());
    }
    if !as_str(nonce).is_some_and(|s| !s.is_empty()) {
        return Err("buildEAT: nonce (eat_nonce) is required for freshness".into());
    }
    let alg_v = g(a, "alg")?.filter(|v| !v.is_null());
    let alg = match alg_v {
        None => DEFAULT_EAT_ALG,
        Some(Value::String(s)) if SUPPORTED_ALGS.contains(&s.as_str()) => s.as_str(),
        Some(v) => return Err(format!("buildEAT: unsupported alg '{}'", js_value_string(v))),
    };
    let cnf = resolve_cnf(args)?;
    if !cnf.contains_key("tls_exporter") && !cnf.contains_key("jkt") {
        return Err("buildEAT: a channel binding (channelId or channelBinding with a TLS exporter / holder-key thumbprint) is required (RA-TLS) \u{2014} refusing to emit unbound evidence".into());
    }
    let iat_ms = fin(g(a, "now")?).unwrap_or_else(clock_ms);
    let mut claims = Map::new();
    claims.insert("iss".into(), issuer.cloned().unwrap_or(Value::Null));
    claims.insert("iat".into(), jnum((iat_ms / 1000.0).floor()));
    claims.insert("eat_nonce".into(), nonce.cloned().unwrap_or(Value::Null));
    claims.insert("cnf".into(), Value::Object(cnf));
    for k in ["ueid", "sueid", "oemid", "dbgstat", "measurements", "measured", "sevsnp"] {
        if let Some(v) = g(a, k)? {
            claims.insert(k.into(), v.clone());
        }
    }
    let header = json!({"alg": alg, "typ": EAT_TYP});
    let input = format!("{}.{}", b64url_enc(js_stringify(&header).as_bytes()), b64url_enc(js_stringify(&Value::Object(claims)).as_bytes()));
    if alg != "EdDSA" {
        return Err("an ES256 token is signed with a P-256 key (this build signs EdDSA only)".into());
    }
    let seed = seed.ok_or("an EdDSA token is signed with an Ed25519 key")?;
    use ed25519_dalek::Signer;
    let sig = ed25519_dalek::SigningKey::from_bytes(seed).sign(input.as_bytes());
    Ok(format!("{input}.{}", b64url_enc(&sig.to_bytes())))
}

fn normalize_typ(t: &str) -> String {
    let l = t.to_lowercase();
    if l.contains('/') {
        l
    } else {
        format!("application/{l}")
    }
}

fn parse_cnf(v: U) -> Option<Value> {
    let Some(Value::Object(m)) = v else { return None };
    let mut out = Map::new();
    for k in ["tls_exporter", "jkt"] {
        if let Some(Value::String(s)) = m.get(k) {
            out.insert(k.into(), json!(s));
        }
    }
    (!out.is_empty()).then_some(Value::Object(out))
}

fn parse_measurements(v: U) -> Option<Value> {
    let Some(Value::Array(a)) = v else { return None };
    let out: Vec<Value> = a
        .iter()
        .filter_map(|e| match (e.get("type"), e.get("value")) {
            (Some(Value::String(t)), Some(Value::String(x))) if e.is_object() => Some(json!({"type": t, "value": x})),
            _ => None,
        })
        .collect();
    (!out.is_empty()).then_some(Value::Array(out))
}

fn parse_tcb_version(v: U) -> Option<Value> {
    match v {
        Some(x @ Value::Number(_)) if fin(v).is_some() => Some(x.clone()),
        Some(x @ Value::String(_)) => Some(x.clone()),
        Some(Value::Object(m)) => {
            let mut o = Map::new();
            for k in ["bootloader", "tee", "snp", "microcode"] {
                if let Some(n @ Value::Number(_)) = m.get(k) {
                    o.insert(k.into(), n.clone());
                }
            }
            Some(Value::Object(o))
        }
        _ => None,
    }
}

fn parse_measured(v: U) -> Option<Value> {
    let Some(Value::Object(m)) = v else { return None };
    let mut out = Map::new();
    for k in ["model_id", "weights_digest", "runtime_measurement", "operator"] {
        match m.get(k) {
            Some(s @ Value::String(_)) => out.insert(k.into(), s.clone()),
            _ => return None,
        };
    }
    if let Some(b @ Value::Bool(_)) = m.get("weights_measured") {
        out.insert("weights_measured".into(), b.clone());
    }
    for k in ["system_prompt_digest", "tool_manifest_digest"] {
        if let Some(s @ Value::String(_)) = m.get(k) {
            out.insert(k.into(), s.clone());
        }
    }
    Some(Value::Object(out))
}

fn parse_sevsnp(v: U) -> Option<Value> {
    let Some(Value::Object(m)) = v else { return None };
    let (Some(ver @ Value::Number(_)), Some(meas @ Value::String(_))) = (m.get("version"), m.get("measurement")) else { return None };
    let mut out = Map::new();
    out.insert("version".into(), ver.clone());
    out.insert("measurement".into(), meas.clone());
    if let Some(t) = parse_tcb_version(m.get("reported_tcb")) {
        out.insert("reported_tcb".into(), t);
    }
    if let Some(n @ Value::Number(_)) = m.get("guest_svn") {
        out.insert("guest_svn".into(), n.clone());
    }
    if let Some(s @ Value::String(_)) = m.get("chip_id") {
        out.insert("chip_id".into(), s.clone());
    }
    for k in ["debug", "degraded"] {
        if let Some(b @ Value::Bool(_)) = m.get(k) {
            out.insert(k.into(), b.clone());
        }
    }
    Some(Value::Object(out))
}

/// Verify an EAT's signature and typ / iss and parse it into claims. Errs on an invalid signature, wrong key, failed iss / typ
/// check, unsupported alg, or a missing iss / iat. A claim of the wrong type is dropped, so a later check fails closed. This
/// proves AUTHENTICITY only: freshness, channel binding and appraisal are separate steps. `opts`: `issuer`, `algorithms`, `typ`,
/// `requireTyp`.
pub fn verify_eat(eat: U, key: &JwkKey, opts: U) -> Result<Value, String> {
    let empty = Value::Object(Map::new());
    let opts = Some(opts.unwrap_or(&empty));
    let Some(Value::String(_)) = eat else { return Err("EAT invalid: token is not a string".into()) };
    let jws = assert_canonical_compact_jws(eat.unwrap(), 3, MAX_EAT_BYTES, true).map_err(|e| format!("EAT invalid: {e}"))?;
    let header = &jws.header;
    let payload = jws.payload.as_ref().ok_or("EAT invalid: payload is not an object")?;
    let alg = match header.get("alg") {
        Some(Value::String(a)) if SUPPORTED_ALGS.contains(&a.as_str()) => a.as_str(),
        _ => return Err("EAT invalid: missing or unsupported `alg` header".into()),
    };
    let allowed = g(opts, "algorithms")?.filter(|v| !v.is_null());
    let alg_ok = match allowed {
        None => true,
        Some(Value::Array(a)) => a.iter().any(|x| x.as_str() == Some(alg)),
        Some(Value::String(s)) => s.contains(alg),
        Some(_) => return Err("allowed.includes is not a function".into()),
    };
    if !alg_ok {
        return Err(format!("EAT invalid: alg {alg} not in the allowed set"));
    }
    if g(opts, "requireTyp")? != Some(&Value::Bool(false)) {
        let want = g(opts, "typ")?.filter(|v| !v.is_null());
        let htyp = header.get("typ");
        let want_s = want.cloned().unwrap_or_else(|| json!(EAT_TYP));
        let Some(Value::String(t)) = htyp else {
            return Err(format!("EAT invalid: typ {} is not {}", js_string(htyp), js_value_string(&want_s)));
        };
        let Value::String(w) = &want_s else { return Err("typ.toLowerCase is not a function".into()) };
        if normalize_typ(t) != normalize_typ(w) {
            return Err(format!("EAT invalid: typ {t} is not {w}"));
        }
    }
    let signing_input = format!("{}.{}", jws.segments[0], jws.segments[1]);
    if !verify_jws_signature(alg, key, signing_input.as_bytes(), &jws.bytes[2]) {
        return Err("EAT invalid: signature does not verify".into());
    }
    let Some(Value::String(iss)) = payload.get("iss") else { return Err("EAT invalid: missing or non-string `iss`".into()) };
    let iat = payload.get("iat");
    if fin(iat).is_none() {
        return Err("EAT invalid: missing or non-numeric `iat`".into());
    }
    if let Some(want) = g(opts, "issuer")? {
        let ok = match want {
            Value::Array(a) => a.iter().any(|x| x.as_str() == Some(iss)),
            x => x.as_str() == Some(iss),
        };
        if !ok {
            return Err(format!("EAT invalid: iss {iss} is not an accepted issuer"));
        }
    }
    let mut c = Map::new();
    c.insert("iss".into(), json!(iss));
    c.insert("iat".into(), iat.cloned().unwrap_or(Value::Null));
    if let Some(s @ Value::String(_)) = payload.get("eat_nonce") {
        c.insert("eat_nonce".into(), s.clone());
    }
    if let Some(v) = parse_cnf(payload.get("cnf")) {
        c.insert("cnf".into(), v);
    }
    for k in ["ueid", "sueid"] {
        if let Some(s @ Value::String(_)) = payload.get(k) {
            c.insert(k.into(), s.clone());
        }
    }
    if let Some(v) = parse_measurements(payload.get("measurements")) {
        c.insert("measurements".into(), v);
    }
    if let Some(s @ Value::String(t)) = payload.get("dbgstat") {
        if DBGSTAT_VALUES.contains(&t.as_str()) {
            c.insert("dbgstat".into(), s.clone());
        }
    }
    if let Some(s @ Value::String(_)) = payload.get("oemid") {
        c.insert("oemid".into(), s.clone());
    }
    if let Some(v) = parse_measured(payload.get("measured")) {
        c.insert("measured".into(), v);
    }
    if let Some(v) = parse_sevsnp(payload.get("sevsnp")) {
        c.insert("sevsnp".into(), v);
    }
    Ok(Value::Object(c))
}

// ---- freshness + channel -------------------------------------------------------------------------------------------------------

fn check(ok: bool, reason: &str) -> Value {
    if ok {
        json!({"ok": true})
    } else {
        json!({"ok": false, "reason": reason})
    }
}

/// ANTI-REPLAY FRESHNESS: the `eat_nonce` must equal the server-issued challenge and `iat` must lie in `[now - maxAgeMs, now]`
/// (plus `clockSkewMs`). Absent / mismatched nonce, future iat or a stale token fail closed. `opts`: `expectedNonce`, `maxAgeMs`,
/// `now`, `clockSkewMs`. A present `clockSkewMs` that is not a finite number is refused (it would disable the age window).
pub fn verify_freshness(eat: U, opts: U) -> Result<Value, String> {
    let now = fin(g(opts, "now")?).unwrap_or_else(clock_ms);
    let skew_v = g(opts, "clockSkewMs")?;
    let skew = match skew_v {
        None => 0.0,
        Some(_) => match fin(skew_v) {
            Some(s) => s.max(0.0),
            None => return Ok(check(false, "invalid clockSkewMs (must be a finite number)")),
        },
    };
    let expected = g(opts, "expectedNonce")?;
    let Some(exp) = as_str(expected).filter(|s| !s.is_empty()) else {
        return Ok(check(false, "no expected (server-issued) nonce supplied (fail closed)"));
    };
    let Some(nonce) = as_str(g(eat, "eat_nonce")?).filter(|s| !s.is_empty()) else {
        return Ok(check(false, "EAT carries no eat_nonce \u{2014} cannot establish freshness (replayable)"));
    };
    if !crate::attest::util::timing_safe_eq(nonce.as_bytes(), exp.as_bytes()) {
        return Ok(check(false, "eat_nonce does not match the server-issued challenge (replayed or relayed evidence)"));
    }
    let Some(iat) = fin(g(eat, "iat")?) else { return Ok(check(false, "EAT has no valid iat (cannot establish age)")) };
    let max_age = match fin(g(opts, "maxAgeMs")?) {
        Some(m) if m > 0.0 => m,
        _ => return Ok(check(false, "invalid maxAgeMs")),
    };
    let iat_ms = iat * 1000.0;
    if !(now.is_finite() && iat_ms - skew <= now) {
        return Ok(check(false, "EAT iat is in the future"));
    }
    if !(now - iat_ms <= max_age + skew && (now - iat_ms).is_finite() && (max_age + skew).is_finite()) {
        return Ok(check(false, "EAT is stale (iat older than maxAgeMs) \u{2014} expired/replayed attestation"));
    }
    Ok(json!({"ok": true}))
}

/// CHANNEL BINDING (RA-TLS): every field of the expected cnf (derived from `channelId` and / or an explicit `expectedCnf`) must be
/// present and equal in the token's `cnf`. No cnf, or one bound to another channel / key, fails closed.
pub fn verify_channel_binding(eat: U, opts: U) -> Result<Value, String> {
    let mut exp_te: Option<String> = None;
    let mut exp_jkt: Option<String> = None;
    if let Some(id) = as_str(g(opts, "channelId")?).filter(|s| !s.is_empty()) {
        exp_te = derive_channel_cnf(Some(&json!(id)), None)?.get("tls_exporter").and_then(Value::as_str).map(String::from);
    }
    if let Some(e) = g(opts, "expectedCnf")? {
        if let Some(t) = as_str(g(Some(e), "tls_exporter")?) {
            exp_te = Some(t.to_string());
        }
        if let Some(j) = as_str(g(Some(e), "jkt")?) {
            exp_jkt = Some(j.to_string());
        }
    }
    if exp_te.is_none() && exp_jkt.is_none() {
        return Ok(check(false, "no expected channel binding supplied (fail closed)"));
    }
    let cnf = g(eat, "cnf")?;
    let (c_te, c_jkt) = if truthy(cnf) { (g(cnf, "tls_exporter")?, g(cnf, "jkt")?) } else { (None, None) };
    if c_te.is_none() && c_jkt.is_none() {
        return Ok(check(false, "EAT carries no channel/key binding (cnf) \u{2014} evidence is not bound to a live channel (RA-TLS)"));
    }
    if let Some(t) = &exp_te {
        if c_te.is_none() || !ct_eq(c_te, t)? {
            return Ok(check(false, "TLS-exporter channel binding mismatch (evidence lifted to another channel?)"));
        }
    }
    if let Some(j) = &exp_jkt {
        if c_jkt.is_none() || !ct_eq(c_jkt, j)? {
            return Ok(check(false, "holder-key thumbprint (cnf.jkt) mismatch"));
        }
    }
    Ok(json!({"ok": true}))
}

// ---- RATS appraisal ----------------------------------------------------------------------------------------------------------------

const TRUSTWORTHY: [&str; 3] = ["affirming-hw-rooted", "affirming", "warning"];

/// A TCB version as a comparable non-negative integer in decimal (leading zeros stripped), or `None` for an unknown shape (fail
/// closed): a number, a decimal string, or the structured SEV-SNP components. `null`, a boolean or an array is not a TCB version.
fn pack_tcb(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => {
            let f = n.as_f64()?;
            if !f.is_finite() || f < 0.0 {
                return None;
            }
            if let Some(u) = n.as_u64() {
                return Some(u.to_string());
            }
            let fl = f.floor();
            Some(if fl == 0.0 { "0".into() } else { format!("{fl:.0}") })
        }
        Value::String(s) => {
            let t = js_trim(s);
            (!t.is_empty() && t.bytes().all(|b| b.is_ascii_digit())).then(|| norm_dec(t))
        }
        Value::Object(m) => {
            let comp = |k: &str| -> Option<u128> {
                match m.get(k) {
                    None => Some(0),
                    Some(Value::Number(n)) => {
                        let f = n.as_f64()?;
                        (f.is_finite() && f.fract() == 0.0 && (0.0..=255.0).contains(&f) && !(f == 0.0 && f.is_sign_negative())).then_some(f as u128)
                    }
                    Some(_) => None,
                }
            };
            let (bl, tee, snp, uc) = (comp("bootloader")?, comp("tee")?, comp("snp")?, comp("microcode")?);
            Some((bl | (tee << 8) | (snp << 48) | (uc << 56)).to_string())
        }
        _ => None,
    }
}

fn norm_dec(s: &str) -> String {
    let t = s.trim_start_matches('0');
    if t.is_empty() {
        "0".into()
    } else {
        t.to_string()
    }
}

fn dec_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn lc(v: &Value) -> Result<String, String> {
    match v {
        Value::String(s) => Ok(s.to_lowercase()),
        _ => Err("s.toLowerCase is not a function".into()),
    }
}

fn lc_list(v: U) -> Result<Vec<String>, String> {
    match v {
        Some(Value::Array(a)) => a.iter().map(lc).collect(),
        _ => Ok(vec![]),
    }
}

fn nonempty(v: U) -> bool {
    matches!(v, Some(Value::Array(a)) if !a.is_empty())
}

/// `list?.find(pred)`: `undefined` for an absent list, a TypeError for a value without `find`.
fn find<'a>(list: U<'a>, pred: impl Fn(&'a Value) -> Result<bool, String>) -> Result<U<'a>, String> {
    match list {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(a)) => {
            for e in a {
                if pred(e)? {
                    return Ok(Some(e));
                }
            }
            Ok(None)
        }
        Some(_) => Err("eat.measurements?.find is not a function".into()),
    }
}

/// The launch measurement to appraise (the measured identity, else the sevsnp block, else a `launch` / `measurement` entry).
pub(crate) fn launch_measurement<'a>(eat: U<'a>) -> Result<U<'a>, String> {
    let measured = g(eat, "measured")?;
    if truthy(measured) {
        if let Some(rm @ Value::String(s)) = g(measured, "runtime_measurement")? {
            if !s.is_empty() {
                return Ok(Some(rm));
            }
        }
    }
    let sevsnp = g(eat, "sevsnp")?;
    if truthy(sevsnp) {
        let m = g(sevsnp, "measurement")?;
        if matches!(m, Some(Value::String(_))) {
            return Ok(m);
        }
    }
    let hit = find(g(eat, "measurements")?, |e| {
        let t = g(Some(e), "type")?;
        Ok(str_is(t, "launch") || str_is(t, "measurement"))
    })?;
    match hit {
        None => Ok(None),
        Some(h) => g(Some(h), "value"),
    }
}

fn weights_measurement<'a>(eat: U<'a>) -> Result<U<'a>, String> {
    let measured = g(eat, "measured")?;
    if truthy(measured) {
        if let Some(w @ Value::String(s)) = g(measured, "weights_digest")? {
            if !s.is_empty() {
                return Ok(Some(w));
            }
        }
    }
    let hit = find(g(eat, "measurements")?, |e| Ok(str_is(g(Some(e), "type")?, "weights")))?;
    match hit {
        None => Ok(None),
        Some(h) => g(Some(h), "value"),
    }
}

/// `Some(true)` / `Some(false)` when the debug status is known, else `None` (the caller fails closed). A present `dbgstat` that is
/// not an RFC 9711 value is unknown (never "disabled").
fn is_debug_disabled(eat: U) -> Result<Option<bool>, String> {
    let dbg = g(eat, "dbgstat")?;
    if let Some(d) = dbg {
        return Ok(match d {
            Value::String(s) if DBGSTAT_VALUES.contains(&s.as_str()) => Some(s != "enabled"),
            _ => None,
        });
    }
    let sevsnp = g(eat, "sevsnp")?;
    if truthy(sevsnp) {
        if let Some(Value::Bool(b)) = g(sevsnp, "debug")? {
            return Ok(Some(!*b));
        }
    }
    Ok(None)
}

fn appraisal(tier: &str, reasons: Vec<String>) -> Value {
    json!({"tier": tier, "trustworthy": TRUSTWORTHY.contains(&tier), "reasons": reasons})
}

/// APPRAISE an EAT's evidence against RATS reference values and endorsements (RFC 9334), kept as separate inputs. Tiers:
/// `affirming-hw-rooted` > `affirming` > `warning` (acceptable); `contraindicated` (the measured state is actively bad) and
/// `rejected` (empty policy, or a required input absent / in an unknown format) fail closed. Endorsements gate WHO (mismatch ->
/// rejected); reference values gate WHAT (bad -> contraindicated, absent -> rejected). An omitted argument defaults to `{}`; an
/// explicit `null` is dereferenced and errs, as in the reference.
pub fn appraise(evidence: U, reference_values: U, endorsements: U, extras: U) -> Result<Value, String> {
    let empty = Value::Object(Map::new());
    let rv = Some(reference_values.unwrap_or(&empty));
    let en = Some(endorsements.unwrap_or(&empty));
    let mut reasons: Vec<String> = vec![];
    macro_rules! done {
        ($tier:expr, $why:expr) => {{
            let mut r = reasons.clone();
            r.push($why.to_string());
            return Ok(appraisal($tier, r));
        }};
    }
    let (en_issuers, en_oemids, en_operators) = (g(en, "issuers")?, g(en, "oemids")?, g(en, "operators")?);
    let has_endorsements = nonempty(en_issuers) || nonempty(en_oemids) || nonempty(en_operators);
    let (rv_meas, rv_models, rv_weights) = (g(rv, "measurements")?, g(rv, "models")?, g(rv, "weightsMeasurements")?);
    let (rv_min_tcb, rv_min_svn) = (g(rv, "minTcb")?, g(rv, "minGuestSvn")?);
    let req_weights = g(rv, "requireMeasuredWeights")? == Some(&Value::Bool(true));
    let req_debug = g(rv, "requireDebugDisabled")? == Some(&Value::Bool(true));
    let has_reference =
        nonempty(rv_meas) || nonempty(rv_models) || nonempty(rv_weights) || req_weights || rv_min_tcb.is_some() || is_num(rv_min_svn) || req_debug;
    if !has_endorsements && !has_reference {
        return Ok(appraisal("rejected", vec!["empty appraisal policy: no endorsements or reference values to appraise against (fail closed)".into()]));
    }

    // Endorsements (WHO) -> rejected on mismatch.
    if nonempty(en_issuers) {
        let iss = g(evidence, "iss")?;
        if !includes(en_issuers, iss) {
            done!("rejected", format!("issuer {} is not an endorsed attester", js_string(iss)));
        }
        reasons.push("issuer endorsed".into());
    }
    if nonempty(en_oemids) {
        let oemid = g(evidence, "oemid")?;
        if as_str(oemid).is_none() || !includes(en_oemids, oemid) {
            done!("rejected", "oemid absent or not endorsed (fail closed)");
        }
        reasons.push("oemid endorsed".into());
    }
    if nonempty(en_operators) {
        let measured = g(evidence, "measured")?;
        let op = if matches!(measured, None | Some(Value::Null)) { None } else { g(measured, "operator")? };
        if !as_str(op).is_some_and(|s| !s.is_empty()) || !includes(en_operators, op) {
            done!("rejected", "hardware operator absent or not endorsed (fail closed)");
        }
        reasons.push("operator endorsed".into());
    }

    // Reference values (WHAT): bad value -> contraindicated; absent / unknown required -> rejected.
    if nonempty(rv_meas) {
        let Some(m) = launch_measurement(evidence)? else {
            done!("rejected", "no launch measurement in evidence to compare against reference values (fail closed)");
        };
        let lowered = lc_list(rv_meas)?;
        if !lowered.contains(&lc(m)?) {
            done!("contraindicated", "launch measurement not in reference values");
        }
        reasons.push("launch measurement matches a reference value".into());
    }
    if nonempty(rv_models) {
        let measured = g(evidence, "measured")?;
        let model = if matches!(measured, None | Some(Value::Null)) { None } else { g(measured, "model_id")? };
        if !as_str(model).is_some_and(|s| !s.is_empty()) {
            done!("rejected", "no model id in evidence (fail closed)");
        }
        if !includes(rv_models, model) {
            done!("contraindicated", "model id not in reference values (model swap?)");
        }
        reasons.push("model id matches a reference value".into());
    }
    if req_weights {
        let measured = g(evidence, "measured")?;
        let wm = if matches!(measured, None | Some(Value::Null)) { None } else { g(measured, "weights_measured")? };
        if wm != Some(&Value::Bool(true)) {
            done!("contraindicated", "weights digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)");
        }
        reasons.push("weights digest is hardware-measured".into());
    }
    if nonempty(rv_weights) {
        let w = weights_measurement(evidence)?;
        let empty_w = match w {
            None => true,
            Some(Value::String(s)) => s.is_empty(),
            Some(Value::Array(a)) => a.is_empty(),
            _ => false,
        };
        if empty_w {
            done!("rejected", "no measured-weights digest in evidence (fail closed)");
        }
        let lowered = lc_list(rv_weights)?;
        if !lowered.contains(&lc(w.unwrap())?) {
            done!("contraindicated", "weights measurement not in reference values (model swap / fine-tune?)");
        }
        reasons.push("weights measurement matches a reference value".into());
    }
    if let Some(min_v) = rv_min_tcb {
        let Some(minimum) = pack_tcb(min_v) else { done!("rejected", "reference minTcb is not a comparable TCB version") };
        let sevsnp = g(evidence, "sevsnp")?;
        let raw_tcb = if matches!(sevsnp, None | Some(Value::Null)) { None } else { g(sevsnp, "reported_tcb")? };
        let Some(got) = raw_tcb.and_then(pack_tcb) else {
            done!("rejected", "evidence TCB version is absent or an unknown format \u{2014} failing closed (see 2025-10-27 GCP firmware drift)");
        };
        if dec_cmp(&got, &minimum) == std::cmp::Ordering::Less {
            done!("contraindicated", "reported TCB is below the reference minimum (downgrade / rollback)");
        }
        reasons.push("TCB at or above reference minimum".into());
    }
    if is_num(rv_min_svn) {
        let sevsnp = g(evidence, "sevsnp")?;
        let svn_v = if matches!(sevsnp, None | Some(Value::Null)) { None } else { g(sevsnp, "guest_svn")? };
        let Some(svn) = fin(svn_v) else { done!("rejected", "guest_svn absent (fail closed)") };
        let min = rv_min_svn.and_then(|v| v.as_f64()).unwrap_or(f64::NAN);
        if svn < min {
            done!("contraindicated", format!("guest_svn {} below reference minimum {}", js_string(svn_v), js_string(rv_min_svn)));
        }
        reasons.push("guest_svn at or above reference minimum".into());
    }
    if req_debug {
        match is_debug_disabled(evidence)? {
            None => done!("rejected", "debug status unknown \u{2014} failing closed"),
            Some(false) => done!("contraindicated", "debug is enabled (host can inspect the guest \u{2014} no confidentiality)"),
            Some(true) => reasons.push("debug disabled".into()),
        }
    }

    // All checks passed: degraded evidence -> warning; a verified AMD signature -> the hardware-rooted tier.
    let sevsnp = g(evidence, "sevsnp")?;
    if !matches!(sevsnp, None | Some(Value::Null)) && g(sevsnp, "degraded")? == Some(&Value::Bool(true)) {
        done!("warning", "evidence came from a degraded (version-tolerant) parse \u{2014} review");
    }
    let ex = Some(extras.unwrap_or(&empty));
    if g(ex, "hardwareVerified")? == Some(&Value::Bool(true)) {
        let label = g(ex, "hardwareRootLabel")?.filter(|v| !v.is_null());
        let label = label.map_or_else(|| AMD_SEV_SNP_HARDWARE_ROOT_LABEL.to_string(), |v| js_value_string(v));
        done!("affirming-hw-rooted", format!("AMD SEV-SNP report signature + VCEK\u{2192}ASK\u{2192}ARK chain verified \u{2014} {label}"));
    }
    Ok(appraisal("affirming", reasons))
}

// ---- AMD hardware root ----------------------------------------------------------------------------------------------------------

/// A certificate input as DER: a `{"$bytes"}` object, or a PEM string holding exactly one certificate.
fn cert_to_der(v: U) -> Result<Vec<u8>, String> {
    if let Some(b) = bytes_of(v) {
        return Ok(b);
    }
    let Some(Value::String(s)) = v else {
        return Err("The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object.".into());
    };
    let blocks = pem_blocks(s);
    if blocks.len() != 1 {
        return Err(format!("expected exactly one PEM certificate, found {}", blocks.len()));
    }
    pem_to_der(blocks[0])
}

fn der_to_pem(der: &[u8]) -> String {
    let b64 = b64_std(der);
    let mut wrapped = String::new();
    for c in b64.as_bytes().chunks(64) {
        wrapped.push_str(std::str::from_utf8(c).unwrap_or(""));
        if c.len() == 64 {
            wrapped.push('\n');
        }
    }
    format!("-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n")
}

fn report_sig_valid(raw: &[u8], key: &PubKey) -> bool {
    let PubKey::Ec { curve: EcCurve::P384, point } = key else { return false };
    let (r, s) = (&raw[0x2a0..0x2a0 + 72], &raw[0x2e8..0x2e8 + 72]);
    if r[48..].iter().any(|x| *x != 0) || s[48..].iter().any(|x| *x != 0) {
        return false;
    }
    let mut rs = Vec::with_capacity(96);
    rs.extend(r[..48].iter().rev());
    rs.extend(s[..48].iter().rev());
    ecdsa_verify_raw(EcCurve::P384, point, &sha384(&raw[..0x2a0]), &rs)
}

/// `verifyGenuineSevSnpReport` with the policy `{measurements, allowDebug}` (the default SEV-SNP policy otherwise: ECDSA-P384
/// report signatures and VMPL 0): the reason on failure.
fn verify_genuine(
    raw: &[u8],
    vcek_der: &[u8],
    ask_ark: &str,
    pin: &str,
    now_ms: f64,
    skew: Option<f64>,
    measurements: &[String],
    allow_debug: bool,
) -> Result<SnpReport, String> {
    let report = snp::parse_report(raw).map_err(|e| format!("report parse failed: {e}"))?;
    if raw.len() != REPORT_LEN {
        return Err(format!("report length {} is not the canonical {}", raw.len(), REPORT_LEN));
    }
    if raw[0x2e8 + 72..].iter().any(|b| *b != 0) || raw[0x2a0 + 48..0x2a0 + 72].iter().any(|b| *b != 0) || raw[0x2e8 + 48..0x2e8 + 72].iter().any(|b| *b != 0) {
        return Err("report signature block has non-zero reserved bytes".into());
    }
    snp::baseb_verify_amd_cert_chain(vcek_der, ask_ark, pin, now_ms, skew).map_err(|e| format!("cert chain invalid: {e}"))?;
    let vcek = Cert::from_der(vcek_der).map_err(|e| format!("genuine verification error (fail closed): {e}"))?;
    let key = vcek.public_key().map_err(|e| format!("genuine verification error (fail closed): {e}"))?;
    if !report_sig_valid(raw, &key) {
        return Err("report signature does not verify under VCEK".into());
    }
    let tbs = tbs_of_certificate(vcek_der).map_err(|e| format!("genuine verification error (fail closed): {e}"))?;
    if let Some(e) = snp::check_vcek_report_binding(&tbs, &report) {
        return Err(e);
    }
    if report.signature_algo != 1 {
        return Err(format!("unexpected signature_algo {}", report.signature_algo));
    }
    if !allow_debug && report.policy & (1u64 << 19) != 0 {
        return Err("guest policy has the DEBUG bit set (host can inspect the guest)".into());
    }
    if report.vmpl != 0 {
        return Err(format!("vmpl {} is not the required 0", report.vmpl));
    }
    if !measurements.is_empty() && !measurements.iter().any(|m| m.to_lowercase() == hex_lower(&report.measurement)) {
        return Err("measurement not in policy allowlist".into());
    }
    Ok(report)
}

/// Compose the AMD SEV-SNP hardware root of trust into one verdict (per-family ARK pin, exact ASK-then-ARK bundle, validity against
/// the verifier clock `nowMs`, report signature, VCEK binding), then project the verified report into EAT evidence and a measured
/// identity. Fails closed on any failure and never errs. `raw_report` and DER certificates are `{"$bytes"}` objects (a PEM
/// certificate is a string). `opts`: `vcek`, `ask`, `ark`, exactly one of `family` (`milan` | `genoa` | `turin`) or
/// `trustAnchorArkSpkiSha384`, `nowMs`, `clockSkewMs`, `expectedMeasurement`, `allowDebug`. The result is
/// `{ok, reason?, hardwareRoot, evidence?, measured?}`.
pub fn verify_amd_attestation(raw_report: U, opts: U) -> Value {
    let root = AMD_SEV_SNP_HARDWARE_ROOT_LABEL;
    match amd_inner(raw_report, opts) {
        Ok(v) => v,
        Err(e) => json!({"ok": false, "reason": format!("AMD attestation verification error (fail closed): {e}"), "hardwareRoot": root}),
    }
}

fn amd_inner(raw_report: U, opts: U) -> Result<Value, String> {
    let root = AMD_SEV_SNP_HARDWARE_ROOT_LABEL;
    let fail = |reason: String| Ok(json!({"ok": false, "reason": reason, "hardwareRoot": root}));
    let family = g(opts, "family")?;
    let pin_v = g(opts, "trustAnchorArkSpkiSha384")?;
    if family.is_some() == pin_v.is_some() {
        return fail("exactly one of family or trustAnchorArkSpkiSha384 must be supplied (the ARK pin is never inferred)".into());
    }
    let pin: String = match family {
        Some(f) => match snp::ark_pin(&js_value_string(f)) {
            Some(p) => p.to_string(),
            None => return fail(format!("unknown AMD family {} (expected milan | genoa | turin)", js_value_string(f))),
        },
        None => match pin_v {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Null) => snp::ark_pin("milan").unwrap_or("").to_string(),
            _ => String::new(),
        },
    };
    let certs = (|| -> Result<(Vec<u8>, String), String> {
        let vcek = cert_to_der(g(opts, "vcek")?)?;
        let ask_ark = der_to_pem(&cert_to_der(g(opts, "ask")?)?) + &der_to_pem(&cert_to_der(g(opts, "ark")?)?);
        Ok((vcek, ask_ark))
    })();
    let (vcek_der, ask_ark) = match certs {
        Ok(c) => c,
        Err(e) => return fail(format!("certificate parse failed: {e}")),
    };
    let expected = g(opts, "expectedMeasurement")?;
    let measurements: Vec<String> = as_str(expected).filter(|s| !s.is_empty()).map(|s| vec![s.to_string()]).unwrap_or_default();
    let now_ms = fin(g(opts, "nowMs")?).unwrap_or(f64::NAN);
    let skew = match g(opts, "clockSkewMs")? {
        None | Some(Value::Null) => None,
        Some(v) => Some(fin(Some(v)).unwrap_or(f64::NAN)),
    };
    let allow_debug = g(opts, "allowDebug")? == Some(&Value::Bool(true));
    let raw = bytes_of(raw_report);
    let Some(raw) = raw else { return fail("report parse failed: parseSevSnpReport: expected Uint8Array".into()) };
    if !matches!(pin_v, None | Some(Value::String(_)) | Some(Value::Null)) {
        return fail("cert chain invalid: AMD chain verification error: the trust anchor pin is not a string".into());
    }
    match verify_genuine(&raw, &vcek_der, &ask_ark, &pin, now_ms, skew, &measurements, allow_debug) {
        Err(reason) => fail(reason),
        Ok(report) => {
            let version = u32le(&raw, 0).unwrap_or(0);
            Ok(json!({"ok": true, "hardwareRoot": root, "evidence": evidence_from_report(version, &report), "measured": measured_from_report(&report)}))
        }
    }
}

// ---- composition ---------------------------------------------------------------------------------------------------------------------

/// The end-to-end check a resource server runs: verify the EAT's signature, then FRESHNESS (nonce + iat), CHANNEL BINDING (cnf vs
/// the live channel) and APPRAISAL against the RATS policy. The first failing gate stops the pipeline and names the reason. With
/// `opts.amd` the AMD report signature and chain are verified here (success lifts the tier to `affirming-hw-rooted`, failure is
/// `contraindicated`). `key` is the attester's verification key; `opts`: nonce, channelId | channelBinding, policy, now, maxAgeMs,
/// clockSkewMs, issuer, algorithms, typ, requireTyp, amd (`rawReport`, `vcek`, `ask`, `ark`, `family` | `trustAnchorArkSpkiSha384`,
/// `clockSkewMs`, `allowDebug`, `expectedMeasurement`). Errs where the reference rejects with a thrown error.
pub fn verify_fresh_attested_eat(eat: U, key: &JwkKey, opts: U) -> Result<Value, String> {
    let mut reasons: Vec<String> = vec![];
    let mut vopts = Map::new();
    for k in ["issuer", "algorithms", "typ", "requireTyp"] {
        if let Some(v) = g(opts, k)? {
            vopts.insert(k.into(), v.clone());
        }
    }
    let vopts = Value::Object(vopts);
    let claims = match verify_eat(eat, key, Some(&vopts)) {
        Ok(c) => c,
        Err(e) => return Ok(json!({"ok": false, "reasons": [format!("EAT signature/claims invalid: {e}")]})),
    };
    reasons.push("signature + typ/iss verified".into());
    let now = fin(g(opts, "now")?).unwrap_or_else(clock_ms);
    let mut f = Map::new();
    if let Some(n) = g(opts, "nonce")? {
        f.insert("expectedNonce".into(), n.clone());
    }
    let max_age = g(opts, "maxAgeMs")?.filter(|v| !v.is_null()).cloned().unwrap_or_else(|| jnum(DEFAULT_MAX_AGE_MS));
    f.insert("maxAgeMs".into(), max_age);
    f.insert("now".into(), jnum(now));
    if let Some(s) = g(opts, "clockSkewMs")? {
        f.insert("clockSkewMs".into(), s.clone());
    }
    let fresh = verify_freshness(Some(&claims), Some(&Value::Object(f)))?;
    if fresh["ok"] != Value::Bool(true) {
        reasons.push(fresh.get("reason").and_then(Value::as_str).unwrap_or("not fresh").to_string());
        return Ok(json!({"ok": false, "reasons": reasons, "claims": claims}));
    }
    reasons.push("fresh (nonce + iat within window)".into());

    let mut c = Map::new();
    if let Some(id) = g(opts, "channelId")? {
        c.insert("channelId".into(), id.clone());
    }
    if let Some(cb) = g(opts, "channelBinding")? {
        c.insert("expectedCnf".into(), cb.clone());
    }
    let chan = verify_channel_binding(Some(&claims), Some(&Value::Object(c)))?;
    if chan["ok"] != Value::Bool(true) {
        reasons.push(chan.get("reason").and_then(Value::as_str).unwrap_or("channel binding failed").to_string());
        return Ok(json!({"ok": false, "reasons": reasons, "claims": claims}));
    }
    reasons.push("channel-bound (cnf matches live channel)".into());

    let mut extras = Map::new();
    if let Some(amd) = g(opts, "amd")? {
        let a = Some(amd);
        let expected: Option<Value> = match g(a, "expectedMeasurement")?.filter(|v| !v.is_null()) {
            Some(e) => Some(e.clone()),
            None => launch_measurement(Some(&claims))?.cloned(),
        };
        let mut ao = Map::new();
        for k in ["vcek", "ask", "ark"] {
            if let Some(v) = g(a, k)? {
                ao.insert(k.into(), v.clone());
            }
        }
        ao.insert("nowMs".into(), jnum(now));
        for k in ["family", "trustAnchorArkSpkiSha384", "clockSkewMs", "allowDebug"] {
            if let Some(v) = g(a, k)? {
                ao.insert(k.into(), v.clone());
            }
        }
        if let Some(e) = expected {
            ao.insert("expectedMeasurement".into(), e);
        }
        let hw = verify_amd_attestation(g(a, "rawReport")?, Some(&Value::Object(ao)));
        if hw["ok"] != Value::Bool(true) {
            let why = hw.get("reason").and_then(Value::as_str).unwrap_or("unknown");
            reasons.push(format!("AMD hardware root verification failed: {why}"));
            return Ok(json!({"ok": false, "tier": "contraindicated", "reasons": reasons, "claims": claims}));
        }
        let label = hw["hardwareRoot"].as_str().unwrap_or(AMD_SEV_SNP_HARDWARE_ROOT_LABEL).to_string();
        reasons.push(format!("AMD SEV-SNP hardware root verified ({label})"));
        extras.insert("hardwareVerified".into(), json!(true));
        extras.insert("hardwareRootLabel".into(), json!(label));
    }
    let policy = g(opts, "policy")?;
    let rvs = g(policy, "referenceValues")?.filter(|v| !v.is_null());
    let ens = g(policy, "endorsements")?.filter(|v| !v.is_null());
    let empty = Value::Object(Map::new());
    let app = appraise(Some(&claims), Some(rvs.unwrap_or(&empty)), Some(ens.unwrap_or(&empty)), Some(&Value::Object(extras)))?;
    let mut all = reasons;
    all.extend(app["reasons"].as_array().into_iter().flatten().filter_map(|r| r.as_str().map(String::from)));
    Ok(json!({"ok": app["trustworthy"], "tier": app["tier"], "reasons": all, "claims": claims}))
}

// ---- admission evidence + artifact discharge ----------------------------------------------------------------------------------------

/// RFC 7638 thumbprint (base64url SHA-256) of an Ed25519 public key given as unpadded base64url (any other value is spelled as
/// JavaScript would in the template).
pub fn ed25519_jkt(holder_pub_b64u: U) -> String {
    let canonical = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}", js_string(holder_pub_b64u));
    sha256_b64u(&[canonical.as_bytes()])
}

fn tier_rank(t: &str) -> i32 {
    match t {
        "affirming-hw-rooted" => 3,
        "affirming" => 2,
        "warning" => 1,
        _ => 0,
    }
}

fn error_name(e: &str) -> &'static str {
    if e.starts_with("Cannot read properties") || e.contains("is not a function") || e.starts_with("The first argument must be of type") {
        "TypeError"
    } else {
        "Error"
    }
}

/// EAT evidence for blueprint admission: the signature, issuer, freshness and RATS appraisal must all pass and `cnf.jkt` must be the
/// RFC 7638 thumbprint of THE INSTANCE KEY (`o.instanceKey`, unpadded base64url Ed25519), so evidence for one instance cannot admit
/// another. `o` carries the options of [`verify_fresh_attested_eat`] plus `minTier` (`affirming` by default; a degraded `warning`
/// token does not admit). Anything unverifiable is `{ok: false, bound: false}`; the identity returned is the measured identity the
/// verifier established.
pub fn eat_admission_evidence(eat: U, key: &JwkKey, o: U) -> Value {
    match admission_inner(eat, key, o) {
        Ok(v) => v,
        Err(e) => json!({"ok": false, "bound": false, "reason": error_name(&e)}),
    }
}

fn admission_inner(eat: U, key: &JwkKey, o: U) -> Result<Value, String> {
    let min_v = g(o, "minTier")?;
    if let Some(m) = min_v {
        if !matches!(m, Value::String(s) if s == "affirming" || s == "affirming-hw-rooted") {
            return Ok(json!({"ok": false, "bound": false, "reason": "invalid minTier"}));
        }
    }
    let min_tier = as_str(min_v).unwrap_or("affirming");
    let mut rest = match o {
        Some(Value::Object(m)) => m.clone(),
        _ => Map::new(),
    };
    rest.remove("instanceKey");
    rest.remove("minTier");
    rest.insert("channelBinding".into(), json!({"jkt": ed25519_jkt(g(o, "instanceKey")?)}));
    let v = verify_fresh_attested_eat(eat, key, Some(&Value::Object(rest)))?;
    if v["ok"] != Value::Bool(true) || v.get("tier").is_none() {
        let why = v["reasons"].as_array().and_then(|r| r.last()).and_then(Value::as_str).unwrap_or("EAT rejected").to_string();
        return Ok(json!({"ok": false, "bound": false, "reason": why}));
    }
    let tier = v["tier"].as_str().unwrap_or("");
    if tier_rank(tier) < tier_rank(min_tier) {
        return Ok(json!({"ok": false, "bound": true, "reason": format!("appraisal tier {tier} is below the minimum")}));
    }
    let m = g(Some(&v["claims"]), "measured")?;
    match m {
        None | Some(Value::Null) => Ok(json!({"ok": true, "bound": true})),
        Some(m) => {
            let f = |k: &str| m.get(k).cloned().unwrap_or(Value::Null);
            Ok(json!({"ok": true, "bound": true, "identity": {"runtime_measurement": f("runtime_measurement"), "model_id": f("model_id"),
                "weights_digest": f("weights_digest"), "operator": f("operator")}}))
        }
    }
}

/// The running image's digest from an ACCEPTED verdict of [`verify_fresh_attested_eat`]: exactly one `measurements` entry labelled
/// `o.slot` (default `image`), lowercase hex of the algorithm's length (`o.alg` default `sha256`: 64, else 128). `null` when the
/// verdict is not ok, the slot is missing or repeated, or the value is malformed (no case folding).
pub fn runtime_digest_from_eat(verdict: U, o: U) -> Result<Value, String> {
    let empty = Value::Object(Map::new());
    let o = Some(o.unwrap_or(&empty));
    if !truthy(verdict) || g(verdict, "ok")? != Some(&Value::Bool(true)) {
        return Ok(Value::Null);
    }
    let claims = g(verdict, "claims")?;
    if !truthy(claims) {
        return Ok(Value::Null);
    }
    let slot_v = g(o, "slot")?.filter(|v| !v.is_null());
    let alg_v = g(o, "alg")?.filter(|v| !v.is_null());
    let default_slot = json!("image");
    let default_alg = json!("sha256");
    let (slot, alg) = (slot_v.unwrap_or(&default_slot), alg_v.unwrap_or(&default_alg));
    let ms = g(claims, "measurements")?.filter(|v| !v.is_null());
    let list: Vec<&Value> = match ms {
        None => vec![],
        Some(Value::Array(a)) => a.iter().collect(),
        Some(_) => return Err("(verdict.claims.measurements ?? []).filter is not a function".into()),
    };
    let mut hits: Vec<&Value> = vec![];
    for m in list {
        if strict_eq(g(Some(m), "type")?, Some(slot)) {
            hits.push(m);
        }
    }
    if hits.len() != 1 {
        return Ok(Value::Null);
    }
    let want = if strict_eq(Some(alg), Some(&default_alg)) { 64 } else { 128 };
    match g(Some(hits[0]), "value")? {
        Some(Value::String(s)) if s.len() == want && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) => Ok(json!({"alg": alg, "digest": s})),
        _ => Ok(Value::Null),
    }
}

/// For one discharge request: (1) the Sigstore bundle against the pinned `roots`, (2) the join with the running image digest
/// (`i.runtime`, from [`runtime_digest_from_eat`]; an explicit `null` is a failed join), (3) the provenance gate (the verifier's own
/// pins, `i.policy`), (4) sign the discharge with the gate's claims under the Ed25519 `issuer_seed` of the `artifact`-class key.
/// Returns `{ok: true, discharge, facts, level}` or `{ok: false, stage: "sigstore" | "gate", code, detail?}`; Errs on a malformed
/// signing input. `i`: bundle, policy, runtime?, request, now (epoch ms), ttl_ms?, nonce? (default: 16 random bytes).
pub fn issue_artifact_discharge(i: &Value, roots: &PinnedRoots, issuer_seed: &[u8; 32]) -> Result<Value, String> {
    let ip = Some(i);
    let null = Value::Null;
    let facts = match verify_sigstore_bundle(g(ip, "bundle")?.unwrap_or(&null), roots) {
        Ok(f) => f,
        Err(e) => return Ok(json!({"ok": false, "stage": "sigstore", "code": e.code, "detail": e.detail})),
    };
    let runtime = g(ip, "runtime")?;
    if runtime == Some(&Value::Null) {
        return Ok(json!({"ok": false, "stage": "gate", "code": "no_runtime"}));
    }
    let now_v = g(ip, "now")?;
    let now_s = match fin(now_v) {
        Some(n) => jnum((n / 1000.0).floor()),
        None => Value::Null,
    };
    let mut gi = Map::new();
    gi.insert("facts".into(), facts.clone());
    if let Some(p) = g(ip, "policy")? {
        gi.insert("policy".into(), p.clone());
    }
    if let Some(r) = runtime {
        gi.insert("runtime".into(), r.clone());
    }
    gi.insert("now".into(), now_s);
    let gate = match provenance_gate(&Value::Object(gi)) {
        Ok(ok) => ok,
        Err(code) => return Ok(json!({"ok": false, "stage": "gate", "code": code})),
    };
    let request = g(ip, "request")?;
    let ttl_v = g(ip, "ttl_ms")?.filter(|v| !v.is_null());
    let req_ttl = g(request, "ttl_ms")?;
    let ttl = ttl_v.or(req_ttl);
    let nonce = match g(ip, "nonce")?.filter(|v| !v.is_null()) {
        Some(n) => n.clone(),
        None => {
            let mut b = [0u8; 16];
            getrandom::getrandom(&mut b).map_err(|e| e.to_string())?;
            json!(b64url_enc(&b))
        }
    };
    let (Some(ttl_n), Some(iat)) = (fin(ttl), fin(now_v)) else { return Err("provenanceDischargeBody: ttl_ms and iat must be numbers".into()) };
    if let Some(r) = req_ttl {
        match fin(Some(r)) {
            Some(rt) if ttl_n <= rt => {}
            _ => return Err("provenanceDischargeBody: ttl_ms exceeds what the caveat accepts".into()),
        }
    }
    let mut body = Map::new();
    body.insert("v".into(), json!(1));
    body.insert("kind".into(), json!("pca-discharge"));
    for k in ["caveat_id", "issuer", "cap_hash", "bind", "action_digest"] {
        if let Some(v) = g(request, k)? {
            body.insert(k.into(), v.clone());
        }
    }
    body.insert("claims".into(), Value::Object(gate.claims.clone()));
    body.insert("iat".into(), now_v.cloned().unwrap_or(Value::Null));
    body.insert("not_after".into(), jnum(iat + ttl_n));
    body.insert("nonce".into(), nonce);
    let kp = KeyPair::from_seed(issuer_seed);
    let discharge = sign_artifact(DISCHARGE_DOMAIN, &Value::Object(body), &kp, &Suite::default())?;
    if let Some(e) = discharge_shape_error(&discharge) {
        return Err(format!("signDischarge: {e}"));
    }
    Ok(json!({"ok": true, "discharge": discharge, "facts": facts, "level": gate.level}))
}

#[cfg(test)]
mod duplicate_member_tests {
    use super::*;
    use ed25519_dalek::Signer;

    // a compact JWS built from raw header and payload text (so a duplicate member survives), signed with a key generated per run
    fn token(header: &str, payload: &str, sk: &ed25519_dalek::SigningKey) -> String {
        let input = format!("{}.{}", crate::b64_encode(header.as_bytes()), crate::b64_encode(payload.as_bytes()));
        format!("{input}.{}", crate::b64_encode(&sk.sign(input.as_bytes()).to_bytes()))
    }

    #[test]
    fn a_duplicate_header_or_payload_member_is_refused() {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let key = JwkKey::Ed25519(sk.verifying_key().to_bytes());
        let header = format!(r#"{{"alg":"EdDSA","typ":"{EAT_TYP}"}}"#);
        let verify = |h: &str, p: &str| verify_eat(Some(&json!(token(h, p, &sk))), &key, None);
        assert_eq!(verify(&header, r#"{"iss":"a","iat":1}"#).unwrap()["iss"], json!("a"));
        let dup_payload = verify(&header, r#"{"iss":"a","iss":"b","iat":1}"#).unwrap_err();
        assert!(dup_payload.starts_with("EAT invalid:") && dup_payload.contains(r#"duplicate key "iss""#), "{dup_payload}");
        let dup_header = verify(&format!(r#"{{"alg":"EdDSA","alg":"none","typ":"{EAT_TYP}"}}"#), r#"{"iss":"a","iat":1}"#).unwrap_err();
        assert!(dup_header.starts_with("EAT invalid:") && dup_header.contains(r#"duplicate key "alg""#), "{dup_header}");
    }
}
