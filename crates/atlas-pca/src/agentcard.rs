//! Signed A2A Agent Cards and AgentFacts attested by PCA: build a card that points at the PCA passport, sign it with a
//! detached JWS (the A2A `AgentCardSignature`, RFC 8785 JCS payload; RFC 7797 unencoded payload, or the A2A 1.0 standard
//! profile), verify it against a key or a JWK Set, issue and verify AgentFacts attestations, the well-known hosting handlers
//! and the registry entry.
//!
//! Keys are JWK objects (signing: an Ed25519 OKP JWK with `d`; other algorithms are refused). Verification follows the JOSE
//! library the reference uses: a JWK Set selects one key (kid / kty / alg / use / key_ops), a single JWK is imported for
//! `alg` (default EdDSA), and any failure of a signature is a refusal value, never an error. Times are epoch milliseconds
//! and ISO 8601 strings (date-only or with `Z` / an offset).
use crate::agent::KeyPair;
use crate::intent_v2::js_number_string;
use crate::jose;
use crate::oauth::truthy;
use crate::oidc::{KeyResolver, LocalJwkSet};
use crate::{b64_encode, decode_b64u_strict, js_stringify};
use serde_json::{json, Map, Value};

pub const DEFAULT_ALG: &str = "EdDSA";
pub const AGENT_FACTS_CONTEXT: [&str; 2] = ["https://www.w3.org/ns/did/v1", "https://nanda.ai/agentfacts/v1"];
pub const PCA_ATTESTOR_ID: &str = "did:atlas:pca-attestor";
pub const WELL_KNOWN_AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";
pub const WELL_KNOWN_AGENT_FACTS_PATH: &str = "/.well-known/agent-facts.json";
const PCA_PASSPORT_HEADER: &str = "pca_passport";
const MAX_JCS_DEPTH: usize = 64;

pub fn constants() -> Value {
    json!({ "DEFAULT_ALG": DEFAULT_ALG, "AGENT_FACTS_CONTEXT": AGENT_FACTS_CONTEXT, "PCA_ATTESTOR_ID": PCA_ATTESTOR_ID,
        "WELL_KNOWN_AGENT_CARD_PATH": WELL_KNOWN_AGENT_CARD_PATH, "WELL_KNOWN_AGENT_FACTS_PATH": WELL_KNOWN_AGENT_FACTS_PATH })
}

// ---- JCS (RFC 8785) and the A2A 1.0 schema ----------------------------------------------------------------------------

fn jcs(v: &Value, depth: usize, out: &mut String) -> Result<(), String> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&js_number_string(n.as_f64().unwrap_or(0.0))),
        Value::String(s) => out.push_str(&serde_json::to_string(s).unwrap()),
        Value::Array(a) => {
            if depth > MAX_JCS_DEPTH {
                return Err("jcs: nesting too deep".into());
            }
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs(x, depth + 1, out)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            if depth > MAX_JCS_DEPTH {
                return Err("jcs: nesting too deep".into());
            }
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16())); // default sort: UTF-16 code units
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap());
                out.push(':');
                jcs(&m[k.as_str()], depth + 1, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// RFC 8785 canonical JSON bytes (keys in UTF-16 code unit order, ECMAScript number text, nesting <= 64).
pub fn jcs_bytes(v: &Value) -> Result<Vec<u8>, String> {
    let mut s = String::new();
    jcs(v, 1, &mut s)?;
    Ok(s.into_bytes())
}

/// The A2A 1.0 Agent Card schema problems (`[]` = conforms).
pub fn validate_agent_card1(card: &Value) -> Vec<String> {
    let Some(card) = card.as_object() else { return vec!["$: the agent card must be an object".into()] };
    let mut p: Vec<String> = Vec::new();
    fn req_str(p: &mut Vec<String>, o: &Map<String, Value>, k: &str, at: &str) {
        if !o.get(k).and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
            p.push(format!("{at}.{k}: required non-empty string"));
        }
    }
    fn opt_str(p: &mut Vec<String>, o: &Map<String, Value>, k: &str, at: &str) {
        if o.get(k).is_some_and(|v| !v.is_string()) {
            p.push(format!("{at}.{k}: must be a string"));
        }
    }
    fn opt_bool(p: &mut Vec<String>, o: &Map<String, Value>, k: &str, at: &str) {
        if o.get(k).is_some_and(|v| !v.is_boolean()) {
            p.push(format!("{at}.{k}: must be a boolean"));
        }
    }
    fn str_array(p: &mut Vec<String>, v: &Value, at: &str, non_empty: bool) {
        match v.as_array() {
            Some(a) if a.iter().all(Value::is_string) => {
                if non_empty && a.is_empty() {
                    p.push(format!("{at}: must not be empty"));
                }
            }
            _ => p.push(format!("{at}: must be an array of strings")),
        }
    }
    fn obj_array(
        p: &mut Vec<String>,
        o: &Map<String, Value>,
        k: &str,
        at: &str,
        required: bool,
        non_empty: bool,
        each: &dyn Fn(&mut Vec<String>, &Map<String, Value>, &str),
    ) {
        let Some(v) = o.get(k) else {
            if required {
                p.push(format!("{at}.{k}: required array"));
            }
            return;
        };
        let Some(a) = v.as_array() else {
            p.push(format!("{at}.{k}: must be an array"));
            return;
        };
        if non_empty && a.is_empty() {
            p.push(format!("{at}.{k}: must not be empty"));
        }
        for (i, e) in a.iter().enumerate() {
            match e.as_object() {
                Some(m) => each(p, m, &format!("{at}.{k}[{i}]")),
                None => p.push(format!("{at}.{k}[{i}]: must be an object")),
            }
        }
    }
    req_str(&mut p, card, "name", "$");
    req_str(&mut p, card, "description", "$");
    req_str(&mut p, card, "version", "$");
    opt_str(&mut p, card, "documentationUrl", "$");
    opt_str(&mut p, card, "iconUrl", "$");
    obj_array(&mut p, card, "supportedInterfaces", "$", true, true, &|p, e, at| {
        req_str(p, e, "url", at);
        req_str(p, e, "protocolBinding", at);
        req_str(p, e, "protocolVersion", at);
        opt_str(p, e, "tenant", at);
    });
    if let Some(pr) = card.get("provider") {
        match pr.as_object() {
            None => p.push("$.provider: must be an object".into()),
            Some(m) => {
                req_str(&mut p, m, "url", "$.provider");
                req_str(&mut p, m, "organization", "$.provider");
            }
        }
    }
    match card.get("capabilities").and_then(Value::as_object) {
        None => p.push("$.capabilities: required object".into()),
        Some(c) => {
            for k in ["streaming", "pushNotifications", "extendedAgentCard"] {
                opt_bool(&mut p, c, k, "$.capabilities");
            }
            obj_array(&mut p, c, "extensions", "$.capabilities", false, false, &|p, e, at| {
                opt_str(p, e, "uri", at);
                opt_str(p, e, "description", at);
                opt_bool(p, e, "required", at);
                if e.get("params").is_some_and(|x| !x.is_object()) {
                    p.push(format!("{at}.params: must be an object"));
                }
            });
        }
    }
    if card.get("securitySchemes").is_some_and(|x| !x.is_object()) {
        p.push("$.securitySchemes: must be an object".into());
    }
    if card.get("securityRequirements").is_some_and(|x| !x.is_array()) {
        p.push("$.securityRequirements: must be an array".into());
    }
    for k in ["defaultInputModes", "defaultOutputModes"] {
        match card.get(k) {
            None => p.push(format!("$.{k}: required array of strings")),
            Some(v) => str_array(&mut p, v, &format!("$.{k}"), true),
        }
    }
    obj_array(&mut p, card, "skills", "$", true, false, &|p, e, at| {
        req_str(p, e, "id", at);
        req_str(p, e, "name", at);
        req_str(p, e, "description", at);
        match e.get("tags") {
            None => p.push(format!("{at}.tags: required array of strings")),
            Some(t) => str_array(p, t, &format!("{at}.tags"), false),
        }
        for k in ["examples", "inputModes", "outputModes"] {
            if let Some(v) = e.get(k) {
                str_array(p, v, &format!("{at}.{k}"), false);
            }
        }
        if e.get("securityRequirements").is_some_and(|x| !x.is_array()) {
            p.push(format!("{at}.securityRequirements: must be an array"));
        }
    });
    obj_array(&mut p, card, "signatures", "$", false, false, &|p, e, at| {
        req_str(p, e, "protected", at);
        req_str(p, e, "signature", at);
        if e.get("header").is_some_and(|x| !x.is_object()) {
            p.push(format!("{at}.header: must be an object"));
        }
    });
    p
}

// ---- dates -------------------------------------------------------------------------------------------------------------

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

/// `Date.parse` for ISO 8601 date and date-time strings (`YYYY[-MM[-DD]]`, then `THH:mm[:ss[.sss]]` with `Z` or `±HH:mm`);
/// anything else is NaN (`None`). shortcut: a date-time without an offset is read as UTC (the reference reads local time).
pub fn parse_iso_date(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    let num = |from: usize, len: usize| -> Option<i64> {
        b.get(from..from + len).filter(|d| d.iter().all(u8::is_ascii_digit)).map(|d| std::str::from_utf8(d).unwrap().parse().unwrap())
    };
    let (year, mut i) = match b.first() {
        Some(b'+' | b'-') => {
            let y = num(1, 6)?;
            if b[0] == b'-' && y == 0 {
                return None;
            }
            (if b[0] == b'-' { -y } else { y }, 7)
        }
        _ => (num(0, 4)?, 4),
    };
    let (mut month, mut day) = (1, 1);
    if b.get(i) == Some(&b'-') {
        month = num(i + 1, 2)?;
        i += 3;
        if b.get(i) == Some(&b'-') {
            day = num(i + 1, 2)?;
            i += 3;
        }
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let (mut h, mut mi, mut sec, mut ms, mut off) = (0, 0, 0, 0.0, 0i64);
    if i < b.len() {
        if b[i] != b'T' {
            return None;
        }
        h = num(i + 1, 2)?;
        if b.get(i + 3) != Some(&b':') {
            return None;
        }
        mi = num(i + 4, 2)?;
        i += 6;
        if b.get(i) == Some(&b':') {
            sec = num(i + 1, 2)?;
            i += 3;
            if b.get(i) == Some(&b'.') {
                let st = i + 1;
                let mut e = st;
                while e < b.len() && b[e].is_ascii_digit() {
                    e += 1;
                }
                if e == st {
                    return None;
                }
                let frac: String = s[st..e].chars().take(3).collect();
                ms = format!("{frac:0<3}").parse::<f64>().ok()?;
                i = e;
            }
        }
        match b.get(i) {
            Some(b'Z') if i + 1 == b.len() => {}
            Some(c @ (b'+' | b'-')) if i + 6 == b.len() && b[i + 3] == b':' => {
                let o = num(i + 1, 2)? * 60 + num(i + 4, 2)?;
                off = if *c == b'+' { o } else { -o };
            }
            None => {}
            _ => return None,
        }
        if h > 24 || mi > 59 || sec > 59 || (h == 24 && (mi > 0 || sec > 0 || ms > 0.0)) {
            return None;
        }
    }
    let days = days_from_civil(year, month, day);
    let t = (days * 86_400 + h * 3600 + mi * 60 + sec - off * 60) as f64 * 1000.0 + ms;
    (t.abs() <= 8.64e15).then_some(t)
}

/// `new Date(ms).toISOString()`; `None` outside the Date range (the reference throws `Invalid time value`).
pub fn iso_string(ms: f64) -> Option<String> {
    if !ms.is_finite() || ms.abs() > 8.64e15 {
        return None;
    }
    let ms = ms.trunc() as i64;
    let (days, rem) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    let ys = if (0..=9999).contains(&y) {
        format!("{y:04}")
    } else if y < 0 {
        format!("-{:06}", -y)
    } else {
        format!("+{y:06}")
    };
    Some(format!("{ys}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", rem / 3_600_000, rem / 60_000 % 60, rem / 1000 % 60, rem % 1000))
}

fn now_ms() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as f64).unwrap_or(0.0)
}

// ---- detached JWS -------------------------------------------------------------------------------------------------------

fn seed_of_jwk(k: &Value) -> Option<[u8; 32]> {
    let o = k.as_object()?;
    if o.get("kty")?.as_str()? != "OKP" || o.get("crv")?.as_str()? != "Ed25519" {
        return None;
    }
    decode_b64u_strict(o.get("d")?.as_str()?, Some(32))?.try_into().ok()
}

/// The A2A `AgentCardSignature` over `payload`: protected `{alg, (typ: JOSE | b64: false, crit: [b64]), kid?, ...header}`.
fn sign_detached(
    payload: &[u8],
    key: &Value,
    alg: Option<&Value>,
    kid: Option<&Value>,
    header: Option<Map<String, Value>>,
    standard: bool,
) -> Result<Value, String> {
    let alg = alg.cloned().unwrap_or(json!(DEFAULT_ALG));
    if alg != DEFAULT_ALG {
        return Err(format!("signDetached: unsupported alg {alg} (only EdDSA signing keys)"));
    }
    let seed = seed_of_jwk(key).ok_or("signDetached: the signing key must be a private Ed25519 JWK")?;
    let mut h = Map::new();
    h.insert("alg".into(), alg);
    if standard {
        h.insert("typ".into(), json!("JOSE"));
    } else {
        h.insert("b64".into(), json!(false));
        h.insert("crit".into(), json!(["b64"]));
    }
    if let Some(k) = kid {
        h.insert("kid".into(), k.clone());
    }
    h.extend(header.unwrap_or_default());
    let prot = b64_encode(js_stringify(&Value::Object(h)).as_bytes());
    let mut input = format!("{prot}.").into_bytes();
    if standard {
        input.extend(b64_encode(payload).as_bytes());
    } else {
        input.extend(payload);
    }
    Ok(json!({ "protected": prot, "signature": b64_encode(&KeyPair::from_seed(&seed).sign(&input)) }))
}

/// A verification key as the reference resolves it.
pub enum VerifyKey {
    Jwks(LocalJwkSet),
    Jwk(Value),
    /// Resolved but useless for verification (a private or symmetric JWK, a non-JWK value): every signature fails.
    Unusable,
}

/// `{jwks?, key?, alg?}` -> the resolver, or the refusal reason.
pub fn resolve_verify_key(opts: &Value) -> Result<VerifyKey, String> {
    if truthy(opts.get("jwks")) {
        return LocalJwkSet::new(&opts["jwks"]).map(VerifyKey::Jwks).map_err(|e| format!("could not resolve verification key: {e}"));
    }
    let Some(k) = opts.get("key") else { return Err("no verification key or JWKS supplied".into()) };
    let Some(o) = k.as_object().filter(|o| o.contains_key("kty")) else { return Ok(VerifyKey::Unusable) };
    // a private JWK still verifies (the public half is derived); only a symmetric key cannot
    if o.get("kty").and_then(Value::as_str) == Some("oct") {
        return Ok(VerifyKey::Unusable);
    }
    // an OKP key's algorithm comes from its curve, so the `alg` option never changes how it imports
    let alg = if o.get("kty").and_then(Value::as_str) == Some("OKP") { DEFAULT_ALG } else { opts.get("alg").and_then(Value::as_str).unwrap_or(DEFAULT_ALG) };
    let mut public = o.clone();
    for m in ["d", "p", "q", "dp", "dq", "qi"] {
        public.remove(m);
    }
    let public = Value::Object(public);
    jose::import_public_jwk(&public, alg).map_err(|e| format!("could not resolve verification key: {e}"))?;
    Ok(VerifyKey::Jwk(public))
}

/// Verify one detached signature; the protected header on success, else the reason.
fn verify_detached(payload: &[u8], sig: &Value, key: &VerifyKey) -> Result<Map<String, Value>, String> {
    let (Some(prot), Some(sg)) = (sig.get("protected").and_then(Value::as_str), sig.get("signature").and_then(Value::as_str)) else {
        return Err("signature is malformed".into());
    };
    let (Some(hb), Some(sb)) = (decode_b64u_strict(prot, None), decode_b64u_strict(sg, None)) else {
        return Err("non-canonical JWS segment".into());
    };
    let h = match jose::parse_json_bytes(&hb)? {
        Value::Object(m) => m,
        _ => return Err("JWS Protected Header is invalid".into()),
    };
    let alg = h.get("alg").and_then(Value::as_str).ok_or("JWS \"alg\" (Algorithm) Header Parameter missing or invalid")?.to_string();
    let b64 = jose::check_crit_b64(&h)?;
    let raw = h.get("b64") == Some(&Value::Bool(false));
    if raw == b64 {
        return Err("JWS Payload must be a string".into());
    }
    let mut input = format!("{prot}.").into_bytes();
    if raw {
        input.extend(payload);
    } else {
        input.extend(b64_encode(payload).as_bytes());
    }
    let jwk = match key {
        VerifyKey::Unusable => return Err("the key cannot verify".into()),
        VerifyKey::Jwk(j) => j.clone(),
        VerifyKey::Jwks(set) => set.resolve(&h).map_err(|e| e.message)?,
    };
    let k = jose::import_public_jwk(&jwk, &alg)?;
    if !jose::verify_jws_signature(&alg, &k, &input, &sb) {
        return Err("signature verification failed".into());
    }
    Ok(h)
}

// ---- cards ---------------------------------------------------------------------------------------------------------------

fn passport_ref_from(p: &Value, uri: Option<&Value>) -> Result<Value, String> {
    let Some(o) = p.as_object() else { return Err("Cannot use 'in' operator to search for 'model_id' in a non-object".into()) };
    let mut r = Map::new();
    if let Some(id) = o.get("id") {
        r.insert("id".into(), id.clone());
    }
    let u = if o.contains_key("model_id") { uri } else { o.get("uri").or(uri) };
    if let Some(u) = u {
        r.insert("uri".into(), u.clone());
    }
    Ok(Value::Object(r))
}

/// A card pointing at the passport (`{id, uri?}`; a full passport is referenced by id).
pub fn build_agent_card(passport: &Value, opts: &Value) -> Result<Value, String> {
    let mut c = Map::new();
    for k in ["name", "description", "url", "version", "skills"] {
        if let Some(v) = opts.get(k) {
            c.insert(k.into(), v.clone());
        }
    }
    c.insert("pcaPassport".into(), passport_ref_from(passport, opts.get("passportUri"))?);
    if let Some(v) = opts.get("pcaProofRef") {
        c.insert("pcaProof".into(), v.clone());
    }
    Ok(Value::Object(c))
}

fn without_signatures(card: &Value) -> Value {
    match card {
        Value::Object(m) => Value::Object(m.iter().filter(|(k, _)| k.as_str() != "signatures").map(|(k, v)| (k.clone(), v.clone())).collect()),
        x => x.clone(),
    }
}

/// Sign a card (one more detached signature). `opts`: `alg`, `passport`, `kid`, `profile` (`pca-detached` | `a2a-1.0`),
/// `schema` (`a2a-1.0`).
pub fn issue_signed_agent_card(card: &Value, signing_key: &Value, opts: &Value) -> Result<Value, String> {
    let mut undefined_id = false;
    let passport = match opts.get("passport").filter(|p| truthy(Some(p))) {
        Some(p) => {
            let mut r = Map::new();
            // `{id: opts.passport.id}`: an absent id is an undefined member, which only JCS refuses (after the schema check)
            match p.get("id") {
                Some(id) => {
                    r.insert("id".into(), id.clone());
                }
                None => undefined_id = true,
            }
            if let Some(u) = p.get("uri") {
                r.insert("uri".into(), u.clone());
            }
            Some(Value::Object(r))
        }
        None => card.get("pcaPassport").cloned(),
    };
    let mut to_sign = card.as_object().cloned().unwrap_or_default();
    if let Some(p) = passport.as_ref().filter(|p| truthy(Some(p))) {
        to_sign.insert("pcaPassport".into(), p.clone());
    }
    let to_sign_v = Value::Object(to_sign.clone());
    if opts.get("schema").and_then(Value::as_str) == Some("a2a-1.0") {
        let problems = validate_agent_card1(&to_sign_v);
        if !problems.is_empty() {
            return Err(format!("issueSignedAgentCard: the card does not match the A2A 1.0 schema: {}", problems.join("; ")));
        }
    }
    if undefined_id {
        return Err("jcs: unsupported type undefined".into());
    }
    let payload = jcs_bytes(&without_signatures(&to_sign_v))?;
    let spec = opts.get("profile").and_then(Value::as_str) == Some("a2a-1.0");
    if spec && !opts.get("kid").and_then(Value::as_str).is_some_and(|k| !k.is_empty()) {
        return Err("issueSignedAgentCard: the 'a2a-1.0' profile requires a kid".into());
    }
    let header = passport.as_ref().filter(|p| truthy(Some(p))).map(|p| {
        let mut h = Map::new();
        if let Some(id) = p.get("id") {
            h.insert(PCA_PASSPORT_HEADER.into(), id.clone());
        }
        h
    });
    let sig = sign_detached(&payload, signing_key, nn(opts.get("alg")), opts.get("kid"), header, spec)?;
    let mut sigs = match to_sign.get("signatures") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => crate::oauth::spread(v, "toSign.signatures")?,
    };
    sigs.push(sig);
    to_sign.insert("signatures".into(), Value::Array(sigs));
    Ok(Value::Object(to_sign))
}

/// Verify every signature of a card. `opts`: `jwks` | `key`, `alg`, `schema`. `{ok, reason?, passportRef?, passport?,
/// pcaProof?}`.
pub fn verify_agent_card(card: &Value, opts: &Value) -> Value {
    let fail = |r: String| json!({ "ok": false, "reason": r });
    if !matches!(card, Value::Object(_) | Value::Array(_)) {
        return fail("agent card is not an object".into());
    }
    let sigs = match card.get("signatures").and_then(Value::as_array) {
        Some(s) if !s.is_empty() => s,
        _ => return fail("agent card carries no signatures".into()),
    };
    if opts.get("schema").and_then(Value::as_str) == Some("a2a-1.0") {
        let problems = validate_agent_card1(card);
        if !problems.is_empty() {
            return fail(format!("agent card does not match the A2A 1.0 schema: {}", problems.join("; ")));
        }
    }
    let key = match resolve_verify_key(opts) {
        Ok(k) => k,
        Err(e) => return fail(e),
    };
    let payload = match jcs_bytes(&without_signatures(card)) {
        Ok(p) => p,
        Err(e) => return fail(format!("agent card has no canonical form: {e}")),
    };
    let mut passport_ref: Option<String> = None;
    for (i, sig) in sigs.iter().enumerate() {
        if !truthy(Some(sig)) {
            return fail(format!("signature {i} is missing"));
        }
        match verify_detached(&payload, sig, &key) {
            Err(e) => return fail(format!("signature {i} did not verify: {e}")),
            Ok(h) => {
                if passport_ref.is_none() {
                    passport_ref = h.get(PCA_PASSPORT_HEADER).and_then(Value::as_str).map(String::from);
                }
            }
        }
    }
    let mut out = Map::new();
    out.insert("ok".into(), json!(true));
    if let Some(r) = passport_ref {
        out.insert("passportRef".into(), json!(r));
    }
    if truthy(card.get("pcaPassport")) {
        out.insert("passport".into(), card["pcaPassport"].clone());
    }
    if truthy(card.get("pcaProof")) {
        out.insert("pcaProof".into(), card["pcaProof"].clone());
    }
    Value::Object(out)
}

// ---- AgentFacts -------------------------------------------------------------------------------------------------------------

/// `x ?? default`: absent or null is nullish.
fn nn(v: Option<&Value>) -> Option<&Value> {
    v.filter(|x| !x.is_null())
}

fn statement_bytes(st: &Map<String, Value>) -> Result<Vec<u8>, String> {
    let mut v = Map::new();
    v.insert("d".into(), json!("atlas-pca/agentfacts/attestation/v1"));
    for k in ["issuer", "subject", "attests", "validFrom"] {
        // an absent member is `undefined`, which the canonical encoder refuses
        v.insert(k.into(), st.get(k).cloned().ok_or("canonicalize: unsupported type undefined")?);
    }
    v.insert("validUntil".into(), nn(st.get("validUntil")).cloned().unwrap_or(Value::Null));
    Ok(crate::canonicalize(&Value::Object(v)).into_bytes())
}

fn make_attestation(subject: &Value, opts: &Value) -> Result<Value, String> {
    let valid_from = match nn(opts.get("validFrom")) {
        Some(v) => v.clone(),
        None => json!(iso_string(nn(opts.get("now")).map_or_else(now_ms, |n| n.as_f64().unwrap_or(f64::NAN))).ok_or("Invalid time value")?),
    };
    let mut st = Map::new();
    st.insert("issuer".into(), nn(opts.get("attestorId")).cloned().unwrap_or(json!(PCA_ATTESTOR_ID)));
    st.insert("subject".into(), subject.clone());
    if let Some(a) = opts.get("attests") {
        st.insert("attests".into(), a.clone());
    }
    st.insert("validFrom".into(), valid_from);
    if let Some(u) = opts.get("validUntil") {
        st.insert("validUntil".into(), u.clone());
    }
    let mut header = Map::new();
    header.insert("attestor".into(), st["issuer"].clone());
    let key = opts.get("attestorKey").cloned().unwrap_or(Value::Null);
    let sig = sign_detached(&statement_bytes(&st)?, &key, nn(opts.get("alg")), opts.get("kid"), Some(header), false)?;
    st.insert("signature".into(), sig);
    Ok(Value::Object(st))
}

/// AgentFacts for a passport with one PCA attestation. `opts`: `attestorKey` (JWK), `attests`, `selfAsserted`, `attestorId`,
/// `agentId`, `alg`, `kid`, `validFrom`, `validUntil`, `now`, `context`.
pub fn issue_agent_facts(passport: &Value, opts: &Value) -> Result<Value, String> {
    if passport.is_null() {
        return Err("Cannot read properties of null (reading 'id')".into());
    }
    let agent_id = nn(opts.get("agentId")).or_else(|| passport.get("id")).cloned();
    let att = make_attestation(agent_id.as_ref().unwrap_or(&Value::Null), opts)?;
    let mut f = Map::new();
    f.insert("@context".into(), nn(opts.get("context")).cloned().unwrap_or(json!(AGENT_FACTS_CONTEXT)));
    if let Some(id) = agent_id {
        f.insert("id".into(), id);
    }
    f.insert("type".into(), json!("AgentFacts"));
    f.insert("selfAsserted".into(), nn(opts.get("selfAsserted")).cloned().unwrap_or(json!({})));
    f.insert("attestations".into(), json!([att]));
    Ok(Value::Object(f))
}

/// One more attestation on existing AgentFacts (subject = `facts.id`).
pub fn add_attestation(facts: &Value, opts: &Value) -> Result<Value, String> {
    let Some(f) = facts.as_object() else { return Err("Cannot read properties of a non-object (reading 'id')".into()) };
    let att = make_attestation(f.get("id").unwrap_or(&Value::Null), opts)?;
    let mut list = crate::oauth::spread(f.get("attestations").unwrap_or(&Value::Null), "facts.attestations")?;
    list.push(att);
    let mut out = f.clone();
    out.insert("attestations".into(), Value::Array(list));
    Ok(Value::Object(out))
}

fn check(issuer: &str, reason: impl Into<String>) -> Value {
    json!({ "issuer": issuer, "ok": false, "reason": reason.into() })
}

fn issuer_of(a: &Value) -> String {
    a.get("issuer").and_then(Value::as_str).filter(|_| truthy(Some(a))).unwrap_or("<unknown>").to_string()
}

fn date_of(v: &Value) -> Option<f64> {
    match v {
        Value::String(s) => parse_iso_date(s),
        _ => None, // shortcut: a non-string date is NaN here (the reference coerces it with String())
    }
}

fn verify_one(a: &Value, doc_id: Option<&Value>, now: f64, key: Option<&VerifyKey>) -> Result<Value, String> {
    let issuer = issuer_of(a);
    let ok_shape = truthy(Some(a))
        && a.get("subject").is_some_and(Value::is_string)
        && a.get("attests").is_some_and(Value::is_object)
        && a.get("validFrom").is_some_and(Value::is_string);
    if !ok_shape {
        return Ok(check(&issuer, "attestation is malformed"));
    }
    let subject = a["subject"].as_str().unwrap();
    if doc_id.and_then(Value::as_str) != Some(subject) {
        let d = doc_id.map_or_else(|| "undefined".to_string(), crate::oauth::js_str);
        return Ok(check(&issuer, format!("attestation subject '{subject}' does not match agent id '{d}'")));
    }
    let Some(from) = date_of(&a["validFrom"]) else { return Ok(check(&issuer, "attestation validFrom is not a valid date")) };
    if !(now.is_finite() && now >= from) {
        return Ok(check(&issuer, "attestation is not yet valid"));
    }
    if let Some(u) = a.get("validUntil") {
        let Some(until) = date_of(u) else { return Ok(check(&issuer, "attestation validUntil is not a valid date")) };
        if !(now.is_finite() && now <= until) {
            return Ok(check(&issuer, "attestation has expired"));
        }
    }
    let Some(key) = key else { return Ok(check(&issuer, "no verification key or JWKS supplied")) };
    let mut st = Map::new();
    for k in ["issuer", "subject", "attests", "validFrom", "validUntil"] {
        if let Some(v) = a.get(k) {
            st.insert(k.into(), v.clone());
        }
    }
    let sig = match a.get("signature") {
        None | Some(Value::Null) => return Err("Cannot read properties of undefined (reading 'protected')".into()),
        Some(s) => s,
    };
    Ok(match verify_detached(&statement_bytes(&st)?, sig, key) {
        Err(e) => check(&issuer, format!("signature did not verify: {e}")),
        Ok(_) => json!({ "issuer": issuer, "ok": true, "attests": a["attests"] }),
    })
}

/// Verify AgentFacts: every attestation (subject, validity window at `opts.now`, signature), then the claim provenance
/// (`attested` wins over `self-asserted`).
pub fn verify_agent_facts(facts: &Value, opts: &Value) -> Result<Value, String> {
    if facts.is_null() {
        return Err("Cannot read properties of null (reading 'selfAsserted')".into());
    }
    let self_asserted = facts.get("selfAsserted").filter(|s| s.is_object()).cloned().unwrap_or(json!({}));
    let now = opts.get("now").and_then(Value::as_f64).unwrap_or_else(now_ms);
    let id = facts.get("id");
    let base = |reason: String, atts: Vec<Value>| {
        let mut m = Map::new();
        m.insert("ok".into(), json!(false));
        if let Some(i) = id {
            m.insert("agentId".into(), i.clone());
        }
        m.insert("attestations".into(), Value::Array(atts));
        m.insert("attested".into(), json!({}));
        m.insert("selfAsserted".into(), self_asserted.clone());
        m.insert("claims".into(), json!({}));
        m.insert("reason".into(), json!(reason));
        Value::Object(m)
    };
    let Some(list) = facts.get("attestations").and_then(Value::as_array) else { return Ok(base("agent facts has no attestations array".into(), vec![])) };
    let mut key = None;
    if !list.is_empty() {
        match resolve_verify_key(opts) {
            Ok(k) => key = Some(k),
            Err(e) => return Ok(base(e, list.iter().map(|a| check(&issuer_of(a), "no verification key or JWKS supplied")).collect())),
        }
    }
    let (mut checks, mut attested, mut all_ok) = (Vec::new(), Map::new(), true);
    for a in list {
        let c = verify_one(a, id, now, key.as_ref())?;
        if c["ok"] == json!(true) {
            if let Some(m) = c["attests"].as_object() {
                attested.extend(m.clone());
            }
        } else {
            all_ok = false;
        }
        checks.push(c);
    }
    let mut claims = Map::new();
    for k in self_asserted.as_object().unwrap().keys() {
        claims.insert(k.clone(), json!("self-asserted"));
    }
    for k in attested.keys() {
        claims.insert(k.clone(), json!("attested"));
    }
    let mut m = Map::new();
    m.insert("ok".into(), json!(all_ok));
    if !all_ok {
        m.insert("reason".into(), json!("one or more attestations did not verify"));
    }
    if let Some(i) = id {
        m.insert("agentId".into(), i.clone());
    }
    m.insert("attestations".into(), Value::Array(checks));
    m.insert("attested".into(), Value::Object(attested));
    m.insert("selfAsserted".into(), self_asserted);
    m.insert("claims".into(), Value::Object(claims));
    Ok(Value::Object(m))
}

// ---- hosting + registry ----------------------------------------------------------------------------------------------------

fn normalize_path(p: &str) -> &str {
    let p = p.split('?').next().unwrap_or("");
    if p.len() > 1 && p.ends_with('/') {
        &p[..p.len() - 1]
    } else {
        p
    }
}

fn hosted(value: &Value, path: &str, req_path: &str) -> Value {
    if normalize_path(req_path) != normalize_path(path) {
        return Value::Null;
    }
    json!({ "status": 200, "headers": { "content-type": "application/json", "cache-control": "no-store" }, "body": js_stringify(value) })
}

/// The response the card handler gives `req_path` (`null` = it declines). `path` defaults to the well-known path.
pub fn agent_card_handler(card: &Value, path: Option<&str>, req_path: &str) -> Value {
    hosted(card, path.unwrap_or(WELL_KNOWN_AGENT_CARD_PATH), req_path)
}

/// The response the AgentFacts handler gives `req_path` (`null` = it declines).
pub fn agent_facts_handler(facts: &Value, path: Option<&str>, req_path: &str) -> Value {
    hosted(facts, path.unwrap_or(WELL_KNOWN_AGENT_FACTS_PATH), req_path)
}

/// A registry entry joining a card and its AgentFacts (attested vs self-asserted-only claim names).
pub fn to_registry_entry(card: &Value, facts: &Value) -> Result<Value, String> {
    if card.is_null() || facts.is_null() {
        return Err("Cannot read properties of null".into());
    }
    let mut attested: Vec<String> = Vec::new();
    let atts = match facts.get("attestations") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => crate::oauth::spread(v, "facts.attestations")?,
    };
    for a in &atts {
        if let Some(m) = a.get("attests").and_then(Value::as_object).filter(|_| truthy(Some(a))) {
            for k in m.keys() {
                if !attested.contains(k) {
                    attested.push(k.clone());
                }
            }
        }
    }
    let self_only: Vec<String> =
        facts.get("selfAsserted").and_then(Value::as_object).map(|m| m.keys().filter(|k| !attested.contains(k)).cloned().collect()).unwrap_or_default();
    let card_url = card.get("url").and_then(|u| u.as_str().map(String::from));
    let agent_card_url = match card.get("url") {
        None => None,
        // `new URL(path, base)`: a non-string base is String()-ed, which never makes a valid absolute URL here
        Some(_) => card_url.as_deref().and_then(|b| url::Url::parse(b).ok()).and_then(|b| b.join(WELL_KNOWN_AGENT_CARD_PATH).ok()).map(|u| u.to_string()),
    };
    let mut e = Map::new();
    if let Some(id) = facts.get("id") {
        e.insert("id".into(), id.clone());
    }
    if let Some(n) = card.get("name") {
        e.insert("name".into(), n.clone());
    }
    for (k, out) in [("url", "url"), ("version", "version"), ("skills", "skills")] {
        if let Some(v) = card.get(k) {
            e.insert(out.into(), v.clone());
        }
    }
    if truthy(card.get("pcaPassport")) {
        e.insert("passport".into(), card["pcaPassport"].clone());
    }
    if truthy(card.get("pcaProof")) {
        e.insert("pcaProof".into(), card["pcaProof"].clone());
    }
    e.insert("card".into(), card.clone());
    if let Some(u) = agent_card_url {
        e.insert("agentCardUrl".into(), json!(u));
    }
    e.insert("facts".into(), facts.clone());
    e.insert("attestedClaims".into(), json!(attested));
    e.insert("selfAssertedClaims".into(), json!(self_only));
    Ok(Value::Object(e))
}
