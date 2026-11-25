//! External-fact attestation for proof-carrying actions: a notary witnesses one HTTP request/response and signs a canonical
//! record of it; the response body is committed as a salted Merkle tree so one field can be disclosed while the rest stay hidden,
//! and the disclosure is bound to a PCActn.
//!
//! Trust boundary: this relies on a trusted or semi-trusted notary (it is NOT trustless zkTLS). Everything fails closed.
//! JSON-valued API (reference member names). Salts come from the caller's closure (the crate never invents randomness here);
//! [`os_salt`] is the production source.
use crate::agent::{rand_bytes, KeyPair};
use crate::{b64_encode, canonicalize_strict, hash_canonical_strict, sha};
use serde_json::{json, Map, Value};

pub const BODY_COMMIT_ALG: &str = "salted-merkle-sha256-v1";
pub const NOTARY_DOMAIN: &[u8] = b"atlas-pca/notary/v1\x00";
pub const ATTESTED_FACT_CAVEAT: &str = "attested_fact";
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// 16 fresh random bytes (a leaf salt).
pub fn os_salt() -> Result<Vec<u8>, String> {
    rand_bytes::<16>().map(|b| b.to_vec())
}

fn safe_integer(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE),
        _ => false,
    }
}

fn neg_zero(v: &Value) -> bool {
    v.as_f64().is_some_and(|f| f == 0.0 && f.is_sign_negative())
}

fn finite(v: &Value) -> bool {
    matches!(v, Value::Number(n) if n.as_f64().is_some_and(f64::is_finite))
}

/// JavaScript truthiness of a decoded JSON value.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        _ => true,
    }
}

/// JavaScript ToNumber for the window bounds a keyring entry may carry.
fn to_number(v: &Value) -> f64 {
    match v {
        Value::Null => 0.0,
        Value::Bool(b) => *b as u8 as f64,
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::String(s) => {
            let t = s.trim();
            match t {
                "" => 0.0,
                "Infinity" | "+Infinity" => f64::INFINITY,
                "-Infinity" => f64::NEG_INFINITY,
                _ if t.contains('_') || t.to_ascii_lowercase().trim_start_matches(['+', '-']).starts_with("inf") || t.to_ascii_lowercase().contains("nan") => {
                    f64::NAN
                }
                _ => t.parse::<f64>().unwrap_or(f64::NAN),
            }
        }
        _ => f64::NAN,
    }
}

fn canonical_equal(a: &Value, b: &Value) -> bool {
    matches!((hash_canonical_strict(a), hash_canonical_strict(b)), (Some(x), Some(y)) if x == y)
}

fn normalize_path(path: &Value) -> Result<Vec<Value>, String> {
    match path {
        Value::String(_) => Ok(vec![path.clone()]),
        Value::Array(a) => Ok(a.clone()),
        _ => Err("path must be a string or an array".into()),
    }
}

struct Leaf {
    path: Vec<Value>,
    value: Value,
    salt: String,
}

fn flatten(value: &Value, prefix: &[Value], out: &mut Vec<(Vec<Value>, Value)>) {
    match value {
        Value::Array(a) if a.is_empty() => out.push((prefix.to_vec(), json!([]))),
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                let mut p = prefix.to_vec();
                p.push(json!(i));
                flatten(x, &p, out);
            }
        }
        Value::Object(m) if m.is_empty() => out.push((prefix.to_vec(), json!({}))),
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            for k in keys {
                let mut p = prefix.to_vec();
                p.push(json!(k));
                flatten(&m[k.as_str()], &p, out);
            }
        }
        v => out.push((prefix.to_vec(), v.clone())),
    }
}

fn chunk_string(s: &str, size: usize) -> Vec<(Vec<Value>, Value)> {
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return vec![(vec![json!("#chunk"), json!(0)], json!(""))];
    }
    chars.chunks(size).enumerate().map(|(i, c)| (vec![json!("#chunk"), json!(i)], json!(c.iter().collect::<String>()))).collect()
}

fn leaf_object(l: &Leaf) -> Value {
    json!({ "p": l.path, "v": l.value, "s": l.salt })
}

fn request_headers_digest(headers: Option<&Value>) -> Result<String, String> {
    let mut norm = Map::new();
    match headers {
        None | Some(Value::Null) => {}
        Some(Value::Object(h)) => {
            for (k, v) in h {
                norm.insert(k.to_lowercase(), v.clone());
            }
        }
        Some(_) => return Err("request.headers must be an object".into()),
    }
    hash_canonical_strict(&Value::Object(norm)).ok_or_else(|| "request headers are outside the strict JSON profile".to_string())
}

/// A public key as base64url: a base64url string, `{"$bytes": b64u}`, or a key pair `{"publicKey": {"$bytes"}}`.
pub fn to_pub_b64u(key: &Value) -> Result<String, String> {
    let bytes = |v: &Value| v.as_object().filter(|m| m.len() == 1).and_then(|m| m.get("$bytes")).and_then(Value::as_str).map(String::from);
    match key {
        Value::String(s) => Ok(s.clone()),
        v if bytes(v).is_some() => Ok(bytes(v).unwrap()),
        Value::Object(m) => m.get("publicKey").and_then(bytes).ok_or_else(|| "not a public key".to_string()),
        _ => Err("not a public key".into()),
    }
}

/// The bytes the notary signs: `NOTARY_DOMAIN || sha256(canonical(session))`.
pub fn notary_message(session: &Value) -> Result<Vec<u8>, String> {
    let mut m = NOTARY_DOMAIN.to_vec();
    m.extend(sha(canonicalize_strict(session)?.as_bytes()));
    Ok(m)
}

/// Witness a request/response: `{attestation, witness}` (the signed attestation plus the prover's private per-leaf openings).
/// `salts` supplies one 16-byte salt per leaf (production: [`os_salt`]); `observed_at` defaults to the clock;
/// `text_chunk_size` (a number >= 1) splits a string body into chunks of that many code points.
pub fn notarize_response(
    request: &Value,
    response: &Value,
    notary_key: &KeyPair,
    observed_at: Option<&Value>,
    text_chunk_size: Option<&Value>,
    salts: &mut dyn FnMut() -> Result<Vec<u8>, String>,
) -> Result<Value, String> {
    if !request.get("method").and_then(Value::as_str).is_some_and(|m| !m.is_empty()) {
        return Err("notarizeResponse: request.method is required".into());
    }
    if !request.get("url").and_then(Value::as_str).is_some_and(|m| !m.is_empty()) {
        return Err("notarizeResponse: request.url is required".into());
    }
    if !safe_integer(response.get("status")) {
        return Err("notarizeResponse: response.status must be an integer".into());
    }
    let body = response.get("body").cloned().unwrap_or(Value::Null);
    let size = text_chunk_size.and_then(Value::as_f64).filter(|s| *s >= 1.0);
    let bare = match (body.as_str(), size) {
        (Some(s), Some(n)) => chunk_string(s, n.floor().min(usize::MAX as f64) as usize),
        _ => {
            let mut out = Vec::new();
            flatten(&body, &[], &mut out);
            out
        }
    };
    let leaves: Vec<Leaf> = bare.into_iter().map(|(path, value)| Ok(Leaf { path, value, salt: b64_encode(&salts()?) })).collect::<Result<_, String>>()?;
    let objs: Vec<Value> = leaves.iter().map(leaf_object).collect();
    let root = crate::merkle_root(&objs)?;
    let observed = match observed_at {
        Some(v) if !v.is_null() => v.clone(),
        _ => json!(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)),
    };
    let session = json!({
        "v": 1,
        "method": request["method"].as_str().unwrap().to_uppercase(),
        "url": request["url"],
        "requestHeadersDigest": request_headers_digest(request.get("headers"))?,
        "responseStatus": response["status"],
        "responseBodyCommit": { "alg": BODY_COMMIT_ALG, "root": root, "size": leaves.len() },
        "observedAt": observed,
    });
    let sig = b64_encode(&notary_key.sign(&notary_message(&session)?));
    let attestation = json!({ "session": session, "notary": notary_key.public, "sig": sig });
    let witness_leaves: Vec<Value> = leaves.iter().map(|l| json!({ "path": l.path, "value": l.value, "salt": l.salt })).collect();
    Ok(json!({ "attestation": attestation, "witness": { "session": session, "leaves": witness_leaves } }))
}

/// RFC 6962 audit path of leaf `index`: `{index, size, path: [{side, hash}]}`.
fn merkle_proof(leaves: &[Value], index: usize) -> Result<Value, String> {
    if index >= leaves.len() {
        return Err("merkleProof: index out of range".into());
    }
    let hs: Vec<Vec<u8>> = leaves.iter().map(crate::leaf_hash).collect::<Option<_>>().ok_or("leaf is outside the strict JSON profile")?;
    let mut path = Vec::new();
    fn prove(hs: &[Vec<u8>], idx: usize, path: &mut Vec<Value>) {
        if hs.len() == 1 {
            return;
        }
        let k = crate::split(hs.len() as u64) as usize;
        if idx < k {
            prove(&hs[..k], idx, path);
            path.push(json!({ "side": "R", "hash": b64_encode(&crate::build(&hs[k..])) }));
        } else {
            prove(&hs[k..], idx - k, path);
            path.push(json!({ "side": "L", "hash": b64_encode(&crate::build(&hs[..k])) }));
        }
    }
    prove(&hs, index, &mut path);
    Ok(json!({ "index": index, "size": leaves.len(), "path": path }))
}

/// Reveal ONE response field (by path) with its Merkle inclusion proof. Refused if the path names no committed leaf.
pub fn disclose_field(_attestation: &Value, witness: &Value, path: &Value) -> Result<Value, String> {
    let want = Value::Array(normalize_path(path)?);
    let leaves = witness.get("leaves").and_then(Value::as_array).ok_or("Cannot read properties of undefined (reading 'length')")?;
    let idx = leaves.iter().position(|l| canonical_equal(&l["path"], &want)).ok_or("discloseField: no committed field at path")?;
    let objs: Vec<Value> = leaves.iter().map(|l| json!({ "p": l["path"], "v": l["value"], "s": l["salt"] })).collect();
    let l = &leaves[idx];
    Ok(json!({ "path": l["path"], "value": l["value"], "salt": l["salt"], "proof": merkle_proof(&objs, idx)? }))
}

fn valid_commit(c: Option<&Value>) -> bool {
    let Some(c) = c.filter(|c| c.is_object()) else { return false };
    c["alg"] == BODY_COMMIT_ALG
        && c["root"].as_str().is_some_and(|r| crate::decode_b64u_strict(r, Some(32)).is_some())
        && safe_integer(c.get("size"))
        && c["size"].as_f64().is_some_and(|s| s >= 1.0)
}

fn valid_session(s: &Value) -> bool {
    s.is_object()
        && s["v"].as_f64() == Some(1.0)
        && s["method"].is_string()
        && s["url"].is_string()
        && s["requestHeadersDigest"].is_string()
        && safe_integer(s.get("responseStatus"))
        && !neg_zero(&s["responseStatus"])
        && safe_integer(s.get("observedAt"))
        && !neg_zero(&s["observedAt"])
        && valid_commit(s.get("responseBodyCommit"))
}

/// The attestation is structurally valid, signed by the TRUSTED notary key, and the signature verifies.
pub fn verify_notary_attestation(attestation: &Value, notary_key: &Value) -> bool {
    let (Some(notary), Some(sig)) = (attestation["notary"].as_str(), attestation["sig"].as_str()) else { return false };
    if !attestation.is_object() || !valid_session(&attestation["session"]) || to_pub_b64u(notary_key).map_or(true, |k| k != notary) {
        return false;
    }
    notary_message(&attestation["session"]).is_ok_and(|m| crate::verify_b64u(notary, &m, sig))
}

/// The attestation is authentic AND the disclosed leaf is included under the attested body root.
pub fn verify_disclosed_field(attestation: &Value, disclosure: &Value, notary_key: &Value) -> bool {
    if !verify_notary_attestation(attestation, notary_key) || !disclosure.is_object() {
        return false;
    }
    let (Some(path), Some(salt), Some(value)) = (disclosure["path"].as_array(), disclosure["salt"].as_str(), disclosure.get("value")) else {
        return false;
    };
    let Some(proof) = disclosure["proof"].as_object().filter(|p| p.get("path").is_some_and(Value::is_array)) else { return false };
    let commit = &attestation["session"]["responseBodyCommit"];
    match (proof.get("size"), commit["size"].as_f64()) {
        (Some(Value::Number(n)), Some(s)) if n.as_f64() == Some(s) => {}
        _ => return false,
    }
    let leaf = json!({ "p": path, "v": value, "s": salt });
    crate::verify_inclusion(commit["root"].as_str().unwrap_or(""), Some(proof), &leaf)
}

/// A stable digest of the attested fact (independent of any PCActn binding).
pub fn fact_ref(attestation: &Value) -> Result<String, String> {
    let get = |k: &str| {
        attestation
            .get(k)
            .cloned()
            .ok_or_else(|| format!("Cannot read properties of {} (reading '{k}')", if attestation.is_null() { "null" } else { "undefined" }))
    };
    hash_canonical_strict(&json!({ "fact": "atlas-pca-notary/v1", "session": get("session")?, "notary": get("notary")?, "sig": get("sig")? }))
        .ok_or_else(|| "factRef: outside the strict JSON profile".to_string())
}

/// A new attestation stamped with the digest of the PCActn the fact is FOR.
pub fn bind_fact_to_pc_actn(attestation: &Value, pc_actn: &Value) -> Result<Value, String> {
    let mut base = match attestation {
        Value::Null => Map::new(),
        Value::Object(m) => m.clone(),
        _ => return Err("attestation must be an object".into()),
    };
    let d = hash_canonical_strict(pc_actn).ok_or("bindFactToPcActn: the PCActn is outside the strict JSON profile")?;
    base.insert("fact_binding".into(), json!({ "pcactn_digest": d }));
    Ok(Value::Object(base))
}

/// Bound in BOTH directions: the fact names the action AND the action's `provenance.trusted_refs` commits to the fact.
pub fn fact_matches_pc_actn(attestation: &Value, pc_actn: &Value) -> bool {
    let Some(d) = attestation["fact_binding"]["pcactn_digest"].as_str() else { return false };
    if hash_canonical_strict(pc_actn).as_deref() != Some(d) {
        return false;
    }
    let Some(refs) = pc_actn["provenance"]["trusted_refs"].as_array() else { return false };
    fact_ref(attestation).is_ok_and(|r| refs.iter().any(|x| x.as_str() == Some(&r)))
}

/// The policy caveat: the notarized field at `path` must equal `equals` (optionally for one `url`, optionally bound to the PCActn).
/// `opts`: `notary`, `path`, `equals`, `url`, `bindToPcActn`.
pub fn require_attested_fact(opts: &Value) -> Result<Value, String> {
    let notary = to_pub_b64u(opts.get("notary").ok_or("notary is required")?)?;
    let path = opts.get("path").and_then(Value::as_array).ok_or("path must be an array")?;
    let mut cv = Map::new();
    cv.insert("type".into(), json!(ATTESTED_FACT_CAVEAT));
    cv.insert("notary".into(), json!(notary));
    cv.insert("path".into(), json!(path));
    if let Some(e) = opts.get("equals") {
        cv.insert("equals".into(), e.clone());
    }
    for k in ["url", "bindToPcActn"] {
        if let Some(v) = opts.get(k) {
            cv.insert(k.into(), v.clone());
        }
    }
    Ok(Value::Object(cv))
}

/// `key` is listed in `ring`, not revoked, and `observed_at` lies in its `[notBefore, notAfter)` window.
pub fn notary_key_usable(ring: &Value, key: &Value, observed_at: &Value) -> bool {
    let Some(ring) = ring.as_array() else { return false };
    if !safe_integer(Some(observed_at)) {
        return false;
    }
    let entries: Vec<&Value> = ring.iter().filter(|e| e.is_object() && e.get("key").is_some_and(|k| k == key)).collect();
    if entries.is_empty() {
        return false;
    }
    let obs = observed_at.as_f64().unwrap();
    let in_window = |e: &Value| e.get("notBefore").is_none_or(|b| obs >= to_number(b)) && e.get("notAfter").is_none_or(|a| obs < to_number(a));
    entries.iter().all(|e| e.get("revoked") != Some(&Value::Bool(true))) && entries.iter().any(|e| in_window(e))
}

fn denied(r: &str) -> Value {
    json!({ "ok": false, "reason": r })
}

/// Admit an action only when the notarized field verifies and satisfies the caveat; every step fails closed.
/// `policy`: `keyring`, `maxAgeMs` (+ `now`); `None` = no policy.
pub fn evaluate_attested_fact_caveat(caveat: &Value, evidence: &Value, policy: Option<&Value>, now: f64) -> Value {
    if !caveat.is_object() || caveat["type"] != ATTESTED_FACT_CAVEAT {
        return denied("not an attested_fact caveat");
    }
    if !caveat["notary"].is_string() || !caveat["path"].is_array() {
        return denied("caveat is malformed (notary/path)");
    }
    let err = |m: &str| denied(&format!("attested_fact evaluation error (fail closed): {m}"));
    if evidence.is_null() {
        return err("Cannot destructure property 'attestation' of 'evidence' as it is null.");
    }
    let (attestation, disclosure, pc_actn) = (&evidence["attestation"], &evidence["disclosure"], evidence.get("pcActn"));
    if !verify_notary_attestation(attestation, &caveat["notary"]) {
        return denied("notary attestation does not verify (fail closed)");
    }
    let empty = json!({});
    let pol = policy.unwrap_or(&empty);
    if pol.is_null() {
        return err("Cannot read properties of null (reading 'keyring')");
    }
    let observed = &attestation["session"]["observedAt"];
    if let Some(ring) = pol.get("keyring") {
        if !notary_key_usable(ring, &attestation["notary"], observed) {
            return denied("notary key is not trusted for this observation time (unlisted, revoked or out of window)");
        }
    }
    if let Some(max) = pol.get("maxAgeMs") {
        let clock = pol.get("now").filter(|n| !n.is_null()).cloned().unwrap_or(json!(now));
        let ok = finite(max) && finite(&clock) && {
            let age = clock.as_f64().unwrap() - observed.as_f64().unwrap_or(f64::NAN);
            age >= 0.0 && age <= max.as_f64().unwrap()
        };
        if !ok {
            return denied("attestation is stale or from the future");
        }
    }
    if let Some(u) = caveat.get("url") {
        if &attestation["session"]["url"] != u {
            return denied("attested session URL does not match the caveat");
        }
    }
    if !verify_disclosed_field(attestation, disclosure, &caveat["notary"]) {
        return denied("disclosed field does not verify under the attested root");
    }
    if !canonical_equal(&disclosure["path"], &caveat["path"]) {
        return denied("disclosed field is not the path the caveat requires");
    }
    if !caveat.get("equals").is_some_and(|e| canonical_equal(&disclosure["value"], e)) {
        return denied("disclosed field value does not satisfy the caveat");
    }
    if truthy(caveat.get("bindToPcActn")) {
        if !truthy(pc_actn) {
            return denied("caveat requires PCActn binding but no PCActn was supplied");
        }
        if !fact_matches_pc_actn(attestation, pc_actn.unwrap()) {
            return denied("fact is not bound to this PCActn");
        }
    }
    json!({ "ok": true, "trust": "notary-trusted" })
}

/// Type guard: a bare caveat object is an attested-fact caveat.
pub fn is_attested_fact_caveat(cv: &Value) -> bool {
    cv["type"] == ATTESTED_FACT_CAVEAT && cv["notary"].is_string() && cv["path"].is_array()
}
