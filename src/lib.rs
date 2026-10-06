//! Reference verifier for the CORE PCActn checks (M0-M3): capability chain, Merkle plan
//! inclusion, Ed25519 leaf signature, counter. Byte-matches `@atlasauth/pca` and the Go reference verifier.

use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::{alphabet, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write;

pub use serde_json;

const SIG_DOMAIN: &[u8] = b"atlas-pca/actn/v1\x00";
const CAP_DOMAIN: &[u8] = b"atlas-pca/cap/v1\x00";
const DEFAULT_REV: &str = "reversible";

// base64url, no padding on output; lenient trailing bits on input (matches Go's RawURLEncoding).
const B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);

fn b64_encode(b: &[u8]) -> String {
    B64.encode(b)
}

/// Decode like Go's `base64.RawURLEncoding.DecodeString` (which skips \r and \n).
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    B64.decode(cleaned.as_bytes()).ok()
}

/// Verdict for the core checks. `checks[name]` is true when it passed.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub allow: bool,
    /// Keys: chain, plan_inclusion, leaf_signature, counter (plus version failures fold into reason only).
    pub checks: BTreeMap<String, bool>,
    pub reason: String,
}

// ---- canonicalization ------------------------------------------------------------------

/// Canonical JSON: keys sorted by UTF-16 code units (recursively), compact, JS string escaping,
/// numbers rendered as shortest round-trip decimal (no exponent), `-0` -> `0`.
pub fn canonicalize(v: &Value) -> String {
    let mut s = String::new();
    ser(&mut s, v);
    s
}

fn js_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn fmt_number(n: &serde_json::Number) -> String {
    // Go parses every literal to float64 then formats with 'f', -1; do the same.
    let f = n.as_f64().unwrap_or(0.0);
    if f == 0.0 {
        return "0".to_string();
    }
    // Rust's Display for f64 is shortest round-trip and never uses exponent notation.
    format!("{}", f)
}

fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn ser(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::String(s) => js_string(out, s),
        Value::Number(n) => out.push_str(&fmt_number(n)),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                ser(out, x);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                js_string(out, k);
                out.push(':');
                ser(out, &m[k.as_str()]);
            }
            out.push('}');
        }
    }
}

fn sha(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}

/// base64url-nopad(sha256(canonical(v))).
pub fn hash_canonical(v: &Value) -> String {
    b64_encode(&sha(canonicalize(v).as_bytes()))
}

// ---- Merkle ----------------------------------------------------------------------------

fn leaf_hash(leaf: &Value) -> Vec<u8> {
    let mut m = vec![0x00u8];
    m.extend_from_slice(canonicalize(leaf).as_bytes());
    sha(&m)
}

fn node_hash(l: &[u8], r: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(1 + l.len() + r.len());
    m.push(0x01);
    m.extend_from_slice(l);
    m.extend_from_slice(r);
    sha(&m)
}

fn split(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

fn build(hs: &[Vec<u8>]) -> Vec<u8> {
    if hs.len() == 1 {
        return hs[0].clone();
    }
    let k = split(hs.len());
    node_hash(&build(&hs[..k]), &build(&hs[k..]))
}

/// RFC-6962-shaped Merkle root (split at the largest power of two < n).
pub fn merkle_root(leaves: &[Value]) -> Result<String, String> {
    if leaves.is_empty() {
        return Err("empty leaf set".into());
    }
    let hs: Vec<Vec<u8>> = leaves.iter().map(leaf_hash).collect();
    Ok(b64_encode(&build(&hs)))
}

/// Never panics; malformed proofs return false.
pub fn verify_inclusion(root: &str, proof: Option<&Map<String, Value>>, leaf: &Value) -> bool {
    let path = match proof.and_then(|p| p.get("path")).and_then(Value::as_array) {
        Some(p) => p,
        None => return false,
    };
    let mut h = leaf_hash(leaf);
    for s in path {
        let step = match s.as_object() {
            Some(s) => s,
            None => return false,
        };
        let side = step.get("side").and_then(Value::as_str).unwrap_or("");
        let hs = step.get("hash").and_then(Value::as_str).unwrap_or("");
        if side != "L" && side != "R" {
            return false;
        }
        let sib = match b64_decode(hs) {
            Some(b) => b,
            None => return false,
        };
        h = if side == "L" { node_hash(&sib, &h) } else { node_hash(&h, &sib) };
    }
    b64_encode(&h) == root
}

/// hashCanonical(params ?? {}).
pub fn params_digest(params: Option<&Value>) -> String {
    match params {
        Some(p) if !p.is_null() => hash_canonical(p),
        _ => hash_canonical(&Value::Object(Map::new())),
    }
}

fn conditions_digest_default() -> String {
    let mut m = Map::new();
    m.insert("pre".into(), Value::Null);
    m.insert("post".into(), Value::Null);
    hash_canonical(&Value::Object(m))
}

fn plan_leaf(node_id: Option<&Value>, action: Option<&Map<String, Value>>, cond: &str) -> Option<Value> {
    let node_id = match node_id {
        Some(v) if !v.is_null() => v.clone(),
        _ => return None,
    };
    let get = |k: &str| action.and_then(|a| a.get(k)).cloned().unwrap_or(Value::Null);
    let pd = match get("params_digest") {
        Value::Null => Value::String(params_digest(None)),
        v => v,
    };
    let rc = match get("reversibility_class") {
        Value::Null => Value::String(DEFAULT_REV.into()),
        v => v,
    };
    let mut m = Map::new();
    m.insert("node_id".into(), node_id);
    m.insert("verb".into(), get("verb"));
    m.insert("resource".into(), get("resource"));
    m.insert("params_digest".into(), pd);
    m.insert("reversibility_class".into(), rc);
    m.insert("conditions".into(), Value::String(cond.to_string()));
    Some(Value::Object(m))
}

// ---- keys ------------------------------------------------------------------------------

fn verify_b64u(pubkey: &str, msg: &[u8], sig: &str) -> bool {
    let pk = match b64_decode(pubkey) {
        Some(b) => b,
        None => return false,
    };
    let pk: [u8; 32] = match pk.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sg = match b64_decode(sig) {
        Some(b) => b,
        None => return false,
    };
    let sg: [u8; 64] = match sg.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(&pk) {
        Ok(v) => v,
        Err(_) => return false,
    };
    vk.verify_strict_compat(msg, &Signature::from_bytes(&sg))
}

/// Cofactorless verification (like Go's crypto/ed25519): rejects S >= L, accepts non-canonical R.
trait VerifyCompat {
    fn verify_strict_compat(&self, msg: &[u8], sig: &Signature) -> bool;
}
impl VerifyCompat for VerifyingKey {
    fn verify_strict_compat(&self, msg: &[u8], sig: &Signature) -> bool {
        use ed25519_dalek::Verifier;
        self.verify(msg, sig).is_ok()
    }
}

// ---- capability chain ------------------------------------------------------------------

/// Hash of the full capability, including its signature.
pub fn cap_hash(c: &Value) -> String {
    hash_canonical(c)
}

fn body_of(c: &Map<String, Value>) -> Value {
    let g = |k: &str| c.get(k).cloned().unwrap_or(Value::Null);
    let mut m = Map::new();
    m.insert("issuer".into(), g("issuer"));
    m.insert("holder".into(), g("holder"));
    m.insert("caveats".into(), g("caveats"));
    m.insert("parent".into(), g("parent"));
    Value::Object(m)
}

fn str_of<'a>(c: &'a Map<String, Value>, k: &str) -> &'a str {
    c.get(k).and_then(Value::as_str).unwrap_or("")
}

fn check_sig(c: &Map<String, Value>, signer: &str, label: &str) -> Option<String> {
    let digest = hash_canonical(&body_of(c));
    let bd = str_of(c, "body_digest");
    let id = str_of(c, "id");
    if digest != bd || id != bd {
        return Some(format!("{label}: body digest mismatch"));
    }
    let msg = b64_decode(bd).map(|d| {
        let mut m = CAP_DOMAIN.to_vec();
        m.extend_from_slice(&d);
        m
    });
    match msg {
        Some(msg) if verify_b64u(signer, &msg, str_of(c, "sig")) => None,
        _ => Some(format!("{label}: bad signature (not signed by expected key)")),
    }
}

/// Mirrors verifyChain in capability.ts. `Ok(())` when valid, else `Err(reason)`.
pub fn verify_chain(chain: &[Value], expected_root_issuer: Option<&str>) -> Result<(), String> {
    if chain.is_empty() {
        return Err("empty chain".into());
    }
    let root = chain[0].as_object().ok_or("hop 0: malformed")?;
    if root.contains_key("parent") {
        return Err("hop 0: root must not have a parent".into());
    }
    if let Some(exp) = expected_root_issuer {
        if root.get("issuer").and_then(Value::as_str) != Some(exp) {
            return Err("hop 0: root issuer is not the expected principal".into());
        }
    }
    if let Some(e) = check_sig(root, str_of(root, "issuer"), "hop 0") {
        return Err(e);
    }
    for i in 1..chain.len() {
        let label = format!("hop {i}");
        let (parent, c) = match (chain[i - 1].as_object(), chain[i].as_object()) {
            (Some(p), Some(c)) => (p, c),
            _ => return Err(format!("{label}: malformed")),
        };
        let ph = cap_hash(&chain[i - 1]);
        if c.get("parent").and_then(Value::as_str) != Some(ph.as_str()) {
            return Err(format!("{label}: broken parent link"));
        }
        // Go compares interface values: both must be equal (same type + value).
        if c.get("issuer") != parent.get("holder") {
            return Err(format!("{label}: issuer is not the parent's bound holder"));
        }
        if let Some(e) = check_sig(c, str_of(parent, "holder"), &label) {
            return Err(e);
        }
        let empty = Vec::new();
        let pc = parent.get("caveats").and_then(Value::as_array).unwrap_or(&empty);
        let cc = c.get("caveats").and_then(Value::as_array).unwrap_or(&empty);
        if cc.len() < pc.len() {
            return Err(format!("{label}: drops parent caveat(s)"));
        }
        for j in 0..pc.len() {
            if hash_canonical(&cc[j]) != hash_canonical(&pc[j]) {
                return Err(format!("{label}: caveat {j} altered or reordered"));
            }
        }
    }
    Ok(())
}

// ---- PCActn ----------------------------------------------------------------------------

/// SIG_DOMAIN || sha256(canonical(pcactn without `sig` and `threshold`)).
pub fn threshold_message(p: &Map<String, Value>) -> Vec<u8> {
    let mut body = Map::new();
    for (k, v) in p {
        if k != "sig" && k != "threshold" {
            body.insert(k.clone(), v.clone());
        }
    }
    let mut m = SIG_DOMAIN.to_vec();
    m.extend_from_slice(&sha(canonicalize(&Value::Object(body)).as_bytes()));
    m
}

/// Checks version, capability chain, plan inclusion, leaf signature and counter.
/// Later-milestone checks (attestation, threshold, revocation, ...) are out of scope.
pub fn verify_pcactn_core(pcactn: &Value, grant: &Value) -> Verdict {
    let mut checks: BTreeMap<String, bool> = BTreeMap::new();
    for k in ["chain", "plan_inclusion", "leaf_signature", "counter"] {
        checks.insert(k.into(), false);
    }
    let mut failed = false;
    let mut reason = String::new();
    let mut fail = |checks: &mut BTreeMap<String, bool>, name: &str, why: &str| {
        failed = true;
        checks.insert(name.into(), false);
        if reason.is_empty() {
            reason = format!("{name}: {why}");
        }
    };

    let empty_map = Map::new();
    let p = match pcactn.as_object() {
        Some(p) => p,
        None => {
            return Verdict {
                allow: false,
                checks,
                reason: "malformed PCActn: not an object".into(),
            }
        }
    };

    if p.get("ver").and_then(Value::as_u64) != Some(1) || !p.get("ver").map_or(false, |v| v.is_u64()) {
        fail(&mut checks, "version", "unsupported ver");
    }

    let empty_vec = Vec::new();
    let chain = p.get("cap_chain").and_then(Value::as_array).unwrap_or(&empty_vec);
    if chain.is_empty() {
        fail(&mut checks, "chain", "empty chain");
    } else {
        // A non-object root hashes like Go's nil map ("{}").
        let root_hash = if chain[0].is_object() {
            cap_hash(&chain[0])
        } else {
            cap_hash(&Value::Object(Map::new()))
        };
        if root_hash != cap_hash(grant) {
            fail(&mut checks, "chain", "chain root is not the grant");
        } else {
            let gi = grant.get("issuer").and_then(Value::as_str);
            match verify_chain(chain, gi) {
                Ok(()) => {
                    checks.insert("chain".into(), true);
                }
                Err(why) => fail(&mut checks, "chain", &why),
            }
        }
    }

    let plan = p.get("plan").and_then(Value::as_object).unwrap_or(&empty_map);
    let action = p.get("action").and_then(Value::as_object);
    let cond = plan
        .get("conditions_digest")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(conditions_digest_default);
    let root = plan.get("root").and_then(Value::as_str).unwrap_or("");
    let proof = plan.get("inclusion_proof").and_then(Value::as_object);
    let ok = plan_leaf(plan.get("node_id"), action, &cond)
        .map(|leaf| verify_inclusion(root, proof, &leaf))
        .unwrap_or(false);
    if ok {
        checks.insert("plan_inclusion".into(), true);
    } else {
        fail(&mut checks, "plan_inclusion", "action is not a node of the committed plan");
    }

    let leaf_msg = "signature does not verify under the leaf holder key";
    if let Some(leaf_cap) = chain.last() {
        let holder = leaf_cap.get("holder").and_then(Value::as_str).unwrap_or("");
        let msg = threshold_message(p);
        match p.get("sig").and_then(Value::as_str) {
            Some(sig) if verify_b64u(holder, &msg, sig) => {
                checks.insert("leaf_signature".into(), true);
            }
            _ => fail(&mut checks, "leaf_signature", leaf_msg),
        }
    } else {
        fail(&mut checks, "leaf_signature", leaf_msg);
    }

    match p.get("counter").and_then(Value::as_i64) {
        Some(i) if i >= 0 => {
            checks.insert("counter".into(), true);
        }
        _ => fail(&mut checks, "counter", "missing or not a non-negative integer"),
    }

    Verdict { allow: !failed, checks, reason }
}
