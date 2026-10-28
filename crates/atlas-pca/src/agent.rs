//! The agent / issuer side of PCA: produce the proofs this crate's verifier checks. Same wire as the TypeScript reference
//! (`mintGrant`, `delegate`, `buildPCActn`, `signEscalationAnswer`, `signDischarge`, `signPassport`, `signWorkflow`, ...),
//! BYTE-exact wherever the algorithm is deterministic (Ed25519, canonical JSON, digests, chain structure); the shared
//! producer vectors (`producer-vectors.json`: fixed keys, nonces and timestamps) pin it.
//!
//! Everything is `serde_json::Value` (the shapes the verifier takes) and every producer returns `Result<_, String>`.
//! Signing: Ed25519, and ML-DSA-65 / ML-DSA-87 (`fips204`) and SLH-DSA-SHA2-128f / 256s (`fips205`) with their hybrid and nested-hybrid suites ( randomised, so they are
//! cross-verified rather than compared byte for byte). FN-DSA signs with the `fndsa-sign` feature; LESS is verify-only here
//! (`unsupported_suite: <alg>`).

use crate::{
    canonicalize, canonicalize_strict, hash_canonical_strict, params_digest, serde_json::json, threshold_message,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use fips204::traits::{KeyGen, SerDes, Signer as PqSigner};
use fips205::traits::{KeyGen as SlhKeyGen, SerDes as SlhSerDes, Signer as SlhSigner};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

pub const PCA_HEADER: &str = "PCA-Action";
/// Lifetime the agent client stamps on a PCActn (20 minutes).
pub const DEFAULT_TTL_MS: i64 = 20 * 60_000;

fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}
fn sha(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}
fn rand_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| e.to_string())?;
    Ok(b)
}
fn strict_hash(v: &Value) -> Result<String, String> {
    hash_canonical_strict(v).ok_or_else(|| "value is outside the strict JSON profile".to_string())
}
fn strict_bytes(v: &Value) -> Result<Vec<u8>, String> {
    canonicalize_strict(v).map(String::into_bytes)
}
fn obj(v: &Value) -> Result<&Map<String, Value>, String> {
    v.as_object().ok_or_else(|| "expected a JSON object".to_string())
}
fn s_of<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k).and_then(|x| x.as_str()).ok_or_else(|| format!("missing string member `{k}`"))
}

/// DEFAULT risk policy a grant carries when the issuer sets none.
pub fn default_risk_policy() -> Value {
    json!({"weights": {"alpha": 0.25, "beta": 0.2, "gamma": 0.2, "delta": 0.2, "epsilon": 0.1, "zeta": 0.05},
           "theta1": 0.25, "theta2": 0.6, "kappa": 1, "lambda": 0.0005, "rho": 0.5, "bMax": 1})
}

// ---- keys ------------------------------------------------------------------------------------------------------------

/// An Ed25519 identity; `public` is the base64url key id every artifact names.
pub struct KeyPair {
    key: SigningKey,
    pub public: String,
}
impl KeyPair {
    pub fn generate() -> Result<KeyPair, String> {
        Ok(KeyPair::from_seed(&rand_bytes::<32>()?))
    }
    pub fn from_seed(seed: &[u8; 32]) -> KeyPair {
        let key = SigningKey::from_bytes(seed);
        let public = b64(key.verifying_key().as_bytes());
        KeyPair { key, public }
    }
    pub fn from_seed_b64u(seed: &str) -> Result<KeyPair, String> {
        let b = crate::decode_b64u_strict(seed, Some(32)).ok_or("an Ed25519 seed is 32 canonical base64url bytes")?;
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        Ok(KeyPair::from_seed(&a))
    }
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.key.sign(msg).to_bytes().to_vec()
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyPair {{ public: {} }}", self.public) // never print the secret
    }
}

enum PqSk {
    M65(fips204::ml_dsa_65::PrivateKey),
    M87(fips204::ml_dsa_87::PrivateKey),
    S128(fips205::slh_dsa_sha2_128f::PrivateKey),
    S256(fips205::slh_dsa_sha2_256s::PrivateKey),
    #[cfg(feature = "fndsa-sign")]
    Fn(Vec<u8>),
}
/// An ML-DSA or SLH-DSA key pair (`public` is the base64url `pq_pk` a suite binds into the signed body).
pub struct PqKeyPair {
    family: &'static str,
    sk: PqSk,
    pub public: String,
}
impl PqKeyPair {
    /// `family`: "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128f" or "SLH-DSA-SHA2-256s".
    pub fn generate(family: &str) -> Result<PqKeyPair, String> {
        match family {
            "ML-DSA-65" => {
                let (pk, sk) = fips204::ml_dsa_65::KG::try_keygen().map_err(|e| e.to_string())?;
                Ok(PqKeyPair { family: "ML-DSA-65", sk: PqSk::M65(sk), public: b64(&pk.into_bytes()) })
            }
            "ML-DSA-87" => {
                let (pk, sk) = fips204::ml_dsa_87::KG::try_keygen().map_err(|e| e.to_string())?;
                Ok(PqKeyPair { family: "ML-DSA-87", sk: PqSk::M87(sk), public: b64(&pk.into_bytes()) })
            }
            "SLH-DSA-SHA2-128f" => {
                let (pk, sk) = fips205::slh_dsa_sha2_128f::KG::try_keygen().map_err(|e| e.to_string())?;
                Ok(PqKeyPair { family: "SLH-DSA-SHA2-128f", sk: PqSk::S128(sk), public: b64(&pk.into_bytes()) })
            }
            "SLH-DSA-SHA2-256s" => {
                let (pk, sk) = fips205::slh_dsa_sha2_256s::KG::try_keygen().map_err(|e| e.to_string())?;
                Ok(PqKeyPair { family: "SLH-DSA-SHA2-256s", sk: PqSk::S256(sk), public: b64(&pk.into_bytes()) })
            }
            #[cfg(feature = "fndsa-sign")]
            "FN-DSA-512" | "FN-DSA-1024" => {
                use fn_dsa_kgen::{sign_key_size, vrfy_key_size, KeyPairGenerator, KeyPairGeneratorStandard, FN_DSA_LOGN_1024, FN_DSA_LOGN_512};
                let (logn, name) = if family == "FN-DSA-512" { (FN_DSA_LOGN_512, "FN-DSA-512") } else { (FN_DSA_LOGN_1024, "FN-DSA-1024") };
                let mut kg = KeyPairGeneratorStandard::default();
                let (mut sk, mut vk) = (vec![0u8; sign_key_size(logn)], vec![0u8; vrfy_key_size(logn)]);
                kg.keygen(logn, &mut rand_core::OsRng, &mut sk, &mut vk);
                Ok(PqKeyPair { family: name, sk: PqSk::Fn(sk), public: b64(&vk) })
            }
            f => Err(format!("unsupported_suite: {f}")),
        }
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        match &self.sk {
            PqSk::M65(k) => k.try_sign(msg, &[]).map(|s| s.to_vec()).map_err(|e| e.to_string()),
            PqSk::M87(k) => k.try_sign(msg, &[]).map(|s| s.to_vec()).map_err(|e| e.to_string()),
            // hedged (randomised), empty context: what the verifiers accept
            PqSk::S128(k) => k.try_sign(msg, &[], true).map(|s| s.to_vec()).map_err(|e| e.to_string()),
            PqSk::S256(k) => k.try_sign(msg, &[], true).map(|s| s.to_vec()).map_err(|e| e.to_string()),
            #[cfg(feature = "fndsa-sign")]
            PqSk::Fn(k) => {
                use fn_dsa_sign::{signature_size, SigningKey, SigningKeyStandard, DOMAIN_NONE, HASH_ID_RAW};
                let mut sk = SigningKeyStandard::decode(k).ok_or("bad FN-DSA signing key")?;
                let mut sig = vec![0u8; signature_size(sk.get_logn())];
                sk.sign(&mut rand_core::OsRng, &DOMAIN_NONE, &HASH_ID_RAW, msg, &mut sig);
                Ok(sig)
            }
        }
    }
}

impl std::fmt::Debug for PqKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PqKeyPair {{ family: {} }}", self.family)
    }
}

/// Signature suite of an artifact; `Suite::default()` is ed25519 (byte-identical to the pre-agility wire).
#[derive(Default)]
pub struct Suite<'a> {
    pub alg: Option<&'a str>,
    pub pq: Option<&'a PqKeyPair>,
}
impl Suite<'_> {
    fn alg(&self) -> &str {
        self.alg.unwrap_or("ed25519")
    }
}

/// (family needed, needs pq_sig, nested) of a suite this module can sign.
fn suite_shape(alg: &str) -> Result<Option<(&'static str, bool, bool)>, String> {
    Ok(match alg {
        "ed25519" => None,
        "ml-dsa-65" => Some(("ML-DSA-65", false, false)),
        "hybrid-ed25519-ml-dsa-65" => Some(("ML-DSA-65", true, false)),
        "hybrid-nested-ed25519-ml-dsa-65" => Some(("ML-DSA-65", true, true)),
        "ml-dsa-87" => Some(("ML-DSA-87", false, false)),
        "hybrid-ed25519-ml-dsa-87" => Some(("ML-DSA-87", true, false)),
        "slh-dsa-sha2-128f" => Some(("SLH-DSA-SHA2-128f", false, false)),
        "hybrid-ed25519-slh-dsa-sha2-128f" => Some(("SLH-DSA-SHA2-128f", true, false)),
        "slh-dsa-sha2-256s" => Some(("SLH-DSA-SHA2-256s", false, false)),
        "hybrid-ed25519-slh-dsa-sha2-256s" => Some(("SLH-DSA-SHA2-256s", true, false)),
        #[cfg(feature = "fndsa-sign")]
        "fn-dsa-512" => Some(("FN-DSA-512", false, false)),
        #[cfg(feature = "fndsa-sign")]
        "fn-dsa-1024" => Some(("FN-DSA-1024", false, false)),
        a if crate::REGISTERED_SUITES.contains(&a) => return Err(format!("unsupported_suite: {a}")),
        a => return Err(format!("unknown signature alg {a:?}")),
    })
}

/// (sig, pq_sig) of `msg` under the suite.
fn sign_with_suite(s: &Suite, ed: Option<&KeyPair>, msg: &[u8]) -> Result<(String, Option<String>), String> {
    let alg = s.alg();
    match suite_shape(alg)? {
        None => Ok((b64(&ed.ok_or("ed25519 needs an Ed25519 key")?.sign(msg)), None)),
        Some((family, hybrid, nested)) => {
            let pq = s.pq.filter(|p| p.family == family).ok_or_else(|| format!("{alg} needs a {family} key pair"))?;
            if !hybrid {
                return Ok((b64(&pq.sign(msg)?), None));
            }
            let e = ed.ok_or_else(|| format!("{alg} needs an Ed25519 key"))?.sign(msg);
            let mut pm = msg.to_vec();
            if nested {
                pm.extend_from_slice(&e);
            }
            Ok((b64(&e), Some(b64(&pq.sign(&pm)?))))
        }
    }
}

fn bind_suite(body: &Value, s: &Suite) -> Result<Map<String, Value>, String> {
    let mut m = obj(body)?.clone();
    if s.alg() != "ed25519" {
        suite_shape(s.alg())?; // an unsupported or unknown suite is named before a missing key pair is
        let pq = s.pq.ok_or("a post-quantum suite needs a key pair")?;
        m.insert("alg".into(), json!(s.alg()));
        m.insert("pq_pk".into(), json!(pq.public));
    }
    Ok(m)
}

/// body + `sig` (and `alg`/`pq_pk`/`pq_sig` for a non-default suite); the signature covers utf8(domain) || strictCanonical(body).
pub fn sign_artifact(domain: &str, body: &Value, ed: &KeyPair, s: &Suite) -> Result<Value, String> {
    let mut m = bind_suite(body, s)?;
    let mut msg = domain.as_bytes().to_vec();
    msg.extend(strict_bytes(&Value::Object(m.clone()))?);
    let (sig, pq_sig) = sign_with_suite(s, Some(ed), &msg)?;
    m.insert("sig".into(), json!(sig));
    if let Some(p) = pq_sig {
        m.insert("pq_sig".into(), json!(p));
    }
    Ok(Value::Object(m))
}

fn sign_body(ed: &KeyPair, domain: &str, body: &Value) -> Result<String, String> {
    let mut msg = domain.as_bytes().to_vec();
    msg.extend(strict_bytes(body)?);
    Ok(b64(&ed.sign(&msg)))
}

// ---- capability chain --------------------------------------------------------------------------------------------------

/// Salted commitment to the plaintext goal: base64url(sha256(canonical({d, goal, salt}))).
pub fn goal_commit_of(goal: &str, salt: &str) -> Result<String, String> {
    strict_hash(&json!({"d": "atlas-pca/goal/v1\0", "goal": goal, "salt": salt}))
}

fn holder_pq_commitment(pq_pk: &str) -> String {
    let mut m = b"atlas-pca/holder-pq/v1\0".to_vec();
    m.extend_from_slice(pq_pk.as_bytes());
    b64(&sha(&m))
}

fn seal(issuer: &str, holder: &str, caveats: Value, parent: Option<String>, holder_pq: Option<String>, ed: &KeyPair, s: &Suite) -> Result<Value, String> {
    let mut body = Map::new();
    body.insert("issuer".into(), json!(issuer));
    body.insert("holder".into(), json!(holder));
    body.insert("caveats".into(), caveats.clone());
    body.insert("parent".into(), parent.as_ref().map_or(Value::Null, |p| json!(p)));
    if let Some(h) = &holder_pq {
        body.insert("holder_pq".into(), json!(h));
    }
    let signable = bind_suite(&Value::Object(body), s)?;
    let digest = strict_hash(&Value::Object(signable))?;
    let raw = crate::decode_b64u_strict(&digest, Some(32)).ok_or("internal: digest")?;
    let mut msg = b"atlas-pca/cap/v1\0".to_vec();
    msg.extend(raw);
    let (sig, pq_sig) = sign_with_suite(s, Some(ed), &msg)?;
    let mut cap = Map::new();
    cap.insert("id".into(), json!(digest));
    cap.insert("issuer".into(), json!(issuer));
    cap.insert("holder".into(), json!(holder));
    cap.insert("caveats".into(), caveats);
    cap.insert("body_digest".into(), json!(digest));
    cap.insert("sig".into(), json!(sig));
    if let Some(p) = parent {
        cap.insert("parent".into(), json!(p));
    }
    if let Some(h) = holder_pq {
        cap.insert("holder_pq".into(), json!(h));
    }
    if s.alg() != "ed25519" {
        cap.insert("alg".into(), json!(s.alg()));
        cap.insert("pq_pk".into(), json!(s.pq.ok_or("missing pq key")?.public));
        if let Some(p) = pq_sig {
            cap.insert("pq_sig".into(), json!(p));
        }
    }
    Ok(Value::Object(cap))
}

fn clone_caveats(v: &Value) -> Result<Value, String> {
    let t = strict_bytes(v)?;
    serde_json::from_slice(&t).map_err(|e| e.to_string())
}

/// A root capability signed by the principal. `holder_pq` is the holder's PQ public key (b64u), committed as `holder_pq`.
pub fn mint_root(principal: &KeyPair, holder: &str, caveats: &Value, holder_pq: Option<&str>, s: &Suite) -> Result<Value, String> {
    seal(&principal.public, holder, clone_caveats(caveats)?, None, holder_pq.map(holder_pq_commitment), principal, s)
}

/// A child capability: caveats = parent.caveats ++ added (append-only, so never wider), signed by the parent's holder.
/// `to_holder` None keeps the holder (and its `holder_pq`); otherwise it is rebound to a sub-agent.
pub fn delegate(parent: &Value, signer: &KeyPair, to_holder: Option<&str>, added: &Value, holder_pq: Option<&str>, s: &Suite) -> Result<Value, String> {
    let ph = s_of(parent, "holder")?;
    let holder = to_holder.unwrap_or(ph);
    let hp = match holder_pq {
        Some(p) => Some(holder_pq_commitment(p)),
        None if holder == ph => parent.get("holder_pq").and_then(|x| x.as_str()).map(String::from),
        None => None,
    };
    let mut cav = clone_caveats(parent.get("caveats").ok_or("parent has no caveats")?)?.as_array().cloned().ok_or("caveats not an array")?;
    cav.extend(clone_caveats(added)?.as_array().cloned().ok_or("added caveats not an array")?);
    let parent_hash = strict_hash(parent)?;
    seal(ph, holder, Value::Array(cav), Some(parent_hash), hp, signer, s)
}

/// Like [`delegate`] with the same holder.
pub fn attenuate(parent: &Value, added: &Value, signer: &KeyPair, s: &Suite) -> Result<Value, String> {
    delegate(parent, signer, None, added, None, s)
}

fn risk_policy_error(p: &Value) -> Option<String> {
    let w = match p.get("weights") {
        Some(w) if w.is_object() => w,
        _ => return Some("risk_policy.weights missing".into()),
    };
    for k in ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"] {
        if !w.get(k).and_then(|x| x.as_f64()).is_some_and(|x| x >= 0.0) {
            return Some(format!("risk_policy.weights.{k} must be finite and >= 0"));
        }
    }
    let f = |k: &str| p.get(k).and_then(|x| x.as_f64());
    for k in ["theta1", "theta2", "kappa", "lambda", "rho", "bMax"] {
        if f(k).is_none() {
            return Some(format!("risk_policy.{k} must be finite"));
        }
    }
    let (t1, t2) = (f("theta1")?, f("theta2")?);
    if t1 < 0.0 || t2 < t1 {
        return Some("risk_policy requires 0 <= theta1 <= theta2".into());
    }
    if f("kappa")? <= 0.0 {
        return Some("risk_policy.kappa must be > 0".into());
    }
    if f("lambda")? < 0.0 || f("rho")? < 0.0 || f("bMax")? < 0.0 {
        return Some("risk_policy lambda/rho/bMax must be >= 0".into());
    }
    None
}

/// A minted root intent grant with the commitment to its goal.
pub struct MintedGrant {
    pub grant: Value,
    pub goal_commit: String,
    pub goal_salt: String,
}

/// Root Intent Grant: a root capability whose first caveat is the policy envelope (`predicates`, `caveats`, `agent_binding`,
/// `risk_policy`, optional `units`/`tighten`/`actions`/...). Only the salted hash of `goal` goes in the grant. `salt` None draws
/// 16 random bytes. Shortcut: the optional envelope members are signed as given; the verifier refuses a malformed one.
pub fn mint_grant(principal: &KeyPair, holder: &str, envelope: &Value, goal: &str, salt: Option<&str>, holder_pq: Option<&str>, s: &Suite) -> Result<MintedGrant, String> {
    if goal.is_empty() {
        return Err("mint_grant: goal required".into());
    }
    for k in ["predicates", "caveats", "risk_policy"] {
        if envelope.get(k).is_none() {
            return Err(format!("mint_grant: envelope.{k} required"));
        }
    }
    if let Some(e) = risk_policy_error(&envelope["risk_policy"]) {
        return Err(format!("mint_grant: {e}"));
    }
    if envelope.get("model_polarity").is_some_and(|m| *m != "legacy") {
        return Err("mint_grant: model_polarity must be 'legacy' when present".into());
    }
    let salt = match salt {
        Some(s) => s.to_string(),
        None => b64(&rand_bytes::<16>()?),
    };
    let commit = goal_commit_of(goal, &salt)?;
    let mut env = Map::new();
    env.insert("type".into(), json!("envelope"));
    env.insert("goal_commit".into(), json!(commit));
    for k in ["predicates", "caveats", "risk_policy"] {
        env.insert(k.into(), envelope[k].clone());
    }
    env.insert("agent_binding".into(), envelope.get("agent_binding").filter(|v| !v.is_null()).cloned().unwrap_or_else(|| json!({})));
    for k in ["objective_risk", "progress", "units", "tighten", "model_polarity", "template_ref", "actions"] {
        if let Some(v) = envelope.get(k).filter(|v| !v.is_null()) {
            env.insert(k.into(), v.clone());
        }
    }
    let grant = mint_root(principal, holder, &Value::Array(vec![Value::Object(env)]), holder_pq, s)?;
    Ok(MintedGrant { grant, goal_commit: commit, goal_salt: salt })
}

// ---- plan + PCActn -----------------------------------------------------------------------------------------------------

fn cond_digest(node: &Value) -> Result<String, String> {
    let n = |k: &str| node.get(k).cloned().unwrap_or(Value::Null);
    let b = sha(&strict_bytes(&json!({"pre": n("pre"), "post": n("post")}))?);
    Ok(b64(&b))
}

fn node_leaf(node: &Value) -> Result<Value, String> {
    let pd = match node.get("params_digest").and_then(|x| x.as_str()) {
        Some(p) => p.to_string(),
        None => params_digest(None),
    };
    Ok(json!({"node_id": node["id"], "verb": node["verb"], "resource": node["resource"], "params_digest": pd,
              "reversibility_class": node.get("reversibility_class").filter(|v| !v.is_null()).cloned().unwrap_or(json!("reversible")),
              "conditions": cond_digest(node)?}))
}

fn leaf_h(leaf: &Value) -> Result<Vec<u8>, String> {
    let mut m = vec![0u8];
    m.extend(strict_bytes(leaf)?);
    Ok(sha(&m))
}
fn node_h(l: &[u8], r: &[u8]) -> Vec<u8> {
    let mut m = vec![1u8];
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
    node_h(&build(&hs[..k]), &build(&hs[k..]))
}
fn prove(hs: &[Vec<u8>], idx: usize, out: &mut Vec<Value>) {
    if hs.len() == 1 {
        return;
    }
    let k = split(hs.len());
    if idx < k {
        prove(&hs[..k], idx, out);
        out.push(json!({"side": "R", "hash": b64(&build(&hs[k..]))}));
    } else {
        prove(&hs[k..], idx - k, out);
        out.push(json!({"side": "L", "hash": b64(&build(&hs[..k]))}));
    }
}

fn plan_hashes(nodes: &[Value]) -> Result<Vec<Vec<u8>>, String> {
    if nodes.is_empty() {
        return Err("commit_plan: empty plan".into());
    }
    let mut seen = std::collections::HashSet::new();
    for n in nodes {
        if !seen.insert(s_of(n, "id")?.to_string()) {
            return Err(format!("commit_plan: duplicate node id {}", s_of(n, "id")?));
        }
    }
    nodes.iter().map(|n| leaf_h(&node_leaf(n)?)).collect()
}
/// Merkle commitment of a plan (RFC 6962 shape, domain separated) as `{root, proofs: {id: proof}}`. A node is
/// `{id, verb, resource, params_digest?, reversibility_class?, pre?, post?}`.
pub fn plan_commit(nodes: &[Value]) -> Result<Value, String> {
    let hs = plan_hashes(nodes)?;
    let mut proofs = Map::new();
    for (i, n) in nodes.iter().enumerate() {
        let mut path = vec![];
        prove(&hs, i, &mut path);
        proofs.insert(s_of(n, "id")?.to_string(), json!({"index": i, "size": hs.len(), "path": path}));
    }
    Ok(json!({"root": b64(&build(&hs)), "proofs": proofs}))
}

/// Sign a PCActn body (without `sig`) with the leaf holder's key under the suite.
pub fn sign_pcactn(body: &Value, leaf: &KeyPair, s: &Suite) -> Result<Value, String> {
    let mut m = bind_suite(body, s)?;
    let msg = threshold_message(&m)?;
    let (sig, pq_sig) = sign_with_suite(s, Some(leaf), &msg)?;
    m.insert("sig".into(), json!(sig));
    if let Some(p) = pq_sig {
        m.insert("pq_sig".into(), json!(p));
    }
    Ok(Value::Object(m))
}

/// Everything [`build_pcactn`] needs. `extra` holds the optional SIGNED slots by wire name (nonce, caution, rationale_commitment,
/// progress_step, prohibition_evidence, tool_binding, intent, intent_session, fresh_at; also provenance / attestation /
/// freshness / risk_claim to replace the empty stubs).
pub struct PcactnInput<'a> {
    pub grant: &'a Value,
    pub chain: &'a [Value],
    pub plan: &'a [Value],
    pub node_id: &'a str,
    pub params: Option<&'a Value>,
    pub counter: i64,
    pub signer: &'a KeyPair,
    pub aud: &'a str,
    pub iat: i64,
    pub exp: Option<i64>,
    pub extra: Map<String, Value>,
    pub suite: Suite<'a>,
}

/// A complete signed PCActn for plan node `node_id` (wire format v2).
pub fn build_pcactn(i: &PcactnInput) -> Result<Value, String> {
    if i.aud.is_empty() {
        return Err("build_pcactn: aud (audience) is required".into());
    }
    let node = i.plan.iter().find(|n| n["id"] == i.node_id).ok_or_else(|| format!("build_pcactn: unknown plan node {}", i.node_id))?;
    let digest = params_digest(i.params);
    if node.get("params_digest").and_then(|x| x.as_str()).is_some_and(|p| p != digest) {
        return Err(format!("build_pcactn: params do not match plan node {}'s params_digest", i.node_id));
    }
    let hs = plan_hashes(i.plan)?;
    let idx = i.plan.iter().position(|n| n["id"] == i.node_id).ok_or("node")?;
    let mut path = vec![];
    prove(&hs, idx, &mut path);
    let mut m = Map::new();
    m.insert("ver".into(), json!(2));
    m.insert("action".into(), json!({"verb": node["verb"], "resource": node["resource"], "params_digest": digest,
        "reversibility_class": node.get("reversibility_class").filter(|v| !v.is_null()).cloned().unwrap_or(json!("reversible"))}));
    m.insert("grant_ref".into(), i.grant["id"].clone());
    m.insert("cap_chain".into(), Value::Array(i.chain.to_vec()));
    m.insert("plan".into(), json!({"root": b64(&build(&hs)), "inclusion_proof": {"index": idx, "size": hs.len(), "path": path},
        "node_id": i.node_id, "conditions_digest": cond_digest(node)?}));
    m.insert("attestation".into(), json!({"quote_digest": "", "epoch": 0, "model_id": "unattested", "measurement": "", "operator": "unattested"}));
    m.insert("provenance".into(), json!({"causal_hash": "", "taint_level": 0, "trusted_refs": []}));
    m.insert("freshness".into(), json!({"beacon_ref": "", "epoch": 0, "accumulator_witness": ""}));
    m.insert("counter".into(), json!(i.counter));
    m.insert("risk_claim".into(), json!({"r": 0, "inputs": {}}));
    m.insert("aud".into(), json!(i.aud));
    m.insert("iat".into(), json!(i.iat));
    m.insert("exp".into(), json!(i.exp.unwrap_or(i.iat + DEFAULT_TTL_MS)));
    for (k, v) in &i.extra {
        if !v.is_null() {
            m.insert(k.clone(), v.clone());
        }
    }
    sign_pcactn(&Value::Object(m), i.signer, &i.suite)
}

/// HTTP headers the native middleware reads: `PCA-Action` (base64url of the PCActn JSON) and, when given, `PCA-Discharges`
/// (base64url JSON array), `PCA-Narrow` and `PCA-Escalation-Answer`.
pub fn pca_headers(pcactn: &Value, discharges: &[Value], narrow: Option<&Value>, escalation_answer: Option<&Value>) -> Vec<(String, String)> {
    let enc = |v: &Value| b64(canonicalize(v).as_bytes());
    let mut h = vec![(PCA_HEADER.to_string(), enc(pcactn))];
    if !discharges.is_empty() {
        h.push(("PCA-Discharges".into(), enc(&Value::Array(discharges.to_vec()))));
    }
    if let Some(n) = narrow {
        h.push(("PCA-Narrow".into(), enc(n)));
    }
    if let Some(a) = escalation_answer {
        h.push(("PCA-Escalation-Answer".into(), enc(a)));
    }
    h
}

// ---- escalation answer, discharge, narrow ------------------------------------------------------------------------------

fn nonce_or(n: Option<&str>) -> Result<String, String> {
    Ok(match n {
        Some(n) => n.to_string(),
        None => b64(&rand_bytes::<16>()?),
    })
}

/// The approving principal's signed answer ("allow" or "deny") to an escalation request; `request` carries `policy_digest`,
/// `action_digest`, `history_head` and (K7) the `render_digest` the approver saw.
pub fn sign_escalation_answer(principal: &KeyPair, request: &Value, decision: &str, iat: i64, expires_at: i64, nonce: Option<&str>, s: &Suite) -> Result<Value, String> {
    if decision != "allow" && decision != "deny" {
        return Err("decision must be 'allow' or 'deny'".into());
    }
    let mut b = json!({"v": 1, "kind": "pca-escalation-answer", "principal": principal.public,
        "policy_digest": request["policy_digest"], "action_digest": request["action_digest"], "history_head": request["history_head"],
        "decision": decision, "iat": iat, "expires_at": expires_at, "nonce": nonce_or(nonce)?});
    if let Some(r) = request.get("render_digest").filter(|v| v.is_string()) {
        b["render_digest"] = r.clone();
    }
    sign_artifact("atlas-pca/escalation-answer/v1\0", &b, principal, s)
}

/// A third-party caveat: the verifier's pin labelled `issuer` (of class `issuer_class`) must sign a discharge whose claims satisfy `require`.
pub fn needs_discharge_caveat(id: &str, issuer: &str, issuer_class: &str, bind: &str, ttl_ms: i64, require: Value) -> Value {
    json!({"type": "needs_discharge", "id": id, "issuer": issuer, "issuer_class": issuer_class, "bind": bind, "ttl_ms": ttl_ms, "require": require})
}
/// No hop may be appended below the hop that carries it.
pub fn sealed_caveat() -> Value {
    json!({"type": "sealed"})
}
/// A lifetime use count (1..256) backed by the verifier's replay store, expiring at `until` (epoch ms).
pub fn max_uses_caveat(id: &str, n: i64, until: i64) -> Value {
    json!({"type": "max_uses", "id": id, "n": n, "until": until})
}

/// The pinned third party's discharge. `action_digest` (the discharge action digest of the exact PCActn) is for `bind` "action".
#[allow(clippy::too_many_arguments)]
pub fn sign_discharge(issuer: &KeyPair, caveat_id: &str, issuer_label: &str, cap_hash: &str, bind: &str, action_digest: Option<&str>, claims: &Value, iat: i64, not_after: i64, nonce: Option<&str>, s: &Suite) -> Result<Value, String> {
    let mut b = json!({"v": 1, "kind": "pca-discharge", "caveat_id": caveat_id, "issuer": issuer_label, "cap_hash": cap_hash, "bind": bind,
        "claims": claims, "iat": iat, "not_after": not_after, "nonce": nonce_or(nonce)?});
    if let Some(a) = action_digest {
        b["action_digest"] = json!(a);
    }
    sign_artifact("atlas-pca/discharge/v1\0", &b, issuer, s)
}
/// Digest of the exact PCActn a bind-`action` discharge authorises.
pub fn discharge_action_digest(pcactn: &Value) -> Result<String, String> {
    strict_hash(&json!({"d": "atlas-pca/discharge-action/v1", "pcactn": pcactn}))
}
/// Content address of a discharge (signature included).
pub fn discharge_digest(d: &Value) -> Result<String, String> {
    strict_hash(&json!({"d": "atlas-pca/discharge-ref/v1", "discharge": d}))
}

/// The leaf holder's self-attenuation, presented beside the PCActn.
#[allow(clippy::too_many_arguments)]
pub fn sign_narrow(holder: &KeyPair, leaf_cap_hash: &str, caveats: &Value, iat: i64, not_after: i64, action_digest: Option<&str>, nonce: Option<&str>, s: &Suite) -> Result<Value, String> {
    let mut b = json!({"v": 1, "kind": "pca-narrow", "cap_hash": leaf_cap_hash, "holder": holder.public, "caveats": caveats,
        "iat": iat, "not_after": not_after, "nonce": nonce_or(nonce)?});
    if let Some(a) = action_digest {
        b["action_digest"] = json!(a);
    }
    sign_artifact("atlas-pca/narrow/v1\0", &b, holder, s)
}

// ---- passport ----------------------------------------------------------------------------------------------------------

/// Content address of the identity fields.
pub fn passport_fingerprint(p: &Value) -> Result<String, String> {
    let g = |k: &str| p.get(k).cloned().unwrap_or(Value::Null);
    strict_hash(&json!({"d": "atlas-pca/passport/v1", "model_id": g("model_id"), "weights_digest": g("weights_digest"),
        "system_prompt_digest": g("system_prompt_digest"), "tool_manifest_digest": g("tool_manifest_digest"),
        "runtime_measurement": g("runtime_measurement"), "operator": g("operator"), "hardware_rooted": g("hardware_rooted")}))
}
/// Fill `id` from the fingerprint of the identity.
pub fn issue_passport(identity: &Value) -> Result<Value, String> {
    let mut m = obj(identity)?.clone();
    m.insert("id".into(), json!(passport_fingerprint(identity)?));
    Ok(Value::Object(m))
}
/// Sign a passport for the agent key `subject`. `iat`/`nbf` None: the passport's `issued_at` (nbf: iat). A hardware_rooted
/// passport needs `evidence` (fail closed).
pub fn sign_passport(passport: &Value, issuer: &KeyPair, subject: &str, iat: Option<i64>, nbf: Option<i64>, exp: i64, evidence: Option<&Value>, s: &Suite) -> Result<Value, String> {
    if passport.get("id").and_then(|x| x.as_str()) != Some(passport_fingerprint(passport)?.as_str()) {
        return Err("sign_passport: passport.id is not the fingerprint of its identity (use issue_passport)".into());
    }
    if passport.get("hardware_rooted") == Some(&json!(true)) && evidence.is_none() {
        return Err("sign_passport: hardware_rooted requires attestation evidence (fail closed)".into());
    }
    let iat = match iat {
        Some(i) => i,
        None => passport.get("issued_at").and_then(|x| x.as_i64()).ok_or("sign_passport: passport.issued_at must be a safe integer")?,
    };
    let nbf = nbf.unwrap_or(iat);
    if exp <= nbf {
        return Err("sign_passport: exp must be after nbf".into());
    }
    let mut b = json!({"typ": "atlas-pca/passport", "ver": 1, "passport": passport, "iss": issuer.public, "sub": subject, "iat": iat, "nbf": nbf, "exp": exp});
    if let Some(e) = evidence {
        let mut ev = obj(e)?.clone();
        ev.entry("at").or_insert(json!(iat));
        b["evidence"] = Value::Object(ev);
    }
    sign_artifact("atlas-pca/passport-sig/v1\0", &b, issuer, s)
}

// ---- workflow, receipts, read grants, aggregate grants, fresh_at ---------------------------------------------------------------

fn signed_by(body: &Value, ed: &KeyPair, domain: &str, what: &str) -> Result<Value, String> {
    if body.get("principal").and_then(|x| x.as_str()) != Some(ed.public.as_str()) {
        return Err(format!("{what}: principal is not the signer"));
    }
    Ok(json!({"body": body, "sig": sign_body(ed, domain, body)?}))
}
/// The principal's signed workflow commitment `{body, sig}`; `body.principal` must be the signer.
pub fn sign_workflow(principal: &KeyPair, body: &Value) -> Result<Value, String> {
    signed_by(body, principal, "atlas-pca/workflow/v1\0", "sign_workflow")
}
/// The principal's signed read grant `{body, sig}`.
pub fn sign_read_grant(principal: &KeyPair, body: &Value) -> Result<Value, String> {
    signed_by(body, principal, "atlas-pca/read-grant/v1\0", "sign_read_grant")
}
/// The principal's signed aggregate-read grant `{body, sig}`.
pub fn sign_aggregate_grant(principal: &KeyPair, body: &Value) -> Result<Value, String> {
    signed_by(body, principal, "atlas-pca/aggregate-grant/v1\0", "sign_aggregate_grant")
}
/// A receipt output for `value` (string, bool or integer); `num` carries the integer an edge may compare.
pub fn wf_output(value: &Value, labels: &[&str], unit: Option<&str>, num: bool) -> Result<Value, String> {
    let mut ls: Vec<&str> = labels.to_vec();
    ls.sort_unstable();
    Ok(json!({"digest": crate::workflow::value_digest(value).ok_or("wf_output: not a scalar")?,
        "num": if num && value.is_i64() { value.clone() } else { Value::Null }, "unit": unit, "labels": ls}))
}
/// The resource server's signed receipt for a workflow step; `prev` is the previous receipt of the workflow.
#[allow(clippy::too_many_arguments)]
pub fn sign_step_receipt(rs: &KeyPair, workflow: &Value, step: &str, outcome: &str, params_dig: &str, outputs: &Value, issued_at: i64, prev: Option<&Value>) -> Result<Value, String> {
    let wf = crate::workflow::workflow_digest(workflow).ok_or("sign_step_receipt: malformed workflow")?;
    let (seq, pref) = match prev {
        Some(p) => (p["seq"].as_i64().ok_or("previous receipt has no seq")? + 1, json!(crate::workflow::receipt_ref(p).ok_or("malformed previous receipt")?)),
        None => (0, Value::Null),
    };
    let base = json!({"v": 1, "wf": wf, "step": step, "seq": seq, "prev": pref, "outcome": outcome, "params_digest": params_dig,
        "outputs": outputs, "issued_at": issued_at, "signer": rs.public});
    let sig = sign_body(rs, "atlas-pca/wf-receipt/v1\0", &base)?;
    let mut m = obj(&base)?.clone();
    m.insert("sig".into(), json!(sig));
    Ok(Value::Object(m))
}
/// A signed consistency token: the high-water mark of the verifier-side state a write produced.
pub fn sign_fresh_at(signer: &KeyPair, scope: &str, state: &Value, issued_at: i64) -> Result<Value, String> {
    let g = |k: &str| state.get(k).cloned().unwrap_or(Value::Null);
    let base = json!({"v": 1, "scope": scope, "revocation_epoch": g("revocation_epoch"), "ledger_tree_size": g("ledger_tree_size"),
        "budget_version": g("budget_version"), "policy_revision": g("policy_revision"), "policy_digest": g("policy_digest"),
        "issued_at": issued_at, "signer": signer.public});
    let sig = sign_body(signer, "atlas-pca/fresh-at/v1\0", &base)?;
    let mut m = obj(&base)?.clone();
    m.insert("sig".into(), json!(sig));
    Ok(Value::Object(m))
}

// ---- the high-level client ---------------------------------------------------------------------------------------------

/// One signed action: the PCActn, the headers to send and the plan node it was built for.
pub struct Action {
    pub pcactn: Value,
    pub headers: Vec<(String, String)>,
    pub node_id: String,
}

/// An agent holding a grant (or a delegated chain): keeps the replay counter, picks nonces and builds the headers.
/// Thread safe. Persist the counter if the process can restart: a lower counter is refused as a replay.
pub struct Agent {
    pub key: KeyPair,
    pub grant: Value,
    pub chain: Vec<Value>,
    pub aud: String,
    pub ttl_ms: i64,
    pub clock: fn() -> i64,
    /// Called with every counter the agent uses, before the action is signed: persist it if the process can restart.
    pub on_counter: Option<Box<dyn Fn(i64) + Send + Sync>>,
    plan: Option<Vec<Value>>,
    counter: Mutex<i64>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

impl Agent {
    /// `counter` is the last counter already used (the next action uses counter + 1).
    pub fn new(key: KeyPair, grant: Value, aud: &str, counter: i64) -> Agent {
        let chain = vec![grant.clone()];
        Agent { key, grant, chain, aud: aud.to_string(), ttl_ms: DEFAULT_TTL_MS, clock: now_ms, on_counter: None, plan: None, counter: Mutex::new(counter) }
    }
    /// Commit to a multi-step plan; `act` then signs against the matching node (and its Merkle proof).
    pub fn use_plan(&mut self, nodes: Vec<Value>) {
        self.plan = Some(nodes);
    }
    /// Build and sign the PCActn for one action. Without a committed plan it commits a one-node plan for the action.
    pub fn act(&self, verb: &str, resource: &str, params: Option<&Value>, extra: Map<String, Value>, suite: &Suite) -> Result<Action, String> {
        let (plan, node_id) = match &self.plan {
            Some(p) => {
                let n = p.iter().find(|n| n["verb"] == verb && n["resource"] == resource).ok_or_else(|| format!("act: no node of the committed plan matches {verb} {resource}"))?;
                (p.clone(), s_of(n, "id")?.to_string())
            }
            None => (vec![json!({"id": "n1", "verb": verb, "resource": resource, "params_digest": params_digest(params)})], "n1".to_string()),
        };
        let counter = {
            let mut c = self.counter.lock().map_err(|_| "counter lock poisoned".to_string())?;
            *c += 1;
            if let Some(h) = &self.on_counter {
                h(*c);
            }
            *c
        };
        let mut extra = extra;
        extra.entry("nonce").or_insert(json!(b64(&rand_bytes::<16>()?)));
        let p = build_pcactn(&PcactnInput {
            grant: &self.grant, chain: &self.chain, plan: &plan, node_id: &node_id, params, counter, signer: &self.key, aud: &self.aud,
            iat: (self.clock)(), exp: None, extra, suite: Suite { alg: suite.alg, pq: suite.pq },
        })?;
        let headers = pca_headers(&p, &[], None, None);
        Ok(Action { pcactn: p, headers, node_id })
    }
    /// A sub-agent signing with `to`, holding this chain plus one narrower hop (caveats are only ever appended).
    pub fn delegate(&self, to: KeyPair, caveats: &Value, suite: &Suite) -> Result<Agent, String> {
        let cap = delegate(self.chain.last().ok_or("empty chain")?, &self.key, Some(&to.public), caveats, None, suite)?;
        let mut chain = self.chain.clone();
        chain.push(cap);
        Ok(Agent { key: to, grant: self.grant.clone(), chain, aud: self.aud.clone(), ttl_ms: self.ttl_ms, clock: self.clock, on_counter: None, plan: None, counter: Mutex::new(0) })
    }
}
