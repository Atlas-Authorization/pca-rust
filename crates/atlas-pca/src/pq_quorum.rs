//! The in-core post-quantum quorum certificate (port of `pq-threshold.ts`): a quorum set is n registered PQ signers, a threshold t
//! and a diversity commitment k (at least k hash-based signers); a proof is at least t INDEPENDENT per-signer signatures over the
//! quorum message (set id, epoch, action digest). Rotation: the old quorum signs the digest of the next set at epoch + 1, and the
//! chain verifier enforces linkage and monotone epochs. No new cryptography: counting, binding and de-duplication on the suite seam.
//!
//! JSON-valued (`&Value` in, the reference's member names out). A reference throw is an `Err`; the verifiers are total.
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha384};

use crate::agent::{KeyPair, PqKeyPair, Suite};

const SET_DOMAIN: &str = "atlas-pca/pq-quorum-set/v1";
const MSG_DOMAIN: &str = "atlas-pca/pq-quorum-msg/v1\0";
const ROTATION_KIND: &str = "pq-quorum-rotation";
/// Largest quorum set.
pub const PQ_QUORUM_MAX_SIGNERS: usize = 256;
/// Longest rotation chain a verifier walks.
pub const PQ_QUORUM_MAX_CHAIN: usize = 1024;

const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

fn sha384_b64(bytes: &[u8]) -> String {
    crate::b64_encode(&Sha384::digest(bytes))
}

/// A JSON number that is a safe integer (and not -0).
fn safe_int(v: Option<&Value>) -> Option<f64> {
    v.filter(|n| n.is_number())
        .and_then(Value::as_f64)
        .filter(|f| f.fract() == 0.0 && f.abs() <= MAX_SAFE && !(*f == 0.0 && f.is_sign_negative()))
}

fn epoch_of(v: Option<&Value>) -> Option<f64> {
    safe_int(v).filter(|f| *f >= 0.0)
}

struct Entry {
    alg: &'static str,
    ed: Option<String>,
    pq: String,
}

impl Entry {
    fn key(&self) -> String {
        format!("{}|{}|{}", self.alg, self.ed.as_deref().unwrap_or(""), self.pq)
    }
    fn hash_based(&self) -> bool {
        self.alg.contains("slh-dsa")
    }
    fn json(&self) -> Value {
        let mut o = Map::new();
        o.insert("alg".into(), json!(self.alg));
        if let Some(ed) = &self.ed {
            o.insert("ed".into(), json!(ed));
        }
        o.insert("pq".into(), json!(self.pq));
        Value::Object(o)
    }
}

/// The registered suite of a quorum signer: a post-quantum one (lattice or hash-based, alone or in an Ed25519 hybrid).
fn pq_suite(alg: Option<&Value>) -> Option<crate::SigSuite> {
    let s = crate::resolve_sig_alg(Some(alg?))?;
    (s.pq.is_some() && !s.alg.contains("less")).then_some(s)
}

/// `ed` is `None` when the member is absent; a present member (even `null`) on a non-hybrid entry is refused.
fn normalize(alg: Option<&Value>, ed: Option<&Value>, pq: Option<&Value>) -> Option<Entry> {
    let suite = pq_suite(alg)?;
    let pq = pq?.as_str()?;
    crate::decode_b64u_strict(pq, Some(suite.pq?.lens().0))?;
    if suite.needs_pq_sig {
        let ed = ed?.as_str()?;
        crate::decode_b64u_strict(ed, Some(32))?;
        return Some(Entry {
            alg: suite.alg,
            ed: Some(ed.to_string()),
            pq: pq.to_string(),
        });
    }
    ed.is_none().then(|| Entry {
        alg: suite.alg,
        ed: None,
        pq: pq.to_string(),
    })
}

struct Set {
    t: f64,
    k: f64,
    signers: Vec<Entry>,
    id: String,
}

impl Set {
    fn json(&self) -> Value {
        json!({"t": self.t as u64, "minHashBased": self.k as u64, "signers": self.signers.iter().map(Entry::json).collect::<Vec<_>>(), "id": self.id})
    }
}

/// Sorts, checks the bounds, the distinctness of every key component and the diversity commitment, and derives the id. Also
/// answers whether the entries were already in canonical order.
fn finalize(entries: Vec<Entry>, t: Option<&Value>, k: Option<&Value>) -> Option<(Set, bool)> {
    let n = entries.len();
    if !(1..=PQ_QUORUM_MAX_SIGNERS).contains(&n) {
        return None;
    }
    let t = safe_int(t).filter(|t| *t >= 1.0 && *t <= n as f64)?;
    let k = safe_int(k).filter(|k| *k >= 0.0 && *k <= t)?;
    let given: Vec<String> = entries.iter().map(Entry::key).collect();
    let mut sorted = entries;
    sorted.sort_by_key(Entry::key);
    let mut seen: Vec<&str> = Vec::new();
    for e in &sorted {
        for c in e.ed.as_deref().into_iter().chain([e.pq.as_str()]) {
            if seen.contains(&c) {
                return None;
            }
            seen.push(c);
        }
    }
    if (sorted.iter().filter(|e| e.hash_based()).count() as f64) < k {
        return None;
    }
    let s: Vec<Value> = sorted.iter().map(|e| json!({"a": e.alg, "e": e.ed, "p": e.pq})).collect();
    let id = sha384_b64(
        crate::canonicalize_strict(&json!({"d": SET_DOMAIN, "t": t as u64, "k": k as u64, "s": s}))
            .ok()?
            .as_bytes(),
    );
    let in_order = sorted.iter().map(Entry::key).eq(given);
    Some((Set { t, k, signers: sorted, id }, in_order))
}

/// The member of a signer's public keys that carries its post-quantum key.
fn pq_key_member(alg: &str) -> &'static str {
    match alg {
        a if a.contains("ml-dsa-65") => "mlDsaPub",
        a if a.contains("ml-dsa-87") => "mlDsa87Pub",
        a if a.contains("slh-dsa-sha2-128f") => "slhDsaPub",
        "fn-dsa-512" => "fnDsa512Pub",
        "fn-dsa-1024" => "fnDsa1024Pub",
        _ => "slhDsa256sPub",
    }
}

/// Build a quorum set `{t, minHashBased, signers: [{alg, ed?, pq}], id}` from `[{alg, keys: {edPub?, mlDsaPub | mlDsa87Pub |
/// slhDsaPub | slhDsa256sPub | fnDsa512Pub | fnDsa1024Pub}}]`: signers in canonical order, every key component distinct,
/// `1 <= t <= n <= 256`, `0 <= minHashBased <= t` and no more than the hash-based signers. `None` is the reference's `bad-set`.
pub fn build_quorum_set(signers: &Value, t: &Value, min_hash_based: &Value) -> Option<Value> {
    let mut entries = Vec::new();
    for s in signers.as_array()? {
        let keys = s.get("keys").filter(|k| k.is_object())?;
        let suite = crate::resolve_sig_alg(Some(s.as_object()?.get("alg")?))?;
        entries.push(normalize(s.get("alg"), keys.get("edPub"), keys.get(pq_key_member(suite.alg)))?);
    }
    finalize(entries, Some(t), Some(min_hash_based)).map(|(set, _)| set.json())
}

fn load(x: &Value) -> Option<Set> {
    let id = x.get("id")?.as_str()?;
    let mut entries = Vec::new();
    for s in x.as_object()?.get("signers")?.as_array()? {
        s.as_object()?;
        entries.push(normalize(s.get("alg"), s.get("ed"), s.get("pq"))?);
    }
    let (set, in_order) = finalize(entries, x.get("t"), x.get("minHashBased"))?;
    (in_order && set.id == id).then_some(set)
}

/// Load a quorum set from the wire: re-derives the id and requires the canonical signer order and the entry shape (`ed` only on a
/// hybrid). `None` is the reference's `bad-set`; extra members are dropped.
pub fn load_quorum_set(x: &Value) -> Option<Value> {
    load(x).map(|s| s.json())
}

/// The message every signer of a quorum signs: the domain prefix, then SHA-384 of the strict canonical `{set_id, epoch, action}`.
/// The arguments are not judged here (any JSON value the strict canonical form accepts).
pub fn quorum_message(set_id: &Value, epoch: &Value, action_digest: &Value) -> Result<Vec<u8>, String> {
    let body = crate::canonicalize_strict(&json!({"set_id": set_id, "epoch": epoch, "action": action_digest}))?;
    let mut m = MSG_DOMAIN.as_bytes().to_vec();
    m.extend_from_slice(&Sha384::digest(body.as_bytes()));
    Ok(m)
}

/// The action digest of a raw message (base64url SHA-384).
pub fn quorum_action_digest(message: &[u8]) -> String {
    sha384_b64(message)
}

/// `signers[index]` as the reference reads it: a non-negative integer, or its decimal text.
fn signer_at<'a>(set: &'a Value, index: &Value) -> Option<&'a Value> {
    let i = match index {
        Value::Number(n) => n.as_f64().filter(|f| *f >= 0.0 && f.fract() == 0.0).map(|f| f as usize),
        Value::String(s) if s == "0" || (!s.starts_with('0') && !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())) => s.parse().ok(),
        _ => None,
    };
    set.get("signers")?.as_array()?.get(i?)
}

/// One signer's share `{i, sig, pq_sig?}` over the quorum message, under the suite of `set.signers[index]`: `ed` is the Ed25519
/// half of a hybrid, `pq` the post-quantum key pair of the suite's family. `Err` for an unknown index or missing key material.
pub fn sign_quorum_share(
    set: &Value,
    index: &Value,
    epoch: &Value,
    action_digest: &Value,
    ed: Option<&KeyPair>,
    pq: Option<&PqKeyPair>,
) -> Result<Value, String> {
    let e = signer_at(set, index).ok_or("signQuorumShare: no such signer index")?;
    let alg = e.get("alg").and_then(Value::as_str).ok_or("signQuorumShare: malformed signer")?;
    let msg = quorum_message(set.get("id").unwrap_or(&Value::Null), epoch, action_digest)?;
    let (sig, pq_sig) = crate::agent::sign_with_suite(&Suite { alg: Some(alg), pq }, ed, &msg)?;
    let mut share = json!({"i": index, "sig": sig});
    if let Some(p) = pq_sig {
        share["pq_sig"] = json!(p);
    }
    Ok(share)
}

/// `{set_id, sigs}`: the shares are copied untouched (a string spreads into its characters, as in the reference).
pub fn assemble_quorum_proof(set: &Value, shares: &Value) -> Result<Value, String> {
    let sigs: Vec<Value> = match shares {
        Value::Array(a) => a.clone(),
        Value::String(s) => s.chars().map(|c| json!(c.to_string())).collect(),
        _ => return Err("the shares are not a list".into()),
    };
    let mut proof = Map::new();
    if let Some(id) = set.get("id") {
        proof.insert("set_id".into(), id.clone());
    }
    proof.insert("sigs".into(), Value::Array(sigs));
    Ok(Value::Object(proof))
}

fn refuse(reason: &str, detail: Option<f64>) -> Value {
    let mut o = json!({"ok": false, "reason": reason});
    if let Some(d) = detail {
        o["detail"] = json!(d as u64);
    }
    o
}

/// `Math.max(k, requireHashBased ?? 0)` as the reference coerces it; NaN when the requirement is not a number.
fn required_diversity(k: f64, require: Option<&Value>) -> f64 {
    let r = match require {
        None | Some(Value::Null) => 0.0,
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::String(s)) if s.trim().is_empty() => 0.0,
        Some(Value::String(s)) => s.trim().parse().unwrap_or(f64::NAN),
        Some(_) => f64::NAN,
    };
    if r.is_nan() {
        r
    } else {
        k.max(r)
    }
}

fn verify(
    set: &Set,
    proof: Option<&Value>,
    epoch: Option<&Value>,
    action_digest: Option<&Value>,
    expected_set_id: Option<&Value>,
    require: Option<&Value>,
) -> Value {
    if expected_set_id.is_some_and(|x| x.as_str() != Some(set.id.as_str())) {
        return refuse("set-mismatch", None);
    }
    let (Some(_), Some(digest)) = (epoch_of(epoch), action_digest.filter(|d| d.is_string())) else {
        return refuse("malformed", None);
    };
    let (Some(set_id), Some(sigs)) = (
        proof.and_then(|p| p.as_object()).and_then(|p| p.get("set_id")).and_then(Value::as_str),
        proof.and_then(|p| p.get("sigs")).and_then(Value::as_array),
    ) else {
        return refuse("malformed", None);
    };
    if set_id != set.id {
        return refuse("set-mismatch", None);
    }
    let n = set.signers.len();
    if sigs.len() > n {
        return refuse("too-many-signatures", None);
    }
    let Ok(msg) = quorum_message(&json!(set.id), epoch.unwrap_or(&Value::Null), digest) else {
        return refuse("malformed", None);
    };
    let mut seen: Vec<usize> = Vec::new();
    let mut hash_based = 0u64;
    for raw in sigs {
        if !raw.is_object() || !raw.get("sig").is_some_and(Value::is_string) {
            return refuse("malformed", None);
        }
        let Some(i) = epoch_of(raw.get("i")).filter(|i| *i < n as f64) else {
            return refuse("unknown-signer", None);
        };
        let at = i as usize;
        if seen.contains(&at) {
            return refuse("duplicate-signer", Some(i));
        }
        seen.push(at);
        let e = &set.signers[at];
        // a hybrid carries pq_sig, a pure suite must not
        if e.ed.is_some() != raw.get("pq_sig").is_some() {
            return refuse("bad-signature", Some(i));
        }
        let ed = e.ed.as_deref().unwrap_or("");
        let source = crate::pq::PqKeySource {
            trusted_pk: Some(e.pq.clone()),
            ..Default::default()
        };
        let key = crate::pq::resolve_pq_verify_key(ed, None, Some(&source));
        if !crate::pq::verify_with_suite(Some(&json!(e.alg)), ed, key.as_ref(), &msg, raw.get("sig"), raw.get("pq_sig")) {
            return refuse("bad-signature", Some(i));
        }
        if e.hash_based() {
            hash_based += 1;
        }
    }
    if (seen.len() as f64) < set.t {
        return refuse("below-threshold", None);
    }
    let k = required_diversity(set.k, require);
    if !(k.fract() == 0.0 && (0.0..=MAX_SAFE).contains(&k)) {
        return refuse("malformed", None);
    }
    if (hash_based as f64) < k {
        return refuse("diversity-unmet", None);
    }
    seen.sort_unstable();
    json!({"ok": true, "signers": seen, "count": seen.len(), "hashBased": hash_based})
}

/// Verify a quorum proof. `input` is `{set, proof, epoch, actionDigest, expectedSetId?, requireHashBased?}`. Total: answers
/// `{ok: true, signers, count, hashBased}` or `{ok: false, reason, detail?}` with the reference's reasons (`malformed`, `bad-set`,
/// `set-mismatch`, `too-many-signatures`, `unknown-signer`, `duplicate-signer`, `bad-signature`, `below-threshold`,
/// `diversity-unmet`). The first failing share decides; shares are counted only after every one of them verified.
pub fn verify_quorum(input: &Value) -> Value {
    if !input.is_object() {
        return refuse("malformed", None);
    }
    match load(input.get("set").unwrap_or(&Value::Null)) {
        Some(set) => verify(
            &set,
            input.get("proof"),
            input.get("epoch"),
            input.get("actionDigest"),
            input.get("expectedSetId"),
            input.get("requireHashBased"),
        ),
        None => refuse("bad-set", None),
    }
}

/// [`verify_quorum`] over a raw message; `opts` may carry `expectedSetId` and `requireHashBased`.
pub fn verify_quorum_approval(set: &Value, proof: &Value, message: &[u8], epoch: &Value, opts: Option<&Value>) -> bool {
    let mut input = json!({"set": set, "proof": proof, "epoch": epoch, "actionDigest": quorum_action_digest(message)});
    for k in ["expectedSetId", "requireHashBased"] {
        if let Some(v) = opts.and_then(|o| o.get(k)) {
            input[k] = v.clone();
        }
    }
    verify_quorum(&input)["ok"] == true
}

/// The action digest the old quorum signs to rotate to `to_set_id` at `to_epoch`.
pub fn rotation_action_digest(to_set_id: &Value, to_epoch: &Value) -> Result<String, String> {
    Ok(sha384_b64(
        crate::canonicalize_strict(&json!({"kind": ROTATION_KIND, "to_set_id": to_set_id, "to_epoch": to_epoch}))?.as_bytes(),
    ))
}

/// `from_epoch + 1` as the reference computes it (a string concatenates).
fn next_epoch(from_epoch: &Value) -> Result<Value, String> {
    match from_epoch {
        Value::Number(n) => Ok(crate::prohibitions::num_value(n.as_f64().unwrap_or(f64::NAN) + 1.0)),
        Value::String(s) => Ok(json!(format!("{s}1"))),
        _ => Err("the epoch is not a number".into()),
    }
}

/// The rotation certificate `{from_set_id, from_epoch, to_set, to_epoch, proof}` (arithmetic and assembly only; nothing is judged).
pub fn build_rotation_cert(from: &Value, from_epoch: &Value, to: &Value, shares: &Value) -> Result<Value, String> {
    let mut cert = Map::new();
    if let Some(id) = from.as_object().ok_or("the old set is not an object")?.get("id") {
        cert.insert("from_set_id".into(), id.clone());
    }
    cert.insert("from_epoch".into(), from_epoch.clone());
    cert.insert("to_set".into(), to.clone());
    cert.insert("to_epoch".into(), next_epoch(from_epoch)?);
    cert.insert("proof".into(), assemble_quorum_proof(from, shares)?);
    Ok(Value::Object(cert))
}

/// One old-quorum signer's share of the rotation to `to` (see [`sign_quorum_share`]).
pub fn sign_rotation_share(from: &Value, index: &Value, from_epoch: &Value, to: &Value, ed: Option<&KeyPair>, pq: Option<&PqKeyPair>) -> Result<Value, String> {
    if to.is_null() {
        return Err("the new set is null".into());
    }
    let digest = rotation_action_digest(to.get("id").unwrap_or(&Value::Null), &next_epoch(from_epoch)?)?;
    sign_quorum_share(from, index, from_epoch, &json!(digest), ed, pq)
}

/// Walk a rotation chain from a pinned genesis set and epoch: each link names the current set and epoch, moves to `epoch + 1`, and
/// carries a quorum proof BY THE CURRENT SET over the next set's id. Answers `{ok: true, set, epoch, length}` or
/// `{ok: false, reason, at}` (`at` is the failing link, -1 for the genesis or the chain itself).
pub fn verify_rotation_chain(genesis_set: &Value, genesis_epoch: &Value, chain: &Value) -> Value {
    let fail = |reason: &str, at: i64| json!({"ok": false, "reason": reason, "at": at});
    let (Some(mut cur), Some(mut epoch)) = (load(genesis_set), epoch_of(Some(genesis_epoch))) else {
        return fail("bad-set", -1);
    };
    let Some(links) = chain.as_array() else { return fail("malformed", -1) };
    if links.len() > PQ_QUORUM_MAX_CHAIN {
        return fail("chain-too-long", -1);
    }
    for (n, c) in links.iter().enumerate() {
        let n = n as i64;
        let (true, Some(from), Some(from_epoch), Some(to_epoch)) = (
            c.is_object(),
            c.get("from_set_id").and_then(Value::as_str),
            epoch_of(c.get("from_epoch")),
            epoch_of(c.get("to_epoch")),
        ) else {
            return fail("malformed", n);
        };
        if from != cur.id {
            return fail("chain-broken", n);
        }
        if from_epoch != epoch || to_epoch != epoch + 1.0 {
            return fail("non-monotone-epoch", n);
        }
        let Some(next) = load(c.get("to_set").unwrap_or(&Value::Null)).filter(|next| next.id != cur.id) else {
            return fail("bad-rotation", n);
        };
        let Ok(digest) = rotation_action_digest(&json!(next.id), &c["to_epoch"]) else {
            return fail("malformed", -1);
        };
        let v = verify(&cur, c.get("proof"), c.get("from_epoch"), Some(&json!(digest)), None, None);
        if v["ok"] != true {
            return fail(v["reason"].as_str().unwrap_or("malformed"), n);
        }
        cur = next;
        epoch = to_epoch;
    }
    json!({"ok": true, "set": cur.json(), "epoch": epoch as u64, "length": links.len()})
}

/// `a === b` of two members that may be absent: equal primitives only.
fn same_primitive(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) | (Some(Value::Null), Some(Value::Null)) => true,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x == y,
        _ => false,
    }
}

/// Two rotation certificates that leave the same set at the same epoch for different sets: evidence of a fork (structural check).
pub fn is_rotation_fork(a: &Value, b: &Value) -> bool {
    let to = |c: &Value| c.as_object().and_then(|c| c.get("to_set")).filter(|t| t.is_object()).cloned();
    let (Some(ta), Some(tb)) = (to(a), to(b)) else { return false };
    same_primitive(a.get("from_set_id"), b.get("from_set_id"))
        && same_primitive(a.get("from_epoch"), b.get("from_epoch"))
        && matches!((ta.get("id"), tb.get("id")), (Some(Value::String(x)), Some(Value::String(y))) if x != y)
}

/// Size accounting of a proof for `set`: `{minBytes, maxBytes, t, compact: false, chosenBytes?}` (the t smallest and the t largest
/// shares; `chosenBytes` for the given signer indices, an unknown index counting 0). `Err` for a set with an unknown suite.
pub fn quorum_proof_size(set: &Value, indices: Option<&Value>) -> Result<Value, String> {
    let share_bytes = |e: &Value| -> Result<f64, String> {
        let s = crate::resolve_sig_alg(Some(e.get("alg").ok_or("a signer without a suite")?)).ok_or("unknown suite")?;
        Ok((s.sig_bytes + if s.needs_pq_sig { s.pq.map_or(0, |p| p.lens().1) } else { 0 }) as f64)
    };
    let signers = set.get("signers").and_then(Value::as_array).ok_or("not a quorum set")?;
    let mut sizes = signers.iter().map(share_bytes).collect::<Result<Vec<f64>, String>>()?;
    sizes.sort_by(f64::total_cmp);
    let t = set
        .get("t")
        .and_then(Value::as_f64)
        .filter(|t| *t >= 0.0)
        .map_or(sizes.len(), |t| (t as usize).min(sizes.len()));
    let mut r = json!({
        "minBytes": sizes[..t].iter().sum::<f64>() as u64, "maxBytes": sizes[sizes.len() - t..].iter().sum::<f64>() as u64, "compact": false,
    });
    if let Some(t) = set.get("t") {
        r["t"] = t.clone();
    }
    if let Some(ix) = indices {
        let chosen: f64 = ix
            .as_array()
            .ok_or("the indices are not a list")?
            .iter()
            .map(|i| signer_at(set, i).map_or(Ok(0.0), share_bytes))
            .sum::<Result<f64, String>>()?;
        r["chosenBytes"] = json!(chosen as u64);
    }
    Ok(r)
}
