//! Cross-domain mesh proofs (the agent mesh, `mesh.ts` `verifyMeshProof`). A mesh proof carries a capability chain, one
//! witnessed head per issuing domain, per-hop log inclusion and revocation non-membership proofs, and a signed leaf
//! action. [`verify_mesh_proof`] checks all of it offline and returns the reference's reason and failing hop.
//!
//! Scope: everything `verifyMeshProof` does, including RFC 9162 consistency proofs from a pinned head. The witness
//! side (cosigning, head publication) is not here: a verifier only checks what they produced.

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};

use super::intent_v2::js_number_string;
use super::{b64_encode, canonicalize_strict, cap_hash, decode_b64u_strict, leaf_hash, node_hash, path_shape, safe_int, sha, verify_b64u, verify_chain_policy, verify_inclusion};

const HEAD_DOMAIN: &str = "atlas-pca/mesh-head/v1\0";
const COSIG_DOMAIN: &str = "atlas-pca/mesh-cosig/v1\0";
const BINDING_DOMAIN: &str = "atlas-pca/mesh-binding/v1\0";
const ACTION_DOMAIN: &str = "atlas-pca/mesh-action/v1\0";
const DEFAULT_MAX_HEAD_AGE_MS: f64 = 300_000.0;
const DEFAULT_MAX_SKEW_MS: f64 = 60_000.0;
const DEFAULT_MAX_CHAIN: i64 = 64;
const MAX_COSIGS: usize = 256;
const MAX_PATH: usize = 128;

/// The result of [`verify_mesh_proof`]. `hop` is the failing hop, when one is named.
#[derive(Debug, Clone, PartialEq)]
pub struct MeshVerdict {
    pub ok: bool,
    pub reason: Option<String>,
    pub hop: Option<usize>,
}

fn fail(reason: impl Into<String>, hop: Option<usize>) -> MeshVerdict {
    MeshVerdict { ok: false, reason: Some(reason.into()), hop }
}

fn rec(v: &Value) -> Option<&Map<String, Value>> {
    v.as_object()
}
fn is_str(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(_)))
}
fn nat(v: Option<&Value>) -> Option<i64> {
    v.and_then(safe_int).filter(|n| *n >= 0)
}
fn num(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64).filter(|f| f.is_finite())
}
fn s<'a>(m: &'a Map<String, Value>, k: &str) -> &'a str {
    m.get(k).and_then(Value::as_str).unwrap_or("")
}

fn msg(domain: &str, body: &Value) -> Option<Vec<u8>> {
    let mut b = domain.as_bytes().to_vec();
    b.extend_from_slice(canonicalize_strict(body).ok()?.as_bytes());
    Some(b)
}

fn valid_head(h: Option<&Value>) -> Option<&Map<String, Value>> {
    let m = rec(h?)?;
    if !is_str(m.get("domain")) || !is_str(m.get("rev_root")) || !is_str(m.get("root")) {
        return None;
    }
    let size = nat(m.get("size"))?;
    nat(m.get("rev_size"))?;
    num(m.get("timestamp"))?;
    ((size == 0) == (s(m, "root").is_empty())).then_some(m)
}

fn valid_consistency(c: Option<&Value>) -> Option<&Map<String, Value>> {
    let m = rec(c?)?;
    nat(m.get("oldSize"))?;
    nat(m.get("newSize"))?;
    let path = m.get("path")?.as_array()?;
    (path.len() <= MAX_PATH && path.iter().all(Value::is_string)).then_some(m)
}

fn valid_inclusion(i: Option<&Value>) -> Option<&Map<String, Value>> {
    let m = rec(i?)?;
    nat(m.get("index"))?;
    nat(m.get("size"))?;
    (m.get("path")?.as_array()?.len() <= MAX_PATH).then_some(m)
}

fn valid_action(a: Option<&Value>) -> Option<&Map<String, Value>> {
    let m = rec(a?)?;
    for k in ["type", "resource", "service_domain", "nonce"] {
        if !is_str(m.get(k)) {
            return None;
        }
    }
    num(m.get("at"))?;
    if let Some(v) = m.get("amount") {
        num(Some(v))?;
    }
    Some(m)
}

// ---- effective authority -----------------------------------------------------------------------------------

#[derive(Default)]
struct Authority {
    actions: Option<Vec<String>>,
    prefixes: Vec<String>,
    max_amount: Option<f64>,
    expires_at: Option<f64>,
    audience: Option<Vec<String>>,
    max_hops: Option<f64>,
}

fn intersect(have: &Option<Vec<String>>, b: Vec<String>) -> Vec<String> {
    match have {
        None => {
            let mut out: Vec<String> = Vec::new();
            for x in b {
                if !out.contains(&x) {
                    out.push(x);
                }
            }
            out.sort();
            out
        }
        Some(a) => a.iter().filter(|x| b.contains(x)).cloned().collect(),
    }
}

fn strings(v: Option<&Value>) -> Option<Vec<String>> {
    v?.as_array()?.iter().map(|x| x.as_str().map(str::to_string)).collect()
}

fn min_of(cur: Option<f64>, v: f64) -> Option<f64> {
    Some(cur.map_or(v, |c| c.min(v)))
}

fn effective(caveats: Option<&Value>) -> Result<Authority, String> {
    let mut e = Authority::default();
    let arr = caveats.and_then(Value::as_array).ok_or("malformed proof")?;
    for cv in arr {
        let c = rec(cv).ok_or("malformed proof")?;
        match c.get("type").and_then(Value::as_str) {
            Some("scope") => {
                let a = strings(c.get("actions")).ok_or("malformed scope caveat")?;
                e.actions = Some(intersect(&e.actions, a));
            }
            Some("resource") => e.prefixes.push(c.get("prefix").and_then(Value::as_str).ok_or("malformed resource caveat")?.to_string()),
            Some("max_amount") => e.max_amount = min_of(e.max_amount, num(c.get("max")).ok_or("malformed max_amount caveat")?),
            Some("expires") => e.expires_at = min_of(e.expires_at, num(c.get("at")).ok_or("malformed expires caveat")?),
            Some("audience") => {
                let d = strings(c.get("domains")).ok_or("malformed audience caveat")?;
                e.audience = Some(intersect(&e.audience, d));
            }
            Some("max_hops") => e.max_hops = min_of(e.max_hops, num(c.get("n")).ok_or("malformed max_hops caveat")?),
            other => {
                let shown = match c.get("type") {
                    None => "undefined".to_string(),
                    Some(Value::String(t)) => t.clone(),
                    Some(Value::Null) => "null".to_string(),
                    Some(v) => v.to_string(),
                };
                let _ = other;
                return Err(format!("unknown caveat type \"{shown}\" (fail closed)"));
            }
        }
    }
    Ok(e)
}

fn subset(child: &[String], parent: &[String]) -> bool {
    child.iter().all(|c| parent.contains(c))
}

fn narrows(child: &Authority, parent: &Authority) -> bool {
    if let Some(pa) = &parent.actions {
        match &child.actions {
            Some(ca) if subset(ca, pa) => {}
            _ => return false,
        }
    }
    if let Some(pa) = &parent.audience {
        match &child.audience {
            Some(ca) if subset(ca, pa) => {}
            _ => return false,
        }
    }
    for (p, c) in [(parent.max_amount, child.max_amount), (parent.expires_at, child.expires_at), (parent.max_hops, child.max_hops)] {
        if let Some(pv) = p {
            match c {
                Some(cv) if cv <= pv => {}
                _ => return false,
            }
        }
    }
    subset(&parent.prefixes, &child.prefixes)
}

fn admits(e: &Authority, a: &Map<String, Value>, now: f64, chain_len: usize) -> Option<String> {
    let typ = s(a, "type");
    if let Some(acts) = &e.actions {
        if !acts.iter().any(|x| x == typ) {
            return Some(format!("action \"{typ}\" not in scope"));
        }
    }
    let res = s(a, "resource");
    for p in &e.prefixes {
        if !res.starts_with(p.as_str()) {
            return Some(format!("resource \"{res}\" outside prefix \"{p}\""));
        }
    }
    if let Some(max) = e.max_amount {
        match a.get("amount").and_then(Value::as_f64) {
            Some(x) if x <= max => {}
            _ => return Some(format!("amount exceeds ceiling {}", js_number_string(max))),
        }
    }
    if let Some(exp) = e.expires_at {
        if now > exp {
            return Some("capability expired".into());
        }
    }
    if let Some(aud) = &e.audience {
        if !aud.iter().any(|x| x == s(a, "service_domain")) {
            return Some("service domain not in audience".into());
        }
    }
    if let Some(h) = e.max_hops {
        if chain_len as f64 > h {
            return Some(format!("chain exceeds max_hops {}", js_number_string(h)));
        }
    }
    None
}

// ---- revocation sets and Merkle proofs -------------------------------------------------------------------

fn bind_root(size: i64, tree: &str) -> Option<String> {
    let mut m = Map::new();
    m.insert("size".into(), Value::from(size));
    m.insert("tree".into(), Value::String(tree.to_string()));
    let mut b = b"pca-revset/v1\0".to_vec();
    b.extend_from_slice(canonicalize_strict(&Value::Object(m)).ok()?.as_bytes());
    Some(b64_encode(&sha(&b)))
}

fn leaf_ok(root: &str, size: i64, id: &str, proof: &Map<String, Value>) -> bool {
    let (Some(psize), Some(index)) = (proof.get("size").and_then(safe_int), proof.get("index").and_then(safe_int)) else { return false };
    if psize != size || index < 0 || index >= size {
        return false;
    }
    let sides = path_shape(index as u64, size as u64);
    let Some(path) = proof.get("path").and_then(Value::as_array) else { return false };
    if path.len() != sides.len() {
        return false;
    }
    let Some(mut h) = leaf_hash(&Value::String(id.to_string())) else { return false };
    for (i, step) in path.iter().enumerate() {
        let Some(step) = step.as_object() else { return false };
        let side = step.get("side").and_then(Value::as_str).unwrap_or("");
        if side.as_bytes() != [sides[i]] {
            return false;
        }
        let Some(sib) = decode_b64u_strict(step.get("hash").and_then(Value::as_str).unwrap_or(""), Some(32)) else { return false };
        h = if side == "L" { node_hash(&sib, &h) } else { node_hash(&h, &sib) };
    }
    bind_root(size, &b64_encode(&h)).as_deref() == Some(root)
}

fn non_membership(root: &str, nm: &Map<String, Value>, id: &str) -> bool {
    let Some(size) = nm.get("size").and_then(safe_int).filter(|n| *n >= 0) else { return false };
    let lo = nm.get("lo").and_then(Value::as_object);
    let hi = nm.get("hi").and_then(Value::as_object);
    if size == 0 {
        return lo.is_none() && hi.is_none() && bind_root(0, &b64_encode(&sha(b""))).as_deref() == Some(root);
    }
    if lo.is_none() && hi.is_none() {
        return false;
    }
    let (mut lo_idx, mut hi_idx) = (0, 0);
    if let Some(l) = lo {
        let Some(lp) = l.get("proof").and_then(Value::as_object) else { return false };
        if !(s(l, "id") < id) || !leaf_ok(root, size, s(l, "id"), lp) {
            return false;
        }
        lo_idx = lp.get("index").and_then(safe_int).unwrap_or(-1);
        if hi.is_none() && lo_idx != size - 1 {
            return false;
        }
    }
    if let Some(h) = hi {
        let Some(hp) = h.get("proof").and_then(Value::as_object) else { return false };
        if !(id < s(h, "id")) || !leaf_ok(root, size, s(h, "id"), hp) {
            return false;
        }
        hi_idx = hp.get("index").and_then(safe_int).unwrap_or(-1);
        if lo.is_none() && hi_idx != 0 {
            return false;
        }
    }
    !(lo.is_some() && hi.is_some() && hi_idx != lo_idx + 1)
}

/// RFC 9162 consistency (section 2.1.4.2) with strict 32-byte base64url hashes.
fn consistency(old_root: &str, new_root: &str, proof: &Map<String, Value>) -> bool {
    let (Some(first), Some(second)) = (proof.get("oldSize").and_then(safe_int), proof.get("newSize").and_then(safe_int)) else { return false };
    if first < 0 || first > second {
        return false;
    }
    let raw: &[Value] = proof.get("path").and_then(Value::as_array).map_or(&[], |v| v.as_slice());
    if raw.len() > MAX_PATH {
        return false;
    }
    let empty = b64_encode(&sha(b""));
    if first == 0 {
        if !raw.is_empty() || old_root != empty {
            return false;
        }
        return if second == 0 { new_root == empty } else { true };
    }
    if first == second {
        return raw.is_empty() && old_root == new_root;
    }
    let mut path: Vec<Vec<u8>> = Vec::new();
    if first & (first - 1) == 0 {
        let Some(o) = decode_b64u_strict(old_root, Some(32)) else { return false };
        path.push(o);
    }
    for p in raw {
        let Some(b) = decode_b64u_strict(p.as_str().unwrap_or(""), Some(32)) else { return false };
        path.push(b);
    }
    if path.is_empty() {
        return false;
    }
    let (mut fn_, mut sn) = (first - 1, second - 1);
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }
    let (mut fr, mut sr) = (path[0].clone(), path[0].clone());
    for c in &path[1..] {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && b64_encode(&fr) == old_root && b64_encode(&sr) == new_root
}

// ---- heads -------------------------------------------------------------------------------------------------

fn check_head_advance(prev: Option<&Value>, next: Option<&Value>, proof: Option<&Value>) -> Option<&'static str> {
    let (Some(p), Some(n)) = (valid_head(prev), valid_head(next)) else { return Some("malformed head") };
    if p.get("domain") != n.get("domain") {
        return Some("head is for a different domain");
    }
    let g = |m: &Map<String, Value>, k: &str| m.get(k).and_then(safe_int).unwrap_or(0);
    if g(n, "size") < g(p, "size") || g(n, "rev_size") < g(p, "rev_size") {
        return Some("head rolls back");
    }
    if g(n, "size") == g(p, "size") {
        if n.get("root") != p.get("root") {
            return Some("equivocation (same size, different log)");
        }
    } else {
        match valid_consistency(proof) {
            Some(c) if g(c, "oldSize") == g(p, "size") && g(c, "newSize") == g(n, "size") => {
                if !consistency(s(p, "root"), s(n, "root"), c) {
                    return Some("head is not consistent with the previous head (fork or rewrite)");
                }
            }
            _ => return Some("consistency proof required for a larger head"),
        }
    }
    if g(n, "rev_size") == g(p, "rev_size") && n.get("rev_root") != p.get("rev_root") {
        return Some("equivocation (revocation set)");
    }
    None
}

struct Trust<'a> {
    human: &'a str,
    witnesses: HashSet<&'a str>,
    threshold: i64,
    now: f64,
    max_head_age: f64,
    max_skew: f64,
    max_action_age: Option<f64>,
    max_chain: i64,
    allowed: Vec<String>,
    root_domain: &'a str,
    issuer_domains: Option<&'a Map<String, Value>>,
    pinned: Option<&'a Map<String, Value>>,
    pq_pins: Option<HashMap<String, String>>,
}

fn opt_ms(t: &Map<String, Value>, k: &str, default: f64) -> Option<f64> {
    match t.get(k) {
        None => Some(default),
        Some(v) => num(Some(v)).filter(|f| *f >= 0.0),
    }
}

fn valid_trust(raw: &Value) -> Result<Trust<'_>, String> {
    let t = rec(raw).ok_or("invalid trust configuration")?;
    let human = t.get("humanPrincipal").and_then(Value::as_str);
    let ws = strings(t.get("witnesses"));
    let (Some(human), Some(ws)) = (human, ws) else { return Err("invalid trust configuration".into()) };
    let witnesses: HashSet<&str> = t.get("witnesses").and_then(Value::as_array).unwrap().iter().filter_map(Value::as_str).collect();
    let _ = ws;
    let threshold = nat(t.get("threshold")).filter(|n| *n >= 1 && *n <= witnesses.len() as i64).ok_or("invalid trust configuration: threshold")?;
    let now = num(t.get("now")).ok_or("invalid trust configuration: now")?;
    let max_head_age = opt_ms(t, "maxHeadAgeMs", DEFAULT_MAX_HEAD_AGE_MS).ok_or("invalid trust configuration: maxHeadAgeMs")?;
    let max_skew = opt_ms(t, "maxClockSkewMs", DEFAULT_MAX_SKEW_MS).ok_or("invalid trust configuration: maxClockSkewMs")?;
    let max_action_age = if t.contains_key("maxActionAgeMs") { Some(opt_ms(t, "maxActionAgeMs", 0.0).ok_or("invalid trust configuration: maxActionAgeMs")?) } else { None };
    let max_chain = match t.get("maxChainLength") {
        None => DEFAULT_MAX_CHAIN,
        Some(v) => nat(Some(v)).filter(|n| *n >= 1).ok_or("invalid trust configuration: maxChainLength")?,
    };
    let allowed = strings(t.get("allowedDomains")).filter(|a| !a.is_empty()).ok_or("invalid trust configuration: allowedDomains is required")?;
    let root_domain = t
        .get("rootDomain")
        .and_then(Value::as_str)
        .filter(|r| allowed.iter().any(|a| a == r))
        .ok_or("invalid trust configuration: rootDomain is required and must be in allowedDomains")?;
    let issuer_domains = match t.get("issuerDomains") {
        None => None,
        Some(v) => Some(rec(v).filter(|m| m.values().all(Value::is_string)).ok_or("invalid trust configuration: issuerDomains")?),
    };
    let pinned = match t.get("pinnedHeads") {
        None => None,
        Some(v) => Some(rec(v).ok_or("invalid trust configuration: pinnedHeads")?),
    };
    let pq_pins = t.get("pqPins").and_then(Value::as_object).map(|m| m.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect());
    Ok(Trust { human, witnesses, threshold, now, max_head_age, max_skew, max_action_age, max_chain, allowed, root_domain, issuer_domains, pinned, pq_pins })
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        _ => true,
    }
}

fn check_cosigned_head(ch: &Value, expected_domain: &str, t: &Trust, pin_proof: Option<&Value>) -> Option<String> {
    let chm = ch.as_object();
    let h = chm.and_then(|m| m.get("head")).and_then(Value::as_object);
    let Some(h) = h.filter(|h| h.get("domain").and_then(Value::as_str) == Some(expected_domain)) else { return Some("head is for a different domain".into()) };
    let hv = chm.and_then(|m| m.get("head"));
    if valid_head(hv).is_none() {
        return Some("malformed head".into());
    }
    let Some(sig) = chm.and_then(|m| m.get("sig")).and_then(Value::as_str) else { return Some("malformed head".into()) };
    let domain = s(h, "domain");
    let hval = Value::Object(h.clone());
    let ok = msg(HEAD_DOMAIN, &hval).is_some_and(|m| verify_b64u(domain, &m, sig));
    if !ok {
        return Some("head not signed by its domain key".into());
    }
    let Some(cosigs) = chm.and_then(|m| m.get("cosigs")).and_then(Value::as_array).filter(|c| c.len() <= MAX_COSIGS) else { return Some("malformed head".into()) };
    let cm = msg(COSIG_DOMAIN, &hval);
    let mut good: HashSet<&str> = HashSet::new();
    for c in cosigs {
        let Some(c) = c.as_object() else { continue };
        let (Some(w), Some(sg)) = (c.get("witness").and_then(Value::as_str), c.get("sig").and_then(Value::as_str)) else { continue };
        if t.witnesses.contains(w) && !good.contains(w) && cm.as_ref().is_some_and(|m| verify_b64u(w, m, sg)) {
            good.insert(w);
        }
    }
    if (good.len() as i64) < t.threshold {
        return Some(format!("head has {}/{} trusted witness cosignatures", good.len(), t.threshold));
    }
    let ts = h.get("timestamp").and_then(Value::as_f64).unwrap_or(f64::NAN);
    if ts > t.now + t.max_skew {
        return Some("head timestamp is in the future".into());
    }
    if t.now - ts > t.max_head_age {
        return Some("head is stale".into());
    }
    if let Some(pins) = t.pinned {
        if let Some(pin) = pins.get(domain).filter(|p| truthy(p)) {
            if let Some(why) = check_head_advance(Some(pin), Some(&hval), pin_proof) {
                return Some(format!("{why} (vs pinned head)"));
            }
        }
    }
    None
}

fn expand_nm(c: Option<&Value>, leaves: &[Value]) -> Option<Map<String, Value>> {
    let m = rec(c?)?;
    nat(m.get("size"))?;
    let mut out = Map::new();
    out.insert("size".into(), m["size"].clone());
    for side in ["lo", "hi"] {
        if let Some(ix) = m.get(side) {
            let i = nat(Some(ix)).filter(|i| (*i as usize) < leaves.len())?;
            out.insert(side.into(), leaves[i as usize].clone());
        }
    }
    Some(out)
}

/// Verify a mesh proof end to end, offline. Total: any malformed input is a verdict, never a panic.
pub fn verify_mesh_proof(proof: &Value, trust: &Value) -> MeshVerdict {
    let t = match valid_trust(trust) {
        Ok(t) => t,
        Err(e) => return fail(e, None),
    };
    let Some(p) = rec(proof) else { return fail("malformed proof", None) };
    let (Some(chain), Some(hops), Some(heads), Some(rev_leaves)) = (
        p.get("chain").and_then(Value::as_array),
        p.get("hops").and_then(Value::as_array),
        p.get("heads").and_then(Value::as_array),
        p.get("rev_leaves").and_then(Value::as_array),
    ) else {
        return fail("malformed proof", None);
    };
    let action_sig = p.get("action_sig").and_then(Value::as_str);
    let (Some(action_sig), Some(action)) = (action_sig, valid_action(p.get("action"))) else { return fail("malformed action", None) };
    if let Some(pp) = p.get("pin_proofs") {
        let ok = pp.as_array().is_some_and(|a| a.len() <= MAX_COSIGS && a.iter().all(|x| rec(x).is_some_and(|m| is_str(m.get("domain")) && valid_consistency(m.get("proof")).is_some())));
        if !ok {
            return fail("malformed pin proofs", None);
        }
    }
    if chain.is_empty() || chain.len() as i64 > t.max_chain {
        return fail("chain length out of bounds", None);
    }
    if heads.len() > chain.len() || rev_leaves.len() > 2 * chain.len() {
        return fail("evidence tables exceed chain size", None);
    }
    if let Err(why) = verify_chain_policy(chain, Some(t.human), None, t.pq_pins.as_ref(), None) {
        return fail(format!("chain: {why}"), None);
    }
    if hops.len() != chain.len() {
        return fail("hop evidence count does not match chain length", None);
    }
    for l in rev_leaves {
        let ok = rec(l).is_some_and(|m| is_str(m.get("id")) && valid_inclusion(m.get("proof")).is_some());
        if !ok {
            return fail("malformed revocation leaves", None);
        }
    }
    let used: HashSet<i64> = hops.iter().filter_map(|h| rec(h).and_then(|m| nat(m.get("head")))).collect();
    if used.len() != heads.len() {
        return fail("unreferenced or missing head in evidence table", None);
    }

    let mut head_err: HashMap<i64, Option<String>> = HashMap::new();
    let mut prev: Option<Authority> = None;
    for (i, capv) in chain.iter().enumerate() {
        let cap = capv.as_object().expect("chain verified");
        let Some(ev) = rec(&hops[i]) else { return fail("malformed hop evidence", Some(i)) };
        let hidx = nat(ev.get("head")).filter(|h| (*h as usize) < heads.len());
        let (Some(domain), Some(hidx), Some(_)) = (ev.get("domain").and_then(Value::as_str), hidx, ev.get("revocation").and_then(Value::as_object)) else {
            return fail("malformed hop evidence", Some(i));
        };
        if !t.allowed.iter().any(|a| a == domain) {
            return fail("issuing domain not allowed by policy", Some(i));
        }
        if i == 0 && domain != t.root_domain {
            return fail("root capability must be anchored in the pinned root domain", Some(i));
        }
        let issuer = s(cap, "issuer");
        if i > 0 {
            if let Some(pin) = t.issuer_domains.and_then(|m| m.get(issuer)) {
                if pin.as_str() != Some(domain) {
                    return fail("issuer key is pinned to a different domain", Some(i));
                }
            }
        }
        let ch = &heads[hidx as usize];
        if !head_err.contains_key(&hidx) {
            let dom = ch.get("head").and_then(|h| h.get("domain")).and_then(Value::as_str).unwrap_or("");
            let pin_proof = p.get("pin_proofs").and_then(Value::as_array).and_then(|a| a.iter().find(|x| x.get("domain").and_then(Value::as_str) == Some(dom))).and_then(|x| x.get("proof"));
            head_err.insert(hidx, check_cosigned_head(ch, dom, &t, pin_proof));
        }
        let Some(head_v) = ch.as_object().and_then(|m| m.get("head")).filter(|h| !h.is_null()) else { return fail("malformed proof", None) };
        let head_m = head_v.as_object();
        if head_m.and_then(|m| m.get("domain")).and_then(Value::as_str) != Some(domain) {
            return fail("source-domain anchor: head is for a different domain", Some(i));
        }
        let head_m = head_m.expect("domain matched");
        if let Some(e) = &head_err[&hidx] {
            return fail(format!("source-domain anchor: {e}"), Some(i));
        }

        let incl = valid_inclusion(ev.get("inclusion"));
        let digest = cap_hash(capv);
        let included = incl.is_some_and(|inc| inc.get("size").and_then(safe_int) == head_m.get("size").and_then(safe_int) && verify_inclusion(s(head_m, "root"), Some(inc), &Value::String(digest.clone())));
        if !included {
            return fail("hop not included in the issuing domain log", Some(i));
        }

        if i > 0 {
            let b = ev.get("binding").and_then(Value::as_object);
            let ok = b.is_some_and(|b| is_str(b.get("role")) && is_str(b.get("sig")) && b.get("agent") == cap.get("issuer") && b.get("domain") == ev.get("domain"));
            if !ok {
                return fail("missing or mismatched domain binding for issuer", Some(i));
            }
            let b = b.unwrap();
            let mut body = Map::new();
            for k in ["agent", "domain", "role"] {
                body.insert(k.into(), b[k].clone());
            }
            if !msg(BINDING_DOMAIN, &Value::Object(body)).is_some_and(|m| verify_b64u(domain, &m, s(b, "sig"))) {
                return fail("domain binding signature invalid", Some(i));
            }
        }

        let rev = ev["revocation"].as_object().unwrap();
        let rev_root = s(head_m, "rev_root");
        match expand_nm(rev.get("cap"), rev_leaves) {
            Some(nm) if non_membership(rev_root, &nm, s(cap, "id")) => {}
            _ => return fail("capability revoked (or revocation proof invalid)", Some(i)),
        }
        match expand_nm(rev.get("issuer_key"), rev_leaves) {
            Some(nm) if non_membership(rev_root, &nm, &format!("key:{issuer}")) => {}
            _ => return fail("issuer key revoked (or revocation proof invalid)", Some(i)),
        }

        let eff = match effective(cap.get("caveats")) {
            Ok(e) => e,
            Err(e) => return fail(e, Some(i)),
        };
        if let Some(pv) = &prev {
            if !narrows(&eff, pv) {
                return fail("hop widens authority", Some(i));
            }
        }
        prev = Some(eff);
    }

    let at = action.get("at").and_then(Value::as_f64).unwrap_or(f64::NAN);
    if at > t.now + t.max_skew {
        return fail("action timestamp is in the future", None);
    }
    if let Some(max) = t.max_action_age {
        if t.now - at > max {
            return fail("action is stale", None);
        }
    }
    let tip = chain.last().unwrap();
    let mut body = Map::new();
    body.insert("action".into(), Value::Object(action.clone()));
    body.insert("tip".into(), Value::String(cap_hash(tip)));
    let holder = tip.get("holder").and_then(Value::as_str).unwrap_or("");
    if !msg(ACTION_DOMAIN, &Value::Object(body)).is_some_and(|m| verify_b64u(holder, &m, action_sig)) {
        return fail("action not signed by the chain tip holder", None);
    }
    if let Some(denied) = admits(prev.as_ref().expect("chain is non-empty"), action, t.now, chain.len()) {
        return fail(format!("action not admitted: {denied}"), None);
    }
    MeshVerdict { ok: true, reason: None, hop: None }
}
