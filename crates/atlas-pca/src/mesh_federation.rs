//! The federation side of the cross-domain mesh (port of the issuing half of `mesh.ts` beyond the domain and the witness): the public
//! effective authority, proof size accounting, the revocation latency model, cross-domain capability translation, the consolidated
//! (federated) budget, the mutual-transparency cross-reference, and the worked example.
//!
//! JSON-valued like the monitor modules: `&Value` in, the reference's field names out. A reference throw is an `Err`; the verifiers are
//! total and fail closed. Numbers a caller supplied are kept as given.
use std::collections::HashMap;

use serde_json::{json, Map, Value};

use crate::agent::{KeyPair, Suite};
use crate::mesh::{effective, narrows, Authority};
use crate::mesh_issue::{MeshDomain, MeshWitness};
use crate::risk::TrustBudget;

/// Default freshness window of a cosigned head.
pub const DEFAULT_MAX_HEAD_AGE_MS: f64 = 300_000.0;
/// Default bound on a delegation chain (and on the depth of a federated budget tree).
pub const DEFAULT_MAX_CHAIN_LENGTH: usize = 64;

const XCAP_DOMAIN: &str = "atlas-pca/mesh-xcap/v1\0";
const XANCHOR_DOMAIN: &str = "atlas-pca/mesh-xanchor/v1\0";
const ACTION_DIGEST_DOMAIN: &str = "atlas-pca/mesh-action-digest/v1\0";

fn msg(domain: &str, body: &Value) -> Result<Vec<u8>, String> {
    let mut m = domain.as_bytes().to_vec();
    m.extend_from_slice(crate::canonicalize_strict(body)?.as_bytes());
    Ok(m)
}

fn finite(v: Option<&Value>) -> Option<f64> {
    v.filter(|n| n.is_number()).and_then(Value::as_f64).filter(|f| f.is_finite())
}

fn string(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str)
}

/// A member that must be present (an absent one is `undefined` in the reference, which its canonical form refuses).
fn present<'a>(o: &'a Value, k: &str) -> Result<&'a Value, String> {
    o.get(k).ok_or_else(|| "canonicalize: unsupported type undefined".to_string())
}

fn number(f: f64) -> Value {
    crate::prohibitions::num_value(f)
}

fn hash(v: &Value) -> Result<String, String> {
    crate::hash_canonical_strict(v).ok_or_else(|| "outside the strict JSON profile".to_string())
}

// ---- effective authority ----------------------------------------------------------------------------------------------------

fn authority_json(e: &Authority) -> Value {
    let mut o = Map::new();
    o.insert("prefixes".into(), json!(e.prefixes));
    if let Some(a) = &e.actions {
        o.insert("actions".into(), json!(a));
    }
    for (k, v) in [("maxAmount", e.max_amount), ("expiresAt", e.expires_at), ("maxHops", e.max_hops)] {
        if let Some(v) = v {
            o.insert(k.into(), number(v));
        }
    }
    if let Some(a) = &e.audience {
        o.insert("audience".into(), json!(a));
    }
    Value::Object(o)
}

/// Conjunction of all caveats as one authority `{prefixes, actions?, maxAmount?, expiresAt?, audience?, maxHops?}`; an unknown or
/// malformed caveat fails closed as `{error}` (the first one in list order). `Err` only for a value that is not a caveat list.
pub fn effective_authority(caveats: &Value) -> Result<Value, String> {
    let list = caveats.as_array().ok_or("caveats is not a list")?;
    // an entry that is not an object has no type: unknown (fail closed); a null entry cannot be read at all
    let cut = list.iter().position(|c| !c.is_object()).unwrap_or(list.len());
    match effective(Some(&Value::Array(list[..cut].to_vec()))) {
        Err(e) => Ok(json!({"error": e})),
        Ok(_) if cut < list.len() && list[cut].is_null() => Err("a caveat is null".into()),
        Ok(_) if cut < list.len() => Ok(json!({"error": "unknown caveat type \"undefined\" (fail closed)"})),
        Ok(e) => Ok(authority_json(&e)),
    }
}

// ---- proof size -------------------------------------------------------------------------------------------------------------

fn bytes(v: &Value) -> Result<f64, String> {
    Ok(crate::canonicalize_strict(v)?.len() as f64)
}

fn at<'a>(list: &'a Value, index: Option<&Value>) -> Option<&'a Value> {
    match (list, index?) {
        (Value::Array(a), Value::Number(n)) => n.as_f64().filter(|f| *f >= 0.0 && f.fract() == 0.0).and_then(|f| a.get(f as usize)),
        (Value::Object(m), Value::String(k)) => m.get(k),
        _ => None,
    }
}

/// Size accounting of a compacted mesh proof (canonical bytes): `{total_bytes, chain_bytes, heads_bytes, rev_leaves_bytes, hops_bytes,
/// uncompacted_bytes}`, the last being what the proof would weigh with every hop carrying its own head and revocation leaves.
pub fn mesh_proof_size(p: &Value) -> Result<Value, String> {
    if p.is_null() {
        return Err("not a proof".into());
    }
    let (chain, action, action_sig) = (present(p, "chain")?, present(p, "action")?, present(p, "action_sig")?);
    let (heads, leaves) = (p.get("heads").unwrap_or(&Value::Null), p.get("rev_leaves").unwrap_or(&Value::Null));
    let truthy = |v: &&Value| !matches!(v, Value::Null | Value::Bool(false)) && v.as_f64() != Some(0.0) && v.as_str() != Some("");
    let expand = |c: Option<&Value>| -> Result<Value, String> {
        let c = c.filter(|c| !c.is_null()).ok_or("malformed hop revocation")?;
        let mut o = Map::new();
        o.insert("size".into(), present(c, "size")?.clone());
        for k in ["lo", "hi"] {
            if let Some(leaf) = at(leaves, c.get(k)).filter(truthy) {
                o.insert(k.into(), leaf.clone());
            }
        }
        Ok(Value::Object(o))
    };
    let mut uncompacted = bytes(chain)? + bytes(action)? + bytes(action_sig)?;
    for h in p.get("hops").and_then(Value::as_array).ok_or("hops is not a list")? {
        let mut full = h.as_object().cloned().unwrap_or_default();
        let rev = h.get("revocation").filter(|r| !r.is_null()).ok_or("malformed hop")?;
        full.insert(
            "head".into(),
            at(heads, h.get("head")).ok_or("canonicalize: unsupported type undefined")?.clone(),
        );
        full.insert(
            "revocation".into(),
            json!({"cap": expand(rev.get("cap"))?, "issuer_key": expand(rev.get("issuer_key"))?}),
        );
        uncompacted += bytes(&Value::Object(full))?;
    }
    Ok(json!({
        "total_bytes": number(bytes(p)?), "chain_bytes": number(bytes(chain)?), "heads_bytes": number(bytes(present(p, "heads")?)?),
        "rev_leaves_bytes": number(bytes(present(p, "rev_leaves")?)?), "hops_bytes": number(bytes(present(p, "hops")?)?),
        "uncompacted_bytes": number(uncompacted),
    }))
}

// ---- revocation latency -----------------------------------------------------------------------------------------------------

/// How long a revocation can stay invisible: to a verifier that takes any fresh head (`unpinned_ms`), to one that also refreshes a
/// pin (`pinned_ms`), and the publication delay itself; `honest_provers_viable` says whether a head can still be fresh when used.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LatencyBound {
    pub published_ms: f64,
    pub unpinned_ms: f64,
    pub pinned_ms: f64,
    pub honest_provers_viable: bool,
}

/// The latency model over `{maxHeadAgeMs, headIntervalMs, maxClockSkewMs?, pinRefreshMs?}` (each a finite number >= 0). Invalid
/// parameters fail closed: every bound is infinite and honest provers are not viable.
pub fn revocation_latency_bound(p: &Value) -> LatencyBound {
    let ok = |k: &str| finite(p.get(k)).filter(|x| *x >= 0.0);
    let optional = |k: &str| p.get(k).is_none() || ok(k).is_some();
    let (Some(age), Some(interval), true, true) = (ok("maxHeadAgeMs"), ok("headIntervalMs"), optional("maxClockSkewMs"), optional("pinRefreshMs")) else {
        return LatencyBound {
            published_ms: f64::INFINITY,
            unpinned_ms: f64::INFINITY,
            pinned_ms: f64::INFINITY,
            honest_provers_viable: false,
        };
    };
    let skew = ok("maxClockSkewMs").unwrap_or(0.0);
    let unpinned = age + skew;
    LatencyBound {
        published_ms: interval,
        unpinned_ms: unpinned,
        pinned_ms: ok("pinRefreshMs").map_or(unpinned, |r| unpinned.min(r)),
        honest_provers_viable: interval + skew < age,
    }
}

// ---- cross-domain capability translation ------------------------------------------------------------------------------------

fn is_caveat_array(v: Option<&Value>) -> bool {
    v.and_then(Value::as_array)
        .is_some_and(|l| l.iter().all(|c| c.is_object() && c.get("type").is_some_and(Value::is_string)))
}

fn pins(v: Option<&Value>) -> Option<HashMap<String, String>> {
    Some(v?.as_object()?.iter().filter_map(|(k, x)| Some((k.clone(), x.as_str()?.to_string()))).collect())
}

fn source_chain<'a>(chain: &'a Value, root_issuer: Option<&str>, pq_pins: Option<&Value>) -> Result<&'a [Value], String> {
    let list = chain.as_array().map(Vec::as_slice).unwrap_or(&[]);
    crate::verify_chain_policy(list, root_issuer, None, pins(pq_pins).as_ref(), None)?;
    Ok(list)
}

fn xcap_body(from: &Value, to: &Value, source_tip: &str, caveats: &Value, issued_at: &Value) -> Value {
    json!({"v": "atlas-pca/mesh-xcap/v1", "from": from, "to": to, "source_tip": source_tip, "caveats": caveats, "issued_at": issued_at})
}

/// Translate a capability chain (rooted in Guardian A's grant) into a capability valid in Guardian B's domain: the chain tip's
/// caveats followed by `args.additionalCaveats` (append-only, hence monotone narrowing), signed by `bridge`. `args` is
/// `{fromGuardian, toGuardian, issued_at, additionalCaveats?, pqPins?}`. `Err` on malformed input; the total, fail-closed function
/// is [`verify_translated_capability`].
pub fn translate_capability(chain: &Value, args: &Value, bridge: &KeyPair) -> Result<Value, String> {
    let list = source_chain(chain, None, args.get("pqPins")).map_err(|e| format!("translateCapability: invalid source chain: {e}"))?;
    if args.get("additionalCaveats").is_some() && !is_caveat_array(args.get("additionalCaveats")) {
        return Err("translateCapability: additionalCaveats must be an array of caveats".into());
    }
    let tip = list.last().ok_or("translateCapability: invalid source chain: empty chain")?;
    let mut caveats = tip.get("caveats").and_then(Value::as_array).cloned().unwrap_or_default();
    caveats.extend(args.get("additionalCaveats").and_then(Value::as_array).cloned().unwrap_or_default());
    let caveats = Value::Array(caveats);
    let source_tip = crate::cap_hash(tip);
    let (from, to, issued_at) = (present(args, "fromGuardian")?, present(args, "toGuardian")?, present(args, "issued_at")?);
    let sig = crate::b64_encode(&bridge.sign(&msg(XCAP_DOMAIN, &xcap_body(from, to, &source_tip, &caveats, issued_at))?));
    Ok(
        json!({"source": chain, "fromGuardian": from, "toGuardian": to, "bridge": bridge.public, "source_tip": source_tip, "caveats": caveats, "issued_at": issued_at, "sig": sig}),
    )
}

/// The effective authority of a translated capability (the conjunction of all its caveats), or `{error}`.
pub fn translated_effective_authority(tc: &Value) -> Value {
    if !tc.is_object() || !is_caveat_array(tc.get("caveats")) {
        return json!({"error": "malformed translated capability"});
    }
    match effective(tc.get("caveats")) {
        Ok(e) => authority_json(&e),
        Err(e) => json!({"error": e}),
    }
}

/// `Number(v)` for the comparison against an expiry: a number, a numeric string, `null` as 0; anything else never compares.
fn loose_number(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::String(s) => s.trim().parse().unwrap_or(f64::NAN),
        Value::Null => 0.0,
        _ => f64::NAN,
    }
}

/// Verify a translated capability END TO END, offline. Total: fails closed on any malformed input. Checks the source chain (with the
/// `rootIssuer` and `pqPins` options), the `fromGuardian` / `toGuardian` / `bridge` pins, the source tip binding, the append-only
/// caveat prefix, the bridge signature, the monotone narrowing of the effective authority and (with `now`) expiry. Answers
/// `{ok: true, from, to, bridge, effective}` or `{ok: false, reason}`. `opts` absent is no options; a `null` is malformed.
pub fn verify_translated_capability(tc: &Value, opts: Option<&Value>) -> Value {
    let fail = |reason: String| json!({"ok": false, "reason": reason});
    let malformed = || fail("malformed translated capability".into());
    let none = json!({});
    let (Some(source), Some(from), Some(to)) = (
        tc.get("source").filter(|s| s.is_array()),
        string(tc.get("fromGuardian")),
        string(tc.get("toGuardian")),
    ) else {
        return malformed();
    };
    let (Some(bridge), Some(source_tip), Some(sig), Some(_), true) = (
        string(tc.get("bridge")),
        string(tc.get("source_tip")),
        string(tc.get("sig")),
        finite(tc.get("issued_at")),
        is_caveat_array(tc.get("caveats")),
    ) else {
        return malformed();
    };
    let opts = match opts {
        Some(Value::Null) => return malformed(),
        Some(o) => o,
        None => &none,
    };
    let list = match source_chain(source, string(opts.get("rootIssuer")), opts.get("pqPins")) {
        Ok(l) => l,
        Err(e) => return fail(format!("source chain: {e}")),
    };
    for (key, have, reason) in [
        ("fromGuardian", from, "source guardian mismatch"),
        ("toGuardian", to, "target guardian mismatch"),
        ("bridge", bridge, "bridge key mismatch"),
    ] {
        if opts.get(key).is_some_and(|want| want.as_str() != Some(have)) {
            return fail(reason.into());
        }
    }
    if from == to {
        return fail("translation does not cross a domain boundary".into());
    }
    let Some(tip) = list.last() else { return malformed() };
    if source_tip != crate::cap_hash(tip) {
        return fail("source_tip does not match the source chain tip".into());
    }
    let (caveats, tip_caveats) = (
        tc["caveats"].as_array().cloned().unwrap_or_default(),
        tip.get("caveats").and_then(Value::as_array).cloned().unwrap_or_default(),
    );
    if caveats.len() < tip_caveats.len() {
        return fail("translation drops a source caveat (widening)".into());
    }
    for (j, c) in tip_caveats.iter().enumerate() {
        match (hash(&caveats[j]), hash(c)) {
            (Ok(a), Ok(b)) if a == b => {}
            (Ok(_), Ok(_)) => return fail(format!("translation altered or reordered source caveat {j} (widening)")),
            _ => return malformed(),
        }
    }
    let Ok(m) = msg(
        XCAP_DOMAIN,
        &xcap_body(&tc["fromGuardian"], &tc["toGuardian"], source_tip, &tc["caveats"], &tc["issued_at"]),
    ) else {
        return malformed();
    };
    if !crate::verify_b64u(bridge, &m, sig) {
        return fail("translation not signed by the declared bridge key".into());
    }
    let eff_s = match effective(tip.get("caveats")) {
        Ok(e) => e,
        Err(e) => return fail(format!("source caveats: {e}")),
    };
    let eff_t = match effective(tc.get("caveats")) {
        Ok(e) => e,
        Err(e) => return fail(e),
    };
    if !narrows(&eff_t, &eff_s) {
        return fail("translated authority widens the source authority".into());
    }
    if let (Some(now), Some(exp)) = (opts.get("now"), eff_t.expires_at) {
        // `Number.isFinite` does not coerce: a null or string clock is not a finite number
        if !(now.is_number() && now.as_f64().is_some_and(|n| n.is_finite() && n <= exp)) {
            return fail("translated capability expired".into());
        }
    }
    json!({"ok": true, "from": from, "to": to, "bridge": bridge, "effective": authority_json(&eff_t)})
}

// ---- consolidated cross-domain budget ---------------------------------------------------------------------------------------

fn refused(reason: impl Into<String>) -> Value {
    json!({"ok": false, "reason": reason.into()})
}

fn budget(b: f64) -> TrustBudget {
    TrustBudget { b, tau: 0.0, as_of: None }
}

fn valid_budget_state(s: &Value) -> bool {
    let (Some(nodes), Some(root), Some(kappa), Some(b_max)) = (
        s.get("nodes").and_then(Value::as_object),
        string(s.get("root")),
        finite(s.get("kappa")),
        finite(s.get("bMax")),
    ) else {
        return false;
    };
    kappa > 0.0
        && b_max >= 0.0
        && nodes.contains_key(root)
        && nodes.values().all(|n| {
            n.is_object()
                && string(n.get("domain")).is_some()
                && finite(n.get("B")).is_some_and(|b| b >= 0.0)
                && !n.get("parent").is_some_and(|p| !p.is_string())
        })
}

/// A federated budget rooted at `args.rootId` (in `args.rootDomain`) with initial budget `B0 <= bMax` under the policy `kappa`.
/// Fails closed on a malformed policy or allocation: `{ok: true, state}` or `{ok: false, reason}`.
pub fn create_federated_budget(args: &Value) -> Value {
    let (Some(root), Some(domain)) = (string(args.get("rootId")), string(args.get("rootDomain"))) else {
        return refused("malformed root");
    };
    if !finite(args.get("kappa")).is_some_and(|k| k > 0.0) {
        return refused("kappa must be finite and > 0");
    }
    let Some(b_max) = finite(args.get("bMax")).filter(|b| *b >= 0.0) else {
        return refused("bMax must be finite and >= 0");
    };
    let Some(b0) = finite(args.get("B0")).filter(|b| *b >= 0.0) else {
        return refused("B0 must be finite and >= 0");
    };
    if b0 > b_max {
        return refused("B0 exceeds bMax");
    }
    let mut nodes = Map::new();
    nodes.insert(root.to_string(), json!({"domain": domain, "B": args["B0"]}));
    json!({"ok": true, "state": {"nodes": nodes, "root": root, "kappa": args["kappa"], "bMax": args["bMax"]}})
}

/// Allocate a sub-agent budget: a new node `args.id` (in `args.domain`) under `args.parent` with ceiling `args.alloc`
/// (`0 <= alloc <=` the parent's CURRENT remaining). A ceiling, not a reservation: the parent is not reduced.
pub fn allocate_sub(state: &Value, args: &Value) -> Value {
    if !valid_budget_state(state) {
        return refused("malformed budget state");
    }
    let (Some(id), Some(domain), Some(parent)) = (string(args.get("id")), string(args.get("domain")), string(args.get("parent"))) else {
        return refused("malformed allocation");
    };
    let nodes = &state["nodes"];
    if nodes.get(id).is_some() {
        return refused("node id already exists");
    }
    let Some(p) = nodes.get(parent) else { return refused("unknown parent") };
    let alloc = args.get("alloc").filter(|a| a.is_number()).and_then(Value::as_f64).unwrap_or(f64::NAN);
    if let Err(e) = crate::risk::sub_budget(&budget(finite(p.get("B")).unwrap_or(0.0)), alloc) {
        return refused(e);
    }
    let mut next = state.clone();
    // the ceiling is the allocation exactly as given
    next["nodes"][id] = json!({"domain": domain, "parent": parent, "B": args["alloc"]});
    json!({"ok": true, "state": next})
}

fn budget_path(nodes: &Map<String, Value>, root: &str, node_id: &str) -> Result<Vec<String>, &'static str> {
    let mut path: Vec<String> = Vec::new();
    let mut cur = Some(node_id.to_string());
    while let Some(c) = cur {
        let node = nodes.get(&c).ok_or("unknown node")?;
        if path.contains(&c) {
            return Err("cycle in budget tree");
        }
        if path.len() >= DEFAULT_MAX_CHAIN_LENGTH {
            return Err("budget tree too deep");
        }
        cur = string(node.get("parent")).map(String::from);
        path.push(c);
    }
    if path.last().map(String::as_str) != Some(root) {
        return Err("node is not rooted at the budget root");
    }
    Ok(path)
}

/// Spend `c` at `node_id`: debits that node AND every ancestor up to the root, each exactly once, ONLY IF all of them can cover it
/// (atomic; no state change otherwise). Every spend debits the root, so the whole delegation tree draws on one budget.
pub fn spend_federated(state: &Value, node_id: &Value, c: &Value) -> Value {
    if !valid_budget_state(state) {
        return refused("malformed budget state");
    }
    let Some(node_id) = node_id.as_str() else {
        return refused("malformed node id");
    };
    let Some(c) = finite(Some(c)).filter(|c| *c >= 0.0) else {
        return refused("spend must be finite and >= 0");
    };
    let (Some(nodes), root) = (state["nodes"].as_object(), state["root"].as_str().unwrap_or("")) else {
        return refused("malformed budget state");
    };
    let path = match budget_path(nodes, root, node_id) {
        Ok(p) => p,
        Err(e) => return refused(e),
    };
    let b_of = |id: &str| finite(nodes[id].get("B")).unwrap_or(0.0);
    let mut next = state.clone();
    let mut set = |id: &str, b: f64| next["nodes"][id]["B"] = number(b);
    if node_id == root {
        if !(b_of(root) >= c) {
            return refused("root budget insufficient");
        }
        set(root, crate::risk::debit(&budget(b_of(root)), c).b);
        return json!({"ok": true, "state": next});
    }
    let interior = &path[1..path.len() - 1];
    if let Some(i) = interior.iter().find(|i| !(b_of(i.as_str()) >= c)) {
        return refused(format!("ancestor \"{i}\" budget insufficient"));
    }
    let (parent, sub) = match crate::risk::debit_consolidated(&budget(b_of(root)), &budget(b_of(node_id)), c) {
        Ok(r) => r,
        Err(e) => return refused(e),
    };
    set(node_id, sub.b);
    set(root, parent.b);
    for i in interior {
        set(i.as_str(), crate::risk::debit(&budget(b_of(i.as_str())), c).b);
    }
    json!({"ok": true, "state": next})
}

/// Whatever the shape of the delegation tree, the total risk of the collective spend between two human recharges is at most
/// `bMax / kappa`; 0 for a malformed policy.
pub fn federated_safety_bound(p: &Value) -> f64 {
    match (p.is_object(), finite(p.get("bMax")), finite(p.get("kappa"))) {
        (true, Some(b_max), Some(kappa)) => crate::risk::safety_bound(b_max, kappa),
        _ => 0.0,
    }
}

// ---- mutual transparency: the cross-reference --------------------------------------------------------------------------------

/// Digest of a mesh action for anchoring (domain-separated, strict canonical).
pub fn mesh_action_digest(action: &Value) -> Result<String, String> {
    hash(&json!({"v": ACTION_DIGEST_DOMAIN, "action": action}))
}

/// The digest of `{action_digest, fromGuardian, toGuardian, nonce, at}` that both Guardians anchor.
pub fn cross_reference_commit(x: &Value) -> Result<String, String> {
    hash(&json!({
        "v": "atlas-pca/mesh-xref/v1", "action_digest": present(x, "action_digest")?, "from": present(x, "fromGuardian")?,
        "to": present(x, "toGuardian")?, "nonce": present(x, "nonce")?, "at": present(x, "at")?,
    }))
}

/// A Guardian signs an anchor binding `commit` at log position `seq`: `{domain, commit, seq, sig}`. The signer does not judge
/// `seq`; [`verify_cross_reference`] refuses one that is not a natural number.
pub fn anchor_cross_reference(domain: &KeyPair, commit: &Value, seq: &Value) -> Result<Value, String> {
    let sig = crate::b64_encode(&domain.sign(&msg(XANCHOR_DOMAIN, &json!({"commit": commit, "seq": seq}))?));
    Ok(json!({"domain": domain.public, "commit": commit, "seq": seq, "sig": sig}))
}

fn valid_anchor(a: Option<&Value>) -> Option<(&str, &str, &Value, &str)> {
    let a = a?;
    let seq = a
        .get("seq")
        .filter(|s| finite(Some(s)).is_some_and(|f| f >= 0.0 && f.fract() == 0.0 && f <= 9_007_199_254_740_991.0 && !f.is_sign_negative()))?;
    Some((string(a.get("domain"))?, string(a.get("commit"))?, seq, string(a.get("sig"))?))
}

/// Verify a cross-reference: both Guardians' anchors (`{from, to}`) commit to the SAME action digest and are each validly signed.
/// Total, fail closed: `{ok: true, commit}` or `{ok: false, reason}`.
pub fn verify_cross_reference(x: &Value, anchors: &Value) -> Value {
    let all = ["action_digest", "fromGuardian", "toGuardian", "nonce"]
        .iter()
        .all(|k| string(x.get(k)).is_some());
    if !x.is_object() || !all || finite(x.get("at")).is_none() {
        return refused("malformed cross-reference");
    }
    let (true, Some(from), Some(to)) = (anchors.is_object(), valid_anchor(anchors.get("from")), valid_anchor(anchors.get("to"))) else {
        return refused("malformed anchors");
    };
    if x["fromGuardian"] == x["toGuardian"] {
        return refused("cross-reference must span two distinct domains");
    }
    let Ok(expected) = cross_reference_commit(x) else {
        return refused("malformed cross-reference");
    };
    if Some(from.0) != x["fromGuardian"].as_str() {
        return refused("source anchor domain does not match the cross-reference");
    }
    if Some(to.0) != x["toGuardian"].as_str() {
        return refused("target anchor domain does not match the cross-reference");
    }
    if from.1 != expected {
        return refused("source anchor commits a different action");
    }
    if to.1 != expected {
        return refused("target anchor commits a different action");
    }
    for (a, reason) in [(from, "source anchor signature invalid"), (to, "target anchor signature invalid")] {
        let Ok(m) = msg(XANCHOR_DOMAIN, &json!({"commit": a.1, "seq": a.2})) else {
            return refused("malformed cross-reference");
        };
        if !crate::verify_b64u(a.0, &m, a.3) {
            return refused(reason);
        }
    }
    json!({"ok": true, "commit": expected})
}

// ---- the worked example -----------------------------------------------------------------------------------------------------

/// A PUBLIC, fixed example key: the first 32 bytes of the TEXT of a domain-tagged hash (as the reference builds it). Never a real key.
fn example_key(label: &str) -> KeyPair {
    let text = crate::hash_canonical(&json!({"seed": format!("atlas-pca/mesh-example/{label}")}));
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&text.as_bytes()[..32]);
    KeyPair::from_seed(&seed)
}

fn publish(d: &mut MeshDomain, witnesses: &mut [MeshWitness], timestamp: f64) -> Result<Value, String> {
    let mut refs: Vec<&mut MeshWitness> = witnesses.iter_mut().collect();
    d.publish_head(&mut refs, timestamp, None)
}

/// A worked proof with 4 hops across 3 organisations: human -> orchestrator (logged in org A), orchestrator -> tool agent (A), tool
/// agent -> service agent (B), service agent -> leaf worker (C); the leaf then performs `payments.refund` for 25 under `/orders/42`.
/// Org A publishes two successive heads, the second cosigned only after every witness verified the consistency proof. Answers
/// `{trust, proof, evidence, chain, heads: {A0, A, B, C}, bindings, domains: {A, B, C}, witnesses}` (ids, no keys); every key is a
/// fixed public example key.
pub fn build_mesh_example(now: f64) -> Result<Value, String> {
    let suite = Suite::default();
    let key = example_key;
    let (human, orchestrator, tool, service, leaf) = (key("human"), key("orchestrator"), key("tool"), key("service"), key("leaf"));
    let mut a = MeshDomain::new("org-A", key("domain-A"));
    let mut b = MeshDomain::new("org-B", key("domain-B"));
    let mut c = MeshDomain::new("org-C", key("domain-C"));
    let mut witnesses = vec![
        MeshWitness::new(key("witness-1")),
        MeshWitness::new(key("witness-2")),
        MeshWitness::new(key("witness-3")),
    ];
    let root = crate::agent::mint_root(
        &human,
        &orchestrator.public,
        &json!([
            {"type": "scope", "actions": ["payments.refund", "payments.read", "orders.read"]}, {"type": "resource", "prefix": "/orders/"},
            {"type": "max_amount", "max": 500}, {"type": "expires", "at": number(now + 3_600_000.0)}, {"type": "audience", "domains": [c.id]},
        ]),
        None,
        &suite,
    )?;
    let hop = |parent: &Value, signer: &KeyPair, to: &KeyPair, added: Value| crate::agent::delegate(parent, signer, Some(&to.public), &added, None, &suite);
    let c1 = hop(
        &root,
        &orchestrator,
        &tool,
        json!([{"type": "scope", "actions": ["payments.refund", "payments.read"]}, {"type": "max_amount", "max": 100}]),
    )?;
    let c2 = hop(
        &c1,
        &tool,
        &service,
        json!([{"type": "resource", "prefix": "/orders/42"}, {"type": "max_hops", "n": 4}]),
    )?;
    let c3 = hop(
        &c2,
        &service,
        &leaf,
        json!([{"type": "scope", "actions": ["payments.refund"]}, {"type": "max_amount", "max": 50}]),
    )?;
    a.record(&root);
    let h_a0 = publish(&mut a, &mut witnesses, now - 2_000.0)?;
    a.record(&c1);
    let h_a = publish(&mut a, &mut witnesses, now - 1_000.0)?; // size 1 -> 2: consistency-proven by every witness
    b.record(&c2);
    c.record(&c3);
    let h_b = publish(&mut b, &mut witnesses, now - 1_000.0)?;
    let h_c = publish(&mut c, &mut witnesses, now - 1_000.0)?;
    let b_orch = a.enroll(&orchestrator.public, "orchestrator")?;
    let b_tool = b.enroll(&tool.public, "tool-agent")?;
    let b_svc = c.enroll(&service.public, "service-agent")?;
    let evidence = vec![
        a.evidence(&root, &h_a, None)?,
        a.evidence(&c1, &h_a, Some(&b_orch))?,
        b.evidence(&c2, &h_b, Some(&b_tool))?,
        c.evidence(&c3, &h_c, Some(&b_svc))?,
    ];
    let chain = vec![root, c1, c2, c3];
    let action =
        json!({"type": "payments.refund", "resource": "/orders/42/line/1", "amount": 25, "service_domain": c.id, "nonce": "n-0001", "at": number(now)});
    let proof = crate::signers_more::assemble_mesh_proof(&chain, &evidence, &action, &leaf, None)?;
    let ids: Vec<&str> = witnesses.iter().map(|w| w.id.as_str()).collect();
    Ok(json!({
        "trust": {"humanPrincipal": human.public, "witnesses": ids, "threshold": 2, "now": number(now), "allowedDomains": [a.id, b.id, c.id], "rootDomain": a.id},
        "proof": proof, "evidence": evidence, "chain": chain,
        "heads": {"A0": h_a0, "A": h_a, "B": h_b, "C": h_c},
        "bindings": {"orchestrator": b_orch, "tool": b_tool, "service": b_svc},
        "domains": {"A": a.id, "B": b.id, "C": c.id}, "witnesses": ids,
    }))
}

/// Witnesses verify real RFC 9162 consistency: a malicious domain rewrites an early log entry and grows the forked log PAST the size
/// the witness last saw. A size-only check would accept it; the consistency proof (computed over the forked log) does not. Answers
/// `{honest_extension_cosigned, fork_larger_than_prior, size_only_check_would_accept, fork_rejected, fork_reason}`.
pub fn demonstrate_fork_rejection() -> Result<Value, String> {
    let (suite, human) = (Suite::default(), example_key("fork-human"));
    let cap = |n: u32| crate::agent::mint_root(&human, &human.public, &json!([{"type": "scope", "actions": [format!("a{n}")]}]), None, &suite);
    let mut w = vec![MeshWitness::new(example_key("fork-witness"))];
    let mut honest = MeshDomain::new("X", example_key("fork-domain"));
    honest.record(&cap(0)?);
    honest.record(&cap(1)?);
    publish(&mut honest, &mut w, 100.0)?;
    honest.record(&cap(2)?);
    let honest_ok = publish(&mut honest, &mut w, 200.0).is_ok();
    let prior = w[0].last_seen(&honest.id).and_then(|h| h["size"].as_f64()).ok_or("the witness saw no head")?;
    // same key, rewritten history (entry 0 differs), grown past the prior size
    let mut fork = MeshDomain::new("X", example_key("fork-domain"));
    for n in [100, 1, 2, 3] {
        fork.record(&cap(n)?);
    }
    let refusal = publish(&mut fork, &mut w, 300.0).err();
    Ok(json!({
        "honest_extension_cosigned": honest_ok, "fork_larger_than_prior": 4.0 > prior, "size_only_check_would_accept": 4.0 >= prior,
        "fork_rejected": refusal.is_some(), "fork_reason": refusal.unwrap_or_default(),
    }))
}
