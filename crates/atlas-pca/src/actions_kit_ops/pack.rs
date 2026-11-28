//! Building, chaining and signing action packs, verifying an upgrade between two versions, the signed evolution records, and the
//! entry of a pack in a SCITT transparency log (pack.ts, evolve.ts, transparency.ts of the reference). The verify side of one
//! pack (`verify_pack`, `pack_digest`, `shard_digest`, `pack_shape_error`, `pack_defs`) is in `actions_registry`.
//!
//! shortcut: signing is Ed25519 only (the reference's `suite` option for post-quantum registry signatures is not carried) and
//! `verify_upgrade` verifies against the core trait registry, as the other natives do.

use super::deps;
use super::{int_of, isi, kerr, negzero, u16cmp, Verifier};
use crate::actions::{core_registry, def_digest, pack_root, tables_digest, traits_digest, validate_def, ActionKitError, Registry};
use crate::actions_registry::{
    compare_versions, evolution_diff_digest, pack_defs, pack_digest, pack_shape_error, rules_digest, shard_digest, verify_evolution_record, verify_pack,
};
use crate::agent::KeyPair;
use crate::scitt::{sign_statement, statement_payload, verify_receipt, TransparencyService};
use crate::{b64_encode, canonicalize_strict};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub const PACK_SIG_DOMAIN: &str = "atlas-pca/action-pack/v1\0";
pub const PACK_SHARD_KIND: &str = "pca-action-pack-shard";
const EVOLUTION_DOMAIN: &str = "atlas-pca/action-evolution/v1\0";
/// Largest shard the builder writes by default.
pub const DEFAULT_SHARD_DEFS: i64 = 512;
/// Most defs an inline pack carries.
pub const MAX_PACK_DEFS: usize = 4096;
pub const PACK_STATEMENT_CONTENT_TYPE: &str = "application/pca-action-pack+json";

type R<T> = Result<T, ActionKitError>;

fn by_verb(a: &Value, b: &Value) -> std::cmp::Ordering {
    u16cmp(a["verb"].as_str().unwrap_or(""), b["verb"].as_str().unwrap_or(""))
}

/// Shard names are the resource family (first segment of `resource.type`) of the defs, split in order into chunks of `max`
/// (`None` = the default). Returns `[{name, defs}]`.
pub fn shard_defs(defs: &[Value], max: Option<&Value>) -> R<Vec<Value>> {
    let m = match max.filter(|m| !m.is_null()) {
        None => DEFAULT_SHARD_DEFS,
        Some(v) if isi(v) && !negzero(v) && v.as_f64().unwrap_or(0.0) >= 1.0 => int_of(v),
        Some(_) => return Err(kerr("bad_shard_size", "the shard size must be a positive integer")),
    } as usize;
    let mut fam: BTreeMap<Vec<u16>, (String, Vec<&Value>)> = BTreeMap::new();
    for d in defs {
        let f = d["resource"]["type"].as_str().unwrap_or("").split('.').next().unwrap_or("").to_string();
        fam.entry(f.encode_utf16().collect()).or_insert_with(|| (f.clone(), vec![])).1.push(d);
    }
    let mut out = Vec::new();
    for (_, (f, l)) in fam {
        for (n, chunk) in l.chunks(m).enumerate() {
            out.push(json!({"name": if l.len() > m { format!("{f}-{}", n + 1) } else { f.clone() }, "defs": chunk}));
        }
    }
    Ok(out)
}

fn sorted_unique_defs_error(defs: &[Value]) -> Option<String> {
    for (i, d) in defs.iter().enumerate() {
        if let Some(e) = validate_def(d) {
            return Some(format!("def {i}: {e}"));
        }
        if i > 0 && by_verb(&defs[i - 1], d) != std::cmp::Ordering::Less {
            return Some(format!("defs must be sorted by verb and unique (at '{}')", d["verb"].as_str().unwrap_or("")));
        }
    }
    None
}

/// Sign `body` under `domain` as the registry: `{alg, kid, value}` (Ed25519).
pub fn sign_registry_doc(domain: &str, body: &Value, kid: &str, secret: &[u8]) -> Result<Value, String> {
    let seed: [u8; 32] = secret.try_into().map_err(|_| "the registry key must be a 32-byte Ed25519 secret".to_string())?;
    let mut msg = domain.as_bytes().to_vec();
    msg.extend_from_slice(canonicalize_strict(body)?.as_bytes());
    Ok(json!({"alg": "ed25519", "kid": kid, "value": b64_encode(&KeyPair::from_seed(&seed).sign(&msg))}))
}

// ---- evolution --------------------------------------------------------------------------------------------------------------

fn map_by_verb(defs: &[Value]) -> R<BTreeMap<Vec<u16>, (String, &Value)>> {
    let mut m = BTreeMap::new();
    for d in defs {
        let v = d["verb"].as_str().unwrap_or("").to_string();
        if m.insert(v.encode_utf16().collect::<Vec<u16>>(), (v.clone(), d)).is_some() {
            return Err(kerr("duplicate_def", format!("verb '{v}' appears twice")));
        }
    }
    Ok(m)
}

/// The unsigned records that take `prev` to `next` (sorted by verb).
pub fn evolution_records(ns: &str, prev: &[Value], next: &[Value], reg: &Registry, v: Verifier) -> Result<Vec<Value>, String> {
    let (a, b) = (map_by_verb(prev).map_err(super::msg)?, map_by_verb(next).map_err(super::msg)?);
    let mut keys: Vec<&Vec<u16>> = a.keys().chain(b.keys().filter(|k| !a.contains_key(*k))).collect();
    keys.sort();
    let mut out = Vec::new();
    for k in keys {
        let (o, n) = (a.get(k), b.get(k));
        let verb = o.or(n).map(|x| x.0.clone()).unwrap_or_default();
        let base = |from: Value, to: Value, class: &str, reasons: Value| json!({"v": 1, "kind": "pca-evolution-record", "ns": ns, "verb": verb, "from": from, "to": to, "class": class, "reasons": reasons});
        match (o, n) {
            (None, Some(n)) => out.push(base(Value::Null, json!(def_digest(n.1)), "added", json!([]))),
            (Some(o), None) => out.push(base(json!(def_digest(o.1)), Value::Null, "removed", json!([]))),
            (Some(o), Some(n)) => {
                let (from, to) = (def_digest(o.1), def_digest(n.1));
                if from == to {
                    continue;
                }
                let d = deps::diff_defs(o.1, n.1, reg, v)?;
                out.push(base(json!(from), json!(to), d["class"].as_str().unwrap_or(""), d["reasons"].clone()));
            }
            (None, None) => {}
        }
    }
    Ok(out)
}

/// Sign the records as the registry.
pub fn sign_evolution(records: &[Value], kid: &str, secret: &[u8]) -> Result<Vec<Value>, String> {
    records
        .iter()
        .map(|r| {
            let sig = sign_registry_doc(EVOLUTION_DOMAIN, r, kid, secret)?;
            let mut o = r.as_object().cloned().unwrap_or_default();
            o.insert("sig".into(), sig);
            Ok(Value::Object(o))
        })
        .collect()
}

fn evo_key(r: &Value) -> Option<String> {
    let s = |k: &str| crate::intent_v2::js_value_string(&r[k]);
    Some(format!("{}|{}|{}|{}|{}", s("verb"), s("from"), s("to"), s("class"), evolution_diff_digest(r)?))
}

/// Does `records` EXACTLY describe the change from `prev` to `next`? `None` = consistent, else the reason.
pub fn evolution_error(ns: &str, prev: &[Value], next: &[Value], records: &[Value], keys: &Value, reg: &Registry, v: Verifier) -> Option<String> {
    for r in records {
        if let Err(e) = verify_evolution_record(r, keys) {
            return Some(format!("evolution record: {e}"));
        }
        if r["ns"].as_str() != Some(ns) {
            return Some(format!("evolution record names namespace '{}', not '{ns}'", crate::intent_v2::js_value_string(&r["ns"])));
        }
    }
    let want = match evolution_records(ns, prev, next, reg, v) {
        Ok(w) => w,
        Err(e) => return Some(format!("evolution error: {e}")),
    };
    let mut want: Vec<String> = match want.iter().map(evo_key).collect::<Option<Vec<_>>>() {
        Some(x) => x,
        None => return Some("evolution error: a record is not in the strict profile".into()),
    };
    let mut have: Vec<String> = match records
        .iter()
        .map(|r| {
            let mut u = r.as_object().cloned().unwrap_or_default();
            u.remove("sig");
            evo_key(&Value::Object(u))
        })
        .collect::<Option<Vec<_>>>()
    {
        Some(x) => x,
        None => return Some("evolution error: a record is not in the strict profile".into()),
    };
    super::sort_u16(&mut want);
    super::sort_u16(&mut have);
    if want.len() != have.len() {
        return Some(format!("evolution has {} records, the change needs {}", have.len(), want.len()));
    }
    if want != have {
        return Some("evolution records do not match the computed change (a missing, extra or mis-classified record)".into());
    }
    None
}

// ---- build / verify ---------------------------------------------------------------------------------------------------------

/// Build, chain and sign a pack. `a` holds `ns, version, stability, defs, source, kid` and optionally `prev: {pack, shards?}` and
/// `shard: true | {max?}`; `secret` is the registry's Ed25519 seed. Returns `{pack, shards}`. An inconsistency is an `ActionKitError`.
pub fn build_pack(a: &Value, secret: &[u8], reg: Option<&Registry>, v: Verifier, shard_uri: Option<&dyn Fn(&str) -> String>) -> R<Value> {
    let core = core_registry();
    let reg = reg.unwrap_or(&core);
    let mut defs: Vec<Value> = a.get("defs").and_then(Value::as_array).cloned().ok_or_else(|| kerr("bad_pack", "defs must be a list"))?;
    defs.sort_by(by_verb);
    if let Some(e) = sorted_unique_defs_error(&defs) {
        return Err(kerr("bad_pack", e));
    }
    if defs.is_empty() {
        return Err(kerr("empty_pack", "a pack has at least one def"));
    }
    let (ns, version) = (a["ns"].as_str().unwrap_or(""), a["version"].as_str().unwrap_or(""));
    let prev = a.get("prev").filter(|p| p.is_object());
    let mut prev_defs: Vec<Value> = Vec::new();
    if let Some(p) = prev {
        let pp = &p["pack"];
        prev_defs = pack_defs(pp, p.get("shards")).map_err(|e| kerr("missing_shard", e))?;
        if pp["ns"].as_str() != Some(ns) {
            return Err(kerr("bad_chain", "the previous pack is of another namespace"));
        }
        if compare_versions(version, pp["version"].as_str().unwrap_or("")).map_err(|e| kerr("bad_version", e))? <= 0 {
            return Err(kerr("bad_chain", "the version must increase"));
        }
    }
    let kid = a["kid"].as_str().unwrap_or("");
    let records = evolution_records(ns, &prev_defs, &defs, reg, v).map_err(|e| kerr("bad_pack", e))?;
    let evolution = sign_evolution(&records, kid, secret).map_err(|e| kerr("bad_pack", e))?;
    let digests: Vec<String> = defs.iter().map(|d| def_digest(d).unwrap_or_default()).collect();
    let root = pack_root(&digests)?;
    let want_shards = match a.get("shard") {
        Some(s) if s != &Value::Bool(false) && !s.is_null() => true,
        _ => defs.len() > MAX_PACK_DEFS,
    };
    let mut shards = Map::new();
    let mut body = Value::Array(defs.clone());
    if want_shards {
        let opts = a.get("shard").filter(|s| s.is_object()).cloned().unwrap_or_else(|| json!({}));
        let mut refs = Vec::new();
        for s in shard_defs(&defs, opts.get("max"))? {
            let name = s["name"].as_str().unwrap_or("").to_string();
            let doc = json!({"v": 1, "kind": PACK_SHARD_KIND, "ns": ns, "version": version, "name": name, "defs": s["defs"]});
            let dg = shard_digest(&doc).ok_or_else(|| kerr("bad_pack", "a shard is not strictly canonical"))?;
            refs.push(json!({"name": name, "digest": dg, "uri": shard_uri.map_or_else(|| format!("shards/{name}.json"), |f| f(&name))}));
            shards.insert(name, doc);
        }
        body = json!({"shards": refs});
    }
    let mut unsigned = Map::new();
    for (k, x) in [
        ("v", json!(1)),
        ("kind", json!("pca-action-pack")),
        ("ns", a["ns"].clone()),
        ("version", a["version"].clone()),
        ("stability", a["stability"].clone()),
        ("traits_digest", json!(traits_digest(reg))),
        ("roles_digest", json!(tables_digest())),
        ("rules_digest", json!(rules_digest())),
        ("root", json!(root)),
        ("defs", body),
        ("source", a["source"].clone()),
        ("prev", prev.map_or(Value::Null, |p| json!(pack_digest(&p["pack"])))),
        ("evolution", Value::Array(evolution)),
    ] {
        unsigned.insert(k.into(), x);
    }
    let unsigned = Value::Object(unsigned);
    // the shape check wants a signed pack; the signature is outside the canonical body, so a placeholder is equivalent
    let mut probe = unsigned.as_object().cloned().unwrap();
    probe.insert("sig".into(), json!({"alg": "ed25519", "kid": kid, "value": "x"}));
    if let Some(pe) = pack_shape_error(&Value::Object(probe)) {
        return Err(kerr("bad_pack", pe));
    }
    let sig = sign_registry_doc(PACK_SIG_DOMAIN, &unsigned, kid, secret).map_err(|e| kerr("bad_pack", e))?;
    let mut pack = unsigned.as_object().cloned().unwrap();
    pack.insert("sig".into(), sig);
    Ok(json!({"pack": pack, "shards": shards}))
}

/// Verify `next` as the successor of `prev`: both verify, same namespace, `next.prev` is `prev`'s digest, the version increases, and the
/// signed evolution is EXACTLY the computed change. Returns `{ok}` or `{ok: false, reason}`.
pub fn verify_upgrade(prev: &Value, next: &Value, keys: &Value, prev_shards: Option<&Value>, shards: Option<&Value>, v: Verifier) -> Value {
    let fail = |r: String| json!({"ok": false, "reason": r});
    let (pd, pdefs) = match verify_pack(prev, keys, prev_shards.filter(|s| !s.is_null())) {
        Ok(x) => x,
        Err(e) => return fail(format!("previous pack: {e}")),
    };
    let ndefs = match verify_pack(next, keys, shards.filter(|s| !s.is_null())) {
        Ok(x) => x.1,
        Err(e) => return fail(format!("pack: {e}")),
    };
    if next["ns"] != prev["ns"] {
        return fail("the packs are of different namespaces".into());
    }
    if next["prev"].as_str() != Some(pd.as_str()) {
        return fail("chain gap: prev does not name the previous pack".into());
    }
    match compare_versions(next["version"].as_str().unwrap_or(""), prev["version"].as_str().unwrap_or("")) {
        Ok(c) if c > 0 => {}
        _ => return fail("the version does not increase".into()),
    }
    let recs: Vec<Value> = next["evolution"].as_array().cloned().unwrap_or_default();
    match evolution_error(next["ns"].as_str().unwrap_or(""), &pdefs, &ndefs, &recs, keys, &core_registry(), v) {
        None => json!({"ok": true}),
        Some(e) => fail(e),
    }
}

/// The pack key entry the registry pins: `{kid, alg: "ed25519", pk}`.
pub fn pack_key_of(kid: &str, secret: &[u8]) -> Result<Value, String> {
    let seed: [u8; 32] = secret.try_into().map_err(|_| "the registry key must be a 32-byte Ed25519 secret".to_string())?;
    Ok(json!({"kid": kid, "alg": "ed25519", "pk": KeyPair::from_seed(&seed).public}))
}

// ---- transparency ------------------------------------------------------------------------------------------------------------

/// The payload the registry signs into the log (small: the digest, not the pack).
pub fn pack_statement_payload(p: &Value) -> Result<Value, String> {
    let digest = pack_digest(p).ok_or("the pack is not strictly canonical")?;
    for k in ["ns", "version", "root"] {
        if !p[k].is_string() {
            return Err(format!("the pack has no {k}"));
        }
    }
    Ok(
        json!({"v": 1, "kind": "pca-action-pack-statement", "ns": p["ns"], "version": p["version"], "digest": digest, "root": p["root"], "prev": p.get("prev").cloned().unwrap_or(Value::Null)}),
    )
}

#[derive(Debug, Clone)]
pub struct PackLogEntry {
    pub statement: Vec<u8>,
    pub receipt: Vec<u8>,
    pub index: u64,
    pub root: String,
}

/// Sign the pack's statement with the registry's COSE key (`signer`: `{alg, key, issuer}`, scitt key forms) and register it.
pub fn append_pack_to_log(pack: &Value, service: &mut TransparencyService, signer: &Value) -> Result<PackLogEntry, String> {
    let payload = pack_statement_payload(pack)?;
    let mut o = signer.as_object().cloned().ok_or("signer must be an object")?;
    o.insert("subject".into(), json!(format!("{}@{}", pack["ns"].as_str().unwrap_or(""), pack["version"].as_str().unwrap_or(""))));
    o.insert("contentType".into(), json!(PACK_STATEMENT_CONTENT_TYPE));
    let statement = sign_statement(&payload, &Value::Object(o))?;
    let r = service.register(&statement)?;
    Ok(PackLogEntry { statement, receipt: r.receipt, index: r.index, root: r.root })
}

/// Does the entry prove `pack` is in the log? The statement must be the pack's own and signed by the registry, the receipt by the log.
/// `keys`: `{registry, log}` as scitt public keys (`{pub}`). Never panics.
pub fn verify_pack_log_entry(pack: &Value, statement: &[u8], receipt: &[u8], keys: &Value, tree_root: Option<&str>) -> bool {
    let mut opts = Map::new();
    if let Some(r) = tree_root {
        opts.insert("treeRoot".into(), json!(r));
    }
    opts.insert("verificationKey".into(), keys["log"].clone());
    opts.insert("statementKey".into(), keys["registry"].clone());
    if !verify_receipt(receipt, statement, &Value::Object(opts)) {
        return false;
    }
    let (Ok(have), Ok(want)) = (statement_payload(statement), pack_statement_payload(pack).and_then(|p| canonicalize_strict(&p))) else { return false };
    have == want.as_bytes()
}
