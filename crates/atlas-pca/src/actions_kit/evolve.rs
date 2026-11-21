//! Signed per-definition changes between two versions of a pack (native port of `evolve.ts` of the reference): the unsigned records,
//! Ed25519 registry signing and the whole-change consistency check. The record shape check and signature verification are in
//! `actions_registry`.

use serde_json::{json, Value};
use std::collections::BTreeMap;

use super::diff::diff_defs;
use super::{get, u16cmp, Verifier};
use crate::actions::{def_digest, Registry};
use crate::actions_registry::{evolution_diff_digest, evolution_record_error, verify_evolution_record, EVOLUTION_RECORD_KIND};
use crate::agent::KeyPair;
use crate::intent_v2::js_value_string;
use crate::{b64_encode, canonicalize_strict};

const EVOLUTION_DOMAIN: &str = "atlas-pca/action-evolution/v1\0";

fn by_verb(defs: &[Value]) -> Result<BTreeMap<String, &Value>, String> {
    let mut m = BTreeMap::new();
    for d in defs {
        let v = js_value_string(get(d, "verb"));
        if m.insert(v.clone(), d).is_some() {
            return Err(format!("verb '{v}' appears twice"));
        }
    }
    Ok(m)
}

fn digest_of(d: &Value) -> Result<String, String> {
    def_digest(d).ok_or_else(|| "the def is not in the strict JSON profile".to_string())
}

/// The unsigned records that take `prev` to `next` (sorted by verb). A verb rename is `removed` + `added`.
pub fn evolution_records(ns: &str, prev: &[Value], next: &[Value], reg: &Registry, verifier: Verifier) -> Result<Vec<Value>, String> {
    let (a, b) = (by_verb(prev)?, by_verb(next)?);
    let mut verbs: Vec<&String> = a.keys().chain(b.keys()).collect();
    verbs.sort_by(|x, y| u16cmp(x, y));
    verbs.dedup();
    let mut out = Vec::new();
    for verb in verbs {
        let base = |from: Value, to: Value, class: &str, reasons: Value| json!({"v": 1, "kind": EVOLUTION_RECORD_KIND, "ns": ns, "verb": verb, "from": from, "to": to, "class": class, "reasons": reasons});
        match (a.get(verb), b.get(verb)) {
            (None, Some(n)) => out.push(base(Value::Null, json!(digest_of(n)?), "added", json!([]))),
            (Some(o), None) => out.push(base(json!(digest_of(o)?), Value::Null, "removed", json!([]))),
            (Some(o), Some(n)) => {
                let (f, t) = (digest_of(o)?, digest_of(n)?);
                if f == t {
                    continue;
                }
                let d = diff_defs(o, n, reg, verifier)?;
                out.push(base(json!(f), json!(t), d["class"].as_str().unwrap_or(""), d["reasons"].clone()));
            }
            (None, None) => {}
        }
    }
    Ok(out)
}

/// Sign the records as the registry (Ed25519 over the evolution domain and the strict canonical record).
pub fn sign_evolution(records: &[Value], kid: &str, secret: &[u8]) -> Result<Vec<Value>, String> {
    let seed: [u8; 32] = secret.try_into().map_err(|_| "the registry key must be a 32-byte Ed25519 secret".to_string())?;
    let kp = KeyPair::from_seed(&seed);
    let mut out = Vec::new();
    for r in records {
        if let Some(bad) = evolution_record_error(r, false) {
            return Err(format!("signEvolutionRecord: {bad}"));
        }
        let mut msg = EVOLUTION_DOMAIN.as_bytes().to_vec();
        msg.extend(canonicalize_strict(r)?.into_bytes());
        let mut s = r.clone();
        s["sig"] = json!({"alg": "ed25519", "kid": kid, "value": b64_encode(&kp.sign(&msg))});
        out.push(s);
    }
    Ok(out)
}

fn key_of(r: &Value) -> Result<String, String> {
    let digest = evolution_diff_digest(r).ok_or("the record is not in the strict JSON profile")?;
    Ok(format!(
        "{}|{}|{}|{}|{}",
        js_value_string(get(r, "verb")),
        js_value_string(get(r, "from")),
        js_value_string(get(r, "to")),
        js_value_string(get(r, "class")),
        digest
    ))
}

/// Does `records` EXACTLY describe the change from prev to next? Every record verifies under the pinned registry keys and names
/// `ns`; none is missing or extra; each class is the one the diff computes. `None` = consistent, else the reason.
pub fn evolution_error(ns: &str, prev: &[Value], next: &[Value], records: &Value, keys: &Value, reg: &Registry, verifier: Verifier) -> Option<String> {
    let Some(recs) = records.as_array() else { return Some("evolution error: the records must be a list".into()) };
    for r in recs {
        if let Err(reason) = verify_evolution_record(r, keys) {
            return Some(format!("evolution record: {reason}"));
        }
        if get(r, "ns").as_str() != Some(ns) {
            return Some(format!("evolution record names namespace '{}', not '{ns}'", js_value_string(get(r, "ns"))));
        }
    }
    let compute = || -> Result<(Vec<String>, Vec<String>), String> {
        let mut want = evolution_records(ns, prev, next, reg, verifier)?.iter().map(key_of).collect::<Result<Vec<_>, _>>()?;
        let mut have = recs
            .iter()
            .map(|r| {
                let mut b = r.clone();
                if let Some(m) = b.as_object_mut() {
                    m.remove("sig");
                }
                key_of(&b)
            })
            .collect::<Result<Vec<_>, _>>()?;
        want.sort_by(|a, b| u16cmp(a, b));
        have.sort_by(|a, b| u16cmp(a, b));
        Ok((want, have))
    };
    let (want, have) = match compute() {
        Ok(x) => x,
        Err(e) => return Some(format!("evolution error: {e}")),
    };
    if want.len() != have.len() {
        return Some(format!("evolution has {} records, the change needs {}", have.len(), want.len()));
    }
    if want.iter().zip(&have).any(|(w, h)| w != h) {
        return Some("evolution records do not match the computed change (a missing, extra or mis-classified record)".into());
    }
    None
}
