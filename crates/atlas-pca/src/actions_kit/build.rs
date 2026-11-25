//! `pca actions build|sign` as pure functions (native port of `build.ts` of the reference): from defs to the unsigned schema, the
//! pack, policy cards, ontology fragment, MCP tool map and generated TypeScript declarations, plus pack signing and the
//! consistency check. Ed25519 signing takes a 32-byte seed.

use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

use super::derive::{card_of, mcp_annotations_of, operation_of, to_ontology, to_schema_doc};
use super::{arr, effective_with, get, ke, opt, u16cmp, Verifier};
use crate::actions::{def_digest, pack_root, tables_digest, traits_digest, validate_def, Registry};
use crate::actions_kit_ops::lint::lint_rules_digest;
use crate::agent::KeyPair;
use crate::intent_v2::js_value_string;
use crate::{b64_encode, canonicalize_strict, decode_b64u_strict, verify_b64u};

pub const MAX_PACK_DEFS: usize = 4096;
const PACK_SIGN_DOMAIN: &str = "atlas-pca/action-pack/v1\0";

fn digest_of(d: &Value) -> Result<String, String> {
    def_digest(d).ok_or_else(|| "the def is not in the strict JSON profile".to_string())
}

fn verb_of(d: &Value) -> &str {
    get(d, "verb").as_str().unwrap_or("")
}

fn mcp_tool(d: &Value) -> Option<&str> {
    opt(get(d, "bindings"), "mcp").and_then(|m| m.get("tool")).and_then(Value::as_str)
}

/// Every output of a build: `{schema, pack, cards, ontology, mcp, types}`. Errs on a pack above the unsharded limit, a duplicate
/// verb, an empty pack or a unit conflict (never a partial build). `cfg` is `{ns, version, stability, site, aud}`.
pub fn build_artifacts(defs_in: &[Value], cfg: &Value, reg: &Registry, verifier: Verifier) -> Result<Value, String> {
    let mut defs: Vec<Value> = defs_in.to_vec();
    defs.sort_by(|a, b| u16cmp(verb_of(a), verb_of(b)));
    if defs.len() > MAX_PACK_DEFS {
        return Err(format!("a pack above {MAX_PACK_DEFS} defs must be sharded ({} given)", defs.len()));
    }
    for w in defs.windows(2) {
        if verb_of(&w[0]) == verb_of(&w[1]) {
            return Err(format!("verb '{}' appears twice", verb_of(&w[0])));
        }
    }
    if defs.is_empty() {
        return Err("a pack has at least one def".into());
    }
    let digests = defs.iter().map(digest_of).collect::<Result<Vec<_>, _>>()?;
    let root = ke(pack_root(&digests))?;
    let meta = json!({"site": get(cfg, "site"), "aud": get(cfg, "aud"), "version": get(cfg, "version"), "pack": {"ns": get(cfg, "ns"), "version": get(cfg, "version"), "root": root}});
    let schema = to_schema_doc(&defs, reg, &meta, verifier)?;
    let pack = json!({
        "v": 1, "kind": "pca-action-pack", "ns": get(cfg, "ns"), "version": get(cfg, "version"), "stability": get(cfg, "stability"),
        "traits_digest": traits_digest(reg), "roles_digest": tables_digest(), "rules_digest": lint_rules_digest(), "root": root, "defs": defs, "prev": null, "evolution": [],
    });
    let mut cards = Vec::new();
    let mut tools = Map::new();
    for d in &defs {
        cards.push(card_of(d, &effective_with(d, reg, verifier)?, reg)?);
    }
    for d in &defs {
        if let Some(t) = mcp_tool(d) {
            tools.insert(t.to_string(), json!({"verb": get(d, "verb"), "annotations": mcp_annotations_of(d, &effective_with(d, reg, verifier)?)}));
        }
    }
    Ok(
        json!({"schema": schema, "pack": pack, "cards": cards, "ontology": to_ontology(&defs, reg, verifier)?, "mcp": {"tools": Value::Object(tools)}, "types": generate_types(&defs)}),
    )
}

/// The ToolActionMap of the defs' MCP bindings applied to one call: tool name and arguments to `{verb, resource}`, or `Null`.
pub fn tool_action(defs: &[Value], tool: &str, args: &Value) -> Value {
    let mut m: BTreeMap<&str, &Value> = BTreeMap::new();
    for d in defs {
        if let Some(t) = mcp_tool(d) {
            m.insert(t, d);
        }
    }
    let Some(d) = m.get(tool) else { return Value::Null };
    let r = operation_of(d, args);
    if r["ok"].as_bool() == Some(true) {
        json!({"verb": r["op"]["verb"], "resource": r["op"]["resource"]})
    } else {
        Value::Null
    }
}

// ---- generated types ---------------------------------------------------------------------------------------------------------

fn is_ident(k: &str) -> bool {
    let mut cs = k.chars();
    cs.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') && cs.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}

fn pascal(s: &str) -> String {
    s.split(['.', '_'])
        .map(|x| {
            let mut c = x.chars();
            c.next().map_or(String::new(), |f| f.to_uppercase().collect::<String>() + c.as_str())
        })
        .collect()
}

fn ts_type(p: &Value) -> String {
    let join_values = |v: &Value| arr(v).iter().map(|x| json_str(x.as_str().unwrap_or(""))).collect::<Vec<_>>().join(" | ");
    match get(p, "type").as_str().unwrap_or("") {
        "integer" | "duration" => "number".into(),
        "boolean" => "boolean".into(),
        "set" => {
            let j = join_values(get(p, "values"));
            format!("Array<{}>", if j.is_empty() { "string".to_string() } else { j })
        }
        "array" => {
            if get(p, "items").as_str() == Some("integer") {
                "number[]".into()
            } else {
                "string[]".into()
            }
        }
        _ => match opt(p, "values") {
            Some(v) => join_values(v),
            None => "string".into(),
        },
    }
}

#[derive(Default)]
struct Node {
    kids: Vec<(String, Node)>,
    leaf: Option<Value>,
}

impl Node {
    fn kid(&mut self, k: &str) -> &mut Node {
        if let Some(i) = self.kids.iter().position(|(n, _)| n == k) {
            return &mut self.kids[i].1;
        }
        self.kids.push((k.to_string(), Node::default()));
        &mut self.kids.last_mut().expect("just pushed").1
    }
}

fn render(n: &Node, indent: &str) -> String {
    let mut kids: Vec<&(String, Node)> = n.kids.iter().collect();
    kids.sort_by(|a, b| u16cmp(&a.0, &b.0));
    let mut lines = Vec::new();
    for (k, c) in kids {
        let key = if is_ident(k) { k.clone() } else { json_str(k) };
        match &c.leaf {
            Some(l) => {
                lines.push(format!("{indent}{key}{}: {};", if l.get("required").and_then(Value::as_bool) == Some(false) { "?" } else { "" }, ts_type(l)))
            }
            None => lines.push(format!("{indent}{key}: {{\n{}\n{indent}}};", render(c, &format!("{indent}  ")))),
        }
    }
    lines.join("\n")
}

/// TypeScript declarations for typed call sites: one params interface per verb, `ActionParams` and `ActionVerb`.
pub fn generate_types(defs: &[Value]) -> String {
    let mut out: Vec<String> = vec!["// Generated by `pca actions build`. Do not edit.".into(), String::new()];
    let mut names = Vec::new();
    let mut sorted: Vec<&Value> = defs.iter().collect();
    sorted.sort_by(|a, b| u16cmp(verb_of(a), verb_of(b)));
    for d in sorted {
        let mut root = Node::default();
        let params = get(d, "params");
        let mut pn: Vec<&String> = params.as_object().map(|m| m.keys().collect()).unwrap_or_default();
        pn.sort_by(|a, b| u16cmp(a, b));
        for name in pn {
            let segs: Vec<&str> = name.split('.').collect();
            let mut n = &mut root;
            for (i, s) in segs.iter().enumerate() {
                n = n.kid(s);
                if i == segs.len() - 1 {
                    n.leaf = Some(params[name.as_str()].clone());
                }
            }
        }
        let iface = format!("{}Params", pascal(verb_of(d)));
        names.push(format!("  {}: {iface};", json_str(verb_of(d))));
        out.extend([format!("export interface {iface} {{"), render(&root, "  "), "}".to_string(), String::new()]);
    }
    out.push("export interface ActionParams {".into());
    out.extend(names);
    out.extend(["}".to_string(), String::new(), "export type ActionVerb = keyof ActionParams;".to_string(), String::new()]);
    out.join("\n")
}

// ---- pack signing and consistency --------------------------------------------------------------------------------------------

fn pack_message(body: &Value) -> Result<Vec<u8>, String> {
    let mut m = PACK_SIGN_DOMAIN.as_bytes().to_vec();
    m.extend(canonicalize_strict(body)?.into_bytes());
    Ok(m)
}

/// `None` when the pack is internally consistent: every def valid and unique, the Merkle root and digests recomputed.
pub fn pack_consistency_error(p: &Value, reg: &Registry) -> Option<String> {
    if !p.is_object() {
        return Some("the pack must be an object".into());
    }
    if p.get("kind").and_then(Value::as_str) != Some("pca-action-pack") || p.get("v").and_then(Value::as_f64) != Some(1.0) {
        return Some("not a pca-action-pack v1".into());
    }
    let defs = match p.get("defs").and_then(Value::as_array) {
        Some(d) if d.len() <= MAX_PACK_DEFS => d,
        _ => return Some("defs must be a list within the unsharded limit".into()),
    };
    let mut seen: Vec<&str> = Vec::new();
    for d in defs {
        if let Some(e) = validate_def(d) {
            let label = if d.is_object() { d.get("verb").map_or("?".to_string(), js_value_string) } else { "?".to_string() };
            return Some(format!("def {label}: {e}"));
        }
        let v = verb_of(d);
        if seen.contains(&v) {
            return Some(format!("verb '{v}' is defined twice"));
        }
        seen.push(v);
    }
    let digests: Result<Vec<String>, String> = defs.iter().map(digest_of).collect();
    let root = match digests.and_then(|ds| ke(pack_root(&ds))) {
        Ok(r) => r,
        Err(e) => return Some(format!("malformed pack: {e}")),
    };
    if p.get("root").and_then(Value::as_str) != Some(root.as_str()) {
        return Some("the pack root does not match its defs".into());
    }
    if p.get("traits_digest").and_then(Value::as_str) != Some(traits_digest(reg).as_str()) {
        return Some("traits_digest does not match the trait registry".into());
    }
    None
}

/// Sign a pack as the registry (Ed25519, 32-byte seed). Refuses an inconsistent pack.
pub fn sign_pack(pack: &Value, kid: &str, secret: &[u8], reg: &Registry) -> Result<Value, String> {
    if let Some(bad) = pack_consistency_error(pack, reg) {
        return Err(format!("signPack: {bad}"));
    }
    let seed: [u8; 32] = secret.try_into().map_err(|_| "the registry key must be a 32-byte Ed25519 secret".to_string())?;
    let mut body = pack.as_object().cloned().unwrap_or_default();
    body.remove("sig");
    let body = Value::Object(body);
    let sig = KeyPair::from_seed(&seed).sign(&pack_message(&body)?);
    let mut out = body;
    out["sig"] = json!({"alg": "ed25519", "kid": kid, "value": b64_encode(&sig)});
    Ok(out)
}

/// The pinned registry key entry `{kid, alg, pk}` of a seed.
pub fn pack_key_of(kid: &str, secret: &[u8]) -> Result<Value, String> {
    let seed: [u8; 32] = secret.try_into().map_err(|_| "the registry key must be a 32-byte Ed25519 secret".to_string())?;
    Ok(json!({"kid": kid, "alg": "ed25519", "pk": KeyPair::from_seed(&seed).public}))
}

/// Verify a signed pack against pinned registry keys: consistency, the key entry by kid, and the signature. Never errs:
/// `{ok: true}` or `{ok: false, reason}`.
pub fn verify_signed_pack(pack: &Value, keys: &Value, reg: &Registry) -> Value {
    let fail = |r: String| json!({"ok": false, "reason": r});
    if let Some(bad) = pack_consistency_error(pack, reg) {
        return fail(bad);
    }
    let sig = match pack.get("sig").and_then(Value::as_object) {
        Some(s)
            if s.get("alg").and_then(Value::as_str) == Some("ed25519")
                && s.get("kid").is_some_and(Value::is_string)
                && s.get("value").is_some_and(Value::is_string) =>
        {
            s
        }
        _ => return fail("missing or malformed signature".into()),
    };
    let kid = sig["kid"].as_str().unwrap_or("");
    let Some(k) = arr(keys).iter().find(|x| x.get("kid").and_then(Value::as_str) == Some(kid)) else {
        return fail(format!("no registry key with kid '{kid}'"));
    };
    let pk = k.get("pk").and_then(Value::as_str);
    if k.get("alg").and_then(Value::as_str) != Some("ed25519") || pk.and_then(|p| decode_b64u_strict(p, Some(32))).is_none() {
        return fail("the registry key entry is malformed".into());
    }
    let mut body = pack.as_object().cloned().unwrap_or_default();
    body.remove("sig");
    let msg = match pack_message(&Value::Object(body)) {
        Ok(m) => m,
        Err(e) => return fail(format!("pack verification error: {e}")),
    };
    if verify_b64u(pk.unwrap_or(""), &msg, sig["value"].as_str().unwrap_or("")) {
        json!({"ok": true})
    } else {
        fail("pack signature invalid".into())
    }
}
