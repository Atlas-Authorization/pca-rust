//! FGA for RAG: retrieval-time, per-principal document filtering driven by the PCA policy evaluator (the pure core of the
//! reference's `@atlasauth/pca-rag`: `aclsFromMetadata`, `compilePolicy`, `principalFromPCActn`, `filterDocuments`).
//!
//! FAIL CLOSED: a document is admitted only when a permit predicate cleanly matches one of its ACL entries (verb = relation,
//! resource = object) and no deny predicate matches. Anything unknown (no ACL, a malformed document, an incomplete policy
//! translation, an evaluator error) drops the document. Every decision is recorded, with a content digest of the whole decision set
//! that binds into a proof trace.
//!
//! Everything is JSON-valued. A principal is a string id or `{id, attributes?, env?}`. A policy is a list of predicates,
//! `{openfga: {model, tuples}}`, `{predicates, denies?, report?}` or an already compiled policy ([`compile_policy`]'s result).
//!
//! shortcut: the framework-shaped retriever wrappers of the reference (`withPcaFilter` and the LangChain / LlamaIndex structural
//! ones) are adapters, not part of this pure core; wrap [`filter_documents_with`] around your retriever. A string attribute bag is
//! spread per UTF-16 unit by the reference; an astral character becomes U+FFFD here (a Rust string holds no lone surrogate).
use crate::arg_provenance::ProvenanceRecorder;
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::panic::{catch_unwind, AssertUnwindSafe};

static NULL: Value = Value::Null;

fn non_empty(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(s)) if !s.is_empty())
}

fn is_doc_acl(v: &Value) -> bool {
    matches!(v, Value::Object(m) if non_empty(m.get("relation")) && non_empty(m.get("object")))
}

fn acl_array(acl: &Value) -> Vec<Value> {
    match acl {
        Value::Array(l) => l.iter().filter(|a| is_doc_acl(a)).cloned().collect(),
        a if is_doc_acl(a) => vec![a.clone()],
        _ => Vec::new(),
    }
}

/// A `relation:object` tag as an ACL entry; the split is at the FIRST colon, so an object id may itself contain colons.
fn tag_to_acl(tag: &Value) -> Option<Value> {
    let t = tag.as_str()?;
    let i = t.find(':')?;
    if i == 0 || i + 1 >= t.len() {
        return None;
    }
    Some(json!({ "relation": &t[..i], "object": &t[i + 1..] }))
}

/// ACL entries from freeform `acl` (one `{relation, object}` entry or a list) and `tags` (`relation:object` strings) metadata.
/// Entries that are not `{relation, object}` strings, and tags that do not split, are not ACLs.
pub fn acls_from_metadata(acl: &Value, tags: &Value) -> Vec<Value> {
    let mut out = acl_array(acl);
    if let Value::Array(l) = tags {
        out.extend(l.iter().filter_map(tag_to_acl));
    }
    out
}

/// The acting identity of a verified PCActn: its LEAF capability holder (map the key to the policy's identity with `opts.id`).
/// `opts` is `{id?, attributes?, env?}`. A PCActn with no leaf holder is an error rather than an empty principal.
pub fn principal_from_pcactn(pcactn: &Value, opts: Option<&Value>) -> Result<Value, String> {
    let leaf = pcactn.get("cap_chain").and_then(Value::as_array).and_then(|c| c.last());
    let holder = leaf.and_then(|l| l.get("holder")).and_then(Value::as_str).filter(|s| !s.is_empty());
    let holder = holder.ok_or("principalFromPCActn: PCActn has no leaf capability holder")?;
    let opt = |k: &str| opts.and_then(|o| o.get(k));
    let mut out = Map::new();
    out.insert("id".into(), opt("id").filter(|v| !v.is_null()).cloned().unwrap_or_else(|| json!(holder)));
    for k in ["attributes", "env"] {
        if let Some(v) = opt(k) {
            out.insert(k.into(), v.clone());
        }
    }
    Ok(Value::Object(out))
}

fn to_principal(p: &Value) -> Map<String, Value> {
    match p {
        Value::String(s) => {
            let mut m = Map::new();
            m.insert("id".into(), json!(s));
            m
        }
        Value::Object(m) => m.clone(),
        Value::Array(_) => Map::new(), // a JavaScript array is an object with no id
        _ => {
            let mut m = Map::new();
            m.insert("id".into(), json!(""));
            m
        }
    }
}

fn incomplete(reason: &str) -> Value {
    json!({ "predicates": [], "denies": [], "incomplete": true, "incompleteReason": reason })
}

/// JavaScript `x.length > 0` for a JSON value that is not null.
fn length_positive(x: &Value) -> bool {
    match x {
        Value::Array(a) => !a.is_empty(),
        Value::String(s) => !s.is_empty(),
        Value::Object(m) => m.get("length").and_then(Value::as_f64).is_some_and(|n| n > 0.0),
        _ => false,
    }
}

/// Compile any policy into `{predicates, denies, incomplete, incompleteReason?, report?}`; an already compiled policy passes
/// through. A value that is not a policy, or a translation with errors, is INCOMPLETE: nothing is admitted. A
/// `{predicates, report}` whose report has no `errors` member is an error (the reference reads `report.errors.length`).
pub fn compile_policy(policy: &Value) -> Result<Value, String> {
    let o = match policy {
        Value::Array(l) => return Ok(json!({ "predicates": l, "denies": [], "incomplete": false })),
        Value::Object(o) => o,
        _ => return Ok(incomplete("no usable policy was supplied (fail closed)")),
    };
    if o.get("incomplete").is_some_and(Value::is_boolean) {
        return Ok(policy.clone());
    }
    if let Some(fga) = o.get("openfga") {
        let (model, tuples) = match fga {
            Value::Object(f) => (f.get("model").unwrap_or(&NULL), f.get("tuples")),
            Value::Array(_) => (&NULL, None), // an array has no model or tuples
            _ => return Ok(incomplete("the OpenFGA policy has no model (fail closed)")),
        };
        let br = crate::policy_bridge::openfga_to_pca(model, tuples);
        let errors = br["report"]["errors"].as_array().map_or(0, Vec::len);
        return Ok(json!({ "predicates": br["predicates"], "denies": br["denies"], "report": br["report"], "incomplete": errors > 0 }));
    }
    let predicates = match o.get("predicates").filter(|p| p.is_array()) {
        Some(p) => p.clone(),
        None => return Ok(incomplete("the policy has no predicates and is not an OpenFGA policy (fail closed)")),
    };
    let denies = o.get("denies").filter(|d| d.is_array()).cloned().unwrap_or_else(|| json!([]));
    let mut out = json!({ "predicates": predicates, "denies": denies, "incomplete": false });
    if let Some(report) = o.get("report") {
        let errors = report.as_object().and_then(|r| r.get("errors")).filter(|e| !e.is_null());
        let errors = errors.ok_or("compilePolicy: report.errors is required")?;
        out["report"] = report.clone();
        out["incomplete"] = json!(length_positive(errors));
    }
    Ok(out)
}

/// `{...attributes, id}`: object spread of a map, a list (index keys) or a string (one key per UTF-16 unit).
fn subject(principal: &Map<String, Value>) -> Map<String, Value> {
    let mut s = Map::new();
    match principal.get("attributes") {
        Some(Value::Object(a)) => s.extend(a.iter().map(|(k, v)| (k.clone(), v.clone()))),
        Some(Value::Array(a)) => s.extend(a.iter().enumerate().map(|(i, v)| (i.to_string(), v.clone()))),
        Some(Value::String(t)) => s.extend(t.encode_utf16().enumerate().map(|(i, u)| (i.to_string(), Value::String(String::from_utf16_lossy(&[u]))))),
        _ => {}
    }
    if let Some(id) = principal.get("id") {
        s.insert("id".into(), id.clone());
    }
    s
}

fn decide_document(id: &str, acls: &[Value], principal: &Map<String, Value>, compiled: &Value) -> Value {
    if compiled.get("incomplete") == Some(&Value::Bool(true)) {
        let why = compiled.get("incompleteReason").and_then(Value::as_str).unwrap_or("policy translation incomplete (fail closed)");
        return json!({ "id": id, "allowed": false, "reason": why });
    }
    let pid = match principal.get("id") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return json!({ "id": id, "allowed": false, "reason": "no principal identity (fail closed)" }),
    };
    if acls.is_empty() {
        return json!({ "id": id, "allowed": false, "reason": "no decidable ACL metadata (fail closed)" });
    }
    let mut last = "no relation grants access (fail closed)".to_string();
    let mut pol = Map::new();
    for k in ["predicates", "denies"] {
        if let Some(v) = compiled.get(k) {
            pol.insert(k.into(), v.clone());
        }
    }
    let pol = Value::Object(pol);
    let subj = Value::Object(subject(principal));
    for acl in acls {
        let mut ctx = json!({ "action": { "verb": acl["relation"], "resource": acl["object"] }, "subject": subj });
        if let Some(env) = principal.get("env") {
            ctx["env"] = env.clone();
        }
        let res = match catch_unwind(AssertUnwindSafe(|| crate::policy_bridge::decide(&pol, &ctx))) {
            Ok(Ok(r)) => r,
            _ => {
                last = "evaluator error (fail closed)".into();
                continue;
            }
        };
        if res["allowed"] == json!(true) {
            let mut d = json!({ "id": id, "allowed": true, "via": acl,
                "reason": format!("granted: {pid} has {} on {}", acl["relation"].as_str().unwrap_or(""), acl["object"].as_str().unwrap_or("")) });
            if let Some(m) = res.get("matched").filter(|m| !m.is_null()) {
                d["matched"] = m.clone();
            }
            return d;
        }
        if let Some(r) = res["reason"].as_str() {
            last = r.to_string();
        }
    }
    json!({ "id": id, "allowed": false, "reason": last })
}

/// A candidate's id (`None`/non-string/empty: positional `doc#i`) or ACL entries; an error marks the document unreadable (dropped).
pub type DocIdFn<'a> = &'a dyn Fn(&Value, usize) -> Result<Value, String>;
pub type DocAclsFn<'a> = &'a dyn Fn(&Value) -> Result<Value, String>;

/// How a document is read. Defaults: `doc.id`, and `doc.acl` + `relation:object` `doc.tags`. `recorder`, when set, records every
/// admitted document as UNTRUSTED retrieval content (an instruction planted in a document cannot later choose who, where or how much).
#[derive(Default)]
pub struct FilterOptions<'a> {
    pub get_id: Option<DocIdFn<'a>>,
    pub get_acls: Option<DocAclsFn<'a>>,
    pub recorder: Option<&'a mut ProvenanceRecorder>,
}

/// The admitted documents (candidate order) and the decision record (the proof trace: principal, considered, allowedIds,
/// allowedIndexes, droppedIds, policyIncomplete, decisions, digest, report?).
#[derive(Debug, Clone)]
pub struct FilterResult {
    pub documents: Vec<Value>,
    pub decision: Value,
}

fn default_id(doc: &Value, _i: usize) -> Result<Value, String> {
    if doc.is_null() {
        return Err("cannot read properties of null (reading 'id')".into());
    }
    Ok(doc.get("id").cloned().unwrap_or(Value::Null))
}

fn default_acls(doc: &Value) -> Result<Value, String> {
    if doc.is_null() {
        return Err("cannot read properties of null (reading 'acl')".into());
    }
    Ok(Value::Array(acls_from_metadata(doc.get("acl").unwrap_or(&NULL), doc.get("tags").unwrap_or(&NULL))))
}

/// [`filter_documents_with`] with the default readers and no recorder.
pub fn filter_documents(principal: &Value, candidates: &Value, policy: &Value) -> Result<FilterResult, String> {
    filter_documents_with(principal, candidates, policy, &mut FilterOptions::default())
}

/// Filter `candidates` to the documents `principal` may see under `policy`. FAILS CLOSED: a document is admitted only when a permit
/// predicate cleanly matches one of its ACL entries and no deny matches; anything unknown is dropped. A non-list candidate set is
/// empty. An error is only a digest outside the strict JSON profile, or a policy whose report has no `errors`.
pub fn filter_documents_with(principal: &Value, candidates: &Value, policy: &Value, opts: &mut FilterOptions<'_>) -> Result<FilterResult, String> {
    let pr = to_principal(principal);
    let compiled = compile_policy(policy)?;
    let list: &[Value] = candidates.as_array().map(Vec::as_slice).unwrap_or(&[]);
    let get_id: DocIdFn<'_> = opts.get_id.unwrap_or(&default_id);
    let get_acls: DocAclsFn<'_> = opts.get_acls.unwrap_or(&default_acls);
    let (mut documents, mut decisions) = (Vec::new(), Vec::new());
    let (mut allowed_ids, mut dropped_ids, mut allowed_idx) = (Vec::new(), Vec::new(), Vec::new());
    let mut seen: HashSet<String> = HashSet::new();
    for (i, doc) in list.iter().enumerate() {
        let (raw_id, raw_acls) = match (get_id(doc, i), get_acls(doc)) {
            (Ok(a), Ok(b)) => (a, b),
            _ => {
                let fid = format!("doc#{i}");
                decisions.push(json!({ "id": fid, "allowed": false, "reason": "unreadable document metadata (fail closed)" }));
                dropped_ids.push(json!(fid));
                continue;
            }
        };
        let mut id = match raw_id {
            Value::String(s) if !s.is_empty() => s,
            _ => format!("doc#{i}"),
        };
        if seen.contains(&id) {
            id = format!("{id}#dup{i}");
        }
        seen.insert(id.clone());
        let d = decide_document(&id, &acl_array(&raw_acls), &pr, &compiled);
        let allowed = d["allowed"] == json!(true);
        decisions.push(d);
        if allowed {
            documents.push(doc.clone());
            allowed_ids.push(json!(id));
            allowed_idx.push(json!(i));
        } else {
            dropped_ids.push(json!(id));
        }
    }
    let pid = pr.get("id").and_then(Value::as_str).unwrap_or("");
    let base = json!({ "principal": pid, "considered": list.len(), "allowedIds": allowed_ids, "allowedIndexes": allowed_idx,
        "droppedIds": dropped_ids, "policyIncomplete": compiled.get("incomplete") == Some(&Value::Bool(true)) });
    let mut hashed = json!({ "v": 1, "kind": "pca-rag/filter" });
    let mut decision = Value::Object(Map::new());
    for (k, v) in base.as_object().into_iter().flatten() {
        hashed[k.as_str()] = v.clone();
        decision[k.as_str()] = v.clone();
    }
    decision["decisions"] = Value::Array(decisions);
    decision["digest"] = json!(crate::hash_canonical_strict(&hashed).ok_or("filterDocuments: the decision is outside the strict JSON profile")?);
    if let Some(r) = compiled.get("report") {
        decision["report"] = r.clone();
    }
    if let Some(rec) = opts.recorder.as_deref_mut() {
        for (i, doc) in documents.iter().enumerate() {
            let src = match get_id(doc, i) {
                Ok(Value::String(s)) => s,
                _ => format!("doc#{i}"),
            };
            rec.retrieval(&src, doc)?;
        }
    }
    Ok(FilterResult { documents, decision })
}
