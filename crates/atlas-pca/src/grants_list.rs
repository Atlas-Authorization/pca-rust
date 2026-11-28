//! List-authorized (port of @atlasauth/pca-grants): "which objects of this type may this agent touch?". Authority is capability AND
//! relationship: `permits` (the grant's own predicates) decides, a relation source can only NARROW. Every page is charged to a read
//! accumulator (scanned AND returned objects), pages are bound by a signed cursor (changing subject, type, filter, policy, relation or
//! limit between pages is refused) and the result carries a signed receipt.
//!
//! A candidate source answers `page({type, cursor?, limit}) -> {objects, next?}`; a relation source `check({subject, relation, object})`
//! and optionally `list_objects({subject, relation, type, cursor?, limit})`; a read accumulator `charge(key, units, now)`
//! ([`WindowReadAccumulator`] is the reference one). The verification side (cursor, receipt, bind) is [`crate::k3`].
use crate::attest::util::b64url_enc;
use crate::grants::{sign_body, signer_of};
use crate::k3::{list_bind, objects_digest, verify_list_cursor, LIST_CURSOR_DOMAIN, LIST_RECEIPT_DOMAIN};
use crate::{hash_canonical, js_stringify, safe_int};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Mutex;

pub const MAX_PAGE_LIMIT: i64 = 500;

/// `code` is `read_budget_exhausted`, `bad_cursor`, `bad_limit`, or `x` for a failing source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListError {
    pub code: String,
    pub message: String,
}

impl ListError {
    fn new(code: &str, message: &str) -> Self {
        Self { code: code.to_string(), message: message.to_string() }
    }
}

impl std::fmt::Display for ListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// Where candidate objects come from: one page `{objects: [string], next?: string}`.
pub trait CandidateSource {
    fn page(&self, q: &Value) -> Result<Value, String>;
}

/// The relationship graph: does `subject` hold `relation` on `object`? Optionally it can enumerate objects.
pub trait RelationSource {
    fn check(&self, q: &Value) -> Result<bool, String>;
    /// Does this source enumerate (`list_objects`)?
    fn has_list_objects(&self) -> bool {
        false
    }
    fn list_objects(&self, _q: &Value) -> Option<Result<Value, String>> {
        None
    }
}

/// Read budget: `charge` returns false when the charge would exceed the cap.
pub trait ReadAccumulator {
    fn charge(&self, key: &str, units: i64, now: i64) -> bool;
}

/// Reference accumulator: `cap` units per `window_ms` fixed window per key.
pub struct WindowReadAccumulator {
    cap: i64,
    window: i64,
    used: Mutex<HashMap<String, (i64, i64)>>,
}

impl WindowReadAccumulator {
    pub fn new(cap: i64, window_ms: i64) -> Self {
        Self { cap, window: window_ms, used: Mutex::new(HashMap::new()) }
    }
}

impl ReadAccumulator for WindowReadAccumulator {
    fn charge(&self, key: &str, units: i64, now: i64) -> bool {
        let mut m = self.used.lock().unwrap_or_else(|e| e.into_inner());
        let (start, n) = match m.get(key) {
            Some(&(start, n)) if now - start < self.window => (start, n),
            _ => (now, 0),
        };
        if n + units > self.cap {
            return false;
        }
        m.insert(key.to_string(), (start, n + units));
        true
    }
}

/// A relation source's `list_objects` as a candidate source for one subject and relation.
pub struct RelationCandidates<'a> {
    rel: &'a dyn RelationSource,
    subject: String,
    relation: String,
}

impl CandidateSource for RelationCandidates<'_> {
    fn page(&self, q: &Value) -> Result<Value, String> {
        let mut m = Map::new();
        m.insert("subject".to_string(), json!(self.subject));
        m.insert("relation".to_string(), json!(self.relation));
        if let Some(o) = q.as_object() {
            for (k, v) in o {
                m.insert(k.clone(), v.clone());
            }
        }
        self.rel.list_objects(&Value::Object(m)).unwrap_or_else(|| Err("candidatesFromRelation: the relation source has no listObjects".to_string()))
    }
}

/// Adapt a relation source's `list_objects` into a candidate source. Errs when it has none.
pub fn candidates_from_relation<'a>(rel: &'a dyn RelationSource, subject: &str, relation: &str) -> Result<RelationCandidates<'a>, String> {
    if !rel.has_list_objects() {
        return Err("candidatesFromRelation: the relation source has no listObjects".to_string());
    }
    Ok(RelationCandidates { rel, subject: subject.to_string(), relation: relation.to_string() })
}

/// One page request. `relation` is `(source, relation name)`; `cursor` the previous page's `next_cursor`; `limit` is a JSON number
/// (1..=500 safe integer, else `bad_limit`).
pub struct ListRequest<'a> {
    pub subject: &'a str,
    pub resource_type: &'a str,
    pub permits: &'a dyn Fn(&str) -> bool,
    pub candidates: &'a dyn CandidateSource,
    pub relation: Option<(&'a dyn RelationSource, &'a str)>,
    pub filter_id: &'a str,
    pub policy_digest: &'a str,
    pub fresh_at_digest: &'a str,
    pub cursor: Option<&'a str>,
    pub limit: &'a Value,
    pub reads: &'a dyn ReadAccumulator,
    pub now: i64,
    pub signing_secret: [u8; 32],
    pub max_scan: Option<i64>,
}

fn source_err(e: String) -> ListError {
    ListError { code: "x".to_string(), message: e }
}

/// One page of authorized objects: `{objects, next_cursor?, receipt}`. Errs with [`ListError`] (`bad_limit`, `bad_cursor`,
/// `read_budget_exhausted`; `x` for a candidate or relation source that failed).
pub fn list_authorized(r: &ListRequest) -> Result<Value, ListError> {
    let limit = match safe_int(r.limit) {
        Some(l) if (1..=MAX_PAGE_LIMIT).contains(&l) => l,
        _ => return Err(ListError::new("bad_limit", &format!("limit must be 1..{MAX_PAGE_LIMIT}"))),
    };
    let secret = r.signing_secret;
    let signer = signer_of(&secret);
    let mut bind_inputs =
        json!({"subject": r.subject, "resourceType": r.resource_type, "filterId": r.filter_id, "policyDigest": r.policy_digest, "limit": limit});
    if let Some((_, name)) = r.relation {
        bind_inputs["relation"] = json!({"relation": name});
    }
    let bind = list_bind(&bind_inputs).ok_or_else(|| source_err("list bind is outside the strict JSON profile".to_string()))?;
    let mut inner: Option<String> = None;
    let mut skip_in: i64 = 0;
    if let Some(cur) = r.cursor {
        let c = verify_list_cursor(&Value::String(cur.to_string()), &signer, Some(&bind_inputs));
        if c.get("ok") != Some(&Value::Bool(true)) {
            return Err(if c.get("reason").and_then(Value::as_str) == Some("bind") {
                ListError::new("bad_cursor", "subject, type, filter, policy or limit changed between pages")
            } else {
                ListError::new("bad_cursor", "the page cursor is malformed, forged or from another signer")
            });
        }
        inner = c.get("inner").and_then(Value::as_str).map(String::from);
        skip_in = c.get("skip").and_then(Value::as_i64).unwrap_or(0);
    }
    let max_scan_n = r.max_scan.unwrap_or(limit * 4).min(1000);
    let key = hash_canonical(&json!({"s": r.subject, "t": r.resource_type}));
    let mut out: Vec<Value> = Vec::new();
    let mut scanned: i64 = 0;
    // candidate pages are always `limit` long so a resume point (page start + objects already consumed) is exact
    let mut page_start = inner;
    let mut skip = skip_in;
    let mut resume: Option<(Option<String>, i64)> = None;
    loop {
        let mut q = Map::new();
        q.insert("type".to_string(), json!(r.resource_type));
        q.insert("limit".to_string(), json!(limit));
        if let Some(ps) = &page_start {
            q.insert("cursor".to_string(), json!(ps));
        }
        let pg = r.candidates.page(&Value::Object(q)).map_err(source_err)?;
        let objs: Vec<Value> = pg
            .get("objects")
            .and_then(Value::as_array)
            .ok_or_else(|| source_err("candidate page without objects".to_string()))?
            .iter()
            .take(limit as usize)
            .cloned()
            .collect();
        // charge what was SCANNED before anything is returned: enumeration by filter-heavy scans is the attack
        let units = (objs.len() as i64 - skip).max(1);
        if !r.reads.charge(&key, units, r.now) {
            return Err(ListError::new("read_budget_exhausted", "the read budget for this subject and type is exhausted"));
        }
        let mut i = skip.max(0) as usize;
        while i < objs.len() && (out.len() as i64) < limit {
            scanned += 1;
            let o = &objs[i];
            i += 1;
            let Some(name) = o.as_str() else { continue };
            if !(r.permits)(name) {
                continue;
            }
            if let Some((source, relation)) = r.relation {
                let allowed = source.check(&json!({"subject": r.subject, "relation": relation, "object": name})).map_err(source_err)?;
                if !allowed {
                    continue;
                }
            }
            out.push(o.clone());
        }
        if i < objs.len() {
            resume = Some((page_start.clone(), i as i64));
            break;
        }
        let next = pg.get("next").and_then(Value::as_str).unwrap_or("");
        if next.is_empty() || objs.is_empty() {
            break;
        }
        page_start = Some(next.to_string());
        skip = 0;
        if (out.len() as i64) >= limit || scanned >= max_scan_n {
            resume = Some((Some(next.to_string()), 0));
            break;
        }
    }
    let objects = Value::Array(out);
    let receipt = json!({
        "v": 1, "subject": r.subject, "resource_type": r.resource_type, "policy_digest": r.policy_digest, "fresh_at": r.fresh_at_digest,
        "filter_digest": r.filter_id, "count": objects.as_array().map_or(0, Vec::len), "objects_digest": objects_digest(&objects), "issued_at": r.now, "signer": signer,
    });
    let mut result = json!({"objects": objects});
    if let Some((inner, skip)) = resume {
        let mut c = Map::new();
        c.insert("v".to_string(), json!(1));
        if let Some(i) = inner {
            c.insert("inner".to_string(), Value::String(i));
        }
        c.insert("skip".to_string(), json!(skip));
        c.insert("bind".to_string(), Value::String(bind));
        c.insert("signer".to_string(), Value::String(signer.clone()));
        let c = Value::Object(c);
        let sig = sign_body(LIST_CURSOR_DOMAIN, &c, &secret).map_err(source_err)?;
        result["next_cursor"] = Value::String(format!("{}.{}", b64url_enc(js_stringify(&c).as_bytes()), sig));
    }
    let rsig = sign_body(LIST_RECEIPT_DOMAIN, &receipt, &secret).map_err(source_err)?;
    let mut receipt = receipt;
    receipt["sig"] = Value::String(rsig);
    result["receipt"] = receipt;
    Ok(result)
}
