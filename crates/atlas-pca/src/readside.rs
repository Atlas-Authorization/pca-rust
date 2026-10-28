//! K5 read-side authorization: `redact_read` (what an agent may SEE), `check_sink` (where it may go next), `read_chain_labels`.
//! A pure, total port of packages/pca/src/readside.ts; replays packages/pca/conformance/readside-vectors.json. Anything malformed,
//! unsigned, unknown or out of scope denies; no function panics. Integers only (see `workflow.rs`).
use crate::fresh_at::verify_body;
use crate::hash_canonical_strict;
use crate::workflow::{int, is_b32, is_b32_str, is_id_str, is_label_str, is_name_str, is_scalar_map, is_str, is_uint, only_keys, sorted_unique, uint, Decision};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const READ_GRANT_DOMAIN: &str = "atlas-pca/read-grant/v1\0";
pub const READ_RECEIPT_DOMAIN: &str = "atlas-pca/read-receipt/v1\0";
const RG_REF: &str = "atlas-pca/read-grant-ref/v1";
const RR_REF: &str = "atlas-pca/read-receipt-ref/v1";
const RH: &str = "atlas-pca/read-hash/v1";
const RT: &str = "atlas-pca/read-token/v1";
const RV: &str = "atlas-pca/read-value/v1";
const SALT_MIN: usize = 16;

/// `show|last4|hash|token|drop|bucket:[1-9][0-9]{0,8}`.
fn is_mode_str(m: &str) -> bool {
    if let Some(n) = m.strip_prefix("bucket:") {
        let b = n.as_bytes();
        return (1..=9).contains(&b.len()) && (b'1'..=b'9').contains(&b[0]) && b.iter().all(u8::is_ascii_digit);
    }
    matches!(m, "show" | "last4" | "hash" | "token" | "drop")
}
fn is_mode(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(is_mode_str)
}
fn rank(m: &str) -> u8 {
    match m {
        "show" => 0,
        "last4" => 1,
        "token" => 3,
        "hash" => 4,
        "drop" => 5,
        _ => 2, // bucket:N
    }
}

struct Entry {
    verb: String,
    resource_prefix: String,
    purposes: Vec<String>,
    modes: BTreeMap<String, String>,
    default_mode: String,
}
pub(crate) struct SinkRule {
    pub(crate) allow: Vec<String>,
    pub(crate) escalate: Vec<String>,
}
pub(crate) struct Grant {
    principal: String,
    issued_at: i64,
    expires_at: i64,
    reads: Vec<Entry>,
    caps: BTreeMap<String, i64>,
    pub(crate) sinks: BTreeMap<String, SinkRule>,
}

fn s(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).map(str::to_string)
}
fn parse_entry(v: &Value) -> Option<Entry> {
    let e = v.as_object().filter(|e| only_keys(e, &["verb", "resource_prefix", "purposes", "modes", "default_mode"]))?;
    if !(is_str(e.get("verb"), 128) && is_str(e.get("resource_prefix"), 512) && is_mode(e.get("default_mode"))) {
        return None;
    }
    let purposes = sorted_unique(e.get("purposes"), is_id_str, 16).filter(|p| !p.is_empty())?;
    let mo = e.get("modes")?.as_object().filter(|m| m.len() <= 32)?;
    let mut modes = BTreeMap::new();
    for (k, x) in mo {
        if !is_label_str(k) || !is_mode(Some(x)) {
            return None;
        }
        modes.insert(k.clone(), s(Some(x))?);
    }
    Some(Entry { verb: s(e.get("verb"))?, resource_prefix: s(e.get("resource_prefix"))?, purposes, modes, default_mode: s(e.get("default_mode"))? })
}
/// Shape of a read grant body (no signature): `validReadGrantBody`.
fn parse_grant(v: &Value) -> Option<Grant> {
    let b = v.as_object().filter(|b| only_keys(b, &["v", "id", "principal", "issued_at", "expires_at", "reads", "caps", "sinks"]))?;
    if b.get("v").and_then(int) != Some(1) || !b.get("id")?.as_str().is_some_and(is_id_str) || !is_b32(b.get("principal")) || !is_uint(b.get("issued_at")) || !is_uint(b.get("expires_at")) {
        return None;
    }
    let ra = b.get("reads")?.as_array().filter(|a| !a.is_empty() && a.len() <= 32)?;
    let reads = ra.iter().map(parse_entry).collect::<Option<Vec<_>>>()?;
    let co = b.get("caps")?.as_object().filter(|c| c.len() <= 32)?;
    let mut caps = BTreeMap::new();
    for (k, x) in co {
        if !is_label_str(k) {
            return None;
        }
        caps.insert(k.clone(), uint(x)?);
    }
    let so = b.get("sinks")?.as_object().filter(|m| m.len() <= 16)?;
    let mut sinks = BTreeMap::new();
    for (k, x) in so {
        let r = x.as_object().filter(|r| only_keys(r, &["allow", "escalate"]))?;
        let allow = sorted_unique(r.get("allow"), is_label_str, 16)?;
        let escalate = sorted_unique(r.get("escalate"), is_label_str, 16)?;
        if !is_id_str(k) || allow.iter().any(|l| escalate.contains(l)) {
            return None;
        }
        sinks.insert(k.clone(), SinkRule { allow, escalate });
    }
    Some(Grant { principal: s(b.get("principal"))?, issued_at: b.get("issued_at").and_then(uint)?, expires_at: b.get("expires_at").and_then(uint)?, reads, caps, sinks })
}

pub fn read_grant_digest(body: &Value) -> Option<String> {
    hash_canonical_strict(&json!({ "d": RG_REF, "g": body }))
}
pub fn read_receipt_ref(r: &Value) -> Option<String> {
    hash_canonical_strict(&json!({ "d": RR_REF, "r": r }))
}

/// `gradeGrant`: the verified grant, its raw body and `now`, or the refusal code. A principal that is not a canonical 32-byte key
/// or a `now` that is not an unsigned safe integer (missing, null, float, string) denies `bad_request` first.
pub(crate) fn grade_grant<'a>(g: Option<&'a Value>, principal: Option<&Value>, now: Option<&Value>) -> Result<(Grant, &'a Value, i64), &'static str> {
    let (Some(p), Some(now)) = (principal.and_then(Value::as_str).filter(|p| is_b32_str(p)), now.and_then(uint)) else { return Err("bad_request") };
    let sg = g.and_then(Value::as_object).filter(|o| only_keys(o, &["body", "sig"])).ok_or("bad_grant")?;
    let raw = &sg["body"];
    let body = parse_grant(raw).ok_or("bad_grant")?;
    if body.principal != p || !verify_body(READ_GRANT_DOMAIN, raw, p, sg["sig"].as_str()) {
        return Err("bad_signature");
    }
    if now < body.issued_at {
        return Err("not_yet");
    }
    if now >= body.expires_at {
        return Err("expired");
    }
    Ok((body, raw, now))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadField {
    pub class: String,
    /// `shown` | `masked` | `dropped`
    pub action: &'static str,
    pub kind: Option<String>,
    pub vd: String,
}
impl ReadField {
    fn to_json(&self) -> Value {
        json!({ "class": self.class, "action": self.action, "kind": self.kind, "vd": self.vd })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReadResult {
    pub decision: Decision,
    pub code: Option<&'static str>,
    pub view: Map<String, Value>,
    pub fields: BTreeMap<String, ReadField>,
    pub labels: Vec<String>,
    pub counts: BTreeMap<String, i64>,
}
impl ReadResult {
    /// The shape of the shared vectors: `{decision, code, view, fields, labels, counts}`.
    pub fn to_json(&self) -> Value {
        json!({
            "decision": self.decision.as_str(),
            "code": self.code,
            "view": self.view,
            "fields": self.fields.iter().map(|(k, f)| (k.clone(), f.to_json())).collect::<Map<String, Value>>(),
            "labels": self.labels,
            "counts": self.counts,
        })
    }
}
fn out(decision: Decision, code: &'static str, counts: BTreeMap<String, i64>) -> ReadResult {
    ReadResult { decision, code: Some(code), view: Map::new(), fields: BTreeMap::new(), labels: vec![], counts }
}
fn no(code: &'static str) -> ReadResult {
    out(Decision::Deny, code, BTreeMap::new())
}
fn uint_counts(v: Option<&Value>) -> Option<BTreeMap<String, i64>> {
    let o = v?.as_object()?;
    let mut m = BTreeMap::new();
    for (k, x) in o {
        if !is_label_str(k) {
            return None;
        }
        m.insert(k.clone(), uint(x)?);
    }
    Some(m)
}

/// The mask of one field: `Some(shown)` or `None` (dropped). `None` inside `Err` is a throw in the reference.
fn mask(mode: &str, v: &Value, cls: &str, salt: &str) -> Result<Option<Value>, ()> {
    Ok(if mode == "last4" {
        // BMP check and the last four count Unicode scalar values
        match v.as_str() {
            Some(t) if t.chars().all(|c| (c as u32) < 0x10000) && t.chars().count() > 4 => {
                let tail: Vec<char> = t.chars().rev().take(4).collect();
                Some(Value::String(format!("****{}", tail.iter().rev().collect::<String>())))
            }
            _ => None,
        }
    } else if let Some(n) = mode.strip_prefix("bucket:") {
        let n: i64 = n.parse().map_err(|_| ())?;
        match int(v) {
            Some(x) if x >= 0 && n > 0 => Some(json!(x - (x % n))),
            _ => None,
        }
    } else if mode == "hash" {
        Some(Value::String(hash_canonical_strict(&json!({ "d": RH, "salt": salt, "c": cls, "v": v })).ok_or(())?))
    } else if mode == "token" {
        let h = hash_canonical_strict(&json!({ "d": RT, "salt": salt, "c": cls, "v": v })).ok_or(())?;
        Some(Value::String(format!("tok_{}", h.get(..22).ok_or(())?)))
    } else {
        None // drop
    })
}

fn class_labels(fields: impl Iterator<Item = (String, bool)>) -> Vec<String> {
    fields.filter(|(_, dropped)| !dropped).map(|(c, _)| c).collect::<BTreeSet<_>>().into_iter().collect()
}

/// Apply a read grant to one response. `inp` is the flat reference input: `{grant, principal, now, verb, resource, purpose,
/// schema: {fields, required}, record, tighten, salt, counts}`. TIGHTEN-ONLY: a weaker requested mode is ignored.
pub fn redact_read(inp: &Value) -> ReadResult {
    redact(inp).unwrap_or_else(|()| no("bad_request"))
}
fn redact(inp: &Value) -> Result<ReadResult, ()> {
    let Some(inp) = inp.as_object() else { return Err(()) };
    let (g, _, _) = match grade_grant(inp.get("grant"), inp.get("principal"), inp.get("now")) {
        Ok(g) => g,
        Err(code) => return Ok(no(code)),
    };
    let bad = Ok(no("bad_request"));
    let (Some(verb), Some(resource), Some(purpose), Some(salt)) = (inp.get("verb").and_then(Value::as_str), inp.get("resource").and_then(Value::as_str), inp.get("purpose").and_then(Value::as_str), inp.get("salt").and_then(Value::as_str)) else { return bad };
    if !is_str(inp.get("verb"), 128) || !is_str(inp.get("resource"), 512) || !is_id_str(purpose) || salt.encode_utf16().count() < SALT_MIN {
        return bad;
    }
    let Some(sc) = inp.get("schema").and_then(Value::as_object) else { return bad };
    let Some(sfields) = sc.get("fields").and_then(Value::as_object) else { return bad };
    let mut classes: BTreeMap<&str, &str> = BTreeMap::new();
    for (k, v) in sfields {
        match v.as_str() {
            Some(c) if is_name_str(k) && is_label_str(c) => classes.insert(k, c),
            _ => return bad,
        };
    }
    let Some(required) = sc.get("required").and_then(Value::as_array) else { return bad };
    let mut req: Vec<&str> = Vec::new();
    for p in required {
        match p.as_str() {
            Some(p) if classes.contains_key(p) => req.push(p),
            _ => return bad,
        }
    }
    let Some(record) = inp.get("record").filter(|r| is_scalar_map(Some(r))).and_then(Value::as_object) else { return bad };
    let Some(tighten) = inp.get("tighten").and_then(Value::as_object) else { return bad };
    if !tighten.iter().all(|(k, v)| is_label_str(k) && is_mode(Some(v))) {
        return bad;
    }
    let Some(in_counts) = uint_counts(inp.get("counts")) else { return bad };
    let Some(entry) = g.reads.iter().find(|e| e.verb == verb && resource.starts_with(e.resource_prefix.as_str()) && e.purposes.iter().any(|p| p == purpose)) else {
        return Ok(out(Decision::Deny, "no_read_scope", in_counts));
    };
    let mut fields: BTreeMap<String, ReadField> = BTreeMap::new();
    let mut view = Map::new();
    let mut used: BTreeMap<&str, i64> = BTreeMap::new();
    let mut paths: Vec<&String> = record.keys().collect();
    paths.sort();
    for path in paths {
        let v = &record[path.as_str()];
        let vd = hash_canonical_strict(&json!({ "d": RV, "salt": salt, "p": path, "v": v })).ok_or(())?;
        // a field the schema does not classify is never shown
        let Some(&cls) = classes.get(path.as_str()) else {
            fields.insert(path.clone(), ReadField { class: "unclassified".into(), action: "dropped", kind: None, vd });
            continue;
        };
        let mut mode: &str = entry.modes.get(cls).map_or(entry.default_mode.as_str(), String::as_str);
        if let Some(t) = tighten.get(cls).and_then(Value::as_str) {
            if rank(t) > rank(mode) {
                mode = t;
            }
        }
        let (shown, action, kind) = if mode == "show" {
            (Some(v.clone()), "shown", None)
        } else {
            (mask(mode, v, cls, salt)?, "masked", Some(if mode.starts_with("bucket:") { "bucket".to_string() } else { mode.to_string() }))
        };
        let Some(shown) = shown else {
            fields.insert(path.clone(), ReadField { class: cls.to_string(), action: "dropped", kind: None, vd });
            continue;
        };
        fields.insert(path.clone(), ReadField { class: cls.to_string(), action, kind, vd });
        view.insert(path.clone(), shown);
        *used.entry(cls).or_insert(0) += 1;
    }
    let mut counts = in_counts.clone();
    for (c, n) in &used {
        let e = counts.entry((*c).to_string()).or_insert(0);
        *e = e.saturating_add(*n);
        if g.caps.get(*c).is_some_and(|cap| *e > *cap) {
            return Ok(out(Decision::Deny, "read_cap", in_counts));
        }
    }
    if req.iter().any(|p| !view.contains_key(*p)) {
        return Ok(out(Decision::Escalate, "required_dropped", in_counts));
    }
    let labels = class_labels(fields.values().map(|f| (f.class.clone(), f.action == "dropped")));
    Ok(ReadResult { decision: Decision::Allow, code: None, view, fields, labels, counts })
}

const RECEIPT_KEYS: [&str; 12] = ["v", "grant", "verb", "resource", "purpose", "seq", "prev", "fields", "labels", "issued_at", "signer", "sig"];

struct RRec {
    grant: String,
    seq: i64,
    prev: Option<String>,
    labels: Vec<String>,
    /// (class, dropped) per field
    fields: Vec<(String, bool)>,
    issued_at: i64,
    signer: String,
}
fn parse_read_receipt(v: &Value) -> Option<RRec> {
    let r = v.as_object().filter(|r| only_keys(r, &RECEIPT_KEYS))?;
    let seq = r.get("seq").and_then(uint)?;
    let prev_null = r.get("prev")?.is_null();
    if r.get("v").and_then(int) != Some(1) || !is_b32(r.get("grant")) || !is_str(r.get("verb"), 128) || !is_str(r.get("resource"), 512) || !r.get("purpose")?.as_str().is_some_and(is_id_str) {
        return None;
    }
    if !(prev_null || is_b32(r.get("prev"))) || (seq == 0) != prev_null || !is_uint(r.get("issued_at")) || !is_b32(r.get("signer")) || !r.get("sig")?.is_string() {
        return None;
    }
    let labels = sorted_unique(r.get("labels"), is_label_str, 32)?;
    let fo = r.get("fields")?.as_object().filter(|f| f.len() <= 64)?;
    let mut fields = Vec::with_capacity(fo.len());
    for (k, f) in fo {
        let f = f.as_object().filter(|f| only_keys(f, &["class", "action", "kind", "vd"]))?;
        let class = f.get("class")?.as_str().filter(|c| *c == "unclassified" || is_label_str(c))?;
        let action = f.get("action")?.as_str().filter(|a| matches!(*a, "shown" | "masked" | "dropped"))?;
        if !is_name_str(k) || !(f.get("kind")?.is_null() || f.get("kind")?.is_string()) || !is_b32(f.get("vd")) {
            return None;
        }
        fields.push((class.to_string(), action == "dropped"));
    }
    Some(RRec { grant: s(r.get("grant"))?, seq, prev: s(r.get("prev")), labels, fields, issued_at: r.get("issued_at").and_then(uint)?, signer: s(r.get("signer"))? })
}

/// The labels carried by a verified, unbroken chain of read receipts, or `(code, at)`. `Err((_, _))` code is always `bad_receipt`.
pub fn read_chain_labels(receipts: &Value, rs_signer: &str, grant_digest: &str, now: i64) -> Result<Vec<String>, (&'static str, usize)> {
    let Some(list) = receipts.as_array() else { return Err(("bad_receipt", 0)) };
    let mut all: BTreeSet<String> = BTreeSet::new();
    let mut prev_raw: Option<&Value> = None;
    for (i, raw) in list.iter().enumerate() {
        let bad = Err(("bad_receipt", i));
        let Some(r) = parse_read_receipt(raw) else { return bad };
        if r.signer != rs_signer || r.grant != grant_digest || r.seq != i as i64 || r.issued_at > now {
            return bad;
        }
        let prev_ok = match prev_raw {
            None => r.prev.is_none(),
            // a reference that cannot be computed is a throw there (caught as bad_request); a chain with no valid ref cannot match
            Some(p) => read_receipt_ref(p).is_some_and(|d| r.prev.as_deref() == Some(d.as_str())),
        };
        let mut body = raw.as_object().cloned().unwrap_or_default();
        body.remove("sig");
        if !prev_ok || !verify_body(READ_RECEIPT_DOMAIN, &Value::Object(body), rs_signer, raw.get("sig").and_then(Value::as_str)) {
            return bad;
        }
        // the receipt's labels must be exactly the classes of its non-dropped fields: an understated label list would launder data
        if class_labels(r.fields.iter().cloned()) != r.labels {
            return bad;
        }
        all.extend(r.labels);
        prev_raw = Some(raw);
    }
    Ok(all.into_iter().collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkResult {
    pub decision: Decision,
    pub code: Option<&'static str>,
    pub labels: Vec<String>,
}
impl SinkResult {
    pub fn to_json(&self) -> Value {
        json!({ "decision": self.decision.as_str(), "code": self.code, "labels": self.labels })
    }
}
fn sink_no(code: &'static str) -> SinkResult {
    SinkResult { decision: Decision::Deny, code: Some(code), labels: vec![] }
}

/// May data read under these receipts reach `sink`? Deny on any label the grant does not allow; escalate on an "ask" label.
/// Every argument is the raw JSON value, so hostile input denies (`bad_request`) instead of failing to type.
pub fn check_sink(grant: &Value, principal: &Value, rs_signer: &Value, now: &Value, sink: &Value, receipts: &Value) -> SinkResult {
    let (g, raw, now) = match grade_grant(Some(grant), Some(principal), Some(now)) {
        Ok(g) => g,
        Err(code) => return sink_no(code),
    };
    let (Some(rs), Some(sink)) = (rs_signer.as_str().filter(|r| is_b32_str(r)), sink.as_str()) else { return sink_no("bad_request") };
    let Some(rule) = g.sinks.get(sink) else { return sink_no("unknown_sink") };
    let Some(digest) = read_grant_digest(raw) else { return sink_no("bad_request") };
    let labels = match read_chain_labels(receipts, rs, &digest, now) {
        Ok(l) => l,
        Err((code, _)) => return sink_no(code),
    };
    if labels.iter().any(|l| !rule.allow.contains(l) && !rule.escalate.contains(l)) {
        return SinkResult { decision: Decision::Deny, code: Some("label_flow"), labels };
    }
    if labels.iter().any(|l| rule.escalate.contains(l)) {
        return SinkResult { decision: Decision::Escalate, code: Some("label_escalate"), labels };
    }
    SinkResult { decision: Decision::Allow, code: None, labels }
}
