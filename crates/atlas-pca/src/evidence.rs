//! The dispute evidence bundle `pca-intent-evidence` v1 (Intent Layer v2): closed-member shape validation, the deterministic normal
//! form, the commitments-only form and the digest that commits to it, the bundle reference and its anchor-log leaf, the accumulator
//! cap reader and the validators of the verifier's trust inputs.
//!
//! Inputs are JSON values. The reference's JavaScript semantics are reproduced where a hostile bundle reaches them (property reads on
//! any value, `Object.keys` order, relational comparison, the `||` chain of the sort comparators, the JSON round trip), so a
//! malformed bundle gives the same shape error, the same order or the same refusal (`Err`, where the reference throws).
//! The COSE signed statement over the bundle reference is [`evidence_signed_statement`]; the full replay is `crate::evidence_verify`. Not ported: the command-line tool.
use crate::actions::js_to_number;
use crate::oauth::js_str;
use crate::{decode_b64u_strict, hash_canonical_strict};
use serde_json::{json, Map, Value};

pub const EVIDENCE_DOMAIN: &str = "atlas-pca/intent-evidence/v1";
pub const EVIDENCE_REPORT_DOMAIN: &str = "atlas-pca/intent-evidence-report/v1";
pub const EVIDENCE_CONTENT_TYPE: &str = "application/pca-intent-evidence+json";
const INTENT_ANCHOR_DOMAIN: &str = "atlas-pca/intent-anchor/v1";
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

const TOP_KEYS: [&str; 23] = [
    "v",
    "kind",
    "subject",
    "statement",
    "session_root",
    "schema",
    "root_grant",
    "maps",
    "answers",
    "canary_labels",
    "canaries",
    "deltas",
    "pcactns",
    "verdicts",
    "accumulator",
    "facts",
    "classifier",
    "offer_sets",
    "labels",
    "effects",
    "settlements",
    "revocation_epochs",
    "anchors",
];

// ---- JavaScript value helpers ----------------------------------------------------------------------------------------------

fn is_obj(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Object(_)))
}

/// `Number.isSafeInteger(v) && !Object.is(v, -0)`.
fn is_int(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Number(n)) => {
            let f = n.as_f64().unwrap_or(f64::NAN);
            f.is_finite() && f == f.floor() && f.abs() <= MAX_SAFE && !(f == 0.0 && f.is_sign_negative())
        }
        _ => false,
    }
}

fn is_num_eq(v: Option<&Value>, want: f64) -> bool {
    matches!(v, Some(Value::Number(n)) if n.as_f64() == Some(want))
}

fn is_str(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(_)))
}

/// `v.k`: an object's member; `undefined` for any other value.
fn get<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.as_object().and_then(|o| o.get(k))
}

/// `v.k` where `v` may be null or undefined (a TypeError).
fn rd<'a>(v: Option<&'a Value>, k: &str) -> Result<Option<&'a Value>, String> {
    match v {
        None | Some(Value::Null) => Err(format!("Cannot read properties of {} (reading '{k}')", if v.is_none() { "undefined" } else { "null" })),
        Some(x) => Ok(get(x, k)),
    }
}

/// `Object.keys` order: array-index keys ascending, then the rest in insertion order.
fn js_keys(o: &Map<String, Value>) -> Vec<&String> {
    let idx = |k: &str| k.parse::<u32>().ok().filter(|n| *n != u32::MAX && n.to_string() == k);
    let mut ints: Vec<(u32, &String)> = o.keys().filter_map(|k| idx(k).map(|n| (n, k))).collect();
    ints.sort_by_key(|(n, _)| *n);
    ints.into_iter().map(|(_, k)| k).chain(o.keys().filter(|k| idx(k).is_none())).collect()
}

/// `JSON.parse(JSON.stringify(v))`: a deep copy in which `-0` becomes `0`.
fn plain(v: &Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(plain).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), plain(x))).collect()),
        Value::Number(n) if n.as_f64() == Some(0.0) => json!(0),
        x => x.clone(),
    }
}

/// The members `{...v}` copies: an object's own, an array's or a string's indices, nothing for any other value.
fn spread(v: &Value) -> Map<String, Value> {
    match v {
        Value::Object(o) => o.clone(),
        Value::Array(a) => a.iter().enumerate().map(|(i, x)| (i.to_string(), x.clone())).collect(),
        Value::String(s) => s.chars().enumerate().map(|(i, c)| (i.to_string(), Value::String(c.to_string()))).collect(),
        _ => Map::new(),
    }
}

/// ToPrimitive of a JSON value for a relational comparison (an array or object becomes its string form).
fn prim(v: Option<&Value>) -> Option<Value> {
    match v {
        Some(Value::Array(_)) | Some(Value::Object(_)) => Some(Value::String(v.map(js_str).unwrap_or_default())),
        x => x.cloned(),
    }
}

/// JavaScript `a < b`.
fn js_lt(a: Option<&Value>, b: Option<&Value>) -> bool {
    let (pa, pb) = (prim(a), prim(b));
    if let (Some(Value::String(x)), Some(Value::String(y))) = (&pa, &pb) {
        return x.encode_utf16().lt(y.encode_utf16());
    }
    js_to_number(pa.as_ref()) < js_to_number(pb.as_ref())
}

/// `a < b ? -1 : a > b ? 1 : 0`.
fn cmp(a: Option<&Value>, b: Option<&Value>) -> f64 {
    if js_lt(a, b) {
        -1.0
    } else if js_lt(b, a) {
        1.0
    } else {
        0.0
    }
}

fn sub(a: Option<&Value>, b: Option<&Value>) -> f64 {
    js_to_number(a) - js_to_number(b)
}

/// `first || rest()` for numbers: zero and NaN are falsy.
fn or(first: f64, rest: impl FnOnce() -> Result<f64, String>) -> Result<f64, String> {
    if first != 0.0 && !first.is_nan() {
        Ok(first)
    } else {
        rest()
    }
}

fn key_of(v: &Value) -> Result<String, String> {
    hash_canonical_strict(v).ok_or_else(|| "canonicalize: value is outside the strict JSON profile".to_string())
}

/// A stable binary-insertion sort with a fallible JavaScript-style comparator (negative = first sorts before second).
fn js_sort(arr: &mut Vec<Value>, mut f: impl FnMut(&Value, &Value) -> Result<f64, String>) -> Result<(), String> {
    for i in 1..arr.len() {
        let pivot = arr[i].clone();
        let (mut lo, mut hi) = (0usize, i);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if f(&pivot, &arr[mid])? < 0.0 {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        arr.remove(i);
        arr.insert(lo, pivot);
    }
    Ok(())
}

/// `x[k].sort(f)`: the member must be an array.
fn sort_member(x: &mut Value, k: &str, f: impl FnMut(&Value, &Value) -> Result<f64, String>) -> Result<(), String> {
    match x.get_mut(k) {
        Some(Value::Array(a)) => js_sort(a, f),
        _ => Err("sort is not a function".into()),
    }
}

// ---- shape -----------------------------------------------------------------------------------------------------------------

fn closed(o: Option<&Value>, keys: &[&str], wher: &str) -> Option<String> {
    let Some(Value::Object(m)) = o else { return Some(format!("{wher} must be an object")) };
    js_keys(m).into_iter().find(|k| !keys.contains(&k.as_str())).map(|k| format!("{wher}: unknown member \"{k}\""))
}

/// Closed-member shape validation (unknown members are refused at every level the bundle owns). `None` when well formed.
pub fn bundle_shape_error(b: &Value) -> Option<String> {
    if let Some(e) = closed(Some(b), &TOP_KEYS, "bundle") {
        return Some(e);
    }
    let x = b;
    let g = |k: &str| get(x, k);
    if !is_num_eq(g("v"), 1.0) || g("kind").and_then(Value::as_str) != Some("pca-intent-evidence") {
        return Some("not a pca-intent-evidence v1 bundle".into());
    }
    if let Some(e) = closed(g("subject"), &["pcactn_digest", "aud", "session"], "subject") {
        return Some(e);
    }
    let s = g("subject").unwrap();
    if !["pcactn_digest", "aud", "session"].iter().all(|k| is_str(get(s, k))) {
        return Some("subject members must be strings".into());
    }
    if let Some(e) = closed(g("statement"), &["commit", "opening"], "statement") {
        return Some(e);
    }
    if !is_str(get(g("statement").unwrap(), "commit")) {
        return Some("statement.commit must be a string".into());
    }
    let sr = g("session_root");
    if !is_obj(sr) || !is_num_eq(get(sr.unwrap(), "v"), 1.0) || get(sr.unwrap(), "kind").and_then(Value::as_str) != Some("pca-intent-session") {
        return Some("session_root is not a pca-intent-session v1".into());
    }
    let sr = sr.unwrap();
    if !is_str(get(sr, "session")) || !is_str(get(sr, "intent_ref")) || !is_int(get(sr, "expires_at")) {
        return Some("session_root is missing session / intent_ref / expires_at".into());
    }
    match get(sr, "principals") {
        Some(Value::Array(p)) if !p.is_empty() && p.iter().all(|p| is_obj(Some(p)) && is_str(get(p, "key"))) => {}
        _ => return Some("session_root.principals must be a non-empty key list".into()),
    }
    if let Some(e) = closed(g("schema"), &["doc", "anchor"], "schema") {
        return Some(e);
    }
    let doc = get(g("schema").unwrap(), "doc");
    if !is_obj(doc) || get(doc.unwrap(), "kind").and_then(Value::as_str) != Some("pca-action-schema") || !is_obj(get(doc.unwrap(), "sig")) {
        return Some("schema.doc is not a signed pca-action-schema".into());
    }
    if !is_obj(g("root_grant")) {
        return Some("root_grant must be a capability".into());
    }
    for k in ["maps", "answers", "canary_labels", "deltas", "pcactns", "verdicts", "effects", "revocation_epochs", "anchors"] {
        if !matches!(g(k), Some(Value::Array(_))) {
            return Some(format!("{k} must be an array"));
        }
    }
    for k in ["facts", "classifier", "offer_sets", "labels", "settlements"] {
        if g(k).is_some_and(|v| !v.is_array()) {
            return Some(format!("{k} must be an array"));
        }
    }
    for (i, m) in g("maps").and_then(Value::as_array).unwrap().iter().enumerate() {
        if let Some(e) = closed(Some(m), &["seq", "commit", "map", "disclosed"], &format!("maps[{i}]")) {
            return Some(e);
        }
        let seq = get(m, "seq");
        if !is_int(seq) || seq.and_then(Value::as_f64).is_some_and(|f| f < 0.0) || !is_str(get(m, "commit")) {
            return Some(format!("maps[{i}] needs an integer seq and a commit"));
        }
    }
    for (i, c) in g("canary_labels").and_then(Value::as_array).unwrap().iter().enumerate() {
        if let Some(e) = closed(Some(c), &["question_id", "label"], &format!("canary_labels[{i}]")) {
            return Some(e);
        }
        if !is_str(get(c, "question_id")) || !(is_num_eq(get(c, "label"), 0.0) || is_num_eq(get(c, "label"), 1.0)) {
            return Some(format!("canary_labels[{i}] is malformed"));
        }
    }
    if let Some(e) = closed(g("canaries"), &["asked", "false_yes", "false_no"], "canaries") {
        return Some(e);
    }
    let cn = g("canaries").unwrap();
    if !["asked", "false_yes", "false_no"].iter().all(|k| is_int(get(cn, k)) && get(cn, k).and_then(Value::as_f64).is_some_and(|f| f >= 0.0)) {
        return Some("canaries counts must be non-negative integers".into());
    }
    if let Some(e) = closed(g("accumulator"), &["holder", "events", "receipts", "sequencer_keys"], "accumulator") {
        return Some(e);
    }
    let acc = g("accumulator").unwrap();
    if !matches!(get(acc, "holder").and_then(Value::as_str), Some("site_local" | "sequenced")) {
        return Some("accumulator.holder must be site_local or sequenced".into());
    }
    let Some(Value::Array(events)) = get(acc, "events") else { return Some("accumulator.events must be an array".into()) };
    for (i, ev) in events.iter().enumerate() {
        if let Some(e) = closed(Some(ev), &["acc", "post", "pcactn_digest", "delta", "status"], &format!("accumulator.events[{i}]")) {
            return Some(e);
        }
        let non_neg = |v: Option<&Value>| is_int(v) && v.and_then(Value::as_f64).is_some_and(|f| f >= 0.0);
        if !is_str(get(ev, "acc")) || !non_neg(get(ev, "post")) || !is_str(get(ev, "pcactn_digest")) {
            return Some(format!("accumulator.events[{i}] is malformed"));
        }
        if get(ev, "delta").is_some() && !non_neg(get(ev, "delta")) {
            return Some(format!("accumulator.events[{i}].delta must be a non-negative integer"));
        }
    }
    if get(acc, "receipts").is_some_and(|v| !v.is_array()) {
        return Some("accumulator.receipts must be an array".into());
    }
    if get(acc, "sequencer_keys").is_some_and(|v| !v.is_array()) {
        return Some("accumulator.sequencer_keys must be an array".into());
    }
    for (i, r) in g("revocation_epochs").and_then(Value::as_array).unwrap().iter().enumerate() {
        if let Some(e) = closed(Some(r), &["epoch", "revoked"], &format!("revocation_epochs[{i}]")) {
            return Some(e);
        }
        if !is_obj(get(r, "epoch")) || !matches!(get(r, "revoked"), Some(Value::Array(_))) {
            return Some(format!("revocation_epochs[{i}] needs an epoch and its revoked list"));
        }
    }
    for (i, a) in g("anchors").and_then(Value::as_array).unwrap().iter().enumerate() {
        if let Some(e) = closed(Some(a), &["kind", "digest", "index", "proof", "signed_tree_head"], &format!("anchors[{i}]")) {
            return Some(e);
        }
    }
    for (i, ef) in g("effects").and_then(Value::as_array).unwrap().iter().enumerate() {
        if !is_obj(Some(ef)) || !is_str(get(ef, "pcactn_digest")) {
            return Some(format!("effects[{i}] needs a pcactn_digest"));
        }
    }
    None
}

// ---- normal form -----------------------------------------------------------------------------------------------------------

fn seq_of(c: &Value) -> Result<f64, String> {
    let Some(Value::Array(cvs)) = rd(Some(c), "caveats")? else { return Err("find is not a function".into()) };
    for k in cvs {
        if rd(Some(k), "type")?.and_then(Value::as_str) == Some("intent_session") {
            let seq = get(k, "seq");
            return Ok(if is_int(seq) { seq.and_then(Value::as_f64).unwrap_or(MAX_SAFE) } else { MAX_SAFE });
        }
    }
    Ok(MAX_SAFE)
}

fn effect_key(e: &Value) -> Result<String, String> {
    if e.is_null() {
        return Err("Cannot destructure property 'params' of null".into());
    }
    let mut m = spread(e);
    m.remove("params");
    key_of(&Value::Object(m))
}

/// Deterministic normal form: the members that are sets (answers, deltas, PCActns, verdicts, effects, epochs, anchors, maps, canary
/// labels, ...) are sorted by a content key; `accumulator.events` is a sequence and is never reordered. `Err` where the reference
/// throws (a bundle that cannot be put in order).
pub fn normalize_bundle(b: &Value) -> Result<Value, String> {
    let mut x = plain(b);
    if !x.is_object() {
        return Err("Cannot read properties of a non-object (reading 'maps')".into());
    }
    let r = |v: &Value, k: &str| -> Result<Option<Value>, String> { Ok(rd(Some(v), k)?.cloned()) };
    sort_member(&mut x, "maps", |a, c| {
        let (sa, sc) = (r(a, "seq")?, r(c, "seq")?);
        or(sub(sa.as_ref(), sc.as_ref()), || Ok(cmp(r(a, "commit")?.as_ref(), r(c, "commit")?.as_ref())))
    })?;
    sort_member(&mut x, "answers", |a, c| {
        or(sub(r(a, "observed_at")?.as_ref(), r(c, "observed_at")?.as_ref()), || {
            or(cmp(r(a, "question_id")?.as_ref(), r(c, "question_id")?.as_ref()), || Ok(cmp(r(a, "sig")?.as_ref(), r(c, "sig")?.as_ref())))
        })
    })?;
    sort_member(&mut x, "canary_labels", |a, c| {
        or(cmp(r(a, "question_id")?.as_ref(), r(c, "question_id")?.as_ref()), || Ok(sub(r(a, "label")?.as_ref(), r(c, "label")?.as_ref())))
    })?;
    sort_member(&mut x, "deltas", |a, c| {
        let (sa, sc) = (seq_of(a)?, seq_of(c)?);
        or(sa - sc, || Ok(cmp(r(a, "id")?.as_ref(), r(c, "id")?.as_ref())))
    })?;
    sort_member(&mut x, "pcactns", |a, c| {
        or(sub(r(a, "iat")?.as_ref(), r(c, "iat")?.as_ref()), || {
            or(sub(r(a, "counter")?.as_ref(), r(c, "counter")?.as_ref()), || Ok(cmp_str(&key_of(a)?, &key_of(c)?)))
        })
    })?;
    sort_member(&mut x, "verdicts", |a, c| {
        or(cmp(r(a, "pcactn_digest")?.as_ref(), r(c, "pcactn_digest")?.as_ref()), || Ok(cmp_str(&key_of(a)?, &key_of(c)?)))
    })?;
    // sorted without the params opening, so withholding an opening never reorders the commitments-only form
    sort_member(&mut x, "effects", |a, c| {
        or(cmp(r(a, "pcactn_digest")?.as_ref(), r(c, "pcactn_digest")?.as_ref()), || Ok(cmp_str(&effect_key(a)?, &effect_key(c)?)))
    })?;
    // issue order (not epoch number): a rollback, an epoch issued later with a lower number, must stay visible
    sort_member(&mut x, "revocation_epochs", |a, c| {
        let ep = |o: &Value, k: &str| -> Result<Option<Value>, String> { Ok(rd(rd(Some(o), "epoch")?, k)?.cloned()) };
        or(sub(ep(a, "issued_at")?.as_ref(), ep(c, "issued_at")?.as_ref()), || {
            or(sub(ep(a, "epoch")?.as_ref(), ep(c, "epoch")?.as_ref()), || Ok(cmp_str(&key_of(a)?, &key_of(c)?)))
        })
    })?;
    sort_member(&mut x, "anchors", |a, c| {
        or(cmp(r(a, "kind")?.as_ref(), r(c, "kind")?.as_ref()), || {
            or(sub(r(a, "index")?.as_ref(), r(c, "index")?.as_ref()), || Ok(cmp(r(a, "digest")?.as_ref(), r(c, "digest")?.as_ref())))
        })
    })?;
    for k in ["facts", "classifier", "offer_sets", "labels", "settlements"] {
        match x.get(k) {
            None | Some(Value::Null) => {}
            Some(_) => sort_member(&mut x, k, |a, c| Ok(cmp_str(&key_of(a)?, &key_of(c)?)))?,
        }
    }
    let has_receipts = crate::oauth::truthy(rd(x.get("accumulator"), "receipts")?);
    if has_receipts {
        match x.get_mut("accumulator").and_then(|a| a.get_mut("receipts")) {
            Some(Value::Array(a)) => js_sort(a, |p, q| Ok(cmp_str(&key_of(p)?, &key_of(q)?)))?,
            _ => return Err("sort is not a function".into()),
        }
    }
    Ok(x)
}

fn cmp_str(a: &str, b: &str) -> f64 {
    match a.encode_utf16().cmp(b.encode_utf16()) {
        std::cmp::Ordering::Less => -1.0,
        std::cmp::Ordering::Greater => 1.0,
        std::cmp::Ordering::Equal => 0.0,
    }
}

/// Assemble a bundle in normal form. `Err` on a malformed part (the exporter's bug, not evidence).
pub fn build_evidence_bundle(parts: &Value) -> Result<Value, String> {
    let mut b = Map::new();
    b.insert("v".into(), json!(1));
    b.insert("kind".into(), json!("pca-intent-evidence"));
    b.extend(spread(parts));
    let n = normalize_bundle(&Value::Object(b))?;
    match bundle_shape_error(&n) {
        Some(bad) => Err(format!("buildEvidenceBundle: {bad}")),
        None => Ok(n),
    }
}

/// (the commitments-only form, whether a committed member is undefined): an undefined member cannot be hashed.
fn commitment(b: &Value) -> Result<(Value, bool), String> {
    let n = normalize_bundle(b)?;
    let mut rest = n.as_object().cloned().unwrap_or_default();
    rest.remove("anchors");
    let mut undef = false;
    let statement = rd(n.get("statement"), "commit")?.cloned();
    let mut st = Map::new();
    match statement {
        Some(c) => {
            st.insert("commit".into(), c);
        }
        None => undef = true,
    }
    rest.insert("statement".into(), Value::Object(st));
    let mut maps = vec![];
    for m in n["maps"].as_array().cloned().unwrap_or_default() {
        let mut e = Map::new();
        for k in ["seq", "commit"] {
            match rd(Some(&m), k)? {
                Some(v) => {
                    e.insert(k.into(), v.clone());
                }
                None => undef = true,
            }
        }
        if let Some(d) = rd(Some(&m), "disclosed")? {
            e.insert("disclosed".into(), d.clone());
        }
        maps.push(Value::Object(e));
    }
    rest.insert("maps".into(), Value::Array(maps));
    let mut effects = vec![];
    for e in n["effects"].as_array().cloned().unwrap_or_default() {
        if e.is_null() {
            return Err("Cannot destructure property 'params' of null".into());
        }
        let mut kept = spread(&e);
        kept.remove("params");
        effects.push(Value::Object(kept));
    }
    rest.insert("effects".into(), Value::Array(effects));
    Ok((Value::Object(rest), undef))
}

/// The commitments-only normal form: no anchors, no statement opening, no full maps, no effect params; every signed artifact and
/// every claim stays in.
pub fn commitment_form(b: &Value) -> Result<Value, String> {
    commitment(b).map(|(f, _)| f)
}

/// The bundle's content address: the hash over the commitments-only normal form.
pub fn evidence_digest(b: &Value) -> Result<String, String> {
    let (form, undef) = commitment(b)?;
    if undef {
        return Err("canonicalize: unsupported type undefined".into());
    }
    key_of(&json!({"d": EVIDENCE_DOMAIN, "b": form}))
}

/// The public reference to a bundle: its digest and subject (the bundle itself stays with the site).
pub fn evidence_ref(bundle: &Value) -> Result<Value, String> {
    let digest = evidence_digest(bundle)?;
    let subject = rd(Some(bundle), "subject")?.map(spread).unwrap_or_default();
    Ok(json!({"kind": "pca-intent-evidence-ref", "digest": digest, "subject": Value::Object(subject)}))
}

/// A COSE Signed Statement over the bundle reference, ready to register with a SCITT transparency service. `opts` = `{alg, key, issuer,
/// subject?}` of [`crate::scitt::sign_statement`]; the subject defaults to the bundle's `subject.pcactn_digest`, and the content type is
/// always [`EVIDENCE_CONTENT_TYPE`] (whatever `opts` carries).
pub fn evidence_signed_statement(bundle: &Value, opts: &Value) -> Result<Vec<u8>, String> {
    let r = evidence_ref(bundle)?;
    let Some(mut o) = opts.as_object().cloned() else { return Err("scitt: options must be an object".into()) };
    if o.get("subject").map_or(true, Value::is_null) {
        match r["subject"].get("pcactn_digest").filter(|d| !d.is_null()) {
            Some(d) => o.insert("subject".into(), d.clone()),
            None => o.remove("subject"),
        };
    }
    o.insert("contentType".into(), json!(EVIDENCE_CONTENT_TYPE));
    crate::scitt::sign_statement(&r, &Value::Object(o))
}

/// The intent-log leaf for an anchored artifact (any kind).
pub fn anchor_commit(kind: &Value, digest: &Value) -> Result<String, String> {
    key_of(&json!({"d": INTENT_ANCHOR_DOMAIN, "kind": kind, "digest": digest}))
}

pub fn evidence_anchor_commit(digest: &Value) -> Result<String, String> {
    anchor_commit(&json!("evidence"), digest)
}

// ---- accumulator cap -------------------------------------------------------------------------------------------------------

fn leaf_caps(conds: Option<&Value>, path: &str) -> Result<Vec<f64>, String> {
    let items: &[Value] = match conds {
        None | Some(Value::Null) => &[],
        Some(Value::Array(a)) => a,
        Some(Value::String(_)) => &[], // iterates characters, none of which is a condition
        Some(_) => return Err("conds is not iterable".into()),
    };
    let mut out = vec![];
    for c in items {
        let is_leaf = c.is_object() && !crate::predicates::is_group_condition(c) && is_str(get(c, "field"));
        if is_leaf {
            let value = get(c, "value");
            if get(c, "field").and_then(Value::as_str) != Some(path) || get(c, "ref").is_some() || !matches!(value, Some(Value::Number(_))) {
                continue;
            }
            let v = value.and_then(Value::as_f64).unwrap_or(f64::NAN);
            match get(c, "op").and_then(Value::as_str) {
                Some("lte") => out.push(v),
                Some("lt") => out.push(v - 1.0),
                _ => {}
            }
        } else if crate::predicates::is_group_condition(c) && get(c, "all_of").is_some() {
            out.extend(leaf_caps(get(c, "all_of"), path)?);
        }
    }
    Ok(out)
}

/// The cap `env.acc.<id>.post <= v` that the grant's envelope states for `verb`: per predicate the tightest bound in its `where`
/// (descending into `all_of`); across predicates (a union) the loosest. `None` when a predicate admitting the verb states no bound,
/// or none admits it.
pub fn cap_of(grant: &Value, acc_id: &Value, verb: &Value) -> Result<Option<f64>, String> {
    let Some(env) = crate::authorize::read_envelope(grant) else { return Ok(None) };
    let path = format!("env.acc.{}.post", js_str(acc_id));
    let verb = js_str(verb);
    let mut cap: Option<f64> = None;
    for p in env.get("predicates").and_then(Value::as_array).cloned().unwrap_or_default() {
        let verbs: Vec<String> = match rd(Some(&p), "verb")? {
            Some(Value::Array(a)) => a.iter().map(|x| if x.is_null() { "null".to_string() } else { js_str(x) }).collect(),
            other => vec![other.map(js_str).unwrap_or_else(|| "undefined".into())],
        };
        if !verbs.contains(&verb) && !verbs.iter().any(|v| v == "*") {
            continue;
        }
        let caps = leaf_caps(get(&p, "where"), &path)?;
        if caps.is_empty() {
            return Ok(None);
        }
        let m = caps.iter().cloned().fold(f64::INFINITY, |a, b| if a.is_nan() || b.is_nan() { f64::NAN } else { a.min(b) });
        cap = Some(match cap {
            None => m,
            Some(c) => {
                if c.is_nan() || m.is_nan() {
                    f64::NAN
                } else {
                    c.max(m)
                }
            }
        });
    }
    Ok(cap)
}

// ---- trust-input validators ------------------------------------------------------------------------------------------------

/// Validate `trust.principals`: a non-empty array of closed `{key, pq_pk?}` with canonical keys. `None` = valid (an absent value is
/// valid).
pub fn principals_trust_error(p: Option<&Value>) -> Option<String> {
    let p = p?;
    let Some(a) = p.as_array().filter(|a| !a.is_empty()) else { return Some("trust.principals must be a non-empty array of {key, pq_pk?}".into()) };
    for (i, x) in a.iter().enumerate() {
        let Some(o) = x.as_object() else { return Some(format!("trust.principals[{i}] must be an object {{key, pq_pk?}}")) };
        for k in js_keys(o) {
            if k != "key" && k != "pq_pk" {
                return Some(format!("trust.principals[{i}]: unknown member '{k}'"));
            }
        }
        if !o.get("key").and_then(Value::as_str).is_some_and(|k| decode_b64u_strict(k, Some(32)).is_some()) {
            return Some(format!("trust.principals[{i}].key must be canonical base64url (32 bytes)"));
        }
        if let Some(pq) = o.get("pq_pk") {
            if !pq.as_str().is_some_and(|s| decode_b64u_strict(s, None).is_some()) {
                return Some(format!("trust.principals[{i}].pq_pk must be canonical base64url"));
            }
        }
    }
    None
}

/// Validate `trust.acc` like the core `policy.acc`: closed members, non-negative safe integers. `None` = valid.
pub fn acc_trust_error(a: Option<&Value>) -> Option<String> {
    let a = a?;
    let Some(o) = a.as_object() else { return Some("trust.acc must be an object".into()) };
    for k in js_keys(o) {
        if k != "max_receipt_age_s" && k != "max_keyset_age_s" {
            return Some(format!("trust.acc: unknown member '{k}'"));
        }
        let v = o.get(k);
        if !(is_int(v) && v.and_then(Value::as_f64).is_some_and(|f| f >= 0.0)) {
            return Some(format!("trust.acc.{k} must be a non-negative safe integer"));
        }
    }
    None
}
