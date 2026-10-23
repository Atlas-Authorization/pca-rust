//! Accumulators, monitors, sequencer reservation receipts and the sequencer's root-signed key sets (Intent Layer v2
//! rule 15). Mirrors `packages/pca/src/intent-acc.ts`.

use serde_json::{Map, Value};

use super::action_schema::{accumulation_params, schema_verb};
use super::intent_strict::*;
use super::intent_suite::{bind_suite_fields, domain_message, optional_alg_error, suite_of, suite_shape_error, verify_pinned_suite, UNSUPPORTED_SUITE};
use super::{canonicalize_strict, MAX_SAFE};

pub(crate) const MAX_SESSION_ACCUMULATORS: usize = 16;
pub(crate) const MAX_SESSION_MONITORS: usize = 16;
const MAX_MONITOR_WITHIN: i64 = 64;
const ACC_AGGS: [&str; 4] = ["sum", "count", "distinct", "max"];
const MONITOR_KINDS: [&str; 5] = ["requires_prior", "precedes", "never", "always", "responds_within"];
pub(crate) const ACC_RECEIPT_DOMAIN: &str = "atlas-pca/acc-receipt/v1\0";
pub(crate) const ACC_RECEIPT_REF_DOMAIN: &str = "atlas-pca/acc-receipt-ref/v1";
pub(crate) const ACC_RESERVE_DOMAIN: &str = "atlas-pca/acc-reserve/v1";
pub(crate) const SEQUENCER_KEYS_DOMAIN: &str = "atlas-pca/sequencer-keys/v1\0";
pub(crate) const SEQUENCER_KEYS_REF_DOMAIN: &str = "atlas-pca/sequencer-keys-ref/v1";
/// Allowed clock skew between a receipt's `issued_at` and the verifier's clock.
pub const RECEIPT_SKEW_MS: i64 = 60_000;
/// A receipt lives at most this long: `issued_at <= expires_at <= issued_at + MAX_RECEIPT_LIFETIME_MS` (15 min).
pub const MAX_RECEIPT_LIFETIME_MS: i64 = 900_000;
/// Default `policy.acc.max_receipt_age_s` (ms).
pub const DEFAULT_MAX_RECEIPT_AGE_MS: i64 = 900_000;
/// Default `policy.acc.max_keyset_age_s` (ms).
pub const DEFAULT_MAX_KEYSET_AGE_MS: i64 = 3_600_000;

/// The freshness bounds of rule 15 for a sequenced receipt (`ReceiptFreshness`).
pub(crate) struct ReceiptFreshness {
    /// `A_r`: `now - receipt.issued_at <= A_r`.
    pub max_receipt_age_ms: f64,
    /// `A_k`: `now - keyset.issued_at <= A_k`.
    pub max_keyset_age_ms: f64,
    /// The newest key set accepted for the holder's root (`acc.keyset_versions[root]` = `{version, digest}`), when tracked.
    pub tracked: Option<(i64, String)>,
}
const RECEIPT_KEYS: [&str; 19] = [
    "v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at", "expires_at", "kid", "ledger", "signer",
    "alg", "pq_pk", "sig", "pq_sig",
];

/// `KID_RE` `^[A-Za-z0-9_.:-]{1,64}$`.
fn is_kid(v: Option<&Value>) -> bool {
    matches!(s(v), Some(k) if !k.is_empty() && k.len() <= 64 && k.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b':' | b'-')))
}

fn predicate_shape_ok(p: Option<&Value>) -> bool {
    match obj(p) {
        Some(o) => match o.get("verb") {
            Some(Value::String(_)) => true,
            Some(Value::Array(a)) => !a.is_empty() && a.iter().all(Value::is_string),
            _ => false,
        },
        None => false,
    }
}

/// `accumulatorDeclError(a)`. `None` = well-formed.
pub(crate) fn accumulator_decl_error(a: &Value) -> Option<String> {
    let a = match a.as_object() {
        Some(a) => a,
        None => return Some("accumulator must be an object".into()),
    };
    const KEYS: [&str; 10] = ["id", "agg", "val", "unit", "sel", "win", "key", "domain_max", "cap", "holder"];
    if let Some(k) = a.keys().find(|k| !KEYS.contains(&k.as_str())) {
        return Some(format!("accumulator: unknown member '{k}'"));
    }
    let id = match s(a.get("id")) {
        Some(id) if is_ident(id) && !RESERVED_NAMES.contains(&id) => id,
        _ => return Some("accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype".into()),
    };
    let at = format!("accumulator '{id}'");
    let agg = s(a.get("agg")).filter(|g| ACC_AGGS.contains(g));
    let agg = match agg {
        Some(g) => g,
        None => return Some(format!("{at}: unknown agg")),
    };
    if a.get("val").is_some() && !s(a.get("val")).is_some_and(is_top_param_path) {
        return Some(format!("{at}: val must be action.params.<name>"));
    }
    if a.get("unit").is_some() && !s(a.get("unit")).is_some_and(|u| u.encode_utf16().count() <= 64 && is_unit_id(u)) {
        return Some(format!("{at}: unit must be a unit id"));
    }
    let sel = match obj(a.get("sel")) {
        Some(x) => x,
        None => return Some(format!("{at}: sel must be an object")),
    };
    if let Some(k) = sel.keys().find(|k| !["verbs", "accumulates_into", "event"].contains(&k.as_str())) {
        return Some(format!("{at}: sel has unknown member '{k}'"));
    }
    if let Some(v) = sel.get("verbs") {
        let ok = v.as_array().is_some_and(|vs| !vs.is_empty() && vs.len() <= 64 && vs.iter().all(|x| bstr_nonempty(x)));
        if !ok {
            return Some(format!("{at}: sel.verbs must be 1..64 verb names"));
        }
    }
    if sel.get("accumulates_into").is_some() && !s(sel.get("accumulates_into")).is_some_and(is_unit_id) {
        return Some(format!("{at}: sel.accumulates_into must be a unit id"));
    }
    if sel.get("event").is_some() && !matches!(s(sel.get("event")), Some("intent_required" | "question" | "clarification")) {
        return Some(format!("{at}: unknown sel.event"));
    }
    let action_sel = sel.get("verbs").is_some() || sel.get("accumulates_into").is_some();
    if action_sel == sel.get("event").is_some() {
        return Some(format!("{at}: sel names actions (verbs / accumulates_into) or a wallet event, exactly one kind"));
    }
    let w = match obj(a.get("win")) {
        Some(w) => w,
        None => return Some(format!("{at}: win must be an object")),
    };
    match s(w.get("kind")) {
        Some("task") => {
            if w.len() != 1 {
                return Some(format!("{at}: win {{kind: task}} has no other member"));
            }
        }
        Some("sliding") => {
            if !exact_keys(w, &["kind", "ms"]) || !sint(w.get("ms")).is_some_and(|m| m > 0) {
                return Some(format!("{at}: win sliding needs a positive ms"));
            }
        }
        Some("period") => {
            if !exact_keys(w, &["kind", "ms", "t0"]) || !sint(w.get("ms")).is_some_and(|m| m > 0) || nonneg(w.get("t0")).is_none() {
                return Some(format!("{at}: win period needs a positive ms and t0 >= 0"));
            }
        }
        _ => return Some(format!("{at}: unknown win kind")),
    }
    match a.get("key") {
        Some(Value::Null) => {}
        k => {
            if !s(k).is_some_and(is_top_param_path) {
                return Some(format!("{at}: key must be null or action.params.<name>"));
            }
        }
    }
    if a.get("domain_max").is_some() && nonneg(a.get("domain_max")).is_none() {
        return Some(format!("{at}: domain_max must be a non-negative safe integer"));
    }
    if a.get("cap").is_some() && nonneg(a.get("cap")).is_none() {
        return Some(format!("{at}: cap must be a non-negative safe integer"));
    }
    let h = match obj(a.get("holder")) {
        Some(h) => h,
        None => return Some(format!("{at}: holder must be an object")),
    };
    let hk = s(h.get("kind"));
    match hk {
        Some("site_local") | Some("wallet") => {
            if h.len() != 1 {
                return Some(format!("{at}: holder {} has no other member", hk.unwrap_or("")));
            }
        }
        Some("sequenced") => {
            const HK: [&str; 6] = ["kind", "uri", "root", "root_alg", "root_pq_pk", "keys_uri"];
            if let Some(k) = h.keys().find(|k| !HK.contains(&k.as_str())) {
                return Some(format!("{at}: holder sequenced has unknown member '{k}'"));
            }
            if !s(h.get("uri")).is_some_and(|u| !u.is_empty()) {
                return Some(format!("{at}: holder sequenced needs a uri"));
            }
            if !b32(h.get("root")) {
                return Some(format!("{at}: holder.root is not canonical base64url (32 bytes)"));
            }
            if let Some(e) = optional_alg_error(h.get("root_alg")) {
                return Some(format!("{at}: holder.root_alg: {e}"));
            }
            if h.get("root_pq_pk").is_some() && !b64any(h.get("root_pq_pk")) {
                return Some(format!("{at}: holder.root_pq_pk is not canonical base64url"));
            }
            if h.get("keys_uri").is_some() && !s(h.get("keys_uri")).is_some_and(|u| !u.is_empty()) {
                return Some(format!("{at}: holder.keys_uri must be a non-empty string"));
            }
        }
        _ => return Some(format!("{at}: unknown holder kind")),
    }
    let wallet = hk == Some("wallet");
    if wallet != sel.get("event").is_some() {
        return Some(format!("{at}: wallet events are wallet-held and only wallet events are"));
    }
    if !wallet {
        if agg != "count" && a.get("val").is_none() && sel.get("accumulates_into").is_none() {
            return Some(format!("{at}: {agg} needs val (or sel.accumulates_into for a sum)"));
        }
        if agg != "sum" && agg != "count" && a.get("val").is_none() {
            return Some(format!("{at}: {agg} needs val"));
        }
        if agg == "count" && a.get("val").is_some() {
            return Some(format!("{at}: count takes no val"));
        }
    }
    None
}

fn bstr_nonempty(x: &Value) -> bool {
    matches!(x, Value::String(st) if !st.is_empty())
}

/// `monitorDeclError(m)`. `None` = well-formed.
pub(crate) fn monitor_decl_error(m: &Value) -> Option<String> {
    let m = match m.as_object() {
        Some(m) => m,
        None => return Some("monitor must be an object".into()),
    };
    if let Some(k) = m.keys().find(|k| !["id", "kind", "p", "q", "status", "within"].contains(&k.as_str())) {
        return Some(format!("monitor: unknown member '{k}'"));
    }
    let id = match s(m.get("id")) {
        Some(id) if is_ident(id) && !RESERVED_NAMES.contains(&id) => id,
        _ => return Some("monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype".into()),
    };
    let at = format!("monitor '{id}'");
    let kind = match s(m.get("kind")).filter(|k| MONITOR_KINDS.contains(k)) {
        Some(k) => k,
        None => return Some(format!("{at}: unknown kind")),
    };
    if !predicate_shape_ok(m.get("p")) {
        return Some(format!("{at}: p must be a predicate"));
    }
    let needs_q = matches!(kind, "requires_prior" | "precedes" | "responds_within");
    if needs_q != m.get("q").is_some() {
        return Some(format!("{at}: q is required exactly for requires_prior / precedes / responds_within"));
    }
    if m.get("q").is_some() && !predicate_shape_ok(m.get("q")) {
        return Some(format!("{at}: q must be a predicate"));
    }
    if m.get("status").is_some() && !matches!(s(m.get("status")), Some("admitted" | "committed")) {
        return Some(format!("{at}: status must be admitted or committed"));
    }
    if (kind == "responds_within") != m.get("within").is_some() {
        return Some(format!("{at}: within is required exactly for responds_within"));
    }
    if m.get("within").is_some() && !sint(m.get("within")).is_some_and(|w| (1..=MAX_MONITOR_WITHIN).contains(&w)) {
        return Some(format!("{at}: within must be an integer in 1..{MAX_MONITOR_WITHIN}"));
    }
    None
}

/// `monitorStates(m)`: the state set Q.
pub(crate) fn monitor_states(m: &Value) -> Vec<String> {
    match s(m.get("kind")) {
        Some("requires_prior") | Some("precedes") => vec!["unmet".into(), "met".into()],
        Some("never") => vec!["clean".into(), "seen".into()],
        Some("always") => vec!["ok".into(), "broken".into()],
        Some("responds_within") => {
            let w = sint(m.get("within")).unwrap_or(0).max(0);
            let mut out = vec!["idle".to_string()];
            out.extend((1..=w).map(|i| format!("pending:{i}")));
            out.push("missed".into());
            out
        }
        _ => Vec::new(),
    }
}

/// `accSelects(a, verb, schema)`. `Err` where the reference throws.
pub(crate) fn acc_selects(a: &Map<String, Value>, verb: &str, schema: Option<&Value>) -> Result<bool, String> {
    let sel = obj(a.get("sel")).ok_or("sel is not an object")?;
    if sel.get("event").is_some() {
        return Ok(false);
    }
    if sel.get("verbs").and_then(Value::as_array).is_some_and(|vs| vs.iter().any(|v| v.as_str() == Some(verb))) {
        return Ok(true);
    }
    if let (Some(unit), Some(doc)) = (sel.get("accumulates_into"), schema) {
        let unit = s(Some(unit)).unwrap_or("");
        return Ok(match schema_verb(doc, verb)? {
            Some(v) => !accumulation_params(v, unit)?.is_empty(),
            None => false,
        });
    }
    Ok(false)
}

/// `val(ω)` for a selected action: the value and, for `distinct`, its canonical key.
pub(crate) struct AccValue {
    pub val: i64,
    pub key: Option<String>,
}

/// `accValueOf(a, verb, params, schema)`. `Ok(Err(reason))` = an unreadable value; `Err` = the reference throws.
pub(crate) fn acc_value_of(a: &Map<String, Value>, verb: &str, params: &Map<String, Value>, schema: Option<&Value>) -> Result<Result<AccValue, String>, String> {
    let read = |path: &str| -> Option<&Value> { params.get(path.strip_prefix("action.params.").unwrap_or(path)) };
    let agg = s(a.get("agg")).unwrap_or("");
    if agg == "count" {
        return Ok(Ok(AccValue { val: 1, key: None }));
    }
    let val = s(a.get("val"));
    if agg == "distinct" {
        let x = val.and_then(read);
        let key = match x {
            Some(Value::String(_)) => x.and_then(|x| canonicalize_strict(x).ok()),
            Some(n) if sint(Some(n)).is_some() => canonicalize_strict(n).ok(),
            _ => None,
        };
        return Ok(match key {
            Some(k) => Ok(AccValue { val: 1, key: Some(k) }),
            None => Err(format!("{} must be a string or a safe integer", val.unwrap_or(""))),
        });
    }
    if let Some(vp) = val {
        return Ok(match nonneg(read(vp)) {
            Some(x) => Ok(AccValue { val: x, key: None }),
            None => Err(format!("{vp} must be a non-negative safe integer")),
        });
    }
    let v = match schema {
        Some(doc) => schema_verb(doc, verb)?,
        None => None,
    };
    let v = match v {
        Some(v) => v,
        None => return Ok(Err(format!("no schema entry for '{verb}' to read accumulates_into"))),
    };
    let unit = s(obj(a.get("sel")).and_then(|x| x.get("accumulates_into"))).unwrap_or("");
    let mut sum: i64 = 0;
    for p in accumulation_params(v, unit)? {
        let x = match read(&p) {
            None => continue,
            Some(x) => x,
        };
        let x = match nonneg(Some(x)) {
            Some(x) => x,
            None => return Ok(Err(format!("{p} must be a non-negative safe integer"))),
        };
        sum += x;
        if sum > MAX_SAFE {
            return Ok(Err("accumulated value exceeds 2^53-1".into()));
        }
    }
    Ok(Ok(AccValue { val: sum, key: None }))
}

fn pre_member(agg: &str) -> &'static str {
    match agg {
        "sum" => "sum",
        "count" => "count",
        "max" => "max",
        _ => "values",
    }
}

/// `preStateError(a, pre)`. `None` = well-formed.
pub(crate) fn pre_state_error(agg: &str, pre: &Value) -> Option<String> {
    let o = match pre.as_object() {
        Some(o) => o,
        None => return Some("pre-state must be an object".into()),
    };
    let want = pre_member(agg);
    if !(o.len() == 1 && o.contains_key(want)) {
        return Some(format!("pre-state of a {agg} accumulator is {{{want}}}"));
    }
    if want == "values" {
        let vs = match o.get("values").and_then(Value::as_array) {
            Some(vs) if vs.iter().all(Value::is_string) => vs,
            _ => return Some("pre-state values must be strings".into()),
        };
        let distinct: std::collections::BTreeSet<&str> = vs.iter().filter_map(Value::as_str).collect();
        if distinct.len() != vs.len() {
            return Some("pre-state values must be distinct".into());
        }
        return None;
    }
    if nonneg(o.get(want)).is_some() {
        None
    } else {
        Some(format!("pre-state {want} must be a non-negative safe integer"))
    }
}

/// `preValue(a, pre)` of a well-formed pre-state.
pub(crate) fn pre_value(agg: &str, pre: &Value) -> i64 {
    match pre_member(agg) {
        "values" => pre.get("values").and_then(Value::as_array).map_or(0, Vec::len) as i64,
        m => nonneg(pre.get(m)).unwrap_or(0),
    }
}

/// `combineAcc(a, pre, v)`: the post-action value, `None` when it leaves the safe-integer range.
pub(crate) fn combine_acc(agg: &str, pre: &Value, v: &AccValue) -> Option<i64> {
    let post = match agg {
        "sum" => pre_value(agg, pre) + v.val,
        "count" => pre_value(agg, pre) + 1,
        "max" => pre_value(agg, pre).max(v.val),
        _ => {
            let vs = pre.get("values").and_then(Value::as_array);
            let n = vs.map_or(0, Vec::len) as i64;
            let has = vs.is_some_and(|vs| vs.iter().any(|x| x.as_str() == v.key.as_deref()));
            n + i64::from(!has)
        }
    };
    (post <= MAX_SAFE).then_some(post)
}

/// `pcactnReservationDigest(p)`: b64u(sha256(strictCanonical({d: "atlas-pca/acc-reserve/v1", b: <PCActn without sig,
/// pq_sig, threshold, intent_session>}))). `None` where the reference throws.
pub fn pcactn_reservation_digest(p: &Value) -> Option<String> {
    let mut b = p.as_object()?.clone();
    for k in ["sig", "pq_sig", "threshold", "intent_session"] {
        b.remove(k);
    }
    let mut m = Map::new();
    m.insert("d".into(), Value::String(ACC_RESERVE_DOMAIN.into()));
    m.insert("b".into(), Value::Object(b));
    digest_of(&Value::Object(m))
}

/// `accReceiptShapeError(r)`. `None` = well-formed.
pub(crate) fn acc_receipt_shape_error(r: &Value) -> Option<String> {
    let r = match r.as_object() {
        Some(r) => r,
        None => return Some("receipt is not an object".into()),
    };
    if let Some(k) = r.keys().find(|k| !RECEIPT_KEYS.contains(&k.as_str())) {
        return Some(format!("receipt: unknown member '{k}'"));
    }
    if !same(r.get("v"), Some(&Value::from(1))) || s(r.get("kind")) != Some("pca-acc-receipt") {
        return Some("not a pca-acc-receipt v1".into());
    }
    if !b32(r.get("session")) {
        return Some("receipt.session is not canonical base64url (32 bytes)".into());
    }
    if !s(r.get("acc")).is_some_and(is_ident) {
        return Some("receipt.acc is not an accumulator id".into());
    }
    if !sint(r.get("seq")).is_some_and(|q| q >= 1) {
        return Some("receipt.seq must be a safe integer >= 1".into());
    }
    if nonneg(r.get("pre")).is_none() || nonneg(r.get("delta")).is_none() || nonneg(r.get("post")).is_none() {
        return Some("receipt pre / delta / post must be non-negative safe integers".into());
    }
    if !b32(r.get("pcactn_digest")) {
        return Some("receipt.pcactn_digest is not canonical base64url (32 bytes)".into());
    }
    if !s(r.get("aud")).is_some_and(|a| !a.is_empty()) {
        return Some("receipt.aud must be a non-empty string".into());
    }
    if nonneg(r.get("issued_at")).is_none() || nonneg(r.get("expires_at")).is_none() {
        return Some("receipt.issued_at / expires_at must be non-negative safe integers".into());
    }
    let (ia, ea) = (nonneg(r.get("issued_at")).unwrap_or(0), nonneg(r.get("expires_at")).unwrap_or(0));
    if !(ea >= ia && ea - ia <= MAX_RECEIPT_LIFETIME_MS) {
        return Some(format!("receipt.expires_at must be within {MAX_RECEIPT_LIFETIME_MS} ms after issued_at"));
    }
    if !is_kid(r.get("kid")) {
        return Some("receipt.kid must match [A-Za-z0-9_.:-]{1,64}".into());
    }
    let ledger_ok = obj(r.get("ledger")).is_some_and(|l| exact_keys(l, &["head", "index"]) && nonneg(l.get("index")).is_some() && b32(l.get("head")));
    if !ledger_ok {
        return Some("receipt.ledger must be {index, head}".into());
    }
    if !b32(r.get("signer")) {
        return Some("receipt.signer is not canonical base64url (32 bytes)".into());
    }
    suite_shape_error(r, "receipt", "receipt.alg: ", "receipt.sig")
}

/// `verifyAccReceiptSignature(r, expectedSigner, pin)`. `Err(unsupported_suite)` when the suite dispatch refuses the
/// receipt's suite.
pub(crate) fn verify_acc_receipt_signature(r: &Value, expected_signer: &str, pin: Option<(&str, &Value)>) -> Result<bool, String> {
    let o = match r.as_object() {
        Some(o) => o,
        None => return Ok(false),
    };
    if let Some(e) = acc_receipt_shape_error(r) {
        return if e.contains(UNSUPPORTED_SUITE) { Err(e) } else { Ok(false) };
    }
    if s(o.get("signer")) != Some(expected_signer) {
        return Ok(false);
    }
    let mut body = o.clone();
    for k in ["alg", "pq_pk", "sig", "pq_sig"] {
        body.remove(k);
    }
    if !bind_suite_fields(&mut body, o.get("alg"), o.get("pq_pk"))? {
        return Ok(false);
    }
    match domain_message(ACC_RECEIPT_DOMAIN, body) {
        Some(msg) => verify_pinned_suite(o.get("alg"), expected_signer, o.get("pq_pk"), &msg, o.get("sig"), o.get("pq_sig"), pin),
        None => Ok(false),
    }
}

/// A key set's content address (`sequencerKeySetDigest`): b64u(sha256(strictCanonical({"d":
/// "atlas-pca/sequencer-keys-ref/v1", "k": set}))) over the whole set, signatures included.
pub fn sequencer_key_set_digest(k: &Value) -> Option<String> {
    let mut m = Map::new();
    m.insert("d".into(), Value::String(SEQUENCER_KEYS_REF_DOMAIN.into()));
    m.insert("k".into(), k.clone());
    digest_of(&Value::Object(m))
}

/// `trackedKeySetError(t)`: `acc.keyset_versions[root]` is exactly `{version, digest}`, version a safe integer >= 1 and
/// digest canonical base64url of 32 bytes. `None` = well-formed.
pub(crate) fn tracked_key_set_error(t: &Value) -> Option<String> {
    let o = match t.as_object() {
        Some(o) => o,
        None => return Some("a tracked key set must be an object {version, digest}".into()),
    };
    if let Some(k) = o.keys().find(|k| *k != "version" && *k != "digest") {
        return Some(format!("a tracked key set has the unknown member '{k}'"));
    }
    if !sint(o.get("version")).is_some_and(|v| v >= 1) {
        return Some("a tracked key set version must be a safe integer >= 1".into());
    }
    if !b32(o.get("digest")) {
        return Some("a tracked key set digest must be canonical base64url (32 bytes)".into());
    }
    None
}

/// `accReceiptDigest(r)` = b64u(sha256(strictCanonical({d: "atlas-pca/acc-receipt-ref/v1", r}))).
pub fn acc_receipt_digest(r: &Value) -> Option<String> {
    let mut m = Map::new();
    m.insert("d".into(), Value::String(ACC_RECEIPT_REF_DOMAIN.into()));
    m.insert("r".into(), r.clone());
    digest_of(&Value::Object(m))
}

/// `sequencerKeySetShapeError(k)`. `None` = well-formed.
pub(crate) fn sequencer_key_set_shape_error(k: &Value) -> Option<String> {
    let k = match k.as_object() {
        Some(k) => k,
        None => return Some("key set is not an object".into()),
    };
    const KEYS: [&str; 10] = ["v", "kind", "sequencer", "version", "issued_at", "keys", "alg", "pq_pk", "sig", "pq_sig"];
    if let Some(x) = k.keys().find(|x| !KEYS.contains(&x.as_str())) {
        return Some(format!("key set: unknown member '{x}'"));
    }
    if !same(k.get("v"), Some(&Value::from(1))) || s(k.get("kind")) != Some("pca-sequencer-keys") {
        return Some("not a pca-sequencer-keys v1".into());
    }
    if !b32(k.get("sequencer")) {
        return Some("sequencer is not canonical base64url (32 bytes)".into());
    }
    if nonneg(k.get("issued_at")).is_none() {
        return Some("issued_at must be a non-negative safe integer".into());
    }
    if !nonneg(k.get("version")).is_some_and(|v| v >= 1) {
        return Some("version must be a safe integer >= 1".into());
    }
    let entries = match k.get("keys").and_then(Value::as_array) {
        Some(e) if !e.is_empty() && e.len() <= 256 => e,
        _ => return Some("keys must be 1..256 entries".into()),
    };
    let mut kids = std::collections::BTreeSet::new();
    for e in entries {
        const EK: [&str; 6] = ["kid", "pk", "alg", "pq_pk", "not_before", "not_after"];
        let e = match e.as_object() {
            Some(e) if e.keys().all(|x| EK.contains(&x.as_str())) => e,
            _ => return Some("keys entries are {kid, pk, alg?, pq_pk?, not_before, not_after?}".into()),
        };
        if !is_kid(e.get("kid")) || !kids.insert(s(e.get("kid")).unwrap_or("")) {
            return Some("key kids must match [A-Za-z0-9_.:-]{1,64} and be distinct".into());
        }
        if !b32(e.get("pk")) {
            return Some("key pk is not canonical base64url (32 bytes)".into());
        }
        if let Some(x) = optional_alg_error(e.get("alg")) {
            return Some(format!("key alg: {x}"));
        }
        if e.get("pq_pk").is_some() && !b64any(e.get("pq_pk")) {
            return Some("key pq_pk is not canonical base64url".into());
        }
        let nb = nonneg(e.get("not_before"));
        let window_ok = match (nb, e.get("not_after")) {
            (None, _) => false,
            (Some(_), None) => true,
            (Some(nb), Some(na)) => nonneg(Some(na)).is_some_and(|na| na >= nb),
        };
        if !window_ok {
            return Some("key validity must be 0 <= not_before <= not_after".into());
        }
    }
    suite_shape_error(k, "key set", "alg: ", "sig")
}

/// `verifySequencerKeySet(k, root, rootPqPk)`: shape, `sequencer == root`, and the root's suite signature over
/// `"atlas-pca/sequencer-keys/v1\0" || strictCanonical({v, kind, sequencer, issued_at, keys} + bound suite fields)`.
/// `Err(unsupported_suite)` when the suite dispatch refuses the set's (or an entry's) suite.
pub(crate) fn verify_sequencer_key_set(k: &Value, root: &str, root_pq_pk: Option<&Value>) -> Result<bool, String> {
    if let Some(e) = sequencer_key_set_shape_error(k) {
        return if e.contains(UNSUPPORTED_SUITE) { Err(e) } else { Ok(false) };
    }
    if s(k.get("sequencer")) != Some(root) {
        return Ok(false);
    }
    let o = match k.as_object() {
        Some(o) => o,
        None => return Ok(false),
    };
    let mut body = Map::new();
    for f in ["v", "kind", "sequencer", "version", "issued_at", "keys"] {
        if let Some(x) = o.get(f) {
            body.insert(f.into(), x.clone());
        }
    }
    if !bind_suite_fields(&mut body, o.get("alg"), o.get("pq_pk"))? {
        return Ok(false);
    }
    let pin = root_pq_pk.map(|p| (root, p));
    match domain_message(SEQUENCER_KEYS_DOMAIN, body) {
        Some(msg) => verify_pinned_suite(o.get("alg"), root, o.get("pq_pk"), &msg, o.get("sig"), o.get("pq_sig"), pin),
        None => Ok(false),
    }
}

/// `verifyReceiptAgainstHolder(r, holder, keySets, now)` (NORMATIVE, rule 15): `issued_at <= now + 60000`; some presented
/// key set verifies under `holder.root` (PQ pinned by `holder.root_pq_pk`) and lists `r.kid` with `pk == r.signer`,
/// `not_before <= issued_at <= not_after` (when set) and the receipt's suite; the receipt verifies under that entry.
/// The error is `unsupported_suite: ...` when the receipt's suite, or the suite of a set that could have vouched for
/// it, is one the suite dispatch refuses.
pub(crate) fn verify_receipt_against_holder(
    r: &Value,
    holder: &Map<String, Value>,
    key_sets: Option<&Value>,
    now: f64,
    f: &ReceiptFreshness,
) -> Result<(), String> {
    const NOT_LISTED: &str = "is not signed by a key the session sequencer's root-signed key set lists for its issue time";
    let ok_age = |x: f64| x.is_finite() && x.fract() == 0.0 && (0.0..=MAX_SAFE as f64).contains(&x);
    if !ok_age(f.max_receipt_age_ms) || !ok_age(f.max_keyset_age_ms) {
        return Err("receipt freshness policy misconfigured (fail closed)".into());
    }
    if let Some(e) = acc_receipt_shape_error(r) {
        return Err(if e.contains(UNSUPPORTED_SUITE) { e } else { format!("malformed receipt: {e}") });
    }
    let issued = num(r.get("issued_at")).unwrap_or(f64::NAN);
    if !(issued <= now + RECEIPT_SKEW_MS as f64) {
        return Err("the receipt is issued in the future".into());
    }
    if !(now - issued <= f.max_receipt_age_ms) {
        return Err(format!("the receipt is older than {} ms", f.max_receipt_age_ms));
    }
    let sets: &[Value] = match key_sets {
        Some(Value::Array(a)) => a.as_slice(),
        _ => &[],
    };
    let root = s(holder.get("root")).unwrap_or("");
    let r_alg = suite_of(r.get("alg"))?.alg;
    let mut unsupported: Option<String> = None;
    for k in sets {
        match verify_sequencer_key_set(k, root, holder.get("root_pq_pk")) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                unsupported.get_or_insert(e);
                continue;
            }
        }
        // tracked {version, digest}: an older set is a rollback, ANOTHER set under the same version an equivocation
        if let Some((tv, td)) = &f.tracked {
            let v = nonneg(k.get("version")).unwrap_or(0);
            if v < *tv || (v == *tv && sequencer_key_set_digest(k).as_deref() != Some(td.as_str())) {
                continue;
            }
        }
        let ks_issued = num(k.get("issued_at")).unwrap_or(f64::NAN);
        if !(ks_issued <= now + RECEIPT_SKEW_MS as f64) || !(now - ks_issued <= f.max_keyset_age_ms) {
            continue;
        }
        let e = k.get("keys").and_then(Value::as_array).and_then(|es| es.iter().find(|e| same(e.get("kid"), r.get("kid"))));
        let e = match e {
            Some(e) => e,
            None => continue,
        };
        if !same(e.get("pk"), r.get("signer")) {
            continue;
        }
        let nb = num(e.get("not_before")).unwrap_or(f64::NAN);
        if issued < nb {
            continue;
        }
        // a retired key verifies only receipts issued in its window AND only until 60 s after its retirement
        if e.get("not_after").is_some_and(|na| {
            let na = num(Some(na)).unwrap_or(f64::NAN);
            !(issued <= na) || !(na >= now - RECEIPT_SKEW_MS as f64)
        }) {
            continue;
        }
        if suite_of(e.get("alg"))?.alg != r_alg {
            continue;
        }
        let pk = s(e.get("pk")).unwrap_or("");
        if verify_acc_receipt_signature(r, pk, e.get("pq_pk").map(|p| (pk, p)))? {
            return Ok(());
        }
    }
    Err(unsupported.unwrap_or_else(|| NOT_LISTED.to_string()))
}

/// `receiptArithmeticOk(a, r, val)`.
pub(crate) fn receipt_arithmetic_ok(agg: &str, r: &Value, val: i64) -> bool {
    let (pre, delta, post) = match (num(r.get("pre")), num(r.get("delta")), num(r.get("post"))) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => return false,
    };
    let val = val as f64;
    match agg {
        "sum" => delta == val && post == pre + delta,
        "count" => delta == 1.0 && post == pre + 1.0,
        "max" => delta == val && post == pre.max(delta),
        _ => (delta == 0.0 || delta == 1.0) && post == pre + delta,
    }
}

#[cfg(test)]
#[path = "k042_intent_acc_test.rs"]
mod k042_test;
