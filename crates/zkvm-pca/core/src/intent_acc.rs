//! Intent Layer v2 (PCA 0.4.2), conformance rule 15 (`accumulators`): a faithful port of `packages/pca/src/intent-acc.ts`
//! (declarations, selection, values, combination, `pca-acc-receipt` v1, `pca-sequencer-keys` v1) and of `accStep` in
//! `packages/pca/src/intent-v2.ts`, minus its first step (`boundRoot`): [`acc_step`] takes the ALREADY BOUND, verified session
//! root S (the coordinator runs the session module's bound-root step first).
//!
//! Strict pass (TS 5e0a33a9, README "strict values / absent vs null / suite capability"): the accumulator context is typed
//! (`state` / `monitors` / `last_seq` objects read by own key, `last_seq` values non-negative safe integers, `receipts` /
//! `sequencer_keys` arrays, `null` = malformed), the schema context is `{docs: [...], keys: [...]}`, the clock must be a safe
//! integer, accumulator and monitor ids refuse `__proto__` / `constructor` / `prototype`, and the env maps are plain data.
//!
//! Receipt / key-set freshness (TS 5e718f47): a receipt lives at most 15 min and is at most `policy.acc.max_receipt_age_s`
//! (default 900 s) old; key sets carry a monotone `version` (checked against the tracked `ctx.acc.keyset_versions[root]` = {version, digest}: no
//! rollback, no equivocation) and
//! are at most `policy.acc.max_keyset_age_s` (default 3600 s) old; a retired key (`not_after < now - 60 s`) stops verifying.
//!
//! Guest policy (suite capability): receipts and key sets verify under every suite `crate::pq_suites` implements (Ed25519,
//! ML-DSA-65/87, SLH-DSA, FN-DSA-512/1024 and the hybrids), a PQ key only as pinned (`holder.root_pq_pk` for a key set, the
//! key-set entry's `pq_pk` for a receipt). A suite the guest lacks (`less-cat1`, its hybrid, anything unregistered) in
//! `holder.root_alg`, the receipt, or the only key set / entry that could judge it fails the check with a reason containing
//! `unsupported_suite`. The malformed TOP-LEVEL context rule (`intentV2ContextError`: policy, params, layers, wb) is the
//! coordinator's; `acc_step` checks the members it owns (`acc`, `schema`). Lone surrogates cannot occur in a Rust `String`.
use crate::canonical::{canonical_bytes, canonicalize, js_string, strict_violation};
use crate::chain::decode_b64u_strict;
use crate::commit::hash_canonical;
use crate::jsnum::{non_neg, safe_int, MAX_SAFE_INT};
use serde_json::{json, Map, Value};

pub const MAX_SESSION_ACCUMULATORS: usize = 16;
pub const MAX_SESSION_MONITORS: usize = 16;
pub const MAX_MONITOR_WITHIN: i64 = 64;
pub const ACC_RECEIPT_DOMAIN: &str = "atlas-pca/acc-receipt/v1\0";
pub const ACC_RECEIPT_REF_DOMAIN: &str = "atlas-pca/acc-receipt-ref/v1";
pub const ACC_RESERVE_DOMAIN: &str = "atlas-pca/acc-reserve/v1";
pub const ACC_RECEIPT_CORE_DOMAIN: &str = "atlas-pca/acc-receipt-core/v1";
pub const SEQUENCER_KEYS_DOMAIN: &str = "atlas-pca/sequencer-keys/v1\0";
/// Allowed clock skew between a receipt's `issued_at` and the verifier's clock.
pub const RECEIPT_SKEW_MS: f64 = 60_000.0;
/// A receipt lives at most this long: `issued_at <= expires_at <= issued_at + MAX_RECEIPT_LIFETIME_MS` (15 min).
pub const MAX_RECEIPT_LIFETIME_MS: u64 = 900_000;
/// Default bound on a receipt's age at verification (`now - issued_at`), policy `acc.max_receipt_age_s` (15 min).
pub const DEFAULT_MAX_RECEIPT_AGE_MS: i64 = 900_000;
/// Default bound on a key set's age (`now - issued_at`), policy `acc.max_keyset_age_s` (1 h).
pub const DEFAULT_MAX_KEYSET_AGE_MS: i64 = 3_600_000;
const SKEW_MS: i64 = 60_000;

/// Freshness bounds of receipt verification (policy `acc`, tracked key-set versions); `None` = the default / not tracked.
/// Values are taken as given (a negative or unsafe bound fails the verification, as in TS).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReceiptFreshness {
    pub max_receipt_age_ms: Option<i64>,
    pub max_keyset_age_ms: Option<i64>,
    pub min_keyset_version: Option<i64>,
    /// The newest key set this verifier accepted for the holder's root (`acc.keyset_versions[root]` = {version, digest}).
    pub tracked: Option<Value>,
}

pub const SEQUENCER_KEYS_REF_DOMAIN: &str = "atlas-pca/sequencer-keys-ref/v1";

/// `sequencerKeySetDigest`: `base64url(sha256(strictCanonical({"d": "atlas-pca/sequencer-keys-ref/v1", "k": set})))`.
pub fn sequencer_key_set_digest(ks: &Value) -> String {
    hash_canonical(&json!({"d": SEQUENCER_KEYS_REF_DOMAIN, "k": ks}))
}

/// `trackedKeySetError`: `acc.keyset_versions[root]` is exactly `{version: safe integer >= 1, digest: 32-byte base64url}`.
pub fn tracked_key_set_error(t: &Value) -> Option<String> {
    let o = match t {
        Value::Object(o) => o,
        _ => return Some("a tracked key set must be an object {version, digest}".into()),
    };
    if let Some(k) = o.keys().find(|k| *k != "version" && *k != "digest") {
        return Some(format!("a tracked key set has the unknown member '{k}'"));
    }
    if !o.get("version").and_then(safe_int).is_some_and(|v| v >= 1) {
        return Some("a tracked key set version must be a safe integer >= 1".into());
    }
    if !matches!(o.get("digest"), Some(Value::String(d)) if decode_b64u_strict(d, 32).is_some()) {
        return Some("a tracked key set digest must be canonical base64url (32 bytes)".into());
    }
    None
}

/// The closed signature-suite registry of `pq.ts` `SIG_SUITES` (only `ed25519` is VERIFIED in the guest).
pub const SIG_ALGS: [&str; 14] = [
    "ed25519",
    "ml-dsa-65",
    "hybrid-ed25519-ml-dsa-65",
    "hybrid-nested-ed25519-ml-dsa-65",
    "slh-dsa-sha2-128f",
    "hybrid-ed25519-slh-dsa-sha2-128f",
    "ml-dsa-87",
    "hybrid-ed25519-ml-dsa-87",
    "slh-dsa-sha2-256s",
    "hybrid-ed25519-slh-dsa-sha2-256s",
    "fn-dsa-512",
    "less-cat1",
    "hybrid-ed25519-less-cat1",
    "fn-dsa-1024",
];

/// The verifier-computed predicate env of rule 15: `acc` = `{id: {post}}`, `mon` = `{id: {state}}`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AccEnv {
    pub acc: Map<String, Value>,
    pub mon: Map<String, Value>,
}

// ---- small JS helpers --------------------------------------------------------------------------------------------------

/// `resolveSigAlg(member)` on an optional member: absent = ed25519; a registered name; anything else (incl. `null`) = None.
fn resolve_alg(o: &Map<String, Value>, k: &str) -> Option<&'static str> {
    match o.get(k) {
        None => Some("ed25519"),
        Some(Value::String(s)) => SIG_ALGS.iter().copied().find(|a| *a == s.as_str()),
        Some(_) => None,
    }
}

/// `decodeB64uStrict(v, 32) !== null`.
fn b32(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(s)) if decode_b64u_strict(s, 32).is_some())
}

/// `decodeB64uStrict(v) !== null` (any decoded length).
fn b64u_any(v: Option<&Value>) -> bool {
    match v {
        Some(Value::String(s)) => s.len() % 4 != 1 && decode_b64u_strict(s, s.len() * 3 / 4).is_some(),
        _ => false,
    }
}

fn str_of<'a>(o: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    o.get(k).and_then(|v| v.as_str())
}

/// `^[A-Za-z0-9_]{1,64}$` (ACC_ID_RE).
pub fn is_acc_id(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
/// `^[A-Za-z0-9_.:-]{1,64}$` (KID_RE).
pub fn is_kid(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
}
/// `^action\.params\.[A-Za-z0-9_]{1,64}$`.
fn is_param_path(s: &str) -> bool {
    s.strip_prefix("action.params.").is_some_and(is_acc_id)
}
/// `^[a-z0-9_]+(?:\.[a-z0-9_]+)*$`.
fn is_unit(s: &str) -> bool {
    !s.is_empty() && s.split('.').all(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
}

/// The exact key set of an object (order-free), compared with `want` (sorted).
fn keys_are(o: &Map<String, Value>, want: &[&str]) -> bool {
    o.len() == want.len() && want.iter().all(|k| o.contains_key(*k))
}

/// JS `path.slice('action.params.'.length)` (14 UTF-16 units); `None` when the cut splits a surrogate pair (the lone
/// surrogate TS would produce can never be an own key of a JSON object).
fn js_slice14(path: &str) -> Option<&str> {
    let mut units = 0usize;
    for (i, c) in path.char_indices() {
        if units == 14 {
            return Some(&path[i..]);
        }
        units += c.len_utf16();
        if units > 14 {
            return None;
        }
    }
    Some("")
}

/// `RESERVED_NAMES` (intent-strict.ts): refused as accumulator and monitor ids.
pub const RESERVED_NAMES: [&str; 3] = ["__proto__", "constructor", "prototype"];

/// `suiteCapabilityError(o[k])` against the TS registry (the shape level): `None` = absent or a registered suite; a
/// non-string is malformed; an unregistered string is `unsupported_suite`.
fn suite_err(o: &Map<String, Value>, k: &str) -> Option<String> {
    match o.get(k) {
        None => None,
        Some(Value::String(s)) => (!SIG_ALGS.contains(&s.as_str())).then(|| format!("unsupported_suite: '{s}'")),
        Some(_) => Some("alg must be a string".into()),
    }
}

/// The GUEST's suite capability for `o[k]`: `Some(reason)` when the member names a suite the guest does not implement
/// (reason contains `unsupported_suite`) or is not a string.
fn guest_suite_err(o: &Map<String, Value>, k: &str) -> Option<String> {
    match o.get(k) {
        None => None,
        Some(Value::String(s)) => (!crate::pq_suites::suite_supported(Some(s))).then(|| format!("unsupported_suite: '{s}'")),
        Some(_) => Some("alg must be a string".into()),
    }
}

// ---- declarations (closed shapes) --------------------------------------------------------------------------------------

/// `accumulatorDeclError` (intent-acc.ts): `None` = a well-formed accumulator declaration.
pub fn accumulator_decl_error(a: &Value) -> Option<String> {
    let a = match a {
        Value::Object(o) => o,
        _ => return Some("accumulator must be an object".into()),
    };
    const KEYS: [&str; 10] = ["id", "agg", "val", "unit", "sel", "win", "key", "domain_max", "cap", "holder"];
    if let Some(k) = a.keys().find(|k| !KEYS.contains(&k.as_str())) {
        return Some(format!("accumulator: unknown member '{k}'"));
    }
    let id = match str_of(a, "id") {
        Some(s) if is_acc_id(s) && !RESERVED_NAMES.contains(&s) => s,
        _ => return Some("accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype".into()),
    };
    let at = format!("accumulator '{id}'");
    let agg = match str_of(a, "agg") {
        Some(s @ ("sum" | "count" | "distinct" | "max")) => s,
        _ => return Some(format!("{at}: unknown agg")),
    };
    if a.contains_key("val") && !str_of(a, "val").is_some_and(is_param_path) {
        return Some(format!("{at}: val must be action.params.<name>"));
    }
    if a.contains_key("unit") && !str_of(a, "unit").is_some_and(|u| u.len() <= 64 && is_unit(u)) {
        return Some(format!("{at}: unit must be a unit id"));
    }
    let sel = match a.get("sel") {
        Some(Value::Object(o)) => o,
        _ => return Some(format!("{at}: sel must be an object")),
    };
    if let Some(k) = sel.keys().find(|k| !["verbs", "accumulates_into", "event"].contains(&k.as_str())) {
        return Some(format!("{at}: sel has unknown member '{k}'"));
    }
    if let Some(v) = sel.get("verbs") {
        let ok = matches!(v, Value::Array(xs) if !xs.is_empty() && xs.len() <= 64 && xs.iter().all(|x| matches!(x, Value::String(s) if !s.is_empty())));
        if !ok {
            return Some(format!("{at}: sel.verbs must be 1..64 verb names"));
        }
    }
    if sel.contains_key("accumulates_into") && !str_of(sel, "accumulates_into").is_some_and(is_unit) {
        return Some(format!("{at}: sel.accumulates_into must be a unit id"));
    }
    if sel.contains_key("event") && !matches!(str_of(sel, "event"), Some("intent_required" | "question" | "clarification")) {
        return Some(format!("{at}: unknown sel.event"));
    }
    let action_sel = sel.contains_key("verbs") || sel.contains_key("accumulates_into");
    let event_sel = sel.contains_key("event");
    if action_sel == event_sel {
        return Some(format!("{at}: sel names actions (verbs / accumulates_into) or a wallet event, exactly one kind"));
    }
    let w = match a.get("win") {
        Some(Value::Object(o)) => o,
        _ => return Some(format!("{at}: win must be an object")),
    };
    match str_of(w, "kind") {
        Some("task") => {
            if w.len() != 1 {
                return Some(format!("{at}: win {{kind: task}} has no other member"));
            }
        }
        Some("sliding") => {
            if !keys_are(w, &["kind", "ms"]) || !w.get("ms").and_then(safe_int).is_some_and(|m| m > 0) {
                return Some(format!("{at}: win sliding needs a positive ms"));
            }
        }
        Some("period") => {
            if !keys_are(w, &["kind", "ms", "t0"]) || !w.get("ms").and_then(safe_int).is_some_and(|m| m > 0) || w.get("t0").and_then(non_neg).is_none() {
                return Some(format!("{at}: win period needs a positive ms and t0 >= 0"));
            }
        }
        _ => return Some(format!("{at}: unknown win kind")),
    }
    match a.get("key") {
        Some(Value::Null) => {}
        Some(Value::String(s)) if is_param_path(s) => {}
        _ => return Some(format!("{at}: key must be null or action.params.<name>")),
    }
    if a.contains_key("domain_max") && a.get("domain_max").and_then(non_neg).is_none() {
        return Some(format!("{at}: domain_max must be a non-negative safe integer"));
    }
    if a.contains_key("cap") && a.get("cap").and_then(non_neg).is_none() {
        return Some(format!("{at}: cap must be a non-negative safe integer"));
    }
    let h = match a.get("holder") {
        Some(Value::Object(o)) => o,
        _ => return Some(format!("{at}: holder must be an object")),
    };
    let hk = str_of(h, "kind");
    match hk {
        Some(k @ ("site_local" | "wallet")) => {
            if h.len() != 1 {
                return Some(format!("{at}: holder {k} has no other member"));
            }
        }
        Some("sequenced") => {
            if let Some(k) = h.keys().find(|k| !["kind", "uri", "root", "root_alg", "root_pq_pk", "keys_uri"].contains(&k.as_str())) {
                return Some(format!("{at}: holder sequenced has unknown member '{k}'"));
            }
            if !str_of(h, "uri").is_some_and(|u| !u.is_empty()) {
                return Some(format!("{at}: holder sequenced needs a uri"));
            }
            if !b32(h.get("root")) {
                return Some(format!("{at}: holder.root is not canonical base64url (32 bytes)"));
            }
            if let Some(e) = suite_err(h, "root_alg") {
                return Some(format!("{at}: holder.root_alg: {e}"));
            }
            if h.contains_key("root_pq_pk") && !b64u_any(h.get("root_pq_pk")) {
                return Some(format!("{at}: holder.root_pq_pk is not canonical base64url"));
            }
            if h.contains_key("keys_uri") && !str_of(h, "keys_uri").is_some_and(|u| !u.is_empty()) {
                return Some(format!("{at}: holder.keys_uri must be a non-empty string"));
            }
        }
        _ => return Some(format!("{at}: unknown holder kind")),
    }
    let wallet = hk == Some("wallet");
    if wallet != event_sel {
        return Some(format!("{at}: wallet events are wallet-held and only wallet events are"));
    }
    if !wallet {
        let has_val = a.contains_key("val");
        if agg != "count" && !has_val && !sel.contains_key("accumulates_into") {
            return Some(format!("{at}: {agg} needs val (or sel.accumulates_into for a sum)"));
        }
        if agg != "sum" && agg != "count" && !has_val {
            return Some(format!("{at}: {agg} needs val"));
        }
        if agg == "count" && has_val {
            return Some(format!("{at}: count takes no val"));
        }
    }
    None
}

/// `predicateShapeOk`: an object whose `verb` is a string or a non-empty array of strings.
fn predicate_shape_ok(p: Option<&Value>) -> bool {
    match p {
        Some(Value::Object(o)) => match o.get("verb") {
            Some(Value::String(_)) => true,
            Some(Value::Array(xs)) => !xs.is_empty() && xs.iter().all(Value::is_string),
            _ => false,
        },
        _ => false,
    }
}

/// `monitorDeclError` (intent-acc.ts): `None` = a well-formed monitor declaration.
pub fn monitor_decl_error(m: &Value) -> Option<String> {
    let m = match m {
        Value::Object(o) => o,
        _ => return Some("monitor must be an object".into()),
    };
    if let Some(k) = m.keys().find(|k| !["id", "kind", "p", "q", "status", "within"].contains(&k.as_str())) {
        return Some(format!("monitor: unknown member '{k}'"));
    }
    let id = match str_of(m, "id") {
        Some(s) if is_acc_id(s) && !RESERVED_NAMES.contains(&s) => s,
        _ => return Some("monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype".into()),
    };
    let at = format!("monitor '{id}'");
    let kind = match str_of(m, "kind") {
        Some(k @ ("requires_prior" | "precedes" | "never" | "always" | "responds_within")) => k,
        _ => return Some(format!("{at}: unknown kind")),
    };
    if !predicate_shape_ok(m.get("p")) {
        return Some(format!("{at}: p must be a predicate"));
    }
    let needs_q = matches!(kind, "requires_prior" | "precedes" | "responds_within");
    if needs_q != m.contains_key("q") {
        return Some(format!("{at}: q is required exactly for requires_prior / precedes / responds_within"));
    }
    if m.contains_key("q") && !predicate_shape_ok(m.get("q")) {
        return Some(format!("{at}: q must be a predicate"));
    }
    if m.contains_key("status") && !matches!(str_of(m, "status"), Some("admitted" | "committed")) {
        return Some(format!("{at}: status must be admitted or committed"));
    }
    if (kind == "responds_within") != m.contains_key("within") {
        return Some(format!("{at}: within is required exactly for responds_within"));
    }
    if m.contains_key("within") && !m.get("within").and_then(safe_int).is_some_and(|w| (1..=MAX_MONITOR_WITHIN).contains(&w)) {
        return Some(format!("{at}: within must be an integer in 1..{MAX_MONITOR_WITHIN}"));
    }
    None
}

/// `monitorStates(m)`: the closed state set Q (`None` where TS throws or returns `undefined`: an unknown kind, or a
/// `responds_within` with a negative / oversized `within`).
pub fn monitor_states(m: &Value) -> Option<Vec<String>> {
    let w = monitor_kind_within(m)?;
    Some(match w {
        MonKind::Fixed(q) => q.iter().map(|s| s.to_string()).collect(),
        MonKind::Within(w) => {
            let mut v = vec!["idle".to_string()];
            v.extend((1..=w).map(|i| format!("pending:{i}")));
            v.push("missed".into());
            v
        }
    })
}

enum MonKind {
    Fixed(&'static [&'static str]),
    Within(u64),
}

fn monitor_kind_within(m: &Value) -> Option<MonKind> {
    match m.get("kind").and_then(Value::as_str)? {
        "requires_prior" | "precedes" => Some(MonKind::Fixed(&["unmet", "met"])),
        "never" => Some(MonKind::Fixed(&["clean", "seen"])),
        "always" => Some(MonKind::Fixed(&["ok", "broken"])),
        "responds_within" => {
            let w = m.get("within").and_then(safe_int).unwrap_or(0);
            // Array.from({length: w}) throws a RangeError for w < 0 or w > 2^32 - 1
            if !(0..=u32::MAX as i64).contains(&w) {
                return None;
            }
            Some(MonKind::Within(w as u64))
        }
        _ => None,
    }
}

/// `monitorStates(m).includes(st)` without materialising Q (`None` = TS throws).
pub fn monitor_state_ok(m: &Value, st: &str) -> Option<bool> {
    Some(match monitor_kind_within(m)? {
        MonKind::Fixed(q) => q.contains(&st),
        MonKind::Within(w) => {
            st == "idle"
                || st == "missed"
                || st.strip_prefix("pending:").is_some_and(|n| {
                    !n.is_empty() && !n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit()) && n.len() <= 10 && n.parse::<u64>().is_ok_and(|i| (1..=w).contains(&i))
                })
        }
    })
}

/// `monitorInitialState(m)`.
pub fn monitor_initial_state(m: &Value) -> &'static str {
    match m.get("kind").and_then(Value::as_str) {
        Some("requires_prior" | "precedes") => "unmet",
        Some("never") => "clean",
        Some("always") => "ok",
        _ => "idle",
    }
}

// ---- schema lookups (read straight from the schema JSON) ---------------------------------------------------------------

/// `schemaVerb(doc, verb)`: `Ok(None)` = no entry; `Err` = the TS `find` throws (a `null` entry before the match).
fn schema_verb<'a>(doc: &'a Value, verb: &str) -> Result<Option<&'a Value>, String> {
    let verbs = match doc.get("verbs") {
        Some(Value::Array(v)) => v,
        _ => return Ok(None),
    };
    for v in verbs {
        match v {
            Value::Null => return Err("schema verb entry is null".into()),
            Value::Object(o) if o.get("verb").and_then(Value::as_str) == Some(verb) => return Ok(Some(v)),
            _ => {}
        }
    }
    Ok(None)
}

/// `accumulationParams(v, unit)`: the integer parameter paths of the verb listing `unit` in `accumulates_into`, in UTF-8
/// order. `Err` = TS throws (missing `params`, a null declaration, a non-array non-string `accumulates_into`).
fn accumulation_params(v: &Value, unit: &str) -> Result<Vec<String>, String> {
    let entries: Vec<(String, &Value)> = match v.get("params") {
        None | Some(Value::Null) => return Err("verb params is not an object".into()),
        Some(Value::Object(o)) => o.iter().map(|(k, d)| (k.clone(), d)).collect(),
        Some(Value::Array(a)) => a.iter().enumerate().map(|(i, d)| (i.to_string(), d)).collect(),
        Some(_) => Vec::new(),
    };
    let mut out = Vec::new();
    for (path, d) in entries {
        if d.is_null() {
            return Err(format!("param declaration {path} is null"));
        }
        let d = match d {
            Value::Object(o) => o,
            _ => continue, // a primitive has no `type`
        };
        if d.get("type").and_then(Value::as_str) != Some("integer") {
            continue;
        }
        let listed = match d.get("accumulates_into") {
            None | Some(Value::Null) => false,
            Some(Value::Array(xs)) => xs.iter().any(|x| x.as_str() == Some(unit)),
            Some(Value::String(s)) => s.contains(unit), // String.prototype.includes
            Some(_) => return Err("accumulates_into.includes is not a function".into()),
        };
        if listed {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// JS truthiness of a JSON value (the `schemaDoc ? ... : ...` tests).
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

// ---- selection, values, combination ------------------------------------------------------------------------------------

/// `accSelects(a, verb, schema)`: ω ∈ sel_ψ (`Err` = TS throws while reading the schema).
pub fn acc_selects(a: &Value, verb: &str, schema: Option<&Value>) -> Result<bool, String> {
    let sel = a.get("sel").and_then(Value::as_object).ok_or("accumulator sel is not an object")?;
    if sel.contains_key("event") {
        return Ok(false);
    }
    if let Some(vs) = sel.get("verbs") {
        match vs {
            Value::Array(xs) => {
                if xs.iter().any(|x| x.as_str() == Some(verb)) {
                    return Ok(true);
                }
            }
            Value::Null => {}
            _ => return Err("sel.verbs is not an array".into()),
        }
    }
    if let (Some(unit), Some(doc)) = (sel.get("accumulates_into"), schema.filter(|d| truthy(d))) {
        let unit = unit.as_str().ok_or("sel.accumulates_into is not a string")?;
        return Ok(match schema_verb(doc, verb)? {
            Some(v) => !accumulation_params(v, unit)?.is_empty(),
            None => false,
        });
    }
    Ok(false)
}

/// `distinctKey(x)`: the strict canonical JSON text of a string or a safe integer.
pub fn distinct_key(x: Option<&Value>) -> Option<String> {
    match x {
        Some(v @ Value::String(_)) => Some(canonicalize(v)),
        Some(v) => safe_int(v).map(|i| i.to_string()),
        None => None,
    }
}

/// val(ω) of a selected action: the value and, for `distinct`, its canonical key.
#[derive(Debug, Clone, PartialEq)]
pub struct AccValue {
    pub val: i64,
    pub key: Option<String>,
}

fn read_param<'a>(params: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    js_slice14(path).and_then(|n| params.get(n))
}

/// `accValueOf(a, verb, params, schema)` (`Err` carries the TS reason, or a TS throw).
pub fn acc_value_of(a: &Value, verb: &str, params: &Map<String, Value>, schema: Option<&Value>) -> Result<AccValue, String> {
    let read = |path: &str| read_param(params, path);
    let agg = a.get("agg").and_then(Value::as_str).unwrap_or("");
    let val = a.get("val").and_then(Value::as_str);
    if agg == "count" {
        return Ok(AccValue { val: 1, key: None });
    }
    if agg == "distinct" {
        // `a.val!`: an absent val reads `undefined.slice` and throws
        let path = val.ok_or("distinct accumulator has no val")?;
        return match distinct_key(read(path)) {
            Some(k) => Ok(AccValue { val: 1, key: Some(k) }),
            None => Err(format!("{path} must be a string or a safe integer")),
        };
    }
    if let Some(path) = val {
        return match read(path).and_then(non_neg) {
            Some(x) => Ok(AccValue { val: x as i64, key: None }),
            None => Err(format!("{path} must be a non-negative safe integer")),
        };
    }
    let v = match schema.filter(|d| truthy(d)) {
        Some(doc) => schema_verb(doc, verb)?,
        None => None,
    };
    let v = v.ok_or_else(|| format!("no schema entry for '{verb}' to read accumulates_into"))?;
    let unit = a.get("sel").and_then(|s| s.get("accumulates_into")).and_then(Value::as_str).ok_or("sel.accumulates_into is not a string")?;
    let mut s: i64 = 0;
    for p in accumulation_params(v, unit)? {
        let x = match read(&p) {
            None => continue,
            Some(x) => x,
        };
        let x = non_neg(x).ok_or_else(|| format!("{p} must be a non-negative safe integer"))?;
        s += x as i64; // both <= 2^53-1: no i64 overflow
        if s > MAX_SAFE_INT {
            return Err("accumulated value exceeds 2^53-1".into());
        }
    }
    Ok(AccValue { val: s, key: None })
}

fn pre_member(agg: &str) -> &'static str {
    match agg {
        "sum" => "sum",
        "count" => "count",
        "max" => "max",
        _ => "values",
    }
}

/// `preStateError(a, s)`: `None` = a well-formed pre-state for the accumulator's agg.
pub fn pre_state_error(agg: &str, s: &Value) -> Option<String> {
    let o = match s {
        Value::Object(o) => o,
        _ => return Some("pre-state must be an object".into()),
    };
    let want = pre_member(agg);
    if !(o.len() == 1 && o.contains_key(want)) {
        return Some(format!("pre-state of a {agg} accumulator is {{{want}}}"));
    }
    if want == "values" {
        let vs = match o.get("values") {
            Some(Value::Array(vs)) if vs.iter().all(Value::is_string) => vs,
            _ => return Some("pre-state values must be strings".into()),
        };
        let mut seen: Vec<&str> = vs.iter().filter_map(Value::as_str).collect();
        seen.sort_unstable();
        seen.dedup();
        return (seen.len() != vs.len()).then(|| "pre-state values must be distinct".into());
    }
    match o.get(want).and_then(non_neg) {
        Some(_) => None,
        None => Some(format!("pre-state {want} must be a non-negative safe integer")),
    }
}

/// `combineAcc(a, pre, v)`: the post-action value, `None` above 2^53-1 (or for a malformed pre-state).
pub fn combine_acc(agg: &str, pre: &Value, v: &AccValue) -> Option<i64> {
    let post = match agg {
        "sum" => pre.get("sum").and_then(non_neg)? as i64 + v.val,
        "count" => pre.get("count").and_then(non_neg)? as i64 + 1,
        "max" => (pre.get("max").and_then(non_neg)? as i64).max(v.val),
        "distinct" => {
            let vs = pre.get("values")?.as_array()?;
            let k = v.key.as_deref();
            vs.len() as i64 + i64::from(!vs.iter().any(|x| x.as_str().is_some() && x.as_str() == k))
        }
        _ => return None,
    };
    (0..=MAX_SAFE_INT).contains(&post).then_some(post)
}

/// `preValue(a, pre)`: the value of a group this action does not feed (post = pre).
pub fn pre_value(agg: &str, pre: &Value) -> Option<i64> {
    match agg {
        "sum" | "count" | "max" => pre.get(pre_member(agg)).and_then(non_neg).map(|x| x as i64),
        "distinct" => pre.get("values").and_then(Value::as_array).map(|v| v.len() as i64),
        _ => None,
    }
}

// ---- reservation receipts (sequenced holder) ---------------------------------------------------------------------------

/// `pcactnReservationDigest(p)`: `hashCanonical({d: "atlas-pca/acc-reserve/v1", b: p minus sig, pq_sig, threshold,
/// intent_session})`; `None` when `p` is not an object or is outside the strict profile (TS throws).
pub fn pcactn_reservation_digest(pcactn: &Value) -> Option<String> {
    let mut body = pcactn.as_object()?.clone();
    for k in ["sig", "pq_sig", "threshold", "intent_session"] {
        body.remove(k);
    }
    let v = json!({ "d": ACC_RESERVE_DOMAIN, "b": Value::Object(body) });
    strict_violation(&v).is_none().then(|| hash_canonical(&v))
}

/// `accReceiptDigest(r)`: `hashCanonical({d: "atlas-pca/acc-receipt-ref/v1", r})` (`None` = outside the strict profile).
pub fn acc_receipt_digest(r: &Value) -> Option<String> {
    let v = json!({ "d": ACC_RECEIPT_REF_DOMAIN, "r": r });
    strict_violation(&v).is_none().then(|| hash_canonical(&v))
}

const RECEIPT_KEYS: [&str; 19] = [
    "v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at", "expires_at", "kid", "ledger", "signer", "alg", "pq_pk", "sig", "pq_sig",
];

/// `accReceiptShapeError(r)`: `None` = a well-formed `pca-acc-receipt` v1.
pub fn acc_receipt_shape_error(r: &Value) -> Option<String> {
    let r = match r {
        Value::Object(o) => o,
        _ => return Some("receipt is not an object".into()),
    };
    if let Some(k) = r.keys().find(|k| !RECEIPT_KEYS.contains(&k.as_str())) {
        return Some(format!("receipt: unknown member '{k}'"));
    }
    if r.get("v").and_then(safe_int) != Some(1) || str_of(r, "kind") != Some("pca-acc-receipt") {
        return Some("not a pca-acc-receipt v1".into());
    }
    if !b32(r.get("session")) {
        return Some("receipt.session is not canonical base64url (32 bytes)".into());
    }
    if !str_of(r, "acc").is_some_and(is_acc_id) {
        return Some("receipt.acc is not an accumulator id".into());
    }
    if !r.get("seq").and_then(safe_int).is_some_and(|s| s >= 1) {
        return Some("receipt.seq must be a safe integer >= 1".into());
    }
    if ["pre", "delta", "post"].iter().any(|k| r.get(*k).and_then(non_neg).is_none()) {
        return Some("receipt pre / delta / post must be non-negative safe integers".into());
    }
    if !b32(r.get("pcactn_digest")) {
        return Some("receipt.pcactn_digest is not canonical base64url (32 bytes)".into());
    }
    if !str_of(r, "aud").is_some_and(|s| !s.is_empty()) {
        return Some("receipt.aud must be a non-empty string".into());
    }
    let (ia, ea) = match (r.get("issued_at").and_then(non_neg), r.get("expires_at").and_then(non_neg)) {
        (Some(i), Some(e)) => (i, e),
        _ => return Some("receipt.issued_at / expires_at must be non-negative safe integers".into()),
    };
    if !(ea >= ia && ea - ia <= MAX_RECEIPT_LIFETIME_MS) {
        return Some(format!("receipt.expires_at must be within {MAX_RECEIPT_LIFETIME_MS} ms after issued_at"));
    }
    if !str_of(r, "kid").is_some_and(is_kid) {
        return Some("receipt.kid must match [A-Za-z0-9_.:-]{1,64}".into());
    }
    let ledger_ok = matches!(r.get("ledger"), Some(Value::Object(l)) if keys_are(l, &["head", "index"]) && l.get("index").and_then(non_neg).is_some() && b32(l.get("head")));
    if !ledger_ok {
        return Some("receipt.ledger must be {index, head}".into());
    }
    if !b32(r.get("signer")) {
        return Some("receipt.signer is not canonical base64url (32 bytes)".into());
    }
    if let Some(e) = suite_err(r, "alg") {
        return Some(format!("receipt.alg: {e}"));
    }
    match resolve_alg(r, "alg") {
        None => return Some("receipt.alg: alg must be a string".into()),
        Some("ed25519") if r.contains_key("pq_pk") || r.contains_key("pq_sig") => return Some("an ed25519 receipt must not carry pq_pk / pq_sig".into()),
        _ => {}
    }
    if !r.get("sig").is_some_and(Value::is_string) {
        return Some("receipt.sig must be a string".into());
    }
    None
}

/// `domain || strictCanonical(body)`; `None` if the body is outside the strict profile (TS throws).
fn domain_message(domain: &str, body: &Value) -> Option<Vec<u8>> {
    if strict_violation(body).is_some() {
        return None;
    }
    let mut m = domain.as_bytes().to_vec();
    m.extend_from_slice(&canonical_bytes(body));
    Some(m)
}

/// Insert the bound suite fields (`bindSuiteFields(body, alg, pq_pk)`): a non-ed25519 suite signs `alg` and `pq_pk` too.
fn bind_suite_fields(body: &mut Map<String, Value>, o: &Map<String, Value>) {
    if let Some(a) = resolve_alg(o, "alg").filter(|a| *a != "ed25519") {
        body.insert("alg".into(), Value::String(a.to_string()));
        body.insert("pq_pk".into(), o.get("pq_pk").cloned().unwrap_or(Value::Null));
    }
}

/// `verifyAccReceiptSignature(r, expectedSigner, {pqPins: {[signer]: pin}})` in the guest (PCA 0.4.2: every suite the guest
/// implements; the PQ key must equal the key-set entry's pinned `pq_pk`; a suite the guest lacks fails closed).
pub fn verify_acc_receipt_signature(r: &Value, expected_signer: &str, pin: Option<&str>) -> bool {
    if acc_receipt_shape_error(r).is_some() {
        return false;
    }
    let o = match r.as_object() {
        Some(o) => o,
        None => return false,
    };
    if str_of(o, "signer") != Some(expected_signer) {
        return false;
    }
    let mut body = o.clone();
    for k in ["alg", "pq_pk", "sig", "pq_sig"] {
        body.remove(k);
    }
    bind_suite_fields(&mut body, o);
    let msg = match domain_message(ACC_RECEIPT_DOMAIN, &Value::Object(body)) {
        Some(m) => m,
        None => return false,
    };
    crate::pq_suites::verify_pinned_suite(resolve_alg(o, "alg"), expected_signer, str_of(o, "pq_pk"), &msg, str_of(o, "sig"), str_of(o, "pq_sig"), pin).is_ok()
}

/// `sequencerKeySetShapeError(k)`: `None` = a well-formed `pca-sequencer-keys` v1.
pub fn sequencer_key_set_shape_error(k: &Value) -> Option<String> {
    let k = match k {
        Value::Object(o) => o,
        _ => return Some("key set is not an object".into()),
    };
    if let Some(x) = k.keys().find(|x| !["v", "kind", "sequencer", "version", "issued_at", "keys", "alg", "pq_pk", "sig", "pq_sig"].contains(&x.as_str())) {
        return Some(format!("key set: unknown member '{x}'"));
    }
    if k.get("v").and_then(safe_int) != Some(1) || str_of(k, "kind") != Some("pca-sequencer-keys") {
        return Some("not a pca-sequencer-keys v1".into());
    }
    if !b32(k.get("sequencer")) {
        return Some("sequencer is not canonical base64url (32 bytes)".into());
    }
    if !k.get("version").and_then(non_neg).is_some_and(|v| v >= 1) {
        return Some("version must be a safe integer >= 1".into());
    }
    if k.get("issued_at").and_then(non_neg).is_none() {
        return Some("issued_at must be a non-negative safe integer".into());
    }
    let keys = match k.get("keys") {
        Some(Value::Array(a)) if !a.is_empty() && a.len() <= 256 => a,
        _ => return Some("keys must be 1..256 entries".into()),
    };
    let mut kids: Vec<&str> = Vec::new();
    for e in keys {
        let e = match e {
            Value::Object(o) if o.keys().all(|x| ["kid", "pk", "alg", "pq_pk", "not_before", "not_after"].contains(&x.as_str())) => o,
            _ => return Some("keys entries are {kid, pk, alg?, pq_pk?, not_before, not_after?}".into()),
        };
        let kid = match str_of(e, "kid") {
            Some(s) if is_kid(s) && !kids.contains(&s) => s,
            _ => return Some("key kids must match [A-Za-z0-9_.:-]{1,64} and be distinct".into()),
        };
        kids.push(kid);
        if !b32(e.get("pk")) {
            return Some("key pk is not canonical base64url (32 bytes)".into());
        }
        if let Some(err) = suite_err(e, "alg") {
            return Some(format!("key alg: {err}"));
        }
        if e.contains_key("pq_pk") && !b64u_any(e.get("pq_pk")) {
            return Some("key pq_pk is not canonical base64url".into());
        }
        let nb = e.get("not_before").and_then(non_neg);
        let na_ok = match e.get("not_after") {
            None => true,
            Some(x) => matches!((non_neg(x), nb), (Some(a), Some(b)) if a >= b),
        };
        if nb.is_none() || !na_ok {
            return Some("key validity must be 0 <= not_before <= not_after".into());
        }
    }
    if let Some(e) = suite_err(k, "alg") {
        return Some(format!("alg: {e}"));
    }
    match resolve_alg(k, "alg") {
        None => return Some("alg: alg must be a string".into()),
        Some("ed25519") if k.contains_key("pq_pk") || k.contains_key("pq_sig") => return Some("an ed25519 key set must not carry pq_pk / pq_sig".into()),
        _ => {}
    }
    if !k.get("sig").is_some_and(Value::is_string) {
        return Some("sig must be a string".into());
    }
    None
}

/// `verifySequencerKeySet(k, root, rootPqPk)` in the guest (PCA 0.4.2: every suite the guest implements; a PQ key set needs
/// `holder.root_pq_pk` as the pin for the root).
pub fn verify_sequencer_key_set(k: &Value, root: &str, root_pq_pk: Option<&str>) -> bool {
    if sequencer_key_set_shape_error(k).is_some() {
        return false;
    }
    let o = match k.as_object() {
        Some(o) => o,
        None => return false,
    };
    if str_of(o, "sequencer") != Some(root) {
        return false;
    }
    let mut body = Map::new();
    for f in ["v", "kind", "sequencer", "version", "issued_at", "keys"] {
        if let Some(v) = o.get(f) {
            body.insert(f.into(), v.clone());
        }
    }
    bind_suite_fields(&mut body, o);
    let msg = match domain_message(SEQUENCER_KEYS_DOMAIN, &Value::Object(body)) {
        Some(m) => m,
        None => return false,
    };
    crate::pq_suites::verify_pinned_suite(resolve_alg(o, "alg"), root, str_of(o, "pq_pk"), &msg, str_of(o, "sig"), str_of(o, "pq_sig"), root_pq_pk).is_ok()
}

/// `verifyReceiptAgainstHolder(r, holder, keySets, now, f)` (rule 15 step 3, sequenced) in the guest. False unless: `now` is a
/// safe integer and every bound a non-negative safe integer; the receipt is well-formed (15-min lifetime), `issued_at <= now
/// + 60 s` and `now - issued_at <= max receipt age` (default 15 min); SOME presented key set verifies under `holder.root`
/// (PQ pinned by `holder.root_pq_pk`), has `version >= min_keyset_version` when tracked, `issued_at <= now + 60 s` and
/// `now - issued_at <= max key-set age` (default 1 h), and lists `receipt.kid` with `pk == receipt.signer`, `not_before <=
/// receipt.issued_at` and, when `not_after` is set, `receipt.issued_at <= not_after` AND `now - 60 s <= not_after` (a retired
/// key stops verifying), the entry's suite equal to the receipt's; and the receipt verifies under that entry (PQ pinned by the
/// entry's `pq_pk`). `key_sets` must be an array.
pub fn verify_receipt_against_holder(r: &Value, holder: &Value, key_sets: &Value, now: f64, f: &ReceiptFreshness) -> bool {
    let safe = |x: i64| (0..=MAX_SAFE_INT).contains(&x);
    let max_age = f.max_receipt_age_ms.unwrap_or(DEFAULT_MAX_RECEIPT_AGE_MS);
    let max_set_age = f.max_keyset_age_ms.unwrap_or(DEFAULT_MAX_KEYSET_AGE_MS);
    let now_ok = now.fract() == 0.0 && now.abs() <= MAX_SAFE_INT as f64 && !(now == 0.0 && now.is_sign_negative());
    if !now_ok || !safe(max_age) || !safe(max_set_age) || f.min_keyset_version.is_some_and(|v| !safe(v)) || f.tracked.as_ref().is_some_and(|t| tracked_key_set_error(t).is_some()) {
        return false;
    }
    let now = now as i64;
    let sets = match key_sets {
        Value::Array(a) => a,
        _ => return false,
    };
    if acc_receipt_shape_error(r).is_some() {
        return false;
    }
    let (issued, kid, signer) = match (r.get("issued_at").and_then(non_neg), r.get("kid").and_then(Value::as_str), r.get("signer").and_then(Value::as_str)) {
        (Some(i), Some(k), Some(s)) => (i as i64, k, s),
        _ => return false,
    };
    if !(issued <= now + SKEW_MS) || !(now - issued <= max_age) {
        return false;
    }
    let ro = match r.as_object() {
        Some(o) => o,
        None => return false,
    };
    let r_alg = resolve_alg(ro, "alg");
    let root = match holder.get("root").and_then(Value::as_str) {
        Some(s) => s,
        None => return false,
    };
    for k in sets {
        if !verify_sequencer_key_set(k, root, holder.get("root_pq_pk").and_then(Value::as_str)) {
            continue;
        }
        let (ver, ks_issued) = match (k.get("version").and_then(non_neg), k.get("issued_at").and_then(non_neg)) {
            (Some(v), Some(i)) => (v as i64, i as i64),
            _ => continue,
        };
        if f.min_keyset_version.is_some_and(|m| ver < m) {
            continue;
        }
        // tracked {version, digest}: no rollback, and one version names one set (a different set is an EQUIVOCATION)
        if let Some(t) = &f.tracked {
            let tv = t.get("version").and_then(safe_int).unwrap_or(i64::MAX);
            if ver < tv || (ver == tv && Some(sequencer_key_set_digest(k).as_str()) != t.get("digest").and_then(Value::as_str)) {
                continue;
            }
        }
        if !(ks_issued <= now + SKEW_MS) || !(now - ks_issued <= max_set_age) {
            continue;
        }
        let e = match k.get("keys").and_then(Value::as_array).and_then(|ks| ks.iter().find(|x| x.get("kid").and_then(Value::as_str) == Some(kid))) {
            Some(Value::Object(e)) => e,
            _ => continue,
        };
        let nb = match e.get("not_before").and_then(non_neg) {
            Some(n) => n as i64,
            None => continue,
        };
        if str_of(e, "pk") != Some(signer) || issued < nb {
            continue;
        }
        if let Some(na) = e.get("not_after") {
            match non_neg(na) {
                Some(na) if issued <= na as i64 && na as i64 >= now - SKEW_MS => {}
                _ => continue,
            }
        }
        if resolve_alg(e, "alg").unwrap_or("ed25519") != r_alg.unwrap_or("x") {
            continue;
        }
        if verify_acc_receipt_signature(r, signer, str_of(e, "pq_pk")) {
            return true;
        }
    }
    false
}

/// After a failed holder check: the `unsupported_suite` reason when the only candidates the guest could not judge use a suite
/// it does not implement (a key set under `holder.root`, or the key-set entry named by `receipt.kid`).
fn unsupported_key_set_suite(r: &Value, holder: &Value, key_sets: &Value) -> Option<String> {
    let root = holder.get("root").and_then(Value::as_str)?;
    let kid = r.get("kid").and_then(Value::as_str)?;
    for k in key_sets.as_array()? {
        let o = match k.as_object() {
            Some(o) if str_of(o, "sequencer") == Some(root) && sequencer_key_set_shape_error(k).is_none() => o,
            _ => continue,
        };
        if let Some(e) = guest_suite_err(o, "alg") {
            return Some(format!("key set alg: {e}"));
        }
        let entry = o.get("keys").and_then(Value::as_array).and_then(|ks| ks.iter().find(|x| x.get("kid").and_then(Value::as_str) == Some(kid)));
        if let Some(e) = entry.and_then(Value::as_object).and_then(|e| guest_suite_err(e, "alg")) {
            return Some(format!("key alg: {e}"));
        }
    }
    None
}

/// `receiptArithmeticOk(a, r, val)` (rule 15 step 5d).
pub fn receipt_arithmetic_ok(agg: &str, r: &Value, val: i64) -> bool {
    let (pre, delta, post) = match (r.get("pre").and_then(non_neg), r.get("delta").and_then(non_neg), r.get("post").and_then(non_neg)) {
        (Some(a), Some(b), Some(c)) => (a as i64, b as i64, c as i64),
        _ => return false,
    };
    match agg {
        "sum" => delta == val && post == pre + delta,
        "count" => delta == 1 && post == pre + 1,
        "max" => delta == val && post == pre.max(delta),
        "distinct" => (delta == 0 || delta == 1) && post == pre + delta,
        _ => false,
    }
}

// ---- the `accumulators` check (rule 15) ----------------------------------------------------------------------------------

fn bad<T>(s: String) -> Result<T, String> {
    Err(s)
}

/// `accCtxError` then `schemaCtxError` (intent-v2.ts): the typed accumulator and schema contexts. Absent = default; present
/// with the wrong JSON type (including `null`) = malformed.
fn acc_ctx_error(ctx: Option<&Value>) -> Option<String> {
    let c = match ctx {
        None => return None,
        Some(Value::Object(c)) => c,
        Some(_) => return Some("the v2 verifier context must be an object".into()),
    };
    if let Some(a) = c.get("acc") {
        let a = match a {
            Value::Object(a) => a,
            _ => return Some("the accumulator context must be an object".into()),
        };
        for k in ["state", "monitors", "last_seq", "keyset_versions"] {
            if a.get(k).is_some_and(|v| !v.is_object()) {
                return Some(format!("acc.{k} must be an object"));
            }
        }
        if let Some(Value::Object(kv)) = a.get("keyset_versions") {
            if let Some(e) = kv.values().find_map(tracked_key_set_error) {
                return Some(format!("acc.keyset_versions: {e}"));
            }
        }
        for k in ["receipts", "sequencer_keys"] {
            if a.get(k).is_some_and(|v| !v.is_array()) {
                return Some(format!("acc.{k} must be an array"));
            }
        }
        if let Some(Value::Object(ls)) = a.get("last_seq") {
            if ls.values().any(|v| non_neg(v).is_none()) {
                return Some("acc.last_seq values must be non-negative safe integers".into());
            }
        }
    }
    if let Some(sc) = c.get("schema") {
        let ok = matches!(sc, Value::Object(o) if o.get("docs").is_some_and(Value::is_array) && o.get("keys").is_some_and(Value::is_array));
        if !ok {
            return Some("the schema context must be {docs: [...], keys: [...]}".into());
        }
    }
    None
}

/// Rule 15 (`accumulators`) = TS `accStep` after its `boundRoot` step: `s` is the bound, verified session root S, `ctx`
/// the `IntentV2Context` (`params`, `acc: {state, monitors, receipts, last_seq, sequencer_keys}`), `schema_doc` the
/// accepted schema whose digest equals `intent_session.schema` (None when the verifier holds none). Returns the env on
/// success, else the first failure's TS reason.
pub fn acc_step(pcactn: &Value, s: &Value, ctx: Option<&Value>, now: f64, schema_doc: Option<&Value>) -> Result<AccEnv, String> {
    // `decideIntentV2` runs no check under a clock that is not a safe integer
    if !(now.fract() == 0.0 && now.abs() <= MAX_SAFE_INT as f64 && !(now == 0.0 && now.is_sign_negative())) {
        return bad("the verifier clock is not a safe integer (fail closed)".into());
    }
    if let Some(e) = acc_ctx_error(ctx) {
        return bad(e);
    }
    let is = match pcactn.get("intent_session") {
        Some(v @ Value::Object(_)) => v,
        _ => return bad("accumulators error (fail closed): the PCActn carries no intent_session object".into()),
    };
    let session = is.get("session");
    let verb = js_string(pcactn.get("action").filter(|a| a.is_object()).and_then(|a| a.get("verb")));
    let empty: Vec<Value> = Vec::new();
    let claims: &Vec<Value> = match is.get("acc") {
        None | Some(Value::Null) => &empty,
        Some(Value::Array(a)) => a,
        Some(_) => return bad("accumulators error (fail closed): intent_session.acc is not an array".into()),
    };
    let decls = s.get("accumulators").and_then(Value::as_array).ok_or("accumulators error (fail closed): S.accumulators is not an array")?;
    let mons_decl = s.get("monitors").and_then(Value::as_array).ok_or("accumulators error (fail closed): S.monitors is not an array")?;
    let id_of = |v: &Value| v.get("id").cloned();
    let holder_kind = |a: &Value| a.get("holder").and_then(|h| h.get("kind")).and_then(Value::as_str).map(str::to_string);
    for c in claims {
        if !c.is_object() {
            return bad("accumulators error (fail closed): a claim is not an object".into());
        }
        let cid = id_of(c);
        let a = match decls.iter().find(|x| x.is_object() && x.get("id").cloned() == cid) {
            Some(a) => a,
            None => return bad(format!("claim '{}' names no accumulator of the session", js_string(cid.as_ref()))),
        };
        if holder_kind(a).as_deref() == Some("wallet") {
            return bad(format!("accumulator '{}' is wallet-held and cannot be claimed at a site", js_string(cid.as_ref())));
        }
    }
    let schema_doc = schema_doc.filter(|d| truthy(d));
    let params = ctx.and_then(|c| c.get("params"));
    // typed by `acc_ctx_error`: every member below is absent or of its JSON type
    let acc_ctx = ctx.and_then(|c| c.get("acc")).and_then(Value::as_object);
    let state = acc_ctx.and_then(|a| a.get("state")).and_then(Value::as_object);
    let last_seq = acc_ctx.and_then(|a| a.get("last_seq")).and_then(Value::as_object);
    let mut env = AccEnv::default();
    for a in decls {
        let ao = a.as_object().ok_or("accumulators error (fail closed): an accumulator is not an object")?;
        let id = str_of(ao, "id").ok_or("accumulators error (fail closed): an accumulator id is not a string")?;
        let agg = str_of(ao, "agg").unwrap_or("");
        let hk = holder_kind(a);
        if hk.as_deref() == Some("wallet") {
            continue;
        }
        let sel_into = ao.get("sel").and_then(Value::as_object).is_some_and(|s| s.contains_key("accumulates_into"));
        if sel_into && schema_doc.is_none() {
            return bad(format!("accumulator '{id}' selects by accumulates_into but the session schema is not available"));
        }
        let selected = acc_selects(a, &verb, schema_doc).map_err(|e| format!("accumulators error (fail closed): {e}"))?;
        let claim = claims.iter().find(|c| c.get("id").and_then(Value::as_str) == Some(id));
        let pre = state.and_then(|st| st.get(id)).cloned();
        if !selected {
            if claim.is_some() {
                return bad(format!("claim '{id}' for an accumulator this action does not feed"));
            }
            if hk.as_deref() == Some("site_local") {
                if let Some(pre) = &pre {
                    if let Some(pe) = pre_state_error(agg, pre) {
                        return bad(format!("accumulator '{id}': {pe}"));
                    }
                    let v = pre_value(agg, pre).ok_or("accumulators error (fail closed): pre-state value")?;
                    env.acc.insert(id.to_string(), json!({ "post": v }));
                }
            }
            continue;
        }
        let claim = match claim {
            Some(c) => c,
            None => return bad(format!("no claim for accumulator '{id}' that this action feeds")),
        };
        let params = match params {
            Some(Value::Object(p)) => p,
            _ => return bad("no plaintext params to compute accumulator values".into()),
        };
        match ao.get("key") {
            None => return bad("accumulators error (fail closed): accumulator key is undefined".into()),
            Some(Value::Null) => {}
            Some(k) => {
                let key = k.as_str().ok_or("accumulators error (fail closed): accumulator key is not a string")?;
                let present = js_slice14(key).is_some_and(|n| params.contains_key(n));
                if !present {
                    return bad(format!("accumulator '{id}': the key parameter {key} is missing"));
                }
                let kd = match schema_doc {
                    Some(doc) => schema_verb(doc, &verb).map_err(|e| format!("accumulators error (fail closed): {e}"))?.map(|v| v.get("params")),
                    None => None,
                };
                let identity = match kd {
                    None => false,
                    // `v.params[a.key]` on a missing / null params throws; every other non-object yields no declaration
                    Some(None) | Some(Some(Value::Null)) => return bad("accumulators error (fail closed): verb params is not an object".into()),
                    Some(Some(Value::Object(ps))) => match ps.get(key) {
                        Some(Value::Object(d)) => matches!(d.get("semantic"), Some(Value::String(sem)) if !sem.starts_with("text.")),
                        _ => false,
                    },
                    Some(Some(_)) => false,
                };
                if !identity {
                    return bad(format!("accumulator '{id}': the key must be a schema-declared identity (not free text)"));
                }
            }
        }
        let v = acc_value_of(a, &verb, params, schema_doc).map_err(|e| format!("accumulator '{id}': {e}"))?;
        let post: i64 = if hk.as_deref() == Some("site_local") {
            if claim.get("receipt").is_some() {
                return bad(format!("accumulator '{id}' is site-local: a receipt is not accepted"));
            }
            let pre = match &pre {
                Some(p) => p,
                None => return bad(format!("no state for site-local accumulator '{id}'")),
            };
            if let Some(pe) = pre_state_error(agg, pre) {
                return bad(format!("accumulator '{id}': {pe}"));
            }
            match combine_acc(agg, pre, &v) {
                Some(x) => x,
                None => return bad(format!("accumulator '{id}' overflows 2^53-1")),
            }
        } else {
            let want = match claim.get("receipt") {
                Some(Value::String(r)) => r.as_str(),
                _ => return bad(format!("accumulator '{id}' is sequenced: the claim needs a reservation receipt")),
            };
            let rc = match acc_ctx.and_then(|c| c.get("receipts")) {
                Some(Value::Array(rs)) => rs.iter().find(|x| acc_receipt_digest(x).as_deref() == Some(want)),
                _ => None,
            };
            let rc = match rc {
                Some(r) => r,
                None => return bad(format!("the reservation receipt for '{id}' was not presented")),
            };
            let holder = ao.get("holder").cloned().unwrap_or(Value::Null);
            let keys = acc_ctx.and_then(|c| c.get("sequencer_keys")).cloned().unwrap_or_else(|| json!([]));
            // suite capability (README "Suite capability"): a suite the guest does not implement fails with unsupported_suite
            if let Some(e) = holder.as_object().and_then(|h| guest_suite_err(h, "root_alg")) {
                return bad(format!("accumulator '{id}': holder.root_alg: {e}"));
            }
            if let Some(e) = rc.as_object().and_then(|r| guest_suite_err(r, "alg")) {
                return bad(format!("the reservation receipt for '{id}': receipt.alg: {e}"));
            }
            // policy.acc (typed by the coordinator's context check) and the tracked key-set version of this root
            let pa = ctx.and_then(|c| c.get("policy")).and_then(|p| p.get("acc"));
            let secs_ms = |k: &str| pa.and_then(|o| o.get(k)).map(|v| safe_int(v).map_or(-1, |s| s.checked_mul(1000).unwrap_or(-1)));
            let root_s = holder.get("root").and_then(Value::as_str).unwrap_or("");
            let fresh = ReceiptFreshness {
                max_receipt_age_ms: secs_ms("max_receipt_age_s"),
                max_keyset_age_ms: secs_ms("max_keyset_age_s"),
                min_keyset_version: None,
                tracked: acc_ctx.and_then(|a| a.get("keyset_versions")).and_then(|kv| kv.get(root_s)).cloned(),
            };
            if !verify_receipt_against_holder(rc, &holder, &keys, now, &fresh) {
                let unsupported = unsupported_key_set_suite(rc, &holder, &keys);
                return bad(format!(
                    "the reservation receipt for '{id}' is not signed by a key the session sequencer's root-signed key set lists for its issue time{}",
                    unsupported.map(|e| format!(" ({e})")).unwrap_or_default()
                ));
            }
            if rc.get("session") != session || rc.get("acc").and_then(Value::as_str) != Some(id) || rc.get("aud") != pcactn.get("aud") || pcactn.get("aud").is_none() {
                return bad(format!("the reservation receipt for '{id}' is for another session, accumulator or audience"));
            }
            match pcactn_reservation_digest(pcactn) {
                Some(d) if rc.get("pcactn_digest").and_then(Value::as_str) == Some(d.as_str()) => {}
                Some(_) => return bad(format!("the reservation receipt for '{id}' is for another action")),
                None => return bad("accumulators error (fail closed): the PCActn is outside the strict profile".into()),
            }
            let exp = rc.get("expires_at").and_then(non_neg).ok_or("accumulators error (fail closed): receipt expires_at")?;
            if !(now <= exp as f64) {
                return bad(format!("the reservation receipt for '{id}' has expired"));
            }
            let seq = rc.get("seq").and_then(safe_int).ok_or("accumulators error (fail closed): receipt seq")?;
            if let Some(last) = last_seq.and_then(|ls| ls.get(id)).and_then(non_neg) {
                if seq <= last as i64 {
                    return bad(format!("the reservation receipt for '{id}' replays seq {seq} (last accepted {last})"));
                }
            }
            if !receipt_arithmetic_ok(agg, rc, v.val) {
                return bad(format!("the reservation receipt for '{id}' does not add up"));
            }
            rc.get("post").and_then(non_neg).ok_or("accumulators error (fail closed): receipt post")? as i64
        };
        if let Some(dm) = ao.get("domain_max") {
            match non_neg(dm) {
                Some(dm) if post as u64 <= dm => {}
                _ => return bad(format!("accumulator '{id}' post {post} is outside its domain (max {})", js_string(Some(dm)))),
            }
        }
        if claim.get("post").and_then(safe_int) != Some(post) {
            return bad(format!("claimed post {} for '{id}' differs from the verifier's {post}", js_string(claim.get("post"))));
        }
        env.acc.insert(id.to_string(), json!({ "post": post }));
    }
    let mons = acc_ctx.and_then(|a| a.get("monitors")).and_then(Value::as_object);
    for m in mons_decl {
        let id = m.get("id").and_then(Value::as_str).ok_or("accumulators error (fail closed): a monitor id is not a string")?;
        let st = mons.and_then(|ms| ms.get(id)).cloned();
        let ok = match &st {
            Some(Value::String(st)) => monitor_state_ok(m, st).ok_or("accumulators error (fail closed): monitor kind")?,
            _ => false,
        };
        if !ok {
            return bad(format!("no valid state for monitor '{id}'"));
        }
        env.mon.insert(id.to_string(), json!({ "state": st }));
    }
    Ok(env)
}
