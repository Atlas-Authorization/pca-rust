//! Intent Layer v2 (PCA 0.4.2) rule 13: the `intent_session` member, the session root S, the session grant caveat, the
//! session revocation step (T22) and the `intent_session` check. A faithful port of
//!   packages/pca/src/intent-session.ts          (`validateIntentSessionWire`, `sessionRootShapeError`, `verifySessionRoot`,
//!                                                `sessionRootDigest`, `grantSessionCaveat`)
//!   packages/pca/src/intent-session-caveat.ts   (`intentSessionCaveatError`)
//!   packages/pca/src/intent-revocation.ts       (the revocation ids, `checkSessionRevocation` steps a-e)
//!   packages/pca/src/revocation.ts              (`checkRevocationEpoch`, `verifyNonMembership`, the sorted Merkle set)
//!   packages/pca/src/intent-v2.ts               (`boundRoot`, `sessionStep` steps 0-7)
//! plus the accumulator / monitor declaration shapes of packages/pca/src/intent-acc.ts that the session-root shape uses
//! (`accumulatorDeclError`, `monitorDeclError`; kept here so this module does not depend on another port in progress).
//!
//! STRICT PASS (TS 5e0a33a9, README "strict values / absent vs null / suite capability"): numbers are safe integers (no
//! coercion), lists are arrays, keyed reads are own members, absent = default and null = malformed (S.layers.org / std),
//! the revocation epoch and every non-membership proof are shape-checked before any comparison, and the clock must be a
//! safe integer. STEP 7 (staged TS redesign): one dedicated revocation authority `S.revocation.key` (required, never a
//! principal) signs epochs that carry their FULL sorted revoked list (root / size / epoch bound), checked append-only
//! against the verifier's tracked last epoch (`session.revocation_last`).
//!
//! SUITES: the guest verifies every suite of [`crate::pq_suites`] (Ed25519, ML-DSA-65/87, SLH-DSA and their hybrids); a PQ
//! signature verifies only under a PQ key the trusted side pins (for S: the verifier's `session.pq_pins[S.signer]`, never S's own
//! `principals[].pq_pk`, guest version 9; `S.revocation.pq_pk`
//! for a revocation epoch). A suite the guest lacks (FN-DSA, LESS, unknown) fails closed with a
//! reason containing `unsupported_suite` (the TS reference accepts every registered suite: those are `requires_suite` cases).
//!
//! Inputs are never trusted: nothing here panics.

use crate::canonical::{canonical_bytes, js_number_to_string, strict_violation};
use crate::commit::{b64u, hash_canonical, sha256};
use crate::jsnum::{non_neg, safe_int, MAX_SAFE_INT};
use serde_json::{Map, Value};

pub const INTENT_SESSION_KIND: &str = "pca-intent-session";
pub const INTENT_SESSION_SIG_DOMAIN: &str = "atlas-pca/intent-session/v1\0";
pub const INTENT_SESSION_REF_DOMAIN: &str = "atlas-pca/intent-session-ref/v1";
pub const INTENT_SESSION_CAVEAT: &str = "intent_session";
/// Largest delta sequence number (2^31 - 1).
pub const MAX_SESSION_SEQ: u64 = 2_147_483_647;

pub const MAX_IS_ACC: usize = 16;
pub const MAX_IS_FACTS: usize = 16;
pub const MAX_IS_PROV_PATHS: usize = 32;
pub const MAX_IS_PROV_REFS: usize = 8;
pub const MAX_IS_CLASSES: usize = 8;
pub const MAX_IS_LABELS: usize = 16;
pub const MAX_IS_STRING_BYTES: usize = 256;
pub const INTENT_SESSION_FIELDS: [&str; 11] = ["session", "root", "seq", "schema", "acc", "facts", "offer_set", "prov", "classes", "labels", "map_form"];

pub const MAX_SESSION_PRINCIPALS: usize = 16;
pub const MAX_SESSION_ACCUMULATORS: usize = 16;
pub const MAX_SESSION_MONITORS: usize = 16;
pub const MAX_MONITOR_WITHIN: i64 = 64;
const ROOT_KEYS: [&str; 18] = [
    "v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors", "question_uri", "revocation", "flows", "expires_at", "signer", "alg", "pq_pk", "sig",
    "pq_sig",
];

/// Revocation-epoch signature domain (revocation.ts `REVEPOCH_DOMAIN`).
pub const REVEPOCH_DOMAIN: &[u8] = b"atlas-pca/revepoch/v1\0";
const REVSET_DOMAIN: &[u8] = b"pca-revset/v1\0";
/// The future skew `checkRevocationEpoch` tolerates on `issued_at`.
pub const REVOCATION_EPOCH_SKEW_MS: f64 = 60_000.0;

/// The closed signature-suite registry (pq.ts `SIG_SUITES` keys).
const SIG_ALGS: [&str; 14] = [
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

// ---- JS-semantics helpers --------------------------------------------------------------------------------------------

fn obj(v: Option<&Value>) -> Option<&Map<String, Value>> {
    match v {
        Some(Value::Object(m)) => Some(m),
        _ => None,
    }
}

/// `v?.[k]` for an own data property of a JSON object (primitives / arrays / null / undefined -> undefined).
fn get<'a>(v: Option<&'a Value>, k: &str) -> Option<&'a Value> {
    obj(v).and_then(|m| m.get(k))
}

/// JS truthiness of a (possibly undefined) JSON value.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0 && !f.is_nan()).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// `a === b` for JSON values (undefined both sides is equal; objects / arrays are distinct references).
fn js_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::Null), Some(Value::Null)) => true,
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x == y,
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        (Some(Value::Number(x)), Some(Value::Number(y))) => match (x.as_f64(), y.as_f64()) {
            (Some(p), Some(q)) => p == q,
            _ => false,
        },
        _ => false,
    }
}

fn js_num_eq(a: Option<&Value>, n: f64) -> bool {
    matches!(a, Some(Value::Number(x)) if x.as_f64() == Some(n))
}

fn str_of(v: Option<&Value>) -> Option<&str> {
    v.and_then(|x| x.as_str())
}

/// `Number.isInteger(v)`.
fn js_is_integer(v: Option<&Value>) -> Option<f64> {
    let f = match v {
        Some(Value::Number(n)) => n.as_f64()?,
        _ => return None,
    };
    (f.is_finite() && f.fract() == 0.0).then_some(f)
}

fn number_to_string(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        if i.unsigned_abs() <= MAX_SAFE_INT as u64 {
            return i.to_string();
        }
    }
    if let Some(u) = n.as_u64() {
        if u <= MAX_SAFE_INT as u64 {
            return u.to_string();
        }
    }
    js_number_to_string(n.as_f64().unwrap_or(f64::NAN))
}

/// ECMAScript ToString (template literals): undefined -> "undefined" (`undef` lets TextEncoder's "" be chosen).
fn js_to_string_with(v: Option<&Value>, undef: &str, depth: usize) -> String {
    match v {
        None => undef.to_string(),
        Some(Value::Null) => "null".to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Number(n)) => number_to_string(n),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(_)) => "[object Object]".to_string(),
        Some(Value::Array(a)) => {
            if depth > 64 {
                return String::new();
            }
            // Array.prototype.join: null / undefined elements become "".
            a.iter()
                .map(|x| match x {
                    Value::Null => String::new(),
                    other => js_to_string_with(Some(other), "", depth + 1),
                })
                .collect::<Vec<_>>()
                .join(",")
        }
    }
}

fn js_to_string(v: Option<&Value>) -> String {
    js_to_string_with(v, "undefined", 0)
}

/// Canonical base64url (no padding) of any decoded length: `@scure/base` `base64urlnopad.decode` + the round trip of
/// hash.ts `decodeB64uStrict` without a length.
fn decode_b64u_any(s: &str) -> Option<Vec<u8>> {
    if s.len() % 4 == 1 || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return None;
    }
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let bytes = URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()?;
    (b64u(&bytes) == s).then_some(bytes)
}

fn b32(v: Option<&Value>) -> bool {
    match v {
        Some(Value::String(s)) => crate::chain::decode_b64u_strict(s, 32).is_some(),
        _ => false,
    }
}

fn b64u_any_ok(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(s)) if decode_b64u_any(s).is_some())
}

/// pq.ts `resolveSigAlg`: absent -> ed25519; a registered name -> itself; anything else -> None.
fn resolve_sig_alg(v: Option<&Value>) -> Option<&'static str> {
    match v {
        None => Some("ed25519"),
        Some(Value::String(s)) => SIG_ALGS.iter().copied().find(|a| *a == s),
        _ => None,
    }
}

/// Names the predicate DSL cannot address (intent-strict.ts `RESERVED_NAMES`): refused as accumulator / monitor ids.
pub const RESERVED_NAMES: [&str; 3] = ["__proto__", "constructor", "prototype"];

/// intent-strict.ts `suiteCapabilityError(alg, implemented)` with the GUEST's implemented set ([`crate::pq_suites`]): absent =
/// ed25519 (None); a non-string is malformed; a string the guest does not implement is `unsupported_suite: '<alg>'`.
pub fn suite_capability_error(alg: Option<&Value>) -> Option<String> {
    match alg {
        None => None,
        Some(Value::String(a)) if crate::pq_suites::suite_supported(Some(a)) => None,
        Some(Value::String(a)) => Some(format!("unsupported_suite: '{a}'")),
        Some(_) => Some("alg must be a string".into()),
    }
}

fn is_word(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// `^[A-Za-z0-9_]{1,64}$`
fn acc_id_ok(s: &str) -> bool {
    is_word(s, 1, 64)
}

/// `^action\.params\.[A-Za-z0-9_]{1,64}$`
fn param_path_ok(s: &str) -> bool {
    s.strip_prefix("action.params.").map(|n| is_word(n, 1, 64)).unwrap_or(false)
}

/// `^[a-z0-9_]+(?:\.[a-z0-9_]+)*$`
fn unit_ok(s: &str) -> bool {
    !s.is_empty() && s.split('.').all(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
}

fn key_set_is(m: &Map<String, Value>, want: &[&str]) -> bool {
    m.len() == want.len() && want.iter().all(|k| m.contains_key(*k))
}

fn first_unknown<'a>(m: &'a Map<String, Value>, allowed: &[&str]) -> Option<&'a str> {
    m.keys().map(|k| k.as_str()).find(|k| !allowed.contains(k))
}

// ---- the PCActn member `intent_session` (wire) -----------------------------------------------------------------------

fn digest_list(v: &Value, name: &str, max: usize) -> Result<(), String> {
    let a = match v.as_array() {
        Some(a) if a.len() <= max => a,
        _ => return Err(format!("'intent_session.{name}' must be an array of at most {max} digests")),
    };
    for x in a {
        if !b32(Some(x)) {
            return Err(format!("'intent_session.{name}' entries must be canonical base64url (32 bytes)"));
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for x in a {
        if !seen.insert(x.as_str().unwrap_or_default()) {
            return Err(format!("'intent_session.{name}' entries must be distinct"));
        }
    }
    Ok(())
}

/// intent-session.ts `validateIntentSessionWire` (Ok = well-formed). The first unknown member reported is the first in
/// UTF-8 order (TS: insertion order); verdicts are identical.
pub fn validate_intent_session_wire(v: &Value) -> Result<(), String> {
    let o = match v {
        Value::Object(m) => m,
        _ => return Err("'intent_session' must be an object".into()),
    };
    if let Some(k) = first_unknown(o, &INTENT_SESSION_FIELDS) {
        return Err(format!("unknown field 'intent_session.{k}'"));
    }
    for k in ["session", "root", "seq", "schema"] {
        if !o.contains_key(k) {
            return Err(format!("missing field 'intent_session.{k}'"));
        }
    }
    for k in ["session", "root", "schema"] {
        if !b32(o.get(k)) {
            return Err(format!("'intent_session.{k}' is not canonical base64url (32 bytes)"));
        }
    }
    match o.get("seq").and_then(non_neg) {
        Some(s) if s <= MAX_SESSION_SEQ => {}
        _ => return Err("'intent_session.seq' must be a safe integer in [0, 2147483647]".into()),
    }
    if let Some(acc) = o.get("acc") {
        let arr = match acc.as_array() {
            Some(a) if a.len() <= MAX_IS_ACC => a,
            _ => return Err(format!("'intent_session.acc' must be an array of at most {MAX_IS_ACC} entries")),
        };
        let mut ids = std::collections::BTreeSet::new();
        for (i, a) in arr.iter().enumerate() {
            let am = match a {
                Value::Object(m) => m,
                _ => return Err(format!("'intent_session.acc[{i}]' must be an object")),
            };
            if let Some(k) = first_unknown(am, &["id", "post", "receipt"]) {
                return Err(format!("unknown field 'intent_session.acc[{i}].{k}'"));
            }
            let id = match am.get("id") {
                Some(Value::String(s)) if acc_id_ok(s) => s.as_str(),
                _ => return Err(format!("'intent_session.acc[{i}].id' must match [A-Za-z0-9_]{{1,64}}")),
            };
            if !ids.insert(id) {
                return Err("'intent_session.acc' ids must be distinct".into());
            }
            if am.get("post").and_then(non_neg).is_none() {
                return Err(format!("'intent_session.acc[{i}].post' must be a non-negative safe integer"));
            }
            if am.contains_key("receipt") && !b32(am.get("receipt")) {
                return Err(format!("'intent_session.acc[{i}].receipt' is not canonical base64url (32 bytes)"));
            }
        }
    }
    if let Some(f) = o.get("facts") {
        digest_list(f, "facts", MAX_IS_FACTS)?;
    }
    if o.contains_key("offer_set") && !b32(o.get("offer_set")) {
        return Err("'intent_session.offer_set' is not canonical base64url (32 bytes)".into());
    }
    if let Some(p) = o.get("prov") {
        let pm = match p {
            Value::Object(m) if m.len() <= MAX_IS_PROV_PATHS => m,
            _ => return Err(format!("'intent_session.prov' must be an object of at most {MAX_IS_PROV_PATHS} entries")),
        };
        for (path, refs) in pm {
            if !param_path_ok(path) {
                return Err(format!("'intent_session.prov' key '{path}' is not action.params.<name>"));
            }
            let ok = match refs.as_array() {
                Some(a) => {
                    !a.is_empty() && a.len() <= MAX_IS_PROV_REFS && a.iter().all(|r| matches!(r, Value::String(s) if !s.is_empty() && s.len() <= MAX_IS_STRING_BYTES))
                }
                None => false,
            };
            if !ok {
                return Err(format!("'intent_session.prov.{path}' must be 1..{MAX_IS_PROV_REFS} non-empty strings of at most {MAX_IS_STRING_BYTES} UTF-8 bytes"));
            }
        }
    }
    if let Some(c) = o.get("classes") {
        digest_list(c, "classes", MAX_IS_CLASSES)?;
    }
    if let Some(l) = o.get("labels") {
        digest_list(l, "labels", MAX_IS_LABELS)?;
    }
    if o.contains_key("map_form") && !matches!(o.get("map_form"), Some(Value::String(f)) if f == "commit") {
        return Err("'intent_session.map_form' must be \"commit\" when present".into());
    }
    Ok(())
}

// ---- the grant caveat --------------------------------------------------------------------------------------------------

/// intent-session.ts `grantSessionCaveat`: the FIRST caveat of `grant` that is an object with `type == "intent_session"`.
pub fn grant_session_caveat(grant: &Value) -> Option<&Value> {
    get(Some(grant), "caveats")?.as_array()?.iter().find(|c| matches!(get(Some(c), "type"), Some(Value::String(t)) if t == INTENT_SESSION_CAVEAT))
}

/// intent-session-caveat.ts `intentSessionCaveatError` (None = well-formed).
pub fn intent_session_caveat_error(c: Option<&Value>) -> Option<String> {
    let m = match obj(c) {
        Some(m) if matches!(m.get("type"), Some(Value::String(t)) if t == INTENT_SESSION_CAVEAT) => m,
        _ => return Some("not an intent_session caveat".into()),
    };
    if let Some(k) = first_unknown(m, &["type", "session", "seq", "root", "prev"]) {
        return Some(format!("intent_session caveat: unknown member '{k}'"));
    }
    if !b32(m.get("session")) || !b32(m.get("root")) {
        return Some("intent_session caveat: session and root must be canonical base64url (32 bytes)".into());
    }
    let seq = match m.get("seq").and_then(non_neg) {
        Some(s) if s <= MAX_SESSION_SEQ => s,
        _ => return Some("intent_session caveat: seq must be a safe integer in [0, 2147483647]".into()),
    };
    if (seq == 0) != !m.contains_key("prev") {
        return Some("intent_session caveat: prev is present exactly when seq > 0".into());
    }
    if m.contains_key("prev") && !b32(m.get("prev")) {
        return Some("intent_session caveat: prev must be canonical base64url (32 bytes)".into());
    }
    None
}

// ---- accumulator / monitor declarations (intent-acc.ts, used by the session-root shape) -------------------------------

fn is_int(v: Option<&Value>) -> Option<i64> {
    v.and_then(safe_int)
}

/// intent-acc.ts `accumulatorDeclError` (None = well-formed).
pub fn accumulator_decl_error(a: &Value) -> Option<String> {
    let m = match a {
        Value::Object(m) => m,
        _ => return Some("accumulator must be an object".into()),
    };
    if let Some(k) = first_unknown(m, &["id", "agg", "val", "unit", "sel", "win", "key", "domain_max", "cap", "holder"]) {
        return Some(format!("accumulator: unknown member '{k}'"));
    }
    let id = match m.get("id") {
        Some(Value::String(s)) if acc_id_ok(s) && !RESERVED_NAMES.contains(&s.as_str()) => s,
        _ => return Some("accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype".into()),
    };
    let at = format!("accumulator '{id}'");
    let agg = match m.get("agg") {
        Some(Value::String(s)) if ["sum", "count", "distinct", "max"].contains(&s.as_str()) => s.as_str(),
        _ => return Some(format!("{at}: unknown agg")),
    };
    if let Some(v) = m.get("val") {
        if !matches!(v, Value::String(s) if param_path_ok(s)) {
            return Some(format!("{at}: val must be action.params.<name>"));
        }
    }
    if let Some(u) = m.get("unit") {
        if !matches!(u, Value::String(s) if s.encode_utf16().count() <= 64 && unit_ok(s)) {
            return Some(format!("{at}: unit must be a unit id"));
        }
    }
    let sel = match m.get("sel") {
        Some(Value::Object(s)) => s,
        _ => return Some(format!("{at}: sel must be an object")),
    };
    if let Some(k) = first_unknown(sel, &["verbs", "accumulates_into", "event"]) {
        return Some(format!("{at}: sel has unknown member '{k}'"));
    }
    if let Some(vs) = sel.get("verbs") {
        let ok = matches!(vs, Value::Array(a) if !a.is_empty() && a.len() <= 64 && a.iter().all(|v| matches!(v, Value::String(s) if !s.is_empty())));
        if !ok {
            return Some(format!("{at}: sel.verbs must be 1..64 verb names"));
        }
    }
    if let Some(ai) = sel.get("accumulates_into") {
        if !matches!(ai, Value::String(s) if unit_ok(s)) {
            return Some(format!("{at}: sel.accumulates_into must be a unit id"));
        }
    }
    if let Some(ev) = sel.get("event") {
        if !matches!(ev, Value::String(s) if ["intent_required", "question", "clarification"].contains(&s.as_str())) {
            return Some(format!("{at}: unknown sel.event"));
        }
    }
    let action_sel = sel.contains_key("verbs") || sel.contains_key("accumulates_into");
    let has_event = sel.contains_key("event");
    if action_sel == has_event {
        return Some(format!("{at}: sel names actions (verbs / accumulates_into) or a wallet event, exactly one kind"));
    }
    let w = match m.get("win") {
        Some(Value::Object(w)) => w,
        _ => return Some(format!("{at}: win must be an object")),
    };
    match w.get("kind").and_then(|k| k.as_str()) {
        Some("task") => {
            if w.len() != 1 {
                return Some(format!("{at}: win {{kind: task}} has no other member"));
            }
        }
        Some("sliding") => {
            if !key_set_is(w, &["kind", "ms"]) || !is_int(w.get("ms")).map(|x| x > 0).unwrap_or(false) {
                return Some(format!("{at}: win sliding needs a positive ms"));
            }
        }
        Some("period") => {
            if !key_set_is(w, &["kind", "ms", "t0"]) || !is_int(w.get("ms")).map(|x| x > 0).unwrap_or(false) || w.get("t0").and_then(non_neg).is_none() {
                return Some(format!("{at}: win period needs a positive ms and t0 >= 0"));
            }
        }
        _ => return Some(format!("{at}: unknown win kind")),
    }
    match m.get("key") {
        Some(Value::Null) => {}
        Some(Value::String(s)) if param_path_ok(s) => {}
        _ => return Some(format!("{at}: key must be null or action.params.<name>")),
    }
    if m.contains_key("domain_max") && m.get("domain_max").and_then(non_neg).is_none() {
        return Some(format!("{at}: domain_max must be a non-negative safe integer"));
    }
    if m.contains_key("cap") && m.get("cap").and_then(non_neg).is_none() {
        return Some(format!("{at}: cap must be a non-negative safe integer"));
    }
    let h = match m.get("holder") {
        Some(Value::Object(h)) => h,
        _ => return Some(format!("{at}: holder must be an object")),
    };
    let hk = h.get("kind").and_then(|k| k.as_str());
    match hk {
        Some(k @ ("site_local" | "wallet")) => {
            if h.len() != 1 {
                return Some(format!("{at}: holder {k} has no other member"));
            }
        }
        Some("sequenced") => {
            if let Some(k) = first_unknown(h, &["kind", "uri", "root", "root_alg", "root_pq_pk", "keys_uri"]) {
                return Some(format!("{at}: holder sequenced has unknown member '{k}'"));
            }
            if !matches!(h.get("uri"), Some(Value::String(s)) if !s.is_empty()) {
                return Some(format!("{at}: holder sequenced needs a uri"));
            }
            if !b32(h.get("root")) {
                return Some(format!("{at}: holder.root is not canonical base64url (32 bytes)"));
            }
            if let Some(e) = suite_capability_error(h.get("root_alg")) {
                return Some(format!("{at}: holder.root_alg: {e}"));
            }
            if h.contains_key("root_pq_pk") && !b64u_any_ok(h.get("root_pq_pk")) {
                return Some(format!("{at}: holder.root_pq_pk is not canonical base64url"));
            }
            if h.contains_key("keys_uri") && !matches!(h.get("keys_uri"), Some(Value::String(s)) if !s.is_empty()) {
                return Some(format!("{at}: holder.keys_uri must be a non-empty string"));
            }
        }
        _ => return Some(format!("{at}: unknown holder kind")),
    }
    let wallet = hk == Some("wallet");
    if wallet != has_event {
        return Some(format!("{at}: wallet events are wallet-held and only wallet events are"));
    }
    if !wallet {
        let has_val = m.contains_key("val");
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

fn predicate_shape_ok(p: Option<&Value>) -> bool {
    match obj(p).and_then(|m| m.get("verb")) {
        Some(Value::String(_)) => true,
        Some(Value::Array(a)) => !a.is_empty() && a.iter().all(|x| x.is_string()),
        _ => false,
    }
}

/// intent-acc.ts `monitorDeclError` (None = well-formed).
pub fn monitor_decl_error(mv: &Value) -> Option<String> {
    let m = match mv {
        Value::Object(m) => m,
        _ => return Some("monitor must be an object".into()),
    };
    if let Some(k) = first_unknown(m, &["id", "kind", "p", "q", "status", "within"]) {
        return Some(format!("monitor: unknown member '{k}'"));
    }
    let id = match m.get("id") {
        Some(Value::String(s)) if acc_id_ok(s) && !RESERVED_NAMES.contains(&s.as_str()) => s,
        _ => return Some("monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype".into()),
    };
    let at = format!("monitor '{id}'");
    let kind = match m.get("kind") {
        Some(Value::String(s)) if ["requires_prior", "precedes", "never", "always", "responds_within"].contains(&s.as_str()) => s.as_str(),
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
    if let Some(s) = m.get("status") {
        if !matches!(s, Value::String(x) if x == "admitted" || x == "committed") {
            return Some(format!("{at}: status must be admitted or committed"));
        }
    }
    if (kind == "responds_within") != m.contains_key("within") {
        return Some(format!("{at}: within is required exactly for responds_within"));
    }
    if m.contains_key("within") && !is_int(m.get("within")).map(|w| (1..=MAX_MONITOR_WITHIN).contains(&w)).unwrap_or(false) {
        return Some(format!("{at}: within must be an integer in 1..{MAX_MONITOR_WITHIN}"));
    }
    None
}

// ---- the session root S ----------------------------------------------------------------------------------------------

/// `sessionRootBody(S)`: the signed body (without signer / suite fields / signatures). `revocation` / `flows` only when
/// present. Callers have checked the shape (every required member is present).
fn session_root_body(s: &Map<String, Value>) -> Map<String, Value> {
    let mut b = Map::new();
    for k in ["v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors", "question_uri", "revocation", "flows", "expires_at"] {
        if let Some(v) = s.get(k) {
            b.insert(k.to_string(), v.clone());
        }
    }
    b
}

/// intent-session.ts `sessionRootShapeError(s, { signed: true })` (None = well-formed).
pub fn session_root_shape_error(sv: &Value) -> Option<String> {
    session_root_shape_error_opt(sv, true)
}

/// `sessionRootShapeError(s, { signed })`.
pub fn session_root_shape_error_opt(sv: &Value, signed: bool) -> Option<String> {
    let s = match sv {
        Value::Object(m) => m,
        _ => return Some("session root is not an object".into()),
    };
    if let Some(k) = first_unknown(s, &ROOT_KEYS) {
        return Some(format!("session root: unknown member '{k}'"));
    }
    if !js_num_eq(s.get("v"), 1.0) || !matches!(s.get("kind"), Some(Value::String(k)) if k == INTENT_SESSION_KIND) {
        return Some("not a pca-intent-session v1".into());
    }
    if !b32(s.get("session")) || !b32(s.get("intent_ref")) {
        return Some("session and intent_ref must be canonical base64url (32 bytes)".into());
    }
    let principals = match s.get("principals") {
        Some(Value::Array(a)) if !a.is_empty() && a.len() <= MAX_SESSION_PRINCIPALS => a,
        _ => return Some(format!("principals must be 1..{MAX_SESSION_PRINCIPALS} keys")),
    };
    let mut keys: Vec<&str> = Vec::new();
    for p in principals {
        let pm = match p {
            Value::Object(m) if first_unknown(m, &["key", "alg", "pq_pk"]).is_none() && b32(m.get("key")) => m,
            _ => return Some("principals entries are {key, alg?, pq_pk?} with a 32-byte key".into()),
        };
        if let Some(e) = suite_capability_error(pm.get("alg")) {
            return Some(format!("principal alg: {e}"));
        }
        if pm.contains_key("pq_pk") && !b64u_any_ok(pm.get("pq_pk")) {
            return Some("principal pq_pk is not canonical base64url".into());
        }
        let k = str_of(pm.get("key")).unwrap_or_default();
        if keys.contains(&k) {
            return Some("principal keys must be distinct".into());
        }
        keys.push(k);
    }
    let schema_ok = match s.get("schema") {
        Some(Value::Object(m)) => key_set_is(m, &["aud", "digest"]) && matches!(m.get("aud"), Some(Value::String(a)) if !a.is_empty()) && b32(m.get("digest")),
        _ => false,
    };
    if !schema_ok {
        return Some("schema must be {aud, digest}".into());
    }
    let l = match s.get("layers") {
        Some(Value::Object(m)) => m,
        _ => return Some("layers must be an object".into()),
    };
    if let Some(k) = first_unknown(l, &["org", "std", "task"]) {
        return Some(format!("layers: unknown member '{k}'"));
    }
    let task_ok = match l.get("task") {
        Some(Value::Object(t)) => t.len() == 1 && t.contains_key("map_digest") && b32(t.get("map_digest")),
        _ => false,
    };
    if !task_ok {
        return Some("layers.task must be {map_digest}".into());
    }
    // absent = no such layer; null is malformed (README "absent vs null")
    match l.get("org") {
        None => {}
        Some(Value::Object(o)) if b32(o.get("digest")) => {}
        Some(_) => return Some("layers.org must be an object with a 32-byte digest (absent = no org layer; null is malformed)".into()),
    }
    match l.get("std") {
        None => {}
        Some(d) => {
            let ok = match d {
                Value::Object(m) => {
                    key_set_is(m, &["digest", "profile", "version"])
                        && matches!(m.get("profile"), Some(Value::String(p)) if !p.is_empty() && p.len() <= 128)
                        && is_int(m.get("version")).map(|v| v >= 1).unwrap_or(false)
                        && b32(m.get("digest"))
                }
                _ => false,
            };
            if !ok {
                return Some("layers.std must be {profile, version >= 1, digest} (absent = no standing profile; null is malformed)".into());
            }
        }
    }
    let accs = match s.get("accumulators") {
        Some(Value::Array(a)) if a.len() <= MAX_SESSION_ACCUMULATORS => a,
        _ => return Some(format!("accumulators must be an array of at most {MAX_SESSION_ACCUMULATORS}")),
    };
    let mut ids: Vec<&str> = Vec::new();
    for a in accs {
        if let Some(e) = accumulator_decl_error(a) {
            return Some(e);
        }
        let id = str_of(get(Some(a), "id")).unwrap_or_default();
        if ids.contains(&id) {
            return Some("accumulator and monitor ids must be distinct".into());
        }
        ids.push(id);
    }
    let mons = match s.get("monitors") {
        Some(Value::Array(a)) if a.len() <= MAX_SESSION_MONITORS => a,
        _ => return Some(format!("monitors must be an array of at most {MAX_SESSION_MONITORS}")),
    };
    let mut mids: Vec<&str> = Vec::new();
    for m in mons {
        if let Some(e) = monitor_decl_error(m) {
            return Some(e);
        }
        let id = str_of(get(Some(m), "id")).unwrap_or_default();
        if mids.contains(&id) {
            return Some("monitor ids must be distinct".into());
        }
        mids.push(id);
    }
    if !matches!(s.get("question_uri"), Some(Value::String(q)) if !q.is_empty() && q.len() <= 2048) {
        return Some("question_uri must be a non-empty string".into());
    }
    if let Some(r) = s.get("revocation") {
        let rm = match r {
            Value::Object(m) if first_unknown(m, &["epoch_uri", "max_age_s", "key", "pq_pk"]).is_none() => m,
            _ => return Some("revocation must be {epoch_uri, max_age_s, key, pq_pk?}".into()),
        };
        if !matches!(rm.get("epoch_uri"), Some(Value::String(e)) if !e.is_empty()) {
            return Some("revocation.epoch_uri must be a non-empty string".into());
        }
        if rm.get("max_age_s").and_then(non_neg).is_none() {
            return Some("revocation.max_age_s must be a non-negative safe integer".into());
        }
        if !b32(rm.get("key")) {
            return Some("revocation.key (the dedicated revocation authority) is required: canonical base64url (32 bytes)".into());
        }
        if keys.contains(&str_of(rm.get("key")).unwrap_or_default()) {
            return Some("revocation.key must not be a session principal (a dedicated revocation authority)".into());
        }
        if rm.contains_key("pq_pk") && !b64u_any_ok(rm.get("pq_pk")) {
            return Some("revocation.pq_pk must be canonical base64url".into());
        }
    }
    if s.contains_key("flows") && !matches!(s.get("flows"), Some(Value::Object(_))) {
        return Some("flows must be an object".into());
    }
    if s.get("expires_at").and_then(non_neg).is_none() {
        return Some("expires_at must be a non-negative safe integer (epoch ms)".into());
    }
    if signed {
        if !b32(s.get("signer")) {
            return Some("signer must be canonical base64url (32 bytes)".into());
        }
        if !keys.contains(&str_of(s.get("signer")).unwrap_or_default()) {
            return Some("signer is not one of the session principals".into());
        }
        if let Some(e) = suite_capability_error(s.get("alg")) {
            return Some(format!("alg: {e}"));
        }
        let suite = resolve_sig_alg(s.get("alg")).unwrap_or("ed25519");
        if suite == "ed25519" && (s.contains_key("pq_pk") || s.contains_key("pq_sig")) {
            return Some("an ed25519 session root must not carry pq_pk / pq_sig".into());
        }
        if !matches!(s.get("sig"), Some(Value::String(_))) {
            return Some("sig must be a string".into());
        }
    }
    if let Some(e) = strict_violation(&Value::Object(session_root_body(s))) {
        return Some(format!("malformed session root: canonicalize: {e}"));
    }
    None
}

/// intent-session.ts `verifySessionRoot(S)` with NO verifier pins: an Ed25519 root verifies as before; a pure-PQ / hybrid
/// root fails closed (see [`verify_session_root_pinned`]).
pub fn verify_session_root(sv: &Value) -> Result<(), String> {
    verify_session_root_pinned(sv, None)
}

/// intent-session.ts `verifySessionRoot(S, {pqPins})`: shape, signer listed, suite signature over
/// `"atlas-pca/intent-session/v1\0" || strictCanonical(body + signer + bound suite fields)`. R3-01 (fail closed, guest
/// version 9): a non-ed25519 root verifies only under the VERIFIER's pin for its signer (`pq_pins` = the context's
/// `session.pq_pins`, an object whose own member for the signer is a string), never under the root's own
/// `principals[].pq_pk` (part of the presented artifact: a pure-PQ signature uses no Ed25519 secret). In order: no pin, a
/// pin other than `S.pq_pk`, a signer principals entry declaring another `pq_pk`, then the suite signature. An Ed25519 root
/// never consults the pins. A suite the guest lacks never reaches this point (the shape check refuses it).
pub fn verify_session_root_pinned(sv: &Value, pq_pins: Option<&Value>) -> Result<(), String> {
    if let Some(e) = session_root_shape_error(sv) {
        return Err(e);
    }
    let s = match sv {
        Value::Object(m) => m,
        _ => return Err("session root is not an object".into()),
    };
    let alg = resolve_sig_alg(s.get("alg"));
    let signer = str_of(s.get("signer")).unwrap_or_default();
    let pin = if crate::pq_suites::suite_needs_pq_pk(alg) {
        let pinned = pq_pins.and_then(Value::as_object).and_then(|m| m.get(signer)).filter(|v| v.is_string());
        let Some(pv) = pinned else {
            return Err(format!(
                "session root suite '{}' needs the signer's PQ key pinned by the verifier (pq_pins); the root's own principals entry proves nothing about who signed it",
                alg.unwrap_or_default()
            ));
        };
        if s.get("pq_pk") != Some(pv) {
            return Err("session root pq_pk does not match the verifier's pin for the signer".into());
        }
        let entry = s
            .get("principals")
            .and_then(Value::as_array)
            .and_then(|ps| ps.iter().find(|p| p.get("key").and_then(Value::as_str) == Some(signer)));
        if entry.and_then(|p| p.get("pq_pk")).is_some_and(|e| Some(e) != s.get("pq_pk")) {
            return Err("session root pq_pk does not match the signer's principals entry".into());
        }
        pv.as_str()
    } else {
        None
    };
    // rootMessage(bindSuiteFields({...body, signer}, alg, pq_pk)): a non-ed25519 suite binds `alg` and `pq_pk`.
    let mut body = session_root_body(s);
    body.insert("signer".into(), Value::String(signer.to_string()));
    if let Some(a) = alg.filter(|a| *a != "ed25519") {
        body.insert("alg".into(), Value::String(a.to_string()));
        // bindSuiteFields copies `pq_pk` as is: an absent one is `undefined`, which the strict canonicalizer refuses (TS throw)
        match s.get("pq_pk") {
            Some(v) => {
                body.insert("pq_pk".into(), v.clone());
            }
            None => return Err("malformed session root: canonicalize: unsupported type undefined".into()),
        }
    }
    let body = Value::Object(body);
    if let Some(e) = strict_violation(&body) {
        return Err(format!("malformed session root: canonicalize: {e}"));
    }
    let mut msg = INTENT_SESSION_SIG_DOMAIN.as_bytes().to_vec();
    msg.extend_from_slice(&canonical_bytes(&body));
    let r = crate::pq_suites::verify_pinned_suite(
        alg,
        signer,
        str_of(s.get("pq_pk")),
        &msg,
        str_of(s.get("sig")),
        str_of(s.get("pq_sig")),
        pin,
    );
    match r {
        Ok(()) => Ok(()),
        Err(crate::pq_suites::SuiteError::Unsupported(a)) => Err(format!("session root signature invalid (unsupported_suite: {a})")),
        Err(_) => Err("session root signature invalid".into()),
    }
}

fn digest_wrapper(s: &Value) -> Value {
    let mut w = Map::new();
    w.insert("d".into(), Value::String(INTENT_SESSION_REF_DOMAIN.into()));
    w.insert("s".into(), s.clone());
    Value::Object(w)
}

/// intent-session.ts `sessionRootDigest`: `hashCanonical({d: "atlas-pca/intent-session-ref/v1", s: S})`. None when the
/// strict canonical form would throw (e.g. S nested 32 deep: the wrapper adds a level).
pub fn session_root_digest(s: &Value) -> Option<String> {
    let w = digest_wrapper(s);
    if strict_violation(&w).is_some() {
        return None;
    }
    Some(hash_canonical(&w))
}

// ---- revocation ids --------------------------------------------------------------------------------------------------

pub fn session_revocation_id(session: &str) -> String {
    format!("pca-intent:session:{session}")
}
pub fn map_revocation_id(map_digest: &str) -> String {
    format!("pca-intent:map:{map_digest}")
}
pub fn delta_revocation_id(grant_id: &str) -> String {
    format!("pca-intent:delta:{grant_id}")
}
pub fn profile_revocation_id(profile: &str, version: i64) -> String {
    format!("pca-intent:profile:{profile}@{version}")
}
/// The `grant_ref` of a session revocation epoch.
pub fn session_revocation_scope(session: &str) -> String {
    format!("pca-intent-session:{session}")
}

// ---- the sorted Merkle revocation set (revocation.ts) ---------------------------------------------------------------

fn node_hash(l: &[u8], r: &[u8]) -> [u8; 32] {
    let mut m = Vec::with_capacity(1 + l.len() + r.len());
    m.push(0x01);
    m.extend_from_slice(l);
    m.extend_from_slice(r);
    sha256(&m)
}

fn bind_root(size: u64, tree: &str) -> String {
    let mut o = Map::new();
    o.insert("size".into(), Value::from(size));
    o.insert("tree".into(), Value::String(tree.into()));
    let mut m = REVSET_DOMAIN.to_vec();
    m.extend_from_slice(&canonical_bytes(&Value::Object(o)));
    b64u(&sha256(&m))
}

fn split(n: u64) -> u64 {
    let mut k = 1u64;
    while k.saturating_mul(2) < n {
        k *= 2;
    }
    k
}

/// Sibling sides (leaf-to-root) of `index` in a tree of `size` leaves (`true` = 'L').
fn expected_sides(index: u64, size: u64, out: &mut Vec<bool>) {
    if size <= 1 {
        return;
    }
    let k = split(size);
    if index < k {
        expected_sides(index, k, out);
        out.push(false);
    } else {
        expected_sides(index - k, size - k, out);
        out.push(true);
    }
}

/// revocation.ts `leafOk`.
fn leaf_ok(root: Option<&Value>, size: u64, id: Option<&Value>, proof: Option<&Value>) -> bool {
    if !truthy(proof) || !js_num_eq(get(proof, "size"), size as f64) {
        return false;
    }
    let index = match js_is_integer(get(proof, "index")) {
        Some(i) if i >= 0.0 && i < size as f64 => i as u64,
        _ => return false,
    };
    let mut sides = Vec::new();
    expected_sides(index, size, &mut sides);
    let path = match get(proof, "path") {
        Some(Value::Array(p)) if p.len() == sides.len() => p,
        _ => return false,
    };
    let id = match id {
        Some(v) if strict_violation(v).is_none() => v,
        _ => return false,
    };
    let mut leaf = vec![0x00u8];
    leaf.extend_from_slice(&canonical_bytes(id));
    let mut h = sha256(&leaf);
    for (step, left) in path.iter().zip(sides.iter()) {
        if step.is_null() {
            return false;
        }
        let want = if *left { "L" } else { "R" };
        if str_of(get(Some(step), "side")) != Some(want) {
            return false;
        }
        let sib = match get(Some(step), "hash") {
            Some(Value::String(s)) => match decode_b64u_any(s) {
                Some(b) => b,
                None => return false,
            },
            _ => return false,
        };
        h = if *left { node_hash(&sib, &h) } else { node_hash(&h, &sib) };
    }
    matches!(root, Some(Value::String(r)) if *r == bind_root(size, &b64u(&h)))
}

/// `compareUtf8(String(a), id) < 0` with TextEncoder's coercion (undefined -> "").
fn utf8_less(a: Option<&Value>, b: &str) -> bool {
    js_to_string_with(a, "", 0).as_bytes() < b.as_bytes()
}

/// revocation.ts `verifyNonMembership(root, proof, id)`. A `size` above 2^53-1 is refused (the session step only reaches
/// here with `size === epoch.set_size`, a safe integer).
pub fn verify_non_membership(root: Option<&Value>, proof: Option<&Value>, id: &str) -> bool {
    if !truthy(proof) {
        return false;
    }
    let size = match js_is_integer(get(proof, "size")) {
        Some(s) if s >= 0.0 && s <= MAX_SAFE_INT as f64 => s as u64,
        _ => return false,
    };
    let lo = get(proof, "lo").filter(|v| truthy(Some(v)));
    let hi = get(proof, "hi").filter(|v| truthy(Some(v)));
    if size == 0 {
        let empty = b64u(&sha256(&[]));
        return lo.is_none() && hi.is_none() && matches!(root, Some(Value::String(r)) if *r == bind_root(0, &empty));
    }
    if lo.is_none() && hi.is_none() {
        return false;
    }
    let index_of = |leaf: &Value| js_is_integer(get(get(Some(leaf), "proof"), "index"));
    if let Some(l) = lo {
        if !utf8_less(get(Some(l), "id"), id) || !leaf_ok(root, size, get(Some(l), "id"), get(Some(l), "proof")) {
            return false;
        }
        if hi.is_none() && index_of(l) != Some((size - 1) as f64) {
            return false;
        }
    }
    if let Some(h) = hi {
        let hid = js_to_string_with(get(Some(h), "id"), "", 0);
        if !(id.as_bytes() < hid.as_bytes()) || !leaf_ok(root, size, get(Some(h), "id"), get(Some(h), "proof")) {
            return false;
        }
        if lo.is_none() && index_of(h) != Some(0.0) {
            return false;
        }
    }
    if let (Some(l), Some(h)) = (lo, hi) {
        match (index_of(l), index_of(h)) {
            (Some(a), Some(b)) if b == a + 1.0 => {}
            _ => return false,
        }
    }
    true
}

/// `Number.isSafeInteger(v) && !Object.is(v, -0)` (intent-strict.ts `isSafeInt`).
fn safe_int_f(v: Option<&Value>) -> Option<f64> {
    v.and_then(safe_int).map(|i| i as f64)
}
/// intent-strict.ts `isSafeNonNeg`.
fn safe_non_neg_f(v: Option<&Value>) -> Option<f64> {
    safe_int_f(v).filter(|f| *f >= 0.0)
}
fn f_is_safe_int(f: f64) -> bool {
    f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE_INT as f64 && !(f == 0.0 && f.is_sign_negative())
}

/// intent-revocation.ts `revocationEpochShapeError` (None = well-formed). `alg` is judged by the GUEST's suite capability.
pub fn revocation_epoch_shape_error(ep: Option<&Value>) -> Option<String> {
    let m = match obj(ep) {
        Some(m) => m,
        None => return Some("the revocation epoch must be an object".into()),
    };
    for k in ["instance_id", "grant_ref", "root", "guardian", "sig"] {
        if !matches!(m.get(k), Some(Value::String(_))) {
            return Some(format!("revocation epoch {k} must be a string"));
        }
    }
    for k in ["epoch", "set_size", "issued_at", "not_after"] {
        if safe_non_neg_f(m.get(k)).is_none() {
            return Some(format!("revocation epoch {k} must be a non-negative safe integer"));
        }
    }
    if m.contains_key("guardian_epoch") && safe_non_neg_f(m.get("guardian_epoch")).is_none() {
        return Some("revocation epoch guardian_epoch must be a non-negative safe integer".into());
    }
    if let Some(e) = suite_capability_error(m.get("alg")) {
        return Some(format!("revocation epoch alg: {e}"));
    }
    if m.contains_key("pq_pk") && !matches!(m.get("pq_pk"), Some(Value::String(_))) {
        return Some("revocation epoch pq_pk must be a string".into());
    }
    if m.contains_key("pq_sig") && !matches!(m.get("pq_sig"), Some(Value::String(_))) {
        return Some("revocation epoch pq_sig must be a string".into());
    }
    None
}

/// revocation.ts `RevocationSet(ids).root` for ids already sorted and distinct: `bindRoot(n, n == 0 ? sha256("") :
/// merkleRoot(ids))`, the RFC 6962-shaped tree over `sha256(0x00 || strictCanonical(id))` leaves.
pub fn revocation_set_root(ids: &[&str]) -> String {
    fn build(hs: &[[u8; 32]]) -> [u8; 32] {
        if hs.len() == 1 {
            return hs[0];
        }
        let k = split(hs.len() as u64) as usize;
        node_hash(&build(&hs[..k]), &build(&hs[k..]))
    }
    if ids.is_empty() {
        return bind_root(0, &b64u(&sha256(&[])));
    }
    let leaves: Vec<[u8; 32]> = ids
        .iter()
        .map(|id| {
            let mut m = vec![0x00u8];
            m.extend_from_slice(&canonical_bytes(&Value::String((*id).to_string())));
            sha256(&m)
        })
        .collect();
    bind_root(ids.len() as u64, &b64u(&build(&leaves)))
}

/// intent-revocation.ts `revokedListError`: `revoked` is an array of strings, strictly ascending in UTF-8 byte order,
/// `length == set_size == epoch`, and its sorted-set root is the signed `root`. `epoch` is a shape-checked epoch.
fn revoked_list_error<'a>(epoch: &Map<String, Value>, revoked: Option<&'a Value>) -> Result<Vec<&'a str>, String> {
    let r: Vec<&str> = match revoked {
        Some(Value::Array(a)) => match a.iter().map(|x| x.as_str()).collect::<Option<Vec<_>>>() {
            Some(v) => v,
            None => return Err("revoked must be an array of ids".into()),
        },
        _ => return Err("revoked must be an array of ids".into()),
    };
    if r.windows(2).any(|w| w[0].as_bytes() >= w[1].as_bytes()) {
        return Err("revoked must be sorted by UTF-8 bytes and distinct".into());
    }
    let size = safe_int_f(epoch.get("set_size"));
    if Some(r.len() as f64) != size || safe_int_f(epoch.get("epoch")) != size {
        return Err("the epoch must be numbered by its set size and list exactly set_size ids".into());
    }
    if str_of(epoch.get("root")) != Some(revocation_set_root(&r).as_str()) {
        return Err("the revoked list is not the signed set (root mismatch)".into());
    }
    Ok(r)
}

/// revocation.ts `checkRevocationEpoch(ep, {guardianPublic: ep.guardian, now, grantRef, pqPins})` on a SHAPE-CHECKED epoch
/// (no rollback pin, no PCActn epoch). A PQ suite verifies only under `pin` (= `pqPins[guardian]`) equal to the epoch's
/// own `pq_pk` (pq.ts `verifyPinnedSuite` / `resolvePqVerifyKey`).
fn check_revocation_epoch(ep: &Map<String, Value>, guardian: &str, now: f64, grant_ref: &str, pin: Option<&str>) -> Result<(), String> {
    const CHECK_ERROR: &str = "revocation epoch check error";
    let suite = match resolve_sig_alg(ep.get("alg")) {
        Some(s) if crate::pq_suites::suite_supported(Some(s)) => s,
        Some(s) => return Err(format!("unsupported_suite: '{s}'")), // unreachable: the shape step refuses it first
        None => return Err("revocation epoch not signed by the pinned guardian".into()),
    };
    // epochMessage: canonicalBytes of the 7 body fields + (for a PQ suite) the bound `alg` and `pq_pk` (undefined throws).
    let mut body = Map::new();
    for k in ["instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after"] {
        match ep.get(k) {
            Some(v) => {
                body.insert(k.into(), v.clone());
            }
            None => return Err(CHECK_ERROR.into()),
        }
    }
    if suite != "ed25519" {
        body.insert("alg".into(), Value::String(suite.into()));
        match ep.get("pq_pk") {
            Some(v) => {
                body.insert("pq_pk".into(), v.clone());
            }
            None => return Err(CHECK_ERROR.into()),
        }
    }
    let body = Value::Object(body);
    if strict_violation(&body).is_some() {
        return Err(CHECK_ERROR.into());
    }
    let mut msg = REVEPOCH_DOMAIN.to_vec();
    msg.extend_from_slice(&canonical_bytes(&body));
    let r = crate::pq_suites::verify_pinned_suite(Some(suite), guardian, str_of(ep.get("pq_pk")), &msg, str_of(ep.get("sig")), str_of(ep.get("pq_sig")), pin);
    match r {
        Ok(()) => {}
        Err(crate::pq_suites::SuiteError::Unsupported(a)) => return Err(format!("unsupported_suite: '{a}'")),
        Err(_) => return Err("revocation epoch signature invalid".into()),
    }
    if str_of(ep.get("grant_ref")) != Some(grant_ref) {
        return Err("revocation epoch is for a different grant".into());
    }
    let num = |k: &str| safe_int_f(ep.get(k)).unwrap_or(f64::NAN);
    if !(now <= num("not_after")) {
        return Err("revocation epoch expired (stale revocation root)".into());
    }
    if !(num("issued_at") <= now + REVOCATION_EPOCH_SKEW_MS) {
        return Err("revocation epoch issued in the future".into());
    }
    Ok(())
}

/// `ms` rendered like a JS template literal of a number.
fn ms_text(ms: f64) -> String {
    js_number_to_string(ms)
}

/// intent-revocation.ts `checkSessionRevocation` (steps a-g; first failure wins). `evidence` = `{epoch, revoked}` (the
/// epoch and its FULL sorted revoked list); `authority` = `S.revocation.key`, the only accepted signer.
pub fn check_session_revocation(evidence: Option<&Value>, session: &str, authority: &str, ids: &[String], now: f64, max_age_ms: f64) -> Result<(), String> {
    let i: Vec<Value> = ids.iter().map(|x| Value::String(x.clone())).collect();
    check_session_revocation_full(evidence, session, None, Some(authority), Some(&i), now, max_age_ms, None, None)
}

/// The full `checkSessionRevocation`: `ids` as a JSON list (None = not an array), `authority` (None = not a string),
/// `pq_pin` = the PQ key S pins for the authority (`S.revocation.pq_pk`), `last` = the verifier's tracked last accepted
/// evidence for the scope (append-only check; None = not tracked).
#[allow(clippy::too_many_arguments)]
pub fn check_session_revocation_full(
    evidence: Option<&Value>,
    session: &str,
    scope: Option<&str>,
    authority: Option<&str>,
    ids: Option<&[Value]>,
    now: f64,
    max_age_ms: f64,
    pq_pin: Option<&str>,
    last: Option<&Value>,
) -> Result<(), String> {
    // a.
    if !(f_is_safe_int(max_age_ms) && max_age_ms >= 0.0) {
        return Err("revocation max age misconfigured (fail closed)".into());
    }
    if !f_is_safe_int(now) {
        return Err("the verifier clock is not a safe integer (fail closed)".into());
    }
    let (authority, ids) = match (authority, ids) {
        (Some(a), Some(i)) => (a, i),
        _ => return Err("ids must be an array and the authority a key".into()),
    };
    if obj(evidence).is_none() {
        return Err("no session revocation epoch supplied".into());
    }
    // b. the evidence is CLOSED: exactly {epoch, revoked} (so is the tracked `last`)
    if let Some(k) = obj(evidence).and_then(|m| m.keys().find(|k| *k != "epoch" && *k != "revoked")) {
        return Err(format!("the revocation evidence has the unknown member '{k}' (it is exactly {{epoch, revoked}})"));
    }
    // b.
    let ep_v = get(evidence, "epoch");
    if let Some(e) = revocation_epoch_shape_error(ep_v) {
        return Err(e);
    }
    let ep = match obj(ep_v) {
        Some(m) => m,
        None => return Err("the revocation epoch must be an object".into()),
    };
    if str_of(ep.get("guardian")) != Some(authority) {
        return Err("the revocation epoch is not signed by the session revocation authority".into());
    }
    // c.
    let default_scope = session_revocation_scope(session);
    check_revocation_epoch(ep, authority, now, scope.unwrap_or(&default_scope), pq_pin)?;
    // d.
    if !(now - safe_int_f(ep.get("issued_at")).unwrap_or(f64::NAN) <= max_age_ms) {
        return Err(format!("the session revocation epoch is older than {} ms", ms_text(max_age_ms)));
    }
    // e.
    let revoked = revoked_list_error(ep, get(evidence, "revoked"))?;
    // f. append-only against the tracked last epoch
    if let Some(l) = last {
        let lep = match obj(get(Some(l), "epoch")) {
            Some(m) if obj(Some(l)).is_some_and(|lo| lo.keys().all(|k| k == "epoch" || k == "revoked")) && revocation_epoch_shape_error(get(Some(l), "epoch")).is_none() => m,
            _ => return Err("the tracked last epoch is malformed (fail closed)".into()),
        };
        let lrev = match revoked_list_error(lep, get(Some(l), "revoked")) {
            Ok(r) => r,
            Err(_) => return Err("the tracked last epoch is malformed (fail closed)".into()),
        };
        let (e_new, e_old) = (safe_int_f(ep.get("epoch")).unwrap_or(f64::NAN), safe_int_f(lep.get("epoch")).unwrap_or(f64::NAN));
        if e_new < e_old {
            return Err("revocation epoch rollback (older than the last accepted)".into());
        }
        for id in &lrev {
            if !revoked.contains(id) {
                return Err(format!("the epoch drops '{id}', revoked in the last accepted epoch (not append-only)"));
            }
        }
        if e_new == e_old && str_of(ep.get("root")) != str_of(lep.get("root")) {
            return Err("two different revocation sets under one epoch number (equivocation)".into());
        }
    }
    // g.
    for idv in ids {
        match idv.as_str() {
            Some(id) if !revoked.contains(&id) => {}
            _ => return Err(format!("'{}' is revoked", js_to_string(Some(idv)))),
        }
    }
    Ok(())
}

/// `primitives.intent_revocation[].input` -> `checkSessionRevocation({epoch, revoked}, {session, scope?, authority, ids,
/// now, maxAgeMs: max_age_ms, last?})` (no PQ pin).
pub fn check_session_revocation_input(input: &Value) -> Result<(), String> {
    let mut ev = Map::new();
    for k in ["epoch", "revoked"] {
        if let Some(v) = input.get(k) {
            ev.insert(k.into(), v.clone());
        }
    }
    let session = str_of(input.get("session")).ok_or("malformed intent_revocation input")?;
    let now = input.get("now").and_then(|v| v.as_f64()).unwrap_or(f64::NAN);
    let max_age = input.get("max_age_ms").and_then(|v| v.as_f64()).unwrap_or(f64::NAN);
    let ids = input.get("ids").and_then(|v| v.as_array()).map(|a| a.as_slice());
    let ev = Value::Object(ev);
    check_session_revocation_full(Some(&ev), session, str_of(input.get("scope")), str_of(input.get("authority")), ids, now, max_age, None, input.get("last"))
}

// ---- boundRoot and the `intent_session` check (intent-v2.ts) ----------------------------------------------------------

/// A step failure: `Bad` = the step's own reason; `Thrown` = the TS step THREW (the pipeline's `run` turns it into
/// `<check> error (fail closed): <message>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepErr {
    Bad(String),
    Thrown(String),
}

impl StepErr {
    /// The reason the TS pipeline reports for this failure in check `name`.
    pub fn reason_in(&self, name: &str) -> String {
        match self {
            StepErr::Bad(r) => r.clone(),
            StepErr::Thrown(m) => format!("{name} error (fail closed): {m}"),
        }
    }
}

fn bad<T>(r: impl Into<String>) -> Result<T, StepErr> {
    Err(StepErr::Bad(r.into()))
}

/// `x.k` where `x` may be null (TypeError) or another primitive (undefined).
fn member<'a>(x: Option<&'a Value>, k: &str) -> Result<Option<&'a Value>, StepErr> {
    match x {
        Some(Value::Null) => Err(StepErr::Thrown(format!("Cannot read properties of null (reading '{k}')"))),
        None => Err(StepErr::Thrown(format!("Cannot read properties of undefined (reading '{k}')"))),
        _ => Ok(get(x, k)),
    }
}

/// intent-v2.ts `boundRoot` with the thrown / returned distinction (shared by rules 13 and 15).
pub fn bound_root_step<'a>(pcactn: &Value, ctx: Option<&'a Value>, now: f64) -> Result<&'a Value, StepErr> {
    let is = pcactn.get("intent_session");
    let s = match get(get(ctx, "session"), "root") {
        Some(s) => s,
        None => return bad("no session root for this session"),
    };
    // R3-01: a PQ / hybrid root verifies only under the VERIFIER's pin for its signer (session.pq_pins), never its own
    // principals list
    if let Err(r) = verify_session_root_pinned(s, get(get(ctx, "session"), "pq_pins")) {
        return bad(format!("session root: {r}"));
    }
    let digest = match session_root_digest(s) {
        Some(d) => d,
        None => {
            let e = strict_violation(&digest_wrapper(s)).unwrap_or("rejected");
            return Err(StepErr::Thrown(format!("canonicalize: {e}")));
        }
    };
    if !js_eq(Some(&Value::String(digest)), member(is, "root")?) {
        return bad("intent_session.root is not the digest of the session root");
    }
    if !js_eq(s.get("session"), member(is, "session")?) {
        return bad("the session root names another session");
    }
    if !(now < safe_int_f(s.get("expires_at")).unwrap_or(f64::NAN)) {
        return bad("the session root has expired");
    }
    Ok(s)
}

/// intent-v2.ts `boundRoot`: the bound, verified session root. A TS throw is returned as its message (see
/// [`bound_root_step`] for the distinction).
pub fn bound_root<'a>(pcactn: &Value, ctx: Option<&'a Value>, now: f64) -> Result<&'a Value, String> {
    bound_root_step(pcactn, ctx, now).map_err(|e| match e {
        StepErr::Bad(r) | StepErr::Thrown(r) => r,
    })
}

/// intent-v2.ts `sessionCtxError`: absent = default; a present `session` context must be an object with an array `grants`
/// and an object `revocation` when present (null is malformed); `pq_pins`, when present, is an object of strings.
fn session_ctx_error(ctx: Option<&Value>) -> Option<String> {
    let se = get(ctx, "session")?;
    let m = match se {
        Value::Object(m) => m,
        _ => return Some("the session context must be an object".into()),
    };
    if m.contains_key("grants") && !matches!(m.get("grants"), Some(Value::Array(_))) {
        return Some("the session grants must be an array".into());
    }
    if m.contains_key("revocation") && !matches!(m.get("revocation"), Some(Value::Object(_))) {
        return Some("the session revocation evidence must be an object".into());
    }
    if m.contains_key("revocation_last") && !matches!(m.get("revocation_last"), Some(Value::Object(_))) {
        return Some("the tracked last revocation epoch must be an object".into());
    }
    if let Some(pp) = m.get("pq_pins") {
        if !pp.as_object().is_some_and(|o| o.values().all(Value::is_string)) {
            return Some("the session pq_pins must be an object of strings".into());
        }
    }
    None
}

/// intent-v2.ts `sessionStep` (rule 13, steps 0-7) with the thrown / returned distinction. Expects a wire-valid PCActn
/// (`intent_session` / `intent` already passed `wire`), as the pipeline guarantees.
pub fn session_step_detail(pcactn: &Value, grant: &Value, ctx: Option<&Value>, now: f64) -> Result<(), StepErr> {
    // 0.
    let max_age_s = get(get(get(ctx, "policy"), "session"), "max_revocation_age_s");
    let max_age_s = match max_age_s {
        None => None,
        Some(v) => match non_neg(v) {
            Some(x) => Some(x),
            None => return bad("session policy misconfigured: max_revocation_age_s must be a non-negative safe integer (fail closed)"),
        },
    };
    // 1-2.
    let is = match pcactn.get("intent_session") {
        Some(v) => v,
        None => return bad("this verifier requires an intent_session but the PCActn carries none"),
    };
    if let Some(e) = session_ctx_error(ctx) {
        return bad(e);
    }
    let intent = match pcactn.get("intent") {
        Some(v) => v,
        None => return bad("an intent_session needs the envelope.intent binding"),
    };
    // 3.
    let s = bound_root_step(pcactn, ctx, now)?;
    if !js_eq(s.get("intent_ref"), member(Some(intent), "ref")?) {
        return bad("intent.ref is not the session statement");
    }
    if !js_eq(get(s.get("schema"), "digest"), member(Some(is), "schema")?) {
        return bad("intent_session.schema is not the session schema");
    }
    if !js_eq(get(s.get("schema"), "aud"), pcactn.get("aud")) {
        return bad("the session schema is for another audience");
    }
    let is_seq = member(Some(is), "seq")?;
    if js_num_eq(is_seq, 0.0) && !js_eq(member(Some(intent), "map_digest")?, get(get(s.get("layers"), "task"), "map_digest")) {
        return bad("a seq-0 action must use the session task map");
    }
    // 4.
    let gc = grant_session_caveat(grant);
    if let Some(e) = intent_session_caveat_error(gc) {
        return bad(format!("admitting root: {e}"));
    }
    if !js_eq(get(gc, "session"), get(Some(is), "session")) || !js_eq(get(gc, "root"), get(Some(is), "root")) || !js_eq(get(gc, "seq"), is_seq) {
        return bad("the admitting root is bound to another session, root or seq");
    }
    // 5.
    let principals: Vec<&str> = s.get("principals").and_then(|p| p.as_array()).map(|a| a.iter().filter_map(|x| str_of(get(Some(x), "key"))).collect()).unwrap_or_default();
    let is_principal = |g: &Value| matches!(get(Some(g), "issuer"), Some(Value::String(i)) if principals.contains(&i.as_str()));
    if !is_principal(grant) {
        return bad("the admitting root is not signed by a session principal");
    }
    // 6.
    let seq = match is_seq.and_then(non_neg) {
        Some(q) => q as usize,
        None => return Err(StepErr::Thrown("intent_session.seq is not wire-valid".into())),
    };
    let empty = Vec::new();
    let prior = match get(get(ctx, "session"), "grants") {
        None => &empty,
        Some(Value::Array(a)) => a,
        Some(_) => return bad(format!("the verifier does not hold the {seq} earlier grants of this session")),
    };
    if prior.len() < seq {
        return bad(format!("the verifier does not hold the {seq} earlier grants of this session"));
    }
    for i in 0..seq {
        let g = &prior[i];
        let is_cap = matches!(g, Value::Object(m) if matches!(m.get("id"), Some(Value::String(_))) && matches!(m.get("issuer"), Some(Value::String(_))));
        if !is_cap {
            return bad(format!("session grant {i} is not a capability"));
        }
        if let Some(e) = suite_capability_error(g.get("alg")) {
            return bad(format!("session grant {i}: {e}"));
        }
        let c = grant_session_caveat(g);
        if intent_session_caveat_error(c).is_some() || !js_eq(get(c, "session"), get(Some(is), "session")) || !js_eq(get(c, "root"), get(Some(is), "root")) || !js_num_eq(get(c, "seq"), i as f64) {
            return bad(format!("session grant {i} does not belong to this session at seq {i}"));
        }
        if !is_principal(g) {
            return bad(format!("session grant {i} is not signed by a session principal"));
        }
        if i > 0 && !js_eq(get(c, "prev"), get(Some(&prior[i - 1]), "id")) {
            return bad(format!("session grant {i} does not chain to grant {}", i - 1));
        }
    }
    if seq > 0 && !js_eq(get(gc, "prev"), get(Some(&prior[seq - 1]), "id")) {
        return bad(format!("the admitting root does not chain to grant {}", seq - 1));
    }
    // 7. revocation (T22)
    let rev = s.get("revocation");
    if rev.is_some() || max_age_s.is_some() {
        let mut ages: Vec<f64> = Vec::new();
        if let Some(a) = get(rev, "max_age_s").and_then(|v| v.as_f64()) {
            ages.push(a);
        }
        if let Some(a) = max_age_s {
            ages.push(a as f64);
        }
        let max_age_ms = ages.iter().copied().fold(f64::INFINITY, f64::min) * 1000.0;
        if rev.is_none() {
            return bad("revocation: the policy requires a revocation epoch but the session root names no revocation authority");
        }
        // only the dedicated authority S.revocation.key signs epochs; a PQ epoch verifies only under S.revocation.pq_pk
        let authority = str_of(get(rev, "key"));
        let pin = str_of(get(rev, "pq_pk"));
        let session = js_to_string(get(Some(is), "session"));
        let mut ids = vec![session_revocation_id(&session), map_revocation_id(&js_to_string(member(Some(intent), "map_digest")?))];
        for g in prior.iter().take(seq) {
            ids.push(delta_revocation_id(&js_to_string(get(Some(g), "id"))));
        }
        ids.push(delta_revocation_id(&js_to_string(get(Some(grant), "id"))));
        let std = get(s.get("layers"), "std");
        if truthy(std) {
            ids.push(format!("pca-intent:profile:{}@{}", js_to_string(get(std, "profile")), js_to_string(get(std, "version"))));
        }
        let ids: Vec<Value> = ids.into_iter().map(Value::String).collect();
        let last = get(get(ctx, "session"), "revocation_last");
        if let Err(r) = check_session_revocation_full(get(get(ctx, "session"), "revocation"), &session, None, authority, Some(&ids), now, max_age_ms, pin, last) {
            return bad(format!("revocation: {r}"));
        }
    }
    Ok(())
}

/// intent-v2.ts `sessionStep` as the pipeline reports it: Ok, or the `intent_session` check's reason (a TS throw becomes
/// `intent_session error (fail closed): <message>`).
pub fn session_step(pcactn: &Value, grant: &Value, ctx: Option<&Value>, now: f64) -> Result<(), String> {
    // decideIntentV2's `run`: a clock that is not a safe integer fails every v2 check
    if !f_is_safe_int(now) {
        return Err("the verifier clock is not a safe integer (fail closed)".into());
    }
    session_step_detail(pcactn, grant, ctx, now).map_err(|e| e.reason_in("intent_session"))
}
