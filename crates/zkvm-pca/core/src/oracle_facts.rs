//! Intent Layer v2 W-B, NORMATIVE conformance rule 16 (`facts`, `primitives.intent_world`): world dimensions from signed
//! oracle facts, relational dimensions and the offer-set optimality dimension, plus the W-B composition (rules 16 → 17 →
//! 18, TS `intent-env.ts` `decideIntentWB`) and the shared artifact plumbing of `intent-artifacts.ts` used by
//! `offer_set`, `param_provenance`, `label_receipts` and `intent_classifier`.
//!
//! Faithful port of `packages/pca/src/oracle-facts.ts` (`decideIntentWorld`, `intentWorldActive`, `validateWorldPolicy`,
//! `validateFactWire`). Every artifact is Ed25519 (strict, `keys.ts` `verify`) under a key the VERIFIER pins; the wire
//! formats are closed member sets with no `alg` / `pq_*` member, so no post-quantum suite can even be expressed here.
//!
//! CLOCK: `now` must be a safe integer; any other JSON value is never coerced and makes every fact and every offer set
//! stale (relational dimensions, which need no clock, are still computed). Freshness and relational arithmetic are exact
//! (i128) on safe integers, which gives the same verdict as the TS binary64 arithmetic. KEYS: every lookup and tally is
//! over own members of sorted maps, so names spelled like `Object.prototype` members are ordinary keys. Never panics.
use crate::canonical::{canonical_bytes, strict_violation};
use crate::chain::decode_b64u_strict;
use crate::pq_suites::{suite_supported, verify_pinned_suite, SuiteError};
use crate::commit::hash_canonical;
use crate::intent_classifier::{classifier_check_active, decide_classifier_dimensions};
use crate::jsnum::{non_neg, safe_int, MAX_SAFE_INT};
use crate::offer_set::{decide_offer_set, validate_offer_policy};
use crate::param_provenance::{decide_param_provenance, ProvOutcome};
use serde_json::{Map, Value};

// ---------------------------------------------------------------- shared W-B artifact plumbing (intent-artifacts.ts)

/// `isDigest`: canonical base64url of exactly 32 bytes.
pub fn is_digest(v: &Value) -> bool {
    matches!(v, Value::String(s) if decode_b64u_strict(s, 32).is_some())
}

/// `isBoundedString(v, max)`: a non-empty string of at most `max` UTF-8 bytes.
pub fn is_bounded_string(v: &Value, max: usize) -> bool {
    matches!(v, Value::String(s) if !s.is_empty() && s.len() <= max)
}

/// `INTENT_NAME_RE` = `^[a-z][a-z0-9_]{0,63}$`.
pub fn is_intent_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 64 && b[0].is_ascii_lowercase() && b[1..].iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// `DATA_CLASS_RE` = `^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$`.
pub fn is_data_class(s: &str) -> bool {
    let seg_ok = |seg: &str| !seg.is_empty() && seg.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_');
    let mut it = s.split('.');
    match it.next() {
        Some(first) if seg_ok(first) && first.as_bytes()[0].is_ascii_lowercase() => it.all(seg_ok),
        _ => false,
    }
}

/// `isPathSegment`: `[A-Za-z0-9_-]{1,64}` and not `__proto__` / `constructor` / `prototype`.
pub fn is_path_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        && !matches!(s, "__proto__" | "constructor" | "prototype")
}

const PARAMS_PREFIX: &str = "action.params.";

/// `isParamPath`: `action.params.<seg>(.<seg>){0,7}`.
pub fn is_param_path(v: &Value) -> bool {
    match v {
        Value::String(s) => is_param_path_str(s),
        _ => false,
    }
}

pub fn is_param_path_str(s: &str) -> bool {
    match s.strip_prefix(PARAMS_PREFIX) {
        Some(rest) => {
            let n = rest.split('.').count();
            (1..=8).contains(&n) && rest.split('.').all(is_path_segment)
        }
        None => false,
    }
}

/// `resolveParamPath(params, path)`: own members segment by segment; `None` = not found.
pub fn resolve_param_path<'a>(params: &'a Value, path: &str) -> Option<&'a Value> {
    let rest = path.strip_prefix(PARAMS_PREFIX)?;
    let mut cur = params;
    for s in rest.split('.') {
        if !is_path_segment(s) {
            return None;
        }
        cur = cur.as_object()?.get(s)?;
    }
    Some(cur)
}

/// `isScalar`: a string, a boolean or a safe integer.
pub fn is_scalar(v: &Value) -> bool {
    matches!(v, Value::String(_) | Value::Bool(_)) || safe_int(v).is_some()
}

/// `scalarEq`: same JSON type and `===` value (numbers by binary64 value).
pub fn scalar_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Number(x), Value::Number(y)) => matches!((x.as_f64(), y.as_f64()), (Some(p), Some(q)) if p == q),
        _ => false,
    }
}

/// `closedMembers(o, required, optional)` is null: exactly the required members plus any optional ones.
pub fn closed_members(o: &Map<String, Value>, required: &[&str], optional: &[&str]) -> bool {
    o.keys().all(|k| required.contains(&k.as_str()) || optional.contains(&k.as_str())) && required.iter().all(|k| o.contains_key(*k))
}

/// The optional suite members every W-B artifact may carry (`SUITE_MEMBERS`).
pub const SUITE_MEMBERS: [&str; 3] = ["alg", "pq_pk", "pq_sig"];

/// `pinPqOk`: a pin's optional `pq_pk` is absent or a non-empty string (JSON `null` is malformed).
pub fn pin_pq_ok(pin: &Map<String, Value>) -> bool {
    match pin.get("pq_pk") {
        None => true,
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => false,
    }
}

/// `artifactSuiteError(a)`: `None` = usable. A non-string `alg` is malformed; an `alg` the GUEST does not implement
/// (`crate::pq_suites::suite_supported`: fn-dsa-*, less-*, unknown) is refused with a reason containing `unsupported_suite`
/// (the TS implements FN-DSA / LESS; the guest fails those closed); non-string `pq_pk` / `pq_sig` are malformed; an
/// ed25519 artifact (alg absent or "ed25519") carries neither `pq_pk` nor `pq_sig`.
pub fn artifact_suite_error(a: &Value) -> Option<String> {
    let alg = match a.get("alg") {
        None => None,
        Some(Value::String(s)) => {
            if !suite_supported(Some(s)) {
                return Some(SuiteError::Unsupported(format!("'{s}'")).to_string());
            }
            Some(s.as_str())
        }
        Some(_) => return Some("alg must be a string".into()),
    };
    for k in ["pq_pk", "pq_sig"] {
        if matches!(a.get(k), Some(v) if !v.is_string()) {
            return Some(format!("{k} must be a string"));
        }
    }
    if matches!(alg, None | Some("ed25519")) && (a.get("pq_pk").is_some() || a.get("pq_sig").is_some()) {
        return Some("an ed25519 artifact must not carry pq_pk / pq_sig".into());
    }
    None
}

/// `verifyArtifactSig(domain, artifact, {pk, pq_pk?})`: the artifact's suite over
/// `utf8(domain) || strictCanonical(artifact \ {sig, pq_sig})` (so `alg` and `pq_pk` are signed), Ed25519 under the pinned
/// `pk`, and a post-quantum / hybrid suite only when the artifact's `pq_pk` equals the pin's `pq_pk`
/// (`crate::pq_suites::verify_pinned_suite`). Total: false on any malformed input.
pub fn verify_artifact_sig(domain: &str, artifact: &Value, pinned_pk: &str, pinned_pq_pk: Option<&str>) -> bool {
    let o = match artifact.as_object() {
        Some(o) => o,
        None => return false,
    };
    let sig = match o.get("sig") {
        Some(Value::String(s)) => s,
        _ => return false,
    };
    let alg = match o.get("alg") {
        None => None,
        Some(Value::String(a)) => Some(a.as_str()),
        Some(_) => return false,
    };
    let mut body = o.clone();
    body.remove("sig");
    body.remove("pq_sig");
    let body = Value::Object(body);
    if strict_violation(&body).is_some() {
        return false;
    }
    let mut msg = domain.as_bytes().to_vec();
    msg.extend_from_slice(&canonical_bytes(&body));
    let art_pq = o.get("pq_pk").and_then(Value::as_str);
    let pq_sig = o.get("pq_sig").and_then(Value::as_str);
    verify_pinned_suite(alg, pinned_pk, art_pq, &msg, Some(sig), pq_sig, pinned_pq_pk).is_ok()
}

/// The pinned signer of a pin entry `{pk, pq_pk?}`.
pub fn pin_of(pin: &Value) -> (&str, Option<&str>) {
    (pin.get("pk").and_then(Value::as_str).unwrap_or(""), pin.get("pq_pk").and_then(Value::as_str))
}

/// `artifactRef(refDomain, slot, artifact)` = hashCanonical({d, [slot]: artifact}); `None` where TS would throw
/// (not strictly canonical).
pub fn artifact_ref(ref_domain: &str, slot: &str, artifact: &Value) -> Option<String> {
    let mut m = Map::new();
    m.insert("d".into(), Value::String(ref_domain.into()));
    m.insert(slot.into(), artifact.clone());
    strict_hash(&Value::Object(m))
}

/// `hashCanonical(v)`, `None` where TS throws (the strict profile refuses `v`).
pub fn strict_hash(v: &Value) -> Option<String> {
    if strict_violation(v).is_some() {
        None
    } else {
        Some(hash_canonical(v))
    }
}

/// `x ?? fallback`: `None` for absent and JSON `null`.
pub fn nn(v: Option<&Value>) -> Option<&Value> {
    v.filter(|x| !x.is_null())
}

/// A non-empty JSON ARRAY (the strict activity typing: an object with its own `length` member is not an array).
pub fn non_empty_array(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Array(a)) if !a.is_empty())
}

/// `isClock(now)`: the clock is usable only when `now` is a safe integer. Any other value (absent, `null`, a string, a
/// fraction) is never coerced: every fact and every offer set is then stale.
pub fn clock(v: Option<&Value>) -> Option<i64> {
    v.and_then(safe_int)
}

/// Is `x` a safe integer by its binary64 value (`isSafeInt` on a computed number)?
fn f64_safe(x: f64) -> Option<i64> {
    (x.is_finite() && x.fract() == 0.0 && x.abs() <= MAX_SAFE_INT as f64 && !(x == 0.0 && x.is_sign_negative())).then_some(x as i64)
}

// ---------------------------------------------------------------- rule 16

pub const FACT_DOMAIN: &str = "atlas-pca/fact/v1\0";
pub const FACT_REF_DOMAIN: &str = "atlas-pca/fact-ref/v1";
pub const MAX_COMMITTED_FACTS: usize = 16;
pub const MAX_WORLDS: usize = 16;
pub const MAX_RELATIONAL: usize = 16;
pub const DEFAULT_WORLD_SKEW_MS: i64 = 60_000;

#[derive(Debug, Clone, PartialEq)]
pub struct WorldResult {
    pub ok: bool,
    pub reason: Option<String>,
    pub world: Map<String, Value>,
    pub single_source: Vec<String>,
}

/// `validateFactWire`: `None` = well-formed.
pub fn validate_fact_wire(f: &Value) -> Option<String> {
    let o = match f.as_object() {
        Some(o) => o,
        None => return Some("fact must be an object".into()),
    };
    if !closed_members(o, &["v", "kind", "name", "subject", "value", "t_obs", "oracle", "sig"], &SUITE_MEMBERS) {
        return Some("fact has unknown or missing members".into());
    }
    if o.get("v").and_then(safe_int) != Some(1) || o.get("kind").and_then(Value::as_str) != Some("pca-fact") {
        return Some("fact must be {v: 1, kind: \"pca-fact\"}".into());
    }
    if !matches!(o.get("name"), Some(Value::String(s)) if is_intent_name(s)) {
        return Some("'fact.name' must match ^[a-z][a-z0-9_]{0,63}$".into());
    }
    let g = |k: &str| o.get(k).unwrap_or(&Value::Null);
    if !is_bounded_string(g("subject"), 256) {
        return Some("'fact.subject' must be a non-empty string (<= 256 bytes)".into());
    }
    if safe_int(g("value")).is_none() && !is_bounded_string(g("value"), 256) {
        return Some("'fact.value' must be a safe integer or a non-empty string (<= 256 bytes)".into());
    }
    if non_neg(g("t_obs")).is_none() {
        return Some("'fact.t_obs' must be a non-negative safe integer".into());
    }
    if !is_bounded_string(g("oracle"), 64) {
        return Some("'fact.oracle' must be a non-empty string (<= 64 bytes)".into());
    }
    if !g("sig").is_string() {
        return Some("'fact.sig' must be a string".into());
    }
    None
}

/// `factRef(f)`; `None` where TS throws.
pub fn fact_ref(f: &Value) -> Option<String> {
    artifact_ref(FACT_REF_DOMAIN, "f", f)
}

/// `ratioPpm(a, b)`: ⌊a·10^6 / b⌋ exactly, `None` when b <= 0, a < 0 or the result is not a safe integer.
pub fn ratio_ppm(a: i64, b: i64) -> Option<i64> {
    if b <= 0 || a < 0 {
        return None;
    }
    let q = (a as i128) * 1_000_000 / (b as i128);
    (q <= MAX_SAFE_INT as i128).then_some(q as i64)
}

/// `lowerMedian(xs)` (non-empty).
pub fn lower_median(xs: &[i64]) -> Option<i64> {
    let mut s = xs.to_vec();
    s.sort_unstable();
    s.get(s.len().checked_sub(1)? / 2).copied()
}

/// `validateWorldPolicy` (rule 16 step 0): `None` = well-formed.
pub fn validate_world_policy(p: &Value) -> Option<String> {
    let p = match p.as_object() {
        Some(p) => p,
        None => return Some("world policy must be an object".into()),
    };
    // closed and typed (README "closed and typed policies"): an unknown member is malformed
    if !closed_members(p, &[], &["skew_ms", "worlds", "relational", "offers"]) {
        return Some("unknown member in the world policy".into());
    }
    if let Some(s) = p.get("skew_ms") {
        if non_neg(s).is_none() {
            return Some("skew_ms must be a non-negative safe integer".into());
        }
    }
    let mut names: Vec<String> = Vec::new();
    fn claim(names: &mut Vec<String>, n: Option<&Value>) -> Option<String> {
        match n {
            Some(Value::String(s)) if is_intent_name(s) => {
                if names.iter().any(|x| x == s) {
                    return Some(format!("duplicate dimension name '{s}'"));
                }
                names.push(s.clone());
                None
            }
            _ => Some("dimension name must match ^[a-z][a-z0-9_]{0,63}$".into()),
        }
    }
    let empty: Vec<Value> = Vec::new();
    let worlds = match p.get("worlds") {
        None => &empty,
        Some(Value::Array(a)) if a.len() <= MAX_WORLDS => a,
        Some(_) => return Some(format!("worlds must be a list of at most {MAX_WORLDS}")),
    };
    for w in worlds {
        let w = match w.as_object() {
            Some(w) => w,
            None => return Some("world entry must be an object".into()),
        };
        if !closed_members(w, &["name", "subject_path", "oracles", "freshness_ms", "min_oracles", "max_faulty"], &[]) {
            return Some("a world is exactly {name, subject_path, oracles, freshness_ms, min_oracles, max_faulty}".into());
        }
        if let Some(e) = claim(&mut names, w.get("name")) {
            return Some(e);
        }
        let name = w.get("name").and_then(Value::as_str).unwrap_or("");
        if !matches!(w.get("subject_path"), Some(Value::String(s)) if s.starts_with("action.")) {
            return Some(format!("world '{name}': subject_path must be rooted at action."));
        }
        if w.get("freshness_ms").and_then(non_neg).is_none() {
            return Some(format!("world '{name}': freshness_ms must be a non-negative safe integer"));
        }
        let mf = match w.get("max_faulty").and_then(non_neg) {
            Some(x) => x as i128,
            None => return Some(format!("world '{name}': max_faulty must be a non-negative safe integer")),
        };
        let mo = match w.get("min_oracles").and_then(safe_int) {
            Some(x) if (x as i128) >= 2 * mf + 1 => x,
            _ => return Some(format!("world '{name}': min_oracles must be a safe integer >= 2*max_faulty+1")),
        };
        let oracles = match w.get("oracles") {
            Some(Value::Array(a)) if (a.len() as i128) >= mo as i128 => a,
            _ => return Some(format!("world '{name}': fewer pinned oracles than min_oracles")),
        };
        let mut kids: Vec<&str> = Vec::new();
        for o in oracles {
            let ok = o.as_object().map_or(false, |o| {
                let kid = o.get("kid").unwrap_or(&Value::Null);
                closed_members(o, &["kid", "pk"], &["pq_pk"]) && is_bounded_string(kid, 64) && is_digest(o.get("pk").unwrap_or(&Value::Null)) && pin_pq_ok(o) && !kids.contains(&kid.as_str().unwrap_or(""))
            });
            if !ok {
                return Some(format!("world '{name}': every oracle needs a unique kid and a 32-byte pk"));
            }
            kids.push(o.get("kid").and_then(Value::as_str).unwrap_or(""));
        }
    }
    let rel = match p.get("relational") {
        None => &empty,
        Some(Value::Array(a)) if a.len() <= MAX_RELATIONAL => a,
        Some(_) => return Some(format!("relational must be a list of at most {MAX_RELATIONAL}")),
    };
    for r in rel {
        let r = match r.as_object() {
            Some(r) => r,
            None => return Some("relational entry must be an object".into()),
        };
        if !closed_members(r, &["name", "fn", "a", "b"], &[]) {
            return Some("a relational entry is exactly {name, fn, a, b}".into());
        }
        if let Some(e) = claim(&mut names, r.get("name")) {
            return Some(e);
        }
        let name = r.get("name").and_then(Value::as_str).unwrap_or("");
        if !matches!(r.get("fn").and_then(Value::as_str), Some("sub" | "ratio_ppm")) {
            return Some(format!("relational '{name}': fn must be \"sub\" or \"ratio_ppm\""));
        }
        for k in ["a", "b"] {
            let op = r.get(k).unwrap_or(&Value::Null);
            let ok = is_param_path(op)
                || matches!(op, Value::String(s) if s.strip_prefix("env.world.").map_or(false, |n| n != name && names.iter().any(|x| x == n)));
            if !ok {
                return Some(format!("relational '{name}': operand must be an action.params path or an earlier env.world dimension"));
            }
        }
    }
    if let Some(off) = p.get("offers") {
        if let Some(e) = validate_offer_policy(off) {
            return Some(e);
        }
        if let Some(e) = claim(&mut names, off.get("name")) {
            return Some(e);
        }
    }
    None
}

/// `intentWorldActive({committed, policy})`: anything committed or any dimension declared.
/// Strict typing: `committed.facts` a non-empty array, `committed.offer_set` a string, `policy.worlds` /
/// `policy.relational` a non-empty array, or `policy.offers` a plain object.
pub fn intent_world_active(committed: &Value, policy: &Value) -> bool {
    non_empty_array(committed.get("facts"))
        || committed.get("offer_set").map_or(false, Value::is_string)
        || non_empty_array(policy.get("worlds"))
        || non_empty_array(policy.get("relational"))
        || policy.get("offers").map_or(false, Value::is_object)
}

/// `intentProvenanceActive`: `prov` present (any value, `null` included), `labels` a non-empty array, or the provenance
/// policy a plain object.
pub fn intent_provenance_active(prov: Option<&Value>, labels: Option<&Value>, policy: Option<&Value>) -> bool {
    prov.is_some() || non_empty_array(labels) || policy.map_or(false, Value::is_object)
}

/// Which W-B checks a verifier reports (`intentWBActive`, conformance `primitives.intent_wb_active`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WbActive {
    pub facts: bool,
    pub provenance: bool,
    pub classes: bool,
}

/// `intentWBActive({intent_session, policy})`.
pub fn intent_wb_active(input: &Value) -> WbActive {
    let s = nn(input.get("intent_session")).unwrap_or(&NO_OBJ);
    let p = nn(input.get("policy")).unwrap_or(&NO_OBJ);
    let mut committed = Map::new();
    for k in ["facts", "offer_set"] {
        if let Some(v) = s.get(k) {
            committed.insert(k.into(), v.clone());
        }
    }
    let world_policy = nn(p.get("world")).unwrap_or(&NO_OBJ);
    let classifiers = nn(p.get("classifiers")).cloned().unwrap_or(Value::Array(Vec::new()));
    WbActive {
        facts: intent_world_active(&Value::Object(committed), world_policy),
        provenance: intent_provenance_active(s.get("prov"), s.get("labels"), p.get("provenance")),
        classes: classifier_check_active(s.get("classes").unwrap_or(&Value::Null), &serde_json::json!({ "classifiers": classifiers })),
    }
}

/// Stand-in for an absent member object: reading a member of `null` finds nothing.
static NO_OBJ: Value = Value::Null;

/// The action's string at a world's `subject_path` (`subjectOf`; `action` is a plain object, `params` its checked params).
fn subject_of<'a>(action: &'a Value, params: &'a Value, path: &str) -> Option<&'a str> {
    match path {
        "action.resource" => action.get("resource").and_then(Value::as_str),
        "action.verb" => action.get("verb").and_then(Value::as_str),
        _ => resolve_param_path(params, path).and_then(Value::as_str),
    }
}

/// Absent vs null: `Ok(None)` when absent, `Ok(Some(v))` when present with the right JSON type, `Err` when present with
/// another type (`null` included).
fn opt_typed(v: Option<&Value>, ok: fn(&Value) -> bool) -> Result<Option<&Value>, ()> {
    match v {
        None => Ok(None),
        Some(x) if ok(x) => Ok(Some(x)),
        Some(_) => Err(()),
    }
}

/// `action` must be a plain object and `action.params` absent (= `{}`) or a plain object (rules 16-18).
pub fn checked_params(action: Option<&Value>) -> Result<&Value, &'static str> {
    let action = match action {
        Some(a @ Value::Object(_)) => a,
        _ => return Err("action must be an object"),
    };
    match opt_typed(action.get("params"), Value::is_object) {
        Ok(Some(p)) => Ok(p),
        Ok(None) => Ok(&EMPTY_PARAMS),
        Err(()) => Err("action.params must be an object"),
    }
}

static EMPTY_PARAMS: Value = Value::Null; // resolving a path in `null` finds nothing, exactly as in `{}`

/// NORMATIVE rule 16: compute `env.world` for one action (`decideIntentWorld`). First failure wins. Never panics.
pub fn decide_intent_world(input: &Value) -> WorldResult {
    let fail = |r: &str| WorldResult { ok: false, reason: Some(format!("facts: {r}")), world: Map::new(), single_source: Vec::new() };
    if !input.is_object() {
        return fail("input must be an object");
    }
    // ABSENT optional members mean empty / default; PRESENT ones of the wrong JSON type (null included) fail closed.
    let empty_policy = Value::Object(Map::new());
    let policy = input.get("policy").unwrap_or(&empty_policy);
    if let Some(pe) = validate_world_policy(policy) {
        return fail(&format!("policy misconfigured (fail closed): {pe}"));
    }
    let skew = policy.get("skew_ms").and_then(safe_int).unwrap_or(DEFAULT_WORLD_SKEW_MS) as i128;
    let action = input.get("action").unwrap_or(&NO_OBJ);
    let params = match checked_params(input.get("action")) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    let empty_obj = Value::Object(Map::new());
    let committed = match opt_typed(input.get("committed"), Value::is_object) {
        Ok(c) => c.unwrap_or(&empty_obj),
        Err(()) => return fail("committed must be an object"),
    };
    let empty: Vec<Value> = Vec::new();
    let committed_facts = match committed.get("facts") {
        None => &empty,
        Some(Value::Array(a)) if a.len() <= MAX_COMMITTED_FACTS => a,
        Some(_) => return fail(&format!("committed facts must be a list of at most {MAX_COMMITTED_FACTS} digests")),
    };
    let mut seen: Vec<&str> = Vec::new();
    for d in committed_facts {
        if !is_digest(d) {
            return fail("a committed fact digest is not canonical base64url (32 bytes)");
        }
        let d = d.as_str().unwrap_or("");
        if seen.contains(&d) {
            return fail("duplicate committed fact digest");
        }
        seen.push(d);
    }
    let committed_offer = committed.get("offer_set");
    if let Some(c) = committed_offer {
        if !is_digest(c) {
            return fail("the committed offer_set is not canonical base64url (32 bytes)");
        }
    }
    let supplied = match opt_typed(input.get("facts"), Value::is_array) {
        Ok(f) => f.and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]),
        Err(()) => return fail("facts must be an array"),
    };
    if opt_typed(input.get("offer_set"), Value::is_object).is_err() {
        return fail("offer_set must be an object");
    }
    let mut by_ref: std::collections::BTreeMap<String, &Value> = std::collections::BTreeMap::new();
    for f in supplied {
        if validate_fact_wire(f).is_some() {
            continue;
        }
        if let Some(r) = fact_ref(f) {
            by_ref.insert(r, f);
        }
    }
    let worlds = policy.get("worlds").and_then(Value::as_array).unwrap_or(&empty);
    // accepted: (name, value, t_obs)
    let mut accepted: Vec<(&str, &Value, i64)> = Vec::new();
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    for d in committed_facts {
        let f = match d.as_str().and_then(|d| by_ref.get(d)) {
            Some(f) => *f,
            None => return fail("a committed fact was not supplied (or is malformed)"),
        };
        if let Some(se) = artifact_suite_error(f) {
            return fail(&format!("fact signature suite: {se}"));
        }
        let fname = f.get("name").and_then(Value::as_str).unwrap_or("");
        let oracle = f.get("oracle").and_then(Value::as_str).unwrap_or("");
        let w = match worlds.iter().find(|x| x.get("name").and_then(Value::as_str) == Some(fname)) {
            Some(w) => w,
            None => return fail(&format!("fact for undeclared world '{fname}'")),
        };
        let pin = w.get("oracles").and_then(Value::as_array).and_then(|os| os.iter().find(|o| o.get("kid").and_then(Value::as_str) == Some(oracle)));
        let pin = match pin {
            Some(p) => p,
            None => return fail(&format!("oracle '{oracle}' is not pinned for world '{fname}'")),
        };
        let (pk, pq) = pin_of(pin);
        if !verify_artifact_sig(FACT_DOMAIN, f, pk, pq) {
            return fail(&format!("bad oracle signature on a '{fname}' fact"));
        }
        let subject = subject_of(action, params, w.get("subject_path").and_then(Value::as_str).unwrap_or(""));
        if subject.is_none() || f.get("subject").and_then(Value::as_str) != subject {
            return fail(&format!("a '{fname}' fact names another subject"));
        }
        if pairs.contains(&(fname, oracle)) {
            return fail(&format!("two facts from oracle '{oracle}' for world '{fname}'"));
        }
        pairs.push((fname, oracle));
        accepted.push((fname, f.get("value").unwrap_or(&Value::Null), f.get("t_obs").and_then(safe_int).unwrap_or(0)));
    }

    let now = clock(input.get("now"));
    let mut world = Map::new();
    let mut single_source = Vec::new();
    for w in worlds {
        let wname = w.get("name").and_then(Value::as_str).unwrap_or("");
        let freshness = w.get("freshness_ms").and_then(safe_int).unwrap_or(0) as i128;
        let min_oracles = w.get("min_oracles").and_then(safe_int).unwrap_or(1);
        // no usable clock: no fact is fresh (fail closed, never coercion)
        let fresh: Vec<&Value> = match now {
            None => Vec::new(),
            Some(now) => {
                let now = now as i128;
                accepted.iter().filter(|(n, _, t)| *n == wname && (*t as i128) <= now + skew && now - (*t as i128) <= freshness).map(|(_, v, _)| *v).collect()
            }
        };
        if (fresh.len() as i64) < min_oracles {
            return fail(&format!("world '{wname}' has {} fresh fact(s), needs {min_oracles}", fresh.len()));
        }
        let nums: Vec<i64> = fresh.iter().filter_map(|v| safe_int(v)).collect();
        if nums.len() == fresh.len() {
            match lower_median(&nums) {
                Some(m) => world.insert(wname.to_string(), Value::from(m)),
                None => return fail("evaluation error (fail closed)"),
            };
        } else if nums.is_empty() {
            let v = fresh[0];
            if fresh.iter().any(|f| *f != v) {
                return fail(&format!("world '{wname}': string facts disagree"));
            }
            world.insert(wname.to_string(), v.clone());
        } else {
            return fail(&format!("world '{wname}': facts mix integer and string values"));
        }
        if min_oracles == 1 {
            single_source.push(wname.to_string());
        }
    }

    for r in policy.get("relational").and_then(Value::as_array).unwrap_or(&empty) {
        let rname = r.get("name").and_then(Value::as_str).unwrap_or("");
        let mut ops = [0i64; 2];
        for (i, k) in ["a", "b"].iter().enumerate() {
            let path = r.get(*k).and_then(Value::as_str).unwrap_or("");
            let v = if let Some(n) = path.strip_prefix("env.world.") {
                world.get(n).and_then(safe_int)
            } else {
                resolve_param_path(params, path).and_then(safe_int)
            };
            match v {
                Some(x) => ops[i] = x,
                None => return fail(&format!("relational '{rname}': an operand is missing or not a safe integer")),
            }
        }
        let v = if r.get("fn").and_then(Value::as_str) == Some("sub") {
            f64_safe(ops[0] as f64 - ops[1] as f64)
        } else {
            ratio_ppm(ops[0], ops[1])
        };
        match v {
            Some(x) => world.insert(rname.to_string(), Value::from(x)),
            None => return fail(&format!("relational '{rname}': result undefined or outside the safe integer range")),
        };
    }

    if let Some(off) = policy.get("offers") {
        let od = decide_offer_set(
            off,
            committed_offer.and_then(Value::as_str),
            input.get("offer_set"),
            params,
            input.get("aud").unwrap_or(&Value::Null),
            input.get("session").unwrap_or(&Value::Null),
            now,
            skew as i64,
        );
        match od {
            Ok(d) => {
                world.insert(off.get("name").and_then(Value::as_str).unwrap_or("").to_string(), Value::from(d.excess));
            }
            Err(reason) => return fail(&reason),
        }
    }
    WorldResult { ok: true, reason: None, world, single_source }
}

// ---------------------------------------------------------------- W-B composition (intent-env.ts decideIntentWB)

#[derive(Debug, Clone, PartialEq)]
pub struct WbResult {
    /// `admit` | `question` | `deny`.
    pub outcome: String,
    /// (`facts` | `provenance` | `classes`, `pass` | `question` | `fail`) in evaluation order, reported checks only.
    pub checks: Vec<(String, String)>,
    /// `world` / `prov` / `class`.
    pub env: Map<String, Value>,
    pub reason: Option<String>,
    pub friction: Option<String>,
}

/// `intentWBContextError`: `intent_session` a plain object; `artifacts` absent or a plain object whose `facts` / `labels`
/// / `verdicts` are absent or arrays and whose `offer_set` is absent or a plain object; `policy` absent or a plain object
/// whose `world` / `provenance` are absent or plain objects and whose `classifiers` is absent or an array. JSON `null`
/// anywhere here is malformed. `None` = well-formed.
pub fn intent_wb_context_error(input: &Value) -> Option<String> {
    if !input.is_object() {
        return Some("input must be an object".into());
    }
    if !input.get("intent_session").map_or(false, Value::is_object) {
        return Some("intent_session must be an object".into());
    }
    if let Some(a) = input.get("artifacts") {
        match a.as_object() {
            None => return Some("artifacts must be an object".into()),
            Some(m) if !closed_members(m, &[], &["facts", "labels", "verdicts", "offer_set"]) => return Some("unknown member in artifacts".into()),
            Some(_) => {}
        }
        for k in ["facts", "labels", "verdicts"] {
            if opt_typed(a.get(k), Value::is_array).is_err() {
                return Some(format!("artifacts.{k} must be an array"));
            }
        }
        if opt_typed(a.get("offer_set"), Value::is_object).is_err() {
            return Some("artifacts.offer_set must be an object".into());
        }
    }
    if let Some(p) = input.get("policy") {
        match p.as_object() {
            None => return Some("policy must be an object".into()),
            Some(m) if !closed_members(m, &[], &["world", "provenance", "classifiers"]) => return Some("unknown member in policy".into()),
            Some(_) => {}
        }
        for k in ["world", "provenance"] {
            if opt_typed(p.get(k), Value::is_object).is_err() {
                return Some(format!("policy.{k} must be an object"));
            }
        }
        if opt_typed(p.get("classifiers"), Value::is_array).is_err() {
            return Some("policy.classifiers must be an array".into());
        }
    }
    None
}

/// Rules 16, 17 and 18 in order (`decideIntentWB`); the first failing check denies and later checks are not reported.
/// A rule-17 `question` continues to rule 18. Never panics.
pub fn decide_intent_wb(input: &Value) -> WbResult {
    let mut out = WbResult { outcome: "admit".into(), checks: Vec::new(), env: Map::new(), reason: None, friction: None };
    if let Some(ce) = intent_wb_context_error(input) {
        out.outcome = "deny".into();
        out.checks = vec![("facts".into(), "fail".into())];
        out.reason = Some(format!("facts: the W-B context is malformed: {ce}"));
        return out;
    }
    let s = input.get("intent_session").unwrap_or(&NO_OBJ);
    let a = input.get("artifacts").unwrap_or(&NO_OBJ);
    let pol = input.get("policy");
    let world_policy = pol.and_then(|p| p.get("world")).cloned().unwrap_or(Value::Object(Map::new()));

    // committed: {facts: s.facts, offer_set: s.offer_set} (absent stays absent; JSON null is a defined value)
    let mut committed = Map::new();
    if let Some(f) = s.get("facts") {
        committed.insert("facts".into(), f.clone());
    }
    if let Some(o) = s.get("offer_set") {
        committed.insert("offer_set".into(), o.clone());
    }
    let committed = Value::Object(committed);
    if intent_world_active(&committed, &world_policy) {
        let mut wi = Map::new();
        for k in ["now", "aud", "session", "action"] {
            if let Some(v) = input.get(k) {
                wi.insert(k.into(), v.clone());
            }
        }
        wi.insert("committed".into(), committed.clone());
        if let Some(v) = a.get("facts") {
            wi.insert("facts".into(), v.clone());
        }
        if let Some(v) = a.get("offer_set") {
            wi.insert("offer_set".into(), v.clone());
        }
        wi.insert("policy".into(), world_policy.clone());
        let w = decide_intent_world(&Value::Object(wi));
        if !w.ok {
            out.outcome = "deny".into();
            out.checks = vec![("facts".into(), "fail".into())];
            out.reason = w.reason;
            return out;
        }
        out.checks.push(("facts".into(), "pass".into()));
        out.env.insert("world".into(), Value::Object(w.world));
    }

    let prov_policy = pol.and_then(|p| p.get("provenance"));
    let prov_active = intent_provenance_active(s.get("prov"), s.get("labels"), prov_policy);
    if prov_active {
        let mut pi = Map::new();
        for k in ["aud", "session", "action"] {
            if let Some(v) = input.get(k) {
                pi.insert(k.into(), v.clone());
            }
        }
        if let Some(v) = s.get("prov") {
            pi.insert("prov".into(), v.clone());
        }
        if let Some(v) = s.get("labels") {
            pi.insert("committed_labels".into(), v.clone());
        }
        if let Some(v) = a.get("labels") {
            pi.insert("labels".into(), v.clone());
        }
        let pp = prov_policy.cloned().unwrap_or_else(|| serde_json::json!({ "params": {} }));
        pi.insert("policy".into(), pp);
        let p = decide_param_provenance(&Value::Object(pi));
        match p.outcome {
            ProvOutcome::Deny => {
                out.outcome = "deny".into();
                out.checks.push(("provenance".into(), "fail".into()));
                out.reason = p.reason;
                return out;
            }
            ProvOutcome::Question => {
                out.checks.push(("provenance".into(), "question".into()));
                out.env.insert("prov".into(), p.env);
                out.outcome = "question".into();
                out.reason = p.reason;
                out.friction = p.friction;
            }
            ProvOutcome::Pass => {
                out.checks.push(("provenance".into(), "pass".into()));
                out.env.insert("prov".into(), p.env);
            }
        }
    }

    let classifiers = pol.and_then(|p| p.get("classifiers")).cloned().unwrap_or(Value::Array(Vec::new()));
    let cls_policy = serde_json::json!({ "classifiers": classifiers });
    let committed_classes = s.get("classes").cloned().unwrap_or(Value::Null);
    if classifier_check_active(&committed_classes, &cls_policy) {
        let mut ci = Map::new();
        for k in ["session", "action"] {
            if let Some(v) = input.get(k) {
                ci.insert(k.into(), v.clone());
            }
        }
        if let Some(v) = s.get("classes") {
            ci.insert("committed".into(), v.clone());
        }
        if let Some(v) = a.get("verdicts") {
            ci.insert("verdicts".into(), v.clone());
        }
        ci.insert("policy".into(), cls_policy);
        let c = decide_classifier_dimensions(&Value::Object(ci));
        if !c.ok {
            out.outcome = "deny".into();
            out.checks.push(("classes".into(), "fail".into()));
            out.reason = c.reason;
            return out;
        }
        out.checks.push(("classes".into(), "pass".into()));
        out.env.insert("class".into(), Value::Object(c.classes));
    }
    out
}
