//! Shared helpers of the Intent Layer v2 modules (rules 13-18 of the conformance README): the value tests the rules
//! are written in. Strict typing throughout: a safe integer is rule 3's (never `-0`, never a coerced string), a list is
//! a JSON array, a lookup is over own members of a JSON object; nothing is coerced. `Option<&Value>` is a member read
//! (`None` = absent, `Some(Null)` = a JSON `null`, which is present). Byte limits are UTF-8 bytes.

use serde_json::{Map, Value};

use super::intent_suite::{suite_of, verify_pinned_suite};
use super::{canonicalize_strict, decode_b64u_strict, hash_canonical_strict, safe_int, MAX_SAFE};

/// Names the predicate DSL refuses as path segments; refused as accumulator ids, monitor ids and schema parameter names.
pub(crate) const RESERVED_NAMES: [&str; 3] = ["__proto__", "constructor", "prototype"];

/// A plain JSON object (`isPlainObject`).
pub(crate) fn obj(v: Option<&Value>) -> Option<&Map<String, Value>> {
    v.and_then(Value::as_object)
}

/// `isSafeInt` / `isInt`: a safe integer that is not `-0`.
pub(crate) fn sint(v: Option<&Value>) -> Option<i64> {
    v.and_then(safe_int)
}

/// `isNonNeg`: a safe integer >= 0 (not `-0`).
pub(crate) fn nonneg(v: Option<&Value>) -> Option<i64> {
    sint(v).filter(|x| *x >= 0)
}

/// The IEEE double a JSON number is (`JSON.parse`); None for a non-number.
pub(crate) fn num(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64(),
        _ => None,
    }
}

/// A double that is an integer of magnitude <= 2^53-1 (`-0` included: a number READ for a bound, not a wire field).
pub(crate) fn safe_integer_f64(x: f64) -> bool {
    x.is_finite() && x.fract() == 0.0 && x.abs() <= MAX_SAFE as f64
}


/// A canonical base64url string of exactly 32 bytes (`isDigest`, `b32`).
pub(crate) fn b32(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(s)) if decode_b64u_strict(s, Some(32)).is_some())
}

/// Canonical base64url of any length (`decodeB64uStrict(v) !== null`).
pub(crate) fn b64any(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(s)) if decode_b64u_strict(s, None).is_some())
}

/// `isBoundedString(v, max)`: a non-empty string of at most `max` UTF-8 bytes.
pub(crate) fn bstr(v: Option<&Value>, max: usize) -> bool {
    matches!(v, Some(Value::String(s)) if !s.is_empty() && s.len() <= max)
}

/// The string a member read yields, when it is one.
pub(crate) fn s(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str)
}

/// Equality of two member reads as JSON scalars (same type and value; numbers by their double value; two absent
/// members are equal; an object or an array never equals anything).
pub(crate) fn same(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::Null), Some(Value::Null)) => true,
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x == y,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        _ => false,
    }
}

/// Scalar equality of rules 16-18: same JSON type and value (`2 != "2"`, `true != 1`).
pub(crate) fn scalar_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    same(a, b)
}

/// `isScalar`: a string, a boolean or a safe integer.
pub(crate) fn is_scalar(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(_)) | Some(Value::Bool(_))) || sint(v).is_some()
}

fn all_bytes(s: &str, f: impl Fn(u8) -> bool) -> bool {
    s.bytes().all(f)
}
fn lower_digit_us(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'
}

/// `INTENT_NAME_RE` `^[a-z][a-z0-9_]{0,63}$`.
pub(crate) fn is_name(v: Option<&Value>) -> bool {
    match s(v) {
        Some(x) => {
            let b = x.as_bytes();
            !b.is_empty() && b.len() <= 64 && b[0].is_ascii_lowercase() && all_bytes(x, lower_digit_us)
        }
        None => false,
    }
}

/// `^[A-Za-z0-9_]{1,64}$` (accumulator / monitor ids, `prov` names, schema parameter names).
pub(crate) fn is_ident(x: &str) -> bool {
    !x.is_empty() && x.len() <= 64 && all_bytes(x, |c| c.is_ascii_alphanumeric() || c == b'_')
}

/// `^action\.params\.[A-Za-z0-9_]{1,64}$`.
pub(crate) fn is_top_param_path(x: &str) -> bool {
    x.strip_prefix("action.params.").is_some_and(is_ident)
}

/// `^[a-z0-9_]+(?:\.[a-z0-9_]+)*$` (unit ids).
pub(crate) fn is_unit_id(x: &str) -> bool {
    !x.is_empty() && x.split('.').all(|seg| !seg.is_empty() && all_bytes(seg, lower_digit_us))
}

/// `DATA_CLASS_RE` `^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$`.
pub(crate) fn is_data_class(x: &str) -> bool {
    let mut segs = x.split('.');
    let first = segs.next().unwrap_or("");
    !first.is_empty()
        && first.as_bytes()[0].is_ascii_lowercase()
        && all_bytes(first, lower_digit_us)
        && segs.all(|seg| !seg.is_empty() && all_bytes(seg, lower_digit_us))
}

const FORBIDDEN_SEGMENTS: [&str; 3] = ["__proto__", "constructor", "prototype"];

/// `isPathSegment`: `^[A-Za-z0-9_-]{1,64}$` and not a prototype name.
pub(crate) fn is_path_segment(x: &str) -> bool {
    !x.is_empty()
        && x.len() <= 64
        && all_bytes(x, |c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        && !FORBIDDEN_SEGMENTS.contains(&x)
}

/// `isParamPath`: `action.params.` followed by 1..8 path segments.
pub(crate) fn is_param_path(v: Option<&Value>) -> bool {
    match s(v).and_then(|p| p.strip_prefix("action.params.")) {
        Some(rest) => {
            let segs: Vec<&str> = rest.split('.').collect();
            !segs.is_empty() && segs.len() <= 8 && segs.iter().all(|x| is_path_segment(x))
        }
        None => false,
    }
}

/// `resolveParamPath(params, path)`: own members of plain objects, segment by segment.
pub(crate) fn resolve_param_path<'a>(params: &'a Value, path: &str) -> Option<&'a Value> {
    let rest = path.strip_prefix("action.params.")?;
    let mut cur = params;
    for seg in rest.split('.') {
        if !is_path_segment(seg) {
            return None;
        }
        cur = cur.as_object()?.get(seg)?;
    }
    Some(cur)
}

/// `closedMembers(o, required, optional) === null`.
pub(crate) fn closed_members(o: &Map<String, Value>, required: &[&str], optional: &[&str]) -> bool {
    o.keys().all(|k| required.contains(&k.as_str()) || optional.contains(&k.as_str())) && required.iter().all(|k| o.contains_key(*k))
}

/// The object `o` has exactly the keys `keys` (`Object.keys(o).sort().join() === keys.join()`).
pub(crate) fn exact_keys(o: &Map<String, Value>, keys: &[&str]) -> bool {
    o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k))
}

/// The optional suite members every W-B artifact may carry (`SUITE_MEMBERS`).
pub(crate) const SUITE_MEMBERS: [&str; 3] = ["alg", "pq_pk", "pq_sig"];

/// `pinPqOk`: a pin's optional `pq_pk` is absent or a non-empty string (JSON `null` is malformed).
pub(crate) fn pin_pq_ok(v: Option<&Value>) -> bool {
    match v {
        None => true,
        Some(Value::String(x)) => !x.is_empty(),
        Some(_) => false,
    }
}

/// `artifactSuiteError(a)`: the suite members of a W-B artifact. `None` = usable. A non-string `alg` is malformed; an
/// `alg` the suite dispatch refuses yields a reason containing `unsupported_suite`; a non-string `pq_pk` / `pq_sig` is
/// malformed; a classical-suite artifact carries neither `pq_pk` nor `pq_sig`.
pub(crate) fn artifact_suite_error(a: &Map<String, Value>) -> Option<String> {
    let suite = match suite_of(a.get("alg")) {
        Ok(x) => x,
        Err(e) => return Some(e),
    };
    for k in ["pq_pk", "pq_sig"] {
        if a.get(k).is_some_and(|x| !x.is_string()) {
            return Some(format!("{k} must be a string"));
        }
    }
    if !suite.needs_pq_pk && (a.contains_key("pq_pk") || a.contains_key("pq_sig")) {
        return Some(format!("an {} artifact must not carry pq_pk / pq_sig", suite.alg));
    }
    None
}

/// utf8(domain) || strictCanonical(artifact without `sig` / `pq_sig`); None when the body is not strictly canonical.
pub(crate) fn artifact_message(domain: &str, artifact: &Map<String, Value>) -> Option<Vec<u8>> {
    let mut body = artifact.clone();
    body.remove("sig");
    body.remove("pq_sig");
    let c = canonicalize_strict(&Value::Object(body)).ok()?;
    let mut m = domain.as_bytes().to_vec();
    m.extend_from_slice(c.as_bytes());
    Some(m)
}

/// `verifyArtifactSig(domain, artifact, {pk, pq_pk?})` (the caller has checked [`artifact_suite_error`]): the suite's
/// signature over [`artifact_message`] through the crate's suite dispatch, Ed25519 under the PINNED `pk`; a
/// post-quantum or hybrid suite only when the artifact's `pq_pk` equals the PQ key PINNED for that signer. Total.
pub(crate) fn verify_artifact_sig(domain: &str, artifact: &Map<String, Value>, pinned_pk: &str, pinned_pq: Option<&Value>) -> bool {
    let msg = match (artifact.get("sig"), artifact_message(domain, artifact)) {
        (Some(Value::String(_)), Some(m)) => m,
        _ => return false,
    };
    let pin = pinned_pq.filter(|p| p.is_string()).map(|p| (pinned_pk, p));
    verify_pinned_suite(artifact.get("alg"), pinned_pk, artifact.get("pq_pk"), &msg, artifact.get("sig"), artifact.get("pq_sig"), pin).unwrap_or(false)
}

/// `artifactRef(refDomain, slot, artifact)` = b64u(sha256(strictCanonical({d, [slot]: artifact}))).
pub(crate) fn artifact_ref(ref_domain: &str, slot: &str, artifact: &Value) -> Option<String> {
    let mut m = Map::new();
    m.insert("d".into(), Value::String(ref_domain.into()));
    m.insert(slot.into(), artifact.clone());
    hash_canonical_strict(&Value::Object(m))
}

/// `hashCanonical(v)` (strict); None where the reference throws.
pub(crate) fn digest_of(v: &Value) -> Option<String> {
    hash_canonical_strict(v)
}

/// Sort strings by their UTF-8 bytes (`compareUtf8`).
pub(crate) fn sort_utf8(xs: &mut [String]) {
    xs.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
}
