//! Operational side of the action kit (native port of lint, business rules, selectors and the signed confirmation, undo,
//! packs and the transparency log entry, the hosted registry, sync, approval-render wrappers, the example runner, review and
//! the authoring YAML load / emit of the reference @atlasauth/pca-actions). JSON-valued: `&Value` in, `Result<Value, String>` out.
//! Everything else the kit needs (derive, diff, evolve, author) lives in sibling modules; `deps` is the one seam to them.

use crate::actions::ActionKitError;
use serde_json::Value;
use std::cmp::Ordering;

pub mod deps;
pub mod effective;
pub mod hosted;
pub mod lint;
pub mod pack;
pub mod render;
pub mod review;
pub mod rules;
pub mod selector;
pub mod sync;
pub mod templates;
pub mod test_runner;
pub mod undo;
pub mod yaml;
pub mod yaml_emit;
pub mod yaml_load;

/// The caller's confirmation verifier (`attestationVerified`): absent means nothing is confirmed.
pub type Verifier<'a> = Option<&'a dyn Fn(&Value) -> bool>;

pub(crate) fn kerr(code: &str, message: impl Into<String>) -> ActionKitError {
    ActionKitError { code: code.into(), message: message.into() }
}

pub(crate) fn u16cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

pub(crate) fn sort_u16(v: &mut [String]) {
    v.sort_by(|a, b| u16cmp(a, b));
}

/// Sorted (UTF-16 order) distinct strings.
pub(crate) fn sort_uniq16(xs: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut v: Vec<String> = xs.into_iter().collect();
    sort_u16(&mut v);
    v.dedup();
    v
}

pub(crate) fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// `Number.isSafeInteger` (a `-0` is a safe integer here; see [`negzero`]).
pub(crate) fn isi(v: &Value) -> bool {
    v.as_f64().is_some_and(|x| x.is_finite() && x.fract() == 0.0 && x.abs() <= 9_007_199_254_740_991.0)
}

pub(crate) fn negzero(v: &Value) -> bool {
    v.as_f64().is_some_and(|x| x == 0.0 && x.is_sign_negative())
}

/// A safe integer that is not `-0` and is >= 0.
pub(crate) fn nonneg(v: &Value) -> bool {
    isi(v) && !negzero(v) && v.as_f64().is_some_and(|x| x >= 0.0)
}

/// The integer value of a safe-integer number.
pub(crate) fn int_of(v: &Value) -> i64 {
    v.as_f64().map_or(0, |x| x as i64)
}

pub(crate) fn js_str(v: &Value) -> String {
    crate::intent_v2::js_value_string(v)
}

pub(crate) fn js_opt(v: Option<&Value>) -> String {
    v.map_or_else(|| "undefined".to_string(), js_str)
}

pub(crate) fn strs_of(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

pub(crate) fn jstrs(xs: &[String]) -> Value {
    Value::Array(xs.iter().map(|x| Value::String(x.clone())).collect())
}

/// ECMAScript `String.prototype.trim` / `\s` set.
pub(crate) fn js_trim(s: &str) -> &str {
    s.trim_matches(crate::action_schema::is_js_ws)
}

/// Map a kit error to the message the reference's `Error.message` carries.
pub(crate) fn msg(e: ActionKitError) -> String {
    e.message
}
