//! Self-explaining PCA decisions (`@atlasauth/pca-explain`): the verifier's per-check result, the Policy VM decision and a
//! delegation chain become precise, human-readable explanations plus text renderers. Everything is pure and read-only: it
//! consumes the real shapes of the core, never re-authorizes anything, and degrades a malformed input to a best-effort
//! explanation.
//!
//! Inputs and explanations are plain JSON trees (`serde_json::Value`); an explanation holds exactly the members of the reference's
//! explanation objects (an `undefined` member is absent). The JavaScript value semantics (`String(x)`, `JSON.stringify`,
//! `Number(x)`, relational comparison, truthiness, property reads on any value, `Object.keys` order) are reproduced where an
//! untrusted field reaches them, so a hostile shape yields the same text, or the same refusal (`Err`) where the reference throws.
//! A string cut at 400 UTF-16 units that splits a surrogate pair carries U+FFFD (a Rust `String` cannot hold a lone surrogate).

use crate::oauth::{js_str, truthy as truthy_opt};
use crate::predicates::{first_unmet_limit, predicate_matches, Ctx};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::cmp::Ordering;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::sync::OnceLock;

/// The cap of an explanation text field (UTF-16 units).
pub const MAX_TEXT: usize = 400;

/// The normative order of the offline verification checks.
pub const VERIFY_CHECK_ORDER: [&str; 9] =
    ["wire", "version", "audience", "validity", "cap_chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format"];

fn check_title(name: &str) -> Option<&'static str> {
    Some(match name {
        "wire" => "wire format",
        "version" => "version",
        "audience" => "audience binding",
        "validity" => "freshness window",
        "cap_chain" => "capability chain",
        "grant_ref_bound" => "grant reference binding",
        "plan_inclusion" => "plan inclusion",
        "leaf_signature" => "leaf signature",
        "counter_format" | "counter" => "counter format",
        "replay" => "replay",
        "plan_root_authorized" => "plan-root authorization",
        "taint_gate" => "taint gate",
        "attestation" => "agent attestation",
        "threshold" => "threshold signature",
        "revocation" => "revocation",
        "zk_compliance" => "zk compliance",
        "bond" => "bond",
        "malformed" => "structure",
        _ => return None,
    })
}

// ---- JavaScript value semantics ---------------------------------------------------------------------------------------------

/// A JavaScript value: `None` is `undefined`, `Some(Value::Null)` is `null`.
type J = Option<Value>;

/// A reference throw (a TypeError); raised with `resume_unwind` so no panic hook runs.
struct Thrown(String);

fn throw(msg: &str) -> ! {
    resume_unwind(Box::new(Thrown(msg.to_string())))
}

/// Run `f`, mapping a reference throw (or any panic) to an `Err`.
fn try_js<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|e| {
        if let Some(t) = e.downcast_ref::<Thrown>() {
            t.0.clone()
        } else if let Some(s) = e.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = e.downcast_ref::<String>() {
            s.clone()
        } else {
            "explain: internal error".to_string()
        }
    })
}

fn len16(s: &str) -> usize {
    s.encode_utf16().count()
}

fn slice16(s: &str, a: usize, b: usize) -> String {
    let u: Vec<u16> = s.encode_utf16().collect();
    let b = b.min(u.len());
    let a = a.min(b);
    char::decode_utf16(u[a..b].iter().copied()).map(|r| r.unwrap_or('\u{FFFD}')).collect()
}

fn is_js_ws(c: char) -> bool {
    crate::action_schema::is_js_ws(c)
}

fn js_trim(s: &str) -> &str {
    s.trim_matches(is_js_ws)
}

fn idx_key(k: &str) -> Option<usize> {
    if k.len() > 9 {
        return None;
    }
    let n: usize = k.parse().ok()?;
    (n.to_string() == k).then_some(n)
}

/// `Object.keys` order: array-index keys ascending, then the rest in insertion order.
fn js_keys(m: &Map<String, Value>) -> Vec<String> {
    let mut idx: Vec<(usize, &String)> = m.keys().filter_map(|k| idx_key(k).map(|n| (n, k))).collect();
    idx.sort();
    idx.into_iter().map(|(_, k)| k.clone()).chain(m.keys().filter(|k| idx_key(k).is_none()).cloned()).collect()
}

/// `o[k]` without throwing: undefined for an absent member or a value without members.
fn get_in(o: Option<&Value>, k: &str) -> J {
    match o? {
        Value::Object(m) => m.get(k).cloned(),
        Value::Array(a) => {
            if k == "length" {
                Some(Value::from(a.len()))
            } else {
                idx_key(k).and_then(|n| a.get(n).cloned())
            }
        }
        Value::String(s) => {
            if k == "length" {
                Some(Value::from(len16(s)))
            } else {
                idx_key(k).filter(|n| *n < len16(s)).map(|n| Value::String(slice16(s, n, n + 1)))
            }
        }
        _ => None,
    }
}

fn g(o: &J, k: &str) -> J {
    get_in(o.as_ref(), k)
}

fn gv(o: &Value, k: &str) -> J {
    get_in(Some(o), k)
}

/// `o[k]` where `o` must not be null or undefined (a TypeError otherwise).
fn rd(o: &J, k: &str) -> J {
    match o {
        None | Some(Value::Null) => throw(&format!("Cannot read properties of {} (reading '{k}')", if o.is_none() { "undefined" } else { "null" })),
        _ => g(o, k),
    }
}

/// `Object.keys(o)`.
fn keys_of(o: &J) -> Vec<String> {
    match o {
        Some(Value::Object(m)) => js_keys(m),
        Some(Value::Array(a)) => (0..a.len()).map(|i| i.to_string()).collect(),
        Some(Value::String(s)) => (0..len16(s)).map(|i| i.to_string()).collect(),
        _ => vec![],
    }
}

fn is_obj(v: &J) -> bool {
    matches!(v, Some(Value::Object(_)) | Some(Value::Array(_)))
}

fn truthy(v: &J) -> bool {
    truthy_opt(v.as_ref())
}

/// `a ?? b`.
fn nn(a: J, b: J) -> J {
    match a {
        None | Some(Value::Null) => b,
        a => a,
    }
}

fn sj(s: &str) -> J {
    Some(Value::String(s.to_string()))
}

fn eq_str(v: &J, s: &str) -> bool {
    matches!(v, Some(Value::String(x)) if x == s)
}

/// `String(x)`.
fn st(v: &J) -> String {
    match v {
        None => "undefined".into(),
        Some(v) => js_str(v),
    }
}

/// `${JSON.stringify(x)}` (undefined stringifies to the text "undefined").
fn jsons(v: &J) -> String {
    match v {
        None => "undefined".into(),
        Some(v) => crate::js_stringify(v),
    }
}

fn to_num(v: &J) -> f64 {
    crate::actions::js_to_number(v.as_ref())
}

fn num_str(f: f64) -> String {
    crate::intent_v2::js_number_string(f)
}

fn is_fin(v: &J) -> bool {
    matches!(v, Some(Value::Number(n)) if n.as_f64().is_some_and(f64::is_finite))
}

fn jnum(f: f64) -> Value {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.0e15 {
        Value::from(f as i64)
    } else {
        serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)
    }
}

fn put(m: &mut Map<String, Value>, k: &str, v: J) {
    if let Some(v) = v {
        m.insert(k.to_string(), v);
    }
}

/// The compact number of an explanation: integers stay integers, fractions round to 4 dp; anything else prints as `String(x)`.
fn n(x: &J) -> String {
    if !is_fin(x) {
        return st(x);
    }
    nf(to_num(x))
}

fn nf(f: f64) -> String {
    if !f.is_finite() {
        return num_str(f);
    }
    if f == f.floor() {
        return num_str(f);
    }
    let y = f * 1e4;
    let fl = y.floor();
    let r = if y - fl >= 0.5 { fl + 1.0 } else { fl };
    num_str(r / 1e4)
}

fn prim(v: &J) -> J {
    match v {
        Some(Value::Array(_)) => Some(Value::String(st(v))),
        Some(Value::Object(_)) => sj("[object Object]"),
        _ => v.clone(),
    }
}

fn u16_lt(a: &str, b: &str) -> bool {
    a.encode_utf16().cmp(b.encode_utf16()) == Ordering::Less
}

fn lt(a: &J, b: &J) -> bool {
    let (pa, pb) = (prim(a), prim(b));
    if let (Some(Value::String(x)), Some(Value::String(y))) = (&pa, &pb) {
        return u16_lt(x, y);
    }
    to_num(&pa) < to_num(&pb)
}

fn le(a: &J, b: &J) -> bool {
    let (pa, pb) = (prim(a), prim(b));
    if let (Some(Value::String(x)), Some(Value::String(y))) = (&pa, &pb) {
        return !u16_lt(y, x);
    }
    to_num(&pa) <= to_num(&pb)
}

fn gt(a: &J, b: &J) -> bool {
    lt(b, a)
}

/// `!(a <= b + k)` (a string or array `b` makes the sum a concatenation); a NaN side is outside the allowance, never inside it.
fn gt_plus(a: &J, b: &J, k: i64) -> bool {
    match prim(b) {
        Some(Value::String(x)) => !le(a, &sj(&format!("{x}{k}"))),
        pb => !(to_num(&prim(a)) <= to_num(&pb) + k as f64),
    }
}

/// `for (const x of v)`: an array's elements or a string's code points; anything else throws.
fn iter_of(v: &J) -> Vec<Value> {
    match v {
        Some(Value::Array(a)) => a.clone(),
        Some(Value::String(s)) => s.chars().map(|c| Value::String(c.to_string())).collect(),
        _ => throw("value is not iterable"),
    }
}

/// `v.slice(k)` of an array or string.
fn slice_from(v: &J, k: usize) -> J {
    match v {
        Some(Value::Array(a)) => Some(Value::Array(a.get(k..).map(<[Value]>::to_vec).unwrap_or_default())),
        Some(Value::String(s)) => Some(Value::String(slice16(s, k, usize::MAX))),
        _ => throw("slice is not a function"),
    }
}

/// `v.includes(needle)` of a string (substring) or an array (element equality); anything else throws.
fn includes(v: &Value, needle: &str) -> bool {
    match v {
        Value::String(s) => s.contains(needle),
        Value::Array(a) => a.iter().any(|x| matches!(x, Value::String(s) if s == needle)),
        _ => throw("includes is not a function"),
    }
}

// ---- cleanText --------------------------------------------------------------------------------------------------------------

// the JavaScript `\s` class, for use inside a bracket class
const WS: &str = r"\t\n\x0b\x0c\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}";

fn clean_patterns() -> &'static Vec<(Regex, &'static str)> {
    static P: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    P.get_or_init(|| {
        let mk = |s: String| Regex::new(&s).expect("explain pattern");
        vec![
            (mk(r"(?-u:\b)eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*".to_string()), "[redacted]"),
            (mk(format!(r"(?-u:\b)((?i-u:Bearer|Basic|Token))[{WS}]+[A-Za-z0-9_.~+/=-]{{6,}}")), "${1} [redacted]"),
            (mk(format!(r"((?i-u:[a-z][a-z0-9+.-]*)://)[^{WS}/@]*:[^{WS}/@]*@")), "${1}[redacted]@"),
            (
                mk(format!(
                    r#"(?-u:\b)((?i-u:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|authorization|auth)["']?[{WS}]*[:=][{WS}]*)("[^"]*"|'[^']*'|[^{WS}"'&,;]+)"#
                )),
                "${1}[redacted]",
            ),
            (mk(r"[A-Za-z0-9_-]{40,}".to_string()), "[redacted]"),
        ]
    })
}

/// Remove what looks like a credential from text built out of untrusted fields (JWTs, bearer credentials, URL userinfo,
/// `token=` style pairs, long unbroken token runs); the result is cut to 400 UTF-16 units. A net, not a proof.
pub fn clean_str(text: &str) -> String {
    let mut t = text.to_string();
    for (rx, rep) in clean_patterns() {
        t = rx.replace_all(&t, *rep).into_owned();
    }
    if len16(&t) > MAX_TEXT {
        format!("{}...", slice16(&t, 0, MAX_TEXT))
    } else {
        t
    }
}

/// `cleanText(text)` for any JSON value (`String(text)` first).
pub fn clean_text(text: &Value) -> String {
    clean_str(&js_str(text))
}

fn clean(v: &J) -> String {
    clean_str(&st(v))
}

// ---- shared helpers ---------------------------------------------------------------------------------------------------------

fn short(key: &J) -> String {
    match key {
        Some(Value::String(s)) if !s.is_empty() => {
            if len16(s) <= 11 {
                s.clone()
            } else {
                format!("{}…", slice16(s, 0, 10))
            }
        }
        _ => "<none>".into(),
    }
}

/// A caveat's non-`type` fields, in `Object.keys` order.
type Rest = Vec<(String, Value)>;

fn rest_get(r: &Rest, k: &str) -> J {
    r.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone())
}

fn value_summary(rest: &Rest) -> String {
    rest.iter()
        .take(6)
        .map(|(k, v)| {
            let shown = if matches!(v, Value::Array(_) | Value::Object(_)) { crate::js_stringify(v) } else { n(&Some(v.clone())) };
            format!("{k}={shown}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn caveat_parts(cv: &J) -> (String, Rest) {
    let typ = match g(cv, "type") {
        Some(Value::String(s)) => s,
        _ => "<malformed>".to_string(),
    };
    let mut rest = Rest::new();
    if is_obj(cv) {
        for k in keys_of(cv) {
            if k != "type" {
                if let Some(v) = g(cv, &k) {
                    rest.push((k, v));
                }
            }
        }
    }
    (typ, rest)
}

fn cond_to_text(c: &J, depth: usize) -> String {
    if !is_obj(c) {
        return "<malformed>".into();
    }
    if depth > 6 {
        return "…".into();
    }
    if let Some(Value::Object(m)) = c {
        if let Some(Value::Array(l)) = m.get("all_of") {
            return format!("({})", l.iter().map(|x| cond_to_text(&Some(x.clone()), depth + 1)).collect::<Vec<_>>().join(" AND "));
        }
        if let Some(Value::Array(l)) = m.get("any_of") {
            return format!("({})", l.iter().map(|x| cond_to_text(&Some(x.clone()), depth + 1)).collect::<Vec<_>>().join(" OR "));
        }
        if let Some(x) = m.get("not") {
            return format!("NOT {}", cond_to_text(&Some(x.clone()), depth + 1));
        }
    }
    let operand = match g(c, "ref") {
        Some(r) => format!("→{}", js_str(&r)),
        None => match c {
            Some(Value::Object(m)) if m.contains_key("value") => n(&m.get("value").cloned()),
            _ => String::new(),
        },
    };
    js_trim(&format!("{} {} {}", st(&g(c, "field")), st(&g(c, "op")), operand)).to_string()
}

fn where_summary(wh: &J) -> String {
    match wh {
        Some(Value::Array(l)) if !l.is_empty() => l.iter().map(|c| cond_to_text(&Some(c.clone()), 0)).collect::<Vec<_>>().join(" AND "),
        _ => "any (no where-bound)".into(),
    }
}

// ---- explainVerification ----------------------------------------------------------------------------------------------------

struct Pin {
    detail: String,
    remedy: String,
    hop: Option<f64>,
}

fn reason_tail(name: &str, vr: &J) -> Option<String> {
    match g(vr, "reason") {
        Some(Value::String(r)) => r.strip_prefix(&format!("{name}: ")).map(str::to_string),
        _ => None,
    }
}

fn validity_pinpoint(p: &J, now: &J) -> Pin {
    let (exp, iat) = (g(p, "exp"), g(p, "iat"));
    let lifetime = to_num(&exp) - to_num(&iat);
    if !gt(&exp, &iat) {
        return Pin {
            detail: format!("exp {} ≤ iat {}: empty validity window", st(&exp), st(&iat)),
            remedy: "set exp strictly greater than iat.".into(),
            hop: None,
        };
    }
    if lifetime > crate::MAX_LIFETIME_MS as f64 {
        return Pin {
            detail: format!("lifetime {}ms exceeds the {}ms maximum", num_str(lifetime), crate::MAX_LIFETIME_MS),
            remedy: format!("shorten the window to ≤ {}ms (buildPCActn ttlMs).", crate::MAX_LIFETIME_MS),
            hop: None,
        };
    }
    if now.is_some() {
        if gt_plus(&iat, now, crate::MAX_SKEW_MS) {
            return Pin {
                detail: format!(
                    "iat {} is {}ms in the future (> {}ms clock-skew allowance)",
                    st(&iat),
                    num_str(to_num(&iat) - to_num(now)),
                    crate::MAX_SKEW_MS
                ),
                remedy: "fix the signer clock; do not pre-date actions.".into(),
                hop: None,
            };
        }
        if !le(now, &exp) {
            return Pin {
                detail: format!("expired {}ms ago (exp {}, now {})", num_str(to_num(now) - to_num(&exp)), st(&exp), st(now)),
                remedy: "build a fresh action — a PCActn lifetime is short by design.".into(),
                hop: None,
            };
        }
    }
    Pin { detail: "validity window invalid".into(), remedy: "build a fresh action with a valid iat/exp window.".into(), hop: None }
}

fn hop_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"hop ([0-9]+)").expect("hop pattern"))
}

fn cap_chain_pinpoint(p: &J) -> Pin {
    let reason = match g(p, "cap_chain") {
        Some(Value::Array(chain)) => match crate::verify_chain(&chain, None) {
            Ok(()) => "chain root is not the grant this verifier expects".to_string(),
            Err(why) => why,
        },
        _ => "cap_chain is not an array".to_string(),
    };
    let remedy = if reason.contains("root issuer") || reason.contains("not the grant") {
        "root the chain at the principal key that minted the grant."
    } else if reason.contains("widens") {
        "a child budget_alloc may not exceed its parent’s carried allocation; lower the sub-allocation."
    } else if reason.contains("caveat") {
        "attenuation is append-only: never drop, reorder or edit a parent caveat."
    } else if reason.contains("signature") {
        "re-sign that hop with the parent holder’s secret key (and matching alg/pq_pk for a PQ suite)."
    } else {
        "rebuild the chain: each hop must be signed by the parent’s bound holder and may only APPEND caveats."
    };
    let hop = hop_re().captures(&reason).and_then(|m| m[1].parse::<f64>().ok());
    Pin { detail: reason, remedy: remedy.into(), hop }
}

fn leaf_sig_pinpoint(p: &J) -> Pin {
    let chain = match g(p, "cap_chain") {
        Some(Value::Array(c)) => Some(c),
        _ => None,
    };
    let idx: i64 = chain.as_ref().map_or(-1, |c| c.len() as i64 - 1);
    let leaf: J = if idx >= 0 { chain.as_ref().map(|c| c[idx as usize].clone()) } else { None };
    let alg = nn(g(p, "alg"), sj("ed25519"));
    let remedy = "sign thresholdMessage(body) with the LEAF holder’s secret key; for a PQ/hybrid suite set alg + pq_pk/pq_sig to match the holder.";
    if !truthy(&leaf) {
        return Pin { detail: "no leaf capability to check the signature against (empty/invalid chain)".into(), remedy: remedy.into(), hop: None };
    }
    Pin {
        detail: format!("leaf hop #{idx} signature (holder {}, suite {}) does not verify", short(&g(&leaf, "holder")), st(&alg)),
        remedy: remedy.into(),
        hop: (idx >= 0).then_some(idx as f64),
    }
}

fn pinpoint(name: &str, p: &J, vr: &J, now: &J) -> Pin {
    let tail = reason_tail(name, vr);
    let or = |d: String| tail.clone().unwrap_or(d);
    let (action, plan) = (g(p, "action"), g(p, "plan"));
    let plain = |detail: String, remedy: String| Pin { detail, remedy, hop: None };
    match name {
        "wire" => plain(
            or("wire structure / strict-canonical-form check failed".into()),
            "do not hand-edit the wire JSON; re-encode via encodePCActn with the current SDK.".into(),
        ),
        "version" => plain(
            or(format!("unsupported ver {} (verifier requires {})", n(&g(p, "ver")), crate::PCACTN_WIRE_VERSION)),
            format!("re-mint the action at wire version {}.", crate::PCACTN_WIRE_VERSION),
        ),
        "audience" => plain(
            or(format!("aud {} does not match this resource server / instance", jsons(&g(p, "aud")))),
            "build the action with aud = this verifier’s instance id (or verify with audience:null to accept any).".into(),
        ),
        "validity" => {
            let v = validity_pinpoint(p, now);
            plain(or(v.detail), v.remedy)
        }
        "cap_chain" => {
            let c = cap_chain_pinpoint(p);
            Pin { detail: or(c.detail), remedy: c.remedy, hop: c.hop }
        }
        "grant_ref_bound" => plain(
            or(format!("grant_ref {} is not the id of the root capability in cap_chain", short(&g(p, "grant_ref")))),
            "set grant_ref to the id of the chain root (cap_chain[0].id); buildPCActn does this from the grant.".into(),
        ),
        "plan_inclusion" => plain(
            or(format!(
                "action (verb {} on {}) is not node {} of committed plan {}",
                jsons(&g(&action, "verb")),
                jsons(&g(&action, "resource")),
                jsons(&g(&plan, "node_id")),
                short(&g(&plan, "root"))
            )),
            "rebuild the PCActn from a committed plan node whose verb/resource/params match (buildPCActn).".into(),
        ),
        "leaf_signature" => {
            let l = leaf_sig_pinpoint(p);
            Pin { detail: or(l.detail), remedy: l.remedy, hop: l.hop }
        }
        "counter" | "counter_format" => plain(
            or(format!("counter {} is missing or not a non-negative safe integer", n(&g(p, "counter")))),
            "use a strictly increasing per-holder counter; a repeated counter is a replay.".into(),
        ),
        "malformed" => {
            plain(or("the PCActn is structurally malformed".into()), "rebuild the action with the SDK; do not construct the wire object by hand.".into())
        }
        _ => plain(or(format!("{name} check failed")), format!("satisfy the {name} requirement (supply the corresponding verifier hook / proof).")),
    }
}

fn pass_detail(name: &str, p: &J) -> String {
    match name {
        "wire" => "wire structure + strict canonical form valid".into(),
        "version" => format!("ver {} supported", n(&g(p, "ver"))),
        "audience" => format!("aud {} matches this resource server", jsons(&g(p, "aud"))),
        "validity" => format!("fresh: iat/exp window valid (lifetime {}s)", nf((to_num(&g(p, "exp")) - to_num(&g(p, "iat"))) / 1000.0)),
        "cap_chain" => {
            let chain = match g(p, "cap_chain") {
                Some(Value::Array(c)) => c,
                _ => vec![],
            };
            format!("{}-hop chain verifies; root issuer {}", chain.len(), short(&chain.first().and_then(|r| gv(r, "issuer"))))
        }
        "grant_ref_bound" => format!("grant_ref {} is the id of the chain root", short(&g(p, "grant_ref"))),
        "plan_inclusion" => {
            let plan = g(p, "plan");
            format!("action is node {} of committed plan {}", jsons(&g(&plan, "node_id")), short(&g(&plan, "root")))
        }
        "leaf_signature" => {
            let leaf = match g(p, "cap_chain") {
                Some(Value::Array(c)) => c.last().cloned(),
                _ => None,
            };
            format!("leaf holder {} signature valid (suite {})", short(&g(&leaf, "holder")), st(&nn(g(p, "alg"), sj("ed25519"))))
        }
        "counter" | "counter_format" => format!("counter {} well-formed", n(&g(p, "counter"))),
        _ => "ok".into(),
    }
}

fn clean_check(c: &Map<String, Value>) -> Map<String, Value> {
    let mut out = c.clone();
    out.insert("detail".into(), Value::String(clean(&c.get("detail").cloned())));
    out
}

fn build_verification(verdict: &str, checks: &[Map<String, Value>], decisive: Option<Map<String, Value>>, summary: String) -> Value {
    let names_where = |status: &str| -> Value {
        Value::Array(checks.iter().filter(|c| matches!(c.get("status"), Some(Value::String(s)) if s == status)).map(|c| c["name"].clone()).collect())
    };
    let mut out = Map::new();
    out.insert("kind".into(), json!("verification"));
    out.insert("verdict".into(), json!(verdict));
    out.insert("allow".into(), json!(verdict == "allow"));
    out.insert("checks".into(), Value::Array(checks.iter().cloned().map(Value::Object).collect()));
    out.insert("passed".into(), names_where("pass"));
    out.insert("failed".into(), names_where("fail"));
    out.insert("notEnforced".into(), names_where("not-enforced"));
    if let Some(d) = decisive {
        out.insert("decisive".into(), Value::Object(d));
    }
    out.insert("summary".into(), json!(summary));
    Value::Object(out)
}

fn denied_verification(why: &str) -> Value {
    let mut e = Map::new();
    e.insert("name".into(), json!("malformed"));
    e.insert("status".into(), json!("fail"));
    e.insert("title".into(), json!("structure"));
    e.insert("detail".into(), json!(why));
    e.insert("remedy".into(), json!("pass the PCActn and the verifier result you verified."));
    e.insert("decisive".into(), json!(true));
    build_verification("deny", &[e.clone()], Some(e), format!("Denied: {why}"))
}

/// Walk the normative checks of an offline verification in order: summarize what held for each pass and pinpoint the first
/// failing check (which hop, which audience mismatch, which validity sub-case, ...) with a concrete remedy. `opts` may carry
/// `now` (epoch ms) to tell "expired" from "clock skew" precisely. A malformed input is a denial, never a refusal.
pub fn explain_verification(pcactn: &Value, verify_result: &Value, opts: &Value) -> Value {
    if !is_obj(&Some(pcactn.clone())) || !is_obj(&Some(verify_result.clone())) {
        return denied_verification("the PCActn or the verifier result is missing");
    }
    match try_js(|| verification_inner(&Some(pcactn.clone()), &Some(verify_result.clone()), &Some(opts.clone()))) {
        Ok(v) => v,
        Err(_) => denied_verification("the PCActn or the verifier result is malformed"),
    }
}

fn verification_inner(p: &J, vr: &J, opts: &J) -> Value {
    let statuses = nn(g(vr, "checks"), Some(json!({})));
    let mut ordered: Vec<String> = VERIFY_CHECK_ORDER.iter().map(|s| s.to_string()).collect();
    for k in keys_of(&statuses) {
        if !ordered.contains(&k) {
            ordered.push(k);
        }
    }
    let decisive_name = ordered.iter().find(|nm| eq_str(&g(&statuses, nm), "fail")).cloned();
    let mut checks: Vec<Map<String, Value>> = vec![];
    let mut decisive: Option<Map<String, Value>> = None;
    for name in &ordered {
        let status = nn(g(&statuses, name), sj("skipped"));
        let title = check_title(name).map_or_else(|| name.clone(), str::to_string);
        let mut entry = Map::new();
        let status_s = match &status {
            Some(Value::String(s)) => s.as_str(),
            _ => "",
        };
        let (detail, remedy, hop) = match status_s {
            "fail" => {
                let pin = pinpoint(name, p, vr, &rd(opts, "now"));
                (pin.detail, Some(pin.remedy), pin.hop)
            }
            "pass" => (pass_detail(name, p), None, None),
            "not-enforced" => ("not enforced by this verifier (no hook / opt-out)".to_string(), None, None),
            "unsupported" => ("the PCActn carries a feature this verifier does not implement (never a pass)".to_string(), None, None),
            _ => ("not reached (a terminal earlier check stopped evaluation)".to_string(), None, None),
        };
        entry.insert("name".into(), json!(name));
        put(&mut entry, "status", status.clone());
        entry.insert("title".into(), json!(title));
        entry.insert("detail".into(), json!(detail));
        if let Some(r) = remedy {
            entry.insert("remedy".into(), json!(r));
        }
        if let Some(h) = hop {
            entry.insert("hop".into(), jnum(h));
        }
        if decisive_name.as_deref() == Some(name.as_str()) {
            entry.insert("decisive".into(), json!(true));
            decisive = Some(entry.clone());
        }
        checks.push(entry);
    }

    // Allow only on an explicit `allow: true` that no check contradicts and that carries per-check statuses.
    let has_checks = matches!(g(vr, "checks"), Some(Value::Object(_)));
    let allow_claimed = matches!(g(vr, "allow"), Some(Value::Bool(true)));
    let claimed = allow_claimed && has_checks;
    let contradicted = claimed && decisive_name.is_some();
    let verdict = if claimed && !contradicted { "allow" } else { "deny" };
    let summary = if verdict == "allow" {
        let passed = checks.iter().filter(|c| matches!(c.get("status"), Some(Value::String(s)) if s == "pass")).count();
        format!("All {passed} evaluated checks passed (no check failed).")
    } else if allow_claimed && !has_checks {
        "Denied: the verifier result carries no per-check statuses (an allow without evidence is treated as a denial).".to_string()
    } else if contradicted {
        let t = decisive.as_ref().map(|d| st(&d.get("title").cloned())).or_else(|| decisive_name.clone()).unwrap_or_default();
        format!("Denied: the verifier result says allow but the \"{t}\" check failed (inconsistent result, treated as a denial).")
    } else if let Some(d) = &decisive {
        format!("Denied at the \"{}\" check: {}", st(&d.get("title").cloned()), st(&d.get("detail").cloned()))
    } else if let Some(Value::String(r)) = g(vr, "reason") {
        format!("Denied: {r}")
    } else {
        "Denied: a check failed".to_string()
    };
    let cleaned: Vec<Map<String, Value>> = checks.iter().map(clean_check).collect();
    build_verification(verdict, &cleaned, decisive.as_ref().map(clean_check), clean_str(&summary))
}

fn glyph(status: &J) -> &'static str {
    match status {
        Some(Value::String(s)) => match s.as_str() {
            "pass" => "✓",
            "fail" => "✗",
            "not-enforced" => "·",
            "unsupported" => "?",
            "skipped" => "–",
            _ => "undefined",
        },
        _ => "undefined",
    }
}

fn pad_end(s: &str, w: usize) -> String {
    let l = len16(s);
    if l < w {
        format!("{s}{}", " ".repeat(w - l))
    } else {
        s.to_string()
    }
}

/// Render a verification explanation (`toText`).
pub fn verification_to_text(e: &Value) -> Result<String, String> {
    try_js(|| {
        let e = Some(e.clone());
        let mut lines = vec![format!("PCA verification — {}", st(&g(&e, "verdict")).to_uppercase()), st(&g(&e, "summary")), String::new()];
        for c in iter_of(&g(&e, "checks")) {
            let c = Some(c);
            let dec = truthy(&g(&c, "decisive"));
            let mark = if dec { " ◀ DECISIVE" } else { "" };
            lines.push(format!("  {} {} {}{}", glyph(&g(&c, "status")), pad_end(&st(&g(&c, "name")), 16), st(&g(&c, "detail")), mark));
            if dec && truthy(&g(&c, "remedy")) {
                lines.push(format!("      ↳ fix: {}", st(&g(&c, "remedy"))));
            }
        }
        lines.join("\n")
    })
}

// ---- explainDecision --------------------------------------------------------------------------------------------------------

fn caveat_remedy(typ: &str, r: &Rest) -> String {
    let gr = |k: &str| rest_get(r, k);
    match typ {
        "expires" => format!("the grant expired at {} (epoch ms); obtain a fresh grant or re-mint with a later 'expires'.", n(&gr("at"))),
        "not_before" => format!("the grant is not valid until {} (epoch ms); retry after that time.", n(&gr("at"))),
        "rate" => format!("rate limit {}/{}s reached; wait for the window to clear or raise the 'rate' caveat.", n(&gr("max")), n(&gr("per_secs"))),
        "max_blast_radius" => format!("the action's blast radius exceeds the caveat max {}; narrow the action or raise 'max_blast_radius'.", n(&gr("max"))),
        "reversibility_max" => format!("the action is more severe than the allowed class '{}'; only that class or lower is permitted.", st(&gr("class"))),
        "delegation_depth" => format!("delegation depth exceeds max {}; act from a shallower hop or raise 'delegation_depth'.", n(&gr("max"))),
        _ => format!("caveat '{typ}' is not satisfied; check its parameters against the action/context."),
    }
}

fn caveat_detail(typ: &str, r: &Rest, satisfied: &J) -> String {
    let bound = value_summary(r);
    let verb = if truthy(satisfied) { "held" } else { "NARROWED/DENIED" };
    if bound.is_empty() {
        format!("{typ} {verb}")
    } else {
        format!("{typ}({bound}) {verb}")
    }
}

fn failed_caveats_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"caveat\(s\) not satisfied: ([^\n\r\x{2028}\x{2029}]+)\z").expect("caveat pattern"))
}

fn failed_caveat_types(reasons: &[Value]) -> Vec<String> {
    let mut out = vec![];
    for r in reasons {
        if let Some(m) = failed_caveats_re().captures(&js_str(r)) {
            for t in m[1].split(',') {
                let t = js_trim(t);
                if !t.is_empty() {
                    out.push(t.to_string());
                }
            }
        }
    }
    out
}

fn risk_band(r: &J, theta1: &J, theta2: &J, tier: &J) -> String {
    if theta1.is_none() || theta2.is_none() {
        return format!("effective tier t={}", st(tier));
    }
    if le(r, theta1) {
        return format!("r {} ≤ θ1 {} → claim band (t=1)", n(r), n(theta1));
    }
    if le(r, theta2) {
        return format!("θ1 {} < r {} ≤ θ2 {} → standard band (t=2)", n(theta1), n(r), n(theta2));
    }
    format!("r {} > θ2 {} → strong band (t=3)", n(r), n(theta2))
}

fn no_decision(reason: &str) -> Value {
    json!({"admit": false, "needStepUp": false, "releaseGuardianShare": false, "r": 1,
        "requiredThreshold": {"t": 3, "proof": "human", "optimisticAllowed": false},
        "budget": {"B": 0, "tau": 0, "asOf": 0}, "reasons": [reason]})
}

/// Explain a Policy-VM decision: which predicate granted the (verb, resource) and under what `where` bound, which caveat narrowed
/// or denied (type and offending value), the risk band and the admission path; for anything short of auto-admit the single
/// decisive reason and remedy. `opts` may carry `envelope` and `context` (`{action, caveat, chain}`; `caveat` is the evaluator's
/// context in camelCase: `now`, `blastRadius`, `reversibilityClass`, `delegationDepth`, `recentActionTimes`). A missing or
/// malformed decision is a denial, never an allow. `Err` only where the reference throws (a null `opts`).
pub fn explain_decision(pcactn: &Value, decision: &Value, opts: &Value) -> Result<Value, String> {
    let _ = pcactn;
    try_js(|| {
        let d = Some(decision.clone());
        if !is_obj(&d) || !is_obj(&g(&d, "requiredThreshold")) {
            return decision_inner(&Some(no_decision("no policy decision supplied (default-deny)")), &Some(opts.clone()));
        }
        match try_js(|| decision_inner(&d, &Some(opts.clone()))) {
            Ok(v) => v,
            Err(_) => decision_inner(&Some(no_decision("the policy decision could not be explained (default-deny)")), &Some(json!({}))),
        }
    })
}

enum PredOut {
    Matched(usize, Value),
    Denied(String),
}

/// `evaluatePredicates(predicates, ctx)` with the matched predicate's index.
fn eval_predicates(preds: &J, act: &Value) -> PredOut {
    let r = catch_unwind(AssertUnwindSafe(|| {
        crate::safe_regex::with_regex_budget(|| {
            let arr = match preds {
                Some(Value::Array(a)) if !a.is_empty() => a,
                _ => return PredOut::Denied("envelope grants no predicates".into()),
            };
            let ctx = Ctx::new(act);
            for (i, p) in arr.iter().enumerate() {
                if predicate_matches(p, &ctx) {
                    return PredOut::Matched(i, p.clone());
                }
            }
            let a = act.get("action");
            let (v, rs) = (st(&get_in(a, "verb")), st(&get_in(a, "resource")));
            match first_unmet_limit(arr, &ctx) {
                Some(l) => PredOut::Denied(format!("{l} not satisfied for {v} on {rs}")),
                None => PredOut::Denied(format!("no predicate permits {v} on {rs}")),
            }
        })
    }));
    r.unwrap_or_else(|_| PredOut::Denied("predicate evaluation error (fail closed)".into()))
}

/// `evaluateAgentCaveats([cv], caveatCtx, actionCtx).ok`: the reference's camelCase context mapped onto the evaluator's.
fn eval_caveat(cv: &Value, cav_ctx: &J, act_ctx: &J) -> bool {
    let inner = match g(act_ctx, "action") {
        Some(v @ Value::Object(_)) => v,
        _ => json!({}),
    };
    let mut c = Map::new();
    for (src, dst) in [
        ("now", "now"),
        ("delegationDepth", "delegation_depth"),
        ("blastRadius", "blast_radius"),
        ("reversibilityClass", "reversibility_class"),
        ("recentActionTimes", "recent_action_times"),
    ] {
        put(&mut c, dst, g(cav_ctx, src));
    }
    c.insert("action".into(), inner.clone());
    let mut tc = Map::new();
    tc.insert("tool".into(), Value::String(if let Some(Value::String(v)) = gv(&inner, "verb") { v } else { String::new() }));
    tc.insert("args".into(), if let Some(p @ Value::Object(_)) = gv(&inner, "params") { p } else { json!({}) });
    if let Some(b @ Value::String(_)) = g(act_ctx, "toolBinding") {
        tc.insert("toolSignatureDigest".into(), b);
    }
    let actx = match act_ctx {
        Some(v @ Value::Object(_)) => v.clone(),
        _ => json!({}),
    };
    crate::evaluate_agent_caveats(&Value::Array(vec![cv.clone()]), &Value::Object(c), Some(&actx), Some(&Value::Object(tc))).0
}

fn decision_inner(decision: &J, opts: &J) -> Value {
    let env = rd(opts, "envelope");
    let ctx = nn(g(opts, "context"), Some(json!({})));
    let reasons: Vec<Value> = match g(decision, "reasons") {
        Some(Value::Array(a)) => a,
        _ => vec![],
    };

    let admitted = matches!(g(decision, "admit"), Some(Value::Bool(true)));
    let rgs = g(decision, "releaseGuardianShare");
    let disposition = if admitted {
        "auto-admit"
    } else if matches!(rgs, Some(Value::Bool(true))) {
        "step-up"
    } else {
        "denied"
    };
    let verdict = if admitted { "allow" } else { "deny" };

    // ---- authority: the granting predicate ----
    let mut grant = Map::new();
    put(&mut grant, "granted", rgs.clone());
    let chain = g(&ctx, "chain");
    let root_cap = g(&chain, "0");
    if truthy(&root_cap) {
        put(&mut grant, "capabilityId", g(&root_cap, "id"));
    }
    let (ctx_action, ctx_caveat) = (g(&ctx, "action"), g(&ctx, "caveat"));
    let has_env = truthy(&env);
    if has_env && truthy(&ctx_action) {
        let preds = g(&env, "predicates");
        let act = match &ctx_action {
            Some(v @ Value::Object(_)) => v.clone(),
            _ => json!({}),
        };
        match eval_predicates(&preds, &act) {
            PredOut::Matched(i, p) => {
                grant.insert("granted".into(), json!(true));
                grant.insert("where".into(), json!(where_summary(&gv(&p, "where"))));
                grant.insert("predicate".into(), p);
                grant.insert("predicateIndex".into(), json!(i));
            }
            PredOut::Denied(reason) => {
                grant.insert("granted".into(), json!(false));
                grant.insert("reason".into(), json!(reason));
            }
        }
    } else if !truthy(&rgs) {
        for r in &reasons {
            if includes(r, "predicate") || includes(r, "not permitted") {
                grant.insert("reason".into(), r.clone());
                break;
            }
        }
    }

    // ---- caveats: per-caveat outcome ----
    let failed_from_reasons = failed_caveat_types(&reasons);
    let can_eval = env.is_some() && ctx_caveat.is_some() && ctx_action.is_some();
    let grant_caveats = nn(g(&env, "caveats"), Some(json!([])));
    let chain0 = g(&chain, "0");
    let mut root_count = 0usize;
    if !matches!(chain0, None | Some(Value::Null)) {
        match rd(&chain0, "caveats") {
            None | Some(Value::Null) => throw("Cannot read properties of undefined (reading 'length')"),
            Some(Value::Array(a)) => root_count = a.len(),
            Some(Value::String(s)) => root_count = len16(&s),
            _ => {}
        }
    }
    let mut delegated: J = Some(json!([]));
    if let Some(Value::Array(cl)) = &chain {
        if cl.len() > 1 {
            let leaf_cvs = nn(gv(&cl[cl.len() - 1], "caveats"), Some(json!([])));
            delegated = slice_from(&leaf_cvs, root_count);
        }
    }
    let classify = |cv: &Value, is_delegated: bool| -> Map<String, Value> {
        let (typ, rest) = caveat_parts(&Some(cv.clone()));
        let satisfied: J = if can_eval && truthy(&ctx_caveat) && truthy(&ctx_action) {
            Some(Value::Bool(eval_caveat(cv, &ctx_caveat, &ctx_action)))
        } else if failed_from_reasons.contains(&typ) {
            Some(Value::Bool(false))
        } else {
            rgs.clone()
        };
        let mut out = Map::new();
        out.insert("type".into(), json!(typ));
        put(&mut out, "satisfied", satisfied.clone());
        out.insert("value".into(), Value::Object(rest.iter().cloned().collect()));
        out.insert("detail".into(), json!(caveat_detail(&typ, &rest, &satisfied)));
        out.insert("delegated".into(), json!(is_delegated));
        if !truthy(&satisfied) {
            out.insert("remedy".into(), json!(caveat_remedy(&typ, &rest)));
        }
        out
    };
    let mut caveats: Vec<Map<String, Value>> = vec![];
    for cv in iter_of(&grant_caveats) {
        caveats.push(classify(&cv, false));
    }
    for cv in iter_of(&delegated) {
        caveats.push(classify(&cv, true));
    }

    // ---- risk / tier ----
    let rt = g(decision, "requiredThreshold");
    let r = g(decision, "r");
    let env_nn = !matches!(env, None | Some(Value::Null));
    let risk_policy: J = if env_nn {
        let rp = rd(&env, "risk_policy");
        if matches!(rp, None | Some(Value::Null)) {
            throw("Cannot read properties of undefined (reading 'theta1')");
        }
        rp
    } else {
        None
    };
    let (theta1, theta2) = (g(&risk_policy, "theta1"), g(&risk_policy, "theta2"));
    let (tier, proof, optimistic) = (g(&rt, "t"), g(&rt, "proof"), g(&rt, "optimisticAllowed"));
    let mut risk = Map::new();
    put(&mut risk, "r", r.clone());
    put(&mut risk, "tier", tier.clone());
    put(&mut risk, "proof", proof.clone());
    put(&mut risk, "optimisticAllowed", optimistic);
    risk.insert("band".into(), json!(risk_band(&r, &theta1, &theta2, &tier)));
    if has_env {
        put(&mut risk, "theta1", theta1);
        put(&mut risk, "theta2", theta2);
    }

    // ---- admission / budget ----
    let kappa = if env_nn { g(&risk_policy, "kappa") } else { None };
    let cost_val: J = kappa.as_ref().map(|k| {
        let rf = match &r {
            Some(Value::Number(x)) => x.as_f64().filter(|f| f.is_finite()).unwrap_or(1.0),
            _ => 1.0,
        };
        let kf = match k {
            Value::Number(x) => x.as_f64().unwrap_or(0.0),
            _ => 0.0,
        };
        jnum(crate::risk::cost(rf, kf))
    });
    let budget_depleted = reasons.iter().any(|x| includes(x, "budget depleted"));
    let path = if admitted {
        format!("auto-admitted at t={} ({}); metered", st(&tier), st(&proof))
    } else if !truthy(&rgs) {
        "guardian share withheld — policy not satisfied (no autonomous or guardian path)".to_string()
    } else if budget_depleted {
        "trust budget cannot cover the cost — step-up to t=3 (human recharge) required".to_string()
    } else {
        format!("step-up to t={} ({}) co-signature required", st(&tier), st(&proof))
    };
    let mut admission = Map::new();
    admission.insert("admit".into(), json!(admitted));
    put(&mut admission, "needStepUp", g(decision, "needStepUp"));
    put(&mut admission, "releaseGuardianShare", rgs.clone());
    put(&mut admission, "budget", g(decision, "budget"));
    admission.insert("path".into(), json!(path));
    put(&mut admission, "cost", cost_val.clone());
    put(&mut admission, "kappa", kappa.clone());

    // ---- the single decisive reason ----
    let mut decisive: Option<Map<String, Value>> = None;
    if !admitted {
        let mut d = Map::new();
        if !truthy(&grant.get("granted").cloned()) {
            d.insert(
                "reason".into(),
                nn(grant.get("reason").cloned(), sj("action not permitted by the envelope predicates (default-deny)")).unwrap_or(Value::Null),
            );
            d.insert("remedy".into(), json!("grant a predicate that permits this verb+resource (and satisfies its where bound)."));
        } else if let Some(ff) = caveats.iter().find(|c| !truthy(&c.get("satisfied").cloned())) {
            d.insert(
                "reason".into(),
                json!(format!("caveat '{}' narrowed the authority away: {}", st(&ff.get("type").cloned()), st(&ff.get("detail").cloned()))),
            );
            if truthy(&ff.get("remedy").cloned()) {
                d.insert("remedy".into(), ff["remedy"].clone());
            }
        } else if budget_depleted {
            let c = cost_val.as_ref().map_or(String::new(), |c| format!("={}", n(&Some(c.clone()))));
            d.insert("reason".into(), json!(format!("risk {} is admissible but the trust budget cannot cover cost κ·r{}", n(&r), c)));
            d.insert("remedy".into(), json!("recharge the budget with a human co-sign, or lower the action risk."));
        } else {
            let rem = if matches!(&tier, Some(Value::Number(t)) if t.as_f64() == Some(3.0)) {
                "obtain a human step-up co-signature."
            } else {
                "obtain the guardian/principal co-signature for this tier."
            };
            d.insert("reason".into(), json!(format!("risk {} exceeds the auto threshold → step-up to t={} ({})", n(&r), st(&tier), st(&proof))));
            d.insert("remedy".into(), json!(rem));
        }
        decisive = Some(d);
    }

    let summary = if admitted {
        let who =
            if truthy(&grant.get("predicate").cloned()) { format!("predicate #{}", st(&grant.get("predicateIndex").cloned())) } else { "policy".to_string() };
        format!("Auto-admitted: {who} grants it, all caveats held, risk r={} is in the t={} band and the budget covers it.", n(&r), st(&tier))
    } else if let Some(d) = &decisive {
        let w = if verdict == "deny" && disposition == "denied" { "Denied" } else { "Needs step-up" };
        format!("{w}: {}", st(&d.get("reason").cloned()))
    } else {
        format!("Not auto-admitted (t={}).", st(&tier))
    };

    let cleaned_caveats: Vec<Value> = caveats
        .iter()
        .map(|c| {
            let mut cc = c.clone();
            cc.insert("detail".into(), json!(clean(&c.get("detail").cloned())));
            Value::Object(cc)
        })
        .collect();
    let mut out = Map::new();
    out.insert("kind".into(), json!("decision"));
    out.insert("verdict".into(), json!(verdict));
    out.insert("disposition".into(), json!(disposition));
    out.insert("grant".into(), Value::Object(grant));
    out.insert("caveats".into(), Value::Array(cleaned_caveats));
    out.insert("risk".into(), Value::Object(risk));
    out.insert("admission".into(), Value::Object(admission));
    if let Some(mut d) = decisive {
        let reason = clean(&d.get("reason").cloned());
        d.insert("reason".into(), json!(reason));
        out.insert("decisive".into(), Value::Object(d));
    }
    out.insert("reasons".into(), Value::Array(reasons.iter().map(|x| json!(clean_text(x))).collect()));
    out.insert("summary".into(), json!(clean_str(&summary)));
    Value::Object(out)
}

/// Render a decision explanation (`toText`).
pub fn decision_to_text(e: &Value) -> Result<String, String> {
    try_js(|| {
        let e = Some(e.clone());
        let mut lines =
            vec![format!("PCA decision — {} ({})", st(&g(&e, "verdict")).to_uppercase(), st(&g(&e, "disposition"))), st(&g(&e, "summary")), String::new()];
        let gr = g(&e, "grant");
        let pred = g(&gr, "predicate");
        if truthy(&g(&gr, "granted")) && truthy(&pred) {
            let verbs = match g(&pred, "verb") {
                Some(Value::Array(l)) => l.iter().map(|x| if x.is_null() { String::new() } else { js_str(x) }).collect::<Vec<_>>().join("|"),
                v => st(&v),
            };
            lines.push(format!(
                "  authority : predicate #{} of grant {} grants {} on {}",
                st(&g(&gr, "predicateIndex")),
                short(&g(&gr, "capabilityId")),
                verbs,
                st(&nn(g(&pred, "resource"), sj("*")))
            ));
            lines.push(format!("              where {}", st(&g(&gr, "where"))));
        } else {
            lines.push(format!("  authority : NOT granted — {}", st(&nn(g(&gr, "reason"), sj("no predicate permits this action")))));
        }
        let cavs = iter_of(&g(&e, "caveats"));
        if cavs.is_empty() {
            lines.push("  caveats   : none".into());
        }
        for c in cavs {
            let c = Some(c);
            let sat = truthy(&g(&c, "satisfied"));
            let src = if truthy(&g(&c, "delegated")) { " [delegated]" } else { "" };
            lines.push(format!("  caveat {}  : {}{}", if sat { "✓" } else { "✗" }, st(&g(&c, "detail")), src));
            if !sat && truthy(&g(&c, "remedy")) {
                lines.push(format!("              ↳ fix: {}", st(&g(&c, "remedy"))));
            }
        }
        let risk = g(&e, "risk");
        lines.push(format!("  risk      : {}; proof={}, optimistic={}", st(&g(&risk, "band")), st(&g(&risk, "proof")), st(&g(&risk, "optimisticAllowed"))));
        let a = g(&e, "admission");
        let cost = g(&a, "cost");
        let cost_str = if cost.is_some() { format!(", cost κ·r={} (κ={})", n(&cost), n(&g(&a, "kappa"))) } else { String::new() };
        lines.push(format!("  budget    : {}{}; B after={}", st(&g(&a, "path")), cost_str, n(&rd(&g(&a, "budget"), "B"))));
        let dec = g(&e, "decisive");
        if truthy(&dec) {
            lines.push(String::new());
            lines.push(format!("  ◀ DECISIVE: {}", st(&g(&dec, "reason"))));
            if truthy(&g(&dec, "remedy")) {
                lines.push(format!("      ↳ fix: {}", st(&g(&dec, "remedy"))));
            }
        }
        lines.join("\n")
    })
}

// ---- explainChain -----------------------------------------------------------------------------------------------------------

fn is_budget_alloc(cv: &J) -> bool {
    is_obj(cv)
        && eq_str(&g(cv, "type"), "budget_alloc")
        && matches!(g(cv, "limit"), Some(Value::Number(x)) if x.as_f64().is_some_and(|f| f.is_finite() && f >= 0.0))
}

/// The per-node budget subtree carried by a chain: one node per well-formed `budget_alloc` caveat, in delegation order. It reads
/// the append-only caveat lineage and does not verify signatures (run `verify_chain` first). `Err` where the reference throws.
pub fn budget_alloc_nodes(chain: &Value) -> Result<Vec<Value>, String> {
    try_js(|| budget_nodes(&Some(chain.clone())))
}

fn budget_nodes(chain: &J) -> Vec<Value> {
    let cl = match chain {
        Some(Value::Array(c)) if !c.is_empty() => c,
        _ => return vec![],
    };
    let leaf_cvs = match rd(&Some(cl[cl.len() - 1].clone()), "caveats") {
        Some(Value::Array(a)) => a,
        _ => return vec![],
    };
    let mut hop = 0usize;
    let mut out = vec![];
    for (ci, cv) in leaf_cvs.iter().enumerate() {
        while hop < cl.len() - 1 {
            let len = match rd(&Some(cl[hop].clone()), "caveats") {
                Some(Value::Array(a)) => a.len(),
                Some(Value::String(s)) => len16(&s),
                _ => 0,
            };
            if len <= ci {
                hop += 1;
            } else {
                break;
            }
        }
        let cvj = Some(cv.clone());
        if !is_budget_alloc(&cvj) {
            continue;
        }
        let intro = Some(cl[hop].clone());
        let Some(cap_id) = rd(&intro, "id") else { throw("canonicalize: undefined member") };
        let np = crate::hash_canonical_strict(&json!({"d": "atlas-pca/budget-node/v1", "cap": cap_id.clone(), "i": ci}))
            .unwrap_or_else(|| throw("canonicalize: value outside the strict profile"));
        let mut node = Map::new();
        node.insert("nodePath".into(), json!(np));
        node.insert("capId".into(), cap_id);
        put(&mut node, "holder", rd(&intro, "holder"));
        node.insert("depth".into(), json!(hop));
        node.insert("caveatIndex".into(), json!(ci));
        node.insert("limit".into(), cv["limit"].clone());
        out.push(Value::Object(node));
    }
    out
}

fn hop_narrowed(is_root: bool, added: &[Value]) -> String {
    let mut bits: Vec<String> = vec![];
    for cv in added {
        let cvj = Some(cv.clone());
        let (typ, rest) = caveat_parts(&cvj);
        if typ == "envelope" {
            let cnt = |k: &str| if let Some(Value::Array(l)) = rest_get(&rest, k) { l.len() } else { 0 };
            bits.push(format!("envelope ({} predicate(s), {} caveat(s))", cnt("predicates"), cnt("caveats")));
        } else if is_budget_alloc(&cvj) {
            bits.push(format!("budget_alloc(B_sub={})", n(&gv(cv, "limit"))));
        } else {
            let bound = value_summary(&rest);
            bits.push(if bound.is_empty() { format!("+{typ}") } else { format!("+{typ}({bound})") });
        }
    }
    if bits.is_empty() {
        return if is_root { "root grant (no caveats)".into() } else { "rebind only (no new caveats)".into() };
    }
    format!("{}{}", if is_root { "grants " } else { "narrows: " }, bits.join(", "))
}

fn chain_inner(chain: &J) -> Map<String, Value> {
    let safe: Vec<Value> = match chain {
        Some(Value::Array(a)) => a.clone(),
        _ => vec![],
    };
    let mut hops: Vec<Value> = vec![];
    for (i, cap) in safe.iter().enumerate() {
        let cap = Some(cap.clone());
        if !truthy(&cap) {
            continue;
        }
        let is_root = i == 0;
        let parent_len = if i > 0 {
            match g(&Some(safe[i - 1].clone()), "caveats") {
                Some(Value::Array(a)) if truthy(&Some(safe[i - 1].clone())) => a.len(),
                _ => 0,
            }
        } else {
            0
        };
        let own: Vec<Value> = match g(&cap, "caveats") {
            Some(Value::Array(a)) => a,
            _ => vec![],
        };
        let added: Vec<Value> = if is_root {
            own
        } else if own.len() >= parent_len {
            own[parent_len..].to_vec()
        } else {
            vec![]
        };
        let budget_cv = added.iter().find(|cv| is_budget_alloc(&Some((*cv).clone())));
        let mut hop = Map::new();
        hop.insert("index".into(), json!(i));
        hop.insert("isRoot".into(), json!(is_root));
        put(&mut hop, "issuer", g(&cap, "issuer"));
        put(&mut hop, "holder", g(&cap, "holder"));
        hop.insert("issuerShort".into(), json!(short(&g(&cap, "issuer"))));
        hop.insert("holderShort".into(), json!(short(&g(&cap, "holder"))));
        put(&mut hop, "alg", nn(g(&cap, "alg"), sj("ed25519")));
        hop.insert("addedCaveats".into(), Value::Array(added.clone()));
        hop.insert("addedCaveatTypes".into(), Value::Array(added.iter().map(|cv| json!(caveat_parts(&Some(cv.clone())).0)).collect()));
        hop.insert("narrowed".into(), json!(clean_str(&hop_narrowed(is_root, &added))));
        if let Some(b) = budget_cv {
            hop.insert("budgetAlloc".into(), b["limit"].clone());
        }
        hops.push(Value::Object(hop));
    }
    let root = safe.first().cloned();
    let leaf = safe.last().cloned();
    let nodes = budget_nodes(&Some(Value::Array(safe.clone())));
    let summary = if safe.is_empty() {
        "empty chain (no authority)".to_string()
    } else {
        format!(
            "{} (principal) delegated through {} hop(s) to the acting holder {}; {} budget node(s).",
            short(&g(&root, "issuer")),
            safe.len() - 1,
            short(&g(&leaf, "holder")),
            nodes.len()
        )
    };
    let mut out = Map::new();
    out.insert("kind".into(), json!("chain"));
    out.insert("depth".into(), json!(safe.len()));
    out.insert("hops".into(), Value::Array(hops));
    put(&mut out, "rootIssuer", g(&root, "issuer"));
    put(&mut out, "leafHolder", g(&leaf, "holder"));
    out.insert("budgetNodes".into(), Value::Array(nodes));
    out.insert("summary".into(), json!(summary));
    out
}

/// Render a delegation chain as an ordered attenuation trace: issuer to holder per hop and what each hop narrowed. With
/// `opts.verify == true` the chain is also checked (`opts.expectedRootIssuer` pins the root issuer); otherwise the trace shows
/// only what the chain claims. `Err` where the reference throws.
pub fn explain_chain(chain: &Value, opts: &Value) -> Result<Value, String> {
    try_js(|| {
        let chain = Some(chain.clone());
        let opts = Some(opts.clone());
        let mut out = chain_inner(&chain);
        if !matches!(rd(&opts, "verify"), Some(Value::Bool(true))) {
            return Value::Object(out);
        }
        let verified = try_js(|| match &chain {
            Some(Value::Array(cl)) => {
                let exp = match g(&opts, "expectedRootIssuer") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) => Some(s),
                    Some(_) => Some("\u{0}non-string".to_string()), // a non-string never matches the root issuer
                };
                match crate::verify_chain(cl, exp.as_deref()) {
                    Ok(()) => (true, None),
                    Err(why) => (false, Some(why)),
                }
            }
            _ => (false, Some("chain is not an array".to_string())),
        })
        .unwrap_or((false, Some("chain could not be verified".to_string())));
        let mut v = Map::new();
        v.insert("ok".into(), json!(verified.0));
        if let Some(why) = verified.1 {
            v.insert("reason".into(), json!(clean_str(&why)));
        }
        out.insert("verification".into(), Value::Object(v));
        Value::Object(out)
    })
}

/// Render a chain explanation (`toText`).
pub fn chain_to_text(e: &Value) -> Result<String, String> {
    try_js(|| {
        let e = Some(e.clone());
        let mut lines = vec![format!("PCA delegation chain — {} hop(s) (attenuation trace)", st(&g(&e, "depth")))];
        let v = g(&e, "verification");
        lines.push(match &v {
            None => "UNVERIFIED: this trace shows what the chain claims; no signature or link was checked.".to_string(),
            Some(_) if matches!(g(&v, "ok"), Some(Value::Bool(true))) => "verified: signatures, links and caveat rules hold.".to_string(),
            Some(_) => format!("NOT VALID: {}", st(&nn(g(&v, "reason"), sj("the chain failed verification")))),
        });
        lines.push(st(&g(&e, "summary")));
        lines.push(String::new());
        for h in iter_of(&g(&e, "hops")) {
            let h = Some(h);
            let tag = if matches!(g(&h, "isRoot"), Some(Value::Bool(true))) { "root " } else { "deleg" };
            lines.push(format!(
                "  #{} {} {} ──▶ {}   {}",
                st(&g(&h, "index")),
                tag,
                st(&g(&h, "issuerShort")),
                st(&g(&h, "holderShort")),
                st(&g(&h, "narrowed"))
            ));
        }
        let nodes = iter_of(&g(&e, "budgetNodes"));
        if !nodes.is_empty() {
            let tree = nodes.iter().map(|nd| format!("depth {} B_sub={}", st(&gv(nd, "depth")), n(&gv(nd, "limit")))).collect::<Vec<_>>().join(" → ");
            lines.push(String::new());
            lines.push(format!("  budget subtree: {tree}"));
        }
        lines.join("\n")
    })
}
