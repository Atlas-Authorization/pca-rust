//! Ternary decision, tighten-only model rule (rule 21) and units check (rule 20): a port of packages/pca/src/decision.ts
//! (the TypeScript is authoritative; goal-to-decision track T2, contracts C-50..C-55). `deny < escalate < allow`; `meet` is the
//! only combinator, so `escalate` never becomes `allow`. Every function is total; anything malformed fails closed.

use super::intent_v2::js_value_string;
use super::predicates::{evaluate_condition_tri, Ctx, Tri};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

fn rank(d: &str) -> Option<u8> {
    match d {
        "deny" => Some(0),
        "escalate" => Some(1),
        "allow" => Some(2),
        _ => None,
    }
}

/// The lower of two decisions; an unknown value is `deny`.
pub fn meet<'a>(a: &'a str, b: &'a str) -> &'a str {
    match (rank(a), rank(b)) {
        (Some(x), Some(y)) => {
            if x <= y {
                a
            } else {
                b
            }
        }
        _ => "deny",
    }
}

/// The meet over a list (`allow` for the empty list, the neutral element).
pub fn meet_all<'a>(ds: &[&'a str]) -> &'a str {
    ds.iter().fold("allow", |acc, d| meet(acc, *d))
}

/// The highest decision a model signal permits (anything but `ok` / `escalate` is `deny`).
pub fn signal_ceiling(s: &Value) -> &'static str {
    match s.as_str() {
        Some("ok") => "allow",
        Some("escalate") => "escalate",
        _ => "deny",
    }
}

/// G-T9: a model can only move a decision down.
pub fn tighten<'a>(base: &'a str, signal: &Value) -> &'a str {
    meet(base, signal_ceiling(signal))
}

/// `d === 'escalate' && answered === true ? 'allow' : d`: anything but an answered escalate is returned UNCHANGED, whatever `d`
/// is (as the reference does).
pub fn pep_decision<'a>(d: &'a str, answered: bool) -> &'a str {
    if d == "escalate" && answered {
        "allow"
    } else {
        d
    }
}

const ESCALATE_PREFIXES: [&str; 2] = ["intent_required:", "escalate:"];

/// The ternary decision of a verdict `{allow, checks, reasons}`.
pub fn decision_of(v: &Value) -> &'static str {
    if v.get("allow") == Some(&Value::Bool(true)) {
        return "allow";
    }
    let checks = match v.get("checks").and_then(Value::as_object) {
        Some(c) => c,
        None => return "deny",
    };
    let empty = vec![];
    let reasons = v.get("reasons").and_then(Value::as_array).unwrap_or(&empty);
    let mut failing = 0;
    for (name, status) in checks {
        if status.as_str() != Some("fail") {
            continue;
        }
        failing += 1;
        let head = format!("{name}: ");
        let mut own = 0;
        for r in reasons {
            if let Some(s) = r.as_str() {
                if let Some(body) = s.strip_prefix(&head) {
                    own += 1;
                    if !ESCALATE_PREFIXES.iter().any(|p| body.starts_with(p)) {
                        return "deny";
                    }
                }
            }
        }
        if own == 0 {
            return "deny";
        }
    }
    if failing > 0 {
        "escalate"
    } else {
        "deny"
    }
}

fn is_model_derived(path: &str, single: &[String]) -> bool {
    let seg: Vec<&str> = path.split('.').collect();
    if seg[0] != "env" || seg.len() < 2 {
        return false;
    }
    if matches!(seg[1], "class" | "prov" | "judge" | "detect") {
        return true;
    }
    if seg[1] == "world" {
        return if seg.len() == 2 {
            !single.is_empty()
        } else {
            single.iter().any(|s| s == seg[2])
        };
    }
    false
}

fn collect_cond_paths(c: &Value, out: &mut BTreeSet<String>, depth: usize) {
    let o = match c.as_object() {
        Some(o) if depth <= 64 => o,
        _ => return,
    };
    for k in ["all_of", "any_of"] {
        if let Some(xs) = o.get(k).and_then(Value::as_array) {
            for x in xs {
                collect_cond_paths(x, out, depth + 1);
            }
        }
    }
    if let Some(n) = o.get("not") {
        if !n.is_null() {
            collect_cond_paths(n, out, depth + 1);
        }
    }
    for k in ["field", "ref", "collection"] {
        if let Some(s) = o.get(k).and_then(Value::as_str) {
            out.insert(s.to_string());
        }
    }
}

fn collect_predicate_paths(
    lists: &[Value],
    in_scope: &dyn Fn(&Value) -> bool,
    out: &mut BTreeSet<String>,
) {
    for l in lists {
        if let Some(arr) = l.as_array() {
            for p in arr {
                if !in_scope(p) {
                    continue;
                }
                if let Some(w) = p.get("where").and_then(Value::as_array) {
                    for c in w {
                        collect_cond_paths(c, out, 0);
                    }
                }
            }
        }
    }
}

/// `s.length` of a JavaScript string: UTF-16 code units.
fn u16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// The pattern the reference prints in its reasons (`NAME_RE.source`).
const NAME_SOURCE: &str = "^[a-z][a-z0-9_]{0,63}$";
const MAX_TIGHTEN_RULES: usize = 64;

/// `^[a-z][a-z0-9_]{0,63}$` (no trailing newline allowed).
fn is_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// `^action\.params\.[A-Za-z0-9_-]{1,64}$`.
fn is_param_path(s: &str) -> bool {
    match s.strip_prefix("action.params.") {
        Some(n) => {
            !n.is_empty()
                && n.len() <= 64
                && n.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        }
        None => false,
    }
}

/// `Object.keys` order of a parsed JSON object: canonical array-index keys first (ascending), then the rest in text order
/// (the crate keeps insertion order: serde_json `preserve_order`).
fn js_keys(o: &Map<String, Value>) -> Vec<&String> {
    fn array_index(k: &str) -> Option<u64> {
        let b = k.as_bytes();
        if k == "0" {
            return Some(0);
        }
        if b.is_empty() || b.len() > 10 || b[0] == b'0' || !b.iter().all(u8::is_ascii_digit) {
            return None;
        }
        k.parse::<u64>().ok().filter(|n| *n < 4_294_967_295)
    }
    let mut idx: Vec<(u64, &String)> = o
        .keys()
        .filter_map(|k| array_index(k).map(|n| (n, k)))
        .collect();
    idx.sort_by_key(|(n, _)| *n);
    let mut out: Vec<&String> = idx.into_iter().map(|(_, k)| k).collect();
    out.extend(o.keys().filter(|k| array_index(k).is_none()));
    out
}

/// The reference closedMembers: the first unknown member (in `Object.keys` order), then the first missing required one, named
/// `<where>.<member>`.
fn closed(
    o: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
    wher: &str,
) -> Option<String> {
    for k in js_keys(o) {
        if !required.contains(&k.as_str()) && !optional.contains(&k.as_str()) {
            return Some(format!("unknown member '{wher}.{k}'"));
        }
    }
    required
        .iter()
        .find(|k| !o.contains_key(**k))
        .map(|k| format!("missing member '{wher}.{k}'"))
}

/// `Number.isSafeInteger(v) && !Object.is(v, -0)` of a parsed JSON number (2.0 is the number 2).
fn is_safe_int(v: &Value) -> Option<f64> {
    let f = v.as_f64()?;
    (f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 && !(f == 0.0 && f.is_sign_negative()))
        .then_some(f)
}

/// The reference tightenListError. `t` is `None` for an ABSENT member (well-formed); a JSON null is present and is not an array.
fn tighten_list_error(t: Option<&Value>) -> Option<String> {
    let t = t?;
    let arr = match t.as_array() {
        Some(a) => a,
        None => return Some("tighten must be an array".into()),
    };
    if arr.len() > MAX_TIGHTEN_RULES {
        return Some(format!("tighten has more than {MAX_TIGHTEN_RULES} rules"));
    }
    let mut ids = BTreeSet::new();
    for (i, r) in arr.iter().enumerate() {
        let o = match r.as_object() {
            Some(o) => o,
            None => return Some(format!("tighten[{i}] must be an object")),
        };
        if let Some(e) = closed(
            o,
            &["id", "when", "signal"],
            &["reason"],
            &format!("tighten[{i}]"),
        ) {
            return Some(e);
        }
        match o["id"].as_str() {
            Some(id) if is_name(id) => {
                if !ids.insert(id.to_string()) {
                    return Some(format!("tighten[{i}].id '{id}' is a duplicate"));
                }
            }
            _ => return Some(format!("tighten[{i}].id must match {NAME_SOURCE}")),
        }
        if !o["when"].is_object() {
            return Some(format!("tighten[{i}].when must be a condition object"));
        }
        if !matches!(o["signal"].as_str(), Some("escalate") | Some("deny")) {
            return Some(format!("tighten[{i}].signal must be 'escalate' or 'deny'"));
        }
        if let Some(rs) = o.get("reason") {
            if !rs.as_str().is_some_and(|s| u16_len(s) <= 256) {
                return Some(format!(
                    "tighten[{i}].reason must be a string of at most 256 characters"
                ));
            }
        }
    }
    None
}

/// The outcome of rule 21. `reason` is the reference's, byte for byte (`None` on `ok`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TightenResult {
    pub outcome: &'static str,
    pub legacy: bool,
    pub offending: Vec<String>,
    pub reason: Option<String>,
}

/// Rule 21 over `{predicates, tighten, polarity, single_source, context}`. Total. A JSON null `tighten` or `polarity` is
/// PRESENT (malformed), never read as absent.
pub fn decide_tighten(input: &Value) -> TightenResult {
    let deny = |off: Vec<String>, why: String| TightenResult {
        outcome: "deny",
        legacy: false,
        offending: off,
        reason: Some(why),
    };
    let single: Vec<String> = input
        .get("single_source")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let pol = input.get("polarity");
    if pol.is_some_and(|p| p.as_str() != Some("legacy")) {
        return deny(
            vec![],
            "model_polarity must be 'legacy' when present".into(),
        );
    }
    let tl = input.get("tighten");
    if let Some(e) = tighten_list_error(tl) {
        return deny(vec![], format!("malformed tighten list: {e}"));
    }
    let mut paths = BTreeSet::new();
    if let Some(ps) = input.get("predicates").and_then(Value::as_array) {
        collect_predicate_paths(ps, &|_| true, &mut paths);
    }
    // BTreeSet<String> orders by UTF-8 bytes
    let offending: Vec<String> = paths
        .into_iter()
        .filter(|p| is_model_derived(p, &single))
        .collect();
    let legacy = pol.is_some() && !offending.is_empty();
    if !offending.is_empty() && !legacy {
        let why = format!(
            "a grant's where reads model-derived path(s) {}: a model may only tighten (move them into tighten[]) (rule 21)",
            offending.join(", ")
        );
        return deny(offending, why);
    }
    let empty = json!({});
    let ctx_v = input
        .get("context")
        .filter(|c| c.is_object())
        .unwrap_or(&empty);
    let ctx = Ctx::new(ctx_v);
    let mut out = "ok";
    let mut reason: Option<String> = None;
    if let Some(rules) = tl.and_then(Value::as_array) {
        for r in rules {
            let id = r["id"].as_str().unwrap_or_default();
            let (sig, why) = match evaluate_condition_tri(&r["when"], &ctx) {
                Tri::True => {
                    let sig = r["signal"].as_str().unwrap_or("deny");
                    let mut why = format!("{} tighten rule '{id}'", if sig == "deny" { "denied by" } else { "escalate: asked by" });
                    if let Some(x) = r.get("reason").and_then(Value::as_str) {
                        why.push_str(&format!(" ({x})"));
                    }
                    (sig, why)
                }
                Tri::Unknown => ("escalate", format!("escalate: rule '{id}' could not be decided (a value it reads is missing or ill-typed)")),
                Tri::False => continue,
            };
            if rank(signal_ceiling(&Value::String(sig.into()))).unwrap_or(0)
                < rank(signal_ceiling(&Value::String(out.into()))).unwrap_or(0)
            {
                out = if sig == "deny" { "deny" } else { "escalate" };
                reason = Some(why);
            }
        }
    }
    TightenResult {
        outcome: out,
        legacy,
        offending,
        reason,
    }
}

/// Every model-derived env path a list of predicate lists reads (`field`, `ref` or `collection` of any nested condition), sorted
/// by UTF-8 byte order and de-duplicated; `single` names the worlds decided by one oracle.
pub fn model_paths_read(predicate_lists: &[Value], single: &[String]) -> Vec<String> {
    let mut found = BTreeSet::new();
    collect_predicate_paths(predicate_lists, &|_| true, &mut found);
    found
        .into_iter()
        .filter(|p| is_model_derived(p, single))
        .collect()
}

/// The reference unitTagsError (keys are visited in `Object.keys` order).
fn unit_tags_error(u: Option<&Value>) -> Option<String> {
    let m = match u.and_then(Value::as_object) {
        Some(m) => m,
        None => return Some("units must be an object".into()),
    };
    if m.len() > 64 {
        return Some("units has more than 64 entries".into());
    }
    for k in js_keys(m) {
        let x = &m[k.as_str()];
        if !is_param_path(k) {
            return Some(format!(
                "units key '{k}' must be an action.params.<name> path"
            ));
        }
        let t = match x.as_object() {
            Some(t) => t,
            None => return Some(format!("units['{k}'] must be an object")),
        };
        if let Some(e) = closed(
            t,
            &["kind"],
            &["currency", "exponent"],
            &format!("units['{k}']"),
        ) {
            return Some(e);
        }
        if !t["kind"]
            .as_str()
            .is_some_and(|s| (1..=64).contains(&u16_len(s)))
        {
            return Some(format!(
                "units['{k}'].kind must be a string of 1..64 characters"
            ));
        }
        if let Some(c) = t.get("currency") {
            if !c.as_str().is_some_and(|s| (1..=16).contains(&u16_len(s))) {
                return Some(format!(
                    "units['{k}'].currency must be a string of 1..16 characters"
                ));
            }
        }
        if let Some(e) = t.get("exponent") {
            if !is_safe_int(e).is_some_and(|f| (0.0..=18.0).contains(&f)) {
                return Some(format!(
                    "units['{k}'].exponent must be an integer in [0, 18]"
                ));
            }
        }
    }
    None
}

/// JavaScript `===` over parsed JSON values (two parsed arrays / objects are never identical).
fn strict_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Array(_) | Value::Object(_), _) | (_, Value::Array(_) | Value::Object(_)) => false,
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        _ => a == b,
    }
}

/// `a.kind === b.kind && a.currency === b.currency && a.exponent === b.exponent` (an absent member equals only an absent one).
fn same_tag(a: &Map<String, Value>, b: &Map<String, Value>) -> bool {
    ["kind", "currency", "exponent"]
        .iter()
        .all(|k| match (a.get(*k), b.get(*k)) {
            (None, None) => true,
            (Some(x), Some(y)) => strict_eq(x, y),
            _ => false,
        })
}

/// The reference tagText: `<kind ?? '?'>[/<currency>][/e<exponent>]`, or `no unit` for no tag.
fn tag_text(t: Option<&Map<String, Value>>) -> String {
    let t = match t {
        Some(t) => t,
        None => return "no unit".into(),
    };
    let mut s = match t.get("kind") {
        None | Some(Value::Null) => "?".to_string(),
        Some(k) => js_value_string(k),
    };
    if let Some(c) = t.get("currency") {
        s.push('/');
        s.push_str(&js_value_string(c));
    }
    if let Some(e) = t.get("exponent") {
        s.push_str("/e");
        s.push_str(&js_value_string(e));
    }
    s
}

/// Rule 20: the policy's unit tags must equal the unit the action schema declares for each parameter. `Err` carries the
/// reference's reason, byte for byte.
pub fn decide_units(input: &Value) -> Result<(), String> {
    if let Some(e) = unit_tags_error(input.get("units")) {
        return Err(e);
    }
    let tags = input["units"].as_object().unwrap();
    let verb = match input.get("verb").and_then(Value::as_str) {
        Some(v) if !v.is_empty() => v,
        _ => return Err("the verb is missing".into()),
    };
    let empty = Map::new();
    let su = match input.get("schema_units") {
        None => &empty, // absent; an explicit null is NOT absent
        Some(v) => v
            .as_object()
            .ok_or("the schema units table must be an object")?,
    };
    let params = input
        .get("verb_params")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("the schema does not declare verb '{verb}'"))?;
    let declared = |path: &str| -> (bool, Option<&Map<String, Value>>) {
        match params.get(path).and_then(Value::as_object) {
            None => (false, None),
            Some(d) => (
                true,
                d.get("unit")
                    .and_then(Value::as_str)
                    .and_then(|id| su.get(id))
                    .and_then(Value::as_object),
            ),
        }
    };
    // the reference visits `Object.keys(tags).sort()`: UTF-16 order, and the keys are ASCII once unit_tags_error passed
    let mut sorted_tags: Vec<(&String, &Value)> = tags.iter().collect();
    sorted_tags.sort_by(|a, b| a.0.cmp(b.0));
    for (p, t) in sorted_tags {
        let (has, tag) = declared(p);
        if !has {
            continue;
        }
        let policy = t.as_object().unwrap();
        match tag {
            Some(tag) if same_tag(tag, policy) => {}
            _ => {
                return Err(format!(
                    "'{p}' is declared as {} by the action schema but the policy term is tagged {} (unit confusion)",
                    tag_text(tag),
                    tag_text(Some(policy))
                ))
            }
        }
    }
    let mut read = BTreeSet::new();
    if let Some(ps) = input.get("predicates").and_then(Value::as_array) {
        collect_predicate_paths(
            ps,
            &|p| match p.get("verb") {
                Some(Value::String(v)) => v == "*" || v == verb,
                Some(Value::Array(a)) => a.iter().any(|x| x.as_str() == Some(verb)),
                _ => false,
            },
            &mut read,
        );
    }
    for p in read.iter().filter(|s| is_param_path(s)) {
        let (has, tag) = declared(p);
        if has && tag.is_some() && !tags.contains_key(p) {
            return Err(format!(
                "a policy term reads '{p}' ({}) without a unit tag",
                tag_text(tag)
            ));
        }
    }
    Ok(())
}

/// One reported intent-v2 check: its name, whether it passed and (a failing one) its reason, if it has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2CheckResult {
    pub name: String,
    pub ok: bool,
    pub reason: Option<String>,
}

/// The ordered reason list of a verdict (decision.ts `foldV2Reasons`): `base` (the core's own reasons), then one
/// `<check>: <reason>` for EVERY failing intent-v2 check not already listed, in pipeline order. A failing check with no reason
/// adds nothing (`decision_of` then reads it as a hard failure). The core keeps only its first failure, so without this fold a
/// multi-check escalation would look like a deny.
pub fn fold_v2_reasons(base: &[String], v2: &[V2CheckResult]) -> Vec<String> {
    let mut out: Vec<String> = base.to_vec();
    for c in v2 {
        if c.ok {
            continue;
        }
        if let Some(r) = &c.reason {
            let line = format!("{}: {}", c.name, r);
            if !out.contains(&line) {
                out.push(line);
            }
        }
    }
    out
}
