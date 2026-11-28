//! The policy-safety CI gate. It drives the real static analyzer ([`crate::analyzer`]) over a PCA envelope, grant, compiled policy, bare
//! `{predicates, caveats}` or a delegation chain and reports findings: five toggleable rules plus schema mismatch. SOUNDNESS: a hard
//! `error` is emitted only from a PROVEN analyzer verdict; any undecidable feature fails safe to a `warn` / `info` that says so. Also the
//! authoring gates (`diff`, `test`, `coverage`) and the command line ([`run`], [`parse_args`]).
//!
//! JSON-valued like the analyzer: policies, options, findings and results are `serde_json::Value`; `Err(message)` is where the reference
//! throws. JavaScript semantics (own-property reads, `undefined` vs `null`, truthiness, `Number(...)` of a flag) are followed.
//!
//! shortcut: a JSON syntax error in a policy file is worded by the Rust parser, not by the JavaScript engine; the engine-worded message
//! of the reference cannot be reproduced.
use crate::analyzer::{self, Iv, FULL_INTERVAL};
use crate::authorize::read_envelope;
use crate::intent_v2::js_number_string;
use crate::oauth::{js_str, truthy};
use crate::ENVELOPE_CAVEAT;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

type R<T> = Result<T, String>;

pub const DEFAULT_DANGEROUS_VERBS: [&str; 15] =
    ["delete", "destroy", "drop", "remove", "purge", "transfer", "payout", "wire", "withdraw", "admin", "grant", "revoke", "deploy", "shutdown", "rotate"];
pub const SCOPE_NARROWING_CAVEATS: [&str; 5] = ["max_blast_radius", "rate", "reversibility_max", "budget_alloc", "delegation_depth"];
pub const BUDGET_GATE_CAVEATS: [&str; 3] = ["max_blast_radius", "rate", "budget_alloc"];
const SEVERITY_ORDER: [&str; 3] = ["info", "warn", "error"];
static NULL: Value = Value::Null;

// ---- JS helpers -------------------------------------------------------------------------------------------------------------

/// `o[k]` of an object (`None` is `undefined`; a non-object has no members).
fn get<'a>(o: &'a Value, k: &str) -> Option<&'a Value> {
    o.as_object().and_then(|m| m.get(k))
}

/// `o[k]` where reading a member of null throws.
fn jget<'a>(o: &'a Value, k: &str) -> R<Option<&'a Value>> {
    if o.is_null() {
        return Err(format!("Cannot read properties of null (reading '{k}')"));
    }
    Ok(get(o, k))
}

fn objlike(v: &Value) -> bool {
    v.is_object() || v.is_array()
}

fn s(v: Option<&Value>) -> String {
    v.map_or("undefined".to_string(), js_str)
}

fn nn<'a>(v: Option<&'a Value>) -> Option<&'a Value> {
    v.filter(|x| !x.is_null())
}

fn is_str(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(_)))
}

fn is_arr(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Array(_)))
}

fn is_rec(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Object(_)))
}

/// A finite number.
fn finite(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64().filter(|f| f.is_finite()),
        _ => None,
    }
}

fn arr(v: &Value) -> R<&Vec<Value>> {
    v.as_array().ok_or_else(|| "not an array".to_string())
}

fn is_js_ws(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

fn trim(s: &str) -> &str {
    s.trim_matches(is_js_ws)
}

fn find(rule: &str, severity: &str, message: String, where_: Option<String>) -> Value {
    let mut m = Map::new();
    m.insert("rule".into(), json!(rule));
    m.insert("severity".into(), json!(severity));
    m.insert("message".into(), json!(message));
    if let Some(w) = where_ {
        m.insert("where".into(), json!(w));
    }
    Value::Object(m)
}

fn verbs_of(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(x)) => vec![x.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        _ => vec![],
    }
}

/// `verb.toLowerCase()` contains one of the `dangerous` keywords (lower-cased); a non-list or a non-string keyword throws, as the reference does.
fn is_dangerous_verb(verb: &str, dangerous: &Value) -> R<bool> {
    let v = verb.to_lowercase();
    let list = dangerous.as_array().ok_or("dangerous.some is not a function")?;
    for kw in list {
        let k = kw.as_str().ok_or("kw.toLowerCase is not a function")?;
        if v.contains(&k.to_lowercase()) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn is_wildcard_resource(r: Option<&Value>) -> bool {
    matches!(r, None) || matches!(r, Some(Value::String(x)) if x == "*")
}

fn has_caveat_of_type(caveats: &[Value], types: &[&str]) -> bool {
    caveats.iter().any(|c| matches!(get(c, "type"), Some(Value::String(t)) if types.contains(&t.as_str())))
}

fn describe_action(a: &Value) -> String {
    let mut parts = vec![s(get(a, "verb")), s(get(a, "resource"))];
    if let Some(p) = get(a, "params").filter(|p| p.as_object().is_some_and(|m| !m.is_empty())) {
        parts.push(crate::js_stringify(p));
    }
    if let Some(rc) = get(a, "reversibilityClass") {
        parts.push(format!("[{}]", js_str(rc)));
    }
    parts.join(" ")
}

fn uniq(xs: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for x in xs {
        if !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

// ---- normalization ----------------------------------------------------------------------------------------------------------

/// A minted grant / delegation hop: the content-addressed, signed shape of a capability.
pub fn is_capability(x: &Value) -> bool {
    x.is_object() && ["id", "issuer", "holder", "body_digest", "sig"].iter().all(|k| is_str(get(x, k))) && is_arr(get(x, "caveats"))
}

/// A signed policy envelope (the root intent grant payload).
pub fn is_envelope(x: &Value) -> bool {
    x.is_object()
        && is_str(get(x, "goal_commit"))
        && is_arr(get(x, "predicates"))
        && is_arr(get(x, "caveats"))
        && is_rec(get(x, "agent_binding"))
        && is_rec(get(x, "risk_policy"))
}

fn is_compiled(x: &Value) -> bool {
    x.is_object() && is_arr(get(x, "predicates")) && is_arr(get(x, "caveats")) && is_rec(get(x, "riskPolicy")) && is_arr(get(x, "actions"))
}

/// Drops the envelope-carrying caveat; keeps the runtime gate caveats (and any appended attenuation).
fn runtime_caveats(caveats: &[Value]) -> Vec<Value> {
    caveats.iter().filter(|c| objlike(c) && get(c, "type").and_then(Value::as_str) != Some(ENVELOPE_CAVEAT)).cloned().collect()
}

fn pol(predicates: &Value, caveats: Vec<Value>, risk: Option<Value>, kind: &str) -> Value {
    let mut m = Map::new();
    m.insert("predicates".into(), predicates.clone());
    m.insert("caveats".into(), Value::Array(caveats));
    if let Some(r) = risk {
        m.insert("riskPolicy".into(), r);
    }
    m.insert("kind".into(), json!(kind));
    Value::Object(m)
}

fn effective(env: &Map<String, Value>, grant: &Value, kind: &str) -> Value {
    let mut cs = env.get("caveats").and_then(Value::as_array).cloned().unwrap_or_default();
    cs.extend(runtime_caveats(get(grant, "caveats").and_then(Value::as_array).map_or(&[][..], |a| a.as_slice())));
    pol(&env["predicates"], cs, env.get("risk_policy").cloned(), kind)
}

/// Reduces any single-policy input to its effective authority: `{ok: true, policy: {predicates, caveats, riskPolicy?, kind}}` or
/// `{ok: false, reason}`.
pub fn normalize_policy_input(input: &Value) -> Value {
    if is_capability(input) {
        return match read_envelope(input) {
            None => json!({ "ok": false, "reason": "grant has no readable `envelope` caveat (malformed or unsigned payload)" }),
            Some(env) => json!({ "ok": true, "policy": effective(&env, input, "grant") }),
        };
    }
    if is_envelope(input) {
        return json!({ "ok": true, "policy": pol(&input["predicates"], input["caveats"].as_array().cloned().unwrap_or_default(), Some(input["risk_policy"].clone()), "envelope") });
    }
    if is_compiled(input) {
        return json!({ "ok": true, "policy": pol(&input["predicates"], input["caveats"].as_array().cloned().unwrap_or_default(), Some(input["riskPolicy"].clone()), "compiled") });
    }
    if input.is_object() && is_arr(get(input, "predicates")) {
        let c = get(input, "caveats").and_then(Value::as_array).cloned().unwrap_or_default();
        return json!({ "ok": true, "policy": pol(&input["predicates"], c, None, "bare") });
    }
    json!({ "ok": false, "reason": "unrecognized policy shape (expected an envelope, grant, compiled policy, or { predicates, caveats })" })
}

/// Normalizes a delegation chain (root to leaf) to one effective policy per hop: `{ok: true, hops}` or `{ok: false, reason}`.
pub fn normalize_chain(chain: &Value) -> R<Value> {
    let chain = arr(chain)?;
    if chain.is_empty() {
        return Ok(json!({ "ok": false, "reason": "empty chain" }));
    }
    if chain.iter().all(is_capability) {
        let Some(env) = read_envelope(&chain[0]) else { return Ok(json!({ "ok": false, "reason": "root grant has no readable `envelope` caveat" })) };
        let hops: Vec<Value> = chain.iter().map(|cap| effective(&env, cap, "chain-hop")).collect();
        return Ok(json!({ "ok": true, "hops": hops }));
    }
    let mut hops = vec![];
    for (i, c) in chain.iter().enumerate() {
        let r = normalize_policy_input(c);
        if r["ok"] != json!(true) {
            return Ok(json!({ "ok": false, "reason": format!("hop {i}: {}", s(r.get("reason"))) }));
        }
        let mut p = r["policy"].clone();
        p["kind"] = json!("chain-hop");
        hops.push(p);
    }
    Ok(json!({ "ok": true, "hops": hops }))
}

// ---- rules ------------------------------------------------------------------------------------------------------------------

fn analyzer_input(p: &Value) -> Value {
    json!({ "predicates": p["predicates"], "caveats": p["caveats"] })
}

fn caveats_of(p: &Value) -> &[Value] {
    p["caveats"].as_array().map_or(&[][..], |a| a.as_slice())
}

fn predicates_of(p: &Value) -> &[Value] {
    p["predicates"].as_array().map_or(&[][..], |a| a.as_slice())
}

fn declared_verbs(predicates: &[Value]) -> Vec<String> {
    let mut concrete = vec![];
    for p in predicates.iter().filter(|p| objlike(p)) {
        concrete.extend(verbs_of(get(p, "verb")).into_iter().filter(|v| v != "*"));
    }
    uniq(concrete)
}

fn gate_description(policy: &Value) -> Option<String> {
    let mut gates: Vec<String> = vec![];
    let cs = caveats_of(policy);
    if has_caveat_of_type(cs, &BUDGET_GATE_CAVEATS) {
        let names: Vec<String> = cs
            .iter()
            .filter(|c| matches!(get(c, "type"), Some(Value::String(t)) if BUDGET_GATE_CAVEATS.contains(&t.as_str())))
            .map(|c| s(get(c, "type")))
            .collect();
        gates.push(names.join("/"));
    }
    if let Some(rp) = nn(get(policy, "riskPolicy")) {
        if finite(get(rp, "theta2")).is_some_and(|t| t < 1.0) {
            gates.push("risk step-up (theta2 < 1)".into());
        }
    }
    (!gates.is_empty()).then(|| gates.join(", "))
}

fn rule_over_broad_grant(policy: &Value, dangerous: &Value, opts: &Value) -> R<Vec<Value>> {
    let mut out = vec![];
    let inp = analyzer_input(policy);
    let scope_narrowing = has_caveat_of_type(caveats_of(policy), &SCOPE_NARROWING_CAVEATS);
    for (i, p) in predicates_of(policy).iter().enumerate() {
        if !objlike(p) {
            continue;
        }
        let verbs = verbs_of(get(p, "verb"));
        let where_ = format!("predicates[{i}]");
        let has_where = matches!(get(p, "where"), Some(Value::Array(w)) if !w.is_empty());
        if verbs.iter().any(|v| v == "*") {
            out.push(find("over-broad-grant", "error", "predicate grants a WILDCARD verb '*' — authority over any action".into(), Some(where_.clone())));
        }
        if is_wildcard_resource(get(p, "resource")) {
            let mut dv = vec![];
            for v in &verbs {
                if is_dangerous_verb(v, dangerous)? {
                    dv.push(v.clone());
                }
            }
            if !dv.is_empty() {
                out.push(find(
                    "over-broad-grant",
                    "error",
                    format!("dangerous verb(s) {} granted on a WILDCARD resource ('*')", crate::js_stringify(&json!(dv))),
                    Some(where_.clone()),
                ));
            } else if !verbs.iter().any(|v| v == "*") {
                out.push(find("over-broad-grant", "warn", "predicate matches ANY resource ('*') — consider a resource prefix".into(), Some(where_.clone())));
            }
        }
        for v in &verbs {
            if v != "*" && is_dangerous_verb(v, dangerous)? && !has_where && !scope_narrowing {
                out.push(find(
                    "over-broad-grant",
                    "error",
                    format!("dangerous verb '{v}' is granted with NO narrowing `where` and no scope-narrowing caveat ({})", SCOPE_NARROWING_CAVEATS.join("/")),
                    Some(where_.clone()),
                ));
            }
        }
    }
    for v in declared_verbs(predicates_of(policy)) {
        let aa = analyzer::always_allows(&inp, &json!(v), opts)?;
        if truthy(aa.get("alwaysAllows")) && aa.get("approximate") != Some(&json!(true)) {
            out.push(find(
                "over-broad-grant",
                "error",
                format!("grants EVERY action of '{v}' — the authority has no effective constraint (always-allow)"),
                None,
            ));
        }
    }
    Ok(out)
}

fn rule_privilege_escalation(hops: &[Value], opts: &Value) -> R<Vec<Value>> {
    let mut out = vec![];
    for i in 1..hops.len() {
        let sub = analyzer::subsumes(&analyzer_input(&hops[i - 1]), &analyzer_input(&hops[i]), opts)?;
        let where_ = Some(format!("hop[{i}]"));
        if truthy(sub.get("subsumes")) {
            continue;
        }
        if sub.get("approximate") == Some(&json!(true)) {
            let reason = nn(sub.get("reason")).filter(|r| truthy(Some(*r)));
            let why = reason.map_or(String::new(), |r| format!(": {}", js_str(r)));
            out.push(find(
                "privilege-escalation",
                "warn",
                format!("could not prove hop {i} attenuation (undecidable{why}) — attenuation not verified"),
                where_,
            ));
        } else {
            let ex = nn(sub.get("counterexample")).map_or(String::new(), |ce| format!(" — child admits '{}' which its parent denies", describe_action(ce)));
            out.push(find(
                "privilege-escalation",
                "error",
                format!("delegation hop {i} ESCALATES authority: its effective authority is not a subset of its parent (attenuation violated){ex}"),
                where_,
            ));
        }
    }
    Ok(out)
}

// which numeric field carries a caveat's bound, and whether the STRICTEST (binding) one is the min or the max
const ORDERED_CAVEATS: [(&str, &str, bool); 5] = [
    ("expires", "at", true),
    ("not_before", "at", false),
    ("max_blast_radius", "max", true),
    ("delegation_depth", "max", true),
    ("budget_alloc", "limit", true),
];
const NUMERIC_OPS: [&str; 5] = ["lt", "lte", "gt", "gte", "eq"];

fn interval_eq(a: &Iv, b: &Iv) -> bool {
    a.lo == b.lo && a.lo_inc == b.lo_inc && a.hi == b.hi && a.hi_inc == b.hi_inc
}

fn is_leaf_condition(c: &Value) -> bool {
    c.is_object() && !["all_of", "any_of", "not"].iter().any(|k| get(c, k).is_some()) && is_str(get(c, "field"))
}

fn non_binding_conditions(where_: &[Value], pred_index: usize) -> Vec<Value> {
    let mut by_field: Vec<(String, Vec<(&Value, usize)>)> = vec![];
    for (i, c) in where_.iter().enumerate() {
        if !is_leaf_condition(c) || get(c, "ref").is_some() {
            continue;
        }
        if !matches!(get(c, "op"), Some(Value::String(o)) if NUMERIC_OPS.contains(&o.as_str())) || finite(get(c, "value")).is_none() {
            continue;
        }
        let field = get(c, "field").and_then(Value::as_str).unwrap_or("").to_string();
        match by_field.iter_mut().find(|(f, _)| *f == field) {
            Some((_, v)) => v.push((c, i)),
            None => by_field.push((field, vec![(c, i)])),
        }
    }
    let tight = |iv: Iv, c: &Value| analyzer::tighten_interval(iv, &c["op"], &c["value"]);
    let mut out = vec![];
    for (field, conds) in &by_field {
        if conds.len() < 2 {
            continue;
        }
        let full = conds.iter().fold(FULL_INTERVAL, |iv, (c, _)| tight(iv, c));
        if analyzer::interval_empty(full) {
            continue; // the whole-predicate unsat case is reported separately
        }
        for (ei, e) in conds.iter().enumerate() {
            let without = conds.iter().enumerate().filter(|(xi, _)| *xi != ei).fold(FULL_INTERVAL, |iv, (_, (c, _))| tight(iv, c));
            if interval_eq(&without, &full) {
                out.push(find(
                    "redundant-caveat",
                    "info",
                    format!(
                        "condition on '{field}' ({} {}) does not tighten the authority — redundant with the other bounds on this field",
                        s(get(e.0, "op")),
                        s(get(e.0, "value"))
                    ),
                    Some(format!("predicates[{pred_index}].where[{}]", e.1)),
                ));
            }
        }
    }
    out
}

fn rule_redundant_caveat(policy: &Value) -> R<Vec<Value>> {
    let mut out = vec![];
    let caveats = caveats_of(policy);
    let mut seen: Vec<(String, usize)> = vec![];
    for (i, cv) in caveats.iter().enumerate() {
        if !objlike(cv) {
            continue;
        }
        let k = crate::js_stringify(cv);
        match seen.iter().find(|(x, _)| *x == k) {
            Some((_, j)) => out.push(find(
                "redundant-caveat",
                "warn",
                format!("caveat {i} ('{}') is an exact duplicate of caveat {j} — dead policy", s(get(cv, "type"))),
                Some(format!("caveats[{i}]")),
            )),
            None => seen.push((k, i)),
        }
    }
    for (typ, field, keep_min) in ORDERED_CAVEATS {
        let vals: Vec<(usize, f64)> = caveats
            .iter()
            .enumerate()
            .filter(|(_, cv)| cv.is_object() && get(cv, "type").and_then(Value::as_str) == Some(typ))
            .filter_map(|(i, cv)| finite(get(cv, field)).map(|v| (i, v)))
            .collect();
        if vals.len() < 2 {
            continue;
        }
        let binding = vals.iter().map(|v| v.1).fold(vals[0].1, |a, b| if keep_min { a.min(b) } else { a.max(b) });
        for (i, v) in &vals {
            if *v != binding {
                out.push(find(
                    "redundant-caveat",
                    "warn",
                    format!(
                        "caveat {i} ('{typ}' {field}={}) is subsumed by a stricter '{typ}' ({field}={}) — it can never bite",
                        js_number_string(*v),
                        js_number_string(binding)
                    ),
                    Some(format!("caveats[{i}]")),
                ));
            }
        }
    }
    for (i, p) in predicates_of(policy).iter().enumerate() {
        let Some(Value::Array(w)) = get(p, "where").filter(|_| p.is_object()) else { continue };
        if !analyzer::predicate_numeric_satisfiable(&Value::Array(w.clone()))? {
            out.push(find(
                "redundant-caveat",
                "warn",
                format!("predicate {i} can never match — its numeric `where` constraints are unsatisfiable (dead policy)"),
                Some(format!("predicates[{i}]")),
            ));
        } else {
            out.extend(non_binding_conditions(w, i));
        }
    }
    Ok(out)
}

fn rule_dangerous_reachability(policy: &Value, dangerous: &Value, extra_targets: &Value, opts: &Value) -> R<Vec<Value>> {
    let mut out = vec![];
    let inp = analyzer_input(policy);
    let mut targets: Vec<Value> = vec![];
    for v in declared_verbs(predicates_of(policy)) {
        if is_dangerous_verb(&v, dangerous)? {
            targets.push(json!({ "verb": v }));
        }
    }
    targets.extend(arr(extra_targets)?.iter().cloned());
    let gate = gate_description(policy);
    for t in &targets {
        let verb = jget(t, "verb")?;
        let resource = jget(t, "resource")?;
        let (proven, approximate, reason, witness);
        if let Some(res) = resource {
            let mut action = Map::new();
            if let Some(v) = verb {
                action.insert("verb".into(), v.clone());
            }
            action.insert("resource".into(), res.clone());
            let r = analyzer::reachable(&inp, &Value::Object(action), opts)?;
            approximate = r.get("approximate") == Some(&json!(true));
            proven = truthy(r.get("reachable")) && !approximate;
            reason = r.get("reason").cloned();
            witness = format!("{} {}", s(verb), js_str(res));
        } else {
            let ad = analyzer::always_denies(&inp, verb.unwrap_or(&NULL), opts)?;
            approximate = ad.get("approximate") == Some(&json!(true));
            proven = ad.get("alwaysDenies") == Some(&json!(false)) && !approximate;
            reason = ad.get("reason").cloned();
            witness = match ad.get("witness") {
                Some(w) => describe_action(w),
                None => s(verb),
            };
        }
        if approximate {
            let why = reason.as_ref().filter(|r| truthy(Some(*r))).map_or(String::new(), |r| format!(": {}", js_str(r)));
            out.push(find("dangerous-reachability", "warn", format!("could not decide reachability of dangerous verb '{}' (undecidable{why})", s(verb)), None));
        } else if proven {
            match &gate {
                None => out.push(find(
                    "dangerous-reachability",
                    "error",
                    format!("dangerous action '{witness}' is REACHABLE with no budget / rate / step-up gate"),
                    None,
                )),
                Some(g) => out.push(find("dangerous-reachability", "info", format!("dangerous action '{witness}' is reachable but gated by {g}"), None)),
            }
        }
    }
    Ok(out)
}

fn is_non_trivial(policy: &Value, dangerous: &Value) -> R<bool> {
    for p in predicates_of(policy).iter().filter(|p| objlike(p)) {
        let verbs = verbs_of(get(p, "verb"));
        let has_where = matches!(get(p, "where"), Some(Value::Array(w)) if !w.is_empty());
        let mut any_dangerous = false;
        for v in &verbs {
            if is_dangerous_verb(v, dangerous)? {
                any_dangerous = true;
                break;
            }
        }
        if verbs.iter().any(|v| v == "*") || any_dangerous || is_wildcard_resource(get(p, "resource")) || !has_where {
            return Ok(true);
        }
    }
    Ok(false)
}

fn rule_missing_safety_floor(policy: &Value, require_expiry: bool, require_scope_gate: bool, dangerous: &Value) -> R<Vec<Value>> {
    let mut out = vec![];
    if predicates_of(policy).is_empty() {
        return Ok(out); // nothing is granted; default-deny needs no floor
    }
    if require_expiry && !has_caveat_of_type(caveats_of(policy), &["expires"]) {
        out.push(find("missing-safety-floor", "warn", "grant has no `expires` caveat — the authority never expires".into(), None));
    }
    if require_scope_gate && is_non_trivial(policy, dangerous)? && !has_caveat_of_type(caveats_of(policy), &BUDGET_GATE_CAVEATS) {
        out.push(find(
            "missing-safety-floor",
            "warn",
            format!("non-trivial grant has no blast-radius / rate / budget gate ({})", BUDGET_GATE_CAVEATS.join("/")),
            None,
        ));
    }
    Ok(out)
}

fn rule_schema_mismatch(policy: &Value, schema: &Value, options: &Value) -> R<Vec<Value>> {
    let r = analyzer::validate_policy_against_schema(&analyzer_input(policy), schema, options)?;
    let findings = r.get("findings").and_then(Value::as_array).cloned().unwrap_or_default();
    Ok(findings
        .iter()
        .map(|f| {
            let mut m = Map::new();
            m.insert("rule".into(), json!("schema-mismatch"));
            m.insert("severity".into(), f["severity"].clone());
            m.insert("message".into(), json!(format!("{}: {}", s(f.get("code")), s(f.get("message")))));
            if let Some(w) = f.get("where") {
                m.insert("where".into(), w.clone());
            }
            Value::Object(m)
        })
        .collect())
}

// ---- lint -------------------------------------------------------------------------------------------------------------------

/// A rule that throws is a finding, not a crash and not silence: a gate must not pass a policy it could not finish checking.
fn guarded(rule: &str, run: impl FnOnce() -> R<Vec<Value>>) -> Vec<Value> {
    let r = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(r) => r,
        Err(p) => Err(crate::taint::panic_message(p.as_ref())),
    };
    r.unwrap_or_else(|e| vec![find("internal-error", "error", format!("rule {rule} could not run: {e}"), None)])
}

struct Cfg {
    ob_enabled: bool,
    ob_verbs: Value,
    privilege_escalation: bool,
    redundant_caveat: bool,
    dr_enabled: bool,
    dr_verbs: Value,
    dr_targets: Value,
    sf_enabled: bool,
    require_expiry: bool,
    require_scope_gate: bool,
}

fn resolve_rules(rules: Option<&Value>) -> Cfg {
    let r = rules.filter(|x| !x.is_null()).unwrap_or(&NULL);
    let (ob, dr, sf) = (get(r, "overBroadGrant"), get(r, "dangerousReachability"), get(r, "missingSafetyFloor"));
    let default_verbs = || json!(DEFAULT_DANGEROUS_VERBS);
    let verbs = |o: Option<&Value>| -> Value {
        match o {
            Some(o) if objlike(o) && truthy(get(o, "dangerousVerbs")) => get(o, "dangerousVerbs").cloned().unwrap_or(Value::Null),
            _ => default_verbs(),
        }
    };
    let not_false = |v: Option<&Value>| v != Some(&json!(false));
    let flag = |o: Option<&Value>, k: &str| match o {
        Some(o) if objlike(o) => not_false(get(o, k)),
        _ => true,
    };
    Cfg {
        ob_enabled: not_false(ob),
        ob_verbs: verbs(ob),
        privilege_escalation: not_false(get(r, "privilegeEscalation")),
        redundant_caveat: not_false(get(r, "redundantCaveat")),
        dr_enabled: not_false(dr),
        dr_verbs: verbs(dr),
        dr_targets: match dr {
            Some(d) if objlike(d) && truthy(get(d, "targets")) => get(d, "targets").cloned().unwrap_or(json!([])),
            _ => json!([]),
        },
        sf_enabled: not_false(sf),
        require_expiry: flag(sf, "requireExpiry"),
        require_scope_gate: flag(sf, "requireScopeGate"),
    }
}

fn analyzer_opts(opts: &Value) -> Value {
    match get(opts, "maxCombinations") {
        Some(mc) => json!({ "maxCombinations": mc }),
        None => json!({}),
    }
}

fn single_rules(cfg: &Cfg, policy: &Value, ao: &Value) -> Vec<Value> {
    let mut out = vec![];
    if cfg.ob_enabled {
        out.extend(guarded("over-broad-grant", || rule_over_broad_grant(policy, &cfg.ob_verbs, ao)));
    }
    if cfg.redundant_caveat {
        out.extend(guarded("redundant-caveat", || rule_redundant_caveat(policy)));
    }
    if cfg.dr_enabled {
        out.extend(guarded("dangerous-reachability", || rule_dangerous_reachability(policy, &cfg.dr_verbs, &cfg.dr_targets, ao)));
    }
    if cfg.sf_enabled {
        out.extend(guarded("missing-safety-floor", || rule_missing_safety_floor(policy, cfg.require_expiry, cfg.require_scope_gate, &cfg.ob_verbs)));
    }
    out
}

fn malformed(reason: &Value) -> Value {
    json!([{ "rule": "malformed-policy", "severity": "error", "message": reason }])
}

/// Lints a single PCA policy (an envelope, a minted grant, a compiled policy or a bare `{predicates, caveats?}`): all findings (empty =
/// clean). `opts`: `{rules?, schema?, schemaOptions?, maxCombinations?}` (`Null` for none).
pub fn lint_policy(input: &Value, opts: &Value) -> Value {
    let norm = normalize_policy_input(input);
    if norm["ok"] != json!(true) {
        return malformed(&norm["reason"]);
    }
    let cfg = resolve_rules(get(opts, "rules"));
    let ao = analyzer_opts(opts);
    let policy = &norm["policy"];
    let mut out = single_rules(&cfg, policy, &ao);
    if let Some(schema) = get(opts, "schema") {
        out.extend(guarded("schema-mismatch", || rule_schema_mismatch(policy, schema, get(opts, "schemaOptions").unwrap_or(&NULL))));
    }
    Value::Array(out)
}

/// Lints a delegation chain (root to leaf): privilege escalation across every consecutive pair, then the single-policy rules on the acting
/// LEAF's effective authority.
pub fn lint_chain(chain: &Value, opts: &Value) -> R<Value> {
    let norm = normalize_chain(chain)?;
    if norm["ok"] != json!(true) {
        return Ok(malformed(&norm["reason"]));
    }
    let cfg = resolve_rules(get(opts, "rules"));
    let ao = analyzer_opts(opts);
    let hops = norm["hops"].as_array().cloned().unwrap_or_default();
    let mut out = vec![];
    if cfg.privilege_escalation {
        out.extend(guarded("privilege-escalation", || rule_privilege_escalation(&hops, &ao)));
    }
    if let Some(leaf) = hops.last() {
        out.extend(single_rules(&cfg, leaf, &ao));
    }
    Ok(Value::Array(out))
}

/// An array input is a delegation chain; anything else is a single policy.
pub fn lint(input: &Value, opts: &Value) -> R<Value> {
    if input.is_array() {
        lint_chain(input, opts)
    } else {
        Ok(lint_policy(input, opts))
    }
}

/// The own severity key a value names, else `None`.
fn rank_key(k: &Value) -> Option<&'static str> {
    let t = js_str(k);
    SEVERITY_ORDER.iter().copied().find(|x| *x == t)
}

fn rank(k: &str) -> u8 {
    SEVERITY_ORDER.iter().position(|x| *x == k).map_or(0, |p| p as u8 + 1)
}

/// Rolls labeled findings into counts and an exit code (0 ok, 1 a finding reaches the threshold, 2 nothing was linted).
pub fn summarize(results: &Value, opts: &Value) -> R<Value> {
    let max_severity = nn(get(opts, "maxSeverity")).cloned().unwrap_or(json!("error"));
    let Some(mk) = rank_key(&max_severity) else { return Err("summarize: maxSeverity must be one of info, warn, error".into()) };
    let mut counts = [("error", 0u64), ("warn", 0), ("info", 0)];
    let list = results.as_array().filter(|a| !a.is_empty());
    let Some(list) = list else {
        return Ok(
            json!({ "results": [], "counts": { "error": 0, "warn": 0, "info": 0 }, "maxSeverity": max_severity, "ok": false, "exitCode": 2, "reason": "no policies were linted" }),
        );
    };
    let mut failing = 0;
    let threshold = rank(mk);
    for r in list {
        for f in arr(jget(r, "findings")?.unwrap_or(&NULL))? {
            let sev = jget(f, "severity")?.and_then(rank_key).unwrap_or("error");
            counts.iter_mut().find(|c| c.0 == sev).map(|c| c.1 += 1);
            if rank(sev) >= threshold {
                failing += 1;
            }
        }
    }
    let ok = failing == 0;
    let count = |k: &str| counts.iter().find(|c| c.0 == k).map_or(0, |c| c.1);
    Ok(
        json!({ "results": results, "counts": { "error": count("error"), "warn": count("warn"), "info": count("info") }, "maxSeverity": max_severity, "ok": ok, "exitCode": if ok { 0 } else { 1 } }),
    )
}

/// Lints a list of labeled policies (or chains) and rolls the findings into a summary.
pub fn lint_policies(items: &Value, opts: &Value) -> R<Value> {
    let mut results = vec![];
    for (i, item) in arr(items)?.iter().enumerate() {
        let label = nn(jget(item, "label")?).cloned().unwrap_or_else(|| json!(format!("policy[{i}]")));
        results.push(json!({ "label": label, "findings": lint(jget(item, "policy")?.unwrap_or(&NULL), opts)? }));
    }
    summarize(&Value::Array(results), opts)
}

// ---- pinned lint rule list --------------------------------------------------------------------------------------------------

pub const LINT_RULES_DIGEST_DOMAIN: &str = "atlas-pca/action-lint-rules/v1";
const LINT_RULES: [(&str, &str, &str); 24] = [
    ("LD-001", "error", "a destroy-like verb whose effects do not delete"),
    ("LD-002", "error", "a money parameter without a currency, or a currency without the iso_currency format"),
    ("LD-003", "error", "a numeric parameter without min and max"),
    ("LD-004", "error", "a money-moving action without idempotency"),
    ("LD-005", "error", "personal data can leave without the matching effect"),
    ("LD-006", "error", "a declared reversibility or blast below the effective floor"),
    ("LD-007", "error", "an unknown trait, role, format, effect or context key, or an invalid custom trait"),
    ("LD-008", "error", "resource id '*' with scope one"),
    ("LD-009", "error", "a duplicate verb or alias collision"),
    ("LD-010", "error", "a write marked reversible with no compensating action in the pack"),
    ("LD-011", "error", "review state confirmed without a valid attestation for this digest"),
    ("LD-012", "error", "a structural param rule that the effective traits require is violated"),
    ("LD-013", "error", "a read-only action that can mutate or handles credentials"),
    ("LD-014", "error", "one binding in two defs"),
    ("LW-001", "warning", "description missing or too long, or title not imperative"),
    ("LW-002", "warning", "a string parameter without max_len"),
    ("LW-003", "warning", "free text flows into an outbound action without the free_text_outbound tag"),
    ("LW-004", "warning", "an unreviewed def in a stable pack"),
    ("LW-005", "warning", "a dismissed suggested trait without a reason"),
    ("LW-006", "warning", "an array parameter without max_items"),
    ("LW-007", "warning", "a critical parameter without provenance_min"),
    ("LW-008", "warning", "verb naming inconsistent with its siblings or with the file namespace"),
    ("LW-009", "warning", "a money-moving, destructive or privilege-changing action without an example"),
    ("LW-010", "warning", "since is missing"),
];

/// The digest the CI gate pins: the ordered (id, severity, title) list of the action-kit lint rules.
pub fn lint_rules_digest() -> String {
    let rules: Vec<Value> = LINT_RULES.iter().map(|(i, sv, t)| json!({ "id": i, "severity": sv, "title": t })).collect();
    crate::hash_canonical(&json!({ "d": LINT_RULES_DIGEST_DOMAIN, "rules": rules }))
}

/// Enforces the pinned digest of the lint rule list: `pin_text` is the content of the pin file (one digest, surrounding whitespace
/// ignored). `actual` defaults to [`lint_rules_digest`].
pub fn check_lint_rules_pin(pin_text: &str, actual: Option<&str>) -> Value {
    let actual = actual.map_or_else(lint_rules_digest, String::from);
    let pinned = trim(pin_text);
    if !(pinned.chars().count() == 43 && pinned.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')) {
        return json!({ "ok": false, "message": "the lint rules pin is not a digest (expected 43 base64url characters)" });
    }
    if pinned == actual {
        return json!({ "ok": true, "message": format!("lint rules digest {actual} matches the pin") });
    }
    json!({ "ok": false, "message": format!("lint rules digest {actual} differs from the pin {pinned}: the rule list changed; review it and update the pin") })
}

// ---- authoring gates --------------------------------------------------------------------------------------------------------

fn bad(line: &str) -> Value {
    json!({ "ok": false, "exitCode": 2, "lines": [line] })
}

/// A policy document as the analyzer reads it: any shape [`lint`] accepts, plus optional `vetoes` and `tighten` members.
pub fn to_analyzer_policy(doc: &Value) -> Value {
    let n = normalize_policy_input(doc);
    if n["ok"] != json!(true) {
        return n;
    }
    let mut policy = Map::new();
    policy.insert("predicates".into(), n["policy"]["predicates"].clone());
    policy.insert("caveats".into(), n["policy"]["caveats"].clone());
    for k in ["vetoes", "tighten"] {
        if let Some(v) = get(doc, k).filter(|v| v.is_array()) {
            policy.insert(k.into(), v.clone());
        }
    }
    json!({ "ok": true, "policy": Value::Object(policy) })
}

fn lines_of(v: Vec<String>, ok: bool) -> Value {
    json!({ "ok": ok, "exitCode": if ok { 0 } else { 1 }, "lines": v })
}

/// `diff`: does this change widen authority, or raise the most that can leave? `{ok, exitCode (0 ok, 1 gate failed, 2 unusable input), lines}`.
pub fn diff_command(old_doc: &Value, new_doc: &Value, o: &Value) -> R<Value> {
    let (a, b) = (to_analyzer_policy(old_doc), to_analyzer_policy(new_doc));
    if a["ok"] != json!(true) {
        return Ok(bad(&format!("old policy: {}", s(a.get("reason")))));
    }
    if b["ok"] != json!(true) {
        return Ok(bad(&format!("new policy: {}", s(b.get("reason")))));
    }
    let mut opts = json!({});
    if let Some(verb) = get(o, "verb") {
        let mut ex = Map::new();
        ex.insert("verb".into(), verb.clone());
        if truthy(get(o, "amountField")) {
            ex.insert("amountField".into(), o["amountField"].clone());
        }
        if truthy(get(o, "integer")) {
            ex.insert("integer".into(), json!(true));
        }
        if let Some(w) = get(o, "windowSecs") {
            ex.insert("windowSecs".into(), w.clone());
        }
        opts = json!({ "exposure": Value::Object(ex) });
    }
    let d = analyzer::diff_policies(&a["policy"], &b["policy"], &opts)?;
    let mut allow = Map::new();
    allow.insert("widen".into(), json!(get(o, "allowWiden") == Some(&json!(true))));
    if let Some(m) = get(o, "maxExposureIncrease") {
        allow.insert("maxExposureIncrease".into(), m.clone());
    }
    let gate = analyzer::diff_gate(&d, &Value::Object(allow))?;
    let gate_ok = truthy(gate.get("ok"));
    let mut lines: Vec<String> = if truthy(d.get("equivalent")) {
        vec!["no change in what is admitted".into()]
    } else {
        match d.get("summary").and_then(Value::as_array).filter(|a| !a.is_empty()) {
            Some(a) => a.iter().map(js_str).collect(),
            None => vec!["no witness found".into()],
        }
    };
    if !gate_ok {
        lines.extend(gate.get("reasons").and_then(Value::as_array).into_iter().flatten().map(|r| format!("FAIL: {}", js_str(r))));
    }
    lines.push(if gate_ok { "PASS" } else { "FAIL" }.into());
    Ok(lines_of(lines, gate_ok))
}

/// `test`: a policy test document against a policy, pinned by digest with `requireDigest`.
pub fn test_command(policy_doc: &Value, tests_doc: &Value, o: &Value) -> R<Value> {
    let p = to_analyzer_policy(policy_doc);
    if p["ok"] != json!(true) {
        return Ok(bad(&format!("policy: {}", s(p.get("reason")))));
    }
    if !tests_doc.is_object() || get(tests_doc, "kind") != Some(&json!("pca-policy-tests")) || !is_arr(get(tests_doc, "cases")) {
        return Ok(bad("tests: not a pca-policy-tests document"));
    }
    let rd = get(o, "requireDigest");
    let opts = rd.map_or(json!({}), |v| json!({ "requireDigest": v }));
    let r = analyzer::run_policy_tests(&p["policy"], tests_doc, &opts)?;
    let mut lines = vec![];
    for f in r["failures"].as_array().into_iter().flatten() {
        let eb = get(f, "expectedDecidedBy");
        let by = nn(get(f, "decidedBy"));
        lines.push(format!(
            "FAIL {}: expected {}{}, got {} by {}",
            s(get(f, "name")),
            s(get(f, "expected")),
            if truthy(eb) { format!(" by {}", s(eb)) } else { String::new() },
            s(get(f, "got")),
            by.map_or("no clause".to_string(), js_str)
        ));
    }
    if !truthy(r.get("digestMatch")) {
        lines.push(format!("{}: the policy differs from the one the examples were confirmed against", if truthy(rd) { "FAIL" } else { "note" }));
    }
    let ok = truthy(r.get("ok"));
    lines.push(format!("{}/{} examples {}", js_str(&r["passed"]), js_str(&r["total"]), if ok { "PASS" } else { "FAIL" }));
    Ok(lines_of(lines, ok))
}

fn to_fixed0(x: f64) -> String {
    if x.is_nan() {
        "NaN".into()
    } else if x.is_infinite() {
        if x > 0.0 { "Infinity" } else { "-Infinity" }.into()
    } else {
        format!("{:.0}", x.round())
    }
}

/// `coverage`: which clauses and thresholds the tests or traffic never exercise, and which mutations they cannot tell apart.
pub fn coverage_command(policy_doc: &Value, traffic_doc: &Value, o: &Value) -> R<Value> {
    let p = to_analyzer_policy(policy_doc);
    if p["ok"] != json!(true) {
        return Ok(bad(&format!("policy: {}", s(p.get("reason")))));
    }
    let actions: Option<Vec<Value>> = match traffic_doc {
        Value::Array(a) => Some(a.clone()),
        _ => get(traffic_doc, "cases")
            .and_then(Value::as_array)
            .map(|cs| cs.iter().map(|c| if c.is_object() { get(c, "action").cloned().unwrap_or(Value::Null) } else { c.clone() }).collect()),
    };
    let valid = |a: &Value| a.is_object() && is_str(get(a, "verb")) && is_str(get(a, "resource"));
    let Some(actions) = actions.filter(|v| v.iter().all(valid)) else {
        return Ok(bad("traffic: expected an array of {verb, resource, params?} actions or a pca-policy-tests document"));
    };
    let r = analyzer::coverage(&p["policy"], &Value::Array(actions), &analyzer::NONE)?;
    let mut mn = Map::new();
    for (src, dst) in [("minClauses", "clauses"), ("minBoundaries", "boundaries"), ("minMutation", "mutation"), ("maxSurvivors", "maxSurvivors")] {
        if let Some(v) = get(o, src) {
            mn.insert(dst.into(), v.clone());
        }
    }
    let gate = analyzer::coverage_gate(&r, &Value::Object(mn))?;
    let sc = &r["score"];
    let pct = |k: &str| to_fixed0(sc[k].as_f64().unwrap_or(f64::NAN) * 100.0);
    let m = &r["mutants"];
    let n = |v: &Value| js_str(v);
    let total = m["total"].as_f64().unwrap_or(f64::NAN) - m["equivalent"].as_f64().unwrap_or(f64::NAN);
    let mut lines = vec![format!(
        "clauses decisive {}%, boundaries covered {}%, mutants killed {}% ({}/{})",
        pct("clauses"),
        pct("boundaries"),
        pct("mutation"),
        n(&m["killed"]),
        js_number_string(total)
    )];
    lines.extend(r["untested"].as_array().into_iter().flatten().map(|i| format!("untested: {}", js_str(i))));
    for sv in m["survivors"].as_array().into_iter().flatten() {
        let kill = nn(get(sv, "killer")).filter(|k| truthy(Some(*k))).map_or(String::new(), |k| format!(" (kill with {})", crate::js_stringify(k)));
        lines.push(format!("survives: {}{kill}", s(get(sv, "description"))));
    }
    lines.extend(gate["reasons"].as_array().into_iter().flatten().map(|x| format!("FAIL: {}", js_str(x))));
    let ok = truthy(gate.get("ok"));
    lines.push(if ok { "PASS" } else { "FAIL" }.into());
    Ok(lines_of(lines, ok))
}

// ---- command line -----------------------------------------------------------------------------------------------------------

const SEVERITIES: [&str; 3] = ["error", "warn", "info"];

pub const HELP: &str = "pca-policy-ci — statically catch unsafe PCA policies before they ship.

Usage:
  pca-policy-ci <files...> [options]
  pca-policy-ci diff <old.json> <new.json> [--allow-widen] [--verb V [--integer] [--amount-field F] [--window-secs N] [--max-exposure-increase N]]
  pca-policy-ci test <policy.json> <tests.json> [--require-digest]
  pca-policy-ci coverage <policy.json> <traffic-or-tests.json> [--min-clauses R] [--min-boundaries R] [--min-mutation R] [--max-survivors N]

Options:
  --max-severity <error|warn|info>  Lowest severity that fails the gate (default: error)
  --format <text|github>            Output format (default: text; 'github' = workflow annotations)
  --schema <file>                   Also check each policy against this signed action schema (JSON)
  --lint-rules-pin <file>           Fail unless the action-kit lint rule list has the digest in <file>
  --quiet, -q                       Only print findings and the summary line
  --help, -h                        Show this help

Each file is a JSON policy (Envelope / grant / compiled / { predicates, caveats }) or a JSON array
treated as a delegation chain. Exits non-zero when any finding is at or above --max-severity.";

/// The command line as `{args: {files, maxSeverity, format, quiet, help, schema?, lintRulesPin?}}` or `{error}`.
pub fn parse_args(argv: &[String]) -> Value {
    let err = |m: String| json!({ "error": m });
    let (mut files, mut max_severity, mut fmt, mut quiet, mut help) = (vec![], "error".to_string(), "text".to_string(), false, false);
    let (mut schema, mut pin): (Option<String>, Option<String>) = (None, None);
    let sev_err = || format!("--max-severity expects one of {}", SEVERITIES.join("|"));
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        let mut next = || {
            i += 1;
            argv.get(i).cloned()
        };
        if a == "--help" || a == "-h" {
            help = true;
        } else if a == "--quiet" || a == "-q" {
            quiet = true;
        } else if a == "--lint-rules-pin" {
            match next() {
                Some(v) if !v.starts_with('-') => pin = Some(v),
                _ => return err("--lint-rules-pin expects a file".into()),
            }
        } else if a == "--max-severity" {
            match next() {
                Some(v) if SEVERITIES.contains(&v.as_str()) => max_severity = v,
                _ => return err(sev_err()),
            }
        } else if let Some(v) = a.strip_prefix("--max-severity=") {
            if !SEVERITIES.contains(&v) {
                return err(sev_err());
            }
            max_severity = v.to_string();
        } else if a == "--schema" {
            match next() {
                Some(v) => schema = Some(v),
                None => return err("--schema expects a file".into()),
            }
        } else if let Some(v) = a.strip_prefix("--schema=") {
            schema = Some(v.to_string());
        } else if a == "--format" {
            match next() {
                Some(v) if v == "text" || v == "github" => fmt = v,
                _ => return err("--format expects 'text' or 'github'".into()),
            }
        } else if let Some(v) = a.strip_prefix("--format=") {
            if v != "text" && v != "github" {
                return err("--format expects 'text' or 'github'".into());
            }
            fmt = v.to_string();
        } else if a.starts_with('-') {
            return err(format!("unknown option '{a}'"));
        } else {
            files.push(a.to_string());
        }
        i += 1;
    }
    let mut args = Map::new();
    args.insert("files".into(), json!(files));
    args.insert("maxSeverity".into(), json!(max_severity));
    args.insert("format".into(), json!(fmt));
    args.insert("quiet".into(), json!(quiet));
    args.insert("help".into(), json!(help));
    if let Some(sc) = schema {
        args.insert("schema".into(), json!(sc));
    }
    if let Some(p) = pin {
        args.insert("lintRulesPin".into(), json!(p));
    }
    json!({ "args": Value::Object(args) })
}

fn resolve(dir: Option<&Path>, f: &str) -> PathBuf {
    dir.map_or_else(|| PathBuf::from(f), |d| d.join(f))
}

/// The file's text (invalid UTF-8 replaced) or the Node-worded system error.
fn read_text(dir: Option<&Path>, f: &str) -> Result<String, String> {
    match std::fs::read(resolve(dir, f)) {
        Ok(b) => Ok(String::from_utf8_lossy(&b).into_owned()),
        Err(e) => {
            let (code, text, op) = match e.raw_os_error() {
                Some(2) => ("ENOENT".to_string(), "no such file or directory".to_string(), "open"),
                Some(13) => ("EACCES".to_string(), "permission denied".to_string(), "open"),
                Some(21) => ("EISDIR".to_string(), "illegal operation on a directory".to_string(), "read"),
                n => (format!("E{}", n.unwrap_or(0)), e.to_string().to_lowercase(), "open"),
            };
            Err(format!("{code}: {text}, {op} '{f}'"))
        }
    }
}

fn lint_file(dir: Option<&Path>, f: &str, schema: Option<&Value>) -> Value {
    let text = match read_text(dir, f) {
        Ok(t) => t,
        Err(e) => return malformed(&json!(format!("cannot read file: {e}"))),
    };
    let doc: Value = match serde_json::from_str(&text) {
        Ok(d) => d,
        Err(e) => return malformed(&json!(format!("invalid JSON: {e}"))),
    };
    let opts = schema.map_or(json!({}), |sc| json!({ "schema": sc }));
    lint(&doc, &opts).unwrap_or_else(|e| json!([{ "rule": "internal-error", "severity": "error", "message": e }]))
}

fn escape_gh(x: &str) -> String {
    x.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A")
}

/// Workflow-command PROPERTY values must also escape `:` and `,`, or a file name can add properties or end the command.
fn escape_gh_prop(x: &str) -> String {
    escape_gh(x).replace(':', "%3A").replace(',', "%2C")
}

fn read_json(dir: Option<&Path>, f: &str) -> Result<Value, String> {
    let text = read_text(dir, f).map_err(|e| format!("{f}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{f}: {e}"))
}

/// `Number(v)` of a flag value when it is a non-blank finite number.
fn flag_number(v: &str) -> Option<Value> {
    let t = trim(v);
    if t.is_empty() {
        return None;
    }
    let radix = |p: &[&str], r: u32| -> Option<f64> {
        let rest = p.iter().find_map(|x| t.strip_prefix(x))?;
        (!rest.is_empty() && rest.chars().all(|c| c.is_digit(r))).then(|| u128::from_str_radix(rest, r).map_or(f64::INFINITY, |n| n as f64))
    };
    let n = if let Some(n) = radix(&["0x", "0X"], 16).or_else(|| radix(&["0o", "0O"], 8)).or_else(|| radix(&["0b", "0B"], 2)) {
        n
    } else {
        let b = t.as_bytes();
        let mut i = 0;
        if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
            i += 1;
        }
        let digits = |i: &mut usize| {
            let st = *i;
            while *i < b.len() && b[*i].is_ascii_digit() {
                *i += 1;
            }
            *i - st
        };
        let int = digits(&mut i);
        let mut frac = 0;
        if i < b.len() && b[i] == b'.' {
            i += 1;
            frac = digits(&mut i);
        }
        if int + frac == 0 {
            return None;
        }
        if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
            i += 1;
            if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
                i += 1;
            }
            if digits(&mut i) == 0 {
                return None;
            }
        }
        if i != b.len() {
            return None;
        }
        t.parse::<f64>().ok()?
    };
    if !n.is_finite() {
        return None;
    }
    Some(if n.fract() == 0.0 && n.abs() < 9007199254740992.0 { json!(n as i64) } else { json!(n) })
}

const VALUED: [&str; 8] =
    ["--verb", "--amount-field", "--window-secs", "--max-exposure-increase", "--min-clauses", "--min-boundaries", "--min-mutation", "--max-survivors"];
const BOOLS: [&str; 3] = ["--allow-widen", "--integer", "--require-digest"];

fn set_flag<'a>(flags: &mut Vec<(&'static str, Option<&'a str>)>, k: &'static str, v: Option<&'a str>) {
    match flags.iter_mut().find(|f| f.0 == k) {
        Some(f) => f.1 = v,
        None => flags.push((k, v)),
    }
}

fn run_authoring(dir: Option<&Path>, cmd: &str, rest: &[String], write: &mut dyn FnMut(&str)) -> i32 {
    let mut files: Vec<&str> = vec![];
    // insertion-ordered flag table: a valued flag keeps its text, a boolean flag is `None`
    let mut flags: Vec<(&'static str, Option<&str>)> = vec![];
    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_str();
        if let Some(k) = VALUED.iter().find(|k| **k == a) {
            i += 1;
            if i >= rest.len() {
                write(&format!("{a} expects a value"));
                return 2;
            }
            set_flag(&mut flags, k, Some(rest[i].as_str()));
        } else if let Some(k) = BOOLS.iter().find(|k| **k == a) {
            set_flag(&mut flags, k, None);
        } else if a.starts_with('-') {
            write(&format!("unknown option '{a}'"));
            return 2;
        } else {
            files.push(a);
        }
        i += 1;
    }
    for (k, v) in &flags {
        if let Some(v) = v {
            if VALUED.contains(k) && *k != "--verb" && *k != "--amount-field" && flag_number(v).is_none() {
                write(&format!("{k} expects a number, got '{v}'"));
                return 2;
            }
        }
    }
    if files.len() != 2 {
        write(&format!("error: {cmd} takes exactly two files"));
        write(HELP);
        return 2;
    }
    let mut docs = vec![];
    for f in &files {
        match read_json(dir, f) {
            Ok(d) => docs.push(d),
            Err(e) => {
                write(&e);
                return 2;
            }
        }
    }
    let flag = |k: &str| flags.iter().find(|f| f.0 == k);
    let has = |k: &str| flag(k).is_some();
    let text = |k: &str| flag(k).and_then(|f| f.1);
    let num = |k: &str| text(k).and_then(flag_number);
    let mut o = Map::new();
    let put = |o: &mut Map<String, Value>, flag_name: &str, key: &str| {
        if let Some(n) = num(flag_name) {
            o.insert(key.into(), n);
        }
    };
    let r = match cmd {
        "diff" => {
            o.insert("allowWiden".into(), json!(has("--allow-widen")));
            if let Some(v) = text("--verb") {
                o.insert("verb".into(), json!(v));
            }
            if let Some(v) = text("--amount-field") {
                o.insert("amountField".into(), json!(v));
            }
            o.insert("integer".into(), json!(has("--integer")));
            put(&mut o, "--window-secs", "windowSecs");
            put(&mut o, "--max-exposure-increase", "maxExposureIncrease");
            diff_command(&docs[0], &docs[1], &Value::Object(o))
        }
        "test" => test_command(&docs[0], &docs[1], &json!({ "requireDigest": has("--require-digest") })),
        _ => {
            put(&mut o, "--min-clauses", "minClauses");
            put(&mut o, "--min-boundaries", "minBoundaries");
            put(&mut o, "--min-mutation", "minMutation");
            put(&mut o, "--max-survivors", "maxSurvivors");
            coverage_command(&docs[0], &docs[1], &Value::Object(o))
        }
    };
    match r {
        Ok(r) => {
            for line in r["lines"].as_array().into_iter().flatten() {
                write(&js_str(line));
            }
            r["exitCode"].as_i64().unwrap_or(2) as i32
        }
        Err(e) => {
            write(&format!("error: {e}"));
            2
        }
    }
}

/// Runs the command line (`<files...>`, `diff`, `test`, `coverage`); `write` receives each output line; relative file names resolve against
/// `dir` (the working directory when `None`). Returns the exit code: 0 ok, 1 a gate failed, 2 unusable input.
pub fn run_in(argv: &[String], dir: Option<&Path>, write: &mut dyn FnMut(&str)) -> i32 {
    if let Some(cmd) = argv.first().filter(|c| ["diff", "test", "coverage"].contains(&c.as_str())) {
        return run_authoring(dir, cmd, &argv[1..], write);
    }
    let parsed = parse_args(argv);
    if let Some(e) = parsed.get("error") {
        write(&js_str(e));
        write(HELP);
        return 2;
    }
    let args = &parsed["args"];
    if args["help"] == json!(true) {
        write(HELP);
        return 0;
    }
    let files: Vec<&str> = args["files"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let mut pin_failed = false;
    if let Some(pin) = get(args, "lintRulesPin").and_then(Value::as_str) {
        let r = match read_text(dir, pin) {
            Ok(t) => check_lint_rules_pin(&t, None),
            Err(e) => json!({ "ok": false, "message": format!("cannot read the lint rules pin: {e}") }),
        };
        let ok = r["ok"] == json!(true);
        write(&format!("{} — {}", if ok { "PASS" } else { "FAIL" }, js_str(&r["message"])));
        pin_failed = !ok;
        if files.is_empty() {
            return if pin_failed { 1 } else { 0 };
        }
    }
    if files.is_empty() {
        write("error: no policy files given");
        write(HELP);
        return 2;
    }
    let mut schema: Option<Value> = None;
    if let Some(sp) = get(args, "schema").and_then(Value::as_str) {
        match read_json(dir, sp) {
            Ok(d) => schema = Some(d),
            Err(e) => {
                write(&e);
                return 2;
            }
        }
    }
    let results: Vec<Value> = files.iter().map(|f| json!({ "label": f, "findings": lint_file(dir, f, schema.as_ref()) })).collect();
    let max_severity = args["maxSeverity"].clone();
    let summary = match summarize(&Value::Array(results.clone()), &json!({ "maxSeverity": max_severity })) {
        Ok(s) => s,
        Err(e) => {
            write(&format!("error: {e}"));
            return 2;
        }
    };
    if args["format"] == json!("github") {
        for r in &results {
            for f in r["findings"].as_array().into_iter().flatten() {
                let props = format!("file={},title={}", escape_gh_prop(&js_str(&r["label"])), escape_gh_prop(&s(get(f, "rule"))));
                let loc = nn(get(f, "where")).map_or(String::new(), |w| format!("{}: ", js_str(w)));
                let level = match s(get(f, "severity")).as_str() {
                    "error" => "error",
                    "warn" => "warning",
                    _ => "notice",
                };
                write(&format!("::{level} {props}::{}", escape_gh(&format!("{loc}{}", s(get(f, "message"))))));
            }
        }
    } else {
        let quiet = args["quiet"] == json!(true);
        for r in &results {
            if !quiet {
                write(&format!("\n{}:", js_str(&r["label"])));
            }
            let fs = r["findings"].as_array().cloned().unwrap_or_default();
            if fs.is_empty() {
                if !quiet {
                    write("  (clean)");
                }
                continue;
            }
            for f in &fs {
                let loc = nn(get(f, "where")).map_or(String::new(), |w| format!(" [{}]", js_str(w)));
                let tag = match s(get(f, "severity")).as_str() {
                    "error" => "ERROR",
                    "warn" => "WARN",
                    _ => "INFO",
                };
                write(&format!("  {tag:<5} {}{loc}: {}", s(get(f, "rule")), s(get(f, "message"))));
            }
        }
    }
    if let Some(reason) = get(&summary, "reason").filter(|r| truthy(Some(*r))) {
        write(&format!("error: {}", js_str(reason)));
    }
    let c = &summary["counts"];
    let ok = summary["ok"] == json!(true);
    write(&format!(
        "\n{} — {} error(s), {} warning(s), {} info across {} policy/policies (fail threshold: {})",
        if ok { "PASS" } else { "FAIL" },
        js_str(&c["error"]),
        js_str(&c["warn"]),
        js_str(&c["info"]),
        results.len(),
        js_str(&summary["maxSeverity"])
    ));
    let code = summary["exitCode"].as_i64().unwrap_or(2) as i32;
    if pin_failed {
        code.max(1)
    } else {
        code
    }
}

/// [`run_in`] over the working directory.
pub fn run(argv: &[String], write: &mut dyn FnMut(&str)) -> i32 {
    run_in(argv, None, write)
}
