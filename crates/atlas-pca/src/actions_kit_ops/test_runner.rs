//! Run every def's executable examples through the real pipeline in process (test-runner.ts): derive the schema, conform the
//! params, expand the floors, decide; plus the generic property checks of the pack: monotonicity over trait additions and subsets,
//! one digest across the JSON and YAML forms, and the schema round trip (the example conforms; every mutation of it is refused).
//! The example policy (`under`) is a small allow selector evaluated here; it can only pre-authorize.
//!
//! shortcut: the JSON and YAML forms are checked by re-reading the def (serde round trip; this directory's YAML emit then load),
//! validating it and comparing the def digest, not through the authoring loader's extra checks.

use super::deps;
use super::effective::{eff_with_trait, effective_with, View};
use super::u16cmp;
use crate::action_schema::conform_action;
use crate::actions::{core_registry, def_digest, floor_decision, floor_of, leq, validate_def, GrantFacts, Registry, CAVEAT_KINDS};
use serde_json::{json, Map, Value};

const SEL_KEYS: [&str; 5] = ["trait", "verb", "where", "caveats", "context"];

fn meta() -> Value {
    json!({"site": "https://example.invalid", "aud": "example", "version": "0"})
}

/// Examples and property checks describe the action AS REVIEWED (its hint view): authoring tests, not enforcement.
fn hint_of(d: &Value, reg: &Registry) -> Result<(View, crate::actions::Profile), String> {
    let e = effective_with(d, reg, None).map_err(super::msg)?;
    Ok((e.hint, e.decl))
}

fn parse_under(under: Option<&Value>) -> Result<Vec<Value>, String> {
    let Some(under) = under else { return Ok(vec![]) };
    let Some(uo) = under.as_object().filter(|o| o.keys().all(|k| k == "allow")) else { return Err("under must be {allow: selector | [selector]}".into()) };
    let allow = uo.get("allow").cloned().unwrap_or(Value::Null);
    let list: Vec<Value> = match &allow {
        Value::Array(a) => a.clone(),
        x => vec![x.clone()],
    };
    let mut out = Vec::new();
    for s in list {
        let Some(so) = s.as_object().filter(|o| o.keys().all(|k| SEL_KEYS.contains(&k.as_str()))) else {
            return Err("an allow selector has trait, verb, where, caveats, context".into());
        };
        if so.contains_key("trait") == so.contains_key("verb") {
            return Err("an allow selector names exactly one of trait and verb".into());
        }
        if so.get("where").is_some_and(|w| !w.is_object()) {
            return Err("where must be an object".into());
        }
        if let Some(c) = so.get("caveats") {
            if !c.as_array().is_some_and(|a| a.iter().all(|x| x.as_str().is_some_and(|x| CAVEAT_KINDS.contains(&x)))) {
                return Err("caveats must be known caveat kinds".into());
            }
        }
        out.push(s);
    }
    Ok(out)
}

fn domain_of(v: &str) -> String {
    v[v.rfind('@').map_or(0, |i| i + 1)..].to_lowercase()
}

/// The caveats of the grant a matching allow selector stands for, or `None` when it does not match this call.
fn grant_of(sel: &Value, d: &Value, flat: &Map<String, Value>, hint: &View) -> Option<Vec<String>> {
    if let Some(t) = sel.get("trait").and_then(Value::as_str) {
        let id = if t.contains('.') { t.to_string() } else { format!("pca.{t}") };
        if !hint.closure.contains(&id) {
            return None;
        }
    }
    if sel.get("verb").is_some_and(|v| v.as_str() != d["verb"].as_str()) {
        return None;
    }
    let mut caveats: Vec<String> = sel.get("caveats").and_then(Value::as_array).into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect();
    caveats.dedup();
    let add = |c: &str, caveats: &mut Vec<String>| {
        if !caveats.iter().any(|x| x == c) {
            caveats.push(c.to_string());
        }
    };
    for (key, cond) in sel.get("where").and_then(Value::as_object).into_iter().flatten() {
        let dom = key.ends_with(".domain");
        let name = if dom { &key[..key.len() - ".domain".len()] } else { key.as_str() };
        let pd = d["params"].get(name).filter(|p| !p.is_null())?;
        let v = flat.get(name)?;
        match cond {
            Value::Array(list) => {
                let s = v.as_str()?;
                let probe = if dom { domain_of(s) } else { s.to_string() };
                if !list.iter().any(|x| x.as_str() == Some(probe.as_str())) {
                    return None;
                }
            }
            Value::Object(c) => {
                let x = v.as_f64()?;
                if c.get("max").and_then(Value::as_f64).is_some_and(|m| x > m) || c.get("min").and_then(Value::as_f64).is_some_and(|m| x < m) {
                    return None;
                }
            }
            _ => return None,
        }
        let role = pd.get("role").and_then(Value::as_str).unwrap_or("");
        if role.starts_with("contact.") || role == "party.payee" {
            add("recipient_scope", &mut caveats);
        } else if role == "money.amount" {
            add("amount_cap", &mut caveats);
        } else if role == "count.limit" {
            add("count_cap", &mut caveats);
        } else if role.starts_with("id.") {
            add("resource_scope", &mut caveats);
        }
    }
    Some(caveats)
}

/// Decide one example: `{got, why}`.
pub fn decide_example(d: &Value, ex: &Value, reg: &Registry, defs: &[Value]) -> Result<Value, String> {
    let doc = deps::to_schema_doc(defs, reg, &meta())?;
    let flat = deps::flatten_params(&ex["params"]);
    let c = conform_action(&doc, d["verb"].as_str().unwrap_or(""), &Value::Object(flat.clone()));
    if !c.ok {
        return Ok(
            json!({"got": "deny", "why": format!("schema_violation {}{}", c.code.clone().unwrap_or_default(), c.path.as_ref().map_or(String::new(), |p| format!(" ({p})")))}),
        );
    }
    let op = deps::operation_of(d, &ex["params"]);
    if op["ok"] != Value::Bool(true) {
        return Ok(json!({"got": "deny", "why": op["reason"]}));
    }
    let sels = match parse_under(ex.get("under")) {
        Ok(s) => s,
        Err(m) => return Ok(json!({"got": "deny", "why": format!("bad example policy: {m}")})),
    };
    let (hint, _) = hint_of(d, reg)?;
    let mut call_ctx: Vec<String> = Vec::new();
    let push = |k: &str, ctx: &mut Vec<String>| {
        if !ctx.iter().any(|x| x == k) {
            ctx.push(k.to_string());
        }
    };
    if let Some(idem) = d.get("idempotency").filter(|i| i.is_object()) {
        let mode = idem["mode"].as_str();
        if mode == Some("natural") || (mode == Some("key_param") && idem.get("param").and_then(Value::as_str).is_some_and(|p| flat.contains_key(p))) {
            push("idempotency", &mut call_ctx);
        }
    }
    let mut grant_caveats: Vec<String> = Vec::new();
    let mut pre = 0;
    for s in &sels {
        let Some(g) = grant_of(s, d, &flat, &hint) else { continue };
        pre = 3;
        for k in g {
            if !grant_caveats.contains(&k) {
                grant_caveats.push(k);
            }
        }
        for k in s.get("context").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
            push(k, &mut call_ctx);
        }
    }
    let got = floor_decision(&GrantFacts { caveats: grant_caveats.clone(), max_esc: 3, preauth_esc: pre }, &call_ctx, &hint.eff);
    let why = if got == "allow" {
        "floor satisfied".to_string()
    } else {
        let mut need: Vec<String> = hint.eff.caveats.iter().filter(|k| !grant_caveats.contains(k)).cloned().collect();
        need.extend(hint.eff.context.iter().filter(|k| !call_ctx.contains(k)).cloned());
        format!("floor needs {}", if need.is_empty() { format!("escalation tier {}", hint.eff.esc) } else { need.join(", ") })
    };
    Ok(json!({"got": got, "why": why}))
}

fn mutations(d: &Value, flat: &Map<String, Value>) -> Vec<(String, Value)> {
    let with = |k: &str, v: Value| -> Value {
        let mut m = flat.clone();
        m.insert(k.to_string(), v);
        Value::Object(m)
    };
    let mut out = vec![("extra param".to_string(), with("zz_undeclared", json!("x")))];
    let mut keys: Vec<&String> = flat.keys().collect();
    keys.sort_by(|a, b| u16cmp(a, b));
    for k in keys {
        let Some(pd) = d["params"].get(k.as_str()).filter(|p| !p.is_null()) else { continue };
        if pd.get("required") != Some(&Value::Bool(false)) {
            let mut m = flat.clone();
            m.remove(k.as_str());
            out.push((format!("missing {k}"), Value::Object(m)));
        }
        let v = &flat[k.as_str()];
        out.push((
            format!("type swap {k}"),
            with(
                k,
                if v.is_string() {
                    json!(12345)
                } else if v.is_number() || v.is_boolean() {
                    json!("x")
                } else {
                    json!({})
                },
            ),
        ));
        if v.is_number() && pd["type"] == "integer" {
            if let Some(mx) = pd.get("max").and_then(Value::as_i64) {
                out.push((format!("above max {k}"), with(k, json!(mx + 1))));
            }
            if let Some(mn) = pd.get("min").and_then(Value::as_i64) {
                out.push((format!("below min {k}"), with(k, json!(mn - 1))));
            }
        }
        if v.is_string() && pd["type"] == "string" {
            if pd.get("values").is_some_and(|x| x.as_array().map_or(!x.is_null(), |a| !a.is_empty())) {
                out.push((format!("outside values {k}"), with(k, json!("not_a_listed_value_zz"))));
            }
            if let Some(ml) = pd.get("max_len").and_then(Value::as_u64) {
                out.push((format!("too long {k}"), with(k, json!("x".repeat(ml as usize + 1)))));
            }
        }
    }
    out
}

fn digest_via_yaml(d: &Value) -> Result<Option<String>, String> {
    let ns = d["verb"].as_str().unwrap_or("").split('.').next().unwrap_or("").to_string();
    let text = super::yaml::stringify(&json!({"ns": ns, "actions": [d]}))?;
    let back = super::yaml::parse(&text)?;
    let d2 = back["actions"].get(0).ok_or("the YAML form has no action")?;
    Ok(if validate_def(d2).is_none() { def_digest(d2) } else { None })
}

/// Run examples and property checks for a set of defs (one pack). `prop_limit` bounds the trait subsets tried per def.
pub fn run_def_tests(defs: &[Value], reg: &Registry, prop_limit: Option<i64>) -> Result<Value, String> {
    let (mut examples, mut props): (Vec<Value>, Vec<Value>) = (vec![], vec![]);
    let limit = prop_limit.unwrap_or(256).max(0) as u64;
    let core = core_registry();
    for d in defs {
        let verb = d["verb"].as_str().unwrap_or("");
        for (index, ex) in d.get("examples").and_then(Value::as_array).into_iter().flatten().enumerate() {
            let r = decide_example(d, ex, reg, defs)?;
            examples.push(json!({"verb": verb, "index": index, "expect": ex["expect"], "got": r["got"], "ok": r["got"] == ex["expect"], "why": r["why"]}));
        }
        // T2: adding any core trait never lowers the effective profile
        let (hint, decl) = hint_of(d, reg)?;
        let _ = decl;
        let mut lowered = Vec::new();
        for t in core.traits.keys() {
            if !leq(&hint.eff, &eff_with_trait(d, t, reg).map_err(super::msg)?) {
                lowered.push(t.clone());
            }
        }
        props.push(json!({"verb": verb, "name": "adding a trait never lowers the profile", "ok": lowered.is_empty(), "detail": lowered.join(", ")}));
        // T2 over subsets of the def's own traits (bounded): F(S) <= F(T)
        let ts = &hint.traits;
        let total = (1u64 << ts.len().min(20)).min(limit);
        let top = floor_of(reg, ts).map_err(super::msg)?;
        let mut bad = 0;
        for mask in 0..total {
            let sub: Vec<String> = ts.iter().enumerate().filter(|(i, _)| ((mask >> (i % 32)) & 1) == 1).map(|(_, t)| t.clone()).collect();
            if !leq(&floor_of(reg, &sub).map_err(super::msg)?, &top) {
                bad += 1;
            }
        }
        props.push(
            json!({"verb": verb, "name": "floors are monotone over trait subsets", "ok": bad == 0, "detail": format!("{total} subsets, {bad} violations")}),
        );
        // one digest across the JSON and YAML forms
        let want = def_digest(d);
        let via_json: Option<String> = serde_json::from_str::<Value>(&serde_json::to_string(d).map_err(|e| e.to_string())?)
            .ok()
            .filter(|x| validate_def(x).is_none())
            .and_then(|x| def_digest(&x));
        let ok_j = via_json.is_some() && via_json == want;
        let via_yaml = digest_via_yaml(d);
        let ok_y = matches!(&via_yaml, Ok(Some(x)) if Some(x) == want.as_ref());
        let word = |ok: bool, r: &Result<Option<String>, String>| -> String {
            if ok {
                "ok".into()
            } else {
                match r {
                    Err(e) => e.clone(),
                    _ => "digest differs".into(),
                }
            }
        };
        props.push(json!({"verb": verb, "name": "one digest across JSON and YAML forms", "ok": ok_j && ok_y,
                          "detail": if ok_j && ok_y { String::new() } else { format!("json {}; yaml {}", word(ok_j, &Ok::<_, String>(via_json.clone())), word(ok_y, &via_yaml)) }}));
        // schema round trip: each example conforms, every mutation is refused
        let exs = d.get("examples").and_then(Value::as_array).cloned().unwrap_or_default();
        if exs.is_empty() {
            props.push(json!({"verb": verb, "name": "schema round trip", "ok": true, "detail": "skipped: no examples"}));
            continue;
        }
        let doc = deps::to_schema_doc(defs, reg, &meta())?;
        let (mut accepted, mut tried): (Vec<String>, usize) = (vec![], 0);
        for ex in &exs {
            let flat = deps::flatten_params(&ex["params"]);
            if !conform_action(&doc, verb, &Value::Object(flat.clone())).ok {
                continue; // a deliberately non-conforming example is a deny example
            }
            for (name, params) in mutations(d, &flat) {
                tried += 1;
                if conform_action(&doc, verb, &params).ok {
                    accepted.push(name);
                }
            }
        }
        let mut uniq: Vec<String> = Vec::new();
        for a in accepted {
            if !uniq.contains(&a) {
                uniq.push(a);
            }
        }
        props.push(json!({"verb": verb, "name": "schema round trip", "ok": uniq.is_empty(), "detail": if uniq.is_empty() { format!("{tried} mutations refused") } else { format!("accepted: {}", uniq.join(", ")) }}));
    }
    let ok = examples.iter().all(|e| e["ok"] == Value::Bool(true)) && props.iter().all(|q| q["ok"] == Value::Bool(true));
    Ok(json!({"examples": examples, "props": props, "ok": ok}))
}

/// The report as plain text: one PASS/FAIL line per example and property, then a summary.
pub fn test_text(r: &Value) -> String {
    let mut lines: Vec<String> = Vec::new();
    for e in r["examples"].as_array().into_iter().flatten() {
        lines.push(format!(
            "{}  {} example {}: expected {}, got {} ({})",
            if e["ok"] == Value::Bool(true) { "PASS" } else { "FAIL" },
            e["verb"].as_str().unwrap_or(""),
            e["index"].as_i64().unwrap_or(0) + 1,
            e["expect"].as_str().unwrap_or(""),
            e["got"].as_str().unwrap_or(""),
            e["why"].as_str().unwrap_or("")
        ));
    }
    for q in r["props"].as_array().into_iter().flatten() {
        let detail = q["detail"].as_str().unwrap_or("");
        lines.push(format!(
            "{}  {} {}{}",
            if q["ok"] == Value::Bool(true) { "PASS" } else { "FAIL" },
            q["verb"].as_str().unwrap_or(""),
            q["name"].as_str().unwrap_or(""),
            if detail.is_empty() { String::new() } else { format!(": {detail}") }
        ));
    }
    let f = lines.iter().filter(|l| l.starts_with("FAIL")).count();
    lines.push(format!("{} passed, {f} failed", lines.len() - f));
    lines.join("\n")
}
