//! Everything an ActionDef yields (native port of `derive.ts` and `explain.ts` of the reference): the signed schema verb and
//! document, the operation binding, risk inputs, policy predicates, ontology terms, the policy card, the escalation tier, MCP
//! annotations and the plain-language explanation. `eff` arguments are [`EffWith`] values from [`effective_with`]; the
//! confirmation verifier is the caller's (see [`Verifier`]).

use serde_json::{json, Map, Value};

use super::{arr, effective_with, get, id_matches, ke, num_value, opt, safe_int, strs, u16cmp, EffWith, Verifier};
use crate::actions::{closure, def_digest, is_read_only, normalize, traits_digest, worst_reversibility, Registry};
use crate::intent_v2::js_value_string;

const MAX_PARAM_PATH_DEPTH: usize = 3;
const ESC_TIERS: [&str; 4] = ["auto", "confirm", "cosign", "stepup"];
const RISK_NAMES: [&str; 4] = ["low", "elevated", "high", "critical"];

fn name_at(xs: &[&'static str], i: i64) -> &'static str {
    usize::try_from(i).ok().and_then(|i| xs.get(i).copied()).unwrap_or("")
}

fn sorted_keys(v: &Value) -> Vec<String> {
    let mut ks: Vec<String> = v.as_object().map(|m| m.keys().cloned().collect()).unwrap_or_default();
    ks.sort_by(|a, b| u16cmp(a, b));
    ks
}

// ---- flattened params + role lookup ------------------------------------------------------------------------------------------

fn walk(out: &mut Map<String, Value>, prefix: &str, depth: usize, v: &Value) {
    match v {
        Value::Object(m) if depth < MAX_PARAM_PATH_DEPTH && !m.is_empty() => {
            for (k, x) in m {
                let p = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                walk(out, &p, depth + 1, x);
            }
        }
        _ => {
            out.insert(prefix.to_string(), v.clone());
        }
    }
}

/// Nested plain objects become dotted keys (up to 3 segments); arrays and scalars are leaves; a deeper object stays a leaf.
pub fn flatten_params(params: &Value) -> Value {
    let mut out = Map::new();
    if let Some(m) = params.as_object() {
        for (k, v) in m {
            walk(&mut out, k, 1, v);
        }
    }
    Value::Object(out)
}

/// The unique param carrying `role`; errs `no_param` / `ambiguous_param` (reference messages).
pub fn param_by_role(d: &Value, role: &str) -> Result<String, String> {
    let params = get(d, "params");
    let mut hits: Vec<String> = sorted_keys(params).into_iter().filter(|n| get(&params[n.as_str()], "role").as_str() == Some(role)).collect();
    let verb = js_value_string(get(d, "verb"));
    match hits.len() {
        0 => Err(format!("'{verb}' has no parameter with role {role}")),
        1 => Ok(hits.remove(0)),
        _ => Err(format!("'{verb}' has several parameters with role {role}")),
    }
}

/// The one adapter to the Goal IR's 4 classes: `read | reversible | external_send | irreversible`.
pub fn effect_class(d: &Value) -> String {
    let n = normalize(d);
    let effects = strs(&n["effects"]);
    if is_read_only(&effects) {
        return "read".into();
    }
    let no = Map::new();
    if worst_reversibility(&n["reversibility"], n["params"].as_object().unwrap_or(&no)) == "irreversible" {
        return "irreversible".into();
    }
    if effects.iter().any(|e| e == "send" || e == "publish" || e == "export") {
        return "external_send".into();
    }
    "reversible".into()
}

// ---- signed schema (v2) ------------------------------------------------------------------------------------------------------

fn unit_id(p: &Value) -> Option<String> {
    let u = opt(p, "unit")?;
    let kind = get(u, "kind").as_str().unwrap_or("");
    if kind != "money" {
        return Some(kind.to_string());
    }
    get(u, "ccy").as_str().map(|c| format!("money.{}", c.to_lowercase()))
}

fn unit_decl(p: &Value) -> Option<Value> {
    let u = opt(p, "unit")?;
    let kind = get(u, "kind").as_str().unwrap_or("");
    if kind != "money" {
        return Some(json!({ "kind": kind }));
    }
    let ccy = get(u, "ccy").as_str()?;
    let mut out = json!({"kind": "money", "currency": ccy});
    if let Some(e) = u.get("exp") {
        out["exponent"] = e.clone();
    }
    Some(out)
}

fn to_param_decl(n: &Value) -> Value {
    let ty = get(n, "type").as_str().unwrap_or("");
    let semantic = match opt(n, "role").and_then(Value::as_str) {
        Some(r) => r.to_string(),
        None => format!("generic.{ty}"),
    };
    let mut d = Map::new();
    d.insert("type".into(), json!(ty));
    d.insert("semantic".into(), json!(semantic));
    d.insert("sensitivity".into(), get(n, "sensitivity").clone());
    if n.get("required").and_then(Value::as_bool) == Some(false) {
        d.insert("required".into(), json!(false));
    }
    if let Some(v) = n.get("values") {
        d.insert("values".into(), v.clone());
    }
    for k in ["min", "max", "max_len", "items", "min_items", "max_items", "format", "provenance_min", "default", "principal_neutral_default", "description"] {
        if let Some(v) = n.get(k) {
            d.insert(k.into(), v.clone());
        }
    }
    if let Some(u) = unit_id(n) {
        d.insert("unit".into(), json!(u));
    }
    if let Some(a) = n.get("accumulates") {
        d.insert("accumulates_into".into(), a.clone());
    }
    if let Some(r) = n.get("role") {
        d.insert("role".into(), r.clone());
    }
    if let Some(t) = n.get("tags") {
        d.insert("tags".into(), t.clone());
    }
    Value::Object(d)
}

/// `{verb, units}`: the signed v2 verb declaration of a def (effects, traits, def digest, materialized floors) and the units it needs.
pub fn to_schema_verb(d: &Value, reg: &Registry, verifier: Verifier) -> Result<Value, String> {
    let n = normalize(d);
    let eff = effective_with(d, reg, verifier)?;
    let mut params = Map::new();
    let mut units = Map::new();
    for (name, p) in n["params"].as_object().into_iter().flatten() {
        params.insert(format!("action.params.{name}"), to_param_decl(p));
        if let (Some(uid), Some(ud)) = (unit_id(p), unit_decl(p)) {
            units.insert(uid, ud);
        }
    }
    let effects = strs(&n["effects"]);
    let mut v = Map::new();
    v.insert("verb".into(), n["verb"].clone());
    v.insert("kind".into(), json!(if is_read_only(&effects) { "read" } else { "write" }));
    v.insert("params".into(), Value::Object(params));
    v.insert("effects".into(), n["effects"].clone());
    v.insert("traits".into(), json!(eff.main.traits));
    v.insert("def".into(), json!(def_digest(d).ok_or("the def is not in the strict JSON profile")?));
    v.insert("floors".into(), eff.main.eff.to_value());
    if let Some(att) = d.get("review").and_then(|r| r.get("attestation")).filter(|a| a.get("sig").is_some() && a.is_object()) {
        if eff.confirmed {
            v.insert("confirmation".into(), att.clone());
        }
    }
    let r = &n["reversibility"];
    if r.is_string() {
        v.insert("reversibility".into(), r.clone());
    } else {
        let mut by = Map::new();
        by.insert("param".into(), json!(format!("action.params.{}", js_value_string(get(r, "by")))));
        by.insert("map".into(), get(r, "map").clone());
        if let Some(df) = r.get("default") {
            by.insert("default".into(), df.clone());
        }
        v.insert("reversibility_by".into(), Value::Object(by));
    }
    let b = &n["bindings"];
    if let Some(m) = opt(b, "mcp") {
        v.insert("mcp".into(), m.get("tool").map_or(json!({}), |t| json!({ "tool": t })));
    }
    if let Some(m) = opt(b, "openapi") {
        v.insert("openapi".into(), m.get("operationId").map_or(json!({}), |t| json!({ "operationId": t })));
    }
    if let Some(desc) = n.get("description") {
        v.insert("description".into(), desc.clone());
    }
    Ok(json!({"verb": Value::Object(v), "units": Value::Object(units)}))
}

fn trait_json(t: &crate::actions::TraitDef) -> Value {
    json!({"id": t.id, "implies": t.implies, "floor": t.floor.to_value(), "card_phrase": t.card_phrase})
}

/// The unsigned v2 schema document of a set of defs (verbs sorted; units merged, a conflicting redefinition refused).
pub fn to_schema_doc(defs: &[Value], reg: &Registry, meta: &Value, verifier: Verifier) -> Result<Value, String> {
    let mut sorted: Vec<&Value> = defs.iter().collect();
    sorted.sort_by(|a, b| u16cmp(get(a, "verb").as_str().unwrap_or(""), get(b, "verb").as_str().unwrap_or("")));
    let mut verbs = Vec::new();
    let mut units: Map<String, Value> = Map::new();
    let mut seen: Vec<&str> = Vec::new();
    for d in sorted {
        let verb = get(d, "verb").as_str().unwrap_or("");
        if seen.contains(&verb) {
            return Err(format!("verb '{verb}' appears twice"));
        }
        seen.push(verb);
        let o = to_schema_verb(d, reg, verifier)?;
        verbs.push(o["verb"].clone());
        for (uid, u) in o["units"].as_object().into_iter().flatten() {
            if let Some(prev) = units.get(uid) {
                if prev.get("kind") != u.get("kind") || prev.get("currency") != u.get("currency") || prev.get("exponent") != u.get("exponent") {
                    return Err(format!("unit '{uid}' is declared with two different definitions"));
                }
            }
            units.insert(uid.clone(), u.clone());
        }
    }
    let mut custom: Vec<&crate::actions::TraitDef> = reg.traits.values().filter(|t| !t.id.starts_with("pca.")).collect();
    custom.sort_by(|a, b| u16cmp(&a.id, &b.id));
    let mut doc = Map::new();
    doc.insert("v".into(), json!(2));
    doc.insert("kind".into(), json!("pca-action-schema"));
    doc.insert("site".into(), get(meta, "site").clone());
    doc.insert("aud".into(), get(meta, "aud").clone());
    doc.insert("version".into(), get(meta, "version").clone());
    if !units.is_empty() {
        doc.insert("units".into(), Value::Object(units));
    }
    doc.insert("verbs".into(), Value::Array(verbs));
    doc.insert("traits_digest".into(), json!(traits_digest(reg)));
    if !custom.is_empty() {
        doc.insert("trait_defs".into(), Value::Array(custom.into_iter().map(trait_json).collect()));
    }
    if let Some(p) = opt(meta, "pack") {
        doc.insert("pack".into(), p.clone());
    }
    Ok(Value::Object(doc))
}

// ---- operation binding -------------------------------------------------------------------------------------------------------

/// `{ok: true, op: {verb, resource, params}}` or `{ok: false, reason}`: refuses (never guesses) a missing or non-matching id.
/// `call_params` is the call's `params` object.
pub fn operation_of(d: &Value, call_params: &Value) -> Value {
    let flat = flatten_params(call_params);
    let dparams = get(d, "params");
    let declared = sorted_keys(dparams);
    let mut params = Map::new();
    for k in &declared {
        if let Some(v) = flat.get(k) {
            params.insert(k.clone(), v.clone());
        }
    }
    let res = get(d, "resource");
    let (rtype, rid, scope) = (js_value_string(get(res, "type")), get(res, "id"), get(res, "scope").as_str().unwrap_or(""));
    let verb = js_value_string(get(d, "verb"));
    let resource = if rid.as_str() != Some("*") && rid.get("exact").is_some() {
        format!("{rtype}:{}", js_value_string(&rid["exact"]))
    } else {
        let want = format!("id.{rtype}");
        let id_param = declared.iter().find(|n| get(&dparams[n.as_str()], "role").as_str() == Some(want.as_str()));
        match id_param.and_then(|n| params.get(n)).and_then(Value::as_str) {
            Some(val) => {
                if !id_matches(rid, &Value::String(val.to_string())) {
                    return json!({"ok": false, "reason": format!("the id '{val}' does not match the resource pattern of {verb}")});
                }
                format!("{rtype}:{val}")
            }
            None if scope != "one" => format!("{rtype}:*"),
            None => return json!({"ok": false, "reason": format!("{verb} needs a parameter with role id.{rtype} to name its resource")}),
        }
    };
    json!({"ok": true, "op": {"verb": get(d, "verb"), "resource": resource, "params": Value::Object(params)}})
}

// ---- risk --------------------------------------------------------------------------------------------------------------------

fn unit01(x: f64) -> f64 {
    x.max(0.0).min(1.0)
}

/// The reversibility score of a class (`REVERSIBILITY_SCORE`).
pub fn reversibility_score(class: &str) -> Value {
    match class {
        "reversible" => json!(1),
        "rate_limited" => json!(0.4),
        _ => json!(0),
    }
}

/// `REVERSIBILITY_SCORE` as an object.
pub fn reversibility_score_table() -> Value {
    json!({"reversible": 1, "rate_limited": 0.4, "irreversible": 0})
}

/// Risk inputs for a call: reversibility score and blast from the effective profile; a money.amount param makes the blast
/// amount/kappa from the signed kappa (missing or invalid: 1, the worst case). Reads nothing the agent claims.
pub fn risk_of(d: &Value, eff: &EffWith, params: Option<&Value>, opts: Option<&Value>) -> Value {
    let mut blast = unit01(eff.main.eff.blast_ppm as f64 / 1_000_000.0);
    let dparams = get(d, "params");
    let money: Vec<String> = sorted_keys(dparams).into_iter().filter(|n| get(&dparams[n.as_str()], "role").as_str() == Some("money.amount")).collect();
    let none = Value::Null;
    let opts = opts.unwrap_or(&none);
    if let Some(first) = money.first() {
        let flat = params.filter(|p| p.as_object().is_some_and(|m| !m.is_empty())).map_or(Value::Object(Map::new()), flatten_params);
        let amount = flat.get(first).and_then(Value::as_f64);
        let kappa = opt(opts, "kappa").and_then(Value::as_f64);
        blast = match (amount, kappa) {
            (Some(a), Some(k)) if a.is_finite() && a >= 0.0 && k > 0.0 => unit01(a / k),
            _ => 1.0,
        };
    }
    let mut out = Map::new();
    out.insert("reversibility".into(), reversibility_score(&eff.main.eff.rev));
    out.insert("blastRadius".into(), num_value(blast));
    out.insert("confidence".into(), json!(1));
    if let Some(t) = opt(opts, "taint").and_then(Value::as_f64).filter(|t| t.is_finite()) {
        out.insert("taint".into(), num_value(unit01(t)));
    }
    Value::Object(out)
}

// ---- predicates --------------------------------------------------------------------------------------------------------------

/// `<type>:<prefix>*`, `<type>:<exact>` or `<type>:*`.
pub fn resource_matcher(d: &Value) -> String {
    let res = get(d, "resource");
    let rtype = js_value_string(get(res, "type"));
    let rid = get(res, "id");
    if rid.as_str() == Some("*") {
        return format!("{rtype}:*");
    }
    match rid.get("exact") {
        Some(e) => format!("{rtype}:{}", js_value_string(e)),
        None => format!("{rtype}:{}*", js_value_string(get(rid, "prefix"))),
    }
}

/// The policy predicate scaffold; a money limit on a def with no money.amount parameter errs (never silently unbounded).
pub fn predicates_of(d: &Value, limits: Option<&Value>) -> Result<Value, String> {
    let mut out = Map::new();
    out.insert("verb".into(), get(d, "verb").clone());
    out.insert("resource".into(), json!(resource_matcher(d)));
    if let Some(m) = limits.and_then(|l| l.get("max_amount")) {
        match safe_int(m) {
            Some(mv) if mv >= 0 => {
                let name = param_by_role(d, "money.amount")?;
                let field = format!("action.params.{name}");
                out.insert("where".into(), json!([{"field": field, "op": "lte", "value": m}, {"field": field, "op": "gte", "value": 0}]));
            }
            _ => return Err("max_amount must be a non-negative safe integer".into()),
        }
    }
    Ok(Value::Object(out))
}

// ---- Goal IR ontology terms --------------------------------------------------------------------------------------------------

fn sorted_u16(xs: Vec<String>) -> Vec<String> {
    let mut xs = xs;
    xs.sort_by(|a, b| u16cmp(a, b));
    xs
}

pub(crate) fn ont_param(d: &Value, p: &Value) -> Value {
    if let Some(u) = opt(p, "unit") {
        let kind = get(u, "kind").as_str().unwrap_or("");
        if kind == "money" {
            let c = get(u, "ccy");
            if let Some(c) = c.as_str() {
                return json!({"kind": "money", "ccys": [c]});
            }
            let ccys =
                get(c, "from").as_str().and_then(|f| get(d, "params").get(f)).and_then(|cp| opt(cp, "values")).map(|v| sorted_u16(strs(v))).unwrap_or_default();
            return json!({"kind": "money", "ccys": ccys});
        }
        let k = match kind {
            "duration" => "duration",
            "bytes" => "bytes",
            "ratio" => "ratio",
            _ => "count",
        };
        return json!({ "kind": k });
    }
    if let Some(r) = opt(p, "role").and_then(Value::as_str).filter(|r| r.starts_with("id.")) {
        return json!({"kind": "id", "of": &r[3..]});
    }
    if let Some(f) = opt(p, "format").and_then(Value::as_str).filter(|f| f.starts_with("id:")) {
        return json!({"kind": "id", "of": &f[3..]});
    }
    match get(p, "type").as_str().unwrap_or("") {
        "duration" => json!({"kind": "duration"}),
        "datetime" | "date" => json!({"kind": "instant"}),
        "integer" => json!({"kind": "count"}),
        "boolean" => json!({"kind": "enum", "values": ["false", "true"]}),
        "set" => json!({"kind": "enum", "values": sorted_u16(strs(get(p, "values")))}),
        "string" => match opt(p, "values") {
            Some(v) => json!({"kind": "enum", "values": sorted_u16(strs(v))}),
            None => json!({"kind": "text"}),
        },
        _ => json!({"kind": "text"}),
    }
}

/// Ontology terms for a set of defs; `effect` is derived ([`effect_class`]), never overridden.
pub fn to_ontology(defs: &[Value], reg: &Registry, verifier: Verifier) -> Result<Value, String> {
    let mut sorted: Vec<&Value> = defs.iter().collect();
    sorted.sort_by(|a, b| u16cmp(get(a, "verb").as_str().unwrap_or(""), get(b, "verb").as_str().unwrap_or("")));
    let mut types: Vec<(String, String)> = Vec::new();
    let mut units = Map::new();
    let mut verbs = Vec::new();
    let mut aliases = Map::new();
    let mut traits = Map::new();
    for d in sorted {
        let res = get(d, "resource");
        let rid = get(res, "id");
        let prefix = if rid.as_str() == Some("*") || rid.get("exact").is_some() { String::new() } else { js_value_string(get(rid, "prefix")) };
        let rtype = js_value_string(get(res, "type"));
        if !types.iter().any(|(t, _)| *t == rtype) {
            types.push((rtype.clone(), prefix));
        }
        let dparams = get(d, "params");
        let mut params = Map::new();
        for name in sorted_keys(dparams) {
            let p = &dparams[name.as_str()];
            params.insert(name.clone(), ont_param(d, p));
            if let Some(u) = opt(p, "unit") {
                let kind = get(u, "kind").as_str().unwrap_or("");
                if kind == "money" {
                    if let Some(c) = get(u, "ccy").as_str() {
                        let mut m = json!({"kind": "money"});
                        if let Some(e) = u.get("exp") {
                            m["exponent"] = e.clone();
                        }
                        units.insert(c.to_string(), m);
                    }
                } else {
                    units.insert(kind.to_string(), json!({ "kind": kind }));
                }
            }
        }
        let verb = js_value_string(get(d, "verb"));
        verbs.push(json!({"id": verb, "effect": effect_class(d), "resource_type": rtype, "params": Value::Object(params)}));
        for a in arr(get(d, "aliases")) {
            let a = js_value_string(a);
            if aliases.get(&a).is_some_and(|v| v.as_str() != Some(verb.as_str())) {
                return Err(format!("alias '{a}' names two verbs"));
            }
            aliases.insert(a, json!(verb));
        }
        traits.insert(verb, json!(effective_with(d, reg, verifier)?.main.traits));
    }
    let types: Vec<Value> = types.into_iter().map(|(i, p)| json!({"id": i, "id_prefix": p})).collect();
    Ok(json!({"types": types, "units": Value::Object(units), "verbs": verbs, "aliases": Value::Object(aliases), "traits": Value::Object(traits)}))
}

// ---- policy card + escalation + MCP annotations ------------------------------------------------------------------------------

fn sentence(s: &str) -> String {
    if s.ends_with(['.', '!', '?']) {
        s.to_string()
    } else {
        format!("{s}.")
    }
}

fn list(xs: &[String]) -> String {
    match xs.len() {
        0 => String::new(),
        1 => xs[0].clone(),
        n => format!("{} and {}", xs[..n - 1].join(", "), xs[n - 1]),
    }
}

/// The deterministic policy card: the title and the phrases of the trait closure, riskiest first.
pub fn card_of(d: &Value, eff: &EffWith, reg: &Registry) -> Result<Value, String> {
    let ids = ke(closure(reg, &eff.main.traits))?;
    let mut ordered: Vec<&crate::actions::TraitDef> = ids.iter().filter_map(|i| reg.traits.get(i)).collect();
    ordered.sort_by(|a, b| b.floor.risk.cmp(&a.floor.risk).then_with(|| u16cmp(&a.id, &b.id)));
    let mut phrases: Vec<String> = Vec::new();
    for t in ordered {
        if !phrases.contains(&t.card_phrase) {
            phrases.push(t.card_phrase.clone());
        }
    }
    let e = &eff.main.eff;
    let second = if eff.confirmed {
        if phrases.is_empty() {
            "This action only reads.".to_string()
        } else {
            format!("This action {}.", list(&phrases))
        }
    } else {
        format!("This action has not been reviewed by a person, so it is treated as the most dangerous kind of action: it {}.", list(&phrases))
    };
    let title = get(d, "title").as_str().unwrap_or("");
    Ok(json!({
        "verb": get(d, "verb"), "title": get(d, "title"), "text": format!("{} {}", sentence(title), second), "risk": name_at(&RISK_NAMES, e.risk),
        "escalation": name_at(&ESC_TIERS, e.esc), "reversibility": e.rev, "blast_ppm": e.blast_ppm, "needs": e.caveats, "context": e.context,
    }))
}

/// The minimum escalation tier of the effective profile.
pub fn escalation_of(eff: &EffWith) -> Value {
    json!({"tier": eff.main.eff.esc, "name": name_at(&ESC_TIERS, eff.main.eff.esc)})
}

/// Advisory MCP tool annotations; an unreviewed def's own claim of safety is never advertised.
pub fn mcp_annotations_of(d: &Value, eff: &EffWith) -> Value {
    let cl = &eff.main.closure;
    let idem = d.get("idempotency").and_then(|i| i.get("mode")).and_then(Value::as_str).unwrap_or("none");
    let ro = is_read_only(&strs(get(d, "effects")));
    json!({
        "readOnlyHint": eff.confirmed && ro, "destructiveHint": cl.iter().any(|t| t == "pca.destructive"),
        "idempotentHint": eff.confirmed && (idem != "none" || ro),
        "openWorldHint": cl.iter().any(|t| t == "pca.network_egress" || t == "pca.external_communication"),
    })
}

// ---- explain.ts --------------------------------------------------------------------------------------------------------------

fn blast_text(ppm: i64) -> String {
    if ppm % 1000 == 0 {
        format!("{}k", ppm / 1000)
    } else {
        format!("{ppm}ppm")
    }
}

/// The plain-language profile of one def: card, effective profile, what a grant must carry, traits and review state.
pub fn explain_def(d: &Value, reg: &Registry, verifier: Verifier) -> Result<String, String> {
    let eff = effective_with(d, reg, verifier)?;
    let card = card_of(d, &eff, reg)?;
    let e = &eff.main.eff;
    let rev = match e.rev.as_str() {
        "irreversible" => "irreversible",
        "rate_limited" => "rate limited",
        _ => "reversible",
    };
    let needs = strs(&card["needs"]);
    let mut lines = vec![
        card["text"].as_str().unwrap_or("").to_string(),
        format!("effective: risk {}, {}, blast {}, escalation: {}", e.risk, rev, blast_text(e.blast_ppm), card["escalation"].as_str().unwrap_or("")),
        format!("grant must carry: {}", if needs.is_empty() { "nothing".to_string() } else { needs.join(", ") }),
    ];
    let ctx = strs(&card["context"]);
    if !ctx.is_empty() {
        lines.push(format!("call must carry: {}", ctx.join(", ")));
    }
    lines.push(format!("traits: {}", if eff.main.closure.is_empty() { "none".to_string() } else { eff.main.closure.join(", ") }));
    let state = js_value_string(get(get(d, "review"), "state"));
    lines.push(format!("review: {}", if eff.confirmed { state } else { format!("{state}, not confirmed by a signed review") }));
    if !eff.confirmed {
        let h = &eff.hint;
        lines.push(format!(
            "until a reviewer signs it this action is treated as the most dangerous kind of action; as written it would be: risk {}, escalation tier {}, traits: {}",
            h.eff.risk,
            h.eff.esc,
            if h.closure.is_empty() { "none".to_string() } else { h.closure.join(", ") }
        ));
    }
    Ok(lines.join("\n"))
}
