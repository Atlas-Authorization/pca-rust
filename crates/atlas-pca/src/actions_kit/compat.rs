//! Migration shims between the old, disagreeing action vocabularies and the one ActionDef vocabulary (native port of `compat.ts` of
//! the reference). Every conversion is total and fails closed: an unknown reversibility word is `irreversible`.

use serde_json::{json, Map, Value};

use super::{get, opt, rev_rank};

const PPM_MAX: f64 = 1_000_000.0;
const RADII: [(&str, f64); 4] = [("one", 50_000.0), ("bounded", 300_000.0), ("tenant", 700_000.0), ("global", 1_000_000.0)];

/// Any old reversibility word to the canonical class; anything unknown is irreversible (fail closed).
pub fn normalize_reversibility(x: &Value) -> &'static str {
    match x.as_str() {
        Some("reversible") | Some("read") => "reversible",
        Some("rate_limited") | Some("costly") => "rate_limited",
        _ => "irreversible",
    }
}

/// The operations-side word for the revocation staleness table (`rate_limited` -> `costly`).
pub fn legacy_operations_class(r: &str) -> String {
    if r == "rate_limited" {
        "costly".into()
    } else {
        r.to_string()
    }
}

pub fn max_rev_of(a: &str, b: &str) -> String {
    if rev_rank(a) >= rev_rank(b) {
        a.to_string()
    } else {
        b.to_string()
    }
}

/// The schema `units` entry / envelope UnitTag of a def's unit; `Null` for a money unit whose currency is a parameter reference.
pub fn unit_tag_of(u: &Value) -> Value {
    let kind = get(u, "kind").as_str().unwrap_or("");
    if kind != "money" {
        return json!({ "kind": kind });
    }
    let Some(ccy) = get(u, "ccy").as_str() else { return Value::Null };
    let mut out = json!({"kind": "money", "currency": ccy});
    if let Some(e) = u.get("exp") {
        out["exponent"] = e.clone();
    }
    out
}

fn js_round(v: f64) -> f64 {
    let f = v.floor();
    if v - f >= 0.5 {
        f + 1.0
    } else {
        f
    }
}

fn ppm_of(x: &Value) -> i64 {
    let f = x.as_f64().filter(|f| f.is_finite()).unwrap_or(1.0);
    js_round(f * 1_000_000.0).max(0.0).min(PPM_MAX) as i64
}

/// The smallest radius whose default covers the float, and the integer ppm.
pub fn blast_of_float(x: &Value) -> Value {
    let ppm = ppm_of(x);
    let radius = RADII.iter().find(|(_, p)| *p >= ppm as f64).map_or("global", |(r, _)| *r);
    json!({"radius": radius, "ppm": ppm})
}

/// A legacy float kept exactly: the largest radius whose default does not exceed it, the ppm override carrying the exact value.
pub fn blast_exact_of_float(x: &Value) -> Value {
    let ppm = ppm_of(x);
    let radius = RADII.iter().rev().find(|(_, p)| *p <= ppm as f64).map_or("one", |(r, _)| *r);
    json!({"radius": radius, "ppm": ppm})
}

/// A word of `words` starting at byte `p`, followed by `_` or the end.
fn word_at(s: &str, p: usize, words: &[&str]) -> bool {
    words.iter().any(|w| s[p..].starts_with(w) && (s.len() == p + w.len() || s.as_bytes()[p + w.len()] == b'_'))
}

/// `/(?:^|_)(?:words)(?:_|$)/`
fn has_word(s: &str, words: &[&str]) -> bool {
    (0..s.len()).any(|p| (p == 0 || s.as_bytes()[p - 1] == b'_') && word_at(s, p, words))
}

fn str_of<'a>(s: &'a Value, k: &str) -> Result<&'a str, String> {
    s.get(k).and_then(Value::as_str).ok_or_else(|| format!("catalog spec: {k} must be a string"))
}

/// Convert an old catalog entry: effects inferred conservatively from the action name (an unknown write is `update`, never `read`);
/// an `amountField` becomes a bounded money.amount parameter; the result is `authored`. `o` is `{ccy, exp, maxAmount}`.
pub fn from_catalog_spec(s: &Value, o: Option<&Value>) -> Result<Value, String> {
    let none = Value::Null;
    let o = o.unwrap_or(&none);
    let action = str_of(s, "action")?;
    let has_amount = s.get("amountField").is_some();
    let mut effects: Vec<&str> = Vec::new();
    if has_amount {
        effects.push("pay");
    }
    if word_at(action, 0, &["read", "get", "list", "view", "search", "fetch", "head"]) && !action.is_empty() {
        effects.push("read");
    }
    if has_word(action, &["delete", "remove", "destroy", "drop", "purge"]) {
        effects.push("delete");
    }
    if has_word(action, &["send", "post", "publish", "notify", "email", "sms"]) {
        effects.push("send");
    }
    if effects.is_empty() {
        effects.push("update");
    }
    let mut params = Map::new();
    if has_amount {
        let field = str_of(s, "amountField")?;
        params.insert(
            field.to_string(),
            json!({
                "type": "integer", "role": "money.amount", "min": 0, "max": opt(o, "maxAmount").cloned().unwrap_or(json!(100_000_000_000i64)),
                "unit": {"kind": "money", "ccy": opt(o, "ccy").cloned().unwrap_or(json!("USD")), "exp": opt(o, "exp").cloned().unwrap_or(json!(2))},
            }),
        );
        params.insert("idempotency_key".into(), json!({"type": "string", "max_len": 128}));
    }
    let b = blast_of_float(get(s, "blastRadius"));
    let wildcard = s.get("resource").is_none() || s["resource"].as_str() == Some("*");
    let desc = str_of(s, "description")?;
    let title = if desc.encode_utf16().count() > 120 {
        let head: Vec<u16> = desc.encode_utf16().take(117).collect();
        format!("{}...", String::from_utf16_lossy(&head))
    } else {
        desc.to_string()
    };
    let mut out = Map::new();
    out.insert("v".into(), json!(1));
    out.insert("kind".into(), json!("pca-action-def"));
    out.insert("verb".into(), json!(str_of(s, "verb")?));
    out.insert("title".into(), json!(title));
    out.insert("description".into(), json!(desc));
    out.insert("effects".into(), json!(effects));
    let id = if wildcard { json!("*") } else { json!({"prefix": "", "class": "any_safe", "len": [1, 128]}) };
    let scope = if wildcard { "set" } else { "one" };
    out.insert("resource".into(), json!({"type": str_of(s, "connector")?, "id": id, "scope": scope}));
    out.insert("params".into(), Value::Object(params));
    out.insert("reversibility".into(), json!(normalize_reversibility(get(s, "reversibility"))));
    out.insert("blast".into(), json!({"radius": b["radius"], "ppm": b["ppm"]}));
    if has_amount {
        out.insert("idempotency".into(), json!({"mode": "key_param", "param": "idempotency_key"}));
    }
    out.insert("review".into(), json!({"state": "authored"}));
    Ok(Value::Object(out))
}

pub fn from_catalog(specs: &Value, o: Option<&Value>) -> Result<Value, String> {
    let xs = specs.as_array().ok_or("catalog specs must be a list")?;
    Ok(Value::Array(xs.iter().map(|s| from_catalog_spec(s, o)).collect::<Result<Vec<_>, _>>()?))
}
