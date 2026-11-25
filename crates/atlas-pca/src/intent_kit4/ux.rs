//! Question cards for human studies (`ux.ts`): a deterministic, structured form of a cell question, and the parser that turns card
//! input into the learner's answer.
use super::{js_num, R};
use crate::intent_kit::compilers::label_of;
use crate::intent_kit::{hash_strict, jn};
use crate::intent_kit2::omega::Vs;
use crate::intent_kit3::js_str;
use crate::intent_kit3::render::render_question;
use serde_json::{json, Map, Value};

fn at<T>(xs: &[T], i: usize) -> R<&T> {
    xs.get(i).ok_or_else(|| "Cannot read properties of undefined (reading 'kind')".to_string())
}

fn idx_of(cell: &[Value], k: usize) -> R<usize> {
    let v = cell.get(k).ok_or("Cannot read properties of undefined")?;
    crate::intent_kit::as_usize(v).ok_or_else(|| "Cannot read properties of undefined".to_string())
}

/// The card of a cell question `{verb, cell}`.
pub fn question_card(omega: &Value, q: &Value) -> R<Value> {
    let verb = &q["verb"];
    let vs_json =
        omega["verbs"].as_array().and_then(|a| a.iter().find(|v| &v["verb"] == verb)).ok_or_else(|| format!("questionCard: no verb {}", js_str(Some(verb))))?;
    let vs = Vs::parse(vs_json)?;
    let cell = q["cell"].as_array().ok_or("Cannot read properties of undefined (reading '0')")?;
    let mut facts = vec![];
    let mut partial = vec![];
    for (k, d) in vs.dims.iter().enumerate() {
        let i = idx_of(cell, k)?;
        let label = label_of(&d.path);
        if d.is_num {
            let (lo, hi) = *at(&d.cells, i)?;
            let text = if lo == hi {
                format!("exactly {}", js_num(lo))
            } else {
                format!("any value from {} to {} (for example {})", js_num(lo), js_num(hi), js_str(Some(&d.rep_value(i)?)))
            };
            facts.push(json!({"path": d.path, "label": label, "text": text}));
            partial.push(json!({"path": d.path, "kind": "num", "lo": jn(lo), "hi": jn(hi)}));
        } else {
            let v = at(&d.values, i)?;
            let text = match v.kind.as_str() {
                "exact" => format!("\"{}\"", v.value),
                "prefix" => format!("anything under \"{}\" not named elsewhere", v.value),
                _ => "any value not named anywhere in the grant or your request".to_string(),
            };
            facts.push(json!({"path": d.path, "label": label, "text": text}));
            let options: Vec<&str> = d.values.iter().filter(|x| x.kind == "exact").map(|x| x.value.as_str()).collect();
            partial.push(json!({"path": d.path, "kind": "cat", "options": options}));
        }
    }
    let cell_idx: Vec<usize> = (0..vs.dims.len()).map(|k| idx_of(cell, k)).collect::<R<_>>()?;
    let mut body = Map::new();
    body.insert("v".into(), json!(1));
    body.insert("verb".into(), verb.clone());
    body.insert("cell".into(), Value::Array(cell.clone()));
    body.insert("sentence".into(), json!(render_question(vs_json, &cell_idx)?));
    body.insert("facts".into(), Value::Array(facts));
    body.insert("reversibility".into(), vs_json.get("reversibility").cloned().unwrap_or(Value::Null));
    body.insert("answers".into(), json!(["yes", "no", "partly"]));
    body.insert("partial".into(), Value::Array(partial));
    let digest = hash_strict(&json!({"d": "atlas-pca/intent-card/v1", "c": Value::Object(body.clone())}))?;
    body.insert("digest".into(), json!(digest));
    Ok(Value::Object(body))
}

/// A safe integer-valued JSON number that is not `-0`.
fn int_not_neg0(x: &Value) -> Option<f64> {
    match x {
        Value::Number(n) => n.as_f64().filter(|f| f.is_finite() && f.fract() == 0.0 && !(*f == 0.0 && f.is_sign_negative())),
        _ => None,
    }
}

/// `[...new Set(x.filter(nonempty string))]`; `x` must be an array (the reference throws on anything else).
fn strings(x: Option<&Value>) -> R<Vec<String>> {
    let a = x.and_then(Value::as_array).ok_or("input.notFor.filter is not a function")?;
    let mut out: Vec<String> = vec![];
    for v in a {
        if let Some(s) = v.as_str().filter(|s| !s.is_empty()) {
            if !out.iter().any(|o| o == s) {
                out.push(s.to_string());
            }
        }
    }
    Ok(out)
}

/// `[...new Set(x)]`: null gives the empty set, a string its characters, an array its distinct items; else a TypeError.
fn set_of(x: Option<&Value>) -> R<Vec<Value>> {
    let items: Vec<Value> = match x {
        None | Some(Value::Null) => return Ok(vec![]),
        Some(Value::String(s)) => s.chars().map(|c| json!(c.to_string())).collect(),
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return Err("object is not iterable".into()),
    };
    let mut out: Vec<Value> = vec![];
    for v in items {
        let dup = out.iter().any(|o| match (o, &v) {
            (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
            _ => o == &v,
        });
        if !dup {
            out.push(v);
        }
    }
    Ok(out)
}

fn is_field(s: &str) -> bool {
    if s == "action.resource" {
        return true;
    }
    match s.strip_prefix("action.params.") {
        Some(n) => {
            let mut cs = n.chars();
            cs.next().is_some_and(|c| c.is_ascii_lowercase() || c == '_') && cs.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        }
        None => false,
    }
}

fn err(msg: String) -> Value {
    json!({"ok": false, "error": msg})
}

/// Turn a card answer into the learner's answer: `{ok, answer}` or `{ok: false, error}`.
pub fn parse_card_answer(card: &Value, inp: &Value) -> R<Value> {
    if inp.get("answer") != Some(&json!("partly")) {
        return Ok(json!({"ok": true, "answer": if inp.get("answer") == Some(&json!("yes")) { 1 } else { 0 }}));
    }
    let partial: &[Value] = card["partial"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    if let Some(nf) = inp.get("newField") {
        let Some(nfs) = nf.as_str().filter(|s| is_field(s)) else { return Ok(err(format!("unknown field {}", js_str(Some(nf))))) };
        if partial.iter().any(|s| s["path"] == *nf) {
            return Ok(err(format!("{nfs} is already on the card; answer partly for it directly")));
        }
        let vals = strings(inp.get("notFor"))?;
        if vals.is_empty() {
            return Ok(err("name at least one value".into()));
        }
        let mut values: Vec<Value> = vals.iter().map(|v| json!({"kind": "exact", "value": v})).collect();
        values.push(json!({"kind": "other", "value": "⊥"}));
        return Ok(json!({"ok": true, "answer": {"kind": "partial", "path": nfs, "newDim": {"kind": "cat", "path": nfs, "values": values},
            "parts": [{"values": vals, "y": 0}, {"other": true, "y": 1}]}}));
    }
    let path = inp.get("path");
    let Some(slot) = partial.iter().find(|s| Some(&s["path"]) == path) else { return Ok(err(format!("the card has no field {}", js_str(path)))) };
    let spath = &slot["path"];
    if slot["kind"] == json!("num") {
        let (lo, hi) = (slot["lo"].as_f64().unwrap_or(f64::NAN), slot["hi"].as_f64().unwrap_or(f64::NAN));
        let in_range = |x: &Value| int_not_neg0(x).is_some_and(|f| f >= lo && f <= hi);
        if let Some(x) = inp.get("upTo") {
            if !in_range(x) || x.as_f64() == Some(hi) {
                return Ok(err(format!("upTo must be an integer in [{}, {}]", js_num(lo), js_num(hi - 1.0))));
            }
            let xf = x.as_f64().unwrap_or(0.0);
            return Ok(json!({"ok": true, "answer": {"kind": "partial", "path": spath, "cuts": [x],
                "parts": [{"lo": jn(lo), "hi": x, "y": 1}, {"lo": jn(xf + 1.0), "hi": jn(hi), "y": 0}]}}));
        }
        if let Some(x) = inp.get("from") {
            if !in_range(x) || x.as_f64() == Some(lo) {
                return Ok(err(format!("from must be an integer in [{}, {}]", js_num(lo + 1.0), js_num(hi))));
            }
            let xf = x.as_f64().unwrap_or(0.0);
            return Ok(json!({"ok": true, "answer": {"kind": "partial", "path": spath, "cuts": [x],
                "parts": [{"lo": jn(lo), "hi": jn(xf - 1.0), "y": 0}, {"lo": x, "hi": jn(hi), "y": 1}]}}));
        }
        if let Some(e) = inp.get("except") {
            let mut ex = set_of(Some(e))?;
            if ex.iter().all(|v| int_not_neg0(v).is_some()) {
                ex.sort_by(|a, b| a.as_f64().partial_cmp(&b.as_f64()).unwrap_or(std::cmp::Ordering::Equal));
            }
            if ex.is_empty() || !ex.iter().all(in_range) {
                return Ok(err(format!("except values must be integers in [{}, {}]", js_num(lo), js_num(hi))));
            }
            let mut parts: Vec<Value> = ex.iter().map(|x| json!({"lo": x, "hi": x, "y": 0})).collect();
            parts.push(json!({"lo": jn(lo), "hi": jn(hi), "y": 1}));
            return Ok(json!({"ok": true, "answer": {"kind": "partial", "path": spath, "cuts": ex, "parts": parts}}));
        }
        return Ok(err("a numeric partly answer needs upTo, from or except".into()));
    }
    if inp.get("notFor").is_none() {
        return Ok(err("a categorical partly answer needs notFor".into()));
    }
    let vals = strings(inp.get("notFor"))?;
    if vals.is_empty() {
        return Ok(err("name at least one value".into()));
    }
    Ok(json!({"ok": true, "answer": {"kind": "partial", "path": spath, "values": vals, "parts": [{"values": vals, "y": 0}, {"other": true, "y": 1}]}}))
}
