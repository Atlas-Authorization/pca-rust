//! Frame and side-effect constraints: monitored state snapshots, write sets, the frame condition over everything a verb does not write
//! and the verb's postconditions (exact numeric deltas, predicate conditions over env.pre / env.post / env.effect).
use super::learner::IntentLearner;
use super::*;
use serde_json::{Map, Value};

pub const FRAME_STATE_DOMAIN: &str = "atlas-pca/intent-frame-state/v1";

/// Digest of a state value (site-local, never cross-language: the lenient canonical form).
pub fn state_digest(value: &Value) -> String {
    crate::hash_canonical(&obj(vec![("d", jstr(FRAME_STATE_DOMAIN)), ("v", value.clone())]))
}

/// Snapshot already-read values (`values` = a JSON object).
pub fn snapshot_state(values: &Value, keep_values: bool) -> R<Value> {
    let m = values.as_object().ok_or("snapshotState: values must be an object")?;
    let mut out = Map::new();
    for (k, v) in m {
        let mut e = Map::new();
        e.insert("digest".into(), Value::String(state_digest(v)));
        if keep_values {
            e.insert("value".into(), v.clone());
        }
        out.insert(k.clone(), Value::Object(e));
    }
    Ok(Value::Object(out))
}

/// A dotted path through objects and (canonical decimal) array indices; `None` is JavaScript `undefined`.
fn get_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = root;
    for s in path.split('.') {
        match cur {
            Value::Object(m) if m.contains_key(s) => cur = &m[s],
            Value::Array(a)
                if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && s.parse::<usize>().ok().is_some_and(|i| i.to_string() == s && i < a.len()) =>
            {
                cur = &a[s.parse::<usize>().unwrap()]
            }
            _ => return None,
        }
    }
    Some(cur)
}

fn str_vec(v: &Value) -> R<Vec<String>> {
    v.as_array().ok_or("expected an array")?.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| "expected strings".to_string())).collect()
}

/// W(action): the declared list, or the parameter-selected list (unknown parameter value: default, else empty).
pub fn write_set_of(spec: &Value, action: &Value) -> R<Vec<String>> {
    let verb = get_str(action, "verb").ok_or("writeSetOf: action.verb")?;
    let d = match get(spec, "writes").and_then(Value::as_object).and_then(|w| w.get(verb)) {
        None | Some(Value::Null) => return Ok(vec![]),
        Some(d) => d,
    };
    if d.is_array() {
        return str_vec(d);
    }
    let p = get_str(d, "param").ok_or("writeSetOf: param")?;
    let empty = Value::Object(Map::new());
    let params = get(action, "params").filter(|v| truthy(Some(v))).unwrap_or(&empty);
    let v = get_path(params, p.strip_prefix("action.params.").unwrap_or(p));
    let key = match v {
        Some(x @ (Value::String(_) | Value::Bool(_) | Value::Number(_))) => Some(crate::intent_v2::js_value_string(x)),
        _ => None,
    };
    let mp = get(d, "map").and_then(Value::as_object).ok_or("writeSetOf: map")?;
    match key.and_then(|k| mp.get(&k)) {
        Some(x) => str_vec(x),
        None => match get(d, "default") {
            Some(x) if truthy(Some(x)) => str_vec(x),
            _ => Ok(vec![]),
        },
    }
}

fn env_reads(c: &Value, out: &mut Vec<String>) {
    let Some(o) = c.as_object() else { return };
    if crate::predicates::is_group_condition(c) {
        if let Some(Value::Array(a)) = o.get("all_of") {
            a.iter().for_each(|x| env_reads(x, out));
        } else if let Some(Value::Array(a)) = o.get("any_of") {
            a.iter().for_each(|x| env_reads(x, out));
        } else if let Some(x) = o.get("not") {
            env_reads(x, out);
        }
        return;
    }
    if let Some(f) = o.get("field").and_then(Value::as_str) {
        if f.starts_with("env.") {
            out.push(f.to_string());
        }
        if let Some(r) = o.get("ref").and_then(Value::as_str) {
            if r.starts_with("env.") {
                out.push(r.to_string());
            }
        }
    }
}

fn nest(s: &Value) -> R<Value> {
    let mut root = Map::new();
    for (k, v) in s.as_object().ok_or("state must be an object")? {
        let vo = v.as_object().ok_or("a snapshot entry must be an object")?;
        let Some(val) = vo.get("value") else { continue };
        let segs: Vec<&str> = k.split('.').collect();
        let mut cur = &mut root;
        for seg in &segs[..segs.len() - 1] {
            let slot = cur.entry(seg.to_string()).or_insert_with(|| Value::Object(Map::new()));
            if !slot.is_object() {
                *slot = Value::Object(Map::new());
            }
            cur = match slot {
                Value::Object(m) => m,
                _ => unreachable!(),
            };
        }
        cur.insert(segs[segs.len() - 1].to_string(), val.clone());
    }
    Ok(Value::Object(root))
}

fn sorted_set(v: &[String]) -> Vec<String> {
    let mut s: Vec<String> = v.to_vec();
    s.sort();
    s.dedup();
    s
}

struct Rep {
    out_of_frame: Vec<String>,
    attributed: Vec<String>,
    post_violated: Vec<String>,
    missing: Vec<String>,
    unmonitored: bool,
}

fn check_inner(spec: &Value, action: &Value, pre: &Value, post: &Value, opts: &Value, rep: &mut Rep) -> R<()> {
    let ok = spec.is_object() && get(spec, "state").is_some_and(Value::is_array) && action.is_object() && pre.is_object() && post.is_object();
    if !ok {
        return Err("spec, action, pre and post must be objects (spec.state an array)".into());
    }
    let state = str_vec(&spec["state"])?;
    rep.unmonitored = state.is_empty();
    let w = write_set_of(spec, action)?;
    let mut sorted = state.clone();
    sorted.sort();
    let attrs: Vec<Value> = get(opts, "attributions").and_then(Value::as_array).cloned().unwrap_or_default();
    for v in &sorted {
        if w.contains(v) {
            continue;
        }
        let a = get(pre, v).filter(|x| !x.is_null());
        let b = get(post, v).filter(|x| !x.is_null());
        let (Some(a), Some(b)) = (a, b) else {
            rep.missing.push(v.clone());
            continue;
        };
        let da = get(a, "digest").ok_or("digest")?;
        let db = get(b, "digest").ok_or("digest")?;
        if da == db {
            continue;
        }
        let me = get(opts, "self");
        let other = attrs.iter().any(|x| get_str(x, "var") == Some(v.as_str()) && get(x, "actor") != me);
        if other {
            rep.attributed.push(v.clone());
        } else {
            rep.out_of_frame.push(v.clone());
        }
    }
    let effect = get(opts, "effect").filter(|e| truthy(Some(e))).cloned().unwrap_or_else(|| Value::Object(Map::new()));
    let env = obj(vec![("pre", nest(pre)?), ("post", nest(post)?), ("effect", effect)]);
    let params = get(action, "params").filter(|p| truthy(Some(p))).cloned().unwrap_or_else(|| Value::Object(Map::new()));
    let verb = get(action, "verb").cloned().ok_or("action.verb")?;
    let ctx_root = obj(vec![
        ("action", obj(vec![("verb", verb.clone()), ("resource", get(action, "resource").cloned().ok_or("action.resource")?), ("params", params)])),
        ("env", env.clone()),
    ]);
    let ctx = crate::predicates::Ctx::new(&ctx_root);
    if let Some(pcs) = get(spec, "post").filter(|p| truthy(Some(p))) {
        for pc in pcs.as_array().ok_or("spec.post must be an array")? {
            if get(pc, "verb") != Some(&verb) {
                continue;
            }
            let id = crate::intent_v2::js_value_string(get(pc, "id").ok_or("pc.id")?);
            let mut pending = false;
            if let Some(ds) = get(pc, "deltas").filter(|d| truthy(Some(d))) {
                for d in ds.as_array().ok_or("deltas must be an array")? {
                    let path = get_str(d, "path").ok_or("delta.path")?;
                    let x = get_path(&env["pre"], path).and_then(num);
                    let y = get_path(&env["post"], path).and_then(num);
                    match (x, y) {
                        (Some(x), Some(y)) => {
                            if y != x + get_num(d, "by").ok_or("delta.by")? {
                                rep.post_violated.push(id.clone());
                                pending = true;
                                break;
                            }
                        }
                        _ => {
                            rep.missing.push(format!("{id}:{path}"));
                            pending = true;
                        }
                    }
                }
            }
            if pending {
                continue;
            }
            let mut reads: Vec<String> = vec![];
            let wh = get(pc, "where").filter(|w| truthy(Some(w)));
            if let Some(w) = wh {
                for c in w.as_array().ok_or("where must be an array")? {
                    env_reads(c, &mut reads);
                }
            }
            let env_root = obj(vec![("env", env.clone())]);
            let absent: Vec<&String> = reads.iter().filter(|r| get_path(&env_root, r).is_none()).collect();
            if !absent.is_empty() {
                rep.missing.extend(absent.iter().map(|r| format!("{id}:{r}")));
                continue;
            }
            if let Some(w) = wh.and_then(Value::as_array).filter(|w| !w.is_empty()) {
                let pred = obj(vec![("verb", verb.clone()), ("where", Value::Array(w.clone()))]);
                if !crate::predicates::evaluate_predicates(&[pred], &ctx) {
                    rep.post_violated.push(id.clone());
                }
            }
        }
    }
    Ok(())
}

/// Check one executed action: the frame condition over the monitored state outside its write set and the verb's postconditions.
/// Total: never refuses. `opts` = `{attributions?: [{var, actor}], self?, effect?}`.
pub fn check_frame(spec: &Value, action: &Value, pre: &Value, post: &Value, opts: &Value) -> Value {
    let mut rep = Rep { out_of_frame: vec![], attributed: vec![], post_violated: vec![], missing: vec![], unmonitored: false };
    if let Err(e) = check_inner(spec, action, pre, post, opts, &mut rep) {
        rep.missing.push(format!("error: {e}"));
    }
    let missing = sorted_set(&rep.missing);
    let post_violated = sorted_set(&rep.post_violated);
    let status = if !rep.out_of_frame.is_empty() || !post_violated.is_empty() {
        "violated"
    } else if !missing.is_empty() {
        "pending"
    } else {
        "ok"
    };
    let sv = |v: &[String]| Value::Array(v.iter().map(|s| jstr(s)).collect());
    obj(vec![
        ("status", jstr(status)),
        ("outOfFrame", sv(&rep.out_of_frame)),
        ("attributed", sv(&rep.attributed)),
        ("postViolated", sv(&post_violated)),
        ("missing", sv(&missing)),
        ("unmonitored", Value::Bool(rep.unmonitored)),
    ])
}

/// A runtime divergence is one more labelled observation; a NEGATIVE one also vetoes the outcome's cell for good.
pub fn apply_divergence(l: &mut IntentLearner, outcome: &Value, y: i64) -> R<Value> {
    let before = l.cells().iter().filter(|c| c.in_grant).count();
    l.observe(outcome, y, "runtime", None)?;
    let after = l.cells().iter().filter(|c| c.in_grant).count();
    let grant = l.synthesize()?;
    Ok(obj(vec![("before", jn(before as f64)), ("after", jn(after as f64)), ("grant", grant)]))
}

/// Feed a frame report back: a violation is a negative runtime observation that vetoes the outcome's cell for good; `ok` and `pending`
/// change nothing (a met frame is not the principal's endorsement).
pub fn apply_frame_report(l: &mut IntentLearner, o: &Value, report: &Value) -> R<Value> {
    if get_str(report, "status") != Some("violated") {
        return Ok(Value::Object(Map::new()));
    }
    Ok(obj(vec![("signal", jstr("postcondition-violation")), ("divergence", apply_divergence(l, o, 0)?)]))
}
