//! Trajectory intent as ordinary intent: the augmented outcome space (one numeric dimension per accumulator, one categorical
//! dimension per monitor), the verifier-computed lift of an action, the trajectory step rule and the wallet's default accumulators
//! (`trajectory.ts`). Builds on the native session-history engine (`intent_history`, `intent_acc`).
use super::js_str;
use super::schema::canon_value;
use crate::intent_acc::{acc_selects, monitor_states};
use crate::intent_history::{acc_post, monitor_state};
use crate::wallet_omega::{cell_of, num_cells};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

pub const ACC_DIM_PREFIX: &str = "env.acc.";
pub const MON_DIM_PREFIX: &str = "env.mon.";
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

pub fn acc_dim_path(id: &str) -> String {
    format!("{ACC_DIM_PREFIX}{id}.post")
}

pub fn mon_dim_path(id: &str) -> String {
    format!("{MON_DIM_PREFIX}{id}.state")
}

/// The v2 dimension kind of a path (a naming convention over the v1 dimensions).
pub fn dim_kind_of(path: &str) -> &'static str {
    for (prefix, kind) in [
        ("action.params.", "param"),
        (ACC_DIM_PREFIX, "acc"),
        (MON_DIM_PREFIX, "mon"),
        ("env.canon.", "canon"),
        ("env.world.", "world"),
        ("env.rel.", "rel"),
        ("env.prov.", "prov"),
        ("env.class.", "class"),
    ] {
        if path.starts_with(prefix) {
            return kind;
        }
    }
    "other"
}

fn arr_of(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or(&[])
}

fn s_of(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn pred_verbs(p: &Value) -> Vec<Value> {
    match p.get("verb") {
        Some(Value::Array(a)) => a.clone(),
        Some(v) => vec![v.clone()],
        None => vec![Value::Null],
    }
}

fn obj_of<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>, String> {
    v.as_object().ok_or_else(|| format!("{what} must be an object"))
}

/// The augmented space from the space and Psi (wallet-held accumulators are not dimensions). `opts = {scope?, schema?, cuts?}`.
pub fn augment_omega(omega: &Value, psi: &Value, opts: &Value) -> Result<Value, String> {
    let schema = opts.get("schema").filter(|s| !s.is_null());
    let selected = opts.get("scope").and_then(Value::as_str) == Some("selected");
    let mut verbs = vec![];
    for vs in arr_of(&omega["verbs"]) {
        let verb = s_of(&vs["verb"]);
        let mut extra: Vec<Value> = vec![];
        for a in arr_of(&psi["accumulators"]) {
            if a["holder"]["kind"] == json!("wallet") {
                continue;
            }
            if selected && !acc_selects(obj_of(a, "accumulator")?, verb, schema)? {
                continue;
            }
            let dm = match a.get("domain_max") {
                Some(d) if !d.is_null() => d,
                _ => return Err(format!("augmentOmega: accumulator '{}' needs domain_max (A_psi) to be a dimension", s_of(&a["id"]))),
            };
            let dmf = dm.as_f64().unwrap_or(f64::NAN);
            let raw = opts.get("cuts").and_then(|c| c.get(s_of(&a["id"]))).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
            let mut ints: BTreeSet<i64> = BTreeSet::new();
            for c in raw {
                if let Some(x) = c.as_f64().filter(|x| x.fract() == 0.0 && *x >= 0.0 && *x <= dmf && x.abs() <= MAX_SAFE) {
                    ints.insert(x as i64);
                }
            }
            extra.push(json!({ "kind": "num", "path": acc_dim_path(s_of(&a["id"])), "lo": 0, "hi": dm, "cuts": ints, "dist": "loguniform" }));
        }
        for m in arr_of(&psi["monitors"]) {
            if selected {
                if let Some(q) = m.get("q").filter(|q| crate::wallet_omega::truthy(q)) {
                    let vs_ = pred_verbs(q);
                    if !(vs_.iter().any(|x| x.as_str() == Some(verb)) || vs_.iter().any(|x| x.as_str() == Some("*"))) {
                        continue;
                    }
                }
            }
            let values: Vec<Value> = monitor_states(m).into_iter().map(|v| json!({ "kind": "exact", "value": v })).collect();
            extra.push(json!({ "kind": "cat", "path": mon_dim_path(s_of(&m["id"])), "values": values }));
        }
        let mut dims: Vec<Value> = arr_of(&vs["dims"]).iter().filter(|d| !matches!(dim_kind_of(s_of(&d["path"])), "acc" | "mon")).cloned().collect();
        dims.extend(extra);
        dims.sort_by(|a, b| s_of(&a["path"]).cmp(s_of(&b["path"])));
        let mut out = vs.clone();
        out["dims"] = Value::Array(dims);
        verbs.push(out);
    }
    Ok(json!({ "v": 1, "approximate": arr_of(&omega["approximate"]), "verbs": verbs }))
}

/// lift(history, action, t) as an outcome of the augmented space; `None` when the verb is not in it.
pub fn lift_action(omega_tilde: &Value, psi: &Value, history: &[Value], cand: &Value, schema: Option<&Value>) -> Result<Option<Value>, String> {
    let verb = s_of(&cand["verb"]);
    let Some(vs) = arr_of(&omega_tilde["verbs"]).iter().find(|v| s_of(&v["verb"]) == verb) else { return Ok(None) };
    let schema = schema.filter(|s| !s.is_null());
    let decl = schema.and_then(|s| arr_of(&s["verbs"]).iter().find(|v| s_of(&v["verb"]) == verb));
    let params = &cand["params"];
    let mut values = Map::new();
    for d in arr_of(&vs["dims"]) {
        let path = s_of(&d["path"]);
        match dim_kind_of(path) {
            "param" => {
                let x = params.as_object().and_then(|m| m.get(&path["action.params.".len()..]));
                if let Some(x) = x.filter(|x| x.is_number() || x.is_string()) {
                    values.insert(path.to_string(), x.clone());
                }
            }
            "canon" => {
                let name = &path["env.canon.".len()..];
                let pd = decl.and_then(|d| d.get("params")).and_then(|p| p.get(format!("action.params.{name}")));
                if let (Some(pd), Some(x)) = (pd.filter(|p| crate::wallet_omega::truthy(p)), params.as_object().and_then(|m| m.get(name))) {
                    values.insert(path.to_string(), json!(canon_value(pd, x)?));
                }
            }
            "acc" => {
                let id = &path[ACC_DIM_PREFIX.len()..path.len() - ".post".len()];
                if let Some(a) = arr_of(&psi["accumulators"]).iter().find(|x| s_of(&x["id"]) == id) {
                    let pm = obj_of(params, "params")?;
                    let v = acc_post(obj_of(a, "accumulator")?, history, verb, pm, cand.get("t"), schema)?;
                    values.insert(path.to_string(), json!(v));
                }
            }
            "mon" => {
                let id = &path[MON_DIM_PREFIX.len()..path.len() - ".state".len()];
                if let Some(m) = arr_of(&psi["monitors"]).iter().find(|x| s_of(&x["id"]) == id) {
                    values.insert(path.to_string(), monitor_state(obj_of(m, "monitor")?, history)?.map_or(Value::Null, Value::String));
                }
            }
            _ if path == "action.resource" => {
                values.insert(path.to_string(), cand["resource"].clone());
            }
            _ => {}
        }
    }
    Ok(Some(json!({ "verb": verb, "values": values })))
}

/// The per-dimension cell of the lift as `{verb, cell}`, or `None` when it lies outside the space (fail closed).
pub fn lifted_cell(omega_tilde: &Value, o: &Value) -> Option<Value> {
    let verb = s_of(&o["verb"]);
    let vs = arr_of(&omega_tilde["verbs"]).iter().find(|v| s_of(&v["verb"]) == verb)?;
    let cell = cell_of(vs, o)?;
    Some(json!({ "verb": verb, "cell": cell }))
}

/// Admit the action iff its lift lies in a cell the grant accepts; the history grows by a `reserved` event on admission.
/// Returns `{admitted, history, lifted}`.
pub fn step_trajectory(
    omega_tilde: &Value,
    psi: &Value,
    history: &[Value],
    cand: &Value,
    in_grant: &dyn Fn(&str, &[usize]) -> bool,
    schema: Option<&Value>,
) -> Result<Value, String> {
    let lifted = lift_action(omega_tilde, psi, history, cand, schema)?;
    let cell = lifted.as_ref().and_then(|l| lifted_cell(omega_tilde, l));
    let verb = s_of(&cand["verb"]);
    let ok = match &cell {
        Some(c) => {
            let idx: Vec<usize> = arr_of(&c["cell"]).iter().map(|x| x.as_u64().unwrap_or(0) as usize).collect();
            in_grant(verb, &idx)
        }
        None => false,
    };
    let mut hist: Vec<Value> = history.to_vec();
    if ok {
        let g = |k: &str| cand.get(k).cloned().ok_or_else(|| format!("candidate.{k} is missing"));
        hist.push(json!({ "id": g("id")?, "verb": g("verb")?, "resource": g("resource")?, "params": g("params")?, "t": g("t")?, "status": "reserved" }));
    }
    Ok(json!({ "admitted": ok, "history": hist, "lifted": lifted.unwrap_or(Value::Null) }))
}

/// `[^A-Za-z0-9_]` -> `_` per UTF-16 code unit, cut to `max` units.
fn sanitize(u: &str, max: usize) -> String {
    let mut out = String::new();
    for c in u.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
        } else {
            for _ in 0..c.len_utf16() {
                out.push('_');
            }
        }
    }
    out.chars().take(max).collect()
}

/// The accumulators the wallet always adds: a per-task spend sum per accumulation unit, a per-verb spend sum for every untagged
/// money.amount parameter, and the wallet-held question counter. `o = {spendDomainMax, questionCap?, holder?}`.
pub fn default_accumulators(schema: &Value, o: &Value) -> Result<Value, String> {
    let holder = o.get("holder").filter(|h| crate::wallet_omega::truthy(h)).cloned().unwrap_or(json!({ "kind": "site_local" }));
    let dom = o.get("spendDomainMax").cloned().ok_or("defaultAccumulators: spendDomainMax is required")?;
    let mut units: BTreeSet<String> = BTreeSet::new();
    let mut untagged: Vec<(String, String)> = vec![];
    for v in schema.get("verbs").and_then(Value::as_array).ok_or("schema.verbs must be a list")? {
        for (path, d) in v.get("params").and_then(Value::as_object).ok_or("params must be an object")? {
            let into = d.get("accumulates_into").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
            for u in into {
                units.insert(js_str(Some(u)));
            }
            if s_of(&d["type"]) == "integer" && s_of(&d["semantic"]) == "money.amount" && into.is_empty() {
                untagged.push((s_of(&v["verb"]).to_string(), path.clone()));
            }
        }
    }
    let mut out: Vec<Value> = vec![];
    for u in &units {
        out.push(json!({ "id": format!("spend_{}", sanitize(u, 58)), "agg": "sum", "unit": u, "sel": { "accumulates_into": u }, "win": { "kind": "task" },
            "key": null, "domain_max": dom, "holder": holder }));
    }
    untagged.sort_by(|a, b| format!("{}{}", a.0, a.1).cmp(&format!("{}{}", b.0, b.1)));
    for (verb, path) in &untagged {
        let tail: String = path.chars().skip("action.params.".len()).collect();
        let id: String = format!("spend_{}_{}", sanitize(verb, usize::MAX), sanitize(&tail, usize::MAX)).chars().take(64).collect();
        out.push(json!({ "id": id, "agg": "sum", "val": path, "sel": { "verbs": [verb] }, "win": { "kind": "task" }, "key": null, "domain_max": dom, "holder": holder }));
    }
    let cap = o.get("questionCap").filter(|c| !c.is_null()).cloned().unwrap_or(json!(6));
    out.push(json!({ "id": "questions", "agg": "count", "sel": { "event": "intent_required" }, "win": { "kind": "task" }, "key": null, "cap": cap, "holder": { "kind": "wallet" } }));
    Ok(Value::Array(out))
}

/// The fact line for an accumulator dimension of a cell; `bracket` wraps every number in `[...]`.
pub fn describe_acc_cell(d: &Value, cell_index: i64, label: &str, this_action: Option<f64>, bracket: bool) -> Result<String, String> {
    let cells = num_cells(d);
    if cell_index < 0 || cell_index as usize >= cells.len() {
        return Err("describeAccCell: no such cell".into());
    }
    let c = cells[cell_index as usize];
    let fmt = |x: f64| -> String {
        let t = js_str(Some(&json!(x)));
        if bracket {
            format!("[{t}]")
        } else {
            t
        }
    };
    let rng = if c.0 == c.1 { format!("exactly {}", fmt(c.0 as f64)) } else { format!("between {} and {}", fmt(c.0 as f64), fmt(c.1 as f64)) };
    Ok(format!("{label}: {rng}{}", this_action.map_or(String::new(), |t| format!(" (this action: {})", fmt(t)))))
}

/// The per-session harm range of a trajectory Monte Carlo estimate: `[0, L_max * H_max]`.
pub fn trajectory_harm_range(max_session_length: f64, harm_max: f64) -> Result<f64, String> {
    let ok_len = max_session_length.is_finite() && max_session_length.fract() == 0.0 && (0.0..=MAX_SAFE).contains(&max_session_length);
    if !ok_len || !(harm_max >= 0.0) {
        return Err("trajectoryHarmRange: bad arguments".into());
    }
    Ok(max_session_length * harm_max)
}
