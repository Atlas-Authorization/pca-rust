//! Semantic diff of two versions of one ActionDef (native port of `diff.ts` and `defdiff.ts` of the reference). `diff_defs` is the
//! grant-pin form (`equal|narrow|widen|incomparable`, never optimistic, over the confirmation-aware effective profile);
//! `diff_defs_authoring` and `diff_packs` are the authoring-CLI form.

use serde_json::{json, Map, Value};

use super::{effective_with, get, id_pattern_contains, opt, profile_eq, rev_rank, strs, Verifier};
use crate::actions::{closure, def_digest, leq, normalize, worst_reversibility, Profile, Registry};
use crate::intent_v2::js_value_string;
use crate::js_stringify;

const INF: f64 = f64::INFINITY;
const DEFAULT_MAX_LEN: f64 = 1024.0;
const DEFAULT_MAX_ITEMS: f64 = 64.0;
const PROVENANCE_LEVELS: [&str; 3] = ["first_party", "tool", "agent"];
const ROLE_FLOOR: [(&str, i32); 17] = [
    ("money.amount", 2),
    ("money.currency", 1),
    ("money.fee", 1),
    ("party.payee", 2),
    ("party.payer", 1),
    ("contact.email", 1),
    ("contact.phone", 1),
    ("contact.address", 1),
    ("person.name", 1),
    ("person.dob", 1),
    ("person.national_id", 2),
    ("credential.secret", 2),
    ("credential.token", 2),
    ("credential.key", 2),
    ("code.command", 2),
    ("query.sql", 2),
    ("text.message", 1),
];

fn scope_rank(s: &str) -> f64 {
    match s {
        "one" => 0.0,
        "set" => 1.0,
        "tenant" => 2.0,
        _ => 3.0,
    }
}

fn idem_rank(s: &str) -> f64 {
    match s {
        "none" => 0.0,
        "natural" => 1.0,
        _ => 2.0,
    }
}

fn sens_rank(s: &str) -> f64 {
    match s {
        "critical" => 2.0,
        "material" => 1.0,
        _ => 0.0,
    }
}

/// `o[k] ?? default` as a number.
fn gn(o: &Value, k: &str, default: f64) -> f64 {
    opt(o, k).and_then(Value::as_f64).unwrap_or(default)
}

/// Object keys sorted recursively (UTF-16 code-unit order, as `Array.prototype.sort` on strings), array order kept: key order is not meaning.
fn sort_keys(v: &Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(sort_keys).collect()),
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            Value::Object(keys.into_iter().map(|k| (k.clone(), sort_keys(&m[k.as_str()]))).collect())
        }
        x => x.clone(),
    }
}

/// `JSON.stringify(sortKeys(v))`.
fn sorted_json(v: &Value) -> String {
    js_stringify(&sort_keys(v))
}

/// JSON.stringify(sortKeys(o[k])) (key order does not matter; an absent member is "undefined").
fn sj(o: &Value, k: &str) -> String {
    o.get(k).map_or("undefined".to_string(), sorted_json)
}

fn set_rel(old: &[String], new: &[String]) -> &'static str {
    let added = new.iter().any(|x| !old.contains(x));
    let removed = old.iter().any(|x| !new.contains(x));
    match (added, removed) {
        (true, true) => "inc",
        (true, false) => "narrow",
        (false, true) => "widen",
        _ => "eq",
    }
}

/// More restrictive = larger.
fn rank_rel(o: f64, n: f64) -> &'static str {
    if n == o {
        "eq"
    } else if n > o {
        "narrow"
    } else {
        "widen"
    }
}

fn strs_in(a: &Value, b: &Value) -> bool {
    strs(a).iter().all(|x| strs(b).contains(x))
}

/// Is every value of inner's domain also a value of outer's? Same declared type required. Sound, not complete.
fn domain_contains(outer: &Value, inner: &Value) -> bool {
    let t = get(outer, "type").as_str().unwrap_or("");
    if get(inner, "type").as_str() != Some(t) {
        return false;
    }
    match t {
        "string" | "object_ref" => {
            if gn(inner, "max_len", DEFAULT_MAX_LEN) > gn(outer, "max_len", DEFAULT_MAX_LEN) {
                return false;
            }
            if let Some(ov) = opt(outer, "values") {
                match opt(inner, "values") {
                    Some(iv) if strs_in(iv, ov) => {}
                    _ => return false,
                }
            }
            opt(outer, "format").is_none() || inner.get("format") == outer.get("format")
        }
        "integer" => gn(inner, "min", -INF) >= gn(outer, "min", -INF) && gn(inner, "max", INF) <= gn(outer, "max", INF),
        "duration" => gn(inner, "min", 0.0).max(0.0) >= gn(outer, "min", 0.0).max(0.0) && gn(inner, "max", INF) <= gn(outer, "max", INF),
        "set" => {
            let (ov, iv) = (strs(get(outer, "values")), strs(get(inner, "values")));
            if !iv.iter().all(|v| ov.contains(v)) {
                return false;
            }
            let o_max = gn(outer, "max_items", ov.len() as f64).min(ov.len() as f64);
            let i_max = gn(inner, "max_items", iv.len() as f64).min(iv.len() as f64);
            gn(inner, "min_items", 0.0) >= gn(outer, "min_items", 0.0) && i_max <= o_max
        }
        "array" => {
            let items = |p: &Value| opt(p, "items").and_then(Value::as_str).unwrap_or("string").to_string();
            if items(outer) != items(inner) {
                return false;
            }
            if gn(inner, "min_items", 0.0) < gn(outer, "min_items", 0.0)
                || gn(inner, "max_items", DEFAULT_MAX_ITEMS) > gn(outer, "max_items", DEFAULT_MAX_ITEMS)
            {
                return false;
            }
            if get(outer, "items").as_str() == Some("integer") {
                return gn(inner, "min", -INF) >= gn(outer, "min", -INF) && gn(inner, "max", INF) <= gn(outer, "max", INF);
            }
            gn(inner, "max_len", DEFAULT_MAX_LEN) <= gn(outer, "max_len", DEFAULT_MAX_LEN)
        }
        _ => true, // boolean, date, datetime: no domain members
    }
}

/// Is every call conforming to `inner` also conforming to `outer`? Closed world, required members, domains.
fn calls_contained(outer: &Map<String, Value>, inner: &Map<String, Value>) -> bool {
    for (name, ip) in inner {
        match outer.get(name) {
            Some(op) if domain_contains(op, ip) => {}
            _ => return false,
        }
    }
    for (name, op) in outer {
        if op.get("required").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        match inner.get(name) {
            Some(ip) if ip.get("required").and_then(Value::as_bool) == Some(true) => {}
            _ => return false,
        }
    }
    true
}

fn call_set_rel(old_p: &Map<String, Value>, new_p: &Map<String, Value>) -> &'static str {
    let sub = calls_contained(old_p, new_p);
    let sup = calls_contained(new_p, old_p);
    if sub && sup {
        "eq"
    } else if sub {
        "narrow"
    } else if sup {
        "widen"
    } else {
        "inc"
    }
}

fn prov_rank(p: Option<&Value>) -> f64 {
    match p.and_then(Value::as_str) {
        None => (PROVENANCE_LEVELS.len() - 1) as f64,
        Some(s) => PROVENANCE_LEVELS.iter().position(|x| *x == s).unwrap_or(0) as f64,
    }
}

fn param_attr_rels(o: &Value, n: &Value) -> Vec<(&'static str, &'static str)> {
    let mut out = Vec::new();
    if o.get("role") != n.get("role") {
        out.push(("role", "inc"));
    }
    out.push((
        "sensitivity",
        rank_rel(sens_rank(get(o, "sensitivity").as_str().unwrap_or("free")), sens_rank(get(n, "sensitivity").as_str().unwrap_or("free"))),
    ));
    out.push(("tags", set_rel(&strs(get(o, "tags")), &strs(get(n, "tags")))));
    out.push(("provenance_min", rank_rel(-prov_rank(opt(o, "provenance_min")), -prov_rank(opt(n, "provenance_min")))));
    if sj(o, "unit") != sj(n, "unit") {
        out.push(("unit", "inc"));
    }
    out.push(("accumulates", set_rel(&strs(get(o, "accumulates")), &strs(get(n, "accumulates")))));
    if sj(o, "default") != sj(n, "default") || o.get("principal_neutral_default") != n.get("principal_neutral_default") {
        out.push(("default", "inc"));
    }
    out
}

fn text_differs(o: &Value, n: &Value) -> bool {
    ["title", "description", "compensates"].iter().any(|k| o.get(*k) != n.get(*k))
}

fn prof_rel(a: &Profile, b: &Profile) -> &'static str {
    if leq(a, b) {
        if leq(b, a) {
            "eq"
        } else {
            "narrow"
        }
    } else if leq(b, a) {
        "widen"
    } else {
        "inc"
    }
}

fn empty() -> Map<String, Value> {
    Map::new()
}

/// The semantic diff of `nxt` against `prev` (two versions of one verb): `{class, reasons}`. Errs for two different verbs.
pub fn diff_defs(prev: &Value, nxt: &Value, reg: &Registry, verifier: Verifier) -> Result<Value, String> {
    let (pv, nv) = (get(prev, "verb"), get(nxt, "verb"));
    if pv != nv {
        return Err(format!("diff compares two versions of one verb, not '{}' and '{}'", js_value_string(pv), js_value_string(nv)));
    }
    let (o, n) = (normalize(prev), normalize(nxt));
    let mut rels: Vec<(String, &'static str)> = Vec::new();
    let text = text_differs(&o, &n);
    rels.push(("effects".into(), set_rel(&strs(&o["effects"]), &strs(&n["effects"]))));
    let (op, np) = (o["params"].as_object().cloned().unwrap_or_else(empty), n["params"].as_object().cloned().unwrap_or_else(empty));
    rels.push(("params.accepted_calls".into(), call_set_rel(&op, &np)));
    let mut names: Vec<&String> = op.keys().collect();
    names.sort();
    for name in names {
        if let Some(np1) = np.get(name) {
            for (k, r) in param_attr_rels(&op[name], np1) {
                rels.push((format!("params.{name}.{k}"), r));
            }
        }
    }
    let eo = effective_with(prev, reg, verifier)?;
    let en = effective_with(nxt, reg, verifier)?;
    let cl = |ts: &[String]| closure(reg, ts).map_err(|e| e.message);
    rels.push(("traits".into(), set_rel(&cl(&eo.hint.traits)?, &cl(&en.hint.traits)?)));
    rels.push(("profile".into(), prof_rel(&eo.hint.eff, &en.hint.eff)));
    rels.push(("confirmation".into(), rank_rel(if eo.confirmed { 0.0 } else { 1.0 }, if en.confirmed { 0.0 } else { 1.0 })));
    rels.push(("effective.traits".into(), set_rel(&cl(&eo.main.traits)?, &cl(&en.main.traits)?)));
    rels.push(("effective.profile".into(), prof_rel(&eo.main.eff, &en.main.eff)));
    let wr = |d: &Value| rev_rank(&worst_reversibility(&d["reversibility"], d["params"].as_object().unwrap_or(&Map::new()))) as f64;
    rels.push(("reversibility".into(), rank_rel(wr(&o), wr(&n))));
    rels.push(("blast".into(), rank_rel(gn(&o["blast"], "ppm", 0.0), gn(&n["blast"], "ppm", 0.0))));
    let (oi, ni) = (&o["idempotency"], &n["idempotency"]);
    let idem = if oi["mode"].as_str() == Some("key_param") && ni["mode"].as_str() == Some("key_param") && oi.get("param") != ni.get("param") {
        "inc"
    } else {
        rank_rel(idem_rank(oi["mode"].as_str().unwrap_or("none")), idem_rank(ni["mode"].as_str().unwrap_or("none")))
    };
    rels.push(("idempotency".into(), idem));
    rels.push(("context".into(), set_rel(&strs(&o["context"]), &strs(&n["context"]))));
    let se = |d: &Value| -> Vec<String> {
        super::arr(&d["side_effects"]).iter().map(|s| format!("{}|{}", js_value_string(get(s, "target")), js_value_string(get(s, "kind")))).collect()
    };
    rels.push(("side_effects".into(), set_rel(&se(&o), &se(&n))));
    let (orr, nrr) = (&o["resource"], &n["resource"]);
    let res_id = if sorted_json(&orr["id"]) == sorted_json(&nrr["id"]) {
        "eq"
    } else if id_pattern_contains(&orr["id"], &nrr["id"]) {
        "narrow"
    } else if id_pattern_contains(&nrr["id"], &orr["id"]) {
        "widen"
    } else {
        "inc"
    };
    rels.push(("resource.id".into(), if orr["type"] != nrr["type"] { "inc" } else { res_id }));
    rels.push(("resource.scope".into(), rank_rel(-scope_rank(orr["scope"].as_str().unwrap_or("")), -scope_rank(nrr["scope"].as_str().unwrap_or("")))));
    let ar = set_rel(&strs(&o["aliases"]), &strs(&n["aliases"])); // new aliases widen what natural language can reach
    rels.push((
        "aliases".into(),
        match ar {
            "narrow" => "widen",
            "widen" => "narrow",
            x => x,
        },
    ));
    rels.push(("bindings".into(), if sorted_json(&o["bindings"]) == sorted_json(&n["bindings"]) { "eq" } else { "inc" }));

    let diffs: Vec<&(String, &'static str)> = rels.iter().filter(|(_, r)| *r != "eq").collect();
    let mut reasons: Vec<String> = diffs.iter().map(|(d, r)| format!("{d}: {}", if *r == "inc" { "incomparable" } else { *r })).collect();
    reasons.sort();
    if text {
        reasons.push("text: title, description or compensates changed".into());
    }
    reasons.sort();
    let has = |r: &str| diffs.iter().any(|(_, x)| *x == r);
    let cls = if has("inc") || (has("narrow") && has("widen")) {
        "incomparable"
    } else if has("widen") {
        "widen"
    } else if has("narrow") {
        "narrow"
    } else {
        "equal"
    };
    Ok(json!({"class": cls, "reasons": reasons}))
}

/// Does a pin follow this change on its own (no principal)?
pub fn diff_is_free(c: &str) -> bool {
    c == "equal" || c == "narrow"
}

// ---- the authoring diff (defdiff.ts) -------------------------------------------------------------------------------------------------

fn num_str(v: Option<&Value>) -> String {
    v.map_or("undefined".to_string(), js_value_string)
}

fn prov_level(v: Option<&Value>) -> i64 {
    match v.and_then(Value::as_str) {
        None => PROVENANCE_LEVELS.len() as i64,
        Some(s) => PROVENANCE_LEVELS.iter().position(|x| *x == s).map_or(-1, |i| i as i64),
    }
}

fn role_floor(r: Option<&Value>) -> i32 {
    r.and_then(Value::as_str).and_then(|r| ROLE_FLOOR.iter().find(|(n, _)| *n == r)).map_or(0, |(_, f)| *f)
}

fn param_diff(k: &str, x: &Value, y: &Value, wide: &mut Vec<String>, narrow: &mut Vec<String>, incomp: &mut Vec<String>) {
    let mut num = |f: &str, lower_is_wider: bool| {
        let (o, n) = (opt(x, f), opt(y, f));
        if o == n {
            return;
        }
        let rank = |v: Option<&Value>| -> f64 {
            match v.and_then(Value::as_f64) {
                Some(f) => f,
                None => {
                    if lower_is_wider {
                        -INF
                    } else {
                        INF
                    }
                }
            }
        };
        let wider_new = if lower_is_wider { rank(n) < rank(o) } else { rank(n) > rank(o) };
        let msg = format!("param {k}: {f} {} to {}", num_str(o), num_str(n));
        if wider_new {
            wide.push(msg)
        } else {
            narrow.push(msg)
        }
    };
    if x["type"] != y["type"] {
        incomp.push(format!("param {k}: type changed"));
    }
    num("min", true);
    num("max", false);
    num("max_len", false);
    num("max_items", false);
    num("min_items", true);
    if sj(x, "unit") != sj(y, "unit") {
        incomp.push(format!("param {k}: unit changed"));
    }
    let (vo, vn) = (opt(x, "values"), opt(y, "values"));
    if vo.is_some() || vn.is_some() {
        match (vo, vn) {
            (None, _) => narrow.push(format!("param {k}: values restricted")),
            (_, None) => wide.push(format!("param {k}: values unrestricted")),
            (Some(vo), Some(vn)) => {
                let (a, b) = (super::arr(vo), super::arr(vn));
                let added: Vec<String> = b.iter().filter(|v| !a.contains(v)).map(js_value_string).collect();
                let removed: Vec<String> = a.iter().filter(|v| !b.contains(v)).map(js_value_string).collect();
                if !added.is_empty() {
                    wide.push(format!("param {k}: values added ({})", added.join(", ")));
                }
                if !removed.is_empty() {
                    narrow.push(format!("param {k}: values removed ({})", removed.join(", ")));
                }
            }
        }
    }
    let (rx, ry) = (x["required"].as_bool(), y["required"].as_bool());
    if rx == Some(true) && ry == Some(false) {
        wide.push(format!("param {k}: required to optional"));
    }
    if rx == Some(false) && ry == Some(true) {
        narrow.push(format!("param {k}: optional to required"));
    }
    let (px, py) = (prov_level(opt(x, "provenance_min")), prov_level(opt(y, "provenance_min")));
    if py > px {
        wide.push(format!("param {k}: provenance_min loosened"));
    } else if py < px {
        narrow.push(format!("param {k}: provenance_min tightened"));
    }
    let (sx, sy) = (sens_rank(get(x, "sensitivity").as_str().unwrap_or("free")), sens_rank(get(y, "sensitivity").as_str().unwrap_or("free")));
    if sy < sx {
        wide.push(format!("param {k}: sensitivity lowered"));
    } else if sy > sx {
        narrow.push(format!("param {k}: sensitivity raised"));
    }
    if x.get("role") != y.get("role") {
        let (fx, fy) = (role_floor(x.get("role")), role_floor(y.get("role")));
        if fy < fx {
            wide.push(format!("param {k}: role changed to a lower-floor role"));
        } else if fy > fx {
            narrow.push(format!("param {k}: role changed to a higher-floor role"));
        } else {
            incomp.push(format!("param {k}: role changed"));
        }
    }
}

/// `{class, breaking, reasons}`: anything not shown to be no wider is widening. A renamed verb is a breaking widen.
pub fn diff_defs_authoring(a: &Value, b: &Value, reg: &Registry) -> Result<Value, String> {
    if get(a, "verb") != get(b, "verb") {
        return Ok(json!({"class": "widen", "breaking": true, "reasons": ["verb renamed: removed + added (grants on the old verb do not follow)"]}));
    }
    let (mut wide, mut narrow, mut incomp): (Vec<String>, Vec<String>, Vec<String>) = (vec![], vec![], vec![]);
    let mut breaking = false;
    let (na, nb) = (normalize(a), normalize(b));
    let ea = effective_with(a, reg, None)?.hint;
    let eb = effective_with(b, reg, None)?.hint;
    if !leq(&ea.eff, &eb.eff) {
        wide.push("the effective profile is not at least the old one".into());
    } else if !profile_eq(&ea.eff, &eb.eff) {
        narrow.push("the effective profile rose".into());
    }
    let (fa, fb) = (strs(&na["effects"]), strs(&nb["effects"]));
    for e in &fa {
        if !fb.contains(e) {
            wide.push(format!("effect {e} removed"));
        }
    }
    for e in &fb {
        if !fa.contains(e) {
            narrow.push(format!("effect {e} added"));
        }
    }
    let (ta, tb) = (strs(&na["traits"]), strs(&nb["traits"]));
    for t in &ta {
        if !tb.contains(t) {
            wide.push(format!("declared trait {t} removed"));
        }
    }
    for t in &tb {
        if !ta.contains(t) {
            narrow.push(format!("declared trait {t} added"));
        }
    }
    let no = Map::new();
    let ra = worst_reversibility(&na["reversibility"], na["params"].as_object().unwrap_or(&no));
    let rb = worst_reversibility(&nb["reversibility"], nb["params"].as_object().unwrap_or(&no));
    if rev_rank(&rb) < rev_rank(&ra) {
        wide.push(format!("reversibility lowered ({ra} to {rb})"));
    } else if rev_rank(&rb) > rev_rank(&ra) {
        narrow.push(format!("reversibility raised ({ra} to {rb})"));
    }
    let (ba, bb) = (gn(&na["blast"], "ppm", 0.0), gn(&nb["blast"], "ppm", 0.0));
    if bb < ba {
        wide.push("blast lowered".into());
    } else if bb > ba {
        narrow.push("blast raised".into());
    }
    let idem = |d: &Value| if d["idempotency"]["mode"].as_str() == Some("none") { 0 } else { 1 };
    if idem(&nb) < idem(&na) {
        wide.push("idempotency loosened".into());
    } else if idem(&nb) > idem(&na) {
        narrow.push("idempotency added".into());
    }
    if na["resource"]["type"] != nb["resource"]["type"] {
        incomp.push("resource type changed".into());
    }
    let (sa, sb) = (scope_rank(na["resource"]["scope"].as_str().unwrap_or("")), scope_rank(nb["resource"]["scope"].as_str().unwrap_or("")));
    if sb > sa {
        wide.push("resource scope widened".into());
    } else if sb < sa {
        narrow.push("resource scope narrowed".into());
    }
    let in_old = id_pattern_contains(&na["resource"]["id"], &nb["resource"]["id"]);
    let in_new = id_pattern_contains(&nb["resource"]["id"], &na["resource"]["id"]);
    if !in_old {
        wide.push("the resource id pattern is not contained in the old one".into());
    } else if !in_new {
        narrow.push("the resource id pattern is narrower".into());
    }
    let (pa, pb) = (na["params"].as_object().cloned().unwrap_or_else(empty), nb["params"].as_object().cloned().unwrap_or_else(empty));
    for (k, x) in &pa {
        let Some(y) = pb.get(k) else {
            narrow.push(format!("param {k} removed"));
            breaking = true;
            continue;
        };
        param_diff(k, x, y, &mut wide, &mut narrow, &mut incomp);
        if x["required"].as_bool() == Some(false) && y["required"].as_bool() == Some(true) {
            breaking = true;
        }
    }
    for (k, y) in &pb {
        if pa.contains_key(k) {
            continue;
        }
        if y["required"].as_bool() == Some(true) {
            narrow.push(format!("required param {k} added"));
            breaking = true;
        } else {
            wide.push(format!("optional param {k} added"));
        }
    }
    if get(get(a, "review"), "state").as_str() == Some("confirmed") && get(get(b, "review"), "state").as_str() != Some("confirmed") {
        narrow.push("review state left confirmed".into());
    }
    let cls = if !incomp.is_empty() || (!wide.is_empty() && !narrow.is_empty()) {
        "incomparable"
    } else if !wide.is_empty() {
        "widen"
    } else if !narrow.is_empty() {
        "narrow"
    } else {
        "equal"
    };
    let cmp_eq = cls == "equal" && def_digest(a) != def_digest(b);
    let mut reasons: Vec<String> = wide.iter().map(|r| format!("widen: {r}")).collect();
    reasons.extend(narrow.iter().map(|r| format!("narrow: {r}")));
    reasons.extend(incomp.iter().map(|r| format!("incomparable: {r}")));
    if cmp_eq {
        reasons.push("equal: only title or description changed".into());
    }
    Ok(json!({"class": cls, "breaking": breaking, "reasons": reasons}))
}

/// Per-verb diff of two sets of defs. A removed verb is `removed`; a new verb is `added`.
pub fn diff_packs(olds: &[Value], news: &[Value], reg: &Registry) -> Result<Vec<Value>, String> {
    let index = |ds: &[Value]| -> std::collections::BTreeMap<String, Value> {
        ds.iter().map(|d| (get(d, "verb").as_str().unwrap_or("").to_string(), d.clone())).collect()
    };
    let (o, n) = (index(olds), index(news));
    let mut verbs: Vec<&String> = o.keys().chain(n.keys()).collect();
    verbs.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    verbs.dedup();
    let mut out = Vec::new();
    for v in verbs {
        match (o.get(v), n.get(v)) {
            (None, Some(_)) => out.push(json!({"verb": v, "class": "added", "breaking": false, "reasons": []})),
            (Some(_), None) => out.push(json!({"verb": v, "class": "removed", "breaking": true, "reasons": ["verb removed"]})),
            (Some(x), Some(y)) => {
                let mut d = diff_defs_authoring(x, y, reg)?;
                let mut e = Map::new();
                e.insert("verb".into(), json!(v));
                if let Some(m) = d.as_object_mut() {
                    e.append(m);
                }
                out.push(Value::Object(e));
            }
            (None, None) => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod key_order_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_is_not_meaning_but_array_order_is() {
        let a = json!({"unit": {"kind": "money", "ccy": "USD", "exp": 2}, "default": {"b": [1, {"y": 1, "x": 2}], "a": 0}});
        let b = json!({"default": {"a": 0, "b": [1, {"x": 2, "y": 1}]}, "unit": {"exp": 2, "ccy": "USD", "kind": "money"}});
        assert_eq!(sj(&a, "unit"), sj(&b, "unit"));
        assert_eq!(sj(&a, "default"), sj(&b, "default"));
        assert_eq!(sorted_json(&a), sorted_json(&b));
        let reordered_array = json!({"b": [{"x": 2, "y": 1}, 1], "a": 0});
        assert_ne!(sj(&json!({"default": a["default"].clone()}), "default"), sj(&json!({"default": reordered_array}), "default"));
        assert_eq!(sj(&json!({}), "unit"), "undefined");
    }
}
