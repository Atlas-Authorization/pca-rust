//! The intent-fidelity ontology: the signed authoring vocabulary (aliases, templates, units), its projection onto the IR
//! ontology, its well-formedness checker, template instantiation, slot typing and locale-aware amount parsing (`ontology.ts`).
//! Ontologies, goals and slot values are JSON trees, exactly as the reference reads them.
//!
//! shortcut: `check_ontology` takes the Allow-witness builder (`examples.ts allowWitness`) as a parameter: it belongs to the
//! examples module of this package; replace the parameter by that function when it lands.
//! shortcut: a bare string where the reference iterates an array or object entries is refused (it would iterate characters).
use super::js::*;
use super::normalize::canonicalize_goal;
use serde_json::{json, Map, Value};
use unicode_normalization::UnicodeNormalization;

type V<'a> = Option<&'a Value>;
type Res<T> = Result<T, String>;

pub const EFFECT_CLASSES: [&str; 4] = ["read", "reversible", "external_send", "irreversible"];
const FOREVER: i64 = 9007199254740991;

fn is_invis(c: char) -> bool {
    matches!(c, '\u{200b}'..='\u{200f}' | '\u{2060}' | '\u{feff}')
}
fn norm(s: &str) -> String {
    s.nfkc().collect::<String>().to_lowercase().chars().filter(|c| !is_invis(*c)).collect()
}
fn s_of(x: V) -> Res<&str> {
    match x {
        Some(Value::String(s)) => Ok(s.as_str()),
        _ => Err("string expected".into()),
    }
}
/// `x.startsWith(p)` for a string `x` (a throw otherwise).
fn starts(x: V, p: V) -> Res<bool> {
    Ok(s_of(x)?.starts_with(js_str(p).as_str()))
}
fn find<'a>(xs: V<'a>, mut pred: impl FnMut(&'a Value) -> Res<bool>) -> Res<V<'a>> {
    for x in seq_members(xs)?.into_iter() {
        if pred(x)? {
            return Ok(Some(x));
        }
    }
    Ok(None)
}
fn is_integer(x: V) -> bool {
    matches!(x, Some(Value::Number(n)) if n.as_f64().is_some_and(|f| f.is_finite() && f.fract() == 0.0))
}
fn num(x: V) -> Option<f64> {
    match x {
        Some(Value::Number(n)) => n.as_f64(),
        _ => None,
    }
}
fn len_pos(x: V) -> bool {
    match x {
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::String(s)) => !s.is_empty(),
        _ => false,
    }
}
/// A set with JavaScript `Set` semantics for the primitive values the ontology holds.
#[derive(Default)]
struct JsSet(Vec<Option<Value>>);
impl JsSet {
    fn has(&self, x: V) -> bool {
        self.0.iter().any(|e| strict_eq(e.as_ref(), x))
    }
    fn add(&mut self, x: V) {
        if !self.has(x) {
            self.0.push(x.cloned());
        }
    }
}

pub fn ontology_digest(o: &Value) -> Res<String> {
    crate::hash_canonical_strict(&json!({"d": "atlas-pca/goal-intent-ontology/v1", "ontology": o}))
        .ok_or_else(|| "canonicalize: value outside the strict canonical profile".to_string())
}
/// The canonical verb id of an id or declared alias; case and homoglyph variants are NOT guessed.
pub fn resolve_verb(o: &Value, word: &str) -> Res<Option<Value>> {
    let w = js_trim(word);
    for v in seq_members(jget(Some(o), "verbs")?)?.into_iter() {
        if strict_eq(jget(Some(v), "id")?, Some(&Value::String(w.to_string()))) {
            return Ok(Some(Value::String(w.to_string())));
        }
    }
    Ok(own(jget(Some(o), "aliases")?, w)?.cloned())
}

// ---- projection onto the IR
/// The currency a goal is written in: the first money quantity in its conditions or bound caps.
pub fn goal_ccy(g: &Value) -> Res<Option<Value>> {
    fn money(q: V) -> Res<Option<Value>> {
        let u = jget(jget(q, "q")?, "u")?;
        Ok(if is_str(jget(u, "k")?, "money") { Some(jget(u, "ccy")?.cloned().unwrap_or(Value::Null)) } else { None })
    }
    fn term(x: V, found: &mut Option<Value>) -> Res<()> {
        if !is_str(jget(x, "k")?, "lit") {
            return Ok(());
        }
        let v = jget(x, "v")?;
        let set_items = if is_str(jget(v, "k")?, "set") { Some(seq(jget(v, "items")?)?) } else { None };
        let items: Vec<V> = match &set_items {
            Some(l) => l.iter().map(Some).collect(),
            None => vec![v],
        };
        for i in items {
            if found.is_none() && is_str(jget(i, "k")?, "q") {
                if let Some(c) = money(i)? {
                    *found = Some(c);
                }
            }
        }
        Ok(())
    }
    fn cond(x: V, found: &mut Option<Value>) -> Res<()> {
        let k = jget(x, "k")?;
        if is_str(k, "cmp") {
            term(jget(x, "l")?, found)?;
            term(jget(x, "r")?, found)?;
        } else if is_str(k, "and") || is_str(k, "or") {
            cond(jget(x, "a")?, found)?;
            cond(jget(x, "b")?, found)?;
        } else if is_str(k, "not") {
            cond(jget(x, "c")?, found)?;
        }
        Ok(())
    }
    let g = Some(g);
    let mut found: Option<Value> = None;
    for gr in seq(jget(g, "grants")?)?.iter() {
        cond(jget(Some(gr), "cond")?, &mut found)?;
    }
    for p in seq(jget(g, "prohibits")?)?.iter() {
        cond(jget(Some(p), "cond")?, &mut found)?;
    }
    for c in seq(jget(g, "escalateOn")?)?.iter() {
        cond(Some(c), &mut found)?;
    }
    for b in seq(jget(g, "bounds")?)?.iter() {
        let cap = jget(Some(b), "cap")?;
        if found.is_none() && is_str(jget(jget(cap, "u")?, "k")?, "money") {
            found = Some(jget(jget(cap, "u")?, "ccy")?.cloned().unwrap_or(Value::Null));
        }
    }
    Ok(found)
}
fn param_ty(p: V, ccy: V) -> Res<Value> {
    let kind = jget(p, "kind")?;
    if is_str(kind, "id") || is_str(kind, "enum") || is_str(kind, "text") {
        return Ok(json!({"k": "s"}));
    }
    if is_str(kind, "money") {
        let ccys = jget(p, "ccys")?;
        let c: Option<Value> = if ccy.is_some() && includes(ccys, ccy) {
            ccy.cloned()
        } else if includes(ccys, Some(&json!("USD"))) {
            Some(json!("USD"))
        } else {
            match ccys {
                Some(Value::Array(a)) => a.first().cloned(),
                _ => return Err("Cannot read properties of undefined (reading '0')".into()),
            }
        };
        let mut u = Map::new();
        u.insert("k".into(), json!("money"));
        if let Some(c) = c {
            u.insert("ccy".into(), c);
        }
        return Ok(json!({"k": "q", "u": Value::Object(u)}));
    }
    let mut u = Map::new();
    if let Some(k) = kind {
        u.insert("k".into(), k.clone());
    }
    Ok(json!({"k": "q", "u": Value::Object(u)}))
}
/// T1's IR `Ontology` (verbs with effect class and typed parameters, relation tables) for an intent ontology. `opts`: `{ccy?, rels?}`.
pub fn to_ir_ontology(o: &Value, opts: &Value) -> Res<Value> {
    let ccy = jget(Some(opts), "ccy")?;
    let mut verbs = Vec::new();
    for v in seq_members(jget(Some(o), "verbs")?)?.into_iter() {
        let params = jget(Some(v), "params")?;
        let mut paths: Vec<String> = entries(params)?.into_iter().map(|(k, _)| k).collect();
        paths.sort_by(|a, b| u16cmp(a, b));
        let mut ps = Vec::new();
        for path in paths {
            ps.push(json!({"path": path, "ty": param_ty(own(params, &path)?, ccy)?}));
        }
        let mut m = Map::new();
        m.insert("verb".into(), jget(Some(v), "id")?.cloned().unwrap_or(Value::Null));
        m.insert("cls".into(), jget(Some(v), "effect")?.cloned().unwrap_or(Value::Null));
        m.insert("params".into(), Value::Array(ps));
        verbs.push(Value::Object(m));
    }
    let rels = match jget(Some(opts), "rels")? {
        None | Some(Value::Null) => json!([]),
        Some(r) => r.clone(),
    };
    Ok(json!({"verbs": verbs, "rels": rels}))
}
/// The IR ontology a goal is typed and decided against: money parameters in the goal's own currency.
pub fn ontology_for_goal(o: &Value, g: &Value, rels: Option<&Value>) -> Res<Value> {
    let mut opts = Map::new();
    opts.insert("rels".into(), rels.cloned().unwrap_or_else(|| json!([])));
    if let Some(c) = goal_ccy(g)? {
        opts.insert("ccy".into(), c);
    }
    to_ir_ontology(o, &Value::Object(opts))
}
/// Relation anchors a goal mentions, declared with no members.
pub fn goal_anchors(g: &Value) -> Res<Vec<Value>> {
    fn sel(s: V, out: &mut Vec<(String, Value)>) -> Res<()> {
        let k = jget(s, "k")?;
        if is_str(k, "related") {
            let (rel, anchor) = (s_of(jget(s, "rel")?)?.to_string(), s_of(jget(s, "anchor")?)?.to_string());
            let key = format!("{rel}\0{anchor}");
            let v = json!({"rel": rel, "anchor": anchor, "members": []});
            match out.iter_mut().find(|(k, _)| *k == key) {
                Some(e) => e.1 = v,
                None => out.push((key, v)),
            }
        } else if is_str(k, "all_of") {
            for p in seq(jget(s, "parts")?)?.iter() {
                sel(Some(p), out)?;
            }
        }
        Ok(())
    }
    let g = Some(g);
    let mut out: Vec<(String, Value)> = Vec::new();
    for gr in seq(jget(g, "grants")?)?.iter() {
        sel(jget(Some(gr), "res")?, &mut out)?;
    }
    for p in seq(jget(g, "prohibits")?)?.iter() {
        sel(jget(Some(p), "res")?, &mut out)?;
    }
    out.sort_by(|a, b| u16cmp(&a.0, &b.0));
    Ok(out.into_iter().map(|(_, v)| v).collect())
}

// ---- slot references
fn refs_res(s: V) -> Res<Vec<String>> {
    let d = |x: V| -> Res<Vec<String>> { Ok(if s_of(x)?.starts_with('$') { vec![s_of(x)?[1..].to_string()] } else { vec![] }) };
    let k = jget(s, "k")?;
    if is_str(k, "exact") {
        d(jget(s, "id")?)
    } else if is_str(k, "oneof") {
        let mut out = vec![];
        for i in seq(jget(s, "ids")?)?.iter() {
            out.extend(d(Some(i))?);
        }
        Ok(out)
    } else if is_str(k, "related") {
        d(jget(s, "anchor")?)
    } else if is_str(k, "all_of") {
        let mut out = vec![];
        for p in seq(jget(s, "parts")?)?.iter() {
            out.extend(refs_res(Some(p))?);
        }
        Ok(out)
    } else {
        Ok(vec![])
    }
}
fn refs_term(x: V) -> Res<Vec<String>> {
    Ok(if is_str(jget(x, "k")?, "slot") { vec![s_of(jget(x, "slot")?)?.to_string()] } else { vec![] })
}
fn refs_cond(c: V) -> Res<Vec<String>> {
    let k = jget(c, "k")?;
    if is_str(k, "cmp") {
        let mut v = refs_term(jget(c, "l")?)?;
        v.extend(refs_term(jget(c, "r")?)?);
        Ok(v)
    } else if is_str(k, "and") || is_str(k, "or") {
        let mut v = refs_cond(jget(c, "a")?)?;
        v.extend(refs_cond(jget(c, "b")?)?);
        Ok(v)
    } else if is_str(k, "not") {
        refs_cond(jget(c, "c")?)
    } else {
        Ok(vec![])
    }
}
fn refs_grant(g: V) -> Res<Vec<String>> {
    let mut v = refs_res(jget(g, "res")?)?;
    v.extend(refs_cond(jget(g, "cond")?)?);
    Ok(v)
}
fn refs_bound(b: V) -> Res<Vec<String>> {
    let c = jget(b, "cap_slot")?;
    Ok(if truthy(c) { vec![s_of(c)?.to_string()] } else { vec![] })
}
fn slot_refs(t: V) -> Res<Vec<String>> {
    let mut v = vec![];
    for g in seq(jget(t, "grants")?)?.iter() {
        v.extend(refs_grant(Some(g))?);
    }
    for p in seq(jget(t, "prohibits")?)?.iter() {
        v.extend(refs_grant(Some(p))?);
    }
    for b in seq(jget(t, "bounds")?)?.iter() {
        v.extend(refs_bound(Some(b))?);
    }
    Ok(v)
}

// ---- the checker
struct Issues(Vec<Value>);
impl Issues {
    fn bad(&mut self, code: &str, wh: Option<Value>, msg: &str) {
        let mut m = Map::new();
        m.insert("code".into(), json!(code));
        if let Some(w) = wh {
            m.insert("where".into(), w);
        }
        m.insert("msg".into(), json!(msg));
        self.0.push(Value::Object(m));
    }
    fn badw(&mut self, code: &str, wh: &str, msg: &str) {
        self.bad(code, Some(json!(wh)), msg);
    }
}
/// Well-formedness checker: every defect as `{code, where, msg}`; an empty list means well formed.
/// `allow_witness(goal, grant, irOntology)` is `examples.ts allowWitness` (is there a minimal Allow witness for the grant).
pub fn check_ontology(o: &Value, allow_witness: &dyn Fn(&Value, &Value, &Value) -> bool) -> Res<Vec<Value>> {
    let ov = Some(o);
    let mut is = Issues(vec![]);
    let (mut type_ids, mut prefixes) = (JsSet::default(), JsSet::default());
    for t in seq(jget(ov, "types")?)?.iter() {
        let tid = jget(Some(t), "id")?;
        if type_ids.has(tid) {
            is.bad("dup_type", tid.cloned(), "duplicate type id");
        }
        type_ids.add(tid);
        let pre = jget(Some(t), "id_prefix")?;
        if !truthy(pre) || prefixes.has(pre) {
            is.bad("dup_prefix", tid.cloned(), "id prefix empty or reused");
        }
        prefixes.add(pre);
    }
    let units = jget(ov, "units")?;
    let units_chars = chars_as_array(units);
    let units = units_chars.as_ref().or(units);
    for (u, d) in entries(units)? {
        let (exp, kind) = (jget(Some(d), "exponent")?, jget(Some(d), "kind")?);
        if is_str(kind, "money") && !(is_integer(exp) && num(exp).is_some_and(|x| (0.0..=4.0).contains(&x))) {
            is.badw("unit_exponent", &u, "money unit needs an integer exponent 0..4");
        }
        if !is_str(kind, "money") && exp.is_some() {
            is.badw("unit_exponent", &u, "only money units carry an exponent");
        }
    }
    let mut rel_ids = JsSet::default();
    for r in seq(jget(ov, "relations")?)?.iter() {
        let rid = jget(Some(r), "id")?;
        if rel_ids.has(rid) {
            is.bad("dup_relation", rid.cloned(), "duplicate relation");
        }
        rel_ids.add(rid);
        if !type_ids.has(jget(Some(r), "from")?) || !type_ids.has(jget(Some(r), "to")?) {
            is.bad("relation_type", rid.cloned(), "relation endpoint type is not declared");
        }
    }
    let mut verb_ids = JsSet::default();
    let mut verbs: Vec<(V, &Value)> = Vec::new();
    for v in seq_members(jget(ov, "verbs")?)?.into_iter() {
        let vid = jget(Some(v), "id")?;
        if verb_ids.has(vid) {
            is.bad("dup_verb", vid.cloned(), "duplicate verb");
        }
        verb_ids.add(vid);
        match verbs.iter_mut().find(|(k, _)| strict_eq(*k, vid)) {
            Some(e) => e.1 = v,
            None => verbs.push((vid, v)),
        }
        if !includes(Some(&json!(EFFECT_CLASSES)), jget(Some(v), "effect")?) {
            is.bad("no_effect_class", vid.cloned(), "verb has no valid effect class");
        }
        if !type_ids.has(jget(Some(v), "resource_type")?) {
            is.bad("verb_resource_type", vid.cloned(), "resource type is not declared");
        }
        let params_v = jget(Some(v), "params")?;
        let params_chars = chars_as_array(params_v);
        for (p, pt) in entries(params_chars.as_ref().or(params_v))? {
            let kind = jget(Some(pt), "kind")?;
            let w = format!("{}.{}", js_str(vid), p);
            if is_str(kind, "money") {
                let ccys = jget(Some(pt), "ccys")?;
                if !len_pos(ccys) {
                    is.badw("param_ccy", &w, "money parameter lists no currency");
                }
                if let Some(Value::Array(a)) = ccys {
                    for c in a {
                        let unit = own(units, &js_str(Some(c)))?;
                        let k = match unit {
                            None | Some(Value::Null) => None,
                            u => jget(u, "kind")?,
                        };
                        if !is_str(k, "money") {
                            is.badw("unit_unknown", &w, &format!("currency {} is not a declared money unit", js_str(Some(c))));
                        }
                    }
                }
            } else if is_str(kind, "enum") {
                if !len_pos(jget(Some(pt), "values")?) {
                    is.badw("param_enum", &w, "enum parameter has no values");
                }
            } else if is_str(kind, "id") {
                let of = jget(Some(pt), "of")?;
                if !truthy(of) || !type_ids.has(of) {
                    is.badw("param_type", &w, "id parameter type is not declared");
                }
            } else if !is_str(kind, "text") {
                let mut any = false;
                for (_, u) in entries(units)? {
                    if strict_eq(jget(Some(u), "kind")?, kind) {
                        any = true;
                    }
                }
                if !any {
                    is.badw("unit_unknown", &w, &format!("no declared unit of kind {}", js_str(kind)));
                }
            }
        }
    }
    // aliases: a function, keys normalized and collision-free, targets canonical, no chains or cycles
    let mut seen: Vec<(String, String)> = Vec::new();
    let aliases = jget(ov, "aliases")?;
    let aliases_chars = chars_as_array(aliases);
    let aliases = aliases_chars.as_ref().or(aliases);
    for (k, target) in entries(aliases)? {
        let nk = norm(&k);
        let non_ascii = k.chars().any(|c| !(' '..='~').contains(&c));
        if k != nk || (non_ascii && k != k.nfkc().collect::<String>()) {
            is.badw("alias_key", &k, "alias key is not in normalized form");
        }
        if k.chars().any(is_invis) {
            is.badw("alias_key", &k, "alias key contains invisible characters");
        }
        if let Some(prev) = seen.iter().find(|(n, _)| *n == nk).map(|(_, p)| p.clone()) {
            if prev != k {
                is.badw("alias_collision", &k, &format!("collides with {prev} after normalization"));
            }
        }
        match seen.iter_mut().find(|(n, _)| *n == nk) {
            Some(e) => e.1 = k.clone(),
            None => seen.push((nk, k.clone())),
        }
        if !verb_ids.has(Some(target)) {
            is.badw("alias_target", &k, "alias target is not a canonical verb");
        }
        if own(aliases, &js_str(Some(target)))?.is_some() {
            is.badw("alias_chain", &k, "alias target is itself an alias (chain or cycle)");
        }
        if verb_ids.has(Some(&Value::String(k.clone()))) && !strict_eq(Some(&Value::String(k.clone())), Some(target)) {
            is.badw("alias_shadow", &k, "alias shadows a canonical verb");
        }
    }
    // templates
    let mut tids = JsSet::default();
    for t in seq(jget(ov, "templates")?)?.iter() {
        let tv = Some(t);
        let tid = jget(tv, "id")?;
        let w = format!("template:{}", js_str(tid));
        if tids.has(tid) {
            is.badw("dup_template", &w, "duplicate template id");
        }
        tids.add(tid);
        let slots = seq(jget(tv, "slots")?)?;
        let mut slot_names = JsSet::default();
        for s in slots.iter() {
            slot_names.add(jget(Some(s), "name")?);
        }
        if slot_names.0.len() != slots.len() {
            is.badw("dup_slot", &w, "duplicate slot");
        }
        let refs = slot_refs(tv)?;
        for r in &refs {
            if !slot_names.has(Some(&Value::String(r.clone()))) {
                is.badw("slot_undeclared", &w, &format!("slot {r} is used but not declared"));
            }
        }
        for s in slots.iter() {
            let sv = Some(s);
            let name = jget(sv, "name")?;
            let sw = format!("{w}.{}", js_str(name));
            let sk = jget(sv, "kind")?;
            if is_str(sk, "id") || is_str(sk, "id_list") {
                let of = jget(sv, "of")?;
                if !truthy(of) || !type_ids.has(of) {
                    is.badw("slot_type", &sw, "id slot type is not declared");
                }
            }
            if is_str(sk, "money") {
                let ccy = jget(sv, "ccy")?;
                let key = match ccy {
                    None => String::new(),
                    Some(Value::String(c)) => c.clone(),
                    _ => "\u{0}".into(),
                };
                let k = match own(units, &key)? {
                    None | Some(Value::Null) => None,
                    u => jget(u, "kind")?,
                };
                if !is_str(k, "money") {
                    is.badw("slot_ccy", &sw, "money slot currency is not a declared unit");
                }
            }
            if (is_str(sk, "enum") || is_str(sk, "enum_list")) && !len_pos(jget(sv, "values")?) {
                is.badw("slot_enum", &sw, "enum slot has no values");
            }
            if !truthy(jget(sv, "mandatory")?) && jget(sv, "default")?.is_none() {
                is.badw("slot_default", &sw, "optional slot needs a default (an unfilled slot must be a hole or a default)");
            }
            if !refs.iter().any(|r| strict_eq(name, Some(&Value::String(r.clone())))) {
                is.badw("slot_unused", &sw, "declared slot is never used");
            }
        }
        let tgrants = seq(jget(tv, "grants")?)?;
        let tbounds = seq(jget(tv, "bounds")?)?;
        if tgrants.is_empty() {
            is.badw("empty_allow", &w, "template has no grant (empty Allow set)");
        }
        let mut gids = JsSet::default();
        for g in tgrants.iter() {
            gids.add(jget(Some(g), "gid")?);
        }
        if gids.0.len() != tgrants.len() {
            is.badw("dup_gid", &w, "duplicate grant id");
        }
        for g in tgrants.iter() {
            let gv = Some(g);
            let gw = format!("{w}.{}", js_str(jget(gv, "gid")?));
            let verb = jget(gv, "verb")?;
            let v = match verbs.iter().find(|(k, _)| strict_eq(*k, verb)) {
                Some((_, v)) => *v,
                None => {
                    is.badw("grant_verb", &gw, "grant verb is not in the ontology");
                    continue;
                }
            };
            check_resource(o, jget(gv, "res")?, v, &gw, &mut is)?;
            check_cond(jget(gv, "cond")?, v, t, &gw, &mut is)?;
            let res = jget(gv, "res")?;
            let effect = jget(Some(v), "effect")?;
            if is_str(jget(res, "k")?, "any") && !(is_str(effect, "read") && !tbounds.is_empty()) {
                is.badw("unbounded", &gw, "wildcard resource in a template");
            }
            if !is_str(effect, "read") && is_str(jget(res, "k")?, "related") && tbounds.is_empty() {
                is.badw("unbounded", &gw, "non-read grant on a related set needs an aggregate bound");
            }
        }
        for p in seq(jget(tv, "prohibits")?)?.iter() {
            let tg = jget(Some(p), "target")?;
            let pw = format!("{w}.{}", js_str(jget(Some(p), "pid")?));
            if is_str(jget(tg, "k")?, "verb") && !verbs.iter().any(|(k, _)| strict_eq(*k, jget(tg, "verb").ok().flatten())) {
                is.badw("prohibit_verb", &pw, "prohibit verb is not in the ontology");
            }
            if is_str(jget(tg, "k")?, "effect") && !includes(Some(&json!(EFFECT_CLASSES)), jget(tg, "cls")?) {
                is.badw("prohibit_effect", &pw, "unknown effect class");
            }
        }
        for b in tbounds.iter() {
            let bv = Some(b);
            let bw = format!("{w}.{}", js_str(jget(bv, "bid")?));
            let over = jget(bv, "over")?;
            if !is_str(over, "all") {
                for x in seq(over)?.iter() {
                    if !gids.has(Some(x)) {
                        is.badw("bound_over", &bw, "bound selects an unknown grant");
                        break;
                    }
                }
            }
            let cs_name = jget(bv, "cap_slot")?;
            if truthy(cs_name) && !slot_names.has(cs_name) {
                is.badw("slot_undeclared", &w, &format!("cap slot {} is not declared", js_str(cs_name)));
            }
            if truthy(cs_name) {
                let mut cs_found: V = None;
                for x in slots.iter() {
                    if strict_eq(jget(Some(x), "name")?, cs_name) {
                        cs_found = Some(x);
                        break;
                    }
                }
                if let Some(cs) = cs_found {
                    let (csk, agg) = (jget(Some(cs), "kind")?, jget(bv, "agg")?);
                    if !(is_str(csk, "money") || is_str(csk, "count")) {
                        is.badw("bound_cap", &bw, "cap slot must be money or count");
                    }
                    if is_str(agg, "count") && !is_str(csk, "count") {
                        is.badw("bound_cap", &bw, "count bound needs a count slot");
                    }
                    if is_str(agg, "sum") && !is_str(csk, "money") {
                        is.badw("bound_cap", &bw, "sum bound over money needs a money slot");
                    }
                }
            }
            if is_str(jget(bv, "agg")?, "sum") && !truthy(jget(bv, "param")?) {
                is.badw("bound_value", &bw, "sum bound has no value parameter");
            }
        }
        // non-empty and bounded after instantiation with the declared example
        let g = instantiate_template(o, tid, jget(tv, "example")?, &json!({"principal": "p", "nl": ""}))?;
        let holes = g["holes"].as_array().cloned().unwrap_or_default();
        if !holes.is_empty() {
            let ids: Vec<String> = holes.iter().map(|h| js_str(h.get("hid"))).collect();
            is.badw("example_holes", &w, &format!("example leaves holes: {}", ids.join(",")));
        } else if g["grants"].as_array().map_or(0, |a| a.len()) != tgrants.len() {
            is.badw("empty_allow", &w, "example instantiation dropped a grant");
        } else {
            let ont = ontology_for_goal(o, &g, None)?;
            if !g["grants"].as_array().unwrap().iter().all(|gr| allow_witness(&g, gr, &ont)) {
                is.badw("empty_allow", &w, "instantiated template has an empty Allow set");
            }
        }
    }
    Ok(is.0)
}

fn id_ok(i: V, pre: V) -> Res<bool> {
    Ok(s_of(i)?.starts_with('$') || (pre.is_some() && starts(i, pre)?))
}
fn check_resource(o: &Value, s: V, v: &Value, w: &str, is: &mut Issues) -> Res<()> {
    let rt = jget(Some(v), "resource_type")?;
    let ty = find(jget(Some(o), "types")?, |t| Ok(strict_eq(jget(Some(t), "id")?, rt)))?;
    let prefix = match ty {
        None => None,
        t => jget(t, "id_prefix")?,
    };
    let k = jget(s, "k")?;
    if is_str(k, "exact") {
        if !id_ok(jget(s, "id")?, prefix)? {
            is.badw("resource_type", w, "exact resource id has the wrong type prefix");
        }
    } else if is_str(k, "oneof") {
        let ids = seq(jget(s, "ids")?)?;
        if ids.is_empty() {
            is.badw("resource_empty", w, "one_of is empty");
        }
        for i in ids.iter() {
            if !id_ok(Some(i), prefix)? {
                is.badw("resource_type", w, "one_of member has the wrong type prefix");
            }
        }
    } else if is_str(k, "related") {
        let rel = jget(s, "rel")?;
        match find(jget(Some(o), "relations")?, |x| Ok(strict_eq(jget(Some(x), "id")?, rel)))? {
            None => is.badw("relation_unknown", w, &format!("relation {} is not declared", js_str(rel))),
            Some(r) => {
                if !strict_eq(jget(Some(r), "to")?, rt) {
                    is.badw("relation_type", w, "relation target type differs from the verb resource type");
                }
                let rf = jget(Some(r), "from")?;
                let ft = find(jget(Some(o), "types")?, |t| Ok(strict_eq(jget(Some(t), "id")?, rf)))?;
                let anchor_pre = match ft {
                    None => None,
                    t => jget(t, "id_prefix")?,
                };
                if !id_ok(jget(s, "anchor")?, anchor_pre)? {
                    is.badw("resource_type", w, "relation anchor has the wrong type prefix");
                }
            }
        }
    } else if is_str(k, "all_of") {
        let parts = seq(jget(s, "parts")?)?;
        if parts.len() < 2 {
            is.badw("all_of_arity", w, "all_of needs at least two parts");
        }
        for x in parts.iter() {
            check_resource(o, Some(x), v, w, is)?;
        }
    }
    Ok(())
}
fn check_cond(c: V, v: &Value, t: &Value, w: &str, is: &mut Issues) -> Res<()> {
    let k = jget(c, "k")?;
    if is_str(k, "and") || is_str(k, "or") {
        check_cond(jget(c, "a")?, v, t, w, is)?;
        return check_cond(jget(c, "b")?, v, t, w, is);
    }
    if is_str(k, "not") {
        return check_cond(jget(c, "c")?, v, t, w, is);
    }
    if !is_str(k, "cmp") {
        return Ok(());
    }
    let l = jget(c, "l")?;
    let lk = jget(l, "k")?;
    let p = if is_str(lk, "param") { own(jget(Some(v), "params")?, &js_str(jget(l, "path")?))? } else { None };
    if !is_str(lk, "param") || !truthy(p) {
        is.badw("cond_param", w, "left side of a comparison must be a declared parameter of the verb");
        return Ok(());
    }
    let op = jget(c, "op")?;
    let pk = jget(p, "kind")?;
    let ordered = ["lt", "lte", "gt", "gte"].iter().any(|o| is_str(op, o));
    if ordered && (is_str(pk, "text") || is_str(pk, "enum") || is_str(pk, "id")) {
        is.badw("cond_order", w, "ordering on a text/enum/id parameter");
    }
    let x = jget(c, "r")?;
    let xk = jget(x, "k")?;
    let in_op = is_str(op, "in") || is_str(op, "nin");
    if is_str(xk, "slot") {
        let sn = jget(x, "slot")?;
        let s = match find(jget(Some(t), "slots")?, |q| Ok(strict_eq(jget(Some(q), "name")?, sn)))? {
            None => return Ok(()),
            Some(s) => s,
        };
        let sk = jget(Some(s), "kind")?;
        let ok_kind = if is_str(pk, "money") {
            is_str(sk, "money")
        } else {
            strict_eq(pk, sk)
                || (is_str(pk, "enum") && (is_str(sk, "enum") || is_str(sk, "enum_list")))
                || (is_str(pk, "id") && (is_str(sk, "id") || is_str(sk, "id_list")))
                || (is_str(pk, "text") && is_str(sk, "text_list"))
        };
        if !ok_kind {
            is.badw(
                "cond_type",
                w,
                &format!("slot {} ({}) does not type-check against parameter kind {}", js_str(jget(Some(s), "name")?), js_str(sk), js_str(pk)),
            );
        }
        let ccys = jget(p, "ccys")?;
        let scc = jget(Some(s), "ccy")?;
        let empty = Value::String(String::new());
        if is_str(pk, "money") && is_str(sk, "money") && !(ccys.is_some() && includes(ccys, Some(scc.unwrap_or(&empty)))) {
            is.badw("cond_unit", w, "slot currency is not accepted by the parameter");
        }
        let list = is_str(sk, "id_list") || is_str(sk, "enum_list") || is_str(sk, "text_list");
        if list != in_op {
            is.badw("cond_type", w, "list slots pair with in/nin and scalar slots with the other operators");
        }
    } else if is_str(xk, "lit") {
        let lv = jget(x, "v")?;
        if is_str(jget(lv, "k")?, "set") {
            let items = seq(jget(lv, "items")?)?;
            if items.is_empty() {
                is.badw("cond_type", w, "empty literal list");
            }
            for i in items.iter() {
                lit_check(Some(i), p, w, is)?;
            }
            if !in_op {
                is.badw("cond_type", w, "a literal set pairs with in/nin");
            }
        } else {
            lit_check(lv, p, w, is)?;
            if in_op {
                is.badw("cond_type", w, "in/nin needs a list");
            }
        }
    } else {
        is.badw("cond_term", w, "unsupported right-hand term");
    }
    Ok(())
}
fn lit_check(l: V, p: V, w: &str, is: &mut Issues) -> Res<()> {
    let pk = jget(p, "kind")?;
    let k = jget(l, "k")?;
    if is_str(k, "q") {
        let u = jget(jget(l, "q")?, "u")?;
        if !strict_eq(jget(u, "k")?, pk) {
            is.badw("cond_type", w, "literal kind differs from the parameter kind");
        }
        let ccys = jget(p, "ccys")?;
        if is_str(jget(u, "k")?, "money") && !(ccys.is_some() && includes(ccys, jget(u, "ccy")?)) {
            is.badw("cond_unit", w, "literal currency is not accepted by the parameter");
        }
    } else if is_str(k, "s") {
        if !(is_str(pk, "enum") || is_str(pk, "id") || is_str(pk, "text")) {
            is.badw("cond_type", w, "literal kind differs from the parameter kind");
        }
        let vals = jget(p, "values")?;
        if is_str(pk, "enum") && !(vals.is_some() && includes(vals, jget(l, "s")?)) {
            is.badw("cond_enum", w, "enum literal is not a member");
        }
    } else {
        is.badw("cond_type", w, "nested literal set");
    }
    Ok(())
}

// ---- slot typing and instantiation
fn quantity_of(s: V, v: &Value) -> Res<Option<Value>> {
    let m = match v {
        Value::String(_) | Value::Array(_) => return Ok(None),
        Value::Object(m) => m,
        _ => return Err("Cannot use 'in' operator to search for a key in a non-object".into()),
    };
    let kind = jget(s, "kind")?;
    let nonneg_safe = |x: Option<&Value>, signed: bool| safe_int(x).is_some_and(|n| signed || n >= 0);
    if m.contains_key("minor") && is_str(kind, "money") && strict_eq(m.get("ccy"), jget(s, "ccy")?) && nonneg_safe(m.get("minor"), false) {
        return Ok(Some(json!({"u": {"k": "money", "ccy": m.get("ccy").cloned().unwrap_or(Value::Null)}, "n": m["minor"].clone()})));
    }
    if m.contains_key("n") && is_str(kind, "count") && nonneg_safe(m.get("n"), false) {
        return Ok(Some(json!({"u": {"k": "count"}, "n": m["n"].clone()})));
    }
    if m.contains_key("ms") && is_str(kind, "duration") && nonneg_safe(m.get("ms"), false) {
        return Ok(Some(json!({"u": {"k": "duration"}, "n": m["ms"].clone()})));
    }
    if m.contains_key("epoch_ms") && is_str(kind, "instant") && nonneg_safe(m.get("epoch_ms"), true) {
        return Ok(Some(json!({"u": {"k": "instant"}, "n": m["epoch_ms"].clone()})));
    }
    Ok(None)
}
fn sv(s: &str) -> Value {
    json!({"k": "s", "s": s})
}
fn id_chars(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}
/// A slot's typed values, or the reason it is missing / invalid (the slot then becomes a Hole).
#[derive(Debug, Clone, PartialEq)]
pub enum SlotLits {
    Lits(Vec<Value>),
    Reason(&'static str),
}
impl SlotLits {
    pub fn to_json(&self) -> Value {
        match self {
            SlotLits::Lits(v) => Value::Array(v.clone()),
            SlotLits::Reason(r) => json!(r),
        }
    }
}
/// Typed value(s) of a slot, or a reason string when it is missing / invalid.
pub fn slot_lits(o: &Value, s: &Value, v: V) -> Res<SlotLits> {
    let v = match v {
        None => return Ok(SlotLits::Reason("missing")),
        Some(v) => v,
    };
    let sv_ = Some(s);
    let kind = jget(sv_, "kind")?;
    if is_str(kind, "money") || is_str(kind, "count") || is_str(kind, "duration") || is_str(kind, "instant") {
        let q = match quantity_of(sv_, v)? {
            Some(q) => q,
            None => return Ok(SlotLits::Reason("ill-typed")),
        };
        if let Some(mx) = jget(sv_, "max")? {
            let n = if is_str(kind, "instant") { 0.0 } else { q["n"].as_f64().unwrap_or(0.0) };
            if num(Some(mx)).is_some_and(|m| n > m) {
                return Ok(SlotLits::Reason("above the template maximum"));
            }
        }
        return Ok(SlotLits::Lits(vec![json!({"k": "q", "q": q})]));
    }
    if is_str(kind, "id") || is_str(kind, "id_list") {
        let of = jget(sv_, "of")?;
        let ty = find(jget(Some(o), "types")?, |t| Ok(strict_eq(jget(Some(t), "id")?, of)))?;
        let pre = match ty {
            None => None,
            t => jget(t, "id_prefix")?,
        };
        let pre_s = if truthy(pre) { Some(js_str(pre)) } else { None };
        if is_str(kind, "id") {
            return Ok(match (v, &pre_s) {
                (Value::String(x), Some(p)) if x.starts_with(p.as_str()) && x.encode_utf16().count() > p.encode_utf16().count() && id_chars(x) => {
                    SlotLits::Lits(vec![sv(x)])
                }
                _ => SlotLits::Reason("ill-typed"),
            });
        }
        if let Value::Array(a) = v {
            if !a.is_empty() && pre_s.is_some() {
                let mut all = true;
                for x in a {
                    let xs = s_of(Some(x))?;
                    if !(pre_s.as_ref().is_some_and(|p| xs.starts_with(p.as_str())) && id_chars(xs)) {
                        all = false;
                        break;
                    }
                }
                if all {
                    return Ok(SlotLits::Lits(a.iter().map(|x| sv(x.as_str().unwrap())).collect()));
                }
            }
        }
        return Ok(SlotLits::Reason("ill-typed"));
    }
    let vals = jget(sv_, "values")?;
    if is_str(kind, "enum") {
        return Ok(match v {
            Value::String(x) if vals.is_some() && includes(vals, Some(v)) => SlotLits::Lits(vec![sv(x)]),
            _ => SlotLits::Reason("ill-typed"),
        });
    }
    if is_str(kind, "enum_list") {
        if let Value::Array(a) = v {
            if !a.is_empty() && vals.is_some() && a.iter().all(|x| includes(vals, Some(x))) {
                return Ok(SlotLits::Lits(a.iter().map(|x| sv(&js_str(Some(x)))).collect()));
            }
        }
        return Ok(SlotLits::Reason("ill-typed"));
    }
    if is_str(kind, "text_list") {
        if let Value::Array(a) = v {
            let good = |x: &Value| matches!(x, Value::String(t) if !t.is_empty() && *t == t.nfkc().collect::<String>() && !t.chars().any(is_invis));
            if !a.is_empty() && a.iter().all(good) {
                return Ok(SlotLits::Lits(a.iter().map(|x| sv(x.as_str().unwrap())).collect()));
            }
        }
        return Ok(SlotLits::Reason("ill-typed"));
    }
    Err("unknown slot kind".into())
}

fn lits<'b>(bound: &'b [(String, Vec<Value>)], n: &str) -> Res<&'b Vec<Value>> {
    bound.iter().find(|(k, _)| k == n).map(|(_, v)| v).ok_or_else(|| format!("slot {n} is not bound"))
}
fn verb_decl<'a>(o: &'a Value, verb: V) -> Res<V<'a>> {
    let mut found: V<'a> = None;
    for v in seq_members(jget(Some(o), "verbs")?)?.into_iter() {
        if strict_eq(jget(Some(v), "id")?, verb) {
            found = Some(v); // a later declaration of the same id replaces an earlier one
        }
    }
    Ok(found)
}
fn is_list_slot(t: &Value, name: &str) -> Res<bool> {
    let s = find(jget(Some(t), "slots")?, |x| Ok(is_str(jget(Some(x), "name")?, name)))?;
    Ok(match s {
        Some(s) => matches!(jget(Some(s), "kind")?, Some(Value::String(k)) if k.ends_with("_list")),
        None => false,
    })
}

/// Template -> Goal (IR, canonical order). Mandatory slots that are missing or ill-typed become Holes; every clause depending on a
/// hole is dropped (the most restrictive completion); a prohibition that depends on a hole widens to every resource. Limits become
/// IR bounds over the surviving grants (admitting grant, lifetime window, session scope). `opts`: `{principal, nl, sources?}`.
pub fn instantiate_template(o: &Value, template_id: V, values: V, opts: &Value) -> Res<Value> {
    let ov = Some(o);
    let t = find(jget(ov, "templates")?, |x| Ok(strict_eq(jget(Some(x), "id")?, template_id)))?
        .ok_or_else(|| format!("unknown template {}", js_str(template_id)))?;
    let tv = Some(t);
    let mut bound: Vec<(String, Vec<Value>)> = Vec::new();
    let mut holes: Vec<Value> = Vec::new();
    for s in seq(jget(tv, "slots")?)?.iter() {
        let name = s_of(jget(Some(s), "name")?)?.to_string();
        let given = match own(values, &name)? {
            None | Some(Value::Null) => jget(Some(s), "default")?,
            v => v,
        };
        match slot_lits(o, s, given)? {
            SlotLits::Reason(r) => {
                let ccy = jget(Some(s), "ccy")?;
                let cs = if truthy(ccy) { format!(" {}", js_str(ccy)) } else { String::new() };
                holes.push(json!({"hid": name, "q": format!("What is the {} ({}{})? ({})", name.replace('_', " "), js_str(jget(Some(s), "kind")?), cs, r), "domain": [], "affects": [], "global": false}));
            }
            SlotLits::Lits(l) => bound.push((name, l)),
        }
    }
    let deps = |refs: &[String]| refs.iter().all(|r| bound.iter().any(|(k, _)| k == r));
    let lits_of = |n: &str| lits(&bound, n);
    let sub = |i: V| -> Res<String> {
        let s = s_of(i)?;
        match s.strip_prefix('$') {
            Some(n) => Ok(lits_of(n)?[0].get("s").and_then(Value::as_str).ok_or("slot value is not a string")?.to_string()),
            None => Ok(s.to_string()),
        }
    };
    let sub_part = |r: V| -> Res<Value> {
        let k = jget(r, "k")?;
        if is_str(k, "exact") {
            Ok(json!({"k": "exact", "id": sub(jget(r, "id")?)?}))
        } else if is_str(k, "oneof") {
            let ids: Res<Vec<String>> = seq(jget(r, "ids")?)?.iter().map(|i| sub(Some(i))).collect();
            Ok(json!({"k": "oneof", "ids": ids?}))
        } else {
            let mut m = r.and_then(Value::as_object).cloned().ok_or("part must be an object")?;
            m.insert("anchor".into(), json!(sub(jget(r, "anchor")?)?));
            Ok(Value::Object(m))
        }
    };
    let sub_res = |r: V| -> Res<Value> {
        let k = jget(r, "k")?;
        if is_str(k, "any") {
            Ok(r.cloned().unwrap())
        } else if is_str(k, "all_of") {
            let parts: Res<Vec<Value>> = seq(jget(r, "parts")?)?.iter().map(|p| sub_part(Some(p))).collect();
            Ok(json!({"k": "all_of", "parts": parts?}))
        } else {
            sub_part(r)
        }
    };
    let ty_of = |verb: V, path: V, ccy: V| -> Res<Value> {
        let key = js_str(path);
        let mut p: V = match verb_decl(o, verb)? {
            Some(v) => own(jget(Some(v), "params")?, &key)?,
            None => None,
        };
        if p.is_none() || matches!(p, Some(Value::Null)) {
            p = None;
            for v in seq_members(jget(ov, "verbs")?)?.into_iter() {
                if let Some(x) = own(jget(Some(v), "params")?, &key)? {
                    p = Some(x);
                    break;
                }
            }
        }
        match p {
            None => Err(format!("parameter {key} is not declared by any verb")),
            p => param_ty(p, ccy),
        }
    };
    let lit = |x: V| -> Res<Option<Value>> {
        let k = jget(x, "k")?;
        if is_str(k, "slot") {
            let n = s_of(jget(x, "slot")?)?;
            let l = lits_of(n)?;
            let v = if is_list_slot(t, n)? { json!({"k": "set", "items": l}) } else { l[0].clone() };
            Ok(Some(json!({"k": "lit", "v": v})))
        } else if is_str(k, "lit") {
            Ok(Some(json!({"k": "lit", "v": jget(x, "v")?.cloned().unwrap_or(Value::Null)})))
        } else {
            Ok(None)
        }
    };
    let ccy_of = |x: &Option<Value>| -> Option<Value> {
        let x = x.as_ref()?;
        let u = &x["v"]["q"]["u"];
        (x["v"]["k"] == "q" && u["k"] == "money").then(|| u["ccy"].clone())
    };
    fn sub_cond(
        c: V,
        verb: V,
        lit: &dyn Fn(V) -> Res<Option<Value>>,
        ccy_of: &dyn Fn(&Option<Value>) -> Option<Value>,
        ty_of: &dyn Fn(V, V, V) -> Res<Value>,
    ) -> Res<Value> {
        let k = jget(c, "k")?;
        if is_str(k, "true") {
            return Ok(c.cloned().unwrap());
        }
        if is_str(k, "and") || is_str(k, "or") {
            let kk = if is_str(k, "and") { "and" } else { "or" };
            return Ok(json!({"k": kk, "a": sub_cond(jget(c, "a")?, verb, lit, ccy_of, ty_of)?, "b": sub_cond(jget(c, "b")?, verb, lit, ccy_of, ty_of)?}));
        }
        if is_str(k, "not") {
            return Ok(json!({"k": "not", "c": sub_cond(jget(c, "c")?, verb, lit, ccy_of, ty_of)?}));
        }
        let (l, r) = (jget(c, "l")?, jget(c, "r")?);
        let (lv, rv) = (lit(l)?, lit(r)?);
        let hint = ccy_of(&lv).or_else(|| ccy_of(&rv));
        let term = |x: V, v: Option<Value>| -> Res<Value> {
            match v {
                Some(v) => Ok(v),
                None => {
                    let path = jget(x, "path")?;
                    Ok(json!({"k": "param", "path": path.cloned().unwrap_or(Value::Null), "ty": ty_of(verb, path, hint.as_ref())?}))
                }
            }
        };
        Ok(json!({"k": "cmp", "op": jget(c, "op")?.cloned().unwrap_or(Value::Null), "l": term(l, lv)?, "r": term(r, rv)?}))
    }
    let scond = |c: V, verb: V| sub_cond(c, verb, &lit, &ccy_of, &ty_of);

    let t_bounds = seq(jget(tv, "bounds")?)?;
    let t_grants = seq(jget(tv, "grants")?)?;
    let mut dropped: Vec<String> = Vec::new();
    let keep_bound: Vec<&Value> = {
        let mut k = vec![];
        for b in t_bounds.iter() {
            if deps(&refs_bound(Some(b))?) {
                k.push(b);
            }
        }
        k
    };
    for b in t_bounds.iter() {
        if !keep_bound.iter().any(|kb| std::ptr::eq(*kb, b)) {
            for g in t_grants.iter() {
                let over = jget(Some(b), "over")?;
                let gid = jget(Some(g), "gid")?;
                if is_str(over, "all") || includes(over, gid) {
                    dropped.push(js_str(gid));
                }
            }
        }
    }
    let mut grants: Vec<Value> = Vec::new();
    for g in t_grants.iter() {
        let gid = js_str(jget(Some(g), "gid")?);
        if dropped.contains(&gid) || !deps(&refs_grant(Some(g))?) {
            dropped.push(gid);
        } else {
            let verb = jget(Some(g), "verb")?;
            grants.push(json!({"gid": gid, "verb": verb.cloned().unwrap_or(Value::Null), "res": sub_res(jget(Some(g), "res")?)?, "cond": scond(jget(Some(g), "cond")?, verb)?}));
        }
    }
    let mut prohibits: Vec<Value> = Vec::new();
    for p in seq(jget(tv, "prohibits")?)?.iter() {
        let tg = jget(Some(p), "target")?;
        let verb_v: Option<Value> = if is_str(jget(tg, "k")?, "verb") {
            jget(tg, "verb")?.cloned()
        } else {
            find(jget(ov, "verbs")?, |v| Ok(strict_eq(jget(Some(v), "effect")?, jget(tg, "cls")?)))?
                .map(|v| jget(Some(v), "id"))
                .transpose()?
                .flatten()
                .cloned()
        };
        let pid = jget(Some(p), "pid")?.cloned().unwrap_or(Value::Null);
        let target = tg.cloned().unwrap_or(Value::Null);
        if deps(&refs_grant(Some(p))?) {
            prohibits
                .push(json!({"pid": pid, "target": target, "res": sub_res(jget(Some(p), "res")?)?, "cond": scond(jget(Some(p), "cond")?, verb_v.as_ref())?}));
        } else {
            prohibits.push(json!({"pid": pid, "target": target, "res": {"k": "any", "reason": "hole"}, "cond": {"k": "true"}}));
        }
    }
    let kept: Vec<String> = grants.iter().map(|g| js_str(g.get("gid"))).collect();
    let mut bounds: Vec<Value> = Vec::new();
    for b in keep_bound {
        let bv = Some(b);
        let over = jget(bv, "over")?;
        let gids: Vec<String> =
            if is_str(over, "all") { kept.clone() } else { seq(over)?.iter().map(|x| js_str(Some(x))).filter(|x| kept.contains(x)).collect() };
        if gids.is_empty() {
            continue;
        }
        let cs = jget(bv, "cap_slot")?;
        let cap_lit: Option<Value> = if truthy(cs) { Some(lits_of(s_of(cs)?)?[0].clone()) } else { None };
        let cap: Value = match cap_lit {
            Some(l) if l["k"] == "q" => l["q"].clone(),
            _ => jget(bv, "cap")?.cloned().unwrap_or(Value::Null),
        };
        let first = grants.iter().find(|g| js_str(g.get("gid")) == gids[0]).ok_or("bound selects no grant")?;
        let verb = first.get("verb");
        let agg = jget(bv, "agg")?;
        let value = if is_str(agg, "sum") {
            let param = jget(bv, "param")?;
            let hint = if cap["u"]["k"] == "money" { Some(cap["u"]["ccy"].clone()) } else { None };
            json!({"k": "param", "path": param.cloned().unwrap_or(Value::Null), "ty": ty_of(verb, param, hint.as_ref())?})
        } else {
            json!({"k": "lit", "v": {"k": "q", "q": {"u": {"k": "count"}, "n": 1}}})
        };
        bounds.push(json!({"bid": jget(bv, "bid")?.cloned().unwrap_or(Value::Null), "sel": {"k": "gids", "gids": gids}, "agg": agg.cloned().unwrap_or(Value::Null), "value": value,
            "key": "", "window": {"k": "lifetime"}, "scope": {"k": "session"}, "cap": cap, "onExceed": jget(bv, "onExceed")?.cloned().unwrap_or(Value::Null)}));
    }
    let od = ontology_digest(o)?;
    let nl = super::digests::nl_digest(jget(Some(opts), "nl")?.ok_or("opts.nl is required")?)?;
    let sources = match jget(Some(opts), "sources")? {
        None | Some(Value::Null) => vec![],
        s => seq(s)?.to_vec(),
    };
    let mut g = Map::new();
    g.insert("v".into(), json!(1));
    if let Some(p) = jget(Some(opts), "principal")? {
        g.insert("principal".into(), p.clone());
    }
    g.insert("ontDigest".into(), json!(od));
    g.insert("nlDigest".into(), json!(nl));
    g.insert("sources".into(), Value::Array(sources));
    g.insert("grants".into(), Value::Array(grants));
    g.insert("prohibits".into(), Value::Array(prohibits));
    g.insert("bounds".into(), Value::Array(bounds));
    g.insert("validity".into(), json!({"notBefore": 0, "notAfter": FOREVER, "maxIdle": 0}));
    g.insert("deleg".into(), json!({"maxDepth": 0, "narrowOnly": true, "mayTouch": []}));
    g.insert("escalateOn".into(), json!([]));
    g.insert("wildcardAck".into(), json!([]));
    g.insert("holes".into(), Value::Array(holes));
    canonicalize_goal(&Value::Object(g))
}

// ---- locale-aware human number parsing (interpreter front end only; the IR has no locale)
fn digits_only(t: &str) -> bool {
    let mut cs = t.chars();
    matches!(cs.next(), Some(c) if c.is_ascii_digit()) && cs.all(|c| c.is_ascii_digit() || c == '.' || c == ',')
}
/// `{ok: true, minor}` or `{ok: false, reason}`. "1,000.50", "1.000,50", "$20", "20 dollars"; ambiguous literals ("1,000" with no
/// locale hint, "1.000") are NOT guessed: they fail and become a Hole. `locale` "en" reads ',' as thousands, "de" reads '.'.
pub fn parse_human_amount(text: &str, exponent: i64, locale: Option<&str>) -> Value {
    let fail = |r: &str| json!({"ok": false, "reason": r});
    let normalized: String = text.nfkc().collect();
    let t: String = js_trim(&normalized).chars().filter(|c| c.is_ascii_digit() || *c == '.' || *c == ',').collect();
    if !digits_only(&t) || t.contains("..") || t.contains(",,") || t.contains(".,") || t.contains(",.") {
        return fail("not a number");
    }
    let (last_dot, last_comma) = (t.rfind('.'), t.rfind(','));
    let (mut dec, mut thou): (Option<char>, Option<char>) = (None, None);
    match (last_dot, last_comma) {
        (Some(d), Some(c)) => {
            dec = Some(if d > c { '.' } else { ',' });
            thou = Some(if d > c { ',' } else { '.' });
        }
        (Some(_), None) | (None, Some(_)) => {
            let sep = if last_dot.is_some() { '.' } else { ',' };
            let parts: Vec<&str> = t.split(sep).collect();
            let group_like = parts.len() > 2 || parts[parts.len() - 1].len() == 3;
            if !group_like {
                dec = Some(sep);
            } else if parts.len() > 2 {
                thou = Some(sep);
            } else if let Some(l) = locale.filter(|l| !l.is_empty()) {
                if (l == "en") == (sep == ',') {
                    thou = Some(sep);
                } else {
                    dec = Some(sep);
                }
            } else {
                return fail("ambiguous separator");
            }
        }
        (None, None) => {}
    }
    let (mut int_part, mut frac) = (t.clone(), String::new());
    if let Some(d) = dec {
        let i = t.rfind(d).unwrap();
        int_part = t[..i].to_string();
        frac = t[i + 1..].to_string();
    }
    if let Some(th) = thou {
        let groups: Vec<&str> = int_part.split(th).collect();
        if groups[1..].iter().any(|g| g.len() != 3) || groups[0].is_empty() || groups[0].len() > 3 {
            return fail("malformed grouping");
        }
        int_part = groups.concat();
    }
    if (frac.len() as i64) > exponent {
        return fail("more decimals than the currency allows");
    }
    let mut digits = int_part;
    digits.push_str(&frac);
    for _ in 0..(exponent - frac.len() as i64).max(0) {
        digits.push('0');
    }
    match digits.parse::<u128>() {
        Ok(m) if m <= FOREVER as u128 => json!({"ok": true, "minor": m as i64}),
        _ => fail("out of range"),
    }
}
/// The strict front-end contract over [`parse_human_amount`]: only digits, `.` and `,` after one optional leading currency symbol;
/// with a locale, a contradicting decimal separator is refused; without one, a repeated or ambiguous separator is a Hole.
pub fn parse_money(text: &str, exponent: i64, locale: Option<&str>) -> Value {
    let s = js_trim(text);
    let t = match s.chars().next() {
        Some('$') | Some('€') | Some('£') => s[s.chars().next().unwrap().len_utf8()..].trim_start_matches(|c: char| JS_WS.contains(c)),
        _ => s,
    };
    if !digits_only(t) {
        return json!({"error": "BAD_NUMBER"});
    }
    let both = t.contains('.') && t.contains(',');
    if let Some(l) = locale {
        let last = t.rfind(|c| c == '.' || c == ',').map(|i| t.as_bytes()[i] as char).unwrap_or('.');
        if both && last != (if l == "en" { '.' } else { ',' }) {
            return json!({"error": "BAD_NUMBER"});
        }
    }
    if locale.is_none() && !both && t.chars().filter(|c| *c == '.' || *c == ',').count() > 1 {
        return json!({"hole": "AMBIGUOUS_NUMBER"});
    }
    let r = parse_human_amount(t, exponent, locale);
    if r["ok"] == true {
        json!({"minor": r["minor"]})
    } else if r["reason"] == "ambiguous separator" {
        json!({"hole": "AMBIGUOUS_NUMBER"})
    } else {
        json!({"error": "BAD_NUMBER"})
    }
}
