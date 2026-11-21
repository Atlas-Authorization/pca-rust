//! The deterministic suggestion layer (native port of the reference's import/suggest.ts and import/rules.ts). A versioned rule set
//! proposes traits, param roles and param tags for a draft def. Union only: a suggestion can ADD a trait, a role (to a param that has
//! none) or a tag, never remove or replace anything, and it never marks a def confirmed. A suggested def is still `pca.unreviewed` for
//! floor purposes; suggestions only improve the card and the review queue. `path_re` is a JavaScript regular expression (see `jsre`).

use super::common::{g, gstr, js_str, jtruthy, kerr, s, svec, tokens_of, type_err, uniq_strs, R};
use super::jsre::{compile_js, js_test};
use super::rules_data::default_rules_value;
use crate::actions::{utf16_len, Registry};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

pub const SUGGEST_RULES_KIND: &str = "pca-suggest-rules";
pub const SUGGEST_RULES_DOMAIN: &str = "atlas-pca/suggest-rules/v1";
const MATCH_KEYS: [&str; 10] =
    ["methods", "path_re", "name_tokens", "name_tokens_strict", "param_names", "param_names_all", "param_types", "param_formats", "roles", "effects"];
const PARAM_TYPES: [&str; 9] = ["string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref"];
const PARAM_TAGS: [&str; 9] = ["pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql"];
const CORE_ROLES: [&str; 26] = [
    "money.amount",
    "money.currency",
    "money.fee",
    "party.payee",
    "party.payer",
    "contact.email",
    "contact.phone",
    "contact.address",
    "person.name",
    "person.dob",
    "person.national_id",
    "credential.secret",
    "credential.token",
    "credential.key",
    "path.fs",
    "query.sql",
    "query.search",
    "code.source",
    "code.command",
    "url.target",
    "text.message",
    "text.public",
    "time.not_before",
    "time.not_after",
    "count.limit",
    "bytes.size",
];
pub const MAX_RULES: usize = 1024;
pub const MAX_LIST: usize = 64;

// a group that holds a quantifier or an alternation, followed by another quantifier: the shapes that backtrack exponentially
static NESTED_QUANTIFIER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\([^)]*[+*][^)]*\)[+*{]|\([^)]*\|[^)]*\)[+*{]").expect("static regex"));
static BACKREF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\\[1-9]").expect("static regex"));
static LOOKAROUND: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\(\?[<=!]").expect("static regex"));

// ---- private helpers ------------------------------------------------------------------------------------------------------

fn lcd(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'
}
fn is_trait_id(t: &str) -> bool {
    match t.split_once('.') {
        Some((a, b)) => {
            let ok = |x: &str, max: usize| !x.is_empty() && x.len() <= max && x.as_bytes()[0].is_ascii_lowercase() && x.bytes().all(lcd);
            ok(a, 32) && ok(b, 64)
        }
        None => false,
    }
}
fn lcd_parts(t: &str, min: usize, max: usize) -> bool {
    let p: Vec<&str> = t.split('.').collect();
    p.len() >= min && p.len() <= max && p.iter().all(|x| !x.is_empty() && x.bytes().all(lcd))
}
fn is_role(r: &str) -> bool {
    CORE_ROLES.contains(&r) || r.strip_prefix("id.").is_some_and(|x| lcd_parts(x, 1, 4)) || r.strip_prefix("x.").is_some_and(|x| lcd_parts(x, 2, 4))
}
fn sort_u16(mut v: Vec<String>) -> Vec<String> {
    v.sort_by_key(|x| x.encode_utf16().collect::<Vec<u16>>());
    v
}
fn uniq_sorted(xs: impl IntoIterator<Item = String>) -> Vec<String> {
    sort_u16(uniq_strs(xs))
}
/// The string members of an array value (anything else: none).
fn arr_strs(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}
fn tr(v: Option<&Value>) -> Option<&Value> {
    v.filter(|x| jtruthy(Some(*x)))
}
fn obj_of(v: Option<&Value>) -> Map<String, Value> {
    v.and_then(Value::as_object).cloned().unwrap_or_default()
}
fn is_one(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Number(n)) if n.as_f64() == Some(1.0))
}
fn is_str_list(v: Option<&Value>, mx: usize) -> bool {
    match v.and_then(Value::as_array) {
        Some(a) => !a.is_empty() && a.len() <= mx && a.iter().all(|x| x.as_str().is_some_and(|t| (1..=64).contains(&utf16_len(t)))),
        None => false,
    }
}
fn is_semver(v: &str) -> bool {
    let p: Vec<&str> = v.split('.').collect();
    p.len() == 3 && p.iter().all(|x| !x.is_empty() && x.bytes().all(|c| c.is_ascii_digit()))
}
fn is_rule_id(v: &str) -> bool {
    v.strip_prefix("SR-").is_some_and(|d| (3..=4).contains(&d.len()) && d.bytes().all(|c| c.is_ascii_digit()))
}
fn req<'a>(o: &'a Value, k: &str) -> R<&'a Value> {
    g(o, k).ok_or_else(|| type_err(format!("Cannot read properties of undefined (reading '{k}')")))
}
fn req_s(o: &Value, k: &str) -> R<String> {
    Ok(js_str(req(o, k)?))
}

// ---- rule set validation, digest, signature ---------------------------------------------------------------------------------

/// `None` if the rule set is well formed: closed members, unique ids, safe regular expressions, known trait/role/tag names.
pub fn suggest_rules_error(r: &Value, known: Option<&HashSet<String>>) -> Option<String> {
    let Some(ro) = r.as_object() else {
        return Some("rules must be an object".into());
    };
    for k in ro.keys() {
        if !["v", "kind", "version", "rules", "digest", "sig"].contains(&k.as_str()) {
            return Some(format!("unknown member '{k}'"));
        }
    }
    if !is_one(ro.get("v")) || ro.get("kind").and_then(Value::as_str) != Some(SUGGEST_RULES_KIND) {
        return Some("not a suggest-rules document (v 1)".into());
    }
    if !ro.get("version").and_then(Value::as_str).is_some_and(is_semver) {
        return Some("version must be semver".into());
    }
    let rules = match ro.get("rules").and_then(Value::as_array) {
        Some(a) if !a.is_empty() && a.len() <= MAX_RULES => a,
        _ => return Some(format!("rules must be 1..{MAX_RULES} entries")),
    };
    let mut ids: HashSet<String> = HashSet::new();
    for rule in rules {
        let Some(rm) = rule.as_object() else {
            return Some("a rule must be an object".into());
        };
        for k in rm.keys() {
            if !["id", "match", "adds", "note"].contains(&k.as_str()) {
                return Some(format!("rule: unknown member '{k}'"));
            }
        }
        let rid = match rm.get("id").and_then(Value::as_str) {
            Some(x) if is_rule_id(x) && !ids.contains(x) => x.to_string(),
            _ => return Some("rule ids must be unique SR-nnn".into()),
        };
        ids.insert(rid.clone());
        let w = &rid;
        match rm.get("note").and_then(Value::as_str) {
            Some(n) if (1..=200).contains(&utf16_len(n)) => {}
            _ => return Some(format!("{w}: note must be 1..200 characters")),
        }
        let m = match rm.get("match").and_then(Value::as_object) {
            Some(m) if !m.is_empty() => m,
            _ => return Some(format!("{w}: match must be a non-empty object")),
        };
        for k in m.keys() {
            if !MATCH_KEYS.contains(&k.as_str()) {
                return Some(format!("{w}: unknown match member '{k}'"));
            }
        }
        for k in ["methods", "name_tokens", "name_tokens_strict", "param_names", "param_names_all", "param_formats", "roles"] {
            if m.contains_key(k) && !is_str_list(m.get(k), MAX_LIST) {
                return Some(format!("{w}: match.{k} must be 1..{MAX_LIST} short strings"));
            }
        }
        if m.contains_key("methods") && !arr_strs(m.get("methods")).iter().all(|x| *x == x.to_uppercase()) {
            return Some(format!("{w}: methods are uppercase"));
        }
        if m.contains_key("param_types")
            && (!is_str_list(m.get("param_types"), MAX_LIST) || !arr_strs(m.get("param_types")).iter().all(|t| PARAM_TYPES.contains(&t.as_str())))
        {
            return Some(format!("{w}: match.param_types is not a list of param types"));
        }
        if m.contains_key("effects") && !is_str_list(m.get("effects"), 12) {
            return Some(format!("{w}: match.effects must be a list of effects"));
        }
        if let Some(pv) = m.get("path_re") {
            let p = match pv.as_str() {
                Some(p) if (1..=128).contains(&utf16_len(p)) => p,
                _ => return Some(format!("{w}: path_re must be 1..128 characters")),
            };
            if NESTED_QUANTIFIER.is_match(p) || BACKREF.is_match(p) || LOOKAROUND.is_match(p) {
                return Some(format!("{w}: path_re uses a construct outside the bounded subset (nested quantifiers, backreferences, lookaround)"));
            }
            if compile_js(p).is_err() {
                return Some(format!("{w}: path_re is not a regular expression"));
            }
        }
        let has_param = m.contains_key("param_names") || m.contains_key("param_names_all") || m.contains_key("param_formats") || m.contains_key("roles");
        if m.contains_key("param_types") && !m.contains_key("param_names") && !m.contains_key("param_formats") && !m.contains_key("param_names_all") {
            return Some(format!("{w}: param_types needs param_names, param_names_all or param_formats"));
        }
        if !is_str_list(rm.get("adds"), 16) {
            return Some(format!("{w}: adds must be 1..16 entries"));
        }
        for a in arr_strs(rm.get("adds")) {
            if let Some(tag) = a.strip_prefix("tag:") {
                if !PARAM_TAGS.contains(&tag) {
                    return Some(format!("{w}: unknown tag '{a}'"));
                }
                if !has_param {
                    return Some(format!("{w}: a tag needs a param matcher"));
                }
            } else if is_role(&a) {
                if !has_param {
                    return Some(format!("{w}: a role needs a param matcher"));
                }
            } else if is_trait_id(&a) {
                if known.is_some_and(|k| !k.contains(&a)) {
                    return Some(format!("{w}: unknown trait '{a}'"));
                }
            } else {
                return Some(format!("{w}: '{a}' is not a trait, role or tag:"));
            }
        }
    }
    None
}

/// b64u sha256 of the strict canonical rule set (without digest and sig).
pub fn rules_digest(r: &Value) -> R<String> {
    let body = json!({"v": req(r, "v")?, "kind": req(r, "kind")?, "version": req(r, "version")?, "rules": req(r, "rules")?});
    crate::hash_canonical_strict(&json!({"d": SUGGEST_RULES_DOMAIN, "rules": body}))
        .ok_or_else(|| kerr("bad_rules", "the rule set is outside the strict JSON profile"))
}

pub fn seal_rules(r: &Value) -> R<Value> {
    let mut m = r.as_object().cloned().ok_or_else(|| type_err("Cannot convert undefined or null to object"))?;
    m.insert("digest".into(), s(&rules_digest(r)?));
    Ok(Value::Object(m))
}

fn rules_message(digest: &str) -> R<Vec<u8>> {
    let mut msg = format!("{SUGGEST_RULES_DOMAIN}\0").into_bytes();
    msg.extend_from_slice(crate::canonicalize_strict(&json!({"digest": digest})).map_err(|e| kerr("bad_rules", e))?.as_bytes());
    Ok(msg)
}

/// Sign a rule set as the rules publisher (a release step; the signature covers the digest).
pub fn sign_rules(rules: &Value, kid: &str, seed: &[u8; 32]) -> R<Value> {
    if let Some(bad) = suggest_rules_error(rules, None) {
        return Err(kerr("bad_rules", bad));
    }
    let mut sealed = seal_rules(rules)?;
    let digest = gstr(&sealed, "digest").unwrap_or("").to_string();
    let sig = crate::agent::KeyPair::from_seed(seed).sign(&rules_message(&digest)?);
    if let Value::Object(m) = &mut sealed {
        m.insert("sig".into(), json!({"alg": "ed25519", "kid": kid, "value": crate::b64_encode(&sig)}));
    }
    Ok(sealed)
}

/// Verify a signed rule set against pinned publisher keys: shape, digest, signature. Never fails: a problem is `{ok:false, reason}`.
pub fn verify_rules(doc: &Value, pins: &Value) -> Value {
    let no = |reason: String| json!({"ok": false, "reason": reason});
    if let Some(bad) = suggest_rules_error(doc, None) {
        return no(bad);
    }
    let want = match rules_digest(doc) {
        Ok(d) => d,
        Err(e) => return no(format!("rules verification error: {}", e.message)),
    };
    if gstr(doc, "digest") != Some(want.as_str()) {
        return no("digest does not match the rules".into());
    }
    let sig = g(doc, "sig");
    if !jtruthy(sig) {
        return no("the rule set is not signed".into());
    }
    let kid = sig.and_then(|x| g(x, "kid"));
    let Some(pl) = pins.as_array() else {
        return no("rules verification error: pins is not iterable".into());
    };
    let pinned = pl.iter().find(|p| p.is_object() && kid.is_some() && g(p, "kid") == kid);
    let Some(k) = pinned else {
        return no(format!("no pinned rules key '{}'", kid.map_or_else(|| "undefined".to_string(), js_str)));
    };
    let value = sig.and_then(|x| g(x, "value"));
    let msg = match rules_message(&want) {
        Ok(m) => m,
        Err(e) => return no(format!("rules verification error: {}", e.message)),
    };
    match (gstr(k, "pk"), value.and_then(Value::as_str)) {
        (Some(pk), Some(v)) if crate::verify_b64u(pk, &msg, v) => json!({"ok": true}),
        _ => no("rules signature invalid".into()),
    }
}

// ---- facts ----------------------------------------------------------------------------------------------------------------

/// Light stemmer: plural, -ing, -ed and a trailing -e fold together (`charges`, `charged`, `charging` -> `charg`).
pub fn stem(t: &str) -> String {
    let mut x = t.to_string();
    let n = |x: &str| x.chars().count();
    let cut = |x: &mut String, k: usize| {
        let keep = x.chars().count() - k;
        *x = x.chars().take(keep).collect();
    };
    if n(&x) > 4 && x.ends_with("ies") {
        cut(&mut x, 3);
        x.push('y');
    } else if n(&x) > 4 && ["ss", "x", "z", "ch", "sh"].iter().any(|p| x.ends_with(&format!("{p}es"))) {
        cut(&mut x, 2);
    } else if n(&x) > 3 && x.ends_with('s') && !x.ends_with("ss") {
        cut(&mut x, 1);
    }
    if n(&x) > 5 && x.ends_with("ing") {
        cut(&mut x, 3);
    } else if n(&x) > 4 && x.ends_with("ed") {
        cut(&mut x, 2);
    }
    if n(&x) > 3 && x.ends_with('e') {
        cut(&mut x, 1);
    }
    x
}

const SEP: &str = "|";

fn path_tokens(p: &str) -> Vec<String> {
    p.split('/').filter(|x| !x.is_empty() && !x.contains('{') && !x.contains('}')).flat_map(tokens_of).collect()
}

fn u16_slice(t: &str, n: usize) -> String {
    let u: Vec<u16> = t.encode_utf16().take(n).collect();
    String::from_utf16_lossy(&u)
}

#[derive(Debug, Clone)]
pub struct FactParam {
    pub name: String,
    pub tokens: Vec<String>,
    pub typ: String,
    pub format: Option<String>,
    pub role: Option<String>,
}

/// What the rules see of a def.
#[derive(Debug, Clone)]
pub struct Facts {
    pub methods: Vec<String>,
    pub locs: Vec<String>,
    pub tokens: Vec<String>,
    pub strict: Vec<String>,
    pub params: Vec<FactParam>,
    pub effects: Vec<String>,
}

impl Facts {
    pub fn to_json(&self) -> Value {
        let params: Vec<Value> = self
            .params
            .iter()
            .map(|p| {
                let mut m = Map::new();
                m.insert("name".into(), s(&p.name));
                m.insert("tokens".into(), svec(&p.tokens));
                m.insert("type".into(), s(&p.typ));
                if let Some(f) = &p.format {
                    m.insert("format".into(), s(f));
                }
                if let Some(r) = &p.role {
                    m.insert("role".into(), s(r));
                }
                Value::Object(m)
            })
            .collect();
        json!({"methods": svec(&self.methods), "locs": svec(&self.locs), "tokens": svec(&self.tokens), "strict": svec(&self.strict), "params": params, "effects": svec(&self.effects)})
    }
}

fn add_method(methods: &mut Vec<String>, m: String) {
    let u = m.to_uppercase();
    if !methods.contains(&u) {
        methods.push(u);
    }
}

pub fn facts_of(d: &Value) -> R<Facts> {
    let b = g(d, "bindings");
    let bind = |k: &str| tr(b.and_then(|x| g(x, k)));
    let mut methods: Vec<String> = vec![];
    let mut locs: Vec<String> = vec![];
    let mut src: Vec<Vec<String>> = vec![];
    let mut path_src: HashSet<usize> = HashSet::new();
    let verb = req_s(d, "verb")?;
    src.push(verb.split('.').skip(1).flat_map(tokens_of).collect());
    for a in d.get("aliases").and_then(Value::as_array).map(|a| a.as_slice()).unwrap_or(&[]) {
        src.push(tokens_of(&js_str(a)));
    }
    src.push(tokens_of(&req_s(d, "title")?));
    if let Some(o) = bind("openapi") {
        src.push(tokens_of(&req_s(o, "operationId")?));
        if let Some(m) = tr(g(o, "method")) {
            add_method(&mut methods, js_str(m));
        }
        if let Some(p) = tr(g(o, "path")) {
            let p = js_str(p);
            locs.push(p.clone());
            path_src.insert(src.len());
            src.push(path_tokens(&p));
        }
    }
    if let Some(h) = bind("http") {
        add_method(&mut methods, req_s(h, "method")?);
        let p = req_s(h, "path")?;
        locs.push(p.clone());
        path_src.insert(src.len());
        src.push(path_tokens(&p));
    }
    if let Some(m) = bind("mcp") {
        let t = req_s(m, "tool")?;
        locs.push(t.clone());
        src.push(tokens_of(&t));
    }
    if let Some(q) = bind("graphql") {
        add_method(&mut methods, req_s(q, "op")?);
        let f = req_s(q, "field")?;
        locs.push(f.clone());
        src.push(tokens_of(&f));
    }
    if let Some(r) = bind("grpc") {
        let (sv, me) = (req_s(r, "service")?, req_s(r, "method")?);
        locs.push(format!("{sv}/{me}"));
        src.push(tokens_of(&sv));
        src.push(tokens_of(&me));
    }
    if let Some(a) = bind("asyncapi") {
        add_method(&mut methods, req_s(a, "op")?);
        let c = req_s(a, "channel")?;
        locs.push(c.clone());
        src.push(tokens_of(&c));
    }
    let mut tokens: Vec<String> = vec![];
    let mut strict: Vec<String> = vec![];
    for (i, sx) in src.iter().enumerate() {
        if !tokens.is_empty() {
            tokens.push(SEP.into());
        }
        tokens.extend(sx.iter().map(|x| stem(x)));
        if !path_src.contains(&i) {
            if !strict.is_empty() {
                strict.push(SEP.into());
            }
            strict.extend(sx.iter().map(|x| stem(x)));
        }
    }
    let pm = g(d, "params").and_then(Value::as_object).ok_or_else(|| type_err("Cannot convert undefined or null to object"))?;
    let mut names: Vec<&String> = pm.keys().collect();
    names.sort_by_key(|x| x.encode_utf16().collect::<Vec<u16>>());
    let mut params = vec![];
    for name in names {
        let p = &pm[name];
        let truthy_str = |k: &str| tr(g(p, k)).map(js_str);
        params.push(FactParam {
            name: name.clone(),
            tokens: tokens_of(name).iter().map(|x| stem(x)).collect(),
            typ: req_s(p, "type")?,
            format: truthy_str("format"),
            role: truthy_str("role"),
        });
    }
    let locs = locs.iter().map(|x| u16_slice(x, 512)).collect();
    let effects = uniq_strs(arr_strs(g(d, "effects")));
    Ok(Facts { methods, locs, tokens, strict, params, effects })
}

// ---- matching -------------------------------------------------------------------------------------------------------------

fn has_seq(hay: &[String], pat: &[String]) -> bool {
    !pat.is_empty() && hay.windows(pat.len()).any(|w| w == pat)
}

fn pat_of(t: &str) -> Vec<String> {
    tokens_of(t).iter().map(|x| stem(x)).collect()
}

fn empty_suggestion() -> Value {
    json!({"traits": [], "roles": {}, "tags": {}, "fired": []})
}

/// The empty suggestion (what `suggest_with_models` starts from).
pub fn empty_suggestion_value() -> Value {
    empty_suggestion()
}

fn role_fits(role: &str, typ: &str) -> bool {
    if ["money.amount", "money.fee", "count.limit", "bytes.size"].contains(&role) {
        return typ == "integer";
    }
    if role.starts_with("time.") {
        return ["date", "datetime", "integer"].contains(&typ);
    }
    typ == "string"
}

/// Run the rules over a def. Only trait ids in `registry` (when given) can be suggested. Pure and deterministic.
pub fn suggest_with_rules(d: &Value, rules: &Value, registry: Option<&Registry>) -> R<Value> {
    let f = facts_of(d)?;
    let mut traits: Vec<String> = vec![];
    let mut roles = Map::new();
    let mut tags: HashMap<String, Vec<String>> = HashMap::new();
    let mut fired: Vec<Value> = vec![];
    let list = req(rules, "rules")?.as_array().ok_or_else(|| type_err("rules.rules is not iterable"))?;
    for rule in list {
        let m = req(rule, "match")?;
        let ml = |k: &str| arr_strs(g(m, k));
        let on = |k: &str| jtruthy(g(m, k));
        if on("methods") && !ml("methods").iter().any(|x| f.methods.contains(x)) {
            continue;
        }
        if on("effects") && !ml("effects").iter().any(|e| f.effects.contains(e)) {
            continue;
        }
        if on("name_tokens") && !ml("name_tokens").iter().any(|p| has_seq(&f.tokens, &pat_of(p))) {
            continue;
        }
        if on("name_tokens_strict") && !ml("name_tokens_strict").iter().any(|p| has_seq(&f.strict, &pat_of(p))) {
            continue;
        }
        if on("path_re") {
            let rx = compile_js(&js_str(req(m, "path_re")?)).map_err(type_err)?;
            if !f.locs.iter().any(|loc| js_test(&rx, loc)) {
                continue;
            }
        }
        if on("roles") && !ml("roles").iter().any(|r| f.params.iter().any(|p| p.role.as_ref() == Some(r))) {
            continue;
        }
        let ptypes = ml("param_types");
        let mut matched: Vec<&FactParam> = vec![];
        if g(m, "param_names").is_some_and(|x| !x.is_null()) || g(m, "param_formats").is_some_and(|x| !x.is_null()) {
            let pats: Vec<Vec<String>> = ml("param_names").iter().map(|x| pat_of(x)).collect();
            let formats = ml("param_formats");
            for p in &f.params {
                if on("param_types") && !ptypes.contains(&p.typ) {
                    continue;
                }
                if on("param_names") && !pats.iter().any(|q| has_seq(&p.tokens, q)) {
                    continue;
                }
                if on("param_formats") && !p.format.as_ref().is_some_and(|x| formats.contains(x)) {
                    continue;
                }
                matched.push(p);
            }
            if matched.is_empty() {
                continue;
            }
        }
        if on("param_names_all") {
            let ok = ml("param_names_all").iter().all(|n| {
                let q = pat_of(n);
                f.params.iter().any(|p| has_seq(&p.tokens, &q) && (!on("param_types") || ptypes.contains(&p.typ) || p.typ == "string"))
            });
            if !ok {
                continue;
            }
        }
        fired.push(req(rule, "id")?.clone());
        for a in arr_strs(g(rule, "adds")) {
            if let Some(tag) = a.strip_prefix("tag:") {
                for p in &matched {
                    let e = tags.entry(p.name.clone()).or_default();
                    if !e.iter().any(|x| x == tag) {
                        e.push(tag.to_string());
                    }
                }
            } else if !is_role(&a) {
                if registry.map_or(true, |r| r.traits.contains_key(&a)) && !traits.contains(&a) {
                    traits.push(a);
                }
            } else {
                for p in &matched {
                    if p.role.is_none() && !roles.contains_key(&p.name) && role_fits(&a, &p.typ) {
                        roles.insert(p.name.clone(), s(&a));
                    }
                }
            }
        }
    }
    traits.retain(|t| t != "pca.unreviewed");
    let keys = sort_u16(tags.keys().cloned().collect());
    let mut tmap = Map::new();
    for k in keys {
        let v = sort_u16(tags[&k].clone());
        tmap.insert(k, svec(&v));
    }
    Ok(json!({"traits": svec(&sort_u16(traits)), "roles": Value::Object(roles), "tags": Value::Object(tmap), "fired": fired}))
}

/// Union two suggestions (the restrictive direction, so no intersection is needed).
pub fn union_suggestions(a: &Value, b: &Value) -> Value {
    let (at, bt) = (obj_of(g(a, "tags")), obj_of(g(b, "tags")));
    let mut keys: Vec<String> = at.keys().cloned().collect();
    keys.extend(bt.keys().cloned());
    let mut tags = Map::new();
    for k in uniq_strs(keys) {
        let mut v = arr_strs(at.get(&k));
        v.extend(arr_strs(bt.get(&k)));
        tags.insert(k, svec(&uniq_sorted(v)));
    }
    let mut ts = arr_strs(g(a, "traits"));
    ts.extend(arr_strs(g(b, "traits")));
    let mut roles = obj_of(g(b, "roles"));
    for (k, v) in obj_of(g(a, "roles")) {
        roles.insert(k, v);
    }
    let mut fired = g(a, "fired").and_then(Value::as_array).cloned().unwrap_or_default();
    fired.extend(g(b, "fired").and_then(Value::as_array).cloned().unwrap_or_default());
    json!({"traits": svec(&uniq_sorted(ts)), "roles": Value::Object(roles), "tags": Value::Object(tags), "fired": fired})
}

/// Apply a suggestion to a def. UNION ONLY: traits are added, a role is set only on a param without one, tags are added; nothing is
/// removed or replaced, no attestation is created, and `review.state` goes from `unreviewed` to `suggested`.
pub fn apply_suggestion(d: &Value, sg: &Value, by: &Value) -> R<Value> {
    let dm = d.as_object().ok_or_else(|| type_err("def is not an object"))?;
    let (s_roles, s_tags, s_traits) = (obj_of(g(sg, "roles")), obj_of(g(sg, "tags")), arr_strs(g(sg, "traits")));
    let mut params = Map::new();
    let mut added_roles = Map::new();
    let mut added_tags: Vec<(String, Vec<String>)> = vec![];
    let pm = g(d, "params").and_then(Value::as_object).ok_or_else(|| type_err("Cannot convert undefined or null to object"))?;
    for (name, p) in pm {
        let mut q = obj_of(Some(p));
        let typ = gstr(p, "type").unwrap_or("");
        if let Some(role) = s_roles.get(name).and_then(Value::as_str) {
            if g(p, "role").is_none() && role_fits(role, typ) {
                q.insert("role".into(), s(role));
                added_roles.insert(name.clone(), s(role));
            }
        }
        if let Some(t) = s_tags.get(name) {
            let have = arr_strs(g(p, "tags"));
            let fresh: Vec<String> = arr_strs(Some(t)).into_iter().filter(|x| !have.contains(x)).collect();
            if !fresh.is_empty() {
                let mut all = have.clone();
                all.extend(fresh.iter().cloned());
                q.insert("tags".into(), svec(&uniq_sorted(all)));
                added_tags.push((name.clone(), fresh));
            }
        }
        params.insert(name.clone(), Value::Object(q));
    }
    let d_traits = arr_strs(g(d, "traits"));
    let fresh_traits: Vec<String> = s_traits.iter().filter(|t| !d_traits.contains(t)).cloned().collect();
    // a money-moving action must be safe to repeat (lint LD-004): add the optional idempotency key the pack generator adds
    let mut idem = g(d, "idempotency").filter(|x| !x.is_null()).cloned();
    if s_traits.iter().any(|t| t == "pca.money_moving")
        && match &idem {
            None => true,
            Some(v) => gstr(v, "mode") == Some("none"),
        }
    {
        idem = Some(json!({"mode": "key_param", "param": "idempotency_key"}));
        if !params.contains_key("idempotency_key") {
            params.insert("idempotency_key".into(), json!({"type": "string", "max_len": 64, "required": false}));
        }
    }
    let review = obj_of(Some(req(d, "review")?));
    let prev = obj_of(review.get("suggested_by"));
    let prev_added = obj_of(prev.get("added").filter(|x| x.as_object().is_some_and(|m| !m.is_empty())));
    let mut at = arr_strs(prev_added.get("traits"));
    at.extend(fresh_traits.iter().cloned());
    let mut added_roles_all = obj_of(prev_added.get("roles"));
    for (k, v) in &added_roles {
        added_roles_all.insert(k.clone(), v.clone());
    }
    let prev_tags = obj_of(prev_added.get("tags"));
    let mut tkeys: Vec<String> = prev_tags.keys().cloned().collect();
    tkeys.extend(added_tags.iter().map(|(k, _)| k.clone()));
    let mut added_tag_map = Map::new();
    for k in uniq_sorted(tkeys) {
        let mut v = arr_strs(prev_tags.get(&k));
        for (n, t) in &added_tags {
            if *n == k {
                v.extend(t.iter().cloned());
            }
        }
        added_tag_map.insert(k, svec(&uniq_sorted(v)));
    }
    let added = json!({"traits": svec(&uniq_sorted(at)), "roles": Value::Object(added_roles_all), "tags": Value::Object(added_tag_map)});
    let rules = [g(by, "rules"), prev.get("rules")].into_iter().find(|x| jtruthy(*x)).flatten();
    let mut models: Vec<Value> = prev.get("models").and_then(Value::as_array).cloned().unwrap_or_default();
    models.extend(g(by, "models").and_then(Value::as_array).cloned().unwrap_or_default());
    let mut sb = Map::new();
    if let Some(r) = rules {
        sb.insert("rules".into(), r.clone());
    }
    if !models.is_empty() {
        sb.insert("models".into(), Value::Array(models));
    }
    sb.insert("added".into(), added);
    let cur_state = review.get("state").cloned().unwrap_or(Value::Null);
    let state = if matches!(cur_state.as_str(), Some("unreviewed") | Some("suggested")) { s("suggested") } else { cur_state };
    let mut out = dm.clone();
    out.insert("params".into(), Value::Object(params));
    if let Some(i) = idem {
        out.insert("idempotency".into(), i);
    }
    if !fresh_traits.is_empty() || !d_traits.is_empty() {
        let mut all = d_traits.clone();
        all.extend(s_traits.iter().cloned());
        out.insert("traits".into(), svec(&uniq_sorted(all)));
    }
    let mut rv = review;
    rv.insert("state".into(), state);
    rv.insert("suggested_by".into(), Value::Object(sb));
    out.insert("review".into(), Value::Object(rv));
    Ok(Value::Object(out))
}

/// The shipped default rule set.
pub fn default_rules() -> Value {
    default_rules_value().clone()
}

pub fn default_rules_sealed() -> Value {
    seal_rules(default_rules_value()).expect("the shipped rules are well formed")
}
