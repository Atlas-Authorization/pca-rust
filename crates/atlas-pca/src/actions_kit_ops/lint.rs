//! The 24 stable lint rules over action definitions, SARIF output and the digest of the rule list (lint.ts). Pure: defs in,
//! findings out, deterministic order. A def that fails `validate_def` is reported as LD-000 and not linted further.

use super::effective::{effective_with, prules_violations};
use super::undo::{compensation_shape, may_be_reversible};
use super::{js_opt, js_str, js_trim, strs_of, u16cmp, utf16_len, Verifier};
use crate::actions::{
    core_registry, def_digest, extend_registry, is_context_key, is_read_only, normalize, traits_digest, validate_def, Registry, CONTEXT_KEYS,
};
use crate::hash_canonical_strict;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub const LINT_RULES: [(&str, &str, &str); 24] = [
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
const NOTE_RULE: (&str, &str, &str) = ("LN-001", "note", "an informational note from the loader");
const STRUCTURE_RULE: (&str, &str, &str) = ("LD-000", "error", "the def is not well formed and cannot be loaded");
const LINT_RULES_DIGEST_DOMAIN: &str = "atlas-pca/action-lint-rules/v1";

const EFFECTS: [&str; 12] = ["read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign"];
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
const PARAM_FORMATS: [&str; 11] = ["email", "url", "uri_https", "uuid", "iban", "phone_e164", "cidr", "iso_country", "iso_currency", "semver", "sha256"];

fn lcd(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'
}
fn lcd_parts(s: &str, min: usize, max: usize) -> bool {
    let p: Vec<&str> = s.split('.').collect();
    p.len() >= min && p.len() <= max && p.iter().all(|x| !x.is_empty() && x.bytes().all(lcd))
}
fn is_role(r: &Value) -> bool {
    r.as_str().is_some_and(|r| {
        CORE_ROLES.contains(&r) || r.strip_prefix("id.").is_some_and(|x| lcd_parts(x, 1, 4)) || r.strip_prefix("x.").is_some_and(|x| lcd_parts(x, 2, 4))
    })
}
fn is_format(f: &Value) -> bool {
    f.as_str().is_some_and(|f| PARAM_FORMATS.contains(&f) || f.strip_prefix("id:").is_some_and(|x| lcd_parts(x, 1, 4)))
}

/// The digest policy-ci pins: the ordered (id, severity, title) list.
pub fn lint_rules_digest() -> String {
    let rows: Vec<Value> = LINT_RULES.iter().map(|r| json!({"id": r.0, "severity": r.1, "title": r.2})).collect();
    hash_canonical_strict(&json!({"d": LINT_RULES_DIGEST_DOMAIN, "rules": rows})).expect("in profile")
}

fn last_seg(verb: &str) -> &str {
    verb.rsplit('.').next().unwrap_or(verb)
}

/// `(?:w1|w2|...)(?:_|\Z)` anchored at the start.
fn starts_word(seg: &str, words: &[&str]) -> bool {
    words.iter().any(|w| seg.strip_prefix(w).is_some_and(|rest| rest.is_empty() || rest.starts_with('_')))
}
const DESTROY: [&str; 10] = ["delete", "destroy", "remove", "purge", "drop", "erase", "wipe", "revoke", "terminate", "truncate"];
const SEND_ALL: [&str; 8] = ["send", "email", "notify", "sms", "message", "post_to", "broadcast", "invite"];
const EXPORT: [&str; 5] = ["export", "download", "dump", "backup", "extract"];
const NAME_GROUPS: [&[&str]; 2] = [&["create_", "new_", "add_", "make_"], &["delete_", "remove_", "destroy_"]];

fn binding_keys(d: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let b = d.get("bindings");
    let on = |k: &str| b.and_then(|b| b.get(k)).filter(|x| x.as_object().is_some_and(|m| !m.is_empty()));
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    if let Some(m) = on("mcp") {
        out.push(format!("mcp:{}", js_opt(m.get("tool"))));
    }
    if let Some(m) = on("openapi") {
        out.push(format!("openapi:{}", js_opt(m.get("operationId"))));
    }
    if let Some(m) = on("http") {
        out.push(format!("http:{} {}", s(m, "method").to_uppercase(), s(m, "path")));
    }
    if let Some(m) = on("graphql") {
        out.push(format!("graphql:{}.{}", s(m, "op"), s(m, "field")));
    }
    if let Some(m) = on("grpc") {
        out.push(format!("grpc:{}/{}", s(m, "service"), s(m, "method")));
    }
    if let Some(m) = on("asyncapi") {
        out.push(format!("asyncapi:{} {}", s(m, "op"), s(m, "channel")));
    }
    out
}

fn vocabulary_issues(x: &Value, reg: &Registry) -> Vec<String> {
    let mut out = Vec::new();
    let Some(o) = x.as_object() else { return out };
    if let Some(es) = o.get("effects").and_then(Value::as_array) {
        for e in es {
            if !e.as_str().is_some_and(|e| EFFECTS.contains(&e)) {
                out.push(format!("unknown effect '{}'", js_str(e)));
            }
        }
    }
    if let Some(ps) = o.get("params").and_then(Value::as_object) {
        for (n, q) in ps {
            let Some(q) = q.as_object() else { continue };
            if let Some(r) = q.get("role") {
                if !is_role(r) {
                    out.push(format!("{n}: unknown role '{}'", js_str(r)));
                }
            }
            if let Some(f) = q.get("format") {
                if !is_format(f) {
                    out.push(format!("{n}: unknown format '{}'", js_str(f)));
                }
            }
        }
    }
    if let Some(cs) = o.get("context").and_then(Value::as_array) {
        for c in cs {
            if !c.as_str().is_some_and(is_context_key) {
                out.push(format!("unknown context key '{}' (known: {}, session_taint_max:<level>)", js_str(c), CONTEXT_KEYS.join(", ")));
            }
        }
    }
    if let Some(ts) = o.get("traits").and_then(Value::as_array) {
        for t in ts {
            if let Some(t) = t.as_str() {
                if !reg.traits.contains_key(t) {
                    out.push(format!("unknown trait '{t}'"));
                }
            }
        }
    }
    out
}

fn imperative_bad(title: &str) -> bool {
    let first = title.split(crate::action_schema::is_js_ws).next().unwrap_or("").to_lowercase();
    let cs: Vec<char> = first.chars().collect();
    let n = cs.len();
    let ends = |s: &str| first.ends_with(s);
    let plural = n >= 2 && cs[n - 1] == 's' && cs[n - 2] != 's';
    ends("ing") || ends("ed") || (plural && !ends("us") && !ends("is")) || first == "a" || first == "an" || first == "the"
}

/// Lint a pack's defs (raw values, so a malformed one is still reported). `opts`: `{customTraits?, stability?, ns?}`. Findings are
/// sorted by verb, rule, param, message. Errors fail CI; warnings fail under strict.
pub fn lint_defs(raw: &[Value], opts: &Value, verifier: Verifier) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    let mut add = |rule: &str, verb: Option<&Value>, message: String, param: Option<&str>| {
        let sev = if rule == STRUCTURE_RULE.0 { "error" } else { LINT_RULES.iter().find(|r| r.0 == rule).map_or("error", |r| r.1) };
        let mut f = Map::new();
        f.insert("rule".into(), json!(rule));
        f.insert("severity".into(), json!(sev));
        if let Some(v) = verb.filter(|v| !v.is_null()) {
            f.insert("verb".into(), v.clone());
        }
        if let Some(p) = param {
            f.insert("param".into(), json!(p));
        }
        f.insert("message".into(), json!(message));
        out.push(Value::Object(f));
    };

    let mut reg = core_registry();
    if let Some(ct) = opts.get("customTraits").filter(|c| c.as_array().map_or(!c.is_null() && c.as_bool() != Some(false), |a| !a.is_empty())) {
        let list: Vec<Value> = ct.as_array().cloned().unwrap_or_default();
        match extend_registry(&reg, &list) {
            Ok(r) => reg = r,
            Err(e) => add("LD-007", None, format!("invalid custom traits: {}", e.message), None),
        }
    }

    let mut defs: Vec<&Value> = Vec::new();
    for x in raw {
        let verb = x.get("verb").filter(|v| v.is_string());
        let vocab = vocabulary_issues(x, &reg);
        if !vocab.is_empty() {
            for v in vocab {
                add("LD-007", verb, v, None);
            }
            continue;
        }
        if let Some(bad) = validate_def(x) {
            add(STRUCTURE_RULE.0, verb, bad, None);
            continue;
        }
        defs.push(x);
    }

    // ---- pack-level rules
    let vs = |d: &Value| d["verb"].as_str().unwrap_or("").to_string();
    let mut by_verb: BTreeMap<String, &Value> = BTreeMap::new();
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for d in &defs {
        if by_verb.contains_key(&vs(d)) {
            add("LD-009", Some(&d["verb"]), format!("verb '{}' is defined twice", vs(d)), None);
        }
        by_verb.insert(vs(d), d);
    }
    for d in &defs {
        let mut ns = vec![vs(d)];
        ns.extend(strs_of(d.get("aliases")));
        for n in ns {
            match names.get(&n) {
                Some(owner) if *owner != vs(d) => add("LD-009", Some(&d["verb"]), format!("'{n}' is also a name of '{owner}'"), None),
                Some(_) => {}
                None => {
                    names.insert(n, vs(d));
                }
            }
        }
    }
    let mut bound: BTreeMap<String, String> = BTreeMap::new();
    for d in &defs {
        for k in binding_keys(d) {
            match bound.get(&k) {
                Some(owner) if *owner != vs(d) => add("LD-014", Some(&d["verb"]), format!("binding {k} is also bound by '{owner}'"), None),
                Some(_) => {}
                None => {
                    bound.insert(k, vs(d));
                }
            }
        }
    }
    for grp in NAME_GROUPS {
        let pick = |d: &Value| grp.iter().find(|p| last_seg(d["verb"].as_str().unwrap_or("")).starts_with(**p)).copied();
        let mut used: BTreeMap<&str, usize> = BTreeMap::new();
        for d in &defs {
            if let Some(g) = pick(d) {
                *used.entry(g).or_insert(0) += 1;
            }
        }
        if used.len() > 1 {
            let win = used.iter().min_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0))).map(|x| *x.0).unwrap_or("");
            for d in &defs {
                if let Some(g) = pick(d) {
                    if g != win {
                        add("LW-008", Some(&d["verb"]), format!("uses '{g}' where its siblings use '{win}'"), None);
                    }
                }
            }
        }
    }
    if let Some(ns) = opts.get("ns").filter(|n| !n.is_null()) {
        for d in &defs {
            let first = vs(d).split('.').next().unwrap_or("").to_string();
            if Some(first.as_str()) != ns.as_str() {
                add("LW-008", Some(&d["verb"]), format!("verb namespace '{first}' differs from the file namespace '{}'", js_str(ns)), None);
            }
        }
    }

    // ---- per-def rules
    for d in &defs {
        let n = normalize(d);
        let Ok(eff) = effective_with(d, &reg, verifier) else { continue };
        let tset: Vec<&String> = eff.hint.traits.iter().collect();
        let cl: Vec<&String> = eff.hint.closure.iter().collect();
        let has_t = |t: &str| tset.iter().any(|x| x.as_str() == t);
        let has_c = |t: &str| cl.iter().any(|x| x.as_str() == t);
        let effects = strs_of(d.get("effects"));
        let verb = &d["verb"];
        let seg = last_seg(verb.as_str().unwrap_or("")).to_string();
        let mut pnames: Vec<&String> = n["params"].as_object().map(|m| m.keys().collect()).unwrap_or_default();
        pnames.sort_by(|a, b| u16cmp(a, b));
        let params =
            |pred: &dyn Fn(&Value) -> bool| -> Vec<String> { pnames.iter().filter(|k| pred(&n["params"][k.as_str()])).map(|k| k.to_string()).collect() };
        let role_of = |q: &Value| q.get("role").and_then(Value::as_str).map(String::from);

        if starts_word(&seg, &DESTROY) && !effects.iter().any(|e| e == "delete") {
            add("LD-001", Some(verb), format!("the verb says '{seg}' but effects do not include delete"), None);
        }
        for k in params(&|q| matches!(role_of(q).as_deref(), Some("money.amount") | Some("money.fee"))) {
            let q = &n["params"][k.as_str()];
            match q.get("unit").filter(|u| u["kind"] == "money") {
                None => add("LD-002", Some(verb), "a money parameter needs a unit of kind money with a currency".into(), Some(&k)),
                Some(u) if !u["ccy"].is_string() => {
                    let from = u["ccy"]["from"].as_str().unwrap_or("");
                    let c = n["params"].get(from);
                    if !c.is_some_and(|c| {
                        c.get("role").and_then(Value::as_str) == Some("money.currency") && c.get("format").and_then(Value::as_str) == Some("iso_currency")
                    }) {
                        add("LD-002", Some(verb), format!("the currency parameter '{from}' needs role money.currency and format iso_currency"), Some(&k));
                    }
                }
                _ => {}
            }
        }
        for k in params(&|q| role_of(q).as_deref() == Some("money.currency")) {
            if n["params"][k.as_str()].get("format").and_then(Value::as_str) != Some("iso_currency") {
                add("LD-002", Some(verb), "a currency parameter needs the iso_currency format".into(), Some(&k));
            }
        }
        for k in params(&|q| matches!(q["type"].as_str(), Some("integer") | Some("duration"))) {
            let q = &n["params"][k.as_str()];
            let role = role_of(q);
            if role.as_deref().is_some_and(|r| r.starts_with("id.")) || (role.as_deref() == Some("count.limit") && q.get("max").is_some()) {
                continue;
            }
            if q.get("min").is_none() || q.get("max").is_none() {
                add(
                    "LD-003",
                    Some(verb),
                    format!(
                        "a numeric parameter needs both min and max (has {}, {})",
                        if q.get("min").is_none() { "no min" } else { "min" },
                        if q.get("max").is_none() { "no max" } else { "max" }
                    ),
                    Some(&k),
                );
            }
        }
        if (effects.iter().any(|e| e == "pay") || has_t("pca.money_moving")) && n["idempotency"]["mode"] == "none" {
            add("LD-004", Some(verb), "a money-moving action needs idempotency key_param or natural".into(), None);
        }
        let pii =
            params(&|q| strs_of(q.get("tags")).iter().any(|t| t == "pii") || role_of(q).is_some_and(|r| r.starts_with("contact.") || r.starts_with("person.")));
        if !pii.is_empty() {
            let mut expected: Vec<&str> = Vec::new();
            for s in d.get("side_effects").and_then(Value::as_array).into_iter().flatten() {
                match s["kind"].as_str() {
                    Some("send") => expected.push("send"),
                    Some("export") => expected.push("export"),
                    _ => {}
                }
            }
            if starts_word(&seg, &SEND_ALL) {
                expected.push("send");
            }
            if starts_word(&seg, &EXPORT) {
                expected.push("export");
            }
            expected.sort();
            expected.dedup();
            let list = pii.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
            for e in expected {
                if !effects.iter().any(|x| x == e) {
                    add(
                        "LD-005",
                        Some(verb),
                        format!("personal data can {} ({list}) but effects do not include {e}", if e == "send" { "be sent" } else { "be exported" }),
                        None,
                    );
                }
            }
        }
        for c in &eff.clamps {
            add(
                "LD-006",
                Some(verb),
                format!("declared {} {} is below the floor {}", if c.field == "rev" { "reversibility" } else { "blast" }, c.declared, c.floor),
                None,
            );
        }
        if n["resource"]["id"] == "*" && n["resource"]["scope"] == "one" {
            add("LD-008", Some(verb), "resource id '*' with scope one names every resource at once".into(), None);
        }
        if !is_read_only(&effects) && may_be_reversible(d) {
            match d.get("compensates").and_then(Value::as_str) {
                None => add("LD-010", Some(verb), "a write declared reversible must name its compensating action (compensates)".into(), None),
                Some(c) => match by_verb.get(c) {
                    None => add("LD-010", Some(verb), format!("compensates '{c}', which is not in the pack"), None),
                    Some(comp) => {
                        let s = compensation_shape(d, comp);
                        if s["ok"] != Value::Bool(true) {
                            add("LD-010", Some(verb), format!("compensates '{c}', which cannot undo it: {}", s["reason"].as_str().unwrap_or("")), None);
                        }
                    }
                },
            }
        }
        let review = &d["review"];
        if review["state"] == "confirmed" {
            match review.get("attestation").filter(|a| !a.is_null()) {
                None => add("LD-011", Some(verb), "confirmed without an attestation".into(), None),
                Some(a) => {
                    if a.get("def_digest").and_then(Value::as_str) != def_digest(d).as_deref() {
                        add("LD-011", Some(verb), "the attestation covers a different digest of this def".into(), None);
                    } else if a.get("traits_digest").and_then(Value::as_str) != Some(traits_digest(&reg).as_str()) {
                        add("LD-011", Some(verb), "the attestation was made against a different trait registry".into(), None);
                    } else if verifier.map_or(a.get("sig").is_none(), |f| !f(d)) {
                        add("LD-011", Some(verb), "the attestation is not signed by a pinned reviewer".into(), None);
                    }
                }
            }
        }
        let dismissed: Vec<Value> = if review["state"] == "confirmed" {
            review.get("attestation").and_then(|a| a.get("dismissed")).and_then(Value::as_array).cloned().unwrap_or_default()
        } else {
            vec![]
        };
        let dismissed_names: Vec<&str> = dismissed.iter().filter_map(|x| x["trait"].as_str()).collect();
        for t in review.get("provenance").and_then(|p| p.get("union")).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
            if !has_c(t) && !dismissed_names.contains(&t) {
                add("LD-011", Some(verb), format!("the union-added trait {t} was removed without a signed dismissal"), None);
            }
        }
        for r in prules_violations(d, &eff.hint.eff.prules) {
            if !["money_has_currency", "money_amount_bounded", "pay_has_idempotency"].contains(&r.as_str()) {
                add("LD-012", Some(verb), format!("structural rule {r} is required by the action's traits and violated"), None);
            }
        }
        if is_read_only(&effects) {
            let enforced = strs_of(d.get("context")).iter().any(|c| c == "sandbox_attested");
            for k in params(&|q| matches!(role_of(q).as_deref(), Some("code.command") | Some("query.sql"))) {
                if !enforced {
                    add(
                        "LD-013",
                        Some(verb),
                        "a read-only action takes code or a query it cannot prove read-only (declare context sandbox_attested)".into(),
                        Some(&k),
                    );
                }
            }
            for k in params(&|q| strs_of(q.get("tags")).iter().any(|t| t == "credential")) {
                add("LD-013", Some(verb), "a read-only action handles a credential".into(), Some(&k));
            }
        }

        // ---- warnings
        match d.get("description") {
            None => add("LW-001", Some(verb), "description is missing".into(), None),
            Some(x) if x.as_str().map_or(0, str::len) > 400 => add("LW-001", Some(verb), "description is longer than 400 bytes".into(), None),
            _ => {}
        }
        let title = d["title"].as_str().unwrap_or("");
        if imperative_bad(title) {
            add("LW-001", Some(verb), format!("title '{title}' is not imperative"), None);
        }
        for k in params(&|q| q["type"] == "string" && q.get("max_len").is_none() && q.get("values").is_none()) {
            add("LW-002", Some(verb), "a string parameter without max_len (the default is 1024; say it)".into(), Some(&k));
        }
        if has_c("pca.external_communication") {
            let idem = n["idempotency"].get("param").and_then(Value::as_str).map(String::from);
            for k in params(&|q| {
                q["type"] == "string"
                    && q.get("values").is_none()
                    && q.get("format").is_none()
                    && role_of(q).map_or(true, |r| r.starts_with("text."))
                    && !strs_of(q.get("tags")).iter().any(|t| t == "free_text_outbound")
            }) {
                if Some(k.as_str()) != idem.as_deref() {
                    add("LW-003", Some(verb), "free text flows into an outbound action without tags: [free_text_outbound]".into(), Some(&k));
                }
            }
        }
        if opts.get("stability").and_then(Value::as_str) == Some("stable") && matches!(review["state"].as_str(), Some("unreviewed") | Some("suggested")) {
            add("LW-004", Some(verb), format!("a {} def in a stable pack", review["state"].as_str().unwrap_or("")), None);
        }
        for x in review.get("attestation").and_then(|a| a.get("dismissed")).and_then(Value::as_array).into_iter().flatten() {
            if utf16_len(js_trim(x["reason"].as_str().unwrap_or(""))) < 5 {
                add("LW-005", Some(verb), format!("dismissed trait {} has no reason", js_opt(x.get("trait"))), None);
            }
        }
        for k in params(&|q| q["type"] == "array" && q.get("max_items").map_or(true, Value::is_null)) {
            add("LW-006", Some(verb), "an array parameter without max_items".into(), Some(&k));
        }
        for k in params(&|q| q["sensitivity"] == "critical" && q.get("provenance_min").is_none()) {
            add("LW-007", Some(verb), "a critical parameter without provenance_min".into(), Some(&k));
        }
        if (has_t("pca.money_moving") || has_t("pca.destructive") || has_t("pca.privilege_change"))
            && d.get("examples").and_then(Value::as_array).map_or(true, |e| e.is_empty())
        {
            add("LW-009", Some(verb), "no example for a money-moving, destructive or privilege-changing action".into(), None);
        }
        if d.get("since").is_none() {
            add("LW-010", Some(verb), "since is missing".into(), None);
        }
    }

    out.sort_by(|a, b| {
        let g = |f: &Value, k: &str| f.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        u16cmp(&g(a, "verb"), &g(b, "verb"))
            .then_with(|| u16cmp(&g(a, "rule"), &g(b, "rule")))
            .then_with(|| u16cmp(&g(a, "param"), &g(b, "param")))
            .then_with(|| u16cmp(&g(a, "message"), &g(b, "message")))
    });
    out
}

/// Does the run fail? Errors always; warnings under `strict`.
pub fn lint_fails(fs: &[Value], strict: bool) -> bool {
    fs.iter().any(|f| f["severity"] == "error" || (strict && f["severity"] == "warning"))
}

fn truthy_str<'a>(f: &'a Value, k: &str) -> Option<&'a str> {
    f.get(k).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// Plain text, one line per finding.
pub fn lint_text(fs: &[Value]) -> String {
    if fs.is_empty() {
        return "0 errors, 0 warnings".into();
    }
    let e = fs.iter().filter(|f| f["severity"] == "error").count();
    let w = fs.iter().filter(|f| f["severity"] == "warning").count();
    let mut lines = Vec::new();
    for f in fs {
        let mut loc = String::new();
        if let Some(file) = truthy_str(f, "file") {
            let at = match f.get("line").filter(|l| !l.is_null()) {
                Some(l) => format!(":{}:{}", js_str(l), f.get("column").filter(|c| !c.is_null()).map_or("1".to_string(), js_str)),
                None => String::new(),
            };
            loc = format!("{file}{at}: ");
        }
        let (v, p) = (truthy_str(f, "verb"), truthy_str(f, "param"));
        let sev = f["severity"].as_str().unwrap_or("");
        lines.push(format!(
            "{sev:<7} {}  {loc}{}{}{}{}",
            f["rule"].as_str().unwrap_or(""),
            v.unwrap_or(""),
            p.map_or(String::new(), |p| format!(" [{p}]")),
            if v.is_some() || p.is_some() { ": " } else { "" },
            f["message"].as_str().unwrap_or("")
        ));
    }
    let notes = fs.len() - e - w;
    format!(
        "{}\n{} error{}, {} warning{}{}",
        lines.join("\n"),
        e,
        if e == 1 { "" } else { "s" },
        w,
        if w == 1 { "" } else { "s" },
        if notes > 0 { format!(", {} note{}", notes, if notes == 1 { "" } else { "s" }) } else { String::new() }
    )
}

/// SARIF 2.1.0, so findings appear as pull request annotations.
pub fn to_sarif(fs: &[Value], tool: Option<&Value>) -> Value {
    let level = |s: &str| {
        if s == "error" {
            "error"
        } else if s == "warning" {
            "warning"
        } else {
            "note"
        }
    };
    let mut driver = Map::new();
    driver.insert("name".into(), tool.and_then(|t| t.get("name")).filter(|n| !n.is_null()).cloned().unwrap_or_else(|| json!("pca actions lint")));
    if let Some(v) = tool.and_then(|t| t.get("version")).filter(|v| v.as_str().map_or(!v.is_null() && **v != json!(0) && **v != json!(false), |s| !s.is_empty()))
    {
        driver.insert("version".into(), v.clone());
    }
    let mut rules = vec![STRUCTURE_RULE, NOTE_RULE];
    rules.extend(LINT_RULES);
    driver.insert(
        "rules".into(),
        Value::Array(rules.iter().map(|r| json!({"id": r.0, "shortDescription": {"text": r.2}, "defaultConfiguration": {"level": level(r.1)}})).collect()),
    );
    let mut results = Vec::new();
    for f in fs {
        let mut loc = Map::new();
        if let Some(file) = truthy_str(f, "file") {
            let mut pl = Map::new();
            pl.insert("artifactLocation".into(), json!({"uri": file}));
            if let Some(l) = f.get("line").filter(|l| !l.is_null()) {
                pl.insert(
                    "region".into(),
                    json!({"startLine": l, "startColumn": f.get("column").filter(|c| !c.is_null()).cloned().unwrap_or_else(|| json!(1))}),
                );
            }
            loc.insert("physicalLocation".into(), Value::Object(pl));
        }
        let verb = truthy_str(f, "verb");
        if let Some(v) = verb {
            loc.insert("logicalLocations".into(), json!([{"name": v, "kind": "member"}]));
        }
        let prefix = verb.map_or(String::new(), |v| format!("{v}{}: ", truthy_str(f, "param").map_or(String::new(), |p| format!(" [{p}]"))));
        results.push(json!({"ruleId": f["rule"], "level": level(f["severity"].as_str().unwrap_or("")), "message": {"text": format!("{prefix}{}", f["message"].as_str().unwrap_or(""))}, "locations": [Value::Object(loc)]}));
    }
    json!({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": driver}, "results": results}]})
}
