//! Dataflow trace rules: the `never <selector> after <selector> within <duration>` language, the Invariant-rule import (the
//! compilable `(x: ToolCall|ToolOutput) -> (y: ToolCall)` subset), the compile to `derive` caveats the verifier enforces from
//! history (one caveat per earlier-action source and chunk of later verbs), the lethal-trifecta lint, and `category_id` (a
//! detector label as a receipt category). Rules, verb tables and outputs are JSON values in the reference's shapes; the
//! compiled caveats and their digest are byte-identical to it.
use crate::action_schema::is_js_ws;
use crate::caveat_lang::{derive_error, DERIVE_MAX_WINDOW_MS};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

pub const MAX_TRACE_CAVEATS: usize = 64;
const B_CHUNK: usize = 8; // 7 + 3k expression nodes <= the derive node limit (32)
pub const PRIVATE_READ_TRAITS: [&str; 4] = ["pca.pii_access", "pca.financial_data_read", "pca.credential_access", "pca.regulated_data"];
pub const EXTERNAL_SEND_TRAITS: [&str; 4] = ["pca.external_communication", "pca.network_egress", "pca.data_export", "pca.public_exposure"];

/// A refusal of the rule language / compiler: a stable `code` and the reference's message.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceRuleError {
    pub code: &'static str,
    pub message: String,
}

fn fail<T>(code: &'static str, message: impl Into<String>) -> Result<T, TraceRuleError> {
    Err(TraceRuleError { code, message: message.into() })
}

/// `^[a-z][a-z0-9_]{0,39}$`
fn rule_id_ok(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty() && b.len() <= 40 && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// `^[A-Za-z0-9_.:/-]{1,256}$`
fn verb_ok(v: &str) -> bool {
    !v.is_empty() && v.len() <= 256 && v.bytes().all(|c| c.is_ascii_alphanumeric() || b"_.:/-".contains(&c))
}

fn id_check(id: &str) -> Result<(), TraceRuleError> {
    if rule_id_ok(id) {
        Ok(())
    } else {
        fail("id", format!("rule id '{id}' must match ^[a-z][a-z0-9_]{{0,39}}$"))
    }
}

/// `^([1-9][0-9]{0,9})(ms|s|m|h|d)$` in ms, at most the 30-day history window.
fn duration(t: &str) -> Result<i64, TraceRuleError> {
    let digits = t.bytes().take_while(u8::is_ascii_digit).count();
    let unit = match &t[digits..] {
        "ms" => 1,
        "s" => 1000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => 0,
    };
    if unit == 0 || digits == 0 || digits > 10 || t.starts_with('0') {
        return fail("duration", format!("'{t}' is not a duration like 10m, 2h or 7d"));
    }
    let ms = t[..digits].parse::<i64>().unwrap_or(i64::MAX) * unit;
    if ms > DERIVE_MAX_WINDOW_MS {
        return fail("window", format!("a window of {t} exceeds the 30-day history the verifier keeps"));
    }
    Ok(ms)
}

fn selector(text: &str, side: &str) -> Result<Value, TraceRuleError> {
    let (mut tools, mut traits, mut resources, mut any) = (Vec::new(), Vec::new(), Vec::new(), false);
    for raw in text.split(',') {
        let a = raw.trim_matches(is_js_ws);
        let units = a.encode_utf16().count();
        if a == "any" {
            any = true;
        } else if let Some(v) = a.strip_prefix("tool:").filter(|v| verb_ok(v)) {
            tools.push(v.to_string());
        } else if let Some(v) = a.strip_prefix("trait:").filter(|v| verb_ok(v)) {
            traits.push(v.to_string());
        } else if a.starts_with("resource:") && units > 9 && units <= 9 + 256 {
            if side == "never" {
                return fail("resource_on_effect", "a resource selector can only name the earlier action (the check reads the current verb)");
            }
            resources.push(a[9..].to_string());
        } else {
            return fail("selector", format!("'{a}' is not tool:<verb>, trait:<id>, resource:<prefix> or any"));
        }
    }
    Ok(json!({ "tools": tools, "traits": traits, "resources": resources, "any": any }))
}

fn is_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

/// `^\s*never\s+(.+?)\s+after\s+(.+?)\s+within\s+(\S+)\s*$`, explored in the regex engine's backtracking order.
fn match_rule(text: &str) -> Option<(String, String, String)> {
    let c: Vec<char> = text.chars().collect();
    let n = c.len();
    let ws = |i: usize| c[i.min(n)..].iter().take_while(|x| is_js_ws(**x)).count();
    let lit = |i: usize, w: &str| w.chars().enumerate().all(|(k, x)| c.get(i + k) == Some(&x));
    let s = |a: usize, b: usize| c[a..b].iter().collect::<String>();
    let mut i = ws(0);
    if !lit(i, "never") {
        return None;
    }
    i += 5;
    for a in (1..=ws(i)).rev() {
        let g1s = i + a;
        for g1e in g1s + 1..=n {
            if is_line_terminator(c[g1e - 1]) {
                break;
            }
            let k = ws(g1e);
            if k == 0 || !lit(g1e + k, "after") {
                continue;
            }
            let j = g1e + k + 5;
            for b in (1..=ws(j)).rev() {
                let g2s = j + b;
                for g2e in g2s + 1..=n {
                    if is_line_terminator(c[g2e - 1]) {
                        break;
                    }
                    let k3 = ws(g2e);
                    if k3 == 0 || !lit(g2e + k3, "within") {
                        continue;
                    }
                    let m = g2e + k3 + 6;
                    let k4 = ws(m);
                    let g3s = m + k4;
                    let g3e = g3s + c[g3s.min(n)..].iter().take_while(|x| !is_js_ws(**x)).count();
                    if k4 > 0 && g3e > g3s && g3e + ws(g3e) == n {
                        return Some((s(g1s, g1e), s(g2s, g2e), s(g3s, g3e)));
                    }
                }
            }
        }
    }
    None
}

/// Parse `never <selector> after <selector> within <duration>` into a rule `{id, never, after, within_ms, reason?}`.
pub fn parse_trace_rule(id: &str, text: &str, reason: Option<&str>) -> Result<Value, TraceRuleError> {
    id_check(id)?;
    let Some((never, after, within)) = match_rule(text) else {
        return fail("syntax", format!("expected 'never <selector> after <selector> within <duration>', got '{text}'"));
    };
    let mut r = json!({ "id": id, "never": selector(&never, "never")?, "after": selector(&after, "after")?, "within_ms": duration(&within)? });
    if let Some(why) = reason {
        r["reason"] = json!(why);
    }
    Ok(r)
}

fn word_len(s: &str) -> usize {
    s.bytes().take_while(|c| c.is_ascii_alphanumeric() || *c == b'_').count()
}

fn strip_ws(s: &str) -> &str {
    s.trim_start_matches(is_js_ws)
}

/// `^raise\s+(?:"([^"]*)"|'([^']*)')\s+if:$` -> the message.
fn match_head(l: &str) -> Option<String> {
    let rest = l.strip_prefix("raise")?;
    let r = strip_ws(rest);
    if r.len() == rest.len() {
        return None;
    }
    let q = r.chars().next().filter(|q| *q == '"' || *q == '\'')?;
    let end = r[1..].find(q)? + 1;
    let tail = &r[end + 1..];
    let t = strip_ws(tail);
    (t.len() < tail.len() && t == "if:").then(|| r[1..end].to_string())
}

/// `^\((\w+):\s*(ToolCall|ToolOutput|Message)\)\s*->\s*\((\w+):\s*(ToolCall|ToolOutput|Message)\)$`
fn match_flow(l: &str) -> Option<(String, String, String, String)> {
    fn event(s: &str) -> Option<(String, String, &str)> {
        let s = s.strip_prefix('(')?;
        let w = word_len(s);
        if w == 0 {
            return None;
        }
        let s2 = strip_ws(s[w..].strip_prefix(':')?);
        let ty = ["ToolCall", "ToolOutput", "Message"].into_iter().find(|t| s2.starts_with(t) && s2[t.len()..].starts_with(')'))?;
        Some((s[..w].to_string(), ty.to_string(), &s2[ty.len() + 1..]))
    }
    let (a, ta, rest) = event(l)?;
    let (b, tb, end) = event(strip_ws(strip_ws(rest).strip_prefix("->")?))?;
    end.is_empty().then_some((a, ta, b, tb))
}

/// `^(\w+)\s+is\s+tool:([A-Za-z0-9_.:/-]+)(\(.*\))?$` -> (var, tool, has argument pattern).
fn match_is(l: &str) -> Option<(String, String, bool)> {
    let w = word_len(l);
    let r = &l[w..];
    let r2 = strip_ws(r);
    if w == 0 || r2.len() == r.len() {
        return None;
    }
    let r3 = r2.strip_prefix("is")?;
    let r4 = strip_ws(r3);
    if r4.len() == r3.len() {
        return None;
    }
    let r5 = r4.strip_prefix("tool:")?;
    let t = r5.bytes().take_while(|c| c.is_ascii_alphanumeric() || b"_.:/-".contains(c)).count();
    let tail = &r5[t..];
    let args = !tail.is_empty();
    if t == 0 || (args && !(tail.len() >= 2 && tail.starts_with('(') && tail.ends_with(')') && !tail.chars().any(is_line_terminator))) {
        return None;
    }
    Some((l[..w].to_string(), r5[..t].to_string(), args))
}

/// Import an Invariant rule (`raise "<message>" if:` / one `(x: ToolCall|ToolOutput) -> (y: ToolCall)` flow / `x is tool:<name>`
/// lines) as a trace rule over `opts.horizon`; `opts.dropUnsupported` drops (and lists) lines outside the subset, keeping an
/// argument-pattern line's tool (a wider match, so more refusals). Returns `{rule, dropped}`.
pub fn parse_invariant_rule(id: &str, text: &str, opts: &Value) -> Result<Value, TraceRuleError> {
    id_check(id)?;
    let Some(horizon) = opts.get("horizon").and_then(Value::as_str) else {
        return fail("horizon", "an Invariant rule has no window: pass the horizon explicitly");
    };
    let within_ms = duration(horizon)?;
    let lines: Vec<&str> = text.split('\n').map(|l| l.trim_matches(is_js_ws)).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    let Some(reason) = match_head(lines.first().copied().unwrap_or("")) else {
        return fail("syntax", "the first line must be raise \"<message>\" if:");
    };
    let Some((a, ta, b, tb)) = match_flow(lines.get(1).copied().unwrap_or("")) else {
        return fail(
            "unsupported",
            "the second line must be one flow '(x: ToolCall|ToolOutput) -> (y: ToolCall)' (chains of three and other patterns are not supported)",
        );
    };
    if ta == "Message" || tb != "ToolCall" {
        return fail("unsupported", "only a tool call or tool output followed by a tool call can be compiled");
    }
    if a == b {
        return fail("syntax", "the two events need distinct names");
    }
    let drop = opts.get("dropUnsupported") == Some(&Value::Bool(true));
    let (mut ta_tools, mut tb_tools, mut dropped) = (Vec::<String>::new(), Vec::<String>::new(), Vec::<String>::new());
    for l in lines.iter().skip(2) {
        let m = match_is(l).filter(|(v, _, _)| *v == a || *v == b);
        if let Some((v, tool, false)) = &m {
            if *v == a { &mut ta_tools } else { &mut tb_tools }.push(tool.clone());
            continue;
        }
        if drop {
            if let Some((v, tool, _)) = m {
                if v == a { &mut ta_tools } else { &mut tb_tools }.push(tool);
            }
            dropped.push(l.to_string());
            continue;
        }
        return fail("unsupported", format!("'{l}' is outside the compilable subset (x is tool:<name>); pass dropUnsupported to refuse more instead"));
    }
    for (v, t) in [(&a, &ta_tools), (&b, &tb_tools)] {
        if t.len() > 1 {
            return fail("unsatisfiable", format!("'{v}' is constrained to two different tools, so the rule can never fire"));
        }
    }
    let sel = |t: &Vec<String>| json!({ "tools": t, "traits": [], "resources": [], "any": t.is_empty() });
    Ok(json!({ "rule": { "id": id, "never": sel(&tb_tools), "after": sel(&ta_tools), "within_ms": within_ms, "reason": reason }, "dropped": dropped }))
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect()
}

fn traits_of(table: &Map<String, Value>, v: &str) -> Vec<String> {
    strs(&table[v]["traits"])
}

fn expand(s: &Value, table: &Map<String, Value>, what: &str) -> Result<Vec<String>, TraceRuleError> {
    let mut out = BTreeSet::new();
    if s["any"] == Value::Bool(true) {
        out.extend(table.keys().cloned());
    }
    for t in strs(&s["tools"]) {
        if !table.contains_key(&t) {
            return fail("unknown_tool", format!("{what}: tool '{t}' is not an action in the verb table"));
        }
        out.insert(t);
    }
    for tr in strs(&s["traits"]) {
        let hit: Vec<&String> = table.keys().filter(|v| traits_of(table, v).contains(&tr)).collect();
        if hit.is_empty() {
            return fail("empty_selector", format!("{what}: trait '{tr}' matches no action"));
        }
        out.extend(hit.into_iter().cloned());
    }
    Ok(out.into_iter().collect())
}

/// Compile trace rules over a verb table (`{verb: {traits, effects?}}`) into `derive` caveats (refused iff a matching earlier
/// action happened within the window AND this action is a later verb; unknown history refuses too), the rule edges, and
/// the digest of the caveat set. `{caveats, edges, digest}`.
pub fn compile_trace_rules(rules: &[Value], table: &Value) -> Result<Value, TraceRuleError> {
    let empty = Map::new();
    let table = table.as_object().unwrap_or(&empty);
    let (mut caveats, mut edges, mut ids) = (Vec::new(), Vec::new(), Vec::<String>::new());
    for r in rules {
        let id = r["id"].as_str().unwrap_or("");
        if !rule_id_ok(id) || ids.iter().any(|x| x == id) {
            return fail("id", format!("rule id '{}' is malformed or repeated", crate::oauth::js_str(&r["id"])));
        }
        ids.push(id.to_string());
        let w = r["within_ms"].as_f64().filter(|w| w.fract() == 0.0 && *w >= 1.0 && *w <= DERIVE_MAX_WINDOW_MS as f64);
        let Some(within) = w.map(|w| w as i64) else { return fail("window", format!("rule '{id}': within_ms must be 1..30 days")) };
        if !strs(&r["never"]["resources"]).is_empty() {
            return fail("resource_on_effect", format!("rule '{id}': a resource selector cannot name the later action"));
        }
        let bs = expand(&r["never"], table, &format!("rule '{id}' never"))?;
        let mut srcs: Vec<(&str, String)> = expand(&r["after"], table, &format!("rule '{id}' after"))?.into_iter().map(|v| ("verb", v)).collect();
        srcs.extend(strs(&r["after"]["resources"]).into_iter().collect::<BTreeSet<_>>().into_iter().map(|p| ("resource_prefix", p)));
        if bs.is_empty() || srcs.is_empty() {
            return fail("empty_selector", format!("rule '{id}': a side matches nothing"));
        }
        let mut n = 0;
        for (k, v) in &srcs {
            for chunk in bs.chunks(B_CHUNK) {
                let is_b =
                    json!({ "op": "or", "args": chunk.iter().map(|b| json!({ "op": "eq", "a": { "ref": "verb" }, "b": { "const": b } })).collect::<Vec<_>>() });
                let mut seen = json!({ "name": "seen", "kind": "count", "window_ms": within });
                seen[*k] = json!(v);
                let c = json!({ "type": "derive", "id": format!("trace.{id}.{n}"),
                    "defs": [seen, { "name": "verb", "kind": "action", "field": "verb" }, { "name": "is_b", "kind": "expr", "expr": is_b }],
                    "check": { "op": "not", "arg": { "op": "and", "args": [{ "op": "gt", "a": { "ref": "seen" }, "b": { "const": 0 } }, { "ref": "is_b" }] } } });
                n += 1;
                if let Some(e) = derive_error(&c) {
                    return fail("internal", format!("rule '{id}' compiled to an invalid caveat: {e}"));
                }
                caveats.push(c);
                if caveats.len() > MAX_TRACE_CAVEATS {
                    return fail("too_large", format!("more than {MAX_TRACE_CAVEATS} caveats: split the rule set or narrow the selectors"));
                }
            }
            let from = if *k == "verb" { json!({ "tool": v }) } else { json!({ "resource": v }) };
            for b in &bs {
                edges.push(json!({ "rule": id, "from": from, "to": b, "within_ms": within }));
            }
        }
    }
    let digest = crate::hash_canonical_strict(&json!({ "d": "atlas-pca/trace-rules/v1", "caveats": caveats }))
        .ok_or(TraceRuleError { code: "internal", message: "caveats outside the canonical profile".into() })?;
    Ok(json!({ "caveats": caveats, "edges": edges, "digest": digest }))
}

/// The lethal-trifecta lint: private reads, untrusted reads (`opts.untrusted`, `opts.untrusted_traits`, or a read-only
/// network-egress verb) and external sends all present, and a send reachable from both an untrusted and a private read with
/// no trace rule (edge) forbidding it. `{private_reads, untrusted_reads, sends, findings: [{send, from_untrusted, from_private}]}`.
pub fn lethal_trifecta(table: &Value, edges: &[Value], opts: Option<&Value>) -> Value {
    let empty = Map::new();
    let t = table.as_object().unwrap_or(&empty);
    let verbs: Vec<&String> = t.keys().collect::<BTreeSet<_>>().into_iter().collect();
    let o = opts.unwrap_or(&Value::Null);
    let (untrusted_list, untrusted_traits) = (strs(&o["untrusted"]), strs(&o["untrusted_traits"]));
    let has = |v: &str, ts: &[&str]| traits_of(t, v).iter().any(|x| ts.contains(&x.as_str()));
    let read_only = |v: &str| {
        let e = strs(&t[v]["effects"]);
        !e.is_empty() && e.iter().all(|x| x == "read")
    };
    let ut: Vec<&str> = untrusted_traits.iter().map(String::as_str).collect();
    let pick = |f: &dyn Fn(&str) -> bool| verbs.iter().filter(|v| f(v)).map(|v| (*v).clone()).collect::<Vec<String>>();
    let private = pick(&|v| has(v, &PRIVATE_READ_TRAITS));
    let untrusted =
        pick(&|v| untrusted_list.iter().any(|u| u == v) || has(v, &ut) || (read_only(v) && traits_of(t, v).iter().any(|x| x == "pca.network_egress")));
    let sends = pick(&|v| has(v, &EXTERNAL_SEND_TRAITS) && !read_only(v));
    let mut findings = Vec::new();
    if !private.is_empty() && !untrusted.is_empty() && !sends.is_empty() {
        let ruled = |from: &str, to: &str| edges.iter().any(|e| e["from"].get("tool").and_then(Value::as_str) == Some(from) && e["to"].as_str() == Some(to));
        for s in &sends {
            let fu: Vec<&String> = untrusted.iter().filter(|u| !ruled(u, s)).collect();
            let fp: Vec<&String> = private.iter().filter(|p| !ruled(p, s)).collect();
            if !fu.is_empty() && !fp.is_empty() {
                findings.push(json!({ "send": s, "from_untrusted": fu, "from_private": fp }));
            }
        }
    }
    json!({ "private_reads": private, "untrusted_reads": untrusted, "sends": sends, "findings": findings })
}

/// A detector's label as a receipt category id (`^[a-z][a-z0-9_]{0,63}$`, else `other`).
pub fn category_id(s: &Value) -> String {
    let Some(s) = s.as_str() else { return "other".into() };
    let mut c = String::new();
    for ch in s.to_lowercase().chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            c.push(ch);
        } else if !c.ends_with('_') || c.is_empty() {
            c.push('_');
        }
    }
    let mut c = c.trim_matches('_').to_string();
    if c.starts_with(|x: char| x.is_ascii_digit()) {
        c.insert_str(0, "c_");
    }
    c.truncate(64);
    let ok = c.as_bytes().first().is_some_and(u8::is_ascii_lowercase) && c.bytes().all(|x| x.is_ascii_lowercase() || x.is_ascii_digit() || x == b'_');
    if ok {
        c
    } else {
        "other".into()
    }
}
