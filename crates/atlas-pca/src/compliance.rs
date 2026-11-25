//! Auditor-ready compliance evidence from PCA proofs and decision records, pre-mapped to the control language auditors use: EU AI
//! Act Art. 12 / Art. 50, ISO/IEC 42001 clauses and SOC 2 CC6, plus the console-activity framework report (EU AI Act, SOC 2, GDPR).
//! Port of the TypeScript reference (`@atlasauth/pca-compliance`). JSON-valued: inputs are the reference's JSON shapes, results are
//! `Result<Value, String>`; a reference throw is an `Err`.
//!
//! Everything is pure and read-only, and total where the reference is: a malformed record degrades to a best-effort one. Property reads
//! follow JavaScript semantics (a missing member is `undefined` = `None`, reading through `null` / `undefined` is an `Err`) so reports
//! match the reference text for text. HONEST SCOPE: an evidence mapping, not a legal certification.
//!
//! shortcut: a slice that would cut a UTF-16 surrogate pair in half yields U+FFFD (a Rust string cannot hold a lone surrogate);
//! `frameworkReport` refuses a non-string framework (the reference also accepts a one-element array through property-key coercion);
//! `frameworkReportToMarkdown` refuses a string `generatedAt` (the reference would parse it as a date); a hex / octal / binary
//! numeric string beyond u64 is NaN.
use crate::intent_v2::{js_number_string, js_value_string};
use crate::{hash_canonical_strict, js_stringify};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

pub const COMPLIANCE_FRAMEWORKS: [&str; 3] = ["eu-ai-act", "iso-42001", "soc2"];
const FRAMEWORK_IDS: [&str; 3] = ["eu-ai-act", "soc2", "gdpr"];

/// A JS value: `None` is `undefined`, `Some(Value::Null)` is `null`.
type R<'a> = Option<&'a Value>;

// ---- JavaScript semantics ---------------------------------------------------------------------------------------------

fn own<'a>(o: R<'a>, k: &str) -> R<'a> {
    match o {
        Some(Value::Object(m)) => m.get(k),
        _ => None,
    }
}

fn nullish(v: R) -> bool {
    matches!(v, None | Some(Value::Null))
}

/// `o.k`: an `Err` when `o` is null / undefined, like the reference.
fn prop<'a>(o: R<'a>, k: &str) -> Result<R<'a>, String> {
    if nullish(o) {
        return Err(format!("Cannot read properties of {} (reading '{k}')", if o.is_none() { "undefined" } else { "null" }));
    }
    Ok(own(o, k))
}

/// `o?.k`.
fn qprop<'a>(o: R<'a>, k: &str) -> R<'a> {
    if nullish(o) {
        None
    } else {
        own(o, k)
    }
}

fn truthy(v: R) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

fn as_str<'a>(v: R<'a>) -> Option<&'a str> {
    match v {
        Some(Value::String(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn is_num(v: R) -> bool {
    matches!(v, Some(Value::Number(_)))
}

/// `Number.isFinite` (no coercion).
fn finite_num(v: R) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64().filter(|f| f.is_finite()),
        _ => None,
    }
}

fn str_is(v: R, s: &str) -> bool {
    matches!(v, Some(Value::String(t)) if t == s)
}

/// A value interpolated into a template literal.
fn tpl(v: R) -> String {
    match v {
        None => "undefined".into(),
        Some(x) => js_value_string(x),
    }
}

fn str_to_number(s: &str) -> f64 {
    let t = s.trim();
    if t.is_empty() {
        return 0.0;
    }
    match t {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    for (p, radix) in [("0x", 16), ("0X", 16), ("0o", 8), ("0O", 8), ("0b", 2), ("0B", 2)] {
        if let Some(r) = t.strip_prefix(p) {
            if !r.chars().all(|c| c.is_ascii_alphanumeric()) {
                return f64::NAN;
            }
            return u64::from_str_radix(r, radix).map(|n| n as f64).unwrap_or(f64::NAN);
        }
    }
    if t.chars().all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-')) {
        t.parse::<f64>().unwrap_or(f64::NAN)
    } else {
        f64::NAN
    }
}

/// JavaScript ToNumber.
fn to_number(v: R) -> f64 {
    match v {
        None => f64::NAN,
        Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::String(s)) => str_to_number(s),
        Some(x) => str_to_number(&js_value_string(x)),
    }
}

/// ToPrimitive for a JSON value (arrays and objects become their string form).
fn to_prim(v: &Value) -> Value {
    match v {
        Value::Array(_) | Value::Object(_) => Value::String(js_value_string(v)),
        x => x.clone(),
    }
}

/// `a > b`: two strings compare by UTF-16 order, anything else numerically.
fn gt(a: &Value, b: &Value) -> bool {
    let (a, b) = (to_prim(a), to_prim(b));
    if let (Value::String(x), Value::String(y)) = (&a, &b) {
        return x.encode_utf16().cmp(y.encode_utf16()) == std::cmp::Ordering::Greater;
    }
    to_number(Some(&a)) > to_number(Some(&b))
}

/// `Math.round`: halves round toward +Infinity.
fn js_round(v: f64) -> f64 {
    let r = v.floor();
    if v - r >= 0.5 {
        r + 1.0
    } else {
        r
    }
}

/// A JS number as a JSON value (a non-finite one as the `{"$num": "NaN"}` marker the reference corpus uses).
fn num_val(f: f64) -> Value {
    if !f.is_finite() {
        // the corpus (and `jsonOut` of the reference) writes NaN / Infinity as {"$num": "NaN"}
        json!({ "$num": js_number_string(f) })
    } else if f.fract() == 0.0 && f.abs() < 9.0e15 {
        Value::from(f as i64)
    } else {
        Value::from(f)
    }
}

/// `v.length`: UTF-16 units of a string, items of an array, `None` (undefined) otherwise; an `Err` on null / undefined.
fn length(v: R) -> Result<Option<usize>, String> {
    match v {
        None | Some(Value::Null) => Err(format!("Cannot read properties of {} (reading 'length')", if v.is_none() { "undefined" } else { "null" })),
        Some(Value::String(s)) => Ok(Some(s.encode_utf16().count())),
        Some(Value::Array(a)) => Ok(Some(a.len())),
        _ => Ok(None),
    }
}

/// `Object.keys` order: array-index keys ascending, then insertion order.
fn js_keys(m: &Map<String, Value>) -> Vec<&String> {
    fn index_key(k: &str) -> Option<u32> {
        let n: u32 = k.parse().ok()?;
        (n != u32::MAX && n.to_string() == k).then_some(n)
    }
    let mut idx: Vec<(u32, &String)> = m.keys().filter_map(|k| index_key(k).map(|n| (n, k))).collect();
    idx.sort();
    idx.into_iter().map(|(_, k)| k).chain(m.keys().filter(|k| index_key(k).is_none())).collect()
}

/// `JSON.stringify(v, null, 2)`.
fn pretty(v: &Value, base: &str, out: &mut String) {
    match v {
        Value::Array(a) if !a.is_empty() => {
            let ind = format!("{base}  ");
            out.push_str("[\n");
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&ind);
                pretty(x, &ind, out);
            }
            out.push('\n');
            out.push_str(base);
            out.push(']');
        }
        Value::Object(m) if !m.is_empty() => {
            let ind = format!("{base}  ");
            out.push_str("{\n");
            for (i, k) in js_keys(m).into_iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&ind);
                out.push_str(&js_stringify(&Value::String(k.clone())));
                out.push_str(": ");
                pretty(&m[k.as_str()], &ind, out);
            }
            out.push('\n');
            out.push_str(base);
            out.push('}');
        }
        x => out.push_str(&js_stringify(x)),
    }
}

/// (year, month, day) of a day count since 1970-01-01 (proleptic Gregorian).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `new Date(ms).toISOString()`; `None` for an invalid / unrepresentable time (a RangeError there).
fn iso_string(ms: f64) -> Option<String> {
    if !ms.is_finite() || ms.abs() > 8.64e15 {
        return None;
    }
    let t = ms.trunc() as i64;
    let (days, rem) = (t.div_euclid(86_400_000), t.rem_euclid(86_400_000));
    let (y, mo, d) = civil(days);
    let ys = if (0..=9999).contains(&y) { format!("{y:04}") } else { format!("{}{:06}", if y > 0 { "+" } else { "-" }, y.abs()) };
    Some(format!("{ys}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", rem / 3_600_000, rem / 60_000 % 60, rem / 1000 % 60, rem % 1000))
}

fn iso(v: R) -> String {
    match finite_num(v) {
        None => "(unknown time)".into(),
        Some(f) => iso_string(f).unwrap_or_else(|| "(unrepresentable time)".into()),
    }
}

fn ts(v: &Value) -> Value {
    json!({ "epochMs": v, "iso": iso(Some(v)) })
}

fn now_ms() -> Value {
    let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
    Value::from(ms)
}

/// Abbreviate a long key for display (UTF-16 units, like the reference).
fn short(key: R, n: usize) -> String {
    let s = match as_str(key) {
        Some(s) if !s.is_empty() => s,
        _ => return "(none)".into(),
    };
    let u: Vec<u16> = s.encode_utf16().collect();
    if u.len() <= n + 1 {
        return s.to_string();
    }
    format!("{}…", String::from_utf16_lossy(&u[..n]))
}

fn numstr(x: R) -> String {
    match x {
        Some(Value::Number(n)) => {
            let f = n.as_f64().unwrap_or(f64::NAN);
            if !f.is_finite() || f.fract() == 0.0 {
                js_number_string(f)
            } else {
                js_number_string(js_round(f * 1e4) / 1e4)
            }
        }
        _ => tpl(x),
    }
}

/// The reference's `Set` over arbitrary values (SameValueZero: primitives by value, each object distinct).
#[derive(Default)]
struct JsSet {
    keys: HashSet<String>,
    objects: usize,
}

impl JsSet {
    fn add(&mut self, v: R) {
        let k = match v {
            None => "u".to_string(),
            Some(Value::Null) => "z".to_string(),
            Some(Value::Bool(b)) => format!("b{b}"),
            Some(Value::Number(n)) => {
                let f = n.as_f64().unwrap_or(f64::NAN);
                if f.is_nan() {
                    "nnan".to_string()
                } else {
                    format!("n{}", (f + 0.0).to_bits())
                }
            }
            Some(Value::String(s)) => format!("s{s}"),
            Some(_) => {
                self.objects += 1;
                format!("o{}", self.objects)
            }
        };
        self.keys.insert(k);
    }

    fn size(&self) -> usize {
        self.keys.len()
    }
}

// ---- AuditEvent -------------------------------------------------------------------------------------------------------

fn is_budget_alloc(cv: &Value) -> bool {
    match cv {
        Value::Object(m) => str_is(m.get("type"), "budget_alloc") && finite_num(m.get("limit")).is_some_and(|l| l >= 0.0),
        _ => false,
    }
}

/// A bounded, human-readable rendering of one caveat.
fn describe_caveat(cv: &Value) -> String {
    let m = match cv {
        Value::Object(m) => m,
        _ => return "(malformed caveat)".into(),
    };
    let ty = match m.get("type") {
        Some(Value::String(s)) => s.as_str(),
        _ => return "(malformed caveat)".into(),
    };
    if ty == "envelope" {
        let n = |k: &str| match m.get(k) {
            Some(Value::Array(a)) => a.len(),
            _ => 0,
        };
        return format!("policy envelope ({} predicate(s), {} caveat(s))", n("predicates"), n("caveats"));
    }
    if is_budget_alloc(cv) {
        return format!("budget allocation ≤ {}", numstr(m.get("limit")));
    }
    let mut parts: Vec<String> = Vec::new();
    for k in js_keys(m).into_iter().take(8) {
        if k == "type" {
            continue;
        }
        let v = &m[k.as_str()];
        parts.push(format!("{k}={}", if matches!(v, Value::Array(_) | Value::Object(_)) { js_stringify(v) } else { numstr(Some(v)) }));
    }
    if parts.is_empty() {
        ty.to_string()
    } else {
        format!("{ty}({})", parts.join(", "))
    }
}

/// The delegation hops: issuer -> holder and the caveats each hop ADDED (append-only diff against its parent).
fn build_delegation_hops(chain: &[Value]) -> Vec<Value> {
    let empty: Vec<Value> = Vec::new();
    let mut hops = Vec::new();
    for (i, cap) in chain.iter().enumerate() {
        if !truthy(Some(cap)) {
            continue;
        }
        let is_root = i == 0;
        let parent_len = if i > 0 && truthy(Some(&chain[i - 1])) {
            match own(Some(&chain[i - 1]), "caveats") {
                Some(Value::Array(a)) => a.len(),
                _ => 0,
            }
        } else {
            0
        };
        let own_cv: &Vec<Value> = match own(Some(cap), "caveats") {
            Some(Value::Array(a)) => a,
            _ => &empty,
        };
        let added: &[Value] = if is_root {
            own_cv
        } else if own_cv.len() >= parent_len {
            &own_cv[parent_len..]
        } else {
            &[]
        };
        let scope: Vec<String> = added.iter().map(describe_caveat).collect();
        let budget = added.iter().find(|c| is_budget_alloc(c));
        let (issuer, holder) = (own(Some(cap), "issuer"), own(Some(cap), "holder"));
        let joined = scope.join("; ");
        let narrative = if is_root {
            format!(
                "Principal {} granted authority to {}{}.",
                short(issuer, 12),
                short(holder, 12),
                if scope.is_empty() { String::new() } else { format!(" under: {joined}") }
            )
        } else {
            format!(
                "{} delegated to {}{}.",
                short(issuer, 12),
                short(holder, 12),
                if scope.is_empty() { " (rebind only, no new constraints)".to_string() } else { format!(", narrowing scope: {joined}") }
            )
        };
        let mut hop = Map::new();
        hop.insert("index".into(), Value::from(i as i64));
        hop.insert("isRoot".into(), Value::Bool(is_root));
        if let Some(v) = issuer {
            hop.insert("issuer".into(), v.clone());
        }
        if let Some(v) = holder {
            hop.insert("holder".into(), v.clone());
        }
        hop.insert("scope".into(), Value::from(scope));
        hop.insert("caveats".into(), Value::Array(added.to_vec()));
        hop.insert("narrative".into(), Value::String(narrative));
        if let Some(b) = budget {
            hop.insert("budgetAlloc".into(), b["limit"].clone());
        }
        hops.push(Value::Object(hop));
    }
    hops
}

/// The signed co-signature (human override) of a PCActn's threshold signature, if any: (record, humanApproved).
fn build_human_override(threshold: R, required_tier: &Value, threshold_check: R) -> Option<(Value, bool)> {
    let shares: &[Value] = match (truthy(threshold), own(threshold, "shares")) {
        (true, Some(Value::Array(a))) => a.as_slice(),
        _ => &[],
    };
    if shares.is_empty() {
        return None;
    }
    // `threshold` is outside the signed body: never report a signed approval (or name approvers) from unverified shares.
    if !str_is(threshold_check, "pass") {
        let state = if nullish(threshold_check) { "absent".to_string() } else { tpl(threshold_check) };
        let narrative =
            format!("{} co-signature share(s) were presented but NOT verified (threshold check: {state}); no human approval is recorded.", shares.len());
        return Some((
            json!({ "humanApproved": false, "approvers": [], "guardianCosigners": [], "roles": [], "requiredTier": required_tier, "narrative": narrative }),
            false,
        ));
    }
    let (mut approvers, mut guardians, mut roles): (Vec<Value>, Vec<Value>, Vec<Value>) = (vec![], vec![], vec![]);
    for s in shares {
        if !truthy(Some(s)) {
            continue;
        }
        let role = match as_str(own(Some(s), "role")) {
            Some(r) => r,
            None => continue,
        };
        roles.push(Value::String(role.to_string()));
        let pk = own(Some(s), "publicKey");
        if role == "principal" && as_str(pk).is_some() {
            approvers.push(pk.cloned().unwrap_or(Value::Null));
        }
        if role == "guardian" && as_str(pk).is_some() {
            guardians.push(pk.cloned().unwrap_or(Value::Null));
        }
    }
    let approved = !approvers.is_empty();
    let tier = tpl(Some(required_tier));
    let narrative = if approved {
        format!(
            "Step-up approved by a signed human co-signature from principal {}{} at tier t={tier}.",
            short(approvers.first(), 12),
            if guardians.is_empty() { String::new() } else { format!(" (plus {} guardian co-sign)", guardians.len()) }
        )
    } else {
        format!("Co-signed by {} guardian share(s) at tier t={tier} (no human principal signature present).", guardians.len())
    };
    Some((
        json!({ "humanApproved": approved, "approvers": approvers, "guardianCosigners": guardians, "roles": roles, "requiredTier": required_tier, "narrative": narrative }),
        approved,
    ))
}

fn first_reason_or(decision: R, fallback: &str) -> Value {
    if let Some(Value::Array(rs)) = own(decision, "reasons") {
        if let Some(Value::String(s)) = rs.first() {
            return Value::String(s.clone());
        }
    }
    Value::String(fallback.to_string())
}

/// The auditor-facing outcome from the proof's verification and the Policy-VM decision.
fn resolve_outcome(verify: R, decision: R) -> (&'static str, Value) {
    if !truthy(verify) || own(verify, "allow") != Some(&Value::Bool(true)) {
        let r = qprop(verify, "reason");
        return ("deny", if nullish(r) { Value::String("proof failed verification".into()) } else { r.cloned().unwrap_or(Value::Null) });
    }
    if !truthy(decision) {
        return ("allow", Value::String("proof verified; no policy decision supplied".into()));
    }
    if truthy(own(decision, "admit")) {
        return ("allow", first_reason_or(decision, "auto-admitted within policy and budget"));
    }
    if truthy(own(decision, "releaseGuardianShare")) {
        return ("step-up", first_reason_or(decision, "policy satisfied but a co-signature is required"));
    }
    ("deny", first_reason_or(decision, "policy did not release authority (default-deny)"))
}

fn str_or(v: R, fallback: &str) -> Value {
    Value::String(as_str(v).unwrap_or(fallback).to_string())
}

/// A normalized AuditEvent from a PCActn, the core verifier's result and the Policy-VM decision. `input` is
/// `{pcactn, verify, decision?, now?, session?}`; `now` (epoch ms) defaults to the clock.
pub fn to_audit_event(input: Option<&Value>) -> Result<Value, String> {
    let p = prop(input, "pcactn")?;
    let default_verify = json!({ "allow": false, "checks": {} });
    let verify: R = match own(input, "verify") {
        v if !nullish(v) => v,
        _ => Some(&default_verify),
    };
    let decision = own(input, "decision");
    let now: Value = match own(input, "now") {
        v if !nullish(v) => v.cloned().unwrap_or(Value::Null),
        _ => now_ms(),
    };
    let chain: Option<&Vec<Value>> = match qprop(p, "cap_chain") {
        Some(Value::Array(a)) => Some(a),
        _ => None,
    };
    let hops = build_delegation_hops(chain.map(|c| c.as_slice()).unwrap_or(&[]));
    let leaf = chain.and_then(|c| c.last());
    let root = chain.and_then(|c| c.first());

    let (outcome, reason) = resolve_outcome(verify, decision);
    let tier = qprop(qprop(decision, "requiredThreshold"), "t");
    let required_tier: Value = if nullish(tier) { Value::from(1) } else { tier.cloned().unwrap_or(Value::Null) };
    let checks_raw = own(verify, "checks");
    let human = build_human_override(qprop(p, "threshold"), &required_tier, qprop(checks_raw, "threshold"));
    let empty_checks = json!({});
    let checks: &Value = if nullish(checks_raw) { &empty_checks } else { checks_raw.unwrap_or(&empty_checks) };
    let crypto_ok = str_is(own(Some(checks), "wire"), "pass") && str_is(own(Some(checks), "leaf_signature"), "pass");

    let action = qprop(p, "action");
    let verb = str_or(qprop(action, "verb"), "(unknown verb)");
    let resource = str_or(qprop(action, "resource"), "(unknown resource)");
    let grant_ref = str_or(qprop(p, "grant_ref"), "(none)");
    let digest = match p.and_then(hash_canonical_strict) {
        Some(d) => d,
        None => "(undigestible)".to_string(),
    };
    let counter = qprop(p, "counter");
    let mut evidence = Map::new();
    evidence.insert("pcactnDigest".into(), Value::String(digest));
    evidence.insert("leafSignature".into(), str_or(qprop(p, "sig"), "(unsigned)"));
    evidence.insert("signatureSuite".into(), str_or(qprop(p, "alg"), "ed25519"));
    evidence.insert("planRoot".into(), str_or(qprop(qprop(p, "plan"), "root"), "(none)"));
    evidence.insert("paramsDigest".into(), str_or(qprop(action, "params_digest"), "(none)"));
    evidence.insert("grantRef".into(), grant_ref.clone());
    evidence.insert("counter".into(), if is_num(counter) { counter.cloned().unwrap_or(Value::Null) } else { Value::from(-1) });
    evidence.insert("cryptographicallyVerifiable".into(), Value::Bool(crypto_ok));
    if let Some(n) = as_str(qprop(p, "nonce")) {
        evidence.insert("nonce".into(), Value::String(n.to_string()));
    }

    let mut risk = Map::new();
    if truthy(decision) {
        let rt = own(decision, "requiredThreshold");
        for (key, val) in [("r", own(decision, "r")), ("tier", qprop(rt, "t")), ("proof", qprop(rt, "proof")), ("budget", own(decision, "budget"))] {
            if let Some(v) = val {
                risk.insert(key.into(), v.clone());
            }
        }
    }

    let word = match outcome {
        "allow" => "ALLOWED",
        "deny" => "DENIED",
        _ => "STEP-UP",
    };
    let human_signed = human.as_ref().is_some_and(|h| h.1);
    let s = |v: &Value| v.as_str().unwrap_or("").to_string();
    let narrative = format!(
        "Agent {} {word} to {} on {} ({}-hop chain rooted at principal {}; {}{}). {}",
        short(qprop(leaf, "holder"), 12),
        s(&verb),
        s(&resource),
        hops.len(),
        short(qprop(root, "issuer"), 12),
        if crypto_ok { "cryptographically verifiable proof" } else { "proof not cryptographically verifiable" },
        if human_signed { "; human-signed step-up" } else { "" },
        tpl(Some(&reason))
    );

    let holder = qprop(leaf, "holder");
    let mut agent = Map::new();
    agent.insert("holder".into(), str_or(holder, "(none)"));
    if let Some(pr) = as_str(qprop(root, "issuer")) {
        agent.insert("principal".into(), Value::String(pr.to_string()));
    }
    let sess = own(input, "session");
    agent.insert("session".into(), if nullish(sess) { grant_ref.clone() } else { sess.cloned().unwrap_or(Value::Null) });

    let nan = num_val(f64::NAN);
    let time = |k: &str| match qprop(p, k) {
        Some(x) if x.is_number() => ts(x),
        _ => ts(&nan),
    };
    let mut event = Map::new();
    event.insert("schema".into(), json!("atlas-pca/audit-event/v1"));
    event.insert("recordedAt".into(), ts(&now));
    event.insert("agent".into(), Value::Object(agent));
    event.insert("delegation".into(), json!({ "depth": hops.len().saturating_sub(1), "hops": hops }));
    event.insert(
        "action".into(),
        json!({
            "verb": verb, "resource": resource, "paramsDigest": evidence["paramsDigest"],
            "reversibilityClass": str_or(qprop(action, "reversibility_class"), "(unknown)"),
            "summary": format!("{} on {}", s(&verb), s(&resource)),
        }),
    );
    event.insert(
        "decision".into(),
        json!({ "outcome": outcome, "reason": reason, "proofVerified": own(verify, "allow") == Some(&Value::Bool(true)), "checks": checks }),
    );
    event.insert("risk".into(), Value::Object(risk));
    event.insert("timestamps".into(), json!({ "issuedAt": time("iat"), "expiresAt": time("exp") }));
    event.insert("evidence".into(), Value::Object(evidence));
    event.insert("narrative".into(), Value::String(narrative));
    if let Some((h, _)) = human {
        event.insert("humanOverride".into(), h);
    }
    Ok(Value::Object(event))
}

// ---- control mappings -------------------------------------------------------------------------------------------------

struct Mapping {
    framework: &'static str,
    control_id: &'static str,
    control_title: &'static str,
    clause: &'static str,
    requirement: &'static str,
    pca_evidence: &'static str,
    evidence_fields: &'static [&'static str],
}

impl Mapping {
    fn to_value(&self) -> Value {
        json!({
            "framework": self.framework, "controlId": self.control_id, "controlTitle": self.control_title, "clause": self.clause,
            "requirement": self.requirement, "pcaEvidence": self.pca_evidence, "evidenceFields": self.evidence_fields,
        })
    }
}

static MAPPINGS: &[Mapping] = &[
    Mapping {
        framework: "eu-ai-act",
        control_id: "eu-ai-act:art-12",
        control_title: "Record-keeping — automatic, traceable logging of events",
        clause: "EU AI Act, Article 12",
        requirement: "High-risk AI systems must automatically record events (\"logs\") over their lifetime, enabling traceability of the system's functioning.",
        pca_evidence: "Every action is a signed PCActn; each log entry CITES its proof (the PCActn digest + the verifying leaf signature), so the record is tamper-evident and cannot be back-dated or fabricated.",
        evidence_fields: &["evidence.pcactnDigest", "evidence.leafSignature", "evidence.cryptographicallyVerifiable", "timestamps.issuedAt"],
    },
    Mapping {
        framework: "eu-ai-act",
        control_id: "eu-ai-act:art-50",
        control_title: "Transparency — disclosure of automated decisions and the acting agent",
        clause: "EU AI Act, Article 50",
        requirement: "Providers/deployers must ensure natural persons are informed that they are interacting with / affected by an AI system; interactions and automated decisions must be disclosed.",
        pca_evidence: "Each entry discloses the acting AGENT identity (leaf holder), the PRINCIPAL it acts for (root issuer), the exact action, and the automated decision outcome + reason — a complete, attributable disclosure per action.",
        evidence_fields: &["agent.holder", "agent.principal", "action.summary", "decision.outcome", "decision.reason"],
    },
    Mapping {
        framework: "iso-42001",
        control_id: "iso-42001:A.6.2.8",
        control_title: "Reasoning trace — AI system event logging",
        clause: "ISO/IEC 42001 Annex A.6.2.8 (AI system event logs / recording)",
        requirement: "The organization shall record events produced by the AI system so that its decisions can be examined and explained after the fact.",
        pca_evidence: "Each entry carries the Policy-VM decision with its decisive reason, the risk score r, the required tier and the trust-budget state — a complete, machine-checked reasoning trace, not a free-text note.",
        evidence_fields: &["decision.reason", "risk.r", "risk.tier", "risk.budget", "decision.checks"],
    },
    Mapping {
        framework: "iso-42001",
        control_id: "iso-42001:A.9.2",
        control_title: "Delegation & authorization chain",
        clause: "ISO/IEC 42001 Annex A.9.2 (authorization / responsible use of AI systems)",
        requirement: "Use of the AI system must be authorized; the authority under which an automated action is taken must be identifiable and bounded.",
        pca_evidence: "The delegation chain is EXPLICIT: each hop records issuer → holder and the scope (caveats) it narrowed, rooted at the principal — authority is attenuated and provable, never ambient.",
        evidence_fields: &["delegation.hops", "delegation.depth", "agent.principal", "delegation.hops[].scope"],
    },
    Mapping {
        framework: "iso-42001",
        control_id: "iso-42001:A.9.3",
        control_title: "Human oversight of AI systems",
        clause: "ISO/IEC 42001 Annex A.9.3 (human oversight)",
        requirement: "Mechanisms for human oversight of the AI system must exist and be exercised for higher-impact decisions.",
        pca_evidence: "Human oversight is a SIGNED CO-SIGNATURE: a step-up is approved by a principal threshold share naming the human approver (cryptographic, not a free-text \"approved by\"); denials and step-up requirements show the oversight boundary being enforced.",
        evidence_fields: &["humanOverride.humanApproved", "humanOverride.approvers", "decision.outcome", "risk.tier"],
    },
    Mapping {
        framework: "iso-42001",
        control_id: "iso-42001:A.6.2.2",
        control_title: "Intended use — action bound to a committed plan",
        clause: "ISO/IEC 42001 Annex A.6.2.2 (AI system requirements / intended purpose)",
        requirement: "The AI system must operate within its intended purpose; actions outside the specified scope must be prevented.",
        pca_evidence: "Every action proves inclusion in a committed plan (the signed plan root): an off-plan action fails verification. The plan root in each entry binds the action to its intended, pre-committed purpose.",
        evidence_fields: &["evidence.planRoot", "action.verb", "action.resource", "decision.checks"],
    },
    Mapping {
        framework: "soc2",
        control_id: "soc2:CC6.1",
        control_title: "Logical access security — least privilege",
        clause: "SOC 2 CC6.1",
        requirement: "The entity implements logical access controls to protect against unauthorized access, enforcing least privilege.",
        pca_evidence: "Access is deny-by-default: actions are constrained by signed predicates and capability attenuation. Denied entries evidence the control actively refusing out-of-scope access.",
        evidence_fields: &["decision.outcome", "delegation.hops[].scope", "decision.checks", "evidence.cryptographicallyVerifiable"],
    },
    Mapping {
        framework: "soc2",
        control_id: "soc2:CC6.2",
        control_title: "Registration & authorization of credentials / identities",
        clause: "SOC 2 CC6.2",
        requirement: "Prior to issuing access, the entity registers and authorizes new identities; access is traceable to an authorizing principal.",
        pca_evidence: "Each agent identity (leaf holder) is bound into a delegation chain rooted at an authorizing principal, with every hop signed — access is always traceable to who authorized it.",
        evidence_fields: &["agent.principal", "agent.holder", "delegation.hops", "evidence.grantRef"],
    },
    Mapping {
        framework: "soc2",
        control_id: "soc2:CC6.3",
        control_title: "Access modification & removal (attenuation / revocation)",
        clause: "SOC 2 CC6.3",
        requirement: "The entity modifies and removes access based on roles/need; access rights are narrowed or withdrawn appropriately.",
        pca_evidence: "Delegation is append-only attenuation: a child hop can only narrow scope, never widen it. Narrowing caveats per hop (and denied actions) evidence access being bounded and withdrawn.",
        evidence_fields: &["delegation.hops[].scope", "delegation.hops[].budgetAlloc", "decision.outcome"],
    },
];

/// `{COMPLIANCE_FRAMEWORKS, CONTROL_MAPPINGS}` of the reference.
pub fn constants() -> Value {
    json!({ "COMPLIANCE_FRAMEWORKS": COMPLIANCE_FRAMEWORKS, "CONTROL_MAPPINGS": MAPPINGS.iter().map(Mapping::to_value).collect::<Vec<_>>() })
}

fn assert_framework(framework: R) -> Result<String, String> {
    match as_str(framework) {
        Some(f) if COMPLIANCE_FRAMEWORKS.contains(&f) => Ok(f.to_string()),
        _ => Err(format!("pca-compliance: unknown framework '{}' (have: {})", tpl(framework), COMPLIANCE_FRAMEWORKS.join(", "))),
    }
}

/// The control mappings for a framework (`None` = undefined: the whole table).
pub fn control_mappings(framework: Option<&Value>) -> Result<Value, String> {
    match framework {
        None => Ok(Value::Array(MAPPINGS.iter().map(Mapping::to_value).collect())),
        f => {
            let fw = assert_framework(f)?;
            Ok(Value::Array(MAPPINGS.iter().filter(|m| m.framework == fw).map(Mapping::to_value).collect()))
        }
    }
}

// ---- ComplianceReport -------------------------------------------------------------------------------------------------

struct Stats {
    total: usize,
    verifiable: usize,
    denied: usize,
    step_up: usize,
    allowed: usize,
    human: usize,
    with_chain: usize,
    with_plan: usize,
    max_depth: Value,
    agents: usize,
    principals: usize,
    sample: Option<Value>,
}

fn compute_stats(events: &[&Value]) -> Result<Stats, String> {
    let (mut agents, mut principals) = (JsSet::default(), JsSet::default());
    let mut s = Stats {
        total: events.len(),
        verifiable: 0,
        denied: 0,
        step_up: 0,
        allowed: 0,
        human: 0,
        with_chain: 0,
        with_plan: 0,
        max_depth: Value::from(0),
        agents: 0,
        principals: 0,
        sample: None,
    };
    for e in events.iter().copied().map(Some) {
        if !truthy(e) {
            continue;
        }
        if truthy(prop(prop(e, "evidence")?, "cryptographicallyVerifiable")?) {
            s.verifiable += 1;
        }
        let outcome = prop(prop(e, "decision")?, "outcome")?;
        if str_is(outcome, "deny") {
            s.denied += 1;
        } else if str_is(outcome, "step-up") {
            s.step_up += 1;
        } else {
            s.allowed += 1;
        }
        if truthy(qprop(own(e, "humanOverride"), "humanApproved")) {
            s.human += 1;
        }
        if length(prop(prop(e, "delegation")?, "hops")?)?.is_some_and(|n| n > 0) {
            s.with_chain += 1;
        }
        if !str_is(prop(prop(e, "evidence")?, "planRoot")?, "(none)") {
            s.with_plan += 1;
        }
        if let Some(d) = prop(prop(e, "delegation")?, "depth")? {
            if gt(d, &s.max_depth) {
                s.max_depth = d.clone();
            }
        }
        let agent = prop(e, "agent")?;
        agents.add(prop(agent, "holder")?);
        let principal = prop(agent, "principal")?;
        if principal.is_some() {
            principals.add(principal);
        }
        let digest = prop(prop(e, "evidence")?, "pcactnDigest")?;
        if s.sample.is_none() && !str_is(digest, "(undigestible)") {
            s.sample = digest.cloned();
        }
    }
    s.agents = agents.size();
    s.principals = principals.size();
    Ok(s)
}

fn evaluate_control(control_id: &str, s: &Stats) -> (&'static str, String, Vec<String>) {
    let mut findings: Vec<String> = Vec::new();
    let total = s.total;
    if total == 0 {
        return ("not-evidenced", "no actions in the reporting period".into(), vec!["no events supplied — nothing to evidence".into()]);
    }
    let tri = |n: usize| {
        if n == total {
            "satisfied"
        } else if n > 0 {
            "partial"
        } else {
            "not-evidenced"
        }
    };
    match control_id {
        "eu-ai-act:art-12" => {
            let digest_note = s.sample.as_ref().map(|d| format!(" (e.g. {})", short(Some(d), 16))).unwrap_or_default();
            if s.verifiable < total {
                findings.push(format!("{} of {total} entries are not cryptographically verifiable", total - s.verifiable));
            }
            (
                if s.verifiable == total { "satisfied" } else { "partial" },
                format!("{total} actions logged; {}/{total} cite a cryptographically verifiable proof{digest_note}", s.verifiable),
                findings,
            )
        }
        "eu-ai-act:art-50" => (
            "satisfied",
            format!("{total} actions each disclose the acting agent, the principal ({} distinct) and the automated decision outcome", s.principals),
            findings,
        ),
        "iso-42001:A.6.2.8" => ("satisfied", format!("{total} actions each carry a decision reason + risk/tier/budget reasoning trace"), findings),
        "iso-42001:A.9.2" => {
            if s.with_chain < total {
                findings.push(format!("{} entries have no delegation chain", total - s.with_chain));
            }
            (
                tri(s.with_chain),
                format!(
                    "{}/{total} actions carry an explicit delegation chain (max depth {}, {} authorizing principal(s))",
                    s.with_chain,
                    tpl(Some(&s.max_depth)),
                    s.principals
                ),
                findings,
            )
        }
        "iso-42001:A.9.3" => {
            if s.human > 0 {
                (
                    "satisfied",
                    format!(
                        "{} step-up(s) approved by a signed human co-signature; {} step-up(s) and {} denial(s) show oversight enforced",
                        s.human, s.step_up, s.denied
                    ),
                    findings,
                )
            } else if s.step_up > 0 || s.denied > 0 {
                findings.push("no human step-up co-signature was exercised in this period".into());
                (
                    "partial",
                    format!(
                        "oversight boundary enforced ({} step-up(s), {} denial(s)) but no signed human co-signature observed in the period",
                        s.step_up, s.denied
                    ),
                    findings,
                )
            } else {
                findings.push("no higher-impact action required human oversight in this period".into());
                ("partial", "all actions were auto-admitted within policy; no oversight event was triggered in the period".into(), findings)
            }
        }
        "iso-42001:A.6.2.2" => {
            if s.with_plan < total {
                findings.push(format!("{} entries are not bound to a committed plan root", total - s.with_plan));
            }
            (tri(s.with_plan), format!("{}/{total} actions are bound to a committed plan root (intended-use binding)", s.with_plan), findings)
        }
        "soc2:CC6.1" => {
            if s.denied > 0 {
                findings.push(format!("{} out-of-scope action(s) denied — access control actively enforced", s.denied));
            }
            (
                "satisfied",
                format!(
                    "deny-by-default access over {total} actions ({} allowed, {} step-up, {} denied); all gated by signed predicates + attenuation",
                    s.allowed, s.step_up, s.denied
                ),
                findings,
            )
        }
        "soc2:CC6.2" => {
            if s.with_chain < total {
                findings.push(format!("{} entries are not traceable to an authorizing principal", total - s.with_chain));
            }
            (
                tri(s.with_chain),
                format!("{} agent identit(ies) traceable to {} authorizing principal(s) via signed delegation chains", s.agents, s.principals),
                findings,
            )
        }
        "soc2:CC6.3" => {
            let narrowed = to_number(Some(&s.max_depth)) >= 1.0;
            if !narrowed && s.denied == 0 {
                findings.push("no attenuating hop or denial observed in the period".into());
            }
            (
                if narrowed || s.denied > 0 { "satisfied" } else { "partial" },
                format!("access narrowed by attenuation (max delegation depth {}) and {} denied action(s)", tpl(Some(&s.max_depth)), s.denied),
                findings,
            )
        }
        _ => ("not-evidenced", "no evaluator for this control".into(), vec!["unmapped control".into()]),
    }
}

/// A structured ComplianceReport for `opts.framework` from AuditEvents: per-control status + evidence, the PCA-unique assurances and a
/// coverage summary. `opts.now` (epoch ms) defaults to the clock.
pub fn to_compliance_report(events: Option<&Value>, opts: Option<&Value>) -> Result<Value, String> {
    let framework = assert_framework(prop(opts, "framework")?)?;
    let list: Vec<&Value> = match events {
        Some(Value::Array(a)) => a.iter().filter(|e| truthy(Some(*e))).collect(),
        _ => vec![],
    };
    let now: Value = match own(opts, "now") {
        v if !nullish(v) => v.cloned().unwrap_or(Value::Null),
        _ => now_ms(),
    };
    let s = compute_stats(&list)?;
    let mut items: Vec<Value> = Vec::new();
    let (mut satisfied, mut partial, mut not_evidenced) = (0usize, 0usize, 0usize);
    for m in MAPPINGS.iter().filter(|m| m.framework == framework) {
        let (status, evidence, findings) = evaluate_control(m.control_id, &s);
        match status {
            "satisfied" => satisfied += 1,
            "partial" => partial += 1,
            _ => not_evidenced += 1,
        }
        items.push(json!({
            "controlId": m.control_id, "controlTitle": m.control_title, "clause": m.clause, "framework": m.framework,
            "status": status, "pcaEvidence": m.pca_evidence, "evidence": evidence, "findings": findings,
        }));
    }
    let total = items.len();
    let fraction = if total > 0 { satisfied as f64 / total as f64 } else { 0.0 };
    let mut iats: Vec<f64> = Vec::new();
    for e in &list {
        if let Some(f) = finite_num(prop(prop(prop(Some(*e), "timestamps")?, "issuedAt")?, "epochMs")?) {
            iats.push(f);
        }
    }
    let (from, to) =
        if iats.is_empty() { (0.0, 0.0) } else { (iats.iter().copied().fold(f64::INFINITY, f64::min), iats.iter().copied().fold(f64::NEG_INFINITY, f64::max)) };
    let st = s.total;
    let narrative = if st == 0 {
        "No events in scope.".to_string()
    } else {
        format!(
            "{}/{st} entries cite a cryptographically verifiable proof; {}/{st} carry an explicit delegation chain; {} step-up(s) carry a signed human co-signature.",
            s.verifiable, s.with_chain, s.human
        )
    };
    let summary = format!(
        "{framework}: {satisfied}/{total} controls satisfied{}{} over {st} action(s).",
        if partial > 0 { format!(", {partial} partial") } else { String::new() },
        if not_evidenced > 0 { format!(", {not_evidenced} not evidenced") } else { String::new() }
    );
    let all_verifiable = st > 0 && s.verifiable == st;
    let all_chain = st > 0 && s.with_chain == st;
    let any_human = s.human > 0;
    let generated = ts(&now);
    let (period_from, period_to) = (ts(&num_val(from)), ts(&num_val(to)));
    let (fraction_v, percent_v) = (num_val(fraction), num_val(js_round(fraction * 100.0)));
    Ok(json!({
        "schema": "atlas-pca/compliance-report/v1",
        "framework": framework,
        "generatedAt": generated,
        "period": { "from": period_from, "to": period_to },
        "eventCount": st,
        "assurances": {
            "cryptographicallyVerifiable": all_verifiable,
            "explicitDelegationChain": all_chain,
            "signedHumanOverrides": any_human,
            "narrative": narrative,
        },
        "items": items,
        "coverage": {
            "total": total, "satisfied": satisfied, "partial": partial, "notEvidenced": not_evidenced,
            "satisfiedFraction": fraction_v, "satisfiedPercent": percent_v,
        },
        "summary": summary,
    }))
}

// ---- renderers --------------------------------------------------------------------------------------------------------

/// The report as stable, pretty JSON (`JSON.stringify(report, null, 2)`); `JSON.stringify(undefined)` is an `Err`.
pub fn render_json(report: Option<&Value>) -> Result<String, String> {
    let r = report.ok_or("renderJson: undefined is not JSON")?;
    let mut out = String::new();
    pretty(r, "", &mut out);
    Ok(out)
}

fn upper(v: R) -> Result<String, String> {
    as_str(v).map(str::to_uppercase).ok_or_else(|| "toUpperCase is not a function".to_string())
}

fn glyph(status: R) -> &'static str {
    match as_str(status) {
        Some("satisfied") => "✓",
        Some("partial") => "◐",
        Some("not-evidenced") => "·",
        _ => "undefined",
    }
}

fn walk<'a>(r: R<'a>, path: &[&str]) -> Result<R<'a>, String> {
    let mut o = r;
    for k in path {
        o = prop(o, k)?;
    }
    Ok(o)
}

/// The report as an auditor-facing Markdown document (admissibility assurances, coverage, control table and detail).
pub fn render_markdown(report: Option<&Value>) -> Result<String, String> {
    let g = |path: &[&str]| walk(report, path);
    let yes = |path: &[&str], no: &str| -> Result<String, String> { Ok(if truthy(g(path)?) { "YES".to_string() } else { no.to_string() }) };
    let mut l: Vec<String> = Vec::new();
    l.push(format!("# PCA compliance evidence — {}", tpl(g(&["framework"])?)));
    l.push(String::new());
    l.push(format!(
        "Generated {} · {} action(s) · coverage: {}/{} satisfied ({}%)",
        tpl(g(&["generatedAt", "iso"])?),
        tpl(g(&["eventCount"])?),
        tpl(g(&["coverage", "satisfied"])?),
        tpl(g(&["coverage", "total"])?),
        tpl(g(&["coverage", "satisfiedPercent"])?)
    ));
    if to_number(g(&["eventCount"])?) > 0.0 {
        l.push(String::new());
        l.push(format!("Reporting period: {} → {}", tpl(g(&["period", "from", "iso"])?), tpl(g(&["period", "to", "iso"])?)));
    }
    l.push(String::new());
    l.push("## Why this trail is admissible (what PCA uniquely provides)".into());
    l.push(String::new());
    l.push(format!(
        "- **Cryptographically verifiable** — {}: every log entry cites its proof (the PCActn digest + the verifying leaf signature), so it is tamper-evident and cannot be back-dated.",
        yes(&["assurances", "cryptographicallyVerifiable"], "PARTIAL")?
    ));
    l.push(format!(
        "- **Explicit delegation chain** — {}: each action records who authorized what scope, hop by hop, rooted at a principal.",
        yes(&["assurances", "explicitDelegationChain"], "PARTIAL")?
    ));
    l.push(format!(
        "- **Signed human-overrides** — {}: a step-up approval is a principal threshold co-signature naming the human approver, not a free-text note.",
        yes(&["assurances", "signedHumanOverrides"], "none in period")?
    ));
    l.push(String::new());
    l.push(format!("> {}", tpl(g(&["assurances", "narrative"])?)));
    l.push(String::new());
    l.push("## Coverage summary".into());
    l.push(String::new());
    l.push("| Satisfied | Partial | Not evidenced | Total |".into());
    l.push("| --- | --- | --- | --- |".into());
    l.push(format!(
        "| {} | {} | {} | {} |",
        tpl(g(&["coverage", "satisfied"])?),
        tpl(g(&["coverage", "partial"])?),
        tpl(g(&["coverage", "notEvidenced"])?),
        tpl(g(&["coverage", "total"])?)
    ));
    l.push(String::new());
    l.push("## Controls".into());
    l.push(String::new());
    l.push("| Control | Clause | Status | Evidence in period |".into());
    l.push("| --- | --- | --- | --- |".into());
    let items: Vec<R> = match g(&["items"])? {
        Some(Value::Array(a)) => a.iter().map(Some).collect(),
        Some(Value::String(s)) if s.is_empty() => vec![],
        _ => return Err("r.items is not iterable".into()),
    };
    for i in &items {
        l.push(format!(
            "| {} (`{}`) | {} | {} {} | {} |",
            tpl(prop(*i, "controlTitle")?),
            tpl(prop(*i, "controlId")?),
            tpl(prop(*i, "clause")?),
            glyph(prop(*i, "status")?),
            upper(prop(*i, "status")?)?,
            tpl(prop(*i, "evidence")?)
        ));
    }
    l.push(String::new());
    l.push("## Control detail".into());
    l.push(String::new());
    for i in &items {
        l.push(format!("### {} — {}", tpl(prop(*i, "controlId")?), tpl(prop(*i, "controlTitle")?)));
        l.push(String::new());
        l.push(format!("- Clause: {}", tpl(prop(*i, "clause")?)));
        l.push(format!("- Status: {} {}", glyph(prop(*i, "status")?), upper(prop(*i, "status")?)?));
        l.push(format!("- PCA evidence basis: {}", tpl(prop(*i, "pcaEvidence")?)));
        l.push(format!("- Evidence in period: {}", tpl(prop(*i, "evidence")?)));
        let findings = prop(*i, "findings")?;
        if length(findings)?.is_some_and(|n| n > 0) {
            l.push("- Findings:".into());
            match findings {
                Some(Value::Array(a)) => a.iter().for_each(|f| l.push(format!("  - {}", tpl(Some(f))))),
                Some(Value::String(s)) => s.chars().for_each(|c| l.push(format!("  - {c}"))),
                _ => {}
            }
        }
        l.push(String::new());
    }
    l.push("---".into());
    l.push(String::new());
    l.push("_Evidence mapping, not a legal certification: a `satisfied` status means the cryptographic evidence the control asks for is present in the supplied records._".into());
    Ok(l.join("\n"))
}

// ---- framework report (console activity stream) ------------------------------------------------------------------------

struct Summary {
    total: usize,
    autonomous: usize,
    human_overseen: usize,
    denied: usize,
    agents: usize,
    bound: f64,
    max_taint: f64,
}

fn base_summary(input: R) -> Result<(Summary, Vec<f64>), String> {
    let events = prop(input, "events")?;
    let p = prop(prop(input, "policy")?, "riskPolicy")?;
    let events: &[Value] = match events {
        Some(Value::Array(a)) => a,
        _ => return Err("e.filter is not a function".into()),
    };
    let (mut autonomous, mut step_up, mut denied, mut max_taint) = (0usize, 0usize, 0usize, 0.0f64);
    let mut agents = JsSet::default();
    for x in events.iter().map(Some) {
        let o = prop(x, "outcome")?;
        if str_is(o, "auto") || str_is(o, "executed") {
            autonomous += 1;
        }
        if str_is(o, "step_up") {
            step_up += 1;
        }
        if str_is(o, "deny") {
            denied += 1;
        }
        // a taint that is present but not a finite number is unknown, and unknown counts as the worst case
        let t = prop(x, "taint")?;
        let v = if t.is_none() { 0.0 } else { finite_num(t).unwrap_or(f64::INFINITY) };
        max_taint = max_taint.max(v);
        agents.add(prop(x, "agent")?);
    }
    let dec = qprop(input, "decisions");
    let dlen = if nullish(dec) { 0 } else { length(dec)?.unwrap_or(0) };
    let (kappa, b_max) = (prop(p, "kappa")?, prop(p, "bMax")?);
    let kn = to_number(kappa);
    let safety = if kn > 0.0 {
        let b = to_number(b_max);
        (if b.is_nan() { f64::NAN } else { b.max(0.0) }) / kn
    } else {
        0.0
    };
    let mut ats = Vec::new();
    for e in events.iter().map(Some) {
        if let Some(f) = finite_num(prop(e, "at")?) {
            ats.push(f);
        }
    }
    Ok((Summary { total: events.len(), autonomous, human_overseen: step_up + dlen, denied, agents: agents.size(), bound: safety * kn, max_taint }, ats))
}

fn ctl(id: &str, name: &str, ok: bool, evidence: String) -> Value {
    let status = if ok { "pass" } else { "warn" };
    json!({ "id": id, "name": name, "status": status, "evidence": evidence })
}

/// A compliance evidence report for a framework from the console activity stream: `input` is
/// `{policy, events, decisions?, hasGoalCommitment?, erasureSupported?}`. `now` (epoch ms) defaults to the clock when undefined.
pub fn framework_report(framework: Option<&Value>, input: Option<&Value>, now: Option<&Value>) -> Result<Value, String> {
    let (s, ats) = base_summary(input)?;
    let fw = match as_str(framework) {
        Some(f) if FRAMEWORK_IDS.contains(&f) => f,
        _ => return Err(format!("frameworkReport: unknown framework '{}' (have: {})", tpl(framework), FRAMEWORK_IDS.join(", "))),
    };
    let goal = truthy(own(input, "hasGoalCommitment"));
    let erasure = truthy(own(input, "erasureSupported"));
    let bound = js_number_string(s.bound);
    let controls: Vec<Value> = match fw {
        "eu-ai-act" => {
            let robust = if s.bound.is_finite() { "pass" } else { "fail" };
            vec![
                ctl("art12-record-keeping", "Automatic logging of events", s.total > 0, format!("{} attributable actions recorded", s.total)),
                ctl(
                    "art14-human-oversight",
                    "Human oversight",
                    s.human_overseen > 0 || s.bound.is_finite(),
                    format!("{} human-reviewed actions; autonomous bound {bound}", s.human_overseen),
                ),
                json!({ "id": "art15-robustness", "name": "Bounded autonomy (accuracy/robustness)", "status": robust, "evidence": format!("machine-checked safety bound = {bound} between human co-signs") }),
                ctl(
                    "art13-transparency",
                    "Transparency / traceability",
                    goal,
                    if goal { "every action binds to a signed goal commitment (lineage)".into() } else { "no goal commitment supplied".into() },
                ),
            ]
        }
        "soc2" => {
            let constrained = matches!(qprop(own(input, "policy"), "predicates"), Some(Value::Array(a)) if !a.is_empty());
            let note = if constrained { None } else { Some("the supplied policy lists no predicates") };
            vec![
                ctl(
                    "cc6.1-access",
                    "Logical access — least privilege",
                    constrained,
                    note.unwrap_or("actions constrained by signed predicates + capability attenuation (deny by default)").into(),
                ),
                ctl(
                    "cc7.2-monitoring",
                    "Monitoring of anomalies",
                    s.total > 0,
                    format!("{} denied + {} escalated actions captured", s.denied, s.human_overseen),
                ),
                ctl("cc7.3-audit-trail", "Audit trail", s.total > 0, format!("{} content-addressed actions across {} agents", s.total, s.agents)),
                ctl(
                    "cc8.1-change",
                    "Change management (policy integrity)",
                    constrained,
                    note.unwrap_or("policy is signed into the grant; tampering breaks verification").into(),
                ),
            ]
        }
        _ => vec![
            ctl(
                "art5-purpose",
                "Purpose limitation",
                goal,
                if goal { "actions bound to a committed goal/purpose".into() } else { "no goal commitment supplied".into() },
            ),
            ctl(
                "art5-minimization",
                "Data minimisation",
                s.total > 0,
                format!("taint-gated data flows; max taint observed = {}", js_number_string(s.max_taint)),
            ),
            ctl("art5-accountability", "Accountability", s.agents > 0, format!("{} attributable agent identities", s.agents)),
            ctl("art17-erasure", "Right to erasure", erasure, if erasure { "erasure path wired".into() } else { "erasure path not asserted".into() }),
        ],
    };
    let pass = controls.iter().all(|c| c["status"] != "fail");
    let (from, to) =
        if ats.is_empty() { (0.0, 0.0) } else { (ats.iter().copied().fold(f64::INFINITY, f64::min), ats.iter().copied().fold(f64::NEG_INFINITY, f64::max)) };
    let generated = match now {
        Some(v) => v.clone(),
        None => now_ms(),
    };
    let summary = json!({
        "totalActions": s.total, "autonomous": s.autonomous, "humanOverseen": s.human_overseen, "denied": s.denied,
        "attributableAgents": s.agents, "autonomousBound": num_val(s.bound), "maxTaintObserved": num_val(s.max_taint),
    });
    Ok(json!({
        "framework": fw,
        "generatedAt": generated,
        "period": { "from": num_val(from), "to": num_val(to) },
        "summary": summary,
        "controls": controls,
        "pass": pass,
    }))
}

/// A short Markdown block of a framework report, for an audit package.
pub fn framework_report_to_markdown(report: Option<&Value>) -> Result<String, String> {
    let generated = match prop(report, "generatedAt")? {
        None => return Err("Invalid time value".into()),
        Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(_) => return Err("generatedAt is not a number".into()),
    };
    let stamp = iso_string(generated).ok_or("Invalid time value")?;
    let summary = prop(report, "summary")?;
    let total = tpl(prop(summary, "totalActions")?);
    let agents = tpl(prop(summary, "attributableAgents")?);
    let pass = truthy(prop(report, "pass")?);
    let fw = tpl(prop(report, "framework")?);
    let controls = match prop(report, "controls")? {
        Some(Value::Array(a)) => a,
        _ => return Err("r.controls.map is not a function".into()),
    };
    let mut l = vec![
        format!("# PCA compliance evidence — {fw}"),
        String::new(),
        format!("Generated {stamp} · {total} actions · {agents} agents · overall: {}", if pass { "PASS" } else { "FAIL" }),
        String::new(),
        "| Control | Status | Evidence |".to_string(),
        "| --- | --- | --- |".to_string(),
    ];
    for c in controls.iter().map(Some) {
        l.push(format!("| {} ({}) | {} | {} |", tpl(prop(c, "name")?), tpl(prop(c, "id")?), upper(prop(c, "status")?)?, tpl(prop(c, "evidence")?)));
    }
    l.push(String::new());
    l.push("_Evidence mapping, not a legal certification._".into());
    Ok(l.join("\n"))
}
