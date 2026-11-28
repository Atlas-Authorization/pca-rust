//! SIEM export of PCA authorization decisions: OCSF 1.x Authorize Session, ArcSight CEF and Elastic Common Schema events plus
//! fail-safe sinks. JSON-valued (a decision record is `{pcactn, verify, decision?, now?, session?}`), byte-identical to the reference
//! including its string / number / Date quirks (UTF-16 lengths, number formatting, `toISOString`). Shipping an event to a SIEM never
//! raises into the caller: sink errors are caught, scrubbed of credentials, reported through `on_error` and returned.
//!
//! shortcut: `now` is an optional epoch-ms number (the reference also accepts a clock function), and a slice that would cut a UTF-16
//! surrogate pair in half yields U+FFFD (a Rust string cannot hold a lone surrogate).
use crate::intent_v2::js_value_string;
use regex::Regex;
use serde_json::{Map, Value};
use std::sync::{mpsc, Arc, OnceLock};
use std::time::Duration;

pub const OCSF_SCHEMA_VERSION: &str = "1.1.0";
pub const ECS_VERSION: &str = "8.11.0";
pub const SECURITY_CHECKS: [&str; 9] = ["wire", "version", "audience", "validity", "cap_chain", "plan_inclusion", "leaf_signature", "counter_format", "replay"];

/// JS `undefined` is `None`; JSON null is `Some(Value::Null)`.
type U = Option<Value>;

// (OCSF id, OCSF label, CEF/ECS 0-10 scale)
type Sev = (i64, &'static str, i64);
const SEV_INFO: Sev = (1, "Informational", 1);
const SEV_LOW: Sev = (2, "Low", 3);
const SEV_MEDIUM: Sev = (3, "Medium", 5);
const SEV_HIGH: Sev = (4, "High", 8);

// ---- JS helpers ------------------------------------------------------------------------------------------------------

fn get(o: &U, k: &str) -> U {
    match o {
        Some(Value::Object(m)) => m.get(k).cloned(),
        _ => None,
    }
}

fn nullish(v: &U) -> bool {
    matches!(v, None | Some(Value::Null))
}

fn truthy(v: &U) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// `typeof v === "string" && v.length > 0 ? v : fallback`
fn str_or(v: &U, fallback: &str) -> String {
    match v {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => fallback.to_string(),
    }
}

fn finite(v: &U) -> U {
    match v {
        Some(Value::Number(n)) if n.as_f64().is_some_and(f64::is_finite) => v.clone(),
        _ => None,
    }
}

fn num_eq(v: &U, x: f64) -> bool {
    matches!(v, Some(Value::Number(n)) if n.as_f64() == Some(x))
}

fn str_eq(v: &U, s: &str) -> bool {
    matches!(v, Some(Value::String(t)) if t == s)
}

fn u16len(s: &str) -> usize {
    s.encode_utf16().count()
}

fn u16slice(s: &str, n: usize) -> String {
    let u: Vec<u16> = s.encode_utf16().take(n).collect();
    String::from_utf16_lossy(&u)
}

/// `Object.entries` over any JSON value.
fn entries(x: &Value) -> Vec<(String, Value)> {
    match x {
        Value::Object(m) => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        Value::Array(a) => a.iter().enumerate().map(|(i, v)| (i.to_string(), v.clone())).collect(),
        Value::String(s) => s.encode_utf16().enumerate().map(|(i, c)| (i.to_string(), Value::String(String::from_utf16_lossy(&[c])))).collect(),
        _ => vec![],
    }
}

fn s2v(s: &str) -> Value {
    Value::String(s.to_string())
}

fn n2v(n: i64) -> Value {
    Value::from(n)
}

/// An object from (key, value) pairs; an `undefined` value is dropped (JSON.stringify / the reference's prune).
fn obj(items: Vec<(&str, U)>) -> Value {
    let mut m = Map::new();
    for (k, v) in items {
        if let Some(v) = v {
            m.insert(k.to_string(), v);
        }
    }
    Value::Object(m)
}

fn some(v: Value) -> U {
    Some(v)
}

/// `new Date(ms).toISOString()`, or the epoch when `ms` is not a valid time value.
fn iso(ms: &Value) -> String {
    let epoch = "1970-01-01T00:00:00.000Z".to_string();
    let f = match ms {
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        _ => return epoch,
    };
    if !f.is_finite() || f.abs() > 8.64e15 {
        return epoch;
    }
    let t = f.trunc() as i64;
    let days = t.div_euclid(86_400_000);
    let rem = t.rem_euclid(86_400_000);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    let ys = if (0..=9999).contains(&y) { format!("{y:04}") } else { format!("{}{:06}", if y < 0 { '-' } else { '+' }, y.abs()) };
    let (h, rem) = (rem / 3_600_000, rem % 3_600_000);
    let (mi, rem) = (rem / 60_000, rem % 60_000);
    format!("{ys}-{m:02}-{d:02}T{h:02}:{mi:02}:{:02}.{:03}Z", rem / 1000, rem % 1000)
}

fn short_key(key: Option<&str>) -> String {
    match key {
        Some(k) if !k.is_empty() => {
            if u16len(k) <= 13 {
                k.to_string()
            } else {
                format!("{}\u{2026}", u16slice(k, 12))
            }
        }
        _ => "(none)".to_string(),
    }
}

fn safe_digest(p: &U) -> String {
    p.as_ref().and_then(crate::hash_canonical_strict).unwrap_or_else(|| "(undigestible)".to_string())
}

// ---- normalization ---------------------------------------------------------------------------------------------------

struct Hop {
    index: i64,
    is_root: bool,
    issuer: String,
    holder: String,
    added_caveats: i64,
}

struct Norm {
    now: Value,
    outcome: &'static str,
    reason: String,
    crypto: bool,
    checks: Value,
    agent_holder: String,
    principal: Option<String>,
    session: String,
    hops: Vec<Hop>,
    depth: i64,
    chain_string: String,
    verb: String,
    resource: String,
    params_digest: String,
    reversibility: String,
    grant_ref: String,
    counter: Value,
    nonce: U,
    plan_root: String,
    suite: String,
    leaf_sig: String,
    proof_digest: String,
    risk_score: U,
    tier: U,
    proof_strength: U,
    caution: U,
    bond_ref: U,
    human_approved: bool,
    approvers: Vec<Value>,
    guardians: Vec<Value>,
    roles: Vec<Value>,
    severity: Sev,
    iat: Value,
    exp: Value,
}

fn first_reason_or(decision: &U, fallback: &str) -> String {
    let first = match get(decision, "reasons") {
        Some(Value::Array(a)) => a.first().cloned(),
        _ => None,
    };
    str_or(&first, fallback)
}

fn resolve_outcome(verify: &U, decision: &U) -> (&'static str, String) {
    if !truthy(verify) || get(verify, "allow") != Some(Value::Bool(true)) {
        return ("deny", str_or(&get(verify, "reason"), "proof failed verification"));
    }
    if !truthy(decision) {
        return ("allow", "proof verified; no policy decision supplied".to_string());
    }
    if truthy(&get(decision, "admit")) {
        return ("allow", first_reason_or(decision, "auto-admitted within policy and budget"));
    }
    if truthy(&get(decision, "releaseGuardianShare")) {
        return ("step-up", first_reason_or(decision, "policy satisfied but a co-signature is required"));
    }
    ("deny", first_reason_or(decision, "policy did not release authority (default-deny)"))
}

fn build_hops(chain: &[Value]) -> Vec<Hop> {
    let mut hops = Vec::new();
    for (i, cap) in chain.iter().enumerate() {
        let cap = Some(cap.clone());
        if !truthy(&cap) {
            continue;
        }
        let parent: U = if i > 0 { Some(chain[i - 1].clone()) } else { None };
        let parent_len = if truthy(&parent) { arr_len(&get(&parent, "caveats")) } else { 0 };
        let own_len = arr_len(&get(&cap, "caveats"));
        let added = if i == 0 { own_len } else { (own_len - parent_len).max(0) };
        hops.push(Hop {
            index: i as i64,
            is_root: i == 0,
            issuer: str_or(&get(&cap, "issuer"), "(none)"),
            holder: str_or(&get(&cap, "holder"), "(none)"),
            added_caveats: added,
        });
    }
    hops
}

fn arr_len(v: &U) -> i64 {
    match v {
        Some(Value::Array(a)) => a.len() as i64,
        _ => 0,
    }
}

type Override = (bool, Vec<Value>, Vec<Value>, Vec<Value>);

fn read_override(threshold: &U, threshold_check: &U) -> Override {
    let shares: Vec<Value> = match if truthy(threshold) { get(threshold, "shares") } else { None } {
        Some(Value::Array(a)) => a,
        _ => vec![],
    };
    // threshold sits outside the signed body: its shares prove nothing until a threshold verifier passed
    if !str_eq(threshold_check, "pass") {
        return (false, vec![], vec![], vec![]);
    }
    let (mut approvers, mut guardians, mut roles) = (vec![], vec![], vec![]);
    for s in shares {
        let s = Some(s);
        let role = match get(&s, "role") {
            Some(Value::String(r)) if truthy(&s) => r,
            _ => continue,
        };
        roles.push(s2v(&role));
        if let Some(pk @ Value::String(_)) = get(&s, "publicKey") {
            if role == "principal" {
                approvers.push(pk.clone());
            }
            if role == "guardian" {
                guardians.push(pk);
            }
        }
    }
    (!approvers.is_empty(), approvers, guardians, roles)
}

fn severity_for(outcome: &str, checks: &U, tier: &U) -> Sev {
    if outcome == "deny" {
        return if SECURITY_CHECKS.iter().any(|k| str_eq(&get(checks, k), "fail")) { SEV_HIGH } else { SEV_MEDIUM };
    }
    if outcome == "step-up" {
        return SEV_MEDIUM;
    }
    if num_eq(tier, 3.0) {
        SEV_MEDIUM
    } else if num_eq(tier, 2.0) {
        SEV_LOW
    } else {
        SEV_INFO
    }
}

fn shown_signature(sig: &str, mode: &U) -> String {
    if str_eq(mode, "full") {
        return sig.to_string();
    }
    if str_eq(mode, "omit") {
        return "(omitted)".to_string();
    }
    if u16len(sig) <= 16 {
        sig.to_string()
    } else {
        format!("{}\u{2026}", u16slice(sig, 16))
    }
}

fn now_ms(now: Option<f64>) -> Value {
    let ms = now.unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as f64).unwrap_or(0.0));
    if ms.fract() == 0.0 && ms.abs() < 9e15 {
        Value::from(ms as i64)
    } else {
        serde_json::Number::from_f64(ms).map(Value::Number).unwrap_or(Value::from(0))
    }
}

fn normalize(record: &Value, opts: &U, now: Option<f64>) -> Result<Norm, String> {
    if record.is_null() {
        return Err("record is required".into());
    }
    let rec = Some(record.clone());
    let p = get(&rec, "pcactn");
    let verify: U = match get(&rec, "verify") {
        v if nullish(&v) => Some(obj(vec![("allow", some(Value::Bool(false))), ("checks", some(Value::Object(Map::new())))])),
        v => v,
    };
    let checks_u: U = match get(&verify, "checks") {
        c if nullish(&c) => Some(Value::Object(Map::new())),
        c => c,
    };
    let n_now = finite(&get(&rec, "now")).unwrap_or_else(|| now_ms(now));
    let chain: Vec<Value> = match get(&p, "cap_chain") {
        Some(Value::Array(a)) => a,
        _ => vec![],
    };
    let hops = build_hops(&chain);
    let leaf: U = chain.last().cloned();
    let root: U = chain.first().cloned();

    let decision = get(&rec, "decision");
    let (outcome, reason) = resolve_outcome(&verify, &decision);
    let rt = get(&decision, "requiredThreshold");
    let tier = get(&rt, "t");
    let (human_approved, approvers, guardians, roles) = read_override(&get(&p, "threshold"), &get(&checks_u, "threshold"));

    let grant_ref = str_or(&get(&p, "grant_ref"), "(none)");
    let agent_holder = str_or(&get(&leaf, "holder"), "(none)");
    let principal = match get(&root, "issuer") {
        Some(Value::String(s)) if !s.is_empty() => Some(s),
        _ => None,
    };
    let mut parts = vec![short_key(Some(principal.as_deref().unwrap_or("(principal?)")))];
    parts.extend(hops.iter().map(|h| short_key(Some(&h.holder))));
    let chain_string = parts.join(" -> ");

    let action = get(&p, "action");
    let str_only = |v: U| match v {
        Some(Value::String(_)) => v,
        _ => None,
    };
    let sev = severity_for(outcome, &checks_u, &tier);
    let depth = if hops.is_empty() { 0 } else { hops.len() as i64 - 1 };
    Ok(Norm {
        crypto: str_eq(&get(&checks_u, "wire"), "pass") && str_eq(&get(&checks_u, "leaf_signature"), "pass"),
        checks: checks_u.clone().unwrap_or(Value::Null),
        session: str_or(&get(&rec, "session"), &grant_ref),
        verb: str_or(&get(&action, "verb"), "(unknown verb)"),
        resource: str_or(&get(&action, "resource"), "(unknown resource)"),
        params_digest: str_or(&get(&action, "params_digest"), "(none)"),
        reversibility: str_or(&get(&action, "reversibility_class"), "(unknown)"),
        counter: finite(&get(&p, "counter")).unwrap_or_else(|| n2v(-1)),
        nonce: str_only(get(&p, "nonce")),
        plan_root: str_or(&get(&get(&p, "plan"), "root"), "(none)"),
        suite: str_or(&get(&p, "alg"), "ed25519"),
        leaf_sig: shown_signature(&str_or(&get(&p, "sig"), "(unsigned)"), &get(opts, "signature")),
        proof_digest: safe_digest(&p),
        risk_score: finite(&get(&decision, "r")),
        proof_strength: get(&rt, "proof"),
        caution: finite(&get(&p, "caution")),
        bond_ref: str_only(get(&p, "bond_ref")),
        iat: finite(&get(&p, "iat")).unwrap_or_else(|| n_now.clone()),
        exp: finite(&get(&p, "exp")).unwrap_or_else(|| n_now.clone()),
        now: n_now,
        outcome,
        reason,
        agent_holder,
        principal,
        hops,
        depth,
        chain_string,
        grant_ref,
        tier,
        human_approved,
        approvers,
        guardians,
        roles,
        severity: sev,
    })
}

fn hop_wire(h: &Hop) -> Value {
    obj(vec![
        ("index", some(n2v(h.index))),
        ("is_root", some(Value::Bool(h.is_root))),
        ("issuer", some(s2v(&h.issuer))),
        ("holder", some(s2v(&h.holder))),
        ("added_caveats", some(n2v(h.added_caveats))),
    ])
}

fn human_override(n: &Norm) -> U {
    if !n.human_approved {
        return None;
    }
    Some(obj(vec![
        ("human_approved", some(Value::Bool(true))),
        ("approvers", some(Value::Array(n.approvers.clone()))),
        ("guardian_cosigners", some(Value::Array(n.guardians.clone()))),
        ("roles", some(Value::Array(n.roles.clone()))),
    ]))
}

fn pca_extensions(n: &Norm) -> Value {
    obj(vec![
        ("proof_digest", some(s2v(&n.proof_digest))),
        ("leaf_signature", some(s2v(&n.leaf_sig))),
        ("signature_suite", some(s2v(&n.suite))),
        ("cryptographically_verifiable", some(Value::Bool(n.crypto))),
        ("plan_root", some(s2v(&n.plan_root))),
        ("params_digest", some(s2v(&n.params_digest))),
        ("grant_ref", some(s2v(&n.grant_ref))),
        ("counter", some(n.counter.clone())),
        ("nonce", n.nonce.clone()),
        ("reversibility_class", some(s2v(&n.reversibility))),
        ("risk_score", n.risk_score.clone()),
        ("risk_tier", n.tier.clone()),
        ("required_proof", n.proof_strength.clone()),
        ("caution", n.caution.clone()),
        ("bond_ref", n.bond_ref.clone()),
        ("delegation_depth", some(n2v(n.depth))),
        ("delegation_chain", some(Value::Array(n.hops.iter().map(hop_wire).collect()))),
        ("checks", some(n.checks.clone())),
        ("human_override", human_override(n)),
    ])
}

fn narrative(n: &Norm) -> String {
    let word = match n.outcome {
        "allow" => "ALLOWED",
        "deny" => "DENIED",
        _ => "STEP-UP",
    };
    format!(
        "Agent {} {} to {} on {} ({}-hop chain rooted at principal {}; {}{}). {}",
        short_key(Some(&n.agent_holder)),
        word,
        n.verb,
        n.resource,
        n.hops.len(),
        short_key(n.principal.as_deref()),
        if n.crypto { "cryptographically verifiable proof" } else { "proof not cryptographically verifiable" },
        if n.human_approved { "; human-signed step-up" } else { "" },
        n.reason
    )
}

// ---- OCSF ------------------------------------------------------------------------------------------------------------

/// OCSF 1.x Authorize Session (category 3, class 3003); `unmapped` carries the proof digest, tier and delegation chain.
pub fn to_ocsf_event(record: &Value, opts: Option<&Value>, now: Option<f64>) -> Result<Value, String> {
    let n = normalize(record, &opts.cloned(), now)?;
    let (aid, aname) = match n.outcome {
        "allow" => (1, "Allow"),
        "deny" => (2, "Deny"),
        _ => (3, "Step-Up"),
    };
    let (actid, actname) = match n.outcome {
        "allow" => (1, "Allowed"),
        "deny" => (2, "Denied"),
        _ => (99, "Other"),
    };
    let status: (i64, &str, String) = match n.outcome {
        "allow" => (1, "Success", n.reason.clone()),
        "deny" => (2, "Failure", n.reason.clone()),
        _ => (99, "Other", format!("step-up / co-signature required: {}", n.reason)),
    };
    let class_name = "Authorize Session";
    let principal = n.principal.clone().unwrap_or_else(|| "(none)".to_string());
    Ok(obj(vec![
        ("activity_id", some(n2v(aid))),
        ("activity_name", some(s2v(aname))),
        ("category_uid", some(n2v(3))),
        ("category_name", some(s2v("Identity & Access Management"))),
        ("class_uid", some(n2v(3003))),
        ("class_name", some(s2v(class_name))),
        ("type_uid", some(n2v(3003 * 100 + aid))),
        ("type_name", some(s2v(&format!("{class_name}: {aname}")))),
        ("action_id", some(n2v(actid))),
        ("action", some(s2v(actname))),
        ("severity_id", some(n2v(n.severity.0))),
        ("severity", some(s2v(n.severity.1))),
        ("status_id", some(n2v(status.0))),
        ("status", some(s2v(status.1))),
        ("status_detail", some(s2v(&status.2))),
        ("time", some(n.iat.clone())),
        (
            "actor",
            some(obj(vec![
                (
                    "user",
                    some(obj(vec![
                        ("type_id", some(n2v(99))),
                        ("type", some(s2v("Agent"))),
                        ("uid", some(s2v(&n.agent_holder))),
                        ("name", some(s2v(&short_key(Some(&n.agent_holder))))),
                    ])),
                ),
                ("invoked_by", some(s2v(&principal))),
                ("session", some(obj(vec![("uid", some(s2v(&n.session))), ("issuer", n.principal.as_deref().map(s2v))]))),
                ("app_name", some(s2v("PCA"))),
            ])),
        ),
        (
            "user",
            some(obj(vec![
                ("type_id", some(n2v(1))),
                ("type", some(s2v("User"))),
                ("uid", some(s2v(&principal))),
                ("name", some(s2v(&short_key(n.principal.as_deref())))),
            ])),
        ),
        (
            "resources",
            some(Value::Array(vec![obj(vec![("type", some(s2v("pca.resource"))), ("name", some(s2v(&n.resource))), ("uid", some(s2v(&n.resource)))])])),
        ),
        ("api", some(obj(vec![("operation", some(s2v(&n.verb))), ("service", some(obj(vec![("name", some(s2v("PCA")))])))]))),
        (
            "metadata",
            some(obj(vec![
                ("version", some(s2v(OCSF_SCHEMA_VERSION))),
                ("product", some(obj(vec![("name", some(s2v("PCA"))), ("vendor_name", some(s2v("Atlas"))), ("version", some(s2v(OCSF_SCHEMA_VERSION)))]))),
                ("logged_time", some(n.now.clone())),
                ("uid", some(s2v(&n.proof_digest))),
                ("labels", some(Value::Array(vec![s2v("pca"), s2v(&format!("outcome:{}", n.outcome)), s2v(&format!("suite:{}", n.suite))]))),
            ])),
        ),
        (
            "observables",
            some(Value::Array(vec![
                obj(vec![
                    ("name", some(s2v("actor.user.uid"))),
                    ("type", some(s2v("User Name"))),
                    ("type_id", some(n2v(4))),
                    ("value", some(s2v(&n.agent_holder))),
                ]),
                obj(vec![
                    ("name", some(s2v("pca.proof.digest"))),
                    ("type", some(s2v("Hash"))),
                    ("type_id", some(n2v(8))),
                    ("value", some(s2v(&n.proof_digest))),
                ]),
                obj(vec![
                    ("name", some(s2v("resources.uid"))),
                    ("type", some(s2v("Resource UID"))),
                    ("type_id", some(n2v(10))),
                    ("value", some(s2v(&n.resource))),
                ]),
            ])),
        ),
        ("count", some(n2v(1))),
        ("message", some(s2v(&narrative(&n)))),
        ("unmapped", some(pca_extensions(&n))),
    ]))
}

// ---- CEF -------------------------------------------------------------------------------------------------------------

fn cef_header_escape(s: &str) -> String {
    let t = s.replace('\\', "\\\\").replace('|', "\\|");
    let mut out = String::new();
    let mut in_nl = false;
    for c in t.chars() {
        if c == '\r' || c == '\n' {
            if !in_nl {
                out.push(' ');
            }
            in_nl = true;
        } else {
            in_nl = false;
            out.push(c);
        }
    }
    out
}

fn cef_ext_escape(s: &str) -> String {
    let t = s.replace('\\', "\\\\").replace('=', "\\=");
    t.replace("\r\n", "\\n").replace('\r', "\\n").replace('\n', "\\n")
}

fn cef_val(v: &U) -> String {
    match v {
        None => "undefined".to_string(),
        Some(v) => js_value_string(v),
    }
}

/// One ArcSight CEF line: standard keys where they fit, the proof digest in cs1 and the delegation chain in cs2.
pub fn to_cef(record: &Value, opts: Option<&Value>, now: Option<f64>) -> Result<String, String> {
    let n = normalize(record, &opts.cloned(), now)?;
    let device_version = match finite(&get(&get(&Some(record.clone()), "pcactn"), "ver")) {
        Some(v) => cef_val(&Some(v)),
        None => "2".to_string(),
    };
    let header = [
        "CEF:0".to_string(),
        cef_header_escape("Atlas"),
        cef_header_escape("PCA"),
        cef_header_escape(&device_version),
        cef_header_escape(&format!("pca-authz-{}", n.outcome)),
        cef_header_escape(&format!("PCA authorization {}: {} on {}", n.outcome, n.verb, n.resource)),
        n.severity.2.to_string(),
    ]
    .join("|");
    let principal = n.principal.clone().unwrap_or_else(|| "(none)".to_string());
    let external_id = match &n.nonce {
        Some(v) => cef_val(&Some(v.clone())),
        None => js_value_string(&n.counter),
    };
    let checks = entries(&n.checks).iter().map(|(k, v)| format!("{k}:{}", js_value_string(v))).collect::<Vec<_>>().join(";");
    let risk = n.risk_score.as_ref().map(js_value_string).unwrap_or_default();
    let tier = if nullish(&n.tier) { String::new() } else { cef_val(&n.tier) };
    let strength = if nullish(&n.proof_strength) { "n/a".to_string() } else { cef_val(&n.proof_strength) };
    let pairs: Vec<(&str, String)> = vec![
        ("act", n.outcome.to_string()),
        ("outcome", n.outcome.to_string()),
        ("suser", principal.clone()),
        ("suid", principal),
        ("duser", n.agent_holder.clone()),
        ("duid", n.agent_holder.clone()),
        ("destinationServiceName", n.verb.clone()),
        ("rt", js_value_string(&n.now)),
        ("start", js_value_string(&n.iat)),
        ("end", js_value_string(&n.exp)),
        ("externalId", external_id),
        ("request", n.resource.clone()),
        ("requestMethod", n.verb.clone()),
        ("cs1Label", "pcaProofDigest".into()),
        ("cs1", n.proof_digest.clone()),
        ("cs2Label", "pcaDelegationChain".into()),
        ("cs2", n.chain_string.clone()),
        ("cs3Label", "pcaProofStrength".into()),
        ("cs3", strength),
        ("cs4Label", "pcaSignatureSuite".into()),
        ("cs4", n.suite.clone()),
        ("cs5Label", "pcaVerifyChecks".into()),
        ("cs5", checks),
        ("cs6Label", "pcaGrantRef".into()),
        ("cs6", n.grant_ref.clone()),
        ("cn1Label", "pcaRiskScore".into()),
        ("cn1", risk),
        ("cn2Label", "pcaDelegationDepth".into()),
        ("cn2", n.depth.to_string()),
        ("cn3Label", "pcaRiskTier".into()),
        ("cn3", tier),
        ("flexString1Label", "pcaHumanApproved".into()),
        ("flexString1", if n.human_approved { "true" } else { "false" }.into()),
        ("cat", "authorization".into()),
        ("msg", n.reason.clone()),
    ];
    let ext = pairs.iter().map(|(k, v)| format!("{k}={}", cef_ext_escape(v))).collect::<Vec<_>>().join(" ");
    Ok(format!("{header}|{ext}"))
}

// ---- ECS -------------------------------------------------------------------------------------------------------------

fn dedupe(xs: Vec<String>) -> Vec<Value> {
    let mut out: Vec<String> = vec![];
    for x in xs {
        if !out.contains(&x) {
            out.push(x);
        }
    }
    out.iter().map(|s| s2v(s)).collect()
}

/// Elastic Common Schema event; the PCA edge lives under `pca.*`.
pub fn to_ecs(record: &Value, opts: Option<&Value>, now: Option<f64>) -> Result<Value, String> {
    let n = normalize(record, &opts.cloned(), now)?;
    let mut users = vec![n.agent_holder.clone()];
    users.extend(n.principal.clone());
    users.extend(n.approvers.iter().filter_map(|v| v.as_str().map(String::from)));
    let hashes = vec![n.proof_digest.clone(), n.leaf_sig.clone()];
    let (etype, eoutcome) = match n.outcome {
        "allow" => ("allowed", "success"),
        "deny" => ("denied", "failure"),
        _ => ("info", "unknown"),
    };
    let event = obj(vec![
        ("kind", some(s2v("event"))),
        ("category", some(Value::Array(vec![s2v("iam")]))),
        ("type", some(Value::Array(vec![s2v(etype)]))),
        ("action", some(s2v(&n.verb))),
        ("outcome", some(s2v(eoutcome))),
        ("module", some(s2v("pca"))),
        ("dataset", some(s2v("pca.authorization"))),
        ("provider", some(s2v("pca"))),
        ("id", some(s2v(&n.proof_digest))),
        ("severity", some(n2v(n.severity.2))),
        ("reason", some(s2v(&n.reason))),
        ("risk_score", n.risk_score.clone()),
    ]);
    let principal = n.principal.clone().unwrap_or_else(|| "(none)".to_string());
    let hops: Vec<Value> = n
        .hops
        .iter()
        .map(|h| {
            obj(vec![
                ("index", some(n2v(h.index))),
                ("isRoot", some(Value::Bool(h.is_root))),
                ("issuer", some(s2v(&h.issuer))),
                ("holder", some(s2v(&h.holder))),
                ("addedCaveats", some(n2v(h.added_caveats))),
            ])
        })
        .collect();
    let pca = obj(vec![
        ("outcome", some(s2v(n.outcome))),
        (
            "proof",
            some(obj(vec![
                ("digest", some(s2v(&n.proof_digest))),
                ("leaf_signature", some(s2v(&n.leaf_sig))),
                ("signature_suite", some(s2v(&n.suite))),
                ("cryptographically_verifiable", some(Value::Bool(n.crypto))),
                ("plan_root", some(s2v(&n.plan_root))),
                ("params_digest", some(s2v(&n.params_digest))),
            ])),
        ),
        (
            "risk",
            some(obj(vec![
                ("score", n.risk_score.clone()),
                ("tier", n.tier.clone()),
                ("required_proof", n.proof_strength.clone()),
                ("caution", n.caution.clone()),
            ])),
        ),
        ("delegation", some(obj(vec![("depth", some(n2v(n.depth))), ("chain", some(s2v(&n.chain_string))), ("hops", some(Value::Array(hops)))]))),
        ("grant_ref", some(s2v(&n.grant_ref))),
        ("counter", some(n.counter.clone())),
        ("nonce", n.nonce.clone()),
        ("reversibility_class", some(s2v(&n.reversibility))),
        ("bond_ref", n.bond_ref.clone()),
        ("checks", some(n.checks.clone())),
        ("human_override", human_override(&n)),
    ]);
    Ok(obj(vec![
        ("@timestamp", some(s2v(&iso(&n.iat)))),
        ("ecs.version", some(s2v(ECS_VERSION))),
        ("event", some(event)),
        (
            "user",
            some(obj(vec![
                ("id", some(s2v(&n.agent_holder))),
                ("name", some(s2v(&short_key(Some(&n.agent_holder))))),
                ("roles", some(Value::Array(vec![s2v("agent")]))),
                ("effective", some(obj(vec![("id", some(s2v(&principal))), ("name", some(s2v(&short_key(n.principal.as_deref()))))]))),
            ])),
        ),
        ("service", some(obj(vec![("name", some(s2v("pca"))), ("type", some(s2v("authorization")))]))),
        ("related", some(obj(vec![("user", some(Value::Array(dedupe(users)))), ("hash", some(Value::Array(dedupe(hashes))))]))),
        ("message", some(s2v(&narrative(&n)))),
        ("pca", some(pca)),
    ]))
}

// ---- scrubbing -------------------------------------------------------------------------------------------------------

// the JavaScript `\s` class, for use inside a bracket class
const WS: &str = r"\t\n\x0b\x0c\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}";

fn scrub_patterns() -> &'static Vec<(Regex, &'static str)> {
    static P: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    P.get_or_init(|| {
        let mk = |s: String| Regex::new(&s).expect("scrub pattern");
        vec![
            (mk(format!(r"((?i-u:[a-z][a-z0-9+.-]*)://)[^{WS}/@]*:[^{WS}/@]*@")), "${1}[redacted]@"),
            (mk(format!(r#"(?-u:\b)((?i-u:authorization)["']?[{WS}]*[:=][{WS}]*)[^\n"']*"#)), "${1}[redacted]"),
            (mk(format!(r"(?-u:\b)((?i-u:Bearer|Basic|Splunk|Token))[{WS}]+[A-Za-z0-9_.~+/=-]{{6,}}")), "${1} [redacted]"),
            (
                mk(format!(
                    r#"(?-u:\b)((?i-u:token|secret|password|passwd|pwd|api[_-]?key|dd-api-key|key|signature|sig|credential)["']?[{WS}]*[:=][{WS}]*)("[^"]*"|'[^']*'|[^{WS}"'&,;]+)"#
                )),
                "${1}[redacted]",
            ),
            (mk(r"[A-Za-z0-9_-]{32,}".to_string()), "[redacted]"),
        ]
    })
}

/// Remove credentials from an error message: URL userinfo, token= style pairs, bearer credentials, long token-like runs.
pub fn scrub_error(message: &Value) -> String {
    let mut t = match message {
        Value::String(s) => s.clone(),
        v => js_value_string(v),
    };
    for (rx, rep) in scrub_patterns() {
        t = rx.replace_all(&t, *rep).into_owned();
    }
    if u16len(&t) > 300 {
        format!("{}...", u16slice(&t, 300))
    } else {
        t
    }
}

fn scrub_str(s: &str) -> String {
    scrub_error(&Value::String(s.to_string()))
}

// ---- sinks -----------------------------------------------------------------------------------------------------------

/// A thrown error is `Err(message)`; `Ok` carries `{ok, error?}`.
pub type DeliverFn = Arc<dyn Fn(&[Value]) -> Result<Value, String> + Send + Sync>;

/// A SIEM destination: `format` is the schema it expects, `deliver(events)` ships `[{line, ..}]`.
#[derive(Clone)]
pub struct SiemSink {
    pub name: String,
    pub format: String,
    pub deliver: DeliverFn,
}

/// `{format, object?, line}`: CEF is a bare line; any format other than cef / ocsf yields ECS.
pub fn format_decision(record: &Value, fmt: &str, opts: Option<&Value>, now: Option<f64>) -> Result<Value, String> {
    let fmt_v = s2v(fmt);
    if fmt == "cef" {
        return Ok(obj(vec![("format", some(fmt_v)), ("line", some(s2v(&to_cef(record, opts, now)?)))]));
    }
    let o = if fmt == "ocsf" { to_ocsf_event(record, opts, now)? } else { to_ecs(record, opts, now)? };
    let line = crate::js_stringify(&o);
    Ok(obj(vec![("format", some(fmt_v)), ("object", some(o)), ("line", some(s2v(&line)))]))
}

fn err_text(e: &str) -> String {
    if e.is_empty() {
        "Error".to_string()
    } else {
        e.to_string()
    }
}

/// What an HTTP collector replies (the reference reads `ok`, `status`, `statusText`).
#[derive(Clone, Debug)]
pub struct FetchResponse {
    pub ok: bool,
    pub status: i64,
    pub status_text: Option<String>,
}

/// The request handed to the fetch closure (header order = the order they are sent).
#[derive(Clone, Debug)]
pub struct FetchInit {
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub type FetchFn = Arc<dyn Fn(&str, &FetchInit) -> Result<FetchResponse, String> + Send + Sync>;

pub struct HttpSinkOptions {
    pub headers: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub name: Option<String>,
    pub timeout_ms: Option<f64>,
}

impl Default for HttpSinkOptions {
    fn default() -> Self {
        Self { headers: vec![], content_type: None, name: None, timeout_ms: None }
    }
}

fn default_content_type(fmt: &str) -> Option<&'static str> {
    match fmt {
        "ocsf" | "ecs" => Some("application/x-ndjson"),
        "cef" => Some("text/plain; charset=utf-8"),
        _ => None,
    }
}

fn lines_of(events: &[Value]) -> Vec<String> {
    events.iter().map(|e| e.get("line").map(js_value_string).unwrap_or_else(|| "undefined".to_string())).collect()
}

/// One POST per batch: NDJSON for OCSF / ECS, raw CEF lines for CEF. Delivery never raises; a collector that does not answer within
/// `timeout_ms` (default 10 s) is reported as a failure (the request thread is abandoned).
pub fn http_sink(url: &str, fmt: &str, fetch: FetchFn, o: HttpSinkOptions) -> SiemSink {
    let url = url.to_string();
    let fmt_s = fmt.to_string();
    let name = o.name.clone().unwrap_or_else(|| format!("http:{fmt}"));
    let deliver: DeliverFn = Arc::new(move |events: &[Value]| {
        let body = lines_of(events).join("\n");
        let mut headers: Vec<(String, String)> = vec![];
        if let Some(ct) = o.content_type.clone().or_else(|| default_content_type(&fmt_s).map(String::from)) {
            headers.push(("content-type".into(), ct));
        }
        for (k, v) in &o.headers {
            match headers.iter_mut().find(|(hk, _)| hk == k) {
                Some(slot) => slot.1 = v.clone(),
                None => headers.push((k.clone(), v.clone())),
            }
        }
        let tm = match o.timeout_ms {
            Some(t) if t.is_finite() && t > 0.0 => t,
            _ => 10000.0,
        };
        let init = FetchInit { method: "POST".into(), headers, body };
        let (tx, rx) = mpsc::channel();
        let (f, u) = (fetch.clone(), url.clone());
        std::thread::spawn(move || {
            let _ = tx.send(f(&u, &init));
        });
        match rx.recv_timeout(Duration::from_secs_f64(tm / 1000.0)) {
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(obj_ok(false, Some("delivery timed out".into()))),
            Err(_) => Ok(obj_ok(false, Some(scrub_str("fetch failed")))),
            Ok(Err(e)) => Ok(obj_ok(false, Some(scrub_str(&err_text(&e))))),
            Ok(Ok(r)) if r.ok => Ok(obj_ok(true, None)),
            Ok(Ok(r)) => {
                let st = r.status_text.filter(|s| !s.is_empty()).map(|s| format!(" {s}")).unwrap_or_default();
                Ok(obj_ok(false, Some(scrub_str(&format!("HTTP {}{}", r.status, st)))))
            }
        }
    });
    SiemSink { name, format: fmt.to_string(), deliver }
}

fn obj_ok(ok: bool, error: Option<String>) -> Value {
    obj(vec![("ok", some(Value::Bool(ok))), ("error", error.map(Value::String))])
}

/// Writes each event's serialized line to `logger`. Never raises.
pub fn console_sink(fmt: Option<&str>, logger: Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>, name: Option<&str>) -> SiemSink {
    let f = fmt.unwrap_or("ocsf").to_string();
    let deliver: DeliverFn = Arc::new(move |events: &[Value]| {
        for l in lines_of(events) {
            if let Err(e) = logger(&l) {
                return Ok(obj_ok(false, Some(scrub_str(&err_text(&e)))));
            }
        }
        Ok(obj_ok(true, None))
    });
    SiemSink { name: name.map(String::from).unwrap_or_else(|| format!("console:{f}")), format: f, deliver }
}

// ---- export ----------------------------------------------------------------------------------------------------------

/// `on_error(message, sink, count)`; an Err it returns is swallowed (it must never reach the auth path).
pub type OnError<'a> = &'a dyn Fn(&str, &str, usize) -> Result<(), String>;

fn safe_on_error(on_error: Option<OnError>, message: &str, sink: &str, count: usize) {
    if let Some(f) = on_error {
        let _ = f(message, sink, count);
    }
}

/// Export decisions in ONE delivery. Fail-safe: any serialization or delivery error is scrubbed, reported through `on_error` and
/// returned as `{ok: false, error}`; nothing is raised.
pub fn export_batch(records: &[Value], sink: &SiemSink, on_error: Option<OnError>, serialize: Option<&Value>, now: Option<f64>) -> Value {
    let fmt = s2v(&sink.format);
    let mut events: Vec<Value> = vec![];
    let mut skipped = 0i64;
    for r in records {
        match format_decision(r, &sink.format, serialize, now) {
            Ok(e) => events.push(e),
            Err(e) => {
                skipped += 1;
                safe_on_error(on_error, &scrub_str(&format!("record could not be serialized: {}", err_text(&e))), &sink.name, 1);
            }
        }
    }
    let count = events.len();
    if events.is_empty() && skipped > 0 {
        return obj(vec![
            ("ok", some(Value::Bool(false))),
            ("delivered", some(n2v(0))),
            ("format", some(fmt)),
            ("error", some(s2v("no record could be serialized"))),
            ("skipped", some(n2v(skipped))),
        ]);
    }
    let skipped_u: U = if skipped > 0 { Some(n2v(skipped)) } else { None };
    match (sink.deliver)(&events) {
        Err(e) => {
            let msg = scrub_str(&err_text(&e));
            safe_on_error(on_error, &msg, &sink.name, count);
            obj(vec![("ok", some(Value::Bool(false))), ("delivered", some(n2v(0))), ("format", some(fmt)), ("error", some(s2v(&msg)))])
        }
        Ok(res) => {
            if truthy(&get(&Some(res.clone()), "ok")) {
                return obj(vec![("ok", some(Value::Bool(true))), ("delivered", some(n2v(count as i64))), ("format", some(fmt)), ("skipped", skipped_u)]);
            }
            let er = get(&Some(res), "error");
            let msg = if nullish(&er) { scrub_str("sink reported a delivery failure") } else { scrub_error(&er.unwrap()) };
            safe_on_error(on_error, &msg, &sink.name, count);
            obj(vec![("ok", some(Value::Bool(false))), ("delivered", some(n2v(0))), ("format", some(fmt)), ("error", some(s2v(&msg))), ("skipped", skipped_u)])
        }
    }
}

/// Export one decision.
pub fn export_decision(record: &Value, sink: &SiemSink, on_error: Option<OnError>, serialize: Option<&Value>, now: Option<f64>) -> Value {
    export_batch(std::slice::from_ref(record), sink, on_error, serialize, now)
}
