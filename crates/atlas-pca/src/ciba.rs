//! OpenID CIBA bridge for PCA step-ups: the canonical displayed action, the binding message and backchannel auth request (with
//! the approval render's match code), tier-3 gating, the co-sign budget effect, the ping-callback check, and the approval brokers
//! (in-memory and durable over a versioned compare-and-set store).
//! Byte-identical to the TypeScript reference where the result is defined; refusal texts are the reference's. Payee display
//! checks use Unicode property tables read from the reference runtime (`ciba_unicode`).
use crate::ciba_unicode as uni;
use crate::intent_v2::{js_number_string, js_value_string};
use crate::risk::{recharge, recharge_full, RiskPolicy, TrustBudget};
use crate::serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use unicode_normalization::UnicodeNormalization;

const DEFAULT_EXPIRY_SEC: f64 = 300.0;
const DEFAULT_INTERVAL_SEC: f64 = 5.0;
const MIN_AUTH_REQ_ID_LEN: usize = 22;
const MAX_GOAL_CHARS: usize = 100;
const MAX_PAYEE_CHARS: usize = 64;
const PAYEE_KEYS: [&str; 5] = ["payee", "to", "recipient", "beneficiary", "destination"];
const MAX_CAS_TRIES: usize = 8;

// ---- text helpers (JavaScript semantics) ---------------------------------------------------------------------------------

/// JavaScript `\s` (WhiteSpace + LineTerminator).
fn js_ws(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

fn nchars(s: &str) -> usize {
    s.chars().count()
}

fn printable_ascii(s: &str) -> bool {
    s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Controls / format characters / line separators to spaces, whitespace runs collapsed, trimmed.
fn plain_text(v: &str) -> String {
    let s: String = v.chars().map(|c| if uni::contains(&uni::CC_CF, c) || c == '\u{2028}' || c == '\u{2029}' { ' ' } else { c }).collect();
    let mut out = String::new();
    let mut ws = false;
    for c in s.chars() {
        if js_ws(c) {
            ws = true;
            continue;
        }
        if ws && !out.is_empty() {
            out.push(' ');
        }
        ws = false;
        out.push(c);
    }
    out
}

fn clip(v: &str, max: usize) -> String {
    if nchars(v) <= max {
        v.to_string()
    } else {
        format!("{}…", v.chars().take(max.saturating_sub(1)).collect::<String>())
    }
}

/// `/because\s+you\s+asked/i` (ASCII case folding, as a non-Unicode JavaScript regex has it).
fn forged_clause(t: &str) -> bool {
    let c: Vec<char> = t.chars().collect();
    let word = |i: &mut usize, w: &str| {
        for x in w.chars() {
            match c.get(*i) {
                Some(y) if y.to_ascii_lowercase() == x => *i += 1,
                _ => return false,
            }
        }
        true
    };
    let spaces = |i: &mut usize| {
        let s = *i;
        while c.get(*i).is_some_and(|x| js_ws(*x)) {
            *i += 1;
        }
        *i > s
    };
    (0..c.len()).any(|s| {
        let mut i = s;
        word(&mut i, "because") && spaces(&mut i) && word(&mut i, "you") && spaces(&mut i) && word(&mut i, "asked")
    })
}

fn is_safe_integer(v: &Value) -> bool {
    v.as_f64().is_some_and(|f| f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0)
}

/// A JSON number for a millisecond / second count (integral values print as integers).
fn num(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 {
        json!(f as i64)
    } else {
        json!(f)
    }
}

// ---- the displayed action ------------------------------------------------------------------------------------------------

fn identifier(v: Option<&Value>, what: &str) -> Result<String, String> {
    let ok = |s: &str| {
        let b = s.as_bytes();
        !b.is_empty() && b.len() <= 64 && b[0].is_ascii_alphanumeric() && b[1..].iter().all(|c| c.is_ascii_alphanumeric() || b"._:/#@+-".contains(c))
    };
    match v.and_then(Value::as_str) {
        Some(s) if ok(s) => {
            if forged_clause(s) {
                return Err(format!("ciba: the step-up {what} contains an approval-explanation clause"));
            }
            Ok(s.to_string())
        }
        _ => Err(format!(
            "ciba: the step-up {what} must be a plain identifier (letters, digits and . _ : / # @ + -, at most 64 characters); refusing to render free text in the approval message"
        )),
    }
}

/// The number of distinct writing systems among the letters of `t` (each letter outside the named groups counts on its own).
fn scripts_of(t: &str) -> usize {
    let mut found = HashSet::new();
    for c in t.chars() {
        match uni::lookup(&uni::LETTER_GROUPS, c) {
            None => {}
            Some(0) => {
                found.insert(format!("other:{c}"));
            }
            Some(g) => {
                found.insert(uni::GROUP_NAMES[g as usize].to_string());
            }
        }
    }
    found.len()
}

fn payee_text(v: &Value) -> Result<String, String> {
    let Some(s) = v.as_str() else { return Err("ciba: the payee must be a string (a nested value cannot be shown to the approver)".into()) };
    let t: String = s.nfc().collect();
    let repeated_ws = t.chars().zip(t.chars().skip(1)).any(|(a, b)| js_ws(a) && js_ws(b));
    if t.is_empty() || t.trim_matches(js_ws) != t || repeated_ws {
        return Err("ciba: the payee must be non-empty without leading, trailing or repeated whitespace".into());
    }
    if t.chars().any(|c| uni::contains(&uni::UNDISPLAYABLE, c)) {
        return Err("ciba: the payee contains control, bidirectional or invisible characters and cannot be displayed".into());
    }
    if t.contains(['"', '\\']) {
        return Err("ciba: the payee must not contain quote or backslash characters".into());
    }
    if nchars(&t) > MAX_PAYEE_CHARS {
        return Err(format!("ciba: the payee is longer than {MAX_PAYEE_CHARS} characters; refusing to truncate what the person approves"));
    }
    if forged_clause(&t) {
        return Err("ciba: the payee contains an approval-explanation clause".into());
    }
    if t.chars().any(|c| uni::contains(&uni::MARK, c)) {
        return Err("ciba: the payee contains combining marks and cannot be shown unambiguously".into());
    }
    if t.nfkc().collect::<String>() != t {
        return Err("ciba: the payee contains compatibility/fullwidth characters that imitate plain ones".into());
    }
    if scripts_of(&t) > 1 {
        return Err("ciba: the payee mixes writing systems (a homograph risk); refusing so the person never approves a look-alike".into());
    }
    Ok(t)
}

/// An ASCII rendering of a payee for the approver: printable ASCII as is, else each non-ASCII word as its IDNA (punycode)
/// form, or `\u{..}` escapes when it is no valid domain label.
pub fn ascii_form(payee: &str) -> String {
    if printable_ascii(payee) {
        return payee.to_string();
    }
    let word = |w: &str| {
        if printable_ascii(w) {
            return w.to_string();
        }
        match url::Host::parse(w).map(|h| h.to_string()) {
            Ok(a) if !a.is_empty() => a,
            _ => w.chars().map(|c| if c as u32 > 0x7e { format!("\\u{{{:x}}}", c as u32) } else { c.to_string() }).collect(),
        }
    };
    payee.split(' ').map(word).collect::<Vec<_>>().join(" ")
}

/// The action as the approver sees it: `{verb, resource, amount?, currency?, payee?}`. Refuses any params field that would not
/// be displayed, free text in the verb / resource, and payees that cannot be shown unambiguously.
pub fn ciba_action_from_step_up(step_up: &Value) -> Result<Value, String> {
    let empty = Map::new();
    let params = match step_up.get("params") {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(m)) => m,
        Some(_) => return Err("ciba: step-up params must be an object".into()),
    };
    let unknown: Vec<&str> = params.keys().map(String::as_str).filter(|k| *k != "amount" && *k != "currency" && !PAYEE_KEYS.contains(k)).collect();
    if !unknown.is_empty() {
        return Err(format!(
            "ciba: step-up params field(s) {} are not displayed in the approval message (displayable: amount, currency, {}); refusing so the person never approves a hidden field",
            unknown.join(", "),
            PAYEE_KEYS.join("/")
        ));
    }
    let present = |k: &str| params.get(k).filter(|v| !v.is_null());
    let mut action = Map::new();
    action.insert("verb".into(), json!(identifier(step_up.get("verb"), "verb")?));
    action.insert("resource".into(), json!(identifier(step_up.get("resource"), "resource")?));
    let payee_keys: Vec<&str> = PAYEE_KEYS.iter().copied().filter(|k| present(k).is_some()).collect();
    if payee_keys.len() > 1 {
        return Err(format!("ciba: more than one payee field ({}) in params; the approver would see only one", payee_keys.join(", ")));
    }
    if let Some(amt) = present("amount") {
        let text = match amt {
            Value::Number(n) => js_number_string(n.as_f64().unwrap_or(f64::NAN)),
            Value::String(s) => s.clone(),
            _ => String::new(),
        };
        if !plain_amount(&text) {
            return Err("ciba: the binding message needs a plain non-negative decimal amount (no sign or exponent)".into());
        }
        let cur = match params.get("currency").and_then(Value::as_str) {
            Some(c) if c.len() == 3 && c.bytes().all(|b| b.is_ascii_alphabetic()) => c,
            _ => return Err("ciba: the binding message needs a 3-letter currency code next to the amount".into()),
        };
        if payee_keys.is_empty() {
            return Err("ciba: an amount needs a payee (payee / to / recipient / beneficiary / destination) so the approver sees who receives it".into());
        }
        action.insert("amount".into(), json!(text));
        action.insert("currency".into(), json!(cur.to_ascii_uppercase()));
    } else if present("currency").is_some() {
        return Err("ciba: a currency without an amount cannot be displayed".into());
    }
    if let [k] = payee_keys[..] {
        action.insert("payee".into(), json!(payee_text(&params[k])?));
    }
    Ok(Value::Object(action))
}

/// `^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$`
fn plain_amount(s: &str) -> bool {
    let (int, frac) = match s.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (s, None),
    };
    let digits = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit());
    digits(int) && (int == "0" || !int.starts_with('0')) && frac.is_none_or(digits)
}

fn needs(n: usize, max: i64) -> String {
    format!("ciba: the binding message needs {n} characters but bindingMessage.maxChars is {max}; refusing to truncate what the person approves")
}

fn s<'v>(a: &'v Value, k: &str) -> Option<&'v str> {
    a.get(k).and_then(Value::as_str)
}

fn binding_message(step_up: &Value, acts_for: &str, max_chars: Option<i64>) -> Result<String, String> {
    let a = ciba_action_from_step_up(step_up)?;
    let mut head = format!("Approve {}", s(&a, "verb").unwrap_or(""));
    if let (Some(amt), Some(cur)) = (s(&a, "amount"), s(&a, "currency")) {
        head += &format!(" {amt} {cur}");
    }
    if let Some(p) = s(&a, "payee") {
        head += &format!(" to \"{p}\"");
        if !printable_ascii(p) {
            head += &format!(" [non-ASCII name; ASCII form: {}]", ascii_form(p));
        }
    }
    head += &format!(" on {}", s(&a, "resource").unwrap_or(""));
    if let Some(m) = max_chars {
        if nchars(&head) as i64 > m {
            return Err(needs(nchars(&head), m));
        }
    }
    let plain_goal = match step_up.get("goal") {
        None => String::new(),
        Some(Value::String(g)) => plain_text(g).replace(['\'', '\u{2018}', '\u{2019}'], "\u{2032}"),
        Some(_) => return Err("ciba: the step-up goal must be a string".into()), // the reference fails on it with a TypeError
    };
    let goal_text = if !plain_goal.is_empty() {
        clip(&plain_goal, MAX_GOAL_CHARS)
    } else {
        match step_up.get("goalCommit") {
            Some(Value::String(c)) if !c.is_empty() => format!("goal {}…", utf16_prefix(c, 10)),
            Some(Value::String(_)) => return Ok(head),
            _ => return Err("ciba: the step-up goalCommit must be a string".into()),
        }
    };
    let prefix = format!(" — because you asked {acts_for} to '");
    let room = max_chars.map_or(i64::MAX, |m| m - nchars(&head) as i64 - nchars(&prefix) as i64 - 1);
    if room >= nchars(&goal_text) as i64 {
        return Ok(format!("{head}{prefix}{goal_text}'"));
    }
    if room >= 8 {
        return Ok(format!("{head}{prefix}{}'", clip(&goal_text, room as usize)));
    }
    Ok(head)
}

/// The first `n` UTF-16 code units (`String.prototype.slice`), never splitting a character.
// shortcut: a surrogate pair straddling the cut is dropped where the reference keeps a lone half; goal commits are base64url.
fn utf16_prefix(s: &str, n: usize) -> String {
    let mut units = 0;
    s.chars()
        .take_while(|c| {
            units += c.len_utf16();
            units <= n
        })
        .collect()
}

/// `[^A-Za-z0-9._-]+` -> `-`, `-` runs collapsed, leading / trailing `-` and `.` dropped.
fn tokenise(v: &str) -> String {
    let mut out = String::new();
    for c in v.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
            if c == '-' && out.ends_with('-') {
                continue;
            }
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches(['-', '.']).to_string()
}

fn compact_binding_message(step_up: &Value, max_chars: i64) -> Result<String, String> {
    let a = ciba_action_from_step_up(step_up)?;
    if let Some(p) = s(&a, "payee") {
        if p.is_empty() || !printable_ascii(p) {
            return Err("ciba: tokenOnly binding message needs an ASCII payee (tokenising would drop characters the person must see)".into());
        }
    }
    let mut raw = vec!["Approve", s(&a, "verb").unwrap_or("")];
    if let (Some(amt), Some(cur)) = (s(&a, "amount"), s(&a, "currency")) {
        raw.extend([amt, cur]);
    }
    if let Some(p) = s(&a, "payee") {
        raw.extend(["to", p]);
    }
    raw.push(s(&a, "resource").unwrap_or(""));
    let parts: Vec<String> = raw.into_iter().map(tokenise).collect();
    if parts.iter().any(String::is_empty) {
        return Err("ciba: tokenOnly binding message cannot represent the verb, payee or resource".into());
    }
    let out = parts.join("-");
    if out.len() as i64 > max_chars {
        return Err(needs(out.len(), max_chars));
    }
    Ok(out)
}

/// The CIBA backchannel authentication request for a step-up. `opts` (camelCase, all optional): `expiresInSec`, `authReqId`,
/// `stepUpScope`, `loginHint`, `bindingMessage: {maxChars, tokenOnly}`, `interval`, `actsFor`.
pub fn to_ciba_auth_request(step_up: &Value, opts: &Value) -> Result<Value, String> {
    let acts_for = match opts.get("actsFor") {
        None => None,
        Some(Value::String(a)) => Some(plain_text(a)).filter(|p| !p.is_empty()).map(|p| clip(&p, 40)),
        Some(_) => return Err("ciba: actsFor must be a string".into()), // the reference fails on it with a TypeError
    };
    let acts_for = acts_for.unwrap_or_else(|| "your agent".into());
    let expiry = opts.get("expiresInSec").cloned().unwrap_or(json!(DEFAULT_EXPIRY_SEC as i64));
    if !is_safe_integer(&expiry) || expiry.as_f64().unwrap_or(0.0) <= 0.0 {
        return Err(format!("ciba: requested_expiry must be a positive integer number of seconds, got {}", js_value_string(&expiry)));
    }
    let verb_text = step_up.get("verb").map_or("undefined".into(), js_value_string);
    let step_up_scope = format!("urn:atlas:pca:stepup:{verb_text}");
    if !step_up_scope.bytes().all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b)) {
        return Err("ciba: the step-up verb cannot be carried as an OAuth scope-token (RFC 6749 3.3)".into());
    }
    let scope = if opts.get("stepUpScope") == Some(&json!(false)) { "openid".to_string() } else { format!("openid {step_up_scope}") };
    let interval = opts.get("interval").cloned().unwrap_or(json!(DEFAULT_INTERVAL_SEC as i64));
    if !is_safe_integer(&interval) || interval.as_f64().unwrap_or(0.0) <= 0.0 {
        return Err(format!("ciba: interval must be a positive integer number of seconds, got {}", js_value_string(&interval)));
    }
    let auth_req_id = match opts.get("authReqId").filter(|v| !v.is_null()) {
        // stricter than the reference, which lets a non-string id through
        Some(v) => v.as_str().ok_or("ciba: auth_req_id must use only A-Za-z0-9.-_ and be 22..1024 characters (CIBA Core 7.3)")?.to_string(),
        None => {
            let mut m = Map::new();
            m.insert("d".into(), json!("atlas-pca/ciba/auth_req_id/v1"));
            if let Some(id) = step_up.get("id") {
                m.insert("stepUp".into(), id.clone());
            }
            crate::hash_canonical(&Value::Object(m))
        }
    };
    let id_ok = auth_req_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-');
    if !id_ok || auth_req_id.len() < MIN_AUTH_REQ_ID_LEN || auth_req_id.len() > 1024 {
        return Err("ciba: auth_req_id must use only A-Za-z0-9.-_ and be 22..1024 characters (CIBA Core 7.3)".into());
    }
    let bm = opts.get("bindingMessage");
    let bm_max = bm.and_then(|b| b.get("maxChars"));
    if let Some(m) = bm_max {
        if !is_safe_integer(m) || m.as_f64().unwrap_or(0.0) < 1.0 {
            return Err("ciba: bindingMessage.maxChars must be a positive integer".into());
        }
    }
    let max_chars = bm_max.and_then(Value::as_f64).map_or(50, |m| m as i64);
    let token_only = bm.and_then(|b| b.get("tokenOnly")) == Some(&json!(true));
    let (render, digest) = (step_up.get("render"), step_up.get("renderDigest"));
    let mut words = None;
    if render.is_some() || digest.is_some() {
        let agree = match (render, digest) {
            (Some(r), Some(d)) => Some(crate::approval_render_digest(r)?.as_str()) == d.as_str(),
            _ => false,
        };
        if !agree {
            return Err("ciba: the step-up render and its digest do not agree; refusing to send an approval that commits to something else".into());
        }
        words = Some(crate::binding_words(digest.and_then(Value::as_str).unwrap_or(""))?);
    }
    let reserve = words.as_ref().map_or(0, |w| w.len() as i64 + 14);
    let mut message = if token_only {
        compact_binding_message(step_up, max_chars - reserve)?
    } else {
        binding_message(step_up, &acts_for, bm_max.map(|_| max_chars - reserve))?
    };
    if let Some(w) = &words {
        message = if token_only { format!("{message}-match-{w}") } else { format!("{message} [match code {w}]") };
    }
    let mut out = Map::new();
    out.insert("auth_req_id".into(), json!(auth_req_id));
    out.insert("binding_message".into(), json!(message));
    out.insert("scope".into(), json!(scope));
    out.insert("requested_expiry".into(), expiry);
    out.insert("interval".into(), interval);
    if let Some(h) = opts.get("loginHint") {
        out.insert("login_hint".into(), h.clone());
    }
    for (from, to) in [("id", "stepUpId"), ("tier", "tier")] {
        if let Some(v) = step_up.get(from) {
            out.insert(to.into(), v.clone());
        }
    }
    if let (Some(r), Some(d)) = (render, digest) {
        out.insert("authorization_details".into(), json!([{ "type": "pca_approval", "render": r, "render_digest": d }]));
        out.insert("render_digest".into(), d.clone());
    }
    Ok(Value::Object(out))
}

// ---- gating, co-sign, ping callback --------------------------------------------------------------------------------------

/// A tier-3 step-up goes out-of-band (CIBA); lower tiers stay in-band.
pub fn requires_ciba(review: &Value) -> bool {
    review.get("kind") == Some(&json!("step_up")) && review.get("request").and_then(|r| r.get("tier")).and_then(Value::as_f64) == Some(3.0)
}

/// The budget effect of a CIBA decision: an approval is a human co-sign (recharge, or a full recharge); a denial changes nothing.
pub fn ciba_decision_to_cosign(approve: bool, budget: &TrustBudget, policy: &RiskPolicy, now: f64, full: bool) -> (TrustBudget, bool) {
    match (approve, full) {
        (true, true) => (recharge_full(policy.b_max, now), true),
        (true, false) => (recharge(budget, policy.rho, policy.b_max, now), true),
        (false, _) => (*budget, false),
    }
}

/// Check a CIBA ping-mode callback: `Authorization: Bearer <client_notification_token>` and the flow's `auth_req_id` in the
/// body. Returns the auth_req_id.
pub fn verify_ping_callback(authorization: Option<&str>, body: &Value, auth_req_id: &str, client_notification_token: Option<&str>) -> Result<String, String> {
    let Some(cnt) = client_notification_token else { return Err("ciba: flow was not started in ping mode".into()) };
    let a = authorization.unwrap_or("");
    let token = a
        .get(..6)
        .filter(|p| p.eq_ignore_ascii_case("bearer"))
        .map(|_| &a[6..])
        .filter(|r| r.starts_with(' '))
        .map(|r| r.trim_start_matches(' '))
        .filter(|t| !t.is_empty() && !t.chars().any(js_ws));
    let Some(token) = token else { return Err("ciba: ping callback lacks a bearer token".into()) };
    let (x, y) = (Sha256::digest(token.as_bytes()), Sha256::digest(cnt.as_bytes()));
    if x.iter().zip(y.iter()).fold(0u8, |d, (p, q)| d | (p ^ q)) != 0 {
        return Err("ciba: ping callback bearer does not match the client_notification_token".into());
    }
    match body.get("auth_req_id").and_then(Value::as_str) {
        Some(id) if id == auth_req_id => Ok(id.to_string()),
        _ => Err("ciba: ping callback auth_req_id does not match this flow".into()),
    }
}

// ---- approval brokers ------------------------------------------------------------------------------------------------------

/// A stored value with its version (0: absent).
#[derive(Clone, Debug)]
pub struct Versioned {
    pub version: u64,
    pub value: Value,
}

/// A versioned key-value store with compare-and-set: the durable broker's only dependency.
pub trait ApprovalStore {
    fn get(&self, key: &str) -> Result<Option<Versioned>, String>;
    /// Write `value` at version `expected + 1` if the current version is `expected`; false when it is not.
    fn cas(&self, key: &str, expected: u64, value: Value) -> Result<bool, String>;
}

/// An in-process [`ApprovalStore`].
#[derive(Default)]
pub struct MemoryApprovalStore(RefCell<HashMap<String, Versioned>>);

impl ApprovalStore for MemoryApprovalStore {
    fn get(&self, key: &str) -> Result<Option<Versioned>, String> {
        Ok(self.0.borrow().get(key).cloned())
    }
    fn cas(&self, key: &str, expected: u64, value: Value) -> Result<bool, String> {
        let mut m = self.0.borrow_mut();
        if m.get(key).map_or(0, |v| v.version) != expected {
            return Ok(false);
        }
        m.insert(key.into(), Versioned { version: expected + 1, value });
        Ok(true)
    }
}

#[derive(Clone)]
struct Rec {
    request: Value,
    created_at: f64,
    expires_at: f64,
    interval: f64,
    decision: Option<String>,
    decided_by: Option<String>,
    decided_at: Option<f64>,
    last_poll_at: Option<f64>,
    consumed: bool,
}

impl Rec {
    fn id(&self) -> &str {
        s(&self.request, "auth_req_id").unwrap_or("")
    }
    fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("request".into(), self.request.clone());
        m.insert("createdAt".into(), num(self.created_at));
        m.insert("expiresAt".into(), num(self.expires_at));
        m.insert("interval".into(), num(self.interval));
        if let Some(d) = &self.decision {
            m.insert("decision".into(), json!(d));
        }
        if let Some(d) = &self.decided_by {
            m.insert("decidedBy".into(), json!(d));
        }
        if let Some(t) = self.decided_at {
            m.insert("decidedAt".into(), num(t));
        }
        if let Some(t) = self.last_poll_at {
            m.insert("lastPollAt".into(), num(t));
        }
        if self.consumed {
            m.insert("consumed".into(), json!(true));
        }
        Value::Object(m)
    }
    fn from_json(v: &Value) -> Result<Rec, String> {
        let f = |k: &str| v.get(k).and_then(Value::as_f64);
        let (Some(_), Some(created_at), Some(expires_at), Some(interval)) =
            (v.get("request").and_then(|r| r.get("auth_req_id")).and_then(Value::as_str), f("createdAt"), f("expiresAt"), f("interval"))
        else {
            return Err("ciba: stored approval record is malformed".into());
        };
        let st = |k: &str| v.get(k).and_then(Value::as_str).map(String::from);
        Ok(Rec {
            request: v["request"].clone(),
            created_at,
            expires_at,
            interval,
            decision: st("decision"),
            decided_by: st("decidedBy"),
            decided_at: f("decidedAt"),
            last_poll_at: f("lastPollAt"),
            consumed: v.get("consumed") == Some(&json!(true)),
        })
    }
}

/// A CIBA approval broker: `start` sends (or re-uses) the request for a step-up, the approver's side `resolve`s it, the agent
/// `poll`s / redeems it once with `token`. Decisions live in an [`ApprovalStore`].
pub struct ApprovalBroker<S: ApprovalStore> {
    store: S,
    now: Box<dyn Fn() -> f64>,
    /// How long an approval stays redeemable after the decision; `None` (the in-memory broker): until the request expires.
    decision_ttl_ms: Option<f64>,
    on_complete: Option<Box<dyn Fn(&Value)>>,
}

/// The in-memory broker (tests, single process).
pub fn create_ciba_broker(now: Box<dyn Fn() -> f64>, on_complete: Option<Box<dyn Fn(&Value)>>) -> ApprovalBroker<MemoryApprovalStore> {
    ApprovalBroker { store: MemoryApprovalStore::default(), now, decision_ttl_ms: None, on_complete }
}

/// The durable broker over `store`; an approval goes stale `decision_ttl_sec` (default 300) after the decision.
pub fn create_durable_ciba_broker<S: ApprovalStore>(
    store: S,
    now: Box<dyn Fn() -> f64>,
    decision_ttl_sec: Option<f64>,
    on_complete: Option<Box<dyn Fn(&Value)>>,
) -> Result<ApprovalBroker<S>, String> {
    let ttl = decision_ttl_sec.unwrap_or(300.0) * 1000.0;
    if !ttl.is_finite() || ttl <= 0.0 {
        return Err("createDurableCibaBroker: decisionTtlSec must be a positive number".into());
    }
    Ok(ApprovalBroker { store, now, decision_ttl_ms: Some(ttl), on_complete })
}

fn outcome(error: &str, interval: f64) -> Value {
    json!({ "ok": false, "error": error, "interval": num(interval) })
}

impl<S: ApprovalStore> ApprovalBroker<S> {
    fn status(&self, r: &Rec, now: f64) -> &'static str {
        match r.decision.as_deref() {
            Some("deny") => "denied",
            Some("approve") => match (self.decision_ttl_ms, r.decided_at) {
                (Some(ttl), Some(at)) if !(now.is_finite() && now < at + ttl) => "expired",
                (Some(_), None) => "expired",
                _ => "approved",
            },
            _ if !(now.is_finite() && now < r.expires_at) => "expired",
            _ => "pending",
        }
    }

    fn snap(&self, r: &Rec, now: f64) -> Value {
        let mut m = Map::new();
        m.insert("auth_req_id".into(), json!(r.id()));
        m.insert("request".into(), r.request.clone());
        m.insert("status".into(), json!(self.status(r, now)));
        m.insert("createdAt".into(), num(r.created_at));
        m.insert("expiresAt".into(), num(r.expires_at));
        if let Some(d) = &r.decided_by {
            m.insert("decidedBy".into(), json!(d));
        }
        if let Some(t) = r.decided_at {
            m.insert("decidedAt".into(), num(t));
        }
        Value::Object(m)
    }

    fn load(&self, id: &str) -> Result<Option<(Rec, u64)>, String> {
        match self.store.get(&format!("a:{id}"))? {
            None => Ok(None),
            Some(v) => Ok(Some((Rec::from_json(&v.value)?, v.version))),
        }
    }

    fn mutate<T>(&self, id: &str, mut f: impl FnMut(Option<Rec>, f64) -> Result<(Option<Rec>, T), String>) -> Result<T, String> {
        for _ in 0..MAX_CAS_TRIES {
            let cur = self.load(id)?;
            let version = cur.as_ref().map_or(0, |c| c.1);
            let (next, out) = f(cur.map(|c| c.0), (self.now)())?;
            match next {
                None => return Ok(out),
                Some(n) if self.store.cas(&format!("a:{id}"), version, n.to_json())? => return Ok(out),
                Some(_) => {}
            }
        }
        Err("ciba: approval store contention, gave up".into())
    }

    /// Send the request for `step_up` (see [`to_ciba_auth_request`] for `opts`; the auth_req_id is always fresh and random), or
    /// return the live one (pending, or approved and not yet redeemed).
    pub fn start(&self, step_up: &Value, opts: &Value) -> Result<Value, String> {
        let live_key = format!("s:{}", step_up.get("id").map_or("undefined".into(), js_value_string));
        for _ in 0..MAX_CAS_TRIES {
            let now = (self.now)();
            let idx = self.store.get(&live_key)?;
            if let Some(i) = &idx {
                if let Some((ex, _)) = self.load(&js_value_string(&i.value))? {
                    if matches!(self.status(&ex, now), "pending" | "approved") && !ex.consumed {
                        return Ok(ex.request);
                    }
                }
            }
            let mut o = opts.as_object().cloned().unwrap_or_default();
            let mut raw = [0u8; 20];
            getrandom::getrandom(&mut raw).map_err(|e| format!("ciba: no randomness: {e}"))?;
            o.insert("authReqId".into(), json!(crate::b64_encode(&raw)));
            let request = to_ciba_auth_request(step_up, &Value::Object(o))?;
            let expiry = request["requested_expiry"].as_f64().unwrap_or(0.0);
            let rec = Rec {
                created_at: now,
                expires_at: now + expiry * 1000.0,
                interval: request["interval"].as_f64().unwrap_or(DEFAULT_INTERVAL_SEC),
                request,
                decision: None,
                decided_by: None,
                decided_at: None,
                last_poll_at: None,
                consumed: false,
            };
            if !self.store.cas(&format!("a:{}", rec.id()), 0, rec.to_json())? {
                continue;
            }
            if self.store.cas(&live_key, idx.as_ref().map_or(0, |i| i.version), json!(rec.id()))? {
                return Ok(rec.request);
            }
        }
        Err("ciba: approval store contention, gave up".into())
    }

    /// `{status}` of a request (a read: it does not count as a token poll).
    pub fn poll(&self, id: &str) -> Result<Value, String> {
        match self.load(id)? {
            None => Err(format!("ciba: unknown auth_req_id {id}")),
            Some((r, _)) => Ok(json!({ "status": self.status(&r, (self.now)()) })),
        }
    }

    /// The token-endpoint outcome: `{ok: true, session}` once (single use), else `{ok: false, error, interval}` with the CIBA
    /// error (authorization_pending, slow_down, access_denied, expired_token, invalid_grant).
    pub fn token(&self, id: &str) -> Result<Value, String> {
        self.mutate(id, |r, now| {
            let Some(mut r) = r else { return Ok((None, outcome("invalid_grant", DEFAULT_INTERVAL_SEC))) };
            if r.consumed {
                return Ok((None, outcome("invalid_grant", r.interval)));
            }
            let too_soon = r.last_poll_at.is_some_and(|t| !(now - t >= r.interval * 1000.0));
            r.last_poll_at = Some(now);
            if too_soon {
                r.interval += 5.0;
                let o = outcome("slow_down", r.interval);
                return Ok((Some(r), o));
            }
            let o = match self.status(&r, now) {
                "pending" => outcome("authorization_pending", r.interval),
                "denied" => outcome("access_denied", r.interval),
                "expired" => outcome("expired_token", r.interval),
                _ => {
                    r.consumed = true;
                    json!({ "ok": true, "session": self.snap(&r, now) })
                }
            };
            Ok((Some(r), o))
        })
    }

    /// Record the approver's decision ("approve" / "deny") by the authenticated decider `by`; only a pending request.
    pub fn resolve(&self, id: &str, decision: &str, by: &str) -> Result<Value, String> {
        if decision != "approve" && decision != "deny" {
            return Err("ciba: decision must be \"approve\" or \"deny\"".into());
        }
        if by.is_empty() {
            return Err("ciba: `by` (the authenticated decider) is required".into());
        }
        let session = self.mutate(id, |r, now| {
            let Some(mut r) = r else { return Err(format!("ciba: unknown auth_req_id {id}")) };
            let cur = self.status(&r, now);
            if cur != "pending" {
                return Err(format!("ciba: cannot resolve {id} — already {cur}"));
            }
            r.decision = Some(decision.into());
            r.decided_by = Some(by.into());
            r.decided_at = Some(now);
            let out = self.snap(&r, now);
            Ok((Some(r), out))
        })?;
        if let Some(cb) = &self.on_complete {
            cb(&session); // the decision is already recorded; a notifier cannot undo it
        }
        Ok(session)
    }

    pub fn get(&self, id: &str) -> Result<Option<Value>, String> {
        Ok(self.load(id)?.map(|(r, _)| self.snap(&r, (self.now)())))
    }
}
