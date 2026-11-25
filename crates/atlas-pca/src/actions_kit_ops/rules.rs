//! A platform's own business rules for one action, compiled into tighten rules and count accumulators (business-rules.ts).
//! Every compiled rule signals `escalate` or `deny`, never `allow`: a rule can only lower a decision. Anything the evaluator
//! cannot decide fires the rule (fail closed).
//!
//! shortcut: time zones come from the system IANA database (/usr/share/zoneinfo, TZif v2+ with the POSIX footer), as the
//! Python port's zoneinfo does; a host with no tz database at all (Windows) uses the embedded table of common zones (`tzdata/`, IANA release 2026f), and any other zone
//! is unknown there, so a `hours` rule naming it is refused (fail closed). Upgrade: embed the whole database.

use super::{isi, js_opt, js_str, kerr, negzero, sort_u16, u16cmp, utf16_len};
use crate::actions::{def_digest, reviewer_pins_error, ActionKitError};
use crate::agent::KeyPair;
use crate::predicates::{evaluate_condition_tri, Ctx, Tri};
use crate::{b64_encode, canonicalize_strict, hash_canonical_strict, verify_b64u};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, OnceLock};

pub const RULE_DAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
const MAX_RULE_CURRENCIES: usize = 32;
const MAX_RULE_LIST: usize = 64;
const MAX_RULE_APPROVERS: f64 = 16.0;
const MAX_RULE_EXAMPLES: usize = 32;
pub const BUSINESS_RULES_DOMAIN: &str = "atlas-pca/action-business-rules/v1";
pub const RULES_REVIEW_DOMAIN: &str = "atlas-pca/action-rules-review/v1";
pub const DEFAULT_EXAMPLE_AT: &str = "2026-01-07T15:00:00Z";
const RULE_KEYS: [&str; 8] = ["amount", "approval", "scope", "rate", "hours", "recipients", "required", "examples"];

macro_rules! re {
    ($p:expr) => {{
        static R: OnceLock<Regex> = OnceLock::new();
        R.get_or_init(|| Regex::new($p).unwrap())
    }};
}

type R<T> = Result<T, ActionKitError>;

fn bad<T>(m: impl Into<String>) -> R<T> {
    Err(kerr("bad_rules", m))
}

fn period_ms(p: &str) -> Option<i64> {
    match p {
        "hour" => Some(3_600_000),
        "day" => Some(86_400_000),
        _ => None,
    }
}

fn closed(o: &Map<String, Value>, allowed: &[&str], at: &str) -> R<()> {
    for k in o.keys() {
        if !allowed.contains(&k.as_str()) {
            return bad(format!("{at}: unknown member '{k}'"));
        }
    }
    Ok(())
}

fn params_of(d: &Value) -> R<&Map<String, Value>> {
    d.get("params").and_then(Value::as_object).ok_or_else(|| kerr("bad_rules", "the definition has no params"))
}

fn verb_of(d: &Value) -> &str {
    d.get("verb").and_then(Value::as_str).unwrap_or("")
}

/// The parameter a reference names (`{param}` or `{role}`), with its definition. `bad_rules` for none or several.
pub fn resolve_param_ref<'a>(d: &'a Value, r: &Value, at: &str) -> R<(String, &'a Value)> {
    let Some(ro) = r.as_object() else { return bad(format!("{at}: name a parameter ({{param}} or {{role}})")) };
    let (has_p, has_r) = (ro.get("param").is_some_and(Value::is_string), ro.get("role").is_some_and(Value::is_string));
    if has_p == has_r {
        return bad(format!("{at}: give exactly one of param or role"));
    }
    let ps = params_of(d)?;
    if has_p {
        let name = ro["param"].as_str().unwrap();
        return match ps.get(name) {
            Some(p) => Ok((name.to_string(), p)),
            None => bad(format!("{at}: '{}' has no parameter '{name}'", verb_of(d))),
        };
    }
    let role = &ro["role"];
    let mut hits: Vec<&String> = ps.iter().filter(|(_, p)| p.get("role") == Some(role)).map(|(n, _)| n).collect();
    hits.sort_by(|a, b| u16cmp(a, b));
    if hits.len() != 1 {
        return bad(format!(
            "{at}: '{}' has {} parameter{} with role {}",
            verb_of(d),
            if hits.is_empty() { "no" } else { "several" },
            if hits.is_empty() { "" } else { "s" },
            js_str(role)
        ));
    }
    Ok((hits[0].clone(), &ps[hits[0]]))
}

#[derive(Debug, Clone)]
pub enum Ccy {
    Literal(String),
    Param(String),
}

#[derive(Debug, Clone)]
pub struct Money {
    pub amount: String,
    pub exp: i64,
    pub ccy: Ccy,
}

/// The money parameters of an action.
pub fn money_of(d: &Value) -> R<Money> {
    let ps = params_of(d)?;
    let mut hits: Vec<&String> = ps.iter().filter(|(_, p)| p.get("role").and_then(Value::as_str) == Some("money.amount")).map(|(n, _)| n).collect();
    hits.sort_by(|a, b| u16cmp(a, b));
    if hits.len() != 1 {
        return bad(format!("'{}' needs exactly one parameter with role money.amount for an amount or approval-above rule (has {})", verb_of(d), hits.len()));
    }
    let name = hits[0];
    let p = &ps[name];
    if p["type"] != "integer" {
        return bad(format!("'{}': the money.amount parameter '{name}' must be an integer", verb_of(d)));
    }
    let Some(u) = p.get("unit").filter(|u| u["kind"] == "money") else {
        return bad(format!("'{}': the amount parameter '{name}' declares no money unit (its currency)", verb_of(d)));
    };
    let exp = u.get("exp").and_then(Value::as_i64).unwrap_or(0);
    match &u["ccy"] {
        Value::String(c) => Ok(Money { amount: name.clone(), exp, ccy: Ccy::Literal(c.clone()) }),
        c => {
            let from = c.get("from").and_then(Value::as_str).unwrap_or("");
            if !ps.contains_key(from) {
                return bad(format!("'{}': the currency parameter '{from}' does not exist", verb_of(d)));
            }
            Ok(Money { amount: name.clone(), exp, ccy: Ccy::Param(from.to_string()) })
        }
    }
}

/// Integer minor units of a money value under exponent `exp`. `bad_rules` for a non-integer or over-precise value.
pub fn minor_units(v: &Value, exp: i64, at: &str) -> R<i64> {
    if v.is_number() {
        if !isi(v) || negzero(v) || v.as_f64().unwrap_or(-1.0) < 0.0 {
            return bad(format!("{at}: an amount is a non-negative integer of minor units, or a decimal string"));
        }
        return Ok(v.as_f64().unwrap_or(0.0) as i64);
    }
    let Some(s) = v.as_str() else { return bad(format!("{at}: an amount is a number of minor units or a decimal string")) };
    let Some(m) = re!(r"^(0|[1-9][0-9]{0,14})(?:\.([0-9]{1,6}))?$").captures(s) else { return bad(format!("{at}: '{s}' is not a decimal amount")) };
    let frac = m.get(2).map_or("", |x| x.as_str());
    if (frac.len() as i64) > exp {
        return bad(format!("{at}: '{s}' has more decimals than the currency's {exp}"));
    }
    let big = |_| kerr("bad_rules", format!("{at}: '{s}' is too large"));
    let whole: i128 = m[1].parse().map_err(big)?;
    let pad: String = format!("{frac}{}", "0".repeat((exp - frac.len() as i64).max(0) as usize));
    let fr: i128 = if pad.is_empty() { 0 } else { pad.parse().map_err(big)? };
    let n = 10i128.checked_pow(exp.clamp(0, 30) as u32).and_then(|p| whole.checked_mul(p)).and_then(|x| x.checked_add(fr));
    match n {
        Some(n) if n <= 9_007_199_254_740_991 => Ok(n as i64),
        _ => bad(format!("{at}: '{s}' is too large")),
    }
}

fn mins(hhmm: &str) -> i64 {
    hhmm[0..2].parse::<i64>().unwrap_or(0) * 60 + hhmm[3..5].parse::<i64>().unwrap_or(0)
}

// ---- time zones (system tzdata) ---------------------------------------------------------------------------------------------

struct Posix {
    std_off: i64,
    dst: Option<(i64, [Rule; 2])>,
}
#[derive(Clone, Copy)]
enum RuleDay {
    M(i64, i64, i64),
    J(i64),
    N(i64),
}
#[derive(Clone, Copy)]
struct Rule {
    day: RuleDay,
    time: i64,
}
struct Tz {
    trans: Vec<i64>,
    idx: Vec<u8>,
    types: Vec<i64>,
    footer: Option<Posix>,
}

fn rd(b: &[u8], at: usize, n: usize) -> Option<i64> {
    let s = b.get(at..at + n)?;
    Some(match n {
        4 => i32::from_be_bytes(s.try_into().ok()?) as i64,
        _ => i64::from_be_bytes(s.try_into().ok()?),
    })
}

fn parse_posix(s: &str) -> Option<Posix> {
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    let name = |i: &mut usize| -> Option<()> {
        if b.get(*i) == Some(&'<') {
            while b.get(*i)? != &'>' {
                *i += 1;
            }
            *i += 1;
        } else {
            let st = *i;
            while b.get(*i).is_some_and(|c| c.is_ascii_alphabetic()) {
                *i += 1;
            }
            if *i - st < 3 {
                return None;
            }
        }
        Some(())
    };
    let num = |i: &mut usize| -> Option<i64> {
        let st = *i;
        while b.get(*i).is_some_and(|c| c.is_ascii_digit()) {
            *i += 1;
        }
        b[st..*i].iter().collect::<String>().parse().ok()
    };
    let offset = |i: &mut usize| -> Option<i64> {
        let mut sign = 1;
        if b.get(*i) == Some(&'-') {
            sign = -1;
            *i += 1;
        } else if b.get(*i) == Some(&'+') {
            *i += 1;
        }
        let mut t = num(i)? * 3600;
        for k in [60, 1] {
            if b.get(*i) == Some(&':') {
                *i += 1;
                t += num(i)? * k;
            }
        }
        Some(sign * t)
    };
    name(&mut i)?;
    let std_off = -offset(&mut i)?;
    if i >= b.len() {
        return Some(Posix { std_off, dst: None });
    }
    name(&mut i)?;
    let mut dst_off = std_off + 3600;
    if b.get(i).is_some_and(|c| *c != ',') {
        dst_off = -offset(&mut i)?;
    }
    let mut rules = [Rule { day: RuleDay::M(3, 2, 0), time: 7200 }, Rule { day: RuleDay::M(11, 1, 0), time: 7200 }];
    if b.get(i) == Some(&',') {
        for r in rules.iter_mut() {
            i += 1; // ','
            let day = match *b.get(i)? {
                'M' => {
                    i += 1;
                    let m = num(&mut i)?;
                    i += 1;
                    let w = num(&mut i)?;
                    i += 1;
                    RuleDay::M(m, w, num(&mut i)?)
                }
                'J' => {
                    i += 1;
                    RuleDay::J(num(&mut i)?)
                }
                _ => RuleDay::N(num(&mut i)?),
            };
            let mut time = 7200;
            if b.get(i) == Some(&'/') {
                i += 1;
                time = offset(&mut i)?;
            }
            *r = Rule { day, time };
        }
    }
    Some(Posix { std_off, dst: Some((dst_off, rules)) })
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn year_of_days(z: i64) -> i64 {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    yoe + era * 400 + if m <= 2 { 1 } else { 0 }
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn rule_day(year: i64, r: &Rule) -> i64 {
    match r.day {
        RuleDay::M(m, w, d) => {
            let d0 = days_from_civil(year, m, 1);
            let dow0 = (d0 + 4).rem_euclid(7);
            let mut day = 1 + (d - dow0).rem_euclid(7) + (w - 1) * 7;
            let dim = [31, if is_leap(year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][(m - 1).clamp(0, 11) as usize];
            while day > dim {
                day -= 7;
            }
            d0 + day - 1
        }
        RuleDay::J(n) => days_from_civil(year, 1, 1) + n - 1 + if is_leap(year) && n >= 60 { 1 } else { 0 },
        RuleDay::N(n) => days_from_civil(year, 1, 1) + n,
    }
}

impl Posix {
    fn offset_at(&self, t: i64) -> i64 {
        let Some((dst_off, rules)) = &self.dst else { return self.std_off };
        let year = year_of_days((t + self.std_off).div_euclid(86400));
        let start = rule_day(year, &rules[0]) * 86400 + rules[0].time - self.std_off;
        let end = rule_day(year, &rules[1]) * 86400 + rules[1].time - dst_off;
        let in_dst = if start < end { t >= start && t < end } else { !(t >= end && t < start) };
        if in_dst {
            *dst_off
        } else {
            self.std_off
        }
    }
}

fn parse_tzif(b: &[u8]) -> Option<Tz> {
    if b.get(0..4)? != b"TZif" {
        return None;
    }
    let version = *b.get(4)?;
    let counts = |at: usize| -> Option<[usize; 6]> {
        let mut c = [0usize; 6];
        for (k, x) in c.iter_mut().enumerate() {
            *x = rd(b, at + 20 + 4 * k, 4)? as usize;
        }
        Some(c) // isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt
    };
    let c1 = counts(0)?;
    let v1len = c1[3] * 4 + c1[3] + c1[4] * 6 + c1[5] + c1[2] * 8 + c1[1] + c1[0];
    let (base, tsz, c) = if version >= b'2' {
        let h2 = 44 + v1len;
        (h2 + 44, 8usize, counts(h2)?)
    } else {
        (44, 4usize, c1)
    };
    let (timecnt, typecnt, charcnt, leapcnt) = (c[3], c[4], c[5], c[2]);
    let mut trans = Vec::with_capacity(timecnt);
    for k in 0..timecnt {
        trans.push(rd(b, base + k * tsz, tsz)?);
    }
    let idx_at = base + timecnt * tsz;
    let idx = b.get(idx_at..idx_at + timecnt)?.to_vec();
    let ty_at = idx_at + timecnt;
    let mut types = Vec::new();
    for k in 0..typecnt {
        types.push(rd(b, ty_at + k * 6, 4)?);
    }
    let footer = if version >= b'2' {
        let end = ty_at + typecnt * 6 + charcnt + leapcnt * (tsz + 4) + c[1] + c[0];
        let rest = b.get(end..)?;
        let txt = std::str::from_utf8(rest).ok()?;
        txt.strip_prefix('\n').and_then(|t| t.lines().next()).filter(|l| !l.is_empty()).and_then(parse_posix)
    } else {
        None
    };
    Some(Tz { trans, idx, types, footer })
}

impl Tz {
    fn offset_at(&self, t: i64) -> i64 {
        if self.trans.is_empty() || t < self.trans[0] {
            return self.types.first().copied().unwrap_or(0);
        }
        if t >= *self.trans.last().unwrap() {
            if let Some(f) = &self.footer {
                return f.offset_at(t);
            }
        }
        let k = self.trans.partition_point(|x| *x <= t) - 1;
        self.types.get(self.idx[k] as usize).copied().unwrap_or(0)
    }
}

/// Where a host keeps its tz database.
const ROOTS: [&str; 4] = ["/usr/share/zoneinfo", "/usr/lib/zoneinfo", "/usr/share/lib/zoneinfo", "/etc/zoneinfo"];

fn find_zone(tz: &str) -> Option<Tz> {
    let segs: Vec<&str> = tz.split('/').collect();
    if segs.iter().any(|s| s.is_empty()) {
        return None;
    }
    for root in ROOTS {
        let mut cur = std::path::PathBuf::from(root);
        let mut ok = true;
        for s in &segs {
            let exact = cur.join(s);
            if exact.exists() {
                cur = exact;
                continue;
            }
            let found = std::fs::read_dir(&cur)
                .ok()
                .and_then(|rd| rd.flatten().find(|e| e.file_name().to_string_lossy().to_lowercase() == s.to_lowercase()).map(|e| e.path()));
            match found {
                Some(p) => cur = p,
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && cur.is_file() {
            if let Some(z) = std::fs::read(&cur).ok().and_then(|b| parse_tzif(&b)) {
                return Some(z);
            }
        }
    }
    // ONLY a host with no tz database at all (Windows) falls back to the embedded table of the common zones (IANA release 2026f; names
    // compare case-insensitively, as on disk): where a database exists, a zone it lacks is unknown, never filled in from the table
    if ROOTS.iter().any(|r| std::path::Path::new(r).is_dir()) {
        return None;
    }
    super::tzdata::EMBEDDED_ZONES.iter().find(|(n, _)| n.eq_ignore_ascii_case(tz)).and_then(|(_, b)| parse_tzif(b))
}

fn zone(tz: &str) -> Option<Arc<Tz>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Arc<Tz>>>>> = OnceLock::new();
    let c = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(h) = c.lock().ok()?.get(tz) {
        return h.clone();
    }
    let z = find_zone(tz).map(Arc::new);
    c.lock().ok()?.insert(tz.to_string(), z.clone());
    z
}

/// Is this a time zone the runtime knows (IANA name)?
pub fn known_time_zone(tz: &str) -> bool {
    !tz.is_empty() && utf16_len(tz) <= 64 && re!(r"^[A-Za-z0-9_+\-/]+$").is_match(tz) && zone(tz).is_some()
}

/// Day of week (0 = Sunday) and minute of day at `now` (ms since the epoch) in `tz`, or `None` when it cannot be computed.
pub fn clock_at(now: &Value, tz: &str) -> Option<(i64, i64)> {
    let f = now.as_f64().filter(|x| x.is_finite() && x.abs() <= 8.64e15)?;
    let t = (f.trunc() as i64).div_euclid(1000);
    let off = zone(tz)?.offset_at(t);
    let local = t + off;
    Some(((local.div_euclid(86400) + 4).rem_euclid(7), local.rem_euclid(86400) / 60))
}

/// `Date.parse` of an RFC 3339 `...Z` second-precision time (day 1..31 rolls over the month, 24:00:00 is the next day); else `None`.
pub fn parse_utc_ms(v: &Value) -> Option<i64> {
    let s = v.as_str()?;
    if !re!(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$").is_match(s) {
        return None;
    }
    let n = |a: usize, b: usize| s[a..b].parse::<i64>().unwrap_or(0);
    let (y, mo, d, h, mi, se) = (n(0, 4), n(5, 7), n(8, 10), n(11, 13), n(14, 16), n(17, 19));
    if !((1..=12).contains(&mo) && (1..=31).contains(&d) && mi <= 59 && se <= 59 && (h <= 23 || (h == 24 && mi == 0 && se == 0))) {
        return None;
    }
    Some((days_from_civil(y, mo, 1) + d - 1) * 86_400_000 + h * 3_600_000 + mi * 60_000 + se * 1000)
}

// ---- validation -------------------------------------------------------------------------------------------------------------

/// `None` iff `rules` is a well-formed rules block for `d`; the reason otherwise.
pub fn business_rules_error(d: &Value, rules: &Value) -> Option<String> {
    validate_rules(d, rules).err().map(|e| e.message)
}

fn ccy_map(d: &Value, m: Option<&Value>, at: &str) -> R<()> {
    let Some(mo) = m.and_then(Value::as_object).filter(|o| !o.is_empty() && o.len() <= MAX_RULE_CURRENCIES) else {
        return bad(format!("{at}: a map of 1..{MAX_RULE_CURRENCIES} currencies to amounts"));
    };
    let money = money_of(d)?;
    for (c, v) in mo {
        if !re!(r"^[A-Z]{3}$").is_match(c) {
            return bad(format!("{at}: '{c}' is not an ISO 4217 currency code"));
        }
        minor_units(v, money.exp, &format!("{at}.{c}"))?;
    }
    Ok(())
}

fn ref_of(s: &Map<String, Value>) -> Value {
    let mut m = Map::new();
    for k in ["param", "role"] {
        if let Some(v) = s.get(k) {
            m.insert(k.into(), v.clone());
        }
    }
    Value::Object(m)
}

fn name_ok(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| re!(r"^[a-z][a-z0-9_]{0,63}$").is_match(s))
}

fn hhmm_ok(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| re!(r"^([01][0-9]|2[0-3]):([0-5][0-9])$").is_match(s))
}

fn domain_ok(s: &str) -> bool {
    s.len() >= 1 && s.len() <= 253 && re!(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$").is_match(s)
}

fn str_list_ok(v: &Value, ok: impl Fn(&str) -> bool) -> bool {
    v.as_array().is_some_and(|a| !a.is_empty() && a.len() <= MAX_RULE_LIST && a.iter().all(|x| x.as_str().is_some_and(&ok)))
}

fn validate_rules(d: &Value, r: &Value) -> R<()> {
    let Some(ro) = r.as_object() else { return bad("rules must be an object") };
    closed(ro, &RULE_KEYS, "rules")?;
    if ro.keys().filter(|k| *k != "examples").count() == 0 {
        return bad("rules: name at least one rule");
    }
    if let Some(a) = ro.get("amount") {
        let Some(ao) = a.as_object() else { return bad("rules.amount must be {max: {CCY: amount}}") };
        closed(ao, &["max"], "rules.amount")?;
        ccy_map(d, ao.get("max"), "rules.amount.max")?;
    }
    if let Some(ap) = ro.get("approval") {
        let Some(apo) = ap.as_object() else { return bad("rules.approval must be an object") };
        closed(apo, &["above", "always", "approvers", "group"], "rules.approval")?;
        if apo.get("always").is_some_and(|a| a != &Value::Bool(true)) {
            return bad("rules.approval.always is true or absent");
        }
        if apo.contains_key("above") == apo.contains_key("always") {
            return bad("rules.approval: give exactly one of above or always");
        }
        if apo.contains_key("above") {
            ccy_map(d, apo.get("above"), "rules.approval.above")?;
        }
        if let Some(n) = apo.get("approvers") {
            if !isi(n) || n.as_f64().unwrap_or(0.0) < 1.0 || n.as_f64().unwrap_or(0.0) > MAX_RULE_APPROVERS {
                return bad(format!("rules.approval.approvers is 1..{}", MAX_RULE_APPROVERS as i64));
            }
        }
        if let Some(g) = apo.get("group") {
            if !name_ok(Some(g)) {
                return bad("rules.approval.group is a lowercase name");
            }
        }
    }
    if let Some(sc) = ro.get("scope") {
        let Some(sa) = sc.as_array().filter(|a| !a.is_empty() && a.len() <= MAX_RULE_LIST) else {
            return bad(format!("rules.scope is a list of 1..{MAX_RULE_LIST} bindings"));
        };
        for (i, s) in sa.iter().enumerate() {
            let Some(so) = s.as_object() else { return bad(format!("rules.scope[{i}] must be an object")) };
            closed(so, &["param", "role", "caller"], &format!("rules.scope[{i}]"))?;
            let (_, p) = resolve_param_ref(d, &ref_of(so), &format!("rules.scope[{i}]"))?;
            if !matches!(p["type"].as_str(), Some("string") | Some("integer")) {
                return bad(format!("rules.scope[{i}]: the bound parameter must be a string or integer id"));
            }
            if !name_ok(so.get("caller")) {
                return bad(format!("rules.scope[{i}].caller is a lowercase attribute name of the caller"));
            }
        }
    }
    if let Some(rt) = ro.get("rate") {
        let Some(ra) = rt.as_array().filter(|a| !a.is_empty() && a.len() <= 4) else { return bad("rules.rate is a list of 1..4 limits") };
        for (i, x) in ra.iter().enumerate() {
            let Some(xo) = x.as_object() else { return bad(format!("rules.rate[{i}] must be an object")) };
            closed(xo, &["max", "per", "by"], &format!("rules.rate[{i}]"))?;
            if !xo.get("max").is_some_and(|m| isi(m) && (1.0..=1_000_000.0).contains(&m.as_f64().unwrap_or(0.0))) {
                return bad(format!("rules.rate[{i}].max is 1..1000000"));
            }
            if !xo.get("per").and_then(Value::as_str).is_some_and(|p| period_ms(p).is_some()) {
                return bad(format!("rules.rate[{i}].per is hour or day"));
            }
            if let Some(b) = xo.get("by") {
                if !matches!(b.as_str(), Some("principal") | Some("org")) {
                    return bad(format!("rules.rate[{i}].by is principal or org"));
                }
            }
        }
    }
    if let Some(h) = ro.get("hours") {
        let Some(ho) = h.as_object() else { return bad("rules.hours must be an object") };
        closed(ho, &["days", "from", "to", "tz", "outside"], "rules.hours")?;
        let days_ok = ho.get("days").and_then(Value::as_array).is_some_and(|a| {
            let ds: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
            !a.is_empty() && ds.len() == a.len() && ds.iter().all(|x| RULE_DAYS.contains(x)) && ds.iter().collect::<BTreeSet<_>>().len() == ds.len()
        });
        if !days_ok {
            return bad(format!("rules.hours.days is a list of distinct days ({})", RULE_DAYS.join(", ")));
        }
        if !hhmm_ok(ho.get("from")) || !hhmm_ok(ho.get("to")) {
            return bad("rules.hours.from and .to are HH:MM (24 h)");
        }
        if !ho.get("tz").and_then(Value::as_str).is_some_and(known_time_zone) {
            return bad(format!("rules.hours.tz '{}' is not a known IANA time zone", js_opt(ho.get("tz"))));
        }
        if let Some(o) = ho.get("outside") {
            if !matches!(o.as_str(), Some("escalate") | Some("deny")) {
                return bad("rules.hours.outside is escalate or deny");
            }
        }
    }
    if let Some(x) = ro.get("recipients") {
        let Some(xo) = x.as_object() else { return bad("rules.recipients must be an object") };
        closed(xo, &["param", "role", "domains", "addresses"], "rules.recipients")?;
        let (name, p) = resolve_param_ref(d, &ref_of(xo), "rules.recipients")?;
        match p["type"].as_str() {
            Some("array") | Some("set") => {
                if p.get("items").is_some_and(|i| !i.is_null() && i != "string") {
                    return bad(format!("rules.recipients: '{name}' must hold strings"));
                }
                if !p.get("max_items").is_some_and(|m| isi(m) && !negzero(m) && m.as_f64().unwrap_or(0.0) <= MAX_RULE_LIST as f64) {
                    return bad(format!("rules.recipients: the list parameter '{name}' needs max_items <= {MAX_RULE_LIST} so every entry can be checked"));
                }
            }
            Some("string") => {}
            _ => return bad(format!("rules.recipients: '{name}' must be a string or a bounded list of strings")),
        }
        let (doms, adds) = (xo.get("domains"), xo.get("addresses"));
        if doms.is_none() && adds.is_none() {
            return bad("rules.recipients: give domains and/or addresses");
        }
        if doms.is_some_and(|v| !str_list_ok(v, domain_ok)) {
            return bad("rules.recipients.domains is a list of lowercase domain names");
        }
        if adds.is_some_and(|v| !str_list_ok(v, |s| re!(r"^[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}$").is_match(s))) {
            return bad("rules.recipients.addresses is a list of lowercase email addresses");
        }
    }
    if let Some(rq) = ro.get("required") {
        let Some(ra) = rq.as_array().filter(|a| !a.is_empty() && a.len() <= MAX_RULE_LIST) else {
            return bad("rules.required is a list of distinct parameter names");
        };
        let distinct: BTreeSet<String> = ra.iter().map(crate::canonicalize).collect();
        if distinct.len() != ra.len() {
            return bad("rules.required is a list of distinct parameter names");
        }
        for n in ra {
            if !n.as_str().is_some_and(|s| params_of(d).is_ok_and(|p| p.contains_key(s))) {
                return bad(format!("rules.required: '{}' has no parameter '{}'", verb_of(d), js_str(n)));
            }
        }
    }
    if let Some(ex) = ro.get("examples") {
        let Some(ea) = ex.as_array().filter(|a| a.len() <= MAX_RULE_EXAMPLES) else {
            return bad(format!("rules.examples is a list of at most {MAX_RULE_EXAMPLES}"));
        };
        for (i, e) in ea.iter().enumerate() {
            let Some(eo) = e.as_object() else { return bad(format!("rules.examples[{i}] must be an object")) };
            closed(eo, &["params", "caller", "at", "recent", "expect"], &format!("rules.examples[{i}]"))?;
            if !eo.get("params").is_some_and(Value::is_object) {
                return bad(format!("rules.examples[{i}].params must be an object"));
            }
            if eo.get("caller").is_some_and(|c| !c.is_object()) {
                return bad(format!("rules.examples[{i}].caller must be an object"));
            }
            if eo.get("at").is_some_and(|a| parse_utc_ms(a).is_none()) {
                return bad(format!("rules.examples[{i}].at is an RFC 3339 UTC time (…Z)"));
            }
            if let Some(rc) = eo.get("recent") {
                if !rc.as_object().is_some_and(|m| m.values().all(|n| isi(n) && !negzero(n) && n.as_f64().unwrap_or(-1.0) >= 0.0)) {
                    return bad(format!("rules.examples[{i}].recent maps rate indexes to counts"));
                }
            }
            if !matches!(eo.get("expect").and_then(Value::as_str), Some("allow") | Some("escalate") | Some("deny")) {
                return bad(format!("rules.examples[{i}].expect is allow, escalate or deny"));
            }
        }
    }
    Ok(())
}

// ---- compiled form ----------------------------------------------------------------------------------------------------------

/// Digest of a rules block (examples are tests, not rules).
pub fn business_rules_digest(verb: &str, rules: &Value) -> Result<String, String> {
    let mut m = rules.as_object().cloned().unwrap_or_default();
    m.remove("examples");
    hash_canonical_strict(&json!({"d": BUSINESS_RULES_DOMAIN, "verb": verb, "rules": m})).ok_or_else(|| "the rules are not strictly canonical".to_string())
}

fn pth(n: &str) -> String {
    format!("action.params.{n}")
}

fn always(verb: &str) -> Value {
    json!({"field": "action.verb", "op": "eq", "value": verb})
}

fn and_of(cs: Vec<Option<Value>>) -> Value {
    let mut xs: Vec<Value> = cs.into_iter().flatten().collect();
    if xs.len() == 1 {
        xs.remove(0)
    } else {
        json!({"all_of": xs})
    }
}

fn ccy_cond(m: &Money, c: &str) -> Option<Value> {
    match &m.ccy {
        Ccy::Param(p) => Some(json!({"field": pth(p), "op": "eq", "value": c})),
        Ccy::Literal(l) if l == c => None,
        Ccy::Literal(_) => Some(json!({"field": "action.verb", "op": "eq", "value": "\u{0}never"})),
    }
}

fn rule_id(s: &str) -> String {
    s.to_lowercase().chars().map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' { c } else { '_' }).take(64).collect()
}

/// `12345` minor units of USD (exp 2) -> "123.45 USD". Deterministic (no locale).
pub fn format_money(minor: i64, ccy: &str, exp: i64) -> String {
    let s = format!("{:0>w$}", minor, w = (exp + 1).max(1) as usize);
    if exp > 0 {
        let k = s.len() - exp as usize;
        format!("{}.{} {ccy}", &s[..k], &s[k..])
    } else {
        format!("{s} {ccy}")
    }
}

fn day_name(d: &str) -> &'static str {
    match d {
        "sun" => "Sun",
        "mon" => "Mon",
        "tue" => "Tue",
        "wed" => "Wed",
        "thu" => "Thu",
        "fri" => "Fri",
        _ => "Sat",
    }
}

fn day_idx(d: &str) -> usize {
    RULE_DAYS.iter().position(|x| *x == d).unwrap_or(0)
}

fn hours_text(h: &Value) -> String {
    let mut ds: Vec<&str> = h["days"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    ds.sort_by_key(|d| day_idx(d));
    let idx: Vec<usize> = ds.iter().map(|d| day_idx(d)).collect();
    let run = idx.len() > 2 && idx.iter().enumerate().all(|(k, x)| k == 0 || *x == idx[k - 1] + 1);
    let days = if run { format!("{}-{}", day_name(ds[0]), day_name(ds[ds.len() - 1])) } else { ds.iter().map(|d| day_name(d)).collect::<Vec<_>>().join(", ") };
    format!("{days} {}-{} ({})", h["from"].as_str().unwrap_or(""), h["to"].as_str().unwrap_or(""), h["tz"].as_str().unwrap_or(""))
}

fn recipients_text(x: &Value) -> String {
    let mut parts: Vec<String> =
        x.get("domains").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(|d| format!("addresses at {d}")).collect();
    parts.extend(x.get("addresses").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(String::from));
    parts.join(" or ")
}

fn ref_for(s: &Value) -> Value {
    s.as_object().map(ref_of).unwrap_or(Value::Null)
}

fn sorted_keys(m: &Value) -> Vec<String> {
    let mut k: Vec<String> = m.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
    sort_u16(&mut k);
    k
}

/// Compile a rules block for `d` into tighten rules and accumulators. `bad_rules` for a malformed block. Deterministic.
pub fn compile_business_rules(d: &Value, rules: &Value) -> R<Value> {
    validate_rules(d, rules)?;
    let verb = verb_of(d).to_string();
    let (mut t, mut acc): (Vec<Value>, Vec<Value>) = (vec![], vec![]);
    let mut out = Map::new();
    out.insert("v".into(), json!(1));
    out.insert("verb".into(), json!(verb));
    out.insert("rules_digest".into(), json!(business_rules_digest(&verb, rules).map_err(|e| kerr("bad_rules", e))?));
    out.insert("def_digest".into(), json!(def_digest(d)));
    let uses_money = rules.get("amount").is_some() || rules["approval"].get("above").is_some();
    let money = if uses_money { Some(money_of(d)?) } else { None };
    let unlisted = |listed: &[String]| -> Option<Value> {
        let m = money.as_ref()?;
        match &m.ccy {
            Ccy::Param(p) => Some(json!({"not": {"field": pth(p), "op": "in", "value": listed}})),
            Ccy::Literal(l) => (!listed.contains(l)).then(|| always(&verb)),
        }
    };
    if let Some(a) = rules.get("amount") {
        let m = money.as_ref().unwrap();
        let listed = sorted_keys(&a["max"]);
        for c in &listed {
            let mx = minor_units(&a["max"][c.as_str()], m.exp, &format!("rules.amount.max.{c}"))?;
            t.push(json!({"id": rule_id(&format!("amount_max_{c}")), "when": and_of(vec![ccy_cond(m, c), Some(json!({"field": pth(&m.amount), "op": "gt", "value": mx}))]),
                          "signal": "deny", "reason": format!("the amount is above the {} ceiling", format_money(mx, c, m.exp))}));
        }
        if let Some(u) = unlisted(&listed) {
            t.push(json!({"id": "amount_currency", "when": u, "signal": "deny", "reason": format!("only {} amounts are allowed", listed.join(", "))}));
        }
    }
    if let Some(ap) = rules.get("approval") {
        let mut approval = Map::new();
        approval.insert("approvers".into(), ap.get("approvers").filter(|x| !x.is_null()).cloned().unwrap_or_else(|| json!(1)));
        if let Some(g) = ap.get("group") {
            approval.insert("group".into(), g.clone());
        }
        out.insert("approval".into(), Value::Object(approval));
        if ap.get("always").is_some_and(|x| x == &Value::Bool(true)) {
            t.push(json!({"id": "approval_always", "when": always(&verb), "signal": "escalate", "reason": "this action always needs approval"}));
        } else {
            let m = money.as_ref().unwrap();
            let listed = sorted_keys(&ap["above"]);
            for c in &listed {
                let x = minor_units(&ap["above"][c.as_str()], m.exp, &format!("rules.approval.above.{c}"))?;
                t.push(json!({"id": rule_id(&format!("approval_above_{c}")), "when": and_of(vec![ccy_cond(m, c), Some(json!({"field": pth(&m.amount), "op": "gt", "value": x}))]),
                              "signal": "escalate", "reason": format!("amounts above {} need approval", format_money(x, c, m.exp))}));
            }
            if let Some(u) = unlisted(&listed) {
                t.push(json!({"id": "approval_currency", "when": u, "signal": "escalate", "reason": format!("amounts in a currency other than {} need approval", listed.join(", "))}));
            }
        }
    }
    for (i, s) in rules.get("scope").and_then(Value::as_array).into_iter().flatten().enumerate() {
        let (name, _) = resolve_param_ref(d, &ref_for(s), &format!("rules.scope[{i}]"))?;
        let caller = s["caller"].as_str().unwrap_or("");
        t.push(json!({"id": format!("scope_{i}"), "when": {"not": {"field": pth(&name), "op": "eq", "ref": format!("subject.{caller}")}}, "signal": "deny",
                      "reason": format!("{name} must be the caller's own {caller}")}));
    }
    for (i, r) in rules.get("rate").and_then(Value::as_array).into_iter().flatten().enumerate() {
        let rid = format!("rate_{i}");
        let by = r.get("by").and_then(Value::as_str).unwrap_or("principal");
        let per = r["per"].as_str().unwrap_or("hour");
        let mx = r["max"].clone();
        acc.push(json!({"id": rid, "agg": "count", "sel": {"verbs": [verb]}, "win": {"kind": "sliding", "ms": period_ms(per).unwrap_or(0)}, "key": null, "domain_max": mx, "cap": mx,
                        "holder": {"kind": "site_local"}, "scope": by}));
        t.push(json!({"id": rid, "when": {"field": format!("env.acc.{rid}"), "op": "gte", "value": mx}, "signal": "deny", "reason": format!("at most {} per {per} per {by}", js_str(&mx))}));
    }
    if let Some(h) = rules.get("hours") {
        let (frm, to) = (mins(h["from"].as_str().unwrap_or("00:00")), mins(h["to"].as_str().unwrap_or("00:00")));
        let mut dows: Vec<i64> = h["days"].as_array().into_iter().flatten().filter_map(Value::as_str).map(|x| day_idx(x) as i64).collect();
        dows.sort();
        let (in_time, day);
        if frm < to {
            in_time = json!({"all_of": [{"field": "env.clock.min", "op": "gte", "value": frm}, {"field": "env.clock.min", "op": "lt", "value": to}]});
            day = json!({"field": "env.clock.dow", "op": "in", "value": dows});
        } else {
            // an overnight window (22:00-06:00): the day named is the day the window starts
            in_time = json!({"any_of": [{"field": "env.clock.min", "op": "gte", "value": frm}, {"field": "env.clock.min", "op": "lt", "value": to}]});
            let next: Vec<i64> = dows.iter().map(|x| (x + 1) % 7).collect();
            day = json!({"any_of": [{"all_of": [{"field": "env.clock.dow", "op": "in", "value": dows}, {"field": "env.clock.min", "op": "gte", "value": frm}]},
                                    {"all_of": [{"field": "env.clock.dow", "op": "in", "value": next}, {"field": "env.clock.min", "op": "lt", "value": to}]}]});
        }
        out.insert("clock_tz".into(), h["tz"].clone());
        t.push(json!({"id": "hours", "when": {"not": {"all_of": [day, in_time]}}, "signal": h.get("outside").cloned().unwrap_or_else(|| json!("escalate")), "reason": format!("outside {}", hours_text(h))}));
    }
    if let Some(x) = rules.get("recipients") {
        let (name, p) = resolve_param_ref(d, &ref_for(x), "rules.recipients")?;
        let ok_at = |path: String| -> Value {
            let mut alts: Vec<Value> = x
                .get("domains")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(|dm| {
                    let esc: String = dm.chars().flat_map(|c| if matches!(c, '\\' | '*' | '?') { vec!['\\', c] } else { vec![c] }).collect();
                    json!({"field": path, "op": "like", "value": format!("*@{esc}")})
                })
                .collect();
            if let Some(a) = x.get("addresses").and_then(Value::as_array) {
                let mut l: Vec<String> = a.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                sort_u16(&mut l);
                alts.push(json!({"field": path, "op": "in", "value": l}));
            }
            json!({"any_of": alts})
        };
        let ok = if p["type"] == "string" {
            ok_at(pth(&name))
        } else {
            let n = p["max_items"].as_i64().unwrap_or(0);
            let mut all: Vec<Value> = (0..n)
                .map(|i| json!({"any_of": [{"field": pth(&format!("{name}.{i}")), "op": "exists", "value": false}, ok_at(pth(&format!("{name}.{i}")))]}))
                .collect();
            all.push(json!({"field": pth(&format!("{name}.{n}")), "op": "exists", "value": false}));
            json!({"all_of": all})
        };
        t.push(json!({"id": "recipients", "when": {"not": ok}, "signal": "deny", "reason": format!("{name} may only name {}", recipients_text(x))}));
    }
    for (i, n) in rules.get("required").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).enumerate() {
        let pr = &params_of(d)?[n];
        let missing = if pr["type"] == "string" {
            json!({"any_of": [{"field": pth(n), "op": "exists", "value": false}, {"field": pth(n), "op": "eq", "value": ""}]})
        } else {
            json!({"field": pth(n), "op": "exists", "value": false})
        };
        t.push(json!({"id": format!("required_{i}"), "when": missing, "signal": "deny", "reason": format!("{n} is required")}));
    }
    for r in t.iter_mut() {
        if let Some(s) = r.get("reason").and_then(Value::as_str) {
            let u: Vec<u16> = s.encode_utf16().collect();
            if u.len() > 256 {
                r["reason"] = json!(format!("{}...", String::from_utf16_lossy(&u[..253])));
            }
        }
    }
    out.insert("tighten".into(), Value::Array(t));
    out.insert("accumulators".into(), Value::Array(acc));
    Ok(Value::Object(out))
}

// ---- evaluation -------------------------------------------------------------------------------------------------------------

fn rank(d: &str) -> i32 {
    match d {
        "deny" => 0,
        "escalate" => 1,
        _ => 2,
    }
}

/// Meet in the order deny < escalate < allow.
pub fn meet_decision<'a>(a: &'a str, b: &'a str) -> &'a str {
    if rank(a) <= rank(b) {
        a
    } else {
        b
    }
}

/// The predicate context the compiled rules are evaluated in: verifier-computed `env` members only.
pub fn rules_context(c: &Value, i: &Value) -> Value {
    let mut env = Map::new();
    if let Some(tz) = c.get("clock_tz").and_then(Value::as_str) {
        if let Some((dow, min)) = clock_at(i.get("now").unwrap_or(&Value::Null), tz) {
            env.insert("clock".into(), json!({"dow": dow, "min": min}));
        }
    }
    let mut acc = Map::new();
    for a in c["accumulators"].as_array().into_iter().flatten() {
        let id = a["id"].as_str().unwrap_or("");
        if let Some(n) = i.get("counts").and_then(|k| k.get(id)).filter(|n| isi(n) && n.as_f64().unwrap_or(-1.0) >= 0.0) {
            acc.insert(id.to_string(), n.clone());
        }
    }
    env.insert("acc".into(), Value::Object(acc));
    json!({
        "action": {"verb": c["verb"], "resource": i.get("resource").filter(|r| !r.is_null()).cloned().unwrap_or_else(|| json!("")), "params": i.get("params").cloned().unwrap_or(Value::Null)},
        "subject": i.get("subject").filter(|s| !s.is_null()).cloned().unwrap_or_else(|| json!({})), "env": env
    })
}

/// Evaluate compiled rules: `allow` unless a rule fires; a fired rule caps the decision at its signal. Never panics.
pub fn evaluate_business_rules(c: &Value, i: &Value) -> Value {
    let ctx = rules_context(c, i);
    let cx = Ctx::new(&ctx);
    let mut decision = "allow".to_string();
    let (mut reasons, mut fired): (Vec<Value>, Vec<Value>) = (vec![], vec![]);
    let mut approval = false;
    for r in c["tighten"].as_array().into_iter().flatten() {
        if evaluate_condition_tri(&r["when"], &cx) == Tri::False {
            continue;
        }
        let sig = r["signal"].as_str().unwrap_or("deny");
        decision = meet_decision(&decision, sig).to_string();
        let id = r["id"].as_str().unwrap_or("");
        fired.push(json!(id));
        reasons.push(json!(format!("{id}: {}", r.get("reason").and_then(Value::as_str).unwrap_or(sig))));
        if sig == "escalate" && id.starts_with("approval_") {
            approval = true;
        }
    }
    let mut out = Map::new();
    out.insert("decision".into(), json!(decision));
    out.insert("reasons".into(), Value::Array(reasons));
    out.insert("fired".into(), Value::Array(fired));
    if approval {
        if let Some(a) = c.get("approval").filter(|a| !a.is_null()) {
            out.insert("approval".into(), a.clone());
        }
    }
    Value::Object(out)
}

/// The decision with rules applied to a base decision: the meet, so rules never raise it.
pub fn with_business_rules<'a>(base: &'a str, v: &'a Value) -> &'a str {
    meet_decision(base, v["decision"].as_str().unwrap_or("deny"))
}

/// Run a rules block's examples.
pub fn run_rule_examples(d: &Value, rules: &Value) -> R<Vec<Value>> {
    let c = compile_business_rules(d, rules)?;
    let mut out = Vec::new();
    for (index, e) in rules.get("examples").and_then(Value::as_array).into_iter().flatten().enumerate() {
        let mut counts = Map::new();
        for (k, a) in c["accumulators"].as_array().into_iter().flatten().enumerate() {
            counts.insert(a["id"].as_str().unwrap_or("").to_string(), e.get("recent").and_then(|r| r.get(k.to_string())).cloned().unwrap_or_else(|| json!(0)));
        }
        let at = e.get("at").cloned().unwrap_or_else(|| json!(DEFAULT_EXAMPLE_AT));
        let mut inp = Map::new();
        inp.insert("params".into(), e["params"].clone());
        inp.insert("now".into(), parse_utc_ms(&at).map_or(Value::Null, |n| json!(n)));
        inp.insert("counts".into(), Value::Object(counts));
        if let Some(cl) = e.get("caller").filter(|c| !c.is_null()) {
            inp.insert("subject".into(), cl.clone());
        }
        let v = evaluate_business_rules(&c, &Value::Object(inp));
        let got = v["decision"].as_str().unwrap_or("deny");
        let why: Vec<&str> = v["reasons"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        out.push(json!({"index": index, "expect": e["expect"], "got": got, "ok": e["expect"].as_str() == Some(got), "why": if why.is_empty() { "no rule fired".to_string() } else { why.join("; ") }}));
    }
    Ok(out)
}

/// One plain sentence per rule, for the policy card and the dashboard. `bad_rules` for a malformed block.
pub fn explain_business_rules(d: &Value, rules: &Value) -> R<Vec<String>> {
    validate_rules(d, rules)?;
    let mut out = Vec::new();
    let m = if rules.get("amount").is_some() || rules["approval"].get("above").is_some() { Some(money_of(d)?) } else { None };
    let lst = |mp: &Value| -> R<String> {
        let m = m.as_ref().unwrap();
        let mut parts = Vec::new();
        for c in sorted_keys(mp) {
            parts.push(format_money(minor_units(&mp[c.as_str()], m.exp, &c)?, &c, m.exp));
        }
        Ok(parts.join(", "))
    };
    if let Some(a) = rules.get("amount") {
        out.push(format!("Refuses amounts above {}; any other currency is refused.", lst(&a["max"])?));
    }
    if let Some(ap) = rules.get("approval") {
        let n = ap.get("approvers").filter(|x| !x.is_null()).and_then(Value::as_i64).unwrap_or(1);
        let who = format!(
            "{n} approver{}{}",
            if n == 1 { "" } else { "s" },
            ap.get("group").and_then(Value::as_str).map_or(String::new(), |g| format!(" from the {g} group"))
        );
        if ap.get("always").is_some_and(|x| x == &Value::Bool(true)) {
            out.push(format!("Always needs approval by {who}."));
        } else {
            out.push(format!("Needs approval by {who} when the amount is above {} (or in another currency).", lst(&ap["above"])?));
        }
    }
    for s in rules.get("scope").and_then(Value::as_array).into_iter().flatten() {
        let (name, _) = resolve_param_ref(d, &ref_for(s), "rules.scope")?;
        out.push(format!("Only the caller's own records: {name} must be the caller's {}.", s["caller"].as_str().unwrap_or("")));
    }
    for r in rules.get("rate").and_then(Value::as_array).into_iter().flatten() {
        out.push(format!(
            "At most {} per {} per {}.",
            js_str(&r["max"]),
            r["per"].as_str().unwrap_or(""),
            if r.get("by").and_then(Value::as_str) == Some("org") { "organisation" } else { "principal" }
        ));
    }
    if let Some(h) = rules.get("hours") {
        out.push(format!(
            "Only {}; outside those hours it {}.",
            hours_text(h),
            if h.get("outside").and_then(Value::as_str) == Some("deny") { "is refused" } else { "needs approval" }
        ));
    }
    if let Some(x) = rules.get("recipients") {
        let (name, _) = resolve_param_ref(d, &ref_for(x), "rules.recipients")?;
        out.push(format!("{name} may only name {}.", recipients_text(x)));
    }
    if let Some(rq) = rules.get("required") {
        out.push(format!("Requires {}.", rq.as_array().into_iter().flatten().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")));
    }
    Ok(out)
}

// ---- lint -------------------------------------------------------------------------------------------------------------------

pub const BUSINESS_RULE_LINTS: [(&str, &str, &str); 4] = [
    ("LR-001", "error", "a rules block is malformed or names a parameter the action does not have"),
    ("LR-002", "error", "a contradiction: under the rules the action can never be allowed"),
    ("LR-003", "warning", "a rule that can never fire or that another rule already covers"),
    ("LR-004", "error", "a rules example does not decide as it expects"),
];

/// Lint one action's rules.
pub fn lint_business_rules(d: &Value, rules: &Value) -> Vec<Value> {
    let f = |rule: &str, sev: &str, msg: String| json!({"rule": rule, "severity": sev, "verb": d["verb"], "message": msg});
    if let Some(e) = business_rules_error(d, rules) {
        return vec![f("LR-001", "error", e)];
    }
    let r = rules;
    let mut out = Vec::new();
    let m = if r.get("amount").is_some() || r["approval"].get("above").is_some() { money_of(d).ok() } else { None };
    let amt = m.as_ref().and_then(|m| d["params"].get(&m.amount));
    let ccy_values: Option<Vec<String>> = m.as_ref().and_then(|m| match &m.ccy {
        Ccy::Param(p) => {
            d["params"][p.as_str()].get("values").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        }
        Ccy::Literal(l) => Some(vec![l.clone()]),
    });
    if let (Some(a), Some(m)) = (r.get("amount"), m.as_ref()) {
        let listed: Vec<String> = a["max"].as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        if let Some(cv) = &ccy_values {
            if !cv.iter().any(|c| listed.contains(c)) {
                out.push(f(
                    "LR-002",
                    "error",
                    format!("rules.amount: none of the action's currencies ({}) has a ceiling, so every call is refused", cv.join(", ")),
                ));
            }
        }
        for c in &listed {
            let mx = minor_units(&a["max"][c.as_str()], m.exp, c).unwrap_or(0);
            if ccy_values.as_ref().is_some_and(|cv| !cv.contains(c)) {
                out.push(f("LR-003", "warning", format!("rules.amount.max.{c}: the action never uses {c}")));
            }
            if let Some(lo) = amt.and_then(|a| a.get("min")).and_then(Value::as_i64) {
                if mx < lo {
                    out.push(f(
                        "LR-002",
                        "error",
                        format!(
                            "rules.amount.max.{c}: the ceiling {} is below the parameter's minimum, so every {c} call is refused",
                            format_money(mx, c, m.exp)
                        ),
                    ));
                }
            }
            if let Some(hi) = amt.and_then(|a| a.get("max")).and_then(Value::as_i64) {
                if mx >= hi {
                    out.push(f("LR-003", "warning", format!("rules.amount.max.{c}: the parameter's own maximum already bounds the amount below this ceiling")));
                }
            }
        }
    }
    if let (Some(above), Some(m)) = (r["approval"].get("above").and_then(Value::as_object), m.as_ref()) {
        for (c, v) in above {
            let x = minor_units(v, m.exp, c).unwrap_or(0);
            let ceil = r.get("amount").and_then(|a| a["max"].get(c));
            if let Some(cv) = ceil {
                if x >= minor_units(cv, m.exp, c).unwrap_or(0) {
                    out.push(f("LR-003", "warning", format!("rules.approval.above.{c}: above the amount ceiling, so the approval can never be asked for")));
                }
            }
            if r.get("amount").is_some() && ceil.is_none() {
                out.push(f("LR-003", "warning", format!("rules.approval.above.{c}: {c} has no ceiling, so it is always refused before an approval")));
            }
        }
    }
    if let Some(h) = r.get("hours").filter(|h| h["from"] == h["to"]) {
        out.push(f(
            "LR-002",
            "error",
            format!(
                "rules.hours: the window {}-{} is empty, so the action is {}",
                h["from"].as_str().unwrap_or(""),
                h["to"].as_str().unwrap_or(""),
                if h.get("outside").and_then(Value::as_str) == Some("deny") { "always refused" } else { "always escalated" }
            ),
        ));
    }
    for n in r.get("required").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
        let p = &d["params"][n];
        if p.get("required") != Some(&Value::Bool(false)) && p["type"] != "string" {
            out.push(f("LR-003", "warning", format!("rules.required: '{n}' is already required by the definition")));
        }
    }
    if let Some(rt) = r.get("rate").and_then(Value::as_array) {
        let mut seen: BTreeMap<String, f64> = BTreeMap::new();
        for x in rt {
            let k = format!("{}|{}", x["per"].as_str().unwrap_or(""), x.get("by").and_then(Value::as_str).unwrap_or("principal"));
            let mx = x["max"].as_f64().unwrap_or(0.0);
            if let Some(prev) = seen.get(&k) {
                out.push(f(
                    "LR-003",
                    "warning",
                    format!(
                        "rules.rate: two limits per {} per {}; only the lower ({}) matters",
                        x["per"].as_str().unwrap_or(""),
                        x.get("by").and_then(Value::as_str).unwrap_or("principal"),
                        js_str(&json!(prev.min(mx)))
                    ),
                ));
            }
            let nv = seen.get(&k).map_or(mx, |p| p.min(mx));
            seen.insert(k, nv);
        }
        if let (Some(h), Some(dd)) = (seen.get("hour|principal"), seen.get("day|principal")) {
            if dd <= h {
                out.push(f("LR-003", "warning", "rules.rate: the daily limit is not above the hourly one, so the hourly limit never fires".into()));
            }
        }
    }
    match run_rule_examples(d, r) {
        Ok(xs) => {
            for x in xs.iter().filter(|x| x["ok"] != Value::Bool(true)) {
                out.push(f(
                    "LR-004",
                    "error",
                    format!(
                        "rules.examples[{}]: expected {}, got {} ({})",
                        js_str(&x["index"]),
                        x["expect"].as_str().unwrap_or(""),
                        x["got"].as_str().unwrap_or(""),
                        x["why"].as_str().unwrap_or("")
                    ),
                ));
            }
        }
        Err(e) => out.push(f("LR-001", "error", e.message)),
    }
    out
}

// ---- semantic diff of rules (widening needs a reviewer) -----------------------------------------------------------------------

fn set_rel(a: &[String], b: &[String]) -> &'static str {
    let (sa, sb): (BTreeSet<&String>, BTreeSet<&String>) = (a.iter().collect(), b.iter().collect());
    let (a_in_b, b_in_a) = (sa.is_subset(&sb), sb.is_subset(&sa));
    if a_in_b && b_in_a {
        "eq"
    } else if b_in_a {
        "narrow"
    } else if a_in_b {
        "widen"
    } else {
        "inc"
    }
}

fn num_rel(a: f64, b: f64) -> &'static str {
    if a == b {
        "eq"
    } else if b < a {
        "narrow"
    } else {
        "widen"
    }
}

fn presence(a: Option<&Value>, b: Option<&Value>) -> Option<&'static str> {
    match (a, b) {
        (None, None) => Some("eq"),
        (None, _) => Some("narrow"),
        (_, None) => Some("widen"),
        _ => None,
    }
}

fn combine(rs: &[&str]) -> &'static str {
    let has = |x: &str| rs.contains(&x);
    if has("inc") || (has("narrow") && has("widen")) {
        "inc"
    } else if has("widen") {
        "widen"
    } else if has("narrow") {
        "narrow"
    } else {
        "eq"
    }
}

fn flip(r: &'static str) -> &'static str {
    match r {
        "widen" => "narrow",
        "narrow" => "widen",
        x => x,
    }
}

fn minutes_of_week(h: &Value) -> BTreeSet<i64> {
    let mut s = BTreeSet::new();
    let (frm, to) = (mins(h["from"].as_str().unwrap_or("00:00")), mins(h["to"].as_str().unwrap_or("00:00")));
    for day in h["days"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        let base = day_idx(day) as i64 * 1440;
        if frm < to {
            s.extend((frm..to).map(|x| base + x));
        } else if frm > to {
            s.extend((frm..1440).map(|x| base + x));
            s.extend((0..to).map(|x| (base + 1440) % 10080 + x));
        }
    }
    s
}

fn keys_of(v: &Value) -> Vec<String> {
    v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default()
}

/// The semantic diff of two rules blocks of one action (either may be absent): `{class, reasons}`. Conservative: unordered = incomparable.
pub fn diff_business_rules(d: &Value, prev: Option<&Value>, next: Option<&Value>) -> R<Value> {
    let empty = json!({});
    let (o, n) = (prev.filter(|p| !p.is_null()).unwrap_or(&empty), next.filter(|p| !p.is_null()).unwrap_or(&empty));
    let uses_money = |x: &Value| x.get("amount").is_some() || x["approval"].get("above").is_some();
    let m = if uses_money(o) || uses_money(n) { Some(money_of(d)?) } else { None };
    let mut rels: Vec<(&str, &'static str)> = Vec::new();
    let ccy_map_rel = |a: &Value, b: &Value| -> R<&'static str> {
        let m = m.as_ref().ok_or_else(|| kerr("bad_rules", "no money"))?;
        // Object.keys(undefined | null) throws in the reference
        if a.is_null() || b.is_null() {
            return Err(kerr("bad_rules", "Cannot convert undefined or null to object"));
        }
        let mut rs = vec![set_rel(&keys_of(a), &keys_of(b))];
        for c in keys_of(a) {
            if let Some(bv) = b.get(&c) {
                rs.push(num_rel(minor_units(&a[c.as_str()], m.exp, &c)? as f64, minor_units(bv, m.exp, &c)? as f64));
            }
        }
        Ok(combine(&rs))
    };
    let mut p = presence(o.get("amount"), n.get("amount"));
    let r = match p.take() {
        Some(x) => x,
        None => ccy_map_rel(&o["amount"]["max"], &n["amount"]["max"])?,
    };
    rels.push(("amount", r));
    let r = match presence(o.get("approval"), n.get("approval")) {
        Some(x) => x,
        None => {
            let (a, b) = (&o["approval"], &n["approval"]);
            let truthy = |x: &Value| x.get("always").is_some_and(|v| v == &Value::Bool(true));
            let mut rs: Vec<&str> = Vec::new();
            if truthy(a) && truthy(b) {
                rs.push("eq");
            } else if truthy(a) {
                rs.push("widen");
            } else if truthy(b) {
                rs.push("narrow");
            } else {
                rs.push(ccy_map_rel(&a["above"], &b["above"])?);
            }
            let ap = |x: &Value| -x.get("approvers").filter(|v| !v.is_null()).and_then(Value::as_f64).unwrap_or(1.0);
            rs.push(num_rel(ap(a), ap(b)));
            rs.push(if a.get("group") == b.get("group") { "eq" } else { "inc" });
            combine(&rs)
        }
    };
    rels.push(("approval", r));
    let skey = |s: &Value| {
        format!("{}|{}|{}", s.get("param").and_then(Value::as_str).unwrap_or(""), s.get("role").and_then(Value::as_str).unwrap_or(""), js_opt(s.get("caller")))
    };
    let list = |x: &Value, k: &str| -> Vec<Value> { x.get(k).and_then(Value::as_array).cloned().unwrap_or_default() };
    let (so, sn): (Vec<String>, Vec<String>) = (list(o, "scope").iter().map(skey).collect(), list(n, "scope").iter().map(skey).collect());
    rels.push(("scope", flip(set_rel(&so, &sn))));
    let best = |x: &Value| -> BTreeMap<String, f64> {
        let mut mp: BTreeMap<String, f64> = BTreeMap::new();
        for r in list(x, "rate") {
            let k = format!("{}|{}", r["per"].as_str().unwrap_or(""), r.get("by").and_then(Value::as_str).unwrap_or("principal"));
            let v = r["max"].as_f64().unwrap_or(f64::INFINITY);
            let e = mp.entry(k).or_insert(f64::INFINITY);
            *e = e.min(v);
        }
        mp
    };
    let (ra, rb) = (best(o), best(n));
    let mut rs: Vec<&str> = Vec::new();
    for k in ra.keys().chain(rb.keys().filter(|k| !ra.contains_key(*k))) {
        rs.push(match (ra.get(k), rb.get(k)) {
            (None, _) => "narrow",
            (_, None) => "widen",
            (Some(a), Some(b)) => num_rel(*a, *b),
        });
    }
    rels.push(("rate", combine(&rs)));
    let r = match presence(o.get("hours"), n.get("hours")) {
        Some(x) => x,
        None => {
            let (a, b) = (&o["hours"], &n["hours"]);
            if a["tz"] != b["tz"] {
                "inc"
            } else {
                let (sa, sb) = (minutes_of_week(a), minutes_of_week(b));
                let inner = if sa == sb {
                    "eq"
                } else if sb.is_subset(&sa) {
                    "narrow"
                } else if sa.is_subset(&sb) {
                    "widen"
                } else {
                    "inc"
                };
                let ov = |x: &Value| if x.get("outside").and_then(Value::as_str) == Some("deny") { 0.0 } else { 1.0 };
                combine(&[inner, num_rel(ov(a), ov(b))])
            }
        }
    };
    rels.push(("hours", r));
    let r = match presence(o.get("recipients"), n.get("recipients")) {
        Some(x) => x,
        None => {
            let (a, b) = (&o["recipients"], &n["recipients"]);
            if a.get("param") != b.get("param") || a.get("role") != b.get("role") {
                "inc"
            } else {
                let allowed = |x: &Value| -> Vec<String> {
                    let mut v: Vec<String> = list(x, "domains").iter().filter_map(Value::as_str).map(|s| format!("@{s}")).collect();
                    v.extend(list(x, "addresses").iter().filter_map(Value::as_str).map(String::from));
                    v
                };
                let (aa, ab) = (allowed(a), allowed(b));
                let covered =
                    |x: &String, st: &[String]| st.contains(x) || (!x.starts_with('@') && x.split('@').nth(1).is_some_and(|dm| st.contains(&format!("@{dm}"))));
                let b_in_a = ab.iter().all(|x| covered(x, &aa));
                let a_in_b = aa.iter().all(|x| covered(x, &ab));
                if b_in_a && a_in_b {
                    "eq"
                } else if b_in_a {
                    "narrow"
                } else if a_in_b {
                    "widen"
                } else {
                    "inc"
                }
            }
        }
    };
    rels.push(("recipients", r));
    let rq = |x: &Value| list(x, "required").iter().filter_map(Value::as_str).map(String::from).collect::<Vec<_>>();
    rels.push(("required", flip(set_rel(&rq(o), &rq(n)))));
    let diffs: Vec<(&str, &str)> = rels.iter().filter(|(_, r)| *r != "eq").cloned().collect();
    let mut reasons: Vec<String> = diffs.iter().map(|(k, r)| format!("rules.{k}: {}", if *r == "inc" { "incomparable" } else { *r })).collect();
    sort_u16(&mut reasons);
    let cls = combine(&diffs.iter().map(|x| x.1).collect::<Vec<_>>());
    Ok(json!({"class": match cls { "eq" => "equal", "inc" => "incomparable", c => c }, "reasons": reasons}))
}

// ---- the reviewer's signature over a widened rules block ----------------------------------------------------------------------

/// `RULES_REVIEW_DOMAIN \0 strictCanonical({verb, def_digest, rules_digest, reviewer_kid, ts})`.
pub fn rules_review_message(b: &Value) -> Result<Vec<u8>, String> {
    let g = |k: &str| b.get(k).cloned().ok_or_else(|| format!("missing {k}"));
    let body =
        json!({"verb": g("verb")?, "def_digest": g("def_digest")?, "rules_digest": g("rules_digest")?, "reviewer_kid": g("reviewer_kid")?, "ts": g("ts")?});
    let mut m = format!("{RULES_REVIEW_DOMAIN}\0").into_bytes();
    m.extend_from_slice(canonicalize_strict(&body)?.as_bytes());
    Ok(m)
}

pub fn sign_rules_review(b: &Value, secret: &[u8]) -> Result<Value, String> {
    let seed: [u8; 32] = secret.try_into().map_err(|_| "the reviewer key must be a 32-byte Ed25519 secret".to_string())?;
    let sig = KeyPair::from_seed(&seed).sign(&rules_review_message(b)?);
    let mut o = b.as_object().cloned().unwrap_or_default();
    o.insert("sig".into(), Value::String(b64_encode(&sig)));
    Ok(Value::Object(o))
}

/// `None` iff `r` is a valid review of exactly these rules on exactly this def (digests, pinned reviewer key, validity, signature). Never panics.
pub fn rules_review_error(r: &Value, d: &Value, rules: &Value, pins: Option<&Value>) -> Option<String> {
    let Some(pins) = pins.filter(|p| !p.is_null()) else { return Some("no reviewer keys are pinned".into()) };
    if let Some(pe) = reviewer_pins_error(pins) {
        return Some(format!("bad pins: {pe}"));
    }
    let Some(ro) = r.as_object() else { return Some("no rules review".into()) };
    if ro.get("verb") != d.get("verb") {
        return Some("the rules review names another action".into());
    }
    if ro.get("def_digest").and_then(Value::as_str) != def_digest(d).as_deref() {
        return Some("the rules review covers another version of the action".into());
    }
    match business_rules_digest(verb_of(d), rules) {
        Ok(x) if ro.get("rules_digest").and_then(Value::as_str) == Some(x.as_str()) => {}
        Ok(_) => return Some("the rules review covers other rules".into()),
        Err(e) => return Some(format!("malformed rules review: {e}")),
    }
    let ts = ro.get("ts");
    let (Some(sig), Some(kid), Some(ts)) =
        (ro.get("sig").and_then(Value::as_str), ro.get("reviewer_kid").and_then(Value::as_str), ts.filter(|t| isi(t) && !negzero(t)))
    else {
        return Some("malformed rules review".into());
    };
    let Some(key) = pins["keys"].as_array().and_then(|ks| ks.iter().find(|k| k["kid"].as_str() == Some(kid))) else {
        return Some(format!("no pinned key '{kid}'"));
    };
    if !super::strs_of(key.get("roles")).iter().any(|x| x == "reviewer") {
        return Some(format!("key '{}' does not hold the reviewer role", js_opt(key.get("kid"))));
    }
    let tsf = ts.as_f64().unwrap_or(0.0);
    if key.get("not_before").and_then(Value::as_f64).is_some_and(|b| tsf < b) || key.get("not_after").and_then(Value::as_f64).is_some_and(|e| tsf > e) {
        return Some("the review time is outside the key validity".into());
    }
    let mut body = ro.clone();
    body.remove("sig");
    match rules_review_message(&Value::Object(body)) {
        Ok(m) if verify_b64u(key["pk"].as_str().unwrap_or(""), &m, sig) => None,
        Ok(_) => Some("the rules review signature is invalid".into()),
        Err(e) => Some(format!("malformed rules review: {e}")),
    }
}

#[cfg(test)]
mod embedded_zone_tests {
    use super::*;

    #[test]
    fn every_embedded_zone_parses_and_the_common_ones_are_there() {
        for (name, bytes) in super::super::tzdata::EMBEDDED_ZONES {
            assert!(parse_tzif(bytes).is_some(), "{name} parses as TZif");
        }
        for n in ["UTC", "Europe/London", "America/New_York", "Australia/Sydney", "Asia/Tokyo", "Europe/Berlin"] {
            assert!(super::super::tzdata::EMBEDDED_ZONES.iter().any(|(z, _)| *z == n), "{n} is embedded");
        }
    }
}
