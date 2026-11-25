//! Deployment checks for a live PCA deployment: clock skew, trusted-proxy settings, the signature-suite policy, root-caveat
//! enforcement and the verifier's required checks, plus the credential scrubber, the result verdict / formatter, the
//! configuration merge and the command-line front end. JSON-valued: a configuration is a `&serde_json::Value` with the reference's
//! member names (`url`, `clock`, `store`, `proxy`, `verifier`), every check returns a result object
//! `{id, status, detail, remediation?, observed?}` (status pass / warn / fail / skip), and every refusal text is the reference's.
//!
//! Network access, the clock and the library under test are injected (closures), so a run is deterministic and testable:
//! [`FetchFn`] (a blocking request returning the response headers), [`NowFn`] (epoch milliseconds) and [`LoadPcaFn`].
//!
//! shortcuts: this crate carries no HTTP client, so without a [`FetchFn`] the clock and probe checks report "cannot observe" (a warn,
//! never a pass); the replay-store check is delegated to [`DoctorDeps::check_store`] (the store-conformance kit is a separate
//! module) and without it a configured adapter is a fail; `load_pca` probes this crate itself and refuses a `pcaDir` (another
//! installation cannot be loaded into a running Rust program); a config file must be `.json`; a `Date` header without a zone is
//! not parsed (the reference reads it as local time, which is host-dependent); a slice that would cut a UTF-16 surrogate pair in
//! half yields U+FFFD (a Rust string cannot hold a lone surrogate).
use crate::action_schema::is_js_ws;
use crate::actions::{js_str_to_number, js_to_number};
use crate::intent_v2::js_number_string;
use crate::oauth::{js_str, truthy};
use crate::{evaluate_caveats, MAX_SKEW_MS};
use regex::Regex;
use serde_json::{json, Map, Number, Value};
use std::sync::OnceLock;

// ---- constants -----------------------------------------------------------------------------------------------------------

pub const CHECK_GROUPS: [&str; 5] = ["clock", "store", "proxy", "suites", "caveats"];
pub const DEFAULT_REFERENCE_URL: &str = "https://www.google.com/generate_204";
pub const ROOT_CAVEAT_MIN_VERSION: &str = "0.4.1";
pub const DEFAULT_REQUIRED: [&str; 7] = ["counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"];
/// The reference's `Object.keys(SIG_SUITES)`: its registry ORDER differs from `crate::REGISTERED_SUITES` (fn-dsa-1024 is last), and the order is
/// printed in the check details.
const SIG_SUITE_KEYS: [&str; 14] = [
    "ed25519",
    "ml-dsa-65",
    "hybrid-ed25519-ml-dsa-65",
    "hybrid-nested-ed25519-ml-dsa-65",
    "slh-dsa-sha2-128f",
    "hybrid-ed25519-slh-dsa-sha2-128f",
    "ml-dsa-87",
    "hybrid-ed25519-ml-dsa-87",
    "slh-dsa-sha2-256s",
    "hybrid-ed25519-slh-dsa-sha2-256s",
    "fn-dsa-512",
    "less-cat1",
    "hybrid-ed25519-less-cat1",
    "fn-dsa-1024",
];
const PROXY_HEADERS: [&str; 3] = ["x-forwarded-for", "forwarded", "x-real-ip"];

pub const CLOCK_REMEDIATION: &str = "Synchronise every verifier, issuer and replay-store host with NTP (chrony or systemd-timesyncd) and alert on drift. PCA tolerates at most 60 s between any two clocks (PCACTN_MAX_SKEW_MS); replay retention is exp + skew, so a clock outside that bound can free a nonce early or reject fresh actions.";
pub const PROXY_REMEDIATION: &str = "Set TRUSTED_PROXY_COUNT to exactly the number of reverse proxies in front of the API that APPEND to the trusted header (1 behind one load balancer / ingress; 0 when clients connect directly), and TRUSTED_PROXY_HEADER to the header they write. Too high lets a client pick its own rate-limit bucket with extra X-Forwarded-For entries; too low merges every client into the proxy's bucket.";
pub const SUITES_REMEDIATION: &str =
    "Set the verifier's allowedSuites to exactly the suites your issuers sign with (names from SIG_SUITES), e.g. ['ed25519'] or ['hybrid-ed25519-ml-dsa-65'].";
pub const PQ_REMEDIATION: &str = "Never set allowUnboundPq. For pure-PQ or hybrid roots, configure pqPins (issuer Ed25519 identity -> PQ public key, from pqPinFor) or verify against your stored root grant (trustedRoot; requirePCA / verifyPCActnCore do this).";
pub const ATOMICITY_REMEDIATION: &str = "Make consumeOnce / advance one atomic operation on the shared store, e.g. Postgres INSERT .. ON CONFLICT (key) DO UPDATE .. WHERE until < $now RETURNING and UPDATE .. WHERE counter < $n RETURNING, Redis SET key NX PX or a Lua compare-and-set; never read, then write. Then run the full kit: pca-store-conformance --adapter <your adapter>.";
pub const DURABILITY_REMEDIATION: &str = "Keep consumed keys and counters in a store with synchronous, persistent commits (Postgres synchronous_commit=on; Redis appendfsync always and maxmemory-policy noeviction), shared by every verifier instance. An in-memory store is only correct for a single process whose lifetime covers the action lifetime.";
pub const CAVEAT_REMEDIATION: &str = "Upgrade @atlasauth/pca to >= 0.4.1 in the deployed application (root caveats outside the envelope are enforced from 0.4.1), redeploy, and re-run pca-doctor with --pca-dir pointing at the application.";

pub const USAGE: &str = "pca-doctor [--url <deployment>] [options]

  --url URL              the live deployment (base URL of the API that verifies PCActns)
  --config FILE          JSON or JS config (see the pca-doctor guide); env and flags override it
  --store MODULE         replay-store adapter module (store conformance kit interface) for the atomicity / durability checks
  --store-option k=v     passed to the adapter factory (repeatable)
  --reference URL|local  clock reference (default https://www.google.com/generate_204)
  --max-skew-ms N        clock fail threshold (default 60000)
  --trusted-proxy-count N, --proxy-header H, --proxy-hops N   the deployment's proxy settings and the real hop count
  --pca-dir DIR          the deployed application's directory (its installed @atlasauth/pca is probed)
  --only a,b | --skip a,b   check groups: clock, store, proxy, suites, caveats
  --no-probe             do not send forged forwarding headers to the deployment
  --strict               warnings fail too
  --json                 machine-readable output

Env: PCA_DOCTOR_URL, PCA_DOCTOR_REFERENCE_URL, PCA_DOCTOR_STORE, TRUSTED_PROXY_COUNT, TRUSTED_PROXY_HEADER, PCA_TRUSTED_PROXY_HOPS,
     PCA_ALLOWED_SUITES (comma list), PCA_PQ_PINS (JSON), PCA_ALLOW_UNBOUND_PQ.";

// ---- JavaScript value semantics over decoded JSON ------------------------------------------------------------------------

/// `o?.k`: absent for a non-object or an absent member.
fn g<'a>(o: Option<&'a Value>, k: &str) -> Option<&'a Value> {
    match o {
        Some(Value::Object(m)) => m.get(k),
        _ => None,
    }
}

/// `v ?? default` as an option: absent or null is nullish.
fn nn(v: Option<&Value>) -> Option<&Value> {
    v.filter(|x| !x.is_null())
}

fn f64_of(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64(),
        _ => None,
    }
}

fn is_int(f: f64) -> bool {
    f.is_finite() && f.trunc() == f
}

fn neg_zero(f: f64) -> bool {
    f == 0.0 && f.is_sign_negative()
}

fn jn(f: f64) -> String {
    js_number_string(f)
}

/// A JSON number for a double (an integral value prints as an integer, `-0` stays `-0`).
fn num_value(f: f64) -> Value {
    if f.is_finite() && f.trunc() == f && f.abs() < 9_007_199_254_740_992.0 && !neg_zero(f) {
        Value::from(f as i64)
    } else {
        Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null)
    }
}

/// Own enumerable members in JavaScript order: array-index keys ascending first, then insertion order.
fn js_entries(m: &Map<String, Value>) -> Vec<(&String, &Value)> {
    fn index_key(k: &str) -> Option<u32> {
        let n: u32 = k.parse().ok()?;
        (n != u32::MAX && n.to_string() == k).then_some(n)
    }
    let mut idx: Vec<(u32, &String, &Value)> = m.iter().filter_map(|(k, v)| index_key(k).map(|n| (n, k, v))).collect();
    idx.sort_by_key(|(n, _, _)| *n);
    idx.into_iter().map(|(_, k, v)| (k, v)).chain(m.iter().filter(|(k, _)| index_key(k).is_none())).collect()
}

fn u16len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

fn pad_end(s: &str, n: usize) -> String {
    let l = u16len(s);
    format!("{s}{}", " ".repeat(n.saturating_sub(l)))
}

/// `s.slice(0, n)` (UTF-16 units); a cut inside a surrogate pair yields U+FFFD.
fn u16_cut(s: &str, n: usize) -> String {
    let (mut out, mut used) = (String::new(), 0usize);
    for c in s.chars() {
        let l = c.len_utf16();
        if used + l <= n {
            out.push(c);
            used += l;
        } else {
            if used < n {
                out.push('\u{FFFD}');
            }
            break;
        }
    }
    out
}

/// `Number.prototype.toFixed(digits)`: exact on the double, ties pick the larger integer.
pub fn js_to_fixed(x: f64, digits: u32) -> String {
    if !x.is_finite() || x.abs() >= 1e21 {
        return jn(x);
    }
    let a = x.abs();
    let bits = a.to_bits();
    let (exp, frac) = (((bits >> 52) & 0x7ff) as i32, bits & ((1u64 << 52) - 1));
    let (m, e) = if exp == 0 { (frac, -1074) } else { (frac | (1u64 << 52), exp - 1075) };
    let p = 10u128.pow(digits);
    let n: u128 = if e >= 0 {
        ((m as u128) * p) << (e as u32)
    } else if -e > 120 {
        0
    } else {
        let denom = 1u128 << (-e) as u32;
        ((m as u128) * p + denom / 2) / denom
    };
    let body = if digits == 0 { n.to_string() } else { format!("{}.{:0w$}", n / p, n % p, w = digits as usize) };
    if x < 0.0 {
        format!("-{body}")
    } else {
        body
    }
}

// ---- results -------------------------------------------------------------------------------------------------------------

fn res(id: &str, status: &str, detail: impl Into<String>, remediation: Option<&str>, observed: Option<Value>) -> Value {
    let mut m = Map::new();
    m.insert("id".into(), json!(id));
    m.insert("status".into(), json!(status));
    m.insert("detail".into(), Value::String(detail.into()));
    if let Some(r) = remediation {
        m.insert("remediation".into(), json!(r));
    }
    if let Some(o) = observed {
        m.insert("observed".into(), o);
    }
    Value::Object(m)
}

// ---- scrub ---------------------------------------------------------------------------------------------------------------

// the JavaScript `\s` class, for use inside a bracket class
const WS: &str = r"\t\n\x0b\x0c\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}";

fn scrub_patterns() -> &'static Vec<(Regex, &'static str)> {
    static P: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    P.get_or_init(|| {
        let mk = |s: String| Regex::new(&s).expect("scrub pattern");
        vec![
            (mk(r"(?-u:\b)eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*".to_string()), "[redacted]"),
            (mk(format!(r#"(?-u:\b)((?i-u:authorization)["']?[{WS}]*[:=][{WS}]*)[^\n"']*"#)), "${1}[redacted]"),
            (mk(format!(r"(?-u:\b)((?i-u:Bearer|Basic|Token))[{WS}]+[A-Za-z0-9_.~+/=-]{{6,}}")), "${1} [redacted]"),
            (mk(format!(r"((?i-u:[a-z][a-z0-9+.-]*)://)[^{WS}/@]*:[^{WS}/@]*@")), "${1}[redacted]@"),
            (
                mk(format!(
                    r#"(?-u:\b)((?i-u:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|auth|sslpassword)["']?[{WS}]*[:=][{WS}]*)("[^"]*"|'[^']*'|[^{WS}"'&,;]+)"#
                )),
                "${1}[redacted]",
            ),
            (mk(r"[A-Za-z0-9_-]{40,}".to_string()), "[redacted]"),
        ]
    })
}

/// Remove credentials from text the doctor prints: URL userinfo, `token=` / `password=` pairs, bearer credentials, JWTs and long
/// token runs; cut to 600 UTF-16 units. A non-string is first converted as `String(x)`.
pub fn scrub_text(text: &Value) -> String {
    match text {
        Value::String(s) => scrub_str(s),
        v => scrub_str(&js_str(v)),
    }
}

pub fn scrub_str(text: &str) -> String {
    let mut t = text.to_string();
    for (rx, rep) in scrub_patterns() {
        t = rx.replace_all(&t, *rep).into_owned();
    }
    if u16len(&t) > 600 {
        format!("{}...", u16_cut(&t, 600))
    } else {
        t
    }
}

/// Scrub every string inside a JSON-like value (nesting deeper than 8 is left as it is).
pub fn scrub_deep(v: &Value) -> Value {
    fn go(v: &Value, depth: usize) -> Value {
        match v {
            Value::String(s) => Value::String(scrub_str(s)),
            _ if depth > 8 => v.clone(),
            Value::Array(a) => Value::Array(a.iter().map(|x| go(x, depth + 1)).collect()),
            Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), go(x, depth + 1))).collect()),
            _ => v.clone(),
        }
    }
    go(v, 0)
}

// ---- fetch and clock -----------------------------------------------------------------------------------------------------

/// One outgoing request: `HEAD` for a clock reading, `GET` for a probe; redirects are never followed.
#[derive(Debug, Clone, Default)]
pub struct FetchInit {
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub timeout_ms: f64,
}

/// The response headers the checks read (`date`, `ratelimit-remaining`).
#[derive(Debug, Clone, Default)]
pub struct FetchResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

impl FetchResponse {
    /// `headers.get(name)`: case-insensitive, the first value.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// A blocking request; `Err` is the transport failure's message.
pub type FetchFn<'a> = &'a dyn Fn(&str, &FetchInit) -> Result<FetchResponse, String>;
/// The clock, epoch milliseconds.
pub type NowFn<'a> = &'a dyn Fn() -> f64;

fn wall_ms() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_millis() as f64)
}

fn os_rand() -> f64 {
    let mut b = [0u8; 4];
    if getrandom::getrandom(&mut b).is_err() {
        b = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos())).to_le_bytes();
    }
    f64::from(u32::from_le_bytes(b)) / 4_294_967_296.0
}

const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
const WSP: &str = r"[ \t\n\x0b\x0c\r]";

fn rfc_date_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(&format!(
            r"(?i-u)^(?:[a-z]+,?{WSP}+)?([0-9]{{1,2}}){WSP}+([a-z]{{3}})[a-z]*{WSP}+([0-9]{{4}}){WSP}+([0-9]{{1,2}}):([0-9]{{2}})(?::([0-9]{{2}}))?{WSP}*(GMT|UTC|UT|Z|[+-][0-9]{{4}})$"
        ))
        .expect("rfc date pattern")
    })
}

fn iso_date_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})(?:T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]{1,9}))?)?(Z|[+-][0-9]{2}:[0-9]{2}))?$")
            .expect("iso date pattern")
    })
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

#[allow(clippy::too_many_arguments)]
fn epoch(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64, ms: i64, off_min: i64) -> f64 {
    let days = days_from_civil(y, mo, 1) + d - 1;
    let t = (((days * 24 + h) * 60 + mi) * 60 + s) * 1000 + ms - off_min * 60_000;
    if t.abs() > 8_640_000_000_000_000 {
        f64::NAN
    } else {
        t as f64
    }
}

/// `Date.parse`: NaN when unparseable. Covers the HTTP date (RFC 1123 with a zone; a weekday word is ignored, as the reference engine
/// does) and ISO 8601 with a zone or date only (UTC). shortcut: a date without a zone is local time in the reference engine
/// (host-dependent) and is NaN here; other legacy spellings are NaN.
pub fn parse_date(s: &str) -> f64 {
    let t = s.trim_matches(is_js_ws);
    let num = |m: &regex::Captures, i: usize| -> i64 { m.get(i).map_or(0, |x| x.as_str().parse::<i64>().unwrap_or(0)) };
    if let Some(m) = rfc_date_re().captures(t) {
        let mn = m[2].to_ascii_lowercase();
        let Some(mon) = MONTHS.iter().position(|x| *x == mn) else { return f64::NAN };
        let (h, mi, sec, day) = (num(&m, 4), num(&m, 5), num(&m, 6), num(&m, 1));
        if h > 24 || mi > 59 || sec > 59 || (h == 24 && (mi != 0 || sec != 0)) || !(1..=31).contains(&day) {
            return f64::NAN;
        }
        let z = m[7].to_ascii_uppercase();
        let off = if z.starts_with('+') || z.starts_with('-') {
            let sign = if z.starts_with('-') { -1 } else { 1 };
            sign * (z[1..3].parse::<i64>().unwrap_or(0) * 60 + z[3..5].parse::<i64>().unwrap_or(0))
        } else {
            0
        };
        return epoch(num(&m, 3), mon as i64 + 1, day, h, mi, sec, 0, off);
    }
    if let Some(m) = iso_date_re().captures(t) {
        let (y, mo, d) = (num(&m, 1), num(&m, 2), num(&m, 3));
        if !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo) {
            return f64::NAN;
        }
        let (h, mi, sec) = (num(&m, 4), num(&m, 5), num(&m, 6));
        let frac = m.get(7).map(|x| x.as_str());
        if h > 24 || mi > 59 || sec > 59 || (h == 24 && (mi != 0 || sec != 0 || frac.is_some())) {
            return f64::NAN;
        }
        let ms = frac.map_or(0, |f| format!("{f}00")[..3].parse::<i64>().unwrap_or(0));
        let off = match m.get(8).map(|x| x.as_str()) {
            Some(z) if z != "Z" => {
                let sign = if z.starts_with('-') { -1 } else { 1 };
                sign * (z[1..3].parse::<i64>().unwrap_or(0) * 60 + z[4..6].parse::<i64>().unwrap_or(0))
            }
            _ => 0,
        };
        return epoch(y, mo, d, h, mi, sec, ms, off);
    }
    f64::NAN
}

/// One reading of a server's clock: remote minus local (ms) and its uncertainty.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DateReading {
    pub offset_ms: f64,
    pub uncertainty_ms: f64,
}

/// One reading of a server's clock from its `Date` header (one-second resolution: +-0.5 s plus half the round trip). `Err` carries
/// the reason nothing could be read.
pub fn read_date(url: &str, fetch: FetchFn, now: NowFn, timeout_ms: f64) -> Result<DateReading, String> {
    let t0 = now();
    let res = fetch(url, &FetchInit { method: "HEAD".into(), headers: vec![], timeout_ms }).map_err(|e| format!("request failed: {e}"))?;
    let t1 = now();
    let date = res.header("date");
    let d = date.map_or(f64::NAN, parse_date);
    if !d.is_finite() {
        return Err(match date {
            None => "no Date header".to_string(),
            Some(s) => format!("unparseable Date header '{s}'"),
        });
    }
    Ok(DateReading { offset_ms: d + 500.0 - (t0 + t1) / 2.0, uncertainty_ms: 500.0 + (t1 - t0) / 2.0 })
}

fn signed_s(ms: f64) -> String {
    format!("{}{} s", if ms >= 0.0 { "+" } else { "-" }, js_to_fixed(ms.abs() / 1000.0, 1))
}

/// Clock skew of the deployment against a reference (the `Date` headers of both, or this machine's clock). FAIL only when the skew is
/// beyond the limit even at the favourable end of the uncertainty interval; WARN when it is above the warning fraction or could be
/// beyond the limit.
pub fn check_clock(cfg: &Value, fetch: FetchFn, now: NowFn) -> Value {
    let url = g(Some(cfg), "url");
    if !truthy(url) {
        return res("clock", "skip", "no deployment URL given (--url)", None, None);
    }
    let url = js_str(url.unwrap_or(&Value::Null));
    let cc = g(Some(cfg), "clock");
    let max = nn(g(cc, "maxSkewMs")).map_or(MAX_SKEW_MS as f64, |v| js_to_number(Some(v)));
    let warn_at = max * nn(g(cc, "warnFraction")).map_or(0.25, |v| js_to_number(Some(v)));
    let timeout = nn(g(cc, "timeoutMs")).map_or(10_000.0, |v| js_to_number(Some(v)));
    let dep = match read_date(&url, fetch, now, timeout) {
        Ok(d) => d,
        Err(e) => {
            return res(
                "clock",
                "warn",
                format!("cannot observe the deployment's clock at {url}: {e}"),
                Some(&format!("Make the deployment answer with a Date header (RFC 9110 requires one from an origin with a clock), or check its clock on the host. {CLOCK_REMEDIATION}")),
                None,
            )
        }
    };
    let ref_url = nn(g(cc, "referenceUrl")).map_or_else(|| DEFAULT_REFERENCE_URL.to_string(), js_str);
    let mut rf = DateReading { offset_ms: 0.0, uncertainty_ms: 0.0 };
    let mut ref_name = "this machine's clock".to_string();
    let mut ref_note = String::new();
    if ref_url != "local" {
        match read_date(&ref_url, fetch, now, timeout) {
            Err(e) => ref_note = format!(" (reference {ref_url} unusable: {e}; compared with this machine's clock instead)"),
            Ok(r) => {
                rf = r;
                ref_name = ref_url.clone();
            }
        }
    }
    let skew = dep.offset_ms - rf.offset_ms;
    let unc = dep.uncertainty_ms + rf.uncertainty_ms;
    let lower = skew.abs() - unc;
    let upper = skew.abs() + unc;
    // a skew, uncertainty or threshold that is not a number can show nothing: fail, never pass
    let measurable = lower.is_finite() && upper.is_finite() && !max.is_nan() && !warn_at.is_nan();
    let status = if !measurable || lower > max {
        "fail"
    } else if skew.abs() > warn_at || upper > max {
        "warn"
    } else {
        "pass"
    };
    let detail = format!(
        "deployment clock {} relative to {ref_name}{ref_note} (+-{} s: Date has 1 s resolution, plus round trips); fail beyond {} s, warn above {} s. The Date header is written by whatever answers the request (a CDN or proxy may set it).",
        signed_s(skew),
        js_to_fixed(unc / 1000.0, 1),
        jn(max / 1000.0),
        jn(warn_at / 1000.0)
    );
    let observed = json!({ "skewMs": num_value(skew), "uncertaintyMs": num_value(unc), "maxSkewMs": num_value(max), "warnAtMs": num_value(warn_at), "reference": ref_name });
    res("clock", status, detail, if status == "pass" { None } else { Some(CLOCK_REMEDIATION) }, Some(observed))
}

// ---- proxy ---------------------------------------------------------------------------------------------------------------

/// The stated TRUSTED_PROXY_COUNT / TRUSTED_PROXY_HEADER against the stated number of appending proxies.
pub fn check_proxy_config(cfg: &Value) -> Value {
    let p = g(Some(cfg), "proxy");
    let Some(n) = g(p, "trustedProxyCount") else {
        return res("proxy.config", "skip", "TRUSTED_PROXY_COUNT not given (config proxy.trustedProxyCount or env TRUSTED_PROXY_COUNT)", None, None);
    };
    let header = nn(g(p, "header")).cloned().unwrap_or_else(|| json!("x-forwarded-for"));
    let (hs, ns) = (js_str(&header), js_str(n));
    let fail = |detail: String| res("proxy.config", "fail", detail, Some(PROXY_REMEDIATION), None);
    let nf = match f64_of(Some(n)) {
        Some(f) if is_int(f) && f >= 0.0 && !neg_zero(f) && f <= 16.0 => f,
        _ => return fail(format!("TRUSTED_PROXY_COUNT={ns} is not an integer in 0..16")),
    };
    if header.as_str() == Some("x-real-ip") && nf == 0.0 {
        return fail("TRUSTED_PROXY_HEADER=x-real-ip needs TRUSTED_PROXY_COUNT >= 1 (with 0 every forwarding header is ignored)".to_string());
    }
    let Some(hops) = g(p, "hops") else {
        return res(
            "proxy.config",
            if nf == 0.0 { "pass" } else { "warn" },
            format!("TRUSTED_PROXY_COUNT={ns} ({hs}); the real number of appending proxies was not stated (proxy.hops / PCA_TRUSTED_PROXY_HOPS), so it cannot be compared"),
            if nf == 0.0 { None } else { Some(PROXY_REMEDIATION) },
            None,
        );
    };
    let (hp, h) = (js_str(hops), js_to_number(Some(hops)));
    if nf > h {
        return fail(format!("TRUSTED_PROXY_COUNT={ns} is larger than the {hp} proxies in front of the API: a client chooses its own address (and rate-limit bucket) with extra {hs} entries"));
    }
    if nf < h {
        return res(
            "proxy.config",
            "warn",
            format!(
                "TRUSTED_PROXY_COUNT={ns} is smaller than the {hp} proxies in front of the API: clients are keyed by a proxy's address and share its bucket"
            ),
            Some(PROXY_REMEDIATION),
            None,
        );
    }
    res("proxy.config", "pass", format!("TRUSTED_PROXY_COUNT={ns} ({hs}) matches the stated {hp} appending proxies"), None, None)
}

/// A random documentation address (RFC 5737 TEST-NET-2 / -3): never a real client. `rand` yields doubles in [0, 1).
pub fn test_net_ip(rand: &mut dyn FnMut() -> f64) -> String {
    let net = if rand() < 0.5 { "198.51.100" } else { "203.0.113" };
    format!("{net}.{}", 1 + (rand() * 254.0).floor() as i64)
}

/// Forged values for all three forwarding headers at once (the server trusts at most one of them).
pub fn forged_headers(rand: &mut dyn FnMut() -> f64) -> Vec<(String, String)> {
    let chain: Vec<String> = (0..17).map(|_| test_net_ip(rand)).collect();
    let forwarded = chain.iter().map(|ip| format!("for={ip}")).collect::<Vec<_>>().join(", ");
    vec![("x-forwarded-for".to_string(), chain.join(", ")), ("forwarded".to_string(), forwarded), ("x-real-ip".to_string(), test_net_ip(rand))]
}

/// The seeded PRNG of the reference's deterministic tests (mulberry32); a doctor run itself draws from the OS.
pub fn mulberry32(seed: u32) -> impl FnMut() -> f64 {
    let mut a = seed;
    move || {
        a = a.wrapping_add(0x6d2b_79f5);
        let mut t = a;
        t = (t ^ (t >> 15)).wrapping_mul(t | 1);
        t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61));
        f64::from(t ^ (t >> 14)) / 4_294_967_296.0
    }
}

fn remaining(fetch: FetchFn, url: &str, headers: Vec<(String, String)>, timeout_ms: f64) -> Result<Option<f64>, String> {
    let r = fetch(url, &FetchInit { method: "GET".into(), headers, timeout_ms })?;
    let n = r.header("ratelimit-remaining").map_or(f64::NAN, js_str_to_number);
    Ok(n.is_finite().then_some(n))
}

fn probe_seq(fetch: FetchFn, url: &str, t: f64, rand: &mut dyn FnMut() -> f64) -> Result<[Option<f64>; 4], String> {
    let a = remaining(fetch, url, vec![], t)?;
    let b = remaining(fetch, url, vec![], t)?;
    let f = remaining(fetch, url, forged_headers(rand), t)?;
    let c = remaining(fetch, url, vec![], t)?;
    Ok([a, b, f, c])
}

/// Forged forwarding headers sent to a public rate-limited path, watching `RateLimit-Remaining`: a forged request that lands in a
/// FRESH bucket while plain requests keep draining one bucket means client-written entries are trusted. A count that is too LOW is
/// not observable from one vantage point. `Err` is a thrown error (an unusable URL).
pub fn check_proxy_probe(cfg: &Value, fetch: FetchFn, rand: &mut dyn FnMut() -> f64) -> Result<Value, String> {
    let id = "proxy.probe";
    let url = g(Some(cfg), "url");
    if !truthy(url) {
        return Ok(res(id, "skip", "no deployment URL given (--url)", None, None));
    }
    let proxy = g(Some(cfg), "proxy");
    if g(proxy, "probe") == Some(&Value::Bool(false)) {
        return Ok(res(id, "skip", "disabled (--no-probe)", None, None));
    }
    let path = nn(g(proxy, "probePath")).map_or_else(|| "/v1/pca/suites".to_string(), js_str);
    let base = url::Url::parse(&js_str(url.unwrap_or(&Value::Null))).map_err(|_| "Invalid URL".to_string())?;
    let target = base.join(&path).map_err(|_| "Invalid URL".to_string())?.to_string();
    let t = nn(g(g(Some(cfg), "clock"), "timeoutMs")).map_or(10_000.0, |v| js_to_number(Some(v)));
    let seq = match probe_seq(fetch, &target, t, rand) {
        Ok(s) => s,
        Err(e) => {
            return Ok(res(
                id,
                "warn",
                format!("probe request to {target} failed: {e}"),
                Some("Set proxy.probePath to a public, rate-limited path of the deployment, or run with --no-probe."),
                None,
            ))
        }
    };
    let observed = json!({ "url": target, "remaining": seq.iter().map(|x| x.map_or(Value::Null, num_value)).collect::<Vec<_>>() });
    let [Some(a), Some(b), Some(f), Some(c)] = seq else {
        return Ok(res(
            id,
            "skip",
            format!("not observable remotely: {target} does not return a RateLimit-Remaining header on every response"),
            None,
            Some(observed),
        ));
    };
    let (sa, sb, sf, sc) = (jn(a), jn(b), jn(f), jn(c));
    if !(b < a && c < b) {
        return Ok(res(
            id,
            "warn",
            format!("inconclusive: the plain requests' bucket did not drain monotonically ({sa}, {sb}, then {sc}): a window rollover, a shared bucket or concurrent traffic. Re-run."),
            None,
            Some(observed),
        ));
    }
    if f > b {
        return Ok(res(
            id,
            "fail",
            format!("a request with FORGED forwarding headers got a fresh rate-limit bucket (remaining {sf}, while the plain requests' bucket was at {sb}): the deployment trusts client-written forwarding entries"),
            Some(PROXY_REMEDIATION),
            Some(observed),
        ));
    }
    Ok(res(
        id,
        "pass",
        format!("forged X-Forwarded-For / Forwarded / X-Real-IP did not move the client to another bucket (remaining {sa}, {sb}, forged {sf}, {sc}). A count that is too LOW is not observable from one client."),
        None,
        Some(observed),
    ))
}

// ---- suites --------------------------------------------------------------------------------------------------------------

fn b64u_ok(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// allowedSuites against the closed suite registry (the library's registered suite names, in registry order).
pub fn check_allowed_suites(cfg: &Value) -> Value {
    let id = "suites.allowed";
    let v = g(Some(cfg), "verifier");
    if !truthy(v) {
        return res(id, "skip", "no verifier configuration given (config verifier.*)", None, None);
    }
    let known = SIG_SUITE_KEYS.join(", ");
    let Some(list) = g(v, "allowedSuites") else {
        return res(
            id,
            "warn",
            format!("allowedSuites is unset: every registered suite is accepted ({}: {known})", SIG_SUITE_KEYS.len()),
            Some(SUITES_REMEDIATION),
            None,
        );
    };
    let items = match list {
        Value::Array(a) if !a.is_empty() => a,
        _ => return res(id, "fail", "allowedSuites is empty or not a list: no PCActn can verify", Some(SUITES_REMEDIATION), None),
    };
    let unknown: Vec<String> = items.iter().filter(|s| !s.as_str().is_some_and(|x| SIG_SUITE_KEYS.contains(&x))).map(js_str).collect();
    if !unknown.is_empty() {
        return res(
            id,
            "fail",
            format!("allowedSuites names suite(s) outside the registry: {} (known: {known})", unknown.join(", ")),
            Some(SUITES_REMEDIATION),
            None,
        );
    }
    res(id, "pass", format!("allowedSuites = {}", items.iter().map(js_str).collect::<Vec<_>>().join(", ")), None, None)
}

/// allowUnboundPq / pqPins / trustedRoot sanity. `Err` is a thrown TypeError (allowedSuites is not a list).
pub fn check_pq_binding(cfg: &Value) -> Result<Value, String> {
    let id = "suites.pq-binding";
    let v = g(Some(cfg), "verifier");
    if !truthy(v) {
        return Ok(res(id, "skip", "no verifier configuration given (config verifier.*)", None, None));
    }
    let fail = |detail: String| Ok(res(id, "fail", detail, Some(PQ_REMEDIATION), None));
    if g(v, "allowUnboundPq") == Some(&Value::Bool(true)) {
        return fail("allowUnboundPq is set: PQ keys are read from the artifact, so a hybrid gives no protection against an Ed25519 forger and a pure-PQ hop can be signed by any key".to_string());
    }
    let pins = g(v, "pqPins");
    let mut pin_count = 0usize;
    if let Some(p) = pins {
        let Value::Object(m) = p else {
            return fail("pqPins is not an object of { ed25519 identity: pq public key }".to_string());
        };
        pin_count = m.len();
        let bad: Vec<&str> = js_entries(m)
            .into_iter()
            .filter(|(k, val)| !(k.len() == 43 && b64u_ok(k)) || !val.as_str().is_some_and(b64u_ok))
            .map(|(k, _)| k.as_str())
            .collect();
        if !bad.is_empty() {
            return fail(format!(
                "pqPins has malformed entries (key must be a 43-char base64url Ed25519 identity, value a base64url PQ key): {}",
                bad.join(", ")
            ));
        }
    }
    let pq: Vec<String> = match nn(g(v, "allowedSuites")) {
        None => SIG_SUITE_KEYS.iter().filter(|s| **s != "ed25519").map(|s| s.to_string()).collect(),
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).filter(|s| *s != "ed25519" && SIG_SUITE_KEYS.contains(s)).map(String::from).collect(),
        Some(_) => return Err("(intermediate value).filter is not a function".to_string()),
    };
    if pq.is_empty() {
        return Ok(res(id, "pass", "no post-quantum suite is accepted (Ed25519 only: no PQ binding needed, and no PQ protection)", None, None));
    }
    let pinned = pin_count > 0;
    if !pinned && g(v, "trustedRoot") != Some(&Value::Bool(true)) {
        return Ok(res(
            id,
            "warn",
            format!("post-quantum suite(s) accepted ({}) with neither pqPins nor a stored trustedRoot: a non-Ed25519 root is refused (fail closed) or its PQ key is not pinned", pq.join(", ")),
            Some(PQ_REMEDIATION),
            None,
        ));
    }
    Ok(res(
        id,
        "pass",
        format!(
            "PQ suites ({}) are bound: {}; allowUnboundPq off",
            pq.join(", "),
            if pinned { format!("{pin_count} pin(s)") } else { "stored trustedRoot".to_string() }
        ),
        None,
        None,
    ))
}

// ---- root caveats and enforcement ----------------------------------------------------------------------------------------

/// The library under test: its version, where it was found and how to probe it. `probe(root_caveat, amount_usd)` decides a payment
/// of that amount under a root grant carrying `root_caveat` and returns the raw decision `{releaseGuardianShare, reasons}`.
pub struct LoadedPca {
    pub version: String,
    pub path: String,
    pub probe: Box<dyn Fn(&Value, f64) -> Result<Value, String>>,
}

/// Loads the library to probe, from the application directory when given.
pub type LoadPcaFn<'a> = &'a dyn Fn(Option<&str>) -> Result<LoadedPca, String>;

/// The library compiled into this program (a `dir` is refused: another installation cannot be loaded into a running Rust program).
pub fn load_pca(dir: Option<&str>) -> Result<LoadedPca, String> {
    if let Some(d) = dir {
        return Err(format!("a separate installation in {d} cannot be loaded into this program (probe the library compiled into it by omitting pcaDir)"));
    }
    Ok(LoadedPca {
        version: env!("CARGO_PKG_VERSION").to_string(),
        path: "atlas-pca (compiled into this program)".to_string(),
        probe: Box::new(|cv, amount| {
            let at = wall_ms();
            let ctx = json!({ "now": num_value(at), "action": { "verb": "pay", "resource": "invoice:42", "reversibility_class": "reversible", "params": { "amount": num_value(amount), "currency": "usd" } } });
            let (ok, failed) = evaluate_caveats(&json!([cv]), &ctx);
            Ok(json!({ "releaseGuardianShare": ok, "reasons": failed }))
        }),
    })
}

/// -1 / 0 / 1 for a < b / = / > over major.minor.patch (pre-release tags ignored); NaN parts compare as -1.
pub fn compare_version(a: &str, b: &str) -> i32 {
    let parts = |s: &str| -> Vec<f64> { s.split(['.', '+', '-']).take(3).map(js_str_to_number).collect() };
    let (pa, pb) = (parts(a), parts(b));
    for i in 0..3 {
        let at = |p: &Vec<f64>| p.get(i).copied().filter(|x| x.is_finite()).unwrap_or(-1.0);
        let (x, y) = (at(&pa), at(&pb));
        if x != y {
            return if x < y { -1 } else { 1 };
        }
    }
    0
}

/// `{allowed, reasons}` of a raw decision: allowed only on `releaseGuardianShare === true`, reasons as strings.
fn decision(raw: &Value) -> Value {
    let reasons: Vec<Value> = match raw.get("reasons") {
        Some(Value::Array(a)) => a.iter().map(|r| Value::String(js_str(r))).collect(),
        _ => vec![],
    };
    json!({ "allowed": raw.get("releaseGuardianShare") == Some(&Value::Bool(true)), "reasons": reasons })
}

/// Root-caveat enforcement (the 0.4.1 security fix): the deployed library must be >= 0.4.1, and a functional probe through THAT
/// library must show a root max_spend of 100 denying 150 and allowing 50, and an unknown root caveat type denying (fail closed).
pub fn check_root_caveats(cfg: &Value, load: Option<LoadPcaFn>) -> Value {
    let id = "caveats.root";
    let d = g(g(Some(cfg), "verifier"), "pcaDir");
    let dir = if truthy(d) { d.map(js_str) } else { None };
    let loaded = match load {
        Some(f) => f(dir.as_deref()),
        None => load_pca(dir.as_deref()),
    };
    let pca = match loaded {
        Ok(p) => p,
        Err(e) => {
            let from = dir.as_ref().map_or(String::new(), |d| format!(" from {d}"));
            return res(id, "fail", format!("cannot load @atlasauth/pca{from}: {e}"), Some(CAVEAT_REMEDIATION), None);
        }
    };
    let where_ = format!("@atlasauth/pca {} at {}", pca.version, pca.path);
    if compare_version(&pca.version, ROOT_CAVEAT_MIN_VERSION) < 0 {
        return res(
            id,
            "fail",
            format!("{where_}: root caveats outside the envelope are NOT enforced before {ROOT_CAVEAT_MIN_VERSION} (legacy behaviour)"),
            Some(CAVEAT_REMEDIATION),
            None,
        );
    }
    let probe = |cv: Value, amount: f64| (pca.probe)(&cv, amount).map(|raw| decision(&raw));
    let probed = (|| -> Result<(Value, Value, Value), String> {
        let over = probe(json!({ "type": "max_spend", "usd": 100 }), 150.0)?;
        let under = probe(json!({ "type": "max_spend", "usd": 100 }), 50.0)?;
        let unknown = probe(json!({ "type": "pca-doctor-unknown-caveat" }), 50.0)?;
        Ok((over, under, unknown))
    })();
    let (over, under, unknown) = match probed {
        Ok(t) => t,
        Err(e) => return res(id, "fail", format!("{where_}: the enforcement probe could not run: {e}"), Some(CAVEAT_REMEDIATION), None),
    };
    let allowed = |d: &Value| d["allowed"] == Value::Bool(true);
    let observed = json!({ "version": pca.version, "over": over, "under": under, "unknown": unknown });
    if allowed(&over) || allowed(&unknown) {
        let what = if allowed(&over) { "max_spend 100 allowed a 150 payment" } else { "an unknown root caveat type was allowed" };
        return res(id, "fail", format!("{where_}: a root caveat was NOT enforced ({what})"), Some(CAVEAT_REMEDIATION), Some(observed));
    }
    if !allowed(&under) {
        let reasons = under["reasons"].as_array().map(|a| a.iter().map(js_str).collect::<Vec<_>>().join("; ")).unwrap_or_default();
        return res(
            id,
            "warn",
            format!("{where_}: inconclusive: the control payment within the root max_spend was denied too ({reasons})"),
            None,
            Some(observed),
        );
    }
    res(id, "pass", format!("{where_}: root caveats enforced (max_spend 100 denies 150, allows 50; an unknown root caveat type denies)"), None, Some(observed))
}

/// requirePCA must not run with insecureAllowUnenforced, and a custom `require` list should keep the defaults. `Err` is a thrown
/// TypeError (`require` is not a list or string).
pub fn check_enforcement(cfg: &Value) -> Result<Value, String> {
    let id = "verifier.enforcement";
    let v = g(Some(cfg), "verifier");
    if !truthy(v) {
        return Ok(res(id, "skip", "no verifier configuration given (config verifier.*)", None, None));
    }
    if g(v, "insecureAllowUnenforced") == Some(&Value::Bool(true)) {
        return Ok(res(
            id,
            "fail",
            "requirePCA runs with insecureAllowUnenforced: required checks that are not enforced do not deny",
            Some("Remove insecureAllowUnenforced and supply the stores the required checks need (counter / revocation / budget)."),
            None,
        ));
    }
    let req = g(v, "require");
    if let Some(r) = req {
        let missing: Vec<&str> = match r {
            Value::Array(a) => DEFAULT_REQUIRED.iter().copied().filter(|c| !a.iter().any(|x| x.as_str() == Some(*c))).collect(),
            Value::String(s) => DEFAULT_REQUIRED.iter().copied().filter(|c| !s.contains(*c)).collect(),
            Value::Null => return Err("Cannot read properties of null (reading 'includes')".to_string()),
            _ => return Err("v.require.includes is not a function".to_string()),
        };
        if !missing.is_empty() {
            return Ok(res(
                id,
                "warn",
                format!("the require list drops default check(s): {}", missing.join(", ")),
                Some(&format!("Keep every default required check ({}) and add to it.", DEFAULT_REQUIRED.join(", "))),
                None,
            ));
        }
    }
    if truthy(req) {
        let Some(Value::Array(a)) = req else { return Err("v.require.join is not a function".to_string()) };
        let joined = a.iter().map(|x| if x.is_null() { String::new() } else { js_str(x) }).collect::<Vec<_>>().join(", ");
        return Ok(res(id, "pass", format!("require = {joined}"), None, None));
    }
    Ok(res(id, "pass", "default required checks; insecureAllowUnenforced off", None, None))
}

// ---- configuration and results -------------------------------------------------------------------------------------------

/// Numeric settings that would make a check meaningless (NaN, negative, zero where a duration is needed) are configuration errors.
pub fn config_problems(cfg: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let pos = |out: &mut Vec<String>, name: &str, v: Option<&Value>, integer: bool| {
        let Some(v) = v else { return };
        let ok = f64_of(Some(v)).is_some_and(|f| f.is_finite() && f > 0.0 && (!integer || is_int(f)));
        if !ok {
            out.push(format!("{name} must be a positive {}", if integer { "integer" } else { "number" }));
        }
    };
    let nonneg = |out: &mut Vec<String>, name: &str, v: Option<&Value>| {
        let Some(v) = v else { return };
        if !f64_of(Some(v)).is_some_and(|f| is_int(f) && f >= 0.0 && !neg_zero(f)) {
            out.push(format!("{name} must be a non-negative integer"));
        }
    };
    let (clock, store, proxy) = (g(Some(cfg), "clock"), g(Some(cfg), "store"), g(Some(cfg), "proxy"));
    pos(&mut out, "clock.maxSkewMs", g(clock, "maxSkewMs"), false);
    pos(&mut out, "clock.timeoutMs", g(clock, "timeoutMs"), false);
    if let Some(wf) = g(clock, "warnFraction") {
        if !f64_of(Some(wf)).is_some_and(|f| f > 0.0 && f <= 1.0) {
            out.push("clock.warnFraction must be a number in (0, 1]".to_string());
        }
    }
    pos(&mut out, "store.concurrency", g(store, "concurrency"), true);
    pos(&mut out, "store.rounds", g(store, "rounds"), true);
    nonneg(&mut out, "proxy.trustedProxyCount", g(proxy, "trustedProxyCount"));
    nonneg(&mut out, "proxy.hops", g(proxy, "hops"));
    if let Some(u) = g(Some(cfg), "url") {
        match url::Url::parse(&js_str(u)) {
            Ok(p) if p.scheme() == "https" || p.scheme() == "http" => {}
            Ok(_) => out.push("url must be an http(s) URL".to_string()),
            Err(_) => out.push("url is not a valid URL".to_string()),
        }
    }
    out
}

/// What a run needs from its host: the HTTP client, the clock, the library loader and the replay-store check. Every member is
/// optional; an absent one makes the dependent check report "cannot observe" or fail, never pass.
#[derive(Default)]
pub struct DoctorDeps<'a> {
    pub fetch: Option<FetchFn<'a>>,
    pub now: Option<NowFn<'a>>,
    pub load_pca: Option<LoadPcaFn<'a>>,
    /// Runs the replay-store atomicity / durability checks for a configuration that names an adapter.
    pub check_store: Option<&'a dyn Fn(&Value) -> Result<Vec<Value>, String>>,
}

fn guarded(out: &mut Vec<Value>, id: &str, run: impl FnOnce() -> Result<Vec<Value>, String>) {
    match run() {
        Ok(r) => out.extend(r),
        Err(e) => out.push(res(
            id,
            "fail",
            format!("{id} could not run: {}", scrub_str(&e)),
            Some("Fix the configuration or the dependency named above and run the doctor again."),
            None,
        )),
    }
}

fn check_store_default(cfg: &Value, deps: &DoctorDeps) -> Result<Vec<Value>, String> {
    let spec = g(g(Some(cfg), "store"), "adapter");
    if !truthy(spec) {
        let detail = "no store adapter given (--store ./adapter.mjs); the replay store cannot be exercised remotely";
        return Ok(vec![res("store.atomicity", "skip", detail, None, None), res("store.durability", "skip", detail, None, None)]);
    }
    match deps.check_store {
        Some(f) => f(cfg),
        None => Ok(vec![res(
            "store.atomicity",
            "fail",
            format!("cannot load the store adapter {}: no store adapter loader was supplied to the doctor", js_str(spec.unwrap_or(&Value::Null))),
            Some("Point --store at a module exporting a store adapter (see the store conformance kit guide)."),
            None,
        )]),
    }
}

/// Run the selected check groups (all when `only` is None) and scrub everything they report. An invalid configuration is reported as
/// `config` failures and nothing else runs. A group that raises is a failed check, not a crashed run and not a skipped one.
pub fn run_doctor(cfg: &Value, only: Option<&[&str]>, deps: &DoctorDeps) -> Vec<Value> {
    let problems = config_problems(cfg);
    if !problems.is_empty() {
        return problems
            .iter()
            .map(|p| res("config", "fail", scrub_str(&format!("invalid configuration: {p}")), Some("Correct the setting; no check was run."), None))
            .collect();
    }
    let sel: &[&str] = only.unwrap_or(&CHECK_GROUPS);
    let no_fetch = |_: &str, _: &FetchInit| -> Result<FetchResponse, String> { Err("no HTTP client was supplied to the doctor".to_string()) };
    let fetch: FetchFn = deps.fetch.unwrap_or(&no_fetch);
    let wall = wall_ms;
    let now: NowFn = deps.now.unwrap_or(&wall);
    let mut out: Vec<Value> = Vec::new();
    if sel.contains(&"clock") {
        guarded(&mut out, "clock", || Ok(vec![check_clock(cfg, fetch, now)]));
    }
    if sel.contains(&"store") {
        guarded(&mut out, "store", || check_store_default(cfg, deps));
    }
    if sel.contains(&"proxy") {
        guarded(&mut out, "proxy.config", || Ok(vec![check_proxy_config(cfg)]));
        guarded(&mut out, "proxy.probe", || check_proxy_probe(cfg, fetch, &mut os_rand).map(|r| vec![r]));
    }
    if sel.contains(&"suites") {
        guarded(&mut out, "suites.allowed", || Ok(vec![check_allowed_suites(cfg)]));
        guarded(&mut out, "suites.pq", || check_pq_binding(cfg).map(|r| vec![r]));
    }
    if sel.contains(&"caveats") {
        guarded(&mut out, "caveats.root", || Ok(vec![check_root_caveats(cfg, deps.load_pca)]));
        guarded(&mut out, "caveats.enforcement", || check_enforcement(cfg).map(|r| vec![r]));
    }
    // nothing the doctor prints may carry a credential from the deployment URL, an adapter option or an error message
    out.iter().map(scrub_deep).collect()
}

fn status_of(r: &Value) -> &str {
    r.get("status").and_then(Value::as_str).unwrap_or("")
}

/// `fail` if any check failed; `warn` if any warned (`fail` under `strict`); else `pass`. A run in which nothing was checked (no
/// results, or every result skipped) is a `fail`: a doctor that looked at nothing must not report a healthy deployment.
pub fn verdict_of(results: &[Value], strict: bool) -> &'static str {
    if !results.iter().any(|r| status_of(r) != "skip") || results.iter().any(|r| status_of(r) == "fail") {
        return "fail";
    }
    if results.iter().any(|r| status_of(r) == "warn") {
        return if strict { "fail" } else { "warn" };
    }
    "pass"
}

pub fn format_results(results: &[Value], target: Option<&str>, strict: bool) -> String {
    let mut lines = vec![format!("pca-doctor{}", target.filter(|t| !t.is_empty()).map_or(String::new(), |t| format!(": {t}")))];
    for r in results {
        let field = |k: &str| r.get(k).map_or_else(|| "undefined".to_string(), js_str);
        lines.push(format!("  {}  {} {}", pad_end(&field("status").to_uppercase(), 4), pad_end(&field("id"), 20), field("detail")));
        if truthy(r.get("remediation")) {
            lines.push(format!("  {}  {} fix: {}", " ".repeat(4), " ".repeat(20), field("remediation")));
        }
    }
    let n = |s: &str| results.iter().filter(|r| status_of(r) == s).count();
    if !results.iter().any(|r| status_of(r) != "skip") {
        lines.push("  FAIL  nothing checked        no check produced a result: nothing about this deployment was verified".to_string());
    }
    lines.push(format!(
        "Summary: {} pass, {} warn, {} fail, {} skip -> {}",
        n("pass"),
        n("warn"),
        n("fail"),
        n("skip"),
        verdict_of(results, strict).to_uppercase()
    ));
    lines.join("\n")
}

fn env_int(name: &str, v: &str) -> Result<Option<Value>, String> {
    if v.is_empty() {
        return Ok(None);
    }
    let n = js_str_to_number(v);
    if !is_int(n) || n < 0.0 || neg_zero(n) {
        return Err(format!("{name} must be a non-negative integer"));
    }
    Ok(Some(num_value(n)))
}

/// The deployment's own environment variable names (as the API and the guides use them). `env` is an object of strings.
pub fn config_from_env(env: &Value) -> Result<Value, String> {
    let e = |k: &str| env.get(k).and_then(Value::as_str);
    let mut c = Map::new();
    if let Some(u) = e("PCA_DOCTOR_URL").filter(|s| !s.is_empty()) {
        c.insert("url".into(), json!(u));
    }
    if let Some(u) = e("PCA_DOCTOR_REFERENCE_URL").filter(|s| !s.is_empty()) {
        c.insert("clock".into(), json!({ "referenceUrl": u }));
    }
    if let Some(u) = e("PCA_DOCTOR_STORE").filter(|s| !s.is_empty()) {
        c.insert("store".into(), json!({ "adapter": u }));
    }
    let mut proxy = Map::new();
    let mut touched = false;
    if let Some(v) = e("TRUSTED_PROXY_COUNT") {
        touched = true;
        if let Some(n) = env_int("TRUSTED_PROXY_COUNT", v)? {
            proxy.insert("trustedProxyCount".into(), n);
        }
    }
    if let Some(h) = e("TRUSTED_PROXY_HEADER").filter(|s| !s.is_empty()) {
        touched = true;
        let h = h.to_lowercase();
        if !PROXY_HEADERS.contains(&h.as_str()) {
            return Err(format!("TRUSTED_PROXY_HEADER must be one of {}", PROXY_HEADERS.join(", ")));
        }
        proxy.insert("header".into(), json!(h));
    }
    if let Some(v) = e("PCA_TRUSTED_PROXY_HOPS") {
        touched = true;
        if let Some(n) = env_int("PCA_TRUSTED_PROXY_HOPS", v)? {
            proxy.insert("hops".into(), n);
        }
    }
    if touched {
        c.insert("proxy".into(), Value::Object(proxy));
    }
    let mut verifier = Map::new();
    if let Some(s) = e("PCA_ALLOWED_SUITES") {
        let list: Vec<Value> = s.split(',').map(|t| t.trim_matches(is_js_ws)).filter(|t| !t.is_empty()).map(|t| json!(t)).collect();
        verifier.insert("allowedSuites".into(), Value::Array(list));
    }
    if let Some(s) = e("PCA_PQ_PINS").filter(|s| !s.is_empty()) {
        let pins: Value = serde_json::from_str(s).map_err(|_| "PCA_PQ_PINS is not valid JSON".to_string())?; // never echo the value
        match &pins {
            Value::Object(m) if m.values().all(Value::is_string) => {}
            _ => return Err("PCA_PQ_PINS must be a JSON object of issuer -> public key strings".to_string()),
        }
        verifier.insert("pqPins".into(), pins);
    }
    if let Some(s) = e("PCA_ALLOW_UNBOUND_PQ") {
        let on = ["1", "true", "yes", "on"].iter().any(|t| s.eq_ignore_ascii_case(t));
        verifier.insert("allowUnboundPq".into(), Value::Bool(on));
    }
    if !verifier.is_empty() {
        c.insert("verifier".into(), Value::Object(verifier));
    }
    Ok(Value::Object(c))
}

/// `Object.entries(v)` of a decoded JSON value (an object's members, an array's or a string's indices).
fn entries_of(v: &Value) -> Vec<(String, Value)> {
    match v {
        Value::Object(m) => js_entries(m).into_iter().map(|(k, x)| (k.clone(), x.clone())).collect(),
        Value::Array(a) => a.iter().enumerate().map(|(i, x)| (i.to_string(), x.clone())).collect(),
        Value::String(s) => s.chars().enumerate().map(|(i, c)| (i.to_string(), Value::String(c.to_string()))).collect(),
        _ => vec![],
    }
}

/// Two-level merge: later sources win per field inside each section.
pub fn merge_config(cs: &[Value]) -> Result<Value, String> {
    let mut out: Map<String, Value> = Map::new();
    for c in cs {
        for (k, val) in entries_of(c) {
            if k == "__proto__" || k == "constructor" || k == "prototype" {
                return Err(format!("config key \"{k}\" is not allowed"));
            }
            if let Value::Object(_) = val {
                let mut merged: Map<String, Value> = match out.get(&k) {
                    Some(prev) if !prev.is_null() => entries_of(prev).into_iter().collect(),
                    _ => Map::new(),
                };
                for (mk, mv) in entries_of(&val) {
                    merged.insert(mk, mv);
                }
                out.insert(k, Value::Object(merged));
            } else {
                out.insert(k, val);
            }
        }
    }
    Ok(Value::Object(out))
}

/// A `.json` configuration file. shortcut: the reference also loads a JS module; a Rust program passes the config itself.
pub fn load_config_file(path: &str) -> Result<Value, String> {
    if !path.ends_with(".json") {
        return Err(format!("only a .json config file can be loaded: {path}"));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))
}

// ---- command line --------------------------------------------------------------------------------------------------------

fn groups(flag: &str, v: Option<&String>) -> Result<Vec<String>, String> {
    let g: Vec<String> = v.map_or("", |s| s.as_str()).split(',').filter(|x| !x.is_empty()).map(String::from).collect();
    let bad: Vec<&String> = g.iter().filter(|x| !CHECK_GROUPS.contains(&x.as_str())).collect();
    if !bad.is_empty() || g.is_empty() {
        let names = if bad.is_empty() { "(none given)".to_string() } else { bad.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ") };
        return Err(format!("{flag}: unknown check group(s) {names}"));
    }
    Ok(g)
}

fn num_arg(flag: &str, v: Option<&String>) -> Result<Value, String> {
    let n = match v {
        Some(s) if !s.is_empty() => js_str_to_number(s),
        _ => f64::NAN,
    };
    if !n.is_finite() {
        return Err(format!("{flag} needs a number"));
    }
    Ok(num_value(n))
}

fn sub<'a>(f: &'a mut Map<String, Value>, name: &str) -> &'a mut Map<String, Value> {
    let e = f.entry(name.to_string()).or_insert_with(|| Value::Object(Map::new()));
    if !e.is_object() {
        *e = Value::Object(Map::new());
    }
    match e {
        Value::Object(m) => m,
        _ => unreachable!("just made an object"),
    }
}

/// `d.key = v`, where an undefined value leaves the member absent.
fn set(d: &mut Map<String, Value>, key: &str, v: Option<&String>) {
    match v {
        Some(s) => {
            d.insert(key.to_string(), json!(s));
        }
        None => {
            d.remove(key);
        }
    }
}

/// The parsed command line: `{flags (a config), only, json, strict, help, config?}`.
pub fn parse_doctor_args(argv: &[String]) -> Result<Value, String> {
    let mut flags: Map<String, Value> = Map::new();
    let mut only: Vec<String> = CHECK_GROUPS.iter().map(|s| s.to_string()).collect();
    let (mut config, mut json_out, mut strict, mut help) = (None::<String>, false, false, false);
    let mut i = 0usize;
    while i < argv.len() {
        let k = argv[i].as_str();
        match k {
            "--url" => {
                let v = next_arg(argv, &mut i);
                set(&mut flags, "url", v);
            }
            "--config" => config = next_arg(argv, &mut i).cloned(),
            "--store" => {
                let v = next_arg(argv, &mut i);
                set(sub(&mut flags, "store"), "adapter", v);
            }
            "--store-option" => {
                let kv = next_arg(argv, &mut i).cloned().unwrap_or_default();
                let eq = match kv.find('=') {
                    Some(e) if e >= 1 => e,
                    _ => return Err("--store-option needs k=v".to_string()),
                };
                let st = sub(&mut flags, "store");
                let opts = sub(st, "options");
                opts.insert(kv[..eq].to_string(), json!(kv[eq + 1..]));
            }
            "--reference" => {
                let v = next_arg(argv, &mut i);
                set(sub(&mut flags, "clock"), "referenceUrl", v);
            }
            "--max-skew-ms" => {
                let n = num_arg(k, next_arg(argv, &mut i))?;
                sub(&mut flags, "clock").insert("maxSkewMs".into(), n);
            }
            "--trusted-proxy-count" => {
                let n = num_arg(k, next_arg(argv, &mut i))?;
                sub(&mut flags, "proxy").insert("trustedProxyCount".into(), n);
            }
            "--proxy-header" => {
                let h = next_arg(argv, &mut i).cloned().unwrap_or_default().to_lowercase();
                if !PROXY_HEADERS.contains(&h.as_str()) {
                    return Err("--proxy-header must be x-forwarded-for, forwarded or x-real-ip".to_string());
                }
                sub(&mut flags, "proxy").insert("header".into(), json!(h));
            }
            "--proxy-hops" => {
                let n = num_arg(k, next_arg(argv, &mut i))?;
                sub(&mut flags, "proxy").insert("hops".into(), n);
            }
            "--no-probe" => {
                sub(&mut flags, "proxy").insert("probe".into(), Value::Bool(false));
            }
            "--pca-dir" => {
                let v = next_arg(argv, &mut i);
                set(sub(&mut flags, "verifier"), "pcaDir", v);
            }
            "--only" => only = groups(k, next_arg(argv, &mut i))?,
            "--skip" => {
                let s = groups(k, next_arg(argv, &mut i))?;
                only.retain(|g| !s.contains(g));
            }
            "--strict" => strict = true,
            "--json" => json_out = true,
            "-h" | "--help" => help = true,
            _ => return Err(format!("unknown argument {k}")),
        }
        i += 1;
    }
    let mut a = Map::new();
    a.insert("flags".into(), Value::Object(flags));
    a.insert("only".into(), json!(only));
    a.insert("json".into(), json!(json_out));
    a.insert("strict".into(), json!(strict));
    a.insert("help".into(), json!(help));
    if let Some(c) = config {
        a.insert("config".into(), json!(c));
    }
    Ok(Value::Object(a))
}

fn next_arg<'a>(argv: &'a [String], i: &mut usize) -> Option<&'a String> {
    *i += 1;
    argv.get(*i)
}

fn json_string(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\u{8}' => o.push_str("\\b"),
            '\u{c}' => o.push_str("\\f"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// `JSON.stringify(v, null, 2)`.
pub fn stringify_pretty(v: &Value) -> String {
    fn go(v: &Value, ind: &str) -> String {
        let inner = format!("{ind}  ");
        match v {
            Value::Null => "null".to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.as_f64().filter(|f| f.is_finite()).map_or("null".to_string(), jn),
            Value::String(s) => json_string(s),
            Value::Array(a) if a.is_empty() => "[]".to_string(),
            Value::Array(a) => format!("[\n{}\n{ind}]", a.iter().map(|x| format!("{inner}{}", go(x, &inner))).collect::<Vec<_>>().join(",\n")),
            Value::Object(m) if m.is_empty() => "{}".to_string(),
            Value::Object(m) => format!(
                "{{\n{}\n{ind}}}",
                js_entries(m).into_iter().map(|(k, x)| format!("{inner}{}: {}", json_string(k), go(x, &inner))).collect::<Vec<_>>().join(",\n")
            ),
        }
    }
    go(v, "")
}

/// The environment of this process as an object of strings (what [`main`] takes as `env`).
pub fn env_from_process() -> Value {
    Value::Object(std::env::vars().map(|(k, v)| (k, Value::String(v))).collect())
}

fn build_config(a: &Value, env: &Value) -> Result<Value, String> {
    let file = match a.get("config").and_then(Value::as_str) {
        Some(p) => load_config_file(p)?,
        None => json!({}),
    };
    merge_config(&[file, config_from_env(env)?, a["flags"].clone()])
}

/// Run the command line: exit code 1 on any fail (and on warn with `--strict`), 2 on usage errors, else 0.
pub fn main(argv: &[String], env: &Value, print: &mut dyn FnMut(&str), print_err: &mut dyn FnMut(&str), deps: &DoctorDeps) -> i32 {
    let setup = parse_doctor_args(argv).and_then(|a| {
        if a["help"] == Value::Bool(true) {
            return Ok((a, None));
        }
        let cfg = build_config(&a, env)?;
        Ok((a, Some(cfg)))
    });
    let (a, cfg) = match setup {
        Ok(t) => t,
        Err(e) => {
            print_err(&format!("{}\n\n{USAGE}", scrub_str(&e)));
            return 2;
        }
    };
    let Some(cfg) = cfg else {
        print(USAGE);
        return 0;
    };
    let only: Vec<&str> = a["only"].as_array().map(|v| v.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    let strict = a["strict"] == Value::Bool(true);
    let results = run_doctor(&cfg, Some(&only), deps);
    let verdict = verdict_of(&results, strict);
    let url = cfg.get("url").filter(|u| !u.is_null());
    if a["json"] == Value::Bool(true) {
        print(&stringify_pretty(&json!({ "target": url.cloned().unwrap_or(Value::Null), "verdict": verdict, "results": results })));
    } else {
        print(&format_results(&results, url.filter(|u| truthy(Some(*u))).map(js_str).as_deref(), strict));
    }
    i32::from(verdict == "fail")
}
