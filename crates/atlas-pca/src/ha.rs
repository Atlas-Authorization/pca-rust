//! Guardian high availability (port of `ha.ts`): which guardians are live, whether a co-sign quorum is reachable, the degrade mode
//! when it is lost (read-only or halt, never fail open), signer selection and failover order, and a durable FENCED leader lease
//! (acquire / renew / release, a strictly monotone fencing epoch, a fence guard and a fenced signer).
//!
//! Lease safety holds if the store's compare-and-swap is linearizable and the holder's clock error stays under `skewMs`. A store
//! error, a corrupt record or a bad store clock is a refusal, never a granted lease and never "free".
//!
//! JSON-valued (`&Value` in, the reference's member names out); a number that is not finite is the `{"$num": "NaN"}` marker of the
//! reference's JSON. A reference throw is an `Err`.
use std::cmp::Ordering;
use std::sync::Mutex;
#[cfg(unix)]
use std::sync::Arc;

use serde_json::{json, Value};
#[cfg(not(feature = "icu-collation"))]
use unicode_normalization::UnicodeNormalization;

#[cfg(unix)]
use crate::durable_state::DurableKv;
use crate::prohibitions::num_value;

/// The longest lease holder id, in UTF-16 code units.
const MAX_HOLDER_LEN: usize = 256;
/// The longest lease lifetime (3600000 ms). Not the constant of the same name of the agent-native module.
pub const MAX_LEASE_TTL_MS: f64 = 3_600_000.0;
/// The default clock-error allowance of a lease: a holder stops acting this long before expiry, a challenger waits this long after it.
pub const DEFAULT_LEASE_SKEW_MS: f64 = 1_000.0;

/// A number: a JSON number, or the `{"$num"}` marker; anything else is NaN (`Number.isFinite` of it is false).
fn jsnum(v: Option<&Value>) -> f64 {
    match v {
        Some(n) if n.is_number() => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::Object(m)) => match m.get("$num").and_then(Value::as_str) {
            Some("Infinity") => f64::INFINITY,
            Some("-Infinity") => f64::NEG_INFINITY,
            _ => f64::NAN,
        },
        _ => f64::NAN,
    }
}

/// ECMAScript `ToNumber` of a JSON value, for the relational comparisons the reference makes on loosely typed members.
fn to_number(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                0.0
            } else {
                t.parse::<f64>().ok().filter(|_| !t.contains(['_', 'n', 'N', 'i'])).unwrap_or(f64::NAN)
            }
        }
        other => jsnum(other),
    }
}

fn is_integer(f: f64) -> bool {
    f.is_finite() && f.fract() == 0.0
}

fn is_safe_integer(f: f64) -> bool {
    is_integer(f) && f.abs() <= 9_007_199_254_740_991.0
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(_) => true,
    }
}

/// `typeof x === 'object' && x !== null` (arrays included).
fn is_object(v: &Value) -> bool {
    v.is_object() || v.is_array()
}

// ---- pure decisions over health facts ------------------------------------------------------------------------------------------

fn guardians_of(set: &Value) -> Option<&Vec<Value>> {
    set.get("guardians").and_then(Value::as_array)
}

/// The guardians that are flagged healthy AND have a fresh heartbeat at `now` (`opts`: `{staleMs}`, default 30000). Fails closed: a
/// malformed set, a non-finite clock or stale window, a non-finite or FUTURE-dated heartbeat, or a `healthy` that is not `true` is down.
pub fn live_guardians(set: &Value, now: f64, opts: Option<&Value>) -> Vec<Value> {
    let stale = match opts.and_then(|o| o.get("staleMs")) {
        None | Some(Value::Null) => 30_000.0,
        other => jsnum(other),
    };
    let Some(list) = guardians_of(set).filter(|_| now.is_finite() && stale.is_finite() && stale >= 0.0) else { return Vec::new() };
    if !list.iter().all(is_object) {
        return Vec::new();
    }
    list.iter()
        .filter(|g| {
            let seen = jsnum(g.get("lastSeen"));
            g.get("healthy") == Some(&Value::Bool(true)) && seen.is_finite() && seen <= now && now - seen <= stale
        })
        .cloned()
        .collect()
}

/// `{total, live, quorum, available, degraded}`: a co-sign quorum is reachable right now / some guardians are live but below quorum.
pub fn quorum_status(set: &Value, now: f64, opts: Option<&Value>) -> Value {
    let live = live_guardians(set, now, opts).len() as f64;
    let quorum = set.get("quorum");
    let q = jsnum(quorum);
    let mut out = serde_json::Map::new();
    out.insert("total".into(), json!(guardians_of(set).map_or(0, Vec::len)));
    out.insert("live".into(), json!(live as u64));
    if let Some(q) = quorum {
        out.insert("quorum".into(), q.clone());
    }
    out.insert("available".into(), json!(is_integer(q) && q >= 1.0 && live >= q));
    out.insert("degraded".into(), json!(live > 0.0 && live < to_number(quorum)));
    Value::Object(out)
}

/// The degradation mode of a quorum status: `normal` (quorum available), `read-only` (below quorum, some guardians live, unless the
/// policy `{allowReadOnly: false}` says otherwise) or `halt`. Never fails open.
pub fn degrade_mode(status: &Value, policy: Option<&Value>) -> &'static str {
    if truthy(status.get("available")) {
        "normal"
    } else if to_number(status.get("live")) > 0.0 && policy.and_then(|p| p.get("allowReadOnly")) != Some(&Value::Bool(false)) {
        "read-only"
    } else {
        "halt"
    }
}

/// `String.prototype.localeCompare` of the root locale: the Unicode collation algorithm over the CLDR root collation (ICU4X), tertiary
/// strength, punctuation not ignored, no numeric ordering: the order a JavaScript runtime without a locale makes. Guardian ids tie-break
/// failover and signer selection, so every implementation must order them identically in every script.
#[cfg(feature = "icu-collation")]
fn locale_compare(a: &str, b: &str) -> Ordering {
    use icu_collator::{options::CollatorOptions, CollatorBorrowed, CollatorPreferences};
    use std::sync::LazyLock;
    static ROOT: LazyLock<CollatorBorrowed<'static>> = LazyLock::new(|| CollatorBorrowed::try_new(CollatorPreferences::default(), CollatorOptions::default()).expect("root collation data is compiled in"));
    ROOT.compare(a, b)
}

/// The Latin-script approximation of the root collation, used only when the `icu-collation` feature is off: punctuation, then digits,
/// then letters; case and accents only break ties (lower case before upper case, no accent before an accent). Other scripts order by
/// code point, which differs from the reference: keep the feature on wherever guardian ids are not Latin script.
#[cfg(not(feature = "icu-collation"))]
fn locale_compare(a: &str, b: &str) -> Ordering {
    fn keys(s: &str) -> (Vec<(u8, u32)>, Vec<char>, Vec<bool>) {
        let (mut primary, mut accents, mut upper) = (Vec::new(), Vec::new(), Vec::new());
        for c in s.nfd() {
            if unicode_normalization::char::is_combining_mark(c) {
                accents.push(c);
                continue;
            }
            let lower = c.to_lowercase().next().unwrap_or(c);
            let class = if c.is_alphabetic() { 2 } else if c.is_numeric() { 1 } else { 0 };
            primary.push((class, lower as u32));
            upper.push(lower != c);
        }
        (primary, accents, upper)
    }
    let (pa, aa, ua) = keys(a);
    let (pb, ab, ub) = keys(b);
    pa.cmp(&pb).then_with(|| aa.cmp(&ab)).then_with(|| ua.cmp(&ub))
}

fn weight_of(g: &Value) -> f64 {
    let w = jsnum(g.get("weight"));
    if w.is_finite() {
        w
    } else {
        0.0
    }
}

/// Live guardians in preference order: highest weight, then freshest, then id.
fn preferred(set: &Value, now: f64, opts: Option<&Value>) -> Result<Vec<Value>, String> {
    let mut live = live_guardians(set, now, opts);
    let mut failure: Option<String> = None;
    // a stable merge sort, as the reference's `sort`; the id comparison is only reached on a tie
    live.sort_by(|a, b| {
        let by_weight = weight_of(b).partial_cmp(&weight_of(a)).unwrap_or(Ordering::Equal);
        by_weight.then_with(|| jsnum(b.get("lastSeen")).partial_cmp(&jsnum(a.get("lastSeen"))).unwrap_or(Ordering::Equal)).then_with(|| {
            match (a.get("id").and_then(Value::as_str), b.get("id").and_then(Value::as_str)) {
                (Some(x), Some(y)) => locale_compare(x, y),
                _ => {
                    failure = Some("Cannot read properties of undefined (reading 'localeCompare')".into());
                    Ordering::Equal
                }
            }
        })
    });
    failure.map_or(Ok(live), Err)
}

fn id_of(g: &Value) -> Value {
    g.get("id").cloned().unwrap_or(Value::Null)
}

/// The guardians to ask for a co-sign: the `quorum` freshest and highest-weight live ones, in that order; empty when quorum is not
/// available (never attempt a co-sign below quorum). `Err` for a set that is not an object.
pub fn select_signers(set: &Value, now: f64, opts: Option<&Value>) -> Result<Vec<Value>, String> {
    if set.is_null() {
        return Err("Cannot read properties of null (reading 'quorum')".into());
    }
    let q = jsnum(set.get("quorum"));
    let live = live_guardians(set, now, opts);
    if !is_integer(q) || q < 1.0 || (live.len() as f64) < q {
        return Ok(Vec::new());
    }
    Ok(preferred(set, now, opts)?.iter().take(q as usize).map(id_of).collect())
}

/// `{primary, standbys}`: the preferred live guardian (null when none) and the remaining live ones in preference order.
pub fn failover_plan(set: &Value, now: f64, opts: Option<&Value>) -> Result<Value, String> {
    let live = preferred(set, now, opts)?;
    Ok(json!({ "primary": live.first().map_or(Value::Null, id_of), "standbys": live.iter().skip(1).map(id_of).collect::<Vec<_>>() }))
}

/// Why a guardian set is malformed (quorum out of range, an empty or duplicate id), or `None`.
pub fn validate_guardian_set(set: &Value) -> Option<&'static str> {
    if !is_object(set) {
        return Some("guardian set is not an object");
    }
    let list = match guardians_of(set) {
        Some(l) if !l.is_empty() => l,
        _ => return Some("guardian set is empty"),
    };
    let q = jsnum(set.get("quorum"));
    if !is_integer(q) || q < 1.0 {
        return Some("quorum must be an integer \u{2265} 1");
    }
    if q > list.len() as f64 {
        return Some("quorum exceeds guardian count");
    }
    if !list.iter().all(|g| is_object(g) && g.get("id").and_then(Value::as_str).is_some_and(|i| !i.is_empty())) {
        return Some("guardian id must be a non-empty string");
    }
    let mut ids: Vec<&str> = list.iter().filter_map(|g| g.get("id").and_then(Value::as_str)).collect();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != list.len() {
        return Some("duplicate guardian ids");
    }
    None
}

// ---- the durable, fenced leader lease -------------------------------------------------------------------------------------------

/// The lease persistence contract. `cas` replaces the record iff the stored one equals `expected` (holder, epoch and expiry; `None`
/// = none), atomically and linearizably, and returns whether it did; `next.epoch` must never be below the stored epoch. `now` is the
/// STORE's clock: every expiry decision uses it, never the caller's. An `Err` is a store failure and is reported as one.
pub trait LeaseStore {
    fn read(&self) -> Result<Option<Value>, String>;
    fn cas(&self, expected: Option<&Value>, next: &Value) -> Result<bool, String>;
    fn now(&self) -> Result<f64, String>;
}

/// A well-formed record: `{holder: string, epoch: safe integer >= 1, expiresAt: finite number >= 0}`.
fn valid_record(r: &Value) -> bool {
    r.is_object()
        && r.get("holder").is_some_and(Value::is_string)
        && r.get("epoch").is_some_and(|e| e.is_number() && is_safe_integer(jsnum(Some(e))) && jsnum(Some(e)) >= 1.0)
        && r.get("expiresAt").is_some_and(|e| e.is_number() && jsnum(Some(e)).is_finite() && jsnum(Some(e)) >= 0.0)
}

/// `===` of two JSON members (numbers by value).
fn strict_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) if x.is_number() && y.is_number() => x.as_f64() == y.as_f64(),
        (Some(x), Some(y)) => x == y,
        (None, None) => true,
        _ => false,
    }
}

#[cfg(unix)]
fn eq_lease(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => ["holder", "epoch", "expiresAt"].iter().all(|k| strict_eq(x.get(k), y.get(k))),
        (None, None) => true,
        _ => false,
    }
}

fn rec(holder: &Value, epoch: f64, expires_at: f64) -> Value {
    json!({ "holder": holder, "epoch": num_value(epoch), "expiresAt": num_value(expires_at) })
}

/// `(ttl, skew)` of lease options `{ttlMs, skewMs?}`, or `None` when the holder or the options are invalid: a holder of 1..=256 UTF-16
/// units, `ttlMs` an integer in [2, MAX_LEASE_TTL_MS], `skewMs` finite, >= 0 and below the ttl.
fn lease_opts(holder: &Value, o: &Value) -> Option<(f64, f64)> {
    let h = holder.as_str()?;
    let len = h.encode_utf16().count();
    if len == 0 || len > MAX_HOLDER_LEN {
        return None;
    }
    let skew = match o.get("skewMs") {
        None | Some(Value::Null) => DEFAULT_LEASE_SKEW_MS,
        other => jsnum(other),
    };
    let ttl = jsnum(o.get("ttlMs"));
    if !is_integer(ttl) || ttl < 2.0 || ttl > MAX_LEASE_TTL_MS || !skew.is_finite() || skew < 0.0 || skew >= ttl {
        return None;
    }
    Some((ttl, skew))
}

fn fail(reason: &str) -> Value {
    json!({ "ok": false, "reason": reason })
}

fn store_error(e: &str) -> Value {
    json!({ "ok": false, "reason": "store-error", "detail": e })
}

/// Reads the record and the store clock; a corrupt record or a non-finite clock is a store error (never "free").
fn snapshot(store: &dyn LeaseStore) -> Result<(Option<Value>, f64), String> {
    let cur = store.read()?;
    let now = store.now()?;
    if !now.is_finite() || cur.as_ref().is_some_and(|c| !valid_record(c)) {
        return Err("corrupt lease state".into());
    }
    Ok((cur, now))
}

fn field(r: &Value, k: &str) -> f64 {
    jsnum(r.get(k))
}

fn granted(store: &dyn LeaseStore, cur: Option<&Value>, next: Value) -> Value {
    match store.cas(cur, &next) {
        Ok(true) => json!({ "ok": true, "lease": next }),
        Ok(false) => fail("lost-race"),
        Err(e) => store_error(&e),
    }
}

/// Takes the lease when it is free (never held, released, or expired past the skew); the epoch increments on every takeover. Answers
/// `{ok: true, lease}` or `{ok: false, reason: invalid | held | lost-race | store-error, detail?}`.
pub fn acquire_lease(store: &dyn LeaseStore, holder: &Value, o: &Value) -> Value {
    let Some((ttl, skew)) = lease_opts(holder, o) else { return fail("invalid") };
    let (cur, now) = match snapshot(store) {
        Ok(s) => s,
        Err(e) => return store_error(&e),
    };
    if let Some(c) = &cur {
        if !(field(c, "expiresAt") + skew <= now) && field(c, "expiresAt") != 0.0 {
            return fail("held");
        }
    }
    let epoch = cur.as_ref().map_or(0.0, |c| field(c, "epoch")) + 1.0;
    granted(store, cur.as_ref(), rec(holder, epoch, now + ttl))
}

/// Extends a lease the caller still holds. Refused (`expired`) once the holder's own safe window (expiry minus skew) has passed, and
/// `stale` after any takeover.
pub fn renew_lease(store: &dyn LeaseStore, lease: &Value, o: &Value) -> Value {
    let p = if valid_record(lease) { lease_opts(&lease["holder"], o) } else { None };
    let Some((ttl, skew)) = p else { return fail("invalid") };
    let (cur, now) = match snapshot(store) {
        Ok(s) => s,
        Err(e) => return store_error(&e),
    };
    let Some(c) = cur.as_ref().filter(|c| strict_eq(c.get("holder"), lease.get("holder")) && strict_eq(c.get("epoch"), lease.get("epoch"))) else {
        return fail("stale");
    };
    if !(field(c, "expiresAt") - skew > now) {
        return fail("expired");
    }
    granted(store, cur.as_ref(), rec(&c["holder"], field(c, "epoch"), now + ttl))
}

/// Gives the lease up early (`expiresAt` 0, epoch kept). Only the current holder at the current epoch can.
pub fn release_lease(store: &dyn LeaseStore, lease: &Value) -> Value {
    if !valid_record(lease) {
        return fail("invalid");
    }
    let (cur, _) = match snapshot(store) {
        Ok(s) => s,
        Err(e) => return store_error(&e),
    };
    let Some(c) = cur.as_ref().filter(|c| strict_eq(c.get("holder"), lease.get("holder")) && strict_eq(c.get("epoch"), lease.get("epoch")) && field(c, "expiresAt") != 0.0) else {
        return fail("stale");
    };
    granted(store, cur.as_ref(), rec(&c["holder"], field(c, "epoch"), 0.0))
}

/// Whether this exact `{holder, epoch}` is still the leader, with its safe window open, per the store: `{ok: true}` or `{ok: false,
/// reason: stale | expired | store-error}`. Any error answers no.
pub fn assert_fence(store: &dyn LeaseStore, token: &Value, skew_ms: f64) -> Value {
    if !truthy(Some(token)) || !skew_ms.is_finite() || skew_ms < 0.0 {
        return fail("stale");
    }
    let (cur, now) = match snapshot(store) {
        Ok(s) => s,
        Err(_) => return fail("store-error"),
    };
    let Some(c) = cur.as_ref().filter(|c| strict_eq(c.get("holder"), token.get("holder")) && strict_eq(c.get("epoch"), token.get("epoch"))) else {
        return fail("stale");
    };
    if field(c, "expiresAt") - skew_ms > now {
        json!({ "ok": true })
    } else {
        fail("expired")
    }
}

/// A fenced operation was refused: `stale`, `expired`, `store-error` or `no-lease`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceError {
    pub reason: String,
}

impl std::fmt::Display for FenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fenced: {}", self.reason)
    }
}

impl std::error::Error for FenceError {}

/// What a fenced signer answers to a refusal: the fence (the signature, if any, is discarded) or the signing step itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FencedError<E> {
    Fence(FenceError),
    Sign(E),
}

/// The result of a fenced signature and the fencing epoch it was made under.
#[derive(Debug, Clone, PartialEq)]
pub struct Fenced<R> {
    pub result: R,
    pub epoch: Value,
}

/// A co-sign function that only runs while the caller is the fenced leader. The fence is checked before AND after the signature: a
/// leader that lost the lease mid-signature gets a [`FenceError`] and the signature is discarded. Check-then-sign is inherently racy,
/// so the downstream must also admit the epoch through a [`FenceGuard`].
pub struct FencedSigner<'a> {
    store: &'a dyn LeaseStore,
    get_lease: Box<dyn Fn() -> Option<Value> + 'a>,
    skew_ms: f64,
}

/// A fenced signer over `store` for the lease `get_lease` returns at call time (`skew_ms`: [`DEFAULT_LEASE_SKEW_MS`] in the reference).
pub fn fenced_signer<'a>(store: &'a dyn LeaseStore, get_lease: impl Fn() -> Option<Value> + 'a, skew_ms: f64) -> FencedSigner<'a> {
    FencedSigner { store, get_lease: Box::new(get_lease), skew_ms }
}

impl FencedSigner<'_> {
    /// Runs `sign` under the fence.
    pub fn call<R, E>(&self, sign: impl FnOnce() -> Result<R, E>) -> Result<Fenced<R>, FencedError<E>> {
        let refuse = |v: &Value| FencedError::Fence(FenceError { reason: v["reason"].as_str().unwrap_or("stale").to_string() });
        let lease = (self.get_lease)().filter(|l| truthy(Some(l))).ok_or_else(|| FencedError::Fence(FenceError { reason: "no-lease".into() }))?;
        let pre = assert_fence(self.store, &lease, self.skew_ms);
        if pre["ok"] != true {
            return Err(refuse(&pre));
        }
        let result = sign().map_err(FencedError::Sign)?;
        let post = assert_fence(self.store, &lease, self.skew_ms);
        if post["ok"] != true {
            return Err(refuse(&post));
        }
        Ok(Fenced { result, epoch: lease.get("epoch").cloned().unwrap_or(Value::Null) })
    }
}

/// Resource-side fencing: remembers the highest epoch seen and refuses anything lower (a stale ex-leader's late write).
pub struct FenceGuard {
    highest: Mutex<f64>,
}

/// A fence guard starting at `initial` (a non-positive or unsafe value starts at 0).
pub fn create_fence_guard(initial: f64) -> FenceGuard {
    FenceGuard { highest: Mutex::new(if is_safe_integer(initial) && initial > 0.0 { initial } else { 0.0 }) }
}

impl FenceGuard {
    /// Admits `epoch` when it is a safe integer >= 1 and not below the highest seen, and records it.
    pub fn admit(&self, epoch: f64) -> bool {
        let mut hi = self.highest.lock().unwrap_or_else(|e| e.into_inner());
        if !is_safe_integer(epoch) || epoch < 1.0 || epoch < *hi {
            return false;
        }
        *hi = epoch;
        true
    }

    pub fn highest(&self) -> f64 {
        *self.highest.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The reference [`LeaseStore`] over any [`DurableKv`] (its `update` is the atomic compare-and-swap); over a durable state it survives
/// restarts. The default key is `ha/lease`, the default clock the system clock.
#[cfg(unix)]
pub struct KvLeaseStore {
    kv: Arc<dyn DurableKv>,
    key: String,
    clock: Option<Box<dyn Fn() -> f64 + Send + Sync>>,
}

#[cfg(unix)]
impl KvLeaseStore {
    pub fn new(kv: Arc<dyn DurableKv>, key: Option<&str>, clock: Option<Box<dyn Fn() -> f64 + Send + Sync>>) -> KvLeaseStore {
        KvLeaseStore { kv, key: key.unwrap_or("ha/lease").to_string(), clock }
    }
}

#[cfg(unix)]
impl LeaseStore for KvLeaseStore {
    fn read(&self) -> Result<Option<Value>, String> {
        let v = self.kv.get(&self.key).map_err(|e| e.to_string())?;
        if v.as_ref().is_some_and(|r| !valid_record(r)) {
            return Err("corrupt lease state".into());
        }
        Ok(v)
    }

    fn cas(&self, expected: Option<&Value>, next: &Value) -> Result<bool, String> {
        if !valid_record(next) {
            return Err("invalid lease record".into());
        }
        let mut matched = false;
        self.kv
            .update(&self.key, &mut |prev: Option<Value>| {
                if prev.as_ref().is_some_and(|p| !valid_record(p)) {
                    return None;
                }
                let prev_epoch = prev.as_ref().map_or(0.0, |p| jsnum(p.get("epoch")));
                if !eq_lease(prev.as_ref(), expected) || jsnum(next.get("epoch")) < prev_epoch {
                    return None;
                }
                matched = true;
                Some(next.clone())
            })
            .map_err(|e| e.to_string())?;
        Ok(matched)
    }

    fn now(&self) -> Result<f64, String> {
        Ok(match &self.clock {
            Some(c) => c(),
            None => std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_millis() as f64),
        })
    }
}
