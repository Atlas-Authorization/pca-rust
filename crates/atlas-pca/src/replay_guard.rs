//! The replay guard of a resource server (port of `replay.ts`): a signature-verified PCActn is accepted ONCE. The shape and window facts are
//! decided first (no store call before every pre-check passed), then the nonce is consumed once per (audience, grant, leaf holder, nonce) and,
//! when a counter store is given, the per-(audience, grant, leaf holder) monotonic counter is advanced. Never fails: every failure, a store
//! failure included, is a denial. The decision order is the machine-proved one of the reference.
use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::events::replay_key;

const MAX_SAFE: f64 = 9_007_199_254_740_991.0;
/// The longest grant reference or leaf holder (UTF-8 bytes) the guard accepts.
pub const MAX_REPLAY_COMPONENT_LEN: usize = 512;
const MAX_AUD_LEN: usize = 256;
const MAX_NONCE_LEN: usize = 128;
const MAX_LIFETIME_MS: f64 = 3_600_000.0;
const MAX_SKEW_MS: f64 = 60_000.0;

/// Records a nonce as consumed. `Ok(true)` iff this call is the first to consume it (no live record); it MUST remember the key until at
/// least `retain_until_ms` and MUST fail (never `Ok(true)`) when it cannot decide.
pub trait ReplayStore {
    fn consume_once(&self, key: &str, retain_until_ms: f64, now_ms: f64) -> Result<bool, String>;
}

/// A per-stream monotonic counter: `Ok(true)` iff `counter` is above the last accepted one.
pub trait CounterStore {
    fn advance(&self, stream_key: &str, counter: f64) -> Result<bool, String>;
}

/// The reference store: correct only for ONE verifier process whose lifetime covers the action lifetime (state is lost on restart and is
/// not shared between instances). When full of live entries it rejects (fails closed) rather than evict.
pub struct InMemoryReplayStore {
    seen: Mutex<HashMap<String, f64>>,
    streams: Mutex<HashMap<String, f64>>,
    max_entries: usize,
}

impl Default for InMemoryReplayStore {
    fn default() -> Self {
        Self::new(100_000)
    }
}

impl InMemoryReplayStore {
    pub fn new(max_entries: usize) -> Self {
        InMemoryReplayStore { seen: Mutex::new(HashMap::new()), streams: Mutex::new(HashMap::new()), max_entries }
    }

    /// The number of live (unpruned) entries.
    pub fn size(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Drop only entries whose retention has fully elapsed (`retain_until < now`); never frees a still-valid key.
    pub fn prune(&self, now_ms: f64) -> usize {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if !now_ms.is_finite() {
            return 0; // an infinite or NaN clock must not free a live key
        }
        let before = seen.len();
        seen.retain(|_, until| *until >= now_ms);
        before - seen.len()
    }
}

impl ReplayStore for InMemoryReplayStore {
    fn consume_once(&self, key: &str, retain_until_ms: f64, now_ms: f64) -> Result<bool, String> {
        if key.is_empty() || !retain_until_ms.is_finite() || !now_ms.is_finite() || retain_until_ms < now_ms {
            return Err("consumeOnce: invalid key or retention horizon".into());
        }
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let until = seen.get(key).copied();
        if until.is_some_and(|u| u >= now_ms) {
            return Ok(false);
        }
        if until.is_none() && seen.len() >= self.max_entries {
            seen.retain(|_, u| *u >= now_ms);
            if seen.len() >= self.max_entries {
                return Err("replay store full of live entries".into());
            }
        }
        seen.insert(key.to_string(), retain_until_ms.max(until.unwrap_or(0.0)));
        Ok(true)
    }
}

impl CounterStore for InMemoryReplayStore {
    fn advance(&self, stream_key: &str, counter: f64) -> Result<bool, String> {
        if stream_key.is_empty() || !is_safe_nonneg(counter) {
            return Err("advance: invalid stream or counter".into());
        }
        let mut streams = self.streams.lock().unwrap_or_else(|e| e.into_inner());
        match streams.get(stream_key) {
            Some(last) if counter <= *last => Ok(false),
            _ => {
                streams.insert(stream_key.to_string(), counter);
                Ok(true)
            }
        }
    }
}

/// What [`guard_pcactn_replay`] decides.
#[derive(Clone, Debug, PartialEq)]
pub enum ReplayVerdict {
    Ok,
    /// `code` is one of malformed, audience, not_yet_valid, expired, replay, store_unavailable.
    Denied {
        code: &'static str,
        reason: String,
    },
}

impl ReplayVerdict {
    pub fn to_json(&self) -> Value {
        match self {
            ReplayVerdict::Ok => json!({"ok": true}),
            ReplayVerdict::Denied { code, reason } => json!({"ok": false, "code": code, "reason": reason}),
        }
    }
}

/// The guard's options.
#[derive(Clone, Copy)]
pub struct GuardOptions<'a> {
    /// The audience this verifier answers for; compared byte-exactly with the PCActn's `aud`.
    pub aud: &'a str,
    /// The verifier clock, epoch ms.
    pub now: f64,
    /// Clock skew tolerated in both directions (default and ceiling 60 000 ms; a negative or non-finite value is the default).
    pub clock_skew_ms: Option<f64>,
    /// `false`: a PCActn without a `nonce` is guarded by the counter alone (default `true`: it is refused).
    pub require_nonce: Option<bool>,
    /// The per-(audience, grant, leaf holder) counter stream; given, the counter is advanced after the nonce.
    pub counters: Option<&'a dyn CounterStore>,
}

fn is_safe_nonneg(n: f64) -> bool {
    n.is_finite() && n.fract() == 0.0 && (0.0..=MAX_SAFE).contains(&n) && !(n == 0.0 && n.is_sign_negative())
}

fn safe_nonneg(v: Option<&Value>) -> Option<f64> {
    v.filter(|x| x.is_number()).and_then(Value::as_f64).filter(|n| is_safe_nonneg(*n))
}

fn deny(code: &'static str, reason: impl Into<String>) -> ReplayVerdict {
    ReplayVerdict::Denied { code, reason: reason.into() }
}

/// May the (signature-verified) PCActn be accepted ONCE? Verify first; only on allow call the guard.
pub fn guard_pcactn_replay(store: &dyn ReplayStore, p: &Value, o: &GuardOptions) -> ReplayVerdict {
    let skew = o.clock_skew_ms.filter(|s| s.is_finite() && *s >= 0.0).unwrap_or(MAX_SKEW_MS).min(MAX_SKEW_MS);
    let object_ok = p.is_object() || p.is_array();
    let chain = if object_ok { p.get("cap_chain") } else { None };
    let leaf = chain.and_then(Value::as_array).and_then(|c| c.last());
    let holder = leaf.and_then(|l| l.get("holder")).and_then(Value::as_str);
    let grant = p.get("grant_ref").and_then(Value::as_str);
    let leaf_ok = leaf.is_some_and(|l| !l.is_null() && *l != json!(false) && *l != json!(0) && *l != json!(""))
        && holder.is_some()
        && grant.is_some();
    let components_ok =
        leaf_ok && [grant.unwrap_or(""), holder.unwrap_or("")].iter().all(|c| !(c.is_empty() || c.len() > MAX_REPLAY_COMPONENT_LEN));
    let nonce = if object_ok { p.get("nonce") } else { None };
    let has_nonce = nonce.is_some();
    let nonce_ok = nonce.and_then(Value::as_str).is_some_and(|n| !n.is_empty() && n.len() <= MAX_NONCE_LEN);
    let now_ok = o.now.fract() == 0.0 && o.now.abs() <= MAX_SAFE;
    let aud_ok = !o.aud.is_empty() && o.aud.len() <= MAX_AUD_LEN;
    let aud_matches = object_ok && p.get("aud").and_then(Value::as_str) == Some(o.aud);
    let iat = if object_ok { safe_nonneg(p.get("iat")) } else { None };
    let exp = if object_ok { safe_nonneg(p.get("exp")) } else { None };
    let counter = if object_ok { safe_nonneg(p.get("counter")) } else { None };
    let window_ok = matches!((iat, exp), (Some(i), Some(e)) if e > i && e - i <= MAX_LIFETIME_MS);
    let (iat_v, exp_v) = (iat.unwrap_or(0.0), exp.unwrap_or(0.0));
    let skew_whole = skew.floor();
    let require_nonce = o.require_nonce != Some(false);
    let has_counters = o.counters.is_some();

    // Pre: the machine-proved order of the pre-checks
    let pre = if !now_ok {
        Some(("malformed", "verifier clock is not an integer epoch-ms"))
    } else if !aud_ok {
        Some(("malformed", "verifier audience is invalid"))
    } else if !object_ok {
        Some(("malformed", "not a PCActn"))
    } else if !aud_matches {
        Some(("audience", "the PCActn is for another audience"))
    } else if !window_ok {
        Some(("malformed", "iat / exp are not a valid bounded window"))
    } else if iat_v > o.now + skew_whole {
        Some(("not_yet_valid", "iat is in the future beyond the clock-skew allowance"))
    } else if o.now > exp_v {
        Some(("expired", "the PCActn has expired"))
    } else if !leaf_ok {
        Some(("malformed", "no leaf holder / grant"))
    } else if !components_ok {
        Some(("malformed", "grant / holder is not a bounded string"))
    } else if counter.is_none() {
        Some(("malformed", "counter is not a non-negative safe integer"))
    } else {
        None
    };
    if let Some((code, reason)) = pre {
        return deny(code, reason);
    }
    // the retention horizon must be representable: a rounded horizon could free a live nonce early
    if exp_v + skew.ceil() > MAX_SAFE {
        return deny("malformed", "exp + clock skew exceeds the safe-integer range (retention horizon not representable)");
    }
    let retain_until = exp_v + skew;
    let (aud, grant, holder) = (o.aud, grant.unwrap_or(""), holder.unwrap_or(""));
    let mut consumed = true;
    if has_nonce && !nonce_ok || !has_nonce && require_nonce {
        return deny(
            "malformed",
            if has_nonce { "nonce must be a non-empty well-formed string of <= 128 UTF-8 bytes" } else { "a nonce is required" },
        );
    }
    if has_nonce {
        let key = replay_key("pca-nonce/v1", &[aud, grant, holder, nonce.and_then(Value::as_str).unwrap_or("")]);
        match store.consume_once(&key, retain_until, o.now) {
            Ok(c) => consumed = c,
            Err(e) => return deny("store_unavailable", format!("replay store failed closed: {e}")),
        }
        if !consumed {
            return deny("replay", "nonce already consumed");
        }
    }
    if let Some(counters) = o.counters {
        let key = replay_key("pca-counter/v1", &[aud, grant, holder]);
        match counters.advance(&key, counter.unwrap_or(0.0)) {
            Ok(true) => {}
            Ok(false) => return deny("replay", "counter is not greater than the last accepted"),
            Err(e) => return deny("store_unavailable", format!("replay store failed closed: {e}")),
        }
    }
    let _ = consumed;
    ReplayVerdict::Ok
}
