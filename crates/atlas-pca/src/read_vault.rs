//! K5 tokenisation vault and aggregate read limits (C-315..C-319), companion of `readside.rs`. A pure, total port of
//! packages/pca/src/read-vault.ts; replays packages/pca/conformance/vault-aggregate-vectors.json. No function panics; anything
//! malformed, unsigned or out of scope denies. Integers only (see `workflow.rs`). Verification only: this crate never signs.
//!
//! VAULT. [`redact_read_with_vault`] runs `redact_read` and records every `tok_...` it minted (class, value, grant digest) in a
//! [`VaultStore`]; [`detokenize`] returns the value only for a signed, unexpired, pinned-principal grant that lets the token's class
//! reach the named sink, and only for a token minted under THIS grant.
//!
//! AGGREGATES. [`aggregate_read`] is a pure step over an explicit state: it charges an epsilon budget, enforces a minimum group size
//! and a query cap, answers a repeated identical query from the state without charging, and (with `dp`) adds discrete Laplace noise
//! drawn by an integer-exact sampler (Canonne-Kamath-Steinke) from a stream of SHA-256 blocks. Noise mode `seeded` is deterministic
//! (the shared vectors pin it); `secure` (the PRODUCTION setting) seeds the same sampler from the OS CSPRNG.
use crate::fresh_at::verify_body;
use crate::readside::{grade_grant, read_grant_digest, ReadResult};
use crate::workflow::{int, is_b32, is_id_str, is_str, is_uint, only_keys, sorted_unique, uint, Decision};
use crate::{b64_encode, decode_b64u_strict, hash_canonical_strict};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

// ---- vault ---------------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct VaultEntry {
    pub cls: String,
    /// the original scalar (string, bool or integer)
    pub value: Value,
    /// digest of the read grant the token was minted under
    pub grant: String,
    pub exp: i64,
}

/// Where minted tokens live. Implementations must not panic; `put` replaces an existing token.
pub trait VaultStore: Send + Sync {
    fn put(&self, token: &str, e: VaultEntry);
    fn get(&self, token: &str) -> Option<VaultEntry>;
}

/// In-process vault (one mutex). One process only; back [`VaultStore`] with a database for several workers.
#[derive(Debug, Default)]
pub struct MemoryVault {
    m: Mutex<HashMap<String, VaultEntry>>,
}
impl MemoryVault {
    pub fn new() -> Self {
        Self::default()
    }
}
impl VaultStore for MemoryVault {
    fn put(&self, token: &str, e: VaultEntry) {
        self.m.lock().unwrap_or_else(|p| p.into_inner()).insert(token.to_string(), e);
    }
    fn get(&self, token: &str) -> Option<VaultEntry> {
        self.m.lock().unwrap_or_else(|p| p.into_inner()).get(token).cloned()
    }
}

fn read_no(code: &'static str) -> ReadResult {
    ReadResult { decision: Decision::Deny, code: Some(code), view: Map::new(), fields: BTreeMap::new(), labels: vec![], counts: BTreeMap::new() }
}

/// `redact_read` that also records every token it minted in `store`. `inp` is the flat `redact_read` input (with `grant`).
pub fn redact_read_with_vault(inp: &Value, store: &dyn VaultStore) -> ReadResult {
    let r = crate::readside::redact_read(inp);
    if r.decision != Decision::Allow {
        return r;
    }
    let body = inp.get("grant").and_then(|g| g.get("body"));
    let (Some(digest), Some(exp)) = (body.and_then(read_grant_digest), body.and_then(|b| b.get("expires_at")).and_then(uint)) else { return read_no("bad_request") };
    let mut minted: Vec<(String, VaultEntry)> = Vec::new();
    for (path, f) in &r.fields {
        if f.action == "masked" && f.kind.as_deref() == Some("token") {
            let (Some(tok), Some(value)) = (r.view.get(path).and_then(Value::as_str), inp.get("record").and_then(|x| x.get(path))) else { return read_no("bad_request") };
            minted.push((tok.to_string(), VaultEntry { cls: f.class.clone(), value: value.clone(), grant: digest.clone(), exp }));
        }
    }
    for (tok, e) in minted {
        store.put(&tok, e);
    }
    r
}

#[derive(Debug, Clone, PartialEq)]
pub struct DetokenizeResult {
    pub decision: Decision,
    pub code: Option<&'static str>,
    pub value: Option<Value>,
}
impl DetokenizeResult {
    /// The shape of the shared vectors: `{decision, code, value}`.
    pub fn to_json(&self) -> Value {
        json!({ "decision": self.decision.as_str(), "code": self.code, "value": self.value })
    }
}
fn dno(code: &'static str) -> DetokenizeResult {
    DetokenizeResult { decision: Decision::Deny, code: Some(code), value: None }
}

/// Turn a token back into its value, only for a sink the grant allows that token's class to reach. Every argument is the raw JSON
/// value, so hostile input denies (`bad_request`) instead of failing to type.
pub fn detokenize(grant: &Value, principal: &Value, now: &Value, sink: &Value, token: &Value, store: &dyn VaultStore) -> DetokenizeResult {
    let (Some(token), Some(sink)) = (token.as_str(), sink.as_str()) else { return dno("bad_request") };
    let (g, raw, now) = match grade_grant(Some(grant), Some(principal), Some(now)) {
        Ok(g) => g,
        Err(code) => return dno(code),
    };
    let Some(digest) = read_grant_digest(raw) else { return dno("bad_request") };
    let Some(e) = store.get(token).filter(|e| e.grant == digest) else { return dno("unknown_token") };
    if now >= e.exp {
        return dno("expired");
    }
    let Some(rule) = g.sinks.get(sink) else { return dno("unknown_sink") };
    if rule.allow.contains(&e.cls) {
        return DetokenizeResult { decision: Decision::Allow, code: None, value: Some(e.value) };
    }
    if rule.escalate.contains(&e.cls) {
        return DetokenizeResult { decision: Decision::Escalate, code: Some("label_escalate"), value: None };
    }
    dno("label_flow")
}

// ---- integer-exact discrete Laplace sampler (Canonne, Kamath, Steinke 2020, Alg. 1-2) ---------------------------------------------
// Every step is integer arithmetic over a stream of 48-bit draws from SHA-256 blocks, so every language agrees byte for byte.
// P[noise = x] is proportional to exp(-|x| * epsilon / sensitivity) with epsilon = epsilon_micro / 1e6. All values stay below 2^53
// (the bound checks below), so i64 is exact.

const DP_STREAM: &str = "atlas-pca/dp-stream/v1";
const TWO48: u64 = 1 << 48;
const MAX_DRAWS: i64 = 100_000;

/// A bad bound, or a sampler that did not terminate (the reference's `RangeError`), or no OS randomness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamplerError;

/// A draw source: block `i` is SHA-256 of the canonical `{d, seed, i}`; each block yields five 48-bit big-endian values (bytes 0-5, 6-11, ..., 24-29).
pub struct Draws {
    seed: String,
    block: i64,
    buf: Vec<u64>,
    pos: usize,
}
/// `Draws` keyed by a seed string (deterministic).
pub fn seeded_draws(seed: &str) -> Draws {
    Draws { seed: seed.to_string(), block: 0, buf: Vec::new(), pos: 0 }
}
/// The PRODUCTION mode: a fresh 32-byte seed from the operating system's CSPRNG (base64url, unpadded). Answers differ per call.
pub fn secure_draws() -> Result<Draws, SamplerError> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|_| SamplerError)?;
    Ok(seeded_draws(&b64_encode(&b)))
}

impl Draws {
    fn next48(&mut self) -> Result<u64, SamplerError> {
        if self.pos >= self.buf.len() {
            let h = hash_canonical_strict(&json!({ "d": DP_STREAM, "seed": self.seed, "i": self.block })).ok_or(SamplerError)?;
            self.block += 1;
            let bytes = decode_b64u_strict(&h, Some(32)).ok_or(SamplerError)?;
            self.buf = (0..5).map(|k| bytes[k * 6..k * 6 + 6].iter().fold(0u64, |v, b| v * 256 + u64::from(*b))).collect();
            self.pos = 0;
        }
        self.pos += 1;
        Ok(self.buf[self.pos - 1])
    }
    /// Uniform on `0..n` for `1 <= n <= 2^47` by rejection sampling of 48-bit values (at most 100000 draws).
    pub fn uniform(&mut self, n: i64) -> Result<i64, SamplerError> {
        if !(1..=(1i64 << 47)).contains(&n) {
            return Err(SamplerError);
        }
        let n = n as u64;
        let limit = TWO48 - (TWO48 % n);
        for _ in 0..MAX_DRAWS {
            let r = self.next48()?;
            if r < limit {
                return Ok((r % n) as i64);
            }
        }
        Err(SamplerError)
    }
    fn bern(&mut self, num: i64, den: i64) -> Result<bool, SamplerError> {
        Ok(self.uniform(den)? < num)
    }
    /// Bernoulli(exp(-num/den)) for 0 <= num/den <= 1.
    fn bern_exp_small(&mut self, num: i64, den: i64) -> Result<bool, SamplerError> {
        for k in 1..=MAX_DRAWS {
            if !self.bern(num, den.checked_mul(k).ok_or(SamplerError)?)? {
                return Ok(k % 2 == 1);
            }
        }
        Err(SamplerError)
    }
    /// Discrete Laplace with P[x] proportional to exp(-|x| s / t) (CKS Alg. 2: `s` is the rate numerator, `t` the scale denominator).
    pub fn discrete_laplace(&mut self, s: i64, t: i64) -> Result<i64, SamplerError> {
        if s < 1 {
            return Err(SamplerError);
        }
        for _ in 0..MAX_DRAWS {
            let u = self.uniform(t)?;
            if !self.bern_exp_small(u, t)? {
                continue;
            }
            let mut v: i64 = 0;
            while self.bern_exp_small(1, 1)? {
                v += 1;
                if v > MAX_DRAWS {
                    return Err(SamplerError);
                }
            }
            let y = (u.checked_add(t.checked_mul(v).ok_or(SamplerError)?).ok_or(SamplerError)?) / s;
            let negative = self.uniform(2)? == 1;
            if negative && y == 0 {
                continue;
            }
            return Ok(if negative { -y } else { y });
        }
        Err(SamplerError)
    }
}

// ---- aggregates ----------------------------------------------------------------------------------------------------------------

pub const AGGREGATE_DOMAIN: &str = "atlas-pca/aggregate-grant/v1\0";
const AG_REF: &str = "atlas-pca/aggregate-grant-ref/v1";
const AG_Q: &str = "atlas-pca/aggregate-query/v1";
const AG_N: &str = "atlas-pca/aggregate-noise/v1";

struct Rule {
    verb: String,
    resource_prefix: String,
    purposes: Vec<String>,
    fns: Vec<String>,
    min_group: i64,
    clamp: i64,
    epsilon_micro: i64,
    dp: bool,
}
struct AGrant {
    principal: String,
    issued_at: i64,
    expires_at: i64,
    rules: Vec<Rule>,
    epsilon_budget_micro: i64,
    max_queries: i64,
}

fn is_fn_str(s: &str) -> bool {
    s == "count" || s == "sum"
}
fn s(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).map(str::to_string)
}
fn parse_rule(v: &Value) -> Option<Rule> {
    let r = v.as_object().filter(|r| only_keys(r, &["verb", "resource_prefix", "purposes", "fns", "min_group", "clamp", "epsilon_micro", "dp"]))?;
    if !(is_str(r.get("verb"), 128) && is_str(r.get("resource_prefix"), 512)) {
        return None;
    }
    let purposes = sorted_unique(r.get("purposes"), is_id_str, 16).filter(|p| !p.is_empty())?;
    let fns = sorted_unique(r.get("fns"), is_fn_str, 2).filter(|f| !f.is_empty())?;
    let (min_group, clamp, epsilon_micro) = (r.get("min_group").and_then(uint)?, r.get("clamp").and_then(uint)?, r.get("epsilon_micro").and_then(uint)?);
    let dp = r.get("dp")?.as_bool()?;
    if min_group < 1 || clamp > 1_000_000 || epsilon_micro > 1_073_741_824 || (dp && epsilon_micro < 1) {
        return None;
    }
    Some(Rule { verb: s(r.get("verb"))?, resource_prefix: s(r.get("resource_prefix"))?, purposes, fns, min_group, clamp, epsilon_micro, dp })
}
/// Shape of an aggregate grant body (no signature): `validAggregateGrantBody`.
fn parse_agrant(v: &Value) -> Option<AGrant> {
    let b = v.as_object().filter(|b| only_keys(b, &["v", "id", "principal", "issued_at", "expires_at", "rules", "epsilon_budget_micro", "max_queries"]))?;
    if b.get("v").and_then(int) != Some(1) || !b.get("id")?.as_str().is_some_and(is_id_str) || !is_b32(b.get("principal")) || !is_uint(b.get("issued_at")) || !is_uint(b.get("expires_at")) {
        return None;
    }
    let ra = b.get("rules")?.as_array().filter(|a| !a.is_empty() && a.len() <= 16)?;
    let rules = ra.iter().map(parse_rule).collect::<Option<Vec<_>>>()?;
    Some(AGrant {
        principal: s(b.get("principal"))?,
        issued_at: b.get("issued_at").and_then(uint)?,
        expires_at: b.get("expires_at").and_then(uint)?,
        rules,
        epsilon_budget_micro: b.get("epsilon_budget_micro").and_then(uint)?,
        max_queries: b.get("max_queries").and_then(uint)?,
    })
}
pub fn aggregate_grant_digest(body: &Value) -> Option<String> {
    hash_canonical_strict(&json!({ "d": AG_REF, "g": body }))
}

/// A fresh aggregate state: `{spent_micro: 0, queries: 0, answered: {}}`.
pub fn empty_aggregate_state() -> Value {
    json!({ "spent_micro": 0, "queries": 0, "answered": {} })
}

#[derive(Debug, Clone, PartialEq)]
pub struct AggregateResult {
    pub decision: Decision,
    pub code: Option<&'static str>,
    pub value: Option<i64>,
    /// `{spent_micro, queries, answered}`; a refusal carries the INPUT state unchanged (the empty state for a malformed one or an internal error)
    pub state: Value,
    pub charged_micro: i64,
}
impl AggregateResult {
    /// The shape of the shared vectors: `{decision, code, value, state, charged_micro}`.
    pub fn to_json(&self) -> Value {
        json!({ "decision": self.decision.as_str(), "code": self.code, "value": self.value, "state": self.state, "charged_micro": self.charged_micro })
    }
}
fn fail(code: &'static str, state: Value) -> AggregateResult {
    AggregateResult { decision: Decision::Deny, code: Some(code), value: None, state, charged_micro: 0 }
}

/// Answer one aggregate under the grant, or refuse. `inp` is the flat reference input `{grant, principal, now, verb, resource,
/// purpose, fn, values, salt, noise, state}`; the input state is never mutated. The reference's `RangeError`s (a bad sampler
/// bound, no termination, no OS randomness) are the catch-all here too: deny `bad_request` with the EMPTY state.
pub fn aggregate_read(inp: &Value) -> AggregateResult {
    aggregate(inp).unwrap_or_else(|_| fail("bad_request", empty_aggregate_state()))
}
fn aggregate(inp: &Value) -> Result<AggregateResult, SamplerError> {
    let Some(inp) = inp.as_object() else { return Err(SamplerError) };
    let Some(st) = inp.get("state").filter(|st| st.is_object()) else { return Ok(fail("bad_request", empty_aggregate_state())) };
    let (Some(spent), Some(queries), Some(answered)) = (st.get("spent_micro").and_then(uint), st.get("queries").and_then(uint), st.get("answered").and_then(Value::as_object)) else {
        return Ok(fail("bad_request", empty_aggregate_state()));
    };
    if !answered.values().all(|v| int(v).is_some()) {
        return Ok(fail("bad_request", empty_aggregate_state()));
    }
    let keep = |code: &'static str| Ok(fail(code, st.clone()));
    let (Some(principal), Some(now)) = (inp.get("principal").and_then(Value::as_str).filter(|p| crate::workflow::is_b32_str(p)), inp.get("now").and_then(uint)) else { return keep("bad_request") };
    let Some(sg) = inp.get("grant").and_then(Value::as_object).filter(|o| only_keys(o, &["body", "sig"])) else { return keep("bad_grant") };
    let raw = &sg["body"];
    let Some(g) = parse_agrant(raw) else { return keep("bad_grant") };
    if g.principal != principal || !verify_body(AGGREGATE_DOMAIN, raw, principal, sg["sig"].as_str()) {
        return keep("bad_signature");
    }
    if now < g.issued_at {
        return keep("not_yet");
    }
    if now >= g.expires_at {
        return keep("expired");
    }
    let (Some(verb), Some(resource), Some(purpose), Some(func), Some(noise), Some(salt), Some(values)) = (
        inp.get("verb").and_then(Value::as_str),
        inp.get("resource").and_then(Value::as_str),
        inp.get("purpose").and_then(Value::as_str),
        inp.get("fn").and_then(Value::as_str),
        inp.get("noise").and_then(Value::as_str),
        inp.get("salt").and_then(Value::as_str),
        inp.get("values").and_then(Value::as_array),
    ) else {
        return keep("bad_request");
    };
    let ints: Option<Vec<i64>> = values.iter().map(int).collect();
    let secure = noise == "secure";
    let Some(ints) = ints.filter(|v| v.len() <= 1_000_000) else { return keep("bad_request") };
    if !is_str(inp.get("verb"), 128) || !is_str(inp.get("resource"), 512) || !is_id_str(purpose) || !is_fn_str(func) || !(secure || noise == "seeded") || salt.encode_utf16().count() < 16 {
        return keep("bad_request");
    }
    let Some(rule) = g.rules.iter().find(|r| r.verb == verb && resource.starts_with(r.resource_prefix.as_str()) && r.purposes.iter().any(|p| p == purpose)) else { return keep("no_read_scope") };
    if !rule.fns.iter().any(|f| f == func) {
        return keep("no_read_scope");
    }
    let n = ints.len() as i64;
    if n < rule.min_group {
        return keep("group_too_small");
    }
    // every value is clamped to +-clamp (the sensitivity) before summing: at most 1e6 * 1e6, exact in i64
    let clamped_sum: i64 = ints.iter().map(|v| (*v).clamp(-rule.clamp, rule.clamp)).sum();
    let gd = aggregate_grant_digest(raw).ok_or(SamplerError)?;
    let qd = hash_canonical_strict(&json!({ "d": AG_Q, "g": gd, "verb": verb, "resource": resource, "purpose": purpose, "fn": func, "n": n, "s": clamped_sum })).ok_or(SamplerError)?;
    if let Some(prior) = answered.get(&qd).and_then(int) {
        return Ok(AggregateResult { decision: Decision::Allow, code: None, value: Some(prior), state: st.clone(), charged_micro: 0 });
    }
    if queries + 1 > g.max_queries {
        return keep("query_cap");
    }
    let cost = if rule.dp { rule.epsilon_micro } else { 0 };
    if spent + cost > g.epsilon_budget_micro {
        return keep("epsilon_exhausted");
    }
    let mut exact = if func == "count" { n } else { clamped_sum };
    if rule.dp {
        let sens = if func == "count" { 1 } else { rule.clamp };
        let mut draws = if secure { secure_draws()? } else { seeded_draws(&hash_canonical_strict(&json!({ "d": AG_N, "salt": salt, "q": qd })).ok_or(SamplerError)?) };
        exact += draws.discrete_laplace(rule.epsilon_micro, sens * 1_000_000)?;
    }
    let mut next = answered.clone();
    next.insert(qd, json!(exact));
    let state = json!({ "spent_micro": spent + cost, "queries": queries + 1, "answered": next });
    Ok(AggregateResult { decision: Decision::Allow, code: None, value: Some(exact), state, charged_micro: cost })
}
