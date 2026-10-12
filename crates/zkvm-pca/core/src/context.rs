//! RT-06: the verifier-relevant evaluation context, committed to the receipt journal and pinnable by a
//! verifier. Before this, the journal held only the verdict and three commitments, so a receipt proved
//! "some context exists for which the gate passes", and `now`, `subject`, `env`, the rate history and the
//! risk inputs were all prover-chosen.
//!
//! Everything the gate reads that is not already covered by `action_commit`, `policy_commit` or
//! `plan_commit` is committed here, in a form a verifier can recompute from its own records:
//! numbers as exact f64 bit patterns (no rounding), JSON values as `hashCanonical` digests.

use crate::commit::hash_canonical;
use crate::DecideInput;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The committed evaluation context (part of the journal).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Context {
    /// `f64::to_bits(now)`: the decision time, epoch ms, exactly as evaluated.
    pub now_bits: u64,
    /// `hashCanonical(subject)`, or the empty string when the subject is ABSENT (R6: distinct from an explicit `null`,
    /// which the predicate DSL resolves differently, e.g. `exists`).
    pub subject_digest: String,
    /// `hashCanonical(env)`; the empty string when absent.
    pub env_digest: String,
    /// `hashCanonical(recent_action_times)`, a JSON array or `null` when absent.
    pub rate_history_digest: String,
    /// R3-12: the delegation depth DERIVED in-guest as `chain.len() - 1` (never a prover input).
    pub delegation_depth: u64,
    /// R3-13: `chain[0].id`, proven equal to the signed `pcactn.grant_ref`.
    pub grant_ref: String,
    /// R3-13: the plan node id the signed PCActn names (proven to be a node of the committed plan matching the action).
    pub node_id: String,
    /// The signed `tool_binding` digest the `tool_schema` caveat compared against.
    pub tool_binding: Option<String>,
    /// Risk inputs at scale S, in the order [semanticDistance, reversibility, blastRadius, taint, confidence, age].
    pub risk_inputs_scaled: [u64; 6],
    pub budget_scaled: u64,
    pub r_floor_scaled: u64,
    /// The pinned root principal the chain was verified against.
    pub root_principal: Option<String>,
    /// `hashCanonical(pcactn)`: the full signed leaf intent the chain verification consumed.
    pub pcactn_digest: String,
    /// R4-04: the signed PCActn's `ver` (proven equal to [`PCACTN_VERSION`]).
    pub pcactn_ver: u64,
    /// R4-04: the signed PCActn's `iat`, epoch ms (a safe integer).
    pub pcactn_iat: i64,
    /// R4-04: the signed PCActn's `exp`, epoch ms (proven `iat < exp <= iat + PCACTN_MAX_LIFETIME_MS`, `iat <= now + skew`,
    /// `now <= exp` at the proven `now`).
    pub pcactn_exp: i64,
    /// R4-04: the signed PCActn's `aud` (non-empty, at most 256 UTF-8 bytes): the verifier pins it to its own audience.
    pub pcactn_aud: String,
    /// R4-04: the signed PCActn's `counter` (a non-negative safe integer; monotonicity against stored state is the
    /// resource server's job, the journal only carries the value so it can be checked there).
    pub pcactn_counter: u64,
}

/// `PCACTN_VERSION` (pcactn.ts): the only wire version the guest and the verifier accept.
pub const PCACTN_VERSION: u64 = 2;
/// `PCACTN_MAX_LIFETIME_MS` (pcactn.ts).
pub const PCACTN_MAX_LIFETIME_MS: i64 = 3_600_000;
/// `PCACTN_MAX_SKEW_MS` (pcactn.ts).
pub const PCACTN_MAX_SKEW_MS: i64 = 60_000;
const MAX_AUD_BYTES: usize = 256;
const MAX_SAFE_INT: i64 = 9_007_199_254_740_991;

/// Why a PCActn's freshness facts are unacceptable at a given clock (mirrors `validityDecision` in the verified core).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    Version,
    Lifetime,
    NotYetValid,
    Expired,
}

/// R4-04: the freshness facts of a signed PCActn, extracted STRICTLY (every field is mandatory and exactly typed: a
/// missing field, a float, a string or a value outside the safe-integer range is `None`, never a default).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcactnFacts {
    pub ver: u64,
    pub iat: i64,
    pub exp: i64,
    pub aud: String,
    pub counter: u64,
}

fn safe_int(v: Option<&Value>) -> Option<i64> {
    let n = v?.as_i64()?;
    (-MAX_SAFE_INT..=MAX_SAFE_INT).contains(&n).then_some(n)
}

impl PcactnFacts {
    pub fn from_pcactn(pc: &Value) -> Option<Self> {
        let ver = safe_int(pc.get("ver"))?;
        let iat = safe_int(pc.get("iat"))?;
        let exp = safe_int(pc.get("exp"))?;
        let counter = safe_int(pc.get("counter"))?;
        let aud = pc.get("aud")?.as_str()?;
        if ver < 0 || counter < 0 || aud.is_empty() || aud.len() > MAX_AUD_BYTES {
            return None;
        }
        Some(PcactnFacts { ver: ver as u64, iat, exp, aud: aud.to_string(), counter: counter as u64 })
    }

    /// `version` + `validity` of verifyPCActnCore at clock `now` (epoch ms; must be a safe integer).
    pub fn check_freshness(&self, now: f64) -> Result<(), Freshness> {
        check_freshness(self.ver, self.iat, self.exp, now)
    }
}

/// The version + validity-window decision (formal/dafny/Verdict.dfy `ValidityDecision` plus `versionOk`).
pub fn check_freshness(ver: u64, iat: i64, exp: i64, now: f64) -> Result<(), Freshness> {
    if ver != PCACTN_VERSION {
        return Err(Freshness::Version);
    }
    // `Number.isSafeInteger(now)`; a non-integer or out-of-range clock is never accepted
    if !(now.is_finite() && now.fract() == 0.0 && now.abs() <= MAX_SAFE_INT as f64) {
        return Err(Freshness::Expired);
    }
    if exp <= iat || exp - iat > PCACTN_MAX_LIFETIME_MS {
        return Err(Freshness::Lifetime);
    }
    if (iat as f64) > now + PCACTN_MAX_SKEW_MS as f64 {
        return Err(Freshness::NotYetValid);
    }
    if now > exp as f64 {
        return Err(Freshness::Expired);
    }
    Ok(())
}

fn digest_opt(v: Option<&Value>) -> String {
    hash_canonical(v.unwrap_or(&Value::Null))
}

/// Digest of an optional context document: `""` when absent, else `hashCanonical(v)` (an explicit `null` included).
fn digest_present(v: Option<&Value>) -> String {
    v.map(hash_canonical).unwrap_or_default()
}

fn times_value(t: &Option<Vec<f64>>) -> Value {
    match t {
        None => Value::Null,
        Some(ts) => Value::Array(
            ts.iter()
                .map(|x| serde_json::Number::from_f64(*x).map(Value::Number).unwrap_or(Value::Null))
                .collect(),
        ),
    }
}

impl Context {
    pub fn from_input(i: &DecideInput) -> Self {
        let facts = i.pcactn.as_ref().and_then(PcactnFacts::from_pcactn);
        Context {
            now_bits: i.now.to_bits(),
            subject_digest: digest_present(i.subject.as_ref()),
            env_digest: digest_present(i.env.as_ref()),
            rate_history_digest: hash_canonical(&times_value(&i.recent_action_times)),
            delegation_depth: crate::derived_delegation_depth(&i.chain),
            grant_ref: i.chain.first().and_then(|c| c.get("id")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
            node_id: i
                .pcactn
                .as_ref()
                .and_then(|p| p.get("plan"))
                .and_then(|p| p.get("node_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            tool_binding: i.tool_binding.clone(),
            risk_inputs_scaled: i.risk_inputs_scaled,
            budget_scaled: i.budget_scaled,
            r_floor_scaled: i.r_floor_scaled,
            root_principal: i.expected_root_principal.clone(),
            pcactn_digest: digest_opt(i.pcactn.as_ref()),
            // a PCActn without well-formed facts is never allowed (see `bind_pcactn`); the defaults only fill the
            // journal of a denied (and therefore unprovable) decision
            pcactn_ver: facts.as_ref().map_or(0, |f| f.ver),
            pcactn_iat: facts.as_ref().map_or(0, |f| f.iat),
            pcactn_exp: facts.as_ref().map_or(0, |f| f.exp),
            pcactn_aud: facts.as_ref().map_or_else(String::new, |f| f.aud.clone()),
            pcactn_counter: facts.as_ref().map_or(0, |f| f.counter),
        }
    }
}

/// What the verifier independently knows and requires. Every field is mandatory: a verifier must state
/// its expectation for each input, there is no "don't care" default. `Option` fields mean "the verifier
/// expects this input to be ABSENT" when `None`.
#[derive(Clone, Debug)]
pub struct ExpectedContext {
    /// The verifier's clock, epoch ms.
    pub now: f64,
    /// Accepted skew between the proven `now` and the verifier clock (ms, both directions).
    pub now_tolerance_ms: f64,
    pub subject: Option<Value>,
    pub env: Option<Value>,
    pub recent_action_times: Option<Vec<f64>>,
    /// Expected derived depth (`chain.len() - 1`).
    pub delegation_depth: u64,
    /// Expected id of the root grant (== signed `grant_ref`).
    pub grant_ref: String,
    /// Expected plan node id.
    pub node_id: String,
    pub tool_binding: Option<String>,
    pub risk_inputs_scaled: [u64; 6],
    pub budget_scaled: u64,
    pub r_floor_scaled: u64,
    pub root_principal: Option<String>,
    /// Expected `hashCanonical(pcactn)`.
    pub pcactn_digest: String,
    /// R4-04, mandatory: the PCActn `ver` the verifier accepts (must be [`PCACTN_VERSION`]).
    pub pcactn_ver: u64,
    /// R4-04, mandatory: the PCActn `iat` / `exp` the verifier holds (from the signed PCActn it was presented).
    pub pcactn_iat: i64,
    pub pcactn_exp: i64,
    /// R4-04, mandatory: the verifier's OWN audience (the PCActn `aud` must equal it; there is no "any audience").
    pub pcactn_aud: String,
    /// R4-04, mandatory: the PCActn `counter` the verifier expects (it checks monotonicity against its own state).
    pub pcactn_counter: u64,
    pub action_commit: String,
    pub policy_commit: String,
    pub plan_commit: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextMismatch {
    /// The journal was produced by guest semantics older than [`crate::MIN_GUEST_VERSION`].
    GuestVersion { proven: u32, minimum: u32 },
    NotAllowed,
    ChainNotVerified,
    Now { proven: u64, expected: u64 },
    Subject,
    Env,
    RateHistory,
    DelegationDepth,
    GrantRef,
    NodeId,
    ToolBinding,
    RiskInputs,
    Budget,
    RiskFloor,
    RootPrincipal,
    PcactnDigest,
    /// R4-04: `ver` differs from the expectation or from [`PCACTN_VERSION`].
    PcactnVersion,
    PcactnIat,
    PcactnExp,
    PcactnAud,
    PcactnCounter,
    /// R4-04: the committed `iat`/`exp` are not a window of `0 < exp - iat <= PCACTN_MAX_LIFETIME_MS`.
    PcactnLifetime,
    /// R4-04: the VERIFIER's clock is before `iat - PCACTN_MAX_SKEW_MS`.
    PcactnNotYetValid,
    /// R4-04: the VERIFIER's clock is after `exp` (or is not a safe integer).
    PcactnExpired,
    ActionCommit,
    PolicyCommit,
    PlanCommit,
}

impl ExpectedContext {
    /// Test/host convenience: derive the expectation from the very input that was proved. A real verifier
    /// builds this from its own clock and records, never from the prover's input.
    pub fn from_input_json(json: &str, now_tolerance_ms: f64) -> Option<Self> {
        let i: DecideInput = serde_json::from_str(json).ok()?;
        let f = i.pcactn.as_ref().and_then(PcactnFacts::from_pcactn)?;
        Some(ExpectedContext {
            now: i.now,
            now_tolerance_ms,
            subject: i.subject.clone(),
            env: i.env.clone(),
            recent_action_times: i.recent_action_times.clone(),
            delegation_depth: crate::derived_delegation_depth(&i.chain),
            grant_ref: Context::from_input(&i).grant_ref,
            node_id: Context::from_input(&i).node_id,
            tool_binding: i.tool_binding.clone(),
            risk_inputs_scaled: i.risk_inputs_scaled,
            budget_scaled: i.budget_scaled,
            r_floor_scaled: i.r_floor_scaled,
            root_principal: i.expected_root_principal.clone(),
            pcactn_digest: digest_opt(i.pcactn.as_ref()),
            pcactn_ver: f.ver,
            pcactn_iat: f.iat,
            pcactn_exp: f.exp,
            pcactn_aud: f.aud,
            pcactn_counter: f.counter,
            action_commit: crate::commit::action_commitment(&i.action),
            policy_commit: crate::commit::policy_commitment(&i.grant),
            plan_commit: crate::commit::plan_commitment(&i.plan).unwrap_or_default(),
        })
    }
}

/// Check a decoded journal against the verifier's expectations. Run it AFTER the receipt itself verified
/// against the pinned image id; this function trusts nothing but the journal bytes it is given.
pub fn check_context(j: &crate::Decision, e: &ExpectedContext) -> Result<(), ContextMismatch> {
    use ContextMismatch as M;
    if j.guest_version < crate::MIN_GUEST_VERSION {
        return Err(M::GuestVersion { proven: j.guest_version, minimum: crate::MIN_GUEST_VERSION });
    }
    if j.allow != 1 {
        return Err(M::NotAllowed);
    }
    if j.chain_verified != 1 {
        return Err(M::ChainNotVerified);
    }
    let c = &j.context;
    let proven_now = f64::from_bits(c.now_bits);
    if !(proven_now.is_finite() && e.now.is_finite() && e.now_tolerance_ms >= 0.0)
        || (proven_now - e.now).abs() > e.now_tolerance_ms
    {
        return Err(M::Now { proven: c.now_bits, expected: e.now.to_bits() });
    }
    if c.subject_digest != digest_present(e.subject.as_ref()) {
        return Err(M::Subject);
    }
    if c.env_digest != digest_present(e.env.as_ref()) {
        return Err(M::Env);
    }
    if c.rate_history_digest != hash_canonical(&times_value(&e.recent_action_times)) {
        return Err(M::RateHistory);
    }
    if c.delegation_depth != e.delegation_depth {
        return Err(M::DelegationDepth);
    }
    if c.grant_ref != e.grant_ref {
        return Err(M::GrantRef);
    }
    if c.node_id != e.node_id {
        return Err(M::NodeId);
    }
    if c.tool_binding != e.tool_binding {
        return Err(M::ToolBinding);
    }
    if c.risk_inputs_scaled != e.risk_inputs_scaled {
        return Err(M::RiskInputs);
    }
    if c.budget_scaled != e.budget_scaled {
        return Err(M::Budget);
    }
    if c.r_floor_scaled != e.r_floor_scaled {
        return Err(M::RiskFloor);
    }
    if c.root_principal != e.root_principal {
        return Err(M::RootPrincipal);
    }
    if c.pcactn_digest != e.pcactn_digest {
        return Err(M::PcactnDigest);
    }
    // R4-04: the PCActn's own version / audience / counter / validity window. The committed values must equal what the
    // verifier holds, AND the window must hold at the VERIFIER's clock (not only at the prover's `now`).
    if c.pcactn_ver != e.pcactn_ver || c.pcactn_ver != PCACTN_VERSION {
        return Err(M::PcactnVersion);
    }
    if c.pcactn_aud != e.pcactn_aud || c.pcactn_aud.is_empty() {
        return Err(M::PcactnAud);
    }
    if c.pcactn_iat != e.pcactn_iat {
        return Err(M::PcactnIat);
    }
    if c.pcactn_exp != e.pcactn_exp {
        return Err(M::PcactnExp);
    }
    if c.pcactn_counter != e.pcactn_counter {
        return Err(M::PcactnCounter);
    }
    match check_freshness(c.pcactn_ver, c.pcactn_iat, c.pcactn_exp, e.now) {
        Ok(()) => {}
        Err(Freshness::Version) => return Err(M::PcactnVersion),
        Err(Freshness::Lifetime) => return Err(M::PcactnLifetime),
        Err(Freshness::NotYetValid) => return Err(M::PcactnNotYetValid),
        Err(Freshness::Expired) => return Err(M::PcactnExpired),
    }
    if j.action_commit != e.action_commit {
        return Err(M::ActionCommit);
    }
    if j.policy_commit != e.policy_commit {
        return Err(M::PolicyCommit);
    }
    if j.plan_commit != e.plan_commit {
        return Err(M::PlanCommit);
    }
    Ok(())
}

/// The journal of the earlier guest builds (image ids `ac95031f...96e3` and `dcf198fc...813a`): verdict and
/// commitments only, NO context. Kept so the legacy receipts can still be decoded; they must not be relied
/// on for any statement about time, subject, environment, rate or risk inputs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyDecision {
    pub allow: u8,
    pub r_scaled: u64,
    pub tier: u8,
    pub action_commit: String,
    pub policy_commit: String,
    pub plan_commit: String,
    pub chain_verified: u8,
}
