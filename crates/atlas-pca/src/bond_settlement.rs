//! Durable bond settlement, the settlement half: exact micro-unit money arithmetic, the slash split, bond sizing, the evidence digests a
//! signed settlement record commits to, record verification and anchoring, [`BondSettlementPlanner`] (the pure half: validates a transition
//! against a read view, re-derives every slash verdict ITSELF, computes the balance movements and signs the record) and
//! [`StoreBondLedger`] (commits the plans to a [`BondStore`] atomically, fails closed, and stamps every time from a clock the claimant cannot
//! touch). INTERNAL ACCOUNTING ONLY: nothing here moves money.
//!
//! THE CHALLENGE-WINDOW CLOCK: the window opens at the ledger's own `registeredAt` (its clock at `open_claim`), lasts the claim's
//! `challenge_window_ms` and is never derived from the claim's `issued_at`. The ledger's "now" is `max(clock(), highest time the store has
//! ever recorded)`, so a clock that steps backwards cannot reopen a closed window or release early.
//!
//! Policies, plans and records are JSON values with the reference's member names. A slash re-runs the Policy VM through the [`DecideFn`]
//! (and, for a dispute, the [`OracleFn`]) the caller supplies; with none supplied it fails closed.

use crate::agent::{sign_with_suite, KeyPair, PqKeyPair, Suite};
use crate::bond_store::{apply_bond_moves, exact_add, from_micros, num, same_settlement, to_micros, BondStore};
use crate::optimistic::{claim_check, validate_window, WindowPolicy, DEFAULT_MIN_CHALLENGE_WINDOW_MS, DEFAULT_WINDOW_POLICY};
use crate::optimistic_adjudication::{adjudicate_dispute, verify_fraud_proof, DecideFn, OracleFn};
use crate::store_errors::{CodedError, R};
use crate::{canonicalize, hash_canonical};
use serde_json::{json, Map, Value};
use std::sync::Arc;

pub const ESCROW_ACCOUNT: &str = "escrow";
/// The default victim-compensation pool account (contains ':', so it can never be a challenger payout account).
pub const COMPENSATION_POOL_ACCOUNT: &str = "pca:pool:compensation";
pub const MICROS_PER_UNIT: i64 = 1_000_000;
pub const SETTLEMENT_LEAF_DOMAIN: &str = "atlas-pca/settlement-leaf/v1";
const SETTLEMENT_DOMAIN: &str = "atlas-pca/bond-settlement/v1\0";
const MAX_SAFE_MICROS: f64 = 1e15;
const MIN_SHARE_QUANTUM: f64 = 9.313225746154785e-10; // 2^-30
static NULL: Value = Value::Null;

fn fin(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64).filter(|f| f.is_finite())
}

/// The conservative reference split: challenger 50%, victim pool 40%, treasury the remainder. Tunable, not a product decision.
pub fn default_slash_split_policy() -> Value {
    json!({"challengerBps": 5000, "victimBps": 4000})
}

/// `{floor: 1, k: 1, maxOpenClaims: 100, maxOpenAmount: Infinity}` (a null / absent `maxOpenAmount` is Infinity; no curve is linear).
pub fn default_bond_policy() -> Value {
    json!({"floor": 1, "k": 1, "maxOpenClaims": 100, "maxOpenAmount": Value::Null})
}

fn max_open_amount(p: &Value) -> f64 {
    fin(p.get("maxOpenAmount")).unwrap_or(f64::INFINITY)
}

// ---- exact money ----------------------------------------------------------------------------------------------------------------

/// Snap a computed amount UP onto the micro grid (a bond is never rounded down); float noise below 1e-3 micro-units is absorbed.
pub fn quantize_up(x: f64) -> f64 {
    if !x.is_finite() || x <= 0.0 {
        return x;
    }
    let scaled = x * MICROS_PER_UNIT as f64;
    if scaled > MAX_SAFE_MICROS {
        return x;
    }
    let r = (scaled + 0.5).floor();
    let m = if r / MICROS_PER_UNIT as f64 == x || (scaled - r).abs() <= 1e-3 { r } else { scaled.ceil() };
    m / MICROS_PER_UNIT as f64
}

fn assert_split_policy(p: &Value) -> Result<(), String> {
    let mut total = 0.0;
    for k in ["challengerBps", "victimBps"] {
        let v = fin(p.get(k)).filter(|v| v.fract() == 0.0 && (0.0..=10_000.0).contains(v));
        total += v.ok_or_else(|| format!("slash split: {k} must be an integer in [0,10000]"))?;
    }
    if total > 10_000.0 {
        return Err("slash split: challengerBps + victimBps must not exceed 10000".into());
    }
    Ok(())
}

fn share_quantum(amount: f64) -> f64 {
    let ulp = f64::from_bits(amount.to_bits() + 1) - amount; // amount is positive and finite here
    if amount == amount.floor() {
        ulp.max(1.0)
    } else {
        ulp.max(MIN_SHARE_QUANTUM)
    }
}

/// The challenger / victim / treasury division of a slashed `amount`: exact (treasury = amount - challenger - victim). `dest` has
/// `challengerAccount` (a string, or an explicit `null` for an anonymous challenge, which pays the whole bond to the treasury),
/// `victimAccount` and `treasuryAccount`.
pub fn compute_slash_split(amount: f64, policy: &Value, dest: &Value) -> Result<Value, String> {
    if !amount.is_finite() || amount <= 0.0 {
        return Err("computeSlashSplit: amount must be a positive finite number".into());
    }
    assert_split_policy(policy)?;
    let acct = |k: &str| dest.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
    let victim = acct("victimAccount").ok_or("computeSlashSplit: victimAccount is required")?;
    let treasury = acct("treasuryAccount").ok_or("computeSlashSplit: treasuryAccount is required")?;
    let ch = dest.get("challengerAccount");
    let out = |c: Value, v: Value, t: Value, amt: Value| {
        let mut r = Map::new();
        r.insert("amount".into(), amt);
        r.insert("challengerReward".into(), c);
        r.insert("victimCompensation".into(), v);
        r.insert("treasuryRemainder".into(), t);
        if let Some(ch) = ch {
            r.insert("challengerAccount".into(), ch.clone());
        }
        r.insert("victimAccount".into(), json!(victim));
        r.insert("treasuryAccount".into(), json!(treasury));
        Value::Object(r)
    };
    if matches!(ch, Some(Value::Null)) {
        return Ok(out(num(0.0), num(0.0), num(amount), num(amount)));
    }
    let (cbps, vbps) = (fin(policy.get("challengerBps")).unwrap_or(0.0), fin(policy.get("victimBps")).unwrap_or(0.0));
    let micros = if amount == amount.floor() { None } else { to_micros(amount) }; // integer bonds keep whole-unit shares
    if let Some(m) = micros {
        let c = (m as i128 * cbps as i128 / 10_000) as i64;
        let v = (m as i128 * vbps as i128 / 10_000) as i64;
        let t = m - c - v;
        return Ok(out(num(from_micros(c)), num(from_micros(v)), num(from_micros(t)), num(from_micros(m))));
    }
    let q = share_quantum(amount);
    let share = |bps: f64| ((amount * bps) / 10_000.0 / q).floor() * q;
    let challenger = share(cbps).min(amount);
    let victim_comp = share(vbps).min(amount - challenger);
    Ok(out(num(challenger), num(victim_comp), num(amount - challenger - victim_comp), num(amount)))
}

// ---- bond sizing ----------------------------------------------------------------------------------------------------------------

/// The largest exponent of a power curve.
const POWER_CURVE_MAX_GAMMA: f64 = 64.0;

/// `e^gamma` for a gamma that is a multiple of 1/8, by exactly rounded IEEE operations only (no `pow`, which is not correctly rounded
/// and differs between libm implementations): `e` multiplied in floor(n/8) times, then by sqrt(e), sqrt(sqrt(e)) and
/// sqrt(sqrt(sqrt(e))) for the set bits 4, 2, 1 of n mod 8 (n = gamma * 8), in that order, one multiplication at a time and never fused.
pub(crate) fn pow_eighths(e: f64, gamma: f64) -> Result<f64, String> {
    let n = gamma * 8.0;
    if !(n.is_finite() && n.fract() == 0.0 && gamma <= POWER_CURVE_MAX_GAMMA) {
        return Err("bondAmount: power curve gamma must be a multiple of 1/8 and at most 64".into());
    }
    let mut r = 1.0f64;
    for _ in 0..(n / 8.0).floor() as u32 {
        r *= e;
    }
    let f = (n % 8.0) as u32;
    let s1 = e.sqrt();
    let s2 = s1.sqrt();
    let s3 = s2.sqrt();
    if f & 4 != 0 {
        r *= s1;
    }
    if f & 2 != 0 {
        r *= s2;
    }
    if f & 1 != 0 {
        r *= s3;
    }
    Ok(r)
}

fn curve_component(curve: Option<&Value>, k: f64, e: f64) -> Result<f64, String> {
    let curve = match curve.filter(|c| !c.is_null()) {
        None => return Ok(k * e),
        Some(c) => c,
    };
    let kind = curve.get("kind").and_then(Value::as_str);
    if kind == Some("linear") {
        return Ok(k * e);
    }
    if kind == Some("power") {
        let g = fin(curve.get("gamma")).filter(|g| *g >= 1.0).ok_or("bondAmount: power curve requires finite gamma >= 1")?;
        return Ok(k * pow_eighths(e, g)?);
    }
    let tiers = curve.get("tiers").and_then(Value::as_array).filter(|t| !t.is_empty()).ok_or("bondAmount: piecewise curve requires at least one tier")?;
    let (mut acc, mut prev_up, mut prev_marginal) = (0.0f64, 0.0f64, 0.0f64);
    for tier in tiers {
        if !tier.is_object() {
            return Err("bondAmount: malformed tier".into());
        }
        let up_to = tier.get("upTo").and_then(Value::as_f64).unwrap_or(f64::NAN);
        let up_to = if tier.get("upTo").is_some_and(Value::is_null) { f64::INFINITY } else { up_to }; // Infinity travels as null
        if !((up_to.is_finite() && up_to > prev_up) || up_to == f64::INFINITY) {
            return Err("bondAmount: piecewise tier `upTo` must be strictly increasing".into());
        }
        let mk = fin(tier.get("marginalK")).filter(|m| *m >= 0.0).ok_or("bondAmount: piecewise `marginalK` must be a finite number >= 0")?;
        if mk < prev_marginal {
            return Err("bondAmount: piecewise marginal rates must be non-decreasing (convex)".into());
        }
        let width = e.min(up_to) - prev_up;
        if width > 0.0 {
            acc += width * mk;
        }
        prev_up = up_to;
        prev_marginal = mk;
        if e <= up_to {
            break;
        }
    }
    if e > prev_up {
        acc += (e - prev_up) * prev_marginal;
    }
    Ok(k * acc)
}

/// `max(floor, curve(k, exposure))` snapped up onto the micro grid; no curve = linear. A non-finite or non-positive exposure gives the floor.
pub fn bond_amount(policy: &Value, exposure: Option<f64>) -> Result<f64, String> {
    let e = exposure.filter(|x| x.is_finite() && *x > 0.0).unwrap_or(0.0);
    let floor = fin(policy.get("floor")).unwrap_or(f64::NAN);
    let k = fin(policy.get("k")).unwrap_or(f64::NAN);
    Ok(quantize_up(floor.max(curve_component(policy.get("curve"), k, e)?)))
}

// ---- evidence digests and anchoring -----------------------------------------------------------------------------------------------

fn claim_identity(claim: &Value) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("claimDigest".into(), claim.get("pcactn_digest").cloned().unwrap_or(Value::Null));
    m.insert("bond_ref".into(), claim.get("bond_ref").cloned().unwrap_or(Value::Null));
    m
}

fn with(mut m: Map<String, Value>, src: &Value, keys: &[&str]) -> Value {
    for k in keys {
        m.insert((*k).into(), src.get(*k).cloned().unwrap_or(Value::Null));
    }
    Value::Object(m)
}

/// Binds a slash to the server-derived fraud verdict (`fraudulent`, `slashBondRef`, `reason`).
pub fn settlement_evidence_digest(claim: &Value, fraud_verdict: &Value) -> String {
    hash_canonical(&with(claim_identity(claim), fraud_verdict, &["fraudulent", "slashBondRef", "reason"]))
}

/// Evidence digest of a revocation slash (a capability in the claim's chain was revoked after the bond opened).
pub fn revocation_evidence_digest(claim: &Value, revoked_cap_id: &str) -> String {
    let mut m = claim_identity(claim);
    m.insert("kind".into(), json!("revocation"));
    m.insert("revokedCapId".into(), json!(revoked_cap_id));
    hash_canonical(&Value::Object(m))
}

/// Evidence digest of a dispute-game slash: the adjudicator's own verdict, never a challenger assertion.
pub fn dispute_evidence_digest(claim: &Value, verdict: &Value) -> String {
    let mut m = claim_identity(claim);
    m.insert("kind".into(), json!("dispute"));
    hash_canonical(&with(m, verdict, &["outcome", "input", "agentValue", "oracleValue", "slashBondRef", "reason"]))
}

/// Verify a settlement record's signature under the guardian public key; suite-agile (a PQ half needs its pin in `pins`,
/// `{ed25519 b64u: PQ public key}`). Never panics.
pub fn verify_settlement(record: &Value, guardian_public: &str, pins: Option<&Value>) -> bool {
    crate::optimistic::settlement_wire_check_pinned(record, guardian_public, pins) == "ok"
}

/// Canonical digest of a signed settlement record (the whole record, signature included).
pub fn settlement_record_digest(record: &Value) -> String {
    hash_canonical(&json!({"t": SETTLEMENT_LEAF_DOMAIN, "record": record}))
}

/// The salted commitment of a settlement record (the opaque transparency-log leaf).
pub fn settlement_commit(salt: &str, record: &Value) -> Result<String, String> {
    if salt.is_empty() {
        return Err("settlementCommit: salt must be a non-empty string".into());
    }
    Ok(hash_canonical(&json!({"salt": salt, "settlement_digest": settlement_record_digest(record)})))
}

/// True iff `salt` + `record` reproduce the anchored `commit`.
pub fn verify_settlement_commit(commit: &str, salt: &str, record: &Value) -> bool {
    settlement_commit(salt, record).is_ok_and(|c| c == commit)
}

/// Append a settlement record as a salted commitment through `append` (a transparency log's append of a commitment string, returning
/// its index); returns `{index, commit, salt}`. A `None` salt draws 16 random bytes.
pub fn append_settlement(append: &mut dyn FnMut(&str) -> Result<u64, String>, record: &Value, salt: Option<&str>) -> Result<Value, String> {
    let salt = match salt {
        Some(s) => s.to_string(),
        None => {
            let mut b = [0u8; 16];
            getrandom::getrandom(&mut b).map_err(|e| format!("appendSettlement: {e}"))?;
            crate::b64_encode(&b)
        }
    };
    let commit = settlement_commit(&salt, record)?;
    let index = append(&commit)?;
    Ok(json!({"index": index, "commit": commit, "salt": salt}))
}

// ---- the planner ------------------------------------------------------------------------------------------------------------------

/// What a planner reads to decide a transition: the bond (if it is the one asked for), balances, and the depositor's open totals.
#[derive(Clone, Debug, Default)]
pub struct BondView {
    pub bond: Option<Value>,
    pub balances: Vec<(String, f64)>,
    pub open_count: f64,
    pub open_sum: f64,
}

impl BondView {
    /// The view of a store `read` snapshot `{bond?, balances, openTotals, highWater}`.
    pub fn from_snapshot(snap: &Value) -> BondView {
        let balances = snap
            .get("balances")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|e| Some((e.get(0)?.as_str()?.to_string(), e.get(1)?.as_f64()?))).collect())
            .unwrap_or_default();
        BondView {
            bond: snap.get("bond").cloned(),
            balances,
            open_count: fin(snap.get("openTotals").and_then(|t| t.get("count"))).unwrap_or(0.0),
            open_sum: fin(snap.get("openTotals").and_then(|t| t.get("sum"))).unwrap_or(0.0),
        }
    }
    pub fn bond(&self, claim_id: &str) -> Option<&Value> {
        self.bond.as_ref().filter(|b| b.get("claimId").and_then(Value::as_str) == Some(claim_id))
    }
    pub fn balance_of(&self, account: &str) -> f64 {
        self.balances.iter().find(|(a, _)| a == account).map_or(0.0, |(_, v)| *v)
    }
}

fn mv(account: &str, op: &str, amount: f64) -> Value {
    json!({"account": account, "op": op, "amount": num(amount)})
}

fn need_treasury(p: &Value, who: &str) -> Result<String, String> {
    p.get("treasury").and_then(Value::as_str).filter(|t| !t.is_empty()).map(str::to_string).ok_or_else(|| format!("{who}: treasury is required"))
}

/// The pure half of bond settlement. A plan is `{claimId, expect, next, open?, moves, record}` (see [`crate::bond_store`]).
pub struct BondSettlementPlanner {
    guardian: KeyPair,
    epoch: Option<i64>,
    alg: Option<String>,
    pq: Option<PqKeyPair>,
    /// The guardian/settlement public key (b64u): hand this to verifiers of the signed records.
    pub guardian_public_key: String,
    pub escrow: String,
    pub bond_policy: Value,
    pub slash_split_policy: Value,
}

impl BondSettlementPlanner {
    pub fn new(
        guardian: KeyPair,
        guardian_epoch: Option<i64>,
        alg: Option<String>,
        pq: Option<PqKeyPair>,
        escrow_account: Option<&str>,
        bond_policy: Option<Value>,
        slash_split_policy: Option<Value>,
    ) -> Result<Self, String> {
        if guardian_epoch.is_some_and(|e| !(0..=9_007_199_254_740_991).contains(&e)) {
            return Err("BondLedger: guardianEpoch must be a non-negative safe integer".into());
        }
        if let Some(a) = alg.as_deref() {
            crate::intent_suite::suite_of(Some(&json!(a))).map_err(|_| format!("BondLedger: unknown signature alg '{a}'"))?;
        }
        Ok(BondSettlementPlanner {
            guardian_public_key: guardian.public.clone(),
            guardian,
            epoch: guardian_epoch,
            alg,
            pq,
            escrow: escrow_account.filter(|e| !e.is_empty()).unwrap_or(ESCROW_ACCOUNT).to_string(),
            bond_policy: bond_policy.unwrap_or_else(default_bond_policy),
            slash_split_policy: slash_split_policy.unwrap_or_else(default_slash_split_policy),
        })
    }

    fn sign(&self, mut base: Map<String, Value>) -> Result<Value, String> {
        if let Some(e) = self.epoch {
            base.insert("guardian_epoch".into(), json!(e));
        }
        let suite = Suite { alg: self.alg.as_deref(), pq: self.pq.as_ref() };
        if self.alg.as_deref().is_some_and(|a| a != "ed25519") {
            let pq = self.pq.as_ref().ok_or("a post-quantum suite needs a key pair")?;
            base.insert("alg".into(), json!(self.alg));
            base.insert("pq_pk".into(), json!(pq.public));
        }
        let mut msg = SETTLEMENT_DOMAIN.as_bytes().to_vec();
        msg.extend(canonicalize(&Value::Object(base.clone())).into_bytes());
        let (sig, pq_sig) = sign_with_suite(&suite, Some(&self.guardian), &msg)?;
        base.insert("sig".into(), json!(sig));
        if let Some(p) = pq_sig {
            base.insert("pq_sig".into(), json!(p));
        }
        Ok(Value::Object(base))
    }

    fn base(claim_id: &str, action: &str, amount: f64, from: &str, to: &str, at: f64, evidence: &str) -> Map<String, Value> {
        let mut m = Map::new();
        for (k, v) in [
            ("claimId", json!(claim_id)),
            ("action", json!(action)),
            ("amount", num(amount)),
            ("from", json!(from)),
            ("to", json!(to)),
            ("at", num(at)),
            ("evidenceDigest", json!(evidence)),
        ] {
            m.insert(k.into(), v);
        }
        m
    }

    fn plan(claim_id: &str, expect: &str, next: &str, moves: Vec<Value>, record: Value) -> Value {
        json!({"claimId": claim_id, "expect": expect, "next": next, "moves": moves, "record": record})
    }

    fn open_bond<'a>(view: &'a BondView, who: &str, claim_id: &str) -> Result<&'a Value, String> {
        let bond = view.bond(claim_id).ok_or_else(|| format!("{who}: no bond for {claim_id}"))?;
        let status = bond.get("status").and_then(Value::as_str).unwrap_or("");
        if status != "open" {
            return Err(format!("{who}: bond {claim_id} is already {status} (double-settle refused)"));
        }
        Ok(bond)
    }

    fn slash_plan(&self, bond: &Value, claim_id: &str, now: f64, evidence: &str, p: &Value) -> Result<Value, String> {
        let treasury = p.get("treasury").and_then(Value::as_str).unwrap_or_default();
        let amount = fin(bond.get("amount")).ok_or("slash: the bond has no amount")?;
        let policy = p.get("splitPolicy").filter(|s| s.is_object()).unwrap_or(&self.slash_split_policy);
        let victim = p.get("compensationAccount").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or(COMPENSATION_POOL_ACCOUNT);
        let mut dest = json!({"victimAccount": victim, "treasuryAccount": treasury});
        dest["challengerAccount"] = p.get("challengerAccount").cloned().unwrap_or(Value::Null);
        let split = compute_slash_split(amount, policy, &dest)?;
        let mut moves = vec![mv(&self.escrow, "debit", amount)]; // the full bond leaves escrow
        let part = |k: &str| fin(split.get(k)).unwrap_or(0.0);
        if let Some(c) = split.get("challengerAccount").and_then(Value::as_str).filter(|c| !c.is_empty() && part("challengerReward") > 0.0) {
            moves.push(mv(c, "credit", part("challengerReward")));
        }
        if part("victimCompensation") > 0.0 {
            moves.push(mv(split["victimAccount"].as_str().unwrap_or_default(), "credit", part("victimCompensation")));
        }
        if part("treasuryRemainder") > 0.0 {
            moves.push(mv(split["treasuryAccount"].as_str().unwrap_or_default(), "credit", part("treasuryRemainder")));
        }
        let mut b = Self::base(claim_id, "slash", amount, &self.escrow, treasury, now, evidence);
        b.insert("split".into(), split);
        Ok(Self::plan(claim_id, "open", "slashed", moves, self.sign(b)?))
    }

    /// Open (lock) a bond: refuses an unaffordable bond, one below `bond_amount(policy, exposure)`, one that breaches the depositor's caps
    /// and a double-open. The bond moves from the depositor into escrow.
    pub fn plan_open(
        &self,
        view: &BondView,
        claim_id: &str,
        amount: f64,
        depositor: &str,
        exposure: Option<f64>,
        now: f64,
        window: Option<&Value>,
    ) -> Result<Value, String> {
        if claim_id.is_empty() {
            return Err("openBond: claimId is required".into());
        }
        if !amount.is_finite() || amount <= 0.0 {
            return Err("openBond: amount must be a positive finite number".into());
        }
        if depositor.is_empty() {
            return Err("openBond: depositor is required".into());
        }
        if view.bond(claim_id).is_some() {
            return Err(format!("openBond: bond {claim_id} already exists (double-open refused)"));
        }
        let required = bond_amount(&self.bond_policy, exposure)?;
        if !(amount >= required) {
            return Err(format!(
                "openBond: amount {} is below the required bond {}",
                crate::intent_v2::js_number_string(amount),
                crate::intent_v2::js_number_string(required)
            ));
        }
        let max_claims = fin(self.bond_policy.get("maxOpenClaims")).unwrap_or(f64::NAN);
        let max_amount = max_open_amount(&self.bond_policy);
        if !(view.open_count.is_finite() && view.open_count + 1.0 <= max_claims) {
            return Err("openBond: depositor open-claim cap reached".into());
        }
        if !((view.open_sum + amount).is_finite() && view.open_sum + amount <= max_amount) {
            return Err("openBond: depositor aggregate open-bond cap exceeded".into());
        }
        if !(view.balance_of(depositor).is_finite() && view.balance_of(depositor) >= amount) {
            return Err("openBond: insufficient balance for the bond".into());
        }
        let record = self.sign(Self::base(claim_id, "open", amount, depositor, &self.escrow, now, ""))?;
        let mut open = json!({"amount": num(amount), "depositor": depositor, "maxOpenClaims": num(max_claims), "maxOpenAmount": max_amount});
        if let Some(w) = window {
            open["window"] = w.clone();
        }
        let mut plan = Self::plan(claim_id, "none", "open", vec![mv(depositor, "debit", amount), mv(&self.escrow, "credit", amount)], record);
        plan["open"] = open;
        Ok(plan)
    }

    /// Release a bond back to its depositor after an unchallenged window; refuses a missing or already settled bond.
    pub fn plan_release(&self, view: &BondView, claim_id: &str, now: f64) -> Result<Value, String> {
        let bond = view.bond(claim_id).ok_or_else(|| format!("releaseBond: no bond for {claim_id}"))?;
        let status = bond.get("status").and_then(Value::as_str).unwrap_or("");
        if status != "open" {
            return Err(format!("releaseBond: bond {claim_id} is already {status} (double-settle refused)"));
        }
        let amount = fin(bond.get("amount")).ok_or("releaseBond: the bond has no amount")?;
        let depositor = bond.get("depositor").and_then(Value::as_str).unwrap_or_default();
        let record = self.sign(Self::base(claim_id, "release", amount, &self.escrow, depositor, now, ""))?;
        Ok(Self::plan(claim_id, "open", "released", vec![mv(&self.escrow, "debit", amount), mv(depositor, "credit", amount)], record))
    }

    /// Slash against a VERIFIED fraud verdict; re-runs the Policy VM itself. `p`: `claimId`, `claim`, `fraudProof`, `grant`,
    /// `openSnapshot`, `treasury`, and optionally `challengerAccount`, `compensationAccount`, `splitPolicy`.
    pub fn plan_slash(&self, view: &BondView, p: &Value, now: f64, decide: Option<DecideFn>) -> Result<Value, String> {
        let claim_id = p.get("claimId").and_then(Value::as_str).unwrap_or_default();
        let claim = p.get("claim").unwrap_or(&NULL);
        let bond = Self::open_bond(view, "slashBond", claim_id)?;
        need_treasury(p, "slashBond")?;
        if claim.get("bond_ref").and_then(Value::as_str) != Some(claim_id) {
            return Err("slashBond: claim.bond_ref does not match claimId".into());
        }
        let null = Value::Null;
        let verdict = verify_fraud_proof(claim, p.get("fraudProof").unwrap_or(&null), p.get("grant").unwrap_or(&null), p.get("openSnapshot").unwrap_or(&null), decide);
        if verdict.get("fraudulent") != Some(&json!(true)) || verdict.get("slashBondRef").and_then(Value::as_str) != Some(claim_id) {
            return Err(format!(
                "slashBond: refused \u{2014} no verified fraud verdict slashing {claim_id} ({})",
                verdict.get("reason").and_then(Value::as_str).unwrap_or("undefined")
            ));
        }
        self.slash_plan(bond, claim_id, now, &settlement_evidence_digest(claim, &verdict), p)
    }

    /// Slash because a capability in the claim's chain was revoked after the bond opened (server-derived evidence). `p` adds `revokedCapId`.
    pub fn plan_slash_on_revocation(&self, view: &BondView, p: &Value, now: f64) -> Result<Value, String> {
        let claim_id = p.get("claimId").and_then(Value::as_str).unwrap_or_default();
        let claim = p.get("claim").unwrap_or(&NULL);
        let bond = Self::open_bond(view, "slashBondOnRevocation", claim_id)?;
        need_treasury(p, "slashBondOnRevocation")?;
        if claim.get("bond_ref").and_then(Value::as_str) != Some(claim_id) {
            return Err("slashBondOnRevocation: claim.bond_ref does not match claimId".into());
        }
        let revoked = p.get("revokedCapId").and_then(Value::as_str).filter(|r| !r.is_empty()).ok_or("slashBondOnRevocation: revokedCapId is required")?;
        self.slash_plan(bond, claim_id, now, &revocation_evidence_digest(claim, revoked), p)
    }

    /// Slash the AGENT's bond because a dispute proved it understated a risk input; re-runs the adjudication itself. `p` adds `dispute`,
    /// `rMargin?` (the objective oracle is the `oracle` argument).
    pub fn plan_slash_on_dispute(&self, view: &BondView, p: &Value, now: f64, oracle: Option<OracleFn>, decide: Option<DecideFn>) -> Result<Value, String> {
        let claim_id = p.get("claimId").and_then(Value::as_str).unwrap_or_default();
        let claim = p.get("claim").unwrap_or(&NULL);
        let bond = Self::open_bond(view, "slashBondOnDispute", claim_id)?;
        need_treasury(p, "slashBondOnDispute")?;
        if claim.get("bond_ref").and_then(Value::as_str) != Some(claim_id) {
            return Err("slashBondOnDispute: claim.bond_ref does not match claimId".into());
        }
        let null = Value::Null;
        let v = adjudicate_dispute(
            claim,
            p.get("dispute").unwrap_or(&null),
            p.get("grant").unwrap_or(&null),
            p.get("openSnapshot").unwrap_or(&null),
            oracle,
            fin(p.get("rMargin")),
            decide,
        );
        if v.get("outcome").and_then(Value::as_str) != Some("agent-fraud")
            || v.get("fraudulent") != Some(&json!(true))
            || v.get("slashBondRef").and_then(Value::as_str) != Some(claim_id)
        {
            return Err(format!(
                "slashBondOnDispute: refused \u{2014} no verified agent-fraud verdict slashing {claim_id} ({}: {})",
                v.get("outcome").and_then(Value::as_str).unwrap_or("undefined"),
                v.get("reason").and_then(Value::as_str).unwrap_or("undefined")
            ));
        }
        self.slash_plan(bond, claim_id, now, &dispute_evidence_digest(claim, &v), p)
    }

    /// Slash the CHALLENGER's counter-bond because the dispute was frivolous (anti-griefing); an anonymous slash, 100% to the treasury.
    pub fn plan_slash_counter_bond(&self, view: &BondView, p: &Value, now: f64, oracle: Option<OracleFn>, decide: Option<DecideFn>) -> Result<Value, String> {
        let cid = p.get("counterBondId").and_then(Value::as_str).unwrap_or_default();
        let claim = p.get("claim").unwrap_or(&NULL);
        let bond = view.bond(cid).ok_or_else(|| format!("slashCounterBond: no counter-bond for {cid}"))?;
        let status = bond.get("status").and_then(Value::as_str).unwrap_or("");
        if status != "open" {
            return Err(format!("slashCounterBond: counter-bond {cid} is already {status} (double-settle refused)"));
        }
        let treasury = need_treasury(p, "slashCounterBond")?;
        let null = Value::Null;
        let v = adjudicate_dispute(
            claim,
            p.get("dispute").unwrap_or(&null),
            p.get("grant").unwrap_or(&null),
            p.get("openSnapshot").unwrap_or(&null),
            oracle,
            fin(p.get("rMargin")),
            decide,
        );
        if v.get("outcome").and_then(Value::as_str) != Some("claim-upheld") || v.get("slashCounterBond") != Some(&json!(true)) {
            return Err(format!(
                "slashCounterBond: refused \u{2014} the dispute is not frivolous ({}: {})",
                v.get("outcome").and_then(Value::as_str).unwrap_or("undefined"),
                v.get("reason").and_then(Value::as_str).unwrap_or("undefined")
            ));
        }
        let mut sp = json!({"treasury": treasury, "challengerAccount": Value::Null});
        for k in ["compensationAccount", "splitPolicy"] {
            if let Some(x) = p.get(k) {
                sp[k] = x.clone();
            }
        }
        self.slash_plan(bond, cid, now, &dispute_evidence_digest(claim, &v), &sp)
    }
}

/// Apply `moves` to a balance lookup in order; `Err` (applying nothing) on an invalid amount or an overdraft.
pub fn apply_moves(balance_of: &dyn Fn(&str) -> f64, moves: &[Value]) -> Result<Map<String, Value>, String> {
    apply_bond_moves(balance_of, moves)
}

/// `a + sign*b` in exact micro-unit integers when both are micro-grid amounts; plain float otherwise.
pub fn exact_add_amounts(a: f64, b: f64, sign: i64) -> f64 {
    exact_add(a, b, sign)
}

// ---- the durable ledger -----------------------------------------------------------------------------------------------------------

fn e(code: &str, msg: impl AsRef<str>) -> CodedError {
    CodedError::new(code, msg)
}

fn plan_err(m: String) -> CodedError {
    CodedError::new("Error", m)
}

fn ends_at(w: &Value) -> f64 {
    fin(w.get("registeredAt")).unwrap_or(f64::NAN) + fin(w.get("windowMs")).unwrap_or(f64::NAN)
}

/// Durable, restart-safe bond settlement over a [`BondStore`]. Every method is idempotent under retry: repeating a transition that already
/// committed returns the stored record and moves nothing, while a conflicting transition (a release after a slash, a second slash with
/// different evidence) fails. Failures are [`CodedError`]s: `store_missing`, `guardian_key_missing`, `clock_invalid`, `store_unavailable`,
/// `store_corrupt`, `invalid_claim`, `window_open`, `window_closed`, `unregistered`, `claim_mismatch` or `conflict`; a planner refusal
/// keeps its own message under the code `Error`.
pub struct StoreBondLedger {
    store: Arc<dyn BondStore>,
    planner: BondSettlementPlanner,
    clock: Box<dyn Fn() -> f64 + Send + Sync>,
    wp: WindowPolicy,
}

impl StoreBondLedger {
    pub fn new(
        store: Arc<dyn BondStore>,
        planner: BondSettlementPlanner,
        clock: Option<Box<dyn Fn() -> f64 + Send + Sync>>,
        window_policy: Option<WindowPolicy>,
    ) -> Self {
        let clock = clock.unwrap_or_else(|| Box::new(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as f64).unwrap_or(0.0)));
        StoreBondLedger { store, planner, clock, wp: window_policy.unwrap_or(DEFAULT_WINDOW_POLICY) }
    }

    pub fn guardian_public_key(&self) -> &str {
        &self.planner.guardian_public_key
    }

    fn load(&self, claim_id: &str, depositor: Option<&str>) -> R<(Value, BondView, f64)> {
        let snap = self.store.read(claim_id, depositor)?;
        let t = (self.clock)();
        if !t.is_finite() {
            return Err(e("clock_invalid", "the clock returned a non-finite time"));
        }
        let view = BondView::from_snapshot(&snap);
        let now = t.max(fin(snap.get("highWater")).unwrap_or(0.0));
        Ok((snap, view, now))
    }

    fn submit(&self, plan: &Value, now: f64) -> R<Value> {
        let out = self.store.commit(plan, &num(now))?;
        if out["outcome"] == "conflict" {
            return Err(e("conflict", out["reason"].as_str().unwrap_or("conflict")));
        }
        Ok(out["record"].clone())
    }

    fn settle(&self, claim_id: &str, plan: &dyn Fn(&BondView, f64) -> Result<Value, String>, gate: Option<&dyn Fn(&Value, f64) -> R<()>>) -> R<Value> {
        let (snap, view, now) = self.load(claim_id, None)?;
        if let Some(bond) = snap.get("bond").filter(|b| !b.is_null()) {
            if bond["status"].as_str() != Some("open") {
                let last = bond["records"].as_array().and_then(|r| r.last()).cloned();
                let mut as_open = view.clone();
                if let Some(b) = as_open.bond.as_mut() {
                    b["status"] = json!("open");
                }
                let again = plan(&as_open, now).map_err(plan_err)?; // fails if the evidence no longer holds
                if let Some(last) = last.filter(|l| same_settlement(l, &again["record"])) {
                    return Ok(last);
                }
                return plan(&view, now).map(|p| p["record"].clone()).map_err(plan_err);
                // the standard double-settle refusal
            }
            if let Some(g) = gate {
                g(bond, now)?;
            }
        }
        let p = plan(&view, now).map_err(plan_err)?;
        self.submit(&p, now)
    }

    /// Top up an account of the internal books (a positive finite amount).
    pub fn deposit(&self, account: &str, amount: f64) -> R<f64> {
        // the ledger guards every store call: an error that is not a store error (the store's own RangeError for a bad account or amount)
        // surfaces as `store_unavailable`
        self.store.deposit(&json!(account), &json!(amount)).map_err(|e| if e.is_range() { CodedError::new("store_unavailable", e.message) } else { e })
    }

    pub fn balance_of(&self, account: &str) -> R<f64> {
        let snap = self.store.read("", Some(account))?;
        Ok(snap["balances"].as_array().and_then(|b| b.first()).and_then(|b| b.get(1)).and_then(Value::as_f64).unwrap_or(0.0))
    }

    /// `none`, `open`, `released` or `slashed`.
    pub fn bond_status(&self, claim_id: &str) -> R<String> {
        let snap = self.store.read(claim_id, None)?;
        Ok(snap.get("bond").and_then(|b| b.get("status")).and_then(Value::as_str).unwrap_or("none").to_string())
    }

    pub fn get_bond(&self, claim_id: &str) -> R<Option<Value>> {
        Ok(self.store.read(claim_id, None)?.get("bond").cloned())
    }

    /// Where the claim's challenge window stands on the ledger's clock; `unregistered` for a bond with no claim.
    pub fn challenge_status(&self, claim_id: &str) -> R<Value> {
        let (snap, _, now) = self.load(claim_id, None)?;
        let w = snap
            .get("bond")
            .and_then(|b| b.get("window"))
            .filter(|w| w.is_object())
            .ok_or_else(|| e("unregistered", format!("bond {claim_id} has no registered claim")))?;
        let ends = ends_at(w);
        Ok(json!({"phase": if now > ends { "finalized" } else { "open" }, "endsAt": num(ends), "now": num(now)}))
    }

    fn replay_open(prior: &Value, depositor: &str, amount: f64, window: Option<&Value>) -> R<Value> {
        let same = prior["depositor"].as_str() == Some(depositor)
            && fin(prior.get("amount")) == Some(amount)
            && prior.get("window").and_then(|w| w.get("claimDigest")) == window.and_then(|w| w.get("claimDigest"));
        match prior["records"].as_array().and_then(|r| r.first()) {
            Some(first) if same => Ok(first.clone()),
            _ => Err(e("conflict", format!("openBond: bond {} already exists (double-open refused)", prior["claimId"].as_str().unwrap_or_default()))),
        }
    }

    /// Register an optimistic claim and lock its bond in one atomic commit. The claim must pass the claim check against the ledger's
    /// clock and its window must be at least the realistic floor; the window then runs from the ledger's own `registeredAt`.
    pub fn open_claim(&self, claim: &Value, pcactn: &Value, signer_public: &str, amount: f64, depositor: &str, exposure: Option<f64>) -> R<Value> {
        let bond_ref = claim.get("bond_ref").and_then(Value::as_str).unwrap_or_default();
        let (snap, view, now) = self.load(if bond_ref.is_empty() { "None" } else { bond_ref }, Some(depositor))?;
        let digest = crate::hash_canonical_strict(pcactn).ok_or_else(|| e("invalid_claim", "malformed claim"))?;
        let check = claim_check(claim, &digest, signer_public, now, &self.wp);
        if check != "ok" {
            let reason = match check {
                "malformed" => Some("malformed claim".to_string()),
                "irreversible" => Some("irreversible action is ineligible for the optimistic path".to_string()),
                "digest" => Some("claim does not cover this PCActn".to_string()),
                "claimed_r" => Some("claimed_r is not finite".to_string()),
                "signature" => Some("claim signature does not verify".to_string()),
                "window" => validate_window(fin(claim.get("issued_at")).unwrap_or(f64::NAN), fin(claim.get("challenge_window_ms")).unwrap_or(f64::NAN), now, &self.wp)
                    .map(str::to_string),
                _ => None,
            };
            return Err(e("invalid_claim", reason.unwrap_or_else(|| check.to_string())));
        }
        let window_ms = fin(claim.get("challenge_window_ms")).unwrap_or(f64::NAN);
        let floor = self.wp.min_window_ms.max(DEFAULT_MIN_CHALLENGE_WINDOW_MS);
        if window_ms < floor {
            return Err(e(
                "invalid_claim",
                format!("challenge window {} ms is below the {} ms floor", crate::intent_v2::js_number_string(window_ms), crate::intent_v2::js_number_string(floor)),
            ));
        }
        if bond_ref.is_empty() {
            return Err(e("invalid_claim", "claim has no bond_ref"));
        }
        let window = json!({"registeredAt": num(now), "windowMs": num(window_ms), "claimDigest": hash_canonical(claim)});
        if let Some(prior) = snap.get("bond").filter(|b| !b.is_null()) {
            return Self::replay_open(prior, depositor, amount, Some(&window));
        }
        let plan = self.planner.plan_open(&view, bond_ref, amount, depositor, exposure, now, Some(&window)).map_err(plan_err)?;
        self.submit(&plan, now)
    }

    /// Open a bond that backs no claim (a challenger's counter-bond). It has no window; settle it with [`Self::slash_counter_bond`] or
    /// [`Self::release_unregistered`].
    pub fn open_bond(&self, claim_id: &str, amount: f64, depositor: &str, exposure: Option<f64>) -> R<Value> {
        let (snap, view, now) = self.load(claim_id, Some(depositor))?;
        if let Some(prior) = snap.get("bond").filter(|b| !b.is_null()) {
            return Self::replay_open(prior, depositor, amount, None);
        }
        let plan = self.planner.plan_open(&view, claim_id, amount, depositor, exposure, now, None).map_err(plan_err)?;
        self.submit(&plan, now)
    }

    /// Release a registered claim's bond once its challenge window has closed on the ledger's clock.
    pub fn release(&self, claim_id: &str) -> R<Value> {
        let gate = |bond: &Value, now: f64| -> R<()> {
            let w = bond
                .get("window")
                .filter(|w| w.is_object())
                .ok_or_else(|| e("unregistered", format!("bond {claim_id} has no registered claim; use release_unregistered for a counter-bond")))?;
            if !(now.is_finite() && now > ends_at(w)) {
                return Err(e("window_open", format!("the challenge window of {claim_id} closes at {}", crate::intent_v2::js_number_string(ends_at(w)))));
            }
            Ok(())
        };
        self.settle(claim_id, &|v, n| self.planner.plan_release(v, claim_id, n), Some(&gate))
    }

    /// Release a bond that backs no claim (a counter-bond).
    pub fn release_unregistered(&self, claim_id: &str) -> R<Value> {
        let gate = |bond: &Value, _now: f64| -> R<()> {
            if bond.get("window").is_some_and(|w| !w.is_null()) {
                return Err(e("conflict", format!("bond {claim_id} backs a registered claim; use release")));
            }
            Ok(())
        };
        self.settle(claim_id, &|v, n| self.planner.plan_release(v, claim_id, n), Some(&gate))
    }

    fn challenge_gate<'a>(claim: &'a Value) -> impl Fn(&Value, f64) -> R<()> + 'a {
        move |bond: &Value, now: f64| {
            let id = bond["claimId"].as_str().unwrap_or_default();
            let w = bond.get("window").filter(|w| w.is_object()).ok_or_else(|| e("unregistered", format!("bond {id} has no registered claim")))?;
            if w.get("claimDigest").and_then(Value::as_str) != Some(hash_canonical(claim).as_str()) {
                return Err(e("claim_mismatch", format!("the claim is not the one registered for {id}")));
            }
            if !(now.is_finite() && now <= ends_at(w)) {
                return Err(e("window_closed", format!("the challenge window of {id} closed at {}", crate::intent_v2::js_number_string(ends_at(w)))));
            }
            Ok(())
        }
    }

    /// Slash on a fraud proof the ledger re-verifies itself, inside the challenge window. `p` as in [`BondSettlementPlanner::plan_slash`].
    pub fn slash_bond(&self, p: &Value, decide: Option<DecideFn>) -> R<Value> {
        let gate = Self::challenge_gate(p.get("claim").unwrap_or(&NULL));
        self.settle(p.get("claimId").and_then(Value::as_str).unwrap_or_default(), &|v, n| self.planner.plan_slash(v, p, n, decide), Some(&gate))
    }

    /// Slash on a dispute the ledger re-adjudicates itself, inside the challenge window.
    pub fn slash_bond_on_dispute(&self, p: &Value, oracle: Option<OracleFn>, decide: Option<DecideFn>) -> R<Value> {
        let gate = Self::challenge_gate(p.get("claim").unwrap_or(&NULL));
        self.settle(p.get("claimId").and_then(Value::as_str).unwrap_or_default(), &|v, n| self.planner.plan_slash_on_dispute(v, p, n, oracle, decide), Some(&gate))
    }

    /// Slash because a capability in the claim's chain was revoked (server-derived evidence; not window-gated).
    pub fn slash_bond_on_revocation(&self, p: &Value) -> R<Value> {
        let claim = p.get("claim").unwrap_or(&NULL);
        let gate = |bond: &Value, _now: f64| -> R<()> {
            if bond.get("window").filter(|w| w.is_object()).is_some_and(|w| w.get("claimDigest").and_then(Value::as_str) != Some(hash_canonical(claim).as_str())) {
                return Err(e("claim_mismatch", format!("the claim is not the one registered for {}", bond["claimId"].as_str().unwrap_or_default())));
            }
            Ok(())
        };
        self.settle(p.get("claimId").and_then(Value::as_str).unwrap_or_default(), &|v, n| self.planner.plan_slash_on_revocation(v, p, n), Some(&gate))
    }

    /// Slash a challenger's counter-bond after a frivolous dispute.
    pub fn slash_counter_bond(&self, p: &Value, oracle: Option<OracleFn>, decide: Option<DecideFn>) -> R<Value> {
        self.settle(p.get("counterBondId").and_then(Value::as_str).unwrap_or_default(), &|v, n| self.planner.plan_slash_counter_bond(v, p, n, oracle, decide), None)
    }
}

// ---- the insurance capital pool -----------------------------------------------------------------------------------------------

/// A finite, fail-closed insurance capital pool. Premiums (priced by [`crate::reputation::price_coverage`]) are credited; victim
/// payouts are debited and refused when they exceed the pool's free capital. Every amount is checked finite and non-negative,
/// and the ledgers always reconcile: `initial + premiumsIn - payoutsOut == balance`.
#[derive(Clone, Debug, PartialEq)]
pub struct InsuranceCapitalPool {
    initial: f64,
    premiums_in: f64,
    payouts_out: f64,
}

impl InsuranceCapitalPool {
    /// A pool seeded with `initial` capital. `Err` unless it is a non-negative finite number.
    pub fn new(initial: f64) -> Result<InsuranceCapitalPool, String> {
        if !initial.is_finite() || initial < 0.0 {
            return Err("InsuranceCapitalPool: initial capital must be a non-negative finite number".into());
        }
        Ok(InsuranceCapitalPool { initial, premiums_in: 0.0, payouts_out: 0.0 })
    }

    /// Free capital: `initial + premiumsIn - payoutsOut`.
    pub fn balance(&self) -> f64 {
        self.initial + self.premiums_in - self.payouts_out
    }

    /// Total premiums collected.
    pub fn premiums_in(&self) -> f64 {
        self.premiums_in
    }

    /// Total victim payouts made.
    pub fn payouts_out(&self) -> f64 {
        self.payouts_out
    }

    /// The accounting snapshot `{initial, premiumsIn, payoutsOut, balance}`.
    pub fn state(&self) -> Value {
        json!({"initial": num(self.initial), "premiumsIn": num(self.premiums_in), "payoutsOut": num(self.payouts_out), "balance": num(self.balance())})
    }

    /// Prices coverage of `exposure` for a reputation score without changing the pool.
    pub fn quote(&self, score: f64, exposure: f64, opts: &crate::reputation::PricingOptions) -> Value {
        crate::reputation::price_coverage(score, exposure, opts)
    }

    /// Prices coverage and, when it is not declined, credits the premium: `{pricing, state}`. A declined quote credits nothing.
    /// `Err` (nothing credited) for a premium that is not a finite number.
    pub fn collect_premium(&mut self, score: f64, exposure: f64, opts: &crate::reputation::PricingOptions) -> Result<Value, String> {
        let pricing = self.quote(score, exposure, opts);
        if pricing["declined"] == false {
            // a premium the JSON cannot carry is not a finite number
            let premium = pricing["premium"].as_f64().filter(|p| p.is_finite() && *p >= 0.0).ok_or("collectPremium: priced premium is not a non-negative finite number")?;
            self.premiums_in += premium;
        }
        Ok(json!({"pricing": pricing, "state": self.state()}))
    }

    /// The pool holds at least `amount` of free capital (`false` for a negative or non-finite amount).
    pub fn can_cover(&self, amount: f64) -> bool {
        amount.is_finite() && amount >= 0.0 && self.balance() >= amount
    }

    /// Pays `amount` of victim compensation out of the pool and returns the state after it. `Err` when the amount is not
    /// positive and finite, or exceeds the free capital: the pool never pays what it does not hold.
    pub fn pay_claim(&mut self, amount: f64) -> Result<Value, String> {
        if !amount.is_finite() || amount <= 0.0 {
            return Err("payClaim: amount must be a positive finite number".into());
        }
        if !(self.balance().is_finite() && amount <= self.balance()) {
            return Err(format!(
                "payClaim: insufficient pool capital (need {}, have {})",
                crate::intent_v2::js_number_string(amount),
                crate::intent_v2::js_number_string(self.balance())
            ));
        }
        self.payouts_out += amount;
        Ok(self.state())
    }
}

#[cfg(test)]
mod pow_eighths_tests {
    use super::pow_eighths;

    #[test]
    fn the_power_curve_is_repeated_multiplication_and_square_roots() {
        assert_eq!(pow_eighths(3.0, 1.0).unwrap(), 3.0);
        assert_eq!(pow_eighths(3.0, 2.0).unwrap(), 9.0);
        assert_eq!(pow_eighths(5.0, 4.0).unwrap(), 625.0);
        assert_eq!(pow_eighths(16.0, 1.5).unwrap(), 64.0); // 16 * sqrt(16)
        assert_eq!(pow_eighths(16.0, 1.25).unwrap(), 32.0); // 16 * sqrt(sqrt(16))
        assert_eq!(pow_eighths(256.0, 1.125).unwrap(), 256.0 * 2.0); // 256 * sqrt(sqrt(sqrt(256)))
        // the order is fixed: floor(n/8) multiplications, then the square-root factors in the order of bits 4, 2, 1
        let e = 7.0f64;
        let (s1, s2, s3) = (e.sqrt(), e.sqrt().sqrt(), e.sqrt().sqrt().sqrt());
        assert_eq!(pow_eighths(e, 2.875).unwrap(), e * e * s1 * s2 * s3);
        assert_eq!(pow_eighths(64.0f64.sqrt(), 64.0).unwrap(), 2.0f64.powi(192));
    }

    #[test]
    fn a_gamma_that_is_not_a_multiple_of_an_eighth_or_exceeds_64_is_refused() {
        let msg = "bondAmount: power curve gamma must be a multiple of 1/8 and at most 64";
        for g in [1.1, 2.3333, 64.125, 65.0, f64::INFINITY, f64::NAN] {
            assert_eq!(pow_eighths(2.0, g), Err(msg.to_string()), "gamma {g}");
        }
    }
}
