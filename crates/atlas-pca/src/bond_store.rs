//! Durable bond settlement, the store half (`packages/pca/src/bond-store.ts`): the `BondStore` contract (`read`, `commit`, `deposit`), the
//! exact micro-unit arithmetic every store shares, the pure transition function and [`KvBondStore`], one document in any atomic key-value
//! store. INTERNAL ACCOUNTING ONLY: nothing here moves money.
//!
//! A plan is `{claimId, expect, next, open?: {amount, depositor, maxOpenClaims, maxOpenAmount, window?}, moves: [{account, op, amount}],
//! record}`. [`commit_bond_plan`] applies it ALL OR NOTHING: the compare-and-swap on the bond's phase, every balance movement, the new
//! phase and the signed record become visible together; committing the same transition twice is a replay (the stored record, nothing
//! moved). Records are JSON values with the reference's member names.
use crate::kv::AtomicKv;
use crate::store_errors::{kv_err, CodedError, R};
use serde_json::{json, Map, Value};
use std::sync::Arc;

pub const BOND_DOC_KEY: &str = "pca-bond-store/v1";
const MICROS: f64 = 1_000_000.0;
const MAX_SAFE_MICROS: f64 = 1e15;
const PHASES: [&str; 3] = ["open", "released", "slashed"];

fn fin(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64).filter(|f| f.is_finite())
}

/// A JSON number the way JavaScript prints it: an integral value is an integer.
pub fn num(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 1e15 {
        json!(f as i64)
    } else {
        json!(f)
    }
}

fn js_round(x: f64) -> f64 {
    (x + 0.5).floor()
}

/// Integer micro-units of `x` when it is a micro-grid amount below 1e15 micros, else `None`.
pub fn to_micros(x: f64) -> Option<i64> {
    if !x.is_finite() || x < 0.0 {
        return None;
    }
    let scaled = x * MICROS;
    if scaled > MAX_SAFE_MICROS {
        return None;
    }
    let r = js_round(scaled);
    if r / MICROS != x && (scaled - r).abs() > 1e-3 {
        return None; // genuinely sub-micro: not a micro-grid amount
    }
    Some(r as i64)
}

pub fn from_micros(m: i64) -> f64 {
    m as f64 / MICROS
}

/// `a + sign*b` in exact micro-unit integers when both are micro-grid amounts; plain float otherwise.
pub fn exact_add(a: f64, b: f64, sign: i64) -> f64 {
    match (to_micros(a), to_micros(b)) {
        (Some(ma), Some(mb)) => from_micros(if sign == 1 { ma + mb } else { ma - mb }),
        _ => a + sign as f64 * b,
    }
}

/// Apply moves in order over a balance reader; Errs (applying nothing) on an invalid amount or an overdraft.
pub fn apply_bond_moves(balance_of: &dyn Fn(&str) -> f64, moves: &[Value]) -> Result<Map<String, Value>, String> {
    let mut out: Map<String, Value> = Map::new();
    let bal = |out: &Map<String, Value>, a: &str| out.get(a).and_then(Value::as_f64).unwrap_or_else(|| balance_of(a));
    for m in moves {
        let op = m.get("op").map_or("None".to_string(), crate::intent_v2::js_value_string);
        let Some(amount) = fin(m.get("amount")).filter(|a| *a >= 0.0) else { return Err(format!("{op}: invalid amount")) };
        let account = m.get("account").and_then(Value::as_str).ok_or("move: account is required")?;
        let cur = bal(&out, account);
        if !cur.is_finite() {
            return Err(format!("{op}: balance of {account} is not finite"));
        }
        if m.get("op").and_then(Value::as_str) == Some("debit") && !(cur >= amount) {
            return Err(format!("debit: insufficient balance for {account}"));
        }
        out.insert(account.to_string(), num(exact_add(cur, amount, if op == "debit" { -1 } else { 1 })));
    }
    Ok(out)
}

fn canon(v: Option<&Value>) -> Option<String> {
    v.filter(|x| !x.is_null()).map(crate::canonicalize)
}

/// Same settlement: action, bond, amount, parties, evidence and split (time and signature bytes ignored).
pub fn same_settlement(a: &Value, b: &Value) -> bool {
    ["claimId", "action", "amount", "from", "to", "evidenceDigest", "split"].iter().all(|k| canon(a.get(*k)) == canon(b.get(*k)))
}

fn same_window(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a.filter(|x| !x.is_null()), b.filter(|x| !x.is_null())) {
        (None, None) => true,
        (Some(a), Some(b)) => canon(a.get("windowMs")) == canon(b.get("windowMs")) && canon(a.get("claimDigest")) == canon(b.get("claimDigest")),
        _ => false,
    }
}

/// The in-memory bond book: `balances` (account -> number), `bonds` (claim id -> row) and the store's time high-water mark.
#[derive(Clone, Debug)]
pub struct BondDoc {
    pub balances: Map<String, Value>,
    pub bonds: Map<String, Value>,
    pub high_water: f64,
}

pub fn empty_bond_doc() -> BondDoc {
    BondDoc { balances: Map::new(), bonds: Map::new(), high_water: 0.0 }
}

fn truthy_obj(v: Option<&Value>) -> Option<&Value> {
    v.filter(|x| x.as_object().is_some_and(|o| !o.is_empty()))
}

/// Apply `plan` to `doc` following the `BondStore.commit` rules. Mutates `doc` ONLY on `committed` (the moves are checked on an overlay
/// first).
pub fn commit_bond_plan(doc: &mut BondDoc, plan: &Value, observed_at: &Value) -> R<Value> {
    let claim_id = plan.get("claimId").and_then(Value::as_str).ok_or_else(|| CodedError::new("Error", "claimId"))?.to_string();
    let bond = doc.bonds.get(&claim_id).cloned();
    let cur = bond.as_ref().map_or("none".to_string(), |b| b["status"].as_str().unwrap_or("").to_string());
    let conflict = |reason: String, current: &str| Ok(json!({"outcome": "conflict", "reason": reason, "current": current}));
    let o = truthy_obj(plan.get("open")).cloned();
    let record = plan.get("record").cloned().unwrap_or(Value::Null);
    if plan.get("expect").and_then(Value::as_str) == Some("none") {
        let Some(o) = o.as_ref().filter(|_| plan.get("next").and_then(Value::as_str) == Some("open")) else {
            return conflict("malformed open plan".into(), &cur);
        };
        if let Some(b) = &bond {
            let recs = b["records"].as_array().cloned().unwrap_or_default();
            let same = canon(b.get("depositor")) == canon(o.get("depositor"))
                && fin(b.get("amount")) == fin(o.get("amount"))
                && same_window(b.get("window"), o.get("window"))
                && !recs.is_empty()
                && same_settlement(&recs[0], &record);
            return if same {
                Ok(json!({"outcome": "replayed", "record": recs[0]}))
            } else {
                conflict(format!("bond {claim_id} already exists"), b["status"].as_str().unwrap_or(""))
            };
        }
        let (mut count, mut total) = (0.0_f64, 0.0_f64);
        for b in doc.bonds.values() {
            if b["status"] == "open" && canon(b.get("depositor")) == canon(o.get("depositor")) {
                count += 1.0;
                total += b["amount"].as_f64().unwrap_or(0.0);
            }
        }
        if !(count.is_finite() && count + 1.0 <= o.get("maxOpenClaims").and_then(Value::as_f64).unwrap_or(f64::NAN)) {
            return conflict("depositor open-claim cap reached".into(), "none");
        }
        let spend = total + o.get("amount").and_then(Value::as_f64).unwrap_or(f64::NAN);
        if !(spend.is_finite() && spend <= o.get("maxOpenAmount").and_then(Value::as_f64).unwrap_or(f64::NAN)) {
            return conflict("depositor aggregate open-bond cap exceeded".into(), "none");
        }
    } else if let Some(b) = &bond {
        if b["status"].as_str() != plan.get("expect").and_then(Value::as_str) {
            let last = b["records"].as_array().and_then(|r| r.last()).cloned();
            if let Some(last) = last.filter(|l| b["status"].as_str() == plan.get("next").and_then(Value::as_str) && same_settlement(l, &record)) {
                return Ok(json!({"outcome": "replayed", "record": last}));
            }
            return conflict(format!("bond {claim_id} is already {}", b["status"].as_str().unwrap_or("")), b["status"].as_str().unwrap_or(""));
        }
    } else {
        return conflict(format!("no bond for {claim_id}"), "none");
    }
    let moves = plan.get("moves").and_then(Value::as_array).cloned().unwrap_or_default();
    let balances = doc.balances.clone();
    let nxt = match apply_bond_moves(&|a| balances.get(a).and_then(Value::as_f64).unwrap_or(0.0), &moves) {
        Ok(n) => n,
        Err(e) => return conflict(e, &cur),
    };
    for (k, v) in nxt {
        doc.balances.insert(k, v);
    }
    if let Some(o) = &o {
        let mut row = json!({"claimId": claim_id, "amount": o["amount"], "depositor": o["depositor"], "status": "open"});
        if let Some(w) = truthy_obj(o.get("window")) {
            row["window"] = w.clone();
        }
        row["records"] = json!([record]);
        doc.bonds.insert(claim_id, row);
    } else if let Some(b) = doc.bonds.get_mut(&claim_id) {
        b["status"] = plan.get("next").cloned().unwrap_or(Value::Null);
        if let Some(r) = b["records"].as_array_mut() {
            r.push(record.clone());
        }
    }
    doc.high_water = doc.high_water.max(fin(Some(observed_at)).unwrap_or(0.0));
    Ok(json!({"outcome": "committed", "record": record}))
}

/// What a planner may read: the bond, the depositor's balance and open totals, and the store's time high-water mark.
pub fn snapshot_of(doc: &BondDoc, claim_id: &str, depositor: Option<&str>) -> Value {
    let (mut count, mut total, mut balances) = (0.0, 0.0, Vec::new());
    if let Some(d) = depositor {
        for b in doc.bonds.values() {
            if b["status"] == "open" && b["depositor"].as_str() == Some(d) {
                count += 1.0;
                total += b["amount"].as_f64().unwrap_or(0.0);
            }
        }
        balances.push(json!([d, doc.balances.get(d).cloned().unwrap_or(json!(0))]));
    }
    let mut out = Map::new();
    if let Some(b) = doc.bonds.get(claim_id) {
        out.insert("bond".into(), b.clone());
    }
    out.insert("balances".into(), Value::Array(balances));
    out.insert("openTotals".into(), json!({"count": num(count), "sum": num(total)}));
    out.insert("highWater".into(), num(doc.high_water));
    Value::Object(out)
}

fn bad(why: &str) -> CodedError {
    CodedError::new("store_corrupt", why)
}

fn decode_doc(raw: Option<&Value>) -> R<BondDoc> {
    let Some(raw) = raw.filter(|r| !r.is_null()) else { return Ok(empty_bond_doc()) };
    let hw = raw.get("highWater").filter(|h| h.is_number());
    if raw.get("v").and_then(Value::as_f64) != Some(1.0) || !raw["balances"].is_array() || !raw["bonds"].is_array() || hw.is_none() {
        return Err(bad("bond document has the wrong shape"));
    }
    let Some(high_water) = fin(hw).filter(|h| *h >= 0.0) else { return Err(bad("highWater is not a non-negative number")) };
    let mut doc = empty_bond_doc();
    doc.high_water = high_water;
    for e in raw["balances"].as_array().into_iter().flatten() {
        let ok = e.as_array().filter(|l| l.len() == 2).and_then(|l| Some((l[0].as_str()?, fin(l.get(1)).filter(|v| *v >= 0.0)?)));
        let Some((a, v)) = ok else { return Err(bad("malformed balance entry")) };
        doc.balances.insert(a.to_string(), num(v));
    }
    for b in raw["bonds"].as_array().into_iter().flatten() {
        let ok = b.is_object()
            && b["claimId"].is_string()
            && b["depositor"].is_string()
            && fin(b.get("amount")).is_some()
            && b["status"].as_str().is_some_and(|s| PHASES.contains(&s))
            && b["records"].as_array().is_some_and(|r| !r.is_empty());
        if !ok {
            return Err(bad("malformed bond row"));
        }
        let id = b["claimId"].as_str().unwrap_or("").to_string();
        if doc.bonds.contains_key(&id) {
            return Err(bad("duplicate bond row"));
        }
        doc.bonds.insert(id, b.clone());
    }
    Ok(doc)
}

fn encode_doc(d: &BondDoc) -> Value {
    json!({"v": 1, "balances": d.balances.iter().map(|(a, v)| json!([a, v])).collect::<Vec<_>>(), "bonds": d.bonds.values().collect::<Vec<_>>(), "highWater": num(d.high_water)})
}

/// The bond store contract.
pub trait BondStore: Send + Sync {
    fn read(&self, claim_id: &str, depositor: Option<&str>) -> R<Value>;
    fn commit(&self, plan: &Value, observed_at: &Value) -> R<Value>;
    fn deposit(&self, account: &Value, amount: &Value) -> R<f64>;
}

/// The reference bond store: the whole book is one document in an atomic key-value store, so every transition is a single atomic
/// read-modify-write. LIMIT: one document, rewritten on every commit; a production deployment implements the store over a database
/// transaction.
pub struct KvBondStore {
    kv: Arc<dyn AtomicKv>,
    key: String,
}

impl KvBondStore {
    pub fn new(kv: Arc<dyn AtomicKv>) -> Self {
        KvBondStore { kv, key: BOND_DOC_KEY.to_string() }
    }
}

impl BondStore for KvBondStore {
    fn read(&self, claim_id: &str, depositor: Option<&str>) -> R<Value> {
        let raw = self.kv.get(&self.key).map_err(kv_err)?;
        Ok(snapshot_of(&decode_doc(raw.as_ref())?, claim_id, depositor))
    }

    fn commit(&self, plan: &Value, observed_at: &Value) -> R<Value> {
        let mut out: Option<R<Value>> = None;
        self.kv
            .update(&self.key, &mut |prev| {
                let step = decode_doc(prev).and_then(|mut d| commit_bond_plan(&mut d, plan, observed_at).map(|r| (d, r)));
                match step {
                    Ok((d, r)) => {
                        let committed = r["outcome"] == "committed";
                        out = Some(Ok(r));
                        committed.then(|| encode_doc(&d))
                    }
                    Err(e) => {
                        out = Some(Err(e));
                        None
                    }
                }
            })
            .map_err(kv_err)?;
        out.unwrap_or_else(|| Err(CodedError::new("store_unavailable", "the store did not run the update")))
    }

    /// Atomically credit `account` with `amount` (a positive finite number). Returns the new balance.
    fn deposit(&self, account: &Value, amount: &Value) -> R<f64> {
        let Some(acct) = account.as_str().filter(|a| !a.is_empty()) else { return Err(CodedError::range("deposit: account is required")) };
        let Some(amt) = fin(Some(amount)).filter(|a| *a > 0.0) else { return Err(CodedError::range("deposit: amount must be a positive finite number")) };
        let mut out: Option<R<f64>> = None;
        self.kv
            .update(&self.key, &mut |prev| match decode_doc(prev) {
                Ok(mut d) => {
                    let bal = d.balances.get(acct).and_then(Value::as_f64).unwrap_or(0.0);
                    let nb = exact_add(bal, amt, 1);
                    d.balances.insert(acct.to_string(), num(nb));
                    out = Some(Ok(nb));
                    Some(encode_doc(&d))
                }
                Err(e) => {
                    out = Some(Err(e));
                    None
                }
            })
            .map_err(kv_err)?;
        out.unwrap_or_else(|| Err(CodedError::new("store_unavailable", "the store did not run the update")))
    }
}
