//! Differential replay of bond settlement against the TypeScript reference (test-data/ref-core-bond-settlement-java.json.gz, 1451 cases):
//! the slash split, exact money arithmetic, bond sizing, the evidence digests and the settlement record digest / commitment / signature,
//! the claim check, the fraud-proof and dispute verdicts (the Policy VM is this crate's `policy_vm::decide`) and the scripted
//! `StoreBondLedger` sequences. Every case is replayed; an unknown function fails the test.
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::bond_settlement::*;
use atlas_pca::bond_store::{apply_bond_moves, num, to_micros, BondStore, KvBondStore};
use atlas_pca::kv::{AtomicKv, MemoryAtomicKv};
use atlas_pca::optimistic::WindowPolicy;
use atlas_pca::optimistic_adjudication::{adjudicate_dispute, verify_claim, verify_fraud_proof};
use atlas_pca::policy_vm::decide;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::store_errors::{CodedError, R};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

const BOND_DOC: &str = "pca-bond-store/v1";
static NULL: Value = Value::Null;

fn vm(input: &Value) -> Result<Value, String> {
    Ok(decide(input))
}

fn window_policy(w: &Value) -> Option<WindowPolicy> {
    w.is_object().then(|| WindowPolicy { min_window_ms: d(&w["minWindowMs"]), max_window_ms: d(&w["maxWindowMs"]), max_skew_ms: d(&w["maxSkewMs"]) })
}

/// A params object with its `@name` fixture references resolved.
fn resolve(fx: &Value, v: &Value) -> Value {
    match v {
        Value::String(s) if s.starts_with('@') => fx.get(&s[1..]).cloned().unwrap_or(Value::Null),
        Value::Array(a) => Value::Array(a.iter().map(|x| resolve(fx, x)).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), resolve(fx, x))).collect()),
        other => other.clone(),
    }
}

/// One scripted `StoreBondLedger` sequence: an op that fails records `{"$err": code}`.
fn ledger_run(fx: &Value, cfg: &Value, ops: &[Value]) -> Value {
    let seed: [u8; 32] = Sha256::digest(b"atlas-pca-conformance/bond/guardian").into();
    let kv = Arc::new(MemoryAtomicKv::new());
    let store: Arc<dyn BondStore> = Arc::new(KvBondStore::new(kv.clone() as Arc<dyn AtomicKv>));
    let clock = Arc::new(Mutex::new(1_800_000_000_000f64));
    let tick = clock.clone();
    let w = &cfg["windowMs"];
    let wp = w.is_object().then(|| WindowPolicy { min_window_ms: d(&w["min"]), max_window_ms: d(&w["max"]), max_skew_ms: d(&w["skew"]) });
    let planner = BondSettlementPlanner::new(
        KeyPair::from_seed(&seed),
        cfg.get("epoch").and_then(Value::as_i64),
        None,
        None,
        cfg.get("escrow").and_then(Value::as_str),
        cfg.get("bondPolicy").cloned(),
        cfg.get("splitPolicy").cloned(),
    )
    .expect("planner");
    let ledger = StoreBondLedger::new(store, planner, Some(Box::new(move || *tick.lock().unwrap())), wp);
    let mut out = Vec::new();
    for op in ops {
        let arg = |i: usize| op.get(i).unwrap_or(&NULL);
        let p = resolve(fx, arg(1));
        let table = p.get("oracleTable").filter(|t| t.is_object()).cloned();
        let resolve_input = |input: &str, _snap: &Value| -> Result<Value, String> { Ok(table.as_ref().and_then(|t| t.get(input)).cloned().unwrap_or(Value::Null)) };
        let oracle: Option<&dyn Fn(&str, &Value) -> Result<Value, String>> = if table.is_some() { Some(&resolve_input) } else { None };
        let step = || -> R<Value> {
            Ok(match text(arg(0)) {
                "clock" => {
                    *clock.lock().unwrap() = arg(1).as_f64().unwrap_or(f64::NAN);
                    Value::Null
                }
                "deposit" => num(ledger.deposit(text(arg(1)), d(arg(2)))?),
                "balance" => num(ledger.balance_of(text(arg(1)))?),
                "status" => json!(ledger.bond_status(text(arg(1)))?),
                "bond" => ledger.get_bond(text(arg(1)))?.unwrap_or(Value::Null),
                "challenge" => ledger.challenge_status(text(arg(1)))?,
                "pub" => json!(ledger.guardian_public_key()),
                "openClaim" => ledger.open_claim(&p["claim"], &p["pcactn"], text(&p["signerPublic"]), d(&p["amount"]), text(&p["depositor"]), p["exposure"].as_f64())?,
                "openBond" => ledger.open_bond(text(&p["claimId"]), d(&p["amount"]), text(&p["depositor"]), p["exposure"].as_f64())?,
                "release" => ledger.release(text(arg(1)))?,
                "releaseUnreg" => ledger.release_unregistered(text(arg(1)))?,
                "slash" => ledger.slash_bond(&p, Some(&vm))?,
                "slashDispute" => ledger.slash_bond_on_dispute(&p, oracle, Some(&vm))?,
                "slashRevoke" => ledger.slash_bond_on_revocation(&p)?,
                "slashCounter" => ledger.slash_counter_bond(&p, oracle, Some(&vm))?,
                "kvSet" => {
                    kv.update(BOND_DOC, &mut |_| Some(arg(1).clone())).map_err(|_| CodedError::new("Error", "kv"))?;
                    Value::Null
                }
                "kvGet" => kv.get(BOND_DOC).map_err(|_| CodedError::new("Error", "kv"))?.unwrap_or(Value::Null),
                _ => return Err(CodedError::new("Error", "op")),
            })
        };
        out.push(match std::panic::catch_unwind(std::panic::AssertUnwindSafe(step)) {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => json!({"$err": e.code}),
            Err(_) => json!({"$err": "Error"}),
        });
    }
    Value::Array(out)
}

fn d(v: &Value) -> f64 {
    v.as_f64().unwrap_or(f64::NAN)
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn ok_or_throw<T>(r: Result<T, String>, f: impl FnOnce(T) -> Value) -> Value {
    match r {
        Ok(v) => f(v),
        Err(e) => json!({"$throws": e}),
    }
}

fn run(f: &str, a: &[Value]) -> Option<Value> {
    Some(match f {
        "computeSlashSplit" => ok_or_throw(compute_slash_split(d(&a[0]), &a[1], &a[2]), |v| v),
        "quantizeUp" => num(quantize_up(d(&a[0]))),
        "toMicros" => to_micros(d(&a[0])).map_or(Value::Null, |m| json!({"$bigint": m.to_string()})),
        "exactAdd" => num(exact_add_amounts(d(&a[0]), d(&a[1]), d(&a[2]) as i64)),
        "applyBondMoves" => {
            let bal = a[0].as_object().cloned().unwrap_or_default();
            let moves = a[1].as_array().cloned().unwrap_or_default();
            ok_or_throw(apply_bond_moves(&|acct| bal.get(acct).and_then(Value::as_f64).unwrap_or(0.0), &moves), Value::Object)
        }
        "bondAmount" => ok_or_throw(bond_amount(&a[0], Some(d(&a[1]))), num),
        "settlementEvidenceDigest" => json!(settlement_evidence_digest(&a[0], &a[1])),
        "revocationEvidenceDigest" => json!(revocation_evidence_digest(&a[0], text(&a[1]))),
        "disputeEvidenceDigest" => json!(dispute_evidence_digest(&a[0], &a[1])),
        "verifySettlement" => json!(verify_settlement(&a[0], text(&a[1]), a.get(2).filter(|p| p.is_object()))),
        "settlementRecordDigest" => json!(settlement_record_digest(&a[0])),
        "settlementCommit" => ok_or_throw(settlement_commit(text(&a[0]), &a[1]), |c| json!(c)),
        "verifySettlementCommit" => json!(a[0].as_str().is_some_and(|c| verify_settlement_commit(c, text(&a[1]), &a[2]))),
        "verifyClaim" => verify_claim(&a[0], &a[1], text(&a[2]), d(&a[3]), window_policy(&a[4]).as_ref()),
        "verifyFraudProof" => verify_fraud_proof(&a[0], &a[1], &a[2], &a[3], Some(&vm)),
        "adjudicateDispute" => {
            let table = a[4].clone();
            let resolve_input = |input: &str, _snap: &Value| -> Result<Value, String> { Ok(table.get(input).cloned().unwrap_or(Value::Null)) };
            let oracle: Option<&dyn Fn(&str, &Value) -> Result<Value, String>> = if table.is_object() { Some(&resolve_input) } else { None };
            adjudicate_dispute(&a[0], &a[1], &a[2], &a[3], oracle, a[5].as_f64(), Some(&vm))
        }
        "ledger" => ledger_run(&a[0], &a[1], a[2].as_array().map(Vec::as_slice).unwrap_or(&[])),
        _ => return None,
    })
}

#[test]
fn bond_settlement_matches_the_reference() {
    let cases = common::ref_cases("core-bond-settlement-java");
    let (mut bad, mut ran) = (Vec::new(), 0usize);
    for c in &cases {
        let f = c["fn"].as_str().unwrap_or("");
        let args = c["args"].as_array().cloned().unwrap_or_default();
        let got = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(f, &args))) {
            Ok(Some(v)) => v,
            Ok(None) => panic!("unhandled corpus function {f}"),
            Err(_) => json!({"$throws": "panic"}),
        };
        ran += 1;
        let want = &c["out"];
        let same = if want.get("$throws").is_some() { got.get("$throws").is_some() } else { atlas_pca::canonicalize(want) == atlas_pca::canonicalize(&got) };
        if !same {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], want, got));
        }
    }
    assert_eq!(ran, 1451, "case total");
    assert!(bad.is_empty(), "{} cases differ:\n{}", bad.len(), bad.iter().take(40).cloned().collect::<Vec<_>>().join("\n"));
}
