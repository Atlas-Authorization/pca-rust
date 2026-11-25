//! Differential replay of the durable stores against the TypeScript reference (test-data/ref-core-stores-java.json.gz): the ledger
//! store, the stored ledger with its checkpoint verification, the bond store and the budget ledger with signed releases and aggregate
//! admission. A failure is compared by its stable code (`RangeError` for an argument error). The mesh-witness section of the same file
//! needs the issuing side of the mesh (`MeshWitness`, `MeshDomain`), which this crate does not carry yet.
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::bond_store::{BondStore, KvBondStore};
use atlas_pca::budget_ledger::*;
use atlas_pca::kv::{AtomicKv, MemoryAtomicKv};
use atlas_pca::ledger_store::{KvLedgerStore, LedgerStore, StoredLedger, StoredLedgerOptions};
use atlas_pca::serde_json::{json, Value};
use atlas_pca::store_errors::{CodedError, R};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn key(label: &str) -> KeyPair {
    let seed: [u8; 32] = Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes()).into();
    KeyPair::from_seed(&seed)
}

fn script(ops: &Value, f: &mut dyn FnMut(&Vec<Value>) -> R<Value>) -> Value {
    Value::Array(
        ops.as_array()
            .unwrap()
            .iter()
            .map(|op| {
                let op = op.as_array().unwrap();
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(op))) {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => json!({"$err": e.code}),
                    Err(_) => json!({"$err": "Error"}),
                }
            })
            .collect(),
    )
}

fn set(kv: &MemoryAtomicKv, k: &str, v: &Value) {
    kv.update(k, &mut |_| Some(v.clone())).unwrap();
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn ledger_store(ops: &Value) -> Value {
    let kv = Arc::new(MemoryAtomicKv::new());
    let st = KvLedgerStore::new(kv.clone() as Arc<dyn AtomicKv>);
    script(ops, &mut |op| match s(&op[0]) {
        "size" => Ok(json!(st.size()?)),
        "read" => Ok(json!(st.read(&op[1], &op[2])?)),
        "append" => st.append(&op[1], &op[2]),
        "cpCount" => Ok(json!(st.checkpoint_count()?)),
        "cps" => Ok(json!(st.checkpoints(&op[1])?)),
        "appendCp" => st.append_checkpoint(&op[1], &op[2]),
        "kvSet" => {
            set(&kv, "pca-ledger-store/v1", &op[1]);
            Ok(Value::Null)
        }
        _ => Err(CodedError::new("Error", "op")),
    })
}

fn stored_ledger(ops: &Value) -> Value {
    let kv = Arc::new(MemoryAtomicKv::new());
    let store: Arc<dyn LedgerStore> = Arc::new(KvLedgerStore::new(kv.clone() as Arc<dyn AtomicKv>));
    let mut handles: HashMap<String, StoredLedger> = HashMap::new();
    let calls = Arc::new(AtomicU64::new(0));
    script(ops, &mut |op| {
        let head = s(&op[0]);
        match head {
            "open" => {
                let g = if op.get(2).is_some_and(|x| x == "other-key") { key("other") } else { key("stored-ledger-guardian") };
                let inst = op.get(3).and_then(Value::as_str).unwrap_or("inst");
                let mut o = StoredLedgerOptions::new(inst, "pr");
                let c = calls.clone();
                o.clock = Some(Box::new(move || 1_800_000_000_000.0 + 1000.0 * c.fetch_add(1, Ordering::SeqCst) as f64));
                let h = StoredLedger::open(store.clone(), g, o)?;
                let out = json!({"size": h.size(), "guardian": h.guardian()});
                handles.insert(s(&op[1]).to_string(), h);
                Ok(out)
            }
            "kvSet" => {
                set(&kv, "pca-ledger-store/v1", &op[1]);
                Ok(Value::Null)
            }
            "kvGet" => Ok(kv.get("pca-ledger-store/v1").unwrap().unwrap_or(Value::Null)),
            _ => {
                let h = handles.get_mut(head).ok_or_else(|| CodedError::new("Error", "handle"))?;
                match s(&op[1]) {
                    "append" => h.append(&op[2]),
                    "checkpoint" => h.checkpoint(),
                    "catchUp" => h.catch_up().map(|_| Value::Null),
                    "head" => Ok(h.head()),
                    "size" => Ok(json!(h.size())),
                    "incl" => h.inclusion_proof(&op[2]),
                    "consFrom" => h.consistency_proof_from(&op[2]),
                    "commits" => Ok(json!(h.commits())),
                    "latest" => Ok(h.latest_checkpoint().unwrap_or(Value::Null)),
                    "chain" => Ok(json!(h.checkpoint_chain())),
                    "guardian" => Ok(json!(h.guardian())),
                    _ => Err(CodedError::new("Error", "op")),
                }
            }
        }
    })
}

fn bond_store(ops: &Value) -> Value {
    let kv = Arc::new(MemoryAtomicKv::new());
    let st = KvBondStore::new(kv.clone() as Arc<dyn AtomicKv>);
    script(ops, &mut |op| match s(&op[0]) {
        "read" => st.read(s(&op[1]), op.get(2).and_then(Value::as_str)),
        "commit" => st.commit(&op[1], &op[2]),
        "deposit" => st.deposit(&op[1], &op[2]).map(atlas_pca::bond_store::num),
        "kvSet" => {
            set(&kv, "pca-bond-store/v1", &op[1]);
            Ok(Value::Null)
        }
        "kvGet" => Ok(kv.get("pca-bond-store/v1").unwrap().unwrap_or(Value::Null)),
        _ => Err(CodedError::new("Error", "op")),
    })
}

fn budget_ledger(ops: &Value) -> Value {
    let rkey = key("release-signer");
    let kv = Arc::new(MemoryAtomicKv::new());
    let mut ledger: Option<KvBudgetLedger> = None;
    let log = KvLedgerStore::new(Arc::new(MemoryAtomicKv::new()) as Arc<dyn AtomicKv>);
    script(ops, &mut |op| {
        let k = s(&op[0]);
        if k == "new" {
            let d = op[1].as_bool().ok_or_else(|| CodedError::new("invalid", "say whether the kv is durable (True or False)"))?;
            let l = KvBudgetLedger::new(kv.clone() as Arc<dyn AtomicKv>, d);
            let out = json!(l.durable);
            ledger = Some(l);
            return Ok(out);
        }
        let l = ledger.as_ref();
        let need = || l.ok_or_else(|| CodedError::new("Error", "no ledger"));
        match k {
            "snapshot" => need()?.snapshot(s(&op[1])),
            "reserve" => need()?.reserve(s(&op[1]), &op[2]),
            "start" => need()?.start(s(&op[1]), s(&op[2])),
            "commit" => need()?.commit(s(&op[1]), s(&op[2])),
            "release" => need()?.release(s(&op[1]), s(&op[2]), Some(&op[3])),
            "expire" => need()?.expire(s(&op[1]), &op[2]),
            "signRelease" => sign_release(&op[1], &op[2], &op[3], &op[4], &rkey),
            "verifyRelease" => Ok(json!(verify_release(&op[1], &if op[2] == "signer" { json!(rkey.public) } else { op[2].clone() }))),
            "releaseCommit" => Ok(json!([release_digest(&op[1]), release_commit(&op[1])])),
            "anchor" => Ok(json!([anchor_release(&log, &op[1])?, log.size()?])),
            "scopeKey" => scope_key(s(&op[1]), &op[2]).map(Value::String),
            "kvSet" => {
                set(&kv, s(&op[1]), &op[2]);
                Ok(Value::Null)
            }
            "admit" => {
                let ad = &op[1];
                let allow = ad["allow"].clone();
                let accs = ad["accumulators"].as_array().cloned().unwrap_or_default();
                let verify = move |state: &Value| json!({"allow": allow, "state": state});
                admit_aggregate_action(
                    need()?,
                    &ad["ids"],
                    &accs,
                    None,
                    &ad["event"],
                    &verify,
                    ad["expiresAt"].as_i64(),
                    ad["maxAttempts"].as_u64().map(|n| n as usize),
                )
            }
            "startAgg" => Ok(json!(start_aggregate(need()?, op[1].as_array().unwrap())?)),
            "settleAgg" => Ok(json!(settle_aggregate(need()?, op[1].as_array().unwrap(), s(&op[2]), None)?)),
            _ => Err(CodedError::new("Error", "op")),
        }
    })
}

#[test]
fn the_durable_stores_match_the_reference() {
    let cases = common::ref_cases("core-stores-java");
    let mut bad = Vec::new();
    let mut ran = std::collections::BTreeMap::new();
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        let ops = &c["args"][0];
        let got = match f {
            "ledgerStore" => ledger_store(ops),
            "storedLedger" => stored_ledger(ops),
            "bondStore" => bond_store(ops),
            "budgetLedger" => budget_ledger(ops),
            "meshWitness" => continue, // the issuing side of the mesh is not in this crate
            other => panic!("unknown section {other}"),
        };
        *ran.entry(f).or_insert(0) += 1;
        if atlas_pca::canonicalize(&c["out"]) != atlas_pca::canonicalize(&got) {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert_eq!((ran["ledgerStore"], ran["storedLedger"], ran["bondStore"], ran["budgetLedger"]), (66, 30, 60, 62), "{ran:?}");
    assert!(bad.is_empty(), "{} cases differ:\n{}", bad.len(), bad.join("\n"));
}
