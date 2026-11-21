//! Differential replay of the chain, receipt, signal, budget and approval parts of test-data/ref-core-sweep-java.json.gz (written by the
//! TypeScript reference; the reputation, coverage and pool parts are in ref_reputation.rs): chain compaction and its memo, the receipt hash
//! chain (driven by op scripts that tamper with the log), the model-signal folds, risk tightening, the budget recommendation, sub-budgets and
//! consolidated debits, the full recharge, class approvals and their decisions, and the co-sign recharge. A reference throw requires a
//! refusal (an op script records `{"$err": "Error"}` for a step that throws); per-function totals are asserted.
mod common;
use std::collections::BTreeMap;

use atlas_pca::approvals::*;
use atlas_pca::budget_forecast::{autonomy_bound_of, recommend_policy};
use atlas_pca::chain_compact::*;
use atlas_pca::frontier_signals::*;
use atlas_pca::receipt_log::*;
use atlas_pca::risk::{
    debit_consolidated, debit_consolidated_path, recharge_full, sub_budget, RiskPolicy, TrustBudget, DEFAULT_RISK_POLICY,
};
use atlas_pca::serde_json::{json, Value};

const FNS: [(&str, usize); 23] = [
    ("hopsRoot", 14),
    ("compactChain", 14),
    ("hopLeaf", 5),
    ("compactChainShapeError", 27),
    ("chainMemo", 8),
    ("receiptFor", 60),
    ("receiptChain", 21),
    ("semanticSignal", 26),
    ("progressSignal", 26),
    ("objectiveSignal", 26),
    ("tightenRiskInputs", 121),
    ("recommendPolicy", 110),
    ("autonomyBoundOf", 10),
    ("subBudget", 117),
    ("debitConsolidated", 288),
    ("debitConsolidatedPath", 72),
    ("rechargeFull", 28),
    ("approveClass", 75),
    ("classApprovalCovers", 675),
    ("coveredByAny", 36),
    ("recordDecision", 2),
    ("pendingRequests", 5),
    ("applyCosign", 48),
];

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn err_step() -> Value {
    json!({"$err": "Error"})
}

fn budget_of(v: &Value) -> TrustBudget {
    let n = |k: &str| v.get(k).and_then(Value::as_f64).unwrap_or(f64::NAN);
    TrustBudget { b: n("B"), tau: n("tau"), as_of: v.get("asOf").and_then(Value::as_f64) }
}

fn budget_json(b: &TrustBudget) -> Value {
    // a member the input did not carry is `undefined` in the reference and so leaves no key (NaN stands for it here)
    let mut o = json!({"B": b.b});
    if !b.tau.is_nan() {
        o["tau"] = json!(b.tau);
    }
    if let Some(a) = b.as_of.filter(|a| !a.is_nan()) {
        o["asOf"] = json!(a);
    }
    o
}

fn chain_of(v: &Value) -> Result<&[Value], String> {
    v.as_array().map(Vec::as_slice).ok_or_else(|| "chain is not an array".to_string())
}

fn memo_run(ops: &Value) -> Value {
    let mut memo: Option<ChainMemo> = None;
    let mut out = Vec::new();
    for op in ops.as_array().unwrap() {
        let r: Result<Value, String> = (|| {
            Ok(match text(&op[0]) {
                "new" => {
                    let o = op.get(1).filter(|o| o.is_object());
                    let max = o.and_then(|o| o.get("maxEntries")).and_then(Value::as_u64).map(|n| n as usize);
                    memo = Some(ChainMemo::new(max, o.and_then(|o| o.get("ttlMs")).and_then(Value::as_i64)));
                    Value::Null
                }
                "remember" => {
                    memo.as_ref().ok_or("no memo")?.remember_verified(chain_of(&op[1])?, text(&op[2]), op[3].as_i64().ok_or("clock")?)?
                }
                "resolve" => {
                    let m = memo.as_ref().ok_or("no memo")?;
                    // a clock that is not a safe integer cannot be passed to the typed API: the reference answers a refusal verdict
                    let Some(clock) = op[2].as_f64().filter(|f| f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0).map(|f| f as i64) else {
                        return Ok(json!({"ok": false, "reason": "the verifier clock is not a safe integer (fail closed)"}));
                    };
                    match m.resolve(&op[1], clock) {
                        Ok(v) => {
                            let hashes: Vec<Value> = (0..v.n).map(|i| json!(v.hash(i))).collect();
                            let counts: Vec<Value> = (0..v.n).map(|i| json!(v.count(i))).collect();
                            json!({"ok": true, "view": {"n": v.n, "hashes": hashes, "counts": counts, "leaf": v.leaf}})
                        }
                        Err(reason) => json!({"ok": false, "reason": reason}),
                    }
                }
                "prune" => {
                    memo.as_ref().ok_or("no memo")?.prune(op[1].as_i64().ok_or("clock")?);
                    Value::Null
                }
                "forget" => json!(memo.as_ref().ok_or("no memo")?.forget(text(&op[1]))),
                "size" => json!(memo.as_ref().ok_or("no memo")?.len()),
                other => return Err(format!("bad op {other}")),
            })
        })();
        out.push(r.unwrap_or_else(|_| err_step()));
    }
    Value::Array(out)
}

fn receipt_run(ops: &Value) -> Value {
    let mut log: Vec<Value> = Vec::new();
    let mut out = Vec::new();
    for op in ops.as_array().unwrap() {
        let r: Result<Value, String> = (|| {
            Ok(match text(&op[0]) {
                "append" => {
                    log = append_receipt(&log, &op[1], &op[2], op.get(3).and_then(Value::as_i64))?;
                    log.last().cloned().unwrap_or(Value::Null)
                }
                "head" => json!(receipt_head(&log)),
                "verify" => match verify_receipt_chain_js(&log)? {
                    Ok(()) => json!({"ok": true}),
                    Err((Some(seq), reason)) => json!({"ok": false, "brokenAt": seq, "reason": reason}),
                    Err((None, reason)) => json!({"ok": false, "reason": reason}),
                },
                "set" => {
                    log = op[1].as_array().ok_or("not an array")?.clone();
                    Value::Null
                }
                "tamper" => {
                    let i = op[1].as_u64().ok_or("index")? as usize;
                    let rec = log.get_mut(i).and_then(Value::as_object_mut).ok_or("no such receipt")?;
                    if op[3] == json!("$del") {
                        rec.remove(text(&op[2]));
                    } else {
                        rec.insert(text(&op[2]).to_string(), op[3].clone());
                    }
                    Value::Null
                }
                "swap" => {
                    let (i, j) = (op[1].as_u64().ok_or("index")? as usize, op[2].as_u64().ok_or("index")? as usize);
                    if i >= log.len() || j >= log.len() {
                        return Err("no such receipt".into());
                    }
                    log.swap(i, j);
                    Value::Null
                }
                "drop" => {
                    let i = op[1].as_u64().ok_or("index")? as usize;
                    log = log.iter().enumerate().filter(|(k, _)| *k != i).map(|(_, r)| r.clone()).collect();
                    Value::Null
                }
                "truncate" => {
                    log.truncate(op[1].as_u64().ok_or("length")? as usize);
                    Value::Null
                }
                other => return Err(format!("bad op {other}")),
            })
        })();
        out.push(r.unwrap_or_else(|_| err_step()));
    }
    Value::Array(out)
}

fn budget_result(r: Result<Vec<TrustBudget>, String>, keys: &[&str]) -> Value {
    match r {
        Ok(v) => {
            let mut o = json!({"ok": true});
            for (k, b) in keys.iter().zip(v.iter()) {
                o[*k] = budget_json(b);
            }
            o
        }
        Err(reason) => json!({"ok": false, "reason": reason}),
    }
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    Ok(match f {
        "hopsRoot" => json!(hops_root(chain_of(&a[0])?)?),
        "compactChain" => compact_chain(chain_of(&a[0])?)?,
        "hopLeaf" => hop_leaf(&a[0]).ok_or("hop outside the strict profile")?,
        "compactChainShapeError" => compact_chain_shape_error(&a[0]).map_or(Value::Null, Value::String),
        "chainMemo" => memo_run(&a[0]),
        "receiptFor" => receipt_for(text(&a[0]), a[1].as_i64().ok_or("seq")?, &a[2], &a[3], a[4].as_i64())?,
        "receiptChain" => receipt_run(&a[0]),
        "semanticSignal" => json!(semantic_signal(&a[0])),
        "progressSignal" => json!(progress_signal(&a[0])),
        "objectiveSignal" => json!(objective_signal(&a[0])),
        "tightenRiskInputs" => tighten_risk_inputs(&a[0], &a[1])?,
        "recommendPolicy" => recommend_policy(a[0].as_f64().ok_or("targetActions")?, a[1].as_f64().ok_or("perActionRisk")?, a[2].as_f64())?,
        "autonomyBoundOf" => json!(autonomy_bound_of(&a[0])),
        "subBudget" => match sub_budget(&budget_of(&a[0]), a[1].as_f64().unwrap_or(f64::NAN)) {
            Ok(s) => json!({"ok": true, "sub": budget_json(&s)}),
            Err(reason) => json!({"ok": false, "reason": reason}),
        },
        "debitConsolidated" => {
            let r = debit_consolidated(&budget_of(&a[0]), &budget_of(&a[1]), a[2].as_f64().unwrap_or(f64::NAN)).map(|(p, s)| vec![p, s]);
            let mut out = budget_result(r, &["parent", "sub"]);
            // the reference spreads each input budget into its result, so members beyond B / tau / asOf ride along
            for (k, input) in [("parent", &a[0]), ("sub", &a[1])] {
                if let (Some(o), Some(i)) = (out.get_mut(k).and_then(Value::as_object_mut), input.as_object()) {
                    i.iter().filter(|(m, _)| !matches!(m.as_str(), "B" | "tau" | "asOf")).for_each(|(m, v)| {
                        o.insert(m.clone(), v.clone());
                    });
                }
            }
            out
        }
        "debitConsolidatedPath" => {
            let path: Vec<TrustBudget> = a[0].as_array().ok_or("path")?.iter().map(budget_of).collect();
            match debit_consolidated_path(&path, a[1].as_f64().unwrap_or(f64::NAN)) {
                Ok(nodes) => json!({"ok": true, "nodes": nodes.iter().map(budget_json).collect::<Vec<_>>()}),
                Err(reason) => json!({"ok": false, "reason": reason}),
            }
        }
        "rechargeFull" => budget_json(&recharge_full(a[0].as_f64().unwrap_or(f64::NAN), a[1].as_f64().unwrap_or(f64::NAN))),
        "approveClass" => {
            let verbs: Vec<&str> = a[0].as_array().ok_or("verbs")?.iter().map(text).collect();
            approve_class(&verbs, a[1].as_i64().ok_or("ttl")?, text(&a[2]), a[3].as_i64(), a[4].as_str())
        }
        "classApprovalCovers" => json!(class_approval_covers(&a[0], text(&a[1]), text(&a[2]), a[3].as_i64().ok_or("clock")?)),
        "coveredByAny" => {
            json!(covered_by_any(a[0].as_array().ok_or("approvals")?, text(&a[1]), text(&a[2]), a[3].as_i64().ok_or("clock")?))
        }
        "recordDecision" => record_decision(&a[0], text(&a[1]), text(&a[2]), a[3].as_i64()),
        "pendingRequests" => Value::Array(pending_requests(a[0].as_array().ok_or("reviews")?)),
        "applyCosign" => {
            let policy = RiskPolicy {
                rho: a[1]["rho"].as_f64().unwrap_or(f64::NAN),
                b_max: a[1]["bMax"].as_f64().unwrap_or(f64::NAN),
                ..DEFAULT_RISK_POLICY
            };
            budget_json(&apply_cosign(&budget_of(&a[0]), &policy, a[2].as_f64().unwrap_or(f64::NAN), a[3] == json!(true)))
        }
        other => panic!("unhandled corpus function {other}"),
    })
}

#[test]
fn core_sweep_rest_replay() {
    let all = common::ref_cases_seeded("core-sweep-java");
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    let mut bad = Vec::new();
    for c in &all {
        let f = text(&c["fn"]);
        if !FNS.iter().any(|(n, _)| *n == f) {
            continue;
        }
        *per_fn.entry(f.to_string()).or_default() += 1;
        let args = c["args"].as_array().unwrap();
        let got = std::panic::catch_unwind(|| run(f, args)).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    let want: BTreeMap<String, usize> = FNS.iter().map(|(k, n)| (k.to_string(), *n)).collect();
    assert_eq!(per_fn, want, "per-function case totals");
    assert!(bad.is_empty(), "{} cases differ:\n{}", bad.len(), bad.iter().take(30).cloned().collect::<Vec<_>>().join("\n"));
}
