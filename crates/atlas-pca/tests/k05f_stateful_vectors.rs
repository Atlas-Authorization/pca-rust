//! The stateful layer (packages/pca/conformance/stateful-vectors.json) replayed through `authorize`: each sequence runs against ONE
//! fresh state store, the trust budget of every holder stream seeded as the vector's `setup.initial_budget` (absent = none = deny-metered,
//! stored here as an empty budget). A step's `failed` is the sorted list of the checks that failed. This is the cross-check of the
//! F2 risk / budget port against the reference.
mod common;

use atlas_pca::*;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::HashSet;

const FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/stateful-vectors.json");

fn run_sequence(seq: &Value) {
    let name = seq["name"].as_str().unwrap();
    let setup = &seq["setup"];
    let grants: Vec<Value> = setup["grants"].as_array().unwrap().clone();
    let revoked: RefCell<HashSet<String>> = RefCell::new(setup["revoked"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default());
    let store = MemoryStateStore::new();
    let empty = json!({"B": 0, "tau": 0, "asOf": 0});
    let seed = if setup["initial_budget"].is_null() { &empty } else { &setup["initial_budget"] };
    for s in seq["steps"].as_array().unwrap() {
        if s["op"] != "present" {
            continue;
        }
        let p = &s["pcactn"];
        let leaf = p["cap_chain"].as_array().and_then(|c| c.last()).and_then(|l| l["holder"].as_str());
        if let (Some(g), Some(h)) = (p["grant_ref"].as_str(), leaf) {
            if grants.iter().any(|x| x["id"] == g) {
                let key = state_key(g, h);
                if store.budget(&key).unwrap().is_none() {
                    // counter 0 is below every vector counter: this only stores the budget
                    assert_eq!(store.claim_budgeted(&key, 0, None, Some(seed)), Ok(BudgetClaim::Claimed), "{name}: seed");
                }
            }
        }
    }
    let resolve = |r: &str| Ok::<_, String>(grants.iter().find(|g| g["id"] == r).cloned());
    let is_revoked = |p: &Value, _: &Value| Ok::<_, String>(p["cap_chain"].as_array().is_some_and(|c| c.iter().any(|x| x["id"].as_str().is_some_and(|id| revoked.borrow().contains(id)))));
    let pins = common::harness_pins();
    let ctx = |_: &Value| Ok::<_, String>(Some(json!({"plan": setup["plan_nodes"], "plan_authorized": true, "risk": setup["risk"]})));
    for (i, s) in seq["steps"].as_array().unwrap().iter().enumerate() {
        if s["op"] == "revoke" {
            revoked.borrow_mut().insert(s["id"].as_str().unwrap().to_string());
            continue;
        }
        // the vectors fix the proof and the server's params (the reference runs with `insecureAllowUnboundOperation`)
        let act = &s["pcactn"]["action"];
        let op = Operation::new(act["verb"].as_str().unwrap_or(""), act["resource"].as_str().unwrap_or(""), s["params"].clone());
        let input = AuthorizeInput {
            operation: Some(&op),
            provenance_bundle: Some(&common::principal_direct),
            audience: setup["audience"].as_str().unwrap(),
            resolve_grant: Some(&resolve),
            state_store: Some(&store),
            is_revoked: Some(&is_revoked),
            context: Some(&ctx),
            now: s["now"].as_i64(),
            provenance_mediators: &pins,
            ..Default::default()
        };
        let r = authorize(Some(&s["pcactn"]), &input);
        let mut failed: Vec<&str> = r.checks.iter().filter(|(_, v)| **v == CheckStatus::Fail).map(|(k, _)| k.as_str()).collect();
        failed.sort_unstable();
        let want: Vec<&str> = s["expect"]["failed"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!((r.allow, failed.clone()), (s["expect"]["allow"].as_bool().unwrap(), want.clone()), "{name} step {i}: {:?}", r.reasons);
    }
}

#[test]
fn every_stateful_sequence_is_reproduced() {
    let d = strict_parse(&std::fs::read_to_string(FILE).unwrap()).unwrap();
    let seqs = d["stateful"].as_array().unwrap();
    assert_eq!(seqs.len(), 20);
    for s in seqs {
        run_sequence(s);
    }
}
