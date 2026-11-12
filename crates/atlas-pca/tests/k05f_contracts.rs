//! Behavioural contracts (contracts.ts, contract-enforcer.ts) replayed over the shared contracts-vectors.json: `validate`, `check`,
//! `advance` (with the next-state digest), `verify` and the durable `enforcer` scenarios; plus the `contract` gate of authorize.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use atlas_pca::contracts::*;
use atlas_pca::prohibitions::{empty_state, state_digest};
use atlas_pca::serde_json::{json, Value};
use atlas_pca::*;

const FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/contracts-vectors.json");

fn doc() -> Value {
    atlas_pca::serde_json::from_str(&std::fs::read_to_string(FILE).unwrap()).unwrap()
}

#[test]
fn the_validate_rows_are_reproduced() {
    for v in doc()["validate"].as_array().unwrap() {
        assert_eq!(json!(validate_contract(&v["contract"])), v["expect"]["problems"], "{}", v["name"]);
    }
}

#[test]
fn the_check_rows_are_reproduced() {
    for v in doc()["check"].as_array().unwrap() {
        assert_eq!(check_contract(&v["action"], &v["contract"], &v["state"]).to_json(), v["expect"], "{}", v["name"]);
    }
}

#[test]
fn the_advance_sequences_are_reproduced_with_their_state_digest() {
    for v in doc()["advance"].as_array().unwrap() {
        let mut st = empty_state(v["genesis_now"].as_f64().unwrap());
        for (i, step) in v["steps"].as_array().unwrap().iter().enumerate() {
            let mut o = AdvanceOptions { now: step["options"]["now"].as_f64(), ..Default::default() };
            if let Some(n) = step["options"]["expectedSeq"].as_f64() {
                o.expected_seq = Some(n);
            }
            if step["options"]["stale_digest_of_genesis"].as_bool() == Some(true) {
                o.expected_state_digest = state_digest(&empty_state(v["genesis_now"].as_f64().unwrap()));
            }
            let r = advance_contract(&st, &step["action"], &v["contract"], &o);
            if r.result.ok {
                st = r.next.clone();
            }
            let mut latched: Vec<&String> = r.next["latched"].as_object().unwrap().keys().collect();
            latched.sort();
            let got = json!({"ok": r.result.ok, "decidedBy": r.decided_by, "violated": r.result.violated, "reasons": r.result.reasons, "seq": r.next["seq"],
                "deadlines": r.next.get("deadlines").cloned().unwrap_or_else(|| json!({})), "latched": latched, "state_digest": state_digest(&r.next)});
            assert_eq!(got, step["expect"], "{} step {i}", v["name"]);
        }
    }
}

#[test]
fn the_verify_rows_are_reproduced() {
    for v in doc()["verify"].as_array().unwrap() {
        let r = verify_contract(&v["contract"], v["principal"].as_str());
        let got = match r {
            Ok(()) => json!({"ok": true}),
            Err(why) => json!({"ok": false, "reason": why}),
        };
        assert_eq!(got, v["expect"], "{}", v["name"]);
    }
}

fn enforcer(head: &Value, kv: &Arc<MemoryAtomicKv>, wall: &Arc<AtomicU64>, latch: bool) -> ContractEnforcer {
    let w = wall.clone();
    ContractEnforcer::open(kv.clone(), &head["contract"], head["principal"].as_str().unwrap(), None, Some(Box::new(move || f64::from_bits(w.load(Ordering::SeqCst)))), latch).unwrap()
}

fn enforce_json(r: &EnforceResult) -> Value {
    json!({"allow": r.allow, "reason": r.reason, "violated": r.violated, "reasons": r.reasons, "seq": r.seq})
}

#[test]
fn the_durable_enforcer_scenarios_are_reproduced() {
    let d = doc();
    let rows = d["enforcer"].as_array().unwrap();
    let head = &rows[0];
    let clock = head["clock"].as_f64().unwrap();
    for v in &rows[1..] {
        let kv = Arc::new(MemoryAtomicKv::new());
        let wall = Arc::new(AtomicU64::new(clock.to_bits()));
        let latch = v["options"]["latchOnViolation"].as_bool().unwrap_or(true);
        let e = enforcer(head, &kv, &wall, latch);
        if let Some(doc) = v.get("stored_document") {
            let key = format!("contract/{}", head["contract"]["id"].as_str().unwrap());
            kv.update(&key, &mut |_| Some(doc.clone())).unwrap();
        }
        for (i, st) in v["steps"].as_array().unwrap().iter().enumerate() {
            let what = format!("{} step {i}", v["name"]);
            match st["op"].as_str().unwrap() {
                "check" => {
                    wall.store(st["wall"].as_f64().unwrap_or(clock).to_bits(), Ordering::SeqCst);
                    let permitted = st["permitted"].as_bool().unwrap_or(true);
                    assert_eq!(enforce_json(&e.check(&st["action"], permitted)), st["expect"], "{what}");
                }
                "peek" => assert_eq!(enforce_json(&e.peek(&st["action"])), st["expect"], "{what}"),
                "state" => {
                    let got = match e.state().unwrap() {
                        None => Value::Null,
                        Some((s, latched)) => json!({"seq": s["seq"], "now": s["now"], "latched": latched, "state_digest": state_digest(&s)}),
                    };
                    assert_eq!(got, st["expect"], "{what}");
                }
                _ => assert_eq!(json!({"cleared": e.reset(st["sig"].as_str().unwrap())}), st["expect"], "{what}"),
            }
        }
    }
}

#[test]
fn a_reset_signature_for_another_contract_or_key_does_not_clear() {
    let d = doc();
    let head = &d["enforcer"][0];
    let kv = Arc::new(MemoryAtomicKv::new());
    let wall = Arc::new(AtomicU64::new(head["clock"].as_f64().unwrap().to_bits()));
    let e = enforcer(head, &kv, &wall, true);
    assert!(!e.check(&json!({"action": {"verb": "delete", "resource": "/r"}}), true).allow);
    let other = atlas_pca::agent::KeyPair::from_seed(&[7u8; 32]);
    assert!(!e.reset(&sign_contract_reset(&other, head["contract"]["id"].as_str().unwrap(), 0)));
    // opening needs the pinned principal and a verifying contract
    let kv2: Arc<dyn AtomicKv> = kv;
    assert_eq!(ContractEnforcer::open(kv2.clone(), &head["contract"], "", None, None, true).err().as_deref(), Some("ContractEnforcer: a pinned principal is required"));
    let wrong = atlas_pca::agent::KeyPair::from_seed(&[8u8; 32]).public;
    assert_eq!(ContractEnforcer::open(kv2, &head["contract"], &wrong, None, None, true).err().as_deref(), Some("ContractEnforcer: contract refused: principal mismatch"));
}
