//! Negative authority (prohibitions.ts): the constitution, the monitor and the signed safety evidence, replayed over the shared
//! prohibition-vectors.json (`constitution`, `monitor`, `evidence`). The evidence rows pin the refusal of a malformed expected
//! constitution (an invariant without a string id can never "cover" an id-less row) and of a non-string evaluated row id.
use atlas_pca::prohibitions::*;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::*;

const FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/prohibition-vectors.json");

fn doc() -> Value {
    strict_parse(&std::fs::read_to_string(FILE).unwrap()).unwrap()
}

#[test]
fn every_constitution_row_is_reproduced() {
    let d = doc();
    let rows = d["constitution"].as_array().unwrap();
    assert_eq!(rows.len(), 33);
    for v in rows {
        let problems = validate_constitution(&v["constitution"]);
        assert_eq!(json!(problems), v["expect"]["problems"], "{} problems", v["name"]);
        let r = check_prohibitions(&v["action"], &v["constitution"], &v["state"]).to_json();
        assert_eq!(r, v["expect"]["result"], "{} result", v["name"]);
    }
}

#[test]
fn every_monitor_sequence_is_reproduced() {
    for m in doc()["monitor"].as_array().unwrap() {
        let mut state = empty_state(m["genesis_now"].as_f64().unwrap());
        for (i, s) in m["steps"].as_array().unwrap().iter().enumerate() {
            let want = &s["expect"];
            if let Some(now) = s["now"].as_f64() {
                match tick_state(&state, now) {
                    Ok(t) => state = t,
                    Err(why) => {
                        assert_eq!((json!(false), json!("clock"), json!(why)), (want["allow"].clone(), want["decidedBy"].clone(), want["reason"].clone()), "{} step {i}", m["name"]);
                        continue;
                    }
                }
            }
            let r = check_and_advance(true, &s["action"], &m["constitution"], &state, None, None);
            assert_eq!(json!(r.allow), want["allow"], "{} step {i} allow", m["name"]);
            assert_eq!(json!(r.decided_by), want["decidedBy"], "{} step {i} decidedBy", m["name"]);
            assert_eq!(json!(r.prohibition.violated), want["violated"], "{} step {i} violated", m["name"]);
            assert_eq!(r.next["seq"], want["seq"], "{} step {i} seq", m["name"]);
            state = r.next;
        }
    }
}

#[test]
fn every_signed_evidence_row_is_reproduced_with_its_exact_reason() {
    let d = doc();
    let rows = d["evidence"].as_array().unwrap();
    assert_eq!(rows.len(), 13);
    for v in rows {
        let got = match verify_signed_safety_evidence(&v["signed"], &v["expected"]) {
            Ok(()) => json!({"ok": true}),
            Err(why) => json!({"ok": false, "reason": why}),
        };
        assert_eq!(got, v["expect"], "{}", v["name"]);
    }
}

#[test]
fn the_state_chain_stale_heads_and_structural_refusals() {
    let c = json!({"version": 1, "principal": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "invariants": [{"id": "a", "kind": "never", "when": {"verb": "delete"}}]});
    let act = json!({"action": {"verb": "read", "resource": "/r"}});
    let s0 = empty_state(1_700_000_000_000.0);
    let r = check_and_advance(true, &act, &c, &s0, Some(1.0), None);
    assert_eq!((r.allow, r.decided_by, r.reason.as_deref()), (false, "state", Some("stale state head (seq)")));
    let r = check_and_advance(true, &act, &c, &s0, None, Some("nope"));
    assert_eq!((r.allow, r.decided_by, r.reason.as_deref()), (false, "state", Some("stale state head (digest)")));
    let good = state_digest(&s0).unwrap();
    assert!(check_and_advance(true, &act, &c, &s0, Some(0.0), Some(&good)).allow);
    // not permitted: the monitor still runs, the decision is the permission layer's
    let r = check_and_advance(false, &act, &c, &s0, None, None);
    assert_eq!((r.allow, r.decided_by), (false, "permission"));
    // a veto wins even when permitted
    let del = json!({"action": {"verb": "delete", "resource": "/r"}});
    let r = check_and_advance(true, &del, &c, &s0, None, None);
    assert_eq!((r.allow, r.decided_by, r.next == s0), (false, "prohibition", true));
    // the chain advances and links; a clock that runs backwards is refused
    let s1 = advance_state_strict(&act, &c, &s0, None).unwrap();
    assert_eq!(s1["seq"], 1);
    assert!(s1["parent"].is_string());
    assert_eq!(advance_state_strict(&act, &c, &s1, Some(1_699_999_999_999.0)), Err("clock regression".into()));
    assert_eq!(tick_state(&json!(null), 1.0), Err("malformed monitor state".into()));
    assert_eq!(advance_state_strict(&json!({"action": {}}), &c, &s0, None), Err("malformed action".into()));
    // canonical state: an empty ledger array is the same state as no entry
    let mut with_empty = s0.clone();
    with_empty["ledger"] = json!({"x": []});
    assert_eq!(state_digest(&with_empty), state_digest(&s0));
}
