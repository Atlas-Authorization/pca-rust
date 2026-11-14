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

// ---- targeted boundary, shape and fail-closed pins ------------------------------------------------------------

fn kp() -> atlas_pca::agent::KeyPair {
    atlas_pca::agent::KeyPair::from_seed(&[21u8; 32])
}

fn never(id: &str, verb: &str) -> Value {
    json!({"id": id, "kind": "never", "p": {"verb": verb}})
}

fn contract_of(clauses: Vec<Value>) -> Value {
    json!({"version": 1, "principal": kp().public, "clauses": clauses})
}

fn act(verb: &str) -> Value {
    json!({"action": {"verb": verb, "resource": "/r"}})
}

fn open_with(kv: Arc<dyn AtomicKv>, c: &Value, clock: f64) -> ContractEnforcer {
    ContractEnforcer::open(kv, c, &kp().public, None, Some(Box::new(move || clock)), true).unwrap()
}

#[test]
fn a_clause_id_of_128_utf16_units_is_fine_and_129_is_refused() {
    let check = |id: String| validate_clause(&never(&id, "x"), &mut vec![], 1);
    assert!(check("a".repeat(128)).is_empty());
    assert_eq!(check("a".repeat(129)), vec![format!("{}: id too long", "a".repeat(129))]);
    assert_eq!(check("a".repeat(130)).len(), 1);
    // length counts UTF-16 units, not chars: 64 astral chars = 128 units, 65 = 130
    assert!(check("\u{1F600}".repeat(64)).is_empty());
    assert_eq!(check("\u{1F600}".repeat(65)), vec![format!("{}: id too long", "\u{1F600}".repeat(65))]);
}

#[test]
fn responds_within_reports_a_bad_trigger_before_the_window() {
    let c = json!({"id": "r", "kind": "responds_within", "within": 2, "q": {"verb": "ack"}});
    assert_eq!(validate_clause(&c, &mut vec![], 1), vec!["r: p: not an object".to_string()]);
    let c = json!({"id": "r", "kind": "responds_within", "within": 2, "p": {"verb": "a"}});
    assert_eq!(validate_clause(&c, &mut vec![], 1), vec!["r: q: not an object".to_string()]);
}

#[test]
fn the_invariant_count_and_duplicate_ids_are_exact() {
    let inv = |i: usize| json!({"id": format!("i{i}"), "kind": "never", "when": {"verb": "w"}});
    let with = |n: usize| json!({"version": 1, "principal": kp().public, "invariants": (0..n).map(inv).collect::<Vec<_>>()});
    let max = atlas_pca::prohibitions::MAX_INVARIANTS;
    assert!(validate_contract(&with(max)).is_empty());
    assert_eq!(validate_contract(&with(max + 1)), vec!["too many invariants".to_string()]);
    assert!(validate_contract(&with(2)).is_empty(), "distinct ids are not duplicates");
    let dup = json!({"version": 1, "principal": kp().public, "invariants": [inv(1), inv(1)]});
    assert_eq!(validate_contract(&dup), vec!["i1: duplicate id".to_string()]);
}

#[test]
fn clause_counting_descends_into_and_clauses_only_and_stops_at_the_depth_bound() {
    let leaf = |i: usize| never(&format!("c{i}"), "x");
    // an `and` of 256 leaves is 257 clauses
    let big = contract_of(vec![json!({"id": "g", "kind": "and", "clauses": (0..256).map(leaf).collect::<Vec<_>>()})]);
    assert!(validate_contract(&big).contains(&"too many clauses".to_string()));
    let ok = contract_of(vec![json!({"id": "g", "kind": "and", "clauses": (0..255).map(leaf).collect::<Vec<_>>()})]);
    assert!(!validate_contract(&ok).contains(&"too many clauses".to_string()));
    // a non-`and` clause's stray `clauses` member is not counted
    let mut stray = never("s", "x");
    stray["clauses"] = json!((0..300).map(leaf).collect::<Vec<_>>());
    assert!(!validate_contract(&contract_of(vec![stray])).contains(&"too many clauses".to_string()));
    // a 20-deep chain of `and` is "too many" at once (and too deep)
    let mut cl = never("leaf", "x");
    for i in 0..20 {
        cl = json!({"id": format!("a{i}"), "kind": "and", "clauses": [cl]});
    }
    let problems = validate_contract(&contract_of(vec![cl]));
    assert!(problems.contains(&"too many clauses".to_string()), "{problems:?}");
    assert!(problems.contains(&"clause nesting too deep".to_string()));
}

#[test]
fn sign_contract_signs_a_valid_contract_and_refuses_an_invalid_one_with_every_problem() {
    let c = contract_of(vec![never("n", "x")]);
    let sc = sign_contract(&c, &kp()).unwrap();
    assert_eq!(sc["id"], json!(contract_id(&c).unwrap()));
    assert!(sc["sig"].as_str().is_some_and(|s| s.len() > 20));
    assert_eq!(verify_contract(&sc, Some(&kp().public)), Ok(()));
    let bad = json!({"version": 2, "principal": "", "clauses": []});
    assert_eq!(sign_contract(&bad, &kp()).unwrap_err(), "signContract: unsupported version 2; principal missing");
}

#[test]
fn an_and_clause_reports_its_failing_children_and_passes_when_none_fail() {
    let c = contract_of(vec![json!({"id": "g", "kind": "and", "clauses": [never("n1", "delete"), never("n2", "drop")]})]);
    let r = check_contract(&act("delete"), &c, &empty_state(1.0));
    assert!(!r.ok);
    assert_eq!(r.violated, vec!["n1".to_string()]);
    assert_eq!(r.reasons, vec!["n1: never-invariant violated (forbidden action)".to_string()]);
    assert_eq!(r.evaluated.len(), 2);
    assert!(check_contract(&act("read"), &c, &empty_state(1.0)).ok);
}

#[test]
fn a_stale_head_on_a_malformed_state_names_the_state_once() {
    let c = contract_of(vec![never("n", "x")]);
    let o = AdvanceOptions { expected_seq: Some(0.0), ..Default::default() };
    let r = advance_contract(&json!(5), &act("read"), &c, &o);
    assert!(!r.result.ok);
    assert_eq!(r.decided_by, "state");
    assert_eq!(r.result.violated, vec!["<state>".to_string()]);
    assert_eq!(r.result.reasons.len(), 2);
    assert_eq!(r.result.reasons[1], "<state>: stale state head (seq)");
    assert_eq!(r.next, json!(5));
}

#[test]
fn only_a_fully_bracketed_violated_id_is_decided_by_the_state() {
    for id in ["<half", "half>"] {
        let c = contract_of(vec![never(id, "delete")]);
        let r = advance_contract(&empty_state(1.0), &act("delete"), &c, &AdvanceOptions::default());
        assert_eq!((r.result.violated.clone(), r.decided_by), (vec![id.to_string()], "contract"), "{id}");
    }
    let c = contract_of(vec![never("n", "delete")]);
    let r = advance_contract(&empty_state(1.0), &json!({"action": {}}), &c, &AdvanceOptions::default());
    assert_eq!((r.result.violated, r.decided_by), (vec!["<action>".to_string()], "state"));
}

#[test]
fn a_resulting_state_that_is_invalid_refuses_the_advance() {
    let mut st = empty_state(5.0);
    for i in 0..1024 {
        st["latched"][format!("k{i}")] = json!(0);
    }
    let c = contract_of(vec![json!({"id": "pre", "kind": "precedes", "p": {"verb": "review"}, "q": {"verb": "deploy"}})]);
    let r = advance_contract(&st, &act("review"), &c, &AdvanceOptions::default());
    assert!(!r.result.ok);
    assert_eq!(r.decided_by, "state");
    assert!(r.result.reasons.last().unwrap().starts_with("<state>: resulting state invalid:"), "{:?}", r.result.reasons);
    assert_eq!(r.next, st);
}

fn valid_doc(c: &Value) -> Value {
    json!({"v": 1, "contract_id": c["id"], "state": empty_state(5.0)})
}

fn state_of(c: &Value, doc: Value) -> Result<bool, String> {
    let kv = Arc::new(MemoryAtomicKv::new());
    let key = format!("contract/{}", c["id"].as_str().unwrap());
    kv.update(&key, &mut |_| Some(doc.clone())).unwrap();
    open_with(kv, c, 5.0).state().map(|s| s.is_some_and(|(_, l)| l))
}

#[test]
fn a_stored_document_is_accepted_only_when_every_part_is_well_formed() {
    let c = sign_contract(&contract_of(vec![never("n", "x")]), &kp()).unwrap();
    let corrupt = "ContractEnforcer: stored state is corrupt or belongs to another contract".to_string();
    assert_eq!(state_of(&c, valid_doc(&c)), Ok(false));
    let mut d = valid_doc(&c);
    d["v"] = json!(2);
    assert_eq!(state_of(&c, d), Err(corrupt.clone()));
    for v in [json!("1"), json!(true), Value::Null] {
        let mut d = valid_doc(&c);
        d["v"] = v;
        assert_eq!(state_of(&c, d), Err(corrupt.clone()));
    }
    let mut d = valid_doc(&c);
    d.as_object_mut().unwrap().remove("v");
    assert_eq!(state_of(&c, d), Err(corrupt.clone()));
    let mut d = valid_doc(&c);
    d["contract_id"] = json!("other");
    assert_eq!(state_of(&c, d), Err(corrupt.clone()));
    let mut d = valid_doc(&c);
    d["state"] = json!({});
    assert_eq!(state_of(&c, d), Err(corrupt.clone()));
    assert_eq!(state_of(&c, json!([1])), Err(corrupt.clone()));
    // the latch record
    let latched = |l: Value| {
        let mut d = valid_doc(&c);
        d["latched"] = l;
        state_of(&c, d)
    };
    assert_eq!(latched(json!({"seq": 3, "violated": ["n"]})), Ok(true));
    assert_eq!(latched(json!({"seq": 0, "violated": []})), Ok(true));
    for bad in [json!(5), Value::Null, json!({}), json!({"seq": 1.5, "violated": []}), json!({"seq": -0.0, "violated": []}), json!({"seq": "1", "violated": []}),
        json!({"seq": 1}), json!({"seq": 1, "violated": [1]}), json!({"seq": 1, "violated": "n"}), json!({"violated": []})] {
        assert_eq!(latched(bad.clone()), Err(corrupt.clone()), "{bad}");
    }
}

struct FailingKv {
    panic: bool,
}

impl AtomicKv for FailingKv {
    fn get(&self, _: &str) -> Result<Option<Value>, StoreError> {
        Err(StoreError("down".into()))
    }

    fn update(&self, _: &str, _: &mut dyn FnMut(Option<&Value>) -> Option<Value>) -> Result<Option<Value>, StoreError> {
        if self.panic {
            panic!("store blew up");
        }
        Err(StoreError("down".into()))
    }
}

#[test]
fn a_failing_or_panicking_store_denies_with_the_store_error_text() {
    let c = sign_contract(&contract_of(vec![never("n", "x")]), &kp()).unwrap();
    for panic in [false, true] {
        let e = open_with(Arc::new(FailingKv { panic }), &c, 5.0);
        let r = e.check(&act("read"), true);
        assert_eq!((r.allow, r.reason, r.reasons, r.seq), (false, "store-error", vec!["store error (fail closed)".to_string()], 0), "panic={panic}");
    }
    let r = open_with(Arc::new(FailingKv { panic: false }), &c, 5.0).peek(&act("read"));
    assert_eq!((r.allow, r.reason, r.reasons), (false, "store-error", vec!["store error (fail closed)".to_string()]));
}

#[test]
fn check_answers_ok_permission_violated_and_state_error_distinctly() {
    let c = sign_contract(&contract_of(vec![never("n", "delete")]), &kp()).unwrap();
    let ok = open_with(Arc::new(MemoryAtomicKv::new()), &c, 5.0);
    let r = ok.check(&act("read"), true);
    assert_eq!((r.allow, r.reason, r.seq), (true, "ok", 1));
    let r = ok.check(&act("read"), false);
    assert_eq!((r.allow, r.reason, r.violated, r.reasons, r.seq), (false, "permission", vec![], vec!["<permission>: not permitted".to_string()], 1));
    let r = ok.check(&json!({"action": {}}), true);
    assert_eq!((r.allow, r.reason, r.violated, r.seq), (false, "state-error", Vec::<String>::new(), 1));
    let r = ok.check(&act("delete"), true);
    assert_eq!((r.allow, r.reason, r.violated, r.seq), (false, "violated", vec!["n".to_string()], 1));
}

#[test]
fn a_non_numeric_clock_never_admits_an_action() {
    let c = sign_contract(&contract_of(vec![never("n", "delete")]), &kp()).unwrap();
    let r = open_with(Arc::new(MemoryAtomicKv::new()), &c, f64::NAN).check(&act("read"), true);
    assert_eq!((r.allow, r.reason), (false, "state-error"));
    // a NaN clock against a stored document is refused up front
    let kv: Arc<dyn AtomicKv> = Arc::new(MemoryAtomicKv::new());
    open_with(kv.clone(), &c, 5.0).check(&act("read"), true);
    let r = open_with(kv, &c, f64::NAN).check(&act("read"), true);
    assert_eq!((r.allow, r.reason, r.reasons), (false, "state-error", vec!["<state>: clock is not finite".to_string()]));
}

#[test]
fn a_latch_is_cleared_only_by_the_principals_signature_at_that_sequence_and_peek_reports_it() {
    let c = sign_contract(&contract_of(vec![never("n", "delete")]), &kp()).unwrap();
    let id = c["id"].as_str().unwrap();
    let e = open_with(Arc::new(MemoryAtomicKv::new()), &c, 5.0);
    assert_eq!(e.check(&act("read"), true).seq, 1);
    let r = e.check(&act("delete"), true);
    assert_eq!((r.allow, r.reason, r.seq), (false, "violated", 1));
    let r = e.peek(&act("read"));
    assert_eq!((r.allow, r.reason, r.violated, r.reasons, r.seq), (false, "latched", vec!["n".to_string()], vec!["<latched>: contract violated at seq 1".to_string()], 1));
    let good = sign_contract_reset(&kp(), id, 1);
    assert!(good.len() > 20 && good != "xyzzy");
    assert!(!e.reset(&sign_contract_reset(&kp(), id, 0)), "a signature for another sequence");
    assert!(!e.reset(&good[..good.len() - 2]));
    assert!(e.reset(&good));
    assert!(e.peek(&act("read")).allow);
    assert!(e.check(&act("read"), true).allow);
}

#[test]
fn peek_allows_a_clean_action_on_an_empty_store_even_with_a_non_numeric_clock() {
    let c = sign_contract(&contract_of(vec![never("n", "delete")]), &kp()).unwrap();
    let r = open_with(Arc::new(MemoryAtomicKv::new()), &c, 5.0).peek(&act("read"));
    assert_eq!((r.allow, r.reason, r.seq), (true, "ok", 0));
    let r = open_with(Arc::new(MemoryAtomicKv::new()), &c, f64::NAN).peek(&act("read"));
    assert_eq!((r.allow, r.reason), (true, "ok"));
    let r = open_with(Arc::new(MemoryAtomicKv::new()), &c, 5.0).peek(&act("delete"));
    assert_eq!((r.allow, r.reason, r.violated), (false, "violated", vec!["n".to_string()]));
}
