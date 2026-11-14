//! Boundary and refusal tests for the constitution / monitor / signed-evidence module: every numeric bound at n-1, n, n+1, every
//! refusal with its exact reason, and the state-advance edge cases (window pruning, ledger overflow, latches).
use atlas_pca::prohibitions::*;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

const P: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const NOW: f64 = 1_700_000_000_000.0;

fn cons(invs: Value) -> Value {
    json!({"version": 1, "principal": P, "invariants": invs})
}

fn vi(i: Value) -> Vec<String> {
    validate_invariant(&i)
}

fn one(s: &str) -> Vec<String> {
    vec![s.to_string()]
}

fn cap() -> Value {
    json!({"id": "c", "kind": "cap", "when": {"verb": "pay"}, "amount": "action.params.usd", "max": 5})
}

fn rate() -> Value {
    json!({"id": "r", "kind": "rate", "when": {"verb": "call"}, "max": 5, "window_secs": 60})
}

fn approval() -> Value {
    json!({"id": "a", "kind": "require_approval_over", "when": {"verb": "pay"}, "amount": "action.params.usd", "threshold": 10,
        "approved": [{"field": "action.params.approved", "op": "eq", "value": true}]})
}

fn with(mut base: Value, k: &str, v: Value) -> Value {
    base[k] = v;
    base
}

fn st(now: f64, ledger: Value, latched: Value) -> Value {
    json!({"now": now, "seq": 0, "parent": null, "ledger": ledger, "latched": latched})
}

fn pay(usd: i64) -> Value {
    json!({"action": {"verb": "pay", "resource": "/x", "params": {"usd": usd}}})
}

// ---- validate_invariant -----------------------------------------------------------------------------------------------

#[test]
fn an_id_is_measured_in_utf16_units() {
    let mk = |id: &str| json!({"id": id, "kind": "never", "when": {"verb": "x"}});
    assert!(vi(mk(&"a".repeat(128))).is_empty());
    let long = "a".repeat(129);
    assert_eq!(vi(mk(&long)), vec![format!("{long}: id too long")]);
    assert!(vi(mk(&"\u{1F600}".repeat(64))).is_empty());
    let long = "\u{1F600}".repeat(65);
    assert_eq!(vi(mk(&long)), vec![format!("{long}: id too long")]);
}

#[test]
fn the_cap_max_bound_is_zero() {
    assert!(vi(cap()).is_empty());
    assert!(vi(with(cap(), "max", json!(0))).is_empty());
    assert_eq!(vi(with(cap(), "max", json!(-1))), one("c: max must be a finite number >= 0"));
    assert_eq!(vi(with(cap(), "max", json!(-0.5))), one("c: max must be a finite number >= 0"));
}

#[test]
fn the_rate_max_bound_is_the_ledger_size() {
    assert!(vi(with(rate(), "max", json!(0))).is_empty());
    assert!(vi(with(rate(), "max", json!(9999))).is_empty());
    assert!(vi(with(rate(), "max", json!(10000))).is_empty());
    for bad in [json!(10001), json!(-1), json!(1.5), json!(-0.0), json!("5")] {
        assert_eq!(vi(with(rate(), "max", bad.clone())), one("r: max must be an integer in [0,10000]"), "{bad}");
    }
}

#[test]
fn the_approval_threshold_bound_is_zero() {
    assert!(vi(approval()).is_empty());
    assert!(vi(with(approval(), "threshold", json!(0))).is_empty());
    assert_eq!(vi(with(approval(), "threshold", json!(-1))), one("a: threshold must be a finite number >= 0"));
    assert_eq!(vi(with(approval(), "threshold", json!("x"))), one("a: threshold must be a finite number >= 0"));
}

#[test]
fn a_bad_trigger_is_refused_in_every_kind_that_has_one() {
    for inv in [cap(), rate(), approval()] {
        let id = inv["id"].as_str().unwrap().to_string();
        assert_eq!(vi(with(inv, "when", json!({}))), vec![format!("{id}: when: bad verb")]);
    }
}

#[test]
fn the_amount_must_be_an_action_path() {
    for inv in [cap(), approval()] {
        let id = inv["id"].as_str().unwrap().to_string();
        for bad in [json!("params.usd"), json!(5), json!("")] {
            assert_eq!(vi(with(inv.clone(), "amount", bad)), vec![format!("{id}: amount must be an action.* path")]);
        }
        let mut gone = inv.clone();
        gone.as_object_mut().unwrap().remove("amount");
        assert_eq!(vi(gone), vec![format!("{id}: amount must be an action.* path")]);
    }
}

#[test]
fn condition_lists_must_be_non_empty_and_well_formed() {
    let nu = |unless: Option<Value>| {
        let mut i = json!({"id": "u", "kind": "never_unless", "when": {"verb": "x"}});
        if let Some(u) = unless {
            i["unless"] = u;
        }
        i
    };
    assert_eq!(vi(nu(None)), one("u: unless must be a non-empty array"));
    assert_eq!(vi(nu(Some(json!([])))), one("u: unless must be a non-empty array"));
    assert_eq!(vi(nu(Some(json!({})))), one("u: unless must be a non-empty array"));
    assert!(vi(nu(Some(json!([{"field": "action.a", "op": "eq", "value": 1}])))).is_empty());
    assert_eq!(vi(nu(Some(json!([{"field": "action.a"}])))), one("u: unknown condition op undefined"));
    assert_eq!(vi(nu(Some(json!([5])))), one("u: condition not an object"));
    assert_eq!(vi(with(approval(), "approved", json!([]))), one("a: approved must be a non-empty array"));
    let mut gone = approval();
    gone.as_object_mut().unwrap().remove("approved");
    assert_eq!(vi(gone), one("a: approved must be a non-empty array"));
    assert_eq!(vi(with(approval(), "approved", json!([{"op": "eq"}]))), one("a: condition.field missing"));
}

#[test]
fn a_constitution_holds_at_most_256_invariants() {
    let mk = |n: usize| cons(Value::Array((0..n).map(|i| json!({"id": format!("i{i}"), "kind": "never", "when": {"verb": "x"}})).collect()));
    assert!(validate_constitution(&mk(255)).is_empty());
    assert!(validate_constitution(&mk(256)).is_empty());
    assert_eq!(validate_constitution(&mk(257)), one("too many invariants"));
}

// ---- num_value --------------------------------------------------------------------------------------------------------

#[test]
fn num_value_keeps_fractions_and_unsafe_integers_as_floats() {
    assert_eq!(num_value(1.5), json!(1.5));
    assert_eq!(num_value(-2.5), json!(-2.5));
    assert!(num_value(7.0).is_i64());
    assert!(num_value(9_007_199_254_740_991.0).is_i64());
    assert!(num_value(-9_007_199_254_740_991.0).is_i64());
    assert!(num_value(9_007_199_254_740_992.0).is_f64());
    assert!(num_value(-9_007_199_254_740_992.0).is_f64());
}

// ---- verify_constitution ----------------------------------------------------------------------------------------------

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(k: &SigningKey) -> String {
    URL_SAFE_NO_PAD.encode(k.verifying_key().to_bytes())
}

fn sign(k: &SigningKey, domain: &str, id: &str) -> String {
    let mut msg = domain.as_bytes().to_vec();
    msg.extend(Sha256::digest(id.as_bytes()));
    URL_SAFE_NO_PAD.encode(k.sign(&msg).to_bytes())
}

fn sign_body(mut sc: Value, k: &SigningKey) -> Value {
    let id = constitution_id(&sc).unwrap();
    sc["sig"] = json!(sign(k, CONSTITUTION_SIG_DOMAIN, &id));
    sc["id"] = json!(id);
    sc
}

fn signed_constitution(k: &SigningKey) -> Value {
    sign_body(json!({"version": 1, "principal": public(k), "invariants": [
        {"id": "spend-day", "kind": "cap", "when": {"verb": "pay", "resource": "*"}, "amount": "action.params.usd", "max": 100, "window_secs": 86400}]}), k)
}

#[test]
fn a_signed_constitution_verifies_only_whole() {
    let k = key(1);
    let sc = signed_constitution(&k);
    assert_eq!(verify_constitution(&sc, None), Ok(()));
    assert_eq!(verify_constitution(&sc, Some(&public(&k))), Ok(()));
    assert_eq!(verify_constitution(&sc, Some(&public(&key(2)))), Err("principal mismatch".to_string()));
    assert_eq!(verify_constitution(&sc, Some("")), Err("principal mismatch".to_string()));
}

#[test]
fn a_structurally_invalid_constitution_is_refused_even_when_correctly_signed() {
    let k = key(1);
    let bad_version = sign_body(json!({"version": 2, "principal": public(&k), "invariants": []}), &k);
    assert_eq!(verify_constitution(&bad_version, None), Err("unsupported version 2".to_string()));
    let bad_kind = sign_body(json!({"version": 1, "principal": public(&k), "invariants": [{"id": "x", "kind": "eventually", "when": {"verb": "v"}}]}), &k);
    assert_eq!(verify_constitution(&bad_kind, None), Err("x: unknown invariant kind eventually".to_string()));
}

#[test]
fn the_id_must_match_the_content() {
    let sc = signed_constitution(&key(1));
    let mut wrong = sc.clone();
    wrong["id"] = json!("x");
    let mut number = sc.clone();
    number["id"] = json!(5);
    let mut absent = sc.clone();
    absent.as_object_mut().unwrap().remove("id");
    let mut edited = sc.clone();
    edited["invariants"][0]["max"] = json!(101);
    for (name, c) in [("wrong", wrong), ("number", number), ("absent", absent), ("edited", edited)] {
        assert_eq!(verify_constitution(&c, None), Err("id does not match content".to_string()), "{name}");
    }
}

#[test]
fn the_signature_must_verify() {
    let sc = signed_constitution(&key(1));
    let mut other_key = sc.clone();
    other_key["sig"] = json!(sign(&key(9), CONSTITUTION_SIG_DOMAIN, sc["id"].as_str().unwrap()));
    let mut absent = sc.clone();
    absent.as_object_mut().unwrap().remove("sig");
    let mut number = sc.clone();
    number["sig"] = json!(5);
    let mut garbage = sc.clone();
    garbage["sig"] = json!("AAAA");
    for (name, c) in [("other key", other_key), ("absent", absent), ("number", number), ("garbage", garbage)] {
        assert_eq!(verify_constitution(&c, None), Err("bad signature".to_string()), "{name}");
    }
}

// ---- state_problem ----------------------------------------------------------------------------------------------------

fn problem(s: &Value) -> Option<String> {
    state_problem(s)
}

fn set_in(mut s: Value, field: &str, key: &str, val: Value) -> Value {
    s[field] = json!({ key: val });
    s
}

#[test]
fn a_state_key_is_bounded_in_utf16_units_and_never_a_prototype_name() {
    let base = st(NOW, json!({}), json!({}));
    let cases = [("ledger", json!([]), "ledger"), ("latched", json!(0), "latch"), ("deadlines", json!(1), "deadline")];
    for (field, val, what) in cases {
        for ok in ["k".repeat(128), "\u{1F600}".repeat(64)] {
            assert_eq!(problem(&set_in(base.clone(), field, &ok, val.clone())), None, "{field} ok");
        }
        for bad in ["k".repeat(129), "\u{1F600}".repeat(65), "__proto__".into(), "constructor".into(), "prototype".into()] {
            assert_eq!(problem(&set_in(base.clone(), field, &bad, val.clone())), Some(format!("malformed monitor state: bad {what} key")), "{field} {}", bad.len());
        }
    }
}

#[test]
fn state_key_counts_are_bounded_at_1024() {
    let many = |n: usize, v: Value| Value::Object((0..n).map(|i| (format!("k{i}"), v.clone())).collect());
    assert_eq!(problem(&st(NOW, many(1024, json!([])), json!({}))), None);
    assert_eq!(problem(&st(NOW, many(1025, json!([])), json!({}))), Some("malformed monitor state: too many keys".into()));
    assert_eq!(problem(&st(NOW, json!({}), many(1024, json!(0)))), None);
    assert_eq!(problem(&st(NOW, json!({}), many(1025, json!(0)))), Some("malformed monitor state: too many keys".into()));
    let mut s = st(NOW, json!({}), json!({}));
    s["deadlines"] = many(1024, json!(1));
    assert_eq!(problem(&s), None);
    s["deadlines"] = many(1025, json!(1));
    assert_eq!(problem(&s), Some("malformed monitor state: too many deadline keys".into()));
}

fn big_ledger(keys: usize, per: usize, extra: usize) -> Value {
    let entries = |n: usize| Value::Array((0..n).map(|_| json!({"t": 0, "amount": 0})).collect());
    let mut m = atlas_pca::serde_json::Map::new();
    for i in 0..keys {
        m.insert(format!("k{i}"), entries(per));
    }
    if extra > 0 {
        m.insert("extra".into(), entries(extra));
    }
    Value::Object(m)
}

#[test]
fn the_total_ledger_entry_count_is_bounded_at_100000() {
    assert_eq!(problem(&st(NOW, big_ledger(10, 10_000, 0), json!({}))), None);
    assert_eq!(problem(&st(NOW, big_ledger(10, 10_000, 1), json!({}))), Some("malformed monitor state: too many entries".into()));
    assert_eq!(problem(&st(NOW, big_ledger(11, 10_000, 0), json!({}))), Some("malformed monitor state: too many entries".into()));
    assert_eq!(problem(&st(NOW, big_ledger(1, 10_001, 0), json!({}))), Some("malformed monitor state: bad ledger".into()));
}

#[test]
fn a_ledger_entry_needs_a_non_negative_amount_and_a_time_not_after_now() {
    let one_entry = |e: Value| st(NOW, json!({"c": [e]}), json!({}));
    assert_eq!(problem(&one_entry(json!({"t": 0, "amount": 0}))), None);
    assert_eq!(problem(&one_entry(json!({"t": NOW - 1.0, "amount": 1}))), None);
    assert_eq!(problem(&one_entry(json!({"t": NOW, "amount": 1}))), None);
    assert_eq!(problem(&one_entry(json!({"t": NOW + 1.0, "amount": 1}))), Some("malformed monitor state: ledger entry after now (clock regression)".into()));
    assert_eq!(problem(&one_entry(json!({"t": 0, "amount": -1}))), Some("malformed monitor state: bad ledger entry".into()));
    assert_eq!(problem(&one_entry(json!({"t": 0}))), Some("malformed monitor state: bad ledger entry".into()));
    assert_eq!(problem(&one_entry(json!(5))), Some("malformed monitor state: bad ledger entry".into()));
}

#[test]
fn a_latch_time_is_a_number_not_after_now() {
    let latch = |t: Value| st(NOW, json!({}), json!({"l": t}));
    assert_eq!(problem(&latch(json!(NOW - 1.0))), None);
    assert_eq!(problem(&latch(json!(NOW))), None);
    assert_eq!(problem(&latch(json!(NOW + 1.0))), Some("malformed monitor state: bad latch".into()));
    assert_eq!(problem(&latch(json!("1"))), Some("malformed monitor state: bad latch".into()));
}

#[test]
fn deadlines_must_be_an_object_of_integral_budgets() {
    let dl = |d: Value| {
        let mut s = st(NOW, json!({}), json!({}));
        s["deadlines"] = d;
        s
    };
    assert_eq!(problem(&dl(json!({"d": 1}))), None);
    assert_eq!(problem(&dl(json!({"d": 1_000_000}))), None);
    assert_eq!(problem(&dl(json!(5))), Some("malformed monitor state: deadlines".into()));
    assert_eq!(problem(&dl(json!([]))), Some("malformed monitor state: deadlines".into()));
    for bad in [json!(0), json!(1_000_001), json!(1.5), json!(-1), json!("1")] {
        assert_eq!(problem(&dl(json!({"d": bad.clone()}))), Some("malformed monitor state: bad deadline".into()), "{bad}");
    }
}

#[test]
fn seq_is_a_non_negative_integer_and_never_negative_zero() {
    let with_seq = |seq: Value, parent: Value| {
        let mut s = st(NOW, json!({}), json!({}));
        s["seq"] = seq;
        s["parent"] = parent;
        s
    };
    assert_eq!(problem(&with_seq(json!(0), json!(null))), None);
    assert_eq!(problem(&with_seq(json!(2), json!("p"))), None);
    for bad in [json!(1.5), json!(-0.0), json!(-1), json!("0"), json!(null)] {
        assert_eq!(problem(&with_seq(bad.clone(), json!(null))), Some("malformed monitor state: seq".into()), "{bad}");
    }
    assert_eq!(canonical_state(&with_seq(json!(-1), json!(null))), Err("malformed monitor state: seq".into()));
    assert_eq!(state_digest(&with_seq(json!(-1), json!(null))), None);
}

#[test]
fn tick_state_allows_the_same_instant_and_refuses_the_past() {
    let s = empty_state(NOW);
    assert_eq!(tick_state(&s, NOW), Ok(s.clone()));
    assert_eq!(tick_state(&s, NOW + 5.0).unwrap()["now"], num_value(NOW + 5.0));
    assert_eq!(tick_state(&s, NOW - 1.0), Err("clock regression".into()));
    assert_eq!(tick_state(&s, f64::NAN), Err("clock regression".into()));
}

// ---- the monitor window -----------------------------------------------------------------------------------------------

#[test]
fn a_ledger_entry_exactly_at_the_window_edge_is_outside_it() {
    let c = cons(json!([with(rate(), "max", json!(1))]));
    let call = json!({"action": {"verb": "call", "resource": "/x"}});
    let at = |t: f64| check_prohibitions(&call, &c, &st(NOW, json!({"r": [{"t": t, "amount": 1}]}), json!({})));
    let edge = at(NOW - 60_000.0);
    assert!(edge.ok);
    let inside = at(NOW - 59_999.0);
    assert!(!inside.ok);
    assert_eq!(inside.reasons, one("r: rate exceeded: 2 > 1 per 60s"));
}

// ---- advance_state_strict ---------------------------------------------------------------------------------------------

fn advance(c: &Value, a: &Value, s: &Value) -> Result<Value, String> {
    advance_state_strict(a, c, s, None)
}

fn read() -> Value {
    json!({"action": {"verb": "read", "resource": "/x", "params": {"usd": 1}}})
}

#[test]
fn window_pruning_drops_the_edge_entry_and_keeps_the_inside_one() {
    let c = cons(json!([with(cap(), "window_secs", json!(60)), rate()]));
    let s = st(NOW, json!({"c": [{"t": NOW - 60_000.0, "amount": 1}], "r": [{"t": NOW - 60_000.0, "amount": 1}]}), json!({}));
    assert_eq!(advance(&c, &read(), &s).unwrap()["ledger"], json!({}));
    let s = st(NOW, json!({"c": [{"t": NOW - 59_999.0, "amount": 1}]}), json!({}));
    assert_eq!(advance(&c, &read(), &s).unwrap()["ledger"], json!({"c": [{"t": num_value(NOW - 59_999.0), "amount": 1}]}));
}

#[test]
fn only_a_matching_action_adds_a_ledger_entry() {
    let c = cons(json!([cap(), rate()]));
    let s = empty_state(NOW);
    assert_eq!(advance(&c, &read(), &s).unwrap()["ledger"], json!({}));
    assert_eq!(advance(&c, &pay(3), &s).unwrap()["ledger"], json!({"c": [{"t": num_value(NOW), "amount": 3}]}));
    let call = json!({"action": {"verb": "call", "resource": "/x"}});
    assert_eq!(advance(&c, &call, &s).unwrap()["ledger"], json!({"r": [{"t": num_value(NOW), "amount": 1}]}));
}

fn full(n: usize, t0: f64, amounts: impl Fn(usize) -> i64) -> Value {
    Value::Array((0..n).map(|i| json!({"t": t0 + i as f64, "amount": amounts(i)})).collect())
}

#[test]
fn a_cap_ledger_over_the_limit_merges_the_two_oldest_keeping_the_later_time() {
    let big = json!({"id": "c", "kind": "cap", "when": {"verb": "pay"}, "amount": "action.params.usd", "max": 1_000_000_000_000i64});
    let c = cons(json!([big]));
    let s = st(NOW, json!({"c": full(10_000, 1000.0, |i| match i { 0 => 2, 1 => 3, _ => 1 })}), json!({}));
    let next = advance(&c, &pay(5), &s).unwrap();
    let l = next["ledger"]["c"].as_array().unwrap();
    assert_eq!(l.len(), 10_000);
    assert_eq!(l[0], json!({"t": 1001, "amount": 5}));
    assert_eq!(l[1], json!({"t": 1002, "amount": 1}));
    assert_eq!(l[9_999], json!({"t": num_value(NOW), "amount": 5}));
    // exactly full is not an overflow
    let s = st(NOW, json!({"c": full(9_999, 1000.0, |_| 1)}), json!({}));
    assert_eq!(advance(&c, &pay(5), &s).unwrap()["ledger"]["c"].as_array().unwrap().len(), 10_000);
}

#[test]
fn a_rate_ledger_over_the_limit_is_refused_and_exactly_full_is_not() {
    let r = json!({"id": "r", "kind": "rate", "when": {"verb": "call"}, "max": 10000, "window_secs": 1_000_000});
    let c = cons(json!([r]));
    let call = json!({"action": {"verb": "call", "resource": "/x"}});
    let s = st(NOW, json!({"r": full(10_000, NOW - 20_000.0, |_| 1)}), json!({}));
    assert_eq!(advance(&c, &call, &s), Err("r: rate ledger overflow".into()));
    let s = st(NOW, json!({"r": full(9_999, NOW - 20_000.0, |_| 1)}), json!({}));
    assert_eq!(advance(&c, &call, &s).unwrap()["ledger"]["r"].as_array().unwrap().len(), 10_000);
}

#[test]
fn an_advance_whose_resulting_state_is_invalid_is_refused() {
    let mut invs: Vec<Value> = (0..10).map(|i| json!({"id": format!("c{i}"), "kind": "cap", "when": {"verb": "other"}, "amount": "action.params.usd", "max": 1_000_000_000_000i64})).collect();
    invs.push(json!({"id": "c10", "kind": "cap", "when": {"verb": "pay"}, "amount": "action.params.usd", "max": 1_000_000_000_000i64}));
    let c = cons(Value::Array(invs));
    let mut ledger = atlas_pca::serde_json::Map::new();
    for i in 0..10 {
        ledger.insert(format!("c{i}"), full(10_000, 1000.0, |_| 1));
    }
    let s = st(NOW, Value::Object(ledger), json!({}));
    assert_eq!(advance(&c, &pay(1), &s), Err("resulting state invalid".into()));
    assert!(advance(&c, &read(), &s).is_ok());
}

#[test]
fn advance_refuses_an_invalid_constitution_or_state_before_anything_else() {
    let s = empty_state(NOW);
    let bad_kind = cons(json!([{"id": "x", "kind": "eventually", "when": {"verb": "v"}}]));
    assert_eq!(advance(&bad_kind, &read(), &s), Err("x: unknown invariant kind eventually".into()));
    let bad_state = with(empty_state(NOW), "seq", json!(-1));
    let malformed = json!({"action": {}});
    assert_eq!(advance(&cons(json!([])), &malformed, &bad_state), Err("malformed monitor state: seq".into()));
    assert_eq!(advance(&cons(json!([])), &malformed, &s), Err("malformed action".into()));
    // the constitution is checked before the state
    assert_eq!(advance(&bad_kind, &malformed, &bad_state), Err("x: unknown invariant kind eventually".into()));
}

#[test]
fn a_latch_is_set_once_and_only_by_a_matching_action() {
    let na = json!({"id": "na", "kind": "never_after", "after": {"verb": "export"}, "forbid": {"verb": "delete"}});
    let rp = json!({"id": "rp", "kind": "require_prior", "when": {"verb": "deploy"}, "prior": {"verb": "review"}});
    let act = |v: &str| json!({"action": {"verb": v, "resource": "/x"}});
    for (inv, hit, miss) in [(na, "export", "read"), (rp, "review", "read")] {
        let id = inv["id"].as_str().unwrap().to_string();
        let c = cons(json!([inv]));
        let fresh = empty_state(1000.0);
        assert_eq!(advance_state_strict(&act(hit), &c, &fresh, Some(2000.0)).unwrap()["latched"], json!({ &id: 2000 }), "{id} latches");
        assert_eq!(advance_state_strict(&act(miss), &c, &fresh, Some(2000.0)).unwrap()["latched"], json!({}), "{id} miss");
        let latched = st(1000.0, json!({}), json!({ &id: 500 }));
        assert_eq!(advance_state_strict(&act(hit), &c, &latched, Some(2000.0)).unwrap()["latched"], json!({ &id: 500 }), "{id} keeps the first latch");
    }
}

// ---- safety evidence --------------------------------------------------------------------------------------------------

fn signed_evidence(evidence: &Value, k: &SigningKey) -> Value {
    let signer = public(k);
    let id = safety_binding_id(evidence, &signer).unwrap();
    json!({"evidence": evidence, "signer": signer, "id": id, "sig": sign(k, SAFETY_EVIDENCE_SIG_DOMAIN, &id)})
}

/// (signed evidence, expected bundle, evidence, action, constitution, state)
fn bundle() -> (Value, Value, Value, Value, Value, Value) {
    let (principal, signer) = (key(1), key(2));
    let sc = signed_constitution(&principal);
    let (action, state) = (pay(1), empty_state(NOW));
    let ev = prove_safety(&action, &sc, &state);
    let signed = signed_evidence(&ev, &signer);
    let expected = json!({"signer": public(&signer), "action": action, "constitution": sc, "state": state});
    (signed, expected, ev, action, sc, state)
}

fn no(why: &str) -> Result<(), String> {
    Err(why.to_string())
}

#[test]
fn a_violated_state_is_listed_once_in_the_evidence() {
    let bad_state = with(empty_state(NOW), "seq", json!(-1));
    let ev = prove_safety(&pay(1), &cons(json!([])), &bad_state);
    assert_eq!(ev["violated"], json!(["<state>"]));
    assert_eq!(ev["ok"], json!(false));
}

#[test]
fn verify_safety_evidence_names_each_refusal() {
    let (_, _, ev, action, sc, state) = bundle();
    assert_eq!(verify_safety_evidence(&ev, &action, &sc, &state), Ok(()));
    for v in [json!(2), json!(true), json!("1"), json!(null), json!(1.5)] {
        assert_eq!(verify_safety_evidence(&with(ev.clone(), "v", v.clone()), &action, &sc, &state), no("unsupported evidence version"), "{v}");
    }
    assert_eq!(verify_safety_evidence(&json!(null), &action, &sc, &state), no("unsupported evidence version"));
    assert_eq!(verify_safety_evidence(&ev, &action, &signed_constitution(&key(3)), &state), no("constitution mismatch"));
    assert_eq!(verify_safety_evidence(&ev, &pay(2), &sc, &state), no("action digest mismatch"));
    assert_eq!(verify_safety_evidence(&ev, &action, &sc, &empty_state(NOW + 1.0)), no("state digest mismatch"));
    assert_eq!(verify_safety_evidence(&with(ev.clone(), "now", json!(1)), &action, &sc, &state), no("evidence does not reproduce"));
}

#[test]
fn unhashable_evidence_fails_closed() {
    let (_, _, ev, action, sc, state) = bundle();
    let ev = with(ev, "extra", json!(9_007_199_254_740_993i64));
    assert_eq!(verify_safety_evidence(&ev, &action, &sc, &state), no("verification error (fail closed)"));
}

fn deleting() -> (Value, Value, Value) {
    (cons(json!([{"id": "no-delete", "kind": "never", "when": {"verb": "delete"}}])), json!({"action": {"verb": "delete", "resource": "/r"}}), empty_state(NOW))
}

#[test]
fn evidence_of_a_violation_is_not_an_admit() {
    let (c, a, s) = deleting();
    let ev = prove_safety(&a, &c, &s);
    assert_eq!(ev["ok"], json!(false));
    assert_eq!(verify_safety_evidence(&ev, &a, &c, &s), no("prohibition violated: no-delete"));
    let signed = signed_evidence(&ev, &key(2));
    let expected = json!({"signer": public(&key(2)), "action": a, "constitution": c, "state": s});
    assert_eq!(verify_signed_safety_evidence(&signed, &expected), no("prohibition violated: no-delete"));
    assert_eq!(verify_signed_safety_evidence(&signed, &with(expected.clone(), "requireOk", json!(false))), Ok(()));
    assert_eq!(verify_signed_safety_evidence(&signed, &with(expected, "requireOk", json!(true))), no("prohibition violated: no-delete"));
}

#[test]
fn signed_evidence_refusals() {
    let (signed, expected, _, _, _, _) = bundle();
    assert_eq!(verify_signed_safety_evidence(&signed, &expected), Ok(()));
    assert_eq!(verify_signed_safety_evidence(&with(signed.clone(), "evidence", json!(5)), &expected), no("malformed input"));
    assert_eq!(verify_signed_safety_evidence(&with(signed.clone(), "evidence", json!([])), &expected), no("malformed input"));
    for pins in [json!([]), json!([""]), json!(["x", 5]), json!(5), json!("")] {
        assert_eq!(verify_signed_safety_evidence(&signed, &with(expected.clone(), "signer", pins.clone())), no("no pinned signer"), "{pins}");
    }
    let other = signed_evidence(&signed["evidence"], &key(9));
    let mut forged = signed.clone();
    forged["sig"] = other["sig"].clone();
    let mut absent = signed.clone();
    absent.as_object_mut().unwrap().remove("sig");
    let mut number = signed.clone();
    number["sig"] = json!(5);
    for (name, s) in [("other key", forged), ("absent", absent), ("number", number)] {
        assert_eq!(verify_signed_safety_evidence(&s, &expected), no("bad signature"), "{name}");
    }
}

#[test]
fn expected_digests_must_agree_with_the_expected_documents() {
    let (signed, expected, _, action, sc, state) = bundle();
    let good = [("actionDigest", hash_canonical_strict(&action).unwrap()), ("constitutionId", constitution_id(&sc).unwrap()), ("stateDigest", state_digest(&state).unwrap())];
    let mut all = expected.clone();
    for (k, d) in &good {
        all[*k] = json!(d);
    }
    assert_eq!(verify_signed_safety_evidence(&signed, &all), Ok(()));
    for (k, why) in [("actionDigest", "expected action and digest disagree"), ("constitutionId", "expected constitution and id disagree"), ("stateDigest", "expected state and digest disagree")] {
        assert_eq!(verify_signed_safety_evidence(&signed, &with(expected.clone(), k, json!("x"))), no(why), "{k}");
    }
}

#[test]
fn a_principal_pin_needs_a_string_signature_and_an_authentic_constitution() {
    let (signed, expected, _, _, _, _) = bundle();
    let pin = json!(public(&key(1)));
    let mut number_sig = with(expected.clone(), "principal", pin.clone());
    number_sig["constitution"]["sig"] = json!(5);
    assert_eq!(verify_signed_safety_evidence(&signed, &number_sig), no("principal pin requires a signed constitution"));
    let mut bad_sig = with(expected.clone(), "principal", pin.clone());
    bad_sig["constitution"]["sig"] = json!(sign(&key(9), CONSTITUTION_SIG_DOMAIN, expected["constitution"]["id"].as_str().unwrap()));
    assert_eq!(verify_signed_safety_evidence(&signed, &bad_sig), no("constitution not authentic: bad signature"));
    let wrong_pin = with(expected.clone(), "principal", json!(public(&key(9))));
    assert_eq!(verify_signed_safety_evidence(&signed, &wrong_pin), no("constitution not authentic: principal mismatch"));
    assert_eq!(verify_signed_safety_evidence(&signed, &with(expected, "principal", pin)), Ok(()));
}

#[test]
fn digest_only_expectations_require_the_evidence_to_cover_every_invariant() {
    let k = key(1);
    let sc = signed_constitution(&k);
    let (action, state) = (pay(1), empty_state(NOW));
    let (ad, sd) = (hash_canonical_strict(&action).unwrap(), state_digest(&state).unwrap());
    let ev = |rows: Value| json!({"v": 1, "constitution": constitution_id(&sc).unwrap(), "action_digest": ad, "state_digest": sd, "now": 0, "evaluated": rows, "ok": true, "violated": []});
    let expected = json!({"signer": public(&key(2)), "actionDigest": ad, "constitution": sc, "stateDigest": sd});
    let row = json!({"id": "spend-day", "kind": "cap", "result": "pass"});
    assert_eq!(verify_signed_safety_evidence(&signed_evidence(&ev(json!([row])), &key(2)), &expected), Ok(()));
    let uncovered = "evidence does not cover every invariant";
    assert_eq!(verify_signed_safety_evidence(&signed_evidence(&ev(json!([])), &key(2)), &expected), no(uncovered));
    assert_eq!(verify_signed_safety_evidence(&signed_evidence(&ev(json!([row.clone(), row.clone()])), &key(2)), &expected), no(uncovered));
    let other = json!({"id": "other", "kind": "cap", "result": "pass"});
    assert_eq!(verify_signed_safety_evidence(&signed_evidence(&ev(json!([other])), &key(2)), &expected), no(uncovered));
}

#[test]
fn tampered_evidence_of_a_violation_is_refused_even_when_a_violation_is_tolerated() {
    let (c, a, s) = deleting();
    let ev = with(prove_safety(&a, &c, &s), "now", json!(1));
    let signed = signed_evidence(&ev, &key(2));
    let expected = json!({"signer": public(&key(2)), "action": a, "constitution": c, "state": s, "requireOk": false});
    assert_eq!(verify_signed_safety_evidence(&signed, &expected), no("evidence does not reproduce"));
}
