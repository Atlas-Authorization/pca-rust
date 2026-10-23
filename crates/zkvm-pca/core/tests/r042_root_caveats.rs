//! PCA 0.4.1 security fix in the guest (guest version 8): caveats on the ROOT grant outside the `envelope` caveat are policy
//! and are enforced exactly like the caveats delegation hops append; `max_spend {usd}` is implemented; unknown root caveat
//! types (including a second `envelope`) fail closed.
//!
//! * `primitives.caveat_eval` (the shared conformance corpus, TS reference = oracle): `policy_caveats(grant, chain)`
//!   evaluated with the guest's caveat evaluator gives exactly `expect.{allow, failed}` for every entry.
//! * decide(): a validly signed chain whose root carries an extra caveat is DENIED when that caveat is unsatisfied and
//!   still ALLOWED when it holds (the 0.4.0 guest ignored the root's own caveats and allowed both).
use pca_zkvm_core::caveats::{action_spend_usd, evaluate_caveats, CaveatCtx};
use pca_zkvm_core::{decide, policy_caveats, root_caveats, DecideInput, GUEST_VERSION, MIN_GUEST_VERSION};
use serde_json::{json, Value};

#[path = "support/chain_mint.rs"]
mod mint;

/// `primitives.caveat_eval` of the shared corpus. The corpus is written one entry per line (conformance-io.mjs) and also
/// holds the 100000-deep `primitives.depth` cases, which exceed serde_json's recursion limit, so only the `caveat_eval`
/// block is parsed.
fn caveat_eval_cases() -> Vec<Value> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../conformance/vectors.json");
    let text = std::fs::read_to_string(p).expect("conformance vectors.json");
    let mut lines = text.lines().skip_while(|l| l.trim() != "\"caveat_eval\": [").skip(1);
    let body: Vec<&str> = lines.by_ref().take_while(|l| !l.trim().starts_with(']')).collect();
    assert!(!body.is_empty(), "primitives.caveat_eval block not found");
    serde_json::from_str(&format!("[{}]", body.join("\n"))).expect("caveat_eval block parses")
}

fn base() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/decide_input.sample.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn allowed(v: &Value) -> bool {
    decide(&serde_json::from_value::<DecideInput>(v.clone()).unwrap()).allow == 1
}

/// The `caveat_eval` context as the guest's caveat context (`action` root = `{action: context.action}`, as in decide()).
fn eval(caveats: &[Value], cx: &Value) -> (bool, Vec<String>) {
    let root = json!({ "action": cx.get("action").cloned().unwrap_or(Value::Null) });
    let f = |k: &str| cx.get(k).and_then(|x| x.as_f64());
    let ctx = CaveatCtx {
        now: f("now").unwrap_or(f64::NAN),
        blast_radius: f("blast_radius"),
        reversibility_class: cx.get("reversibility_class").cloned(),
        delegation_depth: f("delegation_depth"),
        recent_action_times: cx.get("recent_action_times").and_then(|t| t.as_array()).map(|a| a.iter().filter_map(|x| x.as_f64()).collect()),
        action_root: &root,
        tool: None,
        tool_args: None,
        tool_signature_digest: None,
    };
    let o = evaluate_caveats(caveats, &ctx);
    (o.ok, o.failed)
}

#[test]
fn caveat_eval_vectors_match_the_reference() {
    let cases = caveat_eval_cases();
    let cases = &cases;
    assert!(cases.len() >= 40, "expected >= 40 caveat_eval vectors, got {}", cases.len());
    let mut bad = Vec::new();
    for c in cases {
        let chain = c["chain"].as_array().cloned().unwrap_or_default();
        let (ok, failed) = match policy_caveats(&c["grant"], &chain) {
            Some(list) => eval(&list, &c["context"]),
            None => (false, vec!["<malformed>".to_string()]),
        };
        let got = json!({ "allow": ok, "failed": failed });
        if got != c["expect"] {
            bad.push(format!("{}: got {got}, want {}", c["name"], c["expect"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} caveat_eval vectors differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
    let by = |n: &str| cases.iter().find(|c| c["name"] == n).unwrap_or_else(|| panic!("{n} missing"));
    assert_eq!(by("r041-root-max-spend-exceeded")["expect"]["allow"], false);
    assert_eq!(by("r041-root-max-spend-within")["expect"]["allow"], true);
}

#[test]
fn root_caveats_drop_only_the_first_envelope() {
    let g = json!({"caveats": [{"type": "expires", "at": 1}, {"type": "envelope", "n": 1}, {"type": "envelope", "n": 2}, {"type": "x"}]});
    assert_eq!(
        root_caveats(&g).unwrap(),
        vec![json!({"type": "expires", "at": 1}), json!({"type": "envelope", "n": 2}), json!({"type": "x"})]
    );
    assert_eq!(root_caveats(&json!({"caveats": []})).unwrap(), Vec::<Value>::new());
    assert!(root_caveats(&json!({"caveats": {}})).is_none());
    assert!(root_caveats(&json!({})).is_none());
    // policy_caveats = root caveats, then what the leaf appended beyond the grant's own list
    let g = json!({"caveats": [{"type": "envelope"}, {"type": "a"}]});
    let chain = vec![g.clone(), json!({"caveats": [{"type": "envelope"}, {"type": "a"}, {"type": "b"}]})];
    assert_eq!(policy_caveats(&g, &chain).unwrap(), vec![json!({"type": "a"}), json!({"type": "b"})]);
    assert_eq!(policy_caveats(&g, &[]).unwrap(), vec![json!({"type": "a"})]);
}

#[test]
fn action_spend_usd_reads_own_amount_and_currency() {
    let r = |p: Value| action_spend_usd(&json!({"action": {"params": p}}));
    assert_eq!(r(json!({"amount": 10})), Some(10.0));
    assert_eq!(r(json!({"amount": 0})), Some(0.0));
    assert_eq!(r(json!({"amount": 10, "currency": "usd"})), Some(10.0));
    assert_eq!(r(json!({"amount": 10, "currency": "USD"})), Some(10.0));
    for bad in [json!({"amount": -1}), json!({"amount": "10"}), json!({}), json!({"amount": 10, "currency": "eur"}),
        json!({"amount": 10, "currency": "Usd"}), json!({"amount": 10, "currency": null}), json!({"amount": 10, "currency": 1})] {
        assert_eq!(r(bad.clone()), None, "{bad}");
    }
    assert_eq!(action_spend_usd(&json!({"action": {"params": [1]}})), None);
    assert_eq!(action_spend_usd(&json!({"action": []})), None);
    assert_eq!(action_spend_usd(&json!({})), None);
}

#[test]
fn max_spend_is_evaluated_without_a_finite_now() {
    // agent-native types are evaluated before the stock evaluator's finite-`now` gate
    let cx = json!({"action": {"params": {"amount": 5}}});
    assert_eq!(eval(&[json!({"type": "max_spend", "usd": 10})], &cx), (true, vec![]));
    assert_eq!(eval(&[json!({"type": "max_spend", "usd": 4.99})], &cx), (false, vec!["max_spend".to_string()]));
    assert_eq!(eval(&[json!({"type": "max_spend", "usd": 5})], &cx), (true, vec![]));
    assert_eq!(eval(&[json!({"type": "max_spend", "usd": -1})], &cx).0, false);
    assert_eq!(eval(&[json!({"type": "max_spend", "usd": "10"})], &cx).0, false);
    assert_eq!(eval(&[json!({"type": "max_spend"})], &cx).0, false);
}

#[test]
fn decide_enforces_the_root_grants_own_caveats() {
    let b = base();
    assert!(allowed(&b), "fixture baseline must be allowed");
    let now = b["now"].as_f64().unwrap();
    let with = |extra: Value| mint::root_edited(&b, &|cs: &mut Vec<Value>| cs.push(extra.clone()));
    // satisfied root caveats keep the decision
    assert!(allowed(&mint::root_edited(&b, &|_| {})), "re-minted baseline");
    assert!(allowed(&with(json!({"type": "expires", "at": now + 1.0}))));
    assert!(allowed(&with(json!({"type": "delegation_depth", "max": 1}))));
    // unsatisfied / unknown / unreadable root caveats deny (the 0.4.0 guest allowed every one of these)
    assert!(!allowed(&with(json!({"type": "expires", "at": now}))), "expired root caveat");
    assert!(!allowed(&with(json!({"type": "delegation_depth", "max": 0}))), "depth 1 > 0");
    assert!(!allowed(&with(json!({"type": "made_up"}))), "unknown root caveat type");
    assert!(!allowed(&with(json!({"type": "envelope", "goal_commit": "x", "predicates": [], "caveats": []}))), "second envelope");
    assert!(!allowed(&with(json!({"type": "max_spend", "usd": 1000}))), "max_spend without a readable amount");
    assert!(!allowed(&with(json!("not an object"))), "non-object root caveat");
}

#[test]
fn guest_version_marks_the_root_caveat_semantics() {
    // 8 introduced root-caveat enforcement; 9 (session-root PQ pins, r042_session_pq_pins.rs) keeps it
    assert!(GUEST_VERSION >= 8);
    assert!(MIN_GUEST_VERSION >= 8);
}
