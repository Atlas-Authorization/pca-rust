//! Mutation-kill tests (batch Z1, R6-ZK cargo-mutants survivors): ECMAScript number printing (`js_number_to_string`,
//! `ser_number`, `js_string`) at the unsafe-integer and exponent-form boundaries, the risk-policy `theta1 >= 0` boundary of
//! `envelope_well_formed`, the reversibility class taken from the SIGNED action before the node (`decide`), the
//! `tool_schema` depth / node-count / array-items depth limits (agent-native.ts `objectSchemaError` / `specError`), the
//! carried `budget_alloc` monotonicity (capability.ts `allocationsMonotone`: equal is fine) and the journal
//! guest-version floor of `check_context`.
use pca_zkvm_core::canonical::{canonicalize, js_number_to_string, js_string};
use pca_zkvm_core::caveats::{evaluate_caveat, CaveatCtx};
use pca_zkvm_core::chain::verify_hops;
use pca_zkvm_core::commit::{hash_canonical, plan_commitment};
use pca_zkvm_core::context::{check_context, ContextMismatch, ExpectedContext};
use pca_zkvm_core::{decide, decide_from_str, envelope_well_formed, DecideInput, MIN_GUEST_VERSION};
use serde_json::{json, Map, Value};

#[path = "support/chain_mint.rs"]
mod mint;

fn base() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/decide_input.sample.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

// ------------------------------------------------------------------------------- canonical.rs number printing

#[test]
fn js_number_to_string_exponent_forms_match_ecmascript() {
    // Number::toString: n = 21 is the last plain form, n = 22 switches to "e+"; n = -5 (1e-6) is the last "0.0..." form,
    // n = -6 (1e-7) switches to "e-"; one digit has no ".", several digits do.
    let cases: &[(f64, &str)] = &[
        (1e21, "1e+21"),
        (1.5e21, "1.5e+21"),
        (1e22, "1e+22"),
        (1.2345e25, "1.2345e+25"),
        (1e20, "100000000000000000000"),
        (123456789012345680000.0, "123456789012345680000"),
        (1e-7, "1e-7"),
        (1.5e-7, "1.5e-7"),
        (1.23e-18, "1.23e-18"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (1e-6, "0.000001"),
        (1.2345e-6, "0.0000012345"),
        (0.1, "0.1"),
        (123.456, "123.456"),
        (-1e21, "-1e+21"),
        (-1.5e-7, "-1.5e-7"),
        (-0.000001, "-0.000001"),
        (-0.0, "0"),
    ];
    for (f, want) in cases {
        assert_eq!(js_number_to_string(*f), *want, "{f:e}");
    }
}

#[test]
fn ser_number_rounds_unsafe_integers_through_the_double() {
    // JSON.parse('9007199254740993') === 9007199254740992; safe integers print exactly
    assert_eq!(canonicalize(&json!(9007199254740993u64)), "9007199254740992");
    assert_eq!(canonicalize(&json!(-9007199254740993i64)), "-9007199254740992");
    assert_eq!(canonicalize(&json!(9007199254740991u64)), "9007199254740991");
    assert_eq!(canonicalize(&json!(-9007199254740991i64)), "-9007199254740991");
    assert_eq!(canonicalize(&json!(-5)), "-5");
    assert_eq!(canonicalize(&json!([1e21, 1e-7, 9007199254740995u64])), "[1e+21,1e-7,9007199254740996]");
}

#[test]
fn js_string_rounds_unsafe_integers_through_the_double() {
    assert_eq!(js_string(Some(&json!(9007199254740993u64))), "9007199254740992");
    assert_eq!(js_string(Some(&json!(-9007199254740993i64))), "-9007199254740992");
    assert_eq!(js_string(Some(&json!(9007199254740991u64))), "9007199254740991");
    assert_eq!(js_string(Some(&json!(-9007199254740991i64))), "-9007199254740991");
    assert_eq!(js_string(Some(&json!([9007199254740993u64, null, -9007199254740993i64]))), "9007199254740992,,-9007199254740992");
}

// ------------------------------------------------------------------------------- lib.rs envelope_well_formed

fn sample_envelope() -> Value {
    base()["grant"]["caveats"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["type"] == "envelope")
        .unwrap()
        .clone()
}

#[test]
fn envelope_theta1_zero_is_valid_and_negative_is_not() {
    // risk.ts validateRiskPolicy: `theta1 < 0 || theta2 < theta1` refuses; theta1 == 0 is valid
    let e = sample_envelope();
    assert!(envelope_well_formed(&e), "control");
    let mut z = e.clone();
    z["risk_policy"]["theta1"] = json!(0);
    assert!(envelope_well_formed(&z), "theta1 = 0 is valid");
    let mut z = e.clone();
    z["risk_policy"]["theta1"] = json!(0.0);
    z["risk_policy"]["theta2"] = json!(0.0);
    assert!(envelope_well_formed(&z), "theta1 = theta2 = 0 is valid");
    let mut n = e.clone();
    n["risk_policy"]["theta1"] = json!(-0.1);
    assert!(!envelope_well_formed(&n), "theta1 < 0 is refused");
    let mut n = e.clone();
    n["risk_policy"]["theta1"] = json!(-1e-9);
    n["risk_policy"]["theta2"] = json!(0.5);
    assert!(!envelope_well_formed(&n), "a tiny negative theta1 is refused");
}

// ------------------------------------------------------------------------------- lib.rs decide: reversibility class

fn di(v: &Value) -> DecideInput {
    serde_json::from_value(v.clone()).unwrap()
}

fn minted(extra_envelope_caveat: Option<Value>, edit: impl Fn(&mut Value)) -> Value {
    let mut b = base();
    if let Some(cv) = extra_envelope_caveat {
        for c in b["grant"]["caveats"].as_array_mut().unwrap() {
            if c["type"] == "envelope" {
                c["caveats"].as_array_mut().unwrap().push(cv.clone());
            }
        }
    }
    let chain = mint::two_hop(&b, vec![]);
    let mut v = mint::with_chain(&b, chain, &mint::key(3));
    edit(&mut v);
    mint::resign(&mut v, &mint::key(3));
    v
}

#[test]
fn reversibility_class_from_the_action_wins_over_a_node_that_omits_it() {
    // policy-vm.ts: `action.reversibility_class ?? node.reversibility_class`. The action says "reversible"; the signed
    // node n1 omits the class (it commits as the default "reversible", so the plan inclusion still holds). The class is
    // the action's, so a `reversibility_max: reversible` caveat is satisfied.
    let cap = Some(json!({ "type": "reversibility_max", "class": "reversible" }));
    let v = minted(cap, |v| {
        v["plan"][1].as_object_mut().unwrap().remove("reversibility_class");
        let plan = v["plan"].as_array().unwrap().clone();
        v["pcactn"]["plan"]["root"] = json!(plan_commitment(&plan).unwrap());
    });
    assert_eq!(v["action"]["reversibility_class"], json!("reversible"));
    assert_eq!(v["plan"][1]["id"], json!("n1"));
    assert!(v["plan"][1].get("reversibility_class").is_none());
    assert_eq!(decide(&di(&v)).allow, 1);
}

// ------------------------------------------------------------------------------- caveats.rs tool_schema limits

fn tool_schema_caveat(schema: &Value) -> Value {
    let sig = "sigdigest";
    let binding = json!({ "tool": "pay", "signature_digest": sig, "schema": schema });
    json!({ "type": "tool_schema", "tool": "pay", "signature_digest": sig, "schema": schema,
            "schema_digest": hash_canonical(schema), "binding_digest": hash_canonical(&binding) })
}

fn satisfied(schema: Value, args: Value) -> bool {
    let root = json!({});
    let cx = CaveatCtx {
        now: 1.0e12,
        blast_radius: None,
        reversibility_class: None,
        delegation_depth: None,
        recent_action_times: None,
        action_root: &root,
        tool: Some("pay".to_string()),
        tool_args: Some(args),
        tool_signature_digest: None,
    };
    evaluate_caveat(&tool_schema_caveat(&schema), &cx)
}

/// An argument schema whose innermost object spec is `inner` at schema depth `1 + levels` (the root props object is depth
/// 1, each nested object spec adds one).
fn nested(levels: usize, inner: Value) -> Value {
    let mut spec = inner;
    for _ in 1..levels {
        spec = json!({ "type": "object", "props": { "a": spec } });
    }
    json!({ "props": { "a": spec } })
}

#[test]
fn schema_object_at_max_depth_is_valid_one_deeper_is_not() {
    // depth 1 root -> object specs at depth 2..=8 (7 levels), the last with empty props: valid (8 == MAX_SCHEMA_DEPTH)
    let empty_obj = json!({ "type": "object", "props": {} });
    assert!(satisfied(nested(7, empty_obj.clone()), json!({})), "object at depth 8 is valid");
    assert!(!satisfied(nested(8, empty_obj), json!({})), "object at depth 9 is too deep");
    // a scalar at depth 8 is fine, one level deeper is not
    let s = json!({ "type": "string" });
    assert!(satisfied(nested(7, s.clone()), json!({})));
    assert!(!satisfied(nested(8, s), json!({})));
}

#[test]
fn schema_array_items_add_a_level() {
    // an array spec at depth 8 has its items at depth 9: too deep. At depth 7 its items are at 8: fine.
    let arr = json!({ "type": "array", "items": { "type": "string" } });
    assert!(!satisfied(nested(7, arr.clone()), json!({})), "array at depth 8: items at depth 9");
    assert!(satisfied(nested(6, arr.clone()), json!({})), "array at depth 7: items at depth 8");
    // nested arrays: each items level counts
    let arr2 = json!({ "type": "array", "items": { "type": "array", "items": { "type": "string" } } });
    assert!(!satisfied(nested(6, arr2.clone()), json!({})));
    assert!(satisfied(nested(5, arr2), json!({})));
    // the deep value itself still validates
    let arr = json!({ "type": "array", "items": { "type": "string" } });
    assert!(satisfied(json!({ "props": { "x": arr } }), json!({ "x": ["a", "b"] })));
}

fn string_props(n: usize) -> Value {
    let mut m = Map::new();
    for i in 0..n {
        m.insert(format!("s{i:02}"), json!({ "type": "string" }));
    }
    Value::Object(m)
}

/// Root (1 node) + a, b, c (object + 63 strings = 64 nodes each) + d (object + `d_strings`) + e (empty object, visited
/// last): `1 + 192 + 1 + d_strings + 1` nodes, the LAST one counted by `objectSchemaError`.
fn many_nodes(d_strings: usize) -> Value {
    let mut props = Map::new();
    for k in ["a", "b", "c"] {
        props.insert(k.to_string(), json!({ "type": "object", "props": string_props(63) }));
    }
    props.insert("d".to_string(), json!({ "type": "object", "props": string_props(d_strings) }));
    props.insert("e".to_string(), json!({ "type": "object", "props": {} }));
    json!({ "props": Value::Object(props) })
}

#[test]
fn schema_with_exactly_max_nodes_is_valid() {
    // 1 + 192 + 1 + 61 + 1 = 256 == MAX_SCHEMA_NODES (the 256th node is the empty object `e`)
    assert!(satisfied(many_nodes(61), json!({})), "256 nodes is valid");
    assert!(!satisfied(many_nodes(62), json!({})), "257 nodes is too large");
}

// ------------------------------------------------------------------------------- chain.rs allocationsMonotone

#[test]
fn equal_carried_allocations_are_monotone() {
    let b = base();
    let root = mint::pk(&mint::key(1));
    let alloc = |l: f64| json!({ "type": "budget_alloc", "limit": l });
    let ok = mint::two_hop(&b, vec![alloc(10.0), alloc(10.0)]);
    let v = verify_hops(&ok, &root);
    assert!(v.ok, "equal allocations do not widen: {:?}", v.reason);
    let ok = mint::two_hop(&b, vec![alloc(10.0), alloc(10.0), alloc(0.0), alloc(0.0)]);
    assert!(verify_hops(&ok, &root).ok);
    let bad = mint::two_hop(&b, vec![alloc(10.0), alloc(10.5)]);
    let v = verify_hops(&bad, &root);
    assert!(!v.ok);
    assert!(v.reason.unwrap().starts_with("budget_alloc caveat"));
}

// ------------------------------------------------------------------------------- context.rs guest-version floor

#[test]
fn check_context_guest_version_floor() {
    let b = base();
    let exp = ExpectedContext::from_input_json(&b.to_string(), 0.0).expect("input parses");
    let mut j = decide_from_str(&b.to_string());
    check_context(&j, &exp).expect("control");
    j.guest_version = MIN_GUEST_VERSION + 1;
    check_context(&j, &exp).expect("a newer guest passes the floor");
    j.guest_version = MIN_GUEST_VERSION - 1;
    assert_eq!(
        check_context(&j, &exp),
        Err(ContextMismatch::GuestVersion { proven: MIN_GUEST_VERSION - 1, minimum: MIN_GUEST_VERSION })
    );
}
