//! k05 kill tests for the table and merge helpers, pinned to packages/pca/src/missing-context.ts and to Object.keys in node.
use super::*;

#[test]
fn js_keys_is_object_keys_order() {
    // node: Object.keys(JSON.parse(<this text>)) gives exactly the order below
    let v: Value = serde_json::from_str(r#"{"b":1,"10":1,"z":1,"4294967295":1,"007":1,"2":1,"4294967294":1,"a":1,"0":1,"":1,"99999999999999999999":1}"#).unwrap();
    let want = ["0", "2", "10", "4294967294", "b", "z", "4294967295", "007", "a", "", "99999999999999999999"];
    assert_eq!(js_keys(v.as_object().unwrap()), want);
}

#[test]
fn the_first_bad_table_path_follows_object_keys_order() {
    let v: Value = serde_json::from_str(r#"{"z.bad":"principal","1":"principal"}"#).unwrap();
    assert_eq!(supplier_table_error(&v).as_deref(), Some("bad supplier path '1'"));
}

fn path_error(k: &str) -> Option<String> {
    let mut o = Map::new();
    o.insert(k.to_string(), json!("principal"));
    supplier_table_error(&Value::Object(o))
}

#[test]
fn supplier_paths_match_the_reference_regex() {
    // ^(action\.params|subject|env)(\.[A-Za-z_][A-Za-z0-9_]*)*$ and no forbidden segment
    for good in ["subject", "env", "action.params", "action.params.x", "subject._a", "subject.a_b", "subject.a1", "subject.A", "env.a.b.c"] {
        assert_eq!(path_error(good), None, "{good}");
    }
    let bad = [
        "action", "action.foo", "action.x.params", "action.params.", "other", "", "subject.", "subject.1a", "subject.-a", "subject.a-b", "subject.\u{e9}", "subject.a\n",
        "subject.__proto__", "env.constructor", "subject.a.prototype", "action.params.__proto__",
    ];
    for k in bad {
        assert_eq!(path_error(k), Some(format!("bad supplier path '{k}'")), "{k:?}");
    }
}

#[test]
fn the_longest_segment_boundary_prefix_supplies() {
    let t = supplier_table(&json!({"subject": "agent_declared_untrusted", "subject.a": "rs_observation", "subject.a.b": "discharge_issuer"}));
    assert_eq!(supplier_of("subject.a.b.c", &t), "discharge_issuer");
    assert_eq!(supplier_of("subject.a.b", &t), "discharge_issuer");
    assert_eq!(supplier_of("subject.a.x", &t), "rs_observation");
    assert_eq!(supplier_of("subject.ab", &t), "agent_declared_untrusted", "not a segment boundary");
    assert_eq!(supplier_of("subject", &t), "agent_declared_untrusted");
    assert_eq!(supplier_of("subjectx", &t), "principal", "not a segment boundary");
    assert_eq!(supplier_of("env.x", &t), "principal");
}

#[test]
fn an_empty_supplied_object_is_a_leaf() {
    let bound = json!({"action": {"verb": "v", "resource": "r"}});
    let got = bind_context(&bound, &json!({"subject": {"a": {}}, "env": {}}), &SupplierTable::new());
    assert_eq!(got.context, json!({"action": {"verb": "v", "resource": "r"}, "subject": {"a": {}}, "env": {}}));
    assert!(got.conflicts.is_empty() && got.dropped.is_empty());
}

#[test]
fn flattening_stops_at_depth_17() {
    // {"k1":{"k2":...{"k20":1}}}: the reference's leaves() makes the value at depth 17 a leaf, whatever it holds
    let deep = (1..=20).rev().fold(json!(1), |v, i| {
        let mut o = Map::new();
        o.insert(format!("k{i}"), v);
        Value::Object(o)
    });
    let t = supplier_table(&json!({"subject": "agent_declared_untrusted"}));
    let got = bind_context(&json!({"action": {}}), &json!({ "subject": deep }), &t);
    let want = format!("subject.{}", (1..=17).map(|i| format!("k{i}")).collect::<Vec<_>>().join("."));
    assert_eq!(got.dropped, [want]);
}

// ---- decide_with_missing: what collect() calls missing and what it calls ill typed, per missing-context.ts collect ----

fn action_only() -> Value {
    json!({"action": {"verb": "v", "resource": "r"}})
}

fn nested(n: usize) -> Value {
    (0..n).fold(json!({"field": "subject.x", "op": "eq", "value": 1}), |c, _| json!({ "all_of": [c] }))
}

fn reason(where_: Value, bound: &Value) -> Option<String> {
    decide_with_missing(&where_, bound, &Value::Null, None).reason
}

#[test]
fn collect_walks_groups_to_depth_64_and_calls_deeper_ill_typed() {
    let missing = Some("escalate: missing_context principal:subject.x".to_string());
    let ill = Some("ill_typed_context".to_string());
    for n in [0, 1, 64] {
        assert_eq!(reason(json!([nested(n)]), &action_only()), missing, "{n}");
    }
    assert_eq!(reason(json!([nested(65)]), &action_only()), ill);
}

#[test]
fn an_empty_group_or_a_scalar_is_ill_typed_even_beside_a_missing_path() {
    let ill = Some("ill_typed_context".to_string());
    for odd in [json!({"all_of": []}), json!({"any_of": []}), json!({"all_of": 5}), json!({"not": null}), json!(5), json!(null)] {
        assert_eq!(reason(json!([nested(0), odd.clone()]), &action_only()), ill, "{odd}");
    }
}

#[test]
fn params_that_are_not_a_container_count_as_missing_params() {
    // the path resolves, so only the action.params clause keeps this from being ill typed
    let bound = json!({"action": {"verb": "v", "resource": "r", "params": 5}});
    let c = json!([{"field": "action.params", "op": "eq", "value": 1}]);
    assert_eq!(reason(c, &bound), Some("escalate: missing_context principal:action.params".to_string()));
    // a path that resolves and a leaf that stays unknown, with params absent: not the params clause, so ill typed
    let c = json!([{"field": "subject.x", "op": "nope"}]);
    let bound = json!({"action": {"verb": "v", "resource": "r"}, "subject": {"x": 1}});
    assert_eq!(reason(c, &bound), Some("ill_typed_context".to_string()));
}

#[test]
fn a_supplied_param_keeps_the_bound_params() {
    let bound = json!({"action": {"verb": "v", "resource": "r", "params": {"a": 1}}});
    let got = bind_context(&bound, &json!({"action": {"params": {"b": 2}}}), &SupplierTable::new());
    assert_eq!(got.context["action"]["params"], json!({"a": 1, "b": 2}));
    let bare = bind_context(&action_only(), &json!({"action": {"params": {"b": 2}}}), &SupplierTable::new());
    assert_eq!(bare.context["action"]["params"], json!({"b": 2}));
}

#[test]
fn an_absent_bound_action_gets_an_empty_verb_and_resource() {
    // node: bindContext({subject:{id:'u1'}}, {action:{params:{a:1}}}, {}).context.action
    let got = bind_context(&json!({"subject": {"id": "u1"}}), &json!({"action": {"params": {"a": 1}}}), &SupplierTable::new());
    assert_eq!(got.context["action"], json!({"verb": "", "resource": "", "params": {"a": 1}}));
    assert!(got.conflicts.is_empty());
}
