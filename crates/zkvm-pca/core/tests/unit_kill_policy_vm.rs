//! Boundary-level unit tests of the Policy-VM pieces the end-to-end fixtures only touch coarsely: the predicate DSL
//! (`predicates`), the built-in and agent-native caveats (`caveats`), the canonical-JSON profile and the risk tier.
//! Written against cargo-mutants survivors: every assertion pins one operator, boundary or match arm.
use pca_zkvm_core::caveats::{evaluate_caveat, evaluate_caveats, CaveatCtx};
use pca_zkvm_core::canonical::canonicalize;
use pca_zkvm_core::commit::hash_canonical;
use pca_zkvm_core::predicates::{evaluate_condition, evaluate_predicates, predicate_matches, Ctx};
use pca_zkvm_core::risk::{auto_admit, budget_covers, risk_raw, tier, RiskInputsScaled, RiskPolicyScaled, S};
use serde_json::{json, Value};

// ------------------------------------------------------------------------------------------------ predicates

fn root(action: Value) -> Value {
    json!({ "action": action, "subject": {"role": "admin"}, "env": {"region": "eu"} })
}

fn pm(pred: Value, action: Value) -> bool {
    let r = root(action);
    predicate_matches(&pred, &Ctx::new(&r))
}

fn cond(c: Value, action: Value) -> bool {
    let r = root(action);
    let p = json!({ "verb": "*", "where": [c] });
    predicate_matches(&p, &Ctx::new(&r))
}

#[test]
fn array_index_paths() {
    let list: Vec<Value> = (0..12).map(|i| json!(i * 10)).collect();
    let a = json!({ "verb": "v", "resource": "r", "list": list });
    let exists = |idx: &str| cond(json!({ "field": format!("action.list.{idx}"), "op": "exists" }), a.clone());
    for ok in ["0", "1", "2", "9", "10", "11"] {
        assert!(exists(ok), "index {ok} must resolve");
    }
    for bad in ["12", "01", "00", "010", "-1", "x", "1a", "a1", "+1", "1.0", " 1"] {
        assert!(!exists(bad), "path segment {bad:?} must not resolve");
    }
    // the value at the index is the right one
    assert!(cond(json!({ "field": "action.list.7", "op": "eq", "value": 70 }), a.clone()));
    assert!(!cond(json!({ "field": "action.list.7", "op": "eq", "value": 60 }), a));
}

#[test]
fn path_roots_and_forbidden_segments() {
    let a = json!({ "verb": "v", "resource": "r", "o": {"k": 1, "constructor": 2, "__proto__": 3, "prototype": 4} });
    let ex = |f: &str| cond(json!({ "field": f, "op": "exists" }), a.clone());
    assert!(ex("action.o.k") && ex("subject.role") && ex("env.region"));
    assert!(!ex("") && !ex("other.x") && !ex("action.o.constructor") && !ex("action.o.__proto__") && !ex("action.o.prototype"));
    assert!(!ex("action.o.k.deeper"), "descending into a scalar finds nothing");
}

#[test]
fn eq_ne_in_nin_semantics() {
    let a = json!({ "verb": "v", "resource": "r", "n": 5, "s": "abc", "z": null, "o": {"a": [1, 2]} });
    let c = |op: &str, field: &str, value: Value| cond(json!({ "field": field, "op": op, "value": value }), a.clone());
    assert!(c("eq", "action.n", json!(5)) && !c("eq", "action.n", json!(6)));
    assert!(c("ne", "action.n", json!(6)) && !c("ne", "action.n", json!(5)));
    assert!(c("eq", "action.z", Value::Null), "an explicit null operand is a present value");
    assert!(!c("eq", "action.z", json!(0)));
    assert!(c("ne", "action.z", json!(0)) && !c("ne", "action.z", Value::Null));
    assert!(c("eq", "action.o", json!({"a": [1, 2]})) && !c("eq", "action.o", json!({"a": [2, 1]})));
    assert!(c("in", "action.s", json!(["x", "abc"])) && !c("in", "action.s", json!(["x", "y"])));
    assert!(!c("in", "action.s", json!("abc")), "in needs an array operand");
    assert!(c("nin", "action.s", json!(["x", "y"])) && !c("nin", "action.s", json!(["x", "abc"])));
    assert!(!c("nin", "action.s", json!("abc")), "nin needs an array operand");
    assert!(!c("eq", "action.missing", json!(1)) && !c("ne", "action.missing", json!(1)), "absent field: false for every op but exists");
    assert!(!c("bogus", "action.n", json!(5)));
    // an operand-less condition fails (no value key, no ref)
    assert!(!cond(json!({ "field": "action.n", "op": "eq" }), a.clone()));
}

#[test]
fn ordering_ops() {
    let a = json!({ "verb": "v", "resource": "r", "n": 5, "f": 2.5, "s": "b", "z": null });
    let c = |op: &str, field: &str, value: Value| cond(json!({ "field": field, "op": op, "value": value }), a.clone());
    // numbers
    assert!(c("lt", "action.n", json!(6)) && !c("lt", "action.n", json!(5)) && !c("lt", "action.n", json!(4)));
    assert!(c("lte", "action.n", json!(6)) && c("lte", "action.n", json!(5)) && !c("lte", "action.n", json!(4)));
    assert!(c("gt", "action.n", json!(4)) && !c("gt", "action.n", json!(5)) && !c("gt", "action.n", json!(6)));
    assert!(c("gte", "action.n", json!(4)) && c("gte", "action.n", json!(5)) && !c("gte", "action.n", json!(6)));
    assert!(c("lt", "action.f", json!(3)) && c("gt", "action.f", json!(2)));
    // strings (bytewise)
    assert!(c("lt", "action.s", json!("c")) && !c("lt", "action.s", json!("b")) && !c("lt", "action.s", json!("a")));
    assert!(c("lte", "action.s", json!("b")) && c("gte", "action.s", json!("b")));
    assert!(c("gt", "action.s", json!("a")) && !c("gt", "action.s", json!("c")));
    // mixed or non-comparable kinds never order
    for op in ["lt", "lte", "gt", "gte"] {
        assert!(!c(op, "action.n", json!("5")) && !c(op, "action.s", json!(5)) && !c(op, "action.z", json!(1)), "{op} on mixed kinds");
    }
}

#[test]
fn prefix_and_exists() {
    let a = json!({ "verb": "v", "resource": "r", "s": "hello", "n": 1 });
    let c = |op: &str, field: &str, value: Value| cond(json!({ "field": field, "op": op, "value": value }), a.clone());
    assert!(c("prefix", "action.s", json!("he")) && c("prefix", "action.s", json!("hello")) && !c("prefix", "action.s", json!("hex")));
    assert!(!c("prefix", "action.n", json!("1")) && !c("prefix", "action.s", json!(1)));
    assert!(cond(json!({ "field": "action.s", "op": "exists" }), a.clone()));
    assert!(cond(json!({ "field": "action.s", "op": "exists", "value": true }), a.clone()));
    assert!(!cond(json!({ "field": "action.s", "op": "exists", "value": false }), a.clone()));
    assert!(!cond(json!({ "field": "action.nope", "op": "exists" }), a.clone()));
    assert!(cond(json!({ "field": "action.nope", "op": "exists", "value": false }), a.clone()));
    // any other `value` than literal false means "must exist"
    assert!(cond(json!({ "field": "action.s", "op": "exists", "value": 0 }), a.clone()));
    assert!(!cond(json!({ "field": "action.nope", "op": "exists", "value": null }), a));
}

#[test]
fn ref_operands() {
    let a = json!({ "verb": "v", "resource": "r", "a": 3, "b": 3, "c": 4 });
    assert!(cond(json!({ "field": "action.a", "op": "eq", "ref": "action.b" }), a.clone()));
    assert!(!cond(json!({ "field": "action.a", "op": "eq", "ref": "action.c" }), a.clone()));
    assert!(cond(json!({ "field": "action.a", "op": "lt", "ref": "action.c" }), a.clone()));
    assert!(!cond(json!({ "field": "action.a", "op": "eq", "ref": "action.nope" }), a.clone()), "unresolvable ref fails closed");
    // a ref wins over a literal value
    assert!(cond(json!({ "field": "action.a", "op": "eq", "ref": "action.b", "value": 99 }), a));
}

#[test]
fn params_unavailable_fails_closed() {
    // params absent / not an object (TS `typeof p !== 'object'`) => any params-rooted field or ref is unknown, even for
    // `exists:false` and `ne`
    for action in [
        json!({ "verb": "v", "resource": "r" }),
        json!({ "verb": "v", "resource": "r", "params": "abc" }),
        json!({ "verb": "v", "resource": "r", "params": null }),
    ] {
        assert!(!cond(json!({ "field": "action.params", "op": "exists", "value": false }), action.clone()));
        assert!(!cond(json!({ "field": "action.params.x", "op": "exists", "value": false }), action.clone()));
        assert!(!cond(json!({ "field": "action.params.x", "op": "ne", "value": 1 }), action.clone()));
        assert!(!cond(json!({ "field": "action.verb", "op": "eq", "ref": "action.params" }), action.clone()));
        assert!(!cond(json!({ "field": "action.verb", "op": "eq", "ref": "action.params.x" }), action.clone()));
    }
    // R6-ZK-05: an ARRAY is an object to the TS guard, so params-rooted paths resolve into it
    let arr = json!({ "verb": "v", "resource": "r", "params": [1] });
    assert!(cond(json!({ "field": "action.params.0", "op": "eq", "value": 1 }), arr.clone()));
    assert!(cond(json!({ "field": "action.params.x", "op": "exists", "value": false }), arr.clone()));
    assert!(!cond(json!({ "field": "action.params.x", "op": "ne", "value": 1 }), arr.clone()), "unresolved field is unknown");
    assert!(cond(json!({ "field": "action.params", "op": "eq", "value": [1] }), arr));
    // params as a string: both the field and the ref form would resolve if the guard were skipped
    let s = json!({ "verb": "abc", "resource": "r", "params": "abc" });
    assert!(!cond(json!({ "field": "action.params", "op": "eq", "value": "abc" }), s.clone()));
    assert!(!cond(json!({ "field": "action.verb", "op": "eq", "ref": "action.params" }), s));
    // a field that merely starts with the word is NOT a params field
    let other = json!({ "verb": "v", "resource": "r", "paramsX": 1 });
    assert!(cond(json!({ "field": "action.paramsX", "op": "eq", "value": 1 }), other.clone()));
    assert!(cond(json!({ "field": "action.verb", "op": "eq", "ref": "action.verb" }), other));
    // params an object: params-rooted fields and refs work
    let p = json!({ "verb": "v", "resource": "r", "params": {"x": 1, "y": 1, "z": 2} });
    assert!(cond(json!({ "field": "action.params.x", "op": "eq", "value": 1 }), p.clone()));
    assert!(cond(json!({ "field": "action.params.x", "op": "eq", "ref": "action.params.y" }), p.clone()));
    assert!(!cond(json!({ "field": "action.params.x", "op": "eq", "ref": "action.params.z" }), p.clone()));
    assert!(cond(json!({ "field": "action.params", "op": "exists" }), p.clone()));
    assert!(cond(json!({ "field": "action.params.nope", "op": "exists", "value": false }), p.clone()));
    assert!(cond(json!({ "field": "action.verb", "op": "ne", "ref": "action.params.x" }), p));
}

#[test]
fn condition_direct_api() {
    let r = root(json!({ "verb": "v", "resource": "r", "n": 2 }));
    let c = |field: &str, op: &str, value: Option<Value>, reference: Option<&str>| {
        let mut o = json!({ "field": field, "op": op });
        if let Some(v) = value {
            o["value"] = v;
        }
        if let Some(r) = reference {
            o["ref"] = json!(r);
        }
        o
    };
    let ctx = Ctx::new(&r);
    assert!(evaluate_condition(&c("action.n", "eq", Some(json!(2)), None), &ctx));
    assert!(!evaluate_condition(&c("action.n", "eq", Some(json!(3)), None), &ctx));
    assert!(evaluate_condition(&c("action.n", "eq", None, Some("action.n")), &ctx));
    assert!(!evaluate_condition(&c("action.n", "eq", None, None), &ctx));
}

#[test]
fn malformed_where_clauses_fail_closed() {
    let r = root(json!({ "verb": "v", "resource": "r", "n": 1 }));
    let ctx = Ctx::new(&r);
    let p = |w: Value| predicate_matches(&json!({ "verb": "v", "where": w }), &ctx);
    assert!(p(json!([])));
    assert!(p(json!([{ "field": "action.n", "op": "eq", "value": 1 }])));
    assert!(!p(json!("x")) && !p(json!({})));
    assert!(!p(json!([42])) && !p(json!([{ "op": "eq", "value": 1 }])) && !p(json!([{ "field": "action.n", "value": 1 }])));
    assert!(!p(json!([{ "field": 1, "op": "eq", "value": 1 }])) && !p(json!([{ "field": "action.n", "op": 1, "value": 1 }])));
    // all clauses must hold
    assert!(!p(json!([{ "field": "action.n", "op": "eq", "value": 1 }, { "field": "action.n", "op": "eq", "value": 2 }])));
    assert!(p(json!([{ "field": "action.n", "op": "eq", "value": 1 }, { "field": "action.n", "op": "gte", "value": 1 }])));
}

#[test]
fn verb_matching() {
    let a = json!({ "verb": "read", "resource": "r" });
    assert!(pm(json!({ "verb": "read" }), a.clone()));
    assert!(pm(json!({ "verb": "*" }), a.clone()));
    assert!(!pm(json!({ "verb": "write" }), a.clone()));
    assert!(pm(json!({ "verb": ["write", "read"] }), a.clone()));
    assert!(pm(json!({ "verb": ["write", "*"] }), a.clone()));
    assert!(!pm(json!({ "verb": ["write", "delete"] }), a.clone()));
    assert!(!pm(json!({ "verb": [] }), a.clone()));
    assert!(!pm(json!({ "verb": [1, null, "write"] }), a.clone()));
    assert!(pm(json!({ "verb": [1, "read"] }), a.clone()));
    assert!(!pm(json!({ "verb": 7 }), a.clone()));
    assert!(!pm(json!({}), a.clone()), "no verb pattern");
    assert!(!pm(json!("read"), a.clone()), "predicate must be an object");
    assert!(!predicate_matches(&json!({ "verb": "read" }), &Ctx::new(&json!({}))), "no action root");
    assert!(!pm(json!({ "verb": "read" }), json!({ "resource": "r" })), "action without verb");
    assert!(!pm(json!({ "verb": "read" }), json!({ "verb": "read" })), "action without resource");
    assert!(!pm(json!({ "verb": "read" }), json!({ "verb": 1, "resource": "r" })));
}

#[test]
fn resource_matching() {
    let p = |pat: Value, res: &str| pm(json!({ "verb": "*", "resource": pat }), json!({ "verb": "v", "resource": res }));
    assert!(pm(json!({ "verb": "*" }), json!({ "verb": "v", "resource": "anything" })), "omitted resource = any");
    assert!(p(json!("*"), "x") && p(json!("*"), ""));
    assert!(p(json!("db/orders"), "db/orders") && !p(json!("db/orders"), "db/order") && !p(json!("db/orders"), "db/orders2"));
    assert!(p(json!("db/*"), "db/") && p(json!("db/*"), "db/orders") && !p(json!("db/*"), "db") && !p(json!("db/*"), "xdb/orders"));
    assert!(!p(json!(7), "x") && !p(json!(null), "x") && !p(json!(["x"]), "x"));
    // re:
    assert!(p(json!("re:a+b"), "aab") && !p(json!("re:a+b"), "aabc") && !p(json!("re:a+b"), "xaab"));
    assert!(p(json!("re:db/[0-9]+"), "db/42") && !p(json!("re:db/[0-9]+"), "db/x"));
    // source cap: 200 UTF-16 units accepted, 201 refused
    let src200 = "a".repeat(200);
    assert!(p(json!(format!("re:{src200}")), &src200));
    assert!(!p(json!(format!("re:{}", "a".repeat(201))), &"a".repeat(201)));
    // subject cap: 512 units accepted, 513 refused
    assert!(p(json!("re:a*"), &"a".repeat(512)));
    assert!(!p(json!("re:a*"), &"a".repeat(513)));
    assert!(p(json!("re:a*"), &"a".repeat(511)));
    // lengths are UTF-16 code units: 256 astral chars = 512 units (ok), 257 = 514 units (refused)
    assert!(p(json!("re:.*"), &"\u{1F600}".repeat(256)));
    assert!(!p(json!("re:.*"), &"\u{1F600}".repeat(257)));
    // 100 astral chars in the source = 200 units (ok); 101 = 202 (refused)
    let astral100 = "\u{1F600}".repeat(100);
    assert!(p(json!(format!("re:{astral100}")), &astral100));
    let astral101 = "\u{1F600}".repeat(101);
    assert!(!p(json!(format!("re:{astral101}")), &astral101));
}

#[test]
fn evaluate_predicates_default_deny_and_reasons() {
    let r = root(json!({ "verb": "read", "resource": "r" }));
    let ctx = Ctx::new(&r);
    let none = evaluate_predicates(&[], &ctx);
    assert!(!none.allowed);
    assert_eq!(none.reason.as_deref(), Some("envelope grants no predicates"));
    let miss = evaluate_predicates(&[json!({ "verb": "write" }), json!({ "verb": "delete" })], &ctx);
    assert!(!miss.allowed);
    assert_eq!(miss.reason.as_deref(), Some("no predicate permits the action"));
    let hit = evaluate_predicates(&[json!({ "verb": "write" }), json!({ "verb": "read" })], &ctx);
    assert!(hit.allowed);
    assert!(hit.reason.is_none());
}

// -------------------------------------------------------------------------------------------------- caveats

fn with(cur: Option<&str>) -> impl FnOnce(&mut CaveatCtx) {
    let cur = cur.map(|s| Value::String(s.to_string()));
    move |c: &mut CaveatCtx| c.reversibility_class = cur
}

fn times(t: Vec<f64>) -> impl FnOnce(&mut CaveatCtx) {
    move |c: &mut CaveatCtx| c.recent_action_times = Some(t)
}

struct Env {
    root: Value,
}

fn base_ctx(root: &Value) -> CaveatCtx<'_> {
    CaveatCtx {
        now: 100_000.0,
        blast_radius: Some(0.5),
        reversibility_class: Some("reversible".into()),
        delegation_depth: Some(1.0),
        recent_action_times: Some(vec![]),
        action_root: root,
        tool: None,
        tool_args: None,
        tool_signature_digest: None,
    }
}

fn ev(cv: Value, f: impl FnOnce(&mut CaveatCtx)) -> bool {
    let e = Env { root: root(json!({ "verb": "v", "resource": "r" })) };
    let mut c = base_ctx(&e.root);
    f(&mut c);
    evaluate_caveat(&cv, &c)
}

#[test]
fn time_caveats() {
    let exp = json!({ "type": "expires", "at": 1000 });
    assert!(ev(exp.clone(), |c| c.now = 999.0));
    assert!(!ev(exp.clone(), |c| c.now = 1000.0));
    assert!(!ev(exp.clone(), |c| c.now = 1001.0));
    let nb = json!({ "type": "not_before", "at": 1000 });
    assert!(!ev(nb.clone(), |c| c.now = 999.0));
    assert!(ev(nb.clone(), |c| c.now = 1000.0));
    assert!(ev(nb.clone(), |c| c.now = 1001.0));
    for cv in [json!({ "type": "expires" }), json!({ "type": "expires", "at": "1000" }), json!({ "type": "not_before" }), json!({ "type": "not_before", "at": null })] {
        assert!(!ev(cv, |c| c.now = 5.0), "missing / mistyped `at` fails closed");
    }
    // a non-finite clock fails every time-based caveat
    for now in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert!(!ev(exp.clone(), |c| c.now = now) && !ev(nb.clone(), |c| c.now = now));
        assert!(!ev(json!({ "type": "rate", "max": 5, "per_secs": 10 }), |c| c.now = now));
        assert!(!ev(json!({ "type": "max_blast_radius", "max": 1 }), |c| c.now = now));
        assert!(!ev(json!({ "type": "budget_alloc", "limit": 1 }), |c| c.now = now));
        assert!(!ev(json!({ "type": "delegation_depth", "max": 5 }), |c| c.now = now));
        assert!(!ev(json!({ "type": "reversibility_max", "class": "irreversible" }), |c| c.now = now));
    }
    // predicates caveats do not read the clock
    assert!(ev(json!({ "type": "predicates", "allow": [{ "verb": "v" }] }), |c| c.now = f64::NAN));
}

#[test]
fn rate_caveat_window() {
    let rate = |max: Value, per: Value| json!({ "type": "rate", "max": max, "per_secs": per });
    // now = 100000, per = 10 s -> window (90000, 100000]
    let r = rate(json!(1), json!(10));
    assert!(ev(r.clone(), times(vec![])));
    assert!(!ev(r.clone(), times(vec![95_000.0])), "inside the window counts");
    assert!(ev(r.clone(), times(vec![90_000.0])), "the lower bound is exclusive");
    assert!(!ev(r.clone(), times(vec![90_001.0])));
    assert!(!ev(r.clone(), times(vec![100_000.0])), "the upper bound (now) is inclusive");
    assert!(ev(r.clone(), times(vec![100_001.0])), "future timestamps never count");
    assert!(ev(r.clone(), times(vec![50_000.0])), "old timestamps never count");
    // non-finite timestamps are ignored (each of the three conjuncts matters)
    assert!(ev(r.clone(), times(vec![f64::INFINITY, f64::NEG_INFINITY, f64::NAN, 50_000.0, 200_000.0])));
    assert!(ev(r.clone(), times(vec![f64::NEG_INFINITY])));
    assert!(ev(r.clone(), times(vec![200_000.0])));
    // n < max, exactly
    let r3 = rate(json!(3), json!(10));
    assert!(ev(r3.clone(), times(vec![95_000.0, 96_000.0])));
    assert!(!ev(r3.clone(), times(vec![95_000.0, 96_000.0, 97_000.0])));
    assert!(!ev(r3.clone(), times(vec![95_000.0, 96_000.0, 97_000.0, 98_000.0])));
    assert!(!ev(rate(json!(0), json!(10)), times(vec![])), "max 0 never admits");
    // the window length is per_secs * 1000 ms
    assert!(!ev(rate(json!(1), json!(5)), times(vec![96_000.0])));
    assert!(ev(rate(json!(1), json!(5)), times(vec![94_000.0])));
    assert!(!ev(rate(json!(1), json!(100)), times(vec![50_000.0])));
    assert!(!ev(rate(json!(1), json!(0.5)), times(vec![99_600.0])));
    assert!(ev(rate(json!(1), json!(0.5)), times(vec![99_400.0])));
    // fail-closed inputs
    assert!(!ev(r.clone(), |c| c.recent_action_times = None));
    assert!(!ev(rate(json!(5), json!(0)), times(vec![])), "per_secs must be positive");
    assert!(!ev(rate(json!(5), json!(-5)), times(vec![])));
    assert!(ev(rate(json!(5), json!(0.001)), times(vec![])));
    assert!(!ev(json!({ "type": "rate", "per_secs": 10 }), times(vec![])));
    assert!(!ev(json!({ "type": "rate", "max": 5 }), times(vec![])));
    assert!(!ev(rate(json!("5"), json!(10)), times(vec![])));
    assert!(!ev(rate(json!(5), json!("10")), times(vec![])));
}

#[test]
fn blast_radius_depth_budget_reversibility() {
    let br = |max: f64| json!({ "type": "max_blast_radius", "max": max });
    assert!(ev(br(0.6), |_| {}) && ev(br(0.5), |_| {}) && !ev(br(0.4), |_| {}));
    assert!(!ev(br(0.6), |c| c.blast_radius = None));
    assert!(!ev(br(0.6), |c| c.blast_radius = Some(f64::NEG_INFINITY)));
    assert!(!ev(br(0.6), |c| c.blast_radius = Some(f64::NAN)));
    assert!(!ev(json!({ "type": "max_blast_radius" }), |_| {}));

    let dd = |max: f64| json!({ "type": "delegation_depth", "max": max });
    assert!(ev(dd(2.0), |c| c.delegation_depth = Some(2.0)));
    assert!(ev(dd(2.0), |c| c.delegation_depth = Some(1.0)));
    assert!(!ev(dd(2.0), |c| c.delegation_depth = Some(3.0)));
    assert!(ev(dd(0.0), |c| c.delegation_depth = Some(0.0)));
    assert!(!ev(dd(2.0), |c| c.delegation_depth = None));
    assert!(!ev(dd(2.0), |c| c.delegation_depth = Some(f64::NEG_INFINITY)), "a non-finite depth is refused");
    assert!(!ev(dd(2.0), |c| c.delegation_depth = Some(f64::NAN)));
    assert!(!ev(json!({ "type": "delegation_depth" }), |_| {}));

    assert!(ev(json!({ "type": "budget_alloc", "limit": 5 }), |_| {}));
    assert!(ev(json!({ "type": "budget_alloc", "limit": 0 }), |_| {}));
    assert!(!ev(json!({ "type": "budget_alloc", "limit": -1 }), |_| {}));
    assert!(!ev(json!({ "type": "budget_alloc" }), |_| {}));
    assert!(!ev(json!({ "type": "budget_alloc", "limit": "5" }), |_| {}));

    let rv = |class: &str| json!({ "type": "reversibility_max", "class": class });
    for (lim, cur, want) in [
        ("reversible", "reversible", true),
        ("reversible", "rate_limited", false),
        ("reversible", "irreversible", false),
        ("rate_limited", "reversible", true),
        ("rate_limited", "rate_limited", true),
        ("rate_limited", "irreversible", false),
        ("irreversible", "reversible", true),
        ("irreversible", "rate_limited", true),
        ("irreversible", "irreversible", true),
    ] {
        assert_eq!(ev(rv(lim), with(Some(cur))), want, "limit {lim} current {cur}");
    }
    assert!(!ev(rv("bogus"), with(Some("reversible"))));
    assert!(!ev(rv("reversible"), with(Some("bogus"))));
    assert!(!ev(rv("irreversible"), with(None)));
    assert!(!ev(json!({ "type": "reversibility_max" }), with(Some("reversible"))));
}

#[test]
fn caveat_dispatch_and_outcomes() {
    let e = Env { root: root(json!({ "verb": "v", "resource": "r" })) };
    let c = base_ctx(&e.root);
    for bad in [json!(5), json!("expires"), json!([]), json!({}), json!({ "type": 5 }), json!({ "type": "nope" })] {
        assert!(!evaluate_caveat(&bad, &c), "{bad}");
    }
    let ok = evaluate_caveats(&[json!({ "type": "expires", "at": 200000 }), json!({ "type": "budget_alloc", "limit": 1 })], &c);
    assert!(ok.ok && ok.failed.is_empty());
    let mixed = evaluate_caveats(&[json!({ "type": "expires", "at": 5 }), json!({ "type": "budget_alloc", "limit": 1 }), json!({ "type": "not_before", "at": 200000 })], &c);
    assert!(!mixed.ok);
    assert_eq!(mixed.failed, vec!["expires".to_string(), "not_before".to_string()]);
    let weird = evaluate_caveats(&[json!(7), json!({ "type": "zzz" })], &c);
    assert!(!weird.ok);
    assert_eq!(weird.failed, vec!["<malformed>".to_string(), "zzz".to_string()]);
    assert!(evaluate_caveats(&[], &c).ok);
}

#[test]
fn predicates_caveat() {
    let allow = json!({ "type": "predicates", "allow": [{ "verb": "nope" }, { "verb": "v" }] });
    assert!(ev(allow, |_| {}));
    assert!(!ev(json!({ "type": "predicates", "allow": [{ "verb": "nope" }] }), |_| {}));
    assert!(!ev(json!({ "type": "predicates", "allow": [] }), |_| {}));
    assert!(!ev(json!({ "type": "predicates" }), |_| {}));
    assert!(!ev(json!({ "type": "predicates", "allow": "v" }), |_| {}));
}

// ------------------------------------------------------------------------------------------------ tool_schema

fn tool_caveat(tool: &str, schema: Value, sig: &str) -> Value {
    let binding = json!({ "tool": tool, "signature_digest": sig, "schema": schema });
    json!({
        "type": "tool_schema", "tool": tool, "schema": schema, "signature_digest": sig,
        "schema_digest": hash_canonical(&schema), "binding_digest": hash_canonical(&binding),
    })
}

fn call(args: Value) -> impl FnOnce(&mut CaveatCtx) {
    move |c: &mut CaveatCtx| {
        c.tool = Some("t".into());
        c.tool_args = Some(args);
    }
}

fn tool_ok(schema: Value, args: Value) -> bool {
    ev(tool_caveat("t", schema, "sig"), call(args))
}

#[test]
fn tool_schema_wellformedness() {
    let s = || json!({ "props": { "a": { "type": "string" } } });
    assert!(tool_ok(s(), json!({ "a": "x" })));
    assert!(tool_ok(s(), json!({})));
    // wrong binding material
    let good = tool_caveat("t", s(), "sig");
    for key in ["tool", "schema", "schema_digest", "signature_digest", "binding_digest"] {
        let mut cv = good.clone();
        cv.as_object_mut().unwrap().remove(key);
        assert!(!ev(cv, call(json!({}))), "missing {key}");
    }
    for (key, v) in [("tool", json!(5)), ("tool", json!("")), ("schema_digest", json!(5)), ("signature_digest", json!(5)), ("binding_digest", json!(5)), ("schema_digest", json!("x")), ("binding_digest", json!("x")), ("signature_digest", json!("other"))] {
        let mut cv = good.clone();
        cv[key] = v.clone();
        assert!(!ev(cv, call(json!({}))), "{key}={v}");
    }
    // no / malformed call
    assert!(!ev(good.clone(), |_| {}));
    assert!(!ev(good.clone(), |c| c.tool = Some("t".into())));
    assert!(!ev(good.clone(), |c| c.tool_args = Some(json!({}))));
    assert!(!ev(good.clone(), |c| { c.tool = Some("t".into()); c.tool_args = Some(json!([])); }));
    assert!(!ev(good.clone(), |c| { c.tool = Some("t".into()); c.tool_args = Some(json!("x")); }));
    assert!(!ev(good.clone(), |c| { c.tool = Some("other".into()); c.tool_args = Some(json!({})); }), "tool not authorized");
    // signed tool_binding digest: absent is fine, equal is fine, different is refused
    assert!(ev(good.clone(), |c| { call(json!({}))(c); c.tool_signature_digest = Some("sig".into()); }));
    assert!(!ev(good.clone(), |c| { call(json!({}))(c); c.tool_signature_digest = Some("sig2".into()); }));
    // unknown schema top-level key, non-object schema, props missing / mistyped
    assert!(!tool_ok(json!({ "props": {}, "extra": 1 }), json!({})));
    assert!(!tool_ok(json!("x"), json!({})));
    assert!(!tool_ok(json!({}), json!({})));
    assert!(!tool_ok(json!({ "props": [] }), json!({})));
    assert!(tool_ok(json!({ "props": {} }), json!({})));
}

#[test]
fn tool_schema_property_names() {
    let name_ok = |n: &str| tool_ok(json!({ "props": { n: { "type": "boolean" } } }), json!({}));
    for ok in ["a", "A", "z9", "_", "a_b", "_x", "x_", "0", &"a".repeat(64)] {
        assert!(name_ok(ok), "{ok:?} is a safe name");
    }
    for bad in ["", "a-b", "a b", "a.b", "é", "a\n", &"a".repeat(65), "$x", "a/b"] {
        assert!(!name_ok(bad), "{bad:?} is not a safe name");
    }
}

#[test]
fn tool_schema_limits_in_the_schema() {
    // props count: 64 ok, 65 refused
    let props = |n: usize| {
        let mut m = serde_json::Map::new();
        for i in 0..n {
            m.insert(format!("p{i}"), json!({ "type": "boolean" }));
        }
        Value::Object(m)
    };
    assert!(tool_ok(json!({ "props": props(64) }), json!({})));
    assert!(!tool_ok(json!({ "props": props(65) }), json!({})));
    // required: array of declared names, at most 64
    assert!(tool_ok(json!({ "props": props(3), "required": ["p0", "p2"] }), json!({ "p0": true, "p2": false })));
    assert!(!tool_ok(json!({ "props": props(3), "required": ["p0", "zz"] }), json!({ "p0": true })));
    assert!(!tool_ok(json!({ "props": props(3), "required": "p0" }), json!({ "p0": true })));
    assert!(!tool_ok(json!({ "props": props(3), "required": [1] }), json!({})));
    let req = |n: usize| Value::Array((0..n).map(|_| json!("p0")).collect());
    assert!(tool_ok(json!({ "props": props(3), "required": req(64) }), json!({ "p0": true })));
    assert!(!tool_ok(json!({ "props": props(3), "required": req(65) }), json!({ "p0": true })));
    // nesting depth: object -> object -> ... up to 8 levels (schema root = depth 1)
    let nest = |levels: usize| {
        let mut spec = json!({ "type": "boolean" });
        for _ in 0..levels {
            spec = json!({ "type": "object", "props": { "k": spec } });
        }
        json!({ "props": { "k": spec } })
    };
    let nested_args = |levels: usize| {
        let mut v = json!(true);
        for _ in 0..=levels {
            v = json!({ "k": v });
        }
        v
    };
    assert!(tool_ok(nest(2), nested_args(2)));
    let mut max_ok = 0;
    for l in 0..12 {
        if tool_ok(nest(l), nested_args(l)) {
            max_ok = l;
        }
    }
    assert_eq!(max_ok, 6, "deepest accepted nesting (schema depth cap 8, call depth cap 9)");
    assert!(!tool_ok(nest(7), nested_args(7)));
    assert!(!tool_ok(nest(8), nested_args(8)));
    // node budget: 256 schema nodes
    let wide = |n: usize| {
        // one root object node + n scalar nodes
        json!({ "props": props(n) })
    };
    assert!(tool_ok(wide(64), json!({})));
    let two_level = |objs: usize, per: usize| {
        let mut m = serde_json::Map::new();
        for i in 0..objs {
            m.insert(format!("o{i}"), json!({ "type": "object", "props": props(per) }));
        }
        json!({ "props": Value::Object(m) })
    };
    // 1 (root) + objs * (1 + per): 1 + 5*(1+50) = 256 ok ; 1 + 3*(1+50) + (1+51) = 206.. build exact boundary
    assert!(tool_ok(two_level(5, 50), json!({})), "exactly 256 nodes");
    assert!(!tool_ok(two_level(5, 51), json!({})), "261 nodes");
    let mut m = two_level(5, 50);
    m["props"]["extra"] = json!({ "type": "boolean" });
    assert!(!tool_ok(m, json!({})), "257 nodes");
}

#[test]
fn tool_schema_spec_validation() {
    let one = |spec: Value| tool_ok(json!({ "props": { "a": spec } }), json!({}));
    // types and their allowed keys
    assert!(one(json!({ "type": "string", "enum": ["a"], "const": "a", "minLength": 1, "maxLength": 5, "prefix": "a" })));
    assert!(one(json!({ "type": "number", "enum": [1.5], "const": 1.5, "min": 0, "max": 5 })));
    assert!(one(json!({ "type": "integer", "enum": [1], "const": 1, "min": 0, "max": 5 })));
    assert!(one(json!({ "type": "boolean", "enum": [true], "const": true })));
    assert!(one(json!({ "type": "object", "props": {}, "required": [] })));
    assert!(one(json!({ "type": "array", "items": { "type": "boolean" }, "minItems": 0, "maxItems": 4 })));
    for bad in [
        json!(5), json!("string"), json!({}), json!({ "type": 5 }), json!({ "type": "null" }),
        json!({ "type": "string", "min": 1 }), json!({ "type": "number", "minLength": 1 }), json!({ "type": "integer", "prefix": "a" }),
        json!({ "type": "boolean", "min": 1 }), json!({ "type": "boolean", "maxLength": 1 }), json!({ "type": "object", "enum": [] }),
        json!({ "type": "object", "const": {} }), json!({ "type": "array", "enum": [] }), json!({ "type": "array", "props": {} }),
    ] {
        assert!(!one(bad.clone()), "{bad}");
    }
    // const / enum value kinds
    assert!(!one(json!({ "type": "string", "const": 1 })));
    assert!(!one(json!({ "type": "boolean", "const": "true" })));
    assert!(!one(json!({ "type": "number", "const": "1" })));
    assert!(!one(json!({ "type": "integer", "const": 1.5 })));
    assert!(one(json!({ "type": "integer", "const": -3 })));
    // R5-ZK-03: an integer above 2^53-1 is outside the strict canonical profile, so `hashCanonical(schema)` throws in TS => unsatisfied
    assert!(!one(json!({ "type": "integer", "const": 18446744073709551615u64 })));
    assert!(one(json!({ "type": "integer", "const": 9007199254740991u64 })));
    assert!(!one(json!({ "type": "string", "enum": [] })));
    assert!(!one(json!({ "type": "string", "enum": "a" })));
    assert!(!one(json!({ "type": "string", "enum": ["a", 1] })));
    assert!(!one(json!({ "type": "boolean", "enum": [true, "x"] })));
    assert!(!one(json!({ "type": "integer", "enum": [1, 1.5] })));
    assert!(one(json!({ "type": "integer", "enum": [1, -2, 3] })));
    // enum size 256 ok, 257 refused; string constants up to 1024 bytes
    let en = |n: usize| Value::Array((0..n).map(|i| json!(format!("s{i}"))).collect());
    assert!(one(json!({ "type": "string", "enum": en(256) })));
    assert!(!one(json!({ "type": "string", "enum": en(257) })));
    assert!(one(json!({ "type": "string", "const": "x".repeat(1024) })));
    assert!(!one(json!({ "type": "string", "const": "x".repeat(1025) })));
    assert!(one(json!({ "type": "string", "enum": [ "x".repeat(1024) ] })));
    assert!(!one(json!({ "type": "string", "enum": [ "x".repeat(1025) ] })));
    // arrays: items mandatory, minItems/maxItems non-negative ints <= 4096, min <= max
    assert!(!one(json!({ "type": "array" })));
    assert!(!one(json!({ "type": "array", "items": 5 })));
    assert!(one(json!({ "type": "array", "items": { "type": "boolean" }, "maxItems": 4096 })));
    assert!(!one(json!({ "type": "array", "items": { "type": "boolean" }, "maxItems": 4097 })));
    assert!(one(json!({ "type": "array", "items": { "type": "boolean" }, "minItems": 4096 })));
    assert!(!one(json!({ "type": "array", "items": { "type": "boolean" }, "minItems": 4097 })));
    assert!(!one(json!({ "type": "array", "items": { "type": "boolean" }, "minItems": -1 })));
    assert!(!one(json!({ "type": "array", "items": { "type": "boolean" }, "maxItems": 1.5 })));
    assert!(!one(json!({ "type": "array", "items": { "type": "boolean" }, "minItems": "1" })));
    assert!(one(json!({ "type": "array", "items": { "type": "boolean" }, "minItems": 3, "maxItems": 3 })));
    assert!(!one(json!({ "type": "array", "items": { "type": "boolean" }, "minItems": 4, "maxItems": 3 })));
    assert!(one(json!({ "type": "array", "items": { "type": "boolean" }, "minItems": 0, "maxItems": 0 })));
    // array of arrays: item specs are validated recursively
    assert!(one(json!({ "type": "array", "items": { "type": "array", "items": { "type": "boolean" } } })));
    assert!(!one(json!({ "type": "array", "items": { "type": "array", "items": { "type": "null" } } })));
    // nested object inside an object schema validates its own required list
    assert!(!one(json!({ "type": "object", "props": { "x": { "type": "boolean" } }, "required": ["y"] })));
    assert!(one(json!({ "type": "object", "props": { "x": { "type": "boolean" } }, "required": ["x"] })));
    assert!(!one(json!({ "type": "object" })), "object spec needs props");
}

#[test]
fn tool_schema_value_checks() {
    let t = |spec: Value, v: Value| tool_ok(json!({ "props": { "a": spec } }), json!({ "a": v }));
    // strings
    let st = json!({ "type": "string", "minLength": 2, "maxLength": 4, "prefix": "ab" });
    assert!(t(st.clone(), json!("abc")) && t(st.clone(), json!("ab")) && t(st.clone(), json!("abcd")));
    assert!(!t(st.clone(), json!("a")) && !t(st.clone(), json!("abcde")) && !t(st.clone(), json!("xbc")) && !t(st.clone(), json!(5)));
    // lengths count characters, not bytes
    assert!(t(json!({ "type": "string", "maxLength": 2 }), json!("éé")) && !t(json!({ "type": "string", "maxLength": 2 }), json!("ééé")));
    assert!(t(json!({ "type": "string", "minLength": 2 }), json!("éé")) && !t(json!({ "type": "string", "minLength": 3 }), json!("éé")));
    // default maxLength 65536, absolute cap 1 MiB
    assert!(t(json!({ "type": "string" }), json!("x".repeat(65_536))));
    assert!(!t(json!({ "type": "string" }), json!("x".repeat(65_537))));
    assert!(t(json!({ "type": "string", "maxLength": 100_000 }), json!("x".repeat(100_000))));
    assert!(!t(json!({ "type": "string", "maxLength": 100_000 }), json!("x".repeat(100_001))));
    // R5-ZK-01: a maxLength above the absolute cap is MALFORMED (TS `nonNegInt(maxLength, 1 MiB)`), it is never clamped
    assert!(!t(json!({ "type": "string", "maxLength": 2_000_000 }), json!("x".repeat(1_048_577))));
    assert!(!t(json!({ "type": "string", "maxLength": 2_000_000 }), json!("x".repeat(1_048_576))));
    assert!(t(json!({ "type": "string", "maxLength": 1_048_576 }), json!("x".repeat(1_048_576))));
    assert!(!t(json!({ "type": "string", "maxLength": 1_048_576 }), json!("x".repeat(1_048_577))));
    // numbers / integers
    let n = json!({ "type": "number", "min": 1, "max": 3 });
    assert!(t(n.clone(), json!(1)) && t(n.clone(), json!(2.5)) && t(n.clone(), json!(3)));
    assert!(!t(n.clone(), json!(0.99)) && !t(n.clone(), json!(3.01)) && !t(n.clone(), json!("2")) && !t(n.clone(), json!(null)));
    let i = json!({ "type": "integer", "min": 1, "max": 3 });
    assert!(t(i.clone(), json!(1)) && t(i.clone(), json!(3)) && !t(i.clone(), json!(2.5)) && !t(i.clone(), json!(0)) && !t(i.clone(), json!(4)));
    assert!(t(json!({ "type": "integer" }), json!(-7)) && t(json!({ "type": "integer" }), json!(18446744073709551615u64)));
    // R5-ZK-01: JavaScript has one number type (`JSON.parse("1.0") === 1`), so an integral float IS an integer (`Number.isInteger`)
    assert!(t(json!({ "type": "integer" }), json!(1.0)), "1.0 is an integer in JavaScript");
    assert!(!t(json!({ "type": "integer" }), json!(1.5)));
    assert!(t(json!({ "type": "number" }), json!(1.0)) && t(json!({ "type": "number" }), json!(-0.5)));
    // booleans
    assert!(t(json!({ "type": "boolean" }), json!(false)) && !t(json!({ "type": "boolean" }), json!(0)) && !t(json!({ "type": "boolean" }), json!("true")));
    // const / enum on values
    assert!(t(json!({ "type": "string", "const": "x" }), json!("x")) && !t(json!({ "type": "string", "const": "x" }), json!("y")));
    assert!(t(json!({ "type": "number", "const": 2 }), json!(2)) && !t(json!({ "type": "number", "const": 2 }), json!(3)));
    assert!(t(json!({ "type": "boolean", "const": true }), json!(true)) && !t(json!({ "type": "boolean", "const": true }), json!(false)));
    assert!(t(json!({ "type": "string", "enum": ["a", "b"] }), json!("b")) && !t(json!({ "type": "string", "enum": ["a", "b"] }), json!("c")));
    assert!(t(json!({ "type": "integer", "enum": [1, 2] }), json!(2)) && !t(json!({ "type": "integer", "enum": [1, 2] }), json!(3)));
    assert!(t(json!({ "type": "boolean", "enum": [true] }), json!(true)) && !t(json!({ "type": "boolean", "enum": [true] }), json!(false)));
    // arrays
    let a = json!({ "type": "array", "items": { "type": "integer" }, "minItems": 1, "maxItems": 3 });
    assert!(t(a.clone(), json!([1])) && t(a.clone(), json!([1, 2, 3])));
    assert!(!t(a.clone(), json!([])) && !t(a.clone(), json!([1, 2, 3, 4])) && !t(a.clone(), json!([1, "x"])) && !t(a.clone(), json!("x")) && !t(a.clone(), json!({})));
    // default maxItems 256, absolute cap 4096
    let arr = |n: usize| Value::Array((0..n).map(|_| json!(true)).collect());
    let items = json!({ "type": "boolean" });
    assert!(t(json!({ "type": "array", "items": items }), arr(256)));
    assert!(!t(json!({ "type": "array", "items": items }), arr(257)));
    assert!(t(json!({ "type": "array", "items": items, "maxItems": 1000 }), arr(1000)));
    assert!(!t(json!({ "type": "array", "items": items, "maxItems": 1000 }), arr(1001)));
    assert!(t(json!({ "type": "array", "items": items, "maxItems": 4096 }), arr(4096)));
    // nested object values
    let o = json!({ "type": "object", "props": { "x": { "type": "integer" }, "y": { "type": "boolean" } }, "required": ["x"] });
    assert!(t(o.clone(), json!({ "x": 1 })) && t(o.clone(), json!({ "x": 1, "y": true })));
    assert!(!t(o.clone(), json!({})) && !t(o.clone(), json!({ "y": true })) && !t(o.clone(), json!({ "x": 1, "z": 2 })) && !t(o.clone(), json!({ "x": "1" })) && !t(o.clone(), json!([])) && !t(o.clone(), json!(5)));
    // top-level: unexpected / missing arguments
    let schema = json!({ "props": { "a": { "type": "boolean" }, "b": { "type": "boolean" } }, "required": ["a"] });
    assert!(tool_ok(schema.clone(), json!({ "a": true })));
    assert!(!tool_ok(schema.clone(), json!({})));
    assert!(!tool_ok(schema.clone(), json!({ "a": true, "c": true })));
    assert!(!tool_ok(schema, json!({ "b": true })));
}

#[test]
fn tool_schema_value_node_budget() {
    // 10_000 value nodes: an object arg holding arrays; each scalar element and the array itself count one node
    let nodes_schema = json!({ "props": { "a": { "type": "array", "maxItems": 4096, "items": { "type": "array", "maxItems": 4096, "items": { "type": "boolean" } } } } });
    let arr = |n: usize| Value::Array((0..n).map(|_| json!(true)).collect());
    // 1 (a) + 3 inner arrays (each 1 + len): choose lens so total == 10_000 then 10_001
    let args = |lens: [usize; 3]| json!({ "a": [arr(lens[0]), arr(lens[1]), arr(lens[2])] });
    // nodes = 1 + 3 + sum(lens) = 4 + sum
    assert!(tool_ok(nodes_schema.clone(), args([4096, 4096, 1804])), "exactly 10_000 value nodes");
    assert!(!tool_ok(nodes_schema.clone(), args([4096, 4096, 1805])), "10_001 value nodes");
    assert!(tool_ok(nodes_schema, args([10, 10, 10])));
}

// ------------------------------------------------------------------------------------- canonical / risk

#[test]
fn canonical_numbers_and_strings() {
    assert_eq!(canonicalize(&json!(1e20)), "100000000000000000000");
    assert_eq!(canonicalize(&json!(2.5)), "2.5");
    assert_eq!(canonicalize(&json!(-0.0)), "0");
    assert_eq!(canonicalize(&json!(5.0)), "5");
    assert_eq!(canonicalize(&json!(9007199254740992.0)), "9007199254740992");
    assert_eq!(canonicalize(&json!(9007199254740991.0)), "9007199254740991");
    assert_eq!(canonicalize(&json!(-1e20)), "-100000000000000000000");
    assert_eq!(canonicalize(&json!("a\u{1}b")), "\"a\\u0001b\"");
    assert_eq!(canonicalize(&json!("\u{1f}")), "\"\\u001f\"");
    assert_eq!(canonicalize(&json!("\u{b}")), "\"\\u000b\"");
    assert_eq!(canonicalize(&json!("\u{0}")), "\"\\u0000\"");
    assert_eq!(canonicalize(&json!("\u{10}")), "\"\\u0010\"");
    assert_eq!(canonicalize(&json!("\u{20}\u{7f}é")), "\" \u{7f}é\"");
    assert_eq!(canonicalize(&json!("\u{8}\u{9}\u{a}\u{c}\u{d}\"\\")), "\"\\b\\t\\n\\f\\r\\\"\\\\\"");
}

fn policy() -> RiskPolicyScaled {
    RiskPolicyScaled { weights: [200_000; 6], theta1_scaled: 300_000, theta2_scaled: 600_000, kappa: 10, bmax_scaled: S }
}

#[test]
fn tier_boundaries() {
    let p = policy();
    let sc = S as u128;
    let t1 = 300_000u128 * sc;
    let t2 = 600_000u128 * sc;
    assert_eq!(tier(0, &p), 1);
    assert_eq!(tier(t1 - 1, &p), 1);
    assert_eq!(tier(t1, &p), 1);
    assert_eq!(tier(t1 + 1, &p), 2);
    assert_eq!(tier(t2 - 1, &p), 2);
    assert_eq!(tier(t2, &p), 2);
    assert_eq!(tier(t2 + 1, &p), 3);
    assert_eq!(tier(sc * sc, &p), 3);
    // a different policy (thetas must be multiplied by S, not added or divided)
    let q = RiskPolicyScaled { theta1_scaled: 1, theta2_scaled: 2, ..p };
    assert_eq!(tier(sc, &q), 1);
    assert_eq!(tier(sc + 1, &q), 2);
    assert_eq!(tier(2 * sc, &q), 2);
    assert_eq!(tier(2 * sc + 1, &q), 3);
}

#[test]
fn budget_and_auto_admit_boundaries() {
    let p = policy();
    let sc = S as u128;
    let r = 100_000u128 * sc; // r = 0.1 at S^2
    // B * S >= kappa * r_raw  =>  B >= 10 * 100000 = 1_000_000
    assert!(budget_covers(1_000_000, r, &p));
    assert!(!budget_covers(999_999, r, &p));
    assert!(auto_admit(r, 1_000_000, &p));
    assert!(!auto_admit(r, 999_999, &p));
    // tier must be 1 as well
    let hi = 400_000u128 * sc;
    assert!(!auto_admit(hi, u64::MAX, &p));
    assert!(auto_admit(300_000u128 * sc, u64::MAX, &p));
}

#[test]
fn risk_raw_composition() {
    let p = policy();
    let x = RiskInputsScaled { x: [S, 0, 0, 0, S, 0] }; // rev (index 1) and conf (index 4) are inverted
    // terms: S, S-0, 0, 0, S-S=0, 0 -> 200000 * (S + S) = 4e11
    assert_eq!(risk_raw(&x, &p, 0), 200_000u128 * (2 * sc()));
    // inputs above S clamp to S
    let big = RiskInputsScaled { x: [u64::MAX, 0, 0, 0, S, 0] };
    assert_eq!(risk_raw(&big, &p, 0), risk_raw(&x, &p, 0));
    // the sum clamps to S^2
    let all = RiskInputsScaled { x: [S, 0, S, S, 0, S] };
    let heavy = RiskPolicyScaled { weights: [S; 6], ..p };
    assert_eq!(risk_raw(&all, &heavy, 0), sc() * sc());
    // the monotone floor only raises: floor (scale S) * S
    assert_eq!(risk_raw(&x, &p, 900_000), 900_000u128 * sc());
    assert_eq!(risk_raw(&x, &p, 1), risk_raw(&x, &p, 0));
    assert_eq!(risk_raw(&x, &p, u64::MAX), sc() * sc(), "floor clamps to S");
}

fn sc() -> u128 {
    S as u128
}
