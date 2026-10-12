//! cargo-mutants survivor kills (batch Z2a) for `core/src/predicates.rs`: poisoned-action deep equality, boolean
//! canonical equality, the `like` glob parser/matcher, the `member_of` closure bound, and the tri-state leaf guards.
//! Every expected value is the TS reference verdict (packages/pca/src/predicates.ts `triLeaf` / `parseGlob` /
//! `globMatch` / `memberClosure` / `evaluateConditionTri`).
use pca_zkvm_core::predicates::{
    evaluate_condition_tri, js_canonical_eq, Ctx, Tri, MAX_LIKE_PATTERN_LEN, MAX_MEMBER_CLOSURE_NODES,
    MAX_PATTERN_SUBJECT_LEN,
};
use serde_json::{json, Map, Value};

fn root(action: Value) -> Value {
    json!({ "action": action, "subject": {"role": "admin"}, "env": {"region": "eu"} })
}

/// A complete TS projection (all four keys present) so `action` is not poisoned.
fn full_action(extra: Value) -> Value {
    let mut a = json!({ "verb": "v", "resource": "r", "params": {}, "reversibility_class": "reversible" });
    if let Value::Object(e) = extra {
        for (k, v) in e {
            a.as_object_mut().unwrap().insert(k, v);
        }
    }
    a
}

fn tri_with(c: Value, r: &Value) -> Tri {
    evaluate_condition_tri(&c, &Ctx::new(r))
}

fn tri(c: Value, action: Value) -> Tri {
    tri_with(c, &root(action))
}

// ------------------------------------------------------------------------------------ poisoned action / deep_eq

/// TS: `action` built with an `undefined` member (here `params`, `reversibility_class`) makes `canonicalize` throw, so
/// `deepEq` is false, even against itself. Kills `poisoned -> false` (L89) and `|| -> &&` in `deep_eq` (L94).
#[test]
fn poisoned_action_never_deep_equals() {
    let partial = json!({ "verb": "v", "resource": "r" });
    // a == b, both the poisoned action (poisoned(a) && poisoned(b) would still be true; this pins poisoned itself)
    assert_eq!(tri(json!({ "field": "action", "op": "eq", "ref": "action" }), partial.clone()), Tri::False);
    assert_eq!(tri(json!({ "field": "action", "op": "ne", "ref": "action" }), partial.clone()), Tri::True);
    // only the LEFT side poisoned (the literal operand is structurally equal)
    assert_eq!(
        tri(json!({ "field": "action", "op": "eq", "value": {"verb": "v", "resource": "r"} }), partial.clone()),
        Tri::False
    );
    // only the RIGHT side poisoned
    let r = json!({ "action": partial, "subject": {"copy": {"verb": "v", "resource": "r"}}, "env": {} });
    assert_eq!(tri_with(json!({ "field": "subject.copy", "op": "eq", "ref": "action" }), &r), Tri::False);
    assert_eq!(tri_with(json!({ "field": "subject.copy", "op": "in", "value": [] }), &r), Tri::False);
    // control: a complete projection is NOT poisoned and does deep-equal itself
    let full = full_action(json!({}));
    assert_eq!(tri(json!({ "field": "action", "op": "eq", "ref": "action" }), full.clone()), Tri::True);
    assert_eq!(tri(json!({ "field": "action", "op": "eq", "value": full.clone() }), full), Tri::True);
}

/// Kills the deleted `(Bool, Bool)` arm and `== -> !=` on it (L119).
#[test]
fn boolean_canonical_equality() {
    assert!(js_canonical_eq(&json!(true), &json!(true)));
    assert!(js_canonical_eq(&json!(false), &json!(false)));
    assert!(!js_canonical_eq(&json!(true), &json!(false)));
    assert!(!js_canonical_eq(&json!(false), &json!(true)));
    assert!(js_canonical_eq(&json!([true, {"b": false}]), &json!([true, {"b": false}])));
    let a = full_action(json!({ "flag": true }));
    assert_eq!(tri(json!({ "field": "action.flag", "op": "eq", "value": true }), a.clone()), Tri::True);
    assert_eq!(tri(json!({ "field": "action.flag", "op": "eq", "value": false }), a.clone()), Tri::False);
    assert_eq!(tri(json!({ "field": "action.flag", "op": "in", "value": [false, true] }), a), Tri::True);
}

// ------------------------------------------------------------------------------------------------- like / glob

fn like(subject: &str, glob: &str) -> Tri {
    tri(json!({ "field": "action.s", "op": "like", "value": glob }), full_action(json!({ "s": subject })))
}

/// `parseGlob` escape handling (L186 `i + 1`, L188 `i += 1`).
#[test]
fn glob_escapes() {
    assert_eq!(like("a", "\\a"), Tri::True); // escape at index 0
    assert_eq!(like("aa", "\\a"), Tri::False);
    assert_eq!(like("x*y", "x\\*y"), Tri::True); // escaped star is literal
    assert_eq!(like("xzy", "x\\*y"), Tri::False);
    assert_eq!(like("x?y", "x\\?y"), Tri::True);
    assert_eq!(like("xzy", "x\\?y"), Tri::False);
    assert_eq!(like("\\", "\\\\"), Tri::True);
    assert_eq!(like("ab", "\\a\\b"), Tri::True);
    // dangling backslash: parseGlob -> null -> unknown
    assert_eq!(like("\\", "\\"), Tri::Unknown);
    assert_eq!(like("a\\", "a\\"), Tri::Unknown);
}

/// `?` matches exactly one UTF-16 unit (L216 arm, L217 `ti += 1`, L218 `si += 1`).
#[test]
fn glob_question_mark() {
    assert_eq!(like("a", "?"), Tri::True);
    assert_eq!(like("abc", "a?c"), Tri::True);
    assert_eq!(like("ac", "a?c"), Tri::False);
    assert_eq!(like("abbc", "a?c"), Tri::False);
    assert_eq!(like("ab", "??"), Tri::True);
    assert_eq!(like("a", "??"), Tri::False);
    assert_eq!(like("", "?"), Tri::False);
    // an astral character is TWO UTF-16 units
    assert_eq!(like("\u{1F600}", "??"), Tri::True);
    assert_eq!(like("\u{1F600}", "?"), Tri::False);
}

/// Trailing stars are skipped after the subject is consumed (L235 `ti += 1`).
#[test]
fn glob_trailing_stars() {
    assert_eq!(like("a", "a*"), Tri::True);
    assert_eq!(like("", "*"), Tri::True);
    assert_eq!(like("", "**"), Tri::True);
    assert_eq!(like("ab", "a*b*"), Tri::True);
    assert_eq!(like("a", "a*b"), Tri::False);
}

/// `like` length caps are `>` on both the glob and the subject, joined by `||` (L428).
#[test]
fn like_length_caps() {
    let star = |n: usize| "*".repeat(n);
    let subj = |n: usize| "x".repeat(n);
    assert_eq!(like("x", &star(MAX_LIKE_PATTERN_LEN)), Tri::True); // glob at the cap is evaluated
    assert_eq!(like("x", &star(MAX_LIKE_PATTERN_LEN + 1)), Tri::Unknown); // over the cap, short subject
    assert_eq!(like(&subj(MAX_PATTERN_SUBJECT_LEN), "*"), Tri::True); // subject at the cap is evaluated
    assert_eq!(like(&subj(MAX_PATTERN_SUBJECT_LEN + 1), "*"), Tri::Unknown); // over the cap, short glob
    assert_eq!(like(&subj(MAX_PATTERN_SUBJECT_LEN + 1), &star(MAX_LIKE_PATTERN_LEN + 1)), Tri::Unknown);
    // lengths are UTF-16 units: 256 astral chars = 512 units (at the cap), 257 = 514 (over)
    assert_eq!(like(&"\u{1F600}".repeat(256), "*"), Tri::True);
    assert_eq!(like(&"\u{1F600}".repeat(257), "*"), Tri::Unknown);
}

// -------------------------------------------------------------------------------------------------- member_of

/// `memberClosure` dequeues exactly MAX_MEMBER_CLOSURE_NODES nodes (L287 `<`, L292 `visited += 1`): on a chain
/// n0 -> n1 -> ..., the 10_000 visits of n0..n9999 add n1..n10000 to the closure, and n10001 is never reached.
#[test]
fn member_closure_bound() {
    let mut adj = Map::new();
    for i in 0..(MAX_MEMBER_CLOSURE_NODES + 5) {
        adj.insert(format!("n{i}"), json!(format!("n{}", i + 1)));
    }
    let r = json!({
        "action": full_action(json!({ "who": "n0" })),
        "subject": {},
        "env": { "groups": Value::Object(adj) },
    });
    let m = |target: Value| tri_with(json!({ "field": "action.who", "op": "member_of", "collection": "env.groups", "value": target }), &r);
    assert_eq!(m(json!("n0")), Tri::True); // reflexive
    assert_eq!(m(json!("n1")), Tri::True);
    assert_eq!(m(json!(format!("n{}", MAX_MEMBER_CLOSURE_NODES - 1))), Tri::True);
    assert_eq!(m(json!(format!("n{}", MAX_MEMBER_CLOSURE_NODES))), Tri::True);
    assert_eq!(m(json!(format!("n{}", MAX_MEMBER_CLOSURE_NODES + 1))), Tri::False);
    assert_eq!(m(json!(format!("n{}", MAX_MEMBER_CLOSURE_NODES + 2))), Tri::False);
}

/// An ARRAY target operand is filtered to its strings (L381 arm).
#[test]
fn member_of_array_targets() {
    let r = json!({
        "action": full_action(json!({ "who": "alice" })),
        "subject": {},
        "env": { "groups": { "alice": ["eng"], "eng": "staff" } },
    });
    let m = |target: Value| tri_with(json!({ "field": "action.who", "op": "member_of", "collection": "env.groups", "value": target }), &r);
    assert_eq!(m(json!(["staff"])), Tri::True);
    assert_eq!(m(json!([1, "nope", "eng"])), Tri::True);
    assert_eq!(m(json!(["nope", "other"])), Tri::False);
    assert_eq!(m(json!([1, 2])), Tri::Unknown); // no string target
    assert_eq!(m(json!([])), Tri::Unknown);
    assert_eq!(m(json!("staff")), Tri::True);
}

// -------------------------------------------------------------------------------------- tri-state leaf guards

/// TS: `c.field.length === 0` => unknown, BEFORE the `exists` op (L338): `exists:false` on "" is unknown, not true.
#[test]
fn empty_field_is_unknown() {
    let a = full_action(json!({}));
    assert_eq!(tri(json!({ "field": "", "op": "exists", "value": false }), a.clone()), Tri::Unknown);
    assert_eq!(tri(json!({ "field": "", "op": "exists" }), a.clone()), Tri::Unknown);
    assert_eq!(tri(json!({ "not": { "field": "", "op": "exists" } }), a), Tri::Unknown);
}

/// TS: `is_a` with an empty type operand => unknown (L453), not the `typeTagMatch` verdict.
#[test]
fn is_a_empty_type_is_unknown() {
    let a = full_action(json!({ "s": "x", "o": {"type": "doc", "tags": ["t"]} }));
    assert_eq!(tri(json!({ "field": "action.s", "op": "is_a", "value": "" }), a.clone()), Tri::Unknown);
    assert_eq!(tri(json!({ "field": "action.o", "op": "is_a", "value": "" }), a.clone()), Tri::Unknown);
    assert_eq!(tri(json!({ "not": { "field": "action.s", "op": "is_a", "value": "" } }), a.clone()), Tri::Unknown);
    // controls
    assert_eq!(tri(json!({ "field": "action.s", "op": "is_a", "value": "x" }), a.clone()), Tri::True);
    assert_eq!(tri(json!({ "field": "action.s", "op": "is_a", "value": "y" }), a), Tri::False);
}

/// TS: `all_of: []` => unknown (L499), never vacuously true.
#[test]
fn empty_all_of_is_unknown() {
    let a = full_action(json!({}));
    assert_eq!(tri(json!({ "all_of": [] }), a.clone()), Tri::Unknown);
    assert_eq!(tri(json!({ "not": { "all_of": [] } }), a.clone()), Tri::Unknown);
    assert_eq!(tri(json!({ "any_of": [] }), a.clone()), Tri::Unknown);
    assert_eq!(tri(json!({ "all_of": [{ "field": "action.verb", "op": "eq", "value": "v" }] }), a), Tri::True);
}
