//! B6: the limit-naming denial reason. `tests/testdata/limit-reasons.json` holds every case with the reason the
//! TypeScript `evaluatePredicates` returns for it; this crate must produce the same text.

use serde_json::{json, Value};

use super::envelope_predicates_denial;

fn ctx(c: &Value) -> Value {
    json!({"action": {"verb": c["verb"], "resource": c["resource"], "params": c["params"]}})
}

#[test]
fn reasons_match_the_typescript_reference() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/limit-reasons.json")).unwrap();
    let d: Value = serde_json::from_str(&text).unwrap();
    let cases = d["cases"].as_array().unwrap();
    assert!(cases.len() >= 70);
    for c in cases {
        let got = envelope_predicates_denial(c["predicates"].as_array().unwrap(), &ctx(c));
        let want = c["reason"].as_str().map(str::to_string);
        assert_eq!(got, want, "{}", c["name"]);
    }
}

#[test]
fn headline_reasons_are_exact() {
    let leaf = |op: &str, v: Value| json!({"field": "action.params.amount", "op": op, "value": v});
    let at = json!({"action": {"verb": "stripe.refund", "resource": "charge:ch_1", "params": {"amount": 900}}});
    let pred = |w: Value| vec![json!({"verb": "stripe.refund", "resource": "charge:*", "where": [w]})];
    assert_eq!(
        envelope_predicates_denial(&pred(leaf("lte", json!(500))), &at).as_deref(),
        Some("amount <= 500 not satisfied for stripe.refund on charge:ch_1")
    );
    assert_eq!(
        envelope_predicates_denial(&pred(json!({"field": "action.params.currency", "op": "in", "value": ["usd", "eur"]})), &at).as_deref(),
        Some("currency in [\"usd\", \"eur\"] not satisfied for stripe.refund on charge:ch_1")
    );
    // out of scope: the old wording stays; an empty list too
    assert_eq!(
        envelope_predicates_denial(&[json!({"verb": "other", "where": [leaf("lte", json!(1))]})], &at).as_deref(),
        Some("no predicate permits stripe.refund on charge:ch_1")
    );
    assert_eq!(envelope_predicates_denial(&[], &at).as_deref(), Some("envelope grants no predicates"));
}
