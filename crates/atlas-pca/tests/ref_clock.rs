//! The replay clock is the corpus header's `clockMs`, and the clock cases are its `clockCases`; a header without a clock is refused.
mod common;
use atlas_pca::serde_json::json;

#[test]
fn header_clock_and_clock_cases_are_read() {
    let doc = json!({ "about": "a", "generator": "g.mts", "count": 0, "clockMs": 1_700_000_000_000u64, "clockCases": ["f/a", "f/b"], "cases": [] });
    assert_eq!(common::clock_of_header(&doc), 1_700_000_000_000.0);
    let cc = common::clock_cases_of_header(&doc);
    assert!(cc.contains("f/a") && cc.contains("f/b") && cc.len() == 2);
    assert!(common::clock_cases_of_header(&json!({ "cases": [] })).is_empty());
}

#[test]
#[should_panic(expected = "clockMs")]
fn a_header_without_a_clock_is_refused() {
    common::clock_of_header(&json!({ "about": "a", "generator": "g.mts", "count": 0, "cases": [] }));
}
