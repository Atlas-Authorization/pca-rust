//! The replay clock is the corpus header's `clockMs`; a header without it (an older corpus) gives the fallback.
mod common;
use atlas_pca::serde_json::json;

#[test]
fn header_clock_is_read() {
    let doc = json!({ "about": "a", "generator": "g.mts", "count": 0, "clockMs": 1_700_000_000_000u64, "cases": [] });
    assert_eq!(common::clock_of_header(&doc), 1_700_000_000_000.0);
}

#[test]
fn missing_header_clock_falls_back() {
    let doc = json!({ "about": "a", "generator": "g.mts", "count": 0, "cases": [] });
    assert_eq!(common::clock_of_header(&doc), common::FALLBACK_CLOCK_MS);
}
