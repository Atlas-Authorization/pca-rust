//! `enforce.freshness` (pcactn.ts M3 gate): a missing, stub, future or stale signed freshness anchor denies; every boundary is pinned.
use atlas_pca::{freshness_gate_check, FreshnessGate};
use serde_json::{json, Map, Value};

fn p(fr: Value) -> Map<String, Value> {
    json!({ "freshness": fr }).as_object().unwrap().clone()
}

fn gate(max_age_ms: f64) -> FreshnessGate {
    FreshnessGate { max_age_ms, epoch_ms: Some(1000.0), now: None, clock_skew_ms: None }
}

#[test]
fn an_anchor_inside_the_window_passes_and_the_edges_are_exact() {
    let anchor = p(json!({"beacon_ref": "b", "epoch": 100})); // anchor = 100_000 ms
    assert_eq!(freshness_gate_check(&anchor, &gate(5000.0), 100_000), Ok(()), "age 0");
    assert_eq!(freshness_gate_check(&anchor, &gate(5000.0), 105_000), Ok(()), "age == maxAge is fresh");
    assert_eq!(freshness_gate_check(&anchor, &gate(5000.0), 105_001), Err("freshness anchor is stale (older than 5000 ms)".to_string()));
    assert_eq!(freshness_gate_check(&anchor, &gate(5000.0), 99_999), Err("freshness anchor is in the future".to_string()));
    assert_eq!(freshness_gate_check(&anchor, &gate(5000.0), 100_000), Ok(()), "the anchor is not in the future at exactly now");
}

#[test]
fn the_clock_skew_allows_an_anchor_slightly_in_the_future() {
    let anchor = p(json!({"beacon_ref": "b", "epoch": 100}));
    let g = |skew: Option<f64>| FreshnessGate { clock_skew_ms: skew, ..gate(5000.0) };
    assert!(freshness_gate_check(&anchor, &g(None), 99_000).is_err());
    assert_eq!(freshness_gate_check(&anchor, &g(Some(1000.0)), 99_000), Ok(()));
    assert!(freshness_gate_check(&anchor, &g(Some(999.0)), 99_000).is_err());
    assert!(freshness_gate_check(&anchor, &g(Some(-5000.0)), 99_000).is_err(), "a negative skew counts as none");
    assert!(freshness_gate_check(&anchor, &g(Some(f64::NAN)), 99_000).is_err(), "a non-finite skew counts as none");
    assert!(freshness_gate_check(&anchor, &g(Some(f64::INFINITY)), 99_000).is_err(), "an infinite skew counts as none, never as unlimited");
}

#[test]
fn a_missing_or_stub_anchor_is_refused() {
    const MISSING: &str = "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)";
    for fr in [json!(null), json!({}), json!({"beacon_ref": "", "epoch": 5}), json!({"beacon_ref": "b", "epoch": 0}), json!({"beacon_ref": "b", "epoch": -1}), json!({"beacon_ref": 7, "epoch": 5}), json!({"beacon_ref": "b"}), json!({"beacon_ref": "b", "epoch": "5"}), json!({"beacon_ref": "b", "epoch": 1.5})] {
        assert_eq!(freshness_gate_check(&p(fr.clone()), &gate(5000.0), 5000), Err(MISSING.to_string()), "{fr}");
    }
    assert_eq!(freshness_gate_check(&Map::new(), &gate(5000.0), 5000), Err(MISSING.to_string()), "no freshness member");
}

#[test]
fn a_misconfigured_gate_fails_closed() {
    const BAD: &str = "freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)";
    let anchor = p(json!({"beacon_ref": "b", "epoch": 1}));
    for g in [FreshnessGate { epoch_ms: Some(0.0), ..gate(5.0) }, FreshnessGate { epoch_ms: Some(-1.0), ..gate(5.0) }, gate(-1.0), gate(f64::NAN), gate(f64::INFINITY)] {
        assert_eq!(freshness_gate_check(&anchor, &g, 1000), Err(BAD.to_string()), "{g:?}");
    }
    assert_eq!(freshness_gate_check(&anchor, &gate(0.0), 1000), Ok(()), "maxAge 0 accepts an anchor of exactly now");
}

#[test]
fn the_default_epoch_is_a_minute_and_the_gate_may_use_its_own_clock() {
    let anchor = p(json!({"beacon_ref": "b", "epoch": 2})); // 120_000 ms by default
    let g = FreshnessGate { max_age_ms: 1000.0, epoch_ms: None, now: None, clock_skew_ms: None };
    assert_eq!(freshness_gate_check(&anchor, &g, 120_500), Ok(()));
    assert!(freshness_gate_check(&anchor, &g, 119_000).is_err());
    let own = FreshnessGate { now: Some(120_800.0), ..g };
    assert_eq!(freshness_gate_check(&anchor, &own, 999_999_999), Ok(()), "the gate's clock wins over the verifier's");
}
