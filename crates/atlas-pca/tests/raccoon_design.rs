//! `RACCOON_DESIGN` is data: the documented research design, never a signing routine.
use atlas_pca::pq_threshold_lattice::{raccoon_design, EXPERIMENTAL_BANNER};

#[test]
fn the_design_is_documented_research_data() {
    let d = raccoon_design();
    assert_eq!((d["status"].as_str(), d["productionReady"].as_bool(), d["banner"].as_str()), (Some("research-prototype"), Some(false), Some(EXPERIMENTAL_BANNER)));
    assert_eq!((d["construction"].as_array().map(Vec::len), d["whyNoLibraryYet"].as_array().map(Vec::len), d["parameterSets"].as_array().map(Vec::len), d["references"].as_array().map(Vec::len)), (Some(5), Some(4), Some(2), Some(3)));
    assert!(d["shippableAlternative"].as_str().is_some_and(|s| s.starts_with("Use the HYBRID in @atlasauth/pca-pq-threshold")));
}
