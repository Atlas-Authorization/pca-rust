//! The cheap PCActn claims check: audience and validity window, before any crypto.
use atlas_pca::pcactn_cheap::pcactn_cheap_claims;
use atlas_pca::serde_json::json;

const NOW: i64 = 1_800_000_000_000;

fn p(aud: &str, iat: i64, exp: i64) -> atlas_pca::serde_json::Value {
    json!({"aud": aud, "iat": iat, "exp": exp})
}

#[test]
fn a_valid_window_passes_and_every_defect_names_its_check() {
    assert_eq!(pcactn_cheap_claims(&p("i", NOW - 1_000, NOW + 60_000), "i", NOW), None);
    let f = |v: &atlas_pca::serde_json::Value| pcactn_cheap_claims(v, "i", NOW).map(|f| (f.check, f.reason));
    assert_eq!(f(&p("other", NOW, NOW + 1)), Some(("audience", "aud does not match this resource server / instance".to_string())));
    assert_eq!(f(&json!({"iat": NOW, "exp": NOW + 1})).map(|x| x.0), Some("audience"));
    assert_eq!(f(&p("", NOW, NOW + 1)).map(|x| x.0), Some("audience"));
    assert_eq!(f(&json!({"aud": "i", "iat": 1.5, "exp": 3})).unwrap().1, "iat and exp must be safe-integer epoch ms");
    assert_eq!(f(&p("i", NOW, NOW)).unwrap().1, "exp must be greater than iat");
    assert_eq!(f(&p("i", NOW, NOW + 3_600_001)).unwrap().1, "lifetime exceeds 3600000 ms");
    assert_eq!(f(&p("i", NOW + 60_001, NOW + 120_000)).unwrap().1, "iat is in the future (clock skew)");
    assert_eq!(f(&p("i", NOW - 20_000, NOW - 1)).unwrap().1, "the PCActn has expired");
    // the boundaries are inclusive: skew of exactly 60 s and exp == now still pass
    assert_eq!(f(&p("i", NOW + 60_000, NOW + 120_000)), None);
    assert_eq!(f(&p("i", NOW - 10, NOW)), None);
}
