//! The guardian-id tie-break is the root-locale collation (ICU), in every script: Arabic-Indic digits order by their numeric value among
//! ASCII digits, which code point order does not, and equal weight and heartbeat leave only the id to decide the primary.
#![cfg(feature = "icu-collation")]
use atlas_pca::ha::failover_plan;
use atlas_pca::serde_json::json;

fn primary_of(ids: &[&str]) -> String {
    let guardians: Vec<_> = ids
        .iter()
        .map(|id| json!({"id": id, "healthy": true, "lastSeen": 1000, "weight": 1}))
        .collect();
    let plan = failover_plan(&json!({"quorum": 1, "guardians": guardians}), 1000.0, None).unwrap();
    plan["primary"].as_str().unwrap().to_string()
}

#[test]
fn non_latin_ids_order_by_the_root_collation() {
    // U+0662 ARABIC-INDIC DIGIT TWO sorts before "3" under the collation (value 2 < 3) but after it by code point
    assert_eq!(primary_of(&["3", "\u{662}"]), "\u{662}");
    assert_eq!(primary_of(&["\u{662}", "3"]), "\u{662}");
    // lower case before upper case at the tertiary level, no accent before an accent
    assert_eq!(primary_of(&["B", "b"]), "b");
    assert_eq!(primary_of(&["\u{e9}", "e"]), "e");
}
