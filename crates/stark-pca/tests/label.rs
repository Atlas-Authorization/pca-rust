//! The crate must never be described as zero-knowledge: the proof leaks the witness (see the README). The constant,
//! the manifest, the crate documentation and the README all have to say the same thing.

use std::path::Path;

fn read(rel: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)).unwrap()
}

#[test]
fn the_crate_declares_that_it_is_not_zero_knowledge() {
    assert!(!stark_pca::ZERO_KNOWLEDGE);
}

#[test]
fn no_description_claims_zero_knowledge() {
    let manifest = read("Cargo.toml").to_lowercase();
    for banned in ["zk-stark", "zkstark", "zero-knowledge stark", "\"zk\""] {
        assert!(!manifest.contains(banned), "Cargo.toml must not contain {banned:?}");
    }
    let lib = read("src/lib.rs").to_lowercase();
    assert!(!lib.contains("zk-stark"), "the crate documentation must not call the proof a zk-STARK");
    assert!(lib.contains("not zero-knowledge"), "the crate documentation must say the proof is not zero-knowledge");
    let readme = read("README.md").to_lowercase();
    assert!(!readme.contains("zk-stark"), "the README must not call the proof a zk-STARK");
    assert!(readme.contains("**not zero-knowledge.**"), "the README must open its privacy paragraph with the label");
    assert!(!readme.contains("**private witnesses**"), "the README must not call the witness private");
}
