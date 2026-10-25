//! The default fixtures pin the CURRENT (torsion-fixed) guest; the earlier guest's receipts live under
//! `fixtures/legacy/` and must not be mistaken for it.

use risc0_zkvm::sha::Digest;
use risc0_zkvm::Receipt;
use serde_json::Value;

const CURRENT_ID: &str = "432b4713d7981afc30907003d3a2c7e7d0003cc34b2367b4cba8d61b642c0060";
const PRE_V10_ID: &str = "c5107456f3885cfe87f0da62d24aa273e1fe94c982eed57324374dcefa80ac39";
const PRE_V9_ID: &str = "0c97a02b9d6f99131fb1d76207377ccb3546be8b8f6c33387ab078b1d49453a7";
const PRE_042_ID: &str = "3b1eebb56b046e737fb15009bdd065b67d7938cb8d47f3f3f0dadc801f84fdad";
const PRE_R6_ID: &str = "e922536c10e9a003c1c64914d9f11997dbda9e70b2d1294df358bb845f2991a8";
const PRE_R5_ID: &str = "1c1b8bbd531c5f3c93debfa41350b9a5e5c2478959ae2c0994c12de505933b95";
const PRE_R4_ID: &str = "ce0b542313a11e4863661d921157f95e61df18a919c97eea92641bba8699cf1b";
const PRE_R3_ID: &str = "6b0ac8939ebf3f98fbaa6a63ac842e4f24e105142bd3d684f2bc11da796997cc";
const LEGACY2_ID: &str = "dcf198fcfedd63182ddd8c392070d73f03c595b56e5d8649242e878fe530813a";
const LEGACY_ID: &str = "ac95031feecea70e62bfb998a14acd645f400d5a33d5e1bc6200d2aa63ed96e3";

fn path(rel: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures").join(rel)
}
fn read(rel: &str) -> Vec<u8> {
    std::fs::read(path(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}
fn id(rel: &str) -> (Digest, String) {
    let v: Value = serde_json::from_slice(&read(rel)).unwrap();
    let w = v["image_id_words"].as_array().unwrap();
    (Digest::from(core::array::from_fn::<u32, 8, _>(|i| w[i].as_u64().unwrap() as u32)), v["image_id_hex"].as_str().unwrap().to_string())
}

#[test]
fn the_default_top_level_fixtures_pin_the_fixed_guest_and_equal_proof_run() {
    let (_, hex) = id("image_id.json");
    assert_eq!(hex, CURRENT_ID, "default image id must be the context-committing guest (RT-06)");
    for f in ["receipt_succinct.bin", "receipt_groth16.bin"] {
        assert_eq!(read(f), read(&format!("proof_run/{f}")), "{f}: default must be the proof_run receipt");
    }
    assert_eq!(id("image_id.json").0, id("proof_run/image_id.json").0);
}

#[test]
fn legacy_receipts_verify_only_under_the_legacy_image_id() {
    let (legacy_id, hex) = id("legacy/image_id.json");
    assert_eq!(hex, LEGACY_ID);
    let (current_id, _) = id("image_id.json");
    assert_ne!(legacy_id, current_id);
    for f in ["legacy/receipt_succinct.bin", "legacy/receipt_groth16.bin"] {
        let r: Receipt = bincode::deserialize(&read(f)).unwrap();
        r.verify(legacy_id).unwrap_or_else(|e| panic!("{f} must verify under the legacy id: {e}"));
        assert!(r.verify(current_id).is_err(), "{f} must NOT verify under the current image id");
    }
    // the second legacy generation (torsion-fixed guest, journal without context)
    let (l2, hex2) = id("legacy/dcf198fc/image_id.json");
    assert_eq!(hex2, LEGACY2_ID);
    assert_ne!(l2, current_id);
    for f in ["legacy/dcf198fc/receipt_succinct.bin", "legacy/dcf198fc/receipt_groth16.bin"] {
        let r: Receipt = bincode::deserialize(&read(f)).unwrap();
        r.verify(l2).unwrap_or_else(|e| panic!("{f} must verify under its own id: {e}"));
        assert!(r.verify(current_id).is_err(), "{f} must NOT verify under the current image id");
    }
    // the third generation (context-committing guest before red-team round 3: root-only caveats, free depth, unbound PCActn)
    let (l3, hex3) = id("legacy/6b0ac893/image_id.json");
    assert_eq!(hex3, PRE_R3_ID);
    assert_ne!(l3, current_id);
    for f in ["legacy/6b0ac893/receipt_succinct.bin", "legacy/6b0ac893/receipt_groth16.bin"] {
        let r: Receipt = bincode::deserialize(&read(f)).unwrap();
        r.verify(l3).unwrap_or_else(|e| panic!("{f} must verify under its own id: {e}"));
        assert!(r.verify(current_id).is_err(), "{f} must NOT verify under the current image id");
        assert!(r.verify(l2).is_err());
    }
    // the fourth generation (red-team round 3 guest: regex-crate matcher, fail-open tool_schema, no PCActn freshness facts)
    let (l4, hex4) = id("legacy/ce0b5423/image_id.json");
    assert_eq!(hex4, PRE_R4_ID);
    assert_ne!(l4, current_id);
    for f in ["legacy/ce0b5423/receipt_succinct.bin", "legacy/ce0b5423/receipt_groth16.bin"] {
        let r: Receipt = bincode::deserialize(&read(f)).unwrap();
        r.verify(l4).unwrap_or_else(|e| panic!("{f} must verify under its own id: {e}"));
        assert!(r.verify(current_id).is_err(), "{f} must NOT verify under the current image id");
        assert!(r.verify(l3).is_err());
    }
    // the fifth generation (red-team round 4 guest: tool_schema drops malformed bounds, code-point lengths, no `matches` budget, no in-guest wire limits)
    let (l5, hex5) = id("legacy/1c1b8bbd/image_id.json");
    assert_eq!(hex5, PRE_R5_ID);
    assert_ne!(l5, current_id);
    for f in ["legacy/1c1b8bbd/receipt_succinct.bin", "legacy/1c1b8bbd/receipt_groth16.bin"] {
        let r: Receipt = bincode::deserialize(&read(f)).unwrap();
        r.verify(l5).unwrap_or_else(|e| panic!("{f} must verify under its own id: {e}"));
        assert!(r.verify(current_id).is_err(), "{f} must NOT verify under the current image id");
        assert!(r.verify(l4).is_err());
    }
    // the sixth generation (red-team round 5 guest: non-string `ref` read as absent, leaf+group mixes as leaves, plan node by
    // verb/resource, no readEnvelope checks, env/subject held to the wire profile)
    let (l6, hex6) = id("legacy/e922536c/image_id.json");
    assert_eq!(hex6, PRE_R6_ID);
    assert_ne!(l6, current_id);
    for f in ["legacy/e922536c/receipt_succinct.bin", "legacy/e922536c/receipt_groth16.bin"] {
        let r: Receipt = bincode::deserialize(&read(f)).unwrap();
        r.verify(l6).unwrap_or_else(|e| panic!("{f} must verify under its own id: {e}"));
        assert!(r.verify(current_id).is_err(), "{f} must NOT verify under the current image id");
        assert!(r.verify(l5).is_err());
    }
    // the seventh generation (red-team round 6 guest, guest version 7: root caveats outside the envelope not evaluated,
    // `max_spend` unknown; the PCA 0.4.1 security fix)
    let (l7, hex7) = id("legacy/3b1eebb5/image_id.json");
    assert_eq!(hex7, PRE_042_ID);
    assert_ne!(l7, current_id);
    for f in ["legacy/3b1eebb5/receipt_succinct.bin", "legacy/3b1eebb5/receipt_groth16.bin"] {
        let r: Receipt = bincode::deserialize(&read(f)).unwrap();
        r.verify(l7).unwrap_or_else(|e| panic!("{f} must verify under its own id: {e}"));
        assert!(r.verify(current_id).is_err(), "{f} must NOT verify under the current image id");
        assert!(r.verify(l6).is_err());
    }
    // the eighth generation (0.4.2 guest, guest version 8: a pure-PQ / hybrid session root verified under the PQ key named in
    // its own principals[] entry, R3-01)
    let (l8, hex8) = id("legacy/0c97a02b/image_id.json");
    assert_eq!(hex8, PRE_V9_ID);
    assert_ne!(l8, current_id);
    for f in ["legacy/0c97a02b/receipt_succinct.bin", "legacy/0c97a02b/receipt_groth16.bin"] {
        let r: Receipt = bincode::deserialize(&read(f)).unwrap();
        r.verify(l8).unwrap_or_else(|e| panic!("{f} must verify under its own id: {e}"));
        assert!(r.verify(current_id).is_err(), "{f} must NOT verify under the current image id");
        assert!(r.verify(l7).is_err());
    }
    // the ninth generation (guest version 9: `intent_v2_active` did not report a present malformed v2 context)
    let (l9, hex9) = id("legacy/c5107456/image_id.json");
    assert_eq!(hex9, PRE_V10_ID);
    assert_ne!(l9, current_id);
    for f in ["legacy/c5107456/receipt_succinct.bin", "legacy/c5107456/receipt_groth16.bin"] {
        let r: Receipt = bincode::deserialize(&read(f)).unwrap();
        r.verify(l9).unwrap_or_else(|e| panic!("{f} must verify under its own id: {e}"));
        assert!(r.verify(current_id).is_err(), "{f} must NOT verify under the current image id");
        assert!(r.verify(l8).is_err());
    }
    // and the current receipts must not verify under the legacy id
    for f in ["receipt_succinct.bin", "receipt_groth16.bin"] {
        let r: Receipt = bincode::deserialize(&read(f)).unwrap();
        r.verify(current_id).unwrap_or_else(|e| panic!("{f}: {e}"));
        assert!(r.verify(legacy_id).is_err(), "{f} must not verify under the legacy image id");
        assert!(r.verify(l2).is_err(), "{f} must not verify under the second legacy image id");
        assert!(r.verify(l3).is_err(), "{f} must not verify under the pre-R3 image id");
        assert!(r.verify(l4).is_err(), "{f} must not verify under the pre-R4 image id");
        assert!(r.verify(l5).is_err(), "{f} must not verify under the pre-R5 image id");
        assert!(r.verify(l6).is_err(), "{f} must not verify under the pre-R6 image id");
        assert!(r.verify(l7).is_err(), "{f} must not verify under the round-6 (pre-0.4.1) image id");
        assert!(r.verify(l8).is_err(), "{f} must not verify under the guest-version-8 (pre-R3-01) image id");
        assert!(r.verify(l9).is_err(), "{f} must not verify under the guest-version-9 image id");
    }
}

#[test]
fn legacy_guests_attest_the_same_statement_and_the_current_one_adds_the_context() {
    let a: Receipt = bincode::deserialize(&read("legacy/receipt_succinct.bin")).unwrap();
    let b: Receipt = bincode::deserialize(&read("legacy/dcf198fc/receipt_succinct.bin")).unwrap();
    assert_eq!(a.journal.bytes, b.journal.bytes, "same compliant input, same (context-free) legacy statement");
    let c: Receipt = bincode::deserialize(&read("receipt_succinct.bin")).unwrap();
    assert_ne!(a.journal.bytes, c.journal.bytes);
    assert!(c.journal.bytes.len() > a.journal.bytes.len(), "the current journal carries the extra context");
}

#[test]
fn r6_zk06_every_legacy_image_id_is_superseded_and_the_current_one_is_not() {
    use pca_zkvm_verify::{image_id_hex, is_superseded, SUPERSEDED_IMAGE_IDS};
    let legacy = [LEGACY_ID, LEGACY2_ID, PRE_R3_ID, PRE_R4_ID, PRE_R5_ID, PRE_R6_ID, PRE_042_ID, PRE_V9_ID, PRE_V10_ID];
    for rel in ["legacy/image_id.json", "legacy/dcf198fc/image_id.json", "legacy/6b0ac893/image_id.json", "legacy/ce0b5423/image_id.json", "legacy/1c1b8bbd/image_id.json", "legacy/e922536c/image_id.json", "legacy/3b1eebb5/image_id.json", "legacy/0c97a02b/image_id.json", "legacy/c5107456/image_id.json"] {
        let (d, hex) = id(rel);
        assert_eq!(image_id_hex(&d), hex, "{rel}: hex form of the digest");
        assert!(legacy.contains(&hex.as_str()));
        assert!(is_superseded(&d), "{rel} must be on the deny-list");
    }
    assert_eq!(SUPERSEDED_IMAGE_IDS.len(), legacy.len());
    let (cur, hex) = id("image_id.json");
    assert_eq!(image_id_hex(&cur), hex);
    assert!(!is_superseded(&cur), "the current guest must not be on the deny-list");
}
