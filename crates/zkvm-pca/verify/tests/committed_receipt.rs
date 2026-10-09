//! Verifies the COMMITTED succinct receipt against the COMMITTED image id (verification only: no
//! guest toolchain, no proving, no GPU), and checks that mutated receipts, journals and image ids
//! are rejected with the expected reason.

use pca_zkvm_core::Decision;
use risc0_zkvm::sha::Digest;
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{InnerReceipt, Receipt};
use serde_json::Value;
use std::collections::BTreeMap;

fn fx(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures").join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn image_words() -> [u32; 8] {
    let v: Value = serde_json::from_slice(&fx("image_id.json")).unwrap();
    let w = v["image_id_words"].as_array().unwrap();
    core::array::from_fn(|i| w[i].as_u64().unwrap() as u32)
}

fn image_id() -> Digest {
    Digest::from(image_words())
}

fn receipt() -> Receipt {
    bincode::deserialize(&fx("receipt_succinct.bin")).expect("committed receipt decodes")
}

/// Stable, version-independent name of a verification error variant.
fn kind<E: std::fmt::Display>(e: &E) -> String {
    // drop the (varying) hex digests from the message so the reason text is comparable
    e.to_string()
        .split_whitespace()
        .filter(|t| !(t.len() >= 32 && t.trim_end_matches(';').chars().all(|c| c.is_ascii_hexdigit())))
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn image_id_hex_matches_words() {
    let v: Value = serde_json::from_slice(&fx("image_id.json")).unwrap();
    let mut bytes = Vec::new();
    for w in image_words() {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, v["image_id_hex"].as_str().unwrap());
}

#[test]
fn committed_receipt_verifies_against_committed_image_id() {
    let r = receipt();
    assert!(matches!(r.inner, InnerReceipt::Succinct(_)), "committed receipt is a succinct receipt");
    r.verify(image_id()).expect("committed succinct receipt must verify");
}

#[test]
fn committed_journal_is_the_committed_statement() {
    let r = receipt();
    let d: Decision = r.journal.decode().expect("journal decodes as Decision");
    let want: Value = serde_json::from_slice(&fx("public_journal.json")).unwrap();
    assert_eq!(serde_json::to_value(&d).unwrap(), want);
    assert_eq!((d.allow, d.tier, d.chain_verified), (1, 1, 1));
    // and it equals what the pure decision logic computes from the committed input
    let input = String::from_utf8(fx("decide_input.sample.json")).unwrap();
    assert_eq!(pca_zkvm_core::decide_from_str(&input), d);
}

#[test]
fn claim_binds_image_id_and_journal() {
    let r = receipt();
    let claim = r.claim().expect("claim").value().expect("unpruned claim");
    assert_eq!(claim.pre.digest(), image_id(), "claim pre-state is the image id");
    let out = claim.output.as_value().expect("output").clone().expect("some output");
    let jd = out.journal.digest();
    use risc0_zkvm::sha::{Impl, Sha256};
    assert_eq!(jd, *Impl::hash_bytes(&r.journal.bytes), "claim journal digest = sha256(journal)");
}

#[test]
fn wrong_image_id_is_rejected() {
    let r = receipt();
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for word in 0..8 {
        for bit in [0u32, 7, 31] {
            let mut w = image_words();
            w[word] ^= 1 << bit;
            let e = r.verify(Digest::from(w)).expect_err("wrong image id must be rejected");
            *seen.entry(kind(&e)).or_default() += 1;
        }
    }
    eprintln!("wrong image id: {seen:?}");
    assert_eq!(seen.len(), 1, "one consistent rejection reason: {seen:?}");
    assert!(r.verify(Digest::from([0u32; 8])).is_err());
}

#[test]
fn mutated_or_resized_journal_is_rejected() {
    let r = receipt();
    let n = r.journal.bytes.len();
    assert!(n > 0);
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for i in 0..n {
        let mut t = r.clone();
        t.journal.bytes[i] ^= 0x01;
        let e = t.verify(image_id()).expect_err("mutated journal must be rejected");
        *seen.entry(kind(&e)).or_default() += 1;
    }
    let mut t = r.clone();
    t.journal.bytes.push(0);
    *seen.entry(kind(&t.verify(image_id()).expect_err("extended journal"))).or_default() += 1;
    let mut t = r.clone();
    t.journal.bytes.pop();
    *seen.entry(kind(&t.verify(image_id()).expect_err("truncated journal"))).or_default() += 1;
    let mut t = r.clone();
    t.journal.bytes.clear();
    *seen.entry(kind(&t.verify(image_id()).expect_err("empty journal"))).or_default() += 1;
    eprintln!("journal mutations: {seen:?}");
    assert_eq!(seen.len(), 1, "journal tampering has one rejection reason: {seen:?}");
    assert!(seen.keys().next().unwrap().contains("claim"), "{seen:?}");
}

#[test]
fn mutated_seal_is_rejected() {
    let r = receipt();
    let InnerReceipt::Succinct(s) = &r.inner else { panic!("succinct") };
    let n = s.seal.len();
    assert!(n > 1000);
    let mut offs: Vec<usize> = (0..n).step_by((n / 300).max(1)).collect();
    offs.extend([0, 1, 2, n - 1, n - 2, n / 2]);
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for off in offs {
        for mask in [0x1u32, 0x8000_0000] {
            let mut t = r.clone();
            let InnerReceipt::Succinct(ts) = &mut t.inner else { unreachable!() };
            ts.seal[off] ^= mask;
            let e = t
                .verify(image_id())
                .expect_err(&format!("seal mutation at word {off} mask {mask:#x} still verified"));
            *seen.entry(kind(&e)).or_default() += 1;
        }
    }
    eprintln!("seal mutations: {seen:?}");
}

#[test]
fn mutated_receipt_metadata_is_rejected() {
    let r = receipt();
    // control id
    let mut t = r.clone();
    if let InnerReceipt::Succinct(s) = &mut t.inner {
        let mut w: [u32; 8] = s.control_id.into();
        w[0] ^= 1;
        s.control_id = Digest::from(w);
    }
    assert!(t.verify(image_id()).is_err(), "control id");
    // verifier parameters fingerprint
    let mut t = r.clone();
    if let InnerReceipt::Succinct(s) = &mut t.inner {
        let mut w: [u32; 8] = s.verifier_parameters.into();
        w[3] ^= 1;
        s.verifier_parameters = Digest::from(w);
    }
    assert!(t.verify(image_id()).is_err(), "verifier parameters");
    // hash function name
    let mut t = r.clone();
    if let InnerReceipt::Succinct(s) = &mut t.inner {
        s.hashfn = "sha-256-bogus".into();
    }
    assert!(t.verify(image_id()).is_err(), "hashfn");
}

#[test]
fn byte_flips_in_the_serialized_receipt_are_rejected() {
    let good = fx("receipt_succinct.bin");
    let n = good.len();
    let mut decode_fail = 0;
    let mut verify_fail = 0;
    let mut offs: Vec<usize> = (0..n).step_by((n / 500).max(1)).collect();
    offs.extend([0, 1, 7, 8, n - 1, n / 2]);
    for off in offs {
        let mut b = good.clone();
        b[off] ^= 0x01;
        match bincode::deserialize::<Receipt>(&b) {
            Err(_) => decode_fail += 1,
            Ok(rc) => {
                // a flip that decodes may land in non-semantic padding only if the verifier still
                // accepts the identical statement; otherwise it must be rejected.
                match rc.verify(image_id()) {
                    Err(_) => verify_fail += 1,
                    Ok(()) => {
                        let orig = receipt();
                        assert_eq!(rc.journal.bytes, orig.journal.bytes, "accepted mutation changed the journal at {off}");
                    }
                }
            }
        }
    }
    eprintln!("receipt byte flips: {decode_fail} rejected at decode, {verify_fail} at verify");
    assert!(decode_fail + verify_fail > 400);
}

#[test]
fn truncated_receipt_does_not_decode() {
    let good = fx("receipt_succinct.bin");
    for cut in [1usize, 100, good.len() / 2] {
        assert!(bincode::deserialize::<Receipt>(&good[..good.len() - cut]).is_err());
    }
}
