//! Verifies the COMMITTED Groth16 receipt against the COMMITTED image id (verification only: no
//! guest toolchain, no proving, no GPU) and checks that mutated image ids, journals and seals are
//! rejected.

use pca_zkvm_core::Decision;
use risc0_zkvm::sha::{Digest, Digestible};
use risc0_zkvm::{Groth16Receipt, InnerReceipt, Receipt};
use serde_json::Value;

fn fx(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures").join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn image_id() -> Digest {
    let v: Value = serde_json::from_slice(&fx("image_id.json")).unwrap();
    let w = v["image_id_words"].as_array().unwrap();
    Digest::from(core::array::from_fn::<u32, 8, _>(|i| w[i].as_u64().unwrap() as u32))
}

fn receipt() -> Receipt {
    bincode::deserialize(&fx("receipt_groth16.bin")).expect("committed groth16 receipt decodes")
}

fn g16(r: &Receipt) -> &Groth16Receipt<risc0_zkvm::ReceiptClaim> {
    match &r.inner {
        InnerReceipt::Groth16(g) => g,
        _ => panic!("not a groth16 receipt"),
    }
}

#[test]
fn committed_groth16_receipt_verifies() {
    let r = receipt();
    assert!(matches!(r.inner, InnerReceipt::Groth16(_)));
    r.verify(image_id()).expect("groth16 receipt must verify");
}

#[test]
fn groth16_journal_is_the_committed_statement() {
    let r = receipt();
    let d: Decision = r.journal.decode().unwrap();
    let want: Value = serde_json::from_slice(&fx("public_journal.json")).unwrap();
    assert_eq!(serde_json::to_value(&d).unwrap(), want);
    // same statement as the succinct receipt it was wrapped from
    let s: Receipt = bincode::deserialize(&fx("receipt_succinct.bin")).unwrap();
    assert_eq!(r.journal.bytes, s.journal.bytes);
    assert_eq!(r.claim().unwrap().digest(), s.claim().unwrap().digest(), "same claim digest");
}

#[test]
fn groth16_seal_is_a_256_byte_proof() {
    let r = receipt();
    assert_eq!(g16(&r).seal.len(), 256, "A(64) + B(128) + C(64)");
}

#[test]
fn wrong_image_id_is_rejected_for_every_bit_in_the_first_word_and_last_word() {
    let r = receipt();
    let base: [u32; 8] = {
        let v: Value = serde_json::from_slice(&fx("image_id.json")).unwrap();
        let w = v["image_id_words"].as_array().unwrap();
        core::array::from_fn(|i| w[i].as_u64().unwrap() as u32)
    };
    for word in [0usize, 7] {
        for bit in 0..32 {
            let mut m = base;
            m[word] ^= 1 << bit;
            assert!(r.verify(Digest::from(m)).is_err(), "flip word {word} bit {bit} accepted");
        }
    }
}

#[test]
fn mutated_journal_is_rejected_at_every_byte() {
    let r = receipt();
    for i in 0..r.journal.bytes.len() {
        let mut m = r.clone();
        m.journal.bytes[i] ^= 0x01;
        assert!(m.verify(image_id()).is_err(), "journal byte {i} flip accepted");
    }
    let mut ext = r.clone();
    ext.journal.bytes.push(0);
    assert!(ext.verify(image_id()).is_err());
    let mut trunc = r.clone();
    trunc.journal.bytes.pop();
    assert!(trunc.verify(image_id()).is_err());
    let mut empty = r.clone();
    empty.journal.bytes.clear();
    assert!(empty.verify(image_id()).is_err());
}

#[test]
fn mutated_seal_is_rejected_at_every_byte() {
    let r = receipt();
    let n = g16(&r).seal.len();
    for i in 0..n {
        let mut m = r.clone();
        if let InnerReceipt::Groth16(g) = &mut m.inner {
            g.seal[i] ^= 0x01;
        }
        assert!(m.verify(image_id()).is_err(), "seal byte {i} flip accepted");
    }
    // truncated and extended seal
    for tweak in 0..2 {
        let mut m = r.clone();
        if let InnerReceipt::Groth16(g) = &mut m.inner {
            if tweak == 0 { g.seal.pop(); } else { g.seal.push(0); }
        }
        assert!(m.verify(image_id()).is_err());
    }
    let mut zero = r.clone();
    if let InnerReceipt::Groth16(g) = &mut zero.inner {
        g.seal.iter_mut().for_each(|b| *b = 0);
    }
    assert!(zero.verify(image_id()).is_err(), "all-zero seal accepted");
}

#[test]
fn seal_from_another_claim_does_not_verify_here() {
    // swap the verifier-parameters digest: the receipt must no longer verify
    let r = receipt();
    let mut m = r.clone();
    if let InnerReceipt::Groth16(g) = &mut m.inner {
        g.verifier_parameters = Digest::from([1u32; 8]);
    }
    assert!(m.verify(image_id()).is_err());
}

#[test]
fn groth16_receipt_rejects_byte_flips_across_the_serialization() {
    let bytes = fx("receipt_groth16.bin");
    let mut accepted = 0usize;
    for i in 0..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        if let Ok(r) = bincode::deserialize::<Receipt>(&b) {
            if r.verify(image_id()).is_ok() {
                accepted += 1;
                eprintln!("byte {i} flip still verified");
            }
        }
    }
    assert_eq!(accepted, 0);
}
