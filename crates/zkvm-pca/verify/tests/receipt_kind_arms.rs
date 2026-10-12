//! Each receipt-kind arm of `verify_with_context` is pinned by its own message: a Fake receipt is refused as a FAKE
//! (not as an "unsupported kind"), and a real Succinct / Groth16 receipt is never classed as unsupported.
use pca_zkvm_core::{context::ExpectedContext, decide_from_str};
use pca_zkvm_verify::{verify_with_context, VerifyError};
use risc0_zkvm::{sha::Digest, FakeReceipt, InnerReceipt, Receipt, ReceiptClaim};
use serde_json::Value;

fn fx(rel: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures").join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn expected() -> ExpectedContext {
    let input: Value = serde_json::from_slice(&fx("decide_input.sample.json")).unwrap();
    ExpectedContext::from_input_json(&input.to_string(), 0.0).unwrap()
}

#[test]
fn fake_receipt_is_refused_as_fake() {
    let honest = decide_from_str(std::str::from_utf8(&fx("decide_input.sample.json")).unwrap());
    let words = risc0_zkvm::serde::to_vec(&honest).unwrap();
    let journal: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let id = Digest::from([7u32; 8]);
    let r = Receipt::new(InnerReceipt::Fake(FakeReceipt::new(ReceiptClaim::ok(id, journal.clone()))), journal);
    match verify_with_context(&r, id, &expected()) {
        Err(VerifyError::Receipt(m)) => assert_eq!(m, "fake (dev-mode) receipts are never accepted"),
        other => panic!("got {other:?}"),
    }
}

#[test]
fn real_receipts_are_never_classed_unsupported() {
    let w: Value = serde_json::from_slice(&fx("image_id.json")).unwrap();
    let words = w["image_id_words"].as_array().unwrap();
    let id = Digest::from(core::array::from_fn::<u32, 8, _>(|i| words[i].as_u64().unwrap() as u32));
    for f in ["receipt_succinct.bin", "receipt_groth16.bin"] {
        let r: Receipt = bincode::deserialize(&fx(f)).unwrap();
        assert!(matches!(r.inner, InnerReceipt::Succinct(_) | InnerReceipt::Groth16(_)), "{f}");
        if let Err(VerifyError::Receipt(m)) = verify_with_context(&r, id, &expected()) {
            assert!(!m.contains("unsupported receipt kind"), "{f}: {m}");
            assert!(!m.contains("fake"), "{f}: {m}");
        }
    }
}
