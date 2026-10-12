//! R3-14: a dev-mode (FAKE) receipt must NEVER verify, whatever `RISC0_DEV_MODE` says.
//! PoC: redteam/round3/zk/src/zkvm_dev_mode_fake.rs (accepted a forged journal when the verifier
//! process had RISC0_DEV_MODE=1, because risc0-zkvm only refuses `InnerReceipt::Fake` when built with
//! `disable-dev-mode`, which this crate did not enable, and the function never inspected the receipt kind).
use pca_zkvm_core::{context::ExpectedContext, decide_from_str};
use pca_zkvm_verify::{verify_with_context, VerifyError};
use risc0_zkvm::{sha::Digest, FakeReceipt, InnerReceipt, Receipt, ReceiptClaim};
use serde_json::Value;

fn forged() -> (Receipt, Digest, ExpectedContext) {
    let input: Value = serde_json::from_str(include_str!("../../fixtures/decide_input.sample.json")).unwrap();
    let expected = ExpectedContext::from_input_json(&input.to_string(), 0.0).unwrap();
    // forge a journal that matches the sample's expected context exactly
    let honest = decide_from_str(include_str!("../../fixtures/decide_input.sample.json"));
    assert_eq!(honest.allow, 1);
    let words = risc0_zkvm::serde::to_vec(&honest).unwrap();
    let journal: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let image_id = Digest::from([7u32; 8]);
    let claim = ReceiptClaim::ok(image_id, journal.clone());
    (Receipt::new(InnerReceipt::Fake(FakeReceipt::new(claim)), journal), image_id, expected)
}

fn assert_rejected(tag: &str) {
    let (r, id, e) = forged();
    match verify_with_context(&r, id, &e) {
        Err(VerifyError::Receipt(_)) => {}
        other => panic!("{tag}: a fake receipt must be refused with VerifyError::Receipt, got {other:?}"),
    }
}

// All env manipulation lives in ONE test: the process environment is shared across test threads.
#[test]
fn fake_receipts_are_refused_with_and_without_the_dev_mode_env_var() {
    for v in [None, Some("0"), Some("1"), Some("true")] {
        match v {
            Some(x) => std::env::set_var("RISC0_DEV_MODE", x),
            None => std::env::remove_var("RISC0_DEV_MODE"),
        }
        assert_rejected(&format!("RISC0_DEV_MODE={v:?}"));
    }
    std::env::remove_var("RISC0_DEV_MODE");
}
