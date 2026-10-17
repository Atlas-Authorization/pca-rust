//! Verifier-side API for the PCA zkVM receipt.
//!
//! A receipt alone proves "the gate passed for SOME context" (RT-06). [`verify_with_context`] is the
//! entry point that closes that: it verifies the receipt against the pinned image id AND requires the
//! caller to state the context it expects (its own clock, the subject and environment it knows, the rate
//! history from its ledger, the risk inputs it computed, the commitments it holds). There is no
//! overload without an expectation.

use pca_zkvm_core::context::{check_context, ContextMismatch, ExpectedContext};
use pca_zkvm_core::Decision;
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{InnerReceipt, Receipt, VerifierContext};

/// R6-ZK-06: image ids of SUPERSEDED guest builds, refused by [`verify_with_context`] even when the caller pins one of
/// them (image ids are hashes, so there is no "minimum id"; this deny-list plus the journal's `guest_version`, checked
/// against [`pca_zkvm_core::MIN_GUEST_VERSION`], is the minimum-version mechanism). Every guest before round 6 is here:
/// a verifier that kept a pre-R5 id pinned no longer accepts its receipts. The round-6 guest (`3b1eebb5...`, guest version 7)
/// is superseded by guest version 8 (0.4.1: root caveats enforced, `max_spend`), and guest version 8 (`0c97a02b...`) by guest
/// version 9 (R3-01: a PQ / hybrid session root verifies only under the verifier's `session.pq_pins`).
pub const SUPERSEDED_IMAGE_IDS: &[&str] = &[
    "ac95031feecea70e62bfb998a14acd645f400d5a33d5e1bc6200d2aa63ed96e3", // mixed-order delegator key accepted
    "dcf198fcfedd63182ddd8c392070d73f03c595b56e5d8649242e878fe530813a", // journal without context (RT-06)
    "6b0ac8939ebf3f98fbaa6a63ac842e4f24e105142bd3d684f2bc11da796997cc", // root caveats only, prover depth (R3-11..13)
    "ce0b542313a11e4863661d921157f95e61df18a919c97eea92641bba8699cf1b", // regex crate, fail-open tool_schema (R4)
    "1c1b8bbd531c5f3c93debfa41350b9a5e5c2478959ae2c0994c12de505933b95", // malformed bounds dropped, no wire limits (R5)
    "e922536c10e9a003c1c64914d9f11997dbda9e70b2d1294df358bb845f2991a8", // non-string ref, mixed groups, decoy node (R6)
    "3b1eebb56b046e737fb15009bdd065b67d7938cb8d47f3f3f0dadc801f84fdad", // root caveats outside the envelope ignored (0.4.1)
    "0c97a02b9d6f99131fb1d76207377ccb3546be8b8f6c33387ab078b1d49453a7", // PQ session root under its own principals key (R3-01)
];

/// Lower-case hex of an image id digest (the form used in `fixtures/image_id.json`).
pub fn image_id_hex(id: &Digest) -> String {
    id.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Is `id` a superseded guest build?
pub fn is_superseded(id: &Digest) -> bool {
    let h = image_id_hex(id);
    SUPERSEDED_IMAGE_IDS.contains(&h.as_str())
}

#[derive(Debug)]
pub enum VerifyError {
    /// The pinned image id is a superseded guest build ([`SUPERSEDED_IMAGE_IDS`]).
    Superseded(String),
    /// The receipt itself is invalid for this image id (seal, claim, image id or journal digest).
    Receipt(String),
    /// The journal does not decode as the current `Decision` (e.g. a legacy journal without context).
    Journal(String),
    /// The receipt is valid but the proven context differs from what the verifier expects.
    Context(ContextMismatch),
}

/// Verify `receipt` against `image_id`, decode the journal and pin it to `expected`.
pub fn verify_with_context(
    receipt: &Receipt,
    image_id: Digest,
    expected: &ExpectedContext,
) -> Result<Decision, VerifyError> {
    if is_superseded(&image_id) {
        return Err(VerifyError::Superseded(image_id_hex(&image_id)));
    }
    // R3-14: only REAL receipts. A dev-mode `Fake` receipt carries no seal at all and `risc0-zkvm` accepts it
    // whenever `RISC0_DEV_MODE` is set in the verifier's environment (or the crate graph enables the default
    // features), so the kind is checked explicitly: Succinct or Groth16 only. Composite receipts are real but
    // not a published format of this crate; anything else is refused.
    match &receipt.inner {
        InnerReceipt::Succinct(_) | InnerReceipt::Groth16(_) => {}
        InnerReceipt::Fake(_) => {
            return Err(VerifyError::Receipt("fake (dev-mode) receipts are never accepted".into()))
        }
        _ => {
            return Err(VerifyError::Receipt(
                "unsupported receipt kind: only succinct or groth16 receipts are accepted".into(),
            ))
        }
    }
    // ... and the verifier context pins dev mode OFF explicitly, so the `RISC0_DEV_MODE` environment variable
    // is never consulted for this verification.
    let ctx = VerifierContext::default().with_dev_mode(false);
    receipt
        .verify_with_context(&ctx, image_id)
        .map_err(|e| VerifyError::Receipt(e.to_string()))?;
    let d: Decision = receipt.journal.decode().map_err(|e| VerifyError::Journal(e.to_string()))?;
    check_context(&d, expected).map_err(VerifyError::Context)?;
    Ok(d)
}
