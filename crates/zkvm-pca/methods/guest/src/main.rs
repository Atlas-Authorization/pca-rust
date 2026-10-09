//! The RISC Zero guest program: the PCA Policy-VM release gate, run as a program inside the zkVM.
//!
//! It reads the DecideInput (as a JSON string — see `decide_from_str`), runs the FULL decision
//! natively (predicate DSL + caveats + fixed-point risk + threshold ladder + budget gate), recomputes
//! the action/policy/plan commitments with the zkVM's native (accelerated) sha256, and:
//!   - ASSERTS `allow == 1`, so a deny witness panics and produces NO valid receipt (unforgeable);
//!   - commits the full `Decision` (allow + risk + tier + the three commitments) to the journal, so a
//!     verifier binds the proof to exactly these committed inputs.

use risc0_zkvm::guest::env;

fn main() {
    // Input arrives as a JSON string (so serde_json's self-describing deserialization handles the
    // `serde_json::Value` fields; risc0's own serde format cannot deserialize `Value`).
    let input_json: String = env::read();

    let decision = pca_zkvm_core::decide_from_str(&input_json);

    // A deny witness MUST be unprovable: assert the release+auto-admit gate held.
    assert_eq!(
        decision.allow, 1,
        "PCA release gate DENIED (allow=0): the action is not compliant under the policy"
    );

    // Public statement bound into the receipt journal.
    env::commit(&decision);
}
