//! # pca-folding-ivc — one succinct proof of an agent's WHOLE action history (Nova folding)
//!
//! Recursive action-proof aggregation (PCA roadmap **T4.4**) done the *modern* way: a
//! **folding scheme** (Microsoft Nova) instead of naive SNARK-of-a-SNARK recursion. We fold
//! `N` per-action steps into a single [`RecursiveSNARK`] whose size and the per-step prover
//! work are **independent of `N`**, then [`compress`] that into a succinct
//! [`CompressedSNARK`] — ONE proof that attests the agent's entire history.
//!
//! ## What one proof attests
//!
//! The IVC running state is `z = [chain_digest, budget_spent]` (arity 2), starting at
//! `z₀ = [0, 0]`. Step `i` consumes a per-action witness `(action_digestᵢ, costᵢ)` and
//! enforces **in-circuit**:
//!
//!   1. **Unforgeable action history** — `chain_digest₍ᵢ₊₁₎ = H(chain_digestᵢ, action_digestᵢ)`
//!      where `H` is a MiMC-style algebraic hash over the field (an x⁵ S-box, which is a
//!      permutation on the Pasta scalar field). The final `chain_digest` is therefore a
//!      commitment to the *exact ordered sequence* of actions; no action can be inserted,
//!      dropped or reordered without changing it.
//!   2. **Cumulative-risk bound** — `budget_spent₍ᵢ₊₁₎ = budget_spentᵢ + costᵢ` **and**
//!      `budget_spent₍ᵢ₊₁₎ ≤ B_MAX`, enforced by an in-circuit bit-decomposition range gadget.
//!      Because folding carries `budget_spent` across every step, this enforces the
//!      whole-history invariant **Σcostᵢ ≤ B_MAX**. A step whose running total exceeds
//!      `B_MAX` makes the step's R1CS unsatisfiable, so the aggregate proof is *unprovable*.
//!
//! ## Honest scope (candor)
//!
//! * The hash `H` here is a **didactic** fixed-round MiMC (x⁵), domain-separated but **not**
//!   parameterised for production collision resistance (a real deployment would use Poseidon
//!   with audited round counts — Nova re-exports Poseidon gadgets under
//!   `nova_snark::frontend`). It is a faithful placeholder for the *structure* of the chain
//!   invariant, not a production hash.
//! * Nova folds over the **Pallas/Vesta** cycle with an **IPA** PCS and a Spartan
//!   [`CompressedSNARK`]: transparent (no trusted setup) but **not** post-quantum. "PQ-friendly"
//!   in the roadmap sense is that folding reduces the whole history to a *single* relaxed-R1CS
//!   instance that a PQ final SNARK (e.g. a STARK, cf. `sdks/stark-pca-plonky3`) could compress
//!   instead; wiring that PQ wrap is future work. We do not overstate it here.

use ff::{Field, PrimeField};
use serde::{Deserialize, Serialize};

use nova_snark::errors::NovaError;
use nova_snark::frontend::{num::AllocatedNum, AllocatedBit, ConstraintSystem, SynthesisError};
use nova_snark::nova::{CompressedSNARK, ProverKey, PublicParams, RecursiveSNARK, VerifierKey};
use nova_snark::provider::{PallasEngine, VestaEngine};
use nova_snark::traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait, Engine};

// ---- curve cycle + SNARK backends ----------------------------------------------------

/// Primary engine (Pallas).
pub type E1 = PallasEngine;
/// Secondary engine (Vesta) — the other half of the cycle.
pub type E2 = VestaEngine;
/// Transparent IPA polynomial-evaluation engine on each curve (no trusted setup).
pub type EE1 = nova_snark::provider::ipa_pc::EvaluationEngine<E1>;
pub type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
/// Spartan relaxed-R1CS SNARK used to compress the folded instance on each curve.
pub type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
pub type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

/// The step circuit's native field (the primary engine's scalar field).
pub type Scalar = <E1 as Engine>::Scalar;

/// The concrete step circuit type folded at every step.
pub type Circuit = ActionCircuit<Scalar>;

/// Nova public parameters for this step circuit.
pub type PP = PublicParams<E1, E2, Circuit>;
/// The folded recursive proof (one per history).
pub type Recursive = RecursiveSNARK<E1, E2, Circuit>;
/// Compressed-SNARK prover / verifier keys.
pub type CompProverKey = ProverKey<E1, E2, Circuit, S1, S2>;
pub type CompVerifierKey = VerifierKey<E1, E2, Circuit, S1, S2>;
/// The final succinct proof of the whole history.
pub type Compressed = CompressedSNARK<E1, E2, Circuit, S1, S2>;

// ---- circuit parameters --------------------------------------------------------------

/// Cumulative risk ceiling: Σcostᵢ must never exceed this across the whole history.
pub const B_MAX: u64 = 1_000_000;
/// Bit width for the per-action cost range check (costs live in `[0, 2^COST_BITS)`).
pub const COST_BITS: usize = 32;
/// Bit width for the running-budget / headroom range checks. `2^BUDGET_BITS` must exceed
/// `B_MAX` and the largest attainable cumulative total.
pub const BUDGET_BITS: usize = 40;
/// MiMC rounds for the didactic chain hash (see the module-level candor note).
pub const MIMC_ROUNDS: usize = 64;

// ---- public action input -------------------------------------------------------------

/// One action in the agent's history, as plain data. `action_digest` is a digest of the
/// action (here reduced to a `u64` for the demo; a real integration feeds a field element
/// hashed from the canonical action bytes). `cost` is the action's metered risk/cost.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ActionStep {
    pub action_digest: u64,
    pub cost: u64,
}

// ---- the step circuit ----------------------------------------------------------------

/// The per-step circuit `F`: folds one action into the running `[chain_digest, budget_spent]`.
#[derive(Clone, Debug)]
pub struct ActionCircuit<F: PrimeField> {
    action_digest: F,
    cost: F,
}

impl<F: PrimeField> StepCircuit<F> for ActionCircuit<F> {
    fn arity(&self) -> usize {
        2
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // z = [chain_digest_in, budget_spent_in]
        let chain_in = &z[0];
        let budget_in = &z[1];

        // --- per-action witness -------------------------------------------------------
        let action_digest =
            AllocatedNum::alloc(cs.namespace(|| "action_digest"), || Ok(self.action_digest))?;
        let cost = AllocatedNum::alloc(cs.namespace(|| "cost"), || Ok(self.cost))?;
        // cost ∈ [0, 2^COST_BITS): a non-negative, bounded cost (prevents a negative
        // field-wrapped "cost" from gaming the cumulative bound).
        enforce_range(cs.namespace(|| "cost_range"), &cost, COST_BITS)?;

        // --- (1) unforgeable hash-chain of actions ------------------------------------
        let chain_out = hash2(cs.namespace(|| "chain_hash"), chain_in, &action_digest)?;

        // --- (2) cumulative budget + bound --------------------------------------------
        let budget_out = budget_in.add(cs.namespace(|| "budget_add"), &cost)?;
        // budget_out ∈ [0, 2^BUDGET_BITS): non-negative, no field wrap.
        enforce_range(cs.namespace(|| "budget_range"), &budget_out, BUDGET_BITS)?;

        // headroom = B_MAX - budget_out, and headroom ∈ [0, 2^BUDGET_BITS) ⟹ budget_out ≤ B_MAX.
        // If budget_out > B_MAX the headroom is a (huge) field-wrapped negative and cannot be
        // bit-decomposed → the step is UNSATISFIABLE → the aggregate history is unprovable.
        let bmax = F::from(B_MAX);
        let headroom = AllocatedNum::alloc(cs.namespace(|| "headroom"), || {
            let b = budget_out
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?;
            Ok(bmax - b)
        })?;
        cs.enforce(
            || "budget_out + headroom == B_MAX",
            |lc| lc + budget_out.get_variable() + headroom.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + (bmax, CS::one()),
        );
        enforce_range(cs.namespace(|| "headroom_range"), &headroom, BUDGET_BITS)?;

        Ok(vec![chain_out, budget_out])
    }
}

// ---- in-circuit gadgets (bellpepper, via nova_snark::frontend) ------------------------

/// Range gadget: constrain `num ∈ [0, 2^n_bits)` by bit decomposition. Each bit is a
/// booleanity-constrained [`AllocatedBit`]; one linear constraint ties their weighted sum to
/// `num`. An out-of-range (or field-wrapped negative) value has no valid `n_bits` witness.
fn enforce_range<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    num: &AllocatedNum<F>,
    n_bits: usize,
) -> Result<(), SynthesisError> {
    let value = num.get_value();
    let mut bits = Vec::with_capacity(n_bits);
    for i in 0..n_bits {
        let bit_val = value.map(|v| get_bit_le(&v, i));
        let b = AllocatedBit::alloc(cs.namespace(|| format!("bit {i}")), bit_val)?;
        bits.push(b);
    }
    // enforce  Σ 2^i · bitᵢ  ==  num
    cs.enforce(
        || "bit decomposition",
        |lc| {
            let mut lc = lc;
            let mut coeff = F::ONE;
            for b in &bits {
                lc = lc + (coeff, b.get_variable());
                coeff = coeff.double();
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc + num.get_variable(),
    );
    Ok(())
}

/// `x⁵` via square–square–multiply (3 constraints). x⁵ is a permutation on the Pasta scalar
/// field (gcd(5, p−1) = 1), the standard algebraic S-box.
fn pow5<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    x: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let x2 = x.square(cs.namespace(|| "x2"))?;
    let x4 = x2.square(cs.namespace(|| "x4"))?;
    x4.mul(cs.namespace(|| "x5"), x)
}

/// `out = a + c` for a circuit constant `c` (one linear constraint).
fn add_const<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    a: &AllocatedNum<F>,
    c: F,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let out = AllocatedNum::alloc(cs.namespace(|| "val"), || {
        Ok(a.get_value().ok_or(SynthesisError::AssignmentMissing)? + c)
    })?;
    cs.enforce(
        || "a + c == out",
        |lc| lc + a.get_variable() + (c, CS::one()),
        |lc| lc + CS::one(),
        |lc| lc + out.get_variable(),
    );
    Ok(out)
}

/// MiMC-style 2-to-1 algebraic hash, keyed by `right`: `state ← (state + right + Cᵣ)⁵` for
/// `MIMC_ROUNDS` rounds, with a `+ right` feed-forward. Binds both inputs. Mirrored exactly by
/// [`hash2_native`]. (Didactic parameters — see the module candor note.)
fn hash2<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    left: &AllocatedNum<F>,
    right: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let constants = mimc_round_constants::<F>();
    let mut state = left.clone();
    for (i, c) in constants.iter().enumerate() {
        let sr = state.add(cs.namespace(|| format!("sr_{i}")), right)?;
        let t = add_const(cs.namespace(|| format!("t_{i}")), &sr, *c)?;
        state = pow5(cs.namespace(|| format!("sbox_{i}")), &t)?;
    }
    state.add(cs.namespace(|| "feed_forward"), right)
}

// ---- native (out-of-circuit) mirror --------------------------------------------------

/// Deterministic, domain-separated MiMC round constants (an LCG seeded by the golden ratio).
/// Shared by the circuit and the native mirror so both compute an identical hash.
fn mimc_round_constants<F: PrimeField>() -> Vec<F> {
    let mut v = Vec::with_capacity(MIMC_ROUNDS);
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..MIMC_ROUNDS {
        x = x
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        v.push(F::from(x));
    }
    v
}

/// The native (non-circuit) image of [`hash2`]. Lets callers precompute the expected final
/// `chain_digest` and cross-check the IVC output.
pub fn hash2_native<F: PrimeField>(left: F, right: F) -> F {
    let mut state = left;
    for c in mimc_round_constants::<F>() {
        let t = state + right + c;
        let t2 = t * t;
        let t4 = t2 * t2;
        state = t4 * t; // t⁵
    }
    state + right
}

/// Natively replay a history to the expected final `(chain_digest, budget_spent)`.
pub fn native_final_state(actions: &[ActionStep]) -> (Scalar, Scalar) {
    let mut chain = Scalar::ZERO;
    let mut budget = Scalar::ZERO;
    for a in actions {
        chain = hash2_native(chain, Scalar::from(a.action_digest));
        budget += Scalar::from(a.cost);
    }
    (chain, budget)
}

/// Does this history stay within the cumulative bound? (A native pre-check; the circuit is the
/// authority.)
pub fn within_budget(actions: &[ActionStep]) -> bool {
    actions.iter().map(|a| a.cost as u128).sum::<u128>() <= B_MAX as u128
}

// ---- top-level prove / fold / compress / verify --------------------------------------

/// The IVC initial state `z₀ = [0, 0]`.
pub fn initial_state() -> Vec<Scalar> {
    vec![Scalar::ZERO, Scalar::ZERO]
}

/// Build the per-step circuits for a history.
pub fn circuits_for(actions: &[ActionStep]) -> Vec<Circuit> {
    actions
        .iter()
        .map(|a| ActionCircuit {
            action_digest: Scalar::from(a.action_digest),
            cost: Scalar::from(a.cost),
        })
        .collect()
}

/// Derive Nova public parameters for the step circuit (shape-only; witness values in
/// `sample` are irrelevant).
pub fn public_params(sample: &Circuit) -> Result<PP, NovaError> {
    PublicParams::<E1, E2, Circuit>::setup(sample, &*S1::ck_floor(), &*S2::ck_floor())
}

/// A folded, verified recursive proof of one history, with everything needed to compress it.
pub struct ProvedHistory {
    pub pp: PP,
    pub recursive: Recursive,
    pub z0: Vec<Scalar>,
    pub final_state: Vec<Scalar>,
    pub num_steps: usize,
}

/// Fold an entire action history into one [`RecursiveSNARK`] and verify it.
///
/// Returns `Err` for an over-budget (or otherwise unsatisfiable) history: either a
/// `prove_step` fails to fold, or the final `verify` rejects the accumulated instance — in
/// release builds (the demo runs `--release`) the invariant surfaces as a rejected proof, never
/// a panic.
pub fn prove_history(actions: &[ActionStep]) -> Result<ProvedHistory, NovaError> {
    assert!(!actions.is_empty(), "history must contain at least one action");
    let circuits = circuits_for(actions);
    let pp = public_params(&circuits[0])?;
    let z0 = initial_state();

    let mut recursive = RecursiveSNARK::<E1, E2, Circuit>::new(&pp, &circuits[0], &z0)?;
    for c in &circuits {
        recursive.prove_step(&pp, c)?;
    }
    let num_steps = circuits.len();
    let final_state = recursive.verify(&pp, num_steps, &z0)?;

    Ok(ProvedHistory {
        pp,
        recursive,
        z0,
        final_state,
        num_steps,
    })
}

/// Verify a folded recursive proof. Returns the final `[chain_digest, budget_spent]`.
pub fn verify_recursive(
    pp: &PP,
    recursive: &Recursive,
    num_steps: usize,
    z0: &[Scalar],
) -> Result<Vec<Scalar>, NovaError> {
    recursive.verify(pp, num_steps, z0)
}

/// Derive the compressed-SNARK prover/verifier keys.
pub fn compress_keys(pp: &PP) -> Result<(CompProverKey, CompVerifierKey), NovaError> {
    CompressedSNARK::<E1, E2, Circuit, S1, S2>::setup(pp)
}

/// Compress the folded recursive proof into a single succinct [`CompressedSNARK`] — the one
/// proof of the whole history.
pub fn compress(
    pp: &PP,
    pk: &CompProverKey,
    recursive: &Recursive,
) -> Result<Compressed, NovaError> {
    CompressedSNARK::<E1, E2, Circuit, S1, S2>::prove(pp, pk, recursive)
}

/// Verify the compressed proof against the public IO. Returns the final
/// `[chain_digest, budget_spent]`.
pub fn verify_compressed(
    proof: &Compressed,
    vk: &CompVerifierKey,
    num_steps: usize,
    z0: &[Scalar],
) -> Result<Vec<Scalar>, NovaError> {
    proof.verify(vk, num_steps, z0)
}

// ---- small serialization helpers -----------------------------------------------------

/// Big-endian `0x`-hex of a field element (for the JSON public-IO fixtures).
pub fn felt_to_hex<F: PrimeField>(f: &F) -> String {
    let repr = f.to_repr();
    let mut be = repr.as_ref().to_vec(); // Pasta reprs are little-endian
    be.reverse();
    let mut s = String::with_capacity(2 + be.len() * 2);
    s.push_str("0x");
    for b in be {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Extract bit `i` (little-endian) of a field element's canonical representation.
fn get_bit_le<F: PrimeField>(v: &F, i: usize) -> bool {
    let repr = v.to_repr();
    let bytes = repr.as_ref();
    let byte = i / 8;
    if byte >= bytes.len() {
        return false;
    }
    (bytes[byte] >> (i % 8)) & 1 == 1
}
