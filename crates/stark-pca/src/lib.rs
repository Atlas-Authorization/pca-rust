//! # stark-pca — a transparent STARK of the PCA release gate
//!
//! A genuine, verifiable zk-STARK (Winterfell, hash-based, **no trusted setup**,
//! **post-quantum**) proving the *core release gate* of Proof-Carrying Authority.
//!
//! ## What the AIR proves
//!
//! Given PUBLIC inputs — the risk weights `(α,β,γ,δ,ε,ζ)`, the tier-1 threshold `θ₁`,
//! the cost scale `κ`, the budget ceiling `bMax`, the fixed-point scale `S = 1e6`, and
//! two opaque commitments `(policy_commitment, action_commitment)` — and PRIVATE
//! witnesses — the six risk-magnitude inputs `(d, rev, bl, taint, conf, age)`, the trust
//! budget `B`, a predicate-match bit `pm`, and a caveats-satisfied bit `co` — the prover
//! demonstrates knowledge of a witness such that
//!
//! ```text
//!   r_raw = α·d + β·(1−rev) + γ·bl + δ·taint + ε·(1−conf) + ζ·age           (fixed-point, scale S²)
//!   allow = (tier==1) ∧ (B ≥ κ·r) ∧ pm ∧ co   and   allow == 1
//! ```
//!
//! where `r = r_raw / S²` is computed by the **same fixed-point risk functional as
//! the `@atlasauth/pca` reference risk model** (weights clamped `≥0`, inputs in `[0,1]` at scale `S`,
//! reversibility and confidence entering as `1−x`), `tier==1 ⟺ r ≤ θ₁`
//! (`requiredThreshold`'s t=1 band), and `B ≥ κ·r` is the budget-admission cost gate
//! (`admit` / `cost`).
//!
//! `allow` is **derived** in-trace as the product of the four conjuncts and **asserted
//! `== 1`**: a deny witness (`r > θ₁`, `B < κ·r`, `pm == 0`, or `co == 0`) makes the
//! system unsatisfiable, so you cannot forge an `allow` proof. The two inequalities are
//! enforced by in-AIR **bit-decomposition range gadgets** (`θ₁·S² − r_raw ≥ 0` and
//! `B·S − κ·r_raw ≥ 0`), which are real algebraic STARK constraints — not a trusted bit.
//!
//! ## Witness ↔ commitment binding (the in-AIR hash)
//!
//! The private witness is now **bound in-AIR** to a public commitment. A genuine in-AIR
//! algebraic hash (`NUM_LANES=10`-wide cube-S-box SPN: `a_k = (Hₖ + 2^row + RCₖ)³`,
//! diffusion `H'ⱼ = Σₖ aₖ + aⱼ`, one round per trace row) absorbs the **nine quantized
//! witness quantities** `(d, rev, bl, taint, conf, age, B, pm, co)` on row 0 (lanes 0..8) +
//! a capacity IV (lane 9), runs `TRACE_LEN−1` rounds, and the first `COMMIT_LIMBS=4` state
//! lanes at the final row are **asserted equal to a public input** `witness_commitment`
//! (the resource server's algebraic commitment to the quantized action). The same
//! witness columns drive both the risk gate and the hash, so a proof exists only for a
//! witness whose quantized form hashes to the committed value — you cannot prove the gate
//! for a witness that does not match the committed action. See `compute_witness_commitment`.
//!
//! See `README.md` for the precise honest gaps versus the Groth16 Policy-VM circuit
//! (the `@atlasauth/pca` Groth16 circuit). The binding above is over the **quantized preimage** via the
//! AIR's native algebraic hash — it is **not** a recomputation of the SHA-256-of-canonical-
//! JSON `action_commitment` in-AIR (still infeasible in this field); the two are linked
//! off-circuit by the resource server deriving both from one action. Remaining gaps:
//! predicates/caveats are reduced to booleans, the threshold ladder beyond t=1 and the
//! attenuation chain are not encoded.

// Trace-construction code mirrors the AIR column-by-column; index loops are the clearer form.
#![allow(
    clippy::needless_range_loop,
    clippy::manual_memcpy,
    clippy::manual_range_patterns,
    clippy::unnecessary_cast
)]

use serde::{Deserialize, Serialize};
use winter_utils::{ByteReader, Deserializable, DeserializationError, SliceReader};
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, StarkField, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, FieldExtension, PartitionOptions,
    Proof, ProofOptions, Prover, ProverError, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
    TransitionConstraintDegree,
};

/// Fixed-point scale (parts-per-million). Matches the reference risk model and Groth16 circuit (`S = 1e6`).
pub const S: u64 = 1_000_000;
/// Execution-trace length (power of two; ≥ 63 so the range gadgets cover bits 0..=62).
pub const TRACE_LEN: usize = 64;
/// Number of in-AIR range checks (bit-decomposition gadgets).
pub const NUM_RC: usize = 16;

// ---- trace column layout --------------------------------------------------------------

const C_X: [usize; 6] = [0, 1, 2, 3, 4, 5]; // d, rev, bl, taint, conf, age (scaled 0..=S)
const C_BS: usize = 6; // budget, scaled by S
const C_RRAW: usize = 7; // Σ wᵢ·termᵢ  (scale S²)
const C_PM: usize = 8; // predicate-match bit
const C_CO: usize = 9; // caveats-ok bit
const C_TGATE: usize = 10; // tier==1 bit
const C_BGATE: usize = 11; // B≥κ·r bit
const C_ALLOW: usize = 12; // allow == pm·co·tgate·bgate
const C_POW: usize = 13; // 2^step
const RC_BASE: usize = 14; // range-check columns start here (2 per check: bit, acc)

// ---- in-AIR algebraic-hash (witness ↔ commitment binding) layout ---------------------

/// Hash-state lanes: lanes 0..8 absorb the 9 quantized witness quantities, lane 9 = capacity.
pub const NUM_LANES: usize = 10;
/// Number of squeezed output limbs forming the public `witness_commitment`.
pub const COMMIT_LIMBS: usize = 4;
/// Number of 64-bit limbs each opaque 256-bit hex commitment is split into (big-endian: limb 0
/// = hex digits 0..16 ... limb 3 = hex digits 48..64). 64-bit limbs are always `< p` in `f128`,
/// so the split is injective: all 256 bits are bound, with no modular reduction.
pub const HEX_LIMBS: usize = 4;
/// Required length of an opaque commitment: 64 hex digits (a SHA-256 digest).
pub const HEX_COMMITMENT_DIGITS: usize = 64;
/// Hash-state columns start here (one column per lane).
const HASH_BASE: usize = RC_BASE + 2 * NUM_RC; // 46
/// Total trace width.
pub const WIDTH: usize = HASH_BASE + NUM_LANES; // 56

/// Capacity-lane IV and per-lane round constants (nothing-up-my-sleeve; all fit in u64, so
/// they are byte-identical to the Plonky3/Goldilocks crate's constants).
const CAP_IV: u64 = 0x5043_4162_6967_3031; // "PCAbig01"
const RC_SEED: u64 = 0x00A1_B2C3_D4E5_F607;
const RC_STRIDE: u64 = 0x0000_1000_0000_01B3;

#[inline]
const fn rc_k(k: usize) -> u64 {
    RC_SEED.wrapping_add((k as u64).wrapping_mul(RC_STRIDE))
}
#[inline]
const fn h_lane(j: usize) -> usize {
    HASH_BASE + j
}
/// The trace column holding the preimage element absorbed into hash lane `j` (j < 9):
/// lanes 0..5 → the six risk inputs, lane 6 → budget, lane 7 → pm, lane 8 → co.
#[inline]
const fn preimage_col(j: usize) -> usize {
    match j {
        0 | 1 | 2 | 3 | 4 | 5 => C_X[j],
        6 => C_BS,
        7 => C_PM,
        8 => C_CO,
        _ => usize::MAX,
    }
}

#[inline]
const fn rc_bit(k: usize) -> usize {
    RC_BASE + 2 * k
}
#[inline]
const fn rc_acc(k: usize) -> usize {
    RC_BASE + 2 * k + 1
}

/// `rev` (index 1) and `conf` (index 4) enter the functional as `(1 − x)`.
const INVERTED: [bool; 6] = [false, true, false, false, true, false];

// ---- public inputs & policy -----------------------------------------------------------

/// Public policy parameters (the verifier's view). All risk quantities are integers at
/// scale `S`; `kappa` is a non-negative integer cost scale (see README gap note).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyParams {
    /// Risk weights (α,β,γ,δ,ε,ζ) at scale S (e.g. 0.25 → 250000).
    pub weights: [u64; 6],
    /// Fixed-point scale (must equal `S`).
    pub s: u64,
    /// Tier-1 threshold θ₁ at scale S (e.g. 0.25 → 250000).
    pub theta1_scaled: u64,
    /// Cost scale κ (non-negative integer).
    pub kappa: u64,
    /// Budget ceiling bMax at scale S (e.g. 1.0 → 1000000).
    pub bmax_scaled: u64,
    /// Opaque policy commitment: exactly 64 hex digits (256 bits, case-insensitive). All 256
    /// bits are bound into the proof transcript (as `HEX_LIMBS` 64-bit field elements); NOT
    /// constrained in-AIR.
    pub policy_commitment: String,
    /// Opaque action commitment: exactly 64 hex digits (SHA-256 of canonical JSON). All 256
    /// bits are bound into the proof transcript, NOT recomputed in-AIR (see the crate docs / README on the quantized binding).
    pub action_commitment: String,
    /// The resource server's algebraic commitment to the quantized action — the
    /// `COMMIT_LIMBS` field-element limbs (decimal) of [`compute_witness_commitment`]. These
    /// ARE constrained in-AIR: the witness's quantized form is proven to hash to them.
    pub witness_commitment: [String; COMMIT_LIMBS],
}

impl PolicyParams {
    /// The default risk policy of the reference model, scaled by S. Its
    /// `witness_commitment` is the algebraic commitment to the paired [`Witness::compliant`]
    /// quantized action (the default fixture), as a resource server would compute and publish.
    pub fn default_policy() -> Self {
        let wc = compute_witness_commitment(&Witness::compliant());
        PolicyParams {
            weights: [250_000, 200_000, 200_000, 200_000, 100_000, 50_000],
            s: S,
            theta1_scaled: 250_000, // θ₁ = 0.25
            kappa: 1,
            bmax_scaled: 1_000_000, // bMax = 1.0
            policy_commitment: "a1b2c3d4e5f60718293a4b5c6d7e8f90fedcba98765432100123456789abcdef".into(),
            action_commitment: "0f1e2d3c4b5a69788796a5b4c3d2e1f0112233445566778899aabbccddeeff00".into(),
            witness_commitment: core::array::from_fn(|m| wc[m].as_int().to_string()),
        }
    }

    /// θ₁·S² : the tier-1 bound in `r_raw` (scale S²) units. `r ≤ θ₁ ⟺ r_raw ≤ θ₁·S²`.
    fn t1_rraw(&self) -> u128 {
        self.theta1_scaled as u128 * self.s as u128
    }

    /// Check that both opaque commitments are exactly 64 hex digits. Anything else (short,
    /// long, non-hex, `0x`-prefixed) is refused rather than silently truncated.
    pub fn validate(&self) -> Result<(), String> {
        hex256_limbs(&self.policy_commitment).map_err(|e| format!("policy_commitment: {e}"))?;
        hex256_limbs(&self.action_commitment).map_err(|e| format!("action_commitment: {e}"))?;
        Ok(())
    }

    /// The public inputs embedded in / checked against the proof, or `Err` if a commitment is
    /// malformed (see [`PolicyParams::validate`]).
    pub fn try_to_public(&self) -> Result<PublicInputs, String> {
        let pc = hex256_limbs(&self.policy_commitment).map_err(|e| format!("policy_commitment: {e}"))?;
        let ac = hex256_limbs(&self.action_commitment).map_err(|e| format!("action_commitment: {e}"))?;
        let wc: [BaseElement; COMMIT_LIMBS] =
            core::array::from_fn(|m| BaseElement::new(self.witness_commitment[m].parse::<u128>().unwrap_or(0)));
        Ok(PublicInputs {
            weights: self.weights.map(|w| BaseElement::new(w as u128)),
            s: BaseElement::new(self.s as u128),
            t1_rraw: BaseElement::new(self.t1_rraw()),
            kappa: BaseElement::new(self.kappa as u128),
            bmax_scaled: BaseElement::new(self.bmax_scaled as u128),
            policy_commitment: pc.map(|l| BaseElement::new(l as u128)),
            action_commitment: ac.map(|l| BaseElement::new(l as u128)),
            witness_commitment: wc,
        })
    }

    /// Infallible form of [`PolicyParams::try_to_public`].
    ///
    /// # Panics
    /// If a commitment is not exactly 64 hex digits; call [`PolicyParams::validate`] first on
    /// untrusted policies. `prove_release` / `verify_release` do so and never panic.
    pub fn to_public(&self) -> PublicInputs {
        self.try_to_public().expect("malformed policy/action commitment (need 64 hex digits)")
    }
}

/// Parse exactly 64 hex digits into four big-endian 64-bit limbs (all 256 bits, injective).
pub fn hex256_limbs(h: &str) -> Result<[u64; HEX_LIMBS], String> {
    if h.len() != HEX_COMMITMENT_DIGITS || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("must be exactly {HEX_COMMITMENT_DIGITS} hex digits"));
    }
    let mut out = [0u64; HEX_LIMBS];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u64::from_str_radix(&h[16 * i..16 * i + 16], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// Public inputs as field elements. Order here defines the Fiat–Shamir transcript binding.
#[derive(Clone, Debug)]
pub struct PublicInputs {
    pub weights: [BaseElement; 6],
    pub s: BaseElement,
    pub t1_rraw: BaseElement,
    pub kappa: BaseElement,
    pub bmax_scaled: BaseElement,
    /// 256-bit policy commitment as four 64-bit limbs (big-endian).
    pub policy_commitment: [BaseElement; HEX_LIMBS],
    /// 256-bit action commitment as four 64-bit limbs (big-endian).
    pub action_commitment: [BaseElement; HEX_LIMBS],
    pub witness_commitment: [BaseElement; COMMIT_LIMBS],
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut v = Vec::with_capacity(10 + 2 * HEX_LIMBS + COMMIT_LIMBS);
        v.extend_from_slice(&self.weights);
        v.push(self.s);
        v.push(self.t1_rraw);
        v.push(self.kappa);
        v.push(self.bmax_scaled);
        v.extend_from_slice(&self.policy_commitment);
        v.extend_from_slice(&self.action_commitment);
        v.extend_from_slice(&self.witness_commitment);
        v
    }
}

/// Private witness.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Witness {
    /// (d, rev, bl, taint, conf, age) at scale S, each in `[0, S]`.
    pub inputs: [u64; 6],
    /// Trust budget B at scale S.
    pub budget_scaled: u64,
    /// predicate-match bit.
    pub predicate_match: bool,
    /// caveats-satisfied bit.
    pub caveats_ok: bool,
}

impl Witness {
    /// A compliant, low-risk witness that satisfies the gate under the default policy.
    pub fn compliant() -> Self {
        Witness {
            // d=0.10 rev=0.90 bl=0.05 taint=0.00 conf=0.95 age=0.10  → r = 0.065 ≤ θ₁=0.25
            inputs: [100_000, 900_000, 50_000, 0, 950_000, 100_000],
            budget_scaled: 1_000_000, // B = 1.0 ≥ κ·r = 0.065
            predicate_match: true,
            caveats_ok: true,
        }
    }

    /// Non-compliant: high risk AND no budget (r > θ₁ and B < κ·r).
    pub fn non_compliant_risk() -> Self {
        Witness {
            // all risk-maximal → r = 0.90 > θ₁
            inputs: [900_000, 100_000, 900_000, 900_000, 100_000, 900_000],
            budget_scaled: 0,
            predicate_match: true,
            caveats_ok: true,
        }
    }

    /// Non-compliant: compliant risk/budget but predicate does not match (pm = 0).
    pub fn non_compliant_predicate() -> Self {
        let mut w = Witness::compliant();
        w.predicate_match = false;
        w
    }
}

// ---- fixed-point risk functional (scale S²), shared by trace-gen and tests -----------

/// `r_raw = Σ wᵢ·termᵢ` where `termᵢ = xᵢ` or `(S − xᵢ)` for inverted inputs. Scale S².
/// This is the integer image of `riskScore` in the reference model; dividing by S² recovers `r∈[0,1]`.
pub fn risk_raw(inputs: &[u64; 6], weights: &[u64; 6]) -> u128 {
    let mut acc: u128 = 0;
    for i in 0..6 {
        let x = inputs[i] as u128;
        let term = if INVERTED[i] { S as u128 - x } else { x };
        acc += weights[i] as u128 * term;
    }
    acc
}

// ---- in-AIR algebraic hash (witness ↔ commitment binding) ----------------------------

/// Run the full hash-state trace. Row 0 is the initial state (lanes 0..8 = the 9 quantized
/// preimage elements, lane 9 = capacity IV); each subsequent row applies one SPN round with
/// a cube S-box (`a_k = (H_k + 2^row + RC_k)³`) and an invertible `(I+J)` diffusion layer
/// (`H'_j = Σ_k a_k + a_j`). This is exactly the recurrence enforced in-AIR by
/// [`ReleaseAir::evaluate_transition`], so prover trace and verifier constraints agree.
fn hash_state_trace(preimage: &[BaseElement; 9]) -> [[BaseElement; NUM_LANES]; TRACE_LEN] {
    let mut st = [[BaseElement::ZERO; NUM_LANES]; TRACE_LEN];
    for j in 0..9 {
        st[0][j] = preimage[j];
    }
    st[0][9] = BaseElement::new(CAP_IV as u128);
    let rc: [BaseElement; NUM_LANES] = core::array::from_fn(|k| BaseElement::new(rc_k(k) as u128));
    for r in 0..TRACE_LEN - 1 {
        let pow = BaseElement::new(1u128 << r);
        let mut a = [BaseElement::ZERO; NUM_LANES];
        let mut sum = BaseElement::ZERO;
        for k in 0..NUM_LANES {
            let t = st[r][k] + pow + rc[k];
            let c = t * t * t;
            a[k] = c;
            sum += c;
        }
        for j in 0..NUM_LANES {
            st[r + 1][j] = sum + a[j];
        }
    }
    st
}

/// The nine quantized witness quantities, in absorption order (= lanes 0..8).
fn witness_preimage(w: &Witness) -> [BaseElement; 9] {
    [
        BaseElement::new(w.inputs[0] as u128),
        BaseElement::new(w.inputs[1] as u128),
        BaseElement::new(w.inputs[2] as u128),
        BaseElement::new(w.inputs[3] as u128),
        BaseElement::new(w.inputs[4] as u128),
        BaseElement::new(w.inputs[5] as u128),
        BaseElement::new(w.budget_scaled as u128),
        if w.predicate_match { BaseElement::ONE } else { BaseElement::ZERO },
        if w.caveats_ok { BaseElement::ONE } else { BaseElement::ZERO },
    ]
}

/// The algebraic commitment to the quantized witness preimage: the first `COMMIT_LIMBS`
/// hash-state lanes at the final trace row. The resource server computes the *same* value
/// over the quantized action and publishes it as `PolicyParams::witness_commitment`.
pub fn compute_witness_commitment(w: &Witness) -> [BaseElement; COMMIT_LIMBS] {
    let st = hash_state_trace(&witness_preimage(w));
    core::array::from_fn(|m| st[TRACE_LEN - 1][m])
}

// ---- the AIR --------------------------------------------------------------------------

pub struct ReleaseAir {
    context: AirContext<BaseElement>,
    weights: [BaseElement; 6],
    s: BaseElement,
    t1_rraw: BaseElement,
    kappa: BaseElement,
    bmax_scaled: BaseElement,
    witness_commitment: [BaseElement; COMMIT_LIMBS],
}

impl ReleaseAir {
    /// Target value decomposed by range-check `k` (the quantity asserted `≥ 0`), as a
    /// field expression over the *current* trace row. Must match [`rc_target_base`].
    fn rc_target<E: FieldElement<BaseField = BaseElement>>(&self, k: usize, cur: &[E]) -> E {
        let s = E::from(self.s);
        match k {
            // input lower/upper bounds: xᵢ ≥ 0 and S − xᵢ ≥ 0  ⟹  xᵢ ∈ [0, S]
            0 => cur[C_X[0]],
            1 => s - cur[C_X[0]],
            2 => cur[C_X[1]],
            3 => s - cur[C_X[1]],
            4 => cur[C_X[2]],
            5 => s - cur[C_X[2]],
            6 => cur[C_X[3]],
            7 => s - cur[C_X[3]],
            8 => cur[C_X[4]],
            9 => s - cur[C_X[4]],
            10 => cur[C_X[5]],
            11 => s - cur[C_X[5]],
            // budget bounds: B_S ≥ 0 and bMax·S − B_S ≥ 0  ⟹  B_S ∈ [0, bMax·S]
            12 => cur[C_BS],
            13 => E::from(self.bmax_scaled) - cur[C_BS],
            // tier==1 gate: θ₁·S² − r_raw ≥ 0  ⟺  r ≤ θ₁
            14 => E::from(self.t1_rraw) - cur[C_RRAW],
            // budget gate: B_S·S − κ·r_raw ≥ 0  ⟺  B ≥ κ·r
            15 => s * cur[C_BS] - E::from(self.kappa) * cur[C_RRAW],
            _ => unreachable!(),
        }
    }
}

impl Air for ReleaseAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(WIDTH, trace_info.width());

        let mut degrees = Vec::new();
        // (A) constant propagation for columns 0..=12
        for _ in 0..13 {
            degrees.push(TransitionConstraintDegree::new(1));
        }
        // (B) pow recurrence
        degrees.push(TransitionConstraintDegree::new(1));
        // (C) r_raw definition
        degrees.push(TransitionConstraintDegree::new(1));
        // (D) four boolean gates (pm, co, tgate, bgate)
        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::new(2));
        }
        // (E) allow = pm·co·tgate·bgate
        degrees.push(TransitionConstraintDegree::new(4));
        // (F) per range check: boolean(2), residual recurrence(2), init pin(1 × periodic cycle)
        for _ in 0..NUM_RC {
            degrees.push(TransitionConstraintDegree::new(2));
            degrees.push(TransitionConstraintDegree::new(2));
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![TRACE_LEN]));
        }
        // (G) hash SPN round recurrence (cube S-box → degree 3), one per lane
        for _ in 0..NUM_LANES {
            degrees.push(TransitionConstraintDegree::new(3));
        }
        // (H) hash init pins (first row only): degree-1 gated by the step-0 periodic selector
        for _ in 0..NUM_LANES {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![TRACE_LEN]));
        }

        // assertions: pow[0]=1, allow[0]=1, acc_k[last]=0 per range check, and the
        // COMMIT_LIMBS squeezed hash lanes at the last row == public witness_commitment.
        let num_assertions = 2 + NUM_RC + COMMIT_LIMBS;

        ReleaseAir {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            weights: pub_inputs.weights,
            s: pub_inputs.s,
            t1_rraw: pub_inputs.t1_rraw,
            kappa: pub_inputs.kappa,
            bmax_scaled: pub_inputs.bmax_scaled,
            witness_commitment: pub_inputs.witness_commitment,
        }
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<BaseElement>> {
        // s0: a selector that is 1 only at step 0 (period = trace length).
        let mut s0 = vec![BaseElement::ZERO; TRACE_LEN];
        s0[0] = BaseElement::ONE;
        vec![s0]
    }

    fn evaluate_transition<E: FieldElement<BaseField = BaseElement>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let next = frame.next();
        let one = E::ONE;
        let s0 = periodic[0];
        let mut i = 0usize;

        // (A) constant propagation for columns 0..=12
        for c in 0..13 {
            result[i] = next[c] - cur[c];
            i += 1;
        }
        // (B) pow' = 2·pow
        result[i] = next[C_POW] - (cur[C_POW] + cur[C_POW]);
        i += 1;
        // (C) r_raw = Σ wᵢ·termᵢ  (rev, conf inverted as S − x)
        let s = E::from(self.s);
        let mut rraw = E::ZERO;
        for j in 0..6 {
            let w = E::from(self.weights[j]);
            let term = if INVERTED[j] { s - cur[C_X[j]] } else { cur[C_X[j]] };
            rraw += w * term;
        }
        result[i] = cur[C_RRAW] - rraw;
        i += 1;
        // (D) boolean gates
        for &c in &[C_PM, C_CO, C_TGATE, C_BGATE] {
            result[i] = cur[c] * (cur[c] - one);
            i += 1;
        }
        // (E) allow = pm·co·tgate·bgate
        result[i] = cur[C_ALLOW] - cur[C_PM] * cur[C_CO] * cur[C_TGATE] * cur[C_BGATE];
        i += 1;
        // (F) range checks
        for k in 0..NUM_RC {
            let bit = cur[rc_bit(k)];
            let acc = cur[rc_acc(k)];
            let acc_next = next[rc_acc(k)];
            let pow = cur[C_POW];
            // boolean bit
            result[i] = bit * (bit - one);
            i += 1;
            // residual recurrence: acc' = acc − bit·pow   (so acc counts DOWN to 0)
            result[i] = acc_next - (acc - bit * pow);
            i += 1;
            // init pin (only at step 0): acc[0] == target_k
            result[i] = s0 * (acc - self.rc_target(k, cur));
            i += 1;
        }

        // (G) algebraic-hash SPN round: a_k = (H_k + pow + RC_k)³ ; H'_j = Σ_k a_k + a_j.
        // The per-row constant is `pow` (= 2^row, column C_POW), so every round differs; the
        // per-lane RC_k break lane symmetry. This recurrence binds the preimage (row 0) to
        // the squeezed commitment (last row), asserted equal to the public input below.
        let pow = cur[C_POW];
        let mut a = [E::ZERO; NUM_LANES];
        let mut sum = E::ZERO;
        for k in 0..NUM_LANES {
            let t = cur[h_lane(k)] + pow + E::from(BaseElement::new(rc_k(k) as u128));
            let c = t * t * t;
            a[k] = c;
            sum += c;
        }
        for j in 0..NUM_LANES {
            result[i] = next[h_lane(j)] - (sum + a[j]);
            i += 1;
        }
        // (H) hash init pins (step 0 only): lanes 0..8 == the quantized preimage columns,
        // lane 9 == the capacity IV.
        for j in 0..9 {
            result[i] = s0 * (cur[h_lane(j)] - cur[preimage_col(j)]);
            i += 1;
        }
        result[i] = s0 * (cur[h_lane(9)] - E::from(BaseElement::new(CAP_IV as u128)));
        i += 1;
        debug_assert_eq!(i, result.len());
    }

    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        let last = TRACE_LEN - 1;
        let mut a = Vec::with_capacity(2 + NUM_RC + COMMIT_LIMBS);
        a.push(Assertion::single(C_POW, 0, BaseElement::ONE)); // pow[0] = 2^0 = 1
        a.push(Assertion::single(C_ALLOW, 0, BaseElement::ONE)); // allow = 1 (the gate)
        for k in 0..NUM_RC {
            // residual decompositions all reach exactly 0 → each target is a valid
            // non-negative <2^63 bit sum (a deny witness cannot satisfy this).
            a.push(Assertion::single(rc_acc(k), last, BaseElement::ZERO));
        }
        // squeeze: the first COMMIT_LIMBS hash lanes at the last row must equal the public
        // witness_commitment — this is the in-AIR witness ↔ action binding.
        for m in 0..COMMIT_LIMBS {
            a.push(Assertion::single(h_lane(m), last, self.witness_commitment[m]));
        }
        a
    }

    fn context(&self) -> &AirContext<BaseElement> {
        &self.context
    }
}

/// Concrete (non-generic) target value for range-check `k`, used by trace generation.
/// MUST match [`ReleaseAir::rc_target`].
fn rc_target_base(k: usize, x: &[BaseElement; 6], bs: BaseElement, rraw: BaseElement, p: &PublicInputs) -> BaseElement {
    let s = p.s;
    match k {
        0 => x[0],
        1 => s - x[0],
        2 => x[1],
        3 => s - x[1],
        4 => x[2],
        5 => s - x[2],
        6 => x[3],
        7 => s - x[3],
        8 => x[4],
        9 => s - x[4],
        10 => x[5],
        11 => s - x[5],
        12 => bs,
        13 => p.bmax_scaled - bs,
        14 => p.t1_rraw - rraw,
        15 => s * bs - p.kappa * rraw,
        _ => unreachable!(),
    }
}

// ---- trace construction ---------------------------------------------------------------

/// Build the execution trace for `(witness, policy)`.
pub fn build_trace(w: &Witness, policy: &PolicyParams) -> TraceTable<BaseElement> {
    let p = policy.to_public();
    let x: [BaseElement; 6] = w.inputs.map(|v| BaseElement::new(v as u128));
    let bs = BaseElement::new(w.budget_scaled as u128);
    let rraw = BaseElement::new(risk_raw(&w.inputs, &policy.weights));
    let pm = if w.predicate_match { BaseElement::ONE } else { BaseElement::ZERO };
    let co = if w.caveats_ok { BaseElement::ONE } else { BaseElement::ZERO };
    let tgate = BaseElement::ONE; // asserted gate bit (proven consistent by range checks 14/15)
    let bgate = BaseElement::ONE;
    let allow = pm * co * tgate * bgate;

    let mut cols: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; TRACE_LEN]; WIDTH];

    // constant columns (repeated on every row)
    let consts = [x[0], x[1], x[2], x[3], x[4], x[5], bs, rraw, pm, co, tgate, bgate, allow];
    for (c, &val) in consts.iter().enumerate() {
        for row in 0..TRACE_LEN {
            cols[c][row] = val;
        }
    }
    // pow column: 2^row
    for row in 0..TRACE_LEN {
        cols[C_POW][row] = BaseElement::new(1u128 << row);
    }
    // range-check columns
    for k in 0..NUM_RC {
        let target = rc_target_base(k, &x, bs, rraw, &p);
        let v = target.as_int(); // u128 field representation
        let bcol = rc_bit(k);
        let acol = rc_acc(k);
        let mut acc = target;
        for row in 0..TRACE_LEN {
            cols[acol][row] = acc;
            // bits 0..=62 participate in the residual (last transition is 62→63).
            let bit = if row < TRACE_LEN - 1 { ((v >> row) & 1) as u128 } else { 0 };
            cols[bcol][row] = BaseElement::new(bit);
            if row < TRACE_LEN - 1 {
                acc -= BaseElement::new(bit) * cols[C_POW][row];
            }
        }
        // For a valid (<2^63) target, acc[last] == 0. For an out-of-range / negative
        // (field-wrapped, ≥2^63) target it is non-zero → the acc[last]=0 assertion fails.
    }

    // in-AIR algebraic-hash columns: the full SPN state trace over the quantized preimage.
    let st = hash_state_trace(&witness_preimage(w));
    for row in 0..TRACE_LEN {
        for j in 0..NUM_LANES {
            cols[h_lane(j)][row] = st[row][j];
        }
    }

    TraceTable::init(cols)
}

// ---- prover ---------------------------------------------------------------------------

/// Winterfell proof options: 32 queries, blowup 8, no field extension → ~96-bit security.
pub fn proof_options() -> ProofOptions {
    ProofOptions::new(
        32,
        8,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// Minimum security level the verifier will accept.
pub const MIN_SECURITY_BITS: u32 = 95;

struct ReleaseProver {
    options: ProofOptions,
    policy: PolicyParams,
}

impl ReleaseProver {
    fn new(options: ProofOptions, policy: PolicyParams) -> Self {
        Self { options, policy }
    }
}

impl Prover for ReleaseProver {
    type BaseField = BaseElement;
    type Air = ReleaseAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PublicInputs {
        self.policy.to_public()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

// ---- public prove / verify API --------------------------------------------------------

/// Generate a STARK proof that `witness` satisfies the release gate under `policy`.
pub fn prove_release(witness: &Witness, policy: &PolicyParams) -> Result<Proof, ProverError> {
    // Malformed commitments cannot be proven against (ProverError has no better variant).
    if policy.validate().is_err() {
        return Err(ProverError::UnsatisfiedTransitionConstraintError(0));
    }
    let trace = build_trace(witness, policy);
    let prover = ReleaseProver::new(proof_options(), policy.clone());
    prover.prove(trace)
}

/// A slice reader that refuses attacker-controlled over-allocation.
///
/// Winterfell decodes `Vec<T>` by reading a length prefix and then calling
/// `ByteReader::read_many(len)`, whose default implementation does
/// `Vec::with_capacity(len)` BEFORE reading any element. A hostile length prefix therefore makes
/// the process abort with an allocation failure (not a catchable panic). Every serialized element
/// occupies at least one byte, so `len` can never legitimately exceed the bytes that remain; we
/// check exactly that.
struct BoundedReader<'a>(SliceReader<'a>);

impl ByteReader for BoundedReader<'_> {
    fn read_u8(&mut self) -> Result<u8, DeserializationError> {
        self.0.read_u8()
    }
    fn peek_u8(&self) -> Result<u8, DeserializationError> {
        self.0.peek_u8()
    }
    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError> {
        self.0.read_slice(len)
    }
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        self.0.read_array::<N>()
    }
    fn check_eor(&self, num_bytes: usize) -> Result<(), DeserializationError> {
        self.0.check_eor(num_bytes)
    }
    fn has_more_bytes(&self) -> bool {
        self.0.has_more_bytes()
    }
    fn read_many<D>(&mut self, num_elements: usize) -> Result<Vec<D>, DeserializationError>
    where
        Self: Sized,
        D: Deserializable,
    {
        self.0.check_eor(num_elements)?;
        let mut result = Vec::with_capacity(num_elements);
        for _ in 0..num_elements {
            result.push(D::read_from(self)?);
        }
        Ok(result)
    }
}

/// Decode a serialized proof from UNTRUSTED bytes, failing closed.
///
/// Plain `winterfell::Proof::from_bytes` is not safe on hostile input: some corrupted headers trip
/// internal assertions (panic) and a corrupted length prefix can request an enormous allocation
/// (process abort). This decoder bounds every length prefix by the remaining input, converts any
/// residual panic into an error, and rejects trailing bytes. Use it (or
/// [`verify_release_bytes`]) for any proof bytes that arrive from the wire.
pub fn proof_from_bytes(bytes: &[u8]) -> Result<Proof, winterfell::VerifierError> {
    let decoded = std::panic::catch_unwind(|| {
        let mut reader = BoundedReader(SliceReader::new(bytes));
        let proof = Proof::read_from(&mut reader)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::InvalidValue("trailing bytes after proof".into()));
        }
        Ok(proof)
    });
    match decoded {
        Ok(Ok(p)) => Ok(p),
        Ok(Err(e)) => Err(winterfell::VerifierError::ProofDeserializationError(format!("{e}"))),
        Err(_) => Err(winterfell::VerifierError::ProofDeserializationError(
            "malformed proof bytes".into(),
        )),
    }
}

/// Decode (fail-closed) and verify a serialized proof in one step.
pub fn verify_release_bytes(
    bytes: &[u8],
    policy: &PolicyParams,
) -> Result<(), winterfell::VerifierError> {
    verify_release(proof_from_bytes(bytes)?, policy)
}

/// Verify a release-gate STARK proof against the public `policy`. `Ok(())` ⟺ the gate
/// holds (allow == 1) for *some* witness, under exactly these public inputs.
pub fn verify_release(
    proof: Proof,
    policy: &PolicyParams,
) -> Result<(), winterfell::VerifierError> {
    // Fail closed on a malformed proof BEFORE handing it to Winterfell: `Air::new` receives the
    // trace shape straight from the (untrusted) proof and cannot return an error, so a proof
    // claiming another width or length would otherwise abort the verifier with a panic.
    let info = proof.trace_info();
    if info.width() != WIDTH
        || info.length() != TRACE_LEN
        || info.aux_segment_width() != 0
        || info.num_aux_segments() != 0
        || !info.meta().is_empty()
    {
        return Err(winterfell::VerifierError::ProofDeserializationError(
            "proof trace shape does not match the release-gate AIR".into(),
        ));
    }
    // Pin the exact proof options (query count, blowup, FRI parameters, partitioning, ...). The
    // security floor below only bounds the strength; without an exact match, option bytes that
    // do not change the statement (e.g. the row-hash partition rate) would be malleable.
    if proof.options() != &proof_options() {
        return Err(winterfell::VerifierError::UnacceptableProofOptions);
    }
    let pub_inputs = policy.try_to_public().map_err(winterfell::VerifierError::ProofDeserializationError)?;
    let min = winterfell::AcceptableOptions::MinConjecturedSecurity(MIN_SECURITY_BITS);
    // Defence in depth: any residual panic on adversarial bytes is reported as a rejection.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        winterfell::verify::<
            ReleaseAir,
            Blake3_256<BaseElement>,
            DefaultRandomCoin<Blake3_256<BaseElement>>,
            MerkleTree<Blake3_256<BaseElement>>,
        >(proof, pub_inputs, &min)
    }))
    .unwrap_or_else(|_| {
        Err(winterfell::VerifierError::ProofDeserializationError(
            "malformed proof rejected by the verifier".into(),
        ))
    })
}
