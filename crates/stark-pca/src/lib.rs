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
//! `packages/pca/src/risk.ts`** (weights clamped `≥0`, inputs in `[0,1]` at scale `S`,
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
//! See `README.md` for the precise honest gaps versus the Groth16 Policy-VM circuit
//! (`packages/pca/src/zk.ts`): no in-AIR SHA-256 struct commitments (the witness is NOT
//! bound in-AIR to `action_commitment`), predicates/caveats are reduced to booleans,
//! the threshold ladder beyond t=1 and the attenuation chain are not encoded.

use serde::{Deserialize, Serialize};
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

/// Fixed-point scale (parts-per-million). Matches `risk.ts` / `zk.ts` `S = 1e6`.
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
/// Total trace width.
pub const WIDTH: usize = RC_BASE + 2 * NUM_RC; // 46

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
    /// Opaque policy commitment (hex) — bound into the proof transcript, NOT constrained in-AIR.
    pub policy_commitment: String,
    /// Opaque action commitment (hex) — bound into the proof transcript, NOT constrained in-AIR.
    pub action_commitment: String,
}

impl PolicyParams {
    /// The default risk policy of `risk.ts` (`DEFAULT_RISK_POLICY`), scaled by S.
    pub fn default_policy() -> Self {
        PolicyParams {
            weights: [250_000, 200_000, 200_000, 200_000, 100_000, 50_000],
            s: S,
            theta1_scaled: 250_000, // θ₁ = 0.25
            kappa: 1,
            bmax_scaled: 1_000_000, // bMax = 1.0
            policy_commitment: "a1b2c3d4e5f60718293a4b5c6d7e8f90".into(),
            action_commitment: "0f1e2d3c4b5a69788796a5b4c3d2e1f0".into(),
        }
    }

    /// θ₁·S² : the tier-1 bound in `r_raw` (scale S²) units. `r ≤ θ₁ ⟺ r_raw ≤ θ₁·S²`.
    fn t1_rraw(&self) -> u128 {
        self.theta1_scaled as u128 * self.s as u128
    }

    /// Convert the two hex commitments into a pair of field elements (truncated to the
    /// field order) purely for transcript binding.
    fn commitment_elems(&self) -> (BaseElement, BaseElement) {
        (hex_to_felt(&self.policy_commitment), hex_to_felt(&self.action_commitment))
    }

    /// The public inputs embedded in / checked against the proof.
    pub fn to_public(&self) -> PublicInputs {
        let (pc, ac) = self.commitment_elems();
        PublicInputs {
            weights: self.weights.map(|w| BaseElement::new(w as u128)),
            s: BaseElement::new(self.s as u128),
            t1_rraw: BaseElement::new(self.t1_rraw()),
            kappa: BaseElement::new(self.kappa as u128),
            bmax_scaled: BaseElement::new(self.bmax_scaled as u128),
            policy_commitment: pc,
            action_commitment: ac,
        }
    }
}

fn hex_to_felt(h: &str) -> BaseElement {
    // Parse up to 128 bits of hex, reduce mod field order (new() reduces).
    let mut acc: u128 = 0;
    for c in h.chars().filter(|c| c.is_ascii_hexdigit()).take(32) {
        acc = acc.wrapping_mul(16).wrapping_add(c.to_digit(16).unwrap() as u128);
    }
    BaseElement::new(acc)
}

/// Public inputs as field elements. Order here defines the Fiat–Shamir transcript binding.
#[derive(Clone, Debug)]
pub struct PublicInputs {
    pub weights: [BaseElement; 6],
    pub s: BaseElement,
    pub t1_rraw: BaseElement,
    pub kappa: BaseElement,
    pub bmax_scaled: BaseElement,
    pub policy_commitment: BaseElement,
    pub action_commitment: BaseElement,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut v = Vec::with_capacity(12);
        v.extend_from_slice(&self.weights);
        v.push(self.s);
        v.push(self.t1_rraw);
        v.push(self.kappa);
        v.push(self.bmax_scaled);
        v.push(self.policy_commitment);
        v.push(self.action_commitment);
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
/// This is the integer image of `riskScore` in `risk.ts`; dividing by S² recovers `r∈[0,1]`.
pub fn risk_raw(inputs: &[u64; 6], weights: &[u64; 6]) -> u128 {
    let mut acc: u128 = 0;
    for i in 0..6 {
        let x = inputs[i] as u128;
        let term = if INVERTED[i] { S as u128 - x } else { x };
        acc += weights[i] as u128 * term;
    }
    acc
}

// ---- the AIR --------------------------------------------------------------------------

pub struct ReleaseAir {
    context: AirContext<BaseElement>,
    weights: [BaseElement; 6],
    s: BaseElement,
    t1_rraw: BaseElement,
    kappa: BaseElement,
    bmax_scaled: BaseElement,
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

        // assertions: pow[0]=1, allow[0]=1, and acc_k[last]=0 for each range check
        let num_assertions = 2 + NUM_RC;

        ReleaseAir {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            weights: pub_inputs.weights,
            s: pub_inputs.s,
            t1_rraw: pub_inputs.t1_rraw,
            kappa: pub_inputs.kappa,
            bmax_scaled: pub_inputs.bmax_scaled,
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
    }

    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        let last = TRACE_LEN - 1;
        let mut a = Vec::with_capacity(2 + NUM_RC);
        a.push(Assertion::single(C_POW, 0, BaseElement::ONE)); // pow[0] = 2^0 = 1
        a.push(Assertion::single(C_ALLOW, 0, BaseElement::ONE)); // allow = 1 (the gate)
        for k in 0..NUM_RC {
            // residual decompositions all reach exactly 0 → each target is a valid
            // non-negative <2^63 bit sum (a deny witness cannot satisfy this).
            a.push(Assertion::single(rc_acc(k), last, BaseElement::ZERO));
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
    let trace = build_trace(witness, policy);
    let prover = ReleaseProver::new(proof_options(), policy.clone());
    prover.prove(trace)
}

/// Verify a release-gate STARK proof against the public `policy`. `Ok(())` ⟺ the gate
/// holds (allow == 1) for *some* witness, under exactly these public inputs.
pub fn verify_release(
    proof: Proof,
    policy: &PolicyParams,
) -> Result<(), winterfell::VerifierError> {
    let pub_inputs = policy.to_public();
    let min = winterfell::AcceptableOptions::MinConjecturedSecurity(MIN_SECURITY_BITS);
    winterfell::verify::<
        ReleaseAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &min)
}
