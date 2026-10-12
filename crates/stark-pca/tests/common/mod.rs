//! Shared harness for the soundness audit tests: a column-level trace builder over *field
//! elements* (so tests can build witnesses that no `u64` witness can express), a Winterfell prover
//! for arbitrary traces, and `MutAir`, an ablation wrapper around the real `ReleaseAir` that can
//! switch off individual transition constraints and boundary assertions.
//!
//! Nothing here re-implements the constraint system: `MutAir` calls the real
//! `ReleaseAir::evaluate_transition` / `get_assertions` and only zeroes the selected outputs.
#![allow(dead_code)]

use std::cell::RefCell;

use stark_pca::{
    proof_options, PolicyParams, PublicInputs, ReleaseAir, COMMIT_LIMBS, NUM_LANES, NUM_RC, S, TRACE_LEN, WIDTH,
};
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement as F, FieldElement, StarkField},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, PartitionOptions, Proof, ProofOptions, Prover, ProverError,
    StarkDomain, TraceInfo, TracePolyTable, TraceTable,
};

// ---- layout (mirrors the crate's private column map; cross-checked against `build_trace`) ----
pub const C_X: [usize; 6] = [0, 1, 2, 3, 4, 5];
pub const C_BS: usize = 6;
pub const C_RRAW: usize = 7;
pub const C_PM: usize = 8;
pub const C_CO: usize = 9;
pub const C_TG: usize = 10;
pub const C_BG: usize = 11;
pub const C_ALLOW: usize = 12;
pub const C_POW: usize = 13;
pub const RC_BASE: usize = 14;
pub const HASH_BASE: usize = RC_BASE + 2 * NUM_RC;
pub const fn rc_bit(k: usize) -> usize {
    RC_BASE + 2 * k
}
pub const fn rc_acc(k: usize) -> usize {
    RC_BASE + 2 * k + 1
}
pub const fn h_lane(j: usize) -> usize {
    HASH_BASE + j
}

// ---- transition-constraint index map (the order of `result[i]` in `evaluate_transition`) -------
pub const T_A: usize = 0; // 0..13  constant propagation of column c
pub const T_POW: usize = 13;
pub const T_RRAW: usize = 14;
pub const T_BOOL: usize = 15; // 15..19: pm, co, tgate, bgate
pub const T_ALLOW: usize = 19;
pub const T_RC: usize = 20; // 20 + 3k + {0: bit boolean, 1: residual recurrence, 2: init pin}
pub const T_HASH: usize = T_RC + 3 * NUM_RC; // 68..78 round recurrence per lane
pub const T_HINIT: usize = T_HASH + NUM_LANES; // 78..88 init pins (lane 0..8 = preimage, 9 = IV)
pub const NUM_TRANSITIONS: usize = T_HINIT + NUM_LANES; // 88
// ---- boundary-assertion index map --------------------------------------------------------------
pub const A_POW0: usize = 0;
pub const A_ALLOW0: usize = 1;
pub const A_ACC: usize = 2; // 2 + k : acc_k[last] == 0
pub const A_COMMIT: usize = 2 + NUM_RC; // 18 + m
pub const NUM_ASSERTIONS: usize = A_COMMIT + COMMIT_LIMBS; // 22

const CAP_IV: u64 = 0x5043_4162_6967_3031;
const RC_SEED: u64 = 0x00A1_B2C3_D4E5_F607;
const RC_STRIDE: u64 = 0x0000_1000_0000_01B3;
fn rc_k(k: usize) -> u64 {
    RC_SEED.wrapping_add((k as u64).wrapping_mul(RC_STRIDE))
}

pub fn f(v: u128) -> F {
    F::new(v)
}
/// `-v` in the field (a "negative" integer).
pub fn neg(v: u128) -> F {
    F::ZERO - F::new(v)
}

// ---- row-0 semantic assignment ------------------------------------------------------------------

/// The semantic assignment that lives on row 0 (and, in an honest trace, on every row).
#[derive(Clone, Debug)]
pub struct Row0 {
    pub x: [F; 6],
    pub bs: F,
    pub pm: F,
    pub co: F,
    pub tg: F,
    pub bg: F,
    /// `None` => derived honestly as Σ wᵢ·termᵢ in the field.
    pub rraw: Option<F>,
    /// `None` => derived honestly as pm·co·tg·bg.
    pub allow: Option<F>,
}

impl Row0 {
    pub fn from_u64(inputs: [u64; 6], b: u64, pm: bool, co: bool) -> Self {
        Row0 {
            x: inputs.map(|v| f(v as u128)),
            bs: f(b as u128),
            pm: if pm { F::ONE } else { F::ZERO },
            co: if co { F::ONE } else { F::ZERO },
            tg: F::ONE,
            bg: F::ONE,
            rraw: None,
            allow: None,
        }
    }
    pub fn compliant() -> Self {
        let w = stark_pca::Witness::compliant();
        Row0::from_u64(w.inputs, w.budget_scaled, w.predicate_match, w.caveats_ok)
    }
    pub fn preimage(&self) -> [F; 9] {
        [self.x[0], self.x[1], self.x[2], self.x[3], self.x[4], self.x[5], self.bs, self.pm, self.co]
    }
}

pub fn inverted(i: usize) -> bool {
    i == 1 || i == 4
}

/// Σ wᵢ·termᵢ in the field.
pub fn rraw_field(x: &[F; 6], w: &[u64; 6]) -> F {
    let mut acc = F::ZERO;
    for i in 0..6 {
        let term = if inverted(i) { f(S as u128) - x[i] } else { x[i] };
        acc += f(w[i] as u128) * term;
    }
    acc
}

/// Range-check targets 0..16 for a row-0 assignment under `policy`.
pub fn rc_targets(r: &Row0, rraw: F, p: &PolicyParams) -> [F; NUM_RC] {
    let s = f(p.s as u128);
    let t1 = f(p.theta1_scaled as u128 * p.s as u128);
    [
        r.x[0], s - r.x[0], r.x[1], s - r.x[1], r.x[2], s - r.x[2], r.x[3], s - r.x[3], r.x[4], s - r.x[4],
        r.x[5], s - r.x[5], r.bs, f(p.bmax_scaled as u128) - r.bs, t1 - rraw,
        s * r.bs - f(p.kappa as u128) * rraw,
    ]
}

/// The whole hash-state trace for an arbitrary 9-element preimage (same recurrence as the AIR).
pub fn hash_trace(pre: &[F; 9]) -> Vec<[F; NUM_LANES]> {
    hash_trace_with_pow(pre, &honest_pow())
}
pub fn honest_pow() -> Vec<F> {
    (0..TRACE_LEN).map(|r| f(1u128 << r)).collect()
}
pub fn hash_trace_with_pow(pre: &[F; 9], pow: &[F]) -> Vec<[F; NUM_LANES]> {
    let mut st = vec![[F::ZERO; NUM_LANES]; TRACE_LEN];
    st[0][..9].copy_from_slice(pre);
    st[0][9] = f(CAP_IV as u128);
    hash_continue(&mut st, 0, pow);
    st
}
/// Recompute rows `from+1..` from row `from` with the honest round function (round constant `pow[r]`).
pub fn hash_continue(st: &mut [[F; NUM_LANES]], from: usize, pow: &[F]) {
    for r in from..TRACE_LEN - 1 {
        let pow = pow[r];
        let mut a = [F::ZERO; NUM_LANES];
        let mut sum = F::ZERO;
        for k in 0..NUM_LANES {
            let t = st[r][k] + pow + f(rc_k(k) as u128);
            a[k] = t * t * t;
            sum += a[k];
        }
        for j in 0..NUM_LANES {
            st[r + 1][j] = sum + a[j];
        }
    }
}

pub type Cols = Vec<Vec<F>>;

/// Honest column builder over arbitrary field-element row-0 assignments (the same layout and
/// range-check bit extraction as `stark_pca::build_trace`).
pub fn build_cols(r: &Row0, p: &PolicyParams) -> Cols {
    build_cols_pow(r, p, &honest_pow())
}

/// As [`build_cols`] but with an arbitrary `pow` column (used by the pow-column attacks). Range-check
/// bits are the low 63 bits of the target (weights `2^r`); callers override cells that need the
/// custom weights.
pub fn build_cols_pow(r: &Row0, p: &PolicyParams, pow: &[F]) -> Cols {
    let rraw = r.rraw.unwrap_or_else(|| rraw_field(&r.x, &p.weights));
    let allow = r.allow.unwrap_or(r.pm * r.co * r.tg * r.bg);
    let mut cols: Cols = vec![vec![F::ZERO; TRACE_LEN]; WIDTH];
    let consts = [r.x[0], r.x[1], r.x[2], r.x[3], r.x[4], r.x[5], r.bs, rraw, r.pm, r.co, r.tg, r.bg, allow];
    for (c, &v) in consts.iter().enumerate() {
        cols[c] = vec![v; TRACE_LEN];
    }
    for row in 0..TRACE_LEN {
        cols[C_POW][row] = pow[row];
    }
    let targets = rc_targets(r, rraw, p);
    for k in 0..NUM_RC {
        let v = targets[k].as_int();
        let mut acc = targets[k];
        for row in 0..TRACE_LEN {
            cols[rc_acc(k)][row] = acc;
            let bit = if row < TRACE_LEN - 1 { (v >> row) & 1 } else { 0 };
            cols[rc_bit(k)][row] = f(bit);
            if row < TRACE_LEN - 1 {
                acc -= f(bit) * cols[C_POW][row];
            }
        }
    }
    let st = hash_trace_with_pow(&r.preimage(), pow);
    for row in 0..TRACE_LEN {
        for j in 0..NUM_LANES {
            cols[h_lane(j)][row] = st[row][j];
        }
    }
    cols
}

/// Set `policy.witness_commitment` to whatever the trace's final hash lanes hold.
pub fn commit_to_trace(cols: &Cols, p: &mut PolicyParams) {
    for m in 0..COMMIT_LIMBS {
        p.witness_commitment[m] = cols[h_lane(m)][TRACE_LEN - 1].as_int().to_string();
    }
}

/// A policy that is permissive enough to isolate single range checks (θ₁ = 0.6).
pub fn wide_policy() -> PolicyParams {
    let mut p = PolicyParams::default_policy();
    p.theta1_scaled = 600_000;
    p
}

// ---- semantic oracle ------------------------------------------------------------------------------

/// Does the row-0 assignment of `cols` satisfy the *intended* relation of the release gate under
/// `policy`? `Ok` means the claimed statement is true; `Err(clause)` names the first violated
/// clause. Independent of the AIR: it recomputes the relation with exact integer arithmetic.
pub fn statement_holds(cols: &Cols, p: &PolicyParams) -> Result<(), String> {
    let g = |c: usize| cols[c][0].as_int();
    let s = p.s as u128;
    let mut x = [0u128; 6];
    for i in 0..6 {
        x[i] = g(C_X[i]);
        if x[i] > s {
            return Err(format!("input {i} outside [0,S]"));
        }
    }
    let b = g(C_BS);
    if b > p.bmax_scaled as u128 {
        return Err("budget above bMax (or negative)".into());
    }
    let (pm, co) = (g(C_PM), g(C_CO));
    if pm != 1 {
        return Err("predicate_match is not 1".into());
    }
    if co != 1 {
        return Err("caveats_ok is not 1".into());
    }
    let mut rraw: u128 = 0;
    for i in 0..6 {
        let term = if inverted(i) { s - x[i] } else { x[i] };
        rraw += p.weights[i] as u128 * term;
    }
    if rraw > p.theta1_scaled as u128 * s {
        return Err("risk above theta1".into());
    }
    if b * s < p.kappa as u128 * rraw {
        return Err("budget below kappa*risk".into());
    }
    // witness <-> commitment binding: the claimed (row-0) witness must hash to the public value
    let pre = [cols[0][0], cols[1][0], cols[2][0], cols[3][0], cols[4][0], cols[5][0], cols[C_BS][0], cols[C_PM][0], cols[C_CO][0]];
    let st = hash_trace(&pre);
    for m in 0..COMMIT_LIMBS {
        if st[TRACE_LEN - 1][m].as_int().to_string() != p.witness_commitment[m] {
            return Err("claimed witness does not hash to the public witness_commitment".into());
        }
    }
    Ok(())
}

// ---- ablation wrapper ------------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct Ablation {
    /// Transition-constraint indices (see `T_*`) whose output is forced to zero.
    pub drop_transitions: Vec<usize>,
    /// Boundary assertions (index, replacement value) — the assertion is kept in place but pinned to
    /// the supplied value, i.e. made vacuous for the attacker trace.
    pub drop_assertions: Vec<(usize, F)>,
}

thread_local! { static ABL: RefCell<Ablation> = RefCell::new(Ablation::default()); }

pub fn with_ablation<R>(a: Ablation, run: impl FnOnce() -> R) -> R {
    ABL.with(|c| *c.borrow_mut() = a);
    let r = run();
    ABL.with(|c| *c.borrow_mut() = Ablation::default());
    r
}

pub struct MutAir {
    inner: ReleaseAir,
}

impl Air for MutAir {
    type BaseField = F;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        MutAir { inner: ReleaseAir::new(trace_info, pub_inputs, options) }
    }
    fn context(&self) -> &AirContext<F> {
        self.inner.context()
    }
    fn get_periodic_column_values(&self) -> Vec<Vec<F>> {
        self.inner.get_periodic_column_values()
    }
    fn evaluate_transition<E: FieldElement<BaseField = F>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic: &[E],
        result: &mut [E],
    ) {
        self.inner.evaluate_transition(frame, periodic, result);
        ABL.with(|c| {
            for &i in &c.borrow().drop_transitions {
                result[i] = E::ZERO;
            }
        });
    }
    fn get_assertions(&self) -> Vec<Assertion<F>> {
        let mut a = self.inner.get_assertions();
        ABL.with(|c| {
            for &(i, v) in &c.borrow().drop_assertions {
                a[i] = Assertion::single(a[i].column(), a[i].first_step(), v);
            }
        });
        a
    }
}

struct AttackProver {
    options: ProofOptions,
    policy: PolicyParams,
}

impl Prover for AttackProver {
    type BaseField = F;
    type Air = MutAir;
    type Trace = TraceTable<F>;
    type HashFn = Blake3_256<F>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = F>> = DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = F>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = F>> = DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PublicInputs {
        self.policy.to_public()
    }
    fn options(&self) -> &ProofOptions {
        &self.options
    }
    fn new_trace_lde<E: FieldElement<BaseField = F>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<F>,
        domain: &StarkDomain<F>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }
    fn build_constraint_commitment<E: FieldElement<BaseField = F>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<F>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(composition_poly_trace, num_constraint_composition_columns, domain, partition_options)
    }
    fn new_evaluator<'a, E: FieldElement<BaseField = F>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

/// Prove an arbitrary column set against `policy` under the *currently active* ablation (none by
/// default). A prover panic counts as "no proof".
pub fn prove_cols(cols: &Cols, policy: &PolicyParams) -> Option<Proof> {
    let (c, p) = (cols.clone(), policy.clone());
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let prover = AttackProver { options: proof_options(), policy: p };
        prover.prove(TraceTable::init(c)).ok()
    }))
    .unwrap_or(None)
}

/// Prove the honest columns with explicit (possibly weaker) proof options.
pub fn prove_cols_with_options(cols: &Cols, policy: &PolicyParams, options: ProofOptions) -> Option<Proof> {
    let (c, p) = (cols.clone(), policy.clone());
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        AttackProver { options, policy: p }.prove(TraceTable::init(c)).ok()
    }))
    .unwrap_or(None)
}

pub fn prover_error_free(cols: &Cols, policy: &PolicyParams) -> Result<Proof, ProverError> {
    let prover = AttackProver { options: proof_options(), policy: policy.clone() };
    prover.prove(TraceTable::init(cols.clone()))
}

/// Verify under the (possibly ablated) `MutAir`.
pub fn verify_mut(proof: Proof, policy: &PolicyParams) -> bool {
    let pub_inputs = match policy.try_to_public() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let min = winterfell::AcceptableOptions::MinConjecturedSecurity(stark_pca::MIN_SECURITY_BITS);
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        winterfell::verify::<MutAir, Blake3_256<F>, DefaultRandomCoin<Blake3_256<F>>, MerkleTree<Blake3_256<F>>>(
            proof, pub_inputs, &min,
        )
        .is_ok()
    }))
    .unwrap_or(false)
}

/// Does the *real* verifier (`verify_release`, un-ablated `ReleaseAir`) accept a proof for this
/// column set — the question an attacker actually cares about.
pub fn forged_proof_accepted_by_real_verifier(cols: &Cols, policy: &PolicyParams) -> bool {
    match with_ablation(Ablation::default(), || prove_cols(cols, policy)) {
        Some(proof) => stark_pca::verify_release(proof, policy).is_ok(),
        None => false,
    }
}

/// Prove+verify under an ablation. `true` iff the (ablated) system accepts the trace.
pub fn accepted_under(a: Ablation, cols: &Cols, policy: &PolicyParams) -> bool {
    with_ablation(a, || match prove_cols(cols, policy) {
        Some(proof) => verify_mut(proof, policy),
        None => false,
    })
}
