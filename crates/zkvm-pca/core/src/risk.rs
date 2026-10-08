//! Fixed-point risk functional + threshold ladder + budget-admission cost gate.
//!
//! A faithful integer image of `packages/pca/src/risk.ts` at scale `S = 1e6` (identical to the
//! stark-pca Winterfell AIR and the Groth16 Policy-VM circuit). Floating point is NEVER used in the
//! proven path — all quantities are integers at scale S, so the computation is deterministic and
//! reproducible by any verifier (the fixed-point / quantized-integer invariant).
//!
//!   r_raw = Σ wᵢ·termᵢ            (scale S², termᵢ = xᵢ or S−xᵢ for the inverted inputs rev/conf)
//!   r     = clamp(r_raw / S², 0, 1)
//!   tier:  r ≤ θ₁ → 1 ;  r ≤ θ₂ → 2 ;  else 3     (requiredThreshold)
//!   cost gate (admit):  B ≥ κ·r   ⟺   B_scaled·S ≥ κ·r_raw
//!
//! The optional monotone risk floor (`rFloor`, the signed caution) can only RAISE r, never lower it.

pub const S: u64 = 1_000_000;

/// rev (index 1) and conf (index 4) enter as (S − x).
const INVERTED: [bool; 6] = [false, true, false, false, true, false];

/// The 6 risk inputs at scale S, each clamped into [0, S].
#[derive(Clone, Copy, Debug)]
pub struct RiskInputsScaled {
    /// [semanticDistance, reversibility, blastRadius, taint, confidence, age]
    pub x: [u64; 6],
}

/// The policy parameters, all at scale S (except kappa, an integer cost scale).
#[derive(Clone, Copy, Debug)]
pub struct RiskPolicyScaled {
    pub weights: [u64; 6],
    pub theta1_scaled: u64,
    pub theta2_scaled: u64,
    pub kappa: u64,
    pub bmax_scaled: u64,
}

/// r_raw at scale S² (clamped to S² so r ≤ 1.0), with the monotone caution floor applied.
pub fn risk_raw(inputs: &RiskInputsScaled, p: &RiskPolicyScaled, r_floor_scaled: u64) -> u128 {
    let mut acc: u128 = 0;
    for i in 0..6 {
        let xi = inputs.x[i].min(S) as u128;
        let term = if INVERTED[i] { (S as u128) - xi } else { xi };
        acc += (p.weights[i] as u128) * term;
    }
    // clamp to S² (r ≤ 1.0)
    let s2 = (S as u128) * (S as u128);
    if acc > s2 {
        acc = s2;
    }
    // monotone floor: r = max(computed, rFloor). rFloor is at scale S, so its raw form is floor·S.
    let floor_raw = (r_floor_scaled.min(S) as u128) * (S as u128);
    acc.max(floor_raw)
}

/// Threshold tier (1/2/3), faithful to `requiredThreshold`.
pub fn tier(r_raw: u128, p: &RiskPolicyScaled) -> u8 {
    let t1 = (p.theta1_scaled as u128) * (S as u128);
    let t2 = (p.theta2_scaled as u128) * (S as u128);
    if r_raw <= t1 {
        1
    } else if r_raw <= t2 {
        2
    } else {
        3
    }
}

/// Budget covers the metered cost: B ≥ κ·r ⟺ B_scaled·S ≥ κ·r_raw.
pub fn budget_covers(budget_scaled: u64, r_raw: u128, p: &RiskPolicyScaled) -> bool {
    let lhs = (budget_scaled as u128) * (S as u128);
    let rhs = (p.kappa as u128) * r_raw;
    lhs >= rhs
}

/// The machine-only auto-admit gate: tier == 1 AND the budget covers the cost.
pub fn auto_admit(r_raw: u128, budget_scaled: u64, p: &RiskPolicyScaled) -> bool {
    tier(r_raw, p) == 1 && budget_covers(budget_scaled, r_raw, p)
}
