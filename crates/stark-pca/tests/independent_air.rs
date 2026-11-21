//! Second, independent implementation of the release-gate constraint system, and a constraint-completeness sweep.
//!
//! `ReleaseAir` (the Winterfell AIR) is the only place the constraints are written in the crate. This file
//! transcribes them a second time from the statement in the README ("What the AIR proves"), in plain modular
//! integer arithmetic with no Winterfell types and no shared helper from `src/lib.rs`: the field is `u128`
//! arithmetic mod `2^128 - 45*2^40 + 1`, the multiplication is a textbook double-and-add. It is used for three checks.
//!
//! 1. `field_arithmetic_...`: the hand-written field agrees with the library field.
//! 2. `second_evaluator_matches_the_library_constraints_element_for_element`: on honest traces and on single-cell
//!    perturbations of them, all 88 transition values per frame equal `ReleaseAir::evaluate_transition`'s.
//! 3. `no_cell_can_be_changed_to_certify_a_false_statement`: every cell of the 56 x 64 trace is perturbed (five ways) and
//!    the second evaluator plus the boundary assertions are applied. A perturbed trace may be accepted only if the
//!    intended statement still holds (exact integer oracle `statement_holds`); the only cells that can change at all
//!    without breaking a constraint are the 16 range-check bit cells of the last row, which no transition reads
//!    (a transition reads `cur`, and the last row is never `cur`). That set is pinned.
//!
//! Run: `cargo test --release --test independent_air`.

mod common;
use common::*;
use stark_pca::{proof_options, PolicyParams, ReleaseAir, COMMIT_LIMBS, NUM_LANES, NUM_RC, TRACE_LEN, WIDTH};
use winterfell::math::{fields::f128::BaseElement as F, FieldElement, StarkField};
use winterfell::{Air, EvaluationFrame, TraceInfo};

// ---- the independent field: u128 mod p, p = 2^128 - 45 * 2^40 + 1 ------------------------------------------

fn modulus() -> u128 {
    0u128.wrapping_sub(45u128 << 40).wrapping_add(1)
}
fn addmod(a: u128, b: u128) -> u128 {
    let p = modulus();
    let (s, over) = a.overflowing_add(b);
    // on overflow the true sum is s + 2^128, and s.wrapping_sub(p) = s + 2^128 - p (mod 2^128) is that value minus p
    if over || s >= p {
        s.wrapping_sub(p)
    } else {
        s
    }
}
fn submod(a: u128, b: u128) -> u128 {
    if a >= b {
        a - b
    } else {
        modulus() - (b - a)
    }
}
fn mulmod(mut a: u128, mut b: u128) -> u128 {
    let mut acc = 0u128;
    while b > 0 {
        if b & 1 == 1 {
            acc = addmod(acc, a);
        }
        a = addmod(a, a);
        b >>= 1;
    }
    acc
}

// ---- the independent constraint system -----------------------------------------------------------------------
// Column map (README): 0..6 the six risk inputs d, rev, bl, taint, conf, age; 6 budget; 7 r_raw; 8 pm; 9 co;
// 10 tier-1 gate; 11 budget gate; 12 allow; 13 pow; then 16 (bit, residual) pairs; then 10 hash lanes.

const RC0: usize = 14;
const H0: usize = RC0 + 2 * 16; // 46
const _: () = assert!(NUM_TRANSITIONS == 88);
const CAP_IV: u128 = 0x5043_4162_6967_3031;

fn lane_constant(k: usize) -> u128 {
    (0x00A1_B2C3_D4E5_F607u64.wrapping_add((k as u64).wrapping_mul(0x0000_1000_0000_01B3u64))) as u128
}

/// The 88 transition values for the frame (`cur`, `nxt`); `first` is the step-0 periodic selector.
fn indep_transitions(cur: &[u128], nxt: &[u128], first: bool, p: &PolicyParams) -> Vec<u128> {
    let s = p.s as u128;
    let sel = if first { 1u128 } else { 0 };
    let mut out = Vec::with_capacity(NUM_TRANSITIONS);
    // columns 0..=12 never change from row to row
    for c in 0..13 {
        out.push(submod(nxt[c], cur[c]));
    }
    // pow doubles
    out.push(submod(nxt[13], addmod(cur[13], cur[13])));
    // r_raw = sum w_i * term_i, with (S - x) for reversibility and confidence
    let mut rraw = 0u128;
    for i in 0..6 {
        let term = if i == 1 || i == 4 { submod(s, cur[i]) } else { cur[i] };
        rraw = addmod(rraw, mulmod(p.weights[i] as u128, term));
    }
    out.push(submod(cur[7], rraw));
    // pm, co, tier gate, budget gate are bits
    for c in [8usize, 9, 10, 11] {
        out.push(mulmod(cur[c], submod(cur[c], 1)));
    }
    // allow is the product of the four
    out.push(submod(cur[12], mulmod(mulmod(cur[8], cur[9]), mulmod(cur[10], cur[11]))));
    // sixteen non-negativity decompositions
    let t1 = p.theta1_scaled as u128 * s;
    for k in 0..NUM_RC {
        let bit = cur[RC0 + 2 * k];
        let acc = cur[RC0 + 2 * k + 1];
        let acc_next = nxt[RC0 + 2 * k + 1];
        let target = match k {
            0 => cur[0],
            1 => submod(s, cur[0]),
            2 => cur[1],
            3 => submod(s, cur[1]),
            4 => cur[2],
            5 => submod(s, cur[2]),
            6 => cur[3],
            7 => submod(s, cur[3]),
            8 => cur[4],
            9 => submod(s, cur[4]),
            10 => cur[5],
            11 => submod(s, cur[5]),
            12 => cur[6],
            13 => submod(p.bmax_scaled as u128, cur[6]),
            14 => submod(t1, cur[7]),
            15 => submod(mulmod(s, cur[6]), mulmod(p.kappa as u128, cur[7])),
            _ => unreachable!(),
        };
        out.push(mulmod(bit, submod(bit, 1)));
        out.push(submod(acc_next, submod(acc, mulmod(bit, cur[13]))));
        out.push(mulmod(sel, submod(acc, target)));
    }
    // hash round: a_k = (H_k + pow + RC_k)^3, H'_j = (sum_k a_k) + a_j
    let mut a = [0u128; NUM_LANES];
    let mut sum = 0u128;
    for k in 0..NUM_LANES {
        let t = addmod(addmod(cur[H0 + k], cur[13]), lane_constant(k));
        a[k] = mulmod(mulmod(t, t), t);
        sum = addmod(sum, a[k]);
    }
    for j in 0..NUM_LANES {
        out.push(submod(nxt[H0 + j], addmod(sum, a[j])));
    }
    // hash initial state (row 0 only): the nine witness columns, then the capacity constant
    for j in 0..9 {
        // lanes 0..5 absorb the six inputs (columns 0..5), lane 6 the budget (column 6), lanes 7 and 8 pm and co (columns 8, 9)
        let want = if j < 7 { cur[j] } else { cur[j + 1] };
        out.push(mulmod(sel, submod(cur[H0 + j], want)));
    }
    out.push(mulmod(sel, submod(cur[H0 + 9], CAP_IV)));
    assert_eq!(out.len(), NUM_TRANSITIONS);
    out
}

fn row(cols: &Cols, r: usize) -> Vec<u128> {
    (0..WIDTH).map(|c| cols[c][r].as_int()).collect()
}

/// Boundary assertions: pow[0] = 1, allow[0] = 1, every residual ends at 0, hash lanes end at the public commitment.
fn indep_boundary_ok(cols: &Cols, p: &PolicyParams) -> bool {
    let last = TRACE_LEN - 1;
    cols[13][0].as_int() == 1
        && cols[12][0].as_int() == 1
        && (0..NUM_RC).all(|k| cols[RC0 + 2 * k + 1][last].as_int() == 0)
        && (0..COMMIT_LIMBS).all(|m| cols[H0 + m][last].as_int().to_string() == p.witness_commitment[m])
}

/// Do frames `lo..=hi` (clamped to 0..=62) satisfy every transition constraint?
fn frames_ok(cols: &Cols, lo: usize, hi: usize, p: &PolicyParams) -> bool {
    (lo..=hi.min(TRACE_LEN - 2)).all(|r| indep_transitions(&row(cols, r), &row(cols, r + 1), r == 0, p).iter().all(|&v| v == 0))
}

fn indep_accepts(cols: &Cols, p: &PolicyParams) -> bool {
    indep_boundary_ok(cols, p) && frames_ok(cols, 0, TRACE_LEN - 2, p)
}

// ---- traces ----------------------------------------------------------------------------------------------------

fn base_traces() -> Vec<(&'static str, Cols, PolicyParams)> {
    let mut v = Vec::new();
    for (name, row0) in [
        ("compliant", Row0::compliant()),
        ("all-extremes", Row0::from_u64([0, 1_000_000, 0, 0, 1_000_000, 0], 0, true, true)),
    ] {
        let mut policy = PolicyParams::default_policy();
        let cols = build_cols(&row0, &policy);
        commit_to_trace(&cols, &mut policy);
        v.push((name, cols, policy));
    }
    v
}

/// A tiny deterministic generator (the test needs reproducibility, not quality).
fn lcg(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *state >> 11
}

#[test]
fn field_arithmetic_agrees_with_the_library_field() {
    assert_eq!(modulus(), F::MODULUS);
    let mut st = 7u64;
    for _ in 0..2000 {
        let a = ((lcg(&mut st) as u128) << 64 | lcg(&mut st) as u128) % modulus();
        let b = ((lcg(&mut st) as u128) << 64 | lcg(&mut st) as u128) % modulus();
        assert_eq!(addmod(a, b), (F::new(a) + F::new(b)).as_int(), "add");
        assert_eq!(submod(a, b), (F::new(a) - F::new(b)).as_int(), "sub");
        assert_eq!(mulmod(a, b), (F::new(a) * F::new(b)).as_int(), "mul");
    }
    // the corners that overflow a u128 addition
    let top = modulus() - 1;
    assert_eq!(addmod(top, top), (F::new(top) + F::new(top)).as_int());
    assert_eq!(mulmod(top, top), 1);
}

#[test]
fn second_evaluator_matches_the_library_constraints_element_for_element() {
    for (name, cols, policy) in base_traces() {
        let air = ReleaseAir::new(TraceInfo::new(WIDTH, TRACE_LEN), policy.to_public(), proof_options());
        let lib = |cols: &Cols, r: usize| -> Vec<u128> {
            let cur: Vec<F> = (0..WIDTH).map(|c| cols[c][r]).collect();
            let nxt: Vec<F> = (0..WIDTH).map(|c| cols[c][r + 1]).collect();
            let frame = EvaluationFrame::from_rows(cur, nxt);
            let mut res = vec![F::ZERO; NUM_TRANSITIONS];
            air.evaluate_transition(&frame, &[if r == 0 { F::ONE } else { F::ZERO }], &mut res);
            res.iter().map(|v| v.as_int()).collect()
        };
        // the honest trace: every frame, every value
        for r in 0..TRACE_LEN - 1 {
            let mine = indep_transitions(&row(&cols, r), &row(&cols, r + 1), r == 0, &policy);
            assert_eq!(mine, lib(&cols, r), "{name}: frame {r} differs on the honest trace");
            assert!(mine.iter().all(|&v| v == 0), "{name}: honest frame {r} is not satisfied");
        }
        assert!(indep_accepts(&cols, &policy), "{name}: the second evaluator rejects the honest trace");
        // 300 perturbed traces, each compared on both frames the changed cell touches
        let mut st = 99u64;
        for n in 0..300 {
            let (c, r) = ((lcg(&mut st) as usize) % WIDTH, (lcg(&mut st) as usize) % TRACE_LEN);
            let mut bad = cols.clone();
            bad[c][r] = F::new(((lcg(&mut st) as u128) << 64 | lcg(&mut st) as u128) % modulus());
            for fr in [r.wrapping_sub(1), r] {
                if fr > TRACE_LEN - 2 {
                    continue;
                }
                let mine = indep_transitions(&row(&bad, fr), &row(&bad, fr + 1), fr == 0, &policy);
                assert_eq!(mine, lib(&bad, fr), "{name}: perturbation {n} (col {c}, row {r}) frame {fr} differs");
            }
        }
    }
}

#[test]
fn no_cell_can_be_changed_to_certify_a_false_statement() {
    for (name, cols, policy) in base_traces() {
        assert!(indep_accepts(&cols, &policy) && statement_holds(&cols, &policy).is_ok(), "{name}: honest base");
        let s = policy.s as u128;
        let variants: [F; 5] = [F::ONE, neg(1), F::ZERO, f(s), neg(2)];
        let mut accepted_changed: Vec<(usize, usize)> = Vec::new();
        let mut rejected = 0usize;
        for c in 0..WIDTH {
            for r in 0..TRACE_LEN {
                for (vi, v) in variants.iter().enumerate() {
                    let orig = cols[c][r];
                    let new = if vi < 2 { if vi == 0 { orig + F::ONE } else { orig - F::ONE } } else { *v };
                    if new == orig {
                        continue; // not a change
                    }
                    let mut bad = cols.clone();
                    bad[c][r] = new;
                    // only the frames that read (c, r) can change: r - 1 (as `next`) and r (as `cur`); the boundary checks read the rest
                    let ok = indep_boundary_ok(&bad, &policy) && frames_ok(&bad, r.saturating_sub(1), r, &policy);
                    if ok {
                        // an accepted perturbation must still be a true statement; and it must be a pinned free cell
                        assert!(statement_holds(&bad, &policy).is_ok(), "{name}: cell (col {c}, row {r}) -> {:?} certifies a FALSE statement", new);
                        accepted_changed.push((c, r));
                    } else {
                        rejected += 1;
                    }
                }
            }
        }
        accepted_changed.sort();
        accepted_changed.dedup();
        let expected: Vec<(usize, usize)> = (0..NUM_RC).map(|k| (RC0 + 2 * k, TRACE_LEN - 1)).collect();
        for cell in &accepted_changed {
            assert!(expected.contains(cell), "{name}: unexpected unconstrained cell {:?}", cell);
        }
        assert!(rejected > WIDTH * TRACE_LEN * 4, "{name}: only {rejected} perturbations were rejected");
    }
}
