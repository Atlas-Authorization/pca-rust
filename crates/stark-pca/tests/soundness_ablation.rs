//! Constraint-ablation (mutation) audit of the release-gate AIR.
//!
//! For every transition constraint (88) and boundary assertion (22) of the real `ReleaseAir` this
//! file runs a *kill test*: a malicious trace is built that violates that constraint (and, as far
//! as the structure allows, only that one). Three facts are then established:
//!
//!   1. the **real** verifier rejects the malicious proof (the full constraint set kills the mutant);
//!   2. with the constraint **ablated** (the mutant: its output forced to zero) the same malicious
//!      trace proves and verifies, so the test is sensitive to exactly this constraint;
//!   3. an independent integer-arithmetic oracle (`statement_holds`) says whether the ablated
//!      system accepted a *false statement* (`Violating`: the constraint is necessary) or a
//!      statement that is nevertheless true (`Equivalent`: a semantically redundant constraint).
//!
//! A constraint for which no attack could be built under single ablation is reported `Rejected`
//! (implied by the others); every such case is asserted explicitly so the classification cannot
//! drift silently. Run: `cargo test --release --test soundness_ablation -- --nocapture`.

mod common;
use common::*;
use stark_pca::{PolicyParams, COMMIT_LIMBS, NUM_RC, TRACE_LEN};
use winterfell::math::{fields::f128::BaseElement as F, FieldElement, StarkField};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Out {
    /// The ablated system still rejects: the constraint is implied by the others for this attack.
    Rejected,
    /// The ablated system accepts, but the statement it certifies is true (semantically redundant).
    Equivalent,
    /// The ablated system accepts a FALSE statement: the constraint is necessary for soundness.
    Violating,
}

struct Case {
    name: String,
    expect: Out,
    abl: Ablation,
    cols: Cols,
    policy: PolicyParams,
}

fn tr(i: usize) -> Ablation {
    Ablation { drop_transitions: vec![i], drop_assertions: vec![] }
}
fn trs(v: &[usize]) -> Ablation {
    Ablation { drop_transitions: v.to_vec(), drop_assertions: vec![] }
}

/// Build columns for `row` under the wide policy, apply `colmod`, then commit the public
/// witness_commitment to whatever the final hash lanes hold.
fn make(
    name: &str,
    expect: Out,
    abl: Ablation,
    row: Row0,
    colmod: impl Fn(&mut Cols),
) -> Case {
    let mut policy = wide_policy();
    let mut cols = build_cols(&row, &policy);
    colmod(&mut cols);
    commit_to_trace(&cols, &mut policy);
    Case { name: name.into(), expect, abl, cols, policy }
}

fn observe(c: &Case) -> Out {
    // 1. the real verifier must kill every attack
    assert!(
        !forged_proof_accepted_by_real_verifier(&c.cols, &c.policy),
        "{}: the REAL verifier accepted a malicious trace",
        c.name
    );
    // 2/3. ablated system
    if !accepted_under(c.abl.clone(), &c.cols, &c.policy) {
        return Out::Rejected;
    }
    match statement_holds(&c.cols, &c.policy) {
        Ok(()) => Out::Equivalent,
        Err(_) => Out::Violating,
    }
}

fn set_row0_msg(r: &mut Row0, i: usize, v: F) {
    r.x[i] = v;
}

fn build_cases() -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();
    let s = stark_pca::S as u128;
    let last = TRACE_LEN - 1;

    // sanity: my column builder equals the crate's own trace builder on the honest witness
    {
        let p = PolicyParams::default_policy();
        let mine = build_cols(&Row0::compliant(), &p);
        let theirs = stark_pca::build_trace(&stark_pca::Witness::compliant(), &p);
        for c in 0..mine.len() {
            for r in 0..TRACE_LEN {
                assert_eq!(mine[c][r], theirs.get(c, r), "column builder drifted from build_trace at ({c},{r})");
            }
        }
        // and the honest trace is accepted by the real verifier
        let mut pp = p.clone();
        commit_to_trace(&mine, &mut pp);
        assert!(forged_proof_accepted_by_real_verifier(&mine, &pp), "honest trace must verify");
    }

    // ---- (A) constant propagation: tamper the LAST row of each constant column -------------------
    for c in 0..13 {
        cases.push(make(&format!("A[{c}] constant propagation (last-row tamper)"), Out::Equivalent, tr(T_A + c), Row0::compliant(), move |cols| {
            cols[c][last] += F::ONE;
        }));
    }
    // ---- (B) pow recurrence ----------------------------------------------------------------------
    cases.push(make("B pow doubling (last-row tamper)", Out::Equivalent, tr(T_POW), Row0::compliant(), |cols| {
        cols[C_POW][last] += F::ONE;
    }));
    // B: a non-doubling pow column lets a single bit carry an arbitrary field element (-m) for rc14
    {
        let mut row = Row0::from_u64([900_000, 100_000, 900_000, 900_000, 100_000, 900_000], 1_000_000, true, true);
        row.tg = F::ONE;
        let mut pow = honest_pow();
        let policy = wide_policy();
        let rraw = rraw_field(&row.x, &policy.weights);
        let target = rc_targets(&row, rraw, &policy)[14]; // negative: risk above theta1
        pow[62] = target;
        pow[63] = target + target;
        let mut cols = build_cols_pow(&row, &policy, &pow);
        for r in 0..TRACE_LEN {
            cols[rc_bit(14)][r] = if r == 62 { F::ONE } else { F::ZERO };
            cols[rc_acc(14)][r] = if r <= 62 { target } else { F::ZERO };
        }
        let mut p2 = policy.clone();
        commit_to_trace(&cols, &mut p2);
        cases.push(Case {
            name: "B pow doubling (pow[62] carries the over-threshold residual)".into(),
            expect: Out::Violating,
            abl: tr(T_POW),
            cols,
            policy: p2,
        });
    }
    // ---- A_POW0: pow[0] = 1 assertion (scale the whole pow column by 2; every target is even) ----
    {
        let row = Row0::compliant();
        let policy = wide_policy();
        let pow: Vec<F> = (0..TRACE_LEN).map(|r| f(1u128 << (r + 1))).collect();
        let mut cols = build_cols_pow(&row, &policy, &pow);
        let rraw = rraw_field(&row.x, &policy.weights);
        let targets = rc_targets(&row, rraw, &policy);
        for k in 0..NUM_RC {
            let t = targets[k].as_int();
            assert_eq!(t % 2, 0, "attack needs even targets");
            let mut acc = targets[k];
            for r in 0..TRACE_LEN {
                cols[rc_acc(k)][r] = acc;
                let bit = if r < TRACE_LEN - 1 { ((t / 2) >> r) & 1 } else { 0 };
                cols[rc_bit(k)][r] = f(bit);
                if r < TRACE_LEN - 1 {
                    acc -= f(bit) * pow[r];
                }
            }
        }
        let mut p2 = policy.clone();
        commit_to_trace(&cols, &mut p2);
        let v = cols[C_POW][0];
        cases.push(Case {
            name: "A_POW0 assertion pow[0]=1 (hash family / range weights rescaled)".into(),
            expect: Out::Violating,
            abl: Ablation { drop_transitions: vec![], drop_assertions: vec![(A_POW0, v)] },
            cols,
            policy: p2,
        });
    }
    // ---- (C) r_raw definition: understate the risk ------------------------------------------------
    {
        let mut row = Row0::from_u64([900_000, 100_000, 900_000, 900_000, 100_000, 900_000], 1_000_000, true, true);
        row.rraw = Some(F::ZERO);
        cases.push(make("C r_raw definition (risk understated)", Out::Violating, tr(T_RRAW), row, |_| {}));
    }
    // ---- (D) booleans ---------------------------------------------------------------------------
    let inv2 = F::new(2).inv();
    let nonbool = |pm: F, co: F, tg: F, bg: F| {
        let mut r = Row0::compliant();
        r.pm = pm;
        r.co = co;
        r.tg = tg;
        r.bg = bg;
        r
    };
    for (i, nm) in ["pm", "co", "tgate", "bgate"].iter().enumerate() {
        // single ablation of one boolean: the others still force it (product==1) => implied
        let row = match i {
            0 => nonbool(f(2), inv2, F::ONE, F::ONE),
            1 => nonbool(inv2, f(2), F::ONE, F::ONE),
            2 => nonbool(F::ONE, F::ONE, f(2), inv2),
            _ => nonbool(F::ONE, F::ONE, inv2, f(2)),
        };
        cases.push(make(&format!("D[{nm}] boolean, single ablation (implied by product==1 + the other booleans)"), Out::Rejected, tr(T_BOOL + i), row, |_| {}));
    }
    cases.push(make("D[pm,co] booleans ablated together", Out::Violating, trs(&[T_BOOL, T_BOOL + 1]), nonbool(f(2), inv2, F::ONE, F::ONE), |_| {}));
    cases.push(make("D[pm,tgate] booleans ablated together", Out::Violating, trs(&[T_BOOL, T_BOOL + 2]), nonbool(f(2), F::ONE, inv2, F::ONE), |_| {}));
    cases.push(make("D[tgate,bgate] booleans ablated together (tgate/bgate carry no statement)", Out::Equivalent, trs(&[T_BOOL + 2, T_BOOL + 3]), nonbool(F::ONE, F::ONE, f(2), inv2), |_| {}));
    // ---- (E) allow = pm*co*tg*bg ------------------------------------------------------------------
    {
        let mut r = Row0::compliant();
        r.pm = F::ZERO;
        r.allow = Some(F::ONE);
        cases.push(make("E allow product (predicate miss claimed as allow)", Out::Violating, tr(T_ALLOW), r, |_| {}));
        let mut r = Row0::compliant();
        r.co = F::ZERO;
        r.allow = Some(F::ONE);
        cases.push(make("E allow product (caveats unsatisfied claimed as allow)", Out::Violating, tr(T_ALLOW), r, |_| {}));
        let mut r = Row0::compliant();
        r.tg = F::ZERO;
        r.allow = Some(F::ONE);
        cases.push(make("E allow product (tgate=0 claimed as allow; tgate carries no statement)", Out::Equivalent, tr(T_ALLOW), r, |_| {}));
    }
    // ---- A_ALLOW0: allow[0]==1 ----------------------------------------------------------------------
    {
        let mut r = Row0::compliant();
        r.pm = F::ZERO; // honest deny: allow column = 0
        let mut c = make("A_ALLOW0 assertion allow==1 (deny witness, honest allow=0)", Out::Violating, Ablation::default(), r, |_| {});
        c.abl = Ablation { drop_transitions: vec![], drop_assertions: vec![(A_ALLOW0, F::ZERO)] };
        cases.push(c);
    }

    // ---- (F) the 16 range checks --------------------------------------------------------------------
    // For each check k, a witness violating ONLY that check, and four attacks (one per constraint class).
    let bad_row = |k: usize| -> Row0 {
        let mut r = Row0::compliant();
        match k {
            0 => set_row0_msg(&mut r, 0, neg(5)),
            1 => set_row0_msg(&mut r, 0, f(s + 1)),
            2 => set_row0_msg(&mut r, 1, neg(5)),
            3 => set_row0_msg(&mut r, 1, f(s + 1)),
            4 => set_row0_msg(&mut r, 2, neg(5)),
            5 => set_row0_msg(&mut r, 2, f(s + 1)),
            6 => set_row0_msg(&mut r, 3, neg(5)),
            7 => set_row0_msg(&mut r, 3, f(s + 1)),
            8 => set_row0_msg(&mut r, 4, neg(5)),
            9 => set_row0_msg(&mut r, 4, f(s + 1)),
            10 => set_row0_msg(&mut r, 5, neg(5)),
            11 => set_row0_msg(&mut r, 5, f(s + 1)),
            12 => r.bs = neg(5),
            13 => r.bs = f(1_000_001),
            14 => {
                r = Row0::from_u64([900_000, 100_000, 900_000, 900_000, 100_000, 900_000], 1_000_000, true, true);
            }
            15 => r.bs = F::ZERO,
            _ => unreachable!(),
        }
        r
    };
    for k in 0..NUM_RC {
        // k = 12 (B >= 0) is implied by check 15 (S*B - kappa*r_raw >= 0 with r_raw >= 0): every
        // attack must stay rejected even when ALL of check 12's own constraints are removed.
        let implied = k == 12;
        let expect = if implied { Out::Rejected } else { Out::Violating };
        // honest-bits trace: only the acc[last]==0 assertion fails
        {
            let row = bad_row(k);
            let policy = wide_policy();
            let cols = build_cols(&row, &policy);
            let mut p2 = policy.clone();
            commit_to_trace(&cols, &mut p2);
            let a = cols[rc_acc(k)][last];
            assert_ne!(a, F::ZERO, "violating target must leave a non-zero residual");
            cases.push(Case {
                name: format!("F{k} assertion acc[last]==0"),
                expect,
                abl: Ablation { drop_transitions: vec![], drop_assertions: vec![(A_ACC + k, a)] },
                cols,
                policy: p2,
            });
        }
        // boolean: one non-boolean "bit" carries the whole (field-wrapped) target
        cases.push(make(&format!("F{k} bit boolean"), expect, tr(T_RC + 3 * k), bad_row(k), move |cols| {
            let target = cols[rc_acc(k)][0];
            for r in 0..TRACE_LEN {
                cols[rc_bit(k)][r] = if r == 0 { target } else { F::ZERO };
                cols[rc_acc(k)][r] = if r == 0 { target } else { F::ZERO };
            }
        }));
        // residual recurrence: jump the accumulator to 0 on the last transition
        cases.push(make(&format!("F{k} residual recurrence"), expect, tr(T_RC + 3 * k + 1), bad_row(k), move |cols| {
            let target = cols[rc_acc(k)][0];
            for r in 0..TRACE_LEN {
                cols[rc_bit(k)][r] = F::ZERO;
                cols[rc_acc(k)][r] = if r < TRACE_LEN - 1 { target } else { F::ZERO };
            }
        }));
        // init pin: start the accumulator at 0 instead of the target
        cases.push(make(&format!("F{k} init pin acc[0]==target"), expect, tr(T_RC + 3 * k + 2), bad_row(k), move |cols| {
            for r in 0..TRACE_LEN {
                cols[rc_bit(k)][r] = F::ZERO;
                cols[rc_acc(k)][r] = F::ZERO;
            }
        }));
        if implied {
            // remove the WHOLE of check 12 at once; still rejected because check 15 survives
            let mut all = vec![T_RC + 3 * k, T_RC + 3 * k + 1, T_RC + 3 * k + 2];
            all.sort();
            let mut c = make("F12 ALL constraints of check 12 removed (still implied by F15)", Out::Rejected, trs(&all), bad_row(12), move |cols| {
                for r in 0..TRACE_LEN {
                    cols[rc_bit(12)][r] = F::ZERO;
                    cols[rc_acc(12)][r] = F::ZERO;
                }
            });
            let a = Ablation { drop_transitions: all, drop_assertions: vec![(A_ACC + 12, F::ZERO)] };
            c.abl = a;
            cases.push(c);
        }
    }

    // ---- (G) hash round recurrence ----------------------------------------------------------------------
    for j in 0..10 {
        // tamper lane j on the last row only (violates exactly G_j at the 62->63 step)
        let expect = if j < COMMIT_LIMBS { Out::Violating } else { Out::Equivalent };
        cases.push(make(&format!("G[{j}] hash round, last-row tamper of lane {j}"), expect, tr(T_HASH + j), Row0::compliant(), move |cols| {
            cols[h_lane(j)][last] += F::ONE;
        }));
    }
    {
        // the whole hash round removed: lanes 0..3 on the last row set to the commitment of ANOTHER
        // action while the gate is proven for the compliant one.
        let mut other = Row0::compliant();
        other.pm = F::ZERO;
        let other_hash = hash_trace(&other.preimage());
        let all: Vec<usize> = (0..10).map(|j| T_HASH + j).collect();
        cases.push(make("G[all] hash round removed (commitment of a different action)", Out::Violating, trs(&all), Row0::compliant(), move |cols| {
            for m in 0..COMMIT_LIMBS {
                cols[h_lane(m)][last] = other_hash[last][m];
            }
        }));
    }
    // ---- (H) hash init pins ------------------------------------------------------------------------------
    for j in 0..10 {
        // start the hash from a state that differs from the witness columns in lane j only
        cases.push(make(&format!("H[{j}] hash init pin lane {j}"), Out::Violating, tr(T_HINIT + j), Row0::compliant(), move |cols| {
            let mut st = hash_trace(&Row0::compliant().preimage());
            st[0][j] += F::ONE;
            hash_continue(&mut st, 0, &honest_pow());
            for r in 0..TRACE_LEN {
                for l in 0..10 {
                    cols[h_lane(l)][r] = st[r][l];
                }
            }
        }));
    }
    // ---- squeeze assertions: public witness_commitment limb m ----------------------------------------------
    for m in 0..COMMIT_LIMBS {
        let row = Row0::compliant();
        let policy = wide_policy();
        let cols = build_cols(&row, &policy);
        let mut p2 = policy.clone();
        // limb m of the verifier's commitment is that of a DIFFERENT action
        let mut other = Row0::compliant();
        other.pm = F::ZERO;
        let oh = hash_trace(&other.preimage());
        commit_to_trace(&cols, &mut p2);
        // only limb m differs from the trace's own commitment, so ablating assertion m isolates it
        p2.witness_commitment[m] = oh[last][m].as_int().to_string();
        let actual = cols[h_lane(m)][last];
        cases.push(Case {
            name: format!("A_COMMIT[{m}] assertion lane {m} == public witness_commitment[{m}]"),
            expect: Out::Violating,
            abl: Ablation { drop_transitions: vec![], drop_assertions: vec![(A_COMMIT + m, actual)] },
            cols,
            policy: p2,
        });
    }
    cases
}

#[test]
fn every_constraint_is_killed_or_classified() {
    let cases = build_cases();
    let mut tally = [0usize; 3];
    let mut mismatches = Vec::new();
    let mut covered_tr = vec![false; NUM_TRANSITIONS];
    let mut covered_as = vec![false; NUM_ASSERTIONS];
    for c in &cases {
        for &t in &c.abl.drop_transitions {
            covered_tr[t] = true;
        }
        for &(a, _) in &c.abl.drop_assertions {
            covered_as[a] = true;
        }
        let got = observe(c);
        eprintln!("{:<92} expected {:?} observed {:?}", c.name, c.expect, got);
        tally[got as usize] += 1;
        if got != c.expect {
            mismatches.push(format!("{}: expected {:?}, observed {:?}", c.name, c.expect, got));
        }
    }
    eprintln!(
        "cases={} rejected(implied)={} equivalent(redundant)={} violating(necessary)={} transitions covered {}/{} assertions covered {}/{}",
        cases.len(),
        tally[Out::Rejected as usize],
        tally[Out::Equivalent as usize],
        tally[Out::Violating as usize],
        covered_tr.iter().filter(|b| **b).count(),
        NUM_TRANSITIONS,
        covered_as.iter().filter(|b| **b).count(),
        NUM_ASSERTIONS
    );
    assert!(mismatches.is_empty(), "classification drifted:\n{}", mismatches.join("\n"));
    // every one of the 88 transition constraints and 22 assertions was ablated at least once
    assert!(covered_tr.iter().all(|b| *b), "uncovered transition constraints: {:?}", covered_tr.iter().enumerate().filter(|(_, b)| !**b).map(|(i, _)| i).collect::<Vec<_>>());
    assert!(covered_as.iter().all(|b| *b), "uncovered assertions");
}
