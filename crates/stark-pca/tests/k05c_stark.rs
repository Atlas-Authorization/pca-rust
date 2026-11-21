//! 0.5 mutation kills (batch 2) for stark-pca `src/lib.rs`. Each test names the survivors it kills.
//! `build_trace` and `compute_witness_commitment` are the only entry points used; no proving, so each test is cheap.
mod common;
use common::{h_lane, rc_bit, C_ALLOW, C_CO, C_PM};
use stark_pca::{build_trace, compute_witness_commitment, PolicyParams, Witness, NUM_RC, TRACE_LEN};
use winterfell::math::{fields::f128::BaseElement as F, FieldElement};

fn flags(pm: bool, co: bool) -> Witness {
    let mut w = Witness::compliant();
    w.predicate_match = pm;
    w.caveats_ok = co;
    w
}

fn bit(b: bool) -> F {
    if b {
        F::ONE
    } else {
        F::ZERO
    }
}

/// lib.rs:641 / :642 `replace if condition with true in build_trace` (pm / co) and lib.rs:387 / :388 `... in witness_preimage`:
/// the pm / co columns, the allow column and hash lanes 7 / 8 at step 0 (which the AIR pins equal to the pm / co columns)
/// must carry the witness flag itself, for all four flag combinations.
#[test]
fn gate_columns_and_hash_preimage_carry_the_witness_flags() {
    let p = PolicyParams::default_policy();
    for (pm, co) in [(true, true), (true, false), (false, true), (false, false)] {
        let t = build_trace(&flags(pm, co), &p);
        for row in [0, TRACE_LEN - 1] {
            assert_eq!(t.get(C_PM, row), bit(pm), "pm column pm={pm} co={co} row {row}");
            assert_eq!(t.get(C_CO, row), bit(co), "co column pm={pm} co={co} row {row}");
            assert_eq!(t.get(C_ALLOW, row), bit(pm && co), "allow column pm={pm} co={co} row {row}");
        }
        assert_eq!(t.get(h_lane(7), 0), bit(pm), "hash lane 7 absorbs pm (pm={pm} co={co})");
        assert_eq!(t.get(h_lane(8), 0), bit(co), "hash lane 8 absorbs co (pm={pm} co={co})");
    }
}

/// lib.rs:387 / :388 `replace if condition with true in witness_preimage`: the public witness commitment must depend on
/// both flags (a forced-true flag makes a deny witness share the commitment of the allow witness).
#[test]
fn witness_commitment_binds_both_flags() {
    let base = compute_witness_commitment(&flags(true, true));
    let no_pm = compute_witness_commitment(&flags(false, true));
    let no_co = compute_witness_commitment(&flags(true, false));
    assert_ne!(no_pm, base, "pm is part of the committed preimage");
    assert_ne!(no_co, base, "co is part of the committed preimage");
    assert_ne!(no_pm, no_co);
    assert_ne!(compute_witness_commitment(&flags(false, false)), no_pm);
}

/// lib.rs:670 `replace < with <=`, `replace - with +`, `replace - with /` in build_trace (bit row bound): bits 0..=62 take part in
/// the residual, the last row carries 0 whatever the target is. u64::MAX makes target 0 = 2^64 - 1, whose bit 63 is 1.
#[test]
fn range_check_bit_columns_are_zero_on_the_last_row() {
    let p = PolicyParams::default_policy();
    let mut w = Witness::compliant();
    w.inputs[0] = u64::MAX;
    let t = build_trace(&w, &p);
    // control: bits 0 and 62 of 2^64 - 1 are written
    assert_eq!(t.get(rc_bit(0), 0), F::ONE);
    assert_eq!(t.get(rc_bit(0), TRACE_LEN - 2), F::ONE);
    for k in 0..NUM_RC {
        assert_eq!(t.get(rc_bit(k), TRACE_LEN - 1), F::ZERO, "range check {k}: last-row bit");
    }
}
