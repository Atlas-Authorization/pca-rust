//! k05 differential oracle for the optimistic path: tests/data/k05-optimistic.json.gz, written by the TypeScript reference
//! (tools/pca-audit/k05-oracles/optimistic-oracle.mts; the Java, Kotlin, Python, Go, ... suites replay the same file): the check
//! string of claimCheck, fraudProofWireCheck and settlementWireCheck. A number argument that is not a JSON number is NaN (JS
//! `Number(undefined)`), a key that is not a string is "" (no key matches it).
use super::*;
use crate::k042_support::{k05_run, K05};
use serde_json::json;

fn num(v: &Value) -> f64 {
    v.as_f64().unwrap_or(f64::NAN)
}

#[test]
fn k05_optimistic_matches_the_reference() {
    // 4029 cases, ~125 skipped for lone surrogates
    k05_run("optimistic", 3500, |_, f, a| match f {
        "claimCheck" => {
            let p = &a[4];
            let pol = WindowPolicy { min_window_ms: num(&p["minWindowMs"]), max_window_ms: num(&p["maxWindowMs"]), max_skew_ms: num(&p["maxSkewMs"]) };
            K05::Val(json!(claim_check(&a[0], a[1].as_str().unwrap_or(""), a[2].as_str().unwrap_or(""), num(&a[3]), &pol)))
        }
        "fraudProofWireCheck" => K05::Val(json!(fraud_proof_wire_check(&a[0], &a[1]))),
        "settlementWireCheck" => K05::Val(json!(settlement_wire_check(&a[0], a[1].as_str().unwrap_or("")))),
        _ => K05::Skip("fn not in this module"),
    });
}

// ---- wire clauses alone (optimistic.ts, bond-settlement.ts settlementWireCheck) ----

#[test]
fn js_eq_compares_numbers_by_value() {
    assert!(js_eq(Some(&json!(1)), Some(&json!(1.0))));
    assert!(!js_eq(Some(&json!(1)), Some(&json!(2.0))));
}

#[test]
fn an_array_claim_is_an_object_with_no_fields() {
    let pol = WindowPolicy { min_window_ms: 0.0, max_window_ms: 1.0, max_skew_ms: 1.0 };
    assert_eq!(claim_check(&json!([]), "d", "k", 0.0, &pol), "digest");
    assert_eq!(claim_check(&json!(5), "d", "k", 0.0, &pol), "malformed");
}

#[test]
fn understated_risk_must_exceed_the_margin() {
    let claim = json!({"pcactn_digest": "d", "bond_ref": "b", "claimed_r": 1.0});
    let proof = |r: f64| json!({"pcactn_digest": "d", "bond_ref": "b", "claimed_r": 1.0, "reason": "x", "kind": "risk-understated", "r_margin": 0.5, "decision": {"releaseGuardianShare": true, "optimisticAllowed": true, "r": r}});
    assert_eq!(fraud_proof_wire_check(&claim, &proof(1.5)), "consistency");
    assert_eq!(fraud_proof_wire_check(&claim, &proof(1.75)), "ok");
}

#[test]
fn an_anonymous_split_pays_the_treasury_everything() {
    // the signature is bad throughout, so "signature" means the split passed. 1e-20 + 10 is 10 in IEEE doubles: the sum conserves, the shares do not
    let settle = |c: f64, v: f64, t: f64| {
        settlement_wire_check(
            &json!({"claimId": "c", "action": "slash", "amount": 10, "from": "f", "to": "t", "at": 1, "evidenceDigest": "e", "sig": "s",
                "split": {"amount": 10, "challengerReward": c, "victimCompensation": v, "treasuryRemainder": t, "victimAccount": "v", "treasuryAccount": "t", "challengerAccount": null}}),
            "k",
        )
    };
    assert_eq!(settle(0.0, 0.0, 10.0), "signature");
    for (c, v, t) in [(1e-20, 0.0, 10.0), (0.0, 1e-20, 10.0), (5.0, 0.0, 5.0), (0.0, 5.0, 5.0)] {
        assert_eq!(settle(c, v, t), "split", "{c} {v} {t}");
    }
}
