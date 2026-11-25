//! Differential replay of test-data/ref-reputation.json.gz (the input validator and the fail-closed edges of the score) and of
//! the reputation part of test-data/ref-core-sweep-java.json.gz (scoring, coverage pricing, signed coverage quotes, the insurance
//! capital pool), both written by the TypeScript reference. A case the reference refuses must be refused here; reasons and
//! rationales are compared exactly, quote signatures byte for byte.
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::bond_settlement::InsuranceCapitalPool;
use atlas_pca::reputation::*;
use atlas_pca::serde_json::{json, Value};
use common::replay::{replay, replay_cases, thrown};
use sha2::{Digest, Sha256};

/// The underwriter of the sweep corpus: the Ed25519 seed of the label `sweep/underwriter`.
fn underwriter() -> KeyPair {
    KeyPair::from_seed(&Sha256::digest(b"atlas-pca-conformance/sweep/underwriter").into())
}

/// A number argument; a missing, null or non-number one is NaN (the reference treats each as non-finite).
fn double(v: &Value) -> f64 {
    v.as_f64().filter(|_| v.is_number()).unwrap_or(f64::NAN)
}

fn pricing(v: &Value) -> PricingOptions {
    let n = |k: &str| v.get(k).filter(|x| !x.is_null()).map(double);
    PricingOptions { base_rate: n("baseRate"), risk_load: n("riskLoad"), min_score: n("minScore") }
}

fn pool(ops: &[Value]) -> Value {
    let err = || json!({"$err": "Error"});
    let mut pool: Option<InsuranceCapitalPool> = None;
    let mut out = Vec::new();
    for op in ops {
        let name = op[0].as_str().expect("an op name");
        if name == "new" {
            let made = InsuranceCapitalPool::new(double(&op[1]));
            out.push(made.as_ref().map_or_else(|_| err(), InsuranceCapitalPool::state));
            if let Ok(p) = made {
                pool = Some(p);
            }
            continue;
        }
        // an op on a pool that was never created fails in the reference too
        let Some(p) = pool.as_mut() else {
            out.push(err());
            continue;
        };
        out.push(match name {
            "quote" => p.quote(double(&op[1]["score"]), double(&op[2]), &pricing(&op[3])),
            "collect" => p.collect_premium(double(&op[1]["score"]), double(&op[2]), &pricing(&op[3])).unwrap_or_else(|_| err()),
            "canCover" => json!(p.can_cover(double(&op[1]))),
            "pay" => p.pay_claim(double(&op[1])).unwrap_or_else(|_| err()),
            "state" => p.state(),
            other => panic!("unhandled pool op {other}"),
        });
    }
    json!(out)
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => json!({"MAX_REPUTATION_RECORDS": MAX_REPUTATION_RECORDS, "COVERAGE_QUOTE_DOMAIN": COVERAGE_QUOTE_DOMAIN}),
        "validateReputationInput" => json!(validate_reputation_input(&a[0])),
        "reputation" => reputation(&a[0]),
        "priceCoverage" => price_coverage(double(&a[0]["score"]), double(&a[1]), &pricing(&a[2])),
        "issueCoverageQuote" => issue_coverage_quote(&a[0], double(&a[1]), &underwriter(), double(&a[2]), double(&a[3]), &pricing(&a[4])).unwrap_or_else(thrown),
        "verifyCoverageQuote" => {
            let pinned = underwriter().public;
            verify_coverage_quote(&a[0], if a[1] == "@u" { pinned.as_str() } else { a[1].as_str().expect("a key") }, double(&a[2]))
        }
        "pool" => pool(a[0].as_array().expect("ops")),
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn ref_reputation_replay() {
    replay("reputation", 85, 0, run);
}

#[test]
fn ref_sweep_reputation_replay() {
    const FNS: [&str; 5] = ["reputation", "priceCoverage", "issueCoverageQuote", "verifyCoverageQuote", "pool"];
    let cases: Vec<Value> = common::ref_cases_seeded("core-sweep-java").into_iter().filter(|c| FNS.contains(&c["fn"].as_str().unwrap_or(""))).collect();
    replay_cases("core-sweep-java (reputation, coverage, pool)", cases, 353, 0, run);
}

#[test]
fn the_record_cap_is_enforced() {
    let events = vec![json!({"outcome": "auto"}); MAX_REPUTATION_RECORDS + 1];
    let over = json!({"subject": "s", "events": events});
    assert_eq!(validate_reputation_input(&over).as_deref(), Some("too many records"));
    assert_eq!(reputation(&over)["score"], 0);
    let at_cap = json!({"subject": "s", "events": over["events"].as_array().unwrap()[1..]});
    assert_eq!(validate_reputation_input(&at_cap), None);
    let disputes = vec![json!({"id": "d", "subject": "s", "slashed": false, "at": 0}); MAX_REPUTATION_RECORDS + 1];
    assert_eq!(validate_reputation_input(&json!({"subject": "s", "disputes": disputes})).as_deref(), Some("too many records"));
}
