//! Differential replay of test-data/ref-contracts.json.gz (written by the TypeScript reference): the constants, clause validation,
//! the contract id and signer, the embedded constitution and the lift of a constitution into a contract, the contract monitor, the
//! advance with its head guards and clock, and the composition with a permission verdict. A case the reference refuses must be
//! refused here.
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::contracts::*;
use atlas_pca::serde_json::{json, Value};
use common::replay::{replay, skip, thrown};

/// The options object of a case: `None` for a `null` (the typed options cannot express it). A present guard or clock of the wrong
/// type is the value that fails the same way: NaN for a number (stale head, clock regression), "" for a digest (stale head).
fn options(v: Option<&Value>) -> Option<AdvanceOptions> {
    let Some(v) = v else { return Some(AdvanceOptions::default()) };
    if v.is_null() {
        return None;
    }
    let number = |k: &str| v.get(k).map(|n| n.as_f64().unwrap_or(f64::NAN));
    Some(AdvanceOptions {
        expected_seq: number("expectedSeq"),
        expected_state_digest: v.get("expectedStateDigest").map(|d| d.as_str().unwrap_or("").to_string()),
        // `now ?? state.now`: a null clock is the default
        now: v.get("now").filter(|n| !n.is_null()).map(|n| n.as_f64().unwrap_or(f64::NAN)),
    })
}

fn advanced(r: &AdvanceContract) -> Value {
    let mut o = r.result.to_json();
    o["next"] = r.next.clone();
    o["decidedBy"] = json!(r.decided_by);
    o
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => {
            json!({"CONTRACT_VERSION": CONTRACT_VERSION, "CONTRACT_SIG_DOMAIN": CONTRACT_SIG_DOMAIN, "MAX_CLAUSES": MAX_CONTRACT_CLAUSES, "MAX_CLAUSE_DEPTH": MAX_CLAUSE_DEPTH})
        }
        "validateClause" => {
            let mut seen: Vec<String> = a[1].as_array().into_iter().flatten().filter_map(|s| s.as_str().map(String::from)).collect();
            // the depth is a count: a negative or fractional one (below the limit either way) is its floor, at least 0
            json!(validate_clause(&a[0], &mut seen, a[2].as_f64().unwrap_or(0.0).max(0.0) as usize))
        }
        // the reference hashes the own members of whatever it is given; here only an object is a contract (null is refused by both)
        "contractId" if !a[0].is_object() && !a[0].is_null() => skip("a contract that is not an object"),
        "contractId" => contract_id(&a[0]).map_or_else(|| thrown("outside the strict JSON profile"), Value::String),
        "signContract" => a[1]
            .as_str()
            .ok_or_else(|| "not a key".to_string())
            .and_then(KeyPair::from_seed_b64u)
            .and_then(|k| sign_contract(&a[0], &k))
            .unwrap_or_else(thrown),
        // a null has no members to read in the reference; here a null is a document with no members
        "embeddedConstitution" | "contractFromConstitution" if a[0].is_null() => thrown("null"),
        "embeddedConstitution" => embedded_constitution(&a[0]),
        "contractFromConstitution" => contract_from_constitution(&a[0]),
        "checkContract" => check_contract(&a[0], &a[1], &a[2]).to_json(),
        "advanceContract" => match options(a.get(3)) {
            Some(o) => advanced(&advance_contract(&a[0], &a[1], &a[2], &o)),
            None => skip("null options"),
        },
        "checkAndAdvanceContract" => match options(a.get(4)) {
            Some(o) => {
                let permitted = a[0] == true;
                let (allow, r) = check_and_advance_contract(permitted, &a[1], &a[2], &a[3], &o);
                let mut out = advanced(&r);
                out["allow"] = json!(allow);
                out["permitted"] = json!(permitted);
                out
            }
            None => skip("null options"),
        },
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn the_contract_surface_matches_the_reference() {
    // 2 cases carry a lone surrogate; 1 advance passes `null` for the options; 2 ids are asked of a string and an array
    replay("contracts", 1269, 5, run);
}
