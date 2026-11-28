//! Differential replay of the small helpers and the sign-side counterparts against the TypeScript reference:
//! test-data/ref-core-kotlin-gaps.json.gz in full (the salted ledger commitment and its opening, the ledger root, the v2 intent goal,
//! the revocation scope and exposure bound, the budget-allocation caveat), and the signers of test-data/ref-action-pin.json.gz
//! (registry key entries, principal re-approvals) and test-data/ref-intent-misc2.json.gz (classifier verdicts, accumulator receipts,
//! sequencer key sets). A case the reference refuses must be refused here.
mod common;
use atlas_pca::agent::{KeyPair, PqKeyPair, Suite};
use atlas_pca::core_small::*;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::sign_parity::*;

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn d(v: &Value) -> f64 {
    v.as_f64().unwrap_or(f64::NAN)
}

fn thrown(e: String) -> Value {
    json!({"$throws": e})
}

fn ed(v: &Value) -> Result<KeyPair, String> {
    KeyPair::from_seed_b64u(text(&v["$bytes"]))
}

/// Run `f` under the suite a corpus case names: `null` (ed25519) or `{alg, pqSeed?}`.
fn with_suite(v: &Value, f: impl FnOnce(&Suite) -> Result<Value, String>) -> Result<Value, String> {
    let alg = v.get("alg").and_then(Value::as_str);
    let pq = match v.get("pqSeed") {
        Some(seed) => {
            let raw = atlas_pca::decode_b64u_strict(text(&seed["$bytes"]), None).ok_or("pqSeed")?;
            Some(PqKeyPair::from_seed("ML-DSA-65", &raw)?)
        }
        None => None,
    };
    f(&Suite { alg, pq: pq.as_ref() })
}

fn gaps(f: &str, a: &[Value]) -> Value {
    match f {
        "entryCommit" => entry_commit(text(&a[0]), &a[1]).map_or_else(thrown, |c| json!(c)),
        "verifyOpening" => json!(a[0].as_str().is_some_and(|c| verify_opening(c, &a[1]))),
        "ledgerRootOf" => {
            let commits: Vec<String> = a[0].as_array().map(|l| l.iter().map(|c| text(c).to_string()).collect()).unwrap_or_default();
            json!(atlas_pca::ledger_store::ledger_root_of(&commits))
        }
        "parseIntentGoalV2" => a[0].as_str().and_then(parse_intent_goal_v2).map_or(Value::Null, |(s, m)| json!({"session": s, "mapDigest": m})),
        "profileRevocationScope" => json!(profile_revocation_scope(text(&a[0]))),
        "revocationExposureEnd" => atlas_pca::bond_store::num(revocation_exposure_end(d(&a[0]), d(&a[1]), a[2].as_f64())),
        "budgetAllocCaveat" => budget_alloc_caveat(d(&a[0])),
        other => panic!("unhandled corpus function {other}"),
    }
}

fn signer(f: &str, a: &[Value]) -> Option<Result<Value, String>> {
    let null = Value::Null;
    let suite = a.get(2).unwrap_or(&null);
    Some(match f {
        "registryKeyOf" => ed(&a[1]).and_then(|k| with_suite(suite, |s| registry_key_of(text(&a[0]), &k, s))),
        "signReapproval" => ed(&a[0]["principalSecret"]).and_then(|k| sign_reapproval(text(&a[0]["grantId"]), &a[0]["record"], &k)),
        "signClassifierVerdict" => ed(&a[1]).and_then(|k| with_suite(suite, |s| sign_classifier_verdict(&a[0], &k, s))),
        "signAccReceipt" => ed(&a[1]).and_then(|k| with_suite(suite, |s| sign_acc_receipt(&a[0], &k, s))),
        "signSequencerKeySet" => ed(&a[1]).and_then(|k| with_suite(suite, |s| sign_sequencer_key_set(&a[0], &k, s))),
        _ => return None,
    })
}

fn differs(want: &Value, got: &Value) -> bool {
    if want.get("$throws").is_some() {
        got.get("$throws").is_none()
    } else {
        atlas_pca::canonicalize(want) != atlas_pca::canonicalize(got)
    }
}

#[test]
fn the_small_helpers_match_the_reference() {
    let cases = common::ref_cases("core-kotlin-gaps");
    assert_eq!(cases.len(), 112, "case total");
    let bad: Vec<String> = cases
        .iter()
        .filter_map(|c| {
            let got = gaps(text(&c["fn"]), c["args"].as_array().map(Vec::as_slice).unwrap_or(&[]));
            differs(&c["out"], &got).then(|| format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got))
        })
        .collect();
    assert!(bad.is_empty(), "{} cases differ:\n{}", bad.len(), bad.join("\n"));
}

#[test]
fn the_signers_match_the_reference() {
    let (mut ran, mut bad) = (0usize, Vec::new());
    for corpus in ["action-pin", "intent-misc2"] {
        for c in common::ref_cases_seeded(corpus) {
            if common::has_nonfinite(&c["args"]) && c["out"].get("$throws").is_some() {
                ran += 1; // refused by construction: a Rust Value cannot hold a non-finite number
                continue;
            }
            let Some(r) = signer(text(&c["fn"]), c["args"].as_array().map(Vec::as_slice).unwrap_or(&[])) else { continue };
            ran += 1;
            let got = r.unwrap_or_else(thrown);
            if differs(&c["out"], &got) {
                bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
            }
        }
    }
    // registryKeyOf 5 + signReapproval 8 + signClassifierVerdict 6 + signAccReceipt 16 + signSequencerKeySet 15, plus the 7 cases whose
    // non-finite argument is refused by construction (1 in action-pin, 6 in intent-misc2): the counts of the 0.6 regeneration
    assert_eq!(ran, 5 + 8 + 6 + 16 + 15 + 7, "signer cases replayed");
    assert!(bad.is_empty(), "{} cases differ:\n{}", bad.len(), bad.join("\n"));
}

#[test]
fn a_revocation_message_is_domain_separated_and_strict() {
    let m = revoke_message("grant-1", "cap-1").expect("message");
    assert_eq!(m, b"atlas-pca/revoke/v1\0{\"grant_ref\":\"grant-1\",\"revoked_cap_id\":\"cap-1\"}".to_vec());
}

#[test]
fn a_grant_without_an_envelope_carries_no_objective_commitment() {
    assert_eq!(read_objective_commitment(&json!({})), json!({}));
}
