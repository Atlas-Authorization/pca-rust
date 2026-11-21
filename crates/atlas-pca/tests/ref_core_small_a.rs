//! Differential replay of the pure helpers of test-data/ref-core-small-surface.json.gz (written by the TypeScript reference): the cheap PCActn
//! claim check, goal commitments, discharge requests, the named unmet limit, reversibility resolution, the agent caveat context, threshold
//! assembly, the budget-allocation caveat predicate, the decision meet, threshold escalation, the revocation-staleness policy validator, the
//! canonical compact-JWS gate and its detached segments form, the workflow commitment and receipt checks and the revocation membership proof.
//! A reference throw requires a refusal; per-function totals are asserted.
mod common;
use std::collections::BTreeMap;

use atlas_pca::serde_json::{json, Value};

const FNS: [(&str, usize); 18] = [
    ("pcactnCheapClaims", 16),
    ("goalCommitOf", 4),
    ("verifyGoalCommit", 16),
    ("dischargeRequests", 7),
    ("namedUnmetLimitReason", 7),
    ("resolveReversibilityClass", 8),
    ("agentCaveatContext", 5),
    ("assembleThreshold", 4),
    ("isBudgetAllocCaveat", 8),
    ("meetAll", 7),
    ("escalateThreshold", 15),
    ("validateRevocationStaleness", 13),
    ("isCanonicalCompactJws", 28),
    ("isCanonicalCompactJwsOpaque", 28),
    ("isCanonicalCompactJwsMax", 28),
    ("isCanonicalCompactJwsFive", 4),
    ("assertCanonicalJwsSegments", 8),
    ("verifyMembership", 135),
];
const FNS2: [(&str, usize); 2] = [("workflowCommitmentError", 180), ("workflowReceiptError", 171)];

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn opt<'a>(v: &'a Value) -> Option<&'a Value> {
    Some(v).filter(|x| !x.is_null())
}

fn proof_of(name: &str) -> u8 {
    match name {
        "claim" => 0,
        "standard" => 1,
        _ => 2,
    }
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    use atlas_pca::agent::{goal_commit_of, verify_goal_commit};
    use atlas_pca::consts::assemble_threshold;
    use atlas_pca::jose::{assert_canonical_jws_segments, is_canonical_compact_jws, DEFAULT_MAX_JWS_BYTES};
    use atlas_pca::policy_vm::resolve_reversibility_class;
    use atlas_pca::risk::{escalate_threshold, RequiredThreshold};
    use atlas_pca::small_surface::*;
    use atlas_pca::staleness::verify_membership;
    use atlas_pca::surface_misc::is_budget_alloc_caveat;
    use atlas_pca::workflow::{workflow_commitment_error, workflow_receipt_error};
    use atlas_pca::{discharge_requests, meet_all, named_unmet_limit_reason};
    Ok(match f {
        "pcactnCheapClaims" => failure_json(pcactn_cheap_claims_at(&a[0], text(&a[1]), &a[2])),
        "goalCommitOf" => json!(goal_commit_of(text(&a[0]), text(&a[1]))?),
        "verifyGoalCommit" => json!(verify_goal_commit(text(&a[0]), text(&a[1]), text(&a[2]))),
        "dischargeRequests" => Value::Array(discharge_requests(&a[0], &a[1], a[2].as_str())),
        "namedUnmetLimitReason" => {
            named_unmet_limit_reason(a[0].as_array().map_or(&[][..], |v| v.as_slice()), &a[1]).map_or(Value::Null, Value::String)
        }
        "resolveReversibilityClass" => resolve_reversibility_class(&a[0], opt(&a[1]), opt(&a[2])).unwrap_or(Value::Null),
        "agentCaveatContext" => agent_caveat_context(&a[0], &a[1]),
        "assembleThreshold" => assemble_threshold(a[0].as_array().map_or(&[][..], |v| v.as_slice())),
        "isBudgetAllocCaveat" => json!(is_budget_alloc_caveat(&a[0])),
        "meetAll" => {
            let ds: Vec<&str> = a[0].as_array().unwrap().iter().map(text).collect();
            json!(meet_all(&ds))
        }
        "escalateThreshold" => {
            let rt = RequiredThreshold {
                t: a[0]["t"].as_u64().unwrap() as u8,
                proof: proof_of(text(&a[0]["proof"])),
                optimistic_allowed: a[0]["optimisticAllowed"] == json!(true),
            };
            let r = escalate_threshold(rt, a[1].as_u64().unwrap() as u8);
            json!({"t": r.t, "proof": r.proof_name(), "optimisticAllowed": r.optimistic_allowed})
        }
        "validateRevocationStaleness" => json!({"ok": validate_revocation_staleness_json(&a[0]).is_ok()}),
        "isCanonicalCompactJws" => json!(is_canonical_compact_jws(&a[0], 3, DEFAULT_MAX_JWS_BYTES, true)),
        "isCanonicalCompactJwsOpaque" => json!(is_canonical_compact_jws(&a[0], 3, DEFAULT_MAX_JWS_BYTES, false)),
        "isCanonicalCompactJwsMax" => json!(is_canonical_compact_jws(&a[0], 3, 40, true)),
        "isCanonicalCompactJwsFive" => json!(is_canonical_compact_jws(&a[0], 5, DEFAULT_MAX_JWS_BYTES, true)),
        "assertCanonicalJwsSegments" => match assert_canonical_jws_segments(&a[0], &a[1], None) {
            Ok(h) => json!({"ok": true, "header": h}),
            Err(_) => json!({"ok": false}),
        },
        "verifyMembership" => json!(verify_membership(text(&a[0]), &a[1], text(&a[2]))),
        "workflowCommitmentError" => {
            workflow_commitment_error(&a[0], text(&a[1]), a[2].as_i64().ok_or("clock is not an integer")?).map_or(Value::Null, |e| json!(e))
        }
        "workflowReceiptError" => {
            let receipts = a[2].as_array().ok_or("receipts is not an array")?;
            workflow_receipt_error(&a[0], text(&a[1]), receipts, a[3].as_i64().ok_or("clock is not an integer")?)
                .map_or(Value::Null, |i| json!(i))
        }
        other => panic!("unhandled corpus function {other}"),
    })
}

#[test]
fn core_small_surface_pure_helpers_replay() {
    let all = common::ref_cases_seeded("core-small-surface");
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    let mut bad = Vec::new();
    for c in &all {
        let f = text(&c["fn"]);
        if !FNS.iter().chain(FNS2.iter()).any(|(n, _)| *n == f) {
            continue;
        }
        *per_fn.entry(f.to_string()).or_default() += 1;
        let args = c["args"].as_array().unwrap();
        let got = std::panic::catch_unwind(|| run(f, args)).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    let want: BTreeMap<String, usize> = FNS.iter().chain(FNS2.iter()).map(|(k, n)| (k.to_string(), *n)).collect();
    assert_eq!(per_fn, want, "per-function case totals");
    assert!(bad.is_empty(), "{} cases differ:\n{}", bad.len(), bad.iter().take(30).cloned().collect::<Vec<_>>().join("\n"));
}
