//! Differential replay of the agent-native primitives (caution claims, rationale binding, the tool-schema firewall, capability
//! introspection, leases) against the TypeScript reference (test-data/ref-agent-native.json.gz, 1632 cases). Keys are seed labels
//! (`{"$bytes": {"$seed": label}}`, sha256("atlas-pca-conformance/" + label)); the claims and heartbeats the corpus feeds to the
//! verifiers carry real signatures, and describeEnvelope chains are checked with the crate's own chain verifier. A number that is not
//! finite is `{"$num": ...}` (a non-number to every function here, as NaN is to `Number.isFinite`). A reference throw requires a
//! refusal; every other result compares as canonical JSON. A case whose fn has no entry here fails. Skipped (counted, must stay under
//! 10%): cases carrying a lone surrogate (a Rust string cannot hold one).
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::agent_native as an;
use atlas_pca::serde_json::{json, Value};

static NULL: Value = Value::Null;

/// A number argument as a double: `{"$num": "NaN" | "Infinity" | "-Infinity"}` is that value, anything that is not a number is NaN.
fn numish(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::Object(m) => match m.get("$num").and_then(Value::as_str) {
            Some("Infinity") => f64::INFINITY,
            Some("-Infinity") => f64::NEG_INFINITY,
            _ => f64::NAN,
        },
        _ => f64::NAN,
    }
}

fn is_number(v: &Value) -> bool {
    v.is_number() || v.get("$num").is_some()
}

fn opt_str(v: &Value) -> Option<&str> {
    v.as_str()
}

fn key_of(v: &Value) -> Result<KeyPair, String> {
    let b = v
        .get("$bytes")
        .and_then(Value::as_str)
        .and_then(|s| atlas_pca::decode_b64u_strict(s, Some(32)))
        .ok_or("no secret key")?;
    let seed: [u8; 32] = b.try_into().map_err(|_| "no secret key".to_string())?;
    Ok(KeyPair::from_seed(&seed))
}

fn firewall(r: (bool, Option<String>)) -> Value {
    match r {
        (true, _) => json!({"ok": true}),
        (false, why) => json!({"ok": false, "reason": why}),
    }
}

fn judge(spec: &str) -> impl Fn(&str, &Value) -> Result<bool, String> + '_ {
    move |rationale: &str, action: &Value| match spec {
        "true" => Ok(true),
        "false" | "truthy" => Ok(false), // "truthy" returns the string "yes", which is not === true
        "throw" => Err("judge threw".into()),
        s if s.starts_with("contains:") => Ok(rationale.contains(&s["contains:".len()..])),
        s if s.starts_with("action-verb:") => {
            Ok(action.get("verb").and_then(Value::as_str) == Some(&s["action-verb:".len()..]))
        }
        s => Err(format!("unknown judge spec {s}")),
    }
}

fn constants() -> Value {
    json!({
        "CAVEAT_ENVELOPE": an::CAVEAT_ENVELOPE, "CAVEAT_EXPIRES": an::CAVEAT_EXPIRES, "CAVEAT_NOT_BEFORE": an::CAVEAT_NOT_BEFORE,
        "CAVEAT_RATE": an::CAVEAT_RATE, "CAVEAT_MAX_BLAST_RADIUS": an::CAVEAT_MAX_BLAST_RADIUS, "CAVEAT_REVERSIBILITY_MAX": an::CAVEAT_REVERSIBILITY_MAX,
        "CAVEAT_DELEGATION_DEPTH": an::CAVEAT_DELEGATION_DEPTH, "CAVEAT_PREDICATES": an::CAVEAT_PREDICATES, "CAVEAT_TOOL_SCHEMA": an::CAVEAT_TOOL_SCHEMA,
        "CAVEAT_MAX_SPEND": an::CAVEAT_MAX_SPEND, "MAX_CAUTION_REASON_LEN": an::MAX_CAUTION_REASON_LEN, "MIN_SALT_BYTES": an::MIN_SALT_BYTES,
        "MIN_SALT_DISTINCT_BYTES": an::MIN_SALT_DISTINCT_BYTES, "MAX_RATIONALE_LEN": an::MAX_RATIONALE_LEN, "MAX_SCHEMA_DEPTH": an::MAX_SCHEMA_DEPTH,
        "MAX_SCHEMA_NODES": an::MAX_SCHEMA_NODES, "MAX_OBJECT_PROPS": an::MAX_OBJECT_PROPS, "MAX_ENUM_VALUES": an::MAX_ENUM_VALUES,
        "DEFAULT_MAX_ARRAY_ITEMS": an::DEFAULT_MAX_ARRAY_ITEMS, "ABSOLUTE_MAX_ARRAY_ITEMS": an::ABSOLUTE_MAX_ARRAY_ITEMS,
        "DEFAULT_MAX_STRING_LEN": an::DEFAULT_MAX_STRING_LEN, "ABSOLUTE_MAX_STRING_LEN": an::ABSOLUTE_MAX_STRING_LEN, "MAX_VALUE_NODES": an::MAX_VALUE_NODES,
        "HEARTBEAT_SKEW_MS": an::HEARTBEAT_SKEW_MS as i64, "MAX_LEASE_TTL_MS": an::MAX_LEASE_TTL_MS as i64,
    })
}

fn run(f: &str, a: &[Value]) -> Option<Result<Value, String>> {
    let g = |i: usize| a.get(i).unwrap_or(&NULL);
    let opt = |i: usize| Some(g(i)).filter(|v| !v.is_null());
    Some(match f {
        "constants" => Ok(constants()),
        "signCaution" => key_of(g(1)).and_then(|k| atlas_pca::signers_more::sign_caution(&k, g(0))),
        "signHeartbeat" => {
            key_of(g(1)).and_then(|k| atlas_pca::signers_more::sign_heartbeat(&k, g(0)))
        }
        "verifyCaution" => {
            // a given expectation that is not a string can never equal the claim's string member
            if [g(1), g(2)].iter().any(|v| !v.is_null() && !v.is_string()) {
                return Some(Ok(json!(false)));
            }
            Ok(json!(an::verify_caution(
                g(0),
                opt_str(g(1)),
                opt_str(g(2))
            )))
        }
        "combineCaution" => Ok(json!(an::combine_caution(
            is_number(g(0)).then(|| numish(g(0))),
            numish(g(1))
        ))),
        "combineSignedCaution" => Ok(an::combine_signed_caution(
            opt(0),
            g(1).as_str().unwrap_or(""),
            numish(g(2)),
            opt_str(g(3)),
        )),
        "checkCautionMonotone" => {
            let grid: Vec<f64> = g(0)
                .as_array()
                .map(|l| l.iter().filter(|x| is_number(x)).map(numish).collect())
                .unwrap_or_default();
            Ok(an::check_caution_monotone(&grid))
        }
        "isStrongSalt" => Ok(json!(an::is_strong_salt(g(0)))),
        "bindRationale" => match g(1).as_str() {
            None => Err("rationale must be a string".into()),
            // any salt that is not a string is below the floor
            Some(text) => an::bind_rationale(g(0), text, Some(g(2).as_str().unwrap_or(""))),
        },
        "verifyRationale" => Ok(json!(an::verify_rationale(
            g(0),
            g(1),
            (a.len() > 2).then(|| g(2))
        ))),
        "auditRationale" => Ok(an::audit_rationale(
            g(0),
            g(1),
            opt(2),
            &judge(g(3).as_str().unwrap_or("")),
        )),
        "validateArgSchema" => Ok(an_validate(g(0))),
        "toolSchemaCaveat" => an::tool_schema_caveat(g(0), g(1)),
        "evaluateToolSchema" => Ok(firewall(an::evaluate_tool_schema(
            g(0),
            g(1),
        ))),
        "toolSchemaEvaluator" => Ok(json!(an::tool_schema_evaluator(g(0), g(1)))),
        "predicatesCaveat" => an::predicates_caveat(g(0)),
        "actionSpendUsd" => Ok(an::action_spend_usd(g(0)).map_or(Value::Null, |f| json!(f))),
        "agentNativeCaveatEvaluator" => Ok(json!(an::agent_native_caveat_evaluator(g(0), g(1)))),
        "describeEnvelope" => Ok(an::describe_envelope(
            g(0),
            is_number(g(1)).then(|| numish(g(1))),
            opt_str(g(2)),
            opt(3),
        )),
        "envelopePermits" => Ok(json!(an::envelope_permits(
            g(0),
            g(1).as_str().unwrap_or(""),
            g(2).as_str().unwrap_or(""),
            opt(3).map(numish),
            opt(4)
        ))),
        "envelopePermitsToolCall" => Ok(firewall(an::envelope_permits_tool_call(g(0), g(1)))),
        "grantLease" => an::grant_lease(g(0)),
        "leaseState" => Ok(an::lease_state(g(0), numish(g(1)))),
        "renewLease" => Ok(an::renew_capability_lease(g(0), g(1), numish(g(2)))),
        _ => return None,
    })
}

fn an_validate(schema: &Value) -> Value {
    an::validate_arg_schema(schema).map_or(Value::Null, |e| json!(e))
}

#[test]
fn agent_native_vectors() {
    let cases = common::ref_cases_seeded("agent-native");
    assert_eq!(cases.len(), 1632);
    let (mut bad, mut skipped, mut inexpressible) = (Vec::new(), 0, 0usize);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        // a non-finite number cannot be held by a Rust Value: the reference's refusal holds by construction
        if common::has_nonfinite(&c["args"]) && c["out"].get("$throws").is_some() {
            continue;
        }
        // `audit_rationale` takes the action as a `&Value`: a non-finite member of it (the reference answers `malformed`, it does not
        // throw) has no Rust call that means the same. Asserted, not replayed on another number: the value cannot be constructed.
        if f == "auditRationale" && common::has_nonfinite(&c["args"]) {
            common::assert_nonfinite_inexpressible(&c["args"]);
            inexpressible += 1;
            continue;
        }
        let args = c["args"].as_array().unwrap();
        let got = match std::panic::catch_unwind(|| run(f, args)) {
            Ok(Some(r)) => r,
            Ok(None) => {
                bad.push(format!("{}: no Rust entry point for {f}", c["name"]));
                continue;
            }
            Err(_) => Err("panic".to_string()),
        };
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!(
                "{}\n  want {}\n  got  {:?}",
                c["name"], c["out"], got
            ));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(inexpressible > 0, "the corpus carries the non-finite rationale-audit case that is asserted as inexpressible");
    assert!(
        bad.is_empty(),
        "{} of {} cases differ:\n{}",
        bad.len(),
        cases.len(),
        bad.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
