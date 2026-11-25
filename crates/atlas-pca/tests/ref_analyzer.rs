//! Differential replay of the policy analyzer (`@atlasauth/pca-analyzer`: bounded decision engine, relational queries, exposure, residuals,
//! filters, narrowing, coverage, minimal flips, schema validation, policy tests) against the TypeScript reference
//! (test-data/ref-analyzer.json.gz). Policies and results are plain JSON trees; a number that is not finite is `{"$num": ...}` on both
//! sides. A reference throw only requires a refusal. Keys are labels: the Ed25519 key of a label is seeded by
//! sha256("atlas-pca-conformance/" + label), and "$key:LABEL" in an argument stands for its public key.
//! Skipped (counted, must stay under 10%): cases carrying a lone surrogate (a Rust string cannot hold one). No analyzer function is skipped.
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::analyzer as an;
use atlas_pca::serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn key_of(label: &str) -> KeyPair {
    let seed: [u8; 32] = Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes()).into();
    KeyPair::from_seed(&seed)
}

/// "$key:LABEL" replaced by the label's public key.
fn keyed(v: &Value) -> Value {
    match v {
        Value::String(s) => match s.strip_prefix("$key:") {
            Some(label) => Value::String(key_of(label).public),
            None => v.clone(),
        },
        Value::Array(a) => Value::Array(a.iter().map(keyed).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), keyed(x))).collect()),
        _ => v.clone(),
    }
}

fn at(a: &[Value], i: usize) -> &Value {
    a.get(i).unwrap_or(&Value::Null)
}

fn label(v: &Value) -> Result<KeyPair, String> {
    Ok(key_of(v.as_str().ok_or("label is not a string")?))
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "analyzeCaveats" => an::analyze_caveats(&a[0]),
        "numericConjunctionSatisfiable" => an::numeric_conjunction_satisfiable(&a[0]).map(Value::Bool),
        "predicateNumericSatisfiable" => an::predicate_numeric_satisfiable(&a[0]).map(Value::Bool),
        "tightenInterval" => Ok(an::tighten_interval(an::Iv::from_json(&a[0]), at(a, 1), at(a, 2)).to_json()),
        "intervalEmpty" => Ok(Value::Bool(an::interval_empty(an::Iv::from_json(&a[0])))),
        "fieldProbes" => an::field_probes(&a[0]),
        "vetoesFromConstitution" => an::vetoes_from_constitution(&a[0]),
        "toModel" => an::to_model(&a[0]),
        "collectProbes" => an::collect_probes(&a[0]).map(|p| p.to_json()),
        "representatives" => an::representatives(&a[0], 400.0),
        "witnessOf" => an::to_model(&a[0]).and_then(|m| an::witness_of(&m, &a[1])),
        "decideAction" => an::decide_action(&a[0], &a[1]).map(Value::String),
        "admitsConcrete" => an::admits_concrete(&a[0], &a[1]).map(Value::Bool),
        "vetoApplies" => {
            let src = a[1].as_object().cloned().unwrap_or_default();
            let mut x = src.clone();
            x.entry("params").or_insert_with(|| json!({}));
            let nn = |k: &str| match src.get(k) {
                Some(v) if !v.is_null() => v.clone(),
                _ => json!({}),
            };
            let ctx = json!({"action": Value::Object(x), "subject": nn("subject"), "env": nn("env")});
            an::veto_applies(&a[0], &ctx).map(Value::Bool)
        }
        "reachable" => an::reachable(&a[0], &a[1], at(a, 2)),
        "alwaysDenies" => an::always_denies(&a[0], at(a, 1), at(a, 2)),
        "alwaysAllows" => an::always_allows(&a[0], at(a, 1), at(a, 2)),
        "subsumes" => an::subsumes(&a[0], &a[1], at(a, 2)),
        "disjoint" => an::disjoint(&a[0], &a[1], at(a, 2)),
        "equivalent" => an::equivalent(&a[0], &a[1], at(a, 2)),
        "intentConformance" => an::intent_conformance(&a[0], at(a, 1), at(a, 2)),
        "thresholdsOf" => an::thresholds_of(&a[0], a[1].as_str().ok_or("path is not a string")?),
        "maxExposure" => an::max_exposure(&a[0], at(a, 1)),
        "escalationSurface" => an::escalation_surface(&a[0], at(a, 1)),
        "delegationEnvelope" => an::delegation_envelope(&a[0], at(a, 1)),
        "diffPolicies" => an::diff_policies(&a[0], &a[1], at(a, 2)),
        "diffGate" => an::diff_gate(&a[0], at(a, 1)),
        "findWithBackend" => {
            let spec = &a[1];
            an::find_with_backend(&a[0], spec.get("name").unwrap_or(&Value::Null), spec.get("result").unwrap_or(&Value::Null))
        }
        "dagExposure" => an::dag_exposure(&a[0]),
        "residual" => an::residual(&a[0], &a[1], at(a, 2)),
        "residualPolicy" => an::residual_policy(&a[0]),
        "evaluateResidual" => an::evaluate_residual(&a[0], &a[1]).map(Value::String),
        "whatMayIDo" => an::what_may_i_do(&a[0], &a[1], at(a, 2), at(a, 3)),
        "toFilter" => an::to_filter(&a[0], &a[1], at(a, 2), at(a, 3)),
        "evalFilter" => an::eval_filter(&a[0], &a[1]),
        "toUcast" => an::to_ucast(&a[0]),
        "evalUcast" => an::eval_ucast(&a[0], &a[1]).map(Value::Bool),
        "suggestNarrowing" => an::suggest_narrowing(&a[0], &a[1], at(a, 2)),
        "signAccessRequest" => an::sign_access_request(&a[0], &label(&a[1])?),
        "verifyAccessRequest" => Ok(Value::Bool(an::verify_access_request(&a[0], &keyed(at(a, 1))))),
        "coverage" => an::coverage(&a[0], &a[1], at(a, 2)),
        "coverageGate" => an::coverage_gate(&a[0], at(a, 1)),
        "minimalFlip" => an::minimal_flip(&a[0], &a[1], &a[2]),
        "verbShapesFromActionDefs" => an::verb_shapes_from_action_defs(&a[0]),
        "verbShapes" => an::verb_shapes(&a[0]),
        "validatePolicyAgainstSchema" => an::validate_policy_against_schema(&a[0], &a[1], at(a, 2)),
        "policyTestsDoc" => an::policy_tests_doc(&a[0], &a[1]),
        "runPolicyTests" => an::run_policy_tests(&a[0], &a[1], at(a, 2)),
        "generateBoundaryTests" => an::generate_boundary_tests(&a[0], at(a, 1)),
        "decideAll" => an::decide_all(&a[0], &a[1]),
        "signPolicyTests" => an::sign_policy_tests(&a[0], &label(&a[1])?),
        "verifyPolicyTests" => Ok(Value::Bool(an::verify_policy_tests(&a[0], &keyed(at(a, 1))))),
        f => panic!("unknown fn {f}"),
    }
}

/// The corpus spells -0 as -0; compare by the lenient canonical form (numbers by binary64 value, keys sorted).
fn same(want: &Value, got: &Value) -> bool {
    atlas_pca::canonicalize(want) == atlas_pca::canonicalize(got)
}

#[test]
fn analyzer_vectors() {
    let cases = common::ref_cases("analyzer");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let args = c["args"].as_array().unwrap();
        let got = std::panic::catch_unwind(|| run(f, args)).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => same(&c["out"], v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(25).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn analyzer_basics() {
    // a policy admits what a predicate permits and nothing else
    let pol = json!({"predicates": [{"verb": "pay", "resource": "/vendors/*", "where": [{"field": "action.params.amount", "op": "lte", "value": 1000}]}]});
    let ok = json!({"verb": "pay", "resource": "/vendors/a", "params": {"amount": 500}});
    let over = json!({"verb": "pay", "resource": "/vendors/a", "params": {"amount": 5000}});
    assert_eq!(an::decide_action(&pol, &ok).unwrap(), "allow");
    assert_eq!(an::decide_action(&pol, &over).unwrap(), "deny");
    assert!(an::admits_concrete(&pol, &ok).unwrap());
    // the empty policy is vacuous, a wider one subsumes it
    let empty = json!({"predicates": []});
    assert_eq!(an::always_denies(&empty, &an::NONE, &an::NONE).unwrap()["alwaysDenies"], json!(true));
    assert_eq!(an::subsumes(&pol, &empty, &an::NONE).unwrap()["subsumes"], json!(true));
    assert_eq!(an::subsumes(&empty, &pol, &an::NONE).unwrap()["subsumes"], json!(false));
    // a throw is an Err, never a panic
    assert!(an::decide_action(&pol, &Value::Null).is_err());
}
