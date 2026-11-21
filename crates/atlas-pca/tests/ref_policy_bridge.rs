//! Differential replay of the policy bridge (Cedar / OPA-Rego / OpenFGA / strict-CEL translators, `decide`) against the TypeScript
//! reference (test-data/ref-policy-bridge.json.gz), whole-JSON equality per case; a reference throw only requires a refusal.
//! Skipped (counted, must stay under 10%): cases with a lone surrogate, and calls whose text argument is not a string for the entry
//! points that take `&str` (cedarToPca, translateCedar, regoToPca). No corpus function is skipped wholesale.
mod common;
use atlas_pca::policy_bridge::*;
use atlas_pca::serde_json::Value;

fn text(a: &[Value]) -> Result<&str, String> {
    a[0].as_str().ok_or_else(|| "skip".to_string())
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "cedarToPca" => Ok(cedar_to_pca(text(a)?)),
        "translateCedar" => Ok(translate_cedar(text(a)?, a[1].as_bool().unwrap_or(false))),
        "regoToPca" => Ok(rego_to_pca(text(a)?)),
        "openfgaToPca" => Ok(openfga_to_pca(&a[0], a.get(1))),
        "decide" => decide(&a[0], &a[1]),
        "celToCondition" => Ok(cel_to_condition(&a[0], &a[1])),
        "parseCel" => Ok(parse_cel(&a[0])),
        "celToPredicate" => cel_to_predicate(&a[0], &a[1], &a[2]),
        "celConditionsToPca" => cel_conditions_to_pca(&a[0], &a[1]),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn policy_bridge_vectors() {
    let cases = common::ref_cases_seeded("policy-bridge");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        let args = c["args"].as_array().unwrap();
        let text_fn = matches!(f, "cedarToPca" | "translateCedar" | "regoToPca");
        if common::has_lone(&c["args"]) || (text_fn && !args[0].is_string()) {
            skipped += 1;
            continue;
        }
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
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
