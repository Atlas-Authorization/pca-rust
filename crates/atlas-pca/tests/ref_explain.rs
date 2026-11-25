//! Differential replay of the PCA explainer (cleanText, explainVerification / explainDecision / explainChain and their text
//! renderers) against the TypeScript reference (test-data/ref-explain.json.gz). Explanations compare as their JSON (an absent
//! member is a JavaScript undefined); a reference throw only requires a refusal.
//! Skipped (counted, must stay under 10%): cases whose arguments carry a lone surrogate (a Rust String cannot hold one).
//! A lone surrogate in an expected string (a 400-unit cut inside a surrogate pair) is compared as U+FFFD.
mod common;
use atlas_pca::explain::*;
use atlas_pca::serde_json::{json, Map, Value};

fn fix(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(s.replace(common::LONE, "\u{FFFD}")),
        Value::Array(a) => Value::Array(a.iter().map(fix).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.replace(common::LONE, "\u{FFFD}"), fix(x))).collect::<Map<_, _>>()),
        o => o.clone(),
    }
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let empty = json!({});
    let opts = |i: usize| a.get(i).unwrap_or(&empty);
    let text = |r: Result<String, String>| r.map(Value::String);
    match f {
        "cleanText" => Ok(Value::String(clean_text(&a[0]))),
        "explainVerification" => Ok(explain_verification(&a[0], &a[1], opts(2))),
        "explainVerificationText" => text(verification_to_text(&explain_verification(&a[0], &a[1], opts(2)))),
        "explainDecision" => explain_decision(&a[0], &a[1], opts(2)),
        "explainDecisionText" => text(explain_decision(&a[0], &a[1], opts(2)).and_then(|e| decision_to_text(&e))),
        "explainChain" => explain_chain(&a[0], opts(1)),
        "explainChainText" => text(explain_chain(&a[0], opts(1)).and_then(|e| chain_to_text(&e))),
        "consts" => Ok(json!({ "VERIFY_CHECK_ORDER": VERIFY_CHECK_ORDER, "MAX_TEXT": MAX_TEXT })),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn explain_vectors() {
    let cases = common::ref_cases("explain");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let got = std::panic::catch_unwind(|| run(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&fix(&c["out"])) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
