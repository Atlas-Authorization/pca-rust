//! Differential replay of the NL-to-policy grounding half (nlPrompt, parseNLPolicy, the NL facade compiler alone and inside a panel)
//! against the TypeScript reference (test-data/ref-intent-nl-java.json.gz). A catalog argument is a list of extra actions that
//! replace the built-in entry of the same verb in place, or are appended.
mod common;
use atlas_pca::facade::{builtin_catalog, ActionSpec};
use atlas_pca::intent_kit::compilers::{run_compilers, IntentCompiler};
use atlas_pca::nl_policy::{compile_nl_facade, nl_prompt, parse_nl_policy};
use atlas_pca::serde_json::{json, Value};

fn catalog_of(extras: &Value) -> Vec<ActionSpec> {
    let mut cat = builtin_catalog();
    for e in extras.as_array().into_iter().flatten() {
        let s = |k: &str| e.get(k).and_then(Value::as_str).map(String::from);
        let (connector, action) = (s("connector").unwrap_or_default(), s("action").unwrap_or_default());
        let spec = ActionSpec {
            verb: format!("{connector}.{action}"),
            connector,
            action,
            reversibility: s("reversibility").unwrap_or_default(),
            blast_radius: e.get("blastRadius").and_then(Value::as_f64).unwrap_or(0.0),
            amount_field: s("amountField").filter(|a| !a.is_empty()),
            resource: None,
            aliases: e.get("aliases").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(String::from).collect(),
            description: s("description").unwrap_or_default(),
        };
        match cat.iter().position(|c| c.verb == spec.verb) {
            Some(i) => cat[i] = spec,
            None => cat.push(spec),
        }
    }
    cat
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let text = |i: usize| a[i].as_str().unwrap_or_default().to_string();
    match f {
        "nlPrompt" => Ok(json!(nl_prompt(&text(0), &catalog_of(&a[1])))),
        "parseNLPolicy" => Ok(parse_nl_policy(&text(0), &catalog_of(&a[1]))),
        "nlCompile" => {
            let cat = catalog_of(&a[2]);
            Ok(json!({"prompt": nl_prompt(&text(0), &cat), "output": compile_nl_facade("nl", "fam", &text(1), &cat)?}))
        }
        "nlRun" => {
            let raw = text(1);
            let c = if raw == "THROWS" {
                IntentCompiler::throws("nl", "fam", "llm down")
            } else {
                IntentCompiler::nl_facade_with("nl", "fam", &raw, catalog_of(&a[2]))
            };
            Ok(run_compilers(&json!({"text": text(0)}), &[c]))
        }
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn nl_policy_vectors() {
    let cases = common::ref_cases("intent-nl-java");
    assert!(cases.len() >= 250, "corpus shrank: {}", cases.len());
    let mut bad = vec![];
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        let got = std::panic::catch_unwind(|| run(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(8).cloned().collect::<Vec<_>>().join("\n"));
}
