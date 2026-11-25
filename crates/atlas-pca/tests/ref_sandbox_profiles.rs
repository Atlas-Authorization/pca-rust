//! Differential replay of the sandbox policy compiler and the seccomp / Landlock / macOS profile generators and the confinement
//! helper flags against the TypeScript reference (test-data/ref-sandbox.json.gz, cases `policyFromNeeds`, `compilePolicy`,
//! `seccompProfile`, `landlockRuleset`, `macosProfile`, `confineArgs`). A reference throw only requires a refusal.
mod common;
use atlas_pca::{AuthorizedOperation, Operation};
use atlas_pca::sandbox_profiles::*;
use atlas_pca::serde_json::{json, Value};

fn compile(spec: &Value) -> Result<Value, String> {
    let owned: Vec<(Option<AuthorizedOperation>, Operation)> = spec["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|it| {
            let b = &it["bind"];
            let bound = (it["allow"] == true && b.is_object()).then(|| AuthorizedOperation {
                verb: b["verb"].as_str().unwrap().into(),
                resource: b["resource"].as_str().unwrap().into(),
                params_digest: atlas_pca::hash_canonical_strict(&b["params"]).unwrap(),
                id: b.get("id").and_then(Value::as_str).unwrap_or("op").into(),
            });
            let o = &it["operation"];
            (bound, Operation::new(o["verb"].as_str().unwrap_or(""), o["resource"].as_str().unwrap_or(""), o["params"].clone()))
        })
        .collect();
    let items: Vec<(Option<&AuthorizedOperation>, &Operation)> = owned.iter().map(|(b, o)| (b.as_ref(), o)).collect();
    let needs = spec["needs"].clone();
    compile_policy(&items, |op| needs.get(format!("{} {}", op.verb, op.resource)).cloned(), spec.get("proxyPort"))
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "policyFromNeeds" => policy_from_needs(&a[0], a.get(1)),
        "compilePolicy" => compile(&a[0]),
        "seccompProfile" => Ok(seccomp_profile(&a[0])),
        "landlockRuleset" => Ok(landlock_ruleset(&a[0])),
        "macosProfile" => Ok(json!(macos_profile(&a[0]))),
        "confineArgs" => Ok(json!(confine_args(&a[0]))),
        _ => Err("skip".into()),
    }
}

#[test]
fn sandbox_profiles_vectors() {
    let fns = ["policyFromNeeds", "compilePolicy", "seccompProfile", "landlockRuleset", "macosProfile", "confineArgs"];
    let cases = common::ref_cases("sandbox");
    let (mut bad, mut ran) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if !fns.contains(&f) || common::has_lone(&c["args"]) {
            continue;
        }
        ran += 1;
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
    assert!(ran > 500, "only {ran} cases replayed");
    assert!(bad.is_empty(), "{} cases differ:\n{}", bad.len(), bad.join("\n"));
}
