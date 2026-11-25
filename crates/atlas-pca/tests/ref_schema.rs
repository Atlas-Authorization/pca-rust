//! Differential replay of the PCA wire schemas and the structural validator against the TypeScript reference
//! (test-data/ref-schema-dotnet.json.gz: the corpus whose `validate` takes (schemaOrName, value)). Error lists compare exactly,
//! in order. Cases with a lone surrogate (no Rust string) are skipped.
mod common;
use atlas_pca::schema::*;
use atlas_pca::serde_json::Value;

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "schemas" => Ok(all_schemas()),
        "validate" => {
            let schema = match &a[0] {
                Value::String(n) => named_schema(n).ok_or("unknown schema name")?,
                s => s.clone(),
            };
            validate(&schema, &a[1])
        }
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn schema_vectors() {
    let cases = {
        // the corpus is named for the lane that corrected it; load it through the shared helper
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test-data/ref-schema-dotnet.json.gz");
        let o = std::process::Command::new("gzip").arg("-dc").arg(path).output().expect("gzip");
        assert!(o.status.success());
        let doc: Value = atlas_pca::serde_json::from_str(&common::sanitize_lone_surrogates(&String::from_utf8(o.stdout).unwrap())).unwrap();
        doc["cases"].as_array().unwrap().clone()
    };
    assert_eq!(cases.len(), 3216, "the corpus total");
    assert_eq!(cases.iter().filter(|c| c["fn"] == "validate").count(), 3215);
    assert_eq!(cases.iter().filter(|c| c["fn"] == "schemas").count(), 1);
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let got = run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap());
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {got:?}", c["name"], c["out"]));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} lone-surrogate cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
