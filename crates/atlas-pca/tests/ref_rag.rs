//! Differential replay of the pca-rag pure core (aclsFromMetadata, compilePolicy, principalFromPCActn, filterDocuments with its
//! digest-bound decision record and the OpenFGA translation) against the TypeScript reference (test-data/ref-rag.json.gz).
//! A reference throw only requires a refusal. Skipped (counted, must stay under 10%): cases with a lone surrogate (no Rust string).
//! Not replayed: the framework-shaped retriever wrappers (adapters, not in the pure core; the corpus has none).
mod common;
use atlas_pca::rag::*;
use atlas_pca::serde_json::{json, Value};

static NULL: Value = Value::Null;

fn arg(a: &[Value], i: usize) -> &Value {
    a.get(i).unwrap_or(&NULL)
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "aclsFromMetadata" => Ok(Value::Array(acls_from_metadata(arg(a, 0), arg(a, 1)))),
        "compilePolicy" => compile_policy(arg(a, 0)),
        "principalFromPCActn" => principal_from_pcactn(arg(a, 0), a.get(1)),
        "filterDocuments" => {
            let r = filter_documents(arg(a, 0), arg(a, 1), arg(a, 2))?;
            Ok(json!({ "documents": r.documents, "decision": r.decision }))
        }
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn rag_vectors() {
    let cases = common::ref_cases("rag");
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

#[test]
fn rag_fails_closed_without_acl() {
    let r = filter_documents(&json!("user:alice"), &json!([{ "id": "d" }]), &json!([{ "verb": "can_view", "resource": "document:*" }])).unwrap();
    assert!(r.documents.is_empty());
    assert_eq!(r.decision["droppedIds"], json!(["d"]));
}
