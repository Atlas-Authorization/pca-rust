//! Differential replay of the dispute evidence bundle (shape validation, normal form, commitments-only form, digest, reference,
//! anchor leaves, accumulator cap reader, trust-input validators) against the TypeScript reference (test-data/ref-evidence.json.gz).
//! A reference throw only requires a refusal. Not covered (not in this corpus or not ported): verifyEvidenceBundle, the COSE signed
//! statement (a separate java-extra corpus).
mod common;
use atlas_pca::evidence::*;
use atlas_pca::serde_json::{json, Value};

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "consts" => {
            Ok(json!({"EVIDENCE_DOMAIN": EVIDENCE_DOMAIN, "EVIDENCE_REPORT_DOMAIN": EVIDENCE_REPORT_DOMAIN, "EVIDENCE_CONTENT_TYPE": EVIDENCE_CONTENT_TYPE}))
        }
        "bundleShapeError" => Ok(bundle_shape_error(&a[0]).map(Value::String).unwrap_or(Value::Null)),
        "normalizeBundle" => normalize_bundle(&a[0]),
        "buildEvidenceBundle" => build_evidence_bundle(&a[0]),
        "commitmentForm" => commitment_form(&a[0]),
        "evidenceDigest" => evidence_digest(&a[0]).map(Value::String),
        "evidenceRef" => evidence_ref(&a[0]),
        "evidenceAnchorCommit" => evidence_anchor_commit(&a[0]).map(Value::String),
        "anchorCommit" => anchor_commit(&a[0], &a[1]).map(Value::String),
        "capOf" => cap_of(&a[0], &a[1], &a[2]).map(|c| c.map(|n| json!(n)).unwrap_or(Value::Null)),
        "principalsTrustError" => Ok(principals_trust_error(a.first()).map(Value::String).unwrap_or(Value::Null)),
        "accTrustError" => Ok(acc_trust_error(a.first()).map(Value::String).unwrap_or(Value::Null)),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn evidence_vectors() {
    let cases = common::ref_cases("evidence");
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
