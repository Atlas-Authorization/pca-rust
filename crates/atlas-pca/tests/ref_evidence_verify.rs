//! Differential replay of `verify_evidence_bundle` (the dispute evidence replay: findings, summary, report digest) against the
//! TypeScript reference (test-data/ref-evidence-bundle-py.json.gz, 204 cases over the chargeback walkthrough and its tampered /
//! re-trusted variants). The whole findings report, `report_digest` included, is compared. `trust.verifiers` members are constant
//! verdicts. A reference throw only requires a refusal. Skipped (counted, must stay under 10%): cases with a lone surrogate.
mod common;
use atlas_pca::evidence_verify::verify_evidence_bundle;
use atlas_pca::serde_json::Value;

#[test]
fn evidence_bundle_matches_reference() {
    let cases = common::ref_cases("evidence-bundle-py");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        assert_eq!(c["fn"], "verifyEvidenceBundle");
        let args = c["args"].as_array().unwrap().clone();
        let bundle = args.first().cloned().unwrap_or(Value::Null);
        let trust = args.get(1).cloned().unwrap_or(Value::Null);
        let got = std::panic::catch_unwind(|| verify_evidence_bundle(&bundle, &trust)).unwrap_or_else(|_| Err("panic".into()));
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
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(5).cloned().collect::<Vec<_>>().join("\n"));
}
