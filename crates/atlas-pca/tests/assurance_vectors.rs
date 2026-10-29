//! Assurance labels (T8 / B7): replays assurance-vectors.json (`signature_level`, `report`, `requirement`, `multi_root`) against
//! the real functions, then proves the gate inside `authorize`: an unmet requirement denies before any replay state is
//! written, a PCActn carrying `bond_ref` is `unsupported` and denied unless allowed, and results carry the report.
mod common;

use atlas_pca::*;
use common::load;
use serde_json::{json, Value};

fn statuses(v: &Value) -> Vec<(String, CheckStatus)> {
    v.as_object().unwrap().iter().map(|(k, s)| (k.clone(), CheckStatus::parse(s.as_str().unwrap()).unwrap())).collect()
}

fn hooks_of(v: &Value) -> AssuranceHooks {
    let h = |k: &str| v.get("hooks").and_then(|h| h.get(k)).map(|x| HookDecl::from_json(x).unwrap_or_else(|| panic!("hook {k}")));
    AssuranceHooks { attestation: h("attestation"), zk: h("zk"), threshold: h("threshold"), revocation: h("revocation") }
}

#[test]
fn signature_level_vectors() {
    let d = load("assurance-vectors.json");
    let rows = d["signature_level"].as_array().unwrap();
    assert_eq!(rows.len(), 14);
    for v in rows {
        let alg = (!v["alg"].is_null()).then(|| &v["alg"]);
        assert_eq!(signature_level(alg), v["level"].as_str().unwrap(), "{v}");
    }
}

#[test]
fn report_vectors() {
    let d = load("assurance-vectors.json");
    let rows = d["report"].as_array().unwrap();
    assert_eq!(rows.len(), 37);
    for v in rows {
        let name = v["name"].as_str().unwrap();
        let checks = statuses(&v["checks"]);
        let hooks = hooks_of(v);
        let attestation_hook = v.get("attestation_hook").map(|x| HookDecl::from_json(x).unwrap());
        let degraded: Vec<(String, String)> = v.get("degraded").and_then(Value::as_object).map(|o| o.iter().map(|(k, w)| (k.clone(), w.as_str().unwrap().to_string())).collect()).unwrap_or_default();
        let got = assurance_report(&AssuranceSources {
            checks: &checks,
            pcactn: v.get("pcactn"),
            hooks: Some(&hooks),
            attestation_hook: attestation_hook.as_ref(),
            threshold_t: v["threshold_t"].as_f64(),
            allow_unbound_pq: v["allow_unbound_pq"] == json!(true),
            degraded: &degraded,
        });
        assert_eq!(got.to_json(), v["report"], "{name}");
        // the report survives its own JSON form
        assert_eq!(AssuranceReport::from_json(&v["report"]).unwrap(), got, "{name}: round trip");
    }
}

#[test]
fn requirement_vectors() {
    let d = load("assurance-vectors.json");
    let rows = d["requirement"].as_array().unwrap();
    assert_eq!(rows.len(), 47);
    for v in rows {
        let name = v["name"].as_str().unwrap();
        let report = AssuranceReport::from_json(&v["report"]).unwrap_or_else(|| panic!("{name}: report"));
        let got = unmet_assurance(&report, &AssuranceRequirement::from_json(&v["require"]));
        assert_eq!(got.as_deref(), v["unmet"].as_str(), "{name}");
    }
}

#[test]
fn multi_root_vectors() {
    let d = load("assurance-vectors.json");
    let rows = d["multi_root"].as_array().unwrap();
    assert_eq!(rows.len(), 10);
    for v in rows {
        let roots: Vec<RootDecl> = v["roots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| RootDecl { label: Some(AssuranceLabel::new(r["level"].as_str().unwrap())), required: r["required"] == json!(true) })
            .collect();
        assert_eq!(multi_root_level(&roots, v["threshold"].as_i64().unwrap()), v["level"].as_str().unwrap(), "{}", v["name"]);
    }
}

#[test]
fn a_label_comes_from_the_hook_that_declares_it() {
    struct Snp;
    impl AssuranceLabelled for Snp {
        fn assurance_label(&self) -> Option<AssuranceLabel> {
            Some(AssuranceLabel::new("hardware").with_vendor("amd-sev-snp"))
        }
    }
    struct Bare;
    impl AssuranceLabelled for Bare {
        fn assurance_label(&self) -> Option<AssuranceLabel> {
            None
        }
    }
    assert_eq!(HookDecl::of(&Snp), HookDecl::Labelled(AssuranceLabel::new("hardware").with_vendor("amd-sev-snp")));
    assert_eq!(HookDecl::of(&Bare), HookDecl::Unlabelled);
}

// ---- inside authorize ------------------------------------------------------------------------------------------------

fn fixtures() -> Value {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/authorize-fixtures.json")).unwrap();
    strict_parse(&text).unwrap()
}

#[derive(Default)]
struct Cfg<'a> {
    require_assurance: Option<&'a AssuranceRequirement>,
    allow_unsupported: &'a [&'a str],
    require: &'a [&'a str],
}

fn run(store: &MemoryStateStore, mutate: impl FnOnce(&mut Value), cfg: Cfg<'_>) -> AuthorizeResult {
    let d = fixtures();
    let (grant, s) = (d["cases"][0]["grant"].clone(), &d["cases"][0]["steps"][0]);
    let mut pcactn = s["pcactn"].clone();
    mutate(&mut pcactn);
    let op = Operation::from_json(&s["operation"]).unwrap();
    let resolve = move |_: &str| Ok::<_, String>(Some(grant.clone()));
    let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let inp = AuthorizeInput {
        operation: Some(&op),
        audience: d["audience"].as_str().unwrap(),
        resolve_grant: Some(&resolve),
        state_store: Some(store),
        is_revoked: Some(&not_revoked),
        now: d["now"].as_i64(),
        plan: Some("single-step"),
        require_assurance: cfg.require_assurance,
        allow_unsupported: cfg.allow_unsupported,
        require: cfg.require,
        provenance_mediators: &common::harness_pins(),
        provenance_bundle: Some(&common::principal_direct),
        ..Default::default()
    };
    authorize(Some(&pcactn), &inp)
}

#[test]
fn every_result_carries_the_report() {
    let r = run(&MemoryStateStore::new(), |_| {}, Cfg::default());
    assert!(r.allow, "{:?}", r.reasons);
    let leaf = r.assurance.get("leaf_signature").expect("leaf_signature");
    assert_eq!((leaf.outcome, leaf.level.as_deref()), (CheckStatus::Pass, Some("ed25519")));
    assert_eq!(r.assurance.get("cap_chain").map(|c| c.outcome), Some(CheckStatus::Pass));
    assert_eq!(r.assurance.get("replay").map(|c| c.outcome), Some(CheckStatus::Pass));
    let refused = authorize(None, &AuthorizeInput::default());
    assert!(!refused.allow);
    assert_eq!(refused.assurance.get("authorize_config").map(|c| c.outcome), Some(CheckStatus::Fail));
}

#[test]
fn an_unmet_requirement_denies_before_the_replay_counter_is_spent() {
    let store = MemoryStateStore::new();
    let req = AssuranceRequirement { signature_pq: true, ..Default::default() };
    let denied = run(&store, |_| {}, Cfg { require_assurance: Some(&req), ..Default::default() });
    assert!(!denied.allow);
    assert_eq!(denied.check("assurance"), Some(CheckStatus::Fail));
    assert!(denied.reasons.iter().any(|r| r == "assurance: post-quantum signatures required but leaf_signature is ed25519"), "{:?}", denied.reasons);
    // the counter was never claimed: the same PCActn is still accepted without the requirement
    let again = run(&store, |_| {}, Cfg::default());
    assert!(again.allow, "{:?}", again.reasons);
}

#[test]
fn a_met_requirement_passes_and_is_reported() {
    let req = AssuranceRequirement::default();
    let r = run(&MemoryStateStore::new(), |_| {}, Cfg { require_assurance: Some(&req), ..Default::default() });
    assert!(r.allow);
    assert_eq!(r.check("assurance"), Some(CheckStatus::Pass));
    assert_eq!(r.assurance.get("assurance").map(|c| c.outcome), Some(CheckStatus::Pass));
}

#[test]
fn bond_ref_is_unsupported_and_denied_unless_allowed() {
    let with_bond = |p: &mut Value| p["bond_ref"] = json!("b1");
    // the member changes the signed body, so the signature check fails too; the verifier still reports `bond` on the member
    let denied = run(&MemoryStateStore::new(), with_bond, Cfg::default());
    assert!(!denied.allow);
    assert_eq!(denied.check("bond"), Some(CheckStatus::Unsupported));
    assert!(denied.reasons.iter().any(|r| r.starts_with("bond: unsupported: the PCActn carries a feature this verifier does not implement")), "{:?}", denied.reasons);
    assert_eq!(denied.assurance.get("bond").map(|c| (c.outcome, c.reason.clone())), Some((CheckStatus::Unsupported, Some("bond verification is not implemented by this verifier".to_string()))));
    let allowed = run(&MemoryStateStore::new(), with_bond, Cfg { allow_unsupported: &["bond"], ..Default::default() });
    // still reported unsupported (never a pass) but no longer a reason of its own
    assert_eq!(allowed.check("bond"), Some(CheckStatus::Unsupported));
    assert!(!allowed.reasons.iter().any(|r| r.starts_with("bond:")), "{:?}", allowed.reasons);
}

#[test]
fn an_unsupported_check_a_policy_requires_is_a_failed_requirement() {
    let with_bond = |p: &mut Value| p["bond_ref"] = json!("b1");
    let denied = run(&MemoryStateStore::new(), with_bond, Cfg { allow_unsupported: &["bond"], require: &["bond"], ..Default::default() });
    assert_eq!(denied.check("bond"), Some(CheckStatus::Fail));
    assert!(denied.reasons.iter().any(|r| r == "bond: required check is unsupported (default-deny: not enforced by this resource server)"), "{:?}", denied.reasons);
}
