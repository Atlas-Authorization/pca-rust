//! R3-01 in the guest (guest version 9): a pure-PQ / hybrid session root verifies only under the VERIFIER's pin for its
//! signer (`intent_v2.session.pq_pins`), never under the PQ key named in the root's own `principals[]` (part of the presented
//! artifact: a pure ML-DSA signature uses no Ed25519 secret, so anyone naming a principal could sign a root under a key of
//! their choosing). Same rule, reasons and context validation as the TS reference and the nine native verifiers
//! (README "Session-root PQ keys come from the verifier's pin, never from S"). The differential checks against the
//! reference live in v2_session.rs / v2_pipeline.rs (fixtures/ts_v2_session.json, ts_v2_pipeline.json); this file pins the
//! named cases, the reasons and the journal binding of the pins.
use pca_zkvm_core::intent_session::{verify_session_root, verify_session_root_pinned};
use pca_zkvm_core::intent_v2::{ctx_digest, decide_intent_v2};
use pca_zkvm_core::{GUEST_VERSION, MIN_GUEST_VERSION};
use serde_json::{json, Value};

const NEEDS_PIN: &str = "needs the signer's PQ key pinned by the verifier (pq_pins)";
const PIN_MISMATCH: &str = "session root pq_pk does not match the verifier's pin for the signer";
const ENTRY_MISMATCH: &str = "session root pq_pk does not match the signer's principals entry";
const BAD_PINS_CTX: &str = "the session pq_pins must be an object of strings";

fn fx() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/ts_v2_session.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("fixture")).expect("fixture json")
}

fn named<'a>(list: &'a Value, name: &str) -> &'a Value {
    list.as_array().unwrap().iter().find(|c| c["name"] == name).unwrap_or_else(|| panic!("fixture case {name} missing"))
}

fn root_verdict(c: &Value) -> Result<(), String> {
    verify_session_root_pinned(&c["s"], c.get("pq_pins"))
}

fn session_check(c: &Value) -> Option<(bool, Option<String>)> {
    let d = decide_intent_v2(&c["pcactn"], &c["grant"], c.get("ctx").filter(|v| !v.is_null()), c["now"].as_f64().unwrap());
    d.checks.iter().find(|x| x.name == "intent_session").map(|x| (x.ok, x.reason.clone()))
}

/// The `accumulators` check's reason (these scenarios carry no accumulator claims, so the check fails either way: what
/// matters is whether it got past the bound root, which rule 15 shares with rule 13).
fn acc_reason(c: &Value) -> String {
    let d = decide_intent_v2(&c["pcactn"], &c["grant"], c.get("ctx").filter(|v| !v.is_null()), c["now"].as_f64().unwrap());
    let a = d.checks.iter().find(|x| x.name == "accumulators").expect("accumulators reported");
    a.reason.clone().unwrap_or_default()
}

#[test]
fn guest_version_9_marks_the_session_root_pin_rule() {
    assert_eq!(GUEST_VERSION, 9);
    assert_eq!(MIN_GUEST_VERSION, 9, "a version-8 receipt may have admitted an unpinned PQ session root");
}

#[test]
fn a_pq_root_verifies_only_under_the_verifiers_pin() {
    let d = fx();
    let roots = &d["roots"];
    for ok in ["pq-ml-dsa-65", "pq-hybrid", "pq-hybrid-nested", "pq-ml-dsa-87", "pq-hybrid-no-entry-pinned", "pq-ml-dsa-65-pin-extra-ok", "pq-hybrid-pin-extra-ok"] {
        let c = named(roots, ok);
        assert_eq!(c["verify_ok"], true, "{ok}: the reference accepts it");
        assert_eq!(root_verdict(c), Ok(()), "{ok}");
        // the same root WITHOUT the verifier's pin fails closed (the one-argument form has no pins)
        let e = verify_session_root(&c["s"]).unwrap_err();
        assert!(e.contains(NEEDS_PIN), "{ok}: {e}");
    }
    for (name, want) in [
        ("pq-ml-dsa-65-unpinned", NEEDS_PIN),
        ("pq-ml-dsa-65-pins-empty", NEEDS_PIN),
        ("pq-ml-dsa-65-pin-other-signer", NEEDS_PIN),
        ("pq-ml-dsa-65-pin-non-string", NEEDS_PIN),
        ("pq-ml-dsa-65-pin-null", NEEDS_PIN),
        ("pq-ml-dsa-65-pins-array", NEEDS_PIN),
        ("pq-ml-dsa-65-pins-null", NEEDS_PIN),
        ("pq-ml-dsa-65-pins-string", NEEDS_PIN),
        ("pq-hybrid-unpinned", NEEDS_PIN),
        ("pq-hybrid-pin-other-signer", NEEDS_PIN),
        ("pq-ml-dsa-65-pq-pk-missing-unpinned", NEEDS_PIN),
        ("pq-ml-dsa-65-pin-other-key", PIN_MISMATCH),
        ("pq-hybrid-pin-other-key", PIN_MISMATCH),
        ("pq-ml-dsa-65-pq-pk-missing", PIN_MISMATCH),
        ("pq-ml-dsa-65-principal-entry-mismatch", ENTRY_MISMATCH),
        ("pq-ml-dsa-65-pin-mismatch", ENTRY_MISMATCH),
        // the attack: a root signed under an attacker's ML-DSA key that names the real principal (and the attacker's key in
        // principals[]). The old rule (the entry is the pin) accepted it; now it needs the verifier's pin, and the real pin
        // refuses it.
        ("pq-attacker-root-unpinned", NEEDS_PIN),
        ("pq-attacker-root-real-pin", PIN_MISMATCH),
    ] {
        let c = named(roots, name);
        assert_eq!(c["verify_ok"], false, "{name}: the reference refuses it");
        let e = root_verdict(c).unwrap_err();
        assert!(e.contains(want), "{name}: want {want:?}, got {e:?}");
        assert!(c["verify_reason"].as_str().unwrap().contains(want), "{name}: reference reason {}", c["verify_reason"]);
    }
    let alg = verify_session_root(&named(roots, "pq-ml-dsa-65-unpinned")["s"]).unwrap_err();
    assert_eq!(
        alg,
        "session root suite 'ml-dsa-65' needs the signer's PQ key pinned by the verifier (pq_pins); the root's own principals entry proves nothing about who signed it"
    );
    // a pin the attacker chose (i.e. a verifier that pins whatever the root names) is exactly the old rule: it verifies
    assert_eq!(root_verdict(named(roots, "pq-attacker-root-attacker-pin")), Ok(()));
}

#[test]
fn an_ed25519_root_never_consults_the_pins() {
    let d = fx();
    for name in ["ed25519-pq-pins-ignored", "ed25519-pq-pins-malformed-ignored"] {
        let c = named(&d["roots"], name);
        assert_eq!(c["verify_ok"], true);
        assert_eq!(root_verdict(c), Ok(()), "{name}");
    }
}

#[test]
fn rules_13_and_15_read_session_pq_pins() {
    let d = fx();
    let steps = &d["steps"];
    for alg in ["ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "ml-dsa-87"] {
        let ok = named(steps, &format!("session-root-{alg}"));
        assert_eq!(ok["ok"], true, "{alg}: reference");
        assert_eq!(session_check(ok).map(|x| x.0), Some(true), "{alg}");
        let r = acc_reason(ok);
        assert!(!r.starts_with("session root"), "{alg}: rule 15 binds the same pinned root, got {r:?}");
        for (suffix, want) in [("unpinned", NEEDS_PIN), ("pin-other-signer", NEEDS_PIN), ("pin-mismatch", PIN_MISMATCH)] {
            let c = named(steps, &format!("session-root-{alg}-{suffix}"));
            assert_eq!(c["ok"], false, "{alg}-{suffix}: reference");
            let (got, reason) = session_check(c).unwrap();
            assert!(!got && reason.as_deref().is_some_and(|r| r.starts_with("session root: ") && r.contains(want)), "{alg}-{suffix}: {reason:?}");
            let r = acc_reason(c);
            assert!(r.starts_with("session root: ") && r.contains(want), "{alg}-{suffix}: accumulators share the bound root, got {r:?}");
        }
    }
    let c = named(steps, "session-root-ml-dsa-65-principal-entry-mismatch");
    assert!(session_check(c).unwrap().1.unwrap().contains(ENTRY_MISMATCH));
    let c = named(steps, "root-pq-principal-entry-only");
    assert!(session_check(c).unwrap().1.unwrap().contains(NEEDS_PIN));
    assert_eq!(session_check(named(steps, "session-root-ed25519-pq-pins-ignored")).map(|x| x.0), Some(true));
}

#[test]
fn a_malformed_pq_pins_context_fails_intent_session() {
    let d = fx();
    let steps = &d["steps"];
    for name in ["ctx-session-pq-pins-null", "ctx-session-pq-pins-array", "ctx-session-pq-pins-string", "ctx-session-pq-pins-non-string", "ctx-session-pq-pins-null-value", "ctx-session-pq-pins-nested"] {
        let c = named(steps, name);
        assert_eq!(c["ok"], false, "{name}: reference");
        assert_eq!(session_check(c), Some((false, Some(BAD_PINS_CTX.to_string()))), "{name}");
    }
    for name in ["ctx-session-pq-pins-empty", "ctx-session-pq-pins-other-ok"] {
        assert_eq!(session_check(named(steps, name)).map(|x| x.0), Some(true), "{name}");
    }
}

#[test]
fn the_journal_binds_which_pins_were_used() {
    // pq_pins is part of the verifier context whose hashCanonical the journal commits (context.intent_v2.ctx_digest, pinned by
    // ExpectedContext::intent_v2_ctx_digest): another pin set, or none, is another statement
    let d = fx();
    let ctx = named(&d["steps"], "session-root-ml-dsa-65")["ctx"].clone();
    let base = ctx_digest(&ctx);
    let mut none = ctx.clone();
    none["session"].as_object_mut().unwrap().remove("pq_pins");
    let mut other = ctx.clone();
    other["session"]["pq_pins"] = json!({"x": "y"});
    let mut empty = ctx.clone();
    empty["session"]["pq_pins"] = json!({});
    let ds = [base.clone(), ctx_digest(&none), ctx_digest(&other), ctx_digest(&empty)];
    for i in 0..ds.len() {
        for j in i + 1..ds.len() {
            assert_ne!(ds[i], ds[j], "pin sets {i} and {j} must commit to different ctx digests");
        }
    }
    assert_eq!(base, ctx_digest(&ctx), "deterministic");
}
