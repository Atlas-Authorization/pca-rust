//! RT-06 on real receipts: the committed receipt's journal commits the evaluated context, the verifier API
//! requires an expectation, and a backdated clock / swapped subject / swapped env / other rate history /
//! other risk inputs fail even though the receipt itself verifies. PoC: redteam/stark/src/zkvm_unbound_context.rs.

use pca_zkvm_core::context::{check_context, ContextMismatch, ExpectedContext, LegacyDecision};
use pca_zkvm_core::Decision;
use pca_zkvm_verify::{verify_with_context, VerifyError};
use risc0_zkvm::sha::Digest;
use risc0_zkvm::Receipt;
use serde_json::{json, Value};

fn path(rel: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures").join(rel)
}
fn read(rel: &str) -> Vec<u8> {
    std::fs::read(path(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}
fn image_id(rel: &str) -> Digest {
    let v: Value = serde_json::from_slice(&read(rel)).unwrap();
    let w = v["image_id_words"].as_array().unwrap();
    Digest::from(core::array::from_fn::<u32, 8, _>(|i| w[i].as_u64().unwrap() as u32))
}
fn input() -> Value {
    serde_json::from_slice(&read("decide_input.sample.json")).unwrap()
}
fn expected(v: &Value, tol: f64) -> ExpectedContext {
    ExpectedContext::from_input_json(&v.to_string(), tol).unwrap()
}
fn receipts() -> Vec<(&'static str, Receipt)> {
    ["receipt_succinct.bin", "receipt_groth16.bin"]
        .into_iter()
        .map(|f| (f, bincode::deserialize::<Receipt>(&read(f)).unwrap()))
        .collect()
}

#[test]
fn the_committed_journal_carries_the_context_and_equals_the_pure_decision() {
    let want: Decision = serde_json::from_slice(&read("public_journal.json")).unwrap();
    let pure = pca_zkvm_core::decide_from_str(&input().to_string());
    assert_eq!(want, pure);
    for (f, r) in receipts() {
        let d: Decision = r.journal.decode().unwrap_or_else(|e| panic!("{f}: {e}"));
        assert_eq!(d, want, "{f}: journal must equal the committed statement incl. context");
        assert_eq!(d.context.now_bits, 1_760_000_000_000f64.to_bits(), "{f}: now is in the journal");
    }
}

#[test]
fn verify_with_context_accepts_the_true_context() {
    let id = image_id("image_id.json");
    for (f, r) in receipts() {
        verify_with_context(&r, id, &expected(&input(), 0.0)).unwrap_or_else(|e| panic!("{f}: {e:?}"));
    }
}

#[test]
fn a_backdated_now_is_rejected_by_the_verifier_even_though_the_receipt_verifies() {
    let id = image_id("image_id.json");
    // The receipt proves a decision at now = 1.76e12. The honest clock is a year later (the grant's expiry has
    // passed); the old journal carried no `now`, so this was indistinguishable from a fresh receipt.
    let mut e = expected(&input(), 60_000.0);
    e.now = 1_760_000_000_000.0 + 365.0 * 86_400_000.0;
    for (f, r) in receipts() {
        r.verify(id).expect("the receipt itself is valid");
        match verify_with_context(&r, id, &e) {
            Err(VerifyError::Context(ContextMismatch::Now { .. })) => {}
            other => panic!("{f}: backdated now must fail, got {other:?}"),
        }
    }
}

#[test]
fn swapped_subject_env_rate_history_and_risk_inputs_are_rejected() {
    let id = image_id("image_id.json");
    let base = input();
    let cases: Vec<(&str, Box<dyn Fn(&mut Value)>, fn(&ContextMismatch) -> bool)> = vec![
        ("subject", Box::new(|v| v["subject"] = json!({"role": "admin"})), |m| *m == ContextMismatch::Subject),
        ("env", Box::new(|v| v["env"] = json!({"current_device": "dev-EVIL"})), |m| *m == ContextMismatch::Env),
        ("rate history", Box::new(|v| v["recent_action_times"] = json!([])), |m| *m == ContextMismatch::RateHistory),
        ("delegation depth", Box::new(|v| { let c = v["chain"].as_array().unwrap()[..1].to_vec(); v["chain"] = json!(c); }), |m| *m == ContextMismatch::DelegationDepth),
        ("grant ref", Box::new(|v| v["chain"][0]["id"] = json!("other")), |m| *m == ContextMismatch::GrantRef),
        ("plan node", Box::new(|v| v["pcactn"]["plan"]["node_id"] = json!("n2")), |m| *m == ContextMismatch::NodeId),
        ("risk inputs", Box::new(|v| v["risk_inputs_scaled"] = json!([0, 0, 0, 0, 0, 0])), |m| *m == ContextMismatch::RiskInputs),
        ("budget", Box::new(|v| v["budget_scaled"] = json!(1)), |m| *m == ContextMismatch::Budget),
    ];
    let r = &receipts()[0].1;
    for (name, edit, is_expected) in cases {
        let mut v = base.clone();
        edit(&mut v);
        match verify_with_context(r, id, &expected(&v, 0.0)) {
            Err(VerifyError::Context(m)) if is_expected(&m) => {}
            other => panic!("{name}: expected the matching context mismatch, got {other:?}"),
        }
    }
}

#[test]
fn legacy_journals_have_no_context_and_are_refused_by_the_context_api() {
    for (rel, id_rel) in [
        ("legacy/receipt_succinct.bin", "legacy/image_id.json"),
        ("legacy/dcf198fc/receipt_succinct.bin", "legacy/dcf198fc/image_id.json"),
    ] {
        let r: Receipt = bincode::deserialize(&read(rel)).unwrap();
        let id = image_id(id_rel);
        r.verify(id).unwrap_or_else(|e| panic!("{rel} still verifies under its own id: {e}"));
        let d: LegacyDecision = r.journal.decode().unwrap_or_else(|e| panic!("{rel} decodes as the legacy journal: {e}"));
        assert_eq!(d.allow, 1);
        assert!(r.journal.decode::<Decision>().is_err(), "{rel}: a legacy journal must not decode as a context-bearing Decision");
        // R6-ZK-06: refused before the journal is even read, the image id is on the deny-list
        assert!(matches!(verify_with_context(&r, id, &expected(&input(), 0.0)), Err(VerifyError::Superseded(_))));
    }
}

#[test]
fn the_pre_r3_context_journal_is_refused_by_the_current_context_api() {
    // the third generation committed a context, but with the old layout (free delegation_depth_bits, no grant_ref/node_id)
    let r: Receipt = bincode::deserialize(&read("legacy/6b0ac893/receipt_succinct.bin")).unwrap();
    let id = image_id("legacy/6b0ac893/image_id.json");
    r.verify(id).expect("verifies under its own id");
    assert!(verify_with_context(&r, id, &expected(&input(), 0.0)).is_err(), "pre-R3 receipts must not satisfy the current API");
}

#[test]
fn the_pre_r4_context_journal_is_refused_by_the_current_context_api() {
    // the round-3 guest committed a context WITHOUT the PCActn's ver/iat/exp/aud/counter (R4-04): its journal does not decode
    // as the current layout, and a verifier following the current API therefore cannot be satisfied by it
    let r: Receipt = bincode::deserialize(&read("legacy/ce0b5423/receipt_succinct.bin")).unwrap();
    let id = image_id("legacy/ce0b5423/image_id.json");
    r.verify(id).expect("verifies under its own id");
    assert!(r.journal.decode::<Decision>().is_err(), "the pre-R4 journal must not decode as the current Decision");
    assert!(matches!(verify_with_context(&r, id, &expected(&input(), 0.0)), Err(VerifyError::Superseded(_))));
}

#[test]
fn the_pre_r5_and_pre_r6_receipts_are_refused_even_by_a_verifier_that_pins_their_image_id() {
    // R6-ZK-06: the round-4 (1c1b8bbd) and round-5 (e922536c) guests still verify under their own ids, and a verifier that kept
    // one of those ids pinned used to accept them; `verify_with_context` now refuses a superseded image id outright, and under
    // the current id they fail as receipts
    let cur = image_id("image_id.json");
    for g in ["1c1b8bbd", "e922536c"] {
        for f in ["receipt_succinct.bin", "receipt_groth16.bin"] {
            let rel = format!("legacy/{g}/{f}");
            let r: Receipt = bincode::deserialize(&read(&rel)).unwrap();
            let old = image_id(&format!("legacy/{g}/image_id.json"));
            r.verify(old).unwrap_or_else(|e| panic!("{rel} verifies under its own id: {e}"));
            assert!(matches!(verify_with_context(&r, old, &expected(&input(), 0.0)), Err(VerifyError::Superseded(_))), "{rel}");
            assert!(r.verify(cur).is_err());
            assert!(matches!(verify_with_context(&r, cur, &expected(&input(), 0.0)), Err(VerifyError::Receipt(_))), "{rel}");
        }
    }
}

#[test]
fn r6_zk06_the_journal_carries_the_guest_version_and_an_older_one_is_refused() {
    let id = image_id("image_id.json");
    for (f, r) in receipts() {
        let d: Decision = r.journal.decode().unwrap_or_else(|e| panic!("{f}: {e}"));
        assert_eq!(d.guest_version, pca_zkvm_core::GUEST_VERSION, "{f}");
        assert!(d.guest_version >= pca_zkvm_core::MIN_GUEST_VERSION);
        verify_with_context(&r, id, &expected(&input(), 0.0)).unwrap_or_else(|e| panic!("{f}: {e:?}"));
        let mut old = d.clone();
        old.guest_version = pca_zkvm_core::MIN_GUEST_VERSION - 1;
        assert_eq!(
            check_context(&old, &expected(&input(), 0.0)),
            Err(ContextMismatch::GuestVersion { proven: pca_zkvm_core::MIN_GUEST_VERSION - 1, minimum: pca_zkvm_core::MIN_GUEST_VERSION })
        );
    }
}

#[test]
fn a_legacy_receipt_does_not_verify_under_the_current_image_id() {
    let cur = image_id("image_id.json");
    for rel in ["legacy/receipt_succinct.bin", "legacy/dcf198fc/receipt_succinct.bin", "legacy/receipt_groth16.bin", "legacy/dcf198fc/receipt_groth16.bin", "legacy/6b0ac893/receipt_succinct.bin", "legacy/6b0ac893/receipt_groth16.bin", "legacy/ce0b5423/receipt_succinct.bin", "legacy/ce0b5423/receipt_groth16.bin", "legacy/1c1b8bbd/receipt_succinct.bin", "legacy/1c1b8bbd/receipt_groth16.bin", "legacy/e922536c/receipt_succinct.bin", "legacy/e922536c/receipt_groth16.bin"] {
        if rel.contains("1c1b8bbd") || rel.contains("e922536c") {
            let r: Receipt = bincode::deserialize(&read(rel)).unwrap();
            assert!(r.verify(cur).is_err(), "{rel} must not verify under the current id");
            continue;
        }
        let r: Receipt = bincode::deserialize(&read(rel)).unwrap();
        assert!(r.journal.decode::<Decision>().is_err());
        assert!(r.verify(cur).is_err(), "{rel} must not verify under the current id");
    }
}

#[test]
fn the_journal_round_trips_through_the_zkvm_codec_for_every_field() {
    let d = pca_zkvm_core::decide_from_str(&input().to_string());
    let words = risc0_zkvm::serde::to_vec(&d).unwrap();
    let back: Decision = risc0_zkvm::serde::from_slice(&words).unwrap();
    assert_eq!(back, d);
    // and with absent optionals
    let mut v = input();
    for k in ["subject", "env", "recent_action_times", "tool_binding"] {
        v.as_object_mut().unwrap().remove(k);
    }
    let d2 = pca_zkvm_core::decide_from_str(&v.to_string());
    let back2: Decision = risc0_zkvm::serde::from_slice(&risc0_zkvm::serde::to_vec(&d2).unwrap()).unwrap();
    assert_eq!(back2, d2);
    assert!(check_context(&back, &expected(&input(), 0.0)).is_ok());
}

#[test]
fn r4_04_the_journal_commits_the_pcactn_freshness_facts_and_the_verifier_must_pin_them() {
    let id = image_id("image_id.json");
    for (f, r) in receipts() {
        let d: Decision = r.journal.decode().unwrap();
        let c = &d.context;
        assert_eq!((c.pcactn_ver, c.pcactn_iat, c.pcactn_exp, c.pcactn_aud.as_str(), c.pcactn_counter), (2, 1_760_000_000_000, 1_760_001_200_000, "atlas-instance-1", 0), "{f}");
        let ok = expected(&input(), 0.0);
        verify_with_context(&r, id, &ok).unwrap_or_else(|e| panic!("{f}: {e:?}"));
        let cases: Vec<(&str, Box<dyn Fn(&mut ExpectedContext)>, ContextMismatch)> = vec![
            ("foreign audience", Box::new(|e| e.pcactn_aud = "another-instance".into()), ContextMismatch::PcactnAud),
            ("version", Box::new(|e| e.pcactn_ver = 1), ContextMismatch::PcactnVersion),
            ("iat", Box::new(|e| e.pcactn_iat -= 1000), ContextMismatch::PcactnIat),
            ("exp", Box::new(|e| e.pcactn_exp += 1000), ContextMismatch::PcactnExp),
            ("counter", Box::new(|e| e.pcactn_counter = 9), ContextMismatch::PcactnCounter),
        ];
        for (name, edit, want) in cases {
            let mut e = ok.clone();
            edit(&mut e);
            match verify_with_context(&r, id, &e) {
                Err(VerifyError::Context(m)) if m == want => {}
                other => panic!("{f}: {name}: expected {want:?}, got {other:?}"),
            }
        }
        // the receipt is genuine and was proven at an honest `now`, but the verifier's clock is past the PCActn's `exp`
        let mut late = ok.clone();
        late.now = 1_760_001_200_001.0;
        late.now_tolerance_ms = 1.0e9;
        match verify_with_context(&r, id, &late) {
            Err(VerifyError::Context(ContextMismatch::PcactnExpired)) => {}
            other => panic!("{f}: an expired PCActn must be refused by the verifier clock, got {other:?}"),
        }
    }
}
