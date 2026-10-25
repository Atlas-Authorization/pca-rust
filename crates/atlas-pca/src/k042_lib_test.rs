//! Direct unit tests of lib.rs internals the corpus reaches only indirectly: the PQ length gates, the suite refusal wording
//! and (feature `less`) the LESS signature-length rule.
use super::*;
use serde_json::json;

#[test]
fn pq_length_gates_refuse_before_any_verification() {
    for pq in [Pq::MlDsa65, Pq::MlDsa87, Pq::Slh128f, Pq::Slh256s, Pq::FnDsa512, Pq::FnDsa1024] {
        let (pk_len, sig_len) = pq.lens();
        assert!(pq.sig_len_ok(sig_len));
        assert!(!pq.sig_len_ok(sig_len + 1));
        assert!(!pq.sig_len_ok(sig_len - 1));
        let (pk, sig) = (vec![7u8; pk_len], vec![9u8; sig_len]);
        // right lengths, garbage content: no panic, no verification
        assert!(!pq_verify(pq, &pk, b"m", &sig));
        // each length wrong alone
        assert!(!pq_verify(pq, &pk[1..], b"m", &sig));
        assert!(!pq_verify(pq, &[pk.clone(), vec![0]].concat(), b"m", &sig));
        assert!(!pq_verify(pq, &pk, b"m", &sig[1..]));
        assert!(!pq_verify(pq, &pk, b"m", &[sig.clone(), vec![0]].concat()));
        assert!(!pq_verify(pq, &[], b"m", &[]));
        // the base64url wrapper: key length, signature length, encoding
        let b = |x: &[u8]| URL_SAFE_NO_PAD.encode(x);
        assert!(!pq_verify_b64u(pq, &b(&pk), b"m", Some(&json!(b(&sig)))));
        assert!(!pq_verify_b64u(pq, &b(&pk[1..]), b"m", Some(&json!(b(&sig)))));
        assert!(!pq_verify_b64u(pq, &b(&pk), b"m", Some(&json!(b(&sig[1..])))));
        assert!(!pq_verify_b64u(pq, &b(&pk), b"m", Some(&json!(5))));
        assert!(!pq_verify_b64u(pq, &b(&pk), b"m", None));
        assert!(!pq_verify_b64u(pq, "!!", b"m", Some(&json!(b(&sig)))));
    }
}

#[test]
fn suite_refusal_wording() {
    assert_eq!(UNSUPPORTED_SUITE_REASON, "unsupported_suite");
    // a REGISTERED suite is "unsupported" (even one this build implements, asked of the refusal text directly)
    assert_eq!(suite_refusal(Some(&json!("ed25519"))), "unsupported_suite: ed25519");
    assert_eq!(suite_refusal(Some(&json!("ml-dsa-65"))), "unsupported_suite: ml-dsa-65");
    assert_eq!(suite_refusal(Some(&json!("less-cat1"))), "unsupported_suite: less-cat1");
    // anything else is unknown, with the JSON text of the value
    assert_eq!(suite_refusal(Some(&json!("rsa"))), "unknown signature alg '\"rsa\"'");
    assert_eq!(suite_refusal(Some(&json!(5))), "unknown signature alg '5'");
    assert_eq!(suite_refusal(Some(&Value::Null)), "unknown signature alg 'null'");
    assert_eq!(suite_refusal(None), "unknown signature alg ''");
}

#[test]
fn suite_resolution() {
    assert_eq!(resolve_sig_alg(None).unwrap().alg, "ed25519");
    assert!(resolve_sig_alg(Some(&json!(null))).is_none());
    assert!(resolve_sig_alg(Some(&json!(1))).is_none());
    assert!(resolve_sig_alg(Some(&json!("rsa"))).is_none());
    for s in supported_suites() {
        assert_eq!(resolve_sig_alg(Some(&json!(s))).unwrap().alg, s);
    }
}

#[cfg(feature = "less")]
#[test]
fn less_signature_lengths_step_by_sixteen() {
    assert_eq!(less::SIGNATURE_MIN_BYTES, 1153);
    assert_eq!(less::SIGNATURE_MAX_BYTES, 1329);
    for n in 0..1500usize {
        let want = (1153..=1329).contains(&n) && (1329 - n) % 16 == 0;
        assert_eq!(less::sig_len_ok(n), want, "{n}");
        assert_eq!(Pq::LessCat1.sig_len_ok(n), want, "{n}");
    }
    assert!(less::sig_len_ok(1329) && less::sig_len_ok(1153));
    // the wrong key length alone or the wrong signature length alone is refused before the C side runs
    assert!(!less::verify(&vec![0u8; less::PUBLIC_KEY_BYTES], b"m", &vec![0u8; 1154]));
    assert!(!less::verify(&vec![0u8; less::PUBLIC_KEY_BYTES - 1], b"m", &vec![0u8; 1329]));
    assert!(!less::verify(&vec![0u8; less::PUBLIC_KEY_BYTES + 1], b"m", &vec![0u8; 1329]));
    assert!(!less::verify(&vec![0u8; less::PUBLIC_KEY_BYTES], b"m", &vec![0u8; 1329]));
}

#[test]
fn an_intent_without_a_fidelity_is_below_every_floor() {
    let (r, md, salt) = ("ref", "md", "salt");
    let commit = intent_goal_commit(r, md, salt).unwrap();
    let grant = json!({"caveats": [{"type": "envelope", "goal_commit": commit}]});
    let intent = json!({"ref": r, "map_digest": md, "goal_salt": salt, "residual_risk_ppm": 0});
    let pol = IntentPolicy { require: true, min_fidelity_ppm: Some(0.0), max_residual_risk_ppm: None };
    let e = decide_intent(Some(&intent), &grant, Some(&pol), None).unwrap().unwrap_err();
    assert!(e.contains("fidelity -1 ppm is below the policy minimum 0"), "{e}");
    let with = json!({"ref": r, "map_digest": md, "goal_salt": salt, "residual_risk_ppm": 0, "fidelity_ppm": 0});
    assert_eq!(decide_intent(Some(&with), &grant, Some(&pol), None), Some(Ok(())));
}
