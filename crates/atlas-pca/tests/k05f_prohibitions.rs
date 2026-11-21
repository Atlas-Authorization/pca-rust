//! Negative authority (prohibitions.ts): the constitution, the monitor and the signed safety evidence, replayed over the shared
//! prohibition-vectors.json (`constitution`, `monitor`, `evidence`). The evidence rows pin the refusal of a malformed expected
//! constitution (an invariant without a string id can never "cover" an id-less row) and of a non-string evaluated row id.
use atlas_pca::prohibitions::*;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::*;

const FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/prohibition-vectors.json");

fn doc() -> Value {
    strict_parse(&std::fs::read_to_string(FILE).unwrap()).unwrap()
}

#[test]
fn every_constitution_row_is_reproduced() {
    let d = doc();
    let rows = d["constitution"].as_array().unwrap();
    assert_eq!(rows.len(), 33);
    for v in rows {
        let problems = validate_constitution(&v["constitution"]);
        assert_eq!(json!(problems), v["expect"]["problems"], "{} problems", v["name"]);
        let r = check_prohibitions(&v["action"], &v["constitution"], &v["state"]).to_json();
        assert_eq!(r, v["expect"]["result"], "{} result", v["name"]);
    }
}

#[test]
fn every_monitor_sequence_is_reproduced() {
    for m in doc()["monitor"].as_array().unwrap() {
        let mut state = empty_state(m["genesis_now"].as_f64().unwrap());
        for (i, s) in m["steps"].as_array().unwrap().iter().enumerate() {
            let want = &s["expect"];
            if let Some(now) = s["now"].as_f64() {
                match tick_state(&state, now) {
                    Ok(t) => state = t,
                    Err(why) => {
                        assert_eq!((json!(false), json!("clock"), json!(why)), (want["allow"].clone(), want["decidedBy"].clone(), want["reason"].clone()), "{} step {i}", m["name"]);
                        continue;
                    }
                }
            }
            let r = check_and_advance(true, &s["action"], &m["constitution"], &state, None, None);
            assert_eq!(json!(r.allow), want["allow"], "{} step {i} allow", m["name"]);
            assert_eq!(json!(r.decided_by), want["decidedBy"], "{} step {i} decidedBy", m["name"]);
            assert_eq!(json!(r.prohibition.violated), want["violated"], "{} step {i} violated", m["name"]);
            assert_eq!(r.next["seq"], want["seq"], "{} step {i} seq", m["name"]);
            state = r.next;
        }
    }
}

#[test]
fn every_signed_evidence_row_is_reproduced_with_its_exact_reason() {
    let d = doc();
    let rows = d["evidence"].as_array().unwrap();
    assert_eq!(rows.len(), 13);
    for v in rows {
        let got = match verify_signed_safety_evidence(&v["signed"], &v["expected"]) {
            Ok(()) => json!({"ok": true}),
            Err(why) => json!({"ok": false, "reason": why}),
        };
        assert_eq!(got, v["expect"], "{}", v["name"]);
    }
}

#[test]
fn the_state_chain_stale_heads_and_structural_refusals() {
    let c = json!({"version": 1, "principal": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "invariants": [{"id": "a", "kind": "never", "when": {"verb": "delete"}}]});
    let act = json!({"action": {"verb": "read", "resource": "/r"}});
    let s0 = empty_state(1_700_000_000_000.0);
    let r = check_and_advance(true, &act, &c, &s0, Some(1.0), None);
    assert_eq!((r.allow, r.decided_by, r.reason.as_deref()), (false, "state", Some("stale state head (seq)")));
    let r = check_and_advance(true, &act, &c, &s0, None, Some("nope"));
    assert_eq!((r.allow, r.decided_by, r.reason.as_deref()), (false, "state", Some("stale state head (digest)")));
    let good = state_digest(&s0).unwrap();
    assert!(check_and_advance(true, &act, &c, &s0, Some(0.0), Some(&good)).allow);
    // not permitted: the monitor still runs, the decision is the permission layer's
    let r = check_and_advance(false, &act, &c, &s0, None, None);
    assert_eq!((r.allow, r.decided_by), (false, "permission"));
    // a veto wins even when permitted
    let del = json!({"action": {"verb": "delete", "resource": "/r"}});
    let r = check_and_advance(true, &del, &c, &s0, None, None);
    assert_eq!((r.allow, r.decided_by, r.next == s0), (false, "prohibition", true));
    // the chain advances and links; a clock that runs backwards is refused
    let s1 = advance_state_strict(&act, &c, &s0, None).unwrap();
    assert_eq!(s1["seq"], 1);
    assert!(s1["parent"].is_string());
    assert_eq!(advance_state_strict(&act, &c, &s1, Some(1_699_999_999_999.0)), Err("clock regression".into()));
    assert_eq!(tick_state(&json!(null), 1.0), Err("malformed monitor state".into()));
    assert_eq!(advance_state_strict(&json!({"action": {}}), &c, &s0, None), Err("malformed action".into()));
    // canonical state: an empty ledger array is the same state as no entry
    let mut with_empty = s0.clone();
    with_empty["ledger"] = json!({"x": []});
    assert_eq!(state_digest(&with_empty), state_digest(&s0));
}

// ---- principal pin and binding id: presence, not truthiness ---------------------------------------------------------

mod signed_fixture {
    use super::*;
    use atlas_pca::prohibitions::SAFETY_EVIDENCE_SIG_DOMAIN;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    pub fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    pub fn public(k: &SigningKey) -> String {
        URL_SAFE_NO_PAD.encode(k.verifying_key().to_bytes())
    }

    fn sign(k: &SigningKey, domain: &str, id: &str) -> String {
        let mut msg = domain.as_bytes().to_vec();
        msg.extend(Sha256::digest(id.as_bytes()));
        URL_SAFE_NO_PAD.encode(k.sign(&msg).to_bytes())
    }

    pub fn signed_constitution(k: &SigningKey) -> Value {
        let mut sc = json!({"version": 1, "principal": public(k), "invariants": [
            {"id": "spend-day", "kind": "cap", "when": {"verb": "pay", "resource": "*"}, "amount": "action.params.usd", "max": 100, "window_secs": 86400}]});
        let id = constitution_id(&sc).unwrap();
        sc["sig"] = json!(sign(k, CONSTITUTION_SIG_DOMAIN, &id));
        sc["id"] = json!(id);
        sc
    }

    pub fn action() -> Value {
        json!({"action": {"verb": "pay", "resource": "/x", "params": {"usd": 1}}})
    }

    pub fn signed_evidence(evidence: &Value, k: &SigningKey) -> Value {
        let signer = public(k);
        let id = safety_binding_id(evidence, &signer).unwrap();
        json!({"evidence": evidence, "signer": signer, "id": id, "sig": sign(k, SAFETY_EVIDENCE_SIG_DOMAIN, &id)})
    }

    /// (signed evidence, expected bundle, evidence, evidence signer public key)
    pub fn bundle() -> (Value, Value, Value, String) {
        let (principal, signer) = (key(1), key(2));
        let sc = signed_constitution(&principal);
        let (action, state) = (action(), empty_state(1_700_000_000_000.0));
        let ev = prove_safety(&action, &sc, &state);
        let signed = signed_evidence(&ev, &signer);
        let expected = json!({"signer": public(&signer), "action": action, "constitution": sc, "state": state});
        (signed, expected, ev, public(&signer))
    }
}

fn refusal(why: &str) -> Result<(), String> {
    Err(why.to_string())
}

#[test]
fn the_fixture_verifies_with_no_pin_and_with_the_right_pin() {
    let (signed, expected, _, _) = signed_fixture::bundle();
    assert_eq!(verify_signed_safety_evidence(&signed, &expected), Ok(()));
    let mut pinned = expected.clone();
    pinned["principal"] = json!(signed_fixture::public(&signed_fixture::key(1)));
    assert_eq!(verify_signed_safety_evidence(&signed, &pinned), Ok(()));
}

#[test]
fn a_present_principal_pin_that_is_not_the_right_string_refuses() {
    let (signed, expected, _, _) = signed_fixture::bundle();
    let other = signed_fixture::public(&signed_fixture::key(9));
    for pin in [json!(null), json!(5), json!(true), json!([]), json!(""), json!(other)] {
        let mut e = expected.clone();
        e["principal"] = pin.clone();
        assert_eq!(verify_signed_safety_evidence(&signed, &e), refusal("constitution not authentic: principal mismatch"), "pin {pin}");
    }
}

#[test]
fn a_principal_pin_needs_a_signed_constitution() {
    let (signed, mut expected, _, _) = signed_fixture::bundle();
    expected["principal"] = json!(null);
    expected["constitution"].as_object_mut().unwrap().remove("sig");
    assert_eq!(verify_signed_safety_evidence(&signed, &expected), refusal("principal pin requires a signed constitution"));
}

#[test]
fn the_binding_id_exists_only_when_all_three_digests_are_present() {
    let (signed, _, ev, signer) = signed_fixture::bundle();
    assert_eq!(safety_binding_id(&ev, &signer).as_deref(), signed["id"].as_str());
    for k in ["constitution", "action_digest", "state_digest"] {
        let mut cut = ev.clone();
        cut.as_object_mut().unwrap().remove(k);
        assert_eq!(safety_binding_id(&cut, &signer), None, "missing {k}");
        // an explicit null is present
        let mut nulled = ev.clone();
        nulled[k] = json!(null);
        assert!(safety_binding_id(&nulled, &signer).is_some(), "null {k}");
    }
}

#[test]
fn evidence_missing_a_bound_digest_fails_closed() {
    let (signed, expected, _, _) = signed_fixture::bundle();
    for k in ["constitution", "action_digest", "state_digest"] {
        let mut s = signed.clone();
        s["evidence"].as_object_mut().unwrap().remove(k);
        assert_eq!(verify_signed_safety_evidence(&s, &expected), refusal("verification error (fail closed)"), "missing {k}");
    }
}

#[test]
fn a_missing_or_wrong_binding_id_is_a_mismatch() {
    let (signed, expected, _, _) = signed_fixture::bundle();
    let mut absent = signed.clone();
    absent.as_object_mut().unwrap().remove("id");
    for (name, s) in [("absent", absent), ("number", { let mut s = signed.clone(); s["id"] = json!(5); s }), ("null", { let mut s = signed.clone(); s["id"] = json!(null); s }), ("wrong string", { let mut s = signed.clone(); s["id"] = json!("x"); s })] {
        assert_eq!(verify_signed_safety_evidence(&s, &expected), refusal("binding id mismatch"), "{name}");
    }
}
