// Boundaries of verify_passport, each pinned to packages/pca/src/passport.ts (verifyPassport): the field and time checks
// (:293, :297, :298), the validity window with the clock skew clamped to [0, 60 s] (:303-305), and the hardware evidence age
// (:321-322, default 24 h = DEFAULT_PASSPORT_EVIDENCE_AGE_MS).
use atlas_pca::agent::*;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::*;

const NOW: i64 = 1_800_000_000_000;
const MAX_SAFE: i64 = 9_007_199_254_740_991;
const DAY: i64 = 86_400_000;

fn issuer() -> KeyPair {
    KeyPair::from_seed(&[7u8; 32])
}

/// A passport signed by `issuer()`, nbf = iat = NOW - 1000; hardware-rooted with evidence dated `at` when given.
fn signed(exp: i64, at: Option<i64>) -> Value {
    let sub = KeyPair::from_seed(&[9u8; 32]);
    let p = issue_passport(&json!({"model_id": "m", "operator": "op", "hardware_rooted": at.is_some(), "issued_at": NOW - 1000})).unwrap();
    let ev = at.map(|a| json!({"document": {"nonce": "n1"}, "at": a}));
    sign_passport(&p, &issuer(), &sub.public, None, None, exp, ev.as_ref(), &Suite::default()).unwrap()
}

fn check(sp: &Value, now: i64, skew: Option<i64>, max_age: Option<i64>) -> Result<(), &'static str> {
    let issuers = vec![issuer().public];
    let not_revoked = |_: &str, _: &str, _: &str| -> Result<bool, ()> { Ok(false) };
    let attest = |_: &Value, _: &PassportBinding| -> Result<PassportAttestation, ()> {
        Ok(PassportAttestation { ok: true, bound: true, measured: json!({"model_id": "m", "operator": "op"}).as_object().cloned() })
    };
    let o = PassportOptions {
        trusted_issuers: &issuers,
        now_ms: now,
        clock_skew_ms: skew,
        max_evidence_age_ms: max_age,
        subject: None,
        pq_pins: None,
        attest: Some(&attest),
        default_verifier: None,
        revoked: Some(&not_revoked),
    };
    verify_passport(sp, &o)
}

fn edit(sp: &Value, f: impl FnOnce(&mut Value)) -> Value {
    let mut v = sp.clone();
    f(&mut v);
    v
}

/// :293 typ and passport, :297 model_id / operator strings and a boolean hardware_rooted, :298 safe-integer times with
/// exp > nbf and a safe-integer now: each one alone is `malformed` (checked before the signature).
#[test]
fn shape_and_time_checks_each_refuse_alone() {
    let sp = signed(NOW + 60_000, None);
    assert_eq!(check(&sp, NOW, None, None), Ok(()));
    assert_eq!(check(&edit(&sp, |v| v["typ"] = json!("atlas-pca/other")), NOW, None, None), Err("malformed"));
    assert_eq!(check(&edit(&sp, |v| { v.as_object_mut().unwrap().remove("passport"); }), NOW, None, None), Err("malformed"));
    assert_eq!(check(&edit(&sp, |v| { v["passport"].as_object_mut().unwrap().remove("model_id"); }), NOW, None, None), Err("malformed"));
    assert_eq!(check(&edit(&sp, |v| { v["passport"].as_object_mut().unwrap().remove("operator"); }), NOW, None, None), Err("malformed"));
    assert_eq!(check(&edit(&sp, |v| v["passport"]["hardware_rooted"] = json!("false")), NOW, None, None), Err("malformed"));
    let nbf = sp["nbf"].as_i64().unwrap();
    assert_eq!(check(&edit(&sp, |v| v["exp"] = json!(nbf)), NOW, None, None), Err("malformed"));
    assert_eq!(check(&edit(&sp, |v| v["exp"] = json!(nbf - 1)), NOW, None, None), Err("malformed"));
    for now in [MAX_SAFE + 1, -MAX_SAFE - 1, i64::MIN, i64::MAX] {
        assert_eq!(check(&sp, now, None, None), Err("malformed"), "now {now}");
    }
    // a safe now is no time error: these are past the window
    assert_eq!(check(&sp, MAX_SAFE, None, None), Err("expired"));
    assert_eq!(check(&sp, -MAX_SAFE, None, None), Err("not_yet_valid"));
}

/// :303-305: valid while now + skew >= nbf and now - skew < exp; the skew is clamped to [0, 60 s].
#[test]
fn validity_window_with_the_clock_skew() {
    let exp = NOW + 60_000;
    let sp = signed(exp, None);
    let nbf = sp["nbf"].as_i64().unwrap();
    assert_eq!(check(&sp, exp - 1, None, None), Ok(()));
    assert_eq!(check(&sp, exp, None, None), Err("expired"));
    assert_eq!(check(&sp, exp + 4_999, Some(5_000), None), Ok(()));
    assert_eq!(check(&sp, exp + 5_000, Some(5_000), None), Err("expired"));
    assert_eq!(check(&sp, nbf - 5_000, Some(5_000), None), Ok(()));
    assert_eq!(check(&sp, nbf - 5_001, Some(5_000), None), Err("not_yet_valid"));
    assert_eq!(check(&sp, exp + 59_999, Some(120_000), None), Ok(()));
    assert_eq!(check(&sp, exp + 60_000, Some(120_000), None), Err("expired"));
    assert_eq!(check(&sp, exp, Some(-5_000), None), Err("expired"));
}

/// :321-322: stale when maxAge < 0, now - at > maxAge (default 24 h), or at - now > skew.
#[test]
fn hardware_evidence_age_boundaries() {
    let exp = NOW + 30 * DAY;
    let at = |a: i64| signed(exp, Some(a));
    // the 24 h default, inclusive
    assert_eq!(check(&at(NOW - 2 * 3_600_000), NOW, None, None), Ok(()));
    assert_eq!(check(&at(NOW - DAY), NOW, None, None), Ok(()));
    assert_eq!(check(&at(NOW - DAY - 1), NOW, None, None), Err("hardware_evidence_stale"));
    // an explicit max age: 0 admits only now, a negative one admits nothing
    assert_eq!(check(&at(NOW), NOW, None, Some(0)), Ok(()));
    assert_eq!(check(&at(NOW - 1), NOW, None, Some(0)), Err("hardware_evidence_stale"));
    assert_eq!(check(&at(NOW), NOW, None, Some(-1)), Err("hardware_evidence_stale"));
    assert_eq!(check(&at(NOW - 100), NOW, None, Some(100)), Ok(()));
    assert_eq!(check(&at(NOW - 101), NOW, None, Some(100)), Err("hardware_evidence_stale"));
    // evidence from the future: up to the skew
    assert_eq!(check(&at(NOW + 1), NOW, None, None), Err("hardware_evidence_stale"));
    assert_eq!(check(&at(NOW + 5_000), NOW, Some(5_000), None), Ok(()));
    assert_eq!(check(&at(NOW + 5_001), NOW, Some(5_000), None), Err("hardware_evidence_stale"));
}

fn with_hooks(revoked: Option<&dyn Fn(&str, &str, &str) -> Result<bool, ()>>, attest: Option<AttestFn<'_>>) -> Result<(), &'static str> {
    let issuers = vec![issuer().public];
    let o = PassportOptions {
        trusted_issuers: &issuers,
        now_ms: NOW,
        clock_skew_ms: None,
        max_evidence_age_ms: None,
        subject: None,
        pq_pins: None,
        attest,
        default_verifier: None,
        revoked,
    };
    verify_passport(&signed(NOW + 60_000, Some(NOW)), &o)
}

/// passport.ts:309-311 and :325-328: a hook that panics denies, it does not unwind into the caller.
#[test]
fn a_panicking_hook_denies() {
    let ok_rev = |_: &str, _: &str, _: &str| -> Result<bool, ()> { Ok(false) };
    let boom_rev = |_: &str, _: &str, _: &str| -> Result<bool, ()> { panic!("revocation hook") };
    let boom_att = |_: &Value, _: &PassportBinding| -> Result<PassportAttestation, ()> { panic!("attest hook") };
    assert_eq!(with_hooks(Some(&boom_rev), None), Err("revocation_unavailable"));
    assert_eq!(with_hooks(Some(&ok_rev), Some(&boom_att)), Err("hardware_attestation_failed"));
}
