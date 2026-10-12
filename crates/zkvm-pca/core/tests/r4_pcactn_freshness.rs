//! R4-04: the receipt must prove, and the journal must carry, the PCActn's own freshness / audience / version / counter
//! facts (`verifyPCActnCore` checks `version`, `audience`, `validity`, `counter` and the wire form before anything else).
//! Every deny below has a VALID chain and a VALID PCActn signature (the PCActn is re-signed after the edit), so the only
//! possible cause is the new in-guest check. Before the fix every one of them was ALLOWED.
use pca_zkvm_core::{decide_from_str, Decision};
use serde_json::{json, Value};

#[path = "support/chain_mint.rs"]
mod mint;

fn base() -> Value {
    serde_json::from_str(include_str!("../../fixtures/decide_input.sample.json")).unwrap()
}
fn run(v: &Value) -> Decision {
    decide_from_str(&v.to_string())
}
/// edit the signed PCActn, re-sign it with the leaf key, and optionally move the verifier clock
fn edited(f: impl Fn(&mut Value)) -> Value {
    let mut v = base();
    f(&mut v);
    mint::resign(&mut v, &mint::key(3));
    v
}

const IAT: u64 = 1_760_000_000_000;
const EXP: u64 = 1_760_001_200_000;

#[test]
fn control_the_unedited_sample_and_a_resigned_copy_are_allowed() {
    assert_eq!(run(&base()).allow, 1);
    assert_eq!(run(&edited(|_| {})).allow, 1, "re-signing alone must not change the verdict");
}

#[test]
fn journal_commits_ver_iat_exp_aud_counter() {
    let c = run(&base()).context;
    assert_eq!((c.pcactn_ver, c.pcactn_iat, c.pcactn_exp, c.pcactn_aud.as_str(), c.pcactn_counter), (2, IAT as i64, EXP as i64, "atlas-instance-1", 0));
}

#[test]
fn an_expired_pcactn_is_denied_even_though_the_grant_is_still_valid() {
    // grant expires 1_760_010_000_000; the PCActn expired at EXP. The prover supplies an honest-looking `now` after EXP.
    let v = edited(|v| v["now"] = json!(EXP + 1));
    assert_eq!(run(&v).allow, 0);
    // boundary: now == exp passes (verifyPCActnCore: expired only when now > exp)
    assert_eq!(run(&edited(|v| v["now"] = json!(EXP))).allow, 1);
}

#[test]
fn a_pcactn_from_the_future_beyond_the_skew_is_denied() {
    let ok = edited(|v| v["now"] = json!(IAT - 60_000));
    // not_before on the grant is 1_759_999_000_000 so this `now` is inside the grant; iat = now + 60_000 is the boundary
    assert_eq!(run(&ok).allow, 1, "iat == now + skew passes");
    assert_eq!(run(&edited(|v| v["now"] = json!(IAT - 60_001))).allow, 0, "iat > now + skew");
}

#[test]
fn an_over_long_lived_pcactn_is_denied() {
    assert_eq!(run(&edited(|v| v["pcactn"]["exp"] = json!(IAT + 3_600_000))).allow, 1, "exactly the maximum lifetime");
    assert_eq!(run(&edited(|v| v["pcactn"]["exp"] = json!(IAT + 3_600_001))).allow, 0);
    assert_eq!(run(&edited(|v| v["pcactn"]["exp"] = json!(IAT))).allow, 0, "exp must be greater than iat");
    assert_eq!(run(&edited(|v| v["pcactn"]["exp"] = json!(IAT - 1))).allow, 0);
}

#[test]
fn wrong_or_missing_version_is_denied() {
    for ver in [json!(1), json!(3), json!(0), json!("2"), json!(2.5), json!(null)] {
        assert_eq!(run(&edited(|v| v["pcactn"]["ver"] = ver.clone())).allow, 0, "ver {ver}");
    }
    assert_eq!(run(&edited(|v| { v["pcactn"].as_object_mut().unwrap().remove("ver"); })).allow, 0);
}

#[test]
fn missing_or_malformed_freshness_fields_are_denied() {
    for k in ["iat", "exp", "aud", "counter"] {
        assert_eq!(run(&edited(|v| { v["pcactn"].as_object_mut().unwrap().remove(k); })).allow, 0, "missing {k}");
        for bad in [json!(null), json!("1760000000000"), json!(true), json!([]), json!(1.5)] {
            if k == "aud" && bad.is_string() { continue; }
            assert_eq!(run(&edited(|v| v["pcactn"][k] = bad.clone())).allow, 0, "{k} = {bad}");
        }
    }
    // not safe integers
    assert_eq!(run(&edited(|v| v["pcactn"]["counter"] = json!(9_007_199_254_740_992u64))).allow, 0);
    assert_eq!(run(&edited(|v| v["pcactn"]["counter"] = json!(-1))).allow, 0, "negative counter");
    assert_eq!(run(&edited(|v| v["pcactn"]["iat"] = json!(9_007_199_254_740_992u64))).allow, 0);
    // aud: wire form is a non-empty string of at most 256 UTF-8 bytes
    assert_eq!(run(&edited(|v| v["pcactn"]["aud"] = json!(""))).allow, 0);
    assert_eq!(run(&edited(|v| v["pcactn"]["aud"] = json!("a".repeat(257)))).allow, 0);
    assert_eq!(run(&edited(|v| v["pcactn"]["aud"] = json!("a".repeat(256)))).allow, 1);
    assert_eq!(run(&edited(|v| v["pcactn"]["counter"] = json!(7))).allow, 1, "a non-zero counter is fine (monotonicity is the RS's job)");
}

#[test]
fn every_freshness_fact_moves_the_journal() {
    let want = run(&base()).context;
    for (name, f) in [
        ("aud", Box::new(|v: &mut Value| v["pcactn"]["aud"] = json!("other-instance")) as Box<dyn Fn(&mut Value)>),
        ("counter", Box::new(|v: &mut Value| v["pcactn"]["counter"] = json!(5))),
        ("exp", Box::new(|v: &mut Value| v["pcactn"]["exp"] = json!(EXP - 1))),
        ("iat", Box::new(|v: &mut Value| v["pcactn"]["iat"] = json!(IAT + 1))),
    ] {
        let d = run(&edited(|v| f(v)));
        assert_eq!(d.allow, 1, "{name}: an in-range edit is allowed");
        assert_ne!(d.context, want, "{name} is not committed in the journal context");
    }
}

// ---- verifier side: ExpectedContext requires and check_context enforces every fact --------------------------------------
use pca_zkvm_core::context::Context as Ctx;
use pca_zkvm_core::context::{check_context, ContextMismatch as M, ExpectedContext, PCACTN_VERSION};

fn expected(v: &Value) -> ExpectedContext {
    ExpectedContext::from_input_json(&v.to_string(), 0.0).expect("input parses")
}

#[test]
fn verifier_pins_each_freshness_fact() {
    let b = base();
    let j = run(&b);
    check_context(&j, &expected(&b)).expect("control");
    let cases: Vec<(&str, Box<dyn Fn(&mut ExpectedContext)>, M)> = vec![
        ("ver", Box::new(|e| e.pcactn_ver = 1), M::PcactnVersion),
        ("aud", Box::new(|e| e.pcactn_aud = "someone-else".into()), M::PcactnAud),
        ("aud empty", Box::new(|e| e.pcactn_aud = String::new()), M::PcactnAud),
        ("iat", Box::new(|e| e.pcactn_iat += 1), M::PcactnIat),
        ("exp", Box::new(|e| e.pcactn_exp -= 1), M::PcactnExp),
        ("counter", Box::new(|e| e.pcactn_counter = 1), M::PcactnCounter),
    ];
    for (name, f, want) in cases {
        let mut e = expected(&b);
        f(&mut e);
        assert_eq!(check_context(&j, &e), Err(want), "{name}");
    }
    assert_eq!(PCACTN_VERSION, 2);
}

#[test]
fn verifier_clock_decides_the_window_even_when_the_prover_now_was_honest() {
    let b = base();
    let j = run(&b);
    // the receipt is genuine and allow=1 at the proven now; a verifier whose clock is past exp must refuse it
    let mut e = expected(&b);
    e.now = EXP as f64 + 1.0;
    e.now_tolerance_ms = 1.0e9;
    assert_eq!(check_context(&j, &e), Err(M::PcactnExpired));
    e.now = EXP as f64;
    check_context(&j, &e).expect("now == exp is still valid");
    // verifier clock before iat - skew
    e.now = IAT as f64 - 60_001.0;
    assert_eq!(check_context(&j, &e), Err(M::PcactnNotYetValid));
    e.now = IAT as f64 - 60_000.0;
    check_context(&j, &e).expect("iat == now + skew is valid");
    // a fractional / non-finite verifier clock is never accepted as a safe-integer epoch
    e.now = IAT as f64 + 0.5;
    assert_eq!(check_context(&j, &e), Err(M::PcactnExpired));
}

#[test]
fn a_journal_with_an_out_of_policy_window_or_version_is_refused_even_if_the_verifier_agrees_with_it() {
    // forge a journal (not provable by the real guest, but check_context must not rely on that): the verifier "expects" the
    // very same bad facts. The verifier-side checks must still refuse.
    let b = base();
    for (name, f, want) in [
        ("ver 3", Box::new(|c: &mut Ctx, e: &mut ExpectedContext| { c.pcactn_ver = 3; e.pcactn_ver = 3; }) as Box<dyn Fn(&mut Ctx, &mut ExpectedContext)>, M::PcactnVersion),
        ("lifetime 1h+1ms", Box::new(|c: &mut Ctx, e: &mut ExpectedContext| { c.pcactn_exp = IAT as i64 + 3_600_001; e.pcactn_exp = c.pcactn_exp; }), M::PcactnLifetime),
        ("exp == iat", Box::new(|c: &mut Ctx, e: &mut ExpectedContext| { c.pcactn_exp = IAT as i64; e.pcactn_exp = c.pcactn_exp; }), M::PcactnLifetime),
        ("empty aud", Box::new(|c: &mut Ctx, e: &mut ExpectedContext| { c.pcactn_aud = String::new(); e.pcactn_aud = String::new(); }), M::PcactnAud),
    ] {
        let mut j = run(&b);
        let mut e = expected(&b);
        f(&mut j.context, &mut e);
        assert_eq!(check_context(&j, &e), Err(want), "{name}");
    }
}

#[test]
fn from_input_json_refuses_an_input_whose_pcactn_has_no_well_formed_facts() {
    let mut b = base();
    b["pcactn"].as_object_mut().unwrap().remove("exp");
    assert!(ExpectedContext::from_input_json(&b.to_string(), 0.0).is_none(), "no permissive default for a missing exp");
}

#[test]
fn guest_freshness_verdict_equals_ts_verify_pcactn_core_on_every_golden_row() {
    // fixtures/ts_pcactn_freshness.json: for each mutation x verifier clock, whether the TS reference passes
    // wire + version + audience + validity + counter (tests/gen_ts_pcactn_freshness.ts)
    use pca_zkvm_core::context::PcactnFacts;
    let rows: Vec<Value> = serde_json::from_str(include_str!("../../fixtures/ts_pcactn_freshness.json")).unwrap();
    assert!(rows.len() >= 300);
    let (mut fresh, mut stale) = (0, 0);
    let mut bad = Vec::new();
    for r in &rows {
        let want = r["fresh"].as_bool().unwrap();
        let now = r["now"].as_f64().unwrap();
        let got = PcactnFacts::from_pcactn(&r["fields"])
            .map(|f| f.aud == r["expected_aud"].as_str().unwrap() && f.check_freshness(now).is_ok())
            .unwrap_or(false);
        if want { fresh += 1 } else { stale += 1 }
        if got != want {
            bad.push(format!("{} @ now={}: TS {} guest {} ({})", r["name"], now, want, got, r["checks"]));
        }
    }
    assert!(fresh >= 20 && stale >= 200, "both verdicts exercised ({fresh}/{stale})");
    assert!(bad.is_empty(), "{} divergences from verifyPCActnCore:\n{}", bad.len(), bad.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
}
