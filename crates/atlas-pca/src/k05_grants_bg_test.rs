//! k05 differential oracle for break-glass grants: tests/data/k05-grants.json.gz, written by the TypeScript reference
//! (tools/pca-audit/k05-oracles/grants-oracle.mts; the Java, Kotlin, Python, Go, ... suites replay the same file): record and
//! review shapes (unsigned and re-signed) and registry walks replayed step by step on a fresh registry. The lease fns of the same
//! corpus are replayed by lease.rs's k05 test.
use super::*;
use crate::k042_support::{k05_run, K05};
use serde_json::json;

fn strs(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

fn ok_or_code(r: Result<bool, &'static str>) -> Value {
    match r {
        Ok(replaced) => json!({"ok": true, "replaced": replaced}),
        Err(code) => json!({"ok": false, "code": code}),
    }
}

fn bg_walk(pol: &Value, steps: &Value) -> K05 {
    let mut reg = BreakGlassRegistry::new(BreakGlassPolicy { authorities: strs(pol.get("authorities")), reviewers: strs(pol.get("reviewers")) });
    let mut out = Vec::new();
    for s in steps.as_array().map(Vec::as_slice).unwrap_or(&[]) {
        out.push(match s["op"].as_str().unwrap_or("") {
            "accept" => ok_or_code(reg.accept(&s["rec"], &s["now"])),
            "use" => {
                let (Some(id), Some(holder), Some(ad)) = (s["id"].as_str(), s["holder"].as_str(), s["action_digest"].as_str()) else {
                    return K05::Skip("a non-string use argument (typed port)");
                };
                let d = reg.use_grant(id, holder, ad, &s["now"], &s["notified"]);
                json!({"decision": d.decision, "code": d.code, "id": d.id, "use": d.use_n, "remaining": d.remaining, "review_due": d.review_due})
            }
            "review" => {
                let Some(holder) = s["holder"].as_str() else { return K05::Skip("a non-string review holder (typed port)") };
                ok_or_code(reg.review(&s["rec"], holder, &s["now"]))
            }
            _ => {
                let Some(holder) = s["holder"].as_str() else { return K05::Skip("a non-string frozen holder (typed port)") };
                json!(reg.frozen(holder, &s["now"]))
            }
        });
    }
    K05::Val(Value::Array(out))
}

#[test]
fn k05_grants_break_glass_matches_the_reference() {
    // 1883 break-glass cases (verifyBreakGlass, verifyBreakGlassReview, bgWalk), ~33 skipped for lone surrogates
    k05_run("grants", 1650, |_, f, a| match f {
        "verifyBreakGlass" => K05::Val(json!(verify_break_glass(&a[0]))),
        "verifyBreakGlassReview" => K05::Val(json!(verify_break_glass_review(&a[0]))),
        "bgWalk" => bg_walk(&a[0], &a[1]),
        _ => K05::Skip("other module (lease.rs)"),
    });
}

// ---- review and frozen: boundaries under valid signatures (pinned to packages/pca-grants/src/breakglass.ts, isStr counts UTF-16) ----

fn signed_with(k: &crate::agent::KeyPair, domain: &str, mut body: Value) -> Value {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let sig = k.sign(&crate::fresh_at::domain_bytes(domain, &body).unwrap());
    body["sig"] = json!(URL_SAFE_NO_PAD.encode(sig));
    body
}

/// A registry where `holder` has grant `bg1`, first used at 1100 with a 500 ms review clock; and the pinned reviewer.
fn used_grant(holder: &str) -> (BreakGlassRegistry, crate::agent::KeyPair) {
    let auth = crate::agent::KeyPair::from_seed(&[1u8; 32]);
    let reviewer = crate::agent::KeyPair::from_seed(&[2u8; 32]);
    let rec = signed_with(
        &auth,
        BREAK_GLASS_DOMAIN,
        json!({"v": 1, "id": "bg1", "holder": holder, "grant_ref": "g", "reason_digest": "r", "max_uses": 2, "issued_at": 1000, "expires_at": 2000, "review_within": 500, "notify_to": "n", "authority": auth.public}),
    );
    let mut reg = BreakGlassRegistry::new(BreakGlassPolicy { authorities: vec![auth.public.clone()], reviewers: vec![reviewer.public.clone()] });
    assert_eq!(reg.accept(&rec, &json!(1000)), Ok(true));
    assert_eq!(reg.use_grant("bg1", holder, "d", &json!(1100), &json!(true)).decision, "allow");
    (reg, reviewer)
}

fn review_at(k: &crate::agent::KeyPair, at: i64) -> Value {
    signed_with(k, BREAK_GLASS_REVIEW_DOMAIN, json!({"v": 1, "id": "bg1", "outcome": "justified", "notes_digest": "n", "at": at, "reviewer": k.public}))
}

#[test]
fn review_holder_is_one_to_128_utf16_units() {
    for holder in ["h".repeat(128), "\u{1F600}".repeat(64)] {
        let (mut reg, k) = used_grant(&holder);
        assert_eq!(reg.review(&review_at(&k, 1100), &holder, &json!(1200)), Ok(true));
    }
    let (mut reg, k) = used_grant("h");
    let good = review_at(&k, 1100);
    for holder in [String::new(), "h".repeat(129), "\u{1F600}".repeat(65)] {
        assert_eq!(reg.review(&good, &holder, &json!(1200)), Err("bad_record"), "{holder}");
    }
    let mut tampered = good.clone();
    tampered["at"] = json!(1101);
    assert_eq!(reg.review(&tampered, "h", &json!(1200)), Err("bad_record"));
    assert_eq!(reg.review(&good, "other", &json!(1200)), Err("unknown_break_glass"));
}

#[test]
fn review_time_runs_from_the_first_use_to_now_inclusive() {
    let cases = [(1100, 1200, Ok(true)), (1099, 1200, Err("bad_time")), (1200, 1200, Ok(true)), (1201, 1200, Err("bad_time"))];
    for (at, now, want) in cases {
        let (mut reg, k) = used_grant("h");
        assert_eq!(reg.review(&review_at(&k, at), "h", &json!(now)), want, "at {at} now {now}");
    }
}

#[test]
fn frozen_fails_closed_outside_one_to_128_utf16_units() {
    let reg = BreakGlassRegistry::new(BreakGlassPolicy { authorities: vec![], reviewers: vec![] });
    for holder in [String::new(), "h".repeat(129), "\u{1F600}".repeat(65)] {
        assert!(reg.frozen(&holder, &json!(0)), "{holder}");
    }
    for holder in ["h".repeat(128), "\u{1F600}".repeat(64), "h".to_string()] {
        assert!(!reg.frozen(&holder, &json!(0)), "{holder}");
    }
    assert!(reg.frozen("h", &json!(-1)));
}

#[test]
fn a_128_unit_holder_freezes_when_the_review_clock_runs_out() {
    let holder = "h".repeat(128);
    let (reg, _) = used_grant(&holder);
    assert!(!reg.frozen(&holder, &json!(1599)));
    assert!(reg.frozen(&holder, &json!(1600)));
}

// ---- record and review shapes: each clause alone, every other member valid and the signature good (breakglass.ts bgWellFormed, rvWellFormed) ----

const THIRTY_DAYS_MS: i64 = 2_592_000_000;

fn patched(k: &crate::agent::KeyPair, domain: &str, mut body: Value, patch: Value) -> Value {
    for (key, x) in patch.as_object().unwrap() {
        body[key.as_str()] = x.clone();
    }
    signed_with(k, domain, body)
}

fn bg(k: &crate::agent::KeyPair, patch: Value) -> Value {
    let body = json!({"v": 1, "id": "bg1", "holder": "h", "grant_ref": "g", "reason_digest": "r", "max_uses": 2, "issued_at": 1000, "expires_at": 2000, "review_within": 500, "notify_to": "n", "authority": k.public});
    patched(k, BREAK_GLASS_DOMAIN, body, patch)
}

fn rv(k: &crate::agent::KeyPair, patch: Value) -> Value {
    let body = json!({"v": 1, "id": "bg1", "outcome": "justified", "notes_digest": "n", "at": 1100, "reviewer": k.public});
    patched(k, BREAK_GLASS_REVIEW_DOMAIN, body, patch)
}

#[test]
fn record_bounds_are_accepted_at_the_limit() {
    let k = crate::agent::KeyPair::from_seed(&[1u8; 32]);
    assert_eq!(MAX_REVIEW_WITHIN_MS, THIRTY_DAYS_MS);
    for patch in [
        json!({}),
        json!({"max_uses": 1}),
        json!({"max_uses": 16}),
        json!({"expires_at": 1001}),
        json!({"expires_at": 1000 + MAX_BREAK_GLASS_WINDOW_MS}),
        json!({"review_within": 1}),
        json!({"review_within": THIRTY_DAYS_MS}),
        json!({"id": "i".repeat(128), "holder": "h".repeat(128), "grant_ref": "g".repeat(256), "reason_digest": "r".repeat(128), "notify_to": "n".repeat(256)}),
        json!({"id": "\u{1F600}".repeat(64)}),
    ] {
        assert!(verify_break_glass(&bg(&k, patch.clone())), "{patch}");
    }
}

#[test]
fn record_refuses_each_clause_alone() {
    let k = crate::agent::KeyPair::from_seed(&[1u8; 32]);
    assert!(!well_formed(&json!("x")));
    let long = |c: &str, n: usize| json!(c.repeat(n));
    for patch in [
        json!({"v": 2}),
        json!({"id": ""}),
        json!({"id": long("i", 129)}),
        json!({"id": long("\u{1F600}", 65)}),
        json!({"holder": ""}),
        json!({"holder": long("h", 129)}),
        json!({"grant_ref": ""}),
        json!({"grant_ref": long("g", 257)}),
        json!({"reason_digest": ""}),
        json!({"reason_digest": long("r", 129)}),
        json!({"notify_to": ""}),
        json!({"notify_to": long("n", 257)}),
        json!({"authority": ""}),
        json!({"authority": long("a", 129)}),
        json!({"max_uses": 0}),
        json!({"max_uses": 17}),
        json!({"expires_at": 1000}),
        json!({"expires_at": 999}),
        json!({"expires_at": 1001 + MAX_BREAK_GLASS_WINDOW_MS}),
        json!({"review_within": 0}),
        json!({"review_within": THIRTY_DAYS_MS + 1}),
    ] {
        let rec = bg(&k, patch.clone());
        // well_formed itself: the authority clause would otherwise be hidden by the signature check that follows it
        assert!(!well_formed(&rec), "{patch}");
        assert!(!verify_break_glass(&rec), "{patch}");
    }
}

#[test]
fn review_refuses_each_clause_alone() {
    let k = crate::agent::KeyPair::from_seed(&[2u8; 32]);
    for patch in [json!({}), json!({"outcome": "unjustified"}), json!({"at": 0}), json!({"id": "i".repeat(128), "notes_digest": "n".repeat(128)})] {
        assert!(verify_break_glass_review(&rv(&k, patch.clone())), "{patch}");
    }
    assert!(!rv_well_formed(&json!("x")));
    for patch in [
        json!({"v": 2}),
        json!({"id": ""}),
        json!({"id": "i".repeat(129)}),
        json!({"outcome": "maybe"}),
        json!({"outcome": 1}),
        json!({"notes_digest": ""}),
        json!({"notes_digest": "n".repeat(129)}),
        json!({"at": -1}),
        json!({"at": "1"}),
        json!({"reviewer": ""}),
        json!({"reviewer": "r".repeat(129)}),
    ] {
        let rec = rv(&k, patch.clone());
        // rv_well_formed itself: the reviewer clause would otherwise be hidden by the signature check that follows it
        assert!(!rv_well_formed(&rec), "{patch}");
        assert!(!verify_break_glass_review(&rec), "{patch}");
    }
}
