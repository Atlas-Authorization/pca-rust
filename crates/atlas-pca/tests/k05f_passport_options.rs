//! `requirePassport` as reusable `AuthorizeOptions` configuration: a call with no passport (or one that does not verify) is refused
//! with `passport: <reason>` BEFORE the replay counter is spent, and a configuration with no trusted issuers or no revocation source
//! is refused (fail closed), as the reference requires.
mod common;

use std::sync::Arc;

use atlas_pca::agent::*;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::*;
use common::*;

const AUD: &str = "rs-passport";

struct Call {
    grant: Value,
    pcactn: Value,
    op: Operation,
}

fn call() -> Call {
    let (principal, key) = (KeyPair::generate().unwrap(), KeyPair::from_seed(&[9u8; 32]));
    let env = json!({"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": default_risk_policy()});
    let grant = mint_grant(&principal, &key.public, &env, "refund an order", None, None, &Suite::default()).unwrap().grant;
    let agent = Agent::new(key, grant.clone(), AUD, 0);
    let params = json!({"amount_cents": 500});
    let a = agent.act("refund", "orders/1", Some(&params), Default::default(), &Suite::default()).unwrap();
    let op = Operation::from_json(&json!({"verb": "refund", "resource": "orders/1", "params": params})).unwrap();
    Call { grant, pcactn: a.pcactn, op }
}

fn opts(store: Arc<dyn StateStore>, req: PassportRequirement) -> AuthorizeOptions {
    AuthorizeOptions::new(store, |_, _| Ok(false))
        .with_plan(Some(SINGLE_STEP))
        .with_risk(insecure_calm_risk)
        .with_provenance_mediators(harness_pins())
        .with_provenance_bundle(principal_direct)
        .with_require_passport(req)
}

fn run(c: &Call, o: &AuthorizeOptions, passport: Option<&Value>) -> AuthorizeResult {
    let g = c.grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    o.run_with_passport(Some(&c.pcactn), Some(&c.op), AUD, &resolve, c.pcactn["iat"].as_i64(), passport)
}

fn requirement() -> PassportRequirement {
    PassportRequirement { trusted_issuers: vec!["some-issuer".into()], revoked: Some(Arc::new(|_, _, _| Ok(false))), ..Default::default() }
}

#[test]
fn a_call_without_a_passport_is_refused_before_the_counter_is_spent() {
    let c = call();
    let store = Arc::new(MemoryStateStore::new());
    let o = opts(store.clone(), requirement());
    let r = run(&c, &o, None);
    assert!(!r.allow && r.status == 403);
    assert!(r.reasons.iter().any(|x| x == "passport: malformed"), "{:?}", r.reasons);
    let stream = format!("{}:{}", c.grant["id"].as_str().unwrap(), c.pcactn["cap_chain"][0]["holder"].as_str().unwrap());
    assert_eq!(store.last(&stream), Some(None), "a refusal consumes nothing");
    // a passport that is not for a trusted issuer is refused with its reason
    let bogus = json!({"typ": "atlas-pca/passport", "ver": 1, "iss": "someone", "sub": "x", "sig": "s", "passport": {"id": "p", "model_id": "m", "operator": "o", "hardware_rooted": false}, "nbf": 1, "exp": 2, "iat": 1});
    let r = run(&c, &o, Some(&bogus));
    assert!(!r.allow);
    assert!(r.reasons.iter().any(|x| x.starts_with("passport: ")), "{:?}", r.reasons);
}

#[test]
fn a_configuration_without_issuers_or_a_revocation_source_is_refused() {
    let c = call();
    let o = opts(Arc::new(MemoryStateStore::new()), PassportRequirement::default());
    let r = run(&c, &o, None);
    assert!(!r.allow);
    assert!(r.reasons.iter().any(|x| x == "authorize_config: missing required component(s): require_passport.trusted_issuers, require_passport.revoked (fail closed)"), "{:?}", r.reasons);
}

#[test]
fn an_allow_under_the_gate_carries_the_passport_assurance() {
    let c = call();
    let iat = c.pcactn["iat"].as_i64().unwrap();
    let holder = c.pcactn["cap_chain"][0]["holder"].as_str().unwrap().to_string();
    let issuer = KeyPair::generate().unwrap();
    let pp = issue_passport(&json!({"model_id": "m", "operator": "acme", "hardware_rooted": false, "issued_at": iat - 1000})).unwrap();
    let sp = sign_passport(&pp, &issuer, &holder, None, None, iat + 3_600_000, None, &Suite::default()).unwrap();
    let req = PassportRequirement { trusted_issuers: vec![issuer.public.clone()], revoked: Some(Arc::new(|_, _, _| Ok(false))), ..Default::default() };
    let r = run(&c, &opts(Arc::new(MemoryStateStore::new()), req.clone()), Some(&sp));
    assert!(r.allow, "{:?}", r.reasons);
    let e = r.assurance.get("passport").expect("the allow reports the passport");
    assert_eq!((e.outcome, e.level.as_deref(), e.vendor.as_deref()), (CheckStatus::Pass, Some("software"), None));
    // a passport for another key is refused before the guard, and a gate-free call reports no passport entry
    let other = sign_passport(&pp, &issuer, &KeyPair::generate().unwrap().public, None, None, iat + 3_600_000, None, &Suite::default()).unwrap();
    let r = run(&c, &opts(Arc::new(MemoryStateStore::new()), req), Some(&other));
    assert!(!r.allow && r.reasons.iter().any(|x| x == "passport: subject_mismatch"), "{:?}", r.reasons);
}

#[test]
fn raw_text_presented_under_the_gate_is_checked_for_its_passport() {
    let c = call();
    let iat = c.pcactn["iat"].as_i64().unwrap();
    let holder = c.pcactn["cap_chain"][0]["holder"].as_str().unwrap().to_string();
    let issuer = KeyPair::generate().unwrap();
    let pp = issue_passport(&json!({"model_id": "m", "operator": "acme", "hardware_rooted": false, "issued_at": iat - 1000})).unwrap();
    let sp = sign_passport(&pp, &issuer, &holder, None, None, iat + 3_600_000, None, &Suite::default()).unwrap();
    let trusted = vec![issuer.public.clone()];
    let revoked = |_: &str, _: &str, _: &str| Ok::<bool, ()>(false);
    let po = PassportOptions {
        trusted_issuers: &trusted, now_ms: 0, clock_skew_ms: None, max_evidence_age_ms: None, subject: None, pq_pins: None, attest: None,
        default_verifier: None, revoked: Some(&revoked),
    };
    let g = c.grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let is_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let pins = harness_pins();
    let text = serde_json::to_string(&c.pcactn).unwrap();
    for (passport, allowed) in [(Some(&sp), true), (None, false)] {
        let store = MemoryStateStore::new();
        let input = AuthorizeInput {
            risk: Some(&insecure_calm_risk as &RiskFn),
            operation: Some(&c.op),
            audience: AUD,
            resolve_grant: Some(&resolve),
            state_store: Some(&store),
            is_revoked: Some(&is_revoked),
            now: Some(iat),
            plan: Some(SINGLE_STEP),
            provenance_mediators: &pins,
            provenance_bundle: Some(&principal_direct),
            require_passport: Some(&po),
            passport,
            ..Default::default()
        };
        let r = authorize_json(&text, &input);
        assert_eq!(r.allow, allowed, "{:?}", r.reasons);
        if allowed {
            assert_eq!(r.assurance.get("passport").and_then(|e| e.level.as_deref()), Some("software"));
        } else {
            assert!(r.reasons.iter().any(|x| x == "passport: malformed"), "{:?}", r.reasons);
        }
    }
}

fn gate_free_options() -> AuthorizeOptions {
    AuthorizeOptions::new(Arc::new(MemoryStateStore::new()), |_, _| Ok(false))
        .with_plan(Some(SINGLE_STEP))
        .with_risk(insecure_calm_risk)
        .with_provenance_mediators(harness_pins())
        .with_provenance_bundle(principal_direct)
}

#[test]
fn a_call_without_the_gate_reports_no_passport_entry() {
    let c = call();
    let r = run(&c, &gate_free_options(), None);
    assert!(r.allow, "{:?}", r.reasons);
    assert!(r.assurance.get("passport").is_none(), "no gate, no passport assurance");
}

#[test]
fn a_presented_value_has_its_passport_checked_exactly_once() {
    let c = call();
    let iat = c.pcactn["iat"].as_i64().unwrap();
    let holder = c.pcactn["cap_chain"][0]["holder"].as_str().unwrap().to_string();
    let issuer = KeyPair::generate().unwrap();
    let pp = issue_passport(&json!({"model_id": "m", "operator": "acme", "hardware_rooted": false, "issued_at": iat - 1000})).unwrap();
    let sp = sign_passport(&pp, &issuer, &holder, None, None, iat + 3_600_000, None, &Suite::default()).unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = calls.clone();
    let req = PassportRequirement {
        trusted_issuers: vec![issuer.public.clone()],
        revoked: Some(Arc::new(move |_, _, _| {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(false)
        })),
        ..Default::default()
    };
    let r = run(&c, &opts(Arc::new(MemoryStateStore::new()), req), Some(&sp));
    assert!(r.allow, "{:?}", r.reasons);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1, "the revocation source is asked once for a presented value");
}

#[test]
fn a_hardware_rooted_passport_with_a_closure_verifier_reports_level_unknown() {
    let c = call();
    let iat = c.pcactn["iat"].as_i64().unwrap();
    let holder = c.pcactn["cap_chain"][0]["holder"].as_str().unwrap().to_string();
    let issuer = KeyPair::generate().unwrap();
    let pp = issue_passport(&json!({"model_id": "m", "operator": "acme", "hardware_rooted": true, "issued_at": iat - 1000})).unwrap();
    let ev = json!({"document": {"nonce": "n1"}, "at": iat});
    let sp = sign_passport(&pp, &issuer, &holder, None, None, iat + 3_600_000, Some(&ev), &Suite::default()).unwrap();
    for hardware in [false, true] {
        let req = PassportRequirement {
            trusted_issuers: vec![issuer.public.clone()],
            revoked: Some(Arc::new(|_, _, _| Ok(false))),
            attest: Some(Arc::new(|_, _| {
                Ok(PassportAttestation { ok: true, bound: true, measured: json!({"model_id": "m", "operator": "acme"}).as_object().cloned() })
            })),
            hardware,
            ..Default::default()
        };
        let r = run(&c, &opts(Arc::new(MemoryStateStore::new()), req), Some(&sp));
        assert!(r.allow, "hardware={hardware}: {:?}", r.reasons);
        let e = r.assurance.get("passport").expect("the allow reports the passport");
        assert_eq!((e.outcome, e.level.as_deref(), e.vendor.as_deref()), (CheckStatus::Pass, Some("unknown"), None), "hardware={hardware}");
    }
}
