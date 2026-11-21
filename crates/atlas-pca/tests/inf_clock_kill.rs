//! Kill tests: an infinite (or NaN) clock, expiry, budget or tolerance never admits. Each case names what the old comparison did.
use atlas_pca::acp::check_payment_authority;
use atlas_pca::agent_native::envelope_permits;
use atlas_pca::agent::KeyPair;
use atlas_pca::bond_settlement::{BondSettlementPlanner, StoreBondLedger};
use atlas_pca::bond_store::{BondStore, KvBondStore};
use atlas_pca::kv::{AtomicKv, MemoryAtomicKv};
use atlas_pca::analyzer::minimal_flip;
use atlas_pca::ap2::{check_payment_constraints, PayCtx};
use atlas_pca::doctor::{check_clock, FetchInit, FetchResponse};
use atlas_pca::erc7715::{grant_to_permission_request, verify_granted_permission};
use atlas_pca::gnap::{InteractionServer, InteractionServerOptions};
use atlas_pca::signals::{ssf_management_handler, MemoryStreamStore, SsfManageOptions, StreamHealth, StreamHealthOptions};
use atlas_pca::{
    check_revocation_age, execute_authorized, freshness_gate_check, AuthorizedOperation, ExecutableAuthorization, ExecuteOptions, ExecuteOutcome, FreshnessGate,
    MemoryOperationStore, OperationRecord, OperationState, OperationStore, Reversibility,
};
use atlas_pca::ciba::create_ciba_broker;
use atlas_pca::dpop::{DpopReplayStore, InMemoryDpopReplayStore};
use atlas_pca::gateway::MemoryReplayGuard;
use atlas_pca::payments::{shared_payment_token_limits, sign_stripe_payload, verify_stripe_signature};
use atlas_pca::replay_guard::{InMemoryReplayStore, ReplayStore};
use atlas_pca::risk::{debit_consolidated, sub_budget, TrustBudget};
use atlas_pca::serde_json::{json, Value};
use atlas_pca::signals::{create_in_memory_set_replay_store, SetReplayStore};
use atlas_pca::wallet::SlidingWindowCounter;
use atlas_pca::webbotauth::{memory_replay_cache, ReplayCache};
use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;

const BAD: [f64; 3] = [f64::NAN, f64::INFINITY, f64::NEG_INFINITY];

fn tb(b: f64) -> TrustBudget {
    TrustBudget { b, tau: 0.0, as_of: None }
}

// old: `now_sec < held` is false for an infinite clock, so a live jti was accepted again
#[test]
fn dpop_replay_store_refuses_a_non_finite_clock_or_expiry() {
    let s = InMemoryDpopReplayStore::new(None).unwrap();
    assert_eq!(s.add_if_absent("j", 100.0, 10.0), Ok(true));
    for b in BAD {
        assert_eq!(s.add_if_absent("j", 100.0, b), Ok(false), "clock {b}");
        assert_eq!(s.add_if_absent("k", b, 10.0), Ok(false), "expiry {b}");
    }
}

#[test]
fn set_replay_store_refuses_a_non_finite_clock_or_expiry() {
    let mut s = create_in_memory_set_replay_store(None).unwrap();
    assert_eq!(s.add_if_absent("j", 100.0, 10.0), Ok(true));
    for b in BAD {
        assert_eq!(s.add_if_absent("j", 100.0, b), Ok(false), "clock {b}");
        assert_eq!(s.add_if_absent("k", b, 10.0), Ok(false), "expiry {b}");
    }
}

#[test]
fn web_bot_auth_replay_cache_refuses_a_non_finite_clock_or_expiry() {
    let c = memory_replay_cache(None);
    assert_eq!(c.claim("j", 100.0, 10.0), Ok(true));
    for b in BAD {
        assert_eq!(c.claim("j", 100.0, b), Ok(false), "clock {b}");
        assert_eq!(c.claim("k", b, 10.0), Ok(false), "expiry {b}");
    }
}

// old: `retain_until >= +Infinity` is false, so a prune on an infinite clock freed every live key
#[test]
fn replay_store_prune_ignores_a_non_finite_clock() {
    let s = InMemoryReplayStore::new(10);
    assert_eq!(s.consume_once("k", 100.0, 10.0), Ok(true));
    for b in BAD {
        assert_eq!(s.prune(b), 0, "clock {b}");
    }
    assert_eq!(s.consume_once("k", 100.0, 10.0), Ok(false));
}

#[test]
fn gateway_replay_guard_refuses_a_non_finite_clock_or_expiry() {
    let g = MemoryReplayGuard::new(10, Arc::new(|| 10.0));
    for b in BAD {
        assert!(g.claim_at("j", 1000.0, Some(b)).is_err(), "clock {b}");
        assert!(g.claim_at("k", b, None).is_err(), "expiry {b}");
    }
    assert_eq!(g.claim_at("j", 1000.0, None), Ok(true));
}

// old: `now >= expires_at` is false for NaN and -Infinity, so the request stayed pending forever
#[test]
fn ciba_session_expires_on_a_non_finite_clock() {
    let t = Rc::new(Cell::new(0.0));
    let t2 = t.clone();
    let b = create_ciba_broker(Box::new(move || t2.get()), None);
    let su = json!({ "id": "su1", "verb": "stripe.payout", "resource": "acct:1", "params": { "amount": 80, "currency": "USD", "payee": "bob" }, "tier": 3, "reason": "r",
        "goalCommit": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq", "goal": "pay suppliers", "lineage": {}, "r": 0.5, "requestedAt": 1 });
    let req = b.start(&su, &Value::Null).unwrap();
    let id = req["auth_req_id"].as_str().unwrap().to_string();
    assert_eq!(b.poll(&id).unwrap()["status"], json!("pending"));
    for bad in BAD {
        t.set(bad);
        assert_eq!(b.poll(&id).unwrap()["status"], json!("expired"), "clock {bad}");
    }
}

// old: an infinite clock emptied the window (a +Infinity prune dropped every entry) and NaN skipped the cap
#[test]
fn sliding_window_counter_refuses_a_non_finite_clock() {
    let mut w = SlidingWindowCounter::new(1000.0).unwrap();
    assert_eq!(w.try_add(10.0, 2.0), Ok(true));
    for b in BAD {
        assert_eq!(w.try_add(b, 2.0), Ok(false), "clock {b}");
        assert_eq!(w.count(b), 1, "clock {b}");
    }
    assert_eq!(w.try_add(f64::NAN, f64::NAN), Ok(false));
    assert_eq!(w.try_add(11.0, f64::NAN), Ok(false));
}

// old: `alloc > +Infinity` / `+Infinity < x` are false, so an infinite remaining budget covered any allocation or debit
#[test]
fn budgets_that_are_not_finite_cover_nothing() {
    for b in BAD {
        assert!(sub_budget(&tb(b), 5.0).is_err(), "parent {b}");
        assert!(debit_consolidated(&tb(b), &tb(10.0), 1.0).is_err(), "parent {b}");
        assert!(debit_consolidated(&tb(10.0), &tb(b), 1.0).is_err(), "sub {b}");
    }
    assert!(sub_budget(&tb(10.0), 5.0).is_ok());
}

// old: `tolerance < |now - t|` is false for an infinite tolerance, so any stale signature verified
#[test]
fn stripe_signature_refuses_an_infinite_tolerance() {
    let header = sign_stripe_payload("{}", "whsec", 1000.0);
    assert!(verify_stripe_signature("{}", Some(&header), Some("whsec"), 1000.0, 300.0));
    for tol in BAD {
        assert!(!verify_stripe_signature("{}", Some(&header), Some("whsec"), 1_000_000_000.0, tol), "tolerance {tol}");
    }
}

fn closed() -> Value {
    json!({ "payment_amount": { "amount": 10, "currency": "USD" } })
}

fn violations(constraint: Value, context: Value, now: f64) -> Vec<String> {
    let open = json!({ "constraints": [{ "type": "payment.amount_range", "currency": "USD", "max": 1000 }, constraint] });
    check_payment_constraints(Some(&open), Some(&closed()), &PayCtx { open_checkout_hash: None, context: Some(&context), now }).unwrap()
}

// old: with a clock of +Infinity the period start saturated, so a use made in the current period read as unused
#[test]
fn ap2_recurrence_refuses_a_non_finite_clock() {
    let c = json!({ "type": "payment.agent_recurrence", "frequency": "DAILY" });
    let ctx = json!({ "totalAmount": 0, "totalUses": 0, "lastUsedDate": 0 });
    assert!(violations(c.clone(), ctx.clone(), 200_000.0).is_empty());
    for b in BAD {
        assert!(!violations(c.clone(), ctx.clone(), b).is_empty(), "clock {b}");
    }
}

// old: `max * 100` of Infinity made the budget check report nothing, so any spend passed
#[test]
fn ap2_budget_with_an_infinite_max_refuses() {
    let ctx = json!({ "totalAmount": 0, "totalUses": 0 });
    let c = json!({ "type": "payment.budget", "currency": "USD", "max": "Infinity" });
    assert!(!violations(c, ctx.clone(), 1.0).is_empty());
    let ok = json!({ "type": "payment.budget", "currency": "USD", "max": 100 });
    assert!(violations(ok, ctx, 1.0).is_empty());
}

// old: a NaN clock made `at < not_before` false, so the execution window was never enforced
#[test]
fn ap2_execution_date_refuses_a_non_finite_clock() {
    let c = json!({ "type": "payment.execution_date", "not_before": "2000-01-01T00:00:00Z" });
    let ctx = json!({ "totalAmount": 0, "totalUses": 0 });
    assert!(violations(c.clone(), ctx.clone(), 1_000_000_000.0).is_empty());
    for b in BAD {
        assert!(!violations(c.clone(), ctx.clone(), b).is_empty(), "clock {b}");
    }
}

// old: a period end that is not a finite number was not refused (an infinite one left the token with no expiry)
#[test]
fn shared_payment_token_limits_refuses_a_non_finite_period_end() {
    let m = |pe: Value| json!({ "terms": { "autoApproveThreshold": 100, "currency": "USD", "periodEnd": pe }, "budget": { "B": 1000 } });
    assert!(shared_payment_token_limits(&m(json!(2_000_000)), &json!(1_000_000)).is_ok());
    for pe in [json!(null), json!("Infinity"), json!("-Infinity"), json!("NaN")] {
        let err = shared_payment_token_limits(&m(pe.clone()), &json!(1_000_000)).unwrap_err();
        assert!(err.contains("periodEnd must be an epoch-ms time"), "periodEnd {pe}: {err}");
    }
}

// old: only a NaN cap was refused; a negative or non-integer cap compared as a number and was admitted or mis-reasoned
#[test]
fn acp_authority_refuses_a_cap_that_is_not_a_non_negative_integer() {
    let req = json!({ "amount": 5, "currency": "USD", "merchant": "m" });
    assert_eq!(check_payment_authority(&json!({ "maxAmount": 5 }), &req).unwrap()["ok"], true);
    assert_eq!(check_payment_authority(&json!({}), &req).unwrap()["ok"], true);
    for cap in [json!(null), json!(-1), json!(-0.0), json!(1.5), json!("Infinity"), json!("5")] {
        let r = check_payment_authority(&json!({ "maxAmount": cap }), &req).unwrap();
        assert_eq!(r["ok"], false, "cap {cap}");
        assert_eq!(r["reason"], "authorized spend cap is not a non-negative integer (fail closed)", "cap {cap}");
    }
}

// old: an unknown frequency was a violation only when a last-used date existed
#[test]
fn ap2_recurrence_refuses_an_unknown_frequency_without_a_last_used_date() {
    let ctx = json!({ "totalAmount": 0, "totalUses": 0 });
    for f in [json!("HOURLY"), json!(null), json!(7)] {
        let c = json!({ "type": "payment.agent_recurrence", "frequency": f });
        assert_eq!(violations(c, ctx.clone(), 1.0), vec!["unknown recurrence frequency".to_string()], "frequency {f}");
    }
}

// old: n/a (the clock was already checked in load); a non-finite clock must never read as a finalized challenge window
#[test]
fn bond_challenge_status_refuses_a_non_finite_clock() {
    let seed = [7u8; 32];
    for t in BAD {
        let store: Arc<dyn BondStore> = Arc::new(KvBondStore::new(Arc::new(MemoryAtomicKv::new()) as Arc<dyn AtomicKv>));
        let planner = BondSettlementPlanner::new(KeyPair::from_seed(&seed), None, None, None, None, None, None).unwrap();
        let ledger = StoreBondLedger::new(store, planner, Some(Box::new(move || t)), None);
        let err = ledger.challenge_status("c").unwrap_err();
        assert_eq!(err.code, "clock_invalid", "clock {t}");
    }
}

// old: a hint that was present but not a finite number (a non-finite value is stored as null) was skipped, so it never constrained
#[test]
fn envelope_permits_refuses_a_non_finite_hint() {
    let env = |hints: Value| json!({ "ok": true, "unsatisfiable": [], "scopes": null, "remainingBudgetHints": hints });
    assert!(envelope_permits(&env(json!({ "expiresAt": 2000, "notBefore": 100, "delegationDepthRemaining": 1 })), "v", "r", Some(1000.0), None));
    for hints in [json!({ "expiresAt": null }), json!({ "notBefore": null }), json!({ "delegationDepthRemaining": null })] {
        assert!(!envelope_permits(&env(hints.clone()), "v", "r", Some(1000.0), None), "hints {hints}");
    }
}

// old: a non-finite clock or window read as `finalized`, which opens settlement
#[test]
fn claim_status_refuses_a_non_finite_clock_or_window() {
    use atlas_pca::optimistic::claim_status;
    assert_eq!(claim_status(1000.0, 500.0, 1200.0), Ok("open"));
    assert_eq!(claim_status(1000.0, 500.0, 1600.0), Ok("finalized"));
    for b in BAD {
        assert!(claim_status(1000.0, 500.0, b).is_err(), "clock {b}");
        assert!(claim_status(b, 500.0, 1200.0).is_err(), "issued_at {b}");
        assert!(claim_status(1000.0, b, 1200.0).is_err(), "window {b}");
    }
}

// old: a NaN gate clock made both the future and the stale comparison false, so any anchor passed
#[test]
fn freshness_gate_refuses_a_non_finite_gate_clock() {
    let p = json!({ "freshness": { "beacon_ref": "b", "epoch": 1 } });
    let p = p.as_object().unwrap();
    let gate = |now: Option<f64>| FreshnessGate { max_age_ms: 100_000.0, epoch_ms: None, now, clock_skew_ms: None };
    assert_eq!(freshness_gate_check(p, &gate(Some(70_000.0)), 0), Ok(()));
    for b in BAD {
        let e = freshness_gate_check(p, &gate(Some(b)), 0).unwrap_err();
        assert!(e.contains("misconfigured"), "clock {b}: {e}");
    }
}

fn pending_record(id: &str) -> OperationRecord {
    OperationRecord {
        id: id.into(),
        state: OperationState::Pending,
        verb: "v".into(),
        resource: "r".into(),
        params_digest: "d".into(),
        reversibility: Reversibility::Reversible,
        started_at: 0,
        executing_at: None,
        finished_at: None,
        result: None,
        error: None,
    }
}

// old: a negative pending timeout made every open record "older than the timeout", settling an in-flight claim as aborted
#[test]
fn a_negative_pending_timeout_never_ages_an_open_record() {
    let run = |timeout: i64| {
        let store = MemoryOperationStore::new();
        store.create(pending_record("op")).unwrap();
        let az = ExecutableAuthorization {
            allow: true,
            pcactn: Some(json!({ "action": { "reversibility_class": "reversible" } })),
            operation: Some(AuthorizedOperation { verb: "v".into(), resource: "r".into(), params_digest: "d".into(), id: "op".into() }),
        };
        let clock = || 1_000_000i64;
        let opts = ExecuteOptions { store: Some(&store), reversibility_class: Some("reversible"), pending_timeout_ms: Some(timeout), now: Some(&clock), ..Default::default() };
        execute_authorized(&az, |_| Ok(json!(1)), &opts)
    };
    assert!(matches!(run(10), ExecuteOutcome::Aborted { .. }));
    assert!(matches!(run(-1), ExecuteOutcome::Pending { .. }));
}

// old: a skew limit that is not a number made every comparison false, so the clock check passed
#[test]
fn doctor_clock_check_fails_on_a_threshold_that_is_not_a_number() {
    let fetch = |_: &str, _: &FetchInit| -> Result<FetchResponse, String> { Ok(FetchResponse { status: 200, headers: vec![("date".into(), "Thu, 01 Jan 1970 00:00:10 GMT".into())] }) };
    let now = || 10_000.0;
    let status = |clock: Value| check_clock(&json!({ "url": "https://x.example", "clock": clock }), &fetch, &now)["status"].clone();
    assert_eq!(status(json!({ "referenceUrl": "local" })), json!("pass"));
    assert_eq!(status(json!({ "referenceUrl": "local", "maxSkewMs": "abc" })), json!("fail"));
    assert_eq!(status(json!({ "referenceUrl": "local", "warnFraction": "abc" })), json!("fail"));
}

// old: a grant expiry that was not a safe integer bounded nothing, so any wallet expiry rule was accepted
#[test]
fn erc7715_grant_expiry_that_is_not_an_integer_bounds_nothing() {
    let addr = |c: char| format!("0x{}", c.to_string().repeat(40));
    let g = json!({ "grantDigest": "d", "capMinor": 100, "expiresAtSec": 2000 });
    let sent = grant_to_permission_request(&g, 1, &addr('a'), None, "1", None, None).unwrap();
    let mut got = sent.clone();
    got["context"] = json!("0xab");
    got["delegationManager"] = json!(addr('b'));
    let managers = [addr('b')];
    let managers: Vec<&str> = managers.iter().map(String::as_str).collect();
    assert_eq!(verify_granted_permission(&g, &sent, &got, &managers, None), None);
    for bad in [json!(null), json!("2000"), json!(1.5)] {
        let mut g2 = g.clone();
        g2["expiresAtSec"] = bad.clone();
        assert_eq!(verify_granted_permission(&g2, &sent, &got, &managers, None), Some("expiry_extended"), "expiresAtSec {bad}");
    }
    let mut g3 = g.clone();
    g3.as_object_mut().unwrap().remove("expiresAtSec");
    assert_eq!(verify_granted_permission(&g3, &sent, &got, &managers, None), Some("expiry_extended"));
}

// old: a clock, window or history stamp that was infinite or NaN emptied the probe window (or kept every stamp), so the limiter admitted
#[test]
fn minimal_flip_probe_limiter_refuses_a_non_finite_clock_window_or_stamp() {
    let policy = json!({ "predicates": [], "caveats": [] });
    let action = json!({ "verb": "v", "resource": "/r", "params": {} });
    let flip = |probe: Value| minimal_flip(&policy, &action, &json!({ "holderAuthenticated": true, "probe": probe })).unwrap();
    let inf = |s: &str| json!({ "$num": s });
    let ok = flip(json!({ "limit": 5, "windowSecs": 60, "history": [1000], "now": 3000 }));
    assert!(ok.get("refused").is_none());
    for s in ["NaN", "Infinity", "-Infinity"] {
        assert_eq!(flip(json!({ "limit": 5, "windowSecs": 60, "history": [1000], "now": inf(s) }))["refused"], "probe budget exhausted", "now {s}");
        assert_eq!(flip(json!({ "limit": 5, "windowSecs": inf(s), "history": [1000], "now": 3000 }))["refused"], "probe budget exhausted", "window {s}");
        assert_eq!(flip(json!({ "limit": 5, "windowSecs": 60, "history": [inf(s)], "now": 3000 }))["refused"], "probe budget exhausted", "stamp {s}");
    }
    // a NaN limit is exhausted; an infinite limit is the legitimate unbounded cap
    assert_eq!(flip(json!({ "limit": inf("NaN"), "windowSecs": 60, "history": [1000], "now": 3000 }))["refused"], "probe budget exhausted");
    assert!(flip(json!({ "limit": inf("Infinity"), "windowSecs": 60, "history": [1000], "now": 3000 })).get("refused").is_none());
}

fn interaction_server(ttl: f64, now: f64) -> InteractionServer {
    InteractionServer::new(InteractionServerOptions {
        grant_endpoint: "https://as.example/tx".into(),
        supports: vec!["redirect".into()],
        redirect_uri: Box::new(|id| format!("https://as.example/i/{id}")),
        app_uri: None,
        user_code_uri: None,
        ttl_sec: Some(ttl),
        now: Box::new(move || now),
    })
}

// old: an infinite interaction expiry compared true against every finite clock, so the interaction never expired
#[test]
fn gnap_interaction_with_an_infinite_expiry_is_expired() {
    let req = json!({ "start": ["redirect"] });
    let mut live = interaction_server(600.0, 1000.0);
    let (it, _) = live.start(&req).unwrap();
    assert!(live.approve(&it.id).is_ok());
    let mut forever = interaction_server(f64::INFINITY, 1000.0);
    let (it, _) = forever.start(&req).unwrap();
    assert_eq!(forever.approve(&it.id).unwrap_err().code, "expired");
}

// old: a NaN failure limit made `fails >= limit` false, so a stream that kept timing out never read as failing
#[test]
fn stream_health_with_a_nan_failure_limit_reads_failing() {
    let mut h = StreamHealth::new(&json!({}), StreamHealthOptions { verify_timeout_sec: Some(1.0), fail_after: Some(f64::NAN), ..Default::default() });
    assert!(h.request_verification(0.0).unwrap().is_some());
    assert_eq!(h.report(10.0)["state"], "failing");
}

// old: a NaN stream cap made `count >= cap` false, so a receiver could open unlimited streams
#[test]
fn ssf_management_refuses_a_stream_when_the_cap_is_not_a_number() {
    let post = |cap: Option<f64>| {
        let mut store = MemoryStreamStore::default();
        let poll = |id: &str| format!("https://tx.example/poll/{id}");
        let mut deliver = |_: &Value, _: &str| -> Result<(), String> { Ok(()) };
        let clock = || 1000.0;
        let mut new_id = || "s1".to_string();
        let mut o = SsfManageOptions {
            store: &mut store,
            issuer: "https://tx.example".into(),
            events_supported: vec![],
            delivery_methods: None,
            poll_endpoint: &poll,
            signing_seed: [1u8; 32],
            deliver: &mut deliver,
            max_streams_per_receiver: cap,
            max_subjects_per_stream: None,
            now: &clock,
            new_id: &mut new_id,
        };
        let auth = |_: &Value| -> Result<Option<Value>, String> { Ok(Some(json!({ "id": "rx1", "aud": "rx" }))) };
        ssf_management_handler(&mut o, &json!({ "method": "POST", "path": "/ssf/configuration", "body": {} }), &auth)
    };
    assert_ne!(post(None)["status"], 409);
    assert_eq!(post(Some(f64::NAN))["status"], 409);
}

// old: a non-finite verifier clock was reported as an issue in the future; the reason now names the clock
#[test]
fn revocation_age_names_a_clock_that_is_not_finite() {
    assert_eq!(check_revocation_age(Some(1000.0), 2000.0, 300_000.0, "revocation state"), Ok(()));
    for b in BAD {
        let e = check_revocation_age(Some(1000.0), b, 300_000.0, "revocation state").unwrap_err();
        assert_eq!(e, "revocation state cannot be aged: the clock is not a finite number", "clock {b}");
    }
}
