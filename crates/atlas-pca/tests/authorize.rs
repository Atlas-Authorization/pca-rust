//! `authorize` against the shared authorize-fixtures (signed by the TypeScript reference, outcomes recorded), the
//! replay stores and the opt-in middleware mode.

use std::sync::Arc;

use atlas_pca::{authorize, AuthorizeInput, MemoryStateStore, Operation, StateStore};
use serde_json::Value;

fn fixtures() -> Value {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/authorize-fixtures.json")).unwrap();
    atlas_pca::strict_parse(&text).unwrap()
}

fn run_step(d: &Value, grant: &Value, store: &dyn StateStore, step: &Value) -> atlas_pca::AuthorizeResult {
    let op = Operation::from_json(&step["operation"]).unwrap();
    let revoked = step["revoked"].as_bool().unwrap_or(false);
    let g = grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let is_revoked = move |_: &Value, _: &Value| Ok::<_, String>(revoked);
    let input = AuthorizeInput {
        operation: Some(&op),
        audience: d["audience"].as_str().unwrap(),
        resolve_grant: Some(&resolve),
        state_store: Some(store),
        is_revoked: Some(&is_revoked),
        now: d["now"].as_i64(),
        plan: Some("single-step"),
        ..Default::default()
    };
    authorize(Some(&step["pcactn"]), &input)
}

#[test]
fn shared_fixtures_match_the_recorded_outcomes() {
    let d = fixtures();
    let cases = d["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 31);
    for c in cases {
        let store = MemoryStateStore::new();
        for (i, s) in c["steps"].as_array().unwrap().iter().enumerate() {
            let r = run_step(&d, &c["grant"], &store, s);
            if let Some(why) = s["expect"]["reason"].as_str() {
                assert!(r.reason.as_deref().unwrap_or("").contains(why), "{} step {i}: reason {:?} lacks {why:?}", c["name"], r.reason);
            }
            let want: Vec<&str> = s["expect"]["failed"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
            assert_eq!(
                (r.allow, r.status as i64, r.failed_checks()),
                (s["expect"]["allow"].as_bool().unwrap(), s["expect"]["status"].as_i64().unwrap(), want),
                "{} step {i}",
                c["name"]
            );
        }
    }
}

fn first_step(d: &Value) -> (&Value, &Value) {
    (&d["cases"][0]["grant"], &d["cases"][0]["steps"][0])
}

#[test]
fn check_names_are_counter_format_and_replay() {
    assert_eq!(
        atlas_pca::DEFAULT_REQUIRED_CHECKS.join(","),
        "counter_format,replay,revocation,plan_root_authorized,audience,validity,grant_ref_bound,operation,params_digest,policy"
    );
    let d = fixtures();
    let (grant, s) = first_step(&d);
    let r = run_step(&d, grant, &MemoryStateStore::new(), s);
    assert!(r.allow);
    assert_eq!(
        (r.checks.get("counter_format").copied(), r.checks.get("replay").copied(), r.checks.contains_key("counter")),
        (Some(atlas_pca::CheckStatus::Pass), Some(atlas_pca::CheckStatus::Pass), false)
    );
    // the core verifier names its format check counter_format too
    let core = r.verdict.as_ref().unwrap();
    assert_eq!((core.checks.get("counter_format").copied(), core.checks.contains_key("counter")), (Some(true), false));
}

#[test]
fn require_counter_is_an_alias_of_replay() {
    let d = fixtures();
    let (grant, s) = first_step(&d);
    let op = Operation::from_json(&s["operation"]).unwrap();
    let g = grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let store = MemoryStateStore::new();
    let input = AuthorizeInput {
        operation: Some(&op),
        audience: d["audience"].as_str().unwrap(),
        resolve_grant: Some(&resolve),
        state_store: Some(&store),
        is_revoked: Some(&revoked),
        now: d["now"].as_i64(),
        plan: Some("single-step"),
        require: &["counter"],
        ..Default::default()
    };
    let r = authorize(Some(&s["pcactn"]), &input);
    assert_eq!((r.allow, r.status), (true, 200), "{r:?}");
}

struct Fake(Result<atlas_pca::ClaimResult, atlas_pca::StoreError>);
impl StateStore for Fake {
    fn claim(&self, _: &str, _: u64) -> Result<atlas_pca::ClaimResult, atlas_pca::StoreError> {
        self.0.clone()
    }
}

#[test]
fn replay_refusals_use_the_replay_prefix() {
    let d = fixtures();
    let (grant, s) = first_step(&d);
    let n = s["pcactn"]["counter"].as_u64().unwrap();
    for (store, want) in [
        (Fake(Ok(atlas_pca::ClaimResult::replay(Some(7)))), format!("replay: {n} is not greater than last seen 7 (replay)")),
        (Fake(Ok(atlas_pca::ClaimResult::replay(None))), format!("replay: {n} was already claimed (replay)")),
        (Fake(Err(atlas_pca::StoreError("down".into()))), "replay: the replay store failed (fail closed)".to_string()),
    ] {
        let r = run_step(&d, grant, &store, s);
        assert_eq!((r.allow, r.status, r.reason.clone(), r.failed_checks()), (false, 403, Some(want), vec!["replay"]));
        assert!(!r.checks.contains_key("counter"));
    }
}

#[test]
fn missing_components_deny() {
    let d = fixtures();
    let c = &d["cases"][0];
    let s = &c["steps"][0];
    let op = Operation::from_json(&s["operation"]).unwrap();
    let g = c["grant"].clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let store = MemoryStateStore::new();
    let full = AuthorizeInput {
        operation: Some(&op),
        audience: d["audience"].as_str().unwrap(),
        resolve_grant: Some(&resolve),
        state_store: Some(&store),
        is_revoked: Some(&revoked),
        now: d["now"].as_i64(),
        plan: Some("single-step"),
        ..Default::default()
    };
    assert!(authorize(Some(&s["pcactn"]), &full).allow);
    let no_store = AuthorizeInput { state_store: None, ..full };
    let no_revoked = AuthorizeInput { is_revoked: None, ..full };
    let no_op = AuthorizeInput { operation: None, ..full };
    let no_aud = AuthorizeInput { audience: "", ..full };
    let no_resolver = AuthorizeInput { resolve_grant: None, ..full };
    let bad_plan = AuthorizeInput { plan: Some("anything"), ..full };
    for (name, input) in [("store", no_store), ("revoked", no_revoked), ("op", no_op), ("aud", no_aud), ("resolver", no_resolver), ("plan", bad_plan)] {
        let r = authorize(Some(&s["pcactn"]), &input);
        assert!(!r.allow && r.status == 403, "{name}: {r:?}");
    }
}

fn exercise(store: &dyn StateStore) {
    for (n, ok) in [(5u64, true), (5, false), (4, false), (6, true)] {
        assert_eq!(store.claim("k", n).unwrap().ok, ok, "claim {n}");
    }
    assert_eq!(store.claim("k", 1).unwrap().last_counter, Some(6));
    let store: &dyn StateStore = store;
    let wins = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..16).map(|_| sc.spawn(|| store.claim("c", 1).map(|r| r.ok).unwrap_or(false))).collect();
        hs.into_iter().map(|h| h.join().unwrap()).filter(|w| *w).count()
    });
    assert_eq!(wins, 1, "exactly one concurrent claim wins");
}

#[test]
fn memory_store_is_monotone_and_atomic() {
    exercise(&MemoryStateStore::new());
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_store_is_monotone_atomic_and_durable() {
    let dir = std::env::temp_dir().join(format!("pca-authz-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("r.db");
    exercise(&atlas_pca::SqliteStateStore::open(&path).unwrap());
    // a second handle on the same file sees the committed counters (a restart cannot replay)
    let again = atlas_pca::SqliteStateStore::open(&path).unwrap();
    assert!(!again.claim("k", 6).unwrap().ok);
    assert!(again.claim("k", 7).unwrap().ok);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "axum")]
mod mw {
    use super::*;
    use atlas_pca::middleware::{authorize_request, verify_request, GuardConfig};
    use atlas_pca::{canonicalize_strict, AuthorizeOptions};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    fn cfg(d: &Value, grant: &Value, op: Operation) -> (GuardConfig, Arc<MemoryStateStore>) {
        let store = Arc::new(MemoryStateStore::new());
        let g = grant.clone();
        let now = d["now"].as_i64().unwrap();
        let c = GuardConfig::new(d["audience"].as_str().unwrap().to_string(), move |_: &str| Some(g.clone()))
            .with_clock(move || now)
            .with_authorize(AuthorizeOptions::new(store.clone(), |_: &Value, _: &Value| Ok(false)))
            .with_operation(move |_, _| Some(op.clone()));
        let _ = &c;
        (c, store)
    }

    fn header(p: &Value) -> String {
        URL_SAFE_NO_PAD.encode(canonicalize_strict(p).unwrap().as_bytes())
    }

    use atlas_pca::CheckStatus;

    fn base(d: &Value, grant: &Value) -> GuardConfig {
        let g = grant.clone();
        let now = d["now"].as_i64().unwrap();
        GuardConfig::new(d["audience"].as_str().unwrap().to_string(), move |_: &str| Some(g.clone())).with_clock(move || now)
    }

    fn case<'a>(d: &'a Value, name: &str) -> &'a Value {
        d["cases"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap()
    }

    // Every shared fixture step through the DEFAULT guard (no opt-in): the recorded status, and the recorded reason text.
    #[test]
    fn default_guard_runs_every_fixture_case() {
        let d = fixtures();
        for c in d["cases"].as_array().unwrap() {
            let store = Arc::new(MemoryStateStore::new());
            for (i, s) in c["steps"].as_array().unwrap().iter().enumerate() {
                let revoked = s["revoked"].as_bool().unwrap_or(false);
                let op = Operation::from_json(&s["operation"]).unwrap();
                let cfg = base(&d, &c["grant"])
                    .with_authorize(AuthorizeOptions::new(store.clone(), move |_: &Value, _: &Value| Ok(revoked)))
                    .with_operation(move |_, _| Some(op.clone()));
                let r = authorize_request(Some(&header(&s["pcactn"])), None, Operation::from_json(&s["operation"]), &cfg);
                let want = if s["expect"]["allow"].as_bool().unwrap() { 200 } else { s["expect"]["status"].as_u64().unwrap() as u16 };
                assert_eq!(r.status, want, "{} step {i}: {}", c["name"], r.description);
                if let Some(why) = s["expect"]["reason"].as_str() {
                    assert!(r.json_body()["reason"].as_str().unwrap_or("").contains(why), "{} step {i}", c["name"]);
                }
            }
        }
    }

    #[test]
    fn default_guard_without_authorize_options_refuses_naming_the_missing_components() {
        let d = fixtures();
        let c = case(&d, "envelope-predicate-within");
        let s = &c["steps"][0];
        let cfg = base(&d, &c["grant"]);
        let r = authorize_request(Some(&header(&s["pcactn"])), None, Operation::from_json(&s["operation"]), &cfg);
        let a = r.authorization.as_ref().unwrap();
        assert_eq!((r.allow, r.status, a.checks.get("authorize_config").copied()), (false, 403, Some(CheckStatus::Fail)));
        assert_eq!(a.missing, Some(vec!["state_store".to_string(), "is_revoked".to_string()]));
        // verify_request is the same guard: no operation to map, so it never silently downgrades to signature-only
        assert!(!verify_request(Some(&header(&s["pcactn"])), None, &cfg).allow);
    }

    #[test]
    fn default_guard_without_operation_mapping_refuses() {
        let d = fixtures();
        let c = case(&d, "envelope-predicate-within");
        let s = &c["steps"][0];
        let cfg = base(&d, &c["grant"]).with_authorize(AuthorizeOptions::new(Arc::new(MemoryStateStore::new()), |_: &Value, _: &Value| Ok(false)));
        let r = authorize_request(Some(&header(&s["pcactn"])), None, None, &cfg);
        assert_eq!((r.allow, r.status), (false, 403));
        assert_eq!(r.authorization.unwrap().checks.get("operation").copied(), Some(CheckStatus::Fail));
    }

    #[test]
    fn signature_only_is_an_explicit_opt_in_and_skips_policy() {
        let d = fixtures();
        let c = case(&d, "envelope-predicate-400-refused");
        let h = header(&c["steps"][0]["pcactn"]);
        let cfg = base(&d, &c["grant"]);
        assert!(!verify_request(Some(&h), None, &cfg).allow);
        let r = verify_request(Some(&h), None, &cfg.with_signature_only());
        assert!(r.allow && r.status == 200 && r.authorization.is_none(), "{}", r.description);
    }

    #[test]
    #[should_panic(expected = "mutually exclusive")]
    fn signature_only_then_authorize_is_a_construction_error() {
        let d = fixtures();
        let _ = base(&d, &d["cases"][0]["grant"])
            .with_signature_only()
            .with_authorize(AuthorizeOptions::new(Arc::new(MemoryStateStore::new()), |_: &Value, _: &Value| Ok(false)));
    }

    #[test]
    #[should_panic(expected = "mutually exclusive")]
    fn authorize_then_signature_only_is_a_construction_error() {
        let d = fixtures();
        let _ = base(&d, &d["cases"][0]["grant"])
            .with_authorize(AuthorizeOptions::new(Arc::new(MemoryStateStore::new()), |_: &Value, _: &Value| Ok(false)))
            .with_signature_only();
    }

    #[test]
    fn authorize_mode_binds_the_operation_and_refuses_replay() {
        let d = fixtures();
        let by = |n: &str| d["cases"].as_array().unwrap().iter().find(|c| c["name"] == n).unwrap().clone();
        let ok = by("envelope-predicate-within");
        let s = &ok["steps"][0];
        let (c, _) = cfg(&d, &ok["grant"], Operation::from_json(&s["operation"]).unwrap());
        let h = header(&s["pcactn"]);
        let first = authorize_request(Some(&h), None, Operation::from_json(&s["operation"]), &c);
        assert!(first.allow && first.status == 200);
        let replay = authorize_request(Some(&h), None, Operation::from_json(&s["operation"]), &c);
        assert!(!replay.allow && replay.status == 403);
        // the same signed proof for a different executed operation ($400 instead of the signed $50) is refused
        let (c2, _) = cfg(&d, &ok["grant"], Operation::from_json(&s["operation"]).unwrap());
        let mut op = Operation::from_json(&s["operation"]).unwrap();
        op.params["amount"] = serde_json::json!(400);
        assert!(!authorize_request(Some(&h), None, Some(op), &c2).allow);
        // no operation mapped = denied
        assert!(!authorize_request(Some(&h), None, None, &c2).allow);
        // verify_request on an authorize-mode config cannot map an operation and denies
        let (c3, _) = cfg(&d, &ok["grant"], Operation::from_json(&s["operation"]).unwrap());
        assert!(!verify_request(Some(&h), None, &c3).allow);
    }
}
