//! Escalation answers (vectors shared with TypeScript / Go / Python) and the guard: escalate is surfaced distinctly, refused
//! without an answer, admitted only by a bound principal answer spent by the replay counter, never upgraded from a deny.

use std::sync::Mutex;

use atlas_pca::serde_json::{json, Value};
use atlas_pca::{
    authorize, canonicalize_strict, escalation_action_digest, escalation_history_head,
    escalation_policy_digest, supported_suites, verify_escalation_answer, AuthorizeInput,
    ClaimResult, EscalationBinding, EscalationVerdict, MemoryStateStore, Operation, PinnedSigner,
    StateStore, StoreError, Verdict, CORE_HOOK, ESCALATION_ANSWER_DOMAIN,
};
use ed25519_dalek::{Signer, SigningKey};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/"
);
// the hook is process-global: tests that set it run one at a time
static SERIAL: Mutex<()> = Mutex::new(());

fn b64u(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn read(name: &str) -> Value {
    atlas_pca::strict_parse(&std::fs::read_to_string(format!("{DIR}{name}")).unwrap()).unwrap()
}

/// The shared vectors, parsed with plain serde_json (the strict profile caps nesting at 32; some vectors nest deeper).
fn vectors() -> Value {
    let p = format!("{DIR}decision-vectors.json");
    atlas_pca::serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn escalation_answer_vectors() {
    let doc = vectors();
    let have = supported_suites();
    let mut ran = std::collections::BTreeSet::new();
    for e in doc["primitives"]["escalation_answer"].as_array().unwrap() {
        let input = match e["input_text"].as_str() {
            Some(t) => atlas_pca::serde_json::from_str::<Value>(t).unwrap(),
            None => e["input"].clone(),
        };
        let i = &input;
        let pins: Vec<PinnedSigner> = i["principals"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| match p.as_str() {
                Some(pk) => PinnedSigner::ed25519(pk),
                None => PinnedSigner {
                    pk: p["pk"].as_str().unwrap().to_string(),
                    pq_pk: p["pq_pk"].as_str().map(String::from),
                },
            })
            .collect();
        let b = &i["bind"];
        let bind = EscalationBinding {
            policy_digest: b["policy_digest"].as_str().unwrap().into(),
            action_digest: b["action_digest"].as_str().unwrap().into(),
            history_head: b["history_head"].as_str().unwrap().into(),
        };
        let now = i["now"].as_f64().unwrap();
        let now = if now.fract() == 0.0 {
            now as i64
        } else {
            i64::MAX
        }; // a non-integer clock is refused by the safe-integer check
        let r = verify_escalation_answer(&i["answer"], &pins, &bind, now);
        let x = &e["expect"];
        if let Some(need) = e["requires_suite"].as_str() {
            if !have.iter().any(|h| *h == need) {
                // a suite this build cannot run is refused, never accepted and never mistaken for a bad signature
                match &r {
                    EscalationVerdict::Refused(why) => {
                        assert!(why.contains("unsupported_suite"), "{}: {why}", e["name"])
                    }
                    other => panic!("{}: suite {need} is not built, got {other:?}", e["name"]),
                }
                continue;
            }
            if x["ok"].as_bool().unwrap() {
                ran.insert(need.to_string());
            }
        }
        match (&r, x["ok"].as_bool().unwrap()) {
            (
                EscalationVerdict::Ok {
                    principal,
                    decision,
                },
                true,
            ) => assert_eq!(
                (principal.as_str(), decision.as_str()),
                (
                    x["principal"].as_str().unwrap(),
                    x["decision"].as_str().unwrap()
                ),
                "{}",
                e["name"]
            ),
            (EscalationVerdict::Refused(why), false) => assert!(
                why.contains(x["reason_contains"].as_str().unwrap()),
                "{}: {why}",
                e["name"]
            ),
            _ => panic!("{}: got {r:?}, want {x}", e["name"]),
        }
    }
    // every suite this build implements ran its positive vector (a runner that skipped them all would pass vacuously)
    for alg in have
        .iter()
        .filter(|a| **a != "ed25519" && !a.contains("less"))
    {
        assert!(
            ran.contains(*alg),
            "suite {alg} is built but no escalation_answer vector exercised it"
        );
    }
}

fn fixtures() -> Value {
    atlas_pca::strict_parse(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/testdata/authorize-fixtures.json"
        ))
        .unwrap(),
    )
    .unwrap()
}

struct Setup {
    d: Value,
    grant: Value,
    pcactn: Value,
    op: Operation,
    sk: SigningKey,
    pk: String,
}

fn setup() -> Setup {
    let d = fixtures();
    let c = d["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["steps"].as_array().unwrap().len() == 1 && c["steps"][0]["expect"]["allow"] == true
        })
        .unwrap()
        .clone();
    let keys = read("keys.json");
    let seed = atlas_pca::decode_b64u_strict(keys["principal"]["seed"].as_str().unwrap(), Some(32))
        .unwrap();
    Setup {
        grant: c["grant"].clone(),
        pcactn: c["steps"][0]["pcactn"].clone(),
        op: Operation::from_json(&c["steps"][0]["operation"]).unwrap(),
        sk: SigningKey::from_bytes(&<[u8; 32]>::try_from(seed).unwrap()),
        pk: keys["principal"]["public"].as_str().unwrap().to_string(),
        d,
    }
}

fn answer(s: &Setup, last: Option<u64>, over: Value) -> Value {
    let now = s.d["now"].as_i64().unwrap(); // the answer's window is relative to the fixture clock
    let mut body = json!({"v": 1, "kind": "pca-escalation-answer", "principal": s.pk, "policy_digest": escalation_policy_digest(&s.grant).unwrap(),
        "action_digest": escalation_action_digest(&s.pcactn).unwrap(), "history_head": escalation_history_head(last).unwrap(), "decision": "allow",
        "iat": now, "expires_at": now + 600_000, "nonce": "CQkJCQkJCQkJCQkJCQkJCQ"});
    for (k, v) in over.as_object().unwrap() {
        body[k] = v.clone();
    }
    let mut msg = ESCALATION_ANSWER_DOMAIN.as_bytes().to_vec();
    msg.extend_from_slice(canonicalize_strict(&body).unwrap().as_bytes());
    body["sig"] = Value::String(b64u(&s.sk.sign(&msg).to_bytes()));
    body
}

fn inject_provenance(core: &mut Verdict) {
    core.checks.insert("provenance".into(), false);
    core.allow = false;
    core.reason = "provenance: intent_required: a question is required".into();
}

fn inject_hard(core: &mut Verdict) {
    inject_provenance(core);
    core.checks.insert("leaf_signature".into(), false);
}

fn run(
    s: &Setup,
    store: &dyn StateStore,
    answer: Option<&Value>,
    principals: &[PinnedSigner],
) -> atlas_pca::AuthorizeResult {
    let g = s.grant.clone();
    let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
    let is_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let input = AuthorizeInput {
        operation: Some(&s.op),
        audience: s.d["audience"].as_str().unwrap(),
        resolve_grant: Some(&resolve),
        state_store: Some(store),
        is_revoked: Some(&is_revoked),
        now: s.d["now"].as_i64(),
        plan: Some("single-step"),
        escalation_principals: principals,
        escalation_answer: answer,
        ..Default::default()
    };
    authorize(Some(&s.pcactn), &input)
}

fn with_hook<T>(h: Option<fn(&mut Verdict)>, f: impl FnOnce() -> T) -> T {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    *CORE_HOOK.lock().unwrap() = h;
    let r = f();
    *CORE_HOOK.lock().unwrap() = None;
    r
}

#[test]
fn escalate_is_surfaced_and_refused_without_an_answer() {
    let s = setup();
    let r = with_hook(Some(inject_provenance), || {
        run(&s, &MemoryStateStore::new(), None, &[])
    });
    assert_eq!((r.allow, r.decision, r.status), (false, "escalate", 403));
    assert_eq!(
        r.escalation.as_ref().unwrap()["kind"],
        "pca-escalation-request"
    );
}

#[test]
fn hard_failure_is_deny_not_escalate() {
    let s = setup();
    let r = with_hook(Some(inject_hard), || {
        run(&s, &MemoryStateStore::new(), None, &[])
    });
    assert_eq!(
        (r.allow, r.decision, r.escalation.is_none()),
        (false, "deny", true)
    );
}

#[test]
fn valid_answer_admits_once_and_the_counter_spends_it() {
    let s = setup();
    let store = MemoryStateStore::new();
    let pins = vec![PinnedSigner::ed25519(s.pk.clone())];
    let (first, again) = with_hook(Some(inject_provenance), || {
        let first = run(&s, &store, Some(&answer(&s, None, json!({}))), &pins);
        let last = s.pcactn["counter"].as_u64();
        let again = run(&s, &store, Some(&answer(&s, last, json!({}))), &pins);
        (first, again)
    });
    assert_eq!((first.allow, first.decision), (true, "allow"));
    assert_eq!(first.escalation.unwrap()["answered_by"], s.pk.as_str());
    assert!(!again.allow);
    assert_eq!(again.check("replay"), Some(atlas_pca::CheckStatus::Fail));
}

#[test]
fn bad_answers_stay_escalate() {
    let s = setup();
    let pins = vec![PinnedSigner::ed25519(s.pk.clone())];
    let zero = b64u(&[0u8; 32]);
    let bad = vec![
        answer(&s, None, json!({"decision": "deny"})),
        answer(&s, None, json!({"policy_digest": zero})),
        answer(&s, None, json!({"action_digest": zero})),
        answer(&s, Some(99), json!({})),
        answer(&s, None, json!({"iat": 1, "expires_at": 2})),
        json!({"junk": 1}),
    ];
    with_hook(Some(inject_provenance), || {
        for a in &bad {
            let r = run(&s, &MemoryStateStore::new(), Some(a), &pins);
            assert_eq!((r.allow, r.decision), (false, "escalate"), "{a}");
        }
        assert!(
            !run(
                &s,
                &MemoryStateStore::new(),
                Some(&answer(&s, None, json!({}))),
                &[]
            )
            .allow
        );
    });
}

#[test]
fn answer_never_upgrades_a_deny() {
    let s = setup();
    let pins = vec![PinnedSigner::ed25519(s.pk.clone())];
    let r = with_hook(Some(inject_hard), || {
        run(
            &s,
            &MemoryStateStore::new(),
            Some(&answer(&s, None, json!({}))),
            &pins,
        )
    });
    assert_eq!((r.allow, r.decision), (false, "deny"));
}

/// A store whose history head cannot be read (`last` is None, as for a database error): the answer cannot be bound.
struct Bare(MemoryStateStore);
impl StateStore for Bare {
    fn claim(&self, key: &str, counter: u64) -> Result<ClaimResult, StoreError> {
        self.0.claim(key, counter)
    }
    fn last(&self, _key: &str) -> Option<Option<u64>> {
        None
    }
}

#[test]
fn store_that_cannot_read_its_head_cannot_bind_the_history() {
    let s = setup();
    let pins = vec![PinnedSigner::ed25519(s.pk.clone())];
    let r = with_hook(Some(inject_provenance), || {
        run(
            &s,
            &Bare(MemoryStateStore::new()),
            Some(&answer(&s, None, json!({}))),
            &pins,
        )
    });
    assert_eq!((r.allow, r.decision), (false, "escalate"));
}

fn inject_multi_escalate(core: &mut Verdict) {
    for c in ["provenance", "facts", "classes"] {
        core.checks.insert(c.into(), false);
    }
    core.allow = false;
    core.reason = "provenance: intent_required: q1".into();
    core.reasons = vec![
        "provenance: intent_required: q1".into(),
        "facts: intent_required: q2".into(),
        "classes: escalate: q3".into(),
    ];
}

fn inject_multi_one_hard(core: &mut Verdict) {
    inject_multi_escalate(core);
    core.reasons[2] = "classes: class receipt does not verify".into();
}

fn inject_unexplained(core: &mut Verdict) {
    for c in ["provenance", "facts"] {
        core.checks.insert(c.into(), false);
    }
    core.allow = false;
    core.reason = "provenance: intent_required: q".into();
    core.reasons = vec!["provenance: intent_required: q".into()];
}

// A multi-check escalation (every failing check escalate-class, each with its own reason) is ONE escalation that a single
// answer upgrades; one hard failure among them makes the whole decision a deny.
#[test]
fn multi_check_escalation_is_an_escalation() {
    let s = setup();
    let pins = vec![PinnedSigner::ed25519(s.pk.clone())];
    let (open, answered) = with_hook(Some(inject_multi_escalate), || {
        let open = run(&s, &MemoryStateStore::new(), None, &[]);
        let answered = run(
            &s,
            &MemoryStateStore::new(),
            Some(&answer(&s, None, json!({}))),
            &pins,
        );
        (open, answered)
    });
    assert_eq!((open.allow, open.decision), (false, "escalate"));
    assert_eq!(
        open.reasons[..3],
        [
            "provenance: intent_required: q1",
            "facts: intent_required: q2",
            "classes: escalate: q3"
        ]
    );
    assert_eq!(
        open.escalation.as_ref().unwrap()["reasons"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!((answered.allow, answered.decision), (true, "allow"));
    assert!(answered
        .checks
        .values()
        .all(|c| *c != atlas_pca::CheckStatus::Fail));
}

#[test]
fn multi_check_with_one_hard_failure_is_a_deny() {
    let s = setup();
    let pins = vec![PinnedSigner::ed25519(s.pk.clone())];
    let r = with_hook(Some(inject_multi_one_hard), || {
        run(
            &s,
            &MemoryStateStore::new(),
            Some(&answer(&s, None, json!({}))),
            &pins,
        )
    });
    assert_eq!(
        (r.allow, r.decision, r.escalation.is_none()),
        (false, "deny", true)
    );
}

#[test]
fn a_failing_check_with_no_reason_of_its_own_is_a_deny() {
    let s = setup();
    let pins = vec![PinnedSigner::ed25519(s.pk.clone())];
    let r = with_hook(Some(inject_unexplained), || {
        run(
            &s,
            &MemoryStateStore::new(),
            Some(&answer(&s, None, json!({}))),
            &pins,
        )
    });
    assert_eq!((r.allow, r.decision), (false, "deny"));
}
