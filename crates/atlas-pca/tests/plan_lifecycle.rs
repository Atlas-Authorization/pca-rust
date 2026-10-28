//! Plan lifecycle (T10): replays plan-vectors.json scenario by scenario (including the Merkle plan root, which must equal the
//! TypeScript root), then proves the transitions are atomic under real threads and that the registry feeds `authorize`.
mod common;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Barrier};

use atlas_pca::*;
use common::load;
use serde_json::{json, Value};

fn registry(validator: Option<&str>, clock: Arc<AtomicI64>) -> PlanRegistry {
    let reg = PlanRegistry::new().with_clock(move || clock.load(Ordering::SeqCst));
    match validator {
        Some("accept") => reg.with_validator(|_| Ok(())),
        Some("refuse") => reg.with_validator(|_| Err("node outside the grant".into())),
        Some("throw") => reg.with_validator(|_| panic!("policy down")),
        _ => reg,
    }
}

fn step(reg: &PlanRegistry, s: &Value) -> Value {
    let (g, root) = (s["grant"].as_str().unwrap(), s["root"].as_str().unwrap_or(""));
    let at = s["at"].as_i64().unwrap();
    match s["op"].as_str().unwrap() {
        "draft" => reg.draft(g, s["nodes"].as_array().unwrap()).to_json(),
        "validate" => reg.validate(g, root).to_json(),
        "commit" => reg.commit(g, root).to_json(),
        "authorize" => reg.authorize(g, root, PlanApproval::from_json(&s["approval"]).as_ref()).to_json(),
        "revoke" => reg.revoke(g, root, s["reason"].as_str().unwrap()).to_json(),
        "status" => reg.status(g, root, Some(at)).to_json(),
        "check" => {
            let o = PlanCheckOptions {
                node_id: s["node_id"].as_str().map(str::to_string),
                operation: Operation::from_json(&json!({
                    "verb": s["operation"]["verb"], "resource": s["operation"]["resource"], "params": s["operation"].get("params").cloned().unwrap_or(Value::Null)
                }))
                .filter(|_| !s["operation"].is_null()),
                now: Some(at),
            };
            reg.check(g, root, &o).to_json()
        }
        "is_plan_authorized" => json!(reg.is_plan_authorized(g, root)),
        "context" => reg.context(g, root, Some(at)).map_or(Value::Null, |c| c.to_json()),
        other => panic!("unknown op {other}"),
    }
}

#[test]
fn plan_vectors() {
    let d = load("plan-vectors.json");
    let scenarios = d["scenarios"].as_array().unwrap();
    assert_eq!(scenarios.len(), 12);
    let mut steps_run = 0;
    for sc in scenarios {
        let name = sc["name"].as_str().unwrap();
        let clock = Arc::new(AtomicI64::new(0));
        let reg = registry(sc["validator"].as_str(), clock.clone());
        let expect = sc["expect"].as_array().unwrap();
        for (i, (s, want)) in sc["steps"].as_array().unwrap().iter().zip(expect).enumerate() {
            steps_run += 1;
            clock.store(s["at"].as_i64().unwrap(), Ordering::SeqCst);
            assert_eq!(&step(&reg, s), want, "{name} step {i}");
        }
    }
    assert_eq!(steps_run, 87);
}

fn node(id: &str) -> Value {
    json!({"id": id, "verb": "orders.read", "resource": "/orders/1"})
}

fn committed(reg: &PlanRegistry) -> String {
    let root = match reg.draft("g1", &[node("n1")]) {
        PlanTransition::Ok(r) => r.root,
        other => panic!("{other:?}"),
    };
    assert!(reg.validate("g1", &root).is_ok() && reg.commit("g1", &root).is_ok());
    root
}

#[test]
fn n_parallel_claims_of_one_plan_transition_exactly_one_wins() {
    let reg = Arc::new(PlanRegistry::new());
    let root = committed(&reg);
    let n = 16;
    let gate = Arc::new(Barrier::new(n));
    let handles: Vec<_> = (0..n)
        .map(|i| {
            let (reg, root, gate) = (reg.clone(), root.clone(), gate.clone());
            std::thread::spawn(move || {
                gate.wait();
                reg.authorize("g1", &root, Some(&PlanApproval { by: format!("p{i}"), expires_at: None }))
            })
        })
        .collect();
    let outs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(outs.iter().filter(|o| o.is_ok()).count(), 1, "{outs:?}");
    for o in outs.iter().filter(|o| !o.is_ok()) {
        assert!(matches!(o, PlanTransition::Refused { state, reason } if state == "authorized" && reason.ends_with("is authorized: cannot authorize")), "{o:?}");
    }
    let winner = outs.iter().find_map(|o| if let PlanTransition::Ok(r) = o { Some(r.clone()) } else { None }).unwrap();
    assert_eq!(reg.get("g1", &root).unwrap().approval, winner.approval);
}

#[test]
fn n_parallel_drafts_of_one_plan_create_it_once() {
    let reg = Arc::new(PlanRegistry::new());
    let gate = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (reg, gate) = (reg.clone(), gate.clone());
            std::thread::spawn(move || {
                gate.wait();
                reg.draft("g1", &[node("n1")])
            })
        })
        .collect();
    let outs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(outs.iter().filter(|o| o.is_ok()).count(), 1);
}

/// A signed single-step-free fixture: the first authorize fixture step, with the registry supplying the plan.
fn authorize_with(reg: &PlanRegistry) -> AuthorizeResult {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/authorize-fixtures.json")).unwrap();
    let d = strict_parse(&text).unwrap();
    let (grant, s) = (d["cases"][0]["grant"].clone(), &d["cases"][0]["steps"][0]);
    let op = Operation::from_json(&s["operation"]).unwrap();
    let resolve = move |_: &str| Ok::<_, String>(Some(grant.clone()));
    let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let store = MemoryStateStore::new();
    let input = AuthorizeInput {
        operation: Some(&op),
        audience: d["audience"].as_str().unwrap(),
        resolve_grant: Some(&resolve),
        state_store: Some(&store),
        is_revoked: Some(&not_revoked),
        now: d["now"].as_i64(),
        plan: Some("single-step"),
        plans: Some(reg),
        ..Default::default()
    };
    authorize(Some(&s["pcactn"]), &input)
}

#[test]
fn a_registered_plan_that_is_not_executable_denies_authorize_with_the_plan_reason() {
    // the fixture's plan root is not registered: the registry has nothing to say and the single-step plan applies
    let empty = PlanRegistry::new();
    assert!(authorize_with(&empty).allow);
    // register the plan the fixture PCActn commits to, as a draft: the registry now answers, and a draft is not executable
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/authorize-fixtures.json")).unwrap();
    let d = strict_parse(&text).unwrap();
    let p = &d["cases"][0]["steps"][0]["pcactn"];
    let (root, grant_ref) = (p["plan"]["root"].as_str().unwrap().to_string(), p["grant_ref"].as_str().unwrap().to_string());
    let op = &d["cases"][0]["steps"][0]["operation"];
    let n = json!({"id": p["plan"]["node_id"], "verb": op["verb"], "resource": op["resource"], "params_digest": p["action"]["params_digest"], "reversibility_class": p["action"]["reversibility_class"]});
    let reg = PlanRegistry::new();
    // the single node reproduces the PCActn's committed root, so the registry answers for it
    assert_eq!(plan_root_of(std::slice::from_ref(&n)).ok().as_deref(), Some(root.as_str()));
    assert!(reg.draft(&grant_ref, std::slice::from_ref(&n)).is_ok());
    let r = authorize_with(&reg);
    assert!(!r.allow);
    assert_eq!(r.check("plan_state"), Some(CheckStatus::Fail));
    assert!(r.reasons.iter().any(|x| x.starts_with("plan_state: plan ") && x.contains("draft, not authorized")), "{:?}", r.reasons);
    assert!(reg.validate(&grant_ref, &root).is_ok() && reg.commit(&grant_ref, &root).is_ok());
    assert!(reg.authorize(&grant_ref, &root, Some(&PlanApproval { by: "p".into(), expires_at: None })).is_ok());
    assert!(authorize_with(&reg).allow);
    assert!(reg.revoke(&grant_ref, &root, "no").is_ok());
    assert!(!authorize_with(&reg).allow);
}
