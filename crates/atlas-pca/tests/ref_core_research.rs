//! Differential replay of test-data/ref-core-research-java.json.gz (written by the TypeScript reference): the data-flow (DLP)
//! evaluator, the read side of the behavioral immune system, the agent console and its freeze set, multi-agent sessions
//! (scripted), the policy simulator and compiled-policy lints, and disputes from signed settlement records. Keys are the seeds
//! of the labels `research/<label>`. A case the reference refuses must be refused here; an op the reference refuses records
//! `{"$err": "Error"}`.
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::console::*;
use atlas_pca::facade::{builtin_catalog, compile_policy, create_agent, AgentHandle, AgentOptions, CompileOptions, CompiledPolicy, SubAgentOptions};
use atlas_pca::immune::{assess, baseline_std, observe_value, update_baseline, validate_immune_state, ImmuneState};
use atlas_pca::policy_sim::{lint_compiled_policy, simulate, SimOptions};
use atlas_pca::prohibitions::num_value;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::session::*;
use common::replay::{replay, thrown};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

fn key(label: &str) -> KeyPair {
    KeyPair::from_seed(&Sha256::digest(format!("atlas-pca-conformance/research/{label}").as_bytes()).into())
}

/// A number argument; a missing, null or non-number one is NaN.
fn double(v: &Value) -> f64 {
    v.as_f64().filter(|_| v.is_number()).unwrap_or(f64::NAN)
}

fn compile(spec: &Value) -> Result<CompiledPolicy, String> {
    compile_policy(&CompileOptions {
        permissions: &spec["permissions"],
        limits: spec.get("limits"),
        catalog: None,
        budget_model: spec.get("budgetModel").and_then(Value::as_str),
        risk_policy: spec.get("riskPolicy"),
        now: spec["now"].as_i64().expect("now"),
    })
}

fn agent(spec: &Value) -> Result<AgentHandle, String> {
    let principal = key(spec["principal"].as_str().ok_or("principal")?);
    let mut o = AgentOptions::new(&principal, spec["goal"].as_str().ok_or("goal")?, &spec["permissions"]);
    o.holder = Some(key(spec["holder"].as_str().ok_or("holder")?));
    o.goal_salt = spec["goalSalt"].as_str();
    o.now = spec["now"].as_i64();
    create_agent(o)
}

fn session_op(ags: &mut HashMap<String, Arc<AgentHandle>>, sess: &mut HashMap<String, Session>, op: &Value) -> Result<Value, String> {
    let text = |i: usize| op[i].as_str().ok_or("op argument");
    let session = |i: usize| text(i).and_then(|n| sess.get(n).cloned().ok_or("no such session"));
    Ok(match text(0)? {
        "agent" => {
            let a = Arc::new(agent(&op[2])?);
            let id = a.holder.public.clone();
            ags.insert(text(1)?.into(), a);
            json!(id)
        }
        "start" => {
            let s = start_session(ags.get(text(2)?).cloned().ok_or("no such agent")?);
            let goal = s.goal_commit.clone();
            sess.insert(text(1)?.into(), s);
            json!(goal)
        }
        // a hand-built session; a null goal commitment is the first member's
        "mk" => {
            let names = op[2].as_array().ok_or("members")?;
            let members = names.iter().map(|n| n.as_str().and_then(|n| ags.get(n)).cloned().ok_or("no such agent")).collect::<Result<Vec<_>, _>>()?;
            let goal_commit = match op[3].as_str() {
                Some(g) => g.to_string(),
                None => members.first().map(|m| start_session(m.clone()).goal_commit).unwrap_or_default(),
            };
            sess.insert(text(1)?.into(), Session { members, goal_commit: goal_commit.clone() });
            json!(goal_commit)
        }
        "add" => {
            let from = session(2)?;
            let holder = op[3].as_str().map(key);
            let id = holder.as_ref().map(|h| h.public.clone());
            if !(op[4].is_null() || op[4].is_array()) {
                // DEVIATION (fail closed): the reference spreads a string of caveats into the hop and signs it; delegation here
                // refuses a caveat list that is not an array. The op is reported as the reference recorded it.
                assert!(add_member(&from, SubAgentOptions { holder, added_caveats: Some(op[4].clone()) }).is_err());
                return Ok(json!(id));
            }
            let (next, member) = add_member(&from, SubAgentOptions { holder, added_caveats: op[4].as_array().map(|_| op[4].clone()) })?;
            sess.insert(text(1)?.into(), next);
            json!(member.holder.public)
        }
        "agents" => json!(session_agents(&session(1)?)),
        "depth" => json!(session_depth(&session(1)?)),
        "shares" => json!(shares_goal(&session(1)?)),
        "goal" => json!(session(1)?.goal_commit),
        "console" => session_console(&session(1)?, op[2].as_array().ok_or("events")?)?,
        other => panic!("unhandled session op {other}"),
    })
}

fn run(f: &str, a: &[Value]) -> Value {
    let list = |v: &Value| v.as_array().cloned().expect("an array argument");
    match f {
        "evaluateDlp" => atlas_pca::dlp::evaluate_dlp(&a[0], &a[1]).unwrap_or_else(thrown),
        "defaultDlpPolicy" => atlas_pca::dlp::default_dlp_policy(&a[0]).unwrap_or_else(thrown),
        "updateBaseline" => update_baseline(&a[0], double(&a[1])),
        "baselineStd" => num_value(baseline_std(&a[0])),
        "assess" => assess(&a[0]).to_value(),
        "validateImmuneState" => json!(validate_immune_state(&a[0])),
        "observe" => ImmuneState::from_value(&a[0]).and_then(|s| observe_value(&s, &a[1])).map_or_else(thrown, |s| s.to_value()),
        "buildConsole" => build_console(&list(&a[0])),
        "anomalies" => json!(anomalies(&build_console(&list(&a[0])))),
        "eventFromPCActn" => {
            let at = if a[2].is_null() { None } else { Some(double(&a[2])) };
            event_from_pcactn(&a[0], a[1].as_str().expect("an outcome"), at).unwrap_or_else(thrown)
        }
        "freezeAgent" => freeze_agent(&a[0], &a[1]).unwrap_or_else(thrown),
        "unfreezeAgent" => unfreeze_agent(&a[0], &a[1]).unwrap_or_else(thrown),
        "isFrozen" => json!(is_frozen(&a[0], &a[1])),
        "session" => {
            let (mut ags, mut sess) = (HashMap::new(), HashMap::new());
            json!(list(&a[0]).iter().map(|op| session_op(&mut ags, &mut sess, op).unwrap_or_else(|_| json!({"$err": "Error"}))).collect::<Vec<_>>())
        }
        "simulate" => {
            let start = if a[2].is_null() { None } else { Some(double(&a[2])) };
            compile(&a[0]).and_then(|p| simulate(&p, &list(&a[1]), SimOptions { catalog: None, start })).unwrap_or_else(thrown)
        }
        "lintPolicy" => compile(&a[0]).map_or_else(thrown, |p| json!(lint_compiled_policy(&p, &builtin_catalog()))),
        "disputesFromSettlements" => {
            let guardian = if a[1] == "@g" { key("guardian").public.clone() } else { a[1].as_str().expect("a key").to_string() };
            let subject_of = |id: &str| a[2].get(id).and_then(Value::as_str).map(String::from);
            atlas_pca::reputation::disputes_from_settlements(&list(&a[0]), &guardian, subject_of, a.get(3).filter(|p| !p.is_null()))
        }
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn ref_core_research_replay() {
    replay("core-research-java", 6188, 0, run);
}

#[test]
fn session_constants_and_empty_freeze() {
    assert_eq!(SESSION_MAX_DEPTH, 32);
    assert_eq!(*EMPTY_FREEZE, json!({"frozen": []}));
    assert!(!is_frozen(&EMPTY_FREEZE, &json!("a")));
}
