//! Differential replay of test-data/ref-control-blue.json.gz (written by the TypeScript reference): the blue control protocol of the
//! control evaluation against the real native blue stack (ref-control-evals replays only the aggregation, from a stub blue): the example
//! agent with its review battery, the example blue protocol, every episode (replay, predicates and caveats through the agent's review,
//! data-flow governance, the immune-adapted metered budget) and the example evaluation. Totals are asserted; numbers compare to a
//! relative 1e-12 (the leak decays exponentially). A reference refusal (params that are not canonical JSON) must be a refusal here.
mod common;
use std::sync::Arc;

use atlas_pca::agent::KeyPair;
use atlas_pca::approvals::{review_action, ReviewOptions};
use atlas_pca::control_evals::*;
use atlas_pca::control_evals_example::*;
use atlas_pca::facade::{create_agent, AgentHandle, AgentOptions};
use atlas_pca::immune::ImmuneConfig;
use atlas_pca::serde_json::{json, Map, Value};

fn eq(w: &Value, g: &Value) -> bool {
    match (w, g) {
        (Value::Number(a), Value::Number(b)) => {
            let (a, b) = (a.as_f64().unwrap_or(f64::NAN), b.as_f64().unwrap_or(f64::NAN));
            a == b || (a - b).abs() <= 1e-12 * a.abs().max(1.0)
        }
        (Value::Array(a), Value::Array(b)) => a.len() == b.len() && a.iter().zip(b).all(|(x, y)| eq(x, y)),
        (Value::Object(a), Value::Object(b)) => a.len() == b.len() && a.iter().all(|(k, v)| b.get(k).is_some_and(|y| eq(v, y))),
        _ => w == g,
    }
}

fn agent_of(name: &str) -> Arc<AgentHandle> {
    if name == "example" {
        return Arc::new(build_example_agent(None, None).expect("example agent"));
    }
    let principal = KeyPair::generate().expect("key");
    let permissions = json!({ "stripe": ["refund"], "gmail": ["send", "draft"], "files": ["read", "write"], "github": ["read"] });
    let limits = json!({ "refund": "$50/day" });
    let mut o = AgentOptions::new(&principal, "handle refunds and customer email for October", &permissions);
    if name == "cap50" {
        o.limits = Some(&limits);
    }
    o.aud = Some("ins_example");
    o.now = Some(0);
    Arc::new(create_agent(o).expect("agent"))
}

fn blue_of(b: &Value) -> ExampleBlue {
    let mut blue = example_blue(Some(agent_of(b["agent"].as_str().expect("agent")))).expect("blue");
    if b["dlp"] == json!(false) {
        blue.dlp = None;
    }
    if b["theta"] == json!("agent") {
        blue.use_agent_risk_policy().expect("agent risk policy");
    }
    if let Some(x) = b["stepMs"].as_f64() {
        blue.step = x;
    }
    if let Some(x) = b["startMs"].as_f64() {
        blue.start = x;
    }
    if let Some(im) = b.get("immune") {
        let f = |k: &str| im[k].as_f64().expect(k);
        blue.immune_cfg = ImmuneConfig { alpha: f("alpha"), half_life_ms: f("halfLifeMs"), drift_z_sat: f("driftZSat"), step_up_sat: f("stepUpSat"), deny_sat: f("denySat") };
    }
    if let Some(ad) = b.get("adapt") {
        blue.adapt_cfg = (ad["maxKappaMult"].as_f64().expect("maxKappaMult"), ad["minThetaMult"].as_f64().expect("minThetaMult"));
    }
    blue
}

fn red_of(name: &str) -> RedPolicy {
    match name {
        "over-cap" => over_cap_red(),
        "off-verb" => off_verb_red(),
        "slow-burn" => slow_burn_red(),
        "taint-exfil" => taint_exfil_red(),
        "replay" => replay_red(),
        "immune-probe" => immune_probe_burst_red(),
        "benign" => benign_baseline_red(),
        "gap-exploit" => gap_exploit_red(DEFAULT_PROD_RESOURCE),
        other => panic!("unknown red {other}"),
    }
}

fn env_of(name: &str) -> Env {
    if name == "example" {
        example_env()
    } else {
        gap_aware_env(DEFAULT_PROD_RESOURCE)
    }
}

fn build_example_agent_view(case: &Value) -> Result<Value, String> {
    let a = build_example_agent(None, None)?;
    let p = a.policy.to_json();
    let actions: Vec<Value> = a
        .policy
        .actions
        .iter()
        .map(|s| {
            let mut m = s.to_json();
            m.as_object_mut().expect("object").remove("aliases");
            m
        })
        .collect();
    let mut reviews = Vec::new();
    for e in case["out"]["reviews"].as_array().ok_or("reviews")? {
        let params = e.get("params").filter(|p| !p.is_null());
        let opts = ReviewOptions { now: e["now"].as_i64(), insecure_unbound_approval: true, ..Default::default() };
        let r = review_action(&a, e["verb"].as_str().unwrap_or(""), e["resource"].as_str().unwrap_or(""), params, &opts);
        let mut rv = Map::new();
        rv.insert("kind".into(), r["kind"].clone());
        if let Some(reason) = r.get("reason") {
            rv.insert("reason".into(), reason.clone());
        }
        let mut out = e.as_object().cloned().unwrap_or_default();
        out.insert("review".into(), Value::Object(rv));
        reviews.push(Value::Object(out));
    }
    Ok(json!({
        "policy": { "predicates": p["predicates"], "caveats": p["caveats"], "riskPolicy": p["riskPolicy"], "budgetModel": p["budgetModel"],
            "approximations": p["approximations"], "inputLimits": p["inputLimits"], "actions": actions },
        "reviews": reviews,
    }))
}

fn run_case(c: &Value) -> Result<Value, String> {
    let args = &c["args"];
    match c["fn"].as_str().unwrap_or("") {
        "buildExampleAgent" => build_example_agent_view(c),
        "exampleBlue" => {
            let b = example_blue(Some(agent_of(args[0].as_str().ok_or("agent name")?)))?;
            Ok(json!({ "name": "pca-controls", "basePolicy": b.base_policy(), "dlp": b.dlp, "startMs": b.start, "stepMs": b.step }))
        }
        "blueEpisode" => {
            let spec = &args[0];
            let blue = blue_of(&spec["blue"]);
            let env = env_of(spec["env"].as_str().unwrap_or(""));
            let red = match args.get(1).and_then(Value::as_array) {
                Some(list) => {
                    let list = list.clone();
                    RedPolicy::new("custom", "custom", Arc::new(move |_, _, _| list.clone()))
                }
                None => red_of(spec["red"].as_str().ok_or("red")?),
            };
            run_episode(&red, &blue, &env, spec["seed"].as_f64().ok_or("seed")?)
        }
        "exampleEval" => {
            let s = &args[0];
            example_control_eval(s["episodes"].as_f64(), s["seed"].as_f64(), None)
        }
        other => panic!("no native entry point for {other}"),
    }
}

#[test]
fn control_blue_matches_the_reference() {
    let cases = common::ref_cases("control-blue");
    assert_eq!(cases.len(), 362, "case total");
    let (mut bad, mut refused) = (Vec::new(), 0usize);
    let mut per: std::collections::BTreeMap<String, usize> = Default::default();
    for c in &cases {
        *per.entry(c["fn"].as_str().unwrap_or("").to_string()).or_default() += 1;
        let got = run_case(c);
        if c["out"].get("$throws").is_some() {
            if got.is_err() {
                refused += 1;
            } else {
                bad.push(format!("{}: the reference refuses ({}), the native episode completes", c["name"], c["out"]));
            }
        } else {
            match got {
                Ok(v) if eq(&c["out"], &v) => {}
                other => bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], other)),
            }
        }
    }
    assert_eq!(per.get("blueEpisode"), Some(&352));
    assert_eq!(per.get("buildExampleAgent"), Some(&1));
    assert_eq!(per.get("exampleBlue"), Some(&3));
    assert_eq!(per.get("exampleEval"), Some(&6));
    assert_eq!(refused, 5, "the five reference refusals (params that are not canonical JSON) are refusals here too");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(10).cloned().collect::<Vec<_>>().join("\n"));
}
