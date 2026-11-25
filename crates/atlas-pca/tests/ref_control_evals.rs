//! Differential replay of the control-evals package (seeded PRNG, seed mixing, Wilson bound, CI gate, built-in red policies, modeled
//! environments, example DLP policy, episode runner and evaluation) against the TypeScript reference
//! (test-data/ref-control-evals.json.gz). The blue protocol itself (review, DLP, immune system, budget) is not native: the episode
//! and evaluation cases replay the reference's recorded blue decisions through a stub. A reference throw only requires a refusal.
//! Skipped (counted, must stay under 10%): cases with a lone surrogate. Not ported: buildExampleAgent / exampleBlue /
//! exampleControlEval (they bundle the agent, review, DLP and immune stack).
mod common;
use atlas_pca::control_evals::*;
use atlas_pca::serde_json::{json, Value};
use std::sync::Mutex;

fn f(v: &Value) -> f64 {
    v.as_f64().unwrap()
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
        n => panic!("unknown red {n}"),
    }
}

fn env_of(name: &str) -> Env {
    match name {
        "example" => example_env(),
        "gap-aware" => gap_aware_env(DEFAULT_PROD_RESOURCE),
        n => gap_aware_env(n.strip_prefix("gap-aware:").unwrap()),
    }
}

/// Replays recorded decisions: episode k of the run answers from recorded[k], step i from its steps[i].
struct Stub {
    episodes: Vec<Value>,
    next: Mutex<usize>,
    bound: f64,
}

struct StubEpisode {
    rec: Value,
    i: usize,
    cur_money: f64,
}

impl Blue for Stub {
    fn analytic_bound(&self) -> f64 {
        self.bound
    }
    fn new_episode(&self) -> Result<Box<dyn BlueEpisode>, String> {
        let mut n = self.next.lock().unwrap();
        let rec = self.episodes.get(*n).cloned().ok_or("no recorded episode")?;
        *n += 1;
        Ok(Box::new(StubEpisode { rec, i: 0, cur_money: 0.0 }))
    }
}

impl BlueEpisode for StubEpisode {
    fn decide(&mut self, _action: &Value, _at: f64) -> Result<Value, String> {
        let s = self.rec["steps"].get(self.i).cloned().ok_or("no recorded step")?;
        self.i += 1;
        self.cur_money = s["money"].as_f64().unwrap_or(0.0);
        Ok(s)
    }
    fn money_amount(&self, _action: &Value) -> f64 {
        self.cur_money
    }
    fn end_budget(&self) -> f64 {
        f(&self.rec["endBudget"])
    }
}

fn run(fname: &str, a: &[Value]) -> Result<Value, String> {
    match fname {
        "mulberry32" => {
            let mut r = Mulberry32::new(f(&a[0]));
            Ok(Value::Array((0..a[1].as_u64().unwrap()).map(|_| json!(r.next())).collect()))
        }
        "mixSeed" => Ok(json!(mix_seed(f(&a[0]), f(&a[1]), f(&a[2])))),
        "wilsonLowerBound" => Ok(json!(wilson_lower_bound(f(&a[0]), f(&a[1]), a.get(2).map_or(1.645, f)))),
        "assertControlGate" => assert_control_gate(&a[0], &a[1]).map(|_| Value::Null),
        "redGen" => {
            let r = red_of(a[0].as_str().unwrap());
            Ok(json!({ "name": r.name, "strategy": r.strategy, "actions": r.actions(&example_env(), 1.0, 0.0) }))
        }
        "gapExploitCustom" => {
            let r = gap_exploit_red("file:x");
            Ok(json!({ "name": r.name, "actions": r.actions(&example_env(), 0.0, 0.0) }))
        }
        "redLists" => {
            let st = |v: Vec<RedPolicy>| v.into_iter().map(|r| r.strategy).collect::<Vec<_>>();
            Ok(json!({ "builtin": st(builtin_red_policies()), "example": st(example_red_policies()) }))
        }
        "envJudge" => env_of(a[0].as_str().unwrap()).unacceptable_if_allowed(&a[1], &a[2]).map(Value::Bool),
        "exampleDlpPolicy" => Ok(example_dlp_policy()),
        "runEpisode" => {
            let s = &a[0];
            let stub = Stub { episodes: vec![s["recorded"].clone()], next: Mutex::new(0), bound: 0.0 };
            run_episode(&red_of(s["red"].as_str().unwrap()), &stub, &env_of(s["env"].as_str().unwrap()), f(&s["seed"]))
        }
        "controlEval" => {
            let s = &a[0];
            let reds: Vec<RedPolicy> = s["reds"].as_array().map(|r| r.iter().map(|n| red_of(n.as_str().unwrap())).collect()).unwrap_or_default();
            let eps: Vec<Value> = s["recorded"].as_array().unwrap().iter().flat_map(|r| r.as_array().unwrap().clone()).collect();
            let stub = Stub { episodes: eps, next: Mutex::new(0), bound: f(&s["analyticBound"]) };
            control_eval(&reds, &stub, &env_of(s["env"].as_str().unwrap()), &s["episodes"], &s["seed"])
        }
        n => panic!("unknown fn {n}"),
    }
}

#[test]
fn control_evals_vectors() {
    let cases = common::ref_cases("control-evals");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let name = c["fn"].as_str().unwrap();
        let args = c["args"].as_array().unwrap().clone();
        let got = std::panic::catch_unwind(|| run(name, &args)).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(t), Err(m)) => {
                // gate messages are the reference's own; a JS runtime TypeError only requires a refusal
                let want = t.as_str().unwrap_or("");
                !want.starts_with("control gate failed") || m == want
            }
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
}
