//! The example blue control protocol (`example_blue`, with data-flow governance and the behavioral immune system) against the
//! reference's own recorded episodes and evaluations: the native protocol decides every action of every recorded run exactly as the
//! TypeScript stack did (outcome, control, risk, threat level, reason, budget), so the whole episode transcript and the aggregated
//! report compare equal. Cases the reference refused before any decision (bad episodes / seed / red names) must be refused too.
//! Skipped (counted, must stay under 20%): cases with a lone surrogate or an unknown red / environment name.
mod common;
use atlas_pca::control_evals::*;
use atlas_pca::control_evals_example::*;
use atlas_pca::serde_json::Value;
use std::sync::Arc;

fn red_of(name: &str) -> Option<RedPolicy> {
    Some(match name {
        "over-cap" => over_cap_red(),
        "off-verb" => off_verb_red(),
        "slow-burn" => slow_burn_red(),
        "taint-exfil" => taint_exfil_red(),
        "replay" => replay_red(),
        "immune-probe" => immune_probe_burst_red(),
        "benign" => benign_baseline_red(),
        "gap-exploit" => gap_exploit_red(DEFAULT_PROD_RESOURCE),
        _ => return None,
    })
}

fn env_of(name: &str) -> Option<Env> {
    match name {
        "example" => Some(example_env()),
        "gap-aware" => Some(gap_aware_env(DEFAULT_PROD_RESOURCE)),
        n => n.strip_prefix("gap-aware:").map(gap_aware_env),
    }
}

#[test]
fn example_blue_replays_the_recorded_runs() {
    let agent = Arc::new(build_example_agent(None, None).expect("example agent"));
    let cases: Vec<Value> = common::ref_cases("control-evals").into_iter().filter(|c| matches!(c["fn"].as_str(), Some("runEpisode" | "controlEval"))).collect();
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let spec = &c["args"][0];
        let (Some(env), true) = (spec["env"].as_str().and_then(env_of), !common::has_lone(&c["args"])) else {
            skipped += 1;
            continue;
        };
        let threw = c["out"].get("$throws").is_some();
        let got: Result<Value, String> = if c["fn"] == "runEpisode" {
            match (spec["red"].as_str().and_then(red_of), spec["seed"].as_f64()) {
                (Some(red), Some(seed)) => example_blue(Some(agent.clone())).and_then(|b| run_episode(&red, &b, &env, seed)),
                _ => {
                    skipped += 1;
                    continue;
                }
            }
        } else {
            // the refused configurations never reach a decision
            let names: Vec<Option<RedPolicy>> = spec["reds"].as_array().map(|r| r.iter().map(|n| n.as_str().and_then(red_of)).collect()).unwrap_or_default();
            if names.iter().any(Option::is_none) {
                skipped += 1;
                continue;
            }
            let reds: Vec<RedPolicy> = names.into_iter().flatten().collect();
            example_blue(Some(agent.clone())).and_then(|b| control_eval(&reds, &b, &env, &spec["episodes"], &spec["seed"]))
        };
        let ok = match (&got, threw) {
            (Err(_), true) => true,
            (Ok(v), false) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(skipped * 5 < cases.len(), "{skipped} of {} cases skipped", cases.len());
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(10).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn example_control_eval_is_deterministic_and_scores_every_strategy() {
    let r = example_control_eval(None, None, None).expect("evaluation");
    assert_eq!(r["episodes"].as_u64(), Some(8 * example_red_policies().len() as u64));
    assert_eq!(r["seed"].as_f64(), Some(1.0));
    assert_eq!(r["byStrategy"].as_object().map(|m| m.len()), Some(example_red_policies().len()));
    // the budget's analytic bound is bMax / kappa of the example agent: 1 / 500 refunds' worth is not 0
    assert!(r["analyticBound"].as_f64().is_some_and(|b| b > 0.0));
    let again = example_control_eval(None, None, None).expect("evaluation");
    assert_eq!(atlas_pca::canonicalize(&r), atlas_pca::canonicalize(&again));
    assert!(example_control_eval(Some(0.0), None, None).is_err());
}
