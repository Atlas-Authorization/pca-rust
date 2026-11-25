//! Differential replay of test-data/ref-budget-forecast.json.gz (written by the TypeScript reference): the forecast of a plan
//! under a compiled policy (default and custom catalogs, with and without a start time), the policy recommender and the
//! autonomous bound. A case the reference refuses must be refused here.
mod common;
use atlas_pca::budget_forecast::*;
use atlas_pca::catalog::{build_catalog, define_action};
use atlas_pca::facade::{compile_policy, CompileOptions, CompiledPolicy};
use atlas_pca::policy_sim::SimOptions;
use atlas_pca::serde_json::{json, Value};
use common::replay::{replay, thrown};

/// A double of the corpus: a JSON number, or `{"$num": "NaN" | "Infinity" | "-Infinity"}`. Anything else (a string, null) is
/// no number: the reference refuses it as non-finite, and so does NaN here.
fn double(v: &Value) -> f64 {
    match v.get("$num").and_then(Value::as_str) {
        Some("Infinity") => f64::INFINITY,
        Some("-Infinity") => f64::NEG_INFINITY,
        _ => v.as_f64().filter(|_| v.is_number()).unwrap_or(f64::NAN),
    }
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

fn run_forecast(a: &[Value]) -> Result<Value, String> {
    let policy = compile(&a[0])?;
    let custom = match a[3].as_array() {
        Some(actions) => Some(build_catalog(&actions.iter().map(define_action).collect::<Result<Vec<_>, _>>()?)),
        None => None,
    };
    let start = if a[2].is_null() { None } else { Some(double(&a[2])) };
    forecast(&policy, a[1].as_array().expect("a plan"), SimOptions { catalog: custom.as_ref(), start })
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "forecast" => run_forecast(a).unwrap_or_else(thrown),
        "recommendPolicy" => {
            let kappa = if a[2].is_null() { None } else { Some(double(&a[2])) };
            recommend_policy(double(&a[0]), double(&a[1]), kappa).unwrap_or_else(thrown)
        }
        "autonomyBoundOf" => match autonomy_bound_of(&a[0]) {
            b if b.is_nan() => json!({"$num": "NaN"}),
            b => atlas_pca::prohibitions::num_value(b),
        },
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn ref_budget_forecast_replay() {
    replay("budget-forecast", 326, 0, run);
}
