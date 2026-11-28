//! Differential replay of test-data/ref-frontier-signals.json.gz (written by the TypeScript reference): the three signal typings
//! (semantic, progress, objective) and the risk-input tightening. A case the reference refuses must be refused here (a null baseline
//! or objective).
mod common;
use atlas_pca::frontier_signals::*;
use atlas_pca::serde_json::{json, Value};
use common::replay::{replay, thrown};

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "semanticSignal" => json!(semantic_signal(&a[0])),
        "progressSignal" => json!(progress_signal(&a[0])),
        "objectiveSignal" => json!(objective_signal(&a[0])),
        "tightenRiskInputs" => tighten_risk_inputs(&a[0], &a[1]).unwrap_or_else(thrown),
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn frontier_signals_replay() {
    replay("frontier-signals", 690, 0, run);
}
