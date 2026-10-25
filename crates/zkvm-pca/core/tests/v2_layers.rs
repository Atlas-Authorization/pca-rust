//! V5 layers: the guest (intent_layers.rs) against the TS reference verdicts (fixtures/ts_v2_layers.json,
//! gen_ts_v2_layers.ts): ceiling order, absent vs null, closed and typed layers, denied / task, random sweep.
use pca_zkvm_core::intent_layers::{decide_layer_ceilings, decide_layers, LayerDecision};
use serde_json::Value;

#[test]
fn layers_match_the_ts_reference() {
    let f: Value = serde_json::from_str(include_str!("../../fixtures/ts_v2_layers.json")).unwrap();
    let cases = f["cases"].as_array().unwrap();
    assert!(cases.len() > 600);
    let mut bad = Vec::new();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let root = &c["root"];
        if c["kind"] == "ceilings" {
            let got = decide_layer_ceilings(&c["layers"], root);
            let want_ok = c["ok"].as_bool().unwrap();
            let ok = match (&got, want_ok) {
                (Ok(()), true) => true,
                (Err((l, _)), false) => Some(*l) == c["layer"].as_str(),
                _ => false,
            };
            if !ok {
                bad.push(format!("ceilings/{name}: got {got:?}, want ok={want_ok} layer={}", c["layer"]));
            }
        } else {
            let got = decide_layers(&c["grant"], root);
            let want = match c["decision"].as_str().unwrap() {
                "admit" => LayerDecision::Admit(c["by"].as_u64().unwrap() as usize),
                "ceiling" => match c["layer"].as_str().unwrap() {
                    "org" => LayerDecision::Ceiling("org"),
                    "site" => LayerDecision::Ceiling("site"),
                    _ => LayerDecision::Ceiling("std"),
                },
                "intent_denied" => LayerDecision::IntentDenied,
                _ => LayerDecision::IntentRequired,
            };
            if got != want {
                bad.push(format!("layers/{name}: got {got:?}, want {want:?}"));
            }
        }
    }
    assert!(bad.is_empty(), "{} mismatches:\n{}", bad.len(), bad.join("\n"));
}
