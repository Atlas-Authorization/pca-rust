//! 0.4.2 mutation kills for intent_map.rs (rule 19): a differential test against the TS reference
//! (oracle tools/pca-audit/java-mutate/k042-mapartcls-oracle.mjs -> tests/data/k042-mapartcls.json.gz, the same file the Java
//! suite runs). Every validator case asserts the EXACT reason (or null), every decision the exact verdict. The oracle's
//! `learner` leaf has no validator here (this verifier opens only header / cell / metrics leaves) and a decision's
//! residual_risk_ppm is not a member of MapDecision: both are not compared. A case with a lone surrogate is skipped.
use super::*;
use crate::k042_support::{corpus_cases, has_lone};
use serde_json::json;

const FILE: &str = "k042-mapartcls.json.gz";

fn live(fn_name: &str) -> Vec<Value> {
    corpus_cases(FILE, fn_name).into_iter().filter(|c| !c["args"].as_array().unwrap().iter().any(has_lone)).collect()
}

fn report(bad: Vec<String>) {
    assert!(bad.is_empty(), "{} divergent case(s):\n{}", bad.len(), bad.iter().take(400).cloned().collect::<Vec<_>>().join("\n"));
}

fn validators(fn_name: &str, f: impl Fn(&Value) -> Option<String>) {
    let mut bad = Vec::new();
    for c in live(fn_name) {
        // the metrics validator here takes the object leaf (a non-object leaf is refused by the decision, see disclosure_shape)
        if fn_name == "metrics" && !c["args"][0].is_object() {
            continue;
        }
        let want = c["out"].as_str().map(String::from);
        let got = f(&c["args"][0]);
        if want != got {
            bad.push(format!("{}\n  want: {want:?}\n  got:  {got:?}", c["name"]));
        }
    }
    report(bad);
}

#[test]
fn header_leaf() {
    validators("header", |v| header_of(v).err());
}

#[test]
fn cell_leaf() {
    validators("cell", cell_error);
}

#[test]
fn metrics_leaf() {
    validators("metrics", metrics_error);
}

/// The disclosure shape: every reason `decide_map_disclosure` gives with the prefix "map disclosure malformed: ".
#[test]
fn disclosure_shape() {
    validators("disclosure", |d| {
        let r = decide_map_disclosure(None, &json!({}), None, Some(d), None).reason;
        r.strip_prefix("map disclosure malformed: ").map(String::from)
    });
}

#[test]
fn numeric_cells() {
    let mut bad = Vec::new();
    for c in live("numcells") {
        let d = c["args"][0].as_object().unwrap();
        let cuts: Vec<i64> = d["cuts"].as_array().unwrap().iter().map(|x| x.as_i64().unwrap()).collect();
        let got: Vec<Value> = num_cells(d["lo"].as_i64().unwrap(), d["hi"].as_i64().unwrap(), &cuts).into_iter().map(|(a, b)| json!([a, b])).collect();
        if Value::Array(got.clone()) != c["out"] {
            bad.push(format!("{}\n  want: {}\n  got:  {}", c["name"], c["out"], Value::Array(got)));
        }
    }
    report(bad);
}

#[test]
fn cell_of_the_action() {
    let mut bad = Vec::new();
    for c in live("cellof") {
        let a = c["args"].as_array().unwrap();
        let h = header_of(&a[0]).unwrap_or_else(|e| panic!("{}: {e}", c["name"]));
        let params = a.get(2).and_then(Value::as_object).cloned().unwrap_or_default();
        let got = match cell_of(&h, Some(&a[1]), &params) {
            Ok((cell, flat)) => json!({"cell": cell, "flat": flat}),
            Err(_) => Value::Null,
        };
        if got != c["out"] {
            bad.push(format!("{}\n  want: {}\n  got:  {got}", c["name"], c["out"]));
        }
    }
    report(bad);
}

#[test]
fn commitment() {
    let mut bad = Vec::new();
    for c in live("commit") {
        let got = map_commit_of_leaves(&c["args"][0]).map_or(Value::Null, Value::String);
        if got != c["out"] {
            bad.push(format!("{}\n  want: {}\n  got:  {got}", c["name"], c["out"]));
        }
    }
    report(bad);
}

#[test]
fn map_decisions() {
    let mut bad = Vec::new();
    for c in live("decide") {
        let i = &c["args"][0];
        let eps = i.get("max_residual_risk_ppm").and_then(Value::as_i64);
        let d = decide_map_disclosure(i.get("map_commit"), &i["action"], i.get("params"), i.get("disclosure"), eps);
        let o = &c["out"];
        let want = if o["ok"] == Value::Bool(true) { format!("true||{}|{}", o["cell"], o["p_ppm"]) } else { format!("false|{}|[]|0", o["reason"].as_str().unwrap()) };
        let got = if d.ok { format!("true||{}|{}", json!(d.cell), d.p_ppm) } else { format!("false|{}|[]|0", d.reason) };
        if want != got {
            bad.push(format!("{}\n  want: {want}\n  got:  {got}", c["name"]));
        }
    }
    report(bad);
}
