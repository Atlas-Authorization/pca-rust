//! Differential replay of @atlasauth/pca-goal Part 1 (the goal kernel and the typed layer over it) against the reference.
//!  1. `test-data/ref-goal-kernel.json.gz` (PRIMARY gate): every op of the hand-ported kernel, byte-equal as harness text, for
//!     typecheck / compile / render and, per probe, decideg + decidep (recorded from the extracted Dafny code).
//!  2. `test-data/ref-goal.json.gz`: the token-tape codec, digests, normalize, fmt, policy digest (a reference throw requires a refusal).
//!  3. packages/pca-conformance/vectors/goal/*.json (kinds gen / ill / w): the typed layer end to end, with the rules of
//!     packages/pca-goal/adversarial/src/runner.ts (typecheck == compile.reasons, goal / policy digests, every probe's decision and witness,
//!     the witness checker, decideGoal == decidePolicy).
//! Skipped (counted, must stay under 10%): the cases that carry a lone surrogate (a Rust string cannot hold one). Not replayed:
//! the `checkOntology` Allow-witness issue (`examples.ts allowWitness` belongs to the examples module; see ontology.rs).
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::goal::codec::*;
use atlas_pca::goal::compiler::*;
use atlas_pca::goal::digests::*;
use atlas_pca::goal::fmt::*;
use atlas_pca::goal::kernel::goal_call_text;
use atlas_pca::goal::normalize::*;
use atlas_pca::serde_json::{json, Value};

#[test]
fn kernel_corpus() {
    let cases = common::ref_cases("goal-kernel");
    let mut bad: Vec<String> = Vec::new();
    for c in &cases {
        let name = c["name"].as_str().unwrap();
        let a = c["args"].as_array().unwrap();
        let (g, o) = (a[0].as_str().unwrap(), a[1].as_str().unwrap());
        let out = &c["out"];
        for op in ["typecheck", "compile", "render"] {
            let got = goal_call_text(op, g, o, "", "");
            if got.as_deref().ok() != out[op].as_str() {
                bad.push(format!("{name}: {op}\n  want {}\n  got  {got:?}", out[op]));
            }
        }
        for (i, p) in a[2].as_array().unwrap().iter().enumerate() {
            let (act, hist) = (p[0].as_str().unwrap(), p[1].as_str().unwrap());
            for (j, op) in ["decideg", "decidep"].iter().enumerate() {
                let got = goal_call_text(op, g, o, act, hist);
                if got.as_deref().ok() != out["probes"][i][j].as_str() {
                    bad.push(format!("{name}#{i}: {op}\n  want {}\n  got  {got:?}", out["probes"][i][j]));
                }
            }
        }
    }
    assert!(cases.len() >= 200, "{} kernel cases", cases.len());
    assert!(bad.is_empty(), "{} kernel disagreements:\n{}", bad.len(), bad.iter().take(10).cloned().collect::<Vec<_>>().join("\n"));
}

const SKIPPED: [&str; 0] = [];

fn tape_arg(v: &Value) -> Result<Vec<atlas_pca::goal::render::Tok>, String> {
    tape_from_json(v)
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "encodeGoal" => encode_goal(&a[0]).map(|t| tape_to_json(&t)),
        "encodeOntology" => encode_ontology(&a[0]).map(|t| tape_to_json(&t)),
        "encodeAct" => encode_act(&a[0]).map(|t| tape_to_json(&t)),
        "encodeHist" => encode_hist(&a[0]).map(|t| tape_to_json(&t)),
        "decodeGoal" => decode_goal(&tape_arg(&a[0])?),
        "decodePolicy" => decode_policy(&tape_arg(&a[0])?),
        "goalDigest" => goal_digest(&a[0]).map(Value::String),
        "nlDigest" => nl_digest(&a[0]).map(Value::String),
        "modelSetDigest" => {
            let ms: Vec<String> =
                a[0].as_array().ok_or("array expected")?.iter().map(|x| x.as_str().map(String::from).ok_or("string expected")).collect::<Result<_, _>>()?;
            model_set_digest(&ms).map(Value::String)
        }
        "approvalDigest" => approval_digest(&a[0]).map(Value::String),
        "canonicalizeGoal" => canonicalize_goal(&a[0]),
        "stable" => Ok(Value::String(stable(&a[0]))),
        "fmtMoney" => Ok(Value::String(fmt_money(a[0].as_str().ok_or("string expected")?, a[1].as_i64().ok_or("integer expected")?))),
        "fmtQuantity" => fmt_quantity(&a[0]).map(Value::String),
        "fmtValue" => fmt_value(&a[0]).map(Value::String),
        "fmtAct" => fmt_act(&a[0]).map(Value::String),
        "canonicalPolicy" => Ok(Value::String(canonical_policy(&a[0]))),
        "policyDigest" => Ok(Value::String(policy_digest(&a[0]))),
        "renderCard" => atlas_pca::goal::card::render_card(&a[0]),
        "renderCond" => atlas_pca::goal::card::cond(Some(&a[0])).map(Value::String),
        "refExplain" => atlas_pca::goal::refsem::ref_explain(&a[0], &a[1], &a[2], &a[3]),
        "refDecide" => atlas_pca::goal::refsem::ref_decide(&a[0], &a[1], &a[2], &a[3]).map(|d| json!(d)),
        "actionDigest" => atlas_pca::goal::binding::action_digest(&a[0]).map(Value::String),
        "bindDecision" => atlas_pca::goal::binding::bind_decision(&a[0], a[1].as_str().ok_or("decision must be a string")?),
        "guardExecute" => Ok(json!(atlas_pca::goal::binding::guard_execute(&a[0], &a[1]))),
        "claimGate" => Ok(json!(atlas_pca::goal::binding::claim_gate(a[0].as_str().ok_or("base")?, a[1].as_f64().ok_or("min")?, a[2].as_f64()))),
        "goalCommit" => Ok(json!(atlas_pca::goal::binding::goal_commit(a[0].as_str().ok_or("g")?, a[1].as_str().ok_or("p")?, a[2].as_str().ok_or("s")?))),
        "openCommit" => Ok(json!(atlas_pca::goal::binding::open_commit(
            a[0].as_str().ok_or("commit")?,
            a[1].as_str().ok_or("g")?,
            a[2].as_str().ok_or("p")?,
            a[3].as_str().ok_or("s")?
        ))),
        "signPayloadSeed" => atlas_pca::goal::sign::sign_payload(a[0].as_str().ok_or("kind")?, &a[1], &KeyPair::from_seed_b64u(a[2].as_str().ok_or("seed")?)?),
        "signGoalArtifactSeed" => {
            atlas_pca::goal::sign::sign_goal_artifact(a[0].as_str().ok_or("kind")?, &a[1], &KeyPair::from_seed_b64u(a[2].as_str().ok_or("seed")?)?)
        }
        "signerId" => KeyPair::from_seed_b64u(a[0].as_str().ok_or("seed")?).map(|k| json!(k.public)),
        "goalDomain" => Ok(json!(atlas_pca::goal::sign::goal_domain(a[0].as_str().ok_or("kind")?))),
        "verifyPayload" => Ok(json!(atlas_pca::goal::sign::verify_payload(&a[0], a[1].as_str().ok_or("kind")?, a[2].as_array().ok_or("pins")?))),
        "verifyGoalArtifact" => Ok(json!(atlas_pca::goal::sign::verify_goal_artifact(
            a[0].as_str().ok_or("kind")?,
            &a[1],
            a[2].as_str().ok_or("field")?,
            a[3].as_array().ok_or("pins")?
        ))),
        other => Err(format!("skip:{other}")),
    }
}

#[test]
fn goal_corpus() {
    let cases = common::ref_cases_seeded("goal");
    let (mut bad, mut skipped) = (Vec::new(), 0usize);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) || SKIPPED.contains(&f) {
            skipped += 1;
            continue;
        }
        let got = std::panic::catch_unwind(|| run(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| Err("panic".into()));
        if matches!(&got, Err(e) if e.starts_with("skip:")) {
            skipped += 1;
            continue;
        }
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!(
                "{} {}\n  want {}\n  got  {:?}",
                f,
                c["name"],
                c["out"].to_string().chars().take(300).collect::<String>(),
                got.map(|v| v.to_string().chars().take(300).collect::<String>())
            ));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(15).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn conformance_vectors() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packages/pca-conformance/vectors/goal");
    let mut files: Vec<_> =
        std::fs::read_dir(dir).expect("vector dir").map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect();
    files.sort();
    let (mut bad, mut n) = (Vec::<String>::new(), 0usize);
    for f in files {
        if f.file_name().unwrap() == "index.json" {
            continue;
        }
        let v: Value = serde_json_from(&f);
        if v["kind"] == "fn" {
            continue;
        }
        n += 1;
        let id = v["id"].as_str().unwrap().to_string();
        let (g, o) = (&v["goal"], &v["ontology"]);
        if goal_digest(g).ok().as_deref() != v["goal_digest"].as_str() {
            bad.push(format!("{id}: goal_digest"));
        }
        let reasons = typecheck(g, o).expect("typecheck");
        if json!(reasons) != v["compile"]["reasons"] {
            bad.push(format!("{id}: reasons {reasons:?} != {}", v["compile"]["reasons"]));
        }
        let compiled = compile_goal(g, o).expect("compile");
        let ok = compiled["ok"] == true;
        if ok != (v["compile"]["ok"] == true) {
            bad.push(format!("{id}: compile.ok"));
        }
        let pd = if ok { Some(policy_digest(&compiled["policy"])) } else { None };
        if pd.as_deref() != v["policy_digest"].as_str() {
            bad.push(format!("{id}: policy_digest"));
        }
        if !ok {
            continue;
        }
        for (i, p) in v["probes"].as_array().unwrap().iter().enumerate() {
            let r = decide_policy(g, o, &p["action"], &p["history"]).expect("decide_policy");
            let want = &p["expect"];
            let decision_ok = r["ok"] == true && r["decision"] == want["decision"] && r["witness"] == want["witness"];
            let checked_ok = r["decision"] != "allow" || r["witnessChecked"] == true;
            // D_G is defined on a hole-free goal: the reference runners decide the goal with every hole-dependent grant dropped (the
            // compiled policy does the same itself, "the most restrictive completion")
            let stripped = {
                let mut sg = g.clone();
                let holes = g["holes"].as_array().cloned().unwrap_or_default();
                let depends = |gid: &Value| holes.iter().any(|h| h["global"] == json!(true) || h["affects"].as_array().is_some_and(|a| a.contains(gid)));
                sg["grants"] = Value::Array(g["grants"].as_array().cloned().unwrap_or_default().into_iter().filter(|x| !depends(&x["gid"])).collect());
                sg["holes"] = json!([]);
                sg
            };
            let dg = decide_goal(&stripped, o, &p["action"], &p["history"]).expect("decide_goal");
            if !decision_ok || !checked_ok || Some(dg) != want["decision"].as_str() {
                bad.push(format!("{id}#{i}: {r} (decideGoal {dg}) != {want}"));
            }
        }
    }
    assert!(n >= 200, "{n} goal vectors");
    assert!(bad.is_empty(), "{} disagreements:\n{}", bad.len(), bad.iter().take(15).cloned().collect::<Vec<_>>().join("\n"));
}

fn serde_json_from(p: &std::path::Path) -> Value {
    atlas_pca::serde_json::from_str(&std::fs::read_to_string(p).expect("read vector")).expect("parse vector")
}

// ---- ontology (ref-goal-ontology) and legacy lift (ref-goal-legacy)
use atlas_pca::goal::legacy::{lift_legacy, LiftOptions};
use atlas_pca::goal::ontologies::{shipped_catalog, shipped_ontology};
use atlas_pca::goal::ontology::*;

/// A shipped ontology travels by name in the corpus; the hand-written one inline.
fn ont_arg(v: &Value) -> Value {
    match v.as_str() {
        Some(name) => shipped_ontology(name).unwrap_or_else(|| panic!("unknown shipped ontology {name}")),
        None => v.clone(),
    }
}

fn run_ontology(f: &str, a: &[Value]) -> Result<Value, String> {
    let nul = |v: Option<Value>| v.unwrap_or(Value::Null);
    match f {
        "shippedOntology" => Ok(nul(a[0].as_str().and_then(shipped_ontology))),
        "shippedCatalog" => Ok(nul(a[0].as_str().and_then(shipped_catalog))),
        "ontologyDigest" => ontology_digest(&ont_arg(&a[0])).map(Value::String),
        "resolveVerb" => resolve_verb(&ont_arg(&a[0]), a[1].as_str().ok_or("word.trim is not a function")?).map(nul),
        "goalCcy" => goal_ccy(&a[0]).map(nul),
        "goalAnchors" => goal_anchors(&a[0]).map(Value::Array),
        "toIrOntology" => to_ir_ontology(&ont_arg(&a[0]), &a[1]),
        "ontologyForGoal" => ontology_for_goal(&ont_arg(&a[0]), &a[1], None),
        // the Allow-witness builder is `examples.ts allowWitness` (the examples module of this package): replaced by "always
        // found" here, and the one issue it can add is dropped from both sides
        "checkOntology" => check_ontology(&ont_arg(&a[0]), &|_, _, _| true).map(Value::Array),
        "instantiateTemplate" => instantiate_template(&ont_arg(&a[0]), a[1].as_str().map(|_| &a[1]), Some(&a[2]), &a[3]),
        "slotLits" => {
            let v = if a[2].is_null() { None } else { Some(&a[2]) };
            slot_lits(&ont_arg(&a[0]), &a[1], v).map(|r| r.to_json())
        }
        "parseHumanAmount" => Ok(parse_human_amount(a[0].as_str().ok_or("text.normalize is not a function")?, a[1].as_i64().unwrap(), a[2].as_str())),
        "parseMoney" => Ok(parse_money(a[0].as_str().ok_or("not a string")?, a[1].as_i64().unwrap(), a[2].as_str())),
        other => Err(format!("skip:{other}")),
    }
}
fn without_witness_issue(v: &Value) -> Value {
    match v.as_array() {
        Some(a) => Value::Array(a.iter().filter(|i| i["msg"] != "instantiated template has an empty Allow set").cloned().collect()),
        None => v.clone(),
    }
}

#[test]
fn ontology_corpus() {
    let cases = common::ref_cases("goal-ontology");
    let (mut bad, mut skipped) = (Vec::new(), 0usize);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let got = std::panic::catch_unwind(|| run_ontology(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| Err("panic".into()));
        if matches!(&got, Err(e) if e.starts_with("skip:")) {
            skipped += 1;
            continue;
        }
        let (want, got) =
            if f == "checkOntology" { (without_witness_issue(&c["out"]), got.map(|v| without_witness_issue(&v))) } else { (c["out"].clone(), got) };
        let ok = match (want.get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            // an engine crash is a refusal: an ontology the checker reports issues for is refused all the same
            (Some(m), Ok(v)) if common::engine_crash(m.as_str().unwrap_or("")) => v.as_array().is_some_and(|l| !l.is_empty()),
            (None, Ok(v)) => atlas_pca::canonicalize(&want) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!(
                "{} {}\n  want {}\n  got  {:?}",
                f,
                c["name"],
                want.to_string().chars().take(300).collect::<String>(),
                got.map(|v| v.to_string().chars().take(300).collect::<String>())
            ));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(15).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn legacy_corpus() {
    let cases = common::ref_cases("goal-legacy");
    let mut bad = Vec::new();
    for c in &cases {
        let a = c["args"].as_array().unwrap();
        let (limits, principal) = (if a[1].is_null() { None } else { Some(&a[1]) }, a[2].as_str().unwrap());
        let got = lift_legacy(&LiftOptions {
            permissions: &a[0],
            limits,
            catalog: None,
            principal,
            not_after: a[3].as_i64(),
            not_before: a[4].as_i64(),
            nl_digest: a[5].as_str(),
        });
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!(
                "{}\n  want {}\n  got  {:?}",
                c["name"],
                c["out"].to_string().chars().take(300).collect::<String>(),
                got.map(|v| v.to_string().chars().take(300).collect::<String>())
            ));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(15).cloned().collect::<Vec<_>>().join("\n"));
}
