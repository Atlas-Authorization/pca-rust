//! Differential replay of the intent kit, part 1 (classifier, compilers, frames, jit, lattice, layers, learner) against the TypeScript
//! reference (test-data/ref-intent-{classifier,compilers,frames,jit,lattice,layers,learner}.json.gz). A reference throw requires a
//! refusal. Doubles from transcendental functions (log, exp, pow) compare to 1e-12 relative; counts, ppm-like integers, signatures,
//! strings and structure exactly. A frame report's host-runtime error text ("error: ...") is compared as "error: error", as the oracle does.
//! Skipped: none (every function of the seven corpora is replayed). The learner's `harm` option and a caller catalogue are not native
//! (the default harm model and the built-in catalogue only); the corpora use no other.
mod common;
use atlas_pca::intent_kit::classifier::*;
use atlas_pca::intent_kit::compilers::*;
use atlas_pca::intent_kit::frames::*;
use atlas_pca::intent_kit::jit::*;
use atlas_pca::intent_kit::jn;
use atlas_pca::intent_kit::layers::*;
use atlas_pca::intent_kit::learner::*;
use atlas_pca::intent_kit::mapkit::*;
use atlas_pca::intent_kit::metrics::*;
use atlas_pca::intent_kit::multi::*;
use atlas_pca::intent_kit::omega::*;
use atlas_pca::intent_kit::policy::*;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;
use sha2::{Digest, Sha256};

type R<T> = Result<T, String>;

fn a(args: &[Value], i: usize) -> &Value {
    static NULL: Value = Value::Null;
    args.get(i).unwrap_or(&NULL)
}

/// The corpora whose every number gates a decision (the next question, the version-space size, the committee entropy) and is computed
/// by the deterministic math: compared exactly. The other corpora keep a relative 1e-12 on non-integers (reported statistics).
const EXACT_PKGS: [&str; 2] = ["intent-learner", "intent-compilers"];

fn close(x: &Value, y: &Value, tol: bool) -> bool {
    match (x, y) {
        (Value::Object(p), Value::Object(q)) => p.len() == q.len() && p.iter().all(|(k, v)| q.get(k).is_some_and(|w| close(v, w, tol))),
        (Value::Array(p), Value::Array(q)) => p.len() == q.len() && p.iter().zip(q.iter()).all(|(v, w)| close(v, w, tol)),
        (Value::Number(p), Value::Number(q)) => {
            if p.is_i64() && q.is_i64() {
                return p == q;
            }
            let (f, g) = (p.as_f64().unwrap_or(f64::NAN), q.as_f64().unwrap_or(f64::NAN));
            f == g || (tol && ((f - g).abs() <= 1e-15 || (f - g).abs() <= 1e-12 * f.abs().max(g.abs())))
        }
        _ => x == y,
    }
}

fn mk(omega: &Value, mo: &Value, obs: &Value) -> R<IntentLearner> {
    let om = Omega::from_json(omega)?;
    let mut l = create_learner(&om, Some(mo))?;
    for x in obs.as_array().ok_or("observations must be an array")? {
        let oc = json!({"verb": x["verb"], "values": x["values"]});
        l.observe(&oc, x["y"].as_i64().ok_or("y")?, x["source"].as_str().unwrap_or("elicitation"), x.get("region"))?;
    }
    Ok(l)
}

fn dig(x: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(x.as_bytes()))
}

fn specs_of(v: &Value) -> R<Vec<IntentCompiler>> {
    v.as_array().ok_or("specs must be an array")?.iter().map(IntentCompiler::from_spec).collect()
}

fn byte_vec(v: &Value) -> Vec<u8> {
    v.as_array().map(|x| x.iter().map(|b| b.as_u64().unwrap_or(0) as u8).collect()).unwrap_or_default()
}

fn run_classifier(f: &str, x: &[Value]) -> R<Value> {
    match f {
        "calibrate" => calibrate_confusion(a(x, 0), a(x, 1), x.get(2).and_then(Value::as_f64).unwrap_or(0.05)),
        "confusionDigest" => confusion_digest(a(x, 0)).map(Value::String),
        "publishedErrorRate" => published_error_rate(a(x, 0)).map(jn),
        "classifierCardNote" => classifier_card_note(a(x, 0).as_str().ok_or("id")?, a(x, 1)).map(Value::String),
        "riskArrays" => match a(x, 0).as_str() {
            Some("risk") => classifier_risk(a(x, 1)).map(jn),
            Some("sound") => label_sound(a(x, 1)).map(Value::Bool),
            _ => label_sound_bound(a(x, 1), a(x, 2).as_f64().ok_or("hMax")?).map(jn),
        },
        "awareScenario" => {
            let mut l = mk(a(x, 0), a(x, 1), a(x, 2))?;
            classifier_aware_residual_risk(&mut l, a(x, 3))
        }
        "jitScenario" => {
            let mut l = mk(a(x, 0), a(x, 1), a(x, 2))?;
            classifier_jit_cells(&mut l, a(x, 3), a(x, 4).as_f64().ok_or("gamma")?)
        }
        _ => Err(format!("unknown fn {f}")),
    }
}

fn run_compilers(f: &str, x: &[Value]) -> R<Value> {
    match f {
        "slotsPrompt" => Ok(Value::String(slots_prompt(a(x, 0).as_str().ok_or("text")?))),
        "parseSlotsJSON" => Ok(parse_slots_json(a(x, 0).as_str().ok_or("raw")?)),
        "runScenario" => Ok(run_compilers_fn(a(x, 0), &specs_of(a(x, 1))?)),
        "analyze" => analyze_disagreement(a(x, 0), a(x, 1)),
        "flags" => Ok(Value::Bool(panel_flags(&analyze_disagreement(a(x, 0), a(x, 1))?))),
        "anchors" => committee_anchors(a(x, 0), a(x, 1)),
        "compareScenario" => compile_and_compare(a(x, 0), &specs_of(a(x, 1))?, a(x, 2)),
        _ => Err(format!("unknown fn {f}")),
    }
}

fn run_compilers_fn(input: &Value, c: &[IntentCompiler]) -> Value {
    atlas_pca::intent_kit::compilers::run_compilers(input, c)
}

/// The oracle compares a host-runtime error text of checkFrame as "error: error".
fn norm_frame(mut r: Value) -> Value {
    if let Some(ms) = r.get_mut("missing").and_then(Value::as_array_mut) {
        for m in ms {
            if let Some(s) = m.as_str() {
                if s.starts_with("error: ") && !s.starts_with("error: spec, action") {
                    *m = json!("error: error");
                }
            }
        }
    }
    r
}

fn run_frames(f: &str, x: &[Value]) -> R<Value> {
    match f {
        "stateDigest" => Ok(Value::String(state_digest(a(x, 0)))),
        "snapshotState" => snapshot_state(a(x, 0), x.get(1).map_or(true, |k| !matches!(k, Value::Null | Value::Bool(false)))),
        "checkFrame" => Ok(norm_frame(check_frame(a(x, 0), a(x, 1), a(x, 2), a(x, 3), a(x, 4)))),
        "applyScenario" => {
            let mut l = mk(a(x, 0), a(x, 1), a(x, 2))?;
            let result = apply_frame_report(&mut l, a(x, 3), a(x, 4))?;
            let metrics = l.metrics();
            Ok(json!({"result": result, "metrics": metrics}))
        }
        _ => Err(format!("unknown fn {f}")),
    }
}

fn run_jit(f: &str, x: &[Value]) -> R<Value> {
    match f {
        "visitScenario" => {
            let mut l = mk(a(x, 0), a(x, 1), a(x, 2))?;
            let ceilings: Vec<Ceiling> = a(x, 5).as_array().ok_or("ceilings")?.iter().map(|c| named_ceiling(c.as_str().unwrap_or(""))).collect::<R<_>>()?;
            decide_visit(&mut l, a(x, 3), a(x, 4), &ceilings, a(x, 6).as_bool().unwrap_or(false))
        }
        "cellCoords" => {
            let vs = VerbSpace::from_json(a(x, 0))?;
            let cell: Vec<usize> = a(x, 1).as_array().ok_or("cell")?.iter().map(|c| c.as_u64().unwrap_or(u64::MAX) as usize).collect();
            cell_coords(&vs, &cell)
        }
        "cellFromCoords" => {
            let vs = VerbSpace::from_json(a(x, 0))?;
            Ok(match cell_from_coords(&vs, a(x, 1)) {
                Some(c) => Value::Array(c.into_iter().map(jn).collect()),
                None => Value::Null,
            })
        }
        "deltaScenario" => {
            let (omega, mo, obs, more) = (a(x, 0), a(x, 1), a(x, 2), a(x, 3));
            let mut prev = mk(omega, mo, obs)?;
            let all = Value::Array(obs.as_array().unwrap().iter().chain(more.as_array().unwrap().iter()).cloned().collect());
            let mut next = mk(omega, mo, &all)?;
            let d = delta_cells(&mut prev, &mut next);
            let preds = delta_predicates(&next.omega, &d)?;
            Ok(json!({"cells": delta_to_json(&d), "predicates": preds}))
        }
        "requiredScenario" => {
            let om = Omega::from_json(a(x, 0))?;
            let vs = om.verb(a(x, 1).as_str().ok_or("verb")?).ok_or("Cannot read properties of undefined (reading 'verb')")?;
            let mut inp = a(x, 3).as_object().cloned().ok_or("input")?;
            inp.insert("vs".into(), vs.to_json());
            inp.insert("cell".into(), a(x, 2).clone());
            let inp = Value::Object(inp);
            let body = intent_required_body(&inp)?;
            let signed = signed_intent_required(&inp, "site-1", a(x, 4).as_str().ok_or("seed")?)?;
            Ok(json!({"body": body, "signed": signed}))
        }
        "walletScenario" => {
            let (omega, mutation, now, lifted, session, map_digest, seed) =
                (a(x, 0), a(x, 2).as_str().ok_or("mutation")?, a(x, 3), a(x, 4), a(x, 5), a(x, 6), a(x, 7).as_str().ok_or("seed")?);
            let om = Omega::from_json(omega)?;
            let vs = om.verb("stripe.refund").ok_or("no verb")?;
            let mut inp = a(x, 1).as_object().cloned().ok_or("input")?;
            inp.insert("vs".into(), vs.to_json());
            inp.insert("cell".into(), json!([1, 0]));
            let inp = Value::Object(inp);
            let mut body = signed_intent_required(&inp, "site-1", seed)?;
            match mutation {
                "coords" => body["cell"]["coords"]["action.params.amount"] = json!([2, 2]),
                "verb" => body["cell"]["verb"] = json!("gmail.send"),
                "sig" => {
                    let v = body["sig"]["value"].as_str().unwrap().to_string();
                    body["sig"]["value"] = json!(format!("{}AA", &v[..v.len() - 2]));
                }
                "kid" => body["sig"]["kid"] = json!("other"),
                "session" => body["session"] = json!(dig("other")),
                "action" => body["action_digest"] = json!(dig("other")),
                "null" => body = Value::Null,
                _ => {}
            }
            let pk = atlas_pca::agent::KeyPair::from_seed_b64u(seed)?.public;
            let w = json!({"keys": [{"kid": "site-1", "alg": "ed25519", "pk": pk}], "now": now, "session": session, "mapDigest": map_digest, "omegaTilde": omega, "lifted": lifted, "pcactn": a(x, 1)["pcactn"]});
            wallet_check_intent_required(&body, &w)
        }
        "mintScenario" => {
            let (omega, mo, obs, more, args, seed) = (a(x, 0), a(x, 1), a(x, 2), a(x, 3), a(x, 4), a(x, 5).as_str().ok_or("seed")?);
            let mut prev = mk(omega, mo, obs)?;
            let all = Value::Array(obs.as_array().unwrap().iter().chain(more.as_array().unwrap().iter()).cloned().collect());
            let mut next = mk(omega, mo, &all)?;
            Ok(mint_delta(&mut prev, &mut next, args, seed)?.unwrap_or(Value::Null))
        }
        _ => Err(format!("unknown fn {f}")),
    }
}

fn run_lattice(f: &str, x: &[Value]) -> R<Value> {
    match f {
        "latticeScenario" => {
            let mut l = mk(a(x, 0), a(x, 1), a(x, 2))?;
            let c = ceiling_admitters(a(x, 3))?;
            let mut decisions = vec![];
            for o in a(x, 4).as_array().ok_or("outcomes")? {
                decisions.push(decide_outcome_layers(&mut l, &c, o)?);
            }
            Ok(json!({"view": lattice_view(&mut l, &c)?, "decisions": decisions}))
        }
        "orgScenario" => org_layer_from_maps(a(x, 0), a(x, 1)),
        _ => Err(format!("unknown fn {f}")),
    }
}

fn refs_of(v: &Value) -> R<Vec<String>> {
    v.as_array().ok_or("refs")?.iter().map(|s| s.as_str().map(String::from).ok_or_else(|| "ref".to_string())).collect()
}

fn run_layers(f: &str, x: &[Value]) -> R<Value> {
    match f {
        "normalizeRule" => normalize_rule(a(x, 0), &refs_of(a(x, 1))?).map(|n| n.to_json()),
        "effectiveVetoers" => effective_vetoers(a(x, 0), &refs_of(a(x, 1))?).map(|v| json!(v)),
        "ruleAdmits" => {
            let ins: Vec<bool> = a(x, 1).as_array().ok_or("ins")?.iter().map(|b| b.as_bool().unwrap_or(false)).collect();
            rule_admits(&NRule::from_json(a(x, 0))?, &ins).map(Value::Bool)
        }
        "jointAcceptance" => {
            let ps: Vec<f64> = a(x, 1).as_array().ok_or("ps")?.iter().map(|b| b.as_f64().unwrap_or(f64::NAN)).collect();
            joint_acceptance(&NRule::from_json(a(x, 0))?, &ps).map(jn)
        }
        "commonRefinement" => common_refinement(a(x, 0)),
        "ceilingOf" => {
            let c = ceiling_admitters(a(x, 0))?;
            let vs = VerbSpace::from_json(a(x, 1))?;
            Ok(ceiling_of(&c, &vs, a(x, 2))?.map_or(Value::Null, |s| json!(s)))
        }
        "assertAskable" => assert_askable(a(x, 0), a(x, 1)).map(|_| Value::Null),
        "layerCells" => layer_cells(&Omega::from_json(a(x, 0))?, &admitter(a(x, 1))?),
        "ownerRisk" => owner_risk(&Omega::from_json(a(x, 0))?, a(x, 1), &acceptability_of(a(x, 2))?).map(jn),
        "cellKeyOf" => cell_key_of(&Omega::from_json(a(x, 0))?, a(x, 1)).map(Value::String),
        "signLayerApproval" => sign_layer_approval(a(x, 0), a(x, 1).as_str().ok_or("seed")?),
        "verifyQuorumApprovals" => Ok(verify_quorum_approvals(a(x, 0), a(x, 1), a(x, 2), a(x, 3))),
        "measureGrantExact" => measure_grant_exact(&Omega::from_json(a(x, 0))?, a(x, 1), &acceptability_of(a(x, 2))?),
        "measureGrant" => measure_grant(&Omega::from_json(a(x, 0))?, a(x, 1), &acceptability_of(a(x, 2))?, x.get(3).filter(|v| !v.is_null())),
        _ => Err(format!("unknown fn {f}")),
    }
}

fn jq(q: &Value) -> Value {
    if q.is_null() {
        return Value::Null;
    }
    json!({"verb": q["verb"], "cell": q["cell"], "outcome": q["outcome"], "p": q["p"], "score": q["score"]})
}

fn scenario(omega_v: &Value, opts: &Value, ops: &Value) -> R<Value> {
    let omega = Omega::from_json(omega_v)?;
    let mut l = IntentLearner::new(&omega, LearnerOpts::from_json(opts)?)?;
    let mut out = vec![];
    for op in ops.as_array().ok_or("ops")? {
        let kind = op["op"].as_str().ok_or("bad op")?;
        match kind {
            "observe" => {
                let oc = json!({"verb": op["verb"], "values": op["values"]});
                let src = op.get("source").and_then(Value::as_str).unwrap_or("elicitation");
                out.push(l.observe(&oc, op["y"].as_i64().ok_or("y")?, src, op.get("region"))?.unwrap_or(Value::Null));
            }
            "probe" => {
                let oc = json!({"verb": op["verb"], "values": op["values"]});
                out.push(json!([l.acceptance(&oc), l.admits_outcome(&oc), l.is_vetoed(&oc)]));
            }
            "next" => out.push(jq(&l.next_question()?.unwrap_or(Value::Null))),
            "metrics" => out.push(l.metrics()),
            "cells" => out.push(Value::Array(l.cells().iter().map(|c| c.to_json()).collect())),
            "unconfirmed" => {
                out.push(Value::Array(l.unconfirmed_grant_cells().into_iter().map(|(v, c, w)| json!({"verb": v, "cell": c, "weight": w})).collect()))
            }
            "synth" => out.push(l.synthesize()?),
            "vetoed" => out.push(json!(l.vetoed_cells())),
            "observations" => out.push(Value::Array(l.observations.clone())),
            "replay" => {
                let mut r = IntentLearner::replay(&omega, LearnerOpts::from_json(opts)?, &l.observations)?;
                out.push(r.metrics());
            }
            "elicit" => {
                let adm = admitter(&op["policy"])?;
                let mut k = 0u64;
                let flip = op.get("flipEvery").and_then(Value::as_u64).unwrap_or(0);
                let om2 = omega.clone();
                let mut ans = |q: &Value| -> R<i64> {
                    let vs = om2.verb(q["verb"].as_str().ok_or("verb")?).ok_or("no verb")?;
                    let y = if adm.admits(vs, &q["outcome"])? { 1 } else { 0 };
                    k += 1;
                    Ok(if flip != 0 && k % flip == 0 { 1 - y } else { y })
                };
                let o = json!({"epsRisk": op["epsRisk"], "epsBurden": op["epsBurden"], "maxQuestions": op["maxQuestions"], "audit": op.get("audit"), "seed": op.get("seed")});
                let r = elicit(&mut l, &mut ans, &o)?;
                let asked: Vec<Value> = r["asked"].as_array().unwrap().iter().map(jq).collect();
                out.push(json!({"stop": r["stop"], "questions": r["questions"], "auditQuestions": r["auditQuestions"], "seedQuestions": r["seedQuestions"], "asked": asked, "metrics": l.metrics()}));
            }
            _ => return Err("bad op".into()),
        }
    }
    Ok(Value::Array(out))
}

fn run_learner(f: &str, x: &[Value]) -> R<Value> {
    match f {
        "scenario" => scenario(a(x, 0), a(x, 1), a(x, 2)),
        "hypothesisCellSets" => {
            let vs = VerbSpace::from_json(a(x, 0))?;
            let hc = x.get(1).filter(|v| !v.is_null());
            let caps = x.get(2).filter(|v| !v.is_null());
            let (sets, cx) = hypothesis_cell_sets(&vs, hc, caps)?;
            if caps.is_some() || hc.is_none() {
                return Ok(jn(sets.len() as f64));
            }
            Ok(json!({"sets": sets.iter().map(|s| s.iter().map(|b| *b as u64).collect::<Vec<u64>>()).collect::<Vec<_>>(), "complexity": cx}))
        }
        "hypothesisClassName" => hypothesis_class_name(a(x, 0)).map(Value::String),
        "boxesToPredicates" => {
            let vs = VerbSpace::from_json(a(x, 0))?;
            boxes_to_predicates(&vs, &byte_vec(a(x, 1))).map(Value::Array)
        }
        _ => Err(format!("unknown fn {f}")),
    }
}

fn replay(pkg: &str, run: fn(&str, &[Value]) -> R<Value>) {
    let cases = common::ref_cases_seeded(pkg);
    let mut bad: Vec<String> = vec![];
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        let args = c["args"].as_array().unwrap().clone();
        let got = std::panic::catch_unwind(|| run(f, &args)).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => close(v, &c["out"], !EXACT_PKGS.contains(&pkg)),
            _ => false,
        };
        if !ok {
            let g = format!("{:?}", got.map(|v| v.to_string()));
            bad.push(format!(
                "{}\n  want {}\n  got  {}",
                c["name"],
                c["out"].to_string().chars().take(400).collect::<String>(),
                g.chars().take(400).collect::<String>()
            ));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(25).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn intent_classifier_vectors() {
    replay("intent-classifier", run_classifier);
}

#[test]
fn intent_compilers_vectors() {
    replay("intent-compilers", run_compilers);
}

#[test]
fn intent_frames_vectors() {
    replay("intent-frames", run_frames);
}

#[test]
fn intent_jit_vectors() {
    replay("intent-jit", run_jit);
}

#[test]
fn intent_lattice_vectors() {
    replay("intent-lattice", run_lattice);
}

#[test]
fn intent_layers_vectors() {
    replay("intent-layers", run_layers);
}

#[test]
fn intent_learner_vectors() {
    replay("intent-learner", run_learner);
}
