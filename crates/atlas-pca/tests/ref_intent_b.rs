//! Differential replay of intent kit part 2 against the TypeScript reference (@atlasauth/pca-intent) corpora: the outcome space
//! (test-data/ref-intent-omega), multi-principal aggregation (-multi-agg), outcome verification and the Monte Carlo risk estimate
//! (-outcome), profiles (-profile), provenance and regret (-provenance), the trust ramp with signed observations (-ramp) and cut refinement /
//! partial answers / adaptive elicitation (-refine). A reference throw only requires a refusal. Doubles compare exactly except in the
//! multi-agg and refine corpora, which compare non-integral doubles to 1e-12 relative (as the other languages do); a verification problem's
//! language-specific text ("replay failed: ...", a recompute error that is not a reference message) is compared by its prefix.
//! Skipped: nothing (every corpus fn is replayed natively); the custom-harm / callable-option members of the reference carry no JSON form.
mod common;
use atlas_pca::intent_kit2::learner::{Learner, Question};
use atlas_pca::intent_kit2::mapkit::*;
use atlas_pca::intent_kit2::multi_agg::*;
use atlas_pca::intent_kit2::omega::*;
use atlas_pca::intent_kit2::outcome::*;
use atlas_pca::intent_kit2::profile::*;
use atlas_pca::intent_kit2::provenance::*;
use atlas_pca::intent_kit2::ramp::*;
use atlas_pca::intent_kit2::refine::*;
use atlas_pca::intent_kit2::util::*;
use atlas_pca::serde_json::{json, Map, Value};

// ---- harness ----------------------------------------------------------------------------------------------------------------

fn numeq(x: f64, y: f64, close: bool) -> bool {
    if x == y {
        return true;
    }
    if !close || (x.fract() == 0.0 && y.fract() == 0.0) {
        return false;
    }
    (x - y).abs() <= (1e-12 * x.abs().max(y.abs())).max(1e-15)
}

fn eq(a: &Value, b: &Value, close: bool) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => numeq(x.as_f64().unwrap_or(f64::NAN), y.as_f64().unwrap_or(f64::NAN), close),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y.iter()).all(|(p, q)| eq(p, q, close)),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| eq(v, w, close))),
        _ => a == b,
    }
}

fn run(pkg: &str, close: bool, f: &dyn Fn(&str, &[Value]) -> Result<Value, String>) {
    let cases = common::ref_cases_seeded(pkg);
    let mut bad: Vec<String> = vec![];
    for c in &cases {
        let name = c["name"].as_str().unwrap_or("?");
        let fname = c["fn"].as_str().unwrap_or("?");
        let args: Vec<Value> = c["args"].as_array().cloned().unwrap_or_default();
        let got = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(fname, &args))).unwrap_or_else(|_| Err("panic".to_string()));
        let out = &c["out"];
        if out.get("$throws").is_some() {
            if let Ok(v) = got {
                bad.push(format!("{name}: returned {} where the reference throws", v.to_string().chars().take(300).collect::<String>()));
            }
            continue;
        }
        match got {
            Err(e) => bad.push(format!("{name}: refused: {e}")),
            Ok(v) => {
                if !eq(&v, out, close) {
                    bad.push(format!(
                        "{name}: got {} want {}",
                        v.to_string().chars().take(400).collect::<String>(),
                        out.to_string().chars().take(400).collect::<String>()
                    ));
                }
            }
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(25).cloned().collect::<Vec<_>>().join("\n"));
}

fn idx(v: &Value) -> Result<Vec<usize>, String> {
    let mut out = vec![];
    for x in v.as_array().ok_or("an index must be a list")? {
        out.push(fnum(x).filter(|f| *f >= 0.0 && *f == f.floor()).ok_or("a coordinate must be a non-negative integer")? as usize);
    }
    Ok(out)
}

fn one(v: &Value) -> Result<usize, String> {
    Ok(fnum(v).filter(|f| *f >= 0.0 && *f == f.floor()).ok_or("an index must be a non-negative integer")? as usize)
}

fn f(v: &Value) -> Result<f64, String> {
    fnum(v).ok_or_else(|| "a number is required".to_string())
}

fn s(v: &Value) -> Result<&str, String> {
    v.as_str().ok_or_else(|| "a string is required".to_string())
}

fn stats(r: (f64, f64)) -> Value {
    json!({"mass": num(r.0), "harm": num(r.1)})
}

fn mk(omega: &Value, mo: &Value, obs: &Value) -> Result<Learner, String> {
    let mut l = create_learner(omega, mo)?;
    for x in obs.as_array().ok_or("observations must be a list")? {
        l.observe(&json!({"verb": x["verb"], "values": x["values"]}), f(&x["y"])?, s(&x["source"])?, x.get("region").filter(|r| !r.is_null()))?;
    }
    Ok(l)
}

fn cells_of(l: &mut Learner) -> Value {
    Value::Array(l.cells().iter().map(|c| json!({"verb": c.verb, "cell": c.cell, "p": num(c.p)})).collect())
}

// ---- omega ------------------------------------------------------------------------------------------------------------------

fn omega_case(fname: &str, a: &[Value]) -> Result<Value, String> {
    let vs = || Vs::parse(&a[0]);
    let dim = || Dim::parse(&a[0]);
    match fname {
        "deriveOmega" => derive_omega(&a[0]),
        "harmMax" => Ok(num(harm_max(&Omega::parse(&a[0])?)?)),
        "verbSpace" => Ok(a[0]["verbs"].as_array().and_then(|vs| vs.iter().find(|v| v["verb"] == a[1])).cloned().unwrap_or(Value::Null)),
        "verbCellCount" => Ok(num(vs()?.cell_count() as f64)),
        "decodeCell" => Ok(json!(vs()?.decode_cell(f(&a[1])?))),
        "encodeCell" => {
            let i: Vec<f64> = a[1].as_array().ok_or("idx")?.iter().map(|x| f(x)).collect::<Result<_, _>>()?;
            Ok(num(vs()?.encode_cell(&i)?))
        }
        "cellRep" | "seeded" => vs()?.cell_rep(&idx(&a[1])?),
        "cellStats" => Ok(stats(cell_stats(&vs()?, &idx(&a[1])?)?)),
        "cellOf" => Ok(vs()?.cell_of(&a[1]).map(|i| json!(i)).unwrap_or(Value::Null)),
        "harmOf" => Ok(num(harm_of(&vs()?, &a[1]))),
        "cellCount" => Ok(num(dim()?.ncells() as f64)),
        "numCells" => {
            let d = dim()?;
            if !d.is_num {
                return Err("numCells of a categorical dimension".into());
            }
            Ok(Value::Array(d.cells.iter().map(|(lo, hi)| json!({"lo": num(*lo), "hi": num(*hi)})).collect()))
        }
        "numRep" => Ok(num(dim()?.num_rep(one(&a[1])?)?)),
        "repValue" => dim()?.rep_value(one(&a[1])?),
        "catRep" => Ok(Value::String(dim()?.cat_rep(one(&a[1])?)?)),
        "catCellOf" => {
            let d = dim()?;
            if d.is_num {
                return Err("catCellOf of a numeric dimension".into());
            }
            Ok(num(d.cat_cell_of(s(&a[1])?) as f64))
        }
        "cellOfValue" => Ok(num(dim()?.cell_of_value(&a[1]) as f64)),
        "dimCellStats" => Ok(stats(dim_cell_stats(&dim()?, one(&a[1])?)?)),
        "intervalWeight" => Ok(num(interval_weight(&dim()?, f(&a[1])?, f(&a[2])?))),
        "rngSeq" => {
            let mut r = Rng::new(f(&a[0])?);
            Ok(Value::Array((0..f(&a[1])? as usize).map(|_| num(r.next_f64())).collect()))
        }
        "sampleOutcomes" => {
            let om = Omega::parse(&a[0])?;
            let mut r = Rng::new(f(&a[1])?);
            let mut out = vec![];
            for _ in 0..f(&a[2])? as usize {
                out.push(sample_outcome(&om, &mut r)?.1);
            }
            Ok(Value::Array(out))
        }
        "normalizePolicy" => normalize_policy_checked(&a[0]),
        "slotsToPolicy" => slots_to_policy(&a[0]),
        "outcomeToAction" => outcome_to_action(vs()?.reversibility.as_deref(), &a[1]),
        "admits" => {
            let v = Vs::parse(&a[1])?;
            Ok(json!(Admitter::new(&a[0])?.admits(v.reversibility.as_deref(), &a[2])?))
        }
        "regionOfCell" => region_of_cell(&vs()?, &idx(&a[1])?),
        "regionCells" => Ok(json!(region_cells(&vs()?, &a[1], s(&a[2])?)?)),
        "dimCellsIn" => Ok(json!(dim_cells_in(&dim()?, Some(&a[1]).filter(|v| !v.is_null()), s(&a[2])?)?)),
        "restrictRegion" => restrict_region(&json!({"verb": "v", "dims": {}}), &dim()?, &a[1]),
        "valueInRegionDim" => Ok(json!(value_in_region_dim(s(&a[0])?, &a[1], &a[2])?)),
        other => panic!("unknown fn {other}"),
    }
}

#[test]
fn intent_omega_matches_the_reference() {
    run("intent-omega", false, &omega_case);
}

// ---- multi-agg --------------------------------------------------------------------------------------------------------------

const REF_PREFIX: [&str; 7] = ["aggregateIntentMaps", "ruleOf", "liftIntentMap", "crossOrgAggregate", "commonRefinement", "pca-intent", "refineOmega"];

fn norm_problem(p: &str) -> String {
    let mut q = p.to_string();
    while let Some(pos) = q.find("replay failed: ") {
        let rest = pos + "replay failed: ".len();
        let end = q[rest..].find(';').map(|e| rest + e).unwrap_or(q.len());
        q = format!("{}replay failed{}", &q[..pos], &q[end..]);
    }
    let is_ref = |t: &str| REF_PREFIX.iter().any(|r| t.starts_with(r));
    if let Some(rest) = q.strip_prefix("recompute failed: ") {
        return if is_ref(rest) { q.clone() } else { "recompute failed: error".to_string() };
    }
    if !(q.starts_with("input ") || q.starts_with("aggregate does not") || q.starts_with("recompute failed") || q.starts_with("replay failed")) {
        return if is_ref(&q) { q } else { "error".to_string() };
    }
    q
}

fn nrm(r: Value) -> Value {
    let ps: Vec<Value> = r["problems"].as_array().map(|a| a.iter().map(|p| json!(norm_problem(p.as_str().unwrap_or("")))).collect()).unwrap_or_default();
    json!({"ok": r["ok"], "problems": ps})
}

fn build_map(omega: &Value, mo: &Value, obs: &Value, rf: &Value) -> Result<Value, String> {
    let mut l = mk(omega, mo, obs)?;
    emit_intent_map(&mut l, rf.as_str())
}

fn mutations(agg: &Value) -> Vec<Value> {
    let mut out = vec![agg.clone()];
    let mut m = agg.clone();
    m["metrics"]["residual_risk_ppm"] = num(fnum(&agg["metrics"]["residual_risk_ppm"]).unwrap_or(0.0) + 7.0);
    out.push(m);
    let mut m = agg.clone();
    m["cells"][0]["in_grant"] = json!(m["cells"][0]["in_grant"] != json!(true));
    out.push(m);
    let mut m = agg.clone();
    m["aggregation"] = Value::Null;
    out.push(m);
    let mut m = agg.clone();
    m["aggregation"]["rule"] = json!("quorum");
    m["aggregation"]["k"] = json!(1);
    out.push(m);
    let mut m = agg.clone();
    m["aggregation"]["vetoers"] = json!([]);
    out.push(m);
    out
}

fn principal_maps(omega: &Value, principals: &Value, mo: &Value) -> Result<Vec<Value>, String> {
    let mut maps = vec![];
    for p in principals.as_array().ok_or("principals")? {
        maps.push(build_map(omega, mo, &p["observations"], &p["ref"])?);
    }
    Ok(maps)
}

fn multi_case(fname: &str, a: &[Value]) -> Result<Value, String> {
    let empty = json!({});
    match fname {
        "aggregateScenario" => {
            // the reference passes the orgs object as the options argument, so no org label is ever applied
            let opts = if a[3].is_null() { &empty } else { &a[3] };
            let mo = a.get(4).unwrap_or(&Value::Null);
            let maps = principal_maps(&a[0], &a[1], mo)?;
            let agg = aggregate_intent_maps(&maps, &a[2], Some(opts))?;
            let tampered: Vec<Value> = mutations(&agg).iter().map(|m| nrm(verify_aggregate(m, &maps, Some(opts)))).collect();
            let wrong = nrm(verify_aggregate(&agg, &maps[..maps.len() - 1], Some(opts)));
            let combined = if a[2]["kind"] == "unanimity" && a[2].get("vetoers").is_none() { combine_intent_maps(&maps, Some(opts))? } else { Value::Null };
            Ok(json!({"aggregate": agg, "digest": intent_map_digest(&agg)?, "rule": rule_of(&agg)?, "verify": nrm(verify_aggregate(&agg, &maps, Some(opts))),
                "tampered": tampered, "wrongInputs": wrong, "combined": combined}))
        }
        "aggregateTwoOmegas" => {
            let ps = a[2].as_array().ok_or("principals")?;
            let maps = vec![build_map(&a[0], &json!({}), &ps[0]["observations"], &ps[0]["ref"])?, build_map(&a[1], &json!({}), &json!([]), &ps[1]["ref"])?];
            aggregate_intent_maps(&maps, &a[3], None)
        }
        "aggregateOfAggregate" => {
            let maps = principal_maps(&a[0], &a[1], &json!({}))?;
            let agg = aggregate_intent_maps(&maps, &a[2], None)?;
            aggregate_intent_maps(&[agg, maps[0].clone()], &a[2], None)
        }
        "liftOfAggregate" => {
            let maps = principal_maps(&a[0], &a[1], &json!({}))?;
            lift_intent_map(&aggregate_intent_maps(&maps[..1], &a[2], None)?, &a[0])
        }
        "crossScenario" => {
            let specs = a[0].as_array().ok_or("specs")?;
            if a.len() == 2 {
                // the variant that corrupts the first map's metrics, which crossOrgAggregate must refuse
                let mut maps = vec![];
                for sp in specs {
                    maps.push(build_map(&sp["omega"], &json!({}), &sp["observations"], &sp["ref"])?);
                }
                maps[0]["metrics"]["residual_risk_ppm"] = num(fnum(&maps[0]["metrics"]["residual_risk_ppm"]).unwrap_or(0.0) + 9.0);
                return Ok(cross_org_aggregate(&maps, &a[1], None)?.aggregate);
            }
            let opts = if a[2].is_null() { &empty } else { &a[2] };
            let mut maps = vec![];
            for sp in specs {
                let mo = sp.get("mapOpts").filter(|m| !m.is_null()).cloned().unwrap_or_else(|| json!({}));
                maps.push(build_map(&sp["omega"], &mo, &sp["observations"], &sp["ref"])?);
            }
            let r = cross_org_aggregate(&maps, &a[1], Some(opts))?;
            let tampered: Vec<Value> = mutations(&r.aggregate).iter().map(|m| nrm(verify_cross_org_aggregate(m, &maps, Some(opts)))).collect();
            Ok(json!({"aggregate": r.aggregate, "lifted": r.lifted, "omega": r.omega, "digest": intent_map_digest(&r.aggregate)?,
                "verify": nrm(verify_cross_org_aggregate(&r.aggregate, &maps, Some(opts))), "tampered": tampered,
                "wrong": nrm(verify_cross_org_aggregate(&r.aggregate, &maps[1..], Some(opts)))}))
        }
        "liftScenario" => {
            let m = build_map(&a[0], &a[1], &a[2], &a[3])?;
            lift_intent_map(&m, &a[4])
        }
        "omegaKey" => Ok(Value::String(omega_key(&a[0])?)),
        other => panic!("unknown fn {other}"),
    }
}

#[test]
fn intent_multi_agg_matches_the_reference() {
    run("intent-multi-agg", true, &multi_case);
}

// ---- outcome ----------------------------------------------------------------------------------------------------------------

fn outcome_case(fname: &str, a: &[Value]) -> Result<Value, String> {
    match fname {
        "verifyScenario" => {
            let mut l = mk(&a[0], &a[1], &a[2])?;
            let result = verify_outcome(&mut l, &a[3], &a[4], a.get(5).filter(|p| !p.is_null()))?;
            Ok(json!({"result": result, "metrics": l.metrics().to_json()}))
        }
        "mcScenario" => {
            let mut l = mk(&a[0], &a[1], &a[2])?;
            Ok(num(estimate_residual_risk_mc(&mut l, f(&a[3])?, f(&a[4])?)?))
        }
        other => panic!("unknown fn {other}"),
    }
}

#[test]
fn intent_outcome_matches_the_reference() {
    run("intent-outcome", false, &outcome_case);
}

// ---- profile ----------------------------------------------------------------------------------------------------------------

fn profile_case(fname: &str, a: &[Value]) -> Result<Value, String> {
    match fname {
        "signIntentProfile" => sign_intent_profile(&a[0], s(&a[1])?),
        "intentProfileShapeError" => {
            let signed = !(a.get(1).is_some_and(|o| o.is_object() && o["signed"] == json!(false)));
            Ok(intent_profile_shape_error(&a[0], signed).map(Value::String).unwrap_or(Value::Null))
        }
        "verifyIntentProfile" => Ok(verify_intent_profile(&a[0], None)),
        "profileUsable" => Ok(profile_usable(&a[0], &a[1])),
        "intentProfileDigest" => Ok(Value::String(intent_profile_digest(&a[0])?)),
        "verifyProfileSuccession" => Ok(verify_profile_succession(&a[0], &a[1])),
        "profileApplies" => Ok(json!(profile_applies(&a[0], &a[1]))),
        "standingAdmits" => Ok(json!(standing_admits(&a[0], &a[1], &a[2]))),
        "standingPermits" => Ok(json!(standing_permits(&a[0], &a[1], &a[2]))),
        "profileVetoCells" => profile_veto_cells(&a[0], &Omega::parse(&a[1])?),
        "profileCeiling" => Ok(json!(profile_ceiling(&a[0], &a[1], &Vs::parse(&a[2])?, &a[3])?)),
        other => panic!("unknown fn {other}"),
    }
}

#[test]
fn intent_profile_matches_the_reference() {
    run("intent-profile", false, &profile_case);
}

// ---- provenance -------------------------------------------------------------------------------------------------------------

fn amt(x: &Value) -> f64 {
    fnum(&x["values"]["action.params.amount"]).unwrap_or(0.0)
}

fn admits_by(name: &str) -> Box<dyn Fn(&Value) -> bool> {
    match name {
        "all" => Box::new(|_| true),
        "none" => Box::new(|_| false),
        "amountLe50" => Box::new(|x| amt(x) <= 50.0),
        "verbRefund" => Box::new(|x| x["verb"] == "stripe.refund"),
        other => panic!("unknown admits {other}"),
    }
}

fn utility_by(name: &str) -> Box<dyn Fn(&Value) -> f64> {
    match name {
        "amount" => Box::new(amt),
        "negAmount" => Box::new(|x| -amt(x)),
        "zero" => Box::new(|_| 0.0),
        "nan" => Box::new(|_| f64::NAN),
        "amountPlusPrefer" => Box::new(|x| amt(x) + if x["values"]["action.params.recipient"] == "bob" { 1000.0 } else { 0.0 }),
        other => panic!("unknown utility {other}"),
    }
}

type Bound = (Box<dyn Fn(&Value) -> bool>, Box<dyn Fn(&Value) -> f64>);

fn provenance_case(fname: &str, a: &[Value]) -> Result<Value, String> {
    match fname {
        "provenanceBanner" => Ok(provenance_banner(&a[0], a.get(1).and_then(Value::as_str)).map(Value::String).unwrap_or(Value::Null)),
        "isTainted" => Ok(json!(is_tainted(&a[0]))),
        "provenanceFriction" => Ok(provenance_friction(&a[0], &a[1], &a[2]).map(Value::String).unwrap_or(Value::Null)),
        "regret" => {
            let (adm, util) = (admits_by(s(&a[0]["admits"])?), utility_by(s(&a[0]["utility"])?));
            let feasible = a[0]["feasible"].as_array().ok_or("feasible")?;
            Ok(regret_json(&RegretCase { feasible, chosen: &a[0]["chosen"], admits: &*adm, utility: &*util }))
        }
        "report" => {
            let list = a[0].as_array().ok_or("cases")?;
            let bound: Vec<Bound> = list
                .iter()
                .map(|c| -> Result<Bound, String> { Ok((admits_by(s(&c["admits"])?), utility_by(s(&c["utility"])?))) })
                .collect::<Result<Vec<Bound>, String>>()?;
            let cases: Vec<RegretCase> = list
                .iter()
                .zip(bound.iter())
                .map(|(c, (ad, ut))| RegretCase {
                    feasible: c["feasible"].as_array().map(|v| v.as_slice()).unwrap_or(&[]),
                    chosen: &c["chosen"],
                    admits: &**ad,
                    utility: &**ut,
                })
                .collect();
            Ok(regret_report(&cases, a.get(1).and_then(fnum)))
        }
        other => panic!("unknown fn {other}"),
    }
}

#[test]
fn intent_provenance_matches_the_reference() {
    run("intent-provenance", false, &provenance_case);
}

// ---- ramp -------------------------------------------------------------------------------------------------------------------

fn ramp_case(fname: &str, a: &[Value]) -> Result<Value, String> {
    match fname {
        "signObservation" => sign_intent_observation(&a[0], s(&a[1])?),
        "verifyObservation" => Ok(verify_intent_observation(&a[0], a.get(1).unwrap_or(&Value::Null))),
        "rampScenario" => {
            let mut ramp = TrustRamp::new(mk(&a[0], &a[1], &a[2])?, &a[3])?;
            let mut out: Vec<Value> = vec![];
            // the reference's `state` hands out its live pending array, so every state taken before the array is replaced (by a rebase)
            // reads the array's content at the end of that stretch
            let mut live: Vec<usize> = vec![];
            let settle = |out: &mut Vec<Value>, live: &mut Vec<usize>, pending: Value| {
                for i in live.drain(..) {
                    out[i]["pending"] = pending.clone();
                }
            };
            for op in a[4].as_array().ok_or("ops")? {
                match op["op"].as_str() {
                    Some("record") => out.push(ramp.record(&op["outcome"], s(&op["signal"])?)?),
                    Some("observe") => out.push(ramp.record_observation(&op["obs"], &op["ctx"])?),
                    Some("rebase") => {
                        settle(&mut out, &mut live, json!(ramp.pending()));
                        ramp.rebase(mk(&op["omega"], &op["mapOpts"], &op["observations"])?);
                        out.push(json!({"frozen": ramp.frozen(), "pending": ramp.pending().len()}));
                    }
                    _ => {
                        live.push(out.len());
                        out.push(json!({"frozen": ramp.frozen(), "pending": ramp.pending(), "drift": ramp.drift.state().to_json()}));
                    }
                }
            }
            settle(&mut out, &mut live, json!(ramp.pending()));
            let metrics = ramp.l.metrics().to_json();
            Ok(json!([out, {"log": ramp.log(), "frozen": ramp.frozen(), "pending": ramp.pending(), "metrics": metrics}]))
        }
        other => panic!("unknown fn {other}"),
    }
}

#[test]
fn intent_ramp_matches_the_reference() {
    run("intent-ramp", false, &ramp_case);
}

// ---- refine -----------------------------------------------------------------------------------------------------------------

fn refine_case(fname: &str, a: &[Value]) -> Result<Value, String> {
    match fname {
        "refineOmega" => refine_omega(&a[0], &a[1]),
        "regionsOf" => {
            let l = mk(&a[0], &a[1], &a[2])?;
            let om = if a[3] == json!(true) {
                let mut o = a[0].clone();
                o["verbs"] = json!([]);
                o
            } else {
                l.omega.clone()
            };
            let mut out = vec![];
            for x in &l.observations {
                out.push(region_of_observation(&om, x)?);
            }
            Ok(Value::Array(out))
        }
        "refineScenario" => {
            let mut l = mk(&a[0], &a[1], &a[2])?;
            let mut nl = refine_learner(&mut l, &a[3], None)?;
            let metrics = nl.metrics().to_json();
            Ok(json!({"omega": nl.omega, "observations": nl.observations, "metrics": metrics, "cells": cells_of(&mut nl)}))
        }
        "partialScenario" => {
            let mut l = mk(&a[0], &a[1], &a[2])?;
            let q = &a[3];
            let om = Omega::parse(&a[0])?;
            let cell = idx(&q["cell"])?;
            let verb = s(&q["verb"])?.to_string();
            let (outcome, p) = match om.vs_of(&verb) {
                None => (json!({"verb": verb, "values": {}}), 0.5),
                Some(svs) => {
                    let oc = svs.cell_rep(&cell)?;
                    let p = l.acceptance(&oc);
                    (oc, p)
                }
            };
            let (mut nl, added) = answer_partial(&mut l, &Question { verb, cell, outcome, p, score: 0.0 }, &a[4])?;
            let metrics = nl.metrics().to_json();
            let synth = nl.synthesize()?;
            Ok(json!({"omega": nl.omega, "added": added, "observations": nl.observations, "metrics": metrics, "synth": synth}))
        }
        "adaptiveScenario" => {
            let adm = Admitter::new(&a[2])?;
            let partials = a[3].as_array().ok_or("partials")?.clone();
            let every = f(&a[4])? as i64;
            let (mut k, mut pi) = (0i64, 0usize);
            let mut answer = |q: &Question, l: &Learner| -> Result<Value, String> {
                k += 1;
                if every != 0 && k % every == 0 && pi < partials.len() && q.verb == "stripe.refund" {
                    pi += 1;
                    return Ok(partials[pi - 1].clone());
                }
                let vs = l.omega_t.vs_of(&q.verb).ok_or("no such verb")?;
                Ok(json!(if adm.admits(vs.reversibility.as_deref(), &q.outcome)? { 1 } else { 0 }))
            };
            let mut opts = json!({"epsRisk": 0.001, "epsBurden": 0.01, "maxQuestions": 25});
            for (key, v) in a[5].as_object().cloned().unwrap_or_default() {
                opts[key] = v;
            }
            let mut r = elicit_adaptive(create_learner(&a[0], &a[1])?, &mut answer, &opts)?;
            let metrics = r.learner.metrics().to_json();
            let asked: Vec<Value> = r.asked.iter().map(|q| q.to_json()).collect();
            Ok(
                json!({"stop": r.stop, "questions": r.questions, "auditQuestions": r.audit_questions, "seedQuestions": r.seed_questions, "refinements": r.refinements,
                "asked": asked, "omega": r.learner.omega, "metrics": metrics, "observations": r.learner.observations}),
            )
        }
        other => panic!("unknown fn {other}"),
    }
}

#[test]
fn intent_refine_matches_the_reference() {
    run("intent-refine", true, &refine_case);
}

#[allow(dead_code)]
fn _unused(_: Map<String, Value>) {}
