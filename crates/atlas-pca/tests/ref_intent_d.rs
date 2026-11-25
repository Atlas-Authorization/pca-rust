//! Differential replay of intent part 4 (the runtime half of `@atlasauth/pca-intent`) against the TypeScript reference:
//! test-data/ref-intent-routing (bond sizing, judge verdicts, split-conformal calibration, the k-of-n threshold, routing by the
//! learner's posterior, the IC-Att, just-in-time consent), -runtime (runtime digests, effect postconditions, trust-ramp parts,
//! question cards), -map (Intent Map emission, verification, digests, the committed form, divergence) and the part of -misc that
//! tests/ref_intent_c.rs does not replay (compilers, provenance and regret, classifier, frames, jit coordinates).
//! A reference throw requires a refusal. Pure functions (bond, verdicts, calibration, threshold) compare doubles exactly; the
//! learner-bound scenarios compare non-integral doubles to 1e-12 relative (the posterior's transcendental functions).
//! A verification problem is compared by its reference prefix ("replay failed: ..." is "replay failed"); a host-runtime text of
//! checkFrame is compared as "error: error".
//! Skipped: nothing in routing / runtime / map. In misc, the statement / schema / trajectory functions are replayed by
//! tests/ref_intent_c.rs (COVERED_BY_C below, asserted to be exactly the functions this file leaves out).
mod common;
use atlas_pca::intent_kit::classifier::*;
use atlas_pca::intent_kit::compilers::*;
use atlas_pca::intent_kit::frames::{check_frame, snapshot_state, state_digest, write_set_of};
use atlas_pca::intent_kit::jit::*;
use atlas_pca::intent_kit::jn;
use atlas_pca::intent_kit::omega::VerbSpace;
use atlas_pca::intent_kit2::learner::Learner;
use atlas_pca::intent_kit2::mapkit::*;
use atlas_pca::intent_kit2::omega::Vs;
use atlas_pca::intent_kit2::outcome::*;
use atlas_pca::intent_kit2::provenance::*;
use atlas_pca::intent_kit2::ramp::*;
use atlas_pca::intent_kit2::util::{fnum, num};
use atlas_pca::intent_kit4::commit::commit_intent_map;
use atlas_pca::intent_kit4::routing::*;
use atlas_pca::intent_kit4::semantic::*;
use atlas_pca::intent_kit4::ux::*;
use atlas_pca::serde_json::{json, Map, Value};

type R<T> = Result<T, String>;

const COVERED_BY_C: [&str; 12] = [
    "signIntent",
    "verifyIntent",
    "intentRef",
    "deriveOmegaFromSchema",
    "canonValue",
    "dimKindOf",
    "describeAccCell",
    "trajectoryHarmRange",
    "defaultAccumulators",
    "augmentOmega",
    "liftAction",
    "stepTrajectory",
];

fn is_covered_by_c(f: &str) -> bool {
    COVERED_BY_C.contains(&f)
}

// ---- comparison ---------------------------------------------------------------------------------------------------------------

fn dbl(v: &Value) -> f64 {
    match v {
        Value::Object(m) if m.contains_key("$num") => match m["$num"].as_str().unwrap_or("") {
            "Infinity" => f64::INFINITY,
            "-Infinity" => f64::NEG_INFINITY,
            _ => f64::NAN,
        },
        _ => v.as_f64().unwrap_or(f64::NAN),
    }
}

/// JSON equality with numbers compared as doubles (the reference prints 1 and 1.0 alike); `close` allows 1e-12 relative on
/// non-integral doubles.
fn same(got: &Value, want: &Value, close: bool) -> bool {
    if want.as_object().is_some_and(|m| m.contains_key("$num")) {
        let (g, w) = (dbl(got), dbl(want));
        return (g.is_nan() && w.is_nan()) || g == w;
    }
    match (got, want) {
        (Value::Number(a), Value::Number(b)) => {
            let (x, y) = (a.as_f64().unwrap_or(f64::NAN), b.as_f64().unwrap_or(f64::NAN));
            x == y || (close && x.fract() != 0.0 && y.fract() != 0.0 && (x - y).abs() <= (1e-12 * x.abs().max(y.abs())).max(1e-15))
        }
        (Value::Array(a), Value::Array(b)) => a.len() == b.len() && a.iter().zip(b).all(|(x, y)| same(x, y, close)),
        (Value::Object(a), Value::Object(b)) => a.len() == b.len() && b.iter().all(|(k, y)| a.get(k).is_some_and(|x| same(x, y, close))),
        _ => got == want,
    }
}

fn a(args: &[Value], i: usize) -> &Value {
    static NULL: Value = Value::Null;
    args.get(i).unwrap_or(&NULL)
}

fn f(v: &Value) -> R<f64> {
    v.as_f64().ok_or_else(|| format!("expected a number, got {v}"))
}

fn s(v: &Value) -> R<&str> {
    v.as_str().ok_or_else(|| format!("expected a string, got {v}"))
}

fn has_lone(c: &Value) -> bool {
    common::has_lone(c)
}

fn replay(pkg: &str, pure: fn(&str) -> bool, norm: fn(Value) -> Value, run: &dyn Fn(&str, &[Value]) -> Option<R<Value>>) {
    let cases = common::ref_cases_seeded(pkg);
    let (mut skipped, mut bad): (Vec<String>, Vec<String>) = (vec![], vec![]);
    for c in &cases {
        let name = c["name"].as_str().unwrap_or("?").to_string();
        let fname = c["fn"].as_str().unwrap_or("?");
        if has_lone(c) {
            skipped.push(format!("lone-surrogate:{fname}"));
            continue;
        }
        let args = c["args"].as_array().cloned().unwrap_or_default();
        let got = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(fname, &args))) {
            Ok(Some(g)) => g,
            Ok(None) => {
                skipped.push(fname.to_string());
                continue;
            }
            Err(_) => Err("panic".to_string()),
        };
        let want = &c["out"];
        let ok =
            if want.get("$throws").is_some() { got.is_err() } else { got.as_ref().is_ok_and(|g| same(&norm(g.clone()), &norm(want.clone()), !pure(fname))) };
        if !ok {
            let shown = match &got {
                Ok(v) => v.to_string(),
                Err(e) => format!("Err({e})"),
            };
            bad.push(format!("{name}: want {} got {}", want.to_string().chars().take(300).collect::<String>(), shown.chars().take(300).collect::<String>()));
        }
    }
    assert!(bad.is_empty(), "{pkg}: {} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
    let stray: Vec<&String> = skipped.iter().filter(|x| !is_covered_by_c(x) && !x.starts_with("lone-surrogate:")).collect();
    assert!(stray.is_empty(), "{pkg}: functions with no replay: {stray:?}");
    assert!(skipped.len() * 100 <= cases.len() * 55, "{pkg}: {} of {} cases skipped", skipped.len(), cases.len());
}

fn ident(v: Value) -> Value {
    v
}

// ---- learner ------------------------------------------------------------------------------------------------------------------

fn mk(omega: &Value, mo: &Value, obs: &Value) -> R<Learner> {
    let mut l = create_learner(omega, mo)?;
    for x in obs.as_array().ok_or("observations must be a list")? {
        l.observe(&json!({"verb": x["verb"], "values": x["values"]}), f(&x["y"])?, s(&x["source"])?, x.get("region").filter(|r| !r.is_null()))?;
    }
    Ok(l)
}

// ---- routing ------------------------------------------------------------------------------------------------------------------

fn inf(x: f64) -> Value {
    if x.is_finite() {
        num(x)
    } else {
        json!("inf")
    }
}

fn routing_pure(fname: &str) -> bool {
    !matches!(fname, "routeScenario" | "routeVetoScenario" | "conformanceScenario" | "jitScenario")
}

fn conformance(a: &[Value]) -> R<Value> {
    let mut l = mk(&a[0], &a[1], &a[2])?;
    let (oc, ctx, verdicts, copts) = (&a[3], &a[4], &a[5], &a[6]);
    let input = judge_input_of_learner(&mut l, oc, ctx)?;
    let att = intent_conformance_attestation(&input, verdicts, copts)?;
    let mut tampered = vec![];
    for i in 0..6 {
        let mut c = att.clone();
        match i {
            1 => c["ok"] = json!(c["ok"] != json!(true)),
            2 => c["aggregate_score_ppm"] = num(fnum(&c["aggregate_score_ppm"]).unwrap_or(f64::NAN) + 1.0),
            3 => {
                if let Some(d) = c["verdict_digests"].as_array_mut() {
                    d.pop();
                }
            }
            4 => c["k"] = num(fnum(&c["k"]).unwrap_or(f64::NAN) + 1.0),
            5 => c["reason"] = json!("x"),
            _ => {}
        }
        tampered.push(verify_ic_att(&c, &input, verdicts, copts)?);
    }
    let rest = Value::Array(verdicts.as_array().ok_or("verdicts")?.iter().skip(1).cloned().collect());
    tampered.push(verify_ic_att(&att, &input, &rest, copts)?);
    let check = check_intent_conformance(&|_| Ok(verdicts.clone()), &input, copts)?;
    Ok(
        json!({"input": input, "att": att, "digest": ic_att_digest(&att)?, "verify": verify_ic_att(&att, &input, verdicts, copts)?, "tampered": tampered, "check": check}),
    )
}

fn run_routing(fname: &str, a: &[Value]) -> Option<R<Value>> {
    Some(match fname {
        "bondAmount" => f(&a[1]).and_then(|e| bond_amount(&a[0], e)).map(num),
        "quantizeScore" => f(&a[0]).map(|x| num(quantize_score(x))),
        "verifyJudgeVerdict" => Ok(Value::Bool(verify_judge_verdict(&a[0], &a[1], self::a(a, 2)))),
        "conformalThreshold" => Ok(inf(conformal_threshold(&a[0]))),
        "empiricalFalseAllowRate" => f(&a[1]).map(|c| num(empirical_false_allow_rate(&a[0], c))),
        "verifySemanticThreshold" => {
            let t = verify_semantic_threshold(&a[0], &a[1]);
            let mut j = t.to_json();
            if let Some(c) = t.cutoff {
                j["cutoff"] = inf(c);
            }
            Ok(j)
        }
        "routeScenario" => (|| -> R<Value> {
            let mut l = mk(&a[0], &a[1], &a[2])?;
            let mut out = vec![];
            for o in a[3].as_array().ok_or("outcomes")? {
                out.push(route_action(&mut l, o, &a[4])?);
            }
            Ok(Value::Array(out))
        })(),
        "routeVetoScenario" => (|| -> R<Value> {
            let mut l = mk(&a[0], &a[1], &a[2])?;
            let outs = a[3].as_array().ok_or("outcomes")?;
            for o in outs {
                l.observe(o, 0.0, "runtime", None)?;
            }
            let mut out = vec![];
            for o in outs {
                out.push(route_action(&mut l, o, &a[4])?);
            }
            Ok(Value::Array(out))
        })(),
        "conformanceScenario" => conformance(a),
        "jitScenario" => (|| -> R<Value> {
            let mut l = mk(&a[0], &a[1], &a[2])?;
            let (oc, ctx) = (&a[3], &a[5]);
            let req = jit_consent_request_learner(&mut l, oc, &json!({"intentRef": ctx["intentRef"], "mapDigest": ctx["mapDigest"]}))?;
            let digest = jit_consent_digest(&req)?;
            let result = record_jit_decision(&mut l, &req, s(&a[4])?)?;
            let metrics = l.metrics().to_json();
            let route = route_action(&mut l, oc, &json!({}))?;
            Ok(json!({"req": req, "digest": digest, "result": result, "metrics": metrics, "route": route}))
        })(),
        _ => return None,
    })
}

#[test]
fn intent_routing() {
    replay("intent-routing", routing_pure, ident, &run_routing);
}

// ---- runtime ------------------------------------------------------------------------------------------------------------------

fn verb_space<'a>(omega: &'a Value, o: &Value) -> R<&'a Value> {
    omega["verbs"].as_array().and_then(|v| v.iter().find(|x| x["verb"] == o["verb"])).ok_or_else(|| format!("no verb {} in Ω", o["verb"]))
}

fn runtime_pure(fname: &str) -> bool {
    !matches!(fname, "narrowStart" | "driftRun" | "checkPostconditions" | "effectContext")
}

fn run_runtime(fname: &str, a: &[Value]) -> Option<R<Value>> {
    Some(match fname {
        "pcactnActionOf" => pcactn_action_of(&a[0], &a[1]),
        "judgeInputOf" => verb_space(&a[0], &a[1]).and_then(|vs| judge_input_of(vs, &a[1], f(&a[2])?, &a[3])),
        "jitConsentRequest" => verb_space(&a[0], &a[1]).and_then(|vs| jit_consent_request(vs, &a[1], f(&a[2])?, &a[3])),
        "jitConsentDigest" => jit_consent_digest(&a[0]).map(Value::String),
        "calibrationDigest" => calibration_digest(&a[0]).map(Value::String),
        "icAttDigest" => ic_att_digest(&a[0]).map(Value::String),
        "foldSemanticRisk" => f(&a[0]).map(|r| num(fold_semantic_risk(r, &a[1]))),
        "defaultPostconditions" => Ok(Value::Array(default_postconditions())),
        "effectContext" => effect_context(a[0]["reversibility"].as_str(), &a[1], &a[2]),
        "checkPostconditions" => Vs::parse(&a[0]).and_then(|vs| check_postconditions(&vs, &a[1], &a[2], a.get(3))),
        "signalLabel" => s(&a[0]).map(|x| num(signal_label(x))),
        "narrowStart" => narrow_start(&a[0], &a[1], Some(&a[2])),
        "driftRun" => (|| -> R<Value> {
            let mut d = DriftDetector::new(&a[0])?;
            let mut out = vec![];
            for x in a[1].as_array().ok_or("seq")? {
                out.push(d.update(x.as_bool().ok_or("diverged flag")?).to_json());
            }
            out.push(d.state().to_json());
            d.reset();
            out.push(d.state().to_json());
            Ok(Value::Array(out))
        })(),
        "questionCard" => question_card(&a[0], &a[1]),
        "parseCardAnswer" => parse_card_answer(&a[0], &a[1]),
        _ => return None,
    })
}

#[test]
fn intent_runtime() {
    replay("intent-runtime", runtime_pure, ident, &run_runtime);
}

// ---- map ----------------------------------------------------------------------------------------------------------------------

fn secret_of(seed: u64) -> Vec<u8> {
    (0..32u64).map(|i| ((seed + 7 * i) & 255) as u8).collect()
}

/// The oracle compares a verification problem by its prefix ("replay failed: ..." is "replay failed").
fn norm_problems(v: &Value) -> Value {
    let ps: Vec<Value> = v["problems"]
        .as_array()
        .map(|p| p.iter().map(|x| if x.as_str().is_some_and(|t| t.starts_with("replay failed")) { json!("replay failed") } else { x.clone() }).collect())
        .unwrap_or_default();
    json!({"ok": v["ok"], "problems": ps})
}

fn norm_map(v: Value) -> Value {
    if v.get("tampered").is_none() {
        return v;
    }
    let mut v = v;
    v["verify"] = norm_problems(&v["verify"]);
    if let Some(t) = v["tampered"].as_array_mut() {
        for x in t.iter_mut() {
            *x = norm_problems(x);
        }
    }
    v
}

fn at_mut<'a>(m: &'a mut Value, k: &str) -> &'a mut Value {
    match k.parse::<usize>() {
        Ok(i) => &mut m[i],
        Err(_) => &mut m[k],
    }
}

fn bump(m: &mut Value, path: &[&str], by: f64) {
    let mut cur = m;
    for k in path {
        cur = at_mut(cur, k);
    }
    *cur = num(fnum(cur).unwrap_or(f64::NAN) + by);
}

fn disclosures(omega: &Value, cm: &atlas_pca::intent_kit4::commit::Committed) -> R<Vec<Value>> {
    let mut out = vec![];
    for v in omega["verbs"].as_array().ok_or("omega.verbs")? {
        let vs = Vs::parse(v)?;
        let t = vs.cell_count();
        for fl in [0, t / 2, t - 1] {
            let oc = vs.cell_rep(&vs.decode_cell(fl as f64))?;
            let mut params = Map::new();
            let mut resource: Option<Value> = None;
            for (k, x) in oc["values"].as_object().ok_or("values")? {
                if k == "action.resource" {
                    resource = Some(x.clone());
                } else {
                    params.insert(k.chars().skip(14).collect(), x.clone());
                }
            }
            out.push(cm.disclose(&vs.verb, resource.as_ref(), &params)?);
        }
    }
    Ok(out)
}

fn map_scenario(a: &[Value]) -> R<Value> {
    let (omega, mo, obs) = (&a[0], &a[1], &a[2]);
    let mut l = create_learner(omega, mo)?;
    for x in obs.as_array().ok_or("observations must be a list")? {
        l.observe(&json!({"verb": x["verb"], "values": x["values"]}), f(&x["y"])?, s(&x["source"])?, x.get("region").filter(|r| !r.is_null()))?;
    }
    let map = emit_intent_map(&mut l, a[3].as_str())?;
    let muts: Vec<Box<dyn Fn(&mut Value)>> = vec![
        Box::new(|_| {}),
        Box::new(|m| bump(m, &["metrics", "residual_risk_ppm"], 5.0)),
        Box::new(|m| bump(m, &["cells", "0", "p_ppm"], 3.0)),
        Box::new(|m| m["cells"][0]["in_grant"] = json!(m["cells"][0]["in_grant"] != json!(true))),
        Box::new(|m| m["grant_digest"] = json!("AAAA")),
        Box::new(|m| {
            m["observations"].as_array_mut().expect("observations").pop();
        }),
        Box::new(|m| m["kind"] = json!("x")),
        Box::new(|m| m["principals"] = json!(["a", "b"])),
        Box::new(|m| m["aggregation"] = json!({"rule": "unanimity"})),
        Box::new(|m| {
            m["metrics"].as_object_mut().expect("metrics").remove("log2_vs_mbits");
        }),
        Box::new(|m| bump(m, &["learner", "eta_ppm"], 100000.0)),
        Box::new(|m| bump(m, &["metrics", "questions"], 1.0)),
        Box::new(|m| {
            m["cells"].as_array_mut().expect("cells").pop();
        }),
        Box::new(|m| m["omega"]["verbs"][0]["w"] = json!(5)),
        Box::new(|m| m["metrics"]["log2_vs_mbits"] = Value::Null),
        Box::new(|m| bump(m, &["cells", "0", "p_ppm"], 2.0)),
        Box::new(|m| bump(m, &["cells", "0", "p_ppm"], 1.0)),
    ];
    let mut tampered: Vec<Value> = vec![];
    for m in &muts {
        let mut c = map.clone();
        m(&mut c);
        tampered.push(norm_problems(&verify_intent_map(&c)));
    }
    tampered.push(norm_problems(&verify_intent_map(&Value::Null)));
    tampered.push(norm_problems(&verify_intent_map(&json!({"v": 2}))));
    let commit = match commit_intent_map(&map, &secret_of(a[4].as_u64().ok_or("secretSeed")?)).and_then(|cm| disclosures(omega, &cm).map(|d| (cm, d))) {
        Ok((cm, d)) => json!({"map_commit": cm.map_commit, "size": cm.size, "leaves": cm.to_json()["leaves"], "disclosures": d}),
        Err(_) => json!({"error": true}),
    };
    Ok(json!({"map": map, "digest": intent_map_digest(&map)?, "grantDigest": grant_digest(&map["grant"])?, "verify": norm_problems(&verify_intent_map(&map)),
        "tampered": tampered, "options": map_learner_options(&map)?, "omegaRoundtrip": omega_to_json(&omega_from_json(&map["omega"])?)?, "commit": commit}))
}

fn run_map(fname: &str, a: &[Value]) -> Option<R<Value>> {
    Some(match fname {
        "mapScenario" => map_scenario(a),
        "commitIntentMap" => commit_intent_map(&a[0], &secret_of(3)).map(|cm| {
            let j = cm.to_json();
            json!({"map_commit": j["map_commit"], "size": j["size"], "leaves": j["leaves"]})
        }),
        "grantDigest" => grant_digest(&a[0]).map(Value::String),
        "intentMapDigest" => intent_map_digest(&a[0]).map(Value::String),
        "omegaToJSON" => omega_to_json(&a[0]),
        "omegaFromJSON" => omega_from_json(&a[0]),
        "divergence" => (|| -> R<Value> {
            let mut l = mk(&a[0], &a[1], &a[2])?;
            let mut out = vec![];
            for d in a[3].as_array().ok_or("divergences")? {
                out.push(apply_divergence(&mut l, &d["outcome"], f(&d["y"])?)?);
            }
            Ok(Value::Array(out))
        })(),
        _ => return None,
    })
}

#[test]
fn intent_map() {
    replay("intent-map", |_| false, norm_map, &run_map);
}

// ---- misc (what tests/ref_intent_c.rs does not replay) ----------------------------------------------------------------------

/// The reference's host-runtime error texts of checkFrame are compared as "error: error".
fn norm_frame(mut r: Value) -> Value {
    if let Some(ms) = r.get_mut("missing").and_then(Value::as_array_mut) {
        for m in ms {
            if m.as_str().is_some_and(|t| t.starts_with("error: ") && !t.starts_with("error: spec, action")) {
                *m = json!("error: error");
            }
        }
    }
    r
}

fn misc_pure(_: &str) -> bool {
    false
}

fn amt_ok(x: &Value) -> bool {
    fnum(&x["values"]["ok"]) == Some(1.0)
}

fn amt_u(x: &Value) -> f64 {
    fnum(&x["values"]["u"]).unwrap_or(f64::NAN)
}

fn run_misc(fname: &str, a: &[Value]) -> Option<R<Value>> {
    Some(match fname {
        "parseSlotsJSON" => s(&a[0]).map(parse_slots_json),
        "slotsPrompt" => s(&a[0]).map(|t| Value::String(slots_prompt(t))),
        "runCompilers" => a[1]
            .as_array()
            .ok_or_else(|| "specs must be an array".to_string())
            .and_then(|l| l.iter().map(IntentCompiler::from_spec).collect::<R<Vec<_>>>())
            .map(|c| run_compilers(&a[0], &c)),
        "analyzeDisagreement" => analyze_disagreement(&a[0], &a[1]),
        "panelFlags" => Ok(Value::Bool(panel_flags(&a[0]))),
        "committeeAnchors" => committee_anchors(&a[0], &a[1]),
        "provenanceBanner" => Ok(provenance_banner(&a[0], a.get(1).and_then(Value::as_str)).map_or(Value::Null, Value::String)),
        "provenanceFriction" => Ok(provenance_friction(&a[0], &a[1], &a[2]).map_or(Value::Null, Value::String)),
        "regretReport" => (|| -> R<Value> {
            let list = a[0].as_array().ok_or("cases")?;
            let cases: Vec<RegretCase> = list
                .iter()
                .map(|c| RegretCase {
                    feasible: c["feasible"].as_array().map(|v| v.as_slice()).unwrap_or(&[]),
                    chosen: &c["chosen"],
                    admits: &amt_ok,
                    utility: &amt_u,
                })
                .collect();
            Ok(regret_report(&cases, a.get(1).and_then(fnum)))
        })(),
        "calibrateConfusion" => calibrate_confusion(&a[0], &a[1], a.get(2).and_then(Value::as_f64).unwrap_or(0.05)),
        "confusionDigest" => confusion_digest(&a[0]).map(Value::String),
        "publishedErrorRate" => published_error_rate(&a[0]).map(jn),
        "classifierCardNote" => s(&a[0]).and_then(|x| classifier_card_note(x, &a[1])).map(Value::String),
        "classifierRisk" => classifier_risk(&a[0]).map(jn),
        "labelSound" => label_sound(&a[0]).map(Value::Bool),
        "labelSoundBound" => f(&a[1]).and_then(|h| label_sound_bound(&a[0], h)).map(jn),
        "stateDigest" => Ok(Value::String(state_digest(&a[0]))),
        "snapshotState" => snapshot_state(&a[0], a.get(1).is_none_or(|k| !matches!(k, Value::Null | Value::Bool(false)))),
        "writeSetOf" => write_set_of(&a[0], &a[1]).map(|w| json!(w)),
        "checkFrame" => Ok(if a.len() == 1 {
            check_frame(&a[0], &json!({"verb": "v", "resource": "r"}), &json!({}), &json!({}), &Value::Null)
        } else {
            check_frame(&a[0], &a[1], &a[2], &a[3], self::a(a, 4))
        }),
        "cellCoords" => VerbSpace::from_json(&a[0]).and_then(|vs| {
            let cell: Vec<usize> = a[1].as_array().ok_or("cell")?.iter().map(|c| c.as_u64().unwrap_or(u64::MAX) as usize).collect();
            cell_coords(&vs, &cell)
        }),
        "cellFromCoords" => VerbSpace::from_json(&a[0]).map(|vs| match cell_from_coords(&vs, &a[1]) {
            Some(c) => Value::Array(c.into_iter().map(jn).collect()),
            None => Value::Null,
        }),
        "intentRequiredBody" => intent_required_body(&a[0]),
        _ => return None,
    })
}

#[test]
fn intent_misc() {
    fn both(v: Value) -> Value {
        norm_frame(v)
    }
    replay("intent-misc", misc_pure, both, &run_misc);
}
