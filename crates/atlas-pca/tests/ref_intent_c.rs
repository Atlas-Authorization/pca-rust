//! Differential replay of intent part 3 (deterministic rendering and witnesses, the schema-derived outcome space, world dimensions,
//! trajectory accumulators, exact binomial statistics, the signed intent statement) against the TypeScript reference
//! (test-data/ref-intent-{render,schema,world,trajectory,statement,stats,misc}.json.gz). A reference throw requires a refusal.
//!
//! Skipped (counted per corpus): the `misc` functions of compilers / classifier / frames / provenance / regret / jit / cell coordinate
//! helpers (other parts own them). NOT ported in this part, so not replayed: the routing and runtime corpora (routeScenario,
//! conformanceScenario, jitScenario, driftRun, questionCard, ... sit on the learner / map / ramp / ux engines of the other parts)
//! and the intent-map corpus (mapScenario needs the learner).
mod common;
use atlas_pca::intent_kit3::num_json;
use atlas_pca::intent_kit3::render::*;
use atlas_pca::intent_kit3::schema::*;
use atlas_pca::intent_kit3::statement::*;
use atlas_pca::intent_kit3::trajectory::*;
use atlas_pca::intent_kit3::world::*;
use atlas_pca::serde_json::{json, Value};

fn f(v: &Value) -> f64 {
    match v {
        Value::Object(m) if m.contains_key("$num") => match m["$num"].as_str().unwrap_or("") {
            "NaN" => f64::NAN,
            "Infinity" => f64::INFINITY,
            "-Infinity" => f64::NEG_INFINITY,
            _ => f64::NAN,
        },
        _ => v.as_f64().unwrap_or(f64::NAN),
    }
}

fn big_of(v: &Value) -> String {
    v["$bigint"].as_str().expect("bigint").to_string()
}

fn bigv(x: impl ToString) -> Value {
    json!({ "$bigint": x.to_string() })
}

const STATS_DIAGNOSTIC: [&str; 7] = ["binomialCdf", "hoeffdingHalfWidth", "wilsonInterval", "lnGamma", "betacf", "betaInc", "betaQuantile"];

/// JSON equality with numbers compared as doubles (the reference prints 1 and 1.0 alike) and `{"$num": ...}` as non-finite doubles.
/// With `tol` a relative 1e-12 holds on non-integers (the platform's libm in a reported statistic); without it the doubles are equal.
fn same(got: &Value, want: &Value, tol: bool) -> bool {
    if let Some(m) = want.as_object() {
        if m.contains_key("$num") {
            let (g, w) = (f(got), f(want));
            return (g.is_nan() && w.is_nan()) || g == w;
        }
    }
    match (got, want) {
        (Value::Number(a), Value::Number(b)) => {
            // the platform's libm (log, exp, pow) may differ in the last digits: a relative 1e-12 (lead ruling); integers stay exact
            let (x, y) = (a.as_f64().unwrap_or(f64::NAN), b.as_f64().unwrap_or(f64::NAN));
            x == y || (tol && !(a.is_i64() && b.is_i64()) && (x - y).abs() <= 1e-12 * x.abs().max(y.abs()))
        }
        (Value::Array(a), Value::Array(b)) => a.len() == b.len() && a.iter().zip(b).all(|(x, y)| same(x, y, tol)),
        (Value::Object(a), Value::Object(b)) => a.len() == b.len() && b.iter().all(|(k, y)| a.get(k).is_some_and(|x| same(x, y, tol))),
        _ => got == want,
    }
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn cell_of_json(v: &Value) -> Vec<usize> {
    v.as_array().expect("cell").iter().map(|x| x.as_u64().expect("index") as usize).collect()
}

fn opt(a: &[Value], i: usize) -> Option<&Value> {
    a.get(i).filter(|v| !v.is_null())
}

fn str_vec(v: &Value) -> Vec<String> {
    v.as_array().expect("list").iter().map(|x| s(x).to_string()).collect()
}

fn seed_of(v: &Value) -> [u8; 32] {
    let b = common::b64d(s(v));
    b.try_into().expect("32-byte seed")
}

fn run_render(f_: &str, a: &[Value]) -> Option<Result<Value, String>> {
    let sv = |r: Result<String, String>| r.map(Value::String);
    Some(match f_ {
        "renderCondition" => sv(render_condition(&a[0])),
        "labelOf" => Ok(Value::String(label_of(s(&a[0])))),
        "renderCaveat" => sv(render_caveat(&a[0])),
        "renderGrant" => sv(render_grant(&a[0])),
        "renderQuestion" => sv(render_question(&a[0], &cell_of_json(&a[1]))),
        "renderAction" => sv(render_action(&a[0], &a[1])),
        "claimsOf" => claims_of(&a[0], &a[1]),
        "backTranslationDiff" => back_translation_diff(&a[0], &a[1], &a[2]),
        "claimDiff" => {
            let names = opt(a, 3).map(|n| (s(&n[0]).to_string(), s(&n[1]).to_string()));
            claim_diff(&a[0], &a[1], &a[2], names.as_ref().map(|(x, y)| (x.as_str(), y.as_str())))
        }
        "boundaryWitnesses" => boundary_witnesses(&a[0], &a[1]),
        "checkWitnesses" => {
            let mode = s(&a[1]).to_string();
            let oracle = move |w: &Value| -> bool {
                let allows = w["grantAllows"] == json!(true);
                match mode.as_str() {
                    "agree" => allows,
                    "flip" => !allows,
                    "flip-boundary" => {
                        if w["kind"] == json!("boundary") {
                            !allows
                        } else {
                            allows
                        }
                    }
                    _ => w["side"] == json!("inside") && w["kind"] != json!("unconstrained"),
                }
            };
            Ok(check_witnesses(a[0].as_array().expect("witnesses"), &oracle))
        }
        _ => return None,
    })
}

fn run_schema(f_: &str, a: &[Value]) -> Option<Result<Value, String>> {
    Some(match f_ {
        "deriveSchemaOmega" | "deriveOmegaFromSchema" => derive_omega_from_schema(&a[0]),
        "canonValue" => canon_value(&a[0], &a[1]).map(Value::String),
        "effectiveSensitivity" => effective_sensitivity(&a[0], opt(a, 1)),
        "verbReversibility" => verb_reversibility(&a[0]).map(Value::String),
        "walletFloorOverrides" => wallet_floor_overrides(&json!({ "verbs": a[0] }), opt(a, 1)),
        _ => return None,
    })
}

fn run_world(f_: &str, a: &[Value]) -> Option<Result<Value, String>> {
    Some(match f_ {
        "worldDim" => world_dim(s(&a[0]), &a[1]),
        "excessDim" => excess_dim(s(&a[0]), &a[1], a.get(2).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])),
        "optimalityCondition" => Ok(optimality_condition(s(&a[0]), opt(a, 1))),
        "provenanceDim" => Ok(provenance_dim(s(&a[0]))),
        "classifierDim" => Ok(classifier_dim(s(&a[0]), &str_vec(&a[1]))),
        "withDims" => with_dims(&a[0], s(&a[1]), a[2].as_array().expect("dims")),
        "liftOutcome" => lift_outcome(&a[0], &a[1], &str_vec(&a[2])),
        _ => return None,
    })
}

fn grant_of(name: &str) -> Box<dyn Fn(&str, &[usize]) -> bool> {
    match name {
        "all" => Box::new(|_, _| true),
        "none" => Box::new(|_, _| false),
        "cell0" => Box::new(|_, c| c.iter().all(|x| *x == 0)),
        _ => Box::new(|_, c| c[0] <= 1),
    }
}

fn run_traj(f_: &str, a: &[Value]) -> Option<Result<Value, String>> {
    let empty = json!({});
    let hist = |v: &Value| v.as_array().expect("history").clone();
    Some(match f_ {
        "dimKindOf" => Ok(json!(dim_kind_of(s(&a[0])))),
        "accDimPath" => Ok(json!(acc_dim_path(s(&a[0])))),
        "monDimPath" => Ok(json!(mon_dim_path(s(&a[0])))),
        "trajectoryHarmRange" => trajectory_harm_range(f(&a[0]), f(&a[1])).map(num_json),
        "augment" | "augmentOmega" => augment_omega(&a[0], &a[1], a.get(2).unwrap_or(&empty)),
        "liftScenario" => (|| -> Result<Value, String> {
            let tilde = augment_omega(&a[0], &a[1], &a[2])?;
            let lifted = lift_action(&tilde, &a[1], &hist(&a[3]), &a[4], opt(a, 5))?;
            let cell = lifted.as_ref().and_then(|l| lifted_cell(&tilde, l));
            Ok(json!({ "lifted": lifted.clone().unwrap_or(Value::Null), "cell": cell.unwrap_or(Value::Null) }))
        })(),
        "liftAction" => lift_action(&a[0], &a[1], &hist(&a[2]), &a[3], None).map(|o| o.unwrap_or(Value::Null)),
        "stepScenario" => (|| -> Result<Value, String> {
            let tilde = augment_omega(&a[0], &a[1], &a[2])?;
            let g = grant_of(s(&a[5]));
            step_trajectory(&tilde, &a[1], &hist(&a[3]), &a[4], &*g, opt(a, 6))
        })(),
        "stepTrajectory" => {
            // misc: the grant is a list of allowed cells, or "all" / "none"
            let allow = a[4].clone();
            let g = move |_: &str, c: &[usize]| match &allow {
                Value::String(x) if x == "all" => true,
                Value::String(_) => false,
                Value::Array(l) => l.iter().any(|x| cell_of_json(x) == c),
                _ => false,
            };
            // the generator calls `stepTrajectory(.., { ...cand, id: "new" }, ..)`
            let mut cand = a[3].clone();
            if let Some(m) = cand.as_object_mut() {
                m.insert("id".into(), json!("new"));
            }
            step_trajectory(&a[0], &a[1], &hist(&a[2]), &cand, &g, None)
        }
        "defaultAccumulators" => default_accumulators(&a[0], &a[1]),
        "describeAccCell" => {
            let idx = a[1].as_i64().expect("index");
            let this = opt(a, 3).map(f);
            let bracket = a.get(4).and_then(Value::as_str) == Some("bracket");
            describe_acc_cell(&a[0], idx, s(&a[2]), this, bracket).map(Value::String)
        }
        _ => return None,
    })
}

fn run_statement(f_: &str, a: &[Value]) -> Option<Result<Value, String>> {
    Some(match f_ {
        "signIntent" => sign_intent(&a[0], &seed_of(&a[1])),
        "verifyIntent" => Ok(verify_intent(&a[0], a.get(1).unwrap_or(&json!({})))),
        "intentRef" => intent_ref(&a[0]).map(Value::String),
        "intentGoal" => Ok(Value::String(intent_goal(s(&a[0]), a.get(1).and_then(Value::as_str)))),
        "parseIntentGoal" => Ok(parse_intent_goal(&a[0]).unwrap_or(Value::Null)),
        _ => return None,
    })
}

fn run_stats(f_: &str, a: &[Value]) -> Option<Result<Value, String>> {
    use atlas_pca::intent_kit3::stats as st;
    let parse_big = |v: &Value| -> Result<rsa::BigUint, String> {
        let t = big_of(v);
        if t.starts_with('-') {
            return Err("cdfRecNumerator: a must be in [0, 2^52]".into());
        }
        rsa::BigUint::parse_bytes(t.as_bytes(), 10).ok_or_else(|| "bad bigint".to_string())
    };
    Some(match f_ {
        "clopperPearsonUpper" => st::clopper_pearson_upper(f(&a[0]), f(&a[1]), f(&a[2])).map(num_json),
        "clopperPearsonCertified" => st::clopper_pearson_certified(f(&a[0]), f(&a[1]), f(&a[2]))
            .map(|(u, hi, lo)| json!({ "upper": num_json(u), "upperUnits": bigv(hi), "lowerUnits": bigv(lo) })),
        "binomialCdf" => Ok(num_json(st::binomial_cdf(f(&a[0]), a[1].as_i64().expect("n"), f(&a[2])))),
        "doubleToDyadic" => st::double_to_dyadic(f(&a[0])).map(|(n, e)| json!({ "num": bigv(n), "exp": e })),
        "cdfRecNumerator" => parse_big(&a[2])
            .and_then(|x| st::cdf_rec_numerator(a[0].as_u64().expect("n") as usize, a[1].as_u64().expect("k") as usize, &x))
            .map(|n| bigv(n.to_str_radix(10))),
        "cdfExceeds" => (|| -> Result<Value, String> {
            let x = parse_big(&a[2])?;
            let num = parse_big(&a[3]["num"])?;
            st::cdf_exceeds(a[0].as_u64().expect("n") as usize, a[1].as_u64().expect("k") as usize, &x, &num, a[3]["exp"].as_u64().expect("exp") as u32)
                .map(Value::Bool)
        })(),
        "hoeffdingHalfWidth" => Ok(num_json(st::hoeffding_half_width(f(&a[0]), f(&a[1]), a.get(2).map_or(0.05, f)))),
        "wilsonInterval" => {
            let (p, lo, hi) = st::wilson_interval(f(&a[0]), f(&a[1]), a.get(2).map_or(1.959963984540054, f));
            Ok(json!({ "p": num_json(p), "lo": num_json(lo), "hi": num_json(hi) }))
        }
        _ => return None,
    })
}

fn replay(pkg: &str, run: fn(&str, &[Value]) -> Option<Result<Value, String>>, max_skip_pct: usize) {
    let cases = common::ref_cases_seeded(pkg);
    let (mut skipped, mut bad) = (0usize, vec![]);
    for c in &cases {
        let name = s(&c["name"]).to_string();
        if common::has_lone(c) {
            skipped += 1;
            continue;
        }
        let args = c["args"].as_array().expect("args");
        let Some(got) = run(s(&c["fn"]), args) else {
            skipped += 1;
            continue;
        };
        let want = &c["out"];
        // the stats corpus: only the diagnostic statistics keep the documented 1e-12; clopperPearsonUpper / Certified and the integer
        // machinery (cdfRecNumerator, cdfExceeds, doubleToDyadic) are exact
        let tol = pkg != "intent-stats" || STATS_DIAGNOSTIC.contains(&s(&c["fn"]));
        let ok = if want.as_object().is_some_and(|m| m.contains_key("$throws")) { got.is_err() } else { got.as_ref().is_ok_and(|g| same(g, want, tol)) };
        if !ok {
            let shown = match &got {
                Ok(v) => v.to_string(),
                Err(e) => format!("Err({e})"),
            };
            bad.push(format!("{name}: want {} got {}", want.to_string().chars().take(200).collect::<String>(), shown.chars().take(200).collect::<String>()));
        }
    }
    assert!(bad.is_empty(), "{pkg}: {} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(12).cloned().collect::<Vec<_>>().join("\n"));
    assert!(skipped * 100 <= cases.len() * max_skip_pct, "{pkg}: {skipped} of {} cases skipped", cases.len());
}

#[test]
fn intent_render() {
    replay("intent-render", run_render, 0);
}

#[test]
fn intent_schema() {
    replay("intent-schema", run_schema, 0);
}

#[test]
fn intent_world() {
    replay("intent-world", run_world, 0);
}

#[test]
fn intent_trajectory() {
    replay("intent-trajectory", run_traj, 0);
}

#[test]
fn intent_statement() {
    replay("intent-statement", run_statement, 0);
}

#[test]
fn intent_stats() {
    replay("intent-stats", run_stats, 0);
}

fn run_misc(f_: &str, a: &[Value]) -> Option<Result<Value, String>> {
    run_statement(f_, a).or_else(|| run_schema(f_, a)).or_else(|| run_traj(f_, a))
}

#[test]
fn intent_misc() {
    // about 40% of the misc corpus belongs to the compilers / classifier / frames / provenance / jit / regret engines (other parts)
    replay("intent-misc", run_misc, 55);
}
