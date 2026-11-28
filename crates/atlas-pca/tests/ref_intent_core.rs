//! Differential replay of the outcome-space and Intent Map corpora (test-data/ref-intent-omega, ref-intent-map) through the typed design of
//! `intent_kit` (typed `Omega`, `create_learner(&omega, options)`, `IntentLearner`), the single implementation the JSON-valued `intent_kit2`
//! views delegate to. A reference throw only requires a refusal. Not replayed here (the JSON-valued views keep their own copies of these
//! helpers and `tests/ref_intent_b.rs` / `ref_intent_d.rs` replay them): `dimCellsIn`, `restrictRegion`, `valueInRegionDim`.
mod common;
use atlas_pca::intent_kit::frames::apply_divergence;
use atlas_pca::intent_kit::jn;
use atlas_pca::intent_kit::mapkit::*;
use atlas_pca::intent_kit::omega::*;
use atlas_pca::intent_kit::policy::*;
use atlas_pca::intent_kit::region::*;
use atlas_pca::intent_kit4::commit::commit_intent_map;
use atlas_pca::serde_json::{json, Map, Value};

type R<T> = Result<T, String>;

fn numeq(x: f64, y: f64) -> bool {
    x == y
}

fn eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => numeq(x.as_f64().unwrap_or(f64::NAN), y.as_f64().unwrap_or(f64::NAN)),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y.iter()).all(|(p, q)| eq(p, q)),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| eq(v, w))),
        _ => a == b,
    }
}

fn replay(pkg: &str, norm: fn(Value) -> Value, f: &dyn Fn(&str, &[Value]) -> Option<R<Value>>) {
    let cases = common::ref_cases_seeded(pkg);
    let (mut bad, mut run) = (vec![], 0usize);
    for c in &cases {
        let name = c["name"].as_str().unwrap_or("?");
        let fname = c["fn"].as_str().unwrap_or("?");
        let args: Vec<Value> = c["args"].as_array().cloned().unwrap_or_default();
        let got = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(fname, &args))) {
            Ok(Some(r)) => r,
            Ok(None) => continue,
            Err(_) => Err("panic".to_string()),
        };
        run += 1;
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
                let v = norm(v);
                if !eq(&v, &norm(out.clone())) {
                    bad.push(format!(
                        "{name}: got {} want {}",
                        v.to_string().chars().take(400).collect::<String>(),
                        out.to_string().chars().take(400).collect::<String>()
                    ));
                }
            }
        }
    }
    assert!(run > 0, "{pkg}: no case was replayed");
    assert!(bad.is_empty(), "{} of {run} cases differ:\n{}", bad.len(), bad.iter().take(25).cloned().collect::<Vec<_>>().join("\n"));
}

fn ident(v: Value) -> Value {
    v
}

fn fnum(v: &Value) -> R<f64> {
    v.as_f64().ok_or_else(|| "a number is required".to_string())
}

fn s(v: &Value) -> R<&str> {
    v.as_str().ok_or_else(|| "a string is required".to_string())
}

fn one(v: &Value) -> R<usize> {
    Ok(v.as_f64().filter(|f| *f >= 0.0 && *f == f.floor()).ok_or("an index must be a non-negative integer")? as usize)
}

fn idx(v: &Value) -> R<Vec<usize>> {
    v.as_array().ok_or("an index must be a list")?.iter().map(one).collect()
}

fn stats(r: (f64, f64)) -> Value {
    json!({"mass": jn(r.0), "harm": jn(r.1)})
}

/// A verb space as the corpus passes it; a missing weight reads as 0 (only `cellStats` observes it).
fn vs_of(v: &Value, needs_weight: bool) -> R<VerbSpace> {
    let mut v = v.clone();
    if !needs_weight && v.get("weight").is_none() {
        v["weight"] = json!(0);
    }
    VerbSpace::from_json(&v)
}

/// An omega as the corpus passes it; a missing weight reads as 0 unless the function needs it.
fn omega_of(v: &Value, needs_weight: bool) -> R<Omega> {
    let mut v = v.clone();
    if !needs_weight {
        if let Some(vs) = v.get_mut("verbs").and_then(Value::as_array_mut) {
            for x in vs.iter_mut() {
                if x.get("weight").is_none() {
                    x["weight"] = json!(0);
                }
            }
        }
    }
    Omega::from_json(&v)
}

fn omega_case(fname: &str, a: &[Value]) -> Option<R<Value>> {
    Some((|| -> R<Value> {
        match fname {
            "deriveOmega" => Ok(derive_omega(&a[0])?.to_json()),
            "harmMax" => Ok(jn(harm_max(&omega_of(&a[0], false)?)?)),
            "verbSpace" => Ok(a[0]["verbs"].as_array().and_then(|vs| vs.iter().find(|v| v["verb"] == a[1])).cloned().unwrap_or(Value::Null)),
            "verbCellCount" => Ok(jn(verb_cell_count(&vs_of(&a[0], false)?) as f64)),
            "decodeCell" => Ok(json!(decode_cell(&vs_of(&a[0], false)?, one(&a[1])?))),
            "encodeCell" => Ok(jn(encode_cell(&vs_of(&a[0], false)?, &idx(&a[1])?) as f64)),
            "cellRep" | "seeded" => cell_rep(&vs_of(&a[0], false)?, &idx(&a[1])?),
            "cellStats" => Ok(stats(cell_stats(&vs_of(&a[0], true)?, &idx(&a[1])?)?)),
            "cellOf" => Ok(cell_of(&vs_of(&a[0], false)?, &a[1]).map(|i| json!(i)).unwrap_or(Value::Null)),
            "harmOf" => Ok(jn(harm_of(&vs_of(&a[0], false)?, &a[1]))),
            "cellCount" => Ok(jn(Dim::from_json(&a[0])?.cell_count() as f64)),
            "numCells" => match Dim::from_json(&a[0])? {
                Dim::Num { cells, .. } => Ok(Value::Array(cells.iter().map(|(lo, hi)| json!({"lo": jn(*lo), "hi": jn(*hi)})).collect())),
                _ => Err("numCells of a categorical dimension".into()),
            },
            "numRep" => Ok(jn(num_rep(&Dim::from_json(&a[0])?, one(&a[1])?)?)),
            "repValue" => rep_value(&Dim::from_json(&a[0])?, one(&a[1])?),
            "catRep" => Ok(Value::String(cat_rep(&Dim::from_json(&a[0])?, one(&a[1])?)?)),
            "catCellOf" => {
                let d = Dim::from_json(&a[0])?;
                if d.is_num() {
                    return Err("catCellOf of a numeric dimension".into());
                }
                Ok(jn(cat_cell_of(&d, s(&a[1])?).map(|i| i as f64).unwrap_or(-1.0)))
            }
            "cellOfValue" => Ok(jn(cell_of_value(&Dim::from_json(&a[0])?, Some(&a[1])).map(|i| i as f64).unwrap_or(-1.0))),
            "dimCellStats" => Ok(stats(dim_cell_stats(&Dim::from_json(&a[0])?, one(&a[1])?)?)),
            "intervalWeight" => Ok(jn(interval_weight(Dim::from_json(&a[0])?.log(), fnum(&a[1])?, fnum(&a[2])?))),
            "rngSeq" => {
                let mut r = Rng::new(fnum(&a[0])?);
                Ok(Value::Array((0..fnum(&a[1])? as usize).map(|_| jn(r.next())).collect()))
            }
            "sampleOutcomes" => {
                let om = omega_of(&a[0], true)?;
                let mut r = Rng::new(fnum(&a[1])?);
                let mut out = vec![];
                for _ in 0..fnum(&a[2])? as usize {
                    out.push(sample_outcome(&om, &mut r)?.1);
                }
                Ok(Value::Array(out))
            }
            "normalizePolicy" => normalize_policy_checked(&a[0]),
            "regionOfCell" => region_of_cell(&vs_of(&a[0], false)?, &idx(&a[1])?),
            "regionCells" => Ok(json!(region_cells(&vs_of(&a[0], false)?, &a[1], s(&a[2])?)?)),
            "outcomeToAction" => Ok(outcome_to_action(&vs_of(&a[0], false)?, &a[1])),
            "admits" => Ok(json!(admitter(&a[0])?.admits(&vs_of(&a[1], false)?, &a[2])?)),
            _ => return Err(format!("not replayed here: {fname}")),
        }
    })())
    .filter(|r| !matches!(r, Err(e) if e.starts_with("not replayed here")))
}

#[test]
fn intent_omega_typed_design_matches_the_reference() {
    replay("intent-omega", ident, &omega_case);
}

// ---- the Intent Map ---------------------------------------------------------------------------------------------------------

fn secret_of(seed: u64) -> Vec<u8> {
    (0..32u64).map(|i| ((seed + 7 * i) & 255) as u8).collect()
}

/// A verification problem compares by its prefix ("replay failed: ..." is "replay failed").
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
    *cur = jn(cur.as_f64().unwrap_or(f64::NAN) + by);
}

fn mk(omega: &Value, mo: &Value, obs: &Value) -> R<atlas_pca::intent_kit::learner::IntentLearner> {
    let mut l = create_learner(&Omega::from_json(omega)?, Some(mo))?;
    for x in obs.as_array().ok_or("observations must be a list")? {
        l.observe(&json!({"verb": x["verb"], "values": x["values"]}), fnum(&x["y"])? as i64, s(&x["source"])?, x.get("region").filter(|r| !r.is_null()))?;
    }
    Ok(l)
}

fn disclosures(omega: &Value, cm: &atlas_pca::intent_kit4::commit::Committed) -> R<Vec<Value>> {
    let mut out = vec![];
    for v in omega["verbs"].as_array().ok_or("omega.verbs")? {
        let vs = VerbSpace::from_json(v)?;
        let t = verb_cell_count(&vs);
        for fl in [0, t / 2, t - 1] {
            let oc = cell_rep(&vs, &decode_cell(&vs, fl))?;
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
    let mut l = mk(omega, mo, obs)?;
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
        "tampered": tampered, "options": map_learner_options(&map)?, "omegaRoundtrip": omega_to_json(&omega_from_json(&map["omega"])?), "commit": commit}))
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
        "omegaToJSON" => Omega::from_json(&a[0]).map(|o| omega_to_json(&o)),
        "omegaFromJSON" => omega_from_json(&a[0]).map(|o| o.to_json()),
        "divergence" => (|| -> R<Value> {
            let mut l = mk(&a[0], &a[1], &a[2])?;
            let mut out = vec![];
            for d in a[3].as_array().ok_or("divergences")? {
                out.push(apply_divergence(&mut l, &d["outcome"], fnum(&d["y"])? as i64)?);
            }
            Ok(Value::Array(out))
        })(),
        _ => return None,
    })
}

#[test]
fn intent_map_typed_design_matches_the_reference() {
    replay("intent-map", norm_map, &run_map);
}
