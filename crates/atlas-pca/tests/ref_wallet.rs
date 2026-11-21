//! Differential replay of part 1 of the wallet (friction, the signed answer, numerics, canaries, fatigue, risk-priced escalation, the
//! outcome space and cell coordinates) against the TypeScript reference (test-data/ref-wallet.json.gz). A reference throw only requires a
//! refusal, except for the messages the reference raises itself (prefix list in `EXACT`). Numbers compare by IEEE-754 value.
//! Not replayed here (part 2, the trusted card, clarification planning, population priors and the question channel): cleanText, last4,
//! formatNumber, renderCard, cardDigest, cardDigestMatches, cardText, partialError, normalizeTyped, expectedTyped, parseClarifyRequest,
//! informationGain, planClarification, gaussianSigma, gaussian, rrKeepProbability, randomizedResponse, debiasRandomizedResponse,
//! populationCellKey, aggregate, populationPrior, siteQuestionNotice, clarificationNotice, questionText, webhookChannel, textChannel,
//! dispatcher, channel (counted apart; everything else is replayed). Skipped: cases carrying a lone surrogate (counted, under 10%).
mod common;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::wallet::*;
use atlas_pca::wallet_omega as om;
use atlas_pca::wallet_pricing::*;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const PART2: &[&str] = &[
    "cleanText",
    "last4",
    "formatNumber",
    "renderCard",
    "cardDigest",
    "cardDigestMatches",
    "cardText",
    "partialError",
    "normalizeTyped",
    "expectedTyped",
    "parseClarifyRequest",
    "informationGain",
    "planClarification",
    "gaussianSigma",
    "gaussian",
    "rrKeepProbability",
    "randomizedResponse",
    "debiasRandomizedResponse",
    "populationCellKey",
    "aggregate",
    "populationPrior",
    "siteQuestionNotice",
    "clarificationNotice",
    "questionText",
    "webhookChannel",
    "textChannel",
    "dispatcher",
    "channel",
];

/// Reference messages compared exactly (the ones it raises itself).
const EXACT: [&str; 11] = [
    "betaInc:",
    "betaQuantile:",
    "estimateNoise:",
    "signIntentAnswer:",
    "applyAutonomyRaise:",
    "coordsOfBox:",
    "etaUnderLoad:",
    "admissionPolicy:",
    "SlidingWindowCounter:",
    "pickCanary:",
    "clopperPearsonUpper:",
];

fn seed_of(v: &Value) -> [u8; 32] {
    let label = v["$seed"].as_str().expect("seed label");
    Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes()).into()
}

fn sub(v: &Value, oms: &Value) -> Value {
    match v {
        Value::Object(m) if m.len() == 1 && m.contains_key("$omega") => oms[v["$omega"].as_str().unwrap()].clone(),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), sub(x, oms))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(|x| sub(x, oms)).collect()),
        _ => v.clone(),
    }
}

fn n(v: &Value) -> f64 {
    om::num(v).unwrap_or(f64::NAN)
}

fn st(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn idx(v: &Value) -> Vec<usize> {
    v.as_array().map(|a| a.iter().map(|x| x.as_u64().unwrap_or(0) as usize).collect()).unwrap_or_default()
}

fn boxv(v: &Value) -> Vec<Vec<usize>> {
    v.as_array().map(|a| a.iter().map(idx).collect()).unwrap_or_default()
}

fn opt_s(o: Option<String>) -> Value {
    o.map_or(Value::Null, Value::String)
}

fn vs_of<'a>(oms: &'a Value, id: &Value, verb: &Value) -> &'a Value {
    oms[st(id)]["verbs"].as_array().unwrap().iter().find(|v| v["verb"] == *verb).expect("verb")
}

fn cell_at(v: &Value) -> CellAt {
    CellAt { verb: st(&v["verb"]).to_string(), idx: idx(&v["idx"]) }
}

fn pick(ctx: &Value) -> Result<Value, String> {
    let confirmed: Vec<CellAt> = ctx["confirmed"].as_array().unwrap().iter().map(cell_at).collect();
    let known_yes: Vec<CellAt> = ctx["knownYes"].as_array().unwrap().iter().map(cell_at).collect();
    let exclude: HashSet<String> = ctx["exclude"].as_array().unwrap().iter().map(|s| st(s).to_string()).collect();
    let known_no_map = ctx["knownNo"].clone();
    let known_no = move |verb: &str, i: &[usize]| known_no_map.get(cell_key(verb, i)).and_then(Value::as_str).map(String::from);
    let rands: Vec<f64> = ctx["rands"].as_array().unwrap().iter().map(n).collect();
    let mut at = 0usize;
    let mut rand = move || -> Result<f64, String> {
        let r = rands.get(at).copied().ok_or("rand exhausted")?;
        at += 1;
        Ok(r)
    };
    let mut c = PickCtx {
        omega: &ctx["omega"],
        confirmed: &confirmed,
        known_no: &known_no,
        known_yes: &known_yes,
        exclude: &exclude,
        rand: &mut rand,
        rho: ctx.get("rho").and_then(om::num),
        low_harm_session: ctx["lowHarmSession"].as_bool().unwrap(),
        canaries_so_far: ctx["canariesSoFar"].as_u64().unwrap(),
    };
    Ok(match pick_canary(&mut c)? {
        None => Value::Null,
        Some(ch) => json!({ "verb": ch.verb, "idx": ch.idx, "expected": ch.expected, "source": ch.source }),
    })
}

fn sliding(a: &[Value]) -> Result<Value, String> {
    let mut c = match &a[0] {
        Value::Null => SlidingWindowCounter::new(SlidingWindowCounter::DEFAULT_WINDOW_MS)?,
        w if w.is_number() => SlidingWindowCounter::new(n(w))?,
        _ => return Err("SlidingWindowCounter: windowMs must be a positive integer".into()),
    };
    let mut out = vec![];
    for op in a[1].as_array().unwrap() {
        let op = op.as_array().unwrap();
        out.push(if st(&op[0]) == "count" {
            json!({ "v": c.count(n(&op[1])) })
        } else {
            match c.try_add(n(&op[1]), n(&op[2])) {
                Ok(b) => json!({ "v": b }),
                Err(_) => json!({ "err": true }),
            }
        });
    }
    Ok(Value::Array(out))
}

fn run(f: &str, a: &[Value], oms: &Value) -> Result<Value, String> {
    let opt = |i: usize| a.get(i);
    Ok(match f {
        "constants" => constants(),
        "isFrictionTier" => json!(is_friction_tier(&a[0])),
        "frictionRank" => json!(friction_rank(&a[0])),
        "maxFriction" => max_friction(a),
        "satisfiesTier" => json!(satisfies_tier(&a[0], &a[1])),
        "isProvenanceLevel" => json!(is_provenance_level(&a[0])),
        "worstProvenance" => json!(worst_provenance(&a[0])?),
        "frictionFor" => friction_for(&a[0], opt(1))?,
        "pcaActionDigest" => json!(pca_action_digest(&a[0])?),
        "actionValuesOf" => action_values_of(&a[0])?,
        "isB64u32" => json!(is_b64u32(&a[0])),
        "isObj" => json!(is_obj(&a[0])),
        "coordsError" => opt_s(coords_error(&a[0])),
        "answerShapeError" => opt_s(answer_shape_error(&a[0])),
        "signIntentAnswer" => sign_intent_answer(&a[0], &seed_of(&a[1]))?,
        "verifyIntentAnswer" => {
            let mut r = verify_intent_answer(&a[0], opt(1));
            if r["reason"].as_str().is_some_and(|s| s.starts_with("malformed answer:")) {
                r["reason"] = json!("malformed answer");
            }
            r
        }
        "answerRef" => json!(answer_ref(&a[0])?),
        "typedDigest" => json!(typed_digest(st(&a[0]), st(&a[1]))?),
        "deviceChallenge" => {
            let o = &a[0];
            json!(device_challenge(st(&o["questionId"]), st(&o["renderedDigest"]), o["y"].as_i64().unwrap(), o["actionDigest"].as_str())?)
        }
        "lnGamma" => json!(ln_gamma(n(&a[0]))),
        "betacf" => json!(betacf(n(&a[0]), n(&a[1]), n(&a[2]))),
        "betaInc" => json!(beta_inc(n(&a[0]), n(&a[1]), n(&a[2]))?),
        "betaQuantile" => json!(beta_quantile(n(&a[0]), n(&a[1]), n(&a[2]))?),
        "clopperPearsonUpper" => json!(om::clopper_pearson_upper(n(&a[0]), n(&a[1]), n(&a[2]))?),
        "binEnt" => json!(bin_ent(n(&a[0]))),
        "recordCanary" => record_canary(&a[0], &a[1], &a[2])?,
        "estimateNoise" => estimate_noise(&a[0], opt(1).map_or(0.05, n))?.to_value(),
        "cellKey" => json!(cell_key(st(&a[0]), &idx(&a[1]))),
        "boundaryNeighbours" => {
            let conf: Vec<CellAt> = a[1].as_array().unwrap().iter().map(cell_at).collect();
            Value::Array(boundary_neighbours(&a[0], &conf).into_iter().map(|c| json!({ "verb": c.verb, "idx": c.idx })).collect())
        }
        "pickCanary" => pick(&a[0])?,
        "etaUnderLoad" => json!(eta_under_load(n(&a[0]), n(&a[1]), n(&a[2]))?),
        "noiseState" => noise_state(&a[0], n(&a[1]), opt(2))?,
        "admissionPolicy" => admission_policy(&a[0], opt(1))?,
        "doubleConfirmed" => {
            let recs: Vec<Confirmation> =
                a[0].as_array().unwrap().iter().map(|r| Confirmation { screen: n(&r["screen"]), tier: st(&r["tier"]).to_string() }).collect();
            json!(double_confirmed(&recs))
        }
        "slidingWindow" => sliding(a)?,
        "signPricingConfig" => sign_pricing_config(&a[0], &seed_of(&a[1]))?,
        "pricingConfigError" => opt_s(pricing_config_error(&a[0])),
        "freshCalibration" => fresh_calibration(),
        "decideEscalation" => decide_escalation(&a[0], &a[1], &a[2]),
        "signAnswer" => sign_answer(&a[0], &seed_of(&a[1]))?,
        "updateCalibration" => update_calibration(&a[0], &a[1], a[2].as_array().unwrap(), &a[3])?,
        "signAutonomyRaise" => sign_autonomy_raise(&a[0], &seed_of(&a[1]))?,
        "applyAutonomyRaise" => apply_autonomy_raise(&a[0], &a[1], &seed_of(&a[2]))?,
        "coordKeyOf" => json!(coord_key_of(st(&a[0]))),
        "resolveCoords" => match resolve_coords(&a[0], st(&a[1]), &a[2])? {
            BoxResult::Ok { vs, box_ } => json!({ "ok": true, "verb": vs["verb"], "box": box_ }),
            BoxResult::Refused(reason) => json!({ "ok": false, "reason": reason }),
        },
        "coordsOfBox" => coords_of_box(vs_of(oms, &a[0], &a[1]), &boxv(&a[2]))?,
        "coordsOfCell" => coords_of_cell(vs_of(oms, &a[0], &a[1]), &idx(&a[2]))?,
        "cellInBox" => json!(cell_in_box(&boxv(&a[0]), &idx(&a[1]))),
        "boxCells" => json!(box_cells(&boxv(&a[0]))),
        "boxSize" => json!(box_size(&boxv(&a[0]))),
        "cellOfAction" => match cell_of_action(&oms[st(&a[0])], &a[1])? {
            Some((vs, i)) => json!({ "verb": vs["verb"], "idx": i }),
            None => Value::Null,
        },
        "flatIndex" => json!(flat_index(vs_of(oms, &a[0], &a[1]), &idx(&a[2]))),
        "omega.verbCellCount" => json!(om::verb_cell_count(vs_of(oms, &a[0], &a[1]))),
        "omega.cellCount" => json!(om::cell_count(&vs_of(oms, &a[0], &a[1])["dims"][a[2].as_u64().unwrap() as usize])),
        "omega.numCells" => {
            let d = &vs_of(oms, &a[0], &a[1])["dims"][a[2].as_u64().unwrap() as usize];
            Value::Array(om::num_cells(d).into_iter().map(|(lo, hi)| json!({ "lo": lo, "hi": hi })).collect())
        }
        "omega.labelOf" => json!(om::label_of(st(&a[0]))),
        "omega.decodeCell" => json!(om::decode_cell(vs_of(oms, &a[0], &a[1]), a[2].as_u64().unwrap() as usize)),
        "omega.cellStats" => {
            let s = om::cell_stats(vs_of(oms, &a[0], &a[1]), &idx(&a[2]));
            json!({ "mass": s.mass, "harm": s.harm })
        }
        "omega.cellRep" => om::cell_rep(vs_of(oms, &a[0], &a[1]), &idx(&a[2])),
        "omega.cellOf" => om::cell_of(vs_of(oms, &a[0], &a[1]), &a[2]).map_or(Value::Null, |i| json!(i)),
        f => panic!("unknown fn {f}"),
    })
}

#[test]
fn wallet_vectors() {
    let all = common::ref_cases("wallet");
    let oms = all.iter().find(|c| c["fn"] == "omegas").expect("omegas case")["out"].clone();
    let part2: HashSet<&str> = PART2.iter().copied().collect();
    let cases: Vec<&Value> = all.iter().filter(|c| c["fn"] != "omegas" && !part2.contains(c["fn"].as_str().unwrap())).collect();
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let args: Vec<Value> = c["args"].as_array().unwrap().iter().map(|v| sub(v, &oms)).collect();
        let got = std::panic::catch_unwind(|| run(f, &args, &oms)).unwrap_or_else(|_| Err("panic".into()));
        let want = &c["out"];
        let ok = match (want.get("$throws"), &got) {
            (Some(msg), Err(m)) => !EXACT.iter().any(|p| msg.as_str().is_some_and(|s| s.starts_with(p))) || msg.as_str() == Some(m.as_str()),
            (None, Ok(v)) => atlas_pca::canonicalize(want) == atlas_pca::canonicalize(v) || common::json_close(want, v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], want, got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(60).cloned().collect::<Vec<_>>().join("\n"));
}
