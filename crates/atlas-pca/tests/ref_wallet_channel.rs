//! Differential replay of part 2 of the wallet (the trusted card, clarification planning, population priors, delivery and the question
//! channel with its handlers) against the TypeScript reference (test-data/ref-wallet.json.gz). Part 1 is replayed by ref_wallet.rs; this
//! test replays exactly the functions that one filters out: cleanText, last4, formatNumber, renderCard, cardDigest, cardDigestMatches,
//! cardText, partialError, normalizeTyped, expectedTyped, parseClarifyRequest, informationGain, planClarification, gaussianSigma, gaussian,
//! rrKeepProbability, randomizedResponse, debiasRandomizedResponse, populationCellKey, aggregate, populationPrior, siteQuestionNotice,
//! clarificationNotice, questionText, webhookChannel, textChannel, dispatcher and channel (every scripted session, handlers included).
//! A reference throw requires a refusal. Numbers compare by IEEE-754 value, except gaussian and aggregate (the reference's cosine is its own
//! implementation, the platform cosine can differ in the last bit): those compare with a relative tolerance of 1e-12. Skipped: cases carrying
//! a lone surrogate in their arguments (counted, under 10%).
mod common;
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::wallet::{action_values_of, cell_key, CellAt, SlidingWindowCounter};
use atlas_pca::wallet_card as wc;
use atlas_pca::wallet_channel as ch;
use atlas_pca::wallet_omega as om;
use atlas_pca::wallet_population as wp;
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::rc::Rc;

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

/// The functions whose numbers go through the platform cosine.
const CLOSE: &[&str] = &["gaussian", "aggregate"];

fn seed_label(label: &str) -> [u8; 32] {
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

/// A JSON number from a double (an integral one as an integer).
fn nj(f: f64) -> Value {
    if f.is_finite() && f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 {
        json!(f as i64)
    } else {
        json!(f)
    }
}

fn st(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn idx(v: &Value) -> Vec<usize> {
    v.as_array().map(|a| a.iter().map(|x| x.as_u64().unwrap_or(0) as usize).collect()).unwrap_or_default()
}

fn opt_s(o: Option<String>) -> Value {
    o.map_or(Value::Null, Value::String)
}

fn vs_of<'a>(oms: &'a Value, id: &Value, verb: &Value) -> &'a Value {
    oms[st(id)]["verbs"].as_array().unwrap().iter().find(|v| v["verb"] == *verb).expect("verb")
}

fn strings(v: &Value) -> HashSet<String> {
    v.as_array().map(|a| a.iter().map(|x| st(x).to_string()).collect()).unwrap_or_default()
}

/// The randomness source of a case: a draw past the end of the list fails.
fn seq(xs: Vec<f64>) -> wp::Rand {
    let mut at = 0usize;
    Box::new(move || -> Result<f64, String> {
        let r = xs.get(at).copied().ok_or_else(|| "rand exhausted".to_string())?;
        at += 1;
        Ok(r)
    })
}

fn nums(v: &Value) -> Vec<f64> {
    v.as_array().map(|a| a.iter().map(n).collect()).unwrap_or_default()
}

fn plan(x: &Value) -> Result<Value, String> {
    let p = x["view"]["p"].clone();
    let (vetoed, ceiling, asked) = (strings(&x["view"]["vetoed"]), strings(&x["view"]["ceiling"]), strings(&x["asked"]));
    let pf = move |v: &str, i: &[usize]| p.get(&cell_key(v, i)).and_then(om::num).unwrap_or(0.0);
    let vf = move |v: &str, i: &[usize]| vetoed.contains(&cell_key(v, i));
    let cf = move |v: &str, i: &[usize]| ceiling.contains(&cell_key(v, i));
    let cands: Vec<Value> = x["candidates"].as_array().cloned().unwrap_or_default();
    wc::plan_clarification(&wc::PlanInput {
        omega: &x["omega"],
        view: wc::ClarifyView { p: &pf, vetoed: &vf, outside_ceiling: &cf },
        candidates: &cands,
        lift: None,
        asked: &asked,
        eta_pos: n(&x["etaPos"]),
        eta_neg: n(&x["etaNeg"]),
    })
}

fn aggregate(a: &[Value]) -> Result<Value, String> {
    let mut agg = wp::PopulationAggregator::new(&a[0], &a[1], Some(&a[2]), Some(seq(nums(&a[5]))))?;
    let votes: Vec<Value> = a[3].as_array().unwrap().iter().map(|v| agg.contribute(v)).collect();
    let release = agg.release(&a[4]).unwrap_or_else(|_| json!({ "err": true }));
    Ok(json!({ "votes": votes, "release": release }))
}

fn population_prior(a: &[Value], oms: &Value) -> Result<Value, String> {
    let mut pm = wp::population_prior(&a[0], n(&a[1]))?;
    let contained = idx(&a[4]);
    let w = pm.weight(vs_of(oms, &a[2], &a[3]), &|c| contained.contains(&c))?;
    Ok(json!({ "beta": nj(pm.beta), "weight": nj(w) }))
}

fn webhook(a: &[Value]) -> Result<Value, String> {
    let calls: Rc<RefCell<Vec<Value>>> = Rc::new(RefCell::new(vec![]));
    let script: Vec<Value> = a[1].as_array().cloned().unwrap_or_default();
    let (rec, mut at) = (calls.clone(), 0usize);
    let fetch: ch::Fetch = Box::new(move |url: &str, init: &Value| {
        rec.borrow_mut().push(json!({ "url": url, "method": init["method"], "headers": init["headers"], "body": init["body"] }));
        let step = script.get(at).cloned().unwrap_or_else(|| json!({ "ok": true, "status": 200 }));
        at += 1;
        if let Some(t) = step.get("throw").filter(|t| om::truthy(t)) {
            return Err(st(t).to_string());
        }
        Ok(ch::FetchResponse { ok: step["ok"] == json!(true), status: step["status"].clone() })
    });
    let cfg = ch::WebhookConfig { url: a[0].get("url").and_then(Value::as_str).map(String::from), headers: a[0].get("headers").cloned(), fetch: Some(fetch) };
    let mut c = ch::question_webhook_channel(cfg);
    let mut deliveries = vec![];
    for notice in a[2].as_array().unwrap() {
        deliveries.push(c.notify(notice)?);
    }
    let calls = calls.borrow().clone();
    Ok(json!({ "kind": c.kind, "enabled": c.enabled, "deliveries": deliveries, "calls": calls }))
}

fn text_channel(a: &[Value]) -> Result<Value, String> {
    let sent: Rc<RefCell<Vec<Value>>> = Rc::new(RefCell::new(vec![]));
    let send: Option<ch::Sender> = a[2].as_array().cloned().map(|script| {
        let (rec, mut at) = (sent.clone(), 0usize);
        let f: ch::Sender = Box::new(move |body: &Value| {
            rec.borrow_mut().push(body.clone());
            let step = script.get(at).cloned();
            at += 1;
            match step.as_ref().and_then(|s| s.get("throw")).filter(|t| om::truthy(t)) {
                Some(t) => Err(st(t).to_string()),
                None => Ok(()),
            }
        });
        f
    });
    let mut c = ch::question_text_channel(st(&a[0]), st(&a[1]), send);
    let mut deliveries = vec![];
    for notice in a[3].as_array().unwrap() {
        deliveries.push(c.notify(notice)?);
    }
    let sent = sent.borrow().clone();
    Ok(json!({ "kind": c.kind, "enabled": c.enabled, "deliveries": deliveries, "sent": sent }))
}

fn dispatcher(a: &[Value]) -> Result<Value, String> {
    let mut channels = vec![];
    for c in a[0].as_array().unwrap() {
        channels.push(if st(&c["type"]) == "webhook" {
            let fetch: ch::Fetch = Box::new(|_: &str, _: &Value| Ok(ch::FetchResponse { ok: true, status: json!(200) }));
            ch::question_webhook_channel(ch::WebhookConfig { url: c.get("url").and_then(Value::as_str).map(String::from), headers: None, fetch: Some(fetch) })
        } else {
            let send: Option<ch::Sender> = om::truthy(&c["enabled"]).then(|| -> ch::Sender { Box::new(|_: &Value| Ok(())) });
            ch::question_text_channel(st(&c["type"]), "S", send)
        });
    }
    let mut d = ch::create_question_dispatcher(channels);
    let deliveries = d.notify_all(&a[1])?;
    Ok(json!({ "n": d.channels.len(), "deliveries": deliveries }))
}

// ---- the question channel ------------------------------------------------------------------------------------------------------------

fn cells_at(v: &Value) -> Vec<CellAt> {
    v.as_array().map(|a| a.iter().map(|c| CellAt { verb: st(&c["verb"]).to_string(), idx: idx(&c["idx"]) }).collect()).unwrap_or_default()
}

fn merged(base: &Value, add: &Value) -> Value {
    let mut m: Map<String, Value> = base.as_object().cloned().unwrap_or_default();
    if let Some(a) = add.as_object() {
        for (k, v) in a {
            m.insert(k.clone(), v.clone());
        }
    }
    Value::Object(m)
}

fn channel(spec: &Value) -> Result<Value, String> {
    let t = Rc::new(Cell::new(n(&spec["t0"])));
    let counts = Rc::new(RefCell::new(spec["noise"].clone()));
    let v = &spec["view"];
    let (vp, vetoed, ceiling, confirmed) = (v["p"].clone(), strings(&v["vetoed"]), strings(&v["ceiling"]), cells_at(&v["confirmed"]));
    let view = ch::ChannelView {
        p: Box::new(move |verb: &str, i: &[usize]| vp.get(&cell_key(verb, i)).and_then(om::num).unwrap_or(0.0)),
        vetoed: Box::new(move |verb: &str, i: &[usize]| vetoed.contains(&cell_key(verb, i))),
        outside_ceiling: Box::new(move |verb: &str, i: &[usize]| ceiling.contains(&cell_key(verb, i))),
        confirmed: Box::new(move || confirmed.clone()),
    };
    let mut hourly = SlidingWindowCounter::new(spec.get("windowMs").map_or(SlidingWindowCounter::DEFAULT_WINDOW_MS, n))?;
    for ts in nums(&spec["hourlyPre"]) {
        let _ = hourly.try_add(ts, 9_007_199_254_740_991.0);
    }
    let map_digest = st(&spec["mapDigest"]).to_string();
    let (c_read, c_write, t_read) = (counts.clone(), counts.clone(), t.clone());
    let mut o = ch::ChannelOptions::new(
        spec["omega"].clone(),
        st(&spec["session"]).to_string(),
        Box::new(move || map_digest.clone()),
        seed_label(st(&spec["principal"])),
        spec["site"].clone(),
        view,
        hourly,
        Box::new(move || c_read.borrow().clone()),
        Box::new(move |x: Value| *c_write.borrow_mut() = x),
        seq(nums(&spec["rands"])),
        Box::new(move || t_read.get()),
    );
    o.statement_text = spec.get("statementText").and_then(Value::as_str).map(String::from);
    o.units = spec.get("units").filter(|u| om::truthy(u)).cloned();
    o.sensitivity = spec.get("sensitivity").filter(|u| om::truthy(u)).cloned();
    o.identity_paths = spec.get("identityPaths").and_then(Value::as_array).map(|a| a.iter().map(|x| st(x).to_string()).collect()).unwrap_or_default();
    o.caps = spec.get("caps").filter(|u| om::truthy(u)).cloned();
    o.rho = spec.get("rho").and_then(om::num);
    o.fatigue = spec.get("fatigue").filter(|u| om::truthy(u)).cloned();
    o.max_per_screen = spec.get("maxPerScreen").and_then(om::num);
    o.max_box_cells = spec.get("maxBoxCells").and_then(om::num);
    if let Some(d) = spec.get("device").filter(|d| d.is_object()) {
        o.device = Some(ch::Device {
            rp_id: st(&d["rpId"]).to_string(),
            origins: d["origins"].as_array().map(|a| a.iter().map(|x| st(x).to_string()).collect()).unwrap_or_default(),
            credentials: d["credentials"].clone(),
            sign_counts: d.get("signCounts").and_then(Value::as_object).cloned(),
        });
    }
    if let Some(cand) = spec.get("liftCand").filter(|u| om::truthy(u)).cloned() {
        o.lift_candidate =
            Some(Box::new(move |a: &Value| -> Result<Value, String> { Ok(json!({ "verb": a["verb"], "values": merged(&a["values"], &cand) })) }));
    }
    if let Some(add) = spec.get("lift").filter(|u| om::truthy(u)).map(|l| l["add"].clone()) {
        o.lift = Some(Box::new(move |a: &Value| -> Result<Value, String> {
            let v = action_values_of(a)?;
            Ok(json!({ "verb": v["verb"], "values": merged(&v["values"], &add) }))
        }));
    }
    let mut c = ch::TrustedChannel::new(o);
    let session = st(&spec["session"]).to_string();
    let mut seen: Vec<String> = vec![];
    let mut steps: Vec<Value> = vec![];
    for step in spec["steps"].as_array().unwrap() {
        let qid = match step.get("q") {
            Some(q) => seen.get(q.as_u64().unwrap_or(u64::MAX) as usize).cloned().unwrap_or_else(|| "undefined".to_string()),
            None => step.get("qid").and_then(Value::as_str).unwrap_or("undefined").to_string(),
        };
        let sid = step.get("sid").and_then(Value::as_str).unwrap_or(&session).to_string();
        let r: Result<Value, String> = match st(&step["op"]) {
            "time" => {
                t.set(n(&step["t"]));
                Ok(json!({ "t": step["t"] }))
            }
            "receive" => c.receive(&step["ir"], &step["action"]),
            "next" => c.next_screen().inspect(|r| {
                for q in r["questions"].as_array().into_iter().flatten() {
                    seen.push(st(&q["questionId"]).to_string());
                }
            }),
            "answer" => c.answer(&qid, &step["response"]),
            "clarify" => c.clarify(&step["body"]),
            "hQuestion" => ch::question_handler((sid == session).then_some(&mut c), &step["body"]),
            "hClarify" => ch::clarify_handler((sid == session).then_some(&mut c), &step["body"]),
            "summary" => c.summary(),
            "state" => c.state_digest().map(|d| json!({ "digest": d, "asked": c.questions_asked() })),
            "noise" => c.noise().and_then(|nz| c.admission().map(|ad| json!({ "noise": nz, "admission": ad }))),
            "challenge" => c.device_challenge_for(&qid).map(opt_s),
            op => Err(format!("bad op {op}")),
        };
        steps.push(json!({ "op": step["op"], "r": r.unwrap_or_else(|_| json!({ "$err": true })) }));
    }
    let noise = counts.borrow().clone();
    Ok(json!({ "steps": steps, "noise": noise, "signCounts": c.device_sign_counts() }))
}

// ---- the replay -----------------------------------------------------------------------------------------------------------------------

fn run(f: &str, a: &[Value], oms: &Value) -> Result<Value, String> {
    Ok(match f {
        "cleanText" => json!(wc::clean_text(&a[0], n(&a[1]) as usize)?),
        "last4" => json!(wc::last4(st(&a[0]))),
        "formatNumber" => json!(wc::format_number(n(&a[0]), a.get(1))),
        "renderCard" => {
            let mut input = a[0].clone();
            let id = input.as_object_mut().and_then(|m| m.remove("omegaId"));
            if let Some(o) = id.as_ref().and_then(Value::as_str).and_then(|i| oms.get(i)) {
                input["omega"] = o.clone();
            }
            wc::render_card(&input)?
        }
        "cardDigest" => json!(wc::card_digest(&a[0])?),
        "cardDigestMatches" => json!(wc::card_digest_matches(&a[0])?),
        "cardText" => json!(wc::card_text(&a[0])?),
        "partialError" => opt_s(wc::partial_error(&a[0], &a[1])?),
        "normalizeTyped" => opt_s(wc::normalize_typed(st(&a[0]), st(&a[1]), a.get(2))),
        "expectedTyped" => opt_s(wc::expected_typed(&a[0], &a[1])?),
        "parseClarifyRequest" => wc::parse_clarify_request(&a[0]),
        "informationGain" => nj(wc::information_gain(n(&a[0]), n(&a[1]), n(&a[2]))),
        "planClarification" => plan(&a[0])?,
        "gaussianSigma" => nj(wp::gaussian_sigma(n(&a[0]), n(&a[1]), n(&a[2]))?),
        "gaussian" => nj(wp::gaussian(&mut *seq(nums(&a[0])))?),
        "rrKeepProbability" => nj(wp::rr_keep_probability(n(&a[0]))?),
        "randomizedResponse" => {
            let r = n(&a[2]);
            nj(wp::randomized_response(n(&a[0]), n(&a[1]), &mut || -> Result<f64, String> { Ok(r) })?)
        }
        "debiasRandomizedResponse" => nj(wp::debias_randomized_response(n(&a[0]), n(&a[1]), n(&a[2]))?),
        "populationCellKey" => json!(wp::population_cell_key(st(&a[0]), vs_of(oms, &a[1], &a[2]), &idx(&a[3]))?),
        "aggregate" => aggregate(a)?,
        "populationPrior" => population_prior(a, oms)?,
        "siteQuestionNotice" => {
            let mut ctx = json!({ "keys": a[1], "site": a[2], "now": a[3] });
            if let Some(inbox) = a.get(4) {
                ctx["inboxUrl"] = inbox.clone();
            }
            ch::site_question_notice(&a[0], &ctx)?
        }
        "clarificationNotice" => ch::clarification_notice(st(&a[0]), st(&a[1]), a.get(2).and_then(Value::as_str)),
        "questionText" => ch::question_text(&a[0], st(&a[1])),
        "webhookChannel" => webhook(a)?,
        "textChannel" => text_channel(a)?,
        "dispatcher" => dispatcher(a)?,
        "channel" => channel(&a[0])?,
        f => panic!("unknown fn {f}"),
    })
}

/// Equality of two JSON values with numbers within a relative tolerance.
fn close(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| close(v, w))),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(v, w)| close(v, w)),
        (Value::Number(_), Value::Number(_)) => {
            let (x, y) = (n(a), n(b));
            x == y || (x - y).abs() <= 1e-15 + 1e-12 * x.abs().max(y.abs())
        }
        _ => a == b,
    }
}

#[test]
fn wallet_channel_vectors() {
    let all = common::ref_cases("wallet");
    let oms = all.iter().find(|c| c["fn"] == "omegas").expect("omegas case")["out"].clone();
    let part2: HashSet<&str> = PART2.iter().copied().collect();
    let cases: Vec<&Value> = all.iter().filter(|c| part2.contains(c["fn"].as_str().unwrap())).collect();
    assert!(cases.len() > 1500, "part 2 cases missing: {}", cases.len());
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let args: Vec<Value> = c["args"].as_array().unwrap().iter().map(|v| sub(v, &oms)).collect();
        let got = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(f, &args, &oms))).unwrap_or_else(|_| Err("panic".into()));
        let want = &c["out"];
        let ok = match (want.get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) if CLOSE.contains(&f) => close(want, v),
            (None, Ok(v)) => atlas_pca::canonicalize(want) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], want, got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(60).cloned().collect::<Vec<_>>().join("\n"));
}
