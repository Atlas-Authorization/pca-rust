//! Differential replay of @atlasauth/pca-goal Part 2 (interpreters, boundary examples and goal tests, drift, calibration,
//! precedents, review and approval, round trip, trait selectors, the N-version meet, disambiguation, the benchmark) against the
//! reference: `test-data/ref-goal-{interpret,examples,drift,precedent,review,roundtrip,selectors,nversion,bench}.json.gz`.
//! Comparison: by JSON value (canonical form); a reference throw requires an `Err`. Shipped ontologies and domain catalogs travel by
//! NAME and are resolved from the embedded data. The review corpus runs against the corpus's own stub kernel (compile = one policy per
//! grant, decide = a grant names the verb), rebuilt here from its documented rules. Signing seeds come from the corpus arguments.
//! Skipped (counted, must stay under 10% per corpus): the cases that carry a lone surrogate (a Rust string cannot hold one).
//! Not replayed: `compileSelGoal` (the corpus has no case: the proved compiler is injected) and the live vendor transports.
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::goal::ontologies::{shipped_catalog, shipped_ontology};
use atlas_pca::goal::ontology::to_ir_ontology;
use atlas_pca::goal2::bench as bn;
use atlas_pca::goal2::crc;
use atlas_pca::goal2::disambiguate as dis;
use atlas_pca::goal2::drift as dr;
use atlas_pca::goal2::examples as ex;
use atlas_pca::goal2::interpret as it;
use atlas_pca::goal2::nversion as nv;
use atlas_pca::goal2::precedent as pr;
use atlas_pca::goal2::review as rv;
use atlas_pca::goal2::roundtrip as rt;
use atlas_pca::goal2::selectors as sel;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;
use std::cell::RefCell;

type Res<T> = Result<T, String>;

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}
fn arr(v: &Value) -> &[Value] {
    v.as_array().map(|a| a.as_slice()).unwrap_or(&[])
}
fn strs(v: &Value) -> Vec<String> {
    arr(v).iter().map(|x| s(x).to_string()).collect()
}
fn key_of(v: &Value) -> Res<KeyPair> {
    KeyPair::from_seed_b64u(v.as_str().ok_or("seed")?)
}
fn b64(v: &Value) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s(v)).unwrap_or_default()
}
/// A shipped ontology by name, or the inline one.
fn ont(v: &Value) -> Value {
    match v.as_str() {
        Some(n) => shipped_ontology(n).unwrap_or_else(|| panic!("unknown shipped ontology {n}")),
        None => v.clone(),
    }
}
/// A shipped domain's IR ontology by name, or the inline one.
fn ir_ont(v: &Value) -> Value {
    match v.as_str() {
        Some(n) => to_ir_ontology(&shipped_ontology(n).unwrap_or_else(|| panic!("unknown domain {n}")), &json!({})).expect("to_ir_ontology"),
        None => v.clone(),
    }
}
/// A shipped domain's selector catalog by name, or the inline one.
fn cat(v: &Value) -> Value {
    match v.as_str() {
        Some(n) => shipped_catalog(n).unwrap_or_else(|| panic!("unknown catalog {n}")),
        None => v.clone(),
    }
}
fn opt_null(v: Option<Value>) -> Value {
    v.unwrap_or(Value::Null)
}

fn drive(pkg: &str, floor: usize, run: &dyn Fn(&str, &[Value]) -> Res<Value>) {
    let cases = common::ref_cases_seeded(pkg);
    let (mut bad, mut skipped) = (Vec::new(), 0usize);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let args = c["args"].as_array().unwrap();
        let got = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(f, args))).unwrap_or_else(|_| Err("panic".into()));
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
    assert!(cases.len() >= floor, "{pkg}: {} cases", cases.len());
    assert!(skipped * 10 < cases.len(), "{pkg}: {skipped} cases skipped");
    assert!(bad.is_empty(), "{pkg}: {} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(12).cloned().collect::<Vec<_>>().join("\n"));
}

// ---- interpret ------------------------------------------------------------------------------------------------------------------

fn run_interpret(f: &str, a: &[Value]) -> Res<Value> {
    let req = |o: &Value, text: &Value, sources: &Value| json!({"principal": "p1", "text": text, "sources": sources, "ontology": o});
    match f {
        "slotStemsOf" => it::slot_stems(&a[0]).map(|v| json!(v)),
        "sourceDigest" => it::source_digest(s(&a[0])).map(Value::String),
        "extractCandidates" => it::extract_candidates(s(&a[1]), &ont(&a[0]), a[2].as_str()).map(|c| c.to_json()),
        "fillTemplateById" => {
            let o = ont(&a[0]);
            let t = arr(&o["templates"]).iter().find(|t| t["id"] == a[1]).ok_or("template")?.clone();
            it::fill_template(&t, &o, s(&a[2]), a[3].as_str())
        }
        "buildPromptOf" => it::build_prompt(&json!({"principal": "p", "text": a[1], "sources": a[2], "ontology": ont(&a[0])}), a[3] == true),
        "promptKeyOf" => Ok(json!(it::prompt_key(s(&a[1]), s(&a[2]), s(&a[3])))),
        "replayLookup" => it::replay_completion(s(&a[1]), &a[2], s(&a[3]), s(&a[4])).map(Value::String),
        "parseTemplateJSON" => Ok(it::parse_template_json(s(&a[0]))),
        "groundedOf" => {
            let o = ont(&a[0]);
            let t = arr(&o["templates"]).iter().find(|t| t["id"] == a[1]).ok_or("template")?;
            let sl = arr(&t["slots"]).iter().find(|x| x["name"] == a[2]).ok_or("slot")?;
            let c = it::extract_candidates(s(&a[4]), &o, None)?;
            it::grounded(sl, &a[3], &c).map(Value::Bool)
        }
        "interpretRule" => it::rule_interpret("rule", a[3].as_str(), &req(&ont(&a[0]), &a[1], &a[2])),
        "interpretForm" => {
            // the corpus runs the form text with one cited source and every other text with none
            let sources = if s(&a[2]) == "form text" { json!(["s"]) } else { Value::Null };
            let mut r = req(&ont(&a[0]), &a[2], &sources);
            r["form"] = a[1].clone();
            it::form_interpret("form", &r)
        }
        "interpretLlm" => {
            let mode = &a[3];
            let complete = |_p: &Value| -> Res<String> {
                if mode["throw"] == true {
                    Err("boom".to_string())
                } else {
                    Ok(s(&mode["raw"]).to_string())
                }
            };
            it::llm_interpret("m", "f", &complete, a[4] == true, a[5].as_str(), &req(&ont(&a[0]), &a[1], &a[2]))
        }
        "vendor" => {
            let (kind, cfg, fake, system, user) = (s(&a[1]), &a[2], &a[3], s(&a[4]), s(&a[5]));
            let recorded: RefCell<Value> = RefCell::new(json!({}));
            let fetch = |url: &str, init: &Value| -> Res<it::FetchResp> {
                *recorded.borrow_mut() = json!({"url": url, "method": init["method"], "headers": init["headers"], "body": init["body"]});
                if let Some(m) = fake.get("throwMsg").and_then(Value::as_str) {
                    return Err(m.to_string());
                }
                if fake.as_object().is_some_and(|m| m.is_empty()) {
                    // the two fixed-transport cases of the corpus (a custom base URL / token budget)
                    let body = if kind == "openai" {
                        json!({"choices": [{"message": {"content": "x"}}]})
                    } else {
                        json!({"content": [{"type": "text", "text": "x"}]})
                    };
                    return Ok(it::FetchResp { ok: true, status: 200, body: Ok(body) });
                }
                Ok(it::FetchResp { ok: fake["ok"] == true, status: fake["status"].as_i64().unwrap_or(0), body: Ok(fake["body"].clone()) })
            };
            let r = if kind == "anthropic" { it::anthropic_completion(cfg, &fetch, system, user) } else { it::openai_completion(cfg, &fetch, system, user) };
            let req = recorded.borrow().clone();
            Ok(match r {
                Ok(t) => json!({"text": t, "req": req}),
                Err(e) => json!({"error": e, "req": req}),
            })
        }
        "interpretRefundForm" => it::interpret_form(&a[0], &a[1], a[2].as_str().unwrap_or("pr1")),
        "lexicalCompare" => rt::lexical_comparator(&ont(&a[0]), s(&a[1]), s(&a[2])),
        other => Err(format!("skip:{other}")),
    }
}
#[test]
fn interpret_corpus() {
    drive("goal-interpret", 4000, &run_interpret);
}

// ---- examples -------------------------------------------------------------------------------------------------------------------

fn space(goals: &Value, extra: &Value) -> Res<ex::Space> {
    ex::build_space(arr(goals), &strs(extra))
}
fn run_examples(f: &str, a: &[Value]) -> Res<Value> {
    match f {
        "buildSpace" => Ok(space(&a[0], &a[1])?.to_json()),
        "cells" => {
            let verbs = a[2].as_array().map(|_| strs(&a[2]));
            ex::cells(&space(&a[0], &a[1])?, verbs.as_deref())
        }
        "cellKey" => ex::cell_key(&space(&a[0], &a[1])?, &a[2]).map(Value::String),
        "decideCase" => ex::decide_case(&a[0], &a[1], &a[2]),
        "replay" => ex::replay(&a[0], &a[1], arr(&a[2]), &a[3]),
        "allowWitness" => {
            let gr = arr(&a[0]["grants"]).get(a[1].as_u64().unwrap_or(0) as usize).ok_or("grant")?;
            ex::allow_witness(&a[0], gr, &a[2]).map(opt_null)
        }
        "boundaryExamples" => {
            let extra: Vec<Value> = arr(&a[2]).to_vec();
            ex::boundary_examples(&a[0], &a[1], &extra, &strs(&a[3]))
        }
        "reviewSet" => Ok(Value::Array(ex::review_set(arr(&a[0]), a[1].as_u64().unwrap_or(0) as usize))),
        "testsDigest" => ex::tests_digest(arr(&a[0])).map(Value::String),
        "makeGoalTests" => ex::make_goal_tests(&a[0], arr(&a[1])),
        "signGoalTestsSeed" => ex::sign_goal_tests(&a[0], &key_of(&a[1])?),
        "checkGoalTests" => {
            let (mode, gl, o) = (s(&a[2]).to_string(), &a[3], &a[4]);
            let decide = |t: &Value| -> Res<String> {
                Ok(match mode.as_str() {
                    "ref" => s(&ex::decide_case(gl, o, t)?["decision"]).to_string(),
                    "allow" => "allow".into(),
                    "deny" => "deny".into(),
                    _ => "escalate".into(),
                })
            };
            ex::check_goal_tests(&a[0], arr(&a[1]), &decide)
        }
        "signPinSeed" => ex::sign_pin(&a[0], &key_of(&a[1])?),
        "checkPin" => ex::check_pin(&a[0], arr(&a[1]), &a[2]),
        other => Err(format!("skip:{other}")),
    }
}
#[test]
fn examples_corpus() {
    drive("goal-examples", 120, &run_examples);
}
/// The Allow-witness builder Part 1's ontology checker takes as a parameter: the real one, over a one-grant goal of the template.
#[test]
fn allow_witness_feeds_the_ontology_checker() {
    use atlas_pca::goal::ontology::check_ontology;
    let witness = |gl: &Value, gr: &Value, o: &Value| ex::allow_witness(gl, gr, o).map(|w| w.is_some()).unwrap_or(true);
    for name in atlas_pca::goal::ontologies::NAMES {
        let o = shipped_ontology(name).unwrap();
        let issues = check_ontology(&o, &witness).expect("check_ontology");
        assert!(issues.iter().all(|i| i["msg"] != "instantiated template has an empty Allow set"), "{name}: {issues:?}");
    }
}

// ---- drift and crc ----------------------------------------------------------------------------------------------------------------

fn run_flow_drift(a: &[Value]) -> Res<Value> {
    let (goal, opts, steps) = (&a[0], dr::DriftOpts::from_json(&a[1]), arr(&a[2]));
    let mut mon = dr::DriftMonitor::new(goal, opts);
    let mut last: Value = Value::Null;
    let mut out: Vec<Value> = vec![];
    for st in steps {
        match s(&st["op"]) {
            "observe" => out.push(mon.observe(&st["act"], &st["t"])?),
            "state" => out.push(mon.state().clone()),
            "seal" => {
                last = mon.seal(&b64(&st["key"]));
                out.push(last.clone());
            }
            "restoreLast" => {
                let mut sealed = last.clone();
                match s(&st["mode"]) {
                    "state" => sealed["state"]["strikes"] = json!(0),
                    "mac" => {
                        let m = s(&sealed["mac"]).to_string();
                        let first = if m.starts_with('0') { "1" } else { "0" };
                        sealed["mac"] = json!(format!("{first}{}", m.chars().skip(1).collect::<String>()));
                    }
                    "badmac" => sealed["mac"] = json!("zz"),
                    _ => {}
                }
                mon = dr::DriftMonitor::restore(goal, &sealed, &b64(&st["key"]), opts)?;
                out.push(mon.state().clone());
            }
            "guarded" => out.push(dr::guarded_decide(goal, &st["ont"], &mut mon, &st["case"], &st["t"])?),
            other => return Err(format!("unknown op {other}")),
        }
    }
    Ok(Value::Array(out))
}
fn run_drift(f: &str, a: &[Value]) -> Res<Value> {
    match f {
        "flow" => run_flow_drift(a),
        "applyDrift" => Ok(json!(dr::apply_drift(s(&a[0]), &a[1]))),
        "alphaOf" => Ok(crc::alpha_of(a[0].as_f64().ok_or("x")?)),
        "calibrate" => {
            let gate = s(&a[2]).to_string();
            let ppm: f64 = gate.strip_prefix("cp").and_then(|x| x.parse().ok()).unwrap_or(0.0);
            let g = move |k: u64, n: u64| crc::cp_upper95(k, n).map_or(false, |u| u <= ppm / 1e5);
            crc::calibrate(&a[0], &a[1], if gate == "none" { None } else { Some(&g) })
        }
        "assertMonotone" => crc::assert_monotone(&a[0]).map(|_| Value::Null),
        "cpUpper95" => crc::cp_upper95(a[0].as_u64().unwrap_or(0), a[1].as_u64().unwrap_or(0)).map(|x| json!(x)),
        "renderReportMarkdown" => crc::render_report_markdown(&a[0], &a[1]).map(Value::String),
        other => Err(format!("skip:{other}")),
    }
}
#[test]
fn drift_corpus() {
    drive("goal-drift", 140, &run_drift);
}

// ---- precedent --------------------------------------------------------------------------------------------------------------------

fn run_flow_precedent(a: &[Value]) -> Res<Value> {
    let (goal, _ont, grant, principals, steps) = (&a[0], &a[1], &a[2], arr(&a[3]), arr(&a[4]));
    let mut log = pr::PrecedentLog::new(principals);
    let space = ex::build_space(std::slice::from_ref(goal), &[])?;
    let mut out: Vec<Value> = vec![];
    for st in steps {
        let now = st["now"].as_f64().unwrap_or(0.0);
        match s(&st["op"]) {
            "append" => {
                let r = log.append(&st["answer"], &st["answered"], grant, &space, now)?;
                out.push(if r["ok"] == true {
                    json!({"ok": true, "digest": r["entry"]["digest"], "cell": r["entry"]["cell"], "seq": r["entry"]["seq"]})
                } else {
                    r
                });
            }
            "revoke" => {
                let r = log.revoke(&st["rev"])?;
                out.push(if r["ok"] == true { json!({"ok": true, "digest": r["entry"]["digest"], "seq": r["entry"]["seq"]}) } else { r });
            }
            "verifyChain" => out.push(json!(log.verify_chain(&space))),
            "lookup" => out.push(match log.lookup(&st["policyDigest"], &space, &st["case"], now)? {
                Some(h) => json!({"decision": h["decision"], "digest": h["entry"]["digest"]}),
                None => Value::Null,
            }),
            "authorize" => {
                let r = pr::authorize_with_precedents(goal, &a[1], &st["policyDigest"], &log, &st["case"], now)?;
                let mut o = json!({"decision": r["decision"], "via": r["via"]});
                if let Some(p) = r.get("precedent") {
                    o["digest"] = p["digest"].clone();
                }
                out.push(o);
            }
            "tamper" => {
                let i = st["index"].as_u64().unwrap_or(0) as usize;
                let e = log.entries.get_mut(i).ok_or("entry")?;
                if st["del"] == true {
                    e.as_object_mut().ok_or("entry")?.shift_remove(s(&st["key"]));
                } else {
                    e[s(&st["key"])] = st["value"].clone();
                }
                out.push(json!(true));
            }
            _ => out.push(json!(log.head())),
        }
    }
    Ok(Value::Array(out))
}
fn run_precedent(f: &str, a: &[Value]) -> Res<Value> {
    match f {
        "flow" => run_flow_precedent(a),
        "ceilingsOf" => Ok(pr::ceilings_of(&a[0])),
        "answerBodyFor" => Ok(pr::answer_body_for(&a[0], &a[1])),
        "signRevocationSeed" => pr::sign_revocation(&a[0], &key_of(&a[1])?),
        other => Err(format!("skip:{other}")),
    }
}
#[test]
fn precedent_corpus() {
    drive("goal-precedent", 30, &run_precedent);
}

// ---- review -------------------------------------------------------------------------------------------------------------------------

/// The corpus's stub kernel, by mode name.
fn stub(mode: &str) -> rv::ReviewKernel {
    let (m1, m2) = (mode.to_string(), mode.to_string());
    rv::ReviewKernel {
        compile: Box::new(move |gl, _o| {
            if m1 == "throwcompile" {
                return Err("boom".to_string());
            }
            let gr = arr(&gl["grants"]);
            Ok(if gr.is_empty() {
                json!({"ok": false, "reasons": ["empty"]})
            } else {
                json!({"ok": true, "policy": {"gids": gr.iter().map(|x| x["gid"].clone()).collect::<Vec<_>>(), "n": gr.len()}})
            })
        }),
        policy_digest: Box::new(move |p| {
            if m2 == "throwdigest" {
                return Err("boom".to_string());
            }
            atlas_pca::hash_canonical_strict(&json!({"d": "stub-policy", "p": p})).ok_or_else(|| "digest".to_string())
        }),
        analyze: Some(Box::new(|p| Ok(if p["n"].as_f64().unwrap_or(0.0) >= 5.0 { vec!["too many".to_string()] } else { vec![] }))),
        decide: if mode == "nodecide" {
            None
        } else {
            Some(Box::new(|gl, _o, act, _h| {
                let allow = arr(&gl["grants"]).iter().any(|x| x["verb"] == act["verb"]);
                Ok(if allow { "allow" } else { "deny" }.to_string())
            }))
        },
        newly_allowed: if mode == "nonewly" {
            None
        } else {
            Some(Box::new(|prev, next, _o, _l| {
                let w: Vec<Value> = arr(&next["grants"])
                    .iter()
                    .filter(|x| !arr(&prev["grants"]).iter().any(|y| y["gid"] == x["gid"]))
                    .map(|x| json!({"verb": x["verb"], "res": "r", "params": {}, "t": 0, "sess": "s", "prin": "p", "org": "o", "agent": "a", "depth": 0}))
                    .collect();
                Ok(json!({"witnesses": w, "complete": true}))
            }))
        },
    }
}
fn run_review(f: &str, a: &[Value]) -> Res<Value> {
    let rerr = |e: rv::RErr| e.to_string();
    match f {
        "effectiveLimits" => Ok(rv::effective_limits(&a[0]).to_json()),
        "renderPolicyCard" => rv::render_policy_card(&a[0], arr(&a[1]), &a[2]).map_err(rerr),
        "cardDigest" => rv::card_digest(&a[0]).map(Value::String),
        "cardToText" => rv::card_to_text(&a[0]).map(Value::String),
        "diffGoals" => {
            let o = &a[2];
            let k = if s(&o["kmode"]) == "none" { None } else { Some(stub(s(&o["kmode"]))) };
            let mut opts = json!({});
            for key in ["limits", "ontology"] {
                if let Some(v) = o.get(key) {
                    opts[key] = v.clone();
                }
            }
            rv::diff_goals(&a[0], &a[1], k.as_ref(), &opts).map_err(rerr)
        }
        "diffToText" => rv::diff_to_text(&a[0]).map(Value::String).map_err(rerr),
        "approveGoalSeed" => {
            let (o, k) = (&a[2], stub(s(&a[2]["kmode"])));
            let ap = rv::ApproveOpts { kernel: &k, now: o.get("now"), ttl_ms: o.get("ttlMs"), limits: o.get("limits"), base: o.get("base") };
            rv::approve_goal(&a[0], &key_of(&a[1])?, &ap)
        }
        "loadApprovedGoal" => {
            let (o, k) = (&a[2], stub(s(&a[2]["kmode"])));
            let lo =
                rv::LoadOpts { kernel: &k, reviewers: &o["reviewers"], ontology_digest: o.get("ontology_digest"), now: o.get("now"), limits: o.get("limits") };
            Ok(rv::load_approved_goal(&a[0], &a[1], &lo))
        }
        other => Err(format!("skip:{other}")),
    }
}
#[test]
fn review_corpus() {
    drive("goal-review", 400, &run_review);
}
#[test]
fn proved_kernel_compiles_and_decides() {
    let k = rv::proved_kernel();
    assert!(k.decide.is_some() && k.analyze.is_none() && k.newly_allowed.is_none());
}

// ---- roundtrip ----------------------------------------------------------------------------------------------------------------------

fn explainer_of(mode: &str) -> impl Fn(&[String]) -> Res<String> + '_ {
    move |p: &[String]| if mode == "throw" { Err("boom".to_string()) } else { Ok(p.join("\n")) }
}
fn comparator_of(mode: &str) -> impl Fn(&str, &str) -> Res<Value> + '_ {
    move |_t: &str, e: &str| match mode {
        "throw" => Err("boom".to_string()),
        "ok" => Ok(json!({"equivalent": true})),
        "no" => Ok(json!({"equivalent": false, "reason": "x"})),
        m => Ok(json!({"equivalent": e.contains(m.get(9..).unwrap_or(""))})),
    }
}
fn run_roundtrip(f: &str, a: &[Value]) -> Res<Value> {
    match f {
        "cardRoundTrips" => rt::card_round_trips(&a[0]).map(Value::Bool),
        "mutateGoal" => rt::mutate_goal(&a[0], s(&a[1]), &a[2]).map(opt_null),
        "roundTrip" => Ok(json!(rt::round_trip(&a[0], s(&a[1]), &explainer_of(s(&a[2])), &comparator_of(s(&a[3]))))),
        "measureDetection" => rt::measure_detection(arr(&a[0]), &a[1], &explainer_of(s(&a[2])), &comparator_of(s(&a[3]))).map(Value::Array),
        other => Err(format!("skip:{other}")),
    }
}
#[test]
fn roundtrip_corpus() {
    drive("goal-roundtrip", 70, &run_roundtrip);
}

// ---- selectors ------------------------------------------------------------------------------------------------------------------------

fn run_selectors(f: &str, a: &[Value]) -> Res<Value> {
    let verbs = |v: Vec<Value>| Ok(Value::Array(v));
    match f {
        "selCatalogOfDomain" | "catalogOfDomain" => sel::sel_catalog_of_domain(s(&a[0])),
        "catalogOfDefs" => sel::sel_catalog_of_defs(arr(&a[0])),
        "selCatalogDigest" => sel::sel_catalog_digest(&cat(&a[0])).map(Value::String),
        "selGoalDigest" => sel::sel_goal_digest(&a[0]).map(Value::String),
        "classVerbs" => verbs(sel::class_verbs(&cat(&a[0]), &a[1], &a[2])),
        "allowClassVerbs" => verbs(sel::allow_class_verbs(&cat(&a[0]), &a[1], &a[2])),
        "floatClassVerbs" => verbs(sel::float_class_verbs(&cat(&a[0]), &a[1], &a[2])),
        "resolveRole" => Ok(opt_null(sel::resolve_role(&ir_ont(&a[0]), &cat(&a[1]), &a[2], &a[3]))),
        "expandSelGoal" => sel::expand_sel_goal(&a[0], &ir_ont(&a[1]), &cat(&a[2])),
        "selReasons" => sel::sel_reasons(&a[0], &ir_ont(&a[1]), &cat(&a[2])).map(|v| json!(v)),
        "renderSelCard" => sel::render_sel_card(&a[0], &ir_ont(&a[1]), &cat(&a[2])),
        "selCarrier" => sel::sel_carrier(&a[0]),
        "encodeSelCatalog" => sel::encode_sel_catalog(&cat(&a[0])),
        "withRoleParams" => sel::with_role_params(&a[0], &cat(&a[1])),
        "traitClosure" => sel::trait_closure(&strs(&a[0])).map(|v| json!(v)),
        other => Err(format!("skip:{other}")),
    }
}
#[test]
fn selectors_corpus() {
    drive("goal-selectors", 700, &run_selectors);
}

// ---- nversion and disambiguate ----------------------------------------------------------------------------------------------------------

fn run_nversion(f: &str, a: &[Value]) -> Res<Value> {
    match f {
        "meet" => nv::meet(arr(&a[0])),
        "meetGrants" => Ok(Value::Array(nv::meet_grants(arr(&a[0]), arr(&a[1])))),
        "checkPanel" => Ok(Value::Array(nv::check_panel(arr(&a[0])))),
        "nVersion" => nv::n_version(arr(&a[0]), &dis::QOpts::new(&a[1]), a[2].as_f64()),
        "questions" => dis::questions(arr(&a[0]), &dis::QOpts::new(&a[1])).map(Value::Array),
        "disagreementMass" => dis::disagreement_mass(arr(&a[0]), &a[1]).map(|x| json!(x)),
        "allowsWitness" => dis::allows_witness(&a[0], &a[1], &a[2]).map(Value::Bool),
        "disambiguate" => {
            let (readings, o, mode) = (arr(&a[0]), &a[1], s(&a[2]).to_string());
            let ask = |q: &Value| -> Res<String> {
                let allow = match mode.as_str() {
                    "allow" => true,
                    "deny" => false,
                    m => {
                        let i: usize = m.strip_prefix("truth:").and_then(|x| x.parse().ok()).ok_or("mode")?;
                        dis::allows_witness(&readings[i]["goal"], o, q)?
                    }
                };
                Ok(if allow { "allow" } else { "deny" }.to_string())
            };
            let mut opts = dis::QOpts::new(o);
            opts.budget = a[3].as_u64().map(|b| b as usize);
            dis::disambiguate(readings, &ask, &opts)
        }
        other => Err(format!("skip:{other}")),
    }
}
#[test]
fn nversion_corpus() {
    drive("goal-nversion", 90, &run_nversion);
}

// ---- bench --------------------------------------------------------------------------------------------------------------------------------

fn spec_of(id: &str) -> Res<(&'static str, f64, f64)> {
    bn::SIM_SPECS.iter().copied().find(|x| x.0 == id).ok_or_else(|| format!("unknown model {id}"))
}
fn run_bench(f: &str, a: &[Value]) -> Res<Value> {
    match f {
        "rngSeq" => {
            let mut r = bn::Rng::new(a[0].as_f64().ok_or("seed")?);
            Ok(Value::Array((0..a[1].as_u64().unwrap_or(0)).map(|_| json!(r.next())).collect()))
        }
        "generateCases" => {
            bn::generate_cases(s(&a[0]), a[1].as_u64().unwrap_or(0) as usize, a[2].as_f64().ok_or("seed")?, a[3].as_i64(), a[4] == true).map(Value::Array)
        }
        "simulateOutputOf" => bn::simulate_output(&a[0], spec_of(s(&a[1]))?).map(Value::String),
        "truthGoalOf" => bn::truth_goal(&a[0]),
        "recordFixturesOf" => bn::record_fixtures(arr(&a[0])),
        "caseSetDigest" => bn::case_set_digest(arr(&a[0])).map(Value::String),
        "evalCaseOf" => {
            let rec = bn::record_fixtures(std::slice::from_ref(&a[0]))?;
            let out = bn::eval_case(&a[0], &bn::replay_completions(&rec), 12, false);
            out
        }
        "compileWideningOf" => {
            let mut items = vec![];
            for c in arr(&a[0]) {
                let goal = bn::truth_goal(c)?;
                let o = bn::truth_ont(c, &goal)?;
                items.push(json!({"goal": goal, "ont": o}));
            }
            bn::compile_widening_count(&items, None)
        }
        "runDomainOf" => {
            let rec = bn::record_fixtures(arr(&a[1]))?;
            bn::run_domain(s(&a[0]), arr(&a[1]), &rec, "recorded-fixtures", false)
        }
        "summarizeOf" => bn::summarize(s(&a[0]), arr(&a[1]), s(&a[2]), a[3].as_object().map(|_| &a[3])),
        other => Err(format!("skip:{other}")),
    }
}
#[test]
fn bench_corpus() {
    drive("goal-bench", 450, &run_bench);
}
