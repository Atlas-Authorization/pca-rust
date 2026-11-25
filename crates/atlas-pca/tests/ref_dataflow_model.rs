//! Differential replay of the capability-tagged data-flow model and the detector adapters against the TypeScript reference
//! (test-data/ref-dataflow.json.gz; encodings in tools/pca-audit/oracles/dataflow.mts). A reference throw only requires a
//! refusal (an `Err`). Skipped, because tests/ref_dataflow.rs replays them from test-data/ref-dataflow-rs.json.gz:
//! parseTraceRule, parseInvariantRule, compileTraceRules, lethalTrifecta, traceConsts and categoryId (about 31% of the corpus
//! by count but zero native logic here). Also skipped: a detector case whose arguments hold a lone surrogate (a Rust string
//! cannot carry one; the loader's sentinel is asserted to match a reference refusal instead).
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::dataflow_detectors::*;
use atlas_pca::dataflow_model::*;
use atlas_pca::serde_json::{json, Value};

enum Spec {
    T(Tagged),
    Raw,
}

fn spec(v: &Value) -> Result<Spec, String> {
    if let Some(o) = v.as_object() {
        if o.contains_key("$raw") {
            return Ok(Spec::Raw);
        }
        if let Some(inner) = o.get("$t") {
            return Ok(Spec::T(tag(inner.clone(), &Capability::from_json(o.get("cap").unwrap_or(&Value::Null))?)?));
        }
    }
    Ok(Spec::Raw)
}

fn tagged(s: &Spec) -> Option<&Tagged> {
    match s {
        Spec::T(t) => Some(t),
        Spec::Raw => None,
    }
}

fn readers(opts: &Value) -> Option<Vec<String>> {
    opts.get("readers")?.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
}

fn caps(v: &Value) -> Result<Vec<Capability>, String> {
    v.as_array().ok_or("caps must be a list")?.iter().map(Capability::from_json).collect()
}

fn detector(f: &str, a: &[Value]) -> Result<Value, String> {
    let c = &a[1];
    let kp = KeyPair::from_seed_b64u(c["secretKey"]["$bytes"].as_str().ok_or("no seed")?)?;
    let ctx = AdapterContext {
        detector: c["detector"].as_str().ok_or("detector")?.to_string(),
        version: c["version"].as_str().ok_or("version")?.to_string(),
        content: c["content"].clone(),
        secret_key: &kp,
        now: c["now"].clone(),
        session: c.get("session").cloned(),
        calibration_ref: c.get("calibration_ref").cloned(),
    };
    match f {
        "lakeraReceipt" => lakera_receipt(&a[0], &ctx),
        "promptSecurityReceipt" => prompt_security_receipt(&a[0], &ctx),
        _ => generic_receipt(&a[0], &ctx),
    }
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let s = |i: usize| a[i].as_str().unwrap_or("");
    Ok(match f {
        "tag" => tag(a[0].clone(), &Capability::from_json(&a[1])?)?.to_json(),
        "fromTrustedQuery" => from_trusted_query(a[0].clone(), readers(&a[1]).as_deref()).to_json(),
        "fromToolOutput" => from_tool_output(s(0), a[1].clone(), readers(&a[2]).as_deref()).to_json(),
        "fromSource" => from_source(s(0), a[1].clone(), a[2].get("isTrusted") == Some(&json!(true)), readers(&a[2]).as_deref())?.to_json(),
        "unionSources" => json!(union_sources(&caps(&a[0])?)),
        "combineCaps" => combine_caps(&caps(&a[0])?).to_json(),
        "derive" => {
            let specs = a[0].as_array().ok_or("inputs")?.iter().map(spec).collect::<Result<Vec<_>, _>>()?;
            let ins: Vec<Tagged> =
                specs.iter().map(|x| tagged(x).cloned().ok_or("derive: every input must be a tagged value made by this module")).collect::<Result<_, _>>()?;
            let name = s(1).to_string();
            derive(&ins, |vs| match name.as_str() {
                "count" => Ok(json!(vs.len())),
                "pair" => Ok(Value::Array(vs.to_vec())),
                "first" => Ok(vs.first().cloned().unwrap_or(Value::Null)),
                _ => Err("combiner failed".to_string()),
            })?
            .to_json()
        }
        "classifyFlow" => classify_flow(tagged(&spec(&a[0])?), &Sink::from_json(&a[1])).to_json(),
        "canFlow" => {
            let (ok, reason) = can_flow(tagged(&spec(&a[0])?), &Sink::from_json(&a[1]));
            reason.map_or(json!({"ok": ok}), |r| json!({"ok": ok, "reason": r}))
        }
        "checkAction" => {
            let specs: Vec<Option<Spec>> = a[1]
                .as_array()
                .ok_or("args")?
                .iter()
                .map(|x| if x.is_null() || x.get("$hole") == Some(&json!(true)) { Ok(None) } else { spec(x).map(Some) })
                .collect::<Result<_, String>>()?;
            let args: Vec<Arg> = a[1]
                .as_array()
                .unwrap()
                .iter()
                .zip(&specs)
                .map(|(raw, sp)| match sp {
                    Some(Spec::T(t)) => Arg::Tagged(t),
                    Some(Spec::Raw) => Arg::Untagged,
                    None if raw.is_null() => Arg::Undefined,
                    None => Arg::Hole,
                })
                .collect();
            let gov = a[2].clone();
            let governor = move |_: &Value| -> Result<Sink, String> {
                if gov.get("throws") == Some(&json!(true)) {
                    Err("governor failed".into())
                } else {
                    Ok(Sink::from_json(gov.get("sink").unwrap_or(&Value::Null)))
                }
            };
            check_action(&a[0], &args, &governor, a[3].get("expectedArgs").and_then(Value::as_f64)).to_json()
        }
        "dualContext" => {
            let d = &a[0];
            let q = spec(&d["query"])?;
            let (plan, quar) = (d["plan"].as_str().unwrap_or("").to_string(), d["quarantine"].as_str().unwrap_or("").to_string());
            let (p, r) = dual_context(
                tagged(&q),
                |v| match plan.as_str() {
                    "identity" => Ok(v.clone()),
                    "wrap" => Ok(json!({"planned": v})),
                    _ => Err("planner failed".to_string()),
                },
                |p| match quar.as_str() {
                    "tagged_untrusted" => Ok(Some(from_tool_output("quarantine", p.clone(), None))),
                    "trusted" => Ok(Some(from_trusted_query(p.clone(), None))),
                    "raw" => Ok(None),
                    _ => Err("q failed".to_string()),
                },
            )?;
            json!({"plan": p, "result": r.to_json()})
        }
        "externalSendSink" => external_send_sink(s(0)).to_json(),
        "sensitiveSink" => sensitive_sink(s(0)).to_json(),
        "levelOf" => json!(level_of(tagged(&spec(&a[0])?))),
        "consts" => json!({"TRUSTED_QUERY": TRUSTED_QUERY, "tool": tool_provenance("x"), "tool2": tool_provenance("")}),
        "lakeraReceipt" | "promptSecurityReceipt" | "genericReceipt" => detector(f, a)?,
        f => panic!("unknown fn {f}"),
    })
}

const COVERED_ELSEWHERE: [&str; 6] = ["parseTraceRule", "parseInvariantRule", "compileTraceRules", "lethalTrifecta", "traceConsts", "categoryId"];

#[test]
fn dataflow_model_vectors() {
    let cases = common::ref_cases_seeded("dataflow");
    let (mut bad, mut ran, mut skipped) = (Vec::new(), 0, 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if COVERED_ELSEWHERE.contains(&f) {
            continue;
        }
        let args = c["args"].as_array().unwrap();
        let want_throw = c["out"].get("$throws").is_some();
        if Value::Array(args.clone()).to_string().contains(common::LONE) {
            assert!(want_throw, "{}: a lone surrogate must be a reference refusal", c["name"]);
            skipped += 1;
            continue;
        }
        ran += 1;
        match (run(f, args), want_throw) {
            (Err(_), true) => {}
            (Ok(got), false) if atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(&got) => {}
            (got, _) => bad.push(format!("{}\n  want {}\n  got  {got:?}", c["name"], c["out"])),
        }
    }
    assert!(skipped * 10 < ran, "too many skipped: {skipped} of {ran}");
    assert!(bad.is_empty(), "{} of {ran} cases differ:\n{}", bad.len(), bad.join("\n"));
}
