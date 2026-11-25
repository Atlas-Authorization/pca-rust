//! Differential replay of the OpenAI Agents adapter logic (proof sources, the guard pipeline, per-tool option merging, guardrails,
//! step-up) against the TypeScript reference (test-data/ref-openai-agents.json.gz). Tools, verifiers and hooks are rebuilt from the
//! corpus' declarative descriptors (a stub verifier named by tag, call logs for execute / verify / onDeny / onVerified / recorder).
//! The reference's language-specific message tails are cut on both sides ("proof could not be decoded: ...", "full policy mode is
//! missing ..."), and `withPcaTool` reads `with_pca_tool`. The `calls` log of a `pcaTools` run is the shared log as it stands after
//! every tool ran (the reference returns the one array it keeps appending to). `reviewToolCall` is replayed on the intent-null
//! (auto) path only: the rest needs the agent's `reviewAction`, which has no twin here (the closure seam is exercised by the crate's
//! own tests). Skipped (counted, must stay under 10%): cases with a lone surrogate (no Rust string).
mod common;
use atlas_pca::openai_agents::*;
use atlas_pca::serde_json::{json, Map, Value};
use std::sync::{Arc, Mutex};

type Calls = Arc<Mutex<Vec<Value>>>;

static NULL: Value = Value::Null;

fn snapshot(c: &Calls) -> Value {
    Value::Array(c.lock().unwrap().clone())
}

fn log(c: &Calls, v: Value) {
    c.lock().unwrap().push(v);
}

fn norm(m: &str) -> String {
    let mut s = m.replace("withPcaTool", "with_pca_tool");
    for pre in ["proof could not be decoded: ", "full policy mode is missing"] {
        if let Some(i) = s.find(pre) {
            s.truncate(i + pre.len());
        }
    }
    s
}

fn clean(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(norm(s)),
        Value::Array(a) => Value::Array(a.iter().map(clean).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), clean(x))).collect()),
        o => o.clone(),
    }
}

fn verb_of(p: &Value) -> Value {
    p.get("action").and_then(|a| a.get("verb")).cloned().unwrap_or(Value::Null)
}

fn stub(d: &Value, calls: &Calls) -> Verify {
    let (d, calls) = (d.clone(), calls.clone());
    Verify::Func(Arc::new(move |p: &Value| {
        log(&calls, json!(["verify", d["stub"], verb_of(p)]));
        if let Some(t) = d.get("throws").and_then(Value::as_str) {
            return Err(t.to_string());
        }
        let allow = d["allow"] == json!(true);
        let checks = json!({ "sig": if allow { "pass" } else { "fail" } });
        Ok(VerifyResult { allow, checks: Some(checks), reason: d.get("reason").and_then(Value::as_str).map(String::from) })
    }))
}

/// The proof source a `require` descriptor names: `{headers: [field?, header?]}` or `{const: proof | null}`.
fn require_of(r: &Value) -> ProofSourceFn {
    if let Some(h) = r.get("headers").and_then(Value::as_array) {
        return proof_from_input_headers(h.first().and_then(Value::as_str), h.get(1).and_then(Value::as_str));
    }
    let c = r.get("const").filter(|v| !v.is_null()).cloned();
    Arc::new(move |_i: &Value, _rc: &Value| c.clone())
}

fn build_opts(d: &Value, calls: &Calls) -> WithPcaToolOptions {
    let mut o = WithPcaToolOptions::default();
    if let Some(m) = d.get("mode") {
        o.mode = m.as_str().map(String::from);
    }
    o.verb = d.get("verb").and_then(Value::as_str).map(String::from);
    o.audience = match d.get("audience") {
        Some(Value::String(s)) => Audience::Is(s.clone()),
        Some(Value::Null) => Audience::Any,
        _ => Audience::Unset,
    };
    if let Some(v) = d.get("verify").filter(|v| !v.is_null()) {
        o.verify = Some(stub(v, calls));
    }
    if d.get("authorize").is_some_and(|a| !a.is_null()) {
        o.authorize = Some(FullPolicy::default());
    }
    if let Some(r) = d.get("require").filter(|v| !v.is_null()) {
        o.require = Some(require_of(r));
    }
    if d.get("onDeny").is_some_and(|v| !v.is_null()) {
        let c = calls.clone();
        o.on_deny = Some(Arc::new(move |e: &PcaToolDenied, i: &Value| log(&c, json!(["onDeny", e.kind, i]))));
    }
    if d.get("onVerified").is_some_and(|v| !v.is_null()) {
        let c = calls.clone();
        o.on_verified = Some(Arc::new(move |r: &VerifyResult, p: &Value, i: &Value| log(&c, json!(["onVerified", r.allow, verb_of(p), i]))));
    }
    if d.get("recorder").is_some_and(|v| !v.is_null()) {
        let c = calls.clone();
        o.recorder = Some(Arc::new(move |n: &str, out: &Value| -> Result<(), String> {
            log(&c, json!(["recorded", n, out]));
            Ok(())
        }));
    }
    o
}

fn build_tool(td: &Value, calls: &Calls) -> AgentTool {
    let name = td.get("name").and_then(Value::as_str).map(String::from);
    let throws = td.get("throws").and_then(Value::as_str).map(String::from);
    let execute: Option<ExecuteFn> = if td.get("noExecute") == Some(&json!(true)) {
        None
    } else {
        let (calls, name) = (calls.clone(), name.clone());
        Some(Arc::new(move |input: &Value, _rc: Option<&Value>| {
            let n = json!(name);
            log(&calls, json!(["exec", n, input]));
            match &throws {
                Some(t) => Err(ToolError::Tool(t.clone())),
                None => Ok(json!({ "echo": input, "tool": n })),
            }
        }))
    };
    AgentTool { name, fields: Map::new(), execute, needs_approval: None }
}

/// One call's outcome, without the `calls` log (the caller adds the log as it stands once everything ran).
fn outcome(t: &AgentTool, input: &Value, rc: Option<&Value>) -> Value {
    let Some(exec) = &t.execute else { return json!({ "err": "Error", "message": "no execute" }) };
    match exec(input, rc) {
        Ok(out) => json!({ "ok": true, "out": out, "name": t.name, "extra": null, "hasNeedsApproval": t.needs_approval.is_some() }),
        Err(ToolError::Denied(d)) => {
            let mut o = json!({ "err": "PcaToolDenied", "message": norm(&d.message), "kind": d.kind, "verb": d.verb });
            if let Some(c) = d.checks {
                o["checks"] = c;
            }
            o
        }
        Err(ToolError::Tool(m)) => json!({ "err": "Error", "message": norm(&m) }),
    }
}

fn build_error(e: &str, calls: &Calls) -> Value {
    json!({ "err": "TypeError", "message": norm(e), "calls": snapshot(calls), "build": true })
}

fn with_tool(a: &Value) -> Value {
    let calls: Calls = Arc::default();
    let tool = build_tool(&a["tool"], &calls);
    let t = match with_pca_tool(&tool, build_opts(&a["options"], &calls)) {
        Ok(t) => t,
        Err(e) => return build_error(&e, &calls),
    };
    let rc = if a.get("noRunContext") == Some(&json!(true)) { None } else { Some(a.get("runContext").unwrap_or(&NULL)) };
    let mut o = outcome(&t, &a["input"], rc);
    o["calls"] = snapshot(&calls);
    o
}

fn tools_of(a: &Value) -> Value {
    let calls: Calls = Arc::default();
    let tools: Vec<(String, Arc<AgentTool>)> = a["tools"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), Arc::new(build_tool(v, &calls)))).collect();
    let o = &a["options"];
    let mut po = PcaToolsOptions { shared: build_opts(o, &calls), ..Default::default() };
    for (k, v) in o.get("per").and_then(Value::as_object).into_iter().flatten() {
        po.per.insert(k.clone(), build_opts(v, &calls));
    }
    po.only = o.get("only").and_then(Value::as_array).map(|l| l.iter().filter_map(|x| x.as_str().map(String::from)).collect());
    let guarded = match pca_tools(&tools, &po) {
        Ok(g) => g,
        Err(e) => return build_error(&e, &calls),
    };
    let mut res = Map::new();
    for (i, (k, t)) in guarded.iter().enumerate() {
        let mut r = outcome(t, &a["input"], Some(&a["runContext"]));
        r["same"] = json!(Arc::ptr_eq(t, &tools[i].1));
        res.insert(k.clone(), r);
    }
    let all = snapshot(&calls);
    for r in res.values_mut() {
        r["calls"] = all.clone();
    }
    Value::Object(res)
}

fn guardrail_run(a: &Value) -> Value {
    let calls: Calls = Arc::default();
    let kw = build_opts(&a["options"], &calls);
    let require: Option<GuardrailSourceFn> = kw.require.clone().map(|src| -> GuardrailSourceFn { Arc::new(move |args: &Value| src(args, &NULL)) });
    let go = GuardrailOptions {
        require,
        verify: kw.verify.clone(),
        audience: kw.audience.clone(),
        verb: kw.verb.clone(),
        name: a["options"].get("name").and_then(Value::as_str).map(String::from),
    };
    let g = (if a["kind"] == json!("input") { pca_input_guardrail(go) } else { pca_tool_guard(go) }).unwrap();
    match g.execute(&a["args"]) {
        Ok(r) => json!({ "name": g.name, "result": r, "calls": snapshot(&calls) }),
        Err(m) => json!({ "err": "Error", "message": norm(&m), "calls": snapshot(&calls) }),
    }
}

fn step_opts(calls: &Calls) -> StepUpOptions {
    let c = calls.clone();
    let intent: IntentFn = Arc::new(move |t: &str, i: Option<&Value>| -> Option<Value> {
        log(&c, json!(["intent", t, i.cloned().unwrap_or(Value::Null)]));
        None
    });
    StepUpOptions { intent, review: None, standing: None, goal: None, now: None, renderer: None, insecure_unbound_approval: None }
}

fn review_run(a: &Value) -> Value {
    let calls: Calls = Arc::default();
    let r = review_tool_call(&NULL, a["tool"].as_str().unwrap(), a.get("input"), &step_opts(&calls)).unwrap();
    json!({ "r": r, "calls": snapshot(&calls) })
}

fn needs_run(a: &Value) -> Value {
    let calls: Calls = Arc::default();
    let opts = NeedsApprovalOptions {
        step: step_opts(&calls),
        tool_name: a.get("toolName").and_then(Value::as_str).map(String::from),
        approved: None,
        on_step_up: None,
        deny_needs_approval: None,
    };
    if a["via"] == json!("direct") {
        let f = pca_needs_approval(Value::Null, opts);
        let value = f(&json!({}), &a["input"], Some("c1")).unwrap();
        return json!({ "value": value, "calls": snapshot(&calls) });
    }
    let one: ExecuteFn = Arc::new(|_i: &Value, _rc: Option<&Value>| -> Result<Value, ToolError> { Ok(json!(1)) });
    let tool =
        AgentTool { name: a["tool"].get("name").and_then(Value::as_str).map(String::from), fields: Map::new(), execute: Some(one), needs_approval: None };
    let t = with_approval(&tool, Value::Null, opts);
    let value = (**t.needs_approval.as_ref().unwrap())(&json!({}), &a["input"], Some("c1")).unwrap();
    json!({ "value": value, "calls": snapshot(&calls), "name": t.name, "extra": null, "hasExecute": t.execute.is_some() })
}

fn run(f: &str, args: &[Value]) -> Value {
    let a = &args[0];
    let opt = |s: Option<String>| s.map_or(Value::Null, Value::String);
    match f {
        "proofFromRunContext" => opt(proof_from_run_context(a.get("input").unwrap_or(&NULL), a.get("runContext").unwrap_or(&NULL))),
        "guardrailProofFromContext" => opt(guardrail_proof_from_context(&a["args"])),
        "provenanceFromRunContext" => provenance_from_run_context(&a["runContext"]).unwrap_or(Value::Null),
        "proofFromInputHeaders" => {
            let src = proof_from_input_headers(a.get("field").and_then(Value::as_str), a.get("header").and_then(Value::as_str));
            src(&a["input"], &NULL).unwrap_or(Value::Null)
        }
        "pendingStepUps" => pending_step_ups(a),
        "withPcaTool" => with_tool(a),
        "pcaTools" => tools_of(a),
        "guardrail" => guardrail_run(a),
        "reviewToolCall" => review_run(a),
        "needsApproval" => needs_run(a),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn openai_agents_vectors() {
    let cases = common::ref_cases("openai-agents");
    assert!(cases.len() >= 150);
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let f = c["fn"].as_str().unwrap();
        let got = std::panic::catch_unwind(|| run(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| json!("panic"));
        if atlas_pca::canonicalize(&clean(&c["out"])) != atlas_pca::canonicalize(&clean(&got)) {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
