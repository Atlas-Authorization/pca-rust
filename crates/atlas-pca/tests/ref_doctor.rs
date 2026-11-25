//! Differential replay of the deployment doctor (scrubbing, clock / proxy / suites / root-caveat / enforcement checks, results
//! formatting, configuration, command line, whole runs) against the TypeScript reference (test-data/ref-doctor.json.gz). The fake
//! fetch / clock of the generator are named tables, replayed here as closures; the fake library stand-in is a closure over the
//! same seven named behaviours. A reference throw only requires a refusal; the message is compared exactly only for the errors the
//! reference raises itself (configFromEnv, mergeConfig, parseDoctorArgs).
//! Skipped (counted, must stay under 10%): cases whose arguments carry a lone surrogate (a Rust string cannot hold one).
//! Not replayed: the replay-store checks (they need an adapter; the store-conformance corpus covers them).
mod common;
use atlas_pca::doctor::*;
use atlas_pca::serde_json::{json, Map, Value};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;

/// The fake fetch / clock of the generator: each fetch pops the next entry of its url (the last repeats), advances the clock by
/// `rtt` BEFORE answering, and fails with `throw` when set.
struct Env {
    t: Cell<f64>,
    idx: RefCell<HashMap<String, usize>>,
    responses: Value,
}

impl Env {
    fn new(spec: &Value) -> Env {
        Env { t: Cell::new(spec["now"].as_f64().unwrap()), idx: RefCell::new(HashMap::new()), responses: spec["responses"].clone() }
    }
    fn fetch(&self, url: &str, _init: &FetchInit) -> Result<FetchResponse, String> {
        let lst = self.responses.get(url).and_then(Value::as_array).ok_or_else(|| format!("no route {url}"))?;
        let i = {
            let mut m = self.idx.borrow_mut();
            let e = m.entry(url.to_string()).or_insert(0);
            let i = *e;
            *e += 1;
            i
        };
        let rsp = &lst[i.min(lst.len() - 1)];
        self.t.set(self.t.get() + rsp.get("rtt").and_then(Value::as_f64).unwrap_or(0.0));
        if let Some(t) = rsp.get("throw").and_then(Value::as_str).filter(|t| !t.is_empty()) {
            return Err(t.to_string());
        }
        let mut headers = vec![];
        if let Some(d) = rsp.get("date").and_then(Value::as_str) {
            headers.push(("date".to_string(), d.to_string()));
        }
        if let Some(r) = rsp.get("rl").and_then(Value::as_str) {
            headers.push(("ratelimit-remaining".to_string(), r.to_string()));
        }
        Ok(FetchResponse { status: 200, headers })
    }
}

/// The named fake library stand-in: decide() of a root grant under one of seven behaviours.
fn fake_decide(behavior: &str, cav: &Value, amount: f64) -> Result<Value, String> {
    match behavior {
        "throws" => return Err("boom".to_string()),
        "allow-all" => return Ok(json!({ "releaseGuardianShare": true, "reasons": [] })),
        "deny-all" => return Ok(json!({ "releaseGuardianShare": false, "reasons": ["denied", 7] })),
        "nonarray-reasons" => return Ok(json!({ "releaseGuardianShare": false, "reasons": "x" })),
        _ => {}
    }
    if cav["type"] == "max_spend" {
        if behavior == "ignore-max" {
            return Ok(json!({ "releaseGuardianShare": true, "reasons": [] }));
        }
        let usd = cav["usd"].as_f64().unwrap();
        return Ok(if amount <= usd {
            json!({ "releaseGuardianShare": true, "reasons": [] })
        } else {
            json!({ "releaseGuardianShare": false, "reasons": ["over max_spend"] })
        });
    }
    if behavior == "ignore-unknown" {
        return Ok(json!({ "releaseGuardianShare": true, "reasons": [] }));
    }
    Ok(json!({ "releaseGuardianShare": false, "reasons": ["unknown caveat type"] }))
}

fn fake_load(spec: &Value, _dir: Option<&str>) -> Result<LoadedPca, String> {
    if let Some(t) = spec.get("throws").and_then(Value::as_str).filter(|t| !t.is_empty()) {
        return Err(t.to_string());
    }
    let behavior = spec["behavior"].as_str().unwrap().to_string();
    Ok(LoadedPca {
        version: spec["version"].as_str().unwrap().to_string(),
        path: spec["path"].as_str().unwrap().to_string(),
        probe: Box::new(move |cv, amount| fake_decide(&behavior, cv, amount)),
    })
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect()
}

fn headers_value(h: Vec<(String, String)>) -> Value {
    Value::Object(h.into_iter().map(|(k, v)| (k, Value::String(v))).collect::<Map<String, Value>>())
}

fn consts() -> Value {
    json!({
        "USAGE": USAGE, "CHECK_GROUPS": CHECK_GROUPS, "DEFAULT_REQUIRED": DEFAULT_REQUIRED, "ROOT_CAVEAT_MIN_VERSION": ROOT_CAVEAT_MIN_VERSION,
        "DEFAULT_REFERENCE_URL": DEFAULT_REFERENCE_URL, "SUITES_REMEDIATION": SUITES_REMEDIATION, "PQ_REMEDIATION": PQ_REMEDIATION,
        "CLOCK_REMEDIATION": CLOCK_REMEDIATION, "PROXY_REMEDIATION": PROXY_REMEDIATION, "ATOMICITY_REMEDIATION": ATOMICITY_REMEDIATION,
        "DURABILITY_REMEDIATION": DURABILITY_REMEDIATION, "CAVEAT_REMEDIATION": CAVEAT_REMEDIATION,
    })
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "consts" => Ok(consts()),
        "scrubText" => Ok(Value::String(scrub_text(&a[0]))),
        "scrubDeep" => Ok(scrub_deep(&a[0])),
        "checkAllowedSuites" => Ok(check_allowed_suites(&a[0])),
        "checkPqBinding" => check_pq_binding(&a[0]),
        "checkProxyConfig" => Ok(check_proxy_config(&a[0])),
        "checkEnforcement" => check_enforcement(&a[0]),
        "testNetIp" => Ok(Value::String(test_net_ip(&mut mulberry32(a[0].as_f64().unwrap() as u32)))),
        "forgedHeaders" => Ok(headers_value(forged_headers(&mut mulberry32(a[0].as_f64().unwrap() as u32)))),
        "compareVersion" => Ok(json!(compare_version(a[0].as_str().ok_or("skip")?, a[1].as_str().ok_or("skip")?))),
        "checkClock" => {
            let env = Env::new(&a[1]);
            let (fetch, now) = (|u: &str, i: &FetchInit| env.fetch(u, i), || env.t.get());
            Ok(check_clock(&a[0], &fetch, &now))
        }
        "readDate" => {
            let env = Env::new(&a[1]);
            let (fetch, now) = (|u: &str, i: &FetchInit| env.fetch(u, i), || env.t.get());
            Ok(match read_date("https://api.example.com", &fetch, &now, 1000.0) {
                Ok(r) => json!({ "offsetMs": r.offset_ms, "uncertaintyMs": r.uncertainty_ms }),
                Err(e) => json!({ "error": e }),
            })
        }
        "checkProxyProbe" => {
            let env = Env::new(&a[1]);
            let fetch = |u: &str, i: &FetchInit| env.fetch(u, i);
            let mut rand = mulberry32(7);
            check_proxy_probe(&a[0], &fetch, &mut rand)
        }
        "checkRootCaveats" => {
            let load = |d: Option<&str>| fake_load(&a[1], d);
            Ok(check_root_caveats(&a[0], Some(&load)))
        }
        "configProblems" => Ok(json!(config_problems(&a[0]))),
        "verdictOf" => Ok(json!(verdict_of(a[0].as_array().unwrap(), a.get(1).and_then(Value::as_bool).unwrap_or(false)))),
        "formatResults" => Ok(json!(format_results(a[0].as_array().unwrap(), a[1].as_str(), a.get(2).and_then(Value::as_bool).unwrap_or(false)))),
        "configFromEnv" => config_from_env(&a[0]),
        "mergeConfig" => merge_config(a),
        "parseDoctorArgs" => parse_doctor_args(&strs(&a[0])),
        "main" => {
            let (mut out, mut err) = (vec![], vec![]);
            let no_net = |_: &str, _: &FetchInit| -> Result<FetchResponse, String> { Err("no network in a replay".to_string()) };
            let deps = DoctorDeps { fetch: Some(&no_net), ..Default::default() };
            let code = atlas_pca::doctor::main(&strs(&a[0]), &a[1], &mut |s| out.push(s.to_string()), &mut |s| err.push(s.to_string()), &deps);
            Ok(json!({ "code": code, "out": out, "err": err }))
        }
        "runDoctor" => {
            let env = Env::new(&a[2]);
            let (fetch, now) = (|u: &str, i: &FetchInit| env.fetch(u, i), || env.t.get());
            let load = |d: Option<&str>| fake_load(&a[3], d);
            let deps = DoctorDeps { fetch: Some(&fetch), now: Some(&now), load_pca: Some(&load), ..Default::default() };
            let only: Option<Vec<String>> = a[1].as_array().map(|_| strs(&a[1]));
            let only_refs: Option<Vec<&str>> = only.as_ref().map(|v| v.iter().map(String::as_str).collect());
            Ok(Value::Array(run_doctor(&a[0], only_refs.as_deref(), &deps)))
        }
        f => panic!("unknown fn {f}"),
    }
}

/// Numbers compare as doubles (the reference prints 1000 for 1000.0); everything else structurally, objects unordered.
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q)),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w))),
        _ => a == b,
    }
}

/// A lone surrogate in the reference's output (a cut inside a pair) reads as the loader's sentinel; Rust writes U+FFFD there.
fn fix(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(s.replace(common::LONE, "\u{FFFD}")),
        Value::Array(a) => Value::Array(a.iter().map(fix).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), fix(x))).collect()),
        _ => v.clone(),
    }
}

#[test]
fn doctor_vectors() {
    let cases = common::ref_cases("doctor");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let args = c["args"].as_array().unwrap();
        let got = std::panic::catch_unwind(|| run(f, args)).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(m), Err(e)) => !matches!(f, "configFromEnv" | "mergeConfig" | "parseDoctorArgs") || m.as_str() == Some(e.as_str()),
            (None, Ok(v)) => same(&fix(&c["out"]), v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
