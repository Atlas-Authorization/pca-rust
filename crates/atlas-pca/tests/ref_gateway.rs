//! Differential replay of the gateway (canonical query, request binding, path hardening, replay guard, provenance log, presented
//! artifacts, authorize / create_gateway over real signed proofs, the Envoy HTTP / gRPC shapes and the Lambda authorizers) against the
//! TypeScript reference (test-data/ref-gateway.json.gz). A reference throw only requires a refusal.
//! Compared after masking: verdict objects print "<verdict>" and the strict-JSON parser's own message in
//! "undecodable PCA-Action header: <message>" prints "<json>".
//! Skipped (counted, must stay under 10%): cases whose arguments hold a lone surrogate (a Rust string cannot).
//! Not in the corpus and not ported: the Cloudflare Worker adapter (runs JavaScript); full-policy mode runs through the core authorize.
mod common;
use atlas_pca::gateway::*;
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::{AuthorizeOptions, MemoryStateStore};
use std::sync::Arc;

// ---- masking ---------------------------------------------------------------------------------------------------------

fn mask_str(s: &str) -> String {
    let pfx = "undecodable PCA-Action header: ";
    let mut from = 0;
    while let Some(i) = s[from..].find(pfx) {
        let at = from + i;
        if !s[at + pfx.len()..].starts_with("PCA-Action header") {
            return format!("{}{}<json>", &s[..at], pfx);
        }
        from = at + pfx.len();
    }
    s.to_string()
}

fn mask(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(mask_str(s)),
        Value::Array(a) => Value::Array(a.iter().map(mask).collect()),
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, x) in m {
                let verdict = (k == "x-pca-verdict" || k == "pcaVerdict") && x.as_str().is_some_and(|s| !s.is_empty());
                out.insert(k.clone(), if verdict { json!("<verdict>") } else { mask(x) });
            }
            if let Some(h) = out.get("header").and_then(Value::as_object) {
                if h.get("key").and_then(Value::as_str) == Some("x-pca-verdict") && h.get("value").and_then(Value::as_str) != Some("") {
                    let mut h2 = h.clone();
                    h2.insert("value".into(), json!("<verdict>"));
                    out.insert("header".into(), Value::Object(h2));
                }
            }
            Value::Object(out)
        }
        v => v.clone(),
    }
}

// ---- options from a scenario spec -------------------------------------------------------------------------------------

struct Fixed(bool);
impl ReplayGuard for Fixed {
    fn claim(&self, _: &str, _: f64, _: f64) -> Result<bool, String> {
        Ok(self.0)
    }
}
struct Raising;
impl ReplayGuard for Raising {
    fn claim(&self, _: &str, _: f64, _: f64) -> Result<bool, String> {
        Err("store down".into())
    }
}

fn rev(f: impl Fn(&Value) -> Result<Value, String> + Send + Sync + 'static) -> Option<RevocationHook> {
    Some(Arc::new(f))
}
fn cp(f: impl Fn(&Value) -> Result<Value, String> + Send + Sync + 'static) -> CheckProofFn {
    Arc::new(f)
}
fn rg(g: impl ReplayGuard + 'static) -> Option<Arc<dyn ReplayGuard>> {
    Some(Arc::new(g))
}

fn build_opts(spec: &Value) -> GatewayOptions {
    let now = spec["now"].as_i64().unwrap();
    let grants = spec["grants"].clone();
    let mut o = GatewayOptions::default();
    o.audience = spec["audience"].as_str().unwrap().to_string();
    o.routes = spec["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| RouteRule {
            method: r.get("method").and_then(Value::as_str).map(String::from),
            path: r["path"].as_str().unwrap().to_string(),
            capability: RequiredCapability {
                verb: r["capability"]["verb"].as_str().unwrap().to_string(),
                resource: r["capability"].get("resource").and_then(Value::as_str).map(String::from),
            },
        })
        .collect();
    let resolve: ResolveGrantFn =
        Arc::new(move |r: &Value, _: &Value| -> Result<Option<Value>, String> { Ok(r.as_str().and_then(|k| grants.get(k)).cloned()) });
    o.resolve_grant = Some(resolve);
    let now_fn: NowFn = Arc::new(move || now);
    o.now = Some(now_fn);
    o.bind_request = match spec.get("bindRequest") {
        None | Some(Value::Null) => BindRequest::Default,
        Some(Value::String(s)) if s == "off" => BindRequest::Off,
        Some(b) => BindRequest::On(BindOptions {
            authority: b.get("authority").and_then(Value::as_bool).unwrap_or(false),
            body: b.get("body").and_then(Value::as_bool),
        }),
    };
    o.unmatched_route = spec.get("unmatched").and_then(Value::as_str).map(String::from);
    o.path_policy = spec.get("pathPolicy").and_then(Value::as_str).map(String::from);
    o.require_checks = spec.get("requireChecks").and_then(Value::as_array).map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect());
    o.realm = spec.get("realm").and_then(Value::as_str).map(String::from);
    o.insecure_skip_plan_root_check = spec.get("skipPlan") == Some(&json!(true));
    o.authorized_plan_roots = spec.get("planRoots").and_then(Value::as_array).map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect());
    let clock: Arc<dyn Fn() -> f64 + Send + Sync> = Arc::new(move || now as f64);
    let clock2 = clock.clone();
    o.replay_guard = match spec["replay"].as_str().unwrap() {
        "none" => None,
        "always" => rg(Fixed(true)),
        "false" => rg(Fixed(false)),
        "throws" => rg(Raising),
        "memory" => rg(MemoryReplayGuard::new(100_000, clock)),
        "memory-full" => rg(MemoryReplayGuard::new(1, clock2)),
        other => panic!("replay {other}"),
    };
    o.revocation = match spec["revocation"].as_str().unwrap() {
        "none" => None,
        "ok" => rev(|_: &Value| Ok(json!({"enforced": true, "ok": true}))),
        "revoked" => rev(|_: &Value| Ok(json!({"enforced": true, "ok": false, "reason": "grant revoked"}))),
        "revoked-noreason" => rev(|_: &Value| Ok(json!({"enforced": true, "ok": false}))),
        "notEnforced" => rev(|_: &Value| Ok(json!({"enforced": false}))),
        "throws" => rev(|_: &Value| Err("rev down".to_string())),
        other => panic!("revocation {other}"),
    };
    o.check_proof = spec.get("checkProof").and_then(Value::as_str).map(|k| -> CheckProofFn {
        match k {
            "true" => cp(|_| Ok(json!(true))),
            "false" => cp(|_| Ok(json!(false))),
            "obj-true" => cp(|_| Ok(json!({"allow": true}))),
            "obj-false" => cp(|_| Ok(json!({"allow": false}))),
            "obj-false-reason" => cp(|_| Ok(json!({"allow": false, "reason": "over limit"}))),
            "throws" => cp(|_| Err("policy down".to_string())),
            other => panic!("checkProof {other}"),
        }
    });
    o.policy = match spec["policy"].as_str().unwrap() {
        "sig" => Some(Policy::SignatureOnly),
        "bogus" => Some(Policy::Unknown("bogus".into())),
        "full-missing" => {
            let mut fp = FullPolicy::new(ParamsSource::Body, AuthorizeOptions::new(Arc::new(MemoryStateStore::new()), |_, _| Ok(false)));
            fp.options = None;
            Some(Policy::Full(Box::new(fp)))
        }
        _ => None,
    };
    o
}

fn proj(d: &Decision) -> Value {
    let mut headers = Map::new();
    for (k, v) in &d.headers {
        headers.insert(k.clone(), json!(v));
    }
    let mut out = Map::new();
    out.insert("allow".into(), json!(d.allow));
    out.insert("status".into(), json!(d.status));
    out.insert("code".into(), json!(d.code));
    out.insert("reason".into(), json!(d.reason));
    out.insert("headers".into(), Value::Object(headers));
    if let Some(m) = &d.matched {
        out.insert("matched".into(), m.to_value());
    }
    if let Some(gr) = d.pcactn.as_ref().and_then(|p| p.get("grant_ref")) {
        out.insert("grant".into(), gr.clone());
    }
    if let Some(a) = d.verdict.as_ref().and_then(|v| v.get("allow")) {
        out.insert("verdictAllow".into(), a.clone());
    }
    mask(&Value::Object(out))
}

fn authorize_scenario(spec: &Value) -> Value {
    let gw = match create_gateway(build_opts(spec)) {
        Ok(g) => g,
        Err(e) => return json!({ "create": e }),
    };
    Value::Array(spec["requests"].as_array().unwrap().iter().map(|r| proj(&gw.authorize(r))).collect())
}

fn adapter(spec: &Value, f: impl Fn(&Gateway, &Value) -> Value) -> Value {
    match create_gateway(build_opts(spec)) {
        Ok(gw) => mask(&f(&gw, &spec["events"][0])),
        Err(e) => json!({ "create": e }),
    }
}

fn replay_scenario(spec: &Value) -> Value {
    let clock = Arc::new(std::sync::atomic::AtomicI64::new(spec["clock"].as_i64().unwrap_or(0)));
    let c2 = clock.clone();
    let g = MemoryReplayGuard::new(spec["max"].as_u64().unwrap() as usize, Arc::new(move || c2.load(std::sync::atomic::Ordering::SeqCst) as f64));
    let mut out = Vec::new();
    for op in spec["ops"].as_array().unwrap() {
        if let Some(c) = op.get("setClock") {
            clock.store(c.as_i64().unwrap(), std::sync::atomic::Ordering::SeqCst);
            continue;
        }
        out.push(match g.claim_at(op["key"].as_str().unwrap(), op["exp"].as_f64().unwrap(), op.get("now").and_then(Value::as_f64)) {
            Ok(b) => json!(b),
            Err(e) => json!({ "threw": e }),
        });
    }
    Value::Array(out)
}

fn prov_scenario(spec: &Value) -> Value {
    let l = MemoryProvenanceLog::new(spec["max"].as_u64().unwrap() as usize);
    let mut out = Vec::new();
    for op in spec["ops"].as_array().unwrap() {
        if op.get("add").is_some_and(|a| a != &json!(0)) {
            l.add(op["session"].as_str().unwrap(), &op["o"]);
            out.push(json!("added"));
        } else {
            out.push(Value::Array(l.seen(op["session"].as_str().unwrap())));
        }
    }
    Value::Array(out)
}

fn presented_req(rq: &Value) -> Value {
    let mut m = json!({"method": "POST", "path": "/"});
    for (k, v) in rq.as_object().unwrap() {
        m[k.as_str()] = v.clone();
    }
    m
}

fn params_of(kind: &str) -> ParamsSource {
    if kind == "body" {
        ParamsSource::Body
    } else {
        ParamsSource::Func(Arc::new(|_| Some(json!({}))))
    }
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let opt1 = a.get(1).filter(|v| !v.is_null());
    match f {
        "canonicalQuery" => match &a[0] {
            Value::String(s) => canonical_query(s).map(Value::String),
            _ => Err("query is not a string".into()),
        },
        "requestBinding" => request_binding(&a[0], opt1),
        "bindParams" => bind_params(&a[0], opt1),
        "ambiguousPathReason" => Ok(ambiguous_path_reason(a[0].as_str().ok_or("path is not a string")?).map_or(Value::Null, |s| json!(s))),
        "replayScenario" => Ok(replay_scenario(&a[0])),
        "provenanceLogScenario" => Ok(prov_scenario(&a[0])),
        "presentedProvenance" => Ok(presented_provenance(&presented_req(&a[0]), &params_of(a[1].as_str().unwrap())).unwrap_or_else(|| json!({"undef": true}))),
        "presentedArtifacts" => Ok(Value::Object(presented_artifacts(&presented_req(&a[0]), &params_of(a[1].as_str().unwrap())))),
        "authorizeScenario" => Ok(authorize_scenario(&a[0])),
        "envoyScenario" => Ok(adapter(&a[0], |g, e| g.envoy_ext_authz(e))),
        "grpcScenario" => Ok(adapter(&a[0], |g, e| g.envoy_grpc_ext_authz(e))),
        "lambdaScenario" => Ok(adapter(&a[0], |g, e| g.lambda_authorizer(e))),
        "lambdaSimpleScenario" => Ok(adapter(&a[0], |g, e| g.lambda_simple_authorizer(e))),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn gateway_vectors() {
    let cases = common::ref_cases_seeded("gateway");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let got = std::panic::catch_unwind(|| run(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
