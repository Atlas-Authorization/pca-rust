//! Differential replay of the GNAP bridge (access rights, grant requests, bound tokens, jwsd proofs, step-up continuation,
//! interaction modes and the AS state machine) against the TypeScript reference (test-data/ref-gnap.json.gz).
//! A reference throw only requires a refusal, except the interaction functions whose stable `code` must match.
//! Cases with a lone surrogate (no Rust string) are skipped.
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::gnap::*;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn key_of(v: &Value) -> Result<KeyPair, String> {
    KeyPair::from_seed_b64u(v.as_str().ok_or("secret must be a string")?)
}

fn ie(e: InteractionError) -> String {
    format!("{}|{}", e.code, e.message)
}

fn num(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 {
        json!(f as i64)
    } else {
        json!(f)
    }
}

fn body_of(v: Option<&Value>) -> GnapBody {
    match v {
        None => GnapBody::Absent,
        Some(Value::Object(m)) if m.len() == 1 && m.get("$bytes").is_some_and(Value::is_string) => {
            GnapBody::Bytes(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(m["$bytes"].as_str().unwrap()).unwrap())
        }
        Some(x) => GnapBody::Json(x.clone()),
    }
}

fn list(v: &Value) -> Vec<Value> {
    v.as_array().cloned().unwrap_or_default()
}

fn cut_json(mut r: Value) -> Value {
    if let Some(s) = r.get("reason").and_then(Value::as_str) {
        if let (Some(i), true) = (s.find("bad-json ("), s.ends_with(')')) {
            r["reason"] = json!(format!("{}bad-json", &s[..i]));
        }
    }
    r
}

fn verify_request(a: &Value) -> Result<Value, String> {
    let mode = a.get("seenProofMode").and_then(Value::as_str).unwrap_or("none").to_string();
    let body = body_of(a.get("body"));
    let mut args = a.clone();
    args.as_object_mut().unwrap().remove("seenProofMode");
    let mut seen: Vec<Value> = Vec::new();
    let result = {
        let mut store = |id: &str, exp: f64| -> Result<bool, String> {
            seen.push(json!([id, num(exp)]));
            match mode.as_str() {
                "fresh" => Ok(false),
                "replayed" | "undefined" => Ok(true),
                _ => Err("store down".into()),
            }
        };
        let sp: Option<SeenProof> = if mode == "none" { None } else { Some(&mut store) };
        verify_gnap_request(&args, &body, sp)?
    };
    Ok(json!({ "result": cut_json(result), "seen": seen }))
}

fn sign_request(a: &Value) -> Result<Value, String> {
    let k = a.get("key").ok_or("key")?;
    let key = key_of(&k["secretKey"])?;
    if k["publicKey"] != json!(key.public) {
        return Err("Invalid JWK OKP key".into());
    }
    sign_gnap_request(a, &body_of(a.get("body")), &key)
}

fn grant_to_cap(a: &[Value]) -> Result<Value, String> {
    let opts = a.get(1).cloned().unwrap_or(Value::Null);
    let issuer = match opts.get("issuerSecret") {
        Some(s) if s.is_string() => Some(key_of(s)?),
        _ => None,
    };
    grant_request_to_capability(&a[0], &opts, issuer.as_ref())
}

fn complete(a: &Value) -> Result<Value, String> {
    let leaf = key_of(&a["agentLeafSecret"])?;
    let cos: Option<Vec<(String, KeyPair)>> = match a.get("cosignSecrets") {
        None | Some(Value::Null) => None,
        Some(c) => Some(
            c.as_array()
                .ok_or("cosignSecrets")?
                .iter()
                .map(|x| Ok((x["role"].as_str().ok_or("role")?.to_string(), key_of(&x["secret"])?)))
                .collect::<Result<_, String>>()?,
        ),
    };
    complete_gnap_continuation(a, &leaf, cos.as_deref())
}

fn redact(v: &Value, map: &[(String, &str)]) -> Value {
    match v {
        Value::String(s) => {
            let mut o = s.clone();
            for (k, t) in map {
                if !k.is_empty() {
                    o = o.replace(k.as_str(), t);
                }
            }
            json!(o)
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| redact(x, map)).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), redact(x, map))).collect()),
        x => x.clone(),
    }
}

fn scenario(s: &Value) -> Result<Value, String> {
    let clock = Rc::new(Cell::new(1000.0_f64));
    let o = &s["opts"];
    let ge = o.get("grantEndpoint").and_then(Value::as_str).unwrap_or("https://as.example/tx").to_string();
    let c2 = clock.clone();
    let mut srv = InteractionServer::new(InteractionServerOptions {
        grant_endpoint: ge.clone(),
        supports: o["supports"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
        redirect_uri: Box::new(|id| format!("https://as.example/i/{id}")),
        app_uri: o.get("app").is_some_and(|a| a == &json!(true)).then(|| Box::new(|id: &str| format!("app://as/{id}")) as Box<dyn Fn(&str) -> String>),
        user_code_uri: o.get("userCodeUri").and_then(Value::as_str).map(String::from),
        ttl_sec: o.get("ttlSec").and_then(Value::as_f64),
        now: Box::new(move || c2.get()),
    });
    let v: RefCell<std::collections::HashMap<&str, String>> = RefCell::new(Default::default());
    let started: RefCell<Vec<(String, String, String)>> = RefCell::new(Vec::new());
    let mut last_req = Value::Null;
    let mut trace = Vec::new();
    for st in s["steps"].as_array().unwrap() {
        let sub = |x: &Value| -> String {
            let s = x.as_str().unwrap_or("");
            let vv = v.borrow();
            let code = vv.get("code").cloned().unwrap_or_default();
            match s {
                "$code:lower" => code.to_lowercase(),
                "$code:spaced" => format!("{} - {}", &code[..4.min(code.len())], &code[4.min(code.len())..]),
                _ if s.starts_with('$') => vv.get(&s[1..]).cloned().unwrap_or_else(|| s.to_string()),
                _ => s.to_string(),
            }
        };
        let op = st["op"].as_str().unwrap();
        let res: Result<Value, InteractionError> = (|| match op {
            "start" => {
                last_req = st["req"].clone();
                let (it, resp) = srv.start(&st["req"])?;
                let mut vv = v.borrow_mut();
                vv.insert("id", it.id.clone());
                vv.insert("code", it.user_code.clone().unwrap_or_default());
                vv.insert("asnonce", it.finish.as_ref().and_then(|f| f["asNonce"].as_str()).unwrap_or("").to_string());
                started.borrow_mut().push((vv["id"].clone(), vv["code"].clone(), vv["asnonce"].clone()));
                Ok(json!({ "interaction": it.to_json(), "response": resp }))
            }
            "lookup" => Ok(srv.lookup_user_code(&sub(&st["code"])).map(|i| i.to_json()).unwrap_or(Value::Null)),
            "approve" => {
                let r = srv.approve(&sub(&st["id"]))?;
                let id = v.borrow().get("id").cloned().unwrap_or_default();
                let it = srv.get(&id);
                let f = &r["finish"];
                let m: Option<String> = if f["method"] == "push" {
                    f["body"]["hash"].as_str().map(String::from)
                } else {
                    f["url"].as_str().and_then(|u| {
                        let i = u.find("?hash=").or_else(|| u.find("&hash="))? + 6;
                        Some(u[i..].split('&').next().unwrap().to_string()).filter(|x| !x.is_empty())
                    })
                };
                let mut vv = v.borrow_mut();
                vv.insert("ref", r["interactRef"].as_str().unwrap_or("").to_string());
                vv.insert("hash", m.clone().unwrap_or_default());
                let expected = match it.as_ref().and_then(|i| i.finish.as_ref()) {
                    Some(f) => Some(interaction_hash(&json!({ "clientNonce": f["clientNonce"], "asNonce": f["asNonce"], "interactRef": r["interactRef"],
                        "grantEndpoint": it.as_ref().unwrap().grant_endpoint, "hashMethod": f["hashMethod"] }))?),
                    None => None,
                };
                Ok(json!({ "result": r, "hashOk": m == expected }))
            }
            "consume" => Ok(srv.consume(&sub(&st["ref"]))?.to_json()),
            "finalize" => {
                srv.finalize(&sub(&st["id"]));
                Ok(Value::Null)
            }
            "get" => Ok(srv.get(&sub(&st["id"])).map(|i| i.to_json()).unwrap_or(Value::Null)),
            "advance" => {
                clock.set(clock.get() + st["sec"].as_f64().unwrap());
                Ok(num(clock.get()))
            }
            "accept" => {
                let fin = last_req.get("finish").filter(|f| f.is_object()).ok_or(InteractionError { code: "type_error", message: "no finish".into() })?;
                let mut ctx = json!({ "clientNonce": fin["nonce"], "asNonce": v.borrow().get("asnonce").cloned().unwrap_or_default(), "grantEndpoint": ge });
                if let Some(h) = fin.get("hash_method").filter(|h| truthy(h)) {
                    ctx["hashMethod"] = h.clone();
                }
                accept_finish(&json!({ "hash": sub(&st["hash"]), "interact_ref": sub(&st["ref"]) }), &ctx).map(Value::String)
            }
            o => panic!("unknown op {o}"),
        })();
        trace.push(match res {
            Ok(val) => {
                let vv = v.borrow();
                let tokens: Vec<(String, &str)> = ["ref", "hash", "asnonce", "id", "code"]
                    .iter()
                    .zip(["<REF>", "<HASH>", "<ASNONCE>", "<ID>", "<CODE>"])
                    .map(|(k, t)| (vv.get(k).cloned().unwrap_or_default(), t))
                    .collect();
                // every earlier started interaction (start number n, from 0) keeps its own token, as the reference redacts them
                let st_all = started.borrow();
                let earlier: Vec<(String, String)> = st_all
                    .iter()
                    .take(st_all.len().saturating_sub(1))
                    .enumerate()
                    .flat_map(|(n, (i, c, a))| [(i.clone(), format!("<ID:{n}>")), (c.clone(), format!("<CODE:{n}>")), (a.clone(), format!("<ASNONCE:{n}>"))])
                    .collect();
                let tokens: Vec<(String, &str)> = tokens.into_iter().chain(earlier.iter().map(|(v, t)| (v.clone(), t.as_str()))).collect();
                json!({ "op": op, "ok": true, "value": redact(&val, &tokens) })
            }
            Err(e) => json!({ "op": op, "ok": false, "code": if e.code == "type_error" || e.code.starts_with("ERR_") { "other" } else { e.code } }),
        });
    }
    Ok(Value::Array(trace))
}

fn truthy(v: &Value) -> bool {
    !matches!(v, Value::Null | Value::Bool(false)) && v != &json!(0) && v != &json!("")
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let arg = |i: usize| a.get(i).cloned().unwrap_or(Value::Null);
    let s = |i: usize| a[i].as_str().ok_or_else(|| "not a string".to_string());
    match f {
        "constants" => Ok(constants()),
        "AGENT_GNAP_PROFILE" => Ok(agent_gnap_profile()),
        "gnapActionResource" => Ok(json!(gnap_action_resource(s(0)?, s(1)?))),
        "normalizeAccess" => normalize_access(&a[0]).map(Value::Array),
        "accessToPredicates" => Ok(Value::Array(access_to_predicates(&a[0]))),
        "accessContains" => Ok(json!(access_contains(&a[0], &a[1]))),
        "accessWithin" => Ok(json!(access_within(&list(&a[0]), &a[1]))),
        "clampAccess" => Ok(clamp_access(&list(&a[0]), &list(&a[1]))),
        "grantedAccessOf" => granted_access_of(&a[0]).map(Value::Array),
        "holderJwk" => Ok(holder_jwk(&a[0])),
        "resolveHolder" => resolve_holder(&a[0], a.get(1)).map(Value::String),
        "grantRequestToCapability" => grant_to_cap(a),
        "authorizeGnapAction" => Ok(authorize_gnap_action(&a[0], &a[1], &arg(2))),
        "encodeBoundToken" => Ok(json!(encode_bound_token(&a[0]))),
        "capabilityToGrantResponse" => capability_to_grant_response(&a[0], &arg(1)),
        "verifyGnapToken" => Ok(verify_gnap_token(&a[0], &arg(1))),
        "gnapContentDigest" => gnap_content_digest(&body_of(a.first())).map(|d| json!({ "$bytes": b64u(&d) })),
        "gnapContentDigestAbsent" => gnap_content_digest(&GnapBody::Absent).map(|d| json!({ "$bytes": b64u(&d) })),
        "signGnapRequest" => sign_request(&a[0]),
        "verifyGnapRequest" => verify_request(&a[0]),
        "gnapRequestRequiresStepUp" => gnap_request_requires_step_up(&a[0], &arg(1)),
        "beginGnapContinuation" => Ok(begin_gnap_continuation(&a[0])),
        "gnapStepUpShare" => gnap_step_up_share(&a[0], s(1)?, &key_of(&a[2])?, &a[3], &a[4]),
        "completeGnapContinuation" => complete(&a[0]),
        "callbackUriOk" => Ok(json!(callback_uri_ok(&a[0]))),
        "validateInteractRequest" => Ok(json!(validate_interact_request(&a[0]))),
        "interactionHash" => interaction_hash(&a[0]).map(Value::String).map_err(ie),
        "verifyInteractionHash" => verify_interaction_hash(&a[0], &a[1]).map(Value::Bool).map_err(ie),
        "acceptFinish" => accept_finish(&a[0], &a[1]).map(Value::String).map_err(ie),
        "accessToNeeds" => access_to_needs(&a[0]).map(Value::Array).map_err(ie),
        "newUserCode" => new_user_code(a[0].as_i64().ok_or("len")?).map(Value::String),
        "interactionScenario" => scenario(&a[0]),
        f => panic!("unknown fn {f}"),
    }
}

const CODED: [&str; 4] = ["interactionHash", "verifyInteractionHash", "acceptFinish", "accessToNeeds"];

#[test]
fn gnap_vectors() {
    let cases = common::ref_cases_seeded("gnap");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let f = c["fn"].as_str().unwrap();
        let got = std::panic::catch_unwind(|| run(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(e)) => match c["out"].get("code").and_then(Value::as_str) {
                Some(code) if CODED.contains(&f) => e.starts_with(&format!("{code}|")),
                _ => true,
            },
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {got:?}", c["name"], c["out"]));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} lone-surrogate cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
