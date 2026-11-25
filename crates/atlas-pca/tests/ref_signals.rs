//! Differential replay of the SSF / CAEP signals package against the TypeScript reference (test-data/ref-signals.json.gz): SET
//! build / verify, revocation state, the SET replay store, receiveSET, standard revocations, the authorize() adapters,
//! snapshot / restore, SSF stream health, verification, the poll queue and the SSF management API.
//! A reference throw only requires a refusal (its `code` compares when the native carries one). A SET built here (random jti,
//! wall-clock iat) is compared decoded, jti -> "<uuid>" and an iat within two minutes of now -> "<now>"; `sigOk` re-signs the
//! signing input under the transmitter key (Ed25519 is deterministic). Steps that hand the reference a value that is not a
//! revocation state (`{}` or `null`) have no Rust form (the state is a type): their recorded result is taken as is.
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::signals::*;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;

static NULL: Value = Value::Null;

fn num(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 {
        json!(f as i64)
    } else {
        json!(f)
    }
}

fn seed_of(jwk: &Value) -> Option<[u8; 32]> {
    atlas_pca::decode_b64u_strict(jwk.get("d")?.as_str()?, Some(32))?.try_into().ok()
}

/// The frozen clock the corpus generator ran under (its header's clockMs), read once.
fn clock() -> f64 {
    static CLOCK: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    *CLOCK.get_or_init(|| common::ref_clock_ms("signals"))
}


fn is_uuid4(s: &str) -> bool {
    let b = s.as_bytes();
    let hex = |c: u8| c.is_ascii_digit() || (b'a'..=b'f').contains(&c);
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| if [8, 13, 18, 23].contains(&i) { c == b'-' } else { hex(c) })
        && b[14] == b'4'
        && b"89ab".contains(&b[19])
}

fn part(seg: &str) -> Value {
    let raw = atlas_pca::decode_b64u_strict(seg, None).expect("b64u segment");
    atlas_pca::serde_json::from_slice(&raw).expect("json segment")
}

/// The reference's `shape(set)`: decoded header and payload (iat / jti normalised) plus the signature check under `k1`.
fn shape(set: &str, k1: &[u8; 32]) -> Value {
    let s: Vec<&str> = set.split('.').collect();
    let header = part(s[0]);
    let mut payload = part(s[1]);
    if let Some(iat) = payload.get("iat").and_then(Value::as_f64) {
        if (iat * 1000.0 - clock()).abs() < 120_000.0 {
            payload["iat"] = json!("<now>");
        }
    }
    if payload.get("jti").and_then(Value::as_str).is_some_and(is_uuid4) {
        payload["jti"] = json!("<uuid>");
    }
    let sig = atlas_pca::decode_b64u_strict(s[2], None);
    let sig_ok = sig == Some(KeyPair::from_seed(k1).sign(format!("{}.{}", s[0], s[1]).as_bytes()));
    json!({ "header": header, "payload": payload, "sigOk": sig_ok })
}

fn state_json(st: &RevocationState) -> Value {
    let m = |t: &TsMap| Value::Array(t.iter().map(|(k, v)| json!([k, num(v)])).collect());
    json!({ "grants": m(&st.revoked_grants), "agents": m(&st.killed_agents), "intents": st.revoked_intent_ids.as_ref().map(m) })
}

fn err_out(e: &SignalsError) -> Value {
    match e.code {
        Some(c) => json!({ "$err": true, "code": c }),
        None => json!({ "$err": true }),
    }
}

fn err() -> Value {
    json!({ "$err": true })
}

fn mapper(name: &str) -> Option<fn(&Value) -> Option<String>> {
    fn email(s: &Value) -> Option<String> {
        (s.get("format").and_then(Value::as_str) == Some("email")).then(|| s.get("email").and_then(Value::as_str).map(String::from)).flatten()
    }
    fn none(_: &Value) -> Option<String> {
        None
    }
    fn empty(_: &Value) -> Option<String> {
        Some(String::new())
    }
    fn id(s: &Value) -> Option<String> {
        s.get("id").and_then(Value::as_str).map(String::from)
    }
    fn prefixed(s: &Value) -> Option<String> {
        s.get("id").and_then(Value::as_str).map(|i| format!("agent:{i}"))
    }
    match name {
        "email" => Some(email),
        // a throwing or non-string mapper is an unmapped subject in the reference (the throw is caught)
        "throws" | "num" => Some(none),
        "empty" => Some(empty),
        "id" => Some(id),
        "prefixed" => Some(prefixed),
        _ => None,
    }
}

fn std_opts<'a>(sp: &Value, f: &'a Option<fn(&Value) -> Option<String>>) -> StdOptions<'a> {
    StdOptions { subject_to_agent: f.as_ref().map(|g| g as &dyn Fn(&Value) -> Option<String>), fail_on_unmapped: sp.get("fail") == Some(&Value::Bool(true)) }
}

fn mapper_of(sp: &Value) -> Option<fn(&Value) -> Option<String>> {
    sp.get("mapper").and_then(Value::as_str).and_then(mapper)
}

fn state_scenario(spec: &Value, want: &[Value]) -> Value {
    let mut st = create_revocation_state();
    let mut out = Vec::new();
    for (i, s) in spec["ops"].as_array().unwrap().iter().enumerate() {
        let opv = s["op"].as_str().unwrap();
        // shortcut: a non-state target has no Rust form; take the recorded result
        if s.get("badState") == Some(&Value::Bool(true)) || s.get("nullInto") == Some(&Value::Bool(true)) {
            out.push(want[i].clone());
            continue;
        }
        let sp = s.get("std").cloned().unwrap_or(Value::Null);
        let f = mapper_of(&sp);
        let so = std_opts(&sp, &f);
        let r: Value = match opv {
            "apply" => apply_set(&mut st, &s["parsed"]).map(|_| state_json(&st)).unwrap_or_else(|e| err_out(&e)),
            "applyStd" => apply_standard_revocations(&mut st, &s["parsed"], &so)
                .map(|p| json!({ "plan": p.to_value(), "state": state_json(&st) }))
                .unwrap_or_else(|e| err_out(&e)),
            "plan" => plan_standard_revocations(&s["parsed"], &so).map(|p| p.to_value()).unwrap_or_else(|e| err_out(&e)),
            "isRevoked" => json!(is_revoked(&st, s["grant"].as_str().unwrap(), s.get("agent").and_then(Value::as_str))),
            "isIntentRevoked" => json!(is_intent_revoked(&st, s["id"].as_str().unwrap())),
            "stream" => {
                if s.get("useState") == Some(&Value::Bool(true)) {
                    stream_processor(&s["sets"], &mut st).map(|_| state_json(&st)).unwrap_or_else(|e| err_out(&e))
                } else {
                    let mut fresh = create_revocation_state();
                    stream_processor(&s["sets"], &mut fresh).map(|_| state_json(&fresh)).unwrap_or_else(|e| err_out(&e))
                }
            }
            "snapshot" => snapshot_revocation_state(&st),
            "restore" => {
                if s.get("fresh") == Some(&Value::Bool(true)) {
                    let mut fresh = create_revocation_state();
                    restore_revocation_state(&s["snapshot"], &mut fresh).map(|_| state_json(&fresh)).unwrap_or_else(|e| err_out(&e))
                } else {
                    restore_revocation_state(&s["snapshot"], &mut st).map(|_| state_json(&st)).unwrap_or_else(|e| err_out(&e))
                }
            }
            o => panic!("bad op {o}"),
        };
        out.push(r);
    }
    out.push(state_json(&st));
    Value::Array(out)
}

fn replay_scenario(spec: &Value) -> Value {
    let mut store = match create_in_memory_set_replay_store(spec.get("opts")) {
        Ok(s) => s,
        Err(e) => return json!([err_out(&e)]),
    };
    Value::Array(
        spec["ops"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| store.add_if_absent(o[0].as_str().unwrap(), o[1].as_f64().unwrap(), o[2].as_f64().unwrap()).map(Value::Bool).unwrap_or_else(|_| err()))
            .collect(),
    )
}

struct Fixed(bool);
impl SetReplayStore for Fixed {
    fn add_if_absent(&mut self, _: &str, _: f64, _: f64) -> Result<bool, String> {
        Ok(self.0)
    }
}
struct NoExpiry(std::collections::HashSet<String>);
impl SetReplayStore for NoExpiry {
    fn add_if_absent(&mut self, j: &str, _: f64, _: f64) -> Result<bool, String> {
        Ok(self.0.insert(j.to_string()))
    }
}
struct Throws;
impl SetReplayStore for Throws {
    fn add_if_absent(&mut self, _: &str, _: f64, _: f64) -> Result<bool, String> {
        Err("boom".into())
    }
}

fn replay_conformance(spec: &Value) -> Result<Value, String> {
    let kind = spec["store"].as_str().unwrap().to_string();
    let opts = spec.get("opts").cloned();
    let mut make = || -> Box<dyn SetReplayStore> {
        match kind.as_str() {
            "alwaysTrue" => Box::new(Fixed(true)),
            "alwaysFalse" => Box::new(Fixed(false)),
            "noExpiry" => Box::new(NoExpiry(Default::default())),
            _ => Box::new(create_in_memory_set_replay_store(opts.as_ref()).unwrap()),
        }
    };
    // a store that throws mid-run (a full one) makes the whole conformance run throw
    run_set_replay_store_conformance(&mut make).map(|f| json!(f)).map_err(|_| "replay store is full".to_string())
}

fn receive_scenario(spec: &Value, k1_pub: &Value) -> Value {
    let mut st = create_revocation_state();
    let mut store: Box<dyn SetReplayStore> = match spec["store"].as_str().unwrap() {
        "throws" => Box::new(Throws),
        "false" => Box::new(Fixed(false)),
        "mem1" => Box::new(create_in_memory_set_replay_store(Some(&json!({ "maxEntries": 1 }))).unwrap()),
        _ => Box::new(create_in_memory_set_replay_store(None).unwrap()),
    };
    let mut out = Vec::new();
    for d in spec["deliveries"].as_array().unwrap() {
        let t = |k: &str| d.get(k) == Some(&Value::Bool(true));
        let opts = d.get("opts").cloned().unwrap_or(json!({}));
        let sp = d.get("std").cloned();
        let f = sp.as_ref().and_then(mapper_of);
        let so = sp.as_ref().map(|sp| std_opts(sp, &f));
        let key = d.get("key").unwrap_or(k1_pub);
        let store_ref: Option<&mut dyn SetReplayStore> = if t("noStore") { None } else { Some(store.as_mut()) };
        let state_ref = if t("noState") { None } else { Some(&mut st) };
        let mut r = receive_set(&d["set"], key, if t("noOpts") { None } else { Some(&opts) }, store_ref, state_ref, so.as_ref());
        if r["ok"] == json!(false) && r["code"] == json!("verify_failed") && !r["reason"].as_str().unwrap_or("").starts_with("SET invalid:") {
            r["reason"] = json!("<jose>");
        }
        if r["ok"] == json!(true) {
            let p = &r["parsed"];
            let mut m = Map::new();
            for k in ["events", "iss", "jti", "sub", "payload"] {
                if let Some(v) = p.get(k) {
                    m.insert(k.into(), v.clone());
                }
            }
            r = json!({ "ok": true, "parsed": m });
        }
        out.push(r);
    }
    out.push(state_json(&st));
    Value::Array(out)
}

fn adapter_scenario(spec: &Value) -> Value {
    let mut st = create_revocation_state();
    let snap = json!({ "v": 1, "grants": spec.get("grants").cloned().unwrap_or(json!([])), "agents": spec.get("agents").cloned().unwrap_or(json!([])), "intents": [] });
    if let Err(e) = restore_revocation_state(&snap, &mut st) {
        return json!([err_out(&e)]);
    }
    let name = spec.get("agentOf").and_then(Value::as_str).unwrap_or("leaf").to_string();
    let f = move |_p: &Value, g: &Value| -> Result<Option<String>, String> {
        match name.as_str() {
            "throws" => Err("x".into()),
            "empty" => Ok(Some(String::new())),
            "num" => Ok(None),
            "grantId" => Ok(g.get("id").and_then(Value::as_str).map(String::from)),
            c => Ok(c.strip_prefix("const:").map(String::from)),
        }
    };
    let leaf = spec.get("agentOf").and_then(Value::as_str).is_none_or(|a| a == "leaf");
    let agent: Option<AgentOf> = if leaf { None } else { Some(&f) };
    Value::Array(
        spec["calls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                let (p, g) = (c.get("pcactn").unwrap_or(&NULL), c.get("grant").unwrap_or(&NULL));
                json!({ "hook": revocation_hook(&st, p, g, agent), "isRevoked": is_revoked_adapter(&st, g, p, agent) })
            })
            .collect(),
    )
}

fn health_scenario(spec: &Value, cfg: &Value) -> Value {
    let opts = spec.get("opts").map(StreamHealthOptions::from_value).unwrap_or_default();
    let mut h = StreamHealth::new(spec.get("config").unwrap_or(cfg), opts);
    let mut issued: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for s in spec["ops"].as_array().unwrap() {
        let now = s.get("now").and_then(Value::as_f64).unwrap_or(0.0);
        let r = match s["op"].as_str().unwrap() {
            "status" => h.set_status(&s["v"]).map(|_| Value::Null).unwrap_or_else(|_| err()),
            "event" => {
                h.record_event(now);
                Value::Null
            }
            "request" => match h.request_verification(now) {
                Ok(Some(st)) => {
                    issued.push(st);
                    json!(format!("<state:{}>", issued.len() - 1))
                }
                Ok(None) => Value::Null,
                Err(_) => err(),
            },
            "ack" => {
                let st = match s.get("ref").and_then(Value::as_u64) {
                    Some(i) => issued.get(i as usize).map(|x| json!(x)).unwrap_or(Value::Null),
                    None => s.get("state").cloned().unwrap_or(Value::Null),
                };
                json!(h.ack_verification(&st, now))
            }
            "report" => h.report(now),
            "fresh" => json!(h.revocation_fresh_within(s["max"].as_f64().unwrap(), now)),
            o => panic!("bad op {o}"),
        };
        out.push(r);
    }
    Value::Array(out)
}

fn verification_scenario(spec: &Value, k1: &[u8; 32]) -> Value {
    let mut streams: HashMap<String, StreamEntry> = HashMap::new();
    if let Some(m) = spec.get("streams").and_then(Value::as_object) {
        for (k, v) in m {
            streams.insert(
                k.clone(),
                StreamEntry { config: v.get("config").cloned().unwrap_or(Value::Null), last_verification: v.get("lastVerification").and_then(Value::as_f64) },
            );
        }
    }
    let mut out = Vec::new();
    for s in spec["ops"].as_array().unwrap() {
        let seed = if s.get("noKey") == Some(&Value::Bool(true)) { None } else { Some(k1) };
        let r = match handle_verification_request(&mut streams, &s["req"], s["now"].as_f64().unwrap(), seed) {
            Ok(r) if r["status"] == json!(204) => json!({ "status": 204, "set": shape(r["set"].as_str().unwrap(), k1) }),
            Ok(r) => r,
            Err(_) => err(),
        };
        out.push(r);
    }
    out.push(Value::Object(streams.iter().map(|(k, v)| (k.clone(), v.last_verification.map(num).unwrap_or(Value::Null))).collect()));
    Value::Array(out)
}

fn poll_scenario(spec: &Value) -> Value {
    let mut q = PollQueue::new();
    let mut out = Vec::new();
    for s in spec["ops"].as_array().unwrap() {
        let r = if let Some(e) = s.get("enqueue") {
            q.enqueue(e[0].as_str().unwrap(), e[1].as_str().unwrap());
            Value::Null
        } else if s.get("depth").is_some() {
            json!(q.depth())
        } else {
            q.poll(s.get("poll").unwrap_or(&NULL)).unwrap_or_else(|_| err())
        };
        out.push(r);
    }
    out.push(json!({ "depth": q.depth(), "errors": q.errors }));
    Value::Array(out)
}

fn manage_scenario(spec: &Value, k1: &[u8; 32]) -> Value {
    let mut store = MemoryStreamStore::default();
    let delivered = RefCell::new(Vec::<Value>::new());
    let ids = Cell::new(0u32);
    let now = Cell::new(1000.0f64);
    let cur = RefCell::new(Value::Null);
    let so = spec.get("options").cloned().unwrap_or(json!({}));
    let strs = |v: &Value| v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>());
    let events = spec.get("eventsSupported").and_then(strs).unwrap_or_else(|| vec![EV_GRANT_REVOKED.into(), EV_KILL_SWITCH.into(), EV_SESSION_REVOKED.into()]);
    let poll = |id: &str| format!("https://tx.example/poll/{id}");
    let mut deliver = |stream: &Value, set: &str| -> Result<(), String> {
        delivered.borrow_mut().push(json!({ "stream": stream, "set": shape(set, k1) }));
        Ok(())
    };
    let clock = || now.get();
    let mut new_id = || {
        ids.set(ids.get() + 1);
        format!("s{}", ids.get())
    };
    let mut out = Vec::new();
    {
        let mut o = SsfManageOptions {
            store: &mut store,
            issuer: "https://tx.example".into(),
            events_supported: events,
            delivery_methods: so.get("deliveryMethods").and_then(strs),
            poll_endpoint: &poll,
            signing_seed: *k1,
            deliver: &mut deliver,
            max_streams_per_receiver: so.get("maxStreamsPerReceiver").and_then(Value::as_f64),
            max_subjects_per_stream: so.get("maxSubjectsPerStream").and_then(Value::as_f64),
            now: &clock,
            new_id: &mut new_id,
        };
        let auth = |_req: &Value| -> Result<Option<Value>, String> {
            match &*cur.borrow() {
                Value::String(s) if s == "throws" => Err("auth".into()),
                Value::Null => Ok(None),
                r => Ok(Some(r.clone())),
            }
        };
        for st in spec["steps"].as_array().unwrap() {
            now.set(st.get("now").and_then(Value::as_f64).unwrap_or(1000.0));
            *cur.borrow_mut() = match st.get("rcv") {
                None => json!({ "id": "rx1", "aud": "rx" }),
                Some(r) => r.clone(),
            };
            out.push(ssf_management_handler(&mut o, st.get("req").unwrap_or(&NULL), &auth));
        }
    }
    let mut dump = Map::new();
    let receivers = spec.get("receivers").cloned().unwrap_or(json!(["rx1", "rx2"]));
    for rid in receivers.as_array().unwrap() {
        dump.insert(rid.as_str().unwrap().into(), Value::Array(store.list_by_receiver(rid).into_iter().map(|(i, r)| json!([i, r])).collect()));
    }
    out.push(json!({ "delivered": delivered.into_inner(), "store": dump }));
    Value::Array(out)
}

/// Ok(None) = skipped.
fn same(want: &Value, got: Result<Value, String>) -> Result<(), String> {
    match (want.get("$throws"), got) {
        (Some(_), Err(_)) => Ok(()),
        (None, Ok(g)) if atlas_pca::canonicalize(want) == atlas_pca::canonicalize(&g) => Ok(()),
        (_, g) => Err(format!("want {want}, got {g:?}")),
    }
}

/// The replay runs at the corpus generator's frozen clock: every default `iat` and `now` the natives read is `clockMs`.
#[test]
fn signals_vectors() {
    atlas_pca::jose::with_clock_sec((clock() / 1000.0).floor(), signals_vectors_at_clock);
}

fn signals_vectors_at_clock() {
    let cases = common::ref_cases_seeded("signals");
    let k1_priv = cases.iter().find(|c| c["fn"] == "buildSETShape").unwrap()["args"][0]["keyJwk"].clone();
    let k1 = seed_of(&k1_priv).unwrap();
    let k1_pub = json!({ "kty": "OKP", "crv": "Ed25519", "x": k1_priv["x"] });
    let cfg = cases.iter().find(|c| c["fn"] == "validateStreamConfig").unwrap()["args"][0].clone();
    let (mut bad, mut skipped) = (Vec::new(), 0usize);
    for c in &cases {
        if c.to_string().contains(common::LONE) {
            skipped += 1;
            continue;
        }
        let a = c["args"].as_array().unwrap();
        let g = |i: usize| a.get(i).unwrap_or(&NULL);
        let want_arr = c["out"].as_array().cloned().unwrap_or_default();
        let got: Result<Value, String> = match c["fn"].as_str().unwrap() {
            "constants" => Ok(constants()),
            "verifySET" => verify_set(g(0), g(1), g(2)),
            "buildSETShape" => match seed_of(&g(0)["keyJwk"]) {
                Some(s) => build_set(g(0), &s).map(|t| shape(&t, &k1)),
                None => Err("no private key".into()),
            },
            "caepSET" => match seed_of(&g(0)["keyJwk"]) {
                Some(s) if g(0)["kind"] == "risk" => risk_level_change_set(g(0), &s).map(|t| shape(&t, &k1)),
                Some(s) => assurance_level_change_set(g(0), &s).map(|t| shape(&t, &k1)),
                None => Err("no private key".into()),
            },
            "stateScenario" => Ok(state_scenario(g(0), &want_arr)),
            "replayScenario" => Ok(replay_scenario(g(0))),
            "replayConformance" => replay_conformance(g(0)),
            "receiveScenario" => Ok(receive_scenario(g(0), &k1_pub)),
            "adapterScenario" => {
                if g(0).get("badState").is_some() {
                    // a non-state has no Rust form
                    skipped += 1;
                    continue;
                }
                Ok(adapter_scenario(g(0)))
            }
            "validateStreamConfig" => Ok(json!(validate_stream_config(g(0)))),
            "healthScenario" => Ok(health_scenario(g(0), &cfg)),
            "verificationScenario" => Ok(verification_scenario(g(0), &k1)),
            "pollScenario" => Ok(poll_scenario(g(0))),
            "pushResponse" => push_response(g(0)),
            "transmitterMetadata" => {
                let dm =
                    g(0).get("deliveryMethods").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>());
                Ok(transmitter_metadata(g(0)["issuer"].as_str().unwrap(), dm.as_deref(), g(1).as_str().unwrap(), g(2).as_str()))
            }
            "manageScenario" => Ok(manage_scenario(g(0), &k1)),
            other => panic!("unknown fn {other}"),
        };
        if let Err(e) = same(&c["out"], got) {
            bad.push(format!("{}: {e}", c["name"]));
        }
    }
    assert!(skipped * 10 < cases.len(), "too many skipped: {skipped}");
    assert!(bad.is_empty(), "{} of {} differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
