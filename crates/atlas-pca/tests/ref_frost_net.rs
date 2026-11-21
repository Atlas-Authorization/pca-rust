//! Differential replay of test-data/ref-frost-net.json.gz (written by the TypeScript reference): networked FROST signing, the allow token, the
//! signer proof of possession and its enrollment gate, the equivocation guard, the wire decoders, the nonce store (and the contract a custom
//! store must pass, checked against stores broken in each way), the group-algorithm registry, the hybrid co-sign, the PQ quorum block, the
//! guardian signer service and the network coordinator. Dealer shares are rebuilt from their descriptor with the lane's own trusted-dealer
//! keygen; the reference's random draws (`$rng`) are replayed through the random seam. The signer SERVICE and the NETWORK COORDINATOR run in
//! process over scripted randomness, clock and transports (delays, hostile edits, canned responses). A refusal is compared by its class and
//! fields (typed errors; the message text is informative) and a reason exactly, unless the case marks it `reasonOpen`. Every function of the
//! corpus has a handler and the per-function totals are asserted. Two cases cannot be expressed with typed Rust stores and are counted as
//! not run: a store object that lacks a method, and a store whose `load` hands out its own state.
mod common;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use atlas_pca::agent::PqKeyPair;
use atlas_pca::attest::allowlist::JsNum;
use atlas_pca::frost::{frost_trusted_dealer_keygen, FrostParticipantShare};
use atlas_pca::frost_net::*;
use atlas_pca::frost_nonce_store::{assert_nonce_store_contract, MemoryNonceStore, NonceRecord, NonceStore};
use atlas_pca::frost_pq::*;
use atlas_pca::serde_json::{json, Map, Value};

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn b64u(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn enc(b: &[u8]) -> Value {
    json!({ "$bytes": b64u(b) })
}

/// `{"$bytes": b64url}` as bytes; anything else is not bytes.
fn bytes_of(v: &Value) -> Option<Vec<u8>> {
    v.get("$bytes").and_then(Value::as_str).map(common::b64d)
}

fn opt_bytes(v: Option<&Value>) -> Option<Vec<u8>> {
    v.and_then(bytes_of)
}

/// A non-finite double marker `{"$num": "NaN" | "Infinity" | "-Infinity"}`.
fn marker(v: &Value) -> Option<f64> {
    match v.as_object().filter(|m| m.len() == 1)?.get("$num")?.as_str()? {
        "NaN" => Some(f64::NAN),
        "Infinity" => Some(f64::INFINITY),
        "-Infinity" => Some(f64::NEG_INFINITY),
        _ => None,
    }
}

fn has_marker(v: &Value) -> bool {
    marker(v).is_some()
        || match v {
            Value::Array(a) => a.iter().any(has_marker),
            Value::Object(m) => m.values().any(has_marker),
            _ => false,
        }
}

fn js_num(v: Option<&Value>) -> JsNum {
    match v {
        None => JsNum::Undefined,
        Some(x) => match marker(x).or(x.as_f64().filter(|_| x.is_number())) {
            Some(n) => JsNum::Num(n),
            None => JsNum::Other,
        },
    }
}

/// How an allow token's body is canonicalised: a non-finite double is no JSON number, the reference's canonical form refuses it.
fn canon(v: &Value) -> Result<Vec<u8>, String> {
    if has_marker(v) {
        return Err("canonicalize: non-finite number".into());
    }
    atlas_pca::canonicalize_strict(v).map(String::into_bytes)
}

/// Resolve every `{"$share": {...}}` into the dealer share bytes it names.
fn resolve(v: &mut Value) {
    match v {
        Value::Object(m) => {
            if let Some(s) = m.get("$share").filter(|_| m.len() == 1).cloned() {
                let secret = bytes_of(&s["secret"]);
                let coefficients: Vec<Option<Vec<u8>>> = s["coefficients"].as_array().into_iter().flatten().map(bytes_of).collect();
                let ids: Option<Vec<i64>> = s["identifiers"].as_array().map(|a| a.iter().filter_map(Value::as_i64).collect());
                let kg = frost_trusted_dealer_keygen(
                    s["t"].as_i64().unwrap(),
                    s["n"].as_i64().unwrap(),
                    secret.as_deref(),
                    &coefficients,
                    ids.as_deref(),
                )
                .unwrap();
                let id = s["id"].as_i64().unwrap();
                let share = kg.participant_shares.iter().find(|p| p.identifier == id).unwrap();
                *v = enc(&share.share);
            } else {
                m.values_mut().for_each(resolve);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(resolve),
        _ => {}
    }
}

/// The trailing `{"$rng": [...]}` argument as a random seam replaying the draws in order; the arguments without it.
fn rng_of(args: &[Value]) -> (Vec<Value>, RandomBytes) {
    match args.last().and_then(|l| l.get("$rng")).and_then(Value::as_array) {
        Some(draws) => {
            let q: Mutex<VecDeque<Vec<u8>>> = Mutex::new(draws.iter().map(|d| bytes_of(d).unwrap()).collect());
            (
                args[..args.len() - 1].to_vec(),
                Arc::new(move |n| q.lock().unwrap().pop_front().expect("a draw past the script is a bug")[..n].to_vec()),
            )
        }
        None => (args.to_vec(), os_random()),
    }
}

fn thrown(e: impl std::fmt::Display) -> Value {
    json!({"$throws": e.to_string()})
}

fn err_json(e: &FrostNetError) -> Value {
    let mut o = json!({"$throws": e.message()});
    match e {
        FrostNetError::Message(_) => {}
        FrostNetError::PoP { identifier, .. } => {
            o["class"] = json!("PoPError");
            if let Some(i) = identifier {
                o["identifier"] = json!(i);
            }
        }
        FrostNetError::Equivocation { session_id, round, identifier, previous_digest, offending_digest, .. } => {
            o["class"] = json!("EquivocationError");
            o["session_id"] = json!(session_id);
            o["round"] = json!(round);
            o["identifier"] = json!(identifier);
            o["previousDigest"] = json!(previous_digest);
            o["offendingDigest"] = json!(offending_digest);
        }
        FrostNetError::Coordinator { refusals, .. } => {
            o["class"] = json!("CoordinatorError");
            o["refusals"] = json!(refusals);
        }
        FrostNetError::Timeout { refusals, timeout_ms, .. } => {
            o["class"] = json!("CoordinatorTimeoutError");
            o["refusals"] = json!(refusals);
            o["timeoutMs"] = json!(timeout_ms);
        }
    }
    o
}

fn record_json(r: &NonceRecord) -> Value {
    json!({
        "hiding": enc(&r.hiding), "binding": enc(&r.binding), "hidingCommitment": enc(&r.hiding_commitment),
        "bindingCommitment": enc(&r.binding_commitment), "createdAt": r.created_at,
    })
}

fn record_of(v: &Value) -> NonceRecord {
    let b = |k: &str| opt_bytes(v.get(k)).unwrap_or_default();
    NonceRecord {
        hiding: b("hiding"),
        binding: b("binding"),
        hiding_commitment: b("hidingCommitment"),
        binding_commitment: b("bindingCommitment"),
        created_at: v["createdAt"].as_f64().unwrap_or(0.0),
    }
}

// ---- stores ----------------------------------------------------------------------------------------------------------------------

/// A memory store whose named method fails with `store down`.
struct FailStore {
    inner: MemoryNonceStore,
    method: String,
}

impl FailStore {
    fn check(&self, m: &str) -> Result<(), String> {
        if self.method == m {
            Err("store down".into())
        } else {
            Ok(())
        }
    }
}

impl NonceStore for FailStore {
    fn create(&self, s: &str, r: &NonceRecord) -> Result<(), String> {
        self.check("create")?;
        self.inner.create(s, r)
    }
    fn load(&self, s: &str) -> Result<Option<NonceRecord>, String> {
        self.check("load")?;
        self.inner.load(s)
    }
    fn spend(&self, s: &str) -> Result<(), String> {
        self.check("spend")?;
        self.inner.spend(s)
    }
    fn drop_session(&self, s: &str) -> Result<(), String> {
        self.check("drop")?;
        self.inner.drop_session(s)
    }
    fn is_spent(&self, s: &str) -> Result<bool, String> {
        self.check("isSpent")?;
        self.inner.is_spent(s)
    }
}

/// A store broken in one named way (the contract must refuse it).
struct BrokenStore {
    kind: String,
    live: Mutex<BTreeMap<String, NonceRecord>>,
    spent: Mutex<Vec<String>>,
}

impl NonceStore for BrokenStore {
    fn create(&self, s: &str, r: &NonceRecord) -> Result<(), String> {
        let (mut live, spent) = (self.live.lock().unwrap(), self.spent.lock().unwrap());
        if self.kind != "create-overwrites" && live.contains_key(s) {
            return Err("exists".into());
        }
        if self.kind != "create-over-spent" && spent.iter().any(|x| x == s) {
            return Err("spent".into());
        }
        live.insert(s.to_string(), r.clone());
        Ok(())
    }
    fn load(&self, s: &str) -> Result<Option<NonceRecord>, String> {
        Ok(self.live.lock().unwrap().get(s).cloned())
    }
    fn spend(&self, s: &str) -> Result<(), String> {
        let (mut live, mut spent) = (self.live.lock().unwrap(), self.spent.lock().unwrap());
        if live.remove(s).is_none() {
            if self.kind == "spend-unknown-ok" || (self.kind == "spend-twice-ok" && spent.iter().any(|x| x == s)) {
                return Ok(());
            }
            return Err("not live".into());
        }
        spent.push(s.to_string());
        Ok(())
    }
    fn drop_session(&self, s: &str) -> Result<(), String> {
        self.live.lock().unwrap().remove(s);
        if self.kind == "drop-marks-spent" {
            self.spent.lock().unwrap().push(s.to_string());
        }
        Ok(())
    }
    fn is_spent(&self, s: &str) -> Result<bool, String> {
        Ok(self.kind == "unknown-reports-spent" || self.spent.lock().unwrap().iter().any(|x| x == s))
    }
}

fn contract(a: &Value) -> Value {
    let kind = text(&a["store"]);
    let result = if kind == "memory" {
        assert_nonce_store_contract(&|| Arc::new(MemoryNonceStore::default()) as Arc<dyn NonceStore>, &|s| s)
    } else {
        let broken =
            Arc::new(BrokenStore { kind: kind.trim_start_matches("broken:").to_string(), live: Mutex::default(), spent: Mutex::default() });
        let b2 = broken.clone();
        assert_nonce_store_contract(&move || b2.clone() as Arc<dyn NonceStore>, &|s| {
            match broken.kind.as_str() {
                "spent-forgotten-on-restart" => broken.spent.lock().unwrap().clear(),
                "live-lost-on-restart" => broken.live.lock().unwrap().clear(),
                _ => {}
            }
            s
        })
    };
    result.map(|_| Value::Null).unwrap_or_else(thrown)
}

fn nonce_store_ops(ops: &Value) -> Value {
    let st = MemoryNonceStore::default();
    let out: Vec<Value> = ops
        .as_array()
        .unwrap()
        .iter()
        .map(|op| {
            let sid = text(&op["sid"]);
            let r = match text(&op["op"]) {
                "create" => st.create(sid, &record_of(&op["rec"])).map(|_| json!({"ok": true})),
                "load" => st.load(sid).map(|r| json!({"value": r.as_ref().map_or(Value::Null, record_json)})),
                "spend" => st.spend(sid).map(|_| json!({"ok": true})),
                "drop" => st.drop_session(sid).map(|_| json!({"ok": true})),
                _ => st.is_spent(sid).map(|b| json!({"value": b})),
            };
            r.unwrap_or_else(thrown)
        })
        .collect();
    Value::Array(out)
}

// ---- the signer service and the coordinator --------------------------------------------------------------------------------------

fn make_store(kind: Option<&str>) -> Option<Arc<dyn NonceStore>> {
    match kind {
        None | Some("none") => None,
        Some("memory") => Some(Arc::new(MemoryNonceStore::default())),
        Some(k) if k.starts_with("fail-") => Some(Arc::new(FailStore { inner: MemoryNonceStore::default(), method: k[5..].to_string() })),
        Some(other) => panic!("store {other}"),
    }
}

fn service(
    cfg: &Value,
    store: Option<Arc<dyn NonceStore>>,
    clock: Arc<Mutex<f64>>,
    random: RandomBytes,
) -> Result<GuardianSignerService, String> {
    let share = opt_bytes(cfg.get("share"));
    let (gpk, policy) = (opt_bytes(cfg.get("groupPublicKey")), opt_bytes(cfg.get("policyAuthorityPublicKey")));
    GuardianSignerService::new(SignerConfig {
        identifier: cfg.get("identifier").unwrap_or(&Value::Null),
        share: share.as_deref(),
        group_public_key: gpk.as_deref(),
        threshold: cfg.get("threshold").unwrap_or(&Value::Null),
        policy_authority_public_key: policy.as_deref(),
        session_ttl_ms: js_num(cfg.get("sessionTtlMs")),
        now: Arc::new(move || *clock.lock().unwrap()),
        nonce_store: store,
        random,
        canonical: Some(canon),
    })
}

fn enrollment_json(s: &GuardianSignerService) -> Value {
    let (id, pk, pop) = s.enrollment();
    json!({"identifier": id, "publicKey": enc(&pk), "pop": pop})
}

fn signer_service(cfg: &Value, steps: &Value, random: RandomBytes) -> Value {
    let clock = Arc::new(Mutex::new(cfg.get("clock").and_then(Value::as_f64).unwrap_or(1_000_000.0)));
    let store = make_store(cfg.get("store").and_then(Value::as_str));
    let mut svc = match service(cfg, store.clone(), clock.clone(), random.clone()) {
        Ok(s) => s,
        Err(e) => return json!({"ctor": thrown(e), "steps": []}),
    };
    let ctor =
        json!({"verificationShare": enc(&svc.verification_share), "pop": svc.proof_of_possession(), "enrollment": enrollment_json(&svc)});
    let mut out = Vec::new();
    for st in steps.as_array().unwrap() {
        let v = match text(&st["op"]) {
            "round1" => svc.round1(&st["req"]),
            "round2" => svc.round2(&st["req"]),
            "clock" => {
                let mut c = clock.lock().unwrap();
                *c += st["ms"].as_f64().unwrap();
                json!({"clock": *c})
            }
            "restart" => match service(cfg, store.clone(), clock.clone(), random.clone()) {
                Ok(s) => {
                    svc = s;
                    json!({"restarted": true, "pop": svc.proof_of_possession()})
                }
                Err(e) => thrown(e),
            },
            "storeLoad" => store.as_ref().unwrap().load(text(&st["sid"])).map(|r| json!({"live": r.is_some()})).unwrap_or_else(thrown),
            "storeIsSpent" => store.as_ref().unwrap().is_spent(text(&st["sid"])).map(|b| json!({"spent": b})).unwrap_or_else(thrown),
            other => panic!("bad step {other}"),
        };
        out.push(v);
    }
    json!({"ctor": ctor, "steps": out})
}

fn flip(v: &str) -> String {
    let mut raw = common::b64d(v);
    raw[0] ^= 1;
    b64u(&raw)
}

fn apply_edits(resp: &Value, edits: Option<&Value>, round: i64) -> Value {
    let mut r = resp.clone();
    for e in edits.and_then(Value::as_array).into_iter().flatten() {
        if e["round"].as_i64() != Some(round) {
            continue;
        }
        let path = e["path"].as_array().unwrap();
        let mut parent = Some(&mut r);
        for k in &path[..path.len() - 1] {
            parent = parent.and_then(|p| p.as_object_mut()).and_then(|m| m.get_mut(text(k)));
        }
        let key = text(path.last().unwrap()).to_string();
        let Some(m) = parent.and_then(|p| p.as_object_mut()) else { continue };
        match text(&e["op"]) {
            "set" => {
                m.insert(key, e["value"].clone());
            }
            "delete" => {
                m.remove(&key);
            }
            _ => {
                if let Some(v) = m.get(&key).and_then(Value::as_str).map(flip) {
                    m.insert(key, json!(v));
                }
            }
        }
    }
    r
}

/// A scripted signer: a real service over scripted randomness, or canned answers; delays, unreachable rounds and hostile edits on top.
struct ScriptedTransport {
    id: i64,
    spec: Value,
    calls: Mutex<[usize; 2]>,
    svc: Option<GuardianSignerService>,
}

impl ScriptedTransport {
    fn new(spec: &Value) -> Result<Self, String> {
        let svc = if spec.get("canned").is_some_and(|c| !c.is_null()) {
            None
        } else {
            let draws: Mutex<VecDeque<Vec<u8>>> =
                Mutex::new(spec["rng"].as_array().unwrap().iter().map(|d| bytes_of(d).unwrap()).collect());
            let random: RandomBytes =
                Arc::new(move |n| draws.lock().unwrap().pop_front().expect("a draw past the script is a bug")[..n].to_vec());
            Some(service(spec, make_store(spec.get("store").and_then(Value::as_str)), Arc::new(Mutex::new(1_000_000.0)), random)?)
        };
        Ok(ScriptedTransport { id: spec["identifier"].as_i64().unwrap_or(0), spec: spec.clone(), calls: Mutex::new([0, 0]), svc })
    }

    fn respond(&self, round: usize, req: &Value) -> Result<Value, String> {
        let key = format!("r{round}");
        let n = {
            let mut c = self.calls.lock().unwrap();
            c[round - 1] += 1;
            c[round - 1] - 1
        };
        if let Some(ms) = self.spec.get("delay").and_then(|d| d.get(&key)).and_then(Value::as_f64).filter(|m| *m > 0.0) {
            std::thread::sleep(Duration::from_secs_f64(ms / 1000.0));
        }
        if self
            .spec
            .get("throws")
            .and_then(|t| t.get(&key))
            .is_some_and(|t| t.as_bool() == Some(true) || t.as_f64().is_some_and(|f| f != 0.0))
        {
            return Err("unreachable".into());
        }
        let resp = if let Some(canned) = self.spec.get("canned").filter(|c| !c.is_null()) {
            let list = canned[format!("round{round}")].as_array().cloned().unwrap_or_default();
            match list.get(n) {
                Some(c) if c != &json!("throw") => c.clone(),
                _ => return Err("unreachable".into()),
            }
        } else if round == 1 {
            self.svc.as_ref().unwrap().round1(req)
        } else {
            self.svc.as_ref().unwrap().round2(req)
        };
        Ok(apply_edits(&resp, self.spec.get("edits"), round as i64))
    }
}

impl SignerTransport for ScriptedTransport {
    fn identifier(&self) -> i64 {
        self.id
    }
    fn round1(&self, req: &Value) -> Result<Value, String> {
        self.respond(1, req)
    }
    fn round2(&self, req: &Value) -> Result<Value, String> {
        self.respond(2, req)
    }
}

fn coordinator(cfg: &Value) -> Value {
    let sids: Mutex<VecDeque<String>> =
        Mutex::new(cfg.get("sessionIds").and_then(Value::as_array).into_iter().flatten().map(|s| text(s).to_string()).collect());
    let next_sid: Arc<dyn Fn() -> Result<String, String> + Send + Sync> =
        Arc::new(move || sids.lock().unwrap().pop_front().ok_or_else(|| "no more scripted session ids".to_string()));
    let ctor_err = |e: String| json!({"calls": [], "ctor": thrown(e)});
    let mut transports: Vec<Arc<dyn SignerTransport>> = Vec::new();
    for s in cfg["signers"].as_array().unwrap() {
        match ScriptedTransport::new(s) {
            Ok(t) => transports.push(Arc::new(t)),
            Err(e) => return ctor_err(e),
        }
    }
    let gpk = opt_bytes(cfg.get("groupPublicKey"));
    let vshares: Option<Vec<(i64, Vec<u8>)>> = cfg
        .get("verificationShares")
        .and_then(Value::as_array)
        .map(|l| l.iter().map(|v| (v["identifier"].as_i64().unwrap_or(0), opt_bytes(v.get("publicKey")).unwrap_or_default())).collect());
    let enroll_vals: Option<Option<Vec<(Value, Option<Vec<u8>>, Value)>>> = cfg.get("enroll").filter(|e| !e.is_null()).map(|e| {
        e.as_array().map(|l| {
            l.iter()
                .map(|x| {
                    (
                        x.get("identifier").cloned().unwrap_or(Value::Null),
                        opt_bytes(x.get("publicKey")),
                        x.get("pop").cloned().unwrap_or(Value::Null),
                    )
                })
                .collect()
        })
    });
    let enrollments: Option<Option<Vec<EnrollmentIn>>> = enroll_vals
        .as_ref()
        .map(|o| o.as_ref().map(|l| l.iter().map(|(i, pk, pop)| EnrollmentIn { identifier: i, public_key: pk.as_deref(), pop }).collect()));
    let enroll_arg: Option<Option<&[EnrollmentIn]>> = enrollments.as_ref().map(|o| o.as_deref());
    let built = NetworkCoordinator::new(
        gpk.as_deref(),
        cfg.get("threshold").unwrap_or(&Value::Null),
        transports,
        vshares,
        enroll_arg,
        js_num(cfg.get("timeoutMs")),
        next_sid,
    );
    let coord = match built {
        Ok(c) => Arc::new(c),
        Err(e) => return json!({"calls": [], "ctor": err_json(&e)}),
    };
    let calls: Vec<Value> = cfg["calls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let message = opt_bytes(c.get("message"));
            let ids: Option<Vec<Value>> = c.get("signerIds").and_then(Value::as_array).cloned();
            match coord.sign(message.as_deref(), c.get("allow").unwrap_or(&Value::Null), ids.as_deref(), js_num(c.get("timeoutMs"))) {
                Ok(r) => json!({"signature": enc(&r.signature), "sessionId": r.session_id, "signers": r.signers}),
                Err(e) => err_json(&e),
            }
        })
        .collect();
    json!({"calls": calls})
}

// ---- the other handlers ----------------------------------------------------------------------------------------------------------

fn enroll_case(a: &[Value]) -> Value {
    let rows: Option<Vec<(Value, Option<Vec<u8>>, Value)>> = a[0].as_array().map(|l| {
        l.iter()
            .map(|x| {
                (
                    x.get("identifier").cloned().unwrap_or(Value::Null),
                    opt_bytes(x.get("publicKey")),
                    x.get("pop").cloned().unwrap_or(Value::Null),
                )
            })
            .collect()
    });
    let list: Option<Vec<EnrollmentIn>> =
        rows.as_ref().map(|r| r.iter().map(|(i, pk, pop)| EnrollmentIn { identifier: i, public_key: pk.as_deref(), pop }).collect());
    let gpk = opt_bytes(a[1].get("groupPublicKey"));
    match enroll_verification_shares(list.as_deref(), gpk.as_deref()) {
        Ok(v) => Value::Array(v.iter().map(|(i, pk)| json!({"identifier": i, "publicKey": enc(pk)})).collect()),
        Err(e) => err_json(&e),
    }
}

fn guard_case(ops: &Value) -> Value {
    let mut g = EquivocationGuard::new();
    let out: Vec<Value> = ops
        .as_array()
        .unwrap()
        .iter()
        .map(|op| {
            if text(&op["op"]) == "observe" {
                match g.observe(
                    op.get("session_id").unwrap_or(&Value::Null),
                    op.get("round").unwrap_or(&Value::Null),
                    op.get("identifier").unwrap_or(&Value::Null),
                    op.get("message").unwrap_or(&Value::Null),
                ) {
                    Ok(()) => json!({"ok": true}),
                    Err(e) => err_json(&e),
                }
            } else {
                g.forget(text(&op["session_id"]));
                json!({"ok": true})
            }
        })
        .collect();
    Value::Array(out)
}

/// A strict Ed25519 verification under the group key.
fn ed_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(pk) = <[u8; 32]>::try_from(pk) else { return false };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else { return false };
    let Ok(sig) = ed25519_dalek::Signature::from_slice(sig) else { return false };
    vk.verify_strict(msg, &sig).is_ok()
}

fn commitment_json(c: &atlas_pca::frost::FrostCommitment) -> Value {
    json!({"identifier": c.identifier, "hiding": enc(&c.hiding), "binding": enc(&c.binding)})
}

fn sign_hybrid(a: &[Value]) -> Value {
    let (args, _unused) = rng_of(a);
    let gpk = bytes_of(&args[0]).unwrap();
    let quorum: Vec<FrostParticipantShare> = args[1]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| FrostParticipantShare {
            identifier: p["identifier"].as_i64().unwrap(),
            share: opt_bytes(p.get("share")).unwrap_or_default(),
            public_key: opt_bytes(p.get("publicKey")).unwrap_or_default(),
        })
        .collect();
    let message = bytes_of(&args[2]).unwrap_or_default();
    let opts = &args[3];
    let guardian = opts.get("guardianMlDsaSeed").and_then(bytes_of).map(|s| PqKeyPair::from_seed("ML-DSA-65", &s).unwrap());
    let art = sign_hybrid_frost_cosign(
        &gpk,
        &quorum,
        &message,
        opts.get("groupAlg"),
        guardian.as_ref(),
        opts.get("threshold").and_then(Value::as_i64),
    );
    match art {
        Err(e) => thrown(e),
        Ok(art) => {
            let sig = art["sig"].as_str().unwrap();
            let raw = atlas_pca::decode_b64u_strict(sig, None).unwrap_or_default();
            let mut out: Map<String, Value> =
                art.as_object().unwrap().iter().filter(|(k, _)| k.as_str() != "sig").map(|(k, v)| (k.clone(), v.clone())).collect();
            out.insert("sigVerifies".into(), json!(raw.len() == 64 && ed_verify(&gpk, &message, &raw)));
            out.insert("sigLength".into(), json!(raw.len()));
            Value::Object(out)
        }
    }
}

fn run(f: &str, args: &[Value]) -> Value {
    let mut a: Vec<Value> = args.to_vec();
    a.iter_mut().for_each(resolve);
    match f {
        "signerService" => {
            let (a, random) = rng_of(&a);
            signer_service(&a[0], &a[1], random)
        }
        "coordinator" => coordinator(&a[0]),
        "constants" => json!({
            "ALLOW_TOKEN_TYP": ALLOW_TOKEN_TYP, "SIGNER_POP_DST": SIGNER_POP_DST, "MAX_FROST_SIGNING_SET": MAX_FROST_SIGNING_SET,
            "DEFAULT_FROST_GROUP_ALG": DEFAULT_FROST_GROUP_ALG, "PQ_QUORUM_VERSION": PQ_QUORUM_VERSION, "PQ_QUORUM_ALG": PQ_QUORUM_ALG,
            "MAX_PQ_QUORUM_ENTRIES": MAX_PQ_QUORUM_ENTRIES,
        }),
        "frostActionDigest" => match bytes_of(&a[0]) {
            Some(m) => json!(frost_action_digest(&m)),
            None => thrown("frostActionDigest: message must be bytes"),
        },
        "issueAllowToken" => {
            let (a, random) = rng_of(&a);
            let o = &a[1];
            let opts = IssueAllowOpts {
                message: opt_bytes(o.get("message")),
                frost_action_digest: o.get("frostActionDigest").and_then(Value::as_str).map(String::from),
                group_public_key: opt_bytes(o.get("groupPublicKey")),
                canonical: Some(canon),
                nonce: o.get("nonce").and_then(Value::as_str).map(String::from),
                not_before: o.get("notBefore").cloned(),
                expires_at: o.get("expiresAt").cloned(),
            };
            match bytes_of(&a[0]) {
                Some(secret) => issue_allow_token(&secret, &opts, &random).unwrap_or_else(thrown),
                None => thrown("bad secret key size"),
            }
        }
        "verifyAllowToken" => {
            let (policy, gpk, message) =
                (opt_bytes(a[1].get("policyAuthorityPublicKey")), opt_bytes(a[1].get("groupPublicKey")), opt_bytes(a[1].get("message")));
            verify_allow_token(
                &a[0],
                &VerifyAllowExpect {
                    policy_authority_public_key: policy.as_deref(),
                    group_public_key: gpk.as_deref(),
                    message: message.as_deref(),
                    now: js_num(a[1].get("now")),
                    canonical: Some(canon),
                },
            )
        }
        "createSignerPoP" => {
            let (a, random) = rng_of(&a);
            let (share, gpk, nonce) = (opt_bytes(Some(&a[1])), opt_bytes(a[2].get("groupPublicKey")), opt_bytes(a[2].get("nonce")));
            create_signer_pop(&a[0], share.as_deref(), gpk.as_deref(), nonce.as_deref(), &random).unwrap_or_else(thrown)
        }
        "verifySignerPoP" => json!(verify_signer_pop(&a[0], opt_bytes(a[1].get("groupPublicKey")).as_deref())),
        "enrollVerificationShares" => enroll_case(&a),
        "equivocationGuard" => guard_case(&a[0]),
        "decodeCommitment" => decode_commitment(&a[0]).map(|c| commitment_json(&c)).unwrap_or_else(thrown),
        "decodeCommitments" => {
            decode_commitments(&a[0]).map(|l| Value::Array(l.iter().map(commitment_json).collect())).unwrap_or_else(thrown)
        }
        "decodeVerificationShares" => decode_verification_shares(&a[0])
            .map(|l| Value::Array(l.iter().map(|v| json!({"identifier": v.identifier, "publicKey": enc(&v.public_key)})).collect()))
            .unwrap_or_else(thrown),
        "nonceStore" => nonce_store_ops(&a[0]),
        "assertNonceStoreContract" => contract(&a[0]),
        "resolveFrostGroupAlg" => resolve_frost_group_alg(a.first()).map_or(Value::Null, Value::String),
        "frostSignerSetDigest" => frost_signer_set_digest(&a[0]).map(|d| enc(&d)).unwrap_or_else(thrown),
        "frostCosignRepresentative" => {
            match bytes_of(&a[1]) {
                Some(m) => frost_cosign_representative(&a[0], &m, &a[2], &a[3]).map(|d| enc(&d)).unwrap_or_else(thrown),
                None => thrown("Uint8Array expected"),
            }
        }
        "verifyHybridFrostCosign" => {
            let o = &a[4];
            verify_hybrid_frost_cosign(
                &a[0],
                &bytes_of(&a[1]).unwrap_or_default(),
                &a[2],
                &a[3],
                o.get("guardianPqPublicKey"),
                o.get("expectGroupAlg"),
            )
        }
        "signHybridFrostCosign" => sign_hybrid(&a),
        "pqQuorumRepresentative" => enc(&pq_quorum_representative(&bytes_of(&a[0]).unwrap_or_default())),
        "signPqQuorum" => {
            let keys: Vec<_> =
                a[1].as_array().unwrap().iter().map(|s| atlas_pca::pq::ml_dsa_65_keygen(&bytes_of(s).unwrap()).unwrap()).collect();
            sign_pq_quorum(&bytes_of(&a[0]).unwrap_or_default(), &keys, a[2].as_i64()).unwrap_or_else(thrown)
        }
        "normalizePqQuorumPool" => {
            // the pool in input order (the reference returns a Set): each entry normalised alone, the first occurrence kept
            let items: Vec<Value> =
                a[0].as_array().unwrap().iter().map(|p| bytes_of(p).map_or_else(|| p.clone(), |b| json!(b64u(&b)))).collect();
            let mut out: Vec<String> = Vec::new();
            for p in &items {
                for s in normalize_pq_quorum_pool(&json!([p])).unwrap() {
                    if !out.contains(&s) {
                        out.push(s);
                    }
                }
            }
            json!(out)
        }
        "verifyPqQuorum" => {
            let pool = normalize_pq_quorum_pool(&a[2]).unwrap_or_default();
            // the reference takes the pool as given: every entry is a string it holds
            let pool = a[2].as_array().map(|l| l.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or(pool);
            verify_pq_quorum(&a[0], &bytes_of(&a[1]).unwrap_or_default(), &pool, Some(&a[3]))
        }
        other => panic!("unhandled corpus function {other}"),
    }
}

/// Equality of a result with the reference's: an object marked `reasonOpen` must carry a reason (or a refusal text) but not the same one; the
/// message text of a refusal is informative; everything else is compared exactly.
fn eq(got: &Value, want: &Value) -> bool {
    match want {
        Value::Object(o) => {
            let Value::Object(g) = got else { return false };
            let open = o.get("reasonOpen") == Some(&json!(true));
            let keys: Vec<&String> = o.keys().filter(|k| k.as_str() != "reasonOpen").collect();
            g.len() == keys.len()
                && keys.iter().all(|k| {
                    g.contains_key(k.as_str())
                        && (k.as_str() == "$throws" || (open && k.as_str() == "reason") || eq(&g[k.as_str()], &o[k.as_str()]))
                })
        }
        Value::Array(w) => got.as_array().is_some_and(|g| g.len() == w.len() && g.iter().zip(w).all(|(x, y)| eq(x, y))),
        _ => atlas_pca::canonicalize(got) == atlas_pca::canonicalize(want),
    }
}

#[test]
fn frost_net_replay() {
    let cases = common::ref_cases_seeded("frost-net");
    let totals: BTreeMap<&str, usize> = [
        ("constants", 1),
        ("frostActionDigest", 7),
        ("issueAllowToken", 25),
        ("verifyAllowToken", 58),
        ("createSignerPoP", 24),
        ("verifySignerPoP", 36),
        ("enrollVerificationShares", 23),
        ("equivocationGuard", 27),
        ("decodeCommitment", 22),
        ("decodeCommitments", 10),
        ("decodeVerificationShares", 16),
        ("nonceStore", 16),
        ("assertNonceStoreContract", 11),
        ("resolveFrostGroupAlg", 16),
        ("frostSignerSetDigest", 17),
        ("frostCosignRepresentative", 13),
        ("verifyHybridFrostCosign", 60),
        ("signHybridFrostCosign", 18),
        ("pqQuorumRepresentative", 4),
        ("signPqQuorum", 7),
        ("normalizePqQuorumPool", 6),
        ("verifyPqQuorum", 36),
        ("signerService", 95),
        ("coordinator", 86),
    ]
    .into_iter()
    .collect();
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(text(&c["fn"]).to_string()).or_default() += 1;
    }
    assert_eq!(per_fn, totals.iter().map(|(k, n)| (k.to_string(), *n)).collect::<BTreeMap<_, _>>(), "per-function case totals");
    assert_eq!(cases.len(), 634);
    let (mut skipped, mut bad) = (0usize, Vec::new());
    for c in &cases {
        let f = text(&c["fn"]);
        let args = c["args"].as_array().unwrap();
        // a store object without `spend`, and a store whose load hands out its own state, have no typed Rust form
        let untyped = (f == "signerService" && args[0]["store"] == json!("invalid-no-spend"))
            || (f == "assertNonceStoreContract" && args[0]["store"] == json!("broken:load-aliases"));
        if untyped {
            skipped += 1;
            continue;
        }
        let got = run(f, args);
        let ok = if c["out"].get("$throws").is_some() { got.get("$throws").is_some() && eq(&got, &c["out"]) } else { eq(&got, &c["out"]) };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert_eq!(skipped, 2, "cases without a typed form");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
