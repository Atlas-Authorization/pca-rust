//! Differential replay of the pca-grants operational plane (signers, bundles, decision log, replay, shadow rollout, list-authorized,
//! grant management service + HTTP, lease registry/renewal/HTTP, blueprint group kill and admission, consistency tokens) against the
//! TypeScript reference (test-data/ref-grants.json.gz, generator tools/pca-audit/oracles/grants.mts). A reference throw
//! (`{"$throws": ..}`) only requires a refusal; records are compared by JSON value (numbers by value). Keys are
//! sha256("atlas-pca-conformance/" + label) seeds.
//! Skipped (counted, must stay under 10%): cases carrying a lone surrogate (a Rust String cannot hold one).
//! Not in the corpus, therefore not replayed: `run_lease_store_conformance` and the `GrantClient` (not ported).
mod common;
use atlas_pca::blueprint::{BlueprintRegistry, MemoryBlueprintStore};
use atlas_pca::grants::*;
use atlas_pca::grants_list::*;
use atlas_pca::grants_service::*;
use atlas_pca::grants_shadow::*;
use atlas_pca::k3::{record_commit, verify_batch, verify_record_inclusion, GRANT_AMEND_DOMAIN, GRANT_REVOKE_DOMAIN, NEED_APPROVE_DOMAIN};
use atlas_pca::kv::MemoryAtomicKv;
use atlas_pca::lease::{check_lease, LeasePolicy, LeaseRegistry};
use atlas_pca::serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const T0: i64 = 1_800_000_000_000;

fn seed(label: &str) -> [u8; 32] {
    let h = Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes());
    let mut o = [0u8; 32];
    o.copy_from_slice(&h);
    o
}

fn pubkey(label: &str) -> String {
    signer_of(&seed(label))
}

fn st(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

/// JSON equality with numbers compared by value (1 and 1.0 are the same JavaScript number).
fn veq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x == y || x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| veq(p, q)),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| veq(v, w))),
        _ => a == b,
    }
}

fn same(want: &Value, got: &Result<Value, String>) -> bool {
    if want.get("$throws").is_some() {
        return got.is_err();
    }
    matches!(got, Ok(g) if veq(want, g))
}

/// Replace "$key:LABEL" strings and {"$sign": {kind, label, fields}} objects, recursively.
fn resolve(v: &Value) -> Value {
    match v {
        Value::String(s) => match s.strip_prefix("$key:") {
            Some(l) => Value::String(pubkey(l)),
            None => v.clone(),
        },
        Value::Array(a) => Value::Array(a.iter().map(resolve).collect()),
        Value::Object(m) => {
            if let Some(sg) = m.get("$sign") {
                let sk = seed(st(&sg["label"]));
                let fields = resolve(&sg["fields"]);
                let r = match st(&sg["kind"]) {
                    "lease" => sign_lease(&sk, &fields),
                    "leaseOver" => sign_lease_unsafe_over_cap(&sk, &fields),
                    "revocation" => sign_lease_revocation(&sk, &fields),
                    "blueprint" => sign_blueprint(&sk, &fields),
                    "breakglass" => sign_break_glass(&sk, &fields),
                    "review" => sign_break_glass_review(&sk, &fields),
                    other => panic!("unknown $sign kind {other}"),
                };
                return r.expect("a $sign spec signs");
            }
            Value::Object(m.iter().map(|(k, x)| (k.clone(), resolve(x))).collect())
        }
        _ => v.clone(),
    }
}

/// The reference's scenario output without `reason` (the diagnostic text of a refusal result). An HTTP refusal body keeps its `message`:
/// the reference prints it, and the lease replay compares it.
fn strip(o: &Value) -> Value {
    match o {
        Value::Object(m) => Value::Object(m.iter().filter(|(k, _)| k.as_str() != "reason").map(|(k, v)| (k.clone(), strip(v))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(strip).collect()),
        other => other.clone(),
    }
}

fn err_x() -> Value {
    json!({"$err": "x"})
}

fn grant_err(e: &GrantError) -> Value {
    json!({"$err": e.code})
}

fn grant_result(r: Result<Value, GrantError>) -> Value {
    match r {
        Ok(v) => v,
        Err(e) => grant_err(&e),
    }
}

// ---- decision log / replay ----------------------------------------------------------------------------------------------------

fn log_scenario(spec: &Value) -> Result<Value, String> {
    let secret = seed(st(&spec["label"]));
    let mut log = DecisionLog::new(secret, strings(spec.get("mask")));
    let mut recs: Vec<Value> = Vec::new();
    for r in spec["records"].as_array().unwrap() {
        recs.push(log.append(r)?);
    }
    let signer = signer_of(&secret);
    let now = &spec["now"];
    let head = log.head(now)?;
    let idx: Vec<Value> = spec.get("proofs").and_then(Value::as_array).cloned().unwrap_or_default();
    let proofs: Vec<Value> = idx.iter().map(|i| log.proof(i).unwrap_or_else(|_| json!({"$err": true}))).collect();
    let incl: Vec<Value> = idx
        .iter()
        .zip(&proofs)
        .map(|(i, p)| {
            if p.get("$err").is_some() {
                return json!({"$err": true});
            }
            let rec = &recs[i.as_u64().unwrap() as usize];
            json!(verify_record_inclusion(rec, p, &head, &signer))
        })
        .collect();
    let mut batches: Vec<Value> = Vec::new();
    for b in spec.get("batches").and_then(Value::as_array).cloned().unwrap_or_default() {
        let bt = match next_batch(&log, &b["from"], &b["max"], now) {
            Ok(bt) => bt,
            Err(_) => {
                batches.push(json!({"$err": true}));
                continue;
            }
        };
        let from = b["from"].as_i64().unwrap();
        let last_commit = if from == 0 { Some(String::new()) } else { recs.get((from - 1) as usize).and_then(record_commit) };
        let Some(last_commit) = last_commit else {
            batches.push(json!({"$err": true}));
            continue;
        };
        let mut tampered = bt.clone();
        if let Some(r0) = tampered["records"].get_mut(0) {
            r0["at"] = json!(1);
        }
        batches.push(json!({
            "bt": bt,
            "verdict": verify_batch(&bt, from, &last_commit, &signer),
            "tampered": verify_batch(&tampered, from, &last_commit, &signer),
            "wrong": verify_batch(&bt, from, &last_commit, &pubkey("zz")),
        }));
    }
    Ok(json!({"recs": recs, "head": head, "size": log.size(), "proofs": proofs, "incl": incl, "batches": batches}))
}

fn table(t: &Value, i: &Value) -> Option<Value> {
    i.as_str().and_then(|k| t.get(k)).cloned()
}

fn replay_scenario(spec: &Value) -> Result<Value, String> {
    let diff = semantic_diff(&spec["cases"], &|i: &Value| table(&spec["oldT"], i), &|i: &Value| table(&spec["newT"], i));
    let audit = audit_replay(&spec["records"], &spec["cases"], &|i: &Value, rev: &Value| {
        let key = format!("{}@{}", st(i), rev);
        table(&spec["revT"], &Value::String(key))
    });
    Ok(json!({"diff": diff, "audit": audit}))
}

// ---- consistency tokens -------------------------------------------------------------------------------------------------------

fn fresh_scenario(spec: &Value) -> Result<Value, String> {
    let mut iss = FreshAtIssuer::new(seed(st(&spec["label"])), &spec["scope"], &spec["init"]);
    let mut out: Vec<Value> = Vec::new();
    let mut last: Option<Value> = None;
    for s in spec["steps"].as_array().unwrap() {
        let max_age = s.get("maxAge").and_then(Value::as_i64);
        let r = match st(&s["op"]) {
            "advance" => match iss.advance(&s["patch"], &s["now"]) {
                Ok(t) => {
                    last = Some(t.clone());
                    t
                }
                Err(_) => json!({"$err": true}),
            },
            "check" => {
                let token = if s["token"] == "last" { last.clone().unwrap_or(Value::Null) } else { s["token"].clone() };
                iss.check(&token, &s["now"], max_age)
            }
            "current" => iss.current(),
            "tamper" => match &last {
                Some(l) => {
                    let mut t = l.clone();
                    t["policy_revision"] = json!(l["policy_revision"].as_i64().unwrap_or(0) + 1);
                    iss.check(&t, &s["now"], None)
                }
                None => json!({"$err": true}),
            },
            other => panic!("unknown fresh op {other}"),
        };
        out.push(r);
    }
    Ok(Value::Array(out))
}

// ---- shadow -------------------------------------------------------------------------------------------------------------------

fn decide_of(t: &Value, i: &Value) -> Result<Value, String> {
    match t.get(st(i)) {
        Some(Value::String(d)) if d == "throw" => Err("boom".to_string()),
        Some(Value::String(d)) if d == "junk" => Ok(json!("weird")),
        Some(d) => Ok(d.clone()),
        None => Ok(Value::Null),
    }
}

fn shadow_scenario(spec: &Value) -> Result<Value, String> {
    let secret = seed(st(&spec["label"]));
    let mut log = ShadowLog::new(secret);
    let cands = spec["cands"].as_array().unwrap();
    let tables: Vec<Value> = cands.iter().map(|c| c["T"].clone()).collect();
    let deciders: Vec<Box<dyn Fn(&Value) -> Result<Value, String> + '_>> =
        tables.iter().map(|t| Box::new(move |i: &Value| decide_of(t, i)) as Box<dyn Fn(&Value) -> Result<Value, String> + '_>).collect();
    let mut runs: Vec<Value> = Vec::new();
    let enforced_digest = st(&spec["enforcedDigest"]);
    for ob in spec["obs"].as_array().unwrap() {
        let cs: Vec<ShadowCandidate> =
            cands.iter().zip(deciders.iter()).map(|(c, d)| ShadowCandidate { digest: st(&c["digest"]).to_string(), decide: &**d }).collect();
        let run = run_shadow(&ob["input"], &|i: &Value| decide_of(&spec["enforcedT"], i), &cs)?;
        runs.push(json!({"decision": run["decision"], "shadow": run["shadow"]}));
        for oc in run["shadow"].as_array().unwrap() {
            log.observe(enforced_digest, st(&ob["action_digest"]), st(&run["decision"]), oc, &ob["at"])?;
        }
    }
    let mut stats = Map::new();
    let mut diffs = Map::new();
    for c in cands {
        let d = st(&c["digest"]);
        stats.insert(d.to_string(), log.stats(d).to_json());
        diffs.insert(d.to_string(), Value::Array(log.diffs(d)));
    }
    let signer = log.signer();
    let mut verify: Vec<Value> = Vec::new();
    for list in diffs.values() {
        for d in list.as_array().unwrap() {
            let mut bad_sig = d.clone();
            bad_sig["sig"] = json!(format!("{}A", &st(&d["sig"])[1..]));
            let mut later = d.clone();
            later["at"] = json!(d["at"].as_i64().unwrap() + 1);
            verify.push(json!([
                verify_shadow_diff(d, Some(&signer)),
                verify_shadow_diff(d, None),
                verify_shadow_diff(d, Some(&pubkey("zz"))),
                verify_shadow_diff(&bad_sig, Some(&signer)),
                verify_shadow_diff(&later, None)
            ]));
        }
    }
    let mut out = json!({"runs": runs, "diffs": diffs, "stats": stats, "verify": verify, "signer": signer});
    if let Some(g) = spec.get("gate") {
        let principals: Vec<Value> = strings(g.get("principals")).iter().map(|l| json!(pubkey(l))).collect();
        let mut explanations: Vec<Value> = Vec::new();
        for e in g.get("explain").and_then(Value::as_array).cloned().unwrap_or_default() {
            let body = json!({"shadow_digest": e["shadow_digest"], "action_digest": e["action_digest"], "reason_digest": e["reason_digest"]});
            explanations.push(sign_widening_explanation(&seed(st(&e["label"])), &body)?);
        }
        let approval = match g.get("approval").filter(|a| !a.is_null()) {
            Some(a) => Some(sign_promotion_approval(
                &seed(st(&a["label"])),
                &json!({"shadow_digest": a["shadow_digest"], "enforced_digest": a["enforced_digest"], "at": a["at"]}),
            )?),
            None => None,
        };
        out["explanations"] = Value::Array(explanations.clone());
        out["approval"] = approval.clone().unwrap_or(Value::Null);
        let mut opts = g["options"].as_object().cloned().unwrap_or_default();
        if opts.get("principals").is_none_or(Value::is_null) {
            opts.insert("principals".to_string(), Value::Array(principals));
        }
        if opts.get("explanations").is_none_or(Value::is_null) {
            opts.insert("explanations".to_string(), Value::Array(explanations));
        }
        if let Some(a) = approval {
            opts.insert("approval".to_string(), a);
        }
        let gate = promotion_gate(&log, &Value::Object(opts));
        out["gate"] = gate.clone();
        if let Some(p) = spec.get("promote") {
            let used = if p.get("useGate") == Some(&json!(false)) { json!({"ok": false, "code": "bad_input", "reason": "x"}) } else { gate };
            out["promoted"] = promote_shadow(&p["enforced"], &p["candidate"], &used, &p["now"]).unwrap_or_else(|_| json!({"$err": true}));
        }
    }
    Ok(out)
}

// ---- list-authorized ----------------------------------------------------------------------------------------------------------

fn page_of(list: &[String], q: &Value, overfetch: bool, empty_next: bool) -> Value {
    let idx = q.get("cursor").and_then(Value::as_str).and_then(|c| c.parse::<usize>().ok()).unwrap_or(0);
    let limit = q["limit"].as_u64().unwrap_or(0) as usize;
    let extra = if overfetch { 3 } else { 0 };
    let start = idx.min(list.len());
    let end = (idx + limit + extra).min(list.len());
    let mut o = Map::new();
    o.insert("objects".to_string(), json!(list[start..end]));
    if idx + limit < list.len() {
        o.insert("next".to_string(), json!((idx + limit).to_string()));
    } else if empty_next {
        o.insert("next".to_string(), json!(""));
    }
    Value::Object(o)
}

struct Universe {
    list: Vec<String>,
    overfetch: bool,
    empty_next: bool,
}

impl CandidateSource for Universe {
    fn page(&self, q: &Value) -> Result<Value, String> {
        Ok(page_of(&self.list, q, self.overfetch, self.empty_next))
    }
}

struct Rel {
    allowed: HashSet<String>,
    use_list: bool,
    listed: Vec<String>,
    overfetch: bool,
    empty_next: bool,
}

impl RelationSource for Rel {
    fn check(&self, q: &Value) -> Result<bool, String> {
        Ok(self.allowed.contains(st(&q["object"])))
    }
    fn has_list_objects(&self) -> bool {
        self.use_list
    }
    fn list_objects(&self, q: &Value) -> Option<Result<Value, String>> {
        self.use_list.then(|| Ok(page_of(&self.listed, q, self.overfetch, self.empty_next)))
    }
}

fn list_scenario(spec: &Value) -> Result<Value, String> {
    let acc = WindowReadAccumulator::new(spec["cap"].as_i64().unwrap(), spec["windowMs"].as_i64().unwrap());
    let universe = strings(spec.get("universe"));
    let overfetch = spec.get("overfetch") == Some(&json!(true));
    let empty_next = spec.get("emptyNext") == Some(&json!(true));
    let uni = Universe { list: universe.clone(), overfetch, empty_next };
    let rspec = spec.get("relation");
    let rel = Rel {
        allowed: strings(rspec.and_then(|r| r.get("allowed"))).into_iter().collect(),
        use_list: rspec.and_then(|r| r.get("useList")) == Some(&json!(true)),
        listed: match rspec.and_then(|r| r.get("listed")) {
            Some(l) => strings(Some(l)),
            None => universe.clone(),
        },
        overfetch,
        empty_next,
    };
    let permitted: Option<HashSet<String>> = spec.get("permitted").map(|p| strings(Some(p)).into_iter().collect());
    let permits = |x: &str| permitted.as_ref().is_none_or(|p| p.contains(x));
    let as_candidates = rspec.and_then(|r| r.get("asCandidates")) == Some(&json!(true));
    let rname = rspec.map(|r| st(&r["name"]).to_string());
    let mut out: Vec<Value> = Vec::new();
    let mut cursor: Option<String> = None;
    for p in 0..spec["pages"].as_i64().unwrap() {
        let t = spec.get("tamper").filter(|t| t["page"].as_i64() == Some(p));
        let tv = |k: &str| t.and_then(|t| t.get(k));
        let relation_name = tv("relation").and_then(Value::as_str).map(String::from).or_else(|| rname.clone());
        let rc_res = if as_candidates { Some(candidates_from_relation(&rel, st(&spec["subject"]), rname.as_deref().unwrap_or(""))) } else { None };
        if let Some(Err(_)) = &rc_res {
            out.push(err_x());
            if t.is_none() {
                break;
            }
            continue;
        }
        let cand: &dyn CandidateSource = match &rc_res {
            Some(Ok(rc)) => rc as &dyn CandidateSource,
            _ => &uni as &dyn CandidateSource,
        };
        let drop_cursor = tv("dropCursor").is_some_and(|d| d == &json!(true));
        let use_cursor: Option<String> = match (&cursor, drop_cursor) {
            (Some(c), false) => Some(tv("cursor").and_then(Value::as_str).map(String::from).unwrap_or_else(|| c.clone())),
            _ => None,
        };
        let limit = tv("limit").unwrap_or(&spec["limit"]);
        let label = tv("label").and_then(Value::as_str).unwrap_or(st(&spec["label"])).to_string();
        let req = ListRequest {
            subject: tv("subject").and_then(Value::as_str).unwrap_or(st(&spec["subject"])),
            resource_type: st(&spec["type"]),
            permits: &permits,
            candidates: cand,
            relation: if rspec.is_some() { Some((&rel as &dyn RelationSource, relation_name.as_deref().unwrap_or(""))) } else { None },
            filter_id: tv("filterId").and_then(Value::as_str).unwrap_or(st(&spec["filterId"])),
            policy_digest: st(&spec["policyDigest"]),
            fresh_at_digest: st(&spec["freshAt"]),
            cursor: use_cursor.as_deref(),
            limit,
            reads: &acc,
            now: T0 + p * spec.get("nowStep").and_then(Value::as_i64).unwrap_or(1),
            signing_secret: seed(&label),
            max_scan: spec.get("maxScan").and_then(Value::as_i64),
        };
        match list_authorized(&req) {
            Ok(r) => {
                cursor = r.get("next_cursor").and_then(Value::as_str).map(String::from);
                out.push(r);
            }
            Err(e) => {
                out.push(json!({"$err": e.code}));
                if t.is_none() {
                    break;
                }
            }
        }
    }
    Ok(Value::Array(out))
}

fn window_acc(a: &[Value]) -> Result<Value, String> {
    let acc = WindowReadAccumulator::new(a[0].as_i64().unwrap(), a[1].as_i64().unwrap());
    let r: Vec<Value> =
        a[2].as_array().unwrap().iter().map(|o| json!(acc.charge(st(&o["key"]), o["units"].as_i64().unwrap(), o["now"].as_i64().unwrap()))).collect();
    Ok(Value::Array(r))
}

// ---- grant management ---------------------------------------------------------------------------------------------------------

fn sec(by: &str) -> [u8; 32] {
    match by {
        "principal" => seed("$P"),
        "holder" => seed("$A"),
        _ => seed("$X"),
    }
}

fn usage_of(g: &Value) -> Value {
    json!({"rev": g["rev"]})
}
fn budget_of(_g: &Value) -> Value {
    json!({"left": 5})
}
fn residual_of(g: &Value) -> Value {
    json!({"id": g["id"]})
}

fn grant_step(svc: &GrantService, s: &Value) -> Value {
    match st(&s["op"]) {
        "register" => grant_result(svc.register(&s["grant"])),
        "list" => grant_result(svc.list(s.get("filter").unwrap_or(&json!({})))),
        "inspect" => grant_result(svc.inspect(st(&s["id"]))),
        "amend" => {
            let id = st(&s["id"]);
            let g = match svc.inspect(id) {
                Ok(g) => g,
                Err(e) => return grant_err(&e),
            };
            let Some(msg) = amend_message(&g, st(&s["action"]), &s["authority"]) else { return err_x() };
            let mut req = json!({"action": s["action"], "authority": s["authority"]});
            let by = st(&s["by"]);
            if by != "none" {
                let signed_by = s.get("signed_by").and_then(Value::as_str).unwrap_or(if by == "holder" { "holder" } else { "principal" });
                req["signed_by"] = json!(signed_by);
                match sign_body(GRANT_AMEND_DOMAIN, &msg, &sec(by)) {
                    Ok(sig) => req["sig"] = json!(sig),
                    Err(_) => return err_x(),
                }
            }
            if let Some(su) = s.get("stepUp") {
                req["step_up_ref"] = su.clone();
            }
            grant_result(svc.amend(id, &req))
        }
        "revoke" => {
            let id = st(&s["id"]);
            let g = match svc.inspect(id) {
                Ok(g) => g,
                Err(e) => return grant_err(&e),
            };
            let by = st(&s["by"]);
            let auth = match by {
                "admin" => json!({"admin": true}),
                "noauth" => json!({}),
                _ => match sign_body(GRANT_REVOKE_DOMAIN, &grant_revoke_message(st(&g["id"]), st(&s["scope"])), &sec(by)) {
                    Ok(sig) => json!({"sig": sig}),
                    Err(_) => return err_x(),
                },
            };
            grant_result(svc.revoke(id, &s["scope"], &auth))
        }
        "needs" => grant_result(svc.request_needs(st(&s["id"]), &s["needs"])),
        "approve" => {
            let need_id = st(&s["needId"]);
            let nid = match svc.need_grant_id(need_id) {
                Ok(n) => n,
                Err(e) => return grant_err(&e),
            };
            let g = match svc.inspect(&nid) {
                Ok(g) => g,
                Err(e) => return grant_err(&e),
            };
            let msg = need_approve_message(need_id, &nid, &g["rev"], &s["approved"]);
            let Ok(sig) = sign_body(NEED_APPROVE_DOMAIN, &msg, &sec(st(&s["by"]))) else { return err_x() };
            grant_result(svc.approve_needs(need_id, &s["approved"], &json!(sig), s.get("stepUp").and_then(Value::as_str)))
        }
        "deny" => match svc.deny_needs(st(&s["needId"])) {
            Ok(()) => Value::Null,
            Err(e) => grant_err(&e),
        },
        "http" => {
            let mut req = Map::new();
            for k in ["method", "path", "query", "body", "who"] {
                if let Some(v) = s.get(k) {
                    req.insert(k.to_string(), v.clone());
                }
            }
            let auth = |r: &Value| r.get("who").filter(|w| !w.is_null()).cloned();
            grant_http(svc, &auth, &Value::Object(req))
        }
        other => panic!("bad op {other}"),
    }
}

fn grant_scenario(spec: &Value) -> Result<Value, String> {
    let store = Arc::new(MemoryGrantStore::new());
    let events: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let (gc, nc) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let mut svc = GrantService::new(
        store.clone(),
        || T0,
        move |k: &str| {
            if k == "grant" {
                format!("g_{}", gc.fetch_add(1, Ordering::SeqCst) + 1)
            } else {
                format!("n_{}", nc.fetch_add(1, Ordering::SeqCst) + 1)
            }
        },
    );
    let flag = |k: &str| spec.get(k) == Some(&json!(true));
    if flag("providers") {
        svc = svc.with_providers(Providers { usage: Some(usage_of), remaining_budget: Some(budget_of), policy_card: None, residual: Some(residual_of) });
    }
    if flag("stepUp") {
        svc = svc.with_verify_step_up(|r: &str, _g: &Value| r == "ok-step");
    }
    let ev = events.clone();
    svc = svc.with_on_revoke(move |ids: &[String], scope: &str, root: &Value| {
        ev.lock().unwrap().push(json!({"revoked": ids, "scope": scope, "root": root["id"]}));
    });
    let ev = events.clone();
    svc = svc.with_on_change(move |kind: &str, g: &Value| {
        ev.lock().unwrap().push(json!({"change": kind, "id": g["id"], "rev": g["rev"]}));
    });
    if flag("validateNeed") {
        svc = svc.with_validate_need(|n: &Value| if n["verb"] == "forbidden" { Some("verb not allowed".to_string()) } else { None });
    }
    let steps: Vec<Value> = spec["steps"].as_array().unwrap().iter().map(|raw| grant_step(&svc, &resolve(raw))).collect();
    let mut grants = store.list();
    grants.sort_by_key(|g| st(&g["id"]).encode_utf16().collect::<Vec<u16>>());
    let events = events.lock().unwrap().clone();
    Ok(json!({"steps": steps, "events": events, "grants": grants}))
}

// ---- leases -------------------------------------------------------------------------------------------------------------------

fn lease_scenario(spec: &Value) -> Result<Value, String> {
    let mut policy = LeasePolicy::new(vec![pubkey("auth")]);
    if let Some(p) = spec.get("policy") {
        policy.min_approvals = p.get("minApprovals").and_then(Value::as_i64);
        policy.eligible = p.get("eligibleApprovers").map(|e| strings(Some(e)));
        policy.max_ttl_ceiling = p.get("maxTtlCeiling").and_then(Value::as_i64);
    }
    let shards = spec.get("shards").and_then(Value::as_u64).unwrap_or(4) as usize;
    let sod_policy = policy.clone();
    let reg = LeaseRegistry::new(policy, Arc::new(MemoryAtomicKv::new())).with_shards(shards).with_clock(|| T0);
    let mut out: Vec<Value> = Vec::new();
    for raw in spec["steps"].as_array().unwrap() {
        let s = resolve(raw);
        let r = match st(&s["op"]) {
            "accept" => match reg.accept(&s["lease"], &strings(s.get("chain"))) {
                Ok((replaced, seq)) => json!({"ok": true, "replaced": replaced, "seq": seq}),
                // a separation-of-duties refusal carries its reason
                Err("sod") => json!({"ok": false, "code": "sod", "reason": atlas_pca::lease::sod_error(&s["lease"], &sod_policy, &strings(s.get("chain")))}),
                Err(code) => json!({"ok": false, "code": code}),
            },
            "revoke" => match reg.revoke(&s["rev"]) {
                Ok(n) => json!({"ok": true, "revoked": n}),
                Err(code) => json!({"ok": false, "code": code}),
            },
            "get" => match reg.get(st(&s["id"])) {
                Ok(v) => v.unwrap_or(Value::Null),
                Err(_) => err_x(),
            },
            "history" => match reg.history(st(&s["id"])) {
                Ok(h) => Value::Array(h),
                Err(_) => err_x(),
            },
            "shardRevs" => match s["i"].as_u64() {
                Some(i) if (i as usize) < reg.shard_count() => match reg.shard_revocations(i as usize) {
                    Ok(v) => Value::Array(v),
                    Err(_) => err_x(),
                },
                _ => err_x(),
            },
            "renew" => {
                let veto_seq = s.get("vetoSeq").and_then(Value::as_i64);
                let vf = move |c: &Value| c["seq"].as_i64().is_some_and(|q| q >= veto_seq.unwrap_or(i64::MAX));
                let veto: Option<&dyn Fn(&Value) -> bool> = if veto_seq.is_some() { Some(&vf) } else { None };
                let label = s.get("label").and_then(Value::as_str).unwrap_or("auth");
                let r =
                    renew_lease(&seed(label), &reg, st(&s["id"]), &s["now"], &s["increment"], &s["just"], s.get("approvers"), veto, &strings(s.get("chain")));
                if r["ok"] == true {
                    r
                } else {
                    json!({"ok": false, "code": r["code"]})
                }
            }
            "check" => lease_decision_json(&check_lease(&s["lease"], &reg, &s["now"])),
            "http" => {
                let mut req = Map::new();
                for k in ["method", "path", "query", "body", "who"] {
                    if let Some(v) = s.get(k) {
                        req.insert(k.to_string(), v.clone());
                    }
                }
                let auth = |r: &Value| r.get("who").filter(|w| !w.is_null()).cloned();
                let res = lease_http(&reg, &auth, &|| T0, &Value::Object(req));
                json!({"status": res["status"], "body": strip(&res["body"])})
            }
            other => panic!("bad op {other}"),
        };
        out.push(r);
    }
    Ok(Value::Array(out))
}

// ---- blueprints ---------------------------------------------------------------------------------------------------------------

fn blueprint_scenario(spec: &Value) -> Result<Value, String> {
    let reg = BlueprintRegistry::new(vec![pubkey("op")], Arc::new(MemoryBlueprintStore::new()));
    let adm = AdmissionRegistry::new();
    let revoked: Mutex<Vec<Value>> = Mutex::new(Vec::new());
    let mut fresh = FreshAtIssuer::new(
        seed("iss"),
        &json!("scope"),
        &json!({"revocation_epoch": 0, "ledger_tree_size": 0, "budget_version": 0, "policy_revision": 0, "policy_digest": "pd"}),
    );
    let mut out: Vec<Value> = Vec::new();
    for raw in spec["steps"].as_array().unwrap() {
        let s = resolve(raw);
        let r = match st(&s["op"]) {
            "accept" => match reg.accept(&s["bp"]) {
                Ok(replaced) => json!({"ok": true, "replaced": replaced}),
                Err(code) => json!({"ok": false, "code": code}),
            },
            "epoch" => match reg.epoch() {
                Ok(e) => json!(e),
                Err(_) => err_x(),
            },
            "kill" => {
                let label = s.get("label").and_then(Value::as_str).unwrap_or("op");
                let hook = |i: &Value| revoked.lock().unwrap().push(i.clone());
                let revoker: Option<&dyn Fn(&Value)> = if s.get("revoker") == Some(&json!(true)) { Some(&hook) } else { None };
                let fresh_at = if s.get("fresh") == Some(&json!(true)) { Some(&mut fresh) } else { None };
                match group_kill(&seed(label), &reg, st(&s["key"]), &s["now"], s.get("reason").and_then(Value::as_str), revoker, fresh_at) {
                    Ok(v) => v,
                    Err(_) => err_x(),
                }
            }
            "revoked" => Value::Array(revoked.lock().unwrap().clone()),
            "admit" => match reg.get(st(&s["key"])) {
                Ok(Some(bp)) => {
                    adm.admit(st(&s["instance"]), &bp, &s["until"]);
                    json!(true)
                }
                _ => err_x(),
            },
            "admitRevoke" => json!(adm.revoke(st(&s["instance"]), st(&s["key"]))),
            "admitCheck" => match reg.get(st(&s["key"])) {
                Ok(Some(bp)) => json!(adm.check(&s["now"], st(&s["instance"]), &bp)),
                _ => err_x(),
            },
            other => panic!("bad op {other}"),
        };
        out.push(r);
    }
    Ok(Value::Array(out))
}

fn admit_case(a: &[Value]) -> Result<Value, String> {
    let e = a[1].clone();
    let hook = move || -> Result<Value, String> {
        if e.get("$throw").is_some_and(|t| t != &json!(false) && !t.is_null()) {
            return Err("TypeError".to_string());
        }
        Ok(e.clone())
    };
    Ok(admit_with_evidence(&a[0], &hook))
}

// ---- dispatch -----------------------------------------------------------------------------------------------------------------

fn dispatch(f: &str, a: &[Value]) -> Result<Value, String> {
    let key = |i: usize| seed(st(&a[i]));
    match f {
        "signerOf" => Ok(json!(signer_of(&key(0)))),
        "signBody" => sign_body(st(&a[0]), &a[1], &key(2)).map(Value::String),
        "verifyBody" => Ok(json!(verify_body(st(&a[0]), &a[1], &a[2], &a[3]))),
        "signLease" => sign_lease(&key(0), &a[1]),
        "signLeaseUnsafeOverCap" => sign_lease_unsafe_over_cap(&key(0), &a[1]),
        "signLeaseRevocation" => sign_lease_revocation(&key(0), &a[1]),
        "signBlueprint" => sign_blueprint(&key(0), &a[1]),
        "signBreakGlass" => sign_break_glass(&key(0), &a[1]),
        "signBreakGlassReview" => sign_break_glass_review(&key(0), &a[1]),
        "signBundle" => sign_bundle(&a[0], &key(1)),
        "assembleBundle" => Ok(assemble_bundle(&a[0], &a[1])),
        "maskRecord" => mask_record(&a[0], &strings(Some(&a[1]))),
        "logScenario" => log_scenario(&a[0]),
        "replayScenario" => replay_scenario(&a[0]),
        "mergeFreshAt" => merge_fresh_at(&a[0], &a[1]),
        "gateDecision" => Ok(json!(gate_decision(st(&a[0]), &a[1]))),
        "freshScenario" => fresh_scenario(&a[0]),
        "shadowScenario" => shadow_scenario(&a[0]),
        "listScenario" => list_scenario(&a[0]),
        "windowAcc" => window_acc(a),
        "grantScenario" => grant_scenario(&a[0]),
        "leaseScenario" => lease_scenario(&a[0]),
        "blueprintScenario" => blueprint_scenario(&a[0]),
        "admitWithEvidence" => admit_case(a),
        other => panic!("unknown fn {other}"),
    }
}

#[test]
fn replays_the_grants_corpus() {
    let cases = common::ref_cases("grants");
    let (mut run, mut skipped) = (0usize, 0usize);
    for c in &cases {
        if common::has_lone(&c["args"]) || common::has_lone(&c["out"]) {
            skipped += 1;
            continue;
        }
        let name = st(&c["name"]);
        let got = dispatch(st(&c["fn"]), c["args"].as_array().unwrap());
        assert!(same(&c["out"], &got), "{name}: want {} got {got:?}", c["out"]);
        run += 1;
    }
    assert!(skipped * 10 < cases.len(), "{skipped} of {} cases skipped", cases.len());
    assert!(run > 2000, "only {run} cases replayed");
}
