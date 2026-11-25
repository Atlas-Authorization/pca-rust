// The producer op dispatch shared by the producer-vector replay (tests/agent_producer.rs) and the differential driver's
// `produce` kind (tools/pca-diff-fuzz/drivers/rust): one case of producer-vectors.json or producer-pq-vectors.json in, the
// artifact (the case's `expect`) or `{error}` out. An op this crate does not produce answers `{error: "unsupported_op: <op>"}`;
// a suite it does not sign answers an error containing `unsupported_suite`.
#![allow(dead_code)]
use atlas_pca::agent::*;
use atlas_pca::agent::discharge_digest; // explicit: the crate root also exports a caveat-language discharge_digest
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::*;
use std::collections::HashMap;

pub fn i(v: &Value) -> i64 {
    v.as_i64().expect("integer")
}
pub fn s(v: &Value) -> &str {
    v.as_str().expect("string")
}
pub fn arr(v: &Value) -> Vec<Value> {
    v.as_array().expect("array").clone()
}


pub fn run(op: &str, a: &Value, keys: &HashMap<String, KeyPair>, seeds: &HashMap<String, String>, pq: &HashMap<String, Value>) -> Value {
    let k = |n: &Value| &keys[s(n)];
    let own = |n: &Value| KeyPair::from_seed_b64u(&seeds[s(n)]).unwrap();
    let d = Suite::default();
    // a refusal answers {error}: the producer must refuse (and sign nothing)
    let res = |r: Result<Value, String>| r.unwrap_or_else(|e| json!({"error": e}));
    let ok = res;
    match op {
        "ed25519_sign" => {
            let kp = KeyPair::from_seed_b64u(s(&a["seed"])).unwrap();
            json!({"public": kp.public, "sig": b64u(&kp.sign(s(&a["message_utf8"]).as_bytes()))})
        }
        "goal_commit" => json!({"commit": goal_commit_of(s(&a["goal"]), s(&a["salt"])).unwrap()}),
        "params_digest" => json!({"digest": params_digest(if a["params"].is_null() { None } else { Some(&a["params"]) })}),
        "plan_commit" => ok(plan_commit(&arr(&a["nodes"]))),
        "mint_grant" => {
            let r = mint_grant(k(&a["principal"]), &k(&a["holder"]).public, &a["envelope"], s(&a["goal"]), Some(s(&a["salt"])), None, &d).unwrap();
            json!({"grant": r.grant, "goal_commit": r.goal_commit, "goal_salt": r.goal_salt})
        }
        "delegate" => {
            let to = a["to_holder"].as_str().map(|n| keys[n].public.clone());
            ok(delegate(&a["parent"], k(&a["signer"]), to.as_deref(), &a["added_caveats"], None, &d))
        }
        "act" => {
            let mut extra = Map::new();
            for n in ["nonce", "caution", "rationale_commitment", "tool_binding", "fresh_at"] {
                if let Some(v) = a.get(n) {
                    extra.insert(n.into(), v.clone());
                }
            }
            let p = ok(build_pcactn(&PcactnInput {
                grant: &a["grant"], chain: &arr(&a["chain"]), plan: &arr(&a["plan"]), node_id: s(&a["node_id"]),
                params: a.get("params").filter(|v| !v.is_null()), counter: i(&a["counter"]), signer: k(&a["signer"]), aud: s(&a["aud"]),
                iat: i(&a["iat"]), exp: Some(i(&a["exp"])), extra, suite: Suite::default(),
            }));
            if p.get("error").is_some() {
                return p;
            }
            let h = pca_headers(&p, &[], None, None);
            let tm = threshold_message(p.as_object().unwrap()).unwrap();
            json!({"pcactn": p, "threshold_message": b64u(&tm), "header": h[0].1})
        }
        "fresh_at" => ok(sign_fresh_at(k(&a["signer"]), s(&a["scope"]), &a["state"], i(&a["issued_at"]))),
        "escalation_digests" => json!({
            "policy_digest": escalation_policy_digest(&a["grant"]).unwrap(),
            "action_digest": escalation_action_digest(&a["pcactn"]).unwrap(),
            "history_head": escalation_history_head(a["last_counter"].as_u64()).unwrap()}),
        "sign_escalation_answer" => {
            let b = &a["body"];
            ok(sign_escalation_answer(k(&a["signer"]), b, s(&b["decision"]), i(&b["iat"]), i(&b["expires_at"]), Some(s(&b["nonce"])), &d))
        }
        "sign_discharge" => {
            let b = &a["body"];
            ok(sign_discharge(k(&a["signer"]), s(&b["caveat_id"]), s(&b["issuer"]), s(&b["cap_hash"]), s(&b["bind"]), b["action_digest"].as_str(),
                &b["claims"], i(&b["iat"]), i(&b["not_after"]), Some(s(&b["nonce"])), &d))
        }
        "discharge_digest" => json!({"digest": discharge_digest(&a["discharge"]).unwrap()}),
        "sign_narrow" => {
            let b = &a["body"];
            ok(sign_narrow(k(&a["signer"]), s(&b["cap_hash"]), &b["caveats"], i(&b["iat"]), i(&b["not_after"]), b["action_digest"].as_str(), Some(s(&b["nonce"])), &d))
        }
        "sign_passport" => {
            let pp = issue_passport(&a["identity"]).unwrap();
            let sp = ok(sign_passport(&pp, k(&a["issuer"]), &k(&a["subject"]).public, None, None, i(&a["exp"]), None, &d));
            json!({"passport": pp, "signed": sp})
        }
        "sign_workflow" => ok(sign_workflow(k(&a["signer"]), &a["body"])),
        "sign_step_receipt" => ok(sign_step_receipt(k(&a["signer"]), &a["workflow"], s(&a["step"]), s(&a["outcome"]), s(&a["params_digest"]), &a["outputs"],
            i(&a["issued_at"]), a.get("prev").filter(|v| v.is_object()))),
        "sign_read_grant" => ok(sign_read_grant(k(&a["signer"]), &a["body"])),
        "sign_aggregate_grant" => ok(sign_aggregate_grant(k(&a["signer"]), &a["body"])),
        "sign_revocation_epoch" => res(sign_revocation_epoch(k(&a["signer"]), &a["body"], &d)),
        "sign_undo_token" => res(atlas_pca::undo::sign_undo_token(&a["record"], k(&a["signer"]))),
        "sign_undo_receipt" => res(atlas_pca::undo::sign_undo_receipt(&a["body"], k(&a["signer"]))),
        "sign_contract" => res(atlas_pca::contracts::sign_contract(&a["contract"], k(&a["signer"]))),
        "sign_contract_reset" => json!({"sig": atlas_pca::contracts::sign_contract_reset(k(&a["signer"]), s(&a["contract_id"]), i(&a["seq"]))}),
        "sign_constitution" => res(sign_constitution(k(&a["signer"]), &a["constitution"])),
        "sign_safety_evidence" => res(sign_safety_evidence(k(&a["signer"]), &a["evidence"])),
        "sign_threshold_share" => res(sign_threshold_share(s(&a["role"]), k(&a["signer"]), &raw(&a["message"]), &arr(&a["signer_set"]), i(&a["t"]), &d)),
        "sign_prepared_share" => res(sign_prepared_share(s(&a["role"]), k(&a["signer"]), &raw(&a["prepared"]), &d)),
        "sign_pq_binding" => res(sign_pq_binding(k(&a["signer"]), s(&a["pq_pk"]), i(&a["epoch"]), s(&a["aud"]))),
        "sign_caution" => res(sign_caution(k(&a["signer"]), &a["body"])),
        "sign_heartbeat" => res(sign_heartbeat(k(&a["signer"]), &a["body"])),
        "prov_recorder" => {
            let clock: Vec<i64> = arr(&a["clock"]).iter().map(i).collect();
            let tick = std::sync::atomic::AtomicUsize::new(0);
            let seed: [u8; 32] = raw(&json!(seeds[s(&a["key"])])).try_into().unwrap();
            let mut r = atlas_pca::arg_provenance::ProvenanceRecorder::new(s(&a["mediator"]), s(&a["kid"]), Some(seed))
                .unwrap()
                .with_session(s(&a["session"]))
                .unwrap()
                .with_clock(move || clock[tick.fetch_add(1, std::sync::atomic::Ordering::SeqCst)]);
            let outs: Vec<Value> = arr(&a["steps"])
                .iter()
                .map(|st| match s(&st["kind"]) {
                    "principal" => r.principal(s(&st["text"])),
                    "tool" => r.tool(s(&st["name"]), &st["output"]),
                    "retrieval" => r.retrieval(s(&st["source"]), &st["content"]),
                    "web" => r.web(s(&st["url"]), &st["content"]),
                    _ => r.for_action(&Operation::new(s(&st["op"]["verb"]), s(&st["op"]["resource"]), st["op"]["params"].clone())),
                })
                .collect::<Result<_, _>>()
                .unwrap();
            json!({"pin": r.pin(), "receipts": outs[..outs.len() - 1], "bundle": outs[outs.len() - 1]})
        }
        "sign_mesh_action" => json!({"sig": sign_mesh_action(&arr(&a["chain"]), &a["action"], k(&a["signer"])).unwrap()}),
        "sign_session_root" => res(sign_session_root(k(&a["signer"]), &a["body"], &d)),
        "mint_session_grant" => {
            let holder = k(&a["holder"]).public.clone();
            let r = mint_session_grant(&SessionGrantInput {
                principal: k(&a["principal"]), holder: &holder, holder_pq: None, session: s(&a["session"]), seq: i(&a["seq"]), prev: a["prev"].as_str(),
                root: s(&a["root"]), map_digest: s(&a["map_digest"]), map_form: a["map_form"].as_str(), predicates: &a["predicates"],
                caveats: a.get("caveats").filter(|v| !v.is_null()), agent_binding: None, risk_policy: None, salt: a["salt"].as_str(), suite: Suite::default(),
            });
            match r {
                Ok((grant, salt)) => json!({"grant": grant, "goal_salt": salt}),
                Err(e) => json!({"error": e}),
            }
        }
        "sign_action_schema" => res(sign_action_schema(&a["doc"], s(&a["kid"]), k(&a["signer"]), &d)),
        "sign_intent_required" => res(sign_intent_required(&a["body"], s(&a["kid"]), k(&a["signer"]), &d)),
        "sign_progress_step" => res(sign_progress_step(&a["step"], k(&a["signer"]))),
        "sign_labels" => res(sign_labels(&a["body"], k(&a["signer"]), &d)),
        "sign_fact" => res(sign_fact(&a["body"], k(&a["signer"]), &d)),
        "sign_offer_set" => res(sign_offer_set(&a["body"], k(&a["signer"]), &d)),
        "sign_read_receipt" => res(sign_read_receipt(k(&a["signer"]), &a["grant"], s(&a["verb"]), s(&a["resource"]), s(&a["purpose"]), &a["fields"], &a["labels"],
            i(&a["issued_at"]), a.get("prev").filter(|v| v.is_object()))),
        "sign_template" => res(sign_template(&a["def"], k(&a["signer"]))),
        "sign_tighten" => res(sign_tighten(&a["overlay"], k(&a["signer"]))),
        "parse_limit" => res(parse_limit(s(&a["limit"])).map(|l| l.to_json())),
        "compile_policy" => res(compile_policy(&CompileOptions {
            permissions: &a["permissions"], limits: a.get("limits"), catalog: None, budget_model: a["budget_model"].as_str(), risk_policy: None, now: i(&a["now"]),
        })
        .map(|c| {
            let mut j = c.to_json();
            let m = j.as_object_mut().unwrap();
            m.remove("actions");
            m.remove("inputLimits");
            j
        })),
        "facade_act" => {
            let seed: [u8; 32] = raw(&json!(seeds[s(&a["recorder_key"])])).try_into().unwrap();
            let now = i(&a["now"]);
            let rec = atlas_pca::arg_provenance::ProvenanceRecorder::new("agent-harness", "k1", Some(seed)).unwrap().with_session(s(&a["session"])).unwrap().with_clock(move || now);
            let principal = own(&a["principal"]);
            let mut o = AgentOptions::new(&principal, s(&a["goal"]), &a["permissions"]);
            o.limits = a.get("limits");
            o.holder = Some(own(&a["holder"]));
            o.aud = a["aud"].as_str();
            o.now = Some(now);
            o.provenance = Some(rec);
            o.goal_salt = a["goal_salt"].as_str();
            let base = create_agent(o).unwrap();
            for t in a.get("principal_messages").map(arr).unwrap_or_default() {
                base.provenance().lock().unwrap().principal(s(&t)).unwrap();
            }
            let sub = a.get("sub_agent").map(|sa| base.sub_agent(SubAgentOptions { holder: Some(own(&sa["holder"])), added_caveats: Some(sa["added_caveats"].clone()) }).unwrap());
            let h = sub.as_ref().unwrap_or(&base);
            let act = &a["act"];
            let opts = ActOptions { counter: act["counter"].as_i64(), now: act["now"].as_i64(), nonce: act["nonce"].as_str().map(String::from), ..ActOptions::default() };
            let r = h.act(s(&act["verb"]), s(&act["resource"]), act.get("params").filter(|v| !v.is_null()), &opts).unwrap();
            json!({"grant": base.grant, "goal_commit": base.grant["caveats"][0]["goal_commit"], "chain": h.chain, "pcactn": r.pcactn, "encoded": r.encoded,
                "provenance": r.provenance})
        }
        "pq_keygen" => res(pq_from(&json!({"family": a["family"], "seed": a["seed"]})).map(|p| json!({"public": p.public}))),
        "suite_sign" | "mint_root_suite" | "delegate_suite" | "sign_pcactn_suite" | "sign_artifact_suite" => res(suite_op(op, a, keys, pq)),
        o => json!({"error": format!("unsupported_op: {o}")}),
    }
}

pub fn raw(v: &Value) -> Vec<u8> {
    atlas_pca::decode_b64u_strict(s(v), None).expect("base64url")
}


pub fn family_of(f: &str) -> Result<&'static str, String> {
    Ok(match f {
        "ml-dsa-65" => "ML-DSA-65",
        "ml-dsa-87" => "ML-DSA-87",
        "slh-dsa-sha2-128f" => "SLH-DSA-SHA2-128f",
        "slh-dsa-sha2-256s" => "SLH-DSA-SHA2-256s",
        "fn-dsa-512" => "FN-DSA-512",
        "fn-dsa-1024" => "FN-DSA-1024",
        o => return Err(format!("unsupported_suite: {o}")),
    })
}

/// A vector's PQ key `{family, seed, sign_seed?}` (FN-DSA signs from `sign_seed` under the `fndsa-sign` feature; without it,
/// FN-DSA is an unsupported suite).
pub fn pq_from(k: &Value) -> Result<PqKeyPair, String> {
    let p = PqKeyPair::from_seed(family_of(s(&k["family"]))?, &raw(&k["seed"]))?;
    #[cfg(feature = "fndsa-sign")]
    let p = match k.get("sign_seed").and_then(Value::as_str) {
        Some(ss) => p.with_fn_dsa_sign_seed(raw(&json!(ss)).try_into().map_err(|_| "a sign seed is 32 bytes".to_string())?)?,
        None => p,
    };
    Ok(p)
}

fn pq_named(pq: &HashMap<String, Value>, n: &str) -> Result<PqKeyPair, String> {
    pq_from(pq.get(n).ok_or_else(|| format!("unknown pq key {n}"))?)
}

/// The suite-parameterised ops of producer-pq-vectors.json.
fn suite_op(op: &str, a: &Value, keys: &HashMap<String, KeyPair>, pq: &HashMap<String, Value>) -> Result<Value, String> {
    let pqk = match a.get("pq").and_then(Value::as_str) {
        Some(n) => Some(pq_named(pq, n)?),
        None => None,
    };
    let suite = Suite { alg: a["alg"].as_str(), pq: pqk.as_ref() };
    let ed = |n: &str| a.get(n).and_then(Value::as_str).map(|x| &keys[x]);
    let hpq = match a.get("holder_pq").and_then(Value::as_str) {
        Some(n) => Some(pq.get(n).and_then(|k| k["public"].as_str()).ok_or_else(|| format!("unknown pq key {n}"))?.to_string()),
        None => None,
    };
    match op {
        "suite_sign" => {
            let (sig, pq_sig) = sign_with_suite(&suite, ed("ed"), s(&a["message_utf8"]).as_bytes())?;
            let mut o = json!({"sig": sig});
            if let Some(p) = pq_sig {
                o["pq_sig"] = json!(p);
            }
            Ok(o)
        }
        "mint_root_suite" => mint_root(ed("principal").ok_or("principal required")?, &keys[s(&a["holder"])].public, &a["caveats"], hpq.as_deref(), &suite),
        "delegate_suite" => {
            let to = a["to_holder"].as_str().map(|n| keys[n].public.clone());
            delegate(&a["parent"], ed("signer").ok_or("signer required")?, to.as_deref(), &a["added_caveats"], hpq.as_deref(), &suite)
        }
        "sign_pcactn_suite" => Ok(json!({"pcactn": sign_pcactn(&a["body"], ed("signer").ok_or("signer required")?, &suite)?})),
        _ => {
            let (b, k) = (&a["body"], ed("signer").ok_or("signer required")?);
            match s(&a["kind"]) {
                "escalation_answer" => sign_escalation_answer(k, b, s(&b["decision"]), i(&b["iat"]), i(&b["expires_at"]), b["nonce"].as_str(), &suite),
                "revocation_epoch" => sign_revocation_epoch(k, b, &suite),
                o => Err(format!("unsupported_op: sign_artifact_suite/{o}")),
            }
        }
    }
}

pub fn b64u(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut o = String::with_capacity(b.len() * 4 / 3 + 3);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for j in 0..=c.len() {
            o.push(A[(n >> (18 - 6 * j)) as usize & 63] as char);
        }
    }
    o
}

/// One `produce` case `{op, args, keys, pq_keys?}` (keys: name -> `{seed, public}`): `{out}` or `{error}`.
pub fn produce(case: &Value) -> Value {
    let mut keys = HashMap::new();
    let mut seeds = HashMap::new();
    for (n, k) in case["keys"].as_object().into_iter().flatten() {
        match k["seed"].as_str().map(KeyPair::from_seed_b64u) {
            Some(Ok(kp)) => {
                keys.insert(n.clone(), kp);
                seeds.insert(n.clone(), s(&k["seed"]).to_string());
            }
            _ => return json!({"error": format!("bad key {n}")}),
        }
    }
    let pq: HashMap<String, Value> = case["pq_keys"].as_object().map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default();
    let out = run(case["op"].as_str().unwrap_or(""), &case["args"], &keys, &seeds, &pq);
    match out.as_object().filter(|o| o.len() == 1).and_then(|o| o.get("error")) {
        Some(e) => json!({"error": e}),
        None => json!({"out": out}),
    }
}
