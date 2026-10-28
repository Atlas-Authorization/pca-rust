mod common;
use atlas_pca::agent::*;
use atlas_pca::agent::{discharge_digest, sign_artifact}; // explicit: the crate root also exports a caveat-language discharge_digest
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::*;
use common::*;
use std::collections::HashMap;

// Replays packages/pca/conformance/producer-vectors.json against the Rust producers byte for byte (fixed keys, nonces and
// timestamps; Ed25519 is deterministic), then round-trips what they produce through this crate's verifier, ML-DSA suites included.

fn i(v: &Value) -> i64 {
    v.as_i64().expect("integer")
}
fn s(v: &Value) -> &str {
    v.as_str().expect("string")
}
fn arr(v: &Value) -> Vec<Value> {
    v.as_array().expect("array").clone()
}

fn run(op: &str, a: &Value, keys: &HashMap<String, KeyPair>) -> Value {
    let k = |n: &Value| &keys[s(n)];
    let d = Suite::default();
    let ok = |r: Result<Value, String>| r.unwrap_or_else(|e| panic!("{op}: {e}"));
    match op {
        "ed25519_sign" => {
            let kp = KeyPair::from_seed_b64u(s(&a["seed"])).unwrap();
            json!({"public": kp.public, "sig": base64_url(&kp.sign(s(&a["message_utf8"]).as_bytes()))})
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
            let h = pca_headers(&p, &[], None, None);
            json!({"pcactn": p, "header": h[0].1})
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
        o => panic!("unknown op {o}"),
    }
}

fn base64_url(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

#[test]
fn producer_vectors() {
    let doc = load("producer-vectors.json");
    let mut keys = HashMap::new();
    for (n, k) in doc["keys"].as_object().unwrap() {
        let kp = KeyPair::from_seed_b64u(s(&k["seed"])).unwrap();
        assert_eq!(kp.public, s(&k["public"]), "key {n}");
        keys.insert(n.clone(), kp);
    }
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 34);
    let mut bad = vec![];
    for c in cases {
        let mut want = c["expect"].clone();
        if c["op"] == "act" {
            want.as_object_mut().unwrap().remove("threshold_message");
        }
        // compare as parsed JSON (key order and number spelling are not part of the contract)
        let got: Value = atlas_pca::serde_json::from_str(&atlas_pca::serde_json::to_string(&run(s(&c["op"]), &c["args"], &keys)).unwrap()).unwrap();
        if got != want {
            bad.push(s(&c["name"]).to_string());
        }
    }
    assert!(bad.is_empty(), "producer output differs: {bad:?}");
}

fn grant_for(principal: &KeyPair, agent: &KeyPair, holder_pq: Option<&str>) -> Value {
    let env = json!({"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": default_risk_policy()});
    mint_grant(principal, &agent.public, &env, "refund an order", None, holder_pq, &Suite::default()).unwrap().grant
}

fn core_ok(p: &Value, grant: &Value, label: &str) {
    let v = verify_pcactn_core(p, grant, i(&p["iat"]), "rs-test");
    assert!(v.allow, "{label}: refused: {:?}", v.reason);
}

#[test]
fn agent_round_trip_delegate_plan() {
    let (principal, key, sub) = (KeyPair::generate().unwrap(), KeyPair::from_seed(&[7u8; 32]), KeyPair::generate().unwrap());
    let grant = grant_for(&principal, &key, None);
    let agent = Agent::new(KeyPair::from_seed(&[7u8; 32]), grant.clone(), "rs-test", 0);
    let params = json!({"amount_cents": 500});
    let a1 = agent.act("refund", "orders/1", Some(&params), Map::new(), &Suite::default()).unwrap();
    let a2 = agent.act("refund", "orders/1", Some(&params), Map::new(), &Suite::default()).unwrap();
    assert_eq!((i(&a1.pcactn["counter"]), i(&a2.pcactn["counter"])), (1, 2));
    assert_ne!(a1.pcactn["nonce"], a2.pcactn["nonce"]);
    core_ok(&a1.pcactn, &grant, "act");
    let mut t = a1.pcactn.clone();
    t["counter"] = json!(9);
    assert!(!verify_pcactn_core(&t, &grant, i(&t["iat"]), "rs-test").allow, "a tampered counter verified");

    let child = agent.delegate(sub, &json!([sealed_caveat()]), &Suite::default()).unwrap();
    let a = child.act("refund", "orders/2", None, Map::new(), &Suite::default()).unwrap();
    core_ok(&a.pcactn, &grant, "sub-agent");

    let mut planned = Agent::new(KeyPair::from_seed(&[7u8; 32]), grant.clone(), "rs-test", 0);
    planned.use_plan(vec![json!({"id": "a", "verb": "read", "resource": "x"}), json!({"id": "b", "verb": "refund", "resource": "orders/1"})]);
    core_ok(&planned.act("refund", "orders/1", None, Map::new(), &Suite::default()).unwrap().pcactn, &grant, "plan node");
    assert!(planned.act("delete", "everything", None, Map::new(), &Suite::default()).is_err());
}

#[test]
fn refuses_bad_input() {
    let (principal, key) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
    let bad = json!({"predicates": [], "caveats": [], "risk_policy": {}});
    assert!(mint_grant(&principal, &key.public, &bad, "g", None, None, &Suite::default()).is_err());
    let ok = json!({"predicates": [], "caveats": [], "risk_policy": default_risk_policy()});
    assert!(mint_grant(&principal, &key.public, &ok, "", None, None, &Suite::default()).is_err());
    let hw = issue_passport(&json!({"model_id": "m", "operator": "a", "hardware_rooted": true, "issued_at": 1})).unwrap();
    assert!(sign_passport(&hw, &principal, &key.public, None, None, 99, None, &Suite::default()).is_err());
    assert!(sign_discharge(&principal, "c", "l", "h", "chain_hop", None, &json!({}), 1, 2, None, &Suite { alg: Some("fn-dsa-512"), pq: None }).is_err());
}

#[test]
fn ml_dsa_hybrids_cross_verify() {
    for (alg, fam) in [("hybrid-ed25519-ml-dsa-65", "ML-DSA-65"), ("hybrid-nested-ed25519-ml-dsa-65", "ML-DSA-65"), ("ml-dsa-87", "ML-DSA-87"), ("hybrid-ed25519-slh-dsa-sha2-128f", "SLH-DSA-SHA2-128f")] {
        let pq = PqKeyPair::generate(fam).unwrap();
        let (principal, key) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
        let grant = grant_for(&principal, &key, Some(&pq.public));
        let node = json!({"id": "n1", "verb": "refund", "resource": "orders/1"});
        let p = build_pcactn(&PcactnInput {
            grant: &grant, chain: &[grant.clone()], plan: &[node], node_id: "n1", params: None, counter: 1, signer: &key, aud: "rs-test",
            iat: 1_800_000_000_000, exp: None, extra: Map::new(), suite: Suite { alg: Some(alg), pq: Some(&pq) },
        })
        .unwrap();
        assert_eq!(p["alg"], alg);
        core_ok(&p, &grant, alg);
        let other = PqKeyPair::generate(fam).unwrap();
        let node = json!({"id": "n1", "verb": "refund", "resource": "orders/1"});
        let f = build_pcactn(&PcactnInput {
            grant: &grant, chain: &[grant.clone()], plan: &[node], node_id: "n1", params: None, counter: 1, signer: &key, aud: "rs-test",
            iat: 1_800_000_000_000, exp: None, extra: Map::new(), suite: Suite { alg: Some(alg), pq: Some(&other) },
        })
        .unwrap();
        assert!(!verify_pcactn_core(&f, &grant, i(&f["iat"]), "rs-test").allow, "{alg}: an uncommitted PQ key verified");
    }
}

#[cfg(feature = "fndsa-sign")]
#[test]
fn fn_dsa_signs_and_verifies() {
    for (alg, fam) in [("fn-dsa-512", "FN-DSA-512"), ("fn-dsa-1024", "FN-DSA-1024")] {
        let pq = PqKeyPair::generate(fam).unwrap();
        let (principal, key) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
        let grant = grant_for(&principal, &key, Some(&pq.public));
        let node = json!({"id": "n1", "verb": "refund", "resource": "orders/1"});
        let p = build_pcactn(&PcactnInput {
            grant: &grant, chain: &[grant.clone()], plan: &[node], node_id: "n1", params: None, counter: 1, signer: &key, aud: "rs-test",
            iat: 1_800_000_000_000, exp: None, extra: Map::new(), suite: Suite { alg: Some(alg), pq: Some(&pq) },
        })
        .unwrap();
        core_ok(&p, &grant, alg);
    }
}

// ---- exact-outcome kill tests for the refusal paths, counters, nonces and header encoding (mutation-tested module) ----

fn err<T: std::fmt::Debug>(r: Result<T, String>) -> String {
    r.expect_err("expected a refusal")
}

fn env_with(k: &str, v: Value) -> Value {
    let mut e = json!({"predicates": [{"verb": "v", "resource": "r"}], "caveats": [], "risk_policy": default_risk_policy()});
    e[k] = v;
    e
}

fn rp_with(k: &str, v: Value) -> Value {
    let mut rp = default_risk_policy();
    rp[k] = v;
    env_with("risk_policy", rp)
}

#[test]
fn seeds_and_suites() {
    assert_eq!(err(KeyPair::from_seed_b64u("AAAA")), "an Ed25519 seed is 32 canonical base64url bytes");
    let k = KeyPair::from_seed(&[1u8; 32]);
    assert_eq!(KeyPair::from_seed_b64u(&base64_url(&[1u8; 32])).unwrap().public, k.public);
    assert_eq!(k.sign(b"m").len(), 64);
    let d = Suite::default();
    for alg in ["less-cat1", "hybrid-ed25519-less-cat1"] {
        let s = Suite { alg: Some(alg), pq: None };
        assert_eq!(err(sign_artifact("d", &json!({"v": 1}), &k, &s)), format!("unsupported_suite: {alg}"));
    }
    if cfg!(not(feature = "fndsa-sign")) {
        for alg in ["fn-dsa-512", "fn-dsa-1024"] {
            let s = Suite { alg: Some(alg), pq: None };
            assert_eq!(err(sign_artifact("d", &json!({"v": 1}), &k, &s)), format!("unsupported_suite: {alg}"));
            assert_eq!(err(PqKeyPair::generate(&alg.to_uppercase())), format!("unsupported_suite: {}", alg.to_uppercase()));
        }
    }
    assert_eq!(err(sign_artifact("d", &json!({"v": 1}), &k, &Suite { alg: Some("rot13"), pq: None })), "unknown signature alg \"rot13\"");
    assert_eq!(err(sign_artifact("d", &json!({"v": 1}), &k, &Suite { alg: Some("ml-dsa-65"), pq: None })), "a post-quantum suite needs a key pair");
    let pq87 = PqKeyPair::generate("ML-DSA-87").unwrap();
    assert_eq!(err(sign_artifact("d", &json!({"v": 1}), &k, &Suite { alg: Some("ml-dsa-65"), pq: Some(&pq87) })), "ml-dsa-65 needs a ML-DSA-65 key pair");
    let a = sign_artifact("d", &json!({"v": 1}), &k, &d).unwrap();
    assert_eq!(a.as_object().unwrap().len(), 2);
    let a = sign_artifact("d", &json!({"v": 1}), &k, &Suite { alg: Some("ed25519"), pq: None }).unwrap();
    assert!(a.get("alg").is_none() && a["sig"].is_string());
}

#[test]
fn mint_grant_refusals() {
    let (p, h) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
    let d = Suite::default();
    let mg = |env: &Value, goal: &str| err(mint_grant(&p, &h.public, env, goal, None, None, &d).map(|_| ()));
    let ok = env_with("caveats", json!([]));
    assert_eq!(mg(&ok, ""), "mint_grant: goal required");
    for k in ["predicates", "caveats", "risk_policy"] {
        let mut e = ok.clone();
        e.as_object_mut().unwrap().remove(k);
        assert_eq!(mg(&e, "g"), format!("mint_grant: envelope.{k} required"));
    }
    assert_eq!(mg(&env_with("risk_policy", json!({})), "g"), "mint_grant: risk_policy.weights missing");
    let mut w = default_risk_policy()["weights"].clone();
    w["alpha"] = json!(-1);
    assert_eq!(mg(&rp_with("weights", w), "g"), "mint_grant: risk_policy.weights.alpha must be finite and >= 0");
    assert_eq!(mg(&rp_with("theta1", json!("x")), "g"), "mint_grant: risk_policy.theta1 must be finite");
    assert_eq!(mg(&rp_with("theta1", json!(0.7)), "g"), "mint_grant: risk_policy requires 0 <= theta1 <= theta2");
    assert_eq!(mg(&rp_with("theta1", json!(-0.1)), "g"), "mint_grant: risk_policy requires 0 <= theta1 <= theta2");
    assert_eq!(mg(&rp_with("kappa", json!(0)), "g"), "mint_grant: risk_policy.kappa must be > 0");
    assert_eq!(mg(&rp_with("rho", json!(-1)), "g"), "mint_grant: risk_policy lambda/rho/bMax must be >= 0");
    assert_eq!(mg(&env_with("model_polarity", json!("strict")), "g"), "mint_grant: model_polarity must be 'legacy' when present");
    let g = mint_grant(&p, &h.public, &ok, "g", Some("abc"), None, &d).unwrap();
    assert_eq!((g.goal_salt.as_str(), g.goal_commit.as_str()), ("abc", goal_commit_of("g", "abc").unwrap().as_str()));
    let r = mint_grant(&p, &h.public, &ok, "g", None, None, &d).unwrap();
    assert_eq!(atlas_pca::decode_b64u_strict(&r.goal_salt, Some(16)).unwrap().len(), 16);
    let cav = &g.grant["caveats"][0];
    assert_eq!(cav["type"], "envelope");
    assert_eq!(cav["agent_binding"], json!({}));
    let l = mint_grant(&p, &h.public, &env_with("model_polarity", json!("legacy")), "g", None, None, &d).unwrap();
    assert_eq!(l.grant["caveats"][0]["model_polarity"], "legacy");
}

#[test]
fn delegation_and_plan_refusals() {
    let (p, k) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
    let d = Suite::default();
    let ok = env_with("caveats", json!([]));
    let grant = mint_grant(&p, &k.public, &ok, "g", None, None, &d).unwrap().grant;
    let add = json!({"type": "budget_alloc", "limit": 5});
    let child = delegate(&grant, &k, None, &json!([add]), None, &d).unwrap();
    assert_eq!(child["caveats"].as_array().unwrap().len(), grant["caveats"].as_array().unwrap().len() + 1);
    assert_eq!((child["holder"].as_str(), child["issuer"].as_str()), (Some(k.public.as_str()), Some(k.public.as_str())));
    assert_eq!(child["parent"], json!(atlas_pca::hash_canonical_strict(&grant).unwrap()));
    assert!(child.get("holder_pq").is_none());
    let pqg = mint_grant(&p, &k.public, &ok, "g", None, Some("PQKEY"), &d).unwrap().grant;
    let other = KeyPair::generate().unwrap();
    assert_eq!(delegate(&pqg, &k, None, &json!([]), None, &d).unwrap()["holder_pq"], pqg["holder_pq"]);
    assert!(delegate(&pqg, &k, Some(&other.public), &json!([]), None, &d).unwrap().get("holder_pq").is_none());
    assert_ne!(delegate(&pqg, &k, Some(&other.public), &json!([]), Some("OTHER"), &d).unwrap()["holder_pq"], pqg["holder_pq"]);

    let node = json!({"id": "a", "verb": "v", "resource": "r"});
    let build = |plan: &[Value], node_id: &str, aud: &str, params: Option<&Value>, exp: Option<i64>, extra: Map<String, Value>| {
        build_pcactn(&PcactnInput { grant: &grant, chain: &[grant.clone()], plan, node_id, params, counter: 1, signer: &k, aud, iat: 1000, exp, extra, suite: Suite::default() })
    };
    let one = [node.clone()];
    assert_eq!(err(build(&one, "a", "", None, None, Map::new())), "build_pcactn: aud (audience) is required");
    assert_eq!(err(build(&one, "zz", "x", None, None, Map::new())), "build_pcactn: unknown plan node zz");
    let pd = params_digest(Some(&json!({"x": 1})));
    let pinned = [json!({"id": "a", "verb": "v", "resource": "r", "params_digest": pd})];
    assert_eq!(err(build(&pinned, "a", "x", Some(&json!({"x": 2})), None, Map::new())), "build_pcactn: params do not match plan node a's params_digest");
    assert_eq!(err(plan_commit(&[node.clone(), node.clone()])), "commit_plan: duplicate node id a");
    assert_eq!(err(plan_commit(&[])), "commit_plan: empty plan");
    let x = build(&one, "a", "x", None, None, Map::new()).unwrap();
    assert_eq!((x["iat"].as_i64(), x["exp"].as_i64(), x["ver"].as_i64(), x["counter"].as_i64()), (Some(1000), Some(1000 + 20 * 60_000), Some(2), Some(1)));
    assert_eq!(x["action"]["reversibility_class"], "reversible");
    assert_eq!(build(&one, "a", "x", None, Some(5000), Map::new()).unwrap()["exp"], 5000);
    let mut extra = Map::new();
    extra.insert("nonce".into(), json!("n"));
    extra.insert("caution".into(), Value::Null);
    let e = build(&one, "a", "x", None, None, extra).unwrap();
    assert_eq!(e["nonce"], "n");
    assert!(e.get("caution").is_none());
}

#[test]
fn counter_nonce_hook_and_headers() {
    let (p, k) = (KeyPair::generate().unwrap(), KeyPair::from_seed(&[9u8; 32]));
    let grant = mint_grant(&p, &k.public, &env_with("caveats", json!([])), "g", None, None, &Suite::default()).unwrap().grant;
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<i64>::new()));
    let mut agent = Agent::new(k, grant.clone(), "rs", 41);
    agent.clock = || 5000;
    let s2 = seen.clone();
    agent.on_counter = Some(Box::new(move |n: i64| s2.lock().unwrap().push(n)));
    let d = Suite::default();
    let acts: Vec<_> = (0..3).map(|_| agent.act("v", "r", None, Map::new(), &d).unwrap()).collect();
    assert_eq!(acts.iter().map(|a| a.pcactn["counter"].as_i64().unwrap()).collect::<Vec<_>>(), vec![42, 43, 44]);
    assert_eq!(*seen.lock().unwrap(), vec![42, 43, 44]);
    let nonces: std::collections::HashSet<_> = acts.iter().map(|a| a.pcactn["nonce"].as_str().unwrap().to_string()).collect();
    assert_eq!(nonces.len(), 3);
    for a in &acts {
        assert_eq!(atlas_pca::decode_b64u_strict(a.pcactn["nonce"].as_str().unwrap(), Some(16)).unwrap().len(), 16);
        assert_eq!((a.pcactn["iat"].as_i64(), a.pcactn["exp"].as_i64(), a.pcactn["aud"].as_str(), a.node_id.as_str()), (Some(5000), Some(5000 + 20 * 60_000), Some("rs"), "n1"));
    }
    let sub = agent.delegate(KeyPair::generate().unwrap(), &json!([]), &d).unwrap();
    assert_eq!(sub.act("v", "r", None, Map::new(), &d).unwrap().pcactn["counter"], 1);
    assert_eq!((sub.chain.len(), agent.chain.len()), (2, 1));
    let mut fixed = Map::new();
    fixed.insert("nonce".into(), json!("fixed"));
    assert_eq!(agent.act("v", "r", None, fixed, &d).unwrap().pcactn["nonce"], "fixed");
    let mut planned = Agent::new(KeyPair::generate().unwrap(), grant, "rs", 0);
    planned.use_plan(vec![json!({"id": "a", "verb": "v", "resource": "r"})]);
    assert_eq!(err(planned.act("v", "nope", None, Map::new(), &d).map(|_| ())), "act: no node of the committed plan matches v nope");

    // header encoding
    let a = &acts[0];
    assert_eq!(a.headers.len(), 1);
    assert_eq!(a.headers[0].0, "PCA-Action");
    assert!(!a.headers[0].1.contains('='));
    assert_eq!(atlas_pca::decode_b64u_strict(&a.headers[0].1, None).unwrap(), canonicalize(&a.pcactn).into_bytes());
    let full = pca_headers(&a.pcactn, &[json!({"d": 1})], Some(&json!({"n": 2})), Some(&json!({"a": 3})));
    assert_eq!(full.iter().map(|h| h.0.as_str()).collect::<Vec<_>>(), vec!["PCA-Action", "PCA-Discharges", "PCA-Narrow", "PCA-Escalation-Answer"]);
    for (i, body) in [(1, r#"[{"d":1}]"#), (2, r#"{"n":2}"#), (3, r#"{"a":3}"#)] {
        assert_eq!(atlas_pca::decode_b64u_strict(&full[i].1, None).unwrap(), body.as_bytes());
    }
    assert_eq!(pca_headers(&a.pcactn, &[], None, None).len(), 1);
}

#[test]
fn signer_answer_and_passport_refusals() {
    let (k, o) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
    let d = Suite::default();
    let body = json!({"principal": k.public});
    assert_eq!(err(sign_workflow(&o, &body)), "sign_workflow: principal is not the signer");
    assert_eq!(err(sign_read_grant(&o, &body)), "sign_read_grant: principal is not the signer");
    assert_eq!(err(sign_aggregate_grant(&o, &body)), "sign_aggregate_grant: principal is not the signer");
    let req = json!({"policy_digest": "a", "action_digest": "b", "history_head": "c"});
    assert_eq!(err(sign_escalation_answer(&o, &req, "maybe", 1, 2, None, &d)), "decision must be 'allow' or 'deny'");
    let pp = issue_passport(&json!({"model_id": "m", "operator": "o", "hardware_rooted": false, "issued_at": 10})).unwrap();
    let hw = issue_passport(&json!({"model_id": "m", "operator": "o", "hardware_rooted": true, "issued_at": 10})).unwrap();
    assert_eq!(err(sign_passport(&pp, &o, &k.public, None, None, 10, None, &d)), "sign_passport: exp must be after nbf");
    let mut forged = pp.clone();
    forged["model_id"] = json!("other");
    assert_eq!(err(sign_passport(&forged, &o, &k.public, None, None, 99, None, &d)), "sign_passport: passport.id is not the fingerprint of its identity (use issue_passport)");
    assert_eq!(err(sign_passport(&hw, &o, &k.public, None, None, 99, None, &d)), "sign_passport: hardware_rooted requires attestation evidence (fail closed)");
    let sp = sign_passport(&pp, &o, &k.public, None, None, 99, None, &d).unwrap();
    assert_eq!((sp["iat"].as_i64(), sp["nbf"].as_i64(), sp["exp"].as_i64()), (Some(10), Some(10), Some(99)));
    assert_eq!(sign_passport(&pp, &o, &k.public, Some(20), Some(30), 99, None, &d).unwrap()["nbf"], 30);
}
