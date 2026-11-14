mod common;
use atlas_pca::agent::*;
use atlas_pca::agent::sign_artifact;
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::*;
use common::*;
#[path = "producer/ops.rs"]
mod ops;
use ops::*;
use std::collections::HashMap;

// Replays packages/pca/conformance/producer-vectors.json against the Rust producers byte for byte (fixed keys, nonces and
// timestamps; Ed25519 is deterministic), then round-trips what they produce through this crate's verifier, ML-DSA suites included.

fn base64_url(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

#[test]
fn producer_vectors() {
    let doc = load("producer-vectors.json");
    let mut keys = HashMap::new();
    let mut seeds = HashMap::new();
    for (n, k) in doc["keys"].as_object().unwrap() {
        let kp = KeyPair::from_seed_b64u(s(&k["seed"])).unwrap();
        assert_eq!(kp.public, s(&k["public"]), "key {n}");
        keys.insert(n.clone(), kp);
        seeds.insert(n.clone(), s(&k["seed"]).to_string());
    }
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 89);
    let mut bad = vec![];
    for c in cases {
        // compare as parsed JSON (key order and number spelling are not part of the contract)
        let got = reparse(&run(s(&c["op"]), &c["args"], &keys, &seeds, &HashMap::new()));
        if got != c["expect"] {
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
    core_ok_aud(p, grant, label, "rs-test")
}

fn core_ok_aud(p: &Value, grant: &Value, label: &str, aud: &str) {
    let v = verify_pcactn_core_with(p, grant, i(&p["iat"]), aud, &atlas_pca::VerifyOptions { insecure_skip_plan_root_check: true, ..atlas_pca::VerifyOptions::default() });
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
    assert!(!verify_pcactn_core_with(&t, &grant, i(&t["iat"]), "rs-test", &atlas_pca::VerifyOptions { insecure_skip_plan_root_check: true, ..atlas_pca::VerifyOptions::default() }).allow, "a tampered counter verified");

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
        assert!(!verify_pcactn_core_with(&f, &grant, i(&f["iat"]), "rs-test", &atlas_pca::VerifyOptions { insecure_skip_plan_root_check: true, ..atlas_pca::VerifyOptions::default() }).allow, "{alg}: an uncommitted PQ key verified");
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
    // a signed answer every verifier would refuse is never handed out: a short caller nonce fails the reference shape check
    let ok_req = json!({"policy_digest": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "action_digest": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI", "history_head": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"});
    assert!(sign_escalation_answer(&o, &ok_req, "allow", 1, 2, None, &d).is_ok());
    assert_eq!(err(sign_escalation_answer(&o, &ok_req, "allow", 1, 2, Some("n1"), &d)), "sign_escalation_answer: nonce must be canonical base64url of at least 16 bytes");
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

#[test]
fn budget_alloc_is_monotone_down_the_chain() {
    let (p, k) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
    let d = Suite::default();
    let grant = mint_grant(&p, &k.public, &env_with("caveats", json!([])), "g", None, None, &d).unwrap().grant;
    let alloc = |parent: &Value, limit: i64| delegate(parent, &k, None, &json!([{"type": "budget_alloc", "limit": limit}]), None, &d).unwrap();
    let issuer = grant["issuer"].as_str().unwrap().to_string();

    let ten = alloc(&grant, 10);
    let same = alloc(&ten, 10);
    let four = alloc(&same, 4);
    assert_eq!(verify_chain(&[grant.clone(), ten.clone(), same.clone(), four], Some(&issuer)), Ok(()));
    let wide = alloc(&ten, 100);
    assert_eq!(
        verify_chain(&[grant.clone(), ten, wide], Some(&issuer)),
        // The grant's envelope is caveat 0.
        Err("budget_alloc caveat 2: allocation 100 widens the parent's carried allocation 10 (monotone: a child can only allocate <= its parent)".to_string())
    );
}

#[test]
fn allocations_monotone_matches_the_reference_cases() {
    let a = |l: Value| json!({"type": "budget_alloc", "limit": l});
    let bad = |i: usize| Err(format!("budget_alloc caveat {i}: limit must be a finite number >= 0"));
    assert_eq!(allocations_monotone(&[]), Ok(()));
    assert_eq!(allocations_monotone(&[json!({"type": "expires", "at": 1})]), Ok(()));
    assert_eq!(allocations_monotone(&[a(json!(10)), a(json!(10)), a(json!(4)), a(json!(0))]), Ok(()));
    assert_eq!(allocations_monotone(&[json!({"type": "x"}), a(json!(-1))]), bad(1));
    assert_eq!(allocations_monotone(&[a(json!("3"))]), bad(0));
    assert_eq!(allocations_monotone(&[json!({"type": "budget_alloc"})]), bad(0));
    assert_eq!(allocations_monotone(&[a(json!(0))]), Ok(()));
    // Other caveats between two allocations do not reset the carried limit, and fractions print as in JS.
    assert_eq!(
        allocations_monotone(&[a(json!(1.5)), json!({"type": "ttl"}), a(json!(2.5))]),
        Err("budget_alloc caveat 2: allocation 2.5 widens the parent's carried allocation 1.5 (monotone: a child can only allocate <= its parent)".to_string())
    );
}

#[test]
fn a_carried_zk_proof_fails_the_core_without_a_verifier() {
    let (p, k) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
    let grant = grant_for(&p, &k, None);
    let plan = [json!({"id": "a", "verb": "refund", "resource": "orders/1"})];
    let build = |extra: Map<String, Value>| {
        build_pcactn(&PcactnInput { grant: &grant, chain: &[grant.clone()], plan: &plan, node_id: "a", params: None, counter: 1, signer: &k, aud: "rs-test", iat: 1000, exp: None, extra, suite: Suite::default() }).unwrap()
    };
    let plain = build(Map::new());
    core_ok(&plain, &grant, "no proof");
    let v = verify_pcactn_core_with(&plain, &grant, i(&plain["iat"]), "rs-test", &atlas_pca::VerifyOptions { insecure_skip_plan_root_check: true, ..atlas_pca::VerifyOptions::default() });
    assert!(!v.checks.contains_key("zk_compliance"), "no proof, no check");

    let mut extra = Map::new();
    extra.insert("zk_compliance".to_string(), json!({"proof": "x"}));
    let carried = build(extra);
    let v = verify_pcactn_core_with(&carried, &grant, i(&carried["iat"]), "rs-test", &atlas_pca::VerifyOptions { insecure_skip_plan_root_check: true, ..atlas_pca::VerifyOptions::default() });
    assert!(!v.allow);
    assert_eq!(v.checks.get("zk_compliance"), Some(&false));
    assert_eq!(v.reason, "zk_compliance: PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof");
}

// ---- deterministic post-quantum vectors (producer-pq-vectors.json) ----------------------------------------------------------

fn reparse(v: &Value) -> Value {
    atlas_pca::serde_json::from_str(&atlas_pca::serde_json::to_string(v).unwrap()).unwrap()
}

#[test]
fn producer_pq_vectors() {
    let doc = load("producer-pq-vectors.json");
    let fndsa = cfg!(feature = "fndsa-sign");
    let mut keys = HashMap::new();
    let mut seeds = HashMap::new();
    for (n, k) in doc["ed_keys"].as_object().unwrap() {
        keys.insert(n.clone(), KeyPair::from_seed_b64u(s(&k["seed"])).unwrap());
        seeds.insert(n.clone(), s(&k["seed"]).to_string());
    }
    let pq: HashMap<String, Value> = doc["pq_keys"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    for (n, k) in &pq {
        match pq_from(k) {
            Ok(p) => assert_eq!(p.public, s(&k["public"]), "pq key {n}"),
            // without the `fndsa-sign` feature FN-DSA is an unsupported suite (CI also runs this test with the feature)
            Err(e) => assert!(!fndsa && s(&k["family"]).starts_with("fn-dsa") && e.contains("unsupported_suite"), "pq key {n}: {e}"),
        }
    }
    let (mut bad, mut ran) = (vec![], 0);
    for c in doc["cases"].as_array().unwrap() {
        let a = &c["args"];
        let fn_case = c["alg"].as_str().or(a.get("family").and_then(Value::as_str)).is_some_and(|f| f.contains("fn-dsa"));
        let got = reparse(&run(s(&c["op"]), a, &keys, &seeds, &pq));
        if fn_case && !fndsa {
            assert!(got["error"].as_str().is_some_and(|e| e.contains("unsupported_suite")), "{}: {got}", s(&c["name"]));
            continue;
        }
        assert!(c["exact"].as_array().unwrap().iter().any(|l| l == "rust"), "{}: rust must reproduce it exactly", s(&c["name"]));
        ran += 1;
        if got != c["expect"] {
            bad.push(s(&c["name"]).to_string());
        }
    }
    assert!(ran >= if fndsa { 90 } else { 74 }, "only {ran} cases ran");
    assert!(bad.is_empty(), "post-quantum producer output differs: {bad:?}");
}

#[test]
fn produce_answers_out_error_and_unsupported_op() {
    let doc = load("producer-vectors.json");
    let c = doc["cases"].as_array().unwrap().iter().find(|c| c["op"] == "goal_commit").unwrap();
    let case = json!({"op": c["op"], "args": c["args"], "keys": doc["keys"]});
    assert_eq!(produce(&case), json!({"out": c["expect"]}));
    assert_eq!(produce(&json!({"op": "sign_everything", "args": {}, "keys": {}})), json!({"error": "unsupported_op: sign_everything"}));
    let refusal = doc["cases"].as_array().unwrap().iter().find(|c| c["expect"].get("error").is_some()).unwrap();
    assert_eq!(produce(&json!({"op": refusal["op"], "args": refusal["args"], "keys": doc["keys"]})), refusal["expect"]);
    assert_eq!(b64u(b""), "");
    assert_eq!(b64u(b"f"), "Zg");
    assert_eq!(b64u(b"fo"), "Zm8");
    assert_eq!(b64u(&[0xfb, 0xff, 0xbf]), "-_-_");
}

#[test]
fn pq_signing_is_deterministic_and_seeded_keys_refuse_bad_seeds() {
    let k = PqKeyPair::from_seed("ML-DSA-65", &[7u8; 32]).unwrap();
    assert_eq!(k.public, PqKeyPair::from_seed("ML-DSA-65", &[7u8; 32]).unwrap().public);
    assert_eq!(k.family(), "ML-DSA-65");
    let ed = KeyPair::from_seed(&[1u8; 32]);
    let s65 = Suite { alg: Some("ml-dsa-65"), pq: Some(&k) };
    assert_eq!(sign_with_suite(&s65, Some(&ed), b"m").unwrap(), sign_with_suite(&s65, Some(&ed), b"m").unwrap());
    let slh = PqKeyPair::from_seed("SLH-DSA-SHA2-128f", &[3u8; 48]).unwrap();
    let ss = Suite { alg: Some("slh-dsa-sha2-128f"), pq: Some(&slh) };
    assert_eq!(sign_with_suite(&ss, None, b"m").unwrap(), sign_with_suite(&ss, None, b"m").unwrap());
    assert_eq!(err(PqKeyPair::from_seed("ML-DSA-65", &[0u8; 31])), "a ML-DSA-65 seed is 32 bytes");
    assert_eq!(err(PqKeyPair::from_seed("SLH-DSA-SHA2-128f", &[0u8; 32])), "a SLH-DSA-SHA2-128f seed is 48 bytes");
    assert_eq!(err(PqKeyPair::from_seed("SLH-DSA-SHA2-256s", &[0u8; 48])), "a SLH-DSA-SHA2-256s seed is 96 bytes");
    assert_eq!(err(PqKeyPair::from_seed("LESS", &[0u8; 32])), "unsupported_suite: LESS");
    if cfg!(not(feature = "fndsa-sign")) {
        assert_eq!(err(PqKeyPair::from_seed("FN-DSA-512", &[0u8; 32])), "unsupported_suite: FN-DSA-512");
    }
}

// ---- the low-level agent: ttl, PQ sub-agents, mint_grant validators ----------------------------------------------------------

#[test]
fn act_uses_the_agent_ttl() {
    let (p, k) = (KeyPair::generate().unwrap(), KeyPair::from_seed(&[4u8; 32]));
    let grant = grant_for(&p, &k, None);
    let mut agent = Agent::new(k, grant, "rs", 0);
    agent.clock = || 1000;
    agent.ttl_ms = 5000;
    let a = agent.act("refund", "orders/1", None, Map::new(), &Suite::default()).unwrap();
    assert_eq!((a.pcactn["iat"].as_i64(), a.pcactn["exp"].as_i64()), (Some(1000), Some(6000)));
    agent.ttl_ms = 0;
    assert_eq!(err(agent.act("refund", "orders/1", None, Map::new(), &Suite::default()).map(|_| ())), "act: ttl_ms must be > 0");
}

#[test]
fn a_pq_sub_agent_signs_with_its_own_committed_key() {
    let (p, k) = (KeyPair::generate().unwrap(), KeyPair::from_seed(&[5u8; 32]));
    let (ppq, cpq) = (PqKeyPair::from_seed("ML-DSA-65", &[1u8; 32]).unwrap(), PqKeyPair::from_seed("ML-DSA-65", &[2u8; 32]).unwrap());
    let grant = grant_for(&p, &k, Some(&ppq.public));
    let parent = Agent::new(KeyPair::from_seed(&[5u8; 32]), grant.clone(), "rs-test", 0);
    let ps = Suite { alg: Some("hybrid-ed25519-ml-dsa-65"), pq: Some(&ppq) };
    let child = parent.delegate_pq(KeyPair::from_seed(&[6u8; 32]), &cpq, &json!([]), &ps).unwrap();
    let leaf = child.chain.last().unwrap();
    assert_ne!(leaf["holder_pq"], grant["holder_pq"]);
    let a = child.act("refund", "orders/1", None, Map::new(), &Suite { alg: Some("hybrid-ed25519-ml-dsa-65"), pq: Some(&cpq) }).unwrap();
    core_ok(&a.pcactn, &grant, "pq sub-agent");
    // the parent's PQ key is not the sub-agent's: refused before signing, and a leaf signed with it does not verify
    assert_eq!(err(parent.delegate_pq(KeyPair::generate().unwrap(), &ppq, &json!([]), &ps).map(|_| ())), "delegate_pq: the sub-agent needs its own post-quantum key pair, not this agent's");
    let wrong = child.act("refund", "orders/1", None, Map::new(), &ps).unwrap();
    let v = verify_pcactn_core_with(&wrong.pcactn, &grant, i(&wrong.pcactn["iat"]), "rs-test", &atlas_pca::VerifyOptions { insecure_skip_plan_root_check: true, ..atlas_pca::VerifyOptions::default() });
    assert!(!v.allow, "a sub-agent leaf signed with the parent's PQ key verified");
}

#[test]
fn mint_grant_runs_the_envelope_validators_in_reference_order() {
    let (p, h) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
    let d = Suite::default();
    let mg = |env: &Value| err(mint_grant(&p, &h.public, env, "g", None, None, &d).map(|_| ()));
    assert_eq!(mg(&env_with("units", Value::Null)), "mint_grant: units must be an object");
    assert_eq!(mg(&env_with("units", json!({"amount": {"kind": "money"}}))), "mint_grant: units key 'amount' must be an action.params.<name> path");
    assert_eq!(mg(&env_with("tighten", json!({}))), "mint_grant: tighten must be an array");
    assert_eq!(mg(&env_with("tighten", json!([5]))), "mint_grant: tighten[0] must be an object");
    assert_eq!(mg(&env_with("template_ref", json!(1))), "mint_grant: template_ref must be an object");
    assert_eq!(mg(&env_with("template_ref", json!({"x": 1}))), "mint_grant: template_ref has unknown member 'x'");
    assert!(mg(&env_with("actions", json!(1))).starts_with("mint_grant: "));
    assert!(mg(&env_with("provenance", Value::Null)).starts_with("mint_grant: "));
    // units are checked before model_polarity, as the reference does
    let mut both = env_with("units", json!(1));
    both["model_polarity"] = json!("strict");
    assert_eq!(mg(&both), "mint_grant: units must be an object");
    // a present null is kept (and signed) rather than dropped; agent_binding null reads as {}
    let g = mint_grant(&p, &h.public, &env_with("objective_risk", Value::Null), "g", None, None, &d).unwrap().grant;
    assert!(g["caveats"][0].as_object().unwrap().contains_key("objective_risk"));
    assert_eq!(mint_grant(&p, &h.public, &env_with("agent_binding", Value::Null), "g", None, None, &d).unwrap().grant["caveats"][0]["agent_binding"], json!({}));
    let ok = mint_grant(&p, &h.public, &env_with("units", json!({"action.params.amount": {"kind": "money", "currency": "USD", "exponent": 2}})), "g", None, None, &d).unwrap();
    assert_eq!(ok.grant["caveats"][0]["units"]["action.params.amount"]["exponent"], 2);
}

#[test]
fn principal_signers_refuse_malformed_bodies() {
    let k = KeyPair::from_seed(&[1u8; 32]);
    let body = json!({"principal": k.public});
    assert_eq!(err(sign_workflow(&k, &body)), "sign_workflow: malformed workflow");
    assert_eq!(err(sign_read_grant(&k, &body)), "sign_read_grant: malformed grant");
    assert_eq!(err(sign_aggregate_grant(&k, &body)), "sign_aggregate_grant: malformed grant");
}

// ---- the facade --------------------------------------------------------------------------------------------------------------

fn facade(principal: &KeyPair, holder: KeyPair) -> AgentHandle {
    let perms = json!({"stripe": ["refund"], "gmail": ["draft"]});
    let limits = json!({"refund": "$500/day"});
    let mut o = AgentOptions::new(principal, "refund order 1", &perms);
    o.limits = Some(&limits);
    o.holder = Some(holder);
    o.aud = Some("rs-test");
    o.now = Some(1_800_000_000_000);
    create_agent(o).unwrap()
}

#[test]
fn facade_act_verifies_and_counts() {
    let p = KeyPair::generate().unwrap();
    let a = facade(&p, KeyPair::from_seed(&[8u8; 32]));
    assert_eq!(a.policy.budget_model, "dollars");
    assert!(a.autonomy_bound > 0.0);
    assert_eq!(a.budget.b, 500.0);
    assert_eq!(a.grant["caveats"][0]["provenance"]["mediators"][0]["mediator"], "agent-harness");
    let now = Some(1_800_000_001_000);
    let params = json!({"amount": 125, "currency": "usd"});
    let r = a.act("stripe.refund", "charge:ch_1", Some(&params), &ActOptions { now, ..ActOptions::default() }).unwrap();
    assert_eq!(r.pcactn["plan"]["node_id"], "n0");
    assert_eq!(r.pcactn["action"]["reversibility_class"], "irreversible");
    assert_eq!(r.pcactn["risk_claim"]["r"], r.pcactn["risk_claim"]["inputs"]["blastRadius"]);
    assert!(r.pcactn["risk_claim"]["r"].is_number());
    assert!(r.pcactn.get("nonce").is_none());
    assert_eq!(r.pcactn["counter"], 1);
    assert_eq!(r.encoded, canonicalize(&r.pcactn));
    assert_eq!(r.headers.iter().map(|h| h.0.as_str()).collect::<Vec<_>>(), vec!["PCA-Action", "PCA-Provenance"]);
    assert_eq!(r.provenance["receipts"][0]["origin"], "action");
    assert!(r.dry_run.allowed && r.dry_run.reason.is_none(), "{:?}", r.dry_run);
    core_ok(&r.pcactn, &a.grant, "facade act with params");
    // explicit counters raise the auto counter; the next auto counter continues above it
    assert_eq!(a.act("gmail.draft", "t", None, &ActOptions { counter: Some(7), now, ..ActOptions::default() }).unwrap().pcactn["counter"], 7);
    assert_eq!(a.act("gmail.draft", "t", None, &ActOptions { now, ..ActOptions::default() }).unwrap().pcactn["counter"], 8);
    assert_eq!(a.act("gmail.draft", "t", None, &ActOptions { now, ttl_ms: Some(10), nonce: Some("n".into()), caution: Some(0.5), ..ActOptions::default() }).unwrap().pcactn["exp"], 1_800_000_001_010i64);
    assert_eq!(err(a.act("gmail.draft", "t", None, &ActOptions { aud: Some(String::new()), ..ActOptions::default() }).map(|_| ())), "act: aud (resource-server / instance id) is required (pass opts.aud or AgentOptions.aud)");
    // the sub-agent acts under one more hop
    let sub = a.sub_agent(SubAgentOptions { holder: None, added_caveats: Some(json!([{"type": "budget_alloc", "limit": 5}])) }).unwrap();
    assert_eq!(sub.chain.len(), 2);
    let r = sub.act("stripe.refund", "charge:ch_2", Some(&json!({"amount": 90})), &ActOptions { now, ..ActOptions::default() }).unwrap();
    core_ok(&r.pcactn, &a.grant, "facade sub-agent");
    assert_eq!(a.encode_grant(), a.grant.to_string());
}

#[test]
fn facade_dry_run_reasons() {
    let p = KeyPair::generate().unwrap();
    let a = facade(&p, KeyPair::generate().unwrap());
    let now = Some(1_800_000_000_500);
    let over = a.dry_run("stripe.refund", "c", Some(&json!({"amount": 900})), now);
    assert!(!over.allowed && over.reason.is_some() && over.t.is_none(), "{over:?}");
    let unknown = a.dry_run("gmail.send", "x", None, now);
    assert!(!unknown.allowed && unknown.reason.is_some(), "{unknown:?}");
    let late = a.dry_run("gmail.draft", "x", None, Some(1_900_000_000_000));
    assert!(!late.allowed && late.reason.as_deref().is_some_and(|r| r.starts_with("caveat(s) failed: ")), "{late:?}");
    let ok = a.dry_run("gmail.draft", "x", None, now);
    assert!(ok.allowed && ok.reason.is_none() && ok.t.is_some(), "{ok:?}");
}

#[test]
fn parse_limit_and_compile_policy_refusals() {
    assert_eq!(parse_limit("$500/day").unwrap(), ParsedLimit { amount: 500.0, unit: "usd", period_ms: Some(86_400_000) });
    assert_eq!(parse_limit(" 7 ").unwrap(), ParsedLimit { amount: 7.0, unit: "count", period_ms: None });
    assert_eq!(parse_limit("2/MO").unwrap().period_ms, Some(2_592_000_000));
    for (bad, e) in [("5.", "parseLimit: cannot parse limit '5.'"), ("$", "parseLimit: cannot parse limit '$'"), ("5/", "parseLimit: cannot parse limit '5/'"), ("5/d4", "parseLimit: cannot parse limit '5/d4'"), ("5 x", "parseLimit: cannot parse limit '5 x'"), ("", "parseLimit: empty limit")] {
        assert_eq!(err(parse_limit(bad)), e);
    }
    let co = |perms: Value, limits: Option<Value>| {
        let l = limits;
        compile_policy(&CompileOptions { permissions: &perms, limits: l.as_ref(), catalog: None, budget_model: None, risk_policy: None, now: 0 })
    };
    assert_eq!(err(co(json!([]), None).map(|_| ())), "compilePolicy: permissions must be an object");
    assert_eq!(err(co(json!({"stripe": "refund"}), None).map(|_| ())), "compilePolicy: permissions.stripe must be an array");
    assert_eq!(err(co(json!({"stripe": [1]}), None).map(|_| ())), "compilePolicy: permissions.stripe must be an array of action names");
    assert_eq!(err(co(json!({"stripe": ["refund"]}), Some(json!([]))).map(|_| ())), "compilePolicy: limits must be an object");
    assert_eq!(err(co(json!({"stripe": ["refund"]}), Some(json!({"refund": 5}))).map(|_| ())), "parseLimit: empty limit");
    // a null limit under the verb falls through to the action name
    let c = co(json!({"stripe": ["refund"]}), Some(json!({"stripe.refund": null, "refund": "$9"}))).unwrap();
    assert_eq!(c.limits[0].1.amount, 9.0);
    // an alias names the action; an unknown verb is the conservative fallback
    assert_eq!(spec_for(&builtin_catalog(), "stripe.reimburse").verb, "stripe.refund");
    let u = spec_for(&builtin_catalog(), "crm.export.all");
    assert_eq!((u.connector.as_str(), u.action.as_str(), u.reversibility.as_str(), u.blast_radius), ("crm", "export.all", "irreversible", 0.8));
    let ov = json!({"theta1": 0.1, "weights": {"alpha": 0.5}});
    let c = compile_policy(&CompileOptions { permissions: &json!({"github": ["read"]}), limits: None, catalog: None, budget_model: None, risk_policy: Some(&ov), now: 0 }).unwrap();
    assert_eq!((c.risk_policy["theta1"].as_f64(), c.risk_policy["weights"]["alpha"].as_f64(), c.risk_policy["weights"]["beta"].as_f64()), (Some(0.1), Some(0.5), Some(0.2)));
    let bad = json!({"kappa": 0});
    assert_eq!(err(compile_policy(&CompileOptions { permissions: &json!({"github": ["read"]}), limits: None, catalog: None, budget_model: None, risk_policy: Some(&bad), now: 0 }).map(|_| ())), "compilePolicy: derived risk policy invalid: risk_policy.kappa must be > 0");
}

// ---- the other signers: refusals and round trips -----------------------------------------------------------------------------

#[test]
fn other_signers_refuse_and_round_trip() {
    let k = KeyPair::from_seed(&[2u8; 32]);
    let d = Suite::default();
    // threshold shares
    let set = vec![json!({"publicKey": k.public, "role": "guardian"})];
    assert_eq!(err(sign_threshold_share("guardian", &k, b"m", &set, 4, &d)), "shareMessage: t must be 1, 2 or 3");
    assert_eq!(err(sign_threshold_share("guardian", &k, b"m", &[json!(1)], 1, &d)), "shareMessage: malformed signer set");
    assert_eq!(err(sign_prepared_share("root", &k, b"m", &d)), "signPreparedShare: unknown role 'root'");
    assert_eq!(err(sign_prepared_share("agent", &k, b"m", &Suite { alg: Some("rot13"), pq: None })), "signPreparedShare: unknown signature alg 'rot13'");
    let share = sign_threshold_share("guardian", &k, b"m", &set, 2, &d).unwrap();
    assert!(verify_threshold_share(&json!({"role": "guardian", "t": 2, "signer_set": set, "threshold_message": base64_url(b"m"), "share": share})));
    let pq = PqKeyPair::from_seed("ML-DSA-65", &[9u8; 32]).unwrap();
    let pset = vec![json!({"publicKey": k.public, "role": "guardian", "pq_pk": pq.public})];
    let ps = Suite { alg: Some("hybrid-ed25519-ml-dsa-65"), pq: Some(&pq) };
    let pshare = sign_threshold_share("guardian", &k, b"m", &pset, 2, &ps).unwrap();
    assert_eq!(pshare["alg"], "hybrid-ed25519-ml-dsa-65");
    assert!(verify_threshold_share(&json!({"role": "guardian", "t": 2, "signer_set": pset, "threshold_message": base64_url(b"m"), "share": pshare})));
    // caution
    let body = |c: Value, r: Option<&str>| {
        let mut b = json!({"action_digest": "x", "caution": c, "holder": k.public, "extra": 1});
        if let Some(r) = r {
            b["reason"] = json!(r);
        }
        b
    };
    let c = sign_caution(&k, &body(json!(0.5), None)).unwrap();
    assert!(c.get("extra").is_none() && c["sig"].is_string());
    assert_eq!(err(sign_caution(&k, &json!([]))), "signCaution: not an object");
    assert_eq!(err(sign_caution(&k, &json!({"holder": "h", "caution": 0}))), "signCaution: action_digest required");
    assert_eq!(err(sign_caution(&k, &json!({"action_digest": "a", "caution": 0}))), "signCaution: holder required");
    assert_eq!(err(sign_caution(&k, &body(json!("0.5"), None))), "signCaution: caution must be a finite number in [0,1]");
    assert_eq!(err(sign_caution(&k, &body(json!(-0.1), None))), "signCaution: caution must be a finite number in [0,1]");
    assert_eq!(err(sign_caution(&k, &body(json!(0), Some("has space")))), "signCaution: invalid reason");
    assert_eq!(err(sign_caution(&k, &body(json!(0), Some("a".repeat(65).as_str())))), "signCaution: invalid reason");
    assert_eq!(err(sign_caution(&k, &body(json!(0), Some("")))), "signCaution: invalid reason");
    assert_eq!(sign_caution(&k, &body(json!(1), Some("a".repeat(64).as_str()))).unwrap()["reason"].as_str().map(str::len), Some(64));
    assert_eq!(err(sign_heartbeat(&k, &json!({"cap_id": "c"}))), "signHeartbeat: seq required");
    // revocation epoch
    let ep = json!({"instance_id": "i", "grant_ref": "g", "epoch": 1, "set_size": 0, "root": "r", "issued_at": 10, "not_after": 20});
    let mut missing = ep.clone();
    missing.as_object_mut().unwrap().remove("root");
    assert_eq!(err(sign_revocation_epoch(&k, &missing, &d)), "signRevocationEpoch: root required");
    let mut neg = ep.clone();
    neg["epoch"] = json!(-1);
    assert_eq!(err(sign_revocation_epoch(&k, &neg, &d)), "signRevocationEpoch: epoch must be a non-negative safe integer");
    let signed = sign_revocation_epoch(&k, &ep, &d).unwrap();
    assert_eq!(signed["guardian"], json!(k.public));
    assert_eq!(atlas_pca::k05b_g8_seam::check_revocation_epoch(signed.as_object().unwrap(), &k.public, 15.0, "g"), Ok(()));
    // pq binding, safety evidence, session grant
    assert_eq!(sign_pq_binding(&k, "PQ", 9_007_199_254_740_991, "a").unwrap()["epoch"], 9_007_199_254_740_991i64);
    assert_eq!(err(sign_safety_evidence(&k, &json!({"v": 2}))), "signSafetyEvidence: unsupported evidence");
    assert_eq!(err(sign_safety_evidence(&k, &json!({"v": 1, "constitution": "<unhashable>", "action_digest": "a", "state_digest": "s"}))), "signSafetyEvidence: unbound evidence");
    let sg = |seq: i64, prev: Option<&str>, map: &str| {
        mint_session_grant(&SessionGrantInput {
            principal: &k, holder: &k.public, holder_pq: None, session: &base64_url(&[1u8; 32]), seq, prev, root: &base64_url(&[2u8; 32]), map_digest: map, map_form: None,
            predicates: &json!([]), caveats: None, agent_binding: None, risk_policy: None, salt: Some("c2FsdA"), suite: Suite::default(),
        })
    };
    assert_eq!(err(sg(0, None, "short")), "mintSessionGrant: mapDigest must be canonical base64url (32 bytes)");
    assert!(err(sg(1, None, &base64_url(&[3u8; 32]))).starts_with("mintSessionGrant: "));
    let (g, salt) = sg(0, None, &base64_url(&[3u8; 32])).unwrap();
    assert_eq!((salt.as_str(), g["caveats"][1]["type"].as_str()), ("c2FsdA", Some("intent_session")));
    // template / tighten / constitution / action schema / labels / facts: refusals carry the verifier's own text
    assert!(err(sign_template(&json!({}), &k)).starts_with("signTemplate: "));
    assert!(err(sign_tighten(&json!({}), &k)).starts_with("signTighten: "));
    assert!(err(sign_constitution(&k, &json!({}))).starts_with("signConstitution: "));
    assert!(err(sign_action_schema(&json!({}), "k1", &k, &d)).starts_with("signActionSchema: "));
    assert_eq!(err(sign_labels(&json!({}), &k, &d)), "signLabels: malformed pca-labels (the verifier would refuse it)");
    assert_eq!(err(sign_fact(&json!({"name": "Bad"}), &k, &d)), "signFact: malformed pca-fact (the verifier would refuse it)");
    assert_eq!(err(sign_fact(&json!(1), &k, &d)), "signFact: not an object");
    // offer sets: exact vector outputs, the canonical-profile refusals, a non-object body
    let doc = load("producer-vectors.json");
    let site = KeyPair::from_seed_b64u(s(&doc["keys"]["site"]["seed"])).unwrap();
    let case = |n: &str| doc["cases"].as_array().unwrap().iter().find(|c| c["name"] == n).unwrap().clone();
    for n in ["offer-set-complete", "offer-set-partial-page"] {
        let c = case(n);
        assert_eq!(sign_offer_set(&c["args"]["body"], &site, &d).unwrap(), c["expect"], "{n}");
    }
    for n in ["offer-set-refuses-unsafe-price", "offer-set-refuses-unsafe-issued-at"] {
        let c = case(n);
        assert_eq!(err(sign_offer_set(&c["args"]["body"], &site, &d)), "canonicalize: integer outside the safe range (|n| > 2^53-1)", "{n}");
        assert_eq!(c["expect"]["error"], "canonicalize: integer outside the safe range (|n| > 2^53-1)");
    }
    assert_eq!(err(sign_offer_set(&json!([1]), &site, &d)), "expected a JSON object");
    let signed = sign_offer_set(&case("offer-set-complete")["args"]["body"], &site, &d).unwrap();
    let other = sign_offer_set(&case("offer-set-complete")["args"]["body"], &k, &d).unwrap();
    assert_ne!(signed["sig"], other["sig"], "the signature is the signer's");
    assert_eq!(err(sign_session_root(&k, &json!({"x": 1}), &d)), "signSessionRoot: session root: unknown member 'x'");
    assert_eq!(err(sign_session_root(&k, &json!({"principals": []}), &d)), "signSessionRoot: the signer is not one of the session principals");
    assert_eq!(err(sign_mesh_action(&[], &json!({}), &k)), "signMeshAction: empty chain");
}

// ---- natives -> reference: the artifacts this SDK signs, written for the reference to verify (PCA_PRODUCER_OUT) -------------

const SUITES: [(&str, &str); 10] = [
    ("ed25519", ""),
    ("ml-dsa-65", "ML-DSA-65"),
    ("hybrid-ed25519-ml-dsa-65", "ML-DSA-65"),
    ("hybrid-nested-ed25519-ml-dsa-65", "ML-DSA-65"),
    ("ml-dsa-87", "ML-DSA-87"),
    ("hybrid-ed25519-ml-dsa-87", "ML-DSA-87"),
    ("slh-dsa-sha2-128f", "SLH-DSA-SHA2-128f"),
    ("hybrid-ed25519-slh-dsa-sha2-128f", "SLH-DSA-SHA2-128f"),
    ("slh-dsa-sha2-256s", "SLH-DSA-SHA2-256s"),
    ("hybrid-ed25519-slh-dsa-sha2-256s", "SLH-DSA-SHA2-256s"),
];
const V3_AUD: &str = "ins_producer_test";
const V3_NOW: i64 = 1_800_000_000_000;

fn pq_seed(family: &str, n: u8) -> Vec<u8> {
    vec![n; if family.starts_with("SLH-DSA-SHA2-128f") { 48 } else if family.starts_with("SLH-DSA-SHA2-256s") { 96 } else { 32 }]
}

#[test]
fn native_artifacts_verify_and_are_written_for_the_reference() {
    let principal = KeyPair::from_seed(&[11u8; 32]);
    let mut cases = vec![];
    let mut families: Vec<(&str, &str)> = SUITES.to_vec();
    if cfg!(feature = "fndsa-sign") {
        families.extend([("fn-dsa-512", "FN-DSA-512"), ("fn-dsa-1024", "FN-DSA-1024")]);
    }
    for (n, &(alg, fam)) in families.iter().enumerate() {
        let agent = KeyPair::from_seed(&[20 + n as u8; 32]);
        let pq = (!fam.is_empty()).then(|| PqKeyPair::from_seed(fam, &pq_seed(fam, 40 + n as u8)).unwrap());
        let grant = grant_for(&principal, &agent, pq.as_ref().map(|p| p.public.as_str()));
        let mut a = Agent::new(KeyPair::from_seed(&[20 + n as u8; 32]), grant.clone(), V3_AUD, 0);
        a.clock = || V3_NOW;
        let suite = Suite { alg: Some(alg), pq: pq.as_ref() };
        let p = a.act("refund", "orders/1", Some(&json!({"amount_cents": 500})), Map::new(), &suite).unwrap().pcactn;
        core_ok_aud(&p, &grant, alg, V3_AUD);
        cases.push(json!({"kind": "pcactn", "alg": alg, "grant": grant, "pcactn": p}));
        if alg == "hybrid-ed25519-ml-dsa-65" {
            // a delegated PQ sub-agent: its own key, committed on the hop
            let cpq = PqKeyPair::from_seed(fam, &[77u8; 32]).unwrap();
            let child = a.delegate_pq(KeyPair::from_seed(&[78u8; 32]), &cpq, &json!([]), &suite).unwrap();
            let sp = child.act("refund", "orders/2", None, Map::new(), &Suite { alg: Some(alg), pq: Some(&cpq) }).unwrap().pcactn;
            core_ok_aud(&sp, &grant, "pq sub-agent", V3_AUD);
            cases.push(json!({"kind": "pcactn", "alg": alg, "grant": grant, "pcactn": sp}));
            // the escalation answer, revocation epoch and session root under the same suite
            let ppq = PqKeyPair::from_seed(fam, &[79u8; 32]).unwrap();
            let s2 = Suite { alg: Some(alg), pq: Some(&ppq) };
            let req = json!({"policy_digest": base64_url(&[1u8; 32]), "action_digest": base64_url(&[2u8; 32]), "history_head": base64_url(&[3u8; 32])});
            let ans = sign_escalation_answer(&principal, &req, "allow", V3_NOW, V3_NOW + 60_000, None, &s2).unwrap();
            cases.push(json!({"kind": "escalation_answer", "alg": alg, "artifact": ans, "pins": {"pk": principal.public, "pq_pk": ppq.public}}));
            let ep = sign_revocation_epoch(&principal, &json!({"instance_id": V3_AUD, "grant_ref": grant["id"], "epoch": 1, "set_size": 0, "root": base64_url(&[4u8; 32]), "issued_at": V3_NOW, "not_after": V3_NOW + 3_600_000}), &s2).unwrap();
            cases.push(json!({"kind": "revocation_epoch", "alg": alg, "artifact": ep, "pins": {"pk": principal.public, "pq_pk": ppq.public}}));
        }
    }
    // a facade act with params
    let f = facade(&principal, KeyPair::from_seed(&[60u8; 32]));
    let fr = f.act("stripe.refund", "charge:ch_1", Some(&json!({"amount": 125})), &ActOptions { aud: Some(V3_AUD.into()), now: Some(V3_NOW), ..ActOptions::default() }).unwrap();
    cases.push(json!({"kind": "pcactn", "alg": "ed25519", "grant": f.grant, "pcactn": fr.pcactn}));
    // one of each artifact kind (ed25519): the session root, action schema, labels and fact over the producer vectors' bodies
    let pv = load("producer-vectors.json");
    let mut keys = HashMap::new();
    let mut seeds = HashMap::new();
    for (n, k) in pv["keys"].as_object().unwrap() {
        keys.insert(n.clone(), KeyPair::from_seed_b64u(s(&k["seed"])).unwrap());
        seeds.insert(n.clone(), s(&k["seed"]).to_string());
    }
    for (op, kind) in [("sign_session_root", "session_root"), ("sign_action_schema", "action_schema"), ("sign_intent_required", "intent_required"), ("sign_labels", "labels"), ("sign_fact", "fact")] {
        let c = pv["cases"].as_array().unwrap().iter().find(|c| c["op"] == op && c["expect"].get("error").is_none()).unwrap();
        let art = run(op, &c["args"], &keys, &seeds, &HashMap::new());
        assert!(art.get("error").is_none(), "{op}: {art}");
        let mut pins = json!({"pk": keys[s(&c["args"]["signer"])].public});
        if let Some(kid) = c["args"]["kid"].as_str().or(art["kid"].as_str()) {
            pins["kid"] = json!(kid);
        }
        if let Some(site) = art["site"].as_str() {
            pins["site"] = json!(site);
        }
        cases.push(json!({"kind": kind, "alg": "ed25519", "artifact": art, "pins": pins}));
    }
    let site = KeyPair::from_seed(&[61u8; 32]);
    let caution = sign_caution(&site, &json!({"action_digest": base64_url(&[5u8; 32]), "caution": 0.5, "holder": site.public})).unwrap();
    cases.push(json!({"kind": "caution", "alg": "ed25519", "artifact": caution, "pins": {"pk": site.public}}));
    let binding = sign_pq_binding(&site, &PqKeyPair::from_seed("ML-DSA-65", &[62u8; 32]).unwrap().public, 1, V3_AUD).unwrap();
    cases.push(json!({"kind": "pq_binding", "alg": "ed25519", "artifact": binding, "pins": {"pk": site.public}}));
    let doc = json!({"lang": "rust", "aud": V3_AUD, "now": V3_NOW, "cases": cases});
    if let Ok(path) = std::env::var("PCA_PRODUCER_OUT") {
        std::fs::write(&path, atlas_pca::serde_json::to_string_pretty(&doc).unwrap()).expect("write PCA_PRODUCER_OUT");
    }
}

#[test]
fn intent_required_refusals_match_the_reference() {
    let pv = load("producer-vectors.json");
    let c = pv["cases"].as_array().unwrap().iter().find(|c| c["op"] == "sign_intent_required").unwrap();
    let site = KeyPair::from_seed_b64u(s(&pv["keys"][s(&c["args"]["signer"])]["seed"])).unwrap();
    let d = Suite::default();
    let base = c["args"]["body"].clone();
    assert_eq!(sign_intent_required(&base, "site-k1", &site, &d).unwrap(), c["expect"]);
    let with = |k: &str, v: Value| {
        let mut b = base.clone();
        b[k] = v;
        err(sign_intent_required(&b, "site-k1", &site, &d))
    };
    let p = |e: &str| format!("signIntentRequired: {e}");
    assert_eq!(err(sign_intent_required(&json!([]), "k", &site, &d)), p("not an object"));
    assert_eq!(with("extra", json!(1)), p("unknown member 'extra'"));
    assert_eq!(with("v", json!(2)), p("not a pca-intent-required v1"));
    assert_eq!(with("kind", json!("pca-labels")), p("not a pca-intent-required v1"));
    assert_eq!(with("schema", json!("short")), p("schema must be canonical base64url (32 bytes)"));
    assert_eq!(with("cell", json!({"verb": "", "coords": {"a": ["x"]}})), p("cell must be {verb, coords}"));
    assert_eq!(with("cell", json!({"verb": "v", "coords": {"a": ["x"]}, "x": 1})), p("cell must be {verb, coords}"));
    assert_eq!(with("cell", json!({"verb": "v", "coords": {}})), p("coords must be an object of 1..64 dimensions"));
    assert_eq!(with("cell", json!({"verb": "v", "coords": {"": ["x"]}})), p("a coordinate path must be 1..256 characters"));
    assert_eq!(with("cell", json!({"verb": "v", "coords": {"a": [3, 2]}})), p("coords 'a': need 0 <= lo <= hi"));
    assert_eq!(with("cell", json!({"verb": "v", "coords": {"a": [-1, 2]}})), p("coords 'a': need 0 <= lo <= hi"));
    assert_eq!(with("cell", json!({"verb": "v", "coords": {"a": ["x", "x"]}})), p("coords 'a': values must be distinct"));
    assert_eq!(with("cell", json!({"verb": "v", "coords": {"a": [1.5, 2]}})), p("coords 'a': an index range [lo, hi] or a value set"));
    assert_eq!(with("cell", json!({"verb": "v", "coords": {"a": []}})), p("coords 'a': an index range [lo, hi] or a value set"));
    assert_eq!(with("reason", json!("sure")), p("reason must be 'uncertain'"));
    assert_eq!(with("question_id", json!("q 1")), p("question_id must match [A-Za-z0-9_-]{1,64}"));
    assert_eq!(with("question_id", json!("q".repeat(65))), p("question_id must match [A-Za-z0-9_-]{1,64}"));
    assert_eq!(with("friction", json!("shout")), p("unknown friction tier"));
    assert_eq!(with("delivered_to", json!("email")), p("delivered_to must be 'wallet' or 'agent'"));
    assert_eq!(with("expires_at", json!(-1)), p("expires_at must be a non-negative safe integer"));
    assert_eq!(with("expires_at", json!(1.5)), p("expires_at must be a non-negative safe integer"));
    assert_eq!(with("sig", json!({})), p("an unsigned body must not carry sig"));
    // boundaries that are accepted
    assert!(sign_intent_required(&{ let mut b = base.clone(); b["question_id"] = json!("q".repeat(64)); b["expires_at"] = json!(0); b }, "k", &site, &d).is_ok());
    assert!(sign_intent_required(&{ let mut b = base.clone(); b["cell"] = json!({"verb": "v", "coords": {"a": [0, 0]}}); b }, "k", &site, &d).is_ok());
}

#[test]
fn progress_step_binds_the_holder_and_step() {
    let k = KeyPair::from_seed(&[3u8; 32]);
    let step = json!({"goal_commitment": "g", "action_digest": "a", "before_digest": "b", "after_digest": "c", "seq": 0, "prev": "genesis", "digest": "d"});
    let a = sign_progress_step(&step, &k).unwrap();
    assert_eq!((a["step"].clone(), a["holder"].as_str()), (step.clone(), Some(k.public.as_str())));
    let mut moved = step.clone();
    moved["seq"] = json!(1);
    assert_ne!(sign_progress_step(&moved, &k).unwrap()["sig"], a["sig"]);
    assert_ne!(sign_progress_step(&step, &KeyPair::from_seed(&[4u8; 32])).unwrap()["sig"], a["sig"]);
}
