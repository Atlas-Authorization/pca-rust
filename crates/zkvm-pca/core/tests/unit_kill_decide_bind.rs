//! Mutation-kill tests for the decision glue: `bind_pcactn` (every binding rule on its own), `PcactnFacts`, `check_context`
//! (one mismatch variant per journal field, boundaries of the clock tolerance), `verify_hops` shape checks, the fixed-point
//! risk wiring of `decide` (independently recomputed) and the reversibility-class derivation.
//!
//! None of these depend on the committed receipts or journal fixtures (they are in flux while the guest is rebuilt).
use pca_zkvm_core::chain::verify_hops;
use pca_zkvm_core::commit::{conditions_digest, empty_params_digest, plan_commitment};
use pca_zkvm_core::context::{check_context, ContextMismatch as M, ExpectedContext, PcactnFacts, PCACTN_MAX_LIFETIME_MS, PCACTN_MAX_SKEW_MS};
use pca_zkvm_core::risk::S;
use pca_zkvm_core::{bind_pcactn, decide, decide_from_str, DecideInput, Decision};
use serde_json::{json, Value};

#[path = "support/chain_mint.rs"]
mod mint;

fn base() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/decide_input.sample.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn di(v: &Value) -> DecideInput {
    serde_json::from_value(v.clone()).unwrap()
}

fn bound(v: &Value) -> bool {
    bind_pcactn(&di(v)).is_some()
}

/// Edit both the evaluated action and the signed copy identically, so only the plan-leaf comparison can object.
fn edit_action(f: impl Fn(&mut Value)) -> Value {
    let mut v = base();
    f(&mut v["action"]);
    f(&mut v["pcactn"]["action"]);
    v
}

// --------------------------------------------------------------------------------------------- bind_pcactn

#[test]
fn bind_base_and_outputs() {
    let b = bind_pcactn(&di(&base())).expect("the sample binds");
    assert_eq!(b.node_id, "n1");
    assert_eq!(b.grant_ref, base()["pcactn"]["grant_ref"].as_str().unwrap());
}

#[test]
fn bind_grant_ref_and_chain() {
    let mut v = base();
    v["pcactn"]["grant_ref"] = json!("");
    v["chain"][0]["id"] = json!("");
    assert!(!bound(&v), "an empty grant_ref never binds, even if it equals the root id");
    let mut v = base();
    v["pcactn"]["grant_ref"] = json!("other");
    assert!(!bound(&v));
    let mut v = base();
    v["pcactn"].as_object_mut().unwrap().remove("grant_ref");
    assert!(!bound(&v));
    let mut v = base();
    v["pcactn"]["grant_ref"] = json!(5);
    assert!(!bound(&v));
    let mut v = base();
    v["pcactn"]["cap_chain"] = json!([]);
    assert!(!bound(&v));
    let mut v = base();
    v["pcactn"].as_object_mut().unwrap().remove("cap_chain");
    assert!(!bound(&v));
    let mut v = base();
    v["pcactn"].as_object_mut().unwrap().remove("action");
    assert!(!bound(&v));
    let mut v = base();
    v.as_object_mut().unwrap().remove("pcactn");
    assert!(!bound(&v));
    let mut v = base();
    v["chain"] = json!([]);
    assert!(!bound(&v));
}

#[test]
fn bind_action_equality() {
    let mut v = base();
    v["pcactn"]["action"]["params"]["limit"] = json!(51);
    assert!(!bound(&v), "signed action differs from the evaluated action");
    let mut v = base();
    v["action"]["params"]["limit"] = json!(51);
    assert!(!bound(&v));
}

#[test]
fn bind_plan_root_and_node() {
    let mut v = base();
    v["pcactn"]["plan"]["root"] = json!("AAAA");
    assert!(!bound(&v));
    let mut v = base();
    v["pcactn"]["plan"].as_object_mut().unwrap().remove("root");
    assert!(!bound(&v));
    // the plan is edited but the signed root is not
    let mut v = base();
    v["plan"][0]["verb"] = json!("zzz");
    assert!(!bound(&v));
    let mut v = base();
    v["plan"] = json!([]);
    assert!(!bound(&v));
    // node id: absent / unknown / disagreeing prover node id
    let mut v = base();
    v["pcactn"]["plan"].as_object_mut().unwrap().remove("node_id");
    assert!(!bound(&v));
    let mut v = base();
    v["pcactn"]["plan"]["node_id"] = json!("n9");
    assert!(!bound(&v));
    let mut v = base();
    v["node_id"] = json!("n0");
    assert!(!bound(&v), "a prover node_id that disagrees with the signed one");
    let mut v = base();
    v["node_id"] = json!("n1");
    assert!(bound(&v), "a prover node_id that agrees is fine");
    let mut v = base();
    v.as_object_mut().unwrap().remove("node_id");
    assert!(bound(&v), "node_id is optional");
}

#[test]
fn bind_leaf_fields_each_alone() {
    // the plan node n1 is read /acct/123/items reversible
    assert!(!bound(&edit_action(|a| a["verb"] = json!("write"))), "verb alone");
    assert!(!bound(&edit_action(|a| a["resource"] = json!("/acct/123/other"))), "resource alone");
    assert!(!bound(&edit_action(|a| {
        a["verb"] = json!("write");
        a["resource"] = json!("/x");
    })));
    // reversibility class: present and different -> refused; equal -> fine; absent -> not compared
    assert!(!bound(&edit_action(|a| a["reversibility_class"] = json!("irreversible"))));
    assert!(!bound(&edit_action(|a| a["reversibility_class"] = json!("rate_limited"))));
    assert!(bound(&edit_action(|a| a["reversibility_class"] = json!("reversible"))));
    assert!(bound(&edit_action(|a| {
        a.as_object_mut().unwrap().remove("reversibility_class");
    })));
    // params digest: present and different -> refused; equal to the leaf's (the empty-params digest) -> fine
    assert!(!bound(&edit_action(|a| a["params_digest"] = json!("not-the-digest"))));
    assert!(bound(&edit_action(|a| a["params_digest"] = json!(empty_params_digest()))));
}

#[test]
fn bind_conditions_digest() {
    let mut v = base();
    v["pcactn"]["plan"]["conditions_digest"] = json!("wrong");
    assert!(!bound(&v));
    let mut v = base();
    v["pcactn"]["plan"]["conditions_digest"] = json!(5);
    assert!(!bound(&v));
    // absent == the digest of "no pre / no post conditions", which is what node n1 carries
    let mut v = base();
    v["pcactn"]["plan"].as_object_mut().unwrap().remove("conditions_digest");
    assert!(bound(&v));
    assert_eq!(v["pcactn"]["plan"].get("conditions_digest"), None);
    assert_eq!(base()["pcactn"]["plan"]["conditions_digest"].as_str().unwrap(), conditions_digest(&json!({})));
    // a node WITH conditions needs its own digest
    let mut v = base();
    v["plan"][1]["pre"] = json!({"x": 1});
    let root = plan_commitment(v["plan"].as_array().unwrap()).unwrap();
    v["pcactn"]["plan"]["root"] = json!(root);
    assert!(!bound(&v), "the signed digest is the empty-conditions one");
    v["pcactn"]["plan"]["conditions_digest"] = json!(conditions_digest(&v["plan"][1]));
    assert!(bound(&v));
}

#[test]
fn bind_tool_binding() {
    let tb = base()["tool_binding"].as_str().unwrap().to_string();
    let mut v = base();
    v.as_object_mut().unwrap().remove("tool_binding");
    assert!(!bound(&v), "signed binding present, none supplied");
    let mut v = base();
    v["tool_binding"] = json!(format!("{tb}x"));
    assert!(!bound(&v));
    let mut v = base();
    v["pcactn"].as_object_mut().unwrap().remove("tool_binding");
    assert!(!bound(&v), "supplied binding that was never signed");
    v.as_object_mut().unwrap().remove("tool_binding");
    assert!(bound(&v), "neither signed nor supplied");
    let mut v = base();
    v["pcactn"]["tool_binding"] = json!(5);
    assert!(!bound(&v));
}

#[test]
fn bind_freshness_window_is_enforced_at_now() {
    let b = base();
    let iat = b["pcactn"]["iat"].as_i64().unwrap();
    let exp = b["pcactn"]["exp"].as_i64().unwrap();
    for (now, want) in [(iat, true), (exp, true), (exp + 1, false), (iat - PCACTN_MAX_SKEW_MS, true), (iat - PCACTN_MAX_SKEW_MS - 1, false)] {
        let mut v = base();
        v["now"] = json!(now);
        assert_eq!(bound(&v), want, "now = {now}");
    }
}

// ----------------------------------------------------------------------------------------------- PcactnFacts

fn facts(f: impl Fn(&mut Value)) -> Option<PcactnFacts> {
    let mut p = json!({ "ver": 2, "iat": 10, "exp": 20, "aud": "a", "counter": 0 });
    f(&mut p);
    PcactnFacts::from_pcactn(&p)
}

#[test]
fn pcactn_facts_strictness() {
    let ok = facts(|_| {}).unwrap();
    assert_eq!((ok.ver, ok.iat, ok.exp, ok.aud.as_str(), ok.counter), (2, 10, 20, "a", 0));
    assert!(facts(|p| p["ver"] = json!(0)).is_some(), "ver 0 is extractable (check_freshness refuses it later)");
    assert!(facts(|p| p["ver"] = json!(-1)).is_none());
    assert!(facts(|p| p["counter"] = json!(-1)).is_none());
    assert!(facts(|p| p["counter"] = json!(7)).map(|f| f.counter) == Some(7));
    assert!(facts(|p| p["aud"] = json!("")).is_none());
    assert!(facts(|p| p["aud"] = json!("a".repeat(256))).is_some());
    assert!(facts(|p| p["aud"] = json!("a".repeat(257))).is_none());
    assert!(facts(|p| p["aud"] = json!("é".repeat(128))).is_some(), "256 bytes");
    assert!(facts(|p| p["aud"] = json!("é".repeat(129))).is_none(), "258 bytes");
    assert!(facts(|p| p["aud"] = json!(5)).is_none());
    for k in ["ver", "iat", "exp", "counter", "aud"] {
        assert!(facts(|p| {
            p.as_object_mut().unwrap().remove(k);
        })
        .is_none(), "missing {k}");
    }
    assert!(facts(|p| p["iat"] = json!(1.5)).is_none());
    assert!(facts(|p| p["iat"] = json!("10")).is_none());
    assert!(facts(|p| p["iat"] = json!(9_007_199_254_740_991i64)).is_some());
    assert!(facts(|p| p["iat"] = json!(9_007_199_254_740_992i64)).is_none());
    assert!(facts(|p| p["iat"] = json!(-9_007_199_254_740_991i64)).is_some());
    assert!(facts(|p| p["iat"] = json!(-9_007_199_254_740_992i64)).is_none());
}

// ----------------------------------------------------------------------------------------------- check_context

fn journal_and_expected() -> (Decision, ExpectedContext) {
    let s = base().to_string();
    let d = decide_from_str(&s);
    assert_eq!((d.allow, d.chain_verified), (1, 1), "the sample is allowed");
    (d, ExpectedContext::from_input_json(&s, 0.0).unwrap())
}

#[test]
fn check_context_accepts_the_truth_and_names_every_field() {
    let (d, e) = journal_and_expected();
    assert_eq!(check_context(&d, &e), Ok(()));
    let mutate_j = |f: &dyn Fn(&mut Decision)| {
        let mut x = d.clone();
        f(&mut x);
        check_context(&x, &e)
    };
    assert_eq!(mutate_j(&|x| x.allow = 0), Err(M::NotAllowed));
    assert_eq!(mutate_j(&|x| x.chain_verified = 0), Err(M::ChainNotVerified));
    assert_eq!(mutate_j(&|x| x.context.subject_digest = "x".into()), Err(M::Subject));
    assert_eq!(mutate_j(&|x| x.context.env_digest = "x".into()), Err(M::Env));
    assert_eq!(mutate_j(&|x| x.context.rate_history_digest = "x".into()), Err(M::RateHistory));
    assert_eq!(mutate_j(&|x| x.context.delegation_depth += 1), Err(M::DelegationDepth));
    assert_eq!(mutate_j(&|x| x.context.grant_ref = "x".into()), Err(M::GrantRef));
    assert_eq!(mutate_j(&|x| x.context.node_id = "x".into()), Err(M::NodeId));
    assert_eq!(mutate_j(&|x| x.context.tool_binding = None), Err(M::ToolBinding));
    assert_eq!(mutate_j(&|x| x.context.risk_inputs_scaled[0] += 1), Err(M::RiskInputs));
    assert_eq!(mutate_j(&|x| x.context.budget_scaled += 1), Err(M::Budget));
    assert_eq!(mutate_j(&|x| x.context.r_floor_scaled += 1), Err(M::RiskFloor));
    assert_eq!(mutate_j(&|x| x.context.root_principal = None), Err(M::RootPrincipal));
    assert_eq!(mutate_j(&|x| x.context.pcactn_digest = "x".into()), Err(M::PcactnDigest));
    assert_eq!(mutate_j(&|x| x.context.pcactn_ver = 3), Err(M::PcactnVersion));
    assert_eq!(mutate_j(&|x| x.context.pcactn_aud = "other".into()), Err(M::PcactnAud));
    assert_eq!(mutate_j(&|x| x.context.pcactn_iat += 1), Err(M::PcactnIat));
    assert_eq!(mutate_j(&|x| x.context.pcactn_exp += 1), Err(M::PcactnExp));
    assert_eq!(mutate_j(&|x| x.context.pcactn_counter += 1), Err(M::PcactnCounter));
    assert_eq!(mutate_j(&|x| x.action_commit = "x".into()), Err(M::ActionCommit));
    assert_eq!(mutate_j(&|x| x.policy_commit = "x".into()), Err(M::PolicyCommit));
    assert_eq!(mutate_j(&|x| x.plan_commit = "x".into()), Err(M::PlanCommit));
    // the verifier side: every expectation is also compared
    let mutate_e = |f: &dyn Fn(&mut ExpectedContext)| {
        let mut x = e.clone();
        f(&mut x);
        check_context(&d, &x)
    };
    assert_eq!(mutate_e(&|x| x.subject = Some(json!({"other": 1}))), Err(M::Subject));
    assert_eq!(mutate_e(&|x| x.env = None), Err(M::Env));
    assert_eq!(mutate_e(&|x| x.recent_action_times = None), Err(M::RateHistory));
    assert_eq!(mutate_e(&|x| x.delegation_depth += 1), Err(M::DelegationDepth));
    assert_eq!(mutate_e(&|x| x.pcactn_aud.clear()), Err(M::PcactnAud));
    assert_eq!(mutate_e(&|x| x.pcactn_ver = 3), Err(M::PcactnVersion));
}

#[test]
fn check_context_clock_tolerance_boundaries() {
    let (d, e) = journal_and_expected();
    let now = e.now;
    let with = |expected_now: f64, tol: f64| {
        let mut x = e.clone();
        x.now = expected_now;
        x.now_tolerance_ms = tol;
        check_context(&d, &x).err()
    };
    let is_now = |r: Option<M>| matches!(r, Some(M::Now { .. }));
    assert_eq!(with(now, 0.0), None);
    assert!(is_now(with(now + 1.0, 0.0)));
    assert!(is_now(with(now - 1.0, 0.0)));
    assert_eq!(with(now + 5.0, 5.0), None, "difference == tolerance is accepted");
    assert_eq!(with(now - 5.0, 5.0), None);
    assert!(is_now(with(now + 6.0, 5.0)));
    assert!(is_now(with(now - 6.0, 5.0)));
    assert!(is_now(with(now, -1.0)), "a negative tolerance is refused");
    assert!(is_now(with(f64::NAN, 5.0)) && is_now(with(f64::INFINITY, 5.0)) && is_now(with(now, f64::NAN)));
    // a non-finite proven clock
    let mut dd = d.clone();
    dd.context.now_bits = f64::NAN.to_bits();
    assert!(matches!(check_context(&dd, &e), Err(M::Now { .. })));
    dd.context.now_bits = f64::INFINITY.to_bits();
    assert!(matches!(check_context(&dd, &e), Err(M::Now { .. })));
}

#[test]
fn check_context_validity_window_at_the_verifier_clock() {
    let (d, e) = journal_and_expected();
    let (iat, exp) = (d.context.pcactn_iat, d.context.pcactn_exp);
    let at = |now: i64, tol: f64| {
        let mut x = e.clone();
        x.now = now as f64;
        x.now_tolerance_ms = tol;
        check_context(&d, &x).err()
    };
    let big = 1.0e15;
    assert_eq!(at(iat, big), None);
    assert_eq!(at(exp, big), None);
    assert_eq!(at(exp + 1, big), Some(M::PcactnExpired));
    assert_eq!(at(iat - PCACTN_MAX_SKEW_MS, big), None);
    assert_eq!(at(iat - PCACTN_MAX_SKEW_MS - 1, big), Some(M::PcactnNotYetValid));
    // lifetime
    let mut dd = d.clone();
    dd.context.pcactn_exp = iat + PCACTN_MAX_LIFETIME_MS;
    let mut ee = e.clone();
    ee.pcactn_exp = iat + PCACTN_MAX_LIFETIME_MS;
    assert_eq!(check_context(&dd, &ee), Ok(()));
    dd.context.pcactn_exp += 1;
    ee.pcactn_exp += 1;
    assert_eq!(check_context(&dd, &ee), Err(M::PcactnLifetime));
    dd.context.pcactn_exp = iat;
    ee.pcactn_exp = iat;
    assert_eq!(check_context(&dd, &ee), Err(M::PcactnLifetime));
}

// ------------------------------------------------------------------------------------------------ verify_hops

#[test]
fn verify_hops_requires_string_fields_each_alone() {
    let b = base();
    let chain: Vec<Value> = b["chain"].as_array().unwrap().clone();
    let root = b["expected_root_principal"].as_str().unwrap();
    assert!(verify_hops(&chain, root).ok);
    for k in ["id", "issuer", "holder", "body_digest", "sig"] {
        let mut c = chain.clone();
        c[0][k] = json!(5);
        let v = verify_hops(&c, root);
        assert!(!v.ok);
        assert_eq!(v.reason.as_deref(), Some("hop 0: malformed capability"), "{k}");
    }
    for k in ["alg", "pq_pk", "pq_sig", "parent"] {
        let mut c = chain.clone();
        c[0][k] = json!(5);
        assert_eq!(verify_hops(&c, root).reason.as_deref(), Some("hop 0: malformed capability"), "{k}");
    }
    let mut c = chain.clone();
    c[0]["caveats"] = json!({});
    assert_eq!(verify_hops(&c, root).reason.as_deref(), Some("hop 0: malformed capability"));
    let mut c = chain.clone();
    c[0]["caveats"] = json!([5]);
    assert_eq!(verify_hops(&c, root).reason.as_deref(), Some("hop 0: malformed capability"));
    let mut c = chain.clone();
    c[0]["caveats"] = json!([{ "type": 5 }]);
    assert_eq!(verify_hops(&c, root).reason.as_deref(), Some("hop 0: malformed capability"));
    let mut c = chain.clone();
    c[0]["caveats"] = json!([{ "nope": 5 }]);
    assert_eq!(verify_hops(&c, root).reason.as_deref(), Some("hop 0: malformed capability"));
    assert_eq!(verify_hops(&[json!(5)], root).reason.as_deref(), Some("hop 0: malformed capability"));
}

// ------------------------------------------------------------------------------------- decide: risk wiring

fn sc(f: f64) -> u128 {
    if !f.is_finite() || f < 0.0 {
        return 0;
    }
    (f * S as f64).round() as u128
}

/// An independent recomputation of (r_scaled, tier) from the sample's own risk policy.
fn expected_risk(v: &Value) -> (u64, u8) {
    let env = v["grant"]["caveats"].as_array().unwrap().iter().find(|c| c["type"] == "envelope").unwrap();
    let rp = &env["risk_policy"];
    let w = &rp["weights"];
    let ws: Vec<u128> = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"].iter().map(|k| sc(w[*k].as_f64().unwrap())).collect();
    let x: Vec<u128> = v["risk_inputs_scaled"].as_array().unwrap().iter().map(|n| (n.as_u64().unwrap() as u128).min(S as u128)).collect();
    let inv = [false, true, false, false, true, false];
    let mut acc: u128 = 0;
    for i in 0..6 {
        let t = if inv[i] { S as u128 - x[i] } else { x[i] };
        acc += ws[i] * t;
    }
    let s2 = (S as u128) * (S as u128);
    acc = acc.min(s2);
    let floor = (v["r_floor_scaled"].as_u64().unwrap_or(0) as u128).min(S as u128) * S as u128;
    acc = acc.max(floor);
    let t1 = sc(rp["theta1"].as_f64().unwrap()) * S as u128;
    let t2 = sc(rp["theta2"].as_f64().unwrap()) * S as u128;
    let tier = if acc <= t1 { 1 } else if acc <= t2 { 2 } else { 3 };
    ((acc / S as u128) as u64, tier)
}

#[test]
fn decide_risk_matches_an_independent_recomputation() {
    let b = base();
    let (r0, t0) = expected_risk(&b);
    let d0 = decide(&di(&b));
    assert_eq!((d0.r_scaled, d0.tier), (r0, t0));
    assert!(r0 > 0 && r0 < S, "the sample's risk is strictly inside (0, 1): {r0}");
    let cases: Vec<[u64; 6]> = vec![
        [0, 0, 0, 0, 0, 0],
        [S, S, S, S, S, S],
        [S, 0, S, S, 0, S],
        [123_456, 654_321, 111_111, 222_222, 333_333, 444_444],
        [5, 5, 5, 5, 5, 5],
        [u64::MAX, 0, u64::MAX, 0, u64::MAX, 0],
        [500_000, 500_000, 500_000, 500_000, 500_000, 500_000],
        [900_000, 100_000, 800_000, 700_000, 200_000, 600_000],
    ];
    for x in cases {
        for floor in [0u64, 1, 400_000, 999_999, S, u64::MAX] {
            let mut v = base();
            v["risk_inputs_scaled"] = json!(x);
            v["r_floor_scaled"] = json!(floor);
            let (r, t) = expected_risk(&v);
            let d = decide(&di(&v));
            assert_eq!((d.r_scaled, d.tier), (r, t), "x={x:?} floor={floor}");
        }
    }
}

fn well_formed(v: &Value) -> bool {
    let e = v["grant"]["caveats"].as_array().unwrap().iter().find(|c| c["type"] == "envelope").unwrap();
    pca_zkvm_core::envelope_well_formed(e)
}

#[test]
fn decide_policy_scaling_reaches_the_gate() {
    // vary the policy numbers themselves: every one of them goes through `scale`
    let probes: Vec<(&str, f64)> = vec![("theta1", 0.0), ("theta1", 0.9999), ("theta1", 1.0), ("theta2", 0.5), ("theta2", 0.0), ("theta2", 1.0)];
    for (k, val) in probes {
        let mut v = base();
        for c in v["grant"]["caveats"].as_array_mut().unwrap() {
            if c["type"] == "envelope" {
                c["risk_policy"][k] = json!(val);
            }
        }
        // R6: risk.ts validateRiskPolicy (theta2 >= theta1) => an invalid policy is no envelope: fail closed
        let (r, t) = if well_formed(&v) { expected_risk(&v) } else { (S, 3) };
        let d = decide(&di(&v));
        assert_eq!((d.r_scaled, d.tier), (r, t), "{k}={val}");
    }
    for key in ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"] {
        for val in [0.0, 0.05, 0.3, 1.0, 2.5, -0.5] {
            let mut v = base();
            for c in v["grant"]["caveats"].as_array_mut().unwrap() {
                if c["type"] == "envelope" {
                    c["risk_policy"]["weights"][key] = json!(val);
                }
            }
            // R6: a negative weight is refused by validateRiskPolicy => fail closed
            let (r, t) = if well_formed(&v) { expected_risk(&v) } else { (S, 3) };
            assert_eq!(well_formed(&v), val >= 0.0);
            let d = decide(&di(&v));
            assert_eq!((d.r_scaled, d.tier), (r, t), "{key}={val}");
        }
    }
    // a malformed / absent envelope policy fails closed: allow 0, tier 3, r = 1
    let mut v = base();
    for c in v["grant"]["caveats"].as_array_mut().unwrap() {
        if c["type"] == "envelope" {
            c["risk_policy"].as_object_mut().unwrap().remove("kappa");
        }
    }
    let d = decide(&di(&v));
    assert_eq!((d.allow, d.tier, d.r_scaled), (0, 3, S));
}

// ---------------------------------------------- decide: reversibility class derived from the matched plan node

/// A fully signed input whose root envelope carries `extra_caveat` and whose plan/action are as given.
fn minted(extra_envelope_caveat: Option<Value>, edit: impl Fn(&mut Value)) -> Value {
    let mut b = base();
    if let Some(cv) = extra_envelope_caveat {
        for c in b["grant"]["caveats"].as_array_mut().unwrap() {
            if c["type"] == "envelope" {
                c["caveats"].as_array_mut().unwrap().push(cv.clone());
            }
        }
    }
    let chain = mint::two_hop(&b, vec![]);
    let mut v = mint::with_chain(&b, chain, &mint::key(3));
    edit(&mut v);
    mint::resign(&mut v, &mint::key(3));
    v
}

fn allowed(v: &Value) -> bool {
    decide(&di(v)).allow == 1
}

#[test]
fn minted_baseline_is_allowed() {
    assert!(allowed(&minted(None, |_| {})));
}

#[test]
fn reversibility_class_is_taken_from_the_matching_plan_node_when_the_action_omits_it() {
    let cap = Some(json!({ "type": "reversibility_max", "class": "reversible" }));
    // the action states its class itself
    assert!(allowed(&minted(cap.clone(), |_| {})));
    let drop_rc = |v: &mut Value| {
        v["action"].as_object_mut().unwrap().remove("reversibility_class");
        v["pcactn"]["action"].as_object_mut().unwrap().remove("reversibility_class");
    };
    // the matching node (n1: read /acct/123/items) is reversible -> allowed
    assert!(allowed(&minted(cap.clone(), drop_rc)));
    // an EARLIER node shares only the verb (or only the resource) and is irreversible: it must not be picked
    for (name, node) in [
        ("same verb only", json!({"id": "m0", "verb": "read", "resource": "/elsewhere", "reversibility_class": "irreversible"})),
        ("same resource only", json!({"id": "m0", "verb": "other", "resource": "/acct/123/items", "reversibility_class": "irreversible"})),
    ] {
        let v = minted(cap.clone(), |v| {
            drop_rc(v);
            let mut plan = vec![node.clone()];
            plan.extend(v["plan"].as_array().unwrap().iter().cloned());
            v["pcactn"]["plan"]["root"] = json!(plan_commitment(&plan).unwrap());
            v["plan"] = json!(plan);
        });
        assert!(allowed(&v), "{name}: only a node matching BOTH verb and resource supplies the class");
    }
    // and when the matching node itself is irreversible the caveat bites
    let v = minted(cap.clone(), |v| {
        drop_rc(v);
        v["plan"][1]["reversibility_class"] = json!("irreversible");
        let plan = v["plan"].as_array().unwrap().clone();
        v["pcactn"]["plan"]["root"] = json!(plan_commitment(&plan).unwrap());
    });
    assert!(!allowed(&v));
    // no matching node at all -> no class -> the caveat fails closed (and the binding too)
    let v = minted(cap, |v| {
        drop_rc(v);
        v["plan"][1]["verb"] = json!("zzz");
        let plan = v["plan"].as_array().unwrap().clone();
        v["pcactn"]["plan"]["root"] = json!(plan_commitment(&plan).unwrap());
    });
    assert!(!allowed(&v));
}
