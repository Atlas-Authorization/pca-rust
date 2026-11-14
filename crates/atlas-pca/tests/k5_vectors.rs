//! The K5 workflow-admission, read-side and vault/aggregate bindings:
//! packages/pca/conformance/{workflow,readside,vault-aggregate}-vectors.json.
//! A missing file fails, it never skips.
use atlas_pca::read_vault::*;
use atlas_pca::readside::*;
use atlas_pca::serde_json::json;
use atlas_pca::serde_json::Value;
use atlas_pca::workflow::*;

fn load(name: &str) -> Value {
    let path = format!("{}/../../conformance/{name}", env!("CARGO_MANIFEST_DIR"));
    atlas_pca::serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))).expect("parse")
}

#[test]
fn workflow_vectors() {
    let w = load("workflow-vectors.json");
    let mut bad: Vec<String> = Vec::new();
    if workflow_digest(&w["workflows"]["main"]["body"]).as_deref() != w["digests"]["workflow"].as_str() {
        bad.push("workflow digest".into());
    }
    for v in w["digests"]["values"].as_array().unwrap() {
        if value_digest(&v["value"]).as_deref() != v["digest"].as_str() {
            bad.push(format!("value digest {}", v["value"]));
        }
    }
    for p in w["digests"]["params"].as_array().unwrap() {
        if atlas_pca::hash_canonical_strict(&p["params"]).as_deref() != p["digest"].as_str() {
            bad.push("params digest".into());
        }
    }
    assert_eq!(w["digests"]["receipt_refs"].as_array().unwrap().len(), 4);
    let mut seen = std::collections::BTreeSet::new();
    for (group, f) in [("admit", admit_step as fn(&AdmitInput) -> WfResult), ("bind", bind_promises as fn(&AdmitInput) -> WfResult)] {
        for c in w[group].as_array().unwrap() {
            let inp = AdmitInput { workflow: &w["workflows"][c["workflow"].as_str().unwrap()], principal: &c["principal"], rs_signer: &c["rs_signer"], receipts: &c["receipts"], now: &c["now"], request: &c["request"] };
            let got = f(&inp).to_json();
            if got != c["expect"] {
                bad.push(format!("{group} {}: got {got}", c["name"]));
            }
            if let Some(code) = c["expect"]["code"].as_str() {
                seen.insert(code.to_string());
            }
        }
    }
    for c in w["plan_root"].as_array().unwrap() {
        let got = plan_root_authorized(&w["workflows"][c["workflow"].as_str().unwrap()], c["principal"].as_str().unwrap(), c["now"].as_i64().unwrap(), c["root"].as_str().unwrap_or(""));
        if Some(got) != c["expect"].as_bool() {
            bad.push(format!("plan_root {}", c["name"]));
        }
    }
    for code in ["bad_workflow", "bad_dag", "bad_signature", "not_yet", "expired", "goal_mismatch", "plan_root_mismatch", "bad_receipt", "unplanned_step", "step_mismatch", "params_mismatch", "already_done", "budget_exceeded", "deps_unmet", "dep_failed", "stale_dep", "edge_missing", "edge_unit", "edge_digest", "edge_value", "edge_relation", "taint_flow", "pipeline_unconstrained", "taint_escalate"] {
        if !seen.contains(code) {
            bad.push(format!("code {code} not exercised"));
        }
    }
    // hostile input denies, never panics
    let nul = Value::Null;
    let one = atlas_pca::serde_json::json!(1);
    let inp = AdmitInput { workflow: &nul, principal: &nul, rs_signer: &nul, receipts: &nul, now: &one, request: &nul };
    if admit_step(&inp).decision != Decision::Deny || bind_promises(&inp).decision != Decision::Deny {
        bad.push("hostile".into());
    }
    assert!(bad.is_empty(), "{} failures:\n{}", bad.len(), bad.join("\n"));
}

#[test]
fn readside_vectors() {
    let r = load("readside-vectors.json");
    let mut bad: Vec<String> = Vec::new();
    for c in r["redact"].as_array().unwrap() {
        let mut inp = c["input"].clone();
        inp["grant"] = r["grants"][c["grant"].as_str().unwrap()].clone();
        let got = redact_read(&inp).to_json();
        if got != c["expect"] {
            bad.push(format!("redact {}: got {got}", c["name"]));
        }
    }
    for c in r["sinks"].as_array().unwrap() {
        let got = check_sink(&r["grants"][c["grant"].as_str().unwrap()], &c["principal"], &c["rs_signer"], &c["now"], &c["sink"], &c["receipts"]).to_json();
        if got != c["expect"] {
            bad.push(format!("sink {}: got {got}", c["name"]));
        }
    }
    if read_grant_digest(&r["grants"]["main"]["body"]).as_deref() != r["digests"]["grant"].as_str() {
        bad.push("grant digest".into());
    }
    assert_eq!(r["digests"]["receipt_refs"].as_array().unwrap().len(), 4);
    let two = r["sinks"].as_array().unwrap().iter().find(|s| s["name"] == "chain-of-two-public-reads").expect("chain-of-two-public-reads");
    let labels = read_chain_labels(&two["receipts"], r["keys"]["rs"].as_str().unwrap(), r["digests"]["grant"].as_str().unwrap(), 1_800_000_000_000).ok();
    let want: Option<Vec<String>> = r["digests"]["chain_labels"]["labels"].as_array().map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect());
    if labels != want {
        bad.push(format!("chain labels {labels:?}"));
    }
    assert!(bad.is_empty(), "{} failures:\n{}", bad.len(), bad.join("\n"));
}

fn opt_ints(v: &Value) -> Vec<Option<i64>> {
    v.as_array().unwrap().iter().map(Value::as_i64).collect()
}

#[test]
fn vault_aggregate_vectors() {
    let v = load("vault-aggregate-vectors.json");
    let mut bad: Vec<String> = Vec::new();
    for u in v["sampler"]["uniform"].as_array().unwrap() {
        let mut d = seeded_draws(u["seed"].as_str().unwrap());
        let got: Vec<Option<i64>> = u["bounds"].as_array().unwrap().iter().map(|n| d.uniform(n.as_i64().unwrap()).ok()).collect();
        if got != opt_ints(&u["draws"]) {
            bad.push(format!("uniform {}: got {got:?}", u["seed"]));
        }
    }
    for l in v["sampler"]["laplace"].as_array().unwrap() {
        let mut d = seeded_draws(l["seed"].as_str().unwrap());
        let (s, t) = (l["s"].as_i64().unwrap(), l["t"].as_i64().unwrap());
        let got: Vec<Option<i64>> = (0..l["values"].as_array().unwrap().len()).map(|_| d.discrete_laplace(s, t).ok()).collect();
        if got != opt_ints(&l["values"]) {
            bad.push(format!("laplace {}: got {got:?}", l["seed"]));
        }
    }
    for c in v["vault"].as_array().unwrap() {
        let store = MemoryVault::new();
        let mut inp = c["redact"].clone();
        inp["grant"] = v["grants"]["vault"][c["redact_grant"].as_str().unwrap()].clone();
        let red = redact_read_with_vault(&inp, &store);
        let token = if c["token"].is_string() { c["token"].clone() } else { red.view.get(c["field"].as_str().unwrap_or("")).cloned().unwrap_or(Value::Null) };
        let d = &c["detok"];
        let got = detokenize(&v["grants"]["vault"][c["detok_grant"].as_str().unwrap()], &d["principal"], &d["now"], &d["sink"], &token, &store).to_json();
        if got != c["expect"] {
            bad.push(format!("vault {}: got {got}", c["name"]));
        }
    }
    for c in v["aggregate"].as_array().unwrap() {
        let mut state = c["initial_state"].clone();
        for (i, s) in c["steps"].as_array().unwrap().iter().enumerate() {
            let mut inp = json!({
                "principal": v["keys"]["principal"], "now": 1_800_000_000_000i64, "verb": "orders.stats", "resource": "orders/eu", "purpose": "analytics",
                "fn": "sum", "values": [10, 20, 500, -900], "salt": "a-per-read-secret-salt", "noise": "seeded",
            });
            for (k, x) in s["input"].as_object().unwrap() {
                inp[k.as_str()] = x.clone();
            }
            inp["grant"] = v["grants"]["aggregate"][s["input"]["grant"].as_str().unwrap_or("main")].clone();
            inp["state"] = state.clone();
            let r = aggregate_read(&inp);
            if r.to_json() != s["expect"] {
                bad.push(format!("aggregate {} step {i}: got {}", c["name"], r.to_json()));
            }
            state = r.state;
        }
    }
    // hostile input denies with the empty state, never panics
    let h = aggregate_read(&Value::Null);
    if (h.decision, h.code, &h.state) != (Decision::Deny, Some("bad_request"), &empty_aggregate_state()) {
        bad.push("hostile aggregate".into());
    }
    assert!(bad.is_empty(), "{} failures:\n{}", bad.len(), bad.join("\n"));
}

/// `secure` noise is the production setting: two fresh seeds give different streams (the values are not pinned), and a dp read admits.
#[test]
fn secure_noise_differs_per_call() {
    let stream = || {
        let mut d = secure_draws().expect("os randomness");
        (0..8).map(|_| d.uniform(1 << 47).unwrap()).collect::<Vec<i64>>()
    };
    assert_ne!(stream(), stream());
    let v = load("vault-aggregate-vectors.json");
    let inp = json!({
        "principal": v["keys"]["principal"], "now": 1_800_000_000_000i64, "verb": "orders.stats", "resource": "orders/eu", "purpose": "analytics",
        "fn": "sum", "values": [10, 20, 500, -900], "salt": "a-per-read-secret-salt", "noise": "secure",
        "grant": v["grants"]["aggregate"]["main"], "state": empty_aggregate_state(),
    });
    let r = aggregate_read(&inp);
    assert_eq!((r.decision, r.code, r.charged_micro), (Decision::Allow, None, 500_000), "{r:?}");
}
