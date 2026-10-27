//! The A2A binding: packages/pca/conformance/a2a-vectors.json. A missing file fails, it never skips.
use atlas_pca::a2a::*;
use atlas_pca::serde_json::Value;

fn strs(v: &Value) -> Vec<&str> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect()
}

#[test]
fn a2a_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/a2a-vectors.json");
    let doc: Value = atlas_pca::serde_json::from_str(&std::fs::read_to_string(path).expect("read a2a-vectors.json")).expect("parse");
    let mut bad: Vec<String> = Vec::new();
    for c in doc["need"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let exp = &c["expect"];
        let ok = match (decode_need(&c["input"]), exp["ok"].as_bool().unwrap()) {
            (Ok(n), true) => need_digest(&n).as_deref() == exp["digest"].as_str(),
            (Err(code), false) => Some(code) == exp["code"].as_str(),
            _ => false,
        };
        if !ok {
            bad.push(format!("need {name}"));
        }
    }
    let push = &doc["push"];
    for t in push["tokens"].as_array().unwrap() {
        if push_token(t["task_id"].as_str().unwrap(), &strs(&t["chain_ids"]), t["salt"].as_str().unwrap()).as_deref() != t["token"].as_str() {
            bad.push("push token".into());
        }
    }
    for sl in strs(&push["weak_salts"]) {
        if push_token("t", &["a"], sl).is_some() {
            bad.push(format!("weak salt {sl}"));
        }
    }
    for c in push["checks"].as_array().unwrap() {
        let e = &c["expected"];
        let got = check_push(e["task_id"].as_str().unwrap(), &strs(&e["chain_ids"]), e["salt"].as_str().unwrap(), &c["delivered"]["token"], &c["delivered"]["payload"]);
        let exp = &c["expect"];
        let ok = match (&got, exp["ok"].as_bool().unwrap()) {
            (Ok(()), true) => true,
            (Err(r), false) => Some(*r) == exp["reason"].as_str(),
            _ => false,
        };
        if !ok {
            bad.push(format!("push {}: {got:?}", c["name"]));
        }
    }
    for c in doc["chains"].as_array().unwrap() {
        let chains: Vec<Vec<String>> = c["chains"].as_array().unwrap().iter().map(|l| strs(l).iter().map(|x| x.to_string()).collect()).collect();
        let got = check_chain_extension(&chains);
        let exp = &c["expect"];
        let ok = match (&got, exp["ok"].as_bool().unwrap()) {
            (Ok(()), true) => true,
            (Err((hop, r)), false) => Some(*r) == exp["reason"].as_str() && Some(*hop as i64) == exp["failedHop"].as_i64(),
            _ => false,
        };
        if !ok {
            bad.push(format!("chains {}: {got:?}", c["name"]));
        }
    }
    for c in doc["resume"].as_array().unwrap() {
        let pa = c["proof_action"].as_object().map(|o| (o["verb"].as_str().unwrap(), o["resource"].as_str().unwrap()));
        let got = resume_gate(c["state"].as_str().unwrap(), &c["need_encoded"], &c["answer_need_digest"], pa);
        if got != c["expect"].as_str() {
            bad.push(format!("resume {}: {got:?}", c["name"]));
        }
    }
    let r = &doc["receipts"];
    let signer = r["signer"].as_str().unwrap();
    let recs = r["records"].as_array().unwrap();
    for v in r["verify"].as_array().unwrap() {
        if verify_receipt(&recs[v["record"].as_u64().unwrap() as usize], signer) != v["ok"].as_bool().unwrap() {
            bad.push(format!("verify {}", v["record"]));
        }
    }
    for d in r["digests"].as_array().unwrap() {
        if receipt_digest(&recs[d["record"].as_u64().unwrap() as usize]).as_deref() != d["digest"].as_str() {
            bad.push("digest".into());
        }
    }
    for sc in r["scenarios"].as_array().unwrap() {
        let list: Vec<Value> = sc["indices"].as_array().unwrap().iter().map(|i| recs[i.as_u64().unwrap() as usize].clone()).collect();
        let ids = strs(&sc["chain_ids"]);
        let tid = sc["task_id"].as_str().unwrap();
        let got = check_receipt_chain(&list, signer, tid, &ids);
        let exp = &sc["expect"];
        let ok = match &got {
            ReceiptChain::Ok { terminal, last_state } => exp["ok"] == true && Some(*terminal) == exp["terminal"].as_bool() && Some(last_state.as_str()) == exp["last_state"].as_str(),
            ReceiptChain::Refused { code, at } => exp["ok"] == false && Some(*code) == exp["code"].as_str() && (exp["at"].is_null() || at.map(|a| a as i64) == exp["at"].as_i64()),
        };
        if !ok || may_trigger_next(&list, signer, tid, &ids) != sc["may_trigger_next"].as_bool().unwrap() {
            bad.push(format!("receipts {}: {got:?}", sc["name"]));
        }
    }
    assert!(bad.is_empty(), "{} failures:\n{}", bad.len(), bad.join("\n"));
}
