//! Intent Layer v2 rule 15 (`accumulators`) in the guest: `fixtures/ts_v2_acc.json` (TS reference verdicts,
//! `gen_ts_v2_acc.ts`, via `decideIntentV2`) reproduced by `intent_acc::acc_step` and its helpers. Post-quantum cases the guest
//! implements are compared exactly; `requires_suite` cases naming a suite the guest lacks (LESS) must fail with `unsupported_suite`; the others (FN-DSA) compare exactly.
use pca_zkvm_core::intent_acc::*;
use serde_json::Value;

fn fx() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/ts_v2_acc.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn arr<'a>(d: &'a Value, k: &str) -> &'a Vec<Value> {
    d[k].as_array().unwrap_or_else(|| panic!("fixture member {k}"))
}

#[test]
fn acc_step_matches_the_reference() {
    let d = fx();
    let cases = arr(&d, "cases");
    assert!(cases.len() >= 250, "only {} cases", cases.len());
    let (mut ok_n, mut suite_n, mut top_n) = (0, 0, 0);
    let mut bad = Vec::new();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let ctx = &c["ctx"];
        let s = &ctx["session"]["root"];
        let schema_doc = match &c["schema_doc"] {
            Value::Null => None,
            v => Some(v),
        };
        let got = acc_step(&c["pcactn"], s, Some(ctx), c["now"].as_f64().unwrap(), schema_doc);
        let want_ok = c["expect"]["ok"].as_bool().unwrap();
        let reason = got.as_ref().err().cloned().unwrap_or_default();
        if c["requires_suite"].is_string() {
            suite_n += 1;
        }
        if let Some(alg) = c["requires_suite"].as_str().filter(|a| !pca_zkvm_core::pq_suites::suite_supported(Some(a))) {
            // a suite the guest does not implement: fail closed with unsupported_suite, whatever the reference says
            if got.is_ok() || !reason.contains("unsupported_suite") {
                bad.push(format!("{name}: requires {alg}: the guest must fail with unsupported_suite, got {got:?}"));
            }
            continue;
        }
        if c.get("top_ctx_error").is_some() {
            // the coordinator (intent_v2.rs) refuses this context before rule 15: acc_step is not consulted
            top_n += 1;
            if want_ok {
                bad.push(format!("{name}: malformed top-level context accepted by TS"));
            }
            continue;
        }
        if let Some(r) = c["guest_reason_contains"].as_str() {
            if !reason.contains(r) {
                bad.push(format!("{name}: guest reason {reason:?} lacks {r}"));
            }
        }
        match (&got, want_ok) {
            (Ok(env), true) => {
                ok_n += 1;
                let want = &c["expect"]["env"];
                if Value::Object(env.acc.clone()) != want["acc"] || Value::Object(env.mon.clone()) != want["mon"] {
                    bad.push(format!("{name}: env differs: got acc={:?} mon={:?}, want {want}", env.acc, env.mon));
                }
            }
            (Err(_), false) => {}
            (Ok(_), false) => bad.push(format!("{name}: guest ok, TS fails ({})", c["expect"]["reason"])),
            (Err(e), true) => bad.push(format!("{name}: guest fails ({e}), TS ok")),
        }
    }
    assert!(bad.is_empty(), "{} cases differ:\n{}", bad.len(), bad.join("\n"));
    assert!(ok_n >= 40 && suite_n >= 8, "coverage: {ok_n} ok, {suite_n} requires_suite, {top_n} top-level");
    eprintln!("acc_step: {} cases, {ok_n} accepted, {suite_n} requires_suite, {top_n} top-level context errors", cases.len());
}

#[test]
fn declarations_match_the_reference() {
    let d = fx();
    let mut bad = Vec::new();
    for c in arr(&d, "decls") {
        if accumulator_decl_error(&c["decl"]).is_none() != c["ok"].as_bool().unwrap() {
            bad.push(format!("decl {}: {:?}", c["decl"], accumulator_decl_error(&c["decl"])));
        }
    }
    for c in arr(&d, "monitors") {
        let ok = monitor_decl_error(&c["decl"]).is_none();
        if ok != c["ok"].as_bool().unwrap() {
            bad.push(format!("monitor {}: {:?}", c["decl"], monitor_decl_error(&c["decl"])));
        }
        if ok {
            let want: Vec<String> = c["states"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
            if monitor_states(&c["decl"]).as_ref() != Some(&want) {
                bad.push(format!("monitor states {}", c["decl"]));
            }
            for st in &want {
                if monitor_state_ok(&c["decl"], st) != Some(true) {
                    bad.push(format!("monitor_state_ok {} {st}", c["decl"]));
                }
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    assert!(arr(&d, "decls").len() >= 60 && arr(&d, "monitors").len() >= 20);
}

#[test]
fn helpers_match_the_reference() {
    let d = fx();
    let mut bad = Vec::new();
    for c in arr(&d, "pre_states") {
        let agg = c["agg"].as_str().unwrap();
        let ok = pre_state_error(agg, &c["s"]).is_none();
        if ok != c["ok"].as_bool().unwrap() || (ok && pre_value(agg, &c["s"]) != c["value"].as_i64()) {
            bad.push(format!("pre {agg} {}", c["s"]));
        }
    }
    for c in arr(&d, "combine") {
        let v = AccValue { val: c["v"]["val"].as_i64().unwrap(), key: c["v"]["key"].as_str().map(str::to_string) };
        if combine_acc(c["agg"].as_str().unwrap(), &c["pre"], &v) != c["post"].as_i64() {
            bad.push(format!("combine {c}"));
        }
    }
    for c in arr(&d, "arith") {
        if receipt_arithmetic_ok(c["agg"].as_str().unwrap(), &c["r"], c["val"].as_i64().unwrap()) != c["ok"].as_bool().unwrap() {
            bad.push(format!("arith {c}"));
        }
    }
    for c in arr(&d, "digests") {
        if pcactn_reservation_digest(&c["pcactn"]).as_deref() != c["reservation"].as_str() {
            bad.push(format!("reservation digest {}", c["pcactn"]));
        }
    }
    for c in arr(&d, "receipt_shapes") {
        if acc_receipt_shape_error(&c["r"]).is_none() != c["ok"].as_bool().unwrap() {
            bad.push(format!("receipt shape {}: {:?}", c["r"], acc_receipt_shape_error(&c["r"])));
        }
        if acc_receipt_digest(&c["r"]).as_deref() != c["digest"].as_str() {
            bad.push(format!("receipt digest {}", c["r"]));
        }
    }
    for c in arr(&d, "key_set_shapes") {
        if sequencer_key_set_shape_error(&c["k"]).is_none() != c["ok"].as_bool().unwrap() {
            bad.push(format!("key set shape: {:?}", sequencer_key_set_shape_error(&c["k"])));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
