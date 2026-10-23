//! Differential kill test for intent_acc.rs (rule 15) against the TypeScript reference packages/pca/src/intent-acc.ts:
//! tests/data/k042-intentacc.json is written by tools/pca-audit/java-mutate/k042-intentacc-oracle.mjs (the Java suite runs
//! the same file); every case asserts the EXACT reason / verdict / value. A case whose input serde_json cannot hold (a lone
//! surrogate, 1e400) is skipped.
use super::*;
use crate::k042_support::{has_lone, parse, read};
use serde_json::json;

fn cases() -> Vec<Value> {
    let doc = parse(&read("k042-intentacc.json")).expect("corpus");
    let v = doc.as_array().expect("array").clone();
    assert!(v.len() > 1500, "corpus loaded");
    v
}

fn ostr(o: Option<String>) -> Value {
    o.map_or(Value::Null, Value::String)
}

/// Run every case of `fn_name` through `f(args)`; each must equal the TS output.
fn run(fn_name: &str, f: impl Fn(&[Value]) -> Value) {
    run_skip(fn_name, |_| false, f)
}

fn run_skip(fn_name: &str, skip: impl Fn(&[Value]) -> bool, f: impl Fn(&[Value]) -> Value) {
    let (mut bad, mut n) = (Vec::new(), 0);
    for c in cases() {
        if c["fn"] != fn_name {
            continue;
        }
        let args = c["args"].as_array().unwrap();
        if args.iter().any(has_lone) || skip(args) {
            continue;
        }
        n += 1;
        let got = f(args);
        let want = match &c["out"] {
            Value::String(t) => Value::String(t.clone()),
            o => o.clone(),
        };
        if got != want {
            let line = format!("want {}\n    got  {}", want, got);
            if !bad.iter().any(|b: &String| b.ends_with(&line)) {
                bad.push(format!("{}\n    {line}", c["name"]));
            }
        }
    }
    assert!(n > 0, "no cases for {fn_name}");
    assert!(bad.is_empty(), "{}/{} {fn_name} cases differ from the TS reference:\n  {}", bad.len(), n, bad.iter().take(400).cloned().collect::<Vec<_>>().join("\n  "));
}

fn m(v: &Value) -> &Map<String, Value> {
    v.as_object().expect("object")
}

fn st(v: &Value) -> &str {
    v.as_str().expect("string")
}

fn opt(v: &Value) -> Option<&Value> {
    if v.is_null() { None } else { Some(v) }
}

#[test]
fn t_accumulator_decl_error() {
    run("accumulatorDeclError", |a| ostr(accumulator_decl_error(&a[0])));
}

#[test]
fn t_monitor_decl_error() {
    run("monitorDeclError", |a| ostr(monitor_decl_error(&a[0])));
}

#[test]
fn t_monitor_states_of_the_reference() {
    run("monitorStates", |a| json!(monitor_states(&a[0])));
}

#[test]
fn t_tracked_key_set_error() {
    run("trackedKeySetError", |a| ostr(tracked_key_set_error(&a[0])));
}

#[test]
fn t_pre_state() {
    run("preStateError", |a| ostr(pre_state_error(st(&a[0]), &a[1])));
    run("preValue", |a| json!(pre_value(st(&a[0]), &a[1])));
    run("combineAcc", |a| {
        let v = AccValue { val: a[2]["val"].as_i64().unwrap(), key: a[2].get("key").and_then(Value::as_str).map(String::from) };
        combine_acc(st(&a[0]), &a[1], &v).map_or(Value::Null, |n| json!(n))
    });
}

#[test]
fn t_selection_and_values() {
    run("accSelects", |a| match acc_selects(m(&a[0]), st(&a[1]), opt(&a[2])) {
        Ok(b) => json!(b),
        Err(e) => json!(format!("THREW {e}")),
    });
    run("accValueOf", |a| match acc_value_of(m(&a[0]), st(&a[1]), m(&a[2]), opt(&a[3])) {
        Ok(Ok(v)) => json!({"ok": true, "val": v.val, "key": v.key}),
        Ok(Err(r)) => json!({"ok": false, "reason": r}),
        Err(e) => json!(format!("THREW {e}")),
    });
}

#[test]
fn t_receipt_arithmetic() {
    run("receiptArithmeticOk", |a| json!(receipt_arithmetic_ok(st(&a[0]), &a[1], a[2].as_i64().unwrap())));
}

#[test]
fn t_reservation_digest() {
    run("pcactnReservationDigest", |a| ostr(pcactn_reservation_digest(&a[0])));
}

#[test]
fn t_shapes() {
    run("receiptShapeError", |a| ostr(acc_receipt_shape_error(&a[0])));
    run("keySetShapeError", |a| ostr(sequencer_key_set_shape_error(&a[0])));
}

#[test]
fn t_key_set_and_receipt_signatures() {
    run("verifyKeySet", |a| {
        let pq = if a[3] == Value::Bool(true) { Some(&a[2]) } else { None };
        json!(verify_sequencer_key_set(&a[0], st(&a[1]), pq).unwrap_or(false))
    });
    run("verifyReceiptSignature", |a| {
        if !a[0].is_object() {
            return json!(false);
        }
        let signer = st(&a[1]);
        let pin = a[2].as_object().and_then(|p| p.get(signer)).map(|p| (signer, p));
        json!(verify_acc_receipt_signature(&a[0], signer, pin).unwrap_or(false))
    });
}

#[test]
fn t_receipt_against_holder() {
    // This crate's only caller (intent_v2) validates the clock (a safe integer), the policy ages and the tracked key set
    // BEFORE it calls the helper, so a non-integer / negative-zero / out-of-range clock or age and a malformed tracked set
    // are unreachable here: those reference refusals are skipped.
    let unreachable = |a: &[Value]| {
        let int = |v: &Value| v.as_f64().is_some_and(|x| x.fract() == 0.0 && x.abs() <= 9007199254740991.0 && !(x == 0.0 && x.is_sign_negative()));
        !int(&a[3]) || !int(&a[4]) || !int(&a[5]) || a[6].as_object().is_some_and(|_| tracked_key_set_error(&a[6]).is_some())
    };
    run_skip("verifyReceiptAgainstHolder", unreachable, |a| {
        let tracked = a[6].as_object().map(|t| (t["version"].as_i64().unwrap(), t["digest"].as_str().unwrap().to_string()));
        let f = ReceiptFreshness { max_receipt_age_ms: a[4].as_f64().unwrap(), max_keyset_age_ms: a[5].as_f64().unwrap(), tracked };
        json!(verify_receipt_against_holder(&a[0], m(&a[1]), opt(&a[2]), a[3].as_f64().unwrap(), &f).is_ok())
    });
}
