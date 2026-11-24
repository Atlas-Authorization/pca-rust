//! k05 differential oracle for session histories: tests/data/k05-intenthistory.json.gz, written by the TypeScript reference
//! (tools/pca-audit/k05-oracles/intenthistory-oracle.mts; the Java suite replays the same file): every window kind around its
//! edges, accumulator keys, pre-states and post values over junk / corrupt histories and safe-integer edges, and monitor steps and
//! folds (the responds_within counter over hostile `pending:` states). Compared by JSON value; a reference throw must be an `Err`
//! (accPreState / accPost / monitorStep / monitorState; a monitor's undefined is `Ok(None)`); where the reference's inWindow
//! falls off its switch (undefined, falsy) the answer must be false.
use super::*;
use crate::k042_support::{k05_run, K05};
use serde_json::json;

#[test]
fn k05_intenthistory_matches_the_reference() {
    k05_run("intenthistory", 26000, |c, f, a| {
        let want = &c["out"];
        let empty = Map::new();
        match f {
            "inWindow" => {
                let got = match a[0].as_object() {
                    Some(w) => in_window(w, a.get(1), a.get(2)),
                    None if want.get("$throws").is_some() => return K05::Skip("non-object window (typed port)"),
                    None => in_window(&empty, a.get(1), a.get(2)),
                };
                // the reference returns undefined for an unknown kind (the oracle writes null): falsy
                if want.is_null() { K05::Match(!got) } else { K05::Val(json!(got)) }
            }
            "accKeyOf" => match a[0].as_object() {
                Some(acc) => K05::Val(json!(acc_key_of(acc, a[1].as_object().unwrap_or(&empty)))),
                None => K05::Skip("non-object accumulator (typed port)"),
            },
            "accPreState" | "accPost" => {
                let (Some(acc), Some(hist), Some(cand)) = (a[0].as_object(), a[1].as_array(), a[2].as_object()) else {
                    return K05::Skip("non-object accumulator / candidate or non-list history (typed port)");
                };
                let params = cand.get("params").and_then(Value::as_object).unwrap_or(&empty);
                let got = if f == "accPreState" {
                    acc_pre_state(acc, hist, params, cand.get("t"), None)
                } else {
                    let Some(verb) = cand.get("verb").and_then(Value::as_str) else { return K05::Skip("non-string verb (typed port)") };
                    acc_post(acc, hist, verb, params, cand.get("t"), None).map(|n| json!(n))
                };
                match got {
                    Ok(v) => K05::Val(v),
                    Err(_) => K05::Throw(None),
                }
            }
            "monitorStep" => match (a[0].as_object(), a[1].as_str()) {
                (Some(m), Some(q)) => match monitor_step(m, q, &a[2]) {
                    Ok(v) => K05::Val(json!(v)),
                    Err(_) => K05::Throw(None),
                },
                _ => K05::Skip("non-object monitor / non-string state (typed port)"),
            },
            "monitorState" => match (a[0].as_object(), a[1].as_array()) {
                (Some(m), Some(h)) => match monitor_state(m, h) {
                    Ok(v) => K05::Val(json!(v)),
                    Err(_) => K05::Throw(None),
                },
                _ => K05::Skip("non-object monitor / non-list history (typed port)"),
            },
            _ => K05::Skip("fn not in this module"),
        }
    });
}

/// TS 80ad8c7ff (mutation-kill-r13-g2-history.test.ts "refuses an agg outside ..."): accPost refuses an agg outside
/// sum / count / max / distinct first, selected or not, keyed or not; the same declaration with agg "sum" answers 15 / 10 / 15.
#[test]
fn acc_post_refuses_an_unknown_agg_first() {
    const T: i64 = 1_000_000;
    let sum = json!({"id": "spend", "agg": "sum", "val": "action.params.total", "sel": {"verbs": ["pay"]}, "win": {"kind": "task"}, "key": null, "holder": {"kind": "site_local"}});
    let hist = vec![json!({"id": "e1", "verb": "pay", "resource": "r", "params": {"total": 10, "k": "x", "to": "p"}, "t": T, "status": "committed"})];
    let t = json!(T);
    let post = |a: &Value, verb: &str, params: Value| acc_post(a.as_object().unwrap(), &hist, verb, params.as_object().unwrap(), Some(&t), None);
    let keyed = |a: &Value| { let mut a = a.clone(); a["key"] = json!("action.params.k"); a };
    assert_eq!(post(&sum, "pay", json!({"total": 5})), Ok(15));
    assert_eq!(post(&sum, "look", json!({"total": 5})), Ok(10));
    assert_eq!(post(&keyed(&sum), "pay", json!({"total": 5, "k": "x"})), Ok(15));
    for agg in [json!("SUM"), json!("tVm"), json!(""), json!("avg"), Value::Null, json!(1), json!("missing")] {
        let mut bad = sum.clone();
        if agg == json!("missing") { bad.as_object_mut().unwrap().remove("agg"); } else { bad["agg"] = agg.clone(); }
        for verb in ["pay", "look"] {
            assert_eq!(post(&bad, verb, json!({"total": 5})), Err("accPost: unknown agg".to_string()), "{agg} {verb}");
        }
        assert_eq!(post(&keyed(&bad), "pay", json!({"total": 5})), Err("accPost: unknown agg".to_string()), "{agg} keyed");
    }
}

/// inWindow(undefined, ti, t) (intent-history.ts:61-64): an event stamped after the candidate is in any window, but one at the
/// candidate's own time reads `win.kind` of a missing window and throws, so accPreState / accPost refuse; with a window it counts.
#[test]
fn an_event_at_the_candidates_time_with_no_window_is_refused() {
    const T: i64 = 1_000_000;
    let mut acc = json!({"id": "spend", "agg": "sum", "val": "action.params.total", "sel": {"verbs": ["pay"]}, "key": null, "holder": {"kind": "site_local"}});
    let ev = |t: i64| json!({"id": "e1", "verb": "pay", "resource": "r", "params": {"total": 10}, "t": t, "status": "committed"});
    let params = json!({"total": 5});
    let pre = |acc: &Value, t: i64| acc_pre_state(acc.as_object().unwrap(), &[ev(t)], params.as_object().unwrap(), Some(&json!(T)), None);
    assert_eq!(pre(&acc, T + 1), Ok(json!({"sum": 10})));
    assert!(pre(&acc, T).is_err());
    assert!(pre(&acc, T - 1).is_err());
    acc["win"] = json!({"kind": "task"});
    assert_eq!(pre(&acc, T), Ok(json!({"sum": 10})));
}
