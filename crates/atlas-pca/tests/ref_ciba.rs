//! Differential replay of the CIBA bridge against the TypeScript reference (test-data/ref-ciba.json.gz): the displayed action,
//! ASCII forms, auth requests / binding messages, gating, the co-sign effect, the ping-callback check and scripted broker
//! lifecycles (in-memory and durable; the random auth_req_id masked as "ID").
//! A reference refusal must be a refusal; its text compares exactly unless it is a JavaScript TypeError. Cases with a lone
//! surrogate (no Rust string) are skipped.
mod common;
use atlas_pca::ciba::*;
use atlas_pca::risk::{RiskPolicy, TrustBudget, DEFAULT_RISK_POLICY};
use atlas_pca::serde_json::{json, Value};
use std::cell::Cell;
use std::rc::Rc;

/// Deliberately stricter than the reference (which lets a non-string auth_req_id through).
const STRICTER: [&str; 1] = ["toCibaAuthRequest/auth_req_id number"];

fn runtime(msg: &str) -> bool {
    msg.contains("Cannot read properties") || msg.contains("is not a function") || msg.contains("Cannot destructure")
}

fn same(want: &Value, got: Result<Value, String>) -> Result<(), String> {
    match (want.get("$throws").and_then(Value::as_str), got) {
        (Some(w), Err(g)) if w == g || runtime(w) => Ok(()),
        (None, Ok(g)) if atlas_pca::canonicalize(want) == atlas_pca::canonicalize(&g) => Ok(()),
        (_, g) => Err(format!("want {want}, got {g:?}")),
    }
}

fn n(f: f64) -> Value {
    if f.fract() == 0.0 {
        json!(f as i64)
    } else {
        json!(f)
    }
}

fn step_up() -> Value {
    json!({ "id": "su1", "verb": "stripe.payout", "resource": "acct:1", "params": { "amount": 80, "currency": "USD", "payee": "bob" }, "tier": 3, "reason": "r",
        "goalCommit": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq", "goal": "pay suppliers", "lineage": {}, "r": 0.5, "requestedAt": 1 })
}

fn mask(v: Value, id: &str) -> Value {
    match v {
        Value::String(s) if s == id => json!("ID"),
        Value::Array(a) => Value::Array(a.into_iter().map(|x| mask(x, id)).collect()),
        Value::Object(m) => Value::Object(m.into_iter().map(|(k, x)| (k, mask(x, id))).collect()),
        x => x,
    }
}

fn run_ops<S: ApprovalStore>(b: &ApprovalBroker<S>, t: &Cell<f64>, ops: &[Value]) -> Value {
    let su = step_up();
    let mut id = String::new();
    let mut out = Vec::new();
    for op in ops {
        let r = match op["op"].as_str().unwrap() {
            "now" => {
                t.set(op["t"].as_f64().unwrap());
                out.push(Value::Null);
                continue;
            }
            "start" => b.start(op.get("stepUp").unwrap_or(&su), op.get("opts").unwrap_or(&Value::Null)).map(|v| {
                id = v["auth_req_id"].as_str().unwrap().to_string();
                v
            }),
            "poll" => b.poll(&id),
            "token" => b.token(&id),
            "resolve" => b.resolve(&id, op["decision"].as_str().unwrap(), op["by"].as_str().unwrap()),
            "get" => b.get(&id).map(|v| v.unwrap_or(Value::Null)),
            "unknown" => match op["fn"].as_str().unwrap() {
                "poll" => b.poll("nope"),
                "token" => b.token("nope"),
                "resolve" => b.resolve("nope", "approve", "x"),
                _ => b.get("nope").map(|v| v.unwrap_or(Value::Null)),
            },
            o => panic!("unknown op {o}"),
        };
        out.push(match r {
            Ok(v) => json!({ "ok": true, "value": mask(v, &id) }),
            Err(_) => json!({ "ok": false }),
        });
    }
    Value::Array(out)
}

fn lifecycle(kind: &str, ops: &[Value]) -> Value {
    let t = Rc::new(Cell::new(1_000_000.0));
    let clock = {
        let t = t.clone();
        Box::new(move || t.get())
    };
    if kind == "memory" {
        run_ops(&create_ciba_broker(clock, Some(Box::new(|_: &Value| {}))), &t, ops)
    } else {
        run_ops(&create_durable_ciba_broker(MemoryApprovalStore::default(), clock, Some(100.0), None).unwrap(), &t, ops)
    }
}

fn cosign(args: &[Value]) -> Value {
    let b = &args[1];
    let budget = TrustBudget { b: b["B"].as_f64().unwrap(), tau: b["tau"].as_f64().unwrap(), as_of: b["asOf"].as_f64() };
    let p = &args[2];
    let policy =
        RiskPolicy { b_max: p["bMax"].as_f64().unwrap(), rho: p["rho"].as_f64().unwrap(), lambda: p["lambda"].as_f64().unwrap(), ..DEFAULT_RISK_POLICY };
    let full = args.get(4).is_some_and(|o| o["full"] == json!(true));
    let (nb, cosigned) = ciba_decision_to_cosign(args[0] == json!("approve"), &budget, &policy, args[3].as_f64().unwrap(), full);
    let mut bj = json!({ "B": n(nb.b), "tau": n(nb.tau) });
    if let Some(a) = nb.as_of {
        bj["asOf"] = n(a);
    }
    json!({ "budget": bj, "cosigned": cosigned })
}

#[test]
fn ciba_replays_the_reference() {
    let (mut fails, mut ran, mut skipped) = (Vec::new(), 0, 0);
    for c in common::ref_cases("ciba") {
        let (name, args, want) = (c["name"].as_str().unwrap().to_string(), c["args"].as_array().unwrap().clone(), &c["out"]);
        if common::has_lone(&c) {
            skipped += 1;
            continue;
        }
        let r = match c["fn"].as_str().unwrap() {
            "cibaActionFromStepUp" => same(want, ciba_action_from_step_up(&args[0])),
            "asciiForm" => same(want, Ok(json!(ascii_form(args[0].as_str().unwrap())))),
            "toCibaAuthRequest" => {
                let got = to_ciba_auth_request(&args[0], args.get(1).unwrap_or(&Value::Null));
                if STRICTER.contains(&name.as_str()) {
                    got.err().map(|_| ()).ok_or_else(|| "stricter case must refuse".to_string())
                } else {
                    same(want, got)
                }
            }
            "requiresCiba" => same(want, Ok(json!(requires_ciba(&args[0])))),
            "cibaDecisionToCosign" => same(want, Ok(cosign(&args))),
            "verifyPingCallback" => {
                let (input, flow) = (&args[0], &args[1]);
                let got = verify_ping_callback(
                    input.get("authorization").and_then(Value::as_str),
                    input.get("body").unwrap_or(&Value::Null),
                    flow["authReqId"].as_str().unwrap(),
                    flow.get("clientNotificationToken").and_then(Value::as_str),
                );
                same(want, got.map(Value::String))
            }
            "lifecycle" => same(want, Ok(lifecycle(args[0].as_str().unwrap(), args[1].as_array().unwrap()))),
            f => Err(format!("unknown fn {f}")),
        };
        ran += 1;
        if let Err(e) = r {
            fails.push(format!("{name}: {e}"));
        }
    }
    assert!(skipped * 10 < ran, "too many skipped: {skipped} of {ran}");
    assert!(fails.is_empty(), "{} of {ran} cases differ:\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn the_random_auth_req_id_is_canonical_and_fresh() {
    let b = create_ciba_broker(Box::new(|| 0.0), None);
    let a = b.start(&step_up(), &Value::Null).unwrap();
    let mut su = step_up();
    su["id"] = json!("su2");
    let c = b.start(&su, &Value::Null).unwrap();
    let (x, y) = (a["auth_req_id"].as_str().unwrap(), c["auth_req_id"].as_str().unwrap());
    assert_eq!(x.len(), 27);
    assert_ne!(x, y);
}
