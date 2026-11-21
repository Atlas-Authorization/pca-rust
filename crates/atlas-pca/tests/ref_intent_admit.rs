//! Differential replay of the session-store half of the intent history against the TypeScript reference (the `accContextFor` and
//! `admit` cases of test-data/ref-intent-misc2.json.gz), and a party's local Policy-VM evaluation over the decide corpus.
mod common;
use atlas_pca::intent_admit::*;
use atlas_pca::policy_vm::{decide, evaluate_party};
use atlas_pca::serde_json::{json, Value};

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

/// One scripted store sequence: `["store", {durable}]`, `["admit", {...}]`, `["settle", session, id, status]`, `["events", session]`.
fn admit_script(ops: &[Value]) -> Value {
    let mut store = MemoryIntentSessionStore::claiming_durable();
    let mut out: Vec<Value> = Vec::new();
    for op in ops {
        match text(&op[0]) {
            "store" => {
                // an absent flag and `false` are both "not durable"
                store = if op[1]["durable"] == json!(true) { MemoryIntentSessionStore::claiming_durable() } else { MemoryIntentSessionStore::new() };
                out.push(Value::Null);
            }
            "admit" => {
                let a = &op[1];
                let mut seen: Option<Value> = None;
                let r = admit_intent_action(
                    &store,
                    text(&a["session"]),
                    &a["root"],
                    a.get("schema").filter(|s| !s.is_null()),
                    &a["event"],
                    &mut |acc: &Value| {
                        if a["verifyAs"] == json!("throws") {
                            return Err("verify boom".to_string());
                        }
                        seen = Some(acc.clone());
                        Ok(json!({"allow": a["verifyAs"]["allow"]}))
                    },
                    a.get("requireDurable").and_then(Value::as_bool),
                );
                if let Some(acc) = seen {
                    out.push(json!({"acc": acc}));
                }
                out.push(match r {
                    Ok(v) => json!({"allow": v["allow"]}),
                    Err(_) => json!({"$err": true}),
                });
            }
            "settle" => out.push(settle_intent_event(&store, text(&op[1]), text(&op[2]), text(&op[3])).map_or(json!({"$err": true}), Value::Bool)),
            "events" => out.push(Value::Array(store.events_of(text(&op[1])))),
            _ => out.push(json!({"$err": "op"})),
        }
    }
    Value::Array(out)
}

#[test]
fn the_session_store_half_matches_the_reference() {
    let (mut ctx, mut admit, mut bad) = (0usize, 0usize, Vec::new());
    for c in common::ref_cases("intent-misc2") {
        let a = c["args"].as_array().cloned().unwrap_or_default();
        let got = match text(&c["fn"]) {
            "accContextFor" => {
                ctx += 1;
                let history = a[1].as_array().cloned().unwrap_or_default();
                acc_context_for(&a[0], &history, &a[2], a.get(3).filter(|s| !s.is_null())).unwrap_or_else(|e| json!({"$throws": e}))
            }
            "admit" => {
                admit += 1;
                admit_script(a[0].as_array().map(Vec::as_slice).unwrap_or(&[]))
            }
            _ => continue,
        };
        if atlas_pca::canonicalize(&c["out"]) != atlas_pca::canonicalize(&got) {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert_eq!((ctx, admit), (13, 11), "cases replayed");
    assert!(bad.is_empty(), "{} cases differ:\n{}", bad.len(), bad.join("\n"));
}

#[test]
fn a_volatile_store_is_refused_unless_the_caller_accepts_it() {
    let store = MemoryIntentSessionStore::new();
    let root = json!({"accumulators": [], "monitors": []});
    let event = json!({"id": "e1", "verb": "pay", "resource": "r", "params": {}, "t": 1});
    let mut allow = |_: &Value| Ok::<Value, String>(json!({"allow": true}));
    assert!(admit_intent_action(&store, "s", &root, None, &event, &mut allow, None).is_err());
    assert!(store.events_of("s").is_empty());
    assert_eq!(admit_intent_action(&store, "s", &root, None, &event, &mut allow, Some(false)).unwrap()["allow"], json!(true));
    assert_eq!(store.events_of("s")[0]["status"], json!("reserved"));
    assert!(settle_intent_event(&store, "s", "e1", "pending").is_err(), "only committed, released or reverted settle an event");
}

#[test]
fn a_party_vector_is_the_local_decision() {
    let cases = common::ref_cases("decide-java");
    assert!(!cases.is_empty());
    for c in &cases {
        let d = decide(&c["args"][0]);
        let v = evaluate_party(&c["args"][0], None);
        let r = d["r"].as_f64().unwrap();
        assert_eq!((v.allow == 1, v.t), (d["releaseGuardianShare"] == json!(true), d["requiredThreshold"]["t"].as_i64().unwrap()), "{}", c["name"]);
        assert_eq!(v.r_quant, atlas_pca::mpc::quantize_r(r, atlas_pca::mpc::DEFAULT_Q), "{}", c["name"]);
        assert!((0..=100).contains(&v.r_quant));
    }
    // a party that cannot decide contributes the worst case
    let worst = evaluate_party(&json!({}), Some(10));
    assert_eq!((worst.allow, worst.t, worst.r_quant), (0, 3, 10));
}
