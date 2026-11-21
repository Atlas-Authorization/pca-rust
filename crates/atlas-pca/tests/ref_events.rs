//! Differential replay of step-up events and signed webhooks against the TypeScript reference (test-data/ref-events.json.gz).
mod common;
use atlas_pca::events::*;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::MemoryStateStore;

/// A secret arg: a string (its UTF-8 bytes) or `{$bytes}`; anything else is no usable key (empty, so refused as too short).
fn sec(v: &Value) -> Vec<u8> {
    match (v.get("$bytes").and_then(Value::as_str), v.as_str()) {
        (Some(b), _) => common::b64d(b),
        (_, Some(t)) => t.as_bytes().to_vec(),
        _ => Vec::new(),
    }
}

/// A replay store that always errors, and one that always says "already seen".
struct Fixed(Result<bool, ()>);

impl atlas_pca::StateStore for Fixed {
    fn claim(&self, _: &str, _: u64) -> Result<atlas_pca::ClaimResult, atlas_pca::StoreError> {
        unimplemented!("only consume_once is used")
    }
    fn last(&self, _: &str) -> Option<Option<u64>> {
        None
    }
    fn consume_once(&self, _: &str, _: i64, _: i64) -> Result<bool, atlas_pca::StoreError> {
        self.0.map_err(|_| atlas_pca::StoreError("down".into()))
    }
}

fn same(want: &Value, got: Result<Value, String>) -> bool {
    match (want.get("$throws").and_then(Value::as_str), got) {
        // the reference's own messages are exact; a JavaScript SyntaxError only requires a refusal
        (Some(m), Err(_)) if common::engine_crash(m) => true,
        (Some(m), Err(e)) => !(m.starts_with("parseEvent:") || m.starts_with("signWebhook:")) || m == e,
        (None, Ok(v)) => atlas_pca::canonicalize(want) == atlas_pca::canonicalize(&v),
        _ => false,
    }
}

#[test]
fn events_vectors() {
    let cases = common::ref_cases("events");
    let mut bad = Vec::new();
    for c in &cases {
        // a lone surrogate cannot be a Rust string
        if common::has_lone(&c["args"]) {
            continue;
        }
        let a = c["args"].as_array().unwrap();
        let o = |i: usize, k: &str| a.get(i).and_then(|x| x.get(k)).and_then(Value::as_f64);
        let got: Result<Value, String> = match c["fn"].as_str().unwrap() {
            "buildStepUpEvent" => Ok(build_step_up_event_value(&a[0], &a[1])),
            // the reference stringifies whatever it is given (a bare event, or any JSON value)
            "serializeEvent" => Ok(json!(serialize_event(&a[0]))),
            "parseEvent" => match a[0].as_str() {
                Some(t) => parse_event(t),
                None => Err("parseEvent: not a string".into()), // the reference throws on a non-string
            },
            "signWebhook" => sign_webhook(&sec(&a[0]), a[1].as_str().unwrap_or(""), o(2, "timestamp")).map(Value::String),
            "verifyWebhook" => Ok(json!(verify_webhook(&sec(&a[0]), a[1].as_str().unwrap_or(""), a[2].as_str().unwrap_or(""), o(3, "toleranceSec"), o(3, "now")))),
            "replayKey" => {
                let parts: Vec<&str> = a[1..].iter().map(|x| x.as_str().unwrap()).collect();
                Ok(json!(replay_key(a[0].as_str().unwrap(), &parts)))
            }
            "minSecretBytes" => Ok(json!(MIN_SECRET_BYTES)),
            "webhookHeaders" => webhook_headers(&sec(&a[0]), a[1].as_str().unwrap_or(""), o(2, "timestamp")),
            "deliveryScenario" => {
                let sc = &a[0];
                let ds = sc["deliveries"].as_array().unwrap();
                let mem = MemoryStateStore::new();
                let fixed = match sc.get("store").and_then(Value::as_str) {
                    Some("throws") => Some(Fixed(Err(()))),
                    Some("refuses") => Some(Fixed(Ok(false))),
                    _ => None,
                };
                let secret0 = sec(&a[0].get("secret").cloned().unwrap_or(json!("whsec_0123456789abcdef0123456789")));
                Ok(Value::Array(
                    ds.iter()
                        .map(|st| {
                            let op = st.get("opts").filter(|o| o.is_object());
                            // no replay store (none given, or an explicit null) cannot be expressed in the typed API, which requires
                            // one: the reference refuses that before anything else
                            if sc.get("noReplay").is_some() || sc.get("noOpts").is_some() || op.is_none_or(|o| o.get("replay").is_some_and(Value::is_null)) {
                                return json!({"ok": false, "reason": "a replay store is required"});
                            }
                            let op = op.unwrap();
                            let secret = st.get("secret").map_or_else(|| secret0.clone(), sec);
                            let store: &dyn atlas_pca::StateStore = match &fixed {
                                Some(f) => f,
                                None => &mem,
                            };
                            verify_delivery(&secret, st["payload"].as_str().unwrap_or(""), st["header"].as_str().unwrap_or(""), store, op.get("toleranceSec").and_then(Value::as_f64), op.get("now").and_then(Value::as_f64))
                        })
                        .collect(),
                ))
            }
            f => panic!("unknown fn {f}"),
        };
        let shown = format!("{got:?}");
        if !same(&c["out"], got) {
            bad.push(format!("{}\n  want {}\n  got  {shown}", c["name"], c["out"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
