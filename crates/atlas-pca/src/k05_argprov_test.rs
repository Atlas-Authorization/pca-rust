//! k05 differential oracle for provenance by default: tests/data/k05-argprov.json.gz, written by the TypeScript reference
//! (tools/pca-audit/k05-oracles/argprov-oracle.mts; every native replays the same file). Typed-port notes: a decision input whose
//! `mediators` / `observed` is not a list has no Rust form (skipped); a recorder step that throws is compared as "refused" (the
//! message is the reference's own); the request reader returns a String error, so its refusals compare as refusals (the
//! reference's `invalid_pca_header` code belongs to its shared header decoder).
use super::*;
use crate::k042_support::{k05_run, k05_same, K05};
use std::sync::Mutex;

/// Every `{$throws: ...}` object inside `v` as `{$throws: true}` (the recorder records a step's throw in place).
fn thrown(v: &Value) -> Value {
    match v {
        Value::Object(m) if m.contains_key("$throws") => json!({"$throws": true}),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), thrown(x))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(thrown).collect()),
        x => x.clone(),
    }
}

fn recorder(spec: &Value) -> Result<Value, String> {
    let seed: [u8; 32] = decode_b64u_strict(spec["sk"].as_str().unwrap_or(""), Some(32)).ok_or("sk")?.try_into().map_err(|_| "sk")?;
    let clock: Vec<f64> = spec["clock"].as_array().map(|a| a.iter().filter_map(Value::as_f64).collect()).unwrap_or_default();
    let state = Mutex::new((clock, 0f64));
    let mut rec = ProvenanceRecorder::new(spec["mediator"].as_str().unwrap_or(""), spec["kid"].as_str().unwrap_or(""), Some(seed))?
        .with_session(spec["session"].as_str().unwrap_or(""))?
        .with_clock(move || {
            let mut s = state.lock().unwrap();
            if !s.0.is_empty() {
                s.1 = s.0.remove(0);
            }
            s.1.floor() as i64
        });
    let mut outs = Vec::new();
    for st in spec["steps"].as_array().cloned().unwrap_or_default() {
        let arg = |i: usize| st.get(i).cloned().unwrap_or(Value::Null);
        let text = |i: usize| arg(i).as_str().unwrap_or("").to_string();
        let r = match st[0].as_str().unwrap_or("") {
            "principal" => rec.principal(&text(1)),
            "tool" => rec.tool(&text(1), &arg(2)),
            "retrieval" => rec.retrieval(&text(1), &arg(2)),
            "web" => rec.web(&text(1), &arg(2)),
            "action" => Operation::from_json(&arg(1)).ok_or_else(|| "operation".to_string()).and_then(|op| rec.for_action(&op)),
            "direct" => Operation::from_json(&arg(1)).ok_or_else(|| "operation".to_string()).and_then(|op| principal_direct_provenance(&mut rec, &op)),
            _ => continue,
        };
        outs.push(r.unwrap_or_else(|_| json!({"$throws": true})));
    }
    Ok(json!({"pin": rec.pin(), "outs": outs}))
}

#[test]
fn k05_argprov_matches_the_reference() {
    k05_run("argprov", 8700, |case, f, a| match f {
        "provReceiptWireError" => K05::Val(json!(prov_receipt_wire_error(&a[0]))),
        "isProvMediatorPin" => K05::Val(json!(is_prov_mediator_pin(&a[0]))),
        "provActionInfoError" => K05::Val(json!(prov_action_info_error(&a[0]))),
        "isReadOnlyAction" => K05::Val(json!(is_read_only_action(a.first()))),
        "provEnvelopeError" => K05::Val(json!(prov_envelope_error(&a[0]))),
        "occursAsToken" => K05::Val(json!(occurs_as_token(a[0].as_str().unwrap_or(""), a[1].as_str().unwrap_or("")))),
        "provLeaves" => K05::Val(json!(prov_leaves(&a[0]))),
        "provActionDigest" => K05::Val(json!(prov_action_digest(&a[0]))),
        "provReceiptRef" => K05::Val(json!(prov_receipt_ref(&a[0]))),
        "decideArgProvenance" => {
            let null = Value::Null;
            let Some(i) = a[0].as_object() else {
                // a non-object input: the typed input cannot carry it; the reference refuses it as malformed_config
                return K05::Skip("non-object input (typed port)");
            };
            let empty: Vec<Value> = Vec::new();
            let list = |k: &str| match i.get(k) {
                None => Some(empty.as_slice()),
                Some(Value::Array(x)) => Some(x.as_slice()),
                Some(_) => None,
            };
            let (Some(mediators), Some(observed)) = (i.get("mediators").and_then(Value::as_array).map(Vec::as_slice), list("observed")) else {
                return K05::Skip("absent / non-list mediators or observed (typed port)");
            };
            let input = ArgProvenanceInput {
                bundle: i.get("bundle").filter(|b| !b.is_null()),
                operation: i.get("operation").unwrap_or(&null),
                mediators,
                action: i.get("action"),
                principal_plan: i.get("principalPlan").and_then(Value::as_bool).unwrap_or(false),
                principal_control: i.get("principalControl").and_then(Value::as_bool).unwrap_or(false),
                observed,
            };
            K05::Val(decide_arg_provenance(&input).to_json())
        }
        "recorder" => match recorder(&a[0]) {
            Ok(v) => K05::Match(k05_same(&thrown(&case["out"]), &v)),
            Err(_) => K05::Throw(None),
        },
        "defaultProvenanceBundle" => {
            let h = a[0].get("header").and_then(Value::as_str);
            let body = a[0].get("body").and_then(Value::as_str).map(str::as_bytes);
            match read_provenance_bundle(h, body) {
                Ok(v) => K05::Val(v.unwrap_or(Value::Null)),
                Err(_) => K05::Match(case["out"].get("$throws").is_some()),
            }
        }
        _ => K05::Skip("fn not in this module"),
    });
}

// ---- recorder, levels and caps, per arg-provenance.ts ----

fn recorder_at(text: &str) -> (ProvenanceRecorder, Value, Value) {
    let session = KeyPair::from_seed(&[9u8; 32]).public;
    let mut rec = ProvenanceRecorder::new("m", "k", Some([1u8; 32])).unwrap().with_session(&session).unwrap().with_clock(|| 5);
    rec.principal(text).unwrap();
    let op = json!({"verb": "v", "resource": "r", "params": {}});
    let bundle = rec.for_action(&Operation::from_json(&op).unwrap()).unwrap();
    (rec, bundle, op)
}

fn refusal(bundle: &Value, op: &Value, pin: Value) -> Option<&'static str> {
    verify_chain(Some(bundle), op, &[pin]).err().map(|e| e.0)
}

#[test]
fn levels_and_origins_are_the_reference_names() {
    for (name, want) in [("trusted", ProvLevel::Trusted), ("first_party", ProvLevel::FirstParty), ("tool", ProvLevel::Tool), ("web", ProvLevel::Web), ("agent", ProvLevel::Agent)] {
        assert_eq!(ProvLevel::parse(name), Some(want), "{name}");
    }
    assert_eq!(ProvLevel::parse("x"), None);
    assert_eq!(ProvLevel::of_origin("principal"), Some(ProvLevel::Trusted));
    assert_eq!(ProvLevel::of_origin("web"), Some(ProvLevel::Web));
    assert_eq!(ProvLevel::of_origin("action"), None);
}

#[test]
fn leaves_stop_past_depth_32_and_past_4096_entries() {
    let wrap = |n: usize| (0..n).fold(json!("x"), |v, _| json!([v]));
    assert!(prov_leaves(&wrap(32)).is_some());
    assert!(prov_leaves(&wrap(33)).is_none());
    // the entry check runs before each visit: an empty list after exactly 4096 strings is still visited, a string is one too many
    let list = |last: Value| {
        let mut a = vec![json!("s"); 4096];
        a.push(last);
        Value::Array(a)
    };
    assert_eq!(prov_leaves(&list(json!([]))).map(|l| l.len()), Some(4096));
    assert!(prov_leaves(&list(json!("s"))).is_none());
}

#[test]
fn an_out_of_profile_operation_fails_closed_only_when_it_is_the_recorded_verb() {
    let (rec, bundle, _) = recorder_at("hello");
    let bad = |verb: &str| json!({"verb": verb, "resource": "r", "params": {"n": -0.0}});
    assert_eq!(refusal(&bundle, &bad("v"), rec.pin()), Some("malformed_config"));
    assert_eq!(refusal(&bundle, &bad("other"), rec.pin()), Some("unbound_action"));
}

#[test]
fn principal_contents_are_capped_in_utf8_bytes_before_they_are_hashed() {
    let (rec, bundle, op) = recorder_at("hello");
    assert_eq!(refusal(&bundle, &op, rec.pin()), None);
    let with = |text: String| {
        let mut b = bundle.clone();
        b["contents"]["0"] = json!(text);
        b
    };
    assert_eq!(refusal(&with("x".repeat(65_536)), &op, rec.pin()), Some("content_mismatch"));
    assert_eq!(refusal(&with("x".repeat(65_537)), &op, rec.pin()), Some("malformed_bundle"));
    assert_eq!(refusal(&with("\u{e9}".repeat(32_769)), &op, rec.pin()), Some("malformed_bundle"));
}

#[test]
fn the_recorder_shows_its_session_and_never_its_key() {
    let session = KeyPair::from_seed(&[9u8; 32]).public;
    let (rec, _, _) = recorder_at("hello");
    assert_eq!(rec.session(), session);
    assert_eq!(format!("{rec:?}"), format!("ProvenanceRecorder {{ mediator: m, kid: k, session: {session}, receipts: 2 }}"));
    // the default clock is real epoch milliseconds
    assert!(system_now() > 1_600_000_000_000);
}
