//! Rule 14 (signed action schemas, closed-world conformance) differential kill tests against the TypeScript reference:
//! tests/data/k042-actionschema.json is written by tools/pca-audit/java-mutate/k042-actionschema-oracle.mts
//! (actionSchemaShapeError / verifyActionSchema / paramValueViolation / conformAction / accumulationParams / canonProjection
//! on targeted inputs at the exact boundary of every rule); the Java suite runs the same file. Every input is raw JSON text.
//! A case serde_json cannot hold (a lone surrogate, 1e400) is skipped.
use super::*;
use crate::k042_support::{has_lone, parse, read};

fn cases(kind: &str) -> Vec<Value> {
    parse(&read("k042-actionschema.json")).expect("corpus")[kind].as_array().expect(kind).clone()
}

/// A raw JSON input as the verifier sees it (None: not representable).
fn j(raw: &Value) -> Option<Value> {
    parse(raw.as_str().expect("raw json text")).filter(|v| !has_lone(v))
}

fn report(kind: &str, bad: Vec<String>, n: usize) {
    assert!(n > 0, "no {kind} cases ran");
    assert!(bad.is_empty(), "{}/{n} {kind} mismatches:\n{}", bad.len(), bad.iter().take(400).cloned().collect::<Vec<_>>().join("\n"));
}

fn ostr(v: &Value) -> Option<String> {
    v.as_str().map(String::from)
}

#[test]
fn shape() {
    let (mut bad, mut n) = (Vec::new(), 0);
    for c in cases("shape") {
        let Some(doc) = j(&c["doc"]) else { continue };
        n += 1;
        let (want, got) = (ostr(&c["expect"]), action_schema_shape_error(&doc));
        if want != got {
            bad.push(format!("{}: want {want:?} got {got:?}", c["name"]));
        }
    }
    report("shape", bad, n);
}

#[test]
fn param_value_violation_cases() {
    let (mut bad, mut n) = (Vec::new(), 0);
    for c in cases("pvv") {
        let (Some(d), Some(x)) = (j(&c["d"]), j(&c["x"])) else { continue };
        n += 1;
        let want = if c["expect"].is_null() { None } else { Some(format!("{}|{}", c["expect"]["code"].as_str().unwrap(), c["expect"]["reason"].as_str().unwrap())) };
        let got = param_value_violation(d.as_object().unwrap(), &x).map(|(code, r)| format!("{code}|{r}"));
        if want != got {
            bad.push(format!("{}: want {want:?} got {got:?}", c["name"]));
        }
    }
    report("pvv", bad, n);
}

#[test]
fn conform() {
    let (mut bad, mut n) = (Vec::new(), 0);
    for c in cases("conform") {
        let (Some(doc), Some(params)) = (j(&c["doc"]), j(&c["params"])) else { continue };
        n += 1;
        let e = &c["expect"];
        let want = if e["ok"] == Value::Bool(true) { "ok|null|null|".to_string() } else { format!("false|{}|{}|{}", e["code"].as_str().unwrap(), e["path"].as_str().map_or("null".to_string(), String::from), e["reason"].as_str().unwrap()) };
        let r = conform_action(&doc, c["verb"].as_str().unwrap(), &params);
        let got = format!("{}|{}|{}|{}", if r.ok { "ok" } else { "false" }, r.code.as_deref().unwrap_or("null"), r.path.as_deref().unwrap_or("null"), r.reason);
        if want != got {
            bad.push(format!("{}: want <{want}> got <{got}>", c["name"]));
        }
    }
    report("conform", bad, n);
}

#[test]
fn verify() {
    let (mut bad, mut n) = (Vec::new(), 0);
    for c in cases("verify") {
        let (Some(doc), Some(keys)) = (j(&c["doc"]), j(&c["keys"])) else { continue };
        n += 1;
        let (want, got) = (ostr(&c["expect"]), verify_action_schema(&doc, &keys).err());
        if want != got {
            bad.push(format!("{}: want {want:?} got {got:?}", c["name"]));
        }
    }
    report("verify", bad, n);
}

#[test]
fn accumulation_params_cases() {
    let (mut bad, mut n) = (Vec::new(), 0);
    for c in cases("acc") {
        let Some(v) = j(&c["v"]) else { continue };
        n += 1;
        let want = Value::Array(c["expect"].as_array().unwrap().clone());
        let got = match accumulation_params(v.as_object().unwrap(), c["unit"].as_str().unwrap()) {
            Ok(l) => Value::Array(l.into_iter().map(Value::String).collect()),
            Err(e) => Value::String(format!("threw {e}")),
        };
        if want != got {
            bad.push(format!("{}: want {want} got {got}", c["name"]));
        }
    }
    report("acc", bad, n);
}

#[test]
fn canon_projection_cases() {
    let (mut bad, mut n) = (Vec::new(), 0);
    for c in cases("canon") {
        let (Some(doc), Some(params)) = (j(&c["doc"]), j(&c["params"])) else { continue };
        n += 1;
        let e = &c["expect"];
        let want = if e["ok"] == Value::Bool(true) { e["out"].clone() } else { Value::String("threw".into()) };
        let got = match canon_projection(&doc, c["verb"].as_str().unwrap(), params.as_object().unwrap()) {
            Ok(m) => Value::Object(m),
            Err(_) => Value::String("threw".into()),
        };
        if want != got {
            bad.push(format!("{}: want {want} got {got}", c["name"]));
        }
    }
    report("canon", bad, n);
}

#[test]
fn null_entries_throw_like_the_reference() {
    let doc = serde_json::json!({"verbs": [null, {"verb": "v", "params": {}}]});
    assert_eq!(schema_verb(&doc, "v"), Err("verb entry is null".to_string()));
    let doc = serde_json::json!({"verbs": [1, "x", {"verb": "v", "params": {}}]});
    assert!(schema_verb(&doc, "v").unwrap().is_some());
    assert_eq!(schema_verb(&doc, "w"), Ok(None));
    let v = serde_json::json!({"params": {"action.params.a": null}});
    assert_eq!(accumulation_params(v.as_object().unwrap(), "u"), Err("parameter declaration is null".to_string()));
    let v = serde_json::json!({"params": {"action.params.a": 5, "action.params.b": {"type": "integer", "accumulates_into": ["u"]}}});
    assert_eq!(accumulation_params(v.as_object().unwrap(), "u"), Ok(vec!["action.params.b".to_string()]));
}

#[test]
fn calendar_dates() {
    for ok in ["2024-02-29", "2023-01-31", "0001-01-01", "2000-02-29", "9999-12-31"] {
        assert!(is_calendar_date(ok), "{ok}");
    }
    for bad in ["2023-02-29", "1900-02-29", "2024-13-01", "2024-00-10", "2024-01-00", "2024-04-31", "0000-01-01", "2024/01/01", "2024-01/01", "2024/01-01", "2024-1-01", "2024-01-011", "2024-01-1", "", "2024", "abcd-ef-gh", "2024-0a-01", "2024-01-0a"] {
        assert!(!is_calendar_date(bad), "{bad}");
    }
}
