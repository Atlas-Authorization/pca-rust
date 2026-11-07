//! k05 differential oracle for the forbid-wins certificate and linked policy templates: tests/data/k05-policyauthoring.json.gz,
//! written by the TypeScript reference (tools/pca-audit/k05-oracles/policyauthoring-oracle.mts; the Java suite replays the same
//! file): template definitions, slot objects, references and overlays (every member deleted / retyped / at its limit, re-signed),
//! slot grids, registries with overlays and bound parameter objects, and random certificate tables with every single-field
//! corruption. Exact reasons and exact policies; a reference refusal ending in "(fail closed)" (the reference threw on malformed
//! input) only requires a refusal; a certificate whose table is not well typed only requires a rejection.
use super::*;
use crate::k042_support::{k05_run, K05};
use serde_json::json;

const FAIL_CLOSED: &str = "(fail closed)";

fn strs(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

/// A reason (or None) against a reference reason string / null / `{ok, reason?}` output.
fn verified(want: &Value, got: Result<(), String>) -> K05 {
    let w = want.get("reason").and_then(Value::as_str).or_else(|| want.as_str());
    match (w, got) {
        (Some(w), Err(_)) if w.ends_with(FAIL_CLOSED) => K05::Match(true),
        (w, got) => K05::Match(w == got.err().as_deref()),
    }
}

/// A policy (and its overlay count) or a reason against `{ok:true, policy[, overlays]}` / `{ok:false, reason}`.
fn resolved(want: &Value, got: Result<Value, String>) -> K05 {
    match got {
        Ok(v) => K05::Val(v),
        Err(_) if want["reason"].as_str().is_some_and(|w| w.ends_with(FAIL_CLOSED)) => K05::Match(true),
        Err(r) => K05::Val(json!({"ok": false, "reason": r})),
    }
}

#[test]
fn k05_policyauthoring_matches_the_reference() {
    k05_run("policyauthoring", 16900, |c, f, a| {
        let want = &c["out"];
        match f {
            "templateDef" => K05::Val(json!(template_def_error(&a[0]))),
            "tighten" => K05::Val(json!(tighten_overlay_error(&a[0]))),
            "templateRef" => K05::Val(json!(template_ref_error(&a[0]))),
            "verifyTemplate" => verified(want, verify_template(&a[0], &strs(&a[1]))),
            "verifyTighten" => verified(want, verify_tighten(&a[0], &strs(&a[1]))),
            "instantiate" => resolved(want, instantiate_template(&a[0], &a[1]).map(|p| json!({"ok": true, "policy": p}))),
            "resolve" => resolved(want, resolve_link(&a[0], &a[1]).map(|(p, n)| json!({"ok": true, "policy": p, "overlays": n}))),
            "forbid" => {
                // an ill-typed table must be rejected even where the reference's loose compare passes
                let ok = want["ok"].as_bool() == Some(true) && want["typed"].as_bool() == Some(true);
                K05::Match(forbid_certificate_consistent(&a[0], &strs(&a[1])) == ok)
            }
            _ => K05::Skip("fn not in this module"),
        }
    });
}

#[test]
fn template_header_version_length_and_name_charset() {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/policy-link-vectors.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let def = doc["template"]["def"].clone();
    assert_eq!(template_def_error(&def), None);
    let with = |k: &str, v: Value| {
        let mut d = def.clone();
        d[k] = v;
        template_def_error(&d)
    };
    let header = Some("template v / kind mismatch".to_string());
    assert_eq!(with("v", json!(2)), header);
    assert_eq!(with("kind", json!("pca-policy")), header);
    let version = Some("template version must be a string of 1..64 characters".to_string());
    assert_eq!(with("version", json!("v".repeat(64))), None);
    assert_eq!(with("version", json!("v".repeat(65))), version);
    assert_eq!(with("version", json!("\u{e9}".repeat(64))), None, "64 UTF-16 units, 128 bytes");
    assert_eq!(with("version", json!("")), version);
    for bad in ["aB", "a-b", "1a", "_a"] {
        assert!(!name_ok(bad), "{bad}");
    }
    assert!(name_ok("a_1") && name_ok(&"a".repeat(64)) && !name_ok(&"a".repeat(65)));
}
