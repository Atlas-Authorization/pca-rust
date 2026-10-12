//! R5-ZK-01..04 regressions (red-team round 5, area (c)): the guest fails closed on malformed `tool_schema` bounds, counts
//! UTF-16 code units, charges the document regex budget for `matches`, and enforces the strict wire limits in-circuit
//! (strict canonical numbers, depth 32, 512 KiB blobs, 256/1024 caveat caps).
//! Goldens: fixtures/ts_wire_cases.json (tests/gen_ts_wire_cases.ts) and fixtures/ts_tool_schema_cases.json.
use pca_zkvm_core::caveats::{evaluate_caveat, CaveatCtx};
use pca_zkvm_core::canonical::{canonicalize, strict_violation};
use pca_zkvm_core::predicates::{evaluate_predicates, Ctx};
use pca_zkvm_core::{caveat_limit_exceeded, decide, decide_from_str, wire_limits_ok, DecideInput};
use serde_json::{json, Value};

#[path = "support/chain_mint.rs"]
mod mint;

/// `PCA_WIRE_CASES=<file>` replaces the committed golden (the large random run on a cloud box).
fn golden() -> Value {
    match std::env::var("PCA_WIRE_CASES") {
        Ok(p) => serde_json::from_str(&std::fs::read_to_string(p).expect("PCA_WIRE_CASES readable")).unwrap(),
        Err(_) => serde_json::from_str(include_str!("../../fixtures/ts_wire_cases.json")).unwrap(),
    }
}
fn base() -> Value {
    serde_json::from_str(include_str!("../../fixtures/decide_input.sample.json")).unwrap()
}
fn allow(v: &Value) -> u8 {
    decide_from_str(&v.to_string()).allow
}

// ---- constants mirror the TS reference ---------------------------------------------------------------------------------

#[test]
fn wire_constants_equal_the_ts_constants() {
    let c = &golden()["constants"];
    assert_eq!(c["MAX_CAVEATS_PER_HOP"].as_u64().unwrap() as usize, pca_zkvm_core::MAX_CAVEATS_PER_HOP);
    assert_eq!(c["MAX_CAVEATS_PER_CHAIN"].as_u64().unwrap() as usize, pca_zkvm_core::MAX_CAVEATS_PER_CHAIN);
    assert_eq!(c["MAX_ARTIFACT_BYTES"].as_u64().unwrap() as usize, pca_zkvm_core::MAX_ARTIFACT_BYTES);
    assert_eq!(c["MAX_JSON_DEPTH"].as_u64().unwrap() as usize, pca_zkvm_core::canonical::MAX_JSON_DEPTH);
    assert_eq!(c["MAX_DECIMAL_DIGITS"].as_u64().unwrap() as usize, pca_zkvm_core::canonical::MAX_DECIMAL_DIGITS);
    assert_eq!(c["MAX_REGEX_EVALUATIONS_PER_DOCUMENT"].as_u64().unwrap(), pca_zkvm_core::safe_regex::MAX_REGEX_EVALUATIONS_PER_DOCUMENT);
    assert_eq!(c["MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT"].as_u64().unwrap(), pca_zkvm_core::safe_regex::MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT);
    assert_eq!(c["MAX_REGEX_STEPS_PER_DOCUMENT"].as_u64().unwrap(), pca_zkvm_core::safe_regex::MAX_REGEX_STEPS_PER_DOCUMENT);
}

// ---- R5-ZK-03: strict canonical profile, differential against `canonicalizeStrict` --------------------------------------

#[test]
fn strict_profile_agrees_with_canonicalize_strict_on_every_golden_value() {
    let g = golden();
    let mut bad = Vec::new();
    let (mut ok_n, mut no_n) = (0, 0);
    for c in g["canon"].as_array().unwrap() {
        let text = c["text"].as_str().unwrap();
        let want_ok = c["ok"].as_bool().unwrap();
        if want_ok { ok_n += 1 } else { no_n += 1 }
        let (got_ok, got_canon) = match serde_json::from_str::<Value>(text) {
            Err(_) => (false, None),
            Ok(v) => match strict_violation(&v) {
                Some(_) => (false, None),
                None => (true, Some(canonicalize(&v))),
            },
        };
        if got_ok != want_ok || (want_ok && got_canon.as_deref() != c["canon"].as_str()) {
            bad.push(format!("{text}: TS ok={want_ok} canon={} guest ok={got_ok} canon={got_canon:?}", c["canon"]));
        }
    }
    eprintln!("r5 strict profile: values={} accepted={ok_n} refused={no_n} divergences={}", ok_n + no_n, bad.len());
    assert!(ok_n > 500 && no_n > 500);
    assert!(bad.is_empty(), "{} divergences, first 15:\n{}", bad.len(), bad.iter().take(15).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn named_strict_profile_refusals() {
    for (text, why) in [
        ("9007199254740993", "unsafe integer"), ("-9007199254740992", "unsafe integer"), ("18446744073709551615", "u64 max"),
        ("1e300", "integer-valued float above 2^53"), ("-0", "negative zero"), ("-0.0", "negative zero"), ("0.0000001", "below 1e-6"),
        ("0.1234567890123456", "16 significant digits"), ("0.30000000000000004", "17 significant digits"),
    ] {
        let v: Value = serde_json::from_str(text).unwrap();
        assert!(strict_violation(&v).is_some(), "{text} ({why}) must be outside the strict profile");
    }
    for text in ["9007199254740991", "-9007199254740991", "0", "1.0", "0.000001", "0.123456789012345", "123456789.123456", "1e2"] {
        let v: Value = serde_json::from_str(text).unwrap();
        assert!(strict_violation(&v).is_none(), "{text} is admissible");
    }
    let nest = |n: usize| (0..n).fold(json!(1), |x, _| json!([x]));
    assert!(strict_violation(&nest(32)).is_none());
    assert!(strict_violation(&nest(33)).is_some());
}

#[test]
fn caveat_caps_256_per_hop_1024_per_chain() {
    let hop = |n: usize| json!({ "caveats": vec![json!({"type": "expires", "at": 1}); n] });
    assert!(!caveat_limit_exceeded(&[hop(256)]));
    assert!(caveat_limit_exceeded(&[hop(257)]));
    assert!(!caveat_limit_exceeded(&[hop(256), hop(256), hop(256), hop(256)]), "1024 total");
    assert!(caveat_limit_exceeded(&[hop(256), hop(256), hop(256), hop(256), hop(1)]), "1025 total");
    assert!(!caveat_limit_exceeded(&[json!({}), json!({"caveats": 5})]), "non-array caveats count as 0, like the TS");
}

#[test]
fn blob_size_cap_is_512_kib_of_compact_json() {
    // the signed PCActn (a wire document)
    let mut input: DecideInput = serde_json::from_value(base()).unwrap();
    let mut pc = input.pcactn.clone().unwrap();
    pc["pad"] = json!("");
    let n0 = pca_zkvm_core::canonical::json_len(&pc);
    pc["pad"] = json!("x".repeat(524_288 - n0));
    input.pcactn = Some(pc.clone());
    assert_eq!(pca_zkvm_core::canonical::json_len(input.pcactn.as_ref().unwrap()), 524_288);
    assert!(wire_limits_ok(&input), "exactly 524288 bytes is admitted");
    pc["pad"] = json!("x".repeat(524_288 - n0 + 1));
    input.pcactn = Some(pc);
    assert!(!wire_limits_ok(&input), "524289 bytes is refused");
    assert_eq!(decide(&input).allow, 0);
    // R6-ZK-04: `env` / `subject` are the resource server's own context, not wire documents: no cap (the TS has none)
    let mut input: DecideInput = serde_json::from_value(base()).unwrap();
    input.env = Some(json!({ "pad": "x".repeat(600_000), "f": 1e-7, "n": 9007199254740993u64 }));
    input.subject = Some(json!({ "role": "reader", "z": -0.0 }));
    assert!(wire_limits_ok(&input));
    // the plan and the action are capped too
    let mut input: DecideInput = serde_json::from_value(base()).unwrap();
    input.action = json!({ "verb": "read", "resource": "x".repeat(524_300) });
    assert!(!wire_limits_ok(&input));
    let mut input: DecideInput = serde_json::from_value(base()).unwrap();
    input.plan = vec![json!({ "id": "n0", "pad": "x".repeat(524_300) })];
    assert!(!wire_limits_ok(&input));
}

// ---- decide-level: the committed fixture is allowed; each r5 variant is refused; each control is allowed -------------------

#[test]
fn r5_variants_are_refused_and_controls_are_allowed() {
    let b = base();
    assert_eq!(allow(&b), 1, "control: the committed input");
    for (name, v) in mint::r5_controls(&b) {
        assert_eq!(allow(&v), 1, "control {name} must be allowed");
    }
    for (name, v, _g) in mint::r5_variants(&b) {
        assert_eq!(allow(&v), 0, "{name} must be refused");
    }
    for (name, v) in mint::r6_controls(&b) {
        assert_eq!(allow(&v), 1, "r6 control {name} must be allowed");
    }
    for (name, v, _g) in mint::r6_variants(&b) {
        assert_eq!(allow(&v), 0, "{name} must be refused");
    }
}

// ---- R5-ZK-01/02: tool_schema -----------------------------------------------------------------------------------------

fn ts_verdict(schema: Value, args: Value) -> bool {
    let b = base();
    let cv = mint::tool_schema_caveat(&b, schema);
    let root = json!({ "action": { "verb": "read", "resource": "x", "params": args.clone() } });
    let ctx = CaveatCtx {
        now: 1.0e12, blast_radius: None, reversibility_class: None, delegation_depth: None, recent_action_times: None,
        action_root: &root, tool: Some("read".to_string()), tool_args: Some(args), tool_signature_digest: None,
    };
    evaluate_caveat(&cv, &ctx)
}

#[test]
fn malformed_scalar_bounds_deny_never_default() {
    let args = json!({ "s": "abc" });
    let ok = |extra: Value| {
        let mut spec = json!({ "type": "string" });
        for (k, v) in extra.as_object().unwrap() {
            spec[k] = v.clone();
        }
        ts_verdict(json!({ "props": { "s": spec } }), args.clone())
    };
    assert!(ok(json!({})), "control");
    assert!(ok(json!({ "maxLength": 3, "minLength": 3, "prefix": "ab" })), "well-formed bounds");
    for bad in [
        json!({ "maxLength": "3" }), json!({ "maxLength": -1 }), json!({ "maxLength": 3.5 }), json!({ "maxLength": null }), json!({ "maxLength": 1048577 }),
        json!({ "maxLength": true }), json!({ "minLength": "1" }), json!({ "minLength": 0.5 }), json!({ "minLength": null }), json!({ "minLength": 5, "maxLength": 2 }),
        json!({ "prefix": 5 }), json!({ "prefix": null }), json!({ "prefix": "x".repeat(513) }),
    ] {
        assert!(!ok(bad.clone()), "{bad} must deny");
    }
    let num = |extra: Value| {
        let mut spec = json!({ "type": "number" });
        for (k, v) in extra.as_object().unwrap() {
            spec[k] = v.clone();
        }
        ts_verdict(json!({ "props": { "n": spec } }), json!({ "n": 5 }))
    };
    assert!(num(json!({ "min": 1, "max": 10 })));
    for bad in [json!({ "max": "10" }), json!({ "min": "1" }), json!({ "max": null }), json!({ "min": null }), json!({ "min": true }), json!({ "min": 9, "max": 1 })] {
        assert!(!num(bad.clone()), "{bad} must deny");
    }
    let arr = |extra: Value| {
        let mut spec = json!({ "type": "array", "items": { "type": "number" } });
        for (k, v) in extra.as_object().unwrap() {
            spec[k] = v.clone();
        }
        ts_verdict(json!({ "props": { "a": spec } }), json!({ "a": [1, 2] }))
    };
    assert!(arr(json!({ "minItems": 1, "maxItems": 4 })));
    for bad in [json!({ "maxItems": "4" }), json!({ "maxItems": 1.5 }), json!({ "maxItems": null }), json!({ "minItems": "1" }), json!({ "minItems": 3, "maxItems": 2 }), json!({ "maxItems": 4097 })] {
        assert!(!arr(bad.clone()), "{bad} must deny");
    }
}

#[test]
fn string_lengths_count_utf16_code_units() {
    let t = |ml: Value, s: &str| ts_verdict(json!({ "props": { "s": { "type": "string", "maxLength": ml } } }), json!({ "s": s }));
    // R5-ZK-02: one astral character is TWO code units, so maxLength 1 refuses it
    assert!(!t(json!(1), "😀"));
    assert!(t(json!(2), "😀"));
    assert!(!t(json!(3), "😀😀"));
    assert!(t(json!(4), "😀😀"));
    assert!(t(json!(1), "é"));
    let min = |ml: u32, s: &str| ts_verdict(json!({ "props": { "s": { "type": "string", "minLength": ml } } }), json!({ "s": s }));
    assert!(min(2, "😀"), "2 code units satisfy minLength 2");
    assert!(!min(3, "😀"));
    // enum / const strings are capped at 1024 UTF-16 units: 513 astral chars = 1026 units
    assert!(!ts_verdict(json!({ "props": { "s": { "type": "string", "const": "😀".repeat(513) } } }), json!({ "s": "😀".repeat(513) })));
    assert!(ts_verdict(json!({ "props": { "s": { "type": "string", "const": "😀".repeat(512) } } }), json!({ "s": "😀".repeat(512) })));
}

#[test]
fn numeric_equality_is_javascript_equality() {
    // 1 === 1.0 and an integer schema accepts 2.0 (Number.isInteger); the fixture text can only carry what JSON.parse yields
    assert!(ts_verdict(json!({ "props": { "n": { "type": "integer", "const": 2 } } }), serde_json::from_str("{\"n\": 2.0}").unwrap()));
    assert!(ts_verdict(json!({ "props": { "n": { "type": "integer", "enum": [1, 2.0, 3] } } }), json!({ "n": 2 })));
    assert!(!ts_verdict(json!({ "props": { "n": { "type": "integer" } } }), json!({ "n": 2.5 })));
}

// ---- R5-ZK-04: `matches` is charged to the document regex budget, differential against the TS reference -------------------

#[test]
fn matches_conditions_and_budget_agree_with_the_ts_reference() {
    let g = golden();
    let mut bad = Vec::new();
    let (mut allow_n, mut deny_n) = (0, 0);
    for d in g["docs"].as_array().unwrap() {
        let root = json!({ "action": d["action"].clone() });
        let want = d["allow"].as_bool().unwrap();
        if want { allow_n += 1 } else { deny_n += 1 }
        let got = evaluate_predicates(d["predicates"].as_array().unwrap(), &Ctx::new(&root)).allowed;
        if got != want {
            bad.push(format!("{}: TS {want} guest {got}", d["id"]));
        }
    }
    eprintln!("r5 matches/budget docs: {} (allow {allow_n} deny {deny_n}) divergences={}", allow_n + deny_n, bad.len());
    assert!(allow_n > 40 && deny_n > 40);
    assert!(bad.is_empty(), "{} divergences:\n{}", bad.len(), bad.join("\n"));
}

#[test]
fn sixty_four_matches_then_a_re_resource_is_refused_like_ts() {
    let root = json!({ "action": { "verb": "read", "resource": "/acct/7", "params": { "s": "abc" } } });
    let miss = |i: usize| json!({ "verb": "*", "where": [{ "field": "action.params.s", "op": "matches", "value": format!("zz{i}[0-9]+") }] });
    let hit = json!({ "verb": "*", "resource": "re:/acct/[0-9]+" });
    let run = |n: usize| {
        let mut p: Vec<Value> = (0..n).map(miss).collect();
        p.push(hit.clone());
        evaluate_predicates(&p, &Ctx::new(&root)).allowed
    };
    assert!(run(63), "63 misses + the hit is evaluation 64");
    assert!(!run(64), "65th evaluation is refused (this ALLOWED before the fix: the guest never charged `matches`)");
}
