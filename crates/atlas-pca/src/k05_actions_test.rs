//! k05 differential oracle for the action kit: tests/data/k05-actions.json.gz, written by the TypeScript reference
//! (tools/pca-audit/k05-oracles/actions-oracle.mts; every native replays the same file): validateDef and its sub-checks, id
//! patterns, the strict JSON profile, profiles, trait registries, closure / floor / floorDecision, normalize, defDigest,
//! worstReversibility, impliedFromFacts, declProfile, hintTraits, effective, reviewer pins, the signed confirmation, factsDigest,
//! schemaVerbFloorError / schemaFloorError, packRoot / packProof. A case marked `cmp: "code"` carries a message the reference
//! built from its own exception text: only its `<code>: ` prefix is compared (the generator's FIXED rule).
use super::*;
use crate::k042_support::{k05_b64, k05_run, K05};
use std::sync::LazyLock;

static CORE: LazyLock<Registry> = LazyLock::new(core_registry);

fn coded<T>(r: Result<T, ActionKitError>, f: impl Fn(T) -> Value) -> K05 {
    match r {
        Ok(v) => K05::Val(f(v)),
        Err(e) => K05::Throw(Some(e.code)),
    }
}

/// `regOf(custom)`: the core registry, or core extended with the custom trait list.
fn reg_of(custom: &Value) -> Result<Registry, ActionKitError> {
    match custom {
        Value::Null => Ok(CORE.clone()),
        Value::Array(c) => extend_registry(&CORE, c),
        _ => Err(ActionKitError { code: "bad_registry".into(), message: "custom traits must be a list".into() }),
    }
}

fn ids(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

fn pins(v: &Value) -> Option<&Value> {
    (!v.is_null()).then_some(v)
}

/// The `<code>: ` prefix of a reference message (after a leading `<verb>: ` for a schema document).
fn code_prefix(m: &str) -> &str {
    let mut end = 0;
    for (i, _) in m.match_indices(": ") {
        end = i + 2;
        if !m[..i].contains('.') {
            break;
        }
    }
    &m[..end]
}

fn text(case: &Value, got: Option<String>) -> K05 {
    if case.get("cmp").and_then(Value::as_str) == Some("code") {
        let want = case["out"].as_str().unwrap_or("");
        if got.as_deref().is_some_and(|g| g.starts_with(code_prefix(want))) {
            return K05::Match(true);
        }
    }
    K05::Val(json!(got))
}

/// schemaVerbFloorError: a verb whose facts Rust cannot read exactly is refused (`schema_floor_forged: malformed verb: ...`)
/// where the reference reads it leniently (a param that is a string, a non-string role / tag / effect as a property key, a map
/// value that is no class, floors outside the profile) and accepts it or refuses it for another reason: stricter, not compared.
fn floor_text(case: &Value, got: Option<String>) -> K05 {
    match text(case, got.clone()) {
        K05::Val(v) if got.as_deref().is_some_and(|g| g.starts_with("schema_floor_forged: malformed verb: ")) && v != case["out"] => {
            K05::Skip("Rust refuses a verb field the reference reads leniently (stricter)")
        }
        r => r,
    }
}

#[test]
fn k05_actions_matches_the_reference() {
    k05_run("actions", 60000, |case, f, a| {
        let s = |i: usize| a.get(i).and_then(Value::as_str);
        match f {
            "validateDef" => text(case, validate_def(&a[0])),
            "isRole" => K05::Val(json!(s(0).is_some_and(is_role))),
            "isFormat" => K05::Val(json!(s(0).is_some_and(is_format))),
            "isContextKey" => K05::Val(json!(s(0).is_some_and(is_context_key))),
            "paramNameError" => K05::Val(json!(param_name_error(s(0).unwrap_or("")))),
            "jsonProfileError" => K05::Val(json!(json_profile_error(&a[0], 0))),
            "idPatternError" => K05::Val(json!(id_pattern_error(Some(&a[0])))),
            "profileError" => K05::Val(json!(profile_error(&a[0]))),
            "registryError" => K05::Val(json!(registry_error_json(&a[0], a.get(1) == Some(&Value::Bool(true))))),
            "closure" => match reg_of(&a[0]) {
                Ok(r) => coded(closure(&r, &ids(&a[1])), |v| json!(v)),
                Err(e) => K05::Throw(Some(e.code)),
            },
            "floorOf" => match reg_of(&a[0]) {
                Ok(r) => coded(floor_of(&r, &ids(&a[1])), |p| p.to_value()),
                Err(e) => K05::Throw(Some(e.code)),
            },
            "topTraits" => coded(reg_of(&a[0]), |r| json!(top_traits(&r))),
            "traitsDigest" => coded(reg_of(&a[0]), |r| json!(traits_digest(&r))),
            "tablesDigest" => K05::Val(json!(tables_digest())),
            "floorDecision" => {
                let g = GrantFacts { caveats: ids(&a[0]["caveats"]), max_esc: a[0]["max_esc"].as_i64().unwrap_or(0), preauth_esc: a[0]["preauth_esc"].as_i64().unwrap_or(0) };
                match Profile::from_value(&a[2]) {
                    Some(rho) => K05::Val(json!(floor_decision(&g, &ids(&a[1]["context"]), &rho))),
                    None => K05::Skip("a malformed profile has no typed form"),
                }
            }
            "worstReversibility" => {
                let empty = Map::new();
                K05::Val(json!(worst_reversibility(&a[0], a[1].as_object().unwrap_or(&empty))))
            }
            "sensitivityFloor" => match a[0].as_object() {
                Some(p) => K05::Val(json!(param_sensitivity(p))),
                None => K05::Skip("non-object param"),
            },
            "impliedFromFacts" => {
                let f = &a[0];
                let ps: Vec<ParamFacts> = f["params"].as_array().map(|x| x.iter().map(ParamFacts::of).collect()).unwrap_or_default();
                match implied_from_facts(&ids(&f["effects"]), &ps, f.get("scope").and_then(Value::as_str), f["worstRev"].as_str().unwrap_or("")) {
                    Ok(v) => K05::Val(json!(v)),
                    Err(_) => K05::Throw(None),
                }
            }
            "normalize" => K05::Val(normalize(&a[0])),
            "defDigest" => def_digest(&a[0]).map_or(K05::Throw(None), |d| K05::Val(json!(d))),
            "declProfile" => K05::Val(decl_profile(&a[0]).to_value()),
            "hintTraits" => K05::Val(json!(hint_traits(&a[0]))),
            "effective" => coded(effective(&a[0], &CORE, pins(&a[1])), |e| {
                json!({"confirmed": e.confirmed, "traits": e.traits, "closure": e.closure, "floor": e.floor.to_value(), "decl": e.decl.to_value(), "eff": e.eff.to_value()})
            }),
            "reviewerPinsError" => K05::Val(json!(reviewer_pins_error(&a[0]))),
            "reviewMessage" => match a[0].as_object().and_then(review_message) {
                Some(m) => K05::Val(k05_b64(&m)),
                None => K05::Throw(None),
            },
            "isConfirmed" => K05::Val(json!(is_confirmed(&a[0], &CORE, pins(&a[1])))),
            "factsDigest" => facts_digest(&a[0]).map_or(K05::Throw(None), |d| K05::Val(json!(d))),
            "schemaVerbFloorError" => floor_text(case, schema_verb_floor_error(&a[0], &CORE, pins(&a[1]))),
            "schemaFloorError" => text(case, schema_floor_error(&a[0], pins(&a[1]))),
            "packRoot" => coded(pack_root(&ids(&a[0])), |r| json!(r)),
            "packProof" => coded(pack_proof(&ids(&a[0]), s(1).unwrap_or("")), |p| p),
            _ => K05::Skip("fn not in this module"),
        }
    });
}

// ---- the reference fixes of d36d91ac7, one each ----

#[test]
fn rule22_denies_a_non_integer_tier() {
    let fl = json!({"risk": 2, "rev": "irreversible", "blast_ppm": 0, "esc": 2, "caveats": ["amount_cap"], "context": ["idempotency"], "prules": []});
    let doc = json!({"verbs": [{"verb": "a.pay.create", "floors": fl}]});
    let decide = |mut g: Value| {
        g["caveats"] = json!(["amount_cap"]);
        crate::actions_registry::rule22_decide(&doc, "a.pay.create", &g, &json!(["idempotency"]))
    };
    assert_eq!(decide(json!({"max_esc": 3, "preauth_esc": 2})), "allow");
    let bad: Value = serde_json::from_str(r#"[{"preauth_esc": 2}, {"max_esc": "3", "preauth_esc": 2}, {"max_esc": 2.5, "preauth_esc": 2}, {"max_esc": 3, "preauth_esc": -1},
        {"max_esc": -0, "preauth_esc": 0}, {"max_esc": 3, "preauth_esc": true}, {"max_esc": null, "preauth_esc": 2}, {"max_esc": 9007199254740993, "preauth_esc": 2}]"#).unwrap();
    for (i, g) in bad.as_array().unwrap().iter().enumerate() {
        assert_eq!(decide(g.clone()), "deny", "tiers #{i}");
    }
    assert_eq!(floor_decision(&GrantFacts { caveats: vec![], max_esc: 3, preauth_esc: -1 }, &[], &Profile::bottom()), "deny");
}

#[test]
fn a_read_attestation_without_an_array_final_traits_is_not_confirmed() {
    let c = crate::k042_support::k05_cases("actions").into_iter().find(|c| c["name"] == "isConfirmed/read good").expect("isConfirmed/read good");
    let a = c["args"].as_array().unwrap();
    assert!(is_confirmed(&a[0], &CORE, pins(&a[1])), "control");
    for f in [None, Some(Value::Null), Some(json!(""))] {
        let mut d = a[0].clone();
        let att = d["review"]["attestation"].as_object_mut().unwrap();
        match &f {
            None => drop(att.remove("final_traits")),
            Some(v) => drop(att.insert("final_traits".into(), v.clone())),
        }
        assert!(!is_confirmed(&d, &CORE, pins(&a[1])), "final_traits {f:?}");
    }
}

#[test]
fn a_null_max_items_implies_bulk() {
    for (p, bulk) in [(json!({"type": "array"}), true), (json!({"type": "array", "max_items": null}), true), (json!({"type": "array", "max_items": 10}), false)] {
        let t = implied_from_facts(&["create".to_string()], &[ParamFacts::of(&p)], None, "reversible").unwrap();
        assert_eq!(t.iter().any(|x| x == "pca.bulk"), bulk, "{p}");
    }
}

#[test]
fn registry_list_errors_in_the_reference_order() {
    let floor = json!({"risk": 0, "esc": 0, "rev": "reversible", "blast_ppm": 0, "caveats": [], "context": [], "prules": []});
    let ok = json!({"id": "acme.ok", "implies": [], "floor": floor, "card_phrase": "c"});
    assert_eq!(registry_error_json(&json!([ok.clone()]), false), None, "the baseline trait is valid");
    // the size cap comes before any trait shape
    let many = Value::Array(vec![json!({}); MAX_REGISTRY_TRAITS + 1]);
    assert_eq!(registry_error_json(&many, false), Some(format!("a registry holds at most {MAX_REGISTRY_TRAITS} traits")));
    // a malformed trait whose id is readable: the namespace and duplicate rules win over its shape error
    let bad = |id: &str| json!({"id": id, "implies": "x"});
    assert_eq!(registry_error_json(&json!([bad("pca.x")]), false), Some("trait 'pca.x': the pca. namespace is reserved for core traits".into()));
    assert_eq!(registry_error_json(&json!([bad("pca.x")]), true), Some("trait 'pca.x': implies must be up to 8 distinct trait ids".into()));
    assert_eq!(registry_error_json(&json!([ok.clone(), bad("acme.ok")]), false), Some("trait 'acme.ok' is defined twice".into()));
    assert_eq!(registry_error_json(&json!([ok.clone(), bad("acme.other")]), false), Some("trait 'acme.other': implies must be up to 8 distinct trait ids".into()));
}

// ---- schemaVerbFloorError over an empty registry: no top traits and a bottom carried floor, so the outcome is the verb's
// worst reversibility alone (irreversible = missing implied trait; floors.rev below it = forged; else consistent) ----

const BELOW: &str = "schema_floor_forged: floors.rev is below the declared reversibility";
const NO_IRREV: &str = "schema_traits_forged: missing implied trait pca.irreversible";
const BAD_RB: &str = "schema_floor_forged: malformed verb: reversibility_by";

fn bare_verb(rev: &str, floors_rev: &str) -> Value {
    json!({"effects": ["update"], "traits": [], "reversibility": rev,
        "params": {"action.params.mode": {"type": "string", "values": ["a", "b"]}},
        "floors": {"risk": 0, "rev": floors_rev, "blast_ppm": 0, "esc": 0, "caveats": [], "context": [], "prules": []}})
}

fn floor_err(v: &Value) -> Option<String> {
    schema_verb_floor_error(v, &Registry { traits: Default::default() }, None)
}

#[test]
fn a_falsy_reversibility_by_is_absent_and_a_truthy_scalar_is_malformed() {
    let mut v = bare_verb("rate_limited", "reversible");
    assert_eq!(floor_err(&v).as_deref(), Some(BELOW), "absent");
    for rb in [Value::Null, json!(false), json!(0), json!(0.0), json!("")] {
        v["reversibility_by"] = rb.clone();
        assert_eq!(floor_err(&v).as_deref(), Some(BELOW), "falsy {rb}");
    }
    for rb in [json!(true), json!(1), json!("x")] {
        v["reversibility_by"] = rb.clone();
        assert_eq!(floor_err(&v).as_deref(), Some(BAD_RB), "truthy {rb}");
    }
}

#[test]
fn reversibility_by_map_and_default_must_be_classes() {
    let with = |map: Value, default: Option<Value>, floors_rev: &str| {
        let mut v = bare_verb("reversible", floors_rev);
        v["reversibility_by"] = json!({"param": "action.params.mode", "map": map});
        if let Some(d) = default {
            v["reversibility_by"]["default"] = d;
        }
        floor_err(&v)
    };
    let full = json!({"a": "reversible", "b": "rate_limited"});
    // the map covers the domain: worst = rate_limited, whatever a (valid or null) default says
    assert_eq!(with(full.clone(), None, "rate_limited"), None);
    assert_eq!(with(full.clone(), Some(Value::Null), "rate_limited"), None);
    assert_eq!(with(full.clone(), Some(json!("rate_limited")), "rate_limited"), None);
    assert_eq!(with(full.clone(), None, "reversible").as_deref(), Some(BELOW));
    assert_eq!(with(json!({"a": "bogus", "b": "reversible"}), None, "rate_limited").as_deref(), Some(BAD_RB), "unknown map class");
    assert_eq!(with(full, Some(json!("bogus")), "rate_limited").as_deref(), Some(BAD_RB), "unknown default class");
    // the map leaves "b" uncovered: a non-null default stands for it, a missing / null one counts as irreversible
    let part = json!({"a": "reversible"});
    assert_eq!(with(part.clone(), Some(json!("reversible")), "reversible"), None);
    assert_eq!(with(part.clone(), Some(json!("rate_limited")), "reversible").as_deref(), Some(BELOW));
    assert_eq!(with(part.clone(), None, "reversible").as_deref(), Some(NO_IRREV));
    assert_eq!(with(part, Some(Value::Null), "reversible").as_deref(), Some(NO_IRREV));
}

#[test]
fn leq_js_reads_a_string_list_as_a_substring_search() {
    let p = Profile { caveats: vec!["amount_cap".into()], ..Profile::bottom() };
    let q = |c: &str| json!({"risk": 0, "rev": "reversible", "blast_ppm": 0, "esc": 0, "caveats": c, "context": [], "prules": []});
    assert_eq!(leq_js(&p, &q("x_amount_cap_y")), Some(true));
    assert_eq!(leq_js(&p, &q("amount")), Some(false));
}

#[test]
fn a_dropped_digit_breaks_a_rounding_tie_as_js_number_does() {
    // 33 hex digits, 125 bits kept: 53 bits of even mantissa, the halfway bit, zeros, and bit 0 already set. A dropped digit must
    // leave bit 0 set (rounds up); clearing it would make an exact tie (rounds to even, down). Values from node's Number().
    let up = (2f64.powi(52) + 1.0) * 2f64.powi(76);
    let down = 2f64.powi(52) * 2f64.powi(76);
    let d = format!("1{}8{}11", "0".repeat(13), "0".repeat(16));
    assert_eq!(js_str_to_number(&format!("0x{d}")), up);
    let tie = format!("1{}8{}00", "0".repeat(13), "0".repeat(16));
    assert_eq!(js_str_to_number(&format!("0x{tie}")), down);
}

#[test]
fn js_str_to_number_is_js_number() {
    let n = |s: &str| js_str_to_number(s);
    for (s, want) in [
        ("", 0.0), ("  12  ", 12.0), ("\u{feff}7", 7.0), ("0x1F", 31.0), ("0b11", 3.0), ("0o17", 15.0), ("Infinity", f64::INFINITY),
        ("-Infinity", f64::NEG_INFINITY), ("+Infinity", f64::INFINITY), ("1e3", 1000.0), ("1.5", 1.5), (".5", 0.5), ("5.", 5.0), ("-2", -2.0),
    ] {
        assert_eq!(n(s), want, "{s:?}");
    }
    for s in ["0x", "0x+1", "0b-1", "infinity", "1_0", "12a", "--1", "1e", "inf", "NaN"] {
        assert!(n(s).is_nan(), "{s:?} -> {}", n(s));
    }
}

/// The cross-language Number() sweep table (node's `Number(x)`): a floor read from one of the NaN forms must refuse.
#[test]
fn js_str_to_number_sweep_table() {
    let n = js_str_to_number;
    for s in [
        "+-Infinity", "-+Infinity", "+0x1", "-0x1", "0x+1", "0x-1", "0x1_0", "0x 1", "0x", "0b2", "0o8", "1_000", "\u{661}", "\u{ff11}", "infinity", "INFINITY",
        "nan", "NaN", "1e", ".", "+", "1f", "1d", "1L", "inf", "\u{85}1", "1\0", "\u{85}", "\u{180e}", "\u{180e}1", "0x1p3",
    ] {
        assert!(n(s).is_nan(), "{s:?} -> {}", n(s));
    }
    for (s, want) in [
        ("", 0.0), (" \u{a0}\u{feff}", 0.0), (" 12 ", 12.0), ("\u{feff}12\u{a0}", 12.0), ("Infinity", f64::INFINITY), ("+Infinity", f64::INFINITY),
        ("-Infinity", f64::NEG_INFINITY), ("0x10", 16.0), ("0X1f", 31.0), ("0o7", 7.0), ("0b1", 1.0), ("1.", 1.0), (".5", 0.5), ("1e3", 1000.0), ("+1.5", 1.5),
    ] {
        assert_eq!(n(s), want, "{s:?}");
    }
    assert!(n("-0") == 0.0 && n("-0").is_sign_negative());
    // any length of radix digits, rounded as node does: ties to even, a dropped non-zero digit breaks the tie upward
    let (f, zeros) = (|k: usize| "f".repeat(k), "0".repeat(31));
    assert_eq!(n(&format!("0x{}", f(300))), f64::INFINITY);
    assert_eq!(n(&format!("0x{}", f(256))), f64::INFINITY);
    assert_eq!(n(&format!("0x{}", f(255))), 2f64.powi(1020));
    assert_eq!(n(&format!("0x{}1", "0".repeat(200))), 1.0);
    assert_eq!(n(&format!("0b{}", "1".repeat(200))), 2f64.powi(200));
    assert_eq!(n(&format!("0o{}", "7".repeat(100))), 2f64.powi(300));
    assert_eq!(n("0x20000000000001"), 9007199254740992.0);
    assert_eq!(n("0x20000000000003"), 9007199254740996.0);
    assert_eq!(n(&format!("0x20000000000001{zeros}")), 9007199254740992.0 * 2f64.powi(124));
    assert_eq!(n(&format!("0x20000000000001{}1", &zeros[1..])), 9007199254740994.0 * 2f64.powi(124));
    assert!(n(&format!("0x{}g", f(300))).is_nan());
}

/// The other Number() readers go through the same port (bundle.ts compareVersion, attest-nvidia-spdm.ts:317-318).
#[test]
fn compare_version_reads_parts_with_js_number() {
    use crate::k3::compare_version as cv;
    assert_eq!(cv("1.2", "1.2.0"), 0);
    assert_eq!(cv("1.10", "1.9"), 1);
    assert_eq!(cv("1. 2", "1.2"), 0);
    assert_eq!(cv("1.\u{feff}2", "1.2"), 0);
    assert_eq!(cv("0x10", "16"), 0);
    // Rust's parse reads these as numbers; Number() as NaN, whose difference compares as 1 whichever side it is on
    for s in ["inf", "nan", "infinity"] {
        assert_eq!(cv(s, "1"), 1, "{s}");
        assert_eq!(cv("1", s), 1, "{s}");
    }
    assert_eq!(cv("Infinity", "1"), 1);
    assert_eq!(cv("1", "Infinity"), -1);
}

#[test]
fn js_key_prints_numbers_as_javascript_string() {
    let k = |v: Value| js_key(&v).unwrap();
    assert_eq!(k(json!(12)), "12");
    assert_eq!(k(json!(1.5)), "1.5");
    assert_eq!(k(json!(1e21)), "1e+21");
    assert_eq!(k(json!(1e-7)), "1e-7");
    assert_eq!(k(json!([1e21, null, 2])), "1e+21,,2");
}
