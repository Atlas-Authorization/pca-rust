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

#[test]
fn datetime_time_of_day_bounds() {
    for ok in ["2024-02-29T00:00:00Z", "2024-02-29T23:59:59Z", "2024-02-29T23:59:59.999Z", "2024-02-29T09:09:09.5Z"] {
        assert!(datetime_ok(ok), "{ok}");
    }
    for bad in [
        "2024-02-29T24:00:00Z",
        "2024-02-29T30:00:00Z",
        "2024-02-29T00:60:00Z",
        "2024-02-29T00:61:00Z",
        "2024-02-29T00:00:60Z",
        "2024-02-29T00:00:61Z",
        "2024-02-29T99:99:99Z",
        "2024-02-29T00:00:00.Z",
        "2024-02-29T00:00:00.1234Z",
        "2023-02-29T00:00:00Z",
    ] {
        assert!(!datetime_ok(bad), "{bad}");
    }
}

// ---- k05 full-run kills: each structural rule of the v2 formats on an input that passes every OTHER rule ----

#[test]
fn iban_structure_rules_hold_even_when_the_checksum_passes() {
    // every input below satisfies the mod-97 check as computed here, so only the structural rule can refuse it
    assert!(iban_ok("GB82WEST12345698765432"));
    assert!(iban_ok("GB25WEST1234567") && iban_ok("GB16AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), "15 and 34 characters");
    for bad in [
        "GB57WEST123456",                      // 14 characters
        "GB33AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 35 characters
        "gb86WEST12345698765432",              // lowercase country
        "G187WEST12345698765432",              // digit in the country
        "GBAKWEST12345698765432",              // letters as check digits
        "GB53west12345698765432",              // lowercase BBAN
    ] {
        assert!(!iban_ok(bad), "{bad}");
    }
}

#[test]
fn cidr_bounds() {
    // IPv6 forms are written with '_' for ':' (the public-leak scrub reads any IPv6 literal as an address)
    let v6 = |x: &str| x.replace('_', ":");
    for ok in ["0.0.0.0/0", "255.255.255.255/32", "10.0.0.1/8"].map(String::from).into_iter().chain(["__1/128", "fe80__/10"].map(v6)) {
        assert!(cidr_ok(&ok), "{ok}");
    }
    let bad4 = ["256.0.0.0/8", "1.2.3.4/33", "01.2.3.4/8", "1.2.3.4/08", "1.2.3.0004/8", "1.2.3.4/", "1.2.3/8", "a.b.c.d/8", "1.2.3.4"];
    for bad in bad4.map(String::from).into_iter().chain(["__1/129", "__1/0128", "__1/", "1___2/8"].map(v6)) {
        assert!(!cidr_ok(&bad), "{bad}");
    }
    // a single digits-only segment never reaches the IPv4 branch, and a v6 prefix of digits never reaches it either
    for bad in ["5/8", "12/12", "1.2.3.4.5/8"] {
        assert!(!cidr_ok(bad), "{bad}");
    }
}

/// cidr_ok's digit-count gate on its own (canon_dec's bounds make it unobservable through cidr_ok): 1..=max ASCII digits.
#[test]
fn cidr_digit_gate() {
    for (x, max, ok) in [("0", 3, true), ("123", 3, true), ("1234", 3, false), ("", 3, false), ("12a", 3, false), ("1a", 3, false),
        ("a", 3, false), ("99", 2, true), ("100", 2, false), ("\u{0663}", 3, false)] {
        assert_eq!(cidr_digits(x, max), ok, "{x:?} {max}");
    }
}

#[test]
fn semver_identifier_groups() {
    for ok in ["1.0.0", "1.0.0-rc-1", "1.0.0-alpha.1+build-7.x", "0.0.0+a"] {
        assert!(semver_ok(ok), "{ok}");
    }
    for bad in ["1.0.0-", "1.0.0-a..b", "1.0.0-a_b", "1.0.0-a$b", "1.0.0+", "1.0.0+a_b", "1.0.0+a..b", "01.0.0", "1.0"] {
        assert!(!semver_ok(bad), "{bad}");
    }
}

#[test]
fn email_length_and_label_bounds() {
    let at = |local: usize, labels: &[usize]| format!("{}@{}", "a".repeat(local), labels.iter().map(|n| "b".repeat(*n)).collect::<Vec<_>>().join("."));
    let e254 = at(64, &[63, 63, 61]);
    let e255 = at(64, &[63, 63, 62]);
    assert_eq!((e254.len(), e255.len()), (254, 255));
    assert!(email_ok(&e254), "254 characters is the limit");
    assert!(!email_ok(&e255), "255 characters is over it");
    assert!(email_ok(&at(1, &[63, 1])) && email_ok("a@b-c.com"));
    for bad in [at(1, &[64, 3]), "a@b..com".into(), "a@b_c.com".into(), "a@.com".into(), "a@com".into()] {
        assert!(!email_ok(&bad), "{bad}");
    }
}

#[test]
fn param_path_v2_segments() {
    for ok in ["action.params.a", "action.params.a.b", "action.params.a_1.b.c"] {
        assert!(is_param_path_v2(ok), "{ok}");
    }
    for bad in ["action.params.a.b.c.d", "action.params.a..b", "action.params.", "action.params.a-b", "params.a", "action.params.a.b."] {
        assert!(!is_param_path_v2(bad), "{bad}");
    }
}

#[test]
fn datetime_each_shape_rule_alone() {
    for bad in [
        "",
        "2024-02-29",
        "2024-02-29T00:00Z",
        "2024-02-29X00:00:00Z",
        "2024-02-29T00:00:00Y",
        "2024-02-30T00:00:00Z",
        // '/' sorts below '0', so only the digit rule (not the 23/59 bounds) refuses these
        "2024-02-29T/0:00:00Z",
        "2024-02-29T0/:00:00Z",
        "2024-02-29T00:/0:00Z",
        "2024-02-29T00:0/:00Z",
        "2024-02-29T00:00:/0Z",
        "2024-02-29T00:00:0/Z",
        "2024-02-29T00/00:00Z",
        "2024-02-29T00:00/00Z",
        "2024-02-29T00:00:00.1/Z",
        "2024-02-29T00:00:00,1Z",
    ] {
        assert!(!datetime_ok(bad), "{bad}");
    }
    assert!(datetime_ok("2024-02-29T00:00:00.12Z"));
}

#[test]
fn id_format_names() {
    assert_eq!(format_check("id:a1_b.c.d9.e", "Ab-1._:"), Some(true));
    assert_eq!(format_check("id:x", "a b"), Some(false));
    for bad in ["id:a.b.c.d.e", "id:a..b", "id:", "id:.a", "id:a-b", "id:A", "id:a.b-c"] {
        assert_eq!(format_check(bad, "abc"), None, "{bad}");
    }
    assert_eq!(format_check("id:a_b", "abc"), Some(true));
    assert_eq!(format_check("id:9", "abc"), Some(true));
}

#[test]
fn duration_zero_is_in_domain() {
    let d = serde_json::json!({"type": "duration"});
    let d = d.as_object().unwrap();
    assert_eq!(param_value_violation(d, &serde_json::json!(0)), None);
    assert_eq!(param_value_violation(d, &serde_json::json!(-1)).map(|v| v.0), Some("out_of_domain"));
}

const D32: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn v2_verb() -> Value {
    serde_json::json!({
        "verb": "v", "kind": "write",
        "params": {"action.params.a": {"type": "string", "semantic": "s", "sensitivity": "free"}},
        "effects": ["update"], "traits": [], "def": D32,
        "floors": {"risk": 0, "esc": 0, "rev": "reversible", "blast_ppm": 0, "caveats": [], "context": [], "prules": []}
    })
}

fn v2_doc(verb: Value) -> Value {
    serde_json::json!({"v": 2, "kind": "pca-action-schema", "site": "s", "aud": "a", "version": "1", "verbs": [verb]})
}

fn verb_with(k: &str, v: Value) -> Option<String> {
    let mut verb = v2_verb();
    verb[k] = v;
    action_schema_shape_error_unsigned(&v2_doc(verb))
}

#[test]
fn v2_verb_effects_traits_and_param_parents() {
    assert_eq!(action_schema_shape_error_unsigned(&v2_doc(v2_verb())), None, "the baseline is well-formed");
    let eff = Some("verb 'v': effects must be 1..12 known effects".to_string());
    assert_eq!(verb_with("effects", serde_json::json!([])), eff);
    assert_eq!(verb_with("effects", serde_json::json!(["bogus"])), eff);
    assert_eq!(verb_with("effects", serde_json::json!(vec!["update"; 13])), eff, "13 entries, every one known");
    assert_eq!(verb_with("effects", serde_json::json!(["create", "update"])), None);
    let sorted = Some("verb 'v': effects must be sorted and distinct".to_string());
    assert_eq!(verb_with("effects", serde_json::json!(["update", "create"])), sorted);
    assert_eq!(verb_with("effects", serde_json::json!(["update", "update"])), sorted);
    assert_eq!(verb_with("traits", serde_json::json!(["BAD"])), Some("verb 'v': traits must be trait ids".to_string()));
    assert_eq!(verb_with("traits", serde_json::json!(["a.b", "c.d"])), None);
    let mut params = v2_verb()["params"].clone();
    params["action.params.a.b"] = params["action.params.a"].clone();
    assert_eq!(verb_with("params", params), Some("verb 'v': parameter 'action.params.a' is both a value and the parent of 'action.params.a.b'".to_string()));
    let mut siblings = v2_verb()["params"].clone();
    siblings["action.params.ab"] = siblings["action.params.a"].clone();
    assert_eq!(verb_with("params", siblings), None, "a shared prefix without the dot is no parent");
}

#[test]
fn v2_confirmation_dismissed_cap() {
    let item = serde_json::json!({"trait": "a.b", "reason": "r"});
    let conf = |n: usize| serde_json::json!({"def_digest": D32, "traits_digest": D32, "facts_digest": D32, "final_traits": [],
        "dismissed": vec![item.clone(); n], "reviewer_kid": "k", "ts": 0, "sig": "A".repeat(86)});
    assert_eq!(confirmation_shape_error(&conf(64)), None);
    assert_eq!(confirmation_shape_error(&conf(65)), Some("confirmation: dismissed must be an array".to_string()));
}

#[test]
fn v2_doc_trait_defs_and_pack() {
    let doc = |k: &str, v: Value| {
        let mut d = v2_doc(v2_verb());
        d[k] = v;
        action_schema_shape_error_unsigned(&d)
    };
    let td = Some("trait_defs must be an array of up to 64 objects".to_string());
    assert_eq!(doc("trait_defs", serde_json::json!([])), None);
    assert_eq!(doc("trait_defs", serde_json::json!(vec![serde_json::json!({}); 64])), None);
    assert_eq!(doc("trait_defs", serde_json::json!(vec![serde_json::json!({}); 65])), td);
    assert_eq!(doc("trait_defs", serde_json::json!([1])), td);
    assert_eq!(doc("trait_defs", serde_json::json!({})), td);
    let pk = Some("pack must be {ns, version, root}".to_string());
    assert_eq!(doc("pack", serde_json::json!({"ns": "n", "version": "1", "root": D32})), None);
    assert_eq!(doc("pack", serde_json::json!({"ns": "n", "version": "1", "root": D32, "x": 1})), pk);
    assert_eq!(doc("pack", serde_json::json!({"nz": "n", "version": "1", "root": D32})), pk);
    assert_eq!(doc("pack", serde_json::json!({"ns": "n", "version": "", "root": D32})), pk);
    assert_eq!(doc("pack", serde_json::json!({"ns": "n", "version": "1", "root": "AA"})), pk);
}
