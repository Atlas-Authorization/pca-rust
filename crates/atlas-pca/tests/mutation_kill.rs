//! Mutation-kill suite for atlas-pca (cargo-mutants). Boundary tests for the strict-profile helpers plus a
//! characterization snapshot of the public API's observable output (verdict reasons, parse errors, wire errors,
//! chain verdicts) over the whole shared conformance corpus. Regenerate the snapshot deliberately with
//! `UPDATE_MUT_SNAPSHOT=1 cargo test --test mutation_kill snapshot` and review the diff.
mod common;
use atlas_pca::*;
use common::*;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::io::Write;

fn hop(n: usize) -> Value {
    json!({ "caveats": (0..n).map(|_| json!({"type": "note"})).collect::<Vec<_>>() })
}

#[test]
fn caveat_caps_are_exact() {
    assert!(!caveat_limit_exceeded(&[hop(0)]));
    assert!(!caveat_limit_exceeded(&[hop(255)]));
    assert!(!caveat_limit_exceeded(&[hop(256)]));
    assert!(caveat_limit_exceeded(&[hop(257)]));
    assert!(!caveat_limit_exceeded(&[hop(256), hop(256), hop(256), hop(256)])); // total == 1024
    assert!(caveat_limit_exceeded(&[hop(256), hop(256), hop(256), hop(256), hop(1)])); // 1025
    assert!(caveat_limit_exceeded(&[hop(205), hop(205), hop(205), hop(205), hop(205)])); // 1025 via +=
    assert!(!caveat_limit_exceeded(&[hop(204), hop(205), hop(205), hop(205), hop(205)])); // 1024
    assert!(!caveat_limit_exceeded(&[json!({}), json!({"caveats": "x"})]));
}

#[test]
fn number_profile_boundaries() {
    let ok = |v: Value| canonicalize_strict(&v);
    assert_eq!(ok(json!(9007199254740991u64)).unwrap(), "9007199254740991");
    assert_eq!(ok(json!(-9007199254740991i64)).unwrap(), "-9007199254740991");
    assert!(ok(json!(9007199254740992u64)).is_err());
    assert!(ok(json!(-9007199254740992i64)).is_err());
    // u64 beyond i64::MAX
    assert!(ok(json!(9223372036854775808u64)).is_err());
    assert!(ok(json!(18446744073709551615u64)).is_err());
    // integer-valued floats
    assert_eq!(ok(json!(9007199254740991.0f64)).unwrap(), "9007199254740991");
    assert!(ok(json!(9007199254740992.0f64)).is_err());
    assert!(ok(json!(-9007199254740992.0f64)).is_err());
    assert_eq!(ok(json!(0.0f64)).unwrap(), "0");
    assert!(ok(json!(-0.0f64)).is_err());
    assert_eq!(ok(json!(2.5f64)).unwrap(), "2.5");
    assert_eq!(ok(json!(-2.5f64)).unwrap(), "-2.5");
    // tiny non-integers
    assert!(ok(json!(1e-7f64)).is_err());
    assert!(ok(json!(-1e-7f64)).is_err());
    assert!(ok(json!(0.000001f64)).is_ok());
    // significant digits: 15 ok, 16 not
    assert!(ok(json!(0.123456789012345f64)).is_ok());
    assert!(ok(json!(0.1234567890123456f64)).is_err());
    assert!(ok(json!(1234567.890123456f64)).is_err());
    assert!(ok(json!(123456.789012345f64)).is_ok());
    // each error carries its own text
    assert!(ok(json!(-0.0f64)).unwrap_err().ends_with("negative zero"));
    assert!(ok(json!(1e-7f64)).unwrap_err().ends_with("non-integer magnitude below 1e-6"));
    assert!(ok(json!(18446744073709551615u64)).unwrap_err().ends_with("integer outside the safe range"));
}

#[test]
fn nesting_depth_is_enforced_for_arrays_and_objects() {
    let nest_obj = |n: usize| {
        let mut v = json!(1);
        for _ in 0..n {
            v = json!({ "a": v });
        }
        v
    };
    let nest_arr = |n: usize| {
        let mut v = json!(1);
        for _ in 0..n {
            v = json!([v]);
        }
        v
    };
    assert!(canonicalize_strict(&nest_obj(31)).is_ok());
    assert!(canonicalize_strict(&nest_obj(32)).is_ok());
    assert!(canonicalize_strict(&nest_obj(33)).is_err());
    assert!(canonicalize_strict(&nest_obj(40)).is_err());
    assert!(canonicalize_strict(&nest_arr(31)).is_ok());
    assert!(canonicalize_strict(&nest_arr(32)).is_ok());
    assert!(canonicalize_strict(&nest_arr(33)).is_err());
    // mixed
    assert!(canonicalize_strict(&json!({"a": nest_arr(32)})).is_err());
    assert!(canonicalize_strict(&json!([nest_obj(32)])).is_err());
    // the lenient form has no depth cap
    assert!(!canonicalize(&nest_obj(40)).is_empty());
}

#[test]
fn strict_parse_size_cap_is_exact() {
    let pad = |n: usize| format!("{}1", " ".repeat(n - 1));
    assert_eq!(strict_parse(&pad(1 << 20)).unwrap(), json!(1));
    assert_eq!(strict_parse(&pad((1 << 20) - 1)).unwrap(), json!(1));
    assert_eq!(strict_parse(&pad((1 << 20) + 1)).unwrap_err(), "strict JSON: input too large");
}

#[test]
fn params_digest_null_and_absent() {
    let empty = hash_canonical(&json!({}));
    assert_eq!(params_digest(None), empty);
    assert_eq!(params_digest(Some(&Value::Null)), empty);
    assert_ne!(params_digest(Some(&Value::Null)), hash_canonical(&Value::Null));
    let p = json!({"a": 1});
    assert_eq!(params_digest(Some(&p)), hash_canonical(&p));
    assert_ne!(params_digest(Some(&p)), empty);
    assert_eq!(params_digest(Some(&json!(0))), hash_canonical(&json!(0)));
}

#[test]
fn hash_canonical_is_the_sha256_base64url() {
    assert_eq!(hash_canonical(&json!({})), "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o");
    assert_ne!(hash_canonical(&json!(null)), hash_canonical(&json!({})));
    assert_eq!(hash_canonical(&json!(null)).len(), 43);
}

fn extra_json() -> Vec<String> {
    let mut v: Vec<String> = [
        "", " ", "{", "}", "[", "]", "[1,]", "[,1]", "{,}", r#"{"a"}"#, r#"{"a":}"#, r#"{"a":1,}"#, r#"{"a":1 "b":2}"#, "{a:1}", "{'a':1}", "nul", "tru",
        "fals", "null x", "01", "-", "-0", "+1", "1.", ".5", "1e", "1e+", "1E5", "1.5e3", "0.0", "-0.0", "9007199254740993", "-9007199254740993", "1e400",
        "123456789012345678901234567890", "NaN", "Infinity", "-Infinity", r#""abc"#, r#""a\x""#, r#""\u12""#, r#""\u12G4""#, r#""\ud800""#, r#""\udc00""#,
        r#""\ud800\udc00""#, r#""\ud83d\ude00""#, r#""\ud800a""#, r#""\udc00\ud800""#, r#""\ud800\ud800""#, "\"\u{1}\"", "\"\t\"", r#""\t\n\r\b\f\/\\\"""#,
        r#"{"a":1,"a":2}"#, r#"{"a":{"b":1,"b":2}}"#, r#"{"__proto__":1}"#, "[[[[[[[[[[1]]]]]]]]]]", "  [ 1 , 2 ]  ", "\u{feff}[1]", "[1]\n", "[1]x",
        "\u{e9}", "\"\u{e9}\"", r#""\u0000""#, r#"{"a":[1,{"b":null}],"c":true}"#, r#"{"b":1,"a":2}"#, "1 2", "[1 2]", r#"{"a" 1}"#, r#"{"a":1 "#, "[1,", "\"", "\\",
        "tr", "n", "-a", "0x10", "1_0", "0.5", "-0.5", "1.0", "1e2", "1e-2", "0.000001", "0.0000001", "123456.789012345", "1234567.890123456", "12345678901234567",
        r#""\ud800\n""#, r#""\ud800\\""#, r#""\ud800xu1234""#, r#""\ud800\u""#, r#""\ud800\u00""#, r#""\ud800\u0041""#, "\t1", "\u{b}1", "1\u{c}", r#"["a" "b"]"#, r#"{"a":1,,"b":2}"#, r#"{"a":1}{"b":2}"#, "[\"\\u00e9\"]", "[\"\\uD83D\\uDE00\"]",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for n in [1usize, 5, 20, 31, 32, 33, 64, 100, 200] {
        v.push("[".repeat(n) + &"]".repeat(n));
        v.push("{\"a\":".repeat(n) + "1" + &"}".repeat(n));
    }
    for n in [15usize, 16, 17, 20] {
        v.push("1".repeat(n));
    }
    v
}

fn parse_outcome(s: &str) -> Value {
    match strict_parse(s) {
        Ok(v) => json!(["ok", canonicalize_strict(&v).unwrap_or_else(|e| format!("CANON-ERR {e}"))]),
        Err(e) => json!(["err", e]),
    }
}

fn corpus() -> Vec<(String, Value)> {
    let mut out = Vec::new();
    let core = load("vectors.json");
    let adv = load("vectors-adversarial.json.gz");
    for (src, d) in [("core", &core), ("adv", &adv)] {
        for v in d["vectors"].as_array().unwrap() {
            out.push((format!("{src}:{}", v["name"].as_str().unwrap()), v.clone()));
        }
    }
    out
}

fn collect() -> Value {
    let mut vectors = BTreeMap::new();
    let mut wires = BTreeMap::new();
    let mut chains = BTreeMap::new();
    for (name, v) in corpus() {
        let want = v["expect"]["checks"].as_object().unwrap();
        let twf = want.len() == 1 && want.get("wire") == Some(&Value::Bool(false));
        if unsupported_suite(&v).is_some() && !twf {
            continue;
        }
        let now = v["context"]["now"].as_i64().unwrap();
        let aud = v["context"]["aud"].as_str().unwrap();
        let allowed: Option<Vec<String>> = v["context"]["allowed_suites"].as_array().map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect());
        let lone = has_lone(&v["pcactn"]);
        let got = if let Some(raw) = v.get("pcactn_json").and_then(Value::as_str) {
            verify_pcactn_json_policy(raw, &v["grant"], now, aud, allowed.as_deref())
        } else if lone {
            continue;
        } else {
            verify_pcactn_core_policy(&v["pcactn"], &v["grant"], now, aud, allowed.as_deref())
        };
        vectors.insert(name.clone(), json!([got.allow, got.checks, got.reason]));
        if lone || v.get("pcactn_json").is_some() {
            continue;
        }
        let p = &v["pcactn"];
        wires.insert(name.clone(), json!(validate_wire(p).err()));
        if let Some(chain) = p.get("cap_chain").and_then(Value::as_array) {
            let issuer = v["grant"].get("issuer").and_then(Value::as_str);
            let empty: Vec<String> = Vec::new();
            let mut pins = std::collections::HashMap::new();
            if let Some(g) = v["grant"].as_object() {
                if let (Some(i), Some(k)) = (g.get("issuer").and_then(Value::as_str), g.get("pq_pk").and_then(Value::as_str)) {
                    pins.insert(i.to_string(), k.to_string());
                }
            }
            let r = |x: Result<(), String>| json!(x.err());
            chains.insert(
                name.clone(),
                json!([
                    r(verify_chain(chain, issuer)),
                    r(verify_chain(chain, None)),
                    r(verify_chain_policy(chain, issuer, allowed.as_deref(), None, Some(&v["grant"]))),
                    r(verify_chain_policy(chain, issuer, Some(&empty), None, Some(&v["grant"]))),
                    r(verify_chain_policy(chain, issuer, None, Some(&pins), None)),
                    r(verify_chain_policy(chain, None, None, Some(&pins), Some(&v["grant"]))),
                ]),
            );
        }
    }
    let mut parse = BTreeMap::new();
    let mut inputs = extra_json();
    for d in [load("vectors.json"), load("vectors-adversarial.json.gz")] {
        for c in d["primitives"]["json_parse"].as_array().into_iter().flatten() {
            let s = c["input"].as_str().unwrap();
            if !s.contains(LONE) {
                inputs.push(s.to_string());
            }
        }
    }
    for s in inputs {
        let o = parse_outcome(&s);
        parse.insert(s, o);
    }
    let mut b64 = BTreeMap::new();
    for d in [load("vectors.json"), load("vectors-adversarial.json.gz")] {
        for c in d["primitives"]["b64u"].as_array().into_iter().flatten() {
            let len = c["len"].as_u64().map(|n| n as usize);
            let s = c["input"].as_str().unwrap();
            let r = decode_b64u_strict(s, len);
            b64.insert(format!("{s}|{len:?}"), json!(r.map(|b| b.iter().map(|x| format!("{x:02x}")).collect::<String>())));
        }
    }
    let mut shares = BTreeMap::new();
    for d in [load("vectors.json"), load("vectors-adversarial.json.gz")] {
        for (i, s) in d["primitives"]["threshold_share"].as_array().into_iter().flatten().enumerate() {
            shares.insert(format!("{i}:{}", s["role"]), json!(verify_threshold_share(s)));
        }
    }
    let mut m = Map::new();
    m.insert("vectors".into(), json!(vectors));
    m.insert("wires".into(), json!(wires));
    m.insert("chains".into(), json!(chains));
    m.insert("parse".into(), json!(parse));
    m.insert("b64".into(), json!(b64));
    m.insert("shares".into(), json!(shares));
    Value::Object(m)
}

const SNAP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/mutation-snapshot.json.gz");

#[test]
fn snapshot() {
    let got = collect();
    if std::env::var("UPDATE_MUT_SNAPSHOT").is_ok() {
        let text = serde_json::to_vec(&got).unwrap();
        let mut c = std::process::Command::new("gzip").args(["-9n", "-c"]).stdin(std::process::Stdio::piped()).stdout(std::fs::File::create(SNAP).unwrap()).spawn().unwrap();
        c.stdin.take().unwrap().write_all(&text).unwrap();
        assert!(c.wait().unwrap().success());
        return;
    }
    let o = std::process::Command::new("gzip").arg("-dc").arg(SNAP).output().expect("gzip");
    assert!(o.status.success());
    let want: Value = serde_json::from_slice(&o.stdout).unwrap();
    for (sec, w) in want.as_object().unwrap() {
        let g = &got[sec];
        assert_eq!(g.as_object().unwrap().len(), w.as_object().unwrap().len(), "{sec}: entry count");
        let bad: Vec<&String> = w.as_object().unwrap().iter().filter(|(k, wv)| g.get(k.as_str()) != Some(wv)).map(|(k, _)| k).collect();
        assert!(bad.is_empty(), "{sec}: {} differ, e.g. {:?}: got {:?} want {:?}", bad.len(), bad[0], g.get(bad[0].as_str()), w.get(bad[0].as_str()));
    }
}

#[test]
fn high_surrogate_must_be_followed_by_a_low_surrogate_escape() {
    for bad in [r#""\ud800\n""#, r#""\ud800\\""#, r#""\ud800xu1234""#, r#""\ud800""#, r#""\ud800x""#] {
        let e = strict_parse(bad).unwrap_err();
        assert!(e.contains("lone surrogate"), "{bad}: {e}");
    }
    assert!(strict_parse(r#""\ud800\u0041""#).unwrap_err().contains("lone surrogate"));
    assert!(strict_parse(r#""\ud800\u00""#).unwrap_err().contains("bad \\u escape"));
    assert_eq!(strict_parse(r#""\ud83d\ude00""#).unwrap(), json!("\u{1F600}"));
}

#[test]
fn inclusion_proof_index_and_size_bounds() {
    let leaf = json!({"n": 1});
    let root = merkle_root(&[leaf.clone()]).unwrap();
    let mk = |i: i64, s: i64| {
        let mut m = Map::new();
        m.insert("index".into(), json!(i));
        m.insert("size".into(), json!(s));
        m.insert("path".into(), json!([]));
        m
    };
    assert!(verify_inclusion(&root, Some(&mk(0, 1)), &leaf));
    for (i, s) in [(1, 1), (-1, 1), (0, 0), (-1, 0), (0, -1), (5, 3), (2, 1), (-2, 1), (i64::MIN, 1), (0, i64::MIN)] {
        assert!(!verify_inclusion(&root, Some(&mk(i, s)), &leaf), "index {i} size {s}");
    }
    assert!(!verify_inclusion(&root, None, &leaf));
}
