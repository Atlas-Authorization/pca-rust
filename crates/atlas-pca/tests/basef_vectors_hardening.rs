//! The 0.5 hardening vectors (packages/pca/conformance): the core `plan_root_authorized` check (plan-root-vectors.json), the monotone
//! `budget_alloc` list (budget-alloc-vectors.json) and the server-side PQ pins (pq-pin-vectors.json). Each case runs the named vectors.json
//! vector; a missing file fails, it never skips.
use atlas_pca::*;
use serde_json::{Map, Value};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/");

const LONE: char = '\u{10FFFF}';

fn sanitize_lone_surrogates(text: &str) -> String {
    let cs: Vec<char> = text.chars().collect();
    let hex = |at: usize| -> Option<u32> {
        let s: String = cs.get(at..at + 4)?.iter().collect();
        if s.chars().all(|c| c.is_ascii_hexdigit()) {
            u32::from_str_radix(&s, 16).ok()
        } else {
            None
        }
    };
    let mut out = String::with_capacity(text.len());
    let (mut i, mut in_str) = (0, false);
    while i < cs.len() {
        let c = cs[i];
        if !in_str {
            in_str = c == '"';
            out.push(c);
            i += 1;
        } else if c == '"' {
            in_str = false;
            out.push(c);
            i += 1;
        } else if c == '\\' {
            if cs.get(i + 1) == Some(&'u') {
                match hex(i + 2) {
                    Some(hi) if (0xD800..=0xDBFF).contains(&hi) => {
                        let paired = cs.get(i + 6) == Some(&'\\')
                            && cs.get(i + 7) == Some(&'u')
                            && hex(i + 8).is_some_and(|lo| (0xDC00..=0xDFFF).contains(&lo));
                        if paired {
                            out.extend(&cs[i..i + 12]);
                            i += 12;
                        } else {
                            out.push(LONE);
                            i += 6;
                        }
                    }
                    Some(lo) if (0xDC00..=0xDFFF).contains(&lo) => {
                        out.push(LONE);
                        i += 6;
                    }
                    _ => {
                        out.extend(&cs[i..(i + 2).min(cs.len())]);
                        i += 2;
                    }
                }
            } else {
                out.extend(&cs[i..(i + 2).min(cs.len())]);
                i += 2;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

fn load(name: &str) -> Value {
    let b = std::fs::read_to_string(format!("{DIR}{name}")).expect("read file");
    serde_json::from_str(&sanitize_lone_surrogates(&b)).expect("parse json")
}

fn vector(all: &Value, name: &str) -> Value {
    all["vectors"].as_array().unwrap().iter().find(|v| v["name"] == name).unwrap_or_else(|| panic!("no vector {name}")).clone()
}

#[test]
fn plan_root_authorized_vectors() {
    let all = load("vectors.json");
    let doc = load("plan-root-vectors.json");
    let cases = doc["plan_root_authorized"].as_array().unwrap();
    assert_eq!(cases.len(), 9);
    for c in cases {
        let v = vector(&all, c["vector"].as_str().unwrap());
        let root = v["pcactn"]["plan"]["root"].as_str().unwrap().to_string();
        let o = &c["options"];
        let roots: Option<Vec<String>> = o.get("authorizedPlanRoots").and_then(Value::as_array).map(|a| a.iter().map(|r| if r == "$plan_root" { root.clone() } else { r.as_str().unwrap().to_string() }).collect());
        let skip = o.get("insecureSkipPlanRootCheck").and_then(Value::as_bool) == Some(true);
        let got = verify_pcactn_core_with(
            &v["pcactn"],
            &v["grant"],
            v["context"]["now"].as_i64().unwrap(),
            v["context"]["aud"].as_str().unwrap(),
            &VerifyOptions { authorized_plan_roots: roots.as_deref(), insecure_skip_plan_root_check: skip, ..VerifyOptions::default() },
        );
        let name = &c["name"];
        let e = &c["expect"];
        assert_eq!(got.allow, e["allow"].as_bool().unwrap(), "{name}: {got:?}");
        let status = got.checks.get("plan_root_authorized").copied();
        match e["check"].as_str().unwrap() {
            "pass" => assert_eq!(status, Some(true), "{name}"),
            "fail" => assert_eq!(status, Some(false), "{name}"),
            // not-enforced is not reported by the core verdict
            "not-enforced" => assert_eq!(status, None, "{name}"),
            other => panic!("{name}: check {other}"),
        }
        if let Some(r) = e["reason"].as_str() {
            assert_eq!(got.reason, r, "{name}");
        }
    }
}

#[test]
fn budget_alloc_vectors() {
    let doc = load("budget-alloc-vectors.json");
    let cases = doc["budget_alloc"].as_array().unwrap();
    assert_eq!(cases.len(), 24);
    for c in cases {
        let got = allocations_monotone_value(&c["caveats"]);
        let e = &c["expect"];
        match (e["ok"].as_bool().unwrap(), &got) {
            (true, Ok(())) => {}
            (false, Err(why)) => assert_eq!(Some(why.as_str()), e["reason"].as_str(), "{}", c["name"]),
            _ => panic!("{}: {got:?} vs {e}", c["name"]),
        }
    }
}

/// `$grant.issuer`, `$grant.pq_pk` and `$grant.pq_pk[0:20]` in a pin case stand for the vector's grant.
fn resolve(v: &Value, grant: &Value) -> Value {
    match v {
        Value::String(s) if s == "$grant.issuer" => grant["issuer"].clone(),
        Value::String(s) if s == "$grant.pq_pk" => grant["pq_pk"].clone(),
        Value::String(s) if s == "$grant.pq_pk[0:20]" => Value::String(grant["pq_pk"].as_str().unwrap().chars().take(20).collect()),
        other => other.clone(),
    }
}

#[test]
fn pq_pin_vectors() {
    let all = load("vectors.json");
    let doc = load("pq-pin-vectors.json");
    let cases = doc["pq_pin"].as_array().unwrap();
    assert_eq!(cases.len(), 9);
    for c in cases {
        let grant = &vector(&all, c["vector"].as_str().unwrap())["grant"];
        let Some(pins) = c["pq_pins"].as_object() else {
            // pq_pins omitted: the check is not reported at all (authorize reports nothing when `pq_pins` is None)
            assert_eq!(c["expect"]["check"], "absent", "{}", c["name"]);
            continue;
        };
        let mut resolved = Map::new();
        for (k, v) in pins {
            let key = if k == "$grant.issuer" { grant["issuer"].as_str().unwrap().to_string() } else { k.clone() };
            resolved.insert(key, resolve(v, grant));
        }
        let got = pq_pin_check(grant, &resolved);
        let e = &c["expect"];
        match e["check"].as_str().unwrap() {
            "pass" => assert_eq!(got, Ok(()), "{}", c["name"]),
            "fail" => assert_eq!(got.map_err(|w| format!("pq_pin: {w}")), Err(e["reason"].as_str().unwrap().to_string()), "{}", c["name"]),
            other => panic!("{}: check {other}", c["name"]),
        }
    }
}

/// Through the real chain verifier: a root capability whose signed `caveats` member is not a list is refused (the structural check on
/// the hop fires first, so the text is the hop's; the `malformed caveats` text of the budget check is pinned by the vector row above).
#[test]
fn a_chain_whose_leaf_caveats_are_not_an_array_is_refused() {
    use atlas_pca::agent::KeyPair;
    use base64::Engine;
    let (issuer, holder) = (KeyPair::from_seed(&[3u8; 32]), KeyPair::from_seed(&[4u8; 32]));
    let cap = |caveats: Value| {
        let body = serde_json::json!({"issuer": issuer.public, "holder": holder.public, "caveats": caveats.clone(), "parent": null});
        let digest = hash_canonical_strict(&body).unwrap();
        let mut msg = b"atlas-pca/cap/v1\0".to_vec();
        msg.extend(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&digest).unwrap());
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(issuer.sign(&msg));
        serde_json::json!({"id": digest, "issuer": issuer.public, "holder": holder.public, "caveats": caveats, "body_digest": digest, "sig": sig})
    };
    // control: a well-formed list verifies through the same path
    assert_eq!(verify_chain(&[cap(serde_json::json!([]))], Some(issuer.public.as_str())), Ok(()));
    for bad in [serde_json::json!({}), serde_json::json!("x"), serde_json::json!(null), serde_json::json!(5)] {
        assert_eq!(verify_chain(&[cap(bad.clone())], Some(issuer.public.as_str())), Err("hop 0: malformed capability".to_string()), "{bad}");
    }
}
