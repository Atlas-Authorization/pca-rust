//! Caveat language v2 (track K1): the shared vectors (`caveat-lang-vectors.json`: discharge verification, K1 evaluation, caveat
//! shapes, use-slot keys, use reservation, SPIFFE IDs) plus exact-outcome unit tests for hostile input.

mod common;

use atlas_pca::serde_json::{json, Value};
use atlas_pca::{
    bound_caveats, derive_error, discharge_shape_error, evaluate_caveats_k1, evaluate_k1, max_uses_error, max_uses_slot_key,
    narrow_shape_error, needs_discharge_error, reserve_max_uses, spiffe_bound_error, spiffe_id_error, supported_suites, verify_discharge,
    verify_narrow, BoundCaveat, DischargeBinding, DischargePin, DischargeVerdict, K1Ctx, K1Input, MemoryStateStore, NarrowBinding,
    NarrowVerdict, StateStore, UsesVerdict, presented_k1,
};

fn table(name: &str) -> Vec<Value> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/caveat-lang-vectors.json"
    );
    // a missing vector file fails the test, never skips it
    let text = std::fs::read_to_string(p).expect("caveat-lang-vectors.json is missing");
    let v: Value = atlas_pca::serde_json::from_str(&text).unwrap();
    v["primitives"][name].as_array().unwrap().clone()
}

/// A JSON clock; a non-integer value is the clock of a verifier that is not on a safe integer (refused by the clock check).
fn clock(v: &Value) -> i64 {
    let f = v.as_f64().unwrap();
    if f.fract() == 0.0 {
        f as i64
    } else {
        i64::MAX
    }
}

fn pins_of(v: &Value) -> Vec<DischargePin> {
    v.as_array()
        .map(|a| a.iter().map(|p| DischargePin::from_json(p).unwrap()).collect())
        .unwrap_or_default()
}

fn strings(v: &Value) -> Option<Vec<String>> {
    v.as_array().map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect())
}

#[test]
fn discharge_verify_vectors() {
    let have = supported_suites();
    let mut ran = 0;
    for e in table("discharge_verify") {
        let i = &e["input"];
        let b = &i["binding"];
        let pins = pins_of(&b["pins"]);
        let revoked = strings(&b["revoked"]);
        let binding = DischargeBinding {
            cap_hash: b["cap_hash"].as_str().unwrap(),
            action_digest: b["action_digest"].as_str(),
            pins: &pins,
            now: clock(&b["now"]),
            revoked: revoked.as_deref(),
        };
        let r = verify_discharge(&i["discharge"], &i["caveat"], &binding);
        let x = &e["expect"];
        if let Some(need) = e["requires_suite"].as_str() {
            if !have.iter().any(|h| *h == need) {
                // a suite this build cannot run is refused, never accepted and never mistaken for a bad signature
                match &r {
                    DischargeVerdict::Fail { reason } => assert!(reason.contains("unsupported_suite"), "{}: {reason}", e["name"]),
                    other => panic!("{}: suite {need} is not built, got {other:?}", e["name"]),
                }
                continue;
            }
        }
        match (&r, x["ok"].as_bool().unwrap()) {
            (DischargeVerdict::Ok { digest, claims }, true) => {
                assert_eq!(digest.as_str(), x["digest"].as_str().unwrap(), "{}", e["name"]);
                assert_eq!(&Value::Object(claims.clone()), &x["claims"], "{}", e["name"]);
            }
            (DischargeVerdict::Fail { reason }, false) => {
                assert!(reason.contains(x["reason_contains"].as_str().unwrap()), "{}: {reason}", e["name"]);
            }
            _ => panic!("{}: got {r:?}, want {x}", e["name"]),
        }
        ran += 1;
    }
    assert!(ran >= 50, "only {ran} discharge_verify vectors ran");
}

fn k1_of(v: &Value) -> Option<K1Input> {
    if !v.is_object() {
        return None; // an absent or non-object k1 is "not configured"
    }
    Some(K1Input {
        pins: pins_of(&v["pins"]),
        discharges: v["discharges"].as_array().cloned().unwrap_or_default(),
        narrow: v.get("narrow").cloned(),
        action_digest: v["action_digest"].as_str().map(String::from),
        revoked_discharges: strings(&v["revoked_discharges"]),
        spiffe_id: v["spiffe_id"].as_str().map(String::from),
        history: v["history"].as_array().cloned(),
    })
}

#[test]
fn k1_eval_vectors() {
    let mut ran = 0;
    for e in table("k1_eval") {
        let i = &e["input"];
        let (allow, failed) = evaluate_caveats_k1(&i["grant"], &i["chain"], k1_of(&i["k1"]).as_ref(), &i["context"]);
        let mut want: Vec<String> = e["expect"]["failed"].as_array().unwrap().iter().map(|f| f.as_str().unwrap().to_string()).collect();
        want.sort();
        assert_eq!(allow, e["expect"]["allow"].as_bool().unwrap(), "{}: failed {failed:?}", e["name"]);
        assert_eq!(failed, want, "{}", e["name"]);
        ran += 1;
    }
    assert!(ran >= 100, "only {ran} k1_eval vectors ran");
}

fn shape_error(c: &Value) -> Option<String> {
    match c["type"].as_str() {
        Some("needs_discharge") => needs_discharge_error(c),
        Some("max_uses") => max_uses_error(c),
        Some("derive") => derive_error(c),
        Some("spiffe_bound") => spiffe_bound_error(c),
        other => panic!("no shape check for {other:?}"),
    }
}

#[test]
fn caveat_shape_vectors() {
    let rows = table("caveat_shape");
    assert!(rows.len() >= 45, "only {} caveat_shape vectors", rows.len());
    for e in rows {
        let err = shape_error(&e["input"]["caveat"]);
        assert_eq!(err.is_none(), e["expect"]["valid"].as_bool().unwrap(), "{}: {err:?}", e["name"]);
    }
}

#[test]
fn uses_key_vectors() {
    let rows = table("uses_key");
    assert!(rows.len() >= 5);
    for e in rows {
        let i = &e["input"];
        let key = max_uses_slot_key(i["cap_hash"].as_str().unwrap(), i["id"].as_str().unwrap(), i["i"].as_u64().unwrap());
        assert_eq!(key, e["expect"]["key"].as_str().unwrap(), "{}", e["name"]);
    }
}

#[test]
fn uses_reserve_vectors() {
    let mut calls = 0;
    for e in table("uses_reserve") {
        let store = MemoryStateStore::new();
        let bound: Vec<BoundCaveat> = e["input"]["bound"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| BoundCaveat { caveat: b["caveat"].clone(), hop: 0, cap_hash: b["cap_hash"].as_str().unwrap().to_string() })
            .collect();
        let want = e["expect"]["results"].as_array().unwrap();
        let cs = e["input"]["calls"].as_array().unwrap();
        assert_eq!(cs.len(), want.len(), "{}", e["name"]);
        for (n, (c, w)) in cs.iter().zip(want).enumerate() {
            let r = reserve_max_uses(&store, &bound, clock(&c["now"]));
            match (&r, w["ok"].as_bool().unwrap()) {
                (UsesVerdict::Ok { spent }, true) => assert_eq!(*spent as u64, w["spent"].as_u64().unwrap(), "{} call {n}", e["name"]),
                (UsesVerdict::Fail { reason }, false) => {
                    assert!(reason.contains(w["reason_contains"].as_str().unwrap()), "{} call {n}: {reason}", e["name"])
                }
                _ => panic!("{} call {n}: got {r:?}, want {w}", e["name"]),
            }
            calls += 1;
        }
    }
    assert!(calls >= 250, "only {calls} reservation calls ran");
}

/// Run the `consume_once_ttl` steps against a fresh store from `mk`; `'true' | 'false' | 'error'` per step.
fn consume_once_rows(mk: &dyn Fn() -> Box<dyn StateStore>) {
    let mut ran = 0;
    for e in table("consume_once_ttl") {
        let store = mk();
        let want: Vec<&str> = e["expect"]["results"].as_array().unwrap().iter().map(|r| r.as_str().unwrap()).collect();
        let got: Vec<&str> = e["input"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| match store.consume_once(x["key"].as_str().unwrap(), x["retain_until"].as_i64().unwrap(), x["now"].as_i64().unwrap()) {
                Ok(true) => "true",
                Ok(false) => "false",
                Err(_) => "error",
            })
            .collect();
        assert_eq!(got, want, "{}", e["name"]);
        ran += 1;
    }
    assert!(ran >= 9, "only {ran} consume_once_ttl vectors ran");
}

#[test]
fn consume_once_ttl_vectors_memory() {
    consume_once_rows(&|| Box::new(MemoryStateStore::new()));
}

#[cfg(feature = "sqlite")]
#[test]
fn consume_once_ttl_vectors_sqlite() {
    consume_once_rows(&|| {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        Box::new(atlas_pca::SqliteStateStore::from_connection(conn).unwrap())
    });
}

#[test]
fn a_max_uses_slot_expires_with_its_caveat() {
    let store = MemoryStateStore::new();
    let bound = vec![BoundCaveat { caveat: json!({"type": "max_uses", "id": "u", "n": 1, "until": 1000}), hop: 0, cap_hash: "h".into() }];
    assert!(matches!(reserve_max_uses(&store, &bound, 10), UsesVerdict::Ok { spent: 1 }));
    assert!(matches!(reserve_max_uses(&store, &bound, 11), UsesVerdict::Fail { .. }));
    // the slot is remembered until `until`, then forgotten (the caveat itself is expired by then)
    assert_eq!(store.consume_once("x", 20, 10).unwrap(), true);
    assert_eq!(store.consume_once("x", 30, 21).unwrap(), true);
}

#[test]
fn k1_headers_vectors() {
    let mut ran = 0;
    for e in table("k1_headers") {
        let hs: Vec<(String, String)> = e["input"]["headers"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect();
        let got = match presented_k1(hs.iter().map(|(k, v)| (k.as_str(), v.as_str()))) {
            Ok(p) => {
                let mut m = atlas_pca::serde_json::Map::new();
                if let Some(d) = p.discharges {
                    m.insert("discharges".into(), Value::Array(d));
                }
                if let Some(n) = p.narrow {
                    m.insert("narrow".into(), n);
                }
                json!({"ok": true, "value": Value::Object(m)})
            }
            Err(_) => json!({"ok": false}),
        };
        assert_eq!(got, e["expect"], "{}", e["name"]);
        ran += 1;
    }
    assert!(ran >= 14, "only {ran} k1_headers vectors ran");
}

#[test]
fn spiffe_id_vectors() {
    let rows = table("spiffe_id");
    assert!(rows.len() >= 24);
    for e in rows {
        let err = spiffe_id_error(&e["input"]["id"]);
        assert_eq!(err.is_none(), e["expect"]["valid"].as_bool().unwrap(), "{}: {err:?}", e["name"]);
    }
}

// ---- hostile input: exact outcomes, never a panic -----------------------------------------------------------------------

fn nonsense() -> Vec<Value> {
    vec![Value::Null, json!(true), json!(7), json!("x"), json!([]), json!([1, 2]), json!({}), json!({"type": 5})]
}

#[test]
fn hostile_values_are_refused_not_thrown() {
    let binding = DischargeBinding { cap_hash: "x", action_digest: None, pins: &[], now: 1, revoked: None };
    for v in nonsense() {
        assert!(discharge_shape_error(&v).is_some());
        assert!(narrow_shape_error(&v).is_some());
        assert!(needs_discharge_error(&v).is_some());
        assert!(max_uses_error(&v).is_some());
        assert!(derive_error(&v).is_some());
        assert!(spiffe_bound_error(&v).is_some());
        assert!(spiffe_id_error(&v).is_some());
        assert!(matches!(verify_discharge(&v, &v, &binding), DischargeVerdict::Fail { .. }));
        assert!(matches!(verify_narrow(&v, &v, &v, &NarrowBinding { now: 1, action_digest: None }), NarrowVerdict::Fail { .. }));
        assert!(bound_caveats(&v, &v).is_none());
        let r = evaluate_k1(&v, &v, Some(&K1Input::default()), &K1Ctx { now: 1, action: Some(&v) });
        assert!(!r.ok);
        assert_eq!(r.failed, vec!["<malformed>".to_string()]);
        assert_eq!(r.reasons, vec!["malformed capability chain".to_string()]);
        let (allow, failed) = evaluate_caveats_k1(&v, &v, Some(&K1Input::default()), &v);
        assert!(!allow && !failed.is_empty());
    }
}

#[test]
fn unsafe_clock_fails_closed() {
    let grant = json!({"caveats": [{"type": "sealed"}]});
    let r = evaluate_k1(&grant, &Value::Null, Some(&K1Input::default()), &K1Ctx { now: i64::MAX, action: None });
    assert_eq!(r.failed, vec!["<malformed>".to_string()]);
    assert_eq!(r.reasons, vec!["the verifier clock is not a safe integer (fail closed)".to_string()]);
    let store = MemoryStateStore::new();
    assert_eq!(
        reserve_max_uses(&store, &[], i64::MIN),
        UsesVerdict::Fail { reason: "the verifier clock is not a safe integer (fail closed)".into() }
    );
}

#[test]
fn k1_unconfigured_vectors() {
    let mut ran = 0;
    for e in table("k1_unconfigured") {
        let i = &e["input"];
        let (allow, failed) = evaluate_caveats_k1(&i["grant"], &i["chain"], None, &i["context"]);
        let want: Vec<String> = e["expect"]["failed"].as_array().unwrap().iter().map(|f| f.as_str().unwrap().to_string()).collect();
        assert_eq!((allow, failed), (e["expect"]["allow"].as_bool().unwrap(), want), "{}", e["name"]);
        ran += 1;
    }
    assert!(ran >= 8, "only {ran} k1_unconfigured vectors ran");
}

#[test]
fn no_k1_input_refuses_with_the_reason_and_an_empty_one_is_configured() {
    let grant = json!({"caveats": [{"type": "sealed"}]});
    let r = evaluate_k1(&grant, &Value::Null, None, &K1Ctx { now: 1, action: None });
    assert!(!r.ok);
    assert_eq!(r.failed, vec!["sealed".to_string()]);
    assert_eq!(r.reasons, vec!["the caveat language is not configured (no k1 input)".to_string()]);
    assert_eq!(r.bound.len(), 1);
    assert!(evaluate_k1(&grant, &Value::Null, Some(&K1Input::default()), &K1Ctx { now: 1, action: None }).ok);
}

#[test]
fn a_lone_sealed_root_is_satisfied_and_unknown_types_are_not() {
    let sealed = json!({"caveats": [{"type": "sealed"}]});
    let r = evaluate_k1(&sealed, &Value::Null, Some(&K1Input::default()), &K1Ctx { now: 1, action: None });
    assert!(r.ok && r.failed.is_empty() && r.plain.is_empty() && r.bound.len() == 1);
    let ctx = json!({"now": 1, "delegation_depth": 0, "action": {"verb": "v", "resource": "r", "params": {}}});
    assert_eq!(evaluate_caveats_k1(&sealed, &Value::Null, Some(&K1Input::default()), &ctx), (true, vec![]));
    let unknown = json!({"caveats": [{"type": "sealed"}, {"type": "from_the_future"}]});
    assert_eq!(evaluate_caveats_k1(&unknown, &Value::Null, Some(&K1Input::default()), &ctx), (false, vec!["from_the_future".to_string()]));
}

#[test]
fn ids_and_numbers_follow_the_strict_rules() {
    let nd = |id: &str, ttl: Value| {
        json!({"type": "needs_discharge", "id": id, "issuer": "i", "issuer_class": "human", "bind": "chain_hop", "ttl_ms": ttl, "require": []})
    };
    assert!(needs_discharge_error(&nd("kyc", json!(1))).is_none());
    assert!(needs_discharge_error(&nd("kyc\n", json!(1))).is_some(), "no trailing-newline tolerance");
    assert!(needs_discharge_error(&nd("KYC", json!(1))).is_some());
    assert!(needs_discharge_error(&nd("kyc", json!(1.5))).is_some());
    assert!(needs_discharge_error(&nd("kyc", json!(1e300))).is_some());
    assert!(needs_discharge_error(&nd("kyc", json!(true))).is_some());
    assert!(needs_discharge_error(&nd("kyc", json!("1"))).is_some());
    let long = "a".repeat(64);
    assert!(needs_discharge_error(&nd(&long, json!(1))).is_none());
    assert!(needs_discharge_error(&nd(&format!("{long}a"), json!(1))).is_some());
}

#[test]
fn string_bounds_are_utf8_bytes() {
    let req = |v: &str| {
        json!({"type": "needs_discharge", "id": "a", "issuer": "i", "issuer_class": "human", "bind": "chain_hop", "ttl_ms": 1,
               "require": [{"claim": "c", "op": "eq", "value": v}]})
    };
    assert!(needs_discharge_error(&req(&"a".repeat(256))).is_none());
    assert!(needs_discharge_error(&req(&"a".repeat(257))).is_some());
    // 129 two-byte characters are 258 bytes but only 129 characters
    assert!(needs_discharge_error(&req(&"\u{e9}".repeat(129))).is_some());
    assert!(needs_discharge_error(&req("")).is_some());
}

// ---- authorize integration: default off ---------------------------------------------------------------------------------

/// A chain without a K1 caveat behaves exactly as before, with or without an (empty) `k1` input.
#[test]
fn authorize_is_unchanged_without_a_k1_caveat() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/authorize-fixtures.json")).unwrap();
    let d = atlas_pca::strict_parse(&text).unwrap();
    let k1 = K1Input::default();
    let mut steps = 0;
    for c in d["cases"].as_array().unwrap() {
        let store = MemoryStateStore::new();
        let uses = MemoryStateStore::new();
        for s in c["steps"].as_array().unwrap() {
            let op = atlas_pca::Operation::from_json(&s["operation"]).unwrap();
            let revoked = s["revoked"].as_bool().unwrap_or(false);
            let g = c["grant"].clone();
            let resolve = move |_: &str| Ok::<_, String>(Some(g.clone()));
            let is_revoked = move |_: &Value, _: &Value| Ok::<_, String>(revoked);
            let input = atlas_pca::AuthorizeInput {
                operation: Some(&op),
                audience: d["audience"].as_str().unwrap(),
                resolve_grant: Some(&resolve),
                state_store: Some(&store),
                is_revoked: Some(&is_revoked),
                now: d["now"].as_i64(),
                plan: Some("single-step"),
                k1: Some(&k1),
                uses_store: Some(&uses),
                provenance_mediators: &common::harness_pins(),
                provenance_bundle: Some(&common::principal_direct),
                ..Default::default()
            };
            let r = atlas_pca::authorize(Some(&s["pcactn"]), &input);
            assert_eq!((r.allow, r.status as i64), (s["expect"]["allow"].as_bool().unwrap(), s["expect"]["status"].as_i64().unwrap()), "{}", c["name"]);
            steps += 1;
        }
    }
    assert!(steps >= 31, "only {steps} fixture steps ran");
}
