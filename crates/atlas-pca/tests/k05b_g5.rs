//! Kill tests for the 0.5 full mutation run, group g5: lib.rs (caveat cap, u64 canonical form), blueprint, allowlist anchor,
//! JWS parsing, read vault, action-pack shape.
mod common;
use atlas_pca::actions_registry::pack_shape_error;
use atlas_pca::agent::{sign_aggregate_grant, sign_artifact, KeyPair, Suite};
use atlas_pca::attest::jws::{js_json_error, parse_jws};
use atlas_pca::blueprint::{verify_blueprint, BlueprintRegistry, AGENT_BLUEPRINT_DOMAIN};
use atlas_pca::read_vault::{aggregate_read, empty_aggregate_state, seeded_draws, SamplerError};
use atlas_pca::serde_json::{json, Value};
use atlas_pca::{canonicalize, hash_canonical_strict, merkle_root, verify_allowlist_anchored, verify_chain_policy, verify_pcactn_core_with, AnchorEntry, AnchorOptions, CAVEAT_LIMIT_REASON};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

// ---- lib.rs ----------------------------------------------------------------------------------------------------------

fn vec_named(name: &str) -> Value {
    let doc = common::load("vectors.json");
    doc["vectors"].as_array().unwrap().iter().find(|v| v["name"].as_str() == Some(name)).cloned().expect("vector")
}

fn many(n: usize) -> Value {
    Value::Array((0..n).map(|_| json!({"type": "x"})).collect())
}

/// 257 caveats on the root hop break the per-hop cap: the chain check reports the cap (not "root is not the grant", which is
/// what the next test of the chain would say), the reason list carries it, and `verify_chain_policy` refuses with it first.
#[test]
fn the_caveat_cap_is_reported_by_the_core_and_by_verify_chain_policy() {
    let v = vec_named("valid-in-plan-action");
    let now = v["context"]["now"].as_i64().unwrap();
    let aud = v["context"]["aud"].as_str().unwrap();
    let ok = verify_pcactn_core_with(&v["pcactn"], &v["grant"], now, aud, &atlas_pca::VerifyOptions { insecure_skip_plan_root_check: true, ..atlas_pca::VerifyOptions::default() });
    assert!(ok.allow, "{}", ok.reason);
    assert!(ok.reasons.is_empty());

    let mut p = v["pcactn"].clone();
    p["cap_chain"][0]["caveats"] = many(257);
    let got = verify_pcactn_core_with(&p, &v["grant"], now, aud, &atlas_pca::VerifyOptions { insecure_skip_plan_root_check: true, ..atlas_pca::VerifyOptions::default() });
    let want = format!("chain: {CAVEAT_LIMIT_REASON}");
    assert!(!got.allow);
    assert_eq!(got.checks.get("chain"), Some(&false));
    assert_eq!(got.reason, want);
    assert_eq!(got.reasons, vec![want]);

    let chain = [p["cap_chain"][0].clone()];
    assert_eq!(verify_chain_policy(&chain, None, None, None, None), Err(CAVEAT_LIMIT_REASON.to_string()));
}

/// A u64 above 2^53 prints as the double JSON.parse gives (hash.ts lenient form = ECMAScript Number::toString); see k05f_lenient_numbers.rs.
#[test]
fn a_u64_above_i64_max_canonicalizes_as_its_double() {
    assert_eq!(canonicalize(&json!(u64::MAX)), "18446744073709552000");
    assert_eq!(canonicalize(&json!(9_223_372_036_854_775_808u64)), "9223372036854776000");
}

// ---- blueprint -------------------------------------------------------------------------------------------------------

fn signed_bp(k: &KeyPair, over: Value, drop: &[&str]) -> Value {
    let mut b = json!({"v": 1, "id": "fleet", "key": "bp-key", "ceiling": [], "epoch": 1, "status": "active", "issued_at": 1_800_000_000_000i64, "operator": k.public});
    for (key, v) in over.as_object().unwrap() {
        b[key.as_str()] = v.clone();
    }
    for d in drop {
        b.as_object_mut().unwrap().remove(*d);
    }
    sign_artifact(AGENT_BLUEPRINT_DOMAIN, &b, k, &Suite::default()).unwrap()
}

/// blueprint.ts wellFormed: each member is checked on its own; every record below is validly signed over exactly its content.
#[test]
fn a_validly_signed_blueprint_with_a_bad_member_is_refused() {
    let k = KeyPair::from_seed(&[5u8; 32]);
    assert!(verify_blueprint(&signed_bp(&k, json!({}), &[])));
    assert!(verify_blueprint(&signed_bp(&k, json!({"epoch": 0, "max_depth": 1, "expires_at": 0}), &[])));
    for over in [json!({"key": ""}), json!({"epoch": -1}), json!({"issued_at": -1}), json!({"max_depth": 0}), json!({"expires_at": -1})] {
        assert!(!verify_blueprint(&signed_bp(&k, over.clone(), &[])), "{over}");
    }
    for gone in ["key", "epoch", "issued_at"] {
        assert!(!verify_blueprint(&signed_bp(&k, json!({}), &[gone])), "{gone} missing");
    }
}

/// blueprint.ts: a key's record can only be replaced by the same operator, even with a higher epoch.
#[test]
fn a_blueprint_key_cannot_change_operator() {
    let (a, b) = (KeyPair::from_seed(&[5u8; 32]), KeyPair::from_seed(&[6u8; 32]));
    let reg = BlueprintRegistry::new(vec![a.public.clone(), b.public.clone()], std::sync::Arc::new(atlas_pca::blueprint::MemoryBlueprintStore::new()));
    assert_eq!(reg.accept(&signed_bp(&a, json!({}), &[])), Ok(true));
    assert_eq!(reg.accept(&signed_bp(&b, json!({"epoch": 2}), &[])), Err("operator_changed"));
    assert_eq!(reg.accept(&signed_bp(&a, json!({"epoch": 2}), &[])), Ok(true));
}

// ---- allowlist anchor ------------------------------------------------------------------------------------------------

const NOW: i64 = 1_000_000;
const ANCHOR_DOMAIN: &str = "pca-attest-allowlist-anchor/v1";

fn digest() -> String {
    "A".repeat(42) + "_"
}
fn entry_json(iss: &str, ver: i64) -> Value {
    json!({"issuer": iss, "version": ver, "digest": digest()})
}
fn commit(iss: &str, ver: i64) -> Value {
    Value::String(hash_canonical_strict(&json!({"domain": ANCHOR_DOMAIN, "issuer": iss, "version": ver, "digest": digest()})).unwrap())
}
fn head(log: &KeyPair, size: i64, root: &str, alg: bool) -> Value {
    let body = json!({"instance_id": "inst", "principal": "prin", "size": size, "root": root, "prev_root": "prev", "timestamp": NOW});
    let mut h = sign_artifact("atlas-pca/sth/v1\0", &body, log, &Suite::default()).unwrap();
    h["guardian"] = json!(log.public);
    if alg {
        h["alg"] = json!("ed25519");
    }
    h
}
fn run(log: &KeyPair, mine: &AnchorEntry, ev: &Value) -> Result<i64, &'static str> {
    verify_allowlist_anchored(
        mine,
        Some(ev),
        &AnchorOptions { log_key: &log.public, instance_id: "inst", principal: "prin", now_ms: NOW, max_head_age_ms: None, clock_skew_ms: None, cached_head: None },
    )
}
fn mine() -> AnchorEntry {
    AnchorEntry { issuer: "iss".into(), version: 1, digest: digest() }
}

/// A head naming any `alg` is `bad-head` natively, even when the Ed25519 signature over its six fields verifies.
#[test]
fn a_head_that_names_an_alg_is_refused() {
    let log = KeyPair::from_seed(&[9u8; 32]);
    let root = merkle_root(&[commit("iss", 1)]).unwrap();
    let ev = |alg: bool| json!({"head": head(&log, 1, &root, alg), "entries": [entry_json("iss", 1)], "proof": {"index": 0, "size": 1, "path": []}});
    assert_eq!(run(&log, &mine(), &ev(false)), Ok(1));
    assert_eq!(run(&log, &mine(), &ev(true)), Err("bad-head"));
}

/// A signed head of size 3 over the EMPTY root, with no entries supplied: the feed does not match the signed size. (Without the
/// size check the empty feed would hash to the head's root and the failure would surface later as `bad-proof`.)
#[test]
fn a_feed_shorter_than_the_signed_size_is_a_feed_mismatch_even_when_it_hashes_to_the_root() {
    let log = KeyPair::from_seed(&[9u8; 32]);
    let empty = URL_SAFE_NO_PAD.encode(Sha256::digest(b""));
    let ev = json!({"head": head(&log, 3, &empty, false), "entries": [], "proof": {"index": 0, "size": 3, "path": []}});
    assert_eq!(run(&log, &mine(), &ev), Err("feed-mismatch"));
}

/// The proof's `size` must be the head's. Index 0 of a 3-leaf and a 4-leaf tree have the same path shape (R, R), so the honest
/// 3-leaf path also verifies when the proof claims size 4: only the explicit size check refuses it.
#[test]
fn a_proof_claiming_another_size_is_refused_even_when_its_path_still_verifies() {
    let log = KeyPair::from_seed(&[9u8; 32]);
    let cs = [commit("iss", 1), commit("o1", 1), commit("o2", 1)];
    let root = merkle_root(&cs).unwrap();
    let leaf = |c: &Value| merkle_root(&[c.clone()]).unwrap();
    let ev = |size: i64| {
        json!({
            "head": head(&log, 3, &root, false),
            "entries": [entry_json("iss", 1), entry_json("o1", 1), entry_json("o2", 1)],
            "proof": {"index": 0, "size": size, "path": [{"side": "R", "hash": leaf(&cs[1])}, {"side": "R", "hash": leaf(&cs[2])}]},
        })
    };
    assert_eq!(run(&log, &mine(), &ev(3)), Ok(1));
    assert_eq!(run(&log, &mine(), &ev(4)), Err("bad-proof"));
}

// ---- attest/jws ------------------------------------------------------------------------------------------------------

#[test]
fn an_empty_token_is_named_as_such() {
    assert_eq!(parse_jws("", "parseMaaJwt").err(), Some("parseMaaJwt: empty token".to_string()));
}

/// V8 reports text after a complete value as a position, not as an unexpected token.
#[test]
fn trailing_characters_read_like_v8() {
    let text = "{} x";
    let err = atlas_pca::serde_json::from_str::<Value>(text).unwrap_err();
    assert_eq!(js_json_error(text, &err), "Unexpected non-whitespace character after JSON at position 3");
}

// ---- read vault ------------------------------------------------------------------------------------------------------

/// The sampler's rate numerator must be at least 1 (it is the divisor of the result).
#[test]
fn discrete_laplace_refuses_a_non_positive_rate() {
    let mut d = seeded_draws("rate");
    assert_eq!(d.discrete_laplace(0, 1_000_000), Err(SamplerError));
    assert_eq!(d.discrete_laplace(-5, 1_000_000), Err(SamplerError));
}

/// `noise: "secure"` seeds the sampler from the OS: the same read answers differently each time (scale about 1e6), while
/// `seeded` is deterministic.
#[test]
fn secure_aggregate_noise_is_fresh_per_read() {
    let k = KeyPair::from_seed(&[1u8; 32]);
    let body = json!({"v": 1, "id": "g1", "principal": k.public, "issued_at": 100, "expires_at": 200,
        "rules": [{"verb": "read", "resource_prefix": "r/", "purposes": ["audit"], "fns": ["count", "sum"], "min_group": 1, "clamp": 1000, "epsilon_micro": 1000, "dp": true}],
        "epsilon_budget_micro": 1_000_000, "max_queries": 5});
    let grant = sign_aggregate_grant(&k, &body).unwrap();
    let read = |noise: &str| {
        aggregate_read(&json!({"grant": grant, "principal": k.public, "now": 150, "verb": "read", "resource": "r/1", "purpose": "audit", "fn": "sum",
            "values": [1, 2, 3], "salt": "0123456789abcdef", "noise": noise, "state": empty_aggregate_state()}))
    };
    let (s1, s2) = (read("seeded"), read("seeded"));
    assert_eq!((s1.code, s1.charged_micro), (None, 1000));
    assert!(s1.value.is_some());
    assert_eq!(s1.value, s2.value);
    let vals: Vec<Option<i64>> = (0..3).map(|_| read("secure").value).collect();
    assert!(vals.iter().all(Option::is_some), "{vals:?}");
    assert!(vals.iter().any(|v| *v != vals[0]), "three secure reads answered identically: {vals:?}");
}

// ---- action pack -----------------------------------------------------------------------------------------------------

/// A def that fits its own depth cap (32) can still push the pack past it: the pack is canonicalized as a whole.
#[test]
fn a_pack_whose_def_nests_past_the_pack_depth_cap_is_refused() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packages/pca-conformance/vectors/actions/pack-verify-honest.json");
    let case: Value = atlas_pca::serde_json::from_str(&common::sanitize_lone_surrogates(&std::fs::read_to_string(path).expect("pack vector"))).unwrap();
    let mut pack = case["input"]["pack"].clone();
    assert_eq!(pack_shape_error(&pack), None);
    let nest = |levels: usize| {
        let mut v = json!({});
        for _ in 0..levels {
            v = json!({"k": v});
        }
        v
    };
    pack["defs"][0]["examples"][0]["params"] = nest(20);
    assert_eq!(pack_shape_error(&pack), None);
    pack["defs"][0]["examples"][0]["params"] = nest(28);
    assert_eq!(pack_shape_error(&pack), Some("pack: canonicalize: nesting too deep".to_string()));
}
