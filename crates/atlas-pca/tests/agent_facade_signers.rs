//! The agent facade and the agent-side signers, pinned to the TypeScript reference (facade.ts, mesh.ts, threshold.ts,
//! action-schema.ts, intent-session.ts): exact JSON shapes, exact refusal texts and the edges of the limit grammar.
mod common;

use atlas_pca::agent::*;
use atlas_pca::facade::{limit_amount, MAX_LIMIT_LENGTH};
use atlas_pca::serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

fn err<T: std::fmt::Debug>(r: Result<T, String>) -> String {
    r.expect_err("expected a refusal")
}

fn spec(verb: &str, connector: &str, action: &str, rev: &str) -> ActionSpec {
    ActionSpec {
        connector: connector.into(),
        action: action.into(),
        verb: verb.into(),
        reversibility: rev.into(),
        blast_radius: 0.5,
        amount_field: None,
        resource: None,
        aliases: vec![],
    }
}

fn compile(perms: Value, catalog: Option<&[ActionSpec]>, model: Option<&str>) -> CompiledPolicy {
    compile_policy(&CompileOptions {
        permissions: &perms,
        limits: None,
        catalog,
        budget_model: model,
        risk_policy: None,
        now: 0,
    })
    .unwrap()
}

fn handle(now: Option<i64>) -> AgentHandle {
    let p = KeyPair::from_seed(&[31u8; 32]);
    let perms = json!({"stripe": ["refund"], "gmail": ["draft"]});
    let limits = json!({"refund": "$500/day"});
    let mut o = AgentOptions::new(&p, "refund order 1", &perms);
    o.limits = Some(&limits);
    o.holder = Some(KeyPair::from_seed(&[32u8; 32]));
    o.aud = Some("rs-test");
    o.now = now;
    create_agent(o).unwrap()
}

// ---- facade: JSON shapes ------------------------------------------------------------------------------------------------------

#[test]
fn an_action_spec_serializes_with_the_reference_field_names() {
    let refund = spec_for(&builtin_catalog(), "stripe.refund");
    assert_eq!(
        refund.to_json(),
        json!({"connector": "stripe", "action": "refund", "verb": "stripe.refund", "reversibility": "irreversible", "blastRadius": 0.9,
            "amountField": "amount", "aliases": ["issue_refund", "refund", "refund_charge", "reimburse"]})
    );
    let mut s = spec("c.a", "c", "a", "reversible");
    s.blast_radius = 1.0;
    s.resource = Some("orders/*".into());
    assert_eq!(
        s.to_json(),
        json!({"connector": "c", "action": "a", "verb": "c.a", "reversibility": "reversible", "blastRadius": 1, "resource": "orders/*"})
    );
}

#[test]
fn a_dry_run_serializes_only_the_members_it_has() {
    assert_eq!(
        DryRun {
            allowed: false,
            reason: Some("no predicate matched".into()),
            t: None
        }
        .to_json(),
        json!({"allowed": false, "reason": "no predicate matched"})
    );
    assert_eq!(
        DryRun {
            allowed: true,
            reason: None,
            t: Some(2)
        }
        .to_json(),
        json!({"allowed": true, "t": 2})
    );
}

// ---- facade: compile ----------------------------------------------------------------------------------------------------------

#[test]
fn the_reversibility_cap_is_the_strictest_granted_class() {
    let c = compile(json!({"files": ["write"], "gmail": ["draft"]}), None, None);
    assert_eq!(
        c.caveats[0],
        json!({"type": "reversibility_max", "class": "rate_limited"})
    );
    assert_eq!(
        compile(json!({"gmail": ["draft"]}), None, None).caveats[0]["class"],
        "reversible"
    );
    assert_eq!(
        compile(json!({"gmail": ["draft", "send"]}), None, None).caveats[0]["class"],
        "irreversible"
    );
    // a class outside the order ranks below every known class (indexOf = -1): the cap stays 'reversible'
    let cat = [spec("x.y", "x", "y", "bogus")];
    assert_eq!(
        compile(json!({"x": ["y"]}), Some(&cat[..]), None).caveats[0]["class"],
        "reversible"
    );
}

#[test]
fn an_explicit_budget_model_wins_without_a_dollar_limit() {
    let c = compile(json!({"github": ["read"]}), None, Some("dollars"));
    assert_eq!(c.budget_model, "dollars");
    assert_eq!(
        c.risk_policy,
        default_risk_policy(),
        "no '$' limit: the default risk policy"
    );
    assert_eq!(
        compile(json!({"github": ["read"]}), None, Some("risk")).budget_model,
        "risk"
    );
    assert_eq!(
        compile(json!({"github": ["read"]}), None, None).budget_model,
        "risk"
    );
}

#[test]
fn spec_for_resolves_aliases_only_after_a_named_connector() {
    // a leading dot names no connector: no alias lookup, the conservative fallback
    let mut aliased = spec("z", "", "z", "reversible");
    aliased.aliases = vec!["x".into()];
    let s = spec_for(&[aliased], ".x");
    assert_eq!(
        (
            s.connector.as_str(),
            s.action.as_str(),
            s.verb.as_str(),
            s.reversibility.as_str(),
            s.blast_radius
        ),
        ("", "x", ".x", "irreversible", 0.8)
    );
    // an empty action after the dot falls back to the whole verb (rest.join('.') || verb)
    let s = spec_for(&builtin_catalog(), "crm.");
    assert_eq!((s.connector.as_str(), s.action.as_str()), ("crm", "crm."));
}

// ---- facade: parse_limit ------------------------------------------------------------------------------------------------------

#[test]
fn every_period_name_parses() {
    for (p, ms) in [
        ("s", 1000),
        ("sec", 1000),
        ("seconds", 1000),
        ("w", 604_800_000),
        ("week", 604_800_000),
        ("weeks", 604_800_000),
        ("min", 60_000),
        ("hr", 3_600_000),
        ("days", 86_400_000),
    ] {
        assert_eq!(
            parse_limit(&format!("5/{p}")).unwrap().period_ms,
            Some(ms),
            "{p}"
        );
    }
}

#[test]
fn the_length_cap_is_inclusive() {
    let at_cap = format!("1{}", " ".repeat(MAX_LIMIT_LENGTH - 1));
    assert_eq!(
        parse_limit(&at_cap).unwrap(),
        ParsedLimit {
            amount: 1.0,
            unit: "count",
            period_ms: None
        }
    );
    let over = format!("1{}", " ".repeat(MAX_LIMIT_LENGTH));
    assert_eq!(
        err(parse_limit(&over)),
        "parseLimit: limit is longer than 64 characters"
    );
}

#[test]
fn an_amount_needs_an_integer_part() {
    for bad in [".5", "$.5", "$ .5/day"] {
        assert_eq!(
            err(parse_limit(bad)),
            format!("parseLimit: cannot parse limit '{bad}'")
        );
    }
}

#[test]
fn a_zero_limit_is_an_amount() {
    assert_eq!(
        parse_limit("0").unwrap(),
        ParsedLimit {
            amount: 0.0,
            unit: "count",
            period_ms: None
        }
    );
    assert_eq!(
        parse_limit("$0.00/day").unwrap(),
        ParsedLimit {
            amount: 0.0,
            unit: "usd",
            period_ms: Some(86_400_000)
        }
    );
}

#[test]
fn the_amount_guard_refuses_non_finite_and_negative_amounts() {
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, -0.5] {
        assert_eq!(
            limit_amount(bad, "x"),
            Err("parseLimit: bad amount in 'x'".to_string()),
            "{bad}"
        );
    }
    assert_eq!(limit_amount(0.0, "x"), Ok(0.0));
    assert_eq!(limit_amount(2.5, "x"), Ok(2.5));
}

// ---- facade: the handle -------------------------------------------------------------------------------------------------------

#[test]
fn the_autonomy_bound_is_b_max_over_kappa_times_kappa() {
    // one '$500/day' limit: kappa = bMax = 500, safetyBound = 1
    assert_eq!(handle(Some(1_800_000_000_000)).autonomy_bound, 500.0);
}

#[test]
fn the_claimed_risk_is_amount_over_kappa_else_the_blast_radius() {
    let a = handle(Some(1_800_000_000_000));
    let o = ActOptions {
        now: Some(1_800_000_000_100),
        ..ActOptions::default()
    };
    // no amount: Number(undefined) is NaN, so the catalogue's blast radius
    let r = a.act("stripe.refund", "charge:ch_1", None, &o).unwrap();
    assert_eq!(
        r.pcactn["risk_claim"],
        json!({"r": 0.9, "inputs": {"blastRadius": 0.9}})
    );
    let r = a
        .act(
            "stripe.refund",
            "charge:ch_1",
            Some(&json!({"amount": 125})),
            &o,
        )
        .unwrap();
    assert_eq!(r.pcactn["risk_claim"]["r"], json!(0.25));
}

#[test]
fn a_caution_is_signed_into_the_action_only_when_given() {
    let a = handle(Some(1_800_000_000_000));
    let now = Some(1_800_000_000_100);
    let c = a
        .act(
            "gmail.draft",
            "t",
            None,
            &ActOptions {
                now,
                caution: Some(0.5),
                ..ActOptions::default()
            },
        )
        .unwrap();
    assert_eq!(c.pcactn["caution"], json!(0.5));
    assert!(a
        .act(
            "gmail.draft",
            "t",
            None,
            &ActOptions {
                now,
                ..ActOptions::default()
            }
        )
        .unwrap()
        .pcactn
        .get("caution")
        .is_none());
}

#[test]
fn the_default_clock_is_the_system_clock() {
    let ms = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    };
    let before = ms();
    let a = handle(None);
    let r = a
        .act("gmail.draft", "t", None, &ActOptions::default())
        .unwrap();
    let after = ms();
    assert!(
        (before as f64) <= a.budget.tau && a.budget.tau <= (after as f64),
        "budget tau {} not in [{before}, {after}]",
        a.budget.tau
    );
    let iat = r.pcactn["iat"].as_i64().unwrap();
    assert!(
        before <= iat && iat <= after,
        "iat {iat} not in [{before}, {after}]"
    );
}

#[cfg(feature = "fndsa-sign")]
#[test]
fn a_sign_seed_applies_to_fn_dsa_only() {
    let k = PqKeyPair::from_seed("ML-DSA-65", &[1u8; 32]).unwrap();
    assert_eq!(
        err(k.with_fn_dsa_sign_seed([0u8; 32])),
        "a sign seed applies to FN-DSA only, not ML-DSA-65"
    );
    assert!(PqKeyPair::from_seed("FN-DSA-512", &[2u8; 32])
        .unwrap()
        .with_fn_dsa_sign_seed([0u8; 32])
        .is_ok());
}

// ---- signers ------------------------------------------------------------------------------------------------------------------

#[test]
fn only_a_registered_non_ed25519_suite_tags_a_share() {
    let k = KeyPair::from_seed(&[2u8; 32]);
    let set = vec![json!({"publicKey": k.public, "role": "guardian"})];
    let plain = share_message("guardian", b"m", &set, 2, None).unwrap();
    assert_eq!(
        share_message("guardian", b"m", &set, 2, Some("ed25519")).unwrap(),
        plain
    );
    assert_eq!(
        share_message("guardian", b"m", &set, 2, Some("rot13")).unwrap(),
        plain
    );
    let mut tagged = plain.clone();
    tagged.extend(b"\0atlas-pca/share-suite/v1\0ml-dsa-65");
    assert_eq!(
        share_message("guardian", b"m", &set, 2, Some("ml-dsa-65")).unwrap(),
        tagged
    );
}

#[test]
fn a_mesh_proof_shares_heads_and_revocation_leaves() {
    let leaf = KeyPair::from_seed(&[5u8; 32]);
    let chain = vec![json!({"id": "c0"})];
    let action = json!({"verb": "read", "resource": "r"});
    let head = json!({"domain": "d", "size": 4});
    let hops = vec![
        json!({"domain": "d1", "head": {"head": head, "sig": "s1", "cosigs": [{"witness": "w1", "sig": "a"}]}, "inclusion": {"i": 1},
            "revocation": {"cap": {"size": 3, "lo": {"k": 1, "v": 2}, "hi": null}, "issuer_key": {"size": 2, "lo": {"v": 2, "k": 1}, "hi": {"k": 2}}}, "binding": {"b": 1}}),
        // the same head in another member order; one more cosig, one already held
        json!({"domain": "d2", "head": {"head": {"size": 4, "domain": "d"}, "sig": "s1", "cosigs": [{"witness": "w1", "sig": "b"}, {"witness": "w2", "sig": "c"}]}, "inclusion": {"i": 2},
            "revocation": {"cap": {"size": 1, "hi": {"k": 2}}, "issuer_key": {"size": 0, "lo": false}}, "binding": null}),
        json!({"domain": "d3", "head": {"head": head, "sig": "s2", "cosigs": []}, "inclusion": {"i": 3},
            "revocation": {"cap": {"size": 5, "lo": {"k": 3}}, "issuer_key": {"size": 5, "lo": {"k": 3}, "hi": {"k": 3}}}}),
    ];
    let pins = vec![json!({"domain": "d1", "proof": {"p": 1}})];
    let got = assemble_mesh_proof(&chain, &hops, &action, &leaf, Some(&pins[..])).unwrap();
    let want = json!({
        "chain": chain, "action": action, "action_sig": sign_mesh_action(&chain, &action, &leaf).unwrap(),
        "heads": [{"head": head, "sig": "s1", "cosigs": [{"witness": "w1", "sig": "a"}, {"witness": "w2", "sig": "c"}]}, {"head": head, "sig": "s2", "cosigs": []}],
        "rev_leaves": [{"k": 1, "v": 2}, {"k": 2}, {"k": 3}],
        "hops": [
            {"domain": "d1", "head": 0, "inclusion": {"i": 1}, "revocation": {"cap": {"size": 3, "lo": 0}, "issuer_key": {"size": 2, "lo": 0, "hi": 1}}, "binding": {"b": 1}},
            {"domain": "d2", "head": 0, "inclusion": {"i": 2}, "revocation": {"cap": {"size": 1, "hi": 1}, "issuer_key": {"size": 0}}},
            {"domain": "d3", "head": 1, "inclusion": {"i": 3}, "revocation": {"cap": {"size": 5, "lo": 2}, "issuer_key": {"size": 5, "lo": 2, "hi": 2}}}
        ],
        "pin_proofs": pins
    });
    assert_eq!(got, want);
    let none: Vec<Value> = vec![];
    assert!(
        assemble_mesh_proof(&chain, &hops, &action, &leaf, Some(&none[..]))
            .unwrap()
            .get("pin_proofs")
            .is_none(),
        "an empty pin-proof list is not carried"
    );
}

#[test]
fn a_session_root_is_shape_checked_once_signed() {
    let k = KeyPair::from_seed(&[2u8; 32]);
    assert_eq!(
        err(sign_session_root(
            &k,
            &json!({"principals": [{"key": k.public}]}),
            &Suite::default()
        )),
        "signSessionRoot: not a pca-intent-session v1"
    );
}

#[test]
fn an_action_schema_is_shape_checked_before_and_after_signing() {
    let pv = common::load("producer-vectors.json");
    let doc = pv["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["op"] == "sign_action_schema")
        .unwrap()["args"]["doc"]
        .clone();
    let site = KeyPair::from_seed(&[61u8; 32]);
    let d = Suite::default();
    let mut with_sig = doc.clone();
    with_sig["sig"] = json!({"alg": "ed25519", "kid": "k", "value": "AA"});
    assert_eq!(
        err(sign_action_schema(&with_sig, "site-k1", &site, &d)),
        "signActionSchema: an unsigned schema must not carry sig"
    );
    // the signed document must pass the verifier's shape check: a kid it would refuse is refused here
    assert_eq!(
        err(sign_action_schema(&doc, "", &site, &d)),
        "signActionSchema: sig.kid must be a non-empty string"
    );
    assert_eq!(
        err(sign_action_schema(&doc, &"k".repeat(129), &site, &d)),
        "signActionSchema: sig.kid must be a non-empty string"
    );
    // a hybrid suite carries its post-quantum signature; ed25519 carries none
    let pq = PqKeyPair::from_seed("ML-DSA-65", &[9u8; 32]).unwrap();
    let out = sign_action_schema(
        &doc,
        "site-k1",
        &site,
        &Suite {
            alg: Some("hybrid-ed25519-ml-dsa-65"),
            pq: Some(&pq),
        },
    )
    .unwrap();
    assert_eq!(out["sig"]["alg"], "hybrid-ed25519-ml-dsa-65");
    assert!(
        out["sig"]["pq_value"]
            .as_str()
            .is_some_and(|v| !v.is_empty()),
        "{}",
        out["sig"]
    );
    assert!(
        sign_action_schema(&doc, "site-k1", &site, &d).unwrap()["sig"]
            .get("pq_value")
            .is_none()
    );
}
