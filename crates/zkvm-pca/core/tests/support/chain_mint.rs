//! Deterministic minting of signed capability chains and fully bound PCActns for the R3-11/12/13
//! regression tests and for the host's negative proving matrix (`#[path]`-included by both, so the unit
//! tests and the zkVM guest see byte-identical variants). Keys follow `host/src/mint.rs`:
//! root = key(1), first holder = key(2), leaf holder = key(3).
#![allow(dead_code)]
use ed25519_dalek::{Signer, SigningKey};
use pca_zkvm_core::canonical::canonical_bytes;
use pca_zkvm_core::chain::{CAP_DOMAIN, SIG_DOMAIN};
use pca_zkvm_core::commit::{b64u, hash_canonical, plan_commitment, sha256};
use serde_json::{json, Value};

pub fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
pub fn pk(k: &SigningKey) -> String {
    b64u(&k.verifying_key().to_bytes())
}

/// One signed capability hop `signer -> holder`.
pub fn hop(signer: &SigningKey, holder: &SigningKey, caveats: &Value, parent: Option<&Value>) -> Value {
    let parent_hash = parent.map(hash_canonical);
    let body = json!({"issuer": pk(signer), "holder": pk(holder), "caveats": caveats, "parent": parent_hash});
    let d = sha256(&canonical_bytes(&body));
    let dig = b64u(&d);
    let mut msg = CAP_DOMAIN.to_vec();
    msg.extend_from_slice(&d);
    let sig = b64u(&signer.sign(&msg).to_bytes());
    let mut o = json!({"id": dig, "issuer": pk(signer), "holder": pk(holder), "caveats": caveats, "body_digest": dig, "sig": sig});
    if let Some(p) = parent_hash {
        o["parent"] = json!(p);
    }
    o
}

/// Re-sign `v["pcactn"]` with `leaf` so a deny can only come from the binding checks.
pub fn resign(v: &mut Value, leaf: &SigningKey) {
    let mut body = v["pcactn"].clone();
    body.as_object_mut().unwrap().remove("sig");
    let d = sha256(&canonical_bytes(&body));
    let mut msg = SIG_DOMAIN.to_vec();
    msg.extend_from_slice(&d);
    v["pcactn"]["sig"] = json!(b64u(&leaf.sign(&msg).to_bytes()));
}

/// Replace the chain of a decide-input (a minted fixture shape) with `chain` and re-bind + re-sign the PCActn:
/// grant = chain[0], `pcactn.cap_chain` = chain, `pcactn.grant_ref` = chain[0].id, signed by `leaf`.
pub fn with_chain(base: &Value, chain: Vec<Value>, leaf: &SigningKey) -> Value {
    let mut v = base.clone();
    v["grant"] = chain[0].clone();
    v["chain"] = json!(chain);
    v["pcactn"]["cap_chain"] = json!(chain);
    v["pcactn"]["grant_ref"] = chain[0]["id"].clone();
    resign(&mut v, leaf);
    v
}

/// Root envelope-bearing caveat list of the minted fixture.
pub fn root_caveats(base: &Value) -> Vec<Value> {
    base["grant"]["caveats"].as_array().unwrap().clone()
}

/// root(key1) -> key2 -> key3 (leaf holder). Hop 1 appends `extra` caveats to the root list.
pub fn two_hop(base: &Value, extra: Vec<Value>) -> Vec<Value> {
    let c0 = json!(root_caveats(base));
    let mut c1 = root_caveats(base);
    c1.extend(extra);
    let g0 = hop(&key(1), &key(2), &c0, None);
    let g1 = hop(&key(2), &key(3), &json!(c1), Some(&g0));
    vec![g0, g1]
}

/// A 3-hop chain root(key1) -> key2 -> key4 -> key3 whose ROOT envelope has `delegation_depth` max = `max`
/// (the root hop differs from the fixture's, so grant/chain/pcactn are all re-minted).
pub fn three_hop_with_depth_max(base: &Value, max: u64) -> Vec<Value> {
    let mut caveats = root_caveats(base);
    for c in caveats.iter_mut() {
        if c["type"] == "envelope" {
            for cv in c["caveats"].as_array_mut().unwrap() {
                if cv["type"] == "delegation_depth" {
                    cv["max"] = json!(max);
                }
            }
        }
    }
    let c = json!(caveats);
    let g0 = hop(&key(1), &key(2), &c, None);
    let g1 = hop(&key(2), &key(4), &c, Some(&g0));
    let g2 = hop(&key(4), &key(3), &c, Some(&g1));
    vec![g0, g1, g2]
}

/// The R3-11/12/13 variants a correct guest must DENY, all with a VALID signature chain and VALID PCActn
/// signature, so the only possible cause is the new check. `(name, input, restoring_group)`.
pub fn r3_variants(base: &Value) -> Vec<(&'static str, Value, &'static str)> {
    let leaf = key(3);
    let mut out: Vec<(&'static str, Value, &'static str)> = Vec::new();
    out.push((
        "r3_11_delegated_expired_caveat",
        with_chain(base, two_hop(base, vec![json!({"type": "expires", "at": 1_700_000_000_000u64})]), &leaf),
        "delegation",
    ));
    out.push((
        "r3_11_delegated_blast_radius_narrowing",
        with_chain(base, two_hop(base, vec![json!({"type": "max_blast_radius", "max": 0.01})]), &leaf),
        "delegation",
    ));
    out.push((
        "r3_12_three_hops_under_max_depth_1",
        {
            // the prover also claims depth 0; irrelevant, the guest derives chain.len()-1 = 2
            let mut v = with_chain(base, three_hop_with_depth_max(base, 1), &leaf);
            v["delegation_depth"] = json!(0);
            v
        },
        "delegation",
    ));
    out.push((
        "r3_13_pcactn_grant_ref_bogus",
        {
            let mut v = base.clone();
            v["pcactn"]["grant_ref"] = json!("not-the-grant");
            resign(&mut v, &leaf);
            v
        },
        "pcactn",
    ));
    out.push((
        "r3_13_pcactn_plan_node_other",
        {
            let mut v = base.clone();
            v["pcactn"]["plan"]["node_id"] = json!("n2");
            resign(&mut v, &leaf);
            v
        },
        "pcactn",
    ));
    out.push((
        "r3_13_pcactn_plan_root_wrong",
        {
            let mut v = base.clone();
            v["pcactn"]["plan"]["root"] = json!("AAAA");
            resign(&mut v, &leaf);
            v
        },
        "pcactn",
    ));
    out.push((
        "r3_13_pcactn_signed_for_other_action",
        {
            let mut v = base.clone();
            v["pcactn"]["action"]["params"]["limit"] = json!(60);
            resign(&mut v, &leaf);
            v
        },
        "pcactn",
    ));
    out.push((
        "r3_13_input_action_differs_from_signed_action",
        {
            let mut v = base.clone();
            v["action"]["params"]["limit"] = json!(60);
            v
        },
        "action",
    ));
    out.push((
        "r3_13_pcactn_carries_other_chain",
        {
            let mut v = base.clone();
            v["pcactn"]["cap_chain"] = json!(two_hop(base, vec![json!({"type": "max_blast_radius", "max": 0.4})]));
            resign(&mut v, &leaf);
            v
        },
        "pcactn",
    ));
    out.push((
        "r3_13_tool_binding_not_signed",
        {
            let mut v = base.clone();
            v["tool_binding"] = json!("3rdLEXkqzaXOqZYVuCgMwOJ9UD-S2pPeWQruzSjfzHZ");
            v
        },
        "toolbinding",
    ));
    let _ = plan_commitment; // keep the import used for downstream tests
    out
}

/// The R4-03 / R4-04 variants a correct guest must DENY, all with a VALID signature chain and a VALID PCActn signature
/// (the PCActn is re-signed after each edit), so the only possible cause is the new check. `(name, input, restoring_group)`.
pub fn r4_variants(base: &Value) -> Vec<(&'static str, Value, &'static str)> {
    let leaf = key(3);
    let edited = |f: &dyn Fn(&mut Value)| {
        let mut v = base.clone();
        f(&mut v);
        resign(&mut v, &leaf);
        v
    };
    let iat = base["pcactn"]["iat"].as_u64().unwrap();
    let exp = base["pcactn"]["exp"].as_u64().unwrap();
    vec![
        // R4-04: the grant is still valid at this `now`, the PCActn is not
        ("r4_04_pcactn_expired_grant_still_valid", edited(&|v| v["now"] = json!(exp + 1)), "clock"),
        ("r4_04_pcactn_iat_beyond_skew", edited(&|v| v["now"] = json!(iat - 60_001)), "clock"),
        ("r4_04_pcactn_lifetime_over_one_hour", edited(&|v| v["pcactn"]["exp"] = json!(iat + 3_600_001)), "pcactn"),
        ("r4_04_pcactn_exp_not_after_iat", edited(&|v| v["pcactn"]["exp"] = json!(iat)), "pcactn"),
        ("r4_04_pcactn_wrong_version", edited(&|v| v["pcactn"]["ver"] = json!(1)), "pcactn"),
        ("r4_04_pcactn_aud_empty", edited(&|v| v["pcactn"]["aud"] = json!("")), "pcactn"),
        ("r4_04_pcactn_counter_negative", edited(&|v| v["pcactn"]["counter"] = json!(-1)), "pcactn"),
        ("r4_04_pcactn_exp_missing", edited(&|v| { v["pcactn"].as_object_mut().unwrap().remove("exp"); }), "pcactn"),
        // R4-03: a delegator appended a malformed tool_schema restriction; it was silently "satisfied" before
        (
            "r4_03_delegated_malformed_tool_schema",
            with_chain(base, two_hop(base, vec![json!({"type": "tool_schema", "tool": "read"})]), &leaf),
            "delegation",
        ),
    ]
}

/// A `tool_schema` caveat for tool `read` bound to the fixture's signed `tool_binding`, with correct digests.
pub fn tool_schema_caveat(base: &Value, schema: Value) -> Value {
    let sig = base["tool_binding"].as_str().unwrap().to_string();
    let binding = json!({ "tool": "read", "signature_digest": sig, "schema": schema });
    json!({ "type": "tool_schema", "tool": "read", "signature_digest": sig, "schema": schema,
            "schema_digest": hash_canonical(&schema), "binding_digest": hash_canonical(&binding) })
}

/// The schema of the fixture's own `tool_schema` caveat (acct: string with prefix, limit: integer 1..100), with `acct`/`limit` edits.
pub fn fixture_schema(acct_extra: Value, limit_extra: Value) -> Value {
    let mut acct = json!({ "type": "string", "prefix": "acct_" });
    let mut limit = json!({ "type": "integer", "min": 1, "max": 100 });
    for (t, e) in [(&mut acct, acct_extra), (&mut limit, limit_extra)] {
        if let Some(m) = e.as_object() {
            for (k, v) in m {
                t[k] = v.clone();
            }
        }
    }
    json!({ "props": { "acct": acct, "limit": limit }, "required": ["limit", "acct"] })
}

/// A delegated `predicates` caveat with `misses` `matches` conditions that MISS (each is one charged regex evaluation) followed by a
/// predicate whose resource is the `re:` pattern that matches the fixture's action.
pub fn matches_budget_caveat(misses: usize) -> Value {
    let mut allow: Vec<Value> = (0..misses)
        .map(|i| json!({ "verb": "read", "where": [{ "field": "action.params.acct", "op": "matches", "value": format!("zz{i}[0-9]+") }] }))
        .collect();
    allow.push(json!({ "verb": "read", "resource": "re:/acct/[0-9]+/items" }));
    json!({ "type": "predicates", "allow": allow })
}

/// `n` benign delegated caveats (`expires` far in the future), each satisfied at the fixture's `now`.
pub fn benign_caveats(n: usize) -> Vec<Value> {
    (0..n).map(|_| json!({ "type": "expires", "at": 1_760_010_000_000u64 })).collect()
}

/// R5-ZK-01/03/04 variants a correct guest must DENY, all validly signed (only the new checks can be the cause).
/// `(name, input, restoring_group)`. Names with the `r5_wire_`/`r5_cap_` prefix are refused before chain verification
/// (`chain_verified == 0`).
pub fn r5_variants(base: &Value) -> Vec<(&'static str, Value, &'static str)> {
    let leaf = key(3);
    let delegated = |c: Value| with_chain(base, two_hop(base, vec![c]), &leaf);
    vec![
        // R5-ZK-01: malformed scalar bounds used to be DROPPED (defaulted), so the caveat was silently satisfied
        ("r5_01_delegated_maxlength_not_a_number", delegated(tool_schema_caveat(base, fixture_schema(json!({ "maxLength": "abc" }), json!({})))), "delegation"),
        ("r5_01_delegated_minlength_fractional", delegated(tool_schema_caveat(base, fixture_schema(json!({ "minLength": 1.5 }), json!({})))), "delegation"),
        ("r5_01_delegated_prefix_not_a_string", delegated(tool_schema_caveat(base, fixture_schema(json!({ "prefix": 7 }), json!({})))), "delegation"),
        ("r5_01_delegated_max_not_a_number", delegated(tool_schema_caveat(base, fixture_schema(json!({}), json!({ "max": "100" })))), "delegation"),
        ("r5_01_delegated_min_above_max", delegated(tool_schema_caveat(base, fixture_schema(json!({}), json!({ "min": 200 })))), "delegation"),
        // R5-ZK-03: strict canonical profile / size / caveat caps
        ("r5_03_delegated_unsafe_integer_in_schema", delegated(tool_schema_caveat(base, fixture_schema(json!({}), json!({ "max": 18014398509481984u64 })))), "delegation"),
        // (R6-ZK-04: the former `r5_wire_env_*` variants are no longer refused: `env`/`subject` are not strict-profiled by
        // the TS reference; they are allowed controls in [`r6_controls`].)
        ("r5_cap_257_caveats_on_one_hop", delegated_many(base, 256, &leaf), "delegation"),
        // R5-ZK-04: `matches` conditions are charged to the document regex budget, so 63 misses poison the later `re:` resource
        ("r5_04_delegated_matches_budget_poison", delegated(matches_budget_caveat(70)), "delegation"),
    ]
}

fn delegated_many(base: &Value, extra: usize, leaf: &SigningKey) -> Value {
    with_chain(base, two_hop(base, benign_caveats(extra)), leaf)
}

/// Controls for [`r5_variants`]: validly signed inputs just INSIDE each limit; the guest must ALLOW them.
pub fn r5_controls(base: &Value) -> Vec<(&'static str, Value)> {
    let leaf = key(3);
    let delegated = |c: Value| with_chain(base, two_hop(base, vec![c]), &leaf);
    vec![
        ("well_formed_bounds", delegated(tool_schema_caveat(base, fixture_schema(json!({ "maxLength": 64, "minLength": 1 }), json!({ "min": 1, "max": 100 }))))),
        ("256_caveats_on_one_hop", delegated_many(base, 255, &leaf)),
        ("matches_budget_62_misses", delegated(matches_budget_caveat(62))),
        ("env_boundary_values", {
            let mut v = base.clone();
            for (k, x) in [("n", json!(9007199254740991u64)), ("m", json!(-9007199254740991i64)), ("f", json!(0.000001)), ("g", json!(123456789.123456)), ("h", json!(0.5))] {
                v["env"][k] = x;
            }
            v
        }),
    ]
}

// ---- R6 (red-team round 6) -------------------------------------------------------------------------------------------

/// Re-mint the 2-hop chain with the ROOT caveat list edited by `f` (both hops carry the edited list), then re-bind and
/// re-sign the PCActn: everything is validly signed.
pub fn root_edited(base: &Value, f: &dyn Fn(&mut Vec<Value>)) -> Value {
    let mut caveats = root_caveats(base);
    f(&mut caveats);
    let c0 = json!(caveats);
    let g0 = hop(&key(1), &key(2), &c0, None);
    let g1 = hop(&key(2), &key(3), &c0, Some(&g0));
    with_chain(base, vec![g0, g1], &key(3))
}

/// Edit the root envelope caveat (the object holding goal_commit / predicates / caveats / risk_policy).
pub fn envelope_edited(base: &Value, f: &dyn Fn(&mut Value)) -> Value {
    root_edited(base, &|cs| {
        for c in cs.iter_mut() {
            if c["type"] == "envelope" {
                f(c);
            }
        }
    })
}

/// Append one condition to the root envelope's first predicate's `where`.
pub fn with_where(base: &Value, cond: Value) -> Value {
    envelope_edited(base, &|e| e["predicates"][0]["where"].as_array_mut().unwrap().push(cond.clone()))
}

/// Replace the plan (and optionally edit the signed action), recompute the signed plan root and re-sign the PCActn.
pub fn plan_edited(base: &Value, plan: Vec<Value>, edit: &dyn Fn(&mut Value)) -> Value {
    let mut v = base.clone();
    v["plan"] = json!(plan);
    edit(&mut v);
    v["pcactn"]["plan"]["root"] = json!(plan_commitment(v["plan"].as_array().unwrap()).unwrap());
    resign(&mut v, &key(3));
    v
}

fn n1(rc: Option<Value>) -> Value {
    let mut n = json!({"id": "n1", "verb": "read", "resource": "/acct/123/items"});
    if let Some(rc) = rc {
        n["reversibility_class"] = rc;
    }
    n
}

/// The fixture plan without `n1`, then `nodes` appended.
fn plan_without_n1(base: &Value, nodes: Vec<Value>) -> Vec<Value> {
    let mut p: Vec<Value> = base["plan"].as_array().unwrap().iter().filter(|n| n["id"] != "n1").cloned().collect();
    p.extend(nodes);
    p
}

fn drop_action_rc(v: &mut Value) {
    v["action"].as_object_mut().unwrap().remove("reversibility_class");
    v["pcactn"]["action"].as_object_mut().unwrap().remove("reversibility_class");
}

/// R6 variants a correct guest must DENY (the e922536c guest ALLOWED every one), all validly signed.
/// `(name, input, restoring_group)`.
pub fn r6_variants(base: &Value) -> Vec<(&'static str, Value, &'static str)> {
    let acct = |extra: Value| {
        let mut c = json!({"field": "action.params.acct", "op": "eq", "value": "acct_123"});
        for (k, v) in extra.as_object().unwrap() {
            c[k] = v.clone();
        }
        c
    };
    vec![
        // R6-ZK-01: a PRESENT non-string `ref` is a path that does not resolve => unknown => the predicate fails
        ("r6_zk01_where_ref_null", with_where(base, acct(json!({"ref": null}))), "delegation"),
        ("r6_zk01_where_ref_number", with_where(base, acct(json!({"ref": 5}))), "delegation"),
        ("r6_zk01_where_ref_bool", with_where(base, acct(json!({"ref": true}))), "delegation"),
        ("r6_zk01_where_ref_object", with_where(base, acct(json!({"ref": {"p": "action.params.acct"}}))), "delegation"),
        ("r6_zk01_where_ref_array", with_where(base, acct(json!({"ref": ["action.params.acct"]}))), "delegation"),
        // R6-ZK-02: leaf fields + a group key is a GROUP (`not` of a true leaf => false)
        ("r6_zk02_leaf_fields_plus_not_group", with_where(base, acct(json!({"not": {"field": "action.params.acct", "op": "eq", "value": "acct_123"}}))), "delegation"),
        // R6-ZK-03: no action reversibility_class; the SIGNED node n1 carries `null` (commits as the default, so the plan
        // inclusion holds) and a REVERSIBLE decoy with the same verb/resource is listed first
        (
            "r6_zk03_decoy_node_listed_first",
            plan_edited(base, plan_without_n1(base, vec![json!({"id": "n1d", "verb": "read", "resource": "/acct/123/items", "reversibility_class": "reversible"}), n1(Some(Value::Null))]), &drop_action_rc),
            "plan",
        ),
        // plan inclusion recomputed from the signed action (merkle.ts planLeaf): the node commits a params_digest the action does not carry
        (
            "r6_plan_node_params_digest_not_on_action",
            plan_edited(base, plan_without_n1(base, vec![{ let mut n = n1(Some(json!("reversible"))); n["params_digest"] = json!(hash_canonical(&json!({"acct": "acct_999"}))); n }]), &|_| {}),
            "plan",
        ),
        // envelope.ts readEnvelope + validateRiskPolicy
        ("r6_envelope_risk_policy_lambda_missing", envelope_edited(base, &|e| { e["risk_policy"].as_object_mut().unwrap().remove("lambda"); }), "delegation"),
        ("r6_envelope_risk_policy_kappa_zero", envelope_edited(base, &|e| e["risk_policy"]["kappa"] = json!(0)), "delegation"),
        ("r6_envelope_agent_binding_missing", envelope_edited(base, &|e| { e.as_object_mut().unwrap().remove("agent_binding"); }), "delegation"),
        ("r6_envelope_caveats_missing", envelope_edited(base, &|e| { e.as_object_mut().unwrap().remove("caveats"); }), "delegation"),
        ("r6_envelope_goal_commit_not_a_string", envelope_edited(base, &|e| e["goal_commit"] = json!(7)), "delegation"),
    ]
}

/// R6 controls: validly signed inputs the TS reference ALLOWS and the e922536c guest DENIED; the guest must allow them.
pub fn r6_controls(base: &Value) -> Vec<(&'static str, Value)> {
    let env_edit = |f: &dyn Fn(&mut Value)| {
        let mut v = base.clone();
        f(&mut v["env"]);
        v
    };
    let mut no_tb = base.clone();
    no_tb.as_object_mut().unwrap().remove("tool_binding");
    no_tb["pcactn"].as_object_mut().unwrap().remove("tool_binding");
    let schema = fixture_schema(json!({}), json!({}));
    let numeric_sd = json!({ "type": "tool_schema", "tool": "read", "signature_digest": 5, "schema": schema,
        "schema_digest": hash_canonical(&schema),
        "binding_digest": hash_canonical(&json!({ "tool": "read", "signature_digest": "5", "schema": schema })) });
    vec![
        // R6-ZK-04: env is not strict-profiled (the former r5_wire_env_* negatives)
        ("r6_env_unsafe_integer", env_edit(&|e| e["n"] = json!(9007199254740993u64))),
        ("r6_env_negative_zero", env_edit(&|e| e["z"] = json!(-0.0))),
        ("r6_env_exponent_scale_float", env_edit(&|e| e["f"] = json!(1e-7))),
        ("r6_env_over_precise_float", env_edit(&|e| e["f"] = json!(0.1234567890123456))),
        ("r6_env_nesting_33", env_edit(&|e| {
            let mut x = json!(1);
            for _ in 0..32 {
                x = json!([x]);
            }
            e["deep"] = x;
        })),
        ("r6_env_over_512kib", env_edit(&|e| e["pad"] = json!("x".repeat(524_288)))),
        // R6-ZK-02 converse: `not` of a false leaf is true
        ("r6_leaf_fields_plus_not_group_true", with_where(base, json!({"field": "action.params.acct", "op": "eq", "value": "acct_999", "not": {"field": "action.params.acct", "op": "eq", "value": "acct_999"}}))),
        // formerly unported operators / groups
        ("r6_like", with_where(base, json!({"field": "action.params.acct", "op": "like", "value": "acct_*"}))),
        ("r6_is_a", with_where(base, json!({"field": "action.params.acct", "op": "is_a", "value": "acct_123"}))),
        ("r6_member_of", with_where(base, json!({"field": "env.current_device", "op": "member_of", "value": "fleet", "collection": "env.groups"})))
            .pipe_env(&|e| e["groups"] = json!({"dev-1": ["team"], "team": "fleet"})),
        ("r6_any_of_all_of", with_where(base, json!({"any_of": [{"field": "env.x", "op": "exists"}, {"all_of": [{"field": "action.params.limit", "op": "gte", "value": 1}, {"not": {"field": "subject.role", "op": "eq", "value": "admin"}}]}]}))),
        // R6-ZK-05: numeric signature_digest (TS binds String(5)); no tool_binding signed, so the raw value is never compared
        ("r6_tool_schema_numeric_signature_digest", with_chain(&no_tb, two_hop(&no_tb, vec![numeric_sd]), &key(3))),
        // R6-ZK-03 converse: the signed node is reversible, an IRREVERSIBLE decoy is listed first
        (
            "r6_signed_node_reversible_decoy_irreversible_first",
            plan_edited(base, plan_without_n1(base, vec![json!({"id": "n1d", "verb": "read", "resource": "/acct/123/items", "reversibility_class": "irreversible"}), n1(Some(json!("reversible")))]), &drop_action_rc),
        ),
        // merkle.ts planLeaf: a `null` conditions_digest takes the default
        ("r6_conditions_digest_null", {
            let mut v = base.clone();
            v["pcactn"]["plan"]["conditions_digest"] = Value::Null;
            resign(&mut v, &key(3));
            v
        }),
    ]
}

trait PipeEnv {
    fn pipe_env(self, f: &dyn Fn(&mut Value)) -> Self;
}
impl PipeEnv for (&'static str, Value) {
    fn pipe_env(mut self, f: &dyn Fn(&mut Value)) -> Self {
        f(&mut self.1["env"]);
        self
    }
}
