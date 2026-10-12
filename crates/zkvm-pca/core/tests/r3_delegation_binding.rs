//! Red-team round 3 regressions R3-11 / R3-12 / R3-13 (PoC: redteam/round3/zk/src/zkvm_delegated_caveat.rs).
//!
//!  R3-11  caveats appended by a delegation hop are evaluated (the TS reference: every hop's caveats hold).
//!  R3-12  the delegation depth is `chain.len() - 1`, never a prover-supplied scalar.
//!  R3-13  the signed PCActn is tied to the chain, the action, the plan and the node, and those bindings
//!         are committed to the journal.
//!
//! Every deny case below was ALLOWED by the pre-fix guest (verified by running these tests against it).
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
use ed25519_dalek::{Signer, SigningKey};
use pca_zkvm_core::{
    canonical::canonical_bytes,
    chain::{CAP_DOMAIN, SIG_DOMAIN},
    commit::{hash_canonical, plan_commitment, sha256},
    decide_from_str, Decision,
};
use serde_json::{json, Value};

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn pk(k: &SigningKey) -> String {
    B.encode(k.verifying_key().to_bytes())
}

fn hop(signer: &SigningKey, holder: &SigningKey, caveats: &Value, parent: Option<&Value>) -> Value {
    let parent_hash = parent.map(hash_canonical);
    let body = json!({"issuer": pk(signer), "holder": pk(holder), "caveats": caveats, "parent": parent_hash});
    let d = sha256(&canonical_bytes(&body));
    let dig = B.encode(d);
    let mut msg = CAP_DOMAIN.to_vec();
    msg.extend_from_slice(&d);
    let sig = B.encode(signer.sign(&msg).to_bytes());
    let mut o = json!({"id": dig, "issuer": pk(signer), "holder": pk(holder), "caveats": caveats, "body_digest": dig, "sig": sig});
    if let Some(p) = parent_hash {
        o["parent"] = json!(p);
    }
    o
}

/// A fully signed PCActn that carries `chain`, bound to `action`, `grant_ref` and the plan node.
fn pcactn(leaf: &SigningKey, action: &Value, chain: &[Value], plan: &[Value], node_id: &str, cond: &Value) -> Value {
    let mut p = json!({
        "ver": 2, "action": action, "grant_ref": chain[0]["id"], "cap_chain": chain,
        "plan": {"root": plan_commitment(plan).unwrap(), "inclusion_proof": [], "node_id": node_id, "conditions_digest": cond},
        "attestation": {"quote_digest": "", "epoch": 0, "model_id": "unattested", "measurement": "", "operator": "unattested"},
        "provenance": {"causal_hash": "", "taint_level": 0, "trusted_refs": []},
        "freshness": {"beacon_ref": "", "epoch": 0, "accumulator_witness": ""},
        "counter": 0, "risk_claim": {"r": 0, "inputs": {}}, "aud": "atlas-instance-1", "iat": 1760000000000u64, "exp": 1760001200000u64,
        "tool_binding": "3rdLEXkqzaXOqZYVuCgMwOJ9UD-S2pPeWQruzSjfzHY"
    });
    let d = sha256(&canonical_bytes(&p));
    let mut msg = SIG_DOMAIN.to_vec();
    msg.extend_from_slice(&d);
    p["sig"] = json!(B.encode(leaf.sign(&msg).to_bytes()));
    p
}

struct World {
    base: Value,
    root: SigningKey,
    leaf: SigningKey,
    cond: Value,
}
fn world() -> World {
    let base: Value = serde_json::from_str(include_str!("../../fixtures/decide_input.sample.json")).unwrap();
    let cond = base["pcactn"]["plan"]["conditions_digest"].clone();
    World { base, root: key(1), leaf: key(9), cond }
}

impl World {
    /// Build the decide input for `chain` (signed root->leaf by the keys in `hops_keys`); `mutate` may edit it afterwards.
    fn input(&self, chain: Vec<Value>, mutate: impl Fn(&mut Value)) -> Value {
        let plan: Vec<Value> = self.base["plan"].as_array().unwrap().clone();
        let pc = pcactn(&self.leaf, &self.base["action"], &chain, &plan, "n1", &self.cond);
        let mut v = self.base.clone();
        v["grant"] = chain[0].clone();
        v["chain"] = json!(chain);
        v["expected_root_principal"] = json!(pk(&self.root));
        v["pcactn"] = pc;
        v["node_id"] = json!("n1");
        mutate(&mut v);
        v
    }
    /// A 2-hop chain root->mid->leaf-holder where hop 1 appends `extra` caveats.
    fn two_hop(&self, extra: Vec<Value>) -> Vec<Value> {
        let c0 = self.base["grant"]["caveats"].clone();
        let mut c1 = c0.as_array().unwrap().clone();
        c1.extend(extra);
        let mid = key(2);
        let g0 = hop(&self.root, &mid, &c0, None);
        let g1 = hop(&mid, &self.leaf, &json!(c1), Some(&g0));
        vec![g0, g1]
    }
}
fn run(v: &Value) -> Decision {
    decide_from_str(&v.to_string())
}

#[test]
fn control_honest_two_hop_chain_is_allowed() {
    let w = world();
    let d = run(&w.input(w.two_hop(vec![]), |_| {}));
    assert_eq!(d.allow, 1, "control: a fully bound honest input must be allowed");
    assert_eq!(d.chain_verified, 1);
}

// ---- R3-11 ----------------------------------------------------------------------------------------
#[test]
fn r3_11_expired_delegated_caveat_denies() {
    let w = world();
    let chain = w.two_hop(vec![json!({"type": "expires", "at": 1_700_000_000_000u64})]);
    assert_eq!(run(&w.input(chain, |_| {})).allow, 0, "hop-1 expires(at < now) must deny");
}

#[test]
fn r3_11_unsatisfied_delegated_blast_radius_denies() {
    let w = world();
    // risk_inputs_scaled[2] = 0.05 blast radius; a delegator narrowing to 0.01 must bind the delegatee.
    let chain = w.two_hop(vec![json!({"type": "max_blast_radius", "max": 0.01})]);
    assert_eq!(run(&w.input(chain, |_| {})).allow, 0);
}

#[test]
fn r3_11_unknown_delegated_caveat_fails_closed() {
    let w = world();
    let chain = w.two_hop(vec![json!({"type": "made_up_restriction"})]);
    assert_eq!(run(&w.input(chain, |_| {})).allow, 0);
}

#[test]
fn r3_11_satisfied_delegated_caveat_still_allows() {
    let w = world();
    let chain = w.two_hop(vec![json!({"type": "expires", "at": 1_760_010_000_000u64}), json!({"type": "max_blast_radius", "max": 0.4})]);
    assert_eq!(run(&w.input(chain, |_| {})).allow, 1);
}

#[test]
fn r3_11_every_hop_is_evaluated_not_just_the_leaf() {
    let w = world();
    let c0 = w.base["grant"]["caveats"].clone();
    let mut c1 = c0.as_array().unwrap().clone();
    c1.push(json!({"type": "expires", "at": 1_700_000_000_000u64}));
    let c2 = c1.clone();
    let (m1, m2) = (key(2), key(3));
    let g0 = hop(&w.root, &m1, &c0, None);
    let g1 = hop(&m1, &m2, &json!(c1), Some(&g0));
    let g2 = hop(&m2, &w.leaf, &json!(c2), Some(&g1));
    assert_eq!(run(&w.input(vec![g0, g1, g2], |_| {})).allow, 0);
}

// ---- R3-12 ----------------------------------------------------------------------------------------
fn three_hop_max1(w: &World) -> Vec<Value> {
    let mut env = w.base["grant"]["caveats"][0].clone();
    for cv in env["caveats"].as_array_mut().unwrap() {
        if cv["type"] == "delegation_depth" {
            cv["max"] = json!(1);
        }
    }
    let c = json!([env]);
    let (h1, h2) = (key(2), key(3));
    let a0 = hop(&w.root, &h1, &c, None);
    let a1 = hop(&h1, &h2, &c, Some(&a0));
    let a2 = hop(&h2, &w.leaf, &c, Some(&a1));
    vec![a0, a1, a2]
}

#[test]
fn r3_12_prover_cannot_lie_about_delegation_depth() {
    let w = world();
    for lie in [json!(0), json!(1), json!(-5), Value::Null] {
        let l = lie.clone();
        let d = run(&w.input(three_hop_max1(&w), move |v| v["delegation_depth"] = l.clone()));
        assert_eq!(d.allow, 0, "3-hop chain (true depth 2) under max=1 must deny whatever depth the prover claims ({lie})");
    }
    // field absent entirely
    let d = run(&w.input(three_hop_max1(&w), |v| {
        v.as_object_mut().unwrap().remove("delegation_depth");
    }));
    assert_eq!(d.allow, 0);
}

#[test]
fn r3_12_depth_is_derived_and_committed() {
    let w = world();
    let honest = run(&w.input(w.two_hop(vec![]), |_| {}));
    assert_eq!(honest.allow, 1);
    let ctx = serde_json::to_value(&honest).unwrap()["context"].clone();
    assert_eq!(ctx["delegation_depth"], json!(1), "depth derives from chain.len()-1: {ctx}");
    // a prover-supplied value neither changes the decision nor the journal
    let lied = run(&w.input(w.two_hop(vec![]), |v| v["delegation_depth"] = json!(0)));
    assert_eq!(lied, honest);
}

// ---- R3-13 ----------------------------------------------------------------------------------------
#[test]
fn r3_13_pcactn_signed_for_a_different_action_denies() {
    let w = world();
    let other = json!({"verb": "delete", "resource": "/acct/123/items", "params_digest": "x", "reversibility_class": "irreversible"});
    let chain = w.two_hop(vec![]);
    let plan: Vec<Value> = w.base["plan"].as_array().unwrap().clone();
    let pc = pcactn(&w.leaf, &other, &chain, &plan, "n1", &w.cond);
    let d = run(&w.input(chain, move |v| v["pcactn"] = pc.clone()));
    assert_eq!(d.allow, 0, "leaf signed delete, input.action is read");
}

#[test]
fn r3_13_bogus_grant_ref_denies() {
    let w = world();
    let d = run(&w.input(w.two_hop(vec![]), |v| {
        v["pcactn"]["grant_ref"] = json!("not-the-grant");
        // keep the signature valid so ONLY the binding can be the cause
        resign(v);
    }));
    assert_eq!(d.allow, 0);
}

#[test]
fn r3_13_pcactn_carrying_a_different_chain_denies() {
    let w = world();
    let other_chain = w.two_hop(vec![json!({"type": "max_blast_radius", "max": 0.4})]);
    let d = run(&w.input(w.two_hop(vec![]), move |v| {
        v["pcactn"]["cap_chain"] = json!(other_chain);
        resign(v);
    }));
    assert_eq!(d.allow, 0);
}

#[test]
fn r3_13_plan_root_and_node_must_match() {
    let w = world();
    let d = run(&w.input(w.two_hop(vec![]), |v| {
        v["pcactn"]["plan"]["root"] = json!("AAAA");
        resign(v);
    }));
    assert_eq!(d.allow, 0, "signed plan root differs from the committed plan");
    let d = run(&w.input(w.two_hop(vec![]), |v| {
        v["pcactn"]["plan"]["node_id"] = json!("n2");
        resign(v);
    }));
    assert_eq!(d.allow, 0, "signed node n2 is a write/items/42 node, not the read action");
    let d = run(&w.input(w.two_hop(vec![]), |v| v["node_id"] = json!("n0")));
    assert_eq!(d.allow, 0, "prover-supplied node_id disagrees with the signed one");
    let d = run(&w.input(w.two_hop(vec![]), |v| v["plan"] = json!([])));
    assert_eq!(d.allow, 0, "no plan at all");
}

#[test]
fn r3_13_bindings_are_committed_to_the_journal() {
    let w = world();
    let chain = w.two_hop(vec![]);
    let grant_id = chain[0]["id"].clone();
    let d = run(&w.input(chain, |_| {}));
    assert_eq!(d.allow, 1);
    let v = serde_json::to_value(&d).unwrap();
    assert_eq!(v["context"]["grant_ref"], grant_id);
    assert_eq!(v["context"]["node_id"], json!("n1"));
    assert_eq!(v["plan_commit"].as_str().unwrap(), plan_commitment(w.base["plan"].as_array().unwrap()).unwrap());
}

/// Re-sign the (edited) PCActn with the leaf key so a deny can only come from the binding checks.
fn resign(v: &mut Value) {
    let leaf = key(9);
    let mut body = v["pcactn"].clone();
    body.as_object_mut().unwrap().remove("sig");
    let d = sha256(&canonical_bytes(&body));
    let mut msg = SIG_DOMAIN.to_vec();
    msg.extend_from_slice(&d);
    v["pcactn"]["sig"] = json!(B.encode(leaf.sign(&msg).to_bytes()));
}


#[path = "support/chain_mint.rs"]
mod mint;

#[test]
fn the_shared_r3_variant_matrix_is_denied_and_each_has_exactly_one_restoring_group() {
    let base = world().base;
    assert_eq!(run(&base).allow, 1, "control");
    for (name, v, group) in mint::r3_variants(&base) {
        let d = run(&v);
        assert_eq!(d.allow, 0, "{name} must be denied");
        // the variants are validly signed, so the chain itself still verifies (only the new check denies)
        let restored = {
            let mut r = v.clone();
            let keys: &[&str] = match group {
                "delegation" => &["chain", "grant", "expected_root_principal", "pcactn", "delegation_depth"],
                "pcactn" => &["pcactn"],
                "action" => &["action"],
                "toolbinding" => &["tool_binding"],
                _ => unreachable!(),
            };
            for k in keys {
                match base.get(*k) {
                    Some(b) => r[*k] = b.clone(),
                    None => {
                        r.as_object_mut().unwrap().remove(*k);
                    }
                }
            }
            r
        };
        assert_eq!(run(&restored).allow, 1, "{name}: restoring group '{group}' must allow again");
    }
}

#[test]
fn a_stray_prover_supplied_delegation_depth_key_is_ignored() {
    let base = world().base;
    let honest = run(&base);
    let mut v = base.clone();
    v["delegation_depth"] = json!(9);
    assert_eq!(run(&v), honest, "the old input field is no longer read");
}
