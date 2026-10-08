//! Deterministic minter for a REAL signed capability chain + leaf PCActn, for the zkVM fixture.
//!
//! The pre-chain fixture only carried placeholder issuer/holder strings and no signatures, so the guest
//! could not verify a real chain-of-authority. This mints a genuine 2-hop Ed25519 chain
//!
//!     principal --(root grant, carries the policy envelope)--> agentA --(delegate)--> agentB (leaf)
//!
//! and a real leaf PCActn signed by agentB (the leaf holder), using the SAME canonical-JSON bytes and
//! signature domains the guest verifies (`capability.ts` `seal`/`sigMessage`, `pcactn.ts`
//! `thresholdMessage`). Keys are deterministic from fixed 32-byte seeds, so the fixture is reproducible.
//!
//! The policy/action/plan/risk inputs are taken UNCHANGED from the hand-authored template fixture; only
//! the crypto parts are injected (grant issuer/holder become real keys, which is unavoidable to root the
//! chain — and so `policy_commit` legitimately changes). All three commitments are recomputed with the
//! core's canonicaliser (already proven byte-identical to the TS reference), so they remain the TS values.

use ed25519_dalek::{Signer, SigningKey};
use pca_zkvm_core::canonical::canonical_bytes;
use pca_zkvm_core::commit;
use pca_zkvm_core::commit::{b64u, hash_canonical, sha256};
use serde_json::{json, Map, Value};

const CAP_DOMAIN: &[u8] = b"atlas-pca/cap/v1\0";
const SIG_DOMAIN: &[u8] = b"atlas-pca/actn/v2\0";

/// Deterministic signing key from a single-byte seed (filled to 32 bytes).
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// b64u of a signing key's Ed25519 public key — the `issuer`/`holder` wire form.
fn pub_b64u(k: &SigningKey) -> String {
    b64u(k.verifying_key().as_bytes())
}

/// `sigMessage(body_digest)` = `CAP_DOMAIN ‖ sha256(canonical(body))`.
fn cap_sig_message(body: &Value) -> Vec<u8> {
    let d = sha256(&canonical_bytes(body));
    let mut m = Vec::with_capacity(CAP_DOMAIN.len() + 32);
    m.extend_from_slice(CAP_DOMAIN);
    m.extend_from_slice(&d);
    m
}

/// Seal an ed25519 capability hop — faithful to `capability.ts` `seal` (default suite): the signed body is
/// `{issuer, holder, caveats, parent: parent ?? null}`; the hop object carries `parent` only for a child.
fn seal(issuer: &str, holder: &str, caveats: &Value, parent: Option<&str>, signer: &SigningKey) -> Value {
    let parent_val: Value = match parent {
        Some(p) => Value::String(p.to_string()),
        None => Value::Null,
    };
    let mut body = Map::new();
    body.insert("issuer".to_string(), Value::String(issuer.to_string()));
    body.insert("holder".to_string(), Value::String(holder.to_string()));
    body.insert("caveats".to_string(), caveats.clone());
    body.insert("parent".to_string(), parent_val);
    let body = Value::Object(body);

    let body_digest = hash_canonical(&body);
    let sig = signer.sign(&cap_sig_message(&body));

    let mut cap = Map::new();
    cap.insert("id".to_string(), Value::String(body_digest.clone()));
    cap.insert("issuer".to_string(), Value::String(issuer.to_string()));
    cap.insert("holder".to_string(), Value::String(holder.to_string()));
    cap.insert("caveats".to_string(), caveats.clone());
    cap.insert("body_digest".to_string(), Value::String(body_digest));
    cap.insert("sig".to_string(), Value::String(b64u(&sig.to_bytes())));
    if let Some(p) = parent {
        cap.insert("parent".to_string(), Value::String(p.to_string()));
    }
    Value::Object(cap)
}

/// Delegate to a new holder with no added caveats — `capability.ts` `delegate(parent, to, [], signer)`.
/// issuer = parent.holder; caveats = parent.caveats (append-only prefix); parent link = capHash(parent).
fn delegate(parent: &Value, to_holder: &str, signer: &SigningKey) -> Value {
    let issuer = parent.get("holder").and_then(|v| v.as_str()).unwrap_or("");
    let caveats = parent.get("caveats").cloned().unwrap_or(Value::Array(Vec::new()));
    let parent_hash = hash_canonical(parent);
    seal(issuer, to_holder, &caveats, Some(&parent_hash), signer)
}

/// `conditionsDigest()` for a node with no pre/post: `b64u(sha256(canonical({pre:null, post:null})))`.
fn empty_conditions_digest() -> String {
    let body = json!({ "pre": Value::Null, "post": Value::Null });
    b64u(&sha256(&canonical_bytes(&body)))
}

/// Mint the full `DecideInput` (template + real chain + leaf PCActn) and the regenerated commitments.
/// Returns `(decide_input, expected_commitments)`. Deterministic.
pub fn mint_fixture(template: &Value) -> (Value, Value) {
    // Deterministic key material: principal (root), agentA (mid holder), agentB (leaf holder).
    let principal = key(1);
    let agent_a = key(2);
    let agent_b = key(3);
    let principal_pk = pub_b64u(&principal);
    let agent_a_pk = pub_b64u(&agent_a);
    let agent_b_pk = pub_b64u(&agent_b);

    // The policy envelope comes verbatim from the template grant's caveats.
    let caveats = template
        .get("grant")
        .and_then(|g| g.get("caveats"))
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));

    // Root grant (principal -> agentA), signed by the principal. This IS the `grant` the VM evaluates.
    let root = seal(&principal_pk, &agent_a_pk, &caveats, None, &principal);
    // Leaf (agentA -> agentB), no added caveats, signed by agentA.
    let leaf = delegate(&root, &agent_b_pk, &agent_a);
    let chain = Value::Array(vec![root.clone(), leaf.clone()]);

    // ---- the leaf PCActn, signed by agentB (the leaf holder) over the canonical body ----
    let action = template.get("action").cloned().unwrap_or(Value::Null);
    let plan_nodes: Vec<Value> = template
        .get("plan")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let node_id = template
        .get("node_id")
        .and_then(|v| v.as_str())
        .unwrap_or("n1")
        .to_string();
    let now_i = template.get("now").and_then(|v| v.as_f64()).unwrap_or(1_760_000_000_000.0) as i64;
    let grant_ref = root.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let plan_root = commit::plan_commitment(&plan_nodes).unwrap_or_default();

    // PCActn body WITHOUT the unsigned containers (`sig`/`threshold`/`pq_sig`) — the exact bytes signed.
    let pcactn_body = json!({
        "ver": 2,
        "action": action.clone(),
        "grant_ref": grant_ref,
        "cap_chain": chain.clone(),
        "plan": {
            "root": plan_root,
            "inclusion_proof": [],
            "node_id": node_id,
            "conditions_digest": empty_conditions_digest()
        },
        "attestation": { "quote_digest": "", "epoch": 0, "model_id": "unattested", "measurement": "", "operator": "unattested" },
        "provenance": { "causal_hash": "", "taint_level": 0, "trusted_refs": [] },
        "freshness": { "beacon_ref": "", "epoch": 0, "accumulator_witness": "" },
        "counter": 0,
        "risk_claim": { "r": 0, "inputs": {} },
        "aud": "atlas-instance-1",
        "iat": now_i,
        "exp": now_i + 1_200_000
    });
    let sig_msg = {
        let d = sha256(&canonical_bytes(&pcactn_body));
        let mut m = Vec::with_capacity(SIG_DOMAIN.len() + 32);
        m.extend_from_slice(SIG_DOMAIN);
        m.extend_from_slice(&d);
        m
    };
    let leaf_sig = agent_b.sign(&sig_msg);
    let mut pcactn = pcactn_body;
    pcactn
        .as_object_mut()
        .expect("pcactn body is an object")
        .insert("sig".to_string(), Value::String(b64u(&leaf_sig.to_bytes())));

    // ---- assemble the full DecideInput: template fields + injected crypto ----
    let mut input = template.clone();
    let obj = input.as_object_mut().expect("template is a JSON object");
    obj.insert("grant".to_string(), root.clone());
    obj.insert("chain".to_string(), chain);
    obj.insert("pcactn".to_string(), pcactn);
    obj.insert("expected_root_principal".to_string(), Value::String(principal_pk));

    // ---- regenerated commitments (core canonicaliser == TS hashCanonical / commitPlan) ----
    let expected = json!({
        "action_commit": commit::action_commitment(&action),
        "policy_commit": commit::policy_commitment(&root),
        "plan_commit": commit::plan_commitment(&plan_nodes).unwrap_or_default(),
    });

    (input, expected)
}
