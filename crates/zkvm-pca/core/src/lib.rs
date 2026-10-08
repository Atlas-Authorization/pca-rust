//! pca-zkvm-core — the PCA Policy-VM release gate, ported faithfully to run as a program INSIDE a
//! zkVM guest. Shared by the RISC Zero guest (proven) and the host (fixture generation + cross-check).
//!
//! The decision is computed over the ACTUAL structured inputs — the full predicate DSL, every caveat,
//! the fixed-point risk functional, the threshold ladder and the budget gate — with NO reduction to
//! opaque booleans, and the action/policy/plan commitments are recomputed with native sha256 over the
//! canonical-JSON preimages. See `README.md` for exactly what this closes and the honest boundary.

pub mod canonical;
pub mod caveats;
pub mod chain;
pub mod commit;
pub mod predicates;
pub mod risk;

use caveats::{evaluate_caveats, CaveatCtx};
use predicates::{evaluate_predicates, Ctx};
use risk::{auto_admit, risk_raw, tier, RiskInputsScaled, RiskPolicyScaled, S};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The full input the guest reads from the zkVM environment (private witness + public policy preimage).
#[derive(Clone, Debug, Deserialize)]
pub struct DecideInput {
    /// The full root grant capability (contains the `envelope` caveat: predicates, caveats, risk_policy).
    pub grant: Value,
    /// The PCActn action descriptor `{verb, resource, params?, reversibility_class?}`.
    pub action: Value,
    #[serde(default)]
    pub subject: Option<Value>,
    #[serde(default)]
    pub env: Option<Value>,
    /// Committed plan nodes (for the plan Merkle commitment + node lookup).
    #[serde(default)]
    pub plan: Vec<Value>,
    #[serde(default)]
    pub node_id: Option<String>,
    /// Private risk inputs at scale S, order [semanticDistance, reversibility, blastRadius, taint, confidence, age].
    pub risk_inputs_scaled: [u64; 6],
    /// Trust budget at scale S (private).
    pub budget_scaled: u64,
    /// Decision time, epoch ms.
    pub now: f64,
    /// Monotone caution floor at scale S (optional; can only RAISE risk).
    #[serde(default)]
    pub r_floor_scaled: u64,
    // ---- caveat context the VM cannot derive -----------------------------------------------------
    #[serde(default)]
    pub delegation_depth: Option<f64>,
    #[serde(default)]
    pub recent_action_times: Option<Vec<f64>>,
    /// The PCActn's signed `tool_binding` digest (for `tool_schema` caveats).
    #[serde(default)]
    pub tool_binding: Option<String>,
    // ---- signed capability chain (the gap closure) ----------------------------------------------
    /// The FULL signed capability chain (root -> leaf), each hop a `Capability` wire object exactly as
    /// `capability.ts` produces. `chain[0]` MUST be the `grant` (same object), binding the evaluated
    /// policy to the proven chain. Verified in-circuit by [`chain::verify_chain`].
    #[serde(default)]
    pub chain: Vec<Value>,
    /// The pinned root principal (== `grant.issuer`): the chain MUST root at this Ed25519 public key
    /// (`verifyChain`'s `expectedRootIssuer`). Absent => chain verification fails closed.
    #[serde(default)]
    pub expected_root_principal: Option<String>,
    /// The full signed PCActn wire object (the leaf holder's signed intent). Its `sig`/`alg`/`pq_pk`/
    /// `pq_sig` and the canonical body (minus `sig`/`threshold`/`pq_sig`) give the leaf-holder signature
    /// `verifyLeafSuite` checks. Absent => chain verification fails closed.
    #[serde(default)]
    pub pcactn: Option<Value>,
}

/// The public statement the guest commits to the receipt journal.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    /// 1 iff the action is released AND auto-admitted (predicates ∧ caveats ∧ tier==1 ∧ budget≥cost).
    pub allow: u8,
    /// risk r at scale S (decimal; r_raw / S), so a verifier sees the proven risk.
    pub r_scaled: u64,
    /// threshold tier the decision lands at (1/2/3).
    pub tier: u8,
    /// Native-sha256 commitments recomputed in-guest from the preimages.
    pub action_commit: String,
    pub policy_commit: String,
    pub plan_commit: String,
    /// 1 iff the FULL signed capability chain + leaf PCActn signature verified IN-CIRCUIT (root pinned,
    /// every hop Ed25519-signed, delegation-linked, append-only caveats, leaf signed by the leaf holder).
    /// A valid receipt always has `chain_verified == 1` (it is folded into `allow`); the field records in
    /// the journal that the chain-of-authority — not just the policy gate — was proven.
    pub chain_verified: u8,
}

/// Parse a JSON `DecideInput` and run [`decide`]. Fails CLOSED (allow=0) on any parse error. This is
/// the single entry point the zkVM guest calls (the input is passed as a JSON string so `serde_json`'s
/// self-describing deserialization can handle the `serde_json::Value` fields — risc0's own non-
/// self-describing serde format cannot, as `Value` needs `deserialize_any`).
pub fn decide_from_str(json: &str) -> Decision {
    match serde_json::from_str::<DecideInput>(json) {
        Ok(input) => decide(&input),
        Err(_) => Decision {
            allow: 0,
            r_scaled: S,
            tier: 3,
            action_commit: String::new(),
            policy_commit: String::new(),
            plan_commit: String::new(),
            chain_verified: 0,
        },
    }
}

/// Build the leaf PCActn signature material from the full signed PCActn wire object. The signed message
/// is `thresholdMessage(pcactn)` = `SIG_DOMAIN ‖ sha256(canonical(body))` where `body` is the PCActn with
/// its UNSIGNED containers `sig`/`threshold`/`pq_sig` removed (faithful to `pcactn.ts` `thresholdMessage`
/// and `wire.ts`). Returns `None` if the PCActn is not a JSON object.
fn leaf_sig_from_pcactn(pcactn: &Value) -> Option<chain::LeafSig> {
    let obj = pcactn.as_object()?;
    let mut body = pcactn.clone();
    if let Some(m) = body.as_object_mut() {
        m.remove("sig");
        m.remove("threshold");
        m.remove("pq_sig");
    }
    let digest = commit::sha256(&canonical::canonical_bytes(&body));
    let mut message = Vec::with_capacity(chain::SIG_DOMAIN.len() + 32);
    message.extend_from_slice(chain::SIG_DOMAIN);
    message.extend_from_slice(&digest);
    Some(chain::LeafSig {
        message,
        alg: obj.get("alg").and_then(|v| v.as_str()).map(String::from),
        sig: obj.get("sig").and_then(|v| v.as_str()).map(String::from),
        pq_pk: obj.get("pq_pk").and_then(|v| v.as_str()).map(String::from),
        pq_sig: obj.get("pq_sig").and_then(|v| v.as_str()).map(String::from),
    })
}

/// Verify the full signed chain-of-authority for the decision. FAIL CLOSED on any missing part:
///   * the chain is non-empty and `chain[0]` IS the evaluated `grant` (capHash equality) — this binds the
///     policy/envelope the VM evaluated to the proven chain;
///   * `expected_root_principal` is present (== `grant.issuer`); and
///   * the full PCActn leaf signature material is present.
/// Then delegates to [`chain::verify_chain`].
fn verify_full_chain(input: &DecideInput) -> bool {
    if input.chain.is_empty() {
        return false;
    }
    // chain[0] must be the grant (same canonical bytes) — otherwise the proven chain would be unrelated
    // to the policy the VM gated on. Mirrors verifyPCActnCore's `capHash(chain[0]) === capHash(grant)`.
    if commit::hash_canonical(&input.chain[0]) != commit::hash_canonical(&input.grant) {
        return false;
    }
    let root_pk = match &input.expected_root_principal {
        Some(s) => s.as_str(),
        None => return false,
    };
    let leaf = match &input.pcactn {
        Some(p) => match leaf_sig_from_pcactn(p) {
            Some(l) => l,
            None => return false,
        },
        None => return false,
    };
    chain::verify_chain(&input.chain, root_pk, &leaf).ok
}

fn get_envelope(grant: &Value) -> Option<&Value> {
    grant
        .get("caveats")?
        .as_array()?
        .iter()
        .find(|c| c.get("type").and_then(|t| t.as_str()) == Some("envelope"))
}

fn scale(f: f64) -> u64 {
    if !f.is_finite() || f < 0.0 {
        return 0;
    }
    (f * S as f64).round() as u64
}

fn parse_policy(env: &Value) -> Option<RiskPolicyScaled> {
    let rp = env.get("risk_policy")?;
    let w = rp.get("weights")?;
    let weights = [
        scale(w.get("alpha")?.as_f64()?),
        scale(w.get("beta")?.as_f64()?),
        scale(w.get("gamma")?.as_f64()?),
        scale(w.get("delta")?.as_f64()?),
        scale(w.get("epsilon")?.as_f64()?),
        scale(w.get("zeta")?.as_f64()?),
    ];
    Some(RiskPolicyScaled {
        weights,
        theta1_scaled: scale(rp.get("theta1")?.as_f64()?),
        theta2_scaled: scale(rp.get("theta2")?.as_f64()?),
        // kappa is an integer cost scale (quantized, matching stark-pca PolicyParams.kappa: u64)
        kappa: rp.get("kappa")?.as_f64()?.round().max(0.0) as u64,
        bmax_scaled: scale(rp.get("bMax")?.as_f64()?),
    })
}

/// Build the action/subject/env root the predicate & caveat evaluators read.
fn action_root(input: &DecideInput) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("action".to_string(), input.action.clone());
    if let Some(s) = &input.subject {
        m.insert("subject".to_string(), s.clone());
    }
    if let Some(e) = &input.env {
        m.insert("env".to_string(), e.clone());
    }
    Value::Object(m)
}

/// Run the full Policy-VM release+auto-admit gate. Total; never panics on malformed input (fails CLOSED
/// with allow=0). The commitments are always computed (binding is independent of the allow outcome).
pub fn decide(input: &DecideInput) -> Decision {
    let action_commit = commit::action_commitment(&input.action);
    let policy_commit = commit::policy_commitment(&input.grant);
    let plan_commit = commit::plan_commitment(&input.plan).unwrap_or_default();

    let envelope = get_envelope(&input.grant);
    let policy = envelope.and_then(parse_policy);

    // Fail closed if there is no well-formed envelope / policy.
    let (policy, envelope) = match (policy, envelope) {
        (Some(p), Some(e)) => (p, e),
        _ => {
            return Decision {
                allow: 0,
                r_scaled: S,
                tier: 3,
                action_commit,
                policy_commit,
                plan_commit,
                chain_verified: 0,
            }
        }
    };

    let root = action_root(input);

    // 1. predicates (full DSL, default deny)
    let predicates = envelope
        .get("predicates")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();
    let ctx = Ctx::new(&root);
    let predicates_ok = evaluate_predicates(&predicates, &ctx).allowed;

    // reversibility class: action.reversibility_class ?? matched node's
    let rev_class = input
        .action
        .get("reversibility_class")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            let (verb, resource) = (
                input.action.get("verb").and_then(|v| v.as_str()),
                input.action.get("resource").and_then(|v| v.as_str()),
            );
            input
                .plan
                .iter()
                .find(|n| {
                    n.get("verb").and_then(|v| v.as_str()) == verb
                        && n.get("resource").and_then(|v| v.as_str()) == resource
                })
                .and_then(|n| n.get("reversibility_class").and_then(|v| v.as_str()))
                .map(|s| s.to_string())
        });

    // 2. caveats (built-in + agent-native predicates/tool_schema)
    let env_caveats = envelope
        .get("caveats")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    let tool = input.action.get("verb").and_then(|v| v.as_str()).map(|s| s.to_string());
    let tool_args = match input.action.get("params") {
        Some(Value::Object(_)) => input.action.get("params").cloned(),
        _ => Some(Value::Object(serde_json::Map::new())),
    };
    let cctx = CaveatCtx {
        now: input.now,
        blast_radius: Some(input.risk_inputs_scaled[2].min(S) as f64 / S as f64),
        reversibility_class: rev_class,
        delegation_depth: input.delegation_depth,
        recent_action_times: input.recent_action_times.clone(),
        action_root: &root,
        tool,
        tool_args,
        tool_signature_digest: input.tool_binding.clone(),
    };
    let caveats_ok = evaluate_caveats(&env_caveats, &cctx).ok;

    // 3. fixed-point risk + threshold ladder + budget gate
    let inputs = RiskInputsScaled {
        x: input.risk_inputs_scaled,
    };
    let r_raw = risk_raw(&inputs, &policy, input.r_floor_scaled);
    let t = tier(r_raw, &policy);
    let admit = auto_admit(r_raw, input.budget_scaled, &policy);

    // 4. the FULL signed capability chain-of-authority (the gap closure): a forged / broken / misrooted
    //    chain, or a bad leaf signature, makes chain_ok=false => allow=0 => the guest's assert_eq!(allow,1)
    //    panics => the proof is UNPROVABLE. verified in-circuit, so the receipt attests the whole chain.
    let chain_ok = verify_full_chain(input);

    let allow = predicates_ok && caveats_ok && admit && chain_ok;
    // r at scale S (r_raw is at scale S²): divide to report the proven risk.
    let r_scaled = (r_raw / (S as u128)) as u64;

    Decision {
        allow: if allow { 1 } else { 0 },
        r_scaled,
        tier: t,
        action_commit,
        policy_commit,
        plan_commit,
        chain_verified: if chain_ok { 1 } else { 0 },
    }
}
