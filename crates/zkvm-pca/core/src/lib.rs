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
pub mod context;
pub mod intent;
pub mod jsnum;
pub mod pq_suites;
pub mod action_schema;
pub mod rule22;
pub mod intent_session;
pub mod intent_acc;
pub mod oracle_facts;
pub mod offer_set;
pub mod param_provenance;
pub mod label_receipts;
pub mod intent_classifier;
pub mod intent_layers;
pub mod intent_map;
pub mod intent_v2;
pub mod predicates;
pub mod risk;
pub mod safe_regex;

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
    /// `None` = absent; `Some(Value::Null)` = an explicit `null` (the TS reference resolves `subject` to `null` then, and
    /// the context digest keeps the two apart).
    #[serde(default, deserialize_with = "present")]
    pub subject: Option<Value>,
    #[serde(default, deserialize_with = "present")]
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
    // ---- caveat context the VM cannot derive (R3-12: the delegation depth is NOT an input; it is
    //      `chain.len() - 1`, derived in-guest. A stray `delegation_depth` key in the JSON is ignored) -----
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
    /// PCA 0.4.2 Intent Layer v2: the verifier state the v2 checks read (TS `IntentV2Context`: policy, params, schema docs +
    /// keys, session root + grants + revocation evidence + the verifier's session-root PQ pins (`session.pq_pins`), layers, accumulator state / monitors / receipts / last_seq, W-B
    /// artifacts + policy). Its `hashCanonical` is committed to the journal (`context.intent_v2.ctx_digest`).
    #[serde(default)]
    pub intent_v2: Option<Value>,
    /// The full signed PCActn wire object (the leaf holder's signed intent). Its `sig`/`alg`/`pq_pk`/
    /// `pq_sig` and the canonical body (minus `sig`/`threshold`/`pq_sig`) give the leaf-holder signature
    /// `verifyLeafSuite` checks. Absent => chain verification fails closed.
    #[serde(default)]
    pub pcactn: Option<Value>,
}

/// Keep a JSON `null` as `Some(Value::Null)` (serde's `Option` would turn it into `None`, i.e. "absent").
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

/// Version of the guest program's semantics, committed as the FIRST journal field. A verifier refuses any journal below
/// [`MIN_GUEST_VERSION`] (and journals of guests older than this field do not decode at all). 7 = red-team round 6;
/// 8 = PCA 0.4.1/0.4.2: root caveats outside the envelope are enforced and `max_spend` is implemented; 9 = PCA 0.4.2 R3-01:
/// a PQ / hybrid session root verifies only under the verifier's pin (`intent_v2.session.pq_pins`); 10 = PCA 0.4.2 re-pin:
/// `intent_v2_active` is also true for a present malformed v2 context (fail closed, as the reference), a guest rebuild with
/// the same decision semantics. (Rule 22 / version 2 action schemas are in this source but NOT yet in a proven image: the rebuild
/// that ships them is guest version 11 with a new image id and regenerated receipts; a version-10 image refuses every version 2
/// schema, so its receipts stay sound and MIN_GUEST_VERSION stays 10.)
pub const GUEST_VERSION: u32 = 10;
/// The oldest guest semantics a verifier accepts. 9: a version-8 receipt may have admitted a pure-PQ / hybrid session root
/// under the PQ key named in the root's own `principals[]` (anyone naming a principal could sign it), so it is refused; a
/// version-7 receipt does not prove that the root grant's own caveats held (the 0.4.1 security fix). 10: the guest rebuilt at
/// the 0.4.2 re-pin (`intent_v2_active` fail-closed); the version-9 image (`c5107456...`) is on the deny-list.
pub const MIN_GUEST_VERSION: u32 = 10;

/// The public statement the guest commits to the receipt journal.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    /// [`GUEST_VERSION`] of the guest that produced this journal.
    pub guest_version: u32,
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
    /// RT-06: the evaluation context (time, subject, env, rate history, depth, tool binding, risk inputs,
    /// budget, floor, root principal, leaf PCActn digest). A verifier pins it with
    /// [`context::check_context`]; without that call the receipt says nothing about when or for whom.
    pub context: context::Context,
}

/// Parse a JSON `DecideInput` and run [`decide`]. Fails CLOSED (allow=0) on any parse error. This is
/// the single entry point the zkVM guest calls (the input is passed as a JSON string so `serde_json`'s
/// self-describing deserialization can handle the `serde_json::Value` fields — risc0's own non-
/// self-describing serde format cannot, as `Value` needs `deserialize_any`).
pub fn decide_from_str(json: &str) -> Decision {
    match serde_json::from_str::<DecideInput>(json) {
        Ok(input) => decide(&input),
        Err(_) => Decision {
            guest_version: GUEST_VERSION,
            allow: 0,
            r_scaled: S,
            tier: 3,
            action_commit: String::new(),
            policy_commit: String::new(),
            plan_commit: String::new(),
            chain_verified: 0,
            context: context::Context::default(),
        },
    }
}

/// Build the leaf PCActn signature material from the full signed PCActn wire object. The signed message
/// is `thresholdMessage(pcactn)` = `SIG_DOMAIN ‖ sha256(canonical(body))` where `body` is the PCActn with
/// its UNSIGNED containers `sig`/`threshold`/`pq_sig` removed (faithful to `pcactn.ts` `thresholdMessage`
/// and `wire.ts`). Returns `None` if the PCActn is not a JSON object.
pub fn leaf_sig_from_pcactn(pcactn: &Value) -> Option<chain::LeafSig> {
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
    // the root IS the verifier's grant (checked above): a PQ root verifies under it (`trustedRoot: grant`, R3-01)
    chain::verify_chain_with(&input.chain, root_pk, Some(&input.grant), &leaf).ok
}

/// R3-12: the delegation depth is derived from the verified chain, never supplied by the prover.
pub fn derived_delegation_depth(chain: &[Value]) -> u64 {
    chain.len().saturating_sub(1) as u64
}

/// R3-11: the caveats the delegation hops APPENDED to the root (the TS `decide`:
/// `chain.last.caveats.slice(grant.caveats.length)`). Because [`chain::verify_hops`] proves every hop's caveat
/// list is an exact prefix of the next, the leaf list is the union of every hop's caveats, so evaluating the
/// leaf's appended caveats evaluates the intersection of all constraints along the chain. Empty when the
/// chain is the lone root. Only meaningful once the chain verified.
fn delegated_caveats(input: &DecideInput) -> Vec<Value> {
    let root_len = input
        .chain
        .first()
        .and_then(|c| c.get("caveats"))
        .and_then(|c| c.as_array())
        .map_or(0, |a| a.len());
    input
        .chain
        .last()
        .and_then(|c| c.get("caveats"))
        .and_then(|c| c.as_array())
        .map(|a| a.iter().skip(root_len).cloned().collect())
        .unwrap_or_default()
}

/// 0.4.1 policy-vm.ts `rootCaveats`: the caveats on the ROOT grant that the policy layer evaluates as caveats = every entry
/// of `grant.caveats` except the FIRST `envelope` caveat (the one [`get_envelope`] reads; its predicates and inner caveats are
/// evaluated separately). `None` when `grant.caveats` is not an array (TS returns it as is and `evaluateCaveats` refuses
/// it: fail closed). A second `envelope` caveat stays in the list and is unsatisfied (unknown to the evaluator).
pub fn root_caveats(grant: &Value) -> Option<Vec<Value>> {
    let cs = grant.get("caveats")?.as_array()?;
    let first_env = cs.iter().position(|c| c.get("type").and_then(|t| t.as_str()) == Some("envelope"));
    Some(cs.iter().enumerate().filter(|(i, _)| Some(*i) != first_env).map(|(_, c)| c.clone()).collect())
}

/// 0.4.1 policy-vm.ts `policyCaveats`: [`root_caveats`] of the grant, then the caveats the hops appended
/// (`leaf.caveats[len(grant.caveats)..]`); the list the conformance `caveat_eval` vectors evaluate. `None` = not an array.
pub fn policy_caveats(grant: &Value, chain: &[Value]) -> Option<Vec<Value>> {
    let mut root = root_caveats(grant)?;
    let glen = grant.get("caveats").and_then(|c| c.as_array()).map_or(0, |a| a.len());
    if let Some(leaf) = chain.last().and_then(|c| c.get("caveats")).and_then(|c| c.as_array()) {
        root.extend(leaf.iter().skip(glen).cloned());
    }
    Some(root)
}

/// R3-13: what [`bind_pcactn`] proved and the journal commits.
pub struct Binding {
    pub grant_ref: String,
    pub node_id: String,
}

fn str_of<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|x| x.as_str())
}

/// R3-13: tie the signed PCActn to the chain, the action, the plan and the node the gate evaluated. The
/// PCActn signature (checked by `verify_chain`) covers every field compared here, so after this returns
/// `Some`, the signed leaf intent, the verified chain and the evaluated inputs are one object:
///   * `pcactn.grant_ref` is non-empty and equals `chain[0].id`;
///   * `pcactn.cap_chain` is the verified chain (canonical-hash equal);
///   * `pcactn.action` equals the evaluated `action` (canonical-hash equal);
///   * `pcactn.plan.root` equals the plan root recomputed in-guest from `plan`, `pcactn.plan.node_id` names a
///     node of that plan (and equals `node_id` when the prover also supplies one), and that node's leaf
///     fields match the action (verb, resource, reversibility class, params digest when present) and the signed
///     `conditions_digest` (absent == the empty conditions digest, as the TS verifier);
///   * `pcactn.tool_binding` equals the `tool_binding` the `tool_schema` caveat compared against;
///   * 0.4.2: a present `pcactn.intent` is well formed and opens the root grant's goal commitment ([`intent::bind_intent`]);
///   * R4-04: `ver == 2`, `aud` a non-empty string, `counter >= 0`, and `iat < exp <= iat + 1h`, `iat <= now + 60s`,
///     `now <= exp` (all strictly typed safe integers, none optional).
/// Fails CLOSED (`None`) on any absence or mismatch.
pub fn bind_pcactn(input: &DecideInput) -> Option<Binding> {
    let pc = input.pcactn.as_ref()?;
    let root_cap = input.chain.first()?;
    // grant_ref
    let grant_ref = str_of(pc, "grant_ref")?;
    if grant_ref.is_empty() || Some(grant_ref) != str_of(root_cap, "id") {
        return None;
    }
    // the signed chain is the verified chain
    let signed_chain = pc.get("cap_chain")?;
    if commit::hash_canonical(signed_chain) != commit::hash_canonical(&Value::Array(input.chain.clone())) {
        return None;
    }
    // the signed action is the evaluated action
    if commit::hash_canonical(pc.get("action")?) != commit::hash_canonical(&input.action) {
        return None;
    }
    // the signed plan root is the committed plan, the node is in it and matches the action
    let plan_commit = commit::plan_commitment(&input.plan)?;
    let plan = pc.get("plan")?;
    if str_of(plan, "root") != Some(plan_commit.as_str()) {
        return None;
    }
    // R4-04: the signed PCActn's own version, audience, validity window and counter (verifyPCActnCore's `version`,
    // `audience`, `validity`, `counter`). All mandatory and strictly typed; the window is evaluated at the proven `now`
    // (which the verifier pins to its own clock) and the facts themselves are committed to the journal.
    let facts = context::PcactnFacts::from_pcactn(pc)?;
    facts.check_freshness(input.now).ok()?;
    let node_id = str_of(plan, "node_id")?;
    if let Some(n) = &input.node_id {
        if n != node_id {
            return None;
        }
    }
    // verifyPCActnCore `plan_inclusion`: the leaf is recomputed FROM THE SIGNED ACTION (merkle.ts `planLeaf`, with its
    // `??` defaults: an absent or `null` params_digest / reversibility_class / conditions_digest takes the default, any
    // other value is committed as is) and must be a leaf of the committed plan.
    let cond = match plan.get("conditions_digest") {
        None | Some(Value::Null) => Value::String(commit::conditions_digest(&Value::Object(serde_json::Map::new()))),
        Some(v) => v.clone(),
    };
    let action_leaf = commit::plan_leaf(&Value::String(node_id.to_string()), &input.action, cond)?;
    let want = commit::hash_canonical(&action_leaf);
    if !input.plan.iter().any(|n| commit::hash_canonical(&commit::plan_node_leaf(n)) == want) {
        return None;
    }
    // tool binding
    let signed_tb = match pc.get("tool_binding") {
        None => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => return None,
    };
    if signed_tb != input.tool_binding.as_deref() {
        return None;
    }
    // PCA 0.4.2 Intent Layer M2: a present signed `intent` slot must be well formed and open the root grant's goal
    // commitment (intent-binding.ts rule 2); the claims are committed to the journal (`Context::intent`), and the relying
    // party's fidelity / residual-risk policy is applied by the verifier (`check_context`).
    // Intent Layer v2 (rule 13 wire): a present `intent_session` member must be well formed (closed set, digests, bounds).
    if let Some(is) = pc.get("intent_session") {
        intent_session::validate_intent_session_wire(is).ok()?;
    }
    intent::bind_intent(pc, &input.grant).ok()?;
    Some(Binding { grant_ref: grant_ref.to_string(), node_id: node_id.to_string() })
}

/// The plan node the signed PCActn names: the first node whose `id` equals `pcactn.plan.node_id` (policy-vm.ts
/// `plan.find((n) => n.id === nodeId)` with `nodeId = pcactn.plan.node_id`).
fn signed_node(input: &DecideInput) -> Option<&Value> {
    let id = input.pcactn.as_ref()?.get("plan")?.get("node_id")?.as_str()?;
    input.plan.iter().find(|n| n.get("id").and_then(|v| v.as_str()) == Some(id))
}

fn is_num(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64().filter(|f| f.is_finite()),
        _ => None,
    }
}

/// envelope.ts `readEnvelope` + risk.ts `validateRiskPolicy`: a string `goal_commit`, array `predicates` and `caveats`,
/// an object (or array) `agent_binding`, and a valid risk policy. Anything else: no envelope (deny).
pub fn envelope_well_formed(e: &Value) -> bool {
    let ok_obj = |v: Option<&Value>| matches!(v, Some(Value::Object(_)) | Some(Value::Array(_)));
    if !matches!(e.get("goal_commit"), Some(Value::String(_))) {
        return false;
    }
    if !matches!(e.get("predicates"), Some(Value::Array(_))) || !matches!(e.get("caveats"), Some(Value::Array(_))) {
        return false;
    }
    if !ok_obj(e.get("agent_binding")) {
        return false;
    }
    let rp = e.get("risk_policy");
    if !ok_obj(rp) {
        return false;
    }
    let rp = rp.unwrap();
    let w = rp.get("weights");
    if !ok_obj(w) {
        return false;
    }
    for k in ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"] {
        match is_num(w.and_then(|w| w.get(k))) {
            Some(x) if x >= 0.0 => {}
            _ => return false,
        }
    }
    let mut f = [0f64; 6];
    for (i, k) in ["theta1", "theta2", "kappa", "lambda", "rho", "bMax"].iter().enumerate() {
        match is_num(rp.get(*k)) {
            Some(x) => f[i] = x,
            None => return false,
        }
    }
    let [theta1, theta2, kappa, lambda, rho, bmax] = f;
    !(theta1 < 0.0 || theta2 < theta1 || kappa <= 0.0 || lambda < 0.0 || rho < 0.0 || bmax < 0.0)
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

/// Build the action/subject/env root the predicate & caveat evaluators read. The `action` root is the TS reference's
/// `ActionContext.action` = `{verb, resource, params, reversibility_class}` of the signed action (other keys of the
/// signed action, e.g. `params_digest`, are not visible to conditions). A key the action lacks is a TS `undefined`
/// member (see [`predicates::Ctx::action_has_undefined`]).
///
/// The predicate env is given explicitly (Intent Layer v2: the verifier-computed members replace the host's, see
/// [`intent_v2::v2_env`]).
fn action_root_with_env(input: &DecideInput, env: Option<&Value>) -> Value {
    let mut a = serde_json::Map::new();
    for k in ["verb", "resource", "params", "reversibility_class"] {
        if let Some(v) = input.action.get(k) {
            a.insert(k.to_string(), v.clone());
        }
    }
    let mut m = serde_json::Map::new();
    m.insert("action".to_string(), Value::Object(a));
    if let Some(s) = &input.subject {
        m.insert("subject".to_string(), s.clone());
    }
    if let Some(e) = env {
        m.insert("env".to_string(), e.clone());
    }
    Value::Object(m)
}

/// `MAX_ARTIFACT_BYTES` (pcactn.ts): largest JSON blob a verifier parses.
pub const MAX_ARTIFACT_BYTES: usize = 524_288;
/// `MAX_CAVEATS_PER_HOP` (capability.ts).
pub const MAX_CAVEATS_PER_HOP: usize = 256;
/// `MAX_CAVEATS_PER_CHAIN` (capability.ts).
pub const MAX_CAVEATS_PER_CHAIN: usize = 1024;

/// `caveatLimitExceeded` (capability.ts): raw array lengths, before any hashing.
pub fn caveat_limit_exceeded(chain: &[Value]) -> bool {
    let mut total = 0usize;
    for c in chain {
        let n = c.get("caveats").and_then(|x| x.as_array()).map_or(0, |a| a.len());
        if n > MAX_CAVEATS_PER_HOP {
            return true;
        }
        total += n;
    }
    total > MAX_CAVEATS_PER_CHAIN
}

/// R5-ZK-03: the strict wire limits, enforced IN the guest. Every WIRE document (the ones the TS verifier strict-parses or
/// strict-hashes: grant, chain, signed action, PCActn, plan) must (a) be within `MAX_ARTIFACT_BYTES` (512 KiB) as compact
/// JSON, (b) pass the strict canonical profile (safe integers only, no `-0`, no exponent / over-precise floats, nesting
/// <= 32) and (c) respect the caveat caps (256 per hop, 1024 per chain). R6-ZK-04: `subject` and `env` are the resource
/// server's own context, which the TS reference never canonicalizes strictly, so they are NOT held to the profile.
/// `false` => the decision is denied (and the guest's `allow == 1` assertion makes the proof unprovable).
pub fn wire_limits_ok(input: &DecideInput) -> bool {
    let plan = Value::Array(input.plan.clone());
    let chain = Value::Array(input.chain.clone());
    let mut docs: Vec<&Value> = vec![&input.grant, &input.action, &plan, &chain];
    if let Some(v) = &input.pcactn {
        docs.push(v);
    }
    for d in docs {
        if canonical::json_len(d) > MAX_ARTIFACT_BYTES || canonical::strict_violation(d).is_some() {
            return false;
        }
    }
    !caveat_limit_exceeded(&input.chain)
}

/// Run the full Policy-VM release+auto-admit gate. Total; never panics on malformed input (fails CLOSED
/// with allow=0). The commitments are always computed (binding is independent of the allow outcome).
pub fn decide(input: &DecideInput) -> Decision {
    if !wire_limits_ok(input) {
        return Decision {
            guest_version: GUEST_VERSION,
            allow: 0,
            r_scaled: S,
            tier: 3,
            action_commit: String::new(),
            policy_commit: String::new(),
            plan_commit: String::new(),
            chain_verified: 0,
            context: context::Context::default(),
        };
    }
    // R4-05 mirror: ONE regex work budget for the whole decision (envelope predicates + every caveat of every hop),
    // exactly like the TS `decide`.
    safe_regex::with_regex_budget(|| decide_inner(input))
}

fn decide_inner(input: &DecideInput) -> Decision {
    let action_commit = commit::action_commitment(&input.action);
    let policy_commit = commit::policy_commitment(&input.grant);
    let plan_commit = commit::plan_commitment(&input.plan).unwrap_or_default();

    let envelope = get_envelope(&input.grant).filter(|e| envelope_well_formed(e));
    let policy = envelope.and_then(parse_policy);

    // Fail closed if there is no well-formed envelope / policy.
    let (policy, envelope) = match (policy, envelope) {
        (Some(p), Some(e)) => (p, e),
        _ => {
            return Decision {
                guest_version: GUEST_VERSION,
                allow: 0,
                r_scaled: S,
                tier: 3,
                action_commit,
                policy_commit,
                plan_commit,
                chain_verified: 0,
                context: context::Context::from_input(input),
            }
        }
    };

    // 0.4.2 Intent Layer v2: the v2 checks (rules 13-18 + V5 layers), reported only when the PCActn carries `intent_session`
    // or a v2 policy is active; with `intent_session` the verifier-computed env members replace the host's.
    let v2 = input
        .pcactn
        .as_ref()
        .map(|pc| intent_v2::decide_intent_v2(pc, &input.grant, input.intent_v2.as_ref(), input.now))
        .unwrap_or_default();
    let v2_ok = v2.all_ok();
    let eff_env = match input.pcactn.as_ref() {
        Some(pc) => intent_v2::v2_env(input.env.as_ref(), pc, &v2),
        None => input.env.clone(),
    };
    let root = action_root_with_env(input, eff_env.as_ref());

    // 1. predicates (full DSL, default deny)
    let predicates = envelope
        .get("predicates")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();
    let ctx = Ctx::new(&root);
    let predicates_ok = evaluate_predicates(&predicates, &ctx).allowed;

    // reversibility class: `action.reversibility_class ?? node.reversibility_class` (policy-vm.ts), raw values. R6-ZK-03:
    // the node is the one the SIGNED PCActn names (`pcactn.plan.node_id`, first plan node with that id), never the first
    // node that happens to share the action's verb and resource.
    let rev_class = match input.action.get("reversibility_class") {
        Some(v) if !v.is_null() => Some(v.clone()),
        _ => signed_node(input).and_then(|n| n.get("reversibility_class")).cloned(),
    };

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
        delegation_depth: Some(derived_delegation_depth(&input.chain) as f64),
        recent_action_times: input.recent_action_times.clone(),
        action_root: &root,
        tool,
        tool_args,
        tool_signature_digest: input.tool_binding.clone(),
    };
    let caveats_ok = evaluate_caveats(&env_caveats, &cctx).ok;
    // 0.4.1 (security): caveats placed directly on the ROOT grant, outside the envelope, are signed authority too and are
    // enforced exactly like the caveats delegation hops append (policy-vm.ts `decide`: `rootCaveats(grant)`); unknown types,
    // including a second `envelope` caveat, are unsatisfied (fail closed), and a non-array caveat list refuses.
    let root_ok = root_caveats(&input.grant).is_some_and(|rc| evaluate_caveats(&rc, &cctx).ok);
    // R3-11: caveats appended by delegation hops must ALSO hold (attenuation = every hop's caveats hold).
    let delegated_ok = evaluate_caveats(&delegated_caveats(input), &cctx).ok;

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

    // R3-13: the signed PCActn is bound to the chain, action, plan and node that were evaluated.
    let bound_ok = bind_pcactn(input).is_some();

    let allow = predicates_ok && caveats_ok && root_ok && delegated_ok && admit && chain_ok && bound_ok && v2_ok;
    // r at scale S (r_raw is at scale S²): divide to report the proven risk.
    let r_scaled = (r_raw / (S as u128)) as u64;

    Decision {
        guest_version: GUEST_VERSION,
        allow: if allow { 1 } else { 0 },
        r_scaled,
        tier: t,
        action_commit,
        policy_commit,
        plan_commit,
        chain_verified: if chain_ok { 1 } else { 0 },
        context: context::Context::from_input(input).with_intent_v2(input, &v2, eff_env.as_ref()),
    }
}
