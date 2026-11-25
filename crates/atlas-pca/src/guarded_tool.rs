//! Framework-neutral tool guards, the shared core of the AI-stack adapters.
//!
//! * [`ToolGate`] is the resource-server side: it verifies the proof that comes with a tool call (and the call's own input) before the
//!   tool runs, through the same guard as [`crate::openai_agents::with_pca_tool`]. A refusal is an `Err`; the tool never runs.
//! * [`GuardedTool`] is the agent side (the structural wrapper of the reference's LlamaIndex adapter): every call builds a signed
//!   PCActn for the call with [`crate::agent::Agent::act`], hands its headers to `on_proof`, runs the tool, and records the result
//!   as untrusted tool output. It does not authorize anything; the resource server's verifier decides.
//!
//! shortcut: `GuardedTool` has no local dry-run fail-fast (the reference's `failFast`); the server refuses an out-of-grant action.
use crate::adapters::{provenance_headers, AdapterSession};
use crate::agent::{Agent, Suite};
use crate::openai_agents::{with_pca_tool, AgentTool, ToolError, WithPcaToolOptions};
use crate::Operation;
use serde_json::{json, Map, Value};
use std::sync::{Arc, Mutex};

/// Finds the encoded PCActn of a call from its input (a framework with no dispatch context keeps it in a session, a task-local, ...).
pub type ProofFn = Arc<dyn Fn(&Value) -> Option<String> + Send + Sync>;

/// A call's verifier: no proof, or a proof that does not verify, is a refusal.
#[derive(Clone)]
pub struct ToolGate {
    gate: AgentTool,
    proof: ProofFn,
}

impl ToolGate {
    /// A configuration error (unknown mode, missing verifier or policy) is an `Err` here, never a silent pass at call time.
    pub fn new(name: &str, proof: ProofFn, options: WithPcaToolOptions) -> Result<Self, String> {
        let base = AgentTool { name: Some(name.to_string()), execute: Some(Arc::new(|_: &Value, _: Option<&Value>| Ok(Value::Null))), ..Default::default() };
        Ok(ToolGate { gate: with_pca_tool(&base, options)?, proof })
    }

    /// `Ok` only when the call's proof verifies for `input`.
    pub fn authorize(&self, input: &Value) -> Result<(), ToolError> {
        let ctx = match (self.proof)(input) {
            Some(p) => json!({ "pca": p }),
            None => json!({}),
        };
        let run = self.gate.execute.as_ref().ok_or_else(|| ToolError::Tool("PCA tool denied (config): no guard".into()))?;
        run(input, Some(&ctx)).map(|_| ())
    }
}

/// `args -> resource`.
pub type ResourceFn = Arc<dyn Fn(&Value) -> String + Send + Sync>;
/// The tool being guarded: `args -> result`.
pub type InnerFn = Arc<dyn Fn(&Value) -> Result<Value, String> + Send + Sync>;
/// Receives the `PCA-Action` (and `PCA-Provenance`) headers of a call and its arguments, to forward to the resource server.
pub type OnProofFn = Arc<dyn Fn(&[(String, String)], &Value) + Send + Sync>;

/// Agent side: every call carries a fresh PCActn for `verb` on the call's resource.
pub struct GuardedTool {
    agent: Arc<Agent>,
    session: Option<Mutex<AdapterSession>>,
    verb: String,
    resource: ResourceFn,
    on_proof: Option<OnProofFn>,
    inner: InnerFn,
}

impl GuardedTool {
    /// `session`: the conversation's provenance recorder (provenance by default: the bundle rides with the proof and every result is
    /// recorded as untrusted); `None` sends the proof alone.
    pub fn new(agent: Arc<Agent>, session: Option<AdapterSession>, verb: &str, resource: ResourceFn, on_proof: Option<OnProofFn>, inner: InnerFn) -> Self {
        GuardedTool { agent, session: session.map(Mutex::new), verb: verb.to_string(), resource, on_proof, inner }
    }

    /// Build the proof, forward it, run the tool, record the result. A failure to build the proof refuses the call (the tool never runs).
    pub fn call(&self, args: &Value) -> Result<Value, String> {
        let resource = (self.resource)(args);
        let mut headers: Vec<(String, String)> = Vec::new();
        if let Some(s) = &self.session {
            let mut s = s.lock().map_err(|_| "guarded tool: session lock poisoned".to_string())?;
            let bundle = s.recorder.for_action(&Operation::new(self.verb.clone(), resource.clone(), args.clone()))?;
            headers.extend(provenance_headers(Some(&bundle))?);
        }
        let act = self.agent.act(&self.verb, &resource, Some(args), Map::new(), &Suite::default())?;
        headers.extend(act.headers);
        if let Some(f) = &self.on_proof {
            f(&headers, args);
        }
        let out = (self.inner)(args)?;
        if let Some(s) = &self.session {
            s.lock().map_err(|_| "guarded tool: session lock poisoned".to_string())?.record_tool_result(&self.verb, &out)?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openai_agents::{Verify, VerifyResult};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn gate(allow: bool, proof: Option<&'static str>) -> ToolGate {
        let verify = Verify::Func(Arc::new(move |_: &Value| Ok(VerifyResult { allow, checks: None, reason: (!allow).then(|| "stub deny".to_string()) })));
        let p: ProofFn = Arc::new(move |_| proof.map(String::from));
        ToolGate::new("refund", p, WithPcaToolOptions { mode: Some("signature-only".into()), verify: Some(verify), ..Default::default() }).unwrap()
    }

    #[test]
    fn the_gate_admits_only_a_verified_proof() {
        let proof = Some("{\"action\":{\"verb\":\"refund\"}}");
        assert!(gate(true, proof).authorize(&json!({})).is_ok());
        assert!(gate(false, proof).authorize(&json!({})).is_err());
        assert!(gate(true, None).authorize(&json!({})).is_err());
    }

    #[test]
    fn a_guarded_tool_signs_each_call_and_runs_the_tool() {
        let principal = crate::agent::KeyPair::generate().unwrap();
        let key = crate::agent::KeyPair::generate().unwrap();
        let env = json!({"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": crate::agent::default_risk_policy()});
        let grant = crate::agent::mint_grant(&principal, &key.public, &env, "refund", None, None, &Suite::default()).unwrap().grant;
        let agent = Arc::new(Agent::new(key, grant, "aud", 0));
        let runs = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(AtomicUsize::new(0));
        let (r, s) = (runs.clone(), seen.clone());
        let inner: InnerFn = Arc::new(move |_| {
            r.fetch_add(1, Ordering::SeqCst);
            Ok(json!("done"))
        });
        let on_proof: OnProofFn = Arc::new(move |h, _| {
            assert!(h.iter().any(|(k, _)| k.eq_ignore_ascii_case("PCA-Action")));
            s.fetch_add(1, Ordering::SeqCst);
        });
        let t = GuardedTool::new(agent, None, "refund", Arc::new(|a| format!("orders/{}", a["id"])), Some(on_proof), inner);
        assert_eq!(t.call(&json!({"id": 1})).unwrap(), json!("done"));
        assert_eq!((runs.load(Ordering::SeqCst), seen.load(Ordering::SeqCst)), (1, 1));
    }
}
