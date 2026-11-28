//! A `rig` tool wrapper that authorizes before the inner tool runs (feature `rig`; `rig-core` 0.46).
//!
//! [`PcaTool`] wraps any [`rig_core::tool::Tool`]: the call's arguments go through a guarded [`AgentTool`]
//! ([`crate::openai_agents::with_pca_tool`]) first; a refusal is a `ToolExecutionError::refused` (the inner tool never runs). The
//! proof is read from the dispatch [`ToolContext`] slot [`PcaProof`] (the encoded PCActn); no proof is a refusal.
use crate::openai_agents::{with_pca_tool, AgentTool, ToolError, WithPcaToolOptions};
use rig_core::tool::{ContextValue, Tool, ToolContext, ToolErrorKind, ToolExecutionError};
use rig_core::wasm_compat::WasmCompatSend;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::future::Future;
use std::sync::Arc;

/// The encoded PCActn of a call, carried in the dispatch [`ToolContext`] (`context.insert(PcaProof(encoded))`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PcaProof(pub String);

impl ContextValue for PcaProof {
    const KEY: &'static str = "pca_proof";
}

/// `inner`, guarded: every call is authorized first.
pub struct PcaTool<T> {
    inner: T,
    gate: AgentTool,
}

impl<T: Tool> PcaTool<T> {
    /// A configuration error (unknown mode, missing verifier or policy) is an `Err` here, never a silent pass at call time.
    pub fn new(inner: T, options: WithPcaToolOptions) -> Result<Self, String> {
        let gate = AgentTool { name: Some(T::NAME.to_string()), execute: Some(Arc::new(|_: &Value, _: Option<&Value>| Ok(Value::Null))), ..Default::default() };
        Ok(PcaTool { inner, gate: with_pca_tool(&gate, options)? })
    }

    fn authorize(&self, context: &ToolContext, input: &Value) -> Result<(), ToolExecutionError> {
        let run_context = match context.get::<PcaProof>() {
            Ok(Some(PcaProof(p))) => json!({ "pca": p }),
            _ => json!({}),
        };
        let run = self.gate.execute.as_ref().ok_or_else(|| ToolExecutionError::refused("PCA tool denied (config): no guard"))?;
        match run(input, Some(&run_context)) {
            Ok(_) => Ok(()),
            Err(ToolError::Denied(d)) => Err(ToolExecutionError::refused(d.message)),
            Err(ToolError::Tool(m)) => Err(ToolExecutionError::refused(m)),
        }
    }
}

impl<T: Tool> Tool for PcaTool<T>
where
    T::Args: Serialize,
{
    const NAME: &'static str = T::NAME;
    type Args = T::Args;
    type Output = T::Output;
    type Error = ToolExecutionError;

    fn description(&self) -> String {
        self.inner.description()
    }

    fn parameters(&self) -> Value {
        self.inner.parameters()
    }

    fn call(&self, context: &mut ToolContext, args: Self::Args) -> impl Future<Output = Result<Self::Output, Self::Error>> + WasmCompatSend {
        async move {
            let input = serde_json::to_value(&args).map_err(|e| ToolExecutionError::new(ToolErrorKind::InvalidArgs, e.to_string()))?;
            self.authorize(context, &input)?;
            self.inner.call(context, args).await.map_err(|e| self.inner.map_error(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openai_agents::{Verify, VerifyResult};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        let mut f = Box::pin(f);
        let waker = Waker::from(Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);
        loop {
            if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    static RUNS: AtomicUsize = AtomicUsize::new(0);

    struct Refund;
    impl Tool for Refund {
        const NAME: &'static str = "refund";
        type Args = Value;
        type Output = String;
        type Error = std::io::Error;
        fn description(&self) -> String {
            "refund".into()
        }
        fn parameters(&self) -> Value {
            json!({ "type": "object" })
        }
        async fn call(&self, _context: &mut ToolContext, _args: Value) -> Result<String, std::io::Error> {
            RUNS.fetch_add(1, Ordering::SeqCst);
            Ok("done".into())
        }
    }

    fn guarded(allow: bool) -> PcaTool<Refund> {
        let verify = Verify::Func(Arc::new(move |_: &Value| Ok(VerifyResult { allow, checks: None, reason: (!allow).then(|| "stub deny".to_string()) })));
        PcaTool::new(Refund, WithPcaToolOptions { mode: Some("signature-only".into()), verify: Some(verify), ..Default::default() }).unwrap()
    }

    fn proof_ctx() -> ToolContext {
        let mut c = ToolContext::new();
        c.insert(PcaProof("{\"action\":{\"verb\":\"refund\"}}".into())).unwrap();
        c
    }

    #[test]
    fn allowed_runs_inner_tool() {
        let before = RUNS.load(Ordering::SeqCst);
        let out = block_on(guarded(true).call(&mut proof_ctx(), json!({ "amount": 1 }))).unwrap();
        assert_eq!(out, "done");
        assert_eq!(RUNS.load(Ordering::SeqCst), before + 1);
    }

    #[test]
    fn denied_and_missing_proof_never_run_inner_tool() {
        let before = RUNS.load(Ordering::SeqCst);
        let denied = block_on(guarded(false).call(&mut proof_ctx(), json!({}))).unwrap_err();
        assert!(denied.message().contains("PCA tool denied (verify)"), "{}", denied.message());
        let missing = block_on(guarded(true).call(&mut ToolContext::new(), json!({}))).unwrap_err();
        assert!(missing.message().contains("(missing)"), "{}", missing.message());
        assert_eq!(RUNS.load(Ordering::SeqCst), before);
    }
}
