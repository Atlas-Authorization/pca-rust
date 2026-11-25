//! A swiftide tool wrapper that authorizes before the inner tool runs (feature `swiftide`; `swiftide-core` 0.34).
//!
//! [`PcaSwiftideTool`] wraps any boxed [`swiftide_core::chat_completion::Tool`]: the call's arguments go through a [`ToolGate`] first. The
//! proof is found by the [`ProofFn`] you pass (swiftide's agent context carries no proof slot of its own). A refusal is a failed tool output
//! (`ToolOutput::fail`, the agent sees why); the inner tool never runs.
use crate::guarded_tool::{ProofFn, ToolGate};
use crate::openai_agents::WithPcaToolOptions;
use async_trait::async_trait;
use serde_json::Value;
use std::borrow::Cow;
use swiftide_core::chat_completion::errors::ToolError;
use swiftide_core::chat_completion::{Tool, ToolCall, ToolOutput, ToolSpec};
use swiftide_core::AgentContext;

/// `inner`, guarded: every call is authorized first.
#[derive(Clone)]
pub struct PcaSwiftideTool {
    inner: Box<dyn Tool>,
    gate: ToolGate,
}

impl PcaSwiftideTool {
    /// A configuration error is an `Err` here, never a silent pass at call time.
    pub fn new(inner: Box<dyn Tool>, proof: ProofFn, options: WithPcaToolOptions) -> Result<Self, String> {
        let gate = ToolGate::new(&inner.name(), proof, options)?;
        Ok(PcaSwiftideTool { inner, gate })
    }
}

#[async_trait]
impl Tool for PcaSwiftideTool {
    async fn invoke(&self, agent_context: &dyn AgentContext, tool_call: &ToolCall) -> Result<ToolOutput, ToolError> {
        // arguments that are not JSON are refused before anything runs
        let input: Value = match tool_call.args() {
            None => Value::Null,
            Some(a) => serde_json::from_str(a).map_err(ToolError::wrong_arguments)?,
        };
        match self.gate.authorize(&input) {
            Ok(()) => self.inner.invoke(agent_context, tool_call).await,
            Err(e) => Ok(ToolOutput::fail(e.to_string())),
        }
    }

    fn name(&self) -> Cow<'_, str> {
        self.inner.name()
    }

    fn tool_spec(&self) -> ToolSpec {
        self.inner.tool_spec()
    }
}
