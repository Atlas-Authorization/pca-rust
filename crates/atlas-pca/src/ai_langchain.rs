//! A langchain-rust tool wrapper that authorizes before the inner tool runs (feature `langchain-rust`; `langchain-rust` 8).
//!
//! [`PcaLangchainTool`] wraps any [`langchain_rust::tools::Tool`]: the call's input goes through a [`ToolGate`] first, on BOTH entry points
//! (`call` and `run`), so neither bypasses the check. The proof is found by the [`ProofFn`] you pass (the trait has no dispatch context).
//! A refusal is an `Err`; the inner tool never runs.
use crate::guarded_tool::{ProofFn, ToolGate};
use crate::openai_agents::WithPcaToolOptions;
use async_trait::async_trait;
use langchain_rust::tools::Tool;
use serde_json::Value;
use std::error::Error;

/// `inner`, guarded: every call is authorized first.
pub struct PcaLangchainTool<T> {
    inner: T,
    gate: ToolGate,
}

impl<T: Tool> PcaLangchainTool<T> {
    /// A configuration error is an `Err` here, never a silent pass at call time.
    pub fn new(inner: T, proof: ProofFn, options: WithPcaToolOptions) -> Result<Self, String> {
        let gate = ToolGate::new(&inner.name(), proof, options)?;
        Ok(PcaLangchainTool { inner, gate })
    }

    fn authorize(&self, input: &Value) -> Result<(), Box<dyn Error>> {
        self.gate.authorize(input).map_err(|e| Box::new(e) as Box<dyn Error>)
    }
}

#[async_trait]
impl<T: Tool> Tool for PcaLangchainTool<T> {
    fn name(&self) -> String {
        self.inner.name()
    }

    fn description(&self) -> String {
        self.inner.description()
    }

    fn parameters(&self) -> Value {
        self.inner.parameters()
    }

    async fn call(&self, input: &str) -> Result<String, Box<dyn Error>> {
        let v = serde_json::from_str::<Value>(input).unwrap_or_else(|_| Value::String(input.to_string()));
        self.authorize(&v)?;
        self.inner.call(input).await
    }

    async fn run(&self, input: Value) -> Result<String, Box<dyn Error>> {
        self.authorize(&input)?;
        self.inner.run(input).await
    }

    async fn parse_input(&self, input: &str) -> Value {
        self.inner.parse_input(input).await
    }
}
