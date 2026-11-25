//! MCP `tools/call` guard over `rmcp` (feature `rmcp`; `rmcp` 3.10): the PCA decision runs before a tool call is dispatched.
//!
//! * Server: [`PcaMcpGuard::call_tool`] wraps a `ServerHandler::call_tool` body: it authorizes the request (the proof is the
//!   request's `_meta["x-pca-action"]`, else the one the transport supplied, e.g. the decoded `PCA-Action` header), runs the
//!   handler only on an allow, and answers a refusal as an `isError` tool result carrying the refusal text. Fail closed.
//! * Client: [`attach_proof`] puts the encoded PCActn into the request's `_meta["x-pca-action"]`.
//!
//! The decision is [`crate::openai_agents::with_pca_tool`] built per call with the call's verb (the MCP tool name unless a
//! `verb_of` mapping is set), so a proof minted for one tool cannot authorize another.
use crate::openai_agents::{with_pca_tool, AgentTool, ToolError, WithPcaToolOptions};
use rmcp::model::{CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, RequestMetaObject};
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use std::future::Future;
use std::sync::Arc;

/// The `_meta` member carrying the encoded PCActn (the one `mcp::guard_tool_result` writes on results).
pub const PCA_META_KEY: &str = "x-pca-action";

/// Maps an MCP tool name to the PCA verb it needs a proof for.
pub type VerbOfFn = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Client side: carry the encoded PCActn on a `tools/call` request.
pub fn attach_proof(params: &mut CallToolRequestParams, encoded: &str) {
    params.meta.get_or_insert_with(RequestMetaObject::new).insert(PCA_META_KEY.to_string(), json!(encoded));
}

#[derive(Clone)]
pub struct PcaMcpGuard {
    options: WithPcaToolOptions,
    verb_of: Option<VerbOfFn>,
}

impl PcaMcpGuard {
    /// `options` is the shared [`WithPcaToolOptions`] (`verb` is set per call, any value here is replaced). The configuration is
    /// checked once here: an error is returned now, never as a silent pass at call time.
    pub fn new(options: WithPcaToolOptions) -> Result<Self, String> {
        with_pca_tool(&AgentTool { name: Some("(probe)".into()), ..Default::default() }, options.clone())?;
        Ok(PcaMcpGuard { options, verb_of: None })
    }

    /// Bind each tool to the verb `f(tool_name)` instead of the tool name.
    pub fn with_verb_of(mut self, f: VerbOfFn) -> Self {
        self.verb_of = Some(f);
        self
    }

    /// Decide one call: `Ok(())` to dispatch, `Err(result)` is the `isError` tool result to return instead.
    pub fn check(&self, request: &CallToolRequestParams, transport_proof: Option<&str>) -> Result<(), CallToolResult> {
        let refuse = |m: String| CallToolResult::error(vec![ContentBlock::text(m)]);
        let name = request.name.as_ref();
        let verb = self.verb_of.as_ref().map_or_else(|| name.to_string(), |f| f(name));
        let proof = request.meta.as_ref().and_then(|m| m.get(PCA_META_KEY)).and_then(Value::as_str).or(transport_proof);
        let gate = AgentTool { name: Some(name.to_string()), execute: Some(Arc::new(|_: &Value, _: Option<&Value>| Ok(Value::Null))), ..Default::default() };
        let options = WithPcaToolOptions { verb: Some(verb), ..self.options.clone() };
        let gate = with_pca_tool(&gate, options).map_err(refuse)?;
        let run = gate.execute.as_ref().ok_or_else(|| refuse("PCA tool denied (config): no guard".into()))?;
        let input = Value::Object(request.arguments.clone().unwrap_or_default());
        let run_context = proof.map_or_else(|| json!({}), |p| json!({ "pca": p }));
        match run(&input, Some(&run_context)) {
            Ok(_) => Ok(()),
            Err(ToolError::Denied(d)) => Err(refuse(d.message)),
            Err(ToolError::Tool(m)) => Err(refuse(m)),
        }
    }

    /// Wrap a `ServerHandler::call_tool` body: `run(request)` is only called when the PCA decision allows the call.
    pub async fn call_tool<F, Fut>(&self, request: CallToolRequestParams, transport_proof: Option<&str>, run: F) -> Result<CallToolResponse, McpError>
    where
        F: FnOnce(CallToolRequestParams) -> Fut,
        Fut: Future<Output = Result<CallToolResponse, McpError>>,
    {
        match self.check(&request, transport_proof) {
            Ok(()) => run(request).await,
            Err(refusal) => Ok(CallToolResponse::Complete(refusal)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openai_agents::{Verify, VerifyResult};

    fn guard(allow: bool) -> PcaMcpGuard {
        let verify = Verify::Func(Arc::new(move |_: &Value| Ok(VerifyResult { allow, checks: None, reason: (!allow).then(|| "stub deny".to_string()) })));
        PcaMcpGuard::new(WithPcaToolOptions { mode: Some("signature-only".into()), verify: Some(verify), ..Default::default() }).unwrap()
    }

    fn req(name: &'static str) -> CallToolRequestParams {
        CallToolRequestParams::new(name)
    }

    fn text_of(r: &CallToolResult) -> String {
        serde_json::to_string(&r.content).unwrap()
    }

    #[test]
    fn allowed_with_meta_proof_and_with_transport_proof() {
        let mut r = req("refund");
        attach_proof(&mut r, "{\"action\":{\"verb\":\"refund\"}}");
        assert!(guard(true).check(&r, None).is_ok());
        assert!(guard(true).check(&req("refund"), Some("{\"action\":{\"verb\":\"refund\"}}")).is_ok());
    }

    #[test]
    fn refusals_are_error_results() {
        let proof = "{\"action\":{\"verb\":\"refund\"}}";
        let denied = guard(false).check(&req("refund"), Some(proof)).unwrap_err();
        assert_eq!(denied.is_error, Some(true));
        assert!(text_of(&denied).contains("stub deny"));
        // no proof, and a proof minted for another tool
        assert!(text_of(&guard(true).check(&req("refund"), None).unwrap_err()).contains("(missing)"));
        assert!(text_of(&guard(true).check(&req("delete"), Some(proof)).unwrap_err()).contains("(binding)"));
    }

    #[test]
    fn a_bad_configuration_is_refused_at_build_time() {
        assert!(PcaMcpGuard::new(WithPcaToolOptions { mode: Some("nope".into()), ..Default::default() }).is_err());
    }
}
