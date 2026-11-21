//! OpenAI chat-completions tool-call guard over `async-openai` (feature `async-openai`; types of `async-openai` 0.43).
//!
//! A thin glue layer over [`crate::openai_agents`]: every function call the model emits goes through the guarded
//! [`AgentTool`]s of [`crate::openai_agents::pca_tools`] / [`crate::openai_agents::with_pca_tool`] BEFORE the tool runs, and the
//! answer is the `tool` message to send back. A refusal (no proof, bad proof, wrong verb, policy) is that message's text; the
//! tool does not run. Fail closed: unknown tools, custom (non-function) tool calls and undecodable arguments are refused too.
use crate::openai_agents::{AgentTool, ToolError};
use async_openai::types::chat::{
    ChatCompletionMessageToolCall, ChatCompletionMessageToolCalls, ChatCompletionRequestMessage, ChatCompletionRequestToolMessage,
    ChatCompletionRequestToolMessageContent,
};
use serde_json::{json, Value};
use std::sync::Arc;

fn message(tool_call_id: &str, text: String) -> ChatCompletionRequestToolMessage {
    ChatCompletionRequestToolMessage { content: ChatCompletionRequestToolMessageContent::Text(text), tool_call_id: tool_call_id.to_string() }
}

/// Run one function call through its guarded tool and return the `tool` message. `run_context` carries the proof
/// (`{"pca": "<encoded PCActn>"}` by default, see [`crate::openai_agents::proof_from_run_context`]).
pub fn tool_message(tools: &[(String, Arc<AgentTool>)], call: &ChatCompletionMessageToolCall, run_context: &Value) -> ChatCompletionRequestToolMessage {
    let id = call.id.as_str();
    let Some((_, tool)) = tools.iter().find(|(n, _)| *n == call.function.name) else {
        return message(id, format!("PCA tool denied (config) for {}: unknown tool", call.function.name));
    };
    let raw = call.function.arguments.trim();
    let args = if raw.is_empty() { Ok(json!({})) } else { crate::strict_parse(raw) };
    let args = match args {
        Ok(a) => a,
        Err(e) => return message(id, format!("tool arguments are not valid JSON: {e}")),
    };
    let Some(run) = tool.execute.as_ref() else {
        return message(id, format!("PCA tool denied (config) for {}: the tool has no execute()", call.function.name));
    };
    match run(&args, Some(run_context)) {
        Ok(Value::String(s)) => message(id, s),
        Ok(v) => message(id, v.to_string()),
        Err(ToolError::Denied(d)) => message(id, d.message),
        Err(ToolError::Tool(m)) => message(id, m),
    }
}

/// Every tool call of an assistant turn answered with a `tool` message, in order. A custom (non-function) tool call is refused.
pub fn run_tool_calls(tools: &[(String, Arc<AgentTool>)], calls: &[ChatCompletionMessageToolCalls], run_context: &Value) -> Vec<ChatCompletionRequestMessage> {
    calls
        .iter()
        .map(|c| {
            ChatCompletionRequestMessage::Tool(match c {
                ChatCompletionMessageToolCalls::Function(f) => tool_message(tools, f, run_context),
                ChatCompletionMessageToolCalls::Custom(x) => {
                    message(&x.id, "PCA tool denied (config) for (custom tool): custom tool calls are not supported".into())
                }
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openai_agents::{with_pca_tool, Verify, VerifyResult, WithPcaToolOptions};
    use async_openai::types::chat::FunctionCall;

    fn guarded(allow: bool) -> Vec<(String, Arc<AgentTool>)> {
        let inner = AgentTool {
            name: Some("refund".into()),
            execute: Some(Arc::new(|input: &Value, _: Option<&Value>| Ok(json!({ "refunded": input["amount"] })))),
            ..Default::default()
        };
        let verify: Verify =
            Verify::Func(Arc::new(move |_: &Value| Ok(VerifyResult { allow, checks: None, reason: (!allow).then(|| "stub deny".to_string()) })));
        let opts = WithPcaToolOptions { mode: Some("signature-only".into()), verify: Some(verify), ..Default::default() };
        vec![("refund".to_string(), Arc::new(with_pca_tool(&inner, opts).unwrap()))]
    }

    fn call(name: &str, args: &str) -> ChatCompletionMessageToolCall {
        ChatCompletionMessageToolCall { id: "call_1".into(), function: FunctionCall { name: name.into(), arguments: args.into() } }
    }

    fn text(m: &ChatCompletionRequestToolMessage) -> String {
        match &m.content {
            ChatCompletionRequestToolMessageContent::Text(t) => t.clone(),
            _ => panic!("text content expected"),
        }
    }

    fn ctx() -> Value {
        json!({ "pca": "{\"action\":{\"verb\":\"refund\"}}" })
    }

    #[test]
    fn allowed_call_runs_the_tool() {
        let m = tool_message(&guarded(true), &call("refund", "{\"amount\":5}"), &ctx());
        assert_eq!(m.tool_call_id, "call_1");
        assert_eq!(text(&m), "{\"refunded\":5}");
    }

    #[test]
    fn denied_call_returns_the_refusal() {
        let t = text(&tool_message(&guarded(false), &call("refund", "{\"amount\":5}"), &ctx()));
        assert!(t.starts_with("PCA tool denied (verify) for refund"), "{t}");
    }

    #[test]
    fn missing_proof_unknown_tool_and_bad_args_are_refused() {
        let tools = guarded(true);
        assert!(text(&tool_message(&tools, &call("refund", "{}"), &json!({}))).contains("(missing)"));
        assert!(text(&tool_message(&tools, &call("nope", "{}"), &ctx())).contains("unknown tool"));
        assert!(text(&tool_message(&tools, &call("refund", "{not json"), &ctx())).contains("not valid JSON"));
    }

    #[test]
    fn run_tool_calls_answers_each_call() {
        let calls = vec![ChatCompletionMessageToolCalls::Function(call("refund", "{\"amount\":1}"))];
        let out = run_tool_calls(&guarded(true), &calls, &ctx());
        assert!(matches!(&out[0], ChatCompletionRequestMessage::Tool(m) if m.tool_call_id == "call_1"));
    }
}
