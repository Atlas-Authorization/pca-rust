//! Agent-side framework-adapter helpers (the reference's `messageSegments`, `provenanceHeaders` and the `record*` helpers of
//! `@atlasauth/pca` src/adapters.ts): decide which parts of a chat transcript are the principal's own words (TRUSTED) and which
//! are tool output (UNTRUSTED), feed a [`ProvenanceRecorder`] accordingly, and carry the provenance bundle as an HTTP header.
//! Nothing here authorizes: the resource server's verifier decides. Messages are plain JSON values, so no vendor SDK is involved.
//!
//! shortcut: the reference keeps the "already recorded" message count in a `WeakMap` keyed by the recorder; here the count lives in
//! [`AdapterSession`], which owns the recorder (use one session per conversation). A message object that answers `_getType()` /
//! `getType()` (a LangChain class instance) has no JSON form, so the role is read from `role` / `type` only.
use crate::arg_provenance::{encode_provenance_header, ProvenanceRecorder, PROV_HEADER};
use crate::intent_v2::js_value_string;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Largest bundle carried as a header (base64url characters); a larger one goes in the request body as `pca_provenance`.
pub const PROV_HEADER_MAX: usize = 8192;

/// JavaScript `String(v)` for a JSON value.
pub fn js_string(v: &Value) -> String {
    js_value_string(v)
}

/// JavaScript `JSON.stringify(v)` for a JSON value (compact, JavaScript property order).
pub fn js_json(v: &Value) -> String {
    crate::js_stringify(v)
}

/// `PCA-Provenance: <base64url strict canonical JSON>` for a bundle that fits [`PROV_HEADER_MAX`]; empty otherwise (send it in the
/// body). `None` is no bundle. A bundle outside the strict JSON profile is an error.
pub fn provenance_headers(bundle: Option<&Value>) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    if let Some(b) = bundle {
        let v = encode_provenance_header(b)?;
        if v.len() <= PROV_HEADER_MAX {
            out.insert(PROV_HEADER.to_string(), v);
        }
    }
    Ok(out)
}

/// A member of a JSON object under JavaScript `??` semantics: absent and null both read as `None`.
fn get<'a>(o: &'a Value, k: &str) -> Option<&'a Value> {
    match o {
        Value::Object(m) => m.get(k).filter(|v| !v.is_null()),
        _ => None,
    }
}

fn role_of(m: &Value) -> String {
    for k in ["role", "type"] {
        if let Some(Value::String(s)) = get(m, k) {
            return s.clone();
        }
    }
    String::new()
}

fn segment(origin: &str, source: String, content: Value) -> Value {
    json!({ "origin": origin, "source": source, "content": content })
}

/// The context segments a chat message adds, by the conversation's own roles: a user / human turn is the PRINCIPAL (its text, and
/// its other parts); a `tool_result` / `tool-result` / `function_call_output` part inside any turn, a `tool` / `function` turn and
/// a turn of an unknown role are UNTRUSTED tool output; assistant / system / developer turns add nothing. Each segment is
/// `{origin, source, content}`. A value that is neither an object nor an array adds nothing.
pub fn message_segments(m: &Value) -> Vec<Value> {
    if !matches!(m, Value::Object(_) | Value::Array(_)) {
        return Vec::new();
    }
    let role = role_of(m).to_lowercase();
    if ["assistant", "ai", "model", "system", "developer"].contains(&role.as_str()) {
        return Vec::new();
    }
    let content = get(m, "content");
    let tool_name = |x: &Value| -> String {
        let named = ["toolName", "name", "tool_use_id", "toolCallId", "tool_call_id"].iter().find_map(|k| get(x, k));
        named.or_else(|| get(m, "name")).or_else(|| get(m, "tool_call_id")).map(js_string).unwrap_or_else(|| "tool".to_string())
    };
    if role != "user" && role != "human" {
        return vec![segment("tool", tool_name(m), content.unwrap_or(m).clone())];
    }
    let parts = match content {
        Some(Value::Array(parts)) => parts,
        other => return vec![segment("principal", "user".into(), other.cloned().unwrap_or_else(|| json!("")))],
    };
    let mut out = Vec::new();
    let mut text: Vec<String> = Vec::new();
    for part in parts {
        let owned;
        let pt: &Value = match part {
            Value::Object(_) | Value::Array(_) => part,
            other => {
                owned = json!({ "type": "text", "text": js_string(other) });
                &owned
            }
        };
        let t = match get(pt, "type") {
            Some(Value::String(s)) => s.as_str(),
            _ => "",
        };
        if matches!(t, "tool_result" | "tool-result" | "function_call_output") {
            let c = get(pt, "content").or_else(|| get(pt, "result")).or_else(|| get(pt, "output")).unwrap_or(pt);
            out.push(segment("tool", tool_name(pt), c.clone()));
        } else if let Some(Value::String(s)) = get(pt, "text") {
            text.push(s.clone());
        } else {
            out.push(segment("principal", "user".into(), pt.clone()));
        }
    }
    if !text.is_empty() {
        out.insert(0, segment("principal", "user".into(), Value::String(text.join("\n"))));
    }
    out
}

/// One conversation's provenance recorder plus the count of messages already recorded from it (the reference's `seenMessages`).
pub struct AdapterSession {
    pub recorder: ProvenanceRecorder,
    seen: usize,
}

impl AdapterSession {
    pub fn new(recorder: ProvenanceRecorder) -> Self {
        AdapterSession { recorder, seen: 0 }
    }

    /// Record the principal's own message (TRUSTED).
    pub fn record_principal(&mut self, text: &str) -> Result<(), String> {
        self.recorder.principal(text).map(|_| ())
    }

    /// Record a tool result entering the model's context (UNTRUSTED).
    pub fn record_tool_result(&mut self, tool: &str, output: &Value) -> Result<(), String> {
        self.recorder.tool(tool, output).map(|_| ())
    }

    /// Record a conversation's new messages (call it with the whole list before each model turn: messages already recorded are
    /// skipped, a shorter list starts over). A value that is not a list records nothing.
    pub fn record_messages(&mut self, messages: &Value) -> Result<(), String> {
        let list = match messages {
            Value::Array(l) => l,
            _ => return Ok(()),
        };
        let start = if list.len() < self.seen { 0 } else { self.seen };
        for m in &list[start..] {
            for seg in message_segments(m) {
                let content = &seg["content"];
                if seg["origin"] == "principal" {
                    let text = match content {
                        Value::String(s) => s.clone(),
                        other => js_json(other),
                    };
                    self.recorder.principal(&text)?;
                } else {
                    self.recorder.tool(seg["source"].as_str().unwrap_or("tool"), content)?;
                }
            }
        }
        self.seen = list.len();
        Ok(())
    }

    /// Record what the principal asked for: a string is the principal's message; a message list (or `{"messages": [...]}`) goes
    /// through [`AdapterSession::record_messages`]; an object's `input` / `prompt` / `query` / `question` / `message` / `text`
    /// string (or message list) is the principal's message. Anything else records nothing (the gate then keeps the context at
    /// `agent`: fail closed).
    pub fn record_input(&mut self, input: &Value) -> Result<(), String> {
        match input {
            Value::String(s) => self.record_principal(s),
            Value::Array(_) => self.record_messages(input),
            Value::Object(o) => {
                if let Some(m) = o.get("messages").filter(|v| v.is_array()) {
                    self.record_messages(m)?;
                }
                for k in ["input", "prompt", "query", "question", "message", "text"] {
                    match o.get(k) {
                        Some(Value::String(s)) => self.record_principal(s)?,
                        Some(v) if v.is_array() => self.record_messages(v)?,
                        _ => {}
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// `withPrincipalInput`: wrap a framework entry point so its first argument, the principal's request, is recorded in `session` before
/// the call. The returned function has the same shape; a recording failure is returned as `Err` before `f` runs (fail closed).
pub fn with_principal_input<'a, R>(session: &'a std::sync::Mutex<AdapterSession>, f: impl Fn(&Value) -> R + 'a) -> impl Fn(&Value) -> Result<R, String> + 'a {
    move |input: &Value| {
        session.lock().map_err(|_| "the adapter session is poisoned".to_string())?.record_input(input)?;
        Ok(f(input))
    }
}

/// How a framework tool name maps onto a PCA `(verb, resource)`; `None` declines the call (an unmapped tool).
pub type ToolMapping<'a> = &'a dyn Fn(&Value) -> Option<(String, String)>;

/// `bridgeToolCall`: bridge a single framework-agnostic tool call `{name, arguments}` into a signed PCActn through a name to `(verb, resource)`
/// mapping. `Ok(None)` when the mapping declines the call (an unmapped tool); use it inside any framework's middleware to turn its tool-invocation event
/// into a proof-carrying action. The tool's result is not seen here: record it with [`AdapterSession::record_tool_result`]. The audience, the counter
/// and the clock are the agent's own ([`crate::agent::Agent`]).
pub fn bridge_tool_call(agent: &crate::agent::Agent, call: &Value, map: ToolMapping<'_>, suite: &crate::agent::Suite<'_>) -> Result<Option<crate::agent::Action>, String> {
    let Some((verb, resource)) = map(call) else { return Ok(None) };
    let args = call.get("arguments").filter(|a| !a.is_null());
    agent.act(&verb, &resource, args, serde_json::Map::new(), suite).map(Some)
}
