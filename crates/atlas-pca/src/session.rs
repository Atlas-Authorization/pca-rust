//! Multi-agent sessions (port of `session.ts`): a root agent and the sub-agents it delegates to share one signed goal; a
//! session groups them, so a principal sees the whole team under a goal and the console can be scoped to it. Composes the
//! facade's sub-agent delegation and the console projection.
use std::sync::Arc;

use serde_json::Value;

use crate::facade::{AgentHandle, SubAgentOptions};

/// The deepest delegation chain a session accepts.
pub const SESSION_MAX_DEPTH: usize = 32;

/// A team under one goal: the root agent first, then each added sub-agent in delegation order, and the shared goal commitment
/// (from the root grant; empty when the grant has no readable envelope).
#[derive(Clone)]
pub struct Session {
    pub members: Vec<Arc<AgentHandle>>,
    pub goal_commit: String,
}

impl Session {
    /// The root agent (`None` for a hand-built session without members).
    pub fn root(&self) -> Option<&Arc<AgentHandle>> {
        self.members.first()
    }
}

fn goal_commit_of(agent: &AgentHandle) -> String {
    let envelope = crate::authorize::read_envelope(&agent.grant);
    envelope.and_then(|e| e.get("goal_commit").and_then(Value::as_str).map(String::from)).unwrap_or_default()
}

/// Starts a session from a root agent.
pub fn start_session(root: Arc<AgentHandle>) -> Session {
    Session { goal_commit: goal_commit_of(&root), members: vec![root] }
}

/// Adds a sub-agent: one attenuated delegation hop under the session's current leaf. Returns the new session and the member;
/// `session` is left as it was. `Err` past [`SESSION_MAX_DEPTH`] hops, for a session without members, and when the delegation
/// is refused.
pub fn add_member(session: &Session, opts: SubAgentOptions) -> Result<(Session, Arc<AgentHandle>), String> {
    if session.members.len() > SESSION_MAX_DEPTH {
        return Err(format!("addMember: a session is limited to {SESSION_MAX_DEPTH} delegation hops"));
    }
    let parent = session.members.last().ok_or("addMember: the session has no members")?;
    let member = Arc::new(parent.sub_agent(opts)?);
    let mut members = session.members.clone();
    members.push(member.clone());
    Ok((Session { members, goal_commit: session.goal_commit.clone() }, member))
}

/// The holder ids (base64url public keys) of every agent of the session.
pub fn session_agents(session: &Session) -> Vec<String> {
    session.members.iter().map(|m| m.holder.public.clone()).collect()
}

/// A console view scoped to this session's agents. `Err` for a null event (the reference cannot read its agent).
pub fn session_console(session: &Session, events: &[Value]) -> Result<Value, String> {
    if events.iter().any(Value::is_null) {
        return Err("sessionConsole: an event is null".into());
    }
    let ids = session_agents(session);
    let mine: Vec<Value> = events.iter().filter(|e| e.get("agent").and_then(Value::as_str).is_some_and(|a| ids.iter().any(|i| i == a))).cloned().collect();
    Ok(crate::console::build_console(&mine))
}

/// Every member shares the session's goal commitment (a well-formed team). An empty commitment is never shared: a root without
/// a readable envelope has none, and members that all lack one do not share a goal.
pub fn shares_goal(session: &Session) -> bool {
    !session.goal_commit.is_empty() && session.members.iter().all(|m| goal_commit_of(m) == session.goal_commit)
}

/// The depth of the delegation tree (0 = the root only; -1 for a hand-built session without members).
pub fn session_depth(session: &Session) -> i64 {
    session.members.len() as i64 - 1
}
