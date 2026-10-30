//! PROVENANCE BY DEFAULT: an agent cannot be steered by injected content into choosing who, where or how much.
//!
//! A MEDIATOR (the agent harness, a gateway, an MCP client: whatever sees the bytes enter the model's context and holds a key the
//! model cannot reach) appends one signed receipt per context segment to a per-session hash chain: the principal's own message
//! (`principal`), a tool result (`tool`), a retrieved document (`retrieval`), a fetched page (`web`), and finally the action the
//! model chose (`action`, bound to the exact operation digest). The verifier re-derives every label from that chain; nothing the
//! agent writes can lower one. A value is TRUSTED when the context that produced it was purely principal, when it occurs as a whole
//! token in a principal message the chain binds, or when the principal authorized the exact operation (a plan node). The CHOICE of
//! the action is trusted only when the context was purely principal or the principal committed to the step.
//!
//! An action is SENSITIVE unless its facts say it only reads (effects exactly `read`, traits within [`READ_SAFE_TRAITS`]); an
//! unknown action is sensitive. A sensitive action whose choice or any argument is not trusted is `escalate` (only a principal's
//! signed escalation answer admits it); a forged or malformed chain is `deny`. [`crate::authorize`] runs this gate by default as
//! check `provenance_flow`. Same wire and decisions as the TypeScript reference (`arg-provenance.ts`); the shared vectors
//! `arg-provenance-vectors.json` pin them.
//!
//! Every function here is pure and total (no I/O, no clock, no panic); malformed input fails closed.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use crate::agent::{sign_artifact, KeyPair, PqKeyPair, Suite};
use crate::intent_strict::{
    artifact_ref, artifact_suite_error, b32, bstr, closed_members_error, nonneg, pin_pq_ok, s, sint, verify_artifact_sig, SUITE_MEMBERS,
};
use crate::{canonicalize_strict, decode_b64u_strict, hash_canonical_strict, strict_parse, Operation};

/// Signature domain of a provenance receipt (trailing NUL included).
pub const PROV_RECEIPT_DOMAIN: &str = "atlas-pca/prov-receipt/v1\0";
/// Content-address domain of a receipt (`prev` links).
pub const PROV_RECEIPT_REF_DOMAIN: &str = "atlas-pca/prov-receipt-ref/v1";
/// Domain of the operation digest an `action` receipt binds.
pub const PROV_ACTION_DOMAIN: &str = "atlas-pca/prov-action/v1";
/// Request header carrying a bundle (base64url of its JSON). The body member is [`PROV_BODY_MEMBER`].
pub const PROV_HEADER: &str = "PCA-Provenance";
/// JSON body member carrying a bundle when the header is absent.
pub const PROV_BODY_MEMBER: &str = "pca_provenance";
/// Receipts one bundle may hold.
pub const MAX_PROV_RECEIPTS: usize = 256;
/// Largest principal message a bundle may carry (UTF-8 bytes).
pub const MAX_PROV_CONTENT_BYTES: usize = 65_536;
/// Leaves examined per parameter; a larger value is not examined and keeps the context label.
pub const MAX_PROV_LEAVES: usize = 4096;
const MAX_DEPTH: usize = 32;

/// Segment origins, in wire order.
pub const PROV_ORIGINS: [&str; 5] = ["principal", "tool", "retrieval", "web", "action"];
/// Floors a signed action definition may declare per parameter (`provenance_min`).
pub const PROV_FLOORS: [&str; 3] = ["first_party", "tool", "agent"];
/// Traits a read-only action may carry and still be non-sensitive. Any other trait makes the action sensitive.
pub const READ_SAFE_TRAITS: [&str; 3] = ["pca.financial_data_read", "pca.pii_access", "pca.regulated_data"];

/// The label lattice: `trusted < first_party < tool < web < agent` (declaration order is the rank).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProvLevel {
    Trusted,
    FirstParty,
    Tool,
    Web,
    Agent,
}

impl ProvLevel {
    /// The wire name (`trusted`, `first_party`, `tool`, `web`, `agent`).
    pub fn as_str(&self) -> &'static str {
        match self {
            ProvLevel::Trusted => "trusted",
            ProvLevel::FirstParty => "first_party",
            ProvLevel::Tool => "tool",
            ProvLevel::Web => "web",
            ProvLevel::Agent => "agent",
        }
    }

    /// The level named `s` (`None` for anything else).
    pub fn parse(s: &str) -> Option<ProvLevel> {
        Some(match s {
            "trusted" => ProvLevel::Trusted,
            "first_party" => ProvLevel::FirstParty,
            "tool" => ProvLevel::Tool,
            "web" => ProvLevel::Web,
            "agent" => ProvLevel::Agent,
            _ => return None,
        })
    }

    /// The level a segment of `origin` carries (`action` and unknown origins carry none).
    fn of_origin(origin: &str) -> Option<ProvLevel> {
        match origin {
            "principal" => Some(ProvLevel::Trusted),
            "tool" | "retrieval" => Some(ProvLevel::Tool),
            "web" => Some(ProvLevel::Web),
            _ => None,
        }
    }
}

/// The outcome of [`decide_arg_provenance`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgProvenanceDecision {
    /// `pass`: provenance admits; `escalate`: the principal must confirm; `deny`: forged or malformed provenance.
    pub outcome: &'static str,
    /// `malformed_config`, `malformed_operation`, `malformed_action`, `malformed_bundle`, `broken_chain`, `bad_signature`,
    /// `unbound_action`, `content_mismatch` (deny) or `untrusted_control`, `untrusted_args`, `untrusted_control_and_args` (escalate).
    pub code: Option<&'static str>,
    pub reason: Option<String>,
    pub sensitive: bool,
    /// True when a bundle verified under a pinned mediator.
    pub verified: bool,
    /// The label of the action choice.
    pub control: ProvLevel,
    /// The label of every top-level parameter (sorted by UTF-8 bytes).
    pub labels: BTreeMap<String, ProvLevel>,
    /// Sink parameters whose label is above their floor (UTF-8 order).
    pub tainted: Vec<String>,
    /// Where the untrusted content came from: `origin:source`, plus `unlabelled` without a verified chain (UTF-8 order).
    pub path: Vec<String>,
}

impl ArgProvenanceDecision {
    /// The decision as the reference's JSON object (`code` / `reason` only when present).
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("outcome".into(), json!(self.outcome));
        if let Some(c) = self.code {
            m.insert("code".into(), json!(c));
        }
        if let Some(r) = &self.reason {
            m.insert("reason".into(), json!(r));
        }
        m.insert("sensitive".into(), json!(self.sensitive));
        m.insert("verified".into(), json!(self.verified));
        m.insert("control".into(), json!(self.control.as_str()));
        m.insert("labels".into(), Value::Object(self.labels.iter().map(|(k, v)| (k.clone(), json!(v.as_str()))).collect()));
        m.insert("tainted".into(), json!(self.tainted));
        m.insert("path".into(), json!(self.path));
        Value::Object(m)
    }
}

/// The inputs of [`decide_arg_provenance`]. `bundle` `None` (or JSON null) is no bundle; `action` `None` is an unknown action
/// (sensitive); `mediators` are the pinned mediator keys (`{mediator, kid, pk, pq_pk?}`); `observed` is untrusted content the
/// SERVER itself saw reach the agent (`{origin: tool | retrieval | web, source}`, raise only).
#[derive(Debug, Clone, Copy)]
pub struct ArgProvenanceInput<'a> {
    pub bundle: Option<&'a Value>,
    /// `{verb, resource, params}`.
    pub operation: &'a Value,
    pub mediators: &'a [Value],
    pub action: Option<&'a Value>,
    /// The principal authorized this exact operation (a node of an executable, principal-authorized plan).
    pub principal_plan: bool,
    /// The principal committed to this step (an admitted workflow step): the CHOICE is trusted, the values are not.
    pub principal_control: bool,
    pub observed: &'a [Value],
}

// ---------------------------------------------------------------------------------------------------------------- wire

/// The digest an `action` receipt binds: `hashCanonical({d, verb, resource, params})` of the operation `{verb, resource, params}`.
/// `None` when a member is missing or the value is outside the strict profile.
pub fn prov_action_digest(op: &Value) -> Option<String> {
    hash_canonical_strict(&json!({"d": PROV_ACTION_DOMAIN, "verb": op.get("verb")?, "resource": op.get("resource")?, "params": op.get("params")?}))
}

/// Content address of a receipt (signature included): `hashCanonical({d, r})`.
pub fn prov_receipt_ref(r: &Value) -> Option<String> {
    artifact_ref(PROV_RECEIPT_REF_DOMAIN, "r", r)
}

/// Is `k` a well-formed mediator pin `{mediator (1..256 bytes), kid (1..64), pk (canonical b64u 32 bytes), pq_pk?}`?
pub fn is_prov_mediator_pin(k: &Value) -> bool {
    match k.as_object() {
        Some(o) => {
            closed_members_error(o, &["mediator", "kid", "pk"], &["pq_pk"], "pin").is_none()
                && bstr(o.get("mediator"), 256)
                && bstr(o.get("kid"), 64)
                && b32(o.get("pk"))
                && pin_pq_ok(o.get("pq_pk"))
        }
        None => false,
    }
}

/// Wire validation of one receipt (closed members, then the shared artifact suite check). `None` = well-formed.
pub fn prov_receipt_wire_error(r: &Value) -> Option<String> {
    let Some(o) = r.as_object() else { return Some("a receipt must be an object".into()) };
    let req = ["v", "kind", "mediator", "kid", "session", "seq", "prev", "origin", "source", "content_digest", "issued_at", "sig"];
    if let Some(e) = closed_members_error(o, &req, &SUITE_MEMBERS, "receipt") {
        return Some(e);
    }
    if sint(o.get("v")) != Some(1) || s(o.get("kind")) != Some("pca-prov") {
        return Some("a receipt must be {v: 1, kind: \"pca-prov\"}".into());
    }
    if !bstr(o.get("mediator"), 256) {
        return Some("'mediator' must be a non-empty string (<= 256 bytes)".into());
    }
    if !bstr(o.get("kid"), 64) {
        return Some("'kid' must be a non-empty string (<= 64 bytes)".into());
    }
    if !b32(o.get("session")) {
        return Some("'session' must be canonical base64url (32 bytes)".into());
    }
    if nonneg(o.get("seq")).is_none() {
        return Some("'seq' must be a non-negative safe integer".into());
    }
    if !(o.get("prev") == Some(&Value::Null) || b32(o.get("prev"))) {
        return Some("'prev' must be null or canonical base64url (32 bytes)".into());
    }
    if !s(o.get("origin")).is_some_and(|x| PROV_ORIGINS.contains(&x)) {
        return Some(format!("'origin' must be one of {}", PROV_ORIGINS.join(", ")));
    }
    if !bstr(o.get("source"), 256) {
        return Some("'source' must be a non-empty string (<= 256 bytes)".into());
    }
    if !b32(o.get("content_digest")) {
        return Some("'content_digest' must be canonical base64url (32 bytes)".into());
    }
    if nonneg(o.get("issued_at")).is_none() {
        return Some("'issued_at' must be a non-negative safe integer".into());
    }
    if !o.get("sig").is_some_and(Value::is_string) {
        return Some("'sig' must be a string".into());
    }
    artifact_suite_error(o)
}

fn string_list_ok(v: Option<&Value>) -> bool {
    match v {
        None => true,
        Some(Value::Array(a)) => a.len() <= 64 && a.iter().all(|x| bstr(Some(x), 128)),
        Some(_) => false,
    }
}

/// Validate action facts `{effects?: string[], traits?: string[], params?: {name: first_party | tool | agent}}`. `None` = well-formed.
pub fn prov_action_info_error(a: &Value) -> Option<String> {
    let Some(o) = a.as_object() else { return Some("action info must be an object".into()) };
    if let Some(e) = closed_members_error(o, &[], &["effects", "traits", "params"], "action info") {
        return Some(e);
    }
    for k in ["effects", "traits"] {
        if !string_list_ok(o.get(k)) {
            return Some(format!("action info '{k}' must be a list of strings"));
        }
    }
    if let Some(p) = o.get("params") {
        let Some(p) = p.as_object() else { return Some("action info 'params' must be an object".into()) };
        for (k, v) in p {
            if !bstr(Some(&Value::String(k.clone())), 128) || !s(Some(v)).is_some_and(|f| PROV_FLOORS.contains(&f)) {
                return Some(format!("action info param '{k}' must map to first_party | tool | agent"));
            }
        }
    }
    None
}

/// Is an action with these facts non-sensitive (it only reads)? Unknown facts (`None`) are sensitive.
pub fn is_read_only_action(a: Option<&Value>) -> bool {
    let Some(o) = a.and_then(Value::as_object) else { return false };
    let effects = match o.get("effects").and_then(Value::as_array) {
        Some(e) if !e.is_empty() => e,
        _ => return false,
    };
    if !effects.iter().all(|e| e.as_str() == Some("read")) {
        return false;
    }
    match o.get("traits") {
        None | Some(Value::Null) => true,
        Some(Value::Array(t)) => t.iter().all(|x| x.as_str().is_some_and(|x| READ_SAFE_TRAITS.contains(&x))),
        Some(_) => false,
    }
}

/// The grant envelope member `provenance` (`{mode?: "enforce" | "insecure_off", mediators?: Pin[] (<= 16)}`). `None` = well-formed.
pub fn prov_envelope_error(p: &Value) -> Option<String> {
    let Some(o) = p.as_object() else { return Some("provenance must be an object".into()) };
    if let Some(e) = closed_members_error(o, &[], &["mode", "mediators"], "provenance") {
        return Some(e);
    }
    if o.get("mode").is_some_and(|m| m.as_str() != Some("enforce") && m.as_str() != Some("insecure_off")) {
        return Some("provenance.mode must be 'enforce' or 'insecure_off'".into());
    }
    if let Some(m) = o.get("mediators") {
        if !m.as_array().is_some_and(|a| a.len() <= 16 && a.iter().all(is_prov_mediator_pin)) {
            return Some("provenance.mediators must be at most 16 {mediator, kid, pk, pq_pk?}".into());
        }
    }
    None
}

// ---------------------------------------------------------------------------------------------------------------- tokens

/// Word bytes for token boundaries: ASCII letters, digits, `_`, and every byte >= 0x80 (fail closed: fewer matches).
fn is_word(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c >= 0x80
}

/// Does `needle` occur in `text` as a whole token? An occurrence counts when the character before it is not a word character
/// (or the needle starts with a non-word character), and likewise after it. Exact, case-sensitive, no normalization; an empty
/// needle never occurs.
///
/// The reference scans UTF-16 code units; this scans UTF-8 bytes, with the same result: a valid UTF-8 needle can only match at
/// character boundaries (so the occurrences are the same), every occurrence is tried (overlapping ones included), and the unit
/// next to an occurrence is >= 0x80 exactly when the neighbouring UTF-8 byte is (both mean "a non-ASCII character").
pub fn occurs_as_token(text: &str, needle: &str) -> bool {
    let (t, n) = (text.as_bytes(), needle.as_bytes());
    if n.is_empty() {
        return false;
    }
    let (head, tail) = (is_word(n[0]), is_word(n[n.len() - 1]));
    let mut from = 0;
    while let Some(off) = text[from..].find(needle) {
        let i = from + off;
        let end = i + n.len();
        let ok_before = !head || i == 0 || !is_word(t[i - 1]);
        let ok_after = !tail || end == t.len() || !is_word(t[end]);
        if ok_before && ok_after {
            return true;
        }
        // the next occurrence starts at the next character (the reference's `indexOf(needle, i + 1)`)
        from = i + text[i..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// The text of every leaf of a value: strings as they are, other scalars in strict canonical form (`true`, `null`, `120`,
/// `1.5`), object keys included (JSON member order). `None` when deeper than 32, larger than [`MAX_PROV_LEAVES`] or not canonical.
pub fn prov_leaves(v: &Value) -> Option<Vec<String>> {
    fn walk(x: &Value, depth: usize, out: &mut Vec<String>) -> bool {
        if depth > MAX_DEPTH || out.len() > MAX_PROV_LEAVES {
            return false;
        }
        match x {
            Value::String(t) => out.push(t.clone()),
            Value::Array(a) => {
                for y in a {
                    if !walk(y, depth + 1, out) {
                        return false;
                    }
                }
            }
            Value::Object(m) => {
                for (k, y) in m {
                    out.push(k.clone());
                    if !walk(y, depth + 1, out) {
                        return false;
                    }
                }
            }
            scalar => match canonicalize_strict(scalar) {
                Ok(t) => out.push(t),
                Err(_) => return false,
            },
        }
        out.len() <= MAX_PROV_LEAVES
    }
    let mut out = Vec::new();
    walk(v, 0, &mut out).then_some(out)
}

// ---------------------------------------------------------------------------------------------------------------- decision

struct Chain {
    verified: bool,
    context: ProvLevel,
    path: Vec<String>,
    principal_texts: Vec<String>,
}

fn unverified() -> Chain {
    Chain { verified: false, context: ProvLevel::Agent, path: vec!["unlabelled".into()], principal_texts: Vec::new() }
}

type Refusal = (&'static str, String);

fn is_contents_key(k: &str) -> bool {
    let b = k.as_bytes();
    !b.is_empty() && b.len() <= 9 && b.iter().all(u8::is_ascii_digit) && (b[0] != b'0' || b.len() == 1)
}

/// Verify a bundle against the pins and the operation (step 1 of the decision).
fn verify_chain(bundle: Option<&Value>, op: &Value, pins: &[Value]) -> Result<Chain, Refusal> {
    let bundle = match bundle {
        None | Some(Value::Null) => return Ok(unverified()),
        Some(b) => b,
    };
    let bad = |code: &'static str, why: String| Err((code, why));
    let Some(bo) = bundle.as_object() else { return bad("malformed_bundle", "the bundle must be an object".into()) };
    if let Some(e) = closed_members_error(bo, &["v", "kind", "receipts"], &["contents"], "bundle") {
        return bad("malformed_bundle", e);
    }
    if sint(bo.get("v")) != Some(1) || s(bo.get("kind")) != Some("pca-provenance") {
        return bad("malformed_bundle", "the bundle must be {v: 1, kind: \"pca-provenance\"}".into());
    }
    let rs = match bo.get("receipts").and_then(Value::as_array) {
        Some(rs) if !rs.is_empty() && rs.len() <= MAX_PROV_RECEIPTS => rs,
        _ => return bad("malformed_bundle", format!("the bundle must hold 1..{MAX_PROV_RECEIPTS} receipts")),
    };
    for (i, r) in rs.iter().enumerate() {
        if let Some(e) = prov_receipt_wire_error(r) {
            return bad("malformed_bundle", format!("receipt {i}: {e}"));
        }
    }
    let empty = Map::new();
    let contents = match bo.get("contents") {
        None => &empty,
        Some(Value::Object(c)) => c,
        Some(_) => return bad("malformed_bundle", "'contents' must be an object".into()),
    };
    let first = &rs[0];
    for (i, r) in rs.iter().enumerate() {
        if sint(r.get("seq")) != Some(i as i64) {
            return bad("broken_chain", format!("receipt {i} has seq {}", r["seq"]));
        }
        if ["session", "mediator", "kid"].iter().any(|k| r.get(*k) != first.get(*k)) {
            return bad("broken_chain", format!("receipt {i} belongs to another session or mediator"));
        }
        let linked = if i == 0 { r.get("prev") == Some(&Value::Null) } else { s(r.get("prev")).is_some() && s(r.get("prev")).map(str::to_string) == prov_receipt_ref(&rs[i - 1]) };
        if !linked {
            return bad("broken_chain", format!("receipt {i} does not link to its predecessor"));
        }
        if i > 0 && sint(r.get("issued_at")) < sint(rs[i - 1].get("issued_at")) {
            return bad("broken_chain", format!("receipt {i} is older than its predecessor"));
        }
    }
    let last = &rs[rs.len() - 1];
    let want = prov_action_digest(op);
    if s(last.get("origin")) != Some("action") || s(last.get("source")) != s(op.get("verb")) || want.is_none() || s(last.get("content_digest")) != want.as_deref() {
        return bad("unbound_action", "the last receipt is not the action receipt of this operation".into());
    }
    for (k, text) in contents {
        let named = if is_contents_key(k) { k.parse::<usize>().ok().and_then(|n| rs.get(n)) } else { None };
        let r = match named {
            Some(r) if s(r.get("origin")) == Some("principal") => r,
            _ => return bad("malformed_bundle", format!("contents '{k}' does not name a principal receipt")),
        };
        match text {
            Value::String(t) if t.len() <= MAX_PROV_CONTENT_BYTES => {}
            _ => return bad("malformed_bundle", format!("contents '{k}' must be a string of at most {MAX_PROV_CONTENT_BYTES} bytes")),
        }
        match hash_canonical_strict(text) {
            None => return bad("content_mismatch", format!("contents '{k}' is not canonical text")),
            Some(d) if s(r.get("content_digest")) != Some(d.as_str()) => return bad("content_mismatch", format!("contents '{k}' does not hash to its receipt")),
            Some(_) => {}
        }
    }
    let pin = pins.iter().find(|p| p.get("mediator") == first.get("mediator") && p.get("kid") == first.get("kid"));
    // a chain from a mediator this verifier does not pin vouches for nothing: every value stays at the top (escalate, never allow)
    let Some(pin) = pin else { return Ok(unverified()) };
    let pk = s(pin.get("pk")).unwrap_or("");
    for (i, r) in rs.iter().enumerate() {
        let ok = r.as_object().is_some_and(|ro| verify_artifact_sig(PROV_RECEIPT_DOMAIN, ro, pk, pin.get("pq_pk")));
        if !ok {
            return bad("bad_signature", format!("receipt {i} does not verify under the pinned mediator key"));
        }
    }
    let before: Vec<&Value> = rs[..rs.len() - 1].iter().filter(|r| s(r.get("origin")) != Some("action")).collect();
    let mut context = if before.is_empty() { ProvLevel::Agent } else { ProvLevel::Trusted };
    let mut path = BTreeSet::new();
    for r in &before {
        let origin = s(r.get("origin")).unwrap_or("");
        if let Some(lv) = ProvLevel::of_origin(origin) {
            context = context.max(lv);
        }
        if origin != "principal" {
            path.insert(format!("{origin}:{}", s(r.get("source")).unwrap_or("")));
        }
    }
    if before.is_empty() {
        path.insert("unlabelled".into());
    }
    let principal_texts = contents.values().filter_map(|t| t.as_str().map(str::to_string)).collect();
    Ok(Chain { verified: true, context, path: path.into_iter().collect(), principal_texts })
}

fn operation_ok(op: &Value) -> bool {
    bstr(op.get("verb"), 256) && op.get("resource").is_some_and(Value::is_string) && op.get("params").is_some_and(Value::is_object)
}

fn observation_ok(o: &Value) -> bool {
    matches!(s(o.get("origin")), Some("tool" | "retrieval" | "web")) && bstr(o.get("source"), 256)
}

/// The provenance decision for one operation. Steps, first failure wins:
///   0. pins, operation, action facts and observations well-formed, else `deny` (malformed_config / malformed_operation /
///      malformed_action);
///   1. the bundle (when present): wire, chain (contiguous seq, prev links, one session and mediator, non-decreasing issued_at),
///      the last receipt is the `action` receipt of this operation, every principal content hashes to its receipt, every
///      signature verifies under the pinned (mediator, kid). A failure is `deny`. A chain whose mediator is not pinned is ignored
///      (no trust). context = the join of the non-action segments before the action (`agent` when none or unverified);
///   2. server observations join into context (raise only);
///   3. control = `trusted` with `principal_plan` or `principal_control`, else context;
///   4. each top-level parameter: `trusted` with `principal_plan`; else the join over its leaves, where a leaf is `trusted` when
///      the context is trusted or it occurs as a token in a verified principal content, else context; no leaves is `trusted`; a
///      parameter too large to examine is context;
///   5. floors: the facts' `params[p]`, else `first_party` for a sensitive action and `agent` otherwise; a parameter whose label
///      ranks above its floor is tainted;
///   6. a sensitive action whose control is not `trusted`, or any tainted parameter, is `escalate`; otherwise `pass`.
pub fn decide_arg_provenance(input: &ArgProvenanceInput<'_>) -> ArgProvenanceDecision {
    let mut d = ArgProvenanceDecision {
        outcome: "deny",
        code: None,
        reason: None,
        sensitive: true,
        verified: false,
        control: ProvLevel::Agent,
        labels: BTreeMap::new(),
        tainted: Vec::new(),
        path: Vec::new(),
    };
    let deny = |mut d: ArgProvenanceDecision, code: &'static str, why: String| {
        d.outcome = "deny";
        d.code = Some(code);
        d.reason = Some(why);
        d
    };
    if !input.mediators.iter().all(is_prov_mediator_pin) {
        return deny(d, "malformed_config", "mediator pins must be a list of {mediator, kid, pk, pq_pk?}".into());
    }
    let op = input.operation;
    if !operation_ok(op) {
        return deny(d, "malformed_operation", "the operation needs a verb, a resource and a params object".into());
    }
    if let Some(e) = input.action.and_then(prov_action_info_error) {
        return deny(d, "malformed_action", e);
    }
    if !input.observed.iter().all(observation_ok) {
        return deny(d, "malformed_config", "observations must be a list of {origin, source}".into());
    }
    let sensitive = !is_read_only_action(input.action);
    d.sensitive = sensitive;
    let ch = match verify_chain(input.bundle, op, input.mediators) {
        Ok(c) => c,
        Err((code, why)) => return deny(d, code, why),
    };
    d.verified = ch.verified;
    let mut context = ch.context;
    let mut path: BTreeSet<String> = ch.path.into_iter().collect();
    for o in input.observed {
        let origin = s(o.get("origin")).unwrap_or("");
        if let Some(lv) = ProvLevel::of_origin(origin) {
            context = context.max(lv);
        }
        path.insert(format!("{origin}:{}", s(o.get("source")).unwrap_or("")));
    }
    d.path = path.into_iter().collect();
    let plan = input.principal_plan;
    d.control = if plan || input.principal_control { ProvLevel::Trusted } else { context };
    let empty = Map::new();
    let params = op.get("params").and_then(Value::as_object).unwrap_or(&empty); // an object: checked by operation_ok
    for (p, v) in params {
        let label = if plan {
            ProvLevel::Trusted
        } else {
            match prov_leaves(v) {
                None => context,
                Some(leaves) => leaves.iter().fold(ProvLevel::Trusted, |l, leaf| {
                    // a leaf the principal typed verbatim is the principal's choice whatever else the context held
                    let typed = context == ProvLevel::Trusted || ch.principal_texts.iter().any(|t| occurs_as_token(t, leaf));
                    l.max(if typed { ProvLevel::Trusted } else { context })
                }),
            }
        };
        d.labels.insert(p.clone(), label);
    }
    let floors = input.action.and_then(|a| a.get("params")).and_then(Value::as_object);
    for (p, label) in &d.labels {
        let floor = match floors.and_then(|f| f.get(p)).and_then(Value::as_str).and_then(ProvLevel::parse) {
            Some(f) => f,
            None if sensitive => ProvLevel::FirstParty,
            None => ProvLevel::Agent,
        };
        if *label > floor {
            d.tainted.push(p.clone());
        }
    }
    // no segment origin maps to first_party, so a control label is trusted or untrusted
    let bad_control = sensitive && d.control != ProvLevel::Trusted;
    if !bad_control && d.tainted.is_empty() {
        d.outcome = "pass";
        return d;
    }
    let mut parts = Vec::new();
    let verb = op["verb"].as_str().unwrap_or("");
    if bad_control {
        parts.push(format!("the choice of {verb} derives from untrusted content"));
    }
    if !d.tainted.is_empty() {
        parts.push(format!("{} {} from untrusted content", d.tainted.join(", "), if d.tainted.len() == 1 { "derives" } else { "derive" }));
    }
    let wher = if d.path.is_empty() { String::new() } else { format!(" [{}]", d.path.join(", ")) };
    d.outcome = "escalate";
    d.code = Some(match (bad_control, d.tainted.is_empty()) {
        (true, false) => "untrusted_control_and_args",
        (true, true) => "untrusted_control",
        _ => "untrusted_args",
    });
    d.reason = Some(format!("{}{wher}: the principal must confirm (prompt-injection path)", parts.join("; ")));
    d
}

/// The bundle a request carries: the `PCA-Provenance` header (strict unpadded base64url of the JSON, strict-parsed) when present
/// and non-empty, else the JSON body's `pca_provenance` member (a body that is not strict JSON carries none). `Err` = a header
/// that does not decode or parse (the gate then fails closed).
pub fn read_provenance_bundle(header: Option<&str>, body: Option<&[u8]>) -> Result<Option<Value>, String> {
    if let Some(h) = header.filter(|h| !h.is_empty()) {
        let raw = decode_b64u_strict(h, None).ok_or("the PCA-Provenance header is not base64url")?;
        let text = std::str::from_utf8(&raw).map_err(|_| "the PCA-Provenance header is not UTF-8")?;
        return strict_parse(text).map(Some);
    }
    let Some(text) = body.and_then(|b| std::str::from_utf8(b).ok()) else { return Ok(None) };
    Ok(strict_parse(text).ok().and_then(|v| v.get(PROV_BODY_MEMBER).cloned()))
}

// ---------------------------------------------------------------------------------------------------------------- mediator side

/// The mediator side: one recorder per agent session. It must run where the bytes enter the model's context (the harness that
/// builds the prompt, a gateway, an MCP client), with a key the model cannot reach. Receipts are byte-identical to the TypeScript
/// `createProvenanceRecorder` for the same key, session, clock and inputs (Ed25519 is deterministic).
pub struct ProvenanceRecorder {
    mediator: String,
    kid: String,
    key: KeyPair,
    alg: Option<String>,
    pq: Option<PqKeyPair>,
    session: String,
    now: Box<dyn Fn() -> i64 + Send + Sync>,
    chain: Vec<Value>,
    contents: Map<String, Value>,
}

impl std::fmt::Debug for ProvenanceRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProvenanceRecorder {{ mediator: {}, kid: {}, session: {}, receipts: {} }}", self.mediator, self.kid, self.session, self.chain.len())
    }
}

fn system_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// A source name clipped to at most 256 UTF-8 bytes by halving its UTF-16 length (never empty: `-`), as the reference does. A cut
/// inside a surrogate pair leaves a lone surrogate, which the reference's strict canonicalizer refuses: so is it here (an error).
fn clip(src: &str) -> Result<String, String> {
    if src.len() <= 256 {
        return Ok(if src.is_empty() { "-".into() } else { src.to_string() });
    }
    let units: Vec<u16> = src.encode_utf16().collect();
    let half = String::from_utf16(&units[..(units.len() / 2).max(1)]).map_err(|_| "provenance: clipping the source leaves a lone surrogate in string")?;
    clip(&half)
}

/// The text a non-principal segment is recorded as: a string as is, anything else as its JSON text.
fn text_of(v: &Value) -> String {
    match v {
        Value::String(t) => t.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

impl ProvenanceRecorder {
    /// A recorder for `mediator` (1..256 bytes) and `kid` (1..64 bytes). `secret_key`: the mediator's Ed25519 seed (generated when
    /// `None`; then pin [`ProvenanceRecorder::pin`]). The session id is random; the clock is the system clock.
    pub fn new(mediator: &str, kid: &str, secret_key: Option<[u8; 32]>) -> Result<ProvenanceRecorder, String> {
        if !bstr(Some(&json!(mediator)), 256) || !bstr(Some(&json!(kid)), 64) {
            return Err("ProvenanceRecorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required".into());
        }
        let key = match secret_key {
            Some(seed) => KeyPair::from_seed(&seed),
            None => KeyPair::generate()?,
        };
        let mut sid = [0u8; 32];
        getrandom::getrandom(&mut sid).map_err(|e| e.to_string())?;
        let session = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sid);
        Ok(ProvenanceRecorder { mediator: mediator.into(), kid: kid.into(), key, alg: None, pq: None, session, now: Box::new(system_now), chain: Vec::new(), contents: Map::new() })
    }

    /// A fixed session id (canonical base64url of 32 bytes); only before the first receipt.
    pub fn with_session(mut self, session: &str) -> Result<ProvenanceRecorder, String> {
        if !b32(Some(&json!(session))) || !self.chain.is_empty() {
            return Err("ProvenanceRecorder: session must be canonical base64url of 32 bytes, set before the first receipt".into());
        }
        self.session = session.into();
        Ok(self)
    }

    /// The clock (epoch milliseconds).
    pub fn with_clock(mut self, now: impl Fn() -> i64 + Send + Sync + 'static) -> ProvenanceRecorder {
        self.now = Box::new(now);
        self
    }

    /// Sign receipts under a post-quantum or hybrid artifact suite (`alg`, e.g. `hybrid-ed25519-ml-dsa-65`, with its key pair).
    /// The pin then carries the key pair's public key as `pq_pk`.
    pub fn with_suite(mut self, alg: &str, pq: PqKeyPair) -> Result<ProvenanceRecorder, String> {
        // fail at configuration, not at the first receipt
        sign_artifact(PROV_RECEIPT_DOMAIN, &json!({}), &self.key, &Suite { alg: Some(alg), pq: Some(&pq) })?;
        self.alg = Some(alg.into());
        self.pq = Some(pq);
        Ok(self)
    }

    /// The session id (b64u 32 bytes).
    pub fn session(&self) -> &str {
        &self.session
    }

    /// The pin a verifier (or the principal's grant envelope) must carry for this recorder: `{mediator, kid, pk, pq_pk?}`.
    pub fn pin(&self) -> Value {
        let mut p = json!({"mediator": self.mediator, "kid": self.kid, "pk": self.key.public});
        if let (Some(alg), Some(pq)) = (&self.alg, &self.pq) {
            if alg != "ed25519" {
                p["pq_pk"] = json!(pq.public);
            }
        }
        p
    }

    /// Every receipt so far.
    pub fn receipts(&self) -> &[Value] {
        &self.chain
    }

    fn append(&mut self, origin: &str, source: &str, digest: String) -> Result<Value, String> {
        let source = clip(source)?;
        let prev = self.chain.last();
        let issued = prev.and_then(|r| sint(r.get("issued_at"))).unwrap_or(0).max((self.now)());
        let prev_ref = match prev {
            Some(r) => json!(prov_receipt_ref(r).ok_or("provenance: a previous receipt is not canonical")?),
            None => Value::Null,
        };
        let body = json!({"v": 1, "kind": "pca-prov", "mediator": self.mediator, "kid": self.kid, "session": self.session, "seq": self.chain.len(),
            "prev": prev_ref, "origin": origin, "source": source, "content_digest": digest, "issued_at": issued});
        let r = sign_artifact(PROV_RECEIPT_DOMAIN, &body, &self.key, &Suite { alg: self.alg.as_deref(), pq: self.pq.as_ref() })?;
        self.chain.push(r.clone());
        Ok(r)
    }

    fn segment(&mut self, origin: &str, source: &str, text: String) -> Result<Value, String> {
        let digest = hash_canonical_strict(&Value::String(text.clone())).ok_or("provenance: the content is not canonical text")?;
        let r = self.append(origin, source, digest)?;
        if origin == "principal" && text.len() <= MAX_PROV_CONTENT_BYTES {
            self.contents.insert(r["seq"].to_string(), Value::String(text));
        }
        Ok(r)
    }

    /// The principal's own message (TRUSTED; its text rides in the bundle so its values count as typed by the principal).
    pub fn principal(&mut self, text: &str) -> Result<Value, String> {
        self.segment("principal", "user", text.to_string())
    }

    /// A tool result (UNTRUSTED). Non-string output is recorded as its JSON text.
    pub fn tool(&mut self, name: &str, output: &Value) -> Result<Value, String> {
        self.segment("tool", name, text_of(output))
    }

    /// A retrieved document (UNTRUSTED).
    pub fn retrieval(&mut self, source: &str, content: &Value) -> Result<Value, String> {
        self.segment("retrieval", source, text_of(content))
    }

    /// A fetched web page or HTTP response (UNTRUSTED).
    pub fn web(&mut self, url: &str, content: &Value) -> Result<Value, String> {
        self.segment("web", url, text_of(content))
    }

    /// Record the chosen action and return the bundle to present with it (header `PCA-Provenance`, body `pca_provenance`, or
    /// `AuthorizeInput::provenance`).
    pub fn for_action(&mut self, op: &Operation) -> Result<Value, String> {
        if self.chain.len() >= MAX_PROV_RECEIPTS {
            return Err(format!("provenance: the session holds {MAX_PROV_RECEIPTS} receipts; start a new session with the principal's message"));
        }
        let digest = prov_action_digest(&json!({"verb": op.verb, "resource": op.resource, "params": op.params})).ok_or("provenance: the operation is outside the strict JSON profile")?;
        self.append("action", &op.verb, digest)?;
        let mut b = json!({"v": 1, "kind": "pca-provenance", "receipts": self.chain});
        if !self.contents.is_empty() {
            b["contents"] = Value::Object(self.contents.clone());
        }
        Ok(b)
    }
}

/// The bundle for an operation that came straight from the principal (the application's own UI acting on the user's explicit
/// input, no model in between): one principal segment holding the operation, then the action. Under a pinned recorder key the
/// operation's choice and values are trusted.
pub fn principal_direct_provenance(recorder: &mut ProvenanceRecorder, op: &Operation) -> Result<Value, String> {
    recorder.principal(&canonicalize_strict(&json!({"verb": op.verb, "resource": op.resource, "params": op.params}))?)?;
    recorder.for_action(op)
}

/// The header value for a bundle: base64url (no padding) of its strict-canonical JSON.
pub fn encode_provenance_header(bundle: &Value) -> Result<String, String> {
    Ok(base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, canonicalize_strict(bundle)?.as_bytes()))
}
