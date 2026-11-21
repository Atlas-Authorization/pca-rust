//! Agent-native authority primitives (TypeScript `agent-native.ts`): uncertainty attestation (caution claims), rationale binding
//! (commit / reveal / audit), the semantic-firewall builders (`tool_schema` and `predicates` caveats, the agent-native caveat
//! evaluator), capability introspection (what an attenuated chain permits) and the authority lease.
//!
//! Pure and deterministic: no clocks (callers pass `now`), no randomness except the default rationale salt. The verification and
//! evaluation functions are total and fail closed (never panic on hostile input); only the authoring helpers ([`bind_rationale`],
//! [`tool_schema_caveat`], [`predicates_caveat`], [`grant_lease`]) refuse invalid input, so a bad artefact is never minted. Values
//! are `serde_json::Value` (the decoded JSON of the reference): a number is "finite" exactly when `Number.isFinite` says so on the
//! JSON number, and a result that is an object in the reference is a `Value` here. `sign_caution`, `sign_heartbeat`,
//! `validate_arg_schema` and `evaluate_tool_schema` of the same family live in `signers_more` and `authorize`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::panic::{catch_unwind, AssertUnwindSafe};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Map, Value};

use crate::authorize::read_envelope;
pub use crate::authorize::{evaluate_tool_schema, validate_arg_schema};
pub use crate::authorize::{
    ABSOLUTE_MAX_ARRAY_ITEMS, ABSOLUTE_MAX_STRING_LEN, DEFAULT_MAX_ARRAY_ITEMS,
    DEFAULT_MAX_STRING_LEN, MAX_ENUM_VALUES, MAX_OBJECT_PROPS, MAX_SCHEMA_DEPTH, MAX_SCHEMA_NODES,
    MAX_VALUE_NODES,
};
use crate::predicates::{predicate_matches, Ctx};
use crate::safe_regex::with_regex_budget;
use crate::{canonicalize, canonicalize_strict, hash_canonical_strict};

/// Canonical caveat type names (envelope.ts / predicates.ts) plus the two this module adds.
pub const CAVEAT_ENVELOPE: &str = "envelope";
pub const CAVEAT_EXPIRES: &str = "expires";
pub const CAVEAT_NOT_BEFORE: &str = "not_before";
pub const CAVEAT_RATE: &str = "rate";
pub const CAVEAT_MAX_BLAST_RADIUS: &str = "max_blast_radius";
pub const CAVEAT_REVERSIBILITY_MAX: &str = "reversibility_max";
pub const CAVEAT_DELEGATION_DEPTH: &str = "delegation_depth";
/// Delegated verb/resource narrowing, `{allow: Predicate[]}`.
pub const CAVEAT_PREDICATES: &str = "predicates";
/// Tool-call authority bound to an exact tool + signature + (nested) argument schema.
pub const CAVEAT_TOOL_SCHEMA: &str = "tool_schema";
/// Per-action spend ceiling in US dollars, `{type: "max_spend", usd}`.
pub const CAVEAT_MAX_SPEND: &str = "max_spend";

/// Max length of the optional machine-readable caution reason.
pub const MAX_CAUTION_REASON_LEN: usize = 64;
/// Minimum decoded salt length (bytes).
pub const MIN_SALT_BYTES: usize = 16;
/// Minimum number of distinct byte values in a salt.
pub const MIN_SALT_DISTINCT_BYTES: usize = 8;
/// Max rationale length (UTF-16 units).
pub const MAX_RATIONALE_LEN: usize = 8192;
/// Max tolerated skew between a heartbeat's `at` (or the clock vs the last renewal) and server `now`.
pub const HEARTBEAT_SKEW_MS: f64 = 30_000.0;
/// Longest lease ttl accepted (7 days).
pub const MAX_LEASE_TTL_MS: f64 = 604_800_000.0;

const CAUTION_DOMAIN: &str = "atlas-pca/caution/v1";
const RATIONALE_DOMAIN: &str = "atlas-pca/rationale/v1";
const HEARTBEAT_DOMAIN: &str = "atlas-pca/lease-hb/v2";
const CAUTION_KEYS: [&str; 5] = ["action_digest", "caution", "reason", "holder", "sig"];
const HB_KEYS: [&str; 6] = ["cap_id", "seq", "at", "holder", "lease_issued_at", "sig"];
const REV: [&str; 3] = ["reversible", "rate_limited", "irreversible"];

// ---- helpers -------------------------------------------------------------------------------------------------------------

fn fin(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64().filter(|x| x.is_finite()),
        _ => None,
    }
}

fn ne_str(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn clamp01(x: f64) -> f64 {
    x.max(0.0).min(1.0)
}

fn jslen(s: &str) -> usize {
    s.encode_utf16().count()
}

/// A JSON number for a finite double (an integral one as an integer).
fn num(f: f64) -> Value {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.0e15 {
        json!(f as i64)
    } else {
        json!(f)
    }
}

/// `Number.isInteger(x) && !Object.is(x, -0)`.
fn is_int(v: Option<&Value>) -> bool {
    fin(v).is_some_and(|f| f.fract() == 0.0 && !(f == 0.0 && f.is_sign_negative()))
}

fn native_msg(domain: &str, body: &Value) -> Result<Vec<u8>, String> {
    Ok(canonicalize_strict(&json!({"d": domain, "b": body}))?.into_bytes())
}

fn without(o: &Map<String, Value>, key: &str) -> Value {
    let mut b = o.clone();
    b.remove(key);
    Value::Object(b)
}

// ---- 1. uncertainty attestation ---------------------------------------------------------------------------------------

fn caution_error(b: &Value) -> Option<&'static str> {
    let o = b.as_object()?;
    if ne_str(o.get("action_digest")).is_none() {
        return Some("action_digest required");
    }
    if ne_str(o.get("holder")).is_none() {
        return Some("holder required");
    }
    if !fin(o.get("caution")).is_some_and(|c| (0.0..=1.0).contains(&c)) {
        return Some("caution must be a finite number in [0,1]");
    }
    if let Some(r) = o.get("reason") {
        let ok = r.as_str().is_some_and(|s| {
            !s.is_empty()
                && jslen(s) <= MAX_CAUTION_REASON_LEN
                && s.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
        });
        if !ok {
            return Some("invalid reason");
        }
    }
    None
}

/// Verify a caution claim `{action_digest, caution, reason?, holder, sig}`: a plain object with no member outside those five,
/// caution a finite number in [0,1], a valid Ed25519 signature by `claim.holder` over the domain-separated body, bound to
/// `expected_action_digest` when given and signed by `expected_holder` when given (production callers MUST pass the PCActn's
/// holder, otherwise any key may attest). Total: `false` on anything malformed.
pub fn verify_caution(
    claim: &Value,
    expected_action_digest: Option<&str>,
    expected_holder: Option<&str>,
) -> bool {
    let Some(o) = claim.as_object() else {
        return false;
    };
    let Some(sig) = o.get("sig").and_then(Value::as_str) else {
        return false;
    };
    if !o.keys().all(|k| CAUTION_KEYS.contains(&k.as_str())) {
        return false;
    }
    if caution_error(claim).is_some() {
        return false;
    }
    if expected_action_digest
        .is_some_and(|d| o.get("action_digest").and_then(Value::as_str) != Some(d))
    {
        return false;
    }
    if expected_holder.is_some_and(|h| o.get("holder").and_then(Value::as_str) != Some(h)) {
        return false;
    }
    let holder = o.get("holder").and_then(Value::as_str).unwrap_or("");
    match native_msg(CAUTION_DOMAIN, &without(o, "sig")) {
        Ok(m) => crate::verify_b64u(holder, &m, sig),
        Err(_) => false,
    }
}

/// `effectiveRisk = max(agentDeclaredCaution, serverRisk)`: never below the server risk, so under-reporting gains nothing and a
/// higher declaration raises friction. An unusable declaration (`None`, NaN, infinite) is ignored; an unusable server risk fails
/// closed to 1. Both are clamped to [0, 1].
pub fn combine_caution(agent_declared_caution: Option<f64>, server_risk: f64) -> f64 {
    let s = if server_risk.is_finite() {
        clamp01(server_risk)
    } else {
        1.0
    };
    match agent_declared_caution {
        Some(d) if d.is_finite() => clamp01(d).max(s),
        _ => s,
    }
}

/// [`combine_caution`] over a signed claim: only a valid claim bound to `action_digest` (and, when given, to `expected_holder`) is
/// honoured; an invalid, misbound or forged claim degrades to `server_risk`, never below it. Returns
/// `{effectiveRisk, honoured, escalated}`.
pub fn combine_signed_caution(
    claim: Option<&Value>,
    action_digest: &str,
    server_risk: f64,
    expected_holder: Option<&str>,
) -> Value {
    let s = if server_risk.is_finite() {
        clamp01(server_risk)
    } else {
        1.0
    };
    let ok = claim.is_some_and(|c| verify_caution(c, Some(action_digest), expected_holder));
    let declared = if ok {
        fin(claim.and_then(|c| c.get("caution")))
    } else {
        None
    };
    let eff = combine_caution(declared, s);
    json!({"effectiveRisk": num(eff), "honoured": ok, "escalated": eff > s})
}

/// The monotonicity property of [`combine_caution`] over the finite members of `grid`: `{ok: true}`, or `{ok: false,
/// counterexample: [declared, server]}`.
pub fn check_caution_monotone(grid: &[f64]) -> Value {
    let g: Vec<f64> = grid.iter().copied().filter(|x| x.is_finite()).collect();
    for &s in &g {
        for &d in &g {
            let e = combine_caution(Some(d), s);
            if e < clamp01(s) {
                return json!({"ok": false, "counterexample": [num(d), num(s)]});
            }
            for &d2 in &g {
                if d2 >= d && combine_caution(Some(d2), s) < e {
                    return json!({"ok": false, "counterexample": [num(d2), num(s)]});
                }
            }
        }
    }
    json!({"ok": true})
}

// ---- 2. rationale binding ----------------------------------------------------------------------------------------------

/// Entropy floor of a commitment salt: strict base64url (at most 256 characters) that decodes to at least [`MIN_SALT_BYTES`]
/// bytes holding at least [`MIN_SALT_DISTINCT_BYTES`] distinct byte values. A sanity floor, not a proof of randomness.
pub fn is_strong_salt(salt: &Value) -> bool {
    let Some(s) = salt.as_str() else { return false };
    if s.is_empty() || jslen(s) > 256 {
        return false;
    }
    let Some(b) = crate::decode_b64u_strict(s, None) else {
        return false;
    };
    if b.len() < MIN_SALT_BYTES {
        return false;
    }
    let mut seen = [false; 256];
    for x in &b {
        seen[*x as usize] = true;
    }
    seen.iter().filter(|x| **x).count() >= MIN_SALT_DISTINCT_BYTES
}

fn commit_digest(action_digest: &str, salt: &str, rationale: &str) -> Option<String> {
    hash_canonical_strict(
        &json!({"d": RATIONALE_DOMAIN, "a": action_digest, "s": salt, "r": rationale}),
    )
}

/// Commit to a stated reason for `action`: returns `{commitment: {v, action_digest, commitment}, reveal: {rationale, salt}}`.
/// Publish the commitment, KEEP the reveal. `salt` `None` draws 32 random bytes; a given salt must pass [`is_strong_salt`].
/// Refuses (authoring error) an oversized rationale (more than [`MAX_RATIONALE_LEN`] UTF-16 units), a weak salt and a
/// non-canonicalizable action.
pub fn bind_rationale(
    action: &Value,
    rationale: &str,
    salt: Option<&str>,
) -> Result<Value, String> {
    let random;
    let salt = match salt {
        Some(s) => s,
        None => {
            let mut b = [0u8; 32];
            getrandom::getrandom(&mut b).map_err(|e| format!("bindRationale: {e}"))?;
            random = URL_SAFE_NO_PAD.encode(b);
            &random
        }
    };
    if jslen(rationale) > MAX_RATIONALE_LEN {
        return Err("bindRationale: rationale too long".into());
    }
    if !is_strong_salt(&json!(salt)) {
        return Err(
            "bindRationale: salt must be b64u of >=16 bytes with >=8 distinct values".into(),
        );
    }
    let ad =
        hash_canonical_strict(action).ok_or("bindRationale: the action is not canonicalizable")?;
    let cd = commit_digest(&ad, salt, rationale).ok_or("bindRationale: not canonicalizable")?;
    Ok(
        json!({"commitment": {"v": 1, "action_digest": ad, "commitment": cd}, "reveal": {"rationale": rationale, "salt": salt}}),
    )
}

fn commitment_ok(c: &Map<String, Value>) -> bool {
    fin(c.get("v")) == Some(1.0)
        && ne_str(c.get("action_digest")).is_some()
        && ne_str(c.get("commitment")).is_some()
}

/// Does `reveal` open `commitment`, optionally for this very `action` (`Some(&Value::Null)` is an action of JSON null)? A salt
/// below the entropy floor is rejected even if it hashes correctly. Total: `false` on anything malformed.
pub fn verify_rationale(commitment: &Value, reveal: &Value, action: Option<&Value>) -> bool {
    let (Some(c), Some(r)) = (commitment.as_object(), reveal.as_object()) else {
        return false;
    };
    if !commitment_ok(c) {
        return false;
    }
    let Some(rat) = r.get("rationale").and_then(Value::as_str) else {
        return false;
    };
    let salt = r.get("salt").unwrap_or(&Value::Null);
    if jslen(rat) > MAX_RATIONALE_LEN || !is_strong_salt(salt) {
        return false;
    }
    let ad = c.get("action_digest").and_then(Value::as_str).unwrap_or("");
    if let Some(a) = action {
        if hash_canonical_strict(a).as_deref() != Some(ad) {
            return false;
        }
    }
    commit_digest(ad, salt.as_str().unwrap_or(""), rat).as_deref()
        == c.get("commitment").and_then(Value::as_str)
}

/// After-the-fact audit. The resource server never judges the rationale: an auditor supplies `judge(rationale, action)`
/// (`Err` is a failure of the judge, not of the agent). A rationale that opens the commitment and is judged false is
/// attributable (slashable); failing to open it on demand is slashable too; a failing judge yields `judge_error` (not slashable).
/// Returns `{verdict, slashable, evidence: {commitment, action_digest, rationale?}}` with verdict `consistent`,
/// `false_rationale`, `unopened`, `wrong_action`, `malformed` or `judge_error`. Total.
pub fn audit_rationale(
    commitment: &Value,
    action: &Value,
    reveal: Option<&Value>,
    judge: &dyn Fn(&str, &Value) -> Result<bool, String>,
) -> Value {
    let co = commitment.as_object();
    let text = |k: &str| {
        co.and_then(|c| c.get(k))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let (cm, ad) = (text("commitment"), text("action_digest"));
    let out = |verdict: &str, slashable: bool, rationale: Option<&str>| {
        let mut ev = json!({"commitment": cm, "action_digest": ad});
        if let Some(r) = rationale {
            ev["rationale"] = json!(r);
        }
        json!({"verdict": verdict, "slashable": slashable, "evidence": ev})
    };
    let Some(c) = co.filter(|c| commitment_ok(c)) else {
        return out("malformed", false, None);
    };
    match hash_canonical_strict(action) {
        None => return out("malformed", false, None),
        Some(h) if Some(h.as_str()) != c.get("action_digest").and_then(Value::as_str) => {
            return out("wrong_action", false, None)
        }
        _ => {}
    }
    let opened = reveal.filter(|r| verify_rationale(commitment, r, Some(action)));
    let Some(rat) = opened
        .and_then(|r| r.get("rationale"))
        .and_then(Value::as_str)
    else {
        return out("unopened", true, None);
    };
    match judge(rat, action) {
        Err(_) => out("judge_error", false, Some(rat)),
        Ok(true) => out("consistent", false, Some(rat)),
        Ok(false) => out("false_rationale", true, Some(rat)),
    }
}

// ---- 3. semantic firewall ----------------------------------------------------------------------------------------------------

/// Build a `tool_schema` caveat: authority exists only for this exact tool, signature and argument schema. `tool_signature` is the
/// tool name or an object with a string `name`; `arg_schema` must pass [`validate_arg_schema`]. The schema is deep-cloned in
/// canonical form, so later mutation of the input cannot alter the caveat. Refuses a missing tool name, an invalid schema or
/// anything not canonicalizable.
pub fn tool_schema_caveat(tool_signature: &Value, arg_schema: &Value) -> Result<Value, String> {
    let tool = match tool_signature {
        Value::String(s) => s.as_str(),
        Value::Object(o) => o.get("name").and_then(Value::as_str).unwrap_or(""),
        _ => "",
    };
    if tool.is_empty() {
        return Err("toolSchemaCaveat: tool name required".into());
    }
    if let Some(e) = validate_arg_schema(arg_schema) {
        return Err(format!("toolSchemaCaveat: {e}"));
    }
    let schema: Value = serde_json::from_str(&canonicalize(arg_schema))
        .map_err(|e| format!("toolSchemaCaveat: {e}"))?;
    let signature_digest = hash_canonical_strict(tool_signature)
        .ok_or("toolSchemaCaveat: the tool signature is not canonicalizable")?;
    let schema_digest = hash_canonical_strict(&schema)
        .ok_or("toolSchemaCaveat: the schema is not canonicalizable")?;
    let binding_digest = hash_canonical_strict(
        &json!({"tool": tool, "signature_digest": signature_digest, "schema": schema}),
    )
    .ok_or("toolSchemaCaveat: not canonicalizable")?;
    Ok(
        json!({"type": CAVEAT_TOOL_SCHEMA, "tool": tool, "signature_digest": signature_digest, "schema": schema, "schema_digest": schema_digest, "binding_digest": binding_digest}),
    )
}

/// The caveat-evaluator extension point for `tool_schema`: `ctx = {toolCall}`. Any other caveat type is unsatisfied.
pub fn tool_schema_evaluator(caveat: &Value, ctx: &Value) -> bool {
    match ctx.get("toolCall") {
        Some(call) if call.is_object() => evaluate_tool_schema(caveat, call).0,
        _ => false,
    }
}

/// The delegated-narrowing caveat `{type: "predicates", allow}` with `allow` deep-cloned in canonical form.
pub fn predicates_caveat(allow: &Value) -> Result<Value, String> {
    let clone: Value =
        serde_json::from_str(&canonicalize(allow)).map_err(|e| format!("predicatesCaveat: {e}"))?;
    Ok(json!({"type": CAVEAT_PREDICATES, "allow": clone}))
}

/// The action's spend in USD as `max_spend` reads it: the own `action.action.params.amount` (finite, >= 0), with an own
/// `currency`, when present, of "usd" or "USD". `None` = no readable spend.
pub fn action_spend_usd(action: &Value) -> Option<f64> {
    let params = action
        .as_object()?
        .get("action")?
        .as_object()?
        .get("params")?
        .as_object()?;
    let amount = fin(params.get("amount")).filter(|a| *a >= 0.0)?;
    match params.get("currency") {
        Some(c) if c.as_str() != Some("usd") && c.as_str() != Some("USD") => None,
        _ => Some(amount),
    }
}

fn max_spend_ok(cv: &Map<String, Value>, ctx: &Map<String, Value>) -> bool {
    match (
        fin(cv.get("usd")),
        ctx.get("action").and_then(action_spend_usd),
    ) {
        (Some(lim), Some(spend)) => spend <= lim,
        _ => false,
    }
}

/// A superset of the stock envelope caveat evaluator: adds `predicates` (needs `ctx.action`, an action context
/// `{action: {verb, resource, params}}`), `max_spend` (needs `ctx.action`) and `tool_schema` (needs `ctx.toolCall`). The stock
/// context fields are `now`, `blastRadius`, `reversibilityClass`, `delegationDepth` and `recentActionTimes`. Anything else is
/// unsatisfied (fail closed). Total.
pub fn agent_native_caveat_evaluator(caveat: &Value, ctx: &Value) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        with_regex_budget(|| evaluate_agent_native(caveat, ctx))
    }))
    .unwrap_or(false)
}

fn evaluate_agent_native(caveat: &Value, ctx: &Value) -> bool {
    let (Some(cv), Some(x)) = (caveat.as_object(), ctx.as_object()) else {
        return false;
    };
    let ty = cv.get("type").and_then(Value::as_str).unwrap_or("");
    match ty {
        CAVEAT_TOOL_SCHEMA => return tool_schema_evaluator(caveat, ctx),
        CAVEAT_PREDICATES => {
            return match (
                x.get("action").filter(|a| a.is_object()),
                cv.get("allow").and_then(Value::as_array),
            ) {
                (Some(a), Some(allow)) => {
                    let pctx = Ctx::new(a);
                    allow.iter().any(|p| predicate_matches(p, &pctx))
                }
                _ => false,
            }
        }
        CAVEAT_MAX_SPEND => return max_spend_ok(cv, x),
        _ => {}
    }
    let Some(now) = fin(x.get("now")) else {
        return false;
    };
    match ty {
        CAVEAT_EXPIRES => fin(cv.get("at")).is_some_and(|at| now < at),
        CAVEAT_NOT_BEFORE => fin(cv.get("at")).is_some_and(|at| now >= at),
        CAVEAT_RATE => {
            let (Some(max), Some(per)) = (fin(cv.get("max")), fin(cv.get("per_secs"))) else {
                return false;
            };
            let Some(times) = x.get("recentActionTimes").and_then(Value::as_array) else {
                return false;
            };
            if per <= 0.0 {
                return false;
            }
            let lo = now - per * 1000.0;
            let n = times
                .iter()
                .filter_map(|t| fin(Some(t)))
                .filter(|t| *t > lo && *t <= now)
                .count();
            (n as f64) < max
        }
        CAVEAT_MAX_BLAST_RADIUS => {
            matches!((fin(cv.get("max")), fin(x.get("blastRadius"))), (Some(m), Some(b)) if b <= m)
        }
        CAVEAT_REVERSIBILITY_MAX => {
            let (Some(l), Some(c)) = (
                cv.get("class").and_then(Value::as_str),
                x.get("reversibilityClass").and_then(Value::as_str),
            ) else {
                return false;
            };
            matches!((REV.iter().position(|r| *r == l), REV.iter().position(|r| *r == c)), (Some(l), Some(c)) if c <= l)
        }
        CAVEAT_DELEGATION_DEPTH => {
            matches!((fin(cv.get("max")), fin(x.get("delegationDepth"))), (Some(m), Some(d)) if d <= m)
        }
        "budget_alloc" => fin(cv.get("limit")).is_some_and(|l| l >= 0.0),
        "intent_session" => crate::intent_session_caveat_error(Some(caveat)).is_none(),
        _ => false,
    }
}

// ---- 4. capability introspection ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Scope {
    verbs: Vec<String>,
    resources: Vec<String>,
    wh: Vec<Value>,
}

impl Scope {
    fn to_value(&self) -> Value {
        json!({"verbs": self.verbs, "resources": self.resources, "where": self.wh})
    }
}

fn sorted_unique(xs: impl IntoIterator<Item = String>) -> Vec<String> {
    xs.into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn intersect_verbs(a: &[String], b: &[String]) -> Vec<String> {
    if a.iter().any(|x| x == "*") {
        return sorted_unique(b.iter().cloned());
    }
    if b.iter().any(|x| x == "*") {
        return sorted_unique(a.iter().cloned());
    }
    sorted_unique(a.iter().filter(|x| b.contains(x)).cloned())
}

/// Intersect two resource patterns; `None` = empty or not decidable symbolically (a regex).
fn inter_res(a: &str, b: &str) -> Option<String> {
    if a == b {
        return Some(a.to_string());
    }
    if a.starts_with("re:") || b.starts_with("re:") {
        return None;
    }
    if a == "*" {
        return Some(b.to_string());
    }
    if b == "*" {
        return Some(a.to_string());
    }
    match (a.strip_suffix('*'), b.strip_suffix('*')) {
        (Some(pa), Some(pb)) => {
            if pb.starts_with(pa) {
                Some(b.to_string())
            } else if pa.starts_with(pb) {
                Some(a.to_string())
            } else {
                None
            }
        }
        (Some(pa), None) => b.starts_with(pa).then(|| b.to_string()),
        (None, Some(pb)) => a.starts_with(pb).then(|| a.to_string()),
        (None, None) => None,
    }
}

/// Collapse a conjunction of resource patterns; `None` = unsatisfiable.
fn collapse(list: &[String]) -> Option<Vec<String>> {
    let mut lit: Option<String> = None;
    let mut res: BTreeSet<String> = BTreeSet::new();
    for p in list {
        if p.starts_with("re:") {
            res.insert(p.clone());
            continue;
        }
        lit = match lit {
            None => Some(p.clone()),
            Some(l) => Some(inter_res(&l, p)?),
        };
    }
    let mut out: Vec<String> = lit.filter(|l| l != "*").into_iter().collect();
    out.extend(res);
    Some(if out.is_empty() {
        vec!["*".to_string()]
    } else {
        out
    })
}

fn scope_of_predicate(p: &Value) -> Option<Scope> {
    let o = p.as_object()?;
    let verbs: Vec<String> = match o.get("verb") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| x.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()?,
        _ => return None,
    };
    let resource = match o.get("resource") {
        None => "*".to_string(),
        Some(Value::String(s)) => s.clone(),
        _ => return None,
    };
    let wh = match o.get("where") {
        None => vec![],
        Some(Value::Array(a)) => a.clone(),
        _ => return None,
    };
    Some(Scope {
        verbs: sorted_unique(verbs),
        resources: vec![resource],
        wh,
    })
}

fn intersect_scopes(a: &[Scope], b: &[Scope]) -> Option<Vec<Scope>> {
    let mut out: BTreeMap<String, Scope> = BTreeMap::new();
    for x in a {
        for y in b {
            let verbs = intersect_verbs(&x.verbs, &y.verbs);
            if verbs.is_empty() {
                continue;
            }
            let both: Vec<String> = x
                .resources
                .iter()
                .chain(y.resources.iter())
                .cloned()
                .collect();
            let Some(resources) = collapse(&both) else {
                continue;
            };
            let s = Scope {
                verbs,
                resources,
                wh: x.wh.iter().chain(y.wh.iter()).cloned().collect(),
            };
            out.insert(hash_canonical_strict(&s.to_value())?, s);
        }
    }
    Some(out.into_values().collect())
}

fn scope_matches(s: &Value, verb: &str, resource: &str, params: Option<&Value>) -> Option<bool> {
    let verbs = s.get("verbs")?.as_array()?;
    let resources = s.get("resources")?.as_array()?;
    let wh = s.get("where")?.as_array()?;
    if !verbs
        .iter()
        .any(|v| v.as_str() == Some("*") || v.as_str() == Some(verb))
    {
        return Some(false);
    }
    let mut action = json!({"verb": verb, "resource": resource});
    if let Some(p) = params {
        action["params"] = p.clone();
    }
    let ctx = json!({"action": action});
    let pctx = Ctx::new(&ctx);
    for r in resources {
        if !predicate_matches(&json!({"verb": "*", "resource": r}), &pctx) {
            return Some(false);
        }
    }
    if params.is_some() && !wh.is_empty() {
        return Some(predicate_matches(&json!({"verb": "*", "where": wh}), &pctx));
    }
    Some(true)
}

fn well_formed_caveat(cv: &Map<String, Value>, ty: &str) -> bool {
    match ty {
        CAVEAT_EXPIRES | CAVEAT_NOT_BEFORE => fin(cv.get("at")).is_some(),
        CAVEAT_RATE => {
            fin(cv.get("max")).is_some() && fin(cv.get("per_secs")).is_some_and(|p| p > 0.0)
        }
        CAVEAT_MAX_BLAST_RADIUS | CAVEAT_DELEGATION_DEPTH => fin(cv.get("max")).is_some(),
        CAVEAT_REVERSIBILITY_MAX => cv
            .get("class")
            .and_then(Value::as_str)
            .is_some_and(|c| REV.contains(&c)),
        CAVEAT_PREDICATES => cv
            .get("allow")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().all(|p| scope_of_predicate(p).is_some())),
        CAVEAT_TOOL_SCHEMA => ne_str(cv.get("tool")).is_some(),
        "budget_alloc" => fin(cv.get("limit")).is_some_and(|l| l >= 0.0),
        CAVEAT_MAX_SPEND => fin(cv.get("usd")).is_some_and(|l| l >= 0.0),
        _ => false,
    }
}

#[derive(Default)]
struct Hints {
    expires_at: Option<f64>,
    not_before: Option<f64>,
    max_rate: Option<(f64, f64)>,
    max_blast: Option<f64>,
    rev_max: Option<usize>,
    depth_rem: Option<f64>,
    budget: Option<f64>,
    max_spend: Option<f64>,
}

struct Fold {
    bad: BTreeSet<String>,
    scopes: Option<Vec<Scope>>,
    tools: Option<Vec<String>>,
    seen_envelope: bool,
    tool_schemas: Vec<Value>,
    h: Hints,
}

fn lower(cur: Option<f64>, v: f64) -> Option<f64> {
    Some(cur.map_or(v, |c| c.min(v)))
}

fn fold_caveat(st: &mut Fold, cv: &Value, in_envelope: bool, hops: usize) -> Option<()> {
    let ty = cv
        .as_object()
        .and_then(|_| cv.get("type"))
        .and_then(Value::as_str);
    let (Some(o), Some(ty)) = (cv.as_object(), ty) else {
        st.bad.insert("<malformed>".into());
        return Some(());
    };
    if ty == CAVEAT_ENVELOPE {
        // only the root's FIRST envelope caveat is read; the policy VM evaluates any other as unknown => unsatisfied
        if st.seen_envelope || in_envelope {
            st.bad.insert(CAVEAT_ENVELOPE.into());
        }
        st.seen_envelope = true;
        return Some(());
    }
    if !well_formed_caveat(o, ty) {
        st.bad.insert(ty.to_string());
        return Some(());
    }
    let f = |k: &str| fin(o.get(k)).unwrap_or(0.0);
    match ty {
        CAVEAT_PREDICATES => {
            let next: Vec<Scope> = o
                .get("allow")
                .and_then(Value::as_array)?
                .iter()
                .filter_map(scope_of_predicate)
                .collect();
            let base = st.scopes.take().unwrap_or_else(|| {
                vec![Scope {
                    verbs: vec!["*".into()],
                    resources: vec!["*".into()],
                    wh: vec![],
                }]
            });
            st.scopes = Some(intersect_scopes(&base, &next)?);
        }
        CAVEAT_TOOL_SCHEMA => {
            st.tool_schemas.push(cv.clone());
            let tool = o.get("tool").and_then(Value::as_str)?.to_string();
            let schema = o.get("schema").unwrap_or(&Value::Null);
            let consistent = validate_arg_schema(schema).is_none()
                && hash_canonical_strict(schema)?.as_str()
                    == o.get("schema_digest")
                        .and_then(Value::as_str)
                        .unwrap_or("\u{0}")
                && {
                    let sig = o
                        .get("signature_digest")
                        .map_or("undefined".to_string(), crate::intent_v2::js_value_string);
                    hash_canonical_strict(
                        &json!({"tool": tool, "signature_digest": sig, "schema": schema}),
                    )?
                    .as_str()
                        == o.get("binding_digest")
                            .and_then(Value::as_str)
                            .unwrap_or("\u{0}")
                };
            if !consistent {
                st.tools = Some(vec![]);
                st.bad.insert(CAVEAT_TOOL_SCHEMA.into());
            } else {
                st.tools = Some(match st.tools.take() {
                    None => vec![tool],
                    Some(t) => t.into_iter().filter(|x| *x == tool).collect(),
                });
            }
        }
        CAVEAT_EXPIRES => st.h.expires_at = lower(st.h.expires_at, f("at")),
        CAVEAT_NOT_BEFORE => {
            st.h.not_before = Some(st.h.not_before.map_or(f("at"), |c| c.max(f("at"))))
        }
        CAVEAT_RATE => {
            let (m, p) = (f("max"), f("per_secs"));
            // the lower sustained rate (max / per_secs) binds; ties are broken by the smaller max
            let take = match st.h.max_rate {
                None => true,
                Some((cm, cp)) => m / p < cm / cp || (m / p == cm / cp && m < cm),
            };
            if take {
                st.h.max_rate = Some((m, p));
            }
        }
        CAVEAT_MAX_BLAST_RADIUS => st.h.max_blast = lower(st.h.max_blast, f("max")),
        CAVEAT_REVERSIBILITY_MAX => {
            let i = REV
                .iter()
                .position(|r| Some(*r) == o.get("class").and_then(Value::as_str))?;
            if i < st.h.rev_max.unwrap_or(REV.len()) {
                st.h.rev_max = Some(i);
            }
        }
        CAVEAT_DELEGATION_DEPTH => {
            st.h.depth_rem = lower(st.h.depth_rem, f("max") - (hops as f64 - 1.0))
        }
        "budget_alloc" => st.h.budget = lower(st.h.budget, f("limit")),
        CAVEAT_MAX_SPEND => st.h.max_spend = lower(st.h.max_spend, f("usd")),
        _ => {}
    }
    Some(())
}

fn empty_envelope(reason: Option<&str>) -> Value {
    let mut e = json!({"ok": false, "hasEnvelope": false, "scopes": [], "verbs": [], "resources": [], "opaqueResourceConstraints": [], "tools": [],
        "toolSchemas": [], "unsatisfiable": [], "caveats": [], "remainingBudgetHints": {}});
    if let Some(r) = reason {
        e["reason"] = json!(r);
    }
    e
}

/// What an attenuated chain actually permits now, deterministically (`now` is supplied; `None` = unknown). The chain is
/// verified first with `verify_chain_policy` (`expected_root_issuer` `None` = any root; `policy` is the optional
/// `{allowedSuites, pqPins, trustedRoot}` object); an unverifiable chain gives `ok: false` with the chain's reason and nothing
/// permitted. Caveats are conjunctive and append-only, so the envelope is the intersection across all hops: the set the verifier
/// would accept, never wider. A caveat the verifier cannot satisfy (unknown type, malformed fields, a second `envelope`) is listed
/// in `unsatisfiable` and nothing is permitted. The result is the JSON object of the reference (`ok`, `hasEnvelope`, `scopes`,
/// `verbs`, `resources`, `opaqueResourceConstraints`, `tools`, `toolSchemas`, `unsatisfiable`, `caveats`, `remainingBudgetHints`,
/// `reason`?); pass it to [`envelope_permits`] and [`envelope_permits_tool_call`]. Total.
pub fn describe_envelope(
    chain: &Value,
    now: Option<f64>,
    expected_root_issuer: Option<&str>,
    policy: Option<&Value>,
) -> Value {
    catch_unwind(AssertUnwindSafe(|| {
        describe_inner(chain, now, expected_root_issuer, policy)
    }))
    .ok()
    .flatten()
    .unwrap_or_else(|| empty_envelope(Some("introspection error (fail closed)")))
}

fn describe_inner(
    chain: &Value,
    now: Option<f64>,
    expected_root_issuer: Option<&str>,
    policy: Option<&Value>,
) -> Option<Value> {
    let list: &[Value] = chain.as_array().map_or(&[][..], Vec::as_slice);
    let p = policy.and_then(Value::as_object);
    let allowed: Option<Vec<String>> = p
        .and_then(|p| p.get("allowedSuites"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|x| x.as_str().unwrap_or("").to_string())
                .collect()
        });
    let pins: Option<HashMap<String, String>> = p
        .and_then(|p| p.get("pqPins"))
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                .collect()
        });
    let trusted = p
        .and_then(|p| p.get("trustedRoot"))
        .filter(|t| t.is_object());
    if let Err(why) = crate::verify_chain_policy(
        list,
        expected_root_issuer,
        allowed.as_deref(),
        pins.as_ref(),
        trusted,
    ) {
        return Some(empty_envelope(Some(why.as_str())));
    }
    let root = list.first()?;
    let leaf = list.last()?;
    let env0 = read_envelope(root);
    let all = vec![Scope {
        verbs: vec!["*".into()],
        resources: vec!["*".into()],
        wh: vec![],
    }];
    let mut st = Fold {
        bad: BTreeSet::new(),
        scopes: None,
        tools: None,
        seen_envelope: false,
        tool_schemas: vec![],
        h: Hints::default(),
    };
    if let Some(e) = &env0 {
        let mut base = vec![];
        for p in e.get("predicates").and_then(Value::as_array)? {
            match scope_of_predicate(p) {
                Some(s) => base.push(s),
                None => {
                    st.bad.insert("envelope.predicates".into());
                }
            }
        }
        st.scopes = Some(intersect_scopes(&base, &all)?);
        for cv in e.get("caveats").and_then(Value::as_array)? {
            fold_caveat(&mut st, cv, true, list.len())?;
        }
    }
    for cv in leaf
        .get("caveats")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
    {
        fold_caveat(&mut st, cv, false, list.len())?;
    }

    let mut opaque: BTreeSet<String> = BTreeSet::new();
    let (mut scopes_v, mut verbs_v, mut resources_v) = (Value::Null, Value::Null, Value::Null);
    if let Some(scopes) = &st.scopes {
        let (mut vs, mut rs) = (BTreeSet::new(), BTreeSet::new());
        for s in scopes {
            vs.extend(s.verbs.iter().cloned());
            for r in &s.resources {
                rs.insert(r.clone());
                if r.starts_with("re:") {
                    opaque.insert(r.clone());
                }
            }
        }
        scopes_v = Value::Array(scopes.iter().map(Scope::to_value).collect());
        verbs_v = json!(vs);
        resources_v = json!(rs);
    }
    let mut tools_v = st
        .tools
        .as_ref()
        .map_or(Value::Null, |t| json!(sorted_unique(t.iter().cloned())));
    let unsat: Vec<String> = st.bad.iter().cloned().collect();
    let mut reason = None;
    if !unsat.is_empty() {
        scopes_v = json!([]);
        verbs_v = json!([]);
        resources_v = json!([]);
        tools_v = json!([]);
        reason = Some(format!("unsatisfiable caveat(s): {}", unsat.join(", ")));
    }
    let h = &st.h;
    let mut hints = Map::new();
    if let Some(v) = h.expires_at {
        hints.insert("expiresAt".into(), num(v));
        if let Some(n) = now.filter(|n| n.is_finite()) {
            hints.insert("expiresIn".into(), num(v - n));
        }
    }
    if let Some(v) = h.not_before {
        hints.insert("notBefore".into(), num(v));
    }
    if let Some((m, p)) = h.max_rate {
        hints.insert("maxRate".into(), json!({"max": num(m), "per_secs": num(p)}));
    }
    if let Some(v) = h.max_blast {
        hints.insert("maxBlastRadius".into(), num(v));
    }
    if let Some(i) = h.rev_max {
        hints.insert("reversibilityMax".into(), json!(REV[i]));
    }
    if let Some(v) = h.depth_rem {
        hints.insert("delegationDepthRemaining".into(), num(v));
    }
    if let Some(v) = h.budget {
        hints.insert("budgetAlloc".into(), num(v));
    }
    if let Some(v) = h.max_spend {
        hints.insert("maxSpendUsd".into(), num(v));
    }
    let mut env = json!({"ok": true, "hasEnvelope": env0.is_some(), "scopes": scopes_v, "verbs": verbs_v, "resources": resources_v,
        "opaqueResourceConstraints": json!(opaque), "tools": tools_v, "toolSchemas": st.tool_schemas, "unsatisfiable": unsat,
        "caveats": leaf.get("caveats").cloned().unwrap_or(Value::Null), "remainingBudgetHints": Value::Object(hints)});
    if let Some(r) = reason {
        env["reason"] = json!(r);
    }
    Some(env)
}

/// The cheap pre-flight an agent can run before attempting. `false` is DEFINITIVE (the verifier will refuse); `true` means the
/// symbolic envelope allows it. `env` is the result of [`describe_envelope`]. When `params` is given, `where` conditions are
/// evaluated too (fail closed); without it, conditional scopes count as "may permit". `now` `None` = not given; a NaN or infinite
/// `now` is refused, and expiry is exclusive. Total.
pub fn envelope_permits(
    env: &Value,
    verb: &str,
    resource: &str,
    now: Option<f64>,
    params: Option<&Value>,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        with_regex_budget(|| permits_inner(env, verb, resource, now, params))
    }))
    .ok()
    .flatten()
    .unwrap_or(false)
}

fn permits_inner(
    env: &Value,
    verb: &str,
    resource: &str,
    now: Option<f64>,
    params: Option<&Value>,
) -> Option<bool> {
    if env.get("ok") != Some(&Value::Bool(true))
        || !env.get("unsatisfiable")?.as_array()?.is_empty()
    {
        return Some(false);
    }
    match env.get("scopes") {
        Some(Value::Null) => {}
        Some(Value::Array(scopes)) => {
            let mut any = false;
            for s in scopes {
                if scope_matches(s, verb, resource, params)? {
                    any = true;
                    break;
                }
            }
            if !any {
                return Some(false);
            }
        }
        _ => return None,
    }
    let h = env.get("remainingBudgetHints")?;
    // a present hint that is not a finite number (a non-finite value serializes as null) never admits
    if h.get("delegationDepthRemaining").is_some() && !fin(h.get("delegationDepthRemaining")).is_some_and(|r| r >= 0.0) {
        return Some(false);
    }
    if let (Some(lim), Some(p)) = (fin(h.get("maxSpendUsd")), params) {
        match action_spend_usd(&json!({"action": {"params": p}})) {
            Some(spend) if spend <= lim => {}
            _ => return Some(false),
        }
    }
    if let Some(n) = now {
        if !n.is_finite() {
            return Some(false);
        }
        if (h.get("expiresAt").is_some() && !fin(h.get("expiresAt")).is_some_and(|at| n < at))
            || (h.get("notBefore").is_some() && !fin(h.get("notBefore")).is_some_and(|nb| n >= nb))
        {
            return Some(false);
        }
    }
    Some(true)
}

/// Pre-flight for a tool call: the tool must be in `env.tools` (when that is not null) and satisfy EVERY `tool_schema` caveat of
/// the chain; the first failure is returned as `(false, Some(reason))`. `env` is the result of [`describe_envelope`]. Total.
pub fn envelope_permits_tool_call(env: &Value, call: &Value) -> (bool, Option<String>) {
    let fail_closed = || (false, Some("evaluation error (fail closed)".to_string()));
    catch_unwind(AssertUnwindSafe(|| permits_tool_call_inner(env, call)))
        .ok()
        .flatten()
        .unwrap_or_else(fail_closed)
}

fn permits_tool_call_inner(env: &Value, call: &Value) -> Option<(bool, Option<String>)> {
    let unusable = env.get("ok") != Some(&Value::Bool(true))
        || !env.get("unsatisfiable")?.as_array()?.is_empty();
    if unusable {
        let r = match env.get("reason") {
            Some(r) if !r.is_null() => crate::intent_v2::js_value_string(r),
            _ => "envelope not usable".to_string(),
        };
        return Some((false, Some(r)));
    }
    match env.get("tools")? {
        Value::Null => {}
        Value::Array(tools) => {
            if call.is_null() {
                return None;
            }
            let tool = call.get("tool");
            if !tool
                .and_then(Value::as_str)
                .is_some_and(|t| tools.iter().any(|x| x.as_str() == Some(t)))
            {
                let name = tool.map_or("undefined".to_string(), crate::intent_v2::js_value_string);
                return Some((
                    false,
                    Some(format!(
                        "tool {} not authorized",
                        crate::authorize::show(&name)
                    )),
                ));
            }
        }
        _ => return None,
    }
    for tc in env.get("toolSchemas")?.as_array()? {
        let (ok, reason) = evaluate_tool_schema(tc, call);
        if !ok {
            return Some((false, reason));
        }
    }
    Some((true, None))
}

// ---- 5. authority lease ------------------------------------------------------------------------------------------------------

/// Issue a lease `{cap_id, holder, issued_at, renewed_at, ttl_ms, renewals, last_seq, expires_at, hard_expires_at?,
/// max_renewals?}` from `{cap_id, holder, now, ttl_ms, hard_expires_at?, max_renewals?}`. Refuses (authoring error) unless the ids
/// are non-empty, `now` is finite, `0 < ttl_ms <=` [`MAX_LEASE_TTL_MS`], `hard_expires_at` (if present) is finite and after `now`,
/// and `max_renewals` (if present) is a non-negative integer. Persist and update the record atomically (row lock or
/// compare-and-swap on `last_seq`); [`renew_capability_lease`] is a pure function returning the next record.
pub fn grant_lease(args: &Value) -> Result<Value, String> {
    let (Some(cap_id), Some(holder)) = (ne_str(args.get("cap_id")), ne_str(args.get("holder")))
    else {
        return Err("grantLease: cap_id and holder required".into());
    };
    let (Some(now), Some(ttl)) = (fin(args.get("now")), fin(args.get("ttl_ms"))) else {
        return Err("grantLease: invalid now/ttl_ms".into());
    };
    if ttl <= 0.0 || ttl > MAX_LEASE_TTL_MS {
        return Err("grantLease: invalid now/ttl_ms".into());
    }
    let hard = match args.get("hard_expires_at") {
        None => None,
        Some(h) => Some(
            fin(Some(h))
                .filter(|h| *h > now)
                .ok_or("grantLease: hard_expires_at must be finite and in the future")?,
        ),
    };
    let max_renewals = args.get("max_renewals");
    if max_renewals.is_some()
        && !(is_int(max_renewals) && fin(max_renewals).is_some_and(|m| m >= 0.0))
    {
        return Err("grantLease: invalid max_renewals".into());
    }
    let exp = hard.map_or(now + ttl, |h| (now + ttl).min(h));
    let mut l = json!({"cap_id": cap_id, "holder": holder, "issued_at": args["now"], "renewed_at": args["now"], "ttl_ms": args["ttl_ms"],
        "renewals": 0, "last_seq": 0, "expires_at": num(exp)});
    if hard.is_some() {
        l["hard_expires_at"] = args["hard_expires_at"].clone();
    }
    if let Some(m) = max_renewals {
        l["max_renewals"] = m.clone();
    }
    Ok(l)
}

fn lease_error(l: &Value) -> Option<&'static str> {
    const MALFORMED: Option<&str> = Some("malformed lease");
    let Some(o) = l.as_object() else {
        return MALFORMED;
    };
    if ne_str(o.get("cap_id")).is_none() || ne_str(o.get("holder")).is_none() {
        return MALFORMED;
    }
    let (Some(_), Some(renewed), Some(ttl), Some(expires)) = (
        fin(o.get("issued_at")),
        fin(o.get("renewed_at")),
        fin(o.get("ttl_ms")),
        fin(o.get("expires_at")),
    ) else {
        return MALFORMED;
    };
    if ttl <= 0.0 || ttl > MAX_LEASE_TTL_MS {
        return MALFORMED;
    }
    for k in ["renewals", "last_seq"] {
        if !(is_int(o.get(k)) && fin(o.get(k)).is_some_and(|x| x >= 0.0)) {
            return MALFORMED;
        }
    }
    if o.get("max_renewals").is_some()
        && !(is_int(o.get("max_renewals")) && fin(o.get("max_renewals")).is_some_and(|x| x >= 0.0))
    {
        return MALFORMED;
    }
    if let Some(h) = o.get("hard_expires_at") {
        let Some(hard) = fin(Some(h)) else {
            return MALFORMED;
        };
        if expires > hard {
            return Some("lease exceeds hard expiry");
        }
    }
    // a lease can never outlive one ttl past its last renewal: anything else is corruption or tampering
    if expires > renewed + ttl {
        return MALFORMED;
    }
    None
}

/// Whether a lease is live at `now`: the record is well-formed, the clock has not rolled back more than [`HEARTBEAT_SKEW_MS`]
/// past the last renewal, and `now < expires_at`. Returns `{live: true, expiresIn}` or `{live: false, expiresIn: 0, reason}`
/// (malformed, NaN or rolled-back is not live: fail closed; a lapsed lease has `expiresIn` 0).
pub fn lease_state(lease: &Value, now: f64) -> Value {
    let dead = |r: &str| json!({"live": false, "expiresIn": 0, "reason": r});
    if !now.is_finite() {
        return dead("invalid clock");
    }
    if let Some(e) = lease_error(lease) {
        return dead(e);
    }
    let renewed = fin(lease.get("renewed_at")).unwrap_or(0.0);
    let expires_in = fin(lease.get("expires_at")).unwrap_or(0.0) - now;
    if now < renewed - HEARTBEAT_SKEW_MS {
        return dead("clock before last renewal");
    }
    if expires_in <= 0.0 {
        return dead("lease lapsed");
    }
    json!({"live": true, "expiresIn": num(expires_in)})
}

/// Renew a capability lease (the agent-native lease of [`grant_lease`], not the grants `LeaseRegistry`) on a valid, fresh,
/// in-order, holder-signed heartbeat for THIS lease grant. A lease that has already lapsed (or is malformed or clock-anomalous)
/// is dead for good: no resurrection by a late heartbeat. Renewal never extends past `hard_expires_at`, never shortens the lease
/// and consumes the renewal budget. The checks run in this order and the reason names the first that fails. Returns
/// `{ok: true, lease}` or `{ok: false, reason}`. Pure and total.
pub fn renew_capability_lease(lease: &Value, hb: &Value, now: f64) -> Value {
    let refuse = |r: &str| json!({"ok": false, "reason": r});
    let st = lease_state(lease, now);
    if st["live"] != json!(true) {
        let r = st["reason"].as_str().unwrap_or("");
        return refuse(&if r == "lease lapsed" {
            "lease lapsed".to_string()
        } else {
            format!("lease not live: {r}")
        });
    }
    let Some(h) = hb.as_object() else {
        return refuse("malformed heartbeat");
    };
    let Some(sig) = h.get("sig").and_then(Value::as_str) else {
        return refuse("malformed heartbeat");
    };
    if !h.keys().all(|k| HB_KEYS.contains(&k.as_str())) {
        return refuse("malformed heartbeat");
    }
    let same_num = |a: Option<&Value>, b: Option<&Value>| matches!((fin(a), fin(b)), (Some(x), Some(y)) if x == y);
    if h.get("cap_id") != lease.get("cap_id")
        || h.get("holder") != lease.get("holder")
        || !same_num(h.get("lease_issued_at"), lease.get("issued_at"))
    {
        return refuse("heartbeat not for this lease");
    }
    let last_seq = fin(lease.get("last_seq")).unwrap_or(0.0);
    let seq_ok =
        fin(h.get("seq")).filter(|s| s.fract() == 0.0 && s.abs() <= 9_007_199_254_740_991.0);
    if !seq_ok.is_some_and(|s| s > last_seq) {
        return refuse("stale or replayed heartbeat");
    }
    if !fin(h.get("at")).is_some_and(|at| (at - now).abs() <= HEARTBEAT_SKEW_MS) {
        return refuse("heartbeat outside skew window");
    }
    let Ok(msg) = native_msg(HEARTBEAT_DOMAIN, &without(h, "sig")) else {
        return refuse("malformed heartbeat");
    };
    if !crate::verify_b64u(lease["holder"].as_str().unwrap_or(""), &msg, sig) {
        return refuse("bad heartbeat signature");
    }
    let renewals = fin(lease.get("renewals")).unwrap_or(0.0);
    if fin(lease.get("max_renewals")).is_some_and(|m| renewals >= m) {
        return refuse("renewal budget exhausted");
    }
    let mut exp = now + fin(lease.get("ttl_ms")).unwrap_or(0.0);
    if let Some(hard) = fin(lease.get("hard_expires_at")) {
        exp = exp.min(hard);
    }
    if !exp.is_finite() {
        return refuse("malformed lease");
    }
    let mut next = lease.clone();
    next["renewals"] = num(renewals + 1.0);
    next["last_seq"] = h["seq"].clone();
    next["renewed_at"] = num(now.max(fin(lease.get("renewed_at")).unwrap_or(now)));
    next["expires_at"] = num(exp.max(fin(lease.get("expires_at")).unwrap_or(exp)));
    json!({"ok": true, "lease": next})
}
