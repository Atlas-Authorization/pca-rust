//! The high-level agent facade, the same compile-down as the TypeScript `agent()`: the principal's `permissions` and `limits` become
//! a policy envelope (predicates, caveats, risk policy) and a signed Root Intent Grant, and the returned [`AgentHandle`] builds one
//! proof-carrying action per tool call with its provenance bundle. Nothing here authorizes anything: the resource server's
//! verifier decides, and every field the facade emits is covered by a signature.
//!
//! ```no_run
//! use atlas_pca::agent::{create_agent, ActOptions, AgentOptions, KeyPair};
//! use atlas_pca::serde_json::json;
//! let principal = KeyPair::generate().unwrap();
//! let permissions = json!({"stripe": ["refund"]});
//! let limits = json!({"refund": "$500/day"});
//! let mut o = AgentOptions::new(&principal, "reconcile refunds for October", &permissions);
//! o.limits = Some(&limits);
//! o.aud = Some("rs-1");
//! let a = create_agent(o).unwrap();
//! let r = a.act("stripe.refund", "charge:ch_123", Some(&json!({"amount": 42})), &ActOptions::default()).unwrap();
//! // send r.headers (PCA-Action and PCA-Provenance) to the resource server
//! ```

use crate::agent::{delegate, mint_grant, pca_headers, KeyPair, PcactnInput, Suite};
use crate::arg_provenance::{encode_provenance_header, ProvenanceRecorder};
use crate::risk::{admit, safety_bound, validate_risk_policy, RiskPolicy, TrustBudget};
use crate::{params_digest, serde_json::json, Operation};
use serde_json::{Map, Value};
use std::sync::{Arc, Mutex};

/// One catalogued action: the PCA verb `connector.action`, its reversibility class, blast-radius preset, the params field that
/// carries a monetary amount (money-moving verbs only), the default resource matcher (`*` when absent) and its other names.
#[derive(Clone, Debug, PartialEq)]
pub struct ActionSpec {
    pub connector: String,
    pub action: String,
    pub verb: String,
    pub reversibility: String,
    pub blast_radius: f64,
    pub amount_field: Option<String>,
    pub resource: Option<String>,
    pub aliases: Vec<String>,
}

impl ActionSpec {
    /// The reference's field names (`blastRadius`, `amountField`, ...).
    pub fn to_json(&self) -> Value {
        let mut m = json!({"connector": self.connector, "action": self.action, "verb": self.verb, "reversibility": self.reversibility,
            "blastRadius": num(self.blast_radius)});
        if let Some(a) = &self.amount_field {
            m["amountField"] = json!(a);
        }
        if let Some(r) = &self.resource {
            m["resource"] = json!(r);
        }
        if !self.aliases.is_empty() {
            m["aliases"] = json!(self.aliases);
        }
        m
    }
}

/// The 21 built-in reviewed connector actions (the catalogue the server prices risk from), with their aliases.
pub fn builtin_catalog() -> Vec<ActionSpec> {
    crate::catalog_risk::BUILTIN_CATALOG
        .iter()
        .map(|&(verb, rev, blast, amount)| {
            let (connector, action) = verb.split_once('.').unwrap_or((verb, verb));
            let aliases = crate::catalog_risk::BUILTIN_ALIASES.iter().find(|a| a.0 == verb).map_or(vec![], |a| a.1.iter().map(|s| s.to_string()).collect());
            ActionSpec {
                connector: connector.into(),
                action: action.into(),
                verb: verb.to_string(),
                reversibility: rev.to_string(),
                blast_radius: blast,
                amount_field: amount.map(String::from),
                resource: None,
                aliases,
            }
        })
        .collect()
}

/// The spec of `verb`: the catalogued action (a later entry overrides an earlier one with the same verb), else an alias that names
/// exactly one action of the connector, else the conservative fallback (irreversible, blast radius 0.8).
pub fn spec_for(catalog: &[ActionSpec], verb: &str) -> ActionSpec {
    if let Some(s) = catalog.iter().rev().find(|s| s.verb == verb) {
        return s.clone();
    }
    if let Some(dot) = verb.find('.').filter(|d| *d > 0) {
        let (connector, action) = (&verb[..dot], &verb[dot + 1..]);
        // the catalogue by verb (last wins), then the unique alias hit
        let mut by_verb: Vec<&ActionSpec> = vec![];
        for s in catalog {
            match by_verb.iter().position(|x| x.verb == s.verb) {
                Some(i) => by_verb[i] = s,
                None => by_verb.push(s),
            }
        }
        let hits: Vec<&&ActionSpec> = by_verb.iter().filter(|s| s.connector == connector && s.aliases.iter().any(|a| a == action)).collect();
        if hits.len() == 1 {
            return (*hits[0]).clone();
        }
    }
    let mut parts = verb.split('.');
    let connector = parts.next().unwrap_or(verb).to_string();
    let rest: Vec<&str> = parts.collect();
    ActionSpec {
        connector,
        action: if rest.is_empty() || rest.join(".").is_empty() { verb.to_string() } else { rest.join(".") },
        verb: verb.to_string(),
        reversibility: "irreversible".into(),
        blast_radius: 0.8,
        amount_field: None,
        resource: None,
        aliases: vec![],
    }
}

// ---- limits ---------------------------------------------------------------------------------------------------------------

/// A parsed limit: `amount` in dollars (`unit` "usd") or a count ("count"), with the period window in ms when one was named.
#[derive(Clone, Debug, PartialEq)]
pub struct ParsedLimit {
    pub amount: f64,
    pub unit: &'static str,
    pub period_ms: Option<i64>,
}

impl ParsedLimit {
    /// `{amount, unit, periodMs?}`.
    pub fn to_json(&self) -> Value {
        let mut m = json!({"amount": num(self.amount), "unit": self.unit});
        if let Some(p) = self.period_ms {
            m["periodMs"] = json!(p);
        }
        m
    }
}

/// Longest limit string accepted, in UTF-16 units (the grammar needs about 20).
pub const MAX_LIMIT_LENGTH: usize = 64;

fn period_ms(p: &str) -> Option<i64> {
    Some(match p {
        "s" | "sec" | "second" | "seconds" => 1000,
        "m" | "min" | "minute" | "minutes" => 60_000,
        "h" | "hr" | "hour" | "hours" => 3_600_000,
        "d" | "day" | "days" => 86_400_000,
        "w" | "week" | "weeks" => 604_800_000,
        "mo" | "month" | "months" => 2_592_000_000,
        _ => return None,
    })
}

/// Parse `"$500/day"`, `"$500"`, `"10/hour"` or `"10"` (the reference grammar `^(\$)?\s*([0-9]+(\.[0-9]+)?)\s*(/\s*([a-zA-Z]+))?$`
/// on the trimmed string; same refusal texts).
pub fn parse_limit(s: &str) -> Result<ParsedLimit, String> {
    let ws = crate::action_schema::is_js_ws;
    let t = s.trim_matches(ws);
    if t.is_empty() {
        return Err("parseLimit: empty limit".into());
    }
    if s.encode_utf16().count() > MAX_LIMIT_LENGTH {
        return Err(format!("parseLimit: limit is longer than {MAX_LIMIT_LENGTH} characters"));
    }
    let bad = || format!("parseLimit: cannot parse limit '{s}'");
    let mut rest = t;
    let usd = rest.starts_with('$');
    if usd {
        rest = &rest[1..];
    }
    rest = rest.trim_start_matches(ws);
    let int_len = rest.bytes().take_while(u8::is_ascii_digit).count();
    if int_len == 0 {
        return Err(bad());
    }
    let mut num_len = int_len;
    if rest[int_len..].starts_with('.') {
        let frac = rest[int_len + 1..].bytes().take_while(u8::is_ascii_digit).count();
        if frac > 0 {
            num_len += 1 + frac;
        }
    }
    let (digits, tail) = rest.split_at(num_len);
    let tail = tail.trim_start_matches(ws);
    let period = if tail.is_empty() {
        None
    } else {
        let p = tail.strip_prefix('/').ok_or_else(bad)?.trim_start_matches(ws);
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_alphabetic()) {
            return Err(bad());
        }
        Some(p)
    };
    let amount = limit_amount(digits.parse().map_err(|_| bad())?, s)?;
    let period_ms = match period {
        Some(p) => Some(period_ms(&p.to_ascii_lowercase()).ok_or_else(|| format!("parseLimit: unknown period '{p}' in '{s}'"))?),
        None => None,
    };
    Ok(ParsedLimit { amount, unit: if usd { "usd" } else { "count" }, period_ms })
}

/// The reference's amount guard (`parseLimit: bad amount in '<s>'` for a non-finite or negative amount). [`parse_limit`] never
/// reaches the refusal (its grammar admits only `[0-9]+(.[0-9]+)?` within [`MAX_LIMIT_LENGTH`], always finite and >= 0); it stays
/// as defence in depth, as in the reference, and is public only so it can be tested directly.
#[doc(hidden)]
pub fn limit_amount(amount: f64, s: &str) -> Result<f64, String> {
    if !amount.is_finite() || amount < 0.0 {
        return Err(format!("parseLimit: bad amount in '{s}'"));
    }
    Ok(amount)
}

// ---- compiled policy ------------------------------------------------------------------------------------------------------

/// Inputs of [`compile_policy`]. `permissions` is `{connector: [action, ...]}`; `limits` maps an action name, a fully-qualified
/// verb or an alias to a limit string; `budget_model` is "dollars", "risk" or anything else for auto (dollars iff a `$` limit
/// matched); `risk_policy` overrides members of the derived policy (its `weights` merge member by member).
pub struct CompileOptions<'a> {
    pub permissions: &'a Value,
    pub limits: Option<&'a Value>,
    pub catalog: Option<&'a [ActionSpec]>,
    pub budget_model: Option<&'a str>,
    pub risk_policy: Option<&'a Value>,
    pub now: i64,
}

/// The real policy primitives the permissions compile to.
#[derive(Clone, Debug)]
pub struct CompiledPolicy {
    pub predicates: Vec<Value>,
    pub caveats: Vec<Value>,
    /// The wire risk policy (`{weights, theta1, theta2, kappa, lambda, rho, bMax}` plus any override member).
    pub risk_policy: Value,
    pub actions: Vec<ActionSpec>,
    /// "dollars" or "risk".
    pub budget_model: &'static str,
    /// The parsed limits that matched a granted action, by verb (first-match order).
    pub limits: Vec<(String, ParsedLimit)>,
    pub input_limits: Value,
    /// Limits this offline compiler only approximates (a `$N/period` limit is a per-call ceiling plus a one-period lifetime).
    pub approximations: Vec<String>,
}

impl CompiledPolicy {
    /// The reference's shape (`riskPolicy`, `budgetModel`, `inputLimits`, ...).
    pub fn to_json(&self) -> Value {
        let mut limits = Map::new();
        for (v, l) in &self.limits {
            limits.insert(v.clone(), l.to_json());
        }
        json!({"predicates": self.predicates, "caveats": self.caveats, "riskPolicy": self.risk_policy,
            "actions": self.actions.iter().map(ActionSpec::to_json).collect::<Vec<_>>(), "budgetModel": self.budget_model,
            "limits": limits, "inputLimits": self.input_limits, "approximations": self.approximations})
    }
}

/// A JSON number as JavaScript writes it: an integral value within the safe range is an integer.
fn num(x: f64) -> Value {
    if x.is_finite() && x.fract() == 0.0 && x.abs() <= 9_007_199_254_740_991.0 {
        json!(x as i64)
    } else {
        json!(x)
    }
}

fn sev(class: &str) -> i32 {
    match class {
        "reversible" => 0,
        "rate_limited" => 1,
        "irreversible" => 2,
        _ => -1,
    }
}

/// Compile permissions and limits into predicates, caveats and a risk policy. Pure: no keys, no signing.
pub fn compile_policy(o: &CompileOptions) -> Result<CompiledPolicy, String> {
    let builtin;
    let catalog = match o.catalog {
        Some(c) => c,
        None => {
            builtin = builtin_catalog();
            &builtin[..]
        }
    };
    let perms = o.permissions.as_object().ok_or("compilePolicy: permissions must be an object")?;
    let mut actions = vec![];
    for connector in crate::missing_context::js_keys(perms) {
        let acts = perms[connector.as_str()].as_array().ok_or_else(|| format!("compilePolicy: permissions.{connector} must be an array"))?;
        for a in acts {
            let a = a.as_str().ok_or_else(|| format!("compilePolicy: permissions.{connector} must be an array of action names"))?;
            actions.push(spec_for(catalog, &format!("{connector}.{a}")));
        }
    }
    if actions.is_empty() {
        return Err("compilePolicy: no permissions granted".into());
    }
    let empty = Map::new();
    let raw = match o.limits {
        None | Some(Value::Null) => &empty,
        Some(l) => l.as_object().ok_or("compilePolicy: limits must be an object")?,
    };
    // own keys only, read through `??`: a JSON null counts as absent unless it is the last name tried
    let mut limits: Vec<(String, ParsedLimit)> = vec![];
    let mut predicates = vec![];
    for s in &actions {
        let mut r = raw.get(&s.verb);
        if r.is_none_or_null() {
            r = raw.get(&s.action);
        }
        for a in &s.aliases {
            if r.is_none_or_null() {
                r = raw.get(a);
            }
        }
        let lim = match r {
            None => None,
            Some(v) => {
                let p = parse_limit(v.as_str().unwrap_or(""))?;
                match limits.iter().position(|(k, _)| *k == s.verb) {
                    Some(i) => limits[i].1 = p.clone(),
                    None => limits.push((s.verb.clone(), p.clone())),
                }
                Some(p)
            }
        };
        let mut wh = vec![];
        if let Some(l) = lim.as_ref().filter(|l| l.unit == "usd") {
            let Some(f) = &s.amount_field else {
                return Err(format!("compilePolicy: '$' limit on '{}' but the catalog gives that verb no amount field, so the limit could not be enforced", s.verb));
            };
            wh.push(json!({"field": format!("action.params.{f}"), "op": "lte", "value": num(l.amount)}));
            wh.push(json!({"field": format!("action.params.{f}"), "op": "gte", "value": 0}));
        }
        let mut p = json!({"verb": s.verb, "resource": s.resource.clone().unwrap_or_else(|| "*".into())});
        if !wh.is_empty() {
            p["where"] = Value::Array(wh);
        }
        predicates.push(p);
    }
    let mut caveats = vec![];
    let strictest = actions.iter().fold("reversible".to_string(), |acc, s| if sev(&s.reversibility) > sev(&acc) { s.reversibility.clone() } else { acc });
    caveats.push(json!({"type": "reversibility_max", "class": strictest}));
    if let Some(p) = limits.iter().filter_map(|(_, l)| l.period_ms).min() {
        caveats.push(json!({"type": "expires", "at": o.now + p}));
    }
    for (_, l) in limits.iter().filter(|(_, l)| l.unit == "count" && l.period_ms.is_some()) {
        let per = ((l.period_ms.unwrap_or(0) as f64) / 1000.0).round().max(1.0);
        caveats.push(json!({"type": "rate", "max": num(l.amount), "per_secs": num(per)}));
    }
    let dollars: Vec<f64> = limits.iter().filter(|(_, l)| l.unit == "usd").map(|(_, l)| l.amount).collect();
    let model = match o.budget_model {
        Some("dollars") => "dollars",
        Some("risk") => "risk",
        _ if !dollars.is_empty() => "dollars",
        _ => "risk",
    };
    let irreversible = actions.iter().any(|s| s.reversibility == "irreversible");
    let mut rp = if model == "dollars" && !dollars.is_empty() {
        let kappa = dollars.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let b_max: f64 = dollars.iter().sum();
        json!({"weights": {"alpha": 0, "beta": 0, "gamma": 1, "delta": 0, "epsilon": 0, "zeta": 0},
            // within-cap actions auto-approve only when nothing granted is irreversible (a `$` limit never removes a step-up)
            "theta1": if irreversible { json!(0.25) } else { json!(1) }, "theta2": if irreversible { json!(0.6) } else { json!(1) },
            "kappa": if kappa > 0.0 { num(kappa) } else { json!(1) }, "lambda": 0, "rho": 0.5,
            "bMax": if b_max > 0.0 { num(b_max) } else { json!(1) }})
    } else {
        crate::agent::default_risk_policy()
    };
    if let Some(ov) = o.risk_policy.and_then(Value::as_object) {
        let mut weights = rp["weights"].as_object().cloned().unwrap_or_default();
        if let Some(w) = ov.get("weights").and_then(Value::as_object) {
            for (k, v) in w {
                weights.insert(k.clone(), v.clone());
            }
        }
        let m = rp.as_object_mut().ok_or("internal: risk policy")?;
        for (k, v) in ov {
            m.insert(k.clone(), v.clone());
        }
        m.insert("weights".into(), Value::Object(weights));
    }
    if let Some(bad) = validate_risk_policy(&rp) {
        return Err(format!("compilePolicy: derived risk policy invalid: {bad}"));
    }
    let approximations = limits
        .iter()
        .filter(|(_, l)| l.unit == "usd" && l.period_ms.is_some())
        .map(|(v, l)| format!("{v}: ${}/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap", crate::intent_v2::js_number_string(l.amount)))
        .collect();
    Ok(CompiledPolicy { predicates, caveats, risk_policy: rp, actions, budget_model: model, limits, input_limits: Value::Object(raw.clone()), approximations })
}

trait NoneOrNull {
    fn is_none_or_null(&self) -> bool;
}
impl NoneOrNull for Option<&Value> {
    fn is_none_or_null(&self) -> bool {
        self.map_or(true, Value::is_null)
    }
}

// ---- the agent handle -----------------------------------------------------------------------------------------------------

/// Inputs of [`create_agent`]. Build with [`AgentOptions::new`] and set the optional members.
pub struct AgentOptions<'a> {
    /// The principal's key: signs and roots the grant.
    pub principal: &'a KeyPair,
    /// The plaintext goal; only its salted commitment goes in the grant.
    pub goal: &'a str,
    /// `{connector: [action, ...]}`.
    pub permissions: &'a Value,
    /// `{action | verb | alias: "$500/day" | "10/hour" | ...}`.
    pub limits: Option<&'a Value>,
    /// The agent's key; generated when `None`.
    pub holder: Option<KeyPair>,
    pub agent_binding: Option<&'a Value>,
    pub risk_policy: Option<&'a Value>,
    pub budget_model: Option<&'a str>,
    /// The connector catalogue (default: [`builtin_catalog`]).
    pub catalog: Option<Vec<ActionSpec>>,
    /// The default audience of `act`.
    pub aud: Option<&'a str>,
    /// Clock (epoch ms) for minting and the period windows (default: now).
    pub now: Option<i64>,
    /// The provenance mediator; default a fresh recorder for mediator `agent-harness`, kid `k1`. Its pin goes in the grant.
    pub provenance: Option<ProvenanceRecorder>,
    /// The goal salt (b64u); random when `None`. Pass one only to reproduce a grant byte for byte.
    pub goal_salt: Option<&'a str>,
}

impl<'a> AgentOptions<'a> {
    pub fn new(principal: &'a KeyPair, goal: &'a str, permissions: &'a Value) -> AgentOptions<'a> {
        AgentOptions { principal, goal, permissions, limits: None, holder: None, agent_binding: None, risk_policy: None, budget_model: None, catalog: None, aud: None, now: None, provenance: None, goal_salt: None }
    }
}

/// Per-call options of [`AgentHandle::act`].
#[derive(Default, Clone, Debug)]
pub struct ActOptions {
    /// The replay counter; auto-incremented when `None` (an explicit counter raises the auto counter to at least it).
    pub counter: Option<i64>,
    pub aud: Option<String>,
    /// Issued-at (epoch ms); default now.
    pub now: Option<i64>,
    /// Lifetime (default 20 minutes).
    pub ttl_ms: Option<i64>,
    /// No nonce unless given.
    pub nonce: Option<String>,
    /// The agent's uncertainty in [0, 1] (can only raise the server's risk).
    pub caution: Option<f64>,
    /// Override the claimed risk (else from the action spec or the amount).
    pub risk: Option<f64>,
}

/// The local, NON-authoritative pre-check of the grant's own predicates and caveats.
#[derive(Clone, Debug, PartialEq)]
pub struct DryRun {
    pub allowed: bool,
    pub reason: Option<String>,
    /// The tier `admit` assigns under the compiled policy (1 auto, 2, 3 human co-sign).
    pub t: Option<u8>,
}

impl DryRun {
    pub fn to_json(&self) -> Value {
        let mut m = json!({"allowed": self.allowed});
        if let Some(r) = &self.reason {
            m["reason"] = json!(r);
        }
        if let Some(t) = self.t {
            m["t"] = json!(t);
        }
        m
    }
}

/// One built action: the PCActn, its wire encoding (sorted-key JSON), the headers to send (`PCA-Action` and `PCA-Provenance`), the
/// local dry run and the provenance bundle.
#[derive(Clone, Debug)]
pub struct ActResult {
    pub pcactn: Value,
    pub encoded: String,
    pub headers: Vec<(String, String)>,
    pub dry_run: DryRun,
    pub provenance: Value,
}

/// Inputs of [`AgentHandle::sub_agent`].
#[derive(Default)]
pub struct SubAgentOptions {
    /// The sub-agent's key; generated when `None`.
    pub holder: Option<KeyPair>,
    /// Caveats appended on the new hop (default none).
    pub added_caveats: Option<Value>,
}

/// An agent made by [`create_agent`]: the signed grant, the chain, the compiled policy and the holder key that signs actions.
pub struct AgentHandle {
    pub grant: Value,
    /// Root grant first; one more hop per sub-agent.
    pub chain: Vec<Value>,
    /// Opens the grant's goal commitment (keep it with the goal).
    pub goal_salt: String,
    pub policy: CompiledPolicy,
    /// The agent's key: it signs actions and never leaves the client.
    pub holder: KeyPair,
    pub principal_public: String,
    /// The starting trust budget (B = bMax), metered server-side.
    pub budget: TrustBudget,
    /// The most this agent can do between human co-signs (bMax / kappa * kappa).
    pub autonomy_bound: f64,
    catalog: Vec<ActionSpec>,
    rp: RiskPolicy,
    default_aud: Option<String>,
    start_now: i64,
    counter: Mutex<i64>,
    recorder: Arc<Mutex<ProvenanceRecorder>>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn clamp01(x: f64) -> f64 {
    0f64.max(1f64.min(x))
}

/// Build an agent: compile the inputs, mint the grant (its envelope pins the provenance recorder) and return the handle.
pub fn create_agent(o: AgentOptions) -> Result<AgentHandle, String> {
    let now = o.now.unwrap_or_else(now_ms);
    let catalog = o.catalog.unwrap_or_else(builtin_catalog);
    let holder = match o.holder {
        Some(h) => h,
        None => KeyPair::generate()?,
    };
    let policy = compile_policy(&CompileOptions { permissions: o.permissions, limits: o.limits, catalog: Some(&catalog), budget_model: o.budget_model, risk_policy: o.risk_policy, now })?;
    let recorder = match o.provenance {
        Some(r) => r,
        None => ProvenanceRecorder::new("agent-harness", "k1", None)?,
    };
    let env = json!({"predicates": policy.predicates, "caveats": policy.caveats, "agent_binding": o.agent_binding.cloned().unwrap_or_else(|| json!({})),
        "risk_policy": policy.risk_policy, "provenance": {"mediators": [recorder.pin()]}});
    let m = mint_grant(o.principal, &holder.public, &env, o.goal, o.goal_salt, None, &Suite::default())?;
    make(m.grant.clone(), vec![m.grant], m.goal_salt, policy, holder, o.principal.public.clone(), catalog, o.aud.map(String::from), now, Arc::new(Mutex::new(recorder)))
}

#[allow(clippy::too_many_arguments)]
fn make(grant: Value, chain: Vec<Value>, goal_salt: String, policy: CompiledPolicy, holder: KeyPair, principal_public: String, catalog: Vec<ActionSpec>, default_aud: Option<String>, start_now: i64, recorder: Arc<Mutex<ProvenanceRecorder>>) -> Result<AgentHandle, String> {
    let rp = RiskPolicy::from_value(&policy.risk_policy)?;
    let budget = TrustBudget { b: rp.b_max, tau: start_now as f64, as_of: Some(start_now as f64) };
    let autonomy_bound = safety_bound(rp.b_max, rp.kappa) * rp.kappa;
    Ok(AgentHandle { grant, chain, goal_salt, policy, holder, principal_public, budget, autonomy_bound, catalog, rp, default_aud, start_now, counter: Mutex::new(0), recorder })
}

impl AgentHandle {
    fn risk_for(&self, spec: &ActionSpec, params: Option<&Value>, over: Option<f64>) -> f64 {
        if let Some(r) = over {
            return clamp01(r);
        }
        if self.policy.budget_model == "dollars" {
            if let Some(f) = &spec.amount_field {
                let amt = crate::actions::js_to_number(params.and_then(|p| p.get(f.as_str())));
                if amt.is_finite() && self.rp.kappa > 0.0 {
                    return clamp01(amt / self.rp.kappa);
                }
            }
        }
        clamp01(spec.blast_radius)
    }

    /// Offline, non-authoritative pre-check of this grant's predicates and caveats for an action (`now` default: now).
    pub fn dry_run(&self, verb: &str, resource: &str, params: Option<&Value>, now: Option<i64>) -> DryRun {
        let spec = spec_for(&self.catalog, verb);
        let now = now.unwrap_or_else(now_ms);
        let ctx = json!({"action": {"verb": verb, "resource": resource, "params": params.cloned().unwrap_or_else(|| json!({})), "reversibility_class": spec.reversibility}});
        if let Some(reason) = crate::safe_regex::with_regex_budget(|| crate::authorize::envelope_predicates_denial(&self.policy.predicates, &ctx)) {
            return DryRun { allowed: false, reason: Some(reason), t: None };
        }
        // the local handle has no admitted-action history (the server meters it)
        let cctx = json!({"now": now, "blast_radius": num(spec.blast_radius), "reversibility_class": spec.reversibility,
            "delegation_depth": self.chain.len() - 1, "recent_action_times": []});
        let (ok, failed) = crate::evaluate_caveats(&Value::Array(self.policy.caveats.clone()), &cctx);
        if !ok {
            return DryRun { allowed: false, reason: Some(format!("caveat(s) failed: {}", failed.join(", "))), t: None };
        }
        let r = self.risk_for(&spec, params, None);
        DryRun { allowed: true, reason: None, t: Some(admit(r, &self.budget, &self.rp).t) }
    }

    /// Build a proof-carrying action (a one-node plan `n0` committing the catalogue's reversibility and the params digest). It
    /// does not authorize: the resource server's verifier does.
    pub fn act(&self, verb: &str, resource: &str, params: Option<&Value>, o: &ActOptions) -> Result<ActResult, String> {
        let aud = o.aud.as_deref().or(self.default_aud.as_deref()).filter(|a| !a.is_empty()).ok_or("act: aud (resource-server / instance id) is required (pass opts.aud or AgentOptions.aud)")?;
        let spec = spec_for(&self.catalog, verb);
        let node = json!({"id": "n0", "verb": verb, "resource": resource, "reversibility_class": spec.reversibility, "params_digest": params_digest(params)});
        let r = self.risk_for(&spec, params, o.risk);
        let counter = {
            let mut c = self.counter.lock().map_err(|_| "counter lock poisoned".to_string())?;
            match o.counter {
                Some(n) => {
                    *c = (*c).max(n);
                    n
                }
                None => {
                    *c += 1;
                    *c
                }
            }
        };
        let mut extra = Map::new();
        extra.insert("risk_claim".into(), json!({"r": num(r), "inputs": {"blastRadius": num(r)}}));
        if let Some(n) = &o.nonce {
            extra.insert("nonce".into(), json!(n));
        }
        if let Some(c) = o.caution {
            extra.insert("caution".into(), num(c));
        }
        let iat = o.now.unwrap_or_else(now_ms);
        let ttl = o.ttl_ms.unwrap_or(crate::agent::DEFAULT_TTL_MS);
        let pcactn = crate::agent::build_pcactn(&PcactnInput {
            grant: &self.grant, chain: &self.chain, plan: &[node], node_id: "n0", params, counter, signer: &self.holder, aud,
            iat, exp: Some(iat + ttl), extra, suite: Suite::default(),
        })?;
        let op = Operation::new(verb, resource, params.cloned().unwrap_or_else(|| json!({})));
        let provenance = self.recorder.lock().map_err(|_| "provenance recorder lock poisoned".to_string())?.for_action(&op)?;
        let mut headers = pca_headers(&pcactn, &[], None, None);
        headers.push(("PCA-Provenance".into(), encode_provenance_header(&provenance)?));
        Ok(ActResult { encoded: crate::canonicalize(&pcactn), pcactn, headers, dry_run: self.dry_run(verb, resource, params, o.now), provenance })
    }

    /// A sub-agent: a new handle whose chain has one more hop to `holder` (generated when `None`), signed by this agent's key, with
    /// `added_caveats` appended. It shares the policy, catalogue and provenance recorder; its counter starts at 0. Ed25519; for a
    /// sub-agent that signs a post-quantum suite use the low-level `Agent::delegate_pq`.
    pub fn sub_agent(&self, o: SubAgentOptions) -> Result<AgentHandle, String> {
        let sub = match o.holder {
            Some(h) => h,
            None => KeyPair::generate()?,
        };
        let leaf = self.chain.last().ok_or("empty chain")?;
        let child = delegate(leaf, &self.holder, Some(&sub.public), &o.added_caveats.unwrap_or_else(|| json!([])), None, &Suite::default())?;
        let mut chain = self.chain.clone();
        chain.push(child);
        make(self.grant.clone(), chain, self.goal_salt.clone(), self.policy.clone(), sub, self.principal_public.clone(), self.catalog.clone(), self.default_aud.clone(), self.start_now, self.recorder.clone())
    }

    /// The grant as JSON text (transport, inspection).
    pub fn encode_grant(&self) -> String {
        self.grant.to_string()
    }

    /// The shared provenance recorder: record the principal's message and every tool, retrieval or web result that enters the
    /// model's context; `act` appends the action receipt. Keep it out of the model's reach.
    pub fn provenance(&self) -> Arc<Mutex<ProvenanceRecorder>> {
        self.recorder.clone()
    }
}
