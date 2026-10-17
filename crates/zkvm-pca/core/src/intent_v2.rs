//! Intent Layer v2 verification pipeline in the guest (`packages/pca/src/intent-v2.ts`, `decideIntentV2`; conformance README
//! "Intent Layer v2: the verification pipeline", rules 13–18 with V5 layers). After `counter` and `intent` (rule 12), IN THIS
//! ORDER, each check reported only under its condition (absent all of them the decision is the pre-v2 one):
//!
//! | check            | reported iff                                                                         | rule |
//! | `schema`         | the PCActn carries `intent_session`, or `policy.schema.closed_world === true`        | 14 |
//! | `intent_session` | the PCActn carries `intent_session`, or `policy.session.require === true`            | 13 |
//! | `layers`         | the PCActn carries `intent_session` and the verifier configured `layers`             | V5 |
//! | `accumulators`   | the PCActn carries `intent_session`                                                  | 15 |
//! | `facts`, `provenance`, `classes` | the PCActn carries `intent_session` and W-B reports them (first failure ends W-B) | 16–18 |
//!
//! Checks 1–4 are independent; `allow` needs every reported check. The decision also returns the verifier-computed predicate
//! env (`canon` when `schema` passed, `acc` / `mon` when `accumulators` passed, `world` / `prov` / `class` when W-B did not
//! deny), which REPLACES the host-supplied members of those names in the admitting root's predicate env.
//!
//! In the guest the whole verifier state `ctx` (= TS `IntentV2Context`: policy, params, schema docs + keys, session root +
//! grants + revocation evidence, layers, accumulator state / monitors / receipts / last_seq, W-B artifacts + policy) is a
//! PROVER INPUT; its `hashCanonical` digest is committed to the journal and the relying party pins it to its own state
//! (`ExpectedContext::intent_v2_ctx_digest`), so a receipt proves the checks under exactly the verifier's state and policy.
use crate::commit::hash_canonical;
use serde_json::{Map, Value};

pub const V2_ENV_MEMBERS: [&str; 6] = ["acc", "mon", "canon", "world", "prov", "class"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2Check {
    pub name: &'static str,
    pub ok: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct V2Decision {
    pub checks: Vec<V2Check>,
    /// The verifier-computed env members (only those that were computed).
    pub env: Map<String, Value>,
}

impl V2Decision {
    pub fn all_ok(&self) -> bool {
        self.checks.iter().all(|c| c.ok)
    }
}

fn get<'a>(v: Option<&'a Value>, path: &[&str]) -> Option<&'a Value> {
    let mut cur = v?;
    for k in path {
        cur = cur.get(*k)?;
    }
    Some(cur)
}

/// TS `String(x)` for the wire-validated string members (`verb`, `resource`, `aud`); anything else renders like JS would for
/// the cases a wire-valid PCActn can carry (strings only), and `undefined` otherwise.
fn js_str(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        other => crate::canonical::js_string(other),
    }
}

fn is_obj(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Object(_)))
}

fn opt_obj(v: Option<&Value>) -> bool {
    matches!(v, None | Some(Value::Object(_)))
}
fn opt_arr(v: Option<&Value>) -> bool {
    matches!(v, None | Some(Value::Array(_)))
}

/// `intentV2ContextError(ctx)` (strict pass, rules 13-18): ABSENT members mean empty / default; a member PRESENT with `null` or
/// of the wrong JSON type is malformed and fails closed (incl. the members passed through to `layers` and W-B).
pub fn intent_v2_context_error(ctx: Option<&Value>) -> Option<String> {
    let c = match ctx {
        None => return None,
        Some(Value::Object(c)) => c,
        Some(_) => return Some("the v2 verifier context must be an object".into()),
    };
    let pol = c.get("policy");
    if !opt_obj(pol) {
        return Some("policy must be an object".into());
    }
    if let Some(Value::Object(pr)) = pol {
        // closed member sets; every flag a JSON boolean, every number a non-negative safe integer (absent = default)
        if let Some(k) = pr.keys().find(|k| *k != "session" && *k != "schema" && *k != "acc" && *k != "map") {
            return Some(format!("policy: unknown member '{k}'"));
        }
        let ps = pr.get("session");
        if !opt_obj(ps) {
            return Some("policy.session must be an object".into());
        }
        if let Some(Value::Object(o)) = ps {
            if let Some(k) = o.keys().find(|k| *k != "require" && *k != "max_revocation_age_s") {
                return Some(format!("policy.session: unknown member '{k}'"));
            }
            if o.get("require").is_some_and(|v| !v.is_boolean()) {
                return Some("policy.session.require must be a boolean".into());
            }
            if o.get("max_revocation_age_s").is_some_and(|v| crate::jsnum::non_neg(v).is_none()) {
                return Some("policy.session.max_revocation_age_s must be a non-negative safe integer".into());
            }
        }
        let pc = pr.get("schema");
        if !opt_obj(pc) {
            return Some("policy.schema must be an object".into());
        }
        if let Some(Value::Object(o)) = pc {
            if let Some(k) = o.keys().find(|k| *k != "closed_world") {
                return Some(format!("policy.schema: unknown member '{k}'"));
            }
            if o.get("closed_world").is_some_and(|v| !v.is_boolean()) {
                return Some("policy.schema.closed_world must be a boolean".into());
            }
        }
        let pa = pr.get("acc");
        if !opt_obj(pa) {
            return Some("policy.acc must be an object".into());
        }
        if let Some(Value::Object(o)) = pa {
            if let Some(k) = o.keys().find(|k| *k != "max_receipt_age_s" && *k != "max_keyset_age_s") {
                return Some(format!("policy.acc: unknown member '{k}'"));
            }
            for k in ["max_receipt_age_s", "max_keyset_age_s"] {
                if o.get(k).is_some_and(|v| crate::jsnum::non_neg(v).is_none()) {
                    return Some(format!("policy.acc.{k} must be a non-negative safe integer"));
                }
            }
        }
        let pm = pr.get("map");
        if !opt_obj(pm) {
            return Some("policy.map must be an object".into());
        }
        if let Some(Value::Object(o)) = pm {
            if let Some(k) = o.keys().find(|k| *k != "require" && *k != "max_residual_risk_ppm") {
                return Some(format!("policy.map: unknown member '{k}'"));
            }
            if o.get("require").is_some_and(|v| !v.is_boolean()) {
                return Some("policy.map.require must be a boolean".into());
            }
            if o.get("max_residual_risk_ppm").is_some_and(|v| crate::jsnum::non_neg(v).is_none()) {
                return Some("policy.map.max_residual_risk_ppm must be a non-negative safe integer".into());
            }
        }
    }
    if !opt_obj(c.get("params")) {
        return Some("params must be an object".into());
    }
    for k in ["schema", "session", "acc"] {
        if !opt_obj(c.get(k)) {
            return Some(format!("{k} must be an object"));
        }
    }
    match c.get("map") {
        None => {}
        Some(Value::Object(m)) => {
            if let Some(k) = m.keys().find(|k| *k != "disclosure") {
                return Some(format!("map: unknown member '{k}'"));
            }
        }
        Some(_) => return Some("map must be an object".into()),
    }
    if let Some(l) = c.get("layers") {
        let l = match l {
            Value::Object(l) => l,
            _ => return Some("layers must be an object".into()),
        };
        for (k, v) in l {
            if !["org", "site", "std"].contains(&k.as_str()) {
                return Some(format!("layers: unknown member '{k}'"));
            }
            if !(v.is_object() && v.get("predicates").is_some_and(Value::is_array)) {
                return Some(format!("layers.{k} must be {{predicates: [...]}}"));
            }
        }
    }
    if let Some(wb) = c.get("wb") {
        let wb = match wb {
            Value::Object(w) => w,
            _ => return Some("wb must be an object".into()),
        };
        let a = wb.get("artifacts");
        if !opt_obj(a) {
            return Some("wb.artifacts must be an object".into());
        }
        if let Some(a) = a {
            for k in ["facts", "labels", "verdicts"] {
                if !opt_arr(a.get(k)) {
                    return Some(format!("wb.artifacts.{k} must be an array"));
                }
            }
            if !opt_obj(a.get("offer_set")) {
                return Some("wb.artifacts.offer_set must be an object".into());
            }
        }
        let p = wb.get("policy");
        if !opt_obj(p) {
            return Some("wb.policy must be an object".into());
        }
        if let Some(p) = p {
            if !opt_obj(p.get("world")) || !opt_obj(p.get("provenance")) {
                return Some("wb.policy.world / provenance must be objects".into());
            }
            if !opt_arr(p.get("classifiers")) {
                return Some("wb.policy.classifiers must be an array".into());
            }
        }
    }
    None
}

/// `schemaCtxError`: a present schema context is `{docs: [...], keys: [...]}`.
pub(crate) fn schema_ctx_error(ctx: Option<&Value>) -> Option<String> {
    match get(ctx, &["schema"]) {
        None => None,
        Some(sc) if sc.is_object() && sc.get("docs").is_some_and(Value::is_array) && sc.get("keys").is_some_and(Value::is_array) => None,
        Some(_) => Some("the schema context must be {docs: [...], keys: [...]}".into()),
    }
}

/// `isSafeInt(now)`: the verifier clock must be a safe integer (epoch ms), not -0.
fn clock_ok(now: f64) -> bool {
    now.is_finite() && now.fract() == 0.0 && now.abs() <= crate::jsnum::MAX_SAFE_INT as f64 && !(now == 0.0 && now.is_sign_negative())
}

/// Rule 14 (`schema`, TS `schemaStep`): the matched schema document on success.
fn schema_step<'a>(p: &Value, ctx: Option<&'a Value>) -> Result<&'a Value, String> {
    if let Some(e) = schema_ctx_error(ctx) {
        return Err(e);
    }
    let docs = match get(ctx, &["schema", "docs"]).and_then(|d| d.as_array()) {
        Some(d) if !d.is_empty() => d,
        _ => return Err("this verifier has no action schema configured".into()),
    };
    let doc = match p.get("intent_session") {
        Some(is) => {
            let want = is.get("schema");
            docs.iter()
                .find(|d| crate::action_schema::action_schema_digest(d).as_ref().map(|x| Value::String(x.clone())).as_ref() == want)
                .ok_or("intent_session.schema names no schema this verifier accepts")?
        }
        None => &docs[0],
    };
    let keys = get(ctx, &["schema", "keys"]).cloned().unwrap_or(Value::Array(vec![]));
    crate::action_schema::verify_action_schema(doc, &keys).map_err(|r| format!("schema does not verify: {r}"))?;
    if doc.get("aud") != p.get("aud") {
        return Err("schema aud does not match the PCActn aud".into());
    }
    let params = get(ctx, &["params"]);
    if !is_obj(params) {
        return Err("no plaintext params to check against the schema (closed world needs them)".into());
    }
    let params = params.unwrap_or(&Value::Null);
    let pd = p.get("action").and_then(|a| a.get("params_digest"));
    if pd != Some(&Value::String(hash_canonical(params))) {
        return Err("params do not hash to action.params_digest".into());
    }
    let verb = js_str(p.get("action").and_then(|a| a.get("verb")));
    crate::action_schema::conform_action(doc, &verb, params).map_err(|c| format!("schema_violation: {}: {}", c.code, c.reason))?;
    Ok(doc)
}

/// `decideIntentV2(p, grant, ctx, now)`. Total.
pub fn decide_intent_v2(p: &Value, grant: &Value, ctx: Option<&Value>, now: f64) -> V2Decision {
    let mut out = V2Decision::default();
    let present = p.get("intent_session").is_some();
    let policy = get(ctx, &["policy"]);
    // strict pass: a malformed verifier context fails closed: every v2 check that could be reported fails with the reason
    if let Some(e) = intent_v2_context_error(ctx) {
        let committed = present && p.get("intent_session").and_then(|is| is.get("map_form")) == Some(&Value::String("commit".into()));
        let names: &[&'static str] = match (present, committed) {
            (true, true) => &["schema", "intent_session", "accumulators", "map"],
            (true, false) => &["schema", "intent_session", "accumulators"],
            _ => &["schema", "intent_session"],
        };
        for name in names {
            out.checks.push(V2Check { name, ok: false, reason: Some(format!("malformed v2 context: {e}")) });
        }
        return out;
    }
    // the verifier clock must be a safe integer: every check run through `push` fails otherwise (W-B applies its own rule)
    let clock = clock_ok(now);
    let push = |out: &mut V2Decision, name: &'static str, r: Result<(), String>| {
        let r = if clock { r } else { Err("the verifier clock is not a safe integer (fail closed)".to_string()) };
        out.checks.push(match r {
            Ok(()) => V2Check { name, ok: true, reason: None },
            Err(reason) => V2Check { name, ok: false, reason: Some(reason) },
        });
    };
    let verb = js_str(p.get("action").and_then(|a| a.get("verb")));
    let params_v = get(ctx, &["params"]);

    // 1. schema
    if present || get(policy, &["schema", "closed_world"]) == Some(&Value::Bool(true)) {
        // a bad clock fails every run check WITHOUT evaluating it (TS `run`): no env member is computed
        match if clock { schema_step(p, ctx) } else { Err(String::new()) } {
            Ok(doc) => {
                let canon = crate::action_schema::canon_projection(doc, &verb, params_v.unwrap_or(&Value::Null));
                out.env = Map::new();
                out.env.insert("canon".into(), Value::Object(canon));
                push(&mut out, "schema", Ok(()));
            }
            Err(r) => push(&mut out, "schema", Err(r)),
        }
    }
    // 2. intent_session
    if present || get(policy, &["session", "require"]) == Some(&Value::Bool(true)) {
        let r = crate::intent_session::session_step(p, grant, ctx, now);
        push(&mut out, "intent_session", r);
    }
    let map_active = p.get("intent_session").and_then(|is| is.get("map_form")) == Some(&Value::String("commit".into()))
        || get(policy, &["map", "require"]) == Some(&Value::Bool(true));
    let action = {
        let mut a = Map::new();
        a.insert("verb".into(), Value::String(verb.clone()));
        a.insert("resource".into(), Value::String(js_str(p.get("action").and_then(|a| a.get("resource")))));
        a.insert("params".into(), if is_obj(params_v) { params_v.cloned().unwrap_or_default() } else { Value::Object(Map::new()) });
        Value::Object(a)
    };
    // 3. layers
    if present {
        if let Some(layers) = get(ctx, &["layers"]) {
            let mut env = Map::new();
            if let Some(c) = out.env.get("canon") {
                env.insert("canon".into(), c.clone());
            }
            let mut root = Map::new();
            root.insert("action".into(), action.clone());
            root.insert("env".into(), Value::Object(env));
            let r = crate::intent_layers::decide_layer_ceilings(layers, &Value::Object(root)).map_err(|(_, reason)| reason);
            push(&mut out, "layers", r);
        }
    }
    if present {
        // 4. accumulators
        let r = crate::intent_session::bound_root(p, ctx, now).and_then(|s| {
            let schema_doc = p.get("intent_session").and_then(|is| is.get("schema")).and_then(|want| {
                get(ctx, &["schema", "docs"])
                    .and_then(|d| d.as_array())
                    .and_then(|docs| docs.iter().find(|d| crate::action_schema::action_schema_digest(d).as_deref() == want.as_str()))
            });
            crate::intent_acc::acc_step(p, s, ctx, now, schema_doc)
        });
        match r {
            Ok(env) if clock => {
                out.env.insert("acc".into(), Value::Object(env.acc));
                out.env.insert("mon".into(), Value::Object(env.mon));
                push(&mut out, "accumulators", Ok(()));
            }
            r => push(&mut out, "accumulators", r.map(|_| ())),
        }
        // 4a. map (rule 19)
        if map_active {
            push(&mut out, "map", map_step(p, ctx));
        }
        // 5-7. W-B
        let is = p.get("intent_session").cloned().unwrap_or(Value::Null);
        let mut input = Map::new();
        input.insert("now".into(), serde_json::Number::from_f64(now).map(Value::Number).unwrap_or(Value::Null));
        input.insert("aud".into(), Value::String(js_str(p.get("aud"))));
        input.insert("session".into(), is.get("session").cloned().unwrap_or(Value::Null));
        input.insert("action".into(), action.clone());
        input.insert("intent_session".into(), is.clone());
        if let Some(a) = get(ctx, &["wb", "artifacts"]) {
            input.insert("artifacts".into(), a.clone());
        }
        input.insert("policy".into(), get(ctx, &["wb", "policy"]).cloned().unwrap_or(Value::Object(Map::new())));
        let wb = crate::oracle_facts::decide_intent_wb(&Value::Object(input));
        for (name, status) in &wb.checks {
            let name: &'static str = match name.as_str() {
                "facts" => "facts",
                "provenance" => "provenance",
                "classes" => "classes",
                _ => continue,
            };
            let r = match status.as_str() {
                "pass" => Ok(()),
                "question" => Err(format!("intent_required: {}", wb.reason.clone().unwrap_or_else(|| "a question is required".into()))),
                _ => Err(wb.reason.clone().unwrap_or_else(|| "rejected".into())),
            };
            push(&mut out, name, r);
        }
        if wb.outcome != "deny" {
            for k in ["world", "prov", "class"] {
                if let Some(v) = wb.env.get(k) {
                    out.env.insert(k.into(), v.clone());
                }
            }
        }
    } else if map_active {
        push(&mut out, "map", map_step(p, ctx));
    }
    out
}

/// Rule 19 (`map`, V15 Z0 / Z1): the action's cell is inside the committed grant and the committed residual risk is at
/// most ε. The disclosure is a private guest input (not in [`ctx_digest`]).
fn map_step(p: &Value, ctx: Option<&Value>) -> Result<(), String> {
    if p.get("intent_session").and_then(|is| is.get("map_form")) != Some(&Value::String("commit".into())) {
        return Err("this verifier requires a committed map (intent_session.map_form \"commit\")".into());
    }
    let Some(intent) = p.get("intent") else { return Err("a committed map needs the envelope.intent binding".into()) };
    let Some(disclosure) = get(ctx, &["map", "disclosure"]) else { return Err("no disclosure of the committed map was presented".into()) };
    let eps = get(ctx, &["policy", "map", "max_residual_risk_ppm"]).and_then(crate::jsnum::safe_int);
    crate::intent_map::decide_map_disclosure(intent.get("map_digest"), p.get("action"), get(ctx, &["params"]), disclosure, eps).map(|_| ())
}

/// The digest of the verifier's v2 state the journal pins: `hashCanonical` of the context WITHOUT its `map` member (the
/// agent's map disclosure is a private input of the Z1 proof; ε stays pinned through `policy.map`).
pub fn ctx_digest(ctx: &Value) -> String {
    match ctx {
        Value::Object(o) if o.contains_key("map") => {
            let mut c = o.clone();
            c.remove("map");
            hash_canonical(&Value::Object(c))
        }
        _ => hash_canonical(ctx),
    }
}

/// `v2Env` (server/verify.ts): the predicate env of the admitting root. Without `intent_session` it is the host's env
/// unchanged; with it, the host's members named `acc`, `mon`, `canon`, `world`, `prov`, `class` are dropped and the
/// verifier-computed ones (if computed) put in their place.
pub fn v2_env(host_env: Option<&Value>, p: &Value, d: &V2Decision) -> Option<Value> {
    if p.get("intent_session").is_none() {
        return host_env.cloned();
    }
    let mut rest = match host_env {
        Some(Value::Object(o)) => o.clone(),
        _ => Map::new(),
    };
    for k in V2_ENV_MEMBERS {
        rest.remove(k);
    }
    for (k, v) in &d.env {
        rest.insert(k.clone(), v.clone());
    }
    Some(Value::Object(rest))
}

/// True iff any v2 check would be reported (`intentV2Active`).
pub fn intent_v2_active(p: &Value, ctx: Option<&Value>) -> bool {
    p.get("intent_session").is_some()
        || get(ctx, &["policy", "schema", "closed_world"]) == Some(&Value::Bool(true))
        || get(ctx, &["policy", "session", "require"]) == Some(&Value::Bool(true))
        || get(ctx, &["policy", "map", "require"]) == Some(&Value::Bool(true))
}
