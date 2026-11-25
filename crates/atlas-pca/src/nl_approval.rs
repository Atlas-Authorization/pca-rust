//! Generate-then-review for natural-language policy (`packages/pca/src/nl.ts`, the approval half). The model is injected as a
//! `complete(prompt) -> answer` closure (no client, no network) and its output is only ever a DRAFT. A draft becomes policy
//! only after a reviewer whose key YOU pinned signs the exact compiled policy (`approve_draft`); `load_approved_policy` and
//! `agent_from_approved_nl` re-derive everything from the draft contents (they trust nothing the draft says about itself).
//! NOT GUARANTEED: that the model understood the instruction, or that the reviewer read the draft.
use crate::agent::KeyPair;
use crate::facade::{builtin_catalog, compile_policy, create_agent, ActionSpec, AgentHandle, AgentOptions, CompileOptions};
use crate::hash::canonical_bytes_lenient;
use crate::nl_policy::{nl_prompt, parse_nl_policy};
use crate::policy_sim::lint_compiled_policy;
use crate::{b64_encode, hash_canonical, verify_b64u};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Map, Value};

pub const NL_APPROVAL_DOMAIN: &str = "atlas-pca/nl-approval/v1\0";
/// Domain of an approval v2 (binds the instruction, model and prompt).
pub const NL_APPROVAL_DOMAIN_V2: &str = "atlas-pca/nl-approval/v2\0";
/// Model output larger than this (UTF-8 bytes) is refused outright.
pub const MAX_NL_OUTPUT_BYTES: usize = 16_384;
/// An approval may not be valid for longer than this.
pub const MAX_NL_APPROVAL_TTL_MS: i64 = 24 * 3_600_000;
const DEFAULT_NL_APPROVAL_TTL_MS: i64 = 3_600_000;

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

/// A JSON number for a finite double: an integer member prints without a fraction.
fn js_number(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 {
        json!(f as i64)
    } else {
        serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)
    }
}

/// JavaScript truthiness of a JSON value.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null | Value::Bool(false) => false,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        _ => true,
    }
}

/// UTF-16 code-unit order (the JS default `sort`).
fn js_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Digest of the catalog vocabulary a draft was grounded against (verbs, reversibility, amount field).
pub fn catalog_digest(catalog: &[ActionSpec]) -> String {
    let mut rows: Vec<(String, Value)> = catalog.iter().map(|s| (s.verb.clone(), json!([s.verb, s.reversibility, s.amount_field]))).collect();
    rows.sort_by(|a, b| js_cmp(&a.0, &b.0));
    hash_canonical(&json!({ "v": 1, "rows": rows.into_iter().map(|r| r.1).collect::<Vec<_>>() }))
}

/// What approval v2 adds to a draft digest: the instruction text, the model id and the exact prompt. Recomputed from public inputs.
pub fn draft_binding(instruction: &str, catalog: &[ActionSpec], model: Option<&str>) -> Value {
    json!({
        "instruction_digest": hash_canonical(&json!({ "d": "atlas-pca/nl-instruction/v1", "text": instruction })),
        "model": model,
        "prompt_digest": hash_canonical(&json!({ "d": "atlas-pca/nl-prompt/v1", "text": nl_prompt(instruction, catalog) })),
    })
}

/// `permissions` with every connector's actions sorted (the digest is order-insensitive). `Err` when an entry is not an array.
fn sorted_permissions(permissions: &Value) -> Result<Value, String> {
    let m = permissions.as_object().ok_or("permissions is not an object")?;
    let mut keys: Vec<&String> = m.keys().collect();
    keys.sort_by(|a, b| js_cmp(a, b));
    let mut out = Map::new();
    for c in keys {
        // a spread of a string is its characters (the reference spreads whatever it is given)
        let mut l: Vec<Value> = match &m[c] {
            Value::Array(a) => a.clone(),
            Value::String(t) => t.chars().map(|ch| Value::String(ch.to_string())).collect(),
            _ => return Err("actions is not iterable".into()),
        };
        l.sort_by(|a, b| js_cmp(&crate::intent_v2::js_value_string(a), &crate::intent_v2::js_value_string(b)));
        out.insert(c.clone(), Value::Array(l));
    }
    Ok(Value::Object(out))
}

/// Digest an approval v2 signs: the v1 content PLUS `{instruction_digest, model, prompt_digest}`.
pub fn draft_digest_v2(permissions: &Value, limits: &Value, catalog_digest: &str, binding: &Value) -> Result<String, String> {
    Ok(hash_canonical(&json!({
        "v": 2, "permissions": sorted_permissions(permissions)?, "limits": limits, "catalog_digest": catalog_digest,
        "instruction_digest": binding["instruction_digest"], "model": binding["model"], "prompt_digest": binding["prompt_digest"],
    })))
}

/// Digest a v1 (pre-0.5) reviewer signed: `{permissions, limits, catalog digest}`. Kept so old approvals still load.
pub fn draft_digest(permissions: &Value, limits: &Value, catalog_digest: &str) -> Result<String, String> {
    Ok(hash_canonical(&json!({ "v": 1, "permissions": sorted_permissions(permissions)?, "limits": limits, "catalog_digest": catalog_digest })))
}

fn lints_of(permissions: &Value, limits: &Value, catalog: &[ActionSpec]) -> Result<Vec<Value>, String> {
    if permissions.as_object().is_none_or(Map::is_empty) {
        return Ok(vec![]);
    }
    let cp = compile_policy(&CompileOptions { permissions, limits: Some(limits), catalog: Some(catalog), budget_model: None, risk_policy: None, now: 0 })?;
    Ok(lint_compiled_policy(&cp, catalog))
}

/// `policyFromNL`: ask the model, ground its answer against the catalog and lint the compiled result. `{permissions, limits,
/// unknownVerbs, droppedLimits, raw, lints}`.
pub fn policy_from_nl(instruction: &str, complete: &dyn Fn(&str) -> Result<String, String>, catalog: Option<&[ActionSpec]>) -> Result<Value, String> {
    let builtin;
    let catalog = match catalog {
        Some(c) => c,
        None => {
            builtin = builtin_catalog();
            &builtin
        }
    };
    let raw = complete(&nl_prompt(instruction, catalog))?;
    let mut parsed = parse_nl_policy(&raw, catalog);
    let lints = lints_of(&parsed["permissions"], &parsed["limits"], catalog)?;
    parsed["raw"] = json!(raw);
    parsed["lints"] = Value::Array(lints);
    Ok(parsed)
}

/// `draftPolicyFromNL`: ask the model for a DRAFT (never enforced). Err if the model output is oversize.
pub fn draft_policy_from_nl(
    instruction: &str,
    complete: &dyn Fn(&str) -> Result<String, String>,
    catalog: Option<&[ActionSpec]>,
    model: Option<&str>,
) -> Result<Value, String> {
    let builtin;
    let catalog = match catalog {
        Some(c) => c,
        None => {
            builtin = builtin_catalog();
            &builtin
        }
    };
    let raw = complete(&nl_prompt(instruction, catalog))?;
    if raw.len() > MAX_NL_OUTPUT_BYTES {
        return Err(format!("draftPolicyFromNL: model output exceeds {MAX_NL_OUTPUT_BYTES} bytes or is not a string"));
    }
    let p = parse_nl_policy(&raw, catalog);
    let lints = lints_of(&p["permissions"], &p["limits"], catalog)?;
    let cd = catalog_digest(catalog);
    let binding = draft_binding(instruction, catalog, model);
    let digest = draft_digest_v2(&p["permissions"], &p["limits"], &cd, &binding)?;
    let analyzer_ok = p["permissions"].as_object().is_some_and(|m| !m.is_empty()) && !lints.iter().any(|l| l["level"] == "error");
    Ok(json!({
        "status": "draft", "instruction": instruction, "permissions": p["permissions"], "limits": p["limits"], "catalog_digest": cd,
        "binding": binding, "digest": digest, "unknownVerbs": p["unknownVerbs"], "droppedLimits": p["droppedLimits"], "lints": lints, "analyzerOk": analyzer_ok,
    }))
}

fn approval_message(a: &Value, v: i64) -> Vec<u8> {
    let mut m = (if v == 2 { NL_APPROVAL_DOMAIN_V2 } else { NL_APPROVAL_DOMAIN }).as_bytes().to_vec();
    m.extend(canonical_bytes_lenient(&json!({
        "v": v, "digest": a["digest"], "catalog_digest": a["catalog_digest"], "reviewer": a["reviewer"], "approved_at": a["approved_at"], "expires_at": a["expires_at"],
    })));
    m
}

fn sign_approval(body: Value, v: i64, seed: &[u8]) -> Result<Value, String> {
    let sk = SigningKey::from_bytes(&<[u8; 32]>::try_from(seed).map_err(|_| "approveDraft: reviewer secret must be a 32-byte seed".to_string())?);
    let sig = sk.sign(&approval_message(&body, v)).to_bytes();
    let mut out = body;
    out["sig"] = json!(b64_encode(&sig));
    Ok(out)
}

/// `approveDraft`: the human step: sign the exact draft with the reviewer's 32-byte Ed25519 seed. Refuses a draft the analyzer rejects.
pub fn approve_draft(draft: &Value, reviewer_secret: &[u8], now: Option<f64>, ttl_ms: Option<f64>) -> Result<Value, String> {
    if !truthy(&draft["analyzerOk"]) {
        return Err("approveDraft: the draft did not pass the static analyzer".into());
    }
    // `draft.unknownVerbs.length > 0`: an array or string by its length, anything else has none, a missing list is a TypeError
    let proposed = match &draft["unknownVerbs"] {
        Value::Array(l) => !l.is_empty(),
        Value::String(t) => !t.is_empty(),
        Value::Null => return Err("Cannot read properties of undefined (reading 'length')".into()),
        _ => false,
    };
    if proposed {
        return Err("approveDraft: the draft proposed verbs that are not in the catalog".into());
    }
    let now = now.unwrap_or_else(|| now_ms() as f64);
    let ttl = ttl_ms.unwrap_or(DEFAULT_NL_APPROVAL_TTL_MS as f64);
    if !now.is_finite() || !ttl.is_finite() || ttl <= 0.0 || ttl > MAX_NL_APPROVAL_TTL_MS as f64 {
        return Err("approveDraft: invalid time or ttl".into());
    }
    let reviewer = b64_encode(
        SigningKey::from_bytes(&<[u8; 32]>::try_from(reviewer_secret).map_err(|_| "approveDraft: reviewer secret must be a 32-byte seed".to_string())?)
            .verifying_key()
            .as_bytes(),
    );
    let body = json!({ "v": 2, "digest": draft["digest"], "catalog_digest": draft["catalog_digest"], "reviewer": reviewer, "approved_at": js_number(now), "expires_at": js_number(now + ttl) });
    sign_approval(body, 2, reviewer_secret)
}

/// `approveDraftLegacyV1` (deprecated): the pre-0.5 approval that signs the draft WITHOUT the instruction, model or prompt. Only for
/// the legacy-load compatibility window.
pub fn approve_draft_legacy_v1(draft: &Value, reviewer_secret: &[u8], now: Option<f64>, ttl_ms: Option<f64>) -> Result<Value, String> {
    let v2 = approve_draft(draft, reviewer_secret, now, ttl_ms)?;
    let digest = draft_digest(&draft["permissions"], &draft["limits"], draft["catalog_digest"].as_str().unwrap_or(""))?;
    let body = json!({ "v": 1, "digest": digest, "catalog_digest": draft["catalog_digest"], "reviewer": v2["reviewer"], "approved_at": v2["approved_at"], "expires_at": v2["expires_at"] });
    sign_approval(body, 1, reviewer_secret)
}

fn fail(reason: &str) -> Value {
    json!({ "ok": false, "reason": reason })
}

fn is_int(v: &Value) -> bool {
    v.as_f64().is_some_and(|f| f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 && !(f == 0.0 && f.is_sign_negative()))
}

fn is_str(v: &Value) -> bool {
    v.is_string()
}

/// Options of [`load_approved_policy`]: the pinned reviewer keys (empty: everything is refused), the catalog (default: built-in) and the clock.
pub struct LoadApprovedOptions<'a> {
    pub reviewers: &'a [String],
    pub catalog: Option<&'a [ActionSpec]>,
    pub now: Option<f64>,
}

/// `loadApprovedPolicy`: the only door from a draft to policy. Recomputes digest, grounding and lints from the draft contents; never
/// panics. `{ok: true, permissions, limits, reviewer, instruction, legacy_unbound_instruction}` or `{ok: false, reason}`.
pub fn load_approved_policy(draft: &Value, approval: &Value, opts: &LoadApprovedOptions) -> Value {
    load_inner(draft, approval, opts).unwrap_or_else(|_| fail("malformed_approval"))
}

fn load_inner(draft: &Value, a: &Value, opts: &LoadApprovedOptions) -> Result<Value, String> {
    let builtin;
    let catalog = match opts.catalog {
        Some(c) => c,
        None => {
            builtin = builtin_catalog();
            &builtin
        }
    };
    let now = opts.now.unwrap_or_else(|| now_ms() as f64);
    if opts.reviewers.is_empty() {
        return Ok(fail("no_reviewers_pinned"));
    }
    let (perms, limits) = (&draft["permissions"], &draft["limits"]);
    if draft["status"] != json!("draft") || !(perms.is_object() || perms.is_array()) || !(limits.is_object() || limits.is_array()) {
        return Ok(fail("not_a_draft"));
    }
    let cd = catalog_digest(catalog);
    if draft["catalog_digest"].as_str() != Some(cd.as_str()) {
        return Ok(fail("catalog_mismatch"));
    }
    let Some(instruction) = draft["instruction"].as_str() else { return Ok(fail("not_a_draft")) };
    let legacy_draft = draft.get("binding").is_none();
    if !legacy_draft && !draft["binding"].is_object() && !draft["binding"].is_array() {
        return Ok(fail("not_a_draft"));
    }
    let draft_digest_s = draft["digest"].as_str();
    if legacy_draft {
        if Some(draft_digest(perms, limits, &cd)?.as_str()) != draft_digest_s {
            return Ok(fail("tampered_draft"));
        }
    } else {
        let b = &draft["binding"];
        let binding = draft_binding(instruction, catalog, b.get("model").and_then(Value::as_str));
        let same = |k: &str| b.get(k).is_some_and(|x| *x == binding[k]);
        if !same("instruction_digest") || !same("prompt_digest") || !same("model") {
            return Ok(fail("tampered_draft"));
        }
        if Some(draft_digest_v2(perms, limits, &cd, &binding)?.as_str()) != draft_digest_s {
            return Ok(fail("tampered_draft"));
        }
    }
    // re-ground: every verb must be in the catalog and every limit parse, regardless of what the draft claims
    for (c, acts) in perms.as_object().into_iter().flatten() {
        let Some(l) = acts.as_array() else { return Ok(fail("unknown_verbs")) };
        if l.iter().any(|x| x.as_str().is_none_or(|s| !catalog.iter().any(|e| e.verb == format!("{c}.{s}")))) {
            return Ok(fail("unknown_verbs"));
        }
    }
    if draft["unknownVerbs"].as_array().is_some_and(|l| !l.is_empty()) {
        return Ok(fail("unknown_verbs"));
    }
    if perms.as_object().is_none_or(Map::is_empty) {
        return Ok(fail("empty_permissions"));
    }
    if lints_of(perms, limits, catalog)?.iter().any(|l| l["level"] == "error") {
        return Ok(fail("analyzer_error"));
    }
    let v = a["v"].as_f64();
    if !a.is_object()
        || !matches!(v, Some(x) if x == 1.0 || x == 2.0)
        || !is_str(&a["sig"])
        || !is_str(&a["reviewer"])
        || !is_str(&a["digest"])
        || !is_str(&a["catalog_digest"])
        || !is_int(&a["approved_at"])
        || !is_int(&a["expires_at"])
    {
        return Ok(fail("malformed_approval"));
    }
    let legacy = v == Some(1.0);
    if legacy_draft && !legacy {
        return Ok(fail("digest_mismatch")); // a v2 approval promises the instruction is bound; a binding-less draft cannot honor that
    }
    // v1 signed the digest without the binding: recompute it from the (already verified) contents
    let want = if legacy { draft_digest(perms, limits, &cd)? } else { draft_digest_s.unwrap_or("").to_string() };
    if a["digest"].as_str() != Some(want.as_str()) || a["catalog_digest"].as_str() != Some(cd.as_str()) {
        return Ok(fail("digest_mismatch"));
    }
    let reviewer = a["reviewer"].as_str().unwrap_or("");
    if !opts.reviewers.iter().any(|r| r == reviewer) {
        return Ok(fail("reviewer_not_pinned"));
    }
    let (approved, expires) = (a["approved_at"].as_f64().unwrap_or(0.0), a["expires_at"].as_f64().unwrap_or(0.0));
    if expires - approved <= 0.0 || expires - approved > MAX_NL_APPROVAL_TTL_MS as f64 {
        return Ok(fail("ttl_too_long"));
    }
    if !(now.is_finite() && approved <= now) {
        return Ok(fail("not_yet_valid"));
    }
    if !(now < expires) {
        return Ok(fail("expired"));
    }
    if !verify_b64u(reviewer, &approval_message(a, if legacy { 1 } else { 2 }), a["sig"].as_str().unwrap_or("")) {
        return Ok(fail("bad_signature"));
    }
    Ok(json!({ "ok": true, "permissions": perms, "limits": limits, "reviewer": reviewer, "instruction": instruction, "legacy_unbound_instruction": legacy }))
}

/// `agentFromApprovedNL`'s request: the draft, its approval, the pinned reviewers and the agent's principal / goal.
pub struct AgentFromApprovedNl<'a> {
    pub draft: &'a Value,
    pub approval: &'a Value,
    pub reviewers: &'a [String],
    pub catalog: Option<Vec<ActionSpec>>,
    pub now: Option<f64>,
    pub principal: &'a KeyPair,
    /// The grant's goal text. Must equal the approved instruction (v2 approvals); a legacy v1 approval cannot check it.
    pub goal: &'a str,
    pub aud: Option<&'a str>,
    pub holder: Option<KeyPair>,
}

/// `agentFromApprovedNL`: the ONLY NL-to-agent path: mints an agent from a draft a pinned reviewer signed. Err with the rejection reason
/// otherwise. Returns `(agent, reviewer, legacy_unbound_instruction)`.
pub fn agent_from_approved_nl(req: AgentFromApprovedNl) -> Result<(AgentHandle, String, bool), String> {
    let loaded =
        load_approved_policy(req.draft, req.approval, &LoadApprovedOptions { reviewers: req.reviewers, catalog: req.catalog.as_deref(), now: req.now });
    if loaded["ok"] != json!(true) {
        return Err(format!("agentFromApprovedNL: {}", loaded["reason"].as_str().unwrap_or("malformed_approval")));
    }
    let legacy = loaded["legacy_unbound_instruction"] == json!(true);
    if !legacy && loaded["instruction"].as_str() != Some(req.goal) {
        return Err("agentFromApprovedNL: goal_mismatch".into());
    }
    let mut o = AgentOptions::new(req.principal, req.goal, &loaded["permissions"]);
    o.limits = Some(&loaded["limits"]);
    o.catalog = req.catalog;
    o.aud = req.aud;
    o.holder = req.holder;
    o.now = req.now.filter(|n| n.is_finite()).map(|n| n as i64);
    let agent = create_agent(o)?;
    Ok((agent, loaded["reviewer"].as_str().unwrap_or("").to_string(), legacy))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANSWER: &str = r#"{"permissions":{"stripe":["refund","nuke"]},"limits":{"refund":"$200/day"}}"#;
    const SEED: [u8; 32] = [7u8; 32];

    fn draft() -> Value {
        draft_policy_from_nl("let the bot refund up to $200/day", &|_| Ok(ANSWER.to_string()), None, Some("m1")).unwrap()
    }

    fn o(reviewers: &[String], now: i64) -> LoadApprovedOptions<'_> {
        LoadApprovedOptions { reviewers, catalog: None, now: Some(now as f64) }
    }

    fn reviewer() -> String {
        b64_encode(SigningKey::from_bytes(&SEED).verifying_key().as_bytes())
    }

    #[test]
    fn nothing_drafted_becomes_authority_without_a_pinned_signed_approval() {
        let mut d = draft();
        assert_eq!(d["status"], "draft");
        assert_eq!(d["unknownVerbs"], json!(["stripe.nuke"]));
        // a draft that proposed a verb outside the catalog cannot be approved
        assert!(approve_draft(&d, &SEED, Some(1_000.0), None).is_err());
        d["unknownVerbs"] = json!([]);
        let a = approve_draft(&d, &SEED, Some(1_000.0), None).unwrap();
        let rv_v = vec![reviewer()];
        let rv = &rv_v[..];
        let ok = load_approved_policy(&d, &a, &o(rv, 2_000));
        assert_eq!(ok["ok"], true, "{ok}");
        assert_eq!(ok["legacy_unbound_instruction"], false);
        assert_eq!(load_approved_policy(&d, &a, &o(&[], 2_000))["reason"], "no_reviewers_pinned");
        assert_eq!(load_approved_policy(&d, &a, &o(&[String::from("x")], 2_000))["reason"], "reviewer_not_pinned");
        assert_eq!(load_approved_policy(&d, &a, &o(rv, 500))["reason"], "not_yet_valid");
        assert_eq!(load_approved_policy(&d, &a, &o(rv, 1_000 + 3_600_000))["reason"], "expired");
        let mut t = d.clone();
        t["instruction"] = json!("let the bot do anything");
        assert_eq!(load_approved_policy(&t, &a, &o(rv, 2_000))["reason"], "tampered_draft");
        let mut t = d.clone();
        t["permissions"] = json!({"stripe": ["refund", "charge"]});
        assert_eq!(load_approved_policy(&t, &a, &o(rv, 2_000))["reason"], "tampered_draft");
        let mut bad = a.clone();
        bad["sig"] = json!(b64_encode(&[0u8; 64]));
        assert_eq!(load_approved_policy(&d, &bad, &o(rv, 2_000))["reason"], "bad_signature");
        let v1 = approve_draft_legacy_v1(&d, &SEED, Some(1_000.0), None).unwrap();
        let l = load_approved_policy(&d, &v1, &o(rv, 2_000));
        assert_eq!((l["ok"].clone(), l["legacy_unbound_instruction"].clone()), (json!(true), json!(true)));
    }
}
