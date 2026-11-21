//! `verify_evidence_bundle`: deterministic replay of a dispute evidence bundle (Intent Layer v2). Every finding is RECOMPUTED from the
//! signed artifacts; nothing the bundle claims about itself (the canary summary, the accumulator posts, the verdicts) is taken on trust.
//! The output is a findings report whose text comes from fixed templates, so two readers of the same bundle with the same trust inputs
//! get byte-identical reports (`report_digest`). Three statuses, never mixed: `pass` (re-verified here), `fail` (re-verification refuted
//! it), `unverified` (this verifier had no way to check it: no verifier for the format, an unopened map, a missing trust key);
//! `complete` is false whenever one is present.
//!
//! Port of the reference's `verifyEvidenceBundle`. JSON in, JSON out. `trust.verifiers[name]` is a constant verdict descriptor
//! `{ok, reason?}` that OVERRIDES the core default of that artifact (the reference takes a function there; a JSON API can only carry its
//! result). Never fails on a malformed bundle: it is a report with a failed `shape` finding, and a fault inside the replay is a failed
//! `shape` finding too (fail closed). `Err` only where the reference throws on its inputs (a `trust` that is not an object).
//!
//! shortcut: the oracle-fact, classifier-verdict and label-receipt wire validators here answer "malformed ..." without the reference's
//! per-member reason text (their ports return a bare verdict), and a post-quantum root capability is verified under the reader's pins
//! by an extra chain check instead of a dedicated verifier option; upgrade when the validators gain reason strings.
use crate::actions::js_to_number;
use crate::evidence::{
    acc_trust_error, anchor_commit, bundle_shape_error, cap_of, evidence_digest, normalize_bundle, principals_trust_error, EVIDENCE_REPORT_DOMAIN,
};
use crate::intent_acc::{
    acc_value_of, pcactn_reservation_digest, receipt_arithmetic_ok, sequencer_key_set_digest, verify_receipt_against_holder, verify_sequencer_key_set,
    ReceiptFreshness, DEFAULT_MAX_KEYSET_AGE_MS, DEFAULT_MAX_RECEIPT_AGE_MS, RECEIPT_SKEW_MS,
};
use crate::intent_history::{acc_key_of, acc_pre_state, monitor_state};
use crate::intent_kit::jit::intent_action_digest;
use crate::intent_kit2::mapkit::{intent_map_digest, verify_intent_map};
use crate::intent_kit3::statement::{intent_ref, verify_intent};
use crate::intent_revocation::{check_session_revocation, delta_revocation_id, map_revocation_id, session_revocation_id};
use crate::intent_session::{grant_session_caveat, intent_session_caveat_error, session_root_digest, verify_session_root_pinned};
use crate::intent_strict::{artifact_suite_error, verify_artifact_sig};
use crate::intent_v2::{js_number_string, IntentV2Context};
use crate::intent_wb::{
    validate_fact_wire, validate_labels_wire, validate_offer_set_wire, validate_verdict_wire, CLASSIFIER_DOMAIN, FACT_DOMAIN, LABELS_DOMAIN, OFFER_SET_DOMAIN,
};
use crate::oauth::{js_str, truthy};
use crate::wallet::{answer_ref, device_challenge, friction_rank, typed_digest, verify_intent_answer};
use crate::webauthn::{verify_assertion, Assertion, Challenge, CredentialPublicKey, VerifyExpectations};
use crate::{action_schema, hash_canonical_strict, verify_chain_policy, verify_inclusion, verify_pcactn_core_with, VerifyOptions};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};

/// The log name an evidence anchor's signed tree head carries.
pub const INTENT_ANCHOR_LOG: &str = "pca-intent:v1";
const DEFAULT_REVOCATION_MAX_AGE_S: i64 = 300;
const V2_CHECKS: [&str; 3] = ["schema", "intent_session", "accumulators"];
const NOT_PROVEN: [&str; 4] = [
    "That the principal understood the question: the bundle proves only that a deterministic card with the recorded digest was shown and answered at the recorded friction tier.",
    "That the site's signed schema describes what its endpoints really do (SCH).",
    "That the site's effect records and any oracle facts are true (EFF, ORC).",
    "Acceptance of this bundle by any card network, court or regulator.",
];

static NULL: Value = Value::Null;

fn template(code: &str) -> &'static str {
    match code {
        "shape" => "The bundle is well formed (pca-intent-evidence v1, closed members)",
        "principal.pinned" => "Every session-root key that signs in this bundle is a principal key pinned by the reader (attribution)",
        "trust.principals" => "The pinned principal keys (trust.principals) are well formed",
        "statement.commit" => "The session root commits to the intent statement the bundle names",
        "statement.opening" => "The opened statement is signed by a principal and hashes to the committed ref",
        "session_root.signature" => "The session root is signed by one of its principal keys",
        "schema.signature" => "The action schema is signed by a site key",
        "schema.digest" => "The session root binds this action schema",
        "schema.anchor" => "The action schema is anchored in a transparency log",
        "map.replay" => "The task map replays to its committed digest",
        "root_grant" => "The root intent grant G_0 is principal-signed and bound to the session",
        "delta.signature" => "The delta grant is a root capability signed by a principal of the session",
        "delta.chain" => "The delta grant chains to the session (session, seq, prev, root)",
        "delta.backed" => "Every delta grant is backed by a principal \"yes\" answer",
        "answer.signature" => "The answer is signed by a principal of the session, for this session",
        "answer.map" => "The answer refers to a map version in the bundle",
        "answer.tier" => "The answer meets the site minimum friction tier for the verb",
        "answer.typed" => "The typed-tier value re-derives the signed typed digest",
        "answer.device" => "The device-tier WebAuthn assertion verifies with user verification",
        "canaries.summary" => "The canary summary equals the one recomputed from the signed canary answers",
        "pcactn.verify" => "The PCActn verifies (signature, chain, audience, validity at its issue time)",
        "pcactn.root" => "The PCActn's root capability is G_0 or a bundled delta grant",
        "pcactn.session" => "The PCActn's signed intent_session member matches the session, its root grant and the accumulator events",
        "subject.present" => "The subject PCActn is in the bundle",
        "jit.consent" => "The irreversible subject action carries a principal JIT consent bound to its exact action digest",
        "accumulator.declared" => "The accumulator is declared in the session root",
        "accumulator.arithmetic" => "The accumulator posts are the running values of the counted events",
        "accumulator.cap" => "Every accumulator post is within the admitting grant's cap",
        "accumulator.receipts" => "The sequencer reservation receipt verifies and is consistent",
        "acc.keysets.equivocation" => "No two different sequencer key sets share one root and version",
        "acc.keysets" => "The sequencer key set is signed by the session's pinned sequencer root and its version never rolls back",
        "trust.acc" => "The verifier freshness configuration (trust.acc) is well formed",
        "effect.binding" => "The effect record is bound to the PCActn's signed params",
        "effect.charged" => "The charged amount is within the confirmed value",
        "effect.frame" => "No monitored state outside the write set changed",
        "effect.signature" => "The effect record is signed by the site",
        "verdict.signature" => "The site verdict record verifies",
        "fact.signature" => "The oracle fact verifies under a pinned oracle key",
        "classifier.signature" => "The classifier verdict verifies under a pinned judge key",
        "offer_set.signature" => "The offer set is signed by a site key, for this session",
        "labels.signature" => "The label receipt is signed by a pinned site key, for this session",
        "settlement.signature" => "The settlement record verifies",
        "revocation.history" => "The bundled revocation epoch extends its predecessor (one append-only chain by the session revocation authority)",
        "revocation.epoch" => "A fresh revocation epoch shows the session, its maps and its deltas unrevoked at the action time",
        "anchor.inclusion" => "The anchored artifact is included under a guardian-signed head of the intent log",
        _ => "An unknown check",
    }
}

fn status_text(status: &str) -> &'static str {
    match status {
        "pass" => "verified",
        "fail" => "REFUTED",
        _ => "not verified here",
    }
}

// ---- JavaScript value helpers ----------------------------------------------------------------------------------------------------

fn u16key(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn u16cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// `String(v)` of a JSON member (`undefined` for an absent one).
fn n(v: Option<&Value>) -> String {
    v.map_or_else(|| "undefined".to_string(), js_str)
}

fn gv<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k).unwrap_or(&NULL)
}

fn gs<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn is_num(v: Option<&Value>) -> Option<f64> {
    v.filter(|v| v.is_number()).and_then(Value::as_f64).filter(|f| f.is_finite())
}

/// `a === n` for a JSON number.
fn se_num(v: Option<&Value>, x: f64) -> bool {
    v.is_some_and(|v| v.is_number() && v.as_f64() == Some(x))
}

fn arr<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    v.get(k).and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// A JSON number the way the reference writes it (an integral value is an integer).
fn jnum(x: f64) -> Value {
    if x.is_finite() && x.fract() == 0.0 && x.abs() <= 9_007_199_254_740_991.0 {
        json!(x as i64)
    } else {
        json!(x)
    }
}

fn hc(v: &Value) -> Option<String> {
    hash_canonical_strict(v)
}

fn hc_or(v: &Value) -> String {
    hc(v).unwrap_or_default()
}

fn nul(e: Option<String>) -> Value {
    match e {
        None => json!({ "ok": true }),
        Some(r) => json!({ "ok": false, "reason": r }),
    }
}

fn r1(s: impl Into<String>) -> Vec<String> {
    vec![s.into()]
}

fn core_name(name: &str) -> &str {
    match name {
        "chain" => "cap_chain",
        "freshness_anchor" => "freshness",
        o => o,
    }
}

/// A core verdict reason as the reference words it.
fn ts_reason(reason: &str) -> String {
    let mut out = reason.to_string();
    if let Some((head, rest)) = reason.split_once(": ") {
        if head == "chain" || head == "freshness_anchor" {
            out = format!("{}: {}", core_name(head), rest);
        }
    }
    if out == "leaf_signature: signature does not verify under the leaf holder key" {
        out.push_str(" / suite");
    }
    out
}

// ---- findings --------------------------------------------------------------------------------------------------------------------

struct Finding {
    code: String,
    status: &'static str,
    text: String,
    refs: Vec<String>,
}

#[derive(Default)]
struct Findings {
    list: Vec<Finding>,
}

impl Findings {
    fn add(&mut self, code: &str, status: &'static str, refs: Vec<String>, detail: Option<String>) {
        let tail = detail.filter(|d| !d.is_empty()).map(|d| format!(" ({d})")).unwrap_or_default();
        self.list.push(Finding { code: code.to_string(), status, text: format!("{}: {}{}.", template(code), status_text(status), tail), refs });
    }

    fn verdict(&mut self, code: &str, v: &Value, refs: Vec<String>) {
        if truthy(v.get("ok")) {
            self.add(code, "pass", refs, None);
        } else {
            self.add(code, "fail", refs, v.get("reason").filter(|r| !r.is_null()).map(js_str));
        }
    }

    /// Run the supplied `port` verdict if any, else the core default; with neither, the artifact stays unverified.
    fn check(&mut self, code: &str, port: Option<&Value>, core: Option<&dyn Fn() -> Option<Value>>, refs: Vec<String>, what: &str) {
        let v = match (port, core) {
            (Some(p), _) => Some(p.clone()),
            (None, Some(c)) => c(),
            _ => None,
        };
        match v {
            None => self.add(code, "unverified", refs, Some(format!("no verifier for {what}"))),
            Some(v) => self.verdict(code, &v, refs),
        }
    }

    fn has(&self, code: &str, status: &str) -> bool {
        self.list.iter().any(|x| x.code == code && x.status == status)
    }

    fn passed(&self, code: &str) -> bool {
        self.has(code, "pass") && !self.has(code, "fail")
    }
}

fn empty_summary() -> Value {
    json!({
        "admitted_under": null, "principal_keys": [], "answers": { "total": 0, "yes": 0, "no": 0, "partial": 0, "canaries": 0 }, "refusals": [],
        "consent": null, "charged": null, "canary_accuracy": { "correct": 0, "asked": 0 }, "attribution": { "pinned": false, "keys_to_check": [] },
        "proven": [], "not_proven": NOT_PROVEN,
    })
}

fn finish(f: Findings, digest: Option<String>, mut summary: Value) -> Result<Value, String> {
    let mut list = f.list;
    list.sort_by(|x, y| {
        u16key(&x.code)
            .cmp(&u16key(&y.code))
            .then_with(|| u16key(&x.refs.join(",")).cmp(&u16key(&y.refs.join(","))))
            .then_with(|| u16key(x.status).cmp(&u16key(y.status)))
            .then_with(|| u16key(&x.text).cmp(&u16key(&y.text)))
    });
    let consistent = !list.is_empty() && !list.iter().any(|x| x.status == "fail");
    let pinned: Vec<&Finding> = list.iter().filter(|x| x.code == "principal.pinned").collect();
    let attributed = pinned.iter().any(|x| x.status == "pass") && !pinned.iter().any(|x| x.status != "pass");
    let ok = consistent && attributed;
    let complete = !list.iter().any(|x| x.status == "unverified");
    let keys_to_check: Vec<String> =
        summary["attribution"]["keys_to_check"].as_array().map(|a| a.iter().filter_map(|k| k.as_str().map(String::from)).collect()).unwrap_or_default();
    if consistent && !attributed && !keys_to_check.is_empty() {
        let msg = format!(
            "The bundle is internally consistent but NOT attributed to any known principal: verify these session-root keys out of band: {}.",
            keys_to_check.join(", ")
        );
        if let Some(np) = summary["not_proven"].as_array_mut() {
            np.insert(0, json!(msg));
        }
    }
    let mut unverified: Vec<String> = list.iter().filter(|x| x.status == "unverified").map(|x| x.code.clone()).collect::<HashSet<_>>().into_iter().collect();
    unverified.sort_by(|a, b| u16cmp(a, b));
    if !unverified.is_empty() {
        let msg = format!("Checked only through a supplied verifier, or not at all: {}.", unverified.join(", "));
        if let Some(np) = summary["not_proven"].as_array_mut() {
            np.push(json!(msg));
        }
    }
    let findings: Vec<Value> = list.iter().map(|x| json!({ "code": x.code, "status": x.status, "text": x.text, "refs": x.refs })).collect();
    let mut body = Map::new();
    body.insert("ok".into(), json!(ok));
    body.insert("consistent".into(), json!(consistent));
    body.insert("attributed".into(), json!(attributed));
    body.insert("complete".into(), json!(complete));
    body.insert("digest".into(), digest.map_or(Value::Null, Value::String));
    body.insert("findings".into(), Value::Array(findings));
    body.insert("summary".into(), summary);
    let body = Value::Object(body);
    let report_digest = hc(&json!({ "d": EVIDENCE_REPORT_DOMAIN, "r": body })).ok_or("the report is not canonicalizable")?;
    let mut out = body;
    out["report_digest"] = Value::String(report_digest);
    Ok(out)
}

/// Replay a bundle against the reader's trust inputs (`trust`: siteKeys, principals, sessionRootDigest, minTier, jitTier, typedValues,
/// credentials, canaryLabels, oracleKeys, judges, labelKeys, anchorGuardian, acc, verifiers; all optional; JSON null = none). Returns the
/// findings report `{ok, consistent, attributed, complete, digest, findings, summary, report_digest}`.
pub fn verify_evidence_bundle(bundle: &Value, trust: &Value) -> Result<Value, String> {
    let empty = Value::Object(Map::new());
    let trust = if trust.is_null() { &empty } else { trust };
    if !trust.is_object() {
        return Err("trust must be an object".into());
    }
    let mut f = Findings::default();
    let mut summary = empty_summary();
    if let Some(te) = acc_trust_error(trust.get("acc")) {
        f.add("trust.acc", "fail", vec![], Some(te));
        return finish(f, None, summary);
    }
    if let Some(pe) = principals_trust_error(trust.get("principals")) {
        f.add("trust.principals", "fail", vec![], Some(pe));
        return finish(f, None, summary);
    }
    if let Some(bad) = bundle_shape_error(bundle) {
        f.add("shape", "fail", vec![], Some(bad));
        return finish(f, None, summary);
    }
    let normalized = normalize_bundle(bundle).and_then(|b| evidence_digest(&b).map(|d| (b, d)));
    let (b, digest) = match normalized {
        Ok(x) => x,
        Err(e) => {
            f.add("shape", "fail", vec![], Some(format!("not canonicalizable: {e}")));
            return finish(f, None, summary);
        }
    };
    f.add("shape", "pass", vec![], None);
    let replayed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| replay(&b, &digest, trust, &mut f, &mut summary)));
    match replayed {
        Ok(Ok(())) => {}
        Ok(Err(e)) => f.add("shape", "fail", vec![], Some(format!("replay aborted: {e}"))),
        Err(_) => f.add("shape", "fail", vec![], Some("replay aborted: internal fault".to_string())),
    }
    finish(f, Some(digest), summary)
}

struct Grant {
    id: String,
    cap: Value,
    seq: i64,
}

/// The verifier context (`intentV2.acc`) for a candidate action: pre-states of the site-local accumulators and monitor states.
fn acc_context_for(s_root: &Value, history: &[Value], params: &Value, t: &Value, schema: &Value) -> Result<Value, String> {
    let empty = Map::new();
    let pmap = params.as_object().unwrap_or(&empty);
    let mut state = Map::new();
    for a in arr(s_root, "accumulators") {
        let Some(am) = a.as_object() else { continue };
        if gv(gv(a, "holder"), "kind") != "site_local" {
            continue;
        }
        if !gv(a, "key").is_null() && acc_key_of(am, pmap).is_none() {
            continue; // the verifier fails the claim (missing key)
        }
        state.insert(gs(a, "id").to_string(), acc_pre_state(am, history, pmap, Some(t), Some(schema))?);
    }
    let mut monitors = Map::new();
    for m in arr(s_root, "monitors") {
        let Some(mm) = m.as_object() else { continue };
        monitors.insert(gs(m, "id").to_string(), monitor_state(mm, history)?.map_or(Value::Null, Value::String));
    }
    Ok(json!({ "state": state, "monitors": monitors }))
}

struct KeySetsAt {
    sets: Vec<Value>,
    tracked: Option<(i64, String)>,
}

fn replay(b: &Value, digest: &str, trust: &Value, f: &mut Findings, summary: &mut Value) -> Result<(), String> {
    let s_root = gv(b, "session_root");
    let session = gs(gv(b, "subject"), "session").to_string();
    let aud = gs(gv(b, "subject"), "aud").to_string();
    let doc = gv(gv(b, "schema"), "doc");
    // Consistency is checked against the keys the session root names; ATTRIBUTION (below) against the reader's pins.
    let mut principals: Vec<String> = arr(s_root, "principals").iter().map(|p| gs(p, "key").to_string()).collect();
    principals.sort_by(|a, b| u16cmp(a, b));
    summary["principal_keys"] = json!(principals);
    let principals_v = json!(principals);
    let computed_ref = session_root_digest(s_root).ok_or("the session root is not canonicalizable")?;
    let s_ref: Value = match trust.get("sessionRootDigest").filter(|v| !v.is_null()) {
        Some(v) => v.clone(),
        None => Value::String(computed_ref),
    };
    let ports = trust.get("verifiers").filter(|v| !v.is_null());
    let port = |name: &str| ports.and_then(|p| p.get(name)).filter(|v| !v.is_null());
    // The reader's PQ pins (trust.principals[].pq_pk, out of band; NEVER the bundle's own S.principals).
    let mut pq_map: HashMap<String, String> = HashMap::new();
    let mut pq_pins_obj = Map::new();
    if let Some(ps) = trust.get("principals").and_then(Value::as_array) {
        for p in ps {
            if let (Some(k), Some(pq)) = (p.get("key").and_then(Value::as_str), p.get("pq_pk").and_then(Value::as_str)) {
                pq_map.insert(k.to_string(), pq.to_string());
                pq_pins_obj.insert(k.to_string(), json!(pq));
            }
        }
    }
    let pq_pins_v = Value::Object(pq_pins_obj);
    let site_keys = trust.get("siteKeys").filter(|v| !v.is_null());

    // -- session root -------------------------------------------------------------------------------------------------------
    if gs(s_root, "session") != session {
        f.add("session_root.signature", "fail", r1("session_root"), Some("session root is for another session".into()));
    } else {
        let core = || Some(nul(verify_session_root_pinned(s_root, Some(&pq_pins_v)).err()));
        f.check("session_root.signature", port("sessionRoot"), Some(&core), r1("session_root"), "the session root");
    }

    // -- statement ----------------------------------------------------------------------------------------------------------
    let statement = gv(b, "statement");
    f.add("statement.commit", if s_root.get("intent_ref") == statement.get("commit") { "pass" } else { "fail" }, r1("statement"), None);
    let opening = statement.get("opening");
    match opening {
        None => f.add("statement.opening", "unverified", r1("statement"), Some("the statement was not opened (it stays a commitment)".into())),
        Some(op) => {
            let v = verify_intent(op, &json!({}));
            if !truthy(v.get("ok")) {
                f.add("statement.opening", "fail", r1("statement"), v.get("reason").filter(|r| !r.is_null()).map(js_str));
            } else if Some(intent_ref(op)?.as_str()) != statement.get("commit").and_then(Value::as_str) {
                f.add("statement.opening", "fail", r1("statement"), Some("the opening does not hash to the commitment".into()));
            } else if !principals.iter().any(|p| p == gs(op, "principal")) {
                f.add("statement.opening", "fail", r1("statement"), Some("signed by a key that is not a principal of the session".into()));
            } else {
                f.add("statement.opening", "pass", r1("statement"), None);
            }
        }
    }

    // -- schema -------------------------------------------------------------------------------------------------------------
    let schema_core = || site_keys.map(|keys| nul(action_schema::verify_action_schema(doc, keys).err()));
    let schema_core_ref: Option<&dyn Fn() -> Option<Value>> = if site_keys.is_some() { Some(&schema_core) } else { None };
    f.check("schema.signature", port("schema"), schema_core_ref, r1("schema"), "the action schema (no site keys supplied)");
    let schema_digest = action_schema::action_schema_digest(doc).ok_or("the action schema is not canonicalizable")?;
    let s_schema = gv(s_root, "schema");
    f.add("schema.digest", if gs(s_schema, "digest") == schema_digest && gs(s_schema, "aud") == aud { "pass" } else { "fail" }, r1("schema"), None);

    // -- maps ---------------------------------------------------------------------------------------------------------------
    let map_commits: HashSet<String> = arr(b, "maps").iter().map(|m| gs(m, "commit").to_string()).collect();
    for m in arr(b, "maps") {
        let rf = r1(format!("map:{}", n(m.get("seq"))));
        if !truthy(m.get("map")) {
            f.add("map.replay", "unverified", rf, Some("committed map not revealed".into()));
            continue;
        }
        let r = verify_intent_map(&m["map"]);
        if !truthy(r.get("ok")) {
            let problems: Vec<String> = r.get("problems").and_then(Value::as_array).map(|a| a.iter().take(3).map(js_str).collect()).unwrap_or_default();
            f.add("map.replay", "fail", rf, Some(problems.join("; ")));
        } else if intent_map_digest(&m["map"])? != gs(m, "commit") {
            f.add("map.replay", "fail", rf, Some("the revealed map does not hash to its commit".into()));
        } else {
            f.add("map.replay", "pass", rf, None);
        }
    }

    // -- grants: G_0 and the delta chain (core intent_session caveat) -------------------------------------------------------
    let mut grants: Vec<Grant> = Vec::new();
    fn put(grants: &mut Vec<Grant>, g: Grant) {
        match grants.iter_mut().find(|x| x.id == g.id) {
            Some(x) => *x = g,
            None => grants.push(g),
        }
    }
    let g0 = gv(b, "root_grant");
    let chain_of = |c: &Value| verify_chain_policy(std::slice::from_ref(c), c.get("issuer").and_then(Value::as_str), None, Some(&pq_map), None);
    {
        let cv = grant_session_caveat(g0);
        let cv_err = cv.and_then(|c| intent_session_caveat_error(Some(c)));
        if let Err(why) = chain_of(g0) {
            f.add("root_grant", "fail", r1("G_0"), Some(why));
        } else if !principals.iter().any(|p| p == gs(g0, "issuer")) {
            f.add("root_grant", "fail", r1("G_0"), Some("not signed by a principal of the session".into()));
        } else if cv.is_none() || cv_err.is_some() {
            f.add("root_grant", "fail", r1("G_0"), Some(if cv.is_some() { cv_err.unwrap_or_default() } else { "no intent_session caveat".to_string() }));
        } else if let Some(cv) = cv.filter(|c| gs(c, "session") != session || !se_num(c.get("seq"), 0.0) || c.get("root") != Some(&s_ref)) {
            let _ = cv;
            f.add("root_grant", "fail", r1("G_0"), Some("intent_session caveat does not bind seq 0 of this session root".into()));
        } else {
            f.add("root_grant", "pass", r1("G_0"), None);
            put(&mut grants, Grant { id: gs(g0, "id").to_string(), cap: g0.clone(), seq: 0 });
        }
    }
    let mut prev_id = gs(g0, "id").to_string();
    for (i, d) in arr(b, "deltas").iter().enumerate() {
        let want = i as i64 + 1;
        let rf = r1(format!("D_{want}"));
        let chain = chain_of(d);
        if chain.is_err() || !principals.iter().any(|p| p == gs(d, "issuer")) || d.get("parent").is_some() {
            f.add(
                "delta.signature",
                "fail",
                rf,
                Some(match chain {
                    Err(why) => why,
                    Ok(()) => "not a principal-signed root capability".to_string(),
                }),
            );
            continue;
        }
        f.add("delta.signature", "pass", rf.clone(), None);
        let cv = grant_session_caveat(d);
        let n_cv = arr(d, "caveats").iter().filter(|k| k.get("type").and_then(Value::as_str) == Some("intent_session")).count();
        let why2: Option<String> = match cv {
            None => Some("no single intent_session caveat".into()),
            Some(_) if n_cv != 1 => Some("no single intent_session caveat".into()),
            Some(c) => {
                if let Some(e) = intent_session_caveat_error(Some(c)) {
                    Some(e)
                } else if gs(c, "session") != session {
                    Some("bound to another session".into())
                } else if c.get("root") != Some(&s_ref) {
                    Some("bound to another session root".into())
                } else if !se_num(c.get("seq"), want as f64) {
                    Some(format!("seq {} where {} was expected (gap, duplicate or reorder)", n(c.get("seq")), want))
                } else if c.get("prev").and_then(Value::as_str) != Some(prev_id.as_str()) {
                    Some("prev does not name the previous grant".into())
                } else {
                    None
                }
            }
        };
        match why2 {
            Some(w) => f.add("delta.chain", "fail", rf, Some(w)),
            None => {
                f.add("delta.chain", "pass", rf, None);
                put(&mut grants, Grant { id: gs(d, "id").to_string(), cap: d.clone(), seq: want });
            }
        }
        prev_id = gs(d, "id").to_string();
    }

    // -- answers ------------------------------------------------------------------------------------------------------------
    let mut verified: Vec<&Value> = Vec::new();
    for a in arr(b, "answers") {
        let qid = a.get("question_id");
        let rf = r1(format!("answer:{}", n(qid)));
        let v = verify_intent_answer(a, Some(&principals_v));
        if !truthy(v.get("ok")) {
            f.add("answer.signature", "fail", rf, v.get("reason").filter(|r| !r.is_null()).map(js_str));
            continue;
        }
        if gs(a, "session") != session {
            f.add("answer.signature", "fail", rf, Some("answer for another session".into()));
            continue;
        }
        f.add("answer.signature", "pass", rf.clone(), None);
        verified.push(a);
        f.add("answer.map", if map_commits.contains(gs(a, "map_digest")) { "pass" } else { "fail" }, rf.clone(), None);
        let ux = gv(a, "ux");
        if truthy(ux.get("canary")) || !se_num(a.get("y"), 1.0) {
            continue;
        }
        let mn = trust.get("minTier").filter(|m| m.is_object()).and_then(|m| m.get(gs(a, "verb"))).filter(|v| !v.is_null());
        if let Some(mn) = mn {
            let ok = friction_rank(gv(ux, "tier")) >= friction_rank(mn);
            f.add("answer.tier", if ok { "pass" } else { "fail" }, rf.clone(), Some(format!("{} vs minimum {}", n(ux.get("tier")), js_str(mn))));
        }
        if gv(ux, "tier") == "typed" {
            let tv = trust.get("typedValues").filter(|m| m.is_object()).and_then(|m| m.get(gs(a, "question_id"))).filter(|v| !v.is_null());
            match tv {
                None => f.add("answer.typed", "unverified", rf.clone(), Some("the typed value is not known to this verifier".into())),
                Some(tv) => {
                    let tv = tv.as_str().ok_or("the typed value must be a string")?;
                    let ok = typed_digest(gs(a, "question_id"), tv)?.as_str() == ux.get("typed_digest").and_then(Value::as_str).unwrap_or("\0");
                    f.add("answer.typed", if ok { "pass" } else { "fail" }, rf.clone(), None);
                }
            }
        }
        if gv(ux, "tier") == "device" {
            let wa = ux.get("webauthn").filter(|w| truthy(Some(*w)));
            let cred = wa.and_then(|w| trust.get("credentials").filter(|c| c.is_object()).and_then(|c| c.get(gs(w, "credential_id")))).filter(|v| !v.is_null());
            match (wa, cred) {
                (Some(wa), Some(cred)) => {
                    let dec = |k: &str| crate::decode_b64u_strict(gs(wa, k), None).ok_or_else(|| format!("webauthn.{k} is not base64url"));
                    let (ad, cd, sg) = (dec("authenticator_data")?, dec("client_data_json")?, dec("signature")?);
                    let y = a.get("y").and_then(Value::as_i64).unwrap_or(0);
                    let challenge = device_challenge(gs(a, "question_id"), gs(ux, "rendered_digest"), y, ux.get("action_digest").and_then(Value::as_str))?;
                    let pk_v = gv(cred, "publicKey");
                    let cose;
                    let public_key = match pk_v {
                        Value::String(s) => {
                            cose = crate::decode_b64u_strict(s, None).ok_or("the credential public key is not base64url")?;
                            CredentialPublicKey::Cose(&cose)
                        }
                        other => CredentialPublicKey::Jwk(other),
                    };
                    let origins: Vec<&str> = arr(cred, "origins").iter().filter_map(Value::as_str).collect();
                    let expect = VerifyExpectations {
                        expected_challenge: Some(Challenge::B64u(&challenge)),
                        rp_id: gs(cred, "rpId"),
                        origins: &origins,
                        require_uv: true,
                        stored_sign_count: Some(cred.get("signCount").and_then(Value::as_f64).unwrap_or(0.0)),
                        ..VerifyExpectations::default()
                    };
                    let r = verify_assertion(&Assertion { authenticator_data: &ad, client_data_json: &cd, signature: &sg, public_key }, &expect);
                    if truthy(r.get("ok")) {
                        f.add("answer.device", "pass", rf.clone(), None);
                    } else {
                        f.add("answer.device", "fail", rf.clone(), r.get("reason").filter(|x| !x.is_null()).map(js_str));
                    }
                }
                _ => f.add("answer.device", "unverified", rf.clone(), Some("unknown authenticator".into())),
            }
        }
    }
    let is_canary = |a: &&Value| truthy(a.get("ux").and_then(|u| u.get("canary")));
    let real: Vec<&Value> = verified.iter().filter(|a| !is_canary(a)).copied().collect();
    let canaries: Vec<&Value> = verified.iter().filter(|a| is_canary(a)).copied().collect();
    let y_is = |a: &&Value, x: f64| se_num(a.get("y"), x);
    summary["answers"] = json!({
        "total": real.len(),
        "yes": real.iter().filter(|a| y_is(a, 1.0) && a.get("partial").is_none()).count(),
        "no": real.iter().filter(|a| y_is(a, 0.0)).count(),
        "partial": real.iter().filter(|a| a.get("partial").is_some()).count(),
        "canaries": canaries.len(),
    });
    let mut refusals: Vec<String> = real.iter().filter(|a| y_is(a, 0.0)).map(|a| gs(a, "question_id").to_string()).collect();
    refusals.sort_by(|a, b| u16cmp(a, b));
    summary["refusals"] = json!(refusals);
    let yes_count = real.iter().filter(|a| y_is(a, 1.0)).count();
    let n_deltas = arr(b, "deltas").len();
    f.add(
        "delta.backed",
        if yes_count >= n_deltas { "pass" } else { "fail" },
        vec![],
        Some(format!("{n_deltas} delta(s), {yes_count} principal yes answer(s)")),
    );

    // -- canaries: recomputed, the claimed summary is never trusted --------------------------------------------------------------
    let labels: HashMap<&str, &Value> = arr(b, "canary_labels").iter().map(|c| (gs(c, "question_id"), gv(c, "label"))).collect();
    let (mut false_yes, mut false_no, mut missing) = (0usize, 0usize, 0usize);
    let canary_labels = trust.get("canaryLabels").filter(|c| c.is_object());
    for a in &canaries {
        let qid = gs(a, "question_id");
        let label = canary_labels.and_then(|c| c.get(qid)).filter(|v| !v.is_null()).or_else(|| labels.get(qid).copied().filter(|v| !v.is_null()));
        match label {
            None => missing += 1,
            Some(l) if se_num(Some(l), 0.0) && y_is(a, 1.0) => false_yes += 1,
            Some(l) if se_num(Some(l), 1.0) && y_is(a, 0.0) => false_no += 1,
            _ => {}
        }
    }
    summary["canary_accuracy"] = json!({ "correct": canaries.len() as i64 - missing as i64 - false_yes as i64 - false_no as i64, "asked": canaries.len() });
    let c = gv(b, "canaries");
    if missing > 0 {
        f.add("canaries.summary", "fail", vec![], Some(format!("{missing} canary answer(s) without a known label")));
    } else if !se_num(c.get("asked"), canaries.len() as f64) || !se_num(c.get("false_yes"), false_yes as f64) || !se_num(c.get("false_no"), false_no as f64) {
        f.add(
            "canaries.summary",
            "fail",
            vec![],
            Some(format!(
                "claimed {}/{}/{}, recomputed {}/{}/{}",
                n(c.get("asked")),
                n(c.get("false_yes")),
                n(c.get("false_no")),
                canaries.len(),
                false_yes,
                false_no
            )),
        );
    } else {
        f.add("canaries.summary", "pass", vec![], Some(format!("{} asked, {} false yes, {} false no", canaries.len(), false_yes, false_no)));
    }

    // -- sequencer key sets (rule 15): replayed per root in issue order, versions monotone like core keyset_versions ------------
    let acc_trust = trust.get("acc").filter(|a| !a.is_null());
    let mut root_holders: Vec<(String, &Value)> = Vec::new();
    for a in arr(s_root, "accumulators") {
        let h = gv(a, "holder");
        if gv(h, "kind") == "sequenced" {
            let root = gs(h, "root").to_string();
            match root_holders.iter_mut().find(|(r, _)| *r == root) {
                Some(x) => x.1 = h,
                None => root_holders.push((root, h)),
            }
        }
    }
    let holder_of = |root: &str| root_holders.iter().find(|(r, _)| r == root).map(|(_, h)| *h);
    let num_or0 = |x: &Value, k: &str| {
        let v = js_to_number(x.get(k));
        if v.is_nan() {
            0.0
        } else {
            v
        }
    };
    let mut sets: Vec<Value> = gv(gv(b, "accumulator"), "sequencer_keys").as_array().cloned().unwrap_or_default();
    sets.sort_by(|x, y| {
        for k in ["issued_at", "version"] {
            let d = num_or0(x, k) - num_or0(y, k);
            if d < 0.0 {
                return std::cmp::Ordering::Less;
            }
            if d > 0.0 {
                return std::cmp::Ordering::Greater;
            }
        }
        u16cmp(&hc_or(x), &hc_or(y))
    });
    let mut accepted: Vec<Value> = Vec::new();
    let mut verified_sets: Vec<Value> = Vec::new();
    let mut equivocated: HashSet<String> = HashSet::new();
    let mut tracked: HashMap<String, f64> = HashMap::new();
    let mut by_version: HashMap<String, (String, String)> = HashMap::new();
    for (i, k) in sets.iter().enumerate() {
        let rf = format!("keyset#{}:{}", i, if k.is_object() { n(k.get("version")) } else { "?".to_string() });
        let holder = k.get("sequencer").and_then(Value::as_str).and_then(|r| holder_of(r));
        let Some(holder) = holder else {
            f.add("acc.keysets", "fail", vec![rf], Some("not signed by a sequencer root the session root pins".into()));
            continue;
        };
        let root = gs(holder, "root").to_string();
        if !verify_sequencer_key_set(k, &root, holder.get("root_pq_pk")).unwrap_or(false) {
            f.add("acc.keysets", "fail", vec![rf], Some("the key set does not verify under its pinned root".into()));
            continue;
        }
        let version = k.get("version").and_then(Value::as_f64).unwrap_or(f64::NAN);
        let prev = tracked.get(&root).copied();
        if let Some(p) = prev.filter(|p| version < *p) {
            f.add("acc.keysets", "fail", vec![rf], Some(format!("version {} rolls back the tracked version {}", n(k.get("version")), js_number_string(p))));
            continue;
        }
        // Equivocation (core rule 15): two DIFFERENT sets under one root and version are both refused; an identical duplicate is not.
        let slot = format!("{}#{}", root, n(k.get("version")));
        let kd = sequencer_key_set_digest(k).unwrap_or_default();
        let seen = by_version.get(&slot).cloned();
        if let Some((sd, sref)) = seen.as_ref().filter(|(sd, _)| *sd != kd) {
            let _ = sd;
            equivocated.insert(slot.clone());
            verified_sets.push(k.clone());
            f.add(
                "acc.keysets.equivocation",
                "fail",
                vec![sref.clone(), rf],
                Some(format!("two different key sets under version {} of one sequencer root", n(k.get("version")))),
            );
            continue;
        }
        if seen.is_none() {
            by_version.insert(slot, (kd, rf.clone()));
        }
        verified_sets.push(k.clone());
        tracked.insert(root.clone(), prev.unwrap_or(0.0).max(version));
        accepted.push(k.clone());
        f.add("acc.keysets", "pass", vec![rf], None);
    }
    let accepted: Vec<Value> = accepted.into_iter().filter(|k| !equivocated.contains(&format!("{}#{}", gs(k, "sequencer"), n(k.get("version"))))).collect();
    // In force = accepted sets of the root issued by admission (+ the core skew); the tracked state is the newest VERIFIED set issued by then.
    let key_sets_at = |root: &str, t: f64| -> KeySetsAt {
        let issued = |k: &Value| k.get("issued_at").and_then(Value::as_f64).unwrap_or(f64::NAN);
        let ver = |k: &Value| k.get("version").and_then(Value::as_f64).unwrap_or(f64::NAN);
        let mut newest: Option<&Value> = None;
        for k in &verified_sets {
            if gs(k, "sequencer") == root && issued(k) <= t && newest.is_none_or(|nw| ver(k) > ver(nw)) {
                newest = Some(k);
            }
        }
        let poisoned = newest.is_some_and(|nw| equivocated.contains(&format!("{}#{}", root, n(nw.get("version")))));
        let floor = newest.map_or(0.0, ver);
        let sets: Vec<Value> =
            accepted.iter().filter(|k| gs(k, "sequencer") == root && issued(k) <= t + RECEIPT_SKEW_MS as f64 && ver(k) >= floor).cloned().collect();
        let tracked = newest.filter(|_| !poisoned).map(|nw| (ver(nw) as i64, sequencer_key_set_digest(nw).unwrap_or_default()));
        KeySetsAt { sets, tracked }
    };

    // -- PCActns ------------------------------------------------------------------------------------------------------------
    let mut by_digest: HashMap<String, &Value> = HashMap::new();
    let mut digest_order: Vec<String> = Vec::new();
    let mut root_seq: HashMap<String, i64> = HashMap::new();
    let effect_of = |d: &str| arr(b, "effects").iter().find(|e| e.get("pcactn_digest").and_then(Value::as_str) == Some(d));
    let mut grants_sorted: Vec<&Grant> = grants.iter().collect();
    grants_sorted.sort_by_key(|g| g.seq);
    let grants_by_seq: Vec<Value> = grants_sorted.iter().map(|g| g.cap.clone()).collect();
    let epochs = arr(b, "revocation_epochs");
    // Index of the epoch in force at t (the last one issued at or before t, in issue order).
    let epoch_idx_at = |t: f64| -> Option<usize> {
        let mut idx = None;
        for (i, r) in epochs.iter().enumerate() {
            if gv(gv(r, "epoch"), "issued_at").as_f64().is_some_and(|x| x <= t) {
                idx = Some(i);
            }
        }
        idx
    };

    // The admitted history, as the site's store held it: one event per accumulator-bearing PCActn, in event order.
    let mut history: Vec<Value> = Vec::new();
    for ev in arr(gv(b, "accumulator"), "events") {
        let d = gs(ev, "pcactn_digest");
        if history.iter().any(|h| gs(h, "id") == d) {
            continue;
        }
        let p = arr(b, "pcactns").iter().find(|x| hc(x).as_deref() == Some(d));
        let params = effect_of(d).and_then(|e| e.get("params")).filter(|v| !v.is_null());
        if let (Some(p), Some(params)) = (p, params.filter(|v| truthy(Some(*v)))) {
            let status = ev.get("status").filter(|v| !v.is_null()).cloned().unwrap_or_else(|| json!("committed"));
            history
                .push(json!({ "id": d, "verb": p["action"]["verb"], "resource": p["action"]["resource"], "params": params, "t": p["iat"], "status": status }));
        }
    }
    let schema_verbs = json!({ "verbs": doc["verbs"] });
    let site_keys_v = site_keys.cloned().unwrap_or_else(|| json!([]));

    // The verifier state `decide_intent_v2` reads, rebuilt from the bundle (None when the bundle lacks the plaintext params).
    let v2_context = |p: &Value, d: &str, seq: Option<i64>| -> Result<Option<Value>, String> {
        let params = effect_of(d).and_then(|e| e.get("params")).filter(|v| truthy(Some(*v)));
        let (Some(params), Some(seq)) = (params, seq) else { return Ok(None) };
        let iat = gv(p, "iat");
        let idx = history.iter().position(|h| gs(h, "id") == d);
        let before: Vec<Value> = match idx {
            Some(i) => history[..i].to_vec(),
            None => history.iter().filter(|h| h.get("t").and_then(Value::as_f64) <= iat.as_f64()).cloned().collect(),
        };
        let acc = acc_context_for(s_root, &before, params, iat, &schema_verbs)?;
        let t = iat.as_f64().unwrap_or(f64::NAN);
        let ri = epoch_idx_at(t);
        let mut session_ctx = Map::new();
        session_ctx.insert("root".into(), s_root.clone());
        session_ctx.insert("grants".into(), Value::Array(grants_by_seq.iter().take(seq.max(0) as usize).cloned().collect()));
        session_ctx.insert("pq_pins".into(), pq_pins_v.clone());
        if let Some(r) = ri {
            session_ctx.insert("revocation".into(), epochs[r].clone());
            if r > 0 {
                session_ctx.insert("revocation_last".into(), epochs[r - 1].clone());
            }
        }
        let mut kv = Map::new();
        let mut seq_keys: Vec<Value> = Vec::new();
        for (root, _) in &root_holders {
            let ks = key_sets_at(root, t);
            if let Some((v, dg)) = ks.tracked {
                kv.insert(root.clone(), json!({ "version": v, "digest": dg }));
            }
            seq_keys.extend(ks.sets);
        }
        let mut acc_m = acc.as_object().cloned().unwrap_or_default();
        acc_m.insert("receipts".into(), gv(gv(b, "accumulator"), "receipts").as_array().map_or_else(|| json!([]), |r| json!(r)));
        acc_m.insert("sequencer_keys".into(), Value::Array(seq_keys));
        acc_m.insert("keyset_versions".into(), Value::Object(kv));
        let mut ctx = Map::new();
        ctx.insert("params".into(), params.clone());
        ctx.insert("schema".into(), json!({ "docs": [doc], "keys": site_keys_v }));
        ctx.insert("session".into(), Value::Object(session_ctx));
        ctx.insert("acc".into(), Value::Object(acc_m));
        if let Some(at) = acc_trust {
            ctx.insert("policy".into(), json!({ "acc": at }));
        }
        Ok(Some(Value::Object(ctx)))
    };

    for p in arr(b, "pcactns") {
        let Some(d) = hc(p) else {
            f.add("pcactn.verify", "fail", r1("pcactn:?"), Some("not canonicalizable".into()));
            continue;
        };
        by_digest.insert(d.clone(), p);
        digest_order.push(d.clone());
        let rf = r1(format!("pcactn:{d}"));
        let root = p.get("cap_chain").and_then(Value::as_array).and_then(|c| c.first());
        let Some(root) = root.filter(|r| truthy(Some(*r))) else {
            f.add("pcactn.verify", "fail", rf, Some("empty capability chain".into()));
            continue;
        };
        let g = root.get("id").and_then(Value::as_str).and_then(|rid| grants.iter().find(|g| g.id == rid));
        let same_root = g.is_some_and(|g| matches!((hc(&g.cap), hc(root)), (Some(x), Some(y)) if x == y));
        let is_ = p.get("intent_session");
        let ctx = if is_.is_some() && same_root { v2_context(p, &d, g.map(|g| g.seq))? } else { None };
        // The root's authority is pcactn.root (byte-equal to G_0 / a verified delta) plus principal.pinned (trust.principals): a
        // non-Ed25519 root verifies only under the reader's pins, else it is refused.
        let ctx_obj = ctx.as_ref().and_then(IntentV2Context::from_json);
        let opts = VerifyOptions { insecure_skip_plan_root_check: true, pq_pins: Some(&pq_map), intent_v2: ctx_obj.as_ref(), ..VerifyOptions::default() };
        let iat = p.get("iat").and_then(Value::as_f64).unwrap_or(0.0) as i64;
        let r = verify_pcactn_core_with(p, root, iat, &aud, &opts);
        let mut failed: Vec<String> = r.checks.iter().filter(|(_, ok)| !**ok).map(|(k, _)| core_name(k).to_string()).collect();
        let mut reason = ts_reason(&r.reason);
        let pq_chain =
            p.get("cap_chain").and_then(Value::as_array).map(|c| verify_chain_policy(c, root.get("issuer").and_then(Value::as_str), None, Some(&pq_map), None));
        if let Some(Err(why)) = pq_chain {
            if !failed.iter().any(|x| x == "cap_chain") {
                failed.push("cap_chain".into());
                if reason.is_empty() {
                    reason = format!("cap_chain: {why}");
                }
            }
        }
        failed.sort_by(|a, b| u16cmp(a, b));
        let v1f: Vec<&String> = failed.iter().filter(|k| !V2_CHECKS.contains(&k.as_str())).collect();
        let v2f: Vec<&String> = failed.iter().filter(|k| V2_CHECKS.contains(&k.as_str())).collect();
        if v1f.is_empty() {
            f.add("pcactn.verify", "pass", rf.clone(), None);
        } else {
            f.add("pcactn.verify", "fail", rf.clone(), Some(format!("{}: {}", v1f.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "), reason)));
        }
        if let (true, Some(g)) = (same_root, g) {
            f.add("pcactn.root", "pass", rf.clone(), Some(if g.seq == 0 { "G_0".to_string() } else { format!("D_{}", g.seq) }));
            root_seq.insert(d.clone(), g.seq);
        } else {
            f.add("pcactn.root", "fail", rf.clone(), Some("rooted at a grant that is not G_0 or a verified delta of this session".into()));
        }
        if let Some(is_) = is_ {
            let mut why: Option<String> = None;
            if is_.get("session").and_then(Value::as_str) != Some(session.as_str()) {
                why = Some("another session".into());
            } else if is_.get("root") != Some(&s_ref) {
                why = Some("another session root".into());
            } else if is_.get("schema").and_then(Value::as_str) != Some(schema_digest.as_str()) {
                why = Some("another schema".into());
            } else if g.is_some_and(|g| !se_num(is_.get("seq"), g.seq as f64)) {
                why = Some(format!("seq {} but rooted at seq {}", n(is_.get("seq")), g.map_or(0, |g| g.seq)));
            } else {
                let claims: &[Value] = match is_.get("acc") {
                    None | Some(Value::Null) => &[],
                    Some(Value::Array(a)) => a.as_slice(),
                    Some(_) => return Err("is_.acc is not iterable".into()),
                };
                for cl in claims {
                    let ev = arr(gv(b, "accumulator"), "events").iter().find(|e| gs(e, "pcactn_digest") == d && e.get("acc") == cl.get("id"));
                    if ev.is_none_or(|e| !strict_num_eq(e.get("post"), cl.get("post"))) {
                        why = Some(format!("the signed claim {}.post = {} has no matching accumulator event", n(cl.get("id")), n(cl.get("post"))));
                    }
                }
            }
            if why.is_none() && !v2f.is_empty() {
                why = Some(format!("core v2 checks failed: {}", v2f.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
            }
            match (why, ctx.is_some()) {
                (Some(w), _) => f.add("pcactn.session", "fail", rf, Some(w)),
                (None, false) => f.add("pcactn.session", "unverified", rf, Some("the core v2 checks need the plaintext params of the effect record".into())),
                (None, true) => f.add("pcactn.session", "pass", rf, None),
            }
        }
    }
    let subject_digest = gs(gv(b, "subject"), "pcactn_digest").to_string();
    let subject = by_digest.get(&subject_digest).copied();
    f.add("subject.present", if subject.is_some() { "pass" } else { "fail" }, r1(format!("pcactn:{subject_digest}")), None);
    let s_seq = root_seq.get(&subject_digest).copied();
    summary["admitted_under"] = match s_seq {
        None => Value::Null,
        Some(0) => json!("G_0"),
        Some(s) => json!(format!("D_{s}")),
    };

    // -- effects (no core format yet: signature through the port) ----------------------------------------------------------------
    for e in arr(b, "effects") {
        let rf = r1(format!("effect:{}", n(e.get("pcactn_digest"))));
        let Some(p) = by_digest.get(gs(e, "pcactn_digest")).copied() else {
            f.add("effect.binding", "fail", rf, Some("no such PCActn in the bundle".into()));
            continue;
        };
        match e.get("params") {
            None => f.add("effect.binding", "unverified", rf.clone(), Some("no raw params to bind".into())),
            Some(params) => {
                let ok = crate::params_digest(Some(params)) == gs(gv(p, "action"), "params_digest");
                f.add("effect.binding", if ok { "pass" } else { "fail" }, rf.clone(), None);
            }
        }
        if let Some(charged) = e.get("charged").filter(|c| truthy(Some(*c))) {
            let cref = charged.get("ref");
            let name = cref.and_then(Value::as_str).and_then(|r| r.strip_prefix("action.params."));
            let bound = name.and_then(|nm| e.get("params").filter(|p| truthy(Some(*p))).and_then(|p| p.as_object()).and_then(|m| m.get(nm)));
            match (is_num(bound), is_num(charged.get("amount"))) {
                (Some(bound), Some(amount)) => {
                    f.add(
                        "effect.charged",
                        if amount <= bound { "pass" } else { "fail" },
                        rf.clone(),
                        Some(format!("{} vs {}", js_number_string(amount), js_number_string(bound))),
                    );
                    if gs(e, "pcactn_digest") == subject_digest {
                        summary["charged"] = json!({ "amount": jnum(amount), "bound": jnum(bound) });
                    }
                }
                _ => f.add("effect.charged", "unverified", rf.clone(), Some(format!("no numeric {} to compare", n(cref)))),
            }
        }
        if let Some(fv) = e.get("frame_violations") {
            let items: Vec<&Value> = fv.as_array().map(|a| a.iter().collect()).unwrap_or_default();
            let mut names: Vec<String> = items.iter().map(|x| js_str(x)).collect();
            names.sort_by(|a, b| u16cmp(a, b));
            f.add("effect.frame", if items.is_empty() { "pass" } else { "fail" }, rf.clone(), if items.is_empty() { None } else { Some(names.join(", ")) });
        }
        f.check("effect.signature", port("effect"), None, rf, "effect records (no core format yet)");
    }

    // -- JIT consent for an irreversible subject action (core action digest) -----------------------------------------------------
    if let Some(subject) = subject.filter(|s| gs(gv(s, "action"), "reversibility_class") == "irreversible") {
        let rf = r1(format!("pcactn:{subject_digest}"));
        let ad = intent_action_digest(&subject["action"])?;
        let need = trust.get("jitTier").filter(|v| !v.is_null()).cloned().unwrap_or_else(|| json!("typed"));
        let cons = real.iter().find(|a| {
            let ux = gv(a, "ux");
            y_is(a, 1.0)
                && ux.get("consent_for_action") == Some(&Value::Bool(true))
                && ux.get("action_digest").and_then(Value::as_str) == Some(ad.as_str())
                && friction_rank(gv(ux, "tier")) >= friction_rank(&need)
        });
        match cons {
            Some(c) => {
                f.add("jit.consent", "pass", rf, Some(format!("question {}, {} tier", n(c.get("question_id")), n(gv(c, "ux").get("tier")))));
                summary["consent"] = json!({ "question_id": c["question_id"], "tier": c["ux"]["tier"], "signer": c["signer"] });
            }
            None => f.add("jit.consent", "fail", rf, Some(format!("no principal yes at {} tier or above bound to this action digest", js_str(&need)))),
        }
    }

    // -- accumulators (core declarations and value rule) -------------------------------------------------------------------------
    let mut decls: HashMap<String, &Value> = HashMap::new();
    for a in arr(s_root, "accumulators") {
        decls.insert(gs(a, "id").to_string(), a);
    }
    let value_of = |decl: &Value, d: &str| -> Option<i64> {
        let p = by_digest.get(d).copied()?;
        let params = effect_of(d).and_then(|e| e.get("params")).filter(|v| truthy(Some(*v)))?;
        let (dm, pm) = (decl.as_object()?, params.as_object()?);
        match acc_value_of(dm, gs(gv(p, "action"), "verb"), pm, Some(&schema_verbs)) {
            Ok(Ok(v)) => Some(v.val),
            _ => None,
        }
    };
    let mut running: HashMap<String, f64> = HashMap::new();
    for (i, ev) in arr(gv(b, "accumulator"), "events").iter().enumerate() {
        let rf = r1(format!("acc:{}#{}", gs(ev, "acc"), i));
        let Some(decl) = decls.get(gs(ev, "acc")).copied() else {
            f.add("accumulator.declared", "fail", rf, None);
            continue;
        };
        let p = by_digest.get(gs(ev, "pcactn_digest")).copied();
        let status = ev.get("status").and_then(Value::as_str);
        let counted = status != Some("released") && status != Some("reverted");
        let prev = running.get(gs(ev, "acc")).copied().unwrap_or(0.0);
        let post = ev.get("post").and_then(Value::as_f64).unwrap_or(f64::NAN);
        let agg = gs(decl, "agg");
        let mut expected: Option<f64> = None;
        if !counted {
            expected = Some(prev);
        } else if agg == "count" {
            expected = Some(prev + 1.0);
        } else if agg == "sum" || agg == "max" {
            if let Some(val) = value_of(decl, gs(ev, "pcactn_digest")) {
                expected = Some(if agg == "sum" { prev + val as f64 } else { prev.max(val as f64) });
            }
        }
        if p.is_none() {
            f.add("accumulator.arithmetic", "fail", rf.clone(), Some("event names a PCActn that is not in the bundle".into()));
        } else if let Some(exp) = expected {
            let ok = post == exp;
            f.add(
                "accumulator.arithmetic",
                if ok { "pass" } else { "fail" },
                rf.clone(),
                if ok { None } else { Some(format!("post {}, recomputed {}", n(ev.get("post")), js_number_string(exp))) },
            );
        } else if post >= prev {
            f.add("accumulator.arithmetic", "unverified", rf.clone(), Some("contribution not recomputable".into()));
        } else {
            f.add("accumulator.arithmetic", "fail", rf.clone(), Some("post decreased".into()));
        }
        running.insert(gs(ev, "acc").to_string(), if counted { post } else { prev });
        if !counted {
            continue;
        }
        let seq = p.and_then(|_| root_seq.get(gs(ev, "pcactn_digest")).copied());
        let delta = ev.get("delta");
        if let (Some(dl), Some(sq)) = (delta, seq) {
            if dl.as_f64() != Some(sq as f64) || !dl.is_number() {
                f.add("accumulator.cap", "fail", rf, Some("the event names a different admitting grant from the PCActn root".into()));
                continue;
            }
        }
        let want_seq: Option<f64> = seq.map(|s| s as f64).or_else(|| delta.and_then(Value::as_f64));
        let grant = want_seq.and_then(|w| grants.iter().find(|g| g.seq as f64 == w));
        let mut caps: Vec<f64> = Vec::new();
        if let (Some(g), Some(p)) = (grant, p) {
            if let Some(c) = cap_of(&g.cap, gv(ev, "acc"), gv(gv(p, "action"), "verb"))? {
                caps.push(c);
            }
        }
        for k in ["domain_max", "cap"] {
            if let Some(x) = is_num(decl.get(k)) {
                caps.push(x);
            }
        }
        if caps.is_empty() {
            f.add("accumulator.cap", "unverified", rf, Some("no cap stated for this accumulator".into()));
        } else {
            let cap = caps.iter().copied().fold(f64::INFINITY, f64::min);
            f.add("accumulator.cap", if post.is_finite() && post <= cap { "pass" } else { "fail" }, rf, Some(format!("post {}, cap {}", n(ev.get("post")), js_number_string(cap))));
        }
    }
    let receipts: Vec<Value> = gv(gv(b, "accumulator"), "receipts").as_array().cloned().unwrap_or_default();
    if gv(gv(b, "accumulator"), "holder") == "sequenced" && receipts.is_empty() {
        f.add("accumulator.receipts", "fail", r1("accumulator"), Some("a sequenced accumulator without receipts".into()));
    }
    for (i, r) in receipts.iter().enumerate() {
        let core = || -> Option<Value> {
            // None = the signature and freshness held but the contribution cannot be recomputed (params withheld): unverified.
            let decl = decls.get(gs(r, "acc")).copied().filter(|d| gv(gv(d, "holder"), "kind") == "sequenced");
            let Some(decl) = decl else {
                return Some(json!({ "ok": false, "reason": "the receipt names an accumulator that is not sequenced in the session root" }));
            };
            let holder = gv(decl, "holder");
            if gs(r, "session") != session || gs(r, "aud") != aud {
                return Some(json!({ "ok": false, "reason": "receipt for another session or audience" }));
            }
            let d = digest_order
                .iter()
                .find(|dd| by_digest.get(*dd).and_then(|pp| pcactn_reservation_digest(pp)).as_deref() == r.get("pcactn_digest").and_then(Value::as_str));
            let Some(d) = d else { return Some(json!({ "ok": false, "reason": "the receipt reserves for a PCActn that is not in the bundle" })) };
            // Rule 15 freshness is judged at ADMISSION time (the reserved PCActn's iat), never at bundle-verification time.
            let admitted_at = by_digest.get(d).and_then(|p| p.get("iat")).and_then(Value::as_f64).unwrap_or(f64::NAN);
            let ks = key_sets_at(gs(holder, "root"), admitted_at);
            let sec = |k: &str, dflt: i64| acc_trust.and_then(|a| a.get(k)).and_then(Value::as_f64).map_or(dflt as f64, |s| s * 1000.0);
            let fresh = ReceiptFreshness {
                max_receipt_age_ms: sec("max_receipt_age_s", DEFAULT_MAX_RECEIPT_AGE_MS),
                max_keyset_age_ms: sec("max_keyset_age_s", DEFAULT_MAX_KEYSET_AGE_MS),
                tracked: ks.tracked,
            };
            let hmap = holder.as_object()?;
            if verify_receipt_against_holder(r, hmap, Some(&Value::Array(ks.sets)), admitted_at, &fresh).is_err() {
                return Some(json!({ "ok": false, "reason": "not signed by a key the pinned sequencer root listed, or not fresh, at admission time" }));
            }
            if !r.get("expires_at").and_then(Value::as_f64).is_some_and(|e| admitted_at.is_finite() && e.is_finite() && admitted_at <= e) {
                return Some(json!({ "ok": false, "reason": "the receipt had expired when the action was admitted" }));
            }
            let val = value_of(decl, d)?;
            if !receipt_arithmetic_ok(gs(decl, "agg"), r, val) {
                return Some(json!({ "ok": false, "reason": "pre + delta does not give post for the reserved value" }));
            }
            Some(json!({ "ok": true }))
        };
        let rs = r.get("seq").filter(|v| !v.is_null());
        let rf = r1(format!("receipt:{}#{}", n(r.get("acc")), rs.map_or_else(|| i.to_string(), |v| js_str(v))));
        f.check("accumulator.receipts", port("receipt"), Some(&core), rf, "the reserved contribution (the effect params were withheld)");
    }

    // -- W-B artifacts: facts, classifier verdicts, offer sets, label receipts ------------------------------------------------------
    let pin_of = |v: &Value| -> Option<(String, Option<Value>)> {
        match v {
            Value::String(s) => Some((s.clone(), None)),
            Value::Object(o) => o.get("pk").and_then(Value::as_str).map(|pk| (pk.to_string(), o.get("pq_pk").cloned())),
            _ => None,
        }
    };
    let oracle_keys = trust.get("oracleKeys").filter(|o| o.is_object());
    for (i, x) in arr(b, "facts").iter().enumerate() {
        let pin = x.get("oracle").and_then(Value::as_str).and_then(|o| oracle_keys.and_then(|k| k.get(o))).and_then(|v| pin_of(v));
        let core = || -> Option<Value> {
            let (pk, pq) = pin.as_ref()?;
            if !validate_fact_wire(x) {
                return Some(json!({ "ok": false, "reason": "malformed oracle fact" }));
            }
            let ok = x.as_object().is_some_and(|m| verify_artifact_sig(FACT_DOMAIN, m, pk, pq.as_ref()));
            Some(if ok { json!({ "ok": true }) } else { json!({ "ok": false, "reason": "bad oracle signature" }) })
        };
        let core_ref: Option<&dyn Fn() -> Option<Value>> = if pin.is_some() { Some(&core) } else { None };
        f.check("fact.signature", port("fact"), core_ref, r1(format!("fact:{i}")), "this fact (oracle key not pinned)");
    }
    let judges: Vec<&str> = trust.get("judges").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    for (i, x) in arr(b, "classifier").iter().enumerate() {
        let judge = x.get("judge").and_then(Value::as_str);
        let core = || -> Option<Value> {
            if !validate_verdict_wire(x) {
                return Some(json!({ "ok": false, "reason": "malformed classifier verdict" }));
            }
            if gs(x, "session") != session {
                return Some(json!({ "ok": false, "reason": "verdict for another session" }));
            }
            let ok = x.as_object().is_some_and(|m| verify_artifact_sig(CLASSIFIER_DOMAIN, m, judge.unwrap_or(""), None));
            Some(if ok { json!({ "ok": true }) } else { json!({ "ok": false, "reason": "bad judge signature" }) })
        };
        let pinned = judge.is_some_and(|j| judges.contains(&j));
        let core_ref: Option<&dyn Fn() -> Option<Value>> = if pinned { Some(&core) } else { None };
        f.check("classifier.signature", port("classifier"), core_ref, r1(format!("classifier:{i}")), "this classifier verdict (judge not pinned)");
    }
    let site_key_list: Vec<&Value> = site_keys.and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default();
    for (i, x) in arr(b, "offer_sets").iter().enumerate() {
        let key =
            site_key_list.iter().find(|k| x.is_object() && k.get("kid") == x.get("kid") && k.get("alg").and_then(Value::as_str) == Some("ed25519")).copied();
        let core = || -> Option<Value> {
            if let Some(w) = validate_offer_set_wire(x) {
                return Some(json!({ "ok": false, "reason": w }));
            }
            if gs(x, "session") != session {
                return Some(json!({ "ok": false, "reason": "offer set for another session" }));
            }
            let ok = x.as_object().is_some_and(|m| verify_artifact_sig(OFFER_SET_DOMAIN, m, gs(key.unwrap_or(&NULL), "pk"), key.and_then(|k| k.get("pq_pk"))));
            Some(if ok { json!({ "ok": true }) } else { json!({ "ok": false, "reason": "bad site signature" }) })
        };
        let core_ref: Option<&dyn Fn() -> Option<Value>> = if key.is_some() { Some(&core) } else { None };
        f.check("offer_set.signature", port("offerSet"), core_ref, r1(format!("offer_set:{i}")), "this offer set (site key not pinned)");
    }
    let label_keys: Vec<Value> = match trust.get("labelKeys").filter(|v| !v.is_null()) {
        Some(Value::Array(a)) => a.clone(),
        Some(_) => Vec::new(),
        None => site_key_list
            .iter()
            .filter(|k| k.get("alg").and_then(Value::as_str) == Some("ed25519"))
            .map(|k| json!({ "site": doc["site"], "kid": k["kid"], "pk": k["pk"] }))
            .collect(),
    };
    for (i, x) in arr(b, "labels").iter().enumerate() {
        let core = || -> Option<Value> {
            if !validate_labels_wire(x) {
                return Some(json!({ "ok": false, "reason": "malformed label receipt" }));
            }
            let m = x.as_object()?;
            if let Some(se) = artifact_suite_error(m) {
                return Some(json!({ "ok": false, "reason": format!("signature suite: {se}") }));
            }
            let key = label_keys.iter().find(|k| k.is_object() && k.get("site") == x.get("site") && k.get("kid") == x.get("kid"));
            let Some(key) = key else {
                return Some(json!({ "ok": false, "reason": format!("no pinned label key for site '{}' kid '{}'", n(x.get("site")), n(x.get("kid"))) }));
            };
            if !verify_artifact_sig(LABELS_DOMAIN, m, gs(key, "pk"), key.get("pq_pk")) {
                return Some(json!({ "ok": false, "reason": "bad label receipt signature" }));
            }
            if x.get("session").and_then(Value::as_str) != Some(session.as_str()) {
                return Some(json!({ "ok": false, "reason": "label receipt for another session" }));
            }
            Some(json!({ "ok": true }))
        };
        let core_ref: Option<&dyn Fn() -> Option<Value>> = if !label_keys.is_empty() { Some(&core) } else { None };
        f.check("labels.signature", port("labels"), core_ref, r1(format!("labels:{i}")), "this label receipt (no site keys)");
    }

    // -- ported artifacts with no core format --------------------------------------------------------------------------------------
    for v in arr(b, "verdicts") {
        f.check("verdict.signature", port("verdict"), None, r1(format!("verdict:{}", n(v.get("pcactn_digest")))), "site verdicts (no core format yet)");
    }
    for (i, _) in arr(b, "settlements").iter().enumerate() {
        f.check("settlement.signature", port("settlement"), None, r1(format!("settlement:{i}")), "settlement records (no core format yet)");
    }

    // -- revocation (core check_session_revocation, rule 13 step 7) ------------------------------------------------------------------
    // The bundle's epochs, in issue order, must form ONE append-only chain signed by the session's dedicated revocation authority: every
    // epoch is checked as of its own issue time with its predecessor as the tracked `last`; the epoch in force at the action time decides.
    let rev = s_root.get("revocation").filter(|r| truthy(Some(*r)));
    if epochs.is_empty() {
        f.add("revocation.epoch", "unverified", vec![], Some("no revocation epoch in the bundle".into()));
    } else if rev.is_none() {
        f.add("revocation.epoch", "fail", vec![], Some("the session root names no revocation authority".into()));
    } else if let Some(rev) = rev {
        let authority = gs(rev, "key").to_string();
        let max_age_ms = rev.get("max_age_s").filter(|v| !v.is_null()).and_then(Value::as_f64).unwrap_or(DEFAULT_REVOCATION_MAX_AGE_S as f64) * 1000.0;
        let rcheck = |ev: &Value, ids: &[String], now: f64, last: Option<&Value>| -> Value {
            nul(check_session_revocation(Some(ev), &session, &authority, ids, now, max_age_ms, None, rev.get("pq_pk"), last).err())
        };
        let mut history_ok = true;
        for (i, ev) in epochs.iter().enumerate() {
            let at = gv(gv(ev, "epoch"), "issued_at").as_f64().unwrap_or(f64::NAN);
            let v = rcheck(ev, &[], at, if i > 0 { Some(&epochs[i - 1]) } else { None });
            if !truthy(v.get("ok")) {
                history_ok = false;
            }
            f.verdict("revocation.history", &v, r1(format!("epoch#{}:{}", i, n(gv(ev, "epoch").get("epoch")))));
        }
        match subject {
            None => f.add("revocation.epoch", "unverified", vec![], Some("no subject action time".into())),
            Some(subject) => {
                let mut ids = vec![session_revocation_id(&session)];
                ids.extend(arr(b, "maps").iter().map(|m| map_revocation_id(gs(m, "commit"))));
                ids.extend(arr(b, "deltas").iter().map(|d| delta_revocation_id(gs(d, "id"))));
                let iat = subject.get("iat").and_then(Value::as_f64).unwrap_or(f64::NAN);
                match epoch_idx_at(iat) {
                    None => f.add("revocation.epoch", "fail", vec![], Some("every epoch was issued after the action".into())),
                    Some(idx) => {
                        let ev = &epochs[idx];
                        let rf = r1(format!("epoch:{}", n(gv(ev, "epoch").get("epoch"))));
                        if !history_ok {
                            f.add("revocation.epoch", "fail", rf, Some("the bundled epochs are not one append-only chain".into()));
                        } else {
                            let v = rcheck(ev, &ids, iat, if idx > 0 { Some(&epochs[idx - 1]) } else { None });
                            f.verdict("revocation.epoch", &v, rf);
                        }
                    }
                }
            }
        }
    }

    // -- anchors ------------------------------------------------------------------------------------------------------------
    if truthy(gv(b, "schema").get("anchor")) {
        f.add("schema.anchor", "unverified", r1("schema"), Some("the anchor names a log position without an inclusion proof".into()));
    }
    let anchorable = |kind: &Value, d: &Value| -> bool {
        match kind.as_str() {
            Some("evidence") => d.as_str() == Some(digest),
            Some("statement") => d.as_str() == statement.get("commit").and_then(Value::as_str),
            Some("map") => d.as_str().is_some_and(|x| map_commits.contains(x)),
            Some("schema") => d.as_str() == Some(schema_digest.as_str()),
            Some("observation") => verified.iter().any(|a| answer_ref(a).ok().as_deref() == d.as_str()),
            _ => false,
        }
    };
    let anchors = arr(b, "anchors");
    if !anchors.iter().any(|a| gv(a, "kind") == "evidence") {
        f.add("anchor.inclusion", "unverified", r1("anchor:evidence"), Some("the bundle is not anchored".into()));
    }
    for a in anchors {
        let rf = r1(format!("anchor:{}:{}", n(a.get("kind")), n(a.get("index"))));
        if !anchorable(gv(a, "kind"), gv(a, "digest")) {
            f.add("anchor.inclusion", "fail", rf, Some("the anchor names an artifact that is not this one".into()));
            continue;
        }
        let Some(g) = trust.get("anchorGuardian").filter(|g| truthy(Some(*g))) else {
            f.add("anchor.inclusion", "unverified", rf, Some("no anchor-log guardian key supplied".into()));
            continue;
        };
        let h = gv(a, "signed_tree_head");
        let proof = gv(a, "proof");
        let commit = anchor_commit(gv(a, "kind"), gv(a, "digest"))?;
        let ok = gs(h, "principal") == INTENT_ANCHOR_LOG
            && h.get("instance_id") == g.get("instance")
            && crate::ledger::verify_tree_head(h, gs(g, "public"), None)
            && a.get("index").is_some_and(|i| i.is_number() && proof.get("index") == Some(i))
            && h.get("size").is_some_and(|s| s.is_number() && proof.get("size") == Some(s))
            && verify_inclusion(gs(h, "root"), proof.as_object(), &Value::String(commit));
        f.add("anchor.inclusion", if ok { "pass" } else { "fail" }, rf, None);
    }

    // -- attribution: the session-root keys that sign in this bundle must be pinned by the reader --------------------------------------
    // Everything above verifies against keys the bundle's own self-signed session root names, so it proves internal consistency only.
    // The revocation authority and the sequencer roots are named inside S, so they are attributed transitively once S's signer is pinned.
    let mut signing: Vec<&Value> = vec![gv(s_root, "signer"), gv(g0, "issuer")];
    signing.extend(arr(b, "deltas").iter().map(|d| gv(d, "issuer")));
    signing.extend(arr(b, "answers").iter().map(|a| gv(a, "signer")));
    if let Some(op) = opening.filter(|o| truthy(Some(*o))) {
        signing.push(gv(op, "principal"));
    }
    let mut keys: Vec<String> = signing.iter().filter_map(|k| k.as_str().map(String::from)).collect::<HashSet<_>>().into_iter().collect();
    keys.sort_by(|a, b| u16cmp(a, b));
    summary["attribution"]["keys_to_check"] = json!(keys);
    match trust.get("principals").filter(|p| !p.is_null()) {
        None => f.add(
            "principal.pinned",
            "unverified",
            keys.clone(),
            Some("no pinned principal keys: the bundle names its own principals; verify these keys out of band".into()),
        ),
        Some(pins_in) => {
            let pins: HashMap<&str, &Value> = pins_in.as_array().map(|a| a.iter().map(|p| (gs(p, "key"), p)).collect()).unwrap_or_default();
            let unpinned: Vec<String> = keys.iter().filter(|k| !pins.contains_key(k.as_str())).cloned().collect();
            let pq_mismatch = |k: &str| -> bool {
                let Some(pin) = pins.get(k) else { return false };
                let sp = arr(s_root, "principals").iter().find(|x| gs(x, "key") == k);
                pin.get("pq_pk") != sp.and_then(|x| x.get("pq_pk"))
            };
            let mism: Vec<String> = keys.iter().filter(|k| pq_mismatch(k)).cloned().collect();
            if !unpinned.is_empty() {
                f.add("principal.pinned", "fail", unpinned, Some("signing keys that are not pinned principals".into()));
            } else if !mism.is_empty() {
                f.add("principal.pinned", "fail", mism, Some("the session root binds a different PQ key than the pin".into()));
            } else {
                f.add("principal.pinned", "pass", keys.clone(), None);
                summary["attribution"]["pinned"] = json!(true);
            }
        }
    }

    // -- plain-language facts (only what passed) -------------------------------------------------------------------------------------
    let mut proven: Vec<String> = Vec::new();
    let pinned = summary["attribution"]["pinned"] == true;
    if let Some(adm) = summary["admitted_under"].as_str().map(String::from).filter(|_| f.passed("pcactn.verify")) {
        proven.push(format!(
            "The subject action was signed by the agent under {}, a grant signed by the session principal{}.",
            adm,
            if pinned { " (pinned)" } else { " (NOT pinned)" }
        ));
    }
    let who = |k: &str| -> String {
        if pinned {
            format!("Pinned principal key {k}")
        } else {
            format!("Session-root key {k} (NOT pinned: not attributed to a known principal)")
        }
    };
    if let Some(c) = summary["consent"].as_object().filter(|_| !summary["consent"].is_null()) {
        proven.push(format!(
            "{} signed a {}-tier \"yes\" bound to this exact action (question {}).",
            who(&js_str(&c["signer"])),
            js_str(&c["tier"]),
            js_str(&c["question_id"])
        ));
    }
    if let (Some(amount), Some(bound)) = (summary["charged"]["amount"].as_f64(), summary["charged"]["bound"].as_f64()) {
        if amount <= bound {
            proven.push(format!("The charged amount {} is within the confirmed value {}.", js_number_string(amount), js_number_string(bound)));
        }
    }
    if !refusals.is_empty() {
        proven.push(format!("The principal refused {} question(s): {}.", refusals.len(), refusals.join(", ")));
    }
    let asked = summary["canary_accuracy"]["asked"].as_i64().unwrap_or(0);
    if asked != 0 {
        proven.push(format!("Canary accuracy {}/{}.", summary["canary_accuracy"]["correct"].as_i64().unwrap_or(0), asked));
    }
    if f.passed("accumulator.cap") {
        proven.push("Every accumulator post is within the cap of the grant that admitted it.".to_string());
    }
    if f.passed("effect.frame") {
        proven.push("The site reports no change to monitored state outside the write set.".to_string());
    }
    summary["proven"] = json!(proven);
    Ok(())
}

/// `a === b` for two JSON numbers (a missing or non-number member never matches).
fn strict_num_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    matches!((a, b), (Some(x), Some(y)) if x.is_number() && y.is_number() && x.as_f64() == y.as_f64())
}
