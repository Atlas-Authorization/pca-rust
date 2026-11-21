//! Progressive authorization (`precedent.ts`). Widening is only by an escalation request answered by a principal-signed escalation
//! answer. A verified answer becomes an append-only hash-chained precedent bound to (policy digest, decision cell, the answered
//! action's exact quantities as a ceiling). A recorded cell decision is never flipped except by a principal-signed revocation.
//! P1 the allow set grows only by cells with a valid principal signature bound to the policy digest; P2 no replay of an answer onto
//! another policy digest, cell or beyond the signed ceiling; P3 a Deny is never turned into Allow (precedents act only on
//! Escalate); P4 Escalate never becomes Allow implicitly. NOT covered by any signature: the relation facts (`rels`) and the log
//! itself (the integrity of the head is the verifier's to anchor).
use super::examples::{build_space, cell_key, decide_case, mk_act, Space};
use super::*;
use crate::agent::KeyPair;
use crate::escalation::{
    escalation_action_digest, escalation_answer_shape_error, escalation_history_head, escalation_policy_digest, verify_escalation_answer, EscalationBinding,
    EscalationVerdict, PinnedSigner, ESCALATION_ANSWER_DOMAIN,
};
use crate::goal::sign::{sign_payload, verify_payload};
use serde_json::{json, Map};

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn unit_key(q: &Value) -> String {
    let u = g(q, "u");
    if st(g(u, "k")) == "money" {
        format!("money:{}", js_s(g(u, "ccy")))
    } else {
        js_s(g(u, "k"))
    }
}
/// Ceilings are keyed by parameter AND unit (kind + currency): a EUR answer never covers a GBP action.
pub fn ceilings_of(params: &Value) -> Value {
    let mut out = Map::new();
    for (k, v) in params.as_object().into_iter().flatten() {
        if st(g(v, "k")) == "q" {
            out.insert(format!("{k}|{}", unit_key(g(v, "q"))), g(g(v, "q"), "n").clone());
        }
    }
    Value::Object(out)
}
fn case_of(a: &Value) -> Value {
    let act = g(g(a, "pcactn"), "action");
    json!({"act": mk_act(&js_s(g(act, "verb")), &js_s(g(act, "resource")), g(a, "params").clone()), "rels": g(a, "rels")})
}
pub fn sign_revocation(p: &Value, secret: &KeyPair) -> Res<Value> {
    sign_payload("precedent-revocation", p, secret)
}
/// The answer body for a request: bind it to the request's exact (policy, action, history head); sign it as an escalation answer.
/// `o`: `{principal, decision, iat, expires_at, nonce}`.
pub fn answer_body_for(req: &Value, o: &Value) -> Value {
    json!({"v": 1, "kind": "pca-escalation-answer", "principal": g(o, "principal"), "policy_digest": g(req, "policy_digest"),
        "action_digest": g(req, "action_digest"), "history_head": g(req, "history_head"), "decision": g(o, "decision"),
        "iat": g(o, "iat"), "expires_at": g(o, "expires_at"), "nonce": g(o, "nonce")})
}

fn nz(v: &Value) -> Value {
    v.clone()
}
fn entry_digest(e: &Value) -> Res<String> {
    let answered = match e.get("answered") {
        Some(a) if crate::goal::js::truthy(Some(a)) => {
            let mut m = a.as_object().cloned().unwrap_or_default();
            let lc = m.get("lastCounter").cloned().unwrap_or(Value::Null);
            m.insert("lastCounter".into(), lc);
            Value::Object(m)
        }
        _ => Value::Null,
    };
    hc(&json!({"d": "atlas-pca/goal-precedent-entry/v1", "seq": nz(g(e, "seq")), "prev": g(e, "prev"), "kind": g(e, "kind"), "answer": g(e, "answer"),
        "answered": answered, "cell": g(e, "cell"), "ceilings": g(e, "ceilings"), "revocation": g(e, "revocation")}))
}
fn pinned(p: &Value) -> Option<PinnedSigner> {
    match p {
        Value::String(s) => Some(PinnedSigner::ed25519(s.clone())),
        Value::Object(m) => {
            let pk = m.get("pk")?.as_str()?.to_string();
            Some(match m.get("pq_pk").and_then(Value::as_str) {
                Some(q) => PinnedSigner::with_pq(pk, q.to_string()),
                None => PinnedSigner::ed25519(pk),
            })
        }
        _ => None,
    }
}

/// The hash-chained log of recorded answers and revocations. `entries` are plain JSON objects.
pub struct PrecedentLog {
    pub entries: Vec<Value>,
    principals: Vec<Value>,
}
impl PrecedentLog {
    /// `principals`: the pinned signers allowed to answer and revoke (the verifier's own list): `"pk"` or `{pk, pq_pk?}`.
    pub fn new(principals: &[Value]) -> Self {
        PrecedentLog { entries: vec![], principals: principals.to_vec() }
    }
    pub fn head(&self) -> String {
        self.entries.last().map_or(GENESIS.to_string(), |e| st(g(e, "digest")).to_string())
    }
    fn pin_for(&self, pk: &Value) -> Option<&Value> {
        self.principals.iter().find(|p| {
            let k = if p.is_string() { *p } else { g(p, "pk") };
            seq_eq(k, pk)
        })
    }
    /// Everything about an answer that does not depend on the clock: shape, pinned signature, bindings, params digest.
    fn answer_fault(&self, answer: &Value, answered: &Value) -> Res<Option<&'static str>> {
        if escalation_answer_shape_error(answer).is_some() {
            return Ok(Some("malformed answer"));
        }
        let pin = match self.pin_for(g(answer, "principal")) {
            Some(p) => p,
            None => return Ok(Some("bad signature")),
        };
        let (pk, pq) = if pin.is_string() { (st(pin), None) } else { (st(g(pin, "pk")), pin.get("pq_pk")) };
        let am = answer.as_object().ok_or("answer is not an object")?;
        if crate::intent_strict::artifact_suite_error(am).is_some() || !crate::intent_strict::verify_artifact_sig(ESCALATION_ANSWER_DOMAIN, am, pk, pq) {
            return Ok(Some("bad signature"));
        }
        let pcactn = g(answered, "pcactn");
        let ad = escalation_action_digest(pcactn).ok_or("canonicalize: value outside the strict canonical profile")?;
        if !seq_eq(g(answer, "action_digest"), &Value::String(ad)) {
            return Ok(Some("answer is bound to another action"));
        }
        let hh = escalation_history_head(g(answered, "lastCounter").as_u64()).ok_or("canonicalize: value outside the strict canonical profile")?;
        if !seq_eq(g(answer, "history_head"), &Value::String(hh)) {
            return Ok(Some("answer is bound to another history state"));
        }
        if !seq_eq(&Value::String(crate::params_digest(Some(g(answered, "params")))), g(g(pcactn, "action"), "params_digest")) {
            return Ok(Some("params do not match the signed action"));
        }
        Ok(None)
    }
    fn chain_ok(&self, space: &Space) -> Res<bool> {
        let mut prev = GENESIS.to_string();
        for (i, e) in self.entries.iter().enumerate() {
            if !seq_eq(g(e, "seq"), &json!(i))
                || !seq_eq(g(e, "prev"), &Value::String(prev.clone()))
                || !seq_eq(g(e, "digest"), &Value::String(entry_digest(e)?))
            {
                return Ok(false);
            }
            if st(g(e, "kind")) == "answer" {
                let (answer, answered) = (g(e, "answer"), g(e, "answered"));
                if !crate::goal::js::truthy(e.get("answer")) || !crate::goal::js::truthy(e.get("answered")) || self.answer_fault(answer, answered)?.is_some() {
                    return Ok(false);
                }
                if !seq_eq(g(e, "cell"), &Value::String(cell_key(space, &case_of(answered))?)) {
                    return Ok(false);
                }
                if e.get("ceilings").map(jstr) != Some(jstr(&ceilings_of(g(answered, "params")))) {
                    return Ok(false);
                }
            } else if !(crate::goal::js::truthy(e.get("revocation")) && verify_payload(g(e, "revocation"), "precedent-revocation", &self.principals)) {
                return Ok(false);
            }
            prev = st(g(e, "digest")).to_string();
        }
        Ok(true)
    }
    /// Recompute the whole chain (append-only integrity), every signature and binding, and every derived cell and ceiling under `space`.
    /// Total: any failure is `false`.
    pub fn verify_chain(&self, space: &Space) -> bool {
        self.chain_ok(space).unwrap_or(false)
    }
    fn live(&self, policy: &Value, cell: &str, now: f64) -> Option<&Value> {
        let revoked: Vec<&Value> =
            self.entries.iter().filter(|e| st(g(e, "kind")) == "revocation").map(|e| g(g(g(e, "revocation"), "payload"), "target_entry")).collect();
        self.entries.iter().rev().find(|e| {
            st(g(e, "kind")) == "answer"
                && seq_eq(g(g(e, "answer"), "policy_digest"), policy)
                && st(g(e, "cell")) == cell
                && nm(g(g(e, "answer"), "expires_at")) > now && now.is_finite()
                && !revoked.iter().any(|r| seq_eq(r, g(e, "digest")))
        })
    }
    /// Verify the answer (pinned signer, bound to this grant's policy digest and this exact action and history, unexpired) and record
    /// it. `answered`: `{pcactn, params, rels, lastCounter?}`. `{ok: true, entry}` or `{ok: false, reason}`.
    pub fn append(&mut self, answer: &Value, answered: &Value, grant: &Value, space: &Space, now: f64) -> Res<Value> {
        let bind = EscalationBinding {
            policy_digest: escalation_policy_digest(grant).ok_or("canonicalize: value outside the strict canonical profile")?,
            action_digest: escalation_action_digest(g(answered, "pcactn")).ok_or("canonicalize: value outside the strict canonical profile")?,
            history_head: escalation_history_head(g(answered, "lastCounter").as_u64()).ok_or("canonicalize: value outside the strict canonical profile")?,
            render_digest: None,
        };
        let pins: Vec<PinnedSigner> = self.principals.iter().filter_map(pinned).collect();
        if let EscalationVerdict::Refused(r) = verify_escalation_answer(answer, &pins, &bind, now as i64) {
            return Ok(json!({"ok": false, "reason": r}));
        }
        if let Some(f) = self.answer_fault(answer, answered)? {
            return Ok(json!({"ok": false, "reason": f}));
        }
        let cell = cell_key(space, &case_of(answered))?;
        if let Some(ex) = self.live(g(answer, "policy_digest"), &cell, now) {
            if !seq_eq(g(g(ex, "answer"), "decision"), g(answer, "decision")) {
                return Ok(json!({"ok": false, "reason": "conflicts with a recorded decision; revoke it first"}));
            }
        }
        let e = self.push(json!({"kind": "answer", "answer": answer, "answered": answered, "cell": cell, "ceilings": ceilings_of(g(answered, "params"))}))?;
        Ok(json!({"ok": true, "entry": e}))
    }
    /// Record a principal-signed revocation of one recorded answer.
    pub fn revoke(&mut self, rev: &Value) -> Res<Value> {
        if !verify_payload(rev, "precedent-revocation", &self.principals) {
            return Ok(json!({"ok": false, "reason": "bad signature"}));
        }
        let p = g(rev, "payload");
        let found = self.entries.iter().any(|e| {
            st(g(e, "kind")) == "answer"
                && seq_eq(g(e, "digest"), g(p, "target_entry"))
                && seq_eq(g(g(e, "answer"), "policy_digest"), g(p, "policy_digest"))
                && seq_eq(g(e, "cell"), g(p, "cell"))
        });
        if !found {
            return Ok(json!({"ok": false, "reason": "no such precedent"}));
        }
        let e = self.push(json!({"kind": "revocation", "revocation": rev}))?;
        Ok(json!({"ok": true, "entry": e}))
    }
    fn push(&mut self, fields: Value) -> Res<Value> {
        let mut base = Map::new();
        base.insert("seq".into(), json!(self.entries.len()));
        base.insert("prev".into(), json!(self.head()));
        for (k, v) in fields.as_object().into_iter().flatten() {
            base.insert(k.clone(), v.clone());
        }
        let mut entry = Value::Object(base);
        let d = entry_digest(&entry)?;
        entry["digest"] = Value::String(d);
        self.entries.push(entry.clone());
        Ok(entry)
    }
    /// The recorded decision covering this case under this policy, if any (cell match, ceilings respected, unexpired, unrevoked):
    /// `{decision, entry}`.
    pub fn lookup(&self, policy_digest: &Value, space: &Space, c: &Value, now: f64) -> Res<Option<Value>> {
        let e = match self.live(policy_digest, &cell_key(space, c)?, now) {
            Some(e) => e,
            None => return Ok(None),
        };
        let ceil = g(e, "ceilings").as_object().cloned().unwrap_or_default();
        let now2 = ceilings_of(g(g(c, "act"), "params"));
        let now2 = now2.as_object().cloned().unwrap_or_default();
        for (k, v) in &now2 {
            if nm(v) > ceil.get(k).map_or(f64::NEG_INFINITY, nm) {
                return Ok(None); // beyond the signed ceiling
            }
        }
        if ceil.keys().any(|k| !now2.contains_key(k)) {
            return Ok(None); // same parameters and units as the signed witness
        }
        Ok(Some(json!({"decision": g(g(e, "answer"), "decision"), "entry": e})))
    }
}

/// Policy decision refined by precedents. Precedents act only on Escalate (P3, P4); a tampered log fails closed.
/// `{decision, via, precedent?}`.
pub fn authorize_with_precedents(goal: &Value, ont: &Value, policy_digest: &Value, log: &PrecedentLog, c: &Value, now: f64) -> Res<Value> {
    let base = decide_case(goal, ont, c)?["decision"].clone();
    if base != "escalate" {
        return Ok(json!({"decision": base, "via": "policy"}));
    }
    let space = build_space(std::slice::from_ref(goal), &[])?;
    if !log.verify_chain(&space) {
        return Ok(json!({"decision": "escalate", "via": "policy"})); // fail closed on a tampered log
    }
    match log.lookup(policy_digest, &space, c, now)? {
        None => Ok(json!({"decision": "escalate", "via": "policy"})),
        Some(hit) => Ok(json!({"decision": if hit["decision"] == "allow" { "allow" } else { "deny" }, "via": "precedent", "precedent": hit["entry"]})),
    }
}
