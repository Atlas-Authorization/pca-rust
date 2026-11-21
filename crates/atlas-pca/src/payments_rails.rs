//! The rail-facing pieces of pca-payments that need a caller-supplied provider or store: the real-time rail authorizer
//! (`createRailAuthorizer`), the network-token issuance gate (`issueBoundNetworkToken`, `suspendOnRevoke`) with the generic partner
//! adapters (`visaIntelligentCommerceAdapter`, `mastercardAgentPayAdapter`), the optimistic charge bond (`openChargeBond`) and an
//! in-memory budget store (`memoryChargeBudgetStore`). Values are JSON like the rest of `payments`; the TypeScript is authoritative.
use crate::payments::{authorize_charge_atomic, bind_network_token, controls_from_limits, token_ref_error, ChargeBudgetStore};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

/// A budget store that is missing or returned a malformed record (the reference's `ChargeStoreError`): the `Err(String)` of the atomic
/// charge functions carries its message; this type names it for callers that match on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChargeStoreError(pub String);

impl fmt::Display for ChargeStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ChargeStoreError {}

/// An in-memory [`ChargeBudgetStore`] with a real compare-and-set (tests and single-process use).
#[derive(Default)]
pub struct MemoryChargeBudgetStore(Mutex<HashMap<String, (i64, Value)>>);

/// `memoryChargeBudgetStore`.
pub fn memory_charge_budget_store() -> MemoryChargeBudgetStore {
    MemoryChargeBudgetStore::default()
}

impl ChargeBudgetStore for MemoryChargeBudgetStore {
    fn get(&self, key: &str) -> Result<Option<Value>, String> {
        let m = self.0.lock().map_err(|_| "the budget store is poisoned".to_string())?;
        Ok(m.get(key).map(|(version, budget)| json!({"budget": budget, "version": version})))
    }

    fn compare_and_set(&self, key: &str, expected: Option<i64>, budget: &Value) -> Result<bool, String> {
        let mut m = self.0.lock().map_err(|_| "the budget store is poisoned".to_string())?;
        if m.get(key).map(|(v, _)| *v) != expected {
            return Ok(false);
        }
        m.insert(key.into(), (expected.map_or(0, |v| v + 1), budget.clone()));
        Ok(true)
    }
}

// ---- the real-time rail authorizer ----------------------------------------------------------------------------------------------

/// The instrument a rail card is bound to: `{mandate, grant, budgetKey?}`, or `None` for an unknown instrument.
pub type InstrumentLookup<'a> = &'a dyn Fn(&str) -> Option<Value>;

pub struct RailAuthorizerOptions<'a> {
    pub instruments: InstrumentLookup<'a>,
    pub store: &'a dyn ChargeBudgetStore,
    /// The policy VM decision (`decide`) the atomic charge runs.
    pub decide: &'a dyn Fn(&Value) -> Result<Value, String>,
    /// Answer within this many ms or decline (default 1500; Stripe waits 2000).
    pub latency_budget_ms: f64,
    /// The clock in ms (default the system clock).
    pub now: Option<&'a dyn Fn() -> f64>,
    /// A step-up cannot wait at a card terminal: it is declined, and this hook may notify the principal. Its failure never changes the answer.
    pub on_step_up: Option<&'a dyn Fn(&Value, &Value)>,
}

fn decline(reasons: &[&str]) -> Value {
    json!({"approved": false, "reasons": reasons})
}

/// `createRailAuthorizer`'s verdict function: the single path from a normalised rail request (`{id, instrumentId, amount, currency,
/// merchantId?, mcc?}`) to `{approved, reasons, decision?}`. Total: every failure is a decline. `Err` only for a non-positive latency budget.
///
/// shortcut: the authorizer is synchronous, so the latency budget is checked after the decision rather than by racing it; a late decision
/// may already have debited the budget while the answer is a decline (an under-spend, the safe direction, as in the reference).
pub fn authorize_rail(o: &RailAuthorizerOptions, a: &Value) -> Result<Value, String> {
    if !o.latency_budget_ms.is_finite() || o.latency_budget_ms <= 0.0 {
        return Err("createRailAuthorizer: latencyBudgetMs must be positive".into());
    }
    let clock =
        || o.now.map_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as f64).unwrap_or(0.0), |f| f());
    let t0 = clock();
    let verdict = rail_decision(o, a, clock());
    Ok(if clock() - t0 > o.latency_budget_ms { decline(&["latency_budget_exceeded"]) } else { verdict })
}

fn rail_decision(o: &RailAuthorizerOptions, a: &Value, now: f64) -> Value {
    let id = a.get("id").and_then(Value::as_str).filter(|s| !s.is_empty());
    let instrument = a.get("instrumentId").and_then(Value::as_str);
    let (Some(_), Some(instrument)) = (id, instrument) else { return decline(&["malformed_authorization"]) };
    let amount = a.get("amount").and_then(Value::as_i64).filter(|n| *n > 0);
    let Some(amount) = amount else { return decline(&["amount_not_positive_minor_units"]) };
    let Some(currency) = a.get("currency").and_then(Value::as_str).filter(|c| !c.is_empty()) else { return decline(&["currency_missing"]) };
    let Some(merchant) = a.get("merchantId").and_then(Value::as_str).filter(|m| !m.is_empty()) else { return decline(&["merchant_unknown"]) };
    let Some(inst) = (o.instruments)(instrument) else { return decline(&["instrument_unknown"]) };
    let mut charge = json!({"merchant": merchant, "amount": amount, "currency": currency.to_uppercase(), "now": now});
    if let Some(mcc) = a.get("mcc").and_then(Value::as_str) {
        charge["category"] = json!(mcc);
    }
    let key = inst.get("budgetKey").and_then(Value::as_str);
    let d = match authorize_charge_atomic(&inst["mandate"], &charge, &inst["grant"], o.store, o.decide, key) {
        Ok(d) => d,
        Err(_) => return decline(&["authorizer_error"]),
    };
    let reasons: Vec<Value> = d["reasons"].as_array().cloned().unwrap_or_default();
    match d["outcome"].as_str() {
        Some("auto") => json!({"approved": true, "reasons": [], "decision": d}),
        Some("step_up") => {
            if let Some(f) = o.on_step_up {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(a, &d)));
            }
            let mut rs = vec![json!("step_up_required")];
            rs.extend(reasons);
            json!({"approved": false, "reasons": rs, "decision": d})
        }
        _ => {
            let rs = if reasons.is_empty() { vec![json!("denied")] } else { reasons };
            json!({"approved": false, "reasons": rs, "decision": d})
        }
    }
}

// ---- network tokens -------------------------------------------------------------------------------------------------------------

/// A network-token provider (the reference's `NetworkTokenProvider`): issue a token whose own controls equal `controls`, suspend it.
pub trait NetworkTokenProvider {
    fn id(&self) -> &str;
    /// The opaque `token_ref` of a token issued with `controls` for `agent_id`.
    fn issue(&self, controls: &Value, agent_id: &str) -> Result<String, String>;
    /// Suspend the token (grant revoked). Must be idempotent.
    fn suspend(&self, token_ref: &str, reason: &str) -> Result<(), String>;
}

/// Issuance gate: PCA authorises an issuance only with controls no wider than the rail `limits`, and binds the provider's reference
/// (refused when malformed or PAN-shaped) to the grant and the holder. Returns `{binding, controls}`.
pub fn issue_bound_network_token(
    provider: &dyn NetworkTokenProvider,
    limits: &Value,
    grant: &Value,
    agent_id: &str,
    holder_seed: &[u8],
    holder_public: &[u8],
    issuer_nonce: &str,
) -> Result<Value, String> {
    let controls = controls_from_limits(limits, grant)?;
    let token_ref = provider.issue(&controls, agent_id)?;
    if let Some(e) = token_ref_error(&json!(token_ref)) {
        return Err(format!("bindNetworkToken: {e}"));
    }
    let binding = bind_network_token(
        &json!({"provider": provider.id(), "tokenRef": token_ref, "grant": grant, "issuerNonce": issuer_nonce}),
        holder_seed,
        holder_public,
    )?;
    Ok(json!({"binding": binding, "controls": controls}))
}

/// Grant revoked: suspend. A provider error propagates (a failed suspend is not a success).
pub fn suspend_on_revoke(provider: &dyn NetworkTokenProvider, binding: &Value) -> Result<(), String> {
    provider.suspend(binding.get("token_ref").and_then(Value::as_str).unwrap_or(""), "grant_revoked")
}

/// The transport of a partner adapter: POST a JSON body to a path.
pub trait PartnerTransport {
    fn post(&self, path: &str, body: &Value) -> Result<Value, String>;
}

/// A generic partner adapter. LABEL: GENERIC MAPPING, NOT THE PARTNER WIRE FORMAT: the path and body names are placeholders; the control
/// VALUES are exact copies of PCA's limits.
pub struct PartnerAdapter<T: PartnerTransport> {
    id: &'static str,
    scope_key: &'static str,
    transport: T,
}

impl<T: PartnerTransport> NetworkTokenProvider for PartnerAdapter<T> {
    fn id(&self) -> &str {
        self.id
    }

    fn issue(&self, controls: &Value, agent_id: &str) -> Result<String, String> {
        let mut scope = serde_json::Map::new();
        scope.insert("currency".into(), controls["currency"].clone());
        scope.insert("per_authorization_max".into(), controls["perAuthorizationMax"].clone());
        scope.insert("total_max".into(), controls["totalMax"].clone());
        scope.insert("merchant_categories".into(), controls["categories"].clone());
        scope.insert("merchants".into(), controls["merchants"].clone());
        if let Some(e) = controls.get("expiresAt") {
            scope.insert("expires_at".into(), e.clone());
        }
        let mut body = serde_json::Map::new();
        body.insert("agent_id".into(), json!(agent_id));
        body.insert(self.scope_key.into(), Value::Object(scope));
        body.insert("metadata".into(), controls["metadata"].clone());
        let r = self.transport.post("/tokens", &Value::Object(body))?;
        let reference = r.get("token_ref").cloned().unwrap_or(Value::Null);
        if let Some(e) = token_ref_error(&reference) {
            return Err(format!("{}: provider returned {e}", self.id));
        }
        Ok(reference.as_str().unwrap_or_default().to_string())
    }

    fn suspend(&self, token_ref: &str, reason: &str) -> Result<(), String> {
        let enc: String = token_ref
            .bytes()
            .map(|b| if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
            .collect();
        self.transport.post(&format!("/tokens/{enc}/suspend"), &json!({"reason": reason})).map(|_| ())
    }
}

/// Visa Intelligent Commerce, generic mapping (partner-gated; unverified field names).
pub fn visa_intelligent_commerce_adapter<T: PartnerTransport>(transport: T) -> PartnerAdapter<T> {
    PartnerAdapter { id: "visa_ic", scope_key: "instructions", transport }
}

/// Mastercard Agent Pay (agentic tokens over MDES), generic mapping (partner-gated; unverified field names).
pub fn mastercard_agent_pay_adapter<T: PartnerTransport>(transport: T) -> PartnerAdapter<T> {
    PartnerAdapter { id: "mastercard_agent_pay", scope_key: "session_scope", transport }
}

// ---- the optimistic charge bond ---------------------------------------------------------------------------------------------------

/// `openChargeBond`: the optimistic bonded claim for a charge (the dispute / refund window, cryptographically adjudicated). A thin
/// wrapper over [`crate::optimistic::open_optimistic`]; REFUSES an irreversible charge.
pub fn open_charge_bond(pcactn: &Value, opts: &Value, signer_seed: &[u8]) -> Result<Value, String> {
    crate::optimistic::open_optimistic(pcactn, opts, signer_seed, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Fake(RefCell<Vec<(String, Value)>>, &'static str);
    impl PartnerTransport for Fake {
        fn post(&self, path: &str, body: &Value) -> Result<Value, String> {
            self.0.borrow_mut().push((path.into(), body.clone()));
            Ok(json!({"token_ref": self.1}))
        }
    }

    #[test]
    fn memory_store_is_a_real_compare_and_set() {
        let s = memory_charge_budget_store();
        assert!(s.get("k").unwrap().is_none());
        assert!(!s.compare_and_set("k", Some(0), &json!({})).unwrap());
        assert!(s.compare_and_set("k", None, &json!({"B": 1})).unwrap());
        assert!(!s.compare_and_set("k", None, &json!({})).unwrap());
        assert!(s.compare_and_set("k", Some(0), &json!({"B": 2})).unwrap());
        assert_eq!(s.get("k").unwrap().unwrap()["version"], 1);
    }

    #[test]
    fn partner_adapters_map_limits_and_refuse_a_pan() {
        let t = Fake(RefCell::new(vec![]), "tok_ref_1234567890");
        let v = visa_intelligent_commerce_adapter(t);
        let controls = json!({"currency": "USD", "perAuthorizationMax": 100, "totalMax": 500, "categories": ["5734"], "merchants": ["m1"], "metadata": {"grant_digest": "g"}});
        assert_eq!(v.issue(&controls, "agent").unwrap(), "tok_ref_1234567890");
        assert_eq!(v.id(), "visa_ic");
        let sent = v.transport.0.borrow();
        assert_eq!(sent[0].0, "/tokens");
        assert_eq!(sent[0].1["instructions"]["per_authorization_max"], 100);
        drop(sent);
        v.suspend("a b", "grant_revoked").unwrap();
        assert_eq!(v.transport.0.borrow()[1].0, "/tokens/a%20b/suspend");
        let pan = mastercard_agent_pay_adapter(Fake(RefCell::new(vec![]), "4111111111111111"));
        assert!(pan.issue(&controls, "agent").is_err());
    }

    #[test]
    fn rail_authorizer_declines_on_malformed_input_and_unknown_instruments() {
        let store = memory_charge_budget_store();
        let decide = |_: &Value| -> Result<Value, String> { Err("unused".into()) };
        let lookup = |_: &str| None;
        let o = RailAuthorizerOptions { instruments: &lookup, store: &store, decide: &decide, latency_budget_ms: 1500.0, now: None, on_step_up: None };
        let r = |v: Value| authorize_rail(&o, &v).unwrap()["reasons"][0].as_str().unwrap().to_string();
        assert_eq!(r(json!({"id": "", "instrumentId": "i"})), "malformed_authorization");
        assert_eq!(r(json!({"id": "a", "instrumentId": "i", "amount": 0, "currency": "usd", "merchantId": "m"})), "amount_not_positive_minor_units");
        assert_eq!(r(json!({"id": "a", "instrumentId": "i", "amount": 5, "currency": "", "merchantId": "m"})), "currency_missing");
        assert_eq!(r(json!({"id": "a", "instrumentId": "i", "amount": 5, "currency": "usd"})), "merchant_unknown");
        assert_eq!(r(json!({"id": "a", "instrumentId": "i", "amount": 5, "currency": "usd", "merchantId": "m"})), "instrument_unknown");
        let bad = RailAuthorizerOptions { latency_budget_ms: 0.0, ..o };
        assert!(authorize_rail(&bad, &json!({})).is_err());
    }
}
