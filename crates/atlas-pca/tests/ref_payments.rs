//! Differential replay of the payments package against the TypeScript reference (test-data/ref-payments.json.gz): mandates,
//! the charge decision (the reference's recorded decide() result fed back through the injected decider), the charge PCActn,
//! spend rails, Shared Payment Token limits, the Stripe Issuing adapter and agent network tokens.
//! A reference refusal must be a refusal; its text compares exactly unless it is a JavaScript runtime TypeError or a text of the
//! core canonical encoder / PCActn builder (whose wording is the core's, not this package's). Cases with a lone surrogate (no Rust
//! string) and non-string arguments where Rust takes `&str` are skipped (counted, capped).
mod common;
use atlas_pca::payments::*;
use atlas_pca::serde_json::{json, Value};

fn loose(msg: &str) -> bool {
    msg.contains("Cannot read properties")
        || msg.contains("is not a function")
        || msg.contains("is not iterable")
        || msg.starts_with("canonicalize:")
        || msg.starts_with("buildPCActn:")
}

fn same(want: &Value, got: Result<Value, String>) -> Result<(), String> {
    match (want.get("$throws").and_then(Value::as_str), got) {
        (Some(w), Err(g)) if w == g || loose(w) => Ok(()),
        (None, Ok(g)) if atlas_pca::canonicalize(&bytes(want).map_or_else(|| want.clone(), |b| octets(&b))) == atlas_pca::canonicalize(&g) => Ok(()),
        (_, g) => Err(format!("want {want}, got {g:?}")),
    }
}

fn bytes(v: &Value) -> Option<Vec<u8>> {
    atlas_pca::decode_b64u_strict(v.get("$bytes")?.as_str()?, None)
}

/// Bytes compare as a JSON array of octets (the reference's `{"$bytes"}` is decoded to the same form).
fn octets(b: &[u8]) -> Value {
    Value::Array(b.iter().map(|x| json!(x)).collect())
}

fn opt_str(v: Option<&Value>) -> Result<Option<&str>, ()> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        _ => Err(()),
    }
}

/// None = skip (argument type has no Rust form).
static NULL: Value = Value::Null;

fn run(f: &str, a: &[Value]) -> Option<Result<Value, String>> {
    let g = |i: usize| a.get(i).unwrap_or(&NULL);
    let o = |i: usize| a.get(i);
    let s = |i: usize| g(i).as_str();
    let pe = |r: Result<Value, PayError>| r.map_err(|e| e.message);
    Some(match f {
        "isPlainId" => Ok(json!(is_plain_id(g(0)))),
        "isMinorUnits" => Ok(json!(is_minor_units(g(0)))),
        "mandatePredicates" => mandate_predicates(g(0)),
        "mandateCaveats" => mandate_caveats(g(0)),
        "mandateRiskPolicy" => mandate_risk_policy(g(0), g(1)),
        "autoSpendBound" => auto_spend_bound(g(0)),
        "buildPaymentMandate" => {
            let seed = g(0).get("principalSecret").and_then(bytes).unwrap_or_default();
            build_payment_mandate(g(0), &seed)
        }
        "chargeParams" => charge_params(g(0), g(1)),
        "chargeActionContext" => charge_action_context(g(0), g(1)),
        "chargePlanNode" => charge_plan_node(g(0), g(1), s(2)?),
        "chargeDecideInput" => pe(charge_decide_input(g(0), g(1), g(2), g(3))),
        "authorizeCharge" => {
            let rec = g(3).clone();
            pe(authorize_charge(g(0), g(1), g(2), &move |_| Ok(rec.clone())))
        }
        "chargeToPCActn" => {
            let seed = g(2).get("signerSecret").and_then(bytes).unwrap_or_default();
            charge_to_pcactn(g(0), g(1), g(2), &seed)
        }
        "settleCharge" => settle_charge(g(0), g(1)),
        "applyHumanCosign" => apply_human_cosign(g(0), g(1), o(2)),
        "sharedPaymentTokenLimits" => shared_payment_token_limits(g(0), g(1)),
        "railLimits" => rail_limits(g(0), g(1), o(2)),
        "categoriesFromTraits" => categories_from_traits(g(0)),
        "reconcileSettlement" => reconcile_settlement(g(0), g(1)),
        "verifyStripeSignature" => {
            let tol = g(4).as_f64().unwrap_or(STRIPE_WEBHOOK_TOLERANCE_SEC);
            Ok(json!(verify_stripe_signature(s(0)?, opt_str(o(1)).ok()?, opt_str(o(2)).ok()?, g(3).as_f64()?, tol)))
        }
        "signStripePayload" => Ok(json!(sign_stripe_payload(s(0)?, s(1)?, g(2).as_f64()?))),
        "stripeCardParams" => stripe_card_params(g(0), g(1), g(2), o(3)),
        "stripeAuthorizationFromEvent" => Ok(stripe_authorization_from_event(g(0)).unwrap_or(Value::Null)),
        "stripeIssuingWebhook" => {
            let approved = g(4).clone();
            Ok(stripe_issuing_webhook(
                s(0)?,
                opt_str(o(1)).ok()?,
                opt_str(o(2)).ok()?,
                g(3).as_f64()?,
                None,
                None,
                &move |_| json!({ "approved": approved.clone(), "reasons": [] }),
            ))
        }
        "stripeSettlementFromTransaction" => Ok(stripe_settlement_from_transaction(g(0)).unwrap_or(Value::Null)),
        "looksLikePan" => Ok(json!(looks_like_pan(s(0)?))),
        "tokenRefError" => Ok(json!(token_ref_error(g(0)))),
        "bindingMessage" => binding_message(g(0)).map(|b| octets(&b)),
        "bindNetworkToken" => {
            let seed = g(0).get("holderSecret").and_then(bytes).unwrap_or_default();
            let public = g(0).get("holderPublic").and_then(bytes).unwrap_or_default();
            bind_network_token(g(0), &seed, &public)
        }
        "verifyNetworkTokenBinding" => Ok(json!(verify_network_token_binding(g(0), g(1)))),
        "controlsFromLimits" => controls_from_limits(g(0), g(1)),
        "settlementMetadata" => settlement_metadata(g(0), g(1)),
        "reconcileNetworkSettlement" => reconcile_network_settlement(g(0), g(1)),
        "chargeWithNetworkToken" => {
            let seed = g(3).get("signerSecret").and_then(bytes).unwrap_or_default();
            charge_with_network_token(g(0), g(1), g(2), g(3), &seed)
        }
        other => panic!("unknown fn {other}"),
    })
}

#[test]
fn payments_vectors() {
    let cases = common::ref_cases_seeded("payments");
    let (mut bad, mut skipped) = (Vec::new(), 0usize);
    for c in &cases {
        if c.to_string().contains(common::LONE) {
            skipped += 1;
            continue;
        }
        let f = c["fn"].as_str().unwrap();
        match run(f, c["args"].as_array().unwrap()) {
            None => skipped += 1,
            Some(got) => {
                if let Err(e) = same(&c["out"], got) {
                    bad.push(format!("{}: {e}", c["name"]));
                }
            }
        }
    }
    assert!(skipped * 10 < cases.len(), "too many skipped: {skipped}");
    assert!(bad.is_empty(), "{} of {} differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
