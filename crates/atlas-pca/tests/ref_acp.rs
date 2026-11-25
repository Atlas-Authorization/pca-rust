//! Differential replay of ACP delegated payment tokens, x402 v1 and v2 (and its HTTP transport) and Stripe Shared Payment Granted
//! Tokens against the TypeScript reference (test-data/ref-acp.json.gz). Stores, verifiers and settle steps are built from the specs
//! the corpus names ("once" / "always" / "never" / "throw" / "truthy" stores; "throw" / constant verifiers; "echo" / "value" /
//! "throw" / "undef" settle steps). A reference throw only requires a refusal. Cases holding a lone surrogate (no Rust string) are
//! skipped (capped below 10%). Result reasons that embed a library message are cut after the package's own prefix, as the corpus does.
mod common;
use atlas_pca::acp::*;
use atlas_pca::serde_json::{json, Map, Value};
use std::cell::RefCell;
use std::collections::HashSet;

fn norm(mut r: Value) -> Value {
    let reason = r.get("reason").and_then(Value::as_str).map(str::to_owned);
    if let Some(reason) = reason {
        for p in ["token signature did not verify", "bound proof failed to verify"] {
            if reason.starts_with(&format!("{p}: ")) {
                r["reason"] = json!(p);
            }
        }
    }
    if let Some(pr) = r.get("pcaResult").cloned() {
        r["pcaResult"] = json!({ "allow": pr["allow"] });
    }
    r
}

/// Run `call(store)` `times` times over the SAME store; one result when times == 1, else the list.
fn with_store(opts: &Value, times: u64, call: &dyn Fn(Option<ClaimFn>) -> Result<Value, String>) -> Result<Value, String> {
    let spec = opts.get("singleUse").and_then(Value::as_str).unwrap_or("");
    let seen = RefCell::new(HashSet::new());
    let claim = |jti: &str, _exp: &Value| -> Result<Value, String> {
        match spec {
            "once" => Ok(json!(seen.borrow_mut().insert(jti.to_string()))),
            "always" => Ok(json!(true)),
            "never" => Ok(json!(false)),
            "throw" => Err("store down".into()),
            _ => Ok(json!(1)),
        }
    };
    let store: Option<ClaimFn> = if ["once", "always", "never", "throw", "truthy"].contains(&spec) { Some(&claim) } else { None };
    let mut rs = Vec::new();
    for _ in 0..times {
        rs.push(norm(call(store)?));
    }
    Ok(if times == 1 { rs.remove(0) } else { Value::Array(rs) })
}

fn strs(v: Vec<String>) -> Result<Value, String> {
    Ok(json!(v))
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let arg = |i: usize| a.get(i);
    let null = Value::Null;
    let a0 = a.first().unwrap_or(&null);
    let a1 = a.get(1).unwrap_or(&null);
    match f {
        "constants" => Ok(json!({
            "v": ACP_DELEGATED_TOKEN_VERSION, "t": ACP_DELEGATED_TOKEN_TYPE, "s": SPEND_CAP_CAVEAT, "m": MERCHANT_ALLOW_CAVEAT,
            "c": MERCHANT_CATEGORY_CAVEAT, "h": HUMAN_PRESENT_CAVEAT, "x1": X402_VERSION_1, "x2": X402_VERSION_2,
            "sup": X402_SUPPORTED_VERSIONS, "pr": X402_V2_PAYMENT_REQUIRED_HEADER, "ps": X402_PAYMENT_SIGNATURE_HEADER,
            "pe": X402_PAYMENT_RESPONSE_HEADER, "st": x402_http_status(), "spt": STRIPE_SPT_OBJECT,
        })),
        "spendCapCaveat" => Ok(spend_cap_caveat(a0, arg(1))),
        "merchantAllowCaveat" => merchant_allow_caveat(a0),
        "merchantCategoryCaveat" => merchant_category_caveat(a0),
        "humanPresentCaveat" => Ok(human_present_caveat(arg(0))),
        "extractPaymentAuthority" => extract_payment_authority(arg(0)),
        "checkPaymentAuthority" => check_payment_authority(a0, a1),
        "mintDelegatedPaymentToken" => mint_delegated_payment_token(a0, a1).map(Value::String),
        "verifyDelegatedPaymentToken" => {
            let times = arg(2).and_then(Value::as_u64).unwrap_or(1);
            with_store(a1, times, &|store| verify_delegated_payment_token(a0, a1, store))
        }
        "x402Challenge" => x402_challenge(a0, a1),
        "x402ChallengeV2" => x402_challenge_v2(arg(0), a1),
        "x402Settle" => {
            let verify = |_p: &Value| -> Result<Value, String> {
                if a1 == "throw" {
                    Err("verify down".into())
                } else {
                    Ok(a1.clone())
                }
            };
            let sspec = arg(2).and_then(Value::as_str);
            let echo = |p: &Value, c: &Value| -> Result<Option<Value>, String> {
                if c.is_null() {
                    return Err("Cannot read properties of null (reading 'jti')".into());
                }
                let mut o = Map::new();
                if let Some(j) = c.get("jti") {
                    o.insert("jti".into(), j.clone());
                }
                if let Some(t) = p.get("token") {
                    o.insert("token".into(), t.clone());
                }
                Ok(Some(Value::Object(o)))
            };
            let value = |_p: &Value, _c: &Value| -> Result<Option<Value>, String> { Ok(Some(json!("receipt-1"))) };
            let boom = |_p: &Value, _c: &Value| -> Result<Option<Value>, String> { Err("settle down".into()) };
            let undef = |_p: &Value, _c: &Value| -> Result<Option<Value>, String> { Ok(None) };
            let settle: Option<&dyn Fn(&Value, &Value) -> Result<Option<Value>, String>> = match sspec {
                Some("echo") => Some(&echo),
                Some("value") => Some(&value),
                Some("throw") => Some(&boom),
                Some("undef") => Some(&undef),
                _ => None,
            };
            x402_settle(a0, &verify, settle)
        }
        "acpX402Verifier" => {
            let times = arg(2).and_then(Value::as_u64).unwrap_or(1);
            with_store(a1, times, &|store| acp_x402_verify(a0, a1, store))
        }
        "toAcpAllowance" => to_acp_allowance(a0),
        "resourceInfoProblems" => strs(resource_info_problems(arg(0))),
        "requirementV2Problems" => strs(requirement_v2_problems(arg(0))),
        "paymentRequiredV2Problems" => strs(payment_required_v2_problems(arg(0))),
        "paymentPayloadV2Problems" => strs(payment_payload_v2_problems(arg(0))),
        "settlementResponseProblems" => strs(settlement_response_problems(arg(0))),
        "stripeSptProblems" => strs(stripe_spt_problems(arg(0))),
        "encodePaymentRequiredHeader" => encode_payment_required_header(a0).map(Value::String),
        "decodePaymentRequiredHeader" => decode_payment_required_header(arg(0)),
        "encodePaymentSignatureHeader" => encode_payment_signature_header(a0).map(Value::String),
        "decodePaymentSignatureHeader" => decode_payment_signature_header(arg(0)),
        "encodePaymentResponseHeader" => encode_payment_response_header(a0).map(Value::String),
        "decodePaymentResponseHeader" => decode_payment_response_header(arg(0)),
        "x402Negotiate" => x402_negotiate(arg(0), arg(1)),
        "x402AcceptedMatches" => x402_accepted_matches(a0, a1).map(|b| json!(b)),
        "normalizeX402Payload" => Ok(normalize_x402_payload(a0)),
        "readPaymentSignature" => read_payment_signature(a0),
        "x402SettlementResponse" => x402_settlement_response(a0, arg(1)),
        "x402PaymentSignatureHeaders" => x402_payment_signature_headers(a0),
        "parseStripeSpt" => parse_stripe_spt(a0),
        "stripeSptUsable" => stripe_spt_usable(a0, a1),
        "stripeUsageLimitsFor" => stripe_usage_limits_for(a0),
        "stripeSptWithinClaims" => stripe_spt_within_claims(a0, a1),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn acp_vectors() {
    let cases = common::ref_cases_seeded("acp");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let f = c["fn"].as_str().unwrap();
        let got = std::panic::catch_unwind(|| run(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {got:?}", c["name"], c["out"]));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} lone-surrogate cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
