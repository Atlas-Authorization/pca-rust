//! Differential replay of the AP2 mandate package (strict SD-JWT parsing and disclosure processing, ES256, mandate validators and
//! minor units, open-mandate constraint evaluation, issuance / presentation / verification of delegation chains, purchases and the
//! redeem ledger, the PCA terms bridge, settlement payloads) against the TypeScript reference (test-data/ref-ap2.json.gz).
//!
//! Keys are derived from labels (d = sha256("atlas-pca-conformance/ap2/<label>")); ECDSA signatures are randomized in the reference,
//! so every signing function is compared with each signature segment replaced by "SIG". Salts are the oracle's counter
//! ("salt-000000000001" base64url). A reference throw only requires a refusal. Cases holding a lone surrogate (no Rust string) are
//! skipped (capped below 10%). `verifyPcaBinding` is not part of the corpus.
mod common;
use atlas_pca::ap2::*;
use atlas_pca::serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;

const T0: i64 = 1_800_000_000;

fn d_for(label: &str) -> [u8; 32] {
    Sha256::digest(format!("atlas-pca-conformance/ap2/{label}").as_bytes()).into()
}

fn priv_of(label: &str) -> Value {
    p256_private_jwk(&d_for(label), Some(label)).expect("key")
}

fn key_for(label: &str) -> Value {
    ap2_key_pair_from_private_jwk(&priv_of(label)).expect("key pair")
}

fn nokid(jwk: &Value) -> Value {
    Value::Object(jwk.as_object().map(|m| m.iter().filter(|(k, _)| *k != "kid").map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default())
}

fn counter_salt() -> Salt<'static> {
    let mut n = 0u64;
    Box::new(move || {
        n += 1;
        Ok(b64u_encode(format!("salt-{n:012}").as_bytes()))
    })
}

fn strip_sig(t: &str) -> String {
    let is_jwt = |s: &str| {
        let p: Vec<&str> = s.split('.').collect();
        p.len() == 3 && p.iter().all(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    };
    t.split('~').map(|s| if is_jwt(s) { format!("{}.SIG", &s[..s.rfind('.').unwrap_or(0)]) } else { s.to_string() }).collect::<Vec<_>>().join("~")
}

fn mask_reason(s: &str) -> String {
    match s.find("invalid JSON (") {
        Some(i) if s.ends_with(')') => format!("{}invalid JSON (*)", &s[..i]),
        _ => s.to_string(),
    }
}

fn mask(mut v: Value) -> Value {
    if let Some(r) = v.get("reason").and_then(Value::as_str).map(mask_reason) {
        v["reason"] = json!(r);
    }
    v
}

fn proj_chain(r: &ChainResult) -> Value {
    mask(match r {
        Ok(c) => c.to_value(),
        Err(f) => f.to_value(),
    })
}

fn proj_purchase(r: &Result<Purchase, String>) -> Value {
    match r {
        Ok(p) => p.to_value(),
        Err(e) => json!({ "ok": false, "reason": mask_reason(e) }),
    }
}

fn resolver(m: Option<&Value>) -> impl Fn(&Map<String, Value>) -> Result<Option<Value>, String> + '_ {
    move |h: &Map<String, Value>| Ok(m.and_then(Value::as_object).and_then(|mm| h.get("kid").and_then(Value::as_str).and_then(|k| mm.get(k))).cloned())
}

fn text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(o) => o.to_string(),
        None => "undefined".to_string(),
    }
}

fn non_null<'a>(c: &'a Value, k: &str) -> Option<&'a Value> {
    c.get(k).filter(|v| !v.is_null())
}

fn or_str<'a>(v: Option<&'a Value>, default: &'a str) -> &'a str {
    v.and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or(default)
}

fn s(v: Option<&Value>) -> &str {
    v.and_then(Value::as_str).unwrap_or("")
}

fn strs(v: Vec<String>) -> Result<Value, String> {
    Ok(json!(v))
}

fn str_list(v: Option<&Value>) -> Result<Vec<String>, String> {
    v.and_then(Value::as_array).ok_or("not an array")?.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| "not a string".to_string())).collect()
}

fn chain_opts<'a>(c: &Value, ir: KeyResolver<'a>, mr: KeyResolver<'a>) -> ChainOpts<'a> {
    ChainOpts {
        resolve_issuer_key: Some(ir),
        resolve_merchant_key: Some(mr),
        expected_audience: c.get("expectedAudience").cloned(),
        expected_nonce: c.get("expectedNonce").cloned(),
        now: non_null(c, "now").and_then(Value::as_f64),
        clock_skew_seconds: non_null(c, "clockSkewSeconds").and_then(Value::as_f64),
        ..ChainOpts::default()
    }
}

fn purchase_opts<'a>(c: &Value, ir: KeyResolver<'a>, mr: KeyResolver<'a>) -> PurchaseOpts<'a> {
    PurchaseOpts {
        resolve_issuer_key: Some(ir),
        resolve_merchant_key: Some(mr),
        checkout: c.get("checkout").cloned(),
        payment: c.get("payment").cloned(),
        context: non_null(c, "context").cloned(),
        now: non_null(c, "now").and_then(Value::as_f64),
        clock_skew_seconds: non_null(c, "clockSkewSeconds").and_then(Value::as_f64),
    }
}

struct Ledger {
    spec: Value,
    calls: RefCell<Vec<Value>>,
}

impl RedeemLedger for Ledger {
    fn reserve(&self, open_mandate_hash: &str, transaction_id: &Value, amount_minor: &Value) -> Result<Option<Value>, String> {
        self.calls.borrow_mut().push(json!(["reserve", open_mandate_hash, transaction_id, amount_minor]));
        match self.spec.get("mode").and_then(Value::as_str) {
            Some("throw") => Err("down".into()),
            Some("replayed") => Ok(Some(json!("replayed"))),
            Some("undefined") => Ok(None),
            _ => Ok(Some(non_null(&self.spec, "ctx").cloned().unwrap_or_else(|| json!({ "totalAmount": 0, "totalUses": 0 })))),
        }
    }

    fn release(&self, open_mandate_hash: &str, transaction_id: &Value) -> Result<(), String> {
        self.calls.borrow_mut().push(json!(["release", open_mandate_hash, transaction_id]));
        if self.spec.get("releaseThrows").is_some_and(|v| v == &json!(true)) {
            Err("release failed".into())
        } else {
            Ok(())
        }
    }
}

fn mk_open_input(a: &Value) -> Value {
    let mut issuer = Map::new();
    issuer.insert("privateKey".into(), key_for(or_str(a.get("issuerKey"), "issuer"))["privateKey"].clone());
    for k in ["kid", "x5c"] {
        if let Some(v) = non_null(a, k) {
            issuer.insert(k.into(), v.clone());
        }
    }
    let agent = match non_null(a, "agentJwk") {
        Some(j) => j.clone(),
        None => nokid(&key_for(or_str(a.get("agentKey"), "agent"))["publicJwk"]),
    };
    let mut i = Map::new();
    i.insert("issuer".into(), Value::Object(issuer));
    i.insert("agentJwk".into(), agent);
    i.insert("iat".into(), a.get("iat").cloned().unwrap_or(Value::Null));
    i.insert("exp".into(), a.get("exp").cloned().unwrap_or(Value::Null));
    for k in ["pca", "sdAlg", "typ"] {
        if let Some(v) = non_null(a, k) {
            i.insert(k.into(), v.clone());
        }
    }
    i.insert("constraints".into(), a.get("constraints").cloned().unwrap_or(Value::Null));
    Value::Object(i)
}

fn with_members(mut i: Value, a: &Value, members: &[(&str, &str)]) -> Value {
    for (key, member) in members {
        if let Some(v) = non_null(a, key) {
            i[*member] = v.clone();
        }
    }
    i
}

fn present_hop_in(a: &Value) -> Value {
    let mut i = json!({
        "open": a.get("open").cloned().unwrap_or(Value::Null),
        "agentKey": key_for(or_str(a.get("agentKey"), "agent")),
        "aud": a.get("aud").cloned().unwrap_or(Value::Null),
        "nonce": a.get("nonce").cloned().unwrap_or(Value::Null),
        "iat": a.get("iat").cloned().unwrap_or(Value::Null),
    });
    for k in ["exp", "pca", "hashMode"] {
        if let Some(v) = non_null(a, k) {
            i[k] = v.clone();
        }
    }
    i
}

fn from_in(a: &Value) -> Value {
    let merch = json!({ "id": "merchant_1", "name": "Demo Merchant", "website": "https://demo-merchant.example" });
    let merch2 = json!({ "id": "merchant_2", "name": "Other Merchant" });
    let mut o = json!({
        "issuer": { "privateKey": key_for("issuer")["privateKey"], "kid": "issuer-1" },
        "agentJwk": nokid(&key_for("agent")["publicJwk"]),
        "merchants": non_null(a, "merchants").cloned().unwrap_or_else(|| json!([merch, merch2])),
        "iat": non_null(a, "iat").cloned().unwrap_or_else(|| json!(T0)),
    });
    if let Some(e) = non_null(a, "exp") {
        o["exp"] = e.clone();
    }
    o
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let arg = |i: usize| a.get(i);
    let null = Value::Null;
    let a0 = a.first().unwrap_or(&null);
    let a1 = a.get(1).unwrap_or(&null);
    let alg_of = |v: Option<&Value>| -> Result<Option<String>, String> {
        match v {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(x)) => Ok(Some(x.clone())),
            _ => Err("unsupported hash algorithm".into()),
        }
    };
    match f {
        "b64uEncode" => {
            let bytes = match a0 {
                Value::Object(m) if m.contains_key("$bytes") => common::b64d(s(m.get("$bytes"))),
                other => s(Some(other)).as_bytes().to_vec(),
            };
            Ok(json!(b64u_encode(&bytes)))
        }
        "b64uDecode" => {
            a0.as_str().ok_or_else(|| "not base64url".to_string()).and_then(|x| b64u_decode(x, &text(arg(1)))).map(|b| json!({ "$bytes": b64u_encode(&b) }))
        }
        "parseJson" => parse_json(a0.as_str().ok_or("not a string")?, &text(arg(1))),
        "isSdAlg" => Ok(json!(is_sd_alg(arg(0)))),
        "sdDigest" => {
            let alg = match arg(1) {
                None => "sha-256".to_string(),
                Some(Value::String(x)) => x.clone(),
                _ => return Err("unsupported hash algorithm".into()),
            };
            sd_digest(a0.as_str().ok_or("digest input must be ASCII")?, &alg).map(Value::String)
        }
        "assertP256Jwk" => assert_p256_jwk(arg(0), &text(arg(1))),
        "jwkThumbprint" => jwk_thumbprint(arg(0)).map(Value::String),
        "ap2KeyPairFromPrivateJwk" => {
            let mut jwk = priv_of(a0.as_str().ok_or("label")?).as_object().cloned().unwrap_or_default();
            jwk.extend(a1.as_object().cloned().unwrap_or_default());
            ap2_key_pair_from_private_jwk(&Value::Object(jwk)).map(|k| k["publicJwk"].clone())
        }
        "parseSdJwtHop" => parse_sd_jwt_hop(a0.as_str().ok_or("SD-JWT: empty")?).map(|h| h.to_value()),
        "hopSdJwt" => parse_sd_jwt_hop(a0.as_str().ok_or("SD-JWT: empty")?).map(|h| json!(hop_sd_jwt(&h))),
        "sdHashOf" => sd_hash_of(&parse_sd_jwt_hop(s(Some(a0)))?, alg_of(arg(1))?.as_deref()).map(Value::String),
        "issuerJwtHashOf" => issuer_jwt_hash_of(&parse_sd_jwt_hop(s(Some(a0)))?, alg_of(arg(1))?.as_deref()).map(Value::String),
        "processDisclosures" => match a0 {
            Value::String(t) => {
                let h = parse_sd_jwt_hop(t)?;
                process_disclosures(&Value::Object(h.payload.clone()), &h.disclosures, &h.sd_alg)
            }
            _ => process_disclosures(a0, &str_list(arg(1))?, a.get(2).and_then(Value::as_str).unwrap_or("?")),
        },
        "splitChain" => split_chain(a0.as_str().unwrap_or("")).map(|v| json!(v)),
        "disclosureBuilder" => {
            let mut b = disclosure_builder(arg(0), Some(counter_salt()));
            let mut results = Vec::new();
            for op in a1.as_array().ok_or("ops")? {
                if op["kind"] == "element" {
                    results.push(b.element(&op["value"])?);
                } else {
                    results.push(json!(b.property(s(op.get("name")), &op["value"])?));
                }
            }
            Ok(json!({ "results": results, "disclosures": b.disclosures }))
        }
        "parseJwt" => parse_jwt(a0.as_str().ok_or("expected a string")?, &text(arg(1))).map(|j| j.to_value()),
        "verifyJwtEs256" => verify_jwt_es256(&parse_jwt(a0.as_str().ok_or("expected a string")?, "jwt")?, arg(1)).map(|b| json!(b)),
        "verifyHopSignature" => verify_hop_signature(&parse_sd_jwt_hop(s(Some(a0)))?, arg(1)).map(|b| json!(b)),
        "signSdJwt" => {
            let key = key_for(s(a0.get("key")))["privateKey"].clone();
            sign_sd_jwt(a0.get("header"), a0.get("payload").unwrap_or(&null), &str_list(a0.get("disclosures"))?, Some(&key)).map(|t| json!(strip_sig(&t)))
        }
        "signJwtEs256" => {
            let key = key_for(s(a0.get("key")))["privateKey"].clone();
            sign_jwt_es256(a0.get("header"), a0.get("payload").unwrap_or(&null), Some(&key)).map(|t| json!(strip_sig(&t)))
        }
        "currencyExponent" => currency_exponent(arg(0)).map(|e| json!(e)),
        "toMinorUnits" => to_minor_units(arg(0), arg(1)),
        "fromMinorUnits" => from_minor_units(arg(0), arg(1)),
        "openPaymentMandateProblems" => strs(open_payment_mandate_problems(arg(0))),
        "paymentMandateProblems" => strs(payment_mandate_problems(arg(0))),
        "openCheckoutMandateProblems" => strs(open_checkout_mandate_problems(arg(0))),
        "checkoutMandateProblems" => strs(checkout_mandate_problems(arg(0))),
        "assertValid" => {
            let p: fn(Option<&Value>) -> Vec<String> = match a0.as_str() {
                Some("openPaymentMandateProblems") => open_payment_mandate_problems,
                Some("paymentMandateProblems") => payment_mandate_problems,
                Some("openCheckoutMandateProblems") => open_checkout_mandate_problems,
                _ => checkout_mandate_problems,
            };
            assert_valid(arg(1), p, &text(arg(2)))
        }
        "constants" => Ok(json!({
            "VCT_CHECKOUT": VCT_CHECKOUT, "VCT_CHECKOUT_OPEN": VCT_CHECKOUT_OPEN, "VCT_PAYMENT": VCT_PAYMENT, "VCT_PAYMENT_OPEN": VCT_PAYMENT_OPEN,
            "PCA_CLAIM": PCA_CLAIM, "FREQUENCIES": FREQUENCIES, "AP2_COMMIT": AP2_COMMIT, "PCA_BINDING_VERSION": PCA_BINDING_VERSION,
            "TYP_TERMINAL": TYP_TERMINAL, "TYP_INTERMEDIATE": TYP_INTERMEDIATE,
        })),
        "merchantMatches" => merchant_matches(arg(0), arg(1)).map(|b| json!(b)),
        "checkPaymentConstraints" => {
            let o = a.get(2).unwrap_or(&null);
            let now = o.get("now").and_then(Value::as_f64).ok_or("now")?;
            strs(check_payment_constraints(arg(0), arg(1), &PayCtx { open_checkout_hash: o.get("openCheckoutHash"), context: o.get("context"), now })?)
        }
        "projectCheckout" => project_checkout(arg(0)),
        "checkoutTotal" => checkout_total(arg(0)).map(|t| t.unwrap_or(Value::Null)),
        "checkCheckoutConstraints" => strs(check_checkout_constraints(arg(0), a1)?),
        "verifyDelegationChain" => {
            let (ir, mr) = (resolver(a1.get("issuerKeys")), resolver(a1.get("merchantKeys")));
            Ok(proj_chain(&verify_delegation_chain(a0.as_str().unwrap_or(""), &chain_opts(a1, &ir, &mr))))
        }
        "verifyKbHop" => {
            let (hop, prev) = (parse_sd_jwt_hop(s(Some(a0)))?, parse_sd_jwt_hop(s(Some(a1)))?);
            let op = a.get(3).unwrap_or(&null);
            let kb = KbOpts {
                terminal: op.get("terminal").is_some_and(|t| t == &json!(true)),
                expected_audience: op.get("expectedAudience"),
                expected_nonce: op.get("expectedNonce"),
                now: op.get("now").and_then(Value::as_f64).ok_or("now")?,
                skew: op.get("skew").and_then(Value::as_f64).ok_or("skew")?,
            };
            verify_kb_hop(&hop, &prev, a.get(2).unwrap_or(&null), &kb, &text(a.get(4))).map(|h| h.to_value())
        }
        "verifyCheckoutChain" => {
            let (ir, mr) = (resolver(a1.get("issuerKeys")), resolver(a1.get("merchantKeys")));
            Ok(proj_chain(&verify_checkout_chain(a0.as_str().unwrap_or(""), &chain_opts(a1, &ir, &mr))))
        }
        "verifyPaymentChain" => {
            let (ir, mr) = (resolver(a1.get("issuerKeys")), resolver(a1.get("merchantKeys")));
            let mut o = chain_opts(a1, &ir, &mr);
            o.open_checkout_hash = a1.get("openCheckoutHash").cloned();
            o.context = non_null(a1, "context").cloned();
            o.expected_transaction_id = non_null(a1, "expectedTransactionId").cloned();
            Ok(proj_chain(&verify_payment_chain(a0.as_str().unwrap_or(""), &o)))
        }
        "verifyPurchase" => {
            let c = a.get(2).unwrap_or(&null);
            let (ir, mr) = (resolver(c.get("issuerKeys")), resolver(c.get("merchantKeys")));
            Ok(proj_purchase(&verify_purchase(a0.as_str().unwrap_or(""), a1.as_str().unwrap_or(""), &purchase_opts(c, &ir, &mr))))
        }
        "redeemPurchase" => {
            let c = a.get(2).unwrap_or(&null);
            let spec = a.get(3).unwrap_or(&null);
            let (ir, mr) = (resolver(c.get("issuerKeys")), resolver(c.get("merchantKeys")));
            let ledger = Ledger { spec: spec.clone(), calls: RefCell::new(Vec::new()) };
            let r = redeem_purchase(
                a0.as_str().unwrap_or(""),
                a1.as_str().unwrap_or(""),
                &purchase_opts(c, &ir, &mr),
                if spec == "none" { None } else { Some(&ledger) },
            );
            Ok(json!({ "result": proj_purchase(&r), "calls": ledger.calls.into_inner() }))
        }
        "issueOpenPaymentMandate" => {
            let i = with_members(
                mk_open_input(a0),
                a0,
                &[
                    ("payee", "payee"),
                    ("paymentAmount", "paymentAmount"),
                    ("paymentInstrument", "paymentInstrument"),
                    ("pisp", "pisp"),
                    ("executionDate", "executionDate"),
                ],
            );
            issue_open_payment_mandate(&i, Some(counter_salt())).map(|t| json!(strip_sig(&t)))
        }
        "issueOpenCheckoutMandate" => issue_open_checkout_mandate(&mk_open_input(a0), Some(counter_salt())).map(|t| json!(strip_sig(&t))),
        "presentClosedPayment" => {
            let i = with_members(
                present_hop_in(a0),
                a0,
                &[
                    ("transactionId", "transactionId"),
                    ("payee", "payee"),
                    ("paymentAmount", "paymentAmount"),
                    ("paymentInstrument", "paymentInstrument"),
                    ("pisp", "pisp"),
                    ("executionDate", "executionDate"),
                    ("riskData", "riskData"),
                ],
            );
            let i = Value::Object(i.as_object().cloned().unwrap_or_default().into_iter().filter(|(_, v)| !v.is_null()).collect());
            present_closed_payment(&i, Some(counter_salt())).map(|t| json!(strip_sig(&t)))
        }
        "presentClosedCheckout" => {
            let mut i = present_hop_in(a0);
            i["checkoutJwt"] = a0.get("checkoutJwt").cloned().unwrap_or(Value::Null);
            present_closed_checkout(&i, Some(counter_salt())).map(|t| json!(strip_sig(&t)))
        }
        "ap2BudgetMax" => ap2_budget_max(arg(0), arg(1)),
        "ap2BudgetReads" => ap2_budget_reads(arg(0), arg(1)),
        "riskRatio" => Ok(risk_ratio(arg(0), arg(1))),
        "pcaBindingNonce" => pca_binding_nonce(arg(0)).map(Value::String),
        "paymentConstraintsFromTerms" => payment_constraints_from_terms(arg(0), arg(1), arg(2)).map(Value::Array),
        "pcaOpenClaim" => pca_open_claim(arg(0)),
        "openPaymentMandateFromPca" => {
            let mut o = from_in(a0);
            o["checkoutReference"] = non_null(a0, "checkoutReference").cloned().unwrap_or_else(|| json!("REF"));
            open_payment_mandate_from_pca(a0.get("mandate"), &o, Some(counter_salt())).map(|t| json!(strip_sig(&t)))
        }
        "openCheckoutMandateFromPca" => {
            let mut o = from_in(a0);
            o["lineItems"] = non_null(a0, "lineItems")
                .cloned()
                .unwrap_or_else(|| json!([{ "id": "line_1", "acceptable_items": [{ "id": "sku-1", "title": "Widget" }], "quantity": 2 }]));
            open_checkout_mandate_from_pca(a0.get("mandate"), &o, Some(counter_salt())).map(|t| json!(strip_sig(&t)))
        }
        "toAtomicUnits" => to_atomic_units(arg(0), arg(1)).map(Value::String),
        "x402Settlement" => x402_settlement(arg(0), arg(1)),
        "stripeSptSettlement" => stripe_spt_settlement(arg(0), arg(1)),
        "buildPcaPaymentBinding" => {
            let mut i = json!({ "agentJwk": nokid(&key_for("agent")["publicJwk"]) });
            for k in ["mandate", "open", "audience", "counter", "transactionId", "payee", "amount", "instrumentId"] {
                i[k] = a0.get(k).cloned().unwrap_or(Value::Null);
            }
            for k in ["now", "category"] {
                if let Some(v) = non_null(a0, k) {
                    i[k] = v.clone();
                }
            }
            let secret: [u8; 32] = Sha256::digest(format!("atlas-pca-conformance/{}", s(a0.get("agentSeed"))).as_bytes()).into();
            let shares = non_null(a0, "cosign").cloned();
            let cosign = move |_built: &Value| -> Result<Value, String> { Ok(shares.clone().unwrap_or(Value::Null)) };
            let has = non_null(a0, "cosign").is_some();
            build_pca_payment_binding(&i, &secret, if has { Some(&cosign) } else { None })
        }
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn ap2_vectors() {
    let cases = common::ref_cases("ap2");
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
