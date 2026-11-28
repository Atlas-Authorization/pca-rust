//! Differential replay of the A2A adapter (proof-carrying tasks, signed Agent Cards, the AP2 payment-mandate envelope, the
//! AUTH_REQUIRED mapping, the extension declaration, per-hop delegation, push tokens, signed task-update receipts, the extended
//! Agent Card, RFC 8785 JCS, the A2A 1.0 card schema) against the TypeScript reference (test-data/ref-a2a.json.gz).
//!
//! Keys are derived, never stored: the corpus carries the JWK `"d"` of the oracle's test key as the placeholder `$SEED:<label>`
//! (d = b64u(sha256("atlas-pca-conformance/" + label))), substituted here; receipts are signed from the same label seeds. Ed25519 is
//! deterministic, so signed cards and receipts compare byte for byte. JOSE-library reasons ("signature N did not verify: ...",
//! "could not resolve verification key: ...") and the mandate's "malformed payment mandate or PCActn: ..." are cut at the first
//! colon on both sides. A reference throw requires a refusal; the package's own messages (`issueSignedAgentCard:`, `pca-a2a:`,
//! `encodePcaNeed:`, ...) compare exactly. Every verify case of the corpus is refused BEFORE the full verifier (the oracle keeps only
//! those), so the stateless core verifier path is not reached here. Skipped (counted, must stay under 10%): cases with a lone
//! surrogate (no Rust string) and checkReceiptChain / mayTriggerNext cases whose options are not strings.
mod common;
use atlas_pca::a2a_card;
use atlas_pca::a2a_pca::*;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;
use sha2::{Digest, Sha256};

static NULL: Value = Value::Null;
const EXACT: [&str; 7] =
    ["issueSignedAgentCard:", "pca-a2a:", "encodePcaNeed:", "signTaskReceipt:", "pcaPushToken:", "a2aPaymentMandateFromPca:", "extendedAgentCard:"];

fn seed_of(label: &str) -> [u8; 32] {
    Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes()).into()
}

fn unseed(v: &mut Value) {
    // the corpus now carries the seed as `{"$seed": label}`; the older placeholder string `$SEED:<label>` is still accepted
    if let Some(l) = v.as_object().filter(|m| m.len() == 1).and_then(|m| m.get("$seed")).and_then(Value::as_str) {
        *v = Value::String(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed_of(l)));
        return;
    }
    match v {
        Value::String(s) => {
            if let Some(l) = s.strip_prefix("$SEED:") {
                *s = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed_of(l));
            }
        }
        Value::Array(a) => a.iter_mut().for_each(unseed),
        Value::Object(m) => m.iter_mut().for_each(|(_, x)| unseed(x)),
        _ => {}
    }
}

fn octets(b: &[u8]) -> Value {
    Value::Array(b.iter().map(|x| json!(x)).collect())
}

/// Cut a reason that quotes a library at its first colon.
fn norm(mut v: Value) -> Value {
    let cut = v.get("reason").and_then(Value::as_str).and_then(|r| {
        let head = r.split(": ").next().unwrap_or(r);
        let lib = head
            .strip_prefix("signature ")
            .and_then(|t| t.strip_suffix(" did not verify"))
            .is_some_and(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()));
        (r.contains(": ") && (lib || head == "could not resolve verification key" || head == "malformed payment mandate or PCActn")).then(|| head.to_string())
    });
    if let Some(h) = cut {
        v["reason"] = json!(h);
    }
    v
}

fn same(want: &Value, got: Result<Value, String>) -> Result<(), String> {
    let want_n = match want.get("$bytes").and_then(Value::as_str).and_then(|s| atlas_pca::decode_b64u_strict(s, None)) {
        Some(b) => octets(&b),
        None => want.clone(),
    };
    match (want.get("$throws").and_then(Value::as_str), got) {
        (Some(w), Err(g)) if !EXACT.iter().any(|p| w.starts_with(p)) || w == g => Ok(()),
        (None, Ok(g)) if atlas_pca::canonicalize(&norm(want_n)) == atlas_pca::canonicalize(&norm(g.clone())) => Ok(()),
        (_, g) => Err(format!("want {want}, got {g:?}")),
    }
}

fn strs(v: &Value) -> Option<Vec<&str>> {
    v.as_array()?.iter().map(Value::as_str).collect()
}

fn run(f: &str, a: &[Value]) -> Option<Result<Value, String>> {
    let g = |i: usize| a.get(i).unwrap_or(&NULL);
    let empty = json!({});
    Some(match f {
        "constants" => Ok(constants()),
        "jcsBytes" => a2a_card::jcs_bytes(g(0)).map(|b| octets(&b)),
        "validateAgentCard1" => Ok(json!(a2a_card::validate_agent_card1(g(0)))),
        "issueSignedAgentCard" => a2a_card::issue_signed_agent_card(g(0), g(1), a.get(2).unwrap_or(&empty)),
        "verifyAgentCard" => Ok(a2a_card::verify_agent_card(g(0), g(1))),
        "attachPcaToA2ATask" => attach_pca_to_a2a_task(g(0), g(1)),
        "attachPcaToA2AMessage" => attach_pca_to_a2a_message(g(0), g(1)),
        "extractPca" => Ok(extract_pca(g(0)).unwrap_or(Value::Null)),
        "extractPcaFromMessage" => Ok(extract_pca_from_message(g(0)).unwrap_or(Value::Null)),
        "verifyA2ATask" => verify_a2a_task(g(0), g(1)),
        "middleware" => middleware(g(0), g(1)),
        "resumeAuthRequired" => resume_auth_required(g(0), g(1), g(2)),
        "verifyA2ADelegation" => verify_a2a_delegation(g(0)),
        "a2aPaymentMandateFromPca" => a2a_payment_mandate_from_pca(g(0), g(1)),
        "pcaBindingFromA2APaymentMandate" => pca_binding_from_a2a_payment_mandate(g(0)),
        "verifyA2APaymentMandate" => verify_a2a_payment_mandate(g(0), g(1), g(2)),
        "pcaExtensionDeclaration" => Ok(pca_extension_declaration(g(0), a.get(1).and_then(Value::as_bool).unwrap_or(true))),
        "readPcaExtension" => Ok(read_pca_extension(g(0))),
        "clientOptsIntoPca" => Ok(json!(client_opts_into_pca(g(0)))),
        "isAuthRequired" => Ok(json!(is_auth_required(g(0)))),
        "authRequiredStatus" => auth_required_status(g(0), g(1)),
        "readAuthRequiredNeed" => Ok(read_auth_required_need(g(0))),
        "answerMessage" => answer_message(g(0), g(1), g(2)),
        "resumeGate" => resume_gate(g(0)).map(|r| r.map_or(Value::Null, |c| json!(c))),
        "chainExtends" => Ok(json!(chain_extends(g(0).as_array()?, g(1).as_array()?))),
        "checkChainExtension" => check_chain_extension(g(0)),
        "pcaPushToken" => pca_push_token(g(0), g(1), g(2)).map(Value::String),
        "checkPushNotification" => check_push_notification(g(0), g(1)),
        "uniformTaskNotFound" => Ok(uniform_task_not_found()),
        "signTaskReceipt" => sign_task_receipt(&seed_of(g(0).as_str()?), g(1)),
        "verifyTaskReceipt" => Ok(json!(verify_task_receipt(g(0), g(1).as_str()?))),
        "receiptDigest" => receipt_digest(g(0)).map(Value::String),
        "checkReceiptChain" | "mayTriggerNext" => {
            let o = g(1);
            let (signer, task_id, ids) = (o.get("signer")?.as_str()?, o.get("taskId")?.as_str()?, strs(o.get("chainIds")?)?);
            if f == "mayTriggerNext" {
                Ok(json!(may_trigger_next(g(0), signer, task_id, &ids)))
            } else {
                Ok(check_receipt_chain(g(0), signer, task_id, &ids))
            }
        }
        "attachReceipt" => attach_receipt(g(0), g(1)),
        "receiptOfPayload" => Ok(receipt_of_payload(g(0))),
        "extendedAgentCard" => extended_agent_card(g(0), g(1)),
        other => panic!("unknown fn {other}"),
    })
}

#[test]
fn a2a_vectors() {
    let cases = common::ref_cases("a2a");
    let (mut bad, mut skipped) = (Vec::new(), 0usize);
    for c in &cases {
        if c.to_string().contains(common::LONE) {
            skipped += 1;
            continue;
        }
        let mut args = c["args"].clone();
        unseed(&mut args);
        let Some(got) = run(c["fn"].as_str().unwrap(), args.as_array().unwrap()) else {
            skipped += 1;
            continue;
        };
        if let Err(e) = same(&c["out"], got) {
            bad.push(format!("{}: {e}", c["name"]));
        }
    }
    assert!(skipped * 10 < cases.len(), "too many skipped: {skipped} of {}", cases.len());
    assert!(bad.is_empty(), "{} of {} differ:\n{}", bad.len(), cases.len(), bad.iter().take(60).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn constants_match_the_reference() {
    let c = constants();
    assert_eq!(c["RECEIPT_KEY"], json!(RECEIPT_KEY));
    assert_eq!(c["A2A_RECEIPT_DOMAIN"], json!("atlas-pca/a2a-receipt/v1\u{0}"));
}
