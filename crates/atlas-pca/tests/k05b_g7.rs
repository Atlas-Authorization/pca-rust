//! 0.5 mutation kills (group g7): authorize pipeline branches, the OCSP reader, the X.509 reader, K4 signature decoding and
//! calibration, the missing-context merge. Each test names the survivor it kills.
mod common;

use std::sync::Mutex;

use atlas_pca::agent::{default_risk_policy, mint_grant, sign_narrow, Agent, KeyPair, Suite};
use atlas_pca::attest::ocsp::{check_chain_ocsp, verify_ocsp_response, Status};
use atlas_pca::attest::util::{sha1, sha256};
use atlas_pca::attest::x509::{der_wrap as tlv, name_to_string, parse_spki, Cert, PubKey};
use atlas_pca::k4::{pricing_config_error, update_calibration, PPM};
use atlas_pca::missing_context::bind_context;
use atlas_pca::{
    authorize, discharge_action_digest, hash_canonical_strict, missing_authorize_components, plan_root_of, strict_parse, AuthorizeInput, AuthorizeResult, CheckStatus,
    ContextProvider, IntentV2Context, IntentV2Provider, K1Input, MemoryStateStore, Operation, PlanRegistry, Verdict, WorkflowCall, WorkflowGate, CORE_HOOK, SINGLE_STEP,
};
use base64::Engine;
use serde_json::{json, Map, Value};

// CORE_HOOK is process-global: every test that authorizes holds this lock.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    L.lock().unwrap_or_else(|e| e.into_inner())
}

struct Hooked;
impl Hooked {
    fn set(h: fn(&mut Verdict)) -> Hooked {
        *CORE_HOOK.lock().unwrap_or_else(|e| e.into_inner()) = Some(h);
        Hooked
    }
}
impl Drop for Hooked {
    fn drop(&mut self) {
        *CORE_HOOK.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

// ------------------------------------------------------------------------------------------------ authorize: fixtures

/// The first shared authorize fixture step, with the optional registry / context / intent_v2 hooks.
fn fx(plans: Option<&PlanRegistry>, context: Option<&ContextProvider<'_>>, v2: Option<&IntentV2Provider<'_>>) -> AuthorizeResult {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/authorize-fixtures.json")).unwrap();
    let d = strict_parse(&text).unwrap();
    let (grant, s) = (d["cases"][0]["grant"].clone(), &d["cases"][0]["steps"][0]);
    let op = Operation::from_json(&s["operation"]).unwrap();
    let resolve = move |_: &str| Ok::<_, String>(Some(grant.clone()));
    let not_revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let store = MemoryStateStore::new();
    let pins = common::harness_pins();
    let input = AuthorizeInput {
        risk: Some(&atlas_pca::insecure_calm_risk as &atlas_pca::RiskFn), 
        operation: Some(&op),
        audience: d["audience"].as_str().unwrap(),
        resolve_grant: Some(&resolve),
        state_store: Some(&store),
        is_revoked: Some(&not_revoked),
        now: d["now"].as_i64(),
        plan: Some(SINGLE_STEP),
        plans,
        context,
        intent_v2: v2,
        provenance_mediators: &pins,
        provenance_bundle: Some(&common::principal_direct),
        ..Default::default()
    };
    authorize(Some(&s["pcactn"]), &input)
}

fn wire_empty(v: &mut Verdict) {
    v.allow = false;
    v.checks.insert("wire".to_string(), false);
    v.reason = String::new();
}

fn wire_reason(v: &mut Verdict) {
    v.allow = false;
    v.checks.insert("wire".to_string(), false);
    v.reason = "wire: the hook's own reason".to_string();
}

// kills authorize.rs:1479 `if core.reason.is_empty()` -> false and -> true
#[test]
fn a_wire_failure_reports_the_core_reason_or_the_malformed_fallback() {
    let _g = serial();
    assert!(fx(None, None, None).allow, "the fixture is allowed with no hook");
    {
        let _h = Hooked::set(wire_empty);
        let r = fx(None, None, None);
        assert_eq!((r.allow, r.status, r.reason.as_deref()), (false, 401, Some("wire: malformed PCActn")));
        assert_eq!(r.reasons, vec!["wire: malformed PCActn".to_string()]);
    }
    {
        let _h = Hooked::set(wire_reason);
        let r = fx(None, None, None);
        assert_eq!((r.allow, r.status, r.reason.as_deref()), (false, 401, Some("wire: the hook's own reason")));
        assert_eq!(r.reasons, vec!["wire: the hook's own reason".to_string()]);
    }
}

// kills authorize.rs:1425 `if ctx.get("plan").is_none_or(Value::is_null)` -> true
#[test]
fn a_plan_the_context_supplies_is_not_replaced_by_the_registry() {
    let _g = serial();
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/authorize-fixtures.json")).unwrap();
    let d = strict_parse(&text).unwrap();
    let p = &d["cases"][0]["steps"][0]["pcactn"];
    let (root, grant_ref) = (p["plan"]["root"].as_str().unwrap().to_string(), p["grant_ref"].as_str().unwrap().to_string());
    let op = &d["cases"][0]["steps"][0]["operation"];
    let n = json!({"id": p["plan"]["node_id"], "verb": op["verb"], "resource": op["resource"], "params_digest": p["action"]["params_digest"], "reversibility_class": p["action"]["reversibility_class"]});
    assert_eq!(plan_root_of(std::slice::from_ref(&n)).ok().as_deref(), Some(root.as_str()), "the node reproduces the committed root");
    // the registry knows the plan as a DRAFT (not executable): were it consulted, plan_state would fail
    let reg = PlanRegistry::new();
    assert!(reg.draft(&grant_ref, std::slice::from_ref(&n)).is_ok());
    let n2 = n.clone();
    let ctx = move |_: &Value| Ok::<_, String>(Some(json!({"plan": [n2.clone()], "plan_authorized": true})));
    let r = fx(Some(&reg), Some(&ctx), None);
    assert_eq!(r.check("plan_state"), None, "{r:?}");
    assert_eq!(r.check("plan_root_authorized"), Some(CheckStatus::Pass), "{r:?}");
    // control: with no context plan the registry IS consulted and the draft fails closed
    let r = fx(Some(&reg), None, None);
    assert_eq!(r.check("plan_state"), Some(CheckStatus::Fail), "{r:?}");
}

// kills authorize.rs:1451 `if m.get("params").is_none_or(Value::is_null)` -> true
#[test]
fn a_params_member_the_v2_context_supplies_is_kept_as_it_is() {
    let _g = serial();
    // a non-object params stays malformed (a present non-null member is not replaced by the operation's params)
    let v2 = |_: &Value| Ok::<_, String>(IntentV2Context::from_json(&json!({"params": 5})));
    let r = fx(None, None, Some(&v2));
    assert!(!r.allow, "{r:?}");
    assert_eq!(r.check("schema"), Some(CheckStatus::Fail), "{r:?}");
    let all = format!("{} | {}", r.reasons.join(" | "), r.reason.as_deref().unwrap_or(""));
    assert!(all.contains("malformed v2 context: params must be an object"), "{all}");
}

// kills authorize.rs:1003 `if input.resolve_grant.is_none()` -> false
#[test]
fn every_missing_component_is_named_in_order() {
    let want: Vec<String> = ["audience", "resolve_grant", "state_store", "is_revoked"].iter().map(|s| s.to_string()).collect();
    assert_eq!(missing_authorize_components(&AuthorizeInput::default()), want);
    let resolve = |_: &str| Ok::<Option<Value>, String>(None);
    let only_resolver = AuthorizeInput { risk: Some(&atlas_pca::insecure_calm_risk as &atlas_pca::RiskFn), resolve_grant: Some(&resolve), ..Default::default() };
    assert_eq!(missing_authorize_components(&only_resolver), vec!["audience".to_string(), "state_store".to_string(), "is_revoked".to_string()]);
}

// ------------------------------------------------------------------------------------------------ authorize: workflow units

fn workflow_case0(units: [Option<Value>; 2]) -> Vec<AuthorizeResult> {
    let path = format!("{}/../../conformance/authorize-workflow-fixtures.json", env!("CARGO_MANIFEST_DIR"));
    let f = strict_parse(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))).expect("parse");
    let grant = f["grant"].clone();
    let grant_id = grant["id"].as_str().unwrap().to_string();
    let resolve = move |r: &str| Ok::<_, String>(if r == grant_id { Some(grant.clone()) } else { None });
    let revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let plan = f["plan"].clone();
    let context = move |_: &Value| Ok::<_, String>(Some(json!({ "plan": plan, "plan_authorized": true })));
    let c = &f["cases"][0];
    assert_eq!(c["name"], "pay-after-quote");
    let gate = WorkflowGate { principal: f["principal"].as_str().unwrap().into(), rs_signer: f["rs_signer"].as_str().unwrap().into(), required: c["required"].as_bool().unwrap() };
    let store = MemoryStateStore::new();
    let pins = common::harness_pins();
    let mut out = Vec::new();
    for (i, s) in c["steps"].as_array().unwrap().iter().enumerate() {
        let op = Operation::from_json(&s["operation"]).unwrap();
        let w = &s["workflow"];
        let call = WorkflowCall {
            commitment: w["commitment"].clone(),
            receipts: w["receipts"].clone(),
            step: w["step"].clone(),
            units: units[i].clone().unwrap_or_else(|| json!({})),
            goal_digest: w.get("goal_digest").cloned().unwrap_or(Value::Null),
        };
        let input = AuthorizeInput {
            risk: Some(&atlas_pca::insecure_calm_risk as &atlas_pca::RiskFn), 
            operation: Some(&op),
            audience: f["audience"].as_str().unwrap(),
            resolve_grant: Some(&resolve),
            state_store: Some(&store),
            is_revoked: Some(&revoked),
            now: f["now"].as_i64(),
            plan: None,
            context: Some(&context),
            workflow: Some(&gate),
            workflow_call: Some(&call),
            provenance_mediators: &pins,
            provenance_bundle: Some(&common::principal_direct),
            ..Default::default()
        };
        out.push(authorize(Some(&s["pcactn"]), &input));
    }
    out
}

// kills authorize.rs:1406 `if c.units.is_null()` -> false (a null units counts as {}) and -> true (units are the call's)
#[test]
fn a_null_units_counts_as_empty_and_given_units_reach_the_edge_check() {
    let _g = serial();
    let base = workflow_case0([None, None]);
    assert_eq!((base[0].allow, base[1].allow), (true, true), "{base:?}");
    let r = workflow_case0([Some(Value::Null), Some(json!({"amount": "usd"}))]);
    assert_eq!((r[0].allow, r[0].status), (true, 200), "a null units is {{}}: {:?}", r[0]);
    // the receipt's output carries no unit, the request's `amount` does: edge_unit
    assert_eq!((r[1].allow, r[1].decision), (false, "deny"), "{:?}", r[1]);
    assert!(r[1].reason.as_deref().unwrap_or("").contains("workflow: edge_unit (step pay)"), "{:?}", r[1].reason);
}

// ------------------------------------------------------------------------------------------------ authorize: signed scenes

const NOW: i64 = 1_700_000_000_000;

fn fixed_now() -> i64 {
    NOW
}

struct Built {
    grant: Value,
    pcactn: Value,
    op: Operation,
}

fn build(envelope_patch: Option<Value>, no_chain: bool) -> Built {
    let d = Suite::default();
    let (principal, holder) = (KeyPair::from_seed(&[1u8; 32]), KeyPair::from_seed(&[2u8; 32]));
    let mut envelope = json!({"predicates": [{"verb": "v", "resource": "r"}], "caveats": [], "risk_policy": default_risk_policy()});
    if let Some(patch) = &envelope_patch {
        for (k, x) in patch.as_object().unwrap() {
            envelope[k.as_str()] = x.clone();
        }
    }
    let params = json!({});
    let grant = mint_grant(&principal, &holder.public, &envelope, "goal", None, None, &d).unwrap().grant;
    let mut agent = Agent::new(holder, grant.clone(), "aud", 0);
    agent.clock = fixed_now;
    let action = agent.act("v", "r", Some(&params), Map::new(), &d).unwrap();
    let mut pcactn = action.pcactn;
    if no_chain {
        pcactn["cap_chain"] = json!([]);
    }
    Built { grant, pcactn, op: Operation::new("v", "r", params) }
}

fn decide(b: &Built, k1: Option<&K1Input>) -> AuthorizeResult {
    let resolve = |_: &str| Ok::<_, String>(Some(b.grant.clone()));
    let revoked = |_: &Value, _: &Value| Ok::<_, String>(false);
    let store = MemoryStateStore::new();
    let pins = common::harness_pins();
    let input = AuthorizeInput {
        risk: Some(&atlas_pca::insecure_calm_risk as &atlas_pca::RiskFn), 
        operation: Some(&b.op),
        audience: "aud",
        resolve_grant: Some(&resolve),
        state_store: Some(&store),
        is_revoked: Some(&revoked),
        now: Some(NOW),
        plan: Some(SINGLE_STEP),
        k1,
        provenance_mediators: &pins,
        provenance_bundle: Some(&common::principal_direct),
        ..Default::default()
    };
    authorize(Some(&b.pcactn), &input)
}

// kills authorize.rs:1728 `else if k1_result.is_some()` -> true
#[test]
fn with_no_hop_and_no_k1_the_delegated_caveats_check_is_not_reported() {
    let _g = serial();
    let with_hop = decide(&build(None, false), None);
    assert!(with_hop.allow, "{with_hop:?}");
    assert_eq!(with_hop.check("delegated_caveats"), Some(CheckStatus::Pass));
    let no_hop = decide(&build(None, true), None);
    assert_eq!(no_hop.check("delegated_caveats"), None, "{no_hop:?}");
}

// kills authorize.rs:1677 `if let Some(r) = rev_class` (the class joins the caveat context)
#[test]
fn the_effective_class_reaches_the_caveat_context() {
    let _g = serial();
    let b = build(Some(json!({"caveats": [{"type": "reversibility_max", "class": "reversible"}]})), false);
    let r = decide(&b, None);
    assert!(r.allow, "{r:?}");
    assert_eq!(r.check("policy"), Some(CheckStatus::Pass));
}

// kills authorize.rs:1693 `if let Some(k) = k1.as_mut()` (the PCActn's action digest binds the narrow block)
#[test]
fn a_narrow_block_bound_to_this_action_is_admitted() {
    let _g = serial();
    let b = build(None, false);
    let holder = KeyPair::from_seed(&[2u8; 32]);
    let leaf = hash_canonical_strict(&b.grant).unwrap();
    let ad = discharge_action_digest(&b.pcactn).unwrap();
    let caveats = json!([{"type": "expires", "at": NOW + 60_000}]);
    let sign = |digest: Option<&str>| sign_narrow(&holder, &leaf, &caveats, NOW, NOW + 60_000, digest, None, &Suite::default()).unwrap();
    let k1 = K1Input { narrow: Some(sign(Some(&ad))), ..Default::default() };
    let r = decide(&b, Some(&k1));
    assert!(r.allow, "{r:?}");
    assert_eq!(r.check("delegated_caveats"), Some(CheckStatus::Pass));
    // control: a block bound to another action is refused
    let other = sign(Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    let k1 = K1Input { narrow: Some(other), ..Default::default() };
    let r = decide(&b, Some(&k1));
    assert!(!r.allow, "{r:?}");
    assert_eq!(r.check("delegated_caveats"), Some(CheckStatus::Fail));
}

// ------------------------------------------------------------------------------------------------ attest::x509

const SPKI_UNSUPPORTED: &str = "error:1E08010C:DECODER routines::unsupported";
const WRONG_TAG: &str = "error:068000A8:asn1 encoding routines::wrong tag";

fn key_tlv() -> Vec<u8> {
    tlv(0x03, &[vec![0u8], vec![7u8; 32]].concat())
}

// kills x509.rs:229 `return Err(bad())` (#2) and x509.rs:238 (#4)
#[test]
fn an_spki_whose_algorithm_is_not_a_sequence_or_not_led_by_an_oid_is_unsupported() {
    // alg is a SET holding the Ed25519 OID: only the tag stops it
    let set_alg = tlv(0x30, &[tlv(0x31, &tlv(0x06, &[0x2b, 0x65, 0x70])), key_tlv()].concat());
    assert_eq!(parse_spki(&set_alg).err().as_deref(), Some(SPKI_UNSUPPORTED));
    // alg is a SEQUENCE whose first member is an OCTET STRING, not an OID
    let no_oid = tlv(0x30, &[tlv(0x30, &tlv(0x04, &[0])), key_tlv()].concat());
    assert_eq!(parse_spki(&no_oid).err().as_deref(), Some(SPKI_UNSUPPORTED));
    // control: the same bytes with a SEQUENCE and an OID parse
    let good = tlv(0x30, &[tlv(0x30, &tlv(0x06, &[0x2b, 0x65, 0x70])), key_tlv()].concat());
    assert!(matches!(parse_spki(&good), Ok(PubKey::Ed25519(k)) if k == vec![7u8; 32]));
}

// kills x509.rs:111 `if v.is_empty()` in der_uint -> false (a zero modulus is the one-octet 00)
#[test]
fn an_rsa_key_with_an_empty_or_all_zero_number_encodes_it_as_one_zero_octet() {
    for n in [vec![], vec![0u8, 0]] {
        let der = PubKey::Rsa { n, e: vec![1, 0, 1] }.spki_der();
        assert!(der.windows(3).any(|w| w == [0x02, 0x01, 0x00]), "{der:02x?}");
    }
}

// kills x509.rs:711 `if arcs.is_empty()` in oid_dotted -> false (an empty OID renders as an empty key)
#[test]
fn a_name_attribute_with_an_empty_oid_renders_with_an_empty_key() {
    let ava = tlv(0x30, &[tlv(0x06, &[]), tlv(0x0c, b"a")].concat());
    let name = tlv(0x30, &tlv(0x31, &ava));
    assert_eq!(name_to_string(&name), "=a");
    // an attribute with an unknown (non-empty) OID renders dotted
    let ava = tlv(0x30, &[tlv(0x06, &[0x2a, 0x03, 0x04]), tlv(0x0c, b"a")].concat());
    assert_eq!(name_to_string(&tlv(0x30, &tlv(0x31, &ava))), "1.2.3.4=a");
}

fn cert_parts(tbs_tag: u8) -> Vec<u8> {
    let validity = tlv(0x30, &[tlv(0x17, b"200101000000Z"), tlv(0x17, b"400101000000Z")].concat());
    let tbs = tlv(tbs_tag, &[tlv(0x02, &[1]), tlv(0x30, &[]), tlv(0x30, &[]), validity, tlv(0x30, &[]), tlv(0x30, &[])].concat());
    tlv(0x30, &[tbs, tlv(0x30, &[]), tlv(0x03, &[0])].concat())
}

fn dummy_cert() -> Cert {
    Cert::from_der(&cert_parts(0x30)).expect("a structurally valid certificate")
}

// kills x509.rs:419 `return Err(asn1_err())` in expect
#[test]
fn a_certificate_whose_tbs_is_not_a_sequence_is_refused() {
    assert!(Cert::from_der(&cert_parts(0x30)).is_ok());
    assert_eq!(Cert::from_der(&cert_parts(0x31)).err().as_deref(), Some(WRONG_TAG));
}

// ------------------------------------------------------------------------------------------------ attest::ocsp

const BASIC_OID: [u8; 9] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
const SCHEMA_TOP: &str = "OCSP response rejected: Object's schema was not verified against input data for OCSPResponse";
const SCHEMA_BASIC: &str = "OCSP response rejected: Object's schema was not verified against input data for BasicOCSPResponse";

fn ocsp_err(der: &[u8]) -> String {
    let c = dummy_cert();
    verify_ocsp_response(der, &c, &c, &[], 0.0).err().expect("the response must be refused")
}

/// An OCSPResponse of status `status` whose responseBytes carry `rb_oid` and the OCTET STRING `basic`.
fn ocsp_of(status: u8, rb_oid: &[u8], basic: &[u8]) -> Vec<u8> {
    let rb = tlv(0x30, &[tlv(0x06, rb_oid), tlv(0x04, basic)].concat());
    tlv(0x30, &[tlv(0x0a, &[status]), tlv(0xa0, &rb)].concat())
}

// kills ocsp.rs:271 (trailing bytes), :274 (outer tag), :282 (responseStatus), :293 (responseType)
#[test]
fn the_outer_ocsp_response_is_checked_before_anything_reads_inside_it() {
    assert_eq!(ocsp_err(&[0x30, 0x00, 0x00]), "trailing bytes after OCSPResponse");
    // a SET that otherwise reads like a response with status 0 and no responseBytes
    assert_eq!(ocsp_err(&tlv(0x31, &tlv(0x0a, &[0]))), SCHEMA_TOP);
    assert_eq!(ocsp_err(&tlv(0x30, &tlv(0x0a, &[1]))), "OCSP responseStatus is 1 (not successful)");
    assert_eq!(ocsp_err(&ocsp_of(0, &[0x2a, 0x03, 0x04], &[])), "responseType is not id-pkix-ocsp-basic");
}

// kills ocsp.rs:298 (the BasicOCSPResponse tag) and :68 (an empty OID is rendered, not indexed)
#[test]
fn the_basic_response_must_be_a_sequence_and_an_empty_algorithm_oid_is_reported() {
    let unknown_alg = tlv(0x30, &tlv(0x06, &[0x2a, 0x03, 0x04]));
    let as_set = tlv(0x31, &[tlv(0x30, &[]), unknown_alg.clone(), tlv(0x03, &[0])].concat());
    assert_eq!(ocsp_err(&ocsp_of(0, &BASIC_OID, &as_set)), SCHEMA_BASIC);
    // the same members in a SEQUENCE get as far as the signature algorithm
    let as_seq = tlv(0x30, &[tlv(0x30, &[]), unknown_alg, tlv(0x03, &[0])].concat());
    assert_eq!(ocsp_err(&ocsp_of(0, &BASIC_OID, &as_seq)), "unsupported OCSP signature algorithm 1.2.3.4");
    let empty_oid = tlv(0x30, &[tlv(0x30, &[]), tlv(0x30, &tlv(0x06, &[])), tlv(0x03, &[0])].concat());
    assert_eq!(ocsp_err(&ocsp_of(0, &BASIC_OID, &empty_oid)), "unsupported OCSP signature algorithm ");
}

// kills ocsp.rs:46 `return Err(())` in kids: a child that runs past its parent
#[test]
fn a_member_that_overruns_its_parent_is_a_schema_error() {
    // responseBytes declares 12 content octets, but its OCTET STRING (04 03 30 00 00) starts at the 12th and ends 4 past it
    let mut rb = vec![0x30, 0x0c];
    rb.extend(tlv(0x06, &BASIC_OID));
    rb.push(0x04);
    let mut in_a0 = rb;
    in_a0.extend([0x03, 0x30, 0x00, 0x00]);
    let der = tlv(0x30, &[tlv(0x0a, &[0]), tlv(0xa0, &in_a0)].concat());
    assert_eq!(ocsp_err(&der), SCHEMA_TOP);
}

const ROOT: u8 = 1;
const CA: u8 = 2;
const LEAF: u8 = 3;
const RESP: u8 = 5;
const AT_NOW_MS: f64 = 1.8e12; // 2027-01-15T08:00:00Z
const THIS: &str = "20270114000000Z";
const ECDSA_SHA256: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const SHA256_OID: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

fn signing_key(seed: u8) -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap()
}
fn point(seed: u8) -> Vec<u8> {
    signing_key(seed).verifying_key().to_encoded_point(false).as_bytes().to_vec()
}
fn sign_der(seed: u8, msg: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::Signer;
    let s: p256::ecdsa::Signature = signing_key(seed).sign(msg);
    s.to_der().as_bytes().to_vec()
}
fn cn(n: &str) -> Vec<u8> {
    tlv(0x30, &tlv(0x31, &tlv(0x30, &[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, n.as_bytes())].concat())))
}
fn ext(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let crit = if critical { tlv(0x01, &[0xff]) } else { vec![] };
    tlv(0x30, &[tlv(0x06, oid), crit, tlv(0x04, value)].concat())
}
fn good_ca() -> Vec<Vec<u8>> {
    vec![ext(&[0x55, 0x1d, 0x13], true, &tlv(0x30, &tlv(0x01, &[0xff]))), ext(&[0x55, 0x1d, 0x0f], true, &tlv(0x03, &[0, 0x04]))]
}
fn ocsp_signing() -> Vec<Vec<u8>> {
    vec![ext(&[0x55, 0x1d, 0x13], true, &tlv(0x30, &[])), ext(&[0x55, 0x1d, 0x25], false, &tlv(0x30, &tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09])))]
}
/// A certificate for `seed`'s P-256 key signed by `signer`'s.
fn mint(seed: u8, signer: u8, exts: &[Vec<u8>], issuer: &str, subject: &str) -> Vec<u8> {
    let alg = tlv(0x30, &tlv(0x06, &ECDSA_SHA256));
    let validity = tlv(0x30, &[tlv(0x17, b"200101000000Z"), tlv(0x17, b"400101000000Z")].concat());
    let key_alg = tlv(0x30, &[tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]), tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])].concat());
    let spki = tlv(0x30, &[key_alg, tlv(0x03, &[vec![0], point(seed)].concat())].concat());
    let tbs = tlv(
        0x30,
        &[tlv(0xa0, &tlv(0x02, &[2])), tlv(0x02, &[seed]), alg.clone(), cn(issuer), validity, cn(subject), spki, tlv(0xa3, &tlv(0x30, &exts.concat()))].concat(),
    );
    let bits = tlv(0x03, &[vec![0], sign_der(signer, &tbs)].concat());
    tlv(0x30, &[tbs, alg, bits].concat())
}
fn cert(seed: u8, signer: u8, issuer: &str, subject: &str, exts: &[Vec<u8>]) -> Cert {
    Cert::from_der(&mint(seed, signer, exts, issuer, subject)).unwrap()
}
/// SingleResponse: GOOD for serial `serial` issued by `issuer_name` / `issuer_seed`.
fn single(serial: u8, issuer_name: &str, issuer_seed: u8) -> Vec<u8> {
    let id = [tlv(0x30, &tlv(0x06, &SHA256_OID)), tlv(0x04, &sha256(&cn(issuer_name))), tlv(0x04, &sha256(&point(issuer_seed))), tlv(0x02, &[serial])].concat();
    tlv(0x30, &[tlv(0x30, &id), tlv(0x80, &[]), tlv(0x18, THIS.as_bytes())].concat())
}
/// A response signed by the delegated responder (seed RESP, cert signed by `resp_signer`), carrying `embedded` after its cert.
fn delegated(singles: &[Vec<u8>], resp_signer: u8, trailing_embedded: Vec<Vec<u8>>) -> Vec<u8> {
    let rid = tlv(0xa2, &tlv(0x04, &sha1(&point(RESP))));
    let tbs = tlv(0x30, &[rid, tlv(0x18, THIS.as_bytes()), tlv(0x30, &singles.concat())].concat());
    let sig = tlv(0x03, &[vec![0], sign_der(RESP, &tbs)].concat());
    let mut certs = vec![mint(RESP, resp_signer, &ocsp_signing(), if resp_signer == ROOT { "root" } else { "ca" }, "responder")];
    certs.extend(trailing_embedded);
    let basic = tlv(0x30, &[tbs, tlv(0x30, &tlv(0x06, &ECDSA_SHA256)), sig, tlv(0xa0, &tlv(0x30, &certs.concat()))].concat());
    ocsp_of(0, &BASIC_OID, &basic)
}

fn chain3() -> [Cert; 3] {
    [cert(LEAF, CA, "ca", "leaf", &[ocsp_signing()[0].clone()]), cert(CA, ROOT, "root", "ca", &good_ca()), cert(ROOT, ROOT, "root", "root", &good_ca())]
}

// kills ocsp.rs:455 `break` in the embedded-certificate loop: once one verifies, later entries are never parsed
#[test]
fn the_first_embedded_responder_that_verifies_ends_the_search() {
    let [leaf, ca, _root] = chain3();
    let garbage = tlv(0x04, &[1, 2, 3]);
    let der = delegated(&[single(LEAF, "ca", CA)], CA, vec![garbage]);
    let chain = [leaf.clone(), ca.clone()];
    match verify_ocsp_response(&der, &leaf, &ca, &chain, AT_NOW_MS) {
        Ok(o) => assert_eq!(o.status, Status::Good),
        Err(e) => panic!("the first embedded certificate verifies; later ones are not read: {e}"),
    }
    // control: the same response without the trailing entry
    let der = delegated(&[single(LEAF, "ca", CA)], CA, vec![]);
    assert!(verify_ocsp_response(&der, &leaf, &ca, &chain, AT_NOW_MS).is_ok());
}

// kills ocsp.rs:554 `if matched` -> false and :555 `return Err` in check_chain_ocsp
#[test]
fn one_response_may_speak_for_only_one_chain_certificate() {
    let chain = chain3();
    // one responder certificate signed by the root speaks for BOTH links: leaf (issued by ca) and ca (issued by root)
    let both = delegated(&[single(LEAF, "ca", CA), single(CA, "root", ROOT)], ROOT, vec![]);
    assert_eq!(check_chain_ocsp(&chain, &[both], AT_NOW_MS), Err("OCSP response #0 matches more than one chain certificate".to_string()));
    // control: a response for the leaf alone is counted once
    let one = delegated(&[single(LEAF, "ca", CA)], ROOT, vec![]);
    assert_eq!(check_chain_ocsp(&chain, &[one], AT_NOW_MS), Ok(1));
}

// ------------------------------------------------------------------------------------------------ k4

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn sign_body(kp: &KeyPair, kind: &str, body: &Value) -> String {
    let h = hash_canonical_strict(&json!({"kind": kind, "body": body})).unwrap();
    b64u(&kp.sign(h.as_bytes()))
}

fn config_body(principal: &str) -> Value {
    json!({"v": 1, "principal": principal, "currency": "USD", "interruptionCost": 10, "maxInterruptionCost": 100, "hardCeilingLoss": 1000, "epoch": 1, "tightenStepPpm": 500000})
}

fn with_sig(mut body: Value, sig: &str) -> Value {
    body["sig"] = json!(sig);
    body
}

// kills k4.rs:35 and :36 `decode_b64u_strict(..)?` in sig_ok: an undecodable key / signature is malformed, not a bad signature
#[test]
fn an_undecodable_principal_or_signature_makes_the_pricing_config_malformed() {
    assert_eq!(pricing_config_error(&with_sig(config_body("!!"), "AAAA")), Some("config_malformed"));
    assert_eq!(pricing_config_error(&with_sig(config_body("AAAA"), "!!")), Some("config_malformed"));
    // both decode, the signature just does not verify
    assert_eq!(pricing_config_error(&with_sig(config_body("AAAA"), "AAAA")), Some("config_signature_invalid"));
}

// kills k4.rs:162 `if pricing_config_error(config).is_some()` -> false in update_calibration
#[test]
fn a_config_that_does_not_verify_leaves_the_calibration_untouched() {
    let kp = KeyPair::from_seed(&[9u8; 32]);
    let body = config_body(&kp.public);
    let good = with_sig(body.clone(), &sign_body(&kp, "pca.escalation_pricing", &body));
    let forged = with_sig(body.clone(), &b64u(&[0u8; 64]));
    assert_eq!(pricing_config_error(&good), None);
    assert_eq!(pricing_config_error(&forged), Some("config_signature_invalid"));
    let answer_body = json!({"v": 1, "principal": kp.public, "nonce": "nonce-0001", "action_digest": "digest-1", "answer": "deny"});
    let answer = with_sig(answer_body.clone(), &sign_body(&kp, "pca.escalation_answer", &answer_body));
    let risks = Map::new();
    // a verified config folds the signed answer: its nonce is now seen
    assert_eq!(update_calibration(&good, &json!({}), std::slice::from_ref(&answer), &risks), (PPM, vec!["nonce-0001".to_string()]));
    // the same answer under a config whose signature fails folds nothing
    assert_eq!(update_calibration(&forged, &json!({}), &[answer], &risks), (PPM, Vec::<String>::new()));
}

// ------------------------------------------------------------------------------------------------ missing context

// kills missing_context.rs:173 `if path.starts_with("action.params")` -> true
#[test]
fn a_supplied_subject_value_does_not_invent_an_action() {
    let bound = json!({});
    let supplied = json!({"subject": {"id": "u1"}});
    let b = bind_context(&bound, &supplied, &Default::default());
    assert_eq!(b.context, json!({"subject": {"id": "u1"}}));
    assert!(b.conflicts.is_empty() && b.dropped.is_empty());
}
