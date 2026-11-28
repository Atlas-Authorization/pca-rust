//! Differential replay of test-data/ref-sevsnp-helpers.json.gz (written by the TypeScript reference): the hex helper, PEM splitting, the
//! report parser, the P-384 key and signature helpers, the report signature check, the policy gate, the default identity derivation, the
//! KDS VCEK fetch over an injected transport, and the VCEK certificate readers and VCEK / report binding. Every function of the corpus has
//! a handler and the per-function totals are asserted. A reference refusal must be a refusal here; after the prefix `VCEK extensions
//! malformed:` the reference's own text is not compared.
mod common;
use std::cell::RefCell;
use std::collections::BTreeMap;

use atlas_pca::attest::snp::{check_policy, check_vcek_report_binding, parse_report, SnpPolicy, SnpReport, Vmpl};
use atlas_pca::attest::snp_helpers::*;
use atlas_pca::attest::util::sha256;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;
use common::replay::thrown;

const MALFORMED: &str = "VCEK extensions malformed:";

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn bytes(v: &Value) -> Vec<u8> {
    common::b64d(v["$bytes"].as_str().unwrap())
}

fn enc(b: &[u8]) -> Value {
    json!({ "$bytes": b64u(b) })
}

fn big(v: u64) -> Value {
    json!({ "$bigint": v.to_string() })
}

fn bigint(v: &Value) -> Option<u64> {
    v.get("$bigint")?.as_str()?.parse().ok()
}

/// A number: a JSON number, or `{"$num": "NaN" | "Infinity" | "-Infinity"}`.
fn number(v: &Value) -> Option<f64> {
    if v.is_number() {
        return v.as_f64();
    }
    match v.get("$num")?.as_str()? {
        "Infinity" => Some(f64::INFINITY),
        "-Infinity" => Some(f64::NEG_INFINITY),
        _ => Some(f64::NAN),
    }
}

fn report_json(r: &SnpReport) -> Value {
    let (sr, ss) = r.signature();
    let ver = |v: (u8, u8, u8)| json!({"major": v.0, "minor": v.1, "build": v.2});
    json!({
        "version": r.version,
        "guest_svn": r.guest_svn,
        "policy": big(r.policy),
        "family_id": enc(&r.family_id),
        "image_id": enc(&r.image_id),
        "vmpl": r.vmpl,
        "signature_algo": r.signature_algo,
        "current_tcb": big(r.current_tcb),
        "platform_info": big(r.platform_info),
        "report_data": enc(&r.report_data),
        "measurement": enc(&r.measurement),
        "host_data": enc(&r.host_data),
        "id_key_digest": enc(&r.id_key_digest),
        "author_key_digest": enc(&r.author_key_digest),
        "report_id": enc(&r.report_id),
        "report_id_ma": enc(&r.report_id_ma),
        "reported_tcb": big(r.reported_tcb),
        "cpuid_fam_id": r.cpuid_fam_id,
        "cpuid_mod_id": r.cpuid_mod_id,
        "cpuid_step": r.cpuid_step,
        "chip_id": enc(&r.chip_id),
        "committed_tcb": big(r.committed_tcb),
        "current_version": ver(r.current_version),
        "committed_version": ver(r.committed_version),
        "launch_tcb": big(r.launch_tcb),
        "launch_mit_vector": big(r.launch_mit_vector),
        "current_mit_vector": big(r.current_mit_vector),
        "signature": {"r": enc(sr), "s": enc(ss)},
        "signed_len": r.signed().len(),
        "signed_sha256": atlas_pca::attest::util::hex_lower(&sha256(r.signed())),
        "raw_len": r.raw_len,
    })
}

/// A policy list: lowercase strings when it is a non-empty array of strings; a non-array or empty one gates nothing; an array with a
/// non-string entry makes the reference throw (`x.toLowerCase is not a function`) when the gate is reached: a placeholder that never
/// matches stands in and the flag says so.
fn list(p: &Value, k: &str) -> (Vec<String>, bool) {
    match p.get(k).and_then(Value::as_array).filter(|a| !a.is_empty()) {
        Some(a) if a.iter().all(Value::is_string) => (a.iter().map(|x| x.as_str().unwrap().to_lowercase()).collect(), false),
        Some(_) => (vec!["\u{0}".to_string()], true),
        None => (Vec::new(), false),
    }
}

fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn check_policy_case(a: &[Value]) -> Value {
    let report = parse_report(&bytes(&a[0])).unwrap();
    let p = &a[1];
    if p.is_null() {
        return thrown("Cannot read properties of null (reading 'requireEcdsaP384')");
    }
    let (measurements, bad_m) = list(p, "measurements");
    let (host_data, bad_h) = list(p, "hostData");
    let (chip_ids, bad_c) = list(p, "chipIds");
    let require_vmpl = match p.get("requireVmpl") {
        None | Some(Value::Null) => Vmpl::N(0.0),
        Some(Value::Number(n)) => Vmpl::N(n.as_f64().unwrap()),
        Some(Value::String(s)) if s == "any" => Vmpl::Any,
        Some(other) => Vmpl::Never(js_string(other)),
    };
    let policy = SnpPolicy {
        measurements,
        host_data,
        chip_ids,
        allow_debug: p.get("allowDebug") == Some(&json!(true)),
        min_guest_svn: p.get("minGuestSvn").and_then(number),
        min_reported_tcb: p.get("minReportedTcb").and_then(bigint),
        min_committed_tcb: p.get("minCommittedTcb").and_then(bigint),
        min_launch_tcb: p.get("minLaunchTcb").and_then(bigint),
        require_vmpl,
        require_ecdsa_p384: p.get("requireEcdsaP384") != Some(&json!(false)),
    };
    match check_policy(&report, &policy) {
        Some(r)
            if (bad_m && r == "measurement not in policy allowlist")
                || (bad_h && r == "host_data not in policy allowlist")
                || (bad_c && r == "chip_id not in policy allowlist") =>
        {
            thrown("x.toLowerCase is not a function")
        }
        other => other.map_or(Value::Null, Value::String),
    }
}

fn fetch_case(a: &[Value]) -> Value {
    let opts = &a[2];
    let url = RefCell::new(String::new());
    let (status, body) = (opts["status"].as_u64().unwrap() as u16, bytes(&opts["body"]));
    let transport = |u: &str| {
        *url.borrow_mut() = u.to_string();
        Ok(KdsResponse { status, body: body.clone() })
    };
    let fetch: Option<&dyn Fn(&str) -> Result<KdsResponse, String>> = if opts["noFetch"] == json!(true) { None } else { Some(&transport) };
    match fetch_vcek_from_kds(&bytes(&a[0]), bigint(&a[1]).unwrap(), opts["product"].as_str(), opts["baseUrl"].as_str(), fetch) {
        Ok(b) => json!({"url": url.borrow().clone(), "bytes": enc(&b)}),
        Err(e) => thrown(e),
    }
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "toHex" => json!(to_hex(&bytes(&a[0]))),
        "splitPemCertificates" => json!(split_pem_certificates(a[0].as_str().unwrap())),
        "parseReport" => parse_report(&bytes(&a[0])).map(|r| report_json(&r)).unwrap_or_else(thrown),
        "ecdsaP384PublicKey" => ecdsa_p384_public_key(&bytes(&a[0])).map(|p| json!({"point": enc(&p)})).unwrap_or_else(thrown),
        "signatureToCompact" => {
            sev_snp_signature_to_compact(&bytes(&a[0]["r"]), &bytes(&a[0]["s"])).map(|c| enc(&c)).unwrap_or_else(thrown)
        }
        "verifyReportSignature" => {
            let report = parse_report(&bytes(&a[0])).unwrap();
            json!(a[1].get("$bytes").is_some() && verify_sev_snp_report_signature(&report, &bytes(&a[1])))
        }
        "checkPolicy" => check_policy_case(a),
        "deriveIdentity" => make_default_derive_identity(&parse_report(&bytes(&a[0])).unwrap(), a[1] == json!(true)),
        "fetchVcek" => fetch_case(a),
        "extractTbsCertificate" => extract_tbs_certificate(&bytes(&a[0])).map(|t| enc(&t)).unwrap_or_else(thrown),
        "extractVcekPublicKey" => {
            extract_vcek_public_key(&bytes(&a[0])).map(|(p, t)| json!({"point": enc(&p), "tbs": enc(&t)})).unwrap_or_else(thrown)
        }
        "checkVcekReportBinding" => {
            let report = parse_report(&bytes(&a[1])).unwrap();
            check_vcek_report_binding(&bytes(&a[0]), &report).map_or(Value::Null, Value::String)
        }
        "constants" => json!({
            "SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384": SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384,
            "SEV_SNP_POLICY_DEBUG_BIT": big(SEV_SNP_POLICY_DEBUG_BIT),
            "AMD_MILAN_ARK_SPKI_SHA384": AMD_MILAN_ARK_SPKI_SHA384,
        }),
        other => panic!("unhandled corpus function {other}"),
    }
}

fn norm(v: &Value) -> Value {
    match v {
        Value::String(s) if s.starts_with(MALFORMED) => json!(MALFORMED),
        other => other.clone(),
    }
}

#[test]
fn sevsnp_helpers_replay() {
    let cases = common::ref_cases_seeded("sevsnp-helpers");
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(c["fn"].as_str().unwrap().to_string()).or_default() += 1;
    }
    let want: BTreeMap<String, usize> = [
        ("checkVcekReportBinding", 75),
        ("checkPolicy", 57),
        ("parseReport", 17),
        ("extractTbsCertificate", 16),
        ("splitPemCertificates", 15),
        ("fetchVcek", 14),
        ("verifyReportSignature", 13),
        ("ecdsaP384PublicKey", 11),
        ("signatureToCompact", 10),
        ("deriveIdentity", 8),
        ("extractVcekPublicKey", 7),
        ("toHex", 4),
        ("constants", 1),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), *n))
    .collect();
    assert_eq!(per_fn, want, "per-function case totals");
    assert_eq!(cases.len(), 248);
    let mut bad = Vec::new();
    for c in &cases {
        let got = run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap());
        let differs = if c["out"].get("$throws").is_some() {
            got.get("$throws").is_none()
        } else {
            atlas_pca::canonicalize(&norm(&c["out"])) != atlas_pca::canonicalize(&norm(&got))
        };
        if differs {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
