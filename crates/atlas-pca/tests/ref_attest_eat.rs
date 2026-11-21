//! Differential replay of the EAT attestation layer (build / verify, freshness, channel binding, RATS appraisal, tolerant SEV-SNP
//! parse, AMD delegation, post-quantum co-signature, admission evidence, artifact discharge) against the TypeScript reference
//! (test-data/ref-attest-eat.json.gz). A reference throw only requires a refusal.
//!
//! Where this port is deliberately stricter than the vectors the case is asserted as a refusal instead (STRICTER: a present
//! `clockSkewMs` that is not a finite number would disable the age window; an admission `minTier` outside `affirming` /
//! `affirming-hw-rooted`). Two rules postdate the vectors and are asserted by `appraise_hardening` below: a present `dbgstat` that is
//! not an RFC 9711 value is an unknown debug status, and a `minTcb` that is null / boolean / array is not a comparable TCB version.
//! Skipped (counted, must stay under 10%): cases with a lone surrogate, and the three cases whose expected output depends on the
//! day the vectors were made (the real clock). ES256 tokens are verify-only inputs; ES256 signing is not provided.
mod common;
use atlas_pca::agent::{KeyPair, PqKeyPair};
use atlas_pca::attest_eat::*;
use atlas_pca::jose::{import_public_jwk, JwkKey};
use atlas_pca::serde_json::{json, Value};
use atlas_pca::sigstore::parse_trusted_root;
use sha2::{Digest, Sha256};

const STRICTER: [&str; 8] = [
    "verifyFreshness/skew junk string",
    "verifyFreshness/skew junk stale",
    "verifyFreshness/skew string number",
    "verifyFreshness/skew null",
    "verifyFreshness/skew true",
    "verifyFreshAttestedEAT/amd skew junk",
    "eatAdmissionEvidence/min tier unknown",
    "eatAdmissionEvidence/min tier null",
];
const CLOCK: [&str; 3] = ["verifyFreshness/now missing uses clock", "verifyFreshness/now string uses clock", "verifyCoSignedAttestation/now string uses clock"];
const DBGSTAT: [&str; 5] = ["enabled", "disabled", "disabled-since-boot", "disabled-permanently", "disabled-fully-and-permanently"];

fn verify_key(spec: &Value) -> JwkKey {
    let alg = spec["alg"].as_str().expect("key alg");
    let jwk = if alg == "EdDSA" {
        json!({"kty": "OKP", "crv": "Ed25519", "x": spec["pub"]})
    } else {
        json!({"kty": "EC", "crv": "P-256", "x": spec["x"], "y": spec["y"]})
    };
    import_public_jwk(&jwk, alg).expect("verify key")
}

fn seed32(b64u: &str) -> [u8; 32] {
    common::b64d(b64u).try_into().expect("32-byte seed")
}

fn pq_family(prim: &str) -> &'static str {
    match prim {
        "ml-dsa-65" => "ML-DSA-65",
        "ml-dsa-87" => "ML-DSA-87",
        "slh-dsa-sha2-128f" => "SLH-DSA-SHA2-128f",
        "slh-dsa-sha2-256s" => "SLH-DSA-SHA2-256s",
        p => panic!("unknown prim {p}"),
    }
}

fn cosign(verdict: &Value, op: &Value) -> Result<Value, String> {
    let spec = &op["key"];
    let ed = spec.get("ed").and_then(Value::as_str).map(|s| KeyPair::from_seed(&seed32(s)));
    let pq = spec.get("pq").map(|p| PqKeyPair::from_seed(pq_family(p["prim"].as_str().unwrap()), &common::b64d(p["seed"].as_str().unwrap())).expect("pq keys"));
    let keys = CoSignKeys { ed: ed.as_ref(), pq: pq.as_ref() };
    co_sign_attestation(verdict, op.get("suite"), Some(&keys), op.get("now"))
}

fn discharge(i: &Value) -> Result<Value, String> {
    let roots = parse_trusted_root(&i["roots"])?;
    let seed = seed32(i["issuerKey"]["seed"].as_str().unwrap());
    // the reference's counter-hash nonce, first draw (the counter restarts at every call)
    let nonce = atlas_pca::attest::util::b64url_enc(&Sha256::digest(b"eat-oracle-nonce/0")[..16]);
    let mut i = i.clone();
    i["nonce"] = json!(nonce);
    issue_artifact_discharge(&i, &roots, &seed)
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let u = |i: usize| a.get(i);
    match f {
        "constants" => Ok(constants()),
        "deriveChannelCnf" => derive_channel_cnf(u(0), u(1)),
        "bindChannel" => bind_channel(u(0), u(1), u(2)),
        "buildEAT" => {
            let seed = a[0].get("key").and_then(|k| k.get("seed")).and_then(Value::as_str).map(seed32);
            build_eat(&a[0], seed.as_ref()).map(Value::String)
        }
        "verifyEAT" => verify_eat(u(0), &verify_key(&a[1]), u(2).filter(|v| !v.is_null())),
        "verifyFreshness" => verify_freshness(u(0), u(1)),
        "verifyChannelBinding" => verify_channel_binding(u(0), u(1)),
        "appraise" => appraise(u(0), u(1), u(2), u(3)),
        "parseReportTolerant" => {
            let raw = bytes_of(u(0));
            let (mut v, report) = parse_report_tolerant(raw.as_deref());
            v["hasReport"] = json!(report.is_some());
            if let Some(r) = &report {
                v["measured"] = measured_from_report(r);
            }
            Ok(v)
        }
        "verifyAmdAttestation" => Ok(verify_amd_attestation(u(0), u(1))),
        "verifyFreshAttestedEAT" => verify_fresh_attested_eat(u(0), &verify_key(&a[1]["verifyKey"]), u(1)),
        "canonicalVerdictBytes" => canonical_verdict_bytes(u(0), u(1)).map(|b| bytes_value(&b)),
        "verdictFromAppraisal" => verdict_from_appraisal(u(0), u(1)),
        "isPqCoSignSuite" => Ok(json!(is_pq_co_sign_suite(u(0)))),
        "coSignAttestation" => cosign(&a[0], &a[1]),
        "verifyCoSignedAttestation" => Ok(verify_co_signed_attestation(u(0), u(1))),
        "ed25519Jkt" => Ok(json!(ed25519_jkt(u(0)))),
        "eatAdmissionEvidence" => Ok(eat_admission_evidence(u(0), &verify_key(&a[1]["verifyKey"]), u(1))),
        "runtimeDigestFromEat" => runtime_digest_from_eat(u(0), u(1)),
        "issueArtifactDischarge" => discharge(&a[0]),
        f => panic!("unknown fn {f}"),
    }
}

/// The two rules that postdate the vectors: the old reference read an invalid dbgstat as "disabled" and a null / boolean / array
/// minTcb as 0; the hardened one fails closed on both.
fn appraise_postdates(got: &Value, c: &Value) -> bool {
    let a = c["args"].as_array().unwrap();
    let rv = a.get(1).cloned().unwrap_or(Value::Null);
    let last = got["reasons"].as_array().and_then(|r| r.last()).and_then(Value::as_str).unwrap_or("");
    let bad_dbg = a[0].get("dbgstat").is_some_and(|d| !d.as_str().is_some_and(|s| DBGSTAT.contains(&s))) && rv["requireDebugDisabled"] == json!(true);
    let bad_tcb = matches!(rv.get("minTcb"), Some(Value::Null | Value::Bool(_) | Value::Array(_)));
    got["tier"] == json!("rejected")
        && ((bad_dbg && last == "debug status unknown \u{2014} failing closed") || (bad_tcb && last == "reference minTcb is not a comparable TCB version"))
}

#[test]
fn attest_eat_vectors() {
    let mut cases = common::ref_cases_seeded("attest-eat");
    cases.extend(common::ref_gen_cases("attest-eat", true));
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let (f, name) = (c["fn"].as_str().unwrap(), c["name"].as_str().unwrap());
        if common::has_lone(&c["args"]) || CLOCK.contains(&name) {
            skipped += 1;
            continue;
        }
        let args = c["args"].as_array().unwrap();
        let got = std::panic::catch_unwind(|| run(f, args)).unwrap_or_else(|_| Err("panic".into()));
        let ok = if STRICTER.contains(&name) {
            matches!(&got, Ok(v) if v["ok"] == json!(false))
        } else {
            match (c["out"].get("$throws"), &got) {
                (Some(_), Err(_)) => true,
                (None, Ok(v)) => {
                    // without an explicit `now` the age is measured against the wall clock of the run that wrote the corpus
                    let clocked = f == "verifyCoSignedAttestation" && c["out"].get("ageMs").is_some() && !c["args"].to_string().contains("\"now\"");
                    let strip = |x: &Value| {
                        let mut y = x.clone();
                        if let Some(m) = y.as_object_mut().filter(|_| clocked) {
                            m.remove("ageMs");
                        }
                        y
                    };
                    atlas_pca::canonicalize(&strip(&c["out"])) == atlas_pca::canonicalize(&strip(v)) || (f == "appraise" && appraise_postdates(v, c))
                }
                _ => false,
            }
        };
        if !ok {
            bad.push(format!("{name}\n  want {}\n  got  {got:?}", c["out"]));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn stricter_cases_are_present() {
    let names: Vec<String> = common::ref_cases_seeded("attest-eat").iter().chain(common::ref_gen_cases("attest-eat", true).iter()).map(|c| c["name"].as_str().unwrap().to_string()).collect();
    for n in STRICTER.iter().chain(CLOCK.iter()) {
        assert!(names.iter().any(|x| x == n), "{n}");
    }
}

fn reasons_of(v: &Value) -> Vec<String> {
    v["reasons"].as_array().unwrap().iter().map(|r| r.as_str().unwrap().to_string()).collect()
}

/// Hand-computed from the reference (the rules of the 2026-11 hardening), beyond the vectors.
#[test]
fn appraise_hardening() {
    let sev = |tcb: Value| json!({"iss": "i", "sevsnp": {"version": 3, "measurement": "aa", "reported_tcb": tcb}});

    // a present dbgstat outside RFC 9711 is unknown, never "disabled"; no fallback to sevsnp.debug
    let rv = json!({"requireDebugDisabled": true});
    for bad in [json!("bogus"), json!(5), json!(null), json!("Disabled"), json!("")] {
        let ev = json!({"iss": "i", "dbgstat": bad, "sevsnp": {"version": 3, "measurement": "aa", "debug": false}});
        let r = appraise(Some(&ev), Some(&rv), None, None).unwrap();
        assert_eq!((r["tier"].as_str(), r["trustworthy"].as_bool()), (Some("rejected"), Some(false)), "{bad}");
        assert_eq!(reasons_of(&r), ["debug status unknown \u{2014} failing closed"]);
    }
    for ok in DBGSTAT.iter().filter(|d| **d != "enabled") {
        let r = appraise(Some(&json!({"iss": "i", "dbgstat": ok})), Some(&rv), None, None).unwrap();
        assert_eq!((r["tier"].as_str(), reasons_of(&r)), (Some("affirming"), vec!["debug disabled".to_string()]), "{ok}");
    }
    let r = appraise(Some(&json!({"iss": "i", "dbgstat": "enabled"})), Some(&rv), None, None).unwrap();
    assert_eq!(r["tier"], "contraindicated");
    assert_eq!(reasons_of(&r), ["debug is enabled (host can inspect the guest \u{2014} no confidentiality)"]);
    let r = appraise(Some(&json!({"iss": "i", "sevsnp": {"version": 3, "measurement": "aa", "debug": false}})), Some(&rv), None, None).unwrap();
    assert_eq!(r["tier"], "affirming");

    // a null / boolean / array minTcb is not a TCB version (the old reference packed true / [] to 0 and threw on null)
    for bad in [json!(null), json!(true), json!(false), json!([]), json!([1])] {
        let r = appraise(Some(&sev(json!("5"))), Some(&json!({"minTcb": bad})), None, None).unwrap();
        assert_eq!((r["tier"].as_str(), r["trustworthy"].as_bool()), (Some("rejected"), Some(false)), "{bad}");
        assert_eq!(reasons_of(&r), ["reference minTcb is not a comparable TCB version"]);
    }

    // comparable shapes: an empty object is 0; decimal strings compare as integers (leading zeros, beyond 2^64)
    let cmp = |ev_tcb: Value, min: Value| appraise(Some(&sev(ev_tcb)), Some(&json!({"minTcb": min})), None, None).unwrap();
    let r = cmp(json!("5"), json!({}));
    assert_eq!((r["tier"].as_str(), reasons_of(&r)), (Some("affirming"), vec!["TCB at or above reference minimum".to_string()]));
    assert_eq!(cmp(json!("007"), json!("7"))["tier"], "affirming");
    assert_eq!(cmp(json!("7"), json!("8"))["tier"], "contraindicated");
    assert_eq!(cmp(json!("18446744073709551615"), json!("18446744073709551616"))["tier"], "contraindicated");
    assert_eq!(cmp(json!("18446744073709551616"), json!("18446744073709551615"))["tier"], "affirming");
    assert_eq!(cmp(json!({"snp": 2}), json!({"snp": 1, "tee": 255}))["tier"], "affirming");
    assert_eq!(cmp(json!({"snp": 1}), json!({"snp": 2}))["tier"], "contraindicated");
    assert_eq!(cmp(json!({"tee": 256}), json!("1"))["tier"], "rejected"); // component out of range: evidence TCB unknown
    assert_eq!(cmp(json!(null), json!("1"))["tier"], "rejected");
}
