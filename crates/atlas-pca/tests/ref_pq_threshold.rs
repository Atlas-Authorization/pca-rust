//! Differential replay of the PQ threshold step-up verifier (signed FROST group descriptor, ML-DSA-65 pqT-of-m quorum, hybrid
//! verdict) against the TypeScript reference (test-data/ref-pq-threshold.json.gz). A reference throw only requires an Err.
//! A raw `Uint8Array` key crosses as its base64url string (the reference reads both forms identically); message bytes and the
//! authority seed are decoded from `{"$bytes"}`. Skipped (counted, must stay under 10%): cases with a lone surrogate.
//! Not covered by the corpus and not ported: hybrid signing, the step-up fold and the core threshold hook (see src/pq_threshold.rs).
mod common;
use atlas_pca::pq_threshold::*;
use atlas_pca::serde_json::{json, Value};

/// `{"$bytes": s}` -> the string `s` (the base64url form of those bytes); everything else unchanged.
fn revive(v: &Value) -> Value {
    match v {
        Value::Object(m) if m.len() == 1 && m.get("$bytes").is_some_and(Value::is_string) => m["$bytes"].clone(),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), revive(x))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(revive).collect()),
        _ => v.clone(),
    }
}

fn b64u(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn bytes(v: &Value) -> Result<Vec<u8>, String> {
    v.get("$bytes").and_then(Value::as_str).and_then(|s| atlas_pca::decode_b64u_strict(s, None)).ok_or_else(|| "not a byte string".to_string())
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "signerSetCommitment" => signer_set_commitment(&revive(&a[0])).map(Value::String),
        "issueGroupDescriptor" => {
            let o = &a[0];
            let seed = bytes(&o["authoritySeed"])?;
            issue_group_descriptor(&seed, &revive(&o["groupPublicKey"]), &o["t"], &revive(&o["participants"]))
        }
        "verifyGroupDescriptor" => Ok(verify_group_descriptor(&revive(&a[0]), &revive(&a[1]))),
        "normalizePqQuorumPool" => Ok(Value::Array(normalize_pq_quorum_pool(&revive(&a[0]))?.into_iter().map(Value::String).collect())),
        "pqQuorumRepresentative" => Ok(json!({ "$bytes": b64u(&pq_quorum_representative(&bytes(&a[0])?)) })),
        "verifyPqQuorum" => {
            let pool = normalize_pq_quorum_pool(&revive(&a[2]))?;
            Ok(verify_pq_quorum(&revive(&a[0]), &bytes(&a[1])?, &pool, Some(&a[3])))
        }
        "verifyHybridThreshold" => Ok(verify_hybrid_threshold(&revive(&a[0]), &revive(&a[1]), &revive(&a[2]))),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn pq_threshold_vectors() {
    let cases = common::ref_cases_seeded("pq-threshold");
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
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

/// The fold, the core threshold hook and the full step-up verification against test-data/ref-pq-threshold-java-extra.json.gz. A
/// step-up case without an audience string is skipped (the native core always enforces the audience). `hybridSign` signs with the
/// native FROST + ML-DSA-65 co-signers, verifies the artifact, and compares the artifact (signature length only) and the verdict.
fn hybrid_sign(a: &Value) -> Result<Value, String> {
    use atlas_pca::frost::*;
    let int = |v: &Value| v.as_i64().ok_or_else(|| "expected integer".to_string());
    let opt = |v: &Value| -> Result<Option<Vec<u8>>, String> {
        if v.is_null() {
            Ok(None)
        } else {
            bytes(v).map(Some)
        }
    };
    let coeffs: Vec<Option<Vec<u8>>> =
        a["coefficients"].as_array().map(|l| l.iter().map(|x| opt(x)).collect::<Result<_, _>>()).transpose()?.unwrap_or_default();
    let kg = frost_trusted_dealer_keygen(int(&a["t"])?, int(&a["n"])?, opt(&a["secret"])?.as_deref(), &coeffs, None)?;
    let mut quorum = Vec::new();
    for q in a["quorum"].as_array().ok_or("quorum")? {
        let id = int(q)?;
        quorum.push(kg.participant_shares.iter().find(|p| p.identifier == id).ok_or("unknown quorum member")?.clone());
    }
    let seeds: Vec<Vec<u8>> = a["pqSeeds"].as_array().ok_or("pqSeeds")?.iter().map(bytes).collect::<Result<_, _>>()?;
    let mut signers = Vec::new();
    for i in a["pq"].as_array().ok_or("pq")? {
        signers.push(atlas_pca::pq::ml_dsa_65_keygen(&seeds[int(i)? as usize])?);
    }
    let t = int(&a["t"])?;
    let sign_t = if a["signT"].is_null() { t } else { int(&a["signT"])? };
    let gk_b64 = b64u(&kg.group_public_key);
    let gk = if a["groupAsString"] == json!(true) { GroupKeyInput::B64u(&gk_b64) } else { GroupKeyInput::Bytes(&kg.group_public_key) };
    let pq_t = if a["pqT"].is_null() { None } else { Some(int(&a["pqT"])?) };
    let action_v = revive(&a["action"]);
    let action = action_v.as_object().ok_or("action")?;
    let art = hybrid_threshold_sign(action, gk, &quorum, sign_t, &signers, pq_t)?;
    let parts: Vec<Value> = kg.participant_shares.iter().map(|p| json!({ "identifier": p.identifier, "publicKey": b64u(&p.public_key) })).collect();
    let auth = bytes(&a["authSeed"])?;
    let desc = issue_group_descriptor(&auth, &json!(gk_b64), &a["t"], &Value::Array(parts))?;
    let pool: Vec<Value> = signers.iter().map(|s| json!(b64u(&s.public_key))).collect();
    let vt = if a["pqT"].is_null() { json!(signers.len()) } else { a["pqT"].clone() };
    let auth_pk = ed25519_dalek::SigningKey::from_bytes(&<[u8; 32]>::try_from(&auth[..]).map_err(|_| "authSeed")?).verifying_key().to_bytes();
    let verdict = verify_hybrid_threshold(
        &Value::Object(action.clone()),
        &art,
        &json!({ "groupKey": gk_b64, "pqPublicKeys": pool, "t": a["t"], "pqT": vt, "groupDescriptor": desc, "trustedAuthorities": [b64u(&auth_pk)] }),
    );
    let mut out_art = art.clone();
    let sig_len = art["frost"]["sig"].as_str().map_or(0, str::len);
    let f = out_art["frost"].as_object_mut().unwrap();
    f.remove("sig");
    f.insert("sigLen".into(), json!(sig_len));
    Ok(json!({ "artifact": out_art, "verdict": verdict }))
}

fn run_extra(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "hybridSign" => {
            let mut v = a[0].clone();
            common::resolve_seeds(&mut v);
            hybrid_sign(&v)
        }
        "fold" => fold_hybrid_step_up(&revive(&a[0]), &revive(&a[1])),
        "hook" => create_hybrid_threshold_verifier(&revive(&a[0]))?(&revive(&a[1])),
        "stepUp" => {
            let (s, o) = (revive(&a[0]), revive(&a[1]));
            let r = verify_hybrid_step_up(&s, &o)?;
            Ok(json!({"allow": r["allow"], "pq": r["pq"]}))
        }
        f => Err(format!("not replayed: {f}")),
    }
}

#[test]
fn pq_threshold_fold_hook_and_step_up_vectors() {
    let cases = common::ref_cases("pq-threshold-java-extra");
    let (mut bad, mut skipped, mut run_n) = (Vec::new(), 0, 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        let no_audience = f == "stepUp" && !c["args"][1]["audience"].is_string();
        if no_audience || common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        run_n += 1;
        let got = std::panic::catch_unwind(|| run_extra(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| Err("panic".into()));
        let want = if f == "stepUp" { json!({"allow": c["out"]["allow"], "pq": c["out"]["pq"]}) } else { revive(&c["out"]) };
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&want) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], want, got));
        }
    }
    assert!(run_n >= 60, "only {run_n} cases ran ({skipped} skipped)");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
