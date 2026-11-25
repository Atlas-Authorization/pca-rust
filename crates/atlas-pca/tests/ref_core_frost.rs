//! Differential replay of the core FROST(Ed25519, SHA-512) module (RFC 9591 vectors plus hostile inputs) against the TypeScript
//! reference (test-data/ref-core-frost-java.json.gz, plus the CI-generated ref-core-frost-java-gen.json.gz that carries the cases
//! with private keys). Bytes cross as {"$bytes": b64u}; a reference throw only requires an Err. The one-shot nonce registry is
//! process-wide, so every case replays in file order inside one test.
mod common;
use atlas_pca::frost::*;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;

fn out(b: &[u8]) -> Value {
    json!({ "$bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b) })
}

fn bytes(v: &Value) -> Result<Vec<u8>, String> {
    let m = v.as_object().filter(|m| m.len() == 1).ok_or("expected bytes")?;
    Ok(common::b64d(m.get("$bytes").and_then(Value::as_str).ok_or("expected bytes")?))
}

fn opt_bytes(v: &Value) -> Result<Option<Vec<u8>>, String> {
    if v.is_null() {
        Ok(None)
    } else {
        bytes(v).map(Some)
    }
}

fn int(v: &Value) -> Result<i64, String> {
    let f = v.as_f64().ok_or("expected integer")?;
    if f.fract() != 0.0 || f.abs() > 9_007_199_254_740_991.0 {
        return Err("expected integer".into());
    }
    Ok(f as i64)
}

fn opt_int(v: &Value) -> Result<Option<i64>, String> {
    if v.is_null() {
        Ok(None)
    } else {
        int(v).map(Some)
    }
}

fn commitment_in(v: &Value) -> Result<FrostCommitment, String> {
    Ok(FrostCommitment {
        identifier: int(&v["identifier"])?,
        hiding: opt_bytes(&v["hiding"])?.unwrap_or_default(),
        binding: opt_bytes(&v["binding"])?.unwrap_or_default(),
    })
}

fn commitments_in(v: &Value) -> Result<Vec<FrostCommitment>, String> {
    v.as_array().ok_or("commitments must be a list")?.iter().map(commitment_in).collect()
}

fn sig_share_in(v: &Value) -> Result<FrostSigShare, String> {
    Ok(FrostSigShare { identifier: int(&v["identifier"])?, sig_share: opt_bytes(&v["sigShare"])?.unwrap_or_default() })
}

fn vs_in(v: &Value) -> Result<Option<Vec<FrostVerificationShare>>, String> {
    if v.is_null() {
        return Ok(None);
    }
    let l = v.as_array().ok_or("verificationShares must be a list")?;
    l.iter()
        .map(|x| Ok(FrostVerificationShare { identifier: int(&x["identifier"])?, public_key: opt_bytes(&x["publicKey"])?.unwrap_or_default() }))
        .collect::<Result<Vec<_>, String>>()
        .map(Some)
}

fn share_in(v: &Value) -> Result<FrostParticipantShare, String> {
    Ok(FrostParticipantShare {
        identifier: int(&v["identifier"])?,
        share: opt_bytes(&v["share"])?.unwrap_or_default(),
        public_key: opt_bytes(&v["publicKey"])?.unwrap_or_default(),
    })
}

fn commitment_out(c: &FrostCommitment) -> Value {
    json!({ "identifier": c.identifier, "hiding": out(&c.hiding), "binding": out(&c.binding) })
}

fn keygen_in(o: &Value) -> Result<FrostKeyShares, String> {
    let coeffs: Vec<Option<Vec<u8>>> = match o["coefficients"].as_array() {
        Some(l) => l.iter().map(opt_bytes).collect::<Result<_, _>>()?,
        None => Vec::new(),
    };
    let ids: Option<Vec<i64>> = match o["identifiers"].as_array() {
        Some(l) => Some(l.iter().map(int).collect::<Result<_, _>>()?),
        None => None,
    };
    frost_trusted_dealer_keygen(int(&o["t"])?, int(&o["n"])?, opt_bytes(&o["secret"])?.as_deref(), &coeffs, ids.as_deref())
}

fn keys_out(kg: &FrostKeyShares) -> Value {
    let ps: Vec<Value> =
        kg.participant_shares.iter().map(|p| json!({ "identifier": p.identifier, "share": out(&p.share), "publicKey": out(&p.public_key) })).collect();
    let gc: Vec<Value> = kg.group_commitment.iter().map(|c| out(c)).collect();
    json!({ "groupPublicKey": out(&kg.group_public_key), "participantShares": ps, "groupCommitment": gc })
}

fn flow(o: &Value) -> Result<Value, String> {
    let kg = keygen_in(o)?;
    let msg = bytes(&o["message"])?;
    let thr = opt_int(&o["threshold"])?;
    let rnd = o["randomness"].as_array().cloned().unwrap_or_default();
    let (mut commits, mut comms, mut vss, mut ids) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (k, s) in o["signers"].as_array().cloned().unwrap_or_default().iter().enumerate() {
        let id = int(s)?;
        let p = kg.participant_shares.iter().find(|p| p.identifier == id).ok_or("unknown signer")?;
        let r = rnd.get(k).cloned().unwrap_or(Value::Null);
        let c = frost_commit(p, Some(&bytes(&r["hr"])?), Some(&bytes(&r["br"])?))?;
        comms.push(c.commitment.clone());
        commits.push(c);
        ids.push(id);
        vss.push(FrostVerificationShare { identifier: id, public_key: p.public_key.clone() });
    }
    let mut shares = Vec::new();
    for (k, id) in ids.iter().enumerate() {
        let p = kg.participant_shares.iter().find(|p| p.identifier == *id).ok_or("unknown signer")?;
        let n = FrostNonces { hiding: commits[k].hiding_nonce.clone(), binding: commits[k].binding_nonce.clone() };
        let so = FrostSignOpts { threshold: thr, verification_share: Some(p.public_key.clone()), verification_shares: Some(vss.clone()) };
        shares.push(frost_sign(*id, &p.share, &kg.group_public_key, &n, &msg, &comms, &so)?);
    }
    let agg = frost_aggregate(&msg, &comms, &shares, &kg.group_public_key, Some(&vss), thr)?;
    let mut o2 = keys_out(&kg);
    o2["commitments"] = Value::Array(comms.iter().map(commitment_out).collect());
    o2["sigShares"] = Value::Array(shares.iter().map(|s| json!({ "identifier": s.identifier, "sigShare": out(&s.sig_share) })).collect());
    o2["aggregate"] = out(&agg);
    Ok(o2)
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let null = Value::Null;
    let arg = |i: usize| a.get(i).unwrap_or(&null);
    match f {
        "flow" => flow(arg(0)),
        "scalar" => Ok(out(&frost_scalar(&bytes(arg(0))?)?)),
        "isCanonicalScalar" => Ok(Value::Bool(bytes(arg(0)).is_ok_and(|b| frost_is_canonical_scalar(&b)))),
        "hash" => Ok(out(&frost_hash(arg(0).as_str().ok_or("hash name")?, &bytes(arg(1))?)?)),
        "decodeSafePoint" => Ok(out(&frost_decode_safe_point(&bytes(arg(0))?)?)),
        "keygen" => Ok(keys_out(&keygen_in(arg(0))?)),
        "verifyingShare" => Ok(out(&frost_verifying_share(&bytes(arg(0))?)?)),
        "commit" => {
            let p = FrostParticipantShare { identifier: int(arg(0))?, share: bytes(arg(1))?, public_key: Vec::new() };
            let (hr, br) = (opt_bytes(arg(2))?, opt_bytes(arg(3))?);
            let r = frost_commit(&p, hr.as_deref(), br.as_deref())?;
            Ok(json!({ "hidingNonce": out(&r.hiding_nonce), "bindingNonce": out(&r.binding_nonce), "commitment": commitment_out(&r.commitment) }))
        }
        "sign" => {
            let nm = arg(3).as_object().ok_or("nonces must be an object")?;
            let nonces = FrostNonces { hiding: bytes(nm.get("hiding").unwrap_or(&null))?, binding: bytes(nm.get("binding").unwrap_or(&null))? };
            let o = arg(6);
            let so = FrostSignOpts {
                threshold: opt_int(&o["threshold"])?,
                verification_share: opt_bytes(&o["verificationShare"])?,
                verification_shares: vs_in(&o["verificationShares"])?,
            };
            let gpk = opt_bytes(arg(2))?.unwrap_or_default();
            let s = frost_sign(int(arg(0))?, &bytes(arg(1))?, &gpk, &nonces, &bytes(arg(4))?, &commitments_in(arg(5))?, &so)?;
            Ok(json!({ "identifier": s.identifier, "sigShare": out(&s.sig_share) }))
        }
        "aggregate" => {
            let shares: Vec<FrostSigShare> = arg(2).as_array().ok_or("signature shares must be a list")?.iter().map(sig_share_in).collect::<Result<_, _>>()?;
            let gpk = opt_bytes(arg(3))?.unwrap_or_default();
            let vs = vs_in(&arg(4)["verificationShares"])?;
            let sig = frost_aggregate(&bytes(arg(0))?, &commitments_in(arg(1))?, &shares, &gpk, vs.as_deref(), opt_int(&arg(4)["threshold"])?)?;
            Ok(out(&sig))
        }
        "verifySigShare" => {
            let o = arg(0);
            let ok = (|| -> Result<bool, String> {
                Ok(frost_verify_sig_share(
                    int(&o["identifier"])?,
                    &opt_bytes(&o["publicKey"])?.unwrap_or_default(),
                    &commitment_in(&o["commitment"])?,
                    &sig_share_in(&o["sigShare"])?,
                    &commitments_in(&o["signingCommitments"])?,
                    &opt_bytes(&o["groupPublicKey"])?.unwrap_or_default(),
                    &opt_bytes(&o["message"])?.unwrap_or_default(),
                ))
            })();
            Ok(Value::Bool(ok.unwrap_or(false)))
        }
        "cosign" => {
            let gpk = bytes(arg(0))?;
            let q: Vec<FrostParticipantShare> = arg(1).as_array().ok_or("quorum must be a list")?.iter().map(share_in).collect::<Result<_, _>>()?;
            let msg = bytes(arg(2))?;
            let sig = frost_cosign(&gpk, &q, &msg, opt_int(&arg(3)["threshold"])?)?;
            let (pk, sg) = (<[u8; 32]>::try_from(&gpk[..]).map_err(|_| "pk")?, <[u8; 64]>::try_from(&sig[..]).map_err(|_| "sig")?);
            Ok(Value::Bool(
                ed25519_dalek::VerifyingKey::from_bytes(&pk).is_ok_and(|k| k.verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&sg)).is_ok()),
            ))
        }
        f => panic!("unknown fn {f}"),
    }
}

fn replay(cases: &[Value]) -> usize {
    let mut bad = Vec::new();
    for c in cases {
        let f = c["fn"].as_str().unwrap();
        // `flow` records its argument object bare under `args`.
        let args: Vec<Value> = if f == "flow" { vec![c["args"].clone()] } else { c["args"].as_array().cloned().unwrap_or_default() };
        let got = std::panic::catch_unwind(|| run(f, &args)).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
    cases.len()
}

#[test]
fn frost_vectors() {
    assert_eq!(replay(&common::ref_cases_seeded("core-frost-java")), 170);
    let gen = common::ref_gen_cases("core-frost-java", true);
    if !gen.is_empty() {
        assert_eq!(replay(&gen), 111);
    }
}
