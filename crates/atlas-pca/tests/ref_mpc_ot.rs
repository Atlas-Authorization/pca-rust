//! Differential replay of the MPC oblivious-transfer stack (Ed25519 group and Schnorr proofs, the word-array kernels, the base OT,
//! IKNP/KOS extension, the ML-KEM and hybrid base OTs, the MASCOT no-dealer offline phase and the no-dealer malicious runner)
//! against the TypeScript reference (test-data/ref-mpc-ot.json.gz). Every random draw comes from the seeded SplitMix64 stream, so
//! points, pads, matrices and shares match the reference value for value. Big integers cross as DECIMAL STRINGS, bytes as
//! {"$bytes": b64url} (or a bare b64url string where the reference passed a seed), u32 words as JSON numbers. A reference throw
//! only requires a refusal.
//! Skipped: nothing is skipped by design. The ML-KEM cases (kemOt, hybridOt) replay the deterministic key generation (`d || z`
//! from the seeded stream) and derandomised encapsulation of the `ml-kem` crate; if that crate version lacks those hooks the
//! crate does not compile, there is no silent skip.
mod common;
use atlas_pca::mpc::*;
use atlas_pca::mpc_mascot::*;
use atlas_pca::mpc_ot::*;
use atlas_pca::serde_json::{json, Map, Value};
use base64::Engine;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rsa::BigUint;

static NULL: Value = Value::Null;
type R = Result<Value, String>;

fn arg(a: &[Value], i: usize) -> &Value {
    a.get(i).unwrap_or(&NULL)
}

fn err<E: ToString>(e: E) -> String {
    e.to_string()
}

fn text(v: &Value) -> Result<&str, String> {
    v.as_str().ok_or_else(|| "not a string".to_string())
}

fn number(v: &Value) -> Result<f64, String> {
    v.as_f64().ok_or_else(|| "not a number".to_string())
}

/// A JS integer argument: a non-integer is a refusal.
fn int(v: &Value) -> Result<i64, String> {
    let f = number(v)?;
    if !f.is_finite() || f != f.trunc() {
        return Err("not an integer".into());
    }
    Ok(f.clamp(-1e15, 1e15) as i64)
}

fn uint(v: &Value) -> Result<usize, String> {
    let i = int(v)?;
    if i < 0 {
        return Err("negative".into());
    }
    Ok(i as usize)
}

fn list(v: &Value) -> Result<&Vec<Value>, String> {
    v.as_array().ok_or_else(|| "not a list".to_string())
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn bytes_out(b: &[u8]) -> Value {
    json!({ "$bytes": b64(b) })
}

fn bytes_arg(v: &Value) -> Result<Vec<u8>, String> {
    let s = match v {
        Value::String(s) => s.as_str(),
        Value::Object(m) => m.get("$bytes").and_then(Value::as_str).ok_or("expected bytes")?,
        _ => return Err("expected bytes".into()),
    };
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).map_err(|_| "bad base64url".to_string())
}

fn words(v: &Value) -> Result<Vec<u32>, String> {
    list(v)?
        .iter()
        .map(|x| {
            let f = number(x)?;
            if f < 0.0 || f > 4294967295.0 || f != f.trunc() {
                return Err("not a u32 word".to_string());
            }
            Ok(f as u32)
        })
        .collect()
}

fn words_out(w: &[u32]) -> Value {
    Value::Array(w.iter().map(|x| json!(*x)).collect())
}

fn dec_list(v: &Value) -> Result<Vec<String>, String> {
    list(v)?.iter().map(|x| text(x).map(String::from)).collect()
}

fn dec_big(s: &str) -> Result<BigUint, String> {
    BigUint::parse_bytes(s.as_bytes(), 10).filter(|_| !s.is_empty()).ok_or_else(|| "not a non-negative decimal".to_string())
}

fn pt(v: &Value) -> Result<EdwardsPoint, String> {
    ec_from_extended_dec(&dec_list(v)?).map_err(err)
}

fn aff(p: &EdwardsPoint) -> Value {
    let (x, y) = ec_to_affine_dec(p);
    json!({"x": x, "y": y})
}

fn affs(ps: &[EdwardsPoint]) -> Value {
    Value::Array(ps.iter().map(aff).collect())
}

fn z_dec(z: &[u8; 32]) -> String {
    BigUint::from_bytes_le(z).to_str_radix(10)
}

fn bl(l: &[Vec<u8>]) -> Value {
    Value::Array(l.iter().map(|b| bytes_out(b)).collect())
}

fn pairs_out(ps: &[OtPair]) -> Value {
    Value::Array(ps.iter().map(|p| json!([bytes_out(&p[0]), bytes_out(&p[1])])).collect())
}

fn pairs_in(v: &Value) -> Result<Vec<OtPair>, String> {
    list(v)?
        .iter()
        .map(|e| {
            let p = list(e)?;
            if p.len() != 2 {
                return Err("not a pair".to_string());
            }
            Ok([bytes_arg(&p[0])?, bytes_arg(&p[1])?])
        })
        .collect()
}

fn choices(v: &Value) -> Result<Vec<i64>, String> {
    list(v)?.iter().map(int).collect()
}

fn rng(v: &Value) -> Result<OtRng, String> {
    OtRng::from_decimal(text(v)?).map_err(err)
}

fn flip(b: &[u8], mask: u8) -> Vec<u8> {
    b.iter().map(|x| x ^ mask).collect()
}

fn order2() -> EdwardsPoint {
    let q = (BigUint::from(1u8) << 255usize) - BigUint::from(20u8); // q - 1
    ec_from_extended_dec(&["0".to_string(), q.to_str_radix(10), "1".to_string(), "0".to_string()]).expect("the order-2 point")
}

fn scalar_plus_one(z: &[u8; 32]) -> [u8; 32] {
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(*z)).expect("canonical z");
    (s + Scalar::ONE).to_bytes()
}

fn base_tamper(name: &str) -> Result<Option<BaseOtTamper>, String> {
    let mut t = BaseOtTamper::default();
    match name {
        "none" | "" => return Ok(None),
        "S_identity" => t.tamper_s = Some(Box::new(|_| ec_identity())),
        "S_order2" => t.tamper_s = Some(Box::new(|_| order2())),
        "S_other" => t.tamper_s = Some(Box::new(|s| s + ec_base())),
        "proof_z" => t.tamper_proof = Some(Box::new(|p| SchnorrProof { u: p.u, z: scalar_plus_one(&p.z) })),
        "proof_U" => t.tamper_proof = Some(Box::new(|p| SchnorrProof { u: p.u + ec_base(), z: p.z })),
        "R0_identity" => {
            t.tamper_r = Some(Box::new(|r| {
                if !r.is_empty() {
                    r[0] = ec_identity();
                }
            }))
        }
        "R1_order2" => {
            t.tamper_r = Some(Box::new(|r| {
                if r.len() > 1 {
                    r[1] = order2();
                }
            }))
        }
        "R_swap" => {
            t.tamper_r = Some(Box::new(|r| {
                if r.len() > 1 {
                    r.swap(0, 1);
                }
            }))
        }
        "ct_flip" => {
            t.tamper_ciphertext = Some(Box::new(|ct| {
                if !ct.is_empty() {
                    ct[0][0] = flip(&ct[0][0], 1);
                }
            }))
        }
        "ct_flip1" => {
            t.tamper_ciphertext = Some(Box::new(|ct| {
                if let Some(last) = ct.last_mut() {
                    last[1] = flip(&last[1], 0x80);
                }
            }))
        }
        other => return Err(format!("unknown tamper {other}")),
    }
    Ok(Some(t))
}

fn kem_tamper(v: &Value) -> Option<KemMalTamper> {
    match v.as_str() {
        Some("badKey") => Some(KemMalTamper {
            tamper_opened_keys: Some(Box::new(|pk| {
                if !pk.is_empty() {
                    let (a, b) = (pk[0][0].clone(), pk[0][1].clone());
                    pk[0] = [b, a];
                }
            })),
            tamper_receiver_sid: None,
        }),
        Some("badSid") => Some(KemMalTamper { tamper_opened_keys: None, tamper_receiver_sid: Some(Box::new(|s| flip(s, 1))) }),
        _ => None,
    }
}

fn ec_op(a: &[Value]) -> R {
    let op = text(arg(a, 0))?;
    match op {
        "mulBase" => {
            let k = ec_scalar_from_decimal(text(arg(a, 1))?).map_err(err)?;
            let p = ec_mul_base(&k);
            Ok(json!({"p": aff(&p), "enc": bytes_out(&ec_encode_point(&p)), "comp": bytes_out(&ec_compress(&p))}))
        }
        "mul" => {
            let k = ec_scalar_from_decimal(text(arg(a, 1))?).map_err(err)?;
            Ok(aff(&ec_mul(&k, &pt(arg(a, 2))?)))
        }
        "add" => Ok(aff(&(pt(arg(a, 1))? + pt(arg(a, 2))?))),
        "sub" => Ok(aff(&(pt(arg(a, 1))? - pt(arg(a, 2))?))),
        "neg" => Ok(aff(&(-pt(arg(a, 1))?))),
        "dbl" => {
            let p = pt(arg(a, 1))?;
            Ok(aff(&(p + p)))
        }
        "decompress" => {
            let p = ec_decompress(&bytes_arg(arg(a, 1))?).map_err(err)?;
            Ok(json!({"p": aff(&p), "onCurve": true, "identity": ec_is_identity(&p), "prime": ec_has_prime_order(&p), "inSub": ec_is_in_subgroup(&p)}))
        }
        o => Err(format!("unknown op {o}")),
    }
}

fn ec_validate(a: &[Value]) -> R {
    let coords = dec_list(arg(a, 0))?;
    match ec_from_extended_dec(&coords) {
        Ok(p) => Ok(json!({"onCurve": true, "identity": ec_is_identity(&p), "prime": ec_has_prime_order(&p), "inSubgroup": ec_is_in_subgroup(&p)})),
        Err(_) => Ok(json!({"onCurve": false, "identity": ec_raw_identity(&coords), "prime": false, "inSubgroup": false})),
    }
}

fn schnorr(a: &[Value]) -> R {
    let y = ec_scalar_from_decimal(text(arg(a, 0))?).map_err(err)?;
    let nonce = ec_scalar_from_decimal(text(arg(a, 1))?).map_err(err)?;
    let ctx = bytes_arg(arg(a, 2))?;
    let s = ec_mul_base(&y);
    let proof = schnorr_prove(&y, &s, &nonce, &ctx).map_err(err)?;
    let other = b"other-ctx";
    let forged = SchnorrProof { u: proof.u, z: scalar_plus_one(&proof.z) };
    let oor = SchnorrProof { u: proof.u, z: ec_l_bytes() };
    Ok(json!({"S": aff(&s), "U": aff(&proof.u), "z": z_dec(&proof.z), "ok": schnorr_verify(&s, &proof, &ctx), "badCtx": schnorr_verify(&s, &proof, other),
        "forged": schnorr_verify(&s, &forged, &ctx), "oor": schnorr_verify(&s, &oor, &ctx),
        "wrongS": schnorr_verify(&ec_mul_base(&(y + Scalar::ONE)), &proof, &ctx), "identityS": schnorr_verify(&ec_identity(), &proof, &ctx)}))
}

fn kernel(f: &str, a: &[Value]) -> R {
    Ok(match f {
        "prg" => {
            let sb = number(arg(a, 1))?;
            if sb < 0.0 || sb != sb.trunc() {
                return Err("bad start block".into());
            }
            words_out(&otx_prg_column(&bytes_arg(arg(a, 0))?, sb as u64, uint(arg(a, 2))?))
        }
        "maskTail" => {
            let mut w = words(arg(a, 0))?;
            otx_mask_tail(&mut w, uint(arg(a, 1))?);
            words_out(&w)
        }
        "transpose32" => {
            let mut w = words(arg(a, 0))?;
            if w.len() != 32 {
                return Err("transpose32 needs 32 words".into());
            }
            otx_transpose32(&mut w, 0);
            words_out(&w)
        }
        "transposeCols" => words_out(&otx_transpose_cols(&words(arg(a, 0))?, uint(arg(a, 1))?, uint(arg(a, 2))?).map_err(err)?),
        "gfMulX" => {
            let mut w = words(arg(a, 0))?;
            if w.len() != 4 {
                return Err("needs 4 words".into());
            }
            otx_gf_mul_x(&mut w);
            words_out(&w)
        }
        "gfXorInto" => {
            let (mut w, b) = (words(arg(a, 0))?, words(arg(a, 1))?);
            if w.len() != 4 || b.len() != 4 {
                return Err("needs 4 words".into());
            }
            otx_gf_xor_into(&mut w, &b, 0);
            words_out(&w)
        }
        "gfBig" => {
            let w = words(arg(a, 0))?;
            if w.len() != 4 {
                return Err("needs 4 words".into());
            }
            let v = otx_gf_to_u128(&w);
            json!({"big": v.to_string(), "back": words_out(&otx_gf_from_u128(v))})
        }
        "accumColumn" => {
            let (col, chi) = (words(arg(a, 0))?, words(arg(a, 1))?);
            if chi.len() < col.len() * 32 * 4 {
                return Err("challenges too short".into());
            }
            let mut acc = vec![0u32; 4];
            otx_accum_column(&col, &chi, &mut acc);
            words_out(&acc)
        }
        "kosCombine" => words_out(&otx_kos_combine(&words(arg(a, 0))?, uint(arg(a, 1))?, &words(arg(a, 2))?).map_err(err)?),
        "tmmo" => {
            let off = number(arg(a, 2))?;
            if off != off.trunc() {
                return Err("tweak offset must be a non-negative safe integer".into());
            }
            words_out(&otx_tmmo_crh(&words(arg(a, 0))?, uint(arg(a, 1))?, off as i64, &words(arg(a, 3))?).map_err(err)?)
        }
        "tweakDomain" => words_out(&otx_tweak_domain(&bytes_arg(arg(a, 0))?)),
        "bigBytes" => bytes_out(&otx_big_to_bytes(&dec_big(text(arg(a, 0))?)?, uint(arg(a, 1))?)),
        "bytesBig" => Value::String(otx_bytes_to_big(&bytes_arg(arg(a, 0))?).to_str_radix(10)),
        "word64" => {
            let (w, j) = (words(arg(a, 0))?, uint(arg(a, 1))?);
            if 2 * j + 1 >= w.len() {
                return Err("word64 index out of range".into());
            }
            Value::String(otx_word64(&w, j).to_string())
        }
        o => return Err(format!("unknown kernel {o}")),
    })
}

fn binding_bytes_case(a: &[Value]) -> R {
    let b = BaseOtBinding {
        session_id: bytes_arg(arg(a, 0))?,
        sender_index: int(arg(a, 1))?,
        receiver_index: int(arg(a, 2))?,
        round: text(arg(a, 3))?.to_string(),
    };
    Ok(bytes_out(&binding_bytes(&b).map_err(err)?))
}

fn base_ot_kdf_case(a: &[Value]) -> R {
    let i = uint(arg(a, 0))?;
    let b0 = random_binding(&mut OtRng::Seeded(4242), "base-ot");
    let k = |n: u64| ec_mul_base(&Scalar::from(n));
    let r = vec![k(5), k(6)];
    let th = base_ot_transcript_hash(&b0, &k(3), &r).map_err(err)?;
    Ok(json!({"th": bytes_out(&th), "k": bytes_out(&base_ot_kdf(&th, i, &r[0], &k(9)))}))
}

fn random_ot_case(a: &[Value]) -> R {
    let ch = choices(arg(a, 0))?;
    let mut g = rng(arg(a, 1))?;
    let t = base_tamper(arg(a, 2).as_str().unwrap_or(""))?;
    let r = mal_base_random_ot(&ch, &mut g, t.as_ref(), None).map_err(err)?;
    Ok(
        json!({"S": aff(&r.s), "U": aff(&r.proof.u), "z": z_dec(&r.proof.z), "R": affs(&r.r), "senderPads": pairs_out(&r.sender_pads), "recvPads": bl(&r.recv_pads)}),
    )
}

fn base_ot_case(a: &[Value]) -> R {
    let msgs = pairs_in(arg(a, 0))?;
    let ch = choices(arg(a, 1))?;
    let mut g = rng(arg(a, 2))?;
    let t = base_tamper(arg(a, 3).as_str().unwrap_or(""))?;
    let r = base_ot(&msgs, &ch, &mut g, t.as_ref(), None).map_err(err)?;
    let tr = &r.transcript;
    Ok(
        json!({"received": bl(&r.received), "S": aff(&tr.s), "U": aff(&tr.proof.u), "z": z_dec(&tr.proof.z), "R": affs(&tr.r), "ct": pairs_out(&tr.ct), "com": pairs_out(&tr.com)}),
    )
}

fn msg64(v: &Value) -> Result<u64, String> {
    let b = dec_big(text(v)?)?;
    if b.bits() > 64 {
        return Err("message must be in [0, 2^64)".into());
    }
    let mut le = b.to_bytes_le();
    le.resize(8, 0);
    Ok(u64::from_le_bytes(le.try_into().map_err(|_| "width".to_string())?))
}

fn channel_case(a: &[Value]) -> R {
    let ch = choices(arg(a, 0))?;
    let m0 = list(arg(a, 1))?.iter().map(msg64).collect::<Result<Vec<_>, _>>()?;
    let m1 = list(arg(a, 2))?.iter().map(msg64).collect::<Result<Vec<_>, _>>()?;
    let g = rng(arg(a, 3))?;
    let rounds = uint(arg(a, 4))?;
    let mut c = OtChannel::new(g, None, None);
    c.tamper_u = match arg(a, 5).as_str() {
        Some("flip00") => Some(Box::new(|u, _| u[0].v = u[0].v.clone() ^ BigUint::from(1u8))),
        Some("flipLast") => Some(Box::new(|u, _| u[127].v = u[127].v.clone() ^ BigUint::from(32u8))),
        Some("oversize") => Some(Box::new(|u, _| u[3].v = u[3].v.clone() | (BigUint::from(1u8) << 5000usize))),
        Some("negative") => Some(Box::new(|u, _| u[3] = UCol { neg: true, v: BigUint::from(1u8) })),
        Some("round2flip") => Some(Box::new(|u, round| {
            if round == 1 {
                u[10].v = u[10].v.clone() ^ BigUint::from(2u8);
            }
        })),
        _ => None,
    };
    let mut outs = vec![];
    for _ in 0..rounds {
        let e = c.extend(&ch, &m0, &m1).map_err(err)?;
        outs.push(json!({"received": e.received.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
            "uMatrix": e.u_matrix.iter().map(|u| u.to_decimal()).collect::<Vec<_>>()}));
    }
    let sel = c.selector().map_err(err)?;
    let base = match &c.base_transcript {
        Some(t) => json!({"S": aff(&t.s), "R": t.r.len()}),
        None => Value::Null,
    };
    Ok(json!({"selector": sel.to_string(), "outs": outs, "base": base}))
}

fn kos_chi_case(a: &[Value]) -> R {
    let b = bytes_arg(arg(a, 0))?;
    let round = uint(arg(a, 1))?;
    let u = list(arg(a, 2))?.iter().map(|x| dec_big(text(x)?)).collect::<Result<Vec<_>, _>>()?;
    let m_ext = uint(arg(a, 3))?;
    let w = kos_chi_words(&b, round, &u, m_ext);
    let chi: Vec<String> = kos_challenges(&b, round, &u, m_ext).iter().map(|c| c.to_string()).collect();
    Ok(json!({"w": words_out(&w), "chi": chi}))
}

fn mal_transcript_out(t: &KemMalTranscript, with_enc: bool) -> Value {
    let mut v = json!({"rn": bytes_out(&t.rn), "commitments": bl(&t.commitments), "sn": bytes_out(&t.sn), "publicKeys": pairs_out(&t.public_keys), "ciphertexts": pairs_out(&t.ciphertexts)});
    if with_enc {
        v["encrypted"] = pairs_out(&t.encrypted);
    }
    v
}

fn kem_ot_main(a: &[Value]) -> R {
    let f = text(arg(a, 0))?;
    let msgs = pairs_in(arg(a, 1))?;
    let ch = choices(arg(a, 2))?;
    let mut g = rng(arg(a, 3))?;
    let t = kem_tamper(arg(a, 4));
    match f {
        "kemBaseOT" => {
            let r = kem_base_ot(&msgs, &ch, &mut g).map_err(err)?;
            let t = &r.transcript;
            Ok(
                json!({"received": bl(&r.received), "transcript": {"publicKeys": pairs_out(&t.public_keys), "ciphertexts": pairs_out(&t.ciphertexts), "encrypted": pairs_out(&t.encrypted)}}),
            )
        }
        "kemBaseOtMal" => {
            let r = kem_base_ot_mal(&msgs, &ch, &mut g, t.as_ref()).map_err(err)?;
            Ok(json!({"received": bl(&r.received), "transcript": mal_transcript_out(&r.transcript, true)}))
        }
        "kemBaseOtMalRandom" => {
            let r = kem_base_ot_mal_random(&ch, &mut g, t.as_ref()).map_err(err)?;
            Ok(json!({"senderSecrets": pairs_out(&r.sender_secrets), "recvSecrets": bl(&r.recv_secrets), "sid": bytes_out(&r.sid),
                "transcript": mal_transcript_out(&r.transcript, false)}))
        }
        o => Err(format!("unknown fn {o}")),
    }
}

/// The same flows as `kem_ot_main`, composed from the per-party round functions.
fn kem_rounds(a: &[Value]) -> R {
    use atlas_pca::mpc_ot::rounds::*;
    let f = text(arg(a, 0))?;
    let msgs = pairs_in(arg(a, 1))?;
    let ch = choices(arg(a, 2))?;
    let mut g = rng(arg(a, 3))?;
    let t = kem_tamper(arg(a, 4));
    if f == "kemBaseOT" {
        let (rm, st) = kem_base_ot_receive(&ch, &mut g);
        let sm = kem_base_ot_send(&msgs, &rm, &mut g).map_err(err)?;
        let received = kem_base_ot_open(&st, &sm).map_err(err)?;
        return Ok(
            json!({"received": bl(&received), "transcript": {"publicKeys": pairs_out(&rm.public_keys), "ciphertexts": pairs_out(&sm.ciphertexts), "encrypted": pairs_out(&sm.encrypted)}}),
        );
    }
    let (commit, st) = kem_base_ot_mal_commit(&ch, &mut g);
    let nonce = kem_base_ot_mal_sender_nonce(&mut g);
    let mut opening = kem_base_ot_mal_open(&st);
    if let Some(h) = t.as_ref().and_then(|t| t.tamper_opened_keys.as_ref()) {
        h(&mut opening.public_keys);
    }
    let sid_hook = t.as_ref().and_then(|t| t.tamper_receiver_sid.as_deref());
    let tr = |ciphertexts: &[[Vec<u8>; 2]], encrypted: Option<&[[Vec<u8>; 2]]>| {
        let mut v = json!({"rn": bytes_out(&commit.rn), "commitments": bl(&commit.commitments), "sn": bytes_out(&nonce.sn), "publicKeys": pairs_out(&opening.public_keys), "ciphertexts": pairs_out(ciphertexts)});
        if let Some(e) = encrypted {
            v["encrypted"] = pairs_out(e);
        }
        v
    };
    match f {
        "kemBaseOtMal" => {
            let sm = kem_base_ot_mal_send(&msgs, &commit, &nonce, &opening, &mut g).map_err(err)?;
            let received = kem_base_ot_mal_recover(&st, &nonce, &sm, sid_hook).map_err(err)?;
            Ok(json!({"received": bl(&received), "transcript": tr(&sm.ciphertexts, Some(&sm.encrypted))}))
        }
        "kemBaseOtMalRandom" => {
            let sm = kem_base_ot_mal_random_send(&commit, &nonce, &opening, &mut g).map_err(err)?;
            let recv = kem_base_ot_mal_random_recover(&st, &nonce, &sm, sid_hook).map_err(err)?;
            let sid = kem_mal_session_id(&commit.rn, &nonce.sn);
            Ok(
                json!({"senderSecrets": pairs_out(&sm.sender_secrets), "recvSecrets": bl(&recv), "sid": bytes_out(&sid), "transcript": tr(&sm.ciphertexts, None)}),
            )
        }
        o => Err(format!("unknown fn {o}")),
    }
}

fn kem_ot_case(a: &[Value]) -> R {
    let main = kem_ot_main(a);
    let alt = kem_rounds(a);
    match (&main, &alt) {
        (Ok(m), Ok(r)) => assert!(veq(m, r), "round functions differ from the simulator: {m} vs {r}"),
        (Err(_), Err(_)) => {}
        _ => panic!("round functions and the simulator disagree on refusal: {main:?} vs {alt:?}"),
    }
    main
}

/// The hybrid flow composed from the per-party round functions.
fn hybrid_rounds(a: &[Value]) -> R {
    use atlas_pca::mpc_ot::rounds::*;
    let msgs = pairs_in(arg(a, 0))?;
    let ch = choices(arg(a, 1))?;
    let mut g = rng(arg(a, 2))?;
    let t = match arg(a, 3).as_str() {
        Some("ec") => Some(HybridBaseOtTamper { ec: base_tamper("ct_flip")?, ..Default::default() }),
        Some("ecS") => Some(HybridBaseOtTamper { ec: base_tamper("S_identity")?, ..Default::default() }),
        Some("enc") => Some(HybridBaseOtTamper {
            tamper_encrypted: Some(Box::new(|e| {
                if !e.is_empty() {
                    e[0][0] = flip(&e[0][0], 1);
                }
            })),
            ..Default::default()
        }),
        Some("kem") => Some(HybridBaseOtTamper { kem: kem_tamper(&json!("badKey")), ..Default::default() }),
        _ => None,
    };
    let ec = mal_base_random_ot(&ch, &mut g, t.as_ref().and_then(|t| t.ec.as_ref()), None).map_err(err)?;
    let kt = t.as_ref().and_then(|t| t.kem.as_ref());
    let (commit, st) = kem_base_ot_mal_commit(&ch, &mut g);
    let nonce = kem_base_ot_mal_sender_nonce(&mut g);
    let mut opening = kem_base_ot_mal_open(&st);
    if let Some(h) = kt.and_then(|t| t.tamper_opened_keys.as_ref()) {
        h(&mut opening.public_keys);
    }
    let ks = kem_base_ot_mal_random_send(&commit, &nonce, &opening, &mut g).map_err(err)?;
    let kem_recv = kem_base_ot_mal_random_recover(&st, &nonce, &ks, kt.and_then(|t| t.tamper_receiver_sid.as_deref())).map_err(err)?;
    let kem_sid = kem_mal_session_id(&commit.rn, &nonce.sn);
    let sid = hybrid_session_id(&kem_sid, &ec.s);
    let mut sm = hybrid_sender_encrypt(&sid, &msgs, &ec.sender_pads, &ks.sender_secrets).map_err(err)?;
    if let Some(h) = t.as_ref().and_then(|t| t.tamper_encrypted.as_ref()) {
        h(&mut sm.encrypted);
    }
    let received = hybrid_receiver_recover(&sid, &ch, &sm, &ec.recv_pads, &kem_recv).map_err(err)?;
    Ok(json!({"received": bl(&received), "sid": bytes_out(&sid), "ecS": aff(&ec.s), "kemSid": bytes_out(&kem_sid),
        "encrypted": pairs_out(&sm.encrypted), "commitments": pairs_out(&sm.commitments)}))
}

fn hybrid_case(a: &[Value]) -> R {
    let main = hybrid_main(a);
    let alt = hybrid_rounds(a);
    match (&main, &alt) {
        (Ok(m), Ok(r)) => assert!(veq(m, r), "hybrid round functions differ from the simulator: {m} vs {r}"),
        (Err(_), Err(_)) => {}
        _ => panic!("hybrid round functions and the simulator disagree on refusal: {main:?} vs {alt:?}"),
    }
    main
}

fn kem_pad_case(a: &[Value]) -> R {
    if a.len() == 1 {
        return Ok(bytes_out(&kem_ot_pad(0, 0, &[0u8; 32], uint(&a[0])?).map_err(err)?));
    }
    let ss: Vec<u8> = (0..32u8).collect();
    Ok(bytes_out(&kem_ot_pad(uint(arg(a, 0))?, uint(arg(a, 1))?, &ss, uint(arg(a, 2))?).map_err(err)?))
}

fn hybrid_main(a: &[Value]) -> R {
    let msgs = pairs_in(arg(a, 0))?;
    let ch = choices(arg(a, 1))?;
    let mut g = rng(arg(a, 2))?;
    let t = match arg(a, 3).as_str() {
        Some("ec") => Some(HybridBaseOtTamper { ec: base_tamper("ct_flip")?, ..Default::default() }),
        Some("ecS") => Some(HybridBaseOtTamper { ec: base_tamper("S_identity")?, ..Default::default() }),
        Some("enc") => Some(HybridBaseOtTamper {
            tamper_encrypted: Some(Box::new(|e| {
                if !e.is_empty() {
                    e[0][0] = flip(&e[0][0], 1);
                }
            })),
            ..Default::default()
        }),
        Some("kem") => Some(HybridBaseOtTamper { kem: kem_tamper(&json!("badKey")), ..Default::default() }),
        _ => None,
    };
    let r = hybrid_base_ot(&msgs, &ch, &mut g, t.as_ref()).map_err(err)?;
    let tr = &r.transcript;
    Ok(json!({"received": bl(&r.received), "sid": bytes_out(&tr.sid), "ecS": aff(&tr.ec_s), "kemSid": bytes_out(&tr.kem_sid),
        "encrypted": pairs_out(&tr.encrypted), "commitments": pairs_out(&tr.commitments)}))
}

fn hybrid_key_case(a: &[Value]) -> R {
    let n = uint(arg(a, 0))?;
    Ok(bytes_out(&hybrid_transfer_key(&[1u8; 32], 3, 1, &[2u8; 16], &[3u8; 32], n).map_err(err)?))
}

// ---- MASCOT / runner ------------------------------------------------------------------------------------------------------------

fn sv(x: u64) -> Value {
    Value::String(x.to_string())
}

fn ls(x: &[u64]) -> Value {
    Value::Array(x.iter().map(|v| sv(*v)).collect())
}

fn lls(x: &[Vec<u64>]) -> Value {
    Value::Array(x.iter().map(|r| ls(r)).collect())
}

fn dec(v: &Value) -> Result<u64, String> {
    mod_dec(text(v)?).map_err(err)
}

fn felist(v: &Value) -> Result<Vec<u64>, String> {
    list(v)?.iter().map(dec).collect()
}

fn ctx_out(c: &MacContext) -> Value {
    let extra: Vec<Value> = c.extra_keys.iter().map(|k| json!({"alphaShares": ls(&k.alpha_shares), "alpha": sv(k.alpha)})).collect();
    json!({"n": c.n, "alphaShares": ls(&c.alpha_shares), "alpha": sv(c.alpha), "extraKeys": extra})
}

fn auth_out(x: &AuthSV) -> Value {
    json!({"value": ls(&x.value), "mac": ls(&x.mac), "extraMac": lls(&x.extra_mac)})
}

fn triple_out(t: &AuthTriple) -> Value {
    json!({"a": auth_out(&t.a), "b": auth_out(&t.b), "c": auth_out(&t.c)})
}

fn offline_options(v: &Value) -> Result<(NoDealerOptions, Option<&Map<String, Value>>), String> {
    if v.is_null() {
        return Ok((NoDealerOptions::default(), None));
    }
    let o = v.as_object().ok_or("options must be an object")?;
    let mut opts = NoDealerOptions { unsafe_stat_sec: o.get("unsafe") == Some(&Value::Bool(true)), ..Default::default() };
    if let Some(b) = o.get("sacrifice").and_then(Value::as_bool) {
        opts.sacrifice = Some(b);
    }
    let opt_int = |k: &str| -> Result<Option<i64>, String> { o.get(k).filter(|x| !x.is_null()).map(int).transpose() };
    opts.sacrifice_partners = opt_int("partners")?;
    opts.mac_keys = opt_int("keys")?;
    opts.stat_sec = opt_int("statSec")?;
    if let Some(d) = o.get("dev").filter(|x| !x.is_null()) {
        let d = d.as_array().filter(|d| d.len() == 2).ok_or("bad deviation")?;
        opts.deviation = Some(OfflineDeviation { product_mul: int(&d[0])?, delta: dec(&d[1])? });
    }
    Ok((opts, Some(o)))
}

fn offline_case(a: &[Value]) -> R {
    let n = int(arg(a, 0))?;
    let seed = low_u64(text(arg(a, 1))?).map_err(err)?;
    let what = text(arg(a, 2))?;
    let (opts, o) = offline_options(arg(a, 3))?;
    let mut off = NoDealerOffline::new(n, Some(seed), opts).map_err(err)?;
    let base = |off: &NoDealerOffline| json!({"n": off.n(), "statSec": off.stat_sec, "ctx": ctx_out(off.mac_context())});
    let get = |k: &str| o.and_then(|m| m.get(k)).unwrap_or(&NULL);
    let mut out = base(&off);
    match what {
        "ctx" => {}
        "triple" => out["t"] = triple_out(&off.gen_auth_triple().map_err(err)?),
        "input" => {
            let owner = uint(get("owner"))?;
            out["v"] = auth_out(&off.auth_input(dec(get("value"))?, owner).map_err(err)?);
        }
        "multiply" => {
            let (x, y) = (felist(get("x"))?, felist(get("y"))?);
            let z = off.ot_share_multiply(&x, &y).map_err(err)?;
            let sum = z.iter().fold(0u64, |a, v| fadd(a, *v));
            let expect = fmul(x.iter().fold(0u64, |a, v| fadd(a, *v)), y.iter().fold(0u64, |a, v| fadd(a, *v)));
            out["z"] = ls(&z);
            out["sum"] = sv(sum);
            out["expect"] = sv(expect);
        }
        "consistency" => {
            let values = felist(get("values"))?;
            let nn = off.n();
            let mut ins = vec![];
            for (i, v) in values.iter().enumerate() {
                ins.push(off.auth_input(*v, i % nn).map_err(err)?);
            }
            if get("tamper") == &Value::Bool(true) {
                ins[0].value[0] = fadd(ins[0].value[0], 1);
            }
            off.check_input_consistency(&ins).map_err(err)?;
            out["ok"] = Value::Bool(true);
        }
        w => return Err(format!("unknown what {w}")),
    }
    Ok(out)
}

fn offline_blame_case(a: &[Value]) -> R {
    let n = int(arg(a, 0))?;
    let seed = low_u64(text(arg(a, 1))?).map_err(err)?;
    let opts = NoDealerOptions { deviation: Some(OfflineDeviation { product_mul: int(arg(a, 2))?, delta: dec(arg(a, 3))? }), ..Default::default() };
    let mut off = NoDealerOffline::new(n, Some(seed), opts).map_err(err)?;
    match off.gen_auth_triple() {
        Ok(_) => Ok(json!({"aborted": false})),
        Err(MpcError::MacCheckAbort(_)) => Ok(json!({"aborted": true, "name": "OfflineCheatingAbort", "blamed": off.blamed()})),
        Err(e) => Err(err(e)),
    }
}

fn vectors(v: &Value) -> Result<Vec<DecisionVector>, String> {
    list(v)?
        .iter()
        .map(|e| {
            let m = e.as_object().ok_or("decision vector must be an object")?;
            let f = |k: &str| int(m.get(k).unwrap_or(&NULL));
            Ok(DecisionVector { allow: f("allow")?, t: f("t")?, r_quant: f("rQuant")? })
        })
        .collect()
}

fn devs(v: &Value) -> Result<Vec<Deviation>, String> {
    let mut out = vec![];
    for e in list(v)? {
        let d = list(e)?;
        if d.len() < 5 {
            return Err("malformed deviation".into());
        }
        let opt = |x: &Value| -> Result<Option<u64>, String> {
            if x.is_null() {
                Ok(None)
            } else {
                dec(x).map(Some)
            }
        };
        out.push(Deviation {
            open_index: int(&d[0])?,
            party: int(&d[1])?,
            value_delta: opt(&d[2])?,
            mac_delta: opt(&d[3])?,
            mac_key: if d[4].is_null() { None } else { Some(int(&d[4])?) },
        });
    }
    Ok(out)
}

fn no_dealer_run_case(a: &[Value]) -> R {
    let vs = vectors(arg(a, 0))?;
    let m = arg(a, 1).as_object().ok_or("not an object")?;
    let mut cfg = MaliciousConfig::default();
    if let Some(q) = m.get("Q").filter(|x| !x.is_null()) {
        cfg.q = Some(int(q)?);
    }
    if let Some(s) = m.get("seed").filter(|x| !x.is_null()) {
        cfg.seed = Some(low_u64(text(s)?).map_err(err)?);
    }
    if let Some(d) = m.get("deviations").filter(|x| !x.is_null()) {
        cfg.deviations = devs(d)?;
    }
    let r = compose_secure_malicious_no_dealer(&vs, cfg).map_err(err)?;
    Ok(json!({"composed": {"allow": r.composed.allow, "t": r.composed.t, "rQuant": r.composed.r_quant}, "parties": r.parties, "Q": r.q, "opens": r.opens,
        "multiplications": r.multiplications, "offlineMode": r.offline_mode, "triplesVerified": r.triples_verified, "macChecked": r.mac_checked}))
}

fn run(f: &str, a: &[Value]) -> R {
    match f {
        "ecOp" => ec_op(a),
        "ecValidate" => ec_validate(a),
        "ecAssert" => {
            let p = pt(arg(a, 0)).map_err(|_| "p: not on curve".to_string())?;
            ec_assert_in_subgroup(&p, "p").map_err(err)?;
            Ok(Value::Bool(true))
        }
        "schnorr" => schnorr(a),
        "prg" | "maskTail" | "transpose32" | "transposeCols" | "gfMulX" | "gfXorInto" | "gfBig" | "accumColumn" | "kosCombine" | "tmmo" | "tweakDomain"
        | "bigBytes" | "bytesBig" | "word64" => kernel(f, a),
        "bindingBytes" => binding_bytes_case(a),
        "baseOtKdf" => base_ot_kdf_case(a),
        "randomOt" => random_ot_case(a),
        "baseOt" => base_ot_case(a),
        "channel" => channel_case(a),
        "kosChi" => kos_chi_case(a),
        "kemOt" => kem_ot_case(a),
        "kemPad" => kem_pad_case(a),
        "hybridOt" => hybrid_case(a),
        "hybridKey" => hybrid_key_case(a),
        "offline" => offline_case(a),
        "offlineBlame" => offline_blame_case(a),
        "noDealerRun" => no_dealer_run_case(a),
        f => panic!("unknown fn {f}"),
    }
}

fn veq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| veq(p, q)),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| veq(v, w))),
        _ => a == b,
    }
}

#[test]
fn replays_the_mpc_oblivious_transfer_stack() {
    let mut cases = common::ref_cases("mpc-ot");
    assert!(cases.len() >= 440, "corpus shrank: {}", cases.len());
    // the cases that carry private keys are CI-generated (ref-mpc-ot-gen.json.gz): 444 in all
    let gen = common::ref_gen_cases("mpc-ot", false);
    cases.extend(gen.iter().cloned());
    assert!(gen.is_empty() || cases.len() >= 444, "corpus shrank: {}", cases.len());
    let mut failures = vec![];
    for c in &cases {
        let f = c["fn"].as_str().expect("fn");
        let name = c["name"].as_str().expect("name");
        let args = c["args"].as_array().expect("args");
        let want = &c["out"];
        let got = run(f, args);
        if want.get("$throws").is_some() {
            if let Ok(v) = got {
                failures.push(format!("{name}: the reference refuses but the native returned {v}"));
            }
        } else {
            match got {
                Ok(v) if veq(&v, want) => {}
                Ok(v) => failures.push(format!("{name}: got {v}, want {want}")),
                Err(e) => failures.push(format!("{name}: refused ({e}), want {want}")),
            }
        }
    }
    let shown: Vec<&String> = failures.iter().take(10).collect();
    assert!(failures.is_empty(), "{} of {} cases differ; first: {:#?}", failures.len(), cases.len(), shown);
}
