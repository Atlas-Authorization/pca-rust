//! Post-quantum endemic (Masny-Rindal) base OT for the MPC layer: Kyber-768 K-PKE from the vetted `pqc_kyber` reference (through the
//! `pca-mpc-lwe-ot-wasm` crate's safe API; nothing lattice-related is implemented here).
//!
//! The receiver places a real key's offset-by-oracle point at its choice slot and a uniform ring vector at the other, so the sender's
//! effective key for the other slot is uniform and its ciphertext is unrecoverable. The chosen-message form pads and commits each
//! message and aborts on any inconsistency. The receiver's real key pair is the FIPS 203 K-PKE.KeyGen(d). Randomness is [`OtRng`]
//! (the OS CSPRNG, or a SplitMix64 seed for tests), consumed in the reference order so every transcript matches it byte for byte.
use crate::mpc_ot::{OtError, OtResult, OtRng};
use pca_mpc_lwe_ot_wasm::safe::{self, CT_LEN, PK_LEN, SK_LEN, SYM_LEN, TVEC_LEN};
use sha2::{Digest, Sha256};

/// Bytes of a recovered pad in the random-OT form.
pub const ENDEMIC_SECRET_BYTES: usize = SYM_LEN;
/// Byte lengths of the lattice core's public key, secret key, ciphertext, ring vector and symmetric payload (`PK_BYTES` ... `SYM_BYTES`).
pub const PK_BYTES: usize = PK_LEN;
pub const SK_BYTES: usize = SK_LEN;
pub const CT_BYTES: usize = CT_LEN;
pub const TVEC_BYTES: usize = TVEC_LEN;
pub const SYM_BYTES: usize = SYM_LEN;

const TAG_SID: &[u8] = b"atlas-pca-mpc/endemic-lwe-ot-sid";
const TAG_HPK: &[u8] = b"atlas-pca-mpc/endemic-lwe-ot-hpk";
const TAG_N: &[u8] = b"atlas-pca-mpc/endemic-lwe-ot-N";
const TAG_PAD: &[u8] = b"atlas-pca-mpc/endemic-lwe-ot-pad";
const TAG_COMMIT: &[u8] = b"atlas-pca-mpc/endemic-lwe-ot-commit";

pub type Pair = (Vec<u8>, Vec<u8>);

fn abort<T>(m: impl Into<String>) -> OtResult<T> {
    Err(OtError::BaseOtAbort(m.into()))
}

fn invalid<T>(m: impl Into<String>) -> OtResult<T> {
    Err(OtError::Invalid(m.into()))
}

fn arr<const N: usize>(b: &[u8], what: &str) -> OtResult<[u8; N]> {
    b.try_into().or_else(|_| invalid(format!("lattice: {what} must be exactly {N} bytes")))
}

// ---- the lattice core (thin, length-checked wrappers) ----------------------------------------------------------------------------

/// `(public key, secret key)` of Kyber-768 K-PKE, deterministic in the 32-byte seed.
pub fn kpke_keygen(seed: &[u8]) -> OtResult<(Vec<u8>, Vec<u8>)> {
    let (pk, sk) = safe::keygen(&arr(seed, "seed")?).ok_or_else(|| OtError::Invalid("lattice: keygen refused".into()))?;
    Ok((pk.to_vec(), sk.to_vec()))
}

/// `(public key, secret key)` exactly as FIPS 203 Algorithm 13 derives K-PKE.KeyGen(d): the derivation the endemic receiver uses.
pub fn kpke_keygen_fips203(seed: &[u8]) -> OtResult<(Vec<u8>, Vec<u8>)> {
    let (pk, sk) = safe::keygen_fips203(&arr(seed, "seed")?).ok_or_else(|| OtError::Invalid("lattice: keygen (FIPS 203) refused".into()))?;
    Ok((pk.to_vec(), sk.to_vec()))
}

pub fn kpke_enc(public_key: &[u8], message: &[u8], coins: &[u8]) -> OtResult<Vec<u8>> {
    Ok(safe::enc(&arr::<PK_LEN>(public_key, "public key")?, &arr(message, "message")?, &arr(coins, "coins")?).to_vec())
}

pub fn kpke_dec(secret_key: &[u8], ciphertext: &[u8]) -> OtResult<Vec<u8>> {
    Ok(safe::dec(&arr::<SK_LEN>(secret_key, "secret key")?, &arr::<CT_LEN>(ciphertext, "ciphertext")?).to_vec())
}

pub fn ring_add(a: &[u8], b: &[u8]) -> OtResult<Vec<u8>> {
    Ok(safe::ring_add(&arr(a, "a")?, &arr(b, "b")?).to_vec())
}

pub fn ring_sub(a: &[u8], b: &[u8]) -> OtResult<Vec<u8>> {
    Ok(safe::ring_sub(&arr(a, "a")?, &arr(b, "b")?).to_vec())
}

/// SHAKE128 then the FIPS 203 SampleNTT sampler: a uniform ring vector. At most 4096 input bytes.
pub fn hash_to_ring(data: &[u8]) -> OtResult<Vec<u8>> {
    match safe::hash_to_ring(data) {
        Some(r) => Ok(r.to_vec()),
        None => invalid("lattice: hash input must be at most 4096 bytes"),
    }
}

// ---- the protocol ----------------------------------------------------------------------------------------------------------------

fn u32b(x: usize) -> [u8; 4] {
    (x as u32).to_be_bytes()
}

fn xor(a: &[u8], b: &[u8]) -> OtResult<Vec<u8>> {
    if a.len() != b.len() {
        return invalid("endemic-ot: XOR length mismatch");
    }
    Ok(a.iter().zip(b).map(|(x, y)| x ^ y).collect())
}

fn sha(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

/// `sid = H(TAG || rn)`: binds every oracle query to this receiver nonce.
pub fn session_id(rn: &[u8]) -> Vec<u8> {
    sha(&[TAG_SID, rn])
}

fn hpk(sid: &[u8], i: usize, other: &[u8]) -> OtResult<Vec<u8>> {
    hash_to_ring(&[TAG_HPK, sid, &u32b(i), other].concat())
}

/// The pad for a slot: SHA-256 in counter mode over `TAG || sid || i || slot || ctr || payload`.
pub fn pad(sid: &[u8], index: usize, slot: usize, payload: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 32);
    let mut ctr = 0usize;
    while out.len() < length {
        out.extend(sha(&[TAG_PAD, sid, &u32b(index), &[(slot & 1) as u8], &u32b(ctr), payload]));
        ctr += 1;
    }
    out.truncate(length);
    out
}

fn commit(sid: &[u8], i: usize, slot: usize, msg: &[u8], pd: &[u8]) -> Vec<u8> {
    sha(&[TAG_COMMIT, sid, &u32b(i), &[(slot & 1) as u8], msg, pd])
}

#[derive(Debug, Clone)]
pub struct ReceiverMessage {
    pub rn: Vec<u8>,
    pub points: Vec<Pair>,
    pub rhos: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ReceiverState {
    pub choices: Vec<u8>,
    pub secret_keys: Vec<Vec<u8>>,
    pub rhos: Vec<Vec<u8>>,
    pub rn: Vec<u8>,
    pub sid: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SenderMessage {
    pub ciphertexts: Vec<Pair>,
    pub sender_pads: Vec<Pair>,
}

#[derive(Debug, Clone)]
pub struct Transcript {
    pub rn: Vec<u8>,
    pub points: Vec<Pair>,
    pub rhos: Vec<Vec<u8>>,
    pub ciphertexts: Vec<Pair>,
    pub encrypted: Vec<Pair>,
    pub commitments: Vec<Pair>,
}

/// Receiver round: a real key pair per choice, a uniform vector for the other slot, and `C = t_real - Hpk(sid, i, N)` at the choice slot.
pub fn receive(choices: &[u8], rng: &mut OtRng) -> OtResult<(ReceiverMessage, ReceiverState)> {
    let rn = rng.bytes(SYM_LEN);
    let sid = session_id(&rn);
    let (mut points, mut rhos, mut sks, mut kept) = (vec![], vec![], vec![], vec![]);
    for (i, ch) in choices.iter().enumerate() {
        let c = ch & 1;
        let (pk, sk) = kpke_keygen_fips203(&rng.bytes(SYM_LEN))?;
        let n_slot = hash_to_ring(&[TAG_N, &sid, &u32b(i), &rng.bytes(SYM_LEN)].concat())?;
        let c_point = ring_sub(&pk[..TVEC_LEN], &hpk(&sid, i, &n_slot)?)?;
        points.push(if c == 0 { (c_point, n_slot) } else { (n_slot, c_point) });
        rhos.push(pk[TVEC_LEN..].to_vec());
        sks.push(sk);
        kept.push(c);
    }
    let state = ReceiverState { choices: kept, secret_keys: sks, rhos: rhos.clone(), rn: rn.clone(), sid };
    Ok((ReceiverMessage { rn, points, rhos }, state))
}

fn validate(m: &ReceiverMessage) -> OtResult<()> {
    if m.rn.len() != SYM_LEN {
        return abort("endemic LWE OT: malformed session nonce");
    }
    if m.points.len() != m.rhos.len() {
        return abort("endemic LWE OT: points/rhos length mismatch");
    }
    for (i, ((a, b), rho)) in m.points.iter().zip(&m.rhos).enumerate() {
        if a.len() != TVEC_LEN || b.len() != TVEC_LEN {
            return abort(format!("endemic LWE OT: malformed point pair at index {i}"));
        }
        if rho.len() != PK_LEN - TVEC_LEN {
            return abort(format!("endemic LWE OT: malformed rho at index {i}"));
        }
    }
    Ok(())
}

/// Sender round (random-OT form): encrypt a fresh payload under each slot's effective key and output both pads. `tamper` is test-only.
pub fn send_random(message: &ReceiverMessage, rng: &mut OtRng, tamper: Option<&dyn Fn(&mut Vec<Pair>)>) -> OtResult<SenderMessage> {
    validate(message)?;
    let sid = session_id(&message.rn);
    let (mut cts, mut pads) = (vec![], vec![]);
    for (i, ((p0, p1), rho)) in message.points.iter().zip(&message.rhos).enumerate() {
        let pk0 = [ring_add(p0, &hpk(&sid, i, p1)?)?, rho.clone()].concat();
        let pk1 = [ring_add(p1, &hpk(&sid, i, p0)?)?, rho.clone()].concat();
        let (r0, r1) = (rng.bytes(SYM_LEN), rng.bytes(SYM_LEN));
        let ct0 = kpke_enc(&pk0, &r0, &rng.bytes(SYM_LEN))?;
        let ct1 = kpke_enc(&pk1, &r1, &rng.bytes(SYM_LEN))?;
        cts.push((ct0, ct1));
        pads.push((pad(&sid, i, 0, &r0, ENDEMIC_SECRET_BYTES), pad(&sid, i, 1, &r1, ENDEMIC_SECRET_BYTES)));
    }
    if let Some(t) = tamper {
        t(&mut cts);
    }
    Ok(SenderMessage { ciphertexts: cts, sender_pads: pads })
}

/// Receiver recovery (random-OT form): decrypt only the chosen ciphertext.
pub fn recover_random(state: &ReceiverState, sm: &SenderMessage) -> OtResult<Vec<Vec<u8>>> {
    if sm.ciphertexts.len() != state.choices.len() {
        return abort("endemic LWE OT: ciphertext count does not match the transfer count");
    }
    for (i, (a, b)) in sm.ciphertexts.iter().enumerate() {
        if a.len() != CT_LEN || b.len() != CT_LEN {
            return abort(format!("endemic LWE OT: malformed ciphertext pair at index {i}"));
        }
    }
    let mut out = vec![];
    for (i, c) in state.choices.iter().enumerate() {
        let c = (c & 1) as usize;
        let ct = if c == 0 { &sm.ciphertexts[i].0 } else { &sm.ciphertexts[i].1 };
        out.push(pad(&state.sid, i, c, &kpke_dec(&state.secret_keys[i], ct)?, ENDEMIC_SECRET_BYTES));
    }
    Ok(out)
}

/// In-process chosen-message endemic base OT; returns (received, transcript). `rng` is the receiver's stream and the sender's too unless
/// `sender_rng` is given (one stream then serves the receiver, then the sender, as the reference does); `tamper_encrypted` (test-only)
/// corrupts the padded messages on the wire.
pub fn base_ot(
    messages: &[Pair],
    choices: &[u8],
    rng: &mut OtRng,
    sender_rng: Option<&mut OtRng>,
    tamper_encrypted: Option<&dyn Fn(&mut Vec<Pair>)>,
) -> OtResult<(Vec<Vec<u8>>, Transcript)> {
    if messages.len() != choices.len() {
        return invalid("endemic_base_ot: messages/choices length mismatch");
    }
    let (msg, state) = receive(choices, rng)?;
    let srng: &mut OtRng = match sender_rng {
        Some(s) => s,
        None => rng,
    };
    let sid = &state.sid;
    let (mut cts, mut enc, mut com) = (vec![], vec![], vec![]);
    for (i, (m0, m1)) in messages.iter().enumerate() {
        if m0.len() != m1.len() {
            return invalid(format!("endemic_base_ot (index {i}): the two messages must be equal length"));
        }
        let ((p0, p1), rho) = (&msg.points[i], &msg.rhos[i]);
        let (r0, r1) = (srng.bytes(SYM_LEN), srng.bytes(SYM_LEN));
        let ct0 = kpke_enc(&[ring_add(p0, &hpk(sid, i, p1)?)?, rho.clone()].concat(), &r0, &srng.bytes(SYM_LEN))?;
        let ct1 = kpke_enc(&[ring_add(p1, &hpk(sid, i, p0)?)?, rho.clone()].concat(), &r1, &srng.bytes(SYM_LEN))?;
        cts.push((ct0, ct1));
        let (pad0, pad1) = (pad(sid, i, 0, &r0, m0.len()), pad(sid, i, 1, &r1, m1.len()));
        enc.push((xor(m0, &pad0)?, xor(m1, &pad1)?));
        com.push((commit(sid, i, 0, m0, &pad0), commit(sid, i, 1, m1, &pad1)));
    }
    if let Some(t) = tamper_encrypted {
        t(&mut enc);
    }
    let mut received = vec![];
    for (i, ch) in choices.iter().enumerate() {
        let c = (ch & 1) as usize;
        let (ct, e, k) = if c == 0 { (&cts[i].0, &enc[i].0, &com[i].0) } else { (&cts[i].1, &enc[i].1, &com[i].1) };
        let payload = kpke_dec(&state.secret_keys[i], ct)?;
        let pd = pad(sid, i, c, &payload, e.len());
        let m = xor(e, &pd)?;
        // constant-time compare of the commitment
        let c2 = commit(sid, i, c, &m, &pd);
        if c2.iter().zip(k).fold(0u8, |a, (x, y)| a | (x ^ y)) != 0 || c2.len() != k.len() {
            return abort(format!("endemic base OT (index {i}): sender ciphertext inconsistent with its commitment; aborting"));
        }
        received.push(m);
    }
    Ok((received, Transcript { rn: msg.rn, points: msg.points, rhos: msg.rhos, ciphertexts: cts, encrypted: enc, commitments: com }))
}

/// The random-form endemic base OT with both parties in process (`endemicLweBaseOtRandom`): the sender's both pads, the receiver's chosen
/// pad per transfer, the session id and the wire messages.
#[derive(Debug, Clone)]
pub struct RandomResult {
    pub sender_pads: Vec<Pair>,
    pub recv_pads: Vec<Vec<u8>>,
    pub sid: Vec<u8>,
    pub message: ReceiverMessage,
    pub ciphertexts: Vec<Pair>,
}

/// `endemicLweBaseOtRandom`: receive, send (random form), recover. `tamper` (test-only) corrupts the ciphertexts on the wire.
pub fn base_ot_random(choices: &[u8], rng: &mut OtRng, tamper: Option<&dyn Fn(&mut Vec<Pair>)>) -> OtResult<RandomResult> {
    let (message, state) = receive(choices, rng)?;
    let sm = send_random(&message, rng, tamper)?;
    let recv_pads = recover_random(&state, &sm)?;
    Ok(RandomResult { sender_pads: sm.sender_pads, recv_pads, sid: state.sid, message, ciphertexts: sm.ciphertexts })
}

/// `endemicLweBaseOtFn`: the chosen-message endemic base OT as a pluggable base OT (only the received messages are returned).
pub fn base_ot_fn(messages: &[[Vec<u8>; 2]], choices: &[i64], rng: &mut OtRng) -> OtResult<Vec<Vec<u8>>> {
    let pairs: Vec<Pair> = messages.iter().map(|m| (m[0].clone(), m[1].clone())).collect();
    let bits: Vec<u8> = choices.iter().map(|c| (c & 1) as u8).collect();
    Ok(base_ot(&pairs, &bits, rng, None, None)?.0)
}

/// `withEndemicLweBaseOt`: the endemic base OT for [`crate::mpc_ot::OtChannel::new`] (the post-quantum, maliciously secure KOS setup).
pub fn with_endemic_lwe_base_ot() -> crate::mpc_ot::BaseOtFn {
    base_ot_fn
}

#[cfg(test)]
mod surface_tests {
    use super::*;

    #[test]
    fn random_form_and_fn_agree_with_the_chosen_pads() {
        let mut rng = OtRng::from_decimal("4242").unwrap();
        let r = base_ot_random(&[1, 0, 1], &mut rng, None).unwrap();
        for (i, c) in [1usize, 0, 1].iter().enumerate() {
            let (a, b) = &r.sender_pads[i];
            assert_eq!(&r.recv_pads[i], if *c == 0 { a } else { b });
        }
        let m: Vec<[Vec<u8>; 2]> = (0..3).map(|i| [vec![i as u8; 8], vec![9 + i as u8; 8]]).collect();
        let mut rng = OtRng::from_decimal("4243").unwrap();
        let got = with_endemic_lwe_base_ot()(&m, &[0, 1, 1], &mut rng).unwrap();
        assert_eq!(got, vec![m[0][0].clone(), m[1][1].clone(), m[2][1].clone()]);
    }
}
