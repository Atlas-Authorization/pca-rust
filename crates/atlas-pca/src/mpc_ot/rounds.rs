//! The explicit round functions of the ML-KEM base OTs and of the hybrid combiner (the reference's `kemBaseOtReceive`,
//! `kemBaseOtSend`, `kemBaseOtOpen`, `kemBaseOtMal*`, `kemBaseOtMalRandom*`, `hybridSessionId`, `hybridSenderEncrypt`,
//! `hybridReceiverRecover`): each party's step on its own, over the same primitives and in the same randomness order as the
//! in-process simulators in the parent module, so a transcript matches the reference byte for byte.
use super::{
    ct_eq, ec_encode_point, hybrid_commit, hybrid_transfer_key, inv, kem_decaps, kem_encaps, kem_mal_commit, kem_mal_pad, kem_mal_secret, kem_mal_sid,
    kem_ot_pad, kem_receive, sha256, xor_bytes, KemDk, OtError, OtPair, OtResult, OtRng, KEM_NONCE_BYTES, TAG_HYBRID_SID,
};
use curve25519_dalek::edwards::EdwardsPoint;

// ---- semi-honest KEM base OT ------------------------------------------------------------------------------------------------

/// Receiver round 1: the ordered public-key pairs the sender encapsulates under (the chosen key sits at index `choice`).
#[derive(Debug, Clone)]
pub struct KemOtReceiverMessage {
    pub public_keys: Vec<OtPair>,
}

/// The receiver's retained state: only the chosen secret key per transfer.
pub struct KemOtReceiverState {
    pub choices: Vec<usize>,
    pub secret_keys: Vec<KemDk>,
}

/// Sender round: the two ciphertexts and the two padded messages per transfer.
#[derive(Debug, Clone)]
pub struct KemOtSenderMessage {
    pub ciphertexts: Vec<OtPair>,
    pub encrypted: Vec<OtPair>,
}

/// `kemBaseOtReceive`.
pub fn kem_base_ot_receive(choices: &[i64], rng: &mut OtRng) -> (KemOtReceiverMessage, KemOtReceiverState) {
    let (public_keys, st) = kem_receive(choices, rng);
    (KemOtReceiverMessage { public_keys }, KemOtReceiverState { choices: st.choices, secret_keys: st.keys })
}

/// `kemBaseOtSend`.
pub fn kem_base_ot_send(messages: &[OtPair], rm: &KemOtReceiverMessage, rng: &mut OtRng) -> OtResult<KemOtSenderMessage> {
    if messages.len() != rm.public_keys.len() {
        return inv("kemBaseOtSend: messages/publicKeys length mismatch");
    }
    let (mut ciphertexts, mut encrypted) = (Vec::with_capacity(messages.len()), Vec::with_capacity(messages.len()));
    for (i, m) in messages.iter().enumerate() {
        if m[0].len() != m[1].len() {
            return inv(format!("kemBaseOtSend (index {i}): the two messages must be equal length"));
        }
        let (mut ct, mut enc): (OtPair, OtPair) = ([vec![], vec![]], [vec![], vec![]]);
        for s in 0..2 {
            let (c, ss) = kem_encaps(&rm.public_keys[i][s], rng)?;
            ct[s] = c;
            enc[s] = xor_bytes(&m[s], &kem_ot_pad(i, s, &ss, m[s].len())?)?;
        }
        ciphertexts.push(ct);
        encrypted.push(enc);
    }
    Ok(KemOtSenderMessage { ciphertexts, encrypted })
}

/// `kemBaseOtOpen`: decapsulate only the chosen ciphertext and unmask the chosen message.
pub fn kem_base_ot_open(state: &KemOtReceiverState, sm: &KemOtSenderMessage) -> OtResult<Vec<Vec<u8>>> {
    let n = state.choices.len();
    if sm.ciphertexts.len() != n || sm.encrypted.len() != n {
        return inv("kemBaseOtOpen: transcript/state length mismatch");
    }
    let mut received = Vec::with_capacity(n);
    for i in 0..n {
        let c = state.choices[i] & 1;
        let ss = kem_decaps(&state.secret_keys[i], &sm.ciphertexts[i][c])?;
        let e = &sm.encrypted[i][c];
        received.push(xor_bytes(e, &kem_ot_pad(i, c, &ss, e.len())?)?);
    }
    Ok(received)
}

// ---- committed (malicious-hardened) KEM base OT -------------------------------------------------------------------------------

/// Receiver round 1: a nonce and the commitments to the ordered public keys (the keys are not yet revealed).
#[derive(Debug, Clone)]
pub struct KemMalCommitMessage {
    pub rn: Vec<u8>,
    pub commitments: Vec<Vec<u8>>,
}

/// Receiver round 3: the opening of the committed public keys.
#[derive(Debug, Clone)]
pub struct KemMalOpenMessage {
    pub public_keys: Vec<OtPair>,
}

/// Sender round 2: the sender nonce completing the session id.
#[derive(Debug, Clone)]
pub struct KemMalSenderNonce {
    pub sn: Vec<u8>,
}

/// Sender round 4: ciphertexts and `(sid, com)`-bound padded messages.
#[derive(Debug, Clone)]
pub struct KemMalSenderMessage {
    pub ciphertexts: Vec<OtPair>,
    pub encrypted: Vec<OtPair>,
}

/// The receiver's state across the committed flow.
pub struct KemMalReceiverState {
    pub choices: Vec<usize>,
    pub secret_keys: Vec<KemDk>,
    pub public_keys: Vec<OtPair>,
    pub rn: Vec<u8>,
}

/// `kemBaseOtMalCommit`.
pub fn kem_base_ot_mal_commit(choices: &[i64], rng: &mut OtRng) -> (KemMalCommitMessage, KemMalReceiverState) {
    let rn = rng.bytes(KEM_NONCE_BYTES);
    let (public_keys, st) = kem_receive(choices, rng);
    let commitments = (0..choices.len()).map(|i| kem_mal_commit(&rn, i, &public_keys[i][0], &public_keys[i][1])).collect();
    (KemMalCommitMessage { rn: rn.clone(), commitments }, KemMalReceiverState { choices: st.choices, secret_keys: st.keys, public_keys, rn })
}

/// The committed KEM OT's session id `H(TAG || rn || sn)`: both parties' nonces, so neither alone fixes it.
pub fn kem_mal_session_id(rn: &[u8], sn: &[u8]) -> Vec<u8> {
    kem_mal_sid(rn, sn)
}

/// `kemBaseOtMalSenderNonce`.
pub fn kem_base_ot_mal_sender_nonce(rng: &mut OtRng) -> KemMalSenderNonce {
    KemMalSenderNonce { sn: rng.bytes(KEM_NONCE_BYTES) }
}

/// `kemBaseOtMalOpen`.
pub fn kem_base_ot_mal_open(state: &KemMalReceiverState) -> KemMalOpenMessage {
    KemMalOpenMessage { public_keys: state.public_keys.clone() }
}

fn check_opening(rn: &[u8], i: usize, pk: &OtPair, commitment: &[u8]) -> OtResult<Vec<u8>> {
    let com = kem_mal_commit(rn, i, &pk[0], &pk[1]);
    if !ct_eq(&com, commitment) {
        return Err(OtError::KemBaseOtAbort(format!("kem base OT (index {i}): opened public keys do not match the receiver's commitment; aborting")));
    }
    Ok(com)
}

/// `kemBaseOtMalSend`: verify the opened keys against the commitments (abort on mismatch), then encapsulate and pad.
pub fn kem_base_ot_mal_send(
    messages: &[OtPair],
    commit: &KemMalCommitMessage,
    nonce: &KemMalSenderNonce,
    opening: &KemMalOpenMessage,
    rng: &mut OtRng,
) -> OtResult<KemMalSenderMessage> {
    let pks = &opening.public_keys;
    if messages.len() != pks.len() || commit.commitments.len() != pks.len() {
        return inv("kemBaseOtMalSend: messages/commitments/publicKeys length mismatch");
    }
    let sid = kem_mal_sid(&commit.rn, &nonce.sn);
    let (mut ciphertexts, mut encrypted) = (Vec::with_capacity(pks.len()), Vec::with_capacity(pks.len()));
    for (i, m) in messages.iter().enumerate() {
        if m[0].len() != m[1].len() {
            return inv(format!("kemBaseOtMalSend (index {i}): the two messages must be equal length"));
        }
        let com = check_opening(&commit.rn, i, &pks[i], &commit.commitments[i])?;
        let (c0, s0) = kem_encaps(&pks[i][0], rng)?;
        let (c1, s1) = kem_encaps(&pks[i][1], rng)?;
        ciphertexts.push([c0, c1]);
        encrypted
            .push([xor_bytes(&m[0], &kem_mal_pad(&sid, &com, i, 0, &s0, m[0].len()))?, xor_bytes(&m[1], &kem_mal_pad(&sid, &com, i, 1, &s1, m[1].len()))?]);
    }
    Ok(KemMalSenderMessage { ciphertexts, encrypted })
}

/// The receiver's session id, through the test-only `tamper_receiver_sid` hook when one is given.
fn recv_sid(state: &KemMalReceiverState, nonce: &KemMalSenderNonce, tamper_sid: Option<&dyn Fn(&[u8]) -> Vec<u8>>) -> Vec<u8> {
    let sid = kem_mal_sid(&state.rn, &nonce.sn);
    match tamper_sid {
        Some(f) => f(&sid),
        None => sid,
    }
}

/// `kemBaseOtMalRecover`. `tamper_sid` is the test-only `tamperReceiverSid` hook (`None` = honest).
pub fn kem_base_ot_mal_recover(
    state: &KemMalReceiverState,
    nonce: &KemMalSenderNonce,
    sm: &KemMalSenderMessage,
    tamper_sid: Option<&dyn Fn(&[u8]) -> Vec<u8>>,
) -> OtResult<Vec<Vec<u8>>> {
    let n = state.choices.len();
    if sm.ciphertexts.len() != n || sm.encrypted.len() != n {
        return inv("kemBaseOtMalRecover: transcript/state length mismatch");
    }
    let sid = recv_sid(state, nonce, tamper_sid);
    let mut received = Vec::with_capacity(n);
    for i in 0..n {
        let c = state.choices[i] & 1;
        let com = kem_mal_commit(&state.rn, i, &state.public_keys[i][0], &state.public_keys[i][1]);
        let ss = kem_decaps(&state.secret_keys[i], &sm.ciphertexts[i][c])?;
        let e = &sm.encrypted[i][c];
        received.push(xor_bytes(e, &kem_mal_pad(&sid, &com, i, c, &ss, e.len()))?);
    }
    Ok(received)
}

// ---- committed KEM random OT ------------------------------------------------------------------------------------------------

/// Sender round 4 of the random form: ciphertexts (wire) and both per-slot secrets (sender-local, never sent).
#[derive(Debug, Clone)]
pub struct KemMalRandomSenderMessage {
    pub ciphertexts: Vec<OtPair>,
    pub sender_secrets: Vec<OtPair>,
}

/// `kemBaseOtMalRandomSend`.
pub fn kem_base_ot_mal_random_send(
    commit: &KemMalCommitMessage,
    nonce: &KemMalSenderNonce,
    opening: &KemMalOpenMessage,
    rng: &mut OtRng,
) -> OtResult<KemMalRandomSenderMessage> {
    let pks = &opening.public_keys;
    if commit.commitments.len() != pks.len() {
        return inv("kemBaseOtMalRandomSend: commitments/publicKeys length mismatch");
    }
    let sid = kem_mal_sid(&commit.rn, &nonce.sn);
    let (mut ciphertexts, mut sender_secrets) = (Vec::with_capacity(pks.len()), Vec::with_capacity(pks.len()));
    for i in 0..pks.len() {
        let com = check_opening(&commit.rn, i, &pks[i], &commit.commitments[i])?;
        let (c0, s0) = kem_encaps(&pks[i][0], rng)?;
        let (c1, s1) = kem_encaps(&pks[i][1], rng)?;
        ciphertexts.push([c0, c1]);
        sender_secrets.push([kem_mal_secret(&sid, &com, i, 0, &s0), kem_mal_secret(&sid, &com, i, 1, &s1)]);
    }
    Ok(KemMalRandomSenderMessage { ciphertexts, sender_secrets })
}

/// `kemBaseOtMalRandomRecover`.
pub fn kem_base_ot_mal_random_recover(
    state: &KemMalReceiverState,
    nonce: &KemMalSenderNonce,
    sm: &KemMalRandomSenderMessage,
    tamper_sid: Option<&dyn Fn(&[u8]) -> Vec<u8>>,
) -> OtResult<Vec<Vec<u8>>> {
    let n = state.choices.len();
    if sm.ciphertexts.len() != n {
        return inv("kemBaseOtMalRandomRecover: transcript/state length mismatch");
    }
    let sid = recv_sid(state, nonce, tamper_sid);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let c = state.choices[i] & 1;
        let com = kem_mal_commit(&state.rn, i, &state.public_keys[i][0], &state.public_keys[i][1]);
        let ss = kem_decaps(&state.secret_keys[i], &sm.ciphertexts[i][c])?;
        out.push(kem_mal_secret(&sid, &com, i, c, &ss));
    }
    Ok(out)
}

// ---- hybrid combiner ---------------------------------------------------------------------------------------------------------

/// The common session id binding both halves: `H(TAG || kemSid || encode(ecS))`.
pub fn hybrid_session_id(kem_sid: &[u8], ec_s: &EdwardsPoint) -> Vec<u8> {
    sha256(&[TAG_HYBRID_SID, kem_sid, &ec_encode_point(ec_s)])
}

/// The hybrid sender's wire message: padded messages and per-message commitments.
#[derive(Debug, Clone)]
pub struct HybridSenderMessage {
    pub encrypted: Vec<OtPair>,
    pub commitments: Vec<OtPair>,
}

/// `hybridSenderEncrypt`: both halves' per-slot secrets in, padded and committed messages out.
pub fn hybrid_sender_encrypt(sid: &[u8], messages: &[OtPair], ec_secrets: &[OtPair], kem_secrets: &[OtPair]) -> OtResult<HybridSenderMessage> {
    if messages.len() != ec_secrets.len() || messages.len() != kem_secrets.len() {
        return inv("hybridSenderEncrypt: messages/ecSecrets/kemSecrets length mismatch");
    }
    let (mut encrypted, mut commitments) = (Vec::with_capacity(messages.len()), Vec::with_capacity(messages.len()));
    for (i, m) in messages.iter().enumerate() {
        if m[0].len() != m[1].len() {
            return inv(format!("hybridSenderEncrypt (index {i}): the two messages must be equal length"));
        }
        let (mut e, mut c): (OtPair, OtPair) = ([vec![], vec![]], [vec![], vec![]]);
        for s in 0..2 {
            let k = hybrid_transfer_key(sid, i, s, &ec_secrets[i][s], &kem_secrets[i][s], m[s].len())?;
            e[s] = xor_bytes(&m[s], &k)?;
            c[s] = hybrid_commit(sid, i, s, &m[s], &k);
        }
        encrypted.push(e);
        commitments.push(c);
    }
    Ok(HybridSenderMessage { encrypted, commitments })
}

/// `hybridReceiverRecover`: rebuild only the chosen transfer key, unmask, and check the commitment (abort on mismatch).
pub fn hybrid_receiver_recover(sid: &[u8], choices: &[i64], sender: &HybridSenderMessage, ec_recv: &[Vec<u8>], kem_recv: &[Vec<u8>]) -> OtResult<Vec<Vec<u8>>> {
    let n = choices.len();
    if sender.encrypted.len() != n || sender.commitments.len() != n || ec_recv.len() != n || kem_recv.len() != n {
        return inv("hybridReceiverRecover: length mismatch");
    }
    let mut received = Vec::with_capacity(n);
    for (i, ch) in choices.iter().enumerate() {
        let c = (ch & 1) as usize;
        let e = &sender.encrypted[i][c];
        let key = hybrid_transfer_key(sid, i, c, &ec_recv[i], &kem_recv[i], e.len())?;
        let m = xor_bytes(e, &key)?;
        if !ct_eq(&hybrid_commit(sid, i, c, &m, &key), &sender.commitments[i][c]) {
            return Err(OtError::HybridOtAbort(format!("hybrid base OT (index {i}): sender ciphertext inconsistent with its commitment; aborting")));
        }
        received.push(m);
    }
    Ok(received)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msgs(n: usize) -> Vec<OtPair> {
        (0..n).map(|i| [vec![i as u8; 16], vec![0xA0 + i as u8; 16]]).collect()
    }

    #[test]
    fn rounds_agree_with_the_simulators() {
        let choices = [1i64, 0, 1, 1];
        let m = msgs(4);
        let mut r = OtRng::from_decimal("12345").unwrap();
        let (rm, st) = kem_base_ot_receive(&choices, &mut r);
        let sm = kem_base_ot_send(&m, &rm, &mut r).unwrap();
        let got = kem_base_ot_open(&st, &sm).unwrap();
        let mut r2 = OtRng::from_decimal("12345").unwrap();
        assert_eq!(got, super::super::kem_base_ot(&m, &choices, &mut r2).unwrap().received);
        for (i, c) in choices.iter().enumerate() {
            assert_eq!(got[i], m[i][*c as usize]);
        }
    }

    #[test]
    fn committed_rounds_and_abort() {
        let choices = [0i64, 1, 1];
        let m = msgs(3);
        let mut r = OtRng::from_decimal("777").unwrap();
        let (commit, st) = kem_base_ot_mal_commit(&choices, &mut r);
        let nonce = kem_base_ot_mal_sender_nonce(&mut r);
        let opening = kem_base_ot_mal_open(&st);
        let sm = kem_base_ot_mal_send(&m, &commit, &nonce, &opening, &mut r).unwrap();
        let got = kem_base_ot_mal_recover(&st, &nonce, &sm, None).unwrap();
        for (i, c) in choices.iter().enumerate() {
            assert_eq!(got[i], m[i][*c as usize]);
        }
        let mut bad = opening.clone();
        bad.public_keys[1].swap(0, 1);
        assert!(matches!(kem_base_ot_mal_send(&m, &commit, &nonce, &bad, &mut r), Err(OtError::KemBaseOtAbort(_))));
        let rs = kem_base_ot_mal_random_send(&commit, &nonce, &opening, &mut r).unwrap();
        let recv = kem_base_ot_mal_random_recover(&st, &nonce, &rs, None).unwrap();
        for (i, c) in choices.iter().enumerate() {
            assert_eq!(recv[i], rs.sender_secrets[i][*c as usize]);
        }
    }

    #[test]
    fn hybrid_rounds_roundtrip_and_abort() {
        let choices = [1i64, 0];
        let m = msgs(2);
        let sid = b"sid".to_vec();
        let ec: Vec<OtPair> = (0..2).map(|i| [vec![i as u8; 32], vec![9 + i as u8; 32]]).collect();
        let kem: Vec<OtPair> = (0..2).map(|i| [vec![20 + i as u8; 32], vec![30 + i as u8; 32]]).collect();
        let sm = hybrid_sender_encrypt(&sid, &m, &ec, &kem).unwrap();
        let ec_r: Vec<Vec<u8>> = choices.iter().enumerate().map(|(i, c)| ec[i][*c as usize].clone()).collect();
        let kem_r: Vec<Vec<u8>> = choices.iter().enumerate().map(|(i, c)| kem[i][*c as usize].clone()).collect();
        let got = hybrid_receiver_recover(&sid, &choices, &sm, &ec_r, &kem_r).unwrap();
        assert_eq!(got, vec![m[0][1].clone(), m[1][0].clone()]);
        let mut bad = sm.clone();
        bad.encrypted[0][1][0] ^= 1;
        assert!(matches!(hybrid_receiver_recover(&sid, &choices, &bad, &ec_r, &kem_r), Err(OtError::HybridOtAbort(_))));
    }
}
