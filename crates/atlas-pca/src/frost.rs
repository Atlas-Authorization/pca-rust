//! FROST(Ed25519, SHA-512) threshold signing (RFC 9591, ciphersuite FROST-ED25519-SHA512-v1): trusted-dealer key split, round-1
//! commit, round-2 sign, share-verified aggregation and the in-process quorum cosign. The aggregate is an ordinary RFC 8032
//! Ed25519 signature under the group key. Group and scalar arithmetic run on the vetted curve25519-dalek types; only the
//! RFC's protocol steps are written here (a port of `packages/pca/src/frost.ts`, byte-compatible with the shared corpus).
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::{Digest, Sha512};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::Mutex;

pub const FROST_CONTEXT: &str = "FROST-ED25519-SHA512-v1";
/// Bounds the one-shot nonce registry; the oldest entries are evicted first.
pub const SPENT_COMMITMENT_CAP: usize = 262_144;
const MAX_SAFE_INT: i64 = 9_007_199_254_740_991;

struct Spent {
    set: HashSet<Vec<u8>>,
    order: VecDeque<Vec<u8>>,
}
static SPENT: Mutex<Option<Spent>> = Mutex::new(None);

/// One dealer-issued share with its verifying (public) share.
#[derive(Clone)]
pub struct FrostParticipantShare {
    pub identifier: i64,
    pub share: Vec<u8>,
    pub public_key: Vec<u8>,
}
/// The dealer output.
pub struct FrostKeyShares {
    pub group_public_key: Vec<u8>,
    pub participant_shares: Vec<FrostParticipantShare>,
    pub group_commitment: Vec<Vec<u8>>,
}
/// A participant's public round-1 output.
#[derive(Clone)]
pub struct FrostCommitment {
    pub identifier: i64,
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
}
/// The secret round-1 nonces.
pub struct FrostNonces {
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
}
/// The round-1 output of one participant.
pub struct FrostCommitResult {
    pub hiding_nonce: Vec<u8>,
    pub binding_nonce: Vec<u8>,
    pub commitment: FrostCommitment,
}
/// A participant's round-2 output.
#[derive(Clone)]
pub struct FrostSigShare {
    pub identifier: i64,
    pub sig_share: Vec<u8>,
}
/// Binds an identifier to its verifying share.
#[derive(Clone)]
pub struct FrostVerificationShare {
    pub identifier: i64,
    pub public_key: Vec<u8>,
}
/// `None` means absent.
#[derive(Default)]
pub struct FrostSignOpts {
    pub threshold: Option<i64>,
    pub verification_share: Option<Vec<u8>>,
    pub verification_shares: Option<Vec<FrostVerificationShare>>,
}

fn is_id(i: i64) -> bool {
    i > 0 && i <= MAX_SAFE_INT
}

fn wide(b: &[u8]) -> Scalar {
    let mut w = [0u8; 64];
    w[..b.len()].copy_from_slice(b);
    Scalar::from_bytes_mod_order_wide(&w)
}

/// Reduces 0..64 little-endian bytes mod L (the reference `bytesToScalar`); more than 64 bytes is refused.
fn reduce(b: &[u8]) -> Result<Scalar, String> {
    if b.len() > 64 {
        return Err("frost: scalar input longer than 64 bytes".into());
    }
    Ok(wide(b))
}

pub fn frost_scalar(b: &[u8]) -> Result<Vec<u8>, String> {
    reduce(b).map(|s| s.to_bytes().to_vec())
}

/// A 32-byte little-endian value below the group order.
pub fn frost_is_canonical_scalar(b: &[u8]) -> bool {
    <[u8; 32]>::try_from(b).is_ok_and(|a| Scalar::from_canonical_bytes(a).is_some().into())
}

fn id_scalar(id: i64) -> Scalar {
    Scalar::from(id as u64)
}

fn h2s(m: &[u8]) -> Scalar {
    wide(&Sha512::digest(m))
}

fn tagged(tag: &str, m: &[u8]) -> Vec<u8> {
    let mut v = FROST_CONTEXT.as_bytes().to_vec();
    v.extend_from_slice(tag.as_bytes());
    v.extend_from_slice(m);
    v
}

/// H1..H5 of RFC 9591 section 6.1: H1/H2/H3 return a reduced 32-byte scalar, H4/H5 the 64-byte digest.
pub fn frost_hash(which: &str, m: &[u8]) -> Result<Vec<u8>, String> {
    Ok(match which {
        "H1" => h2s(&tagged("rho", m)).to_bytes().to_vec(),
        "H2" => h2s(m).to_bytes().to_vec(),
        "H3" => h2s(&tagged("nonce", m)).to_bytes().to_vec(),
        "H4" => Sha512::digest(tagged("msg", m)).to_vec(),
        "H5" => Sha512::digest(tagged("com", m)).to_vec(),
        _ => return Err(format!("frost: unknown hash {which:?}")),
    })
}

fn h4(m: &[u8]) -> Vec<u8> {
    Sha512::digest(tagged("msg", m)).to_vec()
}
fn h5(m: &[u8]) -> Vec<u8> {
    Sha512::digest(tagged("com", m)).to_vec()
}
fn h1(m: &[u8]) -> Scalar {
    h2s(&tagged("rho", m))
}

const POINT_REJECTED: &str = "frost: point rejected (not canonical, off the curve, small order or not in the prime-order subgroup)";

fn point(b: &[u8]) -> Result<EdwardsPoint, String> {
    let arr = <[u8; 32]>::try_from(b).map_err(|_| "frost: point must be 32 bytes".to_string())?;
    let p = CompressedEdwardsY(arr).decompress().ok_or(POINT_REJECTED)?;
    if p.compress().to_bytes() != arr || p.is_small_order() || !p.is_torsion_free() {
        return Err(POINT_REJECTED.into());
    }
    Ok(p)
}

/// The strict check of any point a caller can influence: 32 bytes, canonical, on the curve, not small order (so not the identity)
/// and in the prime-order subgroup. Returns the canonical encoding.
pub fn frost_decode_safe_point(b: &[u8]) -> Result<Vec<u8>, String> {
    point(b).map(|_| b.to_vec())
}

fn base(s: &Scalar) -> EdwardsPoint {
    ED25519_BASEPOINT_POINT * s
}

fn validate_commitments(lst: &[FrostCommitment], threshold: Option<i64>) -> Result<(), String> {
    if lst.is_empty() {
        return Err("frost: empty commitment list".into());
    }
    if let Some(t) = threshold {
        if t <= 0 || t > MAX_SAFE_INT {
            return Err("frost: invalid threshold".into());
        }
        if (lst.len() as i64) < t {
            return Err(format!("frost: need at least t={t} commitments (got {})", lst.len()));
        }
    }
    let mut seen = HashSet::new();
    for c in lst {
        if !is_id(c.identifier) {
            return Err("frost: participant identifier must be a positive safe integer".into());
        }
        if !seen.insert(c.identifier) {
            return Err(format!("frost: duplicate commitment identifier {}", c.identifier));
        }
        point(&c.hiding)?;
        point(&c.binding)?;
    }
    Ok(())
}

fn rand32() -> Result<Vec<u8>, String> {
    let mut b = vec![0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| format!("frost: no randomness: {e}"))?;
    Ok(b)
}

/// The t-of-n split. `secret`, `coefficients` (t-1 of them) and `identifiers` are optional; missing secret material is drawn from
/// the OS CSPRNG. `identifiers` None means 1..=n.
pub fn frost_trusted_dealer_keygen(
    t: i64,
    n: i64,
    secret: Option<&[u8]>,
    coefficients: &[Option<Vec<u8>>],
    identifiers: Option<&[i64]>,
) -> Result<FrostKeyShares, String> {
    if t < 1 || t > n {
        return Err(format!("frostTrustedDealerKeygen: need 1 <= t <= n (got t={t}, n={n})"));
    }
    let ids: Vec<i64> = match identifiers {
        Some(l) => l.to_vec(),
        None => (1..=n).collect(),
    };
    if ids.len() as i64 != n {
        return Err("frostTrustedDealerKeygen: identifiers.length must equal n".into());
    }
    if ids.iter().collect::<HashSet<_>>().len() != ids.len() {
        return Err("frostTrustedDealerKeygen: identifiers must be distinct".into());
    }
    if ids.iter().any(|&x| x <= 0) {
        return Err("frostTrustedDealerKeygen: identifiers must be positive integers".into());
    }
    let mut coeffs = Vec::new();
    for i in 0..t as usize {
        let raw = if i == 0 { secret.map(<[u8]>::to_vec) } else { coefficients.get(i - 1).cloned().flatten() };
        let raw = match raw {
            Some(r) => r,
            None => rand32()?,
        };
        coeffs.push(reduce(&raw)?);
    }
    let mut out = FrostKeyShares { group_public_key: Vec::new(), participant_shares: Vec::new(), group_commitment: Vec::new() };
    for &id in &ids {
        let x = id_scalar(id);
        let mut acc = Scalar::ZERO;
        for c in coeffs.iter().rev() {
            acc = acc * x + c; // Horner on secret scalars
        }
        out.participant_shares.push(FrostParticipantShare {
            identifier: id,
            share: acc.to_bytes().to_vec(),
            public_key: base(&acc).compress().to_bytes().to_vec(),
        });
    }
    for a in &coeffs {
        out.group_commitment.push(base(a).compress().to_bytes().to_vec());
    }
    out.group_public_key = out.group_commitment[0].clone();
    Ok(out)
}

/// `share * G`.
pub fn frost_verifying_share(share: &[u8]) -> Result<Vec<u8>, String> {
    Ok(base(&reduce(share)?).compress().to_bytes().to_vec())
}

/// Round 1: a fresh (hiding, binding) nonce pair and the public commitments. `None` randomness is drawn from the OS CSPRNG.
pub fn frost_commit(p: &FrostParticipantShare, hiding_randomness: Option<&[u8]>, binding_randomness: Option<&[u8]>) -> Result<FrostCommitResult, String> {
    let hr = match hiding_randomness {
        Some(b) => b.to_vec(),
        None => rand32()?,
    };
    let br = match binding_randomness {
        Some(b) => b.to_vec(),
        None => rand32()?,
    };
    if hr.len() != 32 || br.len() != 32 {
        return Err("frostCommit: nonce randomness must be 32 bytes".into());
    }
    let sk = reduce(&p.share)?.to_bytes();
    let nonce = |r: &[u8]| h2s(&tagged("nonce", &[r, &sk].concat()));
    let (hn, bn) = (nonce(&hr), nonce(&br));
    Ok(FrostCommitResult {
        hiding_nonce: hn.to_bytes().to_vec(),
        binding_nonce: bn.to_bytes().to_vec(),
        commitment: FrostCommitment {
            identifier: p.identifier,
            hiding: base(&hn).compress().to_bytes().to_vec(),
            binding: base(&bn).compress().to_bytes().to_vec(),
        },
    })
}

fn sorted(lst: &[FrostCommitment]) -> Vec<FrostCommitment> {
    let mut c = lst.to_vec();
    c.sort_by_key(|x| x.identifier); // stable
    c
}

fn binding_factors(group_pk: &[u8], lst: &[FrostCommitment], msg: &[u8]) -> BTreeMap<i64, Scalar> {
    let mut enc = Vec::new();
    for c in lst {
        enc.extend_from_slice(&id_scalar(c.identifier).to_bytes());
        enc.extend_from_slice(&c.hiding);
        enc.extend_from_slice(&c.binding);
    }
    let mut prefix = group_pk.to_vec();
    prefix.extend_from_slice(&h4(msg));
    prefix.extend_from_slice(&h5(&enc));
    lst.iter()
        .map(|c| {
            let mut m = prefix.clone();
            m.extend_from_slice(&id_scalar(c.identifier).to_bytes());
            (c.identifier, h1(&m))
        })
        .collect()
}

fn group_commitment(lst: &[FrostCommitment], bf: &BTreeMap<i64, Scalar>) -> Result<EdwardsPoint, String> {
    let mut r = EdwardsPoint::identity();
    for c in lst {
        let (h, b) = (point(&c.hiding)?, point(&c.binding)?);
        r = r + h + b * bf[&c.identifier];
    }
    Ok(r)
}

/// The Lagrange coefficient at zero (public integers only).
fn lambda(participants: &[i64], i: i64) -> Result<Scalar, String> {
    if !participants.contains(&i) {
        return Err("frost: identifier not in participant list".into());
    }
    let (mut num, mut den) = (Scalar::ONE, Scalar::ONE);
    for &j in participants {
        if j != i {
            num *= id_scalar(j);
            den *= id_scalar(j) - id_scalar(i);
        }
    }
    if den == Scalar::ZERO {
        return Err("frost: modular inverse of zero".into());
    }
    let lam = num * den.invert();
    if lam == Scalar::ZERO {
        return Err("frost: zero Lagrange coefficient".into());
    }
    Ok(lam)
}

fn challenge(r: &EdwardsPoint, group_pk: &[u8], msg: &[u8]) -> Scalar {
    h2s(&[&r.compress().to_bytes()[..], group_pk, msg].concat())
}

/// Round 2: this participant's signature share. One-shot: a nonce pair (and its public commitments) signs once, ever.
pub fn frost_sign(
    identifier: i64,
    share: &[u8],
    group_public_key: &[u8],
    nonces: &FrostNonces,
    message: &[u8],
    signing_commitments: &[FrostCommitment],
    o: &FrostSignOpts,
) -> Result<FrostSigShare, String> {
    if !is_id(identifier) {
        return Err("frost: participant identifier must be a positive safe integer".into());
    }
    validate_commitments(signing_commitments, o.threshold)?;
    point(group_public_key)?;
    if nonces.hiding.iter().all(|&b| b == 0) || nonces.binding.iter().all(|&b| b == 0) {
        return Err("frostSign: zero/zeroized nonce".into());
    }
    if nonces.hiding == nonces.binding {
        return Err("frostSign: hiding and binding nonce must differ".into());
    }
    let lst = sorted(signing_commitments);
    let mine = lst.iter().find(|c| c.identifier == identifier).ok_or("frostSign: this identifier has no commitment in the set")?;
    let (hiding, binding, sk) = (reduce(&nonces.hiding)?, reduce(&nonces.binding)?, reduce(share)?);
    if base(&hiding).compress().to_bytes()[..] != mine.hiding[..] || base(&binding).compress().to_bytes()[..] != mine.binding[..] {
        return Err("frostSign: own commitment does not match nonces".into());
    }
    let keys = [[b"h".as_slice(), &mine.hiding].concat(), [b"b".as_slice(), &mine.binding].concat()];
    let mut guard = SPENT.lock().unwrap_or_else(|e| e.into_inner());
    let spent = guard.get_or_insert_with(|| Spent { set: HashSet::new(), order: VecDeque::new() });
    if keys.iter().any(|k| spent.set.contains(k)) {
        return Err("frostSign: nonces already used (one-shot; reuse would leak the signing share)".into());
    }
    if let Some(vs) = &o.verification_share {
        point(vs)?;
        if base(&sk).compress().to_bytes()[..] != vs[..] {
            return Err("frostSign: share does not match verification share".into());
        }
    }
    let participants: Vec<i64> = lst.iter().map(|c| c.identifier).collect();
    if let Some(vss) = &o.verification_shares {
        let mut acc = EdwardsPoint::identity();
        for &pid in &participants {
            let vs = vss.iter().find(|v| v.identifier == pid).ok_or_else(|| format!("frostSign: missing verification share for {pid}"))?;
            acc += point(&vs.public_key)? * lambda(&participants, pid)?;
        }
        if acc.compress().to_bytes()[..] != group_public_key[..] {
            return Err("frostSign: group public key does not match the verification shares".into());
        }
    }
    let bf = binding_factors(group_public_key, &lst, message);
    let r = group_commitment(&lst, &bf)?;
    let c = challenge(&r, group_public_key, message);
    let lam = lambda(&participants, identifier)?;
    let z = hiding + binding * bf[&identifier] + lam * sk * c;
    for k in keys {
        spent.set.insert(k.clone());
        spent.order.push_back(k);
    }
    while spent.order.len() > SPENT_COMMITMENT_CAP {
        if let Some(old) = spent.order.pop_front() {
            spent.set.remove(&old);
        }
    }
    Ok(FrostSigShare { identifier, sig_share: z.to_bytes().to_vec() })
}

/// Checks one signature share against its participant's verifying share; any malformed input is false.
pub fn frost_verify_sig_share(
    identifier: i64,
    public_key: &[u8],
    commitment: &FrostCommitment,
    sig_share: &FrostSigShare,
    signing_commitments: &[FrostCommitment],
    group_public_key: &[u8],
    message: &[u8],
) -> bool {
    verify_share(identifier, public_key, commitment, sig_share, signing_commitments, group_public_key, message).unwrap_or(false)
}

fn verify_share(
    identifier: i64,
    public_key: &[u8],
    commitment: &FrostCommitment,
    sig_share: &FrostSigShare,
    signing_commitments: &[FrostCommitment],
    group_public_key: &[u8],
    message: &[u8],
) -> Result<bool, String> {
    validate_commitments(signing_commitments, None)?;
    let lst = sorted(signing_commitments);
    let bf = binding_factors(group_public_key, &lst, message);
    let bfi = *bf.get(&identifier).ok_or("no binding factor")?;
    let r = group_commitment(&lst, &bf)?;
    let comm_share = point(&commitment.hiding)? + point(&commitment.binding)? * bfi;
    let c = challenge(&r, group_public_key, message);
    let participants: Vec<i64> = lst.iter().map(|x| x.identifier).collect();
    let lam = lambda(&participants, identifier)?;
    let zs = Scalar::from_canonical_bytes(<[u8; 32]>::try_from(&sig_share.sig_share[..]).map_err(|_| "sig share length")?);
    if zs.is_none().into() {
        return Ok(false);
    }
    let zs = zs.unwrap();
    let rhs = comm_share + point(public_key)? * (c * lam);
    Ok(base(&zs) == rhs)
}

/// Verifies every signature share, sums them and returns the 64-byte Ed25519 signature; it fails unless that verifies.
pub fn frost_aggregate(
    message: &[u8],
    signing_commitments: &[FrostCommitment],
    sig_shares: &[FrostSigShare],
    group_public_key: &[u8],
    verification_shares: Option<&[FrostVerificationShare]>,
    threshold: Option<i64>,
) -> Result<Vec<u8>, String> {
    validate_commitments(signing_commitments, threshold)?;
    point(group_public_key)?;
    let lst = sorted(signing_commitments);
    if sig_shares.len() != lst.len() {
        return Err("frostAggregate: need exactly one signature share per commitment".into());
    }
    let mut seen = HashSet::new();
    for s in sig_shares {
        if !lst.iter().any(|c| c.identifier == s.identifier) {
            return Err("frostAggregate: share from non-signer".into());
        }
        if !seen.insert(s.identifier) {
            return Err("frostAggregate: duplicate signature share".into());
        }
    }
    let vss = verification_shares.ok_or("frostAggregate: verificationShares are required (every signature share is verified before aggregation)")?;
    for s in sig_shares {
        let vs = vss.iter().find(|v| v.identifier == s.identifier);
        let com = lst.iter().find(|c| c.identifier == s.identifier);
        match (vs, com) {
            (Some(vs), Some(com)) if frost_verify_sig_share(s.identifier, &vs.public_key, com, s, &lst, group_public_key, message) => {}
            _ => return Err(format!("frostAggregate: invalid signature share from participant {}", s.identifier)),
        }
    }
    let r = group_commitment(&lst, &binding_factors(group_public_key, &lst, message))?;
    let mut z = Scalar::ZERO;
    for s in sig_shares {
        z += reduce(&s.sig_share)?;
    }
    let mut sig = r.compress().to_bytes().to_vec();
    sig.extend_from_slice(&z.to_bytes());
    let (pk, sg) = (<[u8; 32]>::try_from(group_public_key).map_err(|_| "group key length")?, <[u8; 64]>::try_from(&sig[..]).map_err(|_| "sig length")?);
    if !crate::verify_ed25519_strict(&pk, message, &sg) {
        return Err("frostAggregate: aggregate signature does not verify (a share is invalid)".into());
    }
    Ok(sig)
}

/// Runs the whole protocol in process for a quorum of participant shares (the dealer / guardian-tier path).
pub fn frost_cosign(group_public_key: &[u8], quorum: &[FrostParticipantShare], message: &[u8], threshold: Option<i64>) -> Result<Vec<u8>, String> {
    if quorum.is_empty() {
        return Err("frostCosign: empty signing quorum".into());
    }
    if let Some(t) = threshold {
        if (quorum.len() as i64) < t {
            return Err(format!("frostCosign: quorum of {} is below the threshold t={t}", quorum.len()));
        }
    }
    let mut ids = HashSet::new();
    for p in quorum {
        if !is_id(p.identifier) {
            return Err("frost: participant identifier must be a positive safe integer".into());
        }
        if !ids.insert(p.identifier) {
            return Err(format!("frostCosign: duplicate participant {} in quorum", p.identifier));
        }
    }
    let vss: Vec<FrostVerificationShare> =
        quorum.iter().map(|p| FrostVerificationShare { identifier: p.identifier, public_key: p.public_key.clone() }).collect();
    let mut commits = Vec::new();
    for p in quorum {
        commits.push(frost_commit(p, None, None)?);
    }
    let comms: Vec<FrostCommitment> = commits.iter().map(|c| c.commitment.clone()).collect();
    let mut shares = Vec::new();
    for (p, c) in quorum.iter().zip(&commits) {
        let n = FrostNonces { hiding: c.hiding_nonce.clone(), binding: c.binding_nonce.clone() };
        let o = FrostSignOpts { threshold, verification_share: Some(p.public_key.clone()), verification_shares: Some(vss.clone()) };
        shares.push(frost_sign(p.identifier, &p.share, group_public_key, &n, message, &comms, &o)?);
    }
    frost_aggregate(message, &comms, &shares, group_public_key, Some(&vss), threshold)
}
