//! FROST distributed key generation (port of `frost-dkg.ts`): Pedersen / Feldman VSS with a proof of knowledge, signed shares, non-repudiable
//! complaints, blame resolution, echo-broadcast agreement and a verified finalize, with no trusted dealer.
//!
//! Round 1: each participant i draws a degree t-1 polynomial f_i, broadcasts the Feldman commitments `C_i,k = a_i,k * B` and a Schnorr proof of
//! knowledge of `a_i,0` (domain separated, bound to the session and the identifier). Round 2: i sends `f_i(j)` to every j, signed under `a_i,0`
//! (a Schnorr signature verified against `C_i,0`), so a recipient can PROVE a bad share to everyone without being framed. Blame: a complaint
//! carries the accused-signed share; it is justified only if that share fails VSS against the accused's broadcast commitments. Echo broadcast:
//! every qualified party signs off on the same transcript digest before finalize, so an equivocating dealer is detected. Finalize: the signing
//! share is the sum of the received shares, the group key the sum of the constant commitments, checked against the group verifying share.
//!
//! JSON-valued like the reference: packages, shares, complaints and key packages are `serde_json::Value`, with a byte string written
//! `{"$bytes": "<base64url>"}` ([`bv`] / [`bytes_of`]). Every verifier that returns a boolean or a verdict is total (any malformed input is a
//! refusal value); the producing functions return `Err`. Randomness comes from a [`RandomBytes`] seam.
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha512};

use crate::adapters::js_string;
use crate::frost::{frost_decode_safe_point, frost_is_canonical_scalar};
use crate::frost_net::RandomBytes;
use crate::{b64_encode, decode_b64u_strict, hash_canonical_strict};

type R<T> = Result<T, String>;

const CTX: &[u8] = b"FROST-ED25519-SHA512-v1";
const POP_DST: &[u8] = b"dkg-pop";
const SHARE_DST: &[u8] = b"dkg-share";
const SHARE_NONCE_DST: &[u8] = b"dkg-share-nonce";
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;
static NULL: Value = Value::Null;

// ---- JavaScript value semantics ------------------------------------------------------------------------------------------

/// A byte string as the corpus and the wire models write it.
pub fn bv(b: &[u8]) -> Value {
    json!({ "$bytes": b64_encode(b) })
}

/// The bytes of a `{"$bytes": ...}` value; anything else is not bytes.
pub fn bytes_of(v: &Value) -> Option<Vec<u8>> {
    let m = v.as_object().filter(|m| m.len() == 1)?;
    decode_b64u_strict(m.get("$bytes")?.as_str()?, None)
}

fn bytes_req(v: &Value) -> R<Vec<u8>> {
    bytes_of(v).ok_or_else(|| "expected bytes".to_string())
}

/// `Number.isInteger` (a finite whole number that is not a boolean).
pub fn isint(v: &Value) -> Option<f64> {
    v.as_f64().filter(|f| v.is_number() && f.is_finite() && f.fract() == 0.0)
}

/// A positive safe integer.
pub fn safe_pos(v: &Value) -> bool {
    isint(v).is_some_and(|f| f > 0.0 && f <= MAX_SAFE)
}

/// JavaScript `===` for JSON values (an object or array is only ever identical to itself, so never equal here).
pub fn seq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Null, Value::Null) => true,
        _ => false,
    }
}

/// A dictionary key for a JSON scalar (`1` and `1.0` are one key).
pub fn numkey(v: &Value) -> String {
    match v {
        Value::Number(n) => format!("n{}", n.as_f64().unwrap_or(f64::NAN)),
        Value::String(s) => format!("s{s}"),
        other => format!("o{other}"),
    }
}

/// `o[k]`: reading a member of null throws, of any other primitive is undefined (null here).
pub fn gv<'a>(o: &'a Value, k: &str) -> R<&'a Value> {
    match o {
        Value::Null => Err("cannot read properties of null".into()),
        Value::Object(m) => Ok(m.get(k).unwrap_or(&NULL)),
        _ => Ok(&NULL),
    }
}

/// What the reference iterates with a for-of / map: an array; anything else throws.
pub fn arr(v: &Value) -> R<&Vec<Value>> {
    v.as_array().ok_or_else(|| "not iterable".to_string())
}

fn id_i64(v: &Value) -> i64 {
    v.as_f64().unwrap_or(0.0) as i64
}

fn repr(v: &Value) -> String {
    v.to_string()
}

/// Copy member `k` of `o` into `m` when present (an absent member is undefined and is dropped by canonical JSON); reading null throws.
fn put(m: &mut Map<String, Value>, o: &Value, k: &str) -> R<()> {
    match o {
        Value::Null => Err("cannot read properties of null".into()),
        Value::Object(src) => {
            if let Some(x) = src.get(k) {
                m.insert(k.into(), x.clone());
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Scalar from digits in `radix`, reduced mod the group order.
fn digits(s: &str, radix: u32) -> Option<Scalar> {
    if s.is_empty() {
        return None;
    }
    let r = Scalar::from(radix as u64);
    s.chars().try_fold(Scalar::ZERO, |acc, c| Some(acc * r + Scalar::from(c.to_digit(radix)? as u64)))
}

/// `BigInt(x)` reduced mod the group order: a whole number or a decimal / hex / octal / binary string; a fraction, null or an object throws.
fn big(v: &Value) -> R<Scalar> {
    match v {
        Value::Bool(b) => Ok(Scalar::from(*b as u64)),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                return Ok(Scalar::from(u));
            }
            if let Some(i) = n.as_i64() {
                return Ok(-Scalar::from(i.unsigned_abs()));
            }
            let f = n.as_f64().filter(|f| f.is_finite() && f.fract() == 0.0).ok_or("BigInt: not an integer")?;
            let s = digits(&format!("{:.0}", f.abs()), 10).ok_or("BigInt: not an integer")?;
            Ok(if f < 0.0 { -s } else { s })
        }
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                return Ok(Scalar::ZERO);
            }
            let (neg, body) = match t.as_bytes()[0] {
                b'-' => (true, &t[1..]),
                b'+' => (false, &t[1..]),
                _ => (false, t),
            };
            if let Some(d) = digits(body, 10) {
                return Ok(if neg { -d } else { d });
            }
            let lower = t.to_ascii_lowercase();
            for (p, radix) in [("0x", 16), ("0o", 8), ("0b", 2)] {
                if let Some(rest) = lower.strip_prefix(p) {
                    return digits(rest, radix).ok_or_else(|| "BigInt: not a number".to_string());
                }
            }
            Err("BigInt: not a number".into())
        }
        _ => Err("BigInt: cannot convert".into()),
    }
}

fn scalar_of(v: &Value) -> R<[u8; 32]> {
    big(v).map(|s| s.to_bytes())
}

// ---- group helpers -------------------------------------------------------------------------------------------------------------

fn wide(b: &[u8]) -> R<Scalar> {
    if b.len() > 64 {
        return Err("frost: scalar input longer than 64 bytes".into());
    }
    let mut w = [0u8; 64];
    w[..b.len()].copy_from_slice(b);
    Ok(Scalar::from_bytes_mod_order_wide(&w))
}

fn canonical_scalar(b: &[u8]) -> R<Scalar> {
    if !frost_is_canonical_scalar(b) {
        return Err("dkg: scalar must be 32 bytes and < the group order".into());
    }
    Option::<Scalar>::from(Scalar::from_canonical_bytes(<[u8; 32]>::try_from(b).unwrap())).ok_or_else(|| "dkg: scalar".to_string())
}

fn base(s: &Scalar) -> EdwardsPoint {
    ED25519_BASEPOINT_POINT * s
}

fn enc(p: &EdwardsPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

fn safe_point(raw: &[u8]) -> R<EdwardsPoint> {
    let ok = frost_decode_safe_point(raw)?;
    CompressedEdwardsY(<[u8; 32]>::try_from(ok.as_slice()).unwrap()).decompress().ok_or_else(|| "dkg: point".to_string())
}

fn unb64u(v: &Value) -> R<Vec<u8>> {
    v.as_str().and_then(|s| decode_b64u_strict(s, None)).ok_or_else(|| "base64url decode failed".to_string())
}

fn pt_of(v: &Value) -> R<EdwardsPoint> {
    safe_point(&unb64u(v)?)
}

fn hash_to_scalar(parts: &[&[u8]]) -> R<Scalar> {
    let mut h = Sha512::new();
    parts.iter().for_each(|p| h.update(p));
    wide(&h.finalize())
}

/// (first commitment point, the length-prefixed concatenation of the commitment encodings); every commitment must be a safe point.
type CommitVec = (EdwardsPoint, Vec<u8>);

fn commit_vec(commitments: &Value) -> R<CommitVec> {
    let list = commitments.as_array().filter(|l| !l.is_empty()).ok_or("dkg: empty commitment vector")?;
    let pts: Vec<EdwardsPoint> = list.iter().map(pt_of).collect::<R<_>>()?;
    let mut cat = (pts.len() as u32).to_be_bytes().to_vec();
    pts.iter().for_each(|p| cat.extend_from_slice(&enc(p)));
    Ok((pts[0], cat))
}

fn eval_poly(coeffs: &[Scalar], x: &Scalar) -> Scalar {
    coeffs.iter().rev().fold(Scalar::ZERO, |acc, c| acc * x + c)
}

fn vss_check(share: &Scalar, commitments: &Value, at_id: &Value) -> R<bool> {
    let list = commitments.as_array().ok_or("not iterable")?;
    if list.is_empty() {
        return Ok(false);
    }
    let x = big(at_id)?;
    let (mut rhs, mut xk) = (EdwardsPoint::identity(), Scalar::ONE);
    for c in list {
        rhs += pt_of(c)? * xk;
        xk *= x;
    }
    Ok(base(share) == rhs)
}

fn pop_challenge(sid: &[u8], identifier: &Value, cv: &CommitVec, r: &EdwardsPoint) -> R<Scalar> {
    hash_to_scalar(&[CTX, POP_DST, sid, &scalar_of(identifier)?, &cv.1, &enc(r)])
}

fn share_challenge(sid: &[u8], frm: &Value, to: &Value, share: &[u8], cv: &CommitVec, rs: &EdwardsPoint) -> R<Scalar> {
    hash_to_scalar(&[CTX, SHARE_DST, sid, &scalar_of(frm)?, &scalar_of(to)?, share, &cv.1, &enc(rs)])
}

fn share_nonce(a0: &Scalar, sid: &[u8], frm: &Value, to: &Value, share: &[u8], cv: &CommitVec) -> R<Scalar> {
    hash_to_scalar(&[CTX, SHARE_NONCE_DST, &a0.to_bytes(), sid, &scalar_of(frm)?, &scalar_of(to)?, share, &cv.1])
}

fn sign_share_scalar(a0: &Scalar, cv: &CommitVec, sid: &[u8], frm: &Value, to: &Value, share: &[u8]) -> R<String> {
    let k = share_nonce(a0, sid, frm, to, share, cv)?;
    let rs = base(&k);
    let e = share_challenge(sid, frm, to, share, cv, &rs)?;
    let s = k + a0 * e;
    Ok(b64_encode(&[enc(&rs), s.to_bytes()].concat()))
}

fn verify_share_sig(sig: &Value, sid: &[u8], frm: &Value, to: &Value, share: &[u8], cv: &CommitVec) -> bool {
    let go = || -> R<bool> {
        let raw = unb64u(sig)?;
        if raw.len() != 64 {
            return Ok(false);
        }
        let rs = safe_point(&raw[..32])?;
        let s = canonical_scalar(&raw[32..])?;
        let e = share_challenge(sid, frm, to, share, cv, &rs)?;
        Ok(base(&s) == rs + cv.0 * e)
    };
    go().unwrap_or(false)
}

fn verify_share_sig_against_package(sig: &Value, sid: &[u8], frm: &Value, to: &Value, share: &[u8], sender_package: &Value) -> bool {
    let go = || -> R<bool> {
        let commitments = gv(sender_package, "coefficientCommitments")?;
        if !sig.is_string() || commitments.as_array().is_none_or_empty() {
            return Ok(false);
        }
        Ok(verify_share_sig(sig, sid, frm, to, share, &commit_vec(commitments)?))
    };
    go().unwrap_or(false)
}

trait NoneOrEmpty {
    fn is_none_or_empty(&self) -> bool;
}

impl NoneOrEmpty for Option<&Vec<Value>> {
    fn is_none_or_empty(&self) -> bool {
        self.map_or(true, |l| l.is_empty())
    }
}

// ---- round 1 -------------------------------------------------------------------------------------------------------------------

/// One participant's secret round-1 state.
#[derive(Clone, Debug)]
pub struct DkgState {
    pub identifier: i64,
    pub t: i64,
    pub n: i64,
    pub session_id: Vec<u8>,
    /// The t polynomial coefficients (reduced scalars, 32 bytes each).
    pub coefficients: Vec<Vec<u8>>,
    /// The broadcast round-1 package.
    pub package: Value,
}

impl DkgState {
    fn coeffs(&self) -> R<Vec<Scalar>> {
        self.coefficients.iter().map(|c| wide(c)).collect()
    }
    fn id_value(&self) -> Value {
        json!(self.identifier)
    }
}

/// The participant's signature (under its constant coefficient) over a share it sends to `to`; any share bytes can be signed (a cheater's too).
pub fn dkg_sign_share(state: &DkgState, to: &Value, share: &Value) -> R<String> {
    let a0 = wide(&state.coefficients[0])?;
    let cv = commit_vec(gv(&state.package, "coefficientCommitments")?)?;
    sign_share_scalar(&a0, &cv, &state.session_id, &state.id_value(), to, &bytes_req(share)?)
}

/// Round 1 of participant `identifier`: the broadcast package and the secret state. `opts`: `coefficients` (t fixed byte strings) and `popNonce`
/// (a fixed proof nonce) for reproducible vectors; otherwise t coefficients and then the nonce are drawn from `random`.
pub fn dkg_round1(
    identifier: &Value,
    t: &Value,
    n: &Value,
    session_id: &Value,
    opts: Option<&Value>,
    random: &RandomBytes,
) -> R<(Value, DkgState)> {
    let id = isint(identifier).filter(|f| *f > 0.0).ok_or("dkgRound1: identifier must be a positive integer")?;
    let (tf, nf) = (isint(t), isint(n));
    let (tf, nf) = match (tf, nf) {
        (Some(a), Some(b)) if a >= 1.0 && b >= a => (a, b),
        _ => return Err(format!("dkgRound1: need 1 <= t <= n (got t={}, n={})", js_string(t), js_string(n))),
    };
    let sid = bytes_of(session_id).filter(|s| !s.is_empty()).ok_or("dkgRound1: sessionId must be a non-empty byte string")?;
    let none = Value::Null;
    let opts = opts.unwrap_or(&none);
    let given = gv(opts, "coefficients").ok().filter(|c| !c.is_null());
    let coeffs: Vec<Scalar> = match given {
        Some(list) => {
            let l = arr(list)?;
            if l.len() as f64 != tf {
                return Err(format!("dkgRound1: coefficients.length must equal t ({tf})"));
            }
            l.iter().map(|c| wide(&bytes_req(c)?)).collect::<R<_>>()?
        }
        None => (0..tf as usize).map(|_| wide(&random(32))).collect::<R<_>>()?,
    };
    let commitments: Vec<Value> = coeffs.iter().map(|a| json!(b64_encode(&enc(&base(a))))).collect();
    let cv = commit_vec(&Value::Array(commitments.clone()))?;
    let k = match gv(opts, "popNonce").ok().filter(|c| !c.is_null()) {
        Some(p) => wide(&bytes_req(p)?)?,
        None => wide(&random(32))?,
    };
    let r = base(&k);
    let c = pop_challenge(&sid, &json!(id as i64), &cv, &r)?;
    let mu = k + coeffs[0] * c;
    let pkg = json!({
        "identifier": id as i64, "sessionId": b64_encode(&sid), "coefficientCommitments": commitments,
        "proofOfKnowledge": {"R": b64_encode(&enc(&r)), "mu": b64_encode(&mu.to_bytes())},
    });
    let state = DkgState {
        identifier: id as i64,
        t: tf as i64,
        n: nf as i64,
        session_id: sid,
        coefficients: coeffs.iter().map(|c| c.to_bytes().to_vec()).collect(),
        package: pkg.clone(),
    };
    Ok((pkg, state))
}

/// Verify a round-1 package: it names this session and its constant commitment is proven known by the Schnorr proof bound to `from_identifier`.
pub fn dkg_verify_round1(from_identifier: &Value, pkg: &Value, session_id: &Value) -> bool {
    let go = || -> R<bool> {
        let sid = bytes_req(session_id)?;
        if gv(pkg, "sessionId")? != &json!(b64_encode(&sid)) {
            return Ok(false);
        }
        let commitments = gv(pkg, "coefficientCommitments")?;
        if commitments.as_array().is_none_or_empty() {
            return Ok(false);
        }
        let cv = commit_vec(commitments)?;
        let pok = gv(pkg, "proofOfKnowledge")?;
        let r = pt_of(gv(pok, "R")?)?;
        let mu = canonical_scalar(&unb64u(gv(pok, "mu")?)?)?;
        let c = pop_challenge(&sid, from_identifier, &cv, &r)?;
        Ok(base(&mu) == r + cv.0 * c)
    };
    go().unwrap_or(false)
}

// ---- round 2 -------------------------------------------------------------------------------------------------------------------

fn distinct_ids(ids: &[Value]) -> bool {
    let mut seen = std::collections::HashSet::new();
    ids.iter().all(|i| seen.insert(repr(i)))
}

/// The signed shares this participant sends: one per other package, in package order. Packages are not validated here (see
/// [`dkg_verify_round1`]).
pub fn dkg_round2(state: &DkgState, all_round1_packages: &Value) -> R<Vec<Value>> {
    let pkgs = arr(all_round1_packages)?;
    let ids: Vec<Value> = pkgs.iter().map(|p| gv(p, "identifier").cloned()).collect::<R<_>>()?;
    if !distinct_ids(&ids) {
        return Err("dkgRound2: duplicate identifiers in round-1 packages".into());
    }
    let me = state.id_value();
    if !ids.iter().any(|i| seq(i, &me)) {
        return Err("dkgRound2: my own round-1 package is missing".into());
    }
    let sid_b64 = b64_encode(&state.session_id);
    for p in pkgs {
        if gv(p, "sessionId")? != &json!(sid_b64) {
            return Err(format!("dkgRound2: participant {} round-1 package is from a different session", js_string(gv(p, "identifier")?)));
        }
    }
    let coeffs = state.coeffs()?;
    let cv = commit_vec(gv(&state.package, "coefficientCommitments")?)?;
    let mut out = Vec::new();
    for j in &ids {
        if seq(j, &me) {
            continue;
        }
        let share = eval_poly(&coeffs, &big(j)?).to_bytes();
        let sig = sign_share_scalar(&coeffs[0], &cv, &state.session_id, &me, j, &share)?;
        out.push(json!({"from": state.identifier, "to": j, "sessionId": sid_b64, "share": bv(&share), "sig": sig}));
    }
    Ok(out)
}

/// A received share is accepted only if the sender's package verifies, the share is signed by the sender for THIS recipient and session, and it
/// passes Feldman VSS against the sender's broadcast commitments.
pub fn dkg_verify_share(received: &Value, sender_package: &Value, my_identifier: &Value, session_id: &Value) -> bool {
    let go = || -> R<bool> {
        let Some(share) = received.as_object().and_then(|m| m.get("share")).and_then(bytes_of) else { return Ok(false) };
        if !dkg_verify_round1(gv(sender_package, "identifier")?, sender_package, session_id) {
            return Ok(false);
        }
        let sid = bytes_req(session_id)?;
        if !verify_share_sig_against_package(gv(received, "sig")?, &sid, gv(received, "from")?, my_identifier, &share, sender_package) {
            return Ok(false);
        }
        vss_check(&canonical_scalar(&share)?, gv(sender_package, "coefficientCommitments")?, my_identifier)
    };
    go().unwrap_or(false)
}

// ---- blame ---------------------------------------------------------------------------------------------------------------------

/// A complaint carrying the accused-signed share the accuser received. It is only a claim until [`dkg_verify_complaint`] adjudicates it.
pub fn dkg_file_complaint(params: &Value) -> R<Value> {
    let accused = gv(params, "accused")?;
    let accuser = gv(params, "accuser")?;
    let share_sig = gv(params, "shareSig")?;
    if !isint(accused).is_some_and(|f| f > 0.0) {
        return Err("dkgFileComplaint: accused must be a positive integer".into());
    }
    if !isint(accuser).is_some_and(|f| f > 0.0) {
        return Err("dkgFileComplaint: accuser must be a positive integer".into());
    }
    if seq(accused, accuser) {
        return Err("dkgFileComplaint: cannot file a complaint against yourself".into());
    }
    if !share_sig.as_str().is_some_and(|s| !s.is_empty()) {
        return Err("dkgFileComplaint: shareSig (the accused-signed share) is required".into());
    }
    let sid = bytes_of(gv(params, "sessionId")?)
        .filter(|s| !s.is_empty())
        .ok_or("dkgFileComplaint: sessionId must be a non-empty byte string")?;
    let revealed = wide(&bytes_req(gv(params, "receivedShare")?)?)?;
    Ok(
        json!({"accused": accused, "accuser": accuser, "sessionId": b64_encode(&sid), "revealedShare": b64_encode(&revealed.to_bytes()), "shareSig": share_sig}),
    )
}

fn find_package<'a>(packages: &'a Value, identifier: &Value) -> R<Option<&'a Value>> {
    for p in arr(packages)? {
        if seq(gv(p, "identifier")?, identifier) {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

/// Adjudicate a complaint against the accused's broadcast package: justified only when the accused SIGNED a share that FAILS VSS; a share the
/// accused never signed is inadmissible (it cannot frame an honest party) and a valid signed share is a false accusation (the accuser is at
/// fault).
pub fn dkg_verify_complaint(complaint: &Value, round1_packages: &Value) -> Value {
    let go = || -> R<Value> {
        let Some(pkg) = find_package(round1_packages, gv(complaint, "accused")?)? else {
            return Ok(
                json!({"justified": false, "reason": format!("accused {} has no round-1 package to adjudicate against", js_string(gv(complaint, "accused")?))}),
            );
        };
        if gv(pkg, "sessionId")? != gv(complaint, "sessionId")? {
            return Ok(json!({"justified": false, "reason": "complaint sessionId does not match the accused round-1 package session"}));
        }
        let sid = unb64u(gv(complaint, "sessionId")?)?;
        let share = unb64u(gv(complaint, "revealedShare")?)?;
        let (accused, accuser) = (gv(complaint, "accused")?, gv(complaint, "accuser")?);
        if !verify_share_sig_against_package(gv(complaint, "shareSig")?, &sid, accused, accuser, &share, pkg) {
            return Ok(json!({"justified": false, "atFault": accuser,
                "reason": "revealed share is not validly signed by the accused — inadmissible (cannot frame an honest party)"}));
        }
        if vss_check(&canonical_scalar(&share)?, gv(pkg, "coefficientCommitments")?, accuser)? {
            return Ok(
                json!({"justified": false, "atFault": accuser, "reason": "accused-signed share is VALID against the accused commitments — false accusation"}),
            );
        }
        Ok(
            json!({"justified": true, "disqualify": accused, "reason": "accused non-repudiably signed a share that FAILS VSS against its broadcast commitments"}),
        )
    };
    go().unwrap_or_else(|_| json!({"justified": false, "reason": "malformed complaint"}))
}

/// The accused's rebuttal to a complaint: the share it owes the accuser, recomputed from its own polynomial and freshly signed.
pub fn dkg_rebut(accused: &Value, complaint: &Value, state: &DkgState) -> R<Value> {
    if !seq(&state.id_value(), accused) {
        return Err("dkgRebut: myRound2State is not the accused".into());
    }
    if !seq(gv(complaint, "accused")?, accused) {
        return Err("dkgRebut: complaint does not name this accused".into());
    }
    if &json!(b64_encode(&state.session_id)) != gv(complaint, "sessionId")? {
        return Err("dkgRebut: complaint is scoped to a different session than my state".into());
    }
    let accuser = gv(complaint, "accuser")?;
    let share = eval_poly(&state.coeffs()?, &big(accuser)?).to_bytes();
    let share_sig = dkg_sign_share(state, accuser, &bv(&share))?;
    Ok(
        json!({"accused": accused, "accuser": accuser, "sessionId": gv(complaint, "sessionId")?, "presentedShare": b64_encode(&share), "shareSig": share_sig}),
    )
}

/// Who is guilty after a complaint and the accused's optional rebuttal: `{guilty, reason}`. Total.
pub fn dkg_resolve_blame(complaint: &Value, rebuttal: &Value, round1_packages: &Value) -> Value {
    let go = || -> R<Value> {
        let (accused, accuser) = (gv(complaint, "accused")?, gv(complaint, "accuser")?);
        let Some(pkg) = find_package(round1_packages, accused)? else {
            return Ok(
                json!({"guilty": accused, "reason": format!("accused {} has no round-1 package to defend with", js_string(accused))}),
            );
        };
        if gv(pkg, "sessionId")? != gv(complaint, "sessionId")? {
            return Ok(json!({"guilty": accuser, "reason": "complaint names a session the accused did not run — inadmissible"}));
        }
        let sid = unb64u(gv(complaint, "sessionId")?)?;
        let share = unb64u(gv(complaint, "revealedShare")?)?;
        let commitments = gv(pkg, "coefficientCommitments")?;
        if verify_share_sig_against_package(gv(complaint, "shareSig")?, &sid, accused, accuser, &share, pkg) {
            return Ok(if !vss_check(&canonical_scalar(&share)?, commitments, accuser)? {
                json!({"guilty": accused, "reason": "accused non-repudiably signed a share that fails VSS"})
            } else {
                json!({"guilty": accuser, "reason": "accused-signed share is valid against its commitments — false accusation"})
            });
        }
        if !rebuttal.is_null()
            && seq(gv(rebuttal, "accused")?, accused)
            && seq(gv(rebuttal, "accuser")?, accuser)
            && gv(rebuttal, "sessionId")? == gv(complaint, "sessionId")?
        {
            let r_share = unb64u(gv(rebuttal, "presentedShare")?)?;
            let ok = verify_share_sig_against_package(gv(rebuttal, "shareSig")?, &sid, accused, accuser, &r_share, pkg)
                && vss_check(&canonical_scalar(&r_share)?, commitments, accuser)?;
            return Ok(if ok {
                json!({"guilty": accuser, "reason": "accused produced a validly-signed, VSS-correct share for the recipient — the non-receipt/fabrication complaint is refuted"})
            } else {
                json!({"guilty": accused, "reason": "accused could not present a validly-signed, VSS-correct share on rebuttal"})
            });
        }
        Ok(
            json!({"guilty": accuser, "reason": "complaint carries no accused-signed share and the accused offered no rebuttal — inadmissible, cannot frame the accused"}),
        )
    };
    go().unwrap_or_else(|_| {
        let accuser = if complaint.is_object() { gv(complaint, "accuser").cloned().unwrap_or(Value::Null) } else { Value::Null };
        json!({"guilty": accuser, "reason": "malformed complaint — inadmissible"})
    })
}

pub(crate) fn sort_values(v: &[Value]) -> R<Vec<Value>> {
    let mut out = v.to_vec();
    if out.iter().all(Value::is_number) {
        out.sort_by(|a, b| a.as_f64().partial_cmp(&b.as_f64()).unwrap_or(std::cmp::Ordering::Equal));
    } else if out.iter().all(Value::is_string) {
        out.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    } else if out.len() > 1 {
        return Err("sorted: values are not comparable".into());
    }
    Ok(out)
}

fn matching_rebuttal<'a>(rebuttals: &'a [Value], c: &Value) -> R<Option<&'a Value>> {
    for r in rebuttals {
        if seq(gv(r, "accused")?, gv(c, "accused")?)
            && seq(gv(r, "accuser")?, gv(c, "accuser")?)
            && gv(r, "sessionId")? == gv(c, "sessionId")?
        {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// The qualified participants, ascending: those with a valid round-1 package from the run's own session (the plurality session, first seen on a
/// tie) not found guilty by [`dkg_resolve_blame`].
pub fn dkg_qualified_set(participants: &Value, complaints: &Value, round1_packages: &Value, rebuttals: &Value) -> R<Vec<Value>> {
    let none: Vec<Value> = Vec::new();
    let rebuttals = if rebuttals.is_null() { &none } else { arr(rebuttals)? };
    let pkgs = arr(round1_packages)?;
    let mut by_id: std::collections::HashMap<String, &Value> = std::collections::HashMap::new();
    for p in pkgs {
        by_id.insert(numkey(gv(p, "identifier")?), p);
    }
    let mut counts: Vec<(Value, usize)> = Vec::new();
    for p in pkgs {
        let s = gv(p, "sessionId")?;
        match counts.iter_mut().find(|(k, _)| k == s) {
            Some(e) => e.1 += 1,
            None => counts.push((s.clone(), 1)),
        }
    }
    let (mut run_session, mut best) = (json!(""), 0usize);
    for (i, (s, c)) in counts.iter().enumerate() {
        if i == 0 || *c > best {
            best = *c;
            run_session = s.clone();
        }
    }
    let mut qualified: Vec<Value> = Vec::new();
    for p in arr(participants)? {
        let Some(pkg) = by_id.get(&numkey(p)) else { continue };
        if gv(pkg, "sessionId")? != &run_session {
            continue;
        }
        let Ok(sid) = unb64u(gv(pkg, "sessionId")?) else { continue };
        if dkg_verify_round1(p, pkg, &bv(&sid)) && !qualified.iter().any(|q| seq(q, p)) {
            qualified.push(p.clone());
        }
    }
    for c in arr(complaints)? {
        let reb = matching_rebuttal(rebuttals, c)?;
        let res = dkg_resolve_blame(c, reb.unwrap_or(&NULL), round1_packages);
        let guilty = res["guilty"].clone();
        if seq(&guilty, gv(c, "accused")?) {
            qualified.retain(|q| !seq(q, &guilty));
        }
    }
    sort_values(&qualified)
}

// ---- echo broadcast agreement ----------------------------------------------------------------------------------------------------

fn digest(v: &Value) -> R<String> {
    hash_canonical_strict(v).ok_or_else(|| "canonicalize: outside the strict profile".to_string())
}

fn round1_digest(p: &Value) -> R<String> {
    let pok = gv(p, "proofOfKnowledge")?;
    let (mut o, mut pk) = (Map::new(), Map::new());
    for k in ["identifier", "sessionId", "coefficientCommitments"] {
        put(&mut o, p, k)?;
    }
    put(&mut pk, pok, "R")?;
    put(&mut pk, pok, "mu")?;
    o.insert("proofOfKnowledge".into(), Value::Object(pk));
    digest(&Value::Object(o))
}

fn complaint_digest(c: &Value) -> R<String> {
    let mut o = Map::new();
    for k in ["accused", "accuser", "sessionId", "revealedShare", "shareSig"] {
        put(&mut o, c, k)?;
    }
    digest(&Value::Object(o))
}

/// The digest of a participant's view of the ceremony (round-1 packages, complaints, the qualified set, the session), each list in a canonical
/// order. `args`: `round1Packages`, `complaints`, `qualified`, `sessionId` (bytes).
pub fn dkg_transcript_digest(args: &Value) -> R<String> {
    let mut r1: Vec<String> = arr(gv(args, "round1Packages")?)?.iter().map(round1_digest).collect::<R<_>>()?;
    r1.sort();
    let mut cs: Vec<String> = arr(gv(args, "complaints")?)?.iter().map(complaint_digest).collect::<R<_>>()?;
    cs.sort();
    let q = sort_values(arr(gv(args, "qualified")?)?)?;
    let sid = bytes_req(gv(args, "sessionId")?)?;
    digest(&json!({"sessionId": b64_encode(&sid), "round1": r1, "complaints": cs, "qualified": q}))
}

/// The echo a participant broadcasts: its transcript digest, bound to the session.
pub fn dkg_echo(args: &Value) -> R<Value> {
    let sid = bytes_req(gv(args, "sessionId")?)?;
    let identifier = args.get("identifier").ok_or("missing identifier")?;
    Ok(json!({"identifier": identifier, "sessionId": b64_encode(&sid), "transcriptDigest": dkg_transcript_digest(args)?}))
}

/// Agreement across the qualified set: one echo each, all for this session, all carrying the same digest. `{agreed: true, digest}` or
/// `{agreed: false, reason}`. Total.
pub fn dkg_check_echoes(qualified: &Value, echoes: &Value, session_id: &Value) -> Value {
    let go = || -> R<Value> {
        let sid_b64 = b64_encode(&bytes_req(session_id)?);
        let mut q_list: Vec<Value> = Vec::new();
        if !qualified.is_null() {
            for x in arr(qualified)? {
                if !q_list.iter().any(|y| seq(x, y)) {
                    q_list.push(x.clone());
                }
            }
        }
        let mut by_id: Vec<(Value, &Value)> = Vec::new();
        for e in arr(echoes)? {
            let ident = gv(e, "identifier")?;
            if !q_list.iter().any(|q| seq(ident, q)) {
                continue;
            }
            if gv(e, "sessionId")? != &json!(sid_b64) {
                return Ok(json!({"agreed": false, "reason": format!("echo from {} is bound to a different session", js_string(ident))}));
            }
            if by_id.iter().any(|(k, _)| seq(ident, k)) {
                return Ok(json!({"agreed": false, "reason": format!("duplicate echo from qualified participant {}", js_string(ident))}));
            }
            by_id.push((ident.clone(), e));
        }
        let mut agreed: Option<Value> = None;
        for j in &q_list {
            let Some((_, e)) = by_id.iter().find(|(k, _)| seq(k, j)) else {
                return Ok(json!({"agreed": false, "reason": format!("missing echo from qualified participant {}", js_string(j))}));
            };
            let d = gv(e, "transcriptDigest")?;
            match &agreed {
                None => agreed = Some(d.clone()),
                Some(a) if !seq(d, a) => {
                    return Ok(
                        json!({"agreed": false, "reason": format!("qualified participant {} echoed a DIFFERENT transcript (equivocation detected)", js_string(j))}),
                    )
                }
                _ => {}
            }
        }
        Ok(match agreed {
            None => json!({"agreed": false, "reason": "no qualified echoes to agree on"}),
            Some(d) => json!({"agreed": true, "digest": d}),
        })
    };
    go().unwrap_or_else(|_| json!({"agreed": false, "reason": "malformed echoes"}))
}

// ---- finalize ------------------------------------------------------------------------------------------------------------------

/// Combine the received shares into this participant's key package: the signing share, the group public key and every qualified verifying
/// share, with the echo-broadcast agreement checked when given (`agreement`: `{echoes, complaints}`). `Err` on any inconsistency (a bad dealer
/// share, a missing share, a diverging transcript). `qualified` null means every package's participant.
pub fn dkg_finalize(
    my_identifier: &Value,
    state: &DkgState,
    received_shares: &Value,
    all_commitments: &Value,
    qualified: &Value,
    agreement: &Value,
) -> R<Value> {
    if !seq(&state.id_value(), my_identifier) {
        return Err("dkgFinalize: myState.identifier != myIdentifier".into());
    }
    let pkgs = arr(all_commitments)?;
    let ids: Vec<Value> = pkgs.iter().map(|p| gv(p, "identifier").cloned()).collect::<R<_>>()?;
    if !distinct_ids(&ids) {
        return Err("dkgFinalize: duplicate identifiers in commitments".into());
    }
    if !ids.iter().any(|i| seq(i, my_identifier)) {
        return Err("dkgFinalize: my own package is missing from allCommitments".into());
    }
    let sid_b64 = json!(b64_encode(&state.session_id));
    for p in pkgs {
        if gv(p, "sessionId")? != &sid_b64 {
            return Err(format!(
                "dkgFinalize: participant {} round-1 package is from a different session",
                js_string(gv(p, "identifier")?)
            ));
        }
    }
    let source: Vec<Value> = if qualified.is_null() { ids.clone() } else { arr(qualified)?.clone() };
    let qset: Vec<Value> = source.into_iter().filter(|x| ids.iter().any(|i| seq(x, i))).collect();
    let in_q = |x: &Value| qset.iter().any(|q| seq(x, q));
    let mut distinct: Vec<Value> = Vec::new();
    for x in &qset {
        if !distinct.iter().any(|d| seq(x, d)) {
            distinct.push(x.clone());
        }
    }
    if !in_q(my_identifier) {
        return Err("dkgFinalize: myIdentifier is not in the qualified set".into());
    }
    let t = state.t as usize;
    if distinct.len() < t {
        return Err(format!("dkgFinalize: qualified set ({}) is smaller than the threshold t={t}", distinct.len()));
    }
    for p in pkgs {
        if !in_q(gv(p, "identifier")?) {
            continue;
        }
        if arr(gv(p, "coefficientCommitments")?)?.len() != t {
            return Err(format!(
                "dkgFinalize: participant {} committed to the wrong number of coefficients, expected t={t}",
                js_string(gv(p, "identifier")?)
            ));
        }
    }
    if agreement.as_object().is_some_and(|m| m.contains_key("echoes")) {
        let qsorted = sort_values(&distinct)?;
        let sid = bv(&state.session_id);
        let check = dkg_check_echoes(&Value::Array(qsorted.clone()), &agreement["echoes"], &sid);
        if check["agreed"] != json!(true) {
            return Err(format!("dkgFinalize: echo-broadcast agreement failed — {}", js_string(&check["reason"])));
        }
        let comp = agreement.get("complaints").filter(|c| !c.is_null()).cloned().unwrap_or_else(|| json!([]));
        let mine = dkg_transcript_digest(&json!({"round1Packages": pkgs, "complaints": comp, "qualified": qsorted, "sessionId": sid}))?;
        if check["digest"] != json!(mine) {
            return Err(
                "dkgFinalize: echo-broadcast agreement failed — my transcript view diverges from the agreed echo digest (equivocation)"
                    .into(),
            );
        }
    }
    let mut recv: Vec<(&Value, Vec<u8>)> = Vec::new();
    for r in arr(received_shares)? {
        let frm = gv(r, "from")?;
        if seq(frm, my_identifier) || !in_q(frm) {
            continue;
        }
        if gv(r, "sessionId")? != &sid_b64 {
            return Err(format!("dkgFinalize: received share from {} is from a different session", js_string(frm)));
        }
        if recv.iter().any(|(k, _)| seq(frm, k)) {
            return Err(format!("dkgFinalize: duplicate received share from {}", js_string(frm)));
        }
        recv.push((frm, bytes_req(gv(r, "share")?)?));
    }
    for j in &qset {
        if !seq(j, my_identifier) && !recv.iter().any(|(k, _)| seq(j, k)) {
            return Err(format!("dkgFinalize: missing received share from qualified participant {}", js_string(j)));
        }
    }
    let mut signing = eval_poly(&state.coeffs()?, &big(my_identifier)?);
    for (_, share) in &recv {
        signing += wide(share)?;
    }
    let mut group_points: Vec<EdwardsPoint> = Vec::new();
    for k in 0..t {
        let mut acc = EdwardsPoint::identity();
        for p in pkgs {
            if in_q(gv(p, "identifier")?) {
                acc += pt_of(&gv(p, "coefficientCommitments")?[k])?;
            }
        }
        group_points.push(acc);
    }
    let group_pk = enc(&group_points[0]);
    let mut verifying: Vec<(Value, EdwardsPoint)> = Vec::new();
    for j in &qset {
        let x = big(j)?;
        let (mut acc, mut xk) = (EdwardsPoint::identity(), Scalar::ONE);
        for phi in &group_points {
            acc += phi * xk;
            xk *= x;
        }
        verifying.push((j.clone(), acc));
    }
    let mine = verifying.iter().find(|(i, _)| seq(i, my_identifier));
    let consistent = mine.is_some_and(|(_, pk)| {
        // the share's public key must be a safe point and equal base * share
        safe_point(&enc(pk)).is_ok_and(|safe| safe == base(&signing))
    });
    if !consistent {
        return Err("dkgFinalize: signing share is inconsistent with the group verifying share (bad dealer share)".into());
    }
    Ok(json!({
        "identifier": my_identifier, "signingShare": bv(&signing.to_bytes()), "groupPublicKey": bv(&group_pk),
        "verifyingShare": bv(&enc(&base(&signing))),
        "publicKeyPackage": {
            "groupPublicKey": bv(&group_pk),
            "groupCommitment": group_points.iter().map(|p| bv(&enc(p))).collect::<Vec<_>>(),
            "verifyingShares": verifying.iter().map(|(i, p)| json!({"identifier": i, "publicKey": bv(&enc(p))})).collect::<Vec<_>>(),
        },
    }))
}

// ---- in-process simulation -----------------------------------------------------------------------------------------------------

/// Run a whole ceremony in process (tests, dealerless key generation on one host): every participant, every message, the blame round and the
/// echo check. `opts`: `identifiers`, `coefficientsByParticipant`, `sessionId`, `cheaters` (identifiers whose shares are corrupted),
/// `equivocateEchoFor`.
pub fn frost_dkg_simulate(t: &Value, n: &Value, opts: Option<&Value>, random: &RandomBytes) -> R<Value> {
    let (tf, nf) = match (isint(t), isint(n)) {
        (Some(a), Some(b)) if a >= 1.0 && b >= a => (a, b),
        _ => return Err(format!("frostDkgSimulate: need 1 <= t <= n (got t={}, n={})", js_string(t), js_string(n))),
    };
    let none = Value::Null;
    let opts = opts.unwrap_or(&none);
    let ids_v: Vec<Value> = match gv(opts, "identifiers")?.as_array() {
        Some(l) => l.clone(),
        None if gv(opts, "identifiers")?.is_null() => (1..=nf as i64).map(|i| json!(i)).collect(),
        None => return Err("identifiers is not iterable".into()),
    };
    if ids_v.len() as f64 != nf {
        return Err("frostDkgSimulate: identifiers.length must equal n".into());
    }
    if !distinct_ids(&ids_v) {
        return Err("frostDkgSimulate: identifiers must be distinct".into());
    }
    if ids_v.iter().any(|x| !isint(x).is_some_and(|f| f > 0.0)) {
        return Err("frostDkgSimulate: identifiers must be positive integers".into());
    }
    let ids: Vec<i64> = ids_v.iter().map(id_i64).collect();
    let sid = match gv(opts, "sessionId")? {
        s if s.is_null() => random(32),
        s => bytes_req(s)?,
    };
    let sid_v = bv(&sid);
    let cheaters: Vec<Value> = gv(opts, "cheaters")?.as_array().cloned().unwrap_or_default();
    let by_participant = gv(opts, "coefficientsByParticipant")?.as_array();
    let (t_v, n_v) = (json!(tf as i64), json!(nf as i64));
    let mut states: Vec<DkgState> = Vec::new();
    for (idx, i) in ids.iter().enumerate() {
        let coeffs = by_participant.and_then(|l| l.get(idx)).cloned().unwrap_or(Value::Null);
        states.push(dkg_round1(&json!(i), &t_v, &n_v, &sid_v, Some(&json!({"coefficients": coeffs})), random)?.1);
    }
    let round1: Vec<Value> = states.iter().map(|s| s.package.clone()).collect();
    let round1_v = Value::Array(round1.clone());
    for pkg in &round1 {
        if !dkg_verify_round1(&pkg["identifier"], pkg, &sid_v) {
            return Err(format!("frostDkgSimulate: PoP verification failed for participant {}", js_string(&pkg["identifier"])));
        }
    }
    let mut inbox: std::collections::HashMap<i64, Vec<Value>> = ids.iter().map(|i| (*i, Vec::new())).collect();
    let mut complaints: Vec<Value> = Vec::new();
    for st in &states {
        for outgoing in dkg_round2(st, &round1_v)? {
            let mut share = bytes_req(&outgoing["share"])?;
            let mut share_sig = outgoing["sig"].clone();
            if cheaters.iter().any(|c| seq(c, &outgoing["from"])) {
                share[0] ^= 1;
                share_sig = json!(dkg_sign_share(st, &outgoing["to"], &bv(&share))?);
            }
            let sender = round1.iter().find(|p| seq(&p["identifier"], &outgoing["from"])).ok_or("sender package")?;
            let received = json!({"from": outgoing["from"], "share": bv(&share), "sig": share_sig});
            if dkg_verify_share(&received, sender, &outgoing["to"], &sid_v) {
                inbox
                    .get_mut(&id_i64(&outgoing["to"]))
                    .ok_or("recipient")?
                    .push(json!({"from": outgoing["from"], "sessionId": outgoing["sessionId"], "share": bv(&share), "sig": share_sig}));
            } else {
                complaints.push(dkg_file_complaint(
                    &json!({"accused": outgoing["from"], "accuser": outgoing["to"], "receivedShare": bv(&share), "shareSig": share_sig,
                    "senderCommitments": sender["coefficientCommitments"], "sessionId": sid_v}),
                )?);
            }
        }
    }
    let mut rebuttals: Vec<Value> = Vec::new();
    for c in &complaints {
        let st = states.iter().find(|s| seq(&s.id_value(), &c["accused"])).ok_or("accused state")?;
        rebuttals.push(dkg_rebut(&c["accused"], c, st)?);
    }
    let (complaints_v, rebuttals_v) = (Value::Array(complaints.clone()), Value::Array(rebuttals.clone()));
    let participants = Value::Array(ids.iter().map(|i| json!(i)).collect());
    let qualified = dkg_qualified_set(&participants, &complaints_v, &round1_v, &rebuttals_v)?;
    if (qualified.len() as f64) < tf {
        return Err(format!("frostDkgSimulate: only {} qualified participants (< t={}) after the blame round", qualified.len(), tf));
    }
    let equivocator = gv(opts, "equivocateEchoFor")?;
    let mut echoes: Vec<Value> = Vec::new();
    for i in &qualified {
        let view: Vec<Value> = if !equivocator.is_null() && seq(i, equivocator) {
            qualified.iter().take(qualified.len() - 1).cloned().collect()
        } else {
            qualified.clone()
        };
        echoes.push(dkg_echo(
            &json!({"identifier": i, "round1Packages": round1, "complaints": complaints, "qualified": view, "sessionId": sid_v}),
        )?);
    }
    let qualified_v = Value::Array(qualified.clone());
    let agreement = json!({"echoes": echoes, "complaints": complaints});
    let mut key_packages: Vec<Value> = Vec::new();
    for st in &states {
        if qualified.iter().any(|q| seq(q, &st.id_value())) {
            let received = Value::Array(inbox[&st.identifier].clone());
            key_packages.push(dkg_finalize(&st.id_value(), st, &received, &round1_v, &qualified_v, &agreement)?);
        }
    }
    let group_pk = key_packages.first().ok_or("no key packages")?["groupPublicKey"].clone();
    if key_packages.iter().any(|k| k["groupPublicKey"] != group_pk) {
        return Err("frostDkgSimulate: participants disagree on the group public key".into());
    }
    Ok(json!({
        "groupPublicKey": group_pk,
        "participantShares": key_packages.iter().map(|k| json!({"identifier": k["identifier"], "share": k["signingShare"], "publicKey": k["verifyingShare"]})).collect::<Vec<_>>(),
        "groupCommitment": key_packages[0]["publicKeyPackage"]["groupCommitment"],
        "keyPackages": key_packages, "round1Packages": round1, "qualified": qualified, "complaints": complaints, "rebuttals": rebuttals,
        "echoes": echoes, "sessionId": sid_v,
    }))
}
