//! SCITT transparency receipts for Proof-Carrying Authority: RFC 9943 Signed Statements and RFC 9942 COSE Receipts over an
//! RFC 9162 SHA-256 Merkle log, with a strict deterministic CBOR codec (RFC 8949 4.2.1) sufficient for COSE_Sign1, an in-memory
//! reference transparency service and a durable one over a pluggable [`ScittLogStore`].
//!
//! Keys are JSON objects: signing keys `{alg: "EdDSA", seed}` / `{alg: "ES256", d, x, y}`, verification keys `{alg: "EdDSA", pub}` /
//! `{alg: "ES256", x, y}` (base64url members). Everything fails closed.
//!
//! The file-backed log store is [`crate::scitt_file::FileScittLogStore`].
//! Stricter than the reference: the CBOR decoder refuses nesting deeper than [`MAX_CBOR_DEPTH`], Ed25519 verification is strict.
use crate::{b64_encode, canonicalize_strict, decode_b64u_strict};
use serde_json::{json, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const COSE_SIGN1_TAG: u64 = 18;
pub const HDR_ALG: i64 = 1;
pub const HDR_CONTENT_TYPE: i64 = 3;
pub const HDR_CWT_CLAIMS: i64 = 15;
pub const CWT_ISS: i64 = 1;
pub const CWT_SUB: i64 = 2;
pub const HDR_VDS: i64 = 395;
pub const HDR_VDS_PROOFS: i64 = 396;
pub const VDS_RFC9162_SHA256: i64 = 1;
pub const PROOF_TYPE_INCLUSION: i64 = -1;
pub const DEFAULT_CONTENT_TYPE: &str = "application/pca+json";
pub const MAX_APPEND_ATTEMPTS: usize = 16;
pub const MAX_CBOR_DEPTH: usize = 256;

const MAX_SAFE: u64 = 9_007_199_254_740_991;
const MAX_SAFE_F: f64 = 9_007_199_254_740_991.0;
const SAFE_INT_ERR: &str = "cbor: only safe-integer numbers are supported";
const P256_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9,
    0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];
/// floor(n / 2) of the P-256 group order (the low-S bound).
const P256_HALF_N: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC,
    0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

// ---- RFC 9162 Merkle tree -------------------------------------------------------------------------------------------

const L0: &[u8] = &[0];
const L1: &[u8] = &[1];

fn h256(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

pub fn empty_root() -> Vec<u8> {
    h256(&[])
}

/// SHA-256(0x00 || entry).
pub fn leaf_hash(entry: &[u8]) -> Vec<u8> {
    h256(&[L0, entry])
}

/// SHA-256(0x01 || left || right).
pub fn node_hash(left: &[u8], right: &[u8]) -> Vec<u8> {
    h256(&[L1, left, right])
}

fn split_point(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// MTH over already-hashed leaves (RFC 9162 2.1.1).
pub fn tree_hash(leaves: &[Vec<u8>]) -> Vec<u8> {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0].clone(),
        n => {
            let k = split_point(n);
            node_hash(&tree_hash(&leaves[..k]), &tree_hash(&leaves[k..]))
        }
    }
}

/// `Number.isSafeInteger` as an integer.
fn safe_int(v: f64) -> Option<i64> {
    (v.is_finite() && v.fract() == 0.0 && v.abs() <= MAX_SAFE_F).then_some(v as i64)
}

fn is_integer(v: f64) -> bool {
    v.is_finite() && v.fract() == 0.0
}

fn incl(leaves: &[Vec<u8>], i: usize) -> Vec<Vec<u8>> {
    let n = leaves.len();
    if n == 1 {
        return Vec::new();
    }
    let k = split_point(n);
    if i < k {
        let mut p = incl(&leaves[..k], i);
        p.push(tree_hash(&leaves[k..]));
        p
    } else {
        let mut p = incl(&leaves[k..], i - k);
        p.push(tree_hash(&leaves[..k]));
        p
    }
}

/// Inclusion path for leaf `index` (RFC 9162 2.1.3.1), bottom-up.
pub fn inclusion_path(leaves: &[Vec<u8>], index: f64) -> Result<Vec<Vec<u8>>, String> {
    let n = leaves.len();
    let i = safe_int(index).filter(|i| *i >= 0 && (*i as usize) < n).ok_or("rfc9162: leaf index out of range")?;
    Ok(incl(leaves, i as usize))
}

/// Recompute the root from a leaf hash and its path (RFC 9162 2.1.3.2); `None` for an invalid (index, size, path).
pub fn root_from_inclusion_path(leaf: &[u8], index: f64, size: f64, path: &[Vec<u8>]) -> Option<Vec<u8>> {
    let (i, n) = (safe_int(index)?, safe_int(size)?);
    if i < 0 || (index == 0.0 && index.is_sign_negative()) || n < 1 || i >= n {
        return None;
    }
    if leaf.len() != 32 || path.iter().any(|p| p.len() != 32) {
        return None;
    }
    let (mut fnode, mut sn, mut r) = (i as u64, (n - 1) as u64, leaf.to_vec());
    for p in path {
        if sn == 0 {
            return None;
        }
        if fnode & 1 == 1 || fnode == sn {
            r = node_hash(p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        sn >>= 1;
    }
    (sn == 0).then_some(r)
}

pub fn verify_inclusion_path(leaf: &[u8], index: f64, size: f64, path: &[Vec<u8>], root: &[u8]) -> bool {
    root_from_inclusion_path(leaf, index, size, path).is_some_and(|c| c == root)
}

fn subproof(m: usize, d: &[Vec<u8>], complete: bool) -> Vec<Vec<u8>> {
    let n = d.len();
    if m == n {
        return if complete { Vec::new() } else { vec![tree_hash(d)] };
    }
    let k = split_point(n);
    if m <= k {
        let mut p = subproof(m, &d[..k], complete);
        p.push(tree_hash(&d[k..]));
        p
    } else {
        let mut p = subproof(m - k, &d[k..], false);
        p.push(tree_hash(&d[..k]));
        p
    }
}

/// Consistency proof between the first `m` leaves and all of `leaves` (RFC 9162 2.1.4.1).
pub fn consistency_path(leaves: &[Vec<u8>], m: f64) -> Result<Vec<Vec<u8>>, String> {
    let i = safe_int(m).filter(|i| *i >= 1 && (*i as usize) <= leaves.len()).ok_or("rfc9162: consistency size out of range")?;
    Ok(subproof(i as usize, leaves, true))
}

/// ECMAScript ToInt32 of a non-negative safe integer (the reference tests `first & (first - 1)` with a 32-bit AND).
fn i32_of(x: u64) -> i32 {
    (x & 0xFFFF_FFFF) as u32 as i32
}

/// RFC 9162 2.1.4.2. A proof from an empty tree is rejected.
pub fn verify_consistency_path(first: f64, second: f64, first_root: &[u8], second_root: &[u8], path: &[Vec<u8>]) -> bool {
    let (Some(a), Some(b)) = (safe_int(first), safe_int(second)) else { return false };
    if a < 1 || b < a {
        return false;
    }
    if first_root.len() != 32 || second_root.len() != 32 || path.iter().any(|p| p.len() != 32) {
        return false;
    }
    if a == b {
        return path.is_empty() && first_root == second_root;
    }
    if path.is_empty() {
        return false;
    }
    let mut nodes: Vec<Vec<u8>> = path.to_vec();
    let a = a as u64;
    if i32_of(a) & i32_of(a - 1) == 0 {
        nodes.insert(0, first_root.to_vec());
    }
    let (mut fnode, mut sn) = (a - 1, (b - 1) as u64);
    while fnode & 1 == 1 {
        fnode >>= 1;
        sn >>= 1;
    }
    let (mut fr, mut sr) = (nodes[0].clone(), nodes[0].clone());
    for c in &nodes[1..] {
        if sn == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fnode >>= 1;
        sn >>= 1;
    }
    sn == 0 && fr == first_root && sr == second_root
}

// ---- deterministic CBOR ---------------------------------------------------------------------------------------------

/// A CBOR value of the supported profile. Map keys are `Int` or `Text`; a decoded map lists its entries in wire order.
#[derive(Debug, Clone, PartialEq)]
pub enum Cbor {
    Int(i64),
    Text(String),
    Bytes(Vec<u8>),
    Bool(bool),
    Null,
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Tag(u64, Box<Cbor>),
}

/// A JSON number as a CBOR integer (safe integers only; negative zero and floats are refused).
pub fn cbor_int_from_number(n: &Number) -> Result<Cbor, String> {
    if let Some(i) = n.as_i64() {
        return if i.unsigned_abs() <= MAX_SAFE { Ok(Cbor::Int(i)) } else { Err(SAFE_INT_ERR.into()) };
    }
    if n.as_u64().is_some() {
        return Err(SAFE_INT_ERR.into());
    }
    match n.as_f64() {
        Some(f) if f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE_F && !(f == 0.0 && f.is_sign_negative()) => Ok(Cbor::Int(f as i64)),
        _ => Err(SAFE_INT_ERR.into()),
    }
}

/// A plain JSON scalar / array as a CBOR value (objects have no CBOR form here: use [`Cbor::Map`]).
pub fn cbor_from_json(v: &Value) -> Result<Cbor, String> {
    match v {
        Value::Null => Ok(Cbor::Null),
        Value::Bool(b) => Ok(Cbor::Bool(*b)),
        Value::Number(n) => cbor_int_from_number(n),
        Value::String(s) => Ok(Cbor::Text(s.clone())),
        Value::Array(a) => Ok(Cbor::Array(a.iter().map(cbor_from_json).collect::<Result<Vec<_>, _>>()?)),
        Value::Object(_) => Err("cbor: unsupported value".into()),
    }
}

fn head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let mt = major << 5;
    if arg < 24 {
        out.push(mt | arg as u8);
    } else if arg < 0x100 {
        out.extend([mt | 24, arg as u8]);
    } else if arg < 0x1_0000 {
        out.push(mt | 25);
        out.extend((arg as u16).to_be_bytes());
    } else if arg < 0x1_0000_0000 {
        out.push(mt | 26);
        out.extend((arg as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend(arg.to_be_bytes());
    }
}

fn encode_int(i: i64, out: &mut Vec<u8>) -> Result<(), String> {
    if i.unsigned_abs() > MAX_SAFE {
        return Err(SAFE_INT_ERR.into());
    }
    if i >= 0 {
        head(0, i as u64, out);
    } else {
        head(1, (-1 - i) as u64, out);
    }
    Ok(())
}

fn encode_into(v: &Cbor, out: &mut Vec<u8>) -> Result<(), String> {
    match v {
        Cbor::Null => out.push(0xf6),
        Cbor::Bool(false) => out.push(0xf4),
        Cbor::Bool(true) => out.push(0xf5),
        Cbor::Int(i) => encode_int(*i, out)?,
        Cbor::Text(s) => {
            head(3, s.len() as u64, out);
            out.extend(s.as_bytes());
        }
        Cbor::Bytes(b) => {
            head(2, b.len() as u64, out);
            out.extend(b);
        }
        Cbor::Array(a) => {
            head(4, a.len() as u64, out);
            for x in a {
                encode_into(x, out)?;
            }
        }
        Cbor::Map(m) => {
            let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(m.len());
            for (k, val) in m {
                let mut kb = Vec::new();
                match k {
                    Cbor::Int(i) => encode_int(*i, &mut kb).map_err(|_| "cbor: bad integer map key".to_string())?,
                    Cbor::Text(_) => encode_into(k, &mut kb)?,
                    _ => return Err("cbor: bad map key".into()),
                }
                let mut vb = Vec::new();
                encode_into(val, &mut vb)?;
                entries.push((kb, vb));
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            if entries.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err("cbor: duplicate map key".into());
            }
            head(5, m.len() as u64, out);
            for (k, val) in entries {
                out.extend(k);
                out.extend(val);
            }
        }
        Cbor::Tag(t, inner) => {
            if *t > MAX_SAFE {
                return Err("cbor: bad tag".into());
            }
            head(6, *t, out);
            encode_into(inner, out)?;
        }
    }
    Ok(())
}

/// Deterministically encode a CBOR value; errs on anything outside the supported profile.
pub fn encode(v: &Cbor) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    encode_into(v, &mut out)?;
    Ok(out)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

const EOF: &str = "cbor: unexpected end of input";

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, String> {
        let b = *self.buf.get(self.pos).ok_or(EOF)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: u64) -> Result<&'a [u8], String> {
        let n = usize::try_from(n).map_err(|_| EOF.to_string())?;
        if n > self.buf.len() - self.pos {
            return Err(EOF.into());
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn uint(&mut self, n: usize) -> Result<u64, String> {
        let mut v: u64 = 0;
        for _ in 0..n {
            v = (v << 8) | self.byte()? as u64;
        }
        if v > MAX_SAFE {
            return Err("cbor: integer out of safe range".into());
        }
        Ok(v)
    }

    /// (major, argument), enforcing the minimal-length argument encoding.
    fn head(&mut self) -> Result<(u8, u64), String> {
        let ib = self.byte()?;
        let (major, info) = (ib >> 5, ib & 0x1f);
        if major == 7 && info >= 24 {
            return Err("cbor: unsupported simple/float value".into());
        }
        if info < 24 {
            return Ok((major, info as u64));
        }
        let (n, floor) = match info {
            24 => (1, 24),
            25 => (2, 0x100),
            26 => (4, 0x1_0000),
            27 => (8, 0x1_0000_0000u64),
            _ => return Err("cbor: unsupported additional information (indefinite/reserved)".into()),
        };
        let arg = self.uint(n)?;
        if arg < floor {
            return Err("cbor: non-minimal integer".into());
        }
        Ok((major, arg))
    }

    fn value(&mut self, depth: usize) -> Result<Cbor, String> {
        if depth > MAX_CBOR_DEPTH {
            return Err("cbor: nesting too deep".into());
        }
        let (major, arg) = self.head()?;
        match major {
            0 => Ok(Cbor::Int(arg as i64)),
            1 => {
                if arg + 1 > MAX_SAFE {
                    return Err("cbor: integer out of safe range".into());
                }
                Ok(Cbor::Int(-1 - arg as i64))
            }
            2 => Ok(Cbor::Bytes(self.take(arg)?.to_vec())),
            3 => String::from_utf8(self.take(arg)?.to_vec()).map(Cbor::Text).map_err(|_| "The encoded data was not valid for encoding utf-8".to_string()),
            4 => {
                let mut out = Vec::new();
                for _ in 0..arg {
                    out.push(self.value(depth + 1)?);
                }
                Ok(Cbor::Array(out))
            }
            5 => {
                let mut out: Vec<(Cbor, Cbor)> = Vec::new();
                let buf: &'a [u8] = self.buf;
                let mut prev: Option<&'a [u8]> = None;
                for _ in 0..arg {
                    let start = self.pos;
                    let key = self.value(depth + 1)?;
                    if !matches!(key, Cbor::Int(_) | Cbor::Text(_)) {
                        return Err("cbor: map key must be int or text".into());
                    }
                    let kb = &buf[start..self.pos];
                    if prev.is_some_and(|p| p >= kb) {
                        return Err("cbor: map keys not canonically ordered / duplicate".into());
                    }
                    prev = Some(kb);
                    let val = self.value(depth + 1)?;
                    out.push((key, val));
                }
                Ok(Cbor::Map(out))
            }
            6 => Ok(Cbor::Tag(arg, Box::new(self.value(depth + 1)?))),
            7 => match arg {
                20 => Ok(Cbor::Bool(false)),
                21 => Ok(Cbor::Bool(true)),
                22 => Ok(Cbor::Null),
                _ => Err("cbor: unsupported simple/float value".into()),
            },
            _ => Err("cbor: unsupported major type".into()),
        }
    }
}

/// Strictly decode ONE canonical CBOR value; the whole buffer must be consumed.
pub fn decode(data: &[u8]) -> Result<Cbor, String> {
    let mut r = Reader { buf: data, pos: 0 };
    let v = r.value(0)?;
    if r.pos != data.len() {
        return Err("cbor: trailing bytes".into());
    }
    Ok(v)
}

fn map_get(m: &Cbor, key: i64) -> Option<&Cbor> {
    match m {
        Cbor::Map(es) => es.iter().find(|(k, _)| *k == Cbor::Int(key)).map(|(_, v)| v),
        _ => None,
    }
}

fn int(k: i64) -> Cbor {
    Cbor::Int(k)
}

fn text(s: &str) -> Cbor {
    Cbor::Text(s.to_string())
}

// ---- signature suites (EdDSA, ES256) --------------------------------------------------------------------------------

fn alg_label(alg: &str) -> Option<i64> {
    match alg {
        "EdDSA" => Some(-8),
        "ES256" => Some(-7),
        _ => None,
    }
}

fn alg_for_label(label: i64) -> Option<&'static str> {
    match label {
        -8 => Some("EdDSA"),
        -7 => Some("ES256"),
        _ => None,
    }
}

fn member(o: &Value, k: &str, len: usize) -> Option<Vec<u8>> {
    decode_b64u_strict(o.get(k)?.as_str()?, Some(len))
}

/// A 64-byte IEEE-P1363 signature with 0 < r < n and 0 < s <= n/2 (low-S).
fn is_canonical_es256(sig: &[u8]) -> bool {
    if sig.len() != 64 {
        return false;
    }
    let (r, s) = (&sig[..32], &sig[32..]);
    r.iter().any(|b| *b != 0) && r < &P256_N[..] && s.iter().any(|b| *b != 0) && s <= &P256_HALF_N[..]
}

fn sign_bytes(alg: &str, key: &Value, msg: &[u8]) -> Result<Vec<u8>, String> {
    match alg {
        "EdDSA" => {
            use ed25519_dalek::Signer;
            let seed: [u8; 32] =
                member(key, "seed", 32).ok_or("scitt: not an Ed25519 private key")?.try_into().map_err(|_| "scitt: not an Ed25519 private key")?;
            Ok(ed25519_dalek::SigningKey::from_bytes(&seed).sign(msg).to_bytes().to_vec())
        }
        "ES256" => {
            use p256::ecdsa::signature::Signer;
            let d = member(key, "d", 32).ok_or("scitt: not a P-256 private key")?;
            let sk = p256::ecdsa::SigningKey::from_slice(&d).map_err(|_| "scitt: not a P-256 private key".to_string())?;
            let sig: p256::ecdsa::Signature = sk.sign(msg);
            // low-S: a statement has exactly one valid signature form
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(sig.to_bytes().to_vec())
        }
        _ => Err("cbor: unsupported value".into()),
    }
}

fn verify_bytes(alg: &str, key: &Value, msg: &[u8], sig: &[u8], allow_high_s: bool) -> bool {
    match alg {
        "EdDSA" => {
            let (Some(pk), Ok(sg)) = (member(key, "pub", 32), <[u8; 64]>::try_from(sig)) else { return false };
            let Ok(pk) = <[u8; 32]>::try_from(pk) else { return false };
            let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else { return false };
            vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sg)).is_ok()
        }
        "ES256" => {
            use p256::ecdsa::signature::Verifier;
            // ECDSA is malleable: a high-S variant would be a second, distinct Merkle leaf for the same statement.
            if sig.len() != 64 || (!allow_high_s && !is_canonical_es256(sig)) {
                return false;
            }
            let (Some(x), Some(y)) = (member(key, "x", 32), member(key, "y", 32)) else { return false };
            let mut point = vec![4u8];
            point.extend(x);
            point.extend(y);
            let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point) else { return false };
            let Ok(s) = p256::ecdsa::Signature::from_slice(sig) else { return false };
            let s = s.normalize_s().unwrap_or(s);
            vk.verify(msg, &s).is_ok()
        }
        _ => false,
    }
}

/// The COSE_Sign1 Sig_structure (RFC 9052 4.4), external_aad empty.
fn sig_structure(protected_bytes: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    encode(&Cbor::Array(vec![text("Signature1"), Cbor::Bytes(protected_bytes.to_vec()), Cbor::Bytes(Vec::new()), Cbor::Bytes(payload.to_vec())]))
}

// ---- Signed Statements ----------------------------------------------------------------------------------------------

fn tagged_sign1(protected: Vec<u8>, unprotected: Cbor, payload: Option<Vec<u8>>, sig: Vec<u8>) -> Result<Vec<u8>, String> {
    encode(&Cbor::Tag(
        COSE_SIGN1_TAG,
        Box::new(Cbor::Array(vec![Cbor::Bytes(protected), unprotected, payload.map_or(Cbor::Null, Cbor::Bytes), Cbor::Bytes(sig)])),
    ))
}

/// Sign a PCActn / verdict as a COSE Signed Statement (COSE_Sign1) whose payload is the strict canonical JSON of `payload`.
/// `opts` = `{alg, key, issuer, subject?, contentType?}`.
pub fn sign_statement(payload: &Value, opts: &Value) -> Result<Vec<u8>, String> {
    let alg = opts.get("alg").and_then(Value::as_str).ok_or("cbor: unsupported value")?;
    let label = alg_label(alg).ok_or("cbor: unsupported value")?;
    let key = opts.get("key").ok_or("scitt: key is required")?;
    let issuer = opts.get("issuer").and_then(Value::as_str).ok_or("cbor: unsupported value")?;
    let ctype = match opts.get("contentType") {
        None => DEFAULT_CONTENT_TYPE,
        Some(Value::String(s)) => s.as_str(),
        Some(_) => return Err("cbor: unsupported value".into()),
    };
    let mut claims = vec![(int(CWT_ISS), text(issuer))];
    if let Some(s) = opts.get("subject") {
        claims.push((int(CWT_SUB), cbor_from_json(s)?));
    }
    let prot = Cbor::Map(vec![(int(HDR_ALG), int(label)), (int(HDR_CONTENT_TYPE), text(ctype)), (int(HDR_CWT_CLAIMS), Cbor::Map(claims))]);
    let protected_bytes = encode(&prot)?;
    let payload_bytes = canonicalize_strict(payload)?.into_bytes();
    let sig = sign_bytes(alg, key, &sig_structure(&protected_bytes, &payload_bytes)?)?;
    tagged_sign1(protected_bytes, Cbor::Map(Vec::new()), Some(payload_bytes), sig)
}

/// A decoded, structurally validated COSE_Sign1.
#[derive(Debug, Clone)]
pub struct CoseSign1 {
    pub protected_bytes: Vec<u8>,
    /// A `Cbor::Map`.
    pub protected_map: Cbor,
    /// A `Cbor::Map`.
    pub unprotected: Cbor,
    /// `None` when detached.
    pub payload: Option<Vec<u8>>,
    pub signature: Vec<u8>,
}

/// Decode and structurally validate a COSE_Sign1 (tag 18); errs on any deviation.
pub fn decode_cose_sign1(data: &[u8]) -> Result<CoseSign1, String> {
    let Cbor::Tag(COSE_SIGN1_TAG, inner) = decode(data)? else { return Err("cose: not a COSE_Sign1 (tag 18)".into()) };
    let Cbor::Array(arr) = *inner else { return Err("cose: malformed COSE_Sign1 array".into()) };
    let [protected, unprotected, payload, signature]: [Cbor; 4] = arr.try_into().map_err(|_| "cose: malformed COSE_Sign1 array".to_string())?;
    let Cbor::Bytes(protected_bytes) = protected else { return Err("cose: protected must be a bstr".into()) };
    if !matches!(unprotected, Cbor::Map(_)) {
        return Err("cose: unprotected must be a map".into());
    }
    let payload = match payload {
        Cbor::Bytes(b) => Some(b),
        Cbor::Null => None,
        _ => return Err("cose: payload must be a bstr or nil".into()),
    };
    let Cbor::Bytes(signature) = signature else { return Err("cose: signature must be a bstr".into()) };
    let protected_map = if protected_bytes.is_empty() {
        Cbor::Map(Vec::new())
    } else {
        match decode(&protected_bytes)? {
            m @ Cbor::Map(_) => m,
            _ => return Err("cbor: expected a map".into()),
        }
    };
    Ok(CoseSign1 { protected_bytes, protected_map, unprotected, payload, signature })
}

fn alg_of(protected_map: &Cbor) -> Result<&'static str, String> {
    match map_get(protected_map, HDR_ALG) {
        None => Err("cose: missing alg header".into()),
        Some(Cbor::Int(l)) => alg_for_label(*l).ok_or_else(|| "cose: unsupported alg".to_string()),
        Some(_) => Err("cose: unsupported alg".into()),
    }
}

/// Verify a Signed Statement and say WHY it failed. Returns `{ok: true}` or `{ok: false, reason}`; never panics.
pub fn check_statement(statement: &[u8], public_key: &Value, allow_high_s: bool) -> Value {
    let s = match decode_cose_sign1(statement) {
        Ok(s) => s,
        Err(e) => return json!({ "ok": false, "reason": format!("malformed: {e}") }),
    };
    let Some(payload) = &s.payload else { return json!({ "ok": false, "reason": "detached payload" }) };
    let alg = match alg_of(&s.protected_map) {
        Ok(a) => a,
        Err(e) => {
            let reason = if e.contains("missing") { "missing alg header" } else { "unsupported alg" };
            return json!({ "ok": false, "reason": reason });
        }
    };
    let Ok(msg) = sig_structure(&s.protected_bytes, payload) else { return json!({ "ok": false, "reason": "bad signature" }) };
    if verify_bytes(alg, public_key, &msg, &s.signature, allow_high_s) {
        return json!({ "ok": true });
    }
    if alg == "ES256" && !is_canonical_es256(&s.signature) && verify_bytes(alg, public_key, &msg, &s.signature, true) {
        return json!({ "ok": false, "reason": "non-canonical signature (high-S)" });
    }
    json!({ "ok": false, "reason": "bad signature" })
}

pub fn verify_statement(statement: &[u8], public_key: &Value, allow_high_s: bool) -> bool {
    check_statement(statement, public_key, allow_high_s)["ok"] == Value::Bool(true)
}

/// The canonical payload bytes carried by a Signed Statement; errs on a malformed or detached statement.
pub fn statement_payload(statement: &[u8]) -> Result<Vec<u8>, String> {
    decode_cose_sign1(statement)?.payload.ok_or_else(|| "cose: statement payload is detached".to_string())
}

/// The b64u leaf a statement occupies in the transparency log.
pub fn statement_leaf(statement: &[u8]) -> String {
    b64_encode(statement)
}

// ---- inclusion proof codec (RFC 9162) -------------------------------------------------------------------------------

/// Sibling sides (leaf -> root) for `index` in a tree of `size` leaves (RFC 6962 split).
pub fn sibling_sides(index: i64, size: i64) -> Vec<&'static str> {
    let mut out = Vec::new();
    let (mut idx, mut n) = (index, size);
    while n > 1 {
        let k = split_point(n as usize) as i64;
        if idx < k {
            out.push("R");
            n = k;
        } else {
            out.push("L");
            idx -= k;
            n -= k;
        }
    }
    out.reverse();
    out
}

fn proof_hashes(proof: &Value) -> Result<Vec<Vec<u8>>, String> {
    let steps = proof.get("path").and_then(Value::as_array).ok_or("proof.path.map is not a function")?;
    steps
        .iter()
        .map(|step| {
            let step = step.as_object().ok_or("Cannot read properties of null (reading 'hash')")?;
            step.get("hash")
                .and_then(Value::as_str)
                .and_then(|h| decode_b64u_strict(h, Some(32)))
                .ok_or_else(|| "scitt: proof step hash is not a 32-byte b64u hash".to_string())
        })
        .collect()
}

/// Encode an inclusion proof `{index, size, path: [{side, hash}]}` as the RFC 9162 `[size, index, [hash...]]` array.
pub fn encode_inclusion_proof(proof: &Value) -> Result<Vec<u8>, String> {
    let sibs = proof_hashes(proof)?;
    let get = |k: &str| proof.get(k).ok_or_else(|| "cbor: unsupported value".to_string()).and_then(cbor_from_json);
    encode(&Cbor::Array(vec![get("size")?, get("index")?, Cbor::Array(sibs.into_iter().map(Cbor::Bytes).collect())]))
}

struct DecodedProof {
    index: i64,
    size: i64,
    hashes: Vec<Vec<u8>>,
}

fn decode_proof_raw(data: &[u8]) -> Result<DecodedProof, String> {
    let Cbor::Array(v) = decode(data)? else { return Err("scitt: malformed inclusion proof".into()) };
    let [size, index, sibs]: [Cbor; 3] = v.try_into().map_err(|_| "scitt: malformed inclusion proof".to_string())?;
    let (Cbor::Int(size), Cbor::Int(index)) = (size, index) else { return Err("scitt: proof size/index must be integers".into()) };
    if size < 1 || index < 0 || index >= size {
        return Err("scitt: proof size/index out of range".into());
    }
    let Cbor::Array(sibs) = sibs else { return Err("scitt: inclusion path must be an array".into()) };
    if sibs.len() != sibling_sides(index, size).len() {
        return Err("scitt: inclusion path length does not match (index,size)".into());
    }
    let mut hashes = Vec::new();
    for h in sibs {
        match h {
            Cbor::Bytes(b) if b.len() == 32 => hashes.push(b),
            _ => return Err("scitt: inclusion path entry must be a 32-byte bstr".into()),
        }
    }
    Ok(DecodedProof { index, size, hashes })
}

/// Decode an RFC 9162 inclusion proof into `{index, size, path: [{side, hash}]}` (sides re-derived).
pub fn decode_inclusion_proof(data: &[u8]) -> Result<Value, String> {
    let p = decode_proof_raw(data)?;
    let sides = sibling_sides(p.index, p.size);
    let path: Vec<Value> = p.hashes.iter().zip(sides).map(|(h, side)| json!({ "side": side, "hash": b64_encode(h) })).collect();
    Ok(json!({ "index": p.index, "size": p.size, "path": path }))
}

// ---- COSE Receipts (RFC 9942) ---------------------------------------------------------------------------------------

/// A signed COSE Receipt for `proof` against ledger root `root` (b64u, 32 bytes); the payload is detached (nil).
/// `signer` = `{alg, key, issuer?}`.
pub fn build_receipt(root: &str, proof: &Value, signer: &Value) -> Result<Vec<u8>, String> {
    let root_bytes = decode_b64u_strict(root, Some(32)).ok_or("scitt: tree root is not a 32-byte b64u hash")?;
    let alg = signer.get("alg").and_then(Value::as_str).ok_or("cbor: unsupported value")?;
    let label = alg_label(alg).ok_or("cbor: unsupported value")?;
    let key = signer.get("key").ok_or("scitt: key is required")?;
    let mut prot = vec![(int(HDR_ALG), int(label)), (int(HDR_VDS), int(VDS_RFC9162_SHA256))];
    if let Some(iss) = signer.get("issuer") {
        prot.push((int(HDR_CWT_CLAIMS), Cbor::Map(vec![(int(CWT_ISS), cbor_from_json(iss)?)])));
    }
    let protected_bytes = encode(&Cbor::Map(prot))?;
    let unprotected =
        Cbor::Map(vec![(int(HDR_VDS_PROOFS), Cbor::Map(vec![(int(PROOF_TYPE_INCLUSION), Cbor::Array(vec![Cbor::Bytes(encode_inclusion_proof(proof)?)]))]))]);
    let sig = sign_bytes(alg, key, &sig_structure(&protected_bytes, &root_bytes)?)?;
    tagged_sign1(protected_bytes, unprotected, None, sig)
}

fn decode_receipt(receipt: &[u8]) -> Result<(CoseSign1, DecodedProof), String> {
    let cose = decode_cose_sign1(receipt)?;
    if map_get(&cose.protected_map, HDR_VDS) != Some(&Cbor::Int(VDS_RFC9162_SHA256)) {
        return Err("scitt: receipt is not RFC9162_SHA256".into());
    }
    if cose.payload.as_ref().is_some_and(|p| p.len() != 32) {
        return Err("scitt: receipt payload (root) must be 32 bytes".into());
    }
    let proofs = map_get(&cose.unprotected, HDR_VDS_PROOFS).filter(|p| matches!(p, Cbor::Map(_))).ok_or("scitt: missing verifiable-data-structure-proofs")?;
    let Some(Cbor::Array(inclusion)) = map_get(proofs, PROOF_TYPE_INCLUSION) else { return Err("scitt: missing inclusion proof".into()) };
    let Some(first) = inclusion.first() else { return Err("scitt: missing inclusion proof".into()) };
    let Cbor::Bytes(first) = first else { return Err("scitt: inclusion proof must be a bstr".into()) };
    let proof = decode_proof_raw(first)?;
    Ok((cose, proof))
}

/// Verify a COSE Receipt for a Signed Statement; fail closed. `opts` = `{treeRoot?, verificationKey?, statementKey?, allowHighS?}`.
/// At least one anchor (`treeRoot` and/or `verificationKey`) is required; the inclusion proof must bind the EXACT statement bytes
/// to the receipt's root; a given `statementKey` also verifies the statement's own signature. A key that is present is always
/// checked (a null key is refused, never skipped).
pub fn verify_receipt(receipt: &[u8], statement: &[u8], opts: &Value) -> bool {
    verify_receipt_inner(receipt, statement, opts).unwrap_or(false)
}

fn verify_receipt_inner(receipt: &[u8], statement: &[u8], opts: &Value) -> Result<bool, String> {
    let (tree_root, vkey, skey) = (opts.get("treeRoot"), opts.get("verificationKey"), opts.get("statementKey"));
    let high = opts.get("allowHighS") == Some(&Value::Bool(true));
    if tree_root.is_none() && vkey.is_none() {
        return Ok(false); // no anchor
    }
    let (cose, proof) = decode_receipt(receipt)?;
    let Some(root) = root_from_inclusion_path(&leaf_hash(statement), proof.index as f64, proof.size as f64, &proof.hashes) else { return Ok(false) };
    if cose.payload.as_ref().is_some_and(|p| *p != root) {
        return Ok(false);
    }
    if let Some(k) = vkey {
        let alg = alg_of(&cose.protected_map)?;
        if !verify_bytes(alg, k, &sig_structure(&cose.protected_bytes, &root)?, &cose.signature, high) {
            return Ok(false);
        }
    }
    if let Some(t) = tree_root {
        if t.as_str() != Some(b64_encode(&root).as_str()) {
            return Ok(false);
        }
    }
    if let Some(k) = skey {
        if !verify_statement(statement, k, high) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Verify an RFC 9942 / RFC 9162 consistency proof `[old size, new size, [+ bstr]]` between two pinned roots (b64u).
pub fn verify_consistency_proof(proof: &[u8], old_root: &str, new_root: &str) -> bool {
    let Ok(Cbor::Array(v)) = decode(proof) else { return false };
    let Ok([Cbor::Int(old_size), Cbor::Int(new_size), Cbor::Array(path)]) = <[Cbor; 3]>::try_from(v) else { return false };
    let Some(path) = path.into_iter().map(|h| if let Cbor::Bytes(b) = h { Some(b) } else { None }).collect::<Option<Vec<_>>>() else { return false };
    let (Some(r1), Some(r2)) = (decode_b64u_strict(old_root, Some(32)), decode_b64u_strict(new_root, Some(32))) else { return false };
    verify_consistency_path(old_size as f64, new_size as f64, &r1, &r2, &path)
}

// ---- transparency services ------------------------------------------------------------------------------------------

/// A receipt for one log entry against a ledger root.
#[derive(Debug, Clone)]
pub struct Registration {
    pub index: u64,
    pub receipt: Vec<u8>,
    pub root: String,
}

/// A registration plus the Signed Statement that was appended.
#[derive(Debug, Clone)]
pub struct AppendResult {
    pub statement: Vec<u8>,
    pub registration: Registration,
}

/// An RFC 9162 consistency proof with both roots and the RFC 9942 encoding.
#[derive(Debug, Clone)]
pub struct ConsistencyProofResult {
    pub old_size: u64,
    pub new_size: u64,
    pub old_root: String,
    pub new_root: String,
    pub proof: Vec<u8>,
}

fn inclusion_proof_json(index: u64, size: u64, hashes: &[Vec<u8>]) -> Value {
    let sides = sibling_sides(index as i64, size as i64);
    let path: Vec<Value> = hashes.iter().zip(sides).map(|(h, s)| json!({ "side": s, "hash": b64_encode(h) })).collect();
    json!({ "index": index, "size": size, "path": path })
}

fn consistency_bytes(old: u64, new: u64, path: Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
    encode(&Cbor::Array(vec![Cbor::Int(old as i64), Cbor::Int(new as i64), Cbor::Array(path.into_iter().map(Cbor::Bytes).collect())]))
}

/// In-memory reference log: recomputes the Merkle tree on every registration and loses everything on restart. For tests and demos
/// only; the production log is [`DurableTransparencyService`]. `signer` = `{alg, key, issuer?}`.
pub struct TransparencyService {
    statements: Vec<Vec<u8>>,
    leaf_hashes: Vec<Vec<u8>>,
    signer: Value,
}

impl TransparencyService {
    pub fn new(signer: Value) -> Self {
        TransparencyService { statements: Vec::new(), leaf_hashes: Vec::new(), signer }
    }

    pub fn size(&self) -> usize {
        self.statements.len()
    }

    pub fn root(&self) -> String {
        b64_encode(&tree_hash(&self.leaf_hashes))
    }

    /// The statement leaves (b64u of each Signed Statement), in order.
    pub fn snapshot(&self) -> Vec<String> {
        self.statements.iter().map(|s| b64_encode(s)).collect()
    }

    fn receipt_for(&self, index: usize) -> Result<Registration, String> {
        let root = tree_hash(&self.leaf_hashes);
        let size = self.leaf_hashes.len();
        let hashes = inclusion_path(&self.leaf_hashes, index as f64)?;
        let proof = inclusion_proof_json(index as u64, size as u64, &hashes);
        Ok(Registration { index: index as u64, receipt: build_receipt(&b64_encode(&root), &proof, &self.signer)?, root: b64_encode(&root) })
    }

    pub fn register(&mut self, statement: &[u8]) -> Result<Registration, String> {
        if decode_cose_sign1(statement)?.payload.is_none() {
            return Err("scitt: cannot register a statement with a detached payload".into());
        }
        let index = self.statements.len();
        self.statements.push(statement.to_vec());
        self.leaf_hashes.push(leaf_hash(statement));
        self.receipt_for(index)
    }

    /// Sign `payload` as a Signed Statement (`opts` as [`sign_statement`]), register it, and return both.
    pub fn append_and_receipt(&mut self, payload: &Value, opts: &Value) -> Result<AppendResult, String> {
        let statement = sign_statement(payload, opts)?;
        let registration = self.register(&statement)?;
        Ok(AppendResult { statement, registration })
    }

    pub fn get_receipt(&self, index: f64) -> Result<Registration, String> {
        if !is_integer(index) || index < 0.0 || index >= self.statements.len() as f64 {
            return Err("getReceipt: index out of range".into());
        }
        self.receipt_for(index as usize)
    }

    /// The log at `old_size` entries is a prefix of the current log: both roots and the RFC 9942 proof encoding.
    pub fn consistency_proof(&self, old_size: f64) -> Result<ConsistencyProofResult, String> {
        if !is_integer(old_size) || old_size < 1.0 || old_size > self.statements.len() as f64 {
            return Err("consistencyProof: size out of range".into());
        }
        let m = old_size as usize;
        let path = consistency_path(&self.leaf_hashes, old_size)?;
        Ok(ConsistencyProofResult {
            old_size: m as u64,
            new_size: self.statements.len() as u64,
            old_root: b64_encode(&tree_hash(&self.leaf_hashes[..m])),
            new_root: self.root(),
            proof: consistency_bytes(m as u64, self.statements.len() as u64, path)?,
        })
    }
}

/// A new subtree hash to store with an entry (`level` 0 = leaves).
#[derive(Debug, Clone)]
pub struct StoredNode {
    pub level: u32,
    pub index: u64,
    pub hash: Vec<u8>,
}

/// What the durable service needs from a store: `append` is an atomic compare-and-set on the size (entry plus its new subtree
/// hashes land together or not at all); returned entries and nodes are copies.
pub trait ScittLogStore {
    /// The number of entries (a negative or otherwise invalid answer is refused by the service as `store_corrupt`).
    fn size(&self) -> i64;
    fn get_entry(&self, index: u64) -> Option<Vec<u8>>;
    fn get_node(&self, level: u32, index: u64) -> Option<Vec<u8>>;
    fn append(&mut self, expected_size: u64, entry: &[u8], nodes: &[StoredNode]) -> bool;
}

/// In-memory store: single process, forgets everything on restart. For tests only.
#[derive(Default)]
pub struct MemoryScittLogStore {
    entries: Vec<Vec<u8>>,
    nodes: HashMap<(u32, u64), Vec<u8>>,
}

impl MemoryScittLogStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ScittLogStore for MemoryScittLogStore {
    fn size(&self) -> i64 {
        self.entries.len() as i64
    }

    fn get_entry(&self, index: u64) -> Option<Vec<u8>> {
        self.entries.get(usize::try_from(index).ok()?).cloned()
    }

    fn get_node(&self, level: u32, index: u64) -> Option<Vec<u8>> {
        self.nodes.get(&(level, index)).cloned()
    }

    fn append(&mut self, expected_size: u64, entry: &[u8], nodes: &[StoredNode]) -> bool {
        if self.entries.len() as u64 != expected_size {
            return false;
        }
        self.entries.push(entry.to_vec());
        for n in nodes {
            self.nodes.insert((n.level, n.index), n.hash.clone());
        }
        true
    }
}

/// Check a store against the contract the service relies on (compare-and-set, atomic entry-plus-nodes, immutability). `make` builds a
/// fresh empty store. Returns the failures (empty = conforms). The race is the reference's sequence of four appends at the same size.
pub fn check_scitt_log_store<S: ScittLogStore>(make: impl FnOnce() -> Result<S, String>) -> Vec<String> {
    let mut failures: Vec<String> = Vec::new();
    let mut s = match make() {
        Ok(s) => s,
        Err(e) => return vec![format!("the store threw: {e}")],
    };
    let h = |b: u8| vec![b; 32];
    let node = |index: u64, b: u8| StoredNode { level: 0, index, hash: h(b) };
    if s.size() != 0 {
        failures.push("a new store is not empty".into());
    }
    if !s.append(0, &[1], &[node(0, 1)]) {
        failures.push("append at the right size was refused".into());
    }
    if s.append(0, &[2], &[node(1, 2)]) {
        failures.push("append at a stale size was accepted (no compare-and-set)".into());
    }
    if s.size() != 1 {
        failures.push("a refused append changed the size".into());
    }
    if s.get_node(0, 1).is_some() {
        failures.push("a refused append left a node behind (not atomic)".into());
    }
    if s.get_entry(1).is_some() {
        failures.push("a refused append left an entry behind".into());
    }
    if s.get_entry(0).as_deref() != Some(&[1u8][..]) {
        failures.push("the stored entry does not read back".into());
    }
    // a returned entry is an owned copy: changing it must not change the stored one
    if let Some(mut e) = s.get_entry(0) {
        e[0] = 9;
    }
    if s.get_entry(0).as_deref() != Some(&[1u8][..]) {
        failures.push("a returned entry aliases the stored one (mutable)".into());
    }
    let wins = (1u8..=4).filter(|i| s.append(1, &[10 + i], &[node(1, 10 + i)])).count();
    if wins != 1 {
        failures.push("concurrent appends at the same size did not produce exactly one winner".into());
    }
    if s.size() != 2 {
        failures.push("the size after a race is not 2".into());
    }
    failures
}

/// A durable-service failure. `code`: `store_required` | `store_corrupt` | `append_contention` | `out_of_range` | `bad_statement`,
/// or "" for a plain error (a signing failure).
#[derive(Debug, Clone)]
pub struct ScittLogError {
    pub code: &'static str,
    pub message: String,
}

fn log_err(code: &'static str, message: impl Into<String>) -> ScittLogError {
    ScittLogError { code, message: message.into() }
}

fn largest_pow2_below(n: u64) -> u64 {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

fn store_node<S: ScittLogStore>(s: &S, level: u32, index: u64) -> Result<Vec<u8>, ScittLogError> {
    match s.get_node(level, index) {
        Some(h) if h.len() == 32 => Ok(h),
        _ => Err(log_err("store_corrupt", format!("missing or malformed subtree hash ({level}, {index})"))),
    }
}

/// Hash of the range of `n` leaves starting at `lo`.
fn range_hash<S: ScittLogStore>(s: &S, lo: u64, n: u64) -> Result<Vec<u8>, ScittLogError> {
    if n == 1 {
        return store_node(s, 0, lo);
    }
    if n.is_power_of_two() && lo % n == 0 {
        return store_node(s, n.trailing_zeros(), lo / n);
    }
    let k = largest_pow2_below(n);
    Ok(node_hash(&range_hash(s, lo, k)?, &range_hash(s, lo + k, n - k)?))
}

fn store_root<S: ScittLogStore>(s: &S, size: u64) -> Result<Vec<u8>, ScittLogError> {
    if size == 0 {
        Ok(empty_root())
    } else {
        range_hash(s, 0, size)
    }
}

fn store_inclusion<S: ScittLogStore>(s: &S, lo: u64, n: u64, idx: u64) -> Result<Vec<Vec<u8>>, ScittLogError> {
    if n == 1 {
        return Ok(Vec::new());
    }
    let k = largest_pow2_below(n);
    if idx < k {
        let mut p = store_inclusion(s, lo, k, idx)?;
        p.push(range_hash(s, lo + k, n - k)?);
        Ok(p)
    } else {
        let mut p = store_inclusion(s, lo + k, n - k, idx - k)?;
        p.push(range_hash(s, lo, k)?);
        Ok(p)
    }
}

fn store_consistency<S: ScittLogStore>(s: &S, lo: u64, n: u64, m: u64, complete: bool) -> Result<Vec<Vec<u8>>, ScittLogError> {
    if m == n {
        return Ok(if complete { Vec::new() } else { vec![range_hash(s, lo, n)?] });
    }
    let k = largest_pow2_below(n);
    if m <= k {
        let mut p = store_consistency(s, lo, k, m, complete)?;
        p.push(range_hash(s, lo + k, n - k)?);
        Ok(p)
    } else {
        let mut p = store_consistency(s, lo + k, n - k, m - k, false)?;
        p.push(range_hash(s, lo, k)?);
        Ok(p)
    }
}

/// A durable SCITT Transparency Service over a store you supply: an append is O(log n) store reads and writes, state lives
/// entirely in the store. `signer` = `{alg, key, issuer?}`.
pub struct DurableTransparencyService<S: ScittLogStore> {
    store: S,
    signer: Value,
}

impl<S: ScittLogStore> DurableTransparencyService<S> {
    pub fn new(store: S, signer: Value) -> Self {
        DurableTransparencyService { store, signer }
    }

    pub fn size(&self) -> Result<u64, ScittLogError> {
        u64::try_from(self.store.size()).ok().filter(|n| *n <= MAX_SAFE).ok_or_else(|| log_err("store_corrupt", "the store reported an invalid size"))
    }

    pub fn root(&self) -> Result<String, ScittLogError> {
        Ok(b64_encode(&store_root(&self.store, self.size()?)?))
    }

    fn receipt_for(&self, index: u64, size: u64) -> Result<Registration, ScittLogError> {
        let root = store_root(&self.store, size)?;
        let hashes = store_inclusion(&self.store, 0, size, index)?;
        let proof = inclusion_proof_json(index, size, &hashes);
        let receipt = build_receipt(&b64_encode(&root), &proof, &self.signer).map_err(|e| log_err("", e))?;
        Ok(Registration { index, receipt, root: b64_encode(&root) })
    }

    /// Append a Signed Statement (validated structurally first) and return its receipt against the new root.
    pub fn register(&mut self, statement: &[u8]) -> Result<Registration, ScittLogError> {
        match decode_cose_sign1(statement) {
            Ok(c) if c.payload.is_some() => {}
            Ok(_) => return Err(log_err("bad_statement", "cannot register: detached payload")),
            Err(e) => return Err(log_err("bad_statement", format!("cannot register: {e}"))),
        }
        for _ in 0..MAX_APPEND_ATTEMPTS {
            let n = self.size()?;
            let mut h = leaf_hash(statement);
            let mut nodes = vec![StoredNode { level: 0, index: n, hash: h.clone() }];
            let mut level: u32 = 1;
            while (n + 1) % (1u64 << level) == 0 {
                // the new leaf completes a subtree: its left sibling is already stored
                let idx = (n + 1) / (1u64 << level) - 1;
                let left = match self.store.get_node(level - 1, 2 * idx) {
                    Some(l) if l.len() == 32 => l,
                    _ => return Err(log_err("store_corrupt", format!("missing subtree hash ({}, {})", level - 1, 2 * idx))),
                };
                h = node_hash(&left, &h);
                nodes.push(StoredNode { level, index: idx, hash: h.clone() });
                level += 1;
            }
            if self.store.append(n, statement, &nodes) {
                return self.receipt_for(n, n + 1);
            }
        }
        Err(log_err("append_contention", "could not append: the log kept changing"))
    }

    pub fn append_and_receipt(&mut self, payload: &Value, opts: &Value) -> Result<AppendResult, ScittLogError> {
        let statement = sign_statement(payload, opts).map_err(|e| log_err("", e))?;
        let registration = self.register(&statement)?;
        Ok(AppendResult { statement, registration })
    }

    /// A receipt for an entry, against the CURRENT root.
    pub fn get_receipt(&self, index: f64) -> Result<Registration, ScittLogError> {
        let size = self.size()?;
        if !is_integer(index) || index < 0.0 || index >= size as f64 {
            return Err(log_err("out_of_range", "getReceipt: index out of range"));
        }
        self.receipt_for(index as u64, size)
    }

    pub fn get_entry(&self, index: f64) -> Result<Vec<u8>, ScittLogError> {
        let size = self.size()?;
        if !is_integer(index) || index < 0.0 || index >= size as f64 {
            return Err(log_err("out_of_range", "getEntry: index out of range"));
        }
        self.store.get_entry(index as u64).ok_or_else(|| log_err("store_corrupt", format!("entry {index} is missing")))
    }

    /// An RFC 9162 consistency proof that the first `old_size` entries are a prefix of the current log.
    pub fn consistency_proof(&self, old_size: f64) -> Result<ConsistencyProofResult, ScittLogError> {
        let size = self.size()?;
        if !is_integer(old_size) || old_size < 1.0 || old_size > size as f64 {
            return Err(log_err("out_of_range", "consistencyProof: size out of range"));
        }
        let m = old_size as u64;
        let path = store_consistency(&self.store, 0, size, m, true)?;
        Ok(ConsistencyProofResult {
            old_size: m,
            new_size: size,
            old_root: b64_encode(&store_root(&self.store, m)?),
            new_root: b64_encode(&store_root(&self.store, size)?),
            proof: consistency_bytes(m, size, path).map_err(|e| log_err("", e))?,
        })
    }
}
