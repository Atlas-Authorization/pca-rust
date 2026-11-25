//! The pure parts of the MPC networked runner: the length-prefixed JSON wire frame codec, canonical field hex, the `NetAbort`
//! blame record, pairwise-authenticated shares (information-theoretic MACs over F_p), forensic disclosures with the audit that
//! names the cheater, the oblivious-transfer-over-network codecs (strict base64, canonical curve field hex, Ed25519 point
//! validation) and the gadget seed commitments. Sockets, TLS and the distributed driver are not part of this module.
//!
//! Wire values that the reference leaves untyped (`unknown`) stay `serde_json::Value`; field elements are `u64` below
//! `p = 2^61 - 1` (pairwise-authenticated shares keep their raw, possibly unreduced words exactly as received).
//!
//! shortcut: the Ed25519 point codec only validates (canonical coordinates, on the curve, not the identity, prime order) and
//! returns the affine coordinates; the prime-order check is curve25519-dalek's `is_torsion_free`, the only point arithmetic here.
use crate::js_stringify;
use crate::mpc::{fadd, fmul, fneg, fsub, PRIME};
use base64::Engine;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use rsa::BigUint;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

// ---- wire frames ---------------------------------------------------------------------------------------------------------------

/// The wire protocol version.
pub const WIRE_VERSION: i64 = 2;
/// Largest frame body accepted (bytes).
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Every abort kind.
pub const ABORT_KINDS: [&str; 18] = [
    "timeout",
    "disconnect",
    "version",
    "malformed",
    "oversize",
    "duplicate",
    "out-of-order",
    "wrong-round",
    "wrong-session",
    "identity",
    "commitment",
    "ot-check",
    "mac-check",
    "dealer",
    "equivocation",
    "flood",
    "peer-abort",
    "local",
];

static NULL: Value = Value::Null;
const FRAME_TYPES: [&str; 3] = ["hello", "msg", "abort"];

/// Optional members of a [`NetAbort`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NetAbortOpts {
    pub reason: Option<String>,
    pub evidence: Option<Value>,
    pub deadline_ms: Option<i64>,
}

/// An abort of the networked protocol: what happened, who is blamed (only when the evidence names one) and who reported it.
#[derive(Debug, Clone, PartialEq)]
pub struct NetAbort {
    pub message: String,
    pub kind: String,
    pub blamed: Option<i64>,
    pub reporter: i64,
    pub claimed_kind: Option<String>,
    pub claimed_blame: Option<i64>,
    /// Set exactly when nobody is blamed: why the abort cannot be attributed.
    pub reason: Option<String>,
    pub evidence: Option<Value>,
    pub deadline_ms: Option<i64>,
}

impl NetAbort {
    pub fn new(
        kind: &str,
        blamed: Option<i64>,
        reporter: i64,
        detail: &str,
        claimed_kind: Option<&str>,
        claimed_blame: Option<i64>,
        opts: NetAbortOpts,
    ) -> Self {
        let blamed_text = blamed.map_or("none".to_string(), |b| b.to_string());
        let reason = if blamed.is_none() {
            Some(match opts.reason {
                Some(r) if !r.is_empty() => r,
                _ => "unattributable: the evidence available to this party does not identify a culprit".to_string(),
            })
        } else {
            None
        };
        NetAbort {
            message: format!("[{kind}] blamed={blamed_text} reporter={reporter}: {detail}"),
            kind: kind.to_string(),
            blamed,
            reporter,
            claimed_kind: claimed_kind.map(String::from),
            claimed_blame,
            reason,
            evidence: opts.evidence,
            deadline_ms: opts.deadline_ms,
        }
    }
}

/// A frame: a 4-byte big-endian length, then the compact JSON of `{v, ty, sid, seq, rd, d}` (members in that order).
pub fn encode_frame(frame: &Value) -> Result<Vec<u8>, String> {
    let body = js_stringify(frame).into_bytes();
    if body.len() > MAX_FRAME_BYTES {
        return Err("frame too large".into());
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Reassembles frames from arbitrary chunks of a byte stream. A length prefix above [`MAX_FRAME_BYTES`] is refused as soon as
/// its four bytes are in (the body never has to arrive).
#[derive(Debug, Clone, Default)]
pub struct FrameSplitter {
    buf: Vec<u8>,
}

impl FrameSplitter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a chunk; returns every complete frame body now available (possibly none).
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        self.buf.extend_from_slice(chunk);
        let mut out = vec![];
        let mut at = 0usize;
        loop {
            let rest = &self.buf[at..];
            if rest.len() < 4 {
                break;
            }
            let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            if len > MAX_FRAME_BYTES {
                return Err("oversize".into());
            }
            if rest.len() < 4 + len {
                break;
            }
            out.push(rest[4..4 + len].to_vec());
            at += 4 + len;
        }
        self.buf.drain(..at);
        Ok(out)
    }
}

/// A JSON number that is a safe integer and not `-0` (the reference's `Number.isSafeInteger && !Object.is(v, -0)`).
fn safe_int(v: &Value) -> Option<i64> {
    let f = v.as_f64()?;
    if !v.is_number() || f.fract() != 0.0 || f.abs() > 9007199254740991.0 || (f == 0.0 && f.is_sign_negative()) {
        return None;
    }
    Some(f as i64)
}

fn parse_object(body: &[u8]) -> Option<Map<String, Value>> {
    match serde_json::from_str::<Value>(&String::from_utf8_lossy(body)) {
        Ok(Value::Object(m)) => Some(m),
        _ => None,
    }
}

fn envelope_shape_ok(o: &Map<String, Value>) -> bool {
    if o.len() != 6 || !o.contains_key("v") {
        return false;
    }
    if !o.get("ty").and_then(Value::as_str).is_some_and(|t| FRAME_TYPES.contains(&t)) {
        return false;
    }
    if !o.get("sid").is_some_and(Value::is_string) || !o.get("rd").is_some_and(Value::is_string) {
        return false;
    }
    if !o.get("seq").and_then(safe_int).is_some_and(|s| s >= 0) {
        return false;
    }
    o.contains_key("d")
}

/// The `v` member of a frame body, when the body is a JSON object with a safe-integer `v`.
pub fn peek_version(body: &[u8]) -> Option<i64> {
    parse_object(body)?.get("v").and_then(safe_int)
}

/// A well-formed frame of the current wire version, else `None` (any extra / missing member, bad type or bad seq).
pub fn parse_frame(body: &[u8]) -> Option<Value> {
    let o = parse_object(body)?;
    if o.get("v").and_then(Value::as_f64) != Some(WIRE_VERSION as f64) || !o.get("v").is_some_and(Value::is_number) || !envelope_shape_ok(&o) {
        return None;
    }
    Some(Value::Object(o))
}

/// The version of a well-formed frame whose version differs from ours (so the peer can be told to upgrade), else `None`.
pub fn version_mismatch(body: &[u8]) -> Option<i64> {
    let o = parse_object(body)?;
    let v = o.get("v").and_then(safe_int)?;
    if v == WIRE_VERSION || !envelope_shape_ok(&o) {
        return None;
    }
    Some(v)
}

// ---- canonical field hex -------------------------------------------------------------------------------------------------------

/// Lowercase hex of an integer (a negative one keeps its sign, as `BigInt.prototype.toString(16)`).
pub fn hx(x: i128) -> String {
    if x < 0 {
        format!("-{:x}", x.unsigned_abs())
    } else {
        format!("{x:x}")
    }
}

/// A canonical lowercase hex field element (`0` or no leading zero, at most 16 digits) below p, else `None`.
pub fn unhx(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    let ok =
        s == "0" || (!b.is_empty() && b.len() <= 16 && matches!(b[0], b'1'..=b'9' | b'a'..=b'f') && b.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));
    if !ok {
        return None;
    }
    let v = u64::from_str_radix(s, 16).ok()?;
    (v < PRIME).then_some(v)
}

/// [`unhx`] of an untyped wire value (anything but a string is `None`).
pub fn unhx_value(v: &Value) -> Option<u64> {
    unhx(v.as_str()?)
}

/// An array of exactly `len` canonical field elements, else `None`.
pub fn unhx_array(a: &Value, len: usize) -> Option<Vec<u64>> {
    let l = a.as_array()?;
    if l.len() != len {
        return None;
    }
    l.iter().map(unhx_value).collect()
}

// ---- pairwise-authenticated shares ---------------------------------------------------------------------------------------------

/// A pairwise-authenticated share: the value share `x`, the tags this party holds on its value (one per peer) and the keys it
/// holds for the peers' values. Words are kept exactly as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pa {
    pub x: u64,
    pub tag: Vec<u64>,
    pub key: Vec<u64>,
}

/// A value together with one authenticated sharing per MAC key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aw {
    pub v: Pa,
    pub m: Vec<Pa>,
}

/// The environment of one party: its id, the party count, the global MAC difference `delta` and whether tags are kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaEnv {
    pub id: usize,
    pub n: usize,
    pub delta: u64,
    pub tagged: bool,
}

fn zip(a: &[u64], b: &[u64], f: fn(u64, u64) -> u64) -> Result<Vec<u64>, String> {
    if b.len() < a.len() {
        return Err("pairwise-authenticated shares must have the same party count".into());
    }
    Ok(a.iter().zip(b).map(|(x, y)| f(*x, *y)).collect())
}

pub fn pa_add(a: &Pa, b: &Pa) -> Result<Pa, String> {
    Ok(Pa { x: fadd(a.x, b.x), tag: zip(&a.tag, &b.tag, fadd)?, key: zip(&a.key, &b.key, fadd)? })
}

pub fn pa_sub(a: &Pa, b: &Pa) -> Result<Pa, String> {
    Ok(Pa { x: fsub(a.x, b.x), tag: zip(&a.tag, &b.tag, fsub)?, key: zip(&a.key, &b.key, fsub)? })
}

pub fn pa_neg(a: &Pa) -> Pa {
    Pa { x: fneg(a.x), tag: a.tag.iter().map(|t| fneg(*t)).collect(), key: a.key.iter().map(|k| fneg(*k)).collect() }
}

pub fn pa_scale(a: &Pa, c: u64) -> Pa {
    Pa { x: fmul(a.x, c), tag: a.tag.iter().map(|t| fmul(*t, c)).collect(), key: a.key.iter().map(|k| fmul(*k, c)).collect() }
}

/// Add a PUBLIC constant: party 0 adds it to its value share, every other tagged party shifts its key for party 0 by -delta*c.
pub fn pa_add_public0(env: &PaEnv, a: &Pa, c: u64) -> Result<Pa, String> {
    if env.id == 0 {
        return Ok(Pa { x: fadd(a.x, c), tag: a.tag.clone(), key: a.key.clone() });
    }
    if !env.tagged {
        return Ok(a.clone());
    }
    let mut key = a.key.clone();
    let k0 = key.first_mut().ok_or("paAddPublic0: no key for party 0")?;
    *k0 = fsub(*k0, fmul(env.delta, c));
    Ok(Pa { x: a.x, tag: a.tag.clone(), key })
}

pub fn w_add(a: &Aw, b: &Aw) -> Result<Aw, String> {
    Ok(Aw { v: pa_add(&a.v, &b.v)?, m: pair_map(&a.m, &b.m, pa_add)? })
}

pub fn w_sub(a: &Aw, b: &Aw) -> Result<Aw, String> {
    Ok(Aw { v: pa_sub(&a.v, &b.v)?, m: pair_map(&a.m, &b.m, pa_sub)? })
}

pub fn w_neg(a: &Aw) -> Aw {
    Aw { v: pa_neg(&a.v), m: a.m.iter().map(pa_neg).collect() }
}

pub fn w_scale(a: &Aw, c: u64) -> Aw {
    Aw { v: pa_scale(&a.v, c), m: a.m.iter().map(|p| pa_scale(p, c)).collect() }
}

fn pair_map(a: &[Pa], b: &[Pa], f: fn(&Pa, &Pa) -> Result<Pa, String>) -> Result<Vec<Pa>, String> {
    if b.len() < a.len() {
        return Err("authenticated wires must carry the same number of MAC keys".into());
    }
    a.iter().zip(b).map(|(x, y)| f(x, y)).collect()
}

/// Add a PUBLIC constant to an authenticated wire: the value as [`pa_add_public0`], every MAC sharing gains alpha_l * c.
pub fn w_add_public(env: &PaEnv, a: &Aw, c: u64, alpha: &[Pa]) -> Result<Aw, String> {
    if alpha.len() < a.m.len() {
        return Err("wAddPublic: fewer MAC keys than shares".into());
    }
    let m = a.m.iter().zip(alpha).map(|(p, al)| pa_add(p, &pa_scale(al, c))).collect::<Result<Vec<_>, _>>()?;
    Ok(Aw { v: pa_add_public0(env, &a.v, c)?, m })
}

/// Check the tag a peer `from` sent for the opened value `x`: `key[from] + delta * x == tag`.
pub fn pa_verify(env: &PaEnv, a: &Pa, from: usize, x: u64, tag: u64) -> Result<bool, String> {
    let k = a.key.get(from).ok_or("paVerify: no key for that peer")?;
    Ok(fadd(*k, fmul(env.delta, x)) == tag)
}

/// Words one share occupies on the wire.
pub fn pa_width(n: usize, tagged: bool) -> usize {
    if tagged {
        1 + 2 * n.saturating_sub(1)
    } else {
        1
    }
}

/// The wire words of a share: x, then (tagged) the tags and the keys of every peer other than `id`.
pub fn pa_flat(a: &Pa, id: usize, n: usize, tagged: bool) -> Result<Vec<u64>, String> {
    let mut out = vec![a.x];
    if tagged {
        for j in (0..n).filter(|j| *j != id) {
            out.push(*a.tag.get(j).ok_or("paFlat: missing tag")?);
        }
        for j in (0..n).filter(|j| *j != id) {
            out.push(*a.key.get(j).ok_or("paFlat: missing key")?);
        }
    }
    Ok(out)
}

/// Read a share back from wire words starting at `off` (an untagged share has empty tag / key vectors).
pub fn pa_parse(nums: &[u64], off: usize, id: usize, n: usize, tagged: bool) -> Result<Pa, String> {
    let x = *nums.get(off).ok_or("paParse: short input")?;
    if !tagged {
        return Ok(Pa { x, tag: vec![], key: vec![] });
    }
    let (mut tag, mut key) = (vec![0u64; n], vec![0u64; n]);
    let mut o = off + 1;
    for j in (0..n).filter(|j| *j != id) {
        tag[j] = *nums.get(o).ok_or("paParse: short input")?;
        o += 1;
    }
    for j in (0..n).filter(|j| *j != id) {
        key[j] = *nums.get(o).ok_or("paParse: short input")?;
        o += 1;
    }
    Ok(Pa { x, tag, key })
}

pub fn aw_width(n: usize, keys: usize, tagged: bool) -> usize {
    (1 + keys) * pa_width(n, tagged)
}

pub fn aw_flat(a: &Aw, id: usize, n: usize, tagged: bool) -> Result<Vec<u64>, String> {
    let mut out = pa_flat(&a.v, id, n, tagged)?;
    for p in &a.m {
        out.extend(pa_flat(p, id, n, tagged)?);
    }
    Ok(out)
}

pub fn aw_parse(nums: &[u64], off: usize, id: usize, n: usize, keys: usize, tagged: bool) -> Result<Aw, String> {
    let w = pa_width(n, tagged);
    let v = pa_parse(nums, off, id, n, tagged)?;
    let m = (0..keys).map(|l| pa_parse(nums, off + (1 + l) * w, id, n, tagged)).collect::<Result<Vec<_>, _>>()?;
    Ok(Aw { v, m })
}

/// Authenticated sharings one delivered triple needs: a, b, c and (a-hat, c-hat) per sacrifice partner.
pub fn sharings_per_triple(partners: usize) -> usize {
    3 + 2 * partners
}

// ---- forensic disclosures ------------------------------------------------------------------------------------------------------

/// Everything one party discloses about one triple slot after a MAC-check failure: its OT choice bits, the field values it
/// used, and per peer the pads it received and the pads it sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotDisclosure {
    pub bits: Vec<u8>,
    pub y: u64,
    pub z: u64,
    /// Per peer (in wire order): the received values, one per gadget row.
    pub recv: Vec<(i64, Vec<u64>)>,
    /// Per peer (in wire order): the sender masks, one per gadget row.
    pub rho: Vec<(i64, Vec<u64>)>,
}

/// Slots per triple: one for the kept triple plus one per partner.
pub fn slots_for(partners: usize) -> usize {
    1 + partners
}

fn hex_row(r: &[u64]) -> Value {
    Value::Array(r.iter().map(|v| Value::String(hx(*v as i128))).collect())
}

fn side_wire(e: &[(i64, Vec<u64>)]) -> Value {
    Value::Array(e.iter().map(|(p, r)| json!([*p, hex_row(r)])).collect())
}

/// The wire form of a disclosure.
pub fn wire_disclosure(d: &[SlotDisclosure]) -> Value {
    Value::Array(
        d.iter()
            .map(|s| {
                let bits: String = s.bits.iter().map(|b| if *b == 1 { '1' } else { '0' }).collect();
                json!({
                    "bits": bits,
                    "y": hx(s.y as i128),
                    "z": hx(s.z as i128),
                    "recv": side_wire(&s.recv),
                    "rho": side_wire(&s.rho),
                })
            })
            .collect(),
    )
}

fn field(v: &Value) -> Result<u64, String> {
    unhx_value(v).ok_or_else(|| "bad field element".to_string())
}

fn side_parse(x: &Value, rows: usize, peers: &[i64]) -> Result<Vec<(i64, Vec<u64>)>, String> {
    let a = x.as_array().filter(|a| a.len() == peers.len()).ok_or("bad peer table")?;
    let mut m: Vec<(i64, Vec<u64>)> = Vec::with_capacity(a.len());
    for e in a {
        let e = e.as_array().filter(|e| e.len() == 2).ok_or("bad peer entry")?;
        let f = e[0].as_f64().ok_or("bad peer entry")?;
        let p = peers.iter().copied().find(|q| *q as f64 == f).ok_or("bad peer entry")?;
        if m.iter().any(|(q, _)| *q == p) {
            return Err("bad peer entry".into());
        }
        let row = e[1].as_array().filter(|r| r.len() == rows).ok_or("bad row table")?;
        m.push((p, row.iter().map(field).collect::<Result<Vec<_>, _>>()?));
    }
    Ok(m)
}

/// Parse and validate a received disclosure against the agreed slot count, gadget rows and peer set.
pub fn parse_disclosure(raw: &Value, slots: usize, rows: usize, peers: &[i64]) -> Result<Vec<SlotDisclosure>, String> {
    let a = raw.as_array().filter(|a| a.len() == slots).ok_or("bad forensic disclosure")?;
    a.iter()
        .map(|o| -> Result<SlotDisclosure, String> {
            let bits =
                o.get("bits").and_then(Value::as_str).filter(|b| b.len() == rows && b.bytes().all(|c| c == b'0' || c == b'1')).ok_or("bad choice bits")?;
            let get = |k: &str| o.get(k).unwrap_or(&NULL);
            Ok(SlotDisclosure {
                bits: bits.bytes().map(|c| (c == b'1') as u8).collect(),
                y: field(get("y"))?,
                z: field(get("z"))?,
                recv: side_parse(get("recv"), rows, peers)?,
                rho: side_parse(get("rho"), rows, peers)?,
            })
        })
        .collect()
}

/// What the audit found: parties whose own disclosure is internally inconsistent, and (receiver, sender) pairs whose pads disagree.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuditResult {
    pub self_bad: BTreeSet<i64>,
    pub pair_bad: Vec<(i64, i64)>,
}

fn peer_row(side: &[(i64, Vec<u64>)], p: i64) -> Result<&Vec<u64>, String> {
    side.iter().find(|(q, _)| *q == p).map(|(_, r)| r).ok_or_else(|| "audit: disclosure lacks a peer".to_string())
}

/// Cross-check every party's disclosure: each must reproduce its own product share, and each pair of parties must agree on the
/// pads one sent and the other received.
pub fn audit_disclosures(all: &BTreeMap<i64, Vec<SlotDisclosure>>, gadget: &[u64]) -> Result<AuditResult, String> {
    let mut res = AuditResult::default();
    let parties: Vec<i64> = all.keys().copied().collect();
    for &i in &parties {
        let di = &all[&i];
        for (s, sd) in di.iter().enumerate() {
            let mut value: u128 = 0;
            for (k, g) in gadget.iter().enumerate() {
                if sd.bits.get(k) == Some(&1) {
                    value += *g as u128;
                }
            }
            let mut implied = fmul((value % PRIME as u128) as u64, sd.y);
            for &p in parties.iter().filter(|p| **p != i) {
                for v in peer_row(&sd.recv, p)? {
                    implied = fadd(implied, *v % PRIME);
                }
                for v in peer_row(&sd.rho, p)? {
                    implied = fsub(implied, *v);
                }
            }
            if implied != sd.z {
                res.self_bad.insert(i);
            }
            for &p in parties.iter().filter(|p| **p != i) {
                let sp = all[&p].get(s).ok_or("audit: disclosure lacks a slot")?;
                let rho = peer_row(&sp.rho, i)?;
                let got = peer_row(&sd.recv, p)?;
                let y = sp.y % PRIME;
                let mut bad = false;
                for (k, g) in gadget.iter().enumerate() {
                    if bad {
                        break;
                    }
                    let rk = *rho.get(k).ok_or("audit: short mask row")?;
                    let gk = *got.get(k).ok_or("audit: short received row")?;
                    let want = fadd(rk, if sd.bits.get(k) == Some(&1) { fmul(*g, y) } else { 0 });
                    if gk % PRIME != want {
                        bad = true;
                    }
                }
                if bad {
                    res.pair_bad.push((i, p));
                }
            }
        }
    }
    Ok(res)
}

/// The party `me` blames after the audit: the lowest-numbered other party whose own disclosure is inconsistent, else the peer
/// of the first disagreeing pair that involves `me`, else nobody.
pub fn blame_from(me: i64, r: &AuditResult) -> Option<i64> {
    if let Some(p) = r.self_bad.iter().find(|p| **p != me) {
        return Some(*p);
    }
    for (recv, send) in &r.pair_bad {
        if *recv == me {
            return Some(*send);
        }
        if *send == me {
            return Some(*recv);
        }
    }
    None
}

/// Default time the parties wait for the forensic exchange.
pub const DEFAULT_FORENSIC_DEADLINE_MS: i64 = 30_000;

/// The commitment to a disclosure: SHA-256 over a domain tag and the JSON of `[session, party, triple, deadline, nonce, wire]`.
pub fn disclosure_commit(session_id: &str, party: i64, triple_index: i64, deadline_ms: i64, nonce: &str, wire: &Value) -> String {
    let mut h = Sha256::new();
    h.update(b"atlas-pca-mpc/forensic-commit/v1\0");
    h.update(js_stringify(&json!([session_id, party, triple_index, deadline_ms, nonce, wire])).as_bytes());
    hex_of(&h.finalize())
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---- OT-over-network codecs and gadget seed commitments ----------------------------------------------------------------------------

/// Standard base64 with padding.
pub fn b64(u: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(u)
}

/// Strict base64: padded, canonical (re-encoding reproduces the input), optionally of an exact length.
pub fn unb64(s: &Value, len: Option<usize>) -> Result<Vec<u8>, String> {
    let s = s.as_str().ok_or("bad base64")?;
    let body = s.strip_suffix("==").or_else(|| s.strip_suffix('=')).unwrap_or(s);
    if !body.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/') {
        return Err("bad base64".into());
    }
    let b = base64::engine::general_purpose::STANDARD.decode(s).map_err(|_| "non-canonical base64".to_string())?;
    if b64(&b) != s {
        return Err("non-canonical base64".into());
    }
    if len.is_some_and(|l| b.len() != l) {
        return Err("bad length".into());
    }
    Ok(b)
}

/// The Ed25519 field prime 2^255 - 19.
pub fn curve_q() -> BigUint {
    (BigUint::from(1u8) << 255usize) - BigUint::from(19u8)
}

/// The Ed25519 group order l.
pub fn curve_l() -> BigUint {
    BigUint::parse_bytes(b"1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16).expect("group order")
}

/// A canonical lowercase hex element below the curve field prime (`0` or no leading zero, at most 64 digits).
pub fn hex_big(s: &Value) -> Result<BigUint, String> {
    let s = s.as_str().ok_or("bad field element")?;
    let b = s.as_bytes();
    let ok =
        s == "0" || (!b.is_empty() && b.len() <= 64 && matches!(b[0], b'1'..=b'9' | b'a'..=b'f') && b.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));
    if !ok {
        return Err("bad field element".into());
    }
    let v = BigUint::parse_bytes(b, 16).ok_or("bad field element")?;
    if v >= curve_q() {
        return Err("non-canonical field element".into());
    }
    Ok(v)
}

fn curve_d(q: &BigUint) -> BigUint {
    let inv = BigUint::from(121666u32).modpow(&(q - BigUint::from(2u8)), q);
    (q - BigUint::from(121665u32)) * inv % q
}

fn parity(x: &BigUint) -> u8 {
    x.to_bytes_le().first().map_or(0, |b| b & 1)
}

/// A point `{x, y}` of affine hex coordinates, validated: canonical field elements, on the curve, not the identity, and in the
/// prime-order subgroup (no small-order / cofactor component). Returns the coordinates.
pub fn j_pt(v: &Value) -> Result<(BigUint, BigUint), String> {
    if !v.is_object() {
        return Err("bad point".into());
    }
    let x = hex_big(v.get("x").unwrap_or(&NULL))?;
    let y = hex_big(v.get("y").unwrap_or(&NULL))?;
    let q = curve_q();
    let (x2, y2) = (&x * &x % &q, &y * &y % &q);
    let lhs = (&y2 + &q - &x2) % &q;
    let rhs = (BigUint::from(1u8) + curve_d(&q) * &x2 % &q * &y2) % &q;
    if lhs != rhs {
        return Err("received point: not on curve".into());
    }
    if x == BigUint::from(0u8) && y == BigUint::from(1u8) {
        return Err("received point: identity element (forbidden here)".into());
    }
    let mut enc = y.to_bytes_le();
    enc.resize(32, 0);
    let mut arr: [u8; 32] = enc.try_into().map_err(|_| "bad point".to_string())?;
    if parity(&x) == 1 {
        arr[31] |= 0x80;
    }
    let p = CompressedEdwardsY(arr).decompress().ok_or("received point: not on curve")?;
    if !p.is_torsion_free() {
        return Err("received point: not in the prime-order subgroup (small-order/cofactor)".into());
    }
    Ok((x, y))
}

/// The wire form `{x, y}` of affine coordinates.
pub fn pt_j(x: &BigUint, y: &BigUint) -> Value {
    json!({"x": x.to_str_radix(16), "y": y.to_str_radix(16)})
}

/// The affine coordinates of k * B (k reduced mod the group order; x recovered from the compressed point).
pub fn mul_base_affine(k: &BigUint) -> Result<(BigUint, BigUint), String> {
    let mut kb = (k % curve_l()).to_bytes_le();
    kb.resize(32, 0);
    let arr: [u8; 32] = kb.try_into().map_err(|_| "scalar".to_string())?;
    let c = (ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order(arr)).compress().to_bytes();
    let sign = c[31] >> 7;
    let mut yb = c;
    yb[31] &= 0x7f;
    let y = BigUint::from_bytes_le(&yb);
    let q = curve_q();
    let y2 = &y * &y % &q;
    let u = (&y2 + &q - BigUint::from(1u8)) % &q;
    let v = (curve_d(&q) * &y2 + BigUint::from(1u8)) % &q;
    let x2 = u * v.modpow(&(&q - BigUint::from(2u8)), &q) % &q;
    let mut x = x2.modpow(&((&q + BigUint::from(3u8)) / BigUint::from(8u8)), &q);
    if &x * &x % &q != x2 {
        x = x * BigUint::from(2u8).modpow(&((&q - BigUint::from(1u8)) / BigUint::from(4u8)), &q) % &q;
    }
    if &x * &x % &q != x2 {
        return Err("no square root: not a curve point".into());
    }
    if parity(&x) != sign {
        x = (&q - &x) % &q;
    }
    Ok((x, y))
}

/// The commitment to a party's gadget seed: SHA-256(tag, session, decimal party, seed) as hex.
pub fn gadget_commit(session_id: &str, party: i64, seed: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"atlas-pca-mpc/gadget-commit");
    h.update(session_id.as_bytes());
    h.update(party.to_string().as_bytes());
    h.update(seed);
    hex_of(&h.finalize())
}

/// The exact bytes a party signs in the gadget seed exchange (`round` is `gd-c` or `gd-o`).
pub fn gadget_statement(session_id: &str, round: &str, signer: i64, value: &str) -> Vec<u8> {
    js_stringify(&json!(["atlas-pca-mpc/gadget-sig/v1", session_id, round, signer, value])).into_bytes()
}
