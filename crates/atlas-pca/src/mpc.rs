//! Multi-party computation, deterministic layer: the prime field F_p (p = 2^61 - 1), additive secret sharing, Beaver triples, the
//! thermometer encoding, the cleartext and semi-honest composition of stakeholder decision vectors, and the SPDZ-style actively
//! secure layer (authenticated shares with two MAC keys, MAC-check, triple sacrifice, authenticated Beaver multiplication and the
//! malicious composition runner in trusted-dealer mode). Every random draw goes through [`FieldSource`]: the seeded SplitMix64
//! [`FieldRng`] reproduces every share and transcript of the reference byte for byte; production callers use [`SecureFieldRng`]
//! (the OS CSPRNG, rejection-sampled, unbiased).
//!
//! Field elements are `u64` in `[0, p)`; every entry point reduces its arguments first, as the reference does. Arbitrary-size
//! decimal integers (the corpus and wire encoding) enter through [`mod_dec`] / [`low_u64`] / [`low_u128`].
//!
//! shortcut: the no-dealer offline phase (MASCOT over oblivious transfer) is not part of this module: a malicious composition
//! without `insecure_trusted_dealer` and without an [`OfflineProvider`] is refused (fail closed). The trusted dealer is a test
//! and prototype mode, exactly as in the reference. The party `views` of [`MpcResult`] share one transcript (`opened`), they do
//! not copy it per party.
use sha2::{Digest, Sha256};
use std::fmt;

/// The field modulus p = 2^61 - 1.
pub const PRIME: u64 = (1u64 << 61) - 1;
const P128: u128 = PRIME as u128;
/// Largest party count accepted (bounds allocation).
pub const MAX_PARTIES: i64 = 1024;
/// Granularity of the r-quantization.
pub const DEFAULT_Q: i64 = 100;
/// Bits per field element.
pub const FIELD_BITS: usize = 61;
/// Default statistical security parameter for the OT choice-bit encoding.
pub const STAT_SEC: i64 = 64;
/// Smallest `s` accepted without the explicit unsafe flag.
pub const MIN_STAT_SEC: i64 = 40;
/// Default number of independent MAC keys.
pub const MAC_KEYS: i64 = 2;
/// Minimum statistical soundness (bits) a MAC context must give.
pub const MIN_MAC_SOUNDNESS_BITS: f64 = 100.0;
/// Default number of sacrifice partners per kept triple.
pub const SACRIFICE_PARTNERS: i64 = 2;
const T_M: i64 = 3;

/// A refusal. `MacCheckAbort` is the active-security abort (a detected cheater / malformed triple), `Invalid` everything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpcError {
    Invalid(String),
    MacCheckAbort(String),
}

impl fmt::Display for MpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MpcError::Invalid(m) | MpcError::MacCheckAbort(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for MpcError {}

pub type MpcResultOf<T> = Result<T, MpcError>;

fn inv<T>(m: impl Into<String>) -> MpcResultOf<T> {
    Err(MpcError::Invalid(m.into()))
}

fn abort<T>(m: impl Into<String>) -> MpcResultOf<T> {
    Err(MpcError::MacCheckAbort(m.into()))
}

// ---- field ---------------------------------------------------------------------------------------------------------------------

/// Canonical representative in [0, p) of a machine integer.
pub fn mod_u64(x: u64) -> u64 {
    x % PRIME
}

/// Canonical representative in [0, p) of a signed integer.
pub fn mod_i128(x: i128) -> u64 {
    x.rem_euclid(PRIME as i128) as u64
}

fn split_sign(s: &str) -> MpcResultOf<(bool, &str)> {
    let (neg, d) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    if d.is_empty() || !d.bytes().all(|b| b.is_ascii_digit()) {
        return inv("not a decimal integer");
    }
    Ok((neg, d))
}

/// A decimal integer of any size (sign allowed) reduced to [0, p).
pub fn mod_dec(s: &str) -> MpcResultOf<u64> {
    let (neg, d) = split_sign(s)?;
    let mut acc: u128 = 0;
    for b in d.bytes() {
        acc = (acc * 10 + (b - b'0') as u128) % P128;
    }
    Ok(if neg { fneg(acc as u64) } else { acc as u64 })
}

/// A decimal integer of any size as its low 128 bits (two's complement for a negative one; the GF(2^128) mask).
pub fn low_u128(s: &str) -> MpcResultOf<u128> {
    let (neg, d) = split_sign(s)?;
    let mut acc: u128 = 0;
    for b in d.bytes() {
        acc = acc.wrapping_mul(10).wrapping_add((b - b'0') as u128);
    }
    Ok(if neg { acc.wrapping_neg() } else { acc })
}

/// A decimal integer of any size as its low 64 bits (two's complement for a negative one; the SplitMix64 seed mask).
pub fn low_u64(s: &str) -> MpcResultOf<u64> {
    Ok(low_u128(s)? as u64)
}

pub fn fadd(a: u64, b: u64) -> u64 {
    (a % PRIME + b % PRIME) % PRIME
}

pub fn fsub(a: u64, b: u64) -> u64 {
    (a % PRIME + PRIME - b % PRIME) % PRIME
}

pub fn fmul(a: u64, b: u64) -> u64 {
    ((a % PRIME) as u128 * (b % PRIME) as u128 % P128) as u64
}

pub fn fneg(a: u64) -> u64 {
    (PRIME - a % PRIME) % PRIME
}

/// A source of uniform field elements.
pub trait FieldSource {
    fn next(&mut self) -> u64;
}

/// Deterministic SplitMix64 drawing unbiased field elements by rejection sampling (reject the top 2^64 mod p = 8 residues).
/// For bit-reproducible tests and verifiers only; production randomness is [`SecureFieldRng`].
#[derive(Debug, Clone)]
pub struct FieldRng {
    s: u64,
}

impl FieldRng {
    /// The reference default seed.
    pub const DEFAULT_SEED: u64 = 0x243f6a8885a308d3;

    pub fn new(seed: u64) -> Self {
        FieldRng { s: seed }
    }

    /// A seed given as a decimal integer of any size (its low 64 bits, as the reference masks it).
    pub fn from_decimal(seed: &str) -> MpcResultOf<Self> {
        Ok(Self::new(low_u64(seed)?))
    }

    fn next_u64(&mut self) -> u64 {
        self.s = self.s.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.s;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
}

impl Default for FieldRng {
    fn default() -> Self {
        Self::new(Self::DEFAULT_SEED)
    }
}

/// floor(2^64 / p) * p = 8 * p: draws at or above it are rejected so the modulo is exactly uniform.
const LIMIT: u64 = 8 * PRIME;

impl FieldSource for FieldRng {
    fn next(&mut self) -> u64 {
        loop {
            let u = self.next_u64();
            if u < LIMIT {
                return u % PRIME;
            }
        }
    }
}

/// The OS CSPRNG as a field source (unbiased rejection sampling). A failing OS generator panics: there is no weaker fallback.
#[derive(Debug, Clone, Copy, Default)]
pub struct SecureFieldRng;

impl FieldSource for SecureFieldRng {
    fn next(&mut self) -> u64 {
        loop {
            let mut buf = [0u8; 8];
            getrandom::getrandom(&mut buf).expect("operating-system randomness unavailable");
            let u = u64::from_be_bytes(buf);
            if u < LIMIT {
                return u % PRIME;
            }
        }
    }
}

/// The field-randomness policy: the CSPRNG by default, a reproducible seeded stream ONLY for an explicit test seed.
pub fn field_random(test_seed: Option<u64>) -> Box<dyn FieldSource> {
    match test_seed {
        Some(s) => Box::new(FieldRng::new(s)),
        None => Box::new(SecureFieldRng),
    }
}

// ---- additive sharing ----------------------------------------------------------------------------------------------------------

fn parties(fname: &str, n: i64) -> MpcResultOf<usize> {
    if !(1..=MAX_PARTIES).contains(&n) {
        return inv(format!("{fname}: n must be an integer in [1, {MAX_PARTIES}]"));
    }
    Ok(n as usize)
}

/// Split `secret` into `n` additive shares: the first n-1 uniform, the last the complement.
pub fn share(secret: u64, n: i64, rng: &mut dyn FieldSource) -> MpcResultOf<Vec<u64>> {
    let n = parties("share", n)?;
    let mut shares = Vec::with_capacity(n);
    let mut acc = 0u64;
    for _ in 0..n - 1 {
        let s = rng.next();
        shares.push(s);
        acc = fadd(acc, s);
    }
    shares.push(fsub(secret % PRIME, acc));
    Ok(shares)
}

/// Reconstruct from ALL shares; an empty vector or a missing share is refused (fail closed).
pub fn reconstruct(shares: &[Option<u64>]) -> MpcResultOf<u64> {
    if shares.is_empty() {
        return inv("reconstruct: no shares (fail closed)");
    }
    let mut acc = 0u64;
    for s in shares {
        match s {
            None => return inv("reconstruct: missing share (fail closed)"),
            Some(v) => acc = fadd(acc, *v),
        }
    }
    Ok(acc)
}

fn sum_all(shares: &[u64]) -> u64 {
    shares.iter().fold(0, |a, b| fadd(a, *b))
}

/// Sharing of a PUBLIC constant: party 0 holds c, everyone else 0.
pub fn share_constant(c: u64, n: i64) -> MpcResultOf<Vec<u64>> {
    let n = parties("shareConstant", n)?;
    let mut out = vec![0u64; n];
    out[0] = c % PRIME;
    Ok(out)
}

fn require_same_len(x: &[u64], y: &[u64]) -> MpcResultOf<()> {
    if x.len() != y.len() {
        return inv("shared values must have the same party count");
    }
    Ok(())
}

pub fn add_sv(x: &[u64], y: &[u64]) -> MpcResultOf<Vec<u64>> {
    require_same_len(x, y)?;
    Ok(x.iter().zip(y).map(|(a, b)| fadd(*a, *b)).collect())
}

pub fn sub_sv(x: &[u64], y: &[u64]) -> MpcResultOf<Vec<u64>> {
    require_same_len(x, y)?;
    Ok(x.iter().zip(y).map(|(a, b)| fsub(*a, *b)).collect())
}

pub fn neg_sv(x: &[u64]) -> Vec<u64> {
    x.iter().map(|a| fneg(*a)).collect()
}

/// x * c for a PUBLIC scalar c.
pub fn scale_sv(x: &[u64], c: u64) -> Vec<u64> {
    x.iter().map(|a| fmul(*a, c)).collect()
}

/// x + c for a PUBLIC constant c: added to party 0's share only. An empty sharing is refused.
pub fn add_public_sv(x: &[u64], c: u64) -> MpcResultOf<Vec<u64>> {
    if x.is_empty() {
        return inv("addPublicSV: empty sharing");
    }
    let mut out = x.to_vec();
    out[0] = fadd(out[0], c % PRIME);
    Ok(out)
}

/// The logical complement of a shared BIT: a sharing of 1 - b.
pub fn not_bit_sv(b: &[u64]) -> MpcResultOf<Vec<u64>> {
    add_public_sv(&neg_sv(b), 1)
}

// ---- GF(2^128) -----------------------------------------------------------------------------------------------------------------

const GF128_RED: u128 = 0x87;

/// Field addition in GF(2^128): XOR.
pub fn gf128_add(a: u128, b: u128) -> u128 {
    a ^ b
}

/// Multiply by `x`: shift left, reduce with x^128 = x^7 + x^2 + x + 1.
pub fn gf128_mul_x(v: u128) -> u128 {
    let r = v << 1;
    if v >> 127 & 1 == 1 {
        r ^ GF128_RED
    } else {
        r
    }
}

/// Multiply by x^i (i LFSR steps; a negative i is zero steps).
pub fn gf128_mul_by_xi(v: u128, i: i64) -> u128 {
    let mut r = v;
    for _ in 0..i.max(0) {
        r = gf128_mul_x(r);
    }
    r
}

/// Full GF(2^128) multiplication, right to left over the bits of `b`.
pub fn gf128_mul(a: u128, b: u128) -> u128 {
    let (mut res, mut v) = (0u128, a);
    for i in 0..128 {
        if (b >> i) & 1 == 1 {
            res ^= v;
        }
        v = gf128_mul_x(v);
    }
    res
}

// ---- privacy-amplified OT choice-bit encoding ----------------------------------------------------------------------------------

/// Number of encoded choice bits for statistical parameter `s`: 61 + 3s.
pub fn enc_bits(s: i64) -> i64 {
    FIELD_BITS as i64 + 3 * s
}

/// A receiver operand: its field value and the choice bits that encode it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncShare {
    pub value: u64,
    pub bits: Vec<u8>,
}

/// The public gadget vector for `s`: 2^k for s = 0, else m uniform field elements from `next`. `s < 40` needs the unsafe flag.
pub fn make_gadget(s: i64, next: &mut dyn FieldSource, unsafe_ok: bool) -> MpcResultOf<Vec<u64>> {
    if !(0..=64).contains(&s) {
        return inv("statSec must be an integer in [0, 64]");
    }
    if s < MIN_STAT_SEC && !unsafe_ok {
        return inv(format!("statSec {s} is below {MIN_STAT_SEC}: refused (tests may pass the explicit unsafe flag)"));
    }
    let m = enc_bits(s) as usize;
    let mut g = Vec::with_capacity(m);
    for k in 0..m {
        g.push(if s == 0 { ((1u128 << k) % P128) as u64 } else { next.next() });
    }
    Ok(g)
}

/// Evaluate <g, bits> in F_p.
pub fn enc_value(g: &[u64], bits: &[i64]) -> MpcResultOf<u64> {
    if g.len() != bits.len() {
        return inv("encValue: gadget / bits length mismatch");
    }
    let mut v: u128 = 0;
    for (gk, b) in g.iter().zip(bits) {
        if *b == 1 {
            v += (*gk % PRIME) as u128;
        }
    }
    Ok((v % P128) as u64)
}

/// The plain binary encoding of an arbitrary field element (61 bits, weights 2^k).
pub fn plain_share(x: u64) -> EncShare {
    let v = x % PRIME;
    EncShare { value: v, bits: (0..FIELD_BITS).map(|k| ((v >> k) & 1) as u8).collect() }
}

/// The weights of the plain binary encoding.
pub fn plain_gadget() -> Vec<u64> {
    (0..FIELD_BITS).map(|k| ((1u128 << k) % P128) as u64).collect()
}

/// Draw `m` uniform bits from a field source (the 60 low bits of each draw are uniform).
pub fn random_bits(m: usize, rng: &mut dyn FieldSource) -> Vec<u8> {
    let mut out = Vec::with_capacity(m);
    while out.len() < m {
        let w = rng.next();
        let mut i = 0;
        while i < 60 && out.len() < m {
            out.push(((w >> i) & 1) as u8);
            i += 1;
        }
    }
    out
}

/// A fresh uniform operand: uniform bits and the value they encode under `g`.
pub fn sample_enc(g: &[u64], rng: &mut dyn FieldSource) -> EncShare {
    let bits = random_bits(g.len(), rng);
    let bits_i: Vec<i64> = bits.iter().map(|b| *b as i64).collect();
    let value = enc_value(g, &bits_i).expect("gadget and bits have the same length");
    EncShare { value, bits }
}

// ---- Beaver triples ------------------------------------------------------------------------------------------------------------

/// A Beaver multiplication triple, each component additively shared (c = a * b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Triple {
    pub a: Vec<u64>,
    pub b: Vec<u64>,
    pub c: Vec<u64>,
}

/// One opened (reconstructed, public) protocol message; `shares` are the per-party broadcasts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedMsg {
    pub label: &'static str,
    pub value: u64,
    pub shares: Vec<u64>,
}

/// Trusted-dealer preprocessing: one correct triple, each component shared.
pub fn gen_triple(n: i64, rng: &mut dyn FieldSource) -> MpcResultOf<Triple> {
    let a = rng.next();
    let b = rng.next();
    let c = fmul(a, b);
    Ok(Triple { a: share(a, n, rng)?, b: share(b, n, rng)?, c: share(c, n, rng)? })
}

/// `genTriples`: `count` correct trusted-dealer triples for `n` parties.
pub fn gen_triples(count: usize, n: i64, rng: &mut dyn FieldSource) -> MpcResultOf<Vec<Triple>> {
    (0..count).map(|_| gen_triple(n, rng)).collect()
}

/// Secure multiply: a sharing of x*y, consuming `triple`. Every opened value (d, e) is pushed to `transcript` when given.
pub fn beaver_mul(x: &[u64], y: &[u64], triple: &Triple, transcript: Option<&mut Vec<OpenedMsg>>) -> MpcResultOf<Vec<u64>> {
    if x.len() != y.len() {
        return inv("beaverMul: operand party counts differ");
    }
    for part in [&triple.a, &triple.b, &triple.c] {
        if part.len() != x.len() {
            return inv("beaverMul: triple party count differs from the operands");
        }
    }
    let d_shares = sub_sv(x, &triple.a)?;
    let e_shares = sub_sv(y, &triple.b)?;
    let opt = |v: &[u64]| v.iter().map(|s| Some(*s)).collect::<Vec<_>>();
    let d = reconstruct(&opt(&d_shares))?;
    let e = reconstruct(&opt(&e_shares))?;
    if let Some(t) = transcript {
        t.push(OpenedMsg { label: "d", value: d, shares: d_shares });
        t.push(OpenedMsg { label: "e", value: e, shares: e_shares });
    }
    let de = fmul(d, e);
    Ok((0..x.len())
        .map(|i| {
            let zi = fadd(triple.c[i], fadd(fmul(d, triple.b[i]), fmul(e, triple.a[i])));
            if i == 0 {
                fadd(zi, de)
            } else {
                zi
            }
        })
        .collect())
}

// ---- thermometer / decision vectors / cleartext composition -------------------------------------------------------------------

/// Encode v in {0..M} as ge[k] = (v >= k) for k = 1..M. Clamps v into range (fail-safe); a NaN encodes as 0.
pub fn thermometer_encode(v: f64, m: i64) -> MpcResultOf<Vec<u8>> {
    if m < 0 {
        return inv("thermometerEncode: M must be a non-negative integer");
    }
    let clamped = if v.is_nan() { 0.0 } else { v.trunc().min(m as f64).max(0.0) };
    Ok((1..=m).map(|k| (clamped >= k as f64) as u8).collect())
}

/// Decode a thermometer = the number of set bits (the encoded value; for a composed OR the MAX).
pub fn thermometer_decode(bits: &[u8]) -> i64 {
    bits.iter().filter(|b| **b == 1).count() as i64
}

/// JS `Math.round` for a finite number (half rounds up).
fn js_round(x: f64) -> f64 {
    let f = x.floor();
    if x - f >= 0.5 {
        f + 1.0
    } else {
        f
    }
}

/// Quantize r in [0,1] to an integer in {0..Q}. Non-finite => worst case (Q).
pub fn quantize_r(r: f64, q: i64) -> i64 {
    if !r.is_finite() {
        return q;
    }
    let v = js_round(r.max(0.0).min(1.0) * q as f64);
    (v.min(q as f64).max(0.0)) as i64
}

/// A party's decision vector: allow in {0,1}, t in {1,2,3}, rQuant in {0..Q}.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionVector {
    pub allow: i64,
    pub t: i64,
    pub r_quant: i64,
}

/// The composed, revealed decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComposedDecision {
    pub allow: i64,
    pub t: i64,
    pub r_quant: i64,
}

/// Reject a malformed decision vector (e.g. two `allow = -1` would multiply to an allow under the shared AND).
pub fn assert_decision_vectors(vectors: &[DecisionVector], q: i64) -> MpcResultOf<()> {
    for (i, v) in vectors.iter().enumerate() {
        if v.allow != 0 && v.allow != 1 {
            return inv(format!("party {i}: allow must be 0 or 1"));
        }
        if !(1..=3).contains(&v.t) {
            return inv(format!("party {i}: t must be 1, 2 or 3"));
        }
        if v.r_quant < 0 || v.r_quant > q {
            return inv(format!("party {i}: rQuant must be an integer in [0, {q}]"));
        }
    }
    Ok(())
}

/// Cleartext composition: allow = AND, t = MAX, rQuant = MAX. Requires at least one party.
pub fn compose_clear(vectors: &[DecisionVector], q: i64) -> MpcResultOf<ComposedDecision> {
    if vectors.is_empty() {
        return inv("composeClear: no parties (fail closed)");
    }
    assert_decision_vectors(vectors, q)?;
    let mut out = ComposedDecision { allow: 1, t: 1, r_quant: 0 };
    for v in vectors {
        if v.allow == 0 {
            out.allow = 0;
        }
        out.t = out.t.max(v.t);
        out.r_quant = out.r_quant.max(v.r_quant);
    }
    Ok(out)
}

// ---- semi-honest composition ---------------------------------------------------------------------------------------------------

/// One secret-sharing event of the semi-honest run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharingRecord {
    pub label: String,
    pub party: usize,
    pub secret: u64,
    pub shares: Vec<u64>,
}

/// What one party holds after the run (its share of every sharing) and the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyView {
    pub party: usize,
    pub held_shares: Vec<u64>,
    pub output: ComposedDecision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpcResult {
    pub composed: ComposedDecision,
    pub parties: usize,
    pub q: i64,
    pub opened: Vec<OpenedMsg>,
    pub sharings: Vec<SharingRecord>,
    pub views: Vec<PartyView>,
    pub multiplications: usize,
}

struct SecureRun {
    n: usize,
    rng: Box<dyn FieldSource>,
    opened: Vec<OpenedMsg>,
    sharings: Vec<SharingRecord>,
    mults: usize,
}

impl SecureRun {
    fn share_bit(&mut self, bit: u8, label: String, party: usize) -> MpcResultOf<Vec<u64>> {
        let shares = share(bit as u64, self.n as i64, self.rng.as_mut())?;
        self.sharings.push(SharingRecord { label, party, secret: bit as u64, shares: shares.clone() });
        Ok(shares)
    }

    fn mul(&mut self, x: &[u64], y: &[u64]) -> MpcResultOf<Vec<u64>> {
        let t = gen_triple(self.n as i64, self.rng.as_mut())?;
        let z = beaver_mul(x, y, &t, Some(&mut self.opened))?;
        self.mults += 1;
        Ok(z)
    }

    fn and_bits(&mut self, bits: &[Vec<u64>]) -> MpcResultOf<Vec<u64>> {
        if bits.is_empty() {
            return share_constant(1, self.n as i64);
        }
        let mut acc = bits[0].clone();
        for b in &bits[1..] {
            acc = self.mul(&acc, b)?;
        }
        Ok(acc)
    }

    fn or_bits(&mut self, bits: &[Vec<u64>]) -> MpcResultOf<Vec<u64>> {
        if bits.is_empty() {
            return share_constant(0, self.n as i64);
        }
        let mut prod = not_bit_sv(&bits[0])?;
        for b in &bits[1..] {
            let nb = not_bit_sv(b)?;
            prod = self.mul(&prod, &nb)?;
        }
        not_bit_sv(&prod)
    }

    fn open_bit(&self, sv: &[u64]) -> MpcResultOf<bool> {
        let o: Vec<Option<u64>> = sv.iter().map(|s| Some(*s)).collect();
        Ok(reconstruct(&o)? == 1)
    }
}

fn clamp_t(x: i64) -> i64 {
    x.clamp(1, 3)
}

/// Semi-honest secure composition under additive sharing and Beaver triples. `seed: None` draws from the OS CSPRNG.
pub fn compose_secure(vectors: &[DecisionVector], q: Option<i64>, seed: Option<u64>) -> MpcResultOf<MpcResult> {
    let n = vectors.len();
    if n == 0 {
        return inv("composeSecure: no parties (fail closed)");
    }
    let q = q.unwrap_or(DEFAULT_Q);
    assert_decision_vectors(vectors, q)?;
    let mut run = SecureRun { n, rng: field_random(seed), opened: vec![], sharings: vec![], mults: 0 };

    let mut allow_bits = Vec::with_capacity(n);
    for (p, v) in vectors.iter().enumerate() {
        allow_bits.push(run.share_bit(v.allow as u8, format!("p{p}.allow"), p)?);
    }
    let allow_sv = run.and_bits(&allow_bits)?;
    let allow = run.open_bit(&allow_sv)? as i64;

    let t_therm: Vec<Vec<u8>> = vectors.iter().map(|v| thermometer_encode(v.t as f64, T_M)).collect::<Result<_, _>>()?;
    let mut t_ge = Vec::new();
    for k in 0..T_M as usize {
        let mut bits_at_k = Vec::with_capacity(n);
        for p in 0..n {
            bits_at_k.push(run.share_bit(t_therm[p][k], format!("p{p}.t.ge{}", k + 1), p)?);
        }
        let o = run.or_bits(&bits_at_k)?;
        t_ge.push(run.open_bit(&o)? as u8);
    }
    let t = clamp_t(thermometer_decode(&t_ge));

    let r_therm: Vec<Vec<u8>> = vectors.iter().map(|v| thermometer_encode(v.r_quant as f64, q)).collect::<Result<_, _>>()?;
    let mut r_ge = Vec::new();
    for k in 0..q as usize {
        let mut bits_at_k = Vec::with_capacity(n);
        for p in 0..n {
            bits_at_k.push(run.share_bit(r_therm[p][k], format!("p{p}.r.ge{}", k + 1), p)?);
        }
        let o = run.or_bits(&bits_at_k)?;
        r_ge.push(run.open_bit(&o)? as u8);
    }
    let r_quant = thermometer_decode(&r_ge);

    let composed = ComposedDecision { allow, t, r_quant };
    let views = (0..n).map(|p| PartyView { party: p, held_shares: run.sharings.iter().map(|s| s.shares[p]).collect(), output: composed }).collect();
    Ok(MpcResult { composed, parties: n, q, opened: run.opened, sharings: run.sharings, views, multiplications: run.mults })
}

// ---- SPDZ: authenticated shares ------------------------------------------------------------------------------------------------

/// One MAC key: alpha and its additive shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacKey {
    pub alpha_shares: Vec<u64>,
    pub alpha: u64,
}

/// The MAC context: the first key plus `extra_keys` (independent keys multiply the soundness).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacContext {
    pub n: usize,
    pub alpha_shares: Vec<u64>,
    pub alpha: u64,
    pub extra_keys: Vec<MacKey>,
}

/// An authenticated shared value: per-party value shares and, per key, per-party shares of key * value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSV {
    pub value: Vec<u64>,
    pub mac: Vec<u64>,
    pub extra_mac: Vec<Vec<u64>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthTriple {
    pub a: AuthSV,
    pub b: AuthSV,
    pub c: AuthSV,
}

/// All MAC keys of a context, first key first.
pub fn mac_keys(ctx: &MacContext) -> Vec<MacKey> {
    let mut v = vec![MacKey { alpha_shares: ctx.alpha_shares.clone(), alpha: ctx.alpha }];
    v.extend(ctx.extra_keys.iter().cloned());
    v
}

/// Statistical soundness (bits) of `keys` independent MACs over F_p: keys * (log2(p) - 1).
pub fn mac_soundness_bits(keys: i64, p: u64) -> f64 {
    keys as f64 * ((p as f64).log2() - 1.0)
}

fn mk_key(n: i64, rng: &mut dyn FieldSource) -> MpcResultOf<MacKey> {
    let alpha = rng.next();
    Ok(MacKey { alpha, alpha_shares: share(alpha, n, rng)? })
}

/// Dealer setup: fresh MAC keys, additively shared.
pub fn setup_mac(n: i64, rng: &mut dyn FieldSource, keys: i64) -> MpcResultOf<MacContext> {
    if n < 1 {
        return inv("setupMac: n must be a positive integer");
    }
    if !(1..=16).contains(&keys) {
        return inv("setupMac: keys must be an integer in [1, 16]");
    }
    let first = mk_key(n, rng)?;
    let mut extra_keys = Vec::with_capacity(keys as usize - 1);
    for _ in 1..keys {
        extra_keys.push(mk_key(n, rng)?);
    }
    Ok(MacContext { n: n as usize, alpha_shares: first.alpha_shares, alpha: first.alpha, extra_keys })
}

/// Dealer input: share `secret` together with its MAC under every key.
pub fn auth_share(secret: u64, ctx: &MacContext, rng: &mut dyn FieldSource) -> MpcResultOf<AuthSV> {
    let v = secret % PRIME;
    let n = ctx.n as i64;
    let value = share(v, n, rng)?;
    let mac = share(fmul(ctx.alpha, v), n, rng)?;
    let mut extra_mac = Vec::with_capacity(ctx.extra_keys.len());
    for k in &ctx.extra_keys {
        extra_mac.push(share(fmul(k.alpha, v), n, rng)?);
    }
    Ok(AuthSV { value, mac, extra_mac })
}

/// Authenticated PUBLIC constant (no randomness): party 0 holds c; each MAC share is alpha_share * c.
pub fn auth_constant(c: u64, ctx: &MacContext) -> AuthSV {
    let v = c % PRIME;
    let mut value = vec![0u64; ctx.n];
    value[0] = v;
    AuthSV {
        value,
        mac: ctx.alpha_shares.iter().map(|a| fmul(*a, v)).collect(),
        extra_mac: ctx.extra_keys.iter().map(|k| k.alpha_shares.iter().map(|a| fmul(*a, v)).collect()).collect(),
    }
}

fn require_same(x: &AuthSV, y: &AuthSV) -> MpcResultOf<()> {
    if x.value.len() != y.value.len() || x.mac.len() != y.mac.len() || x.value.len() != x.mac.len() || y.value.len() != y.mac.len() {
        return inv("authenticated shared values must have the same party count");
    }
    if x.extra_mac.len() != y.extra_mac.len() {
        return inv("authenticated shared values must carry the same number of MAC keys");
    }
    for (a, b) in x.extra_mac.iter().zip(&y.extra_mac) {
        if a.len() != b.len() || a.len() != x.value.len() {
            return inv("authenticated shared values must have the same party count");
        }
    }
    Ok(())
}

fn zip_auth(x: &AuthSV, y: &AuthSV, f: fn(u64, u64) -> u64) -> MpcResultOf<AuthSV> {
    require_same(x, y)?;
    let z = |a: &[u64], b: &[u64]| a.iter().zip(b).map(|(p, q)| f(*p, *q)).collect::<Vec<_>>();
    Ok(AuthSV { value: z(&x.value, &y.value), mac: z(&x.mac, &y.mac), extra_mac: x.extra_mac.iter().zip(&y.extra_mac).map(|(a, b)| z(a, b)).collect() })
}

pub fn add_auth(x: &AuthSV, y: &AuthSV) -> MpcResultOf<AuthSV> {
    zip_auth(x, y, fadd)
}

pub fn sub_auth(x: &AuthSV, y: &AuthSV) -> MpcResultOf<AuthSV> {
    zip_auth(x, y, fsub)
}

pub fn neg_auth(x: &AuthSV) -> AuthSV {
    AuthSV { value: neg_sv(&x.value), mac: neg_sv(&x.mac), extra_mac: x.extra_mac.iter().map(|r| neg_sv(r)).collect() }
}

/// x * c for a PUBLIC scalar c.
pub fn scale_auth(x: &AuthSV, c: u64) -> AuthSV {
    let k = c % PRIME;
    AuthSV { value: scale_sv(&x.value, k), mac: scale_sv(&x.mac, k), extra_mac: x.extra_mac.iter().map(|r| scale_sv(r, k)).collect() }
}

/// x + c for a PUBLIC constant c: value on party 0, every MAC share gains alpha_share_i * c.
pub fn add_public_auth(x: &AuthSV, c: u64, ctx: &MacContext) -> MpcResultOf<AuthSV> {
    if x.value.len() != ctx.n || x.mac.len() != ctx.n || ctx.alpha_shares.len() != ctx.n || ctx.n == 0 {
        return inv("addPublicAuth: shared value and MAC context disagree on the party count");
    }
    if x.extra_mac.len() != ctx.extra_keys.len() {
        return inv("addPublicAuth: shared value and MAC context disagree on the key count");
    }
    let k = c % PRIME;
    let mut value = x.value.clone();
    value[0] = fadd(value[0], k);
    let mac = x.mac.iter().enumerate().map(|(i, m)| fadd(*m, fmul(ctx.alpha_shares[i], k))).collect();
    let mut extra_mac = Vec::with_capacity(x.extra_mac.len());
    for (row, key) in x.extra_mac.iter().zip(&ctx.extra_keys) {
        if row.len() != ctx.n || key.alpha_shares.len() != ctx.n {
            return inv("addPublicAuth: extra MAC party count mismatch");
        }
        extra_mac.push(row.iter().enumerate().map(|(i, m)| fadd(*m, fmul(key.alpha_shares[i], k))).collect());
    }
    Ok(AuthSV { value, mac, extra_mac })
}

/// The logical complement of a shared authenticated BIT: 1 - b.
pub fn not_bit_auth(b: &AuthSV, ctx: &MacContext) -> MpcResultOf<AuthSV> {
    add_public_auth(&neg_auth(b), 1, ctx)
}

/// The reconstructed value of an authenticated sharing (no MAC check; the engine's `open` is the checked path).
pub fn auth_value(x: &AuthSV) -> u64 {
    sum_all(&x.value)
}

/// Dealer triple: (a, b, c = a*b), each authenticated.
pub fn gen_auth_triple(ctx: &MacContext, rng: &mut dyn FieldSource) -> MpcResultOf<AuthTriple> {
    let a = rng.next();
    let b = rng.next();
    Ok(AuthTriple { a: auth_share(a, ctx, rng)?, b: auth_share(b, ctx, rng)?, c: auth_share(fmul(a, b), ctx, rng)? })
}

/// A triple to keep plus its sacrifice partners (they share `b` with it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TripleWithPartners {
    pub keep: AuthTriple,
    pub partners: Vec<AuthTriple>,
}

/// Fault injection for a malicious dealer (tests): an additive error on c of the kept triple / of each partner.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DealerFault {
    pub keep_c_delta: Option<u64>,
    pub partner_c_delta: Vec<Option<u64>>,
}

/// Dealer triple plus sacrifice partners (1..=8).
pub fn gen_triple_with_partners(ctx: &MacContext, rng: &mut dyn FieldSource, partners: i64, fault: Option<&DealerFault>) -> MpcResultOf<TripleWithPartners> {
    if !(1..=8).contains(&partners) {
        return inv("genTripleWithPartners: partners must be in [1, 8]");
    }
    let a = rng.next();
    let b = rng.next();
    let b_sv = auth_share(b, ctx, rng)?;
    let keep_delta = fault.and_then(|f| f.keep_c_delta).unwrap_or(0);
    let keep_a = auth_share(a, ctx, rng)?;
    let keep_c = auth_share(fadd(fmul(a, b), keep_delta), ctx, rng)?;
    let keep = AuthTriple { a: keep_a, b: b_sv.clone(), c: keep_c };
    let mut ps = Vec::with_capacity(partners as usize);
    for r in 0..partners as usize {
        let ah = rng.next();
        let delta = fault.and_then(|f| f.partner_c_delta.get(r).copied().flatten()).unwrap_or(0);
        let pa = auth_share(ah, ctx, rng)?;
        let pc = auth_share(fadd(fmul(ah, b), delta), ctx, rng)?;
        ps.push(AuthTriple { a: pa, b: b_sv.clone(), c: pc });
    }
    Ok(TripleWithPartners { keep, partners: ps })
}

// ---- SPDZ: engine, MAC-check, sacrifice ----------------------------------------------------------------------------------------

/// A scripted deviation of one (malicious) party at one opening, for the tests: `value_delta` shifts its value share, `mac_delta`
/// shifts its MAC share under key `mac_key` (default 0).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Deviation {
    pub open_index: i64,
    pub party: i64,
    pub value_delta: Option<u64>,
    pub mac_delta: Option<u64>,
    pub mac_key: Option<i64>,
}

/// An opened value kept for the MAC-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedValue {
    pub value: u64,
    pub mac_shares: Vec<Vec<u64>>,
    pub label: String,
}

/// The per-party MAC-check residuals sigma_i = gamma_i - alpha_i * a for each key, over modulus `p`:
/// a = sum_j r_j * v_j and gamma_i = sum_j r_j * mac_i(v_j). An honest run sums to 0 over the parties.
pub fn mac_residuals(p: u64, alpha_shares: &[Vec<u64>], opened: &[OpenedValue], challenges: &[Vec<u64>]) -> MpcResultOf<Vec<Vec<u64>>> {
    if p == 0 {
        return inv("macResiduals: modulus must be positive");
    }
    let pp = p as u128;
    let mulm = |a: u64, b: u64| ((a % p) as u128 * (b % p) as u128 % pp) as u64;
    let addm = |a: u64, b: u64| ((a as u128 + b as u128) % pp) as u64;
    let subm = |a: u64, b: u64| (((a % p) as u128 + pp - (b % p) as u128) % pp) as u64;
    let mut out = Vec::with_capacity(alpha_shares.len());
    for (l, alphas) in alpha_shares.iter().enumerate() {
        let r = challenges.get(l).ok_or_else(|| MpcError::Invalid("macResiduals: missing challenges".into()))?;
        let mut a = 0u64;
        for (j, o) in opened.iter().enumerate() {
            let rj = *r.get(j).ok_or_else(|| MpcError::Invalid("macResiduals: missing challenge".into()))?;
            a = addm(a, mulm(rj, o.value));
        }
        let mut row = Vec::with_capacity(alphas.len());
        for (i, alpha_i) in alphas.iter().enumerate() {
            let mut gamma = 0u64;
            for (j, o) in opened.iter().enumerate() {
                let m = o.mac_shares.get(l).and_then(|row| row.get(i)).ok_or_else(|| MpcError::Invalid("macResiduals: missing MAC share".into()))?;
                gamma = addm(gamma, mulm(r[j], *m));
            }
            row.push(subm(gamma, mulm(*alpha_i, a)));
        }
        out.push(row);
    }
    Ok(out)
}

fn commit(value: u64, nonce: u64) -> [u8; 32] {
    Sha256::digest(format!("{value:x}:{nonce:x}").as_bytes()).into()
}

/// The opening engine: opens authenticated values (recording deviations) and runs the batched MAC-check at the end.
#[derive(Debug, Clone)]
pub struct SpdzEngine {
    ctx: MacContext,
    deviations: Vec<Deviation>,
    opened: Vec<OpenedValue>,
    counter: usize,
}

impl SpdzEngine {
    /// Refuses a context whose keys give less than 100 bits of soundness (the default two keys give 120).
    pub fn new(ctx: &MacContext, deviations: Vec<Deviation>) -> MpcResultOf<Self> {
        let bits = mac_soundness_bits(1 + ctx.extra_keys.len() as i64, PRIME);
        if bits < MIN_MAC_SOUNDNESS_BITS {
            return inv(format!(
                "SpdzEngine: MAC context gives only {bits:.0} bits of statistical soundness (< {MIN_MAC_SOUNDNESS_BITS}); use setupMac(n, rng) with the default {MAC_KEYS} keys"
            ));
        }
        Ok(SpdzEngine { ctx: ctx.clone(), deviations, opened: vec![], counter: 0 })
    }

    pub fn open_count(&self) -> usize {
        self.counter
    }

    /// Open `x` publicly: every party broadcasts its value share (and keeps its MAC shares for the check).
    pub fn open(&mut self, x: &AuthSV, label: &str) -> MpcResultOf<u64> {
        let idx = self.counter as i64;
        self.counter += 1;
        if x.extra_mac.len() != self.ctx.extra_keys.len() {
            return inv("open: value and MAC context disagree on the key count");
        }
        let mut value_shares = x.value.clone();
        let mut mac_shares: Vec<Vec<u64>> = std::iter::once(x.mac.clone()).chain(x.extra_mac.iter().cloned()).collect();
        for d in &self.deviations {
            if d.open_index != idx {
                continue;
            }
            if d.party < 0 || d.party as usize >= self.ctx.n {
                return inv("Deviation.party out of range");
            }
            let party = d.party as usize;
            if let Some(vd) = d.value_delta {
                let s = value_shares.get_mut(party).ok_or_else(|| MpcError::Invalid("open: value shares shorter than the party count".into()))?;
                *s = fadd(*s, vd);
            }
            if let Some(md) = d.mac_delta {
                let key = d.mac_key.unwrap_or(0);
                if key < 0 || key as usize >= mac_shares.len() {
                    return inv("Deviation.macKey out of range");
                }
                let s = mac_shares[key as usize].get_mut(party).ok_or_else(|| MpcError::Invalid("open: MAC shares shorter than the party count".into()))?;
                *s = fadd(*s, md);
            }
        }
        let value = sum_all(&value_shares);
        self.opened.push(OpenedValue { value, mac_shares, label: label.to_string() });
        Ok(value)
    }

    /// The batched MAC-check over everything opened so far: random challenges, per-party residuals, commit-then-open of each
    /// residual, and the residual sum must be 0 under every key (else abort with no output).
    pub fn mac_check(&mut self, rng: &mut dyn FieldSource) -> MpcResultOf<()> {
        if self.opened.is_empty() {
            return Ok(());
        }
        let keys = mac_keys(&self.ctx);
        let challenges: Vec<Vec<u64>> = keys.iter().map(|_| self.opened.iter().map(|_| rng.next()).collect()).collect();
        let alphas: Vec<Vec<u64>> = keys.iter().map(|k| k.alpha_shares.clone()).collect();
        let sigma = mac_residuals(PRIME, &alphas, &self.opened, &challenges)?;
        for row in &sigma {
            let nonces: Vec<u64> = row.iter().map(|_| rng.next()).collect();
            let commitments: Vec<[u8; 32]> = row.iter().zip(&nonces).map(|(s, n)| commit(*s, *n)).collect();
            for (i, c) in commitments.iter().enumerate() {
                if commit(row[i], nonces[i]) != *c {
                    return abort(format!("MAC-check: commitment from party {i} did not open consistently"));
                }
            }
        }
        for (l, row) in sigma.iter().enumerate() {
            let residual = sum_all(row);
            if residual != 0 {
                return abort(format!(
                    "MAC-check FAILED (key {l}): residual {residual} != 0 - an actively-malicious party was detected; aborting with no output"
                ));
            }
        }
        Ok(())
    }
}

/// Certify a batch of dealer triples by sacrifice: each partner is opened against the kept triple under a public non-zero
/// challenge; tau = e*c - c' - rho*b must be 0, the MAC-check authenticates every opening. A bad triple aborts the whole batch.
pub fn sacrifice_verify(batch: &[TripleWithPartners], ctx: &MacContext, rng: &mut dyn FieldSource, deviations: Vec<Deviation>) -> MpcResultOf<Vec<AuthTriple>> {
    let mut engine = SpdzEngine::new(ctx, deviations)?;
    let mut taus: Vec<u64> = vec![];
    for tw in batch {
        if tw.partners.is_empty() {
            return abort("sacrifice: a triple without partners cannot be certified");
        }
        let keep = &tw.keep;
        for sac in &tw.partners {
            if sac.b.value != keep.b.value {
                return abort("sacrifice: partner does not share b with the triple");
            }
            let mut e = rng.next();
            if e == 0 {
                e = 1;
            }
            let rho_sv = sub_auth(&scale_auth(&keep.a, e), &sac.a)?;
            let rho = engine.open(&rho_sv, "sacrifice:rho")?;
            let mut tau = sub_auth(&scale_auth(&keep.c, e), &sac.c)?;
            tau = sub_auth(&tau, &scale_auth(&keep.b, rho))?;
            taus.push(engine.open(&tau, "sacrifice:tau")?);
        }
    }
    engine.mac_check(rng)?;
    for t in taus {
        if t != 0 {
            return abort(format!(
                "Beaver-triple sacrifice FAILED: residual tau={t} != 0 - a malformed triple (c != a*b) was delivered; aborting with no triple emitted"
            ));
        }
    }
    Ok(batch.iter().map(|x| x.keep.clone()).collect())
}

/// Authenticated Beaver multiplication: d and e are opened through the engine (MAC-checked later); the result stays authenticated.
pub fn beaver_mul_auth(x: &AuthSV, y: &AuthSV, triple: &AuthTriple, ctx: &MacContext, engine: &mut SpdzEngine, label: &str) -> MpcResultOf<AuthSV> {
    for t in [&triple.a, &triple.b, &triple.c] {
        require_same(x, t)?;
    }
    require_same(x, y)?;
    let d = engine.open(&sub_auth(x, &triple.a)?, &format!("{label}:d"))?;
    let e = engine.open(&sub_auth(y, &triple.b)?, &format!("{label}:e"))?;
    let z = add_auth(&triple.c, &add_auth(&scale_auth(&triple.b, d), &scale_auth(&triple.a, e))?)?;
    add_public_auth(&z, fmul(d, e), ctx)
}

// ---- malicious (actively secure) composition ----------------------------------------------------------------------------------

/// A source of authenticated triples and inputs that replaces the trusted dealer (the OT-based offline phase).
pub trait OfflineProvider {
    fn n(&self) -> usize;
    fn mac_context(&self) -> &MacContext;
    fn gen_auth_triple(&mut self) -> MpcResultOf<AuthTriple>;
    fn auth_input(&mut self, value: u64, owner: usize) -> MpcResultOf<AuthSV>;
}

/// Trusted-dealer options (only with `insecure_trusted_dealer`).
#[derive(Debug, Clone, Default)]
pub struct DealerOptions {
    /// Certify every triple by sacrifice (default true).
    pub verify_triples: Option<bool>,
    /// Sacrifice partners per triple (default 2).
    pub partners: Option<i64>,
    pub fault: Option<DealerFault>,
}

#[derive(Default)]
pub struct MaliciousConfig {
    pub q: Option<i64>,
    pub seed: Option<u64>,
    pub deviations: Vec<Deviation>,
    pub offline: Option<Box<dyn OfflineProvider>>,
    /// Required to use the in-process trusted dealer (it sees every secret: tests and prototypes only).
    pub insecure_trusted_dealer: bool,
    pub dealer: Option<DealerOptions>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaliciousResult {
    pub composed: ComposedDecision,
    pub parties: usize,
    pub q: i64,
    pub opens: usize,
    pub multiplications: usize,
    /// "trusted-dealer" or "no-dealer".
    pub offline_mode: &'static str,
    pub triples_verified: bool,
    pub mac_checked: bool,
}

struct MalRun {
    ctx: MacContext,
    rng: Box<dyn FieldSource>,
    offline: Option<Box<dyn OfflineProvider>>,
    verify: bool,
    partners: i64,
    fault: Option<DealerFault>,
    mults: usize,
}

impl MalRun {
    fn next_triple(&mut self) -> MpcResultOf<AuthTriple> {
        if let Some(o) = self.offline.as_mut() {
            return o.gen_auth_triple();
        }
        if !self.verify {
            return match &self.fault {
                Some(f) => Ok(gen_triple_with_partners(&self.ctx, self.rng.as_mut(), 1, Some(f))?.keep),
                None => gen_auth_triple(&self.ctx, self.rng.as_mut()),
            };
        }
        let dealt = gen_triple_with_partners(&self.ctx, self.rng.as_mut(), self.partners, self.fault.as_ref())?;
        Ok(sacrifice_verify(&[dealt], &self.ctx, self.rng.as_mut(), vec![])?.remove(0))
    }

    fn share_bit(&mut self, bit: u8, owner: usize) -> MpcResultOf<AuthSV> {
        match self.offline.as_mut() {
            Some(o) => o.auth_input(bit as u64, owner),
            None => auth_share(bit as u64, &self.ctx, self.rng.as_mut()),
        }
    }

    fn mul(&mut self, engine: &mut SpdzEngine, x: &AuthSV, y: &AuthSV, label: String) -> MpcResultOf<AuthSV> {
        let t = self.next_triple()?;
        let z = beaver_mul_auth(x, y, &t, &self.ctx, engine, &label)?;
        self.mults += 1;
        Ok(z)
    }

    fn and_bits(&mut self, engine: &mut SpdzEngine, bits: &[AuthSV]) -> MpcResultOf<AuthSV> {
        if bits.is_empty() {
            return Ok(auth_constant(1, &self.ctx));
        }
        let mut acc = bits[0].clone();
        for (i, b) in bits.iter().enumerate().skip(1) {
            acc = self.mul(engine, &acc, b, format!("and{i}"))?;
        }
        Ok(acc)
    }

    fn or_bits(&mut self, engine: &mut SpdzEngine, bits: &[AuthSV]) -> MpcResultOf<AuthSV> {
        if bits.is_empty() {
            return Ok(auth_constant(0, &self.ctx));
        }
        let mut prod = not_bit_auth(&bits[0], &self.ctx)?;
        for (i, b) in bits.iter().enumerate().skip(1) {
            let nb = not_bit_auth(b, &self.ctx)?;
            prod = self.mul(engine, &prod, &nb, format!("or{i}"))?;
        }
        not_bit_auth(&prod, &self.ctx)
    }

    fn parties_bits(&mut self, vectors_bits: &[Vec<u8>], k: usize) -> MpcResultOf<Vec<AuthSV>> {
        let mut out = Vec::with_capacity(vectors_bits.len());
        for (p, tb) in vectors_bits.iter().enumerate() {
            out.push(self.share_bit(tb[k], p)?);
        }
        Ok(out)
    }
}

/// Actively secure composition: every bit is an authenticated sharing, every multiplication a MAC-checked authenticated Beaver
/// product, every dealer triple sacrificed. Without `insecure_trusted_dealer` an [`OfflineProvider`] is required (the no-dealer
/// phase is not in this module: refused).
pub fn compose_secure_malicious(vectors: &[DecisionVector], cfg: MaliciousConfig) -> MpcResultOf<MaliciousResult> {
    let n = vectors.len();
    if n == 0 {
        return inv("composeSecureMalicious: no parties (fail closed)");
    }
    let q = cfg.q.unwrap_or(DEFAULT_Q);
    assert_decision_vectors(vectors, q)?;
    let mut rng = field_random(cfg.seed);

    if cfg.offline.is_some() && cfg.insecure_trusted_dealer {
        return inv("composeSecureMalicious: offline and insecureTrustedDealer are mutually exclusive (fail closed)");
    }
    if cfg.dealer.is_some() && !cfg.insecure_trusted_dealer && cfg.offline.is_none() {
        return inv("composeSecureMalicious: dealer options require insecureTrustedDealer: true (fail closed)");
    }
    if cfg.offline.is_none() && !cfg.insecure_trusted_dealer {
        return inv(
            "composeSecureMalicious: no offline provider and insecureTrustedDealer not set: the no-dealer offline phase is not available here (fail closed)",
        );
    }
    if let Some(o) = &cfg.offline {
        if o.n() != n {
            return inv("composeSecureMalicious: offline provider party count != number of vectors");
        }
    }
    let ctx = match &cfg.offline {
        Some(o) => o.mac_context().clone(),
        None => setup_mac(n as i64, rng.as_mut(), MAC_KEYS)?,
    };
    let mut engine = SpdzEngine::new(&ctx, cfg.deviations.clone())?;
    let dealer = cfg.dealer.clone().unwrap_or_default();
    let no_dealer = cfg.offline.is_some();
    let verify = dealer.verify_triples.unwrap_or(true);
    let mut run = MalRun { ctx, rng, offline: cfg.offline, verify, partners: dealer.partners.unwrap_or(SACRIFICE_PARTNERS), fault: dealer.fault, mults: 0 };

    let mut allow_bits = Vec::with_capacity(n);
    for (p, v) in vectors.iter().enumerate() {
        allow_bits.push(run.share_bit(v.allow as u8, p)?);
    }
    let allow_sv = run.and_bits(&mut engine, &allow_bits)?;

    let t_therm: Vec<Vec<u8>> = vectors.iter().map(|v| thermometer_encode(v.t as f64, T_M)).collect::<Result<_, _>>()?;
    let mut t_ge = Vec::new();
    for k in 0..T_M as usize {
        let bits = run.parties_bits(&t_therm, k)?;
        t_ge.push(run.or_bits(&mut engine, &bits)?);
    }
    let r_therm: Vec<Vec<u8>> = vectors.iter().map(|v| thermometer_encode(v.r_quant as f64, q)).collect::<Result<_, _>>()?;
    let mut r_ge = Vec::new();
    for k in 0..q as usize {
        let bits = run.parties_bits(&r_therm, k)?;
        r_ge.push(run.or_bits(&mut engine, &bits)?);
    }

    let allow_open = engine.open(&allow_sv, "out:allow")?;
    let mut t_open = Vec::with_capacity(t_ge.len());
    for (k, sv) in t_ge.iter().enumerate() {
        t_open.push((engine.open(sv, &format!("out:t.ge{}", k + 1))? == 1) as u8);
    }
    let mut r_open = Vec::with_capacity(r_ge.len());
    for (k, sv) in r_ge.iter().enumerate() {
        r_open.push((engine.open(sv, &format!("out:r.ge{}", k + 1))? == 1) as u8);
    }

    engine.mac_check(run.rng.as_mut())?;

    Ok(MaliciousResult {
        composed: ComposedDecision { allow: (allow_open == 1) as i64, t: clamp_t(thermometer_decode(&t_open)), r_quant: thermometer_decode(&r_open) },
        parties: n,
        q,
        opens: engine.open_count(),
        multiplications: run.mults,
        offline_mode: if no_dealer { "no-dealer" } else { "trusted-dealer" },
        triples_verified: if no_dealer { true } else { verify },
        mac_checked: true,
    })
}
