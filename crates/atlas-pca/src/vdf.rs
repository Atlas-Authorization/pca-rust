//! Wesolowski VDF over an RSA group plus the PCA timelock (`@atlasauth/pca-vdf`). Pure big-integer math on `rsa::BigUint` (the crate's
//! existing big-integer dependency; not constant time, every input is public). Same domains, transcript, error texts and check order as
//! the reference, so challenge primes, proofs and timelock inputs are byte-identical. A VDF in an RSA group needs a modulus of unknown
//! factorisation ([`rsa_2048_challenge_modulus`] or a ceremony modulus); [`insecure_dev_setup`] is for tests only.
//!
//! Step counts are `f64` (a JavaScript number): a non-integer, negative or above-2^53-1 count is refused exactly as the reference does.
//! Integers that may be negative (an attacker-supplied `x`, `y`, `pi`, `N`) are [`Int`]; moduli that must be positive are `BigUint`.

use rsa::BigUint;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

pub const CHALLENGE_PRIME_BITS: u32 = 256;
pub const INSECURE_DEV_SETUP_DEFAULT_BITS: u32 = 2048;
pub const MIN_PRODUCTION_MODULUS_BITS: usize = 2048;
const MAX_SAFE: f64 = 9007199254740991.0;

const RSA_2048: &str = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357";

/// The RSA-2048 challenge number (factorisation unknown).
pub fn rsa_2048_challenge_modulus() -> BigUint {
    BigUint::parse_bytes(RSA_2048.as_bytes(), 10).expect("RSA-2048 constant")
}

// ---- integers

fn zero() -> BigUint {
    BigUint::from(0u8)
}

fn big(n: u64) -> BigUint {
    BigUint::from(n)
}

fn low64(n: &BigUint) -> u64 {
    n.to_bytes_le().iter().take(8).rev().fold(0u64, |a, b| (a << 8) | *b as u64)
}

fn is_odd(n: &BigUint) -> bool {
    n.to_bytes_le()[0] & 1 == 1
}

/// 2^k.
fn pow2(k: usize) -> BigUint {
    let mut v = vec![0u8; k / 8 + 1];
    v[0] = 1 << (k % 8);
    BigUint::from_bytes_be(&v)
}

fn half(n: &BigUint) -> BigUint {
    n / &big(2)
}

/// base^exp mod m for m >= 1 (m == 1 gives 0).
fn mp(base: &BigUint, exp: &BigUint, m: &BigUint) -> BigUint {
    if *m == big(1) {
        return zero();
    }
    (base % m).modpow(exp, m)
}

fn gcd_u(a: &BigUint, b: &BigUint) -> BigUint {
    let (mut x, mut y) = (a.clone(), b.clone());
    while y != zero() {
        let r = &x % &y;
        x = y;
        y = r;
    }
    x
}

/// A signed integer (JavaScript BigInt) as sign + magnitude; zero is never negative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Int {
    neg: bool,
    mag: BigUint,
}

impl Int {
    /// Decimal text with an optional leading `-` (anything else, an empty string or a fraction, is refused).
    pub fn parse(s: &str) -> Result<Int, String> {
        let (neg, d) = match s.strip_prefix('-') {
            Some(d) => (true, d),
            None => (false, s),
        };
        if d.is_empty() || !d.bytes().all(|c| c.is_ascii_digit()) {
            return Err(format!("Cannot convert {s} to a BigInt"));
        }
        let mag = BigUint::parse_bytes(d.as_bytes(), 10).ok_or_else(|| format!("Cannot convert {s} to a BigInt"))?;
        Ok(Int { neg: neg && mag != zero(), mag })
    }

    pub fn from_biguint(mag: BigUint) -> Int {
        Int { neg: false, mag }
    }

    pub fn is_negative(&self) -> bool {
        self.neg
    }

    pub fn magnitude(&self) -> &BigUint {
        &self.mag
    }

    pub fn to_decimal(&self) -> String {
        format!("{}{}", if self.neg { "-" } else { "" }, self.mag.to_str_radix(10))
    }

    /// The non-negative residue ((x % n) + n) % n for n >= 1.
    fn umod(&self, n: &BigUint) -> BigUint {
        let r = &self.mag % n;
        if self.neg && r != zero() {
            n - &r
        } else {
            r
        }
    }
}

/// A JavaScript number as a non-negative safe-integer step count.
fn steps_of(t: f64) -> Option<u64> {
    (t.is_finite() && t.fract() == 0.0 && (0.0..=MAX_SAFE).contains(&t)).then_some(t as u64)
}

fn steps(t: f64) -> Result<u64, String> {
    steps_of(t).ok_or_else(|| format!("VDF: steps T must be a non-negative safe integer, got {t}"))
}

/// Big-endian minimal bytes (zero is one zero byte).
pub fn big_int_to_bytes(v: &Int) -> Result<Vec<u8>, String> {
    if v.neg {
        return Err("bigIntToBytes: negative value".into());
    }
    Ok(v.mag.to_bytes_be())
}

pub fn bytes_to_big_int(b: &[u8]) -> BigUint {
    BigUint::from_bytes_be(b)
}

fn lp(b: &[u8]) -> Vec<u8> {
    let mut o = (b.len() as u32).to_be_bytes().to_vec();
    o.extend_from_slice(b);
    o
}

/// The greatest common divisor of |a| and |b|.
pub fn gcd(a: &Int, b: &Int) -> BigUint {
    gcd_u(&a.mag, &b.mag)
}

fn is_unit(v: &BigUint, n: &BigUint) -> bool {
    *v != zero() && v < n && gcd_u(v, n) == big(1)
}

fn is_unit_int(v: &Int, n: &BigUint) -> bool {
    !v.neg && is_unit(&v.mag, n)
}

/// base^exp mod m (a negative exponent is refused: no inverse in a group of unknown order).
pub fn modpow(base: &Int, exp: &Int, m: &Int) -> Result<BigUint, String> {
    if m.neg || m.mag == zero() {
        return Err("modpow: modulus must be positive".into());
    }
    if m.mag == big(1) {
        return Ok(zero());
    }
    if exp.neg {
        return Err("modpow: negative exponent (no inverse in a group of unknown order)".into());
    }
    Ok(mp(&base.umod(&m.mag), &exp.mag, &m.mag))
}

// ---- primality: Baillie-PSW (strong Miller-Rabin on the first 25 primes + strong Lucas)

const SMALL_PRIMES: [u64; 25] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97];

fn is_perfect_square(n: &BigUint) -> bool {
    if *n < big(2) {
        return true;
    }
    let mut x = pow2(n.bits().div_ceil(2));
    loop {
        let y = half(&(&x + n / &x));
        if y >= x {
            return &x * &x == *n;
        }
        x = y;
    }
}

/// Jacobi symbol (d / n) for odd n >= 3.
fn jacobi(d: i64, n: &BigUint) -> i32 {
    let m = &big(d.unsigned_abs()) % n;
    let mut a = if d < 0 && m != zero() { n - &m } else { m };
    let mut n = n.clone();
    let mut r = 1;
    while a != zero() {
        while !is_odd(&a) {
            a = half(&a);
            let m8 = low64(&n) & 7;
            if m8 == 3 || m8 == 5 {
                r = -r;
            }
        }
        std::mem::swap(&mut a, &mut n);
        if low64(&a) & 3 == 3 && low64(&n) & 3 == 3 {
            r = -r;
        }
        a = &a % &n;
    }
    if n == big(1) {
        r
    } else {
        0
    }
}

fn mod_i(v: i64, n: &BigUint) -> BigUint {
    let m = &big(v.unsigned_abs()) % n;
    if v < 0 && m != zero() {
        n - &m
    } else {
        m
    }
}

fn sub_mod(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
    (&(a % n) + n - &(b % n)) % n
}

fn is_strong_lucas_u(n: &BigUint) -> bool {
    if *n < big(3) || !is_odd(n) || is_perfect_square(n) {
        return false;
    }
    let mut d: i64 = 5;
    loop {
        let j = jacobi(d, n);
        if j == -1 {
            break;
        }
        if j == 0 && big(d.unsigned_abs()) != *n {
            return false;
        }
        d = if d > 0 { -(d + 2) } else { -d + 2 };
    }
    let q = (1 - d) / 4; // exact: D = 1 (mod 4)
    let (qm, dm) = (mod_i(q, n), mod_i(d, n));
    let halve = |x: &BigUint| if is_odd(x) { half(&(x + n)) } else { half(x) };
    let mut dd = n + &big(1);
    let mut s = 0usize;
    while !is_odd(&dd) {
        dd = half(&dd);
        s += 1;
    }
    let (mut u, mut v, mut qk) = (big(1), big(1), qm.clone());
    let bytes = dd.to_bytes_be();
    let bits: Vec<bool> = bytes.iter().flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1)).skip_while(|b| !*b).collect();
    for bit in bits.iter().skip(1) {
        u = &u * &v % n;
        v = sub_mod(&(&v * &v), &(&qk * &big(2)), n);
        qk = &qk * &qk % n;
        if *bit {
            let u1 = halve(&((&u + &v) % n));
            let v1 = halve(&((&dm * &u + &v) % n));
            u = u1;
            v = v1;
            qk = &qk * &qm % n;
        }
    }
    if u == zero() || v == zero() {
        return true;
    }
    for _ in 1..s {
        v = sub_mod(&(&v * &v), &(&qk * &big(2)), n);
        if v == zero() {
            return true;
        }
        qk = &qk * &qk % n;
    }
    false
}

fn is_mr_u(n: &BigUint) -> bool {
    if *n < big(3) || !is_odd(n) {
        return false;
    }
    let nm1 = n - &big(1);
    let mut d = nm1.clone();
    let mut s = 0u64;
    while !is_odd(&d) {
        d = half(&d);
        s += 1;
    }
    'witness: for a in SMALL_PRIMES {
        let base = &big(a) % n;
        if base == zero() {
            continue;
        }
        let mut x = mp(&base, &d, n);
        if x == big(1) || x == nm1 {
            continue;
        }
        for _ in 1..s {
            x = &x * &x % n;
            if x == nm1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

fn is_prime_u(n: &BigUint) -> bool {
    if *n < big(2) {
        return false;
    }
    for p in SMALL_PRIMES {
        let bp = big(p);
        if *n == bp {
            return true;
        }
        if n % &bp == zero() {
            return false;
        }
    }
    is_mr_u(n) && is_strong_lucas_u(n)
}

/// Trial division by the small primes, then strong Miller-Rabin and strong Lucas.
pub fn is_probable_prime(n: &Int) -> bool {
    !n.neg && is_prime_u(&n.mag)
}

/// Strong Miller-Rabin to the first 25 prime bases.
pub fn is_miller_rabin_probable_prime(n: &Int) -> bool {
    !n.neg && is_mr_u(&n.mag)
}

pub fn is_strong_lucas_probable_prime(n: &Int) -> bool {
    !n.neg && is_strong_lucas_u(&n.mag)
}

// ---- Fiat-Shamir challenge prime

const HASH_TO_PRIME_DOMAIN: &str = "atlas-pca/vdf/wesolowski/hash-to-prime/v1\0";

/// Masks `raw` (big-endian, ceil(bits/8) bytes) to `bits` bits and forces the top and bottom bit.
fn shape_candidate(mut raw: Vec<u8>, bits: usize) -> BigUint {
    if bits % 8 != 0 {
        raw[0] &= (1u8 << (bits % 8)) - 1;
    }
    raw[0] |= 1 << ((bits - 1) % 8);
    let last = raw.len() - 1;
    raw[last] |= 1;
    BigUint::from_bytes_be(&raw)
}

/// The challenge prime's bit length: the default, or an integer in [8, 8192]. Its own function so the 8192 edge is checked without the
/// 8192-bit prime search (minutes) that accepting it starts.
fn challenge_bits(bits: Option<f64>) -> Result<usize, String> {
    let b = match bits {
        None => CHALLENGE_PRIME_BITS as f64,
        Some(b) => b,
    };
    if !(b.is_finite() && b.fract() == 0.0 && (8.0..=8192.0).contains(&b)) {
        return Err("hashToPrime: bits must be an integer in [8, 8192]".into());
    }
    Ok(b as usize)
}

/// The challenge prime of (x, y, T, N); `bits` None = 256, otherwise an integer in [8, 8192].
pub fn hash_to_prime(x: &Int, y: &Int, t: f64, n: &BigUint, bits: Option<f64>) -> Result<BigUint, String> {
    let b = challenge_bits(bits)?;
    let st = steps(t)?;
    if *n == zero() {
        return Err("Division by zero".into());
    }
    let mut tr = HASH_TO_PRIME_DOMAIN.as_bytes().to_vec();
    tr.extend(lp(&x.umod(n).to_bytes_be()));
    tr.extend(lp(&y.umod(n).to_bytes_be()));
    tr.extend(lp(&big(st).to_bytes_be()));
    tr.extend(lp(&n.to_bytes_be()));
    tr.extend(lp(&(b as u32).to_be_bytes()));
    let seed = Sha256::digest(&tr);
    let need = b.div_ceil(8);
    for counter in 0u64.. {
        let mut chunks = Vec::new();
        let mut block = 0u32;
        while chunks.len() < need {
            let mut h = Sha256::new();
            h.update(seed);
            h.update(counter.to_be_bytes());
            h.update(block.to_be_bytes());
            chunks.extend_from_slice(&h.finalize());
            block += 1;
        }
        chunks.truncate(need);
        let cand = shape_candidate(chunks, b);
        if is_prime_u(&cand) {
            return Ok(cand);
        }
    }
    unreachable!("a challenge prime exists for every transcript")
}

// ---- the VDF

/// x^(2^T) mod N by T squarings.
pub fn sequential_square(x: &Int, t: f64, n: &BigUint) -> Result<BigUint, String> {
    if *n <= big(1) {
        return Err("VDF: modulus N must be > 1".into());
    }
    let st = steps(t)?;
    let mut y = x.umod(n);
    for _ in 0..st {
        y = &y * &y % n;
    }
    Ok(y)
}

/// pi = x^floor(2^T / l) mod N by running long division (never materialises 2^T).
fn wesolowski_proof(x: &BigUint, t: u64, l: &BigUint, n: &BigUint) -> BigUint {
    let xr = x % n;
    let mut pi = &big(1) % n;
    let mut r = &big(1) % l;
    for _ in 0..t {
        let two_r = &r * &big(2);
        let b = two_r >= *l;
        r = if b { two_r - l } else { two_r };
        pi = &pi * &pi % n;
        if b {
            pi = &pi * &xr % n;
        }
    }
    pi
}

fn bad_modulus(n: &BigUint) -> bool {
    *n <= big(3) || !is_odd(n)
}

fn nontrivial_unit(xr: &BigUint, n: &BigUint) -> bool {
    is_unit(xr, n) && *xr != big(1) && *xr != n - &big(1)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VdfProof {
    pub y: BigUint,
    pub pi: BigUint,
}

/// The smaller of y and N - y (y must not exceed N).
pub fn canonical_vdf_output(y: &BigUint, n: &BigUint) -> Result<BigUint, String> {
    if y > n {
        return Err("canonicalVdfOutput: y exceeds N".into());
    }
    let c = n - y;
    Ok(if *y > c { c } else { y.clone() })
}

fn eval(x: &Int, t: f64, n: &BigUint, canonical: bool) -> Result<VdfProof, String> {
    if bad_modulus(n) {
        return Err("VDF: modulus N must be odd and > 3".into());
    }
    let st = steps(t)?;
    let xr = x.umod(n);
    if !nontrivial_unit(&xr, n) {
        return Err("VDF: input x must be a non-trivial unit mod N (not 0, 1, -1, or sharing a factor with N)".into());
    }
    let mut y = sequential_square(x, t, n)?;
    if canonical {
        y = canonical_vdf_output(&y, n)?;
    }
    let l = hash_to_prime(x, &Int::from_biguint(y.clone()), t, n, None)?;
    let mut pi = wesolowski_proof(&xr, st, &l, n);
    if canonical {
        pi = canonical_vdf_output(&pi, n)?;
    }
    Ok(VdfProof { y, pi })
}

/// y = x^(2^T) mod N with the Wesolowski proof pi.
pub fn vdf_eval(x: &Int, t: f64, n: &BigUint) -> Result<VdfProof, String> {
    eval(x, t, n, false)
}

/// [`vdf_eval`] with y and pi folded to the smaller of v and N - v.
pub fn vdf_eval_canonical(x: &Int, t: f64, n: &BigUint) -> Result<VdfProof, String> {
    eval(x, t, n, true)
}

/// A verification result: valid, or the reason it was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VdfVerdict {
    Valid,
    /// One of `malformed-input`, `bad-modulus`, `bad-steps`, `non-canonical-y`, `non-canonical-pi`, `bad-input-x`, `equation-mismatch`.
    Rejected(&'static str),
}

impl VdfVerdict {
    pub fn is_ok(&self) -> bool {
        *self == VdfVerdict::Valid
    }

    pub fn reason(&self) -> Option<&'static str> {
        match self {
            VdfVerdict::Valid => None,
            VdfVerdict::Rejected(r) => Some(r),
        }
    }
}

fn verify(x: &Int, y: &Int, pi: &Int, t: f64, n: &Int, canonical: bool) -> VdfVerdict {
    use VdfVerdict::Rejected;
    if n.neg || bad_modulus(&n.mag) {
        return Rejected("bad-modulus");
    }
    let nn = &n.mag;
    let Some(st) = steps_of(t) else { return Rejected("bad-steps") };
    let folded = |v: &BigUint| *v > nn - v;
    if !is_unit_int(y, nn) || (canonical && folded(&y.mag)) {
        return Rejected("non-canonical-y");
    }
    if !is_unit_int(pi, nn) || (canonical && folded(&pi.mag)) {
        return Rejected("non-canonical-pi");
    }
    let xr = x.umod(nn);
    if !nontrivial_unit(&xr, nn) {
        return Rejected("bad-input-x");
    }
    let Ok(l) = hash_to_prime(x, y, t, nn, None) else { return Rejected("malformed-input") };
    let r = mp(&big(2), &big(st), &l);
    let lhs = &mp(&pi.mag, &l, nn) * &mp(&xr, &r, nn) % nn;
    if lhs == y.mag || (canonical && lhs == nn - &y.mag) {
        VdfVerdict::Valid
    } else {
        Rejected("equation-mismatch")
    }
}

/// Verifies (y, pi) for x, T, N; it never fails except by returning a refusal reason.
pub fn vdf_verify_detailed(x: &Int, y: &Int, pi: &Int, t: f64, n: &Int) -> VdfVerdict {
    verify(x, y, pi, t, n, false)
}

/// [`vdf_verify_detailed`] requiring the canonical (smaller-half) y and pi.
pub fn vdf_verify_canonical_detailed(x: &Int, y: &Int, pi: &Int, t: f64, n: &Int) -> VdfVerdict {
    verify(x, y, pi, t, n, true)
}

// ---- modulus screening

fn dev_moduli() -> &'static Mutex<HashSet<Vec<u8>>> {
    static S: OnceLock<Mutex<HashSet<Vec<u8>>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashSet::new()))
}

fn screened_moduli() -> &'static Mutex<HashSet<Vec<u8>>> {
    static S: OnceLock<Mutex<HashSet<Vec<u8>>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashSet::new()))
}

fn screen_primes() -> &'static [u32] {
    static P: OnceLock<Vec<u32>> = OnceLock::new();
    P.get_or_init(|| {
        let limit = 1usize << 16;
        let mut sieve = vec![false; limit];
        let mut out = Vec::new();
        for i in 2..limit {
            if sieve[i] {
                continue;
            }
            out.push(i as u32);
            let mut j = i * i;
            while j < limit {
                sieve[j] = true;
                j += i;
            }
        }
        out
    })
}

/// A test-only modulus whose factors are known (so it provides no delay) and is registered as such.
#[derive(Clone, Debug)]
pub struct InsecureDevSetup {
    pub n: BigUint,
    pub p: BigUint,
    pub q: BigUint,
    pub bits: usize,
}

fn random_prime(bits: usize) -> Result<BigUint, String> {
    if bits < 16 {
        return Err("randomPrime: bits too small".into());
    }
    for _ in 0..50_000 {
        let mut raw = vec![0u8; bits.div_ceil(8)];
        getrandom::getrandom(&mut raw).map_err(|e| e.to_string())?;
        let cand = shape_candidate(raw, bits);
        if is_prime_u(&cand) {
            return Ok(cand);
        }
    }
    Err("insecureDevSetup: randomness source failed to yield a prime (stuck or constant RNG?)".into())
}

/// A random RSA modulus of about `bits` bits (>= 32) for tests; registered so [`check_production_modulus`] refuses it.
pub fn insecure_dev_setup(bits: u32) -> Result<InsecureDevSetup, String> {
    if bits < 32 {
        return Err("insecureDevSetup: bits must be a safe integer >= 32".into());
    }
    let h = (bits / 2) as usize;
    let p = random_prime(h)?;
    let mut q = random_prime(bits as usize - h)?;
    let mut i = 0;
    while p == q {
        if i >= 8 {
            return Err("insecureDevSetup: randomness source returned the same prime repeatedly (constant RNG?)".into());
        }
        q = random_prime(bits as usize - h)?;
        i += 1;
    }
    let n = &p * &q;
    dev_moduli().lock().unwrap_or_else(|e| e.into_inner()).insert(n.to_bytes_be());
    let nb = n.bits();
    Ok(InsecureDevSetup { n, p, q, bits: nb })
}

/// Screens a modulus for production use: `Ok(())`, or the reason it is refused.
pub fn check_production_modulus(n: &Int) -> Result<(), String> {
    if n.neg {
        return Err("modulus is too small".into());
    }
    check_production_u(&n.mag)
}

fn check_production_u(n: &BigUint) -> Result<(), String> {
    let key = n.to_bytes_be();
    let dev = dev_moduli().lock().unwrap_or_else(|e| e.into_inner()).contains(&key);
    if dev {
        return Err("modulus came from insecureDevSetup(): its factors are known, so it provides no delay".into());
    }
    if screened_moduli().lock().unwrap_or_else(|e| e.into_inner()).contains(&key) {
        return Ok(());
    }
    if *n <= big(3) {
        return Err("modulus is too small".into());
    }
    if n.bits() < MIN_PRODUCTION_MODULUS_BITS {
        return Err(format!("modulus is below {MIN_PRODUCTION_MODULUS_BITS} bits"));
    }
    if !is_odd(n) {
        return Err("modulus is even".into());
    }
    if is_perfect_square(n) {
        return Err("modulus is a perfect square".into());
    }
    if is_prime_u(n) {
        return Err("modulus is prime (group order N-1 is public)".into());
    }
    for p in screen_primes() {
        if n % &big(*p as u64) == zero() {
            return Err(format!("modulus has the small prime factor {p}"));
        }
    }
    screened_moduli().lock().unwrap_or_else(|e| e.into_inner()).insert(key);
    Ok(())
}

// ---- PCA timelock: the VDF challenge is bound to the action and to an unpredictable beacon

const X_DERIVATION_DOMAIN: &str = "atlas-pca/vdf/timelock/input/v2\0";

/// A string is an opaque, precomputed digest; any other value is a PCActn digested like the ledger (strict canonical hash).
pub fn action_digest(action: &Value) -> Result<String, String> {
    match action {
        Value::String(s) => Ok(s.clone()),
        v => crate::hash_canonical_strict(v).ok_or_else(|| "timelock: action is outside the strict canonical JSON profile".to_string()),
    }
}

/// x in [2, N) bound to the action and the beacon; deterministic.
pub fn derive_timelock_input(action: &Value, n: &BigUint, beacon: &[u8]) -> Result<BigUint, String> {
    if *n <= big(3) {
        return Err("deriveTimelockInput: modulus N must be a bigint > 3".into());
    }
    let digest = action_digest(action)?;
    if beacon.is_empty() {
        return Err("timelock: a non-empty beacon (unpredictable, post-action value) is required".into());
    }
    let mut msg = X_DERIVATION_DOMAIN.as_bytes().to_vec();
    msg.extend(lp(digest.as_bytes()));
    msg.extend(lp(beacon));
    let raw = BigUint::from_bytes_be(&Sha256::digest(&msg)) % n;
    Ok(if raw <= big(1) { raw + big(2) } else { raw })
}

fn require_production_modulus(n: &BigUint, allow_insecure_dev: bool) -> Result<(), String> {
    if allow_insecure_dev {
        return Ok(());
    }
    check_production_u(n).map_err(|why| {
        format!("timelock: refusing this modulus: {why}. Use RSA_2048_CHALLENGE_MODULUS or a ceremony modulus; tests may pass allowInsecureDevModulus: true.")
    })
}

fn require_steps(s: f64) -> Result<u64, String> {
    steps_of(s).filter(|v| *v >= 1).ok_or_else(|| format!("timelock: steps must be a safe integer >= 1, got {s}"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimelockRequirement {
    pub x: BigUint,
    pub steps: u64,
    pub n: BigUint,
    pub action_digest: String,
}

/// The requirement an action must be accompanied by a proof of.
pub fn require_timelock(action: &Value, steps: f64, n: &BigUint, beacon: &[u8], allow_insecure_dev_modulus: bool) -> Result<TimelockRequirement, String> {
    let s = require_steps(steps)?;
    require_production_modulus(n, allow_insecure_dev_modulus)?;
    let x = derive_timelock_input(action, n, beacon)?;
    Ok(TimelockRequirement { x, steps: s, n: n.clone(), action_digest: action_digest(action)? })
}

/// The proof an elapsed timelock produces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimelockProof {
    pub y: Int,
    pub pi: Int,
    pub steps: u64,
}

impl TimelockProof {
    /// Reads `{kind: "vdf-timelock-proof", y, pi, steps}` (y and pi decimal strings); `None` for anything malformed, which
    /// [`verify_timelock`] treats as a failed proof.
    pub fn from_json(v: &Value) -> Option<TimelockProof> {
        let o = v.as_object()?;
        if o.get("kind")?.as_str()? != "vdf-timelock-proof" {
            return None;
        }
        let steps = steps_of(o.get("steps")?.as_f64()?)?;
        Some(TimelockProof { y: Int::parse(o.get("y")?.as_str()?).ok()?, pi: Int::parse(o.get("pi")?.as_str()?).ok()?, steps })
    }
}

/// Runs the VDF: the squarings ARE the cooling-off, so this is deliberately slow.
pub fn prove_timelock_elapsed(action: &Value, steps: f64, n: &BigUint, beacon: &[u8], allow_insecure_dev_modulus: bool) -> Result<TimelockProof, String> {
    let s = require_steps(steps)?;
    require_production_modulus(n, allow_insecure_dev_modulus)?;
    let x = derive_timelock_input(action, n, beacon)?;
    let p = vdf_eval_canonical(&Int::from_biguint(x), s as f64, n)?;
    Ok(TimelockProof { y: Int::from_biguint(p.y), pi: Int::from_biguint(p.pi), steps: s })
}

/// Fails closed: any malformed input or refused modulus is false. Offline, no clock.
pub fn verify_timelock(action: &Value, proof: &TimelockProof, steps: f64, n: &BigUint, beacon: &[u8], allow_insecure_dev_modulus: bool) -> bool {
    let Ok(required) = require_steps(steps) else { return false };
    if require_production_modulus(n, allow_insecure_dev_modulus).is_err() || proof.steps != required {
        return false;
    }
    let Ok(x) = derive_timelock_input(action, n, beacon) else { return false };
    vdf_verify_canonical_detailed(&Int::from_biguint(x), &proof.y, &proof.pi, required as f64, &Int::from_biguint(n.clone())).is_ok()
}

#[cfg(test)]
mod challenge_bits_test {
    use super::*;

    #[test]
    fn the_bit_length_range_is_inclusive_integral_and_finite() {
        assert_eq!(challenge_bits(None), Ok(CHALLENGE_PRIME_BITS as usize));
        assert_eq!(challenge_bits(Some(8.0)), Ok(8));
        assert_eq!(challenge_bits(Some(8192.0)), Ok(8192));
        for bad in [7.0, 8193.0, 8.5, 1e300, f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -8.0] {
            assert!(challenge_bits(Some(bad)).is_err(), "{bad}");
        }
    }
}
