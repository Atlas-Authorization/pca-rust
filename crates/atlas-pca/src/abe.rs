//! Proof-carrying encryption: FAME ciphertext-policy attribute-based encryption (Agrawal and Chase, ACM CCS 2017, ePrint
//! 2017/807) in the asymmetric BLS12-381 pairing, with the payload sealed under AES-256-GCM and the whole header
//! authenticated (the `@atlasauth/pca-abe` surface).
//!
//! The pairing, hash-to-curve, point and scalar-field arithmetic is the audited `blst` library (through the thin safe layer
//! [`crate::bbs::ec`]); nothing here implements field or pairing math. Keys, ciphertexts and policies are generic JSON values
//! parsed fail-closed: a malformed ciphertext or key is a refusal, never a panic. Every deserialized point is subgroup-checked,
//! canonical and non-identity; every GT value must be a canonical order-r element.
//!
//! Honest limits (as the reference): no key revocation, the policy is public in the ciphertext, the master-key holder decrypts
//! everything, and it is not post-quantum. Secret scalars only meet blst's constant-time field and point operations.
use crate::bbs::ec::{self, Fr, Gt, G1, G2};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap, HashSet};
use zeroize::Zeroize;

/// The ciphertext algorithm label.
pub const ABE_ALG: &str = "fame-cpabe-bls12381-type3/aes-256-gcm";
const CEK_INFO: &str = "atlas-pca-abe/cek/v3";
const SALT_LEN: usize = 16;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
const ATTR_DST: &str = "ATLAS-PCA-ABE:FAME:H-G1:SHA256-SSWU-RO:v1";
/// Upper bound on total nodes in a policy tree (bounds work on untrusted input).
pub const MAX_POLICY_NODES: usize = 1024;
/// Upper bound on gate nesting along any root-to-leaf path (so that "encryptable" implies "decryptable" under the canonical JSON depth cap).
pub const MAX_POLICY_DEPTH: usize = 10;

fn b64u(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn unb64u(x: &Value) -> Option<Vec<u8>> {
    crate::decode_b64u_strict(x.as_str()?, None)
}

// ---- access structures -----------------------------------------------------------------------------------------------

/// The normalised access tree: every interior node is an explicit `t`-of-`n` gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tree {
    Leaf(String),
    Gate { t: usize, of: Vec<Tree> },
}

impl Tree {
    /// The wire form `{kind:"leaf",attr}` / `{kind:"gate",t,of}`.
    pub fn to_json(&self) -> Value {
        match self {
            Tree::Leaf(a) => json!({"kind": "leaf", "attr": a}),
            Tree::Gate { t, of } => json!({"kind": "gate", "t": t, "of": of.iter().map(Tree::to_json).collect::<Vec<_>>()}),
        }
    }

    pub fn leaf_count(&self) -> usize {
        match self {
            Tree::Leaf(_) => 1,
            Tree::Gate { of, .. } => of.iter().map(Tree::leaf_count).sum(),
        }
    }

    /// The leaf attributes in depth-first order.
    pub fn leaf_attrs(&self) -> Vec<&str> {
        fn go<'a>(n: &'a Tree, out: &mut Vec<&'a str>) {
            match n {
                Tree::Leaf(a) => out.push(a),
                Tree::Gate { of, .. } => of.iter().for_each(|c| go(c, out)),
            }
        }
        let mut out = Vec::new();
        go(self, &mut out);
        out
    }

    /// The first attribute named by two leaves: FAME needs an injective row labelling.
    pub fn first_repeated_attribute(&self) -> Option<&str> {
        let mut seen = HashSet::new();
        self.leaf_attrs().into_iter().find(|a| !seen.insert(*a))
    }

    /// The pure, non-cryptographic satisfaction check (a convenience / test oracle).
    pub fn satisfies(&self, has: &dyn Fn(&str) -> bool) -> bool {
        match self {
            Tree::Leaf(a) => has(a),
            Tree::Gate { t, of } => of.iter().filter(|c| c.satisfies(has)).count() >= *t,
        }
    }
}

/// An attribute string is well-formed UTF-16 iff it holds no unpaired surrogate. A Rust `&str` is valid Unicode and so always
/// is; this exists for parity with hosts whose strings can be ill-formed (a key issued for one would alias another).
fn is_ill_formed_utf16(_s: &str) -> bool {
    false
}

fn js_pos_int(v: &Value) -> Option<f64> {
    let f = v.as_f64()?;
    (f > 0.0 && f == f.trunc() && f.is_finite()).then_some(f)
}

fn fmt_num(f: f64) -> String {
    crate::intent_v2::js_number_string(f)
}

/// Validates and normalises an access structure; `Err(reason)` on any malformed node, empty gate, out-of-range threshold or
/// oversized tree.
///
/// - `{attr}` leaf; `{allOf: [...]}` AND; `{anyOf: [...]}` OR; `{threshold: k, of: [...]}` k-of-n.
pub fn normalize_policy_tree(policy: &Value) -> Result<Tree, String> {
    fn walk(p: &Value, path: &str, gates: usize, nodes: &mut usize) -> Result<Tree, String> {
        *nodes += 1;
        if *nodes > MAX_POLICY_NODES {
            return Err(format!("policy too large (> {MAX_POLICY_NODES} nodes)"));
        }
        let Some(m) = p.as_object() else { return Err(format!("{path}: not an object")) };
        let has = |k: &str| m.contains_key(k);
        if has("attr") {
            let attr = match m.get("attr").and_then(Value::as_str) {
                Some(s) if !s.is_empty() => s,
                _ => return Err(format!("{path}: 'attr' must be a non-empty string")),
            };
            if is_ill_formed_utf16(attr) {
                return Err(format!("{path}: 'attr' is not well-formed UTF-16"));
            }
            if has("allOf") || has("anyOf") || has("threshold") || has("of") {
                return Err(format!("{path}: a leaf must not mix 'attr' with a gate"));
            }
            return Ok(Tree::Leaf(attr.to_string()));
        }
        let gate_keys: Vec<&str> = ["allOf", "anyOf", "threshold", "of"].into_iter().filter(|k| has(k)).filter(|k| *k != "of" || !has("threshold")).collect();
        if gate_keys.len() > 1 {
            return Err(format!("{path}: ambiguous node ({}); a gate must use exactly one of allOf/anyOf/threshold", gate_keys.join(", ")));
        }
        if gate_keys.len() == 1 && gates + 1 > MAX_POLICY_DEPTH {
            return Err(format!("{path}: policy nested deeper than {MAX_POLICY_DEPTH} gates"));
        }
        let children = |raw: Option<&Value>, key: &str, nodes: &mut usize| -> Result<Vec<Tree>, String> {
            let list = match raw.and_then(Value::as_array) {
                Some(l) if !l.is_empty() => l,
                _ => return Err(format!("{path}: '{key}' must be a non-empty array")),
            };
            let mut out = Vec::with_capacity(list.len());
            for (i, c) in list.iter().enumerate() {
                out.push(walk(c, &format!("{path}.{key}[{i}]"), gates + 1, nodes)?);
            }
            Ok(out)
        };
        if has("allOf") {
            let kids = children(m.get("allOf"), "allOf", nodes)?;
            return Ok(Tree::Gate { t: kids.len(), of: kids });
        }
        if has("anyOf") {
            let kids = children(m.get("anyOf"), "anyOf", nodes)?;
            return Ok(Tree::Gate { t: 1, of: kids });
        }
        if has("threshold") {
            let Some(f) = m.get("threshold").and_then(js_pos_int) else { return Err(format!("{path}: 'threshold' must be a positive integer")) };
            let kids = children(m.get("of"), "of", nodes)?;
            if f > kids.len() as f64 {
                return Err(format!("{path}: threshold {} exceeds the number of branches ({})", fmt_num(f), kids.len()));
            }
            return Ok(Tree::Gate { t: f as usize, of: kids });
        }
        Err(format!("{path}: unknown policy node (expected attr/allOf/anyOf/threshold)"))
    }
    walk(policy, "policy", 0, &mut 0)
}

/// [`normalize_policy_tree`] as the wire JSON `{kind, ...}`.
pub fn normalize_policy(policy: &Value) -> Result<Value, String> {
    normalize_policy_tree(policy).map(|t| t.to_json())
}

/// Validates an untrusted ciphertext tree (`None` on any deviation); a bounded node budget limits the work.
fn parse_tree(x: &Value, gates: usize, nodes: &mut usize) -> Option<Tree> {
    *nodes += 1;
    let m = x.as_object();
    if *nodes > MAX_POLICY_NODES || m.is_none() {
        return None;
    }
    let m = m?;
    match m.get("kind").and_then(Value::as_str) {
        Some("leaf") => {
            let attr = m.get("attr").and_then(Value::as_str)?;
            if attr.is_empty() || is_ill_formed_utf16(attr) || m.len() != 2 {
                return None;
            }
            Some(Tree::Leaf(attr.to_string()))
        }
        Some("gate") => {
            if gates + 1 > MAX_POLICY_DEPTH || m.len() != 3 {
                return None;
            }
            let t = js_pos_int(m.get("t")?)?;
            let of = m.get("of")?.as_array()?;
            if of.is_empty() || t > of.len() as f64 || of.len() >= MAX_POLICY_NODES {
                return None;
            }
            let mut kids = Vec::with_capacity(of.len());
            for b in of {
                kids.push(parse_tree(b, gates + 1, nodes)?);
            }
            Some(Tree::Gate { t: t as usize, of: kids })
        }
        _ => None,
    }
}

fn parse_tree_json(x: &Value) -> Option<Tree> {
    parse_tree(x, 0, &mut 0)
}

/// Whether the attribute set satisfies the (normalised, wire-form) tree; `false` for a malformed tree.
pub fn satisfies(tree: &Value, attrs: &[String]) -> bool {
    match parse_tree_json(tree) {
        Some(t) => {
            let set: HashSet<&str> = attrs.iter().map(String::as_str).collect();
            t.satisfies(&|a| set.contains(a))
        }
        None => false,
    }
}

fn sort_utf16(v: &mut [String]) {
    v.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
}

/// Every attribute the tree names, de-duplicated and sorted (UTF-16 code unit order, as the reference sorts).
pub fn policy_attributes(tree: &Value) -> Vec<String> {
    let Some(t) = parse_tree_json(tree) else { return Vec::new() };
    let mut out: Vec<String> = t.leaf_attrs().into_iter().collect::<HashSet<_>>().into_iter().map(String::from).collect();
    sort_utf16(&mut out);
    out
}

// ---- FAME group arithmetic -----------------------------------------------------------------------------------------------

fn u32be(n: usize) -> [u8; 4] {
    (n as u32).to_be_bytes()
}

fn hash_to_g1(msg: &[u8]) -> G1 {
    G1::hash_to_curve(msg, ATTR_DST.as_bytes())
}

/// H(y, l, t): kind byte 1, length-prefixed UTF-8 attribute, l, t.
fn h_attr(attr: &str, l: u8, t: u8) -> G1 {
    let mut m = vec![1u8];
    m.extend_from_slice(&u32be(attr.len()));
    m.extend_from_slice(attr.as_bytes());
    m.extend_from_slice(&[l, t]);
    hash_to_g1(&m)
}

/// H0(j, l, t): the column-indexed oracle (kind byte 2).
fn h_col(j: usize, l: u8, t: u8) -> G1 {
    let mut m = vec![2u8];
    m.extend_from_slice(&u32be(j));
    m.extend_from_slice(&[l, t]);
    hash_to_g1(&m)
}

pub type G1x3 = [G1; 3];
pub type G2x3 = [G2; 3];

pub struct FameMpk {
    /// h^a1, h^a2
    pub h1: G2,
    pub h2: G2,
    /// e(g,h)^(d1*a1+d3), e(g,h)^(d2*a2+d3)
    pub t1: Gt,
    pub t2: Gt,
}

pub struct FameMsk {
    pub a: [Fr; 2],
    pub b: [Fr; 2],
    /// g^d1, g^d2, g^d3
    pub g: G1x3,
}

pub struct FameKey {
    pub k0: G2x3,
    pub kp: G1x3,
    pub attrs: HashMap<String, G1x3>,
}

pub struct FameCt {
    pub ct0: G2x3,
    pub rows: Vec<G1x3>,
}

fn gt_of_generators() -> Result<Gt, String> {
    ec::pairing_product(&[G1::generator()], &[G2::generator()]).ok_or_else(|| "abe: pairing failed".to_string())
}

pub fn fame_setup(a: [Fr; 2], b: [Fr; 2], d: [Fr; 3]) -> Result<(FameMpk, FameMsk), String> {
    let egh = gt_of_generators()?;
    let (g, h) = (G1::generator(), G2::generator());
    let mpk = FameMpk {
        h1: h.mul(&a[0]),
        h2: h.mul(&a[1]),
        t1: egh.pow(&d[0].mul(&a[0]).add(&d[2]).to_be_bytes()),
        t2: egh.pow(&d[1].mul(&a[1]).add(&d[2]).to_be_bytes()),
    };
    Ok((mpk, FameMsk { a, b, g: [g.mul(&d[0]), g.mul(&d[1]), g.mul(&d[2])] }))
}

/// (sum_l oracle(l)^pow[l] + g^sigma)^aInv.
fn key_term(oracle: &dyn Fn(u8) -> G1, pow: &[Fr; 3], sigma: &Fr, a_inv: &Fr) -> G1 {
    let mut sum = G1::generator().mul(sigma);
    for l in 0..3u8 {
        sum = sum.add(&oracle(l).mul(&pow[l as usize]));
    }
    sum.mul(a_inv)
}

pub fn fame_keygen(msk: &FameMsk, attrs: &[String], r: [Fr; 2], sigmas: &[Fr], sigma_prime: &Fr) -> Result<FameKey, String> {
    let mut pow = [msk.b[0].mul(&r[0]), msk.b[1].mul(&r[1]), r[0].add(&r[1])];
    let a_inv = [msk.a[0].inv().ok_or("abe: inverse of zero")?, msk.a[1].inv().ok_or("abe: inverse of zero")?];
    let h = G2::generator();
    let k0 = [h.mul(&pow[0]), h.mul(&pow[1]), h.mul(&pow[2])];
    let mut out = HashMap::with_capacity(attrs.len());
    for (i, y) in attrs.iter().enumerate() {
        let sg = sigmas.get(i).ok_or("fameKeygen: one sigma per attribute is required")?;
        let comp = [
            key_term(&|l| h_attr(y, l, 0), &pow, sg, &a_inv[0]),
            key_term(&|l| h_attr(y, l, 1), &pow, sg, &a_inv[1]),
            G1::generator().mul(&Fr::zero().sub(sg)),
        ];
        out.insert(y.clone(), comp);
    }
    let kp = [
        key_term(&|l| h_col(0, l, 0), &pow, sigma_prime, &a_inv[0]).add(&msk.g[0]),
        key_term(&|l| h_col(0, l, 1), &pow, sigma_prime, &a_inv[1]).add(&msk.g[1]),
        G1::generator().mul(&Fr::zero().sub(sigma_prime)).add(&msk.g[2]),
    ];
    pow.iter_mut().for_each(Zeroize::zeroize);
    Ok(FameKey { k0, kp, attrs: out })
}

/// A span-program row: the leaf's attribute and its sparse vector (column -> coefficient; column 0 is always 1).
struct MspRow {
    attr: String,
    vec: Vec<(usize, Fr)>,
}

/// The leaves in depth-first order, each with its span-program row (Shamir down the tree).
fn build_rows(tree: &Tree) -> Vec<MspRow> {
    fn walk(n: &Tree, vec: &[(usize, Fr)], ncols: &mut usize, rows: &mut Vec<MspRow>) {
        match n {
            Tree::Leaf(a) => rows.push(MspRow { attr: a.clone(), vec: vec.to_vec() }),
            Tree::Gate { t, of } => {
                let base = *ncols;
                *ncols += t - 1;
                for (idx, child) in of.iter().enumerate() {
                    let mut cv = vec.to_vec();
                    let x = Fr::from_u64(idx as u64 + 1);
                    let mut pw = Fr::from_u64(1);
                    for k in 1..*t {
                        pw = pw.mul(&x);
                        cv.push((base + k - 1, pw));
                    }
                    walk(child, &cv, ncols, rows);
                }
            }
        }
    }
    let mut rows = Vec::new();
    walk(tree, &[(0, Fr::from_u64(1))], &mut 1, &mut rows);
    rows
}

pub fn fame_encrypt(mpk: &FameMpk, tree: &Tree, s: [Fr; 2]) -> (FameCt, Gt) {
    let rows = build_rows(tree);
    let mut memo: HashMap<(usize, u8), G1> = HashMap::new();
    let mut col_term = |j: usize, l: u8| -> G1 { *memo.entry((j, l)).or_insert_with(|| h_col(j, l, 0).mul(&s[0]).add(&h_col(j, l, 1).mul(&s[1]))) };
    let mut out = Vec::with_capacity(rows.len());
    for row in &rows {
        let mut tri = [G1::identity(), G1::identity(), G1::identity()];
        for l in 0..3u8 {
            let mut acc = h_attr(&row.attr, l, 0).mul(&s[0]).add(&h_attr(&row.attr, l, 1).mul(&s[1]));
            for (j, m) in &row.vec {
                acc = acc.add(&col_term(*j, l).mul(m));
            }
            tri[l as usize] = acc;
        }
        out.push(tri);
    }
    let h = G2::generator();
    let ct0 = [mpk.h1.mul(&s[0]), mpk.h2.mul(&s[1]), h.mul(&s[0].add(&s[1]))];
    let k = mpk.t1.pow(&s[0].to_be_bytes()).mul(&mpk.t2.pow(&s[1].to_be_bytes()));
    (FameCt { ct0, rows: out }, k)
}

/// Lagrange coefficients L_i(0) = prod_{j != i} x_j / (x_j - x_i); `None` on an empty set, a zero point or points that coincide mod r.
fn lagrange_at_zero(xs: &[Fr]) -> Option<Vec<Fr>> {
    if xs.is_empty() {
        return None;
    }
    let mut seen = HashSet::new();
    for x in xs {
        if x.is_zero() || !seen.insert(x.to_be_bytes()) {
            return None;
        }
    }
    let mut out = Vec::with_capacity(xs.len());
    for i in 0..xs.len() {
        let (mut num, mut den) = (Fr::from_u64(1), Fr::from_u64(1));
        for j in 0..xs.len() {
            if j != i {
                num = num.mul(&xs[j]);
                den = den.mul(&xs[j].sub(&xs[i]));
            }
        }
        out.push(num.mul(&den.inv()?));
    }
    Some(out)
}

enum Plan {
    Leaf(usize),
    Gate(Vec<(Fr, Plan)>),
}

/// Chooses, bottom-up, the first `t` satisfiable children of every gate; `None` when `has` does not satisfy the subtree.
fn plan_for(n: &Tree, has: &dyn Fn(&str) -> bool, offset: usize) -> Option<Plan> {
    match n {
        Tree::Leaf(a) => has(a).then_some(Plan::Leaf(offset)),
        Tree::Gate { t, of } => {
            let mut picked = Vec::new();
            let mut off = offset;
            for (i, child) in of.iter().enumerate() {
                if let Some(sub) = plan_for(child, has, off) {
                    picked.push((Fr::from_u64(i as u64 + 1), sub));
                }
                if picked.len() >= *t {
                    break;
                }
                off += child.leaf_count();
            }
            (picked.len() >= *t).then_some(Plan::Gate(picked))
        }
    }
}

fn plan_weights(p: &Plan, w: &Fr, out: &mut BTreeMap<usize, Fr>) -> bool {
    match p {
        Plan::Leaf(row) => {
            out.insert(*row, *w);
            true
        }
        Plan::Gate(of) => {
            let xs: Vec<Fr> = of.iter().map(|c| c.0).collect();
            let Some(lam) = lagrange_at_zero(&xs) else { return false };
            of.iter().zip(&lam).all(|(c, l)| plan_weights(&c.1, &w.mul(l), out))
        }
    }
}

/// Recovers the KEM key, or `None` when the key does not satisfy the tree or a point is degenerate.
pub fn fame_decrypt(key: &FameKey, tree: &Tree, ct: &FameCt) -> Option<Gt> {
    let rows = tree.leaf_attrs();
    if rows.len() != ct.rows.len() {
        return None;
    }
    let plan = plan_for(tree, &|a| key.attrs.contains_key(a), 0)?;
    let mut w = BTreeMap::new();
    if !plan_weights(&plan, &Fr::from_u64(1), &mut w) {
        return None;
    }
    let (mut g1s, mut g2s) = (Vec::new(), Vec::new());
    for l in 0..3usize {
        let mut ct_prod = G1::identity();
        let mut key_prod = key.kp[l];
        for (i, wi) in &w {
            let comp = key.attrs.get(rows[*i])?;
            ct_prod = ct_prod.add(&ct.rows[*i][l].mul(wi));
            key_prod = key_prod.add(&comp[l].mul(wi));
        }
        g1s.extend([key_prod, ct_prod.neg()]);
        g2s.extend([ct.ct0[l], key.k0[l]]);
    }
    ec::pairing_product(&g1s, &g2s)
}

// ---- GT helpers on the 576-byte canonical encoding -----------------------------------------------------------------

/// A canonical encoding of a non-identity element of the order-r subgroup.
pub fn gt_is_element(b: &[u8]) -> bool {
    Gt::from_bytes(b).is_some_and(|g| g.is_element())
}

/// `a^k` for a canonical Fp12 encoding and a 32-byte big-endian exponent.
pub fn gt_pow(a: &[u8], k: &[u8]) -> Option<Vec<u8>> {
    let k: [u8; 32] = k.try_into().ok()?;
    Some(Gt::from_bytes(a)?.pow(&k).to_bytes().to_vec())
}

pub fn gt_mul(a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    Some(Gt::from_bytes(a)?.mul(&Gt::from_bytes(b)?).to_bytes().to_vec())
}

/// prod_i e(g1s[i], g2s[i]) with one final exponentiation; canonical compressed non-identity prime-order points only.
pub fn pairing_product(g1s: &[Vec<u8>], g2s: &[Vec<u8>]) -> Option<Vec<u8>> {
    let a: Option<Vec<G1>> = g1s.iter().map(|b| G1::from_bytes_strict(b)).collect();
    let b: Option<Vec<G2>> = g2s.iter().map(|b| G2::from_bytes_strict(b)).collect();
    Some(ec::pairing_product(&a?, &b?)?.to_bytes().to_vec())
}

// ---- wire ------------------------------------------------------------------------------------------------------------------

fn g1_from(x: &Value) -> Option<G1> {
    let b = unb64u(x)?;
    if b.len() != 48 || b[0] & 0x40 != 0 {
        return None;
    }
    G1::from_bytes_strict(&b)
}

fn g2_from(x: &Value) -> Option<G2> {
    let b = unb64u(x)?;
    if b.len() != 96 || b[0] & 0x40 != 0 {
        return None;
    }
    G2::from_bytes_strict(&b)
}

fn tri<T>(x: &Value, read: impl Fn(&Value) -> Option<T>) -> Option<[T; 3]> {
    let l = x.as_array().filter(|l| l.len() == 3)?;
    Some([read(&l[0])?, read(&l[1])?, read(&l[2])?])
}

fn tri1_json(x: &G1x3) -> Value {
    json!([b64u(&x[0].to_bytes()), b64u(&x[1].to_bytes()), b64u(&x[2].to_bytes())])
}

fn tri2_json(x: &G2x3) -> Value {
    json!([b64u(&x[0].to_bytes()), b64u(&x[1].to_bytes()), b64u(&x[2].to_bytes())])
}

fn is_v2(v: Option<&Value>) -> bool {
    v.and_then(Value::as_f64) == Some(2.0)
}

fn random_scalar() -> Result<Fr, String> {
    loop {
        let mut b = [0u8; 48];
        getrandom::getrandom(&mut b).map_err(|e| format!("abe: {e}"))?;
        let v = Fr::from_be_reduce(&b);
        b.zeroize();
        if !v.is_zero() {
            return Ok(v);
        }
    }
}

/// A fresh master key pair `(mpk, msk)` as JSON values.
pub fn setup() -> Result<(Value, Value), String> {
    let mut s = Vec::with_capacity(7);
    for _ in 0..7 {
        s.push(random_scalar()?);
    }
    let (mpk, msk) = fame_setup([s[0], s[1]], [s[2], s[3]], [s[4], s[5], s[6]])?;
    s.iter_mut().for_each(Zeroize::zeroize);
    let mpk_j = json!({"v": 2, "curve": "bls12-381", "h": [b64u(&mpk.h1.to_bytes()), b64u(&mpk.h2.to_bytes())], "t": [b64u(&mpk.t1.to_bytes()), b64u(&mpk.t2.to_bytes())]});
    let msk_j = json!({"v": 2, "curve": "bls12-381",
        "a": [b64u(&msk.a[0].to_be_bytes()), b64u(&msk.a[1].to_be_bytes())],
        "b": [b64u(&msk.b[0].to_be_bytes()), b64u(&msk.b[1].to_be_bytes())],
        "g": tri1_json(&msk.g)});
    Ok((mpk_j, msk_j))
}

/// Exactly one encoding per scalar: 32 bytes, non-zero and < r.
fn canonical_scalar(x: &Value) -> Option<Fr> {
    let b = unb64u(x)?;
    let f = Fr::from_canonical(&b)?;
    (!f.is_zero()).then_some(f)
}

fn parse_msk(x: &Value) -> Result<FameMsk, String> {
    let bad = || "invalid master secret key".to_string();
    let m = x.as_object().filter(|m| is_v2(m.get("v"))).ok_or_else(bad)?;
    let pair = |k: &str| -> Option<[Fr; 2]> {
        let l = m.get(k)?.as_array().filter(|l| l.len() == 2)?;
        Some([canonical_scalar(&l[0])?, canonical_scalar(&l[1])?])
    };
    let (a, b) = (pair("a").ok_or_else(bad)?, pair("b").ok_or_else(bad)?);
    let g = m.get("g").and_then(|g| tri(g, g1_from)).ok_or_else(bad)?;
    Ok(FameMsk { a, b, g })
}

fn parse_mpk(x: &Value) -> Result<FameMpk, String> {
    let bad = || "invalid master public key".to_string();
    let m = x.as_object().filter(|m| is_v2(m.get("v"))).ok_or_else(bad)?;
    let h = m.get("h").and_then(Value::as_array).filter(|l| l.len() == 2).ok_or_else(bad)?;
    let t = m.get("t").and_then(Value::as_array).filter(|l| l.len() == 2).ok_or_else(bad)?;
    let gt = |v: &Value| unb64u(v).and_then(|b| Gt::from_bytes(&b)).filter(|g| g.is_element());
    Ok(FameMpk { h1: g2_from(&h[0]).ok_or_else(bad)?, h2: g2_from(&h[1]).ok_or_else(bad)?, t1: gt(&t[0]).ok_or_else(bad)?, t2: gt(&t[1]).ok_or_else(bad)? })
}

/// Issues a key for the (de-duplicated, in order) attribute tokens and returns it with the issued names.
fn issue(msk: &Value, attrs: &[String]) -> Result<(Value, Vec<String>), String> {
    let m = parse_msk(msk)?;
    let mut seen = HashSet::new();
    let names: Vec<String> = attrs.iter().filter(|a| seen.insert(a.as_str())).filter(|a| !a.is_empty() && !is_ill_formed_utf16(a)).cloned().collect();
    let r = [random_scalar()?, random_scalar()?];
    let sigmas: Vec<Fr> = names.iter().map(|_| random_scalar()).collect::<Result<_, _>>()?;
    let sp = random_scalar()?;
    let key = fame_keygen(&m, &names, r, &sigmas, &sp)?;
    let mut am = Map::new();
    for n in &names {
        am.insert(n.clone(), json!({"k": tri1_json(&key.attrs[n])}));
    }
    let k = json!({"v": 2, "curve": "bls12-381", "k0": tri2_json(&key.k0), "kp": tri1_json(&key.kp), "attrs": Value::Object(am)});
    Ok((k, names))
}

/// Issues a decryption key for an explicit set of attribute tokens (empty and ill-formed tokens are not issued).
pub fn keygen_for_attributes(msk: &Value, attrs: &[String]) -> Result<Value, String> {
    issue(msk, attrs).map(|k| k.0)
}

/// Like [`keygen_for_attributes`], also returning the attribute names the key was issued for, in order.
pub fn keygen_for_attributes_named(msk: &Value, attrs: &[String]) -> Result<(Value, Vec<String>), String> {
    issue(msk, attrs)
}

/// Parses an untrusted key; a malformed attribute component is treated as not held. `None` if K0, K' or the container is malformed.
fn parse_key(x: &Value) -> Option<FameKey> {
    let m = x.as_object().filter(|m| is_v2(m.get("v")))?;
    let am = m.get("attrs")?.as_object()?;
    let k0 = tri(m.get("k0")?, g2_from)?;
    let kp = tri(m.get("kp")?, g1_from)?;
    let mut attrs = HashMap::new();
    for (name, comp) in am {
        if let Some(k) = comp.as_object().and_then(|c| c.get("k")).and_then(|k| tri(k, g1_from)) {
            attrs.insert(name.clone(), k);
        }
    }
    Some(FameKey { k0, kp, attrs })
}

// ---- encrypt / decrypt -----------------------------------------------------------------------------------------------------

struct Ct {
    salt: String,
    iv: String,
    ct: String,
    tag: String,
    ct0: [String; 3],
    tree: Tree,
    rows: Vec<[String; 3]>,
}

impl Ct {
    fn header_json(&self) -> Value {
        json!({"v": 2, "alg": ABE_ALG, "salt": self.salt, "ct0": self.ct0, "tree": self.tree.to_json(), "rows": self.rows})
    }

    /// The authenticated header: the canonical JSON of everything but the AEAD fields.
    fn aad(&self) -> Result<Vec<u8>, String> {
        crate::canonicalize_strict(&self.header_json()).map(String::into_bytes)
    }

    fn json(&self) -> Value {
        let mut m = self.header_json().as_object().cloned().unwrap_or_default();
        m.insert("iv".into(), self.iv.clone().into());
        m.insert("ct".into(), self.ct.clone().into());
        m.insert("tag".into(), self.tag.clone().into());
        Value::Object(m)
    }
}

/// HKDF-SHA256 (RFC 5869) to 32 bytes: one expand block.
fn cek_of(ikm: &[u8], salt: &[u8]) -> [u8; 32] {
    fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
        for p in parts {
            m.update(p);
        }
        m.finalize().into_bytes().into()
    }
    let mut prk = hmac(salt, &[ikm]);
    let out = hmac(&prk, &[CEK_INFO.as_bytes(), &[1u8]]);
    prk.zeroize();
    out
}

/// Encrypts `plaintext` so that it decrypts only for a holder whose attributes satisfy `policy`. Errs on an invalid policy
/// (including one naming an attribute twice) or master public key.
pub fn encrypt_for_policy(mpk: &Value, policy: &Value, plaintext: &[u8]) -> Result<Value, String> {
    let tree = normalize_policy_tree(policy).map_err(|why| format!("invalid policy: {why}"))?;
    if let Some(dup) = tree.first_repeated_attribute() {
        return Err(format!("invalid policy: attribute {} is named by more than one leaf (single-use attributes only)", crate::js_stringify(&json!(dup))));
    }
    let pk = parse_mpk(mpk)?;
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| format!("abe: {e}"))?;
    let mut s = [random_scalar()?, random_scalar()?];
    let (fc, k) = fame_encrypt(&pk, &tree, s);
    s.iter_mut().for_each(Zeroize::zeroize);
    let mut c = Ct {
        salt: b64u(&salt),
        iv: String::new(),
        ct: String::new(),
        tag: String::new(),
        ct0: [b64u(&fc.ct0[0].to_bytes()), b64u(&fc.ct0[1].to_bytes()), b64u(&fc.ct0[2].to_bytes())],
        tree,
        rows: fc.rows.iter().map(|r| [b64u(&r[0].to_bytes()), b64u(&r[1].to_bytes()), b64u(&r[2].to_bytes())]).collect(),
    };
    let aad = c.aad().map_err(|_| "policy cannot be authenticated (header outside the canonical JSON profile)".to_string())?;
    let mut cek = cek_of(&k.to_bytes(), &salt);
    let cipher = Aes256Gcm::new_from_slice(&cek).map_err(|e| e.to_string())?;
    cek.zeroize();
    let mut iv = [0u8; IV_LEN];
    getrandom::getrandom(&mut iv).map_err(|e| format!("abe: {e}"))?;
    let sealed = cipher.encrypt(Nonce::from_slice(&iv), Payload { msg: plaintext, aad: &aad }).map_err(|_| "abe: seal failed".to_string())?;
    let cut = sealed.len() - TAG_LEN;
    c.iv = b64u(&iv);
    c.ct = b64u(&sealed[..cut]);
    c.tag = b64u(&sealed[cut..]);
    Ok(c.json())
}

fn str_tri(x: &Value) -> Option<[String; 3]> {
    tri(x, |e| {
        let s = e.as_str()?;
        crate::decode_b64u_strict(s, None).map(|_| s.to_string())
    })
}

fn parse_ct(x: &Value) -> Option<Ct> {
    let m = x.as_object()?;
    if !is_v2(m.get("v")) || m.get("alg").and_then(Value::as_str) != Some(ABE_ALG) {
        return None;
    }
    let field = |k: &str| -> Option<String> {
        let s = m.get(k)?.as_str()?;
        crate::decode_b64u_strict(s, None).map(|_| s.to_string())
    };
    let (salt, iv, ct, tag) = (field("salt")?, field("iv")?, field("ct")?, field("tag")?);
    let ct0 = str_tri(m.get("ct0")?)?;
    let tree = parse_tree_json(m.get("tree")?)?;
    let rows_v = m.get("rows")?.as_array()?;
    if rows_v.len() != tree.leaf_count() || tree.first_repeated_attribute().is_some() {
        return None;
    }
    let rows = rows_v.iter().map(str_tri).collect::<Option<Vec<_>>>()?;
    Some(Ct { salt, iv, ct, tag, ct0, tree, rows })
}

/// Validates an untrusted value as a ciphertext; `None` (fail closed) on any deviation. Unknown extra members are dropped.
pub fn parse_ciphertext(x: &Value) -> Option<Value> {
    parse_ct(x).map(|c| c.json())
}

/// The plaintext iff the key's attributes satisfy the ciphertext's policy AND the AEAD authenticates; otherwise `None`. Never panics.
pub fn decrypt(key: &Value, ciphertext: &Value) -> Option<Vec<u8>> {
    let ct = parse_ct(ciphertext)?;
    let pk = parse_key(key)?;
    let dec = |s: &str| crate::decode_b64u_strict(s, None);
    let (salt, iv, body, tag) = (dec(&ct.salt)?, dec(&ct.iv)?, dec(&ct.ct)?, dec(&ct.tag)?);
    let ct0 = tri(&json!(ct.ct0), g2_from)?;
    let rows: Vec<G1x3> = ct.rows.iter().map(|r| tri(&json!(r), g1_from)).collect::<Option<_>>()?;
    let k = fame_decrypt(&pk, &ct.tree, &FameCt { ct0, rows })?;
    let aad = ct.aad().ok()?; // header outside the canonical profile: cannot be authentic
    let mut cek = cek_of(&k.to_bytes(), &salt);
    let cipher = Aes256Gcm::new_from_slice(&cek).ok()?;
    cek.zeroize();
    if iv.len() != IV_LEN || tag.len() != TAG_LEN {
        return None;
    }
    let mut sealed = body;
    sealed.extend_from_slice(&tag);
    cipher.decrypt(Nonce::from_slice(&iv), Payload { msg: &sealed, aad: &aad }).ok()
}

/// [`decrypt`] with the plaintext decoded as UTF-8 text (invalid sequences replaced, a leading BOM dropped).
pub fn decrypt_text(key: &Value, ciphertext: &Value) -> Option<String> {
    let pt = decrypt(key, ciphertext)?;
    let pt = pt.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(&pt);
    Some(String::from_utf8_lossy(pt).into_owned())
}

// ---- capability attributes and payloads -----------------------------------------------------------------------------------

/// Options for [`capability_attributes`].
#[derive(Default, Clone)]
pub struct CapabilityOpts {
    /// The capability chain, root first, ending in the capability; required for `scope:` / `act:` / `verb:` / `resource:`
    /// tokens on a delegated hop. A supplied chain that fails verification yields no attributes (fail closed).
    pub chain: Option<Vec<Value>>,
    /// The principal key the root must be issued by (default: the chain's own root issuer).
    pub principal: Option<String>,
    /// Verifier-side PQ pins by Ed25519 root identity.
    pub pq_pins: Option<HashMap<String, String>>,
}

fn js_verbs(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(|e| e.as_str().map(String::from)).collect(),
        _ => Vec::new(),
    }
}

/// `===` on identifiers: absent equals absent, null equals null, strings by value, anything else never.
fn same_id(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) | (Some(Value::Null), Some(Value::Null)) => true,
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        _ => false,
    }
}

/// The canonical attribute tokens a capability possesses, in insertion order (deterministic and total). `scope:`, `act:`,
/// `verb:` and `resource:` tokens come only from the ROOT capability: a delegated hop's own caveats are restrictions, never grants.
fn cap_attrs(capability: &Value, opts: &CapabilityOpts) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let mut add = |s: String| {
        if seen.insert(s.clone()) {
            out.push(s);
        }
    };
    let (scope_source, env_source): (Option<&Value>, Option<&Value>) = if let Some(chain) = &opts.chain {
        let (Some(root), Some(last)) = (chain.first(), chain.last()) else { return Vec::new() };
        if !root.is_object() || !last.is_object() || !same_id(last.get("id"), capability.get("id")) {
            return Vec::new();
        }
        let principal = opts.principal.as_deref().or_else(|| root.get("issuer").and_then(Value::as_str));
        if crate::verify_chain_policy(chain, principal, None, opts.pq_pins.as_ref(), None).is_err() {
            return Vec::new();
        }
        (root.get("caveats"), Some(root))
    } else if capability.get("parent").is_none() {
        (capability.get("caveats"), Some(capability))
    } else {
        (None, None)
    };
    if let Some(h) = capability.get("holder").and_then(Value::as_str).filter(|h| !h.is_empty()) {
        add(format!("holder:{h}"));
    }
    if let Some(cavs) = scope_source.and_then(Value::as_array) {
        for cv in cavs.iter().filter_map(Value::as_object) {
            match cv.get("type").and_then(Value::as_str) {
                Some("scope") => {
                    if let Some(v) = cv.get("value").and_then(Value::as_str) {
                        add(format!("scope:{v}"));
                    }
                }
                Some("scopes") => {
                    for v in cv.get("values").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                        add(format!("scope:{v}"));
                    }
                }
                _ => {}
            }
        }
    }
    let env = env_source.and_then(crate::authorize::read_envelope);
    if let Some(plist) = env.as_ref().and_then(|e| e.get("predicates")).and_then(Value::as_array) {
        // an array counts as a predicate that names no verb or resource; null and scalars are not predicates
        let empty = Value::Object(Map::new());
        let preds: Vec<&Value> = plist
            .iter()
            .filter_map(|p| {
                if p.is_object() {
                    Some(p)
                } else if p.is_array() {
                    Some(&empty)
                } else {
                    None
                }
            })
            .collect();
        for p in &preds {
            if let Some(r) = p.get("resource").and_then(Value::as_str) {
                for v in js_verbs(p.get("verb")) {
                    add(format!("act:{}", crate::js_stringify(&json!([v, r]))));
                }
            }
        }
        if preds.len() == 1 {
            for v in js_verbs(preds[0].get("verb")) {
                add(format!("verb:{v}"));
            }
            if let Some(r) = preds[0].get("resource").and_then(Value::as_str) {
                add(format!("resource:{r}"));
            }
        }
    }
    out
}

/// The sorted canonical attribute set a capability possesses.
pub fn capability_attributes(capability: &Value, opts: &CapabilityOpts) -> Vec<String> {
    let mut v = cap_attrs(capability, opts);
    sort_utf16(&mut v);
    v
}

/// Issues a key bound to a capability's attributes plus any extra tokens; the holder is recorded. Also returns the issued names.
pub fn keygen_for_capability_named(msk: &Value, capability: &Value, extra: &[String], opts: &CapabilityOpts) -> Result<(Value, Vec<String>), String> {
    let mut attrs = cap_attrs(capability, opts);
    attrs.extend(extra.iter().filter(|a| !a.is_empty()).cloned());
    let (mut key, names) = issue(msk, &attrs)?;
    if let (Some(h), Some(m)) = (capability.get("holder").and_then(Value::as_str), key.as_object_mut()) {
        m.insert("holder".into(), h.into());
    }
    Ok((key, names))
}

/// [`keygen_for_capability_named`] without the names.
pub fn keygen_for_capability(msk: &Value, capability: &Value, extra: &[String], opts: &CapabilityOpts) -> Result<Value, String> {
    keygen_for_capability_named(msk, capability, extra, opts).map(|k| k.0)
}

/// Encrypts a JSON-serialisable payload under a capability policy (`JSON.stringify(payload ?? null)`).
pub fn encrypt_tool_payload(mpk: &Value, policy: &Value, payload: &Value) -> Result<Value, String> {
    encrypt_for_policy(mpk, policy, crate::js_stringify(payload).as_bytes())
}

/// Decrypts a tool payload with a capability-derived key and parses it: `Ok(payload)` or `Err(reason)`.
pub fn decrypt_with_capability(key: &Value, ciphertext: &Value) -> Result<Value, String> {
    let pt = decrypt(key, ciphertext).ok_or("capability does not satisfy the policy, or ciphertext is invalid")?;
    let text = String::from_utf8_lossy(pt.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(&pt)).into_owned();
    serde_json::from_str(&text).map_err(|_| "decrypted payload is not valid JSON".to_string())
}
