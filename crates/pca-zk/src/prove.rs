//! Groth16 proving from circom artifacts: the witness wasm (run by `witness`), a snarkjs `.zkey` (parsed here), and arkworks
//! group arithmetic. The proof has the same shape and meaning as `snarkjs groth16 fullProve` and verifies under the key
//! `snarkjs zkey export verificationkey` writes. The zkey layout is the iden3 binary format: sections of little-endian,
//! Montgomery-form affine points (1 header, 2 Groth header, 3 IC, 4 coefficients, 5 A, 6 B1, 7 B2, 8 C, 9 H).
use crate::verify::Curve;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProveKind {
    Input,
    Witness,
    Zkey,
    Prove,
}

#[derive(Debug)]
pub struct ProveError {
    pub kind: ProveKind,
    pub msg: String,
}

fn pe<T>(kind: ProveKind, msg: impl Into<String>) -> Result<T, ProveError> {
    Err(ProveError { kind, msg: msg.into() })
}

fn u32le(d: &[u8], o: usize) -> Result<usize, String> {
    d.get(o..o + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
        .ok_or_else(|| "zkey is truncated".to_string())
}

/// The section table of a zkey: id to its data.
struct Zkey<'a> {
    secs: Vec<(usize, &'a [u8])>,
}

impl<'a> Zkey<'a> {
    fn parse(d: &'a [u8]) -> Result<Zkey<'a>, String> {
        if d.get(0..4) != Some(b"zkey") {
            return Err("not a zkey file (bad magic)".into());
        }
        let n = u32le(d, 8)?;
        let mut pos = 12usize;
        let mut secs = Vec::new();
        for _ in 0..n {
            let id = u32le(d, pos)?;
            let len = d
                .get(pos + 4..pos + 12)
                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                .ok_or("zkey is truncated")?;
            let start = pos + 12;
            let end = usize::try_from(len)
                .ok()
                .and_then(|l| start.checked_add(l))
                .ok_or("zkey section length overflows")?;
            secs.push((id, d.get(start..end).ok_or("zkey section runs past the end of the file")?));
            pos = end;
        }
        Ok(Zkey { secs })
    }
    fn sec(&self, id: usize) -> Result<&'a [u8], String> {
        self.secs
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, s)| *s)
            .ok_or_else(|| format!("zkey has no section {id}"))
    }
}

struct Header {
    n8q: usize,
    n8r: usize,
    q: BigUint,
    r: BigUint,
    n_vars: usize,
    n_public: usize,
    domain: usize,
    pts: usize,
}

fn header(z: &Zkey) -> Result<Header, String> {
    let s1 = z.sec(1)?;
    if u32le(s1, 0)? != 1 {
        return Err("zkey protocol is not groth16".into());
    }
    let s = z.sec(2)?;
    let n8q = u32le(s, 0)?;
    let q = BigUint::from_bytes_le(s.get(4..4 + n8q).ok_or("zkey is truncated")?);
    let n8r = u32le(s, 4 + n8q)?;
    let r = BigUint::from_bytes_le(s.get(8 + n8q..8 + n8q + n8r).ok_or("zkey is truncated")?);
    let o = 8 + n8q + n8r;
    Ok(Header {
        n8q,
        n8r,
        q,
        r,
        n_vars: u32le(s, o)?,
        n_public: u32le(s, o + 4)?,
        domain: u32le(s, o + 8)?,
        pts: o + 12,
    })
}

fn ntt<F: PrimeField>(a: &mut [F], root: F) {
    let n = a.len();
    let bits = n.trailing_zeros();
    for i in 0..n {
        let j = if bits == 0 { 0 } else { i.reverse_bits() >> (usize::BITS - bits) };
        if i < j {
            a.swap(i, j);
        }
    }
    let mut len = 2;
    while len <= n {
        let wl = root.pow([(n / len) as u64]);
        for i in (0..n).step_by(len) {
            let mut w = F::one();
            for j in 0..len / 2 {
                let (u, v) = (a[i + j], a[i + j + len / 2] * w);
                a[i + j] = u + v;
                a[i + j + len / 2] = u - v;
                w *= wl;
            }
        }
        len <<= 1;
    }
}

fn intt<F: PrimeField>(a: &mut [F], root: F) {
    ntt(a, root.inverse().expect("root is non-zero"));
    let ninv = F::from(a.len() as u64).inverse().expect("domain size is invertible");
    a.iter_mut().for_each(|x| *x *= ninv);
}

fn make_rng(seed: Option<[u8; 32]>) -> Box<dyn rand_core::RngCore> {
    match seed {
        Some(s) => Box::new(<rand_chacha::ChaCha20Rng as rand_core::SeedableRng>::from_seed(s)),
        None => Box::new(rand_core::OsRng),
    }
}

macro_rules! prover {
    ($m:ident, $c:ident, $pairing:ident, $cv:expr) => {
        mod $m {
            use super::*;
            use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
            use ark_ff::{FftField, Field, One, Zero};
            use ark_groth16::{Groth16, Proof, VerifyingKey};
            use ark_snark::SNARK;
            use ark_std::UniformRand;
            use $c::{$pairing, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};

            fn fqv(b: &[u8], rinv: &Fq) -> Fq {
                Fq::from_le_bytes_mod_order(b) * rinv
            }
            fn g1_at(d: &[u8], o: usize, n8: usize, rinv: &Fq) -> G1Affine {
                let (x, y) = (&d[o..o + n8], &d[o + n8..o + 2 * n8]);
                if x.iter().chain(y).all(|&b| b == 0) {
                    return G1Affine::zero();
                }
                G1Affine::new_unchecked(fqv(x, rinv), fqv(y, rinv))
            }
            fn g2_at(d: &[u8], o: usize, n8: usize, rinv: &Fq) -> G2Affine {
                let c = |i: usize| &d[o + i * n8..o + (i + 1) * n8];
                if (0..4).all(|i| c(i).iter().all(|&b| b == 0)) {
                    return G2Affine::zero();
                }
                G2Affine::new_unchecked(Fq2::new(fqv(c(0), rinv), fqv(c(1), rinv)), Fq2::new(fqv(c(2), rinv), fqv(c(3), rinv)))
            }
            fn g1s(d: &[u8], n: usize, n8: usize, rinv: &Fq, what: &str) -> Result<Vec<G1Affine>, String> {
                if d.len() < n * 2 * n8 {
                    return Err(format!("zkey section {what} is too short"));
                }
                Ok((0..n).map(|i| g1_at(d, i * 2 * n8, n8, rinv)).collect())
            }
            fn dq(f: &Fq) -> String {
                BigUint::from(f.into_bigint()).to_string()
            }
            fn dr(f: &Fr) -> String {
                BigUint::from(f.into_bigint()).to_string()
            }
            fn j1(p: &G1Affine) -> Value {
                serde_json::json!([dq(&p.x), dq(&p.y), "1"])
            }
            fn j2(p: &G2Affine) -> Value {
                serde_json::json!([[dq(&p.x.c0), dq(&p.x.c1)], [dq(&p.y.c0), dq(&p.y.c1)], ["1", "0"]])
            }

            /// The primitive 2^k-th root of unity in the convention of snarkjs' field library: the smallest quadratic
            /// non-residue raised to the odd part of r - 1, squared down to order 2^k.
            fn root(k: u32) -> Fr {
                let mut nqr = 2u64;
                while Fr::from(nqr).pow(Fr::MODULUS_MINUS_ONE_DIV_TWO) != -Fr::one() {
                    nqr += 1;
                }
                let mut w = Fr::from(nqr).pow(Fr::TRACE);
                for _ in k..(<Fr as FftField>::TWO_ADICITY) {
                    w.square_in_place();
                }
                w
            }

            pub(super) fn prove(z: &Zkey, h: &Header, wit: &[[u8; 32]], seed: Option<[u8; 32]>, curve_name: &str) -> Result<String, String> {
                let n8 = h.n8q;
                if h.q != BigUint::from(Fq::MODULUS) || h.r != BigUint::from(Fr::MODULUS) || h.n8r != 32 {
                    return Err(format!("zkey is not for the {curve_name} curve"));
                }
                if wit.len() != h.n_vars || h.n_public + 1 > h.n_vars {
                    return Err(format!("witness has {} entries, the zkey expects {}", wit.len(), h.n_vars));
                }
                if !h.domain.is_power_of_two() {
                    return Err("zkey domain size is not a power of two".into());
                }
                let w: Vec<Fr> = wit.iter().map(|b| Fr::from_le_bytes_mod_order(b)).collect();
                let rinv = Fq::from(BigUint::from(1u8) << (8 * n8)).inverse().ok_or("bad modulus")?;

                let s2 = z.sec(2)?;
                let p1 = |i: usize| -> Result<G1Affine, String> {
                    let o = h.pts + i * 2 * n8;
                    if s2.len() < o + 2 * n8 {
                        return Err("zkey header is truncated".into());
                    }
                    Ok(g1_at(s2, o, n8, &rinv))
                };
                let p2 = |i: usize| -> Result<G2Affine, String> {
                    let o = h.pts + i * 2 * n8;
                    if s2.len() < o + 4 * n8 {
                        return Err("zkey header is truncated".into());
                    }
                    Ok(g2_at(s2, o, n8, &rinv))
                };
                // layout after the sizes: alpha1 (G1), beta1 (G1), beta2 (G2), gamma2 (G2), delta1 (G1), delta2 (G2)
                let (alpha1, beta1) = (p1(0)?, p1(1)?);
                let (beta2, gamma2) = (p2(2)?, p2(4)?);
                let (delta1, delta2) = (p1(6)?, p2(7)?);
                let ic = g1s(z.sec(3)?, h.n_public + 1, n8, &rinv, "3")?;
                let pa = g1s(z.sec(5)?, h.n_vars, n8, &rinv, "5")?;
                let pb1 = g1s(z.sec(6)?, h.n_vars, n8, &rinv, "6")?;
                let s7 = z.sec(7)?;
                if s7.len() < h.n_vars * 4 * n8 {
                    return Err("zkey section 7 is too short".into());
                }
                let pb2: Vec<G2Affine> = (0..h.n_vars).map(|i| g2_at(s7, i * 4 * n8, n8, &rinv)).collect();
                let pc = g1s(z.sec(8)?, h.n_vars - h.n_public - 1, n8, &rinv, "8")?;
                let ph = g1s(z.sec(9)?, h.domain, n8, &rinv, "9")?;

                // coefficient entries of A (matrix 0) and B (matrix 1): (matrix, constraint, signal, value)
                let s4 = z.sec(4)?;
                let nco = u32le(s4, 0)?;
                let esz = 12 + h.n8r;
                if s4.len() < 4 + nco * esz {
                    return Err("zkey section 4 is too short".into());
                }
                let mut coefs: Vec<(usize, usize, usize, Fr)> = Vec::with_capacity(nco);
                for i in 0..nco {
                    let o = 4 + i * esz;
                    let (m, c, s) = (u32le(s4, o)?, u32le(s4, o + 4)?, u32le(s4, o + 8)?);
                    if m > 1 || c >= h.domain || s >= h.n_vars {
                        return Err("zkey coefficient is out of range".into());
                    }
                    coefs.push((m, c, s, Fr::from_le_bytes_mod_order(&s4[o + 12..o + esz])));
                }

                let mut rng = make_rng(seed);
                let (r, s) = (Fr::rand(&mut *rng), Fr::rand(&mut *rng));
                let ms = |e: usize| -> String { format!("msm over section {e} has mismatched lengths") };
                let a = G1Projective::from(alpha1)
                    + G1Projective::msm(&pa, &w).map_err(|_| ms(5))?
                    + G1Projective::from(delta1) * r;
                let b2 = G2Projective::from(beta2) + G2Projective::msm(&pb2, &w).map_err(|_| ms(7))? + G2Projective::from(delta2) * s;
                let b1 = G1Projective::from(beta1) + G1Projective::msm(&pb1, &w).map_err(|_| ms(6))? + G1Projective::from(delta1) * s;
                let c0 = G1Projective::msm(&pc, &w[h.n_public + 1..]).map_err(|_| ms(8))?;
                let a_aff = a.into_affine();

                let n = h.domain;
                let k = n.trailing_zeros();
                if k + 1 > <Fr as FftField>::TWO_ADICITY {
                    return Err("zkey domain is larger than the field's two-adicity".into());
                }
                let (wn, w2n) = (root(k), root(k + 1));
                let rinv_r = Fr::from(BigUint::from(1u8) << (8 * h.n8r)).inverse().ok_or("bad modulus")?;
                let vk = VerifyingKey { alpha_g1: alpha1, beta_g2: beta2, gamma_g2: gamma2, delta_g2: delta2, gamma_abc_g1: ic };
                let inputs: Vec<Fr> = w[1..=h.n_public].to_vec();

                // The scalars of the H multi-scalar multiplication are A*B - C evaluated on the odd points of the doubled
                // domain. The stored coefficient scaling is the Montgomery factor of the zkey writer: the first reading is
                // value * R^2 (the writer's form), the others are fallbacks; a reading is accepted only if the finished proof
                // verifies under the zkey's own key, so a wrong guess can never produce a bad proof.
                for scale in [rinv_r * rinv_r, rinv_r, Fr::one()] {
                    let (mut av, mut bv) = (vec![Fr::zero(); n], vec![Fr::zero(); n]);
                    for &(m, c, sg, v) in &coefs {
                        let t = v * scale * w[sg];
                        if m == 0 {
                            av[c] += t;
                        } else {
                            bv[c] += t;
                        }
                    }
                    let mut cv: Vec<Fr> = av.iter().zip(&bv).map(|(x, y)| *x * y).collect();
                    for v in [&mut av, &mut bv, &mut cv] {
                        intt(v, wn);
                        let mut g = Fr::one();
                        for x in v.iter_mut() {
                            *x *= g;
                            g *= w2n;
                        }
                        ntt(v, wn);
                    }
                    let hs: Vec<Fr> = (0..n).map(|i| av[i] * bv[i] - cv[i]).collect();
                    let c = c0
                        + G1Projective::msm(&ph, &hs).map_err(|_| ms(9))?
                        + G1Projective::from(a_aff) * s
                        + b1 * r
                        - G1Projective::from(delta1) * (r * s);
                    let proof = Proof::<$pairing> { a: a_aff, b: b2.into_affine(), c: c.into_affine() };
                    if Groth16::<$pairing>::verify(&vk, &inputs, &proof).unwrap_or(false) {
                        return Ok(serde_json::json!({
                            "proof": { "pi_a": j1(&proof.a), "pi_b": j2(&proof.b), "pi_c": j1(&proof.c), "protocol": "groth16", "curve": Curve::snarkjs_name($cv) },
                            "publicSignals": inputs.iter().map(dr).collect::<Vec<_>>(),
                        })
                        .to_string());
                    }
                }
                Err("the proof does not verify under the zkey's own key: the witness does not satisfy the circuit, or the zkey is not one this prover reads".into())
            }
        }
    };
}

prover!(bn254, ark_bn254, Bn254, Curve::Bn254);
prover!(bls12_381, ark_bls12_381, Bls12_381, Curve::Bls12381);

/// Proves `input` (a JSON object of circuit input signals) with the circom witness wasm and the snarkjs zkey. `seed` makes the
/// blinding factors deterministic (tests only); `None` draws them from the operating system. Returns the JSON text
/// `{"proof": {...}, "publicSignals": [...]}` in snarkjs' encoding.
pub fn prove(curve: Curve, wasm: &[u8], zkey: &[u8], input: &[u8], seed: Option<[u8; 32]>) -> Result<String, ProveError> {
    let input: Value = serde_json::from_slice(input).map_err(|e| ProveError {
        kind: ProveKind::Input,
        msg: format!("input is not JSON: {e}"),
    })?;
    let z = Zkey::parse(zkey).map_err(|m| ProveError {
        kind: ProveKind::Zkey,
        msg: m,
    })?;
    let h = header(&z).map_err(|m| ProveError {
        kind: ProveKind::Zkey,
        msg: m,
    })?;
    let modulus = h.r.clone();
    let want = match curve {
        Curve::Bn254 => BigUint::from(ark_bn254::Fr::MODULUS),
        Curve::Bls12381 => BigUint::from(ark_bls12_381::Fr::MODULUS),
    };
    if modulus != want {
        return pe(ProveKind::Zkey, "zkey is not for the requested curve");
    }
    let wit = crate::witness::calculate(wasm, &input, &modulus).map_err(|m| ProveError {
        kind: ProveKind::Witness,
        msg: m,
    })?;
    let out = match curve {
        Curve::Bn254 => bn254::prove(&z, &h, &wit, seed, "BN254"),
        Curve::Bls12381 => bls12_381::prove(&z, &h, &wit, seed, "BLS12-381"),
    };
    out.map_err(|m| ProveError {
        kind: ProveKind::Prove,
        msg: m,
    })
}
