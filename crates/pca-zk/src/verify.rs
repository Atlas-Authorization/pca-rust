//! Groth16 verification of snarkjs artifacts (JSON verification key, proof and public signals) on BN254 and BLS12-381.
//!
//! Strict by default: decimal strings must be canonical and below the field modulus, every curve point must be on the curve AND
//! in the prime-order subgroup (G1 and G2, in the key and in the proof), affine points need z = 1 (G2 z = [1,0]), the key's
//! protocol, curve and nPublic must be consistent, and the number of public signals must equal the key's.
//!
//! `FLAG_SNARKJS_COMPAT` reproduces what snarkjs' own `groth16.verify` accepts, which is what the TypeScript reference uses
//! and what the native lanes' public API must therefore match: the key's `protocol` and `nPublic` and the proof's
//! `protocol` / `curve` are ignored, and IC entries beyond the signals count are neither read nor validated (a key with fewer IC
//! entries than signals + 1 is still refused). Group, field and subgroup checks are the same in both modes (snarkjs checks
//! less, but an off-subgroup point never makes the pairing equation hold, so the verdict is the same).
//!
//! The key's curve name. Strict mode takes exactly `bn128` or `bls12381`. Compat mode reads it as snarkjs does
//! (`Curve::from_snarkjs_name`: upper-cased, everything but ASCII letters and digits dropped, then `BN128`, `BN254` or
//! `ALTBN128` is BN254 and `BLS12381` is BLS12-381), so `BN254`, `alt_bn128` or `bls12-381` name a curve too. `verify` still
//! requires that curve to be the one it was called with; `verify_snarkjs` takes the curve from the key, as snarkjs does.
use num_bigint::BigUint;
use serde_json::Value;

pub const FLAG_SNARKJS_COMPAT: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Curve {
    Bn254 = 0,
    Bls12381 = 1,
}

impl Curve {
    pub fn from_code(c: i32) -> Option<Curve> {
        match c {
            0 => Some(Curve::Bn254),
            1 => Some(Curve::Bls12381),
            _ => None,
        }
    }
    /// The curve snarkjs picks for a key's `curve` name (its `getCurveFromName`): the name upper-cased, every character
    /// that is not an ASCII letter or digit dropped, then `BN128`, `BN254` or `ALTBN128` for BN254 and `BLS12381` for
    /// BLS12-381. `None` for any other name (snarkjs throws).
    pub fn from_snarkjs_name(name: &str) -> Option<Curve> {
        let n: String = name.to_uppercase().chars().filter(char::is_ascii_alphanumeric).collect();
        match n.as_str() {
            "BN128" | "BN254" | "ALTBN128" => Some(Curve::Bn254),
            "BLS12381" => Some(Curve::Bls12381),
            _ => None,
        }
    }
    /// The name snarkjs gives the curve in a key or proof.
    pub fn snarkjs_name(self) -> &'static str {
        match self {
            Curve::Bn254 => "bn128",
            Curve::Bls12381 => "bls12381",
        }
    }
}

/// Why a verification said no (0 is "no reason": valid).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Reason {
    Ok = 0,
    BadJson = 1,
    BadProtocol = 2,
    BadCurve = 3,
    BadEncoding = 4,
    NotInSubgroup = 5,
    NotAffine = 6,
    BadShape = 7,
    SignalCount = 8,
    IcShort = 9,
    PairingFailed = 10,
}

impl Reason {
    pub fn text(self) -> &'static str {
        match self {
            Reason::Ok => "ok",
            Reason::BadJson => "input is not valid JSON",
            Reason::BadProtocol => "protocol is not groth16",
            Reason::BadCurve => "curve is missing, unknown or does not match",
            Reason::BadEncoding => "field element is not a canonical decimal below the modulus",
            Reason::NotInSubgroup => "point is not on the curve or not in the prime-order subgroup",
            Reason::NotAffine => "point is not affine (z is not 1)",
            Reason::BadShape => "a field is missing or has the wrong shape",
            Reason::SignalCount => "public signal count does not match the key",
            Reason::IcShort => "key has fewer IC entries than signals + 1",
            Reason::PairingFailed => "pairing equation does not hold",
        }
    }
}

#[derive(Debug)]
pub struct Reject {
    pub reason: Reason,
    pub detail: String,
}

type R<T> = Result<T, Reject>;

fn rj<T>(reason: Reason, detail: impl Into<String>) -> R<T> {
    Err(Reject {
        reason,
        detail: detail.into(),
    })
}

fn dec(v: &Value, modulus: &BigUint, what: &str) -> R<BigUint> {
    let Some(s) = v.as_str() else {
        return rj(Reason::BadEncoding, format!("{what}: not a string"));
    };
    if s.is_empty() || s.len() > 120 || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return rj(Reason::BadEncoding, format!("{what}: not a canonical decimal"));
    }
    let Ok(n) = s.parse::<BigUint>() else {
        return rj(Reason::BadEncoding, format!("{what}: unparsable"));
    };
    if &n >= modulus {
        return rj(Reason::BadEncoding, format!("{what}: not below the field modulus"));
    }
    Ok(n)
}

fn arr<'a>(v: &'a Value, len: usize, what: &str) -> R<&'a Vec<Value>> {
    match v.as_array() {
        Some(a) if a.len() == len => Ok(a),
        _ => rj(Reason::BadShape, format!("{what}: expected an array of {len}")),
    }
}

macro_rules! curve {
    ($m:ident, $c:ident, $pairing:ident, $curve:expr, $curve_name:expr) => {
        mod $m {
            use super::*;
            use ark_ff::PrimeField;
            use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
            use ark_snark::SNARK;
            use $c::{$pairing, Fq, Fq2, Fr, G1Affine, G2Affine};

            fn fq(v: &Value, what: &str) -> R<Fq> {
                let m: BigUint = Fq::MODULUS.into();
                Ok(Fq::from(dec(v, &m, what)?))
            }
            fn fr(v: &Value, what: &str) -> R<Fr> {
                let m: BigUint = Fr::MODULUS.into();
                Ok(Fr::from(dec(v, &m, what)?))
            }
            fn g1(v: &Value, what: &str) -> R<G1Affine> {
                let a = arr(v, 3, what)?;
                if a[2].as_str() != Some("1") {
                    return rj(Reason::NotAffine, format!("{what}: z != 1"));
                }
                let p = G1Affine::new_unchecked(fq(&a[0], what)?, fq(&a[1], what)?);
                if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
                    return rj(Reason::NotInSubgroup, what.to_string());
                }
                Ok(p)
            }
            fn g2(v: &Value, what: &str) -> R<G2Affine> {
                let a = arr(v, 3, what)?;
                let z = arr(&a[2], 2, what)?;
                if z[0].as_str() != Some("1") || z[1].as_str() != Some("0") {
                    return rj(Reason::NotAffine, format!("{what}: z != [1,0]"));
                }
                let c = |i: usize| -> R<Fq2> {
                    let r = arr(&a[i], 2, what)?;
                    Ok(Fq2::new(fq(&r[0], what)?, fq(&r[1], what)?))
                };
                let p = G2Affine::new_unchecked(c(0)?, c(1)?);
                if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
                    return rj(Reason::NotInSubgroup, what.to_string());
                }
                Ok(p)
            }

            pub fn verify(vk: &Value, pr: &Value, sigs: &Value, compat: bool) -> R<()> {
                let named = if compat { vk["curve"].as_str().and_then(Curve::from_snarkjs_name) == Some($curve) } else { vk["curve"] == $curve_name };
                if !named {
                    return rj(Reason::BadCurve, "vkey: curve does not match");
                }
                if !compat && vk["protocol"] != "groth16" {
                    return rj(Reason::BadProtocol, "vkey: protocol is not groth16");
                }
                if !compat && (pr["protocol"] != "groth16" || pr["curve"] != vk["curve"]) {
                    return rj(Reason::BadProtocol, "proof: wrong protocol or curve");
                }
                let Some(sigs) = sigs.as_array() else {
                    return rj(Reason::BadShape, "publicSignals: not an array");
                };
                let Some(ic) = vk["IC"].as_array() else {
                    return rj(Reason::BadShape, "vkey: no IC");
                };
                let n = sigs.len();
                if compat {
                    if ic.len() < n + 1 {
                        return rj(Reason::IcShort, "vkey: fewer IC entries than signals + 1");
                    }
                } else if vk["nPublic"].as_u64() != Some(n as u64) || ic.len() != n + 1 {
                    return rj(Reason::SignalCount, "publicSignals: count does not match the key");
                }
                let key = VerifyingKey {
                    alpha_g1: g1(&vk["vk_alpha_1"], "vk_alpha_1")?,
                    beta_g2: g2(&vk["vk_beta_2"], "vk_beta_2")?,
                    gamma_g2: g2(&vk["vk_gamma_2"], "vk_gamma_2")?,
                    delta_g2: g2(&vk["vk_delta_2"], "vk_delta_2")?,
                    gamma_abc_g1: ic[..n + 1].iter().map(|p| g1(p, "IC")).collect::<R<Vec<_>>>()?,
                };
                let proof = Proof {
                    a: g1(&pr["pi_a"], "pi_a")?,
                    b: g2(&pr["pi_b"], "pi_b")?,
                    c: g1(&pr["pi_c"], "pi_c")?,
                };
                let inputs = sigs.iter().map(|s| fr(s, "publicSignals")).collect::<R<Vec<_>>>()?;
                let pvk = PreparedVerifyingKey::from(key);
                match Groth16::<$pairing>::verify_with_processed_vk(&pvk, &inputs, &proof) {
                    Ok(true) => Ok(()),
                    Ok(false) => rj(Reason::PairingFailed, Reason::PairingFailed.text()),
                    Err(e) => rj(Reason::PairingFailed, format!("verification error: {e}")),
                }
            }
        }
    };
}

curve!(bn254, ark_bn254, Bn254, Curve::Bn254, "bn128");
curve!(bls12_381, ark_bls12_381, Bls12_381, Curve::Bls12381, "bls12381");

fn json(b: &[u8], what: &str) -> R<Value> {
    serde_json::from_slice(b).map_err(|e| Reject {
        reason: Reason::BadJson,
        detail: format!("{what}: {e}"),
    })
}

/// Verifies a snarkjs Groth16 proof. `Ok(())` is valid; `Err` carries the reason it was refused.
pub fn verify(curve: Curve, flags: u32, vkey: &[u8], proof: &[u8], signals: &[u8]) -> Result<(), Reject> {
    let (vk, pr, sg) = (json(vkey, "vkey")?, json(proof, "proof")?, json(signals, "publicSignals")?);
    let compat = flags & FLAG_SNARKJS_COMPAT != 0;
    match curve {
        Curve::Bn254 => bn254::verify(&vk, &pr, &sg, compat),
        Curve::Bls12381 => bls12_381::verify(&vk, &pr, &sg, compat),
    }
}

/// Verifies a snarkjs Groth16 proof exactly as snarkjs' `groth16.verify` decides it: the rules of `FLAG_SNARKJS_COMPAT`, on the
/// curve the key itself names (read as snarkjs reads it). A key without a known curve name is refused with `Reason::BadCurve`.
pub fn verify_snarkjs(vkey: &[u8], proof: &[u8], signals: &[u8]) -> Result<(), Reject> {
    let vk = json(vkey, "vkey")?;
    match vk["curve"].as_str().and_then(Curve::from_snarkjs_name) {
        Some(curve) => verify(curve, FLAG_SNARKJS_COMPAT, vkey, proof, signals),
        None => rj(Reason::BadCurve, "vkey: curve is missing or unknown"),
    }
}
