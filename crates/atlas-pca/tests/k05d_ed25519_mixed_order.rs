//! 0.5 mutation kill (review finding): `verify_ed25519_strict` must refuse a MIXED-ORDER public key. dalek's `verify_strict` refuses
//! only SMALL-ORDER A and R, so for A = aB + T (T of order 8) it accepts whenever k = SHA-512(R || A || M) mod L is a multiple of 8
//! ([S]B - [k]A = rB - kT = rB = R). The `!a.is_torsion_free()` disjunct is the only thing that refuses it (TS keys.ts:38 and the
//! Ruby / PHP verifiers refuse it too). Kills `replace || with &&` at the 2nd and 3rd operator of the guard.
use atlas_pca::serde_json::json;
use atlas_pca::verify_artifact_suite;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as B;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha512};

/// The two well-known order-8 encodings (y of the points of order 8 on edwards25519).
const ORDER_8: [&str; 2] = [
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
];

fn unhex(s: &str) -> [u8; 32] {
    let mut o = [0u8; 32];
    for i in 0..32 {
        o[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    o
}

fn accepts(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    verify_artifact_suite(&json!({"sig": B64.encode(sig)}), &B64.encode(pk), msg)
}

/// (A = aB + t, signature) over a message ground until k is a multiple of 8; `t = None` gives the plain prime-order key.
fn sign(a: u64, r: u64, t: Option<[u8; 32]>) -> ([u8; 32], Vec<u8>, [u8; 64]) {
    let (a, r) = (Scalar::from(a), Scalar::from(r));
    let mut point = B * a;
    if let Some(t) = t {
        let tp = CompressedEdwardsY(t).decompress().expect("order-8 point");
        assert!(tp.is_small_order() && !tp.is_torsion_free() && !(tp + tp + tp + tp).is_identity(), "T has order 8");
        point += tp;
    }
    let pk = point.compress().to_bytes();
    let rb = (B * r).compress().to_bytes();
    for n in 0u32.. {
        let msg = format!("k05d mixed-order {n}").into_bytes();
        let mut h = Sha512::new();
        h.update(rb);
        h.update(pk);
        h.update(&msg);
        let k = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
        if t.is_some() && k.to_bytes()[0] & 7 != 0 {
            continue;
        }
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&rb);
        sig[32..].copy_from_slice(&(r + k * a).to_bytes());
        return (pk, msg, sig);
    }
    unreachable!()
}

#[test]
fn a_prime_order_key_still_verifies() {
    let (pk, msg, sig) = sign(0x1234_5678_9abc, 0x0fed_cba9_8765, None);
    assert!(accepts(&pk, &msg, &sig), "control: the signing helper produces valid signatures");
}

#[test]
fn a_mixed_order_public_key_is_refused_though_dalek_verify_strict_accepts_it() {
    for (i, t) in ORDER_8.iter().enumerate() {
        let (pk, msg, sig) = sign(0x1111_2222_3333 + i as u64, 0x4444_5555_6666 + i as u64, Some(unhex(t)));
        let a = CompressedEdwardsY(pk).decompress().unwrap();
        assert!(!a.is_small_order() && !a.is_torsion_free(), "A is mixed order: neither small order nor torsion free");
        // the premise: dalek alone accepts this signature
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        assert!(vk.verify_strict(&msg, &Signature::from_bytes(&sig)).is_ok(), "dalek verify_strict accepts the mixed-order key (T #{i})");
        // the reference (TS keys.ts:38) refuses it
        assert!(!accepts(&pk, &msg, &sig), "mixed-order public key (T #{i}) must be refused");
    }
}
