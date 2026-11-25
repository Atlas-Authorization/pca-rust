//! The public PQ surface (`atlas_pca::pq`): constants against the primitives, deterministic keygen, sign / verify round trips, strict
//! length handling, pinned-key resolution and the LAMPS composite signature.
use atlas_pca::agent::KeyPair;
use atlas_pca::pq::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

#[test]
fn constants_match_the_primitives() {
    assert_eq!(ML_DSA_65_PUBLIC_KEY_BYTES, fips204::ml_dsa_65::PK_LEN);
    assert_eq!(ML_DSA_65_SIGNATURE_BYTES, fips204::ml_dsa_65::SIG_LEN);
    assert_eq!(ML_DSA_87_PUBLIC_KEY_BYTES, fips204::ml_dsa_87::PK_LEN);
    assert_eq!(ML_DSA_87_SIGNATURE_BYTES, fips204::ml_dsa_87::SIG_LEN);
    assert_eq!(SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES, fips205::slh_dsa_sha2_128f::PK_LEN);
    assert_eq!(SLH_DSA_SHA2_128F_SECRET_KEY_BYTES, fips205::slh_dsa_sha2_128f::SK_LEN);
    assert_eq!(SLH_DSA_SHA2_128F_SIGNATURE_BYTES, fips205::slh_dsa_sha2_128f::SIG_LEN);
    assert_eq!(SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES, fips205::slh_dsa_sha2_256s::PK_LEN);
    assert_eq!(SLH_DSA_SHA2_256S_SECRET_KEY_BYTES, fips205::slh_dsa_sha2_256s::SK_LEN);
    assert_eq!(SLH_DSA_SHA2_256S_SIGNATURE_BYTES, fips205::slh_dsa_sha2_256s::SIG_LEN);
    assert_eq!(COMPOSITE_SIGNATURE_BYTES, 3373);
    assert_eq!(DEFAULT_SIG_ALG, "ed25519");
}

#[test]
fn registry_and_key_shape_checks() {
    assert!(is_known_sig_alg("ml-dsa-87"));
    assert!(is_known_sig_alg("ed25519"));
    assert!(!is_known_sig_alg("ML-DSA-87"));
    assert!(!is_known_sig_alg(""));
    assert!(is_well_formed_pq_public_key(&b64(&[1u8; 32])));
    assert!(is_well_formed_pq_public_key(&b64(&[1u8; 1952])));
    assert!(!is_well_formed_pq_public_key(&b64(&[1u8; 33])));
    assert!(!is_well_formed_pq_public_key("AAAA=="));
}

#[test]
fn ml_dsa_round_trips_and_is_deterministic() {
    let kp = ml_dsa_65_keygen(&[7u8; ML_DSA_65_SEED_BYTES]).unwrap();
    assert_eq!(kp.public_key.len(), ML_DSA_65_PUBLIC_KEY_BYTES);
    assert_eq!(ml_dsa_65_keygen(&[7u8; 32]).unwrap().public_key, kp.public_key);
    let sig = ml_dsa_65_sign(&kp.secret_key, b"hello").unwrap();
    assert_eq!(sig.len(), ML_DSA_65_SIGNATURE_BYTES);
    assert_eq!(ml_dsa_65_sign(&kp.secret_key, b"hello").unwrap(), sig);
    assert!(ml_dsa_65_verify(&kp.public_key, b"hello", &sig));
    assert!(!ml_dsa_65_verify(&kp.public_key, b"hellp", &sig));
    assert!(ml_dsa_65_verify_b64u(&encode_ml_dsa_public_key(&kp.public_key), b"hello", &b64(&sig)));
    assert!(!ml_dsa_65_verify_b64u(&encode_ml_dsa_public_key(&kp.public_key), b"hello", &b64(&sig[1..])));
    assert!(!ml_dsa_65_verify(&kp.public_key[1..], b"hello", &sig));
    assert!(ml_dsa_65_keygen(&[7u8; 31]).is_err());
    assert!(ml_dsa_65_sign(&kp.secret_key[1..], b"x").is_err());

    let k87 = ml_dsa_87_keygen(&[9u8; 32]).unwrap();
    let s87 = ml_dsa_87_sign(&k87.secret_key, b"m").unwrap();
    assert!(ml_dsa_87_verify(&k87.public_key, b"m", &s87));
    assert!(!ml_dsa_65_verify(&k87.public_key, b"m", &s87));
    assert!(ml_dsa_87_verify_b64u(&encode_ml_dsa_87_public_key(&k87.public_key), b"m", &b64(&s87)));
}

#[test]
fn slh_dsa_128f_round_trips() {
    let kp = slh_dsa_128f_keygen(&[3u8; SLH_DSA_SHA2_128F_SEED_BYTES]).unwrap();
    assert_eq!(kp.public_key.len(), SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES);
    assert_eq!(kp.secret_key.len(), SLH_DSA_SHA2_128F_SECRET_KEY_BYTES);
    let sig = slh_dsa_128f_sign(&kp.secret_key, b"hello").unwrap();
    assert_eq!(sig.len(), SLH_DSA_SHA2_128F_SIGNATURE_BYTES);
    assert!(slh_dsa_128f_verify(&kp.public_key, b"hello", &sig));
    assert!(!slh_dsa_128f_verify(&kp.public_key, b"hellp", &sig));
    assert!(slh_dsa_128f_verify_b64u(&encode_slh_dsa_public_key(&kp.public_key), b"hello", &b64(&sig)));
    assert!(slh_dsa_128f_keygen(&[3u8; 47]).is_err());
    assert!(slh_dsa_256s_keygen(&[3u8; 95]).is_err());
    let k256 = slh_dsa_256s_keygen(&[4u8; SLH_DSA_SHA2_256S_SEED_BYTES]).unwrap();
    assert_eq!(k256.public_key.len(), SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES);
    assert_eq!(k256.secret_key.len(), SLH_DSA_SHA2_256S_SECRET_KEY_BYTES);
    assert_eq!(encode_slh_dsa_256s_public_key(&k256.public_key), b64(&k256.public_key));
}

#[cfg(not(feature = "fndsa-sign"))]
#[test]
fn fn_dsa_signing_is_refused_without_its_feature_and_verify_stays_closed() {
    assert!(fn_dsa_512_keygen(&[1u8; 32]).is_err());
    assert!(fn_dsa_1024_sign(&[0u8; FN_DSA_1024_SECRET_KEY_BYTES], b"m", &[0u8; 32]).is_err());
    assert!(!fn_dsa_512_verify(&[0u8; FN_DSA_512_PUBLIC_KEY_BYTES], b"m", &[0u8; FN_DSA_512_SIGNATURE_BYTES]));
    assert!(!fn_dsa_1024_verify_b64u("", b"m", ""));
}

#[cfg(feature = "fndsa-sign")]
macro_rules! fn_dsa_case {
    ($kg:ident, $sign:ident, $verify:ident, $verify_b64u:ident, $pk:expr, $sk:expr, $sig:expr) => {{
        let kp = $kg(&[5u8; FN_DSA_SEED_BYTES]).unwrap();
        assert_eq!((kp.verifying_key.len(), kp.signing_key.len()), ($pk, $sk));
        let s = $sign(&kp.signing_key, b"hello", &[6u8; 32]).unwrap();
        assert_eq!(s.len(), $sig);
        assert!($verify(&kp.verifying_key, b"hello", &s));
        assert!(!$verify(&kp.verifying_key, b"hellp", &s));
        assert!($verify_b64u(&encode_fn_dsa_public_key(&kp.verifying_key), b"hello", &b64(&s)));
        assert!($sign(&kp.signing_key[1..], b"x", &[6u8; 32]).is_err());
        assert!($sign(&kp.signing_key, b"x", &[6u8; 31]).is_err());
    }};
}

#[cfg(feature = "fndsa-sign")]
#[test]
fn fn_dsa_round_trips() {
    fn_dsa_case!(
        fn_dsa_512_keygen,
        fn_dsa_512_sign,
        fn_dsa_512_verify,
        fn_dsa_512_verify_b64u,
        FN_DSA_512_PUBLIC_KEY_BYTES,
        FN_DSA_512_SECRET_KEY_BYTES,
        FN_DSA_512_SIGNATURE_BYTES
    );
    fn_dsa_case!(
        fn_dsa_1024_keygen,
        fn_dsa_1024_sign,
        fn_dsa_1024_verify,
        fn_dsa_1024_verify_b64u,
        FN_DSA_1024_PUBLIC_KEY_BYTES,
        FN_DSA_1024_SECRET_KEY_BYTES,
        FN_DSA_1024_SIGNATURE_BYTES
    );
}

#[test]
fn less_availability_is_reported_and_verify_fails_closed_on_shape() {
    let st = less_backend_status();
    assert_eq!(st.available, is_less_backend_active());
    assert_eq!(st.reason.is_none(), st.available);
    assert!(!less_cat1_verify(&[0u8; 5], b"m", &[0u8; LESS_CAT1_SIGNATURE_MAX_BYTES]));
    assert!(!less_cat1_verify(&vec![0u8; LESS_CAT1_PUBLIC_KEY_BYTES], b"m", &[0u8; 100]));
    assert!(!less_cat1_verify(&vec![0u8; LESS_CAT1_PUBLIC_KEY_BYTES], b"m", &[0u8; LESS_CAT1_SIGNATURE_MAX_BYTES - 1]));
    assert!(!less_cat1_verify_b64u("!", b"m", "!"));
    if !st.available {
        assert!(less_cat1_keygen(&[1u8; LESS_SEED_BYTES]).is_err());
        assert!(less_cat1_sign(&[0u8; 32], b"m", &[1u8; 32]).is_err());
    }
}

#[cfg(feature = "less")]
#[test]
fn less_round_trips() {
    let kp = less_cat1_keygen(&[2u8; LESS_SEED_BYTES]).unwrap();
    assert_eq!(kp.public_key.len(), LESS_CAT1_PUBLIC_KEY_BYTES);
    assert_eq!(kp.secret_key.len(), LESS_CAT1_SECRET_KEY_BYTES);
    let sig = less_cat1_sign(&kp.secret_key, b"hello", &[3u8; LESS_SEED_BYTES]).unwrap();
    assert!((LESS_CAT1_SIGNATURE_MIN_BYTES..=LESS_CAT1_SIGNATURE_MAX_BYTES).contains(&sig.len()));
    assert!(less_cat1_verify(&kp.public_key, b"hello", &sig));
    assert!(!less_cat1_verify(&kp.public_key, b"hellp", &sig));
    assert!(less_cat1_verify_b64u(&encode_less_public_key(&kp.public_key), b"hello", &b64(&sig)));
}

#[test]
fn pinned_key_resolution_has_no_unbound_path() {
    let pk = b64(&[2u8; 32]);
    assert!(resolve_pq_verify_key("id", Some(&pk), None).is_none());
    assert!(resolve_pq_verify_key("id", Some(&pk), Some(&PqKeySource::default())).is_none());
    let trusted = PqKeySource { trusted_pk: Some(pk.clone()), ..Default::default() };
    assert_eq!(resolve_pq_verify_key("id", None, Some(&trusted)).unwrap().key(), pk);
    let pins = |v: &str| PqKeySource { pq_pins: Some([("id".to_string(), v.to_string())].into_iter().collect()), ..Default::default() };
    assert!(resolve_pq_verify_key("id", Some(&pk), Some(&pins(&pk))).is_some());
    assert!(resolve_pq_verify_key("id", Some(&pk), Some(&pins(&b64(&[3u8; 32])))).is_none());
    let committed = PqKeySource { holder_pq: Some(holder_pq_commitment_of(&pk)), ..Default::default() };
    assert!(resolve_pq_verify_key("id", Some(&pk), Some(&committed)).is_some());
    assert!(resolve_pq_verify_key("id", Some(&b64(&[9u8; 32])), Some(&committed)).is_none());
    // holder_pq_key: ed25519 needs no key; a PQ suite needs the committed one
    assert!(holder_pq_key(None, "id", Some(&pk), Some(&holder_pq_commitment_of(&pk))).is_none());
    assert!(holder_pq_key(Some("ed25519"), "id", Some(&pk), None).is_none());
    assert!(holder_pq_key(Some("ml-dsa-65"), "id", Some(&pk), Some(&holder_pq_commitment_of(&pk))).is_some());
    assert!(holder_pq_key(Some("ml-dsa-65"), "id", Some(&pk), None).is_none());
    assert!(holder_pq_key(Some("nope"), "id", Some(&pk), Some(&holder_pq_commitment_of(&pk))).is_none());
}

#[test]
fn verify_with_suite_checks_the_pinned_pq_half() {
    use serde_json::json;
    let ed = KeyPair::from_seed(&[1u8; 32]);
    let ml = ml_dsa_65_keygen(&[2u8; 32]).unwrap();
    let pk = encode_ml_dsa_public_key(&ml.public_key);
    let sig = b64(&ml_dsa_65_sign(&ml.secret_key, b"m").unwrap());
    let src = PqKeySource { trusted_pk: Some(pk), ..Default::default() };
    let key = resolve_pq_verify_key(&ed.public, None, Some(&src));
    let alg = json!("ml-dsa-65");
    assert!(verify_with_suite(Some(&alg), &ed.public, key.as_ref(), b"m", Some(&json!(sig)), None));
    assert!(!verify_with_suite(Some(&alg), &ed.public, key.as_ref(), b"n", Some(&json!(sig)), None));
    assert!(!verify_with_suite(Some(&alg), &ed.public, None, b"m", Some(&json!(sig)), None));
    assert!(!verify_leaf_suite(Some(&json!("bogus")), &ed.public, key.as_ref(), b"m", Some(&json!(sig)), None));
    // ed25519 (alg absent) never needs a PQ key
    let esig = b64(&ed.sign(b"m"));
    assert!(verify_leaf_suite(None, &ed.public, None, b"m", Some(&json!(esig)), None));
}

#[test]
fn composite_signature_round_trips_and_binds_the_context() {
    let m = composite_representative(b"msg", b"ctx").unwrap();
    let mut want = b"CompositeAlgorithmSignatures2025COMPSIG-MLDSA65-Ed25519-SHA512\x03ctx".to_vec();
    use sha2::{Digest, Sha512};
    want.extend_from_slice(&Sha512::digest(b"msg"));
    assert_eq!(m, want);
    assert!(composite_representative(b"msg", &[0u8; 256]).is_err());

    let seed = [4u8; 32];
    let ed_pub = URL_SAFE_NO_PAD.decode(KeyPair::from_seed(&seed).public).unwrap();
    let ml = ml_dsa_65_keygen(&[5u8; 32]).unwrap();
    let sig = composite_sign(&seed, &ml.secret_key, b"msg", b"ctx").unwrap();
    assert_eq!(sig.len(), COMPOSITE_SIGNATURE_BYTES);
    assert!(composite_verify(&ed_pub, &ml.public_key, b"msg", &sig, b"ctx"));
    assert!(!composite_verify(&ed_pub, &ml.public_key, b"msg", &sig, b"other"));
    assert!(!composite_verify(&ed_pub, &ml.public_key, b"msg2", &sig, b"ctx"));
    let mut t = sig.clone();
    t[10] ^= 1;
    assert!(!composite_verify(&ed_pub, &ml.public_key, b"msg", &t, b"ctx"));
    let mut t = sig.clone();
    t[COMPOSITE_SIGNATURE_BYTES - 1] ^= 1;
    assert!(!composite_verify(&ed_pub, &ml.public_key, b"msg", &t, b"ctx"));
    assert!(!composite_verify(&ed_pub, &ml.public_key, b"msg", &sig[1..], b"ctx"));
    assert!(!composite_verify(&ed_pub[1..], &ml.public_key, b"msg", &sig, b"ctx"));
    assert!(!composite_verify(&ed_pub, &ml.public_key, b"msg", &sig, &[0u8; 256]));
}
