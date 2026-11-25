//! Replays the verification cases of the shared reference corpus (verifyPolicyVmProof, BN254 and BLS12-381) against pca-zk.
//! The corpus holds the reference's end-to-end verdicts, which include checks that happen before the pairing (envelope shape,
//! circuit and system tags, context pins); the cases those checks alone decide are skipped here (GATE_ONLY). Every other case must
//! agree: in snarkjs-compat mode with the reference, in strict mode with the reference except the quirk-* cases, which snarkjs
//! accepts and strict mode refuses.
//! Corpus: PCA_ZK_CORPUS, else the checkout's sdks/go-pca/testdata/ref-zk.json.gz. PCA_ZK_REQUIRE=1 makes a missing corpus a failure.
use pca_zk::{verify, Curve, FLAG_SNARKJS_COMPAT};
use serde_json::Value;
use std::io::Read;

const GATE_ONLY: [&str; 7] = [
    "expect-now-wrong",
    "expect-thunk-throws",
    "expectRiskHash",
    "circuit-",
    "system-",
    "extra-key",
    "proof-extra-key",
];

fn corpus() -> Option<Value> {
    let p = std::env::var("PCA_ZK_CORPUS")
        .unwrap_or_else(|_| format!("{}/../../../sdks/go-pca/testdata/ref-zk.json.gz", env!("CARGO_MANIFEST_DIR")));
    let Ok(f) = std::fs::File::open(&p) else {
        assert!(std::env::var("PCA_ZK_REQUIRE").is_err(), "corpus not found at {p}");
        eprintln!("skipped: no corpus at {p}");
        return None;
    };
    let mut s = String::new();
    flate2::read::GzDecoder::new(f).read_to_string(&mut s).expect("gunzip corpus");
    Some(serde_json::from_str(&unpaired_surrogates_to_fffd(&s)).expect("corpus JSON"))
}

/// The corpus is written by a JavaScript runtime, which allows lone surrogate escapes in strings (the circuit-lone-surrogate
/// case); serde_json refuses them. Only the gate-only cases carry them, and those are skipped here, so an unpaired escape reads as U+FFFD.
fn unpaired_surrogates_to_fffd(s: &str) -> String {
    let b = s.as_bytes();
    let unit = |i: usize| -> Option<u32> {
        if b.get(i) == Some(&b'\\') && b.get(i + 1) == Some(&b'u') && i + 6 <= b.len() {
            u32::from_str_radix(std::str::from_utf8(&b[i + 2..i + 6]).ok()?, 16).ok()
        } else {
            None
        }
    };
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            out.push(b[i]);
            i += 1;
        } else if let Some(u) = unit(i) {
            let paired = (0xD800..0xDC00).contains(&u) && unit(i + 6).is_some_and(|l| (0xDC00..0xE000).contains(&l));
            if paired {
                out.extend_from_slice(&b[i..i + 12]);
                i += 12;
            } else if (0xD800..0xE000).contains(&u) {
                out.extend_from_slice(b"\\ufffd");
                i += 6;
            } else {
                out.extend_from_slice(&b[i..i + 6]);
                i += 6;
            }
        } else {
            out.extend_from_slice(&b[i..(i + 2).min(b.len())]); // any other escape: copy both bytes so an escaped backslash is not misread
            i += 2;
        }
    }
    String::from_utf8(out).expect("utf-8")
}

fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

#[test]
fn replay_verify_cases() {
    let Some(c) = corpus() else { return };
    let cases = c["cases"].as_array().expect("cases");
    let mut checked = 0;
    for (prefix, curve) in [
        ("verifyPolicyVmProof/bn/", Curve::Bn254),
        ("verifyPolicyVmProof/bls/", Curve::Bls12381),
    ] {
        let default_key = cases
            .iter()
            .find(|x| x["name"] == format!("{prefix}valid"))
            .map(|x| x["args"][1]["verificationKey"].clone())
            .expect("valid case");
        for x in cases.iter().filter(|x| x["name"].as_str().is_some_and(|n| n.starts_with(prefix))) {
            let name = x["name"].as_str().unwrap();
            let stem = &name[prefix.len()..];
            let env = &x["args"][0];
            let vk = match &x["args"][1]["verificationKey"] {
                Value::Null => &default_key,
                k => k,
            };
            let compat = verify(
                curve,
                FLAG_SNARKJS_COMPAT,
                &bytes(vk),
                &bytes(&env["proof"]),
                &bytes(&env["publicSignals"]),
            )
            .is_ok();
            let strict = verify(curve, 0, &bytes(vk), &bytes(&env["proof"]), &bytes(&env["publicSignals"])).is_ok();
            if x["out"] == true {
                assert!(compat, "{name}: compat mode must accept");
                assert_eq!(strict, !stem.starts_with("quirk"), "{name}: strict mode verdict");
            } else if stem.starts_with("protocol-") || stem.starts_with("proof-curve-") {
                // the reference refuses a non-groth16 protocol / a mismatching proof curve before the pairing; snarkjs-compat mode ignores both proof fields by design (verify.rs), strict mode must refuse them
                assert!(!strict, "{name}: strict mode must refuse a wrong proof protocol / curve");
                continue;
            } else if !GATE_ONLY.iter().any(|g| stem.starts_with(g)) {
                assert!(!compat && !strict, "{name}: must be refused in both modes");
            } else {
                continue;
            }
            checked += 1;
        }
    }
    assert!(checked > 120, "only {checked} cases replayed");
}

/// The key's curve name as snarkjs' getCurveFromName reads it: upper-cased, only ASCII letters and digits kept.
#[test]
fn curve_names_as_snarkjs_reads_them() {
    for (name, want) in [
        ("bn128", Some(Curve::Bn254)),
        ("BN128", Some(Curve::Bn254)),
        ("bn254", Some(Curve::Bn254)),
        ("BN-254", Some(Curve::Bn254)),
        ("alt_bn128", Some(Curve::Bn254)),
        ("ALT-BN128", Some(Curve::Bn254)),
        (" bn 128 ", Some(Curve::Bn254)),
        ("b.n.1.2.8", Some(Curve::Bn254)),
        ("bls12381", Some(Curve::Bls12381)),
        ("BLS12-381", Some(Curve::Bls12381)),
        ("bls12_381", Some(Curve::Bls12381)),
        ("Bls12 381", Some(Curve::Bls12381)),
        ("bl\u{17f}12381", Some(Curve::Bls12381)), // long s upper-cases to S, as in JavaScript
        ("", None),
        ("-", None),
        ("bn255", None),
        ("bn1280", None),
        ("xbn128", None),
        ("altbn254", None),
        ("bls12377", None),
        ("bls381", None),
        ("b\u{43d}128", None), // a Cyrillic letter is dropped, leaving B128
    ] {
        assert_eq!(Curve::from_snarkjs_name(name), want, "{name:?}");
    }
}

/// The verification cases of the corpus under other spellings of the key's curve: compat mode decides them as the reference
/// decides the original, strict mode takes only the exact name, and `verify_snarkjs` takes the curve from the key.
#[test]
fn curve_aliases_in_the_key() {
    let Some(c) = corpus() else { return };
    let cases = c["cases"].as_array().expect("cases");
    let find = |name: &str| cases.iter().find(|x| x["name"] == name).unwrap_or_else(|| panic!("no case {name}"));
    for (tag, curve, other, aliases) in [
        ("bn", Curve::Bn254, Curve::Bls12381, ["BN128", "bn254", "alt_bn128"]),
        ("bls", Curve::Bls12381, Curve::Bn254, ["BLS12381", "bls12-381", "BLS12_381"]),
    ] {
        let valid = find(&format!("verifyPolicyVmProof/{tag}/valid"));
        let tampered = find(&format!("verifyPolicyVmProof/{tag}/signal6+1"));
        let (proof, signals) = (bytes(&valid["args"][0]["proof"]), bytes(&valid["args"][0]["publicSignals"]));
        let bad_signals = bytes(&tampered["args"][0]["publicSignals"]);
        for alias in aliases {
            let mut key = valid["args"][1]["verificationKey"].clone();
            key["curve"] = Value::String(alias.to_string());
            let key = bytes(&key);
            assert!(verify(curve, FLAG_SNARKJS_COMPAT, &key, &proof, &signals).is_ok(), "{alias}: compat accepts the alias");
            assert!(pca_zk::verify_snarkjs(&key, &proof, &signals).is_ok(), "{alias}: the key names its curve");
            assert!(verify(curve, FLAG_SNARKJS_COMPAT, &key, &proof, &bad_signals).is_err(), "{alias}: a tampered signal is still refused");
            assert!(pca_zk::verify_snarkjs(&key, &proof, &bad_signals).is_err(), "{alias}: a tampered signal is still refused");
            assert_eq!(verify(curve, 0, &key, &proof, &signals).unwrap_err().reason, pca_zk::Reason::BadCurve, "{alias}: strict takes the exact name only");
            assert_eq!(verify(other, FLAG_SNARKJS_COMPAT, &key, &proof, &signals).unwrap_err().reason, pca_zk::Reason::BadCurve, "{alias}: not the curve asked for");
        }
        // names snarkjs does not know, and a key without one
        for name in [Value::String("bn255".into()), Value::String(String::new()), Value::Null, Value::from(128)] {
            let mut key = valid["args"][1]["verificationKey"].clone();
            key["curve"] = name.clone();
            let key = bytes(&key);
            assert_eq!(verify(curve, FLAG_SNARKJS_COMPAT, &key, &proof, &signals).unwrap_err().reason, pca_zk::Reason::BadCurve, "{name}");
            assert_eq!(pca_zk::verify_snarkjs(&key, &proof, &signals).unwrap_err().reason, pca_zk::Reason::BadCurve, "{name}");
        }
        // the exact name still verifies through every entry point
        let key = bytes(&valid["args"][1]["verificationKey"]);
        assert!(verify(curve, 0, &key, &proof, &signals).is_ok() && pca_zk::verify_snarkjs(&key, &proof, &signals).is_ok());
    }
}
