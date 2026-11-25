//! Differential replay of the Wesolowski VDF and the PCA timelock against the TypeScript reference (test-data/ref-vdf.json.gz).
//! Big integers cross as decimal strings (a string that is not an integer is the reference's BigInt() throw), step counts as JSON
//! numbers (`f64`, the JavaScript number). A reference throw only requires a refusal.
//! Not ported: insecureDevSetup (random; the generator does not exercise the in-process registry) and calibrateSteps (wall clock).
//! Skipped (counted, must stay under 10%): cases whose strings carry a lone surrogate (none expected).
mod common;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::vdf::*;
use base64::Engine;
use rsa::BigUint;

fn bi(v: Option<&Value>) -> Result<Int, String> {
    Int::parse(v.and_then(Value::as_str).ok_or("bigint arg: expected a decimal string")?)
}

/// A modulus argument: a negative value is a refusal for every entry point that takes a positive modulus.
fn bu(v: Option<&Value>) -> Result<BigUint, String> {
    let n = bi(v)?;
    if n.is_negative() {
        return Err("modulus must be positive".into());
    }
    Ok(n.magnitude().clone())
}

fn num(v: Option<&Value>) -> Result<f64, String> {
    v.and_then(Value::as_f64).ok_or_else(|| "expected a number".to_string())
}

fn dec(b: &BigUint) -> Value {
    Value::String(b.to_str_radix(10))
}

fn proof_json(p: &VdfProof) -> Value {
    json!({ "y": dec(&p.y), "pi": dec(&p.pi) })
}

fn verdict(v: VdfVerdict) -> Value {
    match v.reason() {
        None => json!({ "ok": true }),
        Some(r) => json!({ "ok": false, "reason": r }),
    }
}

/// The timelock options object `{steps, N, beacon, allowInsecureDevModulus?}`.
fn opts(v: Option<&Value>) -> Result<(f64, Option<BigUint>, Vec<u8>, bool), String> {
    let o = v.and_then(Value::as_object).ok_or("expected an options object")?;
    let steps = num(o.get("steps")).unwrap_or(f64::NAN);
    let n = bu(o.get("N")).ok();
    let beacon = o.get("beacon").and_then(Value::as_str).map(|s| s.as_bytes().to_vec()).ok_or("beacon must be a string")?;
    Ok((steps, n, beacon, o.get("allowInsecureDevModulus").and_then(Value::as_bool) == Some(true)))
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let g = |i: usize| a.get(i);
    match f {
        "isProbablePrime" => Ok(Value::Bool(is_probable_prime(&bi(g(0))?))),
        "isMillerRabinProbablePrime" => Ok(Value::Bool(is_miller_rabin_probable_prime(&bi(g(0))?))),
        "isStrongLucasProbablePrime" => Ok(Value::Bool(is_strong_lucas_probable_prime(&bi(g(0))?))),
        "hashToPrime" => {
            let bits = match g(4) {
                None | Some(Value::Null) => None,
                Some(v) => Some(num(Some(v))?),
            };
            Ok(dec(&hash_to_prime(&bi(g(0))?, &bi(g(1))?, num(g(2))?, &bu(g(3))?, bits)?))
        }
        "modpow" => Ok(dec(&modpow(&bi(g(0))?, &bi(g(1))?, &bi(g(2))?)?)),
        "gcd" => Ok(dec(&gcd(&bi(g(0))?, &bi(g(1))?))),
        "canonicalVdfOutput" => Ok(dec(&canonical_vdf_output(bi(g(0))?.magnitude(), &bu(g(1))?)?)),
        "bigIntToBytes" => Ok(json!({ "$bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(big_int_to_bytes(&bi(g(0))?)?) })),
        "bytesRoundTrip" => {
            let b = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(g(0).and_then(Value::as_str).ok_or("expected base64url")?)
                .map_err(|e| e.to_string())?;
            let v = Int::from_biguint(bytes_to_big_int(&b));
            Ok(json!({ "$bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(big_int_to_bytes(&v)?) }))
        }
        "sequentialSquare" => Ok(dec(&sequential_square(&bi(g(0))?, num(g(1))?, &bu(g(2))?)?)),
        "vdfEval" => Ok(proof_json(&vdf_eval(&bi(g(0))?, num(g(1))?, &bu(g(2))?)?)),
        "vdfEvalCanonical" => Ok(proof_json(&vdf_eval_canonical(&bi(g(0))?, num(g(1))?, &bu(g(2))?)?)),
        "vdfVerifyDetailed" => Ok(verdict(vdf_verify_detailed(&bi(g(0))?, &bi(g(1))?, &bi(g(2))?, num(g(3))?, &bi(g(4))?))),
        "vdfVerifyCanonicalDetailed" => Ok(verdict(vdf_verify_canonical_detailed(&bi(g(0))?, &bi(g(1))?, &bi(g(2))?, num(g(3))?, &bi(g(4))?))),
        "checkProductionModulus" => Ok(match check_production_modulus(&bi(g(0))?) {
            Ok(()) => json!({ "ok": true }),
            Err(r) => json!({ "ok": false, "reason": r }),
        }),
        "deriveTimelockInput" => {
            let beacon = g(2).and_then(Value::as_str).ok_or("beacon must be a string")?;
            Ok(dec(&derive_timelock_input(g(0).ok_or("action")?, &bu(g(1))?, beacon.as_bytes())?))
        }
        "requireTimelock" => {
            let (steps, n, beacon, allow) = opts(g(1))?;
            let n = n.ok_or("N")?;
            let r = require_timelock(g(0).ok_or("action")?, steps, &n, &beacon, allow)?;
            Ok(json!({ "kind": "vdf-timelock", "x": dec(&r.x), "steps": r.steps, "N": dec(&r.n), "actionDigest": r.action_digest }))
        }
        "proveTimelockElapsed" => {
            let n = bu(g(2))?;
            let o = g(3).and_then(Value::as_object).ok_or("expected an options object")?;
            let beacon = o.get("beacon").and_then(Value::as_str).ok_or("beacon must be a string")?;
            let allow = o.get("allowInsecureDevModulus").and_then(Value::as_bool) == Some(true);
            let p = prove_timelock_elapsed(g(0).ok_or("action")?, num(g(1))?, &n, beacon.as_bytes(), allow)?;
            Ok(json!({ "kind": "vdf-timelock-proof", "y": p.y.to_decimal(), "pi": p.pi.to_decimal(), "steps": p.steps }))
        }
        "verifyTimelock" => {
            // fails closed: anything malformed is `false`, never a refusal
            let ok = (|| {
                let proof = TimelockProof::from_json(g(1)?)?;
                let (steps, n, beacon, allow) = opts(g(2)).ok()?;
                Some(verify_timelock(g(0)?, &proof, steps, &n?, &beacon, allow))
            })();
            Ok(Value::Bool(ok.unwrap_or(false)))
        }
        f => panic!("unknown fn {f}"),
    }
}

/// Replay the corpus cases whose function `pick`s; the corpus is split over several tests so each runs well inside a mutation
/// shard's per-test limit (one test over all 6.6k cases, primality and squarings included, ran for minutes).
fn replay(pick: impl Fn(&str, usize) -> bool) {
    replay_cases(|c, i| !is_8192_bit_search(c) && pick(c["fn"].as_str().unwrap(), i));
}

/// The one case that searches an 8192-bit challenge prime: ~4 minutes even in a release build, so no mutation shard's per-test limit
/// holds it. It has its own `#[ignore]`d test (run in CI with `-- --ignored`); the range edge it exercises is killed fast by
/// `challenge_bits_test` in src/vdf.rs, and the 512-bit cases drive the same search code.
fn is_8192_bit_search(c: &Value) -> bool {
    c["fn"] == "hashToPrime" && c["args"].get(4).and_then(Value::as_f64) == Some(8192.0)
}

fn replay_cases(pick: impl Fn(&Value, usize) -> bool) {
    let all = common::ref_cases("vdf");
    let cases: Vec<&Value> = all.iter().enumerate().filter(|(i, c)| pick(c, *i)).map(|(_, c)| c).collect();
    assert!(!cases.is_empty(), "no case in this group");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let args = c["args"].as_array().unwrap();
        let got = std::panic::catch_unwind(|| run(f, args)).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

const NAMED: &[&str] = &[
    "isProbablePrime",
    "isStrongLucasProbablePrime",
    "isMillerRabinProbablePrime",
    "vdfVerifyDetailed",
    "vdfVerifyCanonicalDetailed",
    "verifyTimelock",
    "vdfEval",
    "vdfEvalCanonical",
    "requireTimelock",
    "proveTimelockElapsed",
    "sequentialSquare",
    "hashToPrime",
    "checkProductionModulus",
];

#[test]
fn vdf_vectors_is_probable_prime() {
    replay(|f, _| f == "isProbablePrime");
}
#[test]
fn vdf_vectors_lucas() {
    replay(|f, _| f == "isStrongLucasProbablePrime");
}
#[test]
fn vdf_vectors_miller_rabin() {
    replay(|f, _| f == "isMillerRabinProbablePrime");
}
#[test]
fn vdf_vectors_verify() {
    replay(|f, _| f == "vdfVerifyDetailed");
}
#[test]
fn vdf_vectors_verify_canonical() {
    replay(|f, _| f == "vdfVerifyCanonicalDetailed");
}
#[test]
fn vdf_vectors_verify_timelock() {
    replay(|f, _| f == "verifyTimelock");
}
#[test]
fn vdf_vectors_eval() {
    replay(|f, _| f == "vdfEval" || f == "vdfEvalCanonical");
}
#[test]
fn vdf_vectors_timelock_and_squares() {
    replay(|f, _| matches!(f, "requireTimelock" | "proveTimelockElapsed" | "sequentialSquare"));
}
/// hashToPrime and the production-modulus screen run big-integer primality in an unoptimised build: a few cases per test, so
/// no test outlasts a mutation shard's slow limit.
macro_rules! sharded {
    ($($name:ident: $f:literal, $k:literal, $n:literal;)*) => {$(
        #[test]
        fn $name() {
            replay(|f, i| f == $f && i % $n == $k);
        }
    )*};
}
sharded! {
    vdf_vectors_hash_to_prime_0: "hashToPrime", 0, 8;
    vdf_vectors_hash_to_prime_1: "hashToPrime", 1, 8;
    vdf_vectors_hash_to_prime_2: "hashToPrime", 2, 8;
    vdf_vectors_hash_to_prime_3: "hashToPrime", 3, 8;
    vdf_vectors_hash_to_prime_4: "hashToPrime", 4, 8;
    vdf_vectors_hash_to_prime_5: "hashToPrime", 5, 8;
    vdf_vectors_hash_to_prime_6: "hashToPrime", 6, 8;
    vdf_vectors_hash_to_prime_7: "hashToPrime", 7, 8;
    vdf_vectors_check_modulus_0: "checkProductionModulus", 0, 6;
    vdf_vectors_check_modulus_1: "checkProductionModulus", 1, 6;
    vdf_vectors_check_modulus_2: "checkProductionModulus", 2, 6;
    vdf_vectors_check_modulus_3: "checkProductionModulus", 3, 6;
    vdf_vectors_check_modulus_4: "checkProductionModulus", 4, 6;
    vdf_vectors_check_modulus_5: "checkProductionModulus", 5, 6;
}
#[test]
#[ignore = "an 8192-bit prime search runs minutes; CI runs it with --ignored"]
fn vdf_vectors_hash_to_prime_8192_bits() {
    replay_cases(|c, _| is_8192_bit_search(c));
}
/// Every function not named above (a new corpus function lands here, never nowhere).
#[test]
fn vdf_vectors_rest() {
    replay(|f, _| !NAMED.contains(&f));
}
