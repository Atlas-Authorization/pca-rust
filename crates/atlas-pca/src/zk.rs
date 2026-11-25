//! Zero-knowledge proof of compliance: the agent proves that an action is a valid derivation under a policy from a committed
//! plan without showing the policy, the plan or its reasoning to the resource server.
//!
//! Two realisations. The attested-VM one ([`create_attested_compliance_prover`], [`create_zk_verifier`]): a trusted VM runs the
//! Policy VM and signs a statement that carries only commitments (digests) of the action, the policy and the plan. The SNARK one:
//! a Groth16 proof (snarkjs encoding) of the first compliance circuit `pca-compliance-v1` (BN254), of the full Policy VM circuit
//! `pca-policyvm-v1` (BN254 and BLS12-381, verifying keys bundled) or of the risk-bound circuit `pca-policyvm-v2` (BN254),
//! checked by [`verify_policy_vm_proof`] and the four [`SnarkBackend`] factories. The rest is the public-input derivation those
//! proofs bind to: [`commitment_field`], [`policy_vm_struct_hash`], the quantizers, the context pins and the canonical envelope
//! gate.
//!
//! The pairing check itself is not in this crate: cargo feature `zk` links the `pca-zk` crate (arkworks) and
//! [`DefaultGroth16Engine`] calls it with the rules of snarkjs' own verifier. Without the feature every other function works and
//! a proof that reaches the pairing check is refused (fail closed). Every gate the reference applies in front of the pairing
//! (envelope shape, circuit and system tags, signal count, allow bit, risk pin, canonical decimals, context pins) is applied here
//! first, whatever the engine.
//!
//! JSON numbers: an integer up to 2^64 - 1 written as a JSON number is taken exactly (the reference needs a bigint above 2^53).
//! Loosely typed input is read as the JavaScript reference reads it (an options value that is not an object counts as empty, a
//! catalog or `params` given as an array or text is indexed, integer text and arrays convert as `BigInt` converts them), and
//! where the reference throws, the function here answers `Err`.

use crate::assurance::{AssuranceLabel, AssuranceLabelled};
use crate::attest::{AttResult, Binding};
use crate::intent_v2::js_value_string;
use crate::zk_ceremony::ceremony_of;
use crate::{canonicalize_strict, decode_b64u_strict, HookResult};
use ed25519_dalek::{Signer, SigningKey};
use rsa::BigUint;
use serde_json::{json, Map, Value};
use std::cmp::Ordering;
use std::collections::HashSet;
use std::sync::Arc;

const DOMAIN: &[u8] = b"atlas-pca/zk-compliance/v1\0";

/// `grant_ref` of the binding a prover VM's hardware quote carries (see [`prover_key_binding`]).
pub const ZK_PROVER_BINDING_REF: &str = "atlas-pca/zk-prover/v1";

const BN254_FR: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
const BN254_FQ: &str = "21888242871839275222246405745257275088696311157297823662689037894645226208583";
const BLS12381_FQ: &str = "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787";
const BLS12381_FR: &str = "52435875175126190479447740508185965837690552500527637822603658699938581184513";
const TWO_64: &str = "18446744073709551616";
const MAX_SAFE: u64 = 9_007_199_254_740_991;

const VKEY_BN254: &str = include_str!("zk_circuits/policyvm_vkey.json");
const VKEY_BLS12381: &str = include_str!("zk_circuits/policyvm_bls12381_vkey.json");
const CIRCUIT_VERSIONS: &str = include_str!("zk_circuits/circuit-versions.json");
const NO_ENGINE: &str = "Groth16 engine not available (build with the cargo feature \"zk\")";

// ---- artifact locations, relative to the reference package (this crate bundles the two Policy VM verifying keys and the circuit
// version table; it ships no circuit build, so the provers take explicit paths)
pub const DEFAULT_VKEY_PATH: &str = "circuits/build/verification_key.json";
pub const DEFAULT_WASM_PATH: &str = "circuits/build/compliance_js/compliance.wasm";
pub const DEFAULT_ZKEY_PATH: &str = "circuits/build/compliance_final.zkey";
pub const POLICYVM_VKEY_PATH: &str = "circuits/policyvm_vkey.json";
pub const POLICYVM_SAMPLE_PROOF_PATH: &str = "circuits/policyvm_sample_proof.json";
pub const POLICYVM_WASM_PATH: &str = "circuits/build/policyvm_js/policyvm.wasm";
pub const POLICYVM_ZKEY_PATH: &str = "circuits/build/policyvm_final.zkey";
pub const POLICYVM_BLS12381_VKEY_PATH: &str = "circuits/policyvm_bls12381_vkey.json";
pub const POLICYVM_BLS12381_SAMPLE_PROOF_PATH: &str = "circuits/policyvm_bls12381_sample_proof.json";
pub const POLICYVM_BOUND_VKEY_PATH: &str = "circuits/build/policyvm_bound_vkey.json";
pub const POLICYVM_BOUND_SAMPLE_PROOF_PATH: &str = "circuits/build/policyvm_bound_sample_proof.json";
pub const POLICYVM_BOUND_WASM_PATH: &str = "circuits/build/policyvm_bound_js/policyvm_bound.wasm";
pub const POLICYVM_BOUND_ZKEY_PATH: &str = "circuits/build/policyvm_bound_final.zkey";

/// Where each value sits in a Policy VM proof's public signals (circuit outputs first, then the public inputs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyVmSignalLayout {
    pub action_hi: usize,
    pub action_lo: usize,
    pub policy_hi: usize,
    pub policy_lo: usize,
    pub plan_hi: usize,
    pub plan_lo: usize,
    pub r: usize,
    pub t: usize,
    pub admit: usize,
    /// The risk commitment halves: only the risk-bound circuit has them.
    pub risk_hi: Option<usize>,
    pub risk_lo: Option<usize>,
    pub allow: usize,
    pub now: usize,
    pub blast: usize,
    pub delegation_depth: usize,
    pub recent_count: usize,
    pub alloc_child: usize,
}

/// Public-signal layout of `pca-policyvm-v1`.
pub const POLICYVM_PUBLIC_SIGNAL: PolicyVmSignalLayout = PolicyVmSignalLayout {
    action_hi: 0,
    action_lo: 1,
    policy_hi: 2,
    policy_lo: 3,
    plan_hi: 4,
    plan_lo: 5,
    r: 6,
    t: 7,
    admit: 8,
    risk_hi: None,
    risk_lo: None,
    allow: 9,
    now: 10,
    blast: 11,
    delegation_depth: 12,
    recent_count: 13,
    alloc_child: 14,
};
pub const POLICYVM_PUBLIC_SIGNAL_COUNT: usize = 15;

/// Public-signal layout of the risk-bound circuit `pca-policyvm-v2`.
pub const POLICYVM_BOUND_PUBLIC_SIGNAL: PolicyVmSignalLayout = PolicyVmSignalLayout {
    action_hi: 0,
    action_lo: 1,
    policy_hi: 2,
    policy_lo: 3,
    plan_hi: 4,
    plan_lo: 5,
    r: 6,
    t: 7,
    admit: 8,
    risk_hi: Some(9),
    risk_lo: Some(10),
    allow: 11,
    now: 12,
    blast: 13,
    delegation_depth: 14,
    recent_count: 15,
    alloc_child: 16,
};
pub const POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT: usize = 17;

/// The risk magnitudes the risk-bound circuit commits to, in struct order.
pub const POLICYVM_BOUND_RISK_FIELDS: [&str; 5] = ["revScore", "taint", "conf", "age", "rFloorIn"];

/// Reversibility classes in the order the circuit encodes them (index 0, 1, 2).
pub const POLICYVM_REVERSIBILITY_ORDER: [&str; 3] = ["reversible", "rate_limited", "irreversible"];

// ---- small helpers -----------------------------------------------------------------------------------------------------------

fn hash_canonical(v: &Value) -> Result<String, String> {
    Ok(crate::b64_encode(&crate::sha(canonicalize_strict(v)?.as_bytes())))
}

/// JavaScript truthiness of an optional JSON value.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        _ => true,
    }
}

/// A canonical decimal: digits only, no leading zero.
fn canon_dec(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) && (s.len() == 1 || !s.starts_with('0'))
}

/// `a < bound` for two canonical decimals.
fn dec_below(a: &str, bound: &str) -> bool {
    a.len() < bound.len() || (a.len() == bound.len() && a < bound)
}

fn big_u64(n: &BigUint) -> Option<u64> {
    let b = n.to_bytes_be();
    (b.len() <= 8).then(|| b.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x)))
}

/// An integer-valued JSON number as a uint64: `Ok(None)` for an integer outside `[0, 2^64)`, `Err` for a fraction.
fn number_u64(n: &serde_json::Number) -> Result<Option<u64>, ()> {
    if let Some(u) = n.as_u64() {
        return Ok(Some(u));
    }
    if n.as_i64().is_some() {
        return Ok(None);
    }
    let f = n.as_f64().ok_or(())?;
    if !f.is_finite() || f.fract() != 0.0 {
        return Err(());
    }
    Ok((0.0..18_446_744_073_709_551_616.0).contains(&f).then_some(f as u64))
}

/// JavaScript `BigInt(text)`: surrounding whitespace ignored, empty is 0, a decimal with an optional sign, or an unsigned
/// `0x` / `0o` / `0b` literal. `(negative, magnitude)`; `None` for anything else.
fn js_string_bigint(s: &str) -> Option<(bool, BigUint)> {
    let t = s.trim_matches(|c: char| (c.is_whitespace() && c != '\u{85}') || c == '\u{feff}');
    if t.is_empty() {
        return Some((false, BigUint::from(0u8)));
    }
    let lower = t.get(..2).map(str::to_ascii_lowercase);
    let (radix, digits, neg) = match lower.as_deref() {
        Some("0x") => (16, &t[2..], false),
        Some("0o") => (8, &t[2..], false),
        Some("0b") => (2, &t[2..], false),
        _ => match t.as_bytes()[0] {
            b'-' => (10, &t[1..], true),
            b'+' => (10, &t[1..], false),
            _ => (10, t, false),
        },
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    let mag = BigUint::parse_bytes(digits.as_bytes(), radix)?;
    Some((neg && mag != BigUint::from(0u8), mag))
}

// ---- commitments -------------------------------------------------------------------------------------------------------------

/// Commitment to the policy: the grant's content address (its `id`, else the digest of its strict canonical JSON). `Err` for a
/// grant outside the strict JSON profile.
pub fn policy_commitment(grant: &Value) -> Result<String, String> {
    match grant.get("id").and_then(Value::as_str) {
        Some(id) => Ok(id.to_string()),
        None => hash_canonical(grant),
    }
}

/// The policy commitment a resource server pins when it may not read the grant ([`policy_commitment`]).
pub fn pinned_policy_commitment(grant: &Value) -> Result<String, String> {
    policy_commitment(grant)
}

/// Commitment to the action: the digest of the PCActn's `action` member (of `null` without one).
pub fn action_commitment(pcactn: &Value) -> Result<String, String> {
    hash_canonical(pcactn.get("action").unwrap_or(&Value::Null))
}

/// The binding a prover VM puts in its hardware quote so that the quote vouches for its key.
pub fn prover_key_binding(prover_public_key: &str, epoch: f64, nonce: &str) -> Binding {
    Binding { holder_pub: prover_public_key.to_string(), grant_ref: ZK_PROVER_BINDING_REF.to_string(), epoch, nonce: nonce.to_string() }
}

/// A base64url commitment as a BN254 scalar-field element (decimal): the decoded bytes, of any length, as a big-endian integer
/// reduced modulo the field order. `Err` for text that is not strict unpadded base64url.
pub fn commitment_field(b64u_commit: &str) -> Result<String, String> {
    let bytes = decode_b64u_strict(b64u_commit, None).ok_or("commitmentField: not base64url")?;
    let r = BigUint::parse_bytes(BN254_FR.as_bytes(), 10).ok_or("field order")?;
    Ok((BigUint::from_bytes_be(&bytes) % r).to_str_radix(10))
}

// ---- canonical Groth16 envelope gate -------------------------------------------------------------------------------------------

fn canon_dec_below(v: Option<&Value>, bound: &str) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| s.len() <= 120 && canon_dec(s) && dec_below(s, bound))
}

fn same_keys(m: &Map<String, Value>, keys: &[&str]) -> bool {
    m.len() == keys.len() && keys.iter().all(|k| m.contains_key(*k))
}

/// True iff `env` is the one canonical Groth16 envelope for `curve` (`"bn254"`, anything else is BLS12-381): exactly the members
/// `system`, `circuit`, `proof`, `publicSignals`; every coordinate and signal a decimal string without leading zeros, at most 120
/// characters and below its field modulus; affine points with z = `"1"` (G2: `["1", "0"]`).
pub fn is_canonical_groth16_envelope(env: &Value, curve: &str) -> bool {
    let Some(e) = env.as_object() else { return false };
    if !same_keys(e, &["system", "circuit", "proof", "publicSignals"]) {
        return false;
    }
    let bn = curve == "bn254";
    let (fq, fr) = if bn { (BN254_FQ, BN254_FR) } else { (BLS12381_FQ, BLS12381_FR) };
    if !e["publicSignals"].as_array().is_some_and(|a| a.iter().all(|x| canon_dec_below(Some(x), fr))) {
        return false;
    }
    let Some(pr) = e["proof"].as_object() else { return false };
    if !same_keys(pr, &["pi_a", "pi_b", "pi_c", "protocol", "curve"]) {
        return false;
    }
    if pr["protocol"] != "groth16" || pr["curve"] != (if bn { "bn128" } else { "bls12381" }) {
        return false;
    }
    let pair = |v: &Value| v.as_array().is_some_and(|a| a.len() == 2 && canon_dec_below(a.first(), fq) && canon_dec_below(a.get(1), fq));
    let g1 = |v: &Value| v.as_array().is_some_and(|a| a.len() == 3 && canon_dec_below(a.first(), fq) && canon_dec_below(a.get(1), fq) && a[2] == "1");
    if !g1(&pr["pi_a"]) || !g1(&pr["pi_c"]) {
        return false;
    }
    let Some(b) = pr["pi_b"].as_array().filter(|b| b.len() == 3) else { return false };
    pair(&b[0]) && pair(&b[1]) && b[2].as_array().is_some_and(|z| z.len() == 2 && z[0] == "1" && z[1] == "0")
}

// ---- struct hashes -----------------------------------------------------------------------------------------------------------

/// A SHA-256 digest as the circuit's two 128-bit big-endian halves (decimal strings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestHalves {
    pub hi: String,
    pub lo: String,
}

/// [`policy_vm_struct_hash`] of fields that are already uint64.
pub fn policy_vm_struct_hash_u64(fields: &[u64]) -> DigestHalves {
    let bytes: Vec<u8> = fields.iter().flat_map(|f| f.to_be_bytes()).collect();
    let d = crate::sha(&bytes);
    let half = |b: &[u8]| b.iter().fold(0u128, |a, x| (a << 8) | u128::from(*x)).to_string();
    DigestHalves { hi: half(&d[..16]), lo: half(&d[16..32]) }
}

/// The integer a struct field stands for: an integer-valued number, a boolean (0 / 1), integer text as JavaScript `BigInt`
/// reads it, or an array (its text). `Err` for anything else and for a value outside the uint64 range.
fn struct_field(v: &Value) -> Result<u64, String> {
    const RANGE: &str = "policyVmStructHash: field out of uint64 range";
    match v {
        Value::Bool(b) => Ok(u64::from(*b)),
        Value::Number(n) => number_u64(n).map_err(|()| "policyVmStructHash: field is not an integer".to_string())?.ok_or_else(|| RANGE.to_string()),
        Value::String(s) => {
            let (neg, mag) = js_string_bigint(s).ok_or("policyVmStructHash: field is not an integer")?;
            big_u64(&mag).filter(|_| !neg).ok_or_else(|| RANGE.to_string())
        }
        // an array converts through its text, as in JavaScript: [] is 0, [5] is 5
        Value::Array(_) => struct_field(&Value::String(js_value_string(v))),
        _ => Err("policyVmStructHash: field is not an integer".into()),
    }
}

/// Serialise the fields as the circuit does (each a 64-bit unsigned big-endian integer), SHA-256 them and split the digest
/// into its two 128-bit halves: what the circuit exposes as a struct commitment.
pub fn policy_vm_struct_hash(fields: &[Value]) -> Result<DigestHalves, String> {
    Ok(policy_vm_struct_hash_u64(&fields.iter().map(struct_field).collect::<Result<Vec<u64>, String>>()?))
}

/// The risk commitment of the risk-bound circuit: [`policy_vm_struct_hash`] of exactly the five risk magnitudes, in
/// [`POLICYVM_BOUND_RISK_FIELDS`] order.
pub fn policy_vm_risk_hash(fields: &[Value]) -> Result<DigestHalves, String> {
    if fields.len() != POLICYVM_BOUND_RISK_FIELDS.len() {
        return Err("policyVmRiskHash: need exactly 5 risk fields".into());
    }
    policy_vm_struct_hash(fields)
}

// ---- quantization: the live action, plan node and policy as the circuit's fixed uint64 structs -----------------------------------

/// Member names a JavaScript value inherits (ECMAScript 2025): reading one of them gives a function, never a number.
const OBJECT_PROTOTYPE_KEYS: [&str; 12] = [
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
    "__proto__",
    "constructor",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toLocaleString",
    "toString",
    "valueOf",
];
const ARRAY_PROTOTYPE_KEYS: [&str; 36] = [
    "at", "concat", "copyWithin", "entries", "every", "fill", "filter", "find", "findIndex", "findLast", "findLastIndex", "flat", "flatMap", "forEach", "includes", "indexOf", "join", "keys",
    "lastIndexOf", "map", "pop", "push", "reduce", "reduceRight", "reverse", "shift", "slice", "some", "sort", "splice", "toReversed", "toSorted", "toSpliced", "unshift", "values", "with",
];
const STRING_PROTOTYPE_KEYS: [&str; 48] = [
    "anchor", "at", "big", "blink", "bold", "charAt", "charCodeAt", "codePointAt", "concat", "endsWith", "fixed", "fontcolor", "fontsize", "includes", "indexOf", "isWellFormed", "italics",
    "lastIndexOf", "link", "localeCompare", "match", "matchAll", "normalize", "padEnd", "padStart", "repeat", "replace", "replaceAll", "search", "slice", "small", "split", "startsWith", "strike",
    "sub", "substr", "substring", "sup", "toLocaleLowerCase", "toLocaleUpperCase", "toLowerCase", "toUpperCase", "toWellFormed", "trim", "trimEnd", "trimLeft", "trimRight", "trimStart",
];
const NUMBER_PROTOTYPE_KEYS: [&str; 3] = ["toExponential", "toFixed", "toPrecision"];

/// The own property `key` of a JSON value as JavaScript has it: a member of an object, an element or the `length` of an array,
/// a UTF-16 code unit or the `length` of text. Nothing else has own properties.
fn own_property(v: &Value, key: &str) -> Option<Value> {
    let index = || key.parse::<u32>().ok().filter(|n| *n != u32::MAX && n.to_string() == key).map(|n| n as usize);
    match v {
        Value::Object(m) => m.get(key).cloned(),
        Value::Array(a) if key == "length" => Some(json!(a.len())),
        Value::Array(a) => index().and_then(|i| a.get(i).cloned()),
        Value::String(s) => {
            let units: Vec<u16> = s.encode_utf16().collect();
            if key == "length" {
                return Some(json!(units.len()));
            }
            index().and_then(|i| units.get(i).map(|u| Value::String(String::from_utf16_lossy(&[*u]))))
        }
        _ => None,
    }
}

/// `key` names a member the value inherits from its JavaScript prototype chain.
fn inherited_property(v: &Value, key: &str) -> bool {
    let own_type: &[&str] = match v {
        Value::Array(_) => &ARRAY_PROTOTYPE_KEYS,
        Value::String(_) => &STRING_PROTOTYPE_KEYS,
        Value::Number(_) => &NUMBER_PROTOTYPE_KEYS,
        _ => &[],
    };
    OBJECT_PROTOTYPE_KEYS.contains(&key) || own_type.contains(&key)
}

/// The options of a quantizer: `null` is refused (the reference throws on it); any other value that is not an object has no
/// members, so it counts as empty.
fn quantize_opts(opts: &Value) -> Result<&Value, String> {
    if opts.is_null() {
        return Err("policyvm quantize: options are null".into());
    }
    Ok(opts)
}

fn content_address_u64(domain: &str, value: &str) -> u64 {
    let d = crate::sha(format!("atlas-pca/policyvm-quantize/{domain}:{value}").as_bytes());
    d[..8].iter().fold(0u64, |a, x| (a << 8) | u64::from(*x))
}

fn to_u64(v: Option<&Value>, what: &str) -> Result<u64, String> {
    let n = match v {
        Some(Value::Number(n)) => number_u64(n).ok().flatten(),
        _ => None,
    };
    n.ok_or_else(|| format!("policyvm quantize: {what} is not a uint64"))
}

fn code_for(domain: &str, value: Option<&Value>, opts: &Value) -> Result<u64, String> {
    let value = value.and_then(Value::as_str).ok_or_else(|| format!("policyvm quantize: {domain} must be a string"))?;
    let map = opts.get(if domain == "verb" { "verbCodes" } else { "resourceCodes" }).filter(|m| truthy(Some(*m)));
    if let Some(code) = map.and_then(|m| own_property(m, value)) {
        return to_u64(Some(&code), &format!("{domain} code"));
    }
    if opts.get("strictCatalog") == Some(&Value::Bool(true)) {
        return Err(format!("policyvm quantize: {domain} \"{value}\" is not in the catalog (strict)"));
    }
    Ok(content_address_u64(domain, value))
}

fn param_scalar(params: Option<&Value>, field: Option<&Value>) -> Result<u64, String> {
    const NOT: &str = "policyvm quantize: paramScalar is not a non-negative integer";
    const MUST: &str = "policyvm quantize: paramScalar must be a non-negative integer";
    let (Some(field), Some(params)) = (field.filter(|f| truthy(Some(*f))), params.filter(|p| truthy(Some(*p)))) else { return Ok(0) };
    // `params[field]`: the member named by the field's text, own or inherited
    let key = js_value_string(field);
    let v = match own_property(params, &key) {
        Some(v) => v,
        None if inherited_property(params, &key) => return Err(NOT.into()),
        None => return Ok(0),
    };
    match &v {
        Value::Null => Ok(0),
        Value::Number(n) => {
            let f = n.as_f64().unwrap_or(f64::NAN);
            if !f.is_finite() || f.fract() != 0.0 || f < 0.0 || (f == 0.0 && f.is_sign_negative()) {
                return Err(MUST.into());
            }
            to_u64(Some(&v), "paramScalar")
        }
        Value::String(s) if !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) => {
            BigUint::parse_bytes(s.as_bytes(), 10).as_ref().and_then(big_u64).ok_or_else(|| "policyvm quantize: paramScalar is not a uint64".to_string())
        }
        _ => Err(NOT.into()),
    }
}

fn reversibility_index(rc: Option<&Value>, what: &str) -> Result<u64, String> {
    let idx = rc.and_then(Value::as_str).and_then(|s| POLICYVM_REVERSIBILITY_ORDER.iter().position(|c| *c == s));
    idx.map(|i| i as u64).ok_or_else(|| format!("policyvm quantize: unknown {what} class {}", rc.unwrap_or(&Value::Null)))
}

/// Quantize the live action (`{verb, resource, reversibility_class?, params?}`) to the circuit's action struct
/// `[verb code, resource code, reversibility index, param scalar]`. `opts` is `{verbCodes?, resourceCodes?, strictCatalog?,
/// paramScalarField?}`: a verb or resource missing from its catalog is content-addressed (first 8 bytes of a domain-tagged
/// SHA-256), or refused under `strictCatalog`. `Err` (fail closed) for anything that cannot be quantized, `null` options
/// included; options of any other type that is not an object count as empty.
pub fn quantize_action_struct(action: &Value, opts: &Value) -> Result<[u64; 4], String> {
    let a = action.as_object().ok_or("policyvm quantize: action is missing")?;
    let o = quantize_opts(opts)?;
    let verb = code_for("verb", a.get("verb"), o)?;
    let resource = code_for("resource", a.get("resource"), o)?;
    let class = a.get("reversibility_class").filter(|c| !c.is_null());
    let rev = match class {
        Some(c) => reversibility_index(Some(c), "reversibility")?,
        None => 0,
    };
    Ok([verb, resource, rev, param_scalar(a.get("params"), o.get("paramScalarField"))?])
}

/// Quantize a plan node (`{verb, resource, semanticDist, planSalt}`) to the circuit's plan struct.
pub fn quantize_plan_struct(plan: &Value, opts: &Value) -> Result<[u64; 4], String> {
    let p = plan.as_object().ok_or("policyvm quantize: plan is missing")?;
    let o = quantize_opts(opts)?;
    Ok([code_for("verb", p.get("verb"), o)?, code_for("resource", p.get("resource"), o)?, to_u64(p.get("semanticDist"), "semanticDist")?, to_u64(p.get("planSalt"), "planSalt")?])
}

/// Quantize a policy (`{weights: {alpha, beta, gamma, delta, epsilon, zeta}, theta1, theta2, kappa, budgetB, policyVerb,
/// policyResource, policyParamBound, expiresAt, notBefore, maxBlast, maxDepth, revMax, rateMax, allocParent}`) to the circuit's
/// 20-field policy struct.
pub fn quantize_policy_struct(policy: &Value, opts: &Value) -> Result<Vec<u64>, String> {
    let p = policy.as_object().ok_or("policyvm quantize: policy is missing")?;
    let o = quantize_opts(opts)?;
    let w = p.get("weights").and_then(Value::as_object).ok_or("policyvm quantize: weights are missing")?;
    let mut out = Vec::with_capacity(20);
    for (k, what) in [("alpha", "wAlpha"), ("beta", "wBeta"), ("gamma", "wGamma"), ("delta", "wDelta"), ("epsilon", "wEpsilon"), ("zeta", "wZeta")] {
        out.push(to_u64(w.get(k), what)?);
    }
    for k in ["theta1", "theta2", "kappa", "budgetB"] {
        out.push(to_u64(p.get(k), k)?);
    }
    out.push(code_for("verb", p.get("policyVerb"), o)?);
    out.push(code_for("resource", p.get("policyResource"), o)?);
    for k in ["policyParamBound", "expiresAt", "notBefore", "maxBlast", "maxDepth"] {
        out.push(to_u64(p.get(k), k)?);
    }
    out.push(reversibility_index(p.get("revMax"), "revMax")?);
    for k in ["rateMax", "allocParent"] {
        out.push(to_u64(p.get(k), k)?);
    }
    Ok(out)
}

/// The quantized structs, ready for [`policy_vm_struct_hash_u64`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVmQuantizedStructs {
    pub action: [u64; 4],
    pub plan: Option<[u64; 4]>,
    pub policy: Option<Vec<u64>>,
}

/// Quantize `{action, plan?, policy?}`: the action struct always, the plan and policy structs when given.
pub fn quantize_policy_vm_inputs(inp: &Value, opts: &Value) -> Result<PolicyVmQuantizedStructs, String> {
    let i = inp.as_object().ok_or("policyvm quantize: input is missing")?;
    Ok(PolicyVmQuantizedStructs {
        action: quantize_action_struct(i.get("action").unwrap_or(&Value::Null), opts)?,
        plan: i.get("plan").filter(|p| truthy(Some(*p))).map(|p| quantize_plan_struct(p, opts)).transpose()?,
        policy: i.get("policy").filter(|p| truthy(Some(*p))).map(|p| quantize_policy_struct(p, opts)).transpose()?,
    })
}

/// The circuit's action commitment recomputed from the live action: a resource server binds a Policy VM proof to this action
/// by pinning these halves (`expect_action_hash`).
pub fn policy_vm_commitment_from_action(action: &Value, opts: &Value) -> Result<DigestHalves, String> {
    Ok(policy_vm_struct_hash_u64(&quantize_action_struct(action, opts)?))
}

// ---- public signals ----------------------------------------------------------------------------------------------------------

fn decode_public(ps: &Value, l: &PolicyVmSignalLayout) -> Result<Value, String> {
    if ps.is_null() {
        return Err("public signals are null".into());
    }
    // `publicSignals[i]` as JavaScript reads it: an array element (a member of an object, a code unit of text)
    let at = |i: usize| own_property(ps, &i.to_string());
    let halves = |hi: usize, lo: usize| {
        let mut m = Map::new();
        for (k, i) in [("hi", hi), ("lo", lo)] {
            if let Some(v) = at(i) {
                m.insert(k.into(), v);
            }
        }
        Value::Object(m)
    };
    let mut out = Map::new();
    out.insert("actionHash".into(), halves(l.action_hi, l.action_lo));
    out.insert("policyHash".into(), halves(l.policy_hi, l.policy_lo));
    out.insert("planHash".into(), halves(l.plan_hi, l.plan_lo));
    if let (Some(hi), Some(lo)) = (l.risk_hi, l.risk_lo) {
        out.insert("riskHash".into(), halves(hi, lo));
    }
    let rest = [("r", l.r), ("t", l.t), ("admit", l.admit), ("allow", l.allow), ("now", l.now), ("blast", l.blast), ("delegationDepth", l.delegation_depth), ("recentCount", l.recent_count), ("allocChild", l.alloc_child)];
    for (k, i) in rest {
        if let Some(v) = at(i) {
            out.insert(k.into(), v);
        }
    }
    Ok(Value::Object(out))
}

/// The statement a `pca-policyvm-v1` proof's public signals carry: `{actionHash, policyHash, planHash, r, t, admit, allow, now,
/// blast, delegationDepth, recentCount, allocChild}` (a signal the array lacks is left out). `Err` for `null`.
pub fn decode_policy_vm_public(public_signals: &Value) -> Result<Value, String> {
    decode_public(public_signals, &POLICYVM_PUBLIC_SIGNAL)
}

/// [`decode_policy_vm_public`] for the risk-bound circuit: the same statement plus `riskHash`.
pub fn decode_policy_vm_bound_public(public_signals: &Value) -> Result<Value, String> {
    decode_public(public_signals, &POLICYVM_BOUND_PUBLIC_SIGNAL)
}

/// The context a verifier requires a proof to have been made for: fixed, or computed at each verification (so `now` can follow
/// a live clock; `Err` denies). The value is `{now?, blast?, delegationDepth?, recentCount?, allocChild?, r?, t?, requireAdmit?,
/// requireTier1?}`; a pin is an exact integer (a safe-integer number or integer text) or an inclusive `{min, max}` window.
#[derive(Clone)]
pub enum PolicyVmExpectSource {
    Fixed(Value),
    Dynamic(Arc<dyn Fn() -> Result<Value, String> + Send + Sync>),
}

/// A pin value as a signed integer `(negative, magnitude)`: a safe-integer number, integer text, a boolean or an array (its text).
fn pin_bigint(v: Option<&Value>) -> Option<(bool, BigUint)> {
    match v? {
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                return (u <= MAX_SAFE).then(|| (false, BigUint::from(u)));
            }
            if let Some(i) = n.as_i64() {
                return (i.unsigned_abs() <= MAX_SAFE).then(|| (true, BigUint::from(i.unsigned_abs())));
            }
            let f = n.as_f64()?;
            (f.fract() == 0.0 && f.abs() <= MAX_SAFE as f64).then(|| (f < 0.0, BigUint::from(f.abs() as u64)))
        }
        Value::String(s) => js_string_bigint(s),
        Value::Bool(b) => Some((false, BigUint::from(u8::from(*b)))),
        Value::Array(_) => js_string_bigint(&js_value_string(v?)),
        _ => None,
    }
}

fn signed_cmp(a: &(bool, BigUint), b: &(bool, BigUint)) -> Ordering {
    match (a.0, b.0) {
        (false, false) => a.1.cmp(&b.1),
        (true, true) => b.1.cmp(&a.1),
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
    }
}

/// `Err` for a null pin on a well-formed signal: the reference throws there.
fn signal_matches_pin(signal: Option<&Value>, pin: &Value) -> Result<bool, String> {
    // a signal that is not text is read through its text, as the reference's pattern test does
    let text = signal.map(|s| s.as_str().map_or_else(|| js_value_string(s), str::to_string));
    let Some(x) = text.filter(|s| canon_dec(s)).and_then(|s| BigUint::parse_bytes(s.as_bytes(), 10)) else { return Ok(false) };
    let x = (false, x);
    Ok(match pin {
        Value::Null => return Err("policyVmContextMatches: a pin is null".into()),
        Value::Array(_) => false,
        Value::Object(w) => match (pin_bigint(w.get("min")), pin_bigint(w.get("max"))) {
            (Some(lo), Some(hi)) => signed_cmp(&lo, &hi) != Ordering::Greater && signed_cmp(&x, &lo) != Ordering::Less && signed_cmp(&x, &hi) != Ordering::Greater,
            _ => false,
        },
        other => pin_bigint(Some(other)).is_some_and(|want| signed_cmp(&x, &want) == Ordering::Equal),
    })
}

/// Do the public signals satisfy `expect`? Also refuses, with or without pins, a context signal (`now`, `blast`,
/// `delegationDepth`, `recentCount`, `allocChild`) that is not a canonical decimal below 2^64: the circuit compares them without
/// a range check, so a field-negative `now` would pass its expiry comparison. A malformed expectation or pin is `Ok(false)`;
/// `Err` where the reference throws: `null` signals, and a `null` pin on a signal that is a canonical decimal.
pub fn policy_vm_context_matches(public_signals: &Value, expect: Option<&PolicyVmExpectSource>, layout: &PolicyVmSignalLayout) -> Result<bool, String> {
    let (ps, l) = (public_signals, layout);
    if ps.is_null() {
        return Err("policyVmContextMatches: public signals are null".into());
    }
    let at = |idx: usize| own_property(ps, &idx.to_string());
    for idx in [l.now, l.blast, l.delegation_depth, l.recent_count, l.alloc_child] {
        if !at(idx).as_ref().and_then(Value::as_str).is_some_and(|s| canon_dec(s) && dec_below(s, TWO_64)) {
            return Ok(false);
        }
    }
    let computed;
    let e = match expect {
        None => return Ok(true),
        Some(PolicyVmExpectSource::Fixed(v)) => v,
        Some(PolicyVmExpectSource::Dynamic(f)) => match f() {
            Ok(v) => {
                computed = v;
                &computed
            }
            Err(_) => return Ok(false),
        },
    };
    if !(e.is_object() || e.is_array()) {
        return Ok(false);
    }
    let pins = [("now", l.now), ("blast", l.blast), ("delegationDepth", l.delegation_depth), ("recentCount", l.recent_count), ("allocChild", l.alloc_child), ("r", l.r), ("t", l.t)];
    for (k, idx) in pins {
        if let Some(pin) = own_property(e, k) {
            if !signal_matches_pin(at(idx).as_ref(), &pin)? {
                return Ok(false);
            }
        }
    }
    let is_one = |idx: usize| at(idx).as_ref().and_then(Value::as_str) == Some("1");
    let flag = |k: &str| truthy(own_property(e, k).as_ref());
    Ok(!(flag("requireAdmit") && !is_one(l.admit)) && !(flag("requireTier1") && !is_one(l.t)))
}

// ---- Groth16 verification ----------------------------------------------------------------------------------------------------

/// The pairing check of a snarkjs Groth16 proof: `Ok(verdict)`, or `Err` when no check could be run (no engine).
pub trait Groth16Engine: Send + Sync {
    fn verify(&self, vkey: &Value, public_signals: &Value, proof: &Value) -> Result<bool, String>;
}

/// The built-in engine. With cargo feature `zk`: the `pca-zk` crate (arkworks) on the curve the key names, by default with the
/// rules of snarkjs' own verifier (the key's `protocol` and `nPublic` and IC entries past the signals are ignored, the curve name
/// is read loosely: `BN254`, `alt_bn128`, `bls12-381`); `strict` refuses such keys and takes only `bn128` / `bls12381`. Without the feature it answers `Err`: nothing is verified.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultGroth16Engine {
    pub strict: bool,
}

impl Groth16Engine for DefaultGroth16Engine {
    #[cfg(feature = "zk")]
    fn verify(&self, vkey: &Value, public_signals: &Value, proof: &Value) -> Result<bool, String> {
        let (key, proof, signals) = (vkey.to_string(), proof.to_string(), public_signals.to_string());
        if !self.strict {
            // the curve is the one the key names, read as snarkjs reads it
            return Ok(pca_zk::verify_snarkjs(key.as_bytes(), proof.as_bytes(), signals.as_bytes()).is_ok());
        }
        let curve = match vkey.get("curve").and_then(Value::as_str) {
            Some("bn128") => pca_zk::Curve::Bn254,
            Some("bls12381") => pca_zk::Curve::Bls12381,
            _ => return Ok(false),
        };
        Ok(pca_zk::verify(curve, 0, key.as_bytes(), proof.as_bytes(), signals.as_bytes()).is_ok())
    }

    #[cfg(not(feature = "zk"))]
    fn verify(&self, _vkey: &Value, _public_signals: &Value, _proof: &Value) -> Result<bool, String> {
        Err(NO_ENGINE.into())
    }
}

/// Options of [`verify_policy_vm_proof`] and of the four SNARK backends.
#[derive(Clone, Default)]
pub struct ZkProofOpts {
    /// The verifying key (snarkjs JSON). Without it `verification_key_path` is read, else the bundled key of the circuit
    /// (`pca-policyvm-v1` on either curve; the other two circuits have none).
    pub verification_key: Option<Value>,
    pub verification_key_path: Option<String>,
    /// Pins on the context signals; any mismatch refuses the proof.
    pub expect: Option<PolicyVmExpectSource>,
    /// Backends only: the proof's action / policy / plan commitment must equal these halves.
    pub expect_action_hash: Option<DigestHalves>,
    pub expect_policy_hash: Option<DigestHalves>,
    pub expect_plan_hash: Option<DigestHalves>,
    /// The risk commitment ([`policy_vm_risk_hash`] of the attested magnitudes). Only the risk-bound circuit carries one: when
    /// set, a `pca-policyvm-v1` proof or other halves are refused.
    pub expect_risk_hash: Option<DigestHalves>,
    /// Backends only: ceremony evidence `{transcript, sha256, r1csSha256?}` for `verification_key`; without it the label says
    /// `single-party`.
    pub ceremony: Option<Value>,
    /// Another pairing engine than [`DefaultGroth16Engine`].
    pub engine: Option<Arc<dyn Groth16Engine>>,
}

fn resolve_vkey(opts: &ZkProofOpts, bundled: Option<&str>) -> Result<Value, String> {
    if let Some(k) = opts.verification_key.as_ref().filter(|k| !k.is_null()) {
        return Ok(k.clone());
    }
    let text = match (&opts.verification_key_path, bundled) {
        (Some(p), _) => std::fs::read_to_string(p).map_err(|e| format!("verifying key {p}: {e}"))?,
        (None, Some(b)) => b.to_string(),
        (None, None) => return Err("no verifying key: this circuit has no bundled key, pass verification_key or verification_key_path".into()),
    };
    serde_json::from_str(&text).map_err(|e| format!("verifying key: {e}"))
}

fn engine_verify(opts: &ZkProofOpts, vkey: &Value, public_signals: &Value, proof: &Value) -> Result<bool, String> {
    match &opts.engine {
        Some(e) => e.verify(vkey, public_signals, proof),
        None => DefaultGroth16Engine::default().verify(vkey, public_signals, proof),
    }
}

fn halves_match(ps: &Value, hi: usize, lo: usize, want: Option<&DigestHalves>) -> bool {
    want.map_or(true, |w| ps.get(hi).and_then(Value::as_str) == Some(w.hi.as_str()) && ps.get(lo).and_then(Value::as_str) == Some(w.lo.as_str()))
}

/// Verify a Policy VM Groth16 proof envelope `{system, circuit, proof, publicSignals}` offline. In order: the circuit
/// (`pca-policyvm-v1`, or `pca-policyvm-v2` on BN254 only), the system (`groth16-bn254` / `groth16-bls12-381`), 15 or 17 public
/// signals, the allow bit, the risk pin, the canonical envelope gate, the context pins, then the pairing check under the
/// verifying key. `Ok(false)` (fail closed) for anything malformed, for a proof the pairing refuses and without a pairing
/// engine; `Err` where the reference throws: a `null` pin in `expect`, a verifying key that cannot be read.
/// Reads `verification_key`, `verification_key_path`, `expect`, `expect_risk_hash` and `engine` of `opts`.
pub fn verify_policy_vm_proof(env: &Value, opts: &ZkProofOpts) -> Result<bool, String> {
    let Some(p) = env.as_object() else { return Ok(false) };
    let circuit = p.get("circuit").and_then(Value::as_str);
    let bound = circuit == Some("pca-policyvm-v2");
    if circuit != Some("pca-policyvm-v1") && !bound {
        return Ok(false);
    }
    let system = p.get("system").and_then(Value::as_str);
    let bls = system == Some("groth16-bls12-381");
    if system != Some("groth16-bn254") && !(bls && !bound) {
        return Ok(false);
    }
    let (l, count) = if bound { (&POLICYVM_BOUND_PUBLIC_SIGNAL, POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT) } else { (&POLICYVM_PUBLIC_SIGNAL, POLICYVM_PUBLIC_SIGNAL_COUNT) };
    let ps = p.get("publicSignals").filter(|x| x.as_array().is_some_and(|a| a.len() == count));
    let (Some(ps), Some(proof)) = (ps, p.get("proof").filter(|x| !x.is_null())) else { return Ok(false) };
    if ps.get(l.allow).and_then(Value::as_str) != Some("1") {
        return Ok(false);
    }
    if let Some(want) = &opts.expect_risk_hash {
        let (Some(hi), Some(lo)) = (l.risk_hi, l.risk_lo) else { return Ok(false) };
        if !halves_match(ps, hi, lo, Some(want)) {
            return Ok(false);
        }
    }
    if !is_canonical_groth16_envelope(env, if bls { "bls12-381" } else { "bn254" }) {
        return Ok(false);
    }
    if !policy_vm_context_matches(ps, opts.expect.as_ref(), l)? {
        return Ok(false);
    }
    let bundled = if bound {
        None
    } else if bls {
        Some(VKEY_BLS12381)
    } else {
        Some(VKEY_BN254)
    };
    let vkey = resolve_vkey(opts, bundled)?;
    Ok(engine_verify(opts, &vkey, ps, proof).unwrap_or(false))
}

/// A SNARK verifier for [`create_zk_verifier`]: it receives the opaque proof and, as public inputs, only the three commitments
/// `{action_commit, policy_commit, plan_commit}`. `Err` is a failure to verify (the hook denies, fail closed).
pub trait SnarkBackend: Send + Sync {
    fn verify(&self, proof: &Value, public_inputs: &Value, ctx: &Value) -> Result<bool, String>;
    /// The proof system this backend declares; `None` is reported as `unknown`.
    fn assurance_label(&self) -> Option<AssuranceLabel> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Circuit {
    Compliance,
    PolicyVm,
    PolicyVmBls,
    PolicyVmBound,
}

/// One of the library's Groth16 backends (see the four `create_*_snark_backend` functions).
#[derive(Clone)]
pub struct ZkSnarkBackend {
    circuit: Circuit,
    opts: ZkProofOpts,
    label: AssuranceLabel,
}

fn backend(circuit: Circuit, opts: ZkProofOpts) -> ZkSnarkBackend {
    let id = match circuit {
        Circuit::Compliance => "pca-compliance-v1",
        Circuit::PolicyVmBound => "pca-policyvm-v2",
        _ => "pca-policyvm-v1",
    };
    // `multi-party` only for an explicit key backed by pinned evidence for this very circuit
    let evidence = opts.ceremony.as_ref().and_then(Value::as_object).map(|c| {
        let mut c = c.clone();
        c.insert("circuit".into(), json!(id));
        Value::Object(c)
    });
    let ceremony = ceremony_of(opts.verification_key.as_ref(), evidence.as_ref());
    let pinned = opts.expect_action_hash.is_some() && opts.expect_policy_hash.is_some() && opts.expect_plan_hash.is_some() && (circuit != Circuit::PolicyVmBound || opts.expect_risk_hash.is_some());
    let label = if circuit == Circuit::Compliance {
        AssuranceLabel::new("groth16")
    } else if pinned {
        AssuranceLabel::new("policyvm_snark")
    } else {
        AssuranceLabel::new("unknown").with_vendor("policyvm-unbound")
    };
    ZkSnarkBackend { circuit, opts, label: label.with_ceremony(ceremony) }
}

/// The backend of the first compliance circuit (`pca-compliance-v1`, BN254; label `groth16`): a well-formed envelope with 7
/// public signals, allow = 1, the three binding tags equal to [`commitment_field`] of the resource server's own commitments,
/// the canonical envelope gate, then the pairing check. No key is bundled: pass `verification_key` or `verification_key_path`.
pub fn create_groth16_snark_backend(opts: ZkProofOpts) -> ZkSnarkBackend {
    backend(Circuit::Compliance, opts)
}

/// The backend of the full Policy VM circuit on BN254 (bundled key by default). It binds the proof through the `expect_*_hash`
/// halves, not through the canonical-JSON commitments: with all three pinned its label is `policyvm_snark`, otherwise `unknown`
/// (a valid proof may then be for another compliant action).
pub fn create_policy_vm_snark_backend(opts: ZkProofOpts) -> ZkSnarkBackend {
    backend(Circuit::PolicyVm, opts)
}

/// [`create_policy_vm_snark_backend`] with the bundled BLS12-381 key as the default.
pub fn create_policy_vm_snark_backend_bls12381(opts: ZkProofOpts) -> ZkSnarkBackend {
    backend(Circuit::PolicyVmBls, opts)
}

/// The backend of the risk-bound circuit (`pca-policyvm-v2`, BN254): the three struct commitments plus the risk commitment;
/// `policyvm_snark` only with all four pinned. No key is bundled.
pub fn create_policy_vm_bound_snark_backend(opts: ZkProofOpts) -> ZkSnarkBackend {
    backend(Circuit::PolicyVmBound, opts)
}

impl ZkSnarkBackend {
    /// The assurance label: the proof system and whether the verifying key comes from a multi-party ceremony.
    pub fn label(&self) -> &AssuranceLabel {
        &self.label
    }

    fn verify_compliance(&self, proof: &Value, public_inputs: &Value) -> Result<bool, String> {
        let Some(env) = proof.as_object() else { return Ok(false) };
        if env.get("system").and_then(Value::as_str) != Some("groth16-bn254") || env.get("circuit").and_then(Value::as_str) != Some("pca-compliance-v1") {
            return Ok(false);
        }
        let ps = env.get("publicSignals").filter(|x| x.as_array().is_some_and(|a| a.len() == 7));
        let (Some(ps), Some(g16)) = (ps, env.get("proof").filter(|x| !x.is_null())) else { return Ok(false) };
        if ps.get(6).and_then(Value::as_str) != Some("1") {
            return Ok(false);
        }
        // signals 3..5 are the binding tags of the policy, plan and action commitments
        for (idx, k) in [(3, "policy_commit"), (4, "plan_commit"), (5, "action_commit")] {
            let commit = public_inputs.get(k).and_then(Value::as_str).ok_or_else(|| format!("{k}: string expected"))?;
            if ps.get(idx).and_then(Value::as_str) != Some(commitment_field(commit)?.as_str()) {
                return Ok(false);
            }
        }
        if !is_canonical_groth16_envelope(proof, "bn254") {
            return Ok(false);
        }
        engine_verify(&self.opts, &resolve_vkey(&self.opts, None)?, ps, g16)
    }

    fn verify_policy_vm(&self, proof: &Value) -> Result<bool, String> {
        let (o, bound) = (&self.opts, self.circuit == Circuit::PolicyVmBound);
        let l = if bound { &POLICYVM_BOUND_PUBLIC_SIGNAL } else { &POLICYVM_PUBLIC_SIGNAL };
        if proof.get("circuit").and_then(Value::as_str) != Some(if bound { "pca-policyvm-v2" } else { "pca-policyvm-v1" }) {
            return Ok(false);
        }
        match proof.get("publicSignals").filter(|x| x.is_array()) {
            Some(ps) => {
                let risk_ok = match (l.risk_hi, l.risk_lo) {
                    (Some(hi), Some(lo)) => halves_match(ps, hi, lo, o.expect_risk_hash.as_ref()),
                    _ => true,
                };
                let structs_ok = halves_match(ps, l.action_hi, l.action_lo, o.expect_action_hash.as_ref()) && halves_match(ps, l.policy_hi, l.policy_lo, o.expect_policy_hash.as_ref()) && halves_match(ps, l.plan_hi, l.plan_lo, o.expect_plan_hash.as_ref());
                if !structs_ok || !risk_ok {
                    return Ok(false);
                }
            }
            None if bound => return Ok(false),
            None => {}
        }
        let bundled = match self.circuit {
            Circuit::PolicyVm => Some(VKEY_BN254),
            Circuit::PolicyVmBls => Some(VKEY_BLS12381),
            _ => None,
        };
        let inner = ZkProofOpts {
            verification_key: Some(resolve_vkey(o, bundled)?),
            expect: o.expect.clone(),
            expect_risk_hash: o.expect_risk_hash.clone().filter(|_| bound),
            engine: o.engine.clone(),
            ..Default::default()
        };
        verify_policy_vm_proof(proof, &inner)
    }
}

impl SnarkBackend for ZkSnarkBackend {
    fn verify(&self, proof: &Value, public_inputs: &Value, _ctx: &Value) -> Result<bool, String> {
        if self.circuit == Circuit::Compliance {
            self.verify_compliance(proof, public_inputs)
        } else {
            self.verify_policy_vm(proof)
        }
    }

    fn assurance_label(&self) -> Option<AssuranceLabel> {
        Some(self.label.clone())
    }
}

impl AssuranceLabelled for ZkSnarkBackend {
    fn assurance_label(&self) -> Option<AssuranceLabel> {
        Some(self.label.clone())
    }
}

// ---- attested-VM statements and the verifier hook ------------------------------------------------------------------------------

fn statement_message(body: &Value) -> Result<Vec<u8>, String> {
    Ok([DOMAIN, canonicalize_strict(body)?.as_bytes()].concat())
}

/// The attested-VM prover: it runs the Policy VM and, only when the guardian share is released, signs a compliance statement
/// that carries commitments and never the policy or the plan.
pub struct AttestedComplianceProver {
    key: SigningKey,
    public_key: String,
}

/// The prover of the VM whose Ed25519 secret key (32-byte seed) is `attestor_secret`.
pub fn create_attested_compliance_prover(attestor_secret: &[u8; 32]) -> AttestedComplianceProver {
    let key = SigningKey::from_bytes(attestor_secret);
    let public_key = crate::b64_encode(&key.verifying_key().to_bytes());
    AttestedComplianceProver { key, public_key }
}

impl AttestedComplianceProver {
    /// The base64url public key a resource server lists in `trusted_prover_keys`.
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Run the Policy VM on `decide_input` and sign the statement `{v: 1, mode: "attested-vm", action_commit, policy_commit,
    /// plan_commit, released: true, r, issued_at, expires_at, prover, sig}` for `pcactn` (times in epoch milliseconds). `Err`
    /// when the action is not compliant: a false statement cannot be proven.
    pub fn prove(&self, pcactn: &Value, decide_input: &Value, issued_at: i64, expires_at: i64) -> Result<Value, String> {
        let decision = crate::policy_vm::decide(decide_input);
        if decision["releaseGuardianShare"] != true {
            let reasons: Vec<&str> = decision["reasons"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            return Err(format!("createAttestedComplianceProver: action is not compliant, nothing to prove ({})", reasons.join("; ")));
        }
        let plan_commit = pcactn.get("plan").and_then(|p| p.get("root")).and_then(Value::as_str).unwrap_or("");
        let mut st = Map::new();
        st.insert("v".into(), json!(1));
        st.insert("mode".into(), json!("attested-vm"));
        st.insert("action_commit".into(), json!(action_commitment(pcactn)?));
        st.insert("policy_commit".into(), json!(policy_commitment(decide_input.get("grant").unwrap_or(&Value::Null))?));
        st.insert("plan_commit".into(), json!(plan_commit));
        st.insert("released".into(), json!(true));
        st.insert("r".into(), decision["r"].clone());
        st.insert("issued_at".into(), json!(issued_at));
        st.insert("expires_at".into(), json!(expires_at));
        st.insert("prover".into(), json!(self.public_key));
        let mut st = Value::Object(st);
        let sig = self.key.sign(&statement_message(&st)?).to_bytes();
        st["sig"] = json!(crate::b64_encode(&sig));
        Ok(st)
    }
}

/// Binds an attested-VM prover key to hardware evidence of the VM's measurement.
#[derive(Clone)]
pub struct ProverAttestationOpts {
    /// The label of the hardware verifier behind `verify_hardware`: it must be `hardware` or `multi_root`.
    pub hardware_label: AssuranceLabel,
    /// Verify the hardware evidence of the prover with this public key: `(prover key, verification context, now in epoch ms,
    /// expected binding)`. The host looks the prover's quote up and runs its vendor verifier on it.
    pub verify_hardware: Arc<dyn Fn(&str, &Value, i64, &Binding) -> AttResult + Send + Sync>,
    /// The binding the quote must carry for this prover key (see [`prover_key_binding`]); `Err` denies.
    pub expected_binding: Arc<dyn Fn(&str) -> Result<Binding, String> + Send + Sync>,
    /// Accepted runtime measurements (the VM image). Required and non-empty.
    pub measurements: Vec<String>,
}

/// Options of [`create_zk_verifier`].
#[derive(Clone, Default)]
pub struct ZkVerifierOpts {
    /// Base64url public keys of the prover VMs trusted in attested-VM mode.
    pub trusted_prover_keys: Vec<String>,
    /// The expected policy commitments, as bare hashes: the statement must commit to one of them, and the verifier never
    /// reads a policy. `None`: the commitment is derived from the grant in hand.
    pub policy_commitments: Option<Vec<String>>,
    /// Delegate the proof to a SNARK backend (the proof is then opaque to the hook).
    pub snark_backend: Option<Arc<dyn SnarkBackend>>,
    /// Prover keys that are no longer trusted, even when still listed as trusted.
    pub revoked_prover_keys: Vec<String>,
    /// Attested-VM mode only: require hardware evidence for the prover key.
    pub prover_attestation: Option<ProverAttestationOpts>,
    /// The clock, epoch milliseconds (default: the system clock).
    pub now: Option<Arc<dyn Fn() -> i64 + Send + Sync>>,
    /// Allowed clock skew in milliseconds; negative or not finite counts as 0.
    pub clock_skew_ms: f64,
}

/// The zero-knowledge compliance verifier hook built by [`create_zk_verifier`].
#[derive(Clone)]
pub struct ZkVerifier {
    opts: ZkVerifierOpts,
    trusted: HashSet<String>,
    revoked: HashSet<String>,
    policy: Option<HashSet<String>>,
    skew: f64,
    label: AssuranceLabel,
}

/// Build the verifier of the proof a PCActn carries in `zk_compliance`. With a SNARK backend it binds the three commitments to
/// this action, plan and policy and delegates. Otherwise the proof is an attested-VM statement: a trusted, unrevoked prover
/// key, a valid Ed25519 signature over the statement, a fresh validity window, and commitments equal to this action, this
/// plan root and an expected policy; then the hardware evidence of the prover key when `prover_attestation` is set. `Err` for
/// a prover attestation without a `hardware` / `multi_root` label or without measurements.
pub fn create_zk_verifier(mut opts: ZkVerifierOpts) -> Result<ZkVerifier, String> {
    if opts.snark_backend.is_some() {
        opts.prover_attestation = None;
    }
    if let Some(pa) = &opts.prover_attestation {
        if !matches!(pa.hardware_label.level.as_str(), "hardware" | "multi_root") {
            return Err("createZkVerifier: proverAttestation.hardwareVerifier must carry a hardware or multi_root assurance label".into());
        }
        if pa.measurements.is_empty() || pa.measurements.iter().any(String::is_empty) {
            return Err("createZkVerifier: proverAttestation.measurements must be a non-empty allowlist".into());
        }
    }
    let label = match (&opts.snark_backend, &opts.prover_attestation) {
        (Some(b), _) => b.assurance_label().unwrap_or_else(|| AssuranceLabel::new("unknown")),
        (None, Some(pa)) => AssuranceLabel::new("attested_vm_hw").with_vendor(format!("hardware-bound:{}", pa.hardware_label.vendor.as_deref().unwrap_or(&pa.hardware_label.level))),
        (None, None) => AssuranceLabel::new("attested_vm"),
    };
    Ok(ZkVerifier {
        trusted: opts.trusted_prover_keys.iter().cloned().collect(),
        revoked: opts.revoked_prover_keys.iter().cloned().collect(),
        policy: opts.policy_commitments.as_ref().map(|p| p.iter().cloned().collect()),
        skew: if opts.clock_skew_ms.is_finite() { opts.clock_skew_ms.max(0.0) } else { 0.0 },
        label,
        opts,
    })
}

impl ZkVerifier {
    /// The assurance label: the backend's in SNARK mode, `attested_vm` or `attested_vm_hw` otherwise.
    pub fn label(&self) -> &AssuranceLabel {
        &self.label
    }

    /// Verify the proof of `ctx.pcactn` under `ctx.grant` (`ctx` is `{pcactn, grant}`). Always enforced; every failure, an
    /// internal error included, denies.
    pub fn verify(&self, ctx: &Value) -> HookResult {
        let reason = match self.check(ctx) {
            Ok(None) => return HookResult::Enforced { ok: true, reason: None, t: None },
            Ok(Some(reason)) => reason,
            Err(e) => format!("zk verification error (fail closed): {e}"),
        };
        HookResult::Enforced { ok: false, reason: Some(reason), t: None }
    }

    /// This verifier as the `zk` hook of `authorize` (`(pcactn, grant, now)`; the verifier uses its own clock).
    pub fn into_hook(self) -> impl Fn(&Value, &Value, i64) -> HookResult + Send + Sync + 'static {
        move |pcactn: &Value, grant: &Value, _now: i64| self.verify(&json!({ "pcactn": pcactn, "grant": grant }))
    }

    /// `Ok(None)`: verified. `Ok(Some(reason))`: denied. `Err`: could not verify.
    fn check(&self, ctx: &Value) -> Result<Option<String>, String> {
        let deny = |r: &str| Ok(Some(r.to_string()));
        let null = Value::Null;
        let pcactn = ctx.get("pcactn").unwrap_or(&null);
        let Some(proof) = pcactn.get("zk_compliance").filter(|p| !p.is_null()) else { return deny("no zk_compliance proof present") };
        let action_commit = action_commitment(pcactn)?;
        let plan_commit = pcactn.get("plan").and_then(|p| p.get("root")).and_then(Value::as_str).unwrap_or("");
        let grant = ctx.get("grant").unwrap_or(&null);
        let derived = match &self.policy {
            Some(_) => None,
            None => Some(policy_commitment(grant)?),
        };

        if let Some(backend) = &self.opts.snark_backend {
            // the proof is opaque: bind the public inputs to this action and plan, then delegate
            let policy_commit = match (&self.policy, derived) {
                (Some(p), _) if p.len() == 1 => p.iter().next().cloned().unwrap_or_default(),
                (_, Some(d)) => d,
                _ => policy_commitment(grant)?,
            };
            let inputs = json!({ "action_commit": action_commit, "policy_commit": policy_commit, "plan_commit": plan_commit });
            return if backend.verify(proof, &inputs, ctx)? { Ok(None) } else { deny("snark backend rejected the proof") };
        }

        let st = proof;
        let text = |k: &str| st.get(k).and_then(Value::as_str);
        if !st.get("v").is_some_and(|v| v.is_number() && v.as_f64() == Some(1.0)) || text("mode") != Some("attested-vm") {
            return deny("unrecognized compliance statement");
        }
        if st.get("released") != Some(&Value::Bool(true)) {
            return deny("statement does not assert release");
        }
        let Some(prover) = text("prover").filter(|p| self.trusted.contains(*p)) else { return deny("prover key is not trusted") };
        if self.revoked.contains(prover) {
            return deny("prover key is revoked");
        }
        let Some(sig) = text("sig") else { return deny("compliance statement signature does not verify") };
        let mut body = st.as_object().cloned().unwrap_or_default();
        body.remove("sig");
        if !crate::verify_b64u(prover, &statement_message(&Value::Object(body))?, sig) {
            return deny("compliance statement signature does not verify");
        }

        let time = |k: &str| st.get(k).filter(|v| v.is_number()).and_then(Value::as_f64);
        let (Some(issued), Some(expires)) = (time("issued_at"), time("expires_at")) else { return deny("malformed statement validity window") };
        if expires < issued {
            return deny("malformed statement validity window");
        }
        let now_ms = match &self.opts.now {
            Some(clock) => clock(),
            None => std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64),
        };
        if !(self.skew.is_finite() && now_ms as f64 + self.skew >= issued) {
            return deny("compliance statement not yet valid");
        }
        if !(self.skew.is_finite() && now_ms as f64 - self.skew <= expires) {
            return deny("compliance statement expired");
        }

        // the only policy and plan knowledge the verifier needs is these hashes
        if text("action_commit") != Some(action_commit.as_str()) {
            return deny("statement does not bind to this action");
        }
        if text("plan_commit") != Some(plan_commit) {
            return deny("statement does not bind to this plan commitment");
        }
        let expected = |c: &str| match (&self.policy, &derived) {
            (Some(p), _) => p.contains(c),
            (None, d) => d.as_deref() == Some(c),
        };
        if !text("policy_commit").is_some_and(expected) {
            return deny("statement policy commitment is not an expected policy");
        }

        // hardware binding of the prover key, last (the expensive check): anything but a bound, measured, allowlisted identity denies
        if let Some(pa) = &self.opts.prover_attestation {
            let hw = (pa.verify_hardware)(prover, ctx, now_ms, &(pa.expected_binding)(prover)?);
            if !hw.ok {
                return Ok(Some(format!("prover hardware evidence invalid: {}", hw.reason.as_deref().unwrap_or("no reason given"))));
            }
            if hw.bound != Some(true) {
                return deny("prover hardware evidence does not bind the prover key");
            }
            let Some(m) = hw.measured.as_ref().and_then(|m| m.get("runtime_measurement")).and_then(Value::as_str) else { return deny("prover hardware evidence carries no measured identity") };
            if !pa.measurements.iter().any(|a| a == m) {
                return deny("prover VM measurement is not allowlisted");
            }
        }
        Ok(None)
    }
}

impl AssuranceLabelled for ZkVerifier {
    fn assurance_label(&self) -> Option<AssuranceLabel> {
        Some(self.label.clone())
    }
}

// ---- circuit versions --------------------------------------------------------------------------------------------------------

/// The version record of one circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitVersion {
    pub circuit: String,
    /// SHA-256 over the circuit's whole source set plus the pinned compiler.
    pub source_sha256: String,
    pub circom: String,
    pub circomlib: String,
}

/// The bundled version of a circuit id (`pca-compliance-v1`, `pca-policyvm-v1`, `pca-policyvm-v2`); `Err` for an unknown id.
pub fn circuit_version(id: &str) -> Result<CircuitVersion, String> {
    let v: Value = serde_json::from_str(CIRCUIT_VERSIONS).map_err(|e| format!("circuitVersion: {e}"))?;
    let text = |x: &Value| x.as_str().map(str::to_string);
    let source = v["circuits"].as_object().and_then(|m| m.get(id)).and_then(|c| text(&c["source_sha256"]));
    match (source, text(&v["circom"]), text(&v["circomlib"])) {
        (Some(source_sha256), Some(circom), Some(circomlib)) => Ok(CircuitVersion { circuit: id.to_string(), source_sha256, circom, circomlib }),
        _ => Err(format!("circuitVersion: unknown circuit {}", json!(id))),
    }
}

// ---- provers -----------------------------------------------------------------------------------------------------------------

/// Where a prover finds the circuit's witness calculator and proving key. Both are required: this crate ships no circuit build.
#[derive(Debug, Clone, Default)]
pub struct ZkProverOpts {
    pub wasm_path: Option<String>,
    pub zkey_path: Option<String>,
}

/// A witness value as the decimal text the circuit input takes.
fn witness_text(k: &str, v: Option<&Value>) -> Result<Value, String> {
    match v {
        Some(Value::String(s)) => Ok(json!(s)),
        Some(Value::Number(n)) if n.is_u64() || n.is_i64() => Ok(json!(n.to_string())),
        Some(Value::Number(n)) => Ok(json!(crate::intent_v2::js_number_string(n.as_f64().unwrap_or(f64::NAN)))),
        _ => Err(format!("witness member {k} must be a number or decimal text")),
    }
}

fn full_prove(input: Map<String, Value>, opts: &ZkProverOpts, circuit: &str) -> Result<Value, String> {
    let (Some(wasm), Some(zkey)) = (&opts.wasm_path, &opts.zkey_path) else { return Err("prover: wasm_path and zkey_path are required".into()) };
    #[cfg(feature = "zk")]
    {
        let read = |p: &String| std::fs::read(p).map_err(|e| format!("prover: {p}: {e}"));
        let out = pca_zk::prove(pca_zk::Curve::Bn254, &read(wasm)?, &read(zkey)?, Value::Object(input).to_string().as_bytes(), None).map_err(|e| format!("prover: {:?}: {}", e.kind, e.msg))?;
        let out: Value = serde_json::from_str(&out).map_err(|e| format!("prover: {e}"))?;
        Ok(json!({ "system": "groth16-bn254", "circuit": circuit, "proof": out["proof"], "publicSignals": out["publicSignals"] }))
    }
    #[cfg(not(feature = "zk"))]
    {
        let _ = (wasm, zkey, input, circuit);
        Err(NO_ENGINE.into())
    }
}

fn witness_input(witness: &Value) -> Result<Map<String, Value>, String> {
    let mut input = Map::new();
    for (k, v) in witness.as_object().ok_or("prover: the witness must be an object")? {
        input.insert(k.clone(), witness_text(k, Some(v))?);
    }
    Ok(input)
}

/// Generate a Groth16 proof of the first compliance circuit from `{action_commit, policy_commit, plan_commit, verb, resource,
/// planVerb, policySalt, planSalt, actionSalt, risk, budget}` (the last eight private). `Err` for a non-compliant witness (a
/// false statement has no proof), without the proving artifacts and without cargo feature `zk`.
pub fn prove_groth16_compliance(inp: &Value, opts: &ZkProverOpts) -> Result<Value, String> {
    let mut input = Map::new();
    for k in ["verb", "resource", "planVerb", "policySalt", "planSalt", "actionSalt", "risk", "budget"] {
        input.insert(k.into(), witness_text(k, inp.get(k))?);
    }
    for (tag, k) in [("shaPolicy", "policy_commit"), ("shaPlan", "plan_commit"), ("shaAction", "action_commit")] {
        let commit = inp.get(k).and_then(Value::as_str).ok_or_else(|| format!("{k}: string expected"))?;
        input.insert(tag.into(), json!(commitment_field(commit)?));
    }
    input.insert("allow".into(), json!("1"));
    full_prove(input, opts, "pca-compliance-v1")
}

/// Generate a `pca-policyvm-v1` proof (BN254) from the complete fixed-point witness (every circuit input). `Err` as
/// [`prove_groth16_compliance`].
pub fn prove_policy_vm_compliance(witness: &Value, opts: &ZkProverOpts) -> Result<Value, String> {
    full_prove(witness_input(witness)?, opts, "pca-policyvm-v1")
}

/// Generate a risk-bound `pca-policyvm-v2` proof; the same witness inputs as [`prove_policy_vm_compliance`].
pub fn prove_policy_vm_bound_compliance(witness: &Value, opts: &ZkProverOpts) -> Result<Value, String> {
    full_prove(witness_input(witness)?, opts, "pca-policyvm-v2")
}
