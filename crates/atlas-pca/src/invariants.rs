//! Deterministic surface of the invariants package: key pairs from seeds, the signed legal-chain builder, the risk `worsen`
//! helper and the registry constants. The property generators and the runner are in `crate::invariants_check` (own SplitMix64 stream,
//! not the reference library's, so a seed explores different cases than the reference does).
use crate::agent::{delegate, mint_root, KeyPair, Suite};
use serde_json::{json, Map, Value};

pub const DEFAULT_SEED: u64 = 20260108;
pub const DEFAULT_NUM_RUNS: u64 = 1000;
/// Allocation base of the first `budget_frac` caveat.
const BUDGET_ALLOC_BASE: f64 = 1_000_000.0;

pub const INVARIANT_NAMES: [&str; 12] = [
    "attenuation-monotonicity",
    "risk-wellformed-and-monotone",
    "admission-soundness",
    "cumulative-budget-bound",
    "fail-closed:undecidable-leaf",
    "fail-closed:undecidable-groups",
    "fail-closed:member-of-cycle-safe",
    "fail-closed:unknown-caveat-type",
    "fail-closed:forged-chain-rejected",
    "fail-closed:garbage-chain-rejected",
    "forbid-monotone",
    "determinism",
];

/// A generated Ed25519 identity: any 32 bytes are a valid secret seed.
pub struct GenKeyPair {
    pub secret_key: [u8; 32],
    pub public_key: Vec<u8>,
    /// base64url public key (the `issuer` / `holder` string form).
    pub public: String,
    pub signer: KeyPair,
}

pub fn key_pair_from_seed(seed: &[u8]) -> Result<GenKeyPair, String> {
    let s: [u8; 32] = seed.try_into().map_err(|_| format!("private key of length 32 expected, got {}", seed.len()))?;
    let signer = KeyPair::from_seed(&s);
    let public_key = crate::decode_b64u_strict(&signer.public, Some(32)).ok_or("bad public key")?;
    Ok(GenKeyPair { secret_key: s, public_key, public: signer.public.clone(), signer })
}

fn seed_of(v: &Value, what: &str) -> Result<GenKeyPair, String> {
    let s = v.as_str().ok_or_else(|| format!("{what}: a base64url seed string is required"))?;
    key_pair_from_seed(&crate::decode_b64u_strict(s, None).ok_or_else(|| format!("{what}: not canonical base64url"))?)
}

fn spec_to_caveat(spec: &Value, running: &mut Option<f64>) -> Result<Value, String> {
    let f = |k: &str| spec.get(k).cloned().ok_or_else(|| format!("caveat spec missing {k}"));
    match spec.get("k").and_then(Value::as_str).ok_or("caveat spec without k")? {
        k @ ("expires" | "not_before") => Ok(json!({ "type": k, "at": f("at")? })),
        "rate" => Ok(json!({ "type": "rate", "max": f("max")?, "per_secs": f("per_secs")? })),
        "max_blast_radius" => Ok(json!({ "type": "max_blast_radius", "max": f("max")? })),
        "reversibility_max" => Ok(json!({ "type": "reversibility_max", "class": f("cls")? })),
        "delegation_depth" => Ok(json!({ "type": "delegation_depth", "max": f("max")? })),
        "budget_frac" => {
            let frac = f("frac")?.as_f64().ok_or("frac must be a number")?;
            if !(0.0..=1.0).contains(&frac) {
                return Err("frac must be in [0,1]".into());
            }
            // an integer in [0, previous allocation]: monotone non-increasing and canonical-wire-safe
            let limit = (running.unwrap_or(BUDGET_ALLOC_BASE) * frac).floor();
            *running = Some(limit);
            Ok(json!({ "type": "budget_alloc", "limit": limit as i64 }))
        }
        k => Err(format!("unknown caveat spec {k:?}")),
    }
}

fn specs(v: &Value, running: &mut Option<f64>) -> Result<Value, String> {
    let a = v.as_array().ok_or("specs must be an array")?;
    Ok(Value::Array(a.iter().map(|s| spec_to_caveat(s, running)).collect::<Result<Vec<_>, _>>()?))
}

/// A signed, legally-attenuating chain from a model {principalSeed, holder0Seed (base64url strings), rootSpecs,
/// hops:[{holderSeed, addedSpecs}], predicates}. Returns {caps, predicates, rootIssuer, holders}.
pub fn build_chain(m: &Value) -> Result<Value, String> {
    let mut running: Option<f64> = None;
    let principal = seed_of(&m["principalSeed"], "principalSeed")?;
    let holder0 = seed_of(&m["holder0Seed"], "holder0Seed")?;
    let root = mint_root(&principal.signer, &holder0.public, &specs(&m["rootSpecs"], &mut running)?, None, &Suite::default())?;
    let mut caps = vec![root.clone()];
    let mut holders = vec![json!(holder0.public)];
    let mut prev = root;
    let mut signer = holder0.signer;
    for hop in m["hops"].as_array().ok_or("hops must be an array")? {
        let to = seed_of(&hop["holderSeed"], "holderSeed")?;
        let cap = delegate(&prev, &signer, Some(&to.public), &specs(&hop["addedSpecs"], &mut running)?, None, &Suite::default())?;
        caps.push(cap.clone());
        holders.push(json!(to.public));
        prev = cap;
        signer = to.signer;
    }
    let mut o = Map::new();
    o.insert("caps".into(), Value::Array(caps));
    o.insert("predicates".into(), m["predicates"].clone());
    o.insert("rootIssuer".into(), json!(principal.public));
    o.insert("holders".into(), Value::Array(holders));
    Ok(Value::Object(o))
}

fn clamp01(x: f64) -> f64 {
    if x < 0.0 {
        0.0
    } else if x > 1.0 {
        1.0
    } else {
        x
    }
}

/// A risk input at least as bad as `base` on every risk-increasing axis and no better on every protective axis.
pub fn worsen(base: &Value, d: &Value) -> Result<Value, String> {
    let n = |v: &Value, k: &str| v.get(k).and_then(Value::as_f64).ok_or_else(|| format!("{k} must be a number"));
    let mut o = Map::new();
    o.insert("semanticDistance".into(), json!(clamp01(n(base, "semanticDistance")? + n(d, "dSem")?)));
    o.insert("blastRadius".into(), json!(clamp01(n(base, "blastRadius")? + n(d, "dBlast")?)));
    o.insert("taint".into(), json!(clamp01(n(base, "taint")? + n(d, "dTaint")?)));
    o.insert("age".into(), json!(clamp01(n(base, "age")? + n(d, "dAge")?)));
    o.insert("reversibility".into(), json!(clamp01(n(base, "reversibility")? - n(d, "dRev")?)));
    o.insert("confidence".into(), json!(clamp01(n(base, "confidence")? - n(d, "dConf")?)));
    Ok(Value::Object(o))
}
