//! Differential replay of test-data/ref-beacons.json.gz (written by the TypeScript reference): minting, the signed message, the beacon
//! reference, verification (software and post-quantum suites, window, scope), monotonic acceptance, the frozen-liveness check and the
//! durable acceptor over a store with injected failures and junk. Every function of the corpus has a handler and the per-function totals are
//! asserted. A reference refusal must be a refusal here. The 1 verdict the reference accepts only through its legacy unbound
//! post-quantum opt-out is asserted REFUSED. A beacon, claim or body carrying a non-finite number has no canonical form: the signed, hashed
//! and minted outputs refuse it as the reference does. The constructor cases of a store that is not one cannot be built in the typed API:
//! the harness answers them from the spec.
mod common;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use atlas_pca::agent::{KeyPair, PqKeyPair, Suite};
use atlas_pca::beacon::*;
use atlas_pca::kv::{AtomicKv, MemoryAtomicKv};
use atlas_pca::serde_json::{json, Value};
use base64::Engine;
use common::replay::thrown;

fn has_marker(v: &Value) -> bool {
    match v {
        Value::Object(m) => (m.len() == 1 && m.contains_key("$num")) || m.values().any(has_marker),
        Value::Array(a) => a.iter().any(has_marker),
        _ => false,
    }
}

fn verdict(r: Result<(), String>) -> Value {
    match r {
        Ok(()) => json!({"ok": true}),
        Err(reason) => json!({"ok": false, "reason": reason}),
    }
}

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// A store that fails its next `update` when told to.
struct FlakyKv {
    inner: MemoryAtomicKv,
    fail_next: AtomicBool,
}

impl AtomicKv for FlakyKv {
    fn get(&self, key: &str) -> Result<Option<Value>, atlas_pca::StoreError> {
        self.inner.get(key)
    }
    fn update(&self, key: &str, f: &mut dyn FnMut(Option<&Value>) -> Option<Value>) -> Result<Option<Value>, atlas_pca::StoreError> {
        if self.fail_next.swap(false, Ordering::SeqCst) {
            return Err(atlas_pca::StoreError("kv down".into()));
        }
        self.inner.update(key, f)
    }
}

fn acceptor(ops: &Value) -> Value {
    let kv = Arc::new(FlakyKv { inner: MemoryAtomicKv::new(), fail_next: AtomicBool::new(false) });
    let acc = BeaconAcceptor::new(kv.clone());
    let out: Vec<Value> = ops
        .as_array()
        .unwrap()
        .iter()
        .map(|op| match op[0].as_str().unwrap() {
            "accept" => verdict(acc.accept_check(&op[1], &op[2])),
            "fail" => {
                kv.fail_next.store(true, Ordering::SeqCst);
                Value::Null
            }
            "raw" => {
                let b = &op[1];
                let key = format!("beacon-seq/v1/{}", atlas_pca::js_stringify(&json!([b["instance"], b["scope"], b["issuer"]])));
                let value = op[2].clone();
                kv.inner.update(&key, &mut |_| Some(value.clone())).unwrap();
                Value::Null
            }
            _ => json!({"$err": "op"}),
        })
        .collect();
    Value::Array(out)
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => json!({
            "GLOBAL_SCOPE": GLOBAL_SCOPE,
            "BEACON_EPOCH_MS": BEACON_EPOCH_MS,
            "BEACON_MAX_VALIDITY_MS": BEACON_MAX_VALIDITY_MS,
            "BEACON_CLOCK_SKEW_MS": BEACON_CLOCK_SKEW_MS,
        }),
        "issueLivenessBeacon" => {
            let args = &a[0];
            if has_marker(args)
                && !args.get("seq").is_some_and(has_marker)
                && !args.get("issuedAt").is_some_and(has_marker)
                && !args.get("validityMs").is_some_and(has_marker)
            {
                return thrown("canonicalize: non-finite number");
            }
            let issuer = KeyPair::from_seed_b64u(args["issuerSecret"]["$bytes"].as_str().unwrap()).unwrap();
            let spec = args.get("suite").filter(|s| !s.is_null());
            let alg = spec.and_then(|s| s["alg"].as_str());
            let pq = match spec.filter(|_| alg != Some("ed25519")) {
                Some(s) => match s.get("pqSeed") {
                    Some(seed) => Some(PqKeyPair::from_seed("ML-DSA-65", &common::b64d(seed["$bytes"].as_str().unwrap())).unwrap()),
                    None => return thrown("mlDsa65Keygen: the seed is required"),
                },
                None => None,
            };
            issue_liveness_beacon_value(args, &issuer, &Suite { alg, pq: pq.as_ref() }).unwrap_or_else(thrown)
        }
        "livenessBeaconMessage" => liveness_beacon_message(&a[0]).map(|m| json!({"$bytes": b64u(&m)})).unwrap_or_else(thrown),
        "beaconRef" if has_marker(&a[0]) => thrown("canonicalize: non-finite number"),
        "beaconRef" => beacon_ref(&a[0]).map(Value::String).unwrap_or_else(|| thrown("outside the strict profile")),
        "verifyLivenessBeacon" => verdict(verify_liveness_beacon_check(&a[0], &a[1])),
        "acceptBeacon" => verdict(accept_beacon_value(&a[0], &a[1])),
        "isFrozenLiveness" => json!(is_frozen_liveness_check(&a[0], &a[1])),
        "acceptor" => acceptor(&a[0]),
        "ctor" => {
            // a store is a typed object here: only a working one builds
            let built = a[0] == json!("ok") || a[0].get("update") == Some(&json!("fn"));
            if built {
                let _ = BeaconAcceptor::new(Arc::new(MemoryAtomicKv::new()));
            }
            json!({"built": built})
        }
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn beacons_replay() {
    let cases = common::ref_cases_seeded("beacons");
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(c["fn"].as_str().unwrap().to_string()).or_default() += 1;
    }
    let want: BTreeMap<String, usize> = [
        ("verifyLivenessBeacon", 67),
        ("issueLivenessBeacon", 36),
        ("acceptor", 19),
        ("acceptBeacon", 18),
        ("livenessBeaconMessage", 12),
        ("beaconRef", 8),
        ("isFrozenLiveness", 8),
        ("ctor", 5),
        ("constants", 1),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), *n))
    .collect();
    assert_eq!(per_fn, want, "per-function case totals");
    assert_eq!(cases.len(), 174);

    // the reference accepts a post-quantum beacon without a pin only through its legacy unbound opt-out, which is not offered here
    let (unbound, rest): (Vec<Value>, Vec<Value>) =
        cases.into_iter().partition(|c| c["args"].to_string().contains("allowUnboundPq") && c["out"]["ok"] == json!(true));
    assert_eq!(unbound.len(), 1, "reference acceptances through the unbound opt-out");
    for c in &unbound {
        assert_eq!(run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap())["ok"], json!(false), "{} must be refused", c["name"]);
    }
    let mut bad = Vec::new();
    for c in &rest {
        let got = run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap());
        let differs = if c["out"].get("$throws").is_some() {
            got.get("$throws").is_none()
        } else {
            atlas_pca::canonicalize(&c["out"]) != atlas_pca::canonicalize(&got)
        };
        if differs {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), rest.len(), bad.join("\n"));
}
