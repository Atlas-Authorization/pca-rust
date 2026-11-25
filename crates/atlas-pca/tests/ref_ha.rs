#![cfg(unix)]
//! Differential replay of test-data/ref-ha.json.gz (written by the TypeScript reference): guardian liveness, quorum, the degrade
//! mode, signer selection and failover, guardian-set validation, the fence guard, the lease (scripted against one in-memory
//! store with an injected clock and injected faults) and the raw compare-and-swap of the key-value lease store. A case the
//! reference refuses must be refused here.
mod common;
use atlas_pca::durable_state::{create_memory_durable_kv, DurableKv, MemoryDurableKv};
use atlas_pca::ha::*;
use atlas_pca::prohibitions::num_value;
use atlas_pca::serde_json::{json, Value};
use common::replay::{replay, thrown};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const KEY: &str = "ha/lease";

/// A number: a JSON number, or `{"$num": "NaN" | "Infinity" | "-Infinity"}`; anything else is NaN.
fn double(v: &Value) -> f64 {
    match v.get("$num").and_then(Value::as_str) {
        Some("Infinity") => f64::INFINITY,
        Some("-Infinity") => f64::NEG_INFINITY,
        _ => v.as_f64().filter(|_| v.is_number()).unwrap_or(f64::NAN),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Fault {
    None,
    Read,
    Now,
    Cas,
    LoseCas,
}

/// The reference's test store: a `KvLeaseStore` over an in-memory kv with an injected clock and injected faults.
struct Harness {
    kv: Arc<MemoryDurableKv>,
    clock: Arc<Mutex<f64>>,
    fault: Mutex<Fault>,
    inner: KvLeaseStore,
}

impl Harness {
    fn new() -> Harness {
        let kv = Arc::new(create_memory_durable_kv());
        let clock = Arc::new(Mutex::new(0.0));
        let c = clock.clone();
        let inner = KvLeaseStore::new(kv.clone(), None, Some(Box::new(move || *c.lock().unwrap())));
        Harness { kv, clock, fault: Mutex::new(Fault::None), inner }
    }
    fn fault(&self) -> Fault {
        *self.fault.lock().unwrap()
    }
}

impl LeaseStore for Harness {
    fn read(&self) -> Result<Option<Value>, String> {
        if self.fault() == Fault::Read {
            return Err("boom".into());
        }
        self.inner.read()
    }
    fn cas(&self, expected: Option<&Value>, next: &Value) -> Result<bool, String> {
        match self.fault() {
            Fault::Cas => Err("boom".into()),
            Fault::LoseCas => {
                *self.fault.lock().unwrap() = Fault::None;
                Ok(false)
            }
            _ => self.inner.cas(expected, next),
        }
    }
    fn now(&self) -> Result<f64, String> {
        if self.fault() == Fault::Now {
            return Err("boom".into());
        }
        self.inner.now()
    }
}

fn lease_script(ops: &[Value]) -> Value {
    let h = Harness::new();
    let mut refs: HashMap<String, Value> = HashMap::new();
    // a remembered ref, else the literal record (an unknown ref is undefined: Null here)
    let resolve = |refs: &HashMap<String, Value>, v: &Value| match v {
        Value::String(s) => refs.get(s).cloned().unwrap_or(Value::Null),
        other => other.clone(),
    };
    let mut out = Vec::new();
    for op in ops {
        let name = op[0].as_str().unwrap_or("");
        out.push(match name {
            "clock" => {
                *h.clock.lock().unwrap() = double(&op[1]);
                Value::Null
            }
            "fault" => {
                *h.fault.lock().unwrap() = match op[1].as_str() {
                    Some("none") => Fault::None,
                    Some("read") => Fault::Read,
                    Some("now") => Fault::Now,
                    Some("cas") => Fault::Cas,
                    Some("loseCas") => Fault::LoseCas,
                    other => panic!("unhandled fault {other:?}"),
                };
                Value::Null
            }
            "raw" => {
                h.kv.set(KEY, &op[1]).expect("raw write");
                Value::Null
            }
            "read" => h.kv.get(KEY).expect("read").unwrap_or(Value::Null),
            "acquire" => {
                let r = acquire_lease(&h, &op[2], &op[3]);
                if r["ok"] == true {
                    refs.insert(op[1].as_str().expect("ref").to_string(), r["lease"].clone());
                }
                r
            }
            "renew" => renew_lease(&h, &resolve(&refs, &op[1]), &op[2]),
            "release" => {
                let r = release_lease(&h, &resolve(&refs, &op[1]));
                if r["ok"] == true {
                    if let Some(name) = op[1].as_str() {
                        refs.insert(name.to_string(), r["lease"].clone());
                    }
                }
                r
            }
            "fence" => {
                let skew = if op[2].is_null() { DEFAULT_LEASE_SKEW_MS } else { double(&op[2]) };
                assert_fence(&h, &resolve(&refs, &op[1]), skew)
            }
            "signer" => {
                let lease = resolve(&refs, &op[1]);
                let skew = if op[2].is_null() { DEFAULT_LEASE_SKEW_MS } else { double(&op[2]) };
                let (advance, throws) = (double(&op[3]), op[4] == true);
                let signer = fenced_signer(&h, || Some(lease.clone()).filter(|l| !l.is_null()), skew);
                match signer.call(|| {
                    *h.clock.lock().unwrap() += advance;
                    if throws {
                        Err("sign")
                    } else {
                        Ok("signed")
                    }
                }) {
                    Ok(f) => json!({"ok": true, "result": f.result, "epoch": f.epoch}),
                    Err(FencedError::Fence(e)) => json!({"ok": false, "reason": e.reason}),
                    Err(FencedError::Sign(e)) => json!({"ok": false, "error": e}),
                }
            }
            _ => json!({"$err": "bad op"}),
        });
    }
    Value::Array(out)
}

fn kv_cas(a: &[Value]) -> Value {
    let kv = Arc::new(create_memory_durable_kv());
    if !a[0].is_null() {
        kv.set(KEY, &a[0]).expect("seed");
    }
    let store = KvLeaseStore::new(kv.clone(), None, None);
    match store.cas(Some(&a[1]).filter(|e| !e.is_null()), &a[2]) {
        Ok(ok) => json!({"ok": ok, "stored": kv.get(KEY).expect("get").unwrap_or(Value::Null)}),
        Err(e) => thrown(e),
    }
}

fn run(f: &str, a: &[Value]) -> Value {
    let opts = |i: usize| Some(&a[i]).filter(|o| !o.is_null());
    match f {
        "liveGuardians" => Value::Array(live_guardians(&a[0], double(&a[1]), opts(2))),
        "quorumStatus" => quorum_status(&a[0], double(&a[1]), opts(2)),
        "degradeMode" => json!(degrade_mode(&a[0], opts(1))),
        "selectSigners" => select_signers(&a[0], double(&a[1]), opts(2)).map_or_else(thrown, Value::Array),
        "failoverPlan" => failover_plan(&a[0], double(&a[1]), opts(2)).unwrap_or_else(thrown),
        "validateGuardianSet" => validate_guardian_set(&a[0]).map_or(Value::Null, |m| json!(m)),
        "fenceGuard" => {
            let g = create_fence_guard(double(&a[0]));
            let admits: Vec<bool> = a[1].as_array().expect("epochs").iter().map(|e| g.admit(double(e))).collect();
            json!({"admits": admits, "highest": num_value(g.highest())})
        }
        "lease" => lease_script(a[0].as_array().expect("ops")),
        "kvCas" => kv_cas(a),
        "constants" => json!({"MAX_LEASE_TTL_MS": num_value(MAX_LEASE_TTL_MS), "DEFAULT_LEASE_SKEW_MS": num_value(DEFAULT_LEASE_SKEW_MS)}),
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn ha_replay() {
    replay("ha", 753, 0, run);
}
