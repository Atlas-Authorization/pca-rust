//! Differential replay of key rotation, subtree re-issue and apply_rotation against the TypeScript reference
//! (test-data/ref-rotate.json.gz). Keys cross as base64url Ed25519 seeds; a throw only requires a refusal.
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::revoke::RevocationRegistry;
use atlas_pca::rotate::*;
use atlas_pca::serde_json::{json, Value};
use std::cell::Cell;

/// The frozen clock the corpus generator ran under (its header's clockMs), read once.
fn clock() -> f64 {
    static CLOCK: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    *CLOCK.get_or_init(|| common::ref_clock_ms("rotate"))
}

/// The `revokedAt` of the pre-existing revocations of a rotation scenario: a constant of the oracle's own scenario script (its output
/// prints it as the number), not the generator's frozen clock.
const PRE_REVOKED_AT: u64 = 1_800_000_000_000;

fn key(v: &Value) -> Result<KeyPair, String> {
    KeyPair::from_seed_b64u(v.as_str().ok_or("seed is not a string")?)
}

/// An entry whose revokedAt is within two minutes of the generator's frozen clock prints as "<now>"; the registry under test reads the
/// same clock.
fn norm(v: Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.into_iter().map(norm).collect()),
        Value::Object(m) => Value::Object(
            m.into_iter()
                .map(|(k, x)| {
                    let near = k == "revokedAt" && x.as_f64().is_some_and(|f| (f - clock()).abs() < 120_000.0);
                    (k, if near { json!("<now>") } else { norm(x) })
                })
                .collect(),
        ),
        x => x,
    }
}

/// The reference's scenario sink: a registry whose `revoke` throws on its `fail_at`-th call, `unrevoke` always when `fail_unrevoke`.
struct Sink {
    reg: RevocationRegistry,
    calls: Cell<u64>,
    fail_at: Option<u64>,
    fail_unrevoke: bool,
}

impl RevocationSink for Sink {
    fn revoke(&self, input: &Value) -> Result<(), String> {
        self.calls.set(self.calls.get() + 1);
        if self.fail_at == Some(self.calls.get()) {
            return Err("sink down".into());
        }
        self.reg.revoke(input).map(|_| ())
    }
    fn unrevoke(&self, key: &Value) -> Result<bool, String> {
        if self.fail_unrevoke {
            return Err("unrevoke down".into());
        }
        self.reg.unrevoke(key)
    }
    fn lookup(&self, kind: &str, value: &str) -> Result<Option<Value>, String> {
        self.reg.lookup(kind, value)
    }
}

fn apply_scenario(spec: &Value) -> Value {
    let sink = Sink {
        reg: RevocationRegistry::default().with_clock(clock),
        calls: Cell::new(0),
        fail_at: spec.get("failAt").and_then(Value::as_u64),
        fail_unrevoke: spec.get("failUnrevoke") == Some(&json!(true)),
    };
    for id in spec.get("pre").and_then(Value::as_array).into_iter().flatten() {
        sink.reg.revoke(&json!({ "kind": "cap", "value": id, "reason": "pre", "revokedAt": PRE_REVOKED_AT })).unwrap();
    }
    let result = match apply_rotation(&sink, spec.get("records").unwrap_or(&Value::Null), spec.get("reissued")) {
        Ok(ids) => json!(ids),
        Err(_) => json!({ "$err": true }),
    };
    json!({ "result": result, "list": norm(Value::Array(sink.reg.list().unwrap())) })
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let arg = |i: usize| a.get(i).cloned().unwrap_or(Value::Null);
    match f {
        "rotateAgentKey" => {
            let op = common::with_now_if_absent(Some(&arg(1)), clock());
            rotate_agent_key(&arg(0), &key(&op["oldSeed"])?, &key(&op["newSeed"])?, &op)
        }
        "rotatePrincipalKey" => {
            let op = common::with_now_if_absent(Some(&arg(0)), clock());
            let hs = match op.get("holderSeeds") {
                Some(Value::Array(h)) => h.iter().map(key).collect::<Result<Vec<_>, _>>()?,
                _ => Vec::new(), // absent or null: `holderSecrets ?? []`
            };
            rotate_principal_key(&op, &key(&op["oldSeed"])?, &key(&op["newSeed"])?, &hs)
        }
        "revokeAndReissueSubtree" => {
            let op = common::with_now_if_absent(Some(&arg(2)), clock());
            revoke_and_reissue_subtree(&arg(0), &arg(1), &key(&op["newSeed"])?, &key(&op["ancestorSeed"])?, &op)
        }
        "compromisedKeyFlow" => {
            let op = common::with_now_if_absent(Some(&arg(2)), clock());
            compromised_key_flow(&arg(0), &arg(1), &key(&op["newSeed"])?, &key(&op["ancestorSeed"])?, &op)
        }
        "applyRotationScenario" => Ok(apply_scenario(&arg(0))),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn rotate_vectors() {
    let cases = common::ref_cases_seeded("rotate");
    let mut bad = Vec::new();
    for c in &cases {
        if common::lone_refusal(c) {
            continue;
        }
        let got = run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap()).map(norm);
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {got:?}", c["name"], c["out"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
