//! Differential replay of the revocation registry, chain check, verifyWithRevocation and CAEP bridge against the TypeScript
//! reference (test-data/ref-revoke.json.gz). A scenario's steps run over one registry; a step that throws is `{"$err": true}`.
mod common;
use atlas_pca::revoke::*;
use atlas_pca::serde_json::{json, Value};

/// A store that fails `get` (`fail_get`) or `all` (`fail_all`) the way the reference's throwing stores do.
struct Failing {
    base: InMemoryRevocationStore,
    fail_get: bool,
    fail_all: bool,
}

impl RevocationStore for Failing {
    fn add(&self, e: Value) -> Result<(), String> {
        self.base.add(e)
    }
    fn remove(&self, k: &str, v: &str) -> Result<bool, String> {
        self.base.remove(k, v)
    }
    fn get(&self, k: &str, v: &str) -> Result<Option<Value>, String> {
        if self.fail_get {
            Err("boom".into())
        } else {
            self.base.get(k, v)
        }
    }
    fn all(&self) -> Result<Vec<Value>, String> {
        if self.fail_all {
            Err("boom".into())
        } else {
            self.base.all()
        }
    }
    fn clear(&self) -> Result<(), String> {
        self.base.clear()
    }
}

/// The frozen clock the corpus generator ran under (its header's clockMs), read once.
fn clock() -> f64 {
    static CLOCK: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    *CLOCK.get_or_init(|| common::ref_clock_ms("revoke"))
}

/// The reference prints a revokedAt within two minutes of the wall clock, or of its generator's frozen clock, as "<now>".
fn norm(v: Value) -> Value {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as f64;
    match v {
        Value::Array(a) => Value::Array(a.into_iter().map(norm).collect()),
        Value::Object(m) => Value::Object(
            m.into_iter()
                .map(|(k, x)| {
                    let near = k == "revokedAt" && x.as_f64().is_some_and(|f| (f - now).abs() < 120_000.0 || (f - clock()).abs() < 120_000.0);
                    (k, if near { json!("<now>") } else { norm(x) })
                })
                .collect(),
        ),
        x => x,
    }
}

fn scenario(spec: &Value) -> Value {
    let st = spec.get("store").and_then(Value::as_str).unwrap_or("mem");
    let reg = RevocationRegistry::new(Failing { base: InMemoryRevocationStore::new(), fail_get: st == "failGet", fail_all: st == "failAll" });
    let mut out = Vec::new();
    for s in spec["ops"].as_array().unwrap() {
        let g = |k: &str| s.get(k);
        let v = |k: &str| s.get(k).cloned().unwrap_or(Value::Null);
        let r: Result<Value, String> = match s["op"].as_str().unwrap() {
            "revoke" => reg.revoke(&v("input")),
            "revokeSubtree" => reg.revoke_subtree(&v("target"), g("opts")),
            "unrevoke" => reg.unrevoke(&v("key")).map(Value::Bool),
            "list" => reg.list().map(Value::Array),
            "lookup" => reg.lookup(s["kind"].as_str().unwrap(), s["value"].as_str().unwrap()).map(|e| e.unwrap_or(Value::Null)),
            "prefixes" => reg.prefixes().map(Value::Array),
            "clear" => reg.clear().map(|_| Value::Null),
            "killAgent" => reg.kill_agent(&v("holder"), g("opts")),
            "killSubtree" => reg.kill_subtree(&v("root"), g("opts")),
            "check" => Ok(check_revocation(&v("p"), &reg, g("opts"))),
            "verify" => Ok(verify_with_revocation(&v("p"), &v("core"), &reg, g("opts"))),
            "ingest" => ingest_caep_event(&v("event"), &reg).map(Value::Array),
            op => panic!("unknown op {op}"),
        };
        out.push(r.map(norm).unwrap_or_else(|_| json!({ "$err": true })));
    }
    Value::Array(out)
}

#[test]
fn revoke_vectors() {
    let cases = common::ref_cases("revoke");
    let mut bad = Vec::new();
    for c in &cases {
        let a = c["args"].as_array().unwrap();
        let got = match c["fn"].as_str().unwrap() {
            "scenario" => scenario(&a[0]),
            "isActiveAt" => json!(is_active_at(&a[0], &a[1])),
            "caepEventTypes" => caep_event_types(),
            f => panic!("unknown fn {f}"),
        };
        if atlas_pca::canonicalize(&c["out"]) != atlas_pca::canonicalize(&got) {
            bad.push(format!("{}\n  want {}\n  got  {got}", c["name"], c["out"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
