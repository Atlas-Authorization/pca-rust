//! Sandbox runtime classes and the receipt hash chain: every handle use and every egress decision, refusals included, appended to
//! an append-only chain whose entries commit to the previous one. `satisfies_runtime_class` orders the classes weakest first.
//! JSON-valued: a receipt is the reference's object, digests are the strict canonical hash of the receipt without `digest` / `sig`.
use crate::hash_canonical_strict;
use serde_json::{json, Map, Value};

/// Runtime classes, weakest first. A grant (or a resource server) can require a minimum; the host states the class it actually
/// enforces. The class is a claim by the host operator, recorded in every receipt; nothing here proves an OS profile was applied.
pub const RUNTIME_CLASSES: [&str; 4] = ["none", "os_confined", "egress_default_deny", "wasi_no_ambient"];
pub const GENESIS: &str = "genesis";

/// True only when both names are known and `attested` is at least `required`. An unknown name never satisfies.
pub fn satisfies_runtime_class(attested: &str, required: &str) -> bool {
    let idx = |s: &str| RUNTIME_CLASSES.iter().position(|c| *c == s);
    matches!((idx(attested), idx(required)), (Some(a), Some(r)) if a >= r)
}

fn digest_of(v: &Value) -> Result<String, String> {
    hash_canonical_strict(v).ok_or_else(|| "canonicalize: value is outside the strict JSON profile".to_string())
}

/// Append-only hash chain of use receipts.
pub struct ReceiptLog {
    pub entries: Vec<Value>,
    now: Box<dyn Fn() -> f64 + Send>,
    sign: Option<Box<dyn Fn(&str) -> String + Send>>,
}

impl ReceiptLog {
    /// `now`: the host clock in epoch ms (default the system clock); `sign`: an optional host signature over a digest.
    pub fn new(now: Option<Box<dyn Fn() -> f64 + Send>>, sign: Option<Box<dyn Fn(&str) -> String + Send>>) -> ReceiptLog {
        let now =
            now.unwrap_or_else(|| Box::new(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as f64).unwrap_or(0.0)));
        ReceiptLog { entries: vec![], now, sign }
    }

    /// Append a receipt of `body` (`kind`, `subject`, `outcome`, `reason`, and any further members, which are carried and hashed).
    /// A body member named like a chain member (`seq`, `at`, ...) replaces it, as the reference's object spread does. `Err` when the
    /// receipt is outside the strict JSON profile (nothing is appended).
    pub fn append(&mut self, runtime_class: &str, body: &Value) -> Result<Value, String> {
        let prev = self.entries.last().and_then(|e| e.get("digest")).and_then(Value::as_str).unwrap_or(GENESIS).to_string();
        let mut m = Map::new();
        m.insert("v".into(), json!(1));
        m.insert("seq".into(), json!(self.entries.len()));
        m.insert("prev".into(), json!(prev));
        m.insert("at".into(), json!((self.now)()));
        m.insert("runtime_class".into(), json!(runtime_class));
        if let Some(b) = body.as_object() {
            m.extend(b.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        let digest = digest_of(&Value::Object(m.clone()))?;
        m.insert("digest".into(), json!(digest));
        if let Some(sign) = &self.sign {
            m.insert("sig".into(), json!(sign(&digest)));
        }
        let r = Value::Object(m);
        self.entries.push(r.clone());
        Ok(r)
    }
}

/// Recompute the chain: `{ok: true}`, or `{ok: false, at, reason}` on a bad digest, a broken link, a gap, a reorder, or (with
/// `verify_sig`) a bad signature. `Err` where the reference throws (not an array, a null entry, a value outside the profile).
pub fn verify_receipt_chain(receipts: &Value, verify_sig: Option<&dyn Fn(&str, &str) -> bool>) -> Result<Value, String> {
    let items = receipts.as_array().ok_or("receipts.entries is not a function")?;
    let mut prev = GENESIS.to_string();
    for (i, r) in items.iter().enumerate() {
        if r.is_null() {
            return Err("Cannot read properties of null (reading 'v')".into());
        }
        let fail = |reason: &str| Ok(json!({"ok": false, "at": i, "reason": reason}));
        let get = |k: &str| r.as_object().and_then(|o| o.get(k));
        if !matches!(get("v"), Some(Value::Number(n)) if n.as_f64() == Some(1.0))
            || !matches!(get("seq"), Some(Value::Number(n)) if n.as_f64() == Some(i as f64))
        {
            return fail("bad_seq");
        }
        if get("prev").and_then(Value::as_str) != Some(prev.as_str()) {
            return fail("broken_link");
        }
        let mut rest = r.as_object().cloned().unwrap_or_default();
        let digest = rest.remove("digest");
        let sig = rest.remove("sig");
        if Some(digest_of(&Value::Object(rest))?) != digest.as_ref().and_then(Value::as_str).map(String::from) {
            return fail("bad_digest");
        }
        let digest = digest.and_then(|d| d.as_str().map(String::from)).unwrap_or_default();
        if let Some(v) = verify_sig {
            if !sig.as_ref().and_then(Value::as_str).is_some_and(|s| v(&digest, s)) {
                return fail("bad_sig");
            }
        }
        prev = digest;
    }
    Ok(json!({"ok": true}))
}
