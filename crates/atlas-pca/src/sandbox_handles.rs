//! Sandbox capability handle table (a per-sandbox CSpace): indices are small 1-based integers meaningful only inside one table. A
//! slot exists only because an allowing authorize result is bound to exactly that operation; derivation is monotone (a child holds
//! only what the parent gave up); revoking a slot revokes everything derived from it. Every use, refusals included, is receipted.
//! Indices, `uses` and `expiresAt` are `f64` like the reference's numbers, so a fractional or out-of-range value is refused the
//! same way. Single-threaded: the table owns its receipt log (`log()` reads it).
use crate::authorize::{AuthorizedOperation, Operation};
use crate::hash_canonical_strict;
use crate::sandbox_egress::is_bound_for;
use crate::sandbox_receipts::{satisfies_runtime_class, ReceiptLog, GENESIS, RUNTIME_CLASSES};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

pub const IMPORT_MODULE: &str = "pca:act";
pub const ALLOWED_IMPORTS: [&str; 3] = ["invoke", "handle_count", "handle_verb"];
/// Negative return codes of a handle use (the WASM ABI returns them as i32), in the reference's order.
pub const USE_ERR: [(&str, i32); 6] =
    [("unknown_handle", -1), ("spent", -2), ("out_too_small", -3), ("bad_memory", -4), ("executor_error", -5), ("no_executor", -6)];

/// The sandbox module constants as the reference's `moduleConsts` oracle reports them.
pub fn module_consts() -> Value {
    let mut use_err = serde_json::Map::new();
    for (k, v) in USE_ERR {
        use_err.insert(k.into(), json!(v));
    }
    json!({
        "IMPORT_MODULE": IMPORT_MODULE,
        "ALLOWED_IMPORTS": ALLOWED_IMPORTS,
        "USE_ERR": Value::Object(use_err),
        "GENESIS": GENESIS,
        "RUNTIME_CLASSES": RUNTIME_CLASSES,
        "DOMAIN": crate::runtime_claim::RUNTIME_CLAIM_DOMAIN,
    })
}

/// What a tool may do with a handle: run the one authorized operation, given `{verb, resource, params}` (the signed params, never
/// the guest's). `Err` is a throw or a non-bytes return.
pub type Executor = Box<dyn Fn(&Value) -> Result<Vec<u8>, String> + Send>;
/// The result bytes, or the refusal reason (a key of [`USE_ERR`]).
pub type UseResult = Result<Vec<u8>, &'static str>;

/// The reference's JSON shape of a use result: `{ok: true, result: {$bytes}}` or `{ok: false, reason}`.
pub fn use_result_json(r: &UseResult) -> Value {
    match r {
        Ok(b) => json!({"ok": true, "result": {"$bytes": crate::b64_encode(b)}}),
        Err(reason) => json!({"ok": false, "reason": reason}),
    }
}

#[derive(Default, Clone)]
pub struct MintOptions {
    /// How many times the handle may be used (default 1; an integer in 1..=1_000_000).
    pub uses: Option<f64>,
    /// Epoch ms after which the handle is spent.
    pub expires_at: Option<f64>,
    /// Refuse to mint into a table below this class.
    pub requires: Option<String>,
}

struct Slot {
    op: Value,
    params_digest: String,
    op_id: String,
    uses: f64,
    expires_at: f64,
    revoked: bool,
    children: Vec<usize>,
}

pub struct HandleTable {
    pub runtime_class: String,
    log: ReceiptLog,
    executors: HashMap<String, Executor>,
    now: Box<dyn Fn() -> f64 + Send>,
    slots: Vec<Slot>,
}

impl HandleTable {
    /// `now`: epoch ms (default the system clock).
    pub fn new(runtime_class: &str, log: ReceiptLog, executors: HashMap<String, Executor>, now: Option<Box<dyn Fn() -> f64 + Send>>) -> HandleTable {
        let now =
            now.unwrap_or_else(|| Box::new(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as f64).unwrap_or(0.0)));
        HandleTable { runtime_class: runtime_class.into(), log, executors, now, slots: vec![] }
    }

    pub fn log(&self) -> &ReceiptLog {
        &self.log
    }

    pub fn size(&self) -> usize {
        self.slots.len()
    }

    fn at(&self, index: f64) -> Option<usize> {
        (index.fract() == 0.0 && index >= 1.0 && index <= self.slots.len() as f64).then(|| index as usize - 1)
    }

    fn live(&self, i: usize) -> bool {
        let s = &self.slots[i];
        !s.revoked && s.uses > 0.0 && { let t = (self.now)(); t.is_finite() && t < s.expires_at }
    }

    /// Mint a handle for `operation`; `bound` is the operation an ALLOWING authorize result carries (`None` for a refusal).
    /// Returns the 1-based index. `Err` (fail closed) when the table class is below `requires`, the result does not allow exactly
    /// `operation`, or `uses` is not an integer in 1..=1_000_000.
    pub fn mint(&mut self, bound: Option<&AuthorizedOperation>, operation: &Operation, opts: &MintOptions) -> Result<usize, String> {
        if let Some(r) = &opts.requires {
            if !satisfies_runtime_class(&self.runtime_class, r) {
                return Err(format!("runtime_class_too_weak: table is {}, grant requires {r}", self.runtime_class));
            }
        }
        if !is_bound_for(bound, operation) {
            return Err("not_authorized: result does not allow exactly this operation".into());
        }
        let uses = opts.uses.unwrap_or(1.0);
        if uses.fract() != 0.0 || !(1.0..=1_000_000.0).contains(&uses) {
            return Err("bad_uses".into());
        }
        let params_digest = hash_canonical_strict(&operation.params).ok_or("not_authorized: params outside the strict profile")?;
        self.slots.push(Slot {
            op: json!({"verb": operation.verb, "resource": operation.resource, "params": operation.params}),
            params_digest,
            op_id: bound.map(|b| b.id.clone()).unwrap_or_default(),
            uses,
            expires_at: opts.expires_at.unwrap_or(f64::INFINITY),
            revoked: false,
            children: vec![],
        });
        Ok(self.slots.len())
    }

    /// Derive a narrower handle: takes `uses` from the parent (never more than it has) and an expiry no later than the parent's.
    pub fn attenuate(&mut self, index: f64, uses: Option<f64>, expires_at: Option<f64>) -> Result<usize, String> {
        let pi = self.at(index).filter(|i| self.live(*i)).ok_or("unknown_handle")?;
        let (p_uses, p_exp) = (self.slots[pi].uses, self.slots[pi].expires_at);
        let uses = uses.unwrap_or(p_uses);
        if uses.fract() != 0.0 || uses < 1.0 || uses > p_uses {
            return Err("attenuate_widens".into());
        }
        let exp = expires_at.unwrap_or(p_exp);
        if !(exp <= p_exp) {
            return Err("attenuate_widens".into());
        }
        let p = &mut self.slots[pi];
        p.uses -= uses;
        let child =
            Slot { op: p.op.clone(), params_digest: p.params_digest.clone(), op_id: p.op_id.clone(), uses, expires_at: exp, revoked: false, children: vec![] };
        self.slots.push(child);
        let ci = self.slots.len();
        self.slots[pi].children.push(ci);
        Ok(ci)
    }

    /// Revoke a handle and, transitively, every handle derived from it. An unknown or already revoked index is a no-op.
    pub fn revoke(&mut self, index: f64) {
        let Some(i) = self.at(index) else { return };
        if self.slots[i].revoked {
            return;
        }
        self.slots[i].revoked = true;
        for c in self.slots[i].children.clone() {
            self.revoke(c as f64);
        }
    }

    /// The verb a handle carries.
    pub fn verb_of(&self, index: f64) -> Option<String> {
        self.at(index).and_then(|i| self.slots[i].op["verb"].as_str().map(String::from))
    }

    /// Use a handle: run the executor on the authorized operation and record a receipt. A use is consumed before the executor runs
    /// and stays consumed if it fails.
    pub fn use_handle(&mut self, index: f64) -> UseResult {
        let Some(i) = self.at(index) else {
            let body = json!({"kind": "handle_use", "subject": {"op_id": "", "verb": "", "resource": "", "params_digest": ""}, "outcome": "refused", "reason": "unknown_handle"});
            let _ = self.log.append(&self.runtime_class, &body);
            return Err("unknown_handle");
        };
        if !self.live(i) {
            return self.finish(i, Err("spent"));
        }
        let verb = self.slots[i].op["verb"].as_str().unwrap_or("").to_string();
        if !self.executors.contains_key(&verb) {
            return self.finish(i, Err("no_executor"));
        }
        self.slots[i].uses -= 1.0;
        let op = self.slots[i].op.clone();
        let exec = &self.executors[&verb];
        let r = catch_unwind(AssertUnwindSafe(|| exec(&op)));
        let r = match r {
            Ok(Ok(b)) => Ok(b),
            _ => Err("executor_error"),
        };
        self.finish(i, r)
    }

    fn finish(&mut self, i: usize, r: UseResult) -> UseResult {
        let outcome = match &r {
            Ok(_) => "ok",
            Err("executor_error") => "error",
            Err(_) => "refused",
        };
        let s = &self.slots[i];
        let reason = match &r {
            Ok(_) => "used",
            Err(e) => *e,
        };
        let subject = json!({"op_id": s.op_id, "verb": s.op["verb"], "resource": s.op["resource"], "params_digest": s.params_digest});
        let body = json!({"kind": "handle_use", "subject": subject, "outcome": outcome, "reason": reason});
        let _ = self.log.append(&self.runtime_class, &body);
        r
    }
}
