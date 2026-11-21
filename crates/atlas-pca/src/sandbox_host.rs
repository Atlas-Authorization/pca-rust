//! `createSandbox` (packages/pca-sandbox/src/host.ts): the WebAssembly host assembled from its parts. The tool is a core module
//! whose only import is `pca:act.{invoke,handle_count,handle_verb}`; the only authority it holds is the handles minted into the
//! table. The runtime class of the table is the one an attestor-signed runtime claim PROVES, capped at what a WASM host can show
//! (`wasi_no_ambient`); without a verified claim the class is `none` (an operator's say-so does not count).
//!
//! Unlike the reference's in-thread `run`, every run here is metered (an instruction budget is required, as in `sandbox_wasm`) and
//! bounded by a wall-clock deadline, so `run_async` (kill a tool that never returns) and `run` are one and the same call.
use crate::sandbox_claims::verified_runtime_class_trust;
use crate::sandbox_handles::{Executor, HandleTable};
use crate::sandbox_receipts::ReceiptLog;
use crate::sandbox_wasm::{run, CoreOptions, RunResult};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Inputs of [`create_sandbox`]. Build with [`SandboxOptions::new`].
pub struct SandboxOptions {
    pub executors: HashMap<String, Executor>,
    /// A receipt log to append to (default a fresh one on `now`).
    pub log: Option<ReceiptLog>,
    /// The host clock in epoch ms (default the system clock).
    pub now: Option<Arc<dyn Fn() -> f64 + Send + Sync>>,
    /// Largest tool binary accepted (default 1 MiB).
    pub max_module_bytes: usize,
    /// Largest linear memory a tool may declare, in 64 KiB pages (default 256 = 16 MiB).
    pub max_memory_pages: u64,
    /// Largest result one handle use may return to the tool (default 1 MiB).
    pub max_result_bytes: usize,
    /// Instruction budget per run (no default: a budget is a decision).
    pub fuel: u64,
    /// Wall-clock deadline per run in ms (default 5000).
    pub timeout_ms: u64,
    /// `(claim, trust)`: the signed runtime claim and the trust it is checked against (`{pinnedAttestors, passportDigest,
    /// verifiedEvidenceDigests, now}`). Without a claim that verifies, the table is class `none`.
    pub runtime_claim: Option<(Value, Value)>,
}

impl SandboxOptions {
    pub fn new(executors: HashMap<String, Executor>, fuel: u64) -> SandboxOptions {
        SandboxOptions {
            executors,
            log: None,
            now: None,
            max_module_bytes: 1 << 20,
            max_memory_pages: 256,
            max_result_bytes: 1 << 20,
            fuel,
            timeout_ms: 5000,
            runtime_claim: None,
        }
    }
}

/// A WebAssembly host over one handle table.
pub struct Sandbox {
    /// The handle table (mint, derive, revoke, use); its log is `table.lock().log()`.
    pub table: Arc<Mutex<HandleTable>>,
    core: CoreOptions,
}

impl Sandbox {
    /// Validate and run the tool's export `entry` (usually `"run"`). `Ok(value)` is the entry's i32 result (0 when it returns
    /// nothing); `Err(reason)` is one of the reference's reasons (`module_size`, `malformed_module`, `memory_limits`,
    /// `ambient_import:<m>.<n>`, `no_entry`, `trap:...`) or `fuel_exhausted` / `timeout`.
    pub fn run(&self, bytes: &[u8], entry: &str) -> RunResult {
        run(&self.table, bytes, entry, &self.core)
    }
}

/// The class a runtime claim proves, capped at `wasi_no_ambient`; `none` for anything that does not verify.
fn table_class(claim: Option<&(Value, Value)>) -> &'static str {
    match claim.map(|(c, t)| verified_runtime_class_trust(c, t)) {
        Some(c @ ("wasi_no_ambient" | "egress_default_deny" | "os_confined")) => c,
        _ => "none",
    }
}

/// `createSandbox`.
pub fn create_sandbox(o: SandboxOptions) -> Sandbox {
    let clock = |now: &Option<Arc<dyn Fn() -> f64 + Send + Sync>>| -> Option<Box<dyn Fn() -> f64 + Send>> {
        now.clone().map(|n| Box::new(move || n()) as Box<dyn Fn() -> f64 + Send>)
    };
    let log = o.log.unwrap_or_else(|| ReceiptLog::new(clock(&o.now), None));
    let class = table_class(o.runtime_claim.as_ref());
    let table = Arc::new(Mutex::new(HandleTable::new(class, log, o.executors, clock(&o.now))));
    let mut core = CoreOptions::new(o.fuel);
    core.timeout_ms = o.timeout_ms;
    core.max_module_bytes = o.max_module_bytes;
    core.max_memory_pages = o.max_memory_pages;
    core.max_result_bytes = o.max_result_bytes;
    Sandbox { table, core }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_reference::build_probe_tool;

    #[test]
    fn unverified_claim_is_class_none_and_the_probe_runs() {
        let s = create_sandbox(SandboxOptions::new(HashMap::new(), 1_000_000));
        assert_eq!(s.table.lock().unwrap().runtime_class, "none");
        assert!(s.run(&build_probe_tool(None), "run").is_ok());
        assert_eq!(s.run(&[], "run"), Err("module_size".into()));
        let bad = (serde_json::json!({}), serde_json::json!({}));
        let s2 = create_sandbox(SandboxOptions { runtime_claim: Some(bad), ..SandboxOptions::new(HashMap::new(), 1_000_000) });
        assert_eq!(s2.table.lock().unwrap().runtime_class, "none");
    }
}
