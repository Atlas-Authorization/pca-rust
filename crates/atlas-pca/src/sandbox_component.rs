//! Component host: runs a WebAssembly component (the `tool` world of the PCA act interface) by spawning the reference
//! `pca-wasmtime-host` binary and answering its handle requests over JSON lines on stdio. The host binary is the only thing that
//! interprets the component: it meters instruction fuel, refuses every import but the handle interface, and has no WASI.
//!
//! Trust in the binary: its path comes from configuration only and its SHA-256 is pinned. A missing binary, a missing pin or a
//! different hash is refused before anything is spawned. The child gets an empty environment and no shell.
//! Limit of the pin: the hash is checked on the file's bytes, then the path is executed; a writer who can replace the file in
//! between wins that race. Install the binary somewhere only the operator can write.
use crate::sandbox_handles::{HandleTable, USE_ERR};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub type RunResult = Result<i64, String>;

/// Where the reference host binary is and the SHA-256 (64 hex chars) it must have.
#[derive(Clone)]
pub struct HostBinary {
    pub path: String,
    pub expected_sha256: String,
}

#[derive(Clone)]
pub struct ComponentOptions {
    pub fuel: u64,
    pub timeout_ms: u64,
    pub max_result_bytes: usize,
}

impl ComponentOptions {
    /// `fuel` has no default: a budget is a decision.
    pub fn new(fuel: u64) -> ComponentOptions {
        ComponentOptions {
            fuel,
            timeout_ms: 10_000,
            max_result_bytes: 1 << 20,
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Constant-time comparison of two equal-purpose hex strings.
fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// Check the binary against its pin: `host_unpinned`, `host_missing` or `host_hash_mismatch`.
pub fn verify_host_binary(h: &HostBinary) -> Result<(), String> {
    read_verified_host(h).map(|_| ())
}

/// The pinned binary's bytes, only if they match the pin; callers exec a private copy of these bytes, never the path.
fn read_verified_host(h: &HostBinary) -> Result<Vec<u8>, String> {
    let pin = h.expected_sha256.to_lowercase();
    if pin.len() != 64 || !pin.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("host_unpinned".into());
    }
    let bytes = std::fs::read(&h.path).map_err(|_| "host_missing".to_string())?;
    if !ct_eq(&hex(&Sha256::digest(&bytes)), &pin) {
        return Err("host_hash_mismatch".into());
    }
    Ok(bytes)
}

fn temp_dir() -> std::io::Result<std::path::PathBuf> {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let d = std::env::temp_dir().join(format!("pca-comp-{}", hex(&b)));
    crate::private_file::create_dir_private(&d)?;
    Ok(d)
}

/// Run `component` (binary or WAT text) under the pinned host with `fuel` instructions and a wall-clock timeout, serving its
/// handle requests from `table`. Reasons: bad_fuel, host_unpinned, host_missing, host_hash_mismatch, host_unavailable,
/// host_protocol, host_exit, timeout, or whatever the host reports (fuel_exhausted, ambient_import:<name>, trap, ...).
pub fn run_component(
    table: &Arc<Mutex<HandleTable>>,
    component: &[u8],
    host: &HostBinary,
    o: &ComponentOptions,
) -> RunResult {
    if o.fuel < 1 || o.fuel > (1u64 << 53) {
        return Err("bad_fuel".into());
    }
    verify_host_binary(host)?;
    run_host(
        table,
        host,
        &["__FILE__".into(), o.fuel.to_string()],
        Some(component),
        o.timeout_ms,
        o.max_result_bytes,
    )
}

/// Shared by both subprocess modes: write `payload` to a temp file (replacing the `__FILE__` argument), spawn, serve, clean up.
pub(crate) fn run_host(
    table: &Arc<Mutex<HandleTable>>,
    host: &HostBinary,
    args: &[String],
    payload: Option<&[u8]>,
    timeout_ms: u64,
    max_result: usize,
) -> RunResult {
    // hash, then exec a private 0700 copy of the verified bytes: the path cannot be swapped between the check and the exec
    let verified = read_verified_host(host)?;
    let dir = temp_dir().map_err(|_| "host_unavailable".to_string())?;
    let result = (|| -> RunResult {
        let exe = dir.join("host");
        std::fs::write(&exe, &verified).map_err(|_| "host_unavailable".to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "host_unavailable".to_string())?;
        }
        let file = dir.join("tool.component");
        if let Some(p) = payload {
            std::fs::write(&file, p).map_err(|_| "host_unavailable".to_string())?;
        }
        let argv: Vec<String> = args
            .iter()
            .map(|a| {
                if a == "__FILE__" {
                    file.to_string_lossy().into_owned()
                } else {
                    a.clone()
                }
            })
            .collect();
        // a concurrent fork elsewhere in the process can briefly hold the just-written executable open for writing (ETXTBSY)
        let mut tries = 0;
        let mut child = loop {
            match Command::new(&exe)
                .args(&argv)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(c) => break c,
                Err(e) if e.raw_os_error() == Some(26) && tries < 50 => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => return Err("host_unavailable".to_string()),
            }
        };
        let mut stdin = child.stdin.take().ok_or("host_unavailable")?;
        let stdout = child.stdout.take().ok_or("host_unavailable")?;
        let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(l) => {
                        if tx.send(Some(l)).is_err() {
                            return;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = tx.send(None);
        });
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let out = loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = match rx.recv_timeout(left) {
                Ok(Some(l)) => l,
                Ok(None) => break Err("host_exit".to_string()),
                Err(_) => break Err("timeout".to_string()),
            };
            let Ok(m) = serde_json::from_str::<Value>(&line) else {
                break Err("host_protocol".to_string());
            };
            if let Some(f) = m.get("fail").and_then(Value::as_str) {
                break Err(f.to_string());
            }
            if let Some(d) = m.get("done").and_then(Value::as_i64) {
                break Ok(d);
            }
            let h = m
                .get("h")
                .and_then(Value::as_f64)
                .filter(|h| h.fract() == 0.0)
                .unwrap_or(0.0);
            let reply = match m.get("op").and_then(Value::as_str) {
                Some("count") => json!({"n": table.lock().map(|t| t.size()).unwrap_or(0)}),
                Some("verb") => match table.lock().ok().and_then(|t| t.verb_of(h)) {
                    Some(v) => json!({"ok": v}),
                    None => json!({"err": -1}),
                },
                Some("invoke") => match table.lock().map(|mut t| t.use_handle(h)) {
                    Ok(Ok(b)) if b.len() > max_result => json!({"err": -3}),
                    Ok(Ok(b)) => json!({"ok": b}),
                    Ok(Err(reason)) => {
                        json!({"err": USE_ERR.iter().find(|(k, _)| *k == reason).map(|(_, c)| *c).unwrap_or(-5)})
                    }
                    Err(_) => json!({"err": -5}),
                },
                _ => break Err("host_protocol".to_string()),
            };
            if writeln!(stdin, "{reply}")
                .and_then(|_| stdin.flush())
                .is_err()
            {
                break Err("host_exit".to_string());
            }
        };
        let _ = child.kill();
        let _ = child.wait();
        out
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// Core-module mode of the same pinned binary: `core <module> <fuel> <max_pages> <timeout_ms> [entry]`. Use this where the
/// in-process engine (`sandbox_wasm`, feature `sandbox-wasm`) is not built.
pub fn run_core_subprocess(
    table: &Arc<Mutex<HandleTable>>,
    module: &[u8],
    host: &HostBinary,
    fuel: u64,
    max_pages: u64,
    timeout_ms: u64,
    entry: &str,
) -> RunResult {
    if fuel < 1 || fuel > (1u64 << 53) {
        return Err("bad_fuel".into());
    }
    verify_host_binary(host)?;
    let args = vec![
        "core".into(),
        "__FILE__".into(),
        fuel.to_string(),
        max_pages.to_string(),
        timeout_ms.to_string(),
        entry.to_string(),
    ];
    // the host enforces its own epoch deadline; the parent's kill timer is a little longer so the host's reason wins
    run_host(table, host, &args, Some(module), timeout_ms + 1000, 1 << 20)
}
