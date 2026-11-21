//! The local launcher: runs the dealer (if any) and each party as its own node on loopback, with a fresh per-run identity for each,
//! optionally routes one link through a [`FaultProxy`], and collects each node's one-line JSON verdict.
//!
//! [`launch_local`] runs every node on its own thread with its own runtime in this process (the nodes still talk only over the TLS mesh);
//! [`launch_processes`] runs the same nodes as separate OS processes of the `pca-mpc-party` binary. Identities live in a throw-away
//! directory that is removed afterwards.
use super::certs::write_identity;
use super::clock::MeshClock;
use super::faults::{FaultProxy, FrameFault, WireFault};
use super::party_main::{run_node, DealerFaultCfg, NodeConfig, NodeSpec};
use super::prep::Offline;
use super::protocol::Behavior;
use crate::mpc::DecisionVector;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Multiplier for every launcher / test timeout, from `PCA_MPC_TEST_TIMEOUT_SCALE` (default 1; raise it on a slow machine).
pub fn timeout_scale() -> f64 {
    std::env::var("PCA_MPC_TEST_TIMEOUT_SCALE").ok().and_then(|s| s.parse::<f64>().ok()).filter(|x| x.is_finite() && *x > 0.0).unwrap_or(1.0)
}

/// Scale a duration (ms) by the one timeout knob.
pub fn scaled(ms: u64) -> u64 {
    (ms as f64 * timeout_scale()).ceil() as u64
}

/// `count` DISTINCT free loopback ports, all held open at the same time (so they cannot collide with each other) and released together.
pub fn reserve_ports(count: usize) -> Result<Vec<u16>, String> {
    let listeners = (0..count).map(|_| TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("reserve port: {e}"))).collect::<Result<Vec<_>, String>>()?;
    listeners.iter().map(|l| l.local_addr().map(|a| a.port()).map_err(|e| e.to_string())).collect()
}

#[derive(Clone, Default)]
pub struct NodeOverride {
    pub behavior: Option<Behavior>,
    pub frame_fault: Option<FrameFault>,
    pub dealer_fault: Option<DealerFaultCfg>,
    pub input: Option<DecisionVector>,
    pub recv_timeout_ms: Option<u64>,
}

/// Route the connection `dialer -> target` through a faulty TCP proxy.
#[derive(Clone, Copy)]
pub struct WireFaultSpec {
    pub dialer: i64,
    pub target: i64,
    pub fault: WireFault,
}

pub struct LaunchOptions {
    pub n: usize,
    pub q: Option<i64>,
    pub vectors: Vec<DecisionVector>,
    pub recv_timeout_ms: Option<u64>,
    /// Hard wall-clock cap for the whole run (a hang becomes a failed node, never a hung test).
    pub kill_after_ms: Option<u64>,
    pub overrides: BTreeMap<i64, NodeOverride>,
    pub wire_fault: Option<WireFaultSpec>,
    pub dealer_seed: Option<u64>,
    /// `NoDealer` (default: the parties run the OT offline phase) or `TrustedDealer` (adds a dealer node; needs `insecure_trusted_dealer`).
    pub offline: Offline,
    pub insecure_trusted_dealer: bool,
    /// A virtual clock for every node's mesh (in-process launcher only).
    pub clock: Option<Arc<dyn MeshClock>>,
}

impl LaunchOptions {
    pub fn new(n: usize, vectors: Vec<DecisionVector>) -> Self {
        LaunchOptions {
            n,
            q: None,
            vectors,
            recv_timeout_ms: None,
            kill_after_ms: None,
            overrides: BTreeMap::new(),
            wire_fault: None,
            dealer_seed: None,
            offline: Offline::NoDealer,
            insecure_trusted_dealer: false,
            clock: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeOutput {
    pub id: i64,
    /// `party` or `dealer`.
    pub role: &'static str,
    pub exit_code: i32,
    /// The node's one JSON line (`ok`, `result` / `error`, ...); null when it printed none.
    pub json: Value,
    pub stderr: String,
}

#[derive(Debug)]
pub struct Launched {
    pub outputs: Vec<NodeOutput>,
    pub wall_ms: u128,
    pub proxy_log: Vec<String>,
}

struct Plan {
    dir: PathBuf,
    configs: Vec<NodeConfig>,
    /// The proxy's bound listener and port, its fault, and the real port of the node it forwards to.
    proxy: Option<(TcpListener, u16, WireFault, u16)>,
}

fn session_id() -> String {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("operating-system randomness unavailable");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn plan(o: &LaunchOptions) -> Result<Plan, String> {
    let n = o.n;
    if o.offline == Offline::TrustedDealer && !o.insecure_trusted_dealer {
        return Err("launch: offline 'trusted-dealer' requires insecure_trusted_dealer: true".into());
    }
    if o.vectors.len() != n {
        return Err("launch: one decision vector per party".into());
    }
    let dealer = o.offline == Offline::TrustedDealer;
    let node_count = if dealer { n + 1 } else { n };
    let dir = std::env::temp_dir().join(format!("pca-mpc-net-{}-{}", std::process::id(), session_id()));
    let sid = session_id();
    let ports = reserve_ports(node_count)?;
    let mut ids = vec![];
    for i in 0..node_count {
        ids.push(write_identity(&dir.join(format!("node{i}")), &format!("mpc-node-{i}"))?);
    }
    let proxy = match o.wire_fault {
        Some(w) => {
            let l = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("proxy: {e}"))?;
            let port = l.local_addr().map_err(|e| e.to_string())?.port();
            let mut fault = w.fault;
            fault.ms = fault.ms.map(scaled);
            Some((l, port, fault, ports[w.target as usize]))
        }
        None => None,
    };
    let proxy_port = proxy.as_ref().map(|p| p.1);
    let mut configs = vec![];
    for id in 0..node_count as i64 {
        let nodes: Vec<NodeSpec> = (0..node_count)
            .map(|j| NodeSpec {
                id: j as i64,
                host: "127.0.0.1".to_string(),
                port: match (o.wire_fault, proxy_port) {
                    (Some(w), Some(pp)) if w.dialer == id && w.target == j as i64 => pp,
                    _ => ports[j],
                },
                cert_path: ids[j].1.to_string_lossy().to_string(),
            })
            .collect();
        let is_dealer = dealer && id == n as i64;
        let mut cfg = NodeConfig::new(
            if is_dealer { "dealer" } else { "party" },
            id,
            n,
            &sid,
            &ids[id as usize].0.to_string_lossy(),
            &ids[id as usize].1.to_string_lossy(),
            nodes,
        );
        cfg.q = o.q;
        cfg.offline = Some(o.offline);
        cfg.insecure_trusted_dealer = o.insecure_trusted_dealer;
        cfg.input = if is_dealer { None } else { o.vectors.get(id as usize).copied() };
        cfg.listen_host = Some("127.0.0.1".to_string());
        cfg.recv_timeout_ms = Some(scaled(o.recv_timeout_ms.unwrap_or(30_000)));
        cfg.connect_timeout_ms = Some(scaled(120_000));
        cfg.dealer_seed = if is_dealer { o.dealer_seed } else { None };
        cfg.clock = o.clock.clone();
        if let Some(ov) = o.overrides.get(&id) {
            cfg.behavior = ov.behavior.clone();
            cfg.frame_fault = ov.frame_fault.clone();
            cfg.dealer_fault = ov.dealer_fault.clone();
            if let Some(i) = ov.input {
                cfg.input = Some(i);
            }
            if let Some(t) = ov.recv_timeout_ms {
                cfg.recv_timeout_ms = Some(scaled(t));
            }
        }
        cfg.unsafe_test_hooks = cfg.hooks_requested();
        configs.push(cfg);
    }
    Ok(Plan { dir, configs, proxy })
}

fn role_of(cfg: &NodeConfig) -> &'static str {
    if cfg.role == "dealer" {
        "dealer"
    } else {
        "party"
    }
}

/// Start the fault proxy of a plan on its own thread; returns its stop handle, thread and log.
fn start_proxy(p: &mut Plan) -> Option<(tokio::sync::oneshot::Sender<()>, std::thread::JoinHandle<()>, Arc<std::sync::Mutex<Vec<String>>>)> {
    let (listener, _, fault, real_port) = p.proxy.take()?;
    let proxy = FaultProxy::new(listener, "127.0.0.1", real_port, fault);
    let log = proxy.log.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let h = std::thread::spawn(move || {
        if let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
            let _ = rt.block_on(proxy.serve(rx));
        }
    });
    Some((tx, h, log))
}

/// Run every node on its own thread (own runtime) in this process, all talking over loopback TLS.
pub fn launch_local(o: LaunchOptions) -> Result<Launched, String> {
    let mut p = plan(&o)?;
    let proxy = start_proxy(&mut p);
    let t0 = Instant::now();
    let cap = Duration::from_millis(scaled(o.kill_after_ms.unwrap_or(120_000)));
    let handles: Vec<_> = p
        .configs
        .iter()
        .cloned()
        .map(|cfg| {
            std::thread::spawn(move || -> NodeOutput {
                let (id, role) = (cfg.id, role_of(&cfg));
                let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(r) => r,
                    Err(e) => return NodeOutput { id, role, exit_code: 1, json: Value::Null, stderr: e.to_string() },
                };
                match rt.block_on(async { tokio::time::timeout(cap, run_node(&cfg, true)).await }) {
                    Ok(out) => NodeOutput { id, role, exit_code: out.code, json: out.json, stderr: String::new() },
                    Err(_) => NodeOutput {
                        id,
                        role,
                        exit_code: 137,
                        json: json!({"ok": false, "role": cfg.role, "id": id, "error": {"kind": "local", "message": "killed: the node did not finish within the launcher cap"}}),
                        stderr: String::new(),
                    },
                }
            })
        })
        .collect();
    let outputs: Vec<NodeOutput> = handles
        .into_iter()
        .enumerate()
        .map(|(i, h)| h.join().unwrap_or(NodeOutput { id: i as i64, role: "party", exit_code: 101, json: Value::Null, stderr: "node thread panicked".into() }))
        .collect();
    let mut proxy_log = vec![];
    if let Some((stop, h, log)) = proxy {
        let _ = stop.send(());
        let _ = h.join();
        proxy_log = log.lock().map(|l| l.clone()).unwrap_or_default();
    }
    let _ = std::fs::remove_dir_all(&p.dir);
    Ok(Launched { outputs, wall_ms: t0.elapsed().as_millis(), proxy_log })
}

/// Run every node as its own OS process of the `pca-mpc-party` binary at `bin`.
pub fn launch_processes(o: LaunchOptions, bin: &Path) -> Result<Launched, String> {
    let mut p = plan(&o)?;
    let proxy = start_proxy(&mut p);
    let t0 = Instant::now();
    let cap = Duration::from_millis(scaled(o.kill_after_ms.unwrap_or(120_000)));
    let mut handles = vec![];
    for cfg in p.configs.iter() {
        let path = p.dir.join(format!("cfg{}.json", cfg.id));
        crate::private_file::write_private(&path, cfg.to_json().to_string().as_bytes()).map_err(|e| e.to_string())?;
        let mut cmd = std::process::Command::new(bin);
        cmd.arg(&path).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).stdin(std::process::Stdio::null());
        if cfg.hooks_requested() {
            cmd.env("PCA_MPC_UNSAFE_TEST_HOOKS", "1");
        } else {
            cmd.env_remove("PCA_MPC_UNSAFE_TEST_HOOKS");
        }
        let mut child = cmd.spawn().map_err(|e| format!("spawn {}: {e}", bin.display()))?;
        let (id, role) = (cfg.id, role_of(cfg));
        handles.push(std::thread::spawn(move || -> NodeOutput {
            let start = Instant::now();
            let status = loop {
                match child.try_wait() {
                    Ok(Some(s)) => break s.code().unwrap_or(-1),
                    Ok(None) if start.elapsed() > cap => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break 137;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                    Err(_) => break -1,
                }
            };
            let read = |s: Option<&mut dyn std::io::Read>| {
                let mut t = String::new();
                if let Some(r) = s {
                    let _ = r.read_to_string(&mut t);
                }
                t
            };
            let so = read(child.stdout.as_mut().map(|s| s as &mut dyn std::io::Read));
            let se = read(child.stderr.as_mut().map(|s| s as &mut dyn std::io::Read));
            let json = so.lines().rev().find(|l| !l.trim().is_empty()).and_then(|l| serde_json::from_str::<Value>(l).ok()).unwrap_or(Value::Null);
            NodeOutput { id, role, exit_code: status, json, stderr: se.chars().take(2000).collect() }
        }));
    }
    let outputs: Vec<NodeOutput> = handles
        .into_iter()
        .enumerate()
        .map(|(i, h)| h.join().unwrap_or(NodeOutput { id: i as i64, role: "party", exit_code: 101, json: Value::Null, stderr: "waiter panicked".into() }))
        .collect();
    let mut proxy_log = vec![];
    if let Some((stop, h, log)) = proxy {
        let _ = stop.send(());
        let _ = h.join();
        proxy_log = log.lock().map(|l| l.clone()).unwrap_or_default();
    }
    let _ = std::fs::remove_dir_all(&p.dir);
    Ok(Launched { outputs, wall_ms: t0.elapsed().as_millis(), proxy_log })
}
