//! One MPC node (a party, the trusted dealer or an OT demo role) as its OWN node, talking to the others only over the TLS mesh. It is
//! driven by a JSON config ([`NodeConfig`]) and reports exactly one JSON line: the result or the attributable abort. The `pca-mpc-party`
//! binary is a thin wrapper over [`cli`]; the in-process launcher calls [`run_node`] directly.
//!
//! Usage: `pca-mpc-party <config.json>`, or `pca-mpc-party keygen <dir> <cn>` (writes `<dir>/key.pem` and `<dir>/cert.pem`).
//!
//! The test hooks (`behavior`, `frame_fault`, `dealer_fault`) are refused unless the config sets `unsafeTestHooks` AND the environment
//! variable `PCA_MPC_UNSAFE_TEST_HOOKS=1` is set.
use super::certs::{read_pem, write_identity};
use super::clock::MeshClock;
use super::faults::{tamper_for, FrameFault, FrameFaultKind};
use super::mesh::{Mesh, MeshConfig, NodeAddr};
use super::ot_net::{run_ot_receiver, run_ot_sender};
use super::prep::Offline;
use super::protocol::{run_dealer, run_party, Behavior, DealerConfig, PartyConfig};
use super::{abort_json, local, CRASH_DETAIL, NULL, SILENT_DETAIL};
use crate::mpc::{low_u64, DealerFault, DecisionVector};
use crate::mpc_net::NetAbort;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSpec {
    pub id: i64,
    pub host: String,
    pub port: u16,
    pub cert_path: String,
}

/// TEST ONLY (dealer role): a lying dealer, `c = a*b + keep_c_delta`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DealerFaultCfg {
    pub keep_c_delta: Option<u64>,
    pub partner_c_delta: Vec<Option<u64>>,
    pub mac_fault_at_input: Option<usize>,
}

#[derive(Clone)]
pub struct NodeConfig {
    /// `party`, `dealer`, `ot-sender` or `ot-receiver`.
    pub role: String,
    /// For the ot-* roles: which base OT and how many transfers.
    pub ot: Option<(String, usize)>,
    pub id: i64,
    pub n: usize,
    pub q: Option<i64>,
    pub session_id: String,
    pub input: Option<DecisionVector>,
    pub listen_host: Option<String>,
    pub nodes: Vec<NodeSpec>,
    pub key_path: String,
    pub cert_path: String,
    pub recv_timeout_ms: Option<u64>,
    pub connect_timeout_ms: Option<u64>,
    /// TEST ONLY: needs `unsafe_test_hooks` and the environment opt-in, else the node refuses to start.
    pub behavior: Option<Behavior>,
    /// TEST ONLY: same gating as `behavior`.
    pub frame_fault: Option<FrameFault>,
    pub unsafe_test_hooks: bool,
    pub dealer_seed: Option<u64>,
    /// Which offline phase the parties run (default no-dealer, no dealer node). `trusted-dealer` also needs `insecure_trusted_dealer`.
    pub offline: Option<Offline>,
    pub insecure_trusted_dealer: bool,
    pub dealer_fault: Option<DealerFaultCfg>,
    /// Bind first: bind this node's listener (its own port may be 0), print one `{"listening":<port>,"id":<id>}` line, then read one stdin line
    /// `{"ports":{"<id>":<port>,...}}` carrying every peer's real port before dialing anyone.
    pub bind_first: bool,
    /// In-process only (not part of the JSON form): a listener the caller already holds; the node serves on it and never re-binds.
    pub listener: Option<Arc<std::net::TcpListener>>,
    /// In-process only (not part of the JSON form): the mesh clock.
    pub clock: Option<Arc<dyn MeshClock>>,
}

impl NodeConfig {
    pub fn new(role: &str, id: i64, n: usize, session_id: &str, key_path: &str, cert_path: &str, nodes: Vec<NodeSpec>) -> Self {
        NodeConfig {
            role: role.to_string(),
            ot: None,
            id,
            n,
            q: None,
            session_id: session_id.to_string(),
            input: None,
            listen_host: None,
            nodes,
            key_path: key_path.to_string(),
            cert_path: cert_path.to_string(),
            recv_timeout_ms: None,
            connect_timeout_ms: None,
            behavior: None,
            frame_fault: None,
            unsafe_test_hooks: false,
            dealer_seed: None,
            offline: None,
            insecure_trusted_dealer: false,
            dealer_fault: None,
            bind_first: false,
            listener: None,
            clock: None,
        }
    }

    pub fn hooks_requested(&self) -> bool {
        self.behavior.is_some() || self.frame_fault.is_some() || self.dealer_fault.is_some()
    }

    pub fn to_json(&self) -> Value {
        let mut o = json!({
            "role": self.role,
            "id": self.id,
            "n": self.n,
            "sessionId": self.session_id,
            "nodes": self.nodes.iter().map(|x| json!({"id": x.id, "host": x.host, "port": x.port, "certPath": x.cert_path})).collect::<Vec<_>>(),
            "keyPath": self.key_path,
            "certPath": self.cert_path,
            "unsafeTestHooks": self.unsafe_test_hooks,
            "insecureTrustedDealer": self.insecure_trusted_dealer,
        });
        let mut put = |k: &str, v: Value| o[k] = v;
        if self.bind_first {
            put("bindFirst", json!(true));
        }
        if let Some((kind, count)) = &self.ot {
            put("ot", json!({"kind": kind, "count": count}));
        }
        if let Some(q) = self.q {
            put("Q", json!(q));
        }
        if let Some(v) = self.input {
            put("input", json!({"allow": v.allow, "t": v.t, "rQuant": v.r_quant}));
        }
        if let Some(h) = &self.listen_host {
            put("listenHost", json!(h));
        }
        if let Some(t) = self.recv_timeout_ms {
            put("recvTimeoutMs", json!(t));
        }
        if let Some(t) = self.connect_timeout_ms {
            put("connectTimeoutMs", json!(t));
        }
        if let Some(b) = &self.behavior {
            put("behavior", json!({"kind": b.kind, "round": b.round}));
        }
        if let Some(f) = &self.frame_fault {
            put("frameFault", json!({"kind": f.kind.name(), "round": f.round, "to": f.to, "accuse": f.accuse}));
        }
        if let Some(s) = self.dealer_seed {
            put("dealerSeed", json!(s.to_string()));
        }
        if let Some(m) = self.offline {
            put("offline", json!(m.as_str()));
        }
        if let Some(d) = &self.dealer_fault {
            put(
                "dealerFault",
                json!({
                    "keepCDelta": d.keep_c_delta.map(|x| x.to_string()),
                    "partnerCDelta": d.partner_c_delta.iter().map(|x| x.map(|y| y.to_string())).collect::<Vec<_>>(),
                    "macFaultAtInput": d.mac_fault_at_input,
                }),
            );
        }
        o
    }

    pub fn from_json(v: &Value) -> Result<NodeConfig, String> {
        let text = |k: &str| v.get(k).and_then(Value::as_str).map(String::from).ok_or_else(|| format!("config: missing {k}"));
        let int = |x: &Value, k: &str| x.get(k).and_then(Value::as_i64);
        let dec = |s: &Value| -> Result<Option<u64>, String> {
            match s.as_str() {
                Some(t) => low_u64(t).map(Some).map_err(|e| e.to_string()),
                None => Ok(None),
            }
        };
        let nodes = v
            .get("nodes")
            .and_then(Value::as_array)
            .ok_or("config: missing nodes")?
            .iter()
            .map(|x| -> Result<NodeSpec, String> {
                Ok(NodeSpec {
                    id: int(x, "id").ok_or("config: node id")?,
                    host: x.get("host").and_then(Value::as_str).ok_or("config: node host")?.to_string(),
                    port: int(x, "port").and_then(|p| u16::try_from(p).ok()).ok_or("config: node port")?,
                    cert_path: x.get("certPath").and_then(Value::as_str).ok_or("config: node certPath")?.to_string(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let mut cfg = NodeConfig::new(
            &text("role")?,
            int(v, "id").ok_or("config: missing id")?,
            int(v, "n").ok_or("config: missing n")? as usize,
            &text("sessionId")?,
            &text("keyPath")?,
            &text("certPath")?,
            nodes,
        );
        cfg.q = int(v, "Q");
        cfg.listen_host = v.get("listenHost").and_then(Value::as_str).map(String::from);
        cfg.recv_timeout_ms = v.get("recvTimeoutMs").and_then(Value::as_u64);
        cfg.connect_timeout_ms = v.get("connectTimeoutMs").and_then(Value::as_u64);
        cfg.unsafe_test_hooks = v.get("unsafeTestHooks") == Some(&Value::Bool(true));
        cfg.insecure_trusted_dealer = v.get("insecureTrustedDealer") == Some(&Value::Bool(true));
        cfg.bind_first = v.get("bindFirst") == Some(&Value::Bool(true));
        cfg.input = match v.get("input") {
            Some(i) if i.is_object() => Some(DecisionVector {
                allow: int(i, "allow").ok_or("config: input.allow")?,
                t: int(i, "t").ok_or("config: input.t")?,
                r_quant: int(i, "rQuant").ok_or("config: input.rQuant")?,
            }),
            _ => None,
        };
        if let Some(o) = v.get("ot").filter(|o| o.is_object()) {
            cfg.ot = Some((o.get("kind").and_then(Value::as_str).unwrap_or("ec").to_string(), o.get("count").and_then(Value::as_u64).unwrap_or(128) as usize));
        }
        cfg.behavior = v.get("behavior").filter(|b| b.is_object()).map(|b| Behavior {
            kind: b.get("kind").and_then(Value::as_str).unwrap_or("").to_string(),
            round: b.get("round").and_then(Value::as_str).map(String::from),
        });
        if let Some(f) = v.get("frameFault").filter(|f| f.is_object()) {
            let kind = f.get("kind").and_then(Value::as_str).and_then(FrameFaultKind::parse).ok_or("config: frameFault.kind")?;
            cfg.frame_fault =
                Some(FrameFault { kind, round: f.get("round").and_then(Value::as_str).unwrap_or("").to_string(), to: int(f, "to"), accuse: int(f, "accuse") });
        }
        cfg.dealer_seed = dec(v.get("dealerSeed").unwrap_or(&NULL))?;
        cfg.offline = match v.get("offline").and_then(Value::as_str) {
            Some(s) => Some(Offline::parse(s).ok_or("config: offline")?),
            None => None,
        };
        if let Some(d) = v.get("dealerFault").filter(|d| d.is_object()) {
            cfg.dealer_fault = Some(DealerFaultCfg {
                keep_c_delta: dec(d.get("keepCDelta").unwrap_or(&NULL))?,
                partner_c_delta: match d.get("partnerCDelta").and_then(Value::as_array) {
                    Some(a) => a.iter().map(dec).collect::<Result<Vec<_>, String>>()?,
                    None => vec![],
                },
                mac_fault_at_input: d.get("macFaultAtInput").and_then(Value::as_u64).map(|x| x as usize),
            });
        }
        Ok(cfg)
    }
}

/// What a node did: its one JSON line, its exit code and whether it is to die abruptly (the test-only `crash` behaviour).
#[derive(Debug, Clone)]
pub struct NodeOutcome {
    pub json: Value,
    pub code: i32,
    pub crash: bool,
}

fn failure(cfg: &NodeConfig, e: &NetAbort, mesh: Option<&Mesh>) -> NodeOutcome {
    let mut o = json!({"ok": false, "role": cfg.role, "id": cfg.id, "error": abort_json(e)});
    if let Some(m) = mesh {
        o["links"] = links_json(m);
        o["events"] = json!(m.events().0);
    }
    NodeOutcome { json: o, code: 3, crash: false }
}

fn links_json(m: &Mesh) -> Value {
    json!(m
        .stats()
        .iter()
        .map(|s| json!({"peer": s.peer, "appBytesOut": s.app_bytes_out, "appBytesIn": s.app_bytes_in, "framesOut": s.frames_out, "framesIn": s.frames_in}))
        .collect::<Vec<_>>())
}

/// Run one node to completion. `hooks_allowed` is the environment opt-in (`PCA_MPC_UNSAFE_TEST_HOOKS=1`). A node that did not crash lingers
/// 300 ms before returning, so the abort frames it just wrote reach the peers before its sockets go away.
pub async fn run_node(cfg: &NodeConfig, hooks_allowed: bool) -> NodeOutcome {
    let out = run_node_inner(cfg, hooks_allowed).await;
    if !out.crash {
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    out
}

async fn run_node_inner(cfg: &NodeConfig, hooks_allowed: bool) -> NodeOutcome {
    let hooks = cfg.hooks_requested();
    if hooks && !(cfg.unsafe_test_hooks && hooks_allowed) {
        return failure(cfg, &local(cfg.id, "refusing to start: test hooks (behavior/frameFault/dealerFault) are not enabled in this environment"), None);
    }
    let build = || -> Result<Mesh, String> {
        let nodes = cfg
            .nodes
            .iter()
            .map(|x| -> Result<NodeAddr, String> { Ok(NodeAddr { id: x.id, host: x.host.clone(), port: x.port, cert_pem: read_pem(&x.cert_path)? }) })
            .collect::<Result<Vec<_>, String>>()?;
        let link_to = (cfg.role == "dealer").then(|| nodes.iter().filter(|x| x.id < cfg.n as i64).map(|x| x.id).collect::<Vec<_>>());
        Mesh::new(MeshConfig {
            clock: cfg.clock.clone(),
            self_id: cfg.id,
            nodes,
            link_to,
            key_pem: read_pem(&cfg.key_path)?,
            cert_pem: read_pem(&cfg.cert_path)?,
            session_id: cfg.session_id.clone(),
            listen_host: cfg.listen_host.clone(),
            connect_timeout_ms: cfg.connect_timeout_ms,
            recv_timeout_ms: cfg.recv_timeout_ms,
            tamper: cfg.frame_fault.clone().map(tamper_for),
            unsafe_test_hooks: hooks,
            before_hello: None,
            max_inbox_frames: None,
            max_inbox_bytes: None,
            listener: cfg.listener.clone(),
        })
    };
    let mesh = match build() {
        Ok(m) => m,
        Err(e) => return failure(cfg, &local(cfg.id, &e), None),
    };
    let t0 = Instant::now();
    let run = async {
        mesh.connect().await?;
        let connect_ms = t0.elapsed().as_millis() as u64;
        let mut o = match cfg.role.as_str() {
            "dealer" => {
                let df = cfg.dealer_fault.clone();
                run_dealer(
                    &mesh,
                    DealerConfig {
                        insecure_trusted_dealer: cfg.insecure_trusted_dealer,
                        n: cfg.n,
                        q: cfg.q,
                        seed: cfg.dealer_seed,
                        fault: df.as_ref().map(|d| DealerFault { keep_c_delta: d.keep_c_delta, partner_c_delta: d.partner_c_delta.clone() }),
                        mac_fault_at_input: df.and_then(|d| d.mac_fault_at_input),
                    },
                )
                .await?;
                json!({"ok": true, "role": "dealer", "id": cfg.id})
            }
            "ot-sender" | "ot-receiver" => {
                let (kind, count) = cfg.ot.clone().unwrap_or(("ec".to_string(), 128));
                let r = if cfg.role == "ot-sender" { run_ot_sender(&mesh, 1, &kind, count).await? } else { run_ot_receiver(&mesh, 0, &kind, count).await? };
                json!({"ok": true, "role": cfg.role, "result": r.to_json()})
            }
            "party" => {
                let input = cfg.input.ok_or_else(|| local(cfg.id, "config: a party needs an input"))?;
                let r = run_party(
                    &mesh,
                    PartyConfig {
                        id: cfg.id,
                        n: cfg.n,
                        q: cfg.q,
                        input,
                        dealer_id: None,
                        offline: cfg.offline,
                        insecure_trusted_dealer: cfg.insecure_trusted_dealer,
                        behavior: cfg.behavior.clone(),
                        unsafe_test_hooks: hooks,
                        session_id: cfg.session_id.clone(),
                        forensic_deadline_ms: None,
                    },
                )
                .await?;
                json!({"ok": true, "role": "party", "result": r.to_json()})
            }
            other => return Err(local(cfg.id, &format!("config: unknown role {other}"))),
        };
        o["connectMs"] = json!(connect_ms);
        o["links"] = links_json(&mesh);
        o["events"] = json!(mesh.events().0);
        Ok::<Value, NetAbort>(o)
    };
    match run.await {
        Ok(o) => NodeOutcome { json: o, code: 0, crash: false },
        Err(e) if e.kind == "local" && e.message.ends_with(CRASH_DETAIL) => NodeOutcome { json: json!(null), code: 7, crash: true },
        Err(e) if e.kind == "local" && e.message.ends_with(SILENT_DETAIL) => {
            // stay connected but stop participating: the peers must time out (bounded here so a launcher never hangs)
            let cap = Duration::from_millis(cfg.recv_timeout_ms.unwrap_or(30_000) * 3 + 5_000);
            let start = Instant::now();
            while mesh.failed().is_none() && start.elapsed() < cap {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            failure(cfg, &e, Some(&mesh))
        }
        Err(e) => {
            let e = mesh.failed().filter(|_| e.kind == "local").unwrap_or(e);
            failure(cfg, &e, Some(&mesh))
        }
    }
}

/// Bind first: bind this node's listener on its own configured port (0 = the OS picks), report the port it really holds on `out`, then read
/// one line from `input` carrying every peer's real port and write them into `cfg.nodes`. The held listener goes to the mesh and is never released.
pub fn bind_first(cfg: &mut NodeConfig, input: &mut dyn std::io::BufRead, out: &mut dyn std::io::Write) -> Result<(), String> {
    let me = cfg.nodes.iter().position(|x| x.id == cfg.id).ok_or("bind first: this node is not in the node list")?;
    let host = cfg.listen_host.clone().unwrap_or_else(|| "0.0.0.0".to_string());
    let l = std::net::TcpListener::bind((host.as_str(), cfg.nodes[me].port)).map_err(|e| format!("bind first: {e}"))?;
    let port = l.local_addr().map_err(|e| e.to_string())?.port();
    cfg.nodes[me].port = port;
    writeln!(out, "{}", json!({"listening": port, "id": cfg.id})).and_then(|_| out.flush()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    if input.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
        return Err("stdin closed before the port map arrived".to_string());
    }
    let map: Value = serde_json::from_str(&line).map_err(|e| format!("bind first: port map: {e}"))?;
    for x in cfg.nodes.iter_mut().filter(|x| x.id != cfg.id) {
        x.port = map["ports"][x.id.to_string()].as_u64().and_then(|p| u16::try_from(p).ok()).ok_or_else(|| format!("bind first: no port for node {}", x.id))?;
    }
    cfg.listener = Some(Arc::new(l));
    Ok(())
}

/// The command line: `keygen <dir> <cn>` or `<config.json>`. Prints exactly one JSON line and returns the exit code.
pub fn cli(args: Vec<String>) -> i32 {
    if args.first().map(String::as_str) == Some("keygen") {
        let (Some(dir), cn) = (args.get(1), args.get(2).map_or("mpc-node", String::as_str)) else {
            eprintln!("usage: pca-mpc-party keygen <dir> <cn>");
            return 2;
        };
        return match write_identity(std::path::Path::new(dir), cn) {
            Ok((k, c)) => {
                println!("{}", json!({"keyPath": k.to_string_lossy(), "certPath": c.to_string_lossy()}));
                0
            }
            Err(e) => {
                eprintln!("{e}");
                1
            }
        };
    }
    let Some(path) = args.first() else {
        eprintln!("usage: pca-mpc-party <config.json> | keygen <dir> <cn>");
        return 2;
    };
    let cfg = match std::fs::read_to_string(path)
        .map_err(|e| e.to_string())
        .and_then(|t| serde_json::from_str::<Value>(&t).map_err(|e| e.to_string()))
        .and_then(|v| NodeConfig::from_json(&v))
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            return 2;
        }
    };
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("runtime: {e}");
            return 1;
        }
    };
    let hooks_allowed = std::env::var("PCA_MPC_UNSAFE_TEST_HOOKS").as_deref() == Ok("1");
    let mut cfg = cfg;
    if cfg.bind_first {
        if let Err(e) = bind_first(&mut cfg, &mut std::io::stdin().lock(), &mut std::io::stdout()) {
            println!("{}", failure(&cfg, &local(cfg.id, &e), None).json);
            return 3;
        }
    }
    let out = rt.block_on(async {
        let o = run_node(&cfg, hooks_allowed).await;
        if !o.crash {
            println!("{}", o.json);
        }
        o
    });
    out.code
}
