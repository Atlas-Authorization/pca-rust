//! TEST-ONLY fault injection for the networked MPC. Two layers, deliberately separate:
//!
//! - [`tamper_for`]: a MALICIOUS SENDER rewriting its own outgoing frames at the application layer (duplicate, reorder, skipped sequence,
//!   garbage, truncation, wrong round / session, oversize length, drop, silence, a forged accusation). The bytes still travel inside valid
//!   TLS, so the receiver's framing checks decide.
//! - [`FaultProxy`]: a NETWORK adversary on the wire (a TCP middlebox): drop / delay / truncate / bit-flip / duplicate / reorder at the
//!   byte level. TLS 1.3 record authentication rejects tampering, so the expected outcome is an attributable-to-the-link `disconnect`,
//!   never a silently corrupted value.
use super::mesh::{Tamper, TamperEvent};
use crate::mpc_net::encode_frame;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::TcpListener as StdListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameFaultKind {
    Duplicate,
    Reorder,
    SkipSeq,
    Garbage,
    Truncate,
    Bitflip,
    WrongRound,
    WrongSession,
    Oversize,
    Drop,
    SilentFrom,
    ExtraField,
    /// Replace the frame with an abort frame that accuses `accuse`.
    FalseAccuse,
}

impl FrameFaultKind {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "duplicate" => Self::Duplicate,
            "reorder" => Self::Reorder,
            "skip-seq" => Self::SkipSeq,
            "garbage" => Self::Garbage,
            "truncate" => Self::Truncate,
            "bitflip" => Self::Bitflip,
            "wrong-round" => Self::WrongRound,
            "wrong-session" => Self::WrongSession,
            "oversize" => Self::Oversize,
            "drop" => Self::Drop,
            "silent-from" => Self::SilentFrom,
            "extra-field" => Self::ExtraField,
            "false-accuse" => Self::FalseAccuse,
            _ => return None,
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Duplicate => "duplicate",
            Self::Reorder => "reorder",
            Self::SkipSeq => "skip-seq",
            Self::Garbage => "garbage",
            Self::Truncate => "truncate",
            Self::Bitflip => "bitflip",
            Self::WrongRound => "wrong-round",
            Self::WrongSession => "wrong-session",
            Self::Oversize => "oversize",
            Self::Drop => "drop",
            Self::SilentFrom => "silent-from",
            Self::ExtraField => "extra-field",
            Self::FalseAccuse => "false-accuse",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameFault {
    pub kind: FrameFaultKind,
    /// Protocol round to attack (e.g. `mul0`).
    pub round: String,
    /// Restrict to one recipient; default: all recipients.
    pub to: Option<i64>,
    /// For `FalseAccuse`: the (honest) party the malicious sender names in its forged abort frame.
    pub accuse: Option<i64>,
}

impl FrameFault {
    pub fn new(kind: FrameFaultKind, round: &str) -> Self {
        FrameFault { kind, round: round.to_string(), to: None, accuse: None }
    }
}

fn with(frame: &Value, key: &str, v: Value) -> Value {
    let mut f = frame.clone();
    f[key] = v;
    f
}

/// The tamper hook of a malicious sender following `spec`.
pub fn tamper_for(spec: FrameFault) -> Tamper {
    let state: Mutex<(HashMap<i64, Vec<u8>>, bool)> = Mutex::new((HashMap::new(), false));
    Arc::new(move |ev: &TamperEvent| -> Vec<Vec<u8>> {
        let mut st = state.lock().expect("fault state");
        if st.1 {
            return vec![];
        }
        let rd = ev.frame["rd"].as_str().unwrap_or("");
        let hit = rd == spec.round && spec.to.map_or(true, |t| t == ev.to);
        let enc = |v: &Value| encode_frame(v).unwrap_or_default();
        if spec.kind == FrameFaultKind::Reorder {
            if let Some(held) = st.0.remove(&ev.to) {
                return vec![ev.raw.clone(), held]; // the later frame first, then the held-back one
            }
            if hit {
                st.0.insert(ev.to, ev.raw.clone());
                return vec![];
            }
            return vec![ev.raw.clone()];
        }
        if !hit {
            return vec![ev.raw.clone()];
        }
        let raw = &ev.raw;
        match spec.kind {
            FrameFaultKind::Duplicate => vec![raw.clone(), raw.clone()],
            FrameFaultKind::SkipSeq => vec![enc(&with(&ev.frame, "seq", json!(ev.frame["seq"].as_i64().unwrap_or(0) + 1)))],
            FrameFaultKind::Garbage => {
                let mut g = vec![0x5au8; raw.len()];
                g[0..4].copy_from_slice(&((raw.len() - 4) as u32).to_be_bytes());
                vec![g]
            }
            FrameFaultKind::Truncate => vec![raw[..(raw.len() / 2).max(5).min(raw.len())].to_vec()],
            FrameFaultKind::Bitflip => {
                let mut b = raw.clone();
                let i = (b.len() as f64 * 0.6).floor() as usize;
                b[i] ^= 0x04;
                vec![b]
            }
            FrameFaultKind::WrongRound => vec![enc(&with(&ev.frame, "rd", json!(format!("zzz-{rd}"))))],
            FrameFaultKind::WrongSession => vec![enc(&with(&ev.frame, "sid", json!("not-this-session")))],
            FrameFaultKind::Oversize => vec![0x7fff_ffffu32.to_be_bytes().to_vec()],
            FrameFaultKind::Drop => vec![],
            FrameFaultKind::SilentFrom => {
                st.1 = true;
                vec![]
            }
            FrameFaultKind::FalseAccuse => {
                let f = with(&with(&ev.frame, "ty", json!("abort")), "rd", json!("abort"));
                vec![enc(&with(&f, "d", json!({"kind": "timeout", "blamed": spec.accuse.unwrap_or(0), "detail": "forged accusation"})))]
            }
            FrameFaultKind::ExtraField => vec![enc(&with(&ev.frame, "x", json!(1)))],
            FrameFaultKind::Reorder => unreachable!("handled above"),
        }
    })
}

// ----------------------------------------------------------------------------- TCP fault proxy

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireFaultKind {
    None,
    Drop,
    Delay,
    Truncate,
    Bitflip,
    Duplicate,
    Reorder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Client to server.
    C2s,
    /// Server to client.
    S2c,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireFault {
    pub kind: WireFaultKind,
    pub dir: Dir,
    /// The fault starts after this many bytes have passed in that direction (skips the TLS handshake).
    pub after_bytes: usize,
    /// Delay in milliseconds (`Delay`; default one second).
    pub ms: Option<u64>,
}

/// A transparent TCP proxy that misbehaves once, after `after_bytes` bytes, in one direction.
///
/// shortcut: a `Delay` fault holds the stream for the delay (later chunks queue behind it) instead of timing each chunk independently;
/// the order and the total delay of delivery are the same, the spacing of later chunks is not.
pub struct FaultProxy {
    listener: StdListener,
    target: (String, u16),
    fault: WireFault,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl FaultProxy {
    /// `listener` must already be bound (so a node that dials early finds it).
    pub fn new(listener: StdListener, target_host: &str, target_port: u16, fault: WireFault) -> Self {
        FaultProxy { listener, target: (target_host.to_string(), target_port), fault, log: Arc::new(Mutex::new(vec![])) }
    }

    /// Serve until `stop` fires (or its sender is dropped).
    pub async fn serve(self, mut stop: tokio::sync::oneshot::Receiver<()>) -> Result<(), String> {
        self.listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let listener = TcpListener::from_std(self.listener).map_err(|e| e.to_string())?;
        loop {
            tokio::select! {
                _ = &mut stop => return Ok(()),
                acc = listener.accept() => {
                    let Ok((client, _)) = acc else { continue };
                    let (host, port, fault, log) = (self.target.0.clone(), self.target.1, self.fault, self.log.clone());
                    tokio::spawn(async move {
                        if let Ok(up) = TcpStream::connect((host.as_str(), port)).await {
                            let (cr, cw) = client.into_split();
                            let (ur, uw) = up.into_split();
                            let a = tokio::spawn(pipe(cr, uw, fault, Dir::C2s, log.clone()));
                            let b = tokio::spawn(pipe(ur, cw, fault, Dir::S2c, log));
                            let _ = a.await;
                            let _ = b.await;
                        }
                    });
                }
            }
        }
    }
}

async fn pipe(mut from: tokio::net::tcp::OwnedReadHalf, mut to: tokio::net::tcp::OwnedWriteHalf, f: WireFault, dir: Dir, log: Arc<Mutex<Vec<String>>>) {
    let active = f.kind != WireFaultKind::None && f.dir == dir;
    let (mut seen, mut fired, mut done) = (0usize, false, false);
    let mut held: Option<Vec<u8>> = None;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let chunk = &buf[..n];
        let before = seen;
        seen += n;
        if !active || done || before + n <= f.after_bytes {
            if active && f.kind == WireFaultKind::Drop && fired {
                continue; // a black hole stays black
            }
            if to.write_all(chunk).await.is_err() {
                break;
            }
            continue;
        }
        if !fired {
            fired = true;
            log.lock().expect("proxy log").push(format!("fault {:?} {:?} after {}B", f.kind, f.dir, f.after_bytes).to_lowercase());
        }
        match f.kind {
            WireFaultKind::Drop | WireFaultKind::None => {}
            WireFaultKind::Delay => {
                tokio::time::sleep(Duration::from_millis(f.ms.unwrap_or(1000))).await;
                if to.write_all(chunk).await.is_err() {
                    break;
                }
            }
            WireFaultKind::Truncate => {
                done = true;
                let _ = to.write_all(&chunk[..n / 2]).await;
                let _ = to.shutdown().await;
                return;
            }
            WireFaultKind::Bitflip => {
                done = true;
                let mut b = chunk.to_vec();
                b[n / 2] ^= 0x01;
                let _ = to.write_all(&b).await;
            }
            WireFaultKind::Duplicate => {
                done = true;
                let _ = to.write_all(chunk).await;
                let _ = to.write_all(chunk).await;
            }
            WireFaultKind::Reorder => match held.take() {
                None => held = Some(chunk.to_vec()),
                Some(h) => {
                    done = true;
                    let _ = to.write_all(chunk).await;
                    let _ = to.write_all(&h).await;
                }
            },
        }
    }
    if let Some(h) = held {
        let _ = to.write_all(&h).await;
    }
    let _ = to.shutdown().await;
}
