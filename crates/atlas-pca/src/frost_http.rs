//! The HTTP transport of networked FROST: one signer served over loopback HTTP and the coordinator-side transport that talks to it
//! (`startSignerHttpServer` / `httpSignerTransport`).
//!
//! [`start_signer_http_server`] serves ONE [`GuardianSignerService`]: `POST /round1` and `POST /round2`, JSON in and out (every byte string is
//! base64url). It binds the given host (use 127.0.0.1) on a port (0: an ephemeral one) and answers one connection at a time; run it in its own OS
//! process for real trust-domain separation. A handler error is a refusal response, never a leaked stack or share. The channel itself
//! (confidentiality, availability) is the deployment's responsibility. [`HttpSignerTransport`] is the [`SignerTransport`] of one remote signer;
//! `timeout_ms` bounds each call (default 10 s) and a failure is an `Err`, which the coordinator records as an unreachable signer.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{json, Value};

use crate::frost_net::{GuardianSignerService, SignerTransport};

/// The largest request body the server reads.
pub const BODY_LIMIT: usize = 1 << 20;
const HEADER_LIMIT: usize = 16 * 1024;

/// The status and payload for one request (pure; no socket). A non-POST is 405, an unknown path 404, anything that cannot be read is a 400
/// refusal naming this signer.
pub fn respond(service: &GuardianSignerService, method: &str, target: &str, body: &[u8]) -> (u16, Value) {
    if method != "POST" {
        return (405, json!({"ok": false, "reason": "method not allowed"}));
    }
    if target != "/round1" && target != "/round2" {
        return (404, json!({"ok": false, "reason": "not found"}));
    }
    let refused = |why: String| (400, json!({"ok": false, "identifier": service.identifier, "refused": true, "reason": if why.is_empty() { "bad request".to_string() } else { why }}));
    if body.len() > BODY_LIMIT {
        return refused("request body too large".into());
    }
    let req: Value = if body.is_empty() {
        json!({})
    } else {
        match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => return refused(e.to_string()),
        }
    };
    (200, if target == "/round1" { service.round1(&req) } else { service.round2(&req) })
}

/// A running signer HTTP server.
pub struct SignerHttpServer {
    pub url: String,
    pub port: u16,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl SignerHttpServer {
    /// Stop accepting and wait for the serving thread.
    pub fn close(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for SignerHttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn reason_of(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "OK",
    }
}

fn send(conn: &mut TcpStream, status: u16, payload: &Value) {
    let json = payload.to_string();
    let head = format!("HTTP/1.1 {status} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", reason_of(status), json.len());
    let _ = conn.write_all(head.as_bytes()).and_then(|_| conn.write_all(json.as_bytes()));
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn handle(service: &GuardianSignerService, conn: &mut TcpStream) {
    let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf: Vec<u8> = Vec::new();
    let end = loop {
        if let Some(e) = find(&buf, b"\r\n\r\n") {
            break e;
        }
        if buf.len() > HEADER_LIMIT {
            return;
        }
        let mut chunk = [0u8; 4096];
        match conn.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split(' ');
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let len = lines
        .filter_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("content-length")))
        .map(|(_, v)| v.trim().parse::<usize>().unwrap_or(0))
        .next()
        .unwrap_or(0);
    if len > BODY_LIMIT {
        send(conn, 400, &json!({"ok": false, "identifier": service.identifier, "refused": true, "reason": "request body too large"}));
        return;
    }
    let mut body = buf[end + 4..].to_vec();
    while body.len() < len {
        let mut chunk = vec![0u8; (len - body.len()).min(65536)];
        match conn.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    body.truncate(len);
    let (status, payload) = respond(service, method, target, &body);
    send(conn, status, &payload);
}

/// `startSignerHttpServer`: serve `service` on `host` (default 127.0.0.1) and `port` (default 0: an ephemeral one).
pub fn start_signer_http_server(service: Arc<GuardianSignerService>, host: Option<&str>, port: Option<u16>) -> Result<SignerHttpServer, String> {
    let host = host.unwrap_or("127.0.0.1");
    let listener = TcpListener::bind((host, port.unwrap_or(0))).map_err(|e| format!("startSignerHttpServer: could not listen on {host}:{} ({e})", port.unwrap_or(0)))?;
    let bound = listener.local_addr().map_err(|_| "startSignerHttpServer: could not determine server address".to_string())?.port();
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let thread = std::thread::spawn(move || {
        while !flag.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut conn, _)) => {
                    let _ = conn.set_nonblocking(false);
                    // a broken or hostile connection ends that connection only
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle(&service, &mut conn)));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        }
    });
    Ok(SignerHttpServer { url: format!("http://{host}:{bound}"), port: bound, stop, thread: Some(thread) })
}

/// `httpSignerTransport`: the transport of one remote signer, over HTTP/1.1 with one connection per call.
pub struct HttpSignerTransport {
    base_url: String,
    identifier: i64,
    timeout: Duration,
}

/// `httpSignerTransport(baseUrl, identifier, {timeoutMs})`: `timeout_ms` bounds each call (default 10 s).
pub fn http_signer_transport(base_url: &str, identifier: i64, timeout_ms: Option<u64>) -> HttpSignerTransport {
    HttpSignerTransport { base_url: base_url.trim_end_matches('/').to_string(), identifier, timeout: Duration::from_millis(timeout_ms.unwrap_or(10_000)) }
}

impl HttpSignerTransport {
    fn post(&self, path: &str, body: &Value) -> Result<Value, String> {
        let rest = self.base_url.strip_prefix("http://").ok_or("httpSignerTransport: only http:// URLs are supported")?;
        let (authority, prefix) = rest.split_once('/').map_or((rest, String::new()), |(a, p)| (a, format!("/{p}")));
        let addr = authority.to_socket_addrs().map_err(|e| format!("{authority}: {e}"))?.next().ok_or_else(|| format!("{authority}: no address"))?;
        let mut conn = TcpStream::connect_timeout(&addr, self.timeout).map_err(|e| e.to_string())?;
        conn.set_read_timeout(Some(self.timeout)).and_then(|_| conn.set_write_timeout(Some(self.timeout))).map_err(|e| e.to_string())?;
        let payload = body.to_string();
        let req = format!("POST {prefix}{path} HTTP/1.1\r\nhost: {authority}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}", payload.len());
        conn.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        conn.take(2 * BODY_LIMIT as u64).read_to_end(&mut raw).map_err(|e| e.to_string())?;
        let end = find(&raw, b"\r\n\r\n").ok_or("httpSignerTransport: malformed response")?;
        serde_json::from_slice(&raw[end + 4..]).map_err(|e| format!("httpSignerTransport: response is not JSON ({e})"))
    }
}

impl SignerTransport for HttpSignerTransport {
    fn identifier(&self) -> i64 {
        self.identifier
    }
    fn round1(&self, req: &Value) -> Result<Value, String> {
        self.post("/round1", req)
    }
    fn round2(&self, req: &Value) -> Result<Value, String> {
        self.post("/round2", req)
    }
}
