//! `createEgressProxy` (packages/pca-sandbox/src/egress.ts): a forward proxy for non-WASM tools. Set it as the tool's only route
//! out (HTTP(S)_PROXY, a network namespace, or the generated OS profile that permits connecting only to this proxy). Every request
//! is claimed against the admissions of an [`EgressPolicy`]; refusals answer 403 and are receipted. The upstream address is
//! resolved through a guard that refuses private addresses unless `allow_private`, so an admitted host name cannot be re-pointed
//! at an internal service.
//!
//! Plain `http://` requests are forwarded over HTTP/1.1 (one request per connection) and `CONNECT` becomes a byte tunnel. The
//! crate carries no TLS client: an absolute `https://` URL sent as a plain request (clients normally use CONNECT for https) is
//! forwarded through `https_upstream` when the caller supplies one, and answers 502 `upstream:tls_unavailable` otherwise (fail
//! closed). A request body must carry `Content-Length` (a chunked request is refused 501). The upstream response is relayed with
//! its framing headers (`Content-Length` / `Transfer-Encoding`) intact and `Connection: close`.
use crate::sandbox_egress::{is_private_address, EgressDecision, EgressPolicy};
use crate::sandbox_receipts::ReceiptLog;
use serde_json::json;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// Hop-by-hop headers (and `host`) not forwarded in either direction.
const HOP: [&str; 10] =
    ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "host"];
const MAX_HEAD: usize = 65_536;

/// A plain request handed to the caller's `https_upstream`.
#[derive(Debug, Clone)]
pub struct UpstreamRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// The answer of `https_upstream` (relayed with its headers minus the hop-by-hop ones, and a computed `content-length`).
#[derive(Debug, Clone)]
pub struct UpstreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// An `https://` transport supplied by the caller (the crate has no TLS client). `Err` is a transport failure: the proxy answers 502.
pub type HttpsUpstream = Arc<dyn Fn(&UpstreamRequest) -> Result<UpstreamResponse, String> + Send + Sync>;

#[derive(Clone)]
pub struct EgressProxyOptions {
    pub policy: Arc<Mutex<EgressPolicy>>,
    pub log: Arc<Mutex<ReceiptLog>>,
    /// The runtime class receipts carry (default `egress_default_deny`).
    pub runtime_class: String,
    /// Permit upstreams that resolve to private / loopback addresses (tests, internal APIs). Default false (the SSRF guard).
    pub allow_private: bool,
    /// Largest request body (default 1 MiB); a larger one is refused 413 `body_too_large`.
    pub max_body_bytes: usize,
    /// Connect and read deadline towards the upstream (default 10 s).
    pub upstream_timeout_ms: u64,
    pub https_upstream: Option<HttpsUpstream>,
}

impl EgressProxyOptions {
    pub fn new(policy: Arc<Mutex<EgressPolicy>>, log: Arc<Mutex<ReceiptLog>>) -> Self {
        EgressProxyOptions {
            policy,
            log,
            runtime_class: "egress_default_deny".into(),
            allow_private: false,
            max_body_bytes: 1 << 20,
            upstream_timeout_ms: 10_000,
            https_upstream: None,
        }
    }
}

/// A running proxy. Dropping it (or [`EgressProxy::close`]) stops accepting; in-flight connections finish.
pub struct EgressProxy {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl EgressProxy {
    /// The address the proxy listens on (useful after binding port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn close(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // wake the blocking accept
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(500));
        if let Some(h) = self.accept.take() {
            let _ = h.join();
        }
    }
}

impl Drop for EgressProxy {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// `createEgressProxy`: bind `bind` (for example `"127.0.0.1:0"`) and serve until closed.
pub fn create_egress_proxy(o: EgressProxyOptions, bind: &str) -> std::io::Result<EgressProxy> {
    let listener = TcpListener::bind(bind)?;
    let addr = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let (flag, shared) = (stop.clone(), Arc::new(o));
    let accept = std::thread::spawn(move || {
        for conn in listener.incoming() {
            if flag.load(Ordering::SeqCst) {
                break;
            }
            if let Ok(c) = conn {
                let s = shared.clone();
                std::thread::spawn(move || handle(c, &s));
            }
        }
    });
    Ok(EgressProxy { addr, stop, accept: Some(accept) })
}

// ---- receipts -----------------------------------------------------------------------------------------------------------------

fn receipt(o: &EgressProxyOptions, method: &str, url: &str, d: &EgressDecision, outcome: &str, reason: &str) {
    let subject = match d {
        EgressDecision::Allow { op_id, verb, resource, params_digest } => {
            json!({"op_id": op_id, "verb": verb, "resource": resource, "params_digest": params_digest})
        }
        EgressDecision::Deny { .. } => {
            json!({"op_id": "", "verb": "", "resource": format!("{method} {url}").chars().take(256).collect::<String>(), "params_digest": ""})
        }
    };
    if let Ok(mut l) = o.log.lock() {
        let _ = l.append(&o.runtime_class, &json!({"kind": "egress", "subject": subject, "outcome": outcome, "reason": reason}));
    }
}

fn claim(o: &EgressProxyOptions, method: &str, url: &str, body: &[u8]) -> EgressDecision {
    match o.policy.lock() {
        Ok(mut p) => p.claim(method, url, body),
        Err(_) => EgressDecision::Deny { reason: "policy_unavailable".into() },
    }
}

fn deny(c: &mut TcpStream, o: &EgressProxyOptions, method: &str, url: &str, reason: &str, status: u16) {
    receipt(o, method, url, &EgressDecision::Deny { reason: reason.into() }, "refused", reason);
    let body = json!({"error": "egress_denied", "reason": reason}).to_string();
    let text = if status == 413 { "Payload Too Large" } else { "Forbidden" };
    let _ = c.write_all(
        format!("HTTP/1.1 {status} {text}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes(),
    );
}

fn short(s: &str) -> String {
    format!("upstream:{s}").chars().take(64).collect()
}

// ---- wire ---------------------------------------------------------------------------------------------------------------------

/// Read until the blank line: `(head text, bytes read after it)`. `None` for a closed or oversized head.
fn read_head(s: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            return Some((String::from_utf8_lossy(&buf[..i]).into_owned(), buf[i + 4..].to_vec()));
        }
        if buf.len() > MAX_HEAD {
            return None;
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

fn headers_of(head: &str) -> Vec<(String, String)> {
    head.split("\r\n").skip(1).filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect()
}

fn io_code(e: &std::io::Error) -> String {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => "ECONNREFUSED".into(),
        TimedOut | WouldBlock => "timeout".into(),
        ConnectionReset => "ECONNRESET".into(),
        _ => "error".into(),
    }
}

/// Resolve and connect through the private-address guard. `Err` is the reason code (`EACCES` for a refused private address).
fn dial(o: &EgressProxyOptions, host: &str, port: u16) -> Result<TcpStream, String> {
    let timeout = Duration::from_millis(o.upstream_timeout_ms);
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs().map_err(|_| "ENOTFOUND".to_string())?.collect();
    if addrs.is_empty() {
        return Err("ENOTFOUND".into());
    }
    if !o.allow_private && addrs.iter().any(|a| is_private_address(&a.ip().to_string())) {
        return Err("EACCES".into());
    }
    let mut last = "error".to_string();
    for a in addrs {
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(s) => {
                let _ = s.set_read_timeout(Some(timeout));
                let _ = s.set_write_timeout(Some(timeout));
                return Ok(s);
            }
            Err(e) => last = io_code(&e),
        }
    }
    Err(last)
}

fn bad_gateway(c: &mut TcpStream) {
    let _ = c.write_all(b"HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
}

// ---- one connection -----------------------------------------------------------------------------------------------------------

fn handle(mut c: TcpStream, o: &EgressProxyOptions) {
    let _ = c.set_read_timeout(Some(Duration::from_secs(30)));
    let Some((head, rest)) = read_head(&mut c) else {
        let _ = c.write_all(b"HTTP/1.1 400 Bad Request\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
        return;
    };
    let mut parts = head.lines().next().unwrap_or("").split(' ');
    let (method, target) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string());
    if method.eq_ignore_ascii_case("CONNECT") {
        return connect(c, o, &target, rest);
    }
    let headers = headers_of(&head);
    let get = |k: &str| headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str());
    if get("transfer-encoding").is_some() {
        return deny(&mut c, o, &method, &target, "chunked_unsupported", 403);
    }
    let want: usize = match get("content-length") {
        None => 0,
        Some(v) => match v.parse() {
            Ok(n) => n,
            Err(_) => return deny(&mut c, o, &method, &target, "bad_content_length", 403),
        },
    };
    if want > o.max_body_bytes {
        return deny(&mut c, o, &method, &target, "body_too_large", 413);
    }
    let mut body = rest;
    body.truncate(want);
    while body.len() < want {
        let mut b = vec![0u8; (want - body.len()).min(65_536)];
        match c.read(&mut b) {
            Ok(0) | Err(_) => return deny(&mut c, o, &method, &target, "incomplete_body", 403),
            Ok(n) => body.extend_from_slice(&b[..n]),
        }
    }
    let d = claim(o, &method, &target, &body);
    if let EgressDecision::Deny { reason } = &d {
        return deny(&mut c, o, &method, &target, reason, 403);
    }
    let Ok(u) = url::Url::parse(&target) else {
        return deny(&mut c, o, &method, &target, "not_absolute_url", 403);
    };
    let host = u.host_str().unwrap_or("").trim_start_matches('[').trim_end_matches(']').to_string();
    let fwd: Vec<(String, String)> = headers.iter().filter(|(k, _)| !HOP.contains(&k.to_ascii_lowercase().as_str())).cloned().collect();
    if u.scheme() == "https" {
        let Some(up) = &o.https_upstream else {
            receipt(o, &method, &target, &d, "error", "upstream:tls_unavailable");
            return bad_gateway(&mut c);
        };
        if !o.allow_private && host.parse::<std::net::IpAddr>().is_ok() && is_private_address(&host) {
            receipt(o, &method, &target, &d, "error", "upstream:EACCES");
            return bad_gateway(&mut c);
        }
        return match up(&UpstreamRequest { method: method.clone(), url: target.clone(), headers: fwd, body }) {
            Ok(r) => {
                let mut out = format!("HTTP/1.1 {} \r\n", r.status);
                for (k, v) in r.headers.iter().filter(|(k, _)| !HOP.contains(&k.to_ascii_lowercase().as_str()) && !k.eq_ignore_ascii_case("content-length")) {
                    out.push_str(&format!("{k}: {v}\r\n"));
                }
                out.push_str(&format!("content-length: {}\r\nconnection: close\r\n\r\n", r.body.len()));
                let _ = c.write_all(out.as_bytes()).and_then(|_| c.write_all(&r.body));
                receipt(o, &method, &target, &d, "ok", &format!("status:{}", r.status));
            }
            Err(e) => {
                receipt(o, &method, &target, &d, "error", &short(&e));
                bad_gateway(&mut c);
            }
        };
    }
    let port = u.port().unwrap_or(80);
    let mut up = match dial(o, &host, port) {
        Ok(s) => s,
        Err(code) => {
            receipt(o, &method, &target, &d, "error", &short(&code));
            return bad_gateway(&mut c);
        }
    };
    let path = format!("{}{}", u.path(), u.query().map(|q| format!("?{q}")).unwrap_or_default());
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\n",
        u.host_str().map(|h| if let Some(p) = u.port() { format!("{h}:{p}") } else { h.to_string() }).unwrap_or_default()
    );
    for (k, v) in fwd.iter().filter(|(k, _)| !k.eq_ignore_ascii_case("content-length")) {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()));
    if let Err(e) = up.write_all(req.as_bytes()).and_then(|_| up.write_all(&body)) {
        receipt(o, &method, &target, &d, "error", &short(&io_code(&e)));
        return bad_gateway(&mut c);
    }
    let Some((uhead, urest)) = read_head(&mut up) else {
        receipt(o, &method, &target, &d, "error", "upstream:timeout");
        return bad_gateway(&mut c);
    };
    let status: u16 = uhead.lines().next().unwrap_or("").split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(502);
    let mut out = format!("{}\r\n", uhead.lines().next().unwrap_or("HTTP/1.1 502 Bad Gateway"));
    for (k, v) in headers_of(&uhead).iter().filter(|(k, _)| {
        let l = k.to_ascii_lowercase();
        l == "transfer-encoding" || !HOP.contains(&l.as_str())
    }) {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("connection: close\r\n\r\n");
    let _ = c.write_all(out.as_bytes()).and_then(|_| c.write_all(&urest)).and_then(|_| std::io::copy(&mut up, &mut c).map(|_| ()));
    receipt(o, &method, &target, &d, "ok", &format!("status:{status}"));
}

fn connect(mut c: TcpStream, o: &EgressProxyOptions, target: &str, rest: Vec<u8>) {
    let d = claim(o, "CONNECT", target, &[]);
    if let EgressDecision::Deny { reason } = &d {
        receipt(o, "CONNECT", target, &d, "refused", reason);
        let _ = c.write_all(b"HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n");
        return;
    }
    let Some((h, p)) = target.rsplit_once(':') else {
        return bad_gateway(&mut c);
    };
    let (host, port) = (h.trim_start_matches('[').trim_end_matches(']'), p.parse::<u16>().unwrap_or(0));
    let mut up = match dial(o, host, port) {
        Ok(s) => s,
        Err(code) => {
            receipt(o, "CONNECT", target, &d, "error", &short(&code));
            let _ = c.write_all(b"HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n");
            return;
        }
    };
    receipt(o, "CONNECT", target, &d, "ok", "tunnel");
    if c.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").is_err() || (!rest.is_empty() && up.write_all(&rest).is_err()) {
        return;
    }
    let _ = c.set_read_timeout(None);
    let _ = up.set_read_timeout(None);
    let (Ok(mut c2), Ok(mut up2)) = (c.try_clone(), up.try_clone()) else {
        return;
    };
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut c2, &mut up2);
        let _ = up2.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut up, &mut c);
    let _ = c.shutdown(std::net::Shutdown::Both);
    let _ = t.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorize::{AuthorizedOperation, Operation};

    /// A one-shot HTTP/1.1 upstream on loopback answering 200 `hello`.
    fn upstream() -> (u16, JoinHandle<()>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let _ = read_head(&mut s);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello");
            }
        });
        (port, h)
    }

    fn proxy(port: u16, allow_private: bool) -> (EgressProxy, Arc<Mutex<ReceiptLog>>) {
        let policy = Arc::new(Mutex::new(EgressPolicy::new(Box::new(|| 0.0))));
        let op = Operation::new("net.get", "127.0.0.1", json!({}));
        let bound = AuthorizedOperation {
            verb: "net.get".into(),
            resource: "127.0.0.1".into(),
            params_digest: crate::hash_canonical_strict(&json!({})).unwrap(),
            id: "op1".into(),
        };
        let tmpl = json!({"method": "GET", "scheme": "http", "host": "127.0.0.1", "port": port, "path": "/ok"});
        policy.lock().unwrap().admit(Some(&bound), &op, move |_| Some(tmpl), None, None).unwrap();
        let log = Arc::new(Mutex::new(ReceiptLog::new(None, None)));
        let mut o = EgressProxyOptions::new(policy, log.clone());
        o.allow_private = allow_private;
        (create_egress_proxy(o, "127.0.0.1:0").unwrap(), log)
    }

    fn ask(p: &EgressProxy, req: String) -> String {
        let mut s = TcpStream::connect(p.local_addr()).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    #[test]
    fn admitted_request_is_forwarded_and_receipted() {
        let (port, up) = upstream();
        let (p, log) = proxy(port, true);
        let out = ask(&p, format!("GET http://127.0.0.1:{port}/ok HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(out.starts_with("HTTP/1.1 200") && out.ends_with("hello"), "{out}");
        let e = log.lock().unwrap().entries.clone();
        assert_eq!((e.len(), e[0]["outcome"].as_str(), e[0]["subject"]["op_id"].as_str()), (1, Some("ok"), Some("op1")));
        up.join().unwrap();
        // the single admission is spent: the same request is now refused
        let again = ask(&p, format!("GET http://127.0.0.1:{port}/ok HTTP/1.1\r\n\r\n"));
        assert!(again.starts_with("HTTP/1.1 403") && again.contains("spent"), "{again}");
    }

    #[test]
    fn private_upstream_is_refused_unless_allowed_and_unadmitted_is_403() {
        let (p, log) = proxy(9, false);
        let out = ask(&p, "GET http://127.0.0.1:9/ok HTTP/1.1\r\n\r\n".into());
        assert!(out.starts_with("HTTP/1.1 502"), "{out}");
        assert_eq!(log.lock().unwrap().entries[0]["reason"], "upstream:EACCES");
        let out = ask(&p, "GET http://example.invalid/x HTTP/1.1\r\n\r\n".into());
        assert!(out.starts_with("HTTP/1.1 403"), "{out}");
        let out = ask(&p, "CONNECT evil.example:443 HTTP/1.1\r\n\r\n".into());
        assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    }
}
