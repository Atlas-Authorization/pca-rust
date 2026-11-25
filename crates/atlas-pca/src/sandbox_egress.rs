//! Sandbox egress admission: the default-deny policy that maps one authorized operation to the one outbound request it permits
//! (exact host, port, method; exact path or prefix; exact query; body hash), and the private-address check the egress proxy uses
//! to stop an admitted host name from being re-pointed at an internal service. The forward proxy server itself, the WebAssembly
//! host, the OS profile generators, the receipt log and the handle table are separate pieces of the sandbox package.
//!
//! `is_private_address` is STRICTER than the first reference vectors (as every native is, see the 0.5 reference fix): only the
//! global unicast range 2000::/3 is public among IPv6 addresses; IPv4-mapped, IPv4-compatible and NAT64 (64:ff9b::/96) addresses
//! are judged by their embedded IPv4 address; any zone id, and anything that is not a plain IP literal, is private.
use crate::authorize::{AuthorizedOperation, Operation};
use crate::hash_canonical_strict;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4_private(a: Ipv4Addr) -> bool {
    let [a, b, _, _] = a.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 100 && (64..=127).contains(&b))
        || a >= 224
}

/// Loopback, link-local, private, CGNAT, multicast and unspecified addresses, every IPv6 address outside 2000::/3 (embedded IPv4
/// judged by its IPv4 rule), a zone id, and any string that is not a plain IP literal.
pub fn is_private_address(ip: &str) -> bool {
    if ip.contains('%') {
        return true;
    }
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => v4_private(a),
        Ok(IpAddr::V6(a)) => {
            let s = a.segments();
            let embedded = |lo: &[u16]| Ipv4Addr::new((lo[0] >> 8) as u8, lo[0] as u8, (lo[1] >> 8) as u8, lo[1] as u8);
            if s[..5] == [0; 5] && (s[5] == 0xffff || s[5] == 0) {
                return v4_private(embedded(&s[6..])); // ::ffff:a.b.c.d (mapped) and ::a.b.c.d (compatible, includes :: and ::1)
            }
            if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0; 4] {
                return v4_private(embedded(&s[6..])); // NAT64
            }
            s[0] & 0xe000 != 0x2000
        }
        Err(_) => true,
    }
}

/// True only if an ALLOWING authorize result's bound operation is exactly `operation` (verb, resource, params digest): the
/// reference's `isAuthorizedFor`. `bound` is `None` for a refusal.
pub fn is_bound_for(bound: Option<&AuthorizedOperation>, operation: &Operation) -> bool {
    bound.is_some_and(|b| {
        !operation.verb.is_empty()
            && !operation.resource.is_empty()
            && operation.params.is_object()
            && b.verb == operation.verb
            && b.resource == operation.resource
            && hash_canonical_strict(&operation.params).as_deref() == Some(b.params_digest.as_str())
    })
}

/// The one outbound request an authorized operation maps to (a JSON template): `method`, `scheme`, `host`, `port?`, `path`,
/// `path_prefix?`, `query?`, `body_sha256?`, `tunnel?`.
struct Admission {
    op_id: String,
    op: Operation,
    method: String,
    scheme: String,
    host: String,
    port: i64,
    path: String,
    path_prefix: bool,
    query: Option<String>,
    body_sha256: Option<String>,
    tunnel: bool,
    uses: f64,
    expires_at: f64,
}

/// An admission decision: `Allow` carries the bound operation's id and the operation it was admitted for.
#[derive(Debug, Clone, PartialEq)]
pub enum EgressDecision {
    Allow { op_id: String, verb: String, resource: String, params_digest: String },
    Deny { reason: String },
}

impl EgressDecision {
    /// The reference's JSON shape: `{allow, op_id, admission}` or `{allow: false, reason}`.
    pub fn to_json(&self) -> Value {
        match self {
            EgressDecision::Allow { op_id, verb, resource, params_digest } => {
                json!({"allow": true, "op_id": op_id, "admission": {"verb": verb, "resource": resource, "params_digest": params_digest}})
            }
            EgressDecision::Deny { reason } => json!({"allow": false, "reason": reason}),
        }
    }
}

fn deny(r: &str) -> EgressDecision {
    EgressDecision::Deny { reason: r.into() }
}

fn default_port(scheme: &str) -> i64 {
    if scheme == "http" {
        80
    } else {
        443
    }
}

fn host_ok(h: &str) -> bool {
    if h.parse::<IpAddr>().is_ok() {
        return true;
    }
    let label = |l: &str| {
        let b = l.as_bytes();
        !b.is_empty() && b.len() <= 63 && b[0] != b'-' && b[b.len() - 1] != b'-' && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
    };
    !h.is_empty() && h.split('.').all(label)
}

fn path_ok(p: &str) -> bool {
    if !p.starts_with('/') || p.contains(['?', '#', '\\']) {
        return false;
    }
    let l = p.to_ascii_lowercase();
    if l.contains("%2e") || l.contains("%2f") || l.contains("%5c") {
        return false;
    }
    !l.split('/').skip(1).any(|seg| seg == "." || seg == "..")
}

/// Default deny. The only way a request is allowed is by matching a template admitted from a verified operation.
pub struct EgressPolicy {
    admissions: Vec<Admission>,
    now: Box<dyn Fn() -> f64 + Send>,
}

impl EgressPolicy {
    pub fn new(now: Box<dyn Fn() -> f64 + Send>) -> EgressPolicy {
        EgressPolicy { admissions: vec![], now }
    }

    /// Admit the request that `operation` maps to. `bound` is the operation an ALLOWING authorize result carries (`None` for a
    /// refusal); `to_request` maps the operation to a template. `Err` unless the result allows exactly `operation` and the
    /// template is well formed. `uses` (default 1) must be a positive integer.
    pub fn admit(
        &mut self,
        bound: Option<&AuthorizedOperation>,
        operation: &Operation,
        to_request: impl FnOnce(&Operation) -> Option<Value>,
        uses: Option<&Value>,
        expires_at: Option<f64>,
    ) -> Result<(), String> {
        let authorized = is_bound_for(bound, operation);
        if !authorized {
            return Err("not_authorized: result does not allow exactly this operation".into());
        }
        let t = to_request(operation).filter(|t| !t.is_null()).ok_or("no_egress_for_operation")?;
        let s = |k: &str| t.get(k).and_then(Value::as_str);
        let host = s("host").ok_or("bad_template_host")?;
        if !host_ok(host) || host != host.to_lowercase() {
            return Err("bad_template_host".into());
        }
        let scheme = match s("scheme") {
            Some(x @ ("http" | "https")) => x,
            _ => return Err("bad_template_scheme".into()),
        };
        let port = match t.get("port") {
            None | Some(Value::Null) => default_port(scheme),
            Some(Value::Number(n)) => match n.as_f64() {
                Some(f) if f == f.floor() && (1.0..=65535.0).contains(&f) => f as i64,
                _ => return Err("bad_template_port".into()),
            },
            Some(_) => return Err("bad_template_port".into()),
        };
        let method = s("method").filter(|m| !m.is_empty() && m.bytes().all(|c| c.is_ascii_uppercase())).ok_or("bad_template_method")?;
        let path = s("path").filter(|p| path_ok(p)).ok_or("bad_template_path")?;
        let uses = match uses.filter(|u| !u.is_null()) {
            None => 1.0,
            Some(Value::Number(n)) => match n.as_f64() {
                Some(f) if f == f.floor() && f >= 1.0 => f,
                _ => return Err("bad_uses".into()),
            },
            Some(_) => return Err("bad_uses".into()),
        };
        self.admissions.push(Admission {
            op_id: bound.map(|b| b.id.clone()).unwrap_or_default(),
            op: operation.clone(),
            method: method.into(),
            scheme: scheme.into(),
            host: host.into(),
            port,
            path: path.into(),
            path_prefix: t.get("path_prefix") == Some(&Value::Bool(true)),
            query: s("query").map(String::from),
            body_sha256: s("body_sha256").map(String::from),
            tunnel: t.get("tunnel") == Some(&Value::Bool(true)),
            uses,
            expires_at: expires_at.unwrap_or(f64::INFINITY),
        });
        Ok(())
    }

    /// Decide and, if allowed, spend one use of the matching admission. Anything not matched is denied with a reason.
    pub fn claim(&mut self, method: &str, url: &str, body: &[u8]) -> EgressDecision {
        let target = match parse_target(method, url) {
            Ok(t) => t,
            Err(r) => return deny(&r),
        };
        let mut why = "no_admission";
        let now = (self.now)();
        let body_hash = || crate::b64_encode(&Sha256::digest(body));
        for a in self.admissions.iter_mut() {
            if target.connect != a.tunnel {
                continue;
            }
            if !target.connect && (a.method != method.to_uppercase() || target.scheme != a.scheme) {
                continue;
            }
            if target.host != a.host || target.port != a.port {
                continue;
            }
            if !target.connect {
                let prefix = if a.path.ends_with('/') { a.path.clone() } else { format!("{}/", a.path) };
                let path_matches = if a.path_prefix { target.path == a.path || target.path.starts_with(&prefix) } else { target.path == a.path };
                if !path_matches {
                    continue;
                }
                if target.query != a.query.clone().unwrap_or_default() {
                    why = "query_mismatch";
                    continue;
                }
                if !body.is_empty() && a.body_sha256.as_deref() != Some(body_hash().as_str()) {
                    why = "body_mismatch";
                    continue;
                }
                if body.is_empty() && a.body_sha256.as_deref().is_some_and(|h| h != body_hash()) {
                    why = "body_mismatch";
                    continue;
                }
            }
            if a.uses < 1.0 || !(now.is_finite() && now < a.expires_at) {
                why = "spent"; // reported only when the request would otherwise have matched
                continue;
            }
            a.uses -= 1.0;
            return EgressDecision::Allow {
                op_id: a.op_id.clone(),
                verb: a.op.verb.clone(),
                resource: a.op.resource.clone(),
                params_digest: hash_canonical_strict(&a.op.params).unwrap_or_default(),
            };
        }
        deny(why)
    }
}

struct Target {
    connect: bool,
    scheme: String,
    host: String,
    port: i64,
    path: String,
    query: String,
}

/// `^([a-z0-9.-]+|\[[0-9a-f:]+\]):(\d{1,5})$` (case-insensitive): a CONNECT target.
fn parse_connect(url: &str) -> Option<(String, i64)> {
    let (host, port) = url.rsplit_once(':')?;
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let bare = if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        (!inner.is_empty() && inner.bytes().all(|c| c.is_ascii_hexdigit() || c == b':')).then_some(inner)?
    } else {
        (!host.is_empty() && host.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')).then_some(host)?
    };
    Some((bare.to_lowercase(), port.parse().ok()?))
}

fn parse_target(method: &str, url: &str) -> Result<Target, String> {
    if method.to_uppercase() == "CONNECT" {
        let (host, port) = parse_connect(url).ok_or("bad_connect_target")?;
        return Ok(Target { connect: true, scheme: "https".into(), host, port, path: String::new(), query: String::new() });
    }
    let u = url::Url::parse(url).map_err(|_| "not_absolute_url".to_string())?;
    if !matches!(u.scheme(), "http" | "https") || !u.username().is_empty() || u.password().is_some() || u.fragment().is_some_and(|f| !f.is_empty()) {
        return Err("bad_url".into());
    }
    // encoded dots and slashes are how a prefix match is walked out of: refuse rather than decode
    let lp = u.path().to_ascii_lowercase();
    if lp.contains("%2e") || lp.contains("%2f") || lp.contains("%5c") || lp.contains('\\') {
        return Err("encoded_path".into());
    }
    let scheme = u.scheme().to_string();
    let host = u.host_str().unwrap_or("").trim_start_matches('[').trim_end_matches(']').to_lowercase();
    let port = u.port().map(i64::from).unwrap_or_else(|| default_port(&scheme));
    Ok(Target { connect: false, scheme, host, port, path: u.path().to_string(), query: u.query().unwrap_or("").to_string() })
}
