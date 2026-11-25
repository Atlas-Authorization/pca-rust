//! The client of the grant management resource (packages/pca-grants/src/client.ts): list, inspect, amend, revoke and request / approve /
//! deny needs over `/pca/grants...`. It also carries the newest `fresh_at` consistency token it has seen and attaches it to later
//! requests (read-your-writes). The transport is injected, as everywhere in this crate.
use crate::fresh_at::verify_fresh_at;
use crate::grants::merge_fresh_at;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::fmt;

/// An error answer of the grant API (status >= 400): `{error, message}` of the body, or the status text.
#[derive(Debug, Clone, PartialEq)]
pub struct GrantApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl fmt::Display for GrantApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for GrantApiError {}

/// Every way a call can fail: the API answered an error, or the transport / the reply was unusable.
#[derive(Debug, Clone, PartialEq)]
pub enum GrantClientError {
    Api(GrantApiError),
    Transport(String),
}

impl fmt::Display for GrantClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GrantClientError::Api(e) => e.fmt(f),
            GrantClientError::Transport(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for GrantClientError {}

#[derive(Debug, Clone)]
pub struct GrantRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GrantResponse {
    pub status: u16,
    /// Response headers (names compared case-insensitively).
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub type GrantTransport = Box<dyn Fn(&GrantRequest) -> Result<GrantResponse, String>>;

pub struct GrantClientOptions {
    pub base_url: String,
    pub transport: GrantTransport,
    /// The AS's pinned token signer. When set, a `pca-fresh-at` header that does not verify is ignored.
    pub fresh_signer: Option<String>,
    /// Extra request headers (an authorization header, say), computed per call.
    pub headers: Option<Box<dyn Fn() -> Vec<(String, String)>>>,
}

impl GrantClientOptions {
    pub fn new(base_url: &str, transport: GrantTransport) -> Self {
        GrantClientOptions { base_url: base_url.into(), transport, fresh_signer: None, headers: None }
    }
}

pub struct GrantClient {
    o: GrantClientOptions,
    latest: RefCell<Option<Value>>,
}

/// `createGrantClient`.
pub fn create_grant_client(o: GrantClientOptions) -> GrantClient {
    GrantClient { o, latest: RefCell::new(None) }
}

fn enc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

fn num(t: &Value, k: &str) -> f64 {
    t.get(k).and_then(Value::as_f64).unwrap_or(f64::NAN)
}

impl GrantClient {
    fn call(&self, method: &'static str, path: &str, body: Option<Value>) -> Result<Value, GrantClientError> {
        let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
        if let Some(l) = &*self.latest.borrow() {
            headers.push(("pca-fresh-at".into(), l.to_string()));
        }
        if let Some(h) = &self.o.headers {
            headers.extend(h());
        }
        let req = GrantRequest { method, url: format!("{}{}", self.o.base_url.trim_end_matches('/'), path), headers, body: body.map(|b| b.to_string()) };
        let res = (self.o.transport)(&req).map_err(GrantClientError::Transport)?;
        if let Some((_, tok)) = res.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("pca-fresh-at")) {
            self.fold_header(tok);
        }
        let json: Value = serde_json::from_str(&res.body).unwrap_or_else(|_| json!({}));
        if !(200..300).contains(&res.status) {
            let s = |k: &str| json.get(k).and_then(Value::as_str).map(String::from);
            return Err(GrantClientError::Api(GrantApiError {
                status: res.status,
                code: s("error").unwrap_or_else(|| "error".into()),
                message: s("message").unwrap_or_default(),
            }));
        }
        Ok(json)
    }

    /// Fold a `pca-fresh-at` header: ignored when malformed or (with a pinned signer) unverified; never replaces a fresher token with an older one.
    fn fold_header(&self, tok: &str) {
        let Ok(t) = serde_json::from_str::<Value>(tok) else { return };
        if let Some(signer) = &self.o.fresh_signer {
            if !verify_fresh_at(&t, signer) {
                return;
            }
        }
        let mut latest = self.latest.borrow_mut();
        let newer = match &*latest {
            None => true,
            Some(l) => ["revocation_epoch", "policy_revision", "ledger_tree_size", "budget_version"].iter().all(|k| num(&t, k) >= num(l, k)),
        };
        if newer {
            *latest = Some(t);
        }
    }

    /// `list`: grants by `principal`, `agent`, `status`, `limit`, `cursor` (any subset, as an object).
    pub fn list(&self, q: &Value) -> Result<Value, GrantClientError> {
        let mut s = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in q.as_object().into_iter().flatten() {
            s.append_pair(k, &v.as_str().map(String::from).unwrap_or_else(|| v.to_string()));
        }
        let qs = s.finish();
        self.call("GET", &format!("/pca/grants{}", if qs.is_empty() { String::new() } else { format!("?{qs}") }), None)
    }

    pub fn inspect(&self, id: &str) -> Result<Value, GrantClientError> {
        self.call("GET", &format!("/pca/grants/{}", enc(id)), None)
    }

    pub fn amend(&self, id: &str, req: &Value) -> Result<Value, GrantClientError> {
        self.call("POST", &format!("/pca/grants/{}/amend", enc(id)), Some(req.clone()))
    }

    /// `revoke`: `scope` defaults to `grant` in the reference.
    pub fn revoke(&self, id: &str, scope: &str, sig: Option<&str>) -> Result<Value, GrantClientError> {
        self.call("DELETE", &format!("/pca/grants/{}?scope={scope}", enc(id)), sig.map(|s| json!({"sig": s})))
    }

    pub fn request_needs(&self, id: &str, needs: &Value) -> Result<Value, GrantClientError> {
        self.call("POST", &format!("/pca/grants/{}/needs", enc(id)), Some(json!({"needs": needs})))
    }

    pub fn approve_needs(&self, need_id: &str, approved: &Value, sig: &str, step_up_ref: Option<&str>) -> Result<Value, GrantClientError> {
        let mut b = json!({"approved": approved, "sig": sig});
        if let Some(r) = step_up_ref.filter(|r| !r.is_empty()) {
            b["step_up_ref"] = json!(r);
        }
        self.call("POST", &format!("/pca/needs/{}/approve", enc(need_id)), Some(b))
    }

    pub fn deny_needs(&self, need_id: &str) -> Result<Value, GrantClientError> {
        self.call("POST", &format!("/pca/needs/{}/deny", enc(need_id)), None)
    }

    /// The newest consistency token seen on any response: attach it to later requests to make them read-your-writes.
    pub fn fresh_at(&self) -> Option<Value> {
        self.latest.borrow().clone()
    }

    /// Fold the newest token into a `fresh_at` state (`None` when no token was seen yet).
    pub fn fold_fresh_at(&self, s: &Value) -> Option<Value> {
        self.latest.borrow().as_ref().and_then(|l| merge_fresh_at(l, s).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    fn client(replies: Vec<GrantResponse>, seen: Rc<RefCell<Vec<GrantRequest>>>) -> GrantClient {
        let q = RefCell::new(replies.into_iter());
        let mut o = GrantClientOptions::new(
            "https://as.example/",
            Box::new(move |r| {
                seen.borrow_mut().push(r.clone());
                q.borrow_mut().next().ok_or_else(|| "no reply".to_string())
            }),
        );
        o.headers = Some(Box::new(|| vec![("authorization".into(), "Bearer t".into())]));
        create_grant_client(o)
    }

    fn reply(status: u16, body: &str, fresh: Option<&str>) -> GrantResponse {
        GrantResponse { status, headers: fresh.map(|f| vec![("PCA-Fresh-At".to_string(), f.to_string())]).unwrap_or_default(), body: body.into() }
    }

    #[test]
    fn calls_paths_errors_and_the_monotone_fresh_at_fold() {
        let seen = Rc::new(RefCell::new(vec![]));
        let tok = |e: i64| json!({"revocation_epoch": e, "policy_revision": 1, "ledger_tree_size": 1, "budget_version": 1}).to_string();
        let (t5, t3) = (tok(5), tok(3));
        let c = client(
            vec![
                reply(200, r#"{"grants":[]}"#, Some(&t5)),
                reply(200, "{}", Some(&t3)),
                reply(404, r#"{"error":"not_found","message":"no such grant"}"#, None),
                reply(200, r#"{"revoked":["g"]}"#, None),
            ],
            seen.clone(),
        );
        assert_eq!(c.list(&json!({"principal": "p", "limit": 5})).unwrap(), json!({"grants": []}));
        assert_eq!(c.fresh_at().unwrap()["revocation_epoch"], 5);
        c.inspect("g/1").unwrap();
        assert_eq!(c.fresh_at().unwrap()["revocation_epoch"], 5, "an older token never replaces a fresher one");
        let e = c.amend("x", &json!({})).unwrap_err();
        assert_eq!(e, GrantClientError::Api(GrantApiError { status: 404, code: "not_found".into(), message: "no such grant".into() }));
        c.revoke("g", "grant", Some("sig")).unwrap();
        let s = seen.borrow();
        assert_eq!(s[0].url, "https://as.example/pca/grants?principal=p&limit=5");
        assert_eq!(s[1].url, "https://as.example/pca/grants/g%2F1");
        assert!(s[1].headers.iter().any(|(k, _)| k == "pca-fresh-at"), "the newest token rides on the next request");
        assert!(s[1].headers.iter().any(|(k, v)| k == "authorization" && v == "Bearer t"));
        assert_eq!((s[3].method, s[3].url.as_str(), s[3].body.as_deref()), ("DELETE", "https://as.example/pca/grants/g?scope=grant", Some(r#"{"sig":"sig"}"#)));
    }

    #[test]
    fn a_pinned_signer_ignores_an_unverified_token() {
        let seen = Rc::new(RefCell::new(vec![]));
        let mut c = client(vec![reply(200, "{}", Some(r#"{"revocation_epoch":9,"policy_revision":1,"ledger_tree_size":1,"budget_version":1}"#))], seen);
        c.o.fresh_signer = Some("someone".into());
        c.inspect("g").unwrap();
        assert!(c.fresh_at().is_none());
    }
}
