//! `protect()`: the secure defaults for an axum resource server, in one call (feature `axum`). The Rust counterpart of
//! `protect()` in `@atlasauth/pca`.
//!
//! ```ignore
//! let p = protect(ProtectOptions::new("ins_acme", vec![grant], |parts, body| {
//!     Some(Operation::new("stripe.refund", "charge:ch_1", params_from(body)))
//! }));
//! let app = Router::new().route("/refunds", post(handler)).layer(p.layer());
//! p.revoker.revoke(&grant_id); // later: every action under that grant is refused
//! ```
//!
//! It fills in the parts every server otherwise wires by hand, and nothing else: the grant lookup (your own list or
//! function, never the request), an in-memory replay store (pass your own with [`ProtectOptions::state_store`] for more than
//! one process), a revocation source, and `plan: single-step` (the grant alone limits what runs). Everything is still
//! [`crate::authorize`]: bound to the operation your route executes, default-deny. An option you pass wins over the default.
//!
//! Not included: the TypeScript `protect()` also prices risk from the connector catalog (`catalogRisk`). This crate has no
//! catalog, so risk-priced policies need their inputs through [`ProtectOptions::tune`].

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use axum::http::request::Parts;
use serde_json::Value;

use crate::middleware::{Capability, GuardConfig, PcaLayer};
use crate::{AuthorizeOptions, MemoryStateStore, Operation, StateStore, SINGLE_STEP};

type Resolver = Arc<dyn Fn(&str) -> Option<Capability> + Send + Sync>;
type OperationFn = Arc<dyn Fn(&Parts, &[u8]) -> Option<Operation> + Send + Sync>;
type RevokedFn = Arc<dyn Fn(&Value, &Value) -> Result<bool, String> + Send + Sync>;
type TuneFn = Box<dyn FnOnce(AuthorizeOptions) -> AuthorizeOptions>;

/// What [`protect`] needs: the audience, where grants come from and how a request maps to its operation.
pub struct ProtectOptions {
    audience: String,
    resolver: Resolver,
    operation: OperationFn,
    state_store: Option<Arc<dyn StateStore>>,
    is_revoked: Option<RevokedFn>,
    clock: Option<Arc<dyn Fn() -> i64 + Send + Sync>>,
    tune: Option<TuneFn>,
}

impl ProtectOptions {
    /// The grants this server accepts, looked up by `id` (a proof's `grant_ref`). `operation` maps a request (head and
    /// buffered body) to the operation the handler will execute, from your routing and parsed input, never from the proof.
    pub fn new(audience: impl Into<String>, grants: Vec<Capability>, operation: impl Fn(&Parts, &[u8]) -> Option<Operation> + Send + Sync + 'static) -> Self {
        Self::with_resolver(
            audience,
            move |grant_ref| grants.iter().find(|g| g.get("id").and_then(Value::as_str) == Some(grant_ref)).cloned(),
            operation,
        )
    }

    /// Like [`ProtectOptions::new`] with a function from `grant_ref` to the grant (your store).
    pub fn with_resolver(
        audience: impl Into<String>,
        resolver: impl Fn(&str) -> Option<Capability> + Send + Sync + 'static,
        operation: impl Fn(&Parts, &[u8]) -> Option<Operation> + Send + Sync + 'static,
    ) -> Self {
        ProtectOptions { audience: audience.into(), resolver: Arc::new(resolver), operation: Arc::new(operation), state_store: None, is_revoked: None, clock: None, tune: None }
    }

    /// Your replay store (default: in memory, correct for one process only).
    pub fn state_store(mut self, store: Arc<dyn StateStore>) -> Self {
        self.state_store = Some(store);
        self
    }

    /// An extra revocation source, consulted in addition to [`Revoker::revoke`] (`Ok(true)` = revoked).
    pub fn is_revoked(mut self, f: impl Fn(&Value, &Value) -> Result<bool, String> + Send + Sync + 'static) -> Self {
        self.is_revoked = Some(Arc::new(f));
        self
    }

    /// The clock in epoch milliseconds (default: the system clock).
    pub fn clock(mut self, f: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Some(Arc::new(f));
        self
    }

    /// Adjust the [`AuthorizeOptions`] after the defaults are set (plan mode, context, required checks, staleness ...).
    pub fn tune(mut self, f: impl FnOnce(AuthorizeOptions) -> AuthorizeOptions + 'static) -> Self {
        self.tune = Some(Box::new(f));
        self
    }
}

/// Revokes grants by id. Clones share one set; a revoked id is refused on its next request.
#[derive(Clone, Default)]
pub struct Revoker(Arc<Mutex<HashSet<String>>>);

impl Revoker {
    /// Refuse every further action under this grant id.
    pub fn revoke(&self, grant_id: &str) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).insert(grant_id.to_string());
    }

    /// Whether the id was revoked. A poisoned lock counts as revoked (fail closed).
    pub fn is_revoked(&self, grant_id: &str) -> bool {
        self.0.lock().map(|s| s.contains(grant_id)).unwrap_or(true)
    }
}

/// The result of [`protect`].
pub struct Protected {
    /// The guard configuration: pass to [`PcaLayer::new`], `from_fn_with_state(config, pca_guard)` or [`Protected::layer`].
    pub config: GuardConfig,
    /// Revoke a grant by id.
    pub revoker: Revoker,
}

impl Protected {
    /// A tower layer for an axum route or router.
    pub fn layer(&self) -> PcaLayer {
        PcaLayer::new(self.config.clone())
    }
}

/// Build the default-deny guard described in the module docs.
pub fn protect(o: ProtectOptions) -> Protected {
    let revoker = Revoker::default();
    let seen = revoker.clone();
    let extra = o.is_revoked;
    let hook = move |pcactn: &Value, grant: &Value| -> Result<bool, String> {
        // a grant with no readable id cannot be looked up in the revoked set: refuse it
        match grant.get("id").and_then(Value::as_str) {
            Some(id) if !seen.is_revoked(id) => {}
            _ => return Ok(true),
        }
        match &extra {
            Some(f) => f(pcactn, grant),
            None => Ok(false),
        }
    };
    let store = o.state_store.unwrap_or_else(|| Arc::new(MemoryStateStore::new()));
    let mut opts = AuthorizeOptions::new(store, hook).with_plan(Some(SINGLE_STEP));
    if let Some(t) = o.tune {
        opts = t(opts);
    }
    let (resolver, operation) = (o.resolver, o.operation);
    let mut config = GuardConfig::new(o.audience, move |r| resolver(r)).with_authorize(opts).with_operation(move |p, b| operation(p, b));
    if let Some(c) = o.clock {
        config = config.with_clock(move || c());
    }
    Protected { config, revoker }
}
