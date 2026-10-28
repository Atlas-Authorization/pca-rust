//! A minimal resource server: `POST /refunds` runs only for a request that carries a proof for exactly that operation.
use atlas_pca::middleware::Capability;
use atlas_pca::protect::{protect, ProtectOptions, Protected};
use atlas_pca::Operation;
use axum::http::request::Parts;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};

/// The verb and resource this route executes. The agent signs exactly these; the proof is refused for any other.
pub const VERB: &str = "payments.send";
pub const RESOURCE: &str = "payments/acme";

/// The request -> operation mapping, from the route and the parsed body, never from the proof.
pub fn refund_operation(parts: &Parts, body: &[u8]) -> Option<Operation> {
    if parts.uri.path() != "/refunds" {
        return None;
    }
    let params: Value = serde_json::from_slice(body).ok()?;
    Some(Operation::new(VERB, RESOURCE, params))
}

/// The default-deny guard for this server: grants come from the list, never the request.
pub fn guard(audience: &str, grants: Vec<Capability>) -> Protected {
    protect(ProtectOptions::new(audience, grants, refund_operation))
}

/// The router around a guard (use [`guard`], or `protect` with your own options).
pub fn app(p: &Protected) -> Router {
    Router::new().route("/refunds", post(refund)).layer(p.layer())
}

// Reached only after the proof verified for this exact body.
async fn refund(Json(body): Json<Value>) -> Json<Value> {
    Json(json!({ "refunded": body["amount"], "currency": body["currency"] }))
}
