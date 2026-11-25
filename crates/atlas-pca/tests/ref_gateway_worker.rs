//! The Cloudflare Worker adapter of the gateway: URL parsing, deny responses, forged `x-pca-*` header handling on an allowed route.
use atlas_pca::gateway::*;
use std::sync::Arc;

fn gw() -> Gateway {
    let mut o = GatewayOptions::default();
    o.audience = "https://api.example".into();
    o.policy = Some(Policy::SignatureOnly);
    o.replay_guard = Some(Arc::new(MemoryReplayGuard::with_system_clock(10)));
    o.require_checks = Some(vec![]);
    o.unmatched_route = Some("allow".into());
    create_gateway(o).expect("gateway")
}

fn req(url: &str, headers: &[(&str, &str)]) -> WorkerRequest {
    WorkerRequest { method: "GET".into(), url: url.into(), headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), body: None }
}

#[test]
fn allowed_request_loses_forged_pca_headers() {
    let r = req("https://api.example/x?a=1#f", &[("X-PCA-Verdict", "pass"), ("accept", "*/*")]);
    match gw().cloudflare_worker(r.clone(), true) {
        WorkerOutcome::Forward(c) => assert_eq!(c.headers, vec![("accept".to_string(), "*/*".to_string())]),
        o => panic!("{o:?}"),
    }
    match gw().cloudflare_worker(r, false) {
        WorkerOutcome::Respond { status, body, .. } => {
            assert_eq!(status, 400);
            assert!(body.contains("forged-pca-header"));
        }
        o => panic!("{o:?}"),
    }
}

#[test]
fn clean_request_is_forwarded_unchanged() {
    match gw().cloudflare_worker(req("https://api.example", &[("accept", "*/*")]), true) {
        WorkerOutcome::Forward(c) => assert_eq!(c.headers.len(), 1),
        o => panic!("{o:?}"),
    }
}

#[test]
fn unmatched_route_default_denies() {
    let mut o = GatewayOptions::default();
    o.audience = "https://api.example".into();
    o.policy = Some(Policy::SignatureOnly);
    o.replay_guard = Some(Arc::new(MemoryReplayGuard::with_system_clock(10)));
    o.require_checks = Some(vec![]);
    let g = create_gateway(o).expect("gateway");
    match g.cloudflare_worker(req("https://api.example/x", &[]), true) {
        WorkerOutcome::Respond { status, headers, body } => {
            assert!(status == 401 || status == 403, "{status}");
            assert_eq!(headers[0], ("content-type".to_string(), "application/json".to_string()));
            assert!(body.starts_with("{\"error\":"));
        }
        o => panic!("{o:?}"),
    }
}
