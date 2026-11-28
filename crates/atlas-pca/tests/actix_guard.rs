//! Tests for the actix-web PCA guard (feature `actix`): the pure pipeline and the denial paths of the live middleware. The
//! allow path rides the same `verify_request` core the axum tests cover with signed conformance vectors.
#![cfg(feature = "actix")]

use actix_web::{test, web, App, FromRequest, HttpResponse};
use atlas_pca::actix::{guard_request, OperationInput, PcaGuard, PcaVerified};
use atlas_pca::middleware::GuardConfig;

fn cfg() -> GuardConfig {
    GuardConfig::new("rs-test", |_: &str| None).with_signature_only().with_insecure_skip_plan_root_check().with_clock(|| 1_000)
}

fn h(name: &str, v: &str) -> (String, Option<String>) {
    (name.to_string(), Some(v.to_string()))
}

#[test]
fn no_proof_is_401_with_a_challenge() {
    let r = guard_request(&cfg(), &[], None, OperationInput::Unmapped);
    assert!(!r.allow);
    assert_eq!(r.status, 401);
    assert_eq!(r.www_authenticate().unwrap(), "PCA realm=\"pca\", error=\"invalid_request\"");
}

#[test]
fn an_undecodable_proof_is_401_and_an_unreadable_one_too() {
    for hs in [vec![h("pca-action", "%%%")], vec![("pca-action".to_string(), None)]] {
        let r = guard_request(&cfg(), &hs, None, OperationInput::Unmapped);
        assert_eq!((r.allow, r.status), (false, 401));
    }
}

#[test]
fn a_mapped_but_unmapped_operation_never_allows() {
    let r = guard_request(&cfg(), &[h("pca-action", "e30")], None, OperationInput::Mapped(None));
    assert!(!r.allow);
}

#[test]
fn live_guard_denies_without_calling_the_handler() {
    actix_web::rt::System::new().block_on(async {
        let app = test::init_service(App::new().wrap(PcaGuard::new(cfg())).route("/", web::get().to(|| async { HttpResponse::Ok().finish() }))).await;
        let resp = test::call_service(&app, test::TestRequest::get().uri("/").to_request()).await;
        assert_eq!(resp.status().as_u16(), 401);
        assert!(resp.headers().get("www-authenticate").unwrap().to_str().unwrap().starts_with("PCA realm=\"pca\""));
        let resp = test::call_service(&app, test::TestRequest::get().uri("/").insert_header(("pca-action", "%%%")).to_request()).await;
        assert_eq!(resp.status().as_u16(), 401);
    });
}

#[test]
fn body_form_with_a_limit_denies_an_oversize_body_with_413() {
    actix_web::rt::System::new().block_on(async {
        let app =
            test::init_service(App::new().wrap(PcaGuard::new(cfg()).with_body_limit(4)).route("/", web::post().to(|| async { HttpResponse::Ok().finish() })))
                .await;
        let resp = test::call_service(&app, test::TestRequest::post().uri("/").set_payload("0123456789").to_request()).await;
        assert_eq!(resp.status().as_u16(), 413);
    });
}

#[test]
fn the_extractor_refuses_when_the_guard_is_absent() {
    actix_web::rt::System::new().block_on(async {
        let (req, mut pl) = test::TestRequest::get().to_http_parts();
        assert!(PcaVerified::from_request(&req, &mut pl).await.is_err());
    });
}
