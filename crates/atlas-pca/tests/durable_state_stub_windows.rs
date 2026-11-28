//! The non-Unix durable-state stub (src/durable_state_stub.rs): it compiles only off Unix, so the Linux gate never runs it.
#![cfg(not(unix))]
use atlas_pca::durable_state::*;

#[test]
fn every_code_has_its_reference_name() {
    let all = [
        (DurableStateErrorCode::Corrupt, "corrupt"),
        (DurableStateErrorCode::Rollback, "rollback"),
        (DurableStateErrorCode::LockTimeout, "lock-timeout"),
        (DurableStateErrorCode::LockLost, "lock-lost"),
        (DurableStateErrorCode::LinkUnsupported, "link-unsupported"),
        (DurableStateErrorCode::KeyMismatch, "key-mismatch"),
        (DurableStateErrorCode::Invalid, "invalid"),
        (DurableStateErrorCode::TooLarge, "too-large"),
        (DurableStateErrorCode::Io, "io"),
    ];
    for (c, n) in all {
        assert_eq!(c.as_str(), n);
    }
}

#[test]
fn an_error_message_is_code_colon_detail_and_displays_as_such() {
    let e = DurableStateError::new(DurableStateErrorCode::Corrupt, "bad");
    assert_eq!(e.code, DurableStateErrorCode::Corrupt);
    assert_eq!(e.message, "corrupt: bad");
    assert_eq!(e.to_string(), "corrupt: bad");
}

#[test]
fn open_and_recover_refuse_with_link_unsupported() {
    let d = std::env::temp_dir().join(format!("stub-{}", std::process::id()));
    for e in [open_durable_state(&d).unwrap_err(), recover_durable_state(&d).unwrap_err()] {
        assert_eq!(e.code, DurableStateErrorCode::LinkUnsupported);
        assert!(e.message.starts_with("link-unsupported: this platform has no stable link-count API"));
    }
    assert!(!d.exists(), "a refusal creates nothing");
}
