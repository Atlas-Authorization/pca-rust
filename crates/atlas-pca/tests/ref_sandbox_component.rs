//! The component host: pin logic, JSON-lines protocol against a fake host, and (when PCA_WASMTIME_HOST_BIN and
//! PCA_WASMTIME_HOST_SHA256 name a built reference host) real runs.
use atlas_pca::sandbox_component::*;
use atlas_pca::sandbox_handles::*;
use atlas_pca::sandbox_receipts::ReceiptLog;
use atlas_pca::sandbox_reference::reference_component_wat;
use atlas_pca::serde_json::json;
use atlas_pca::{AuthorizedOperation, Operation};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn sha(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn table() -> Arc<Mutex<HandleTable>> {
    let mut ex: HashMap<String, Executor> = HashMap::new();
    ex.insert("fs.read".into(), Box::new(|_| Ok(vec![5, 6])));
    let mut t = HandleTable::new("wasi_no_ambient", ReceiptLog::new(None, None), ex, None);
    let params = json!({});
    let bound = AuthorizedOperation {
        verb: "fs.read".into(),
        resource: "/x".into(),
        params_digest: atlas_pca::hash_canonical_strict(&params).unwrap(),
        id: "op".into(),
    };
    t.mint(
        Some(&bound),
        &Operation::new("fs.read", "/x", params),
        &MintOptions::default(),
    )
    .unwrap();
    Arc::new(Mutex::new(t))
}

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("pca-comp-test-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[cfg(unix)]
fn fake(tag: &str, body: &str) -> HostBinary {
    use std::os::unix::fs::PermissionsExt;
    let p = dir(tag).join("host.sh");
    let script = format!("#!/bin/sh\n{body}\n");
    std::fs::write(&p, &script).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    HostBinary {
        path: p.to_string_lossy().into(),
        expected_sha256: sha(script.as_bytes()),
    }
}

#[test]
fn pin_refusals() {
    let t = table();
    let o = ComponentOptions::new(1000);
    let missing = HostBinary {
        path: "/nonexistent/pca-wasmtime-host".into(),
        expected_sha256: "a".repeat(64),
    };
    assert_eq!(
        run_component(&t, b"x", &missing, &o),
        Err("host_missing".into())
    );
    let unpinned = HostBinary {
        path: "/bin/sh".into(),
        expected_sha256: String::new(),
    };
    assert_eq!(
        run_component(&t, b"x", &unpinned, &o),
        Err("host_unpinned".into())
    );
    let wrong = HostBinary {
        path: "/bin/sh".into(),
        expected_sha256: "0".repeat(64),
    };
    assert_eq!(
        run_component(&t, b"x", &wrong, &o),
        Err("host_hash_mismatch".into())
    );
    assert_eq!(
        run_component(&t, b"x", &wrong, &ComponentOptions::new(0)),
        Err("bad_fuel".into())
    );
}

#[cfg(unix)]
#[test]
fn protocol_against_fake_host() {
    let t = table();
    // count -> reply, invoke(1) -> reply, then done
    let h = fake("proto", "printf '{\"op\":\"count\"}\\n'; read a; printf '{\"op\":\"invoke\",\"h\":1}\\n'; read b; case \"$b\" in *\"[5,6]\"*) printf '{\"done\":5,\"fuel_used\":1}\\n';; *) printf '{\"fail\":\"bad_reply\"}\\n';; esac");
    assert_eq!(
        run_component(&t, b"x", &h, &ComponentOptions::new(1000)),
        Ok(5)
    );
    // the use is spent: a second run gets err -2 (spent) and the fake reports bad_reply
    assert_eq!(
        run_component(&t, b"x", &h, &ComponentOptions::new(1000)),
        Err("bad_reply".into())
    );
}

#[cfg(unix)]
#[test]
fn hung_host_is_killed_and_garbage_is_refused() {
    let t = table();
    let hang = fake("hang", "read a");
    let mut o = ComponentOptions::new(1000);
    o.timeout_ms = 200;
    assert_eq!(run_component(&t, b"x", &hang, &o), Err("timeout".into()));
    let junk = fake("junk", "echo not-json");
    assert_eq!(
        run_component(&t, b"x", &junk, &ComponentOptions::new(1000)),
        Err("host_protocol".into())
    );
    let quiet = fake("quiet", "exit 0");
    assert_eq!(
        run_component(&t, b"x", &quiet, &ComponentOptions::new(1000)),
        Err("host_exit".into())
    );
    let fail = fake("fail", "echo '{\"fail\":\"fuel_exhausted\"}'");
    assert_eq!(
        run_component(&t, b"x", &fail, &ComponentOptions::new(1000)),
        Err("fuel_exhausted".into())
    );
}

fn real() -> Option<HostBinary> {
    let (p, h) = (
        std::env::var("PCA_WASMTIME_HOST_BIN").ok()?,
        std::env::var("PCA_WASMTIME_HOST_SHA256").ok()?,
    );
    Some(HostBinary {
        path: p,
        expected_sha256: h,
    })
}

#[test]
fn real_host_limits() {
    let Some(host) = real() else {
        assert!(
            std::env::var("CI").unwrap_or_default().is_empty(),
            "CI must export PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256"
        );
        eprintln!("skipped: PCA_WASMTIME_HOST_BIN / PCA_WASMTIME_HOST_SHA256 not set");
        return;
    };
    let wat = reference_component_wat(None);
    assert_eq!(
        run_component(
            &table(),
            wat.as_bytes(),
            &host,
            &ComponentOptions::new(1_000_000)
        ),
        Ok(5)
    );
    let spin = reference_component_wat(Some(&json!({"spin": true})));
    assert_eq!(
        run_component(
            &table(),
            spin.as_bytes(),
            &host,
            &ComponentOptions::new(10_000)
        ),
        Err("fuel_exhausted".into())
    );
    let amb = reference_component_wat(Some(&json!({"extraImport": "wasi:cli/environment@0.2.0"})));
    assert_eq!(
        run_component(
            &table(),
            amb.as_bytes(),
            &host,
            &ComponentOptions::new(1_000_000)
        ),
        Err("ambient_import:wasi:cli/environment@0.2.0".into())
    );
}

#[test]
fn real_host_core_mode() {
    let Some(host) = real() else {
        assert!(
            std::env::var("CI").unwrap_or_default().is_empty(),
            "CI must export PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256"
        );
        return;
    };
    use atlas_pca::sandbox_reference::build_tool;
    let m = build_tool(&json!({"calls": [{"handle": 1, "ptr": 0, "cap": 16}], "returns": "byte0"}))
        .unwrap();
    assert_eq!(
        run_core_subprocess(&table(), &m, &host, 1_000_000, 256, 5000, "run"),
        Ok(5)
    );
    let spin = build_tool(&json!({"calls": [], "spin": true})).unwrap();
    assert_eq!(
        run_core_subprocess(&table(), &spin, &host, 10_000, 256, 5000, "run"),
        Err("fuel_exhausted".into())
    );
}
