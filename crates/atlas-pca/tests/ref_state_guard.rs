//! The replay-state profile through the real guard, including child processes: the SQLite store shared by this test binary
//! re-executing itself.
#![cfg(feature = "sqlite")]
use atlas_pca::store_conformance::guard::{run_worker_if_requested, ProcessSpec};
use atlas_pca::store_conformance::*;
use atlas_pca::{SqliteStateStore, StateStore};
use std::sync::Arc;

const DB_ENV: &str = "ATLAS_PCA_TEST_STATE_DB";

#[test]
fn sqlite_state_store_passes_across_processes() {
    if let Ok(path) = std::env::var(DB_ENV) {
        let open = move || Arc::new(SqliteStateStore::open(&path).expect("open")) as Arc<dyn StateStore>;
        if run_worker_if_requested(&open) {
            return;
        }
    }
    let path = std::env::temp_dir().join(format!("atlas-pca-state-guard-{}.db", std::process::id()));
    let p = path.clone();
    let open = move || Arc::new(SqliteStateStore::open(&p).expect("open")) as Arc<dyn StateStore>;
    let mut spec = ProcessSpec::new(std::env::current_exe().expect("exe"), vec!["--exact".into(), "sqlite_state_store_passes_across_processes".into(), "--nocapture".into()]);
    spec.env.push((DB_ENV.into(), path.to_string_lossy().into_owned()));
    let report = run_state_store_conformance_with(&open, &Options { rounds: 3, copies: 8, durable: true }, Some(&spec));
    report.assert_passed();
    for t in ["one-instance", "instances", "processes", "crash-after-claim-process"] {
        assert!(report.tests.iter().any(|r| r.test == t && r.status == Status::Pass), "{t} missing or not passed: {report:?}");
    }
    let _ = std::fs::remove_file(&path);
}
