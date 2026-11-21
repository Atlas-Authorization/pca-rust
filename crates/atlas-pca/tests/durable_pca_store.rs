//! `durable_pca_state_store`: the replay / budget / pin store over an atomic key/value store (in memory, and over the crash-safe
//! durable state on Unix, where it is also shared between handles of one directory).

use std::sync::Arc;

use atlas_pca::durable_pca_store::durable_pca_state_store;
use atlas_pca::kv::{AtomicKv, MemoryAtomicKv};
use atlas_pca::serde_json::json;
use atlas_pca::{BudgetClaim, StateStore, StoreScope};

fn contract(s: &dyn StateStore) {
    assert!(s.claim("g:h", 1).unwrap().ok);
    let again = s.claim("g:h", 1).unwrap();
    assert!(!again.ok);
    assert_eq!(again.last_counter, Some(1), "a replay names the stored counter");
    assert!(!s.claim("g:h", 0).unwrap().ok, "a lower counter is a replay too");
    assert!(s.claim("g:h", 7).unwrap().ok);
    assert_eq!(s.last("g:h"), Some(Some(7)));
    assert_eq!(s.last("never"), Some(None));
    // budgets: the first claim stores one, a stale read conflicts, a replay never writes
    let b1 = json!({"B": 10.0, "tau": 1.0, "asOf": 1.0});
    let b2 = json!({"B": 6.0, "tau": 2.0, "asOf": 2.0});
    assert_eq!(s.claim_budgeted("m", 1, None, Some(&b1)).unwrap(), BudgetClaim::Claimed);
    assert_eq!(s.budget("m").unwrap(), Some(b1.clone()));
    assert_eq!(s.claim_budgeted("m", 2, None, Some(&b2)).unwrap(), BudgetClaim::Conflict, "the stored budget no longer equals what was read");
    assert_eq!(s.claim_budgeted("m", 1, Some(&b1), Some(&b2)).unwrap(), BudgetClaim::Replay(Some(1)));
    assert_eq!(s.budget("m").unwrap(), Some(b1.clone()), "neither refusal wrote");
    assert_eq!(s.claim_budgeted("m", 2, Some(&b1), Some(&b2)).unwrap(), BudgetClaim::Claimed);
    assert_eq!(s.budget("m").unwrap(), Some(b2.clone()));
    assert_eq!(s.claim_budgeted("m", 3, Some(&b2), None).unwrap(), BudgetClaim::Claimed, "no `after` keeps the stored budget");
    assert_eq!(s.budget("m").unwrap(), Some(b2));
    // pins only rise
    assert_eq!(s.pin("g:epoch").unwrap(), None);
    s.raise_pin("g:epoch", 5).unwrap();
    s.raise_pin("g:epoch", 3).unwrap();
    assert_eq!(s.pin("g:epoch").unwrap(), Some(5));
    s.raise_pin("g:epoch", 9).unwrap();
    assert_eq!(s.pin("g:epoch").unwrap(), Some(9));
    // a TTL'd consume-once
    assert!(s.consume_once("slot", 100, 10).unwrap());
    assert!(!s.consume_once("slot", 100, 50).unwrap(), "a live record refuses");
    assert!(s.consume_once("slot", 300, 200).unwrap(), "an elapsed record is forgotten");
    assert!(s.consume_once("", 100, 10).is_err());
    assert!(s.consume_once("x", 5, 10).is_err());
}

#[test]
fn the_store_contract_holds_over_the_memory_kv() {
    let s = durable_pca_state_store(Arc::new(MemoryAtomicKv::new()));
    assert_eq!(s.scope(), StoreScope::Shared);
    assert!(s.supports_pins());
    contract(&s);
}

#[test]
fn prefix_and_scope_are_configurable_and_namespaces_do_not_collide() {
    let kv: Arc<dyn AtomicKv> = Arc::new(MemoryAtomicKv::new());
    let a = durable_pca_state_store(kv.clone()).with_prefix("a:").with_scope(StoreScope::Process);
    let b = durable_pca_state_store(kv.clone()).with_prefix("b:");
    assert_eq!(a.scope(), StoreScope::Process);
    assert!(a.claim("k", 1).unwrap().ok);
    assert!(b.claim("k", 1).unwrap().ok, "another prefix is another stream");
    assert!(kv.get("a:k").unwrap().is_some() && kv.get("b:k").unwrap().is_some());
}

#[cfg(unix)]
#[test]
fn the_store_over_the_durable_state_survives_a_reopen_and_is_shared_between_handles() {
    use atlas_pca::durable_state::{open_durable_state, DurableStateOptions};
    let d = std::env::temp_dir().join(format!("pca-dps-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let open = || Arc::new(open_durable_state(DurableStateOptions::new(&d)).unwrap());
    {
        let s = durable_pca_state_store(open());
        contract(&s);
    }
    let again = durable_pca_state_store(open());
    assert!(!again.claim("g:h", 7).unwrap().ok, "the counter survived the restart");
    assert!(again.claim("g:h", 8).unwrap().ok);
    let other = durable_pca_state_store(open());
    assert!(!other.claim("g:h", 8).unwrap().ok, "a second handle of the same directory sees the first one's claim");
    let _ = std::fs::remove_dir_all(&d);
}
