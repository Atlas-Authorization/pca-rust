//! Feature `sqlite`: the durable state store holds revocation-epoch pins and trust budgets atomically with the counter, and they
//! survive a restart.
#![cfg(feature = "sqlite")]

use atlas_pca::{BudgetClaim, SqliteStateStore, StateStore, StoreScope};
use serde_json::{json, Value};

fn path(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("pca-state-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join("state.db")
}

fn budget(b: f64) -> Value {
    json!({"B": b, "tau": 0, "asOf": 0})
}

#[test]
fn pins_are_monotone_and_durable() {
    let p = path("pins");
    let s = SqliteStateStore::open(&p).unwrap();
    assert_eq!(s.scope(), StoreScope::Shared);
    assert!(s.supports_pins());
    assert_eq!(s.pin("g:epoch").unwrap(), None);
    s.raise_pin("g:epoch", 5).unwrap();
    s.raise_pin("g:epoch", 3).unwrap();
    assert_eq!(s.pin("g:epoch").unwrap(), Some(5), "a pin never lowers");
    s.raise_pin("g:epoch", 7).unwrap();
    drop(s);
    let again = SqliteStateStore::open(&p).unwrap();
    assert_eq!(again.pin("g:epoch").unwrap(), Some(7), "the pin survives a restart");
    assert_eq!(again.pin("other:epoch").unwrap(), None);
}

#[test]
fn the_budget_and_the_counter_move_together() {
    let p = path("budget");
    let s = SqliteStateStore::open(&p).unwrap();
    assert_eq!(s.budget("k").unwrap(), None);
    assert_eq!(s.claim_budgeted("k", 1, None, Some(&budget(0.8))).unwrap(), BudgetClaim::Claimed);
    assert_eq!(s.budget("k").unwrap(), Some(budget(0.8)));
    assert_eq!(s.last("k"), Some(Some(1)));
    assert_eq!(s.claim_budgeted("k", 2, None, Some(&budget(0.5))).unwrap(), BudgetClaim::Conflict, "a stale read");
    assert_eq!(s.budget("k").unwrap(), Some(budget(0.8)));
    assert_eq!(s.last("k"), Some(Some(1)), "a conflict does not consume the counter");
    assert_eq!(s.claim_budgeted("k", 2, Some(&budget(0.8)), Some(&budget(0.5))).unwrap(), BudgetClaim::Claimed);
    assert_eq!(s.claim_budgeted("k", 2, Some(&budget(0.5)), Some(&budget(0.1))).unwrap(), BudgetClaim::Replay(Some(2)));
    assert_eq!(s.claim_budgeted("k", 3, Some(&budget(0.5)), None).unwrap(), BudgetClaim::Claimed);
    assert_eq!(s.budget("k").unwrap(), Some(budget(0.5)));
    drop(s);
    let again = SqliteStateStore::open(&p).unwrap();
    assert_eq!(again.budget("k").unwrap(), Some(budget(0.5)), "the budget survives a restart");
    assert_eq!(again.last("k"), Some(Some(3)));
}
