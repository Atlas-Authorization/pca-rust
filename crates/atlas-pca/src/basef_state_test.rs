//! H15 (strict): lease and break-glass state lives in the REQUIRED key-value store, so a second registry over the same store sees the
//! first one's revocations, uses and reviews; a store that fails is `store_unreachable`. F5: revocation pruning past the ceiling.
use super::*;
use crate::agent::KeyPair;
use crate::authorize::StoreError;
use crate::break_glass::{BreakGlassPolicy, BreakGlassRegistry, BREAK_GLASS_DOMAIN, BREAK_GLASS_REVIEW_DOMAIN};
use crate::kv::{AtomicKv, MemoryAtomicKv};
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;

/// A store that delegates to memory until `down` is set, then fails every call.
struct FlakyKv {
    inner: MemoryAtomicKv,
    down: AtomicBool,
}
impl FlakyKv {
    fn new() -> Arc<FlakyKv> {
        Arc::new(FlakyKv { inner: MemoryAtomicKv::new(), down: AtomicBool::new(false) })
    }
    fn fail(&self) -> Result<(), StoreError> {
        if self.down.load(Ordering::SeqCst) {
            Err(StoreError("down".into()))
        } else {
            Ok(())
        }
    }
}
impl AtomicKv for FlakyKv {
    fn get(&self, key: &str) -> Result<Option<Value>, StoreError> {
        self.fail()?;
        self.inner.get(key)
    }
    fn update(&self, key: &str, f: &mut dyn FnMut(Option<&Value>) -> Option<Value>) -> Result<Option<Value>, StoreError> {
        self.fail()?;
        self.inner.update(key, f)
    }
}

fn signed_with(k: &KeyPair, domain: &str, mut body: Value) -> Value {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let sig = k.sign(&crate::fresh_at::domain_bytes(domain, &body).unwrap());
    body["sig"] = json!(URL_SAFE_NO_PAD.encode(sig));
    body
}

fn lease(k: &KeyPair, patch: Value) -> Value {
    let mut body = json!({"v": 1, "lease_id": "l1", "path": "a/b", "grant_ref": "g", "holder": "h", "requester": "q", "approvers": ["ap"], "justification_digest": "j1", "seq": 1, "issued_at": 1000, "renewed_at": 1000, "expires_at": 2000, "max_ttl": 10000, "authority": k.public});
    for (key, x) in patch.as_object().unwrap() {
        body[key.as_str()] = x.clone();
    }
    signed_with(k, LEASE_DOMAIN, body)
}

fn renewal(k: &KeyPair, digest: &str) -> Value {
    lease(k, json!({"seq": 2, "renewed_at": 1500, "expires_at": 3000, "justification_digest": digest}))
}

fn lease_revocation(k: &KeyPair, value: &str, at: i64) -> Value {
    signed_with(k, LEASE_REVOKE_DOMAIN, json!({"v": 1, "target": "lease", "value": value, "revoked_at": at, "authority": k.public}))
}

fn registry(k: &KeyPair, kv: Arc<dyn AtomicKv>) -> LeaseRegistry {
    LeaseRegistry::new(LeasePolicy::new(vec![k.public.clone()]), kv)
}

#[test]
fn a_second_registry_over_the_same_store_sees_the_revocation_and_the_lease() {
    let k = KeyPair::from_seed(&[1u8; 32]);
    let kv: Arc<dyn AtomicKv> = Arc::new(MemoryAtomicKv::new());
    let (one, two) = (registry(&k, kv.clone()), registry(&k, kv));
    let first = lease(&k, json!({}));
    assert_eq!(one.accept(&first, &[]), Ok((true, 1)));
    assert_eq!(two.get("l1"), Ok(Some(first.clone())), "the other registry reads the same record");
    // a renewal accepted through the second registry advances the first one's view
    assert_eq!(two.accept(&renewal(&k, "j2"), &[]), Ok((true, 2)));
    assert_eq!(one.get("l1").unwrap().unwrap()["seq"], 2);
    assert_eq!(one.history("l1").unwrap().len(), 2);
    // the revocation written through one registry refuses the seq-1 record presented to a fresh registry
    assert_eq!(one.revoke(&lease_revocation(&k, "l1", 5000)), Ok(1));
    let fresh = registry(&k, Arc::clone(&one.kv));
    assert_eq!(fresh.accept(&first, &[]), Err("revoked"));
    assert_eq!(check_lease(&renewal(&k, "j2"), &fresh, &json!(1600)).code, Some("revoked"));
}

#[test]
fn a_failing_store_is_store_unreachable_everywhere() {
    let k = KeyPair::from_seed(&[1u8; 32]);
    let kv = FlakyKv::new();
    let reg = registry(&k, kv.clone());
    assert_eq!(reg.accept(&lease(&k, json!({})), &[]), Ok((true, 1)));
    kv.down.store(true, Ordering::SeqCst);
    assert_eq!(reg.accept(&renewal(&k, "j2"), &[]), Err("store_unreachable"));
    assert_eq!(reg.revoke(&lease_revocation(&k, "l1", 5000)), Err("store_unreachable"));
    assert!(reg.get("l1").is_err());
    let d = check_lease(&lease(&k, json!({})), &reg, &json!(1500));
    assert_eq!((d.decision, d.code, d.lease_id.as_deref()), ("deny", Some("store_unreachable"), Some("l1")));
    // a registry that never reached the store: the very first call is refused
    let cold = registry(&k, kv.clone());
    assert_eq!(cold.accept(&lease(&k, json!({})), &[]), Err("store_unreachable"));
    kv.down.store(false, Ordering::SeqCst);
    assert_eq!(cold.accept(&renewal(&k, "j2"), &[]), Ok((true, 2)));
}

#[test]
fn the_shard_count_is_pinned_in_the_store() {
    let k = KeyPair::from_seed(&[1u8; 32]);
    let kv: Arc<dyn AtomicKv> = Arc::new(MemoryAtomicKv::new());
    let four = registry(&k, kv.clone()).with_shards(4);
    assert_eq!(four.shard_count(), 4);
    assert_eq!(four.accept(&lease(&k, json!({})), &[]), Ok((true, 1)));
    let eight = registry(&k, kv.clone()).with_shards(8);
    assert_eq!(eight.accept(&renewal(&k, "j2"), &[]), Err("store_unreachable"), "another count would hide the existing leases");
    assert!(eight.get("l1").is_err());
    assert_eq!(registry(&k, kv).with_shards(4).get("l1").unwrap().unwrap()["seq"], 1);
}

#[test]
fn shards_are_one_to_4096() {
    let k = KeyPair::from_seed(&[1u8; 32]);
    for ok in [1usize, 4096] {
        assert_eq!(registry(&k, Arc::new(MemoryAtomicKv::new())).with_shards(ok).shard_count(), ok);
    }
    for bad in [0usize, 4097] {
        assert!(std::panic::catch_unwind(|| registry(&KeyPair::from_seed(&[1u8; 32]), Arc::new(MemoryAtomicKv::new())).with_shards(bad)).is_err(), "{bad}");
    }
    assert_eq!(shard_of("any", 1), 0);
    assert!((0..100).all(|i| shard_of(&format!("lease-{i}"), 16) < 16));
    // sha256("l1")[..4] mod 16, pinned so a port that hashes differently is caught
    assert_eq!(shard_of("l1", 16), 6);
}

#[test]
fn two_concurrent_renewals_one_wins() {
    let k = KeyPair::from_seed(&[1u8; 32]);
    let reg = Arc::new(registry(&k, Arc::new(MemoryAtomicKv::new())));
    assert_eq!(reg.accept(&lease(&k, json!({})), &[]), Ok((true, 1)));
    let (a, b) = (renewal(&k, "ja"), renewal(&k, "jb"));
    let results: Vec<_> = std::thread::scope(|s| {
        let ha = s.spawn(|| reg.accept(&a, &[]));
        let hb = s.spawn(|| reg.accept(&b, &[]));
        vec![ha.join().unwrap(), hb.join().unwrap()]
    });
    assert_eq!(results.iter().filter(|r| **r == Ok((true, 2))).count(), 1, "{results:?}");
    assert_eq!(results.iter().filter(|r| **r == Err("lease_fork")).count(), 1, "{results:?}");
    assert_eq!(reg.history("l1").unwrap().len(), 2);
}

#[test]
fn a_revocation_is_pruned_once_revoked_at_plus_the_ceiling_is_past() {
    let k = KeyPair::from_seed(&[1u8; 32]);
    let revoke_at_clock = |now: i64| {
        let mut p = LeasePolicy::new(vec![k.public.clone()]);
        p.max_ttl_ceiling = Some(1000);
        let clock = Arc::new(AtomicI64::new(now));
        let reg = LeaseRegistry::new(p, Arc::new(MemoryAtomicKv::new())).with_clock(move || clock.load(Ordering::SeqCst));
        assert_eq!(reg.revoke(&lease_revocation(&k, "l1", 5000)), Ok(0));
        reg.shard_revocations(shard_of("l1", 16)).unwrap().len()
    };
    assert_eq!(revoke_at_clock(5999), 1);
    assert_eq!(revoke_at_clock(6000), 1, "kept at exactly revoked_at + ceiling");
    assert_eq!(revoke_at_clock(6001), 0, "pruned one millisecond later");
    // without a ceiling nothing is ever pruned
    let reg = LeaseRegistry::new(LeasePolicy::new(vec![k.public.clone()]), Arc::new(MemoryAtomicKv::new())).with_clock(|| i64::MAX / 2);
    assert_eq!(reg.revoke(&lease_revocation(&k, "l1", 5000)), Ok(0));
    assert_eq!(reg.shard_revocations(shard_of("l1", 16)).unwrap().len(), 1);
}

// ---- break-glass

fn bg_policy(auth: &KeyPair, reviewer: &KeyPair) -> BreakGlassPolicy {
    BreakGlassPolicy { authorities: vec![auth.public.clone()], reviewers: vec![reviewer.public.clone()] }
}

fn bg_record(auth: &KeyPair, max_uses: i64) -> Value {
    signed_with(
        auth,
        BREAK_GLASS_DOMAIN,
        json!({"v": 1, "id": "bg1", "holder": "h", "grant_ref": "g", "reason_digest": "r", "max_uses": max_uses, "issued_at": 1000, "expires_at": 2000, "review_within": 500, "notify_to": "n", "authority": auth.public}),
    )
}

#[test]
fn a_break_glass_budget_is_shared_by_every_registry_over_the_store() {
    let (auth, reviewer) = (KeyPair::from_seed(&[1u8; 32]), KeyPair::from_seed(&[2u8; 32]));
    let kv: Arc<dyn AtomicKv> = Arc::new(MemoryAtomicKv::new());
    let (one, two) = (BreakGlassRegistry::new(bg_policy(&auth, &reviewer), kv.clone()), BreakGlassRegistry::new(bg_policy(&auth, &reviewer), kv));
    assert_eq!(one.accept(&bg_record(&auth, 1), &json!(1000)), Ok(true));
    assert_eq!(two.accept(&bg_record(&auth, 1), &json!(1000)), Ok(false), "the same record again is a no-op");
    assert_eq!(one.use_grant("bg1", "h", "d1", &json!(1100), &json!(true)).decision, "allow");
    let second = two.use_grant("bg1", "h", "d2", &json!(1200), &json!(true));
    assert_eq!((second.decision, second.code), ("deny", Some("budget_exhausted")));
    assert_eq!(two.uses("h", "bg1").unwrap().len(), 1);
    // the freeze (an unreviewed use past its review clock) is visible to the other registry
    assert!(!two.frozen("h", &json!(1599)));
    assert!(two.frozen("h", &json!(1600)));
    // and so is the review that lifts it
    let review = signed_with(&reviewer, BREAK_GLASS_REVIEW_DOMAIN, json!({"v": 1, "id": "bg1", "outcome": "justified", "notes_digest": "n", "at": 1100, "reviewer": reviewer.public}));
    assert_eq!(one.review(&review, "h", &json!(1700)), Ok(true));
    assert!(!two.frozen("h", &json!(1700)));
    assert_eq!(two.review(&review, "h", &json!(1700)), Ok(false));
}

#[test]
fn a_use_by_another_holder_in_the_same_shard_is_wrong_holder() {
    let (auth, reviewer) = (KeyPair::from_seed(&[1u8; 32]), KeyPair::from_seed(&[2u8; 32]));
    let reg = BreakGlassRegistry::new(bg_policy(&auth, &reviewer), Arc::new(MemoryAtomicKv::new())).with_shards(1);
    assert_eq!(reg.accept(&bg_record(&auth, 2), &json!(1000)), Ok(true));
    let d = reg.use_grant("bg1", "other", "d", &json!(1100), &json!(true));
    assert_eq!((d.decision, d.code, d.id.as_deref()), ("deny", Some("wrong_holder"), Some("bg1")));
    let unknown = reg.use_grant("nope", "h", "d", &json!(1100), &json!(true));
    assert_eq!(unknown.code, Some("unknown_break_glass"));
    assert!(std::panic::catch_unwind(|| BreakGlassRegistry::new(BreakGlassPolicy { authorities: vec![], reviewers: vec![] }, Arc::new(MemoryAtomicKv::new())).with_shards(0)).is_err());
}

#[test]
fn a_failing_store_denies_break_glass_use_and_freezes_the_holder() {
    let (auth, reviewer) = (KeyPair::from_seed(&[1u8; 32]), KeyPair::from_seed(&[2u8; 32]));
    let kv = FlakyKv::new();
    let reg = BreakGlassRegistry::new(bg_policy(&auth, &reviewer), kv.clone());
    assert_eq!(reg.accept(&bg_record(&auth, 2), &json!(1000)), Ok(true));
    kv.down.store(true, Ordering::SeqCst);
    assert_eq!(reg.accept(&bg_record(&auth, 3), &json!(1000)), Err("store_unreachable"));
    let d = reg.use_grant("bg1", "h", "d", &json!(1100), &json!(true));
    assert_eq!((d.decision, d.code, d.id.as_deref()), ("deny", Some("store_unreachable"), Some("bg1")));
    assert!(reg.frozen("h", &json!(0)), "a store that cannot answer fails closed");
    let review = signed_with(&reviewer, BREAK_GLASS_REVIEW_DOMAIN, json!({"v": 1, "id": "bg1", "outcome": "justified", "notes_digest": "n", "at": 1100, "reviewer": reviewer.public}));
    assert_eq!(reg.review(&review, "h", &json!(1200)), Err("store_unreachable"));
    assert!(reg.uses("h", "bg1").is_err());
}
