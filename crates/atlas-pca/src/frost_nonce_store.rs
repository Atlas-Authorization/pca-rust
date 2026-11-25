//! The FROST signer's nonce store contract (port of `frost-nonce-store.ts`): the round-1 nonces a signer has issued and not yet spent, kept so
//! that a restart can neither lose a live session nor sign a spent one twice. `create` refuses an existing live or spent id, `load` returns a
//! COPY, `spend` is one-way (the secret is wiped, the id is remembered and `create` refuses it forever), `drop_session` removes a live record
//! without marking it spent, `is_spent` is true only for a spent id. [`assert_nonce_store_contract`] is the self-test a custom (durable)
//! store must pass.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// One session's issued nonces and public commitments.
#[derive(Clone, Debug, PartialEq)]
pub struct NonceRecord {
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
    pub hiding_commitment: Vec<u8>,
    pub binding_commitment: Vec<u8>,
    pub created_at: f64,
}

/// A nonce store. Every method may fail (a store that is down): the signer service turns that into a refusal, never a signature.
pub trait NonceStore: Send + Sync {
    fn create(&self, session_id: &str, record: &NonceRecord) -> Result<(), String>;
    fn load(&self, session_id: &str) -> Result<Option<NonceRecord>, String>;
    fn spend(&self, session_id: &str) -> Result<(), String>;
    fn drop_session(&self, session_id: &str) -> Result<(), String>;
    fn is_spent(&self, session_id: &str) -> Result<bool, String>;
}

/// An in-process nonce store (tests, single-process signers): it forgets everything at exit, so a signer that must survive a restart needs a
/// durable one.
#[derive(Default)]
pub struct MemoryNonceStore {
    state: Mutex<(HashMap<String, NonceRecord>, HashSet<String>)>,
}

impl NonceStore for MemoryNonceStore {
    fn create(&self, session_id: &str, record: &NonceRecord) -> Result<(), String> {
        if session_id.is_empty() {
            return Err("nonce-store: session id must be a non-empty string".into());
        }
        let mut s = self.state.lock().unwrap();
        if s.0.contains_key(session_id) || s.1.contains(session_id) {
            return Err("nonce-store: session already exists".into());
        }
        s.0.insert(session_id.to_string(), record.clone());
        Ok(())
    }
    fn load(&self, session_id: &str) -> Result<Option<NonceRecord>, String> {
        Ok(self.state.lock().unwrap().0.get(session_id).cloned())
    }
    fn spend(&self, session_id: &str) -> Result<(), String> {
        let mut s = self.state.lock().unwrap();
        if s.0.remove(session_id).is_none() {
            return Err("nonce-store: cannot spend a session that is not live".into());
        }
        s.1.insert(session_id.to_string());
        Ok(())
    }
    fn drop_session(&self, session_id: &str) -> Result<(), String> {
        self.state.lock().unwrap().0.remove(session_id);
        Ok(())
    }
    fn is_spent(&self, session_id: &str) -> Result<bool, String> {
        Ok(self.state.lock().unwrap().1.contains(session_id))
    }
}

/// Exercise a store: `make()` builds one, `reopen(store)` simulates a restart (return the store a restarted process would see). `Err` is
/// `nonce-store contract: <the first violated property>`. (A store that hands out a record its own state still aliases cannot be told
/// apart from a correct one here: records are owned values.)
pub fn assert_nonce_store_contract(make: &dyn Fn() -> Arc<dyn NonceStore>, reopen: &dyn Fn(Arc<dyn NonceStore>) -> Arc<dyn NonceStore>) -> Result<(), String> {
    let rec = |n: u8| NonceRecord {
        hiding: vec![n; 32],
        binding: vec![n.wrapping_add(1); 32],
        hiding_commitment: vec![n.wrapping_add(2); 32],
        binding_commitment: vec![n.wrapping_add(3); 32],
        created_at: n as f64,
    };
    let must = |ok: bool, what: &str| if ok { Ok(()) } else { Err(format!("nonce-store contract: {what}")) };
    let ok = |r: Result<(), String>| r.is_ok();
    let mut s = make();
    must(s.load("a")?.is_none() && !s.is_spent("a")?, "an unknown id is neither live nor spent")?;
    s.create("a", &rec(1))?;
    must(!ok(s.create("a", &rec(9))), "create must refuse an existing live id")?;
    s.create("b", &rec(5))?;
    s = reopen(s);
    let got = s.load("a")?;
    must(got.as_ref().is_some_and(|g| g.hiding[0] == 1 && g.created_at == 1.0), "a live record survives a restart")?;
    must(s.load("a")?.is_some_and(|g| g.hiding[0] == 1), "load returns a copy")?;
    s.spend("a")?;
    must(s.load("a")?.is_none() && s.is_spent("a")?, "spend removes the secret and records the marker")?;
    must(!ok(s.spend("a")), "a second spend must throw")?;
    must(!ok(s.create("a", &rec(2))), "create must refuse a spent id")?;
    must(!ok(s.spend("zzz")), "spend of an unknown id must throw")?;
    s = reopen(s);
    must(s.is_spent("a")? && s.load("a")?.is_none(), "a spent marker survives a restart")?;
    must(s.load("b")?.is_some(), "the other live record survives")?;
    s.drop_session("b")?;
    must(s.load("b")?.is_none() && !s.is_spent("b")?, "drop removes a live record without marking it spent")?;
    s.drop_session("never-existed")?;
    Ok(())
}
