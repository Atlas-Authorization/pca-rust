//! Durable transparency ledger (`packages/pca/src/ledger-store.ts`): the `LedgerStore` contract, the reference [`KvLedgerStore`] and
//! [`StoredLedger`].
//!
//! CLAIMED: TAMPER EVIDENCE, given at least one honest independent witness. The ledger is an append-only Merkle log with
//! guardian-signed checkpoints. A party holding a checkpoint can later demand a consistency proof and catch a log that was rewritten,
//! truncated or forked.
//!
//! THE STORE: `append` and `append_checkpoint` are compare-and-swap on the current length (all entries of a batch or none, so two
//! writers never assign one index twice and a log never has holes); committing the same batch again at the same position is a replay.
//!
//! [`StoredLedger::open`] rebuilds the Merkle tree from the stored commits and checks it against EVERY stored checkpoint (guardian
//! signature, signed `prev_root` chain, the RFC 9162 consistency proof at each boundary, and that the commits reproduce each root): a
//! store that lost entries after a checkpoint (`rollback`), edited an entry (`tamper`) or holds a forged checkpoint FAILS CLOSED with a
//! typed error. `checkpoint` refuses to sign a head that is not consistent with the previous one. Synchronous.
use crate::agent::{sign_artifact, KeyPair, PqKeyPair, Suite};
use crate::kv::AtomicKv;
use crate::ledger::{verify_head_consistency_pinned, verify_tree_head_pinned, STH_DOMAIN};
use crate::store_errors::{kv_err, safe_int, CodedError, R};
use crate::{b64_encode, hash_canonical};
use serde_json::{json, Value};
use std::sync::Arc;

pub const LEDGER_DOC_KEY: &str = "pca-ledger-store/v1";

fn is_commit(c: &Value) -> bool {
    c.as_str().is_some_and(|s| !s.is_empty())
}

// ---- the in-memory log -------------------------------------------------------------------------------------------------

/// Root of a commit sequence (the empty log is SHA-256 of the empty string).
pub fn ledger_root_of(commits: &[String]) -> String {
    if commits.is_empty() {
        return b64_encode(&crate::sha(b""));
    }
    b64_encode(&crate::build(&leaf_hashes(commits)))
}

fn leaf_hashes(commits: &[String]) -> Vec<Vec<u8>> {
    commits.iter().map(|c| crate::leaf_hash(&Value::String(c.clone())).unwrap_or_default()).collect()
}

fn sub(m: usize, hs: &[Vec<u8>], b: bool, out: &mut Vec<Vec<u8>>) {
    let n = hs.len();
    if m == n {
        if !b {
            out.push(crate::build(hs));
        }
        return;
    }
    let k = crate::split(n as u64) as usize;
    if m <= k {
        sub(m, &hs[..k], b, out);
        out.push(crate::build(&hs[k..]));
    } else {
        sub(m - k, &hs[k..], false, out);
        out.push(crate::build(&hs[..k]));
    }
}

/// RFC 6962 SUBPROOF(m, D[n], true): the consistency proof between the first `old_size` and the first `new_size` commits.
pub fn consistency_proof(commits: &[String], old_size: &Value, new_size: Option<&Value>) -> R<Value> {
    let n_all = commits.len() as i64;
    let new_v = new_size.cloned().unwrap_or_else(|| json!(n_all));
    let (Some(old), Some(new)) = (old_size.as_i64(), new_v.as_i64()) else { return Err(CodedError::range("consistencyProof: invalid sizes")) };
    if old < 0 || old > new || new > n_all {
        return Err(CodedError::range("consistencyProof: invalid sizes"));
    }
    let mut out = Vec::new();
    if 0 < old && old < new {
        sub(old as usize, &leaf_hashes(&commits[..new as usize]), true, &mut out);
    }
    Ok(json!({"oldSize": old, "newSize": new, "path": out.iter().map(|h| b64_encode(h)).collect::<Vec<_>>()}))
}

/// An in-memory RFC 9162 transparency log over opaque commits (the verifier-side checks are in [`crate::ledger`]).
#[derive(Clone, Debug, Default)]
pub struct TransparencyLedger {
    commits: Vec<String>,
    principal: String,
}

impl TransparencyLedger {
    pub fn from_entries(commits: Vec<String>) -> Self {
        TransparencyLedger { commits, principal: String::new() }
    }
    /// The same log under a principal id (recorded in the tree heads signed over it; the default is `""`).
    pub fn with_principal(mut self, principal: &str) -> Self {
        self.principal = principal.to_string();
        self
    }
    pub fn principal(&self) -> &str {
        &self.principal
    }
    pub fn size(&self) -> usize {
        self.commits.len()
    }
    /// Append a precomputed opaque commitment leaf; refuses an empty commit.
    pub fn append_commitment(&mut self, commit: &str) -> Result<Value, String> {
        if commit.is_empty() {
            return Err("appendCommitment: commit must be a non-empty string".into());
        }
        self.commits.push(commit.to_string());
        Ok(json!({"index": self.commits.len() - 1, "commit": commit}))
    }
    /// `{size, root}`.
    pub fn head(&self) -> Value {
        json!({"size": self.size(), "root": ledger_root_of(&self.commits)})
    }
    /// The root the log had when it contained only the first `size` entries.
    pub fn root_at(&self, size: &Value) -> R<String> {
        match safe_int(size) {
            Some(n) if n >= 0 && n as usize <= self.size() => Ok(ledger_root_of(&self.commits[..n as usize])),
            _ => Err(CodedError::range("rootAt: size out of range")),
        }
    }
    pub fn commits(&self) -> Vec<String> {
        self.commits.clone()
    }
    pub fn inclusion_proof(&self, index: &Value) -> R<Value> {
        let leaves: Vec<Value> = self.commits.iter().map(|c| Value::String(c.clone())).collect();
        crate::grants::merkle_proof(&leaves, index).map_err(CodedError::range)
    }
    pub fn consistency_proof(&self, old_size: &Value, new_size: Option<&Value>) -> R<Value> {
        consistency_proof(&self.commits, old_size, new_size)
    }
}

// ---- the store ---------------------------------------------------------------------------------------------------------

fn empty_ledger_doc() -> Value {
    json!({"v": 1, "commits": [], "checkpoints": []})
}

/// Append `commits` to `doc` iff it has exactly `expected_size` entries (all or none); a batch already stored there is a replay.
pub fn append_to_ledger_doc(doc: &mut Value, expected_size: &Value, commits: &Value) -> R<Value> {
    let expected = safe_int(expected_size).filter(|n| *n >= 0).ok_or_else(|| CodedError::range("append: expectedSize must be a non-negative safe integer"))?;
    let list = commits
        .as_array()
        .filter(|l| !l.is_empty() && l.iter().all(is_commit))
        .ok_or_else(|| CodedError::range("append: commits must be a non-empty array of non-empty strings"))?;
    let stored = doc["commits"].as_array().cloned().unwrap_or_default();
    let size = stored.len() as i64;
    if expected < size {
        let same = list.iter().enumerate().all(|(i, c)| (i as i64 + expected) < size && stored[(expected as usize) + i] == *c);
        return Ok(json!({"outcome": if same { "replayed" } else { "conflict" }, "size": size}));
    }
    if expected > size {
        return Ok(json!({"outcome": "conflict", "size": size}));
    }
    let all = doc["commits"].as_array_mut().expect("decoded doc");
    all.extend(list.iter().cloned());
    Ok(json!({"outcome": "appended", "size": all.len()}))
}

/// The checkpoint counterpart of [`append_to_ledger_doc`].
pub fn checkpoint_to_ledger_doc(doc: &mut Value, expected_count: &Value, cp: &Value) -> R<Value> {
    let expected =
        safe_int(expected_count).filter(|n| *n >= 0).ok_or_else(|| CodedError::range("appendCheckpoint: expectedCount must be a non-negative safe integer"))?;
    let cps = doc["checkpoints"].as_array().cloned().unwrap_or_default();
    let count = cps.len() as i64;
    let conflict = |why: &str| json!({"outcome": "conflict", "count": count, "reason": why});
    if expected < count {
        if hash_canonical(&cps[expected as usize]) == hash_canonical(cp) {
            return Ok(json!({"outcome": "replayed", "count": count}));
        }
        return Ok(conflict("another checkpoint holds that position"));
    }
    if expected > count {
        return Ok(conflict("the checkpoint position is ahead of the log"));
    }
    let sth = cp.get("sth").filter(|s| s.is_object());
    let (size, root_ok) = match sth {
        // Object.is(size, -0) is refused: a negative zero reads as 0 through the integer view
        Some(s) => (safe_int(&s["size"]).filter(|n| *n >= 0 && !s["size"].as_f64().is_some_and(|f| f == 0.0 && f.is_sign_negative())), s["root"].is_string()),
        None => (None, false),
    };
    let (Some(sth), Some(size), true) = (sth, size, root_ok) else { return Ok(conflict("malformed checkpoint")) };
    if size > doc["commits"].as_array().map_or(0, Vec::len) as i64 {
        return Ok(conflict("the checkpoint is beyond the end of the log"));
    }
    if let Some(last) = cps.last().map(|c| &c["sth"]).filter(|l| l.as_object().is_some_and(|o| !o.is_empty())) {
        let ls = last["size"].as_f64().unwrap_or(f64::NAN);
        if (size as f64) < ls || ((size as f64) == ls && sth["root"] != last["root"]) {
            return Ok(conflict("the checkpoint does not extend the previous one"));
        }
    }
    let list = doc["checkpoints"].as_array_mut().expect("decoded doc");
    list.push(cp.clone());
    Ok(json!({"outcome": "appended", "count": list.len()}))
}

fn corrupt(why: &str) -> CodedError {
    CodedError::new("store_corrupt", why)
}

fn decode_doc(raw: Option<&Value>) -> R<Value> {
    let Some(raw) = raw.filter(|r| !r.is_null()) else { return Ok(empty_ledger_doc()) };
    let shape = raw.get("v").and_then(Value::as_f64) == Some(1.0)
        && raw["commits"].as_array().is_some_and(|l| l.iter().all(is_commit))
        && raw["checkpoints"].is_array();
    if !shape {
        return Err(corrupt("ledger document has the wrong shape"));
    }
    if !raw["checkpoints"].as_array().is_some_and(|l| l.iter().all(|c| c.is_object() && c["sth"].is_object())) {
        return Err(corrupt("malformed checkpoint entry"));
    }
    Ok(raw.clone())
}

/// The ledger store contract: every method is synchronous and total in its failure (an `Err`, never a panic).
pub trait LedgerStore: Send + Sync {
    fn size(&self) -> R<i64>;
    fn read(&self, from: &Value, to: &Value) -> R<Vec<String>>;
    fn append(&self, expected_size: &Value, commits: &Value) -> R<Value>;
    fn checkpoint_count(&self) -> R<i64>;
    fn checkpoints(&self, from: &Value) -> R<Vec<Value>>;
    fn append_checkpoint(&self, expected_count: &Value, cp: &Value) -> R<Value>;
}

/// The reference ledger store: the whole log is one document in an atomic key-value store, so every write is one atomic read-modify-write.
/// LIMIT: rewritten on every write; a production log lives in a database with a unique index on the position.
pub struct KvLedgerStore {
    kv: Arc<dyn AtomicKv>,
    key: String,
}

impl KvLedgerStore {
    pub fn new(kv: Arc<dyn AtomicKv>) -> Self {
        KvLedgerStore { kv, key: LEDGER_DOC_KEY.to_string() }
    }

    pub fn with_key(kv: Arc<dyn AtomicKv>, key: &str) -> Self {
        KvLedgerStore { kv, key: key.to_string() }
    }

    fn doc(&self) -> R<Value> {
        decode_doc(self.kv.get(&self.key).map_err(kv_err)?.as_ref())
    }

    fn write(&self, op: &dyn Fn(&mut Value) -> R<Value>) -> R<Value> {
        let mut out: Option<R<Value>> = None;
        self.kv
            .update(&self.key, &mut |prev| match decode_doc(prev).and_then(|mut d| op(&mut d).map(|r| (d, r))) {
                Ok((d, r)) => {
                    let appended = r["outcome"] == "appended";
                    out = Some(Ok(r));
                    appended.then_some(d)
                }
                Err(e) => {
                    out = Some(Err(e));
                    None
                }
            })
            .map_err(kv_err)?;
        out.unwrap_or_else(|| Err(CodedError::new("store_unavailable", "the store did not run the update")))
    }
}

impl LedgerStore for KvLedgerStore {
    fn size(&self) -> R<i64> {
        Ok(self.doc()?["commits"].as_array().map_or(0, Vec::len) as i64)
    }

    fn read(&self, from: &Value, to: &Value) -> R<Vec<String>> {
        let d = self.doc()?;
        let all = d["commits"].as_array().cloned().unwrap_or_default();
        match (safe_int(from), safe_int(to)) {
            (Some(f), Some(t)) if f >= 0 && f <= t && t as usize <= all.len() => {
                Ok(all[f as usize..t as usize].iter().filter_map(|c| c.as_str().map(String::from)).collect())
            }
            _ => Err(CodedError::range("read: range is not inside the log")),
        }
    }

    fn append(&self, expected_size: &Value, commits: &Value) -> R<Value> {
        self.write(&|d| append_to_ledger_doc(d, expected_size, commits))
    }

    fn checkpoint_count(&self) -> R<i64> {
        Ok(self.doc()?["checkpoints"].as_array().map_or(0, Vec::len) as i64)
    }

    fn checkpoints(&self, from: &Value) -> R<Vec<Value>> {
        let d = self.doc()?;
        let all = d["checkpoints"].as_array().cloned().unwrap_or_default();
        match safe_int(from) {
            Some(f) if f >= 0 && f as usize <= all.len() => Ok(all[f as usize..].to_vec()),
            _ => Err(CodedError::range("checkpoints: from is not inside the list")),
        }
    }

    fn append_checkpoint(&self, expected_count: &Value, cp: &Value) -> R<Value> {
        self.write(&|d| checkpoint_to_ledger_doc(d, expected_count, cp))
    }
}

// ---- the stored ledger -------------------------------------------------------------------------------------------------

fn unavailable(e: CodedError) -> CodedError {
    if e.is_range() {
        CodedError::new("store_unavailable", if e.message.is_empty() { "store failed" } else { &e.message })
    } else {
        e
    }
}

/// The options of [`StoredLedger::open`].
pub struct StoredLedgerOptions {
    pub instance_id: String,
    pub principal: String,
    /// Epoch ms of a checkpoint; default the system clock.
    pub clock: Option<Box<dyn Fn() -> f64 + Send + Sync>>,
    /// A post-quantum or hybrid checkpoint suite (needs `pin`).
    pub alg: Option<String>,
    pub pq: Option<PqKeyPair>,
    /// The PQ pins `{ed25519 b64u: pq_pk}` the checkpoints verify under.
    pub pin: Option<Value>,
}

impl StoredLedgerOptions {
    pub fn new(instance_id: &str, principal: &str) -> Self {
        StoredLedgerOptions { instance_id: instance_id.into(), principal: principal.into(), clock: None, alg: None, pq: None, pin: None }
    }
}

/// A transparency log over a ledger store. Open it with [`StoredLedger::open`]: no instance exists whose state was not verified
/// against the stored checkpoints.
pub struct StoredLedger {
    store: Arc<dyn LedgerStore>,
    guardian: KeyPair,
    opts: StoredLedgerOptions,
    log: TransparencyLedger,
    cps: Vec<Value>,
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null | Value::Bool(false) => false,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        Value::Number(n) => n.as_f64() != Some(0.0),
        _ => true,
    }
}

impl StoredLedger {
    /// Load the log and verify it against every stored checkpoint. Errs with `pin_missing`, `rollback`, `tamper`, `forged_checkpoint`,
    /// `inconsistent`, `store_corrupt` or `store_unavailable`.
    pub fn open(store: Arc<dyn LedgerStore>, guardian: KeyPair, opts: StoredLedgerOptions) -> R<StoredLedger> {
        if let Some(alg) = opts.alg.as_deref() {
            if alg != "ed25519" && (!crate::pq::is_known_sig_alg(alg) || !opts.pin.as_ref().is_some_and(truthy)) {
                return Err(CodedError::new(
                    "pin_missing",
                    "a post-quantum or hybrid checkpoint suite needs a PQ pin for the guardian (and a known suite name)",
                ));
            }
        }
        let load = || -> R<(Vec<String>, Vec<Value>)> {
            let size = store.size()?;
            Ok((store.read(&json!(0), &json!(size))?, store.checkpoints(&json!(0))?))
        };
        let (commits, cps) = load().map_err(unavailable)?;
        let me = StoredLedger { store, guardian, opts, log: TransparencyLedger::from_entries(commits), cps };
        me.verify_against_checkpoints().map_err(unavailable)?;
        Ok(me)
    }

    fn pins(&self) -> Option<&Value> {
        self.opts.pin.as_ref()
    }

    /// `Ok(())` or `(at, reason)` of the first checkpoint that does not verify.
    fn verify_chain(&self, cps: &[Value]) -> Result<(), (usize, &'static str)> {
        for (i, cp) in cps.iter().enumerate() {
            if !cp.is_object() || !verify_tree_head_pinned(&cp["sth"], &self.guardian.public, None, self.pins()) {
                return Err((i, "head"));
            }
            if i == 0 {
                continue;
            }
            if !truthy(&cp["proof"]) {
                return Err((i, "proof_missing"));
            }
            if !verify_head_consistency_pinned(&cps[i - 1]["sth"], &cp["sth"], &cp["proof"], &self.guardian.public, None, self.pins()) {
                return Err((i, "inconsistent"));
            }
        }
        Ok(())
    }

    fn verify_against_checkpoints(&self) -> R<()> {
        let attested = self.cps.iter().map(|c| safe_int(&c["sth"]["size"]).unwrap_or(0)).fold(0, i64::max);
        if (self.log.size() as i64) < attested {
            return Err(CodedError::new("rollback", format!("the log has {} entries but a checkpoint attests {attested}", self.log.size())));
        }
        for (i, cp) in self.cps.iter().enumerate() {
            let sth = &cp["sth"];
            if sth["instance_id"] != json!(self.opts.instance_id) || sth["principal"] != json!(self.opts.principal) {
                return Err(CodedError::new("forged_checkpoint", format!("checkpoint {i} belongs to another log")));
            }
            let root = self.log.root_at(&sth["size"])?;
            if sth["root"] != json!(root) {
                return Err(CodedError::new(
                    "tamper",
                    format!("the stored entries do not reproduce the root of checkpoint {i} (size {})", crate::intent_v2::js_value_string(&sth["size"])),
                ));
            }
        }
        if self.cps.is_empty() {
            return Ok(());
        }
        match self.verify_chain(&self.cps) {
            Ok(()) => Ok(()),
            Err((at, reason)) => {
                Err(CodedError::new(if reason == "inconsistent" { "inconsistent" } else { "forged_checkpoint" }, format!("checkpoint {at}: {reason}")))
            }
        }
    }

    pub fn size(&self) -> usize {
        self.log.size()
    }

    /// The guardian public key (b64u) every checkpoint verifies under.
    pub fn guardian(&self) -> &str {
        &self.guardian.public
    }

    pub fn latest_checkpoint(&self) -> Option<Value> {
        self.cps.last().map(|c| c["sth"].clone())
    }

    pub fn checkpoint_chain(&self) -> Vec<Value> {
        self.cps.clone()
    }

    pub fn head(&self) -> Value {
        self.log.head()
    }

    pub fn inclusion_proof(&self, index: &Value) -> R<Value> {
        self.log.inclusion_proof(index)
    }

    /// RFC 9162 proof from a size the caller already pinned to the current log.
    pub fn consistency_proof_from(&self, old_size: &Value) -> R<Value> {
        self.log.consistency_proof(old_size, None)
    }

    pub fn commits(&self) -> Vec<String> {
        self.log.commits()
    }

    /// Append an opaque commitment leaf. Idempotent under retry at the position the caller read; if another writer took that position the
    /// ledger reloads and appends at the new tail. Returns `{index, commit}`.
    pub fn append(&mut self, commit: &Value) -> R<Value> {
        let Some(commit) = commit.as_str().filter(|c| !c.is_empty()) else {
            return Err(CodedError::new("invalid_commit", "a commit must be a non-empty string"));
        };
        for _ in 0..16 {
            let index = self.log.size();
            let out = self.store.append(&json!(index), &json!([commit])).map_err(unavailable)?;
            if matches!(out["outcome"].as_str(), Some("appended" | "replayed")) {
                self.log.append_commitment(commit).map_err(|e| CodedError::new("invalid_commit", e))?;
                return Ok(json!({"index": index, "commit": commit}));
            }
            self.catch_up()?; // another writer advanced the log: pick up its entries, then try the new tail
        }
        Err(CodedError::new("conflict", "the log kept moving; could not append"))
    }

    /// Reload entries other writers appended since this handle last looked (and re-verify them against the checkpoints).
    pub fn catch_up(&mut self) -> R<()> {
        let size = self.store.size().map_err(unavailable)?;
        if size < self.log.size() as i64 {
            return Err(CodedError::new("rollback", format!("the store shrank from {} to {size} entries", self.log.size())));
        }
        let new = self.store.read(&json!(self.log.size()), &json!(size)).map_err(unavailable)?;
        for c in new {
            self.log.append_commitment(&c).map_err(|e| CodedError::new("store_unavailable", e))?;
        }
        let more = self.store.checkpoints(&json!(self.cps.len())).map_err(unavailable)?;
        self.cps.extend(more);
        self.verify_against_checkpoints().map_err(unavailable)
    }

    fn assert_store_matches_memory(&self) -> R<()> {
        let stored = self.store.read(&json!(0), &json!(self.log.size())).map_err(unavailable)?;
        if stored != self.log.commits() {
            return Err(CodedError::new("tamper", "the stored entries no longer match this handle; refusing to sign a checkpoint over them"));
        }
        Ok(())
    }

    /// Sign and persist a checkpoint of the current head. It is verified BEFORE it is stored: the new head must be consistent with the
    /// previous checkpoint, so a log that was rewritten under this handle is refused (`inconsistent`). An unchanged head returns the
    /// existing checkpoint.
    pub fn checkpoint(&mut self) -> R<Value> {
        self.catch_up()?;
        self.assert_store_matches_memory()?;
        let prev = self.cps.last().cloned();
        let h = self.log.head();
        if let Some(p) = &prev {
            if p["sth"]["size"] == h["size"] {
                return Ok(p["sth"].clone());
            }
        }
        let t = match &self.opts.clock {
            Some(c) => c(),
            None => std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_millis() as f64),
        };
        if !t.is_finite() {
            return Err(CodedError::new("clock_invalid", "the clock returned a non-finite time"));
        }
        let body = json!({
            "instance_id": self.opts.instance_id, "principal": self.opts.principal, "size": h["size"], "root": h["root"],
            "prev_root": prev.as_ref().map_or(json!(""), |p| p["sth"]["root"].clone()), "timestamp": t.floor() as i64,
        });
        let suite = Suite { alg: self.opts.alg.as_deref(), pq: self.opts.pq.as_ref() };
        let signed = sign_artifact(STH_DOMAIN, &body, &self.guardian, &suite).map_err(|e| CodedError::new("store_unavailable", e))?;
        let mut sth = body.clone();
        sth["guardian"] = json!(self.guardian.public);
        for (k, v) in signed.as_object().into_iter().flatten() {
            if body.get(k).is_none() {
                sth[k] = v.clone();
            }
        }
        let cp = match &prev {
            Some(p) => json!({"sth": sth, "proof": self.log.consistency_proof(&p["sth"]["size"], Some(&h["size"]))?}),
            None => json!({"sth": sth}),
        };
        let mut chain = self.cps.clone();
        chain.push(cp.clone());
        if let Err((at, reason)) = self.verify_chain(&chain) {
            return Err(if reason == "head" {
                CodedError::new(
                    "forged_checkpoint",
                    "the new checkpoint does not verify under the pinned guardian identity (check the guardian key and the PQ pin)",
                )
            } else {
                CodedError::new("inconsistent", format!("the new head is not consistent with checkpoint {}", at - 1))
            });
        }
        let out = self.store.append_checkpoint(&json!(self.cps.len()), &cp).map_err(unavailable)?;
        if out["outcome"] == "conflict" {
            return Err(CodedError::new("conflict", out["reason"].as_str().unwrap_or("conflict")));
        }
        self.cps.push(cp);
        Ok(sth)
    }
}
