//! The issuing and witnessing side of the cross-domain mesh (`mesh.ts` `MeshDomain`, `MeshWitness` and the sorted revocation set
//! behind them): an append-only delegation log with revocation set and head publication ([`MeshDomain`]), an independent log witness
//! that cosigns a head only if it is an append-only, revocation-monotone, non-regressing extension of the last head it cosigned
//! ([`MeshWitness`]), and the size-bound revocation set whose non-membership proofs the verifier checks ([`RevocationSet`]).
//! The verifier is [`crate::mesh`]; proofs are assembled by [`crate::signers_more::assemble_mesh_proof`].
//!
//! Heads, cosignatures, bindings and evidence are JSON values with the reference's member names. A failure is an `Err` whose text is
//! the reference's message.

use crate::agent::KeyPair;
use crate::mesh::{check_head_advance, msg, valid_head};
use crate::mesh_witness_store::MeshWitnessStore;
use crate::{b64_encode, cap_hash, merkle_root, sha, verify_b64u};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

const HEAD_DOMAIN: &str = "atlas-pca/mesh-head/v1\0";
const COSIG_DOMAIN: &str = "atlas-pca/mesh-cosig/v1\0";
const BINDING_DOMAIN: &str = "atlas-pca/mesh-binding/v1\0";
/// Cap on a witness's accepted revocation list.
const MAX_REV_IDS: usize = 1_000_000;
pub const DEFAULT_MAX_CLOCK_SKEW_MS: f64 = 60_000.0;

/// Id used in a domain's revocation set to revoke an agent KEY (kills every capability it issues).
pub fn key_revocation_id(agent_public: &str) -> String {
    format!("key:{agent_public}")
}

fn strict(domain: &str, body: &Value) -> Result<Vec<u8>, String> {
    msg(domain, body).ok_or_else(|| "canonicalize: value is outside the strict profile".to_string())
}

fn sign_b64(key: &KeyPair, m: &[u8]) -> String {
    b64_encode(&key.sign(m))
}

// ---- the revocation set ------------------------------------------------------------------------------------------------------------

/// A sorted (UTF-8 byte order), size-bound set of revoked ids. Its root commits to the size and the Merkle root of the sorted ids, so
/// a verifier can check inclusion and (by bracketing neighbours) non-membership of an id.
#[derive(Clone, Debug, Default)]
pub struct RevocationSet {
    ids: Vec<String>,
}

impl RevocationSet {
    pub fn new() -> Self {
        RevocationSet::default()
    }

    pub fn from_ids<I: IntoIterator<Item = String>>(ids: I) -> Self {
        let mut s = RevocationSet::new();
        for id in ids {
            s.revoke(&id);
        }
        s
    }

    pub fn size(&self) -> usize {
        self.ids.len()
    }

    /// Idempotent. Returns true when newly revoked.
    pub fn revoke(&mut self, id: &str) -> bool {
        match self.ids.binary_search_by(|x| x.as_str().cmp(id)) {
            Ok(_) => false,
            Err(at) => {
                self.ids.insert(at, id.to_string());
                true
            }
        }
    }

    pub fn has(&self, id: &str) -> bool {
        self.ids.binary_search_by(|x| x.as_str().cmp(id)).is_ok()
    }

    /// The sorted revoked ids.
    pub fn list(&self) -> Vec<String> {
        self.ids.clone()
    }

    fn leaves(&self) -> Vec<Value> {
        self.ids.iter().map(|i| Value::String(i.clone())).collect()
    }

    /// `b64u(sha256("pca-revset/v1\0" || strictCanonical({size, tree})))` over the Merkle root of the sorted ids (the empty-tree root
    /// when empty).
    pub fn root(&self) -> Result<String, String> {
        let tree = if self.ids.is_empty() { b64_encode(&sha(b"")) } else { merkle_root(&self.leaves())? };
        Ok(b64_encode(&sha(&strict("pca-revset/v1\0", &json!({"size": self.ids.len(), "tree": tree}))?)))
    }

    /// Inclusion proof `{index, size, path}` of a revoked id.
    pub fn membership_proof(&self, id: &str) -> Result<Value, String> {
        let i = self.ids.binary_search_by(|x| x.as_str().cmp(id)).map_err(|_| "membershipProof: id is not revoked".to_string())?;
        crate::grants::merkle_proof(&self.leaves(), &json!(i))
    }

    /// `{size, lo?, hi?}`: the neighbours of `id` in sorted order with inclusion proofs. `Err` when the id IS revoked.
    pub fn non_membership_proof(&self, id: &str) -> Result<Value, String> {
        let at = match self.ids.binary_search_by(|x| x.as_str().cmp(id)) {
            Ok(_) => return Err("nonMembershipProof: id is revoked".into()),
            Err(at) => at,
        };
        let n = self.ids.len();
        let leaves = self.leaves();
        let leaf = |i: usize| -> Result<Value, String> { Ok(json!({"id": self.ids[i], "proof": crate::grants::merkle_proof(&leaves, &json!(i))?})) };
        let mut p = json!({"size": n});
        if at > 0 {
            p["lo"] = leaf(at - 1)?;
        }
        if at < n {
            p["hi"] = leaf(at)?;
        }
        Ok(p)
    }
}

// ---- the witness -------------------------------------------------------------------------------------------------------------------

/// An independent log witness. It cosigns a domain head only if (1) the domain signed it, (2) it is an RFC 9162-verified append-only
/// extension of the last head THIS witness cosigned for that domain, (3) its revocation list reproduces `rev_root` and is a superset of
/// the previously cosigned list, and (4) the timestamp does not regress (nor run ahead of the witness's own clock, when configured).
/// State is committed only after every check passes (and after it was saved, when a store is given). First sight of a domain is
/// trust-on-first-use.
pub struct MeshWitness {
    /// The witness's public key (b64u).
    pub id: String,
    key: KeyPair,
    store: Option<Box<dyn MeshWitnessStore>>,
    clock: Option<Box<dyn Fn() -> f64>>,
    max_skew_ms: f64,
    seen: BTreeMap<String, (Value, Vec<String>)>,
}

impl MeshWitness {
    /// A witness with no store and no clock.
    pub fn new(key: KeyPair) -> MeshWitness {
        MeshWitness { id: key.public.clone(), key, store: None, clock: None, max_skew_ms: DEFAULT_MAX_CLOCK_SKEW_MS, seen: BTreeMap::new() }
    }

    /// A witness with durable memory (loaded now: a corrupt state fails, the witness never starts empty over damaged memory), an optional
    /// clock (heads timestamped beyond `now + max_skew_ms` are refused) and its skew bound.
    pub fn with_options(
        key: KeyPair,
        store: Option<Box<dyn MeshWitnessStore>>,
        clock: Option<Box<dyn Fn() -> f64>>,
        max_skew_ms: Option<f64>,
    ) -> Result<MeshWitness, String> {
        let mut w = MeshWitness::new(key);
        w.clock = clock;
        w.max_skew_ms = max_skew_ms.unwrap_or(DEFAULT_MAX_CLOCK_SKEW_MS);
        if let Some(loaded) = store.as_ref().map(|s| s.load()).transpose()?.flatten() {
            w.import_state(&loaded)?;
        }
        w.store = store;
        Ok(w)
    }

    /// The newest head this witness cosigned for `domain` (what a domain must prove consistency from).
    pub fn last_seen(&self, domain: &str) -> Option<Value> {
        self.seen.get(domain).map(|(h, _)| h.clone())
    }

    fn state_of(seen: &BTreeMap<String, (Value, Vec<String>)>) -> Value {
        json!({"seen": seen.values().map(|(h, r)| json!({"head": h, "rev_ids": r})).collect::<Vec<_>>()})
    }

    /// Cosign a head. `req`: `{head: {head, sig, cosigs}, consistency?, rev_ids}`. Fails (and changes nothing) if any rule is violated.
    pub fn cosign(&mut self, req: &Value) -> Result<Value, String> {
        let ch = req.get("head").filter(|c| c.is_object());
        let h = ch.and_then(|c| c.get("head")).filter(|h| valid_head(Some(h)).is_some());
        let (ch, h) = match (ch, h) {
            (Some(c), Some(h)) if c.get("sig").is_some_and(Value::is_string) => (c, h),
            _ => return Err("witness: malformed head".into()),
        };
        let domain = h["domain"].as_str().unwrap_or_default().to_string();
        let ok = strict(HEAD_DOMAIN, h).map(|m| verify_b64u(&domain, &m, ch["sig"].as_str().unwrap_or_default())).unwrap_or(false);
        if !ok {
            return Err("witness: head not signed by its domain".into());
        }
        let ts = h["timestamp"].as_f64().unwrap_or(f64::NAN);
        if let Some(clock) = &self.clock {
            let clk = clock();
            if !(clk.is_finite() && self.max_skew_ms.is_finite() && ts <= clk + self.max_skew_ms) {
                return Err("witness: head timestamp is in the future".into());
            }
        }
        let ids: Vec<String> = match req.get("rev_ids").and_then(Value::as_array) {
            Some(a) if a.len() <= MAX_REV_IDS && a.iter().all(Value::is_string) => a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect(),
            _ => return Err("witness: malformed revocation list".into()),
        };
        let set = RevocationSet::from_ids(ids);
        if Some(set.size() as f64) != h["rev_size"].as_f64() || h["rev_root"].as_str() != Some(set.root()?.as_str()) {
            return Err("witness: revocation list does not match head".into());
        }
        if let Some((prev_head, prev_rev)) = self.seen.get(&domain) {
            if let Some(why) = check_head_advance(Some(prev_head), Some(h), req.get("consistency")) {
                return Err(format!("witness: {why}"));
            }
            if !(ts >= prev_head["timestamp"].as_f64().unwrap_or(f64::NAN)) {
                return Err("witness: timestamp regresses".into());
            }
            let now = set.list();
            if !prev_rev.iter().all(|id| now.binary_search(id).is_ok()) {
                return Err("witness: revocation set drops a previously cosigned revocation".into());
            }
        }
        let mut next = self.seen.clone();
        next.insert(domain.clone(), (h.clone(), set.list()));
        if let Some(store) = &self.store {
            // persist first, commit to memory second: if the write fails nothing was cosigned and nothing changed
            store.save(&Self::state_of(&next)).map_err(|_| "witness: could not persist state; refusing to cosign".to_string())?;
        }
        self.seen = next;
        Ok(json!({"witness": self.id, "sig": sign_b64(&self.key, &strict(COSIG_DOMAIN, h)?)}))
    }

    /// Export memory for persistence (deterministic order).
    pub fn export_state(&self) -> Value {
        Self::state_of(&self.seen)
    }

    /// Restore memory; each record must be internally consistent (its revocation list reproduces its root).
    pub fn import_state(&mut self, state: &Value) -> Result<(), String> {
        let mut next = BTreeMap::new();
        // `for (const s of state.seen)`: a string yields its characters (none has a head) and any other non-list is not iterable
        match state.get("seen") {
            None | Some(Value::Null) | Some(Value::Array(_)) => {}
            Some(Value::String(t)) if t.is_empty() => {}
            Some(_) => return Err("witness: malformed state".into()),
        }
        for s in state.get("seen").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
            let head = s.get("head").filter(|h| valid_head(Some(h)).is_some());
            let ids = s.get("rev_ids").and_then(Value::as_array).filter(|a| a.iter().all(Value::is_string));
            let (Some(head), Some(ids)) = (head, ids) else { return Err("witness: malformed state".into()) };
            let set = RevocationSet::from_ids(ids.iter().filter_map(|i| i.as_str().map(str::to_string)));
            if Some(set.size() as f64) != head["rev_size"].as_f64() || head["rev_root"].as_str() != Some(set.root()?.as_str()) {
                return Err("witness: malformed state".into());
            }
            next.insert(head["domain"].as_str().unwrap_or_default().to_string(), (head.clone(), set.list()));
        }
        self.seen = next;
        Ok(())
    }
}

// ---- the domain --------------------------------------------------------------------------------------------------------------------

/// Issuer-side state of one organisation: an append-only delegation log, a revocation set, and head publication.
pub struct MeshDomain {
    pub name: String,
    /// The domain's public key (b64u, self-certifying id).
    pub id: String,
    key: KeyPair,
    log: Vec<String>,
    /// The domain's current revocation set.
    pub rev: RevocationSet,
    snaps: HashMap<String, (Vec<String>, RevocationSet)>,
}

impl MeshDomain {
    pub fn new(name: &str, key: KeyPair) -> MeshDomain {
        MeshDomain { name: name.to_string(), id: key.public.clone(), key, log: Vec::new(), rev: RevocationSet::new(), snaps: HashMap::new() }
    }

    /// Vouch that an agent key belongs to this domain: `{agent, domain, role, sig}`.
    pub fn enroll(&self, agent: &str, role: &str) -> Result<Value, String> {
        let m = strict(BINDING_DOMAIN, &json!({"agent": agent, "domain": self.id, "role": role}))?;
        Ok(json!({"agent": agent, "domain": self.id, "role": role, "sig": sign_b64(&self.key, &m)}))
    }

    /// Log a delegation hop issued in this domain (by capability hash). Idempotent; returns the leaf index.
    pub fn record(&mut self, cap: &Value) -> usize {
        let h = cap_hash(cap);
        match self.log.iter().position(|x| *x == h) {
            Some(i) => i,
            None => {
                self.log.push(h);
                self.log.len() - 1
            }
        }
    }

    /// Revoke a capability id (`cap.id`) or an agent key ([`key_revocation_id`]).
    pub fn revoke(&mut self, id: &str) {
        self.rev.revoke(id);
    }

    /// RFC 9162 consistency proof between two sizes of this domain's current log (`new_size` defaults to the current size).
    pub fn consistency_proof(&self, old_size: &Value, new_size: Option<&Value>) -> Result<Value, String> {
        crate::ledger_store::consistency_proof(&self.log, old_size, new_size).map_err(|e| e.to_string())
    }

    /// The proof a verifier holding `pin` needs to accept `head` (a head this domain published, larger than the pin): `{domain, proof}`.
    /// Fails if the head is unknown or the pin is not a prefix of its log.
    pub fn pin_proof(&self, pin: &Value, head: &Value) -> Result<Value, String> {
        let snap = head.get("sig").and_then(Value::as_str).and_then(|s| self.snaps.get(s)).ok_or("pinProof: unknown head")?;
        let new_size = head.get("head").and_then(|h| h.get("size")).ok_or("pinProof: malformed head")?;
        let proof = crate::ledger_store::consistency_proof(&snap.0, pin.get("size").unwrap_or(&Value::Null), Some(new_size)).map_err(|e| e.to_string())?;
        Ok(json!({"domain": self.id, "proof": proof}))
    }

    /// Publish a head: domain-signed, then cosigned by `witnesses`, each shown a real consistency proof from ITS last-seen head plus the
    /// revocation list. Fails if too few witnesses cosign (`threshold`: at least this many; default every witness); nothing is recorded as
    /// published on failure.
    pub fn publish_head(&mut self, witnesses: &mut [&mut MeshWitness], timestamp: f64, threshold: Option<usize>) -> Result<Value, String> {
        let root = if self.log.is_empty() { String::new() } else { merkle_root(&self.log.iter().map(|c| Value::String(c.clone())).collect::<Vec<_>>())? };
        let head = json!({"domain": self.id, "size": self.log.len(), "root": root, "rev_root": self.rev.root()?, "rev_size": self.rev.size(), "timestamp": if timestamp.fract() == 0.0 && timestamp.abs() < 9e15 { json!(timestamp as i64) } else { json!(timestamp) }});
        let sig = sign_b64(&self.key, &strict(HEAD_DOMAIN, &head)?);
        let mut ch = json!({"head": head, "sig": sig, "cosigs": []});
        let rev_ids = self.rev.list();
        let size = self.log.len() as i64;
        let mut errors: Vec<String> = Vec::new();
        let mut cosigs: Vec<Value> = Vec::new();
        for w in witnesses.iter_mut() {
            let prev = w.last_seen(&self.id);
            let prev_size = prev.as_ref().and_then(|p| p["size"].as_i64());
            let consistency = match prev_size {
                Some(ps) if ps < size => Some(self.consistency_proof(&json!(ps), Some(&json!(size)))?),
                Some(ps) if ps > size => Some(json!({"oldSize": ps, "newSize": size, "path": []})), // refused as a rollback
                _ => None,
            };
            let mut req = json!({"head": ch, "rev_ids": rev_ids});
            if let Some(c) = consistency {
                req["consistency"] = c;
            }
            match w.cosign(&req) {
                Ok(c) => cosigs.push(c),
                Err(e) => errors.push(e),
            }
        }
        if cosigs.len() < threshold.unwrap_or(witnesses.len()) {
            return Err(errors.into_iter().next().unwrap_or_else(|| "publishHead: not enough witnesses".to_string()));
        }
        ch["cosigs"] = Value::Array(cosigs);
        self.snaps.insert(sig_of(&ch), (self.log.clone(), RevocationSet::from_ids(self.rev.list())));
        Ok(ch)
    }

    /// Build per-hop evidence `{domain, head, inclusion, revocation: {cap, issuer_key}, binding?}` against a previously published head.
    /// Fails if the capability is not in that head's log or if it / its issuer key is revoked as of that head.
    pub fn evidence(&self, cap: &Value, head: &Value, binding: Option<&Value>) -> Result<Value, String> {
        let (log, rev) = head.get("sig").and_then(Value::as_str).and_then(|s| self.snaps.get(s)).ok_or("evidence: unknown head")?;
        let idx = log.iter().position(|x| *x == cap_hash(cap)).ok_or("evidence: capability not in this head")?;
        let leaves: Vec<Value> = log.iter().map(|c| Value::String(c.clone())).collect();
        let cap_id = cap.get("id").and_then(Value::as_str).ok_or("evidence: capability has no id")?;
        let issuer = cap.get("issuer").and_then(Value::as_str).ok_or("evidence: capability has no issuer")?;
        let mut ev = json!({
            "domain": self.id,
            "head": head,
            "inclusion": crate::grants::merkle_proof(&leaves, &json!(idx))?,
            "revocation": {"cap": rev.non_membership_proof(cap_id)?, "issuer_key": rev.non_membership_proof(&key_revocation_id(issuer))?},
        });
        if let Some(b) = binding {
            ev["binding"] = b.clone();
        }
        Ok(ev)
    }
}

fn sig_of(ch: &Value) -> String {
    ch["sig"].as_str().unwrap_or_default().to_string()
}
