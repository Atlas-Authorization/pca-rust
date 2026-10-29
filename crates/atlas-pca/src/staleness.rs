//! Revocation staleness (T9): a verifier-side cap on how old the revocation state may be, per reversibility class.
//!
//! The signer of a revocation epoch chooses `not_after`; this lets the VERIFIER cap `now - issued_at`, with a stricter window
//! for actions that cannot be undone. Port of `revocation.ts` (`checkRevocationAge`, `revocationMaxAgeMs`,
//! `effectiveReversibility`, `checkRevocationEpoch`, the staleness branch of `createRevocationChecker`); the shared vectors
//! `staleness-vectors.json` pin every rule. Nothing changes unless a [`RevocationStaleness`] is configured.

use std::sync::Arc;

use serde_json::{Map, Value};

use super::intent_suite::{bind_suite_fields, domain_message, suite_of, verify_pinned_suite};
use super::{b64_encode, canonicalize_strict, decode_b64u_strict, leaf_hash, node_hash, path_shape, safe_int, sha};

const REVEPOCH_DOMAIN: &str = "atlas-pca/revepoch/v1\0";
/// The signer re-signs the epoch at least this often.
pub const REVOCATION_EPOCH_REFRESH_MS: f64 = 60_000.0;
/// How long a signed epoch is acceptable.
pub const REVOCATION_EPOCH_VALIDITY_MS: f64 = 300_000.0;
/// Default maximum age of revocation state for an irreversible action: two refresh periods.
pub const REVOCATION_IRREVERSIBLE_MAX_AGE_MS: f64 = 120_000.0;
const SKEW_MS: f64 = 60_000.0;

/// The effective reversibility class of an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reversibility {
    Reversible,
    Costly,
    /// A stored record that spells the middle class `costly` (the pre-rename word, still accepted for one release): kept
    /// verbatim so a record round-trips unchanged. Behaves as `Costly`; `effective_reversibility` never returns it.
    LegacyCostly,
    Irreversible,
}

impl Reversibility {
    /// The class named by a stored string (`None` for anything else).
    pub fn parse(s: &str) -> Option<Reversibility> {
        match s {
            "reversible" => Some(Reversibility::Reversible),
            "rate_limited" => Some(Reversibility::Costly),
            "costly" => Some(Reversibility::LegacyCostly),
            "irreversible" => Some(Reversibility::Irreversible),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Reversibility::Reversible => "reversible",
            Reversibility::Costly => "rate_limited",
            Reversibility::LegacyCostly => "costly",
            Reversibility::Irreversible => "irreversible",
        }
    }
}

/// Severity of a class over both vocabularies (`rate_limited` shares the middle tier). Anything else is the most restrictive.
fn rank_of(c: Option<&str>) -> u8 {
    match c {
        Some("reversible") => 0,
        Some("rate_limited") | Some("costly") => 1,
        _ => 2,
    }
}

/// The stricter of the server's authoritative class and the PCActn's signed class. A missing, non-string or unknown class is
/// irreversible (fail closed); only an absent SERVER class counts as reversible (nothing authoritative to tighten with).
pub fn effective_reversibility(server_class: Option<&str>, signed_class: Option<&Value>) -> Reversibility {
    let server = server_class.map_or(0, |s| rank_of(Some(s)));
    let signed = rank_of(signed_class.and_then(Value::as_str));
    match server.max(signed) {
        0 => Reversibility::Reversible,
        1 => Reversibility::Costly,
        _ => Reversibility::Irreversible,
    }
}

/// Per-class windows of a staleness policy.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct StalenessWindows {
    pub irreversible: Option<f64>,
    pub costly: Option<f64>,
}

/// Verifier-side revocation staleness policy. The policy is ON when `max_revocation_age_ms` or `staleness` is set.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct RevocationStalenessPolicy {
    /// Maximum age for any action (default [`REVOCATION_EPOCH_VALIDITY_MS`]).
    pub max_revocation_age_ms: Option<f64>,
    /// Per-class maximum age, each capped by `max_revocation_age_ms`. Defaults: irreversible 2 min, costly = the general cap.
    pub staleness: Option<StalenessWindows>,
    /// Accept an unsigned (bare) revocation root for an irreversible action. Default false.
    pub allow_unsigned_root_for_irreversible: bool,
}

fn positive(name: &str, v: Option<f64>) -> Result<(), String> {
    match v {
        Some(x) if !(x.is_finite() && x > 0.0) => Err(format!("{name} must be a positive number of milliseconds")),
        _ => Ok(()),
    }
}

impl RevocationStalenessPolicy {
    /// A malformed policy is a configuration error (raised when the gate is built, never at request time).
    pub fn validate(&self) -> Result<(), String> {
        positive("max_revocation_age_ms", self.max_revocation_age_ms)?;
        positive("staleness.irreversible", self.staleness.and_then(|s| s.irreversible))?;
        positive("staleness.costly", self.staleness.and_then(|s| s.costly))
    }

    /// True when any age option is set.
    pub fn is_on(&self) -> bool {
        self.max_revocation_age_ms.is_some() || self.staleness.is_some()
    }

    /// The maximum age of revocation state this policy allows for an action of `cls`.
    pub fn max_age_ms(&self, cls: Reversibility) -> f64 {
        let max = self.max_revocation_age_ms.unwrap_or(REVOCATION_EPOCH_VALIDITY_MS);
        let w = self.staleness.unwrap_or_default();
        match cls {
            Reversibility::Irreversible => max.min(w.irreversible.unwrap_or(REVOCATION_IRREVERSIBLE_MAX_AGE_MS)),
            Reversibility::Costly | Reversibility::LegacyCostly => max.min(w.costly.unwrap_or(max)),
            Reversibility::Reversible => max,
        }
    }

    /// Lenient construction from `{maxRevocationAgeMs?, staleness?: {irreversible?, costly?}, allowUnsignedRootForIrreversible?}`.
    /// A present non-numeric value becomes NaN, which [`validate`](Self::validate) refuses.
    pub fn from_json(v: &Value) -> RevocationStalenessPolicy {
        let num = |o: &Map<String, Value>, k: &str| o.get(k).map(|x| x.as_f64().unwrap_or(f64::NAN));
        let empty = Map::new();
        let o = v.as_object().unwrap_or(&empty);
        RevocationStalenessPolicy {
            max_revocation_age_ms: num(o, "maxRevocationAgeMs"),
            staleness: o
                .get("staleness")
                .and_then(Value::as_object)
                .map(|s| StalenessWindows { irreversible: num(s, "irreversible"), costly: num(s, "rate_limited").or_else(|| num(s, "costly")) }),
            allow_unsigned_root_for_irreversible: o.get("allowUnsignedRootForIrreversible") == Some(&Value::Bool(true)),
        }
    }
}

/// A number as JavaScript prints it (integers without a fraction, `NaN`).
pub(crate) fn js_num(f: f64) -> String {
    if f.is_nan() {
        "NaN".into()
    } else if f == 0.0 {
        "0".into()
    } else if f.fract() == 0.0 && f.abs() < 1e21 {
        format!("{f:.0}")
    } else {
        f.to_string()
    }
}

/// Age check of revocation state issued at `issued_at`. An unknown (absent, NaN, infinite) issue time is unverifiable and
/// denies; a time more than 60 s in the future denies; an age over `max_age_ms` (NaN included) denies. Never panics.
pub fn check_revocation_age(issued_at: Option<f64>, now: f64, max_age_ms: f64, what: &str) -> Result<(), String> {
    let Some(i) = issued_at.filter(|x| x.is_finite()) else {
        return Err(format!("{what} age is unknown (unverifiable revocation state)"));
    };
    if !(i <= now + SKEW_MS) {
        return Err(format!("{what} issued in the future"));
    }
    if !(now - i <= max_age_ms) {
        return Err(format!("{what} is {} ms old, over the verifier's maximum of {} ms (stale revocation state)", js_num(now - i), js_num(max_age_ms)));
    }
    Ok(())
}

/// Options of [`check_revocation_epoch`].
#[derive(Debug, Clone, Copy)]
pub struct EpochCheckOptions<'a> {
    /// The pinned guardian public key (b64u Ed25519).
    pub guardian_public: &'a str,
    /// Epoch ms (no implicit clock).
    pub now: f64,
    pub grant_ref: Option<&'a str>,
    /// Newest epoch already accepted for the grant: an older one is a rollback.
    pub last_accepted_epoch: Option<f64>,
    /// The epoch the PCActn signed in `freshness.epoch`; must be >= the signed epoch.
    pub pcactn_epoch: Option<f64>,
    /// Verifier-side maximum age (`now - issued_at`); `None`: only `not_after` bounds staleness.
    pub max_age_ms: Option<f64>,
    /// `(guardian, pq_pk)`: the PQ key pinned for a guardian that signs with a post-quantum / hybrid suite. Without it such an
    /// epoch is refused (the pin rule of the other signed artifacts).
    pub pq_pin: Option<(&'a str, &'a Value)>,
}

/// Verify a signed revocation epoch (signature, binding, expiry, rollback, PCActn freshness). Never panics.
pub fn check_revocation_epoch(ep: &Value, o: &EpochCheckOptions<'_>) -> Result<(), String> {
    const NOT_PINNED: &str = "revocation epoch not signed by the pinned guardian";
    let Some(m) = ep.as_object() else { return Err(NOT_PINNED.into()) };
    if m.get("guardian").and_then(Value::as_str) != Some(o.guardian_public) || suite_of(m.get("alg")).is_err() {
        return Err(NOT_PINNED.into());
    }
    let int = |k: &str| m.get(k).and_then(safe_int);
    let (Some(epoch), Some(set_size), Some(issued_at), Some(not_after)) = (int("epoch"), int("set_size"), int("issued_at"), int("not_after")) else {
        return Err("malformed revocation epoch".into());
    };
    if epoch < 0 || set_size < 0 {
        return Err("malformed revocation epoch".into());
    }
    let mut body = Map::new();
    for f in ["instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after"] {
        body.insert(f.into(), m.get(f).cloned().unwrap_or(Value::Null));
    }
    let bad_sig = || "revocation epoch signature invalid".to_string();
    if !bind_suite_fields(&mut body, m.get("alg"), m.get("pq_pk")).unwrap_or(false) {
        return Err(bad_sig());
    }
    let msg = domain_message(REVEPOCH_DOMAIN, body).ok_or_else(bad_sig)?;
    if !verify_pinned_suite(m.get("alg"), o.guardian_public, m.get("pq_pk"), &msg, m.get("sig"), m.get("pq_sig"), o.pq_pin).unwrap_or(false) {
        return Err(bad_sig());
    }
    if let Some(g) = o.grant_ref {
        if m.get("grant_ref").and_then(Value::as_str) != Some(g) {
            return Err("revocation epoch is for a different grant".into());
        }
    }
    if !(o.now <= not_after as f64) {
        return Err("revocation epoch expired (stale revocation root)".into());
    }
    if !(issued_at as f64 <= o.now + SKEW_MS) {
        return Err("revocation epoch issued in the future".into());
    }
    if let Some(max) = o.max_age_ms {
        check_revocation_age(Some(issued_at as f64), o.now, max, "revocation epoch")?;
    }
    if let Some(last) = o.last_accepted_epoch {
        if (epoch as f64) < last {
            return Err(format!("revocation epoch {epoch} is older than the last accepted {} (rollback)", js_num(last)));
        }
    }
    if let Some(pe) = o.pcactn_epoch {
        if !(pe >= epoch as f64) {
            return Err(format!("PCActn freshness.epoch {} predates the revocation epoch {epoch}", js_num(pe)));
        }
    }
    Ok(())
}

/// The size-bound set root: b64u(sha256("pca-revset/v1\0" || strictCanonical({size, tree}))).
fn bind_root(size: i64, tree: &str) -> Option<String> {
    let mut m = Map::new();
    m.insert("size".into(), Value::from(size));
    m.insert("tree".into(), Value::String(tree.into()));
    let mut b = b"pca-revset/v1\0".to_vec();
    b.extend_from_slice(canonicalize_strict(&Value::Object(m)).ok()?.as_bytes());
    Some(b64_encode(&sha(&b)))
}

/// A leaf proof `{id, proof: {index, size, path}}` checked against the bound root; returns the leaf index when it folds to it.
/// Strict like the reference: index and size bound to the path shape, every sibling canonical base64url of exactly 32 bytes.
fn leaf_ok(root: &str, size: i64, leaf: &Value) -> Option<(String, i64)> {
    let l = leaf.as_object()?;
    let id = l.get("id")?.as_str()?;
    let pr = l.get("proof")?.as_object()?;
    let index = pr.get("index").and_then(safe_int)?;
    if pr.get("size").and_then(safe_int)? != size || index < 0 || index >= size {
        return None;
    }
    let path = pr.get("path")?.as_array()?;
    let shape = path_shape(index as u64, size as u64);
    if shape.len() != path.len() {
        return None;
    }
    let mut h = leaf_hash(&Value::String(id.to_string()))?;
    for (i, s) in path.iter().enumerate() {
        let step = s.as_object()?;
        let side = step.get("side").and_then(Value::as_str)?;
        if side.as_bytes() != [shape[i]] {
            return None;
        }
        let sib = decode_b64u_strict(step.get("hash").and_then(Value::as_str)?, Some(32))?;
        h = if side == "L" { node_hash(&sib, &h) } else { node_hash(&h, &sib) };
    }
    (bind_root(size, &b64_encode(&h))? == root).then(|| (id.to_string(), index))
}

/// Verify `id` is NOT in the sorted revocation set `root` commits to (`verifyNonMembership`): adjacent neighbours (UTF-8 byte
/// order) with inclusion proofs against the size-bound root, or the empty-set root. Never panics; anything malformed is false.
pub fn verify_non_membership(root: &str, proof: &Value, id: &str) -> bool {
    let Some(p) = proof.as_object() else { return false };
    let Some(size) = p.get("size").and_then(safe_int).filter(|s| *s >= 0) else { return false };
    let side = |k: &str| p.get(k).filter(|v| !v.is_null());
    let (lo, hi) = (side("lo"), side("hi"));
    if size == 0 {
        return lo.is_none() && hi.is_none() && bind_root(0, &b64_encode(&sha(b""))).as_deref() == Some(root);
    }
    if lo.is_none() && hi.is_none() {
        return false;
    }
    let mut lo_idx = None;
    if let Some(l) = lo {
        match leaf_ok(root, size, l) {
            Some((lid, i)) if lid.as_bytes() < id.as_bytes() => lo_idx = Some(i),
            _ => return false,
        }
        if hi.is_none() && lo_idx != Some(size - 1) {
            return false; // id above the maximum
        }
    }
    if let Some(h) = hi {
        match leaf_ok(root, size, h) {
            Some((hid, i)) if id.as_bytes() < hid.as_bytes() => {
                if lo.is_none() && i != 0 {
                    return false; // id below the minimum
                }
                if let Some(li) = lo_idx {
                    if i != li + 1 {
                        return false;
                    }
                }
            }
            _ => return false,
        }
    }
    true
}

/// What the resource server knows about the current revocation state for one request.
#[derive(Debug, Clone, Default)]
pub struct RevocationState {
    /// A guardian-signed epoch (preferred: it dates itself).
    pub epoch: Option<Value>,
    /// A revocation root from your own trusted source. With an `epoch` it must equal the epoch's root.
    pub root: Option<String>,
    /// When your trusted source issued `root` (epoch ms); `None` = unknown age, which a staleness policy denies.
    pub root_issued_at: Option<f64>,
}

type StateFn = dyn Fn(&Value, &Value) -> Result<Option<RevocationState>, String> + Send + Sync;
type LastEpochFn = dyn Fn(&Value) -> Option<f64> + Send + Sync;
type IdsFn = dyn Fn(&Value) -> Vec<String> + Send + Sync;
type ProofFn = dyn Fn(&Value, &str) -> Option<Value> + Send + Sync;

/// The staleness gate wired into [`authorize`](crate::authorize) (`AuthorizeInput::revocation_staleness`). It runs AFTER the
/// boolean `is_revoked` hook (which keeps working unchanged) and fails the same `revocation` check.
#[derive(Clone)]
pub struct RevocationStaleness {
    policy: RevocationStalenessPolicy,
    guardian_public: Option<String>,
    guardian_pq_pin: Option<(String, Value)>,
    state: Arc<StateFn>,
    last_accepted_epoch: Option<Arc<LastEpochFn>>,
    ids: Option<Arc<IdsFn>>,
    proof_for: Option<Arc<ProofFn>>,
}

impl RevocationStaleness {
    /// `state(pcactn, grant)` returns the revocation state for this request; `Ok(None)` means no signed epoch is available
    /// (denied). A malformed policy is an error.
    pub fn new(
        policy: RevocationStalenessPolicy,
        state: impl Fn(&Value, &Value) -> Result<Option<RevocationState>, String> + Send + Sync + 'static,
    ) -> Result<Self, String> {
        policy.validate()?;
        Ok(RevocationStaleness { policy, guardian_public: None, guardian_pq_pin: None, state: Arc::new(state), last_accepted_epoch: None, ids: None, proof_for: None })
    }

    /// The pinned guardian key (b64u Ed25519) that signs revocation epochs. Required to accept a signed epoch.
    pub fn with_guardian(mut self, guardian_public: impl Into<String>) -> Self {
        self.guardian_public = Some(guardian_public.into());
        self
    }

    /// The PQ key pinned for the guardian (a post-quantum / hybrid epoch is refused without it).
    pub fn with_guardian_pq_pin(mut self, guardian: impl Into<String>, pq_pk: Value) -> Self {
        self.guardian_pq_pin = Some((guardian.into(), pq_pk));
        self
    }

    /// The newest epoch number already accepted for this grant (verifier-side monotonic pin): an older epoch is a rollback.
    pub fn with_last_accepted_epoch(mut self, f: impl Fn(&Value) -> Option<f64> + Send + Sync + 'static) -> Self {
        self.last_accepted_epoch = Some(Arc::new(f));
        self
    }

    /// Which capability ids need a non-membership proof. Default: every `id` in the PCActn's `cap_chain` (a revoked ancestor kills
    /// its descendants).
    pub fn with_ids(mut self, f: impl Fn(&Value) -> Vec<String> + Send + Sync + 'static) -> Self {
        self.ids = Some(Arc::new(f));
        self
    }

    /// The non-membership proof for a capability id, `f(pcactn, id)` (e.g. carried with the action). Without a proof source, or when
    /// it returns `None`, the request is denied (fail closed).
    pub fn with_proofs(mut self, f: impl Fn(&Value, &str) -> Option<Value> + Send + Sync + 'static) -> Self {
        self.proof_for = Some(Arc::new(f));
        self
    }

    pub fn policy(&self) -> &RevocationStalenessPolicy {
        &self.policy
    }

    /// The whole decision for one request. `server_class` is your authoritative class for the action, if any.
    pub fn check(&self, pcactn: &Value, grant: &Value, server_class: Option<&str>, now: f64) -> Result<(), String> {
        let state = (self.state)(pcactn, grant)?;
        let last = self.last_accepted_epoch.as_ref().and_then(|f| f(pcactn));
        let ids: Vec<String> = match &self.ids {
            Some(f) => f(pcactn),
            None => pcactn.get("cap_chain").and_then(Value::as_array).map_or_else(Vec::new, |c| {
                c.iter().filter_map(|x| x.get("id").and_then(Value::as_str).map(str::to_string)).collect()
            }),
        };
        let proof_for = |id: &str| self.proof_for.as_ref().and_then(|f| f(pcactn, id));
        decide_gate_ids(
            &self.policy,
            self.guardian_public.as_deref(),
            self.guardian_pq_pin.as_ref().map(|(g, k)| (g.as_str(), k)),
            last,
            pcactn,
            server_class,
            now,
            state.as_ref(),
            &ids,
            &proof_for,
        )
    }
}

/// [`decide_gate_ids`] with no capability ids to prove (the freshness step alone): signed epoch with the verifier cap, a bare
/// root with its issue time, irreversible refused on an unsigned root unless allowed, missing state denied, root / epoch root
/// mismatch.
#[allow(clippy::too_many_arguments)]
pub fn decide_gate(
    policy: &RevocationStalenessPolicy,
    guardian_public: Option<&str>,
    pq_pin: Option<(&str, &Value)>,
    last_accepted_epoch: Option<f64>,
    pcactn: &Value,
    server_class: Option<&str>,
    now: f64,
    state: Option<&RevocationState>,
) -> Result<(), String> {
    decide_gate_ids(policy, guardian_public, pq_pin, last_accepted_epoch, pcactn, server_class, now, state, &[], &|_| None)
}

/// The whole `createRevocationChecker` decision: the staleness step (signed epoch with the verifier cap, a bare root with its
/// issue time, irreversible refused on an unsigned root unless allowed, missing state denied, root / epoch root mismatch), then
/// for every id in `ids` a valid non-membership proof (`proof_for`) against the epoch's (or bare) root.
#[allow(clippy::too_many_arguments)]
pub fn decide_gate_ids(
    policy: &RevocationStalenessPolicy,
    guardian_public: Option<&str>,
    pq_pin: Option<(&str, &Value)>,
    last_accepted_epoch: Option<f64>,
    pcactn: &Value,
    server_class: Option<&str>,
    now: f64,
    state: Option<&RevocationState>,
    ids: &[String],
    proof_for: &dyn Fn(&str) -> Option<Value>,
) -> Result<(), String> {
    let cls = policy.is_on().then(|| effective_reversibility(server_class, pcactn.get("action").and_then(|a| a.get("reversibility_class"))));
    let max_age = cls.map(|c| policy.max_age_ms(c));
    let Some(state) = state else { return Err("no signed revocation epoch".into()) };
    let root = if let Some(ep) = &state.epoch {
        let Some(g) = guardian_public else { return Err("no signed revocation epoch".into()) };
        let pcactn_epoch = pcactn.get("freshness").and_then(|f| f.get("epoch")).filter(|e| !e.is_null()).map(|e| e.as_f64().unwrap_or(f64::NAN));
        check_revocation_epoch(
            ep,
            &EpochCheckOptions {
                guardian_public: g,
                now,
                grant_ref: pcactn.get("grant_ref").and_then(Value::as_str),
                last_accepted_epoch,
                pcactn_epoch,
                max_age_ms: max_age,
                pq_pin,
            },
        )?;
        let ep_root = ep.get("root").and_then(Value::as_str).unwrap_or("");
        if state.root.as_deref().is_some_and(|r| r != ep_root) {
            return Err("revocation root does not match the signed epoch".into());
        }
        Some(ep_root.to_string())
    } else {
        if let (Some(c), Some(max)) = (cls, max_age) {
            if c == Reversibility::Irreversible && !policy.allow_unsigned_root_for_irreversible {
                return Err("unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)".into());
            }
            check_revocation_age(state.root_issued_at, now, max, "revocation root")?;
        }
        state.root.clone()
    };
    let Some(root) = root.filter(|r| !r.is_empty()) else { return Err("no revocation root".into()) };
    for id in ids {
        let Some(proof) = proof_for(id) else { return Err(format!("no non-membership proof for {id}")) };
        if !verify_non_membership(&root, &proof, id) {
            return Err(format!("capability {id} is revoked or proof invalid"));
        }
    }
    Ok(())
}
