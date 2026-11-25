//! The wire, the inbox and the driver of a networked FROST DKG (port of `frost-dkg-channel.ts`): a versioned JSON envelope per message
//! (`{"v", "sid", "kind", "body"}`, strict JSON, capped at 256 KiB, bound to the session), strict decoders for each body kind, a per-link INBOX
//! (the first message per peer and kind wins, a second identical one is a `duplicate` and a different one an `equivocation`, either poisons
//! that peer for every later collect), an in-memory network for tests, and [`run_dkg_over_channel`], one party's whole ceremony over any
//! [`DkgChannel`]. The channel is synchronous (`collect` blocks up to its timeout). TLS framing is in [`crate::frost_dkg_tls`].
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::adapters::{js_json, js_string};
use crate::frost_dkg::{self as d, bv, numkey, safe_pos, seq, sort_values};
use crate::frost_net::RandomBytes;
use crate::{b64_encode, decode_b64u_strict, strict_parse_bytes};

pub const DKG_WIRE_VERSION: u32 = 1;
pub const DKG_MAX_MESSAGE_BYTES: usize = 256 * 1024;
pub const DKG_MAX_PARTICIPANTS: usize = 256;
pub const DKG_MESSAGE_KINDS: [&str; 5] = ["round1", "share", "complaints", "rebuttals", "echo"];

/// A ceremony failure. `code` is one of timeout, identity, wrong-session, duplicate, equivocation, malformed, oversize, closed, protocol,
/// disqualified; `peer` the participant to blame (`None` when none).
#[derive(Clone, Debug, PartialEq)]
pub struct DkgChannelError {
    pub code: String,
    pub peer: Option<Value>,
    pub detail: String,
}

impl DkgChannelError {
    pub fn new(code: &str, peer: Option<Value>, detail: &str) -> Self {
        DkgChannelError { code: code.into(), peer, detail: detail.into() }
    }
    fn rebind(&self, peer: &Value) -> Self {
        DkgChannelError { code: self.code.clone(), peer: Some(peer.clone()), detail: self.detail.clone() }
    }
}

impl fmt::Display for DkgChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.peer {
            None => write!(f, "dkg channel ({}): {}", self.code, self.detail),
            Some(p) => write!(f, "dkg channel ({}, peer {}): {}", self.code, js_string(p), self.detail),
        }
    }
}

impl std::error::Error for DkgChannelError {}

type CE<T> = Result<T, DkgChannelError>;

fn malformed(what: &str) -> DkgChannelError {
    DkgChannelError::new("malformed", None, what)
}

// ---- envelope ------------------------------------------------------------------------------------------------------------------

/// The wire bytes of a message: JSON of `{"v", "sid", "kind", "body"}` (member order as written, body members in the order given).
pub fn encode_dkg_message(session_id: &[u8], kind: &Value, body: &Value) -> CE<Vec<u8>> {
    let data = js_json(&json!({"v": DKG_WIRE_VERSION, "sid": b64_encode(session_id), "kind": kind, "body": body})).into_bytes();
    if data.len() > DKG_MAX_MESSAGE_BYTES {
        return Err(DkgChannelError::new("oversize", None, &format!("message of {} bytes exceeds the cap", data.len())));
    }
    Ok(data)
}

fn as_record<'a>(x: &'a Value, keys: &[&str], what: &str) -> CE<&'a serde_json::Map<String, Value>> {
    let o = x.as_object().ok_or_else(|| malformed(&format!("{what} is not an object")))?;
    if o.len() != keys.len() || !keys.iter().all(|k| o.contains_key(*k)) {
        return Err(malformed(&format!("{what} has unexpected or missing members")));
    }
    Ok(o)
}

/// Parse and check one envelope: strict JSON, exactly the four members, wire version 1, a known kind, this session. Returns `{kind, body}`.
/// `data` is `None` for something that is not bytes.
pub fn decode_dkg_message(data: Option<&[u8]>, session_id: &[u8]) -> CE<Value> {
    let data = data.ok_or_else(|| malformed("message is not bytes"))?;
    if data.len() > DKG_MAX_MESSAGE_BYTES {
        return Err(DkgChannelError::new("oversize", None, &format!("message of {} bytes exceeds the cap", data.len())));
    }
    let msg = strict_parse_bytes(data).map_err(|_| malformed("message is not strict JSON"))?;
    let o = as_record(&msg, &["v", "sid", "kind", "body"], "envelope")?;
    if o["v"].as_f64() != Some(DKG_WIRE_VERSION as f64) || !o["v"].is_number() {
        return Err(malformed("unsupported wire version"));
    }
    if !o["kind"].as_str().is_some_and(|k| DKG_MESSAGE_KINDS.contains(&k)) {
        return Err(malformed("unknown message kind"));
    }
    if o["sid"] != json!(b64_encode(session_id)) {
        return Err(DkgChannelError::new("wrong-session", None, "message names another session"));
    }
    Ok(json!({"kind": o["kind"], "body": o["body"]}))
}

fn pos_int(x: &Value, what: &str) -> CE<Value> {
    if safe_pos(x) {
        Ok(x.clone())
    } else {
        Err(malformed(&format!("{what} is not a positive integer")))
    }
}

fn b64_field(x: &Value, what: &str, length: Option<usize>) -> CE<Value> {
    if x.as_str().and_then(|s| decode_b64u_strict(s, length)).is_some() {
        Ok(x.clone())
    } else {
        Err(malformed(&format!("{what} is not canonical base64url")))
    }
}

/// A round-1 package from the wire: exact members, t commitments of 32 canonical bytes each, a 32-byte proof pair. Not validated as points.
pub fn decode_dkg_round1_package(x: &Value, t: &Value) -> CE<Value> {
    let o = as_record(x, &["identifier", "sessionId", "coefficientCommitments", "proofOfKnowledge"], "round-1 package")?;
    let pok = as_record(&o["proofOfKnowledge"], &["R", "mu"], "proof of knowledge")?;
    let cc = o["coefficientCommitments"].as_array().filter(|c| t.is_number() && Some(c.len() as f64) == t.as_f64());
    let Some(cc) = cc else { return Err(malformed(&format!("round-1 package must commit to exactly t={} coefficients", js_string(t)))) };
    Ok(json!({
        "identifier": pos_int(&o["identifier"], "identifier")?, "sessionId": b64_field(&o["sessionId"], "sessionId", None)?,
        "coefficientCommitments": cc.iter().map(|c| b64_field(c, "coefficient commitment", Some(32))).collect::<CE<Vec<_>>>()?,
        "proofOfKnowledge": {"R": b64_field(&pok["R"], "PoP R", Some(32))?, "mu": b64_field(&pok["mu"], "PoP mu", Some(32))?},
    }))
}

/// A share message from the wire (the share as bytes).
pub fn decode_dkg_share_message(x: &Value) -> CE<Value> {
    let o = as_record(x, &["from", "to", "sessionId", "share", "sig"], "share message")?;
    let share = b64_field(&o["share"], "share", Some(32))?;
    Ok(json!({
        "from": pos_int(&o["from"], "from")?, "to": pos_int(&o["to"], "to")?, "sessionId": b64_field(&o["sessionId"], "sessionId", None)?,
        "share": bv(&decode_b64u_strict(share.as_str().unwrap_or(""), None).unwrap_or_default()), "sig": b64_field(&o["sig"], "share signature", Some(64))?,
    }))
}

fn complaint_of(x: &Value) -> CE<Value> {
    let o = as_record(x, &["accused", "accuser", "sessionId", "revealedShare", "shareSig"], "complaint")?;
    Ok(json!({
        "accused": pos_int(&o["accused"], "accused")?, "accuser": pos_int(&o["accuser"], "accuser")?, "sessionId": b64_field(&o["sessionId"], "sessionId", None)?,
        "revealedShare": b64_field(&o["revealedShare"], "revealed share", Some(32))?, "shareSig": b64_field(&o["shareSig"], "share signature", Some(64))?,
    }))
}

fn rebuttal_of(x: &Value) -> CE<Value> {
    let o = as_record(x, &["accused", "accuser", "sessionId", "presentedShare", "shareSig"], "rebuttal")?;
    Ok(json!({
        "accused": pos_int(&o["accused"], "accused")?, "accuser": pos_int(&o["accuser"], "accuser")?, "sessionId": b64_field(&o["sessionId"], "sessionId", None)?,
        "presentedShare": b64_field(&o["presentedShare"], "presented share", Some(32))?, "shareSig": b64_field(&o["shareSig"], "share signature", Some(64))?,
    }))
}

fn list_of(x: &Value, key: &str, one: fn(&Value) -> CE<Value>) -> CE<Vec<Value>> {
    let o = as_record(x, &[key], key)?;
    let lst =
        o[key].as_array().filter(|l| l.len() <= DKG_MAX_PARTICIPANTS).ok_or_else(|| malformed(&format!("{key} is not a bounded list")))?;
    lst.iter().map(one).collect()
}

pub fn decode_dkg_complaints(x: &Value) -> CE<Vec<Value>> {
    list_of(x, "complaints", complaint_of)
}

pub fn decode_dkg_rebuttals(x: &Value) -> CE<Vec<Value>> {
    list_of(x, "rebuttals", rebuttal_of)
}

pub fn decode_dkg_echo(x: &Value) -> CE<Value> {
    let o = as_record(x, &["identifier", "sessionId", "transcriptDigest"], "echo")?;
    Ok(json!({
        "identifier": pos_int(&o["identifier"], "identifier")?, "sessionId": b64_field(&o["sessionId"], "sessionId", None)?,
        "transcriptDigest": b64_field(&o["transcriptDigest"], "transcript digest", Some(32))?,
    }))
}

// ---- inbox ---------------------------------------------------------------------------------------------------------------------

#[derive(Default)]
struct InboxState {
    seen: HashMap<(String, String), (String, Value)>,
    errors: HashMap<String, DkgChannelError>,
    gone: HashSet<String>,
    closed: bool,
}

/// Messages received from the authenticated links of one participant. [`DkgInbox::accept`] files a message under (kind, sender); the first
/// error per peer is sticky and is what every later [`DkgInbox::collect`] that names that peer returns.
pub struct DkgInbox {
    session_id: Vec<u8>,
    peers: Vec<Value>,
    st: Mutex<InboxState>,
    cv: Condvar,
}

impl DkgInbox {
    pub fn new(session_id: &[u8], peers: &[Value]) -> Self {
        DkgInbox { session_id: session_id.to_vec(), peers: peers.to_vec(), st: Mutex::new(InboxState::default()), cv: Condvar::new() }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, InboxState> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn fail(&self, peer: &Value, err: &DkgChannelError) {
        let mut st = self.lock();
        st.errors.entry(numkey(peer)).or_insert_with(|| err.rebind(peer));
        self.cv.notify_all();
    }

    pub fn accept(&self, sender: &Value, data: Option<&[u8]>) {
        if !self.peers.iter().any(|p| seq(sender, p)) {
            return;
        }
        let filed = || -> CE<()> {
            let m = decode_dkg_message(data, &self.session_id)?;
            let kind = m["kind"].as_str().unwrap_or("").to_string();
            let digest = b64_encode(data.unwrap_or(&[]));
            let mut st = self.lock();
            let key = (kind.clone(), numkey(sender));
            if let Some(prev) = st.seen.get(&key) {
                let code = if prev.0 == digest { "duplicate" } else { "equivocation" };
                return Err(DkgChannelError::new(code, Some(sender.clone()), &format!("second {kind} message")));
            }
            st.seen.insert(key, (digest, m["body"].clone()));
            self.cv.notify_all();
            Ok(())
        };
        if let Err(e) = filed() {
            self.fail(sender, &e);
        }
    }

    pub fn peer_gone(&self, peer: &Value) {
        self.lock().gone.insert(numkey(peer));
        self.cv.notify_all();
    }

    pub fn close(&self) {
        self.lock().closed = true;
        self.cv.notify_all();
    }

    /// The bodies of `kind` from every id in `from_ids` (ascending), waiting up to `timeout_ms` for the rest. Fails with the first sticky error
    /// of a wanted peer (lowest id first), `closed` when the channel closed or a wanted peer's link ended first, `timeout` naming the lowest
    /// missing id.
    pub fn collect(&self, kind: &str, from_ids: &[Value], timeout_ms: f64) -> CE<Vec<(Value, Value)>> {
        let want = sort_values(from_ids).unwrap_or_else(|_| from_ids.to_vec());
        let wait = if timeout_ms.is_nan() { 0.0 } else { (timeout_ms / 1000.0).clamp(0.0, 1.0e7) };
        let deadline = Instant::now() + Duration::from_secs_f64(wait);
        let mut st = self.lock();
        loop {
            for i in &want {
                if let Some(e) = st.errors.get(&numkey(i)) {
                    return Err(e.clone());
                }
            }
            let mut out: Vec<(Value, Value)> = Vec::new();
            for i in &want {
                if let Some(m) = st.seen.get(&(kind.to_string(), numkey(i))) {
                    if !out.iter().any(|(k, _)| seq(k, i)) {
                        out.push((i.clone(), m.1.clone()));
                    }
                }
            }
            if out.len() == want.len() {
                return Ok(out);
            }
            if st.closed {
                return Err(DkgChannelError::new("closed", None, "channel closed before all messages arrived"));
            }
            let present = |i: &Value| out.iter().any(|(k, _)| seq(k, i));
            if let Some(g) = want.iter().find(|i| !present(i) && st.gone.contains(&numkey(i))) {
                return Err(DkgChannelError::new("closed", Some(g.clone()), &format!("link ended before its {kind} message arrived")));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                let missing: Vec<&Value> = want.iter().filter(|i| !present(i)).collect();
                let names: Vec<String> = missing.iter().map(|m| js_string(m)).collect();
                return Err(DkgChannelError::new(
                    "timeout",
                    Some(missing[0].clone()),
                    &format!("no {kind} message from {}", names.join(",")),
                ));
            }
            st = self.cv.wait_timeout(st, left).unwrap_or_else(|e| e.into_inner()).0;
        }
    }
}

// ---- channels ------------------------------------------------------------------------------------------------------------------

/// One party's view of the link layer: its identity, its (authenticated) peers, and the five operations of the ceremony.
pub trait DkgChannel {
    fn self_id(&self) -> Value;
    fn peers(&self) -> Vec<Value>;
    fn broadcast(&self, kind: &str, body: &Value) -> CE<()>;
    fn send(&self, to: &Value, kind: &str, body: &Value) -> CE<()>;
    fn collect(&self, kind: &str, from_ids: &[Value], timeout_ms: f64) -> CE<Vec<(Value, Value)>>;
    fn close(&self);
}

/// `intercept(from, to, kind, bytes)` may drop (`None`) or replace the bytes of a delivery.
pub type Intercept = Arc<dyn Fn(&Value, &Value, &str, &[u8]) -> Option<Vec<u8>> + Send + Sync>;

struct NetShared {
    session_id: Vec<u8>,
    inboxes: HashMap<String, Arc<DkgInbox>>,
    intercept: Option<Intercept>,
}

impl NetShared {
    fn deliver(&self, from: &Value, to: &Value, data: &[u8]) {
        if let Some(ib) = self.inboxes.get(&numkey(to)) {
            ib.accept(from, Some(data));
        }
    }

    fn route(&self, from: &Value, to: &Value, kind: &str, body: &Value) -> CE<()> {
        let data = encode_dkg_message(&self.session_id, &json!(kind), body)?;
        let out = match &self.intercept {
            Some(f) => f(from, to, kind, &data),
            None => Some(data),
        };
        if let Some(bytes) = out {
            self.deliver(from, to, &bytes);
        }
        Ok(())
    }
}

/// A channel wired through in-process inboxes.
pub struct MemoryChannel {
    self_id: Value,
    peers: Vec<Value>,
    net: Arc<NetShared>,
}

impl DkgChannel for MemoryChannel {
    fn self_id(&self) -> Value {
        self.self_id.clone()
    }
    fn peers(&self) -> Vec<Value> {
        self.peers.clone()
    }
    fn broadcast(&self, kind: &str, body: &Value) -> CE<()> {
        self.peers.iter().try_for_each(|p| self.net.route(&self.self_id, p, kind, body))
    }
    fn send(&self, to: &Value, kind: &str, body: &Value) -> CE<()> {
        if !self.peers.iter().any(|p| seq(to, p)) {
            return Err(DkgChannelError::new("identity", Some(to.clone()), "not a connected peer"));
        }
        self.net.route(&self.self_id, to, kind, body)
    }
    fn collect(&self, kind: &str, from_ids: &[Value], timeout_ms: f64) -> CE<Vec<(Value, Value)>> {
        self.net.inboxes[&numkey(&self.self_id)].collect(kind, from_ids, timeout_ms)
    }
    fn close(&self) {
        self.net.inboxes[&numkey(&self.self_id)].close()
    }
}

/// Channels for every id wired through in-process inboxes.
pub struct MemoryNetwork {
    /// In ascending id order.
    pub channels: Vec<MemoryChannel>,
    net: Arc<NetShared>,
}

impl MemoryNetwork {
    /// Inject a message as if `from` sent it.
    pub fn deliver(&self, from: &Value, to: &Value, data: &[u8]) {
        self.net.deliver(from, to, data)
    }
}

pub fn create_memory_dkg_network(ids: &[Value], session_id: &[u8], intercept: Option<Intercept>) -> MemoryNetwork {
    let ordered = sort_values(ids).unwrap_or_else(|_| ids.to_vec());
    let inboxes: HashMap<String, Arc<DkgInbox>> = ordered
        .iter()
        .map(|i| (numkey(i), Arc::new(DkgInbox::new(session_id, &ordered.iter().filter(|p| !seq(p, i)).cloned().collect::<Vec<_>>()))))
        .collect();
    let net = Arc::new(NetShared { session_id: session_id.to_vec(), inboxes, intercept });
    let channels = ordered
        .iter()
        .map(|i| MemoryChannel { self_id: i.clone(), peers: ordered.iter().filter(|p| !seq(p, i)).cloned().collect(), net: net.clone() })
        .collect();
    MemoryNetwork { channels, net }
}

// ---- driver --------------------------------------------------------------------------------------------------------------------

/// What a ceremony can fail with: a channel failure naming the peer to blame, or any other refusal of a ceremony step.
#[derive(Clone, Debug, PartialEq)]
pub enum DkgError {
    Channel(DkgChannelError),
    Other(String),
}

impl From<DkgChannelError> for DkgError {
    fn from(e: DkgChannelError) -> Self {
        DkgError::Channel(e)
    }
}

impl From<String> for DkgError {
    fn from(e: String) -> Self {
        DkgError::Other(e)
    }
}

impl fmt::Display for DkgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DkgError::Channel(e) => e.fmt(f),
            DkgError::Other(s) => f.write_str(s),
        }
    }
}

fn bind<T>(peer: &Value, r: CE<T>) -> CE<T> {
    r.map_err(|e| e.rebind(peer))
}

fn pe(code: &str, peer: &Value, what: &str) -> DkgChannelError {
    DkgChannelError::new(code, Some(peer.clone()), what)
}

/// One party's whole DKG over `ch`: round 1 and the proofs of knowledge, the signed shares, the blame round (a bad share must be provable, else
/// the ceremony aborts), the rebuttals, the qualified set, the echo agreement and the verified finalize. Returns `{keyPackage, qualified,
/// complaints}`; fails with a [`DkgChannelError`] naming the peer to blame.
pub fn run_dkg_over_channel(
    ch: &dyn DkgChannel,
    t: &Value,
    participants: &[Value],
    session_id: &[u8],
    timeout_ms: Option<f64>,
    coefficients: Option<&Value>,
    random: &RandomBytes,
) -> Result<Value, DkgError> {
    let me = ch.self_id();
    let proto = |what: &str| DkgError::Channel(DkgChannelError::new("protocol", None, what));
    let ids = sort_values(participants).map_err(DkgError::Other)?;
    let ids_bad = ids.len() > DKG_MAX_PARTICIPANTS || ids.iter().enumerate().any(|(k, i)| !safe_pos(i) || (k > 0 && seq(&ids[k - 1], i)));
    if ids_bad {
        return Err(proto("participants must be distinct positive integers within the cap"));
    }
    if !ids.iter().any(|i| seq(&me, i)) {
        return Err(proto("this participant is not in the participant list"));
    }
    if !safe_pos(t) || t.as_f64().unwrap_or(0.0) > ids.len() as f64 {
        return Err(proto("need 1 <= t <= n"));
    }
    let others: Vec<Value> = ids.iter().filter(|i| !seq(i, &me)).cloned().collect();
    let peers = ch.peers();
    if peers.len() != others.len() || !others.iter().enumerate().all(|(k, o)| seq(&peers[k], o)) {
        return Err(proto("the channel peers are not exactly the other participants"));
    }
    let sid_b64 = b64_encode(session_id);
    let sid_v = bv(session_id);
    let tmo = timeout_ms.unwrap_or(30000.0);
    let n = json!(ids.len());

    let (my_pkg, state) =
        d::dkg_round1(&me, t, &n, &sid_v, Some(&json!({"coefficients": coefficients.cloned().unwrap_or(Value::Null)})), random)?;
    ch.broadcast("round1", &my_pkg)?;
    let mut pkgs: Vec<Value> = vec![my_pkg];
    for (frm, body) in ch.collect("round1", &others, tmo)? {
        let p = bind(&frm, decode_dkg_round1_package(&body, t))?;
        if !seq(&p["identifier"], &frm) {
            return Err(pe("identity", &frm, &format!("package claims identifier {}", js_string(&p["identifier"]))).into());
        }
        if p["sessionId"] != json!(sid_b64) {
            return Err(pe("wrong-session", &frm, "package names another session").into());
        }
        pkgs.push(p);
    }
    let by_id: HashMap<String, Value> = pkgs.iter().map(|p| (numkey(&p["identifier"]), p.clone())).collect();
    let pok: Vec<Value> = pkgs.iter().filter(|p| d::dkg_verify_round1(&p["identifier"], p, &sid_v)).cloned().collect();
    let ok_peers: Vec<Value> = others.iter().filter(|o| pok.iter().any(|p| seq(&p["identifier"], o))).cloned().collect();
    let pkgs_v = Value::Array(pkgs.clone());

    for s in d::dkg_round2(&state, &Value::Array(pok))? {
        let share = d::bytes_of(&s["share"]).unwrap_or_default();
        ch.send(
            &s["to"],
            "share",
            &json!({"from": s["from"], "to": s["to"], "sessionId": s["sessionId"], "share": b64_encode(&share), "sig": s["sig"]}),
        )?;
    }
    let mut inbox: Vec<Value> = Vec::new();
    let mut mine: Vec<Value> = Vec::new();
    for (frm, body) in ch.collect("share", &ok_peers, tmo)? {
        let m = bind(&frm, decode_dkg_share_message(&body))?;
        if !seq(&m["from"], &frm) {
            return Err(pe("identity", &frm, &format!("share claims sender {}", js_string(&m["from"]))).into());
        }
        if !seq(&m["to"], &me) {
            return Err(pe("identity", &frm, &format!("share is addressed to {}", js_string(&m["to"]))).into());
        }
        if m["sessionId"] != json!(sid_b64) {
            return Err(pe("wrong-session", &frm, "share names another session").into());
        }
        let received = json!({"from": frm, "sessionId": m["sessionId"], "share": m["share"], "sig": m["sig"]});
        let sender = &by_id[&numkey(&frm)];
        if d::dkg_verify_share(&received, sender, &me, &sid_v) {
            inbox.push(received);
            continue;
        }
        let c = d::dkg_file_complaint(&json!({
            "accused": frm, "accuser": me, "receivedShare": m["share"], "shareSig": m["sig"],
            "senderCommitments": sender["coefficientCommitments"], "sessionId": sid_v,
        }))?;
        if d::dkg_verify_complaint(&c, &pkgs_v)["justified"] != json!(true) {
            return Err(pe("protocol", &frm, "share failed verification and is not admissible blame").into());
        }
        mine.push(c);
    }

    ch.broadcast("complaints", &json!({"complaints": mine}))?;
    let mut complaints: Vec<Value> = mine.clone();
    for (frm, body) in ch.collect("complaints", &others, tmo)? {
        let lst = bind(&frm, decode_dkg_complaints(&body))?;
        let mut pairs: HashSet<String> = HashSet::new();
        for c in lst {
            if !seq(&c["accuser"], &frm) {
                return Err(pe("identity", &frm, &format!("complaint filed as {}", js_string(&c["accuser"]))).into());
            }
            if c["sessionId"] != json!(sid_b64) {
                return Err(pe("wrong-session", &frm, "complaint names another session").into());
            }
            if seq(&c["accused"], &frm) || !ids.iter().any(|i| seq(&c["accused"], i)) {
                return Err(pe("protocol", &frm, "complaint names an invalid accused").into());
            }
            if !pairs.insert(js_string(&c["accused"])) {
                return Err(pe("duplicate", &frm, "two complaints against one accused").into());
            }
            complaints.push(c);
        }
    }
    let mut rebuttals: Vec<Value> = Vec::new();
    for c in complaints.iter().filter(|c| seq(&c["accused"], &me)) {
        rebuttals.push(d::dkg_rebut(&me, c, &state)?);
    }
    ch.broadcast("rebuttals", &json!({"rebuttals": rebuttals}))?;
    let mut all_rebuttals = rebuttals.clone();
    for (frm, body) in ch.collect("rebuttals", &others, tmo)? {
        for r in bind(&frm, decode_dkg_rebuttals(&body))? {
            if !seq(&r["accused"], &frm) {
                return Err(pe("identity", &frm, &format!("rebuttal made as {}", js_string(&r["accused"]))).into());
            }
            if r["sessionId"] != json!(sid_b64) {
                return Err(pe("wrong-session", &frm, "rebuttal names another session").into());
            }
            all_rebuttals.push(r);
        }
    }

    let complaints_v = Value::Array(complaints.clone());
    let qualified = d::dkg_qualified_set(&Value::Array(ids.clone()), &complaints_v, &pkgs_v, &Value::Array(all_rebuttals))?;
    if !qualified.iter().any(|q| seq(q, &me)) {
        return Err(pe("disqualified", &me, "this participant was disqualified by the blame round").into());
    }
    if (qualified.len() as f64) < t.as_f64().unwrap_or(0.0) {
        return Err(proto("fewer than t participants remain qualified"));
    }

    let echo = d::dkg_echo(
        &json!({"identifier": me, "round1Packages": pkgs, "complaints": complaints, "qualified": qualified, "sessionId": sid_v}),
    )?;
    ch.broadcast("echo", &echo)?;
    let mut echoes: Vec<Value> = vec![echo];
    let echo_from: Vec<Value> = qualified.iter().filter(|q| !seq(q, &me)).cloned().collect();
    for (frm, body) in ch.collect("echo", &echo_from, tmo)? {
        let e = bind(&frm, decode_dkg_echo(&body))?;
        if !seq(&e["identifier"], &frm) {
            return Err(pe("identity", &frm, &format!("echo claims identifier {}", js_string(&e["identifier"]))).into());
        }
        echoes.push(e);
    }
    let qualified_v = Value::Array(qualified.clone());
    let agreement = d::dkg_check_echoes(&qualified_v, &Value::Array(echoes.clone()), &sid_v);
    if agreement["agreed"] != json!(true) {
        return Err(DkgChannelError::new("equivocation", None, agreement["reason"].as_str().unwrap_or("")).into());
    }
    let key_package =
        d::dkg_finalize(&me, &state, &Value::Array(inbox), &pkgs_v, &qualified_v, &json!({"echoes": echoes, "complaints": complaints}))?;
    Ok(json!({"keyPackage": key_package, "qualified": qualified, "complaints": complaints}))
}
