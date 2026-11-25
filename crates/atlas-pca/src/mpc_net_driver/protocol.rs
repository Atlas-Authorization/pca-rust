//! The DISTRIBUTED malicious-with-abort (SPDZ-style) composition protocol (research prototype).
//!
//! Same circuit and semantics as [`crate::mpc::compose_secure_malicious`] (allow = AND, t = MAX, r = MAX via thermometers; authenticated
//! Beaver multiplication; batched MAC-check before any output), but each party is its OWN node holding ONLY its own shares and every
//! opening is a real message over the TLS mesh. Rounds (n parties, C = 1 + 3 + Q independent chains, k = MAC_KEYS global keys):
//!
//! - `prep`: dealer to party (trusted-dealer mode), or the OT offline phase of [`super::offline`] (no-dealer mode, the default)
//! - `coin1-*`: commit/open of a random seed, the public challenges of the triple sacrifice
//! - `sac-rho`, `sac-tau`: value shares of rho = e*a - a-hat and tau = e*c - c-hat - rho*b; every tau must be 0
//! - `inputs` (dealer) / `in-check` (no-dealer): masked inputs / the opening of a masked random combination of the inputs
//! - `mul0..`: value shares of d = x-a, e = y-b for all chains at once; `out`: value shares of the output bits
//! - `<rd>.t`: after every opening, the pairwise tags; each receiver verifies the sender's share at once and blames it if one fails
//! - `coin-c/o`, `sig-c/o`: the MAC-check challenges and the committed residual shares (sums must be 0)
//! - `digest`: hash of the whole broadcast transcript; any disagreement aborts
//! - `blame`: only after a failed MAC-check: every party opens its combined MAC shares with their pairwise tags
//!
//! No output is decoded until the MAC-check and the transcript echo pass. HONEST LIMITS: no security proof; the echo broadcast is a hash
//! exchange; the trusted dealer is trusted for privacy; in no-dealer mode a wrong OT operand in the offline products is named only
//! for n = 2 (or by the forensic audit of the discarded triple).
use super::mesh::Mesh;
use super::prep::{Offline, Prep};
use super::{local, nab, CRASH_DETAIL, NULL, SILENT_DETAIL};
use crate::mpc::{
    auth_share, fadd, field_random, fmul, fsub, gen_triple_with_partners, mac_keys, setup_mac, thermometer_decode, thermometer_encode, AuthSV,
    ComposedDecision, DealerFault, DecisionVector, FieldSource, DEFAULT_Q, MAC_KEYS, PRIME, SACRIFICE_PARTNERS,
};
use crate::mpc_net::{
    audit_disclosures, aw_flat, aw_parse, aw_width, blame_from, hx, pa_flat, pa_parse, pa_verify, pa_width, sharings_per_triple, unhx_array, w_add,
    w_add_public, w_neg, w_scale, w_sub, Aw, NetAbort, NetAbortOpts, Pa, PaEnv, SlotDisclosure, DEFAULT_FORENSIC_DEADLINE_MS,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Instant;

/// Thermometer width of the `t` component.
pub const T_M: usize = 3;
/// Hex numbers per `prep` frame (keeps every frame far below the frame cap).
const PREP_CHUNK: usize = 30_000;

/// Number of independent circuit chains (= output bits = input bits per owner).
pub fn chain_count(q: i64) -> usize {
    1 + T_M + q as usize
}

/// Test-only protocol-level misbehaviour for a (malicious) party. Never set in production.
///
/// Kinds: `open-lie`, `mac-lie`, `bad-tag`, `sigma-lie`, `offline-lie`, `ot-u-lie`, `ot-proof-lie`, `equivocate`, `bad-coin-open`,
/// `bad-sigma-open`, `short-array`, `noncanonical`, `crash`, `silent`. A `crash` / `silent` behaviour surfaces as a local abort whose
/// detail is [`CRASH_DETAIL`] / [`SILENT_DETAIL`]; the node entry point then dies or idles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Behavior {
    pub kind: String,
    pub round: Option<String>,
}

impl Behavior {
    pub fn new(kind: &str, round: Option<&str>) -> Self {
        Behavior { kind: kind.to_string(), round: round.map(String::from) }
    }

    pub(super) fn is(&self, kind: &str) -> bool {
        self.kind == kind
    }

    fn at(&self, kind: &str, rd: &str) -> bool {
        self.kind == kind && self.round.as_deref() == Some(rd)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RoundStat {
    pub rd: String,
    pub ms: f64,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

#[derive(Debug, Clone)]
pub struct PartyResult {
    pub id: i64,
    pub n: usize,
    pub q: i64,
    pub composed: ComposedDecision,
    pub rounds: Vec<RoundStat>,
    pub transcript_digest: String,
    pub wall_ms: f64,
    pub multiplications: usize,
    pub opens: usize,
    pub offline_mode: Offline,
    pub mac_keys: usize,
    pub sacrificed_triples: usize,
    pub sacrifice_partners: usize,
    pub identifiable_abort: bool,
}

impl PartyResult {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "n": self.n,
            "Q": self.q,
            "composed": {"allow": self.composed.allow, "t": self.composed.t, "rQuant": self.composed.r_quant},
            "rounds": self.rounds.iter().map(|r| json!({"rd": r.rd, "ms": r.ms, "bytesOut": r.bytes_out, "bytesIn": r.bytes_in})).collect::<Vec<_>>(),
            "transcriptDigest": self.transcript_digest,
            "wallMs": self.wall_ms,
            "multiplications": self.multiplications,
            "opens": self.opens,
            "offlineMode": self.offline_mode.as_str(),
            "macKeys": self.mac_keys,
            "sacrificedTriples": self.sacrificed_triples,
            "sacrificePartners": self.sacrifice_partners,
            "identifiableAbort": self.identifiable_abort,
        })
    }
}

// ---- parse errors ---------------------------------------------------------------------------------------------------------------

/// A failure while parsing a peer's message: an abort to raise as is, or a plain message that becomes `malformed` naming the peer.
#[derive(Debug)]
pub enum PErr {
    Abort(NetAbort),
    Msg(String),
}

impl From<String> for PErr {
    fn from(s: String) -> Self {
        PErr::Msg(s)
    }
}

impl From<&str> for PErr {
    fn from(s: &str) -> Self {
        PErr::Msg(s.to_string())
    }
}

impl From<NetAbort> for PErr {
    fn from(a: NetAbort) -> Self {
        PErr::Abort(a)
    }
}

pub type PR<T> = Result<T, PErr>;

/// A malformed message from `p`.
pub(super) fn bad(id: i64, p: i64, what: &str) -> PErr {
    PErr::Abort(nab("malformed", Some(p), id, what))
}

/// An array of exactly `len` canonical field elements from `p`.
pub(super) fn arr(id: i64, p: i64, raw: &Value, len: usize) -> PR<Vec<u64>> {
    unhx_array(raw, len).ok_or_else(|| bad(id, p, &format!("expected {len} canonical field elements")))
}

pub(super) fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A 64-digit lowercase hex string, decoded.
pub(super) fn hex64(raw: &Value) -> Option<(String, Vec<u8>)> {
    let s = raw.as_str()?;
    if s.len() != 64 || !s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let b = (0..32).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16)).collect::<Result<Vec<u8>, _>>().ok()?;
    Some((s.to_string(), b))
}

/// SHA-256 over the parts, each followed by a zero byte (domain separation of the variable-length parts).
pub(super) fn sha(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
        h.update([0u8]);
    }
    h.finalize().to_vec()
}

pub(super) fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("operating-system randomness unavailable");
    b
}

/// Uniform non-zero field element `j` of the public challenge stream `label` derived from `seed` (rejection on p).
fn challenge(seed: &[u8], label: &str, j: usize) -> u64 {
    let mut ctr = 0u64;
    loop {
        let h = sha(&[b"chal", seed, format!("{label}:{j}:{ctr}").as_bytes()]);
        let x = u64::from_be_bytes(h[0..8].try_into().expect("8 bytes")) & ((1u64 << 61) - 1);
        if x < PRIME && x != 0 {
            return x;
        }
        ctr += 1;
    }
}

fn hxs(v: &[u64]) -> Value {
    Value::Array(v.iter().map(|x| Value::String(hx(*x as i128))).collect())
}

// ---- dealer ---------------------------------------------------------------------------------------------------------------------

pub struct DealerConfig {
    /// Required `true`: the dealer sees every share and key.
    pub insecure_trusted_dealer: bool,
    pub n: usize,
    pub q: Option<i64>,
    /// Deterministic stream for reproducible tests; omit in real runs (OS CSPRNG).
    pub seed: Option<u64>,
    /// TEST ONLY: a LYING dealer that authenticates a wrong product c = a*b + delta.
    pub fault: Option<DealerFault>,
    /// TEST ONLY: a dealer that deals party 0 a MAC share of input mask number `mac_fault_at_input` that does not match its value.
    pub mac_fault_at_input: Option<usize>,
}

fn deal_pa(x: &[u64], deltas: &[u64], rng: &mut dyn FieldSource) -> Vec<Pa> {
    let n = x.len();
    let k: Vec<Vec<u64>> = (0..n).map(|i| (0..n).map(|j| if i == j { 0 } else { rng.next() }).collect()).collect();
    (0..n)
        .map(|p| Pa {
            x: x[p],
            tag: (0..n).map(|j| if j == p { 0 } else { fadd(k[p][j], fmul(deltas[j], x[p])) }).collect(),
            key: (0..n).map(|j| if j == p { 0 } else { k[j][p] }).collect(),
        })
        .collect()
}

fn deal_aw(sv: &AuthSV, deltas: &[u64], rng: &mut dyn FieldSource) -> Vec<Aw> {
    let mut comps = vec![deal_pa(&sv.value, deltas, rng), deal_pa(&sv.mac, deltas, rng)];
    for e in &sv.extra_mac {
        comps.push(deal_pa(e, deltas, rng));
    }
    (0..sv.value.len()).map(|p| Aw { v: comps[0][p].clone(), m: comps[1..].iter().map(|c| c[p].clone()).collect() }).collect()
}

/// The TRUSTED DEALER role: samples the MAC keys, the verification keys, sacrifice-certified authenticated triples and authenticated
/// input masks, and ships each party only its own slice. It never sees any party's input bit (inputs are masked), but it knows every
/// key and share, so it can break privacy and integrity if it colludes with parties. A dealer that deals a wrong triple is caught by the
/// parties' sacrifice check.
pub async fn run_dealer(mesh: &Mesh, cfg: DealerConfig) -> Result<(), NetAbort> {
    let me = mesh.self_id();
    if !cfg.insecure_trusted_dealer {
        return Err(local(
            me,
            "runDealer requires insecure_trusted_dealer: true (a dealer sees every share and MAC key; the default offline phase has no dealer)",
        ));
    }
    let n = cfg.n;
    let q = cfg.q.unwrap_or(DEFAULT_Q);
    let c = chain_count(q);
    let le = |e: crate::mpc::MpcError| local(me, &e.to_string());
    let mut rng = field_random(cfg.seed);
    let ctx = setup_mac(n as i64, rng.as_mut(), MAC_KEYS).map_err(le)?;
    let keys = mac_keys(&ctx);
    let deltas: Vec<u64> = (0..n)
        .map(|_| loop {
            let d = rng.next();
            if d != 0 {
                break d;
            }
        })
        .collect();
    let mut per_party: Vec<Vec<u64>> = (0..n).map(|p| vec![deltas[p]]).collect();
    let alpha_pa: Vec<Vec<Pa>> = keys.iter().map(|k| deal_pa(&k.alpha_shares, &deltas, rng.as_mut())).collect();
    for p in 0..n {
        for a in &alpha_pa {
            per_party[p].extend(pa_flat(&a[p], p, n, true).map_err(|e| local(me, &e))?);
        }
    }
    let n_triples = (n - 1) * c;
    for _ in 0..n_triples {
        let tr = gen_triple_with_partners(&ctx, rng.as_mut(), SACRIFICE_PARTNERS, cfg.fault.as_ref()).map_err(le)?;
        let mut sharings = vec![&tr.keep.a, &tr.keep.b, &tr.keep.c];
        for pt in &tr.partners {
            sharings.push(&pt.a);
            sharings.push(&pt.c);
        }
        for sv in sharings {
            let aws = deal_aw(sv, &deltas, rng.as_mut());
            for p in 0..n {
                per_party[p].extend(aw_flat(&aws[p], p, n, true).map_err(|e| local(me, &e))?);
            }
        }
    }
    let mut masks_by_owner: Vec<Vec<u64>> = vec![vec![]; n];
    for qi in 0..n * c {
        let owner = qi / c;
        let r = rng.next();
        masks_by_owner[owner].push(r);
        let mut sv = auth_share(r, &ctx, rng.as_mut()).map_err(le)?;
        if cfg.mac_fault_at_input == Some(qi) {
            sv.mac[0] = fadd(sv.mac[0], 1);
        }
        let aws = deal_aw(&sv, &deltas, rng.as_mut());
        for p in 0..n {
            per_party[p].extend(aw_flat(&aws[p], p, n, true).map_err(|e| local(me, &e))?);
        }
    }
    for p in 0..n {
        per_party[p].extend(masks_by_owner[p].iter().copied());
    }
    for (p, nums) in per_party.iter().enumerate() {
        let hexes: Vec<String> = nums.iter().map(|v| hx(*v as i128)).collect();
        let chunks = hexes.len().div_ceil(PREP_CHUNK).max(1);
        let first: Vec<&String> = hexes.iter().take(PREP_CHUNK).collect();
        mesh.send(p as i64, "prep", json!({"total": hexes.len(), "chunks": chunks, "nums": first})).await?;
        for ci in 1..chunks {
            let part: Vec<&String> = hexes.iter().skip(ci * PREP_CHUNK).take(PREP_CHUNK).collect();
            mesh.send(p as i64, &format!("prep.{ci}"), json!(part)).await?;
        }
    }
    mesh.finish().await;
    Ok(())
}

// ---- party ----------------------------------------------------------------------------------------------------------------------

pub struct PartyConfig {
    pub id: i64,
    pub n: usize,
    pub q: Option<i64>,
    pub input: DecisionVector,
    /// Node id of the dealer (default n).
    pub dealer_id: Option<i64>,
    /// Which offline phase to run (default no-dealer). `TrustedDealer` also needs `insecure_trusted_dealer`.
    pub offline: Option<Offline>,
    /// Explicit opt-in to the trusted-dealer offline phase: one process then sees every share and MAC key.
    pub insecure_trusted_dealer: bool,
    /// TEST ONLY: refused unless `unsafe_test_hooks` is true.
    pub behavior: Option<Behavior>,
    pub unsafe_test_hooks: bool,
    pub session_id: String,
    /// Deadline (ms) every party has to commit to and open its forensic disclosure; shared by all parties (default 30 s).
    pub forensic_deadline_ms: Option<i64>,
}

struct Opened {
    val: u64,
    /// My MAC share (with its pairwise tags / keys) under each key, as used at this opening.
    mac: Vec<Pa>,
}

/// The state of one party's run: the mesh, the broadcast transcript, the round statistics and every opened value.
pub struct Run<'a> {
    pub(super) mesh: &'a Mesh,
    pub(super) id: i64,
    pub(super) n: usize,
    pub(super) session_id: String,
    pub(super) beh: Option<Behavior>,
    pub(super) others: Vec<i64>,
    transcript: Sha256,
    rounds: Vec<RoundStat>,
    opened: Vec<Opened>,
}

impl<'a> Run<'a> {
    fn new(mesh: &'a Mesh, cfg: &PartyConfig) -> Self {
        Run {
            mesh,
            id: cfg.id,
            n: cfg.n,
            session_id: cfg.session_id.clone(),
            beh: cfg.behavior.clone(),
            others: (0..cfg.n as i64).filter(|i| *i != cfg.id).collect(),
            transcript: Sha256::new(),
            rounds: vec![],
            opened: vec![],
        }
    }

    pub(super) fn crash_if(&self, rd: &str) -> Result<(), NetAbort> {
        match &self.beh {
            Some(b) if b.at("crash", rd) => Err(local(self.id, CRASH_DETAIL)),
            Some(b) if b.at("silent", rd) => Err(local(self.id, SILENT_DETAIL)),
            _ => Ok(()),
        }
    }

    fn totals(&self) -> (u64, u64) {
        self.mesh.stats().iter().fold((0, 0), |a, s| (a.0 + s.app_bytes_out, a.1 + s.app_bytes_in))
    }

    pub(super) async fn abort<T>(&self, e: NetAbort) -> Result<T, NetAbort> {
        Err(self.mesh.abort(e).await)
    }

    /// One all-to-all round among the parties: send `mine(peer)` to each peer, collect and validate theirs. `hashed = false` keeps a
    /// round (the peer-specific pairwise tags) out of the echoed transcript.
    pub(super) async fn exchange<T>(
        &mut self,
        rd: &str,
        mine: &dyn Fn(i64) -> Value,
        parse: &dyn Fn(i64, &Value) -> PR<T>,
        common: &Value,
        hashed: bool,
        timeout_ms: Option<u64>,
    ) -> Result<BTreeMap<i64, T>, NetAbort> {
        self.crash_if(rd)?;
        let a = self.totals();
        let s = Instant::now();
        for p in self.others.clone() {
            self.mesh.send(p, rd, mine(p)).await?;
        }
        let raw = self.mesh.collect(rd, &self.others, timeout_ms).await?;
        let mut parsed = BTreeMap::new();
        for p in &self.others {
            match parse(*p, &raw[p]) {
                Ok(v) => {
                    parsed.insert(*p, v);
                }
                Err(PErr::Abort(e)) => return self.abort(e).await,
                Err(PErr::Msg(m)) => return self.abort(nab("malformed", Some(*p), self.id, &format!("round '{rd}': {m}"))).await,
            }
        }
        if hashed {
            // transcript: party order, canonical JSON of what each party broadcast in this round
            self.transcript.update(rd.as_bytes());
            for p in 0..self.n as i64 {
                self.transcript.update(format!("|{p}:").as_bytes());
                let v = if p == self.id { common } else { &raw[&p] };
                self.transcript.update(crate::js_stringify(v).as_bytes());
            }
        }
        let b = self.totals();
        self.rounds.push(RoundStat { rd: rd.to_string(), ms: s.elapsed().as_secs_f64() * 1000.0, bytes_out: b.0 - a.0, bytes_in: b.1 - a.1 });
        Ok(parsed)
    }

    /// Open authenticated values: broadcast value shares, verify pairwise tags (when tagged), record for the MAC-check.
    async fn open_many(&mut self, prep: &Prep, rd: &str, ws: &[Aw]) -> Result<Vec<u64>, NetAbort> {
        let (id, n) = (self.id, self.n);
        let beh = self.beh.clone();
        let mut send_vals: Vec<u64> = ws.iter().map(|x| x.v.x).collect();
        let mut macs: Vec<Vec<Pa>> = ws.iter().map(|x| x.m.clone()).collect();
        if let Some(b) = beh.as_ref().filter(|b| b.round.as_deref() == Some(rd)) {
            if b.is("open-lie") && !send_vals.is_empty() {
                send_vals[0] = fadd(send_vals[0], 1);
            }
            if b.is("mac-lie") && !macs.is_empty() && !macs[0].is_empty() {
                macs[0][0].x = fadd(macs[0][0].x, 1);
            }
        }
        let common: Vec<String> = send_vals.iter().map(|v| hx(*v as i128)).collect();
        let common_v = json!(common);
        let first_peer = self.others.first().copied();
        let mine = |peer: i64| -> Value {
            if let Some(b) = beh.as_ref().filter(|b| b.round.as_deref() == Some(rd)) {
                if b.is("equivocate") && Some(peer) == first_peer {
                    let mut c = common.clone();
                    if let Some(f) = send_vals.first() {
                        c[0] = hx(fadd(*f, 1) as i128);
                    }
                    return json!(c);
                }
                if b.is("short-array") {
                    return json!(common.iter().skip(1).collect::<Vec<_>>());
                }
                if b.is("noncanonical") {
                    let mut c = common.clone();
                    if !c.is_empty() {
                        c[0] = hx(PRIME as i128);
                    }
                    return json!(c);
                }
            }
            common_v.clone()
        };
        let len = ws.len();
        let got = self.exchange(rd, &mine, &|p, raw| arr(id, p, raw, len), &common_v, true, None).await?;
        if prep.tagged {
            let env = PaEnv { id: id as usize, n, delta: prep.delta, tagged: prep.tagged };
            // pairwise tags: peer-specific, so a separate un-echoed round; each receiver verifies at once
            let tag_msg = |peer: i64| -> Value {
                let v: Vec<String> = ws
                    .iter()
                    .enumerate()
                    .map(|(i, x)| {
                        let t = x.v.tag[peer as usize];
                        hx((if beh.as_ref().is_some_and(|b| b.at("bad-tag", rd)) && i == 0 { fadd(t, 1) } else { t }) as i128)
                    })
                    .collect();
                json!(v)
            };
            let tags = self.exchange(&format!("{rd}.t"), &tag_msg, &|p, raw| arr(id, p, raw, len), &NULL, false, None).await?;
            for p in self.others.clone() {
                for (i, w) in ws.iter().enumerate() {
                    if !pa_verify(&env, &w.v, p as usize, got[&p][i], tags[&p][i]).map_err(|e| local(id, &e))? {
                        return self
                            .abort(nab(
                                "mac-check",
                                Some(p),
                                id,
                                &format!("pairwise MAC on party {p}'s opened share failed in round '{rd}' (index {i}): the share or its tag is not what the dealer issued"),
                            ))
                            .await;
                    }
                }
            }
        }
        let mut out = Vec::with_capacity(ws.len());
        for i in 0..ws.len() {
            let mut sum = send_vals[i];
            for p in &self.others {
                sum = fadd(sum, got[p][i]);
            }
            out.push(sum);
            self.opened.push(Opened { val: sum, mac: macs[i].clone() });
        }
        Ok(out)
    }

    /// Commit / open of a random seed, giving a joint public seed.
    async fn coin(&mut self, label: &str, tamper_open: bool) -> Result<Vec<u8>, NetAbort> {
        let id = self.id;
        let sid = self.session_id.clone();
        let my_seed = rand32();
        let my_seed_hex = hexs(&my_seed);
        let commit_of = |p: i64, seed: &[u8]| hexs(&sha(&[b"seed", sid.as_bytes(), label.as_bytes(), p.to_string().as_bytes(), seed]));
        let seed_commit = commit_of(id, &my_seed);
        let commits = self
            .exchange(
                &format!("{label}-c"),
                &|_| json!(seed_commit),
                &|p, raw| hex64(raw).map(|x| x.0).ok_or_else(|| bad(id, p, "bad commitment")),
                &json!(seed_commit),
                true,
                None,
            )
            .await?;
        let lie = tamper_open && self.beh.as_ref().is_some_and(|b| b.is("bad-coin-open"));
        let open_msg = |_: i64| -> Value {
            if lie {
                json!(hexs(&rand32()))
            } else {
                json!(my_seed_hex)
            }
        };
        let seeds = self
            .exchange(
                &format!("{label}-o"),
                &open_msg,
                &|p, raw| {
                    let (_, sd) = hex64(raw).ok_or_else(|| bad(id, p, "bad seed"))?;
                    if commit_of(p, &sd) != commits[&p] {
                        return Err(PErr::Abort(nab("commitment", Some(p), id, &format!("party {p} opened a coin seed that does not match its commitment"))));
                    }
                    Ok(sd)
                },
                &json!(my_seed_hex),
                true,
                None,
            )
            .await?;
        let lbl = label.as_bytes();
        let mut parts: Vec<Vec<u8>> = vec![b"joint".to_vec(), sid.as_bytes().to_vec(), lbl.to_vec()];
        for p in 0..self.n as i64 {
            parts.push(if p == id { my_seed.to_vec() } else { seeds[&p].clone() });
        }
        let refs: Vec<&[u8]> = parts.iter().map(|v| v.as_slice()).collect();
        Ok(sha(&refs))
    }
}

/// The offline material of a trusted dealer, read from its `prep` frames.
async fn receive_dealer_prep(run: &Run<'_>, c: usize, dealer_id: i64) -> Result<Prep, NetAbort> {
    let (id, n) = (run.id, run.n);
    let (k, partners) = (MAC_KEYS as usize, SACRIFICE_PARTNERS as usize);
    let aw = aw_width(n, k, true);
    let n_triples = (n - 1) * c;
    let n_inputs = n * c;
    let total = 1 + k * pa_width(n, true) + n_triples * sharings_per_triple(partners) * aw + n_inputs * aw + c;
    let first = run.mesh.recv(dealer_id, "prep", None).await?;
    let mut nums: Vec<u64> = vec![];
    let step = (|| -> PR<()> {
        let field = |v: &Value, key: &str| v.get(key).and_then(Value::as_f64);
        if field(&first, "total") != Some(total as f64) {
            return Err(bad(id, dealer_id, "bad prep size"));
        }
        let chunks = total.div_ceil(PREP_CHUNK).max(1);
        if field(&first, "chunks") != Some(chunks as f64) {
            return Err(bad(id, dealer_id, "bad prep chunk count"));
        }
        let take = |raw: &Value, len: usize| unhx_array(raw, len).ok_or_else(|| bad(id, dealer_id, "bad prep numbers"));
        nums = take(first.get("nums").unwrap_or(&NULL), PREP_CHUNK.min(total))?;
        Ok(())
    })();
    if let Err(e) = step {
        return run
            .abort(match e {
                PErr::Abort(a) => a,
                PErr::Msg(m) => nab("malformed", Some(dealer_id), id, &m),
            })
            .await;
    }
    let chunks = total.div_ceil(PREP_CHUNK).max(1);
    for ci in 1..chunks {
        let part = run.mesh.recv(dealer_id, &format!("prep.{ci}"), None).await?;
        match unhx_array(&part, PREP_CHUNK.min(total - ci * PREP_CHUNK)) {
            Some(v) => nums.extend(v),
            None => return run.abort(nab("malformed", Some(dealer_id), id, "bad prep numbers")).await,
        }
    }
    let le = |e: String| local(id, &e);
    let mut o = 0usize;
    let delta = nums[o];
    o += 1;
    if delta == 0 {
        return run.abort(nab("dealer", Some(dealer_id), id, "the dealer gave me a zero verification key")).await;
    }
    let w = pa_width(n, true);
    let mut alpha = vec![];
    for _ in 0..k {
        alpha.push(pa_parse(&nums, o, id as usize, n, true).map_err(le)?);
        o += w;
    }
    let mut triples = vec![];
    for _ in 0..n_triples {
        let mut sh = vec![];
        for _ in 0..sharings_per_triple(partners) {
            sh.push(aw_parse(&nums, o, id as usize, n, k, true).map_err(le)?);
            o += aw;
        }
        triples.push(sh);
    }
    let mut inputs = vec![];
    for _ in 0..n_inputs {
        inputs.push(aw_parse(&nums, o, id as usize, n, k, true).map_err(le)?);
        o += aw;
    }
    let my_plain = nums[o..o + c].to_vec();
    Ok(Prep { mode: Offline::TrustedDealer, tagged: true, delta, alpha, triples, inputs, my_plain, check_mask: None, forensics: None })
}

/// Run one party of the distributed protocol to its decision, or to an attributable abort.
pub async fn run_party(mesh: &Mesh, cfg: PartyConfig) -> Result<PartyResult, NetAbort> {
    let (id, n) = (cfg.id, cfg.n);
    let q = cfg.q.unwrap_or(DEFAULT_Q);
    let dealer_id = cfg.dealer_id.unwrap_or(n as i64);
    let offline = cfg.offline.unwrap_or(Offline::NoDealer);
    if offline == Offline::TrustedDealer && !cfg.insecure_trusted_dealer {
        return Err(nab(
            "local",
            None,
            id,
            "offline 'trusted-dealer' requires insecure_trusted_dealer: true (the dealer sees every share and key); the default is 'no-dealer'",
        ));
    }
    let c = chain_count(q);
    let (k, p_cnt) = (MAC_KEYS as usize, SACRIFICE_PARTNERS as usize);
    if cfg.behavior.is_some() && !cfg.unsafe_test_hooks {
        return Err(nab("local", None, id, "the behavior test hook requires unsafe_test_hooks: true (test-only)"));
    }
    let t0 = Instant::now();
    if n < 1 {
        return Err(nab("local", None, id, "n must be >= 1"));
    }
    let v = cfg.input;
    if ![0, 1].contains(&v.allow) || ![1, 2, 3].contains(&v.t) || v.r_quant < 0 || v.r_quant > q {
        return Err(nab("local", None, id, "invalid decision vector"));
    }
    let mut run = Run::new(mesh, &cfg);
    let sid = cfg.session_id.clone();
    let le = |e: String| local(id, &e);

    // ---- offline phase: prep from the trusted dealer, or the OT-based no-dealer phase ----
    run.crash_if("prep")?;
    let prep_start = Instant::now();
    let before = run.totals();
    let prep = if offline == Offline::TrustedDealer {
        receive_dealer_prep(&run, c, dealer_id).await?
    } else {
        super::offline::run_offline_net(&mut run, c, v, q).await?
    };
    let after = run.totals();
    run.rounds.push(RoundStat {
        rd: "prep".into(),
        ms: prep_start.elapsed().as_secs_f64() * 1000.0,
        bytes_out: after.0 - before.0,
        bytes_in: after.1 - before.1,
    });

    let env = PaEnv { id: id as usize, n, delta: prep.delta, tagged: prep.tagged };
    let add_pub = |x: &Aw, cst: u64| w_add_public(&env, x, cst, &prep.alpha).map_err(|e| local(id, &e));
    let not = |x: &Aw| add_pub(&w_neg(x), 1);
    let beh = cfg.behavior.clone();

    // ---- sacrifice: certify every triple against its partners before it is used ----
    let n_t = prep.triples.len();
    if n_t > 0 {
        let joint1 = run.coin("coin1", false).await?;
        // a peer that detects the failed sacrifice sends its tau share and disclosures and then its abort claim back to back; the claim is read in link order, after every frame that peer sent before it, so this party finishes its OWN verified detection instead of reporting the peer's unverified accusation
        mesh.set_defer_aborts(true);
        let mut rho_w = vec![];
        for t in 0..n_t {
            let tr = &prep.triples[t];
            for r in 0..p_cnt {
                let e = challenge(&joint1, "sac", t * p_cnt + r);
                rho_w.push(w_sub(&w_scale(&tr[0], e), &tr[3 + 2 * r]).map_err(le)?);
            }
        }
        let rho = run.open_many(&prep, "sac-rho", &rho_w).await?;
        let mut tau_w = vec![];
        for t in 0..n_t {
            let tr = &prep.triples[t];
            for r in 0..p_cnt {
                let e = challenge(&joint1, "sac", t * p_cnt + r);
                let x = w_sub(&w_scale(&tr[2], e), &tr[3 + 2 * r + 1]).map_err(le)?;
                tau_w.push(w_sub(&x, &w_scale(&tr[1], rho[t * p_cnt + r])).map_err(le)?);
            }
        }
        let tau = run.open_many(&prep, "sac-tau", &tau_w).await?;
        if tau.iter().all(|x| *x == 0) {
            mesh.set_defer_aborts(false);
        }
        if let Some(bad_at) = tau.iter().position(|x| *x != 0) {
            // Dealer-free mode: the triple is discarded, so its OT transcript can be disclosed and audited to name a party that fed a
            // wrong operand into a triple product. Every honest party reaches this point together.
            let mut attributed: Option<i64> = None;
            let mut note = String::new();
            if let (Offline::NoDealer, Some(fx)) = (prep.mode, prep.forensics.as_ref()) {
                let bt = bad_at / p_cnt;
                let mine = (fx.disclose)(bt);
                let got = super::forensics::exchange_disclosures(
                    &mut run,
                    super::forensics::ForensicArgs {
                        triple_index: bt as i64,
                        mine: &mine,
                        slots: fx.slots,
                        rows: fx.rows,
                        deadline_ms: cfg.forensic_deadline_ms.unwrap_or(DEFAULT_FORENSIC_DEADLINE_MS),
                    },
                )
                .await?;
                let mut all: BTreeMap<i64, Vec<SlotDisclosure>> = BTreeMap::new();
                all.insert(id, mine);
                all.extend(got);
                let res = audit_disclosures(&all, &fx.gadget).map_err(le)?;
                attributed = blame_from(id, &res);
                note = match attributed {
                    None => format!(
                        " (OT transcript audit: {} inconsistent pair(s), no party can be named from this view: a pair failure between two other parties is not evidence against either of them to me)",
                        res.pair_bad.len()
                    ),
                    Some(a) => format!(" (OT transcript audit names party {a})"),
                };
            }
            // every honest tag already verified, so the opened tau are the true ones: the dealt triple is wrong
            let dealer = prep.mode == Offline::TrustedDealer;
            let blamed = if dealer { Some(dealer_id) } else { attributed.or(if n == 2 { Some(1 - id) } else { None }) };
            return run
                .abort(NetAbort::new(
                    if dealer { "dealer" } else { "mac-check" },
                    blamed,
                    id,
                    &format!("triple sacrifice FAILED at triple {} (partner {}): c != a*b in the offline material; aborting with no output{note}", bad_at / p_cnt, bad_at % p_cnt),
                    None,
                    None,
                    NetAbortOpts {
                        reason: Some("the triple sacrifice failed in dealer-free mode and the OT transcript audit of this party's own view names no one (a failing pair that does not involve me is not evidence I can use, and an accusation is never accepted against a third party)".to_string()),
                        ..Default::default()
                    },
                ))
                .await;
        }
    }

    // ---- inputs: bit k of owner o is the C-vector [allow, t-therm(3), r-therm(Q)] ----
    let mut my_bits: Vec<u8> = vec![v.allow as u8];
    my_bits.extend(thermometer_encode(v.t as f64, T_M as i64).map_err(|e| local(id, &e.to_string()))?);
    my_bits.extend(thermometer_encode(v.r_quant as f64, q).map_err(|e| local(id, &e.to_string()))?);
    let masked: Vec<u64> =
        if prep.mode == Offline::TrustedDealer { my_bits.iter().enumerate().map(|(i, b)| fsub(*b as u64, prep.my_plain[i])).collect() } else { vec![] };
    let mut got_masked: BTreeMap<i64, Vec<u64>> = BTreeMap::new();
    if prep.mode == Offline::TrustedDealer {
        let msg = hxs(&masked);
        got_masked = run.exchange("inputs", &|_| msg.clone(), &|p, raw| arr(id, p, raw, c), &msg, true, None).await?;
    } else {
        // No-dealer: the inputs are already authenticated sharings of the bits. Run the MASCOT input-consistency check: open a random
        // masked combination (the opening joins the batched MAC-check below).
        let joint_in = run.coin("coin-in", false).await?;
        let mut w = prep.check_mask.clone().ok_or_else(|| local(id, "no-dealer prep lacks the input check mask"))?;
        for qi in 0..n * c {
            w = w_add(&w, &w_scale(&prep.inputs[qi], challenge(&joint_in, "in", qi))).map_err(le)?;
        }
        run.open_many(&prep, "in-check", &[w]).await?;
    }
    let bit_share = |owner: usize, kk: usize| -> Result<Aw, NetAbort> {
        if prep.mode == Offline::TrustedDealer {
            let public = if owner as i64 == id { masked[kk] } else { got_masked[&(owner as i64)][kk] };
            add_pub(&prep.inputs[owner * c + kk], public)
        } else {
            Ok(prep.inputs[owner * c + kk].clone())
        }
    };

    // ---- chains: acc_c over owners; allow uses AND, the others OR (= NOT AND NOT) ----
    let is_or = |ch: usize| ch != 0;
    let mut acc: Vec<Aw> = vec![];
    for ch in 0..c {
        let b0 = bit_share(0, ch)?;
        acc.push(if is_or(ch) { not(&b0)? } else { b0 });
    }
    let mut mults = 0usize;
    for s in 1..n {
        let trs: Vec<&Vec<Aw>> = (0..c).map(|ch| &prep.triples[(s - 1) * c + ch]).collect();
        let mut ys = vec![];
        for ch in 0..c {
            let b = bit_share(s, ch)?;
            ys.push(if is_or(ch) { not(&b)? } else { b });
        }
        let mut opens = vec![];
        for ch in 0..c {
            opens.push(w_sub(&acc[ch], &trs[ch][0]).map_err(le)?);
        }
        for ch in 0..c {
            opens.push(w_sub(&ys[ch], &trs[ch][1]).map_err(le)?);
        }
        let public = run.open_many(&prep, &format!("mul{}", s - 1), &opens).await?;
        let mut next = vec![];
        for ch in 0..c {
            let (d, e) = (public[ch], public[c + ch]);
            let (ta, tb, tc) = (&trs[ch][0], &trs[ch][1], &trs[ch][2]);
            let z = w_add(tc, &w_add(&w_scale(tb, d), &w_scale(ta, e)).map_err(le)?).map_err(le)?;
            next.push(add_pub(&z, fmul(d, e))?);
        }
        acc = next;
        mults += c;
    }

    // ---- outputs: allow as-is; the or-chains are NOT of the product ----
    let mut out_shares = vec![];
    for (ch, x) in acc.iter().enumerate() {
        out_shares.push(if is_or(ch) { not(x)? } else { x.clone() });
    }
    let out_vals = run.open_many(&prep, "out", &out_shares).await?;

    // ---- MAC-check: coin-flip for the challenges, one independent challenge vector per key ----
    let opened = std::mem::take(&mut run.opened);
    let joint = run.coin("coin", true).await?;
    let chal = |l: usize, j: usize| challenge(&joint, &format!("mac{l}"), j);
    let combo = |l: usize, pick: &dyn Fn(&Opened) -> u64| -> u64 { opened.iter().enumerate().fold(0, |g, (j, o)| fadd(g, fmul(chal(l, j), pick(o)))) };
    let a_pub: Vec<u64> = (0..k).map(|l| combo(l, &|o| o.val)).collect();
    let gamma: Vec<u64> = (0..k).map(|l| combo(l, &|o| o.mac[l].x)).collect();
    let sigma: Vec<u64> = (0..k).map(|l| fsub(gamma[l], fmul(prep.alpha[l].x, a_pub[l]))).collect();
    let sig_nonce = rand32();
    let sig_commit = |p: i64, s: &[u64], nonce: &[u8]| {
        hexs(&sha(&[b"sigma", sid.as_bytes(), p.to_string().as_bytes(), s.iter().map(|x| hx(*x as i128)).collect::<Vec<_>>().join(",").as_bytes(), nonce]))
    };
    let sigma_sent: Vec<u64> = if beh.as_ref().is_some_and(|b| b.is("sigma-lie")) {
        sigma.iter().enumerate().map(|(l, s)| if l == 0 { fadd(*s, 1) } else { *s }).collect()
    } else {
        sigma.clone()
    };
    let my_sig_commit = sig_commit(id, &sigma_sent, &sig_nonce);
    let sig_commits = run
        .exchange(
            "sig-c",
            &|_| json!(my_sig_commit),
            &|p, raw| hex64(raw).map(|x| x.0).ok_or_else(|| bad(id, p, "bad commitment")),
            &json!(my_sig_commit),
            true,
            None,
        )
        .await?;
    let my_sig_open = json!({"s": hxs(&sigma_sent), "nonce": hexs(&sig_nonce)});
    let lie_open = beh.as_ref().is_some_and(|b| b.is("bad-sigma-open"));
    let sig_open_msg = |_: i64| -> Value {
        if lie_open {
            let s: Vec<u64> = sigma_sent.iter().enumerate().map(|(l, s)| if l == 0 { fadd(*s, 1) } else { *s }).collect();
            json!({"s": hxs(&s), "nonce": hexs(&sig_nonce)})
        } else {
            my_sig_open.clone()
        }
    };
    let sig_opens = run
        .exchange(
            "sig-o",
            &sig_open_msg,
            &|p, raw| {
                let sv = unhx_array(raw.get("s").unwrap_or(&NULL), k);
                let nonce = raw.get("nonce").and_then(hex64);
                let (Some(sv), Some((_, nb))) = (sv, nonce) else { return Err(bad(id, p, "bad sigma opening")) };
                if sig_commit(p, &sv, &nb) != sig_commits[&p] {
                    return Err(PErr::Abort(nab("commitment", Some(p), id, &format!("party {p} opened a MAC residual that does not match its commitment"))));
                }
                Ok(sv)
            },
            &my_sig_open,
            true,
            None,
        )
        .await?;
    let residual: Vec<u64> = (0..k).map(|l| run.others.iter().fold(sigma_sent[l], |r, p| fadd(r, sig_opens[p][l]))).collect();
    let mac_failed = residual.iter().any(|r| *r != 0);

    // ---- transcript echo: everyone must have seen the same broadcasts (also fixes the sigma data for the blame) ----
    let digest = hexs(&run.transcript.clone().finalize());
    let digests = run
        .exchange("digest", &|_| json!(digest), &|p, raw| hex64(raw).map(|x| x.0).ok_or_else(|| bad(id, p, "bad digest")), &json!(digest), true, None)
        .await?;
    for p in run.others.clone() {
        if digests[&p] != digest {
            return run
                .abort(nab("equivocation", Some(p), id, &format!("transcript digest of party {p} differs from mine (a broadcast was inconsistent)")))
                .await;
        }
    }

    if mac_failed {
        let msg = "MAC-check FAILED: an opened value or MAC share was inconsistent; aborting with no output";
        if !prep.tagged {
            // No pairwise tags in this mode: the evidence cannot name a party, except in the two-party case.
            return run
                .abort(NetAbort::new(
                    "mac-check",
                    if n == 2 { Some(1 - id) } else { None },
                    id,
                    msg,
                    None,
                    None,
                    NetAbortOpts {
                        reason: Some(
                            "this mode carries no pairwise tags, so a MAC-check failure cannot name a party (only possible with two parties)".to_string(),
                        ),
                        ..Default::default()
                    },
                ))
                .await;
        }
        // ---- blame: every party opens its combined MAC shares with their pairwise tags; each verifier checks them ----
        let blame_msg = |peer: i64| -> Value {
            let gt: Vec<u64> = (0..k).map(|l| combo(l, &|o| o.mac[l].tag[peer as usize])).collect();
            json!({"g": hxs(&gamma), "gt": hxs(&gt), "a": hxs(&prep.alpha.iter().map(|a| a.x).collect::<Vec<_>>()), "at": hxs(&prep.alpha.iter().map(|a| a.tag[peer as usize]).collect::<Vec<_>>())})
        };
        // Abort claims arriving during this round are read in link order (see Mesh::set_defer_aborts): the cheater's own abort must not
        // pre-empt an honest party that has not yet received every peer's blame data.
        mesh.set_defer_aborts(true);
        let blames = run
            .exchange(
                "blame",
                &blame_msg,
                &|p, raw| {
                    let f = |key: &str| arr(id, p, raw.get(key).unwrap_or(&NULL), k);
                    Ok((f("g")?, f("gt")?, f("a")?, f("at")?))
                },
                &NULL,
                false,
                None,
            )
            .await;
        mesh.set_defer_aborts(false);
        let blames = blames?;
        for p in run.others.clone() {
            let (g, gt, a, at) = &blames[&p];
            for l in 0..k {
                let key_combo = combo(l, &|o| o.mac[l].key[p as usize]);
                if fadd(key_combo, fmul(env.delta, g[l])) != gt[l] {
                    return run.abort(nab("mac-check", Some(p), id, &format!("{msg} - party {p}'s MAC share (key {l}) does not match its pairwise tag"))).await;
                }
                if fadd(prep.alpha[l].key[p as usize], fmul(env.delta, a[l])) != at[l] {
                    return run.abort(nab("mac-check", Some(p), id, &format!("{msg} - party {p}'s key share (key {l}) does not match its pairwise tag"))).await;
                }
                if fsub(g[l], fmul(a[l], a_pub[l])) != sig_opens[&p][l] {
                    return run
                        .abort(nab(
                            "mac-check",
                            Some(p),
                            id,
                            &format!("{msg} - party {p}'s opened MAC residual (key {l}) is not what its authenticated shares give"),
                        ))
                        .await;
                }
            }
        }
        // Every other party's data is consistent with its pairwise tags; so is mine: the offline material disagrees.
        if prep.mode == Offline::TrustedDealer {
            return run
                .abort(nab(
                    "dealer",
                    Some(dealer_id),
                    id,
                    &format!("{msg} - every party's shares verify, so the trusted dealer's MACs are inconsistent with its values"),
                ))
                .await;
        }
        return run
            .abort(NetAbort::new(
                "mac-check",
                if n == 2 { Some(1 - id) } else { None },
                id,
                &format!("{msg} - every party's shares verify under its pairwise tags, so the offline material is inconsistent (a wrong OT operand): not attributable"),
                None,
                None,
                NetAbortOpts {
                    reason: Some("every party's shares verify under its pairwise tags, so the failure is in the offline OT material and no party can be named".to_string()),
                    ..Default::default()
                },
            ))
            .await;
    }

    // ---- only now decode ----
    let bit = |x: u64| -> u8 { (x == 1) as u8 };
    let allow = bit(out_vals[0]) as i64;
    let t_bits: Vec<u8> = out_vals[1..1 + T_M].iter().map(|x| bit(*x)).collect();
    let r_bits: Vec<u8> = out_vals[1 + T_M..].iter().map(|x| bit(*x)).collect();
    let composed = ComposedDecision { allow, t: thermometer_decode(&t_bits).clamp(1, 3), r_quant: thermometer_decode(&r_bits) };
    mesh.finish().await;
    Ok(PartyResult {
        id,
        n,
        q,
        composed,
        rounds: run.rounds.clone(),
        transcript_digest: digest,
        wall_ms: t0.elapsed().as_secs_f64() * 1000.0,
        multiplications: mults,
        opens: opened.len(),
        offline_mode: prep.mode,
        mac_keys: k,
        sacrificed_triples: n_t,
        sacrifice_partners: p_cnt,
        identifiable_abort: prep.tagged,
    })
}
