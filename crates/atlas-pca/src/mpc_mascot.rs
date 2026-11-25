//! The no-dealer SPDZ offline phase (MASCOT-style): every product of two additively shared values is built from real oblivious
//! transfers (Gilboa multiplication over IKNP/KOS OT extension, [`crate::mpc_ot`]), the MAC key is distributed and never
//! reconstructed, and every produced triple is certified by the sacrifice check. When a check fails the OT transcripts are searched
//! to blame the cheating party ([`NoDealerOffline::blamed`]).
//!
//! [`compose_secure_malicious_no_dealer`] is the malicious composition runner with the reference default: without an explicit
//! offline provider and without `insecure_trusted_dealer` it builds a fresh [`NoDealerOffline`] (the dealer-free default of the
//! reference), then runs `crate::mpc::compose_secure_malicious`.
use crate::mpc::{
    add_auth, compose_secure_malicious, fadd, fmul, fneg, fsub, make_gadget, plain_gadget, plain_share, sacrifice_verify, sample_enc, scale_auth, share,
    AuthSV, AuthTriple, DecisionVector, EncShare, FieldRng, FieldSource, MacContext, MacKey, MaliciousConfig, MaliciousResult, MpcError, MpcResultOf,
    OfflineProvider, SecureFieldRng, SpdzEngine, TripleWithPartners, MAC_KEYS, MAX_PARTIES, PRIME, SACRIFICE_PARTNERS, STAT_SEC,
};
use crate::mpc_ot::{OtChannel, OtRng};
use std::collections::{BTreeSet, HashMap};

fn inv<T>(m: impl Into<String>) -> MpcResultOf<T> {
    Err(MpcError::Invalid(m.into()))
}

/// TEST-ONLY: the `product_mul`-th product's claimed share is shifted by `delta` (a party lying about a product).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineDeviation {
    pub product_mul: i64,
    pub delta: u64,
}

/// The offline options; `None` fields mean the defaults.
#[derive(Debug, Clone, Default)]
pub struct NoDealerOptions {
    pub sacrifice: Option<bool>,
    pub sacrifice_partners: Option<i64>,
    pub mac_keys: Option<i64>,
    pub deviation: Option<OfflineDeviation>,
    pub stat_sec: Option<i64>,
    pub unsafe_stat_sec: bool,
}

struct OtRecord {
    sender: usize,
    msg0: Vec<u64>,
    msg1: Vec<u64>,
    received: Vec<u64>,
}

struct ProductClaim {
    claimed: Vec<u64>,
    implied: Vec<u64>,
}

/// One party's operand of a multiplication: an encoded (value, choice bits) share, or a plain value.
#[derive(Clone)]
enum Operand {
    Enc(EncShare),
    Plain(u64),
}

struct MulReq {
    x: Vec<Operand>,
    y: Vec<u64>,
}

struct Part {
    bits: Vec<u8>,
    plain: bool,
}

struct Piece {
    value: u64,
    parts: Vec<Part>,
}

struct Seg {
    q: usize,
    start: usize,
    length: usize,
    sender_sum: u64,
}

/// The OT-based offline provider; it implements [`OfflineProvider`].
pub struct NoDealerOffline {
    n: usize,
    pub stat_sec: i64,
    key_enc: Vec<Vec<EncShare>>,
    ctx: MacContext,
    gadget: Vec<u64>,
    sacrifice_partners: i64,
    rng: Box<dyn FieldSource>,
    seed: u64,
    deterministic: bool,
    channels: HashMap<(usize, usize), OtChannel>,
    sacrifice_on: bool,
    deviation: Option<OfflineDeviation>,
    product_mul_count: i64,
    log: Option<Vec<OtRecord>>,
    claims: Vec<ProductClaim>,
    blamed: Vec<usize>,
}

impl NoDealerOffline {
    /// The no-dealer offline provider of `n` parties; `Some(seed)` makes every draw reproducible (tests only), `None` is the OS CSPRNG.
    pub fn new(n: i64, seed: Option<u64>, opts: NoDealerOptions) -> MpcResultOf<Self> {
        if n < 1 || n > MAX_PARTIES {
            return inv("NoDealerOffline: n must be a positive integer");
        }
        let n = n as usize;
        let mut rng: Box<dyn FieldSource> = match seed {
            Some(s) => Box::new(FieldRng::new(s)),
            None => Box::new(SecureFieldRng),
        };
        let seed_v = seed.unwrap_or(0xabcdef12345);
        let keys = opts.mac_keys.unwrap_or(MAC_KEYS);
        if !(1..=16).contains(&keys) {
            return inv("NoDealerOffline: macKeys must be an integer in [1, 16]");
        }
        let stat_sec = opts.stat_sec.unwrap_or(STAT_SEC);
        let gadget = make_gadget(stat_sec, rng.as_mut(), opts.unsafe_stat_sec)?;
        let mut key_enc = Vec::with_capacity(keys as usize);
        for _ in 0..keys {
            key_enc.push((0..n).map(|_| sample_enc(&gadget, rng.as_mut())).collect::<Vec<_>>());
        }
        let partners = opts.sacrifice_partners.unwrap_or(SACRIFICE_PARTNERS);
        if !(1..=8).contains(&partners) {
            return inv("NoDealerOffline: sacrificePartners must be an integer in [1, 8]");
        }
        let mut all: Vec<MacKey> = key_enc
            .iter()
            .map(|row| {
                let shares: Vec<u64> = row.iter().map(|e| e.value).collect();
                let alpha = shares.iter().fold(0u64, |a, s| fadd(a, *s));
                MacKey { alpha_shares: shares, alpha }
            })
            .collect();
        let first = all.remove(0);
        let ctx = MacContext { n, alpha_shares: first.alpha_shares, alpha: first.alpha, extra_keys: all };
        Ok(NoDealerOffline {
            n,
            stat_sec,
            key_enc,
            ctx,
            gadget,
            sacrifice_partners: partners,
            rng,
            seed: seed_v,
            deterministic: seed.is_some(),
            channels: HashMap::new(),
            sacrifice_on: opts.sacrifice.unwrap_or(true),
            deviation: opts.deviation,
            product_mul_count: 0,
            log: None,
            claims: vec![],
            blamed: vec![],
        })
    }

    /// The parties the OT transcripts convicted in the last aborted triple (empty when none or no abort).
    pub fn blamed(&self) -> &[usize] {
        &self.blamed
    }

    fn channel_for(&mut self, i: usize, j: usize) -> &mut OtChannel {
        let (seed, det) = (self.seed, self.deterministic);
        self.channels.entry((i, j)).or_insert_with(|| {
            let rng =
                if det { OtRng::Seeded(seed ^ (i as u64 + 1).wrapping_mul(0x100000001b3) ^ (j as u64 + 1).wrapping_mul(0x1000000000)) } else { OtRng::Secure };
            OtChannel::new(rng, None, None)
        })
    }

    /// The batched Gilboa multiplication: one OT-extension call per ordered party pair for every request.
    fn mul_batch(&mut self, reqs: Vec<MulReq>) -> MpcResultOf<Vec<Vec<u64>>> {
        let n = self.n;
        for r in &reqs {
            if r.x.len() != n || r.y.len() != n {
                return inv("otShareMultiply: wrong length");
            }
        }
        let gadget = self.gadget.clone();
        let plain_g = plain_gadget();
        let mut pieces: Vec<Vec<Piece>> = Vec::with_capacity(reqs.len());
        for r in &reqs {
            let mut row = Vec::with_capacity(n);
            for xi in &r.x {
                row.push(match xi {
                    Operand::Enc(e) => Piece { value: e.value, parts: vec![Part { bits: e.bits.clone(), plain: false }] },
                    Operand::Plain(p) => {
                        let v = *p % PRIME;
                        let e = sample_enc(&gadget, self.rng.as_mut());
                        let d = plain_share(fsub(v, e.value));
                        Piece { value: v, parts: vec![Part { bits: e.bits, plain: false }, Part { bits: d.bits, plain: true }] }
                    }
                });
            }
            pieces.push(row);
        }
        let mut z: Vec<Vec<u64>> = reqs.iter().enumerate().map(|(q, r)| (0..n).map(|i| fmul(pieces[q][i].value, r.y[i])).collect()).collect();
        for i in 0..n {
            for j in 0..n {
                if i == j {
                    continue;
                }
                let rows: usize = pieces.iter().map(|p| p[i].parts.iter().map(|x| x.bits.len()).sum::<usize>()).sum();
                let mut bits = vec![0i64; rows];
                let mut msg0 = vec![0u64; rows];
                let mut msg1 = vec![0u64; rows];
                let mut segs: Vec<Seg> = vec![];
                let mut at = 0usize;
                for (q, r) in reqs.iter().enumerate() {
                    let y = r.y[j] % PRIME;
                    for part in &pieces[q][i].parts {
                        let gad = if part.plain { &plain_g } else { &gadget };
                        let length = part.bits.len();
                        let mut sender_sum = 0u64;
                        for k in 0..length {
                            let rho = self.rng.next();
                            sender_sum = fadd(sender_sum, rho);
                            bits[at + k] = part.bits[k] as i64;
                            msg0[at + k] = rho;
                            msg1[at + k] = fadd(rho, fmul(gad[k], y));
                        }
                        segs.push(Seg { q, start: at, length, sender_sum });
                        at += length;
                    }
                }
                let ext = self.channel_for(i, j).extend(&bits, &msg0, &msg1).map_err(|e| MpcError::Invalid(e.to_string()))?;
                if let Some(log) = self.log.as_mut() {
                    log.push(OtRecord { sender: j, msg0, msg1, received: ext.received.clone() });
                }
                for sg in &segs {
                    let mut receiver_sum = 0u64;
                    for k in 0..sg.length {
                        receiver_sum = fadd(receiver_sum, ext.received[sg.start + k] % PRIME);
                    }
                    z[sg.q][i] = fadd(z[sg.q][i], receiver_sum);
                    z[sg.q][j] = fadd(z[sg.q][j], fneg(sg.sender_sum));
                }
            }
        }
        Ok(z)
    }

    /// Additive shares of `x * y` where party `i` holds `x_i` and `y_i` (all cross terms via OT).
    pub fn ot_share_multiply(&mut self, x: &[u64], y: &[u64]) -> MpcResultOf<Vec<u64>> {
        let z = self.mul_batch(vec![MulReq { x: x.iter().map(|v| Operand::Plain(*v)).collect(), y: y.to_vec() }])?;
        Ok(z.into_iter().next().expect("one request"))
    }

    fn key_req(&self, l: usize) -> Vec<Operand> {
        self.key_enc[l].iter().cloned().map(Operand::Enc).collect()
    }

    fn authenticate(&mut self, value_shares: &[u64]) -> MpcResultOf<AuthSV> {
        let reqs = (0..self.key_enc.len()).map(|l| MulReq { x: self.key_req(l), y: value_shares.to_vec() }).collect();
        let macs = self.mul_batch(reqs)?;
        Ok(to_auth(value_shares.to_vec(), &macs))
    }

    fn claim_product(&mut self, implied: &[u64]) -> Vec<u64> {
        let mut z = implied.to_vec();
        let idx = self.product_mul_count;
        self.product_mul_count += 1;
        if let Some(d) = &self.deviation {
            if d.product_mul == idx {
                z[0] = fadd(z[0], d.delta);
            }
        }
        self.claims.push(ProductClaim { claimed: z.clone(), implied: implied.to_vec() });
        z
    }

    fn sample_shares(&mut self) -> Vec<EncShare> {
        (0..self.n).map(|_| sample_enc(&self.gadget, self.rng.as_mut())).collect()
    }

    fn raw_triple_with_partners(&mut self, partners: usize) -> MpcResultOf<TripleWithPartners> {
        let (n, kk) = (self.n, self.key_enc.len());
        let a_enc = self.sample_shares();
        let b_shares: Vec<u64> = (0..n).map(|_| self.rng.next()).collect();
        let ah_enc: Vec<Vec<EncShare>> = (0..partners).map(|_| self.sample_shares()).collect();
        let a_val: Vec<u64> = a_enc.iter().map(|e| e.value).collect();
        let ah_val: Vec<Vec<u64>> = ah_enc.iter().map(|r| r.iter().map(|e| e.value).collect()).collect();
        let enc_ops = |e: &[EncShare]| -> Vec<Operand> { e.iter().cloned().map(Operand::Enc).collect() };
        let mut reqs = vec![MulReq { x: enc_ops(&a_enc), y: b_shares.clone() }];
        for r in 0..partners {
            reqs.push(MulReq { x: enc_ops(&ah_enc[r]), y: b_shares.clone() });
        }
        let mac_start = reqs.len();
        for l in 0..kk {
            reqs.push(MulReq { x: self.key_req(l), y: a_val.clone() });
            reqs.push(MulReq { x: self.key_req(l), y: b_shares.clone() });
            for r in 0..partners {
                reqs.push(MulReq { x: self.key_req(l), y: ah_val[r].clone() });
            }
        }
        let z1 = self.mul_batch(reqs)?;
        let c_shares = self.claim_product(&z1[0]);
        let ch_shares: Vec<Vec<u64>> = (0..partners).map(|r| self.claim_product(&z1[1 + r])).collect();
        let per = 2 + partners;
        let mut reqs2 = vec![];
        for l in 0..kk {
            reqs2.push(MulReq { x: self.key_req(l), y: c_shares.clone() });
            for r in 0..partners {
                reqs2.push(MulReq { x: self.key_req(l), y: ch_shares[r].clone() });
            }
        }
        let z2 = self.mul_batch(reqs2)?;
        let per2 = 1 + partners;
        let b = to_auth(b_shares.clone(), &mac_of(&z1, mac_start, per, 1, kk));
        let keep = AuthTriple { a: to_auth(a_val, &mac_of(&z1, mac_start, per, 0, kk)), b: b.clone(), c: to_auth(c_shares, &mac_of(&z2, 0, per2, 0, kk)) };
        let parts = (0..partners)
            .map(|r| AuthTriple {
                a: to_auth(ah_val[r].clone(), &mac_of(&z1, mac_start, per, 2 + r, kk)),
                b: b.clone(),
                c: to_auth(ch_shares[r].clone(), &mac_of(&z2, 0, per2, 1 + r, kk)),
            })
            .collect();
        Ok(TripleWithPartners { keep, partners: parts })
    }

    /// Search the OT transcripts and the product claims for the party that cheated.
    fn attribute(&mut self, msg: &str) -> MpcError {
        let mut blamed: BTreeSet<usize> = BTreeSet::new();
        if let Some(log) = &self.log {
            for r in log {
                for k in 0..r.received.len() {
                    let got = r.received[k] % PRIME;
                    if got != r.msg0[k] && got != r.msg1[k] {
                        blamed.insert(r.sender);
                        break;
                    }
                }
            }
        }
        for c in &self.claims {
            for i in 0..c.claimed.len() {
                if c.claimed[i] != c.implied[i] {
                    blamed.insert(i);
                }
            }
        }
        self.blamed = blamed.into_iter().collect();
        let mut m = msg.to_string();
        if !self.blamed.is_empty() {
            let names: Vec<String> = self.blamed.iter().map(|b| b.to_string()).collect();
            m.push_str(&format!("; offline OT transcript names party {}", names.join(", ")));
        }
        MpcError::MacCheckAbort(m)
    }

    /// One authenticated triple, certified by the sacrifice check (or raw when sacrifice is switched off).
    pub fn gen_auth_triple(&mut self) -> MpcResultOf<AuthTriple> {
        self.blamed.clear();
        if !self.sacrifice_on {
            return Ok(self.raw_triple_with_partners(0)?.keep);
        }
        self.log = Some(vec![]);
        self.claims.clear();
        let result = self.certified_triple();
        self.log = None;
        self.claims.clear();
        result
    }

    fn certified_triple(&mut self) -> MpcResultOf<AuthTriple> {
        let t = self.raw_triple_with_partners(self.sacrifice_partners as usize)?;
        match sacrifice_verify(&[t], &self.ctx, self.rng.as_mut(), vec![]) {
            Ok(mut cert) => Ok(cert.remove(0)),
            Err(MpcError::MacCheckAbort(m)) => Err(self.attribute(&m)),
            Err(e) => Err(e),
        }
    }

    /// An authenticated sharing of a value contributed by `owner`, MACed by OT under the distributed key.
    pub fn auth_input(&mut self, value: u64, owner: usize) -> MpcResultOf<AuthSV> {
        if owner >= self.n {
            return inv("authInput: owner out of range");
        }
        let sh = share(value % PRIME, self.n as i64, self.rng.as_mut())?;
        self.authenticate(&sh)
    }

    /// Verify that every supplied input's MAC matches its value via a random combination (aborting otherwise).
    pub fn check_input_consistency(&mut self, inputs: &[AuthSV]) -> MpcResultOf<()> {
        if inputs.is_empty() {
            return Ok(());
        }
        for inp in inputs {
            if inp.value.len() != self.n || inp.mac.len() != self.n {
                return inv("checkInputConsistency: input party count mismatch");
            }
        }
        let mut engine = SpdzEngine::new(&self.ctx, vec![])?;
        let r_shares: Vec<u64> = (0..self.n).map(|_| self.rng.next()).collect();
        let mut w = self.authenticate(&r_shares)?;
        for inp in inputs {
            let mut e = self.rng.next();
            if e == 0 {
                e = 1;
            }
            w = add_auth(&w, &scale_auth(inp, e))?;
        }
        engine.open(&w, "input-check:w")?;
        engine.mac_check(self.rng.as_mut())
    }
}

fn to_auth(value: Vec<u64>, macs: &[Vec<u64>]) -> AuthSV {
    AuthSV { value, mac: macs[0].clone(), extra_mac: macs[1..].to_vec() }
}

fn mac_of(z: &[Vec<u64>], start: usize, per: usize, off: usize, keys: usize) -> Vec<Vec<u64>> {
    (0..keys).map(|l| z[start + l * per + off].clone()).collect()
}

impl OfflineProvider for NoDealerOffline {
    fn n(&self) -> usize {
        self.n
    }

    fn mac_context(&self) -> &MacContext {
        &self.ctx
    }

    fn gen_auth_triple(&mut self) -> MpcResultOf<AuthTriple> {
        NoDealerOffline::gen_auth_triple(self)
    }

    fn auth_input(&mut self, value: u64, owner: usize) -> MpcResultOf<AuthSV> {
        NoDealerOffline::auth_input(self, value, owner)
    }
}

/// `makeNoDealerOffline`: a fresh no-dealer offline phase for `n` parties (malicious-secure by default).
pub fn make_no_dealer_offline(n: i64, seed: Option<u64>, opts: NoDealerOptions) -> MpcResultOf<NoDealerOffline> {
    NoDealerOffline::new(n, seed, opts)
}

/// The actively secure composition with the reference's default offline phase: when `cfg` names no offline provider and does not
/// opt into the trusted dealer, a fresh no-dealer (OT-based) offline phase for `vectors.len()` parties is built (seeded by
/// `cfg.seed`, else the OS CSPRNG) and used. Everything else is `crate::mpc::compose_secure_malicious`.
pub fn compose_secure_malicious_no_dealer(vectors: &[DecisionVector], mut cfg: MaliciousConfig) -> MpcResultOf<MaliciousResult> {
    if cfg.offline.is_none() && !cfg.insecure_trusted_dealer && cfg.dealer.is_none() {
        cfg.offline = Some(Box::new(NoDealerOffline::new(vectors.len() as i64, cfg.seed, NoDealerOptions::default())?));
    }
    compose_secure_malicious(vectors, cfg)
}
