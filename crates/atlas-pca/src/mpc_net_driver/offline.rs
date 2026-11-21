//! The NO-DEALER offline phase over the mutual-TLS mesh (research prototype).
//!
//! Each party is its own node holding only its own shares. Nobody is trusted to know the MAC keys, the triples or the inputs: every
//! party samples its own key shares and triple shares, and the products needed for the triples and the MACs are computed by Gilboa OT
//! multiplication between every ordered pair of parties ([`crate::mpc_mascot`] is the in-process model of exactly this computation):
//!
//! - `ob-S` / `ob-R` / `ob-C`: the kappa = 128 base OTs of every ordered pair (malicious-secure, session-bound Chou-Orlandi: Schnorr proof
//!   of knowledge, point validation, transcript KDF, commitments to the ciphertexts)
//! - `gd-*`: the signed commit / reveal / echo of the choice-bit gadget seeds ([`super::gadget`])
//! - `in-share`: each owner splits every input bit into additive shares and sends one to each peer
//! - `ox<layer>.<chunk>.u` / `.y`: the OT-extension receiver messages (u matrix and KOS pair, checked by the sender) and the ciphertexts
//!
//! Layer 1 holds the triple products c = a*b, c-hat = a-hat*b and the MACs of every value known before them; layer 2 the MACs of the
//! products; layer 3 the pairwise tags (identifiable abort): one OT product of my share with the peer's secret verification key.
//! SELECTIVE FAILURE: receivers multiply with the gadget sum of 253 uniform choice bits, never with the bits of their share; the tag
//! layer splits its derived operands as `e + d` with an encoded `e`. NOT here: a security proof, and attribution of a wrong OT operand in
//! the offline products (named only by the forensic audit of the discarded triple, or for n = 2).
use super::prep::{Forensics, Offline, Prep};
use super::protocol::{arr, bad, PErr, Run, PR};
use super::{local, nab, NULL};
use crate::mpc::{
    fadd, fmul, fsub, make_gadget, mod_u64, plain_gadget, plain_share, sample_enc, DecisionVector, EncShare, FieldSource, SecureFieldRng, MAC_KEYS, PRIME,
    SACRIFICE_PARTNERS, STAT_SEC,
};
use crate::mpc_net::{b64, hex_big, hx, j_pt, pt_j, sharings_per_triple, unb64, Aw, NetAbort, Pa};
use crate::mpc_ot::{
    base_ot_receiver_decrypt, base_ot_sender_encrypt, binding_bytes, ec_decompress, ec_to_affine_dec, mal_base_ot_receiver_respond, mal_base_ot_sender_derive,
    mal_base_ot_sender_setup, otx_big_to_bytes, otx_bytes_to_big, BaseOtBinding, BaseOtSenderSetup, ExtPending, ExtRoundMsg, OtError, OtExtReceiver,
    OtExtSender, OtPair, OtResult, OtRng, SchnorrProof, TamperU, UCol, OT_KAPPA, OT_SSEC,
};
use curve25519_dalek::edwards::EdwardsPoint;
use rsa::BigUint;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Most OT rows per extension round (bounds frame size and memory).
const ROWS_PER_ROUND: usize = 128 * crate::mpc::FIELD_BITS;

// ---- wire codecs ----------------------------------------------------------------------------------------------------------------

pub(super) fn pt_value(p: &EdwardsPoint) -> Value {
    let (x, y) = ec_to_affine_dec(p);
    pt_j(&BigUint::parse_bytes(x.as_bytes(), 10).expect("decimal x"), &BigUint::parse_bytes(y.as_bytes(), 10).expect("decimal y"))
}

/// A validated point (canonical coordinates, on the curve, not the identity, in the prime-order subgroup) from its `{x, y}` wire form.
pub(super) fn point_of(v: &Value) -> Result<EdwardsPoint, String> {
    let (x, y) = j_pt(v)?;
    let mut enc = y.to_bytes_le();
    enc.resize(32, 0);
    if x.to_bytes_le().first().is_some_and(|b| b & 1 == 1) {
        enc[31] |= 0x80;
    }
    ec_decompress(&enc).map_err(|e| e.to_string())
}

pub(super) fn z_hex(z: &[u8; 32], lie: bool) -> String {
    let v = BigUint::from_bytes_le(z);
    (if lie { v + BigUint::from(1u8) } else { v }).to_str_radix(16)
}

pub(super) fn z_bytes(v: &Value) -> Result<[u8; 32], String> {
    let mut b = hex_big(v)?.to_bytes_le();
    if b.len() > 32 {
        return Err("bad field element".into());
    }
    b.resize(32, 0);
    b.try_into().map_err(|_| "bad field element".to_string())
}

fn pairs_b64(ps: &[OtPair]) -> Value {
    Value::Array(ps.iter().map(|p| json!([b64(&p[0]), b64(&p[1])])).collect())
}

fn parse_pairs(raw: &Value, count: usize, len: usize) -> Result<Vec<OtPair>, String> {
    let a = raw.as_array().filter(|a| a.len() == count).ok_or("bad pair array")?;
    a.iter()
        .map(|p| {
            let p = p.as_array().filter(|p| p.len() == 2).ok_or("bad pair")?;
            Ok([unb64(&p[0], Some(len))?, unb64(&p[1], Some(len))?])
        })
        .collect()
}

fn encode_u(msg: &ExtRoundMsg, m_ext: usize) -> Value {
    let cb = m_ext.div_ceil(8);
    let mut bytes = Vec::with_capacity(cb * msg.u.len());
    for c in &msg.u {
        bytes.extend(otx_big_to_bytes(&c.v, cb));
    }
    json!({"u": b64(&bytes), "x": format!("{:x}", msg.x), "t": format!("{:x}", msg.t_comb)})
}

fn decode_u(raw: &Value, m_ext: usize) -> Result<ExtRoundMsg, String> {
    if !raw.is_object() {
        return Err("bad extension message".into());
    }
    let cb = m_ext.div_ceil(8);
    let bytes = unb64(raw.get("u").unwrap_or(&NULL), Some(OT_KAPPA * cb))?;
    let u = (0..OT_KAPPA).map(|i| UCol::new(otx_bytes_to_big(&bytes[i * cb..(i + 1) * cb]))).collect();
    Ok(ExtRoundMsg { u, x: hex128(raw.get("x").unwrap_or(&NULL))?, t_comb: hex128(raw.get("t").unwrap_or(&NULL))? })
}

/// A canonical lowercase hex value of at most 128 bits (`0` or no leading zero).
fn hex128(v: &Value) -> Result<u128, String> {
    let s = v.as_str().ok_or("bad 128-bit value")?;
    let b = s.as_bytes();
    let ok =
        s == "0" || (!b.is_empty() && b.len() <= 32 && matches!(b[0], b'1'..=b'9' | b'a'..=b'f') && b.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));
    if !ok {
        return Err("bad 128-bit value".into());
    }
    u128::from_str_radix(s, 16).map_err(|_| "bad 128-bit value".to_string())
}

fn le8(v: &[u64]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn encode_y(y0: &[u64], y1: &[u64]) -> Value {
    json!({"y0": b64(&le8(y0)), "y1": b64(&le8(y1))})
}

fn decode_y(raw: &Value, m: usize) -> Result<(Vec<u64>, Vec<u64>), String> {
    if !raw.is_object() {
        return Err("bad ciphertext message".into());
    }
    let words = |b: Vec<u8>| -> Vec<u64> { b.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().expect("8 bytes"))).collect() };
    let a = unb64(raw.get("y0").unwrap_or(&NULL), Some(m * 8))?;
    let b = unb64(raw.get("y1").unwrap_or(&NULL), Some(m * 8))?;
    Ok((words(a), words(b)))
}

// ---- the jointly contributed gadget ---------------------------------------------------------------------------------------------

/// The hash chain that expands the agreed seeds into the gadget weights: `H(seed || counter)`, low 61 bits, rejecting values >= p.
struct HashChain {
    seed: Vec<u8>,
    ctr: u64,
}

impl FieldSource for HashChain {
    fn next(&mut self) -> u64 {
        loop {
            let mut h = Sha256::new();
            h.update(&self.seed);
            h.update(self.ctr.to_le_bytes());
            self.ctr += 1;
            let d = h.finalize();
            let v = u64::from_le_bytes(d[0..8].try_into().expect("8 bytes")) & ((1u64 << 61) - 1);
            if v < PRIME {
                return v;
            }
        }
    }
}

/// The public gadget of the privacy-amplified choice-bit encoding from the parties' contributed seeds: `H(all seeds in party order ||
/// session)` expanded by a hash chain. Every party commits to a fresh random seed before any seed is revealed.
fn gadget_from_seeds(session_id: &str, seeds: &[Vec<u8>]) -> Result<Vec<u64>, String> {
    let mut h0 = Sha256::new();
    h0.update(b"atlas-pca-mpc/enc-gadget");
    h0.update(session_id.as_bytes());
    for s in seeds {
        h0.update(s);
    }
    let mut chain = HashChain { seed: h0.finalize().to_vec(), ctr: 0 };
    make_gadget(STAT_SEC, &mut chain, false).map_err(|e| e.to_string())
}

// ---- the OT multiplication layers -----------------------------------------------------------------------------------------------

/// One OT multiplication item: my choice bits (weights `gad`, public) against my sender operand `y`.
struct Item<'a> {
    bits: &'a [u8],
    gad: &'a [u64],
    y: u64,
}

/// Per-row transcript of selected items (for post-abort attribution): `[peer][item]`.
#[derive(Default)]
struct Kept {
    recv: BTreeMap<i64, BTreeMap<usize, Vec<u64>>>,
    rho: BTreeMap<i64, BTreeMap<usize, Vec<u64>>>,
}

struct Rows {
    recv: BTreeMap<i64, Vec<u64>>,
    send_sum: BTreeMap<i64, Vec<u64>>,
    kept: Kept,
}

/// Turn an OT error into an abort naming `peer` (`ot-check` for a cheating OT peer, `malformed` for a refused argument).
async fn guard<T>(run: &Run<'_>, peer: i64, what: &str, r: OtResult<T>) -> Result<T, NetAbort> {
    match r {
        Ok(v) => Ok(v),
        Err(e) => {
            let kind = match e {
                OtError::BaseOtAbort(_) | OtError::MalOtAbort(_) | OtError::PointValidation(_) => "ot-check",
                _ => "malformed",
            };
            run.abort(nab(kind, Some(peer), run.id, &format!("{what}: {e}"))).await
        }
    }
}

struct Off {
    id: i64,
    others: Vec<i64>,
    rng: OtRng,
    frng: SecureFieldRng,
    delta: u64,
    gadget: Vec<u64>,
    recv_ch: BTreeMap<i64, OtExtReceiver>,
    send_ch: BTreeMap<i64, OtExtSender>,
    ot_u_lie: bool,
}

impl Off {
    /// The Gilboa OT core. For every peer p: as the OT RECEIVER towards p I choose with the bits of my item `t` and get
    /// `recv[p][t] = x_t*y^p_t + sum(rho^p_t)` (p's operand and masks); as the OT SENDER towards p I offer `(rho_k, rho_k + g_k*y_t)` with
    /// fresh masks and keep `send_sum[p][t] = sum(rho)`. Over the pair, `recv - send_sum` is an additive sharing of `x_t * y_t`.
    async fn ot_rows(&mut self, run: &mut Run<'_>, layer: &str, items: &[Item<'_>], keep: Option<&BTreeSet<usize>>) -> Result<Rows, NetAbort> {
        let others = self.others.clone();
        let t_cnt = items.len();
        let mut rows = Rows { recv: BTreeMap::new(), send_sum: BTreeMap::new(), kept: Kept::default() };
        for p in &others {
            rows.recv.insert(*p, vec![0; t_cnt]);
            rows.send_sum.insert(*p, vec![0; t_cnt]);
            rows.kept.recv.insert(*p, BTreeMap::new());
            rows.kept.rho.insert(*p, BTreeMap::new());
        }
        if t_cnt == 0 || others.is_empty() {
            return Ok(rows);
        }
        let total: usize = items.iter().map(|i| i.bits.len()).sum();
        let mut row_item = vec![0usize; total];
        let mut item_off = vec![0usize; t_cnt];
        let mut choice: Vec<i64> = vec![0; total];
        let mut m0: BTreeMap<i64, Vec<u64>> = others.iter().map(|p| (*p, vec![0u64; total])).collect();
        let mut m1: BTreeMap<i64, Vec<u64>> = others.iter().map(|p| (*p, vec![0u64; total])).collect();
        let mut off = 0usize;
        for (t, it) in items.iter().enumerate() {
            let len = it.bits.len();
            item_off[t] = off;
            let kept_here = keep.is_some_and(|k| k.contains(&t));
            if kept_here {
                for p in &others {
                    rows.kept.recv.get_mut(p).expect("peer").insert(t, vec![0; len]);
                }
            }
            for k in 0..len {
                choice[off + k] = it.bits[k] as i64;
                row_item[off + k] = t;
            }
            for p in &others {
                let (a0, a1) = (m0.get_mut(p).expect("peer"), m1.get_mut(p).expect("peer"));
                let mut sum_rho = 0u64;
                for k in 0..len {
                    let rho = self.frng.next();
                    sum_rho = fadd(sum_rho, rho);
                    a0[off + k] = rho;
                    a1[off + k] = fadd(rho, fmul(it.gad[k], it.y));
                }
                rows.send_sum.get_mut(p).expect("peer")[t] = sum_rho;
                if kept_here {
                    rows.kept.rho.get_mut(p).expect("peer").insert(t, a0[off..off + len].to_vec());
                }
            }
            off += len;
        }
        let (mut start, mut chunk) = (0usize, 0usize);
        while start < total {
            let end = total.min(start + ROWS_PER_ROUND);
            let m = end - start;
            let m_ext = m + OT_KAPPA + OT_SSEC;
            let tag = format!("ox{layer}.{chunk}");
            let mut begun: BTreeMap<i64, (ExtRoundMsg, ExtPending)> = BTreeMap::new();
            for p in &others {
                let cb = m_ext.div_ceil(8);
                // an inconsistent matrix: flip the first row in 64 of the 128 columns only (not a different choice vector)
                let mut tam: Option<TamperU> = if self.ot_u_lie {
                    Some(Box::new(move |u: &mut Vec<UCol>, _round: usize| {
                        for c in u.iter_mut().take(64) {
                            let mut b = otx_big_to_bytes(&c.v, cb);
                            b[0] ^= 1;
                            c.v = otx_bytes_to_big(&b);
                        }
                    }))
                } else {
                    None
                };
                let ch = self.recv_ch.get_mut(p).expect("channel");
                let r = ch.begin(&mut self.rng, &choice[start..end], tam.as_mut());
                begun.insert(*p, guard(run, *p, &format!("OT extension ({tag})"), r).await?);
            }
            let us = run
                .exchange(&format!("{tag}.u"), &|peer| encode_u(&begun[&peer].0, m_ext), &|_p, raw| decode_u(raw, m_ext).map_err(PErr::Msg), &NULL, false, None)
                .await?;
            let mut ys: BTreeMap<i64, (Vec<u64>, Vec<u64>)> = BTreeMap::new();
            for p in &others {
                let r = self.send_ch.get_mut(p).expect("channel").respond(&us[p], &m0[p][start..end], &m1[p][start..end]);
                ys.insert(*p, guard(run, *p, &format!("OT extension ({tag})"), r).await?);
            }
            let cts = run
                .exchange(&format!("{tag}.y"), &|peer| encode_y(&ys[&peer].0, &ys[&peer].1), &|_p, raw| decode_y(raw, m).map_err(PErr::Msg), &NULL, false, None)
                .await?;
            for p in &others {
                let r = self.recv_ch.get_mut(p).expect("channel").finish(&begun[p].1, &cts[p].0, &cts[p].1);
                let got = guard(run, *p, &format!("OT extension ({tag})"), r).await?;
                let rv = rows.recv.get_mut(p).expect("peer");
                for j in 0..m {
                    let t = row_item[start + j];
                    rv[t] = fadd(rv[t], mod_u64(got[j]));
                    if keep.is_some_and(|k| k.contains(&t)) {
                        rows.kept.recv.get_mut(p).expect("peer").get_mut(&t).expect("kept item")[start + j - item_off[t]] = mod_u64(got[j]);
                    }
                }
            }
            start = end;
            chunk += 1;
        }
        Ok(rows)
    }

    /// Given my shares `xs[t]` of X_t and `ys[t]` of Y_t, my additive share of X_t * Y_t = (sum x)(sum y): the diagonal x_i*y_i locally plus,
    /// for every ordered pair, the Gilboa OT product of one party's x with the other's y.
    async fn mul_layer(
        &mut self,
        run: &mut Run<'_>,
        layer: &str,
        xs: &[&EncShare],
        ys: &[u64],
        lie_at: Option<usize>,
        keep: Option<&BTreeSet<usize>>,
    ) -> Result<(Vec<u64>, Kept), NetAbort> {
        let gadget = self.gadget.clone();
        let mut z: Vec<u64> = xs.iter().zip(ys).map(|(x, y)| fmul(x.value, *y)).collect();
        let items: Vec<Item<'_>> =
            xs.iter().enumerate().map(|(t, x)| Item { bits: &x.bits, gad: &gadget, y: if Some(t) == lie_at { fadd(ys[t], 1) } else { ys[t] } }).collect();
        let rows = self.ot_rows(run, layer, &items, keep).await?;
        for p in &self.others {
            for t in 0..z.len() {
                z[t] = fsub(fadd(z[t], rows.recv[p][t]), rows.send_sum[p][t]);
            }
        }
        Ok((z, rows.kept))
    }

    /// Pairwise tags for my shares `xs`: for every peer j a tag T_ij (mine) and a key K_ij with `T_ij = K_ij + delta_j * x_i`, where delta_j is
    /// j's secret verification key. One OT product of my x with j's delta per item. A tag operand has no uniform choice-bit encoding of its
    /// own, so each x is split as `e + d` with a fresh encoded `e` and `d = x - e`; both halves are multiplied with delta and added.
    async fn tag_layer(&mut self, run: &mut Run<'_>, layer: &str, xs: &[u64]) -> Result<(BTreeMap<i64, Vec<u64>>, BTreeMap<i64, Vec<u64>>), NetAbort> {
        let gadget = self.gadget.clone();
        let plain = plain_gadget();
        let mut es: Vec<EncShare> = vec![];
        let mut ds: Vec<EncShare> = vec![];
        for x in xs {
            let e = sample_enc(&gadget, &mut self.frng);
            ds.push(plain_share(fsub(*x, e.value)));
            es.push(e);
        }
        let mut items: Vec<Item<'_>> = vec![];
        for u in 0..xs.len() {
            items.push(Item { bits: &es[u].bits, gad: &gadget, y: self.delta });
            items.push(Item { bits: &ds[u].bits, gad: &plain, y: self.delta });
        }
        let rows = self.ot_rows(run, layer, &items, None).await?;
        let (mut tag, mut key) = (BTreeMap::new(), BTreeMap::new());
        for p in &self.others {
            let (r, k) = (&rows.recv[p], &rows.send_sum[p]);
            tag.insert(*p, (0..xs.len()).map(|u| fadd(r[2 * u], r[2 * u + 1])).collect::<Vec<u64>>());
            key.insert(*p, (0..xs.len()).map(|u| fadd(k[2 * u], k[2 * u + 1])).collect::<Vec<u64>>());
        }
        Ok((tag, key))
    }
}

/// Run the no-dealer offline phase and return this party's material.
pub async fn run_offline_net(run: &mut Run<'_>, c: usize, input: DecisionVector, q: i64) -> Result<Prep, NetAbort> {
    let (id, n) = (run.id, run.n);
    let others = run.others.clone();
    let (k, p_cnt) = (MAC_KEYS as usize, SACRIFICE_PARTNERS as usize);
    let le = |e: String| local(id, &e);
    let mut frng = SecureFieldRng;
    // my pairwise verification key: non-zero and secret, it verifies every share the peers open to me
    let delta = loop {
        let d = frng.next();
        if d != 0 {
            break d;
        }
    };
    let sid: Vec<u8> = Sha256::new().chain_update(b"atlas-pca-mpc/net-session/v2").chain_update(run.mesh.session_id().as_bytes()).finalize().to_vec();
    // Binding of the channel whose EXTENSION RECEIVER (= base-OT sender) is `recv` and extension sender is `send`.
    let chan =
        |recv: i64, send: i64, round: &str| BaseOtBinding { session_id: sid.clone(), sender_index: recv, receiver_index: send, round: round.to_string() };
    let mut off = Off {
        id,
        others: others.clone(),
        rng: OtRng::Secure,
        frng,
        delta,
        gadget: vec![],
        recv_ch: BTreeMap::new(),
        send_ch: BTreeMap::new(),
        ot_u_lie: run.beh.as_ref().is_some_and(|b| b.is("ot-u-lie")),
    };
    let proof_lie = run.beh.as_ref().is_some_and(|b| b.is("ot-proof-lie"));
    let offline_lie = run.beh.as_ref().is_some_and(|b| b.is("offline-lie"));

    // ------------------------------------------------------------------ base OTs (kappa per ordered pair, both roles)
    let mut seeds: BTreeMap<i64, Vec<OtPair>> = BTreeMap::new();
    let mut my_setup: BTreeMap<i64, BaseOtSenderSetup> = BTreeMap::new();
    let mut selector: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
    for p in &others {
        let kos_r = binding_bytes(&chan(id, *p, "iknp-kos")).map_err(|e| local(id, &e.to_string()))?;
        let mut r = OtExtReceiver::new(kos_r);
        seeds.insert(*p, r.make_seeds(&mut off.rng));
        off.recv_ch.insert(*p, r);
        let st = mal_base_ot_sender_setup(&mut off.rng, &chan(id, *p, "offline-kappa"));
        my_setup.insert(*p, guard(run, *p, "base OT (sender setup)", st).await?);
        let kos_s = binding_bytes(&chan(*p, id, "iknp-kos")).map_err(|e| local(id, &e.to_string()))?;
        let mut s = OtExtSender::new(kos_s);
        selector.insert(*p, s.make_selector(&mut off.rng));
        off.send_ch.insert(*p, s);
    }
    let their_s = run
        .exchange(
            "ob-S",
            &|peer| {
                let st = &my_setup[&peer];
                json!({"S": pt_value(&st.s), "U": pt_value(&st.proof.u), "z": z_hex(&st.proof.z, proof_lie)})
            },
            &|p, raw| -> PR<(EdwardsPoint, SchnorrProof)> {
                if !raw.is_object() {
                    return Err(bad(id, p, "bad S message"));
                }
                let get = |key: &str| raw.get(key).unwrap_or(&NULL);
                let proof = SchnorrProof { u: point_of(get("U"))?, z: z_bytes(get("z"))? };
                Ok((point_of(get("S"))?, proof))
            },
            &NULL,
            false,
            None,
        )
        .await?;
    let mut respond: BTreeMap<i64, (Vec<EdwardsPoint>, Vec<Vec<u8>>)> = BTreeMap::new();
    for p in &others {
        let (s, proof) = &their_s[p];
        let r = mal_base_ot_receiver_respond(s, proof, &selector[p], &mut off.rng, &chan(*p, id, "offline-kappa"));
        respond.insert(*p, guard(run, *p, "base OT (receiver)", r).await?);
    }
    let their_r = run
        .exchange(
            "ob-R",
            &|peer| Value::Array(respond[&peer].0.iter().map(pt_value).collect()),
            &|p, raw| -> PR<Vec<EdwardsPoint>> {
                let a = raw.as_array().filter(|a| a.len() == OT_KAPPA).ok_or_else(|| bad(id, p, "bad R array"))?;
                Ok(a.iter().map(point_of).collect::<Result<Vec<_>, String>>()?)
            },
            &NULL,
            false,
            None,
        )
        .await?;
    let mut enc: BTreeMap<i64, (Vec<OtPair>, Vec<OtPair>)> = BTreeMap::new();
    for p in &others {
        let st = &my_setup[p];
        let r = mal_base_ot_sender_derive(&st.y, &st.t, &their_r[p], &st.s, &chan(id, *p, "offline-kappa"))
            .and_then(|pads| base_ot_sender_encrypt(&seeds[p], &pads));
        enc.insert(*p, guard(run, *p, "base OT (sender)", r).await?);
    }
    let their_ct = run
        .exchange(
            "ob-C",
            &|peer| json!({"ct": pairs_b64(&enc[&peer].0), "com": pairs_b64(&enc[&peer].1)}),
            &|p, raw| -> PR<(Vec<OtPair>, Vec<OtPair>)> {
                if !raw.is_object() {
                    return Err(bad(id, p, "bad ciphertext message"));
                }
                let get = |key: &str| raw.get(key).unwrap_or(&NULL);
                Ok((parse_pairs(get("ct"), OT_KAPPA, 16)?, parse_pairs(get("com"), OT_KAPPA, 32)?))
            },
            &NULL,
            false,
            None,
        )
        .await?;
    for p in &others {
        let m = &their_ct[p];
        let got = guard(run, *p, "base OT (receiver)", base_ot_receiver_decrypt(&selector[p], &respond[p].1, &m.0, &m.1)).await?;
        let r = off.send_ch.get_mut(p).expect("channel").set_seeds(got);
        guard(run, *p, "base OT (receiver)", r).await?;
    }

    // ------------------------------------------------------------------ the jointly contributed choice-bit gadget
    // signed commit / reveal / echo (gadget.rs): one corrupt party cannot give different honest parties different gadgets
    let agreed = super::gadget::agree_gadget_seeds(run, None).await?;
    off.gadget = gadget_from_seeds(run.mesh.session_id(), &agreed).map_err(le)?;
    let gadget = off.gadget.clone();

    // ------------------------------------------------------------------ my randomness and the input sharings
    let alpha_enc: Vec<EncShare> = (0..k).map(|_| sample_enc(&gadget, &mut off.frng)).collect();
    let alpha_share: Vec<u64> = alpha_enc.iter().map(|e| e.value).collect();
    let mut my_bits: Vec<u8> = vec![input.allow as u8];
    my_bits.extend(crate::mpc::thermometer_encode(input.t as f64, super::protocol::T_M as i64).map_err(|e| local(id, &e.to_string()))?);
    my_bits.extend(crate::mpc::thermometer_encode(input.r_quant as f64, q).map_err(|e| local(id, &e.to_string()))?);
    if my_bits.len() != c {
        return Err(local(id, "input chain count mismatch"));
    }
    // split each of my bits into additive shares: a random share for every peer, the rest is mine
    let out_shares: BTreeMap<i64, Vec<u64>> = others.iter().map(|p| (*p, (0..c).map(|_| off.frng.next()).collect())).collect();
    let my_own: Vec<u64> = (0..c).map(|ch| others.iter().fold(my_bits[ch] as u64, |s, p| fsub(s, out_shares[p][ch]))).collect();
    let got_shares = run
        .exchange(
            "in-share",
            &|peer| Value::Array(out_shares[&peer].iter().map(|v| Value::String(hx(*v as i128))).collect()),
            &|p, raw| arr(id, p, raw, c),
            &NULL,
            false,
            None,
        )
        .await?;
    let mut input_value: Vec<u64> = vec![]; // my value share of every (owner, chain)
    for o in 0..n as i64 {
        for ch in 0..c {
            input_value.push(if o == id { my_own[ch] } else { got_shares[&o][ch] });
        }
    }
    let mask_share = off.frng.next(); // my share of the input-check mask

    let n_t = (n - 1) * c;
    let mut a_e: Vec<EncShare> = vec![];
    let mut b_s: Vec<u64> = vec![];
    let mut ah_e: Vec<Vec<EncShare>> = vec![];
    for _ in 0..n_t {
        a_e.push(sample_enc(&gadget, &mut off.frng));
        b_s.push(off.frng.next());
        ah_e.push((0..p_cnt).map(|_| sample_enc(&gadget, &mut off.frng)).collect());
    }
    let a_s: Vec<u64> = a_e.iter().map(|e| e.value).collect();
    let ah_s: Vec<Vec<u64>> = ah_e.iter().map(|row| row.iter().map(|e| e.value).collect()).collect();

    // ------------------------------------------------------------------ layer 1: products and the MACs of known values
    let mut xs1: Vec<&EncShare> = vec![];
    let mut ys1: Vec<u64> = vec![];
    macro_rules! push {
        ($xs:ident, $ys:ident, $x:expr, $y:expr) => {{
            $xs.push($x);
            $ys.push($y);
            $xs.len() - 1
        }};
    }
    let mut i_c: Vec<usize> = vec![];
    let mut i_ch: Vec<Vec<usize>> = vec![];
    let mut i_ma: Vec<Vec<usize>> = vec![];
    let mut i_mb: Vec<Vec<usize>> = vec![];
    let mut i_mah: Vec<Vec<Vec<usize>>> = vec![];
    for t in 0..n_t {
        i_c.push(push!(xs1, ys1, &a_e[t], b_s[t]));
        i_ch.push((0..p_cnt).map(|r| push!(xs1, ys1, &ah_e[t][r], b_s[t])).collect());
        i_ma.push(alpha_enc.iter().map(|al| push!(xs1, ys1, al, a_s[t])).collect());
        i_mb.push(alpha_enc.iter().map(|al| push!(xs1, ys1, al, b_s[t])).collect());
        i_mah.push((0..p_cnt).map(|r| alpha_enc.iter().map(|al| push!(xs1, ys1, al, ah_s[t][r])).collect()).collect());
    }
    let i_in: Vec<Vec<usize>> = input_value.iter().map(|val| alpha_enc.iter().map(|al| push!(xs1, ys1, al, *val)).collect()).collect();
    let i_mask: Vec<usize> = alpha_enc.iter().map(|al| push!(xs1, ys1, al, mask_share)).collect();
    let keep_items: BTreeSet<usize> = i_c.iter().copied().chain(i_ch.iter().flatten().copied()).collect();
    let lie_at = if offline_lie && !i_c.is_empty() { Some(i_c[0]) } else { None };
    let (z1, kept1) = off.mul_layer(run, "1", &xs1, &ys1, lie_at, Some(&keep_items)).await?;
    drop(xs1);

    // ------------------------------------------------------------------ layer 2: the MACs of the products
    let c_s: Vec<u64> = i_c.iter().map(|i| z1[*i]).collect();
    let ch_s: Vec<Vec<u64>> = i_ch.iter().map(|row| row.iter().map(|i| z1[*i]).collect()).collect();
    let mut xs2: Vec<&EncShare> = vec![];
    let mut ys2: Vec<u64> = vec![];
    let mut i_mc: Vec<Vec<usize>> = vec![];
    let mut i_mch: Vec<Vec<Vec<usize>>> = vec![];
    for t in 0..n_t {
        i_mc.push(alpha_enc.iter().map(|al| push!(xs2, ys2, al, c_s[t])).collect());
        i_mch.push(ch_s[t].iter().map(|chv| alpha_enc.iter().map(|al| push!(xs2, ys2, al, *chv)).collect()).collect());
    }
    let (z2, _) = off.mul_layer(run, "2", &xs2, &ys2, None, None).await?;
    drop(xs2);

    // ------------------------------------------------------------------ assemble, then pairwise-tag every share
    let pa = |x: u64| Pa { x, tag: vec![0; n], key: vec![0; n] };
    let aw = |value: u64, mac_idx: &[usize], z: &[u64]| Aw { v: pa(value), m: mac_idx.iter().map(|i| pa(z[*i])).collect() };
    let mut triples: Vec<Vec<Aw>> = vec![];
    for t in 0..n_t {
        let mut sh = vec![aw(a_s[t], &i_ma[t], &z1), aw(b_s[t], &i_mb[t], &z1), aw(c_s[t], &i_mc[t], &z2)];
        for r in 0..p_cnt {
            sh.push(aw(ah_s[t][r], &i_mah[t][r], &z1));
            sh.push(aw(ch_s[t][r], &i_mch[t][r], &z2));
        }
        if sh.len() != sharings_per_triple(p_cnt) {
            return Err(local(id, "triple assembly mismatch"));
        }
        triples.push(sh);
    }
    let mut inputs: Vec<Aw> = input_value.iter().enumerate().map(|(qi, val)| aw(*val, &i_in[qi], &z1)).collect();
    let mut check_mask = aw(mask_share, &i_mask, &z1);
    let mut alpha: Vec<Pa> = alpha_share.iter().map(|x| pa(*x)).collect();
    // every share, in one fixed order: the MAC keys, the triples, the inputs, the check mask (value share, then its MAC shares)
    let mut all_x: Vec<u64> = alpha.iter().map(|p| p.x).collect();
    for w in triples.iter().flatten().chain(inputs.iter()).chain(std::iter::once(&check_mask)) {
        all_x.push(w.v.x);
        all_x.extend(w.m.iter().map(|m| m.x));
    }
    let (tags, keys) = off.tag_layer(run, "3", &all_x).await?;
    let mut u = 0usize;
    let mut assign = |x: &mut Pa| {
        for p in &others {
            x.tag[*p as usize] = tags[p][u];
            x.key[*p as usize] = keys[p][u];
        }
        u += 1;
    };
    alpha.iter_mut().for_each(&mut assign);
    for w in triples.iter_mut().flatten().chain(inputs.iter_mut()).chain(std::iter::once(&mut check_mask)) {
        assign(&mut w.v);
        w.m.iter_mut().for_each(&mut assign);
    }

    // the OT transcript of the triple products, for the forensic audit of a failed sacrifice
    let rows = gadget.len();
    let fx_others = others.clone();
    let disclose = move |t: usize| -> Vec<crate::mpc_net::SlotDisclosure> {
        let slot = |item: usize, x: &EncShare, z: u64| crate::mpc_net::SlotDisclosure {
            bits: x.bits.clone(),
            y: b_s[t],
            z,
            recv: fx_others.iter().map(|p| (*p, kept1.recv[p][&item].clone())).collect(),
            rho: fx_others.iter().map(|p| (*p, kept1.rho[p][&item].clone())).collect(),
        };
        let mut v = vec![slot(i_c[t], &a_e[t], c_s[t])];
        for (r, item) in i_ch[t].iter().enumerate() {
            v.push(slot(*item, &ah_e[t][r], ch_s[t][r]));
        }
        v
    };
    Ok(Prep {
        mode: Offline::NoDealer,
        tagged: true,
        delta,
        alpha,
        triples,
        inputs,
        my_plain: my_bits.iter().map(|b| *b as u64).collect(),
        check_mask: Some(check_mask),
        forensics: Some(Forensics { gadget, rows, slots: 1 + p_cnt, disclose: Box::new(disclose) }),
    })
}
