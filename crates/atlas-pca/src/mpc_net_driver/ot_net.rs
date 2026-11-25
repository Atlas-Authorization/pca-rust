//! Pairwise base oblivious transfer OVER THE NETWORK (the malicious-secure Chou-Orlandi-style OT on Ed25519: Schnorr proof of knowledge,
//! subgroup validation of every received point, transcript KDF), run between two nodes of a mesh. A FUNCTIONAL-CORRECTNESS demonstration:
//! after the protocol the receiver reveals its choice bits and a hash of each received pad (a demo-only step, NOT part of the OT) so the
//! sender can check that the pad the receiver got equals its own pad at the receiver's choice.
//!
//! The post-quantum endemic-LWE variant (`kind = "lwe"`, Masny-Rindal over Module-LWE) runs when the crate is built with the `mpc-endemic`
//! feature next to `mpc-net-driver`; without it the kind is refused.
use super::mesh::Mesh;
use super::offline::{point_of, pt_value, z_bytes, z_hex};
use super::protocol::hexs;
use super::{local, nab, NULL};
use crate::mpc_net::NetAbort;
#[cfg(feature = "mpc-endemic")]
use crate::mpc_net::{b64, unb64};
use crate::mpc_ot::{
    binding_bytes, mal_base_ot_receiver_respond, mal_base_ot_sender_derive, mal_base_ot_sender_setup, BaseOtBinding, OtError, OtPair, OtRng, SchnorrProof,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct OtNetResult {
    pub kind: String,
    pub role: &'static str,
    pub count: usize,
    pub ms: f64,
    pub matched: bool,
    /// Digest over all pads this party holds (sender: both pads; receiver: the chosen pads): evidence, not secrets.
    pub pad_digest: String,
}

impl OtNetResult {
    pub fn to_json(&self) -> Value {
        json!({"kind": self.kind, "role": self.role, "count": self.count, "ms": self.ms, "matched": self.matched, "padDigest": self.pad_digest})
    }
}

fn sha(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    hexs(&h.finalize())
}

/// Binding of a base OT on this mesh: the session (hashed to a fixed length), who sends, who receives, which round.
pub fn net_binding(mesh: &Mesh, sender_index: i64, receiver_index: i64, round: &str) -> BaseOtBinding {
    let sid = Sha256::new().chain_update(b"atlas-pca-mpc/net-session/v2").chain_update(mesh.session_id().as_bytes()).finalize().to_vec();
    BaseOtBinding { session_id: sid, sender_index, receiver_index, round: round.to_string() }
}

/// Wrap peer-supplied data parsing so any failure aborts naming the peer.
async fn parsing<T>(mesh: &Mesh, peer: i64, rd: &str, r: Result<T, String>) -> Result<T, NetAbort> {
    match r {
        Ok(v) => Ok(v),
        Err(m) => Err(mesh.abort(nab("malformed", Some(peer), mesh.self_id(), &format!("round '{rd}': {m}"))).await),
    }
}

fn require_kind(mesh: &Mesh, kind: &str) -> Result<(), NetAbort> {
    match kind {
        "ec" => Ok(()),
        #[cfg(feature = "mpc-endemic")]
        "lwe" => Ok(()),
        #[cfg(not(feature = "mpc-endemic"))]
        "lwe" => Err(local(mesh.self_id(), "base OT kind 'lwe' needs the mpc-endemic feature")),
        other => Err(local(mesh.self_id(), &format!("unknown base OT kind '{other}'"))),
    }
}

/// The endemic-LWE sender: reads the receiver's message, answers with the ciphertexts, returns the sender pads.
#[cfg(feature = "mpc-endemic")]
async fn lwe_sender(mesh: &Mesh, peer: i64, count: usize, rng: &mut OtRng) -> Result<Vec<OtPair>, NetAbort> {
    use crate::mpc_endemic::{send_random, Pair, ReceiverMessage};
    let me = mesh.self_id();
    let m = mesh.recv(peer, "ot-recv", None).await?;
    let msg = parsing(
        mesh,
        peer,
        "ot-recv",
        (|| -> Result<ReceiverMessage, String> {
            let points = m.get("points").and_then(Value::as_array).filter(|a| a.len() == count);
            let rhos = m.get("rhos").and_then(Value::as_array).filter(|a| a.len() == count);
            let (points, rhos) = points.zip(rhos).ok_or("bad receiver message")?;
            let pair = |pp: &Value| -> Result<Pair, String> {
                match pp.as_array().map(Vec::as_slice) {
                    Some([a, b]) => Ok((unb64(a, None)?, unb64(b, None)?)),
                    _ => Err("bad point pair".to_string()),
                }
            };
            Ok(ReceiverMessage {
                rn: unb64(m.get("rn").unwrap_or(&NULL), Some(32))?,
                points: points.iter().map(pair).collect::<Result<_, _>>()?,
                rhos: rhos.iter().map(|r| unb64(r, Some(32))).collect::<Result<_, _>>()?,
            })
        })(),
    )
    .await?;
    let sm = match send_random(&msg, rng, None) {
        Ok(x) => x,
        Err(e) => return Err(mesh.abort(nab("malformed", Some(peer), me, &format!("lwe sender: {e}"))).await),
    };
    mesh.send(peer, "ot-ct", Value::Array(sm.ciphertexts.iter().map(|(a, b)| json!([b64(a), b64(b)])).collect())).await?;
    Ok(sm.sender_pads.into_iter().map(|(a, b)| [a, b]).collect())
}

/// The endemic-LWE receiver: sends its message for `choices`, reads the ciphertexts, returns the chosen pads.
#[cfg(feature = "mpc-endemic")]
async fn lwe_receiver(mesh: &Mesh, peer: i64, count: usize, choices: &[i64], rng: &mut OtRng) -> Result<Vec<Vec<u8>>, NetAbort> {
    use crate::mpc_endemic::{receive, recover_random, Pair, SenderMessage};
    let bits: Vec<u8> = choices.iter().map(|&c| c as u8).collect();
    let (message, state) = receive(&bits, rng).map_err(|e| local(mesh.self_id(), &e.to_string()))?;
    mesh.send(
        peer,
        "ot-recv",
        json!({
            "rn": b64(&message.rn),
            "points": message.points.iter().map(|(a, b)| json!([b64(a), b64(b)])).collect::<Vec<_>>(),
            "rhos": message.rhos.iter().map(|r| b64(r)).collect::<Vec<_>>(),
        }),
    )
    .await?;
    let ct_raw = mesh.recv(peer, "ot-ct", None).await?;
    let ciphertexts = parsing(
        mesh,
        peer,
        "ot-ct",
        (|| -> Result<Vec<Pair>, String> {
            let a = ct_raw.as_array().filter(|a| a.len() == count).ok_or("bad ciphertext array")?;
            a.iter()
                .map(|pp| match pp.as_array().map(Vec::as_slice) {
                    Some([x, y]) => Ok((unb64(x, None)?, unb64(y, None)?)),
                    _ => Err("bad ct pair".to_string()),
                })
                .collect()
        })(),
    )
    .await?;
    parsing(mesh, peer, "ot-ct", recover_random(&state, &SenderMessage { ciphertexts, sender_pads: vec![] }).map_err(|e| e.to_string())).await
}

pub async fn run_ot_sender(mesh: &Mesh, peer: i64, kind: &str, count: usize) -> Result<OtNetResult, NetAbort> {
    require_kind(mesh, kind)?;
    let t0 = Instant::now();
    let mut rng = OtRng::Secure;
    #[cfg(feature = "mpc-endemic")]
    let pads: Vec<OtPair> = if kind == "lwe" { lwe_sender(mesh, peer, count, &mut rng).await? } else { ec_sender(mesh, peer, count, &mut rng).await? };
    #[cfg(not(feature = "mpc-endemic"))]
    let pads: Vec<OtPair> = ec_sender(mesh, peer, count, &mut rng).await?;
    sender_verify(mesh, peer, kind, count, pads, t0).await
}

async fn ec_sender(mesh: &Mesh, peer: i64, count: usize, rng: &mut OtRng) -> Result<Vec<OtPair>, NetAbort> {
    let me = mesh.self_id();
    let binding = net_binding(mesh, me, peer, "ot-ec");
    binding_bytes(&binding).map_err(|e| local(me, &e.to_string()))?;
    let setup = mal_base_ot_sender_setup(rng, &binding).map_err(|e| local(me, &e.to_string()))?;
    mesh.send(peer, "ot-S", json!({"S": pt_value(&setup.s), "U": pt_value(&setup.proof.u), "z": z_hex(&setup.proof.z, false)})).await?;
    let r_raw = mesh.recv(peer, "ot-R", None).await?;
    let r = parsing(
        mesh,
        peer,
        "ot-R",
        (|| -> Result<Vec<_>, String> {
            let a = r_raw.as_array().filter(|a| a.len() == count).ok_or("bad R array")?;
            a.iter().map(point_of).collect()
        })(),
    )
    .await?;
    let pads: Vec<OtPair> = match mal_base_ot_sender_derive(&setup.y, &setup.t, &r, &setup.s, &binding) {
        Ok(p) => p,
        Err(e) => return Err(mesh.abort(nab("malformed", Some(peer), me, &e.to_string())).await),
    };
    Ok(pads)
}

async fn sender_verify(mesh: &Mesh, peer: i64, kind: &str, count: usize, pads: Vec<OtPair>, t0: Instant) -> Result<OtNetResult, NetAbort> {
    // demo-only verification: the receiver reveals choices and pad hashes
    let v = mesh.recv(peer, "ot-verify", None).await?;
    let ok = parsing(
        mesh,
        peer,
        "ot-verify",
        (|| -> Result<bool, String> {
            let choices = v.get("choices").and_then(Value::as_array).filter(|c| c.len() == count).ok_or("bad verify message")?;
            let hashes = v.get("padHashes").and_then(Value::as_array).filter(|c| c.len() == count).ok_or("bad verify message")?;
            Ok(choices.iter().enumerate().all(|(i, c)| match c.as_f64() {
                Some(x) if x == 0.0 || x == 1.0 => hashes[i].as_str() == Some(sha(&[pads[i][x as usize].as_slice()]).as_str()),
                _ => false,
            }))
        })(),
    )
    .await?;
    mesh.send(peer, "ot-done", json!({"matched": ok})).await?;
    mesh.finish().await;
    let all: Vec<&[u8]> = pads.iter().flat_map(|p| [p[0].as_slice(), p[1].as_slice()]).collect();
    Ok(OtNetResult { kind: kind.to_string(), role: "sender", count, ms: t0.elapsed().as_secs_f64() * 1000.0, matched: ok, pad_digest: sha(&all) })
}

pub async fn run_ot_receiver(mesh: &Mesh, peer: i64, kind: &str, count: usize) -> Result<OtNetResult, NetAbort> {
    require_kind(mesh, kind)?;
    let t0 = Instant::now();
    let mut rng = OtRng::Secure;
    let choices: Vec<i64> = rng.bytes(count).iter().map(|b| (b & 1) as i64).collect();
    #[cfg(feature = "mpc-endemic")]
    let recv_pads =
        if kind == "lwe" { lwe_receiver(mesh, peer, count, &choices, &mut rng).await? } else { ec_receiver(mesh, peer, &choices, &mut rng).await? };
    #[cfg(not(feature = "mpc-endemic"))]
    let recv_pads = ec_receiver(mesh, peer, &choices, &mut rng).await?;
    let hashes: Vec<String> = recv_pads.iter().map(|p| sha(&[p.as_slice()])).collect();
    mesh.send(peer, "ot-verify", json!({"choices": choices, "padHashes": hashes})).await?;
    let d = mesh.recv(peer, "ot-done", None).await?;
    let matched = d.get("matched") == Some(&Value::Bool(true));
    mesh.finish().await;
    let all: Vec<&[u8]> = recv_pads.iter().map(|p| p.as_slice()).collect();
    Ok(OtNetResult { kind: kind.to_string(), role: "receiver", count, ms: t0.elapsed().as_secs_f64() * 1000.0, matched, pad_digest: sha(&all) })
}

async fn ec_receiver(mesh: &Mesh, peer: i64, choices: &[i64], rng: &mut OtRng) -> Result<Vec<Vec<u8>>, NetAbort> {
    let me = mesh.self_id();
    let s_raw = mesh.recv(peer, "ot-S", None).await?;
    let (s, proof) = parsing(
        mesh,
        peer,
        "ot-S",
        (|| -> Result<_, String> {
            if !s_raw.is_object() {
                return Err("bad S message".to_string());
            }
            let get = |k: &str| s_raw.get(k).unwrap_or(&NULL);
            let proof = SchnorrProof { u: point_of(get("U"))?, z: z_bytes(get("z"))? };
            Ok((point_of(get("S"))?, proof))
        })(),
    )
    .await?;
    let (r, recv_pads) = match mal_base_ot_receiver_respond(&s, &proof, choices, rng, &net_binding(mesh, peer, me, "ot-ec")) {
        Ok(x) => x,
        Err(e) => {
            let kind = if matches!(e, OtError::BaseOtAbort(_)) { "commitment" } else { "malformed" };
            return Err(mesh.abort(nab(kind, Some(peer), me, &e.to_string())).await);
        }
    };
    mesh.send(peer, "ot-R", Value::Array(r.iter().map(pt_value).collect())).await?;
    Ok(recv_pads)
}
