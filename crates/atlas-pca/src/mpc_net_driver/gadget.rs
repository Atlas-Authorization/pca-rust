//! Agreement on the joint choice-bit gadget seeds: a signed commit-reveal with an echo round, so that ONE corrupt party cannot make the
//! honest parties derive different gadgets and then blame each other.
//!
//! A plain commit-reveal leaves each party's message to each peer unauthenticated beyond the TLS link, so a corrupt party could send a
//! different commitment and seed to each honest peer; the honest parties would then compute different gadgets, the triple sacrifice would
//! fail, and the forensic audit (which uses each verifier's OWN gadget) would make honest parties accuse each other. Here every commitment
//! and every opening is SIGNED by its sender with the sender's pinned TLS identity key. After the reveal each party echoes to every peer
//! the signed values it received from each third party (`gd-e`):
//!
//! - an echoed signature that does not verify is a forgery by the echoer: blame the echoer (first-hand, checked against the pinned key);
//! - an echoed statement that verifies but differs from the one received directly from the same signer means the signer signed two
//!   values for one round: blame the signer, with both signed statements as TRANSFERABLE evidence. An honest party signs one value per
//!   round, so it can never be framed this way.
//!
//! With n = 2 there is no third party to equivocate towards, so the echo round is skipped.
use super::protocol::{bad, hex64, hexs, rand32, PErr, Run};
use super::NULL;
use crate::mpc_net::{gadget_commit, gadget_statement, NetAbort, NetAbortOpts};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// A signed value: the value and the hex of its ECDSA signature.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Signed {
    v: String,
    s: String,
}

impl Signed {
    fn to_value(&self) -> Value {
        json!({"v": self.v, "s": self.s})
    }
}

/// A `{v, s}` object whose value is 64 lowercase hex digits and whose signature is 16..200 lowercase hex digits.
fn signed_of(x: &Value) -> Option<Signed> {
    let v = x.get("v")?.as_str()?;
    let s = x.get("s")?.as_str()?;
    let hex = |t: &str| t.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
    if v.len() != 64 || !hex(v) || !(16..=200).contains(&s.len()) || !hex(s) {
        return None;
    }
    Some(Signed { v: v.to_string(), s: s.to_string() })
}

/// Hex decoding as a byte buffer reads it: whole pairs only, a trailing odd digit is dropped.
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).filter_map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect()
}

/// Run the signed commit / reveal / echo and return every party's seed in party order (mine included). `my_seed` is injectable for tests.
pub async fn agree_gadget_seeds(run: &mut Run<'_>, my_seed: Option<[u8; 32]>) -> Result<Vec<Vec<u8>>, NetAbort> {
    let (id, n) = (run.id, run.n);
    let sid = run.session_id.clone();
    let mesh = run.mesh;
    let sign = |round: &str, value: &str| -> Result<Signed, NetAbort> {
        let sig = mesh.sign(&gadget_statement(&sid, round, id, value))?;
        Ok(Signed { v: value.to_string(), s: hexs(&sig) })
    };
    let check = |signer: i64, round: &str, m: &Signed| mesh.verify(signer, &gadget_statement(&sid, round, signer, &m.v), &unhex(&m.s));

    let my_seed = my_seed.unwrap_or_else(rand32);
    let my_commit = sign("gd-c", &gadget_commit(&sid, id, &my_seed))?.to_value();
    let commits: BTreeMap<i64, Signed> = run
        .exchange(
            "gd-c",
            &|_| my_commit.clone(),
            &|p, raw| {
                let m = signed_of(raw).ok_or_else(|| bad(id, p, "bad gadget commitment"))?;
                if !check(p, "gd-c", &m) {
                    return Err(bad(id, p, "gadget commitment signature does not verify"));
                }
                Ok(m)
            },
            &NULL,
            false,
            None,
        )
        .await?;
    let my_open = sign("gd-o", &hexs(&my_seed))?.to_value();
    let opens: BTreeMap<i64, Signed> = run
        .exchange(
            "gd-o",
            &|_| my_open.clone(),
            &|p, raw| {
                let m = signed_of(raw).ok_or_else(|| bad(id, p, "bad gadget seed"))?;
                if !check(p, "gd-o", &m) {
                    return Err(bad(id, p, "gadget seed signature does not verify"));
                }
                let (_, seed) = hex64(&Value::String(m.v.clone())).ok_or_else(|| bad(id, p, "bad gadget seed"))?;
                if gadget_commit(&sid, p, &seed) != commits[&p].v {
                    return Err(PErr::Abort(super::nab(
                        "commitment",
                        Some(p),
                        id,
                        &format!("party {p} opened a gadget seed that does not match its commitment"),
                    )));
                }
                Ok(m)
            },
            &NULL,
            false,
            None,
        )
        .await?;

    if n >= 3 {
        let others = run.others.clone();
        run.exchange(
            "gd-e",
            &|peer| {
                Value::Array(others.iter().filter(|j| **j != peer).map(|j| json!({"j": j, "c": commits[j].to_value(), "o": opens[j].to_value()})).collect())
            },
            &|p, raw| {
                let expect: Vec<i64> = others.iter().copied().filter(|j| *j != p).collect();
                let a = raw.as_array().filter(|a| a.len() == expect.len()).ok_or_else(|| bad(id, p, "bad gadget echo"))?;
                for (e, j) in a.iter().zip(&expect) {
                    let (ec, eo) = match (e.get("j").and_then(Value::as_f64), e.get("c").and_then(signed_of), e.get("o").and_then(signed_of)) {
                        (Some(ej), Some(c), Some(o)) if ej == *j as f64 => (c, o),
                        _ => return Err(bad(id, p, "bad gadget echo entry")),
                    };
                    // a statement that does not verify under j's pinned key was forged by the echoer p
                    if !check(*j, "gd-c", &ec) || !check(*j, "gd-o", &eo) {
                        return Err(bad(id, p, &format!("gadget echo carries a statement that party {j} did not sign")));
                    }
                    let (mine_c, mine_o) = (&commits[j], &opens[j]);
                    if ec.v != mine_c.v || eo.v != mine_o.v {
                        // both statements verify under j's key and differ: j signed two values for one round
                        let commits_differ = ec.v != mine_c.v;
                        return Err(PErr::Abort(NetAbort::new(
                            "equivocation",
                            Some(*j),
                            id,
                            &format!(
                                "party {j} signed different gadget {} for different parties (shown by party {p}'s echo)",
                                if commits_differ { "commitments" } else { "seeds" }
                            ),
                            None,
                            None,
                            NetAbortOpts {
                                evidence: Some(json!({
                                    "signer": j,
                                    "round": if commits_differ { "gd-c" } else { "gd-o" },
                                    "statements": if commits_differ { [mine_c.to_value(), ec.to_value()] } else { [mine_o.to_value(), eo.to_value()] },
                                })),
                                ..Default::default()
                            },
                        )));
                    }
                }
                Ok(true)
            },
            &NULL,
            false,
            None,
        )
        .await?;
    }
    Ok((0..n as i64).map(|p| if p == id { my_seed.to_vec() } else { unhex(&opens[&p].v) }).collect())
}
