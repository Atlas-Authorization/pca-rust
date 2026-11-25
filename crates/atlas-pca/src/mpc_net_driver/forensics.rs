//! The commit-first exchange of the post-abort disclosure of the discarded triple's OT transcript (dealer-free mode), so a wrong operand
//! in the offline triple products is ATTRIBUTED instead of only detected. The pure parts (wire form, strict parse, audit, blame choice,
//! commitment) are in [`crate::mpc_net`]; this is the network round.
//!
//! COMMIT FIRST: disclosures are not sent in the clear first. Every party first broadcasts a hiding, binding commitment to its disclosure
//! (`forensic-c`), and only after it holds ALL commitments does it open (`forensic-o`). A rushing corrupt OT sender therefore cannot read
//! the honest receivers' choice bits and received values and then solve for a `rho` / `y` that passes every pair and self check. A party
//! whose opening does not match its commitment is blamed (`commitment`); one that never commits or opens within the shared deadline is
//! blamed by timeout (a first-hand observation of the blaming party, not transferable proof).
use super::protocol::{bad, hex64, hexs, rand32, PErr, Run};
use super::NULL;
use crate::mpc_net::{disclosure_commit, parse_disclosure, wire_disclosure, NetAbort, SlotDisclosure};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub struct ForensicArgs<'a> {
    pub triple_index: i64,
    pub mine: &'a [SlotDisclosure],
    pub slots: usize,
    pub rows: usize,
    /// Time every party has to produce its commitment and opening; shared by all parties and carried in the commit message.
    pub deadline_ms: i64,
}

/// Commit-first disclosure exchange. Returns every OTHER party's verified disclosure.
pub async fn exchange_disclosures(run: &mut Run<'_>, a: ForensicArgs<'_>) -> Result<BTreeMap<i64, Vec<SlotDisclosure>>, NetAbort> {
    let (id, n) = (run.id, run.n as i64);
    let sid = run.session_id.clone();
    let wire = wire_disclosure(a.mine);
    let nonce = hexs(&rand32());
    let my_commit = disclosure_commit(&sid, id, a.triple_index, a.deadline_ms, &nonce, &wire);
    let timeout = Some(a.deadline_ms.max(0) as u64);
    let commits = run
        .exchange(
            "forensic-c",
            &|_| json!({"c": my_commit, "d": a.deadline_ms}),
            &|p, raw| {
                let c = raw.get("c").and_then(hex64).map(|x| x.0).ok_or_else(|| bad(id, p, "bad forensic commitment"))?;
                if raw.get("d").and_then(Value::as_f64) != Some(a.deadline_ms as f64) {
                    let got = raw.get("d").map_or("undefined".to_string(), |v| v.to_string());
                    return Err(bad(id, p, &format!("forensic deadline {got} differs from the agreed {}", a.deadline_ms)));
                }
                Ok(c)
            },
            &NULL,
            false,
            timeout,
        )
        .await?;
    run.exchange(
        "forensic-o",
        &|_| json!({"w": wire, "nonce": nonce}),
        &|p, raw| {
            let nonce = raw.get("nonce").and_then(hex64).map(|x| x.0).ok_or_else(|| bad(id, p, "bad forensic opening"))?;
            let w = raw.get("w").unwrap_or(&NULL);
            if disclosure_commit(&sid, p, a.triple_index, a.deadline_ms, &nonce, w) != commits[&p] {
                return Err(PErr::Abort(super::nab(
                    "commitment",
                    Some(p),
                    id,
                    &format!("party {p} opened a forensic disclosure that does not match its commitment"),
                )));
            }
            let peers: Vec<i64> = (0..n).filter(|q| *q != p).collect();
            Ok(parse_disclosure(w, a.slots, a.rows, &peers)?)
        },
        &NULL,
        false,
        timeout,
    )
    .await
}
