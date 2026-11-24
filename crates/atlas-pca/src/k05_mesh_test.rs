//! k05 differential oracle for the cross-domain agent mesh: tests/data/k05-mesh.json.gz, written by the TypeScript reference
//! (tools/pca-audit/k05-oracles/mesh-oracle.mts; every native replays the same file): verifyMeshProof (verdict ok / reason / hop),
//! checkHeadAdvance, the effective authority of a caveat list, and the Merkle primitives under it (verifyLedgerConsistency,
//! verifyNonMembership).
use super::*;
use crate::k042_support::{k05_run, K05};
use serde_json::json;

#[test]
fn k05_mesh_matches_the_reference() {
    k05_run("mesh", 15900, |_, f, a| match f {
        "verifyMeshProof" => {
            let v = verify_mesh_proof(&a[0], &a[1]);
            let mut o = json!({"ok": v.ok});
            if let Some(r) = v.reason {
                o["reason"] = json!(r);
            }
            if let Some(h) = v.hop {
                o["hop"] = json!(h);
            }
            K05::Val(o)
        }
        "checkHeadAdvance" => K05::Val(json!(check_head_advance(a.first(), a.get(1), a.get(2)))),
        "verifyLedgerConsistency" => K05::Val(json!(crate::ledger::verify_ledger_consistency(&a[0], &a[1], &a[2]))),
        "verifyNonMembership" => match (a[0].as_str(), a[2].as_str()) {
            (Some(root), Some(id)) => K05::Val(json!(crate::staleness::verify_non_membership(root, &a[1], id))),
            _ => K05::Skip("non-string root / id (typed port)"),
        },
        "effectiveAuthority" => K05::Val(match effective(a.first()) {
            Err(e) => json!({"error": e}),
            Ok(e) => {
                let mut o = json!({"prefixes": e.prefixes});
                for (k, v) in [("actions", e.actions), ("audience", e.audience)] {
                    if let Some(v) = v {
                        o[k] = json!(v);
                    }
                }
                for (k, v) in [("maxAmount", e.max_amount), ("expiresAt", e.expires_at), ("maxHops", e.max_hops)] {
                    if let Some(v) = v {
                        o[k] = json!(v);
                    }
                }
                o
            }
        }),
        _ => K05::Skip("fn not in this module"),
    });
}

/// a head pinned at size 0 (root '') advances: '' is checked as the RFC 9162 empty-tree root; a non-vacuous or mis-sized proof is refused.
#[test]
fn empty_head_advances() {
    let j: Value = serde_json::from_str(r#"{"e":{"domain":"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A","size":0,"root":"","rev_root":"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8","rev_size":0,"timestamp":1800000000000},"n":{"domain":"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A","size":3,"root":"CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow","rev_root":"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8","rev_size":0,"timestamp":1800000000000},"ok":{"oldSize":0,"newSize":3,"path":[]},"path":{"oldSize":0,"newSize":3,"path":["CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow"]},"old1":{"oldSize":1,"newSize":3,"path":[]}}"#).unwrap();
    let adv = |pf: Option<&Value>| check_head_advance(j.get("e"), j.get("n"), pf);
    assert_eq!(adv(j.get("ok")), None);
    assert_eq!(adv(None), Some("consistency proof required for a larger head"));
    assert_eq!(adv(j.get("path")), Some("head is not consistent with the previous head (fork or rewrite)"));
    assert_eq!(adv(j.get("old1")), Some("consistency proof required for a larger head"));
}
