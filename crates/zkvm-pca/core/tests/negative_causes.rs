//! Cause attribution for the negative-proving matrix.
//!
//! The guest reports every refusal with the same panic text ("PCA release gate DENIED (allow=0)"), so
//! `fixtures/proof_run/negative_proving.json` cannot say WHY a variant produced no receipt. The guest
//! runs exactly the code of `decide_from_str`, so the cause can be established natively and exactly: for
//! each variant, restore ONE input group (risk/budget, action, chain+grant+root, leaf PCActn, clock,
//! delegation chain+PCActn, tool binding) to the committed compliant value and observe which single restoration turns the
//! denial into an allow. The cause is the group whose restoration is both necessary and sufficient.
//! The table also checks the pure-decision fields recorded in `negative_proving.json` (tier,
//! r_scaled, chain_verified) so this attribution is tied to the variants that were actually proved.
//!
//! Keep `variants()` in step with `negative_variants` in `host/src/bin/prove_run.rs`; the test fails if
//! the names differ from the committed run.

use pca_zkvm_core::decide_from_str;
use serde_json::{json, Value};

fn fx(name: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures").join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn flip_first(s: &str) -> String {
    let mut c: Vec<char> = s.chars().collect();
    c[0] = if c[0] == 'A' { 'B' } else { 'A' };
    c.into_iter().collect()
}

#[path = "support/chain_mint.rs"]
mod mint;

type Variant = (&'static str, Value, &'static str);

fn variants(base: &Value, tv: &Value) -> Vec<Variant> {
    let m = |f: &dyn Fn(&mut Value)| {
        let mut v = base.clone();
        f(&mut v);
        v
    };
    let mut out: Vec<Variant> = vec![
        ("risk_above_theta1_and_zero_budget", m(&|v| { v["risk_inputs_scaled"] = json!([900000, 100000, 900000, 900000, 100000, 900000]); v["budget_scaled"] = json!(0); }), "risk"),
        ("predicate_miss_verb_delete", m(&|v| v["action"]["verb"] = json!("delete")), "action"),
        ("chain_leaf_hop_signature_tampered", m(&|v| { let s = v["chain"][1]["sig"].as_str().unwrap().to_string(); v["chain"][1]["sig"] = json!(flip_first(&s)); }), "chain"),
        ("chain_root_hop_signature_tampered", m(&|v| { let s = v["chain"][0]["sig"].as_str().unwrap().to_string(); v["chain"][0]["sig"] = json!(flip_first(&s)); }), "chain"),
        ("chain_misrooted_wrong_pinned_principal", m(&|v| v["expected_root_principal"] = json!("not-the-pinned-root-principal-key")), "chain"),
        ("chain_leaf_hop_dropped", m(&|v| { let c = v["chain"].as_array().unwrap()[..1].to_vec(); v["chain"] = json!(c); }), "chain"),
        ("leaf_pcactn_signature_tampered", m(&|v| { let s = v["pcactn"]["sig"].as_str().unwrap().to_string(); v["pcactn"]["sig"] = json!(flip_first(&s)); }), "pcactn"),
        ("leaf_pcactn_missing", m(&|v| { v.as_object_mut().unwrap().remove("pcactn"); }), "pcactn"),
        ("chain_hop_alg_pq_unsupported_in_guest", m(&|v| v["chain"][1]["alg"] = json!("ml-dsa-65")), "chain"),
        ("expired_grant", m(&|v| v["now"] = json!(1_760_020_000_000u64)), "clock"),
    ];
    for name in [
        "leaf_sig_noncanonical_S_plus_L",
        "leaf_sig_identity_R_zero_S",
        "leaf_body_digest_tampered",
        "leaf_caveats_emptied_unsigned",
        "mixed_order_delegator_key_with_k_0_mod_8",
    ] {
        let case = tv["cases"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap();
        let mut v = base.clone();
        v["chain"] = case["chain"].clone();
        v["grant"] = case["chain"][0].clone();
        out.push((Box::leak(format!("ts_variant_{name}").into_boxed_str()), v, "chain"));
    }
    // R3-11/12/13: validly signed chains/PCActns that only the new in-guest checks refuse
    out.extend(mint::r3_variants(base));
    // R4-03 / R4-04
    out.extend(mint::r4_variants(base));
    // R5-ZK-01/03/04
    out.extend(mint::r5_variants(base));
    // R6-ZK-01..03 + TS readEnvelope / planLeaf parity
    out.extend(mint::r6_variants(base));
    out
}

/// Restore one input group of `variant` to the committed compliant `base` value.
fn restore(variant: &Value, base: &Value, group: &str) -> Value {
    let mut v = variant.clone();
    let keys: &[&str] = match group {
        "risk" => &["risk_inputs_scaled", "budget_scaled"],
        "action" => &["action"],
        "chain" => &["chain", "grant", "expected_root_principal"],
        "pcactn" => &["pcactn"],
        "clock" => &["now"],
        "delegation" => &["chain", "grant", "expected_root_principal", "pcactn", "delegation_depth"],
        "toolbinding" => &["tool_binding"],
        "wire" => &["env", "subject"],
        "plan" => &["plan", "pcactn", "node_id", "action"],
        _ => unreachable!(),
    };
    for k in keys {
        match base.get(*k) {
            Some(b) => v[*k] = b.clone(),
            None => {
                v.as_object_mut().unwrap().remove(*k);
            }
        }
    }
    v
}

#[test]
fn every_negative_variant_has_exactly_one_restoring_group_and_it_is_the_expected_cause() {
    let base: Value = serde_json::from_str(&fx("decide_input.sample.json")).unwrap();
    let tv: Value = serde_json::from_str(&fx("ts_chain_variants.json")).unwrap();
    let neg: Value = serde_json::from_str(&fx("proof_run/negative_proving.json")).unwrap();
    assert_eq!(decide_from_str(&base.to_string()).allow, 1, "control");

    let vs = variants(&base, &tv);
    let committed: Vec<&str> = neg.as_array().unwrap().iter().map(|r| r["variant"].as_str().unwrap()).collect();
    let ours: Vec<&str> = vs.iter().map(|(n, _, _)| *n).collect();
    assert_eq!(ours, committed, "variant list drifted from the committed proving run");

    let groups = ["risk", "action", "chain", "pcactn", "clock", "delegation", "toolbinding", "wire", "plan"];
    let mut summary = Vec::new();
    for ((name, v, expected), rec) in vs.iter().zip(neg.as_array().unwrap()) {
        let d = decide_from_str(&v.to_string());
        assert_eq!(d.allow, 0, "{name}");
        // tie to the committed run
        let pd = &rec["pure_decision"];
        assert_eq!((d.tier as u64, d.r_scaled, d.chain_verified as u64), (pd["tier"].as_u64().unwrap(), pd["r_scaled"].as_u64().unwrap(), pd["chain_verified"].as_u64().unwrap()), "{name}: differs from negative_proving.json");
        // "delegation" (chain+PCActn re-minted together) overlaps "chain" and "pcactn" by construction: it is only a
        // candidate for the R3-11/12 variants, and never for the older ones.
        let in_play = |g: &&str| match *expected {
            "delegation" => *g != "chain" && *g != "pcactn" && *g != "plan",
            "plan" => *g != "chain" && *g != "pcactn" && *g != "delegation",
            "pcactn" if name.starts_with("r3_") || name.starts_with("r4_") || name.starts_with("r5_") => *g != "delegation" && *g != "chain" && *g != "plan",
            _ => *g != "delegation" && *g != "plan",
        };
        let fixing: Vec<&str> = groups.iter().copied().filter(in_play).filter(|g| decide_from_str(&restore(v, &base, g).to_string()).allow == 1).collect();
        assert_eq!(fixing, vec![*expected], "{name}: groups whose restoration allows");
        // attribution is exclusive: the cause group is the only one that matters, and restoring ALL BUT it stays denied
        let others_restored = groups.iter().copied().filter(in_play).filter(|g| g != expected).fold(v.clone(), |acc, g| restore(&acc, &base, g));
        assert_eq!(decide_from_str(&others_restored.to_string()).allow, 0, "{name}: restoring every other group must not allow");
        summary.push(format!("{name} -> {expected} (chain_verified={})", d.chain_verified));
    }
    eprintln!("{}", summary.join("\n"));
    // chain causes are visible in the decision, too: chain_verified==0 exactly for chain/pcactn causes
    for ((name, v, expected), _) in vs.iter().zip(neg.as_array().unwrap()) {
        let d = decide_from_str(&v.to_string());
        // r5_wire_* / r5_cap_* / r5_03 unsafe integer: refused before chain verification (strict wire limits), so chain_verified is 0 as well
        let chain_cause = *expected == "chain"
            || (*expected == "pcactn" && !name.starts_with("r3_") && !name.starts_with("r4_") && !name.starts_with("r5_"))
            || name.starts_with("r5_wire_")
            || name.starts_with("r5_cap_")
            // the unsafe integer sits in a SIGNED caveat: the strict wire profile of the chain refuses it before verification
            || *name == "r5_03_delegated_unsafe_integer_in_schema"
            // no well-formed envelope (readEnvelope): `decide` returns before verifying the chain
            || name.starts_with("r6_envelope_");
        assert_eq!(d.chain_verified == 0, chain_cause, "{name}");
    }
}
