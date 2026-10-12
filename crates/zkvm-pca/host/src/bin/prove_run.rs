//! Reproducible proving run for the committed receipts: succinct receipt, Groth16 wrap, and the negative
//! (non-compliant => no receipt) matrix. UNAUDITED / experimental.
//!
//!   cargo run --release -p pca-zkvm-host --bin prove_run -- <out-dir>            (CPU)
//!   cargo run --release -p pca-zkvm-host --features cuda --bin prove_run -- <out-dir>   (NVIDIA GPU)
//!
//! Groth16 wrapping (stark-to-snark) runs the RISC Zero docker prover on x86_64 Linux, so docker must be
//! available on the proving host. Nothing here needs to run on the verifier's machine.
//!
//! Set PCA_SKIP_GROTH16=1 to skip the wrap (e.g. a CUDA build: the CUDA Groth16 wrap needs the `risc0-groth16` rzup
//! component), and PCA_WRAP_ONLY=<succinct receipt> to only wrap an existing succinct receipt via docker.
//! Set PCA_ONLY_NEGATIVE=1 to run only the negative matrix (fast, no proving of the compliant input).
//!
//! Writes: receipt_succinct.bin, receipt_groth16.bin, journal.json, run_stats.json, negative_proving.json.

#[path = "../../../core/tests/support/chain_mint.rs"]
mod mint;

use pca_zkvm_core::{decide_from_str, Decision};
use pca_zkvm_methods::{PCA_ZKVM_GUEST_ELF, PCA_ZKVM_GUEST_ID};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, InnerReceipt, ProverOpts, Receipt};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Instant;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("fixtures")
}

fn env_for(input_json: &str) -> ExecutorEnv<'static> {
    ExecutorEnv::builder().write(&input_json.to_string()).unwrap().build().unwrap()
}

fn id_hex() -> String {
    let mut b = Vec::new();
    for w in PCA_ZKVM_GUEST_ID.iter() {
        b.extend_from_slice(&w.to_le_bytes());
    }
    hex::encode(b)
}

fn flip_first(s: &str) -> String {
    let mut c: Vec<char> = s.chars().collect();
    c[0] = if c[0] == 'A' { 'B' } else { 'A' };
    c.into_iter().collect()
}

/// The negative matrix: (name, mutated input). Each one the pure decision logic must deny.
fn negative_variants(base: &Value) -> Vec<(&'static str, Value)> {
    let mut out: Vec<(&'static str, Value)> = Vec::new();
    let m = |f: &dyn Fn(&mut Value)| {
        let mut v = base.clone();
        f(&mut v);
        v
    };
    out.push(("risk_above_theta1_and_zero_budget", m(&|v| {
        v["risk_inputs_scaled"] = json!([900000, 100000, 900000, 900000, 100000, 900000]);
        v["budget_scaled"] = json!(0);
    })));
    out.push(("predicate_miss_verb_delete", m(&|v| v["action"]["verb"] = json!("delete"))));
    out.push(("chain_leaf_hop_signature_tampered", m(&|v| {
        let s = v["chain"][1]["sig"].as_str().unwrap().to_string();
        v["chain"][1]["sig"] = json!(flip_first(&s));
    })));
    out.push(("chain_root_hop_signature_tampered", m(&|v| {
        let s = v["chain"][0]["sig"].as_str().unwrap().to_string();
        v["chain"][0]["sig"] = json!(flip_first(&s));
    })));
    out.push(("chain_misrooted_wrong_pinned_principal", m(&|v| {
        v["expected_root_principal"] = json!("not-the-pinned-root-principal-key")
    })));
    out.push(("chain_leaf_hop_dropped", m(&|v| {
        let c = v["chain"].as_array().unwrap()[..1].to_vec();
        v["chain"] = json!(c);
    })));
    out.push(("leaf_pcactn_signature_tampered", m(&|v| {
        let s = v["pcactn"]["sig"].as_str().unwrap().to_string();
        v["pcactn"]["sig"] = json!(flip_first(&s));
    })));
    out.push(("leaf_pcactn_missing", m(&|v| {
        v.as_object_mut().unwrap().remove("pcactn");
    })));
    out.push(("chain_hop_alg_pq_unsupported_in_guest", m(&|v| v["chain"][1]["alg"] = json!("ml-dsa-65"))));
    out.push(("expired_grant", m(&|v| v["now"] = json!(1_760_020_000_000u64))));
    // chain variants produced by the TypeScript reference generator whose chain[0] still equals the grant
    let tv: Value = serde_json::from_str(
        &std::fs::read_to_string(fixtures_dir().join("ts_chain_variants.json")).unwrap(),
    )
    .unwrap();
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
        v["grant"] = case["chain"][0].clone(); // chain[0] must be the grant; the torsion case re-seals the root hop
        let n: &'static str = Box::leak(format!("ts_variant_{name}").into_boxed_str());
        out.push((n, v));
    }
    // R3-11/12/13: validly signed chains/PCActns that only the new in-guest checks refuse (shared with core's tests)
    for (n, v, _group) in mint::r3_variants(base) {
        out.push((n, v));
    }
    // R4-03 / R4-04: malformed tool_schema, expired / future / over-long / wrong-version PCActns (validly signed)
    for (n, v, _group) in mint::r4_variants(base) {
        out.push((n, v));
    }
    // R5-ZK-01/03/04: malformed scalar bounds, strict wire limits, `matches` regex budget (validly signed)
    for (n, v, _group) in mint::r5_variants(base) {
        out.push((n, v));
    }
    // R6-ZK-01..03 + TS readEnvelope / planLeaf parity: each one was ALLOWED by the e922536c guest
    for (n, v, _group) in mint::r6_variants(base) {
        out.push((n, v));
    }
    out
}

fn main() {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let out_dir = PathBuf::from(std::env::args().nth(1).expect("usage: prove_run <out-dir>"));
    std::fs::create_dir_all(&out_dir).unwrap();

    let input_json = std::fs::read_to_string(fixtures_dir().join("decide_input.sample.json")).unwrap();
    let input: Value = serde_json::from_str(&input_json).unwrap();
    let input_json = serde_json::to_string(&input).unwrap();
    let host_decision = decide_from_str(&input_json);
    assert_eq!(host_decision.allow, 1, "the committed input must be allowed by the pure decision");
    println!("zkvm version: {}", risc0_zkvm::VERSION);
    println!("image id: {}", id_hex());

    let prover = default_prover();

    // Wrap an existing succinct receipt only (e.g. one proved on a GPU) into Groth16.
    if let Ok(path) = std::env::var("PCA_WRAP_ONLY") {
        let succinct: Receipt = bincode::deserialize(&std::fs::read(&path).unwrap()).unwrap();
        succinct.verify(PCA_ZKVM_GUEST_ID).expect("input succinct receipt must verify");
        let t = Instant::now();
        let groth = prover.compress(&ProverOpts::groth16(), &succinct).expect("groth16 wrap (needs docker on x86_64)");
        let ms = t.elapsed().as_millis();
        assert!(matches!(groth.inner, InnerReceipt::Groth16(_)));
        groth.verify(PCA_ZKVM_GUEST_ID).expect("groth16 receipt verifies");
        assert_eq!(groth.journal.bytes, succinct.journal.bytes);
        let gb = bincode::serialize(&groth).unwrap();
        std::fs::write(out_dir.join("receipt_groth16.bin"), &gb).unwrap();
        std::fs::write(
            out_dir.join("run_stats_wrap.json"),
            serde_json::to_string_pretty(&json!({
                "risc0_zkvm_version": risc0_zkvm::VERSION, "image_id_hex": id_hex(), "wrapped_from": path,
                "groth16_wrap_ms": ms, "groth16_bytes": gb.len(), "cuda_feature": cfg!(feature = "cuda"),
            })).unwrap(),
        ).unwrap();
        println!("groth16 wrap of {path}: {ms} ms, {} bytes", gb.len());
        return;
    }
    let skip_groth16 = std::env::var("PCA_SKIP_GROTH16").is_ok();
    let only_negative = std::env::var("PCA_ONLY_NEGATIVE").is_ok();
    let mut stats = serde_json::Map::new();
    stats.insert("risc0_zkvm_version".into(), json!(risc0_zkvm::VERSION));
    stats.insert("image_id_hex".into(), json!(id_hex()));
    stats.insert("cuda_feature".into(), json!(cfg!(feature = "cuda")));

    // ---- succinct receipt ----------------------------------------------------------------------------
    if !only_negative {
    let t = Instant::now();
    let info = prover
        .prove_with_opts(env_for(&input_json), PCA_ZKVM_GUEST_ELF, &ProverOpts::succinct())
        .expect("compliant input must prove");
    let succinct_ms = t.elapsed().as_millis();
    let succinct = info.receipt;
    assert!(matches!(succinct.inner, InnerReceipt::Succinct(_)));
    succinct.verify(PCA_ZKVM_GUEST_ID).expect("succinct receipt verifies");
    let journal: Decision = succinct.journal.decode().unwrap();
    assert_eq!(journal, host_decision, "journal equals the pure decision");
    assert_eq!(journal.chain_verified, 1);
    let ectx = pca_zkvm_core::context::ExpectedContext::from_input_json(&input_json, 0.0).unwrap();
    pca_zkvm_core::context::check_context(&journal, &ectx).expect("journal context equals the proved input");
    let sb = bincode::serialize(&succinct).unwrap();
    std::fs::write(out_dir.join("receipt_succinct.bin"), &sb).unwrap();
    std::fs::write(out_dir.join("journal.json"), serde_json::to_string_pretty(&journal).unwrap()).unwrap();
    println!("succinct: {succinct_ms} ms, {} bytes, cycles total={} user={} segments={}", sb.len(),
        info.stats.total_cycles, info.stats.user_cycles, info.stats.segments);
    stats.insert("succinct_prove_ms".into(), json!(succinct_ms));
    stats.insert("succinct_bytes".into(), json!(sb.len()));
    stats.insert("total_cycles".into(), json!(info.stats.total_cycles));
    stats.insert("user_cycles".into(), json!(info.stats.user_cycles));
    stats.insert("segments".into(), json!(info.stats.segments));

    // ---- Groth16 wrap (stark-to-snark) -----------------------------------------------------------------
    if skip_groth16 {
        stats.insert("groth16".into(), json!("skipped (PCA_SKIP_GROTH16)"));
    } else {
    let t = Instant::now();
    let groth = prover.compress(&ProverOpts::groth16(), &succinct).expect("groth16 wrap (needs docker on x86_64)");
    let groth_ms = t.elapsed().as_millis();
    assert!(matches!(groth.inner, InnerReceipt::Groth16(_)));
    groth.verify(PCA_ZKVM_GUEST_ID).expect("groth16 receipt verifies");
    assert_eq!(groth.journal.bytes, succinct.journal.bytes);
    let gb = bincode::serialize(&groth).unwrap();
    std::fs::write(out_dir.join("receipt_groth16.bin"), &gb).unwrap();
    println!("groth16: {groth_ms} ms, {} bytes", gb.len());
    stats.insert("groth16_wrap_ms".into(), json!(groth_ms));
    stats.insert("groth16_bytes".into(), json!(gb.len()));
    if let InnerReceipt::Groth16(g) = &groth.inner {
        stats.insert("groth16_seal_bytes".into(), json!(g.seal.len()));
    }
    let r2: Receipt = bincode::deserialize(&gb).unwrap();
    r2.verify(PCA_ZKVM_GUEST_ID).expect("groth16 receipt verifies after a serialize round trip");
    }
    std::fs::write(out_dir.join("run_stats.json"), serde_json::to_string_pretty(&Value::Object(stats)).unwrap()).unwrap();
    }

    // ---- negative proving matrix ---------------------------------------------------------------------
    let mut neg = Vec::new();
    for (name, v) in negative_variants(&input) {
        let s = serde_json::to_string(&v).unwrap();
        let pure = decide_from_str(&s);
        assert_eq!(pure.allow, 0, "{name}: pure decision must deny");
        // 1) execution only
        let ex = default_executor().execute(env_for(&s), PCA_ZKVM_GUEST_ELF);
        let ex_err = match &ex {
            Err(e) => format!("{e:#}"),
            Ok(_) => panic!("SECURITY FAILURE: {name}: the guest EXECUTED to completion"),
        };
        // 2) full proving attempt, succinct, must yield no receipt
        let t = Instant::now();
        let pr = prover.prove_with_opts(env_for(&s), PCA_ZKVM_GUEST_ELF, &ProverOpts::succinct());
        let pr_err = match &pr {
            Err(e) => format!("{e:#}"),
            Ok(_) => panic!("SECURITY FAILURE: {name}: a receipt was produced"),
        };
        println!("NEGATIVE {name}: no receipt ({} ms): {pr_err}", t.elapsed().as_millis());
        neg.push(json!({
            "variant": name,
            "pure_decision": {
                "allow": pure.allow, "tier": pure.tier, "r_scaled": pure.r_scaled, "chain_verified": pure.chain_verified,
                "action_commit_empty": pure.action_commit.is_empty(),
            },
            "execute_error": ex_err,
            "prove_error": pr_err,
            "receipt_produced": false,
        }));
    }
    std::fs::write(out_dir.join("negative_proving.json"), serde_json::to_string_pretty(&neg).unwrap()).unwrap();
    println!("ALL DONE: {} negative variants produced no receipt", neg.len());
}
