//! Host driver for the PCA zkVM full-fidelity path.
//!
//! Proves a COMPLIANT input, verifies the receipt, decodes the committed statement, then runs the
//! negative (non-compliant => unprovable) and tamper (mutated journal => verify rejects) tests, and
//! captures cycle count + prove/verify timings. Writes the committed fixtures (image id, decoded
//! journal, sample input) and the succinct sample receipt into `../fixtures`.

use pca_zkvm_core::{commit, decide_from_str, Decision};
use pca_zkvm_methods::{PCA_ZKVM_GUEST_ELF, PCA_ZKVM_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};
use serde_json::{json, Value};
use std::time::Instant;

mod mint;

fn fixtures_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
}

/// Load the sample COMPLIANT DecideInput — the single source of truth produced by the REAL TS
/// implementation (`fixtures/decide_input.sample.json`), so the in-guest native-sha256 commitments can
/// be asserted byte-identical to the TS reference in `fixtures/expected_commitments.json`.
fn compliant_input() -> Value {
    let p = fixtures_dir().join("decide_input.sample.json");
    let s = std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("cannot read {}: {} (run generate_fixture first)", p.display(), e));
    serde_json::from_str(&s).expect("decide_input.sample.json must be valid JSON")
}

/// The TS reference commitments the in-guest sha256 must reproduce.
fn expected_commitments() -> Value {
    let p = fixtures_dir().join("expected_commitments.json");
    let s = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {}", p.display(), e));
    serde_json::from_str(&s).expect("expected_commitments.json must be valid JSON")
}

/// A non-compliant variant: risk-maximal inputs (r > theta1) AND no budget => gate denies.
fn non_compliant_risk(input: &Value) -> Value {
    let mut v = input.clone();
    v["risk_inputs_scaled"] = json!([900000, 100000, 900000, 900000, 100000, 900000]);
    v["budget_scaled"] = json!(0);
    v
}

/// A non-compliant variant: a predicate miss (verb not permitted).
fn non_compliant_predicate(input: &Value) -> Value {
    let mut v = input.clone();
    v["action"]["verb"] = json!("delete");
    v
}

fn build_env(input_json: &str) -> ExecutorEnv<'static> {
    ExecutorEnv::builder()
        .write(&input_json.to_string())
        .unwrap()
        .build()
        .unwrap()
}

fn id_hex() -> String {
    // PCA_ZKVM_GUEST_ID is [u32; 8]; render as the canonical 32-byte little-endian hex digest.
    let mut bytes = Vec::with_capacity(32);
    for word in PCA_ZKVM_GUEST_ID.iter() {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    hex::encode(bytes)
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let fx = fixtures_dir();
    std::fs::create_dir_all(&fx).unwrap();

    // Load the hand-authored TEMPLATE (policy / action / plan / risk inputs) and MINT the REAL signed
    // capability chain + leaf PCActn into it (deterministic from fixed seeds). The regenerated fixtures
    // are written back so `decide_input.sample.json` now carries a real chain and `expected_commitments`
    // reflects the real (real-issuer) grant. Idempotent: re-running reproduces byte-identical fixtures.
    let template = compliant_input();
    let (input, expected_regen) = mint::mint_fixture(&template);
    std::fs::write(
        fx.join("decide_input.sample.json"),
        serde_json::to_string_pretty(&input).unwrap(),
    )
    .unwrap();
    std::fs::write(
        fx.join("expected_commitments.json"),
        serde_json::to_string_pretty(&expected_regen).unwrap(),
    )
    .unwrap();
    let input_json = serde_json::to_string(&input).unwrap();

    // Host-side sanity: run the pure decision (same code the guest runs) and confirm it allows.
    let host_decision = decide_from_str(&input_json);
    println!("== host (pure) decision on the compliant input ==");
    println!("{}", serde_json::to_string_pretty(&host_decision).unwrap());
    assert_eq!(host_decision.allow, 1, "compliant fixture must be allowed by the pure decision");

    let prover = default_prover();

    // ---- cycle count via a cheap composite prove --------------------------------------------------
    println!("\n== proving (composite STARK) the COMPLIANT input ==");
    let t0 = Instant::now();
    let composite = prover
        .prove_with_opts(build_env(&input_json), PCA_ZKVM_GUEST_ELF, &ProverOpts::composite())
        .expect("compliant input must prove");
    let composite_ms = t0.elapsed().as_millis();
    let stats = &composite.stats;
    println!(
        "composite prove: {} ms | total_cycles={} user_cycles={} segments={}",
        composite_ms, stats.total_cycles, stats.user_cycles, stats.segments
    );

    // verify composite
    let tv = Instant::now();
    composite
        .receipt
        .verify(PCA_ZKVM_GUEST_ID)
        .expect("composite receipt must verify");
    let verify_ms = tv.elapsed().as_millis();
    println!("composite verify: {} ms -> OK", verify_ms);

    let journal: Decision = composite.receipt.journal.decode().unwrap();
    println!("journal (committed statement):\n{}", serde_json::to_string_pretty(&journal).unwrap());
    assert_eq!(journal.allow, 1);
    // The gap closure: the receipt attests the full chain-of-authority was verified IN-CIRCUIT.
    assert_eq!(journal.chain_verified, 1, "the proven decision must have verified the signed chain in-circuit");
    println!("chain_verified = {} (signed cap-chain + leaf PCActn verified in-circuit)", journal.chain_verified);

    // ---- cross-check: the in-guest sha256 commitments equal the host's independent recomputation ---
    let action = input.get("action").unwrap();
    let grant = input.get("grant").unwrap();
    let plan: Vec<Value> = input.get("plan").unwrap().as_array().unwrap().clone();
    let host_action_commit = commit::action_commitment(action);
    let host_policy_commit = commit::policy_commitment(grant);
    let host_plan_commit = commit::plan_commitment(&plan).unwrap_or_default();
    println!("\n== commitment cross-check (journal == host recomputation) ==");
    println!("action_commit  journal={} host={}", journal.action_commit, host_action_commit);
    println!("policy_commit  journal={} host={}", journal.policy_commit, host_policy_commit);
    println!("plan_commit    journal={} host={}", journal.plan_commit, host_plan_commit);
    assert_eq!(journal.action_commit, host_action_commit);
    assert_eq!(journal.policy_commit, host_policy_commit);
    assert_eq!(journal.plan_commit, host_plan_commit);

    // ---- HARD byte-match against the TS reference (packages/pca hashCanonical / commitPlan) --------
    let expected = expected_commitments();
    println!("\n== byte-match vs TS reference (packages/pca) ==");
    for (k, got) in [
        ("action_commit", &journal.action_commit),
        ("policy_commit", &journal.policy_commit),
        ("plan_commit", &journal.plan_commit),
    ] {
        let want = expected.get(k).and_then(|v| v.as_str()).unwrap_or("<missing>");
        println!("{:<14} zkVM={} TS={} {}", k, got, want, if got == want { "MATCH" } else { "MISMATCH" });
        assert_eq!(got.as_str(), want, "in-guest {} does not match the TS reference", k);
    }

    // ---- succinct receipt (constant size; the committed sample + the wrap/onchain path) -----------
    println!("\n== proving (succinct) the COMPLIANT input for the committed fixture ==");
    let ts = Instant::now();
    let succinct = prover
        .prove_with_opts(build_env(&input_json), PCA_ZKVM_GUEST_ELF, &ProverOpts::succinct())
        .expect("succinct prove must succeed");
    let succinct_ms = ts.elapsed().as_millis();
    succinct.receipt.verify(PCA_ZKVM_GUEST_ID).expect("succinct receipt must verify");
    let succinct_bytes = bincode::serialize(&succinct.receipt).unwrap();
    println!("succinct prove: {} ms | receipt size: {} bytes", succinct_ms, succinct_bytes.len());

    // ---- NEGATIVE test: a non-compliant witness must be UNPROVABLE --------------------------------
    println!("\n== negative test: non-compliant (risk>theta1, B=0) must NOT prove ==");
    let nc_risk = serde_json::to_string(&non_compliant_risk(&input)).unwrap();
    assert_eq!(decide_from_str(&nc_risk).allow, 0, "host: risk variant must be denied");
    let r1 = prover.prove_with_opts(build_env(&nc_risk), PCA_ZKVM_GUEST_ELF, &ProverOpts::composite());
    match &r1 {
        Err(e) => println!("risk-variant prove correctly FAILED: {}", e),
        Ok(_) => panic!("SECURITY FAILURE: a non-compliant (risk) input produced a valid receipt"),
    }

    println!("\n== negative test: non-compliant (predicate miss) must NOT prove ==");
    let nc_pred = serde_json::to_string(&non_compliant_predicate(&input)).unwrap();
    assert_eq!(decide_from_str(&nc_pred).allow, 0, "host: predicate variant must be denied");
    let r2 = prover.prove_with_opts(build_env(&nc_pred), PCA_ZKVM_GUEST_ELF, &ProverOpts::composite());
    match &r2 {
        Err(e) => println!("predicate-variant prove correctly FAILED: {}", e),
        Ok(_) => panic!("SECURITY FAILURE: a predicate-miss input produced a valid receipt"),
    }

    // ---- NEGATIVE test: a FORGED/TAMPERED chain signature must make the compliant input UNPROVABLE ----
    println!("\n== negative test: tampered leaf-hop chain signature must NOT prove ==");
    let nc_chain = serde_json::to_string(&tamper_chain_sig(&input)).unwrap();
    assert_eq!(decide_from_str(&nc_chain).allow, 0, "host: tampered-chain variant must be denied");
    let r3 = prover.prove_with_opts(build_env(&nc_chain), PCA_ZKVM_GUEST_ELF, &ProverOpts::composite());
    match &r3 {
        Err(e) => println!("tampered-chain prove correctly FAILED: {}", e),
        Ok(_) => panic!("SECURITY FAILURE: a tampered chain signature produced a valid receipt"),
    }

    // ---- NEGATIVE test: a MISROOTED chain (not rooted at the pinned principal) must NOT prove ----
    println!("\n== negative test: misrooted chain (wrong expected_root_principal) must NOT prove ==");
    let nc_root = serde_json::to_string(&misroot_chain(&input)).unwrap();
    assert_eq!(decide_from_str(&nc_root).allow, 0, "host: misrooted-chain variant must be denied");
    let r4 = prover.prove_with_opts(build_env(&nc_root), PCA_ZKVM_GUEST_ELF, &ProverOpts::composite());
    match &r4 {
        Err(e) => println!("misrooted-chain prove correctly FAILED: {}", e),
        Ok(_) => panic!("SECURITY FAILURE: a misrooted chain produced a valid receipt"),
    }

    // ---- TAMPER test: mutate the journal of a valid receipt => verify must reject ------------------
    println!("\n== tamper test: flip a journal byte => verify must reject ==");
    let mut tampered = composite.receipt.clone();
    if tampered.journal.bytes.is_empty() {
        panic!("journal unexpectedly empty");
    }
    tampered.journal.bytes[0] ^= 0xff;
    match tampered.verify(PCA_ZKVM_GUEST_ID) {
        Err(e) => println!("tampered-journal verify correctly REJECTED: {}", e),
        Ok(_) => panic!("SECURITY FAILURE: a tampered journal still verified"),
    }

    // ---- wrong image id: verify must reject -------------------------------------------------------
    println!("\n== wrong-image-id test: verify must reject ==");
    let mut wrong_id = PCA_ZKVM_GUEST_ID;
    wrong_id[0] ^= 0x1;
    match composite.receipt.verify(wrong_id) {
        Err(e) => println!("wrong-image-id verify correctly REJECTED: {}", e),
        Ok(_) => panic!("SECURITY FAILURE: receipt verified under a wrong image id"),
    }

    // ---- write fixtures ---------------------------------------------------------------------------
    let image_id = id_hex();
    std::fs::write(
        fx.join("image_id.json"),
        serde_json::to_string_pretty(&json!({
            "guest": "pca-zkvm-guest",
            "zkvm": "risc0",
            "image_id_hex": image_id,
            "image_id_words": PCA_ZKVM_GUEST_ID,
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(fx.join("public_journal.json"), serde_json::to_string_pretty(&journal).unwrap()).unwrap();
    std::fs::write(fx.join("receipt_succinct.bin"), &succinct_bytes).unwrap();
    // decide_input.sample.json + expected_commitments.json were regenerated above by `mint::mint_fixture`
    // (they now carry a REAL signed chain + leaf PCActn; the policy/action/plan inputs are the template's).

    println!("\n== fixtures written to {} ==", fx.display());
    println!("image_id (sha256-style 32-byte hex): {}", image_id);
    println!("\nALL TESTS PASSED");
}

/// Flip the FIRST base64url character of the leaf hop's signature. The Ed25519 verification of that hop
/// then fails => `verify_chain` denies => `allow=0` => unprovable. The first character carries no
/// trailing-bit constraint, so the mutated signature stays canonical base64url (well-formed but invalid).
fn tamper_chain_sig(input: &Value) -> Value {
    let mut v = input.clone();
    let sig = v["chain"][1]["sig"].as_str().unwrap_or("").to_string();
    v["chain"][1]["sig"] = json!(flip_first_b64u_char(&sig));
    v
}

/// Point `expected_root_principal` at a different value so the chain no longer roots at the pinned
/// principal: `verify_chain` rejects at "root issuer is not the expected principal".
fn misroot_chain(input: &Value) -> Value {
    let mut v = input.clone();
    v["expected_root_principal"] = json!("not-the-pinned-root-principal-key");
    v
}

fn flip_first_b64u_char(s: &str) -> String {
    let mut chars: Vec<char> = s.chars().collect();
    if let Some(c) = chars.first_mut() {
        *c = if *c == 'A' { 'B' } else { 'A' };
    }
    chars.into_iter().collect()
}
