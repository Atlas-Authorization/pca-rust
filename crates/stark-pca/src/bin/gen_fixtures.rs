//! Generate committed fixtures: a sample STARK proof + its public inputs + the verifier
//! parameters. Run with `cargo run --release --bin gen_fixtures`.

use std::fs;
use std::time::Instant;

use stark_pca::{
    prove_release, verify_release, PolicyParams, Witness, MIN_SECURITY_BITS, S, TRACE_LEN, WIDTH,
};
use winterfell::math::StarkField;

fn main() {
    let policy = PolicyParams::default_policy();
    let witness = Witness::compliant();

    let t0 = Instant::now();
    let proof = prove_release(&witness, &policy).expect("prove failed");
    let prove_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let bytes = proof.to_bytes();

    let t1 = Instant::now();
    verify_release(
        winterfell::Proof::from_bytes(&bytes).unwrap(),
        &policy,
    )
    .expect("verify failed");
    let verify_ms = t1.elapsed().as_secs_f64() * 1000.0;

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    fs::create_dir_all(&dir).unwrap();

    // sample proof (binary)
    fs::write(dir.join("sample_proof.bin"), &bytes).unwrap();

    // public inputs (the policy; verifier reconstructs PublicInputs from this)
    let pub_json = serde_json::to_string_pretty(&serde_json::json!({
        "description": "Public inputs for the committed sample release-gate STARK proof.",
        "policy": policy,
        "public_field_elements": policy
            .to_public_elements_decimal(),
    }))
    .unwrap();
    fs::write(dir.join("public_inputs.json"), pub_json).unwrap();

    // verifier parameters ("vkey-equivalent": STARKs are transparent — there is no vkey;
    // these public parameters + the AIR source fully determine verification).
    let params_json = serde_json::to_string_pretty(&serde_json::json!({
        "scheme": "zk-STARK (Winterfell), transparent / hash-based / post-quantum / no trusted setup",
        "hash": "Blake3_256",
        "field": "f128 (Winterfell 128-bit prime field)",
        "field_extension": "None",
        "num_queries": 32,
        "blowup_factor": 8,
        "grinding_factor": 0,
        "fri_folding_factor": 8,
        "fri_max_remainder_degree": 31,
        "min_conjectured_security_bits": MIN_SECURITY_BITS,
        "trace_width": WIDTH,
        "trace_length": TRACE_LEN,
        "scale_S": S,
        "proof_size_bytes": bytes.len(),
        "note": "A STARK has no circuit-specific trusted setup and no verifying key; the AIR definition in src/lib.rs plus these public parameters are the complete verification artifact."
    }))
    .unwrap();
    fs::write(dir.join("params.json"), params_json).unwrap();

    let r = stark_pca::risk_raw(&witness.inputs, &policy.weights);
    println!("fixtures written to {}", dir.display());
    println!("  proof size      : {} bytes", bytes.len());
    println!("  prove time      : {:.1} ms", prove_ms);
    println!("  verify time     : {:.1} ms", verify_ms);
    println!("  r (scale S^2)   : {}  ->  r = {:.6}", r, r as f64 / (S as u128 * S as u128) as f64);
    println!("  theta1 (S^2)    : {}", policy.to_public().t1_rraw.as_int());
    println!("  allow           : 1 (verified OK)");
}

// Small helper on PolicyParams for the fixture JSON.
trait PubElemsDecimal {
    fn to_public_elements_decimal(&self) -> Vec<String>;
}
impl PubElemsDecimal for PolicyParams {
    fn to_public_elements_decimal(&self) -> Vec<String> {
        use winterfell::math::ToElements;
        self.to_public()
            .to_elements()
            .iter()
            .map(|e| e.as_int().to_string())
            .collect()
    }
}
