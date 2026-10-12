//! Wraps the committed succinct receipt into a Groth16 receipt and verifies it against the
//! committed image id. Usage: pca-zkvm-wrap <fixtures-dir> <out-dir>
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{default_prover, InnerReceipt, ProverOpts, Receipt};
use std::time::Instant;

fn main() {
    let mut a = std::env::args().skip(1);
    let fx = std::path::PathBuf::from(a.next().expect("fixtures dir"));
    let out = std::path::PathBuf::from(a.next().expect("out dir"));
    std::fs::create_dir_all(&out).unwrap();

    let id: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fx.join("image_id.json")).unwrap()).unwrap();
    let words: Vec<u32> = id["image_id_words"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_u64().unwrap() as u32)
        .collect();
    let image_id = Digest::from(<[u32; 8]>::try_from(words).expect("8 words"));

    let succinct: Receipt =
        bincode::deserialize(&std::fs::read(fx.join("receipt_succinct.bin")).unwrap()).unwrap();
    assert!(matches!(succinct.inner, InnerReceipt::Succinct(_)));
    succinct.verify(image_id).expect("input succinct receipt must verify");

    let t = Instant::now();
    let g16 = default_prover()
        .compress(&ProverOpts::groth16(), &succinct)
        .expect("groth16 compress");
    let ms = t.elapsed().as_millis();
    assert!(matches!(g16.inner, InnerReceipt::Groth16(_)), "result must be Groth16");
    g16.verify(image_id).expect("groth16 receipt must verify");
    assert_eq!(g16.journal.bytes, succinct.journal.bytes);

    let bytes = bincode::serialize(&g16).unwrap();
    std::fs::write(out.join("receipt_groth16.bin"), &bytes).unwrap();
    println!("GROTH16_OK compress_ms={ms} receipt_bytes={}", bytes.len());
}
