//! pca-zk command line, used by the CI cross-checks against snarkjs.
//!
//!   pca-zk verify bn254|bls12-381 <vkey.json> <proof.json> <public.json> [--compat]
//!       exit 0 valid, 1 rejected (reason on stderr), 2 usage. --compat reproduces snarkjs' acceptance (see pca_zk.h).
//!   pca-zk prove bn254|bls12-381 <circuit.wasm> <circuit.zkey> <input.json> <proof.json> <public.json> [seed-hex-64]
//!       writes the snarkjs proof.json and public.json; the seed (tests only) makes the proof deterministic.
use pca_zk::{prove, verify, Curve, FLAG_SNARKJS_COMPAT};
use std::process::exit;

fn curve(s: &str) -> Curve {
    match s {
        "bn254" => Curve::Bn254,
        "bls12-381" => Curve::Bls12381,
        _ => usage(),
    }
}

fn usage() -> ! {
    eprintln!("usage: pca-zk verify <curve> <vkey> <proof> <public> [--compat] | pca-zk prove <curve> <wasm> <zkey> <input> <proof-out> <public-out> [seed-hex]");
    exit(2)
}

fn read(p: &str) -> Vec<u8> {
    std::fs::read(p).unwrap_or_else(|e| {
        eprintln!("cannot read {p}: {e}");
        exit(2)
    })
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("verify") if a.len() == 6 || (a.len() == 7 && a[6] == "--compat") => {
            let flags = if a.len() == 7 { FLAG_SNARKJS_COMPAT } else { 0 };
            match verify(curve(&a[2]), flags, &read(&a[3]), &read(&a[4]), &read(&a[5])) {
                Ok(()) => println!("valid"),
                Err(e) => {
                    eprintln!("rejected: {} ({})", e.reason.text(), e.detail);
                    exit(1)
                }
            }
        }
        Some("prove") if a.len() == 8 || a.len() == 9 => {
            let seed = a.get(8).map(|h| {
                let b: Vec<u8> = (0..h.len() / 2)
                    .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap_or(0))
                    .collect();
                <[u8; 32]>::try_from(b.as_slice()).unwrap_or_else(|_| usage())
            });
            match prove(curve(&a[2]), &read(&a[3]), &read(&a[4]), &read(&a[5]), seed) {
                Ok(json) => {
                    let v: serde_json::Value = serde_json::from_str(&json).expect("prover emits JSON");
                    std::fs::write(&a[6], v["proof"].to_string()).expect("write proof");
                    std::fs::write(&a[7], v["publicSignals"].to_string()).expect("write public signals");
                }
                Err(e) => {
                    eprintln!("prove failed ({:?}): {}", e.kind, e.msg);
                    exit(1)
                }
            }
        }
        _ => usage(),
    }
}
