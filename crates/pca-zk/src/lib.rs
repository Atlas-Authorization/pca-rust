//! pca-zk: Groth16 verification and proving for snarkjs / circom artifacts on BN254 and BLS12-381 (arkworks), and the
//! C library built from it (libpcazk, cargo feature `capi`, header include/pca_zk.h). Rust callers use this crate directly.
pub mod prove;
pub mod verify;
mod witness;

#[cfg(feature = "capi")]
pub mod capi;

pub use prove::{prove, ProveError, ProveKind};
pub use verify::{verify, verify_snarkjs, Curve, Reason, Reject, FLAG_SNARKJS_COMPAT};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
