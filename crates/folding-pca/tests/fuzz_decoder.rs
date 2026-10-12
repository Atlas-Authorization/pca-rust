//! Bounded structure-aware fuzzing of the compressed-proof decoder + verifier, with an allocation watchdog.
//!
//! The committed proof (bincode, fixed-int lengths) is mutated for `FOLD_FUZZ_SECS` (default 20 s): byte
//! flips, hostile 8-byte length prefixes at random offsets, boundary field-element blocks, truncation,
//! insertion, deletion, duplication. Requirements: no panic escapes `decode + verify`, no mutant verifies,
//! no single allocation exceeds 256 MiB (a hostile length prefix must not make the process abort).
//! A child-process pass rewrites an 8-byte length prefix at every 8th offset to a hostile size and
//! requires every child to exit normally.
//!
//! Run: `FOLD_FUZZ_SECS=120 cargo test --release --test fuzz_decoder -- --nocapture`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::{Duration, Instant};

use pca_folding_ivc::{circuits_for, compress_keys, public_params, verify_compressed, ActionStep, CompVerifierKey, Compressed};

struct Watchdog;
static MAX_ALLOC: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Watchdog {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        MAX_ALLOC.fetch_max(l.size(), Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        MAX_ALLOC.fetch_max(new, Relaxed);
        System.realloc(p, l, new)
    }
}
#[global_allocator]
static A: Watchdog = Watchdog;

fn proof_bytes() -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/compressed_proof.bin")).unwrap()
}
fn vk() -> CompVerifierKey {
    let hist: Vec<ActionStep> = (0..8u64).map(|i| ActionStep { action_digest: 0xC0FF_EE00 + i, cost: 100_000 }).collect();
    let c = circuits_for(&hist);
    let pp = public_params(&c[0]).unwrap();
    compress_keys(&pp).unwrap().1
}
fn decode_and_verify(bytes: &[u8], vk: &CompVerifierKey) -> bool {
    match bincode::deserialize::<Compressed>(bytes) {
        Ok(p) => verify_compressed(&p, vk, 8).is_ok(),
        Err(_) => false,
    }
}

const HOSTILE: [u64; 7] = [1 << 33, 1 << 40, 1 << 52, 1 << 58, 1 << 62, u64::MAX / 32, u64::MAX];

#[test]
fn child_probe() {
    let (Ok(off), Ok(idx)) = (std::env::var("FUZZ_OFF"), std::env::var("FUZZ_IDX")) else { return };
    let mut b = proof_bytes();
    let off: usize = off.parse().unwrap();
    if off + 8 > b.len() {
        return;
    }
    b[off..off + 8].copy_from_slice(&HOSTILE[idx.parse::<usize>().unwrap()].to_le_bytes());
    // decode only: the verifier key is not needed to expose an allocation abort in the decoder
    let _ = bincode::deserialize::<Compressed>(&b);
}

#[test]
fn hostile_length_prefixes_never_abort_the_process() {
    let exe = std::env::current_exe().unwrap();
    let len = proof_bytes().len();
    let stride: usize = std::env::var("FOLD_ABORT_STRIDE").ok().and_then(|s| s.parse().ok()).unwrap_or(8);
    let bad = std::sync::Mutex::new(Vec::new());
    let spawned = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for t in 0..8usize {
            let (exe, bad, spawned) = (&exe, &bad, &spawned);
            s.spawn(move || {
                for off in (t * stride..len).step_by(8 * stride) {
                    for idx in [2usize, 4, 6] {
                        let st = std::process::Command::new(exe)
                            .args(["--exact", "child_probe", "--nocapture"])
                            .env("FUZZ_OFF", off.to_string())
                            .env("FUZZ_IDX", idx.to_string())
                            .stderr(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .status()
                            .unwrap();
                        spawned.fetch_add(1, Relaxed);
                        if !st.success() {
                            bad.lock().unwrap().push((off, idx, format!("{st:?}")));
                        }
                    }
                }
            });
        }
    });
    let bad = bad.into_inner().unwrap();
    eprintln!("abort hunt: {} child processes, {} abnormal exits", spawned.load(Relaxed), bad.len());
    assert!(bad.is_empty(), "decoder aborted on a hostile length prefix: {:?}", &bad[..bad.len().min(10)]);
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn structure_aware_fuzz_bounded_budget() {
    let secs: u64 = std::env::var("FOLD_FUZZ_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(20);
    let vk = vk();
    let good = proof_bytes();
    assert!(decode_and_verify(&good, &vk));
    std::panic::set_hook(Box::new(|_| {}));
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut execs, mut accepted, mut escaped, mut decoded) = (0u64, 0u64, 0u64, 0u64);
    MAX_ALLOC.store(0, Relaxed);
    while Instant::now() < deadline {
        let mut m = good.clone();
        match rng.below(8) {
            0 => {
                let i = rng.below(m.len());
                m[i] ^= 1 << rng.below(8);
            }
            1 => {
                let i = rng.below(m.len() - 8);
                m[i..i + 8].copy_from_slice(&HOSTILE[rng.below(HOSTILE.len())].to_le_bytes());
            }
            2 => {
                // a 32-byte field-element block replaced by a boundary value
                let i = rng.below(m.len() / 32) * 32;
                let mut blk = [0u8; 32];
                match rng.below(4) {
                    0 => {}
                    1 => blk[0] = 1,
                    2 => blk = [0xff; 32],
                    _ => {
                        blk[..16].copy_from_slice(&u128::MAX.to_le_bytes());
                    }
                }
                m[i..i + 32].copy_from_slice(&blk);
            }
            3 => {
                let cut = 1 + rng.below(m.len() - 1);
                m.truncate(cut);
            }
            4 => {
                let i = rng.below(m.len());
                let n = 1 + rng.below(64);
                let ins: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                m.splice(i..i, ins);
            }
            5 => {
                let i = rng.below(m.len());
                let n = (1 + rng.below(200)).min(m.len() - i);
                m.drain(i..i + n);
            }
            6 => {
                let n = 1 + rng.below(512);
                let (a, b) = (rng.below(m.len() - n), rng.below(m.len() - n));
                let blk = m[a..a + n].to_vec();
                m[b..b + n].copy_from_slice(&blk);
            }
            _ => {
                let i = rng.below(m.len() / 8) * 8;
                let j = rng.below(m.len() / 8) * 8;
                for k in 0..8 {
                    m.swap(i + k, j + k);
                }
            }
        }
        if m == good {
            continue;
        }
        execs += 1;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (bincode::deserialize::<Compressed>(&m).is_ok(), decode_and_verify(&m, &vk)))) {
            Ok((d, v)) => {
                decoded += d as u64;
                accepted += v as u64;
            }
            Err(_) => escaped += 1,
        }
    }
    let _ = std::panic::take_hook();
    let max_alloc = MAX_ALLOC.load(Relaxed);
    eprintln!("fuzz: {execs} executions in {secs}s; decoded {decoded}; accepted mutants {accepted}; panics escaping decode+verify {escaped}; largest single allocation {max_alloc} bytes");
    assert_eq!(accepted, 0, "a mutated proof verified");
    assert_eq!(escaped, 0, "panic escaped decode+verify");
    assert!(max_alloc < 256 << 20, "single allocation of {max_alloc} bytes");
    assert!(execs > 200, "too few executions: {execs}");
}
