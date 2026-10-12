//! Structure-aware fuzzing of the proof decoder and verifier, with an allocation watchdog.
//!
//! * `hostile_counts_never_abort_the_process` is the regression test for a real defect: a length
//!   prefix *inside* an opaque batch opening (reached only during verification, not during decoding)
//!   could be rewritten to 2^52 and made `verify_release_bytes` abort the process with
//!   "memory allocation of ... bytes failed". Every candidate offset is rewritten in a child process
//!   (an abort cannot be caught in-process) and the child must exit cleanly.
//! * `structure_aware_fuzz_bounded_budget` mutates a valid proof with structure-aware operators for a
//!   bounded time (`STARK_FUZZ_SECS`, default 12 s) under a counting allocator: no panic may escape,
//!   no input may verify, and no single allocation may exceed 64 MiB.
//!
//! Run: `STARK_FUZZ_SECS=120 cargo test --release --test fuzz_decoder -- --nocapture`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::{Duration, Instant};

use stark_pca::{prove_release, verify_release_bytes, PolicyParams, Witness};
use winter_utils::{ByteWriter, Serializable};

// ---- allocation watchdog -------------------------------------------------------------------------
struct Watchdog;
static MAX_ALLOC: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Watchdog {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        MAX_ALLOC.fetch_max(l.size(), Relaxed);
        let live = LIVE.fetch_add(l.size(), Relaxed) + l.size();
        PEAK.fetch_max(live, Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        MAX_ALLOC.fetch_max(new, Relaxed);
        if new > l.size() {
            let live = LIVE.fetch_add(new - l.size(), Relaxed) + (new - l.size());
            PEAK.fetch_max(live, Relaxed);
        } else {
            LIVE.fetch_sub(l.size() - new, Relaxed);
        }
        System.realloc(p, l, new)
    }
}
#[global_allocator]
static A: Watchdog = Watchdog;

fn fixture() -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/sample_proof.bin")).unwrap()
}

/// Write `n` as a 9-byte variable-length integer (the encoding's special case): 0x00 then u64 LE.
fn vint9(n: u64) -> [u8; 9] {
    let mut b = [0u8; 9];
    b[1..].copy_from_slice(&n.to_le_bytes());
    b
}

const HOSTILE: [u64; 8] = [1 << 33, 1 << 40, 1 << 52, 1 << 58, (1 << 58) + 1, 1 << 62, u64::MAX / 24, u64::MAX];

// ---------------------------------------------------------------- child-process abort hunt

#[test]
fn child_probe() {
    // executed by the parent below via `--exact child_probe` with the offset in the environment
    let (Ok(off), Ok(idx)) = (std::env::var("FUZZ_OFF"), std::env::var("FUZZ_IDX")) else { return };
    let mut b = fixture();
    let off: usize = off.parse().unwrap();
    let n = HOSTILE[idx.parse::<usize>().unwrap()];
    if off + 9 > b.len() {
        return;
    }
    b[off..off + 9].copy_from_slice(&vint9(n));
    let _ = verify_release_bytes(&b, &PolicyParams::default_policy());
}

#[test]
fn hostile_counts_never_abort_the_process() {
    let exe = std::env::current_exe().unwrap();
    let len = fixture().len();
    let stride: usize = std::env::var("STARK_ABORT_STRIDE").ok().and_then(|s| s.parse().ok()).unwrap_or(4);
    let bad = std::sync::Mutex::new(Vec::new());
    let spawned = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for t in 0..8usize {
            let (exe, bad, spawned) = (&exe, &bad, &spawned);
            s.spawn(move || {
                for off in (t * stride..len).step_by(8 * stride) {
                    for idx in [2usize, 3, 5, 7] {
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
    assert!(bad.is_empty(), "verifier aborted on hostile counts: {:?}", &bad[..bad.len().min(10)]);
}

// ---------------------------------------------------------------- bounded structure-aware fuzz

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

thread_local! { static PANICS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) }; }

#[test]
fn structure_aware_fuzz_bounded_budget() {
    let secs: u64 = std::env::var("STARK_FUZZ_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(12);
    let policy = PolicyParams::default_policy();
    let good = fixture();
    // a second valid proof (different statement) as a splice donor
    let mut w2 = Witness::compliant();
    w2.inputs[0] += 5_000;
    let mut p2 = policy.clone();
    let wc = stark_pca::compute_witness_commitment(&w2);
    p2.witness_commitment = core::array::from_fn(|m| winterfell::math::StarkField::as_int(&wc[m]).to_string());
    let donor = prove_release(&w2, &p2).unwrap().to_bytes();
    assert!(verify_release_bytes(&good, &policy).is_ok());

    std::panic::set_hook(Box::new(|info| {
        let loc = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
        PANICS.with(|p| p.borrow_mut().push(loc));
    }));

    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut execs, mut accepted_mutants) = (0u64, 0u64);
    let mut by_op = [0u64; 9];
    MAX_ALLOC.store(0, Relaxed);
    while Instant::now() < deadline {
        let mut m = good.clone();
        let op = rng.below(9);
        by_op[op] += 1;
        match op {
            0 => {
                let i = rng.below(m.len());
                m[i] ^= 1 << rng.below(8);
            }
            1 => {
                // hostile 9-byte count at a random position
                let i = rng.below(m.len() - 9);
                m[i..i + 9].copy_from_slice(&vint9(HOSTILE[rng.below(HOSTILE.len())]));
            }
            2 => {
                // hostile count in the canonical (shortest) variable-length encoding
                let i = rng.below(m.len() - 9);
                let mut w = Vec::new();
                w.write_usize(HOSTILE[rng.below(HOSTILE.len())] as usize);
                let n = w.len();
                m[i..i + n].copy_from_slice(&w);
            }
            3 => {
                // whole 16-byte element replaced by a boundary value
                let i = rng.below(m.len() / 16) * 16;
                let vals = [0u128, 1, u128::MAX, (1u128 << 127), 0xFFFF_FFFF_FFFF_FFFF, 0xffffffffffffff00_u128 << 64];
                m[i..i + 16].copy_from_slice(&vals[rng.below(vals.len())].to_le_bytes());
            }
            4 => {
                let cut = 1 + rng.below(m.len() - 1);
                m.truncate(cut);
            }
            5 => {
                let i = rng.below(m.len());
                let n = 1 + rng.below(64);
                let ins: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                m.splice(i..i, ins);
            }
            6 => {
                let i = rng.below(m.len());
                let n = (1 + rng.below(200)).min(m.len() - i);
                m.drain(i..i + n);
            }
            7 => {
                // splice a block from the donor proof at the same offset
                let i = rng.below(m.len().min(donor.len()) - 1);
                let n = (1 + rng.below(2000)).min(m.len().min(donor.len()) - i);
                m[i..i + n].copy_from_slice(&donor[i..i + n]);
            }
            _ => {
                // duplicate a block over another place
                let n = 1 + rng.below(512);
                let a = rng.below(m.len() - n);
                let b = rng.below(m.len() - n);
                let blk = m[a..a + n].to_vec();
                m[b..b + n].copy_from_slice(&blk);
            }
        }
        execs += 1;
        if m == good {
            continue;
        }
        if verify_release_bytes(&m, &policy).is_ok() {
            accepted_mutants += 1;
        }
    }
    let _ = std::panic::take_hook();
    let panics = PANICS.with(|p| p.borrow().clone());
    let mut distinct = panics.clone();
    distinct.sort();
    distinct.dedup();
    let max_alloc = MAX_ALLOC.load(Relaxed);
    eprintln!(
        "fuzz: {execs} executions in {secs}s (ops {by_op:?}); accepted mutants {accepted_mutants}; internal panics caught {} at {distinct:?}; largest single allocation {} bytes; peak live {} bytes",
        panics.len(),
        max_alloc,
        PEAK.load(Relaxed)
    );
    assert_eq!(accepted_mutants, 0, "a mutated proof verified");
    assert!(max_alloc < 64 << 20, "single allocation of {max_alloc} bytes while decoding hostile input");
    assert!(execs > 1000, "too few executions: {execs}");
}

/// In-process regression for the nested-count abort: rewriting a length prefix inside an opaque
/// batch opening to 2^52 used to abort the verifier ("memory allocation of 108086391056891904 bytes
/// failed") before the opening layout was pre-validated. The offsets are found by scanning the
/// committed proof (they move whenever the proof options change): every offset whose rewrite is
/// refused by the opening-layout check must be refused at decode time, without allocating.
#[test]
fn nested_count_rewrite_is_refused_at_decode_time() {
    let good = fixture();
    let mut refused = 0;
    for off in 0..good.len() - 9 {
        let mut m = good.clone();
        m[off..off + 9].copy_from_slice(&vint9(1 << 52));
        let Err(e) = stark_pca::proof_from_bytes(&m) else { continue };
        if format!("{e:?}").contains("batch opening") {
            assert!(verify_release_bytes(&m, &PolicyParams::default_policy()).is_err());
            refused += 1;
        }
    }
    assert!(refused >= 7, "only {refused} nested-count offsets found");
    assert!(MAX_ALLOC.load(Relaxed) < 64 << 20);
}
