//! The seeded FN-DSA generator is SHAKE256(seed) read as a byte stream: every draw takes the next stream bytes, a word draw
//! reads them little-endian (the reference's seeded keygen and signing read the same stream).
use super::*;
use rand_core::RngCore;

// SHAKE256("seed"), first 16 bytes
const SEED_STREAM: [u8; 16] = [
    0x4f, 0xd6, 0x80, 0x0b, 0x5d, 0xdf, 0x65, 0x32, 0x3d, 0xe2, 0x9f, 0x59, 0xe5, 0xda, 0x90, 0xd3,
];

#[test]
fn the_stream_is_shake256_of_the_seed() {
    let mut b = [0u8; 16];
    ShakeRng::new(b"").fill_bytes(&mut b);
    assert_eq!(
        b,
        [
            0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e,
            0xeb, 0x24
        ]
    );
    ShakeRng::new(b"seed").fill_bytes(&mut b);
    assert_eq!(b, SEED_STREAM);
}

#[test]
fn a_word_draw_reads_the_stream_little_endian() {
    assert_eq!(ShakeRng::new(b"seed").next_u32(), 0x0b80_d64f);
    assert_eq!(ShakeRng::new(b"seed").next_u64(), 0x3265_df5d_0b80_d64f);
}

#[test]
fn try_fill_bytes_fills_from_the_stream() {
    let mut b = [0u8; 16];
    ShakeRng::new(b"seed").try_fill_bytes(&mut b).unwrap();
    assert_eq!(b, SEED_STREAM);
}
