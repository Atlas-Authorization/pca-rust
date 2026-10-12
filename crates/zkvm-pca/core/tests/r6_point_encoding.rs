//! R6: the delegator key A (and the signature's R) must be a CANONICAL encoding, exactly as the TS reference (`keys.ts`
//! `verify`: noble `fromHex(.., zip215 = false)`, not small-order, torsion-free). Golden: fixtures/ts_r6_points.json
//! (tests/gen_ts_r6_points.ts). curve25519-dalek's decompression reduces `y` mod p, so before R6 the guest decoded the
//! `y + p` aliases (y < 19) and a sign-bit-set `x = 0` point to the same group element as the canonical encoding.
use curve25519_dalek::edwards::CompressedEdwardsY;
use pca_zkvm_core::chain::ed25519_point_strict;
use serde_json::Value;

fn golden() -> Value {
    serde_json::from_str(include_str!("../../fixtures/ts_r6_points.json")).unwrap()
}
fn bytes(h: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()).collect();
    v.try_into().unwrap()
}

#[test]
fn point_decoder_equals_the_typescript_reference_on_every_encoding() {
    let g = golden();
    let cases = g["cases"].as_array().unwrap();
    assert!(cases.len() >= 130);
    let mut bad = Vec::new();
    for c in cases {
        let b = bytes(c["hex"].as_str().unwrap());
        let got = ed25519_point_strict(&b).is_some_and(|p| !p.is_small_order());
        if got != c["accept"].as_bool().unwrap() {
            bad.push(format!("{}: ts={} guest={got}", c["name"], c["accept"]));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn non_canonical_aliases_decompress_in_dalek_but_are_refused() {
    // every TS-undecodable alias that dalek still decompresses is refused by the strict decoder
    let mut aliases = 0;
    for c in golden()["cases"].as_array().unwrap() {
        let b = bytes(c["hex"].as_str().unwrap());
        if !c["decodes"].as_bool().unwrap() && CompressedEdwardsY(b).decompress().is_some() {
            aliases += 1;
            assert!(ed25519_point_strict(&b).is_none(), "{}", c["name"]);
        }
    }
    assert!(aliases > 0, "the golden must contain dalek-decodable non-canonical aliases");
}
