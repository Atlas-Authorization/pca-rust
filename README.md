# pca-rust

Proof-Carrying Authority (PCA) verifier for Rust. **Preview.**

PCA is authF: instead of verifying a token, you verify a proof-carrying action (a PCActn) - the capability chain, Merkle plan inclusion, Ed25519 leaf signature and counter. This is a reference verifier that passes the shared conformance vectors.

> Preview: the wire format and API may change before 1.0.

## Install

`cargo add atlas-pca --git https://github.com/Atlas-Authorization/pca-rust` (crate `atlas-pca`; not yet published to crates.io)

## Verify

```rust
use atlas_pca::verify_pcactn_core;

let v = verify_pcactn_core(&pcactn, &grant); // both serde_json::Value
if v.allow {
    // chain, plan_inclusion, leaf_signature, counter all passed
} else {
    eprintln!("denied: {} {:?}", v.reason, v.checks);
}
```

## Conformance tests

The shared golden vectors are vendored in `conformance/` (synced from the hub). Run:

```
cargo test
```

The reference verifier must produce the same `allow` and the same pass/fail for each of the four checks on every vector.

## Links

- Hub (spec, other languages): https://github.com/Atlas-Authorization/pca
- Live docs: https://atlasauth.net/pca
- TypeScript reference: npm `@atlasauth/pca`

## License

MIT
