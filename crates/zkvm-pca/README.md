# PCA release gate in a zkVM (RISC Zero)

> Status: **experimental, unaudited, not published.**

The Proof-Carrying Authority release decision (full predicate language, fixed-point risk,
caveats, native SHA-256 commitments and an in-guest Ed25519 capability-chain check) runs inside a
RISC Zero guest. The host produces a succinct receipt whose journal is the public statement
(`allow`, `r_scaled`, `tier`, three commitments, `chain_verified`).

## Verifying the committed receipt

No guest toolchain, proving or GPU is needed to verify:

```
cargo test -p pca-zkvm-verify      # receipt checks (verification only)
cargo test -p pca-zkvm-core        # decision logic, standard vectors, reference cross-checks
```

## What is validated

- **Committed receipt.** The committed succinct receipt verifies against the committed image id,
  its claim binds the image id and the SHA-256 of the journal, and the journal equals the
  committed statement and the output of the pure decision logic on the committed input.
- **Rejections, with reasons.** A wrong image id (24 single-bit variants) and a mutated, extended,
  truncated or emptied journal (every byte) are rejected with "claim digest does not match the
  expected digest". Seal mutations are rejected as "invalid receipt format" or "verification
  indicates proof is invalid"; a mutated control id, verifier-parameter digest or hash-function
  name is rejected; byte flips across the serialized receipt are rejected.
- **Official vectors.** The five Ed25519 vectors of RFC 8032 section 7.1 verify in the strict
  verifier the guest uses; bit mutations of message, signature and key, key confusion between
  vectors, a non-canonical S (S + L) and a small-order key/R are rejected. The four SHA-256
  vectors of RFC 6234 reproduce. Provenance (URL, retrieval date, SHA-256 of the RFC text) is in
  the fixture file.
- **Reference cross-checks.** The commitments equal the TypeScript reference output, and the
  chain verdicts (untouched, tampered leaf hop, tampered root hop, wrong pinned root) equal those
  of the TypeScript `verifyChain`, which uses a different Ed25519 implementation.

## What is not validated

- The receipt was produced once; proving was not re-run in these checks.
- Only Ed25519 chains are proven in-guest; post-quantum suites fail closed.
- No third-party review of the guest or the decision logic. The zkVM and its parameters are an
  external dependency of the soundness claim.
