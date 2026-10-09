# atlas-pca

Reference verifier for **Proof-Carrying Authority (PCA)**, an execution-authentication framework for
autonomous agents. The agent presents a self-contained proof-carrying action (PCActn) with every
request, and the resource server verifies it offline instead of trusting a bearer token.

> Status: **0.2.0, unaudited.** Not independently security-reviewed.

## Install

```sh
cargo add atlas-pca
# optional tower/axum middleware
cargo add atlas-pca --features axum
```

## Checks

Verification is stateless and fail-closed, in a fixed normative order: `wire`, `version`, `audience`,
`validity`, `chain`, `grant_ref_bound`, `plan_inclusion`, `leaf_signature`, `counter`.

`grant_ref_bound` (new in 0.2.0) requires the signed `grant_ref` to be byte-equal to the id of the root
capability (`cap_chain[0]`). Proofs that previously verified with a mismatched `grant_ref` are now
rejected. ML-DSA-65 (FIPS-204) leaf signatures are supported alongside Ed25519.

The crate passes the shared 172-vector PCA conformance corpus that the other language verifiers
(TypeScript, Python, Go, ...) also pass.

## Links

- Source: https://github.com/Atlas-Authorization/pca-rust
- Specification and docs: https://github.com/Atlas-Authorization/pca

License: MIT
