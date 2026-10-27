# atlas-pca

Reference verifier for **Proof-Carrying Authority (PCA)**, an execution-authentication framework for
autonomous agents. The agent presents a self-contained proof-carrying action (PCActn) with every
request, and the resource server verifies it offline instead of trusting a bearer token.

> Status: **0.4.3, unaudited.** Not independently security-reviewed.

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

## Caveats (policy layer)

The core verifier (and the `axum` middleware) does **not** evaluate caveats: it checks that they are carried, signed and
only ever appended along the chain, and treats their content as opaque. A resource server that enforces a grant's caveats
calls the policy-layer helpers with its own action:

```rust
use atlas_pca::{evaluate_caveats, policy_caveats};
use serde_json::json;

let ctx = json!({
    "now": now_ms,
    "delegation_depth": chain.as_array().map_or(0, |c| c.len().saturating_sub(1)),
    "action": { "verb": "pay", "resource": "invoice:42", "params": { "amount": 50, "currency": "usd" } },
});
let (ok, failed) = evaluate_caveats(&policy_caveats(&grant, &chain), &ctx);
if !ok { /* deny: `failed` lists the unsatisfied caveat types */ }
```

`policy_caveats` is the ROOT grant's caveats (minus its first `envelope` caveat, the policy container) followed by the
caveats the delegation hops appended. Since 0.4.1 the root's own caveats are included, so a `max_spend` (or any other
caveat) placed directly on the root grant is enforced exactly like one a hop appended. Implemented types: `max_spend`,
`expires`, `not_before`, `rate`, `max_blast_radius`, `reversibility_max`, `delegation_depth`, `budget_alloc`; any other
type is unsatisfied (fail closed).

The `PCA-Action` header is decoded strictly (`decode_pca_header`): unpadded base64url only, no whitespace, canonical
trailing bits, valid UTF-8. Anything else is a `401`.

## Links

- Source: https://github.com/Atlas-Authorization/pca-rust
- Specification and docs: https://github.com/Atlas-Authorization/pca

License: MIT

## Suite policy defaults

- No list (`None`) means no restriction: the verifier accepts every signature suite it knows.
- An empty list (`Some(&[])`) means refuse everything.
- The hosted API defaults to `ed25519` plus the hybrids that include Ed25519, and refuses the pure post-quantum suites (`ml-dsa-*`, `slh-dsa-*`, `fn-dsa-*`, `less-cat1`) unless the operator lists them. To match it offline, pass `allowed_suites` exactly: `ed25519`, `hybrid-ed25519-ml-dsa-65`, `hybrid-nested-ed25519-ml-dsa-65`, `hybrid-ed25519-ml-dsa-87`, `hybrid-ed25519-slh-dsa-sha2-128f`, `hybrid-ed25519-slh-dsa-sha2-256s`, `hybrid-ed25519-less-cat1`. The effective hosted list is readable at `GET /v1/pca/suites`; see docs/pca/reference/wire-formats.md.
