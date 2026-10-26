# atlas-pca

> Maturity: **stable** (stable core). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Reference verifier for **Proof-Carrying Authority (PCA)**, an execution-authentication framework for
autonomous agents. The agent presents a self-contained proof-carrying action (PCActn) with every
request, and the resource server verifies it offline instead of trusting a bearer token.

> Status: **0.4.1, unaudited.** Not independently security-reviewed.

## Install

```sh
cargo add atlas-pca
# optional tower/axum middleware
cargo add atlas-pca --features axum
```

## Checks

Verification is stateless and fail-closed, in a fixed normative order: `wire`, `version`, `audience`,
`validity`, `chain`, `grant_ref_bound`, `plan_inclusion`, `leaf_signature`, `counter_format`.

`grant_ref_bound` (new in 0.2.0) requires the signed `grant_ref` to be byte-equal to the id of the root
capability (`cap_chain[0]`). Proofs that previously verified with a mismatched `grant_ref` are now
rejected. ML-DSA-65 (FIPS-204) leaf signatures are supported alongside Ed25519.

The crate runs the shared PCA conformance corpus: 676 PCActn vectors (129 that must verify, 547 that must be
refused) and 984 primitive vectors (canonical JSON, base64url, JSON parsing, Merkle proofs, caveat evaluation,
threshold shares, chain pins and more). The cross-language gate also runs it against the full adversarial set of
4,358 PCActn vectors and 1,178 adversarial primitives. The TypeScript, Python, Go and other verifiers run the same files. Vectors
that need a signature suite this crate does not implement are skipped by the runner; the verifier refuses such a
suite with `unsupported_suite`.

## What a passing result does not cover

`counter_format: pass` is a format check: the counter is a non-negative integer. It does **not** mean the action was not
replayed. Verification is stateless by design, and the crate has no replay store, so the resource server must persist,
per grant and agent, the last accepted counter and refuse anything not strictly greater, atomically across all of its
processes.

The `axum` middleware runs `authorize` by default (next section). Only if you opt in with `with_signature_only()` does it run
the core verifier alone, and then it does not check replay, revocation, caveats, envelope predicates, plan authorization,
risk or thresholds, and does not compare the request body with the signed `params_digest`. Do those checks in your handler
(the caveat and predicate helpers below, `params_digest` on the body you will execute, your replay and revocation stores).

## authorize: verify the proof AND the operation (0.5)

`authorize` verifies the PCActn and binds it to the operation your handler will execute: the params must open the signed
digest (a proof for $50 cannot execute $400, a proof for X cannot execute Y), the grant's envelope predicates and root and
delegated caveats are evaluated (an unknown caveat type fails closed), revocation is checked, and only then is an atomic
replay claim made. A missing component (audience, grant resolver, replay store, revocation check, operation) denies with
status 403 and names what is missing.

```rust
use atlas_pca::{authorize, AuthorizeInput, MemoryStateStore, Operation};

let store = MemoryStateStore::new(); // one process; feature `sqlite`: SqliteStateStore::open("replay.db")
let op = Operation::new("payments.send", "payments/acme", params); // from YOUR routing and parsed input
let resolve = |grant_ref: &str| Ok::<_, String>(grants.get(grant_ref).cloned());
let revoked = |_pcactn: &_, grant: &_| Ok::<_, String>(revocations.contains(grant));
let result = authorize(Some(&pcactn), &AuthorizeInput {
    operation: Some(&op),
    audience: "payments-rs",
    resolve_grant: Some(&resolve),
    state_store: Some(&store),
    is_revoked: Some(&revoked),
    plan: Some("single-step"),
    ..Default::default()
});
if !result.allow { /* result.status is 401 or 403, result.reason the decisive reason */ }
```

Implement `StateStore::claim(key, counter)` over your database as one atomic operation (strictly increasing counter per
key). `MemoryStateStore` is the in-process reference; the `sqlite` feature adds `SqliteStateStore` (one upsert per claim).

With the `axum` feature the default guard runs `authorize`. Configure it with
`GuardConfig::with_authorize(AuthorizeOptions::new(store, is_revoked))` and
`GuardConfig::with_operation(|parts, body| Some(Operation::new(..)))`: a denied request never reaches the inner service, and
an allowed one carries the `AuthorizeResult` as a request extension. A `GuardConfig` without `with_authorize` refuses every
request with 403 `authorize_config`, naming what is missing (`state_store`, `is_revoked`); it never falls back to
signature-only.

Verifying the signature, chain and freshness only is an explicit opt-in, `GuardConfig::new(..).with_signature_only()`: no
policy, replay, revocation or operation binding. Calling both `with_signature_only` and `with_authorize` panics at construction.

### Check names and denial reasons

- `counter_format` is the core verifier's check that the counter is a well-formed non-negative safe integer
  (`counter_format: missing or not a non-negative safe integer`).
- `replay` is the stateful check in `authorize`: `replay: 3 is not greater than last seen 3 (replay)`,
  `replay: 3 was already claimed (replay)` or `replay: the replay store failed (fail closed)`.
- `DEFAULT_REQUIRED_CHECKS` (must be `pass`): `counter_format`, `replay`, `revocation`, `plan_root_authorized`, `audience`,
  `validity`, `grant_ref_bound`, `operation`, `params_digest`, `policy`, plus `AuthorizeInput::require`. The name `counter`
  in `require` is accepted as an alias of `replay`.
- When the action's verb and resource are in scope of a predicate but one of its `where` limits is not met, the denial names
  the limit: `policy: amount <= 100 not satisfied for payments.send on payments/acme`, or
  `currency in ["usd", "eur"] not satisfied for ...`. When no predicate is in scope the reason stays
  `no predicate permits <verb> on <resource>`.

### Upgrading to 0.5

- `GuardConfig` now runs `authorize` by default. Add `with_authorize(..)` and `with_operation(..)`, or call
  `with_signature_only()` to keep the old signature-only behaviour.
- The check `counter` is now `counter_format` in the core verdict; a replay refusal is reported under `replay`.
- `DEFAULT_REQUIRED_CHECKS` has 10 entries instead of 9.
- A reason `no predicate permits ...` for an unmet limit now names the limit.

## Ledger and optimistic-path verification (0.5)

`atlas_pca::ledger` checks the transparency ledger: RFC 9162 consistency proofs, signed tree heads pinned to the guardian key, k-of-n witness cosignatures, head-to-head consistency, whole checkpoint chains and equivocation between witnessed heads. Tamper evidence holds as long as at least one independent honest witness cosigns the heads you pin.

```rust
use atlas_pca::ledger::{verify_checkpoint_chain, verify_tree_head};
// policy = {"witnessKeys": [...], "threshold": 1}; chain = [{"sth": ..}, {"sth": .., "proof": ..}, ...]
let ok = verify_tree_head(&sth, guardian_public, Some(&policy));
let verdict = verify_checkpoint_chain(&chain, guardian_public, Some(&policy));
```

`atlas_pca::optimistic` checks the wire form of the optimistic path: `claim_check` names the first failing check of a bonded claim, `settlement_wire_check` does the same for a guardian-signed settlement record, and `fraud_proof_wire_check` confirms a fraud proof is well-formed and consistent with its claim. Settlement is internal accounting only; no money moves. Deciding whether a fraud proof is true means re-running the policy engine and is done by the TypeScript settlement layer, not here. Only Ed25519 heads, cosignatures, claims and records are verified; any other suite is refused.

## Hardware attestation

The verifier checks hardware evidence itself: AMD SEV-SNP, Intel TDX (DCAP, with the Intel PCS collateral), Azure Attestation,
Google Confidential Space and NVIDIA GPU (device chain, SPDM transcript, signed reference manifests, CRLs and OCSP). Build one
from a configuration and run it over the evidence for one action:

```rust
use atlas_pca::attest::{verifier_from_config, Binding};
use serde_json::json;

let v = verifier_from_config(
    "amd-sev-snp",
    &json!({
        "family": "genoa",
        "binding": "report-data",
        "policy": { "measurements": ["<hex of the 48-byte launch measurement>"] },
    }),
)?; // a configuration that would accept anything (no allowlist, no trust anchor) is refused here
let expected = Binding { holder_pub: key, grant_ref: format!("passport:{id}"), epoch: 0.0, nonce };
let res = v.verify_evidence(Some(&evidence), now_ms, &expected);
// res.ok && res.bound == Some(true): the quote is genuine, bound to that holder, grant, epoch and nonce,
// and res.measured is the hardware-measured identity
```

The configuration and the evidence of each vendor are the language-neutral ones of the shared conformance vectors, and the
verifiers answer exactly what the TypeScript verifiers answer, reason text included. They fail closed: a missing allowlist,
trust anchor, issuer, collateral or binding is a denial, never a pass. They are classical (ECDSA, RSA), not post-quantum, and do
no network I/O: the evidence, the collateral (Intel PCS, NVIDIA reference manifests, CRLs, OCSP responses) and the trust anchors
are yours to supply. The Azure signing-key discovery and rotation store is not part of the crate: you configure the trust anchors.

To verify hardware-rooted passports with it, set `PassportOptions::default_verifier`; an `attest` verifier you supply still wins:

```rust
let verifier = verifier_from_config(vendor, &config)?.with_evidence(evidence); // the evidence reaches the verifier out of band
let o = PassportOptions { trusted_issuers: &issuers, now_ms, default_verifier: Some(&verifier), revoked: Some(&revoked), ..options };
```

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
- The hosted API defaults to `ed25519` plus the hybrids that include Ed25519, and refuses the pure post-quantum suites (`ml-dsa-*`, `slh-dsa-*`, `fn-dsa-*`, `less-cat1`) unless the operator lists them. To match it offline, pass `allowed_suites` exactly: `ed25519`, `hybrid-ed25519-ml-dsa-65`, `hybrid-nested-ed25519-ml-dsa-65`, `hybrid-ed25519-ml-dsa-87`, `hybrid-ed25519-slh-dsa-sha2-128f`, `hybrid-ed25519-slh-dsa-sha2-256s`, `hybrid-ed25519-less-cat1`. The effective hosted list is readable at `GET /v1/pca/suites`; see the [wire formats reference](https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/wire-formats.md).
