# atlas-pca

> Maturity: **stable** (stable core). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Reference verifier for **Proof-Carrying Authority (PCA)**, an execution-authentication framework for
autonomous agents. The agent presents a self-contained proof-carrying action (PCActn) with every
request, and the resource server verifies it offline instead of trusting a bearer token.

> Status: **0.5.0, stable core verifier.** The shared conformance corpus is reproduced byte for byte; the middleware
> checks the proof only (see the security contract for what each surface enforces).

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

## Goal binding, revocation staleness, operation records, plans and assurance (0.5)

### Goal binding v3

`IntentPolicy::approved_goal` pins the root grant to the exact goal the principal signed and the policy compiled from it:

```rust
use atlas_pca::{intent_goal_commit_v3, ApprovedGoalRef, IntentPolicy};

let goal = ApprovedGoalRef { goal_digest, policy_digest }; // canonical base64url, 32 bytes each
let policy = IntentPolicy { approved_goal: Some(goal.clone()), ..Default::default() }; // implies `require`
// a wallet mints the grant with the commitment of the same goal:
let commit = intent_goal_commit_v3(&goal, &goal_salt);
```

Under `approved_goal` the grant must open against the v3 goal and only that: a v1 / v2 grant does not open it, a v3 grant
does not open under a different goal or policy digest, an absent `intent` or a grant without a goal commitment fails, and
the fidelity and risk floors still apply. A malformed digest (short, padded, empty, an extra member) is a misconfiguration
and fails closed.

### Revocation staleness

A guardian-signed revocation epoch carries its own validity window; staleness lets YOU cap how old the revocation state may be,
with a stricter window for actions that cannot be undone. Off unless configured.

```rust
use atlas_pca::{AuthorizeOptions, RevocationStaleness, RevocationStalenessPolicy, RevocationState};

let gate = RevocationStaleness::new(RevocationStalenessPolicy { max_revocation_age_ms: Some(300_000.0), ..Default::default() }, |_pcactn, _grant| {
    Ok(Some(RevocationState { epoch: Some(latest_signed_epoch()), ..Default::default() }))
})?
.with_guardian(guardian_public_key);
let options = AuthorizeOptions::new(store, is_revoked).with_revocation_staleness(gate); // or AuthorizeInput::revocation_staleness
```

The class is the stricter of your context's authoritative `reversibility_class` and the PCActn's signed class; a missing or
unknown class counts as irreversible. Setting any age option turns the cap on: any action 5 minutes by default, irreversible
2 minutes (`max_revocation_age_ms`, `staleness.irreversible` and `staleness.costly` override them). An irreversible action needs a signed epoch unless
`allow_unsigned_root_for_irreversible` is set; a bare root needs its issue time (`root_issued_at`), and an unknown age is denied.
The gate runs after your boolean `is_revoked` hook (which keeps working unchanged) and fails the same `revocation` check.

The gate also checks that no capability in the chain is revoked: after the freshness step, every capability id (default: each
`id` in the PCActn's `cap_chain`, override with `.with_ids(..)`) needs a valid non-membership proof against the epoch's root,
supplied by `.with_proofs(|pcactn, id| Some(proof))`. A missing proof denies (fail closed), so a gate without a proof source
denies every request that has a capability chain. `verify_non_membership(root, proof, id)` is public for custom use.

### Operation records: run it at most once

`authorize` consumes the replay counter; a crash, a client retry or two workers can still run the side effect twice.
`execute_authorized` closes that gap with one record per operation id:

```rust
use atlas_pca::{execute_authorized, ExecutableAuthorization, ExecuteOptions, MemoryOperationStore};

let store = MemoryOperationStore::new(); // KvOperationStore over SqliteAtomicKv (feature `sqlite`) is durable
let out = execute_authorized(
    &ExecutableAuthorization::from(&result),
    |h| call_downstream(&h.idempotency_key), // the operation id is the downstream idempotency key
    &ExecuteOptions { store: Some(&store), recheck: Some(&recheck), ..Default::default() },
);
```

The record goes `pending`, then `executing`, then `committed` or `failed`; a second execution of the same id is answered from the
record and never runs the function again. An irreversible operation (the stricter of the signed class and
`ExecuteOptions::reversibility_class`) needs a `recheck` that confirms revocation, expiry and approval immediately before it
runs; a refusal records `aborted`. An open record older than the timeout is settled by `recover_operations`: `pending` becomes
`aborted`, `executing` becomes `uncertain` (the effect may have happened: reconcile it by idempotency key and settle it with
`resolve_operation`). `Executor` combines `authorize` and `execute_authorized` and answers a replay-only denial from the record.
With the `axum` feature `GuardResult::execute` runs it for an allowed request and `operation_response` maps the outcome to a status.

### Plan lifecycle

`PlanRegistry` tracks a plan commitment: `draft`, `validate`, `commit`, `authorize` (the principal's approval, optionally until
`expires_at`) and `revoke`, each one atomic. The root is the Merkle root of the node leaves, computed from the nodes. A plan is
executable only when authorized, unexpired and its stored nodes still hash to the root; `check` adds the per-action rules (the
node exists, the operation matches what was approved). `AuthorizeInput::plans` feeds the registered plan into `authorize`; an
operation whose plan is not executable fails `plan_root_authorized` and `plan_state` with the plan's own reason.

### Assurance labels

Every `AuthorizeResult` carries `assurance`: per check, its outcome and what a pass rests on (the signature suites and their
`ed25519` / `hybrid` / `pq` level, the label of an attestation, proof or threshold hook). Labels come from YOUR configuration
(`AssuranceHooks`, `AssuranceLabelled`), never from the presented evidence; an unlabelled hook is `unknown` and satisfies nothing.
A PCActn that carries `bond_ref` reports `bond` as `unsupported` and is denied unless listed in `allow_unsupported`.

```rust
let req = AssuranceRequirement { signature_pq: true, attestation: Some("hardware".into()), ..Default::default() };
let result = authorize(Some(&pcactn), &AuthorizeInput { require_assurance: Some(&req), ..input });
```

A requirement that is not met fails the `assurance` check before any replay state is written. Weaker, missing, failed,
unlabelled, preview (FROST, DKG, MPC), degraded and unsupported evidence never meets a requirement.

### Step-up from the principal's device

`atlas_pca::stepup` lists, approves and denies PCA step-ups. `PrincipalDeviceKey` keeps the principal's Ed25519 key in a
`SecretStore` you provide (the key is a software key: gate approvals behind a user-presence check) and `StepUpClient` signs the
step-up's threshold message and posts it. You supply the HTTP stack through `StepUpTransport`; the crate adds no HTTP dependency.

### Testing your own store

`atlas_pca::store_conformance` runs the replay-state contract (`run_state_store_conformance`: claim burst, concurrent claims,
durability, crash after the claim) and the operation-record contract (`run_operation_store_conformance`: create once,
compare-and-set transitions, terminal states, durability, execute once across handles) against a factory of handles on your
backend. Put `report.assert_passed()` in your test suite.

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
