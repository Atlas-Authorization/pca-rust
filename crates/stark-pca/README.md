# stark-pca — a transparent STARK of the PCA release gate

Install: `cargo add stark-pca`

A **genuine, verifiable zk-STARK** of the core *release decision* of Proof-Carrying
Authority, built with the [Winterfell](https://github.com/facebook/winterfell) STARK
library (pure Rust).

- **Transparent** — no trusted setup, no toxic waste, no per-circuit ceremony.
- **Post-quantum** — security rests only on a collision-resistant hash (BLAKE3) and the
  random-oracle / FRI low-degree-test assumptions; there is no discrete-log or pairing
  assumption anywhere.
- **No verifying key** — a STARK has no circuit-specific setup artifact. The AIR in
  `src/lib.rs` plus the public parameters in `fixtures/params.json` are the *complete*
  verification artifact (this is the "vkey-equivalent").

Winterfell version: **0.13.1**. Status: **0.3.0, unaudited.**

---

## What the AIR proves (exactly)

Field: Winterfell's 128-bit prime field (`f128`). Hash: `Blake3_256`. Fixed-point scale
`S = 1_000_000` (parts-per-million), matching the `@atlasauth/pca` reference risk model and its Groth16
Policy-VM circuit.

**Public inputs** (bound into the Fiat–Shamir transcript, so a proof only verifies against
*these* values): the six risk weights `(α, β, γ, δ, ε, ζ)` at scale `S`; the tier-1
threshold `θ₁` at scale `S`; the integer cost scale `κ`; the budget ceiling `bMax` at
scale `S`; the scale `S`; two opaque 256-bit commitments `policy_commitment`, `action_commitment`
(each exactly 64 hex digits, split into `HEX_LIMBS = 4` big-endian 64-bit field elements, so all
256 bits are bound); and the `COMMIT_LIMBS = 4` limbs of `witness_commitment` — the resource server's algebraic
commitment to the quantized action, which the AIR **constrains** (unlike the two opaque
commitments, which it only transcript-binds). See the binding section below.

**Private witnesses**: the six risk-magnitude inputs
`(d, rev, bl, taint, conf, age)` ∈ `[0, S]`; the trust budget `B` at scale `S`; a
predicate-match bit `pm`; and a caveats-satisfied bit `co`.

The prover demonstrates, with real in-AIR algebraic constraints, knowledge of a witness
such that:

1. **Fixed-point risk functional** (the integer image of `riskScore` in the reference model,
   scale `S²`):

   ```
   r_raw = α·d + β·(S − rev) + γ·bl + δ·taint + ε·(S − conf) + ζ·age
   r      = r_raw / S²        (so r ∈ [0,1] is the real-valued risk)
   ```

   `rev` and `conf` enter as `(S − x)` exactly as `(1 − reversibility)` and
   `(1 − confidence)` do in the reference model.

2. **Input validity**: each `x ∈ {d, rev, bl, taint, conf, age}` is proven to lie in
   `[0, S]` (i.e. a well-formed `[0,1]` fixed-point magnitude), via two bit-decomposition
   range gadgets per input (`x ≥ 0` and `S − x ≥ 0`). The budget `B` is proven to lie in
   `[0, bMax·S]`.

3. **The release gate**:

   ```
   allow = (tier == 1) ∧ (B ≥ κ·r) ∧ pm ∧ co        and        allow == 1
   ```

   - `tier == 1 ⟺ r ≤ θ₁` — the auto-admit band of `requiredThreshold()`. Enforced in-AIR
     as the range gadget `θ₁·S² − r_raw ≥ 0`.
   - `B ≥ κ·r` — the budget-admission cost gate of `admit()` / `cost()`. Enforced in-AIR
     as the range gadget `B·S − κ·r_raw ≥ 0` (exact rational comparison; no truncation).
   - `pm`, `co` are proven boolean (`b² = b`).
   - `allow` is **derived** in-trace as the product `tgate · bgate · pm · co` and
     **asserted `== 1`**. The two inequality bits `tgate`, `bgate` are proven consistent
     with the range gadgets above, so a deny witness — `r > θ₁`, `B < κ·r`, `pm = 0`, or
     `co = 0` — makes the constraint system **unsatisfiable**. You cannot forge an `allow`.

4. **Witness ↔ commitment binding**: a native in-AIR algebraic hash (a 10-lane cube-S-box
   SPN, one round per trace row) absorbs the nine quantized witness quantities and the first
   four squeezed state lanes are **asserted equal to the public `witness_commitment`**. The
   same witness columns drive both the gate and the hash, so you cannot prove the gate for a
   witness that does not match the committed (quantized) action. See the honest fidelity-gap
   note below for exactly what this binds (the quantized struct) vs. the SHA-256 canonical
   JSON `action_commitment` (not recomputed in-AIR).

The inequalities are enforced with genuine **bit-decomposition range gadgets**: a value
`V` is proven `0 ≤ V < 2⁶³` by exhibiting its 63 bits (each constrained boolean) summed by
a per-step running residual that must reach exactly `0`. A "negative" (deny) difference
wraps to a field element `≥ 2⁶³`, which has no valid 63-bit decomposition — so the residual
cannot reach `0` and no proof exists. This soundness relies on the field order lying in
`(2⁶³, 2¹²⁸)`, which holds for `f128`.

### Conformance tests (`tests/integration.rs`)

1. `compliant_witness_proves_and_verifies` — a compliant witness (`r = 0.065 ≤ θ₁ = 0.25`,
   `B = 1.0 ≥ κ·r`, `pm = co = 1`) proves and verifies **OK**.
2. `non_compliant_risk_cannot_prove_allow` — `r > θ₁` and `B < κ·r`: no verifying `allow`
   proof can be produced.
3. `non_compliant_predicate_cannot_prove_allow` — `pm = 0`: no verifying `allow` proof.
4. `tampered_proof_is_rejected` — a bit-flipped proof fails verification.
5. `tampered_public_input_is_rejected` — a proof does not verify under a different
   `action_commitment` (transcript binding).
6. `tampered_policy_weight_is_rejected` — a proof does not verify under a different weight.
7. `committed_fixture_proof_verifies` — the committed `fixtures/sample_proof.bin` verifies.

### Validation status (mutation and cross-checks, `tests/mutation.rs`)

- **Mutation tests on the committed proof.** Byte flips in every serialized section (context,
  query count, commitments, trace queries, constraint queries, out-of-domain frame, FRI proof,
  proof-of-work nonce), truncation and trailing bytes are all rejected. Rejection reasons are
  recorded per section (decode failure, out-of-domain inconsistency, trace/constraint opening
  mismatch, FRI failure, unacceptable options).
- **Public-input tampering.** Changing any one of the public values (each weight, scale, threshold,
  cost scale, budget ceiling, both opaque commitments, each witness-commitment limb) makes the
  committed proof fail with an out-of-domain constraint inconsistency.
- **Cross-check against the TypeScript reference.** The default policy, the fixed-point risk
  value, the tier-1 decision and the allow/deny outcome for ten witnesses (including budget just
  below and just above cost, predicate and caveat failures) match the output of the TypeScript
  reference risk model (`riskScore`, `admit`) recorded in `fixtures/ts_reference.json`. That file
  is produced by `tests/gen_ts_reference.mjs`; it is reference-implementation output, not an
  official standard vector (none exists for this statement).
- **Hardened proof decoding.** Use `proof_from_bytes` / `verify_release_bytes` for proof bytes
  that arrive from the network. The stock Winterfell decoder can panic or abort the process on
  hostile input (a corrupted header trips an internal assertion; a corrupted length prefix
  requests a huge allocation). The decoder here bounds every length prefix, converts any panic
  into an error and rejects trailing bytes. `verify_release` also pins the exact proof options
  and trace shape, and reports a residual panic as a rejection.
- **Opaque commitments bind all 256 bits.** `policy_commitment` and `action_commitment` must be
  exactly 64 hex digits (anything else is refused, never truncated). Each is split into four
  big-endian 64-bit limbs (always `< p` in `f128`, so the split is injective) and appended to
  the public inputs. Public-input layout (field elements, in transcript order): 6 weights, `S`,
  `θ₁·S²`, `κ`, `bMax`, 4 policy-commitment limbs, 4 action-commitment limbs, 4
  `witness_commitment` limbs (24 elements; it was 16). Collision / second-preimage strength of the
  bound commitment is therefore that of SHA-256 (the two commitments are transcript-bound, not
  constrained in-AIR). Tests flip the last hex digit of every limb and assert rejection, and a
  regression test shows commitments differing only in the final digit are distinct statements.
  Fixtures are regenerated with `cargo run --release --bin gen_fixtures` (and
  `node tests/gen_ts_reference.mjs` from the repo root for the TS limb-split vectors).
- **Still not validated.** There is no external or official test-vector suite for this AIR, the
  construction has not been reviewed by a third party, and the in-AIR algebraic hash is a custom
  design (not a standardized hash). The package remains experimental and unaudited.

---

## Honest fidelity gaps vs the Groth16 Policy-VM circuit

This STARK is scoped to the **release gate + the fixed-point risk functional**. It is
**NOT** at parity with the full Groth16 Policy-VM circuit. The precise gaps:

- **The witness IS now bound in-AIR — to the quantized preimage, via a native algebraic
  hash (not SHA-256).** The AIR runs a genuine in-AIR algebraic hash and **asserts the
  private witness hashes to a public commitment**, so a proof can no longer be produced for
  a witness that does not match the committed action. Precisely:
  - A `NUM_LANES = 10`-wide **cube-S-box SPN** (`aₖ = (Hₖ + 2^row + RCₖ)³`, diffusion
    `H'ⱼ = Σₖ aₖ + aⱼ`, one round per trace row, per-row constant `2^row`, per-lane
    constants `RCₖ`) absorbs the **nine quantized witness quantities**
    `(d, rev, bl, taint, conf, age, B, pm, co)` on row 0 (lanes 0..8) + a capacity IV
    (lane 9).
  - The first `COMMIT_LIMBS = 4` state lanes at the final row are **asserted equal to a new
    public input `witness_commitment`** (the four field-element limbs the resource server
    publishes). The same witness columns feed both the risk gate and the hash, so the proof
    exists *only* for a witness whose quantized form hashes to the committed value. This is
    the `compute_witness_commitment` function; on `f128`, `gcd(3, p−1)=1`, so the cube S-box
    is a field permutation.
  - **What it binds, honestly:** this binds the **quantized witness struct** (the integer
    risk/budget/boolean preimage, at scale `S`) to the committed action — it is **NOT** an
    in-AIR recomputation of the SHA-256-of-canonical-JSON `action_commitment` (full
    variable-length canonical-JSON SHA-256 in-field remains infeasible without a dedicated
    SHA-256 AIR and a large blow-up — that is what the RISC Zero zkVM guest does with
    the accelerated sha256 precompile). The algebraic `witness_commitment` and the opaque
    SHA-256 `action_commitment` are linked **off-circuit** by the resource server deriving
    both from one action. Collision resistance of the binding rests on the algebraic-hash
    (MiMC/Poseidon-family, algebraic-degree) heuristic; a SHA-256-identical binding, and a
    larger round count / `x⁷` S-box on small fields, are documented follow-ups.

- **Predicates and caveats are reduced to booleans.** The circuit encodes a
  `(verb, resource)` allow-list entry with a numeric `where` bound, and the six
  conjunctive caveats. Here, predicate-match and caveats-satisfied are single boolean
  witness bits (`pm`, `co`) — the policy-matching logic that *produces* those bits is not
  re-derived in-AIR.

- **Only the t=1 tier band is encoded.** `requiredThreshold` has a three-tier ladder
  (t=1/t=2/t=3) and an optimistic-acceptance rule. This AIR proves exactly the
  machine-auto-admit gate `tier == 1 ⟺ r ≤ θ₁`; `θ₂` and the t=2/t=3 bands are not encoded.

- **No attenuation / delegation chain.** The circuit encodes the capability-chain
  narrowing (`budget_alloc` monotonicity, depth bound). This AIR does not.

- **`κ` restricted to a non-negative integer.** The reference model allows a real-valued `kappa`.
  Here `κ` is an integer multiplier (default `1`). The budget comparison is done by
  up-scaling (`B·S ≥ κ·r_raw`), so it is an **exact** rational comparison with no
  truncation error — but fractional `κ` is out of scope.

- **The clamp-at-1 is a no-op on the allow domain.** `riskScore` clamps `r` into `[0,1]`.
  Because the gate requires `r ≤ θ₁ < 1`, the clamp never binds on any satisfiable
  `allow` input, so it is omitted; `r_raw` is compared directly (`r_raw ≤ θ₁·S²`).

- **Witness-data-dependent constraint degrees.** Winterfell's *debug-only*
  `validate_transition_degrees` aid requires exact declared-vs-measured degree equality,
  which a data-dependent AIR (e.g. a zero-valued input collapsing a range-check to degree
  0) cannot satisfy for all witnesses. Our declared degrees are correct **upper** bounds
  (never under-declared → always sound); that dev-only assertion is disabled in the test
  profile (see `Cargo.toml`). Proofs are generated and verified normally.

What this STARK *does* give you that Groth16 does not: a **transparent, post-quantum,
setup-free** proof of the release decision and the fixed-point risk functional.

---

## Build, test, and regenerate fixtures

```bash
cargo test --release                    # 15 tests: conformance, mutation, cross-check
cargo run --release --bin gen_fixtures  # regenerate fixtures/
```

Sample timings on a 4-vCPU machine: **prove ≈ 3.5 ms**, **verify ≈ 0.4 ms**, proof size
**37,824 bytes** (~37 KB).

## Fixtures (committed)

- `fixtures/sample_proof.bin` — a sample `allow` STARK proof (binary, ~37 KB).
- `fixtures/public_inputs.json` — the public inputs (policy) for that proof.
- `fixtures/params.json` — the STARK/verification parameters (the "vkey-equivalent").


