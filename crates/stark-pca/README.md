# stark-pca — a transparent STARK of the PCA release gate

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

This crate was developed and verified end-to-end on a fresh Azure VM (Ubuntu 24.04,
`Standard_D4s_v4`, 4 vCPU, region `westus3`). Winterfell version: **0.13.1**.

---

## What the AIR proves (exactly)

Field: Winterfell's 128-bit prime field (`f128`). Hash: `Blake3_256`. Fixed-point scale
`S = 1_000_000` (parts-per-million), matching `packages/pca/src/risk.ts` and the Groth16
Policy-VM circuit in `packages/pca/src/zk.ts`.

**Public inputs** (bound into the Fiat–Shamir transcript, so a proof only verifies against
*these* values): the six risk weights `(α, β, γ, δ, ε, ζ)` at scale `S`; the tier-1
threshold `θ₁` at scale `S`; the integer cost scale `κ`; the budget ceiling `bMax` at
scale `S`; the scale `S`; and two opaque commitments `policy_commitment`,
`action_commitment`.

**Private witnesses**: the six risk-magnitude inputs
`(d, rev, bl, taint, conf, age)` ∈ `[0, S]`; the trust budget `B` at scale `S`; a
predicate-match bit `pm`; and a caveats-satisfied bit `co`.

The prover demonstrates, with real in-AIR algebraic constraints, knowledge of a witness
such that:

1. **Fixed-point risk functional** (the integer image of `riskScore` in `risk.ts`,
   scale `S²`):

   ```
   r_raw = α·d + β·(S − rev) + γ·bl + δ·taint + ε·(S − conf) + ζ·age
   r      = r_raw / S²        (so r ∈ [0,1] is the real-valued risk)
   ```

   `rev` and `conf` enter as `(S − x)` exactly as `(1 − reversibility)` and
   `(1 − confidence)` do in `risk.ts`.

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

---

## Honest fidelity gaps vs the Groth16 Policy-VM circuit (`zk.ts`)

This STARK is scoped to the **release gate + the fixed-point risk functional**. It is
**NOT** at parity with the full Groth16 Policy-VM circuit. The precise gaps:

- **No in-AIR SHA-256 / struct commitments.** The Groth16 circuit computes the
  action/policy/plan commitments with SHA-256 *in-circuit* over a fixed-layout quantized
  struct, binding the private witness to the public commitment. This STARK does **not**
  hash in-AIR. `policy_commitment` / `action_commitment` are carried in the public inputs
  (so the proof is *bound* to them via Fiat–Shamir and cannot be replayed under different
  commitments), but the AIR does **not prove that the private risk inputs are the
  pre-images of those commitments**. Consequently this is a proof of *knowledge of some
  valid fixed-point witness that passes the gate*, not a proof that *the specific committed
  action* passes. Closing this gap requires an in-AIR hash (e.g. Rescue/Poseidon or a
  SHA-256 AIR) binding the inputs to `action_commitment`.

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

- **`κ` restricted to a non-negative integer.** `risk.ts` allows a real-valued `kappa`.
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
cargo test                              # debug; all 7 conformance tests
cargo test --release                    # faster
cargo run --release --bin gen_fixtures  # regenerate fixtures/
```

Sample timings on the build VM (`Standard_D4s_v4`, 4 vCPU): **prove ≈ 3.5 ms**,
**verify ≈ 0.4 ms**, proof size **37,824 bytes** (~37 KB).

## Fixtures (committed)

- `fixtures/sample_proof.bin` — a sample `allow` STARK proof (binary, ~37 KB).
- `fixtures/public_inputs.json` — the public inputs (policy) for that proof.
- `fixtures/params.json` — the STARK/verification parameters (the "vkey-equivalent").

Large proving/LDE artifacts (`target/`) are git-ignored and regenerable.
