# pca-folding-ivc

> Status: **0.3.0, unaudited.** Install: `cargo add pca-folding-ivc`

**One succinct proof of an agent's entire PCA action history — via a folding scheme (Nova), not naive recursion.**

This crate implements recursive action-proof aggregation for Proof-Carrying Authority (PCA) the
modern way. Instead of proving a SNARK-of-a-SNARK-of-a-SNARK… (naive recursion, where the verifier
circuit grows and every level re-proves the one below), it uses **Incrementally Verifiable
Computation (IVC)** built on **Microsoft Nova's folding scheme** (`nova-snark`, pinned
`=0.76.0`). `N` per-action steps are *folded* into a single `RecursiveSNARK`, then compressed
once into a succinct `CompressedSNARK`.

## What the one proof attests

The IVC running state is `z = [chain_digest, budget_spent]` (arity 2), starting at `z₀ = [0, 0]`.
Each step `i` consumes a per-action witness `(action_digestᵢ, costᵢ)` and enforces **in-circuit**:

1. **Unforgeable action history (hash chain).**
   `chain_digest₍ᵢ₊₁₎ = H(chain_digestᵢ, action_digestᵢ)`,
   where `H` is a **Poseidon** 2-to-1 hash (arity 2, `Strength::Standard`, 128-bit) over the
   circuit's native field. The final `chain_digest` is a collision-resistant commitment to the
   *exact ordered sequence* of actions — nothing can be inserted, dropped, or reordered without
   finding a Poseidon collision.

2. **Cumulative-risk bound `Σcostᵢ ≤ bMax`.**
   `budget_spent₍ᵢ₊₁₎ = budget_spentᵢ + costᵢ`, plus an in-circuit bit-decomposition range check
   that `budget_spent₍ᵢ₊₁₎ ≤ B_MAX`. Because folding carries `budget_spent` across every step,
   this is a **whole-history** invariant: a step whose running total exceeds `B_MAX` is
   **unsatisfiable**, so the aggregate proof cannot be produced.

The compressed proof verifies against just the public IO (`z₀`, the final
`[chain_digest, budget_spent]`, and the step count) — a verifier learns the history is
well-formed and within budget **without** replaying any action.

## Folding vs. naive recursion — the win

| | Naive recursion (SNARK-of-SNARK) | Folding (Nova / this crate) |
|---|---|---|
| Per-step prover work | grows (must verify prior proof in-circuit) | **constant** (fold = a few group ops) |
| In-circuit verifier | a full SNARK verifier each level | **none** until the final compression |
| Recursive-proof size | depends on depth | **independent of `N`** |
| Final artifact | a deep proof | **one** `CompressedSNARK` of the whole history |

Folding defers all "SNARK verification" to a *single* step at the very end: the whole history
collapses to one relaxed-R1CS instance, which Spartan compresses once.

## Run it

```
cargo run --release --bin demo
```

The demo folds a sample **8-action** history, verifies the `RecursiveSNARK`, compresses it to a
`CompressedSNARK` and verifies that, prints the curve cycle / proof size / timings, then shows an
**over-budget** history correctly **failing to prove** (`Σcost > bMax` is unprovable). It writes
fixtures to `fixtures/`:

- `compressed_proof.bin` — the single succinct proof (bincode)
- `verifier_key.bin` — the compressed-SNARK verifier key (bincode)
- `public_io.json` — `z₀`, final `[chain_digest, budget_spent]`, `bMax`, step count, actions
- `params.json` — scheme / curve / sizes / timings metadata

## Construction

- **Folding / IVC:** `nova-snark 0.76.0`, `StepCircuit` over the **Pallas/Vesta** cycle of curves.
- **PCS:** IPA (`ipa_pc::EvaluationEngine`) — **transparent**, no trusted setup.
- **Final compression:** Spartan `RelaxedR1CSSNARK`.
- **Gadgets:** bellpepper (vendored as `nova_snark::frontend`) — `AllocatedNum`, `AllocatedBit`,
  linear constraints. No folding is hand-rolled.
- **Chain hash:** **Poseidon** via the vetted `neptune` sponge that `nova-snark` vendors at
  `nova_snark::frontend::gadgets::poseidon` (the same code Nova uses for its own folding random
  oracle) — arity 2, `Strength::Standard`. No hash is hand-rolled.

## Honest scope

- The chain hash `H` is a **production, collision-resistant Poseidon** over the circuit's native
  field — the vetted `neptune` implementation vendored inside `nova-snark`
  (`nova_snark::frontend::gadgets::poseidon`), instantiated through the sponge API at arity 2 and
  `Strength::Standard` (Poseidon-paper round numbers for width `t = 3`, quintic S-box, 128-bit
  security over GF(p)). The in-circuit and native hashes share identical, deterministically-derived
  constants, so the folded IVC output matches the native replay. This is no longer a didactic
  placeholder.
- Nova over Pallas/Vesta with IPA is **transparent but not post-quantum**. "PQ-friendly" here means that folding reduces the whole history to a *single* relaxed-R1CS instance
  that a PQ final SNARK (e.g. a STARK) could compress instead;
  wiring that PQ wrap is future work and is not claimed here.

## Validation status

`cargo test --release` runs 13 tests:

- **Committed proof.** The committed `compressed_proof.bin` verifies against the public IO in
  `public_io.json` (final chain digest and spent budget equal an independent native replay of the
  eight actions). The verifier key is re-derived from the circuit shape, not read from a file.
- **Rejections, with reasons.** Wrong step count (including zero), wrong initial state, wrong arity,
  an over-budget history, an out-of-range cost, byte flips across the whole proof, truncation and a
  spliced proof are all rejected. Over-budget and out-of-range cost fail at proving with
  "Relaxed R1CS is unsatisfiable"; step-count and initial-state changes fail verification with
  "Invalid output hash in R1CS instances"; wrong arity with "Invalid input or output arity".
- **Chain digest.** Reordering or dropping an action changes the digest.
- **Not validated.** There is no official test-vector suite for this circuit, the Poseidon
  instance is checked only against the in-circuit/native agreement of the same library (not
  against an independent Poseidon implementation), and the construction has not been reviewed by
  a third party. The package remains unaudited and the folding scheme is not post-quantum.
