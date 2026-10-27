# pca-folding-ivc

> Status: **0.4.3, unaudited.** Install: `cargo add pca-folding-ivc`

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
   `chain_digest₍ᵢ₊₁₎ = H(chain_digestᵢ, H(action_digestᵢ, costᵢ))`,
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
- **The start state is pinned (R3-15).** The step circuit only constrains `budget_spent' in [0, B_MAX]`, so a
  prover that starts from a field-negative `z0 = [0, -X]` could fold a history whose real total exceeds `B_MAX`
  by `X` and still verify under *that* z0. `verify_compressed(proof, vk, num_steps)` and
  `verify_recursive(pp, rec, num_steps)` therefore take no `z0`: they always verify against `initial_state()`
  `= [0, 0]`. A start claimed by a prover or read from `public_io.json` can only be *compared*
  (`verify_compressed_claimed`, `check_claimed_z0`); it is never used to verify. `public_io.json` records
  `z0_commitment = H(z0[0], z0[1])`. Test: `tests/z0_pinning.rs` (ports the red-team attack).
- Nova over Pallas/Vesta with IPA is **transparent but not post-quantum**. "PQ-friendly" here means that folding reduces the whole history to a *single* relaxed-R1CS instance
  that a PQ final SNARK (e.g. a STARK) could compress instead;
  wiring that PQ wrap is future work and is not claimed here.

## Validation status

`cargo test --release` runs 16 tests:

- **Committed proof.** The committed `compressed_proof.bin` verifies against the public IO in
  `public_io.json` (final chain digest and spent budget equal an independent native replay of the
  eight actions). The verifier key is re-derived from the circuit shape, not read from a file.
- **Rejections, with reasons.** Wrong step count (including zero), wrong initial state, wrong arity,
  an over-budget history, an out-of-range cost, byte flips across the whole proof, truncation and a
  spliced proof are all rejected. Over-budget and out-of-range cost fail at proving with
  "Relaxed R1CS is unsatisfiable"; step-count and initial-state changes fail verification with
  "Invalid output hash in R1CS instances"; wrong arity with "Invalid input or output arity".
- **Chain digest.** Reordering or dropping an action changes the digest.
- **Independent Poseidon cross-check.** `tests/poseidon_crosscheck.rs` compares the chain hash with
  32 outputs (edge values 0, 1, p-1 and seeded random pairs) from an independent, unoptimised
  Python HADES implementation (`tools/poseidon_reference.py`, standard library only). That
  reference first reproduces the published IAIK hadeshash test vectors `poseidonperm_x5_255_3` and
  `poseidonperm_x5_254_3` (source URL, retrieval date and SHA-256 are in
  `fixtures/poseidon_crosscheck.json`) before it is used. The match covers the permutation, the Grain
  round constants, the round numbers (8 full, 55 partial), the Cauchy MDS matrix and the sponge
  domain tag. The parameter choices themselves (Cauchy MDS with x_i = i, y_i = t + i; the +2 full /
  x1.075 partial round margin; Grain S-box field bits set to 1) are this instance's own, so there
  is no published test vector for the exact instance; the published vectors validate the reference,
  not the instance parameters.
- **Cost binding (RT-05).** The metered cost is absorbed into the chain through the leaf
  `H(action_digest, cost)`, so the final `chain_digest` commits to the exact ordered (action, cost)
  sequence. A prover cannot relabel a history with cheaper costs and keep the honest digest: the
  verifier recomputes the expected digest with `native_final_state` from the ledger's (action, cost)
  records and compares it with the proved `final_state[0]`. The `Σcost <= B_MAX` guarantee therefore
  holds for the costs the verifier's ledger records, not for self-reported ones. A verifier that
  accepts any `chain_digest` from the prover without recomputing it from the ledger gets no such
  guarantee. (Costs themselves must still come from a trusted meter; the proof does not price actions.)
- **Long history.** `cargo run --release --bin longfold -- 1000` folds 1000 actions (cost 1000 each,
  cumulative cost exactly `B_MAX`), checks the folded output against the native replay, compresses
  and verifies the proof, and confirms a wrong step count is rejected. On an Apple-silicon Mac:
  fold plus recursive verification 90.4 s, compression setup 0.24 s, compression proving 2.75 s,
  compressed verification 45.6 ms, compressed proof 10624 bytes (the same size as the 8-step proof).
  These are the values recorded in the result file, measured after the RT-05 fix; an earlier version of
  this paragraph quoted 346 s / 4.1 s / 0.11 s from a run before the fix.
  Result: `fixtures/longfold_1000.json`.
  The same run on a 40-vCPU AMD EPYC Azure VM (CPU only) gives the identical final chain digest
  (`0x176d49be...e6e9`), fold plus recursive verification 49 s, compression proving 0.49 s, 168 MB peak
  RSS (`fixtures/longfold_1000_azure_vm.json`); 4000 steps (cost 250 each): fold 197 s, 178 MB peak RSS,
  compressed proof still 10624 bytes (`fixtures/longfold_4000_azure_vm.json`).
  The two `*_azure_vm.json` files were measured before RT-05 (chain digest without the cost leaf, one
  Poseidon fewer per step); their digests are superseded and only the timings remain indicative.
  `fixtures/longfold_1000.json` is regenerated for the cost-bound circuit.
- **Constraint audit.** `tests/soundness_r1cs.rs` runs the real step circuit against a recording constraint
  system. Honest and malicious single-step witnesses (2082 cases, including field-negative costs that no
  `u64` can express) are accepted or rejected exactly as the native replay says, with the same constraint
  shape for every witness. Every auxiliary wire is pinned (10817 single-wire edits each violate a
  constraint). Dropping each of the 355 constraints in turn ("mutants") is detected for 314 of them by an
  assignment that violates the intended relation yet satisfies all other constraints; the 41 that survive are
  the range gadget on the running total, which is redundant (the incoming total is at most `B_MAX` and the
  cost is below 2^32, so the new total is below 2^33; the headroom gadget bounds it again) and is shown
  equivalent when removed as a whole on 3000 witnesses. At the Nova level, field-negative and out-of-range
  costs and a one-over-the-ceiling total fail to fold. The interior of the vendored Poseidon gadget is covered
  by the same mutation run (all 238 constraints are necessary) plus the independent cross-check above.
- **Security level.** `tests/security_bits.rs` asserts the arithmetic: about 2^126.8 for the discrete log on the
  curve cycle and Poseidon round numbers above the paper's bounds for 128 bits; classical adversary,
  random-oracle model, not post-quantum.
- **Decoder fuzzing.** `tests/fuzz_decoder.rs` mutates the committed proof under an allocation watchdog and a
  child-process pass with hostile length prefixes: no panic escapes decode-and-verify, no mutant verifies,
  no hostile length makes the process abort.
- **Not validated.** There is no official test-vector suite for this circuit, and the construction
  has not been reviewed by a third party. The package remains unaudited and the folding scheme is
  not post-quantum.
