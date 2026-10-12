# Changelog

## 0.4.1 - 2026-10-12

- Lockstep release with the PCA 0.4.1 security fix (root caveats enforced in the policy layer). No change in this crate.

## 0.4.0 - 2026-10-11 (BREAKING)

- R3-15 fix (BREAKING API): `verify_compressed(proof, vk, num_steps)` and `verify_recursive(pp, rec, num_steps)` no longer take `z0`; they verify against the pinned `initial_state()` `[0, 0]`. A start state taken from a prover or a public-IO file was accepted as-is, so a field-negative `z0 = [0, -X]` hid `X` of early spend while the chain digest still matched the honest ledger. New `verify_compressed_claimed` / `verify_recursive_claimed` / `check_claimed_z0` compare a claimed start with the pinned one and refuse anything else; new `initial_state_commitment()`; `public_io.json` gains `z0_commitment`. Tests: `tests/z0_pinning.rs`.

- RT-05 fix (breaking: chain digests change): each step now folds the leaf `H(action_digest, cost)` into the chain, so the final digest commits to the (action, cost) sequence and a relabelled-cost history can no longer present the honest digest. New `action_leaf_native`; `native_final_state` updated. Tests: `tests/cost_binding.rs` (failing before the fix), soundness and ablation tests updated (593 constraints). Fixtures regenerated.

- Soundness audit tests: R1CS-level constraint mutation of the step circuit against the native replay, no-free-wires check, Nova-level malicious witnesses, security-level arithmetic, decoder fuzzing. Added `ActionCircuit::from_field_witness` so adversarial witnesses can be presented. Untracked the Python bytecode.

- Validation: chain hash cross-checked against an independent Python Poseidon reference that reproduces the published IAIK hadeshash vectors; 1000-step fold verified (346 s fold, 10624-byte compressed proof). New `longfold` binary and `tools/poseidon_reference.py`. No API changes.

## 0.3.0

Lockstep release. 0.2.0 is superseded by the extra tests below; there are no API or behaviour changes.


- Tests: committed-proof verification, tampered/wrong public IO, over-budget and out-of-range rejection with asserted reasons, byte-flip and splice rejection. No API changes.

## 0.2.0 (superseded by 0.3.0)

- Documentation cleanup; license is now MIT only (previously `MIT OR Apache-2.0`).
- Added crate metadata (repository, keywords, categories) and LICENSE.
- Lockstep version bump with `atlas-pca` 0.2.0; no API changes.

## 0.1.0

- Initial release.
