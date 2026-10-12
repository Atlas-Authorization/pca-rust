# Changelog

## 0.4.1 - 2026-10-12

- Lockstep release with the PCA 0.4.1 security fix (root caveats enforced in the policy layer). No change in this crate.

## 0.4.0 - 2026-10-11 (BREAKING)

- **Breaking: proofs generated with 0.3.0 and earlier no longer verify.** The pinned proof options now use 37 FRI queries (was 32) at blow-up 8, so the conjectured security level is 110 bits (was 95, below the 100-bit floor): min(min(128, 3 * 37) - 1, 128). `MIN_SECURITY_BITS` is 100 (was 95), the verifier still pins the exact options, and proofs made with the old 32-query options are refused with `UnacceptableProofOptions`. Proven security rises to 54 bits (list decoding) and 30 bits (unique decoding). Cost: the sample proof grows from 43,135 to 48,894 bytes (+13 %); prove time 2.2 to 2.7 ms and verify time 0.4 to 0.8 ms on the sample witness (single timed run, release build). Fixtures regenerated. Regenerate any stored proof.

## 0.3.0

**0.2.0 is superseded; upgrade.**

- **Breaking: public-input layout changed and proofs from 0.2.0 do not verify.** Regenerate proofs; commitments must be exactly 64 hex digits (see the first fix below).

- Security: **the opaque `policy_commitment` / `action_commitment` bound only the first 128 bits.** Both are now required to be exactly 64 hex digits and are bound in full as four 64-bit limbs each (public inputs grow from 16 to 24 elements; committed proof fixtures regenerated). Malformed commitments are refused instead of truncated. New `hex256_limbs`, `PolicyParams::validate`/`try_to_public`.
- Fix: `verify_release` could panic on a proof whose header claims a different trace shape or invalid options, and `Proof::from_bytes` could panic or abort (huge allocation) on corrupted bytes. Added `proof_from_bytes` / `verify_release_bytes` (bounded, fail-closed decoding), exact proof-option and trace-shape checks, and panic-to-rejection handling.
- Tests: per-section mutation tests on the committed proof, per-field public-input tampering, and a cross-check against the TypeScript reference risk model.

## 0.2.0 (superseded by 0.3.0)

- Documentation cleanup; license is now MIT only (previously `MIT OR Apache-2.0`).
- Added crate metadata (repository, keywords, categories) and LICENSE.
- Lockstep version bump with `atlas-pca` 0.2.0; no API changes.

## 0.1.0

- Initial release.
