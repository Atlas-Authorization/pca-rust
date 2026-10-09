# Changelog

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
