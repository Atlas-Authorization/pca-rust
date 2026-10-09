# Changelog

## 0.3.0

- Lockstep release with the `@atlasauth/pca*` family. No change to the verifier API or behaviour in this package. Aligns with the 0.3.0 conformance corpus and the fixed reference implementations; adapters now require `atlas-pca>=0.3.0,<0.4`. Upgrade together with the rest of the family.

## 0.2.0 (superseded by 0.3.0)

- New normative check `grant_ref_bound`: the signed `grant_ref` must equal `cap_chain[0].id` (behaviour change).
- Aligned with the 172-vector shared conformance corpus (strings ordered by UTF-8 bytes wherever they feed a hash or commitment).
- Added crate metadata (repository, keywords, categories), README and LICENSE.

## 0.1.0

- Initial release.
