# PCA conformance suite

Golden vectors for the CORE PCActn verification: capability chain, Merkle plan
inclusion, Ed25519 leaf signature, counter. These vectors are vendored. Synced from Atlas-Authorization/pca (https://github.com/Atlas-Authorization/pca) - the canonical source. Do not edit here; re-sync from the hub.

## Files

- `keys.json` - fixed test keys: `{ principal|agent|subagent|rogue: { seed, public } }`, both base64url
  (no padding). `seed` = sha256("atlas-pca-conformance/<label>") is the Ed25519 private seed.
- `vectors.json` - `{ format, sig_domain, cap_domain, primitives, vectors }`.

### `vectors[]`

`{ name, description, grant, plan_nodes, pcactn, expect: { allow, checks: { chain, plan_inclusion, leaf_signature, counter } } }`

`grant` is the root capability, `plan_nodes` the committed plan (informational; the PCActn carries the
root + inclusion proof), `pcactn` the wire object. A verifier calls `verify(pcactn, grant)` and must
produce the same `allow` and the same pass/fail (true/false) for each of the four checks.

### `primitives`

- `canonical[]`: `{ value, expect, hash }` - canonical JSON string and `base64url(sha256(canonical))`.
- `merkle[]`: `{ leaves, root, proofs[] }` - roots and inclusion proofs per leaf.
- `params_digest_empty`: `hashCanonical({})`.

## Rules every implementation must match

- Canonical JSON: object keys sorted by UTF-16 code units, recursively; no whitespace; JS
  `JSON.stringify` string escaping (only `"` `\\` and control chars escaped, `\b\f\n\r\t` short forms,
  other controls `\u00xx` lowercase; non-ASCII emitted raw). Integers only in vectors.
- Hash = base64url, NO padding, of SHA-256.
- Merkle: leaf = H(0x00 || canon(leaf)); node = H(0x01 || L || R); split at the largest power of two < n.
  Proof step `{side, hash}`: side is where the SIBLING sits.
- Plan leaf: `{node_id, verb, resource, params_digest (default hash({})), reversibility_class
  (default "reversible"), conditions (default hash({pre:null,post:null}))}`.
- Signed message for the leaf signature: `"atlas-pca/actn/v1\0" || sha256(canonical(pcactn minus sig, threshold))`.
- Capability hop: `id = body_digest = hash({issuer, holder, caveats, parent|null})`, signature over
  `"atlas-pca/cap/v1\0" || raw(body_digest)` by the parent's holder (root: by the issuer); `parent` =
  hash of the full parent capability; child caveats must have the parent's caveats as an exact prefix;
  chain[0] must equal the grant and root issuer must equal grant.issuer.


> Synced from Atlas-Authorization/pca — the canonical source.
