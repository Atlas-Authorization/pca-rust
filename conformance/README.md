# PCA conformance suite (wire format v2)

Golden + adversarial vectors for CORE PCActn verification (strict wire form, freshness binding, capability
chain, Merkle plan inclusion, Ed25519 leaf signature, counter) PLUS the full post-quantum crypto-agility
coverage and the v2.1 agent-leaf share binding. Regenerate (deterministic) with the TWO-STAGE pipeline — the
base generator writes the ed25519 core corpus, then the PQ generator APPENDS all post-quantum coverage:

    pnpm --filter @atlasauth/pca build \
      && node packages/pca/scripts/gen-conformance.mjs \
      && node packages/pca/scripts/gen-conformance-pq.mjs

Each generator asserts every vector's / primitive's stated intent against the TypeScript reference before it
is written (`verifyPCActnCore` for PCActns; `verifyThreshold` / `verifyWithSuite` for the threshold + artifact
primitives); `packages/pca/src/conformance.test.ts` then re-runs the reference over the whole written file.
The language verifiers (`sdks/*-pca`) must reproduce `allow` and every listed check for EVERY vector.

### Post-quantum + v2.1 coverage (`gen-conformance-pq.mjs`)

- LEAF verification under ALL 10 registered suites (`requires: "pq"`): `ed25519`; the lattice `ml-dsa-65` /
  `ml-dsa-87` and their `hybrid-ed25519-*`; the SUF-CMA `hybrid-nested-ed25519-ml-dsa-65`; the hash-based
  `slh-dsa-sha2-128f` / `slh-dsa-sha2-256s` and their hybrids. Per suite: a positive + a corrupt-primary-sig
  negative; per HYBRID also a corrupt-`pq_sig` and a missing-`pq_sig` (wire) negative; plus the global
  `pq-leaf-unknown-alg`, `pq-leaf-ed25519-stray-pqpk` and `pq-leaf-pure-mldsa65-stray-pqsig` wire negatives.
- NON-LEAF verification (`requires: "pq-nonleaf"`): a capability-chain delegation hop signed under each of the
  9 non-ed25519 suites — positive + corrupt per suite, + a downgrade (strip `alg`/`pq_pk`/`pq_sig`) negative
  per hybrid (the suite fields are bound into the signed hop `body_digest`).
- `agent_leaf_binding: "2.1"` marks the clean-break agent-leaf share binding (see `primitives.threshold_share`).

## Files

- `keys.json` - fixed keys `{ principal|agent|subagent|rogue: { seed, public } }` (base64url, no padding);
  `seed = sha256("atlas-pca-conformance/<label>")`. Extra chain keys are `sha256("atlas-pca-conformance/hop<i>")`.
- `vectors.json` - `{ format: 2, ver: 2, sig_domain, cap_domain, share_domain, check_order, limits, primitives, vectors }`.

### `vectors[]`

`{ name, class: positive|negative, description, grant, plan_nodes, context: { now, aud }, pcactn | pcactn_json, expect: { allow, checks } }`

- `pcactn` is the already-parsed object; `pcactn_json` is RAW TEXT that MUST first go through the strict JSON
  profile below (a parse failure == `wire` failure; the verdict is `{allow:false, checks:{wire:false}}`).
- A verifier runs `verify(pcactn, grant, now = context.now, audience = context.aud)`.
- `expect.checks` are booleans. If `wire` is false it is the ONLY entry (a wire failure is terminal: nothing else
  is evaluated). Otherwise all of `wire, version, audience, validity, chain, plan_inclusion, leaf_signature,
  counter` are present. `allow` = every check true.
- Normative check order (`check_order`): wire, version, audience, validity, chain, plan_inclusion, leaf_signature, counter.

### `primitives`

- `canonical[]`: `{ value, expect, hash }` - STRICT canonical JSON and `base64url(sha256(canonical))`.
- `json_parse[]`: `{ input, accept, canonical? }` - strict JSON profile; `accept:false` MUST be rejected.
- `b64u[]`: `{ input, valid, len? }` - strict base64url; `len` = required decoded byte length.
- `merkle[]`, `params_digest_empty` - unchanged.
- `threshold_share[]`: role/signerSetHash/t-bound share vectors. Each `{ role, t, signer_set, threshold_message,
  signer_set_hash, share_message, share, valid? }`. A verifier that checks threshold shares MUST confirm
  `share` verifies over `share_message` (under `share.publicKey` / `share.pq_pk` per `share.alg`) iff
  `valid` (default `true`). v2.1 AGENT-LEAF BINDING: the `role:"agent"` entries sign the SAME
  `"atlas-pca/share/agent\0" || sha256(thresholdMessage) || signerSetHash || t` bytes as guardian/principal
  (positive); the OLD bare-threshold-message agent share (`agent-bare-rejected`) and a cross-signer-set replay
  (`agent-bound-wrong-set`) are `valid:false`. Guardian/principal share bytes are UNCHANGED by v2.1.
- `pq_artifact[]`: representative post-quantum signatures for the non-leaf transparency/authority surfaces —
  `sth`, `revocation`, `beacon`, `bond-settlement`, `safety-certificate`, `judge-verdict`,
  `software-attestation` — each `{ artifact, alg, ed_pub, pq_pk?, body, message, sig, pq_sig?, valid }`. All
  route through the SAME pq.ts agility seam as the leaf; a verifier confirms the signature over
  `message` with the suite `alg` iff `valid`. Spans all 10 suites (positive + a corrupt-`sig` negative each).

## NORMATIVE rules (wire format v2)

### 1. Signed body and message
`ver = 2`. Signed message: `"atlas-pca/actn/v2\0" || sha256(canonical(body))` where `body` is the PCActn WITHOUT
`sig` and `threshold`. Signed fields (v2): `ver, action{verb,resource,params_digest,reversibility_class}, grant_ref,
cap_chain, plan{root,inclusion_proof{index,size,path[{side,hash}]},node_id,conditions_digest?}, attestation{quote_digest,
epoch,model_id,measurement,operator}, provenance{causal_hash,taint_level,trusted_refs}, freshness{beacon_ref,epoch,
accumulator_witness}, counter, risk_claim{r,inputs}, aud, iat, exp` + optional `nonce, caution, rationale_commitment,
progress_step, prohibition_evidence, tool_binding, zk_compliance, bond_ref`. `threshold` is the only unsigned container.
The top-level field set is CLOSED (unknown top-level / action / plan / proof / cap_chain-hop keys => `wire` fails). A capability-chain hop is closed to exactly `{id, issuer, holder, body_digest, caveats, sig, parent?}` — any other key is unsigned malleability and fails `wire`.

### 2. Strict JSON profile (parsing signed bytes)
Parse with a hand-written RFC 8259 parser, NOT a platform default, rejecting: comments; trailing commas; BOM; any
whitespace other than space/TAB/LF/CR; duplicate object keys (compared after unescaping); lone surrogates (raw or as
`\uXXXX` escapes); raw control characters (< U+0020) in strings; unknown escapes; nesting deeper than 32 containers;
input longer than 2^20 UTF-8 bytes; and any number not in the canonical number form (3). Result must be an object.

### 3. Numbers
- Integer fields MUST be safe integers (|n| <= 2^53-1; `-0` rejected): `ver, counter, iat, exp, attestation.epoch,
  freshness.epoch, plan.inclusion_proof.index, plan.inclusion_proof.size`. A float literal (`1.0`, `7e0`, `1.5`) or a
  value >= 2^53 in any of them is a `wire` failure.
- ANY number, anywhere in the signed body (including caveats): an integer lexeme must be a safe integer; a non-integer
  must be plain decimal (no exponent, no leading `+`/zeros, no trailing fractional zero, no `.5`/`5.`), have at most 15
  significant digits, and magnitude >= 1e-6. `-0` is rejected. (Such a number round-trips through an IEEE-754 double
  and the shortest-round-trip decimal printer byte-for-byte in every language.)
- Time unit: `iat`, `exp` are epoch MILLISECONDS.

### 4. Canonical serialization (what is hashed/signed)
Objects: keys sorted BYTEWISE over their UTF-8 encoding (== Unicode code point order; NOT UTF-16 code unit order).
No whitespace. Strings: escape only `"` `\` and control chars < U+0020 (`\b \f \n \r \t` short forms, others `\u00xx`
lowercase); everything else (incl. U+007F, U+2028/2029, astral) raw UTF-8. Numbers per (3). Arrays keep order.

### 5. Byte fields (strict base64url)
RFC 4648 section 5, NO padding, alphabet `A-Za-z0-9-_` only, no whitespace, `len % 4 != 1`, and the unused trailing bits
of the last character MUST be zero (re-encoding the decoded bytes must reproduce the string exactly). Fixed lengths:
signatures 64 bytes (`sig`, every `cap_chain[i].sig`, threshold share `sig`); 32 bytes: `grant_ref`, `cap_chain[i].{id,
issuer,holder,body_digest,parent}`, `plan.root`, proof `hash`, `action.params_digest`, `plan.conditions_digest` (when
present; a non-string is a `wire` failure, never a default), `rationale_commitment`, `tool_binding`, share `publicKey`.

### 6. Freshness binding (checks `audience`, `validity`)
`aud` (non-empty string <= 256 UTF-8 bytes) MUST equal the verifier's own audience id. `exp > iat`; `exp - iat <= 3,600,000`;
`iat <= now + 60,000`; `now <= exp`. Optional `nonce`: non-empty string <= 128 UTF-8 bytes (a resource server MAY track it).
`caution` in [0,1] (MONOTONE: verifier uses `r = max(server r, caution)`).

### 7. Other checks
`version`: `ver == 2`. `chain`: <= 16 capabilities (checked before any signature work), root == grant, strict
RFC 8032 signatures (reject non-canonical S, non-canonical / small-order / mixed-order points: the identity key and the
order-2 key with signature R=identity,S=0 MUST NOT verify), hash-linked, issuer==parent.holder, append-only caveats.
`plan_inclusion`: index/size bound to the path shape (path length and every side recomputed from `index,size` by the
RFC 6962 split; `size >= 1`, `0 <= index < size`), 32-byte siblings. `leaf_signature`: strict Ed25519 under the leaf
holder over the signed message. `counter`: safe integer >= 0.

### 8. Capability / plan / Merkle (unchanged from v1)
Capability hop: `id = body_digest = hash({issuer, holder, caveats, parent|null})`, signature over
`"atlas-pca/cap/v1\0" || raw(body_digest)`; `parent` = hash of the full parent capability. Merkle leaf = H(0x00 || canon(leaf)),
node = H(0x01 || L || R), split at the largest power of two < n. Plan leaf: `{node_id, verb, resource, params_digest
(default hash({})), reversibility_class (default "reversible"), conditions (default hash({pre:null,post:null}))}`.
(Note: key order inside these hashes is now bytewise-UTF-8 too; this only differs from v1 for keys containing astral
characters.)

### 9. Threshold shares (server side)
Guardian / principal share message: `"atlas-pca/share/<role>\0" || sha256(thresholdMessage) || signerSetHash || t(1 byte)`
with `signerSetHash = sha256("atlas-pca/signerset/v1\0" || canonical(sort_by(role, publicKey)[{publicKey, role}]))`.
The agent share is the leaf `sig` over `thresholdMessage` itself. `verifyThreshold` requires t in {1,2,3}, exactly one
key per role, no key under two roles, and counts DISTINCT KEYS.
