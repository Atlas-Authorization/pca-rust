# PCA conformance suite (wire format v2)

Golden + adversarial vectors for CORE PCActn verification (strict wire form, freshness binding, capability
chain, Merkle plan inclusion, Ed25519 leaf signature, counter) PLUS the full post-quantum crypto-agility
coverage and the v2.1 agent-leaf share binding.

## Two corpora: curated core + full adversarial set

| file | what | who vendors it | size |
|---|---|---|---|
| `vectors.json` | **Curated core**: the 172 golden vectors (ed25519 core + post-quantum + v2.1) AND a deterministic, representative sample of every adversarial family (`adv-*`: 90 vectors, 6 per family; for each family the smallest vector of every distinct outcome class, then an even stride) plus a sample of the adversarial primitives. | every language verifier's native suite and every public mirror (`pca-go`, `pca-python`, ... `pca-swift`, `pca-kotlin`) | ~1.9 MB |
| `vectors-adversarial.json.gz` | The **full** adversarial parser-differential set: 4,209 `adv-*` PCActn vectors + 1,178 primitives (425 `json_parse`, 718 `b64u`, 35 `canonical`), same schema. `primitives` holds ONLY the adversarial entries; `sample_in_core` lists the names also present in `vectors.json`. A plain `vectors-adversarial.json` is accepted wherever the `.gz` is (write one with `gen-conformance-adv.mjs --plain`). | the flagship `pca` repo and the monorepo gate only (`scripts/pca-conformance-all.sh` via `gen-adversarial.ts`); NOT the language mirrors | ~1.1 MB gz (~15 MB expanded) |

Native per-language suites assert MINIMUM counts, never exact sizes, so the core can be re-sampled safely. The full set is exercised cross-language by the gate
(`bash scripts/pca-conformance-all.sh --fuzz 300`), which drives every verifier over the core + full set + seeded fuzz and fails on any disagreement.

Regenerate (deterministic, idempotent; the gzip header carries no timestamp so the bytes are reproducible) with the THREE-STAGE pipeline — the
base generator writes the ed25519 core corpus, the PQ generator APPENDS all post-quantum coverage, the adversarial generator writes
the full set and splices the core sample:

    pnpm --filter @atlasauth/pca build \
      && node packages/pca/scripts/gen-conformance.mjs \
      && node packages/pca/scripts/gen-conformance-pq.mjs \
      && node packages/pca/scripts/gen-conformance-adv.mjs \
      && node packages/pca/scripts/gen-conformance-r6.mjs \
      && node packages/pca/scripts/gen-conformance-depth.mjs \
      && node packages/pca/scripts/gen-conformance-mut.mjs
    # then, to refresh the committed gate manifest + matrix:
    packages/pca/node_modules/.bin/tsx packages/pca-conformance/adversarial/gen-adversarial.ts

Files are written one vector per line (valid JSON; shared writer `scripts/conformance-io.mjs`).

Each generator asserts every vector's / primitive's stated intent against the TypeScript reference before it
is written (`verifyPCActnCore` for PCActns; `verifyThreshold` / `verifyWithSuite` for the threshold + artifact
primitives); `packages/pca/src/conformance.test.ts` then re-runs the reference over the written file.
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

### Mutation-driven single-rule vectors (`mut-*`, `gen-conformance-mut.mjs`)

77 vectors (plus 2 `threshold_set` entries) for behaviour that native mutation testing (go-pca, python-pca) showed no earlier vector pinned: each is ONE mutation of a valid
PCActn (signed fields re-signed, so only the targeted rule can fail). They cover: wire typing of every `attestation` /
`provenance` / `freshness` / `risk_claim` field; the `caution` [0,1] bounds, `prohibition_evidence`, `threshold` container,
`progress_step`, `rationale_commitment` / `tool_binding` shapes; the `aud` (256) and `nonce` (128) byte caps on both sides;
closed field sets of `action` / `plan` / `inclusion_proof` / proof steps / hops and caveat `type`; single-leaf Merkle
index/size bounds and path-length mismatches; one vector per capability-chain rejection reason (root with parent, foreign
root, broken parent link, issuer not the parent holder, empty chain, non-string hop fields, caveat altered at index 1,
3-hop drop/swap); `counter = 0` accepted; `holder_pq` of the wrong length, a 1951-byte leaf `pq_pk`, string `trusted_refs` accepted, a pure ml-dsa-65 root equal to the stored grant (`requires: "pq-nonleaf"`); threshold shares with an explicit `"alg":"ed25519"` and over a set with an identical duplicate entry. They are golden vectors in the gate (category `golden`; the `requires` one runs in the native suites).

### PQ key binding + suite policy (`pqbind-*`, R3-03)

Every native verifier enforces the same F-2 binding as the TypeScript reference (`pqBindingError`, `verifyChain`, the PCActn leaf step):

- a hop (index >= 1) or the leaf whose suite carries a PQ key (`ml-dsa-65`, `hybrid-ed25519-ml-dsa-65`) is accepted only if
  `b64u(sha256("atlas-pca/holder-pq/v1\0" || utf8(pq_pk)))` equals the signer's `holder_pq` (the parent hop's, or the leaf capability's). No `holder_pq` means reject (fail closed; natives have no `allowUnboundPq`). Hop 0 is pinned by `chain[0] == grant`.
- `holder_pq` is part of the signed hop body when present and must be canonical base64url (32 bytes) on the wire.
- optional `context.allowed_suites` (array; absent = no policy; `[]` refuses everything) restricts the suite of every hop (root included) and of the leaf (absent `alg` == `ed25519`). A refusal fails `chain` (hop) or `leaf_signature` (leaf).

The 26 `pqbind-*` vectors (generated by `gen-conformance-pq.mjs`, each asserted against the reference) cover: attacker-own-key pure and hybrid leaves over an unbound grant, genuine keys over an unbound grant, an attacker key under a committed grant, a tampered `holder_pq`, a `holder_pq` signed by the wrong key, the `allowed_suites` policy (incl. the empty list), PQ hops with an attacker key or an unbound parent, and three-hop chains. They are also a `pq-binding` category in the all-languages gate.

### Standalone chain API: verifier-side root PQ authority (`primitives.chain_pin`, R4-01)

The PCActn path pins hop 0 by `chain[0] == grant`. The exported standalone chain API of every verifier (`verify_chain` / `VerifyChain`) has no grant, so it takes the root's PQ authority from the caller, exactly like TS `verifyChain` (R3-01):

- a non-ed25519 ROOT (`ml-dsa-65`, hybrid, ...) is accepted only if `pq_pins[root.issuer]` equals the root's `pq_pk` (a differing pin is a refusal), OR `trusted_root` is the root itself (same content hash: the verifier's own stored grant). Otherwise: `hop 0: root suite '<alg>' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)`. Natives have no `allowUnboundPq`.
- order of checks at hop 0: root-has-parent, expected root issuer, `allowed_suites`, then PQ authority, then the signature.
- ONE function resolves the verification key (`resolve*PqKey`); the low-level PQ verify accepts only its result, never `pq_pk` read from the artifact.

`primitives.chain_pin[]` entries: `{ name, class, description, chain, expected_root_issuer, pq_pins?, trusted_root?, allowed_suites?, expect: { ok, reason? } }`. A runner calls the chain API with those arguments and requires `ok`; when `expect.reason` starts with `hop 0: root suite` it must match exactly. 28 vectors: attacker-own-key pure-PQ and hybrid roots naming the victim issuer, wrong / foreign / absent pins, `trusted_root` equal and unequal, pinned and trusted positives, corrupt signatures under a right pin, mixed chains (ed25519 root + bound PQ hop, pinned PQ root + ed25519 / PQ / hybrid hops, attacker PQ hop), suite-policy ordering. The gate feeds them as `kind: "chain"` items (`raw` = JSON of the whole input; verdict `{allow, checks: {chain}}`, category `chain-pin`).

## Files

- `keys.json` - fixed keys `{ principal|agent|subagent|rogue: { seed, public } }` (base64url, no padding);
  `seed = sha256("atlas-pca-conformance/<label>")`. Extra chain keys are `sha256("atlas-pca-conformance/hop<i>")`.
- `vectors.json` (core) / `vectors-adversarial.json.gz` (full adversarial set) - `{ format: 2, ver: 2, sig_domain, cap_domain, share_domain, check_order, limits, primitives, vectors }`.

### Shared hard limits (`limits`)

Every verifier enforces the same limits, in the same order, with the same reason strings (the reason is not part of the compared verdict, but is stable):

| limit | value | where | failure |
|---|---|---|---|
| raw PCActn document size | 524,288 UTF-8 bytes (`max_artifact_bytes`) | FIRST, before any JSON parsing | `wire`: `artifact exceeds size limit (max 524288 bytes)` |
| strict JSON input (non-PCActn use: `canon`, `json_parse`) | 1 MiB (`max_json_chars`) | start of the strict parser | parse error |
| delegation chain depth | 16 hops (`max_chain_hops`) | start of the chain check | `chain` |
| caveats per hop / per chain | 256 / 1,024 (`max_caveats_per_hop`, `max_caveats_per_chain`) | after the depth bound, on raw list sizes, before any hashing or signature work | `chain`: `chain exceeds caveat limit (max 256 per hop, 1024 per chain)` |

The size cap leaves room for a hybrid LESS PCActn (about 130 KB of base64url `pq_pk` plus the signature, roughly 200 KB in all). The `adv-size-*` family (limit-1, limit, limit+1, multi-byte widths, a ~200 KB LESS-sized document) lives in `vectors-adversarial.json.gz` only: those documents are 200 to 600 KB each and are never sampled into the vendored core.

### Weak Ed25519 keys and signatures (`adv-ed-*`, `ed-weak-*`)

The reference rejects small-order and mixed-order keys and R, non-canonical S and non-canonical point encodings (stricter than plain RFC 8032). `adv-ed-{leaf,hop,root}-*` place each crafted signature on a PCActn leaf, a delegation hop and a root hop; `primitives.threshold_share` carries the `ed-weak-*` agent shares (all `valid: false`). Every one is accepted by a plain RFC 8032 equation (checked by `scripts/ed25519-weak.mjs`), so a native verifier built on a plain library fails them. Deterministic: fixed labels, nonces and tweak search.

### `vectors[]`

`{ name, class: positive|negative, description, grant, plan_nodes, context: { now, aud }, pcactn | pcactn_json, expect: { allow, checks } }`

- `pcactn` is the already-parsed object; `pcactn_json` is RAW TEXT that MUST first go through the strict JSON
  profile below (a parse failure == `wire` failure; the verdict is `{allow:false, checks:{wire:false}}`).
- A verifier runs `verify(pcactn, grant, now = context.now, audience = context.aud)`.
- `expect.checks` are booleans. If `wire` is false it is the ONLY entry (a wire failure is terminal: nothing else
  is evaluated). Otherwise all of `wire, version, audience, validity, chain, grant_ref_bound, plan_inclusion,
  leaf_signature, counter` are present. `allow` = every check true.
- Normative check order (`check_order`): wire, version, audience, validity, chain, grant_ref_bound, plan_inclusion, leaf_signature, counter.

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
  R6-02: when the signer set registers a `pq_pk` for the share's role, the share MUST use a PQ (pure or
  hybrid) suite verified under that registered key; an ed25519-only share for such a role is `valid:false`
  (`agent-bound-signerset-with-pq-pk`), a hybrid one verifies (`agent-hybrid-signerset-with-pq-pk`).
- `threshold_set[]` (round 6, `gen-conformance-r6.mjs`): WHOLE signer-set validation for one share, same schema as
  `threshold_share` plus optional `requires` (a suite the runner must implement, else it skips the entry). `valid` is
  true iff the reference `verifyThreshold({shares:[share]}, threshold_message, signer_set, t)` counts the share for
  `role`. Every native must validate the ENTIRE set exactly like the reference before looking at the share: every
  entry is an object with a known role (`agent`/`guardian`/`principal`, case-sensitive) and a canonical 32-byte
  base64url `publicKey`; a present `pq_pk` (JSON null is present) is canonical base64url of a registered PQ key
  length (1952, 2592, 32, 64, 897, 1793, 97484 bytes); one key per role, one role per key; a duplicate
  (role, key) entry is accepted only if it carries the same `pq_pk` (or none on both). `t` must be 1, 2 or 3.
  `share.role` must equal `role`; a role that registers `pq_pk` needs a PQ / hybrid share (R6-02).
- `signer_set_hash[]`: `{ name, signer_set, hash }`, the reference `signerSetHash` (b64u). Rows are sorted by the
  UTF-8 BYTES of (role, publicKey) (not UTF-16 code units: non-BMP strings) and carry `pq_pk` whenever it is a
  string, including `""`.
- `malformed[]`: `{ name, description, api, input }`, every one a DENY that must come back as a clean verdict, never
  an exception escaping the public entry point (R6-05). `api: "chain"` -> `verify_chain(input.chain,
  input.expected_root_issuer)` is not ok (includes correctly SIGNED hops whose caveats or optional fields are
  ill-typed: the reference type check refuses them); `api: "threshold_share"` -> `verify_threshold_share(input)` is
  false for ANY JSON value; `api: "pcactn_json"` -> strict-parse `input.text` (a parse failure is a deny) and verify
  against `input.grant` / `input.now` / `input.aud`: not allowed.
- `depth[]` (`gen-conformance-depth.mjs`): `{ name, description, api, depth, input, valid, expand? }`, nesting-depth
  limits (MAX_JSON_DEPTH = 32) on every untrusted entry point at 31 / 32 / 33 and at 100000. Same `api` dispatch as
  `malformed[]` plus `json_parse` (`input.text` -> strict parse accepts); `valid` is the reference verdict (chain ok /
  share counted / allowed / accepted), and every case must be a clean verdict (no exception, panic or stack overflow).
  `depth` counts the untrusted value (chain array, share entry, PCActn document, parsed text; outermost container = 1).
  A chain hop is canonicalised (and capped) on its own, so a depth-N chain holds depth N-1 hops (chain 33 verifies, 34
  does not); extra signer-set member fields are never canonicalised, so they count at any depth. The huge cases carry
  `expand: { marker, levels, leaf }`: replace the string value equal to `marker` in `input` (chain / threshold_share)
  or the substring `marker` of `input.text` (pcactn_json / json_parse) with `levels` nested arrays around `leaf`,
  built iteratively, before running the case.
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
`version`: `ver == 2`. `grant_ref_bound`: `grant_ref` is a non-empty string byte-equal to `cap_chain[0].id` (exact comparison, no normalization; independent of `chain`; fails closed when the chain is empty). `chain`: <= 16 capabilities (checked before any signature work), root == grant, strict
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
