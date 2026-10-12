# PCA release gate in a zkVM (RISC Zero)

> Status: **experimental, unaudited, not published.**

The Proof-Carrying Authority release decision (full predicate language, fixed-point risk,
caveats, native SHA-256 commitments and an in-guest Ed25519 capability-chain check) runs inside a
RISC Zero guest. The host produces a succinct receipt whose journal is the public statement
(`allow`, `r_scaled`, `tier`, three commitments, `chain_verified`, and the evaluated `context`, see RT-06 below).

## Red-team round 6 (R6-ZK-01 to R6-ZK-06): current guest `3b1eebb5...fdad`

BREAKING: new image id `3b1eebb56b046e737fb15009bdd065b67d7938cb8d47f3f3f0dadc801f84fdad`, and the journal gains a leading `guest_version` field (7). The guest now matches the
TypeScript reference (`verifyPCActnCore` plan inclusion + `policy-vm.ts` `decide`) field by field:

- conditions are evaluated three-valued (`true`/`false`/`unknown`) exactly as `evaluateConditionTri`, with the FULL DSL: `like`,
  `is_a`, `member_of` and the `all_of`/`any_of`/`not` groups are ported (no deny-only gaps remain);
- a PRESENT `ref` of any type (`null`, number, object, ...) is a path that must resolve, so it is `unknown` (R6-ZK-01: `ref: null`
  used to fall back to `value` and allow); an object carrying `all_of`/`any_of`/`not` is a group whatever leaf fields it also has
  (R6-ZK-02); `action.params` that is an array counts as present (R6-ZK-05);
- the reversibility class is `action.reversibility_class ?? node.reversibility_class` with the node the SIGNED
  `pcactn.plan.node_id` names, never the first node with the same verb/resource (R6-ZK-03);
- the plan binding recomputes `planLeaf(node_id, action, conditions_digest ?? default)` from the signed action, with the `??`
  defaults of merkle.ts; the envelope must pass `readEnvelope` + `validateRiskPolicy` (string `goal_commit`, array `predicates` and
  `caveats`, object `agent_binding`, finite non-negative weights, finite `theta1 <= theta2`, `kappa > 0`, `lambda`, `rho`, `bMax >= 0`);
- `tool_schema` binds `String(signature_digest)` like the TS (R6-ZK-05); `subject` and `env` are not held to the wire profile
  (R6-ZK-04: the TS never strict-canonicalizes them; numbers outside the profile are hashed as ECMAScript `Number::toString`);
- the delegator key A and the signature's R must re-encode to the same 32 bytes (no `y >= p` alias, no sign bit on `x = 0`), as
  noble with `zip215: false` (`chain::ed25519_point_strict`);
- the image id is reproducible from any checkout path: the guest is built in risc0's docker guest builder
  (`r0.1.97.0`, `methods/build.rs`); `bash host/box-prove.sh <out>` reproduces the whole run on an x86_64 Linux box;
- the verifier refuses every superseded image id (`SUPERSEDED_IMAGE_IDS`, all six earlier guests) even when the caller pins it,
  and `check_context` refuses a journal whose `guest_version` is below `MIN_GUEST_VERSION` (R6-ZK-06).

Evidence: guest vs TS reference, all validly signed (the chain and PCActn are re-minted per case): the field-typing matrix
(`fixtures/ts_r6_cases.json`, 4,792 cases: every optional field x absent / null / wrong types) 0 divergences (the round-5 guest:
457); 3 x 100,000 random cases on cloud boxes, 0 divergences (the round-5 guest: 5,541 on seed 1); 132 Ed25519 encodings
(`fixtures/ts_r6_points.json`) identical. Receipts re-proved on CPU (a 4-core pcaq job on a shared 8-vCPU x86 Azure box; no exclusive box was free): succinct 224530 bytes,
12 segments, 12582912 cycles, 5424 s; Groth16 1801 bytes, 139.4 s; negative matrix 55 variants, none
produced a receipt (13 new `r6_*`). The round-5 receipts are under `fixtures/legacy/e922536c/`. Residual differences, all in the
deny direction and outside the TS wire domain: a non-string `pcactn.tool_binding` or `plan.node_id` is refused (TS ignores /
stringly matches it), JSON nesting deeper than serde's 128 in `env`/`subject` does not parse, and a malformed DecideInput witness
field (`recent_action_times` not an array of numbers) refuses the whole decision instead of only the `rate` caveat.

## Red-team round 5 (R5-ZK-01 to R5-ZK-04): guest `e922536c...91a8` (superseded by round 6)

The guest now (a) treats a malformed `tool_schema` scalar bound (`maxLength`, `minLength`, `prefix`, `min`, `max`, `minItems`,
`maxItems`) as UNSATISFIABLE instead of dropping it and applying a default (R5-ZK-01), (b) counts string lengths in UTF-16 code
units like JavaScript (R5-ZK-02), (c) enforces the strict wire limits in-guest: documents of at most 512 KiB, the strict canonical
number profile (safe integers, no `-0`, no exponent-scale or over-precise floats), nesting at most 32, and the 256 per hop /
1024 per chain caveat caps (R5-ZK-03), and (d) evaluates `matches` conditions and charges them to the same per-document regex
budget as `re:` resources (R5-ZK-04). This is a breaking change of the guest image id only (journal and verifier API unchanged).
Receipts were re-proved on CPU (succinct 224522 bytes, 12 segments, 12058624 cycles, 4231 s on a shared 8-vCPU box; Groth16 1793
bytes, 192.5 s); the negative matrix is 48 variants (14 new `r5_*`). The round-4 receipts (`1c1b8bbd...3b95`) are under
`fixtures/legacy/1c1b8bbd/`. Statements below that cite `1c1b8bbd...3b95`, "34 variants" or "2957.3 s" describe the round-4 build.
Evidence: 0 divergences from the TS reference on 200,000 random `tool_schema` cases, the 24,000 PoC cases, 100,194 canonical-profile
values and 471 `matches`/budget documents (`core/tests/r5_*.rs`, `CHANGELOG.md`). Still not ported (not-true, i.e. fail closed): the
`like`, `is_a`, `member_of` operators and `all_of`/`any_of`/`not` condition groups.

## Red-team round 4 (R4-02 to R4-04): guest `1c1b8bbd...3b95` (superseded by round 5)

The guest now (a) matches `re:` patterns with a Rust port of the TypeScript linear-time NFA matcher (`core/src/safe_regex.rs`: same
subset guard, JavaScript flagless semantics over UTF-16 code units, same limits, and the per-document regex budget of the
reference), instead of the `regex` crate whose semantics differed on 15 of 17 audited cases (R4-02); (b) treats a malformed or
unbound `tool_schema` caveat as UNSATISFIED (R4-03); and (c) enforces the signed PCActn's own `ver == 2`, `aud`, `counter >= 0`,
`iat < exp <= iat + 1 h`, `iat <= now + 60 s`, `now <= exp` in-guest and commits `pcactn_ver`, `pcactn_iat`, `pcactn_exp`,
`pcactn_aud`, `pcactn_counter` to the journal (R4-04). `ExpectedContext` requires all five (no "any audience" default) and
`check_context` also evaluates the window against the VERIFIER's clock, so a genuine receipt proven at an honest `now` is
refused once the verifier's clock passes `exp`. This is a breaking change of the guest, the journal layout and
`ExpectedContext`; see `CHANGELOG.md`.

Receipts were re-proved on CPU on an exclusive 8-vCPU x86_64 box: succinct 224522 bytes, 11 segments, 11534336 cycles,
2957.3 s; Groth16 wrap with the docker prover 1793 bytes (256-byte seal), 187.8 s; the negative proving matrix is now 34
variants (9 new: `r4_03_*`, `r4_04_*`, all with valid signatures). The round-3 receipts (`ce0b5423...cf1b`) are under
`fixtures/legacy/ce0b5423/`: they verify under their own id, do not decode as the current journal and are refused by
`verify_with_context`. The statements below that cite `ce0b5423...cf1b`, "25 variants", "224418 bytes" or "5387 s" describe the
round-3 build. Evidence: `core/tests/r4_regex_differential.rs` (7207 golden cases from the TS reference plus the 100k run in
`redteam/round4/zk/differential-100k.result.txt`, 373,748 cases, 0 divergences), `core/tests/r4_tool_schema_fail_closed.rs`,
`core/tests/r4_pcactn_freshness.rs`, `verify/tests/context_pinning.rs`.

Still not covered (honest boundary): the strict wire form of `validateWireV2` (canonical numbers, caveat-count and size caps) is
not enforced in-guest, and the guest has no `matches`, `like`, `is_a` or boolean condition groupings (they evaluate false).

## Red-team round 3 (R3-11 to R3-14): previous guest `ce0b5423...cf1b`

The guest now (a) evaluates the caveats of every hop of the chain (not just the root envelope), (b) derives the
delegation depth as `chain.len() - 1` (the `delegation_depth` input is gone), and (c) binds the signed PCActn to the
verified chain, the action, the plan root and node and the tool binding, committing `delegation_depth`, `grant_ref` and
`node_id` to the journal. The verifier refuses fake (dev-mode) receipts and ignores `RISC0_DEV_MODE`. See
`CHANGELOG.md`. Receipts were re-proved on CPU (succinct 224418 bytes, 5387 s, 12.06M cycles; Groth16 1689 bytes,
264 s); the negative proving matrix is now 25 variants (the 9 new ones carry valid signatures, so only the new check can
be the cause). The statements below that cite image ids `6b0ac893...97cc`, `dcf198fc...813a` or "16 variants" describe
earlier builds; the pre-R3 receipts are under `fixtures/legacy/6b0ac893/`. Tests: `core/tests/r3_delegation_binding.rs`,
`verify/tests/dev_mode_fake_receipt.rs`.

## RT-06: the journal commits the context it evaluated

Before this change the journal held only the verdict and three commitments, so a receipt proved "the gate
passes for SOME now / subject / env / rate history / risk inputs" and a backdated `now` produced a
byte-identical journal. The journal now also commits `context`: `now` (exact f64 bits), digests of `subject`,
`env` and the rate history, the delegation depth, the tool binding, the six risk inputs, the budget, the risk
floor, the pinned root principal and a digest of the signed leaf PCActn. `policy_commit` (the grant) and
`action_commit` were already there.

A verifier must state what it expects: `pca_zkvm_verify::verify_with_context(receipt, image_id, &ExpectedContext)`
verifies the receipt and then `pca_zkvm_core::context::check_context` rejects any mismatch (`Now` outside the
tolerance window, `Subject`, `Env`, `RateHistory`, `DelegationDepth`, `RiskInputs`, `Budget`, ...). There is no
overload without an expectation; calling `receipt.verify` alone still says nothing about when or for whom.
Tests: `core/tests/context_binding.rs` (backdated `now` changes the journal; every input moves the context) and
`verify/tests/context_pinning.rs` (the committed receipts: a verifier clock a year later, a swapped subject,
env, rate history, depth, risk inputs or budget are rejected although the receipt verifies).

Consequences, stated plainly. The raw risk inputs, budget and floor are now public (they were private
witnesses); a deployment that needs them hidden would commit a salted digest instead. The guest still cannot
know the true time: it only commits the `now` it was given, and the verifier's clock check is what makes it
meaningful. The current guest has image id `6b0ac893...97cc`; the receipts were proved on CPU (8 vCPU Azure
x86, 3365 s, 11.5M cycles, 11 segments) and wrapped to Groth16 with the docker prover (211 s, 1585 bytes);
provenance is in `fixtures/proof_run/PROVENANCE.json`. The earlier guests (`dcf198fc...813a`, `ac95031f...96e3`)
are kept under `fixtures/legacy/` and `fixtures/legacy/dcf198fc/`: they still verify under their own ids, decode
only as `LegacyDecision`, and are refused by `verify_with_context`. The statements in the sections below about
the `dcf198fc` guest describe that earlier build; the structure of the checks is unchanged for the current one.

## Verifying the committed receipt

No guest toolchain, proving or GPU is needed to verify:

```
cargo test -p pca-zkvm-verify      # succinct and Groth16 receipt checks (verification only)
cargo test -p pca-zkvm-core        # decision logic, standard vectors, reference cross-checks
```

## What is validated

- **Committed receipt.** The committed succinct receipt verifies against the committed image id,
  its claim binds the image id and the SHA-256 of the journal, and the journal equals the
  committed statement and the output of the pure decision logic on the committed input.
- **Groth16 receipt.** `fixtures/receipt_groth16.bin` (825 bytes, 256-byte seal) is the committed
  succinct receipt wrapped into a Groth16 receipt with RISC Zero's Groth16 prover
  (`risc0-zkvm` 3.0.6, prover image `risczero/risc0-groth16-prover:v2025-04-03.1`; provenance in
  `fixtures/proof_run/PROVENANCE.json`). The files directly under `fixtures/` (`image_id.json`,
  `receipt_succinct.bin`, `receipt_groth16.bin`) are byte-identical to `fixtures/proof_run/` and pin the
  current guest. It verifies against that image id on a Mac with the verify-only crate, carries the same
  journal and the same claim digest as the succinct receipt, and is rejected for: a bit flip in
  the first or last image-id word (all 64 variants), a flip in any journal byte, an extended,
  truncated or empty journal, a flip of the low bit of each of the 256 seal bytes, a truncated, extended or
  all-zero seal, a changed verifier-parameters digest, and a flip of the low bit of any byte of the serialized
  receipt. The exhaustive check, every one of the 2048 single-bit seal flips, is in
  `verify/tests/groth16_proof_run.rs` and accepts exactly three flips (see "Seal malleability" below), so
  "every seal bit" is not rejected.
- **Proof run on an H100 (current guest).** `fixtures/proof_run/` holds a succinct receipt proved on an
  NVIDIA H100 NVL (Azure `Standard_NCC40ads_H100_v5`, CUDA build of the host) in 24.9 s, against 530.8 s for
  the same proof on 40 CPU vCPUs (9.6 GB peak RSS on CPU, 0.66 GB on the host side of the GPU run; 11.5M
  cycles, 11 segments), and its Groth16 wrap (825 bytes, 256-byte seal; 21.3 s using the docker stark-to-snark
  prover on x86_64 CPU). The Groth16 receipt verifies on a Mac with the verify-only crate against image id
  `dcf198fc...813a`, and is rejected for a wrong image id (24 variants, "claim digest does not match"), any
  mutated, extended, truncated or emptied journal (same reason), every one of the 2048 single-bit seal flips
  except three, a resized seal, a changed verifier-parameters digest, and byte flips across the serialized
  receipt. Provenance (versions, image id, hosts, date, sha256 of every artifact) is in
  `fixtures/proof_run/PROVENANCE.json`. The receipts of the earlier guest build (image id `ac95031f...96e3`)
  are kept under `fixtures/legacy/`; they still verify under that id, do not verify under the current one,
  and make the same public statement (`verify/tests/legacy_and_default_fixtures.rs`).
- **Independent on-chain-style check.** `verify/tests/groth16_proof_run.rs` re-derives the
  `RiscZeroGroth16Verifier` equation with arkworks directly (public inputs: control root halves, claim digest
  halves, BN254 control id; canonical field decoding; pairing check) without calling the RISC Zero verifier.
  It accepts the genuine receipt, rejects every one of the 2048 single-bit seal flips and a changed claim
  digest. An actual Solidity/EVM execution of the verifier contract was not run.
- **Seal malleability in the Rust verifier (observation).** RISC Zero's Rust Groth16 verifier still accepts
  the seal when bit 7 of byte 32, 128 or 224 is flipped (the flag bits that share the top byte of each y
  coordinate are ignored by arkworks' uncompressed decoding). The points, and therefore the statement, are
  unchanged, so this is not unsoundness, but a hash of the seal must not be used as a unique receipt
  identifier; the canonical decoder above (like the EVM precompile) rejects those encodings.
- **Negative proving.** For 16 non-compliant inputs (risk above the ladder with no budget, a predicate miss,
  tampered leaf and root hop signatures, a misrooted chain, a dropped leaf hop, a tampered or missing leaf
  PCActn signature, a post-quantum suite hop, an exceeded delegation depth, an expired grant, a non-canonical
  S + L signature, an identity-R zero-S signature, a tampered body digest, an emptied caveat list, and a
  mixed-order delegator key) the guest panics ("PCA release gate DENIED") during both execution and proving,
  so the prover returns an error and no receipt exists (`fixtures/proof_run/negative_proving.json`, with the
  pure decision's tier and `chain_verified` per variant). The compliant input proves in the same run as the
  positive control.
- **Rejections, with reasons.** A wrong image id (24 single-bit variants) and a mutated, extended,
  truncated or emptied journal (every byte) are rejected with "claim digest does not match the
  expected digest". Seal mutations are rejected as "invalid receipt format" or "verification
  indicates proof is invalid"; a mutated control id, verifier-parameter digest or hash-function
  name is rejected; byte flips across the serialized receipt are rejected.
- **Official vectors.** The five Ed25519 vectors of RFC 8032 section 7.1 verify in the strict
  verifier the guest uses; bit mutations of message, signature and key, key confusion between
  vectors, a non-canonical S (S + L) and a small-order key/R are rejected. The four SHA-256
  vectors of RFC 6234 reproduce. Provenance (URL, retrieval date, SHA-256 of the RFC text) is in
  the fixture file.
- **Reference cross-checks.** The commitments equal the TypeScript reference output, and the
  chain verdicts (untouched, tampered leaf hop, tampered root hop, wrong pinned root) equal those
  of the TypeScript `verifyChain`, which uses a different Ed25519 implementation. A second suite
  (`core/tests/ts_variants.rs`, fixture generated by `core/tests/gen_ts_chain_variants.mjs`) compares verdicts
  and reason texts on 49 tampered, re-signed (valid signatures, semantic violations) and structurally odd
  chains (signature edits and encodings, non-canonical S + L, identity R, digest and id edits, holder and
  issuer swaps, caveats dropped, widened, reordered or appended, broken parent links, reversed and duplicated
  hops, 16 and 17 hops, budget allocations widened, narrowed, negative and non-numeric, a mixed-order key) and
  13 leaf PCActn variants against the TypeScript reference (@noble/curves). Reason text may differ only for
  the unknown and post-quantum suites, which the guest rejects by design.
- **Torsion cases.** The variant set also holds three cases with a torsion R: R plus an order-8 point with an
  honest prime-order key, a small-order R, and a mixed-order key together with a mixed-order R ground so that
  the cofactorless equation holds. The last one is accepted by `verify_strict` alone and rejected by the guest
  and the reference, which shows the torsion-freeness requirement is the cause. With a prime-order key a
  torsion R can never satisfy the cofactorless equation, so the R test cannot be isolated as the only reason
  for a denial; it is defence in depth.
- **Differential run.** `core/tests/differential.rs` drives the guest's decision code with 2528 seeded random
  and boundary witnesses (2328 in the quantisation domain) and requires it to equal an exact integer
  reference; the TypeScript float model agrees except at 47 exact boundaries where it is stricter. Outside the
  domain the guest clamps (and has no `bMax` range check, like the TypeScript model), whereas the STARK crates
  refuse such witnesses.
- **Why a variant was refused.** The guest reports every refusal with the same panic text.
  `core/tests/negative_causes.rs` runs the same decision code natively and, for each of the 16 variants,
  shows which single input group (risk and budget, action, chain, leaf PCActn, clock, delegation depth),
  restored to its compliant value, turns the denial into an allow, and that no other group does.
- **Bug found and fixed by that suite.** The guest used `verify_strict`, which rejects small-order A and R but
  not mixed-order ones; the TypeScript reference also rejects any non-torsion-free A or R. A delegator key
  A + T (T of order 8) with a signature ground so that k = 0 mod 8 satisfied the cofactorless equation in the
  guest but not in the reference (a verdict divergence on keys the delegator chooses, not a forgery of the
  pinned root). `core/src/chain.rs` now also requires A and R to be torsion-free. This changed the guest, so
  the image id changed (`ac95031f...96e3` to `dcf198fc...813a`); `proof_run` is the rebuilt guest.

## What is not validated

- The receipts were produced once per guest build; the guest proof was not re-run in the verify
  checks, and the Groth16 receipts were wrapped from succinct receipts. The Groth16 step relies on
  RISC Zero's trusted setup for its wrapping circuit.
- The CUDA Groth16 wrap (rzup component `risc0-groth16`) aborted with "an illegal memory access was
  encountered" on the confidential-compute H100 VM, so the committed Groth16 receipt used the CPU
  docker wrap of the GPU-proved succinct receipt. The GPU succinct proof itself worked.
- The sample input is a single compliant action; cycle counts and timings are for that input only.
- The torsion-freeness fix is covered by the cross-implementation test, the strict-only counterfactual and the
  negative-proving matrix, but there is no RFC vector for mixed-order keys.
- The negative-proving record (`negative_proving.json`) carries the guest's generic refusal text; the reason
  for each refusal is attributed natively (`negative_causes.rs`), not read from the guest, because naming the
  reason inside the guest would change the image id.
- Only Ed25519 chains are proven in-guest; post-quantum suites fail closed.
- No third-party review of the guest or the decision logic. The zkVM and its parameters are an
  external dependency of the soundness claim.
