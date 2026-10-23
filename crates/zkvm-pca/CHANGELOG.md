# Changelog

## PCA 0.4.2 re-pin (BREAKING: new guest image id `432b4713d7981afc30907003d3a2c7e7d0003cc34b2367b4cba8d61b642c0060`, guest version 10)

The guest follows the reference fix that `intentV2Active` is also true for a PRESENT but malformed v2 context (fail closed;
the TypeScript reference and the native verifiers already do). `intent_v2_active` has no caller in the guest, yet the code
change alters the compiled guest (a comment-only change leaves the image id unchanged), so the guest is rebuilt and re-proved.
Image id `c5107456f3885cfe87f0da62d24aa273e1fe94c982eed57324374dcefa80ac39` to `432b4713d7981afc30907003d3a2c7e7d0003cc34b2367b4cba8d61b642c0060`; `GUEST_VERSION` = `MIN_GUEST_VERSION` = 10; journal layout unchanged (the proved journal differs only in `guest_version`).

- **`intent_v2_active`** (`intent_v2.rs`) adds `intent_v2_context_error(ctx).is_some()`, as rust-pca. Test: `core/tests/v2_active.rs`.
- **Verifier:** `c5107456...` joins `SUPERSEDED_IMAGE_IDS`; version-9 journals decode but are refused by `MIN_GUEST_VERSION`
  (`a_guest_version_9_receipt_is_refused`). Its receipts moved to `fixtures/legacy/c5107456/`.
- **Proving run** (one run, GCP pca-box n2 custom 12 vCPU / 62 GB, CPU proving, RISC Zero 3.0.6, guest built in the docker guest
  builder via `host/box-prove.sh`): succinct receipt 3,426,705 ms (12 segments, 12,582,912 cycles, 11,143,341 user), Groth16
  wrap 106,350 ms (1,817 bytes), negative matrix 55 of 55 variants panic with no receipt.

## PCA 0.4.2 R3-01 (BREAKING: new guest image id `c5107456f3885cfe87f0da62d24aa273e1fe94c982eed57324374dcefa80ac39`, guest version 9)

The guest follows the session-root PQ pin fix of the TypeScript reference and the nine native verifiers (R3-01). Image id
`0c97a02b...53a7` to `c5107456f3885cfe87f0da62d24aa273e1fe94c982eed57324374dcefa80ac39`; `GUEST_VERSION` = `MIN_GUEST_VERSION` = 9; journal layout unchanged.

- **A PQ / hybrid session root verifies only under the verifier's pin (security).** `verify_session_root_pinned(S, pq_pins)`
  (`intent_session.rs`, = TS `verifySessionRoot(S, {pqPins})`, = rust-pca): for a non-ed25519 suite the signer's PQ key comes from
  `intent_v2.session.pq_pins[S.signer]` (an own member, a string), never from the root's own `principals[].pq_pk`. No pin, a pin
  other than `S.pq_pk`, or a signer principals entry declaring another key fails, with the reference's reasons, before the
  suite signature. Ed25519 roots ignore the pins. Guest version 8 verified a pure-PQ root under the key its own principals entry
  named, so it proved roots that anyone naming a principal could sign. Rules 13 and 15 (`boundRoot`) pass the pins.
- **Context validation.** A present `session.pq_pins` that is not an object of strings is malformed (`the session pq_pins must be
  an object of strings`, `intent_session` fails), as `sessionCtxError`.
- **Binding.** The pins are part of `DecideInput.intent_v2`, whose `hashCanonical` the journal commits
  (`context.intent_v2.ctx_digest`, pinned by `ExpectedContext::intent_v2_ctx_digest`): a receipt binds the pin set it was
  proved under, like `session.revocation_last` and the other verifier trust inputs.
- **Tests:** `ts_v2_session.json` / `ts_v2_pipeline.json` regenerated from the reference with the verifier pins per case and the
  R3-01 set (conformance `session-root-*-{unpinned,pin-other-signer,pin-mismatch}`, `principal-entry-mismatch`,
  `ed25519-pq-pins-ignored`, `ctx-session-pq-pins-*`, plus malformed pin sets and the attacker-key root);
  `core/tests/r042_session_pq_pins.rs` pins the version, reasons, rule 15 and the `ctx_digest` binding.
- **Verifier:** `0c97a02b...53a7` joins `SUPERSEDED_IMAGE_IDS`; version-8 journals decode but are refused by
  `MIN_GUEST_VERSION` (`a_guest_version_8_receipt_is_refused`). Its receipts moved to `fixtures/legacy/0c97a02b/`.
- **Proving run** (one run, temporary GCP VM, 12 vCPU n2, CPU proving, RISC Zero 3.0.6, guest built in the docker guest
  builder): succinct receipt 2,621,116 ms (12 segments, 12,582,912 cycles, 11,143,341 user), Groth16 wrap 147,814 ms (1,817
  bytes), negative matrix 55 of 55 variants panic with no receipt. The proved journal differs from version 8's only in
  `guest_version` (the committed sample input has no session root).

## PCA 0.4.2 (BREAKING: new guest image id `0c97a02b9d6f99131fb1d76207377ccb3546be8b8f6c33387ab078b1d49453a7`, guest version 8)

The guest now enforces the PCA 0.4.1 security fix (root caveats outside the envelope are policy; `max_spend`), the
Intent Layer M2 `intent` binding and Intent Layer v2 (rules 13-19). Image id
`3b1eebb5...fdad` to `0c97a02b9d6f99131fb1d76207377ccb3546be8b8f6c33387ab078b1d49453a7`; `GUEST_VERSION` = `MIN_GUEST_VERSION` = 8.

- **Root caveats are enforced (security).** `decide` evaluates `root_caveats(grant)` (every caveat on the root grant except its
  first `envelope` caveat, = TS `rootCaveats`) with the same caveat context and ANDs it into `allow`, exactly as `policy-vm.ts`
  `decide()`. Unknown types, a second `envelope` caveat and non-object entries are unsatisfied (fail closed); a non-array list
  refuses. The round-6 guest signed off on actions that a root `expires`, `delegation_depth`, `max_spend`, ... caveat forbade.
- **`max_spend {usd}`** (`caveats.rs`): own `action.params.amount` finite and `0 <= amount <= usd`, own `currency` when present
  exactly `"usd"`/`"USD"`; evaluated before the finite-`now` gate (agent-native). New `action_spend_usd`, `policy_caveats`.
- **Intent binding (Intent Layer M2).** A present signed `pcactn.intent` is wire-checked and must open the root grant's goal
  commitment (`intent::bind_intent`, = `intent-binding.ts` rule 2), else deny; the claims go to the journal as
  `context.intent`, and `check_context` applies the relying party's `ExpectedContext::intent_policy` (rules 0, 1, 3, 4).
  `r042_intent.rs` matches the TS reference on 35 wire slots, 3 goal commits and 360 binding x policy combinations.
- **Intent Layer v2 (rules 13-19).** The v2 pipeline (`intent_v2.rs` `decide_intent_v2`, = TS `decideIntentV2`): schema,
  intent_session (incl. revocation epochs), layers (closed and typed), accumulators, map, and the W-B unit (facts,
  provenance, classes), with the strict rules (absent vs null, safe-integer numbers and clock, closed typed policies,
  malformed top-level context fails every reportable check). Journal `context.intent_v2` = {ctx_digest, checks, env};
  `ExpectedContext::intent_v2_ctx_digest` pins the verifier state. `decide_read_purpose` ported.
- **Committed map (V15, rule 19, Z1).** `intent_map.rs`: per-leaf salted Merkle map commitment, cell of omega, the `map`
  check over the agent's disclosure as a private input (`ctx_digest` excludes `map`), goal `pca-intent:v2c:`.
- **Signature suites.** `pq_suites.rs`: ML-DSA-65/87, SLH-DSA-SHA2-128f/256s, hybrids, nested hybrid, FN-DSA-512/1024
  (`fn-dsa-vrfy` 0.4); PQ keys only from trusted-side pins; LESS / unknown algs fail with `unsupported_suite: <alg>`.
  Capability chains bind `alg` / `pq_pk` per hop (`chain.rs`, 153 corpus vectors).
- **Tests:** TS-differential fixtures for every v2 rule (`ts_v2_{schema,session,acc,wb,layers,pipeline}.json`) and the
  shared corpus families (`intent_world`, `intent_provenance`, `intent_classifier`, `intent_wb_active`,
  `intent_read_purpose`, `intent_map_commit`, `intent_map`, `intent_schema`, `intent_revocation`).
- **Verifier:** `3b1eebb5...fdad` joins `SUPERSEDED_IMAGE_IDS`; version-7 journals are refused by `MIN_GUEST_VERSION`. Its
  receipts moved to `fixtures/legacy/3b1eebb5/`.
- **Tests:** `core/tests/r042_root_caveats.rs` (every `primitives.caveat_eval` entry equals the reference; decide denies
  unsatisfied / unknown / second-envelope / unreadable `max_spend` root caveats and still allows satisfied ones; fail-first
  checked by removing the `root_ok` conjunct); verify tests cover the seventh legacy generation.

## Round 6, PCA 0.4.0 release (2026-10-11; BREAKING: new guest image id `3b1eebb5...fdad`, journal gains `guest_version`)

Red-team round 6 (`docs/pca/security/red-team report-round6.md`, R6-ZK-01 to R6-ZK-06). Image id `e922536c...91a8` to
`3b1eebb56b046e737fb15009bdd065b67d7938cb8d47f3f3f0dadc801f84fdad`. The journal (`Decision`) gains a FIRST field `guest_version: u32` (= `GUEST_VERSION` = 7); `context.subject_digest` /
`env_digest` are now the empty string when the document is ABSENT (an explicit `null` hashes as `null`). Verifier API: new
`VerifyError::Superseded`, `SUPERSEDED_IMAGE_IDS`, `is_superseded`, `image_id_hex`; `ContextMismatch::GuestVersion`;
`MIN_GUEST_VERSION`. The round-5 receipts moved to `fixtures/legacy/e922536c/`; they still verify under their own id, and
`verify_with_context` refuses them (and every older generation) with `Superseded` even when that id is pinned.

- **R6-ZK-01 (Medium) a present non-string `ref` is a path, not "absent".** `ref: null` (or a number, bool, object, array) resolves
  to nothing, so the condition is unknown and the predicate denies, as `triLeaf` (`c.ref !== undefined`). It used to fall back to
  `value` (guest allow, TS deny, validly signed).
- **R6-ZK-02 (Low-Medium) mixed leaf/group conditions are groups.** Conditions are evaluated three-valued with `all_of` / `any_of` /
  `not` exactly as `evaluateConditionTri` (`isGroupCondition` precedence, empty or non-array groups unknown, `not` of unknown is
  unknown); the `like` (UTF-16 glob, O(n*m)), `is_a` and `member_of` (bounded reflexive BFS, 10,000 nodes) operators are ported, so
  the guest has no deny-only gaps left in the DSL.
- **R6-ZK-03 (Low-Medium) the reversibility class comes from the signed node.** `action.reversibility_class ?? node.reversibility_class`
  (raw values, `null` falls through like `??`) where the node is the first plan node whose id is `pcactn.plan.node_id`; it was the
  first node with the same verb/resource (a reversible decoy listed first passed `reversibility_max`).
- **Plan binding = TS plan inclusion.** The leaf is `planLeaf(node_id, signed action, conditions_digest ?? default)` with merkle.ts
  `??` defaults and must be a leaf of the committed plan; node leaves use the same `??` (a non-string class / params digest is
  committed as is). A node committing a `params_digest` the action does not carry is now refused (was allowed); a `null`
  `conditions_digest` takes the default (was refused).
- **Envelope = `readEnvelope` + `validateRiskPolicy`.** A missing `goal_commit` / `agent_binding` / `caveats`, a non-array
  `predicates`, a negative weight, a non-finite `lambda` / `rho`, `theta2 < theta1` or `kappa <= 0` now deny (several were allowed).
- **R6-ZK-04/05 (Low, liveness) no deny-only divergences on TS-allowed documents.** `subject` / `env` are no longer held to the
  strict wire profile or the 512 KiB cap (the TS never strict-canonicalizes them); numbers outside the profile compare as the
  doubles `JSON.parse` yields and are hashed with ECMAScript `Number::toString`. `tool_schema` binds `String(signature_digest)` and
  compares the signed `tool_binding` with `!==` against the raw value (a numeric digest without a signed binding is satisfiable, as
  in TS). An array `action.params` is "present" for params-rooted paths (`typeof [] === 'object'`). Conditions see the TS
  `ActionContext.action` (`verb`, `resource`, `params`, `reversibility_class` only); a whole-`action` equality is false when one of
  those is absent (TS `canonicalize` throws on the `undefined` member).
- **Ed25519 points are canonical.** `chain::ed25519_point_strict`: A and R must decompress, RE-ENCODE to the same bytes and be
  torsion-free (dalek's decompression reduced `y` mod p and accepted the `y + p` aliases and a sign bit on `x = 0`).
- **Reproducible image id.** The guest is now built in risc0's docker guest builder (`risczero/risc0-guest-builder:r0.1.97.0`,
  `methods/build.rs`) with `sdks/zkvm-pca` as the context, so source paths are `/src/...`. A host-toolchain build embedded the
  absolute path of `core/` in panic locations: three checkouts of one commit built to three image ids (`/work/pca/...`,
  two job directories). Two docker builds from different directories give the same id. `PCA_ZKVM_LOCAL_BUILD=1` keeps the old
  path-dependent build for development. `host/box-prove.sh` installs docker.io + docker-buildx and keeps temp files off a private
  `/tmp` (the docker Groth16 prover bind-mounts them).
- **R6-ZK-06 (Low/Info) minimum guest version.** See above; `fixtures/` HEAD pins only the image id its source builds to.

Evidence (all validly signed; the chain and PCActn re-minted per case; `core/tests/r6_*.rs`): field-typing matrix 4,792 cases, 0
divergences (round-5 guest: 457); random corpora 3 x 100,000 (seeds 1, 2, 3) on cloud boxes, 0 divergences (round-5 guest: 5,541 on
seed 1); Ed25519 encodings 132, 0 divergences. Proof run on CPU (a 4-core pcaq job on a shared 8-vCPU x86 Azure box): succinct 224530 bytes,
12 segments, 12582912 cycles, 5424 s; Groth16 1801 bytes, 139.4 s; negative matrix 55 variants (the six
former `r5_wire_env_*` negatives are now allowed controls; 13 new `r6_*`), none produced a receipt.

## Round 5 (BREAKING: guest image id `e922536c...91a8`)

Red-team round 5, area (c) (`docs/pca/security/red-team report-round5.md`, R5-ZK-01 to R5-ZK-04). The guest changed, so the image
id changed (`1c1b8bbd...3b95` to `e922536c10e9a003c1c64914d9f11997dbda9e70b2d1294df358bb845f2991a8`). The journal layout and the
verifier API are unchanged. Receipts of the round-4 guest still verify under their own id (`fixtures/legacy/1c1b8bbd/`), decode
as the current journal, and are refused by `verify_with_context` against the current id (`Err(Receipt)`).

- **R5-ZK-01 (Medium) malformed `tool_schema` scalar bounds are unsatisfiable, never defaulted.** `spec_error` now validates
  `minLength`, `maxLength` (non-negative integer <= 1 MiB), `prefix` (string <= 512 UTF-16 units), `min`/`max` (finite),
  `minItems`/`maxItems` (non-negative integer <= 4096) and the `min <= max` orderings exactly like `validateArgSchema`;
  `check_value` denies a malformed bound instead of `.and_then(as_u64)` + default. Numbers follow JavaScript: one number type
  (`1.0` is an integer, `===` on scalars compares by value), an integer above 2^53-1 in a schema is outside the strict profile
  so `hashCanonical(schema)` throws in TS and the caveat is unsatisfied here too. 1,236 of 24,000 PoC cases were guest-allow /
  TS-deny; now 0.
- **R5-ZK-02 (Low-Medium) lengths count UTF-16 code units.** `maxLength`, `minLength`, the 1024-unit `enum`/`const` string cap and
  the 512-unit `prefix` cap use `str::encode_utf16().count()` like `String.prototype.length`.
- **R5-ZK-03 (Low-Medium) strict wire limits are enforced in-guest** (`decide` refuses before evaluating anything, `allow = 0`,
  hence unprovable): every document (grant, action, plan, chain, subject, env, PCActn) must be <= 524,288 bytes of compact JSON
  (`MAX_ARTIFACT_BYTES`), pass the strict canonical profile of `canonicalizeStrict` (integers within +-(2^53-1), no `-0`, no
  non-integer below 1e-6 or above 15 significant digits, container nesting <= 32), and the chain must respect 256 caveats per hop /
  1024 per chain (`caveatLimitExceeded`). Because the guest receives parsed values, "exponent floats" are judged on the parsed
  double exactly as `JSON.parse` would give it (`1e2` is the safe integer 100; `1e-7` and `1e300` are refused). `serde_json` is
  built with `float_roundtrip` so parsing is correctly rounded like V8. A `tool_schema` whose schema is outside the profile is
  unsatisfied (TS: `hashCanonical` throws).
- **R5-ZK-04 (Medium-Low) `matches` is evaluated and charged to the document regex budget.** `predicates.rs` ports the `matches`
  condition (both operands strings, source <= 200 and subject <= 512 UTF-16 units, `isSafeRegexSource`, `chargeRegex`, linear-time
  match), sharing ONE budget (64 evaluations, 8192 source units, 5,000,000 steps, poisoned scope) with `re:` resources across the
  envelope predicates and every caveat, as `decide` does in TS. `like`, `is_a`, `member_of` and `all_of`/`any_of`/`not` groups are
  still not ported (they are not-true, the fail-closed direction; Part A's constitution scoping has no guest counterpart because the
  guest has no constitution).
- Existing tests that encoded the old permissive behaviour were corrected (`unit_kill_policy_vm.rs`: an out-of-range `maxLength`
  is malformed, not clamped; `1.0` is an integer; an integer above 2^53-1 in a schema is refused).
- Tests: `core/tests/r5_tool_schema_random.rs` (golden `fixtures/ts_tool_schema_random.json`, 4,800 cases, from
  `gen_ts_tool_schema_random.ts`), `core/tests/r5_wire_limits.rs` (golden `fixtures/ts_wire_cases.json`, from
  `gen_ts_wire_cases.ts`: 3,194 canonical-profile values with exact canonical bytes, the wire constants, 471 `matches` / budget
  documents), 28 more `tool_schema` golden cases in `fixtures/ts_tool_schema_cases.json` (67 total), unit tests for every bound,
  UTF-16 lengths, caveat caps, the 512 KiB boundary (524,288 admitted, 524,289 refused), `verify/tests/legacy_and_default_fixtures.rs`
  and `context_pinning.rs` for the new legacy id. The negative proving matrix grows from 34 to 48 variants (all validly signed, so
  only the new check can be the cause): `r5_01_*` (5, malformed bounds / min above max in a delegated `tool_schema`),
  `r5_03_delegated_unsafe_integer_in_schema`, `r5_wire_env_*` (6: unsafe integer, `-0`, 1e-7, over-precise float, nesting 33, over
  512 KiB), `r5_cap_257_caveats_on_one_hop`, `r5_04_delegated_matches_budget_poison`; `core/tests/support/chain_mint.rs` also
  carries `r5_controls` (just-inside-the-limit inputs that must be ALLOWED, so the refusals are not over-broad).
- Differential run (cloud box cloud-box-18, x86_64), TS reference vs the guest's own code: 200,000 random `tool_schema` cases (25,000
  schemas x 4 argument sets, seeds 7 and 11, 18,313 satisfied) + the 24,000 round-5 PoC cases (3,585 satisfied) + 100,194 random
  canonical-profile values (68,558 admitted, exact canonical bytes compared) + 471 `matches`/budget documents: 0 divergences
  (before: 1,236 of 24,000). Results: `redteam/round5/zk/r5-fix.result.txt`.
- Receipts regenerated on CPU (PCA cloud farm box cloud-box-21, 8 vCPU x86_64 Ubuntu 24.04, shared with other jobs: load average 8-14, so
  the wall time is not comparable to earlier runs): succinct 224522 bytes, 12 segments, 12058624 total / 10630339 user cycles,
  4231.4 s; Groth16 1793 bytes (256-byte seal), wrap 192.5 s; 48 of 48 negative variants produced no receipt. The round-4
  receipts moved to `fixtures/legacy/1c1b8bbd/`.

## Round 4 (BREAKING: new guest image id, journal layout and verifier API)

Red-team round 4 (`docs/pca/security/red-team report-round4.md`, R4-02 to R4-04, plus the R4-05 document regex budget
mirrored from the TypeScript reference). The guest changed, so the image id changed (`ce0b5423...cf1b` to
`1c1b8bbd...3b95`). Receipts of the round-3 guest still verify under their own id (`fixtures/legacy/ce0b5423/`), do not decode
as the current journal, and are refused by `verify_with_context` against the current id.

- **R4-02 (Medium) the guest evaluates `re:` patterns with the SAME engine as the TypeScript reference.** The Rust
  `regex` crate (Unicode `\d \w \s`, `.` excluding only `\n`, `\b`, `(?i)`, `\p{L}`, `[[:alpha:]]`, nested quantifiers) is gone
  (dependency removed). `core/src/safe_regex.rs` is a line-by-line port of `isSafeRegexSource` (predicates.ts) and of
  the R3-02 parser / Thompson NFA / Pike simulation (safe-regex.ts): JavaScript flagless semantics over UTF-16 code
  units, the same supported subset, the same refusals (a pattern outside the subset does not match), the same limits
  (200-unit source, 512-unit subject, 4096 instructions, `{n,m}` <= 64, 22-bit cost budget, <= 3 unbounded quantifiers,
  2,000,000 steps per match) and the R4-05 per-document budget (64 evaluations, 8192 source units, 5,000,000 NFA steps,
  poisoned scope), opened by `decide`, `evaluate_predicates`, `evaluate_caveats` and `predicate_matches` exactly like the
  TS `withRegexBudget` scopes. One deliberate fail-closed difference: parser nesting is capped at 256 groups (TS relies on
  its stack); a 200-unit source cannot reach it legitimately.
- **R4-03 (Medium) `tool_schema` fails closed.** `evaluate_tool_schema` returns `Result<(), String>`; a missing or
  mistyped `tool`, `schema`, `schema_digest`, `signature_digest`, `binding_digest`, a schema that is not an object, no
  call context (no tool / arguments that are not an object) and every internal lookup that used to `?`-return `None`
  (read as "satisfied") are now unsatisfied. `signature_digest` must be a string (TS `String(undefined)` would accept
  the literal `"undefined"`; the guest is stricter, which is the fail-closed direction).
- **R4-04 (Medium) the journal commits the PCActn's own facts and the verifier must pin them.** `Context` gains
  `pcactn_ver`, `pcactn_iat`, `pcactn_exp`, `pcactn_aud`, `pcactn_counter`. `bind_pcactn` now requires, all mandatory and
  strictly typed (safe integers, no floats/strings/defaults): `ver == 2`, a non-empty `aud` of at most 256 UTF-8 bytes,
  `counter >= 0`, `iat < exp <= iat + 3,600,000`, `iat <= now + 60,000`, `now <= exp` (`now` must be a safe integer), i.e.
  `verifyPCActnCore`'s `version`, `audience`, `validity` and `counter` rules.
  `ExpectedContext` gains the mandatory `pcactn_ver`, `pcactn_iat`, `pcactn_exp`, `pcactn_aud`, `pcactn_counter` (no
  "any audience" default; `from_input_json` returns `None` for a PCActn without well-formed facts). `check_context` compares
  each and additionally evaluates the window against the VERIFIER's clock (`ContextMismatch::PcactnVersion`, `PcactnAud`,
  `PcactnIat`, `PcactnExp`, `PcactnCounter`, `PcactnLifetime`, `PcactnNotYetValid`, `PcactnExpired`), so a genuine receipt
  proven at an honest `now` is refused once the verifier's clock is past `exp`. Counter monotonicity against stored state
  stays the resource server's job; the journal carries the value so it can be checked there.
- Not done (still open, see README "What is not validated"): the strict wire form of `validateWireV2` (canonical numbers,
  256/1024 caveat caps, 512 KiB cap) is not enforced in-guest; the guest still has no `matches`, `like`, `is_a` or boolean
  condition groupings (they evaluate false, the fail-closed direction).
- Tests (all failing before the fix; every denied input has VALID signatures so only the new check can be the cause):
  `core/tests/r4_regex_differential.rs` (7207 golden cases from the TS reference: the 17 PoC cases, a hand corpus, generated
  pattern x subject pairs, 27 whole-document budget cases) and the 100k run below; `core/tests/r4_tool_schema_fail_closed.rs`
  (the 6 PoC cases + 32 more against TS); `core/tests/r4_pcactn_freshness.rs` (denials, boundaries, journal, 308 rows
  of TS `verifyPCActnCore` verdicts, verifier-side pinning); `verify/tests/context_pinning.rs` (real receipts);
  the negative proving matrix grows from 25 to 34 variants (`r4_03_*`, `r4_04_*` in `core/tests/support/chain_mint.rs`).
  TS generators: `core/tests/gen_ts_regex_cases.ts`, `gen_ts_tool_schema_cases.ts`, `gen_ts_pcactn_freshness.ts`.
- Differential run (cloud box, x86_64): 373,748 pattern x subject cases generated from 160,000 random patterns (seeds 7 and 13, 70,464 + 42,931 distinct patterns, 122,344 allow / 251,404 deny) against the TS reference, 0 divergences (`redteam/round4/zk/differential-100k.result.txt`); the PoC harnesses now report 0/17 and 0/6 divergences.
- Receipts regenerated on CPU (PCA cloud farm box cloud-box-21, 8 vCPU x86_64 Ubuntu 24.04, exclusive lease, no GPU): succinct 224522 bytes, 11 segments, 11534336 total / 10375868 user cycles, 2957.3 s; Groth16 1793 bytes
  (256-byte seal), wrap 187.8 s. Full id `1c1b8bbd531c5f3c93debfa41350b9a5e5c2478959ae2c0994c12de505933b95`. The round-3 receipts moved to `fixtures/legacy/ce0b5423/`.

## Round 3 (BREAKING: new guest image id, journal layout and verifier behaviour)

Red-team round 3 (`docs/pca/security/red-team report-round3.md`, R3-11 to R3-14). The guest changed, so the image id
changed (`6b0ac893...97cc` to `ce0b5423...cf1b`). Receipts of earlier guests still verify under their own ids
(`fixtures/legacy/`), decode only as `LegacyDecision` or the previous layout, and are refused by
`verify_with_context` against the current id.

- **R3-11 (High) delegated caveats are evaluated.** The guest used to evaluate only the root envelope's caveats;
  caveats appended by delegation hops were neither evaluated nor committed, so a delegatee escaped its delegator's
  narrowing. It now also evaluates every caveat the chain appended to the root (`chain.last.caveats` beyond the
  root's), exactly like the TypeScript `decide`. `verify_hops` already proves each hop's caveat list is an exact
  prefix of the next, so this is the intersection of all constraints along the chain. An unknown delegated caveat
  type fails closed.
- **R3-12 (High) delegation depth is derived.** `DecideInput.delegation_depth` is removed (a stray key in the input
  JSON is ignored). The depth fed to the `delegation_depth` caveat is `chain.len() - 1`, and the journal commits it as
  `context.delegation_depth` (a `u64`, replacing `delegation_depth_bits: Option<u64>`).
- **R3-13 (Medium) the PCActn is bound to the chain, action and plan.** New `bind_pcactn` (fail closed): the signed
  `pcactn.grant_ref` equals `chain[0].id`; `pcactn.cap_chain` equals the verified chain; `pcactn.action` equals the
  evaluated `action`; `pcactn.plan.root` equals the plan root recomputed in-guest; `pcactn.plan.node_id` names a node of
  that plan (and equals `node_id` when also supplied) whose verb, resource, reversibility class, params digest (when
  present) and conditions digest match; the signed `tool_binding` equals the `tool_binding` the `tool_schema` caveat
  compared against. The journal commits `context.grant_ref` and `context.node_id` next to the existing `action_commit`,
  `plan_commit`, `policy_commit`.
  Fixture note: the minted PCActn now carries the signed `tool_binding` slot (the sample input always supplied one).
- **R3-14 (Medium) fake receipts are refused.** `pca_zkvm_verify::verify_with_context` accepts only
  `InnerReceipt::Succinct` and `InnerReceipt::Groth16`; `Fake` (dev mode) and every other kind return
  `VerifyError::Receipt`. Verification runs under `VerifierContext::default().with_dev_mode(false)`, so the
  `RISC0_DEV_MODE` environment variable is never consulted, whatever features the dependency graph unifies.
- API: `ExpectedContext` gains `grant_ref: String`, `node_id: String`, and `delegation_depth` is a `u64` (the derived
  depth); `ContextMismatch` gains `GrantRef`, `NodeId`. `Decision.context` fields change accordingly (journal layout).
- Tests (failing before the fix, all denied inputs carry VALID signatures so only the new check can be the cause):
  `core/tests/r3_delegation_binding.rs`, the R3 variants in `core/tests/negative_causes.rs`, `verify/tests/dev_mode_fake_receipt.rs`,
  context-pinning cases for depth, grant_ref and node_id. The negative proving matrix grows from 16 to 25 variants.
- Receipts regenerated on CPU (Azure Standard_D8s_v6, 8 vCPU): succinct 224418 bytes, 12 segments, 12058624 cycles, 5386.9 s; Groth16 1689 bytes (256-byte seal), wrap 264.5 s. Full id `ce0b542313a11e4863661d921157f95e61df18a919c97eea92641bba8699cf1b`. The pre-R3 receipts moved to `fixtures/legacy/6b0ac893/`.
