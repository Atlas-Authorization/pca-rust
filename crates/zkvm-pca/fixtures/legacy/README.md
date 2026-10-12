Receipts of the EARLIER guest build (image id `ac95031f...96e3`), kept only to show that they still verify under
their own id and not under the current one. That guest accepted a mixed-order delegator key that the reference
implementation rejects. Do not pin these; the files directly under `fixtures/` (`image_id.json`,
`receipt_succinct.bin`, `receipt_groth16.bin`) belong to the current guest (`dcf198fc...813a`) and are byte-identical
to `fixtures/proof_run/`.

The next generation (`dcf198fc...813a`, torsion-fixed, journal still without context) is under `legacy/dcf198fc/`. The current guest (`6b0ac893...97cc`) commits the evaluated context (RT-06); `fixtures/` top level and `fixtures/proof_run/` belong to it.

The guest before red-team round 3 (`6b0ac893...97cc`, context-committing, but evaluating only root caveats, with a prover-supplied depth and an unbound PCActn) is under `legacy/6b0ac893/`. The current guest (`ce0b5423...cf1b`) is the one in `fixtures/` top level and `fixtures/proof_run/`.

The round-3 guest (`ce0b5423...cf1b`: `regex`-crate `re:` matcher, fail-open `tool_schema`, no PCActn freshness facts in the journal) is under `legacy/ce0b5423/`. The current guest (`1c1b8bbd...3b95`) is the one in `fixtures/` top level and `fixtures/proof_run/`.

The round-4 guest (`1c1b8bbd...3b95`: tool_schema drops malformed bounds, code-point lengths, no `matches` budget, no in-guest wire limits) is under `legacy/1c1b8bbd/`. The current guest (`e922536c...91a8`) is the one in `fixtures/` top level and `fixtures/proof_run/`.

The round-5 guest (`e922536c...91a8`: a non-string `ref` read as absent, leaf+group mixes evaluated as leaves, the plan node chosen by verb/resource, no `readEnvelope` checks, `env`/`subject` held to the wire profile, non-canonical Ed25519 encodings decoded) is under `legacy/e922536c/`. The current guest (`3b1eebb56b046e737fb15009bdd065b67d7938cb8d47f3f3f0dadc801f84fdad`) is the one in `fixtures/` top level and `fixtures/proof_run/`. Every image id under `legacy/` is on the verifier deny-list (`pca_zkvm_verify::SUPERSEDED_IMAGE_IDS`): `verify_with_context` refuses those receipts even when their id is pinned.
