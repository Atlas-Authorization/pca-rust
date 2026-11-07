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

The round-6 guest (`3b1eebb56b046e737fb15009bdd065b67d7938cb8d47f3f3f0dadc801f84fdad`, guest version 7: caveats on the root grant outside the `envelope` caveat were not evaluated and `max_spend` was an unknown type, the PCA 0.4.1 security fix) is under `legacy/3b1eebb5/`. Version-7 journals are refused by `MIN_GUEST_VERSION`, and the `3b1eebb5` id is on the deny-list.

The PCA 0.4.2 guest (`0c97a02b9d6f99131fb1d76207377ccb3546be8b8f6c33387ab078b1d49453a7`, guest version 8: a pure-PQ / hybrid session root verified under the PQ key named in its own `principals[]` entry instead of the verifier's pin, R3-01) is under `legacy/0c97a02b/`. Version-8 journals have the current layout and decode, but `MIN_GUEST_VERSION` (now 10) refuses them, and the `0c97a02b` id is on the deny-list.

The guest-version-9 build (`c5107456f3885cfe87f0da62d24aa273e1fe94c982eed57324374dcefa80ac39`: `intent_v2_active` did not report a present malformed v2 context) is under `legacy/c5107456/`. The current guest (guest version 10, `432b4713d7981afc30907003d3a2c7e7d0003cc34b2367b4cba8d61b642c0060`) is the one in `fixtures/` top level and `fixtures/proof_run/`. Version-9 journals have the current layout and decode, but `MIN_GUEST_VERSION` (10) refuses them, and the `c5107456` id is on the deny-list.

The guest-version-10 build (`432b4713d7981afc30907003d3a2c7e7d0003cc34b2367b4cba8d61b642c0060`: no rule 22, refuses every version 2 action schema) is under `legacy/432b4713/`. The current guest (guest version 11, `6bb6b7d5e66671fb314eaa5018e04463346374ced15df7bc784815cb95de1f6e`) is the one in `fixtures/` top level and `fixtures/proof_run/`. Version-10 journals decode but `MIN_GUEST_VERSION` (11) refuses them, and the `432b4713` id is on the deny-list.
