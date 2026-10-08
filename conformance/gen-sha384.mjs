// Generates conformance/sha384-vectors.json: golden vectors for the OPTIONAL SHA-384 hash suite (P4).
//
//   pnpm --filter @atlasauth/pca build && node packages/pca/conformance/gen-sha384.mjs
//
// This is a DEDICATED corpus file. The shared PCActn corpus (conformance/vectors.json) is UNCHANGED and
// remains entirely sha256 — SHA-384 is an opt-in margin/agility variant, never the implicit default, so it
// is not spliced into the corpus the language SDK verifiers consume by default. Each vector's stated intent
// is asserted against the TypeScript reference (hashCanonical / merkleRoot / merkleProof / verifyInclusion)
// BEFORE it is written, so a reference bug can never silently become a golden vector. Every digest here is
// deterministic (SHA-384 over a fixed canonical input), so the file is byte-reproducible across runs.
//
// HONEST RATIONALE: SHA-256 is already post-quantum adequate (Grover => ~2^128 preimage, BHT => ~2^128
// collision). SHA-384 is a larger-margin OPTION (~2^192 under the same models), NOT a fix for a SHA-256
// weakness. The two suites are mutually FAIL-CLOSED: a proof built under one never verifies under the other.
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as pca from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const outPath = join(here, 'sha384-vectors.json');

const SUITE = 'sha384';
const DEFAULT = 'sha256';

// ---- canonical-digest vectors: SAME canonical bytes as the sha256 corpus, hashed under sha384 ----
// Reusing the exact `primitives.canonical` values from gen-conformance.mjs demonstrates that the canonical
// SERIALIZATION is suite-independent and only the DIGEST changes (and is distinct from the sha256 digest).
const canonicalValues = [
  { b: 1, a: [true, null, 'x'], c: { z: 1, y: 2 } },
  { '～': 1, '\u{1F600}': 2 },
  { s: 'café <&> "q" \\ \n \u0001   \u007f' },
  { n: [0, -1, 1.5, 100000, 0.1, -0.25, 9007199254740991] },
  { '': 1, a: { '': 2 }, 'a\u0000': 3, aa: 4 },
];
const canonical = canonicalValues.map((value) => {
  const expect = pca.canonicalizeStrict(value); // suite-independent canonical JSON text
  const hash = pca.hashCanonical(value, SUITE); // base64url(sha384(canonical))
  const sha256Hash = pca.hashCanonical(value); // default suite, for the distinctness assertion
  // Assert the stated intent against the reference before writing.
  if (pca.hashCanonical(value, DEFAULT) !== sha256Hash) throw new Error('canonical: sha256 default drifted');
  if (hash === sha256Hash) throw new Error(`canonical: sha384 digest not distinct from sha256 for ${expect}`);
  if (pca.b64u(pca.unb64u(hash)).length !== hash.length || pca.unb64u(hash).length !== 48) {
    throw new Error(`canonical: sha384 digest is not 48 bytes for ${expect}`);
  }
  // Reproducible: recomputing yields the same digest.
  if (pca.hashCanonical(value, SUITE) !== hash) throw new Error('canonical: sha384 digest not reproducible');
  return { value, suite: SUITE, expect, hash, sha256_hash: sha256Hash };
});

// ---- Merkle vectors: a full tree + an inclusion proof for every leaf, under sha384 ----
const merkle = [3, 5, 7].map((n) => {
  const leaves = Array.from({ length: n }, (_, i) => ({ i, t: 'leaf' }));
  const root = pca.merkleRoot(leaves, SUITE);
  const sha256Root = pca.merkleRoot(leaves); // same leaves, default suite
  const proofs = leaves.map((_, i) => pca.merkleProof(leaves, i, SUITE));
  const sha256Proofs = leaves.map((_, i) => pca.merkleProof(leaves, i));

  if (root === sha256Root) throw new Error(`merkle(${n}): sha384 root not distinct from sha256 root`);
  if (pca.unb64u(root).length !== 48) throw new Error(`merkle(${n}): sha384 root is not 48 bytes`);
  if (pca.merkleRoot(leaves, SUITE) !== root) throw new Error(`merkle(${n}): sha384 root not reproducible`);

  for (let i = 0; i < n; i++) {
    const p = proofs[i];
    if (p.hash_suite !== SUITE) throw new Error(`merkle(${n}): proof[${i}] is not self-describing (hash_suite)`);
    // sha384 siblings are 48 bytes.
    for (const step of p.path) if (pca.unb64u(step.hash).length !== 48) throw new Error(`merkle(${n}): sibling not 48 bytes`);
    // Positive: the sha384 proof verifies against the sha384 root.
    if (!pca.verifyInclusion(root, p, leaves[i])) throw new Error(`merkle(${n}): sha384 proof[${i}] did not verify`);
    // FAIL-CLOSED cross-suite:
    //  (a) a sha384 proof MUST NOT verify against the sha256 root.
    if (pca.verifyInclusion(sha256Root, p, leaves[i])) throw new Error(`merkle(${n}): sha384 proof[${i}] verified as sha256 root!`);
    //  (b) a sha256 proof MUST NOT verify against the sha384 root.
    if (pca.verifyInclusion(root, sha256Proofs[i], leaves[i])) throw new Error(`merkle(${n}): sha256 proof[${i}] verified as sha384 root!`);
    //  (c) stripping the hash_suite tag (=> read as sha256) MUST fail (48-byte siblings fail the 32-byte decode).
    const stripped = { index: p.index, size: p.size, path: p.path };
    if (pca.verifyInclusion(root, stripped, leaves[i])) throw new Error(`merkle(${n}): hash_suite-stripped sha384 proof[${i}] still verified!`);
    //  (d) mislabeling a sha256 proof as sha384 MUST fail (32-byte siblings fail the 48-byte decode).
    const mislabeled = { ...sha256Proofs[i], hash_suite: SUITE };
    if (pca.verifyInclusion(sha256Root, mislabeled, leaves[i])) throw new Error(`merkle(${n}): sha256 proof mislabeled sha384 still verified!`);
    //  (e) an unknown hash_suite value MUST fail closed.
    const bogus = { ...p, hash_suite: 'sha512' };
    if (pca.verifyInclusion(root, bogus, leaves[i])) throw new Error(`merkle(${n}): unknown hash_suite verified!`);
  }

  return { n, leaves, suite: SUITE, root, sha256_root: sha256Root, proofs, sha256_proofs: sha256Proofs };
});

const corpus = {
  format: 1,
  suite: SUITE,
  default_hash_suite: DEFAULT,
  description:
    'Optional SHA-384 hash-suite (P4) golden vectors for canonical digests and the Merkle tree. Non-breaking: ' +
    'the sha256 default is unchanged; sha384 is opt-in margin/agility (NOT a SHA-256 fix). The two suites are ' +
    'mutually fail-closed — a proof built under one never verifies under the other. hash_suite ABSENT => sha256.',
  hash_len_bytes: 48,
  primitives: { canonical, merkle },
};

writeFileSync(outPath, JSON.stringify(corpus, null, 2) + '\n');
const proofCount = merkle.reduce((s, m) => s + m.proofs.length, 0);
console.log(`wrote ${canonical.length} canonical + ${merkle.length} merkle (${proofCount} sha384 inclusion proofs) vectors to ${outPath}`);
