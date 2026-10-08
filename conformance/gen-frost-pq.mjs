// Generates conformance/frost-pq-vectors.json: golden + adversarial vectors for the HYBRID PQ FROST
// guardian-quorum co-sign (packages/pca/src/frost-pq.ts). This is a DEDICATED corpus file — the hybrid
// FROST co-sign is a PCA-internal guardian primitive, not a PCActn, so it is NOT spliced into the shared
// PCActn corpus (conformance/vectors.json) that the language SDK verifiers consume.
//
//   pnpm --filter @atlasauth/pca build && node packages/pca/conformance/gen-frost-pq.mjs
//
// Each vector's stated intent is asserted against the TypeScript reference (verifyHybridFrostCosign) BEFORE
// it is written, so a reference bug can never silently become a golden vector. The FROST Ed25519 aggregate
// uses FRESH nonces per run (nonce secrecy forbids reuse), so the `sig` bytes are not byte-reproducible
// across regenerations; every emitted vector is nonetheless a VALID witness of its stated verdict, and the
// companion test (frost-pq.test.ts) re-verifies the committed file against the live reference. The group key
// and the guardian ML-DSA material are fixed/deterministic.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { b64u, unb64u, utf8, frostTrustedDealerKeygen, mlDsa65Keygen } from '../dist/index.js';
// frost-pq is a PCA-internal guardian primitive (not re-exported from index); import it by path.
import { signHybridFrostCosign, verifyHybridFrostCosign } from '../dist/frost-pq.js';

const here = dirname(fileURLToPath(import.meta.url));
const outPath = join(here, 'frost-pq-vectors.json');

const HYBRID = 'hybrid-ed25519-ml-dsa-65';
const MSG = utf8('atlas-pca/frost-pq-conformance/threshold-message');

const fromHex = (h) => {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
};

// Deterministic 2-of-3 FROST group (RFC 9591 Appendix secret/coefficient) — the group PUBLIC key is fixed.
const kg = frostTrustedDealerKeygen(2, 3, {
  secret: fromHex('7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304'),
  coefficients: [fromHex('178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204')],
});
const groupPublicKey = kg.groupPublicKey;
const groupPublicKeyB64u = b64u(groupPublicKey);
const quorum = [kg.participantShares[0], kg.participantShares[2]]; // participants 1 and 3
const signerSet = quorum.map((p) => p.identifier);

// Deterministic guardian ML-DSA-65 key.
const guardianSeed = new Uint8Array(32);
for (let i = 0; i < 'guardian'.length; i++) guardianSeed[i] = 'guardian'.charCodeAt(i);
const guardian = mlDsa65Keygen(guardianSeed);
const guardianPq = b64u(guardian.publicKey);

const flipByte = (b64, idx = 0) => {
  const bytes = unb64u(b64);
  bytes[idx] ^= 0x01;
  return b64u(bytes);
};

const vectors = [];
function add(name, cls, description, { artifact, signerSet: sSet, guardianPqPublicKey, expectGroupAlg }, want) {
  const opts = {};
  if (guardianPqPublicKey !== undefined) opts.guardianPqPublicKey = guardianPqPublicKey;
  if (expectGroupAlg !== undefined) opts.expectGroupAlg = expectGroupAlg;
  const v = verifyHybridFrostCosign(artifact, MSG, groupPublicKeyB64u, sSet, opts);
  if (v.ok !== want.ok) throw new Error(`vector ${name}: reference ok=${v.ok} != intended ok=${want.ok} (${v.reason ?? ''})`);
  if (want.edOk !== undefined && v.edOk !== want.edOk) throw new Error(`vector ${name}: edOk=${v.edOk} != ${want.edOk}`);
  if (want.pqOk !== undefined && v.pqOk !== want.pqOk) throw new Error(`vector ${name}: pqOk=${v.pqOk} != ${want.pqOk}`);
  const expect = { ok: v.ok, edOk: v.edOk, pqOk: v.pqOk };
  if (v.groupAlg !== undefined) expect.groupAlg = v.groupAlg;
  vectors.push({
    name,
    class: cls,
    description,
    message: b64u(MSG),
    group_public_key: groupPublicKeyB64u,
    signer_set: sSet,
    ...(guardianPqPublicKey !== undefined ? { guardian_pq_public_key: guardianPqPublicKey } : {}),
    ...(expectGroupAlg !== undefined ? { expect_group_alg: expectGroupAlg } : {}),
    artifact,
    expect,
  });
}

// --- classical ed25519 (back-compat) ---
const edArt = signHybridFrostCosign(groupPublicKey, quorum, MSG);
add('frost-pq-ed25519-valid', 'positive',
  'Classical FROST aggregate only (groupAlg absent => ed25519). The artifact is just { sig }: a plain Ed25519 Schnorr group signature under the group key. Verifies with the Ed25519 check alone (back-compat).',
  { artifact: edArt, signerSet },
  { ok: true, edOk: true, pqOk: false });

{
  const bad = { ...edArt, sig: flipByte(edArt.sig) };
  add('frost-pq-ed25519-tampered-sig', 'negative',
    'ed25519 artifact with a corrupted FROST aggregate: the Ed25519 group signature no longer verifies => deny.',
    { artifact: bad, signerSet },
    { ok: false, edOk: false, pqOk: false });
}

// --- hybrid ed25519 + ML-DSA-65 ---
const hyArt = signHybridFrostCosign(groupPublicKey, quorum, MSG, { groupAlg: HYBRID, guardianMlDsa: guardian });
add('frost-pq-hybrid-valid', 'positive',
  'Hybrid co-sign: the FROST Ed25519 aggregate AND the guardian ML-DSA-65 co-signature over the context-bound representative BOTH verify => allow. A quantum adversary must break BOTH primitives.',
  { artifact: hyArt, signerSet, guardianPqPublicKey: guardianPq },
  { ok: true, edOk: true, pqOk: true });

add('frost-pq-hybrid-tampered-ed', 'negative',
  'Hybrid co-sign with a corrupted Ed25519 half (the ML-DSA half still valid): fail-closed hybrid requires BOTH => deny.',
  { artifact: { ...hyArt, sig: flipByte(hyArt.sig) }, signerSet, guardianPqPublicKey: guardianPq },
  { ok: false, edOk: false, pqOk: true });

add('frost-pq-hybrid-tampered-pq', 'negative',
  'Hybrid co-sign with a corrupted ML-DSA-65 half (the Ed25519 half still valid): fail-closed hybrid requires BOTH => deny.',
  { artifact: { ...hyArt, pq_sig: flipByte(hyArt.pq_sig) }, signerSet, guardianPqPublicKey: guardianPq },
  { ok: false, edOk: true, pqOk: false });

add('frost-pq-hybrid-missing-pqsig', 'negative',
  'Hybrid groupAlg DECLARED but the guardian ML-DSA co-signature is absent (stripped): deny — there is no silent downgrade to the classical half (analogous to pq-hybrid-missing-pqsig on the leaf).',
  { artifact: { sig: hyArt.sig, groupAlg: HYBRID, pq_pk: hyArt.pq_pk }, signerSet, guardianPqPublicKey: guardianPq },
  { ok: false });

add('frost-pq-hybrid-wrong-signer-set', 'negative',
  'Hybrid co-sign verified under a DIFFERENT quorum ([1,2]) than the one bound at signing ([1,3]): the representative differs so the ML-DSA half fails => deny.',
  { artifact: hyArt, signerSet: [1, 2], guardianPqPublicKey: guardianPq },
  { ok: false, edOk: true, pqOk: false });

add('frost-pq-hybrid-no-registered-key', 'negative',
  'Hybrid co-sign but the verifier is given NO registered guardian ML-DSA key: the co-sign cannot be verified on a self-asserted pq_pk => deny.',
  { artifact: hyArt, signerSet },
  { ok: false });

add('frost-pq-hybrid-downgrade-pinned', 'negative',
  'A classical ed25519-only artifact presented where the verifier PINS expectGroupAlg=hybrid: deny (fail-closed downgrade guard — a caller that knows the guardian runs hybrid refuses the classical-only artifact).',
  { artifact: edArt, signerSet, guardianPqPublicKey: guardianPq, expectGroupAlg: HYBRID },
  { ok: false });

const corpus = {
  format: 1,
  suite: 'frost-pq-hybrid-guardian-cosign',
  description: 'Hybrid PQ FROST guardian-quorum co-sign (ed25519 FROST aggregate + ML-DSA-65 guardian co-sign). Fail-closed hybrid: BOTH halves must verify. groupAlg absent == ed25519 (classical back-compat).',
  group_alg_default: 'ed25519',
  primitives: {
    cosign_domain: 'atlas-pca/frost-pq-cosign/v1\u0000',
    signer_set_domain: 'atlas-pca/frost-signer-set/v1\u0000',
    representative: 'cosign_domain || groupAlg || 0x00 || groupPublicKey(32) || sha256(message) || sha256(signer_set_domain || canonical(sorted-distinct ids))',
    ml_dsa_65_public_key_bytes: 1952,
    ml_dsa_65_signature_bytes: 3309,
  },
  vectors,
};

writeFileSync(outPath, JSON.stringify(corpus, null, 2) + '\n');
console.log(`wrote ${vectors.length} frost-pq vectors (${vectors.filter((v) => v.class === 'positive').length} positive, ${vectors.filter((v) => v.class === 'negative').length} negative) to ${outPath}`);
