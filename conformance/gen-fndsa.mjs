// Generates conformance/fndsa-vectors.json: golden + adversarial vectors for the FN-DSA (Falcon, FIPS 206)
// pure-PQ signature suites (fn-dsa-512 / fn-dsa-1024) registered in packages/pca/src/pq.ts.
//
//   pnpm --filter @atlasauth/pca build && node packages/pca/conformance/gen-fndsa.mjs
//
// This is a DEDICATED corpus file. The shared PCActn corpus (conformance/vectors.json) is UNCHANGED —
// FN-DSA is an opt-in beyond-core suite whose verification routes through the @atlasauth/pca-fndsa-wasm
// binding (the vetted pure-Rust `fn-dsa` crate by Thomas Pornin, the Falcon author) and is NOT yet in the
// 9 native-verifier SDKs, so it is never spliced into the corpus those SDKs consume by default.
//
// Each vector's stated intent is asserted against the TypeScript reference (verifyLeafSuite — the suite
// dispatch — and validateSignatureWire) BEFORE it is written, so a reference bug can never silently become
// a golden vector. FN-DSA keygen and signing are deterministic (SHAKE256-seeded), so every digest/signature
// here is byte-reproducible across runs.
//
// HONEST STATUS: FIPS 206 is finalized-pending; the `fn-dsa` crate warns its encodings may change before
// 1.0. VERIFICATION is the public-key operation the PCA verifier performs. The suites are PURE-PQ
// (non-hybrid) LATTICE signatures: `sig` carries the FN-DSA signature, `pq_pk` the verifying key, no `pq_sig`.
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  b64u,
  unb64u,
  utf8,
  fnDsa512Keygen,
  fnDsa1024Keygen,
  fnDsa512Sign,
  fnDsa1024Sign,
  verifyLeafSuite,
  validateSignatureWire,
  FN_DSA_512_PUBLIC_KEY_BYTES,
  FN_DSA_512_SIGNATURE_BYTES,
  FN_DSA_1024_PUBLIC_KEY_BYTES,
  FN_DSA_1024_SIGNATURE_BYTES,
} from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const outPath = join(here, 'fndsa-vectors.json');

const MSG = utf8('atlas-pca/fndsa-conformance/falcon-leaf-message');

// Deterministic seeds (distinct per variant) so keys + signatures are byte-reproducible.
const seed = (label) => {
  const s = new Uint8Array(32);
  for (let i = 0; i < label.length && i < 32; i++) s[i] = label.charCodeAt(i);
  return s;
};

// A b64u byte-flip (keeps canonical length; the decoded signature is well-formed but invalid).
const flipByte = (b64, idx = 0) => {
  const bytes = unb64u(b64);
  bytes[idx] ^= 0x01;
  return b64u(bytes);
};
// A b64u truncation (one byte short => wrong decoded length => wire fail).
const dropByte = (b64) => {
  const bytes = unb64u(b64);
  return b64u(bytes.slice(0, bytes.length - 1));
};

const PARAMS = {
  'fn-dsa-512': {
    keygen: fnDsa512Keygen,
    sign: fnDsa512Sign,
    pkBytes: FN_DSA_512_PUBLIC_KEY_BYTES,
    sigBytes: FN_DSA_512_SIGNATURE_BYTES,
  },
  'fn-dsa-1024': {
    keygen: fnDsa1024Keygen,
    sign: fnDsa1024Sign,
    pkBytes: FN_DSA_1024_PUBLIC_KEY_BYTES,
    sigBytes: FN_DSA_1024_SIGNATURE_BYTES,
  },
};

// Mint a deterministic key pair + a valid signature for each variant.
const material = {};
for (const [alg, p] of Object.entries(PARAMS)) {
  const kp = p.keygen(seed(`fndsa-kg-${alg}`));
  if (kp.verifyingKey.length !== p.pkBytes) throw new Error(`${alg}: verifying key is not ${p.pkBytes} bytes`);
  const sig = p.sign(kp.signingKey, MSG, seed(`fndsa-sign-${alg}`));
  if (sig.length !== p.sigBytes) throw new Error(`${alg}: signature is not ${p.sigBytes} bytes`);
  material[alg] = { kp, sig: b64u(sig), pq_pk: b64u(kp.verifyingKey) };
}

const vectors = [];

// Assert a vector's stated verdict against the live reference, then record it.
//  - `verify` is verifyLeafSuite (the suite dispatch) over the message.
//  - `wire` is validateSignatureWire: null == well-formed, a string == rejected.
//  - overall allow == (wire well-formed) AND (verify true); a negative vector must be DENIED.
function add(name, cls, description, { alg, pq_pk, sig, pq_sig }, want) {
  const wireObj = { alg, sig };
  if (pq_pk !== undefined) wireObj.pq_pk = pq_pk;
  if (pq_sig !== undefined) wireObj.pq_sig = pq_sig;
  const wire = validateSignatureWire(wireObj); // string (reason) | null
  const verify = verifyLeafSuite({ alg, holder: 'unused-for-pure-pq', pqPublicKey: pq_pk, message: MSG, sig });

  const wireOk = wire === null;
  if (wireOk !== want.wireOk) throw new Error(`vector ${name}: wireOk=${wireOk} (reason='${wire ?? ''}') != intended ${want.wireOk}`);
  if (verify !== want.verify) throw new Error(`vector ${name}: verify=${verify} != intended ${want.verify}`);
  const allow = wireOk && verify;
  const intendedAllow = cls === 'positive';
  if (allow !== intendedAllow) throw new Error(`vector ${name}: allow=${allow} but class='${cls}'`);

  vectors.push({
    name,
    class: cls,
    description,
    alg,
    message: b64u(MSG),
    ...(pq_pk !== undefined ? { pq_pk } : {}),
    sig,
    ...(pq_sig !== undefined ? { pq_sig } : {}),
    expect: { verify, wire_ok: wireOk, allow },
  });
}

// ---- positive: a valid FN-DSA signature verifies and is well-formed, for both parameter sets ----
add('fn-dsa-512-valid', 'positive',
  'A valid FN-DSA-512 (Falcon-512, category 1) signature over the message, verified under the verifying key in pq_pk. The suite dispatch routes to the pca-fndsa-wasm verifier => allow.',
  { alg: 'fn-dsa-512', pq_pk: material['fn-dsa-512'].pq_pk, sig: material['fn-dsa-512'].sig },
  { verify: true, wireOk: true });

add('fn-dsa-1024-valid', 'positive',
  'A valid FN-DSA-1024 (Falcon-1024, category 5) signature over the message, verified under pq_pk => allow.',
  { alg: 'fn-dsa-1024', pq_pk: material['fn-dsa-1024'].pq_pk, sig: material['fn-dsa-1024'].sig },
  { verify: true, wireOk: true });

// ---- negative: corrupted signature (well-formed length, cryptographically invalid) => deny ----
add('fn-dsa-512-tampered-sig', 'negative',
  'FN-DSA-512 with one byte flipped in the signature: still 666 bytes (wire well-formed) but the Falcon verification fails => deny.',
  { alg: 'fn-dsa-512', pq_pk: material['fn-dsa-512'].pq_pk, sig: flipByte(material['fn-dsa-512'].sig) },
  { verify: false, wireOk: true });

add('fn-dsa-1024-tampered-sig', 'negative',
  'FN-DSA-1024 with one byte flipped in the signature: well-formed (1280 bytes) but invalid => deny.',
  { alg: 'fn-dsa-1024', pq_pk: material['fn-dsa-1024'].pq_pk, sig: flipByte(material['fn-dsa-1024'].sig) },
  { verify: false, wireOk: true });

// ---- negative: a signature verified under the WRONG verifying key => deny ----
{
  const otherPk = b64u(fnDsa512Keygen(seed('fndsa-kg-fn-dsa-512-OTHER')).verifyingKey);
  add('fn-dsa-512-wrong-key', 'negative',
    'A valid FN-DSA-512 signature verified under a DIFFERENT (well-formed) verifying key: wire is well-formed but verification fails => deny.',
    { alg: 'fn-dsa-512', pq_pk: otherPk, sig: material['fn-dsa-512'].sig },
    { verify: false, wireOk: true });
}

// ---- negative: WRONG-SIZE fields => wire fail (terminal) + verify false ----
add('fn-dsa-512-wrong-size-sig', 'negative',
  'FN-DSA-512 whose signature is one byte short (665 bytes): the per-suite wire check rejects it (sig must be 666 bytes) => deny.',
  { alg: 'fn-dsa-512', pq_pk: material['fn-dsa-512'].pq_pk, sig: dropByte(material['fn-dsa-512'].sig) },
  { verify: false, wireOk: false });

add('fn-dsa-512-wrong-size-pk', 'negative',
  'FN-DSA-512 whose pq_pk is one byte short (896 bytes): the per-suite wire check rejects it (pq_pk must be 897 bytes) => deny.',
  { alg: 'fn-dsa-512', pq_pk: dropByte(material['fn-dsa-512'].pq_pk), sig: material['fn-dsa-512'].sig },
  { verify: false, wireOk: false });

// ---- negative: STRAY pq_sig on a pure (non-hybrid) suite => wire fail even though the sig itself is valid ----
add('fn-dsa-512-stray-pq_sig', 'negative',
  "FN-DSA-512 (a pure, non-hybrid suite) carrying a stray pq_sig field: the signature itself still verifies, but the wire check rejects the object (pq_sig must be absent for fn-dsa-512) => DENY. Fail-closed: a malformed wire shape is terminal regardless of the cryptography.",
  { alg: 'fn-dsa-512', pq_pk: material['fn-dsa-512'].pq_pk, sig: material['fn-dsa-512'].sig, pq_sig: material['fn-dsa-1024'].sig },
  { verify: true, wireOk: false });

// ---- negative: UNKNOWN alg => wire fail + fail-closed suite dispatch ----
add('fn-dsa-512-unknown-alg', 'negative',
  "A stray / unknown alg 'falcon-512' (NOT the registered 'fn-dsa-512'): resolveSigAlg returns null, so the wire check rejects it and the suite dispatch verifies false => deny.",
  { alg: 'falcon-512', pq_pk: material['fn-dsa-512'].pq_pk, sig: material['fn-dsa-512'].sig },
  { verify: false, wireOk: false });

// ---- negative: CROSS-VARIANT mislabel (a 512 artifact presented as fn-dsa-1024) => wire fail ----
add('fn-dsa-512-as-1024', 'negative',
  'An FN-DSA-512 signature + key MISLABELED as fn-dsa-1024: the 666-byte sig and 897-byte key fail the fn-dsa-1024 wire check (expects 1280 / 1793 bytes), and the suite dispatch cannot verify => deny.',
  { alg: 'fn-dsa-1024', pq_pk: material['fn-dsa-512'].pq_pk, sig: material['fn-dsa-512'].sig },
  { verify: false, wireOk: false });

const corpus = {
  format: 1,
  suite: 'fn-dsa-falcon-fips206',
  description:
    'FN-DSA (Falcon, FIPS 206) pure-PQ signature suites fn-dsa-512 / fn-dsa-1024 golden + adversarial vectors. ' +
    'Verification routes through @atlasauth/pca-fndsa-wasm (vetted pure-Rust fn-dsa crate). Non-breaking / opt-in: ' +
    'the shared PCActn corpus (vectors.json) is unchanged and FN-DSA is NOT yet in the native-verifier SDKs. ' +
    'Each vector is asserted against verifyLeafSuite (suite dispatch) + validateSignatureWire before writing.',
  default_sig_alg: 'ed25519',
  sizes: {
    'fn-dsa-512': { public_key_bytes: FN_DSA_512_PUBLIC_KEY_BYTES, signature_bytes: FN_DSA_512_SIGNATURE_BYTES },
    'fn-dsa-1024': { public_key_bytes: FN_DSA_1024_PUBLIC_KEY_BYTES, signature_bytes: FN_DSA_1024_SIGNATURE_BYTES },
  },
  vectors,
};

writeFileSync(outPath, JSON.stringify(corpus, null, 2) + '\n');
const pos = vectors.filter((v) => v.class === 'positive').length;
const neg = vectors.filter((v) => v.class === 'negative').length;
console.log(`wrote ${vectors.length} fndsa vectors (${pos} positive, ${neg} negative) to ${outPath}`);
