// Generates conformance/less-vectors.json: known-answer vectors for the LESS suites (`less-cat1`,
// `hybrid-ed25519-less-cat1`; LESS is a NIST additional-signature round-2 candidate, not a standard) registered in
// packages/pca/src/pq.ts, for the native verifiers that implement LESS through the patched reference C (sdks/pca-less-c).
//
//   node packages/pca/conformance/gen-less.mjs
//
// Needs no install (Node >= 22.18 / 23.6: it loads the TypeScript source with Node's type stripping): keys and signatures
// come from @atlasauth/pca-less-wasm's own source and wasm (src/core.ts + wasm/less_cat1.wasm: the backend the TS reference
// dispatches LESS to), the Ed25519 half of the hybrid from node:crypto. Every vector's stated verdict is asserted BEFORE
// it is written against exactly what pq.ts computes for it: the wire rule of validateSignatureWire (canonical base64url,
// pq_pk 97,484 bytes, the LESS component 1,153..1,329 bytes in steps of 16) and verifyLeafSuite (hybrid: Ed25519 half
// first, then lessCat1Verify = the wasm `verify`). Keygen and signing are seeded, so the file is byte-reproducible.
//
// Shape: { keys: {<name>: {pq_pk, ed_pub}}, vectors: [{name, class, description, alg, key, message, sig, pq_sig?,
// pq_pk_override?, expect: {verify, wire_ok, allow}}] }. A verifier resolves the vector's PQ key as keys[key].pq_pk (or
// pq_pk_override when present), its Ed25519 key as keys[key].ed_pub, and verifies `message` under `alg`; allow ==
// wire_ok && verify. The 130 KB keys are stored once.
//
// Malleation vectors (`less-cat1-seed-padded-*`): a VALID signature with an extra 16-byte seed slot and its seed count
// raised by one. The unpatched upstream reference accepted them; the patched C (sdks/pca-less-c, also inside the wasm) and the
// wrapper's canonical seed count check refuse them, and so must every verifier.
import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const less = await import(join(here, '../../pca-less-wasm/src/core.ts'));
less.initLessSync(readFileSync(join(here, '../../pca-less-wasm/wasm/less_cat1.wasm')));
const outPath = join(here, 'less-vectors.json');

const PK_BYTES = 97484, SIG_MIN = 1153, SIG_MAX = 1329, SIG_STEP = 16, ED_SIG = 64;
if (less.VARIANT !== 'less-252-45' || less.sizes().publicKey !== PK_BYTES || less.sizes().signatureMax !== SIG_MAX) throw new Error('unexpected LESS variant');

const b64u = (b) => Buffer.from(b).toString('base64url');
const unb64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
const seed = (label) => { const s = new Uint8Array(32); for (let i = 0; i < label.length && i < 32; i++) s[i] = label.charCodeAt(i); return s; };
const MSG = new TextEncoder().encode('atlas-pca/less-conformance/code-based-leaf-message');

function edKey(label) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed(label))]);
  const priv = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  return { priv, pub: Buffer.from(createPublicKey(priv).export({ format: 'jwk' }).x, 'base64url') };
}
function lessKey(label) { less.seedWith(seed(label)); return less.keygen(); }
function lessSign(sk, msg, label) { less.seedWith(seed(label)); return less.signDetached(sk, msg); }

const keys = {};
const mat = {};
for (const name of ['main', 'other']) {
  const k = lessKey(`less-kg-${name}`), e = edKey(`less-ed-${name}`);
  keys[name] = { pq_pk: b64u(k.publicKey), ed_pub: b64u(e.pub) };
  mat[name] = { less: k, ed: e };
}

// the reference's verdict for one vector (pq.ts validateSignatureWire + verifyLeafSuite, LESS through the wasm)
const lenOk = (n) => n >= SIG_MIN && n <= SIG_MAX && (SIG_MAX - n) % SIG_STEP === 0;
const canon = (s) => typeof s === 'string' && /^[A-Za-z0-9_-]*$/.test(s) && s.length % 4 !== 1 && b64u(unb64u(s)) === s;
function reference(v) {
  const pk = v.pq_pk_override ?? keys[v.key].pq_pk;
  const hybrid = v.alg === 'hybrid-ed25519-less-cat1';
  const lessField = hybrid ? v.pq_sig : v.sig;
  const wire = canon(pk) && unb64u(pk).length === PK_BYTES && canon(lessField) && lenOk(unb64u(lessField).length)
    && (!hybrid || (canon(v.sig) && unb64u(v.sig).length === ED_SIG));
  const msg = unb64u(v.message);
  const lessOk = () => canon(pk) && canon(lessField) && unb64u(pk).length === PK_BYTES && lenOk(unb64u(lessField).length) && less.verify(unb64u(pk), msg, unb64u(lessField)) === true;
  let verify;
  if (!hybrid) verify = lessOk();
  else {
    const edOk = canon(v.sig) && unb64u(v.sig).length === ED_SIG && edVerify(null, msg, createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: keys[v.key].ed_pub }, format: 'jwk' }), unb64u(v.sig));
    verify = edOk && lessOk();
  }
  return { verify, wire_ok: wire, allow: wire && verify };
}

const vectors = [];
function add(name, cls, description, v, want) {
  const vec = { name, class: cls, description, ...v, message: v.message ?? b64u(MSG) };
  const got = reference(vec);
  if (got.verify !== want.verify || got.wire_ok !== want.wire_ok || got.allow !== (cls === 'positive')) {
    throw new Error(`${name}: reference ${JSON.stringify(got)} != intended ${JSON.stringify(want)} (${cls})`);
  }
  vectors.push({ ...vec, expect: got });
}
const mutate = (b64, f) => { const b = unb64u(b64); f(b); return b64u(b); };

const sigMain = b64u(lessSign(mat.main.less.secretKey, MSG, 'less-sign-main'));
const sigOther = b64u(lessSign(mat.other.less.secretKey, MSG, 'less-sign-other'));
const edMain = b64u(edSign(null, MSG, mat.main.ed.priv));
const leaves = unb64u(sigMain).at(-1);

// ---- less-cat1 (pure: `sig` is the LESS signature under pq_pk)
const P = { alg: 'less-cat1', key: 'main' };
add('less-cat1-valid', 'positive', 'A valid less-252-45 signature over the message.', { ...P, sig: sigMain }, { verify: true, wire_ok: true });
add('less-cat1-valid-other-key', 'positive', 'A second key pair, its own valid signature.', { ...P, key: 'other', sig: sigOther }, { verify: true, wire_ok: true });
add('less-cat1-flip-digest', 'negative', 'First byte (challenge digest) flipped.', { ...P, sig: mutate(sigMain, (b) => { b[0] ^= 1; }) }, { verify: false, wire_ok: true });
add('less-cat1-flip-salt', 'negative', 'A salt byte flipped.', { ...P, sig: mutate(sigMain, (b) => { b[40] ^= 0x80; }) }, { verify: false, wire_ok: true });
add('less-cat1-flip-seed', 'negative', 'A published seed byte flipped.', { ...P, sig: mutate(sigMain, (b) => { b[b.length - 2] ^= 1; }) }, { verify: false, wire_ok: true });
add('less-cat1-padding-bit', 'negative', 'A padding bit (252..255) of the first cf_monom_actions row set (upstream defect 2 path).', { ...P, sig: mutate(sigMain, (b) => { b[64 + 31] |= 0x10; }) }, { verify: false, wire_ok: true });
add('less-cat1-seed-count-up', 'negative', 'The trailing seed-count byte raised by one at the same length (upstream defect 1 path).', { ...P, sig: mutate(sigMain, (b) => { b[b.length - 1] = leaves + 1; }) }, { verify: false, wire_ok: true });
add('less-cat1-seed-count-max', 'negative', 'The trailing seed-count byte 255 (above MAX_PUBLISHED_SEEDS).', { ...P, sig: mutate(sigMain, (b) => { b[b.length - 1] = 255; }) }, { verify: false, wire_ok: true });
add('less-cat1-wrong-message', 'negative', 'A valid signature checked against a different message.', { ...P, sig: sigMain, message: b64u(new TextEncoder().encode('atlas-pca/less-conformance/another-message')) }, { verify: false, wire_ok: true });
add('less-cat1-wrong-key', 'negative', 'A valid signature under the other key.', { ...P, key: 'other', sig: sigMain }, { verify: false, wire_ok: true });
add('less-cat1-empty-message-forged', 'negative', 'The signature over the message, checked against the empty message.', { ...P, sig: sigMain, message: '' }, { verify: false, wire_ok: true });
add('less-cat1-truncated-one', 'negative', 'One byte short: not a length the parameter set produces.', { ...P, sig: b64u(unb64u(sigMain).slice(0, -1)) }, { verify: false, wire_ok: false });
add('less-cat1-drop-last-seed', 'negative', 'The last published seed removed (a producible length; the seed count byte no longer matches).', { ...P, sig: b64u(Uint8Array.from([...unb64u(sigMain).slice(0, -17), leaves])) }, { verify: false, wire_ok: true });
const padded = (fill) => { const s = unb64u(sigMain); const m = new Uint8Array(s.length + SIG_STEP); m.set(s.subarray(0, s.length - 1), 0); m.fill(fill, s.length - 1, m.length - 1); m[m.length - 1] = leaves + 1; return b64u(m); };
add('less-cat1-seed-padded-zero', 'negative', 'Malleation: a valid signature with an extra all-zero 16-byte seed slot and its seed count raised by one (accepted by the unpatched upstream reference).', { ...P, sig: padded(0x00) }, { verify: false, wire_ok: true });
add('less-cat1-seed-padded-junk', 'negative', 'Malleation: a valid signature with an extra 16-byte seed slot of 0xab and its seed count raised by one.', { ...P, sig: padded(0xab) }, { verify: false, wire_ok: true });
add('less-cat1-oversize', 'negative', 'Longer than the maximum signature.', { ...P, sig: b64u(new Uint8Array(SIG_MAX + SIG_STEP)) }, { verify: false, wire_ok: false });
add('less-cat1-zero-min', 'negative', 'All-zero signature of the minimum length.', { ...P, sig: b64u(new Uint8Array(SIG_MIN)) }, { verify: false, wire_ok: true });
add('less-cat1-pk-short', 'negative', 'Public key one byte short.', { ...P, sig: sigMain, pq_pk_override: b64u(unb64u(keys.main.pq_pk).slice(0, -1)) }, { verify: false, wire_ok: false });
add('less-cat1-noncanonical-b64', 'negative', 'Signature in padded base64url.', { ...P, sig: sigMain + '=' }, { verify: false, wire_ok: false });

// ---- hybrid-ed25519-less-cat1 (`sig` Ed25519 under ed_pub, `pq_sig` LESS under pq_pk; both)
const H = { alg: 'hybrid-ed25519-less-cat1', key: 'main' };
add('hybrid-less-valid', 'positive', 'Valid Ed25519 half and valid LESS half.', { ...H, sig: edMain, pq_sig: sigMain }, { verify: true, wire_ok: true });
add('hybrid-less-bad-ed25519', 'negative', 'Ed25519 half flipped, LESS half valid.', { ...H, sig: mutate(edMain, (b) => { b[0] ^= 1; }), pq_sig: sigMain }, { verify: false, wire_ok: true });
add('hybrid-less-bad-less', 'negative', 'Ed25519 half valid, LESS half flipped.', { ...H, sig: edMain, pq_sig: mutate(sigMain, (b) => { b[0] ^= 1; }) }, { verify: false, wire_ok: true });
add('hybrid-less-swapped-halves', 'negative', 'LESS signature in `sig`, Ed25519 in `pq_sig`.', { ...H, sig: sigMain, pq_sig: edMain }, { verify: false, wire_ok: false });
add('hybrid-less-seed-padded', 'negative', 'Malleation of the LESS half: valid Ed25519 half, LESS half with an extra seed slot and a raised seed count.', { ...H, sig: edMain, pq_sig: padded(0x5c) }, { verify: false, wire_ok: true });
add('hybrid-less-pq-sig-truncated', 'negative', 'LESS half one byte short.', { ...H, sig: edMain, pq_sig: b64u(unb64u(sigMain).slice(0, -1)) }, { verify: false, wire_ok: false });

const doc = {
  format: 1,
  suite: 'less-cat1',
  description: 'LESS (less-252-45, NIST additional-signature round-2 candidate; not a standard) known answers for the less-cat1 / hybrid-ed25519-less-cat1 suites, including seed-padding malleation that every verifier must refuse. Signatures from @atlasauth/pca-less-wasm (patched reference, wasm/BUILD.json); every verdict asserted against the pq.ts rules (validateSignatureWire + verifyLeafSuite) before writing. Natives verify through the same patched reference C (sdks/pca-less-c).',
  sizes: { pq_pk: PK_BYTES, sig_min: SIG_MIN, sig_max: SIG_MAX, sig_step: SIG_STEP },
  keys,
  vectors,
};
writeFileSync(outPath, JSON.stringify(doc, null, 1) + '\n');
console.log(`wrote ${vectors.length} vectors to ${outPath}`);
