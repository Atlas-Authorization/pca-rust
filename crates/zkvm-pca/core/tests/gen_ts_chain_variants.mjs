// Regenerates fixtures/ts_chain_variants.json: verdicts of the TypeScript reference
// (@atlasauth/pca verifyChain / verifyLeafSuite; @noble/curves Ed25519, a different implementation from the
// ed25519-dalek the guest uses) on ~45 tampered / re-signed / structurally odd variants of the committed chain.
// Run from the repo root after `pnpm --filter @atlasauth/pca build`:
//   node sdks/zkvm-pca/core/tests/gen_ts_chain_variants.mjs
// Output of the TS reference implementation; NOT an official standard vector.
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const pcaDir = join(here, '../../../../packages/pca');
const require = createRequire(join(pcaDir, 'package.json'));
const pca = require(join(pcaDir, 'dist/index.js'));
const { ed25519 } = require('@noble/curves/ed25519');
const { verifyChain, verifyLeafSuite, thresholdMessage, hashCanonical, sign, budgetAllocCaveat } = pca;
const inp = JSON.parse(readFileSync(join(here, '../../fixtures/decide_input.sample.json'), 'utf8'));

const b64u = (u8) => Buffer.from(u8).toString('base64url');
const unb64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
const seedKey = (n) => new Uint8Array(32).fill(n);
const pub = (n) => b64u(ed25519.getPublicKey(seedKey(n)));
const CAP_DOMAIN = Buffer.from('atlas-pca/cap/v1\0', 'latin1');
const sigMsg = (bd) => Buffer.concat([CAP_DOMAIN, Buffer.from(unb64u(bd))]);
const clone = (x) => JSON.parse(JSON.stringify(x));
const flip = (s) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
const baseCaveats = inp.chain[0].caveats;

// local re-implementation of capability.ts `seal` (ed25519 default suite); `signFn` lets us forge odd signatures.
function seal({ issuer, holder, caveats, parent }, signFn) {
  const body = { issuer, holder, caveats, parent: parent ?? null };
  const body_digest = hashCanonical(body);
  const cap = { id: body_digest, issuer, holder, caveats, body_digest, sig: b64u(signFn(sigMsg(body_digest))) };
  if (parent !== undefined) cap.parent = parent;
  return cap;
}
const signer = (n) => (m) => sign(seedKey(n), m);
const capHash = (c) => hashCanonical(c);

// sanity: our local seal reproduces the committed root hop byte for byte (Ed25519 is deterministic).
const rebuilt = seal({ issuer: pub(1), holder: pub(2), caveats: baseCaveats }, signer(1));
if (hashCanonical(rebuilt) !== hashCanonical(inp.chain[0])) throw new Error('local seal does not reproduce chain[0]');

const ROOT = inp.expected_root_principal;
const cases = [];
const add = (name, chain, root = ROOT, note) => cases.push({ name, chain, expected_root: root, note, ...tsVerdict(chain, root) });
function tsVerdict(chain, root) { const r = verifyChain(chain, root); return { ts_ok: r.ok, ts_reason: r.ok ? null : r.reason }; }
const C = () => clone(inp.chain);

add('untouched', C());
{ const c = C(); c[1].sig = flip(c[1].sig); add('leaf_sig_first_char_flipped', c); }
{ const c = C(); c[0].sig = flip(c[0].sig); add('root_sig_first_char_flipped', c); }
add('wrong_pinned_root', C(), 'not-the-pinned-root-principal-key');
add('pinned_root_is_hop0_holder', C(), pub(2));
add('pinned_root_empty_string', C(), '');
{ const c = C(); const s = c[1].sig; c[1].sig = s.slice(0, -1) + (s.at(-1) === 'A' ? 'Q' : 'A'); add('leaf_sig_last_char_changed', c); }
{ const c = C(); c[1].sig = c[1].sig.slice(0, -1); add('leaf_sig_truncated_1_char', c); }
{ const c = C(); c[1].sig += 'A'; add('leaf_sig_extended_1_char', c); }
{ const c = C(); c[1].sig += '=='; add('leaf_sig_base64_padded', c); }
{ const c = C(); c[1].sig = c[1].sig.replace(/[-_]/, '+'); add('leaf_sig_std_base64_alphabet_if_present', c); }
{ const c = C(); c[1].sig = 'A'.repeat(86); add('leaf_sig_all_zero', c); }
{ const c = C(); c[1].sig = c[0].sig; add('leaf_sig_is_roots_sig', c); }
{ // non-canonical S: S' = S + L (still < 2^256) -- malleable signature, must be rejected by a strict verifier
  const c = C(); const raw = Buffer.from(unb64u(c[1].sig)); const L = ed25519.CURVE.n;
  let S = 0n; for (let i = 31; i >= 0; i--) S = (S << 8n) | BigInt(raw[32 + i]);
  let S2 = S + L; for (let i = 0; i < 32; i++) { raw[32 + i] = Number(S2 & 0xffn); S2 >>= 8n; }
  c[1].sig = b64u(raw); add('leaf_sig_noncanonical_S_plus_L', c);
}
{ // small-order R and S=0 (the classic lax-verifier forgery shape)
  const c = C(); const raw = new Uint8Array(64); raw[0] = 1; c[1].sig = b64u(raw); add('leaf_sig_identity_R_zero_S', c);
}
{ const c = C(); c[1].body_digest = flip(c[1].body_digest); add('leaf_body_digest_tampered', c); }
{ const c = C(); c[1].id = flip(c[1].id); add('leaf_id_tampered', c); }
{ const c = C(); c[0].body_digest = flip(c[0].body_digest); add('root_body_digest_tampered', c); }
{ const c = C(); c[1].holder = pub(9); add('leaf_holder_swapped_unsigned', c); }
{ const c = C(); c[1].issuer = pub(9); add('leaf_issuer_swapped_unsigned', c); }
{ const c = C(); c[1].caveats[0].caveats[0].at += 1; add('leaf_caveat_edited_unsigned', c); }
{ const c = C(); c[1].caveats = []; add('leaf_caveats_emptied_unsigned', c); }
{ const c = C(); c[1].parent = flip(c[1].parent); add('leaf_parent_link_flipped_unsigned', c); }
{ const c = C(); c[0].parent = c[1].parent; add('root_has_parent_unsigned', c); }
add('empty_chain', []);
add('root_only_chain', [clone(inp.chain[0])]);
add('chain_reversed', C().reverse());
add('hop_duplicated', [inp.chain[0], inp.chain[1], inp.chain[1]].map(clone));
{ const c = C(); c[1].sig = 7; add('sig_not_a_string', c); }
{ const c = C(); delete c[1].caveats; add('caveats_missing', c); }
{ const c = C(); c[1].caveats = [{ nope: 1 }]; add('caveat_without_type', c); }
{ const c = C(); c[1].alg = 'ed25519'; add('explicit_alg_ed25519_on_unchanged_body', c, ROOT, 'alg field present; the signed body is unchanged for ed25519'); }
{ const c = C(); c[1].alg = 'rot13'; add('unknown_alg', c, ROOT, 'reason text may differ (in-guest rejects every non-ed25519 suite by design)'); }
{ const c = C(); c[1].alg = 'ml-dsa-65'; add('pq_alg_declared_without_pq_material', c, ROOT, 'reason text may differ; the guest fails closed on every PQ suite by design'); }

// ---- correctly re-signed variants (valid signatures, semantic violations) ----------------------
const A = pub(2), B = pub(3);
const hop0 = inp.chain[0];
const mk = (over, signN = 2) => seal({ issuer: A, holder: B, caveats: clone(hop0.caveats), parent: capHash(hop0), ...over }, signer(signN));
add('resigned_valid_extra_caveat_appended', [clone(hop0), mk({ caveats: [...clone(hop0.caveats), { type: 'expires', at: 1760000100000 }] })]);
add('resigned_caveat_dropped', [clone(hop0), mk({ caveats: clone(hop0.caveats).slice(0, -1) })] );
{ const cv = clone(hop0.caveats); cv[0].caveats[0].at = 1999999999999; add('resigned_caveat_widened_expiry', [clone(hop0), mk({ caveats: cv })]); }
{ const cv = clone(hop0.caveats); add('resigned_caveats_reordered', [clone(hop0), mk({ caveats: [{ type: 'expires', at: 1 }, ...cv] })]); }
add('resigned_wrong_signer_key', [clone(hop0), mk({}, 3)]);
add('resigned_issuer_not_parent_holder', [clone(hop0), mk({ issuer: B }, 3)]);
add('resigned_broken_parent_link', [clone(hop0), mk({ parent: capHash(inp.chain[1]) })]);
{ const r = seal({ issuer: pub(1), holder: A, caveats: clone(baseCaveats), parent: 'AAAA' }, signer(1)); add('resigned_root_with_parent', [r, mk({ parent: capHash(r) })]); }
{ // budget_alloc monotonicity
  const r1 = seal({ issuer: pub(1), holder: A, caveats: [...clone(baseCaveats), budgetAllocCaveat(100)] }, signer(1));
  const widen = seal({ issuer: A, holder: B, caveats: [...clone(r1.caveats), budgetAllocCaveat(200)], parent: capHash(r1) }, signer(2));
  add('resigned_budget_alloc_widened', [r1, widen]);
  const narrow = seal({ issuer: A, holder: B, caveats: [...clone(r1.caveats), budgetAllocCaveat(50)], parent: capHash(r1) }, signer(2));
  add('resigned_budget_alloc_narrowed_valid', [r1, narrow]);
  const neg = seal({ issuer: A, holder: B, caveats: [...clone(r1.caveats), budgetAllocCaveat(-1)], parent: capHash(r1) }, signer(2));
  add('resigned_budget_alloc_negative', [r1, neg]);
  const nan = seal({ issuer: A, holder: B, caveats: [...clone(r1.caveats), { type: 'budget_alloc', limit: 'x' }], parent: capHash(r1) }, signer(2));
  add('resigned_budget_alloc_non_numeric', [r1, nan]);
}
{ // depth: 16 hops valid, 17 too long
  const mkChain = (n) => {
    const ch = [seal({ issuer: pub(1), holder: pub(2), caveats: clone(baseCaveats) }, signer(1))];
    for (let i = 1; i < n; i++) { const p = ch[i - 1]; ch.push(seal({ issuer: p.holder, holder: pub(2 + i), caveats: clone(p.caveats), parent: capHash(p) }, signer(1 + i))); }
    return ch;
  };
  add('chain_16_hops_valid', mkChain(16)); add('chain_17_hops_too_long', mkChain(17));
}
{ // Torsion: a delegatee key A' = A + T (T of order 8). Cofactorless verify accepts a signature with
  // k = H(R||A'||M) = 0 mod 8; a strict-torsion-free verifier (the TS reference) must reject A'.
  const T = ed25519.ExtendedPoint.fromHex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a');
  if (!T.isSmallOrder() || T.multiply(4n).equals(ed25519.ExtendedPoint.ZERO)) throw new Error('not an order-8 point');
  const ext = ed25519.utils.getExtendedPublicKey(seedKey(2)); // agentA scalar
  const Aprime = ed25519.ExtendedPoint.fromHex(ext.pointBytes).add(T);
  const Apb = Aprime.toRawBytes();
  const L = ed25519.CURVE.n; const mod = (x) => ((x % L) + L) % L;
  const rootT = seal({ issuer: pub(1), holder: b64u(Apb), caveats: clone(baseCaveats) }, signer(1));
  const body = { issuer: b64u(Apb), holder: B, caveats: clone(rootT.caveats), parent: capHash(rootT) };
  const bd = hashCanonical(body); const msg = sigMsg(bd);
  let found = null;
  for (let n = 1n; n < 5000n && !found; n++) {
    const r = mod(n * 0x9e3779b97f4a7c15n + 12345n); const R = ed25519.ExtendedPoint.BASE.multiply(r).toRawBytes();
    const k = mod(BigInt('0x' + Buffer.from(createHash('sha512').update(Buffer.concat([R, Apb, msg])).digest().reverse()).toString('hex')));
    if (k % 8n === 0n) { const S = mod(r + k * ext.scalar); const sb = new Uint8Array(32); let t = S; for (let i = 0; i < 32; i++) { sb[i] = Number(t & 0xffn); t >>= 8n; } found = Buffer.concat([R, sb]); }
  }
  if (!found) throw new Error('grind failed');
  const hop1 = { id: bd, issuer: b64u(Apb), holder: B, caveats: clone(rootT.caveats), body_digest: bd, sig: b64u(found), parent: capHash(rootT) };
  add('mixed_order_delegator_key_with_k_0_mod_8', [rootT, hop1], ROOT,
    'A\' = A + (order-8 point); signature grinds k = 0 mod 8 so the COFACTORLESS equation holds. Only a verifier that rejects non-torsion-free keys (TS) rejects it.');
}

{ // Torsion in R. For a COFACTORLESS check ([S]B = R + [k]A) an R with a torsion component can verify only if
  // [k]A carries the opposite torsion, i.e. only when A is ALSO mixed-order. With a prime-order A it can never
  // satisfy the equation, so the R test is not independently observable; the cases below pin that both
  // implementations reject: (1) torsion R with an honest prime-order key, (2) mixed-order A and mixed-order R
  // ground so that the cofactorless equation holds (T_R = -[k mod 8]T), (3) the same with the SMALL-order R = T.
  const T = ed25519.ExtendedPoint.fromHex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a');
  const L = ed25519.CURVE.n; const mod = (x) => ((x % L) + L) % L;
  const le = (x) => { const o = new Uint8Array(32); let t = x; for (let i = 0; i < 32; i++) { o[i] = Number(t & 0xffn); t >>= 8n; } return o; };
  const hk = (R, Ab, msg) => mod(BigInt('0x' + Buffer.from(createHash('sha512').update(Buffer.concat([R, Ab, msg])).digest().reverse()).toString('hex')));
  const extA = ed25519.utils.getExtendedPublicKey(seedKey(2));
  const mkHop = (issuerB64, parent, sigBytes, bodyHolder) => {
    const body = { issuer: issuerB64, holder: bodyHolder, caveats: clone(baseCaveats), parent: capHash(parent) };
    const bd = hashCanonical(body);
    return { body, bd, msg: sigMsg(bd), fin: (sig) => ({ id: bd, issuer: issuerB64, holder: bodyHolder, caveats: clone(baseCaveats), body_digest: bd, sig: b64u(sig), parent: capHash(parent) }) };
  };
  // (1) prime-order key, R = rB + T
  {
    const rootH = seal({ issuer: pub(1), holder: pub(2), caveats: clone(baseCaveats) }, signer(1));
    const h = mkHop(pub(2), rootH, null, B);
    const r = mod(0x1234567890abcdefn); const R = ed25519.ExtendedPoint.BASE.multiply(r).add(T).toRawBytes();
    const k = hk(R, ed25519.ExtendedPoint.fromHex(extA.pointBytes).toRawBytes(), h.msg);
    add('prime_order_key_with_torsion_R', [rootH, h.fin(Buffer.concat([R, le(mod(r + k * extA.scalar))]))], ROOT,
      'A is prime order; R = rB + (order-8 point). The cofactorless equation cannot hold, so the R torsion test is never the only reason.');
  }
  // (2) mixed A' and mixed R with a valid cofactorless equation
  {
    const Aprime = ed25519.ExtendedPoint.fromHex(extA.pointBytes).add(T); const Apb = Aprime.toRawBytes();
    const rootT = seal({ issuer: pub(1), holder: b64u(Apb), caveats: clone(baseCaveats) }, signer(1));
    const h = mkHop(b64u(Apb), rootT, null, B);
    let found = null, cUsed = 0;
    for (let n = 1n; n < 20000n && !found; n++) {
      const r = mod(n * 0x9e3779b97f4a7c15n + 777n);
      for (let c = 1n; c < 8n && !found; c++) {
        const R = ed25519.ExtendedPoint.BASE.multiply(r).add(T.multiply(8n - c)).toRawBytes();
        const k = hk(R, Apb, h.msg);
        if (k % 8n === c) { found = Buffer.concat([R, le(mod(r + k * extA.scalar))]); cUsed = Number(c); }
      }
    }
    if (!found) throw new Error('grind failed (mixed A and R)');
    add('mixed_order_key_and_mixed_order_R_cofactorless_valid', [rootT, h.fin(found)], ROOT,
      `A' = A + T and R = rB + [${8 - cUsed}]T chosen so that [S]B = R + [k]A' holds cofactorlessly (k mod 8 = ${cUsed}); both points are mixed-order.`);
  }
  // (3) small-order R = T with a prime-order key (dalek verify_strict and the TS reference both reject small-order R)
  {
    const rootH = seal({ issuer: pub(1), holder: pub(2), caveats: clone(baseCaveats) }, signer(1));
    const h = mkHop(pub(2), rootH, null, B);
    const R = T.toRawBytes();
    const k = hk(R, ed25519.ExtendedPoint.fromHex(extA.pointBytes).toRawBytes(), h.msg);
    add('small_order_R_with_prime_order_key', [rootH, h.fin(Buffer.concat([R, le(mod(k * extA.scalar))]))], ROOT, 'R is a small-order point.');
  }
}

// ---- leaf PCActn signature variants (TS verifyLeafSuite on the same message the guest checks) ----
const holderLeaf = inp.chain[1].holder;
const leafVerdict = (p) => { try { return !!verifyLeafSuite({ alg: p.alg, holder: holderLeaf, pqPublicKey: p.pq_pk, message: thresholdMessage(p), sig: p.sig, pqSig: p.pq_sig }); } catch { return false; } };
const leaf_cases = [];
const addLeaf = (name, p) => leaf_cases.push({ name, pcactn: p, ts_ok: leafVerdict(p) });
const P = () => clone(inp.pcactn);
addLeaf('untouched', P());
{ const p = P(); p.sig = flip(p.sig); addLeaf('sig_first_char_flipped', p); }
{ const p = P(); p.action.verb = 'delete'; addLeaf('action_verb_changed', p); }
{ const p = P(); p.exp += 1; addLeaf('exp_changed', p); }
{ const p = P(); p.counter = 1; addLeaf('counter_changed', p); }
{ const p = P(); p.plan.root = flip(p.plan.root); addLeaf('plan_root_changed', p); }
{ const p = P(); p.sig = inp.chain[1].sig; addLeaf('sig_is_a_chain_hop_sig', p); }
{ const p = P(); p.sig = p.sig.slice(0, -1); addLeaf('sig_truncated', p); }
{ const p = P(); const m = thresholdMessage(p); p.sig = b64u(sign(seedKey(2), m)); addLeaf('signed_by_wrong_key_agentA', p); }
{ const p = P(); p.alg = 'rot13'; addLeaf('unknown_alg', p); }
{ const p = P(); p.alg = 'ed25519'; addLeaf('explicit_alg_ed25519', p); }
{ const p = P(); p.threshold = { x: 1 }; addLeaf('unsigned_threshold_container_added', p); }
{ const p = P(); p.pq_sig = 'AAAA'; addLeaf('unsigned_pq_sig_container_added', p); }

const out = {
  description: 'Verdicts of the TypeScript reference (@atlasauth/pca verifyChain / verifyLeafSuite, @noble/curves Ed25519) on tampered, re-signed and structurally odd variants of the committed capability chain and leaf PCActn.',
  generator: 'core/tests/gen_ts_chain_variants.mjs',
  node: process.version,
  note: 'Output of the TS reference implementation, not an official standard vector.',
  cases, leaf_cases,
};
writeFileSync(join(here, '../../fixtures/ts_chain_variants.json'), JSON.stringify(out) + '\n');
console.log(cases.length, 'chain cases;', leaf_cases.length, 'leaf cases');
for (const c of cases) console.log(c.ts_ok ? 'OK  ' : 'DENY', c.name, c.ts_reason ?? '');
for (const c of leaf_cases) console.log(c.ts_ok ? 'OK  ' : 'DENY', 'leaf:' + c.name);
