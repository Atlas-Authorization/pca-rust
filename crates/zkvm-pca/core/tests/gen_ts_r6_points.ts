// R6: Ed25519 point-encoding verdicts of the TypeScript reference (`keys.ts` `verify`: noble `fromHex` with zip215=false,
// then not small-order and torsion-free), for the in-guest `chain::ed25519_point_strict`. Vectors: every `y + p` alias
// (y = 0..18, both sign bits, the only y >= p encodings that fit in 255 bits), the canonical encodings of the same y,
// sign-bit-set x = 0 points, the 8 small-order points, real public keys and their sign-flipped twins.
// Output of the TS reference; NOT a standard vector.
//   redteam/run.sh --tsconfig redteam/round4/tsconfig.json sdks/zkvm-pca/core/tests/gen_ts_r6_points.ts <out.json>
import { writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
// the SAME @noble/curves the TS reference (packages/pca) resolves
const { ed25519 } = createRequire(new URL('../../../../packages/pca/package.json', import.meta.url))('@noble/curves/ed25519');

const out = process.argv[2];
if (!out) throw new Error('usage: gen_ts_r6_points.ts <out.json>');
const P = 2n ** 255n - 19n;
const le = (n: bigint, sign: number): Uint8Array => {
  const b = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    b[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (sign) b[31]! |= 0x80;
  return b;
};
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const verdict = (b: Uint8Array): { decodes: boolean; accept: boolean } => {
  try {
    const pt = ed25519.ExtendedPoint.fromHex(b, false);
    return { decodes: true, accept: !pt.isSmallOrder() && pt.isTorsionFree() };
  } catch {
    return { decodes: false, accept: false };
  }
};
const cases: { name: string; hex: string; decodes: boolean; accept: boolean }[] = [];
const add = (name: string, b: Uint8Array) => cases.push({ name, hex: hex(b), ...verdict(b) });
for (let y = 0n; y < 19n; y++) {
  for (const s of [0, 1]) {
    add(`y=${y}+p sign=${s}`, le(y + P, s));
    add(`y=${y} sign=${s}`, le(y, s));
  }
}
for (let i = 1; i <= 24; i++) {
  const pk = ed25519.getPublicKey(new Uint8Array(32).fill(i));
  add(`pk(seed ${i})`, pk);
  const f = Uint8Array.from(pk);
  f[31]! ^= 0x80;
  add(`pk(seed ${i}) sign flipped`, f);
}
// the 8 torsion points (order | 8), via [L]·P of the basepoint multiples is not available, so use the known encodings
for (const h of [
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '0000000000000000000000000000000000000000000000000000000000000000',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
]) add(`torsion ${h.slice(0, 8)}`, Uint8Array.from(Buffer.from(h, 'hex')));
writeFileSync(out, JSON.stringify({ generator: 'gen_ts_r6_points.ts', cases }, null, 1));
console.log(`${cases.length} encodings, accepted ${cases.filter((c) => c.accept).length}, decodable ${cases.filter((c) => c.decodes).length}`);
