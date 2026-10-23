// verifyWithSuite verdicts of the TypeScript reference (packages/pca/src/pq.ts) for every registered signature suite, with the
// PQ key resolved as a VERIFIER-TRUSTED key (resolvePqVerifyKey trustedPk). The guest (pq_suites.rs) must agree on every suite
// it implements and refuse the others with `unsupported_suite`.
//   packages/pca/node_modules/.bin/tsx sdks/zkvm-pca/core/tests/gen_ts_pq_suites.ts sdks/zkvm-pca/fixtures/ts_pq_suites.json
import { writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import * as pq from '../../../../packages/pca/src/pq';
import { b64u, publicKeyOf } from '../../../../packages/pca/src/index';

const out = process.argv[2];
if (!out) throw new Error('usage: gen_ts_pq_suites.ts <out.json>');
const seed = (l: string, n = 32) => {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 32) out.set(createHash('sha256').update(`zk-pq-suites/${l}/${i}`).digest().subarray(0, Math.min(32, n - i)), i);
  return out;
};
const edSecret = seed('ed');
const edPub = b64u(publicKeyOf(edSecret));
const otherEd = b64u(publicKeyOf(seed('other-ed')));
const keys: Record<string, unknown> = { edSecret };
const tryKey = (name: string, f: () => unknown) => {
  try {
    keys[name] = f();
  } catch (e) {
    console.error(`keygen ${name}: ${(e as Error).message}`);
  }
};
tryKey('mlDsa', () => pq.mlDsa65Keygen(seed('ml65')));
tryKey('mlDsa87', () => pq.mlDsa87Keygen(seed('ml87')));
tryKey('slhDsa', () => pq.slhDsa128fKeygen(seed('slh128f', 48)));
tryKey('slhDsa256s', () => pq.slhDsa256sKeygen(seed('slh256s', 96)));
tryKey('fnDsa512', () => ({ ...pq.fnDsa512Keygen(seed('fn512')), signSeed: seed('fn512-sign') }));
tryKey('fnDsa1024', () => ({ ...pq.fnDsa1024Keygen(seed('fn1024')), signSeed: seed('fn1024-sign') }));
tryKey('lessCat1', () => ({ ...pq.lessCat1Keygen(seed('less')), signSeed: seed('less-sign') }));

const msg = new TextEncoder().encode('atlas-pca/zk-pq-suites/v1\0hello');
const flip = (s: string | undefined) => {
  if (s === undefined) return undefined;
  const b = Buffer.from(s, 'base64url');
  b[b.length >> 1] ^= 1;
  return b.toString('base64url');
};
const cases: unknown[] = [];
const skipped: string[] = [];
for (const alg of Object.keys(pq.SIG_SUITES)) {
  let parts: { sig: string; pq_sig?: string };
  let pqPk: string | undefined;
  try {
    parts = pq.signWithSuite(alg, keys as never, msg) as never;
    pqPk = pq.suitePqPublicKey(alg, keys as never);
  } catch (e) {
    skipped.push(`${alg}: ${(e as Error).message}`);
    continue;
  }
  const verdict = (edP: string, m: Uint8Array, p: { sig?: string; pq_sig?: string }, pk: string | undefined) => {
    const pinned = pk !== undefined ? pq.resolvePqVerifyKey(edP, pk, { trustedPk: pk }) ?? undefined : undefined;
    try {
      return pq.verifyWithSuite(alg, { edPub: edP, ...(pinned ? { pq: pinned } : {}) } as never, m, p as never);
    } catch {
      return false;
    }
  };
  const add = (name: string, edP: string, m: Uint8Array, p: { sig?: string; pq_sig?: string }, pk: string | undefined) =>
    cases.push({ name: `${alg}/${name}`, alg, msg: b64u(m), ed_pk: edP, ...(p.sig !== undefined ? { sig: p.sig } : {}), ...(p.pq_sig !== undefined ? { pq_sig: p.pq_sig } : {}), ...(pk !== undefined ? { pq_pk: pk } : {}), ok: verdict(edP, m, p, pk) });
  add('valid', edPub, msg, parts, pqPk);
  add('sig-corrupt', edPub, msg, { ...parts, sig: flip(parts.sig) }, pqPk);
  if (parts.pq_sig !== undefined) {
    add('pq_sig-corrupt', edPub, msg, { ...parts, pq_sig: flip(parts.pq_sig) }, pqPk);
    add('pq_sig-missing', edPub, msg, { sig: parts.sig }, pqPk);
  }
  add('wrong-ed-key', otherEd, msg, parts, pqPk);
  add('wrong-msg', edPub, new TextEncoder().encode('other message'), parts, pqPk);
  if (pqPk !== undefined) {
    add('pq_pk-missing', edPub, msg, parts, undefined);
    add('pq_pk-truncated', edPub, msg, parts, pqPk.slice(0, -4));
  }
}
writeFileSync(out, JSON.stringify({ about: 'verifyWithSuite verdicts (gen_ts_pq_suites.ts)', skipped, cases }, null, 1) + '\n');
console.log(`cases ${cases.length}, suites ${new Set(cases.map((c) => (c as { alg: string }).alg)).size}, skipped ${skipped.length}`);
