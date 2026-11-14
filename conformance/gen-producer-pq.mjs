// Regenerates producer-pq-vectors.json: the post-quantum signing vectors (every registered suite except LESS) that a native
// producer replays. ML-DSA and SLH-DSA signing in the reference is the FIPS 204 / FIPS 205 DETERMINISTIC variant (no fresh
// randomness), keygen is seeded, and FN-DSA signs with a fixed 32-byte seed, so every byte here is reproducible.
//
//   pnpm --filter @atlasauth/pca build && node packages/pca/conformance/gen-producer-pq.mjs > packages/pca/conformance/producer-pq-vectors.json
//
// Generated from the built reference (like gen-fndsa.mjs). Before anything is written:
//   - every case is checked with the reference verifiers (verifyWithSuite, verifyChain, verifyPCActnCore,
//     verifyEscalationAnswer, checkRevocationEpoch), so a reference bug cannot become a golden vector;
//   - every ML-DSA / SLH-DSA signature is verified a second time by Node's OpenSSL, independently of the reference;
//   - the whole file is produced twice and the two outputs must be byte-identical (pins the deterministic signing default).
// PCA_REF=<path> imports the reference from another entry point instead of ../dist/index.js.
import { createHash, createPublicKey, verify as osslVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const refUrl = process.env.PCA_REF ? pathToFileURL(process.env.PCA_REF).href : new URL('../dist/index.js', import.meta.url).href;
const mod = await import(refUrl);
const R = typeof mod.signWithSuite === 'function' ? mod : mod.default;
if (!R.isFnDsaBackendActive()) throw new Error('FN-DSA backend unavailable: build @atlasauth/pca-fndsa-wasm first');

const b64u = (b) => Buffer.from(b).toString('base64url');
const unb64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
const sha = (s) => createHash('sha256').update(s).digest();
const utf8 = (s) => new Uint8Array(Buffer.from(s, 'utf8'));
const cat = (...xs) => new Uint8Array(Buffer.concat(xs.map((x) => Buffer.from(x))));
const plain = (v) => JSON.parse(JSON.stringify(v));

// Seed bytes for a label, any length (sha256 counter blocks).
function seedBytes(label, n) {
  const out = [];
  for (let i = 0; out.length * 32 < n; i++) out.push(sha('producer-pq-vector:' + label + ':' + i));
  return new Uint8Array(Buffer.concat(out).subarray(0, n));
}

// ---- Ed25519 identities: the same seeds as producer-vectors.json ----
const K = JSON.parse(readFileSync(here + 'keys.json', 'utf8'));
const ED = {};
for (const n of ['principal', 'agent', 'subagent']) {
  const sk = unb64u(K[n].seed);
  if (b64u(R.publicKeyOf(sk)) !== K[n].public) throw new Error('keys.json public mismatch for ' + n);
  ED[n] = { seed: K[n].seed, public: K[n].public, sk };
}

// ---- PQ families and which languages must match each byte for byte ----
const SIGNERS8 = ['go', 'python', 'rust', 'java', 'kotlin', 'dotnet', 'php', 'ruby'];
const FAMILIES = {
  'ml-dsa-65': { seedLen: 32, keygen: R.mlDsa65Keygen, slot: 'mlDsa', oid: '608648016503040312', keygenExact: [...SIGNERS8, 'swift'], signExact: SIGNERS8 },
  'ml-dsa-87': { seedLen: 32, keygen: R.mlDsa87Keygen, slot: 'mlDsa87', oid: '608648016503040313', keygenExact: [...SIGNERS8, 'swift'], signExact: SIGNERS8 },
  'slh-dsa-sha2-128f': { seedLen: 48, keygen: R.slhDsa128fKeygen, slot: 'slhDsa', oid: '608648016503040315', keygenExact: SIGNERS8, signExact: SIGNERS8 },
  'slh-dsa-sha2-256s': { seedLen: 96, keygen: R.slhDsa256sKeygen, slot: 'slhDsa256s', oid: '608648016503040318', keygenExact: SIGNERS8, signExact: SIGNERS8 },
  'fn-dsa-512': { seedLen: 32, keygen: R.fnDsa512Keygen, slot: 'fnDsa512', keygenExact: ['rust'], signExact: ['rust'] },
  'fn-dsa-1024': { seedLen: 32, keygen: R.fnDsa1024Keygen, slot: 'fnDsa1024', keygenExact: ['rust'], signExact: ['rust'] },
};
const ALL9 = [...SIGNERS8, 'swift'];
// Every registered suite but LESS (TypeScript-only signing). `family` null = Ed25519 only.
const SUITES = [
  ['ed25519', null],
  ['ml-dsa-65', 'ml-dsa-65'],
  ['hybrid-ed25519-ml-dsa-65', 'ml-dsa-65'],
  ['hybrid-nested-ed25519-ml-dsa-65', 'ml-dsa-65'],
  ['ml-dsa-87', 'ml-dsa-87'],
  ['hybrid-ed25519-ml-dsa-87', 'ml-dsa-87'],
  ['slh-dsa-sha2-128f', 'slh-dsa-sha2-128f'],
  ['hybrid-ed25519-slh-dsa-sha2-128f', 'slh-dsa-sha2-128f'],
  ['slh-dsa-sha2-256s', 'slh-dsa-sha2-256s'],
  ['hybrid-ed25519-slh-dsa-sha2-256s', 'slh-dsa-sha2-256s'],
  ['fn-dsa-512', 'fn-dsa-512'],
  ['fn-dsa-1024', 'fn-dsa-1024'],
];
const exactFor = (family) => (family === null ? ALL9 : FAMILIES[family].signExact);

// ---- Node OpenSSL cross-check (independent of the reference) ----
function spki(oidHex, pk) {
  const len = (n) => (n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]));
  const tlv = (t, b) => Buffer.concat([Buffer.from([t]), len(b.length), b]);
  const alg = tlv(0x30, tlv(0x06, Buffer.from(oidHex, 'hex')));
  return createPublicKey({ key: tlv(0x30, Buffer.concat([alg, tlv(0x03, Buffer.concat([Buffer.from([0]), Buffer.from(pk)]))])), format: 'der', type: 'spki' });
}
let osslChecked = 0;
// Check the PQ component of a suite signature over `msg` with OpenSSL (ML-DSA / SLH-DSA only; FN-DSA has no OpenSSL support).
function osslCheck(alg, pqPkB64u, msg, parts) {
  const suite = R.resolveSigAlg(alg);
  if (suite.alg === 'ed25519' || suite.hasFnDsa512 || suite.hasFnDsa1024) return;
  const family = SUITES.find(([a]) => a === alg)[1];
  const pqSig = suite.needsPqSig ? parts.pq_sig : parts.sig;
  const signed = alg === 'hybrid-nested-ed25519-ml-dsa-65' ? cat(msg, unb64u(parts.sig)) : msg;
  if (!osslVerify(null, signed, spki(FAMILIES[family].oid, unb64u(pqPkB64u)), unb64u(pqSig))) throw new Error(`OpenSSL refused the ${alg} signature`);
  osslChecked++;
}

async function build() {
  // ---- PQ keys: one per (role, family) ----
  const PQ = {};
  const pqKeys = {};
  for (const [family, f] of Object.entries(FAMILIES)) {
    for (const role of ['principal', 'agent', 'subagent']) {
      const name = `${role}/${family}`;
      const seed = seedBytes(name, f.seedLen);
      const kp = f.keygen(seed);
      const entry = { family, seed: b64u(seed) };
      if (family.startsWith('fn-dsa')) {
        const signSeed = seedBytes(name + ':sign', 32);
        PQ[name] = { family, public: b64u(kp.verifyingKey), material: { verifyingKey: kp.verifyingKey, signingKey: kp.signingKey, signSeed } };
        entry.sign_seed = b64u(signSeed);
      } else {
        PQ[name] = { family, public: b64u(kp.publicKey), material: kp };
      }
      entry.public = PQ[name].public;
      pqKeys[name] = entry;
    }
  }
  const suiteOpts = (alg, pqName) => (pqName === null ? { alg } : { alg, [FAMILIES[PQ[pqName].family].slot]: PQ[pqName].material });
  const pqOf = (role, family) => (family === null ? null : `${role}/${family}`);

  const cases = [];
  const add = (c) => cases.push(c);
  const T0 = 1_800_000_000_000;
  const AUD = 'rs-producer-pq-vectors';
  const NONCE = (n) => b64u(sha('producer-pq-vector:nonce:' + n).subarray(0, 16));
  const RISK = { weights: { alpha: 0.25, beta: 0.2, gamma: 0.2, delta: 0.2, epsilon: 0.1, zeta: 0.05 }, theta1: 0.25, theta2: 0.6, kappa: 1, lambda: 0.0005, rho: 0.5, bMax: 1 };

  // pq_keygen
  for (const [family, f] of Object.entries(FAMILIES)) {
    const name = `agent/${family}`;
    add({ name: `pq-keygen-${family}`, op: 'pq_keygen', exact: f.keygenExact, args: { family, seed: pqKeys[name].seed }, expect: { public: pqKeys[name].public } });
  }

  for (const [alg, family] of SUITES) {
    const exact = exactFor(family);
    const suiteOf = (role) => suiteOpts(alg, pqOf(role, family));
    const hasEd = R.resolveSigAlg(alg).hasEd25519;

    // suite_sign: the raw seam
    const msgText = 'atlas-pca producer pq vector: ' + alg;
    const agentPq = pqOf('agent', family);
    const parts = R.signWithSuite(alg, { edSecret: ED.agent.sk, ...(agentPq ? { [FAMILIES[family].slot]: PQ[agentPq].material } : {}) }, utf8(msgText));
    const pin = agentPq ? R.resolvePqVerifyKey(ED.agent.public, PQ[agentPq].public, { trustedPk: PQ[agentPq].public }) : undefined;
    if (!R.verifyWithSuite(alg, { edPub: ED.agent.public, ...(pin ? { pq: pin } : {}) }, utf8(msgText), parts)) throw new Error('suite_sign does not verify: ' + alg);
    if (agentPq) osslCheck(alg, PQ[agentPq].public, utf8(msgText), parts);
    add({ name: `suite-sign-${alg}`, op: 'suite_sign', alg, exact, args: { alg, ed: hasEd ? 'agent' : null, pq: agentPq, message_utf8: msgText }, expect: parts });

    // mint_root_suite: the principal roots a grant for the agent, committing the agent's PQ key (holder_pq)
    const goal_commit = R.goalCommitOf('pq vector goal ' + alg, 'pq-salt');
    const caveats = [{ type: 'envelope', goal_commit, predicates: [{ verb: 'read', resource: 'orders/*' }, { verb: 'refund', resource: 'orders/*' }], caveats: [], agent_binding: {}, risk_policy: RISK }];
    const rootArgs = { alg, principal: 'principal', pq: pqOf('principal', family), holder: 'agent', holder_pq: agentPq, caveats };
    const root = R.mintRoot({ principalSecret: ED.principal.sk, principalPublic: ED.principal.public, holder: ED.agent.public, ...(agentPq ? { holderPq: PQ[agentPq].public } : {}), caveats, suite: suiteOf('principal') });
    const principalPins = family ? { [ED.principal.public]: PQ[pqOf('principal', family)].public } : {};
    const vr = R.verifyChain([root], ED.principal.public, { pqPins: principalPins });
    if (!vr.ok) throw new Error(`mint_root_suite ${alg}: ${vr.reason}`);
    if (family) osslCheck(alg, root.pq_pk, cat(utf8('atlas-pca/cap/v1\0'), unb64u(root.body_digest)), root);
    add({ name: `mint-root-${alg}`, op: 'mint_root_suite', alg, exact, args: rootArgs, expect: plain(root) });

    // delegate_suite: the agent hands a sub-agent its own PQ key (holder_pq = the sub-agent's key, never the parent's)
    const subPq = pqOf('subagent', family);
    const delArgs = { alg, parent: plain(root), signer: 'agent', pq: agentPq, to_holder: 'subagent', holder_pq: subPq, added_caveats: [{ type: 'budget_alloc', limit: 5 }] };
    const del = R.delegate(root, ED.subagent.public, delArgs.added_caveats, ED.agent.sk, suiteOf('agent'), subPq ? PQ[subPq].public : undefined);
    const vd = R.verifyChain([root, del], ED.principal.public, { pqPins: principalPins });
    if (!vd.ok) throw new Error(`delegate_suite ${alg}: ${vd.reason}`);
    if (family) osslCheck(alg, del.pq_pk, cat(utf8('atlas-pca/cap/v1\0'), unb64u(del.body_digest)), del);
    add({ name: `delegate-${alg}`, op: 'delegate_suite', alg, exact, args: delArgs, expect: plain(del) });

    // sign_pcactn_suite: an unsigned body (buildPCActn output minus `sig`) signed under the suite; agent leaf and sub-agent leaf
    const plan = [{ id: 'n0', verb: 'refund', resource: 'orders/1', reversibility_class: 'compensable', params_digest: R.paramsDigest({ amount_cents: 500, currency: 'USD' }) }];
    for (const [who, chain, counter] of [['agent', [root], 1], ['subagent', [root, del], 2]]) {
      const built = R.buildPCActn({ grant: root, chain, plan, nodeId: 'n0', params: { amount_cents: 500, currency: 'USD' }, counter, signerSecret: ED[who].sk, aud: AUD, iat: T0, exp: T0 + 1_200_000, nonce: NONCE(alg + who) });
      const { sig: _drop, ...body } = built;
      void _drop;
      const leafPq = pqOf(who, family);
      const p = R.signPCActnSuite(body, { alg, edLeafSecret: ED[who].sk, ...(leafPq ? { [FAMILIES[family].slot]: PQ[leafPq].material } : {}) });
      const v = await R.verifyPCActnCore(p, { grant: root, nowEpoch: T0 + 1000, audience: AUD, insecureSkipPlanRootCheck: true });
      if (!v.allow) throw new Error(`sign_pcactn_suite ${alg}/${who}: ${JSON.stringify(v.checks)}`);
      if (family) osslCheck(alg, p.pq_pk, R.thresholdMessage(p), p);
      add({ name: `sign-pcactn-${alg}-${who}`, op: 'sign_pcactn_suite', alg, exact, args: { alg, signer: who, pq: leafPq, body: plain(body) }, expect: { pcactn: plain(p) } });
    }

    // sign_artifact_suite: escalation answer + revocation epoch, signed by the principal under the suite
    const principalPq = pqOf('principal', family);
    const pinned = { pk: ED.principal.public, ...(principalPq ? { pq_pk: PQ[principalPq].public } : {}) };
    const dig = (s) => b64u(sha('producer-pq-vector:' + s));
    const ansBody = { v: 1, kind: 'pca-escalation-answer', principal: ED.principal.public, policy_digest: dig('pol'), action_digest: dig('act'), history_head: dig('hist'), decision: 'allow', iat: T0, expires_at: T0 + 600_000, nonce: NONCE('ans' + alg) };
    const ans = R.signEscalationAnswer(ansBody, ED.principal.sk, suiteOf('principal'));
    const va = R.verifyEscalationAnswer(ans, [pinned], { policy_digest: ansBody.policy_digest, action_digest: ansBody.action_digest, history_head: ansBody.history_head }, T0 + 1000);
    if (!va.ok) throw new Error(`escalation answer ${alg}: ${va.reason}`);
    if (family) {
      const { sig: _s, pq_sig: _q, ...ansSigned } = ans;
      osslCheck(alg, ans.pq_pk, cat(utf8(R.ESCALATION_ANSWER_DOMAIN), R.canonicalBytes(ansSigned)), ans);
    }
    add({ name: `artifact-escalation-answer-${alg}`, op: 'sign_artifact_suite', alg, exact, args: { kind: 'escalation_answer', alg, signer: 'principal', pq: principalPq, body: ansBody }, expect: plain(ans) });

    const epBody = { instance_id: 'inst_pq', grant_ref: root.id, epoch: 4, set_size: 2, root: dig('revset'), issued_at: T0, not_after: T0 + 3_600_000 };
    const ep = R.signRevocationEpoch(ED.principal.sk, epBody, suiteOf('principal'));
    const ve = R.checkRevocationEpoch(ep, { guardianPublic: ED.principal.public, now: T0 + 1000, grantRef: root.id, pqPins: principalPq ? { [ED.principal.public]: PQ[principalPq].public } : {} });
    if (!ve.ok) throw new Error(`revocation epoch ${alg}: ${ve.reason}`);
    if (family) {
      const bound = { ...epBody, alg: ep.alg, pq_pk: ep.pq_pk };
      osslCheck(alg, ep.pq_pk, cat(utf8('atlas-pca/revepoch/v1\0'), R.canonicalBytes(bound)), ep);
    }
    add({ name: `artifact-revocation-epoch-${alg}`, op: 'sign_artifact_suite', alg, exact, args: { kind: 'revocation_epoch', alg, signer: 'principal', pq: principalPq, body: epBody }, expect: plain(ep) });
  }

  return {
    format: 1,
    suite: 'producer-pq',
    layer: 'agent-side signing (post-quantum)',
    description:
      'Exact outputs of the post-quantum producers for every registered suite except LESS (LESS signing is TypeScript only). ' +
      'ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) sign in their DETERMINISTIC variant (ML-DSA rnd = 32 zero bytes; SLH-DSA opt_rand = PK.seed), ' +
      'with the pure (empty-context) interface; keygen is seeded (ML-DSA: the 32-byte xi; SLH-DSA: SK.seed || SK.prf || PK.seed); ' +
      'FN-DSA keygen and signing are seeded (SHAKE256 over the 32-byte seed / sign_seed). So `expect` is reproducible byte for byte. ' +
      '`ed_keys` are the Ed25519 identities (the same seeds as producer-vectors.json); `pq_keys` are named `<role>/<family>`. ' +
      'In `args`, `principal`/`holder`/`signer`/`to_holder`/`ed` name an Ed25519 key, and `pq`/`holder_pq` name a PQ key (null = none); ' +
      '`holder_pq` commits that key\'s `public`. `exact` lists the languages that must reproduce `expect` byte for byte (compare parsed JSON); ' +
      'every other language that verifies the suite must ACCEPT the expected artifact under the reference verifiers instead. ' +
      'sign_pcactn_suite signs a ready body (`args.body`, a PCActn without `sig`): bind `alg` and `pq_pk` into it, then sign ' +
      '"atlas-pca/actn/v2\\u0000" || sha256(canonical(body)) (the header encoding is covered by producer-vectors.json). ' +
      'sign_artifact_suite `kind` is escalation_answer (signEscalationAnswer) or revocation_epoch (signRevocationEpoch; the guardian is `signer`).',
    ed_keys: Object.fromEntries(Object.entries(ED).map(([n, k]) => [n, { seed: k.seed, public: k.public }])),
    pq_keys: pqKeys,
    cases,
  };
}

const first = JSON.stringify(await build(), null, 2) + '\n';
const checkedOnce = osslChecked;
const second = JSON.stringify(await build(), null, 2) + '\n';
if (first !== second) throw new Error('two runs produced different bytes: post-quantum signing is not deterministic (check the @noble/post-quantum version)');
if (checkedOnce === 0) throw new Error('no OpenSSL cross-check ran');
process.stderr.write(`producer-pq-vectors: ${JSON.parse(first).cases.length} cases, ${checkedOnce} PQ signatures cross-checked with OpenSSL, deterministic across two runs\n`);
process.stdout.write(first);
