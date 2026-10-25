// PCA 0.4.2 Intent Layer v2, rule 14 (`pca-action-schema` v1): verdicts and values of the TypeScript reference
// (packages/pca/src/action-schema.ts, canonProjection from intent-v2.ts) that the guest's `action_schema` module must reproduce.
//   shape:   actionSchemaShapeError(doc, {signed})
//   verify:  verifyActionSchema(doc, keys)          (guest_unsupported: informational; v2_schema.rs decides with
//            pq_suites::suite_supported: a suite the guest lacks (less) must fail with `unsupported_suite`)
//   conformance_primitives / conformance_vectors: copied from packages/pca/conformance/vectors.json (primitives.intent_schema;
//            the schema docs/keys of the schema-* vectors with requires_suite / reason_contains)
//   digest:  actionSchemaDigest(doc) (null = throws)
//   conform: conformAction(doc, verb, params) + canonProjection (for conforming actions)
//   rev:     reversibilityOf / verbReversibility
//     packages/pca/node_modules/.bin/tsx sdks/zkvm-pca/core/tests/gen_ts_v2_schema.ts <out.json>
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import {
  actionSchemaShapeError,
  verifyActionSchema,
  actionSchemaDigest,
  signActionSchema,
  actionSchemaKeyOf,
  conformAction,
  reversibilityOf,
  verbReversibility,
} from '../../../../packages/pca/src/action-schema';
import { canonProjection } from '../../../../packages/pca/src/intent-v2';
import { mlDsa65Keygen, mlDsa87Keygen, slhDsa128fKeygen } from '../../../../packages/pca/src/pq';

const out = process.argv[2];
if (!out) throw new Error('usage: gen_ts_v2_schema.ts <out.json>');
const seed = (label: string) => new Uint8Array(createHash('sha256').update(label).digest());
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const tail = (s: string) => {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  return s.slice(0, -1) + A[A.indexOf(s.at(-1)!) ^ 1];
};
const b64 = (n: number) => Buffer.alloc(n, 7).toString('base64url');

const SK = seed('schema-site-key');
const SK2 = seed('schema-other-key');
const P = 'action.params.';

const base: any = {
  v: 1,
  kind: 'pca-action-schema',
  site: 'https://shop.example',
  aud: 'shop.example',
  version: '2026-10-01',
  units: { 'money.usd_cents': { kind: 'money', currency: 'USD', exponent: 2 }, count: { kind: 'count' } },
  state: [],
  verbs: [
    {
      verb: 'order.place',
      kind: 'write',
      params: {
        [P + 'amount']: { type: 'integer', semantic: 'money.amount', sensitivity: 'critical', min: 1, max: 100000, unit: 'money.usd_cents', accumulates_into: ['spend.total', 'spend.day'] },
        [P + 'currency']: { type: 'string', semantic: 'money.currency', sensitivity: 'material', values: ['USD', 'EUR', 'é€'] },
        [P + 'note']: { type: 'string', semantic: 'text.note', sensitivity: 'free', required: false, max_len: 8 },
        [P + 'desc']: { type: 'string', semantic: 'text.desc', sensitivity: 'free', required: false },
        [P + 'gift']: { type: 'boolean', semantic: 'flag.gift', sensitivity: 'free', required: false, default: false, principal_neutral_default: true },
        [P + 'ship_on']: { type: 'date', semantic: 'time.date', sensitivity: 'material', required: false },
        [P + 'tags']: { type: 'set', semantic: 'meta.tags', sensitivity: 'free', values: ['b', 'a', 'c', 'Z', 'é'], required: false, min_items: 1, max_items: 3 },
        [P + 'colors']: { type: 'set', semantic: 'meta.colors', sensitivity: 'free', values: ['red', 'green'], required: false },
        [P + 'qty']: { type: 'array', items: 'integer', semantic: 'count.qty', sensitivity: 'material', min: 0, max: 10, required: false, max_items: 3, min_items: 1 },
        [P + 'skus']: { type: 'array', semantic: 'item.sku', sensitivity: 'material', required: false, max_len: 4, items: 'sku' },
        [P + 'ids']: { type: 'array', semantic: 'item.id', sensitivity: 'free', required: false },
        [P + 'big']: { type: 'integer', semantic: 'count.big', sensitivity: 'free', required: false, unit: 'count', issued_by_site: true, description: 'unbounded' },
      },
      reversibility_by: { param: P + 'gift', map: { true: 'reversible' }, default: 'rate_limited' },
    },
    {
      verb: 'order.get',
      kind: 'read',
      params: { [P + 'id']: { type: 'string', semantic: 'order.id', sensitivity: 'free' } },
      mcp: { tool: 'get_order' },
      openapi: { operationId: 'getOrder' },
      harm: {},
      world: [],
      effects: {},
      returns: {},
      description: 'Read an order',
      reversibility: 'reversible',
    },
    { verb: 'noop', kind: 'write', params: {} },
  ],
};
const signed = signActionSchema(clone(base), 'k1', SK) as any;
const KEY = actionSchemaKeyOf('k1', SK);

// ---------------------------------------------------------------- shape
const shape: any[] = [];
const sh = (name: string, mut: (d: any) => void, opts: { signed?: boolean } = {}) => {
  const d = clone(opts.signed === false ? base : signed);
  mut(d);
  shape.push({ name, doc: d, signed: opts.signed !== false, err: actionSchemaShapeError(d, opts) });
};
const v0 = (d: any) => d.verbs[0];
const pa = (d: any, n = 'amount') => d.verbs[0].params[P + n];
sh('baseline', () => {});
sh('unsigned baseline', () => {}, { signed: false });
sh('unsigned carries sig', (d) => (d.sig = signed.sig), { signed: false });
// doc level
for (const x of [[], null, 'x', 7]) shape.push({ name: `doc ${JSON.stringify(x)}`, doc: x, signed: true, err: actionSchemaShapeError(x) });
sh('doc unknown member', (d) => (d.extra = 1));
sh('doc constructor member', (d) => (d['constructor'] = 1));
sh('v=2', (d) => (d.v = 2));
sh('v="1"', (d) => (d.v = '1'));
sh('v missing', (d) => delete d.v);
sh('kind wrong', (d) => (d.kind = 'pca-action-schemas'));
sh('site empty', (d) => (d.site = ''));
sh('site 2048', (d) => (d.site = 's'.repeat(2048)));
sh('site 2049', (d) => (d.site = 's'.repeat(2049)));
sh('aud 256 bytes multibyte', (d) => (d.aud = 'é'.repeat(128)));
sh('aud 258 bytes multibyte', (d) => (d.aud = 'é'.repeat(129)));
sh('version 129', (d) => (d.version = 'v'.repeat(129)));
sh('version number', (d) => (d.version = 3));
sh('units not object', (d) => (d.units = []));
sh('units null', (d) => (d.units = null));
sh('unit id malformed', (d) => (d.units['Money'] = { kind: 'money' }));
sh('unit id trailing dot', (d) => (d.units['a.'] = { kind: 'money' }));
sh('unit id 64', (d) => (d.units['u'.repeat(64)] = { kind: 'k' }));
sh('unit id 65', (d) => (d.units['u'.repeat(65)] = { kind: 'k' }));
sh('unit not object', (d) => (d.units.count = 'x'));
sh('unit no kind', (d) => (d.units.count = { currency: 'USD' }));
sh('unit kind 65', (d) => (d.units.count = { kind: 'k'.repeat(65) }));
sh('unit unknown member', (d) => (d.units.count.extra = 1));
sh('unit currency 17', (d) => (d.units.count.currency = 'c'.repeat(17)));
sh('unit currency number', (d) => (d.units.count.currency = 1));
sh('unit exponent 18', (d) => (d.units.count.exponent = 18));
sh('unit exponent 19', (d) => (d.units.count.exponent = 19));
sh('unit exponent -1', (d) => (d.units.count.exponent = -1));
sh('unit exponent 1.5', (d) => (d.units.count.exponent = 1.5));
sh('state not array', (d) => (d.state = {}));
sh('state absent', (d) => delete d.state);
sh('units absent (unit refs break)', (d) => delete d.units);
sh('verbs empty', (d) => (d.verbs = []));
sh('verbs not array', (d) => (d.verbs = {}));
sh('verbs 257', (d) => (d.verbs = Array.from({ length: 257 }, (_, i) => ({ verb: 'v' + i, kind: 'read', params: {} }))));
sh('verbs 256', (d) => (d.verbs = Array.from({ length: 256 }, (_, i) => ({ verb: 'v' + i, kind: 'read', params: {} }))));
sh('verb duplicate', (d) => d.verbs.push({ verb: 'noop', kind: 'read', params: {} }));
// verb level
sh('verb entry not object', (d) => d.verbs.push(5));
sh('verb entry null', (d) => d.verbs.push(null));
sh('verb unknown member', (d) => (v0(d).extra = 1));
sh('verb name empty', (d) => (v0(d).verb = ''));
sh('verb name 129', (d) => (v0(d).verb = 'v'.repeat(129)));
sh('verb name number', (d) => (v0(d).verb = 1));
sh('verb kind bad', (d) => (v0(d).kind = 'delete'));
sh('verb params array', (d) => (v0(d).params = []));
sh('verb params absent', (d) => delete v0(d).params);
sh('verb 64 params', (d) => (v0(d).params = Object.fromEntries(Array.from({ length: 64 }, (_, i) => [P + 'p' + i, { type: 'boolean', semantic: 's', sensitivity: 'free' }]))));
sh('verb 65 params', (d) => (v0(d).params = Object.fromEntries(Array.from({ length: 65 }, (_, i) => [P + 'p' + i, { type: 'boolean', semantic: 's', sensitivity: 'free' }]))));
sh('verb reversibility bad', (d) => (d.verbs[1].reversibility = 'maybe'));
sh('verb reversibility null', (d) => (d.verbs[1].reversibility = null));
sh('rev_by not object', (d) => (v0(d).reversibility_by = 'x'));
sh('rev_by unknown member', (d) => (v0(d).reversibility_by.extra = 1));
sh('rev_by param undeclared', (d) => (v0(d).reversibility_by.param = P + 'nope'));
sh('rev_by param number', (d) => (v0(d).reversibility_by.param = 1));
sh('rev_by map empty', (d) => (v0(d).reversibility_by.map = {}));
sh('rev_by map bad class', (d) => (v0(d).reversibility_by.map = { true: 'undo' }));
sh('rev_by map array', (d) => (v0(d).reversibility_by.map = ['reversible']));
sh('rev_by default bad', (d) => (v0(d).reversibility_by.default = 'x'));
sh('rev_by no default', (d) => delete v0(d).reversibility_by.default);
sh('mcp extra member', (d) => (d.verbs[1].mcp.extra = 'x'));
sh('mcp tool empty', (d) => (d.verbs[1].mcp.tool = ''));
sh('mcp tool 129', (d) => (d.verbs[1].mcp.tool = 't'.repeat(129)));
sh('mcp wrong key', (d) => (d.verbs[1].mcp = { name: 'x' }));
sh('mcp empty object', (d) => (d.verbs[1].mcp = {}));
sh('openapi extra', (d) => (d.verbs[1].openapi.x = 1));
sh('openapi not object', (d) => (d.verbs[1].openapi = 'getOrder'));
sh('harm array', (d) => (d.verbs[1].harm = []));
sh('effects null', (d) => (d.verbs[1].effects = null));
sh('returns string', (d) => (d.verbs[1].returns = 's'));
sh('world object', (d) => (d.verbs[1].world = {}));
sh('verb description 1025', (d) => (d.verbs[1].description = 'd'.repeat(1025)));
sh('verb description empty', (d) => (d.verbs[1].description = ''));
// param level
sh('param path bad prefix', (d) => (v0(d).params['params.x'] = { type: 'boolean', semantic: 's', sensitivity: 'free' }));
sh('param path nested', (d) => (v0(d).params[P + 'a.b'] = { type: 'boolean', semantic: 's', sensitivity: 'free' }));
sh('param path 64', (d) => (v0(d).params[P + 'n'.repeat(64)] = { type: 'boolean', semantic: 's', sensitivity: 'free' }));
sh('param path 65', (d) => (v0(d).params[P + 'n'.repeat(65)] = { type: 'boolean', semantic: 's', sensitivity: 'free' }));
sh('param path empty name', (d) => (v0(d).params[P] = { type: 'boolean', semantic: 's', sensitivity: 'free' }));
sh('param decl not object', (d) => (v0(d).params[P + 'x'] = 'string'));
sh('param unknown member', (d) => (pa(d).extra = 1));
sh('param type unknown', (d) => (pa(d).type = 'number'));
sh('param type absent', (d) => delete pa(d).type);
sh('param semantic empty', (d) => (pa(d).semantic = ''));
sh('param semantic 129', (d) => (pa(d).semantic = 's'.repeat(129)));
sh('param sensitivity bad', (d) => (pa(d).sensitivity = 'high'));
sh('param required string', (d) => (pa(d).required = 'yes'));
sh('param required null', (d) => (pa(d).required = null));
sh('values empty', (d) => (pa(d, 'currency').values = []));
sh('values not array', (d) => (pa(d, 'currency').values = 'USD'));
sh('values 256', (d) => (pa(d, 'currency').values = Array.from({ length: 256 }, (_, i) => 'v' + i)));
sh('values 257', (d) => (pa(d, 'currency').values = Array.from({ length: 257 }, (_, i) => 'v' + i)));
sh('values item empty', (d) => (pa(d, 'currency').values = ['USD', '']));
sh('values item 257 bytes', (d) => (pa(d, 'currency').values = ['x'.repeat(257)]));
sh('values item number', (d) => (pa(d, 'currency').values = ['USD', 1]));
sh('values duplicate', (d) => (pa(d, 'currency').values = ['USD', 'USD']));
sh('values on integer', (d) => (pa(d).values = ['1']));
sh('values on boolean', (d) => (pa(d, 'gift').values = ['true']));
sh('set without values', (d) => delete pa(d, 'tags').values);
sh('min on string', (d) => (pa(d, 'currency').min = 1));
sh('max on boolean', (d) => (pa(d, 'gift').max = 1));
sh('min on array of strings', (d) => (pa(d, 'skus').min = 1));
sh('min float', (d) => (pa(d).min = 1.5));
sh('min unsafe', (d) => (pa(d).min = 2 ** 53));
sh('min null', (d) => (pa(d).min = null));
sh('min > max', (d) => (pa(d).min = 100001));
sh('min == max', (d) => (pa(d).min = 100000));
sh('min > max on int array', (d) => (pa(d, 'qty').min = 11));
sh('unit on string', (d) => (pa(d, 'currency').unit = 'count'));
sh('unit undeclared', (d) => (pa(d).unit = 'money.eur'));
sh('unit number', (d) => (pa(d).unit = 1));
sh('max_len 0', (d) => (pa(d, 'note').max_len = 0));
sh('max_len 1', (d) => (pa(d, 'note').max_len = 1));
sh('max_len float', (d) => (pa(d, 'note').max_len = 2.5));
sh('max_len string', (d) => (pa(d, 'note').max_len = '8'));
sh('items on string', (d) => (pa(d, 'note').items = 'integer'));
sh('items empty', (d) => (pa(d, 'skus').items = ''));
sh('items 65', (d) => (pa(d, 'skus').items = 'i'.repeat(65)));
sh('min_items on string', (d) => (pa(d, 'note').min_items = 0));
sh('min_items -1', (d) => (pa(d, 'tags').min_items = -1));
sh('max_items float', (d) => (pa(d, 'tags').max_items = 1.5));
sh('min_items > max_items', (d) => (pa(d, 'tags').min_items = 4));
sh('min_items == max_items', (d) => (pa(d, 'tags').min_items = 3));
sh('pnd string', (d) => (pa(d, 'gift').principal_neutral_default = 'true'));
sh('pnd without default', (d) => delete pa(d, 'gift').default);
sh('pnd false without default', (d) => ((pa(d, 'gift').principal_neutral_default = false), delete pa(d, 'gift').default));
sh('default null with pnd', (d) => (pa(d, 'gift').default = null));
sh('acc on string', (d) => (pa(d, 'note').accumulates_into = ['x']));
sh('acc empty', (d) => (pa(d).accumulates_into = []));
sh('acc 8', (d) => (pa(d).accumulates_into = Array.from({ length: 8 }, (_, i) => 'u' + i)));
sh('acc 9', (d) => (pa(d).accumulates_into = Array.from({ length: 9 }, (_, i) => 'u' + i)));
sh('acc not array', (d) => (pa(d).accumulates_into = 'spend'));
sh('acc bad id', (d) => (pa(d).accumulates_into = ['Spend']));
sh('acc id 65', (d) => (pa(d).accumulates_into = ['s'.repeat(65)]));
sh('acc id 64', (d) => (pa(d).accumulates_into = ['s'.repeat(64)]));
sh('acc duplicate', (d) => (pa(d).accumulates_into = ['a', 'a']));
sh('acc number', (d) => (pa(d).accumulates_into = [1]));
sh('issued_by_site string', (d) => (pa(d, 'big').issued_by_site = 'yes'));
sh('param description 1025', (d) => (pa(d, 'big').description = 'd'.repeat(1025)));
sh('param description 1024', (d) => (pa(d, 'big').description = 'd'.repeat(1024)));
sh('param description number', (d) => (pa(d, 'big').description = 1));
// strict pass: reserved names, null default, own __proto__ data
sh('param name __proto__', (d) => (v0(d).params[P + '__proto__'] = { type: 'boolean', semantic: 's', sensitivity: 'free' }));
sh('param name constructor', (d) => (v0(d).params[P + 'constructor'] = { type: 'boolean', semantic: 's', sensitivity: 'free' }));
sh('param name prototype', (d) => (v0(d).params[P + 'prototype'] = { type: 'boolean', semantic: 's', sensitivity: 'free' }));
sh('param name Prototype ok', (d) => (v0(d).params[P + 'Prototype'] = { type: 'boolean', semantic: 's', sensitivity: 'free', required: false }));
sh('param default null', (d) => (pa(d, 'note').default = null));
sh('param default 0 ok', (d) => (pa(d, 'note').default = 0));
sh('rev_by map own __proto__', (d) => (v0(d).reversibility_by.map = JSON.parse('{"__proto__":"reversible","true":"rate_limited"}')));
sh('rev_by map own __proto__ bad class', (d) => (v0(d).reversibility_by.map = JSON.parse('{"__proto__":"undo"}')));
sh('unit id constructor', (d) => (d.units['constructor'] = { kind: 'k' }));
// sig level
sh('sig absent', (d) => delete d.sig);
sh('sig not object', (d) => (d.sig = 'x'));
sh('sig unknown member', (d) => (d.sig.extra = 1));
sh('sig alg unknown', (d) => (d.sig.alg = 'rsa'));
sh('sig alg null', (d) => (d.sig.alg = null));
sh('sig alg absent', (d) => delete d.sig.alg);
sh('sig alg PQ name', (d) => (d.sig.alg = 'ml-dsa-65'));
sh('sig kid empty', (d) => (d.sig.kid = ''));
sh('sig kid 129', (d) => (d.sig.kid = 'k'.repeat(129)));
sh('sig value non-canonical', (d) => (d.sig.value = tail(d.sig.value)));
sh('sig value padded', (d) => (d.sig.value = d.sig.value + '='));
sh('sig value len%4==1', (d) => (d.sig.value = 'AAAAA'));
sh('sig value empty', (d) => (d.sig.value = ''));
sh('sig value number', (d) => (d.sig.value = 1));
sh('sig pq_value bad', (d) => (d.sig.pq_value = '!!'));
sh('sig pq_value ok', (d) => (d.sig.pq_value = b64(5)));
// strict canonical profile (body)
sh('state unsafe int', (d) => (d.state = [2 ** 53]));
sh('state float 16 digits', (d) => (d.state = [0.1234567890123456]));
sh('state float ok', (d) => (d.state = [0.5]));
sh('state tiny float', (d) => (d.state = [1e-7]));
sh('harm unsafe negative', (d) => (d.verbs[1].harm = { x: -(2 ** 53) }));
sh('default unsafe', (d) => (pa(d, 'gift').default = 2 ** 60));
sh('state depth 31', (d) => { let x: any = []; for (let i = 0; i < 29; i++) x = [x]; d.state = x; });
sh('state depth 32', (d) => { let x: any = []; for (let i = 0; i < 30; i++) x = [x]; d.state = x; });
sh('state depth 33', (d) => { let x: any = []; for (let i = 0; i < 31; i++) x = [x]; d.state = x; });

// ---------------------------------------------------------------- verify
const verify: any[] = [];
const vf = (name: string, doc: any, keys: any, guestUnsupported = false) => {
  const r = verifyActionSchema(doc, keys) as any;
  verify.push({ name, doc, keys, ok: r.ok, reason: r.ok ? null : r.reason, guest_unsupported: guestUnsupported });
};
vf('ok', signed, [KEY]);
vf('ok second key', signed, [{ kid: 'k0', alg: 'ed25519', pk: actionSchemaKeyOf('k0', SK2).pk }, KEY]);
vf('ok key alg absent', signed, [{ kid: 'k1', pk: KEY.pk }]);
vf('ok sig alg absent', (() => { const d = clone(signed); delete d.sig.alg; return d; })(), [KEY]);
vf('ok non-object key skipped', signed, [null, 5, 'k1', KEY]);
vf('ok ed25519 with stray pq_value', (() => { const d = clone(signed); d.sig.pq_value = b64(10); return d; })(), [KEY]);
vf('ok key with pq_pk ignored for ed25519', signed, [{ ...KEY, pq_pk: b64(32) }]);
vf('ok unicode', signActionSchema({ ...clone(base), site: 'https://ünï.example/✓' }, 'k1', SK), [KEY]);
vf('tampered body', { ...clone(signed), version: '2026-10-02' }, [KEY]);
vf('tampered verb', (() => { const d = clone(signed); d.verbs[0].params[P + 'amount'].max = 100001; return d; })(), [KEY]);
vf('wrong signer', signActionSchema(clone(base), 'k1', SK2), [KEY]);
vf('sig flipped', (() => { const d = clone(signed); d.sig.value = (d.sig.value[0] === 'A' ? 'B' : 'A') + d.sig.value.slice(1); return d; })(), [KEY]);
vf('sig 63 bytes', (() => { const d = clone(signed); d.sig.value = b64(63); return d; })(), [KEY]);
vf('sig zero 64', (() => { const d = clone(signed); d.sig.value = Buffer.alloc(64).toString('base64url'); return d; })(), [KEY]);
vf('wrong kid', signed, [{ ...KEY, kid: 'k2' }]);
vf('first matching kid has wrong pk', signed, [{ ...KEY, pk: actionSchemaKeyOf('k1', SK2).pk }, KEY]);
vf('keys empty', signed, []);
vf('keys not array', signed, { k1: KEY });
vf('keys null', signed, null);
vf('key pk 31 bytes', signed, [{ ...KEY, pk: b64(31) }]);
vf('key pk non-canonical', signed, [{ ...KEY, pk: tail(KEY.pk) }]);
vf('key pk absent', signed, [{ kid: 'k1', alg: 'ed25519' }]);
vf('key pk number', signed, [{ kid: 'k1', alg: 'ed25519', pk: 1 }]);
vf('key alg mismatch PQ', signed, [{ ...KEY, alg: 'ml-dsa-65' }]);
vf('key alg unknown', signed, [{ ...KEY, alg: 'rsa' }]);
vf('key alg null', signed, [{ ...KEY, alg: null }]);
vf('sig alg hybrid vs key ed25519', (() => { const d = clone(signed); d.sig.alg = 'hybrid-ed25519-ml-dsa-65'; return d; })(), [KEY]);
vf('shape failure surfaces', { ...clone(signed), extra: 1 }, [KEY]);
vf('doc not object', 'x', [KEY]);
// PQ suites the guest implements (crate::pq_suites): exact TS parity
{
  const mlDsa = mlDsa65Keygen(seed('schema-mldsa'));
  const mlDsa87 = mlDsa87Keygen(seed('schema-mldsa87'));
  const slhDsa = slhDsa128fKeygen(new Uint8Array(createHash('sha512').update('schema-slh').digest().subarray(0, 48)));
  const other: any = {
    mlDsa: mlDsa65Keygen(seed('schema-mldsa-other')),
    mlDsa87: mlDsa87Keygen(seed('schema-mldsa87-other')),
    slhDsa: slhDsa128fKeygen(new Uint8Array(createHash('sha512').update('schema-slh-other').digest().subarray(0, 48))),
  };
  const suites: any[] = [
    { alg: 'ml-dsa-65', mlDsa },
    { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa },
    { alg: 'hybrid-nested-ed25519-ml-dsa-65', mlDsa },
    { alg: 'ml-dsa-87', mlDsa87 },
    { alg: 'hybrid-ed25519-ml-dsa-87', mlDsa87 },
    { alg: 'slh-dsa-sha2-128f', slhDsa },
    { alg: 'hybrid-ed25519-slh-dsa-sha2-128f', slhDsa },
  ];
  for (const suite of suites) {
    const alg = suite.alg;
    const d = signActionSchema(clone(base), 'kpq', SK, suite);
    const key = actionSchemaKeyOf('kpq', SK, suite);
    vf(`pq ${alg} ok`, d, [key]);
    vf(`pq ${alg} tampered`, { ...clone(d), version: 'x' }, [key]);
    vf(`pq ${alg} key downgraded to ed25519`, d, [{ kid: 'kpq', alg: 'ed25519', pk: key.pk }]);
    vf(`pq ${alg} key without pq_pk (no pin)`, d, [{ kid: 'kpq', alg, pk: key.pk }]);
    vf(`pq ${alg} key pq_pk of another key`, d, [{ ...key, pq_pk: actionSchemaKeyOf('kpq', SK, { ...other, alg }).pq_pk }]);
    if (d.sig.pq_value !== undefined) vf(`pq ${alg} pq_value dropped`, (() => { const x = clone(d); delete x.sig.pq_value; return x; })(), [key]);
    if (alg !== 'ml-dsa-65') vf(`pq ${alg} sig.alg relabelled ml-dsa-65`, (() => { const x = clone(d); x.sig.alg = 'ml-dsa-65'; return x; })(), [{ ...key, alg: 'ml-dsa-65' }]);
  }
  // registered suites the guest does not implement (LESS; FN-DSA is implemented since fn-dsa-vrfy): unsupported_suite
  // FN-DSA (implemented by the guest): a garbage pq_pk / signature fails in both
  for (const alg of ['fn-dsa-512', 'fn-dsa-1024']) {
    const d = clone(signed);
    d.sig.alg = alg;
    vf(`fn-dsa garbage ${alg}`, d, [{ ...KEY, alg, pq_pk: b64(32) }]);
  }
  for (const alg of ['less-cat1', 'hybrid-ed25519-less-cat1']) {
    const d = clone(signed);
    d.sig.alg = alg;
    vf(`guest-unsupported ${alg}`, d, [{ ...KEY, alg, pq_pk: b64(32) }], true);
  }
}
// strict pass: key typing, unknown suites
vf('key pq_pk null', signed, [{ ...KEY, pq_pk: null }]);
vf('key pq_pk number', signed, [{ ...KEY, pq_pk: 5 }]);
vf('key alg number', signed, [{ ...KEY, alg: 1 }]);
vf('key alg unknown string', signed, [{ ...KEY, alg: 'x-unknown-suite' }]);
vf('sig alg unknown string', (() => { const d = clone(signed); d.sig.alg = 'x-unknown-suite'; return d; })(), [KEY]);
vf('sig alg null', (() => { const d = clone(signed); d.sig.alg = null; return d; })(), [KEY]);
vf('keys string', signed, 'k1');

// ---------------------------------------------------------------- digest
const digest: any[] = [];
const dg = (name: string, doc: any) => {
  let r: string | null;
  try {
    r = actionSchemaDigest(doc);
  } catch {
    r = null;
  }
  digest.push({ name, doc, digest: r });
};
dg('signed', signed);
dg('unsigned', base);
dg('unicode', { ...clone(signed), site: 'ü✓𝄞' });
dg('float', { ...clone(signed), state: [0.25, 1e21 / 1e21] });
dg('unsafe int', { ...clone(signed), state: [2 ** 53] });
dg('depth 31 under s', (() => { const d = clone(signed); let x: any = []; for (let i = 0; i < 29; i++) x = [x]; d.state = x; return d; })());
dg('depth 32 under s (33 total)', (() => { const d = clone(signed); let x: any = []; for (let i = 0; i < 30; i++) x = [x]; d.state = x; return d; })());
dg('string', 'x');
dg('null', null);

// ---------------------------------------------------------------- conform + canon
const conform: any[] = [];
const cf = (name: string, verb: string, params: any, doc: any = signed) => {
  const r = conformAction(doc, verb, params) as any;
  const row: any = { name, doc: doc === signed ? null : doc, verb, params, ok: r.ok };
  if (!r.ok) Object.assign(row, { code: r.code, path: r.path ?? null, reason: r.reason });
  try {
    row.canon = canonProjection(doc, verb, params && typeof params === 'object' && !Array.isArray(params) ? params : {});
  } catch {
    row.canon = null;
  }
  if (!r.ok) row.canon = null;
  conform.push(row);
};
const ok = { amount: 500, currency: 'USD' };
cf('minimal', 'order.place', ok);
cf('full', 'order.place', { ...ok, note: 'hi', desc: 'x', gift: true, ship_on: '2024-02-29', tags: ['c', 'a', 'é', 'Z'].slice(0, 3), colors: ['green', 'red'], qty: [0, 10, 5], skus: ['ab', 'é€'], ids: ['x', 'y'], big: -9007199254740991 });
cf('gift false', 'order.place', { ...ok, gift: false, tags: ['é', 'Z', 'a'] });
cf('canon arrays', 'order.place', { ...ok, qty: [3], skus: [], ids: Array.from({ length: 64 }, (_, i) => String(i)) });
cf('read verb', 'order.get', { id: 'o1' });
cf('noop', 'noop', {});
cf('params array', 'order.place', []);
cf('params null', 'order.place', null);
cf('params string', 'order.place', 'x');
cf('unknown verb', 'order.cancel', ok);
cf('unknown verb before params check', 'order.cancel', { zzz: 1 });
cf('verb case', 'Order.place', ok);
cf('undeclared param', 'order.place', { ...ok, zzz: 1 });
cf('undeclared first in byte order', 'order.place', { amount: 'bad', AAA: 1 });
cf('undeclared beats missing', 'noop', { x: 1 });
cf('undeclared dotted', 'order.place', { ...ok, 'a.b': 1 });
cf('missing amount', 'order.place', { currency: 'USD' });
cf('missing currency', 'order.place', { amount: 5 });
cf('missing order (amount first)', 'order.place', {});
cf('byte order: amount bad before currency missing', 'order.place', { amount: 'x' });
cf('missing read id', 'order.get', {});
cf('optional null present', 'order.place', { ...ok, note: null });
cf('string bad type', 'order.place', { ...ok, currency: 1 });
cf('string not in values', 'order.place', { ...ok, currency: 'usd' });
cf('string multibyte value', 'order.place', { ...ok, currency: 'é€' });
cf('string max_len 8 ok', 'order.place', { ...ok, note: '12345678' });
cf('string max_len 9', 'order.place', { ...ok, note: '123456789' });
cf('string max_len bytes', 'order.place', { ...ok, note: 'éééé' });
cf('string max_len bytes over', 'order.place', { ...ok, note: 'éééé1' });
cf('string default 1024', 'order.place', { ...ok, desc: 'd'.repeat(1024) });
cf('string default 1025', 'order.place', { ...ok, desc: 'd'.repeat(1025) });
cf('string default 1025 bytes multibyte', 'order.place', { ...ok, desc: 'd'.repeat(1023) + 'é' });
cf('string empty ok', 'order.place', { ...ok, desc: '' });
cf('int min', 'order.place', { ...ok, amount: 1 });
cf('int below min', 'order.place', { ...ok, amount: 0 });
cf('int max', 'order.place', { ...ok, amount: 100000 });
cf('int above max', 'order.place', { ...ok, amount: 100001 });
cf('int float', 'order.place', { ...ok, amount: 1.5 });
cf('int string', 'order.place', { ...ok, amount: '5' });
cf('int unsafe', 'order.place', { ...ok, big: 2 ** 53 });
cf('int max safe', 'order.place', { ...ok, big: 2 ** 53 - 1 });
cf('int negative unbounded', 'order.place', { ...ok, big: -5 });
cf('int bool', 'order.place', { ...ok, amount: true });
cf('bool bad', 'order.place', { ...ok, gift: 'true' });
cf('bool number', 'order.place', { ...ok, gift: 1 });
cf('date ok', 'order.place', { ...ok, ship_on: '2026-10-12' });
cf('date leap 2000', 'order.place', { ...ok, ship_on: '2000-02-29' });
cf('date non-leap 1900', 'order.place', { ...ok, ship_on: '1900-02-29' });
cf('date non-leap 2023', 'order.place', { ...ok, ship_on: '2023-02-29' });
cf('date 2023-02-28', 'order.place', { ...ok, ship_on: '2023-02-28' });
cf('date apr 31', 'order.place', { ...ok, ship_on: '2026-04-31' });
cf('date dec 31', 'order.place', { ...ok, ship_on: '2026-12-31' });
cf('date month 13', 'order.place', { ...ok, ship_on: '2026-13-01' });
cf('date month 00', 'order.place', { ...ok, ship_on: '2026-00-01' });
cf('date day 00', 'order.place', { ...ok, ship_on: '2026-01-00' });
cf('date year 0000', 'order.place', { ...ok, ship_on: '0000-01-01' });
cf('date year 0001', 'order.place', { ...ok, ship_on: '0001-01-01' });
cf('date with time', 'order.place', { ...ok, ship_on: '2026-10-12T00:00:00Z' });
cf('date short', 'order.place', { ...ok, ship_on: '2026-1-12' });
cf('date trailing newline', 'order.place', { ...ok, ship_on: '2026-10-12\n' });
cf('date slashes', 'order.place', { ...ok, ship_on: '2026/10/12' });
cf('date unicode digits', 'order.place', { ...ok, ship_on: '２０２６-10-12' });
cf('date number', 'order.place', { ...ok, ship_on: 20261012 });
cf('set ok', 'order.place', { ...ok, tags: ['a'] });
cf('set not array', 'order.place', { ...ok, tags: 'a' });
cf('set non-string item', 'order.place', { ...ok, tags: ['a', 1] });
cf('set duplicate', 'order.place', { ...ok, tags: ['a', 'a'] });
cf('set duplicate and foreign (distinct first)', 'order.place', { ...ok, tags: ['x', 'x'] });
cf('set foreign member', 'order.place', { ...ok, tags: ['a', 'x'] });
cf('set empty below min_items 1', 'order.place', { ...ok, tags: [] });
cf('set 4 above max_items 3', 'order.place', { ...ok, tags: ['a', 'b', 'c', 'Z'] });
cf('set default max = values.length', 'order.place', { ...ok, colors: ['red', 'green'] });
cf('set default min 0', 'order.place', { ...ok, colors: [] });
cf('array int ok', 'order.place', { ...ok, qty: [0, 10] });
cf('array int not array', 'order.place', { ...ok, qty: 3 });
cf('array int item string', 'order.place', { ...ok, qty: ['1'] });
cf('array int item float', 'order.place', { ...ok, qty: [1.5] });
cf('array int item above max', 'order.place', { ...ok, qty: [11] });
cf('array int item below min', 'order.place', { ...ok, qty: [-1] });
cf('array int range before later type', 'order.place', { ...ok, qty: [11, 'x'] });
cf('array int type before later range', 'order.place', { ...ok, qty: ['x', 11] });
cf('array int range before length', 'order.place', { ...ok, qty: [1, 2, 3, 11] });
cf('array int empty below min_items', 'order.place', { ...ok, qty: [] });
cf('array int 4 above max_items', 'order.place', { ...ok, qty: [1, 2, 3, 4] });
cf('array str max_len 4 ok', 'order.place', { ...ok, skus: ['abcd', 'éé'] });
cf('array str 5 bytes', 'order.place', { ...ok, skus: ['abcde'] });
cf('array str non-string', 'order.place', { ...ok, skus: [1] });
cf('array str null item', 'order.place', { ...ok, skus: [null] });
cf('array default max_items 64', 'order.place', { ...ok, ids: Array.from({ length: 64 }, () => 'x') });
cf('array default max_items 65', 'order.place', { ...ok, ids: Array.from({ length: 65 }, () => 'x') });
cf('array default max_len 1024', 'order.place', { ...ok, ids: ['i'.repeat(1024)] });
cf('array default max_len 1025', 'order.place', { ...ok, ids: ['i'.repeat(1025)] });
cf('array of objects', 'order.place', { ...ok, ids: [{}] });
cf('own __proto__ param is undeclared', 'order.place', JSON.parse('{"amount":5,"currency":"USD","__proto__":{"x":1}}'));
cf('constructor param is undeclared', 'order.place', { ...ok, constructor: 1 });
cf('toString param is undeclared', 'order.place', { ...ok, toString: 'x' });
// a doc whose duplicate-free first verb wins, schemaVerb on a hand doc
cf('hand doc first match wins', 'v', { a: 1 }, { verbs: [{ verb: 'v', kind: 'read', params: { [P + 'a']: { type: 'integer', semantic: 's', sensitivity: 'free', max: 0 } } }, { verb: 'v', kind: 'read', params: { [P + 'a']: { type: 'integer', semantic: 's', sensitivity: 'free' } } }] });
cf('hand doc verbs not array', 'v', {}, { verbs: {} });
cf('hand doc required true explicit', 'v', {}, { verbs: [{ verb: 'v', kind: 'read', params: { [P + 'a']: { type: 'boolean', semantic: 's', sensitivity: 'free', required: true } } }] });
cf('hand doc unknown type', 'v', { a: 1 }, { verbs: [{ verb: 'v', kind: 'read', params: { [P + 'a']: { type: 'number', semantic: 's', sensitivity: 'free' } } }] });

// ---------------------------------------------------------------- reversibility
const rev: any[] = [];
const rv = (name: string, v: any, params: any) => rev.push({ name, verb: v, params, of: reversibilityOf(v, params), max: verbReversibility(v) });
const vp = signed.verbs[0];
rv('rev_by gift true', vp, { gift: true });
rv('rev_by gift false (default)', vp, { gift: false });
rv('rev_by absent', vp, {});
rv('rev_by string "true"', vp, { gift: 'true' });
rv('read default', signed.verbs[1], {});
rv('write default', signed.verbs[2], {});
rv('explicit rate_limited', { verb: 'x', kind: 'write', params: {}, reversibility: 'rate_limited' }, {});
const vb = (map: any, dflt?: string, decl: any = { type: 'boolean', semantic: 's', sensitivity: 'free' }) => ({ verb: 'x', kind: 'write', params: { [P + 'm']: decl }, reversibility_by: { param: P + 'm', map, ...(dflt ? { default: dflt } : {}) } });
rv('bool covered both', vb({ true: 'rate_limited', false: 'reversible' }), { m: false });
rv('bool covered, default ignored in max', vb({ true: 'reversible', false: 'reversible' }, 'irreversible'), { m: true });
rv('bool uncovered no default', vb({ true: 'reversible' }), { m: false });
rv('enum covered', vb({ a: 'reversible', b: 'rate_limited' }, undefined, { type: 'string', semantic: 's', sensitivity: 'free', values: ['a', 'b'] }), { m: 'b' });
rv('enum uncovered', vb({ a: 'reversible' }, 'rate_limited', { type: 'string', semantic: 's', sensitivity: 'free', values: ['a', 'b'] }), { m: 'b' });
rv('integer key', vb({ '5': 'reversible' }, 'rate_limited', { type: 'integer', semantic: 's', sensitivity: 'free' }), { m: 5 });
rv('integer key miss', vb({ '5': 'reversible' }, 'rate_limited', { type: 'integer', semantic: 's', sensitivity: 'free' }), { m: 6 });
rv('float key unmapped', vb({ '1.5': 'reversible' }, 'rate_limited', { type: 'integer', semantic: 's', sensitivity: 'free' }), { m: 1.5 });
rv('map own __proto__ is data', vb(JSON.parse('{"__proto__":"rate_limited"}'), 'reversible', { type: 'string', semantic: 's', sensitivity: 'free' }), JSON.parse('{"m":"__proto__"}'));
rv('map constructor key absent', vb({ x: 'reversible' }, 'rate_limited', { type: 'string', semantic: 's', sensitivity: 'free' }), { m: 'constructor' });
rv('free string no values', vb({ x: 'reversible' }, 'reversible', { type: 'string', semantic: 's', sensitivity: 'free' }), { m: 'x' });

// ---------------------------------------------------------------- conformance corpus (rule 14 parts)
let conformance_primitives: any[] | null = null;
let conformance_vectors: any[] | null = null;
{
  const p = 'packages/pca/conformance/vectors.json';
  if (existsSync(p)) {
    const f = JSON.parse(readFileSync(p, 'utf8'));
    conformance_primitives = f.primitives?.intent_schema ?? null;
    if (conformance_primitives) {
      // for each schema-* vector: its accepted schema docs / keys and the TS verdict of verifyActionSchema(docs[0], keys)
      conformance_vectors = (f.vectors ?? [])
        .filter((v: any) => /^schema-/.test(v.name) && Array.isArray(v.context?.intent_v2?.schema?.docs) && v.context.intent_v2.schema.docs.length > 0)
        .map((v: any) => {
          const sc = v.context.intent_v2.schema;
          const r = verifyActionSchema(sc.docs[0], sc.keys) as any;
          return { name: v.name, doc: sc.docs[0], keys: sc.keys, ok: r.ok, reason: r.ok ? null : r.reason, requires_suite: v.requires_suite ?? null, reason_contains: v.expect?.reason_contains ?? null };
        });
    }
  }
}

writeFileSync(out, JSON.stringify({ signed, keys: [KEY], shape, verify, digest, conform, rev, conformance_primitives, conformance_vectors }, null, 1));
console.log(`wrote ${out}: shape ${shape.length}, verify ${verify.length}, digest ${digest.length}, conform ${conform.length}, rev ${rev.length}, conformance primitives ${conformance_primitives?.length ?? 'n/a'}, vectors ${conformance_vectors?.length ?? 'n/a'}`);
