#!/usr/bin/env node
// sbom-merge.mjs: one CycloneDX JSON SBOM for a release from one SBOM per published package (or per install).
//
//   node .github/scripts/sbom-merge.mjs --name "atlas-pca (PyPI)" --version 0.5.0 --out sbom-pypi.cdx.json \
//        --part atlas-pca@0.5.0=core.cdx.json --part atlas-pca-crewai@0.5.0=crewai.cdx.json [--purl-type pypi]
//   --part FILE                 (no name) the part's own metadata.component is the package
//
// The output's metadata.component is the release; it depends on every part's package, and each package depends on what
// its part lists (its edges in the part's dependency graph; if the part gives it none, e.g. a requirements SBOM, every
// component of the part). Components are de-duplicated by purl (else by name@version). Deterministic: the timestamp is SOURCE_DATE_EPOCH
// when set, the serial number is derived from the content, and everything is sorted.
// Exit 2 on a missing or non-CycloneDX part, or a part with no package identity.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf(`--${n}`); return i >= 0 ? args[i + 1] : undefined; };
const all = (n) => args.flatMap((a, i) => (a === `--${n}` ? [args[i + 1]] : []));
const die = (m) => { console.error(`::error::sbom-merge: ${m}`); process.exit(2); };
const name = opt('name'), version = opt('version'), out = opt('out'), purlType = opt('purl-type');
const parts = all('part');
if (!name || !version || !out || parts.length === 0) die('usage: sbom-merge.mjs --name N --version V --out F --part [name@ver=]FILE ...');

const comps = new Map();       // ref -> component (no nested components)
const deps = new Map();        // ref -> Set(ref)
const tools = new Map();
let spec = '1.5';
const edge = (from, to) => { if (!deps.has(from)) deps.set(from, new Set()); if (to) deps.get(from).add(to); };
const keyOf = (c) => (c.purl ? String(c.purl).split('?')[0] : `${c.group ? `${c.group}/` : ''}${c.name}@${c.version ?? ''}`);
const strip = ({ components, 'bom-ref': _r, ...rest }) => rest;
const vnum = (s) => s.split('.').map(Number);
const newer = (a, b) => { const [x, y] = [vnum(a), vnum(b)]; return x[0] !== y[0] ? x[0] > y[0] : x[1] > y[1]; };

const roots = [];
for (const p of parts) {
  const m = /^(.+)@([^@=]+)=(.+)$/.exec(p);
  const file = m ? m[3] : p;
  if (!existsSync(file)) die(`part ${file} does not exist`);
  let bom;
  try { bom = JSON.parse(readFileSync(file, 'utf8')); } catch (e) { die(`part ${file} is not JSON (${e.message.slice(0, 80)})`); }
  if (bom?.bomFormat !== 'CycloneDX' || typeof bom.specVersion !== 'string') die(`part ${file} is not a CycloneDX JSON BOM`);
  if (newer(bom.specVersion, spec)) spec = bom.specVersion;
  for (const t of [bom.metadata?.tools?.components ?? [], Array.isArray(bom.metadata?.tools) ? bom.metadata.tools : []].flat()) {
    if (t?.name) tools.set(`${t.name}@${t.version ?? ''}`, { type: 'application', ...(t.group ? { group: t.group } : {}), name: t.name, ...(t.version ? { version: t.version } : {}) });
  }
  // the part's package: --part name@version (a purl of --purl-type if given), else the part's own metadata.component
  let root = bom.metadata?.component;
  if (m) {
    root = { type: 'library', name: m[1], version: m[2], ...(purlType ? { purl: `pkg:${purlType}/${m[1].replace(/^@/, '%40')}@${m[2]}` } : {}) };
  }
  if (!root?.name) die(`part ${file}: no package name (give --part name@version=${file})`);
  const ref = new Map();       // the part's own bom-refs -> merged refs
  const add = (c) => {
    const k = keyOf(c);
    if (c['bom-ref']) ref.set(c['bom-ref'], k);
    if (!comps.has(k)) comps.set(k, { ...strip(c), 'bom-ref': k });
    for (const n of c.components ?? []) add(n);
    return k;
  };
  const rootRef = add({ ...root, 'bom-ref': bom.metadata?.component?.['bom-ref'] ?? root['bom-ref'] });
  roots.push(rootRef);
  for (const c of bom.components ?? []) add(c);
  edge(rootRef);
  for (const d of bom.dependencies ?? []) {
    const from = ref.get(d.ref);
    if (!from) continue;
    edge(from);
    for (const t of d.dependsOn ?? []) if (ref.has(t)) edge(from, ref.get(t));
  }
  // no graph from the package itself (a requirements SBOM lists pins with empty edges): it depends on every component
  if (deps.get(rootRef).size === 0) for (const c of bom.components ?? []) if (keyOf(c) !== rootRef) edge(rootRef, keyOf(c));
}

const releaseRef = `release:${name}@${version}`;
const sorted = [...comps.values()].filter((c) => c['bom-ref'] !== releaseRef).sort((a, b) => a['bom-ref'].localeCompare(b['bom-ref']));
const dependencies = [{ ref: releaseRef, dependsOn: [...new Set(roots)].sort() },
  ...[...deps].sort(([a], [b]) => a.localeCompare(b)).map(([r, s]) => ({ ref: r, dependsOn: [...s].filter((t) => t !== r).sort() }))];
const epoch = Number(process.env.SOURCE_DATE_EPOCH);
const body = {
  bomFormat: 'CycloneDX', specVersion: spec, version: 1,
  metadata: {
    timestamp: (Number.isFinite(epoch) && epoch > 0 ? new Date(epoch * 1000) : new Date()).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    tools: { components: [...tools.values()].sort((a, b) => a.name.localeCompare(b.name)) },
    component: { type: 'application', 'bom-ref': releaseRef, name, version },
  },
  components: sorted,
  dependencies,
};
const h = createHash('sha256').update(JSON.stringify({ ...body, metadata: { ...body.metadata, timestamp: '' } })).digest('hex');
const serialNumber = `urn:uuid:${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${((parseInt(h[16], 16) & 3) | 8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
writeFileSync(out, JSON.stringify({ bomFormat: body.bomFormat, specVersion: spec, serialNumber, version: 1, metadata: body.metadata, components: sorted, dependencies }, null, 2) + '\n');
console.log(`sbom-merge: ${out}: ${roots.length} package(s), ${sorted.length - roots.length} other component(s), CycloneDX ${spec}`);
