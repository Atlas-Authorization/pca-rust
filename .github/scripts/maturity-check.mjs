#!/usr/bin/env node
// maturity-check.mjs: every published PCA package declares its maturity tier, and says it where users look.
//
//   node .github/scripts/maturity-check.mjs [--root DIR] [--write-docs] [--list]
//
// Tiers: stable | production | hardened | experimental. "hardened" is the label "experimental: hardened, awaiting audit":
// engineering for an independent audit / ceremony / hardware programme is done, the programme itself is not; it is never
// shown as production, and a hardened package's README header must say "awaiting" and name what it awaits. Where a package declares it:
//   npm     package.json            "pca": { "maturity": "<tier>" }
//   PyPI    pyproject.toml          [tool.pca] maturity = "<tier>"
//   crates  Cargo.toml              [package.metadata.pca] maturity = "<tier>"
// Which packages are published (the same sets the release workflows publish):
//   npm     packages/<dir>/package.json, <dir> contains "pca", not private, named @atlasauth/pca* or create-pca-app
//   PyPI    pyproject.toml, packages/*/pyproject.toml and sdks/*/pyproject.toml whose project is atlas-pca or atlas-pca-*
//   crates  the CRATES of the Rust release workflow (.github/workflows/release.yml, or in the monorepo
//           scripts/pca-ci-workflows/pca-rust/workflows/release.yml), found under crates/* or sdks/*
// Checks, per package: a valid tier; a README; the README header (the text before its first "## " heading) carries
// "Maturity: **<tier>**" with the declared tier (so an experimental package's header says "experimental"); a stable or
// production package's header and "## Status" section do not call it experimental; a hardened package's header says
// "hardened, awaiting <independent audit | trusted-setup ceremony | hardware evaluation | independent witnesses | final standard>";
// no header calls a non-experimental package a preview or a prototype. A production package may carry `pending_ci`
// (npm: "pca": { "pending_ci": true }, PyPI: [tool.pca] pending_ci = true, crates: [package.metadata.pca] pending_ci = true):
// every item of the definition of done except the green CI run and the mutation gate is met; the flip is deleting the key.
// For @atlasauth/pca (packages/pca/maturity.json present): pca.features in its manifest equals the file's feature tiers;
// every source module belongs to exactly one feature; the runtime import closure of src/core.ts reaches no experimental
// module outside core_experimental_baseline, and every baseline entry is still reached (the list only shrinks).
// The maturity page (docs/pca/maturity.md in the monorepo, docs/maturity.md in the flagship) holds generated tables
// between <!-- maturity:<ecosystem>:start --> / <!-- maturity:<ecosystem>:end --> markers: they must match the manifests
// (--write-docs regenerates them). --list prints every package and its tier.
// Exit 0 ok, 1 findings, 2 usage error.
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';

const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf(`--${n}`); return i >= 0 ? args[i + 1] : undefined; };
const ROOT = opt('root') ?? '.';
const TIERS = ['stable', 'production', 'hardened', 'experimental'];
// tiers that may not be reached from PCA Core (everything below production)
const BELOW_PRODUCTION = ['hardened', 'experimental'];
const problems = [];
const bad = (where, msg) => problems.push(`${where}: ${msg}`);
const read = (p) => readFileSync(join(ROOT, p), 'utf8');
const has = (p) => existsSync(join(ROOT, p));
const dirs = (p) => (has(p) ? readdirSync(join(ROOT, p), { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort() : []);

// minimal TOML reading: the string value of `key` inside table `[table]` (no inline tables or multi-line strings needed)
function tomlValue(text, table, key) {
  let cur = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, '').trim();
    const t = /^\[([^\[\]]+)\]$/.exec(line);
    if (t) { cur = t[1].trim(); continue; }
    if (cur !== table) continue;
    const m = new RegExp(`^${key.replace(/[-.]/g, '\\$&')}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|(\\S+))`).exec(line);
    if (m) return m[1] ?? m[2] ?? m[3];
  }
  return undefined;
}

// ---- discover the published packages -------------------------------------------------------------------------------
const pkgs = []; // { eco, name, version, tier, dir, manifest }
for (const d of dirs('packages')) {
  const f = `packages/${d}/package.json`;
  if (!d.includes('pca') || !has(f)) continue;
  let m;
  try { m = JSON.parse(read(f)); } catch (e) { bad(f, `not JSON (${e.message.slice(0, 60)})`); continue; }
  if (m.private || !(String(m.name).startsWith('@atlasauth/pca') || m.name === 'create-pca-app')) continue;
  pkgs.push({ eco: 'npm', name: m.name, version: m.version, tier: m.pca?.maturity, dir: `packages/${d}`, manifest: f, json: m });
}
for (const f of ['pyproject.toml', ...dirs('packages').map((d) => `packages/${d}/pyproject.toml`), ...dirs('sdks').map((d) => `sdks/${d}/pyproject.toml`)]) {
  if (!has(f)) continue;
  const t = read(f);
  const name = tomlValue(t, 'project', 'name');
  if (!/^atlas-pca(-[a-z0-9-]+)?$/.test(name ?? '')) continue;
  pkgs.push({ eco: 'pypi', name, version: tomlValue(t, 'project', 'version'), tier: tomlValue(t, 'tool.pca', 'maturity'), pending: tomlValue(t, 'tool.pca', 'pending_ci') === 'true', dir: dirname(f), manifest: f });
}
const relWf = ['.github/workflows/release.yml', 'scripts/pca-ci-workflows/pca-rust/workflows/release.yml'].find((p) => has(p) && /^\s+CRATES:/m.test(read(p)));
if (relWf) {
  const crates = /^\s+CRATES:\s*(.+)$/m.exec(read(relWf))[1].replace(/#.*$/, '').trim().split(/\s+/);
  const manifests = [...dirs('crates').map((d) => `crates/${d}/Cargo.toml`), ...dirs('sdks').map((d) => `sdks/${d}/Cargo.toml`)].filter(has);
  for (const c of crates) {
    const f = manifests.find((p) => tomlValue(read(p), 'package', 'name') === c);
    if (!f) { bad(relWf, `crate ${c} is released but no crates/*/Cargo.toml or sdks/*/Cargo.toml names it`); continue; }
    const t = read(f);
    pkgs.push({ eco: 'crates', name: c, version: tomlValue(t, 'package', 'version'), tier: tomlValue(t, 'package.metadata.pca', 'maturity'), pending: tomlValue(t, 'package.metadata.pca', 'pending_ci') === 'true', dir: dirname(f), manifest: f });
  }
}
if (pkgs.length === 0) { console.error('maturity-check: no published package found under ' + ROOT); process.exit(2); }

// ---- per package: tier + README header ------------------------------------------------------------------------------
const where = { npm: 'package.json "pca": { "maturity" }', pypi: '[tool.pca] maturity', crates: '[package.metadata.pca] maturity' };
for (const p of pkgs) {
  const id = `${p.eco} ${p.name} (${p.manifest})`;
  if (!TIERS.includes(p.tier)) { bad(id, p.tier === undefined ? `declares no maturity tier (${where[p.eco]})` : `tier "${p.tier}" is not one of ${TIERS.join(', ')}`); continue; }
  const readme = `${p.dir}/README.md`;
  if (!has(readme)) { bad(id, 'has no README.md'); continue; }
  const md = read(readme);
  const lines = md.split(/\r?\n/);
  const firstH2 = lines.findIndex((l) => /^## /.test(l));
  const header = lines.slice(0, firstH2 < 0 ? 60 : Math.min(firstH2, 60)).join('\n');
  const marker = /Maturity:\s*\*\*(stable|production|hardened|experimental)\*\*/i.exec(header);
  if (!marker) { bad(id, `README header (before the first "## " heading) lacks "Maturity: **${p.tier}**"`); continue; }
  if (marker[1].toLowerCase() !== p.tier) bad(id, `README header says ${marker[1].toLowerCase()}, the manifest says ${p.tier}`);
  // an experimental package's header says so: its marker line reads "Maturity: **experimental**" (checked above)
  if (p.tier === 'hardened' && !/hardened,\s+(formally verified \(model\),\s+)?awaiting\s+(an?\s+)?(independent audit|trusted-setup ceremony|hardware evaluation|independent witnesses|final standard)/i.test(header)) {
    bad(id, 'hardened, but its README header lacks "hardened, awaiting <independent audit | trusted-setup ceremony | hardware evaluation | independent witnesses | final standard>": it must say exactly what it awaits');
  }
  if (p.tier !== 'experimental' && /\b(preview|prototype)\b/i.test(header)) bad(id, `${p.tier}, but its README header calls it a preview or a prototype: say its real tier, or what it awaits`);
  if (p.tier !== 'experimental' && p.tier !== 'hardened') {
    const status = md.split(/^## Status\s*$/m)[1]?.split(/^## /m)[0]?.trim() ?? '';
    // the Maturity line itself may name other tiers (e.g. of features inside the package); the rest of the header may not
    const rest = header.split('\n').filter((l) => !l.includes(marker[0])).join('\n');
    if (/\bexperimental\b/i.test(rest)) bad(id, `${p.tier}, but its README header calls it experimental`);
    if (/^(\*\*)?experimental\b/i.test(status)) bad(id, `${p.tier}, but its README "## Status" section starts with "Experimental"`);
  }
}

// ---- @atlasauth/pca: feature tiers, module map, Core import closure -------------------------------------------------
const core = pkgs.find((p) => p.eco === 'npm' && p.name === '@atlasauth/pca');
let coreReport = null;
if (core && has(`${core.dir}/maturity.json`)) {
  const mapFile = `${core.dir}/maturity.json`;
  const map = JSON.parse(read(mapFile));
  const want = Object.fromEntries(Object.entries(map.features).map(([k, v]) => [k, v.tier]));
  if (JSON.stringify(core.json.pca?.features ?? null) !== JSON.stringify(want)) bad(core.manifest, `pca.features ${JSON.stringify(core.json.pca?.features ?? null)} differs from ${mapFile} (${JSON.stringify(want)})`);
  for (const [k, v] of Object.entries(map.features)) if (!TIERS.includes(v.tier)) bad(mapFile, `feature ${k}: tier "${v.tier}" is not valid`);
  const srcDir = join(ROOT, core.dir, 'src');
  const walk = (d) => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(d, e.name)) : [join(d, e.name)]));
  const modules = walk(srcDir).filter((f) => f.endsWith('.ts') && !/\.(test|d)\.ts$/.test(f) && !/\.test-util\.ts$/.test(f))
    .map((f) => relative(srcDir, f).replace(/\.ts$/, '').split('\\').join('/')).sort();
  const glob = (g) => new RegExp(`^${g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`);
  const testOnly = (m) => (map.test_only ?? []).some((g) => glob(g).test(m));
  const owner = new Map();
  for (const [k, v] of Object.entries(map.features)) {
    for (const m of v.modules) {
      if (owner.has(m)) bad(mapFile, `module ${m} is in both ${owner.get(m)} and ${k}`);
      owner.set(m, k);
      if (!modules.includes(m)) bad(mapFile, `feature ${k} lists ${m}, which is not a module of src/`);
    }
  }
  for (const m of modules) if (!owner.has(m) && !testOnly(m)) bad(mapFile, `module src/${m}.ts has no maturity tier: add it to a feature`);
  // runtime import closure of src/core.ts (type-only imports carry no code)
  const closure = new Map([['core', null]]);
  const queue = ['core'];
  while (queue.length) {
    const m = queue.shift();
    const text = readFileSync(join(srcDir, `${m}.ts`), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    for (const x of text.matchAll(/(?:^|[\n;])\s*(?:import|export)\s+(?!type\s)([^;]*?)\bfrom\s+['"](\.[^'"]+)['"]|import\(\s*['"](\.[^'"]+)['"]\s*\)/g)) {
      const clause = (x[1] ?? '').trim();
      if (/^\{[^}]*\}$/.test(clause) && clause.slice(1, -1).split(',').every((s) => !s.trim() || /^type\s/.test(s.trim()))) continue;
      const target = join(dirname(m), (x[2] ?? x[3]).replace(/\.js$/, '')).split('\\').join('/');
      const resolved = [target, `${target}/index`].find((t) => modules.includes(t));
      if (resolved && !closure.has(resolved)) { closure.set(resolved, m); queue.push(resolved); }
    }
  }
  const expIn = [...closure.keys()].filter((m) => BELOW_PRODUCTION.includes(map.features[owner.get(m)]?.tier)).sort();
  const baseline = [...(map.core_experimental_baseline ?? [])].sort();
  const chain = (m) => { const out = [m]; let c = m; while (closure.get(c)) { c = closure.get(c); out.unshift(c); } return out.join(' -> '); };
  for (const m of expIn) if (!baseline.includes(m)) bad(mapFile, `PCA Core now imports the experimental module ${m} (${owner.get(m)}): ${chain(m)}`);
  for (const m of baseline) if (!expIn.includes(m)) bad(mapFile, `core_experimental_baseline lists ${m}, which Core no longer reaches: remove it`);
  coreReport = { modules: modules.length, closure: closure.size, experimental: expIn };
}

// ---- the maturity page's generated tables ----------------------------------------------------------------------------
const doc = ['docs/pca/maturity.md', 'docs/maturity.md'].find(has);
const label = { npm: 'npm', pypi: 'PyPI', crates: 'crates.io' };
function table(eco) {
  const rows = pkgs.filter((p) => p.eco === eco).sort((a, b) => TIERS.indexOf(a.tier) - TIERS.indexOf(b.tier) || a.name.localeCompare(b.name));
  return ['| Package | Tier |', '|---|---|', ...rows.map((p) => `| \`${p.name}\` | ${p.tier ?? '**none**'} |`)].join('\n');
}
function featureTable() {
  if (!core || !has(`${core.dir}/maturity.json`)) return null;
  const map = JSON.parse(read(`${core.dir}/maturity.json`));
  const rows = Object.entries(map.features).sort(([, a], [, b]) => TIERS.indexOf(a.tier) - TIERS.indexOf(b.tier));
  return ['| Feature | Tier | Key | Modules |', '|---|---|---|---|', ...rows.map(([k, v]) => `| ${v.title} | ${v.tier} | \`${k}\` | ${v.modules.length} |`)].join('\n');
}
if (doc) {
  let text = read(doc);
  const blocks = { ...Object.fromEntries(['npm', 'pypi', 'crates'].filter((e) => pkgs.some((p) => p.eco === e)).map((e) => [e, table(e)])), features: featureTable() };
  for (const [k, body] of Object.entries(blocks)) {
    if (body === null) continue;
    const re = new RegExp(`(<!-- maturity:${k}:start -->)([\\s\\S]*?)(<!-- maturity:${k}:end -->)`);
    if (!re.test(text)) { bad(doc, `no <!-- maturity:${k}:start --> ... end block`); continue; }
    const cur = re.exec(text)[2];
    if (cur !== `\n${body}\n`) {
      if (args.includes('--write-docs')) text = text.replace(re, (_, a, __, c) => `${a}\n${body}\n${c}`);
      else bad(doc, `the ${k} table does not match the manifests (run maturity-check.mjs --write-docs)`);
    }
  }
  if (args.includes('--write-docs')) writeFileSync(join(ROOT, doc), text);
}

// ---- report ---------------------------------------------------------------------------------------------------------
const count = (eco, t) => pkgs.filter((p) => p.eco === eco && p.tier === t).length;
if (args.includes('--list')) for (const p of pkgs) console.log(`${p.eco.padEnd(6)} ${String(p.tier).padEnd(12)} ${p.name}`);
for (const eco of ['npm', 'pypi', 'crates']) {
  const n = pkgs.filter((p) => p.eco === eco).length;
  if (n) console.log(`maturity: ${label[eco]}: ${n} published package(s): ${TIERS.filter((t) => t !== 'hardened' || count(eco, t) > 0).map((t) => `${count(eco, t)} ${t}`).join(', ')}`);
}
const pend = pkgs.filter((p) => p.json?.pca?.pending_ci === true || p.pending === true);
for (const p of pend) { if (p.tier !== 'production') bad(p.name, '"pending_ci" is only meaningful on a production package'); else console.log(`maturity: ${p.name}: production, pending_ci (flip after the CI gates are green)`); }
if (coreReport) console.log(`maturity: @atlasauth/pca: ${coreReport.modules} modules classified; PCA Core reaches ${coreReport.closure} module(s), ${coreReport.experimental.length} of them experimental (the pinned baseline; it may only shrink)`);
if (doc) console.log(`maturity: ${doc}: tables ${problems.some((p) => p.startsWith(doc)) ? 'NOT in sync' : 'in sync'}`);
if (problems.length) {
  for (const p of problems) console.log(`::error::maturity: ${p}`);
  console.log(`maturity-check FAILED: ${problems.length} problem(s)`);
  process.exit(1);
}
console.log('maturity-check ok');
