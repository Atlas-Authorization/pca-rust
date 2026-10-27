#!/usr/bin/env node
// release-notes.mjs: the GitHub Release body for one version: its CHANGELOG section plus how to verify the assets.
//
//   node .github/scripts/release-notes.mjs --version 0.4.3 --repo Atlas-Authorization/pca \
//        --changelog docs/CHANGELOG.md [--changelog other.md ...] [--registry "npm: @atlasauth/pca*"] \
//        [--sbom sbom-npm.cdx.json] [--evidence security-evidence-pca-0.4.3.md] > notes.md
//
// The section is the first "## " heading that names the version as a whole token ("## 0.4.3 - 2026-11-02",
// "## Unreleased (0.4.3)"), up to the next "## " heading. If no heading names it, a heading that is exactly
// "## Unreleased" is used (the bump commit had not renamed it yet); otherwise the body links to the changelog.
import { existsSync, readFileSync } from 'node:fs';

const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf(`--${n}`); return i >= 0 ? args[i + 1] : undefined; };
const all = (n) => args.flatMap((a, i) => (a === `--${n}` ? [args[i + 1]] : []));
const version = opt('version');
const repo = opt('repo');
if (!version || !repo) { console.error('usage: release-notes.mjs --version X.Y.Z --repo owner/name --changelog FILE ...'); process.exit(2); }
const registries = all('registry');
const sbom = opt('sbom');
const evidence = opt('evidence');

const esc = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const named = new RegExp(`(^|[^0-9A-Za-z.])v?${esc}([^0-9A-Za-z.-]|$)`);

function section(md) {
  const lines = md.split(/\r?\n/);
  const heads = lines.flatMap((l, i) => (/^## /.test(l) ? [i] : []));
  const pick = heads.find((i) => named.test(lines[i])) ?? heads.find((i) => /^## Unreleased\s*$/i.test(lines[i]));
  if (pick === undefined) return null;
  const end = heads.find((i) => i > pick) ?? lines.length;
  return lines.slice(pick + 1, end).join('\n').trim();
}

let body = null;
let source = null;
for (const f of all('changelog')) {
  if (!existsSync(f)) continue;
  const s = section(readFileSync(f, 'utf8'));
  if (s) { body = s; source = f; break; }
}

const out = [];
if (body) {
  out.push(body.replace(/^###/gm, '##'));
} else {
  const first = all('changelog')[0];
  out.push(`See the [changelog](https://github.com/${repo}/blob/v${version}/${first ?? 'CHANGELOG.md'}) for this release.`);
}
out.push('', '---', '', '## Verifying this release', '');
if (registries.length) {
  out.push('Published from this repository by GitHub Actions:', '');
  for (const r of registries) out.push(`- ${r}`);
  out.push('');
}
out.push(
  'Every asset below has a GitHub build-provenance attestation and is listed in `SHA256SUMS`:',
  '',
  '```sh',
  `gh release download v${version} --repo ${repo}`,
  'sha256sum -c SHA256SUMS',
  `gh attestation verify <asset> --repo ${repo}`,
  '```',
);
if (sbom) {
  out.push('', `\`${sbom}\` is the CycloneDX SBOM of this release; an SBOM attestation binds it to every package file:`, '',
    '```sh', `gh attestation verify <asset> --repo ${repo} --predicate-type https://cyclonedx.org/bom`, '```');
}
if (evidence) {
  out.push('', `\`${evidence}\` (and the \`.json\` beside it) is the security evidence report: the exact commit, which gates ran`
    + ' with their run ids and results, the SBOM and dependency-audit results, and every outstanding exception.');
}
process.stdout.write(out.join('\n') + '\n');
if (source) console.error(`release-notes: section for ${version} taken from ${source}`);
else console.error(`release-notes: no changelog section for ${version}; the body links to the changelog`);
