#!/usr/bin/env node
// vuln-gate.mjs: the release dependency-vulnerability gate. Reads the JSON report of an ecosystem's audit tool, rates
// every finding, applies the reviewed allowlist and fails the release on any high or critical finding that is not
// allowlisted.
//
//   node .github/scripts/vuln-gate.mjs --ecosystem npm|pypi|crates --report FILE [--report FILE ...]
//        [--allowlist .github/vuln-allowlist.json] [--out result.json] [--osv] [--now YYYY-MM-DD]
//
// Reports: `npm audit --json` (auditReportVersion 2), `pip-audit --format json`, `cargo audit --json`.
// Severity, first that applies: the tool's own label (npm), a CVSS 3.x vector in the report (cargo audit), with --osv
// the OSV record of the id (database_specific.severity, else its CVSS 3.x vector). A finding that cannot be rated is
// treated as critical: an unknown is never waved through.
// Allowlist (JSON): { "entries": [ { "id", "ecosystem", "package", "reason", "reviewed_by", "reviewed_on", "expires" } ] };
// an entry matches a finding by id or alias plus package name. An entry with a missing field, a reason under 20
// characters, an expiry before its review date, more than 180 days after it, or already passed is invalid and fails the
// gate (its finding stays blocking). Entries that match nothing are reported as unused.
// Exit: 0 pass, 1 blocking findings or invalid allowlist entries, 2 unreadable / unrecognised report or usage error.
import { existsSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs';

const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf(`--${n}`); return i >= 0 ? args[i + 1] : undefined; };
const all = (n) => args.flatMap((a, i) => (a === `--${n}` ? [args[i + 1]] : []));
const ecosystem = opt('ecosystem');
const reports = all('report');
const allowFile = opt('allowlist');
const outFile = opt('out');
const useOsv = args.includes('--osv');
const now = opt('now') ?? new Date().toISOString().slice(0, 10);
const die = (msg) => { console.error(`::error::vuln-gate: ${msg}`); process.exit(2); };
if (!['npm', 'pypi', 'crates'].includes(ecosystem) || reports.length === 0) {
  die('usage: vuln-gate.mjs --ecosystem npm|pypi|crates --report FILE [--report FILE ...] [--allowlist F] [--out F] [--osv]');
}

const BLOCKING = new Set(['high', 'critical', 'unknown']);
const label = (s) => {
  const v = String(s ?? '').toLowerCase();
  if (v === 'moderate') return 'medium';
  return ['low', 'medium', 'high', 'critical'].includes(v) ? v : null;
};
const band = (score) => (score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : score > 0 ? 'low' : 'none');

// CVSS 3.0 / 3.1 base score (FIRST specification, section 7.1 and Appendix A roundup). null if not a complete 3.x vector.
function cvss3(vector) {
  const m = /^CVSS:3\.[01]\/(.+)$/.exec(String(vector ?? '').trim());
  if (!m) return null;
  const v = Object.fromEntries(m[1].split('/').map((kv) => kv.split(':')));
  const W = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }, AC: { L: 0.77, H: 0.44 }, UI: { N: 0.85, R: 0.62 },
    CIA: { H: 0.56, L: 0.22, N: 0 },
  };
  const changed = v.S === 'C';
  if (!['U', 'C'].includes(v.S)) return null;
  const PR = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[v.PR];
  const [av, ac, ui, c, i, a] = [W.AV[v.AV], W.AC[v.AC], W.UI[v.UI], W.CIA[v.C], W.CIA[v.I], W.CIA[v.A]];
  if ([PR, av, ac, ui, c, i, a].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const expl = 8.22 * av * ac * PR * ui;
  if (impact <= 0) return 0;
  const roundup = (x) => { const n = Math.round(x * 100000); return n % 10000 === 0 ? n / 100000 : (Math.floor(n / 10000) + 1) / 10; };
  return roundup(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10));
}

function read(file) {
  if (!existsSync(file)) die(`report ${file} does not exist (did the audit tool run?)`);
  try { return JSON.parse(readFileSync(file, 'utf8')); } catch (e) { die(`report ${file} is not JSON (${e.message.slice(0, 80)})`); }
}

// ---- one parser per tool; each yields { id, aliases, package, version, title, url, severity|null, score|null, rated_by }
function parseNpm(r, file) {
  if (r?.auditReportVersion !== 2 || typeof r.vulnerabilities !== 'object') die(`${file} is not an npm audit v2 report`);
  const out = [];
  for (const [name, v] of Object.entries(r.vulnerabilities)) {
    for (const via of v.via ?? []) {
      if (typeof via !== 'object') continue; // a transitive edge: the advisory is listed under its own package
      const ghsa = /GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i.exec(via.url ?? '')?.[0];
      out.push({
        id: ghsa ?? `npm-${via.source}`, aliases: via.source ? [`npm-${via.source}`] : [], package: via.name ?? name,
        version: via.range ? `affected ${via.range}` : null, title: via.title ?? '', url: via.url ?? null,
        severity: label(via.severity), score: typeof via.cvss?.score === 'number' && via.cvss.score > 0 ? via.cvss.score : null,
        rated_by: label(via.severity) ? 'npm audit' : null,
      });
    }
  }
  return out;
}
function parsePip(r, file) {
  const deps = Array.isArray(r) ? r : r?.dependencies;
  if (!Array.isArray(deps)) die(`${file} is not a pip-audit JSON report`);
  return deps.flatMap((d) => (d.vulns ?? []).map((x) => ({
    id: x.id, aliases: x.aliases ?? [], package: d.name, version: d.version ?? null, title: (x.description ?? '').split('\n')[0].slice(0, 160),
    url: `https://osv.dev/vulnerability/${x.id}`, severity: null, score: null, rated_by: null,
  })));
}
function parseCargo(r, file) {
  if (!Array.isArray(r?.vulnerabilities?.list)) die(`${file} is not a cargo audit JSON report`);
  return r.vulnerabilities.list.map((x) => {
    const score = cvss3(x.advisory?.cvss);
    return {
      id: x.advisory?.id, aliases: x.advisory?.aliases ?? [], package: x.package?.name ?? x.advisory?.package, version: x.package?.version ?? null,
      title: x.advisory?.title ?? '', url: x.advisory?.url ?? `https://rustsec.org/advisories/${x.advisory?.id}`,
      severity: score === null ? null : band(score), score, rated_by: score === null ? null : 'CVSS vector in the RustSec advisory',
    };
  });
}
// cargo audit's warnings (unmaintained, unsound, yanked) are not vulnerabilities; they are reported, never blocking
const cargoWarnings = (r) => Object.entries(r?.warnings ?? {}).flatMap(([kind, list]) => (Array.isArray(list) ? list : []).map((w) => ({
  kind, id: w.advisory?.id ?? null, package: w.package?.name ?? null, version: w.package?.version ?? null, title: w.advisory?.title ?? kind,
})));

async function osvRate(f) {
  for (const id of [f.id, ...f.aliases]) {
    if (!/^(GHSA|PYSEC|RUSTSEC|CVE)-/.test(id)) continue;
    try {
      const res = await fetch(`${process.env.OSV_API ?? 'https://api.osv.dev/v1'}/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(15000) });
      if (!res.ok) continue;
      const rec = await res.json();
      const lab = label(rec.database_specific?.severity);
      const vec = (rec.severity ?? []).find((s) => s.type === 'CVSS_V3')?.score;
      const score = cvss3(vec);
      if (lab) return { severity: lab, score, rated_by: `OSV ${id} (database severity)` };
      if (score !== null) return { severity: band(score), score, rated_by: `OSV ${id} (CVSS 3 vector)` };
    } catch { /* unreachable OSV leaves the finding unrated, which blocks */ }
  }
  return null;
}

// ---- allowlist ------------------------------------------------------------------------------------------------------
const DAY = 86400000;
const isDate = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s));
function loadAllowlist() {
  if (!allowFile) return [];
  if (!existsSync(allowFile)) die(`allowlist ${allowFile} does not exist`);
  let j;
  try { j = JSON.parse(readFileSync(allowFile, 'utf8')); } catch (e) { die(`allowlist ${allowFile} is not JSON (${e.message.slice(0, 80)})`); }
  if (!Array.isArray(j?.entries)) die(`allowlist ${allowFile} has no "entries" array`);
  return j.entries.map((e, n) => {
    const problems = [];
    for (const k of ['id', 'ecosystem', 'package', 'reason', 'reviewed_by', 'reviewed_on', 'expires']) {
      if (typeof e?.[k] !== 'string' || !e[k].trim()) problems.push(`no ${k}`);
    }
    if (typeof e?.reason === 'string' && e.reason.trim().length < 20) problems.push('reason under 20 characters (say why it does not apply)');
    if (!isDate(e?.reviewed_on) || !isDate(e?.expires)) problems.push('reviewed_on / expires are not YYYY-MM-DD');
    else {
      const span = (Date.parse(e.expires) - Date.parse(e.reviewed_on)) / DAY;
      if (span <= 0) problems.push('expires is not after reviewed_on');
      if (span > 180) problems.push('expires is more than 180 days after reviewed_on');
      if (e.expires < now) problems.push(`expired on ${e.expires}`);
    }
    return { n, entry: e, problems, used: false };
  });
}
const normName = (eco, s) => (eco === 'pypi' ? String(s ?? '').toLowerCase().replace(/[-_.]+/g, '-') : String(s ?? ''));

// ---- main -----------------------------------------------------------------------------------------------------------
const parse = { npm: parseNpm, pypi: parsePip, crates: parseCargo }[ecosystem];
const raw = [];
const warnings = [];
for (const f of reports) {
  const r = read(f);
  raw.push(...parse(r, f));
  if (ecosystem === 'crates') warnings.push(...cargoWarnings(r));
}
// one finding per (package, version, id): several reports (one per distribution) name the same pin
const seen = new Map();
for (const f of raw) {
  if (!f.id || !f.package) die('a report entry has no advisory id or package name');
  const k = `${normName(ecosystem, f.package)}\0${f.version}\0${f.id}`;
  if (!seen.has(k)) seen.set(k, f);
  else seen.get(k).aliases = [...new Set([...seen.get(k).aliases, ...f.aliases])];
}
const findings = [...seen.values()];
if (useOsv) {
  for (const f of findings) {
    if (f.severity) continue;
    const r = await osvRate(f);
    if (r) Object.assign(f, r);
  }
}
const allow = loadAllowlist();
for (const f of findings) {
  if (!f.severity) { f.severity = 'unknown'; f.rated_by = 'unrated: treated as critical'; }
  const ids = new Set([f.id, ...f.aliases].map((x) => x.toUpperCase()));
  const hit = allow.find((a) => a.entry?.ecosystem === ecosystem && ids.has(String(a.entry?.id).toUpperCase())
    && normName(ecosystem, a.entry?.package) === normName(ecosystem, f.package));
  if (hit) hit.used = true;
  f.allowlisted = hit && hit.problems.length === 0 ? { id: hit.entry.id, reason: hit.entry.reason, reviewed_by: hit.entry.reviewed_by, expires: hit.entry.expires } : null;
  f.blocking = BLOCKING.has(f.severity) && !f.allowlisted;
}
const invalid = allow.filter((a) => a.problems.length && (a.entry?.ecosystem === ecosystem || !['npm', 'pypi', 'crates'].includes(a.entry?.ecosystem)));
const unused = allow.filter((a) => !a.used && !a.problems.length && a.entry.ecosystem === ecosystem);
const blocking = findings.filter((f) => f.blocking);
const count = (s) => findings.filter((f) => f.severity === s).length;
const result = {
  ecosystem, tool: { npm: 'npm audit', pypi: 'pip-audit', crates: 'cargo audit' }[ecosystem], checked_on: now,
  verdict: blocking.length || invalid.length ? 'fail' : 'pass',
  counts: { critical: count('critical'), high: count('high'), medium: count('medium'), low: count('low'), unknown: count('unknown'),
    allowlisted: findings.filter((f) => f.allowlisted).length, blocking: blocking.length },
  findings: findings.sort((a, b) => a.package.localeCompare(b.package) || a.id.localeCompare(b.id)),
  warnings,
  allowlist: {
    file: allowFile ?? null,
    used: allow.filter((a) => a.used && !a.problems.length).map((a) => a.entry),
    unused: unused.map((a) => a.entry),
    invalid: invalid.map((a) => ({ entry: a.entry, problems: a.problems })),
  },
};
if (outFile) writeFileSync(outFile, JSON.stringify(result, null, 2) + '\n');

for (const f of findings) {
  const tag = f.blocking ? '::error::' : f.allowlisted ? '' : BLOCKING.has(f.severity) ? '::error::' : '::warning::';
  console.log(`${tag}${ecosystem} ${f.package}${f.version ? ` ${f.version}` : ''}: ${f.id} ${f.severity}${f.score ? ` (${f.score})` : ''}`
    + `${f.allowlisted ? ` allowlisted until ${f.allowlisted.expires}: ${f.allowlisted.reason}` : ''} ${f.title}`.trimEnd());
}
for (const w of warnings) console.log(`::notice::${ecosystem} ${w.package ?? ''} ${w.version ?? ''}: ${w.kind}${w.id ? ` ${w.id}` : ''} (reported, not blocking)`);
for (const a of invalid) console.log(`::error::allowlist entry #${a.n} (${a.entry?.id ?? '?'}): ${a.problems.join('; ')}`);
for (const a of unused) console.log(`::warning::allowlist entry ${a.entry.id} (${a.entry.package}) matches no finding: remove it`);
const line = `${ecosystem}: ${findings.length} finding(s): ${result.counts.critical} critical, ${result.counts.high} high, ${result.counts.medium} medium, `
  + `${result.counts.low} low, ${result.counts.unknown} unrated; ${result.counts.allowlisted} allowlisted; ${blocking.length} blocking`
  + `${invalid.length ? `; ${invalid.length} invalid allowlist entr${invalid.length === 1 ? 'y' : 'ies'}` : ''} -> ${result.verdict.toUpperCase()}`;
console.log(line);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `#### Dependency vulnerabilities\n\n${line}\n\n`);
process.exit(result.verdict === 'pass' ? 0 : 1);
