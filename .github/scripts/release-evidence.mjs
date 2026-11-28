#!/usr/bin/env node
// release-evidence.mjs: the per-release SECURITY EVIDENCE REPORT (markdown + JSON) attached to the GitHub Release.
//
//   node .github/scripts/release-evidence.mjs --config .github/evidence-gates.json --repo owner/name --tag v0.5.0 \
//        --version 0.5.0 --commit SHA --run-id ID [--run-attempt N] [--dry-run true|false] [--packages FILE.json] \
//        [--sums SHA256SUMS] [--sbom FILE ...] [--vuln RESULT.json ...] [--toolchain FILE] [--wait-minutes M] \
//        [--out-dir DIR] [--strict]
//
// For every gate in the config ({ id, label, workflow, required, repo?, job?, jobs?, artifacts? }) it finds the GitHub
// Actions run that decides it: the newest completed run of that workflow at the release commit (for a gate in another
// repository: at that repository's tag of the same version); if there is none, the newest completed run on the release-
// candidate branches (config rc_branches, "{version}" substituted), recorded with the commit it ran on. A run still in
// progress at the release commit is waited for up to --wait-minutes. The gate's result is the run's conclusion, or the
// conclusion of the named `job`. `jobs: true` lists every job (one row per layer / tool / shard group). `artifacts` are
// downloaded and summarised (kind "mutation": counts + score + ledger verdict; kind "cross-language": per-language status,
// unwaived and waived disagreements). This run's own jobs and steps (reproducible pack, leak scan, ...) are listed too.
// SBOMs (CycloneDX) and vuln-gate results are summarised; every exception (gate not at the release commit, failed or
// missing gate, allowlisted or below-threshold vulnerability, waived disagreement, the config's known_exceptions) is
// collected under "Outstanding exceptions".
// --strict (a real release): exit 1 if a required gate has no successful run, a vulnerability result failed, or an SBOM
// is missing or empty. Without it the report is written and the exit is 0 (dry run). Exit 2 on usage / config errors.
// API: $GITHUB_API_URL (default https://api.github.com) with $GH_TOKEN / $GITHUB_TOKEN.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf(`--${n}`); return i >= 0 ? args[i + 1] : undefined; };
const all = (n) => args.flatMap((a, i) => (a === `--${n}` ? [args[i + 1]] : []));
const die = (m) => { console.error(`::error::release-evidence: ${m}`); process.exit(2); };
const A = {
  config: opt('config'), repo: opt('repo'), tag: opt('tag'), version: opt('version'), commit: opt('commit'),
  runId: opt('run-id'), runAttempt: opt('run-attempt') ?? '1', dryRun: opt('dry-run') === 'true',
  packages: opt('packages'), sums: opt('sums'), sboms: all('sbom'), vulns: all('vuln'), toolchain: opt('toolchain'),
  wait: Number(opt('wait-minutes') ?? '0'), outDir: opt('out-dir') ?? '.', strict: args.includes('--strict'),
  pollSeconds: Number(process.env.EVIDENCE_POLL_SECONDS ?? '60'),
};
for (const k of ['config', 'repo', 'tag', 'version', 'commit']) if (!A[k]) die(`--${k} is required`);
if (!/^[0-9a-f]{40}$/.test(A.commit)) die(`--commit ${A.commit} is not a full commit SHA`);
let config;
try { config = JSON.parse(readFileSync(A.config, 'utf8')); } catch (e) { die(`config ${A.config}: ${e.message}`); }
if (!Array.isArray(config.gates) || config.gates.some((g) => !g.id || !g.label || !g.workflow)) die('config: every gate needs id, label, workflow');

const API = (process.env.GITHUB_API_URL ?? 'https://api.github.com').replace(/\/$/, '');
const SERVER = (process.env.GITHUB_SERVER_URL ?? 'https://github.com').replace(/\/$/, '');
const TOKEN = process.env.GH_TOKEN ?? process.env.GITHUB_TOKEN ?? '';
const hdrs = { accept: 'application/vnd.github+json', 'user-agent': 'pca-release-evidence', ...(TOKEN ? { authorization: `Bearer ${TOKEN}` } : {}) };
async function api(path) {
  for (let i = 0; i < 3; i++) {
    try {
      const r = await fetch(`${API}${path}`, { headers: hdrs, signal: AbortSignal.timeout(30000) });
      if (r.status === 404) return null;
      if (r.ok) return await r.json();
      if (r.status < 500 && r.status !== 429) throw new Error(`${r.status} ${path}`);
    } catch (e) { if (i === 2) throw e; }
    await new Promise((res) => setTimeout(res, 1000 * (i + 1)));
  }
  throw new Error(`GitHub API ${path} kept failing`);
}
const sleep = (s) => new Promise((r) => setTimeout(r, s * 1000));
const short = (s) => (s ? s.slice(0, 12) : '');

// ---- gate lookup ----------------------------------------------------------------------------------------------------
const tagCommit = new Map();
async function commitFor(repo) {
  if (repo === A.repo) return A.commit;
  if (!tagCommit.has(repo)) {
    const c = await api(`/repos/${repo}/commits/${encodeURIComponent(A.tag)}`).catch(() => null);
    tagCommit.set(repo, c?.sha ?? null);
  }
  return tagCommit.get(repo);
}
const runsOf = async (repo, wf, q) => (await api(`/repos/${repo}/actions/workflows/${encodeURIComponent(wf)}/runs?per_page=50&${q}`))?.workflow_runs ?? [];
const newest = (runs) => [...runs].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.id - a.id);
async function jobsOf(repo, runId) {
  const out = [];
  for (let page = 1; page <= 10; page++) {
    const j = await api(`/repos/${repo}/actions/runs/${runId}/jobs?filter=latest&per_page=100&page=${page}`);
    out.push(...(j?.jobs ?? []));
    if (!j || out.length >= (j.total_count ?? 0) || (j.jobs ?? []).length === 0) break;
  }
  return out;
}

async function lookup(g) {
  const repo = g.repo ?? A.repo;
  const res = { id: g.id, label: g.label, workflow: g.workflow, repo, required: g.required !== false, run: null, result: 'missing',
    at_release_commit: false, note: null, jobs: [], artifacts: [] };
  try {
    const sha = await commitFor(repo);
    let pending = null;
    if (sha) {
      const deadline = Date.now() + A.wait * 60000;
      for (;;) {
        const runs = newest(await runsOf(repo, g.workflow, `head_sha=${sha}`));
        const done = runs.find((r) => r.status === 'completed');
        pending = runs.find((r) => r.status !== 'completed' && (!done || Date.parse(r.created_at) > Date.parse(done.created_at)));
        if (done && !pending) { res.run = done; res.at_release_commit = true; break; }
        if (!pending) break;
        if (Date.now() >= deadline) {
          if (done) { res.run = done; res.at_release_commit = true; }
          res.note = `run ${pending.id} at the release commit was still ${pending.status} when this report was written`;
          break;
        }
        await sleep(A.pollSeconds);
      }
    } else if (repo !== A.repo) {
      res.note = `${repo} has no tag ${A.tag}`;
    }
    if (!res.run) {
      const branches = (config.rc_branches ?? ['ci/{version}-rc']).map((b) => b.replaceAll('{version}', A.version));
      const cands = [];
      for (const b of branches) cands.push(...(await runsOf(repo, g.workflow, `branch=${encodeURIComponent(b)}&status=completed`)));
      const r = newest(cands).find((x) => x.status === 'completed');
      if (r) {
        res.run = r;
        const why = `no completed run at the release commit; newest run on ${r.head_branch} (commit ${short(r.head_sha)})`;
        res.note = res.note ? `${res.note}; ${why}` : why;
        if (sha && r.head_sha !== sha) res.compare = `${SERVER}/${repo}/compare/${r.head_sha}...${sha}`;
      }
    }
    if (!res.run) { res.note = res.note ?? 'no completed run found at the release commit or on the release-candidate branches'; return res; }
    const jobs = g.job || g.jobs ? await jobsOf(repo, res.run.id) : [];
    if (g.job) {
      const j = jobs.find((x) => x.name === g.job || x.name.startsWith(`${g.job} `));
      res.result = j ? (j.conclusion ?? j.status) : 'missing';
      if (!j) res.note = `${res.note ? `${res.note}; ` : ''}the run has no job "${g.job}"`;
    } else {
      res.result = res.run.conclusion ?? res.run.status;
    }
    if (g.jobs) res.jobs = jobs.map((j) => ({ name: j.name, result: j.conclusion ?? j.status, url: j.html_url }));
    for (const a of g.artifacts ?? []) res.artifacts.push(await artifact(repo, res.run.id, a));
  } catch (e) {
    res.result = 'error';
    res.note = `lookup failed: ${String(e.message ?? e).slice(0, 160)}`;
  }
  return res;
}

// ---- artifacts ------------------------------------------------------------------------------------------------------
async function artifact(repo, runId, a) {
  const out = { name: a.name, kind: a.kind, available: false, summary: null };
  const list = await api(`/repos/${repo}/actions/runs/${runId}/artifacts?per_page=100&name=${encodeURIComponent(a.name)}`);
  const art = (list?.artifacts ?? []).find((x) => x.name === a.name && !x.expired);
  if (!art) { out.summary = 'not uploaded by this run (or expired)'; return out; }
  const tmp = mkdtempSync(join(tmpdir(), 'evidence-'));
  try {
    const r = await fetch(art.archive_download_url, { headers: hdrs, redirect: 'follow', signal: AbortSignal.timeout(120000) });
    if (!r.ok) { out.summary = `download refused (${r.status})`; return out; }
    writeFileSync(join(tmp, 'a.zip'), Buffer.from(await r.arrayBuffer()));
    const u = spawnSync('unzip', ['-q', '-o', join(tmp, 'a.zip'), '-d', join(tmp, 'x')], { encoding: 'utf8' });
    if (u.status !== 0) { out.summary = 'archive could not be unpacked'; return out; }
    const file = readdirSync(join(tmp, 'x'), { recursive: true }).map(String).find((f) => f.split('/').pop() === a.file);
    if (!file) { out.summary = `${a.file} not in the artifact`; return out; }
    const data = JSON.parse(readFileSync(join(tmp, 'x', file), 'utf8'));
    out.available = true;
    out.summary = summarise(a.kind, data);
  } catch (e) {
    out.summary = `unreadable: ${String(e.message ?? e).slice(0, 120)}`;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  return out;
}
function summarise(kind, d) {
  if (kind === 'mutation') {
    return { tool: d.tool ?? null, verdict: d.verdict ?? null, score: d.score ?? null, counts: d.counts ?? null, survivors: d.survivors ?? null,
      listed_equivalents: d.listed_equivalents ?? null, packages: d.packages ?? null };
  }
  if (kind === 'cross-language') {
    return { languages: d.status ?? {}, suites: Object.fromEntries(Object.entries(d.suites ?? {}).map(([l, s]) => [l, s.declared ?? []])),
      counts: d.counts ?? {}, unwaived: (d.problems ?? []).length, waived: (d.waived ?? []).map((w) => ({ name: w.name, reason: w.reason })) };
  }
  return d;
}

// ---- local inputs ---------------------------------------------------------------------------------------------------
const readJson = (f, what) => { try { return JSON.parse(readFileSync(f, 'utf8')); } catch (e) { return { __error: `${what} ${f}: ${e.message.slice(0, 120)}` }; } };
function sbomSummary(f) {
  if (!existsSync(f)) return { file: f.split('/').pop(), ok: false, error: 'missing' };
  const b = readJson(f, 'SBOM');
  if (b.__error || b.bomFormat !== 'CycloneDX') return { file: f.split('/').pop(), ok: false, error: b.__error ?? 'not CycloneDX' };
  const n = (b.components ?? []).length;
  return { file: f.split('/').pop(), ok: n > 0, format: `CycloneDX ${b.specVersion}`, components: n, packages: (b.dependencies?.[0]?.dependsOn ?? []).length,
    serialNumber: b.serialNumber ?? null, ...(n > 0 ? {} : { error: 'no components' }) };
}
function vulnSummary(f) {
  const v = readJson(f, 'vulnerability result');
  if (v.__error) return { file: f, verdict: 'fail', error: v.__error };
  return { ecosystem: v.ecosystem, tool: v.tool, verdict: v.verdict, counts: v.counts, checked_on: v.checked_on,
    findings: (v.findings ?? []).map((x) => ({ id: x.id, package: x.package, version: x.version, severity: x.severity, allowlisted: x.allowlisted, blocking: x.blocking })),
    warnings: v.warnings ?? [], allowlist: { used: v.allowlist?.used ?? [], unused: v.allowlist?.unused ?? [], invalid: v.allowlist?.invalid ?? [] } };
}
const packages = A.packages ? readJson(A.packages, 'packages') : [];
const sums = A.sums && existsSync(A.sums)
  ? readFileSync(A.sums, 'utf8').split('\n').filter(Boolean).map((l) => { const [sha256, ...f] = l.trim().split(/\s+/); return { file: f.join(' ').replace(/^\*/, ''), sha256 }; })
  : [];
const toolchain = A.toolchain && existsSync(A.toolchain)
  ? Object.fromEntries(readFileSync(A.toolchain, 'utf8').split('\n').filter((l) => l.includes('=')).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1).trim()]))
  : {};

// ---- main -----------------------------------------------------------------------------------------------------------
const gates = [];
for (const g of config.gates) gates.push(await lookup(g));
let thisRun = null;
if (A.runId) {
  try {
    const jobs = await jobsOf(A.repo, A.runId);
    thisRun = { id: Number(A.runId), attempt: Number(A.runAttempt), url: `${SERVER}/${A.repo}/actions/runs/${A.runId}`,
      jobs: jobs.map((j) => ({ name: j.name, result: j.conclusion ?? j.status, steps: (j.steps ?? []).map((s) => ({ name: s.name, result: s.conclusion ?? s.status })) })) };
  } catch (e) { thisRun = { id: Number(A.runId), url: `${SERVER}/${A.repo}/actions/runs/${A.runId}`, error: String(e.message ?? e).slice(0, 160) }; }
}
const sboms = A.sboms.map(sbomSummary);
const vulns = A.vulns.map(vulnSummary);

const exceptions = [];
const ex = (kind, text, ref) => exceptions.push({ kind, text, ...(ref ? { ref } : {}) });
if (A.dryRun) ex('dry-run', 'This is a dry run: nothing was published to the registry.');
for (const g of gates) {
  const where = g.repo === A.repo ? '' : ` (${g.repo})`;
  if (g.result !== 'success') ex(g.required ? 'gate' : 'gate-optional', `${g.label}${where}: ${g.result}${g.note ? ` (${g.note})` : ''}`, g.run?.html_url);
  else if (!g.at_release_commit) ex('gate-commit', `${g.label}${where}: passed on commit ${short(g.run.head_sha)}, not on the release commit${g.note?.includes('still') ? ` (${g.note.split(';')[0]})` : ''}`, g.compare ?? g.run.html_url);
  for (const j of g.jobs) if (!['success', 'skipped'].includes(j.result)) ex('gate-job', `${g.label}${where}: job "${j.name}" ${j.result}`, j.url);
  for (const a of g.artifacts) {
    if (!a.available) ex('evidence', `${g.label}${where}: artifact ${a.name} ${a.summary}`);
    else if (a.kind === 'cross-language') for (const w of a.summary.waived) ex('waived', `${g.label}${where}: waived disagreement ${w.name}: ${w.reason}`);
  }
}
for (const v of vulns) {
  if (v.error) { ex('vulnerability', `vulnerability result unreadable: ${v.error}`); continue; }
  for (const f of v.findings) {
    if (f.allowlisted) ex('vulnerability', `${v.ecosystem} ${f.package} ${f.version ?? ''}: ${f.id} (${f.severity}) allowlisted until ${f.allowlisted.expires}: ${f.allowlisted.reason}`);
    else if (!f.blocking) ex('vulnerability-below-threshold', `${v.ecosystem} ${f.package} ${f.version ?? ''}: ${f.id} (${f.severity}), below the release threshold`);
    else ex('vulnerability', `${v.ecosystem} ${f.package} ${f.version ?? ''}: ${f.id} (${f.severity}) BLOCKING`);
  }
  for (const w of v.warnings) ex('advisory-warning', `${v.ecosystem} ${w.package ?? ''} ${w.version ?? ''}: ${w.kind}${w.id ? ` ${w.id}` : ''}`);
  for (const i of v.allowlist.invalid) ex('allowlist', `invalid allowlist entry ${i.entry?.id ?? '?'}: ${i.problems.join('; ')}`);
}
for (const s of sboms) if (!s.ok) ex('sbom', `SBOM ${s.file}: ${s.error}`);
for (const k of config.known_exceptions ?? []) ex('known', k);

const failures = [
  ...gates.filter((g) => g.required && g.result !== 'success').map((g) => `required gate ${g.id}: ${g.result}`),
  ...vulns.filter((v) => v.verdict !== 'pass').map((v) => `vulnerability gate ${v.ecosystem ?? v.file}: ${v.verdict}`),
  ...sboms.filter((s) => !s.ok).map((s) => `SBOM ${s.file}: ${s.error}`),
  ...(A.sboms.length ? [] : ['no SBOM given']),
  ...(A.vulns.length ? [] : ['no vulnerability result given']),
];
const report = {
  schema: 'pca-release-evidence/1',
  release: config.release ?? A.repo, repository: A.repo, tag: A.tag, version: A.version, commit: A.commit,
  commit_url: `${SERVER}/${A.repo}/commit/${A.commit}`, dry_run: A.dryRun, generated_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
  release_run: thisRun, packages: Array.isArray(packages) ? packages.map((p) => ({ name: p.name, version: p.version, ...(p.file ? { file: p.file } : {}) })) : packages,
  artifacts: sums, toolchain,
  gates: gates.map((g) => ({ id: g.id, label: g.label, repository: g.repo, workflow: g.workflow, required: g.required, result: g.result,
    at_release_commit: g.at_release_commit, run_id: g.run?.id ?? null, run_attempt: g.run?.run_attempt ?? null, run_url: g.run?.html_url ?? null,
    run_commit: g.run?.head_sha ?? null, run_branch: g.run?.head_branch ?? null, run_finished_at: g.run?.updated_at ?? null,
    note: g.note, ...(g.compare ? { compare: g.compare } : {}), jobs: g.jobs, artifacts: g.artifacts })),
  sbom: sboms, vulnerabilities: vulns, exceptions,
  verdict: failures.length ? 'incomplete' : 'complete', failures,
};

// ---- markdown -------------------------------------------------------------------------------------------------------
const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
const icon = (r) => (r === 'success' || r === 'pass' ? 'pass' : r === 'skipped' ? 'skipped' : `**${r}**`);
const md = [];
md.push(`# Security evidence: ${report.release} ${A.version}`, '');
md.push(`- Tag: \`${A.tag}\`${A.dryRun ? ' (dry run: nothing published)' : ''}`);
md.push(`- Commit: [\`${A.commit}\`](${report.commit_url})`);
if (thisRun) md.push(`- Release workflow run: [${thisRun.id}](${thisRun.url}) (attempt ${A.runAttempt})`);
md.push(`- Generated: ${report.generated_at}`);
md.push(`- Evidence verdict: **${report.verdict}**${failures.length ? `: ${failures.join('; ')}` : ''}`, '');
md.push('Machine-readable copy: the `.json` file with the same name. Both are listed in `SHA256SUMS` and carry a build-provenance attestation (`gh attestation verify <file> --repo ' + A.repo + '`).', '');
if (report.packages.length) {
  md.push('## Packages', '', '| package | version |', '|---|---|', ...report.packages.map((p) => `| \`${cell(p.name)}\` | ${cell(p.version)} |`), '');
}
md.push('## Gates', '', '| gate | result | run | commit | note |', '|---|---|---|---|---|');
for (const g of report.gates) {
  const run = g.run_id ? `[${g.run_id}](${g.run_url})` : '-';
  const at = g.run_commit ? (g.at_release_commit ? 'release commit' : `\`${short(g.run_commit)}\`${g.compare ? ` ([diff](${g.compare}))` : ''}`) : '-';
  md.push(`| ${cell(g.label)}${g.repository !== A.repo ? ` (${cell(g.repository)})` : ''}${g.required ? '' : ' (informational)'} | ${icon(g.result)} | ${run} | ${at} | ${cell(g.note ?? '')} |`);
}
md.push('');
for (const g of report.gates) {
  if (!g.jobs.length && !g.artifacts.length) continue;
  md.push(`### ${g.label}`, '');
  if (g.jobs.length) md.push('| job | result |', '|---|---|', ...g.jobs.map((j) => `| ${cell(j.name)} | ${icon(j.result)} |`), '');
  for (const a of g.artifacts) {
    if (!a.available) { md.push(`- \`${a.name}\`: ${a.summary}`, ''); continue; }
    if (a.kind === 'mutation') {
      const s = a.summary;
      md.push(`- Mutation merge: **${s.verdict ?? '?'}**, score ${s.score ?? '?'}${s.tool ? ` (${s.tool})` : ''}; counts ${JSON.stringify(s.counts ?? {})}`
        + `${s.survivors !== null ? `; ${s.survivors} survivor(s)` : ''}${s.listed_equivalents !== null ? `, ${s.listed_equivalents} listed equivalent(s)` : ''}`, '');
    } else if (a.kind === 'cross-language') {
      const s = a.summary;
      md.push(`- \`${a.name}\`: ${s.unwaived} unwaived disagreement(s), ${s.waived.length} waived; vectors ${JSON.stringify(s.counts)}`, '');
      md.push('| language | status | suites |', '|---|---|---|', ...Object.entries(s.languages).map(([l, st]) => `| ${l} | ${cell(st)} | ${cell((s.suites[l] ?? []).join(', '))} |`), '');
    } else md.push(`- \`${a.name}\`: \`${cell(JSON.stringify(a.summary).slice(0, 300))}\``, '');
  }
}
if (thisRun?.jobs?.length) {
  md.push('## This release run', '');
  for (const j of thisRun.jobs) {
    md.push(`- ${j.name}: ${icon(j.result)}`);
    for (const s of j.steps.filter((x) => !/^(Set up job|Complete job|Post |Run actions\/)/.test(x.name))) md.push(`  - ${s.name}: ${icon(s.result)}`);
  }
  md.push('');
}
md.push('## SBOM', '');
if (!sboms.length) md.push('No SBOM was given.', '');
for (const s of sboms) md.push(s.ok ? `- \`${s.file}\`: ${s.format}, ${s.packages} package(s), ${s.components} component(s), ${s.serialNumber}` : `- \`${s.file}\`: **${s.error}**`);
md.push('');
md.push('## Dependency vulnerabilities', '');
if (!vulns.length) md.push('No vulnerability result was given.', '');
for (const v of vulns) {
  if (v.error) { md.push(`- **unreadable**: ${v.error}`); continue; }
  const c = v.counts;
  md.push(`- ${v.ecosystem} (${v.tool}, ${v.checked_on}): **${v.verdict}**: ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low, ${c.unknown} unrated; ${c.allowlisted} allowlisted; ${c.blocking} blocking`);
}
md.push('', 'Release threshold: a high, critical or unrated finding fails the release unless a reviewed, unexpired allowlist entry covers it.', '');
md.push('## Outstanding exceptions', '');
if (!exceptions.length) md.push('None.');
for (const e of exceptions) md.push(`- [${e.kind}] ${e.text}${e.ref ? ` ([link](${e.ref}))` : ''}`);
md.push('');
if (Object.keys(toolchain).length) md.push('## Toolchain', '', ...Object.entries(toolchain).map(([k, v]) => `- ${k}: ${v}`), '');
if (sums.length) md.push('## Artifacts (SHA-256)', '', '| file | sha256 |', '|---|---|', ...sums.map((s) => `| ${cell(s.file)} | \`${s.sha256}\` |`), '');

mkdirSync(A.outDir, { recursive: true });
const base = `security-evidence-${A.repo.split('/').pop()}-${A.version}`;
writeFileSync(join(A.outDir, `${base}.json`), JSON.stringify(report, null, 2) + '\n');
writeFileSync(join(A.outDir, `${base}.md`), md.join('\n'));
console.log(`release-evidence: ${join(A.outDir, base)}.{md,json}: ${gates.length} gate(s), ${exceptions.length} exception(s), verdict ${report.verdict}`);
for (const f of failures) console.log(`${A.strict ? '::error::' : '::warning::'}evidence: ${f}`);
if (process.env.GITHUB_STEP_SUMMARY) writeFileSync(process.env.GITHUB_STEP_SUMMARY, md.join('\n') + '\n', { flag: 'a' });
process.exit(A.strict && failures.length ? 1 : 0);
