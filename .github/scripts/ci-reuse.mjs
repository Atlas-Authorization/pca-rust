#!/usr/bin/env node
// Input-hash reuse for the heavy workflows (a run is skipped when an earlier green run recorded the same input hash).
//   node ci-reuse.mjs check  --workflow=<slug> [--self=<.github/workflows/x.yml>] [--exclude=<glob,...>] [--external=<spec> ...]
//                            [--extra=<text>] [--ref=<ref of the externals>] [--always-full]
//   node ci-reuse.mjs record --workflow=<slug> --hash=<hash from check> --out=<dir> [--always-full]
// env: GH_TOKEN, GITHUB_REPOSITORY, GITHUB_REF_NAME, GITHUB_RUN_ID, GITHUB_OUTPUT, GITHUB_STEP_SUMMARY,
//      FORCE_FULL (bypass the lookup), GATE_FULL (this run is a full run: only a full record may stand for it), PARTIAL (never reuse).
// check never fails the job: any problem means "no reuse". It prints skip=true only when an earlier run recorded the same
// hash (a record exists only when every job of that run succeeded), is not expired, is < MAX_AGE_DAYS old, and ran on a ci/** branch
// or this branch. Externals: flagship | natives | repo:<name>[:<path>;<path>] (tree shas of a blobless depth-1 clone).
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const FORMAT = 1;
export const MAX_AGE_DAYS = 14;
const NATIVES = ['go', 'python', 'ruby', 'php', 'dotnet', 'rust', 'java', 'kotlin', 'swift'];
const sha = (s) => createHash('sha256').update(s).digest('hex');
const truthy = (v) => /^(true|1|yes)$/i.test(String(v ?? '').trim());

// glob -> RegExp: `**` any depth, `*` within a segment, a trailing `/` = a directory prefix, `.ext` style `*.md` matches at any depth.
export function globToRe(g) {
  if (g.endsWith('/')) g += '**';
  let re = '';
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === '*' && g[i + 1] === '*') { re += '.*'; i++; if (g[i + 1] === '/') i++; }
    else if (c === '*') re += '[^/]*';
    else re += c.replace(/[.+^${}()|[\]\\?]/g, '\\$&');
  }
  return new RegExp(`^${g.includes('/') ? '' : '(?:.*/)?'}${re}$`);
}

// the hashed file list: `git ls-files -s` of `root`, minus the excludes and (default) every workflow file but `self`
export function fileLines(root, { exclude = [], self = '' } = {}) {
  const ex = exclude.map(globToRe);
  const out = execFileSync('git', ['-C', root, 'ls-files', '-s', '-z'], { encoding: 'utf8', maxBuffer: 1 << 29 }).split('\0').filter(Boolean);
  const lines = [];
  for (const rec of out) {
    const tab = rec.indexOf('\t'), path = rec.slice(tab + 1);
    if (/^\.github\/workflows\/[^/]+$/.test(path) && path !== self) continue;
    if (ex.some((r) => r.test(path))) continue;
    lines.push(`${rec.slice(0, tab)} ${path}`); // "mode blob stage path"
  }
  return lines.sort();
}

const git = (args, opt = {}) => execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opt }).trim();

// tree fingerprint of a remote repo at a ref (blobless, depth 1); null when the ref does not exist or the clone fails
function remoteTree(repo, ref, paths) {
  const owner = process.env.GITHUB_REPOSITORY_OWNER || (process.env.GITHUB_REPOSITORY || 'Atlas-Authorization/x').split('/')[0];
  const dir = mkdtempSync(join(tmpdir(), 'reuse-ext-'));
  try {
    git(['clone', '-q', '--depth', '1', '--filter=blob:none', '--no-checkout', '--branch', ref, `https://github.com/${owner}/${repo}.git`, dir]);
    if (!paths?.length) return `${repo}@${git(['-C', dir, 'rev-parse', 'HEAD^{tree}'])}`;
    return paths.map((p) => { try { return `${repo}:${p}=${git(['-C', dir, 'rev-parse', `HEAD:${p}`])}`; } catch { return `${repo}:${p}=absent`; } }).join('\n');
  } catch { return null; } finally { rmSync(dir, { recursive: true, force: true }); }
}

// the sparse path list fetch-flagship-corpus.sh checks out of the flagship (read from the script: the two cannot drift)
function flagshipPaths(root) {
  const t = readFileSync(join(root, '.github/scripts/fetch-flagship-corpus.sh'), 'utf8');
  const m = /sparse-checkout set ([^\n]+)/.exec(t);
  if (!m) throw new Error('no sparse-checkout list in fetch-flagship-corpus.sh');
  return m[1].trim().split(/\s+/);
}

export function externals(specs, ref, root) {
  const parts = [];
  for (const s of specs) {
    let r;
    if (s === 'flagship') r = remoteTree('pca', ref, flagshipPaths(root));
    else if (s === 'natives') { const t = NATIVES.map((l) => remoteTree(`pca-${l}`, ref)); r = t.includes(null) ? null : t.join('\n'); }
    else if (s.startsWith('repo:')) { const [, name, p] = s.split(':'); r = remoteTree(name, ref, p ? p.split(';') : undefined); }
    else throw new Error(`unknown external ${s}`);
    if (r === null) return { unknown: `${s} at ref ${ref} is not available` };
    parts.push(`X ${s}\n${r}`);
  }
  return { text: parts.join('\n') };
}

export function computeHash({ workflow, extra = '', lines, ext = '' }) {
  return sha([`V${FORMAT}`, workflow, extra, ...lines, ext].join('\n'));
}

const name = (workflow, hash, mode) => `ci-reuse-${workflow}-${hash.slice(0, 40)}-${mode}`;
const gh = (args) => execFileSync('gh', ['api', ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 26 });
const setOut = (k, v) => process.env.GITHUB_OUTPUT && appendFileSync(process.env.GITHUB_OUTPUT, `${k}=${v}\n`);
const summary = (t) => process.env.GITHUB_STEP_SUMMARY && appendFileSync(process.env.GITHUB_STEP_SUMMARY, t + '\n');

function parse(argv) {
  const o = { external: [] };
  for (const a of argv) {
    const m = /^--([a-z-]+)(?:=(.*))?$/s.exec(a);
    if (!m) continue;
    if (m[1] === 'external') o.external.push(m[2]); else o[m[1]] = m[2] ?? true;
  }
  return o;
}

function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const o = parse(rest);
  const workflow = o.workflow;
  const alwaysFull = !!o['always-full'];
  const mode = alwaysFull || truthy(process.env.GATE_FULL) ? 'full' : 'inc';
  if (cmd === 'record') {
    if (!o.hash) { console.error('record: no hash (the check did not produce one): nothing recorded'); return; }
    mkdirSync(o.out, { recursive: true });
    const art = name(workflow, o.hash, mode);
    writeFileSync(join(o.out, 'record.json'), JSON.stringify({ format: FORMAT, workflow, hash: o.hash, mode, run_id: process.env.GITHUB_RUN_ID, sha: process.env.GITHUB_SHA, branch: process.env.GITHUB_REF_NAME, created_at: new Date().toISOString() }, null, 1));
    setOut('artifact', art);
    console.log(`recording ${art}`);
    return;
  }
  if (cmd !== 'check') { console.error('usage: ci-reuse.mjs check|record'); process.exit(2); }
  setOut('skip', '');
  try {
    const root = process.cwd();
    const lines = fileLines(root, { exclude: (o.exclude || '').split(',').filter(Boolean), self: o.self || '' });
    const ref = o.ref || process.env.GITHUB_REF_NAME || 'main';
    const ext = externals(o.external, ref, root);
    if (ext.unknown) { console.log(`::notice::no reuse: ${ext.unknown}`); return; }
    const hash = computeHash({ workflow, extra: o.extra || '', lines, ext: ext.text || '' });
    setOut('hash', hash);
    console.log(`input hash ${hash} (${lines.length} tracked file(s), ${o.external.length} external(s), mode ${mode})`);
    if (truthy(process.env.FORCE_FULL)) { console.log('::notice::FORCE_FULL set: the work is redone'); return; }
    if (truthy(process.env.PARTIAL)) { console.log('::notice::partial run: never reuses'); return; }
    const repo = process.env.GITHUB_REPOSITORY, branch = process.env.GITHUB_REF_NAME, me = String(process.env.GITHUB_RUN_ID);
    // a full run accepts only a full record; an iteration run accepts either
    for (const m of mode === 'full' ? ['full'] : ['full', 'inc']) {
      const res = JSON.parse(gh([`repos/${repo}/actions/artifacts?name=${name(workflow, hash, m)}&per_page=30`]));
      for (const a of res.artifacts || []) {
        const age = (Date.now() - Date.parse(a.created_at)) / 864e5;
        const hb = a.workflow_run?.head_branch || '';
        if (a.expired || age > MAX_AGE_DAYS || String(a.workflow_run?.id) === me) continue;
        if (!(hb === branch || hb.startsWith('ci/'))) continue;
        const url = `https://github.com/${repo}/actions/runs/${a.workflow_run.id}`;
        console.log(`::notice title=reused::${workflow}: identical inputs already passed in ${url} (${m} run, ${age.toFixed(1)} day(s) old): not re-run`);
        summary(`### Reused\n\n\`${workflow}\` has the same inputs (hash \`${hash.slice(0, 16)}\`) as ${url}, a ${m} run on \`${hb}\` that passed all jobs ${age.toFixed(1)} day(s) ago. The heavy jobs of this run are skipped.`);
        setOut('skip', 'true'); setOut('source', url);
        return;
      }
    }
    console.log('no earlier run with these inputs: the work runs');
    summary(`### No reuse\n\n\`${workflow}\`: no passing run with input hash \`${hash.slice(0, 16)}\` (mode ${mode}) in the last ${MAX_AGE_DAYS} days.`);
  } catch (e) {
    console.log(`::notice::no reuse (check error: ${String(e.stderr || e.message || e).slice(0, 300)})`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main();
