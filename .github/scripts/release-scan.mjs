#!/usr/bin/env node
// release-scan.mjs: refuse to publish a release artifact that carries a secret, a private key or a build-machine path.
//
//   node .github/scripts/release-scan.mjs <artifact|dir> ...
//     artifacts: .tgz / .tar.gz / .crate (gzip tar), .whl / .zip; a directory is scanned file by file.
//   exit 0: clean.  exit 1: findings.  exit 2: usage error or an artifact that could not be opened (fail closed).
//
// Every member of every artifact is read as bytes (latin1, so binary members and invalid UTF-8 never hide a match) and
// checked for:
//   private-key  a PEM private-key block
//   secret       registry / cloud / chat token shapes (npm, GitHub, PyPI, crates.io, AWS, Slack, Stripe)
//   home-path    a developer or CI home directory (macOS, Linux, Windows): a build that leaked its own location
//   credentials  a credentials file shipped as a member (.npmrc, .pypirc, .netrc, .env, cargo credentials)
// Findings name the artifact, the member and the category, never the matched value.
// The sources were already scanned before they reached this repository; this scan covers what the BUILD added.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, relative } from 'node:path';

// Patterns are assembled from fragments so this file does not itself match them.
const J = (...p) => p.join('');
const BEGIN = J('-----', 'BEGIN');
const PATTERNS = [
  { cat: 'private-key', re: new RegExp(J(BEGIN, ' ([A-Z0-9]+ )*PRIV', 'ATE KEY-----')) },
  { cat: 'secret', re: new RegExp(J('(?<![A-Za-z0-9_])', 'npm', '_[A-Za-z0-9]{36}(?![A-Za-z0-9])')) },
  { cat: 'secret', re: new RegExp(J('(?<![A-Za-z0-9_])', 'gh', '[pousr]_[A-Za-z0-9]{36,}')) },
  { cat: 'secret', re: new RegExp(J('github', '_pat_[A-Za-z0-9_]{50,}')) },
  { cat: 'secret', re: new RegExp(J('pypi', '-AgE[A-Za-z0-9_-]{40,}')) },
  { cat: 'secret', re: new RegExp(J('(?<![A-Za-z0-9])', 'AK', 'IA[0-9A-Z]{16}(?![0-9A-Z])')) },
  { cat: 'secret', re: new RegExp(J('xo', 'x[abprs]-[A-Za-z0-9-]{10,}')) },
  { cat: 'secret', re: new RegExp(J('(?<![A-Za-z0-9])', '[sr]k', '_live_[A-Za-z0-9]{16,}')) },
  // crates.io tokens are "cio" + 32 alphanumerics: a shape random base64 also produces, so only on short lines
  { cat: 'secret', short: true, re: new RegExp(J('(?<![A-Za-z0-9])', 'ci', 'o[A-Za-z0-9]{32}(?![A-Za-z0-9])')) },
  // home directories. Placeholder names used in docs are allowed (ALLOWED_HOME).
  { cat: 'home-path', home: true, re: new RegExp(J('/', 'Users', '/([A-Za-z0-9._-]{1,64})/'), 'g') },
  { cat: 'home-path', home: true, re: new RegExp(J('/', 'home', '/([A-Za-z0-9._-]{1,64})/'), 'g') },
  { cat: 'home-path', home: true, re: new RegExp(J('[A-Za-z]:\\\\{1,2}', 'Users', '\\\\{1,2}([A-Za-z0-9._ -]{1,64})\\\\'), 'gi') },
];
const ALLOWED_HOME = new Set(['user', 'username', 'you', 'your-name', 'yourname', 'me', 'name', 'example', 'alice', 'bob',
  'foo', 'shared', 'public', 'default', 'dev', 'app', 'node', 'nobody', 'x', '...', 'u', '$user', 'jane', 'john']);
const CREDENTIAL_FILES = /(^|\/)(\.npmrc|\.pypirc|\.netrc|\.env(\.[^/]*)?|credentials(\.toml)?|\.git-credentials)$/;
const SHORT_LINE = 400;
const MAX_MEMBER = 64 << 20;

const args = process.argv.slice(2);
if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
  console.error('usage: release-scan.mjs <artifact|dir> ...');
  process.exit(2);
}

const findings = [];
let opened = 0;
let failedOpen = 0;

function walk(dir) {
  const out = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    const st = statSync(p);
    if (st.isDirectory()) out.push(...walk(p));
    else if (st.isFile()) out.push(p);
  }
  return out;
}

function scanBuffer(label, member, buf) {
  if (CREDENTIAL_FILES.test(member)) findings.push(`${label} :: ${member} : credentials (file name)`);
  const text = buf.toString('latin1');
  const hit = new Set();
  for (const p of PATTERNS) {
    if (p.home) {
      p.re.lastIndex = 0;
      for (const m of text.matchAll(p.re)) {
        if (!ALLOWED_HOME.has(m[1].toLowerCase())) { hit.add(p.cat); break; }
      }
    } else if (p.short) {
      for (const line of text.split('\n')) {
        if (line.length <= SHORT_LINE && p.re.test(line)) { hit.add(p.cat); break; }
      }
    } else if (p.re.test(text)) {
      hit.add(p.cat);
    }
  }
  for (const c of hit) findings.push(`${label} :: ${member} : ${c}`);
}

function scanTree(label, root) {
  for (const f of walk(root)) {
    const st = statSync(f);
    if (st.size > MAX_MEMBER) { findings.push(`${label} :: ${relative(root, f)} : too large to scan (fail closed)`); continue; }
    scanBuffer(label, relative(root, f).split('\\').join('/'), readFileSync(f));
  }
}

function extract(artifact, into) {
  const name = basename(artifact);
  let r;
  if (/\.(tgz|tar\.gz|crate)$/.test(name)) r = spawnSync('tar', ['-xzf', artifact, '-C', into], { encoding: 'utf8' });
  else if (/\.(whl|zip)$/.test(name)) r = spawnSync('python3', ['-I', '-c', 'import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])', artifact, into], { encoding: 'utf8' });
  else return null;
  return r.status === 0 ? true : (r.stderr || r.error?.message || 'extract failed').trim().split('\n').pop();
}

for (const target of args) {
  if (!existsSync(target)) { console.error(`missing: ${target}`); failedOpen++; continue; }
  if (statSync(target).isDirectory()) { scanTree(target, target); opened++; continue; }
  const tmp = mkdtempSync(join(process.env.RUNNER_TEMP ?? tmpdir(), 'release-scan-'));
  try {
    const ok = extract(target, tmp);
    if (ok === null) { scanBuffer(basename(target), basename(target), readFileSync(target)); opened++; }
    else if (ok === true) { scanTree(basename(target), tmp); opened++; }
    else { console.error(`cannot open ${basename(target)}: ${ok}`); failedOpen++; }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

for (const f of findings) console.log(f);
console.log(`release-scan: ${opened} artifact(s) scanned, ${findings.length} finding(s), ${failedOpen} unreadable`);
process.exit(failedOpen ? 2 : findings.length ? 1 : 0);
