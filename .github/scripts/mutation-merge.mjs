#!/usr/bin/env node
// Merge the shard reports of a sharded mutation run and check the survivors against the equivalent-mutant ledger.
// (Shared by the native repos' mutation.yml; one identical copy per repo under .github/scripts/.)
//
//   node mutation-merge.mjs --crate=<go-pca|...> --shards=N --reports=<dir> --checker=<flagship>/tools/pca-audit --src=<dir>
//
// Every shard writes shard-<k>.json = { shard: k, of: N, crate, tool, ok: true, counts: {...}, survivors: [...] } (survivors in
// the native-check-equivalents.mjs format: { crate, file, mutant, line, occurrence?, lineno?, fn? }). A missing shard, a shard
// with ok != true or a shard of another run (of != N) FAILS the merge: an incomplete run never passes.
// The ledger is the flagship's tools/pca-audit/native-mutation-equivalents.json restricted to this crate, merged with the repo's
// own mutation-equivalents.part.json (if any). PASS = every survivor matches exactly one ledger entry and no ledger entry of the
// crate is STALE (its mutant was not reported as a survivor).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const opt = (n) => process.argv.slice(2).find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3);
const crate = opt('crate'), shards = Number(opt('shards')), reports = opt('reports'), checker = opt('checker'), src = opt('src');
if (!crate || !(shards >= 1) || !reports || !checker || !src) { console.error('usage: mutation-merge.mjs --crate= --shards= --reports= --checker= --src='); process.exit(2); }

const found = new Map();
const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (/^shard-\d+\.json$/.test(e.name)) found.set(p, JSON.parse(fs.readFileSync(p, 'utf8'))); } };
if (fs.existsSync(reports)) walk(reports);
const errors = [];
const byShard = new Map();
for (const [p, r] of found) {
  if (r.of !== shards || r.crate !== crate) { errors.push(`${p}: report of another run (crate ${r.crate}, of ${r.of})`); continue; }
  if (byShard.has(r.shard)) errors.push(`shard ${r.shard} reported twice`);
  byShard.set(r.shard, r);
}
const totals = {};
const survivors = [];
for (let k = 1; k <= shards; k++) {
  const r = byShard.get(k);
  if (!r) { errors.push(`shard ${k}/${shards}: no report (the shard failed or was cancelled)`); continue; }
  if (r.ok !== true) { errors.push(`shard ${k}/${shards}: tool error (${r.error ?? 'ok != true'})`); continue; }
  for (const [s, n] of Object.entries(r.counts ?? {})) totals[s] = (totals[s] ?? 0) + n;
  survivors.push(...r.survivors);
}
const tool = [...byShard.values()][0]?.tool ?? '?';
console.log(`${crate}: ${tool}, ${byShard.size}/${shards} shard reports, counts ${JSON.stringify(totals)}, ${survivors.length} survivor(s)`);
if (errors.length) { console.error(errors.join('\n')); console.error('FAIL: incomplete run'); summary('FAIL (incomplete run)'); evidence('fail', null); process.exitCode = 1; }
else merge();

function merge() {

// root/sdks/<crate> -> the mutated source tree; ledger = this crate's entries (+ the repo's part file via --merge)
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'mutmerge-'));
fs.mkdirSync(path.join(work, 'sdks'));
fs.symlinkSync(path.resolve(src), path.join(work, 'sdks', crate));
const full = JSON.parse(fs.readFileSync(path.join(checker, 'native-mutation-equivalents.json'), 'utf8'));
const mine = full.equivalents.filter((e) => e.crate === crate);
const ledger = path.join(work, 'ledger.json');
fs.writeFileSync(ledger, JSON.stringify({ about: full.about, equivalents: mine }, null, 1));
const survFile = path.join(work, 'survivors.json');
fs.writeFileSync(survFile, JSON.stringify(survivors, null, 1));
fs.copyFileSync(survFile, path.join(reports, 'survivors-merged.json'));

const r = spawnSync('node', [path.join(checker, 'native-check-equivalents.mjs'), '--merge', `--root=${work}`, `--ledger=${ledger}`, survFile], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
process.stdout.write(r.stdout ?? '');
process.stderr.write(r.stderr ?? '');
let rc = r.status ?? 1;
const merged = JSON.parse(fs.readFileSync(ledger, 'utf8')).equivalents.length;
// the checker only looks for STALE entries of crates that appear in the survivor list: with zero survivors, every ledger entry
// of this crate is stale
if (rc === 0 && survivors.length === 0 && merged > 0) { console.error(`FAIL: 0 survivors but ${merged} ledger entries for ${crate}: all STALE`); rc = 1; }
const unlisted = (r.stderr ?? '').split('\n').filter((l) => l.startsWith('UNLISTED SURVIVOR')).length;
const stale = (r.stderr ?? '').split('\n').filter((l) => l.startsWith('STALE')).length;
console.log(`ledger entries for ${crate}: ${merged}; unlisted survivors: ${unlisted}; stale entries: ${stale}`);
summary(rc === 0 ? 'PASS' : `FAIL (${unlisted} unlisted survivor(s), ${stale} stale entr${stale === 1 ? 'y' : 'ies'})`);
evidence(rc === 0 ? 'pass' : 'fail', merged, { unlisted, stale });
// exitCode, not process.exit(): exit() right after a large stderr write to a pipe drops the unflushed tail of the list
process.exitCode = rc;
}

function summary(verdict) {
  const f = process.env.GITHUB_STEP_SUMMARY;
  if (!f) return;
  const rows = Object.entries(totals).map(([s, n]) => `| ${s} | ${n} |`).join('\n');
  fs.appendFileSync(f, `### Mutation: ${crate} (${tool})\n\n**${verdict}**: ${survivors.length} survivor(s) over ${shards} shard(s)\n\n| status | mutants |\n|---|---|\n${rows}\n\n`);
}

// reports/mutation-summary.json: the merge result for the release evidence report (uploaded as the mutation-summary artifact).
// score = detected / (detected + undetected) over the tool's counts (killed / caught / timeout vs survived / missed / no
// tests); every undetected mutant of a passing merge is a listed equivalent.
function evidence(verdict, listed, extra = {}) {
  const sum = (re) => Object.entries(totals).filter(([k]) => re.test(k)).reduce((a, [, n]) => a + n, 0);
  const det = sum(/^(killed|caught|timeout)$/i), und = sum(/^(survived|missed|no[ _-]?tests?|no[ _-]?coverage|nocov)$/i);
  const score = det + und ? `${((100 * det) / (det + und)).toFixed(1)} %` : null;
  fs.mkdirSync(reports, { recursive: true });
  fs.writeFileSync(path.join(reports, 'mutation-summary.json'), JSON.stringify({ crate, tool, shards, shard_reports: byShard.size, verdict, score,
    counts: totals, survivors: survivors.length, listed_equivalents: listed, ...extra }, null, 1) + '\n');
}
