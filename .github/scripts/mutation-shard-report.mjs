#!/usr/bin/env node
// Write one shard's report for mutation-merge.mjs:
//   node mutation-shard-report.mjs --crate=<crate> --shard=<k> --of=<N> --tool=<name> --counts=<counts.json> --survivors=<survivors.json> --out=<shard-k.json>
// counts.json: { "<status>": n, ... }; survivors.json: [{ crate, file, mutant, line, occurrence?, lineno?, fn? }].
// Only written when the shard's tool step succeeded: a failed shard leaves no report and fails the merge.
import fs from 'node:fs';
const opt = (n) => process.argv.slice(2).find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3);
const [crate, tool, out] = [opt('crate'), opt('tool'), opt('out')];
const shard = Number(opt('shard')), of = Number(opt('of'));
const counts = JSON.parse(fs.readFileSync(opt('counts'), 'utf8'));
const survivors = JSON.parse(fs.readFileSync(opt('survivors'), 'utf8'));
for (const s of survivors) {
  if (s.crate !== crate || typeof s.file !== 'string' || typeof s.mutant !== 'string' || typeof s.line !== 'string') {
    console.error(`malformed survivor record: ${JSON.stringify(s).slice(0, 200)}`);
    process.exit(1);
  }
}
const total = Object.values(counts).reduce((a, b) => a + b, 0);
if (total === 0) { console.error('shard ran 0 mutants: refusing to report an empty shard as a pass'); process.exit(1); }
fs.writeFileSync(out, JSON.stringify({ shard, of, crate, tool, ok: true, counts, survivors }, null, 1));
console.log(`${crate} shard ${shard}/${of} (${tool}): ${JSON.stringify(counts)}, ${survivors.length} survivor(s)`);
