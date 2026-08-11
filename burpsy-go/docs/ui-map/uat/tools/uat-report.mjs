#!/usr/bin/env node
// Join results/index.tsv against every results/*.tsv and print what is actually covered.
//
// The number this exists to print honestly is the **unrun** count. A coverage figure computed over
// only the cases somebody remembered to run is how 1,300 unrun cases came to be described as a test
// matrix; see results/README.md.
//
// Exit code: 0 when the report is coherent, 1 when a results file names a case the matrices do not
// contain, or claims a pass with no evidence. Neither is a test failure — they are reasons the report
// itself cannot be trusted, which is worse.

import { readFileSync, existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const resultsDir = join(here, "..", "results");
const indexPath = join(resultsDir, "index.tsv");

if (!existsSync(indexPath)) {
  console.error("uat-report: results/index.tsv is missing. Run `node uat-index.mjs` first.");
  process.exit(1);
}

/** Parse a TSV with a header row into objects. */
function tsv(path) {
  const lines = readFileSync(path, "utf8").split("\n").filter((line) => line.trim() !== "");
  const header = lines.shift().split("\t");
  return lines.map((line) => {
    const parts = line.split("\t");
    return Object.fromEntries(header.map((key, i) => [key, parts[i] ?? ""]));
  });
}

const cases = tsv(indexPath);
const known = new Map(cases.map((c) => [c.id, c]));

const resultFiles = readdirSync(resultsDir)
  .filter((name) => name.endsWith(".tsv") && name !== "index.tsv")
  .sort();

const VALID = new Set(["pass", "fail", "blocked", "skip"]);
// Latest result per case wins, decided by the `at` timestamp rather than by file order: two runners
// can write two files, and "whichever sorted last alphabetically" is not a rule anyone can reason
// about.
const latest = new Map();
const problems = [];

for (const file of resultFiles) {
  for (const row of tsv(join(resultsDir, file))) {
    const where = `${file}`;
    if (!row.id) continue;
    if (!known.has(row.id)) {
      // Fatal. A result for a case that does not exist inflates the numerator with a row nobody can
      // go back and read — a worse state than having no result at all.
      problems.push(`${where}: result for unknown case ${row.id}`);
      continue;
    }
    if (!VALID.has(row.status)) {
      problems.push(`${where}: case ${row.id} has status ${JSON.stringify(row.status)}; want one of ${[...VALID].join(", ")}`);
      continue;
    }
    if (row.status === "pass" && !row.evidence.trim()) {
      // A pass with no evidence is a recollection. This directory exists because recollection was
      // being counted as coverage.
      problems.push(`${where}: case ${row.id} passes with no evidence`);
      continue;
    }
    if ((row.status === "skip" || row.status === "blocked") && !row.note.trim()) {
      // Counted as unrun rather than rejected: a skip whose reason nobody wrote down is, for
      // reporting purposes, a case that was not run. Reported so it can be fixed.
      problems.push(`${where}: case ${row.id} is ${row.status} with no note — counted as unrun`);
      continue;
    }
    const prior = latest.get(row.id);
    if (!prior || (row.at || "") >= (prior.at || "")) latest.set(row.id, { ...row, file });
  }
}

const tally = { pass: 0, fail: 0, blocked: 0, skip: 0 };
for (const row of latest.values()) tally[row.status]++;
const unrun = cases.length - latest.size;

// Per-type, because the cheap-to-automate subsets are the `keyboard` and `a11y` rows — the plan's
// route to real coverage is driving those from Playwright + axe, and this is the cut that shows
// whether that is working.
const byType = new Map();
for (const c of cases) {
  const type = c.type || "(none)";
  const bucket = byType.get(type) ?? { total: 0, pass: 0, fail: 0, blocked: 0, skip: 0, unrun: 0 };
  bucket.total++;
  const row = latest.get(c.id);
  if (row) bucket[row.status]++;
  else bucket.unrun++;
  byType.set(type, bucket);
}

const pct = (n) => (cases.length === 0 ? "0.0" : ((n / cases.length) * 100).toFixed(1));

console.log(`\nUAT coverage — ${cases.length} cases, ${resultFiles.length} result file(s)\n`);
console.log(`  pass     ${String(tally.pass).padStart(5)}  (${pct(tally.pass)}%)`);
console.log(`  fail     ${String(tally.fail).padStart(5)}`);
console.log(`  blocked  ${String(tally.blocked).padStart(5)}  precondition unmet — not a pass`);
console.log(`  skip     ${String(tally.skip).padStart(5)}  deliberately not run, with a reason`);
console.log(`  UNRUN    ${String(unrun).padStart(5)}  (${pct(unrun)}%)  no result recorded — never a pass`);

console.log(`\n  by type:`);
console.log(`    ${"type".padEnd(12)} ${"total".padStart(6)} ${"pass".padStart(6)} ${"fail".padStart(6)} ${"unrun".padStart(6)}`);
for (const [type, b] of [...byType].sort((a, b) => b[1].total - a[1].total)) {
  console.log(`    ${type.padEnd(12)} ${String(b.total).padStart(6)} ${String(b.pass).padStart(6)} ${String(b.fail).padStart(6)} ${String(b.unrun).padStart(6)}`);
}

if (tally.fail > 0) {
  console.log(`\n  failing cases:`);
  for (const row of [...latest.values()].filter((r) => r.status === "fail")) {
    const c = known.get(row.id);
    console.log(`    ${row.id.padEnd(20)} ${c.section} — ${row.note || "(no note)"} [${row.file}]`);
  }
}

if (problems.length > 0) {
  console.log(`\n  ${problems.length} problem(s) with the results themselves:`);
  for (const problem of problems) console.log(`    ${problem}`);
  console.log(
    `\n  These are not test failures. They are reasons this report cannot be trusted, which is worse:\n` +
      `  a result naming a case that does not exist, or a pass with nothing behind it, both make the\n` +
      `  coverage figure above wrong in the direction that flatters it.`,
  );
  process.exit(1);
}

if (unrun === cases.length) {
  console.log(
    `\n  Nothing has been run yet. That is the honest state, and it is what this tooling was added to\n` +
      `  make sayable: before it, the same situation was described as "1,300 UAT cases".\n` +
      `  The cheapest first cut is the keyboard and a11y rows, which drive from Playwright + axe.\n`,
  );
}
