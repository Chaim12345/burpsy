#!/usr/bin/env node
// Build results/index.tsv from the four UAT matrices.
//
// The matrices are the spec: 1,300 rows of `| ID | Route | Precondition | Steps | Expected | Type |`
// across four files, grouped under `## <page>` headings. The index flattens them to one row per case
// so results can be joined against it, and so a result naming a case that does not exist can be
// caught rather than silently counted.
//
// Deliberately regenerated rather than hand-maintained: a hand-maintained index of 1,300 ids drifts
// from the matrices on the first edit, and then the coverage denominator is wrong in a direction
// nobody notices.

import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { dirname, join, basename } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const uatDir = join(here, "..");
const resultsDir = join(uatDir, "results");

// A case id is upper-case letters/digits/dashes, a number, and optionally a lowercase letter:
// SITEMAP-001, HTTP-HISTORY-042, HISTORY-023b.
//
// The letter suffix is not decoration. The matrices use it for cases inserted after their neighbours
// were already numbered and cross-referenced — `HISTORY-023b`, `HISTORY-023c`, `LOGGER-004b` — and the
// first version of this regex required the id to end in a digit, so it dropped all three **silently**.
// The count came out at 1297 against a hand grep's 1300 and the difference looked like the grep being
// loose; it was this. Which is the failure this whole directory is about: a coverage denominator that
// is quietly missing rows reports better coverage than really exists.
//
// Anchored to the first table cell so the cross-reference tables at the end of each matrix — rows whose
// first cell is a control name and whose second lists a dozen ids — are not read as cases.
const CASE_ROW = /^\|\s*([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d+[a-z]?)\s*\|(.*)$/;

/** Split a markdown table row's remaining cells, trimming each. */
function cells(rest) {
  // Trailing `|` produces an empty final element; dropped so column counts are the visible ones.
  const parts = rest.split("|").map((cell) => cell.trim());
  if (parts.length && parts[parts.length - 1] === "") parts.pop();
  return parts;
}

const rows = [];
const seen = new Map(); // id -> "file:line", so a duplicate can name both places
let duplicates = 0;

const matrices = readdirSync(uatDir)
  .filter((name) => name.endsWith("-uat.md"))
  .sort();

if (matrices.length === 0) {
  console.error("uat-index: found no *-uat.md matrices next to this tool");
  process.exit(1);
}

for (const file of matrices) {
  const text = readFileSync(join(uatDir, file), "utf8");
  let section = "";
  text.split("\n").forEach((line, index) => {
    // `## SiteMap page (sitemap.tsx)` — the page a block of cases belongs to. Kept because the most
    // useful cut of a coverage report is per page, not per file: two pages often share a file.
    const heading = /^#{2,3}\s+(.*?)\s*$/.exec(line);
    if (heading) {
      section = heading[1];
      return;
    }
    const match = CASE_ROW.exec(line);
    if (!match) return;
    const id = match[1];
    const rest = cells(match[2]);
    // Type is the last column. Taken from the end rather than by index so a matrix that adds a
    // column in the middle does not silently start reporting the wrong field as the type.
    const type = rest.length ? rest[rest.length - 1] : "";
    const route = rest.length ? rest[0] : "";
    const where = `${file}:${index + 1}`;
    if (seen.has(id)) {
      console.error(`uat-index: duplicate case id ${id} at ${where} (first seen ${seen.get(id)})`);
      duplicates++;
      return;
    }
    seen.set(id, where);
    rows.push({ id, file, section, route, type, where });
  });
}

// Sorted by id so the file is stable across runs and a regeneration is an empty diff when nothing
// changed. Numeric-aware, so SITEMAP-9 sorts before SITEMAP-10 rather than after it.
const collator = new Intl.Collator("en", { numeric: true });
rows.sort((a, b) => collator.compare(a.id, b.id));

const out = ["id\tfile\tsection\troute\ttype\tsource"]
  .concat(rows.map((r) => [r.id, r.file, r.section, r.route, r.type, r.where].join("\t")))
  .join("\n");
writeFileSync(join(resultsDir, "index.tsv"), out + "\n");

const byType = rows.reduce((acc, r) => ((acc[r.type || "(none)"] = (acc[r.type || "(none)"] ?? 0) + 1), acc), {});
console.log(`uat-index: ${rows.length} cases across ${matrices.length} matrices -> results/index.tsv`);
for (const [type, count] of Object.entries(byType).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${String(count).padStart(5)}  ${type}`);
}

// Type names that differ only by punctuation are the same type spelled two ways, and they split a
// per-type coverage figure in half without anything looking wrong. `happy` and `happy-path` are the
// live example: 657 and 243 rows, one concept, and a report that lists them separately invites the
// reader to conclude the smaller one is a narrow category rather than the same one under another name.
//
// Reported rather than normalised. Normalising here would make the report tidy and leave the matrices
// inconsistent, so the next 900 rows would be written in whichever spelling their author happened to
// see — and the tool would keep quietly papering over it.
// The rule is "one name is the other plus a suffix", not "the names normalise to the same string".
// Stripping punctuation was tried first and does not work: `happy` and `happypath` are still two
// different keys, so the live collision went unreported by the very check written for it.
//
// A prefix test catches it and leaves genuinely distinct neighbours alone — `disabled-state` and
// `enabled-state` are neither a prefix of the other, and they really are different types.
const types = [...new Set(rows.map((r) => r.type).filter(Boolean))].sort();
const countOf = (type) => rows.filter((r) => r.type === type).length;
const collisions = [];
for (const shorter of types) {
  for (const longer of types) {
    if (shorter !== longer && /^[-_ ]/.test(longer.slice(shorter.length)) && longer.startsWith(shorter)) {
      collisions.push([shorter, longer]);
    }
  }
}
if (collisions.length > 0) {
  console.error(`\nuat-index: ${collisions.length} type name(s) look like one type spelled two ways:`);
  for (const [shorter, longer] of collisions) {
    console.error(`  ${shorter} (${countOf(shorter)}) vs ${longer} (${countOf(longer)})`);
  }
  console.error(`  Pick one spelling per type in the matrices; the per-type coverage cut is split until then.`);
}

// A duplicate id means two cases cannot be told apart in a results file, so one of them can never be
// recorded. Fatal rather than a warning for the same reason an unknown id is fatal in the report.
if (duplicates > 0) {
  console.error(`uat-index: ${duplicates} duplicate id(s); results cannot address these unambiguously`);
  process.exit(1);
}
