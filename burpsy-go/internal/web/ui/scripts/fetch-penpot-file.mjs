#!/usr/bin/env node
// Fetches the burpsy Penpot file over Penpot's REST API and rewrites
// src/tokens/penpot-export.json from it. This is what removes the human from
// the export hop: before this, "Penpot is canonical" was a claim resting on
// somebody having pasted three set dumps in by hand, and gen-tokens.mjs's
// --check could only prove the CSS matched that paste, not that the paste
// matched Penpot.
//
// Usage:
//   node scripts/fetch-penpot-file.mjs              # fetch, refuse on divergence
//   node scripts/fetch-penpot-file.mjs --overwrite   # fetch, adopt Penpot's values
//   node scripts/fetch-penpot-file.mjs --save-raw <p> # also dump the decoded file
//
// Exit codes, and the distinction matters:
//   0  fetched, validated, and the export is up to date (written or unchanged)
//   1  something is WRONG — refuse, change nothing
//   3  SKIPPED because there are no credentials, or no way to reach Penpot past its Cloudflare
//      challenge (see loadBrowserRunner below). Not a pass. A caller that treats 3 as success has
//      broken the one rule this repo cares about most.
//
// Requires PENPOT_ACCESS_TOKEN in the environment. Generate one at
// <instance>/#/settings/access-tokens ("Access tokens" in profile settings) and
// export it; it is a password and must never be committed. The header form is
// `Authorization: Token <token>`, per help.penpot.app/technical-guide/integration/.
//
// The Accept header is NOT negotiable: `application/transit+json`. Penpot's
// get-file will happily answer `application/json`, but clojure.data.json has no
// write handler for the TokensLib record, so the tokens are silently dropped
// from the response (penpot/penpot#7540). Asking for JSON would give us a
// well-formed, plausible, token-free payload — the worst possible failure.
import { readFileSync, writeFileSync, renameSync, unlinkSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { decodeTransit } from "./lib/transit.mjs";
import { unwrapPenpot, collectTokenSets, tokenToExportShape, PointerEncountered } from "./lib/penpot-file.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const tokensDir = path.join(here, "..", "src", "tokens");
const exportPath = path.join(tokensDir, "penpot-export.json");

// Resolves a browser-mediated POST, or null if no Chromium runner is available.
//
// This script does not take its own dependency on playwright-core — it borrows the one the e2e suite
// already installs (burpsy-go/internal/web/ui/e2e/node_modules), rather than doubling an already-heavy
// dependency for a browser that is needed for exactly one thing: clearing a bot check before making an
// API call that has nothing to do with rendering a page. The browser is a fallback, reached only when
// a direct fetch() hits a Cloudflare challenge (see the transport comment below) — so its absence is a
// SKIP, not a hard failure, and instances without the challenge never need it at all.
async function loadBrowserRunner() {
  const entry = path.join(here, "..", "e2e", "node_modules", "playwright-core", "index.mjs");
  let chromium;
  try {
    ({ chromium } = await import(pathToFileURLString(entry)));
  } catch {
    return null;
  }
  return async function runInBrowser(origin, endpoint, token, fileId) {
    const browser = await chromium.launch({ headless: true });
    try {
      const page = await browser.newPage();
      // A real navigation, not a bare fetch from a blank page: the challenge is served (and its
      // clearance cookie set) in response to a page load, and an about:blank page's fetch() has
      // nothing to attach that cookie to.
      await page.goto(origin + "/", { waitUntil: "domcontentloaded", timeout: 60000 });
      // The interstitial resolves asynchronously after the page loads; there is no load event or
      // selector to wait on from outside its own script, so this is a fixed pause rather than a
      // polled condition. Measured to complete well inside this window against the real instance.
      await page.waitForTimeout(6000);
      return await page.evaluate(
        async ({ endpoint, token, fileId }) => {
          const res = await fetch(endpoint, {
            method: "POST",
            headers: {
              Authorization: `Token ${token}`,
              "Content-Type": "application/json",
              Accept: "application/transit+json",
            },
            body: JSON.stringify({ id: fileId }),
          });
          return { status: res.status, contentType: res.headers.get("content-type"), body: await res.text() };
        },
        { endpoint, token, fileId },
      );
    } finally {
      await browser.close();
    }
  };
}

// import() wants a file:// URL on some platforms even for an absolute path; building it by hand
// avoids adding a "url" import solely for pathToFileURL.
function pathToFileURLString(absPath) {
  return "file://" + absPath.split(path.sep).map(encodeURIComponent).join("/");
}

const argv = process.argv.slice(2);
const OVERWRITE = argv.includes("--overwrite");
const saveRawAt = argv.includes("--save-raw") ? argv[argv.indexOf("--save-raw") + 1] : null;

function die(message) {
  console.error(`fetch-penpot-file: ${message}`);
  process.exit(1);
}

function skip(reason) {
  console.error(`fetch-penpot-file: SKIPPED — ${reason}`);
  console.error(`This is a SKIP, not a pass: nothing was fetched and nothing was verified against Penpot.`);
  process.exit(3);
}

// The set names in Penpot, and the keys they land under in penpot-export.json.
// The mapping is explicit rather than derived (s/\//./) so that a set being
// renamed in Penpot fails loudly here instead of quietly adding a fourth key
// nobody reads.
const SET_KEY_BY_PENPOT_NAME = {
  primitives: "primitives",
  "semantic/dark": "semantic.dark",
  "semantic/light": "semantic.light",
};

// Same contract gen-tokens.mjs asserts. Checked here too, BEFORE anything is
// written, because the whole point of this script is that a partial answer must
// never reach the export file. A truncated fetch that passes this check and
// fails in the generator has already destroyed the good copy.
// 75 + 7: radius.none/sm/md, border.hairline/focus, font.weight.regular/bold, added directly in
// Penpot (none of the three token types existed before) and now present in the export. Must match
// gen-tokens.mjs's copy of this table, per both files' own instructions.
const EXPECTED_COUNTS = { primitives: 82, "semantic.dark": 44, "semantic.light": 44 };

const existing = JSON.parse(readFileSync(exportPath, "utf8"));
const provenance = existing._provenance ?? {};
const fileId = provenance.file?.id;
const fileUrl = provenance.file?.url;
if (!fileId) die(`src/tokens/penpot-export.json has no _provenance.file.id — nothing to fetch.`);

// Derive the instance origin from the recorded file URL rather than hardcoding
// it, so a self-hosted move is a one-line provenance edit. PENPOT_API_ORIGIN
// overrides it, for the two cases where the API does not live at the same origin
// as the workspace URL: a self-hosted instance behind a separate API host, and
// fetch-penpot-file.test.mjs, which points this script at a local fixture server
// so every path below can be exercised without credentials.
let origin = process.env.PENPOT_API_ORIGIN;
if (!origin) {
  try {
    origin = new URL(fileUrl).origin;
  } catch {
    die(`_provenance.file.url is not a URL (${fileUrl}) — cannot derive the Penpot instance origin.`);
  }
}

const token = process.env.PENPOT_ACCESS_TOKEN;
if (!token) {
  skip(
    `PENPOT_ACCESS_TOKEN is not set.\n` +
      `  Generate a personal access token in Penpot profile settings -> Access tokens, then:\n` +
      `    export PENPOT_ACCESS_TOKEN=<token>\n` +
      `  Only the account holder can do this; there is no way to fetch the file without it.`,
  );
}

const endpoint = `${origin}/api/rpc/command/get-file`;

// No `features` are declared on purpose. get-file inlines fdata/pointer-map and
// fdata/objects-map storage when the client does not claim to understand them
// (backend/src/app/rpc/commands/files.clj), which is exactly what we want: plain
// inlined data rather than references we would have to resolve with follow-up
// get-file-fragment calls. penpot-file.mjs throws if a pointer slips through
// anyway.
//
// Transport is a two-step escalation, and the order matters. A plain Node fetch() is tried FIRST,
// because it is what works everywhere the challenge is absent: a localhost fixture (the tests), a
// self-hosted Penpot, or any instance not fronted by Cloudflare. When it works, nothing heavier is
// touched and the whole pipeline runs headless — which is the entire reason this script exists rather
// than a human pasting exports.
//
// design.penpot.app, however, sits behind Cloudflare's JS challenge: a plain request gets HTTP 403
// with a "Just a moment..." HTML interstitial body, regardless of Authorization, Accept, User-Agent,
// Origin or Referer. That is emphatically NOT a credentials problem, and the earlier failure mode
// this script guarded against was reporting it as one — sending the next person chasing an access
// token that was never the issue. So the challenge is detected specifically (an HTML/`cf-mitigated`
// 403/429/503, not a JSON 401/403 from Penpot itself) and only then is the request retried inside a
// real browser context that can clear it. A genuine credentials rejection still falls straight
// through to the die() below, exactly as before.
//
// Everything after the transport — decode, validate, diff, write — is untouched by this shape.
async function directFetch() {
  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Token ${token}`,
      "Content-Type": "application/json",
      Accept: "application/transit+json",
    },
    body: JSON.stringify({ id: fileId }),
  });
  return {
    status: res.status,
    contentType: res.headers.get("content-type"),
    cfMitigated: res.headers.get("cf-mitigated"),
    body: await res.text(),
  };
}

// A Cloudflare interstitial, not Penpot's own answer: a challenge is served as an HTML body (or with
// a `cf-mitigated` header) under a 403/429/503, whereas Penpot's own 401/403 is a transit/JSON body.
// Matching on the interstitial rather than the bare status is what keeps a real credentials failure
// from being retried in a browser forever.
function looksLikeCloudflareChallenge(r) {
  if (r.status !== 403 && r.status !== 429 && r.status !== 503) return false;
  if (r.cfMitigated) return true;
  const ct = (r.contentType ?? "").toLowerCase();
  return ct.includes("text/html") && /just a moment|challenge-platform|cf-chl|enable javascript and cookies/i.test(r.body ?? "");
}

let response;
let directError;
try {
  response = await directFetch();
} catch (err) {
  directError = err;
}

if (!response || looksLikeCloudflareChallenge(response)) {
  const runInBrowser = await loadBrowserRunner();
  if (!runInBrowser) {
    const why = response
      ? `${origin} is behind a Cloudflare challenge and no Chromium runner is available to clear it`
      : `a direct request to ${origin} failed (${directError.message}) and no Chromium runner is available to retry through a browser`;
    skip(
      `${why}.\n` +
        `  Looked for playwright-core under burpsy-go/internal/web/ui/e2e/node_modules — that is where\n` +
        `  the e2e suite installs it. Run \`bun install\` there, or \`npx playwright install chromium\`\n` +
        `  if the package is present but the browser binary is not.`,
    );
  }
  try {
    response = await runInBrowser(origin, endpoint, token, fileId);
  } catch (err) {
    skip(`could not reach ${origin} through a browser context (${err.message}). No claim either way about whether the export is current.`);
  }
}

if (response.status === 401 || response.status === 403) {
  die(
    `Penpot rejected the credentials (HTTP ${response.status}) — this is Penpot's own answer, not a bot\n` +
      `  check (a Cloudflare challenge is detected separately and retried in a browser).\n` +
      `  Check that PENPOT_ACCESS_TOKEN is current — tokens can be set to expire — and that the\n` +
      `  account can read file ${fileId}.`,
  );
}
if (response.status !== 200) {
  die(`get-file returned HTTP ${response.status}. Refusing to touch the export.\n  body: ${response.body.slice(0, 300)}`);
}

const contentType = response.contentType ?? "";
if (!contentType.includes("transit+json")) {
  die(
    `expected a transit+json response, got "${contentType}".\n` +
      `  A JSON response would be missing the token catalogue entirely (penpot#7540), so a plausible\n` +
      `  payload in the wrong format is more dangerous than an error. Refusing to continue.`,
  );
}

const bodyText = response.body;
let file;
try {
  file = unwrapPenpot(decodeTransit(JSON.parse(bodyText)));
} catch (err) {
  if (err instanceof PointerEncountered) die(err.message);
  die(`could not decode the transit response: ${err.message}`);
}

if (saveRawAt) {
  writeFileSync(saveRawAt, JSON.stringify(file, null, 2));
  console.log(`wrote the decoded file to ${saveRawAt}`);
}

const data = file.data;
if (!data) die(`the response had no :data — get-file returned a file summary rather than file data.`);

const tokensLib = data["tokens-lib"];
if (!tokensLib) {
  die(
    `the file data has no tokens-lib. Either this file genuinely has no design tokens, or the\n` +
      `  response was serialised without them. Refusing to overwrite a good export with nothing.`,
  );
}

const sets = collectTokenSets(tokensLib.sets ?? {});
if (sets.length === 0) die(`tokens-lib contains no token sets.`);

const bySetName = new Map(sets.map((s) => [s.name, s]));
const fetched = {};
for (const [penpotName, key] of Object.entries(SET_KEY_BY_PENPOT_NAME)) {
  const set = bySetName.get(penpotName);
  if (!set) {
    die(
      `Penpot has no token set named "${penpotName}". Sets found: ${sets.map((s) => `"${s.name}"`).join(", ") || "(none)"}.\n` +
        `  If a set was deliberately renamed, update SET_KEY_BY_PENPOT_NAME in this script in the same\n` +
        `  commit, so the rename is a reviewable change rather than a silently missing key.`,
    );
  }
  fetched[key] = Object.values(set.tokens ?? {}).map(tokenToExportShape);
}

// Count assertion BEFORE any write.
for (const [key, expected] of Object.entries(EXPECTED_COUNTS)) {
  const got = fetched[key].length;
  if (got !== expected) {
    die(
      `Penpot's "${key}" set has ${got} tokens, expected ${expected}.\n` +
        `  If the design genuinely gained or lost tokens, update EXPECTED_COUNTS in BOTH this script and\n` +
        `  scripts/gen-tokens.mjs in the same commit. Until then this is treated as a partial or wrong\n` +
        `  response and the existing export is left untouched.`,
    );
  }
}

// --- divergence ------------------------------------------------------------
// A fetch that quietly reverts a deliberate local change is worse than no
// fetch: it would re-open the exact drift channel this pipeline exists to
// close, from the other direction. So differences are reported per token, with
// the direction stated, and adopting them takes --overwrite.
const diffs = [];
for (const key of Object.keys(EXPECTED_COUNTS)) {
  const local = new Map((existing[key] ?? []).map((t) => [t.name, t]));
  const remote = new Map(fetched[key].map((t) => [t.name, t]));
  for (const [name, r] of remote) {
    const l = local.get(name);
    if (!l) {
      diffs.push({ key, name, kind: "only in Penpot", local: "—", remote: fmt(r.value) });
    } else if (fmt(l.value) !== fmt(r.value)) {
      diffs.push({ key, name, kind: "value differs", local: fmt(l.value), remote: fmt(r.value) });
    } else if (l.type !== r.type) {
      diffs.push({ key, name, kind: "type differs", local: l.type, remote: r.type });
    }
  }
  for (const name of local.keys()) {
    if (!remote.has(name)) diffs.push({ key, name, kind: "only in the repo", local: fmt(local.get(name).value), remote: "—" });
  }
}

function fmt(value) {
  return typeof value === "object" && value !== null ? JSON.stringify(value) : String(value);
}

if (diffs.length && !OVERWRITE) {
  console.error(`fetch-penpot-file: ${diffs.length} token(s) differ between Penpot and src/tokens/penpot-export.json.\n`);
  const width = Math.max(...diffs.map((d) => d.name.length), 4);
  for (const d of diffs) {
    console.error(`  ${d.key.padEnd(15)} ${d.name.padEnd(width)}  repo: ${d.local}   penpot: ${d.remote}   (${d.kind})`);
  }
  console.error(`\nNothing was written. Decide which side is right, and say so explicitly:`);
  console.error(`  * Penpot is right (the normal case) — re-run with --overwrite to adopt its values.`);
  console.error(`  * The repo is right — then the change belongs in Penpot. Make it there and re-fetch;`);
  console.error(`    do not hand-edit the export, because the next fetch would revert it.`);
  console.error(`\nIf these differences are values that were deliberately staged locally, they should be in`);
  console.error(`PENDING-TOKEN-CHANGES.md and applied to the Penpot file — not left diverging here.`);
  process.exit(1);
}

// --- write -----------------------------------------------------------------
const out = structuredClone(existing);
for (const key of Object.keys(EXPECTED_COUNTS)) out[key] = fetched[key];

out._provenance = {
  ...provenance,
  file: { ...(provenance.file ?? {}), name: file.name ?? provenance.file?.name },
  exportedAt: new Date().toISOString().slice(0, 10),
  // The honesty upgrade this script buys. A hand-pasted export could only ever
  // claim recency; a machine fetch was actually read from the live file, and the
  // hashes below now attest to something real.
  exportMethod: "REST get-file over transit+json, by scripts/fetch-penpot-file.mjs",
  verifiedAgainstLiveFile: true,
  setHashes: Object.fromEntries(Object.keys(EXPECTED_COUNTS).map((k) => [k, createHash("sha256").update(JSON.stringify(fetched[k])).digest("hex").slice(0, 16)])),
  hashesProve:
    "These hashes were taken from a machine fetch of the live Penpot file, so for this export they " +
    "attest to correctness and not merely recency. That holds only until someone hand-edits an array " +
    "here — gen-tokens.mjs will then fail on the hash, which is the point. Re-fetch rather than patch.",
};
// Superseded by exportMethod/verifiedAgainstLiveFile: the note about names
// having been typed in from a partial read of the token panel only applied to
// the hand-pasted era.
if (out._provenance.unverifiedInThisSnapshot) delete out._provenance.unverifiedInThisSnapshot.names;

// Write via a temp file and rename so an interrupted run cannot leave a
// half-written export where a valid one used to be.
const tmp = `${exportPath}.tmp`;
try {
  writeFileSync(tmp, JSON.stringify(out, null, 2) + "\n");
  renameSync(tmp, exportPath);
} catch (err) {
  try {
    unlinkSync(tmp);
  } catch {}
  die(`could not write the export: ${err.message}`);
}

const counts = Object.keys(EXPECTED_COUNTS).map((k) => `${k}=${fetched[k].length}`).join(" ");
console.log(`fetched file ${fileId} from ${origin}`);
console.log(`wrote src/tokens/penpot-export.json (${counts})`);
if (diffs.length) console.log(`adopted ${diffs.length} change(s) from Penpot (--overwrite).`);
console.log(`Now run \`bun run gen:tokens\` to regenerate the CSS, then \`bun run check\`.`);

// Exit explicitly. fetch() leaves its connection in undici's keep-alive pool,
// and that live handle can keep the event loop from draining — the script would
// finish its work and then sit there, which in CI is indistinguishable from a
// hang. Every other path already exits through die()/skip().
process.exit(0);
