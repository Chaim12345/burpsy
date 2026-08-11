#!/usr/bin/env node
// End-to-end tests for fetch-penpot-file.mjs against a local fixture server.
//
// There is no Penpot access token in this environment, so the script has never
// run against the real API. That makes these tests the only evidence that it
// does the right thing — and in particular that its refusal paths refuse. A
// fetch script whose happy path is untested is a nuisance; one whose failure
// paths are untested will one day overwrite a good export with nothing.
//
// The fixture server speaks real transit: encodeTransit below emits the same
// tags Penpot does (penpot/tokens-lib, penpot/token-set, penpot/token,
// ordered-map), verified against the reference writer's output in
// lib/transit.test.mjs. It deliberately emits no cache codes — the cache is
// optional for a writer and required only of a reader, and lib/transit.test.mjs
// already covers it against reference output.
//
// Each case runs the real script as a subprocess against a throwaway copy of
// src/tokens, so nothing here can touch the working tree.
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, cpSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const realExport = JSON.parse(readFileSync(path.join(here, "..", "src", "tokens", "penpot-export.json"), "utf8"));

let failures = 0;
function check(name, actual, expected) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) {
    failures++;
    console.error(`FAIL ${name}\n  expected ${e}\n  actual   ${a}`);
  } else {
    console.log(`ok   ${name}`);
  }
}
function checkMatch(name, text, re) {
  if (re.test(text)) console.log(`ok   ${name}`);
  else {
    failures++;
    console.error(`FAIL ${name}\n  expected output matching ${re}\n  got: ${text.slice(0, 600)}`);
  }
}

// --- a minimal transit writer, for fixtures only ---------------------------
const kw = (s) => `~:${s}`;
const uuid = (s) => `~u${s}`;
function tmap(pairs) {
  const out = ["^ "];
  for (const [k, v] of pairs) out.push(k, v);
  return out;
}
const orderedMap = (pairs) => ["~#ordered-map", pairs.map(([k, v]) => [k, v])];
const tagged = (tag, rep) => [`~#${tag}`, rep];

// Penpot serialises a token type as its INTERNAL keyword, not the DTCG name the
// export file uses: "dimension" is stored as :dimensions, "borderWidth" as
// :stroke-width, "fontFamilies" as :font-family. The fixture emits the internal
// form so the tests exercise the real translation in tokenToExportShape — an
// earlier version of this fixture echoed the DTCG names back and would have
// passed no matter how wrong that translation was.
const KEYWORD_BY_DTCG_TYPE = {
  dimension: "dimensions",
  fontFamilies: "font-family",
  fontSizes: "font-size",
  fontWeights: "font-weight",
  borderWidth: "stroke-width",
  borderRadius: "border-radius",
  letterSpacing: "letter-spacing",
  textCase: "text-case",
  textDecoration: "text-decoration",
};
function tokenRep(t) {
  const isPlainObject = typeof t.value === "object" && t.value !== null && !Array.isArray(t.value);
  return tagged("penpot/token", tmap([
    [kw("id"), uuid("00000000-0000-0000-0000-00000000000a")],
    [kw("name"), t.name],
    [kw("type"), kw(KEYWORD_BY_DTCG_TYPE[t.type] ?? t.type)],
    [kw("value"), isPlainObject ? tmap(Object.entries(t.value).map(([k, v]) => [kw(k), v])) : t.value],
  ]));
}
function setRep(name, tokens) {
  return tagged("penpot/token-set", tmap([
    [kw("id"), uuid("00000000-0000-0000-0000-00000000000b")],
    [kw("name"), name],
    [kw("tokens"), orderedMap(tokens.map((t) => [t.name, tokenRep(t)]))],
  ]));
}
// Sets live in a prefixed tree: "S-" a set, "G-" a group. "semantic/dark" is a
// grouped name and must arrive nested, which is what collectTokenSets walks.
function tokensLibRep(bySetName) {
  const semantic = [];
  const top = [];
  for (const [name, tokens] of Object.entries(bySetName)) {
    if (name.includes("/")) semantic.push([`S-${name.split("/")[1]}`, setRep(name, tokens)]);
    else top.push([`S-${name}`, setRep(name, tokens)]);
  }
  const tree = [...top];
  if (semantic.length) tree.push(["G-semantic", orderedMap(semantic)]);
  return tagged("penpot/tokens-lib", tmap([[kw("sets"), orderedMap(tree)], [kw("themes"), orderedMap([])], [kw("active-themes"), ["~#ordered-set", []]]]));
}
function filePayload({ sets, includePointer = false, omitTokensLib = false, shapes = [] } = {}) {
  const objects = orderedMap(shapes.map((s, i) => [uuid(`00000000-0000-0000-0000-${String(i).padStart(12, "0")}`), tmap(Object.entries(s).map(([k, v]) => [kw(k), v]))]));
  const dataPairs = [
    [kw("pages"), [uuid("00000000-0000-0000-0000-0000000000f1")]],
    [kw("pages-index"), orderedMap([[uuid("00000000-0000-0000-0000-0000000000f1"), tmap([[kw("name"), "Tools"], [kw("objects"), objects]])]])],
  ];
  if (includePointer) dataPairs.push([kw("tokens-lib"), tagged("penpot/pointer", [uuid("00000000-0000-0000-0000-0000000000cc"), null])]);
  else if (!omitTokensLib) dataPairs.push([kw("tokens-lib"), tokensLibRep(sets)]);
  return tmap([[kw("id"), uuid("81f57451-85cc-819d-8008-712303b37e30")], [kw("name"), "burpsy design system"], [kw("data"), tmap(dataPairs)]]);
}

// The real 82/44/44 catalogue, straight out of the checked-in export.
const realSets = () => ({
  primitives: realExport.primitives,
  "semantic/dark": realExport["semantic.dark"],
  "semantic/light": realExport["semantic.light"],
});

// --- harness ---------------------------------------------------------------
function serve(handler) {
  const server = createServer(handler);
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, origin: `http://127.0.0.1:${server.address().port}` })));
}

function sandbox() {
  const dir = mkdtempSync(path.join(tmpdir(), "penpot-fetch-"));
  mkdirSync(path.join(dir, "scripts"), { recursive: true });
  mkdirSync(path.join(dir, "src", "tokens"), { recursive: true });
  cpSync(path.join(here, "lib"), path.join(dir, "scripts", "lib"), { recursive: true });
  cpSync(path.join(here, "fetch-penpot-file.mjs"), path.join(dir, "scripts", "fetch-penpot-file.mjs"));
  // gen-tokens too, so the "the generator accepts what the fetch wrote" assertion
  // runs entirely inside the sandbox instead of rewriting the real src/tokens.
  cpSync(path.join(here, "gen-tokens.mjs"), path.join(dir, "scripts", "gen-tokens.mjs"));
  cpSync(path.join(here, "..", "src", "tokens", "penpot-export.json"), path.join(dir, "src", "tokens", "penpot-export.json"));
  return dir;
}

// Async on purpose, and this is not a style preference. The fixture server runs
// in THIS process, so spawnSync would freeze the event loop that has to answer
// the child's request — the child blocks on fetch(), the parent blocks on the
// child, and neither ever moves. The first version of this file deadlocked
// exactly that way.
//
// The timeout stays because it caught a second, independent bug: the script
// finished its work and then never exited, because fetch() had left a keep-alive
// socket in undici's pool and the event loop would not drain. In CI that is
// indistinguishable from a hang, so a non-exit is now a loud failure.
function run(dir, { origin, token = "test-token", args = [] } = {}) {
  const env = { ...process.env, PENPOT_ACCESS_TOKEN: token, PENPOT_API_ORIGIN: origin };
  if (token === null) delete env.PENPOT_ACCESS_TOKEN;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(dir, "scripts", "fetch-penpot-file.mjs"), ...args], { env });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    const timer = setTimeout(() => child.kill("SIGKILL"), 20000);
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (signal) reject(new Error(`fetch-penpot-file did not exit (killed by ${signal}) — args: ${args.join(" ") || "(none)"}`));
      else resolve({ code, out, err });
    });
  });
}

function runNode(scriptPath, cwd) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [scriptPath], { cwd });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    const timer = setTimeout(() => child.kill("SIGKILL"), 20000);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, out, err });
    });
  });
}

const transitJson = (payload) => ({ status: 200, type: "application/transit+json", body: JSON.stringify(payload) });
function responder(spec) {
  return (req, res) => {
    const s = typeof spec === "function" ? spec(req) : spec;
    res.writeHead(s.status, { "content-type": s.type });
    res.end(s.body);
  };
}

// --- 1. no credentials -> exit 3, and it must not read as a pass -----------
{
  const dir = sandbox();
  const before = readFileSync(path.join(dir, "src/tokens/penpot-export.json"), "utf8");
  const r = await run(dir, { origin: "http://127.0.0.1:1", token: null });
  check("no token: exit code is 3 (skipped), not 0", r.code, 3);
  checkMatch("no token: says SKIPPED", r.err, /SKIPPED/);
  checkMatch("no token: says it is not a pass", r.err, /not a pass/);
  checkMatch("no token: names the env var and where to get one", r.err, /PENPOT_ACCESS_TOKEN[\s\S]*Access tokens/);
  check("no token: export untouched", readFileSync(path.join(dir, "src/tokens/penpot-export.json"), "utf8"), before);
}

// --- 2. happy path: identical catalogue, no divergence ---------------------
{
  const dir = sandbox();
  const { server, origin } = await serve(responder(transitJson(filePayload({ sets: realSets() }))));
  const r = await run(dir, { origin });
  server.close();
  check("identical catalogue: exit 0", r.code, 0);
  checkMatch("identical catalogue: reports the counts", r.out, /primitives=82 semantic\.dark=44 semantic\.light=44/);
  const written = JSON.parse(readFileSync(path.join(dir, "src/tokens/penpot-export.json"), "utf8"));
  check("identical catalogue: primitives preserved exactly", written.primitives, realExport.primitives);
  check("identical catalogue: semantic.dark preserved exactly", written["semantic.dark"], realExport["semantic.dark"]);
  check("identical catalogue: provenance records the method", written._provenance.exportMethod.startsWith("REST get-file"), true);
  check("identical catalogue: provenance claims live verification", written._provenance.verifiedAgainstLiveFile, true);
  check("identical catalogue: file name from Penpot wins", written._provenance.file.name, "burpsy design system");
  check("identical catalogue: the stale 'names were typed in' caveat is dropped", written._provenance.unverifiedInThisSnapshot?.names, undefined);
  checkMatch("identical catalogue: hash note now claims correctness", written._provenance.hashesProve, /attest to correctness/);
  // The generator must accept what the fetch wrote, hashes included.
  const gen = await runNode(path.join(dir, "scripts", "gen-tokens.mjs"), dir);
  check("identical catalogue: the generator accepts what the fetch wrote", gen.code, 0);
  if (gen.code !== 0) console.error(gen.err);
  check("identical catalogue: hashes it wrote are self-consistent", /no longer matches its recorded hash/.test(gen.err), false);
}

// --- 3. divergence is reported per token and refuses to write --------------
{
  const dir = sandbox();
  const sets = realSets();
  sets.primitives = sets.primitives.map((t) => (t.name === "height.toolbar" ? { ...t, value: "38px" } : t));
  sets["semantic/dark"] = sets["semantic/dark"].map((t) => (t.name === "color.chrome" ? { ...t, value: "{grey.550}" } : t));
  const { server, origin } = await serve(responder(transitJson(filePayload({ sets }))));
  const before = readFileSync(path.join(dir, "src/tokens/penpot-export.json"), "utf8");
  const r = await run(dir, { origin });
  check("divergence: exit 1", r.code, 1);
  checkMatch("divergence: names the token and both directions", r.err, /height\.toolbar\s+repo: 29px\s+penpot: 38px/);
  checkMatch("divergence: catches the semantic set too", r.err, /color\.chrome\s+repo: \{grey\.700\}\s+penpot: \{grey\.550\}/);
  checkMatch("divergence: says nothing was written", r.err, /Nothing was written/);
  checkMatch("divergence: points at PENDING-TOKEN-CHANGES.md", r.err, /PENDING-TOKEN-CHANGES\.md/);
  check("divergence: export untouched", readFileSync(path.join(dir, "src/tokens/penpot-export.json"), "utf8"), before);

  const r2 = await run(dir, { origin, args: ["--overwrite"] }); // server is still open for this second run
  server.close();
  check("divergence + --overwrite: exit 0", r2.code, 0);
  const written = JSON.parse(readFileSync(path.join(dir, "src/tokens/penpot-export.json"), "utf8"));
  check("divergence + --overwrite: adopted Penpot's value", written.primitives.find((t) => t.name === "height.toolbar").value, "38px");
  checkMatch("divergence + --overwrite: says how many it adopted", r2.out, /adopted 2 change\(s\)/);
}

// --- 4. every refusal path leaves the export alone ------------------------
const refusals = [
  ["HTTP 500", responder({ status: 500, type: "application/transit+json", body: "boom" }), /HTTP 500/],
  ["401 unauthorised", responder({ status: 401, type: "application/transit+json", body: "" }), /rejected the credentials/],
  ["JSON instead of transit", responder({ status: 200, type: "application/json", body: "{}" }), /expected a transit\+json response[\s\S]*7540/],
  ["undecodable body", responder({ status: 200, type: "application/transit+json", body: "not json" }), /could not decode/],
  ["no tokens-lib", responder(transitJson(filePayload({ sets: realSets(), omitTokensLib: true }))), /no tokens-lib[\s\S]*Refusing to overwrite/],
  ["pointer instead of inlined data", responder(transitJson(filePayload({ sets: realSets(), includePointer: true }))), /penpot\/pointer[\s\S]*silently incomplete/],
];
for (const [name, handler, expected] of refusals) {
  const dir = sandbox();
  const before = readFileSync(path.join(dir, "src/tokens/penpot-export.json"), "utf8");
  const { server, origin } = await serve(handler);
  const r = await run(dir, { origin });
  server.close();
  check(`${name}: exit 1`, r.code, 1);
  checkMatch(`${name}: explains itself`, r.err, expected);
  check(`${name}: export untouched`, readFileSync(path.join(dir, "src/tokens/penpot-export.json"), "utf8"), before);
}

// --- 5. a truncated catalogue must never be written ----------------------
{
  const dir = sandbox();
  const sets = realSets();
  sets.primitives = sets.primitives.slice(0, 40); // a paste that lost its tail
  const before = readFileSync(path.join(dir, "src/tokens/penpot-export.json"), "utf8");
  const { server, origin } = await serve(responder(transitJson(filePayload({ sets }))));
  const r = await run(dir, { origin, args: ["--overwrite"] });
  server.close();
  check("truncated set: exit 1 even with --overwrite", r.code, 1);
  checkMatch("truncated set: reports both counts", r.err, /has 40 tokens, expected 82/);
  check("truncated set: export untouched", readFileSync(path.join(dir, "src/tokens/penpot-export.json"), "utf8"), before);
}

// --- 6. a renamed set fails loudly rather than dropping a key ------------
{
  const dir = sandbox();
  const sets = realSets();
  sets["semantic/darkmode"] = sets["semantic/dark"];
  delete sets["semantic/dark"];
  const { server, origin } = await serve(responder(transitJson(filePayload({ sets }))));
  const r = await run(dir, { origin, args: ["--overwrite"] });
  server.close();
  check("renamed set: exit 1", r.code, 1);
  checkMatch("renamed set: lists what it did find", r.err, /no token set named "semantic\/dark"[\s\S]*semantic\/darkmode/);
}

console.log(failures ? `\n${failures} fetch test(s) failed.` : "\nAll fetch tests passed.");
process.exit(failures ? 1 : 0);
