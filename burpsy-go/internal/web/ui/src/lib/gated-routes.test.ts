/**
 * The console's gated-route table against the Go source, and the client rule built on it
 * (burpsy-react-ui-p1uz). Run with `bun run test:lib`.
 */
import { afterEach, describe, expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { api, CONFIRM_HEADER, confirmUrlFor, gatedPatternFor, manifestPatternFor } from "./api";
import { ROUTE_GATED } from "./gated-routes";
import { ROUTE_RISK } from "./route-risk";
import {
 gatedTable,
 parseGatedRiskClasses,
 parseManifestRisks,
 renderGatedRoutesModule,
 renderRouteRiskModule,
 riskTable,
} from "./route-manifest";

const web = join(import.meta.dir, "..", "..", "..");
const manifestGo = readFileSync(join(web, "route_manifest.go"), "utf8");
const agentToolsGo = readFileSync(join(web, "agent_tools.go"), "utf8");

describe("the generated table matches the Go manifest", () => {
 test("the parse found the manifest, not a fragment of it", () => {
  // A floor, so a parse that silently found three entries cannot pass the comparison below.
  expect(parseManifestRisks(manifestGo).length).toBeGreaterThan(100);
  expect(parseGatedRiskClasses(agentToolsGo)).toEqual(["riskAttack", "riskCredential", "riskDestructive", "riskScope"]);
 });

 test("gated-routes.ts is current — run `bun run gen:gated-routes` if this fails", () => {
  expect(renderGatedRoutesModule(ROUTE_GATED)).toBe(renderGatedRoutesModule(gatedTable(manifestGo, agentToolsGo)));
 });

 test("route-risk.ts is current — the REST-API page's inventory matches the server's classes (wt0r)", () => {
  expect(renderRouteRiskModule(ROUTE_RISK)).toBe(renderRouteRiskModule(riskTable(manifestGo)));
 });

 test("known routes are classified as the server classifies them", () => {
  expect(ROUTE_GATED["/api/project/open"]).toBe(true);
  expect(ROUTE_GATED["/api/proxy/ca/regenerate"]).toBe(true);
  expect(ROUTE_GATED["/api/projects"]).toBe(false);
  expect(ROUTE_GATED["/api/browser/launch"]).toBe(false);
 });
});

describe("gatedPatternFor follows the gate's longest-match rule", () => {
 test("an exact gated route", () => {
  expect(gatedPatternFor("/api/backup")).toBe("/api/backup");
 });
 test("an id under a gated subtree resolves to the subtree, whose pair shares one mint", () => {
  expect(gatedPatternFor("/api/session/rules/7")).toBe("/api/session/rules/");
  expect(confirmUrlFor("/api/session/rules/")).toBe("/api/session/rules/confirm");
  expect(confirmUrlFor("/api/session/rules")).toBe("/api/session/rules/confirm");
 });
 test("an ungated longer pattern under a gated one wins", () => {
  const table = { "/api/x": true, "/api/x/read": false };
  expect(manifestPatternFor("/api/x/read", table)).toBe("/api/x/read");
  expect(gatedPatternFor("/api/x/read", table)).toBeUndefined();
  expect(gatedPatternFor("/api/x/other", table)).toBe("/api/x");
 });
 test("prefixes are segment-bounded and queries are ignored", () => {
  const table = { "/api/audit": true };
  expect(gatedPatternFor("/api/auditlog", table)).toBeUndefined();
  expect(gatedPatternFor("/api/audit?x=1", table)).toBe("/api/audit");
 });
 test("a mint request is never itself gated", () => {
  expect(gatedPatternFor("/api/session/prompts/confirm")).toBeUndefined();
  expect(gatedPatternFor("/api/backup/confirm")).toBeUndefined();
 });
});

describe("api() mints for gated mutations only", () => {
 const originalFetch = globalThis.fetch;
 afterEach(() => {
  globalThis.fetch = originalFetch;
 });

 function record(): { calls: { url: string; method: string; token: string | null }[] } {
  const log = { calls: [] as { url: string; method: string; token: string | null }[] };
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
   const url = String(input);
   log.calls.push({ url, method: init?.method ?? "GET", token: new Headers(init?.headers).get(CONFIRM_HEADER) });
   if (url.endsWith("/confirm"))
    return new Response(
     JSON.stringify({ token: "tok", binding: "b", call: { method: "POST", url: "/", body_bytes: 0, body_sha256: "", body_kind: "none" } }),
     { status: 200 },
    );
   return new Response("{}", { status: 200 });
  }) as typeof fetch;
  return log;
 }

 test("a DELETE under a gated subtree mints at the pattern's /confirm", async () => {
  const log = record();
  await api("/api/session/rules/3", { method: "DELETE" });
  expect(log.calls).toEqual([
   { url: "/api/session/rules/confirm", method: "POST", token: null },
   { url: "/api/session/rules/3", method: "DELETE", token: "tok" },
  ]);
 });
 test("a read of a gated route sends no mint", async () => {
  const log = record();
  await api("/api/scope");
  expect(log.calls.map((c) => c.url)).toEqual(["/api/scope"]);
 });
 test("a mutation of an ungated route sends no mint", async () => {
  const log = record();
  await api("/api/browser/launch", { method: "POST", body: "{}" });
  expect(log.calls.map((c) => c.url)).toEqual(["/api/browser/launch"]);
 });
 test("a caller that already holds a token is left alone", async () => {
  const log = record();
  await api("/api/backup", { method: "POST", headers: { [CONFIRM_HEADER]: "mine" } });
  expect(log.calls).toEqual([{ url: "/api/backup", method: "POST", token: "mine" }]);
 });
});

describe("no mutating call bypasses the gated client", () => {
 // Every raw fetch() in the console, outside api.ts. Each is allowed only with the reason it cannot
 // reach a gated route; a new raw POST/PUT/DELETE has to be routed through api() or gatedFetch().
 const ALLOWED_RAW_FETCH: Record<string, string> = {
  "src/app.tsx:/api/config/export": "GET download of the configuration",
  "src/lib/data.policy.ts:/ca.crt": "HEAD probe of the CA certificate",
  "src/pages/intruder.tsx:/api/intruder/payload-files": "riskLocal upload (ungated)",
  "src/ui/clickbandit-dialog.tsx:/api/engagement/clickbandit.js": "GET of the Clickbandit script as text, not JSON",
 };
 function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
   const path = join(dir, name);
   if (statSync(path).isDirectory()) return sources(path);
   return /\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name) ? [path] : [];
  });
 }
 test("every raw fetch is a known read or an ungated route", () => {
  const root = join(import.meta.dir, "..", "..");
  const found: string[] = [];
  for (const file of sources(join(root, "src"))) {
   const rel = file.slice(root.length + 1);
   if (rel === "src/lib/api.ts") continue;
   const text = readFileSync(file, "utf8");
   for (const match of text.matchAll(/(?<![\w.])fetch\(\s*["'`]([^"'`$?]+)/g)) found.push(`${rel}:${match[1]}`);
   // A raw fetch whose URL is not a literal cannot be checked at all.
   for (const match of text.matchAll(/(?<![\w.])fetch\(\s*(?!["'`])([A-Za-z_][\w.]*)/g)) found.push(`${rel}:<${match[1]}>`);
  }
  const unexpected = found.filter((entry) => !(entry in ALLOWED_RAW_FETCH));
  expect(unexpected).toEqual([]);
  // The positive control: the scan finds every allowlisted call, so an empty `unexpected` means the
  // scan worked rather than that it matched nothing (and a stale allowlist entry fails here).
  expect([...new Set(found)].sort()).toEqual(Object.keys(ALLOWED_RAW_FETCH).sort());
 });
});

describe("manifestPatternFor reads the mux's wildcard spellings, as routeRiskFor does (PR 363 review)", () => {
 // Without this the Sequencer's stop/pause/resume resolved to the gated exact route
 // "/api/sequencer/capture", minted at /api/sequencer/capture/confirm, and the server (which
 // resolves the same URL to the "{rest...}" key) answered 400, so the capture kept running.
 test("a path under a {rest...} key resolves to that key, which is not gated", () => {
  for (const action of ["stop", "pause", "resume"]) {
   const path = `/api/sequencer/capture/${action}`;
   expect(manifestPatternFor(path)).toBe("/api/sequencer/capture/{rest...}");
   expect(gatedPatternFor(path)).toBeUndefined();
  }
 });
 test("the exact route under it is still the gated one", () => {
  expect(manifestPatternFor("/api/sequencer/capture")).toBe("/api/sequencer/capture");
  expect(gatedPatternFor("/api/sequencer/capture")).toBe("/api/sequencer/capture");
 });
 test("{x...} is the remainder: empty and nested paths belong to it", () => {
  const table = { "/api/x": true, "/api/x/{rest...}": false };
  expect(manifestPatternFor("/api/x/", table)).toBe("/api/x/{rest...}");
  expect(manifestPatternFor("/api/x/a/b/c", table)).toBe("/api/x/{rest...}");
  expect(manifestPatternFor("/api/xy", table)).toBeUndefined();
 });
 test("{id} matches one non-empty segment, and the literal-richer key wins", () => {
  const table = { "/api/tasks/{id}": false, "/api/tasks/{id}/cancel": false, "/api/tasks": true };
  expect(manifestPatternFor("/api/tasks/7", table)).toBe("/api/tasks/{id}");
  expect(manifestPatternFor("/api/tasks/7/cancel", table)).toBe("/api/tasks/{id}/cancel");
  expect(manifestPatternFor("/api/tasks/7/other", table)).toBe("/api/tasks");
  expect(manifestPatternFor("/api/tasks//cancel", table)).toBe("/api/tasks");
 });
 test("{$} anchors the one path with the trailing slash", () => {
  const table = { "/api/a/attacks/{$}": false, "/api/a/attacks/{id}": false };
  expect(manifestPatternFor("/api/a/attacks/", table)).toBe("/api/a/attacks/{$}");
  expect(manifestPatternFor("/api/a/attacks/9", table)).toBe("/api/a/attacks/{id}");
 });
 test("a literal beats a wildcard even when the wildcard spelling is longer", () => {
  const table = { "/api/skills/disabled": false, "/api/skills/{rest...}": true };
  expect(manifestPatternFor("/api/skills/disabled", table)).toBe("/api/skills/disabled");
  expect(manifestPatternFor("/api/skills/other", table)).toBe("/api/skills/{rest...}");
 });
 test("every wildcard key in the generated table resolves its own sample path to a key at least as specific", () => {
  const literal = (p: string) => p.replace(/\{[^}]*\}/g, "").length;
  for (const key of Object.keys(ROUTE_GATED).filter((k) => k.includes("{"))) {
   const sample = key
    .replace("{$}", "")
    .replace(/\{[^}]*\.\.\.\}/, "a/b")
    .replace(/\{[^}]*\}/g, "x1");
   const got = manifestPatternFor(sample);
   expect(got).toBeDefined();
   expect(literal(got as string)).toBeGreaterThanOrEqual(literal(key));
  }
 });
});
