// Boots a real burpsy-go for the browser suite to drive, and seeds it with real traffic.
//
// The shape is deliberately the same as e2e-go.sh's: build the Go binary to a temp path, start a
// throwaway origin, start burpsy pointed at nothing in particular, then wait on ALL THREE listeners
// before asserting anything. e2e.sh records why the third wait exists — waiting only on burpsy raced
// the origin's startup and produced a spurious "upstream connect failed" — and that reason applies
// verbatim here, except a browser turns the race into a flaky screenshot instead of a clear error.
//
// Two things this file is careful about, both of which have already cost this repo something:
//
//  1. The binary goes to a temp directory, never into the tree. `go build -o burpsy-go/burpsy` leaves
//     an untracked binary behind and two PRs have been rejected for committing exactly that.
//  2. Ports are 182xx, chosen to sit clear of every shell suite: e2e.sh uses 180xx, e2e-go.sh 181xx,
//     e2e-scan.sh 183xx. verify.sh serialises the suites, but a human running two in two terminals
//     should not get a confusing bind failure out of it.
//
// The seeding matters as much as the booting. Half the routes render a table, and a table with zero
// rows exercises the empty state rather than the table — so a suite against a freshly started server
// would report every data view as fine while proving nothing about any of them. Sorting, selection
// and the row-detail panes all need rows that actually differ from each other.

import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createConnection, createServer } from "node:net";
import {
 existsSync,
 mkdirSync,
 mkdtempSync,
 openSync,
 readFileSync,
 rmSync,
 writeFileSync,
} from "node:fs";
import { request as httpRequest } from "node:http";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

/** Everything globalTeardown needs to undo what globalSetup did. */
export interface Harness {
 dir: string;
 webPort: number;
 proxyPort: number;
 targetPort: number;
 burpsyPid: number;
 targetPid: number;
}

const PREFERRED = { proxy: 18280, web: 18281, target: 18299 };

/**
 * e2e/artifacts/ — the gitignored directory the report, traces and screenshots already go to.
 *
 * The state file and burpsy's log live here rather than under /tmp, and that is not a preference. A
 * run whose /tmp working directory was swept mid-suite produced 40 tests failing with a flat
 * ERR_CONNECTION_REFUSED and no log to explain any of them; on a shared machine /tmp has other
 * tenants and a sweeper, and this directory does not. The BINARY still goes to /tmp, matching
 * e2e-go.sh — that is what keeps an untracked executable out of the tree, and losing it mid-run is
 * harmless because the running process holds its inode.
 */
export function artifactsDir(): string {
 const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "artifacts");
 mkdirSync(dir, { recursive: true });
 return dir;
}

/**
 * Where the state file lives, so setup and teardown agree without sharing memory.
 *
 * One fixed path per checkout, which means TWO concurrent runs of this suite would clobber each
 * other's record and teardown would kill the wrong pair of processes. That is deliberate rather than
 * overlooked: verify.sh runs the e2e suites sequentially and this config uses a single worker, so
 * there is no supported way to have two. If that ever changes, key this on the runner's pid.
 */
export function statePath(): string {
 return join(artifactsDir(), "run-state.json");
}

export function readHarness(): Harness {
 return JSON.parse(readFileSync(statePath(), "utf8")) as Harness;
}

/**
 * The burpsy-go module root, found by walking up to the go.mod rather than counting `..`s.
 *
 * BURPSY_E2E_GO_ROOT overrides it. That exists for one narrow job: developing this suite against a
 * known-good checkout while the working tree is mid-edit by someone else. It must never be set in
 * verify.sh or in CI — the whole value of the suite is that it builds and tests the tree in front of
 * it, and pointing it elsewhere makes a green run a statement about a different tree.
 */
function goModuleRoot(): string {
 const override = process.env.BURPSY_E2E_GO_ROOT;
 if (override) {
  if (!existsSync(join(override, "go.mod"))) throw new Error(`BURPSY_E2E_GO_ROOT has no go.mod: ${override}`);
  return override;
 }
 let here = dirname(fileURLToPath(import.meta.url));
 for (let i = 0; i < 10; i += 1) {
  if (existsSync(join(here, "go.mod"))) return here;
  here = dirname(here);
 }
 throw new Error("could not find burpsy-go/go.mod above the e2e directory");
}

/**
 * Ports this process has already handed out.
 *
 * freePort proves a port is free by binding a probe socket and then *closing* it, so between the
 * probe and burpsy actually binding, the port is free again — and a second freePort call will happily
 * return the same number. That is not a rare race, it is the deterministic case: all three ports are
 * allocated up front and bound afterwards.
 *
 * It really happened. With 18280 and 18281 both held by something else, the walk-forward gave
 * `proxy=18282 web=18282`, burpsy bound the proxy and then died with
 * `listen tcp 127.0.0.1:18282: bind: address already in use`, and the whole suite reported as one
 * failure with no tests run. Claiming each port as it is issued is what stops the allocator handing
 * out a number it has already promised.
 */
const claimed = new Set<number>();

/**
 * A port that is free right now and has not already been issued by this process. The preferred number
 * is tried first so logs and tcpdumps stay recognisable across runs; if something else holds it we
 * walk forward rather than fail, because a suite that cannot start is indistinguishable from a suite
 * that found a bug.
 *
 * The walk is bounded to 15 rather than 40 because the preferred numbers are only 19 apart
 * (18280/18281/18299) and a 40-wide window let the proxy's search wander onto the target's preferred
 * port — a second way for two services to be told to share one number.
 */
async function freePort(preferred: number): Promise<number> {
 const span = 15;
 for (let port = preferred; port < preferred + span; port += 1) {
  if (claimed.has(port)) continue;
  const free = await new Promise<boolean>((done) => {
   const probe = createServer();
   probe.once("error", () => done(false));
   probe.once("listening", () => probe.close(() => done(true)));
   probe.listen(port, "127.0.0.1");
  });
  if (free) {
   claimed.add(port);
   return port;
  }
 }
 throw new Error(`no free port in [${preferred}, ${preferred + span}) not already claimed by this run`);
}

function sleep(ms: number): Promise<void> {
 return new Promise((done) => setTimeout(done, ms));
}

/**
 * Progress breadcrumbs to stderr.
 *
 * These are permanent, not debug leftovers. Playwright reports a globalSetup failure as the bare
 * exception — a socket-level error out of the seeding phase arrives as "Error: socket hang up" with no
 * indication of which of the six steps produced it, which cost an afternoon once already.
 */
function note(message: string): void {
 process.stderr.write(`[e2e-ui] ${message}\n`);
}

/** Poll until an HTTP GET answers at all. Any status counts — we are waiting on the listener. */
async function waitForHttp(url: string, attempts = 150): Promise<void> {
 for (let i = 0; i < attempts; i += 1) {
  try {
   const response = await fetch(url);
   await response.arrayBuffer();
   return;
  } catch {
   await sleep(100);
  }
 }
 throw new Error(`timed out waiting for ${url}`);
}

/**
 * Poll until a TCP connect succeeds. The proxy port speaks HTTP-via-proxy, not plain HTTP, so an
 * ordinary GET against it is not a readiness check — e2e-go.sh reaches for /dev/tcp for this reason.
 */
async function waitForTcp(port: number, attempts = 150): Promise<void> {
 for (let i = 0; i < attempts; i += 1) {
  const up = await new Promise<boolean>((done) => {
   const socket = createConnection({ host: "127.0.0.1", port });
   socket.once("connect", () => socket.end(() => done(true)));
   socket.once("error", () => done(false));
  });
  if (up) return;
  await sleep(100);
 }
 throw new Error(`timed out waiting for tcp 127.0.0.1:${port}`);
}

/**
 * One request through burpsy's proxy. A proxy client sends the ABSOLUTE form in the request line,
 * which is exactly what node's http.request does when given `path: "http://host/..."` — so this is
 * the same wire bytes curl -x produces, and it lands in HTTP history the same way.
 *
 * `agent: false` — a fresh socket per request — is a WORKAROUND FOR A REAL BUG in burpsy's proxy, not
 * a stylistic choice. The proxy passes the upstream's `Connection: keep-alive` and `Keep-Alive:
 * timeout=5` straight through to the client and then closes the client socket anyway, so a second
 * request sent on that socket gets "socket hang up". Node's global agent has kept connections alive
 * by default since v19, which is why this bites here; curl -x survives it only because curl silently
 * reconnects ("Connection died, retrying a fresh connect"), which is why none of the shell suites
 * ever noticed. Reproduce it with:
 *   curl -sv -x http://127.0.0.1:PROXY http://ORIGIN/one http://ORIGIN/two
 * Remove this once the proxy either honours keep-alive or rewrites the header to `Connection: close`.
 */
function viaProxy(proxyPort: number, url: string): Promise<void> {
 return new Promise((done, fail) => {
  const target = new URL(url);
  const req = httpRequest(
   {
    host: "127.0.0.1",
    port: proxyPort,
    method: "GET",
    path: url,
    headers: { Host: target.host },
    agent: false,
   },
   (response) => {
    response.resume();
    response.once("end", () => done());
   },
  );
  req.once("error", fail);
  req.end();
 });
}

async function postJson(webPort: number, path: string, body: unknown): Promise<unknown> {
 const response = await fetch(`http://127.0.0.1:${webPort}${path}`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(body),
 });
 return response.json().catch(() => null);
}

/**
 * The traffic every run seeds, exported because a second consumer now names the same paths.
 *
 * `ui-live.sh` stands this harness up and hands the console to an agent that drives it in a browser
 * instead of to Playwright, and that agent has to know what it should be looking at: "history has
 * rows" is not a claim anyone can check, "history holds these five paths, and no sixth" is. Spelling
 * the list in a shell script as well as here is how the two would drift, so it is spelled once.
 *
 * A change here changes what the live pass looks at, which is why it is a const rather than an
 * inline array — someone editing the fixture should see that it is load-bearing.
 */
export const SEEDED_PATHS = ["/zebra", "/alpha?q=1", "/mango/deep/path", "/beta", "/quokka?size=8"] as const;

/** The Repeater send's path — the one row that belongs in the Tool log and not in proxy history. */
export const SEEDED_REPEATER_PATH = "/repeated";

/** Dense ids start at zero and id 0 is a real exchange, so the seeded audit names it explicitly. */
export const SEEDED_AUDIT_ID = 0;

/**
 * Give every data view something real to render.
 *
 * The paths, methods and response sizes are deliberately all different. A sort assertion against
 * rows that happen to be identical passes whether or not sorting works, which is the same class of
 * vacuous check this tree is being cleaned of.
 */
async function seed(harness: Omit<Harness, "burpsyPid" | "targetPid">): Promise<void> {
 const { proxyPort, webPort, targetPort } = harness;
 const origin = `http://127.0.0.1:${targetPort}`;

 // Proxy traffic: fills HTTP history, the site map, and the dashboard's activity counters. The paths
 // are deliberately not in alphabetical order, so an ascending sort in the UI has to move something.
 for (const path of SEEDED_PATHS) {
  try {
   await viaProxy(proxyPort, `${origin}${path}`);
  } catch (error) {
   throw new Error(`seeding ${path} through the proxy failed: ${(error as Error).message}`);
  }
 }
 note(`seeded ${SEEDED_PATHS.length} proxied exchanges through 127.0.0.1:${proxyPort}`);

 // A repeater send: fills the Tool log, which only ever shows requests burpsy itself made, so
 // proxy traffic alone would leave that route on its empty state.
 const raw = `GET ${SEEDED_REPEATER_PATH}?x=9 HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\nConnection: close\r\n\r\n`;
 await postJson(webPort, "/api/repeater/send", { target: origin, protocol: "http", request: raw });
 note("seeded one repeater send");

 // An audit against the first exchange: fills Issues. Exchange ids are a dense counter from zero
 // and id 0 is a real id — e2e-go.sh has a whole section on the bug where it was rejected.
 await postJson(webPort, `/api/audit/${SEEDED_AUDIT_ID}`, {});
 note(`seeded one audit against exchange ${SEEDED_AUDIT_ID}`);

 // The server records exchanges asynchronously; give the last of them a moment to land so the
 // first test to open HTTP history does not race the write.
 await sleep(600);
}

export async function start(): Promise<Harness> {
 const goRoot = goModuleRoot();
 const dir = mkdtempSync(join(tmpdir(), "burpsy-ui-e2e-"));
 const bin = join(dir, "burpsy");

 const build = spawnSync("go", ["build", "-o", bin, "./cmd/burpsy"], {
  cwd: goRoot,
  encoding: "utf8",
 });
 if (build.status !== 0) {
  throw new Error(`go build ./cmd/burpsy failed:\n${build.stderr || build.stdout}`);
 }

 const proxyPort = await freePort(PREFERRED.proxy);
 const webPort = await freePort(PREFERRED.web);
 const targetPort = await freePort(PREFERRED.target);

 // The origin runs as its own process rather than inside this one: Playwright's globalSetup process
 // is not guaranteed to outlive setup, and an origin that dies mid-run looks exactly like a proxy
 // bug from inside the browser. Its script lives in artifacts/ alongside the log, because a /tmp
 // sweep that removes it would take out the origin's `import` at any later restart.
 const targetScript = join(artifactsDir(), "origin.mjs");
 writeFileSync(targetScript, ORIGIN_SOURCE);
 // detached: true puts each child in its OWN process group, and it is load-bearing.
 //
 // Playwright runs globalSetup in a process of its own and tears that process's group down when it
 // is finished with it, which sent burpsy a SIGTERM roughly a minute into the run. burpsy logged a
 // tidy "Shutting down..." and every test from that point on failed with a flat
 // ERR_CONNECTION_REFUSED — 40 failures whose real cause was one signal nobody meant to send.
 // Detached, these two outlive setup, and stop() kills them explicitly by pid instead.
 const target = spawn(process.execPath, [targetScript, String(targetPort)], {
  stdio: "ignore",
  detached: true,
 });
 target.unref();

 // artifacts/, not the temp directory: this log is the only account of what the server did, and it
 // has to outlive both the run and anything that tidies /tmp.
 const logPath = join(artifactsDir(), "burpsy.log");
 const log = openSync(logPath, "w");
 const burpsy = spawn(bin, ["--proxy", `127.0.0.1:${proxyPort}`, "--web", `127.0.0.1:${webPort}`], {
  stdio: ["ignore", log, log],
  detached: true,
 });
 burpsy.unref();

 const died = (child: ChildProcess, name: string) =>
  child.once("exit", (code) => {
   if (code !== null && code !== 0) note(`${name} exited with ${code}`);
  });
 died(target, "origin");
 died(burpsy, "burpsy");

 const harness: Harness = {
  dir,
  webPort,
  proxyPort,
  targetPort,
  burpsyPid: burpsy.pid ?? -1,
  targetPid: target.pid ?? -1,
 };

 // Written NOW, before anything that can throw. globalTeardown reads this file and nothing else, so
 // a state file written after seeding means a seeding failure leaks a burpsy holding 182xx — and the
 // NEXT run then finds those ports busy, silently talks to the stale process, and fails somewhere
 // else entirely. That happened while this file was being written and cost an hour of looking in the
 // wrong place.
 writeFileSync(statePath(), JSON.stringify(harness, null, 2));

 note(`built ${bin}; ports proxy=${proxyPort} web=${webPort} origin=${targetPort}`);
 try {
  await waitForHttp(`http://127.0.0.1:${targetPort}/`);
  await waitForHttp(`http://127.0.0.1:${webPort}/api/stats`);
  await waitForTcp(proxyPort);
  assertOurListeners(logPath, harness);
  note("all three listeners up, and they are ours");
  await seed(harness);
 } catch (error) {
  // The log is the only place burpsy's own account of the failure exists, and Playwright prints the
  // exception alone. Folding it in beats "socket hang up" with no context.
  throw new Error(`${(error as Error).message}\n--- burpsy log ---\n${tail(logPath, 25)}`);
 }
 return harness;
}

/**
 * Confirm the listeners we waited for belong to the burpsy we started.
 *
 * This is not paranoia. burpsy logs a failed bind at error level and KEEPS RUNNING with no listener —
 * so a stale instance on the same port makes every readiness probe pass while the process under test
 * serves nothing. From the outside that is indistinguishable from success, and it produced a wholly
 * misleading failure two steps later. Reading burpsy's own log for the bind error is the cheapest
 * honest check available from here.
 */
function assertOurListeners(logPath: string, harness: Harness): void {
 const log = existsSync(logPath) ? readFileSync(logPath, "utf8") : "";
 if (/address already in use|failed to bind/.test(log)) {
  throw new Error(
   `burpsy failed to bind (pid ${harness.burpsyPid}) yet stayed alive, so the probes above were ` +
   `answered by something else on proxy=${harness.proxyPort} web=${harness.webPort}. ` +
   `Check for a leftover burpsy: ss -ltn | grep 182`,
  );
 }
}

function tail(path: string, lines: number): string {
 if (!existsSync(path)) return "(no log)";
 return readFileSync(path, "utf8").split("\n").slice(-lines).join("\n");
}

export function stop(harness: Harness): void {
 for (const pid of [harness.burpsyPid, harness.targetPid]) {
  if (pid > 0) {
   try {
    // The process GROUP (-pid), because these are spawned detached and are therefore group
    // leaders — killing the group also collects anything they spawned. SIGKILL rather than
    // SIGTERM: they are throwaway processes with nothing to flush, and one that slow-walks a TERM
    // leaves a listener on 182xx that makes the NEXT run's probes pass against the wrong process,
    // which is the failure assertOurListeners exists to catch and is better prevented than
    // diagnosed.
    process.kill(-pid, "SIGKILL");
   } catch {
    try {
     process.kill(pid, "SIGKILL");
    } catch {
     // Already gone; nothing to do. A failed kill must not mask a test failure.
    }
   }
  }
 }
 // The temp directory holds only the built binary, and building to a temp path is exactly what keeps
 // an untracked executable out of the tree. burpsy's log is in artifacts/ and deliberately KEPT: a
 // mid-run server death surfaces in the browser as a flat ERR_CONNECTION_REFUSED on whichever test
 // came next, and without the log that is indistinguishable from a broken selector.
 rmSync(harness.dir, { recursive: true, force: true });
 rmSync(statePath(), { force: true });
}

/**
 * The throwaway origin. It echoes method and path so an assertion can tell one captured exchange
 * from another, and pads the body by a per-path amount so response lengths differ — which is what
 * makes "sort by Length actually reorders the rows" a real assertion rather than a tautology.
 */
const ORIGIN_SOURCE = `import http from "node:http";
const port = Number(process.argv[2]);
let counter = 0;
// A 2x2 PNG (red pixels), hand-built to the spec so the harness needs no image asset on disk.
// n7n's Render-view test renders this through the proxy: a payload the test can assert pixel
// bytes for, not an opaque blob.
const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAIAAAD91JpzAAAAEUlEQVR4nGP8z0Dw //8DwwADAGnvABMCAAAAAElFTkSuQmCC".replace(/ /g, ""),
  "base64",
);
http
  .createServer((req, res) => {
    counter += 1;
    if ((req.url ?? "").startsWith("/image.png")) {
      res.writeHead(200, { "Content-Type": "image/png", "Content-Length": PNG.length });
      res.end(PNG);
      return;
    }
    const pad = "x".repeat((req.url ?? "/").length * 7);
    const body = \`ORIGIN-OK \${req.method} \${req.url} \${pad}\`;
    res.writeHead(200, {
      "Content-Type": "text/plain",
      "Content-Length": Buffer.byteLength(body),
      "Set-Cookie": \`E2E_SESSION=tok\${String(counter).padStart(4, "0")}; Path=/; SameSite=Lax\`,
    });
    res.end(body);
  })
  .listen(port, "127.0.0.1");
`;
