# Verifying a change to the web console

The console is the only surface a person actually looks at, and for most of this project's life
"verified" in a UI change meant "an agent looked at it". This page is what makes that check
repeatable. It replaces the playwright suite as the gate: `./e2e-ui.sh` still exists and still runs,
but it is not what a claim about the UI has to survive any more.

**Nothing here is a substitute for looking at the thing.** Step 4 is the pass; steps 1–3 exist so that
what you look at is the code in the tree, on traffic that means something.

## Why the spec suite stopped being the gate

Not because it was wrong — it found real defects, and its fixtures are still the fixture vocabulary
(step 3 below imports them). Three things made it the wrong instrument:

- **Time.** A full run is ~10 minutes of Chromium. That is long enough that UI verification gets
  deferred to "later", and a check that gets deferred is a check that does not happen.
- **It did not check itself.** Playwright transpiles without typechecking, so the suite was red on
  files nobody had touched: two specs named the `consoleErrors` fixture and never read it, asserting
  nothing about the console they had asked for (`burpsy-react-ui-93au`). The typecheck is wired in
  now (`e2e-ui.sh`), but the lesson stands: a passing suite is not a suite that asserts.
- **It answered the wrong question.** "37 passed" is a statement about the specs. What a UI claim
  needs is that a browser, loading this binary, on this traffic, shows the right thing — and an agent
  driving the real console answers that directly, and can report what it saw.

## 1. Stand it up

```bash
./ui-live.sh          # builds the bundle, builds the binary, boots it, seeds traffic, prints the pass
./ui-live.sh --stop   # afterwards, always
```

It refuses rather than half-running (non-zero exit, no partial pass) when bun, go, node or axe-core
is missing, and it rebuilds `ui/dist/` **before** the binary, because the Go binary embeds the bundle
via `go:embed` — build in the other order and you spend a careful afternoon looking at the previous
revision of `src/`. One pass at a time: it refuses to start while another run holds the fixture ports.

## 2. What is running

A real `burpsy` built from the tree, a throwaway origin, and the seeding the spec suite used:

| | |
|---|---|
| Web console | `http://127.0.0.1:18281/` |
| Proxy (`curl -x`) | `http://127.0.0.1:18280` |
| Fixture origin | a loopback node server, port printed on start |

Seeded: five proxied exchanges (`/zebra /alpha?q=1 /mango/deep/path /beta /quokka?size=8`), one
Repeater send (`/repeated` — Tool log only), and one audit against exchange 0 (Issues).

A port that looks unfamiliar means something else is on the preferred one; the harness walks forward
and prints what it chose. What it must never do is let a probe pass against a *stale* burpsy — the
harness reads burpsy's own log for a bind failure and refuses if it finds one, because burpsy logs a
failed bind and keeps running.

## 3. Drive it

An agent driving `agent-browser` is the intended instrument; a person with a browser is fine too.

```bash
export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/tmp/burpsy-ab-runtime} && mkdir -p "$XDG_RUNTIME_DIR"
agent-browser open http://127.0.0.1:18281/
agent-browser wait --load networkidle
```

The `XDG_RUNTIME_DIR` line is not decoration: without it the daemon fails to start and every command
after it is a connection error.

## 4. The pass

Do all four. The first two are mechanical and the last two are where defects actually live.

Parts (a), (b) and (d) are scripted — `./ui-pass.sh` (repo root) drives an already-running console:

```bash
./ui-live.sh &                    # in another terminal; the script never boots its own fixture
./ui-pass.sh                      # every route: h1, axe, page errors
./ui-pass.sh --route scope --route sequencer   # just the routes a change touched
```

It reads the route list and expected h1 text out of `e2e/harness/routes.ts` (the contract, not a
second copy), injects axe per route, and exits non-zero on the first failure class it finds. It
refuses rather than half-running when the console is not up, when agent-browser or python3 is
missing, or when axe-core is not installed. A full sweep is ~75 seconds; a three-route check is ~6.
Part (c) is still yours — that is the part that finds defects, and the script deliberately does not
pretend to do it.

### a. Every route renders, and says which route it is

The route list is `burpsy-go/internal/web/ui/e2e/harness/routes.ts` — 26 ids, and the exact list the
spec suite asserted. `ui-live.sh` prints it with each route's `<h1>`.

For each route: open `/#<id>`, wait, and read the h1. It must be the route's own title.

```bash
agent-browser open "http://127.0.0.1:18281/#history" && agent-browser get text "main h1"
```

The h1 is the claim that matters. Navigation here is a hash change against a mounted app, so the
*previous* route's h1 is on screen for a frame or two — a page that renders the wrong h1 is a stale
pane, and it is exactly the failure a screenshot cannot show. `agent-browser diff snapshot` around a
navigation shows what actually moved.

### b. No uncaught errors, and a console you can explain

```bash
agent-browser errors      # must be EMPTY — uncaught exceptions
agent-browser console     # must be EXPLAINED, not empty
```

The console is not required to be silent, and pretending it is would make this check useless. In a
default run exactly three things appear — two `[error]` lines, both explained here, and one `[info]`:

- `[info] Download the React DevTools...` — React's dev-mode notice.
- `[error] Failed to load resource: the server responded with a status of 404 (Not Found)` — the probe
  for `/ca.crt` (`src/lib/data.policy.ts:90`). burpsy is started here without `-intercept-tls`, so
  there is no CA to hand out and the console asks before offering one. **That 404 is correct
  behaviour**; a console driver that flagged it would be crying wolf on every load.

  It is **one probe per page load, from the app shell** (`src/app.tsx:171`), not one per route — the
  earlier version of this section attributed it to `#dashboard` and `#settings` and called those "the
  two that mount the CA probe". That is wrong, and it became visible while verifying Match & Replace:
  the error appears on `#matchreplace` too, because the shell mounts the probe for every route. In a
  multi-route sweep the fetch happens once and is cached, so the single console line lands against
  whichever route the sweep opened first — which is how it came to look route-specific. `#dashboard`
  and `#settings` do also read the result, which is why a *rendered* "no CA" message appears on those
  two only.
- A second `[error] ... 404` — `/favicon.ico`. The console declares its icon inline (`index.html`'s
  `data:image/svg+xml` link), so there is no such file to serve, but Chromium still probes the
  conventional path on a page it opened itself. Verified 2026-09-14: the served page carries the icon
  link, `curl /favicon.ico` answers 404, and no app code requests it. Nothing to fix; it is listed
  here so the next pass does not re-investigate it.

Anything else at error level is a finding. Chromium's "Failed to load resource" line names no URL, so
attribute it by listing what the page requested rather than guessing from the text:

```bash
agent-browser network requests --clear && agent-browser reload
agent-browser network requests
curl -s -o /dev/null -w '%{http_code}\n' <candidate-url>
```

### c. The behaviour the change is about

Route rendering is smoke. The pass is not done when the pages load; it is done when the *specific
behaviour* has been driven and its result read. What "read" means:

- **Read the rendered state, not the code.** A checkbox that visibly ticks is not a preference saved;
  reload and look again.
- **Every claim names something a person could check.** "The Edited badge appears" is not it;
  "the row for `/held-edited-by-hand` shows `Edited`, and the four rows nobody touched show `—`" is.
- **Drive it the way the operator would.** Click the control. Use the keyboard where the affordance is
  keyboard-only. Where the feature is about bytes on the wire, send something through the proxy
  (`curl -x http://127.0.0.1:18280 http://127.0.0.1:<origin>/your-path`) and read the row it lands in.
- **Check the negative.** The row that should *not* be there, the toggle that should *not* change the
  date, the disabled control's reason text. Half of what this tree has fixed was an over-marking:
  burpsy flagging an edit nobody made, a count that included something it should not.

### d. Accessibility, per changed route

The same rule set the a11y spec ran:

```bash
agent-browser eval --stdin < burpsy-go/internal/web/ui/e2e/node_modules/axe-core/axe.min.js
agent-browser eval --stdin <<'JS'
(async () => {
  const r = await axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] } });
  return JSON.stringify(r.violations.map(v => ({ id: v.id, impact: v.impact, nodes: v.nodes.map(n => n.target.join(" ")) })));
})()
JS
```

Zero violations. Re-inject after every `open`/navigation — the injection lives in the document, and a
route change that reloads the page leaves you with `axe is not defined`.

Do not reach for a threshold ("no more than 12 violations") if a rule turns out to be unsatisfiable.
A number becomes the contract and numbers only go up. Name the rule and the reason in this file, file
an issue for it, and keep it failing loudly until it is fixed or the exception is written down.

## 5. Report

The report is the deliverable — a claim without it is an assertion.

- **What you looked at**: the route(s) and the fixture(s), by name.
- **What you saw**, in the browser's words: the h1 text, the row states, the count, the console line.
- **What you did not look at**, said out loud. A pass that covered three of four checks and says so is
  useful; one that implies coverage it did not have is the failure mode this file exists to prevent.
- **"Not reproduced" is a result.** If you tried to break the fix and could not, say what you tried —
  the shape of the attempt is the evidence for the claim, and it is more informative than a screenshot.
- **Count honestly.** If the console had an unexpected 404, that is a finding even if the feature under
  test works. Do not round it to "console is clean".

## What this does not cover

- **Regressions in routes you did not open.** The sweep in (a) is the mitigation; skipping it means
  your change is verified only where you looked, and saying so is part of the report.
- **Concurrency and load.** One browser, one operator. Two clients, a slow origin, a socket that dies
  mid-response — those want `e2e-go.sh` and the Go tests, not this.
- **The committed screenshots.** `e2e/specs/screenshots.spec.ts` regenerates
  `e2e/artifacts/screenshots/` and is run only through `./e2e-ui.sh` now. Losing that means the design
  diffs in `docs/ui-map/` go stale silently; if you are doing visual work, run the suite for its
  screenshots even though it is not the gate.
- **The Rust tree.** It is the frozen reference. This page is about `burpsy-go`.
