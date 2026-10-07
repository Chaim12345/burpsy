#!/usr/bin/env bash
# The live browser pass over the web console — burpsy's UI check, instead of the playwright suite.
#
# Why the swap. The spec suite is a ~10 minute Chromium run per pass, which is long enough that UI
# verification gets deferred, and it is transpiled without being typechecked — two of its specs named
# the consoleErrors fixture and never read it, so they asserted nothing, and nobody could tell
# (burpsy-react-ui-93au, fixed in e61c5d2). What a UI change most needs proving is that a person
# opening the console sees the right thing, and that is not what a green spec says. An agent driving
# agent-browser covers the same ground in a fraction of the time and can report what it actually saw.
# The suite is still in the tree and still runs (`./e2e-ui.sh`); it is just not the gate any more.
#
# What this script does is stand the console up on the SAME fixtures the specs used — it imports the
# harness's own `start()` and `ROUTES`, so neither the seeded traffic nor the route list can drift
# from what the specs exercised — and then get out of the way. It judges nothing. The judging is done
# in a browser and burpsy-go/docs/UI-VERIFICATION.md is what the pass must cover and what a claim
# needs to rest on.
#
#   ./ui-live.sh          start the console, seeded, and print the pass
#   ./ui-live.sh --stop   stop it and clean up
#
# Deliberately NOT named e2e-*.sh: verify.sh sweeps `for s in e2e*.sh` and runs everything it finds,
# and a script whose job is to leave three processes running is not something a sweep should pick up.
#
# One pass at a time. The harness keeps ONE state file per checkout for its teardown to find, so a
# live pass and an e2e-ui run in the same checkout would overwrite each other's record and the loser's
# teardown would kill the wrong processes. This script keeps its own copy (`$LIVE` below) so its own
# --stop is not at the mercy of that file, and refuses to start while either is present.
#
# Refusals exit NON-ZERO, unlike the e2e scripts' quiet exit 0. Those are swept up by verify.sh, which
# turns a silent exit into a SKIP line so an unavailable check does not read as a pass. This script is
# only ever run on purpose, so "it could not run" must never look like success.
set -uo pipefail
cd "$(dirname "$0")"

UI=burpsy-go/internal/web/ui
E2E=$UI/e2e
# Absolute, because several of the node invocations below run with $E2E as their cwd — a relative path
# handed to those resolves against the wrong directory and the failure looks like a missing file.
ROOT=$(pwd)
STATE=$ROOT/$E2E/artifacts/run-state.json   # the harness's own record, shared with e2e-ui.sh
LIVE=$ROOT/$E2E/artifacts/live-pass.json    # this script's copy, so --stop is not hostage to the above

if [ "${1:-}" = "--stop" ]; then
  if [ ! -f "$LIVE" ]; then
    echo "no live pass is running: there is no $LIVE"
    exit 0
  fi
  ( cd "$E2E" && node --input-type=module -e '
import { readFileSync, rmSync, existsSync } from "node:fs";
import { stop, statePath } from "./harness/server.ts";
const h = JSON.parse(readFileSync(process.argv[1], "utf8"));
stop(h);
// Said out loud: this is the one command that kills processes and deletes a directory, and silence on
// success reads exactly like having done nothing.
console.log(`stopped burpsy ${h.burpsyPid} and the origin ${h.targetPid}; removed ${h.dir}`);
// stop() removes the harness state file only if it is the one it knows about; a copy left behind by
// an interleaved e2e-ui run is not ours to delete, so it is reported rather than quietly removed.
if (existsSync(statePath())) console.log(`note: ${statePath()} also exists — an e2e-ui run may be in flight`);
' "$LIVE" )
  RC=$?
  # The record is only removed when the kill actually succeeded. It is the only thing that knows which
  # pids and which temp directory belong to this pass, so deleting it after a failed kill strands a
  # burpsy holding the fixture ports AND removes the means of finding it. The first version of this
  # script did exactly that, and the fixture had to be hunted down by pid.
  if [ "$RC" = "0" ]; then
    rm -f "$LIVE"
  else
    echo "the pass was NOT stopped — $LIVE is kept so a retry can find it" >&2
  fi
  exit $RC
fi
if [ -n "${1:-}" ]; then echo "usage: ./ui-live.sh [--stop]" >&2; exit 2; fi

command -v node >/dev/null 2>&1 || { echo "REFUSED: no node on PATH — nothing to start the fixture with" >&2; exit 1; }
command -v go   >/dev/null 2>&1 || { echo "REFUSED: no go toolchain — cannot build the server under test" >&2; exit 1; }
command -v bun  >/dev/null 2>&1 || {
  echo "REFUSED: no bun — cannot rebuild the bundle, and the binary embeds ui/dist/, so a pass here" >&2
  echo "         would be looking at whatever was committed last, not at src/. Install bun, or run" >&2
  echo "         'cd $UI && bun run build' by hand first." >&2
  exit 1
}
if [ ! -f "$E2E/node_modules/axe-core/axe.min.js" ]; then
  echo "REFUSED: axe-core is not installed (run: cd $E2E && npm ci) — the accessibility half of the" >&2
  echo "         pass is the half that regresses silently, so it is not optional here." >&2
  exit 1
fi

# A stale run makes every readiness probe pass against the wrong process, which is a failure that
# costs an afternoon to diagnose from the browser. Catching it here is cheap. The harness's own state
# file is checked as well as ours: if it exists, the run that wrote it is still holding the fixture
# ports, and starting a second one would clobber its record.
if [ -f "$LIVE" ]; then
  echo "REFUSED: a live pass is already running. Run ./ui-live.sh --stop first." >&2
  exit 1
fi
if [ -f "$STATE" ]; then
  echo "REFUSED: $STATE exists — an e2e-ui run (or an interrupted one) is holding the fixture ports." >&2
  echo "         Wait for it, or stop it, before starting a live pass." >&2
  exit 1
fi

# The bundle FIRST, before the harness builds the binary. The Go binary embeds ui/dist/app.js and
# ui/style.css via go:embed, so building the server before the bundle would embed the previous
# revision of src/ and the pass would be a careful look at code that is not in the tree.
echo "== building the bundle from src/ ..."
( cd "$UI" && bun run build ) || { echo "REFUSED: bun run build failed" >&2; exit 1; }

echo "== starting the fixture (real burpsy, throwaway origin, seeded traffic) ..."
( cd "$E2E" && node --input-type=module -e '
import { start } from "./harness/server.ts";
const h = await start();
console.log(`started burpsy ${h.burpsyPid} and the origin ${h.targetPid}`);
' ) || { echo "REFUSED: the fixture did not come up (its breadcrumbs are above)" >&2; exit 1; }

# Taken immediately after start and BEFORE anything that can fail, matching the harness's own reason
# for writing its state file first: a pass recorded after the readout means a crash between the two
# leaves a burpsy holding the ports with nothing on disk saying so.
cp "$STATE" "$LIVE"

# The trailing newline is load-bearing: `read` returns nonzero at EOF *without* a delimiter, so a
# write with no newline would take the refusal path and report the state file as unreadable — a
# refusal pointing at the wrong thing.
read -r WEB PROXY ORIGIN < <(node -e '
const h = JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"));
process.stdout.write(`${h.webPort} ${h.proxyPort} ${h.targetPort}\n`);
' "$LIVE") || { echo "REFUSED: $LIVE is unreadable" >&2; exit 1; }

# Both read out of the harness rather than retyped here, so a change to the fixture or the route list
# cannot leave this printout describing a console that no longer matches the one it started.
SEEDED=$(cd "$E2E" && node --input-type=module -e '
import { SEEDED_PATHS, SEEDED_REPEATER_PATH, SEEDED_AUDIT_ID } from "./harness/server.ts";
console.log(SEEDED_PATHS.join(" "));
console.log(`${SEEDED_REPEATER_PATH} (Tool log only), and exchange ${SEEDED_AUDIT_ID} audited (Issues)`);
')
ROUTES=$(cd "$E2E" && node --input-type=module -e '
import { ROUTES } from "./harness/routes.ts";
console.log(ROUTES.map((r) => `#${r.id}`).join(" "));
console.log(ROUTES.map((r) => `#${r.id}  ->  h1 "${r.h1}"`).join("\n    "));
')

cat <<EOF

== the console is up, on traffic

  Web console     http://127.0.0.1:$WEB/
  Proxy (curl -x) http://127.0.0.1:$PROXY
  Fixture origin  http://127.0.0.1:$ORIGIN

  Seeded, in HTTP history and the site map:
    $(echo "$SEEDED" | head -1)
  Seeded, elsewhere:
    $(echo "$SEEDED" | sed -n 2p)

  Those are the paths the browser should show. "History has rows" is not a claim anyone can check;
  "history holds these five paths and no sixth" is, and the sixth is what a leak looks like.

== setting up agent-browser

  It needs a runtime directory or its daemon refuses to start. That is the whole trap:

    export XDG_RUNTIME_DIR=\${XDG_RUNTIME_DIR:-/tmp/burpsy-ab-runtime} && mkdir -p "\$XDG_RUNTIME_DIR"
    agent-browser open http://127.0.0.1:$WEB/
    agent-browser wait --load networkidle

== the routes, read from the suite's own list (harness/routes.ts)

  $(echo "$ROUTES" | sed -n 1p)

  Each of them, one at a time — the hash IS the route, so this is a navigation and not a click:

$(echo "$ROUTES" | sed -n '2,$p' | sed 's/^/    /')

  The h1 is the claim: it is the page saying which page it is, and the suite asserted the same text.
  A route that renders the previous route's h1 is a stale pane, which a screenshot cannot show.
  \`agent-browser diff snapshot\` before and after a navigation is the cheap way to see it.

== the browser's own account of itself

  agent-browser console     # the console, unfiltered
  agent-browser errors      # uncaught exceptions and page errors: this one must be EMPTY

  The console is NOT required to be empty, and pretending otherwise would make this check useless.
  What is expected in a default run, and nothing more:

    [info]  "Download the React DevTools..." — React's own dev-mode notice, not this app's doing.
    [error] "Failed to load resource: ... 404" — a NETWORK fact, and it names no URL. The one
            expected here is the probe for /ca.crt, which answers 404 because burpsy was started
            without -intercept-tls: TLS interception is off, so the console asks whether there is a
            certificate before offering one. src/lib/data.policy.ts:90 is that probe.

  Anything else at error level, and any page error, is a finding. To attribute a bare 404, list what
  the page actually asked for rather than guessing from the text:

    agent-browser network requests --clear && agent-browser reload
    agent-browser network requests            # method + URL for every request (no status column)
    curl -s -o /dev/null -w '%{http_code} <url>\\n' <url>   # ...and probe the candidates

== accessibility, per route

  The same rules the a11y spec ran (wcag2a, wcag2aa, wcag21a, wcag21aa), injected into the page:

    agent-browser eval --stdin < $E2E/node_modules/axe-core/axe.min.js
    agent-browser eval --stdin <<'JS'
    (async () => {
      const r = await axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] } });
      return JSON.stringify(r.violations.map(v => ({ id: v.id, impact: v.impact, nodes: v.nodes.map(n => n.target.join(" ")) })));
    })()
    JS

  Re-inject after every open/navigation — the injection lives in the document, so a route change
  that reloads the page throws \`axe is not defined\`. The assertion is ZERO violations, with no
  exceptions list: a rule that cannot be satisfied gets named in the doc and filed, not thresholded.

== the pass itself

  burpsy-go/docs/UI-VERIFICATION.md is the definition — what a change has to be checked against and
  what evidence a claim needs. The short version: a page that loads is not a page that works, and
  "not reproduced" is a result worth reporting as loudly as "reproduced".

  When you are done:  ./ui-live.sh --stop
EOF
