#!/usr/bin/env bash
# Browser acceptance test for the web console: does the UI burpsy-go actually serves work?
#
# Until this existed there was NO browser verification in this repository at all. The only
# measurements of the console live in docs/ui-map/07-design-analysis.md, taken out-of-tree and
# unreproducible from this checkout — so "verified" in any UI claim meant "an agent looked at it". The
# suite this script runs is the fix: it builds burpsy-go, boots it, drives the real console in a real
# Chromium, and asserts on what the browser reports.
#
# What it covers, so the shape is visible without reading the specs:
#   * every one of the 17 routes in src/nav.ts renders, names itself in an <h1>, owns the URL hash,
#     does not hit the ErrorBoundary, and logs ZERO console errors
#   * behaviour, not smoke: the theme toggle changes rendered colour (not just the attribute), mod+K
#     opens and runs the command palette, ? opens the shortcut sheet, a table header actually
#     reorders rows, arrow keys move the table selection, Radix tab panes swap
#   * axe-core over every route in BOTH themes, plus the palette and the shortcut sheet
#   * 68 screenshots — 17 routes x {1440x900, 390x844} x {dark, light}. Dark is the shipped default
#     and 07-design-analysis.md measures light only, so on the evidence in this tree the default
#     theme had never been measured.
#
# Same output contract as the sibling e2e scripts: a "N passed, M failed" line at the end, which is
# what verify.sh greps for. Same refusal contract too — if the browser or the toolchain is missing it
# prints one line saying so and exits 0 WITHOUT a result line, and verify.sh turns that into a SKIP.
# A check that did not run is not a check that passed.
#
# `./e2e-ui.sh --check` runs the precondition block and nothing else: exit 0 means the suite can run,
# exit 3 prints the reason it cannot. That mode exists so verify.sh can report the SKIP with the real
# reason without keeping a second copy of "is there a browser on this machine" that can drift from
# this one — the way the /tmp/BChecks condition is currently spelled in two places.
set -uo pipefail
cd "$(dirname "$0")"

UI=burpsy-go/internal/web/ui
E2E=$UI/e2e
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

PASS=0; FAIL=0
ok(){ echo "  PASS  $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
refuse(){ echo "$1"; [ "$CHECK_ONLY" = "1" ] && exit 3; exit 0; }

# ---- refusals: everything below needs all of these, and none of them is this suite's business ----
command -v node >/dev/null 2>&1 || refuse "node absent — the browser suite cannot run"
command -v go   >/dev/null 2>&1 || refuse "no go toolchain — cannot build the server the suite drives"
[ -d "$E2E/node_modules/@playwright/test" ] \
  || refuse "playwright not installed — run: (cd $E2E && npm ci)"

# Whether a browser BINARY exists, which is a different question from whether the npm package does.
# playwright-core resolves the revision it wants against ~/.cache/ms-playwright; an npm install that
# skipped the browser download leaves the package present and every test failing on launch, which
# would report as 30-odd failures rather than as "no browser here".
BROWSER=$(cd "$E2E" && node -e '
const { existsSync } = require("node:fs");
try {
  const path = require("playwright-core").chromium.executablePath();
  process.stdout.write(existsSync(path) ? path : "");
} catch { process.stdout.write(""); }
' 2>/dev/null)
[ -n "$BROWSER" ] \
  || refuse "no chromium for playwright — run: (cd $E2E && npx playwright install chromium)"

[ "$CHECK_ONLY" = "1" ] && exit 0

# ---- is the console under test the console in src/? ---------------------------------------------
# The Go binary embeds ui/dist/app.js and ui/style.css via go:embed, so the browser only ever sees
# the COMMITTED bundle. Edit a .tsx and forget `bun run build` and this suite passes a stale UI while
# reporting on the new source — the exact "a partial result looking complete" failure the rest of
# this tree is being cleaned of, and it would be invisible from inside the browser.
#
# mtimes cannot answer this (a fresh clone's are all checkout time), so the bundle is rebuilt to a
# temp directory and compared byte for byte. bun's minified output is deterministic, which is what
# makes the comparison meaningful rather than noisy.
if command -v bun >/dev/null 2>&1; then
  FRESH=$(mktemp -d /tmp/burpsy-ui-fresh-XXXXXX)
  if (cd "$UI" && bun build src/app.tsx --outdir "$FRESH" --minify >/dev/null 2>&1 \
      && bun build src/styles.css --outfile "$FRESH/style.css" --minify >/dev/null 2>&1); then
    if cmp -s "$FRESH/app.js" "$UI/dist/app.js" && cmp -s "$FRESH/style.css" "$UI/style.css"; then
      ok "the embedded bundle matches src/ — the browser is testing current source"
    else
      no "the embedded bundle is STALE: dist/app.js or style.css does not match a rebuild of src/ (run: cd $UI && bun run build)"
    fi
  else
    echo "  note  could not rebuild the bundle to compare; the suite still runs against the embedded one"
  fi
  rm -rf "$FRESH"
else
  echo "  note  bun absent — cannot check whether the embedded bundle matches src/"
fi

# ---- the suite ----------------------------------------------------------------------------------
# The JSON reporter rather than scraping the human one: "17 passed (12s)" is a presentation detail and
# has changed shape across playwright releases, while the JSON stats field is part of its contract.
#
# --line-buffered / sed -u are load-bearing, not tidiness. Without them the whole suite's output sits
# in a pipe buffer and a nine-minute run prints nothing at all until it ends, which is
# indistinguishable from a hang — and the first instinct on a silent run is to kill it.
REPORT="$E2E/artifacts/report.json"
(cd "$E2E" && PLAYWRIGHT_JSON_OUTPUT_NAME="artifacts/report.json" \
  npx playwright test --reporter=list,json) 2>&1 \
  | grep --line-buffered -vE '^\s*$' | sed -u 's/^/  /'

read -r P F S <<<"$(node -e '
const fs = require("node:fs");
try {
  const report = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const s = report.stats ?? {};
  // "unexpected" is playwright for a test that failed; "flaky" passed only on retry, and retries are
  // off in this config, so a nonzero flaky count would itself be a surprise worth failing on.
  process.stdout.write(`${s.expected ?? 0} ${(s.unexpected ?? 0) + (s.flaky ?? 0)} ${s.skipped ?? 0}`);
} catch { process.stdout.write("0 0 0"); }
' "$REPORT")"
rm -f "$REPORT"

if [ "${P:-0}" = "0" ] && [ "${F:-0}" = "0" ]; then
  no "the playwright suite produced no results (did globalSetup fail? its breadcrumbs are above)"
else
  PASS=$((PASS + P))
  FAIL=$((FAIL + F))
  echo "  ----  playwright: $P passed, $F failed, $S skipped"
fi

echo
echo "  screenshots: $E2E/artifacts/screenshots/  report: $E2E/artifacts/report/index.html"
echo "############ $PASS passed, $FAIL failed ############"
[ "$FAIL" -eq 0 ]
