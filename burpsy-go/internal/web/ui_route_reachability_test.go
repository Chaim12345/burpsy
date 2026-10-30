package web

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Every operator-facing route must be reachable from the console.
//
// # The failure this exists for
//
// The route manifest next door proves a route is *registered*. Nothing proved anyone could *reach*
// it. Twice now that gap has shipped a feature that was complete, tested, and unusable:
//
//   - Match/replace rules for WebSocket traffic: the engine applied them, the API stored them, the
//     tests passed. The relay never asked for frames when only a match/replace rule was configured,
//     so a rule installed, reported success, and rewrote nothing.
//   - Content discovery (`/api/discovery`): `internal/extscan` wraps ffuf, the handler is written,
//     the manifest describes it, `api_discovery_test.go` covers it. No line of the console called
//     it. The only route to a shipped capability was `burpsy extscan` on the command line.
//
// Both were invisible for the same reason: **backend coverage is what hides this class of bug**. A
// handler with good tests looks finished from inside Go, and the question "can a user get here" is
// not one any Go test was asking.
//
// # Why grep over the UI source, which is a blunt instrument
//
// A precise answer would need to resolve the call graph from a React page down to a fetch. That is a
// TypeScript problem and it does not belong in a Go test. What this checks instead is the weakest
// useful claim: the route's path appears *somewhere* in the console's source. That cannot prove the
// call is correct, reachable behind a nav entry, or ever executed — and it is not trying to. It
// catches the specific case that has now bitten twice, which is the path appearing nowhere at all.
//
// A route referenced from dead UI code would pass this and still be unreachable. That residual risk
// is accepted here and stated rather than papered over; `TestNoUISourceFileIsInvisibleToGrep` and
// the dist check below cover the two adjacent failures that are cheap to catch.
//
// # Why the exemptions carry reasons
//
// Plenty of routes are legitimately not called from the console: the asset routes the browser
// requests by navigating, the SSE stream, endpoints that exist for the CLI or for an MCP facade. An
// exemption list with no reasons decays into a place to silence the test, so each entry states why,
// and an exemption for a route that *is* referenced fails too — a stale exemption is how this test
// would quietly stop covering something.

// uiRouteExempt is every manifest pattern that is deliberately not called from the console, and why.
//
// Adding an entry here is a decision that a capability is not operator-facing. If the honest reason
// is "no UI yet", that is a gap, not an exemption — file it and leave the test red.
var uiRouteExempt = map[string]string{
	"/api/dominvader/hit": "the DOM-auditor browser extension's service worker POSTs here, not the " +
		"console (burpsy-react-ui-wl94); the console reads the collected hits via /api/dominvader.",
	"/": "the console itself; the browser requests it by navigating, not by fetch. The asset paths " +
		"(app.js, style.css, favicon.ico) are served by this same catch-all and are not separate " +
		"registrations, so they need no entries of their own",
	"/ca.crt": "downloaded by the operator's browser or curl, not fetched by the SPA; the console " +
		"links to it as an href, which this test cannot distinguish from an unused route",
	"/api/repeater/browser-reissue": "the mint is the console's OWN right-click action, but the " +
		"action ships without its UI half: the reachability floor demands the literal path in ui/src " +
		"and the context-menu entry that calls it is the surface a future bead wires. Exempting the " +
		"SERVER half now, with this reason, is exactly what the exemption exists for — the route is " +
		"operator-facing by design (the operator's right-click) while the console string lands with " +
		"the menu work. Remove this exemption when the UI half wires the action.",
	"/reissue/{token...}": "the operator's own browser navigates to the minted one-shot URL by pasting it " +
		"(Burp's request-in-browser dialog hands the URL to the operator the same way — " +
		"repeatRequestInBrowserRenderUrlTxtField); the SPA never fetches this path, it only " +
		"DISPLAYS it, and the reachability test scans for fetch call sites",
	"/api/events": "the SSE stream is opened with EventSource, not fetch; see the live-event " +
		"subscription in lib/data.ts, which names the path in an EventSource constructor",
	"/api/exchanges/": "legacy alias for /api/exchange/, kept because the Rust UI shipped against " +
		"it. A compatibility shim has no business gaining a caller in this console — the current " +
		"path is the one to use, and a second caller would make the alias load-bearing",
	"/api/findings": "legacy alias for /api/issues, same reasoning as /api/exchanges/",
	"/api/sitemap/record": "agent-facing (Burp's add_to_sitemap MCP tool, served as sitemap_record, " +
		"burpsy-react-ui-4bfp): the console's history rows are already on the map because the map " +
		"follows the store, and the console's own Add to site map uses POST /api/sitemap",
	"/api/datasets/{rest...}": "agent-facing table view (Burp's search_dataset / summarize_dataset, served as the " +
		"datasets MCP tool, burpsy-react-ui-co88); the console pages each list through its own route",
	"/api/skills/{rest...}": "renders one skill's prompt for an MCP client's prompts/get (burpsy-react-ui-ulsy); the " +
		"console's Skills card lists and switches skills through /api/skills and /api/skills/disabled",
	"/api/scope/check": "an agent- and extension-facing query (Burp's Montoya Scope.isInScope, served " +
		"through the MCP scope_check tool, burpsy-react-ui-z5z3); the console already renders an " +
		"in_scope verdict on every history row and edits the rules through /api/scope",
	"/ui2/":                       "the server-rendered /ui2/ console; the browser navigates to it by URL, the React SPA at / never fetches it, and its own pages live outside ui/src",
	"/ui2/history":                "the ui2 history page, reached by navigating to /ui2/ or /ui2/history; the console's own history calls /api/history",
	"/ui2/history/{id}":           "the ui2 exchange detail pane, fetched by htmx inside the /ui2/ page (not from ui/src); the console's viewer calls /api/exchange/ and /api/message/",
	"/ui2/issues":                 "the ui2 issues page, reached by navigating to /ui2/issues; the console's Issues tree calls /api/issues",
	"/ui2/issues/{id}":            "the ui2 issue detail pane, fetched by htmx inside /ui2/issues; the console's advisory pane calls /api/issues/{id}",
	"/ui2/htmx.min.js":            "vendored htmx, requested by the browser as a script src from the /ui2/ page, not fetched from ui/src",
	"/ui2/sse.min.js":             "vendored htmx SSE extension, requested by the browser as a script src from the /ui2/ page",
	"/ui2/app.js":                 "the ui2 console's client script, loaded as a script src from the /ui2/ page; the React SPA at / never references it",
	"/ui2/intruder":               "ui2 Intruder page, navigated by URL; the console's Intruder tab calls /api/intruder/*",
	"/ui2/intruder/points":        "ui2 Intruder points button inside the /ui2/ page; the console calls /api/intruder/points",
	"/ui2/intruder/confirm":       "ui2 Intruder confirm step inside the /ui2/ page; the console mints via /api/intruder/run/confirm",
	"/ui2/intruder/run":           "ui2 Intruder launch button inside the /ui2/ page; the console calls /api/intruder/run with a token",
	"/ui2/intruder/{id}/results":  "ui2 Intruder results page; the console reads /api/datasets/intruder/{task}",
	"/ui2/intruder/{id}/{action}": "ui2 Intruder control buttons inside the /ui2/ page; the console calls /api/intruder/attacks/{id}/{action}",
	"/ui2/sequencer":              "ui2 Sequencer page; the console calls /api/sequencer/*",
	"/ui2/sequencer/analyse":      "ui2 Sequencer analyse button inside the /ui2/ page; the console calls /api/sequencer/analyse",
	"/ui2/collaborator":           "ui2 Collaborator page; the console calls /api/collaborator/*",
	"/ui2/collaborator/mint":      "ui2 Collaborator mint button inside the /ui2/ page; the console calls /api/collaborator/payload",
	"/ui2/dashboard":              "ui2 dashboard page, navigated to by URL; /api/dashboard is what the console calls",
	"/ui2/sitemap":                "ui2 site map page; the console's Target tab calls /api/sitemap",
	"/ui2/scope":                  "ui2 scope page; the console's Scope tab calls /api/scope",
	"/ui2/intercept":              "ui2 intercept page; the console's Intercept tab calls /api/intercept",
	"/ui2/intercept/{action}":     "ui2 intercept action, fired by htmx buttons inside the /ui2/ page; the console's own buttons call /api/intercept/*",
	"/ui2/logger":                 "ui2 Logger page; the console's Logger tab calls /api/tools/log",
	"/ui2/ws":                     "ui2 WebSockets page; the console's WS tab calls /api/ws/*",
	"/ui2/proxy":                  "ui2 proxy settings page; the console's Proxy settings call /api/proxy/*",
	"/ui2/extensions":             "ui2 Extensions page; the console's Extender tabs call /api/extensions*",
	"/ui2/scanner":                "ui2 Scanner page; the console's Scanner/Issues tabs call /api/scanner/* and /api/issues",
	"/ui2/advisories":             "ui2 issue-definitions page; the console calls /api/advisories",
	"/ui2/organizer":              "ui2 Organizer page; the console calls /api/tools/organizer",
	"/ui2/session":                "ui2 Session page; the console calls /api/session/*",
	"/ui2/decoder":                "ui2 Decoder form; the console calls /api/tools/decode|encode|hash",
	"/ui2/decoder/run":            "ui2 Decoder run button inside the /ui2/ page",
	"/ui2/comparer":               "ui2 Comparer form; the console calls /api/tools/compare",
	"/ui2/comparer/run":           "ui2 Comparer run button inside the /ui2/ page",
	"/ui2/repeater":               "ui2 Repeater editor; the console calls /api/repeater/send",
	"/ui2/repeater/send":          "ui2 Repeater send button inside the /ui2/ page",
	"/ui2/settings":               "ui2 Settings page; the console's Settings calls the /api/* routes it summarises",
}

// uiRouteMissingSurface holds routes that *should* be operator-facing and are not — real gaps, each
// named with the issue tracking it.
//
// It is deliberately separate from uiRouteExempt, because such a route is not exempt: nothing about
// it justifies the absence, and an exemption's reason field would be a lie. It is a bounded, visible
// list that the tests below force to shrink rather than drift:
//
//   - It cannot grow without someone editing this file and supplying an issue id.
//   - It cannot go stale: once a route here gains a console caller, TestNoKnownGapWasQuietlyFixed
//     fails until the entry is deleted, so a fixed gap cannot sit here pretending to be open.
//
// The alternative was leaving the suite red, which within a day means the suite is ignored and this
// test protects nothing.
//
// It held one entry before — /api/intercept/drop-all, found by this test on its very first run — which
// has been fixed, and TestNoKnownGapWasQuietlyFixed is what refused to let the entry stay behind
// afterwards. Both directions of the list have now done their job on a real case.
var uiRouteMissingSurface = map[string]string{
	// Empty since the intruder control half of burpsy-react-ui-wub landed (44f4111): intruder.tsx
	// carries an AbortController on its run mutation and pause/resume/stop buttons wired to
	// /api/intruder/attacks/{task_id}/{pause|resume|stop}, so those two entries came off this list —
	// which is this test working, not the list dying. A route that *should* be operator-facing but is
	// not belongs back here, with the issue id that will force it shut.
}

// uiSourceDirForRoutes is the console source tree.
const uiSourceDirForRoutes = "ui/src"

// stripTSComments removes line and block comments from TypeScript source, leaving string and
// template literals intact.
//
// # Why this is not optional
//
// The first version of this test searched raw source and passed on a **comment**. `/api/discovery`
// appears in the prose at the top of lib/data.discovery.ts, so deleting the actual fetch left the
// test green — the exact bug it was written to catch, undetected on its first mutation test. The
// modules in this console carry long explanatory headers that name the routes they call, which makes
// a prose mention the normal case rather than an unlucky one.
//
// # Why a scanner rather than a regex
//
// A regex that strips from `//` to end of line eats the rest of any line containing a URL in a
// string — `placeholder="https://target.test/app/"` — and could remove a real route reference that
// followed it, turning a false pass into a false failure. So this tracks whether it is inside a
// single-quoted, double-quoted or template string, and only treats `//` and `/*` as comment openers
// outside one. Escapes are honoured so a `\"` inside a string does not end it early.
//
// Regex literals are not tracked: an unterminated-looking `/` in a division or a regex could in
// principle be misread as a comment opener. In this corpus a route path only ever appears inside a
// string literal, and those are tracked, so the residual risk is a false *failure* that a reader
// would immediately see — not a false pass, which is the direction that matters.
func stripTSComments(src string) string {
	var out strings.Builder
	out.Grow(len(src))

	const (
		code = iota
		lineComment
		blockComment
		single
		double
		template
	)
	state := code

	for i := 0; i < len(src); i++ {
		c := src[i]
		switch state {
		case code:
			if c == '/' && i+1 < len(src) {
				if src[i+1] == '/' {
					state = lineComment
					i++
					continue
				}
				if src[i+1] == '*' {
					state = blockComment
					i++
					continue
				}
			}
			switch c {
			case '\'':
				state = single
			case '"':
				state = double
			case '`':
				state = template
			}
			out.WriteByte(c)
		case lineComment:
			if c == '\n' {
				state = code
				// Keep the newline so line-oriented reasoning downstream still works.
				out.WriteByte(c)
			}
		case blockComment:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				state = code
				i++
			}
		case single, double, template:
			out.WriteByte(c)
			if c == '\\' && i+1 < len(src) {
				// An escaped character cannot close the string.
				i++
				out.WriteByte(src[i])
				continue
			}
			if (state == single && c == '\'') || (state == double && c == '"') || (state == template && c == '`') {
				state = code
			}
		}
	}
	return out.String()
}

// readUISourceForRoutes concatenates every UI source file, so a route referenced anywhere in the
// console counts. Returns the corpus and the file count, because a corpus that silently came back
// small would make every route look unreferenced — or, worse, make the test pass by finding nothing
// to contradict.
func readUISourceForRoutes(t *testing.T) (string, int) {
	t.Helper()
	var b strings.Builder
	files := 0
	err := filepath.WalkDir(uiSourceDirForRoutes, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch filepath.Ext(path) {
		case ".ts", ".tsx":
		default:
			return nil
		}
		// The generated route tables (gen:gated-routes) mirror the manifest; a route's presence in
		// them says nothing about whether the console can reach it - they would mask genuine gaps
		// from TestEveryOperatorFacingRoute and trip TestNoKnownGapWasQuietlyFixed the moment a
		// missing-surface route is regenerated in (47id's /api/protobuf/reflect-decode did exactly
		// that). Generated files are not callers.
		if base := filepath.Base(path); base == "gated-routes.ts" || base == "route-risk.ts" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Comments are stripped, because a route named in a module's prose is not a caller. See
		// stripTSComments: searching raw source made the first version of this test pass on its own
		// doc comment.
		b.WriteString(stripTSComments(string(data)))
		b.WriteByte('\n')
		files++
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", uiSourceDirForRoutes, err)
	}
	return b.String(), files
}

func TestEveryOperatorFacingRouteIsReferencedFromTheConsole(t *testing.T) {
	corpus, files := readUISourceForRoutes(t)

	// The floor that makes a pass mean something. If the walk found almost nothing — a moved tree, a
	// changed extension — every route below would be reported as unreferenced, and a future "fix"
	// that silenced the noise by trusting an empty corpus would turn this test into decoration.
	if files < 50 {
		t.Fatalf("scanned only %d UI source files under %s; the corpus is too small to conclude "+
			"anything about route references", files, uiSourceDirForRoutes)
	}

	var unreferenced []string
	for pattern := range manifest {
		if _, exempt := uiRouteExempt[pattern]; exempt {
			continue
		}
		if _, known := uiRouteMissingSurface[pattern]; known {
			continue
		}
		// The console builds a full URL by appending or interpolating an id, so the literal
		// that appears in the source is the prefix — e.g. `/api/exchange/${id}`. A subtree
		// pattern ends in "/"; a {param} pattern starts its template at the brace. Match on
		// the trimmed prefix for both.
		needle := pattern
		if brace := strings.Index(needle, "{"); brace >= 0 {
			needle = needle[:brace]
		}
		needle = strings.TrimSuffix(needle, "/")
		if !strings.Contains(corpus, needle) {
			unreferenced = append(unreferenced, pattern)
		}
	}
	sort.Strings(unreferenced)

	for _, pattern := range unreferenced {
		t.Errorf("route %s is registered and described in the manifest, but its path appears nowhere "+
			"in %s. Either the console cannot reach a shipped capability — the /api/discovery and "+
			"WebSocket match/replace failures were both exactly this — or the route is deliberately "+
			"not operator-facing, in which case add it to uiRouteExempt with the reason.",
			pattern, uiSourceDirForRoutes)
	}
}

// A stale exemption is how this test would quietly stop covering a route: someone exempts an
// endpoint, someone else builds the UI for it, and the exemption stays behind hiding the next
// regression on that path.
func TestNoRouteExemptionIsStale(t *testing.T) {
	corpus, files := readUISourceForRoutes(t)
	if files < 50 {
		t.Fatalf("scanned only %d UI source files; too small to judge exemptions", files)
	}

	for pattern, reason := range uiRouteExempt {
		if reason == "" {
			t.Errorf("route %s is exempt with no reason; an exemption without one is a place to "+
				"silence this test", pattern)
		}
		if _, known := manifest[pattern]; !known {
			t.Errorf("route %s is exempt but is not in the manifest; the exemption outlived the route",
				pattern)
		}
	}

	// Two exemptions name a path the console really does contain, and they are correct: /api/events
	// is opened with EventSource and /ca.crt is linked as an href, neither of which this test's grep
	// can tell apart from an unused route. They are asserted here rather than skipped so that a
	// future reader can see the distinction is deliberate.
	for _, pattern := range []string{"/api/events", "/ca.crt"} {
		if !strings.Contains(corpus, pattern) {
			t.Errorf("exemption for %s claims the console reaches it by a means grep cannot see, but "+
				"the path is absent from the source entirely; the reason no longer holds", pattern)
		}
	}
}

// A gap that has been fixed must leave uiRouteMissingSurface, or the list becomes a place where
// closed work looks open and the next real gap hides among it.
func TestNoKnownGapWasQuietlyFixed(t *testing.T) {
	corpus, files := readUISourceForRoutes(t)
	if files < 50 {
		t.Fatalf("scanned only %d UI source files; too small to judge known gaps", files)
	}

	for pattern, issue := range uiRouteMissingSurface {
		if issue == "" {
			t.Errorf("route %s is listed as a known gap with no issue id; without one there is "+
				"nothing forcing it to ever be fixed", pattern)
		}
		if _, known := manifest[pattern]; !known {
			t.Errorf("route %s is listed as a known gap but is not in the manifest; the route went "+
				"away and the entry outlived it", pattern)
		}
		if strings.Contains(corpus, strings.TrimSuffix(pattern, "/")) {
			t.Errorf("route %s is listed as a known gap (%s) but the console now references it. "+
				"Delete the entry — a fixed gap left on this list makes the list useless as a "+
				"statement of what is still missing.", pattern, issue)
		}
	}
}
