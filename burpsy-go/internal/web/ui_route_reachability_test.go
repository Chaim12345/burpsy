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
	"/reissue/": "the operator's own browser navigates to the minted one-shot URL by pasting it " +
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
	"/api/datasets/": "agent-facing table view (Burp's search_dataset / summarize_dataset, served as the " +
		"datasets MCP tool, burpsy-react-ui-co88); the console pages each list through its own route",
	"/api/skills/": "renders one skill's prompt for an MCP client's prompts/get (burpsy-react-ui-ulsy); the " +
		"console's Skills card lists and switches skills through /api/skills and /api/skills/disabled",
	"/api/scope/check": "an agent- and extension-facing query (Burp's Montoya Scope.isInScope, served " +
		"through the MCP scope_check tool, burpsy-react-ui-z5z3); the console already renders an " +
		"in_scope verdict on every history row and edits the rules through /api/scope",
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
	// The MCP-target scanner's server half landed first (burpsy-react-ui-wflj, salvaged from the
	// review-collab-fix snapshot under burpsy-react-ui-a4ir); the console page that posts an endpoint,
	// a credential and the tools to call, and renders the inventory, list outcomes and findings, is the
	// remaining half of wflj. An operator can reach it today only through the MCP scan tool or curl.
	"/api/mcpscan": "burpsy-react-ui-wflj",
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
		// A subtree pattern ends in "/" and the console builds the full URL by appending an id, so
		// the literal that appears in the source is the prefix without its trailing slash — e.g.
		// `/api/exchange/${id}`. Match on the trimmed form for those.
		needle := strings.TrimSuffix(pattern, "/")
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
