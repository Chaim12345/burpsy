package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The route manifest.
//
// # Why this exists
//
// `setupRoutes` is 49 `mux.HandleFunc` calls in one function, and until now nothing checked it. A
// route deleted or renamed in a refactor produced a 404 in production — discovered by an operator
// clicking something that used to work, with no test going red anywhere. That is a bad failure for a
// surface the UI is written against, and a worse one for the API surface this port is in the middle of
// tripling: an area that adds eight routes and drops one on merge would ship silently.
//
// So the expected set lives here, as data, with a one-line descriptor per route. A dropped
// registration now fails `Test_every_registered_route_is_in_the_manifest` **by name**, which tells the
// next reader what broke instead of leaving them to bisect a 404.
//
// # Why it is parsed out of the source rather than read off the mux
//
// `http.ServeMux` has no API to enumerate its patterns — not in 1.22's rewrite either. The three
// alternatives were: wrap HandleFunc in a recording helper (invasive, and a route registered directly
// would escape the recorder — exactly the case this test is for); probe every path in the manifest and
// check it does not 404 (proves the manifest's routes exist, but cannot notice a route that exists and
// is *not* in the manifest); or read the registrations out of the source. The third is the only one
// that catches both directions, so `setupRoutes` is parsed with go/ast.
//
// This is not as fragile as it sounds: it walks the AST for calls whose selector is `HandleFunc` and
// takes their first argument when it is a string literal, so reformatting, reordering and comment
// changes are all invisible to it. What it would miss is a pattern built at runtime from a variable —
// and `Test_every_route_pattern_is_a_literal` fails if anyone introduces one, rather than letting the
// manifest quietly stop covering it.
//
// # What a descriptor is for
//
// `summary` is documentation. `methods` is what the 405 test drives. `risk` is the field MCP-02 needs:
// scope-widening, attack-launching and credential-reading calls require per-call operator confirmation
// when driven by a model rather than by a human clicking, and the only place that can be declared
// without every future facade re-deciding it is next to the route.

// riskClass says what an unattended caller can do with a route. Declared per route so one shared
// server-side check can enforce confirmation, rather than 21 facades each deciding for themselves.
type riskClass string

const (
	// riskRead reads state and sends nothing outbound.
	riskRead riskClass = "read"
	// riskLocal mutates burpsy's own state — annotations, rules, settings — without sending traffic.
	riskLocal riskClass = "local-write"
	// riskEgress sends traffic to the engagement target. Bounded: one request, or a handful.
	riskEgress riskClass = "egress"
	// riskAttack sends unbounded traffic: an attack, an audit, a crawl, a capture. The class MCP-02
	// requires confirmation for, because a model that miscounts here is a denial of service against a
	// client's production system.
	riskAttack riskClass = "attack"
	// riskScope changes what the engagement is allowed to touch. Confirmation-worthy for the opposite
	// reason to riskAttack: it does not send anything itself, it removes the thing that says no.
	riskScope riskClass = "scope"
	// riskCredential reads or replays credentials — the cookie jar, session macros. Confirmation-worthy
	// because the output is secret, not because the call is dangerous.
	riskCredential riskClass = "credential"
	// riskDestructive irreversibly discards evidence.
	//
	// This class was added because writing the manifest found a route nobody had classified:
	// `DELETE /api/tools/log` answers {"cleared": true} and wipes the record of every request this
	// process has sent. On an engagement that log is the answer to "what did you send to my
	// production system", so losing it is not the same kind of act as clearing a filter box — and
	// riskLocal, which is what it would otherwise have been folded into, is defined as writing
	// burpsy's own state and is exactly the wrong shape for it. Discovered by
	// Test_every_route_rejects_a_verb_it_does_not_implement, which is the whole argument for having
	// a manifest: the verb was reachable, undocumented, and destructive.
	riskDestructive riskClass = "destructive"
	// riskAsset serves a static asset (the UI, the CA certificate).
	riskAsset riskClass = "asset"
)

// route is one registered pattern and what it accepts.
type route struct {
	// methods is every verb the handler answers. The 405 test derives the disallowed set from it, so
	// an entry that overstates this weakens a real check — keep it exact.
	methods []string
	summary string
	risk    riskClass
	// subPath is a concrete path under a subtree pattern, for the routes registered with a trailing
	// slash. Required for those, because the pattern itself is not a requestable URL: "/api/audit/"
	// with no id is not what any caller sends, and testing the bare prefix would exercise a branch no
	// operator reaches.
	subPath string
	// pathValidatedFirst marks a handler that resolves its path segment *before* checking the method,
	// so a bogus segment answers 404 rather than 405 whatever the verb. Correct behaviour — "there is
	// no such direction" is a truer answer than "wrong verb" — but it means the 405 test has to send a
	// valid segment, which is what subPath supplies.
	pathValidatedFirst bool
}

// manifest is every route this server registers. Keep it sorted by pattern; the test enforces that,
// because a 49-entry map that is not sorted is a merge conflict generator.
var manifest = map[string]route{
	"/": {
		methods: []string{"GET"}, risk: riskAsset,
		summary: "the operator console: index.html, app.js, style.css, and the SPA catch-all",
	},
	"/api/audit/": {
		methods: []string{"POST"}, risk: riskAttack, subPath: "0",
		summary: "run an active audit over one captured exchange, by id (0 is valid — see HONEST-05)",
	},
	"/api/config/export": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "one JSON bundle of every configurable surface: scope, intercept rules, session handling rules",
	},
	// Import rewrites what the engagement may touch — the bundle carries scope — so it shares
	// /api/scope's confirmation-worthy class rather than sitting with ordinary writes.
	// /api/scanner/config joins it: flipping audit families mid-engagement changes what the
	// scanner is allowed to send, which is the same class of decision.
	"/api/config/import": {
		methods: []string{"POST"}, risk: riskScope,
		summary: "apply a configuration bundle; a bundle with any invalid rule is refused without applying any part",
	},
	"/api/crawl": {
		// GET reports the last crawl's coverage report; POST starts one.
		methods: []string{"GET", "POST"}, risk: riskAttack,
		summary: "GET: the last crawl's coverage report. POST: crawl from a seed URL under stated bounds",
	},
	"/api/dashboard": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "running tasks, the activity log, and every coverage summary with its breakdown",
	},
	"/api/events": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "SSE change stream; the UI refetches on a frame rather than polling",
	},
	"/api/events/stats": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "the stream's own counters: frames sent, subscribers, coalesced signals",
	},
	"/api/exchange/": {
		methods: []string{"GET", "PATCH"}, risk: riskLocal, subPath: "0",
		summary: "one exchange row by id; PATCH sets its notes and/or highlight (UX-15)",
	},
	"/api/exchanges/": {
		methods: []string{"GET"}, risk: riskRead, subPath: "0",
		summary: "legacy alias for /api/exchange/ — kept because the Rust UI shipped against it",
	},
	"/api/findings": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "legacy alias for /api/issues",
	},
	"/api/history": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "proxy history, filtered by the typed query DSL",
	},
	"/api/http2/program": {
		methods: []string{"POST"}, risk: riskEgress,
		summary: "send a raw HTTP/2 frame program: the pseudo-header and frame-level surface",
	},
	"/api/intercept": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "interception state: enabled, wired, and what is currently held",
	},
	"/api/intercept/": {
		// POST only, and this is also the catch-all under /api/intercept — see the note in setupRoutes
		// about preserving handleInterceptHeld's breadth through the Phase 1 ServeMux migration.
		methods: []string{"POST"}, risk: riskLocal, subPath: "1",
		summary: "resolve one held message: forward, drop, or forward edited bytes",
	},
	"/api/intercept/drop-all": {
		methods: []string{"POST"}, risk: riskLocal,
		summary: "drop every held message in one round trip; answers the count actually dropped",
	},
	"/api/intercept/enable": {
		methods: []string{"POST"}, risk: riskLocal,
		summary: "turn interception on or off",
	},
	"/api/intercept/rules/": {
		// "requests" and "responses", plural — see directionFor. The singular was a guess when this
		// entry was first written, and it answered 404 "Unknown direction" for every verb, which the
		// 405 test read as a missing guard. The handler was right; the manifest was wrong.
		methods: []string{"GET", "PUT"}, risk: riskLocal, subPath: "requests",
		pathValidatedFirst: true,
		summary:            "the match rules deciding which messages are held, per direction",
	},
	"/api/intruder/points": {
		methods: []string{"POST"}, risk: riskRead,
		summary: "enumerate insertion points in a stored request; sends nothing",
	},
	"/api/intruder/run": {
		methods: []string{"POST"}, risk: riskAttack,
		summary: "run an intruder attack: payloads spliced into one insertion point set",
	},
	"/api/issues": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "findings, with the catalogue advisory each resolved to",
	},
	"/api/message/": {
		methods: []string{"GET"}, risk: riskRead, subPath: "0",
		summary: "raw bytes of one stored message, with pretty and hex views",
	},
	"/api/protocols": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "per-surface HTTP/1.1 vs HTTP/2 counts, and why a send was downgraded",
	},
	"/api/proxy/passthrough": {
		methods: []string{"GET", "POST", "DELETE"}, risk: riskLocal,
		summary: "the TLS passthrough host-pattern list, live: add and remove without restarting the proxy",
	},
	"/api/repeater/send": {
		methods: []string{"POST"}, risk: riskEgress,
		summary: "send one operator-authored request and record the exchange",
	},
	"/api/report/": {
		methods: []string{"GET"}, risk: riskRead, subPath: "json",
		summary: "export findings as json, sarif or html",
	},
	"/api/scanner/audit": {
		methods: []string{"POST"}, risk: riskAttack,
		summary: "legacy alias for /api/audit/{id}, taking the id in the body",
	},
	"/api/scanner/config": {
		methods: []string{"GET", "PUT"}, risk: riskScope,
		summary: "the audit families and performance knobs, readable and editable while the process runs; PUT persists the overrides",
	},
	"/api/scanner/configs": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "the built-in scan configurations, generated from the table rather than listed by hand",
	},
	"/api/scanner/coverage": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "what the check set covers, and what it declines to look at",
	},
	"/api/scanner/live": {
		methods: []string{"GET", "POST"}, risk: riskAttack,
		summary: "the live sweep over newly-completed proxied traffic; POST opts in",
	},
	"/api/scope": {
		methods: []string{"GET", "POST"}, risk: riskScope,
		summary: "the engagement scope: what every sender is allowed to reach",
	},
	"/api/sequencer/analyse": {
		methods: []string{"POST"}, risk: riskRead,
		summary: "statistical analysis of a token sample; sends nothing",
	},
	"/api/sequencer/capture": {
		methods: []string{"POST"}, risk: riskAttack,
		summary: "start a capture: N sends of one request, one token extracted per response",
	},
	"/api/sequencer/capture/": {
		// Two operations under one subtree, and deliberately different verbs: reading a token list does
		// not change state, stopping a capture does. Unguarded, `GET .../stop` answered {"stopped":true}
		// — a state change reported for a request that could not have caused one.
		methods: []string{"GET", "POST"}, risk: riskRead, subPath: "1",
		summary: "GET {id}: one capture's accumulated tokens. POST stop: cancel a running capture",
	},
	"/api/session/cookies": {
		methods: []string{"GET"}, risk: riskCredential,
		summary: "the coordinator's cookie jar, per authority (see HONEST-03)",
	},
	"/api/session/login": {
		methods: []string{"POST"}, risk: riskCredential,
		summary: "run a login macro, or probe whether the current session is still valid",
	},
	"/api/session/rules": {
		methods: []string{"GET", "POST"}, risk: riskCredential,
		summary: "session handling rules: which hosts get re-authenticated, and how",
	},
	"/api/session/rules/": {
		// PUT and DELETE only. The collection route below is where GET and POST live.
		methods: []string{"PUT", "DELETE"}, risk: riskCredential, subPath: "1",
		summary: "one session rule by id: PUT replaces it (including macro promotion), DELETE removes it",
	},
	"/api/sitemap": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "the site map as a real tree, with per-subtree exchange counts",
	},
	"/api/stats": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "proxy counters, tool counts, and the DOM engine's admission state",
	},
	"/api/tasks/": {
		methods: []string{"POST"}, risk: riskLocal, subPath: "{id}/cancel",
		summary: "POST {id}/cancel: ask a running task to stop; an unknown or finished id answers 404",
	},
	"/api/tools/compare": {
		methods: []string{"POST"}, risk: riskRead,
		summary: "diff two messages or two pasted buffers",
	},
	"/api/tools/decode": {
		methods: []string{"POST"}, risk: riskRead,
		summary: "run one decode layer over a buffer, reporting whether it was partial",
	},
	"/api/tools/encode": {
		methods: []string{"POST"}, risk: riskRead,
		summary: "run one encode layer over a buffer",
	},
	"/api/tools/hash": {
		methods: []string{"POST"}, risk: riskRead,
		summary: "hash a buffer under a named algorithm",
	},
	"/api/tools/log": {
		// DELETE clears the whole log, which nothing documented and nothing had classified until the
		// 405 test found the verb reachable. See riskDestructive.
		methods: []string{"GET", "DELETE"}, risk: riskDestructive,
		summary: "GET: every request this process sent, per tool, with what it dropped at the bound. " +
			"DELETE: clears it, discarding the record of what was sent to the target",
	},
	"/api/tools/organizer": {
		methods: []string{"GET", "POST"}, risk: riskLocal,
		summary: "the organizer's saved items",
	},
	"/api/tools/organizer/": {
		// POST updates and DELETE removes. Not GET, and not PUT — both of which this entry originally
		// guessed at. Worth recording because POST-to-update is unusual enough that a reader would
		// expect PUT, and the 405 test is what settled it.
		methods: []string{"POST", "DELETE"}, risk: riskLocal, subPath: "1",
		summary: "one organizer item by id: POST updates title/note/highlight, DELETE removes it",
	},
	"/api/tools/rules": {
		// PUT, not POST: the whole rule set is replaced as a document rather than appended to, which is
		// the right shape for a list whose order is its semantics.
		methods: []string{"GET", "PUT"}, risk: riskLocal,
		summary: "match & replace rules applied to proxied traffic; PUT replaces the whole set",
	},
	"/api/tools/rules/test": {
		methods: []string{"POST"}, risk: riskRead,
		summary: "dry-run the match & replace set against a buffer without installing it",
	},
	"/api/ws/connections": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "WebSocket connections the proxy has relayed",
	},
	"/api/ws/history": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "WebSocket frames, per connection",
	},
	"/api/ws/message/": {
		methods: []string{"GET"}, risk: riskRead, subPath: "1",
		summary: "one WebSocket frame's payload, as text or hex",
	},
	"/ca.crt": {
		methods: []string{"GET"}, risk: riskAsset,
		summary: "the CA certificate the proxy signs leaves with, so a browser can be told to trust it",
	},
}

// registeredPatterns parses setupRoutes and returns every pattern it registers, plus every call whose
// pattern was not a string literal. See the file comment for why this is read out of the source.
func registeredPatterns(t *testing.T) (literal []string, nonLiteral int) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "server.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse server.go: %v", err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "HandleFunc" || len(call.Args) == 0 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			nonLiteral++
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil {
			nonLiteral++
			return true
		}
		literal = append(literal, pattern)
		return true
	})
	return literal, nonLiteral
}

func Test_every_registered_route_is_in_the_manifest(t *testing.T) {
	patterns, _ := registeredPatterns(t)
	if len(patterns) == 0 {
		t.Fatal("parsed no routes out of server.go; the AST walk is broken, not the routing")
	}
	seen := make(map[string]bool, len(patterns))
	for _, pattern := range patterns {
		seen[pattern] = true
		if _, ok := manifest[pattern]; !ok {
			t.Errorf("route %q is registered but has no manifest entry.\n"+
				"Add one: what it does, which verbs it answers, and its risk class — the risk class is "+
				"what decides whether an unattended caller has to confirm before invoking it.", pattern)
		}
	}
	// The other direction, and the reason this test is worth having: a route dropped in a refactor
	// used to surface as a 404 that an operator found by clicking something that had worked.
	for pattern := range manifest {
		if !seen[pattern] {
			t.Errorf("route %q is in the manifest but nothing registers it. Either setupRoutes lost a "+
				"HandleFunc call, or the route was deliberately removed and this entry should go with it.",
				pattern)
		}
	}
	// Registered twice would panic at startup, so this can only fire if the panic is ever relaxed —
	// but the duplicate is worth naming here rather than debugging as a boot crash.
	counts := map[string]int{}
	for _, pattern := range patterns {
		counts[pattern]++
	}
	for pattern, n := range counts {
		if n > 1 {
			t.Errorf("route %q is registered %d times; http.ServeMux panics on this", pattern, n)
		}
	}
}

// A pattern built from a variable would be invisible to the manifest, so it is refused rather than
// silently uncovered. If a future area genuinely needs one, this test is the place to decide how the
// manifest represents it — not the place to delete.
func Test_every_route_pattern_is_a_literal(t *testing.T) {
	_, nonLiteral := registeredPatterns(t)
	if nonLiteral > 0 {
		t.Errorf("%d route(s) registered with a non-literal pattern; the manifest cannot cover those",
			nonLiteral)
	}
}

// Sorted, because an unsorted 49-entry literal is a merge-conflict generator: two areas appending
// their routes at the end of a map both touch the same line.
func Test_the_manifest_is_sorted_by_pattern(t *testing.T) {
	got := make([]string, 0, len(manifest))
	for pattern := range manifest {
		got = append(got, pattern)
	}
	// The manifest is a map, so source order is not observable at runtime — the source itself is what
	// has to be ordered. Read it back and check the entries appear in sorted order.
	sorted := append([]string(nil), got...)
	sort.Strings(sorted)
	source, err := parser.ParseFile(token.NewFileSet(), "route_manifest_test.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse this file: %v", err)
	}
	var inSource []string
	ast.Inspect(source, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		if lit, ok := kv.Key.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if pattern, err := strconv.Unquote(lit.Value); err == nil && strings.HasPrefix(pattern, "/") {
				inSource = append(inSource, pattern)
			}
		}
		return true
	})
	if len(inSource) != len(manifest) {
		t.Skipf("found %d '/'-prefixed keys in source against %d manifest entries; ordering not checked",
			len(inSource), len(manifest))
	}
	if !sort.StringsAreSorted(inSource) {
		for i := 1; i < len(inSource); i++ {
			if inSource[i-1] > inSource[i] {
				t.Errorf("manifest is out of order: %q precedes %q", inSource[i-1], inSource[i])
			}
		}
	}
}

// allMethods is every verb the 405 test may send. TRACE and CONNECT are left out: neither is something
// a caller sends to this API, and CONNECT has a meaning to the proxy that has nothing to do with here.
var allMethods = []string{
	http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
	http.MethodPatch, http.MethodDelete, http.MethodOptions,
}

// Every route answers 405 to a verb it does not implement.
//
// Table-driven over the manifest, so a new route gets this check by existing rather than by its author
// remembering. The class it protects against is small but real: a handler with no verb guard decodes a
// GET's absent body and answers "Invalid request body" — a complaint about the payload for what is
// actually a wrong-method call, which sends the caller looking in the wrong place. Two routes were in
// that state (handleIntruderPoints, handleSequencerCapture) before this test existed.
//
// Phase 1's migration to Go 1.22 `"POST /api/..."` patterns makes the whole class unrepresentable. At
// that point this test stops being a check on handler discipline and becomes a check on the manifest's
// accuracy, which is still worth running.
func Test_every_route_rejects_a_verb_it_does_not_implement(t *testing.T) {
	// s is built once and shared by every subtest below, unlike everywhere else in this package where
	// a fresh server per test is the correct choice. Building a full Server (routes, sitemap,
	// dashboard registries, ...) once instead of once per (route, disallowed verb) pair is what turns
	// this table's ~190 cases from a quadratic cost into a linear one.
	//
	// What makes that safe, stated accurately: the subtests here are sequential - none calls
	// t.Parallel() - and every 405 in this package comes from a hand-written verb guard inside the
	// handler, which in each case precedes any state mutation. It is NOT true that ServeMux rejects a
	// wrong verb before the handler runs; this package does not use Go 1.22 method patterns
	// ("POST /api/..."), as the note above about that migration being future work says. An earlier
	// version of this comment claimed the structural guarantee, which would have been the better
	// reason had it existed - and will be, once those patterns land.
	s := newTestServer()
	for pattern, spec := range manifest {
		// The UI catch-all deliberately serves the SPA for anything it does not recognise, so it has no
		// wrong-verb answer to give. Asserting one would be asserting a behaviour nobody wants.
		if pattern == "/" {
			continue
		}
		allowed := make(map[string]bool, len(spec.methods))
		for _, method := range spec.methods {
			allowed[method] = true
		}
		// HEAD follows GET through net/http, so a GET route answering a HEAD is correct rather than a
		// missing guard. OPTIONS is left alone for the same reason: no route here implements CORS
		// preflight, and 405 for it is fine, but so is anything else.
		if allowed[http.MethodGet] {
			allowed[http.MethodHead] = true
		}

		path := pattern
		if spec.subPath != "" {
			path = pattern + spec.subPath
		}
		for _, method := range allMethods {
			if allowed[method] || method == http.MethodOptions {
				continue
			}
			t.Run(method+" "+path, func(t *testing.T) {
				req := httptest.NewRequest(method, path, nil)
				rec := httptest.NewRecorder()
				s.mux.ServeHTTP(rec, req)
				if rec.Code != http.StatusMethodNotAllowed {
					t.Errorf("%s %s answered %d, want 405.\nEither the handler is missing a verb guard, "+
						"or the manifest's methods list for %q is wrong — check which before changing either.\n"+
						"body: %s", method, path, rec.Code, pattern, strings.TrimSpace(rec.Body.String()))
				}
			})
		}
	}
}

// Every route declares a risk class, and a summary that says what it does.
//
// This is the field MCP-02 needs: a model driving this API unattended must confirm before widening
// scope, launching an attack or reading credentials, and one shared server-side check can only enforce
// that if the declaration exists on every route. An empty risk class on a new route would make it
// invisible to that check — which is the failure mode where the confirmation gate looks like it covers
// everything and quietly does not.
func Test_every_route_declares_a_risk_class_and_a_summary(t *testing.T) {
	valid := map[riskClass]bool{
		riskRead: true, riskLocal: true, riskEgress: true, riskAttack: true,
		riskScope: true, riskCredential: true, riskAsset: true, riskDestructive: true,
	}
	for pattern, spec := range manifest {
		if !valid[spec.risk] {
			t.Errorf("route %q has risk class %q, which is not one of the declared classes", pattern, spec.risk)
		}
		if strings.TrimSpace(spec.summary) == "" {
			t.Errorf("route %q has no summary", pattern)
		}
		if len(spec.methods) == 0 {
			t.Errorf("route %q lists no methods, so nothing can be asserted about it", pattern)
		}
		// A subtree pattern is not a requestable URL: "/api/audit/" with no id is not what any caller
		// sends. Without a concrete segment the 405 test would exercise a branch no operator reaches.
		if strings.HasSuffix(pattern, "/") && pattern != "/" && spec.subPath == "" {
			t.Errorf("route %q is a subtree pattern with no subPath, so it is tested at a URL nobody requests",
				pattern)
		}
	}
}

// Every route that can send unbounded traffic or read a secret is one an unattended caller must
// confirm. Asserted as a set rather than per route so that adding a facade cannot quietly drop one out
// of the confirmation-worthy list — the count is stated, and changing it is a deliberate edit with a
// reason, not a side effect.
func Test_the_confirmation_worthy_routes_are_the_ones_we_think_they_are(t *testing.T) {
	var attack, scope, credential, destructive []string
	for pattern, spec := range manifest {
		switch spec.risk {
		case riskAttack:
			attack = append(attack, pattern)
		case riskScope:
			scope = append(scope, pattern)
		case riskCredential:
			credential = append(credential, pattern)
		case riskDestructive:
			destructive = append(destructive, pattern)
		}
	}
	sort.Strings(attack)
	sort.Strings(scope)
	sort.Strings(credential)
	sort.Strings(destructive)

	wantAttack := []string{
		"/api/audit/", "/api/crawl", "/api/intruder/run", "/api/scanner/audit",
		"/api/scanner/live", "/api/sequencer/capture",
	}
	wantScope := []string{"/api/config/import", "/api/scanner/config", "/api/scope"}
	wantCredential := []string{
		"/api/session/cookies", "/api/session/login", "/api/session/rules", "/api/session/rules/",
	}
	equal := func(name string, got, want []string) {
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s routes are\n  %v\nand this test expects\n  %v\n"+
				"If a route was added, add it here too and say why it belongs in this class. If one was "+
				"reclassified, that is a decision about whether an unattended caller may invoke it without "+
				"asking — make it deliberately.", name, got, want)
		}
	}
	equal("attack", attack, wantAttack)
	equal("scope", scope, wantScope)
	equal("credential", credential, wantCredential)
	equal("destructive", destructive, []string{"/api/tools/log"})
}
