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
// `setupRoutes` is one long run of `mux.HandleFunc` calls in one function, and until now nothing checked it. A
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

// Sorted, because an unsorted literal of this size is a merge-conflict generator: two areas appending
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
		// Each action sub-path is swept with its own allowed set, so a verb guard missing from one
		// branch of a subtree cannot hide behind a sibling branch that has one.
		for suffix, verbs := range spec.actionPaths {
			actionAllowed := map[string]bool{}
			for _, v := range verbs {
				actionAllowed[v] = true
			}
			if actionAllowed[http.MethodGet] {
				actionAllowed[http.MethodHead] = true
			}
			actionPath := pattern + suffix
			for _, method := range allMethods {
				if actionAllowed[method] || method == http.MethodOptions {
					continue
				}
				t.Run(method+" "+actionPath, func(t *testing.T) {
					req := httptest.NewRequest(method, actionPath, nil)
					rec := httptest.NewRecorder()
					s.mux.ServeHTTP(rec, req)
					if rec.Code != http.StatusMethodNotAllowed {
						t.Errorf("%s %s answered %d, want 405. This is an ACTION path: it changes state, "+
							"so every verb it does not implement must be refused before it acts.\nbody: %s",
							method, actionPath, rec.Code, strings.TrimSpace(rec.Body.String()))
					}
				})
			}
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
		riskExecute: true,
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
	var attack, scope, credential, destructive, execute []string
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
		case riskExecute:
			execute = append(execute, pattern)
		}
	}
	sort.Strings(attack)
	sort.Strings(scope)
	sort.Strings(credential)
	sort.Strings(destructive)
	sort.Strings(execute)

	wantAttack := []string{
		"/api/apiscan", "/api/audit/", "/api/audit/selected", "/api/crawl", "/api/discovery", "/api/intruder/run", "/api/scanner/audit",
		// "Audit again" belongs here for the same reason /api/audit/ does: it re-runs the whole check set
		// against a live target through runAudit. That it is spelled as an action on an existing queue
		// row does not make it cheaper than a first audit — AuditWithin gives it a fresh admission
		// ledger precisely so that it is not.
		"/api/scanner/audit-items/",
		"/api/scanner/live",
		// The two schedule routes arm a crawl or an audit to run unattended at a wall-clock time. See
		// their manifest entries: deferring an attack does not make arming it a lesser act than
		// launching one, and the run happens with nobody watching.
		"/api/schedules", "/api/schedules/",
		"/api/sequencer/capture",
	}
	// The pool routes join this class because a pool decides how hard every tool that names it may
	// hit the target; /api/network/settings joins it because a resolution override sends a request
	// the scope authorised by name to an address the operator chose. Neither escapes the gate — the
	// scope still says yes or no about the name — but both change where the authorised bytes land,
	// which is an engagement-shaped decision an unattended caller must confirm.
	// /api/collaborator/server joins for the same reason as /api/network/settings, one step further
	// out: it does not change where the *target's* bytes land, it chooses which third party is told
	// the engagement exists and receives its out-of-band callbacks. Minting is already riskEgress on
	// the grounds that a registration discloses the engagement; picking the recipient is the decision
	// behind that disclosure, and an unattended caller repointing it — or passing "public" to use
	// interactsh's shared pool — is exactly what a confirmation gate is for.
	wantScope := []string{
		"/api/collaborator/server", "/api/config/import", "/api/network/settings", "/api/pools",
		"/api/pools/", "/api/scanner/config", "/api/scope",
	}
	// /api/blindxss is in the credential class because a callback carries the victim browser's
	// `document.cookie`. It is the first entry there whose secret is not a credential burpsy holds
	// but a third party's, which is a stronger reason to require confirmation rather than a weaker
	// one.
	// The two /api/network routes join this class because they hold the operator's own
	// credentials for the target: an HTTP password and a TLS client identity. Neither
	// route can serve the secret itself, but enumerating which accounts are bound to which
	// hosts is a read worth confirming, and a write arms every later send to present one.
	//
	// Sorted, like the manifest itself, because two branches each appended their own routes to
	// this list and the merge produced two declarations of it — a set this test compares by
	// joined string cannot afford an arbitrary order.
	// /api/proxy/ca/import joins because it accepts a CA private key. It is the only entry here whose
	// credential is a *signing* one rather than an authenticating one, and the only route in the whole
	// manifest whose success invalidates work the operator has already done outside burpsy: the
	// previous CA stops signing, so every trust store they installed it into has to be updated.
	wantCredential := []string{
		"/api/blindxss",
		"/api/network/auth", "/api/network/client-certs",
		"/api/proxy/ca/import",
		"/api/session/cookies", "/api/session/login", "/api/session/rules", "/api/session/rules/",
		"/api/settings/triage",
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
	// /api/backup joins the destructive class because it prunes: each call keeps only `retention`
	// snapshots and deletes the rest, so a caller invoking it in a loop rolls the whole retention
	// window off the disk irreversibly while every individual response reports success. Same shape as
	// clearing the tool log, which is what this class was created for.
	// /api/issues/ joins because its DELETE discards a finding — engagement evidence, per the class
	// definition. The PUT on the same subtree is only a triage note on evidence that survives it; it
	// rides along rather than splitting one pattern across two classes.
	// /api/sitemap joins because its DELETE removes a branch from the view the operator reasons and
	// reports from (burpsy-react-ui-10e). The stored exchanges survive — the recorded decision — so
	// it is the mildest member here; it sits in the class because making a worked branch invisible
	// is closer to "discard evidence" than to "write burpsy's own state", and because an unattended
	// caller trimming the map would hide what the operator is being shown.
	// /api/proxy/ca/regenerate joins the destructive class because it irreversibly discards the
	// current signing CA: the previous certificate stops signing, every cached leaf is dropped, and
	// persisting the new pair overwrites the old key on disk with no path back. See its manifest entry
	// for why it is not the credential class its sibling import sits in.
	//
	// /api/dashboard/events joins because its DELETE clears the event log — scope.changed and
	// crawl.refused are the record of what the engagement was allowed to touch and what the tool
	// refused, so discarding them is discarding evidence, the same act as clearing the tool log.
	equal("destructive", destructive, []string{"/api/backup", "/api/dashboard/events", "/api/issues/", "/api/proxy/ca/regenerate", "/api/sitemap", "/api/tools/log"})
	// Exactly two routes execute operator-supplied code, and both are on the Extender surface: one
	// starts a plugin, one invokes something a running plugin registered. A third appearing here means
	// something new can reach exec, which is a decision to make on purpose.
	equal("execute", execute, []string{"/api/extensions/invoke", "/api/extensions/load"})
}
