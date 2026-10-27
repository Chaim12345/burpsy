package crawler

// What the speculative-hidden-link phase already extracts from JavaScript (burpsy-react-ui-jwy5).
//
// # Why this file exists rather than a jsluice integration
//
// The bead says "integrate jsluice". jsluice's own go.mod requires github.com/smacker/go-tree-sitter,
// which is CGO bindings to a C parser — and this tree verifies `CGO_ENABLED=0 go build ./...` as clean
// (burpsy-go/docs/HANDOFF-2026-08-13.md:191). burpsy's distribution is a single static binary with no
// C toolchain requirement, and trading that for extraction accuracy is a release decision rather than a
// coding one.
//
// So before adding a dependency, MEASURE what is already there. discover.go:364-367 already reads
// script BODIES and mines root-shaped tokens from them, and this file establishes how much of a real
// bundle that finds — as a number, with the misses named. A measurement converts "we need jsluice" into
// either "we need cgo" or "we need string handling", and those have very different costs.
//
// # What these tests are NOT
//
// They are not a claim that JS parsing is solved. They are the baseline any replacement is measured
// against, which is the only thing that makes a comparison honest. The gaps are asserted as GAPS — the
// tests that name a miss are the ones that document what the next change has to fix.

import (
	"strings"
	"testing"
)

// A realistic minified SPA bundle fragment: a router table, a concatenated base, a fetch with a
// template literal, and a sourceMappingURL. Every shape here is something a real framework emits.
const spaBundleFragment = `
!function(){var e={routes:[{path:"/dashboard"},{path:"/settings/profile"},{path:"/orders/{id}"}],
fetch:function(n){return fetch(BASE+n,{credentials:"include"})},
orders:function(e){return fetch(` + "`/users/${e.id}/orders`" + `)},
API:"/api/v1",ADMIN:"/admin/panel",LOGOUT:"/logout",
BUNDLE:"static/js/main.a1b2c3.js"};window.__APP=e}();
//# sourceMappingURL=main.a1b2c3.js.map`

func TestTheSpeculativePhaseFindsTheStraightQuotedRoutes(t *testing.T) {
	got := speculativeURLFields(spaBundleFragment)

	// The quoted router table is the easy case and it should work: three distinct path literals.
	for _, want := range []string{"/dashboard", "/settings/profile", "/orders/{id}"} {
		if !containsStr(got, want) {
			t.Errorf("%q was not extracted from a plain quoted route literal; got %v", want, got)
		}
	}
	// And the constants that are paths in their own right.
	for _, want := range []string{"/api/v1", "/admin/panel", "/logout"} {
		if !containsStr(got, want) {
			t.Errorf("%q was not extracted from a path-valued constant; got %v", want, got)
		}
	}
	// A template literal's interpolation is never queued as text (burpsy-react-ui-crawl-template-literal):
	// fetch(`/users/${e.id}/orders`) yields its whole leading segment, /users/, as the JS extractor does.
	if !containsStr(got, "/users/") {
		t.Errorf("the template literal's whole leading segment /users/ was not extracted; got %v", got)
	}
	for _, g := range got {
		if strings.Contains(g, "${") {
			t.Errorf("a raw template interpolation was extracted as a URL: %q", g)
		}
	}
	// The bundle's own filename is NOT a path and must not become one. A .js file sitting at the site
	// root is not a location, and admitting it is exactly the invented-URL failure the package refuses.
	if containsStr(got, "static/js/main.a1b2c3.js") {
		t.Errorf("the bundle's own path was extracted as a location: %v", got)
	}
}

// The gaps that decide whether cgo is warranted. Each is asserted as a MISS, so the day one closes
// the test fails and says so, and the baseline is updated rather than left describing a miss that
// no longer exists.
func TestWhatTheSpeculativePhaseCannotResolve(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{
			// The single biggest miss. A framework that composes its API from a constant plus a segment
			// yields "/admin" nowhere in the source as a complete literal — the whole string only
			// exists after evaluation.
			name: "a concatenated path",
			// The bundle composes fetch(BASE + n) where BASE is never a complete literal, so the
			// composed path does not exist anywhere in the source text.
			want: "/api/v1/admin",
		},
		{
			// Second: a template literal is assembled at runtime from parts the reader sees separately.
			// The fixture's fetch(`/users/${e.id}/orders`) yields only its raw source text; the route
			// it stands for, with the interpolation as a parameter segment, is not recovered. (This
			// case used to want "/users/`${id}`", a token the tokenizer splits on backticks and so
			// could never produce, against a fixture with no template literal in it: a miss that
			// could not stop being a miss.)
			name: "a template-literal path",
			want: "/users/{id}/orders",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A closed gap FAILS rather than skips: a skip is silent in the summary, so the
			// baseline would go on documenting a miss that no longer exists and the jsluice/cgo
			// decision would be made against stale numbers. Whoever closes it updates this file.
			if containsStr(speculativeURLFields(spaBundleFragment), tc.want) {
				t.Fatalf("%q is now extracted: this gap is CLOSED. Move it out of the misses into "+
					"TestTheSpeculativePhaseFindsTheStraightQuotedRoutes and re-examine the jsluice "+
					"question rather than assume it", tc.want)
			}
			t.Logf("MISS, as expected: %q is not recoverable from the source text alone. This is the case "+
				"that decides whether cgo is worth the static binary", tc.want)
		})
	}
}

// The source map is the highest-value half of the bead and nothing currently fetches it. That is a
// documented absence here rather than an omission in the test file.
func TestTheSourceMappingURLIsVisibleButUnfollowed(t *testing.T) {
	// The reference IS in the body, so a reader can see the map exists...
	if !strings.Contains(spaBundleFragment, "sourceMappingURL=main.a1b2c3.js.map") {
		t.Fatal("fixture assumption broken: the fragment no longer names a source map")
	}
	// ...and the speculative phase does not extract it, because it is not root-shaped: it has a scheme-
	// relative prefix on the file, not a leading slash.
	got := speculativeURLFields(spaBundleFragment)
	// By suffix, not equality: every token the phase emits starts with "/" or a scheme, so an exact
	// match on the bare file name could never fire and this check could never fail.
	if anyHasSuffix(got, "main.a1b2c3.js.map") {
		t.Fatal("the source map is now extracted: this baseline is stale. Update it, and note that " +
			"criterion 2 needs a FETCH of the map, not just its extraction")
	}
	t.Log("the source map is not extracted: the phase mines root-shaped tokens, and this is a " +
		"scheme-relative reference. Criterion 2 needs a deliberate fetch, which is the only new " +
		"request this bead would introduce")
}

// De-duplication: the same literal appears many times in a real bundle and the frontier must not be
// flooded with one URL.
func TestRepeatedLiteralsAreExtractedOnce(t *testing.T) {
	noisy := strings.Repeat(`fetch("/api/thing")+`, 40)
	got := speculativeURLFields(noisy)
	n := 0
	for _, g := range got {
		if g == "/api/thing" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("/api/thing was extracted %d times from a repeated literal, want 1", n)
	}
}

func anyHasSuffix(list []string, suffix string) bool {
	for _, v := range list {
		if strings.HasSuffix(v, suffix) {
			return true
		}
	}
	return false
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
