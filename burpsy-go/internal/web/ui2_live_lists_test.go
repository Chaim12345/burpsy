package web

import (
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/burpsy-go/burpsy/internal/proxy"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
	"testing"
)

// The Intercept and Logger views live-refresh off the event stream the hub already
// publishes (changeIntercept and changeToolLog announce on every change - covered
// behaviourally by TestEveryChangeSourceAnnouncesItsOwnKind). These pins hold the
// client wiring: which frame each view consumes, where the answer swaps, and the
// guards that keep a swap from taking operator state away.
func TestUI2LiveListWiring(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/app.js", nil))
	js := rec.Body.String()

	for _, want := range []string{
		// Each view consumes only its own kind.
		"view === 'intercept' && kind === 'intercept'",
		"view === 'logger' && kind === 'toollog'",
		"view === 'ws' && kind === 'ws'",
		"view === 'organizer' && kind === 'organizer'",
		"view === 'proxy' && kind === 'proxy'",
		"view === 'session' && kind === 'session'",
		// The Scope page rides its own kind; its swap root is #srows, not #rows.
		"view === 'scope' && kind === 'scope'",
		"what === 'scope') {\n    url = '/ui2/scope'",
		// The consumer is only half the wiring: the refresh must also know where the
		// Session fragment lives. (A consumer branch without this case refreshes nothing.)
		"what === 'session') {\n    url = '/ui2/session'",
		"view === 'dashboard' && (kind === 'dashboard' || kind === 'history' || kind === 'toollog' || kind === 'issues')",
		// The Logger refresh carries the rendered search so it survives the swap.
		`#rows input[name="search"]`,
		// Guards: an open held-message editor, a focused field, and unsaved edits
		// (caught by defaultValue/defaultChecked comparison, so blurred fields and
		// closed editors count too) arm the pill instead of refreshing.
		"details.held-editor[open]",
		"f.value === f.defaultValue",
		"f.checked === f.defaultChecked",
		// A live refresh is never issued while an operator request is in flight, so
		// a pre-change answer can never swap in over the operator's fresher one.
		"liveOpFlight > 0",
		// Unsaved edits are captured before a live swap and re-applied after it, so
		// the pill's manual refresh cannot silently discard them.
		"var captured = rows ? liveDirtyFields(rows) : [];",
		"liveReapplyDirty(liveDirtySaved)",
		// A transient sheet with no operator-editable fields (the Sequencer review
		// sheet between the start form and the list) neither overwrites nor clears
		// the saved edits, so the swap back to the form still re-applies them.
		"var hasEditable = rows && rows.querySelector(",
		"if (captured.length) liveDirtySaved = captured;",
		"else if (hasEditable) liveDirtySaved = null;",
		"if (hasEditable2 || !liveDirtySaved) {",
		// The Sequencer view's start form lives in #rows too: its operator swaps
		// (confirm, run, stop) get the same capture-and-re-apply as intercept/logger.
		`v === 'intercept' || v === 'logger' || v === 'sequencer'`,
		// Successful OPERATOR #rows swaps on the guarded views get the same
		// capture-and-re-apply, so forwarding one held item no longer wipes unsaved
		// edits in another; a failed submission never swaps, so drafts survive there
		// by definition.
		"!tag && !liveDirtyView()",
		// Selects have no defaultValue; their rendered state lives on the options.
		"o.selected !== o.defaultSelected",
		// A select whose options carry no selected attribute defaults to its FIRST option -
		// without this case an untouched select (the Scope page's kind picker) reads dirty
		// forever and the live refresh always falls back to the pill.
		"f.options[0].selected",
		// An open rule-edit details counts as operator state even untouched and unfocused -
		// a live refresh must not collapse it.
		"details.scope-edit[open]",
		// A multiple-select with no selected attributes defaults to NOTHING selected, unlike
		// the single-select's first option.
		"f.multiple",
		// The pill names the scope change in its own words, not as generic traffic.
		"what === 'scope' ? 'Scope changed'",
		// While the bottom-docked scope editor is open, the pill docks to the top instead
		// of covering the editor's fields, and it re-docks if the sheet opens or closes
		// while the pill is pending (toggle does not bubble - capture phase).
		"p.classList.toggle('livepill-top'",
		"addEventListener('toggle'",
		// A swap can also remove the open editor WITHOUT a toggle event - the node is
		// discarded, not closed - so the dock is re-evaluated after every swap too.
		"addEventListener('htmx:afterSwap', livePillDock)",
		// The Sequencer page rides the dashboard kind: captures announce start/finish
		// through the task registry; per-token ticks stay silent on purpose. Its start
		// form is operator state, so it joins the guarded list, and the pill names it.
		"view === 'sequencer' && kind === 'dashboard'",
		"what === 'sequencer') {\n    url = '/ui2/sequencer'",
		"what === 'scope' || what === 'sequencer'",
		"'Captures changed'",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lost live-list wiring %q", want)
		}
	}
}

// Both views must keep serving their #rows fragment to HX requests - that fragment is
// the live refresh's swap target - and the Logger fragment must keep carrying its
// search in a hidden input, which is where the live refresh reads it back from.
func TestUI2LiveListFragments(t *testing.T) {
	s := newTestServer()
	for _, path := range []string{"/ui2/intercept", "/ui2/logger", "/ui2/ws", "/ui2/organizer", "/ui2/proxy", "/ui2/dashboard", "/ui2/session"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("HX-Request", "true")
		s.mux.ServeHTTP(rec, req)
		body := rec.Body.String()
		if !strings.HasPrefix(body, `<div id="rows">`) {
			t.Errorf("%s no longer serves its #rows fragment root", path)
		}
	}
	// The Scope page's swap root is #srows - the live refresh targets it by that id.
	srec := httptest.NewRecorder()
	sreq := httptest.NewRequest(http.MethodGet, "/ui2/scope", nil)
	sreq.Header.Set("HX-Request", "true")
	s.mux.ServeHTTP(srec, sreq)
	if !strings.HasPrefix(srec.Body.String(), `<div id="srows">`) {
		t.Errorf("/ui2/scope no longer serves its #srows fragment root")
	}
	// The top-dock style for the pill must ship in the page's own style block; the JS
	// toggle without it would still let the pill cover the open scope editor.
	frec := httptest.NewRecorder()
	s.mux.ServeHTTP(frec, httptest.NewRequest(http.MethodGet, "/ui2/scope", nil))
	if !strings.Contains(frec.Body.String(), "#livepill.livepill-top") {
		t.Errorf("scope page no longer carries the pill top-dock style")
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ui2/logger?search=carried", nil)
	req.Header.Set("HX-Request", "true")
	s.mux.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `name="search" value="carried"`) {
		t.Errorf("logger fragment no longer carries its search in a hidden input")
	}
}

// The ui2 Proxy page's passthrough section renders the policy's host list: the template read a
// field the API never sends, so the section answered "No passthrough hosts" even with hosts
// attached - a staleness no live refresh could ever fix. This pins the rendered host.
func TestUI2ProxyPassthroughRendersAttachedHosts(t *testing.T) {
	s := newTestServer()
	policy := proxy.NewTlsPolicy()
	s.WithTlsPolicy(policy)
	policy.AddPassthrough("pinned-render.test")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/proxy", nil))
	if !strings.Contains(rec.Body.String(), "pinned-render.test") {
		t.Errorf("/ui2/proxy does not render the attached passthrough host")
	}
}

// The ui2 Session page renders the cookie jar's contents, not only its hint: until this table
// existed the page showed nothing about a live session's cookies even though the API enumerates
// them. This pins a held cookie's name, value and authority in the served HTML.
func TestUI2SessionRendersCookieJarContents(t *testing.T) {
	s := newTestServer()
	coord := session.NewCoordinator(zap.NewNop())
	s.WithSessionCoordinator(coord)
	coord.SetCookie("rendered.test", 443, true, "sid", "synthetic-render")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/session", nil))
	body := rec.Body.String()
	// The page now carries jar values verbatim; the browser must never store a copy.
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("/ui2/session Cache-Control = %q, want no-store (the page renders jar values)", cc)
	}
	for _, want := range []string{"sid", "synthetic-render", "rendered.test"} {
		if !strings.Contains(body, want) {
			t.Errorf("/ui2/session does not render %q from the attached jar", want)
		}
	}
	// A session cookie has no expiry; the page says so rather than printing the zero time.
	if strings.Contains(body, "0001-01-01") {
		t.Errorf("/ui2/session renders the zero time as a session cookie's expiry")
	}
}

// The Session page's rules table renders the fields the rules API actually serves: it asked
// each row for "type" and "host", keys the API has never sent, so the table rendered empty
// cells for every rule - and a live rule add was invisible on the page even when the fragment
// refreshed. This pins the rendered name of an attached rule.
func TestUI2SessionRendersRuleNames(t *testing.T) {
	s := newTestServer()
	coord := session.NewCoordinator(zap.NewNop())
	s.WithSessionCoordinator(coord)
	rule := session.NewSessionRule("rendered-rule-name", []string{"rendered.test"}, nil)
	rule.Actions = []*session.Action{{Kind: session.ActionSetHeader, Enabled: true, Name: "x-t", Value: "1"}}
	if _, err := coord.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/session", nil))
	if !strings.Contains(rec.Body.String(), "rendered-rule-name") {
		t.Errorf("/ui2/session does not render the attached rule's name")
	}
}
