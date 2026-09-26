package scanner

// The browser half of the stored lifecycle.
//
// RefetchStoredTargets closes the HTTP half: it asks for the pages again and feeds each raw
// response body to the ledger. That is everything a stored canary needs *provided the server puts
// it in the response*. A page that fetches the stored value with script and writes it into the
// document leaves the canary out of every byte the HTTP re-fetch sees, so the ledger records the
// canary as Outstanding for ever and the "(stored DOM-based)" rows have nothing to match against.
// The rows were wired, dispatched and permanently unable to report - the combination this project
// treats as worse than declining outright.
//
// This file adds the second look a browser can take. It renders the same targets the HTTP pass
// re-fetched, feeds the rendered document to the ledger exactly as the raw body is fed, and
// separately records which canaries a script carried into an instrumented sink. Those two are not
// the same claim: a page that merely displays stored input is not a DOM-based finding, and only the
// sink observations decide a "(stored DOM-based)" row.
//
// # Everything declined is counted
//
// A render pass that cannot run reports why. No browser is an error; DOM checks switched off, a
// page with no script, and targets beyond the cap are counted in the outcome. A zero here means
// "rendered N pages, saw nothing" only when Rendered is non-zero, which is the distinction
// StoredRefetchOutcome already makes for the HTTP half and for the same reason.

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
)

// MaxStoredDOMRenders bounds how many pages one render pass loads.
//
// Every render is a real browser tab against a real page, so an unbounded pass over a large scan's
// GET surface would be the slowest thing in a scan by an order of magnitude. The cap is recorded
// rather than silent: Capped in the outcome says how many pages were never looked at, so a clean
// result is not mistaken for a complete one.
const MaxStoredDOMRenders = 120

// storedRenderConcurrency is how many tabs the pass drives at once. Renders are independent and
// dominated by waiting for page script, so a small pool turns a serial minute into a few seconds.
const storedRenderConcurrency = 4

// StoredDOMRenderOutcome is what the browser's second look managed to do.
type StoredDOMRenderOutcome struct {
	// Candidates is how many re-fetch targets existed at all.
	Candidates int
	// NoScript is how many were not rendered because their response carries no script. A document
	// with no script renders to what it already was, so a browser could not reveal anything the
	// HTTP pass did not already see.
	NoScript int
	// Capped is how many were dropped by MaxStoredDOMRenders.
	Capped int
	// Rendered is how many pages were loaded in the browser.
	Rendered int
	// Failed is how many could not be loaded.
	Failed int
	// Observed is how many canary sightings the rendered documents produced.
	Observed int
	// SinkHits is how many times a script carried a planted canary into an instrumented sink.
	SinkHits int
	// Declined explains a pass that did not run for a reason that is not an error - DOM checks
	// switched off, or nothing planted to look for.
	Declined string
}

// Summary renders the outcome in the vocabulary a report can print.
func (o StoredDOMRenderOutcome) Summary() string {
	if o.Declined != "" {
		return "no browser render pass: " + o.Declined
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d of %d targets rendered in a browser", o.Rendered, o.Candidates)
	if o.NoScript > 0 {
		fmt.Fprintf(&b, ", %d skipped as script-free", o.NoScript)
	}
	if o.Capped > 0 {
		fmt.Fprintf(&b, ", %d beyond the render cap and never looked at", o.Capped)
	}
	if o.Failed > 0 {
		fmt.Fprintf(&b, ", %d failed to load", o.Failed)
	}
	fmt.Fprintf(&b, "; %d canary sighting(s) in a rendered document, %d reached a sink", o.Observed, o.SinkHits)
	return b.String()
}

// domStoredSighting is one planted canary that a page's own script fed to a dangerous sink.
type domStoredSighting struct {
	// Canary names the exchange that planted the value, which is what makes the finding
	// second-order rather than a plain DOM flow.
	Canary StoredCanary
	// Observation is the sink call, its argument and the stack it happened on.
	Observation domexec.Observation
	// SeenIn and SeenPath are the rendered page.
	SeenIn   core.ExchangeID
	SeenPath string
}

// domStoredSightings returns a snapshot of every sink sighting the render pass has recorded.
func (s *ActiveScanner) domStoredSightings() []domStoredSighting {
	if s == nil {
		return nil
	}
	s.domStoredMu.Lock()
	defer s.domStoredMu.Unlock()
	return append([]domStoredSighting(nil), s.domStored...)
}

// RenderStoredTargets loads every plausible target in a real browser and feeds what the page's
// script produced back into the stored ledger.
//
// It runs after RefetchStoredTargets rather than instead of it. The HTTP pass is cheaper, sees
// pages this one skips, and its sightings are what the non-DOM stored rows are decided on; this
// pass exists for the flows that pass alone cannot see.
func (s *ActiveScanner) RenderStoredTargets(ctx context.Context) (StoredDOMRenderOutcome, error) {
	var out StoredDOMRenderOutcome
	if s == nil || s.store == nil {
		return out, fmt.Errorf("stored DOM render: no traffic store")
	}
	if s.stored == nil {
		return out, fmt.Errorf("stored DOM render: no stored-input ledger, so nothing was planted to look for")
	}
	if snap := s.ConfigSnapshot(); !domChecksEnabled(&snap) {
		out.Declined = "DOM checks are not enabled for this scan, so no page was rendered"
		return out, nil
	}
	if s.browsers == nil {
		// Not a decline. A scan that asked for DOM checks and has no browser looked at nothing,
		// and the stored DOM rows must be told that rather than shown an empty result.
		return out, fmt.Errorf("stored DOM render: no DOM execution capability is configured for this scan")
	}
	tokens := s.stored.Tokens()
	if len(tokens) == 0 {
		out.Declined = "nothing was planted, so a rendered page could not show a canary"
		return out, nil
	}
	browser, err := s.browsers.Browser(ctx)
	if err != nil {
		return out, err
	}

	targets, noScript := s.storedRenderTargets()
	out.Candidates = len(targets) + noScript
	out.NoScript = noScript
	if len(targets) > MaxStoredDOMRenders {
		out.Capped = len(targets) - MaxStoredDOMRenders
		targets = targets[:MaxStoredDOMRenders]
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	work := make(chan refetchTarget)
	for i := 0; i < storedRenderConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range work {
				render, err := browser.ObserveStored(ctx, exchangeURL(t.exchange), tokens)
				mu.Lock()
				if err != nil {
					out.Failed++
					mu.Unlock()
					continue
				}
				s.recordRender(&out, t, render)
				mu.Unlock()
			}
		}()
	}
	for _, t := range targets {
		select {
		case work <- t:
		case <-ctx.Done():
		}
	}
	close(work)
	wg.Wait()

	return out, nil
}

// recordRender stores one rendered document as its own exchange and files what it showed. Called
// under the caller's lock, because it mutates the outcome and the sighting list together.
func (s *ActiveScanner) recordRender(out *StoredDOMRenderOutcome, t refetchTarget, render domexec.StoredRender) {
	ex, err := s.storeRenderedDocument(t, render.HTML)
	if err != nil {
		// The document cannot be cited, so a sighting attributed to it could not be reproduced.
		out.Failed++
		return
	}
	out.Rendered++
	out.Observed += len(s.stored.Observe(ex.ID, t.path, []byte(render.HTML)))

	for _, o := range render.Observations {
		canary, ok := s.stored.CanaryFor(o.Canary)
		if !ok {
			continue
		}
		out.SinkHits++
		s.domStoredMu.Lock()
		s.domStored = append(s.domStored, domStoredSighting{
			Canary: canary, Observation: o, SeenIn: ex.ID, SeenPath: t.path,
		})
		s.domStoredMu.Unlock()
	}
}

// storeRenderedDocument records a rendered document as its own exchange, so a sighting in it can be
// cited like any other.
//
// The response it writes is labelled, because it is not one: no server ever sent these bytes. They
// are what the browser produced after running the page's script, and a reader who mistook them for
// the wire response would look for markup in a raw body that never contained it.
func (s *ActiveScanner) storeRenderedDocument(t refetchTarget, html string) (*core.Exchange, error) {
	raw := "GET " + t.path + " HTTP/1.1\r\nHost: " + t.exchange.Host + "\r\n\r\n"
	reqID, err := s.store.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		return nil, err
	}
	respRaw := "HTTP/1.1 200 OK\r\nX-Burpsy-Document: rendered by the headless browser, not the wire response\r\n" +
		"Content-Type: text/html\r\nContent-Length: " + fmt.Sprint(len(html)) + "\r\n\r\n" + html
	respID, err := s.store.Put([]byte(respRaw), core.DirectionResponse)
	if err != nil {
		return nil, err
	}
	ex := &core.Exchange{
		Request: core.MsgPtr(reqID), Response: &respID,
		Host: t.exchange.Host, Port: t.exchange.Port, TLS: t.exchange.TLS,
		Method: "GET", Path: t.path,
		// Taken from the head written just above rather than hardcoded "text/html", so the row and the
		// stored response cannot come to disagree if that head is ever edited. It is a rendered
		// document, which genuinely is HTML — the X-Burpsy-Document header is what says no server sent
		// it, and that caveat belongs on the response, not smuggled into the type column.
		Mime: core.MimeEssence([]byte(respRaw)),
	}
	s.store.AddExchange(ex)
	return ex, nil
}

// storedRenderTargets splits the re-fetch surface into pages worth rendering and pages that cannot
// possibly repay the cost.
//
// The filter is soundness, not a guess: a document containing no script at all parses to exactly
// the markup the HTTP pass already fed to the ledger, so rendering it could not surface a canary
// the ledger has not already been shown. Anything with script is rendered, however unlikely, because
// deciding which script *would* reach a sink is the question the browser is being asked.
func (s *ActiveScanner) storedRenderTargets() (targets []refetchTarget, noScript int) {
	for _, t := range s.storedRefetchTargets() {
		body := responseBody(responseRaw(s, t.exchange))
		if !strings.Contains(strings.ToLower(body), "<script") {
			noScript++
			continue
		}
		targets = append(targets, t)
	}
	return targets, noScript
}
