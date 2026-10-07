package scanner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// storedTarget serves vulnapp and seeds the two endpoints the stored pair needs.
func storedTarget(t *testing.T) (*ActiveScanner, *core.TrafficStore, map[string]core.ExchangeID) {
	t.Helper()
	srv := httptest.NewServer(vulnapp.Handler())
	t.Cleanup(srv.Close)

	host, portStr, ok := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	if !ok {
		t.Fatalf("cannot split %q", srv.URL)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("port: %v", err)
	}

	store := core.NewTrafficStore()
	ids := map[string]core.ExchangeID{}
	for _, path := range []string{"/comment?comment=hello", "/comments", "/safe/comments"} {
		res, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
		raw0, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		_ = res.Body.Close()
		body := string(raw0)

		raw := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
		reqID, err := store.Put([]byte(raw), core.DirectionRequest)
		if err != nil {
			t.Fatalf("put request: %v", err)
		}
		respRaw := "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
		respID, err := store.Put([]byte(respRaw), core.DirectionResponse)
		if err != nil {
			t.Fatalf("put response: %v", err)
		}
		ex := &core.Exchange{
			Request: core.MsgPtr(reqID), Response: &respID,
			Host: host, Port: uint16(port), TLS: false, Method: "GET", Path: path,
		}
		store.AddExchange(ex)
		ids[path] = ex.ID
	}

	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithStoredLedger(NewStoredLedger()).
		WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: time.Minute, CheckStored: true,
			PendingDeadline: 2 * time.Second})
	return scan, store, ids
}

// The defect this closes: a canary planted during the audit cannot appear in any response the scan
// already holds, because all of them predate the planting. Only a second look can see it.
func TestARefetchSeesACanaryThatNoCapturedResponseCouldHaveContained(t *testing.T) {
	scan, _, ids := storedTarget(t)

	// Plant through the real submission endpoint, exactly as a stored check does.
	canary, err := scan.stored.Plant(ids["/comment?comment=hello"], "/comment", "query comment")
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}
	ex, err := scan.store.GetExchange(ids["/comment?comment=hello"])
	if err != nil {
		t.Fatalf("GetExchange: %v", err)
	}
	gate := scan.probeGate(ex)
	if gate == nil {
		t.Fatal("no authorised sender for the seeded exchange, so nothing could be planted")
	}
	if _, err := gate.SendRequest(context.Background(), &sender.Request{
		Method: "GET", Host: ex.Host, Port: ex.Port, TLS: false,
		Path: "/comment?comment=" + canary.Token,
	}); err != nil {
		t.Fatalf("submit canary: %v", err)
	}

	// Before the re-fetch nothing can possibly have seen it.
	if got := scan.stored.SecondOrderObservations(); len(got) != 0 {
		t.Fatalf("got %d sightings before any re-fetch, want 0: every captured response predates "+
			"the planting, so a sighting here would mean the ledger is matching something else", len(got))
	}

	out, err := scan.RefetchStoredTargets(context.Background())
	if err != nil {
		t.Fatalf("RefetchStoredTargets: %v", err)
	}
	if out.Refetched == 0 {
		t.Fatalf("re-fetched nothing (%s); every assertion below would be vacuous", out.Summary())
	}
	if out.Observed == 0 {
		t.Fatalf("the canary was submitted to /comment and /comments renders every stored comment, "+
			"but the re-fetch saw no sighting: %s", out.Summary())
	}

	sightings := scan.stored.SecondOrderObservations()
	if len(sightings) == 0 {
		t.Fatal("no second-order observation recorded, so a stored check still could not fire")
	}
	var onOtherPage bool
	for _, s := range sightings {
		if s.SeenIn != s.Canary.Origin {
			onOtherPage = true
		}
	}
	if !onOtherPage {
		t.Error("every sighting was attributed to the exchange that planted it, which is reflection " +
			"rather than storage - the whole distinction the second-order rows rest on")
	}
}

// A re-fetch with no ledger must refuse rather than report a clean second look.
func TestRefetchRefusesWithoutALedger(t *testing.T) {
	scan, _, _ := storedTarget(t)
	scan.stored = nil
	if _, err := scan.RefetchStoredTargets(context.Background()); err == nil {
		t.Error("re-fetching with no ledger reported success; nothing was planted, so there is " +
			"nothing to look for and saying so is the only honest outcome")
	}
}

// A re-fetch with no sender must refuse: the pages that would render a canary cannot be requested.
func TestRefetchRefusesWithoutASender(t *testing.T) {
	scan, _, _ := storedTarget(t)
	scan.sender = nil
	if _, err := scan.RefetchStoredTargets(context.Background()); err == nil {
		t.Error("re-fetching with no sender reported success rather than naming the missing capability")
	}
}

// The summary must separate "looked and saw nothing" from "never looked".
func TestTheRefetchSummaryDistinguishesNoSightingsFromNoRefetches(t *testing.T) {
	looked := StoredRefetchOutcome{Candidates: 3, Refetched: 3}
	never := StoredRefetchOutcome{Candidates: 3, Refused: 3}
	if s := looked.Summary(); !strings.Contains(s, "3 of 3") {
		t.Errorf("Summary() = %q, want the re-fetch count so a zero-sighting result can be read", s)
	}
	if s := never.Summary(); !strings.Contains(s, "refused by scope") {
		t.Errorf("Summary() = %q, want the refusal named: zero sightings after zero requests is "+
			"not a negative result", s)
	}
	withOutstanding := StoredRefetchOutcome{Candidates: 1, Refetched: 1, Outstanding: 2}
	if s := withOutstanding.Summary(); !strings.Contains(s, "not clean") {
		t.Errorf("Summary() = %q, want outstanding canaries refused the word clean", s)
	}
}

// Re-fetching must not amplify: the same page captured many times is one target.
func TestRefetchVisitsEachTargetOnceRegardlessOfHowOftenItWasCaptured(t *testing.T) {
	scan, store, _ := storedTarget(t)
	ex, err := store.GetExchange(scan.storedRefetchTargets()[0].exchange.ID)
	if err != nil {
		t.Fatalf("GetExchange: %v", err)
	}
	before := len(scan.storedRefetchTargets())
	for range 5 {
		store.AddExchange(&core.Exchange{
			Request: ex.Request, Response: ex.Response,
			Host: ex.Host, Port: ex.Port, Method: http.MethodGet, Path: ex.Path,
		})
	}
	if after := len(scan.storedRefetchTargets()); after != before {
		t.Errorf("targets went from %d to %d after re-capturing the same page five times; a second "+
			"pass that scales with history length is a request amplifier", before, after)
	}
}
