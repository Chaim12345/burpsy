package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- A finding is reported against the URL it was actually found at ----------------------------
//
// The defect this pins: findingToIssueView resolved an occurrence with
// `GetExchange(uint64(occ.Request))` — an exchange lookup keyed by a *message* id. Messages and
// exchanges are both dense counters from zero, so that did not fail. Six proxied requests give
// messages 0..11 and exchanges 0..5, so the request message id of exchange 1 is 2, which is also
// exchange 2's id. The lookup returned a real exchange belonging to an unrelated request, and a
// finding on /search was reported against /login. Findings whose message id ran past the exchange
// count lost their host and path entirely, and the same bug put the wrong hostnames in every
// exported report.
//
// Attribution is the whole value of a finding, so these tests assert the URL, not just that a
// lookup succeeded. A test that only checked "host is non-empty" would have passed throughout.

type issueOccWire struct {
	ExchangeID uint64 `json:"exchange_id"`
	Path       string `json:"path"`
}

type issueWire struct {
	CheckName   string         `json:"check_name"`
	Host        string         `json:"host"`
	Occurrences []issueOccWire `json:"occurrences"`
}

type issuesWire struct {
	Findings []issueWire `json:"findings"`
}

func issuesGet(t *testing.T, s *Server) issuesWire {
	t.Helper()
	rec := get(t, s, "/api/issues")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/issues: status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var v issuesWire
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode issues response %q: %v", rec.Body.String(), err)
	}
	return v
}

// findingOn records a finding against one exchange the way the passive scanner does.
func findingOn(s *Server, name string, ex *core.Exchange) {
	s.findings.Add(core.NewFinding{
		Name:     name,
		Severity: core.SeverityLow,
		Occurrences: []core.Occurrence{{
			ExchangeID: ex.ID,
			Request:    ex.Request,
			Response:   ex.Response,
		}},
	})
}

// The canonical reproduction. Every exchange gets a finding named after its own path, so any
// mismatch between the finding and the exchange it is reported against is visible by name.
func TestEveryFindingIsReportedAgainstThePathItWasFoundAt(t *testing.T) {
	s := newTestServer()

	paths := []string{"/", "/search", "/login", "/api/debug", "/cart", "/checkout"}
	for _, p := range paths {
		ex := addTraffic(t, s.store, "shop.test", "GET", p)
		findingOn(s, "issue at "+p, ex)
	}

	got := issuesGet(t, s)
	if len(got.Findings) != len(paths) {
		t.Fatalf("findings = %d, want %d", len(got.Findings), len(paths))
	}
	for _, f := range got.Findings {
		if len(f.Occurrences) != 1 {
			t.Errorf("%s: occurrences = %d, want 1", f.CheckName, len(f.Occurrences))
			continue
		}
		want := "issue at " + f.Occurrences[0].Path
		if f.CheckName != want {
			t.Errorf("finding %q was reported at path %q — it belongs to a different exchange",
				f.CheckName, f.Occurrences[0].Path)
		}
		if f.Host != "shop.test" {
			t.Errorf("%s: host = %q, want shop.test", f.CheckName, f.Host)
		}
	}
}

// The second half of the same defect: past the point where message ids outrun exchange ids, the
// lookup found nothing and the occurrence came back with no host and no path at all. With six
// exchanges, the request message ids of the last three (6, 8, 10) are all beyond the exchange count.
func TestFindingsOnLaterExchangesKeepTheirHostAndPath(t *testing.T) {
	s := newTestServer()

	var last *core.Exchange
	for i, p := range []string{"/a", "/b", "/c", "/d", "/e", "/f"} {
		ex := addTraffic(t, s.store, "shop.test", "GET", p)
		if i == 5 {
			last = ex
		}
	}
	findingOn(s, "late finding", last)

	got := issuesGet(t, s)
	if len(got.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(got.Findings))
	}
	f := got.Findings[0]
	if f.Host != "shop.test" {
		t.Errorf("host = %q, want shop.test — the occurrence lost its attribution", f.Host)
	}
	if f.Occurrences[0].Path != "/f" {
		t.Errorf("path = %q, want /f", f.Occurrences[0].Path)
	}
	if f.Occurrences[0].ExchangeID != uint64(last.ID) {
		t.Errorf("exchange_id = %d, want %d", f.Occurrences[0].ExchangeID, last.ID)
	}
}

// ExchangeByRequest is the lookup that cannot silently mismatch, and this is what makes it different
// from GetExchange: fed a message id that is also a valid exchange id, it resolves the exchange that
// really owns that message, or reports that none does.
func TestExchangeByRequestResolvesTheOwnerNotTheSameNumberedExchange(t *testing.T) {
	store := core.NewTrafficStore()
	var exchanges []*core.Exchange
	for _, p := range []string{"/zero", "/one", "/two", "/three"} {
		exchanges = append(exchanges, addTraffic(t, store, "shop.test", "GET", p))
	}

	for _, want := range exchanges {
		got, err := store.ExchangeByRequest(core.MsgOrZero(want.Request))
		if err != nil {
			t.Fatalf("request message %d: %v", want.Request, err)
		}
		if got.ID != want.ID {
			t.Errorf("request message %d resolved to exchange %d (%s), want %d (%s)",
				want.Request, got.ID, got.Path, want.ID, want.Path)
		}
	}

	// A message id no exchange owns is an error, not a plausible neighbour. Response message ids are
	// the obvious case: they are real message ids that are never an exchange's request.
	if ex, err := store.ExchangeByRequest(*exchanges[0].Response); err == nil {
		t.Errorf("a response message resolved to exchange %d (%s); it owns no exchange", ex.ID, ex.Path)
	}
}
