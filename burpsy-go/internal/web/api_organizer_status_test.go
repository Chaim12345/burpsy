package web

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/organizer"
	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
)

// organizerItemPath builds the one-item route; the status PUT appends the /status subpath.
func organizerItemPath(id int, suffix string) string {
	return "/api/tools/organizer/" + itoa(uint64(id)) + "/" + suffix
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

// The workflow status (4t8 / Burp's organizer "Statuses") and the HTTP status code are two
// different columns answering two different questions — "what did the operator decide" vs "what
// did the server say". These tests pin the wire contract: a new item starts New, the PUT route
// sets one of the five, refuses an unrepresentable one by naming the valid set, answers 404 for
// an unknown item, and the status round-trips through the persist mirror with legacy/NULL rows
// reading back as New.

func TestAnOrganizerItemStartsNewAndPUTStatusSetsEachOfTheFive(t *testing.T) {
	s := organizerTestServer(t)
	item := s.organizer.Add(captureExchange(t, s, "app.test", "/a", 200, "text/html"))

	if item.Status != organizer.StatusNew {
		t.Fatalf("a fresh item is %q, want %q: the whole point of the statuses is distinguishing untriaged from worked-through", item.Status, organizer.StatusNew)
	}

	for _, want := range []organizer.Status{
		organizer.StatusInProgress, organizer.StatusPostponed,
		organizer.StatusDone, organizer.StatusIgnored, organizer.StatusNew,
	} {
		rec := putJSON(t, s, organizerItemPath(item.ID, "status"), map[string]any{"status": string(want)})
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT status %q = %d, want 200", want, rec.Code)
		}
		if got := s.organizer.List()[0].Status; got != want {
			t.Fatalf("status after PUT = %q, want %q", got, want)
		}
	}
}

func TestOrganizerStatusPUTRefusesAnUnrepresentableStatusNamingTheValidSet(t *testing.T) {
	s := organizerTestServer(t)
	item := s.organizer.Add(captureExchange(t, s, "app.test", "/a", 200, ""))

	rec := putJSON(t, s, organizerItemPath(item.ID, "status"), map[string]any{"status": "finished"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT an invented status = %d, want 400", rec.Code)
	}
	for _, name := range []string{"new", "in_progress", "postponed", "done", "ignored"} {
		if !contains(rec.Body.String(), name) {
			t.Fatalf("400 body %q does not name valid status %q; the operator must be told what they can set", rec.Body.String(), name)
		}
	}
	if got := s.organizer.List()[0].Status; got != organizer.StatusNew {
		t.Fatalf("refused PUT changed the status to %q; a refusal must be a no-op", got)
	}
}

func TestOrganizerStatusPUTOnAnUnknownItemIs404(t *testing.T) {
	s := organizerTestServer(t)
	rec := putJSON(t, s, organizerItemPath(99, "status"), map[string]any{"status": "done"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("PUT status on unknown item = %d, want 404", rec.Code)
	}
}

func TestOrganizerStatusRoundTripsThroughPersistWithLegacyRowsReadingNew(t *testing.T) {
	// A bare Server has no persist mirror; this round trip needs a real one, built the way the
	// persist tests build theirs (TempDir + Open) and attached through WithPersist.
	ps, err := persist.Open(filepath.Join(t.TempDir(), "organizer-status.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("Open persist: %v", err)
	}
	s := organizerTestServer(t).WithPersist(ps)
	item := s.organizer.Add(captureExchange(t, s, "app.test", "/a", 200, ""))
	if rec := putJSON(t, s, organizerItemPath(item.ID, "status"), map[string]any{"status": "in_progress"}); rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200", rec.Code)
	}

	// Save through the mirror and load back, the same path a restart takes. SaveOrganizer is
	// called by the change hook, but calling it directly makes the round trip explicit.
	ps.SaveOrganizer(s.organizer.List())
	loaded, err := ps.LoadOrganizer()
	if err != nil {
		t.Fatalf("LoadOrganizer: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Status != organizer.StatusInProgress {
		t.Fatalf("loaded = %+v; the workflow status must survive the save/load round trip", loaded)
	}

	// A legacy row carries no status at all; it must read back as New (never triaged), not as
	// some invented default that looks like a decision. A legacy shape is reproduced by saving an
	// item whose Status is the zero value "" — SaveOrganizer writes it and LoadOrganizer must
	// refuse it as not-a-status and answer New.
	ps.SaveOrganizer([]organizer.Item{{ID: 7, Exchange: item.Exchange, Title: "legacy", Highlight: "none"}})
	legacy, err := ps.LoadOrganizer()
	if err != nil {
		t.Fatalf("LoadOrganizer legacy: %v", err)
	}
	var legacyItem *organizer.Item
	for i := range legacy {
		if legacy[i].ID == 7 {
			legacyItem = &legacy[i]
		}
	}
	if legacyItem == nil {
		t.Fatalf("legacy row id 7 missing from load: %+v", legacy)
	}
	if legacyItem.Status != organizer.StatusNew {
		t.Fatalf("a legacy row read back as %q, want %q — the honest reading of never-triaged", legacyItem.Status, organizer.StatusNew)
	}
}
