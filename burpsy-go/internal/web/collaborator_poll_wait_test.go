package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/oob"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// burpsy-react-ui-myr2: POST /api/collaborator/poll filters by payload id and long-polls.

// growingOOB is an open channel whose interaction log a test appends to while a poll waits.
type growingOOB struct {
	domain string
	mu     sync.Mutex
	log    []oob.Interaction
}

func (f *growingOOB) Channel(context.Context) (scanner.OOBChannel, error) { return f, nil }
func (f *growingOOB) Registration() scanner.OOBRegistration {
	return scanner.OOBRegistration{Attempted: true, Open: true, Domain: f.domain}
}
func (f *growingOOB) Close() error   { return nil }
func (f *growingOOB) Domain() string { return f.domain }
func (f *growingOOB) InteractionsFor(string) ([]oob.Interaction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]oob.Interaction(nil), f.log...), nil
}

// hit appends one DNS interaction naming marker, from a distinct resolver each time.
func (f *growingOOB) hit(marker string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, oob.Interaction{
		Protocol: "dns", QType: "A", FullID: marker, UniqueID: marker,
		RawRequest:    ";; QUESTION\n" + strings.ToUpper(marker) + ".oobtest.oast.example. IN A",
		RemoteAddress: "10.0.0." + string(rune('1'+len(f.log))), Timestamp: time.Now(),
	})
}

type pollReply struct {
	State string `json:"state"`
	Poll  *struct {
		Status          string            `json:"status"`
		PayloadIDs      []string          `json:"payload_ids"`
		Received        int               `json:"received"`
		Distinct        int               `json:"distinct"`
		MinInteractions int               `json:"min_interactions"`
		WaitedMs        int64             `json:"waited_ms"`
		Interactions    []json.RawMessage `json:"interactions"`
		Hint            string            `json:"hint"`
	} `json:"poll"`
}

func pollWith(t *testing.T, s *Server, body string) (pollReply, string, int) {
	t.Helper()
	rec := postJSONRaw(t, s, "/api/collaborator/poll", body)
	var out pollReply
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out, rec.Body.String(), rec.Code
}

// mintTwo mints two payloads on a growing channel and returns their addresses and markers.
func mintTwo(t *testing.T) (*Server, *growingOOB, [2]string, [2]string) {
	t.Helper()
	s := newTestServerWithScanner(t)
	f := &growingOOB{domain: "oobtest.oast.example"}
	s.wiredScanner().WithOOBProvider(f)
	if rec := postJSONRaw(t, s, "/api/collaborator/payload", `{"count":2}`); rec.Code != http.StatusOK {
		t.Fatalf("mint = %d: %s", rec.Code, rec.Body.String())
	}
	minted, _ := s.collab().snapshot()
	if len(minted) != 2 {
		t.Fatalf("minted %d", len(minted))
	}
	return s, f, [2]string{minted[0].Address, minted[1].Address}, [2]string{minted[0].Marker, minted[1].Marker}
}

func TestPollFiltersByPayloadID(t *testing.T) {
	s, f, addr, marker := mintTwo(t)
	f.hit(marker[0])

	got, raw, code := pollWith(t, s, `{"payload_ids":["`+addr[0]+`"]}`)
	if code != http.StatusOK || got.Poll == nil || got.Poll.Status != "complete" || got.Poll.Received != 1 || len(got.Poll.Interactions) != 1 {
		t.Fatalf("poll for the payload that fired answered %d: %s", code, raw)
	}
	// The other payload: nothing, and an empty array rather than null.
	got, raw, _ = pollWith(t, s, `{"payload_ids":["`+strings.ToUpper(marker[1])+`"]}`)
	if got.Poll == nil || got.Poll.Status != "empty" || got.Poll.Received != 0 || !strings.Contains(raw, `"interactions":[]`) {
		t.Fatalf("poll for the silent payload (by marker, upper-cased) answered: %s", raw)
	}
	if got.Poll.PayloadIDs[0] != addr[1] {
		t.Fatalf("the marker did not resolve to its address: %v", got.Poll.PayloadIDs)
	}
	// A payload this process never minted is refused, not waited on.
	if _, raw, code := pollWith(t, s, `{"payload_ids":["nope.oast.example"],"wait_seconds":30}`); code != http.StatusBadRequest || !strings.Contains(raw, "nope.oast.example") {
		t.Fatalf("an unknown payload id answered %d: %s", code, raw)
	}
	// An empty body keeps the original reply shape: no poll block.
	if _, raw, _ := pollWith(t, s, ``); strings.Contains(raw, `"poll"`) {
		t.Fatalf("a bare poll grew a poll block: %s", raw)
	}
}

func TestALongPollReturnsEarlyWhenAnInteractionArrives(t *testing.T) {
	old := collaboratorPollInterval
	collaboratorPollInterval = 50 * time.Millisecond
	t.Cleanup(func() { collaboratorPollInterval = old })

	s, f, addr, marker := mintTwo(t)
	go func() {
		time.Sleep(300 * time.Millisecond)
		f.hit(marker[1])
	}()
	start := time.Now()
	got, raw, _ := pollWith(t, s, `{"payload_ids":["`+addr[1]+`"],"wait_seconds":20}`)
	if got.Poll == nil || got.Poll.Status != "complete" || got.Poll.Received != 1 {
		t.Fatalf("the long-poll did not report the arrival: %s", raw)
	}
	if took := time.Since(start); took > 5*time.Second || took < 250*time.Millisecond {
		t.Fatalf("the long-poll took %v; it should return soon after the 300ms arrival", took)
	}
}

func TestALongPollReturnsAtTheDeadlineWithWhatArrived(t *testing.T) {
	old := collaboratorPollInterval
	collaboratorPollInterval = 50 * time.Millisecond
	t.Cleanup(func() { collaboratorPollInterval = old })

	s, f, addr, marker := mintTwo(t)
	start := time.Now()
	got, raw, _ := pollWith(t, s, `{"payload_ids":["`+addr[0]+`"],"wait_seconds":1}`)
	if got.Poll == nil || got.Poll.Status != "empty" || time.Since(start) < 900*time.Millisecond || got.Poll.WaitedMs < 900 {
		t.Fatalf("a wait with no arrivals answered after %v: %s", time.Since(start), raw)
	}
	f.hit(marker[0])
	got, raw, _ = pollWith(t, s, `{"payload_ids":["`+addr[0]+`"],"wait_seconds":1,"min_interactions":3}`)
	if got.Poll == nil || got.Poll.Status != "timeout" || got.Poll.Received != 1 || got.Poll.MinInteractions != 3 {
		t.Fatalf("fewer than min_interactions did not answer timeout with the one that came: %s", raw)
	}
	if _, raw, code := pollWith(t, s, `{"wait_seconds":61}`); code != http.StatusBadRequest {
		t.Fatalf("wait_seconds 61 answered %d: %s", code, raw)
	}
}

func TestALongPollWithNoChannelDoesNotWait(t *testing.T) {
	s := newTestServerWithScanner(t)
	start := time.Now()
	got, raw, code := pollWith(t, s, `{"wait_seconds":30}`)
	if code != http.StatusOK || got.Poll == nil || got.Poll.Status != "unavailable" || !strings.Contains(got.Poll.Hint, "no out-of-band channel is open") || time.Since(start) > 2*time.Second {
		t.Fatalf("an unconfigured channel answered %d after %v: %s", code, time.Since(start), raw)
	}
}
