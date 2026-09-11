package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/oob"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// The Intruder Collaborator payload type (hi8): each payload is a fresh out-of-band address,
// minted at launch and recorded in the hub the Collaborator page polls — the decompiled
// original's Zcc_.buildNextPayload mints per request and Zrvn's panel bounds it with "Number
// of payloads to generate" plus the "Include Collaborator server location" checkbox.
//
// The refusal shape matters as much as the mint: Burp ends the payload set on a missing
// channel (null from buildNextPayload), which would silently shorten an OOB sweep — a shortened
// sweep reads as a clean one. burpsy refuses the launch instead, naming the reason.

// mintableOOB is a provider whose channel opens without a subprocess: the Collaborator payload
// type tests DO call Channel() (unlike the server-change tests, whose fake panics on it by
// design), and a real registration would put the network in the unit suite. InteractionsFor
// answers empty — these tests pin minting and attribution, not callback correlation.
type mintableOOB struct {
	domain string
}

func (f *mintableOOB) Channel(context.Context) (scanner.OOBChannel, error) { return f, nil }
func (f *mintableOOB) Registration() scanner.OOBRegistration {
	return scanner.OOBRegistration{Attempted: true, Open: true, Domain: f.domain}
}
func (f *mintableOOB) Close() error                                      { return nil }
func (f *mintableOOB) Domain() string                                    { return f.domain }
func (f *mintableOOB) InteractionsFor(string) ([]oob.Interaction, error) { return nil, nil }

func Test_collaborator_payload_type_mints_distinct_addresses_into_the_attack(t *testing.T) {
	s := newTestServerWithScanner(t)
	s.scanner.WithOOBProvider(&mintableOOB{domain: "oobtest.oast.example"})

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("seen"))
	}))
	defer origin.Close()
	host, port := hostPort(t, origin)
	raw := fmt.Sprintf("GET /?q=x HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port)
	id := putMessage(t, s, []byte(raw), core.DirectionRequest)

	rec := postJSONRaw(t, s, "/api/intruder/run", fmt.Sprintf(`{
		"msg_id": %d, "target": "%s:%d", "mode": "sniper", "points": [0],
		"payload_sources": [{"type": "collaborator", "count": 3}]
	}`, id, host, port))
	if rec.Code != http.StatusOK {
		t.Fatalf("run = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var view struct {
		Report struct {
			Sent    int `json:"sent"`
			Planned int `json:"planned"`
		} `json:"report"`
		Examples []struct {
			Payloads []string `json:"payloads"`
		} `json:"examples"`
		PayloadSets []struct {
			Kind  string   `json:"kind"`
			Items []string `json:"items"`
		} `json:"payload_sets"`
	}
	if err := decodeInto(rec, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Report.Sent != 3 {
		t.Fatalf("three minted payloads = three sends, got %d", view.Report.Sent)
	}
	seen := map[string]bool{}
	for _, ex := range view.Examples {
		for _, p := range ex.Payloads {
			seen[p] = true
			if !strings.HasSuffix(p, ".oobtest.oast.example") {
				t.Fatalf("payload %q is not on the channel's domain", p)
			}
		}
	}
	if len(seen) != 3 {
		t.Fatalf("three DISTINCT addresses should reach the wire, got %d: %v", len(seen), seen)
	}
	if len(view.PayloadSets) != 1 || view.PayloadSets[0].Kind != "collaborator" {
		t.Fatalf("the payload set should be named collaborator, got %+v", view.PayloadSets)
	}

	// The mint is recorded in the hub the Collaborator page polls, so the payloads the attack
	// used are visible and attributable there — the same accounting the page's own mint button
	// gets. A payload the page never shows is an address nobody can correlate a callback to.
	hub := hubPayloads(t, s)
	if len(hub) != 3 {
		t.Fatalf("the hub should record the 3 minted payloads, got %d", len(hub))
	}
}

// Include-location off yields the bare interaction id — Burp's unchecked "Include Collaborator
// server location" (Zcc_ passes the flag straight to the address builder).
func Test_collaborator_payload_type_omits_the_server_location_when_asked(t *testing.T) {
	s := newTestServerWithScanner(t)
	s.scanner.WithOOBProvider(&mintableOOB{domain: "oobtest.oast.example"})

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("seen"))
	}))
	defer origin.Close()
	host, port := hostPort(t, origin)
	raw := fmt.Sprintf("GET /?q=x HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port)
	id := putMessage(t, s, []byte(raw), core.DirectionRequest)

	rec := postJSONRaw(t, s, "/api/intruder/run", fmt.Sprintf(`{
		"msg_id": %d, "target": "%s:%d", "mode": "sniper", "points": [0],
		"payload_sources": [{"type": "collaborator", "count": 2, "include_location": false}]
	}`, id, host, port))
	if rec.Code != http.StatusOK {
		t.Fatalf("run = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var view struct {
		Examples []struct {
			Payloads []string `json:"payloads"`
		} `json:"examples"`
	}
	if err := decodeInto(rec, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, ex := range view.Examples {
		for _, p := range ex.Payloads {
			if strings.Contains(p, ".") {
				t.Fatalf("bare interaction ids carry no domain dot, got %q", p)
			}
		}
	}
}

// No channel configured: the launch is refused with the reason, not silently shortened.
func Test_collaborator_payload_type_refuses_without_a_channel(t *testing.T) {
	s := newTestServerWithScanner(t) // no OOB provider

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a refused attack must not reach the wire")
	}))
	defer origin.Close()
	host, port := hostPort(t, origin)
	raw := fmt.Sprintf("GET /?q=x HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port)
	id := putMessage(t, s, []byte(raw), core.DirectionRequest)

	rec := postJSONRaw(t, s, "/api/intruder/run", fmt.Sprintf(`{
		"msg_id": %d, "target": "%s:%d", "mode": "sniper", "points": [0],
		"payload_sources": [{"type": "collaborator", "count": 3}]
	}`, id, host, port))
	if rec.Code != http.StatusConflict {
		t.Fatalf("no channel should refuse the launch with 409, got %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if !strings.Contains(rec.Body.String(), "no out-of-band interaction channel") {
		t.Fatalf("the refusal should name the missing channel, got: %s", strings.TrimSpace(rec.Body.String()))
	}
}

// The batch ceiling applies to the payload type as it does to the Collaborator page's mint.
func Test_collaborator_payload_type_honours_the_batch_ceiling(t *testing.T) {
	s := newTestServerWithScanner(t)
	s.scanner.WithOOBProvider(&mintableOOB{domain: "oobtest.oast.example"})

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a refused attack must not reach the wire")
	}))
	defer origin.Close()
	host, port := hostPort(t, origin)
	raw := fmt.Sprintf("GET /?q=x HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port)
	id := putMessage(t, s, []byte(raw), core.DirectionRequest)

	rec := postJSONRaw(t, s, "/api/intruder/run", fmt.Sprintf(`{
		"msg_id": %d, "target": "%s:%d", "mode": "sniper", "points": [0],
		"payload_sources": [{"type": "collaborator", "count": 101}]
	}`, id, host, port))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("count past the ceiling should be refused, got %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if !strings.Contains(rec.Body.String(), "100") {
		t.Fatalf("the refusal should name the bound, got: %s", strings.TrimSpace(rec.Body.String()))
	}
}
