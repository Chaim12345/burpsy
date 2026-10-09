package web

// The Intruder "Interactions" column (burpsy-react-ui-nib6): every attempt of a Collaborator-payload
// attack names the addresses it sent, and the Collaborator interaction log attributes each callback
// to one of those addresses — so a callback that arrives after the attack ends is tied back to the
// row that provoked it. The console joins the two; these tests pin both halves on the wire.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/oob"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// callbackOOB is mintableOOB with an interaction log the test fills after the attack.
type callbackOOB struct {
	mintableOOB
	mu  sync.Mutex
	log []oob.Interaction
}

func (f *callbackOOB) Channel(context.Context) (scanner.OOBChannel, error) { return f, nil }
func (f *callbackOOB) InteractionsFor(string) ([]oob.Interaction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]oob.Interaction(nil), f.log...), nil
}

func TestIntruderAttemptsNameTheirCollaboratorAddressesAndCallbacksAttributeToThem(t *testing.T) {
	s := newTestServerWithScanner(t)
	channel := &callbackOOB{mintableOOB: mintableOOB{domain: "oobtest.oast.example"}}
	s.wiredScanner().WithOOBProvider(channel)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("seen")) }))
	defer origin.Close()
	host, port := hostPort(t, origin)
	id := putMessage(t, s, []byte(fmt.Sprintf("GET /?q=x HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port)), core.DirectionRequest)

	// Store full payloads stays off: the column must work for an ordinary attack.
	rec := postJSONRaw(t, s, "/api/intruder/run", fmt.Sprintf(`{
		"msg_id": %d, "target": "%s:%d", "mode": "sniper", "points": [0],
		"payload_sources": [{"type": "collaborator", "count": 3}]
	}`, id, host, port))
	if rec.Code != http.StatusOK {
		t.Fatalf("run = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var view struct {
		Report struct {
			Attempts []struct {
				Ordinal              int       `json:"ordinal"`
				Payloads             *[]string `json:"payloads"`
				CollaboratorPayloads []string  `json:"collaborator_payloads"`
			} `json:"attempts"`
		} `json:"report"`
	}
	if err := decodeInto(rec, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(view.Report.Attempts) != 3 {
		t.Fatalf("want three attempts, got %d", len(view.Report.Attempts))
	}
	byAddress := map[string]int{}
	for _, a := range view.Report.Attempts {
		if a.Payloads != nil {
			t.Errorf("attempt %d carries payloads although Store full payloads was off", a.Ordinal)
		}
		if len(a.CollaboratorPayloads) != 1 || !strings.HasSuffix(a.CollaboratorPayloads[0], ".oobtest.oast.example") {
			t.Fatalf("attempt %d collaborator_payloads = %v, want its one minted address", a.Ordinal, a.CollaboratorPayloads)
		}
		byAddress[a.CollaboratorPayloads[0]] = a.Ordinal
	}
	if len(byAddress) != 3 {
		t.Fatalf("the three attempts must carry three distinct addresses: %v", byAddress)
	}

	// A callback arrives after the attack, for the second attempt's address, in DNS-0x20 casing.
	var second string
	for addr, ord := range byAddress {
		if ord == view.Report.Attempts[1].Ordinal {
			second = addr
		}
	}
	channel.mu.Lock()
	channel.log = append(channel.log, oob.Interaction{Protocol: "dns", QType: "A", RemoteAddress: "198.51.100.7",
		RawRequest: "query " + strings.ToUpper(second[:4]) + second[4:]})
	channel.mu.Unlock()

	var got struct {
		Rows []struct {
			Payload string `json:"payload"`
		} `json:"rows"`
	}
	if err := decodeInto(getJSON(t, s, "/api/collaborator/interactions"), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Rows) != 1 || got.Rows[0].Payload != second {
		t.Fatalf("interaction rows = %+v, want one attributed to %q (attempt %d)", got.Rows, second, byAddress[second])
	}
}

func TestIntruderAttemptsWithoutACollaboratorSetOmitTheField(t *testing.T) {
	s := newTestServerWithScanner(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("seen")) }))
	defer origin.Close()
	host, port := hostPort(t, origin)
	id := putMessage(t, s, []byte(fmt.Sprintf("GET /?q=x HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port)), core.DirectionRequest)
	rec := postJSONRaw(t, s, "/api/intruder/run", fmt.Sprintf(`{
		"msg_id": %d, "target": "%s:%d", "mode": "sniper", "points": [0], "payload_sets": [["a", "b"]]
	}`, id, host, port))
	if rec.Code != http.StatusOK {
		t.Fatalf("run = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "collaborator_payloads") {
		t.Errorf("an attack with no Collaborator set still reports collaborator_payloads: %s", rec.Body.String())
	}
}
