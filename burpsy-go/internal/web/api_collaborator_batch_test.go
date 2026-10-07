package web

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/oob"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// The batch mint (burpsy-react-ui-v8q) is verified against the REAL public interactsh pool,
// not a fake: the oob package's own fixtures came from a live capture and its field names are
// pinned to the binary's actual -json output, so a fake channel would only prove the handler
// loops N times over a provider that returns a constant. The real binary, real registration,
// and real DNS announce prove the whole chain the operator actually exercises — including that
// a batch of N still shares ONE registration (one Interactsh session) and only the markers
// differ, which is the attribution contract this endpoint's marker_note documents.
//
// The test is skipped automatically when the binary, the network, or the registration is not
// available — the honest-failure contract this project runs on. When skipped it says so
// rather than passing silently: a skip line is visible in the verbose run, which is the point.
func TestTheCollaboratorBatchMintAgainstThePublicPool(t *testing.T) {
	if testing.Short() {
		t.Skip("live registration against the public interactsh pool; not a short-mode test")
	}
	// The comment above promises this skips when the binary is not available, and until
	// burpsy-react-ui-qcng it did not: it skipped only on -short, so a machine without
	// interactsh-client failed the whole internal/web package with `503: "interactsh-client" not
	// found on PATH`. That is the failure the honest-failure contract is supposed to prevent, and
	// it was reported as a package failure rather than a skip.
	if _, err := exec.LookPath("interactsh-client"); err != nil {
		t.Skip("interactsh-client is not on PATH; the live registration cannot run, and a skip is " +
			"the honest outcome here rather than a failure that reads as a broken handler")
	}

	// Real registration via the real binary and the real public pool (empty ServerURL = the
	// client's own default pool). The 45s bound covers the slow end of a real DNS round trip.
	provider := scanner.NewLazyOOBProvider(oob.Options{Timeout: 45 * time.Second})
	t.Cleanup(func() { _ = provider.Close() })

	s := newTestServerWithScanner(t)
	s.scanner.WithOOBProvider(provider)

	// Single mint: the contract the existing client reads — one "address" plus a 1-entry
	// "addresses" — must survive the batch change unchanged.
	single := mintPayload(t, s, `{}`)
	if single.Address == "" || len(single.Addresses) != 1 || single.Addresses[0] != single.Address {
		t.Fatalf("single mint should still carry the old address field and a 1-entry list, got address=%q addresses=%v",
			single.Address, single.Addresses)
	}

	// Batch of 3: three distinct addresses on the ONE registered domain, the legacy field
	// holding the first, and a marker per address — the marker is what attributes a callback,
	// so a batch that lost it would hand out addresses nobody could tell apart later.
	batch := mintPayload(t, s, `{"count":3}`)
	if len(batch.Addresses) != 3 || len(batch.Markers) != 3 {
		t.Fatalf("batch of 3 should mint 3 addresses and 3 markers, got %d/%d",
			len(batch.Addresses), len(batch.Markers))
	}
	domain := single.Domain
	if domain == "" {
		t.Fatal("the single mint reported no domain; cannot verify the batch shares the registration")
	}
	seen := map[string]bool{}
	for i, a := range batch.Addresses {
		if seen[a] {
			t.Fatalf("batch minted a duplicate address %q", a)
		}
		seen[a] = true
		if !strings.HasSuffix(a, "."+domain) {
			t.Fatalf("address %q is not on the registered domain %q", a, domain)
		}
		if !strings.HasPrefix(a, batch.Markers[i]+".") {
			t.Fatalf("address %q does not carry its own marker %q", a, batch.Markers[i])
		}
	}
	if batch.Addresses[0] != batch.Address {
		t.Fatalf("legacy address field should be the first of the batch, got %q vs %q",
			batch.Address, batch.Addresses[0])
	}

	// The batch lands in the hub the status reads, so the Collaborator page lists every
	// minted address — a batch the page then showed as one payload would be the honest-counting
	// defect this project refuses.
	if got := len(hubPayloads(t, s)); got != 4 {
		t.Fatalf("after a single mint and a batch of 3 the hub should hold 4 payloads, got %d", got)
	}

	// Ceiling: a count past the bound is refused with the bound named, not silently truncated —
	// truncation would hand the operator fewer addresses than the request implies and let a
	// script mint the rest one at a time. Refusal needs no channel, but this run holds one,
	// which is the stronger case: the bound must refuse even when minting would succeed.
	refused := postJSON(t, s, "/api/collaborator/payload", map[string]any{"count": 101})
	if refused.Code != http.StatusBadRequest {
		t.Fatalf("count 101 should be refused (bound is 100), got %d: %s",
			refused.Code, strings.TrimSpace(refused.Body.String()))
	}
	if !strings.Contains(refused.Body.String(), "100") {
		t.Fatalf("the refusal should name the bound, got: %s", strings.TrimSpace(refused.Body.String()))
	}
	if got := len(hubPayloads(t, s)); got != 4 {
		t.Fatalf("a refused mint must record nothing, but the hub now holds %d payloads", got)
	}
}

// mintPayload posts one mint request and decodes the response shape the Collaborator page reads.
func mintPayload(t *testing.T, s *Server, body string) (m struct {
	Address   string   `json:"address"`
	Addresses []string `json:"addresses"`
	Markers   []string `json:"markers"`
	Domain    string   `json:"domain"`
}) {
	t.Helper()
	rec := postJSONRaw(t, s, "/api/collaborator/payload", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/collaborator/payload %s = %d: %s", body, rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode mint response: %v", err)
	}
	return m
}

// hubPayloads reads the payload list the Collaborator page renders, decoded loosely enough that
// this test asserts the count and not the view's field spelling.
func hubPayloads(t *testing.T, s *Server) []map[string]any {
	t.Helper()
	rec := get(t, s, "/api/collaborator/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/collaborator/status = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var st struct {
		Payloads []map[string]any `json:"payloads"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	return st.Payloads
}
