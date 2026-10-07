package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// exiu item 1 through the wire: POST /api/scanner/audit-items/{id}/cancel, Burp's
// auditItemContextMenuCancel (running-scans/results/audit-items/index.html:102-115).
//
// The point of the route is stopping ONE item, so the tests that matter are about which items it
// stops and — as much — which it leaves alone.

type cancelResp struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
	Item   *struct {
		State      string `json:"state"`
		Label      string `json:"status_label"`
		BurpStatus string `json:"burp_status"`
		Note       string `json:"note"`
		ExchangeID uint64 `json:"exchange_id"`
	} `json:"item"`
}

func cancelItem(t *testing.T, s *Server, id uint64) (int, cancelResp) {
	t.Helper()
	rec := postJSON(t, s, "/api/scanner/audit-items/"+u64(id)+"/cancel", map[string]any{})
	var out cancelResp
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func u64(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// withQueueServer builds a server whose audit queue is the given ledger.
//
// The ledger is a Server field rather than a With* option — withAuditItems is a config decorator,
// not a constructor — so a test that needs its own queue sets it the one way there is.
func withQueueServer(ledger *scanner.AuditItemLedger) *Server {
	s := newTestServer()
	s.auditItems = ledger
	return s
}

// The route works and answers with the refreshed row, so a client does not have to re-list to see
// the cancel it just caused — the same contract its sibling action keeps.
func TestCancellingAQueuedItemOverTheWire(t *testing.T) {
	ledger := scanner.NewAuditItemLedger(10)
	ledger.Enqueue(7, 5)
	s := withQueueServer(ledger)

	code, out := cancelItem(t, s, 7)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", code, out.Reason)
	}
	if out.Status != "ok" {
		t.Errorf("status = %q, want \"ok\"", out.Status)
	}
	if out.Item == nil {
		t.Fatal("no item in the reply; the caller would have to re-list to see its own action")
	}
	if out.Item.State != "cancelled" {
		t.Errorf("state = %q, want cancelled", out.Item.State)
	}
	if out.Item.BurpStatus != "CANCELLED" {
		t.Errorf("burp_status = %q, want CANCELLED", out.Item.BurpStatus)
	}
}

// ONE item. This is the whole reason the control exists — the alternative was disabling the whole
// live task — so an endpoint that stopped more than it was asked to would be worse than none.
func TestCancellingOneItemLeavesTheOthersAlone(t *testing.T) {
	ledger := scanner.NewAuditItemLedger(10)
	ledger.Enqueue(1, 5)
	ledger.Enqueue(2, 5)
	ledger.Enqueue(3, 5)
	s := withQueueServer(ledger)

	if code, out := cancelItem(t, s, 2); code != http.StatusOK {
		t.Fatalf("status = %d: %s", code, out.Reason)
	}
	var cancelled, other int
	for _, row := range ledger.Items(0) {
		if row.ExchangeID == 2 {
			cancelled++
			continue
		}
		if row.State == scanner.ItemStateCancelled {
			other++
		}
	}
	if cancelled != 1 {
		t.Errorf("the named item is cancelled %d times, want 1", cancelled)
	}
	if other != 0 {
		t.Errorf("%d other item(s) were cancelled too; this control stops exactly one", other)
	}
}

// The refusals are 409s carrying a reason, not bare failures. An operator who clicks Cancel on a
// finished row has to learn it finished rather than seeing something fail.
func TestCancellingAnItemTheQueueDoesNotHoldIsAConflictNotASilentSuccess(t *testing.T) {
	ledger := scanner.NewAuditItemLedger(10)
	s := withQueueServer(ledger)

	code, _ := cancelItem(t, s, 999)
	if code != http.StatusConflict {
		t.Fatalf("status = %d for an item that is not queued, want 409", code)
	}
	// 409 and not 404: the route and the id are fine, the item is simply not in a cancellable state.
	// 404 would read as "this endpoint does not exist", which is a different problem to go and fix.
	if code == http.StatusNotFound {
		t.Error("a missing item answered 404, which reads as a missing endpoint rather than a live queue")
	}
}

// A non-numeric id is a 400, and exchange id 0 is a REAL id — these ids count from zero, so
// refusing 0 would make the very first capture of a session the one row that cannot be cancelled.
func TestCancellingRejectsANonNumericIdAndAcceptsZero(t *testing.T) {
	ledger := scanner.NewAuditItemLedger(10)
	ledger.Enqueue(0, 5)
	s := withQueueServer(ledger)

	if code, _ := cancelItem(t, s, 0); code != http.StatusOK {
		t.Errorf("status = %d for exchange 0, want 200; ids count from zero and 0 is the first capture",
			code)
	}
	rec := postJSON(t, s, "/api/scanner/audit-items/not-a-number/cancel", map[string]any{})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d for a non-numeric id, want 400", rec.Code)
	}
}

// And the sibling action is untouched: a cancel must not have cost the re-audit.
func TestTheReAuditActionStillWorks(t *testing.T) {
	// newTestServer already carries a store, and the message goes into it, so the re-audit has a
	// real exchange to run against — a re-audit of a missing one would answer 200 with a refusal
	// body and the test would pass for the wrong reason.
	s := newTestServer()
	id := requestMessage(t, s.store, "GET /still-works HTTP/1.1\r\nHost: app.test\r\n\r\n")
	ledger := scanner.NewAuditItemLedger(10)
	ledger.Enqueue(core.ExchangeID(id), 5)
	s.auditItems = ledger

	rec := postJSON(t, s, "/api/scanner/audit-items/"+u64(uint64(id))+"/again", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("audit again status = %d", rec.Code)
	}
	// And a bogus action is still a 404 naming both, so the refusal tells the operator what exists.
	rec = postJSON(t, s, "/api/scanner/audit-items/1/nonsense", map[string]any{})
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d for an unknown action, want 404", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "cancel") {
		t.Errorf("the 404 for an unknown action does not name the two that exist: %s", body)
	}
}
