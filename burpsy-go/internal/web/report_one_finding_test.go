package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// exiu item 3: the per-issue Report menu opened whole-scan exports, and report Evidence held only
// method, host, path and status — no bytes. The deliverable an assessor needs is the request that
// produced a finding and the response that came back; a scan-wide, metadata-only export means a
// single-issue report has to be assembled by hand.
//
// Nothing new is stored: an occurrence already names its request and response message ids, and the
// capture store already holds the bytes.

// oneFindingReport is the decoded /api/report/finding/{id}.
type oneFindingReport struct {
	ID       uint64 `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Evidence []struct {
		Host          string `json:"host"`
		Method        string `json:"method"`
		RequestMsgID  uint64 `json:"request_msg_id"`
		ResponseMsgID uint64 `json:"response_msg_id"`
	} `json:"evidence"`
	Messages []struct {
		ID  uint64 `json:"id"`
		Raw string `json:"raw"`
	} `json:"messages"`
	MessagesOmitted int `json:"messages_omitted"`
}

// The core property: the report for one finding carries the request and response that produced it,
// byte for byte. A report that names a message id and stops there is a reference, not evidence.
func TestASingleFindingReportCarriesTheBytesBehindIt(t *testing.T) {
	store := core.NewTrafficStore()
	id := requestMessage(t, store, "GET /admin?x=1 HTTP/1.1\r\nHost: app.test\r\n\r\n")

	fs := core.NewFindingStore()
	req := core.MsgId(id)
	fs.Add(core.NewFinding{
		Name:   "SQL injection",
		TaskID: 4,
		Target: core.FindingTarget{Host: "app.test", Path: "/admin"},
		Occurrences: []core.Occurrence{{
			ExchangeID: 0, Request: &req,
		}},
	})
	s := NewServer(store, core.NewScope()).WithFindings(fs)

	rec := get(t, s, "/api/report/finding/0")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out oneFindingReport
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Name != "SQL injection" {
		t.Errorf("name = %q, want the finding's own", out.Name)
	}
	if len(out.Evidence) == 0 {
		t.Fatal("the report carries no evidence; a description of a finding is not evidence for it")
	}
	if len(out.Messages) == 0 {
		t.Fatal("the report names where the finding was seen but carries none of the bytes, which is " +
			"the shape the bead is about")
	}
	var sawRequest bool
	for _, m := range out.Messages {
		if strings.Contains(m.Raw, "GET /admin?x=1") {
			sawRequest = true
		}
	}
	if !sawRequest {
		t.Errorf("no message carries the request; got %+v", out.Messages)
	}
}

// Every evidence entry's message ids must actually resolve, and the bytes must be the bytes — the
// id spaces are separate dense counters, so a mismatched lookup returns a real, unrelated message
// rather than an error. That is the silent-wrong-answer failure the id fields exist to make visible.
func TestEveryMessageIdInASingleFindingReportResolvesToItsOwnBytes(t *testing.T) {
	store := core.NewTrafficStore()
	first := core.MsgId(requestMessage(t, store, "GET /one HTTP/1.1\r\nHost: a.test\r\n\r\n"))
	second := core.MsgId(requestMessage(t, store, "POST /two HTTP/1.1\r\nHost: b.test\r\n\r\n"))

	fs := core.NewFindingStore()
	fs.Add(core.NewFinding{
		Name:   "Two places",
		Target: core.FindingTarget{Host: "a.test"},
		Occurrences: []core.Occurrence{
			{Request: msgPtr(first)},
			{Request: msgPtr(second)},
		},
	})
	s := NewServer(store, core.NewScope()).WithFindings(fs)

	rec := get(t, s, "/api/report/finding/0")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var out oneFindingReport
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Messages) != 2 {
		t.Fatalf("messages = %d, want 2 — one per occurrence", len(out.Messages))
	}
	// Each id must name ITS OWN message. A swap is the failure this asserts against, and it is
	// silent: both ids resolve, both carry a plausible request, and the report is quietly wrong.
	for _, m := range out.Messages {
		want := "/one"
		if m.ID == uint64(second) {
			want = "/two"
		}
		if !strings.Contains(m.Raw, want) {
			t.Errorf("message %d carries %q, which is not the message that id names (wanted %q)",
				m.ID, firstLine(m.Raw), want)
		}
	}
}

// msgPtr is the pointer form Occurrence wants. A bare MsgId cannot express "no request" -- its
// zero is the first message the project ever captured -- so the field is a pointer and this keeps
// that visible at every call site rather than scattering a nil check nobody will remember.
func msgPtr(id core.MsgId) *core.MsgId { return &id }

func firstLine(s string) string {
	if i := strings.Index(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	if len(s) > 40 {
		return s[:40]
	}
	return s
}

// Evidence that cannot be read is COUNTED, not dropped. A report that silently omits half its
// evidence reads as "there was no request", which is a claim about the target rather than about the
// capture, and the two lead an assessor to opposite conclusions.
func TestEvidenceThatCannotBeReadIsCountedRatherThanSilentlyDropped(t *testing.T) {
	store := core.NewTrafficStore()
	fs := core.NewFindingStore()
	// A message id the store does not hold: the capture has been evicted, or the id is stale.
	fs.Add(core.NewFinding{
		Name:   "Evicted",
		Target: core.FindingTarget{Host: "app.test"},
		Occurrences: []core.Occurrence{
			{Request: msgPtr(core.MsgId(9999))},
		},
	})
	s := NewServer(store, core.NewScope()).WithFindings(fs)

	rec := get(t, s, "/api/report/finding/0")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var out oneFindingReport
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Messages) != 0 {
		t.Errorf("messages = %d, want 0 — the store cannot produce that message", len(out.Messages))
	}
	if out.MessagesOmitted != 1 {
		t.Errorf("messages_omitted = %d, want 1; a report that drops unreadable evidence without saying "+
			"so reads as a finding with no request behind it", out.MessagesOmitted)
	}
}

// A finding that does not exist is a 404, not an empty report. "This finding produced nothing" and
// "this finding does not exist" are different answers, and a stale link must not read as a clean
// result.
func TestASingleFindingReportForAMissingFindingIsNotAnEmptyDocument(t *testing.T) {
	s := NewServer(core.NewTrafficStore(), core.NewScope()).WithFindings(core.NewFindingStore())
	rec := get(t, s, "/api/report/finding/42")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; an empty document for a deleted finding reads as a clean result", rec.Code)
	}
	rec = get(t, s, "/api/report/finding/not-a-number")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d for a non-numeric id, want 400", rec.Code)
	}
}

// The bulk exports must NOT start carrying bytes. A scan of a large project has thousands of rows
// and their request bodies between them; a report that inlined them would be unusable as a document
// and enormous on disk. The split is the reason the single-finding path exists at all.
func TestTheScanWideExportStillCarriesNoBytes(t *testing.T) {
	store := core.NewTrafficStore()
	requestMessage(t, store, "GET /wide HTTP/1.1\r\nHost: app.test\r\n\r\n")
	fs := core.NewFindingStore()
	id := uint64(0)
	req := core.MsgId(id)
	fs.Add(core.NewFinding{
		Name:        "Wide",
		Target:      core.FindingTarget{Host: "app.test", Path: "/wide"},
		Occurrences: []core.Occurrence{{Request: &req}},
	})
	s := NewServer(store, core.NewScope()).WithFindings(fs)

	rec := get(t, s, "/api/report/json")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, `"messages"`) {
		t.Error("the scan-wide JSON export carries a messages block; it must stay a summary, and the " +
			"bytes belong to the single-finding report")
	}
	if !strings.Contains(body, "request_msg_id") {
		t.Error("the scan-wide export does not name the message ids, so a reader holding a capture " +
			"cannot follow the reference themselves")
	}
}

// The two exports must not be able to describe the same finding differently — that is the whole
// reason reportRow was extracted.
func TestASingleFindingRowMatchesTheScanWideRowForTheSameFinding(t *testing.T) {
	store := core.NewTrafficStore()
	requestMessage(t, store, "GET /same HTTP/1.1\r\nHost: app.test\r\n\r\n")
	fs := core.NewFindingStore()
	req := core.MsgId(0)
	fs.Add(core.NewFinding{
		Name:        "Same finding",
		Severity:    core.SeverityHigh,
		Confidence:  core.ConfidenceFirm,
		Description: "the detail",
		Target:      core.FindingTarget{Host: "app.test", Path: "/same"},
		Occurrences: []core.Occurrence{{Request: &req}},
	})
	s := NewServer(store, core.NewScope()).WithFindings(fs)

	rec := get(t, s, "/api/report/finding/0")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var one oneFindingReport
	if err := json.Unmarshal(rec.Body.Bytes(), &one); err != nil {
		t.Fatalf("decode: %v", err)
	}
	rec = get(t, s, "/api/report/json")
	var wide struct {
		Findings []oneFindingReport `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &wide); err != nil {
		t.Fatalf("decode wide: %v", err)
	}
	if len(wide.Findings) != 1 {
		t.Fatalf("wide findings = %d, want 1", len(wide.Findings))
	}
	w := wide.Findings[0]
	if one.Name != w.Name || one.Severity != w.Severity {
		t.Errorf("single-finding report says %q/%q, scan-wide says %q/%q; two builders for one document "+
			"is how a finding describes itself differently in two exports",
			one.Name, one.Severity, w.Name, w.Severity)
	}
	if len(one.Evidence) != len(w.Evidence) {
		t.Errorf("evidence counts differ: %d vs %d", len(one.Evidence), len(w.Evidence))
	}
}
