package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Save entire history (burpsy-react-ui-pznm), driven through POST /api/repeater/history-export and
// asserted on the marshalled file the route returns.

type historyFileWire struct {
	Format    string `json:"format"`
	Tab       string `json:"tab"`
	Requested int    `json:"requested"`
	Exported  int    `json:"exported"`
	Entries   []struct {
		Index           int     `json:"index"`
		RequestBase64   string  `json:"request_base64"`
		ResponseBase64  *string `json:"response_base64"`
		ResponseLength  int     `json:"response_length"`
		Status          int     `json:"status"`
		ResponseMissing string  `json:"response_missing"`
	} `json:"entries"`
	Skipped []struct {
		Index  int    `json:"index"`
		Reason string `json:"reason"`
	} `json:"skipped"`
	MissingResponses int `json:"missing_responses"`
}

func TestSaveEntireHistoryRoundTripsABinaryBodyByteForByte(t *testing.T) {
	s := newTestServer()
	// A response body that is not UTF-8: exactly what the browser's string copy cannot carry.
	binary := []byte{0x00, 0x01, 0xff, 0xfe, 0x80, 'o', 'k', 0xc3}
	respRaw := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/grpc\r\nContent-Length: 8\r\n\r\n"), binary...)
	reqRaw := []byte("POST /svc HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n\x08\x96")
	reqID, _ := s.store.Put(reqRaw, core.DirectionRequest)
	respID, _ := s.store.Put(respRaw, core.DirectionResponse)
	r1, r2 := uint64(reqID), uint64(respID)

	rec := postJSON(t, s, "/api/repeater/history-export", map[string]any{
		"tab":     "gRPC / call #1",
		"target":  "https://h:443",
		"entries": []map[string]any{{"request_msg_id": r1, "response_msg_id": r2, "kind": "http"}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Disposition"); got != `attachment; filename="repeater-history-gRPC-call-1.json"` {
		t.Fatalf("Content-Disposition = %q, want a sanitised attachment filename", got)
	}
	var file historyFileWire
	if err := json.Unmarshal(rec.Body.Bytes(), &file); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if file.Format != "burpsy-repeater-history/1" || file.Requested != 1 || file.Exported != 1 || len(file.Entries) != 1 {
		t.Fatalf("file = %+v, want one exported entry under the declared format", file)
	}
	gotReq, _ := base64.StdEncoding.DecodeString(file.Entries[0].RequestBase64)
	if !bytes.Equal(gotReq, reqRaw) {
		t.Fatalf("request bytes = %q, want %q", gotReq, reqRaw)
	}
	if file.Entries[0].ResponseBase64 == nil {
		t.Fatal("response_base64 is null for an entry whose response is stored")
	}
	gotResp, _ := base64.StdEncoding.DecodeString(*file.Entries[0].ResponseBase64)
	if !bytes.Equal(gotResp, respRaw) {
		t.Fatalf("response bytes = %x, want %x — the binary body must round-trip exactly", gotResp, respRaw)
	}
	if file.Entries[0].Status != 200 || file.Entries[0].ResponseLength != len(respRaw) {
		t.Fatalf("status/length = %d/%d", file.Entries[0].Status, file.Entries[0].ResponseLength)
	}
}

func TestSaveEntireHistoryCountsWhatItCouldNotExport(t *testing.T) {
	s := newTestServer()
	reqID, _ := s.store.Put([]byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n"), core.DirectionRequest)
	r := uint64(reqID)
	missing := uint64(9_999)

	rec := postJSON(t, s, "/api/repeater/history-export", map[string]any{
		"tab": "t",
		"entries": []map[string]any{
			{"request_msg_id": r, "kind": "http"}, // 0: no response recorded
			{"kind": "ws"},                        // 1: a WebSocket send
			{"request_msg_id": missing, "response_msg_id": r, "kind": "http"}, // 2: request not stored
			{"request_msg_id": r, "response_msg_id": missing, "kind": "http"}, // 3: response not stored
			{"kind": "http"}, // 4: no ids at all
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d: %s", rec.Code, rec.Body.String())
	}
	var file historyFileWire
	json.Unmarshal(rec.Body.Bytes(), &file)
	if file.Requested != 5 || file.Exported != 2 || len(file.Skipped) != 3 || file.MissingResponses != 2 {
		t.Fatalf("requested/exported/skipped/missing = %d/%d/%d/%d, want 5/2/3/2", file.Requested, file.Exported, len(file.Skipped), file.MissingResponses)
	}
	wantSkipped := map[int]string{1: "WebSocket", 2: "request message 9999 is not in the store", 4: "no stored request"}
	for _, skip := range file.Skipped {
		if want, ok := wantSkipped[skip.Index]; !ok || !strings.Contains(skip.Reason, want) {
			t.Fatalf("skip %+v, want one of %v", skip, wantSkipped)
		}
	}
	if file.Entries[0].Index != 0 || file.Entries[0].ResponseBase64 != nil || file.Entries[0].ResponseMissing == "" {
		t.Fatalf("entry 0 = %+v, want an exported request with its missing response named", file.Entries[0])
	}
	if file.Entries[1].Index != 3 || !strings.Contains(file.Entries[1].ResponseMissing, "9999") {
		t.Fatalf("entry for index 3 = %+v, want response_missing naming message 9999", file.Entries[1])
	}
}

func TestSaveEntireHistoryOfAnEmptyTabIsEmptyListsNotNull(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/repeater/history-export", map[string]any{"tab": "", "entries": []any{}})
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"entries":[]`) || !strings.Contains(body, `"skipped":[]`) {
		t.Fatalf("empty export = %s, want entries and skipped as [] not null", body)
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, `repeater-history-tab.json`) {
		t.Fatalf("an unnamed tab's filename = %q", got)
	}
}

func TestSaveEntireHistoryRefusesAnUnboundedExport(t *testing.T) {
	s := newTestServer()
	entries := make([]map[string]any, maxHistoryExportEntries+1)
	for i := range entries {
		entries[i] = map[string]any{"kind": "ws"}
	}
	rec := postJSON(t, s, "/api/repeater/history-export", map[string]any{"entries": entries})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "at most 10000") {
		t.Fatalf("oversized export = %d %q", rec.Code, rec.Body.String())
	}
}
