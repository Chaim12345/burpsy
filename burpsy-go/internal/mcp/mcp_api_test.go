package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/web"
)

// consoleOver starts a real gated console over a store the test can write to.
func consoleOver(t *testing.T, store *core.TrafficStore) string {
	t.Helper()
	srv := web.NewServer(store, core.NewScope())
	ts := httptest.NewServer(srv.MCPGuarded())
	t.Cleanup(ts.Close)
	return ts.URL
}

// putExchange records one GET exchange the way the proxy would and returns its id.
func putExchange(t *testing.T, store *core.TrafficStore, host, path string) core.ExchangeID {
	t.Helper()
	id, err := store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	status := uint16(200)
	store.AddExchange(&core.Exchange{Request: core.MsgPtr(id), Host: host, Port: 80, Method: "GET", Path: path, Status: &status})
	all := store.Exchanges()
	return all[len(all)-1].ID
}

// MCP-level tests for the API additions of 2jrr.1 phase 2, through the real stdio session against a
// real gated console.

// z5z3: "is this URL in scope" through the scope_check tool.
func TestScopeCheckThroughTheMCPTool(t *testing.T) {
	srv, base := newConsole(t)
	_ = srv
	res := callGrouped(t, base, "scope_check", map[string]any{
		"op":   "POST /api/scope/check",
		"body": map[string]any{"urls": []string{"https://app.test/x", "gopher://app.test/"}},
	})
	if res.IsError {
		t.Fatalf("scope_check failed: %s", textOf(res))
	}
	var view struct {
		Results []struct {
			InScope     bool            `json:"in_scope"`
			Reason      string          `json:"reason"`
			Error       string          `json:"error"`
			MatchedRule json.RawMessage `json:"matched_rule"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(bodyLine(t, textOf(res))), &view); err != nil {
		t.Fatalf("%v\n%s", err, textOf(res))
	}
	if len(view.Results) != 2 || !view.Results[0].InScope || view.Results[0].Reason != "no_include_rules" ||
		string(view.Results[0].MatchedRule) != "null" || view.Results[1].Error == "" {
		t.Fatalf("unexpected verdicts: %+v", view.Results)
	}
	// GET with the url query parameter.
	res = callGrouped(t, base, "scope_check", map[string]any{"op": "GET /api/scope/check", "query": map[string]string{"url": "http://app.test/"}})
	if res.IsError || !strings.Contains(textOf(res), `"in_scope":true`) {
		t.Fatalf("GET scope_check: %s", textOf(res))
	}
}

// 4bfp: record a captured exchange into the site map through the sitemap_record tool.
func TestSitemapRecordThroughTheMCPTool(t *testing.T) {
	store := core.NewTrafficStore()
	base := consoleOver(t, store)
	id := putExchange(t, store, "rec.test", "/r")
	res := callGrouped(t, base, "sitemap_record", map[string]any{"body": map[string]any{"exchange_id": id}})
	if res.IsError || !strings.Contains(textOf(res), `"already_on_map":true`) || !strings.Contains(textOf(res), `"exchange_id":`) {
		t.Fatalf("sitemap_record: %s", textOf(res))
	}
	res = callGrouped(t, base, "sitemap_record", map[string]any{"body": map[string]any{"exchange_id": 4242}})
	if !res.IsError || !strings.Contains(textOf(res), "HTTP 404") {
		t.Fatalf("an unknown id was not a 404: %s", textOf(res))
	}
}

// yahm: a body over the 1 MiB result cap is read to its last byte through windowed reads over
// tools/call — the whole-message read is cut, the windows are not.
func TestA3MiBBodyIsReadPastTheResultCapThroughWindows(t *testing.T) {
	store := core.NewTrafficStore()
	base := consoleOver(t, store)
	body := make([]byte, 3<<20)
	for i := range body {
		body[i] = byte(i*13 + i/509)
	}
	raw := append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 3145728\r\n\r\n"), body...)
	mid, err := store.Put(raw, core.DirectionResponse)
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprint(uint64(mid))

	whole := callGrouped(t, base, "history", map[string]any{"op": "GET /api/message/{id}", "id": id})
	if !strings.Contains(textOf(whole), "truncated at") {
		t.Fatal("a 3 MiB message read whole was not cut at the cap; this test's premise is gone")
	}

	var got []byte
	offset := 0
	for calls := 0; ; calls++ {
		if calls > 60 {
			t.Fatal("more windows than a 3 MiB body can need")
		}
		res := callGrouped(t, base, "history", map[string]any{
			"op": "GET /api/message/{id}", "id": id,
			"query": map[string]string{"byte_offset": fmt.Sprint(offset), "max_bytes": "65536"},
		})
		if res.IsError || strings.Contains(textOf(res), "truncated at") {
			t.Fatalf("window at %d: %.300s", offset, textOf(res))
		}
		var w struct {
			WindowBase64 string `json:"window_base64"`
			NextOffset   *int   `json:"next_offset"`
		}
		if err := json.Unmarshal([]byte(bodyLine(t, textOf(res))), &w); err != nil {
			t.Fatalf("window at %d is not the window view: %v", offset, err)
		}
		chunk, err := base64.StdEncoding.DecodeString(w.WindowBase64)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, chunk...)
		if w.NextOffset == nil {
			break
		}
		offset = *w.NextOffset
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("reassembled %d bytes, stored body is %d; they differ", len(got), len(body))
	}
}

// co88: a long history is paged to its last row through the datasets tool, past where a whole-list
// read is cut at the result cap.
func TestALongHistoryIsPagedToItsLastRowThroughTheDatasetsTool(t *testing.T) {
	store := core.NewTrafficStore()
	base := consoleOver(t, store)
	long := "/" + strings.Repeat("p", 900)
	const n = 1500
	for i := 0; i < n; i++ {
		putExchange(t, store, "long.test", fmt.Sprintf("%s/%d", long, i))
	}
	whole := callGrouped(t, base, "history", map[string]any{"op": "GET /api/history", "query": map[string]string{"limit": "100000"}})
	if !strings.Contains(textOf(whole), "truncated at") {
		t.Fatal("the whole history fits in one result; this test's premise is gone")
	}
	seen := 0
	offset := 0
	for page := 0; ; page++ {
		if page > 10 {
			t.Fatal("too many pages")
		}
		res := callGrouped(t, base, "datasets", map[string]any{
			"op": "GET /api/datasets/", "id": "history",
			"query": map[string]string{"limit": "500", "offset": fmt.Sprint(offset), "return_columns": "id"},
		})
		if res.IsError || strings.Contains(textOf(res), "truncated at") {
			t.Fatalf("page at %d: %.300s", offset, textOf(res))
		}
		var view struct {
			Rows []struct {
				ID int `json:"id"`
			} `json:"rows"`
			NextOffset *int `json:"next_offset"`
		}
		if err := json.Unmarshal([]byte(bodyLine(t, textOf(res))), &view); err != nil {
			t.Fatal(err)
		}
		for _, r := range view.Rows {
			if r.ID != seen {
				t.Fatalf("row %d has id %d", seen, r.ID)
			}
			seen++
		}
		if view.NextOffset == nil {
			break
		}
		offset = *view.NextOffset
	}
	if seen != n {
		t.Fatalf("paged %d rows of %d", seen, n)
	}
}

// vuxy: a structured, edited send previewed through the send tool — nothing leaves the process.
func TestAnEditedSendIsPreviewedThroughTheSendTool(t *testing.T) {
	store := core.NewTrafficStore()
	base := consoleOver(t, store)
	raw := "GET /a?x=1 HTTP/1.1\r\nHost: t.test\r\n\r\n"
	mid, err := store.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	res := callGrouped(t, base, "send", map[string]any{"op": "POST /api/repeater/send", "body": map[string]any{
		"from_message": uint64(mid), "target": "http://t.test:80", "dry_run": true, "http_version": "1.1",
		"edits": []map[string]any{{"op": "set_query_param", "name": "x", "value": "2"}, {"op": "set_header", "name": "X-Test", "value": "1"}},
	}})
	if res.IsError || !strings.Contains(textOf(res), `"request":"GET /a?x=2 HTTP/1.1\r\nHost: t.test\r\nX-Test: 1\r\n\r\n"`) {
		t.Fatalf("the preview is not the edited request: %s", textOf(res))
	}
	bad := callGrouped(t, base, "send", map[string]any{"op": "POST /api/repeater/send", "body": map[string]any{
		"from_message": uint64(mid), "target": "http://t.test:80", "dry_run": true,
		"edits": []map[string]any{{"op": "set_header", "nme": "X"}},
	}})
	if !bad.IsError || !strings.Contains(textOf(bad), `unknown field "nme"`) {
		t.Fatalf("a misspelled edit field was not refused: %s", textOf(bad))
	}
}
