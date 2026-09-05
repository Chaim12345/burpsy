package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// A row whose send produced an exchange carries that exchange's id on both tool-log routes, so
// Logger's message viewer can resolve the request/response bytes through the traffic store instead of
// the log keeping a copy. A row with no bytes behind it — a transport failure, a whole-run row — must
// send null, never 0: the traffic store counts rows from zero, so a 0 here would point the viewer at
// the first exchange ever captured, which is a real row.
func Test_tool_log_rows_carry_the_exchange_they_came_from(t *testing.T) {
	s := newTestServer()

	ex := &core.Exchange{Host: "h.test", Port: 80, Method: "GET", Path: "/from-exchange"}
	s.store.AddExchange(ex)
	linked := ex.ID

	s.toolLog.Record(toollog.ToolRepeater, "h.test", 80, false, "GET", "/from-exchange", 200, nil, 1, "", &linked)
	s.toolLog.Record(toollog.ToolRepeater, "h.test", 80, false, "GET", "/bare", 0, nil, 1, "send failed", nil)

	type row struct {
		Path     string  `json:"path"`
		Exchange *uint64 `json:"exchange"`
	}
	var got struct {
		Entries []row `json:"entries"`
	}
	rec := get(t, s, "/api/tools/log")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/tools/log: status = %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode tool log %q: %v", rec.Body.String(), err)
	}
	var bare, fromExchange *row
	for i := range got.Entries {
		switch got.Entries[i].Path {
		case "/bare":
			bare = &got.Entries[i]
		case "/from-exchange":
			fromExchange = &got.Entries[i]
		}
	}
	if bare == nil || fromExchange == nil {
		t.Fatalf("rows missing: bare = %+v, linked = %+v", bare, fromExchange)
	}
	if fromExchange.Exchange == nil || *fromExchange.Exchange != uint64(linked) {
		t.Fatalf("/from-exchange exchange = %v, want %d", fromExchange.Exchange, linked)
	}
	if bare.Exchange != nil {
		t.Fatalf("/bare exchange = %d, want null; a zero would point the viewer at exchange 0, which is a real row", *bare.Exchange)
	}
}
