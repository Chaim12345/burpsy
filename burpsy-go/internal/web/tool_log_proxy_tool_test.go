package web

import (
	"encoding/json"
	"net/http"
	"testing"
)

// The Logger page builds its tool filter's option list and its per-tool capture checkboxes from the
// histogram on this wire, which the handler seeds from toollog.ToolAll — so a tool absent from the
// map is a tool the operator can neither filter to nor switch off. Proxy traffic is recorded now
// (burpsy-react-ui-6dt); this is the other half of that, and it is the half that decides whether the
// operator can see, filter and stop the proxy rows at all.
func TestTheLogWireListsProxyBesideTheOtherTools(t *testing.T) {
	s := newTestServer()
	rec := get(t, s, "/api/tools/log")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/tools/log: status = %d", rec.Code)
	}
	var view struct {
		Counts    map[string]int  `json:"counts"`
		Capturing map[string]bool `json:"capturing"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := view.Counts["proxy"]; !ok {
		t.Errorf("counts has no %q key (%v) — the page's tool filter is built from this map, so proxy rows would be recorded and then unfilterable", "proxy", view.Counts)
	}
	if on, ok := view.Capturing["proxy"]; !ok || !on {
		t.Errorf("capturing[proxy] = %v (present %v), want true: Burp's capture filter carries a Proxy axis and every tool captures by default", on, ok)
	}
}
