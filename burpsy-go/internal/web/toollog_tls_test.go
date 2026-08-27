package web

// The tool log's TLS flag reaches the wire.
//
// toollog.Entry has carried `TLS bool` since the log existed. The wire projection dropped it, so
// Logger's "Copy URL (as logged)" and "Copy as curl" inferred the scheme from the port — the only
// honest guess available given the shape, and the pane's own comment said so. The consequence is that
// an HTTPS service on 8443 rendered and copied as `http://host:8443/…`, and an operator pasting that
// into a terminal or a report debugs their copy rather than their target.
//
// The test asserts the projection on BOTH routes that serve the log, because two projections of one
// row are what let started_ms go missing from one of them before.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/burpsy-go/burpsy/internal/toollog"
)

func TestToolLogWireCarriesTheTLSFlag(t *testing.T) {
	srv := newTestServer()
	// The exact failing case from the report: HTTPS on a non-443 port, plus a plaintext row on a port
	// that is not 80, so a projection that hardcoded either answer fails on one of them.
	srv.toolLog.Record(toollog.ToolRepeater, "api.example", 8443, true, "GET", "/v1/x", 200,
		toollog.Bytes(12), 5, "")
	srv.toolLog.Record(toollog.ToolRepeater, "plain.example", 8080, false, "GET", "/v1/y", 200,
		toollog.Bytes(12), 5, "")

	var log struct {
		Entries []struct {
			Host string `json:"host"`
			Port uint16 `json:"port"`
			TLS  bool   `json:"tls"`
		} `json:"entries"`
	}
	req := httptest.NewRequest(http.MethodGet, "/api/tools/log", nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("log status = %d, want 200", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &log); err != nil {
		t.Fatalf("decode: %v", err)
	}

	byHost := map[string]bool{}
	for _, e := range log.Entries {
		byHost[e.Host] = e.TLS
	}
	if len(byHost) != 2 {
		t.Fatalf("entries = %+v, want both rows", log.Entries)
	}
	if !byHost["api.example"] {
		t.Error("the https-on-8443 row is projected with tls=false, so Copy URL emits http:// for it")
	}
	if byHost["plain.example"] {
		t.Error("the plaintext row is projected with tls=true")
	}
}

func TestDashboardActivityCarriesTheTLSFlagToo(t *testing.T) {
	srv := newTestServer()
	srv.toolLog.Record(toollog.ToolRepeater, "api.example", 8443, true, "GET", "/v1/x", 200,
		toollog.Bytes(12), 5, "")

	var dashboard struct {
		Activity []struct {
			Host string `json:"host"`
			TLS  bool   `json:"tls"`
		} `json:"activity"`
	}
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d, want 200", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &dashboard); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(dashboard.Activity) == 0 {
		t.Fatal("no activity rows")
	}
	for _, row := range dashboard.Activity {
		if row.Host == "api.example" && !row.TLS {
			t.Error("the dashboard's activity row drops the TLS flag; the two projections of one log " +
				"row must not disagree")
		}
	}
}
