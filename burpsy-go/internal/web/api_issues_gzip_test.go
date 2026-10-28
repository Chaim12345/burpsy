package web

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func gzipIssuesServer(n int) *Server {
	s := newTestServer()
	for i := 0; i < n; i++ {
		s.findings.Add(core.NewFinding{
			Name: fmt.Sprintf("Issue %d", i), Severity: core.SeverityLow, TaskID: 1,
			Target: core.FindingTarget{Host: "t.test", Port: 80, Path: fmt.Sprintf("/p%d", i)},
		})
	}
	return s
}

func getIssues(s *Server, path, enc string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if enc != "" {
		req.Header.Set("Accept-Encoding", enc)
	}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// A big summary list is compressed for a client that asks, and decodes to the same document.
func TestIssueSummaryIsGzippedWhenLargeAndAsked(t *testing.T) {
	s := gzipIssuesServer(gzipJSONMinRows + 10)
	plain := getIssues(s, "/api/issues?summary=1", "")
	if plain.Header().Get("Content-Encoding") != "" {
		t.Fatalf("no Accept-Encoding must stay identity")
	}
	rec := getIssues(s, "/api/issues?summary=1", "gzip, deflate")
	if rec.Header().Get("Content-Encoding") != "gzip" || rec.Header().Get("Vary") == "" {
		t.Fatalf("headers = %v", rec.Header())
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(zr)
	var a, b map[string]any
	if json.Unmarshal(raw, &a) != nil || json.Unmarshal(plain.Body.Bytes(), &b) != nil {
		t.Fatal("undecodable")
	}
	if len(a["findings"].([]any)) != len(b["findings"].([]any)) || a["counted"] != b["counted"] {
		t.Errorf("decoded gzip differs from identity body")
	}
	if rec.Body.Len() >= plain.Body.Len() {
		t.Errorf("gzip %d not smaller than %d", rec.Body.Len(), plain.Body.Len())
	}
}

func TestIssueGzipSkipsSmallListsCountAndFullDocument(t *testing.T) {
	small := gzipIssuesServer(5)
	smallRec := getIssues(small, "/api/issues?summary=1", "gzip")
	if smallRec.Header().Get("Content-Encoding") != "" {
		t.Error("a small list must not be compressed")
	}
	if smallRec.Header().Get("Vary") == "" {
		t.Error("the small identity variant must also say Vary: Accept-Encoding")
	}
	big := gzipIssuesServer(gzipJSONMinRows + 10)
	if getIssues(big, "/api/issues?count=1", "gzip").Header().Get("Content-Encoding") != "" {
		t.Error("count must not be compressed")
	}
	if getIssues(big, "/api/issues", "gzip").Header().Get("Content-Encoding") != "" {
		t.Error("only the summary list is compressed")
	}
}

// The Accept-Encoding matrix: q=0 refuses, "*" accepts, a longer token is not gzip, and both the
// compressed and the identity variant say Vary.
func TestIssueGzipAcceptEncodingMatrix(t *testing.T) {
	s := gzipIssuesServer(gzipJSONMinRows + 10)
	cases := map[string]bool{
		"gzip":                true,
		"GZIP":                true,
		"gzip;q=0":            false,
		"gzip;q=0.0":          false,
		"gzip;q=0.5":          true,
		"deflate, gzip;q=1.0": true,
		"identity":            false,
		"br":                  false,
		"*":                   true,
		"*;q=0":               false,
		"gzip;q=0, *":         false,
		"notgzip":             false,
		"gzipped":             false,
		"x-gzip":              true,
		"":                    false,
	}
	for header, want := range cases {
		rec := getIssues(s, "/api/issues?summary=1", header)
		got := rec.Header().Get("Content-Encoding") == "gzip"
		if got != want {
			t.Errorf("Accept-Encoding %q: gzip = %v, want %v", header, got, want)
		}
		if rec.Header().Get("Vary") == "" {
			t.Errorf("Accept-Encoding %q: response lacks Vary", header)
		}
	}
}
