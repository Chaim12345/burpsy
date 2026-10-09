package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// ---- 7qc3: Grep - Payloads through POST /api/intruder/run -------------------------------------------

// The target decodes the URL-encoded payload and echoes it in its original form, which is the case
// Burp's "Match against pre-URL-encoded payloads" exists for. The listener proves the encoded bytes
// are what went out; the report proves only the pre-encoded match sees the echo.
func TestIntruderGrepPayloadsMatchesTheDecodedEchoOnlyWhenAskedTo(t *testing.T) {
	target := startCaptureTarget(t, func(req string) string {
		line := strings.SplitN(req, " ", 3)[1]
		u, err := url.Parse(line)
		if err != nil {
			return okResponse("bad request target")
		}
		return okResponse("results for " + u.Query().Get("q"))
	})
	raw := "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	srv, id, _ := intruderSendFixture(t, raw)
	start := strings.Index(raw, "alpha")
	run := func(grep map[string]any) (counts [][]int, reflected []bool) {
		t.Helper()
		var view struct {
			Report struct {
				Attempts []struct {
					Reflected       bool  `json:"reflected"`
					ReflectedCounts []int `json:"reflected_counts"`
				} `json:"attempts"`
				GrepPayloads map[string]bool `json:"grep_payloads"`
			} `json:"report"`
		}
		var body json.RawMessage
		if code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
			"msg_id": id, "target": "http://" + target.addr, "mode": "sniper",
			"manual_points":         []map[string]int{{"start": start, "end": start + len("alpha")}},
			"payload_sets":          [][]string{{"<b x>"}},
			"url_encode_characters": "<>",
			"grep_payloads":         grep,
			"rps":                   1000, "retries": 0,
		}, &body); code != http.StatusOK {
			t.Fatalf("run = %d: %s", code, body)
		}
		if err := json.Unmarshal(body, &view); err != nil {
			t.Fatal(err)
		}
		for k, v := range grep {
			if view.Report.GrepPayloads[k] != v {
				t.Fatalf("report.grep_payloads = %v, want it to echo %v", view.Report.GrepPayloads, grep)
			}
		}
		for _, a := range view.Report.Attempts {
			counts = append(counts, a.ReflectedCounts)
			reflected = append(reflected, a.Reflected)
		}
		return counts, reflected
	}

	counts, reflected := run(map[string]any{"enabled": true, "case_sensitive": true, "match_pre_url_encoded": true})
	if len(counts) != 1 || !reflected[0] || len(counts[0]) != 1 || counts[0][0] != 1 {
		t.Fatalf("pre-URL-encoded: counts %v reflected %v, want the decoded echo counted once", counts, reflected)
	}
	counts, reflected = run(map[string]any{"enabled": true, "case_sensitive": true, "match_pre_url_encoded": false})
	if len(counts) != 1 || reflected[0] || counts[0][0] != 0 {
		t.Fatalf("as sent: counts %v reflected %v, want the encoded payload not found in a decoded echo", counts, reflected)
	}
	for _, r := range target.requests() {
		if !strings.HasPrefix(r, "GET /search?q=%3Cb%20x%3E HTTP/1.1\r\n") {
			t.Fatalf("the listener received %q, want the URL-encoded payload on the wire", r)
		}
	}
}
