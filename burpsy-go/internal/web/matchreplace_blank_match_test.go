package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// burpsy-react-ui-wtm2 through the HTTP surface: the live PUT and the dry-run test endpoint
// refuse a blank match they cannot honour, name the rule and the reason (the console's toast
// shows this body verbatim), and leave the live set alone; a blank-match header rule is accepted
// and adds a header.

func TestMatchReplaceBlankMatchRefusalsReachTheCaller(t *testing.T) {
	cases := []struct{ name, rule, reason string }{
		{"body", `{"rule_type":"request_body","enabled":true,"string_match":"","string_replace":"x"}`, "only meaningful for a request or response header rule"},
		{"empty header", `{"rule_type":"request_header","enabled":true,"string_match":"","string_replace":""}`, "end the header block"},
		{"crlf header", `{"rule_type":"response_header","enabled":true,"string_match":"","string_replace":"X-A: 1\r\nX-B: 2"}`, "CR or LF"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer()
			good := `{"rule_type":"response_body","enabled":true,"string_match":"a","string_replace":"b"}`
			if rec := putRules(t, ts, `{"rules":[`+good+`]}`); rec.Code != http.StatusOK {
				t.Fatalf("setup PUT = %d %s", rec.Code, rec.Body.String())
			}
			rec := putRules(t, ts, `{"rules":[`+good+`,`+tc.rule+`]}`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("PUT = %d, want 400 (body %q)", rec.Code, rec.Body.String())
			}
			if body := rec.Body.String(); !strings.Contains(body, "Rule 1") || !strings.Contains(body, tc.reason) {
				t.Errorf("refusal %q does not name rule 1 and the reason %q", body, tc.reason)
			}
			if rules := ts.matchReplace.Rules(); len(rules) != 1 || rules[0].StringMatch != "a" {
				t.Fatalf("a refused PUT changed the live set: %+v", rules)
			}

			test := `{"input":"GET / HTTP/1.1\r\nHost: h\r\n\r\n","direction":"request","draft_rules":[` + tc.rule + `]}`
			req := httptest.NewRequest(http.MethodPost, "/api/tools/rules/test", strings.NewReader(test))
			trec := httptest.NewRecorder()
			ts.mux.ServeHTTP(trec, req)
			if trec.Code != http.StatusBadRequest || !strings.Contains(trec.Body.String(), "Draft rule 0") || !strings.Contains(trec.Body.String(), tc.reason) {
				t.Errorf("dry run = %d %q, want 400 naming draft rule 0 and %q", trec.Code, trec.Body.String(), tc.reason)
			}
		})
	}
}

func TestMatchReplaceBlankHeaderMatchAddsAHeaderThroughTheTestEndpoint(t *testing.T) {
	ts := newTestServer()
	rule := `{"rule_type":"request_header","enabled":true,"string_match":"","string_replace":"X-A: 1"}`
	if rec := putRules(t, ts, `{"rules":[`+rule+`]}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT of a blank-match header rule = %d %s, want 200", rec.Code, rec.Body.String())
	}
	test := `{"input":"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n","direction":"request","draft_rules":[` + rule + `]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tools/rules/test", strings.NewReader(test))
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("test endpoint = %d %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Changed bool `json:"changed"`
		Output  struct {
			Text string `json:"text"`
		} `json:"output"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if want := "GET / HTTP/1.1\r\nHost: example.com\r\nX-A: 1\r\n\r\n"; !got.Changed || got.Output.Text != want {
		t.Fatalf("output = %+v, want changed and %q", got, want)
	}
}
