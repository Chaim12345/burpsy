package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// Logger's view axes through the real route (burpsy-react-ui-uvpb): each axis narrows the rows a GET
// returns, switching it off brings every row back, and the capture filter is untouched.

func seedToolLogForView(t *testing.T) *Server {
	t.Helper()
	s := newTestServer()
	s.scope.AddInclude("in.test")

	html, json, none := "text/html", "application/json", ""
	// A form POST whose parameters live only in the body: the row's path has no query string, so only
	// the linked exchange's capture-time count can say it is parameterized.
	form := &core.Exchange{Host: "in.test", Port: 80, Method: "POST", Path: "/login", RequestParams: 2}
	s.store.AddExchange(form)
	formID := form.ID
	plain := &core.Exchange{Host: "in.test", Port: 80, Method: "GET", Path: "/about.html", RequestParams: 0}
	s.store.AddExchange(plain)
	plainID := plain.ID

	s.toolLog.RecordMime(toollog.ToolRepeater, "in.test", 80, false, "POST", "/login", 200, toollog.Bytes(10), 1, "", &formID, &html)
	s.toolLog.RecordMime(toollog.ToolRepeater, "in.test", 80, false, "GET", "/about.html", 200, toollog.Bytes(20), 1, "", &plainID, &html)
	s.toolLog.RecordMime(toollog.ToolRepeater, "in.test", 80, false, "GET", "/api/items.json?page=2", 200, toollog.Bytes(30), 1, "", nil, &json)
	s.toolLog.RecordMime(toollog.ToolRepeater, "out.test", 80, false, "GET", "/app.js", 200, toollog.Bytes(40), 1, "", nil, &none)
	s.toolLog.Record(toollog.ToolRepeater, "in.test", 80, false, "GET", "/down", 0, nil, 1, "send failed", nil)
	return s
}

func toolLogPaths(t *testing.T, s *Server, query string) []string {
	t.Helper()
	rec := get(t, s, "/api/tools/log"+query)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/tools/log%s: %d %s", query, rec.Code, rec.Body.String())
	}
	var got struct {
		Entries []struct {
			Path string  `json:"path"`
			Mime *string `json:"mime"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, e := range got.Entries {
		out = append(out, e.Path)
	}
	sort.Strings(out)
	return out
}

func Test_tool_log_view_axes_each_narrow_the_rows(t *testing.T) {
	s := seedToolLogForView(t)
	cases := []struct {
		query string
		want  []string
	}{
		{"", []string{"/about.html", "/api/items.json?page=2", "/app.js", "/down", "/login"}},
		{"?scope_only=1", []string{"/about.html", "/api/items.json?page=2", "/down", "/login"}},
		{"?has_response=1", []string{"/about.html", "/api/items.json?page=2", "/app.js", "/login"}},
		// /login is parameterized through its exchange's body count; items.json through its query.
		{"?parameterized=1", []string{"/api/items.json?page=2", "/login"}},
		{"?mime=application/json", []string{"/api/items.json?page=2"}},
		{"?mime=text/html,application/json", []string{"/about.html", "/api/items.json?page=2", "/login"}},
		{"?ext=.js", []string{"/app.js"}},
		{"?ext=html,json", []string{"/about.html", "/api/items.json?page=2"}},
		{"?scope_only=1&has_response=1&mime=text/html", []string{"/about.html", "/login"}},
	}
	for _, c := range cases {
		if got := toolLogPaths(t, s, c.query); strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%q: got %v, want %v", c.query, got, c.want)
		}
	}
}

// In-scope is judged against the scope as it is now: widening the scope re-includes a row without
// re-recording it — the view axis is reversible, unlike the capture filter.
func Test_tool_log_scope_axis_is_rejudged_when_the_scope_changes(t *testing.T) {
	s := seedToolLogForView(t)
	if got := toolLogPaths(t, s, "?scope_only=1"); strings.Contains(strings.Join(got, ","), "/app.js") {
		t.Fatalf("out.test row shown before it is in scope: %v", got)
	}
	s.scope.AddInclude("out.test")
	if got := toolLogPaths(t, s, "?scope_only=1"); !strings.Contains(strings.Join(got, ","), "/app.js") {
		t.Fatalf("out.test row not shown after the scope widened: %v", got)
	}
}

// The new mime field marshals as a string, "" or null — three different facts, never collapsed.
func Test_tool_log_rows_carry_mime_as_marshalled(t *testing.T) {
	s := seedToolLogForView(t)
	raw := get(t, s, "/api/tools/log").Body.String()
	for _, want := range []string{`"mime":"text/html"`, `"mime":""`, `"mime":null`} {
		if !strings.Contains(raw, want) {
			t.Errorf("marshalled log lacks %s", want)
		}
	}
}
