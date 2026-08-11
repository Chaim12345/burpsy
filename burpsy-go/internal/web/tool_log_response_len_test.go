package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"go.uber.org/zap"
)

// HONEST-04.
//
// Every row on both tool-log routes used to report a response length of zero. The cause was deeper
// than a bad constant: toollog.Entry had no length field and Record took no such argument, so the wire
// projection in toolLogEntryView had nothing to project and filled in a literal 0. Logger's Length
// column therefore read as "every response was empty" on a pane whose entire job is reconciling what
// one of burpsy's tools sent against what came back.
//
// Two facts have to stay apart for the fix to be worth anything, which is what this test pins:
//
//   - a send that got a response reports that response's real byte count;
//   - a send that got no response reports null, not 0. Roughly half the Record call sites are error
//     paths, and a 0 there would be the same lie in a new place — a measurement nobody made.
//
// The expected length is taken from the response the repeater handler itself returned rather than
// written down as a number, so the assertion cannot pass against a length that happens to match a
// constant while the plumbing carries something else entirely.
//
// Both /api/tools/log and /api/dashboard are covered because both were wrong. They now share
// toolLogEntryView, but they did not always, and fixing one while the other kept sending zeroes would
// leave the Dashboard pane lying about the same rows the Logger tab told the truth about.
func Test_tool_log_rows_carry_the_response_length_they_actually_received_HONEST_04(t *testing.T) {
	body := "the body an operator is trying to size up, which is not zero bytes long"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer target.Close()

	// A second listener, taken and then shut down, gives an authority that resolves and refuses. That
	// is the error path: a real target, no response.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	s := newTestServer()
	liveHost, livePort := targetHostPort(t, target.URL)
	deadHost, deadPort := targetHostPort(t, deadURL)
	for _, host := range []string{liveHost, deadHost} {
		if rec := postJSON(t, s, "/api/scope", map[string]string{"action": "include", "pattern": host}); rec.Code != http.StatusOK {
			t.Fatalf("include %s in scope: status = %d", host, rec.Code)
		}
	}

	send := func(host string, port uint16, path string) *httptest.ResponseRecorder {
		authority := fmt.Sprintf("%s:%d", host, port)
		return postJSON(t, s, "/api/repeater/send", map[string]any{
			"target":  authority,
			"request": "GET " + path + " HTTP/1.1\r\nHost: " + authority + "\r\nConnection: close\r\n\r\n",
		})
	}

	rec := send(liveHost, livePort, "/answered")
	if rec.Code != http.StatusOK {
		t.Fatalf("send to the live target: status = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	var sent struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode repeater response %q: %v", rec.Body.String(), err)
	}
	// The bytes the send actually returned, measured here rather than predicted. A guard against the
	// degenerate case where both the expectation and the row are zero and the test proves nothing.
	wantLen := len(sent.Response)
	if wantLen <= len(body) {
		t.Fatalf("the repeater returned %d bytes for a %d-byte body; the raw response should carry a status line and headers too",
			wantLen, len(body))
	}

	if rec := send(deadHost, deadPort, "/refused"); rec.Code != http.StatusBadGateway {
		t.Fatalf("send to the closed target: status = %d (%s), want 502 — the error path is what records a null length",
			rec.Code, rec.Body.String())
	}

	// Read the same two rows back through both routes. `response_len` is decoded into *int on purpose:
	// a plain int would silently turn the JSON null this test exists to require into a zero, which is
	// the very confusion under test.
	type row struct {
		Path        string `json:"path"`
		ResponseLen *int   `json:"response_len"`
	}
	routes := map[string]func() []row{
		"/api/tools/log": func() []row {
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
			return got.Entries
		},
		"/api/dashboard": func() []row {
			var got struct {
				Activity []row `json:"activity"`
			}
			rec := get(t, s, "/api/dashboard")
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /api/dashboard: status = %d", rec.Code)
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode dashboard %q: %v", rec.Body.String(), err)
			}
			return got.Activity
		},
	}

	for route, read := range routes {
		t.Run(route, func(t *testing.T) {
			rows := read()
			var answered, refused *row
			for i := range rows {
				switch rows[i].Path {
				case "/answered":
					answered = &rows[i]
				case "":
					// The failed send is logged before the request line is parsed, so it carries the
					// synthetic "SEND" method and an empty path. Identified by the absence of a path
					// rather than by position, so a change in ordering does not silently match the
					// wrong row.
					refused = &rows[i]
				}
			}
			if answered == nil || refused == nil {
				t.Fatalf("%s did not carry both rows: answered = %+v, refused = %+v", route, answered, refused)
			}
			if answered.ResponseLen == nil {
				t.Errorf("%s reports a null length for a send that received %d bytes; null means no response arrived",
					route, wantLen)
			} else if *answered.ResponseLen != wantLen {
				t.Errorf("%s reports response_len = %d, want %d — the length of the response the send actually returned",
					route, *answered.ResponseLen, wantLen)
			}
			if refused.ResponseLen != nil {
				t.Errorf("%s reports response_len = %d for a send that never got a response, want null; a zero here claims an empty response arrived",
					route, *refused.ResponseLen)
			}
		})
	}
}

// HONEST-04, durable half.
//
// The mirror has to keep the distinction the live log makes, or a restart converts it back into the
// defect: a null that reloads as 0 is a row inventing an empty response for a send that failed. The
// same applies to a database written before the column existed — such a row's length is unknown, and
// unknown is null.
func Test_a_restored_tool_log_row_keeps_an_unknown_response_length_unknown_HONEST_04(t *testing.T) {
	p, err := persist.Open(filepath.Join(t.TempDir(), "toollog.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer p.Close()

	log := toollog.New()
	log.SetPersistenceSink(p.SaveToolLog)
	measured := log.Record(toollog.ToolRepeater, "answered.test", 80, false, "GET", "/answered", 200,
		toollog.Bytes(4096), 7, "")
	// A measured zero, which is a response that arrived carrying nothing. It has to survive as a
	// number: collapsing it into null would lose a real measurement, the mirror image of the bug.
	empty := log.Record(toollog.ToolRepeater, "empty.test", 80, false, "GET", "/empty", 204,
		toollog.Bytes(0), 3, "")
	failed := log.Record(toollog.ToolRepeater, "refused.test", 80, false, "SEND", "", 0, nil, 0, "connection refused")

	restored := toollog.New()
	if err := p.Restore(nil, nil, nil, nil, nil, nil, restored); err != nil {
		t.Fatalf("restore: %v", err)
	}
	byID := map[uint64]*toollog.Entry{}
	for _, e := range restored.All() {
		byID[e.ID] = e
	}
	if len(byID) != 3 {
		t.Fatalf("restored %d rows, want the 3 that were recorded", len(byID))
	}

	// Rendered through lenStr, not with %v: ResponseLen is a *int, so %v prints the pointer address.
	// A failure message reading "restored as 0x184956f90e60, want 4096" tells the next reader nothing,
	// and this suite exists precisely so a wrong length is legible rather than merely detected.
	if got := byID[measured].ResponseLen; got == nil || *got != 4096 {
		t.Errorf("the measured length restored as %s, want 4096", lenStr(got))
	}
	if got := byID[empty].ResponseLen; got == nil || *got != 0 {
		t.Errorf("the measured zero restored as %s, want 0 — a response of no bytes is still a measurement", lenStr(got))
	}
	if got := byID[failed].ResponseLen; got != nil {
		t.Errorf("the unmeasured row restored as %d, want nil; a send that got no response must not come back claiming an empty one", *got)
	}
}

// lenStr renders a nullable response length the way the wire does: a number, or "null" when no
// response was received. Exists because %v on a *int prints an address, which turned a real assertion
// failure into an unreadable one.
func lenStr(n *int) string {
	if n == nil {
		return "null"
	}
	return strconv.Itoa(*n)
}
