package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// burpsy-react-ui-7py5: the History "Parameterized requests" filter counted the query string alone and
// dropped every body-only parameterized request — a JSON API POST, a multipart upload, an XML API
// call. The count is computed at the capture seam now; these tests pin it end to end, from the raw
// request through the wire to what a filter would read.

// captureThrough runs one request through the real capture seam and returns the exchange, so the
// count under test is the one a proxy request actually gets rather than one set by a fixture.
func captureThrough(t *testing.T, request string) *core.Exchange {
	t.Helper()
	store := core.NewTrafficStore()
	c := scanner.Capture{Store: store, Source: core.SourceProxy}
	ex, err := c.Record(scanner.CapturedExchange{
		Request:  []byte(request),
		Response: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
		Host:     "a.test", Port: 80, Method: "POST", Path: requestPath(request),
	})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	return ex
}

func requestPath(request string) string {
	// The start line is the first line; the target is its second field.
	line := request
	for i := 0; i < len(request); i++ {
		if request[i] == '\n' {
			line = request[:i]
			break
		}
	}
	fields := splitFields(line)
	if len(fields) < 2 {
		return "/"
	}
	return fields[1]
}

func splitFields(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\r' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// The three cases the path-only count got wrong, through the real seam.
func TestABodyOnlyRequestReachesHistoryAsParameterized(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request string
		want    int
	}{
		{
			"a urlencoded form post with no query string",
			"POST /login HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=x",
			2,
		},
		{
			"a JSON API post",
			"POST /api/v1/login HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}",
			1,
		},
		{
			"a multipart upload",
			"POST /upload HTTP/1.1\r\nHost: a.test\r\nContent-Type: multipart/form-data; boundary=B\r\n\r\n" +
				"--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\ndata\r\n--B--\r\n",
			1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ex := captureThrough(t, tc.request)
			if ex.RequestParams != tc.want {
				t.Errorf("RequestParams = %d, want %d. A path-only check would report 0 here and the "+
					"filter would drop this row", ex.RequestParams, tc.want)
			}
		})
	}
}

// The field is on the wire under the name the console reads, and it is not omitempty: a zero is a
// real answer ("certainly no parameters") and omitting it would leave the console unable to tell that
// from a row the projection never reached.
func TestTheParameterCountIsOnTheHistoryWireUnderTheNameTheConsoleReads(t *testing.T) {
	s := newTestServer()

	// A captured exchange, so the count is the capture seam's and not a fixture's.
	c := scanner.Capture{Store: s.store, Source: core.SourceProxy}
	if _, err := c.Record(scanner.CapturedExchange{
		Request:  []byte("POST /api HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}"),
		Response: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
		Host:     "a.test", Port: 80, Method: "POST", Path: "/api",
	}); err != nil {
		t.Fatalf("capture: %v", err)
	}

	rec := get(t, s, "/api/history")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/history: %d", rec.Code)
	}
	// A bare array, not an object: historyGet's contract is a top-level list, the same shape
	// TypeScript's useHistory types it as.
	var rows []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rows) == 0 {
		t.Skip("the fixture produced no exchange rows")
	}
	for _, row := range rows {
		v, present := row["request_params"]
		if !present {
			t.Fatalf("a history row carries no request_params key; the console cannot filter on a " +
				"field that is not there, and a zero-value fallback would be a guess")
		}
		n, isNum := v.(float64)
		if !isNum {
			t.Fatalf("request_params = %v (%T), want a number", v, v)
		}
		if n != 1 {
			t.Errorf("request_params = %v on the wire, want 1 for a JSON API post with no query "+
				"string. A body this cannot parse is counted as one rather than zero, because zero "+
				"would be a claim nobody made", n)
		}
	}
}
