package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- Organizer filter fields (burpsy-react-ui-k4r) ---------------------------------------------
//
// The filters themselves are a UI concern. What is tested here is the thing the UI cannot get right
// on its own: whether a row can be judged at all, and whether the three "empty" cases stay apart.
//
// The case worth the most attention is the last one. The organizer outlives the traffic store, so an
// item whose exchange has been evicted has no status, no MIME and no scope answer — and the tempting
// implementations both lie. Filtering it out hides a note the operator wrote, and defaulting it to
// zero/""/false makes it answer questions it cannot.

// organizerTestServer builds a server with a real store and an empty (allow-all) scope.
func organizerTestServer(t *testing.T) *Server {
	t.Helper()
	return NewServer(core.NewTrafficStore(), core.NewScope())
}

// captureExchange records one request/response pair and returns its id.
//
// Mime is set the way the proxy sets it — through core.MimeEssence over the real response bytes —
// rather than assigned directly, so a test asserting "text/html" from a "text/HTML; charset=utf-8"
// header is exercising the same stripping the capture path uses.
func captureExchange(t *testing.T, s *Server, host, path string, status uint16, contentType string) int {
	t.Helper()
	req := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	res := "HTTP/1.1 " + strconv.Itoa(int(status)) + " OK\r\n"
	if contentType != "" {
		res += "Content-Type: " + contentType + "\r\n"
	}
	res += "Content-Length: 2\r\n\r\nhi"

	reqID, err := s.store.Put([]byte(req), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := s.store.Put([]byte(res), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	code := status
	ex := &core.Exchange{
		Host: host, Port: 443, TLS: true, Method: "GET", Path: path,
		Request: core.MsgPtr(reqID), Response: &respID, Status: &code,
		Mime: core.MimeEssence([]byte(res)),
	}
	s.store.AddExchange(ex)
	return int(ex.ID)
}

// captureRequestOnly records a request with no response, which is a real state — a request in
// flight, or one whose peer never answered — and not a status of zero.
func captureRequestOnly(t *testing.T, s *Server, host, path string) int {
	t.Helper()
	reqID, err := s.store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	ex := &core.Exchange{Host: host, Port: 443, TLS: true, Method: "GET", Path: path, Request: core.MsgPtr(reqID)}
	s.store.AddExchange(ex)
	return int(ex.ID)
}

// organizerRows drives the real handler and decodes what a browser would receive.
func organizerRows(t *testing.T, s *Server) []map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleOrganizer(rec, httptest.NewRequest(http.MethodGet, "/api/tools/organizer", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/tools/organizer = %d, body %q", rec.Code, rec.Body.String())
	}
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v — body %q", err, rec.Body.String())
	}
	return body.Items
}

// The ordinary case: a saved exchange resolves, and every field a filter needs is on the wire.
func TestOrganizerRowCarriesTheFieldsItsFiltersNeed(t *testing.T) {
	s := organizerTestServer(t)
	exchange := captureExchange(t, s, "app.test", "/admin", 200, "text/html; charset=utf-8")
	s.organizer.Add(exchange)

	rows := organizerRows(t, s)
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	row := rows[0]

	if row["resolved"] != true {
		t.Errorf("resolved = %v, want true for an exchange still in the store", row["resolved"])
	}
	if row["host"] != "app.test" {
		t.Errorf("host = %v", row["host"])
	}
	if row["status"] != float64(200) {
		t.Errorf("status = %v, want 200", row["status"])
	}
	// Parameters stripped and lowercased, so a MIME filter matches "text/html" rather than having to
	// know about charset spellings.
	if row["mime"] != "text/html" {
		t.Errorf("mime = %v, want text/html with parameters stripped", row["mime"])
	}
	if row["has_response"] != true {
		t.Errorf("has_response = %v, want true", row["has_response"])
	}
	if row["in_scope"] != true {
		t.Errorf("in_scope = %v; an empty scope allows everything, so a captured exchange is in it",
			row["in_scope"])
	}
}

// The organizer page (burpsy-react-ui-i3l) reads a saved item's bytes through these two ids, feeding
// them to the same GET /api/message/{id} History already uses. If either id is missing or wrong the
// page has no way to show what was saved — it would either render nothing or, worse, another
// exchange's message.
func TestOrganizerRowCarriesRequestAndResponseMessageIds(t *testing.T) {
	s := organizerTestServer(t)
	reqID, err := s.store.Put([]byte("GET /admin HTTP/1.1\r\nHost: app.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{Host: "app.test", Port: 443, TLS: true, Method: "GET", Path: "/admin", Request: core.MsgPtr(reqID), Response: &respID}
	s.store.AddExchange(ex)
	s.organizer.Add(int(ex.ID))

	row := organizerRows(t, s)[0]
	if got, want := row["request"], float64(reqID); got != want {
		t.Errorf("request = %v, want %v (the message store id, not the exchange id)", got, want)
	}
	if got, want := row["response"], float64(respID); got != want {
		t.Errorf("response = %v, want %v", got, want)
	}
}

// Message id 0 is the first message ever captured in a fresh store, and a bare `uint64` field with
// `omitempty` would drop it — the exact bug internal/web/api_types.go's ExchangeView.Request avoids
// by carrying no `omitempty` at all. organizerItemView.Request is a *uint64 for the same reason
// (unlike ExchangeView it also needs to express "no exchange to read the id from" for an unresolved
// row), and this pins that a real zero id still reaches the wire.
func TestOrganizerRowRequestZeroIsNotDroppedAsIfAbsent(t *testing.T) {
	s := organizerTestServer(t)
	exchange := captureRequestOnly(t, s, "app.test", "/first") // the store's very first message: id 0
	s.organizer.Add(exchange)

	rec := httptest.NewRecorder()
	s.handleOrganizer(rec, httptest.NewRequest(http.MethodGet, "/api/tools/organizer", nil))
	if !strings.Contains(rec.Body.String(), `"request":0`) {
		t.Fatalf("body = %q, want an explicit \"request\":0 rather than the field dropped", rec.Body.String())
	}

	row := organizerRows(t, s)[0]
	if got, present := row["request"]; !present || got != float64(0) {
		t.Errorf("request = %v (present=%v), want 0", got, present)
	}
	// No response was captured, so this must be the field the console reads to decide that,
	// distinct from a request id of 0.
	if _, present := row["response"]; present {
		t.Errorf("response present on a request-only exchange: %v", row["response"])
	}
}

// The Organizer's Tool column and filter-by-tool (burpsy-react-ui-ldfk) read core.Exchange.Source —
// the field the crawler/repeater/intruder/scanner already set at capture and never rewrite — rather
// than inventing a second notion of "which tool made this". Two rows: one a tool actually claimed,
// one nobody did, because the unattributed case (proxy traffic captured before Source existed, or
// simply never labelled) is the one most likely to be rendered as a blank cell by mistake.
func TestOrganizerRowCarriesTheOriginatingTool(t *testing.T) {
	s := organizerTestServer(t)

	reqID, err := s.store.Put([]byte("GET /a HTTP/1.1\r\nHost: app.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	attributed := &core.Exchange{Host: "app.test", Port: 443, TLS: true, Method: "GET", Path: "/a", Request: core.MsgPtr(reqID), Source: core.SourceIntruder}
	s.store.AddExchange(attributed)
	s.organizer.Add(int(attributed.ID))

	// captureExchange (above) never sets Source, so this is the zero value.
	s.organizer.Add(captureExchange(t, s, "app.test", "/b", 200, "text/html"))

	rows := organizerRows(t, s)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	byPath := map[string]map[string]any{}
	for _, row := range rows {
		path, _ := row["path"].(string)
		byPath[path] = row
	}
	if got := byPath["/a"]["tool"]; got != "intruder" {
		t.Errorf("tool = %v, want intruder", got)
	}
	// Named, not blank: an empty string here would be indistinguishable from the field never
	// having been sent, which is exactly the ambiguity Source.String() exists to remove.
	if got := byPath["/b"]["tool"]; got != "unattributed" {
		t.Errorf("tool = %v, want unattributed", got)
	}
}

// The row that cannot be judged. This is the whole reason `resolved` exists.
func TestAnOrganizerItemWhoseExchangeIsGoneIsShownAndMarkedUnresolved(t *testing.T) {
	s := organizerTestServer(t)
	// Never captured, so it resolves to nothing — the same state an evicted exchange reaches. Added
	// through the store directly because the POST handler correctly refuses an id it cannot resolve.
	s.organizer.Add(999_999)

	rows := organizerRows(t, s)
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1 — an item whose exchange is gone must still be listed: the "+
			"operator's note is the thing worth keeping and this row is the only place it appears",
			len(rows))
	}
	row := rows[0]

	if row["resolved"] != false {
		t.Errorf("resolved = %v, want false", row["resolved"])
	}
	// The three fields a filter would use must be ABSENT, not zero. A status of 0, an empty MIME and
	// in_scope=false are all answers, and this row has none to give. request/response join the list
	// for i3l: there is no message store id to read when there is no exchange to read it from, and a
	// present-but-zero id here would send the page fetching /api/message/0, which belongs to
	// whatever real message happens to sit at that position. tool joins it for ldfk: there is no
	// core.Exchange to read a Source off, and Source.String() never returns "" (see Tool's own
	// doc), so a present tool field here would always be a lie about a real origin.
	for _, field := range []string{"status", "mime", "in_scope", "host", "request", "response", "tool"} {
		if value, present := row[field]; present {
			t.Errorf("%s = %v on an unresolved row; it must be absent rather than a default, because "+
				"a default is indistinguishable from a real answer", field, value)
		}
	}
}

// "No response yet" must not read as a status or a MIME. Both are empty on the wire and only
// has_response separates them, which is exactly what the store's own documentation warns about.
func TestAnExchangeWithNoResponseIsNotAZeroStatus(t *testing.T) {
	s := organizerTestServer(t)
	s.organizer.Add(captureRequestOnly(t, s, "app.test", "/slow"))

	rows := organizerRows(t, s)
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	row := rows[0]

	if row["resolved"] != true {
		t.Fatalf("resolved = %v; the exchange is in the store, only its response is missing", row["resolved"])
	}
	if value, present := row["status"]; present {
		t.Errorf("status = %v for an exchange with no response; a request that never came back is "+
			"not a status of zero", value)
	}
	if row["has_response"] != false {
		t.Errorf("has_response = %v, want false", row["has_response"])
	}
	// And it is still judgeable for scope, because scope is about the request.
	if row["in_scope"] != true {
		t.Errorf("in_scope = %v; scope depends on the request, which exists", row["in_scope"])
	}
}

// A response that named no usable Content-Type: empty MIME, but a response all the same. Without
// has_response this is the same wire shape as the test above, and a MIME filter would treat a real
// response as a pending one.
func TestAResponseWithNoContentTypeIsDistinguishableFromNoResponse(t *testing.T) {
	s := organizerTestServer(t)
	exchange := captureExchange(t, s, "app.test", "/raw", 204, "")
	s.organizer.Add(exchange)

	row := organizerRows(t, s)[0]
	if row["has_response"] != true {
		t.Errorf("has_response = %v, want true — the response exists, it just named no media type",
			row["has_response"])
	}
	if value, present := row["mime"]; present && value != "" {
		t.Errorf("mime = %v, want absent or empty", value)
	}
	if row["status"] != float64(204) {
		t.Errorf("status = %v, want 204", row["status"])
	}
}

// Out-of-scope rows are reported as such rather than dropped, so the in-scope filter is the
// operator's choice and not something the server made for them.
func TestAnOutOfScopeExchangeIsReportedNotOmitted(t *testing.T) {
	s := organizerTestServer(t)
	// A scope with one include leaves everything else out.
	s.scope.AddInclude("allowed.test")

	inside := captureExchange(t, s, "allowed.test", "/a", 200, "text/html")
	outside := captureExchange(t, s, "other.test", "/b", 200, "text/html")
	s.organizer.Add(inside)
	s.organizer.Add(outside)

	rows := organizerRows(t, s)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want both — filtering is the console's decision, not this endpoint's",
			len(rows))
	}

	byHost := map[string]map[string]any{}
	for _, row := range rows {
		host, _ := row["host"].(string)
		byHost[host] = row
	}
	if got := byHost["allowed.test"]["in_scope"]; got != true {
		t.Errorf("allowed.test in_scope = %v, want true", got)
	}
	if got := byHost["other.test"]["in_scope"]; got != false {
		t.Errorf("other.test in_scope = %v, want false", got)
	}
}

// The list order is the operator's, not the server's.
func TestOrganizerOrderIsPreserved(t *testing.T) {
	s := organizerTestServer(t)
	var want []float64
	for _, path := range []string{"/third", "/first", "/second"} {
		exchange := captureExchange(t, s, "app.test", path, 200, "text/html")
		item := s.organizer.Add(exchange)
		want = append(want, float64(item.ID))
	}

	rows := organizerRows(t, s)
	if len(rows) != len(want) {
		t.Fatalf("got %d rows, want %d", len(rows), len(want))
	}
	for i, id := range want {
		if rows[i]["id"] != id {
			t.Errorf("row %d id = %v, want %v — the organizer is a list the operator built and this "+
				"endpoint must not re-sort it", i, rows[i]["id"], id)
		}
	}
}

// An empty organizer must serialise as an empty list, so a client cannot read "no field" as "no items".
func TestAnEmptyOrganizerSerialisesAsAnEmptyList(t *testing.T) {
	s := organizerTestServer(t)
	rec := httptest.NewRecorder()
	s.handleOrganizer(rec, httptest.NewRequest(http.MethodGet, "/api/tools/organizer", nil))
	if !strings.Contains(rec.Body.String(), `"items":[]`) {
		t.Errorf("body = %q, want an explicit empty items array rather than null", rec.Body.String())
	}
}
