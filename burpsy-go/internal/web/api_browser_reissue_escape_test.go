package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The re-issue answer page (burpsy-react-ui-tvdg) interpolates TARGET-CONTROLLED data into HTML:
// the exchange's host and path come from a recorded request line, and a request line can carry
// `<svg/onload=...>`. The page is served from the console's own origin with
// Content-Type: text/html, so an unescaped value is script execution in the operator's session.
//
// The previous htmlEscape was strings.NewReplacer with IDENTITY pairs, so it returned its input
// unchanged and the call sites that used it escaped nothing.

func TestHTMLEscapeActuallyEscapes(t *testing.T) {
	// The named defect: a helper whose whole job is to escape must not return its input.
	if got := htmlEscape(`<svg/onload=alert(1)>`); got == `<svg/onload=alert(1)>` {
		t.Errorf("htmlEscape returned its input unchanged: the answer page would render the value as markup. "+
			"got %q", got)
	}
	// `&` legitimately survives — it is the first character of every entity the escaper emits — so
	// the assertion is on the characters that would start a tag or end an attribute, not on `&`.
	if got := htmlEscape(`<>"'`); strings.ContainsAny(got, `<>"'`) {
		t.Errorf("htmlEscape left a markup metacharacter in place: %q", got)
	}
	if got := htmlEscape("a & b"); got != "a &amp; b" {
		t.Errorf("a bare ampersand must be escaped before the others are appended, else the entities "+
			"this function emits would themselves be malformed: got %q", got)
	}
}

func TestTheAnswerPageNeverRendersAStoredPathAsMarkup(t *testing.T) {
	s := newTestServer()

	// A recorded exchange whose PATH is the payload. position-is-the-id means this is the shape a
	// request line produces, and nothing about recording it is unusual.
	payloadPath := "/<svg/onload=alert(1)>"
	reqID, err := s.store.Put([]byte("GET "+payloadPath+" HTTP/1.1\r\nHost: target.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	ex := &core.Exchange{
		Request: reqID, Host: "target.test", Port: 80, Method: "GET", Path: payloadPath, Source: core.SourceProxy,
	}
	s.store.AddExchange(ex)

	// Mint a token and fetch the answer page through the real handler path.
	token := s.reissueMint(ex.ID, "original")
	if token == "" {
		t.Fatal("no token minted")
	}
	req := httptest.NewRequest(http.MethodGet,
		"/reissue/"+token+"?variant=original", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	s.handleBrowserReissueFetch(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET the answer page = %d (%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "<svg/onload") {
		t.Errorf("the answer page served the stored path as live markup: %q", body)
	}
	if !strings.Contains(body, "&lt;svg") {
		t.Errorf("the answer page does not contain the escaped path at all, so the value was dropped "+
			"rather than escaped: %q", body)
	}
	// The page is served as HTML from the console's own origin, so its response type is part of
	// what makes the escaping necessary. Pin it so a future change that serves this as text/plain
	// is recognised as the defence it would be.
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q; this page is HTML on the console's own origin, and the escaping "+
			"above is what makes that safe", ct)
	}
}
