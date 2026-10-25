package scanner

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// existingQueryValues (Zr02's evidence source)
// ---------------------------------------------------------------------------

func TestExistingQueryValuesParsesQueryString(t *testing.T) {
	values := existingQueryValues("/search?q=hello&empty=&x=world")
	if len(values) != 2 || values[0] != "hello" || values[1] != "world" {
		t.Fatalf("got %v, want [hello world]", values)
	}
}

func TestExistingQueryValuesNoQueryString(t *testing.T) {
	if values := existingQueryValues("/search"); values != nil {
		t.Fatalf("path with no query string must yield no values, got %v", values)
	}
}

// ---------------------------------------------------------------------------
// linkAttributeReflection
// ---------------------------------------------------------------------------

func TestLinkAttributeReflectionDetectsHref(t *testing.T) {
	payload := "https://evil.invalid/x"
	body := `<a href="` + payload + `">click</a>`
	if attr := linkAttributeReflection(body, payload); attr != "href" {
		t.Fatalf("got %q, want href", attr)
	}
}

func TestLinkAttributeReflectionIgnoresPlainTextReflection(t *testing.T) {
	payload := "https://evil.invalid/x"
	body := "you searched for " + payload
	if attr := linkAttributeReflection(body, payload); attr != "" {
		t.Fatalf("plain-text reflection outside an attribute must not match, got %q", attr)
	}
}

func TestLinkAttributeReflectionDetectsFormAction(t *testing.T) {
	payload := "https://evil.invalid/submit"
	body := `<form action='` + payload + `'>`
	if attr := linkAttributeReflection(body, payload); attr != "formaction" && attr != "action" {
		t.Fatalf("got %q, want action or formaction", attr)
	}
}

// ---------------------------------------------------------------------------
// encodeHeaderInjectionSeparator (port of burp.Zw9s.Ze)
// ---------------------------------------------------------------------------

func TestEncodeHeaderInjectionSeparatorRawVariant(t *testing.T) {
	if got := encodeHeaderInjectionSeparator("\r\n", 0); got != "\r\n" {
		t.Fatalf("variant 0 must leave the separator unmodified, got %q", got)
	}
}

func TestEncodeHeaderInjectionSeparatorPercentVariant(t *testing.T) {
	if got := encodeHeaderInjectionSeparator("\r\n", 1); got != "%0d%0a" {
		t.Fatalf("got %q, want %%0d%%0a", got)
	}
}

func TestEncodeHeaderInjectionSeparatorNullPrefixVariant(t *testing.T) {
	if got := encodeHeaderInjectionSeparator("\r", 2); got != "\x00\r" {
		t.Fatalf("variant 2 must prepend a NUL byte, got %q", got)
	}
}

func TestPercentEncodeNonAlnumPreservesAlphanumerics(t *testing.T) {
	if got := percentEncodeNonAlnum("aB3"); got != "aB3" {
		t.Fatalf("alphanumeric input must pass through unchanged, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// evaluatedNotReflected (code injection evidence)
// ---------------------------------------------------------------------------

func TestEvaluatedNotReflectedRequiresAbsenceOfLiteralPayload(t *testing.T) {
	payload := "${6*7}"
	want := "42"
	if evaluatedNotReflected("result: "+want, want, payload) != true {
		t.Fatal("response containing only the evaluated product must count as evaluated")
	}
	if evaluatedNotReflected("echo: "+payload+" -> "+want, want, payload) != false {
		t.Fatal("response containing the literal payload alongside the product is a reflection, not evaluation")
	}
	if evaluatedNotReflected("nothing here", want, payload) != false {
		t.Fatal("response missing the product must not count as evaluated")
	}
}

// ---------------------------------------------------------------------------
// ssiEvaluated
// ---------------------------------------------------------------------------

func TestSSIEvaluatedRequiresTrueBranchOnlyAndNoLiteralDirective(t *testing.T) {
	trueToken, falseToken := "brptTRUE", "brpfFALSE"
	if !ssiEvaluated("prefix "+trueToken+" suffix", trueToken, falseToken) {
		t.Fatal("true branch alone, no directive text, must count as evaluated")
	}
	if ssiEvaluated(trueToken+" "+falseToken, trueToken, falseToken) {
		t.Fatal("both branches present means the server did not evaluate the conditional")
	}
	if ssiEvaluated(`<!--#if expr="1 = 1" -->`+trueToken, trueToken, falseToken) {
		t.Fatal("the literal directive surviving means the server did not process it as SSI")
	}
	if ssiEvaluated("neither token here", trueToken, falseToken) {
		t.Fatal("no evidence must not count as evaluated")
	}
}

// ---------------------------------------------------------------------------
// rawHeaderValue
// ---------------------------------------------------------------------------

// headerLookup used to live here, reading a parsed header map. It went when the open-redirect and
// header-injection rows moved onto ProbeHarness, which returns raw wire bytes — and a parsed map is
// the wrong shape for a check about header splitting, because parsing is exactly what normalises the
// split away.
func TestRawHeaderValueHandlesBareLFAndPrefersTheInjectedHeader(t *testing.T) {
	// CRLF-framed, the ordinary case.
	crlf := "HTTP/1.1 302 Found\r\nLocation: /home\r\nX-Burpsy-Canary: abcd\r\n\r\nbody"
	if got := rawHeaderValue(crlf, "X-Burpsy-Canary"); got != "abcd" {
		t.Errorf("CRLF: got %q, want abcd", got)
	}

	// Bare-LF framing. Two of the three header-injection separators produce this, so a CRLF-only
	// split made the majority of that row's probes unable to confirm.
	lf := "HTTP/1.1 200 OK\nX-Echo: tok\nX-Burpsy-Canary: abcd\n\nbody"
	if got := rawHeaderValue(lf, "X-Burpsy-Canary"); got != "abcd" {
		t.Errorf("bare LF: got %q, want abcd — a server that splits with LF alone has still split", got)
	}

	// Response splitting injects a SECOND Location after the legitimate one; the injected one is
	// where the browser goes and is what the caller is asking about.
	split := "HTTP/1.1 302 Found\r\nLocation: /home\r\nLocation: https://evil.example/\r\n\r\n"
	if got := rawHeaderValue(split, "Location"); got != "https://evil.example/" {
		t.Errorf("duplicated header: got %q, want the injected value", got)
	}

	// The body must not be searched, or a body mentioning a header name reads as a header.
	bodyOnly := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nLocation: https://evil.example/"
	if got := rawHeaderValue(bodyOnly, "Location"); got != "" {
		t.Errorf("body match: got %q, want empty — the header block ends at the blank line", got)
	}
}

// ---------------------------------------------------------------------------
// ReflectionProbeCheckDescriptors registration shape
// ---------------------------------------------------------------------------

func TestReflectionProbeCheckDescriptorsAreValidAndNative(t *testing.T) {
	descs := ReflectionProbeCheckDescriptors()
	if len(descs) != 6 {
		t.Fatalf("got %d descriptors, want 6", len(descs))
	}
	seen := make(map[uint32]struct{})
	for _, d := range descs {
		if d.Implementation != ImplementationNative {
			t.Errorf("%q is Implementation %q, want ImplementationNative", d.Name, d.Implementation)
		}
		if !d.Valid() || !d.Runnable() {
			t.Errorf("%q is not a valid, runnable descriptor", d.Name)
		}
		if _, dup := seen[d.TypeIndex]; dup {
			t.Errorf("duplicate TypeIndex %d in ReflectionProbeCheckDescriptors", d.TypeIndex)
		}
		seen[d.TypeIndex] = struct{}{}
	}
}

// ---------------------------------------------------------------------------
// redirectTargetHost (burpsy-react-ui-j1mk.36)
// ---------------------------------------------------------------------------

// The open-redirect proof is the host a browser would navigate to, so every row here is a Location
// value paired with where a WHATWG-conforming browser actually goes from http://app.example:8080/r.
func TestRedirectTargetHostResolvesTheWayABrowserDoes(t *testing.T) {
	const base = "http://app.example:8080/r?next=x"
	cases := []struct {
		location, want string
	}{
		{"http://evil.example/", "evil.example"},
		{"//evil.example/", "evil.example"},
		{"HTTP://Evil.Example/", "evil.example"},
		// The origin-prefix pattern: the app wrote its own authority, the value supplied userinfo.
		{"http://app.example:8080@evil.example/", "evil.example"},
		// Backslash is a separator for a special scheme or a scheme-less reference.
		{`/\evil.example/`, "evil.example"},
		{`\/evil.example/`, "evil.example"},
		{"https:evil.example", "evil.example"},
		{"/\t/evil.example", "evil.example"},
		{"  //evil.example", "evil.example"},
		// Same-origin targets that merely CONTAIN the external name.
		{"http://app.example:8080/@evil.example/", "app.example"},
		{`http://app.example:8080/\/evil.example`, "app.example"},
		{"/evil.example/", "app.example"},
		{`\aevil.example/`, "app.example"},
		{"/?u=//evil.example", "app.example"},
		{"@evil.example/", "app.example"},
	}
	for _, c := range cases {
		got, ok := redirectTargetHost(base, c.location)
		if !ok || got != c.want {
			t.Errorf("redirectTargetHost(%q) = %q, %v; want %q", c.location, got, ok, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// checkOpenRedirect finding attribution (burpsy-react-ui-j1mk.16)
// ---------------------------------------------------------------------------

// The parity harness matches burpsy's rows against ground truth on (endpoint, parameter): a
// redirect finding without the insertion point's name is an unmatched row even though the check
// fired. The check knows the point - the detail text already names it - so the finding must carry
// it in Param the way the row's detail does.
func TestOpenRedirectFindingNamesTheInsertionPoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := r.URL.Query().Get("url"); u != "" && u != "/home" {
			w.Header().Set("Location", u)
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "home")
	}))
	t.Cleanup(srv.Close)
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)
	store := core.NewTrafficStore()
	id := seedAuditExchange(t, store, host, uint16(port), "/redirect?url=/home", "home")
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: 30 * time.Second, CheckReflectionProbes: true})
	_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, DefaultAuditConfig())
	var f *Finding
	for _, x := range findings {
		if x.Name == openRedirectIssue {
			f = x
		}
	}
	if f == nil {
		t.Fatal("an endpoint that redirects to the injected host was not reported")
	}
	if f.Param != "url" {
		t.Fatalf("the redirect finding does not name its insertion point: got %q, want %q", f.Param, "url")
	}
}
