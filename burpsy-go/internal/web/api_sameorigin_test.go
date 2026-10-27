package web

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// burpsy-react-ui-s19k: the console has no authentication, it is a tool that sends attacks, and it
// binds to loopback — which stops other hosts and not the operator's own browser, which visits hostile
// targets all day while burpsy runs.
//
// Every test here drives s.guarded, the handler ListenAndServe actually serves, rather than s.mux. A
// gate tested through the mux would be testing a field production never reads, which is the shape of
// a control that looks covered and is not.

// A hostile page's cross-origin POST is refused. This is the CSRF case: the operator's browser
// carries the request to 127.0.0.1:8081 and the server cannot tell who asked.
func TestACrossOriginPostCannotDriveTheConsole(t *testing.T) {
	s := newTestServer()
	for _, tc := range []struct {
		name   string
		origin string
	}{
		{"a hostile page", "https://evil.example"},
		{"another loopback origin", "http://localhost:3000"},
		{"a sandboxed iframe's null origin", "null"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/scope", bytes.NewReader([]byte(`{"add":["evil.example"]}`)))
			req.Host = "127.0.0.1:8081"
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			s.guarded.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; a page the operator visited added a scope rule "+
					"without them asking (body: %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// The attack that loopback binding does NOT stop, and the reason the Host check exists: a hostile
// domain that rebinds to 127.0.0.1 is same-origin to the BROWSER, so it sends no cross-origin Origin
// and a Sec-Fetch-Site of same-origin. Only the Host header betrays it.
func TestADomainThatRebindsToLoopbackIsRefusedOnItsOwnHostHeader(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/api/scope", bytes.NewReader([]byte(`{"add":["x"]}`)))
	req.Host = "rebind.evil.example:8081"
	// Both signals a rebinding browser would send are absent or benign, so only Host can catch this.
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; a domain that rebound to loopback wrote scope with a "+
			"same-origin Sec-Fetch-Site and no Origin header (body: %s)", rec.Code, rec.Body.String())
	}
}

// Sec-Fetch-Site is the browser's own signal and cannot be forged by page script, so it is checked on
// its own — a request that omits Origin entirely still has to satisfy it.
func TestACrossSiteSecFetchHeaderIsRefusedWithNoOriginHeaderAtAll(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/api/crawl", bytes.NewReader([]byte(`{"seeds":["http://x/"]}`)))
	req.Host = "127.0.0.1:8081"
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403; Sec-Fetch-Site: cross-site with no Origin header at all", rec.Code)
	}
}

// "none" is a user-initiated navigation — a typed URL or a bookmark. It is legitimately not
// same-origin, so refusing it would break the one thing the operator is certain they did.
func TestAUserInitiatedRequestIsNotRefusedForSayingNone(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/api/scope", bytes.NewReader([]byte(`{}`)))
	req.Host = "127.0.0.1:8081"
	req.Header.Set("Sec-Fetch-Site", "none")
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Error("a Sec-Fetch-Site of none was refused; that is a typed URL or a bookmark, and refusing " +
			"it makes the console unusable from a bookmark")
	}
}

// The gate must not break the console. A same-origin POST with no Origin header — which is what the
// console's own fetch() sends — has to work, or the fix is a denial of service rather than a defence.
func TestTheConsolesOwnRequestsStillWork(t *testing.T) {
	s := newTestServer()
	for _, tc := range []struct {
		name         string
		method       string
		path         string
		host         string
		secFetchSite string
		origin       string
	}{
		{"same-origin fetch with Sec-Fetch-Site", http.MethodPost, "/api/scope", "127.0.0.1:8081", "same-origin", ""},
		{"same-origin fetch without Sec-Fetch-Site", http.MethodPost, "/api/scope", "127.0.0.1:8081", "", ""},
		{"localhost", http.MethodPost, "/api/scope", "localhost:8081", "same-origin", ""},
		{"same-site", http.MethodPost, "/api/scope", "127.0.0.1:8081", "same-site", ""},
		{"an Origin that matches the Host", http.MethodPost, "/api/scope", "127.0.0.1:8081", "", "http://127.0.0.1:8081"},
		{"a GET, which cannot change state", http.MethodGet, "/api/history", "127.0.0.1:8081", "cross-site", ""},
		{"the CA certificate download", http.MethodGet, "/ca.crt", "127.0.0.1:8081", "cross-site", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader([]byte(`{}`)))
			req.Host = tc.host
			if tc.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			s.guarded.ServeHTTP(rec, req)

			if rec.Code == http.StatusForbidden {
				t.Errorf("the console's own %s %s was refused; the gate has broken the product it "+
					"protects", tc.method, tc.path)
			}
		})
	}
}

// A non-loopback bind is a deliberate operator choice, so naming the address is the deliberate step.
// Without naming it, a hostile page from anywhere is refused — which is the safe default.
func TestANonLoopbackBindWorksOnlyWhenTheOperatorNamesIt(t *testing.T) {
	body := `{"seeds":["http://127.0.0.1:1/"]}`

	// Unnamed: the host is not accepted.
	unconfigured := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/api/crawl", bytes.NewReader([]byte(body)))
	req.Host = "burp.internal:8081"
	rec := httptest.NewRecorder()
	unconfigured.guarded.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("an unnamed non-loopback Host was accepted with status %d; a console reachable off "+
			"this machine must not answer a caller it was not told about", rec.Code)
	}

	// Named: the same request is the operator's own browser.
	configured := newTestServer().WithAllowedHosts("burp.internal:8081")
	req2 := httptest.NewRequest(http.MethodPost, "/api/crawl", bytes.NewReader([]byte(body)))
	req2.Host = "burp.internal:8081"
	rec2 := httptest.NewRecorder()
	configured.guarded.ServeHTTP(rec2, req2)
	if rec2.Code == http.StatusForbidden {
		t.Errorf("the operator named the host and was still refused: %s", rec2.Body.String())
	}
}

// The refusal says what happened and how to avoid it, and says nothing about the console's routes or
// its version. A refusal that explained the control would tell an attacker probing for it exactly
// which header to try next.
func TestTheRefusalExplainsItselfAndLeaksNothing(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/api/crawl", bytes.NewReader([]byte(`{"seeds":["http://x/"]}`)))
	req.Host = "evil.example"
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "console") {
		t.Errorf("the refusal does not say what was refused: %q", body)
	}
	for _, leak := range []string{"Sec-Fetch", "Origin", "Host", "/api/", "allowed", "token"} {
		if strings.Contains(body, leak) {
			t.Errorf("the refusal names %q, which tells a caller probing for the control which header "+
				"or route to try next: %q", leak, body)
		}
	}
}

// The gate is installed over the FINISHED mux, so a route registered after it cannot be added
// outside it. This pins the installation point rather than the behaviour, because the behaviour is
// what the tests above check and the installation is what makes it hold for the next route.
func TestTheGateWrapsTheWholeMuxNotARegisteredSubset(t *testing.T) {
	s := newTestServer()
	if s.guarded == nil {
		t.Fatal("the guarded handler is nil, so ListenAndServe would serve the mux with no gate at all")
	}
	// A path that exists in the manifest but is not one these tests name, so the check is not
	// accidentally about the routes exercised above.
	req := httptest.NewRequest(http.MethodPost, "/api/tools/hash", bytes.NewReader([]byte(`{}`)))
	req.Host = "evil.example"
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d for a route no other test here names; the gate is not covering the "+
			"whole mux", rec.Code)
	}
}

// A refused request must not have reached the handler. A 403 produced AFTER the state changed would
// be the worst possible outcome: the attack succeeded and the operator was told it did not.
func TestARefusedRequestNeverReachesItsHandler(t *testing.T) {
	s := newTestServer()
	before := len(s.crawls.list())

	req := httptest.NewRequest(http.MethodPost, "/api/crawl", bytes.NewReader(
		[]byte(`{"seeds":["http://127.0.0.1:1/"]}`)))
	req.Host = "evil.example"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)

	if got := len(s.crawls.list()); got != before {
		t.Errorf("a refused request started a crawl anyway: %d runs, was %d. A 403 raised after the "+
			"handler ran would be the worst outcome — the attack succeeded and the operator was told "+
			"it did not", got, before)
	}
	var reply map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &reply)
	if _, ok := reply["task_id"]; ok {
		t.Error("the refusal body carries a task_id, so a caller can read a crawl it was not allowed " +
			"to start")
	}
}

// burpsy-react-ui-rebind-read: a page on a domain that rebinds to 127.0.0.1 is same-origin to the
// browser, so it can READ the reply to a GET — which is what made exempting reads from the Host check
// a leak of every captured cookie. The foreign-Host read is refused; the same read on the console's
// own loopback Host still works, so the fix is not a denial of service on the console itself.
func TestARebindingPageCannotReadCapturedTraffic(t *testing.T) {
	s := newTestServer()
	id, err := s.store.Put([]byte("GET /account HTTP/1.1\r\nHost: target.test\r\nCookie: session=rebind-secret-cookie\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	msg := "/api/message/" + strconv.FormatUint(uint64(id), 10)

	for _, path := range []string{msg, "/api/history"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(method+" "+path, func(t *testing.T) {
				// Foreign Host, and the headers a rebound same-origin page really sends.
				req := httptest.NewRequest(method, path, nil)
				req.Host = "rebind.attacker.example:8081"
				req.Header.Set("Sec-Fetch-Site", "same-origin")
				rec := httptest.NewRecorder()
				s.guarded.ServeHTTP(rec, req)
				if rec.Code != http.StatusForbidden {
					t.Errorf("status = %d, want 403: a page that rebound to loopback read %s", rec.Code, path)
				}
				if strings.Contains(rec.Body.String(), "rebind-secret-cookie") {
					t.Errorf("the refusal carries the captured cookie: %q", rec.Body.String())
				}

				// Loopback Host: the console's own read.
				for _, host := range []string{"127.0.0.1:8081", "localhost:8081", "[::1]:8081"} {
					req := httptest.NewRequest(method, path, nil)
					req.Host = host
					req.Header.Set("Sec-Fetch-Site", "same-origin")
					rec := httptest.NewRecorder()
					s.guarded.ServeHTTP(rec, req)
					// HEAD is not served on every route (a 405 there is the handler's answer, not the
					// gate's), so HEAD only has to get past the gate; GET has to succeed.
					if rec.Code == http.StatusForbidden || method == http.MethodGet && rec.Code != http.StatusOK {
						t.Errorf("Host %s: status = %d; the console's own read was refused", host, rec.Code)
					}
				}
			})
		}
	}

	// And the loopback read carries the content, so the 200 above is the real view.
	req := httptest.NewRequest(http.MethodGet, msg, nil)
	req.Host = "127.0.0.1:8081"
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "rebind-secret-cookie") {
		t.Errorf("the loopback read did not return the message: %q", rec.Body.String())
	}
}

// A configured non-loopback name is accepted on reads too, and naming one does not lock out loopback.
func TestANamedHostReadsAndLoopbackStillWorksBesideIt(t *testing.T) {
	s := newTestServer().WithAllowedHosts("burp.internal:8081")
	for _, tc := range []struct {
		host string
		want int
	}{
		{"burp.internal:8081", http.StatusOK},
		{"127.0.0.1:8081", http.StatusOK},
		{"burp.internal.evil.example:8081", http.StatusForbidden},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/history", nil)
		req.Host = tc.host
		rec := httptest.NewRecorder()
		s.guarded.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("GET /api/history with Host %s: status = %d, want %d", tc.host, rec.Code, tc.want)
		}
	}
}

// The address the console is bound to is accepted without a separate step, so a non-loopback bind
// does not 403 the operator's first page load now that reads are Host-checked. A wildcard bind is
// accepted on interface ADDRESSES only; a DNS name is never inferred.
func TestTheBindAddressIsAcceptedAndAWildcardBindAcceptsOnlyInterfaceAddresses(t *testing.T) {
	ifaces := func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("2001:db8::10"), Mask: net.CIDRMask(64, 128)},
			&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		}, nil
	}
	for _, tc := range []struct {
		bind     string
		accepted []string
		refused  []string
	}{
		{"192.0.2.10:8081", []string{"192.0.2.10:8081", "127.0.0.1:8081"}, []string{"192.0.2.11:8081", "evil.example:8081"}},
		{"0.0.0.0:8081", []string{"192.0.2.10:8081", "[2001:db8::10]:8081", "localhost:8081"}, []string{"[fe80::1]:8081", "evil.example:8081"}},
		{":8081", []string{"192.0.2.10:8081"}, []string{"evil.example:8081"}},
		{"127.0.0.1:8081", []string{"127.0.0.1:8081"}, []string{"192.0.2.10:8081", "evil.example:8081"}},
	} {
		s := newTestServer()
		s.allowBindAddr(tc.bind, ifaces)
		for _, h := range tc.accepted {
			if !s.acceptsHost(h) {
				t.Errorf("bind %s: Host %s refused", tc.bind, h)
			}
		}
		for _, h := range tc.refused {
			if s.acceptsHost(h) {
				t.Errorf("bind %s: Host %s accepted", tc.bind, h)
			}
		}
	}
}
