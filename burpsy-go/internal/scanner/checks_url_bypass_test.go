package scanner

// The 0vzb.4 auth-bypass probes (checks_url_bypass.go) against a raw-handler target that models
// the front/back disagreement the check reads. No ServeMux: it canonicalises dot segments before
// dispatch, which would do the router's job for it.
//
// The vulnerable server decides access on the request target as written, then routes on the
// normalised spelling and honours X-Original-URL / X-Rewrite-URL. The safe twin decides on the
// fully normalised path and ignores the override headers.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

const urlBypassAdminBody = "<!DOCTYPE html><html><body><h1>admin console</h1></body></html>"

// urlBypassNormalise is the vulnerable server's router-side path resolution: decode percent
// escapes once, drop ";…" path parameters, resolve dot segments, collapse doubled separators and
// trim trailing whitespace — every step a real container does AFTER an as-written access check.
func urlBypassNormalise(u string) string {
	u, _, _ = strings.Cut(u, "?")
	var b strings.Builder
	for i := 0; i < len(u); i++ {
		if u[i] == '%' && i+2 < len(u) {
			var v int
			if _, err := fmt.Sscanf(u[i+1:i+3], "%02x", &v); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(u[i])
	}
	u = strings.TrimRight(b.String(), " \t")
	segs := strings.Split(u, "/")
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		s, _, _ = strings.Cut(s, ";")
		switch s {
		case "", ".":
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, s)
		}
	}
	return "/" + strings.Join(out, "/")
}

// urlBypassServer returns the vulnerable (true) or safe (false) twin. Both serve / (a public page)
// and refuse /admin2 as written; only the vulnerable one can be talked out of the refusal.
func urlBypassServer(vuln bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		route := r.RequestURI
		if vuln {
			// The back end honours the override headers; the front check below never sees them.
			if o := r.Header.Get("X-Original-URL"); o != "" {
				route = o
			} else if o := r.Header.Get("X-Rewrite-URL"); o != "" {
				route = o
			}
		}
		decide := route
		if !vuln {
			decide = urlBypassNormalise(route)
		}
		if decide == "/admin2" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "<!DOCTYPE html><html><body><h1>denied</h1></body></html>")
			return
		}
		if urlBypassNormalise(route) == "/admin2" {
			fmt.Fprint(w, urlBypassAdminBody)
			return
		}
		if urlBypassNormalise(route) == "/" {
			fmt.Fprint(w, "<!DOCTYPE html><html><body><h1>welcome</h1></body></html>")
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<!DOCTYPE html><html><body><h1>no such page</h1></body></html>")
	}
}

// urlBypassAudit seeds a GET /admin2 capture against the given server and audits it with only
// CheckURLAuthBypass toggled by mod.
func urlBypassAudit(t *testing.T, handler http.Handler, mod func(*ScanConfig)) []*Finding {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("test server port %q: %v", portStr, err)
	}
	rt := &runtimeTarget{srv: srv, host: host, port: port, store: core.NewTrafficStore(), exchanges: map[string]core.ExchangeID{}}
	client := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	rt.seed(t, client, vulnapp.Endpoint{Path: "/admin2", Note: "refused page for the URL-bypass probes"})
	cfg := &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckURLAuthBypass: true}
	if mod != nil {
		mod(cfg)
	}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	outcome, findings := scan.AuditWithin(ctx, rt.exchanges["/admin2"], scan.AuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit failed: %s", outcome.Error)
	}
	return findings
}

func urlBypassFinding(fs []*Finding) *Finding {
	for _, f := range fs {
		if f.Name == "Broken access control" && f.Param != "" {
			return f
		}
	}
	return nil
}

func TestURLAuthBypassFindsBothTechniquesOnTheVulnerableServer(t *testing.T) {
	fs := urlBypassAudit(t, urlBypassServer(true), nil)
	f := urlBypassFinding(fs)
	if f == nil {
		var got []string
		for _, x := range fs {
			got = append(got, x.Name+"/"+x.Param)
		}
		t.Fatalf("no access-bypass finding on the vulnerable server (got %v)", got)
	}
	if f.Confidence != "firm" || f.Severity != "high" {
		t.Errorf("confidence/severity %s/%s, want firm/high", f.Confidence, f.Severity)
	}
	if !strings.Contains(f.Evidence, "HTTP 403") {
		t.Errorf("evidence does not name the refusal: %s", f.Evidence)
	}
}

func TestURLAuthBypassFindsTheHeaderTechniqueWhenPathsAreNormalisedEarly(t *testing.T) {
	// A server whose front check DOES normalise (so path spellings cannot bypass it) but whose back
	// end still honours X-Original-URL.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if urlBypassNormalise(r.RequestURI) == "/admin2" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "<!DOCTYPE html><html><body><h1>denied</h1></body></html>")
			return
		}
		if o := r.Header.Get("X-Original-URL"); o != "" && urlBypassNormalise(o) == "/admin2" {
			fmt.Fprint(w, urlBypassAdminBody)
			return
		}
		if urlBypassNormalise(r.RequestURI) == "/" {
			fmt.Fprint(w, "<!DOCTYPE html><html><body><h1>welcome</h1></body></html>")
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<!DOCTYPE html><html><body><h1>no such page</h1></body></html>")
	}
	fs := urlBypassAudit(t, http.HandlerFunc(handler), nil)
	f := urlBypassFinding(fs)
	if f == nil {
		t.Fatal("no finding for the X-Original-URL bypass")
	}
	if f.Param != "X-Original-URL" {
		t.Errorf("param %q, want the header that carried the bypass", f.Param)
	}
}

func TestURLAuthBypassStaysQuietOnTheSafeTwin(t *testing.T) {
	fs := urlBypassAudit(t, urlBypassServer(false), nil)
	if f := urlBypassFinding(fs); f != nil {
		t.Fatalf("safe twin reported: %s\n%s", f.Description, f.Evidence)
	}
}

func TestURLAuthBypassIsOffWithoutItsSwitch(t *testing.T) {
	fs := urlBypassAudit(t, urlBypassServer(true), func(c *ScanConfig) { c.CheckURLAuthBypass = false })
	if f := urlBypassFinding(fs); f != nil {
		t.Fatalf("reported with the switch off: %s", f.Description)
	}
}

// rawSetRequestTarget rewrites only the target, leaving method, version and headers intact.
func TestRawSetRequestTarget(t *testing.T) {
	raw := "GET /admin2?x=1 HTTP/1.1\r\nHost: h\r\n\r\n"
	got := rawSetRequestTarget(raw, "/%2e/admin2")
	want := "GET /%2e/admin2 HTTP/1.1\r\nHost: h\r\n\r\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
