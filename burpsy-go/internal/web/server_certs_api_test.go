package web

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/servercerts"
)

// Burp's "Server TLS certificates" (burpsy-react-ui-t75m) through its route: empty is [] and says
// whether a store is attached, a recorded certificate is on the wire, and DELETE clears.
func TestTheServerCertificatesRoute(t *testing.T) {
	bare := newTestServer()
	if body := get(t, bare, "/api/network/server-certificates").Body.String(); !strings.Contains(body, `"attached":false`) ||
		!strings.Contains(body, `"certificates":[]`) {
		t.Fatalf("without a store: %s", body)
	}

	store := servercerts.New()
	s := newTestServer().WithServerCerts(store)
	if body := get(t, s, "/api/network/server-certificates").Body.String(); !strings.Contains(body, `"attached":true`) ||
		!strings.Contains(body, `"certificates":[]`) {
		t.Fatalf("an empty attached store: %s", body)
	}
	origin := httptest.NewTLSServer(http.NotFoundHandler())
	defer origin.Close()
	store.Record("app.test", 443, []*x509.Certificate{origin.Certificate()})
	body := get(t, s, "/api/network/server-certificates").Body.String()
	for _, want := range []string{`"leaf":true`, `"seen_on":["app.test:443"]`, `"count":1`, `"sha256":"`} {
		if !strings.Contains(body, want) {
			t.Errorf("GET lacks %s: %s", want, body)
		}
	}
	if rec := deleteReq(t, s, "/api/network/server-certificates"); rec.Code != http.StatusOK {
		t.Fatalf("DELETE = %d", rec.Code)
	}
	if body := get(t, s, "/api/network/server-certificates").Body.String(); !strings.Contains(body, `"certificates":[]`) {
		t.Errorf("DELETE did not clear: %s", body)
	}
}
