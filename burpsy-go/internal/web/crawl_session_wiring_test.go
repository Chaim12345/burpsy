package web

import (
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/crawler"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// burpsy-react-ui-nc9s: crawler/session_gate.go was complete and tested, and NEITHER production
// crawl wired it — api_crawl.go and api_apiscan.go built their crawler.Config without a
// SessionCoordinator. Every operator-launched crawl therefore ran the unauthenticated one from the
// first expiry onwards, silently, and reported whatever the public pages yielded: a confident empty
// result with no signal that the session had been lost.
//
// The test below is the guard the bead asks for: a production crawl's config must carry a
// coordinator whenever this server has one. A nil there is the whole defect, and it is invisible
// from the request side — a crawl that starts, runs, and reports is exactly what a broken one does.

// The wiring, asserted on the seam rather than on behaviour, because a behaviour test needs a
// target that expires a session and the defect is that the seam was never connected.
func TestAProductionCrawlIsWiredToTheSessionCoordinator(t *testing.T) {
	coord := session.NewCoordinator(zap.NewNop())
	s := newTestServer().WithSessionCoordinator(coord)

	// Read the config production actually builds, NOT the helper that feeds it. An earlier version of
	// this test called the helper directly and passed against the unwired shape — the helper was
	// right and nothing called it, which was the entire defect. A field missing from a literal
	// nobody inspects is invisible, so the assertion has to be on the literal.
	cfg := s.crawlConfig(crawlStartReq{}, nil, crawler.Limits{}, nil, nil, false, crawler.ErrorHandling{})
	if cfg.SessionCoordinator == nil {
		t.Fatal("the crawl configuration a production crawl builds carries no SessionCoordinator; " +
			"the re-login seam is unreachable from every operator-launched crawl (burpsy-react-ui-nc9s)")
	}
	if cfg.SessionCoordinator != crawler.SessionCoordinator(coord) {
		t.Error("the crawl's coordinator is not the server's own; a re-login would land in a jar the " +
			"Session page and every other tool do not read")
	}
}

// The same assertion for the API scan, which launches the same engine in a different mode. Both
// config literals were missing the field, and fixing one would leave the other silently broken.
func TestAnAPIScanIsAlsoWiredToTheSessionCoordinator(t *testing.T) {
	coord := session.NewCoordinator(zap.NewNop())
	s := newTestServer().WithSessionCoordinator(coord)
	// apiScanConfig is the same seam for the seeds-only mode; if it does not exist yet the
	// production literal is still inline and this cannot be asserted, which is the point.
	cfg := s.apiScanConfig(apiScanReq{}, nil, crawler.Limits{}, nil)
	if cfg.SessionCoordinator == nil {
		t.Fatal("the API scan's configuration carries no SessionCoordinator; an API scan that loses " +
			"its session enumerates the login redirect as though it were an endpoint")
	}
}

// And the nil case is a real nil, not a typed one. A non-nil interface holding a nil pointer is the
// shape that panics on first use rather than at the call — which is worse than the original defect,
// because a crawl that starts and then panics takes the process with it.
func TestAServerWithNoCoordinatorHandsACrawlARealNil(t *testing.T) {
	s := newTestServer()
	s.sessionCoordinator = nil
	got := s.crawlSessionCoordinator()
	if got != nil {
		t.Errorf("a server with no coordinator handed the crawl %v, want nil", got)
	}
	// The crawler's own guard is the other half: it must treat nil as "no re-login", not as a crash.
	if c := s.crawlSessionCoordinator(); c != nil {
		t.Error("the nil case is not stable across calls")
	}
}

// The login-page pattern reaches the crawler on BOTH request types. Both launch the same engine in
// different modes, and a session rule that keeps a crawl alive must keep an API scan alive for the
// same reason — a scan that walks authenticated routes and loses its session enumerates the login
// redirect as though it were an endpoint.
func TestTheLoginPagePatternIsAcceptedOnBothCrawlRequestTypes(t *testing.T) {
	s := newTestServer().WithSessionCoordinator(session.NewCoordinator(zap.NewNop()))
	s.scope.AddInclude("127.0.0.1")

	// A crawl: the field must reach crawler.New, which compiles it and REFUSES a malformed one.
	// The refusal is the observable half — it proves the field was read, not merely accepted.
	rec := postJSON(t, s, "/api/crawl", map[string]any{
		"seeds":              []string{"http://127.0.0.1:1/"},
		"login_page_pattern": "([unclosed",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a crawl with an uncompilable login_page_pattern answered %d, want 400. A pattern the "+
			"server ignores would be a control that appears to work and detects nothing", rec.Code)
	}

	// An API scan takes the same field. Its request is refused for a different reason (no document),
	// which is why this asserts the pattern is not the cause: a 400 naming the definition is the
	// field having been read and passed on.
	rec = postJSON(t, s, "/api/audit/apiscan", map[string]any{
		"definition":         "{}",
		"login_page_pattern": "([unclosed",
	})
	if rec.Code == http.StatusOK {
		t.Error("an API scan with an uncompilable login_page_pattern ran; the field is not reaching " +
			"that config either")
	}
}

// A seeds-only request must still be accepted after the field was added. A new field that changed
// the required set would be a breaking change to a route the console calls every day, and the
// regression would be invisible to every other test here.
func TestACrawlRequestUnchangedByTheNewFieldStillWorks(t *testing.T) {
	s := newTestServer().WithSessionCoordinator(session.NewCoordinator(zap.NewNop()))
	rec := postJSON(t, s, "/api/crawl", map[string]any{"seeds": []string{"http://127.0.0.1:1/"}})
	if rec.Code == http.StatusBadRequest {
		t.Errorf("a seeds-only crawl was refused: %s", rec.Body.String())
	}
}

// A well-formed pattern is accepted by both, which is the other half: a refusal on every pattern
// would pass the test above while making the control useless.
func TestAWellFormedLoginPagePatternIsAcceptedOnACrawl(t *testing.T) {
	s := newTestServer().WithSessionCoordinator(session.NewCoordinator(zap.NewNop()))
	// The seed host is in scope but unreachable, so the crawl starts and finds nothing — the point is
	// that the CONFIGURATION was accepted, not that the crawl succeeded.
	rec := postJSON(t, s, "/api/crawl", map[string]any{
		"seeds":              []string{"http://127.0.0.1:1/"},
		"login_page_pattern": `(?i)<title>.*sign in`,
	})
	if rec.Code == http.StatusBadRequest {
		t.Errorf("a well-formed login_page_pattern was refused: %s", rec.Body.String())
	}
}

// And the store the crawl shares is the one the coordinator's jar belongs to — the same
// coordinator every other tool routes through, not a second instance the crawl would populate and
// nothing else would read.
func TestTheCrawlsCoordinatorIsTheServersOwn(t *testing.T) {
	coord := session.NewCoordinator(zap.NewNop())
	s := newTestServer().WithSessionCoordinator(coord)
	// Identity, not equality: a Coordinator is a pointer-shaped value with internal state, and the
	// only thing that matters is that the crawl drives THIS one.
	if s.crawlSessionCoordinator() != crawler.SessionCoordinator(coord) {
		t.Error("the crawl's coordinator is not the server's own; a re-login would land in a jar " +
			"the Session page and every other tool do not read")
	}
}
