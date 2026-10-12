package scanner

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// perLevelRoute is a route for an application that serves one URL per level and labels each level's
// navigation entry with the URL's last segment. It is test data: the scanner ships no route.
func perLevelRoute() XSSBrowserTarget {
	return XSSBrowserTarget{
		Match:          "app.test",
		RootURL:        "http://app.test/",
		MasterSelector: ".nav-item",
		MasterText:     "Reflect",
		LevelSelector:  ".sub-item",
		LevelFromPath:  true,
		InputSelector:  "#q",
		SubmitSelector: "#go",
	}
}

// TestTheLevelIsTakenFromTheExchangePathWhenTheRouteAsksForIt is the regression guard for the
// per-level silent miss: a route that is generic over levels must drive the level of the exchange it is
// confirming, not a fixed one, or the sink never carries the payload of the point under test.
func TestTheLevelIsTakenFromTheExchangePathWhenTheRouteAsksForIt(t *testing.T) {
	sc := &ActiveScanner{config: &ScanConfig{XSSBrowserTargets: []XSSBrowserTarget{perLevelRoute()}}}
	for _, level := range []string{"LEVEL_1", "LEVEL_2", "LEVEL_3"} {
		cc := &CheckContext{
			Scanner:  sc,
			Exchange: &core.Exchange{Host: "app.test", Path: "/Reflect/" + level + "?value=1"},
		}
		got, ok := xssBrowserTargetFor(cc)
		if !ok {
			t.Fatalf("no route matched %s, so the browser confirmation was declined", level)
		}
		if got.LevelText != level {
			t.Errorf("confirming %s drove %q", level, got.LevelText)
		}
	}
	// Without LevelFromPath the path is not read: the route names its own view or none.
	r := perLevelRoute()
	r.LevelFromPath = false
	sc = &ActiveScanner{config: &ScanConfig{XSSBrowserTargets: []XSSBrowserTarget{r}}}
	got, _ := xssBrowserTargetFor(&CheckContext{Scanner: sc, Exchange: &core.Exchange{Host: "app.test", Path: "/Reflect/LEVEL_2"}})
	if got.LevelText != "" {
		t.Errorf("a route that did not ask for it had its level derived from the path: %q", got.LevelText)
	}
}

// TestAnExplicitlyNamedLevelIsNotOverridden pins that a caller who states the level keeps it.
func TestAnExplicitlyNamedLevelIsNotOverridden(t *testing.T) {
	sc := &ActiveScanner{config: &ScanConfig{XSSBrowserTargets: []XSSBrowserTarget{{
		Match: "example.test", MasterText: "Fam", LevelText: "PINNED", LevelFromPath: true,
	}}}}
	cc := &CheckContext{Scanner: sc, Exchange: &core.Exchange{
		Host: "example.test", Path: "/Fam/OTHER_LEVEL",
	}}
	got, ok := xssBrowserTargetFor(cc)
	if !ok || got.LevelText != "PINNED" {
		t.Fatalf("a stated LevelText was rewritten to %q (matched=%v)", got.LevelText, ok)
	}
}

// TestNoRouteShipsWithTheScanner pins that the browser confirmation has no built-in route: with the
// switch on and no caller-supplied route, every host is declined rather than driven through a route
// written for one particular application.
func TestNoRouteShipsWithTheScanner(t *testing.T) {
	sc := &ActiveScanner{config: &ScanConfig{CheckXSSBrowserConfirm: true}}
	for _, host := range []string{"127.0.0.1", "localhost", "example.test"} {
		if _, ok := xssBrowserTargetFor(&CheckContext{Scanner: sc, Exchange: &core.Exchange{Host: host, Path: "/x/LEVEL_1"}}); ok {
			t.Errorf("host %s matched a route nobody configured", host)
		}
	}
}

// TestABrowserRouteOffTheExchangesOriginIsNotNavigated pins the scope rule: the browser goes only to a
// route on the audited exchange's own scheme, host and port.
func TestABrowserRouteOffTheExchangesOriginIsNotNavigated(t *testing.T) {
	ex := &core.Exchange{Host: "app.test", Port: 8080, Path: "/r?q=1"}
	for root, wantOK := range map[string]bool{
		"http://app.test:8080/":   true,
		"http://APP.test:8080/x/": true,
		"http://app.test/":        false,
		"https://app.test:8080/":  false,
		"http://evil.test:8080/":  false,
		"/relative/":              false,
	} {
		reason := xssBrowserRouteOutOfScope(ex, XSSBrowserTarget{RootURL: root})
		if (reason == "") != wantOK {
			t.Errorf("root %q: in scope = %v, want %v (%s)", root, reason == "", wantOK, reason)
		}
	}
}

// TestABrowserConfirmationCreditsOnlyTheRequestItDrove is the attribution rule: a sink fed through a
// request to another path, or carrying the value in another parameter, is not this point's.
func TestABrowserConfirmationCreditsOnlyTheRequestItDrove(t *testing.T) {
	ex := &core.Exchange{Host: "app.test", Port: 80, Path: "/api/echo?value=seed"}
	query := bcheck.InsertionPoint{Kind: bcheck.IpQuery, Name: "value"}
	const canary = "zxssAbC123"
	cases := []struct {
		name string
		sent []domexec.SentRequest
		want bool
	}{
		{"the audited path and parameter", []domexec.SentRequest{{Method: "GET", URL: "http://app.test/api/echo?value=%3Cb%3E" + canary}}, true},
		{"another path", []domexec.SentRequest{{Method: "GET", URL: "http://app.test/api/other?value=" + canary}}, false},
		{"another parameter", []domexec.SentRequest{{Method: "GET", URL: "http://app.test/api/echo?q=" + canary}}, false},
		{"another origin", []domexec.SentRequest{{Method: "GET", URL: "http://cdn.test/api/echo?value=" + canary}}, false},
		{"no request at all", nil, false},
	}
	for _, c := range cases {
		if _, got := xssBrowserDroveThisPoint(ex, query, c.sent, canary); got != c.want {
			t.Errorf("%s: attributed = %v, want %v", c.name, got, c.want)
		}
	}
	body := bcheck.InsertionPoint{Kind: bcheck.IpBody, Name: "value"}
	if _, ok := xssBrowserDroveThisPoint(ex, body, []domexec.SentRequest{{Method: "POST", URL: "http://app.test/api/echo",
		Body: `{"value":"<b>` + canary + `"}`}}, canary); !ok {
		t.Error("a JSON body carrying the value in the audited key was not attributed")
	}
	if xssBrowserAttributable(bcheck.InsertionPoint{Kind: bcheck.IpHeader, Name: "X-Foo"}) {
		t.Error("a header point was treated as attributable to a page's request")
	}
}

// TestTheBrowserConfirmationNeverWritesTheScannersConfig is the regression guard for the data race: the
// reflected-XSS check used to install a default route list into the scanner's shared config from
// inside a running check, without the config lock, while sibling checks read it.
func TestTheBrowserConfirmationNeverWritesTheScannersConfig(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		// Reflected, but as text/plain: the shape that sends the check to the browser confirmation.
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("you said " + r.URL.Query().Get("value")))
		}))
	}()
	port := targetPort(t, ln.Addr().String())
	store := core.NewTrafficStore()
	id := seedAuditExchange(t, store, "127.0.0.1", port, "/echo?value=seed", "you said seed")
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{MaxConcurrency: 2, Timeout: 30 * time.Second, CheckXss: true, CheckXSSBrowserConfirm: true})
	_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, DefaultAuditConfig())
	if got := scan.ConfigSnapshot().XSSBrowserTargets; len(got) != 0 {
		t.Fatalf("a check wrote %d browser route(s) into the scanner's shared config", len(got))
	}
	if hasFinding(findings, xssReflectedIssue) {
		t.Fatal("reflected XSS was reported for a text/plain echo with no browser route configured")
	}
}

// TestTheBrowserConfirmLadderEvadesTheNaiveFiltersThatStripTheFirstSpelling is the regression guard for
// the per-level miss on a filter that deletes a tag by name. The confirmation is a substring test on a
// sink's argument, so every rung must keep the canary literal while surviving the filter; a spelling that
// hides the canary in an encoded blob would decode to an exploit yet never match, reading as clean.
func TestTheBrowserConfirmLadderEvadesTheNaiveFiltersThatStripTheFirstSpelling(t *testing.T) {
	// LEVEL_2 deletes any tag whose name starts with one of s,c,r,i,p,t,m,g,a (measured against a live
	// VulnerableApp: `<svg` and `<img` are stripped, `<details` and `<object` survive).
	level2 := func(p string) bool {
		for _, bad := range []string{"<script", "<svg", "<img", "<iframe", "<input", "<meta", "<a "} {
			if strings.Contains(strings.ToLower(p), bad) {
				return false
			}
		}
		return true
	}
	// LEVEL_3 adds only the literal keyword rejections `alert` and `javascript`; it does NOT block
	// onerror/onload, which is precisely why a confirmation-handler spelling is the rung that survives it.
	level3 := func(p string) bool {
		if !level2(p) {
			return false
		}
		low := strings.ToLower(p)
		return !strings.Contains(low, "alert") && !strings.Contains(low, "javascript")
	}

	ladder := xssBrowserConfirmLadder(genericXSSPayloads(), maxXSSBrowserConfirmAttempts)
	if len(ladder) == 0 {
		t.Fatal("the ladder is empty, so the confirmation would send nothing")
	}
	if got := ladder[0].note; got != genericXSSPayloads()[0].note {
		t.Errorf("the ladder does not lead with the context-specific payload: first note %q", got)
	}
	if len(ladder) != maxXSSBrowserConfirmAttempts {
		t.Errorf("the ladder has %d rungs, want the bounded %d", len(ladder), maxXSSBrowserConfirmAttempts)
	}
	for _, filter := range []struct {
		name string
		pass func(string) bool
	}{{"LEVEL_2 tag-name filter", level2}, {"LEVEL_3 tag-name + keyword filter", level3}} {
		found := false
		for _, p := range ladder {
			payload := p.build("CANARY")
			if !strings.Contains(payload, "CANARY") {
				t.Errorf("%s: rung %q does not keep the canary literal, so a sink carrying it could never "+
					"match and the page would read as clean", filter.name, p.note)
				continue
			}
			if filter.pass(payload) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: no rung survives, so every level behind that filter is reported clean", filter.name)
		}
	}
}
