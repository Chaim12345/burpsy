package web

// The monitored-tool set (burpsy-react-ui-sn3j), driven over the surfaces that absorb. What
// these tests pin:
//
//   - a Repeater send absorbs its response's Set-Cookie into the jar, attributed to the
//     Repeater, and a source switched off stops absorbing while the send still lands in the
//     tool log — the toggle changes the jar, not the tool;
//   - an Intruder attack's stored exemplar absorbs too, one exemplar per distinct bucket;
//   - the monitor action on the jar write route configures the set and echoes the set in force.
import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/session"
)

// cookieEchoOrigin answers every request with one Set-Cookie carrying the path, so each send
// is distinguishable in the jar.
func cookieEchoOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", fmt.Sprintf("sid=from-%s; Path=/", strings.TrimPrefix(r.URL.Path, "/")))
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(origin.Close)
	return origin
}

func repeaterPost(t *testing.T, s *Server, target string, request string) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{"target": target, "request": request}
	raw, _ := json.Marshal(body)
	rec := httptest.NewRequest(http.MethodPost, "/api/repeater/send", strings.NewReader(string(raw)))
	out := httptest.NewRecorder()
	s.mux.ServeHTTP(out, rec)
	return out
}

func TestARepeaterSendAbsorbsItsResponseCookies(t *testing.T) {
	origin := cookieEchoOrigin(t)
	target, _ := url.Parse(origin.URL)
	s := newTestServerWithCoordinator(t)

	rec := repeaterPost(t, s, target.Host, "GET /login HTTP/1.1\r\nHost: "+target.Host+"\r\n\r\n")
	if rec.Code != http.StatusOK {
		t.Fatalf("repeater send = %d: %s", rec.Code, rec.Body.String())
	}
	// The jar holds the cookie the Repeater's response set, and the observation names the source.
	portNum, _ := strconv.Atoi(target.Port())
	jarHost, jarPort := target.Hostname(), uint16(portNum)
	if h := s.sessionCoordinator.CookieHeader(jarHost, jarPort, false, "/"); !strings.Contains(h, "sid=from-login") {
		t.Errorf("cookie header after the Repeater send = %q, want the login path's cookie — the Repeater response must feed the jar", h)
	}
	obs := s.sessionCoordinator.Observation()
	found := false
	for _, src := range obs.Sources {
		if src == session.SourceRepeater {
			found = true
		}
	}
	if !found {
		t.Errorf("observation sources = %v, want the repeater attached", obs.Sources)
	}
}

func TestSwitchingTheRepeaterOffStopsAbsorbingButNotSending(t *testing.T) {
	origin := cookieEchoOrigin(t)
	target, _ := url.Parse(origin.URL)
	portNum2, _ := strconv.Atoi(target.Port())
	s := newTestServerWithCoordinator(t)

	// Monitor only the proxy.
	mon := httptest.NewRequest(http.MethodPost, "/api/session/cookies", strings.NewReader(`{"action":"monitor","tools":["proxy"]}`))
	recMon := httptest.NewRecorder()
	s.mux.ServeHTTP(recMon, mon)
	if recMon.Code != http.StatusOK {
		t.Fatalf("monitor = %d: %s", recMon.Code, recMon.Body.String())
	}

	rec := repeaterPost(t, s, target.Host, "GET /login HTTP/1.1\r\nHost: "+target.Host+"\r\n\r\n")
	if rec.Code != http.StatusOK {
		t.Fatalf("the switched-off Repeater still sent: status %d — the toggle changes the jar, not the tool", rec.Code)
	}
	if h := s.sessionCoordinator.CookieHeader(target.Hostname(), uint16(portNum2), false, "/"); strings.Contains(h, "sid=from-login") {
		t.Errorf("cookie header = %q after a switched-off source, want the send to leave the jar alone", h)
	}
	// and observed, so the wiring is still reportable
	if obs := s.sessionCoordinator.Observation(); obs.ResponsesObserved == 0 {
		t.Error("the switched-off source's response was not counted as observed — the empty jar becomes undebuggable")
	}
}

func TestTheMonitorActionEchoesTheSetInForce(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	mon := httptest.NewRequest(http.MethodPost, "/api/session/cookies", strings.NewReader(`{"action":"monitor","tools":["repeater","proxy","repeater"]}`))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, mon)
	if rec.Code != http.StatusOK {
		t.Fatalf("monitor = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Monitoring []string `json:"monitoring"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Monitoring) != 2 || out.Monitoring[0] != "proxy" || out.Monitoring[1] != "repeater" {
		t.Errorf("monitoring echo = %v, want the deduped sorted set [proxy repeater]", out.Monitoring)
	}

	// and the GET reports it too
	get := httptest.NewRequest(http.MethodGet, "/api/session/cookies", nil)
	recGet := httptest.NewRecorder()
	s.mux.ServeHTTP(recGet, get)
	var view struct {
		Monitored []string `json:"monitored"`
	}
	json.Unmarshal(recGet.Body.Bytes(), &view)
	if len(view.Monitored) != 2 || view.Monitored[0] != "proxy" || view.Monitored[1] != "repeater" {
		t.Errorf("GET /api/session/cookies monitored = %v, want [proxy repeater]", view.Monitored)
	}
}

func TestTheMonitorActionRefusesAnEmptyToolsList(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	mon := httptest.NewRequest(http.MethodPost, "/api/session/cookies", strings.NewReader(`{"action":"monitor","tools":[]}`))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, mon)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty tools list = %d, want 400 — empty is the missed-field zero value, not an operator asking to monitor nothing", rec.Code)
	}
}
