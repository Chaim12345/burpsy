package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func postUI2Form(t *testing.T, s *Server, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// The Sequencer page's live-capture chain: the start form rides the same two-step review as
// every other request-hungry launch (the API route is riskAttack), and pause/resume/stop
// drive a running capture through the API's control verbs. This pins the whole loop against
// a real loopback token source: form -> review -> minted start -> tokens actually arrive ->
// stop ends it - and that a foreign token cannot start anything.
func TestUI2SequencerCaptureFlow(t *testing.T) {
	host, port, hits := tokenServer(t, func(n int) string {
		return fmt.Sprintf("Set-Cookie: SESSIONID=tok-%d\r\n", n)
	})
	s := captureServer(t, host, port)
	target := fmt.Sprintf("%s:%d", host, port)
	raw := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", target)

	// The page offers the start form with the location kinds and the count/delay/threads knobs.
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/sequencer", nil))
	page := rec.Body.String()
	for _, want := range []string{
		`hx-post="/ui2/sequencer/capture/confirm"`,
		`name="target"`, `name="request"`, `name="count"`, `name="delay_ms"`, `name="threads"`,
		`value="cookie"`, `value="header"`, `value="form_field"`, `value="body_regex"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("/ui2/sequencer lost start-form element %q", want)
		}
	}

	form := url.Values{
		"target":   {target},
		"protocol": {"http"},
		"count":    {"12"},
		"delay_ms": {"5"},
		"kind":     {"cookie"},
		"name":     {"SESSIONID"},
		"request":  {raw},
	}

	// A request posted LF-only (what the browser's textarea submits) is reviewed with its
	// head restored to CRLF - the reviewed body is the body that will be sent.
	lfForm := url.Values{}
	for k, v := range form {
		lfForm[k] = v
	}
	lfForm.Set("request", "GET / HTTP/1.1\nHost: "+target+"\n\n")
	rec = postUI2Form(t, s, "/ui2/sequencer/capture/confirm", lfForm)
	if !strings.Contains(rec.Body.String(), `GET / HTTP/1.1\r\nHost:`) {
		t.Errorf("an LF-only head was not restored to CRLF in the reviewed body: %s", rec.Body.String()[:ui2Min(400, rec.Body.Len())])
	}

	// confirm mints a one-time review naming the exact call.
	rec = postUI2Form(t, s, "/ui2/sequencer/capture/confirm", form)
	body := rec.Body.String()
	for _, want := range []string{"Review before starting:", "POST /api/sequencer/capture", `name="token"`,
		// A confirmation gate shows the WHOLE exact body it binds: the truncated one-line
		// preview cuts before the target and threads fields, so their presence with the
		// full request proves nothing is hidden from the review.
		"exact body (what the token binds, in full)",
		`&#34;target&#34;:&#34;` + target + `&#34;`, `&#34;threads&#34;`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("confirm page missing %q: %s", want, body[:ui2Min(400, len(body))])
		}
	}
	m := regexp.MustCompile(`name="token" value="([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("confirm page carried no token: %s", body[:ui2Min(400, len(body))])
	}
	token := m[1]

	// A foreign token cannot start the capture: the gate refuses and nothing runs.
	bad := url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Set("token", "not-the-minted-token")
	rec = postUI2Form(t, s, "/ui2/sequencer/capture/run", bad)
	if !strings.Contains(rec.Body.String(), "confirmation required") {
		t.Errorf("run with a foreign token was not refused: %s", rec.Body.String()[:ui2Min(300, rec.Body.Len())])
	}
	if n := len(s.captureSet().running()); n != 0 {
		t.Fatalf("%d captures running after a refused start", n)
	}

	// The minted token starts it; the tokens really arrive.
	good := url.Values{}
	for k, v := range form {
		good[k] = v
	}
	good.Set("token", token)
	rec = postUI2Form(t, s, "/ui2/sequencer/capture/run", good)
	if strings.Contains(rec.Body.String(), "<strong>Not") || strings.Contains(rec.Body.String(), "confirmation required") {
		t.Fatalf("run with the minted token failed: %s", rec.Body.String()[:ui2Min(300, rec.Body.Len())])
	}
	// The run response is the first place the operator looks for their new capture: it must
	// render the row it just started, not the pre-dispatch list.
	if strings.Contains(rec.Body.String(), "No captures.") {
		t.Error("the run response rendered the pre-dispatch list (No captures.) instead of the capture it just started")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(s.captureSet().running()) == 0 && *hits >= 12 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if *hits < 12 {
		t.Errorf("capture sent %d requests, want 12 - the page reported a start the loop did not perform", *hits)
	}

	// A second capture with a wide count is stopped by the page's own control. The reviewed
	// body and the spent body must be the same call, so the form changes BEFORE the mint.
	form.Set("count", "500")
	form.Set("delay_ms", "25")
	rec = postUI2Form(t, s, "/ui2/sequencer/capture/confirm", form)
	m = regexp.MustCompile(`name="token" value="([^"]+)"`).FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("second confirm carried no token")
	}
	good = url.Values{}
	for k, v := range form {
		good[k] = v
	}
	good.Set("token", m[1])
	rec = postUI2Form(t, s, "/ui2/sequencer/capture/run", good)
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(s.captureSet().running()) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if len(s.captureSet().running()) == 0 {
		t.Fatal("second capture never showed as running")
	}
	rec = postUI2Form(t, s, "/ui2/sequencer/capture/stop", url.Values{})
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(s.captureSet().running()) != 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if n := len(s.captureSet().running()); n != 0 {
		t.Errorf("%d captures still running after the page's stop", n)
	}
	// The re-rendered page offers the controls only while something runs.
	if strings.Contains(rec.Body.String(), "A capture is running") {
		t.Errorf("controls still shown after the stop")
	}
}
