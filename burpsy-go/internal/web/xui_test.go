package web

import (
	"context"
	"fmt"
	"github.com/burpsy-go/burpsy/internal/core"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestXUIPagesAndAssets(t *testing.T) {
	s := newTestServer()
	for path, want := range map[string]string{"/x": "xui-rows", "/x/prove": "xui-rows", "/x/datastar.js": "", "/x/xui.css": ""} {
		rec := get(t, s, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		if want != "" && !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("%s: missing %q", path, want)
		}
	}
}

func TestXUIDetailErrors(t *testing.T) {
	s := newTestServer()
	if c := get(t, s, "/x/detail?id=abc").Code; c != http.StatusBadRequest {
		t.Fatalf("bad id: %d", c)
	}
	if c := get(t, s, "/x/detail?id=999999").Code; c != http.StatusNotFound {
		t.Fatalf("missing id: %d", c)
	}
}

func TestXUIStreamSendsFirstFrameAndStops(t *testing.T) {
	s := newTestServer()
	for _, p := range []string{"/x/map/stream", "/x/prove/stream"} {
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		defer cancel()
		req := httptest.NewRequest(http.MethodGet, p, nil).WithContext(ctx)
		rec := httptest.NewRecorder()
		done := make(chan struct{})
		go func() { s.mux.ServeHTTP(rec, req); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("%s did not stop after context cancel", p)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
			t.Fatalf("%s content-type %q", p, ct)
		}
		if !strings.Contains(rec.Body.String(), "datastar-patch-elements") {
			t.Fatalf("%s: no patch frame: %q", p, rec.Body.String())
		}
	}
}

// streamBody runs one stream route for d and returns what it sent. during runs concurrently.
func streamBody(t *testing.T, s *Server, path string, d time.Duration, during func()) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { s.mux.ServeHTTP(rec, req); close(done) }()
	if during != nil {
		during()
	}
	<-done
	return rec.Body.String()
}

func TestXUIMapWindowIsBoundedAndLabeled(t *testing.T) {
	s := newTestServer()
	for i := 0; i < xuiWindow+50; i++ {
		s.store.AddExchange(&core.Exchange{Host: "h.test", Port: 80, Method: "GET", Path: "/p"})
	}
	body := streamBody(t, s, "/x/map/stream", 600*time.Millisecond, nil)
	if n := strings.Count(firstPatch(body, `id="xui-rows"`), `class="data"`); n != xuiWindow {
		t.Fatalf("rendered %d rows in the first frame set, want exactly %d", n, xuiWindow)
	}
	want := fmt.Sprintf("%d requests (newest %d shown)", xuiWindow+50, xuiWindow)
	if !strings.Contains(body, want) {
		t.Fatalf("missing label %q", want)
	}
}

func TestXUIDetailLabelsTruncatedPreview(t *testing.T) {
	s := newTestServer()
	big := "HTTP/1.1 200 OK\r\n\r\n" + strings.Repeat("A", xuiMessagePreview+5000)
	reqID, _ := s.store.Put([]byte("GET / HTTP/1.1\r\nHost: h.test\r\n\r\n"), core.DirectionRequest)
	rspID, _ := s.store.Put([]byte(big), core.DirectionResponse)
	ex := &core.Exchange{Host: "h.test", Port: 80, Method: "GET", Path: "/", Request: core.MsgPtr(reqID), Response: &rspID}
	s.store.AddExchange(ex)
	rec := get(t, s, fmt.Sprintf("/x/detail?id=%d", ex.ID))
	body := rec.Body.String()
	if !strings.Contains(body, fmt.Sprintf("Preview: first %d of %d bytes", xuiMessagePreview, len(big))) {
		t.Fatalf("truncated response not labeled: %.300q", body)
	}
	if strings.Count(body, "Preview: first") != 1 {
		t.Fatalf("the short request must not carry a truncation note")
	}
}

func TestXUIProveOrdersBySeverityAndBoundsWindow(t *testing.T) {
	s := newTestServer()
	sevs := []core.Severity{core.SeverityInformational, core.SeverityLow, core.SeverityMedium, core.SeverityHigh, core.SeverityCritical}
	for i := 0; i < xuiWindow+60; i++ {
		s.findings.Add(core.NewFinding{Name: fmt.Sprintf("distinct finding %d", i), Severity: sevs[i%5], TaskID: 1,
			Target: core.FindingTarget{Host: "t.test", Port: 80, Path: fmt.Sprintf("/p%d", i)}})
	}
	body := streamBody(t, s, "/x/prove/stream", 600*time.Millisecond, nil)
	body = firstPatch(body, `id="xui-rows"`)
	if n := strings.Count(body, `<tr class="data">`); n != xuiWindow {
		t.Fatalf("rendered %d finding rows, want %d", n, xuiWindow)
	}
	last := 5
	for _, m := range regexp.MustCompile(`class="sev sev-([a-z]+)"`).FindAllStringSubmatch(body, -1) {
		r := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}[m[1]]
		if r > last {
			t.Fatalf("severity order broke: %s after a lower severity", m[1])
		}
		last = r
	}
}

func TestXUIStreamPushesAreRateCapped(t *testing.T) {
	s := newTestServer()
	body := streamBody(t, s, "/x/map/stream", 1300*time.Millisecond, func() {
		for i := 0; i < 200; i++ {
			s.store.AddExchange(&core.Exchange{Host: "h.test", Port: 80, Method: "GET", Path: "/p"})
			time.Sleep(5 * time.Millisecond)
		}
	})
	pushes := strings.Count(body, `id="xui-count"`)
	max := int(1300*time.Millisecond/xuiMinPush) + 2
	if pushes < 2 || pushes > max {
		t.Fatalf("%d count patches in 1.3s, want between 2 and %d", pushes, max)
	}
}

func TestXUIDatastarPairing(t *testing.T) {
	js := get(t, newTestServer(), "/x/datastar.js").Body.String()
	if !strings.HasPrefix(js, "// Datastar v1.0.4") {
		t.Fatalf("vendored client is not v1.0.4: %.40q", js)
	}
	mod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mod), "github.com/starfederation/datastar-go v1.2.2") {
		t.Fatal("datastar-go is not v1.2.2: the server SDK and the vendored client were verified as a pair")
	}
}

// firstPatch returns the first SSE event that patches the element carrying marker.
func firstPatch(body, marker string) string {
	for _, ev := range strings.Split(body, "\n\n") {
		if strings.Contains(ev, marker) {
			return ev
		}
	}
	return ""
}
