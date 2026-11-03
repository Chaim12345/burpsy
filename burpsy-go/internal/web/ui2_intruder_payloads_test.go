package web

import (
	"bytes"
	"html"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// postUI2Form posts an urlencoded form to the mux and returns the body.
func postUI2IntruderForm(t *testing.T, s *Server, path string, form url.Values) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST %s = %d: %.300s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

var ui2HiddenInputRe = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)

// ui2RunFormFields returns the hidden fields of the review sheet's run form, as the browser posts them.
func ui2RunFormFields(t *testing.T, frag string) url.Values {
	t.Helper()
	i := strings.Index(frag, `hx-post="/ui2/intruder/run"`)
	if i < 0 {
		t.Fatalf("no run form in the review sheet: %.400s", frag)
	}
	out := url.Values{}
	for _, m := range ui2HiddenInputRe.FindAllStringSubmatch(frag[i:], -1) {
		out.Add(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	return out
}

// ui2ReviewBody is the review sheet's full-body <pre>, unescaped.
func ui2ReviewBody(t *testing.T, frag string) string {
	t.Helper()
	i := strings.Index(frag, "<pre")
	j := strings.Index(frag, "</pre>")
	if i < 0 || j < i {
		t.Fatalf("review sheet shows no body: %.400s", frag)
	}
	body := frag[i:j]
	return html.UnescapeString(body[strings.Index(body, ">")+1:])
}

// MUST FIX 1: the default target is the base request's own Host. A newer capture to another host
// must change neither the reviewed target nor the one the run step rebuilds.
func TestUI2IntruderTargetComesFromTheBaseRequest(t *testing.T) {
	s := newTestServer()
	msgA := seedUI2ExchangeMsgID(t, s, "GET /p?a=1 HTTP/1.1\r\nHost: a.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	seedUI2Exchange(t, s, "GET /q?b=1 HTTP/1.1\r\nHost: b.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	form := url.Values{"msg_id": {strconv.FormatUint(msgA, 10)}, "all_points": {"on"}, "set0_type": {"list"}, "set0_items": {"x"}}

	frag := postUI2IntruderForm(t, s, "/ui2/intruder/confirm", form)
	if body := ui2ReviewBody(t, frag); !strings.Contains(body, `"target": "a.test"`) {
		t.Fatalf("reviewed target is not the base request's host: %s", body)
	}
	echo := ui2RunFormFields(t, frag)
	if echo.Get("target") != "a.test" {
		t.Fatalf("run form carries target %q, want a.test", echo.Get("target"))
	}
	// The run step recomputes a blank target the same way.
	req := httptest.NewRequest(http.MethodPost, "/ui2/intruder/run", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()
	run, errText := s.ui2IntruderRunPayload(req)
	if errText != "" || run["target"] != "a.test" {
		t.Fatalf("run step target = %v (%s), want a.test", run["target"], errText)
	}
}

// MUST FIX 2: the review sheet shows the whole bound body, not a 200-byte preview.
func TestUI2IntruderReviewShowsTheFullBody(t *testing.T) {
	s := newTestServer()
	msg := seedUI2ExchangeMsgID(t, s, "GET /p?a=1 HTTP/1.1\r\nHost: p.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	var items []string
	for i := 0; i < 60; i++ {
		items = append(items, "payload-"+strconv.Itoa(i))
	}
	frag := postUI2IntruderForm(t, s, "/ui2/intruder/confirm", url.Values{
		"msg_id": {strconv.FormatUint(msg, 10)}, "all_points": {"on"},
		"set0_type": {"list"}, "set0_items": {strings.Join(items, "\n")},
	})
	body := ui2ReviewBody(t, frag)
	for _, want := range []string{`"target": "p.test"`, `"points"`, "payload-59"} {
		if !strings.Contains(body, want) {
			t.Errorf("review body lacks %s: %.300s", want, body)
		}
	}
	if strings.Contains(body, "…") {
		t.Errorf("review body was truncated")
	}
	if !strings.Contains(frag, "#0 query a = 1") {
		t.Errorf("review sheet does not name the selected position: %.600s", frag)
	}
}

// A cluster bomb with two typed payload sets and a processing rule goes through review and run:
// the victim sees exactly the product of the set sizes, each payload prefixed.
func TestUI2IntruderClusterBombLaunch(t *testing.T) {
	s := newTestServer()
	var hits atomic.Int32
	var sawPrefix atomic.Bool
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.HasPrefix(r.URL.Query().Get("b"), "x-") {
			sawPrefix.Store(true)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(victim.Close)
	vhost := strings.TrimPrefix(victim.URL, "http://")
	s.scope.AddInclude("127.0.0.1")
	msg := seedUI2ExchangeMsgID(t, s, "GET /p?a=1&b=2 HTTP/1.1\r\nHost: "+vhost+"\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	form := url.Values{
		"form_seen": {"1"}, "msg_id": {strconv.FormatUint(msg, 10)}, "mode": {"cluster_bomb"},
		"points_listed": {"1"}, "point": {"0", "1"},
		"set_count": {"2"},
		"set0_type": {"numbers"}, "set0_seen": {"numbers"}, "set0_from": {"1"}, "set0_to": {"3"}, "set0_step": {"1"},
		"set1_type": {"list"}, "set1_seen": {"list"}, "set1_items": {"u\nv"},
		"rule_count": {"1"}, "rule0_kind": {"add_prefix"}, "rule0_text": {"x-"},
		"max_in_flight": {"2"}, "update_host_header": {"on"},
	}
	frag := postUI2IntruderForm(t, s, "/ui2/intruder/confirm", form)
	body := ui2ReviewBody(t, frag)
	for _, want := range []string{`"mode": "cluster_bomb"`, `"type": "numbers"`, `"rule": "add_prefix"`, `"max_in_flight": 2`, `"update_host_header": true`} {
		if !strings.Contains(body, want) {
			t.Fatalf("review body lacks %s: %s", want, body)
		}
	}
	echo := ui2RunFormFields(t, frag)
	page := postUI2IntruderForm(t, s, "/ui2/intruder/run", echo)
	if strings.Contains(page, `role="alert"`) && !strings.Contains(page, "/results") {
		t.Fatalf("launch refused: %.600s", page)
	}
	if got := hits.Load(); got != 6 {
		t.Fatalf("victim saw %d requests, want 3×2 = 6", got)
	}
	if !sawPrefix.Load() {
		t.Errorf("the add_prefix rule never reached the wire")
	}
}

// A reviewed field edited before the run step changes the body, and the gate refuses the token.
func TestUI2IntruderTamperedReviewIsRefused(t *testing.T) {
	s := newTestServer()
	var hits atomic.Int32
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	t.Cleanup(victim.Close)
	s.scope.AddInclude("127.0.0.1")
	msg := seedUI2ExchangeMsgID(t, s, "GET /p?a=1 HTTP/1.1\r\nHost: "+strings.TrimPrefix(victim.URL, "http://")+"\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	frag := postUI2IntruderForm(t, s, "/ui2/intruder/confirm", url.Values{
		"msg_id": {strconv.FormatUint(msg, 10)}, "all_points": {"on"}, "set0_type": {"list"}, "set0_items": {"a"},
	})
	echo := ui2RunFormFields(t, frag)
	echo.Set("set0_items", "a\nb\nc")
	page := postUI2IntruderForm(t, s, "/ui2/intruder/run", echo)
	if !strings.Contains(page, `role="alert"`) || strings.Contains(page, "/results") {
		t.Fatalf("a tampered body was launched: %.400s", page)
	}
	if hits.Load() != 0 {
		t.Fatalf("victim saw %d requests from a refused launch", hits.Load())
	}
}

// Hand-placed § markers become byte spans of the stored request, whatever line endings the
// textarea sent back.
func TestUI2MarkedSpans(t *testing.T) {
	raw := []byte("GET /p HTTP/1.1\r\nHost: h\r\nX: abc\r\n\r\n")
	spans, errText := ui2MarkedSpans(raw, "GET /p HTTP/1.1\nHost: h\nX: §abc§\n\n")
	if errText != "" || len(spans) != 1 || string(raw[spans[0]["start"]:spans[0]["end"]]) != "abc" {
		t.Fatalf("spans = %v (%s)", spans, errText)
	}
	if _, errText := ui2MarkedSpans(raw, "GET /p HTTP/1.1\nHost: h\nX: §abd§\n\n"); errText == "" {
		t.Fatal("an edited request was accepted as markers only")
	}
}

func TestUI2IntruderPayloadsRerender(t *testing.T) {
	s := newTestServer()
	frag := postUI2IntruderForm(t, s, "/ui2/intruder/payloads", url.Values{
		"set_count": {"1"}, "set0_type": {"numbers"}, "set0_seen": {"list"}, "op": {"add_set"},
	})
	if !strings.Contains(frag, `name="set1_type"`) {
		t.Errorf("add_set did not add a second set: %.300s", frag)
	}
	if !strings.Contains(frag, `name="set0_from" value="1"`) {
		t.Errorf("a newly chosen numbers type did not render its defaults: %.600s", frag)
	}
}

func ui2UploadRequest(t *testing.T, fields map[string]string, file string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	if file != "" {
		fw, _ := mw.CreateFormFile("upload_file_0", "words.txt")
		_, _ = fw.Write([]byte(file))
	}
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/ui2/intruder/payloads/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func TestUI2IntruderPayloadUpload(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, ui2UploadRequest(t, map[string]string{"upload_set": "0", "set_count": "1"}, "alpha\nbeta\n"))
	frag := rec.Body.String()
	m := regexp.MustCompile(`name="set0_filename" value="([^"]+)"`).FindStringSubmatch(frag)
	if rec.Code != http.StatusOK || m == nil || !strings.Contains(frag, "2 payloads") {
		t.Fatalf("upload = %d, set 0 does not name the stored file: %.600s", rec.Code, frag)
	}
	stored := html.UnescapeString(m[1])
	t.Cleanup(func() { _ = os.Remove(stored) })
	if got, err := os.ReadFile(stored); err != nil || string(got) != "alpha\nbeta\n" {
		t.Fatalf("stored file %s = %q, %v", stored, got, err)
	}
}

func TestUI2IntruderPayloadUploadWithoutFileRefuses(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, ui2UploadRequest(t, map[string]string{"upload_set": "0", "set_count": "1"}, ""))
	if !strings.Contains(rec.Body.String(), "Upload refused") || strings.Contains(rec.Body.String(), "set0_filename") {
		t.Fatalf("an upload without a file was not refused: %.400s", rec.Body.String())
	}
}

func TestUI2IntruderControlRefusesANonNumericID(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/ui2/intruder/1%2F..%2Fx/stop", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("control with id %q = %d, want 400", "1/../x", rec.Code)
	}
}
