package web

import (
	"bytes"
	"encoding/json"
	"html"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// ui2Post posts a urlencoded form through the mux.
func ui2Post(t *testing.T, s *Server, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// ui2IntruderLaunch runs a reviewed attack with grep settings against a loopback victim and
// returns the task id. The victim echoes the payload and a token=<payload>; to extract.
func ui2IntruderLaunch(t *testing.T) (*Server, uint64, uint64) {
	t.Helper()
	s := newTestServer()
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello " + r.URL.Query().Get("a") + " token=tok-" + r.URL.Query().Get("a") + ";"))
	}))
	t.Cleanup(victim.Close)
	vhost := strings.TrimPrefix(victim.URL, "http://")
	s.scope.AddInclude("127.0.0.1")
	msgID := seedUI2ExchangeMsgID(t, s, "GET /p?a=1 HTTP/1.1\r\nHost: "+vhost+"\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\nhello token=tok-1;")
	form := url.Values{
		"msg_id": {strconv.FormatUint(msgID, 10)}, "payloads": {"admin\n=1+1"}, "point": {"0"}, "points_listed": {"1"}, // the a= value is the one default point
		"settings_present": {"1"}, "store_requests": {"on"}, "store_responses": {"on"}, "retries": {"0"},
		"grep_match_list": {"hello"}, "grep_match_mode": {"simple"}, "grep_extract": {`token=([^;]*);`},
		"grep_payloads_enabled": {"on"}, "store_full_payloads": {"on"},
	}
	frag := ui2Post(t, s, "/ui2/intruder/confirm", form).Body.String()
	if !strings.Contains(frag, "grep_match_list") || !strings.Contains(frag, "retries") {
		t.Fatalf("the reviewed body does not carry the settings: %s", frag[:ui2Min(600, len(frag))])
	}
	// The browser posts back every hidden input of the review, unescaped.
	run := url.Values{"token": {extractHiddenInput(t, frag, "token")}}
	for _, k := range append([]string{"msg_id", "target", "payload_placement", "point", "all_points", "payloads", "points_listed", "form_seen"}, ui2IntruderSettingsFields...) {
		for _, v := range extractHiddenInputs(frag, k) {
			run.Add(k, html.UnescapeString(v))
		}
	}
	body := ui2Post(t, s, "/ui2/intruder/run", run).Body.String()
	var task uint64
	s.ui2IntruderReports.Range(func(k, _ any) bool { task = k.(uint64); return false })
	if task == 0 {
		t.Fatalf("the run kept no report: %s", body[:ui2Min(600, len(body))])
	}
	return s, task, msgID
}

func TestUI2IntruderResultsShowGrepColumnsAndSortFilter(t *testing.T) {
	s, task, _ := ui2IntruderLaunch(t)
	base := "/ui2/intruder/" + strconv.FormatUint(task, 10)
	page := getUI2(t, s, base+"/results").Body.String()
	for _, want := range []string{`data-sort="grep0"`, ">hello</a>", "tok-admin", "Result buckets", "Payload sets", "Errors"} {
		if !strings.Contains(page, want) {
			t.Errorf("results page lacks %q", want)
		}
	}
	filtered := getUI2(t, s, base+"/results?q=admin&sort=payload&order=desc").Body.String()
	// Only the rows table is filtered; the bucket summary beside it always covers the whole run.
	rows := filtered[strings.Index(filtered, `id="rows-body"`):]
	rows = rows[:strings.Index(rows, "</tbody>")]
	if !strings.Contains(rows, "tok-admin") || strings.Contains(rows, "tok-=1") {
		t.Errorf("filter q=admin did not narrow the rows")
	}
	if rec := getUI2(t, s, "/ui2/intruder/abc/results"); rec.Code != http.StatusNotFound {
		t.Errorf("a non-numeric attack id answered %d, want 404", rec.Code)
	}
}

func TestUI2IntruderItemActions(t *testing.T) {
	s, task, _ := ui2IntruderLaunch(t)
	base := "/ui2/intruder/" + strconv.FormatUint(task, 10)
	item := getUI2(t, s, base+"/item/0").Body.String()
	for _, want := range []string{"Request item again", "Send to Repeater", "Comparer A", "copy-btn"} {
		if !strings.Contains(item, want) {
			t.Errorf("row view lacks %q", want)
		}
	}
	if rep := getUI2(t, s, base+"/item/0/repeater").Body.String(); !strings.Contains(rep, "a=admin") {
		t.Errorf("repeater draft is not the attempt's request")
	}
	if cmp := getUI2(t, s, base+"/compare?a=req:0&b=req:1").Body.String(); !strings.Contains(cmp, "Diff") {
		t.Errorf("compare did not diff the two requests")
	}
	if rec := getUI2(t, s, base+"/item/99"); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown ordinal answered %d", rec.Code)
	}
}

func TestUI2IntruderCommentSavesAndRefusesOversize(t *testing.T) {
	s, task, _ := ui2IntruderLaunch(t)
	base := "/ui2/intruder/" + strconv.FormatUint(task, 10)
	ui2Post(t, s, base+"/comment", url.Values{"ordinal": {"0"}, "comment": {"look here"}})
	if !strings.Contains(getUI2(t, s, base+"/results").Body.String(), "look here") {
		t.Error("the comment is not on the results row")
	}
	if rec := ui2Post(t, s, base+"/comment", url.Values{"ordinal": {"0"}, "comment": {strings.Repeat("x", 1001)}}); rec.Code != http.StatusBadRequest {
		t.Errorf("an oversize comment answered %d, want 400", rec.Code)
	}
}

func TestUI2IntruderAgainReviewsThenSends(t *testing.T) {
	s, task, _ := ui2IntruderLaunch(t)
	base := "/ui2/intruder/" + strconv.FormatUint(task, 10)
	if body := ui2Post(t, s, base+"/again/run", url.Values{"ordinal": {"0"}}).Body.String(); !strings.Contains(body, "no confirmation token") {
		t.Fatalf("again without a token was not refused: %s", body)
	}
	frag := ui2Post(t, s, base+"/again/confirm", url.Values{"ordinal": {"0"}}).Body.String()
	if !strings.Contains(frag, "request_ids") || !strings.Contains(frag, "data-arm-on-load") {
		t.Fatalf("review does not show the full bound body: %s", frag)
	}
	sent := ui2Post(t, s, base+"/again/run", url.Values{"ordinal": {"0"}, "token": {extractHiddenInput(t, frag, "token")}}).Body.String()
	if !strings.Contains(sent, "Sent again") || !strings.Contains(sent, "tok-admin") {
		t.Fatalf("the confirmed re-send did not answer the new response: %s", sent)
	}
}

func TestUI2IntruderExportGuardsFormulas(t *testing.T) {
	s, task, _ := ui2IntruderLaunch(t)
	base := "/ui2/intruder/" + strconv.FormatUint(task, 10)
	csvBody := getUI2(t, s, base+"/export?format=csv").Body.String()
	if !strings.Contains(csvBody, "'=1+1") || !strings.Contains(csvBody, "Grep extract") {
		t.Errorf("CSV lacks the guarded formula payload or headers: %s", csvBody)
	}
	var view map[string]any
	if err := json.Unmarshal(getUI2(t, s, base+"/export?format=json").Body.Bytes(), &view); err != nil || view["task_id"] == nil {
		t.Errorf("JSON export is not the RunView: %v", err)
	}
	if rec := getUI2(t, s, "/ui2/intruder/987654/export?format=csv"); rec.Code != http.StatusNotFound {
		t.Errorf("export of an unknown attack answered %d", rec.Code)
	}
}

func TestUI2IntruderConfigSaveLoadAndRefusal(t *testing.T) {
	s := newTestServer()
	msgID := seedUI2ExchangeMsgID(t, s, "GET /p?a=1 HTTP/1.1\r\nHost: p.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	form := url.Values{"msg_id": {strconv.FormatUint(msgID, 10)}, "target": {"saved.test:8080"}, "payloads": {"x"},
		"point": {"0"}, "settings_present": {"1"}, "retries": {"5"}, "positions": {"with"}}
	saved := ui2Post(t, s, "/ui2/intruder/config/save", form).Body.String()
	doc := extractTextarea(t, strings.Replace(saved, "<textarea readonly", `<textarea name="cfg"`, 1), "cfg")
	doc = html.UnescapeString(doc)
	if !strings.Contains(doc, `"retries"`) || !strings.Contains(doc, ui2IntruderConfigFormat) {
		t.Fatalf("saved config lacks the form: %s", doc)
	}
	if rec := ui2Post(t, s, "/ui2/intruder/config/save", url.Values{"config": {doc}}); !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Errorf("download mode answered no attachment")
	}
	load := func(text string) string {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("config_file", "a.json")
		_, _ = fw.Write([]byte(text))
		_ = mw.Close()
		req := httptest.NewRequest(http.MethodPost, "/ui2/intruder/config/load", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("HX-Request", "true")
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		return rec.Body.String()
	}
	if got := load(doc); !strings.Contains(got, `value="saved.test:8080"`) || !strings.Contains(got, `value="5"`) || !strings.Contains(got, `name="point" value="0" checked`) {
		t.Errorf("loaded config was not restored into the form: %s", got[:ui2Min(400, len(got))])
	}
	bad := strings.Replace(doc, `"retries"`, `"mode"`, 1)
	if got := html.UnescapeString(load(bad)); !strings.Contains(got, `"mode" cannot be restored`) {
		t.Errorf("a config with an unrestorable field was not refused: %s", got)
	}
	without := ui2Post(t, s, "/ui2/intruder/config/save", url.Values{"point": {"0"}, "positions": {"without"}}).Body.String()
	if strings.Contains(without, "point") {
		t.Errorf("copy without positions kept the points")
	}
}

func TestUI2IntruderDefaultSettingsAndExtract(t *testing.T) {
	s := newTestServer()
	def := getUI2(t, s, "/ui2/intruder/config/default").Body.String()
	if !strings.Contains(def, `name="settings_present"`) || !strings.Contains(def, `name="store_requests" checked`) {
		t.Errorf("default settings section is not Burp's defaults")
	}
	exID := seedUI2Exchange(t, s, "GET / HTTP/1.1\r\nHost: p.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\n<input name=csrf value=abc123>")
	ex, _ := s.store.GetExchange(exID)
	rid := strconv.FormatUint(uint64(*ex.Response), 10)
	out := ui2Post(t, s, "/ui2/intruder/settings/extract", url.Values{"extract_response_id": {rid}, "extract_text": {"abc123"}}).Body.String()
	if !strings.Contains(out, "value=([\\s\\S]*?)&gt;") || !strings.Contains(out, "Extracts exactly") {
		t.Errorf("extract helper did not build a rule that extracts the selection: %s", out)
	}
	if out := ui2Post(t, s, "/ui2/intruder/settings/extract", url.Values{"extract_response_id": {rid}, "extract_text": {"nope"}}).Body.String(); !strings.Contains(out, "does not occur") {
		t.Errorf("text absent from the response was not refused: %s", out)
	}
}

func extractTextarea(t *testing.T, html, name string) string {
	t.Helper()
	marker := `<textarea name="` + name + `"`
	i := strings.Index(html, marker)
	if i < 0 {
		t.Fatalf("no %q textarea in fragment", name)
	}
	rest := html[i+len(marker):]
	j := strings.Index(rest, ">")
	k := strings.Index(rest, "</textarea>")
	if j < 0 || k < 0 || k < j {
		t.Fatalf("malformed %q textarea in fragment", name)
	}
	return rest[j+1 : k]
}
