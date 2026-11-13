package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/proxy"
)

// ui2ProxyConfirmRun drives one reviewed write the way the page does: confirm, then run with
// only the review id and token. It returns the confirm body and the run recorder.
func ui2ProxyConfirmRun(t *testing.T, s *Server, area string, form url.Values) (string, int, string) {
	t.Helper()
	conf := postUI2Form(t, s, "/ui2/proxy/"+area+"/confirm", form)
	body := conf.Body.String()
	id, token := ui2ReviewFields(t, body)
	run := postUI2Form(t, s, "/ui2/proxy/"+area+"/run", url.Values{"review_id": {id}, "token": {token}})
	return body, run.Code, run.Body.String()
}

func ui2ListenerCount(t *testing.T, s *Server) int {
	t.Helper()
	var view proxyListenerView
	if err := json.Unmarshal(get(t, s, "/api/proxy/listener").Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	return len(view.Listeners)
}

func TestUI2ProxyListenerAddAndRemoveThroughReview(t *testing.T) {
	s, _ := startAPIProxy(t)
	if !strings.Contains(getUI2(t, s, "/ui2/proxy/listeners").Body.String(), "default (-proxy-bind)") {
		t.Fatal("listeners page does not show the boot listener")
	}
	review, code, after := ui2ProxyConfirmRun(t, s, "listeners", url.Values{
		"op": {"add"}, "bind": {"127.0.0.1:0"}, "redirect_port": {"8443"}, "invisible": {"off"}, "support_http2": {"on"},
	})
	for _, want := range []string{"POST /api/proxy/listener", `&#34;bind&#34;: &#34;127.0.0.1:0&#34;`, `&#34;redirect_port&#34;: 8443`, `&#34;invisible&#34;: false`} {
		if !strings.Contains(review, want) {
			t.Errorf("review lacks %s:\n%s", want, review)
		}
	}
	if code != http.StatusOK || !strings.Contains(after, "Saved: POST /api/proxy/listener") {
		t.Fatalf("run = %d: %s", code, after)
	}
	if n := ui2ListenerCount(t, s); n != 2 {
		t.Fatalf("after the reviewed add there are %d listeners, want 2", n)
	}
	_, code, after = ui2ProxyConfirmRun(t, s, "listeners", url.Values{"op": {"remove"}, "id": {"listener-1"}})
	if code != http.StatusOK || !strings.Contains(after, "Saved: DELETE /api/proxy/listener?id=listener-1") {
		t.Fatalf("remove run = %d: %s", code, after)
	}
	if n := ui2ListenerCount(t, s); n != 1 {
		t.Fatalf("after the reviewed remove there are %d listeners, want 1", n)
	}
}

func TestUI2ProxyListenerRunRefusesAForeignTokenAndAReplay(t *testing.T) {
	s, _ := startAPIProxy(t)
	conf := postUI2Form(t, s, "/ui2/proxy/listeners/confirm", url.Values{"op": {"add"}, "bind": {"127.0.0.1:0"}})
	id, token := ui2ReviewFields(t, conf.Body.String())
	bad := postUI2Form(t, s, "/ui2/proxy/listeners/run", url.Values{"review_id": {id}, "token": {token + "x"}})
	if !strings.Contains(bad.Body.String(), "does not match") {
		t.Errorf("a foreign token was not refused: %s", bad.Body.String())
	}
	// The failed spend killed the entry: the right token is now a replay.
	again := postUI2Form(t, s, "/ui2/proxy/listeners/run", url.Values{"review_id": {id}, "token": {token}})
	if !strings.Contains(again.Body.String(), "unknown or was already used") {
		t.Errorf("a spent review ran again: %s", again.Body.String())
	}
	if n := ui2ListenerCount(t, s); n != 1 {
		t.Fatalf("a refused run added a listener: %d listeners", n)
	}
	// The boot listener cannot be removed, and the refusal comes at review time.
	rm := postUI2Form(t, s, "/ui2/proxy/listeners/confirm", url.Values{"op": {"remove"}, "id": {"default"}})
	if !strings.Contains(rm.Body.String(), "not removed") || strings.Contains(rm.Body.String(), `name="review_id"`) {
		t.Errorf("removing the boot listener was offered a review: %s", rm.Body.String())
	}
}

func ui2OptionsServer() *Server {
	return NewServer(core.NewTrafficStore(), core.NewScope()).WithProxyOptions(proxy.NewOptions())
}

// ui2OptionsForm is the options form as rendered, with the given keys flipped on.
func ui2OptionsForm(t *testing.T, s *Server, on ...string) url.Values {
	t.Helper()
	page := getUI2(t, s, "/ui2/proxy/options").Body.String()
	form := url.Values{}
	for _, k := range proxy.OptionKeys {
		key := string(k)
		was := ui2HiddenValue(page, "was_"+key)
		if was == "" {
			t.Fatalf("options page lacks was_%s", key)
		}
		form.Set("was_"+key, was)
		if was == "true" {
			form.Set("opt_"+key, "on")
		}
	}
	for _, k := range on {
		form.Set("opt_"+k, "on")
	}
	return form
}

func TestUI2ProxyOptionsSendsOnlyTheChangedKey(t *testing.T) {
	s := ui2OptionsServer()
	review, code, after := ui2ProxyConfirmRun(t, s, "options", ui2OptionsForm(t, s, "remove_all_javascript"))
	if !strings.Contains(review, "PUT /api/proxy/options\n{\n  &#34;remove_all_javascript&#34;: true\n}") {
		t.Errorf("review is not the one-key diff:\n%s", review)
	}
	if code != http.StatusOK || !strings.Contains(after, "Saved: PUT /api/proxy/options") {
		t.Fatalf("run = %d: %s", code, after)
	}
	if !s.proxyOptions.Snapshot()["remove_all_javascript"] {
		t.Error("the reviewed switch is not on")
	}
	if !strings.Contains(after, "Outcome counters") || !strings.Contains(after, "Considered") {
		t.Error("options page lacks the outcome counters table")
	}
}

func TestUI2ProxyOptionsRunRefusesDrift(t *testing.T) {
	s := ui2OptionsServer()
	conf := postUI2Form(t, s, "/ui2/proxy/options/confirm", ui2OptionsForm(t, s, "remove_object_tags"))
	id, token := ui2ReviewFields(t, conf.Body.String())
	// Another client changes a different switch between review and confirm.
	_ = s.proxyOptions.Set("remove_all_javascript", true)
	run := postUI2Form(t, s, "/ui2/proxy/options/run", url.Values{"review_id": {id}, "token": {token}})
	if !strings.Contains(run.Body.String(), "changed between your review") {
		t.Errorf("drift was not refused: %s", run.Body.String())
	}
	if s.proxyOptions.Snapshot()["remove_object_tags"] {
		t.Error("a drifted review was dispatched")
	}
	// No change at all is refused at review.
	none := postUI2Form(t, s, "/ui2/proxy/options/confirm", ui2OptionsForm(t, s))
	if !strings.Contains(none.Body.String(), "nothing changed") {
		t.Errorf("an empty diff was offered a review: %s", none.Body.String())
	}
}

func TestUI2ProxyHistoryLoggingWritesAndRefusesUnknownMode(t *testing.T) {
	s := newTestServerWithPersist(t)
	rec := postUI2Form(t, s, "/ui2/proxy/history-logging", url.Values{"mode": {"stop"}})
	if !strings.Contains(rec.Body.String(), "Proxy history logging saved: stop") {
		t.Fatalf("history logging write: %s", rec.Body.String())
	}
	if !strings.Contains(get(t, s, "/api/proxy/history-logging").Body.String(), `"stop"`) {
		t.Error("the mode was not saved")
	}
	bad := postUI2Form(t, s, "/ui2/proxy/history-logging", url.Values{"mode": {"always"}})
	if !strings.Contains(bad.Body.String(), "must be stop, ask or nothing") {
		t.Errorf("unknown mode not refused: %s", bad.Body.String())
	}
	if !strings.Contains(get(t, s, "/api/proxy/history-logging").Body.String(), `"stop"`) {
		t.Error("a refused mode changed the saved one")
	}
}

// ui2MRForm is the editor form for a draft of (type, match, replace) rules.
func ui2MRForm(t *testing.T, s *Server, rules ...[3]string) url.Values {
	t.Helper()
	page := getUI2(t, s, "/ui2/proxy/match-replace").Body.String()
	form := url.Values{"baseline": {ui2HiddenValue(page, "baseline")}, "n": {strconv.Itoa(len(rules))}, "ucl": {"on"}}
	for i, r := range rules {
		p := "r" + strconv.Itoa(i) + "_"
		form.Set(p+"type", r[0])
		form.Set(p+"cat", "literal")
		form.Set(p+"match", r[1])
		form.Set(p+"replace", r[2])
		form.Set(p+"enabled", "on")
	}
	return form
}

func TestUI2MatchReplaceSaveThroughReview(t *testing.T) {
	s := newTestServer()
	review, code, after := ui2ProxyConfirmRun(t, s, "match-replace", ui2MRForm(t, s, [3]string{"request_header", "X-A: 1", "X-A: 2"}))
	if !strings.Contains(review, "PUT /api/tools/rules") || !strings.Contains(review, "X-A: 2") {
		t.Errorf("review does not show the whole body:\n%s", review)
	}
	if code != http.StatusOK || !strings.Contains(after, "Saved: PUT /api/tools/rules") {
		t.Fatalf("run = %d: %s", code, after)
	}
	rules := get(t, s, "/api/tools/rules").Body.String()
	if !strings.Contains(rules, `"string_replace":"X-A: 2"`) {
		t.Errorf("saved rules: %s", rules)
	}
}

func TestUI2MatchReplaceRefusesAStaleBaselineAndAnInvalidRule(t *testing.T) {
	s := newTestServer()
	form := ui2MRForm(t, s, [3]string{"request_header", "a", "b"})
	// The saved set changes under the open editor.
	put := newReq(http.MethodPut, "/api/tools/rules")
	put.Body = ioNopCloser(strings.NewReader(`{"rules":[{"rule_type":"response_body","enabled":true,"string_match":"x","string_replace":"y","category":"literal"}]}`))
	s.mux.ServeHTTP(newRecorder(), put)
	stale := postUI2Form(t, s, "/ui2/proxy/match-replace/confirm", form)
	if !strings.Contains(stale.Body.String(), "changed since this editor was loaded") {
		t.Errorf("a stale draft was offered a review: %s", stale.Body.String())
	}
	bad2 := ui2MRForm(t, s, [3]string{"request_header", "(", "x"})
	bad2.Set("r0_cat", "regex")
	badRe := postUI2Form(t, s, "/ui2/proxy/match-replace/confirm", bad2)
	if strings.Contains(badRe.Body.String(), `name="review_id"`) || !strings.Contains(badRe.Body.String(), "rule 0") {
		t.Errorf("an invalid regex was offered a review: %s", badRe.Body.String())
	}
}

func TestUI2MatchReplaceDraftEditAndTest(t *testing.T) {
	s := newTestServer()
	form := ui2MRForm(t, s, [3]string{"request_header", "one", "1"}, [3]string{"response_body", "r", "R"}, [3]string{"request_header", "two", "2"})
	up := postUI2Form(t, s, "/ui2/proxy/match-replace/edit?op=up&i=2", form)
	body := up.Body.String()
	// The second request rule moved above the first; the response rule kept its slot.
	if i, j := strings.Index(body, `value="two"`), strings.Index(body, `value="one"`); i < 0 || j < 0 || i > j {
		t.Errorf("reorder did not move rule 2 above rule 0:\n%s", body)
	}
	if !strings.Contains(body, "unsaved changes") {
		t.Error("an edited draft is not marked unsaved")
	}
	add := postUI2Form(t, s, "/ui2/proxy/match-replace/edit?op=add&set=response", form)
	if !strings.Contains(add.Body.String(), `name="n" value="4"`) {
		t.Errorf("add did not grow the draft")
	}
	form.Set("sample", "GET / HTTP/1.1\r\nHost: t\r\nX: one\r\n\r\n")
	form.Set("direction", "request")
	test := postUI2Form(t, s, "/ui2/proxy/match-replace/test", form)
	if !strings.Contains(test.Body.String(), "X: 1") || !strings.Contains(test.Body.String(), "changed") {
		t.Errorf("draft test output: %s", test.Body.String())
	}
	if strings.Contains(get(t, s, "/api/tools/rules").Body.String(), `"one"`) {
		t.Error("editing or testing the draft saved it")
	}
}

func TestUI2MatchReplaceKeepsLineBreaksExact(t *testing.T) {
	s := newTestServer()
	put := newReq(http.MethodPut, "/api/tools/rules")
	put.Body = ioNopCloser(strings.NewReader(`{"rules":[{"rule_type":"request_header","enabled":true,"string_match":"^X$","string_replace":"A: 1\r\nB: 2","category":"regex"}]}`))
	s.mux.ServeHTTP(newRecorder(), put)
	page := getUI2(t, s, "/ui2/proxy/match-replace").Body.String()
	b64 := ui2HiddenValue(page, "r0_replace_b64")
	if b64 == "" {
		t.Fatalf("a multi-line value is not carried exactly: %s", page)
	}
	form := url.Values{"baseline": {ui2HiddenValue(page, "baseline")}, "n": {"1"}, "r0_type": {"request_header"}, "r0_cat": {"regex"},
		"r0_match": {"^X$"}, "r0_replace_b64": {b64}, "r0_enabled": {"on"}}
	// The untouched draft round-trips to the saved hash, so there is nothing to save.
	if rec := postUI2Form(t, s, "/ui2/proxy/match-replace/confirm", form); !strings.Contains(rec.Body.String(), "nothing changed") {
		t.Errorf("an untouched multi-line rule reads as changed: %s", rec.Body.String())
	}
}
