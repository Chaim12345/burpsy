package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/intercept"
)

// ui2InterceptRulesDraft is the editor form for one list, with base read from the editor page.
func ui2InterceptRulesDraft(t *testing.T, s *Server, dir string, active bool, rules ...map[string]string) url.Values {
	t.Helper()
	page := getUI2(t, s, "/ui2/intercept/rules?dir="+dir).Body.String()
	form := url.Values{"dir": {dir}, "form_base": {extractHiddenInput(t, page, "form_base")}, "n": {strconv.Itoa(len(rules))}}
	if active {
		form.Set("active", "on")
	}
	for i, r := range rules {
		for k, v := range r {
			form.Set(k+"_"+strconv.Itoa(i), v)
		}
	}
	return form
}

func ui2InterceptRuleSpecs(t *testing.T, s *Server, dir string) []intercept.Rule {
	t.Helper()
	d, _ := directionFor(dir)
	l := s.intercept.Rules(d)
	out := make([]intercept.Rule, len(l.Rules))
	for i, r := range l.Rules {
		out[i] = *r
	}
	return out
}

func TestUI2InterceptRulesPageRendersStoredList(t *testing.T) {
	s := newTestServer()
	rules := []intercept.Rule{
		{Field: intercept.FieldHost, Category: intercept.CategoryLiteral, StringMatch: "a.test", Enabled: true},
		{Field: intercept.FieldPath, Category: intercept.CategoryRegex, StringMatch: "^/admin", Enabled: true, Op: intercept.RuleOpAnd},
	}
	if err := s.intercept.SetRules(intercept.DirectionRequest, true, rules); err != nil {
		t.Fatal(err)
	}
	body := getUI2(t, s, "/ui2/intercept/rules?dir=requests").Body.String()
	for _, want := range []string{"Request interception rules", `value="a.test"`, `value="^/admin"`, `<option value="and" selected>AND</option>`, "on with 2 condition(s)"} {
		if !strings.Contains(body, want) {
			t.Errorf("rules page missing %q", want)
		}
	}
}

func TestUI2InterceptRulesEditTransformsWithoutWriting(t *testing.T) {
	s := newTestServer()
	form := ui2InterceptRulesDraft(t, s, "requests", true,
		map[string]string{"field": "host", "match": "one", "category": "literal", "action": "hold", "op": "or", "enabled": "on"},
		map[string]string{"field": "path", "match": "two", "category": "literal", "action": "pass", "op": "and"})
	form.Set("edit", "up-1")
	body := postUI2Form(t, s, "/ui2/intercept/rules/edit", form).Body.String()
	if strings.Index(body, `value="two"`) > strings.Index(body, `value="one"`) {
		t.Errorf("up-1 did not move rule 2 above rule 1")
	}
	form.Set("edit", "add")
	if body := postUI2Form(t, s, "/ui2/intercept/rules/edit", form).Body.String(); !strings.Contains(body, `name="n" value="3"`) {
		t.Errorf("add did not append a rule")
	}
	if n := len(ui2InterceptRuleSpecs(t, s, "requests")); n != 0 {
		t.Errorf("a draft edit wrote %d rules", n)
	}
}

func TestUI2InterceptRulesReviewedSave(t *testing.T) {
	s := newTestServer()
	form := ui2InterceptRulesDraft(t, s, "responses", true,
		map[string]string{"field": "status_code", "match": "^5", "category": "regex", "action": "hold", "op": "or", "enabled": "on"},
		map[string]string{"field": "response_header", "member": "X-Debug", "match": "1", "category": "literal", "action": "pass", "op": "and", "enabled": "on"})
	sheet := postUI2Form(t, s, "/ui2/intercept/rules/confirm", form).Body.String()
	if !strings.Contains(sheet, "PUT /api/intercept/rules/responses") || !strings.Contains(sheet, "data-arm-on-load") {
		t.Fatalf("review sheet missing the exact call: %s", sheet[:ui2Min(400, len(sheet))])
	}
	if n := len(ui2InterceptRuleSpecs(t, s, "responses")); n != 0 {
		t.Fatalf("confirm wrote %d rules before the run", n)
	}
	id, token := ui2ReviewFields(t, sheet)
	out := postUI2Form(t, s, "/ui2/intercept/rules/run", url.Values{"review_id": {id}, "token": {token}}).Body.String()
	if !strings.Contains(out, "Saved the response list") {
		t.Fatalf("run did not report the save: %s", out[:ui2Min(400, len(out))])
	}
	got := ui2InterceptRuleSpecs(t, s, "responses")
	if len(got) != 2 || got[1].Member != "X-Debug" || got[1].Op != intercept.RuleOpAnd || got[1].Action != intercept.RuleActionPass {
		t.Errorf("saved rules = %+v", got)
	}
	// The API read carries the AND back, so a later edit does not turn it into OR.
	if rec := getUI2(t, s, "/api/intercept/rules/responses"); !strings.Contains(rec.Body.String(), `"op":"and"`) {
		t.Errorf("GET rules dropped the AND: %s", rec.Body.String())
	}
}

func TestUI2InterceptRulesRunRefusesForgedTokenAndDrift(t *testing.T) {
	s := newTestServer()
	form := ui2InterceptRulesDraft(t, s, "requests", true, map[string]string{"field": "host", "match": "x", "category": "literal", "action": "hold", "op": "or", "enabled": "on"})
	id, _ := ui2ReviewFields(t, postUI2Form(t, s, "/ui2/intercept/rules/confirm", form).Body.String())
	if out := postUI2Form(t, s, "/ui2/intercept/rules/run", url.Values{"review_id": {id}, "token": {"forged"}}).Body.String(); !strings.Contains(out, "does not match") {
		t.Errorf("forged token not refused: %s", out[:ui2Min(300, len(out))])
	}
	// A draft whose base predates a newer list is refused at review time.
	if err := s.intercept.SetRules(intercept.DirectionRequest, true, []intercept.Rule{{Field: intercept.FieldHost, StringMatch: "other", Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	if out := postUI2Form(t, s, "/ui2/intercept/rules/confirm", form).Body.String(); !strings.Contains(out, "changed since this editor opened") {
		t.Errorf("stale draft not refused: %s", out[:ui2Min(300, len(out))])
	}
	if got := ui2InterceptRuleSpecs(t, s, "requests"); len(got) != 1 || got[0].StringMatch != "other" {
		t.Errorf("a refused review changed the list: %+v", got)
	}
}

func TestUI2InterceptQuickRuleFromHeld(t *testing.T) {
	s := newTestServer()
	h := ui2HoldRequest(t, s, "GET /x.js HTTP/1.1\r\nHost: a.test\r\n\r\n")
	h.Path = "/x.js"
	sheet := postUI2Form(t, s, "/ui2/intercept/rules/quick", url.Values{"id": {strconv.FormatUint(h.ID, 10)}, "kind": {"pass-ext"}}).Body.String()
	id, token := ui2ReviewFields(t, sheet)
	postUI2Form(t, s, "/ui2/intercept/rules/run", url.Values{"review_id": {id}, "token": {token}})
	got := ui2InterceptRuleSpecs(t, s, "requests")
	if len(got) != 1 || got[0].Field != intercept.FieldExtension || got[0].StringMatch != "js" || got[0].Action != intercept.RuleActionPass {
		t.Errorf("quick rule = %+v", got)
	}
	if out := postUI2Form(t, s, "/ui2/intercept/rules/quick", url.Values{"id": {"999"}, "kind": {"pass-host"}}).Body.String(); !strings.Contains(out, "no longer held") {
		t.Errorf("quick rule on a gone hold not refused")
	}
}

func TestUI2InterceptAnnotateHeld(t *testing.T) {
	s := newTestServer()
	h := ui2HoldRequest(t, s, "GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
	path := "/ui2/intercept/annotate-" + strconv.FormatUint(h.ID, 10)
	out := postUI2Form(t, s, path, url.Values{"comment": {"look here"}, "highlight": {"red"}}).Body.String()
	if !strings.Contains(out, "Annotation saved") || h.Comment != "look here" || h.Highlight != "red" {
		t.Errorf("annotation not saved: %q %q", h.Comment, h.Highlight)
	}
	if out := postUI2Form(t, s, path, url.Values{"comment": {"x"}, "highlight": {"plaid"}}).Body.String(); !strings.Contains(out, "unknown highlight") || h.Comment != "look here" {
		t.Errorf("unknown highlight not refused")
	}
}

func TestUI2InterceptBulkForwardAndDrop(t *testing.T) {
	s := newTestServer()
	a := ui2HoldRequest(t, s, "GET /a HTTP/1.1\r\nHost: a.test\r\n\r\n")
	b := ui2HoldRequest(t, s, "GET /b HTTP/1.1\r\nHost: a.test\r\n\r\n")
	c := ui2HoldRequest(t, s, "GET /c HTTP/1.1\r\nHost: a.test\r\n\r\n")
	out := postUI2Form(t, s, "/ui2/intercept/forward-checked", url.Values{"ids": {strconv.FormatUint(a.ID, 10), strconv.FormatUint(b.ID, 10), "999"}}).Body.String()
	if !strings.Contains(out, "Forwarded 2 checked message(s)") || !strings.Contains(out, "#999") {
		t.Errorf("bulk forward note: %s", out[:ui2Min(300, len(out))])
	}
	if act, _, _, _ := a.Wait(); act != intercept.ActionForward {
		t.Errorf("a not forwarded")
	}
	postUI2Form(t, s, "/ui2/intercept/drop-checked", url.Values{"ids": {strconv.FormatUint(c.ID, 10)}})
	if act, _, _, _ := c.Wait(); act != intercept.ActionDrop {
		t.Errorf("c not dropped")
	}
}

func TestUI2InterceptForwardRetargetAndHoldResponse(t *testing.T) {
	s := newTestServer()
	h := ui2HoldRequest(t, s, "GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
	path := "/ui2/intercept/forward-" + strconv.FormatUint(h.ID, 10)
	if out := postUI2Form(t, s, path, url.Values{"host": {"b.test"}, "port": {"0"}, "scheme": {"https"}}).Body.String(); !strings.Contains(out, "Not forwarded") {
		t.Fatalf("port 0 not refused")
	}
	if len(s.intercept.Held()) != 1 {
		t.Fatalf("a refused retarget resolved the hold")
	}
	postUI2Form(t, s, path, url.Values{"host": {"b.test"}, "port": {"8443"}, "scheme": {"https"}, "hold_response": {"on"}})
	_, _, target, _ := h.Wait()
	if target == nil || target.Host != "b.test" || target.Port != 8443 || !target.TLS {
		t.Errorf("target = %+v", target)
	}
	if s.intercept.PendingResponses() != 1 {
		t.Errorf("hold_response did not arm a response hold")
	}
}

func TestUI2InterceptOptions(t *testing.T) {
	s := newTestServer()
	postUI2Form(t, s, "/ui2/intercept/in-scope-on", url.Values{})
	if !s.intercept.InScopeOnly() {
		t.Errorf("in-scope-on did not set the filter")
	}
	postUI2Form(t, s, "/ui2/intercept/newline", url.Values{"add_missing_blank_line": {"on"}})
	if nl := s.intercept.NewlineCorrections(); !nl.AddMissingBlankLine || nl.TrimTrailingNewlinesInURLEncodedBody {
		t.Errorf("newline corrections = %+v", nl)
	}
	if out := postUI2Form(t, s, "/ui2/intercept/startup", url.Values{"mode": {"on"}}).Body.String(); !strings.Contains(out, "Not saved") {
		t.Errorf("startup without persistence not refused")
	}
	ps := newTestServerWithPersist(t)
	if out := postUI2Form(t, ps, "/ui2/intercept/startup", url.Values{"mode": {"restore"}}).Body.String(); !strings.Contains(out, "set to restore") || ps.persist.LoadInterceptStartup() != "restore" {
		t.Errorf("startup restore not saved")
	}
}

func TestUI2InterceptSendToTool(t *testing.T) {
	s := newTestServer()
	h := ui2HoldRequest(t, s, "GET /seed HTTP/1.1\r\nHost: a.test\r\n\r\n")
	rec := getUI2(t, s, "/ui2/intercept/send?id="+strconv.FormatUint(h.ID, 10)+"&to=repeater")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "GET /seed") || !strings.Contains(rec.Body.String(), "http://a.test:80") {
		t.Errorf("repeater not seeded: %d", rec.Code)
	}
	if len(s.intercept.Held()) != 1 {
		t.Errorf("send-to-tool resolved the hold")
	}
	if body := getUI2(t, s, "/ui2/intercept/send?id=999&to=decoder").Body.String(); !strings.Contains(body, "no longer held") {
		t.Errorf("gone hold not refused")
	}
}

func TestUI2InterceptQueueShowsRowTools(t *testing.T) {
	s := newTestServer()
	h := ui2HoldRequest(t, s, "POST /x.php HTTP/1.1\r\nHost: a.test\r\nContent-Length: 1\r\n\r\nq")
	h.Path = "/x.php"
	body := getUI2(t, s, "/ui2/intercept").Body.String()
	for _, want := range []string{"Don&#39;t intercept .php files", "to=comparer", `data-copy="http://a.test/x.php"`, "--data-raw", "Forward and intercept the response", `name="ids"`, "Edit request rules"} {
		if !strings.Contains(body, want) {
			t.Errorf("queue missing %q", want)
		}
	}
	if strings.Contains(body, "stays in the console") {
		t.Errorf("the stale rule-editing note is still rendered")
	}
}
