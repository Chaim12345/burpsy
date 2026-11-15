package web

import (
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ui2GatedRunForm reads a gated review sheet's hidden fields into the run form.
func ui2GatedRunForm(t *testing.T, sheet string, names ...string) url.Values {
	t.Helper()
	form := url.Values{"token": {extractHiddenInput(t, sheet, "token")}}
	for _, n := range names {
		form.Set(n, html.UnescapeString(extractHiddenInput(t, sheet, n)))
	}
	return form
}

func ui2IssueJSON(t *testing.T, s *Server, id uint64) map[string]any {
	t.Helper()
	rec := getUI2(t, s, "/api/issues/"+strconv.FormatUint(id, 10))
	var v map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("GET /api/issues/%d: %d %s", id, rec.Code, rec.Body.String())
	}
	return v
}

func TestUI2IssuesListFiltersBySourceAndText(t *testing.T) {
	s := newTestServer()
	seedUI2Finding(t, s, "Hand-found thing", "high", "f.test", "/a")
	for _, c := range []struct {
		query string
		want  bool
	}{
		{"", true}, {"?source=manual", true}, {"?source=scan", false},
		{"?q=hand-found", true}, {"?q=nomatch", false}, {"?severity=High", true}, {"?severity=Low", false},
	} {
		body := getUI2(t, s, "/ui2/issues"+c.query).Body.String()
		if got := strings.Contains(body, "Hand-found thing</td>"); got != c.want {
			t.Errorf("GET /ui2/issues%s lists the finding = %v, want %v", c.query, got, c.want)
		}
	}
}

func TestUI2IssueTriageReviewedWritesLand(t *testing.T) {
	s := newTestServer()
	id := seedUI2Finding(t, s, "Triage me", "low", "t.test", "/t")
	ids := strconv.FormatUint(id, 10)
	for _, c := range []struct{ op, value, key string }{
		{"severity", "High", "severity"},
		{"false_positive", "true", "false_positive"},
		{"comment", "checked by hand <b>", "comment"},
	} {
		sheet := postUI2Form(t, s, "/ui2/issues/action/confirm", url.Values{"op": {c.op}, "id": {ids}, "value": {c.value}}).Body.String()
		if !strings.Contains(sheet, "PUT /api/issues/"+ids) || !strings.Contains(sheet, "disabled data-arm-on-load") {
			t.Fatalf("%s: the review does not show the exact call: %s", c.op, sheet)
		}
		rec := postUI2Form(t, s, "/ui2/issues/action/run", ui2GatedRunForm(t, sheet, "op", "id", "value"))
		if !strings.Contains(rec.Body.String(), "Applied:") || rec.Header().Get("HX-Trigger") != "ui2-issues-changed" {
			t.Fatalf("%s: run did not apply: %s", c.op, rec.Body.String())
		}
	}
	v := ui2IssueJSON(t, s, id)
	if v["severity"] != "High" || v["false_positive"] != true || v["comment"] != "checked by hand <b>" {
		t.Errorf("after the reviewed writes the issue is %v / %v / %q", v["severity"], v["false_positive"], v["comment"])
	}
}

func TestUI2IssueTriageRefusesATamperedRun(t *testing.T) {
	s := newTestServer()
	id := seedUI2Finding(t, s, "Tamper", "low", "x.test", "/x")
	ids := strconv.FormatUint(id, 10)
	sheet := postUI2Form(t, s, "/ui2/issues/action/confirm", url.Values{"op": {"severity"}, "id": {ids}, "value": {"High"}}).Body.String()
	form := ui2GatedRunForm(t, sheet, "op", "id", "value")
	form.Set("value", "Critical")
	rec := postUI2Form(t, s, "/ui2/issues/action/run", form)
	if !strings.Contains(rec.Body.String(), "Not applied") {
		t.Errorf("a tampered run was not refused: %s", rec.Body.String())
	}
	if got := ui2IssueJSON(t, s, id)["severity"]; got != "Low" {
		t.Errorf("severity after a tampered run = %v, want Low", got)
	}
	// Delete through the same flow lands; a replay of its spent token does not run again.
	sheet = postUI2Form(t, s, "/ui2/issues/action/confirm", url.Values{"op": {"delete"}, "id": {ids}, "value": {""}}).Body.String()
	runForm := ui2GatedRunForm(t, sheet, "op", "id", "value")
	if rec := postUI2Form(t, s, "/ui2/issues/action/run", runForm); !strings.Contains(rec.Body.String(), "deleted") {
		t.Fatalf("delete did not land: %s", rec.Body.String())
	}
	if _, err := s.findings.Get(id); err == nil {
		t.Errorf("the finding survived a reviewed delete")
	}
}

func TestUI2IssueLLMRefusedWhenUnconfigured(t *testing.T) {
	s := newTestServer()
	id := seedUI2Finding(t, s, "LLM", "high", "l.test", "/l")
	for _, form := range []url.Values{
		{"op": {"llm"}, "id": {strconv.FormatUint(id, 10)}, "value": {""}},
		{"op": {"llm_all"}, "id": {""}, "value": {""}},
	} {
		body := postUI2Form(t, s, "/ui2/issues/action/confirm", form).Body.String()
		if !strings.Contains(body, "LLM triage is not configured") || strings.Contains(body, `name="token"`) {
			t.Errorf("%s: an unconfigured LLM triage minted a review: %s", form.Get("op"), body)
		}
	}
}

func TestUI2IssueDetailOffersTriageExportAndCopy(t *testing.T) {
	s := newTestServer()
	id := seedUI2Finding(t, s, "Detail", "medium", "d.test", "/d")
	body := getUI2(t, s, "/ui2/issues/"+strconv.FormatUint(id, 10)).Body.String()
	for _, want := range []string{`value="severity"`, `value="confidence"`, `value="false_positive"`, `value="delete"`,
		`value="llm"`, "/api/report/finding/" + strconv.FormatUint(id, 10), `class="btn copy-btn" data-copy="Detail"`} {
		if !strings.Contains(body, want) {
			t.Errorf("issue detail is missing %q", want)
		}
	}
}

func TestUI2ConsolidationHeldReviewSavesOnce(t *testing.T) {
	s := newTestServer()
	conf := postUI2Form(t, s, "/ui2/issues/consolidation/confirm", url.Values{
		"default": {"keep_both"}, "new_name": {"Cookie without Secure"}, "new_action": {"keep_new"},
	})
	sheet := conf.Body.String()
	if !strings.Contains(sheet, "PUT /api/issues/consolidation") || !strings.Contains(sheet, "keep_both") {
		t.Fatalf("the review does not show the exact body: %s", sheet)
	}
	id, token := ui2ReviewFields(t, sheet)
	run := url.Values{"review_id": {id}, "token": {token}}
	if rec := postUI2Form(t, s, "/ui2/issues/consolidation/run", run); !strings.Contains(rec.Body.String(), "Consolidation policy saved") {
		t.Fatalf("run did not save: %s", rec.Body.String())
	}
	got := getUI2(t, s, "/api/issues/consolidation").Body.String()
	if !strings.Contains(got, `"default":"keep_both"`) || !strings.Contains(got, `"Cookie without Secure":"keep_new"`) {
		t.Errorf("policy after the reviewed save: %s", got)
	}
	// The held review is single-use.
	if rec := postUI2Form(t, s, "/ui2/issues/consolidation/run", run); !strings.Contains(rec.Body.String(), "already used") {
		t.Errorf("a spent review ran again: %s", rec.Body.String())
	}
}

func TestUI2ConsolidationRefusesDrift(t *testing.T) {
	s := newTestServer()
	sheet := postUI2Form(t, s, "/ui2/issues/consolidation/confirm", url.Values{"default": {"keep_new"}}).Body.String()
	id, token := ui2ReviewFields(t, sheet)
	s.applyConsolidation(core.ConsolidationPolicy{Default: core.ConsolidateKeepBoth})
	rec := postUI2Form(t, s, "/ui2/issues/consolidation/run", url.Values{"review_id": {id}, "token": {token}})
	if !strings.Contains(rec.Body.String(), "changed since this review") {
		t.Errorf("a drifted policy was overwritten: %s", rec.Body.String())
	}
	if got := getUI2(t, s, "/api/issues/consolidation").Body.String(); !strings.Contains(got, `"default":"keep_both"`) {
		t.Errorf("policy after a refused run: %s", got)
	}
}

func TestUI2ReportLinksCarryTheSettings(t *testing.T) {
	s := newTestServer()
	seedUI2Finding(t, s, "Report", "high", "r.test", "/r")
	body := getUI2(t, s, "/ui2/issues/report?title=Q3&organise_by=url&sections_set=1&sections=detail&message_mode=full&severity=high&host=r.test&hide_fp=1").Body.String()
	links := map[string]string{}
	for _, f := range []string{"html", "xml", "json", "sarif"} {
		marker := `href="/api/report/` + f + `?`
		i := strings.Index(body, marker)
		if i < 0 {
			t.Fatalf("no %s link: %s", f, body)
		}
		rest := body[i+len(`href="`):]
		links[f] = html.UnescapeString(rest[:strings.Index(rest, `"`)])
	}
	for f, want := range map[string][]string{
		"html":  {"title=Q3", "organise_by=url", "sections=detail", "message_mode=full", "severity=high", "host=r.test", "exclude_false_positives=true"},
		"xml":   {"sections=detail", "message_mode=full", "severity=high"},
		"json":  {"severity=high", "host=r.test", "exclude_false_positives=true"},
		"sarif": {"severity=high"},
	} {
		for _, w := range want {
			if !strings.Contains(links[f], w) {
				t.Errorf("%s link %q lacks %s", f, links[f], w)
			}
		}
	}
	if strings.Contains(links["json"], "title=") {
		t.Errorf("the json link carries an html-only setting: %s", links["json"])
	}
	for f, ct := range map[string]string{"html": "text/html", "json": "application/json"} {
		if rec := getUI2(t, s, links[f]); rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), ct) {
			t.Errorf("%s link answered %d %s", f, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
}

func TestUI2AuditQueueCancelReviewed(t *testing.T) {
	s := newTestServer()
	exID := seedUI2Exchange(t, s, "GET /q HTTP/1.1\r\nHost: q.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	s.auditItems.Enqueue(exID, 3)
	ids := strconv.FormatUint(uint64(exID), 10)
	if page := getUI2(t, s, "/ui2/auditqueue").Body.String(); !strings.Contains(page, `hx-get="/ui2/auditqueue/item/`+ids+`"`) || !strings.Contains(page, "Pending 1") {
		t.Fatalf("the queue page does not list the item: %s", page)
	}
	if detail := getUI2(t, s, "/ui2/auditqueue/item/"+ids).Body.String(); !strings.Contains(detail, "/q") || !strings.Contains(detail, `value="cancel"`) {
		t.Fatalf("the item pane lacks its request or actions: %s", detail)
	}
	sheet := postUI2Form(t, s, "/ui2/auditqueue/action/confirm", url.Values{"op": {"cancel"}, "id": {ids}}).Body.String()
	if !strings.Contains(sheet, "POST /api/scanner/audit-items/"+ids+"/cancel") {
		t.Fatalf("the review does not show the exact call: %s", sheet)
	}
	// Refusal: the token is bound to this item, so a run naming another one is refused.
	tampered := ui2GatedRunForm(t, sheet, "op", "id")
	tampered.Set("id", ids+"9")
	if rec := postUI2Form(t, s, "/ui2/auditqueue/action/run", tampered); !strings.Contains(rec.Body.String(), "Not applied") {
		t.Errorf("a tampered run was not refused: %s", rec.Body.String())
	}
	sheet = postUI2Form(t, s, "/ui2/auditqueue/action/confirm", url.Values{"op": {"cancel"}, "id": {ids}}).Body.String()
	rec := postUI2Form(t, s, "/ui2/auditqueue/action/run", ui2GatedRunForm(t, sheet, "op", "id"))
	if !strings.Contains(rec.Body.String(), "Done:") || rec.Header().Get("HX-Trigger") != "ui2-auditqueue-changed" {
		t.Fatalf("cancel did not land: %s", rec.Body.String())
	}
	if got := getUI2(t, s, "/api/scanner/audit-items").Body.String(); !strings.Contains(got, `"state":"cancelled"`) {
		t.Errorf("queue after the reviewed cancel: %s", got)
	}
}
